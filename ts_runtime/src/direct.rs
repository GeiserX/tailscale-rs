//! Direct (disco) UDP underlay manager.
//!
//! This actor owns the single [`MagicSock`] that carries WireGuard datagrams directly over
//! UDP to peers' reachable endpoints, discovering and confirming paths with the disco
//! protocol. It mirrors [`crate::multiderp::Multiderp`] but for the direct underlay: it
//! registers one [`DirectTransport`] with the dataplane and bridges packets between that
//! transport and the dataplane's underlay channels.
//!
//! # Anti-leak posture
//!
//! A peer is reported as having a direct path *only* when [`MagicSock::best_addr`] returns
//! `Some` (i.e. a disco pong confirmed the path and its trust has not expired). The route
//! layer upgrades such peers from DERP to direct and auto-downgrades them back to DERP when
//! trust lapses. There is never a silent host-network dial, so the real origin IP cannot leak
//! when direct connectivity is unavailable.

use core::{net::SocketAddr, time::Duration};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
};

use kameo::{
    actor::ActorRef,
    message::{Context, Message},
};
use tokio::task::JoinSet;
use ts_keys::{DiscoPublicKey, NodePublicKey};
use ts_magicsock::{BindingVerifier, DirectTransport, MagicSock, SelfEndpoint};
use ts_transport::{
    BatchRecvIter, PeerId, PeerLookup, UnderlayTransport, UnderlayTransportExt, UnderlayTransportId,
};

use crate::{
    Env, Error,
    dataplane::{DataplaneActor, NewUnderlayTransport, UnderlayFromDataplane, UnderlayToDataplane},
    multiderp::{self, Multiderp},
    peer_tracker::{PeerDb, PeerState},
};

/// How often to (re)ping candidate endpoints. [`MagicSock::send_pings`] only pings paths that
/// need (re)confirmation, so this interval just bounds how quickly an expired path
/// (`TRUST_DURATION`) is re-confirmed.
///
/// No-flap timing invariant (spans crates): the magicsock best-path refresh lead
/// `REFRESH_BEFORE_EXPIRY` (3.5s) must exceed this interval plus a realistic best-path RTT, so the
/// best is re-pinged and re-confirmed before `TRUST_DURATION` (6.5s) lapses and `best_addr` goes
/// `None`. Raising this interval shrinks that slack; keep it in step with the magicsock `path.rs`
/// constants (which carry the reciprocal note).
const PING_INTERVAL: Duration = Duration::from_secs(2);

/// Bounds for the **randomized** delay between periodic STUN Binding Request sweeps to the derp map's
/// STUN servers (from the one bound underlay socket, to learn our reflexive/public address even
/// before any peer pongs — complementing the pong-harvest path on the same socket without a second
/// egress). Each sweep waits a fresh uniform delay in `[MIN, MAX)`, matching Go magicsock which arms
/// its `periodicReSTUNTimer` with `tstime.RandomDurationBetween(20s, 26s)` per cycle
/// (`magicsock.go`). The jitter — and the sub-30s ceiling — are deliberate: a fixed 30s beat is a
/// traffic-analysis fingerprint, and 30s is a common UDP NAT mapping timeout on Linux, so Go keeps
/// every interval strictly under it. A real `tailscaled` shows a jittered ~23s mean here, not a
/// deterministic 30.0s tick.
const STUN_PROBE_INTERVAL_MIN: Duration = Duration::from_secs(20);
const STUN_PROBE_INTERVAL_MAX: Duration = Duration::from_secs(26);

/// A uniform random delay in `[STUN_PROBE_INTERVAL_MIN, STUN_PROBE_INTERVAL_MAX)`, the analog of Go
/// `tstime.RandomDurationBetween(min, max)` (`min + rand.N(max-min)`): both are uniform over the
/// half-open interval. Uses the non-crypto thread RNG (`rand`), like the other timing jitters in this
/// crate (e.g. the multiderp reconnect backoff) — this is timing jitter, not key material, so it
/// deliberately does not use the ring/crypto RNG.
///
/// `random_range` panics on an empty range, so the bounds must stay ordered `MIN < MAX` (they are
/// distinct compile-time constants today). If these ever become equal or runtime-configurable, guard
/// the `MIN == MAX` case first (Go's `RandomDurationBetween` returns `min` there rather than panicking).
fn stun_probe_delay() -> Duration {
    rand::random_range(STUN_PROBE_INTERVAL_MIN..STUN_PROBE_INTERVAL_MAX)
}

/// How often to re-evaluate our own candidate endpoints and (if changed) advertise them to
/// control. Reflexive addresses accrue asynchronously as disco pongs arrive, so we poll and
/// only publish when the set actually differs from what we last advertised.
const ADVERTISE_INTERVAL: Duration = Duration::from_secs(5);

/// Our magicsock candidate endpoints, published for [`crate::control_runner::ControlRunner`] to
/// forward to the control server so peers can learn where to attempt direct connections.
///
/// All addresses originate from the single bound underlay socket — there is no second egress.
#[derive(Clone)]
pub struct EndpointAdvertisement {
    pub endpoints: Arc<Vec<SelfEndpoint>>,
}

/// The IPv4 bind address for the direct underlay socket (unit tests).
///
/// IPv4-only and ephemeral-port: per the anti-leak rules this socket is the only egress path for
/// the direct underlay, and IPv6 is disabled in our default deployment. The production bind no
/// longer parses this string (it constructs the address from
/// [`Ipv4Addr::UNSPECIFIED`](core::net::Ipv4Addr) and the resolved port in [`bind_underlay_addr`]);
/// the constant is retained as the canonical `0.0.0.0:0` literal the socket tests bind directly.
#[cfg(test)]
const BIND_ADDR: &str = "0.0.0.0:0";

/// Bind a [`MagicSock`] to the given UNSPECIFIED-address family at `listen_port`, falling back to an
/// OS-chosen ephemeral port (`:0`) if `listen_port` is non-zero and already taken.
///
/// The single port-collision fallback the initial bind shares with [`rebind_socket`]'s
/// `Err(_) if prefer_port != 0 => bind(0)`: a pinned [`Config::wireguard_listen_port`] that happens
/// to be taken must not fail bring-up. `listen_port == 0` (ephemeral) needs no fallback — there is
/// nothing more permissive to retry — so its error propagates unchanged. `our_disco` is cloned per
/// attempt because [`MagicSock::bind`] consumes it (it is no longer `Copy`); `our_node_key` is a
/// `Copy` public key.
async fn bind_unspecified_with_fallback(
    ip: core::net::IpAddr,
    listen_port: u16,
    our_disco: &ts_keys::DiscoPrivateKey,
    our_node_key: NodePublicKey,
) -> Result<MagicSock, ts_magicsock::Error> {
    let pinned = SocketAddr::new(ip, listen_port);
    match MagicSock::bind(pinned, our_disco.clone(), our_node_key).await {
        Ok(sock) => Ok(sock),
        // Pinned port taken (or otherwise unbindable): fall back to an ephemeral port so a port
        // collision never takes the node down. Only when a port was actually pinned.
        Err(_) if listen_port != 0 => {
            tracing::warn!(
                %pinned,
                "underlay bind on pinned port failed; falling back to an ephemeral port",
            );
            MagicSock::bind(SocketAddr::new(ip, 0), our_disco.clone(), our_node_key).await
        }
        Err(e) => Err(e),
    }
}

/// Choose the underlay UDP socket and the address it bound to, honoring the (default-off)
/// `enable_ipv6` overlay gate and the (default-ephemeral) `listen_port` pin.
///
/// `listen_port` is [`Config::wireguard_listen_port`](ts_control::Config::wireguard_listen_port)
/// resolved to a `u16` (`0` = OS-chosen ephemeral, today's behavior; non-zero = pin that port with
/// an ephemeral fallback if it is taken — see [`bind_unspecified_with_fallback`]). It governs only
/// the bound port; the bind *family* still follows `enable_ipv6`:
///
/// - `enable_ipv6 == false` (default): bind `0.0.0.0:listen_port` (`0.0.0.0:0` = byte-for-byte the
///   historical IPv4-only ephemeral path). This upholds the sacred IPv4-only invariant of the
///   privacy-proxy deployment.
/// - `enable_ipv6 == true`: attempt a dual-stack bind on `[::]:listen_port` so a single socket
///   serves both native v6 and v4-mapped traffic. **Fail inert, never panic**: if the v6 bind fails
///   (e.g. a host with `net.ipv6.conf.all.disable_ipv6=1`), warn and fall back to the IPv4 bind so
///   the node still comes up — protective if the gate is mis-flagged on a hardened box.
///
/// A successful pinned port carries across a later [`MagicSock::rebind`], which re-prefers the
/// socket's current local port.
///
/// NOTE (dep gap reported to the architect): [`MagicSock::bind`] takes only a [`SocketAddr`] and
/// constructs the `tokio::net::UdpSocket` itself, so this site cannot set `IPV6_V6ONLY` explicitly
/// (that would require `socket2::Socket`/`libc`, neither of which is a dependency of `ts_runtime`,
/// or a change to `ts_magicsock`). The dual-stack socket therefore relies on the kernel's
/// `IPV6_V6ONLY` default, which is dual-stack on Linux (our deployment) but v6-only on macOS. To
/// force `set_only_v6(false)` portably, either `socket2` must become a dependency or `MagicSock`
/// must expose a bind that accepts a pre-configured socket.
async fn bind_underlay_addr(
    enable_ipv6: bool,
    listen_port: u16,
    our_disco: ts_keys::DiscoPrivateKey,
    our_node_key: NodePublicKey,
) -> Result<MagicSock, ts_magicsock::Error> {
    use core::net::{Ipv4Addr, Ipv6Addr};

    // IPv4-only default: the historical family, now honoring the pinned port (`0` = ephemeral, i.e.
    // byte-for-byte the original `0.0.0.0:0`).
    if !enable_ipv6 {
        return bind_unspecified_with_fallback(
            Ipv4Addr::UNSPECIFIED.into(),
            listen_port,
            &our_disco,
            our_node_key,
        )
        .await;
    }

    // Overlay IPv6 enabled: try the dual-stack bind (same port pin + ephemeral fallback) first.
    match bind_unspecified_with_fallback(
        Ipv6Addr::UNSPECIFIED.into(),
        listen_port,
        &our_disco,
        our_node_key,
    )
    .await
    {
        Ok(sock) => Ok(sock),
        Err(e) => {
            // Inert fallback: the host likely has IPv6 disabled at the kernel. Come up IPv4-only
            // (still honoring the pinned port) rather than crash — protective on a hardened proxy
            // box even if the gate is set.
            tracing::warn!(
                error = %e,
                "dual-stack underlay bind failed (host IPv6 disabled?); falling back to IPv4-only",
            );
            bind_unspecified_with_fallback(
                Ipv4Addr::UNSPECIFIED.into(),
                listen_port,
                &our_disco,
                our_node_key,
            )
            .await
        }
    }
}

/// Owns the direct (disco) UDP underlay and bridges it to the dataplane.
///
/// `sock`/`transport_id` are `Option`: if the underlay UDP socket fails to bind at startup the
/// manager stays **inert** (both `None`) rather than panicking, and the runtime continues
/// DERP-only. DERP-only is the anti-leak-safe fallback — there is simply no direct path to offer,
/// so no peer is ever upgraded off DERP and the real origin IP cannot leak.
pub struct DirectManager {
    sock: Option<Arc<MagicSock>>,
    transport_id: Option<UnderlayTransportId>,
    peer_db: Arc<RwLock<Option<Arc<PeerDb>>>>,
    /// Retained so the `RebindAndReprobe` handler can fetch the current v4 STUN servers
    /// ([`Multiderp::stun_servers_v4`]) and fire an immediate STUN sweep right after the rebind —
    /// the same source the periodic [`run_stun_prober`] uses. Held here (not just cloned into the
    /// prober task) because the on-demand sweep runs inside the actor handler.
    multiderp: ActorRef<Multiderp>,
    #[allow(dead_code)]
    tasks: JoinSet<()>,
}

#[kameo::messages]
impl DirectManager {
    /// The id of the single direct underlay transport registered with the dataplane.
    ///
    /// `Some` once the actor has started and the underlay socket bound; `None` if the bind failed
    /// at startup, in which case the route updater stays DERP-only (fail-closed). The `Option`
    /// also satisfies kameo's `Reply` bound (a bare newtype is not a reply).
    #[message]
    pub fn direct_transport_id(&self) -> Option<UnderlayTransportId> {
        self.transport_id
    }

    /// Of the given peers, the current trusted direct UDP endpoint (`MagicSock::best_addr`) for each
    /// that has one — Go's per-peer `CurAddr`. A peer appears in the map only if its disco key is
    /// known and `best_addr` returns `Some` right now (live query — never cached — so trust expiry
    /// downgrades immediately); an absent peer is relayed via DERP.
    #[message]
    pub fn best_addrs(&self, ids: Vec<PeerId>) -> HashMap<PeerId, SocketAddr> {
        let mut addrs = HashMap::new();

        // No bound underlay socket (bind failed => inert, DERP-only): no peer has a direct path.
        let Some(sock) = self.sock.as_ref() else {
            return addrs;
        };

        let db = poisoned_read(&self.peer_db);
        let Some(db) = db.as_ref() else {
            return addrs;
        };

        for id in ids {
            let Some((_, node)) = db.get(&id) else {
                continue;
            };
            let Some(disco) = node.disco_key else {
                continue;
            };
            if let Some(addr) = sock.best_addr(&disco) {
                addrs.insert(id, addr);
            }
        }

        addrs
    }

    /// The current trusted direct endpoint **and its last-measured RTT** for the peer with this
    /// disco key, or `None` if it has no direct path right now (relayed via DERP, or the underlay is
    /// inert). The latency is the most recent confirming pong's RTT — up to one probe interval
    /// stale, not a fresh on-demand measurement. Keyed by disco (the caller resolves the peer's
    /// disco key from its node) so no `PeerId`↔node-id ambiguity enters here. Backs `Device`'s
    /// direct-path report.
    #[message]
    pub fn direct_path_latency(&self, disco: DiscoPublicKey) -> Option<(SocketAddr, Duration)> {
        self.sock.as_ref()?.best_addr_and_latency(&disco)
    }

    /// Hand out the underlay [`MagicSock`] handle (or `None` if the bind failed / inert DERP-only
    /// mode). This is a cheap synchronous clone so the caller can run an **awaiting** operation —
    /// `MagicSock::ping_now`, which sends a disco ping and awaits the pong for up to a timeout — OFF
    /// this actor's mailbox. Doing the await here (in a `#[message]`) would block the DirectManager
    /// for the whole ping timeout, serializing every other message behind it.
    #[message]
    pub fn sock_handle(&self) -> Option<Arc<MagicSock>> {
        self.sock.clone()
    }

    /// Of the given peers, return those that currently have a trusted direct path — the key set of
    /// [`best_addrs`](Self::best_addrs). A peer is included only if its disco key is known and
    /// [`MagicSock::best_addr`] returns `Some` for it right now (live query — never cached — so trust
    /// expiry downgrades immediately).
    #[message]
    pub fn peers_with_direct_path(&self, ids: Vec<PeerId>) -> HashSet<PeerId> {
        self.best_addrs(ids).into_keys().collect()
    }

    /// Re-bind the underlay UDP socket after a network/link change (the engine half of
    /// `Device::rebind`). Delegates to [`MagicSock::rebind`], which swaps the socket and resets the
    /// stale local mapping (clears reflexive + confirmed best paths, keeps candidates) so peers
    /// re-probe over the new socket and fail closed to DERP meanwhile. No-op (`Ok`) when the underlay
    /// bind failed at startup (DERP-only inert mode — there is no socket to rebind).
    #[message]
    pub async fn rebind(&self) -> Result<(), ts_magicsock::Error> {
        match self.sock.as_ref() {
            Some(sock) => sock.rebind().await,
            None => Ok(()),
        }
    }

    /// Re-bind the underlay socket AND immediately re-probe connectivity, atomically in the actor —
    /// the auto-recovery path the [`NetmonSupervisor`](crate::netmon::NetmonSupervisor) fires on a
    /// coalesced link change. This is the engine half of "react to a network change": after a Wi-Fi
    /// switch / sleep-wake the old socket's NAT mapping and learned paths are stale, and the bare
    /// [`rebind`](Self::rebind) only swaps the socket then waits out the periodic ping (2s) / STUN
    /// (~23s) timers before anything re-confirms. This message collapses that wait:
    ///
    /// 1. [`MagicSock::rebind`] — swap the socket; clear reflexive + every confirmed best path
    ///    (keeping candidates), so peers fail closed to DERP and re-probe over the new socket.
    /// 2. [`MagicSock::send_pings`] — re-ping all candidates **now** on the freshly-swapped socket,
    ///    so a still-reachable peer re-confirms its direct path immediately instead of after up to a
    ///    full `PING_INTERVAL`.
    /// 3. An immediate STUN sweep to the derp map's v4 STUN servers (same source + gate as the
    ///    periodic [`run_stun_prober`]): re-learn our reflexive/public address on the new socket
    ///    now, rather than waiting out the jittered ~23s timer.
    ///
    /// Doing all three inside the actor handler keeps them ordered and race-free against the
    /// periodic pinger/prober (the actor processes one message at a time). A no-op (`Ok`) when the
    /// underlay bind failed at startup (DERP-only inert mode — there is no socket to rebind/probe).
    /// The STUN sweep is best-effort and never fails the message: if multiderp is unavailable or the
    /// peer-count gate is closed it is simply skipped (pong-harvest still re-learns reflexives as
    /// the re-ping pongs arrive), mirroring how [`run_stun_prober`] treats those cases.
    ///
    /// The bare [`rebind`](Self::rebind) message and the `Device::rebind` path are left UNCHANGED so
    /// a manual embedder's rebind stays a first-class, probe-free socket swap.
    #[message]
    pub async fn rebind_and_reprobe(&self) -> Result<(), ts_magicsock::Error> {
        let Some(sock) = self.sock.as_ref() else {
            // Inert / DERP-only: nothing to rebind or probe.
            return Ok(());
        };

        // 1. Swap the socket + reset stale local mapping (clears best paths, keeps candidates).
        sock.rebind().await?;

        // 2. Re-ping all candidates now on the new socket (every best is None post-rebind, so this
        //    re-pings everything under the normal cadence gates). A send error is non-fatal: the
        //    periodic pinger backstops it.
        if let Err(e) = sock.send_pings().await {
            tracing::trace!(error = %e, "rebind-and-reprobe: re-ping after rebind");
        }

        // 3. Immediate STUN sweep on the new socket, gated exactly like the periodic prober (skip
        //    while there are no peers — Go's len(peerSet)==0 stop). Best-effort throughout: a stale
        //    derp/multiderp or empty server list just skips this round; pong-harvest from the
        //    re-pings above still re-learns reflexives.
        self.stun_sweep_once(sock).await;

        Ok(())
    }

    /// Force an immediate STUN/endpoint re-probe **without** rebinding the underlay socket — the
    /// engine half of `Device::re_stun` (Go magicsock's `Conn.ReSTUN`). This is the STUN sweep of
    /// [`rebind_and_reprobe`](Self::rebind_and_reprobe) (step 3) on its own: it does NOT swap the
    /// socket and does NOT re-ping peers, so the existing socket, its NAT mapping, and every learned
    /// path are preserved — it only re-learns our reflexive (public) address right now instead of
    /// waiting out the jittered ~23s periodic [`run_stun_prober`] timer.
    ///
    /// Lighter than [`rebind`](Self::rebind)/[`rebind_and_reprobe`](Self::rebind_and_reprobe): use it
    /// when our public endpoint may have changed (e.g. a NAT rebinding) but the socket itself is
    /// fine. A no-op (`Ok`) when the underlay bind failed at startup (DERP-only inert mode — no
    /// socket to probe from). Best-effort and gated exactly like the periodic prober (skipped while
    /// there are no peers — Go's `len(peerSet)==0` stop): a stale derp/multiderp or empty server list
    /// simply skips this round.
    #[message]
    pub async fn re_stun(&self) -> Result<(), ts_magicsock::Error> {
        let Some(sock) = self.sock.as_ref() else {
            // Inert / DERP-only: no socket to STUN from.
            return Ok(());
        };
        self.stun_sweep_once(sock).await;
        Ok(())
    }

    /// One immediate STUN sweep from the bound socket, gated like the periodic prober (skip while
    /// there are no peers — Go's `len(peerSet)==0` stop). Best-effort: a stale/unavailable multiderp
    /// or an empty v4-STUN-server list just skips this round (pong-harvest still re-learns
    /// reflexives). Shared by [`rebind_and_reprobe`](Self::rebind_and_reprobe) (after the rebind +
    /// re-ping) and [`re_stun`](Self::re_stun) (on its own, no rebind), so the gate + server fetch +
    /// per-server fan-out live in one place.
    async fn stun_sweep_once(&self, sock: &MagicSock) {
        if stun_probe_should_run(&self.peer_db) {
            match self.multiderp.ask(multiderp::StunServersV4).await {
                Ok((servers,)) => probe_stun_servers_once(sock, &servers).await,
                Err(e) => {
                    tracing::trace!(error = %e, "stun sweep: querying stun servers");
                }
            }
        }
    }
}

/// The disco<->node-key binding verifier installed on the [`MagicSock`] (see
/// [`ts_magicsock::BindingVerifier`]). A live read of the peer db (it is replaced as netmaps
/// arrive), so revocations take effect immediately.
///
/// - For a disco **Ping** (`claimed_node_key == Some`): returns `true` only if a peer with this
///   disco key exists in the netmap *and* its control-advertised node key equals the claimed one.
///   A peer must not open a direct path under a node key control did not bind to its disco key.
/// - For a **CallMeMaybe** (`claimed_node_key == None`, no node key on the wire): returns `true`
///   only if the disco key is a current netmap member. This stops an unknown/spoofed disco key
///   from steering us into host-probing attacker-chosen endpoints.
fn verify_binding(
    peer_db: &RwLock<Option<Arc<PeerDb>>>,
    disco: &DiscoPublicKey,
    claimed_node_key: Option<&NodePublicKey>,
) -> bool {
    let db = poisoned_read(peer_db);
    let Some(db) = db.as_ref() else {
        return false;
    };
    let Some((_, node)) = db.get(disco) else {
        return false;
    };
    match claimed_node_key {
        // Ping: the claimed node key must be exactly the one control bound to this disco key.
        Some(claimed) => node.node_key == *claimed,
        // CallMeMaybe: membership is enough — the disco key resolving to a netmap peer above
        // already proves it.
        None => true,
    }
}

/// Read an [`RwLock`] guarding the peer db, recovering from poisoning rather than propagating the
/// panic. The peer db is a snapshot replaced wholesale on each netmap update with no cross-field
/// invariant a mid-write panic could leave half-applied, so reading the inner value is safe. A
/// single panic while a writer held this lock must not poison it and cascade-kill the pinger, the
/// binding verifier, and the relayed-disco demux — that would take the dataplane down instead of
/// failing closed to DERP.
fn poisoned_read(
    lock: &RwLock<Option<Arc<PeerDb>>>,
) -> std::sync::RwLockReadGuard<'_, Option<Arc<PeerDb>>> {
    lock.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Write-lock counterpart of [`poisoned_read`]. Same rationale: recover the inner snapshot rather
/// than let one panicking writer poison the lock and cascade-kill every reader.
fn poisoned_write(
    lock: &RwLock<Option<Arc<PeerDb>>>,
) -> std::sync::RwLockWriteGuard<'_, Option<Arc<PeerDb>>> {
    lock.write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Bidirectional [`PeerId`] <-> [`DiscoPublicKey`] lookup backed by a snapshot of the peer db.
///
/// Uses the owned (`Arc<RwLock<...>>`) form rather than a borrow, because the direct socket
/// lives for the whole runtime and the lookup must outlive any single call.
struct DiscoPeerLookup(Arc<RwLock<Option<Arc<PeerDb>>>>);

impl PeerLookup<PeerId, DiscoPublicKey> for DiscoPeerLookup {
    fn lookup_key(&self, id: PeerId) -> Option<DiscoPublicKey> {
        let db = poisoned_read(&self.0);
        let db = db.as_ref()?;
        let (_, node) = db.get(&id)?;
        node.disco_key
    }
}

impl PeerLookup<DiscoPublicKey, PeerId> for DiscoPeerLookup {
    fn lookup_key(&self, key: DiscoPublicKey) -> Option<PeerId> {
        let db = poisoned_read(&self.0);
        let db = db.as_ref()?;
        let (id, _) = db.get(&key)?;
        Some(id)
    }
}

/// Bridge packets between the direct transport and the dataplane underlay channels.
///
/// A simplified [`crate::multiderp::run_derp_once`]: no reconnect or home-derp logic, because
/// the single UDP socket is always bound and never needs re-establishment.
async fn run_direct(
    transport: impl UnderlayTransport<PeerKey = PeerId, Error = ts_magicsock::Error>,
    mut from_dataplane: UnderlayFromDataplane,
    to_dataplane: UnderlayToDataplane,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    while !*shutdown.borrow() {
        tokio::select! {
            _ = shutdown.changed() => break,

            from_direct = transport.recv() => {
                for ret in from_direct.batch_iter() {
                    match ret {
                        Ok((peer_id, pkts)) => {
                            let pkts = pkts.into_iter().collect::<Vec<_>>();
                            if to_dataplane.send((peer_id, pkts)).is_err() {
                                tracing::error!("underlay receive channel closed");
                                return;
                            }
                        }
                        Err(e) => {
                            tracing::trace!(error = %e, "ignoring undecodable direct packet");
                        }
                    }
                }
            }

            from_net = from_dataplane.recv() => {
                let Some(from_net) = from_net else {
                    tracing::warn!("direct underlay queue closed");
                    break;
                };

                if let Err(e) = transport.send([from_net]).await {
                    tracing::trace!(error = %e, "sending direct packet");
                }
            }
        }
    }
}

/// Periodically (re)ping candidate endpoints to confirm and keep direct paths alive.
async fn run_pinger(sock: Arc<MagicSock>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(PING_INTERVAL);
    // If a tick is missed (e.g. send_pings ran long under load), space the next tick a full period
    // out rather than firing a burst of catch-up ticks back-to-back.
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    while !*shutdown.borrow() {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = interval.tick() => {
                if let Err(e) = sock.send_pings().await {
                    tracing::trace!(error = %e, "sending disco pings");
                }
            }
        }
    }
}

/// Periodically send active STUN Binding Requests to the derp map's STUN servers, learning our
/// reflexive (public) address even before any peer pongs.
///
/// Leak-safe by construction: every request is emitted from the *one* bound underlay socket (see
/// [`MagicSock::send_stun_request`]) and only FixedAddr-v4 STUN servers are targeted (UseDns
/// nodes are skipped by [`Multiderp::stun_servers_v4`] to avoid a DNS-leak / second egress). This
/// complements — does not replace — the disco pong-harvest reflexive path; if the derp map lists
/// no v4 STUN servers the request list is empty and we simply fall back to pong-harvest.
async fn run_stun_prober(
    sock: Arc<MagicSock>,
    peer_db: Arc<RwLock<Option<Arc<PeerDb>>>>,
    multiderp: ActorRef<Multiderp>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    // Re-randomize the delay every cycle (Go re-arms `periodicReSTUNTimer` with a fresh
    // `RandomDurationBetween(20s, 26s)` each time) rather than using a fixed `interval`, so the
    // sweep cadence is jittered and never a deterministic beat. No leading immediate sweep: the
    // disco pong-harvest path already learns reflexives from the first peer ping, so we wait a full
    // jittered delay before the first active sweep (matching Go, whose periodic timer is armed for a
    // future instant, not fired immediately).
    while !*shutdown.borrow() {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = tokio::time::sleep(stun_probe_delay()) => {
                // Skip the sweep while we have no peers (Go's peer-count stop condition — see
                // [`stun_probe_should_run`]). On-wire-equivalent to Go stopping its periodic timer,
                // and auto-resumes the moment a peer appears.
                if !stun_probe_should_run(&peer_db) {
                    continue;
                }

                // Best-effort: if multiderp is unavailable just skip this round (pong-harvest
                // still runs), matching how the other loops treat multiderp send errors.
                let servers = match multiderp.ask(multiderp::StunServersV4).await {
                    Ok((servers,)) => servers,
                    Err(e) => {
                        tracing::trace!(error = %e, "querying stun servers from multiderp");
                        continue;
                    }
                };
                probe_stun_servers_once(&sock, &servers).await;
            }
        }
    }
}

/// Whether the periodic STUN sweep should run this round — the fork's analog of Go magicsock's
/// `shouldDoPeriodicReSTUNLocked` peer-count gate (`len(c.peerSet) == 0` → don't STUN).
///
/// Returns `true` only when a netmap is loaded *and* it has at least one peer. STUN exists to keep
/// our NAT mapping open so peers can reach us directly; with no configured peer there is nobody to
/// reach, so the sweep is pure waste — and, more importantly for parity, a real `tailscaled` falls
/// quiet on STUN in that state (Go stops its `periodicReSTUNTimer`). A node that keeps emitting
/// Binding Requests every ~23s with no peer is a visible "no peer traffic but steady STUN"
/// fingerprint. This is the single highest-signal stop condition; Go's other three (idle past
/// `sessionActiveTimeout`, network-down/homeless, zero private key) need activity/network-state
/// plumbing the runtime does not have yet — and the zero-key case is structurally impossible here
/// (the socket is always bound with a real key before the prober is spawned).
///
/// Factored out of [`run_stun_prober`]'s loop so the gate is unit-testable without the actor/timer
/// machinery, mirroring [`probe_stun_servers_once`]. Uses the same `peer_db` snapshot discipline as
/// [`run_call_me_maybe`] (`poisoned_read`, fail-quiet when no netmap is loaded).
fn stun_probe_should_run(peer_db: &RwLock<Option<Arc<PeerDb>>>) -> bool {
    let db = poisoned_read(peer_db);
    db.as_ref().is_some_and(|db| !db.peers().is_empty())
}

/// Send one STUN Binding Request to each server in `servers` from the one bound socket.
///
/// Each send fails closed inside [`MagicSock::send_stun_request`] (a non-v4 server is refused, the
/// in-flight set is capped); a transient io error just skips that server for this round rather than
/// aborting the sweep. Factored out of [`run_stun_prober`]'s sweep loop so the per-sweep fan-out
/// (including the empty-list no-op when the derp map lists no FixedAddr-v4 STUN servers) is
/// unit-testable without the actor/timer machinery.
async fn probe_stun_servers_once(sock: &MagicSock, servers: &[SocketAddr]) {
    for &s in servers {
        if let Err(e) = sock.send_stun_request(s).await {
            tracing::trace!(error = %e, server = %s, "sending stun binding request");
        }
    }
}

/// Periodically re-evaluate our own candidate endpoints and publish them on the bus when they
/// change, so control can be told where peers may reach us directly. Only republishes on a real
/// change to avoid spamming control with redundant side-band map requests.
///
/// Reflexive (STUN-equivalent) endpoints come solely from the disco pong-harvest path on the one
/// bound socket (peers echo our public `src`); we deliberately do **not** run a netcheck-style
/// multi-socket prober for self-endpoint discovery. Such a prober binds its own sockets (including
/// an IPv6 `[::]:0` egress that violates the IPv4-only invariant), so its reflexive mapping would be
/// both a different NAT path and a potential IPv6 leak — which is why the old `ts_netcheck`
/// `StunProber` was removed entirely rather than left dormant in the production binary. Pong-harvest
/// is the leak-safe, parity-correct source for Tier 1.
async fn run_advertiser(
    sock: Arc<MagicSock>,
    env: Env,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(ADVERTISE_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last: Vec<SelfEndpoint> = Vec::new();

    while !*shutdown.borrow() {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = interval.tick() => {
                let mut eps = sock.self_endpoints();
                eps.sort_by_key(|e| (e.addr, e.ty as u8));
                if eps == last {
                    continue;
                }
                last = eps.clone();

                if let Err(e) = env
                    .publish(EndpointAdvertisement {
                        endpoints: Arc::new(eps),
                    })
                    .await
                {
                    tracing::error!(error = %e, "publishing endpoint advertisement");
                }
            }
        }
    }
}

/// Periodically send a `CallMeMaybe` over DERP to each peer that has no confirmed direct path
/// yet, prompting it to disco-ping our candidate endpoints so a direct path can open. Gated on
/// [`MagicSock::best_addr`] being `None`: once a path is confirmed we stop relaying to that peer,
/// so this never spams DERP for peers that are already direct.
///
/// We only target peers that have a disco key. The relay region is the peer's netmap home region
/// when control supplied one, else the inferred region from [`Multiderp::region_for_peer`] (an
/// observed route, or our own home region as a last resort) — the same connectivity-floor inference
/// the route updater uses, so a peer whose netmap carried no region can still be prompted to open a
/// direct path (issue #24: without this the WireGuard floor came up over DERP but the direct upgrade
/// was never even attempted for a no-region peer). The frame carries our
/// [`MagicSock::self_endpoints`] — the same set advertised to control — so no host-identifying
/// address beyond that is disclosed.
async fn run_call_me_maybe(
    sock: Arc<MagicSock>,
    peer_db: Arc<RwLock<Option<Arc<PeerDb>>>>,
    multiderp: ActorRef<Multiderp>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(ADVERTISE_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    while !*shutdown.borrow() {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = interval.tick() => {
                // A CallMeMaybe is only actionable to a remote peer if we have a reflexive
                // (STUN-discovered) candidate it can actually reach across the internet; a purely
                // local LAN address is useless to relay over DERP. Skip the whole cadence until we
                // have one, so peers that can never go direct don't incur perpetual relay load.
                // Snapshot self_endpoints once per tick (it locks the reflexive set internally).
                let have_reflexive = sock
                    .self_endpoints()
                    .iter()
                    .any(|e| e.ty == ts_magicsock::SelfEndpointType::Stun);
                if !have_reflexive {
                    continue;
                }

                // Snapshot the targets under the read lock, then release it before any await.
                // `region` is the netmap home region when control gave one, else `None` to be
                // resolved via the fallback below (outside the lock — it's an actor `ask`). We keep
                // the peer either way so a no-region peer is still prompted to go direct.
                let targets: Vec<(ts_keys::NodePublicKey, DiscoPublicKey, Option<ts_derp::RegionId>)> = {
                    let db = poisoned_read(&peer_db);
                    let Some(db) = db.as_ref() else { continue; };

                    db.peers()
                        .values()
                        .filter_map(|node| {
                            let disco = node.disco_key?;
                            // Only prompt peers that don't already have a confirmed direct path.
                            if sock.best_addr(&disco).is_some() {
                                return None;
                            }
                            Some((node.node_key, disco, node.derp_region))
                        })
                        .collect()
                };

                for (node_key, disco, netmap_region) in targets {
                    // Resolve the relay region: netmap home region, else the inferred fallback
                    // (observed route / our home region) — the same floor the route updater uses.
                    let region = match netmap_region {
                        Some(region) => Some(region),
                        None => {
                            // PeerId lookup + region inference both live in multiderp; ask it.
                            match multiderp.ask(multiderp::RegionForNode { node: node_key }).await {
                                Ok(region) => region,
                                Err(e) => {
                                    tracing::trace!(error = %e, "inferring call-me-maybe relay region");
                                    None
                                }
                            }
                        }
                    };
                    let Some(region) = region else {
                        // No region from netmap, no observed route, no home region yet: nothing to
                        // relay through this round. Recovered on the next cadence once one appears.
                        continue;
                    };

                    let frame = match sock.seal_call_me_maybe(&disco) {
                        Ok(frame) => frame,
                        Err(e) => {
                            tracing::trace!(error = %e, "sealing call-me-maybe");
                            continue;
                        }
                    };

                    if let Err(e) = multiderp
                        .tell(multiderp::SendDisco {
                            peer: node_key,
                            region,
                            frame,
                        })
                        .await
                    {
                        tracing::trace!(error = %e, "relaying call-me-maybe to multiderp");
                    }
                }
            }
        }
    }
}

impl kameo::Actor for DirectManager {
    type Args = (Env, ActorRef<DataplaneActor>, ActorRef<Multiderp>);
    type Error = Error;

    async fn on_start(
        (env, dataplane, multiderp): Self::Args,
        slf: ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        env.subscribe::<Arc<PeerState>>(&slf).await?;

        let peer_db: Arc<RwLock<Option<Arc<PeerDb>>>> = Default::default();
        let mut tasks = JoinSet::new();

        // The disco<->node-key binding verifier: an inbound disco ping must present the node key
        // control bound to its disco key, or `handle_disco` drops it (fail closed). Closed over a
        // live handle to `peer_db` so it tracks netmap changes (revocations take effect at once).
        let verifier_db = peer_db.clone();
        let binding_verifier: BindingVerifier = Arc::new(move |disco, claimed_node_key| {
            verify_binding(&verifier_db, disco, claimed_node_key)
        });

        // Bind the direct underlay UDP socket. A bind failure is transient/environmental (e.g. no
        // ephemeral ports available); rather than panicking the actor we degrade to **DERP-only**
        // and stay inert. DERP-only is the anti-leak-safe fallback (no direct path is ever offered,
        // so the real origin IP can't leak), mirroring the MagicDNS responder's bind-failure
        // posture. The route updater treats a `None` transport id as "stay on DERP" (fail-closed).
        //
        // `enable_ipv6` (default `false`) gates the bind family: IPv4-only `0.0.0.0:0` historically,
        // or a dual-stack `[::]:0` with an inert IPv4 fallback when the overlay opts into IPv6. See
        // [`bind_underlay_addr`].
        let sock = match bind_underlay_addr(
            env.enable_ipv6,
            // The pinned WireGuard/disco port (`Config::wireguard_listen_port`), or `0` for an
            // OS-chosen ephemeral port (today's default). A pinned-but-taken port falls back to
            // ephemeral inside `bind_underlay_addr` so a collision never fails bring-up.
            env.wireguard_listen_port.unwrap_or(0),
            // `.clone()`: the disco private key is no longer `Copy` and `env` is shared (`Arc`),
            // so clone it out for the bind. `node_keys.public` is a `Copy` public key.
            env.keys.disco_keys.private.clone(),
            env.keys.node_keys.public,
        )
        .await
        {
            Ok(sock) => Arc::new(
                sock.with_enable_ipv6(env.enable_ipv6)
                    .with_binding_verifier(binding_verifier),
            ),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    enable_ipv6 = env.enable_ipv6,
                    "direct underlay udp bind failed; direct manager inert, staying DERP-only",
                );
                return Ok(Self {
                    sock: None,
                    transport_id: None,
                    peer_db,
                    multiderp,
                    tasks,
                });
            }
        };

        let (transport_id, from_dataplane, to_dataplane) =
            dataplane.ask(NewUnderlayTransport).await?;

        let transport =
            DirectTransport::new(sock.clone()).with_key_lookup(DiscoPeerLookup(peer_db.clone()));

        tasks.spawn(run_direct(
            transport,
            from_dataplane,
            to_dataplane,
            env.shutdown.clone(),
        ));
        tasks.spawn(run_pinger(sock.clone(), env.shutdown.clone()));
        tasks.spawn(run_advertiser(
            sock.clone(),
            env.clone(),
            env.shutdown.clone(),
        ));
        // Active STUN probing shares the one bound socket; clone the multiderp ref before it is
        // moved into run_call_me_maybe below. `peer_db` is cloned so the prober can skip the sweep
        // while there are no peers (Go's `shouldDoPeriodicReSTUNLocked` peer-count stop condition).
        tasks.spawn(run_stun_prober(
            sock.clone(),
            peer_db.clone(),
            multiderp.clone(),
            env.shutdown.clone(),
        ));

        // Hand the bound socket to multiderp so a peer's `CallMeMaybe` relayed to us over DERP is
        // demuxed into the magicsock (and can open a direct path) instead of being forwarded to the
        // dataplane as junk. Best-effort: if multiderp has stopped we stay relay-blind for inbound
        // CallMeMaybe but everything else is unaffected.
        if let Err(e) = multiderp
            .tell(multiderp::SetDirectSock { sock: sock.clone() })
            .await
        {
            tracing::warn!(error = %e, "could not install direct socket on multiderp");
        }

        // Clone for the struct field (the on-demand STUN sweep in `RebindAndReprobe` needs it)
        // before `run_call_me_maybe` consumes the original.
        let multiderp_for_field = multiderp.clone();
        tasks.spawn(run_call_me_maybe(
            sock.clone(),
            peer_db.clone(),
            multiderp,
            env.shutdown.clone(),
        ));

        Ok(Self {
            sock: Some(sock),
            transport_id: Some(transport_id),
            peer_db,
            multiderp: multiderp_for_field,
            tasks,
        })
    }
}

impl Message<Arc<PeerState>> for DirectManager {
    type Reply = ();

    async fn handle(&mut self, msg: Arc<PeerState>, _ctx: &mut Context<Self, Self::Reply>) {
        // Reconcile, don't just add: control is authoritative for each peer's underlay endpoints,
        // so an address it stops advertising must be pruned (otherwise a revoked/reassigned addr
        // stays a ping candidate forever and could be re-confirmed as a direct path). Peers that
        // leave the netmap entirely are dropped so both path and attribution maps stay bounded.
        //
        // When the underlay bind failed at startup (`sock == None`) we're inert/DERP-only: there is
        // no socket to reconcile endpoints against, so skip it. We still keep `peer_db` current for
        // any other consumers and so the manager recovers no worse than the route-updater's
        // DERP-only path.
        if let Some(sock) = self.sock.as_ref() {
            let mut live = HashSet::new();
            for node in msg.peers.peers().values() {
                let Some(disco) = node.disco_key else {
                    continue;
                };
                live.insert(disco);
                sock.set_netmap_endpoints(disco, node.underlay_addresses.iter().copied());
            }
            sock.retain_peers(&live);
        }

        let mut db = poisoned_write(&self.peer_db);
        *db = Some(msg.peers.clone());
    }
}

#[cfg(test)]
mod tests {
    use ts_control::{Node, StableNodeId, TailnetAddress};
    use ts_keys::{DiscoPrivateKey, NodePrivateKey};

    use super::*;
    use crate::peer_tracker::PeerDb;

    /// Build a minimal netmap peer with the given disco and node keys.
    fn node_with_keys(disco: DiscoPublicKey, node_key: NodePublicKey, stable: &str) -> Node {
        Node {
            id: 1,
            stable_id: StableNodeId(stable.to_string()),
            hostname: "peer".to_string(),
            user_id: 0,
            tailnet: Some("ts.net".to_string()),
            tags: vec![],
            tailnet_address: TailnetAddress {
                ipv4: "100.64.0.9/32".parse().unwrap(),
                ipv6: "fd7a::9/128".parse().unwrap(),
            },
            node_key,
            node_key_expiry: None,
            online: None,
            last_seen: None,
            key_signature: vec![],
            machine_key: None,
            disco_key: Some(disco),
            accepted_routes: vec![],
            underlay_addresses: vec![],
            derp_region: None,
            cap: Default::default(),
            cap_map: Default::default(),
            peerapi_port: None,
            peerapi_dns_proxy: false,
            is_wireguard_only: false,
            exit_node_dns_resolvers: vec![],
            peer_relay: false,
            ssh_host_keys: vec![],
            service_vips: Default::default(),
        }
    }

    fn db_with(node: Node) -> Arc<RwLock<Option<Arc<PeerDb>>>> {
        let mut db = PeerDb::default();
        db.upsert(&node);
        Arc::new(RwLock::new(Some(Arc::new(db))))
    }

    /// A Ping whose claimed node key matches the netmap binding is accepted; a mismatched node key
    /// (or unknown disco key, or empty netmap) is rejected. This is the disco<->node-key binding
    /// check that stops a peer opening a direct path under a node key control did not bind to it.
    #[test]
    fn verify_binding_ping_requires_exact_node_key() {
        let disco = DiscoPrivateKey::random().public_key();
        let node_key = NodePrivateKey::random().public_key();
        let other_key = NodePrivateKey::random().public_key();

        let db = db_with(node_with_keys(disco, node_key, "n1"));

        assert!(
            verify_binding(&db, &disco, Some(&node_key)),
            "correct disco<->node-key binding must be accepted"
        );
        assert!(
            !verify_binding(&db, &disco, Some(&other_key)),
            "a claimed node key that is not the bound one must be rejected"
        );

        let unknown_disco = DiscoPrivateKey::random().public_key();
        assert!(
            !verify_binding(&db, &unknown_disco, Some(&node_key)),
            "a disco key not in the netmap must be rejected"
        );

        let empty: Arc<RwLock<Option<Arc<PeerDb>>>> = Default::default();
        assert!(
            !verify_binding(&empty, &disco, Some(&node_key)),
            "with no netmap loaded the verifier fails closed"
        );
    }

    /// A CallMeMaybe carries no node key (claimed=None): membership is sufficient. A member disco
    /// key is accepted; a stranger disco key is rejected. This stops a spoofed disco key from
    /// steering us into host-probing attacker-chosen endpoints.
    #[test]
    fn verify_binding_call_me_maybe_is_membership_only() {
        let disco = DiscoPrivateKey::random().public_key();
        let node_key = NodePrivateKey::random().public_key();

        let db = db_with(node_with_keys(disco, node_key, "n1"));

        assert!(
            verify_binding(&db, &disco, None),
            "a netmap-member disco key must be accepted for a CallMeMaybe"
        );

        let stranger = DiscoPrivateKey::random().public_key();
        assert!(
            !verify_binding(&db, &stranger, None),
            "a non-member disco key must be rejected for a CallMeMaybe"
        );
    }

    /// One probe round to a v4 STUN server emits a well-formed STUN Binding Request from the one
    /// bound underlay socket: 20 bytes, message type `0x0001`, magic cookie `0x2112A442`. This
    /// pins the per-tick fan-out that `run_stun_prober` drives, independent of the interval/actor
    /// machinery.
    #[tokio::test]
    async fn probe_stun_servers_once_sends_binding_request() {
        let sock = Arc::new(
            MagicSock::bind(
                BIND_ADDR.parse().unwrap(),
                DiscoPrivateKey::random(),
                NodePrivateKey::random().public_key(),
            )
            .await
            .unwrap(),
        );

        // A real local v4 sink so the request is actually delivered and observable.
        let sink = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server: SocketAddr = sink.local_addr().unwrap();

        probe_stun_servers_once(&sock, &[server]).await;

        let mut buf = [0u8; 64];
        let (n, _from) = tokio::time::timeout(Duration::from_secs(2), sink.recv_from(&mut buf))
            .await
            .expect("a STUN binding request must arrive at the v4 server")
            .unwrap();

        // A STUN Binding Request is 40 bytes: the 20-byte header + SOFTWARE("tailnode") +
        // FINGERPRINT, matching Go net/stun.Request (a bare header is rejected by Tailscale's DERP
        // STUN servers as ErrWrongSoftware). See ts_magicsock::stun::encode_binding_request.
        assert_eq!(
            n, 40,
            "a STUN Binding Request is the 40-byte SOFTWARE+FINGERPRINT form"
        );
        assert_eq!(
            &buf[0..2],
            &0x0001u16.to_be_bytes(),
            "message type must be Binding Request (0x0001)"
        );
        assert_eq!(
            &buf[2..4],
            &0x0014u16.to_be_bytes(),
            "message length must be 0x0014 (the 20 trailing attribute bytes)"
        );
        assert_eq!(
            &buf[4..8],
            &0x2112_A442u32.to_be_bytes(),
            "the STUN magic cookie must be present at bytes[4..8]"
        );
        // SOFTWARE attribute: type 0x8022, len 8, value "tailnode".
        assert_eq!(
            &buf[20..22],
            &0x8022u16.to_be_bytes(),
            "SOFTWARE attribute type"
        );
        assert_eq!(&buf[24..32], b"tailnode", "SOFTWARE value must be tailnode");
        // FINGERPRINT attribute: type 0x8028, len 4.
        assert_eq!(
            &buf[32..34],
            &0x8028u16.to_be_bytes(),
            "FINGERPRINT attribute type"
        );
    }

    /// With `enable_ipv6 == false` (the default) the underlay socket binds the historical IPv4
    /// path: its local address is in the v4 family (`0.0.0.0`). This pins the sacred default — the
    /// privacy-proxy deployment must stay byte-for-byte IPv4-only when the gate is off.
    #[tokio::test]
    async fn bind_underlay_addr_v4_default_is_unchanged() {
        let sock = bind_underlay_addr(
            false,
            0,
            DiscoPrivateKey::random(),
            NodePrivateKey::random().public_key(),
        )
        .await
        .expect("the IPv4 underlay bind must succeed");

        let local = sock.local_addr().expect("a bound socket has a local addr");
        assert!(
            local.is_ipv4(),
            "with enable_ipv6 == false the underlay must bind the v4 family, got {local}"
        );
        assert_eq!(
            local.ip(),
            "0.0.0.0".parse::<core::net::IpAddr>().unwrap(),
            "the v4 default binds the unspecified v4 address"
        );
    }

    /// A pinned `wireguard_listen_port` (Go `--port`) binds exactly that UDP port when it is free —
    /// the stable-endpoint behavior an operator behind a fixed-pinhole firewall needs. Uses a port
    /// the OS just handed out (then released) to avoid colliding with anything already bound.
    #[tokio::test]
    async fn bind_underlay_addr_pins_requested_port_when_free() {
        // Grab an OS-assigned port, then release it so we can pin it deterministically.
        let probe = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let want = probe.local_addr().unwrap().port();
        drop(probe);

        let sock = bind_underlay_addr(
            false,
            want,
            DiscoPrivateKey::random(),
            NodePrivateKey::random().public_key(),
        )
        .await
        .expect("pinned-port underlay bind must succeed");

        let local = sock.local_addr().expect("a bound socket has a local addr");
        assert!(local.is_ipv4(), "still the v4 family, got {local}");
        assert_eq!(
            local.port(),
            want,
            "a free pinned port must be bound exactly (got {local})"
        );
    }

    /// A pinned port that is already taken must NOT fail bring-up: the bind falls back to an
    /// OS-chosen ephemeral port (mirroring `rebind_socket`'s `Err(_) if prefer_port != 0 => bind(0)`
    /// fallback), so a port collision can never take the node down. The bound port ends up different
    /// from the (occupied) pinned one.
    #[tokio::test]
    async fn bind_underlay_addr_falls_back_to_ephemeral_when_port_taken() {
        // Occupy a port for the whole test so the pinned bind below must collide.
        let occupier = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let taken = occupier.local_addr().unwrap().port();

        let sock = bind_underlay_addr(
            false,
            taken,
            DiscoPrivateKey::random(),
            NodePrivateKey::random().public_key(),
        )
        .await
        .expect("a taken pinned port must fall back to ephemeral, never error");

        let local = sock.local_addr().expect("a bound socket has a local addr");
        assert!(local.is_ipv4(), "still the v4 family, got {local}");
        assert_ne!(
            local.port(),
            taken,
            "the occupied port must not be bound; an ephemeral port is used instead"
        );
        assert_ne!(local.port(), 0, "a real ephemeral port must be assigned");
        drop(occupier);
    }

    /// With `enable_ipv6 == true` a dual-stack bind on `[::]:0` is attempted. On a normal dev host
    /// that yields a v6-family socket; if this environment cannot bind v6 at all, the documented
    /// inert fallback returns a v4 socket instead (never a panic, never an error). Either outcome is
    /// acceptable here — the non-flaky guarantee is that a usable socket comes back. The positive
    /// "is v6" assertion is gated on the v6 bind actually succeeding so CI without v6 loopback
    /// doesn't flake.
    #[tokio::test]
    async fn bind_underlay_addr_v6_attempts_dual_stack_or_falls_back() {
        let sock = bind_underlay_addr(
            true,
            0,
            DiscoPrivateKey::random(),
            NodePrivateKey::random().public_key(),
        )
        .await
        .expect("bind must succeed (dual-stack, else inert IPv4 fallback) and never error");

        let local = sock.local_addr().expect("a bound socket has a local addr");

        // Probe whether this host can bind `[::]:0` at all. If it can, the underlay must have taken
        // the dual-stack (v6-family) path; if it can't, the inert fallback must have produced a v4
        // socket. This keeps the assertion deterministic on both v6-capable and v6-disabled hosts.
        match tokio::net::UdpSocket::bind("[::]:0").await {
            Ok(_) => assert!(
                local.is_ipv6(),
                "on a v6-capable host enable_ipv6 == true must bind the v6 (dual-stack) family, \
                 got {local}"
            ),
            Err(_) => assert!(
                local.is_ipv4(),
                "on a host that cannot bind v6 the inert fallback must yield a v4 socket, got \
                 {local}"
            ),
        }
    }

    /// An empty server list (the derp map lists no FixedAddr-v4 STUN servers) is a no-op: nothing is
    /// sent and we silently fall back to pong-harvest. Probing must not require a STUN server.
    #[tokio::test]
    async fn probe_stun_servers_once_empty_list_is_noop() {
        let sock = Arc::new(
            MagicSock::bind(
                BIND_ADDR.parse().unwrap(),
                DiscoPrivateKey::random(),
                NodePrivateKey::random().public_key(),
            )
            .await
            .unwrap(),
        );

        // No servers => no sends, no panic, returns promptly.
        probe_stun_servers_once(&sock, &[]).await;
    }

    /// The periodic STUN sweep is gated on having at least one peer — Go magicsock's
    /// `shouldDoPeriodicReSTUNLocked` `len(c.peerSet) == 0` stop condition. With no netmap loaded,
    /// or a netmap with zero peers, the gate is closed (no STUN, so no "peerless but steady STUN"
    /// fingerprint); once a peer is present it opens.
    #[test]
    fn stun_probe_gated_on_peer_presence() {
        // No netmap loaded yet → fail-quiet (closed), like `verify_binding`'s empty case.
        let empty: Arc<RwLock<Option<Arc<PeerDb>>>> = Default::default();
        assert!(
            !stun_probe_should_run(&empty),
            "with no netmap loaded the prober must not STUN"
        );

        // A netmap with zero peers → still closed.
        let no_peers: Arc<RwLock<Option<Arc<PeerDb>>>> =
            Arc::new(RwLock::new(Some(Arc::new(PeerDb::default()))));
        assert!(
            !stun_probe_should_run(&no_peers),
            "an empty peer set must not STUN (Go's len(peerSet)==0 stop)"
        );

        // One peer present → open.
        let disco = DiscoPrivateKey::random().public_key();
        let node_key = NodePrivateKey::random().public_key();
        let with_peer = db_with(node_with_keys(disco, node_key, "n1"));
        assert!(
            stun_probe_should_run(&with_peer),
            "with a peer present the prober resumes STUN"
        );
    }

    /// `re_stun` (Go `Conn.ReSTUN`) is the STUN sweep WITHOUT a rebind: its body is exactly the
    /// shared [`DirectManager::stun_sweep_once`] gate — skip while there are no peers (Go's
    /// `len(peerSet)==0` stop), otherwise fetch the v4 STUN servers and probe each. This pins the two
    /// gate decisions `re_stun` makes (the peer-presence gate it shares with the periodic prober, and
    /// the empty-server-list no-op), independent of the actor machinery — the same way the periodic
    /// prober's per-tick fan-out is pinned by [`probe_stun_servers_once_*`]. The inert (no-socket,
    /// DERP-only) path is the `self.sock.is_none()` early-return, structurally identical to
    /// [`DirectManager::rebind`]'s inert no-op.
    #[tokio::test]
    async fn re_stun_sweep_gate_matches_periodic_prober() {
        // No peers (and no netmap) → the sweep is gated closed, so re_stun probes nothing.
        let no_peers: Arc<RwLock<Option<Arc<PeerDb>>>> = Default::default();
        assert!(
            !stun_probe_should_run(&no_peers),
            "re_stun must skip the sweep with no peers, like the periodic prober"
        );

        // With a peer present the gate opens; an empty derp v4-STUN list is then a clean no-op
        // (probing must never require a STUN server — pong-harvest backstops it).
        let disco = DiscoPrivateKey::random().public_key();
        let node_key = NodePrivateKey::random().public_key();
        let with_peer = db_with(node_with_keys(disco, node_key, "n1"));
        assert!(
            stun_probe_should_run(&with_peer),
            "re_stun sweeps once a peer is present"
        );
        let sock = Arc::new(
            MagicSock::bind(
                BIND_ADDR.parse().unwrap(),
                DiscoPrivateKey::random(),
                NodePrivateKey::random().public_key(),
            )
            .await
            .unwrap(),
        );
        // Empty server list (what an unavailable/stale derp map yields) → no sends, returns promptly.
        probe_stun_servers_once(&sock, &[]).await;
    }

    /// The periodic STUN delay is a uniform random value in `[20s, 26s)`, matching Go magicsock's
    /// `RandomDurationBetween(20s, 26s)` re-arm — never a fixed 30s beat, and always strictly under
    /// the ~30s UDP-NAT-timeout ceiling. Sampling many draws pins both the bounds and that the value
    /// actually varies (jitter), so a regression to a constant interval is caught.
    #[test]
    fn stun_probe_delay_is_jittered_within_go_bounds() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            let d = stun_probe_delay();
            assert!(
                d >= STUN_PROBE_INTERVAL_MIN && d < STUN_PROBE_INTERVAL_MAX,
                "delay {d:?} out of [20s, 26s)"
            );
            assert!(
                d < Duration::from_secs(30),
                "delay {d:?} must stay under the 30s UDP-NAT-timeout ceiling"
            );
            seen.insert(d);
        }
        // 1000 draws across a 6s (≈6e9 ns) range must yield many distinct values — a fixed-interval
        // regression would collapse this to 1.
        assert!(
            seen.len() > 100,
            "expected jittered delays, got only {} distinct value(s)",
            seen.len()
        );
    }
}
