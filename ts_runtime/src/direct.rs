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
    collections::HashSet,
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
const PING_INTERVAL: Duration = Duration::from_secs(2);

/// How often to send active STUN Binding Requests to the derp map's STUN servers, from the one
/// bound underlay socket, to learn our reflexive (public) address even before any peer pongs.
/// This complements the pong-harvest path on the same socket without opening a second egress.
const STUN_PROBE_INTERVAL: Duration = Duration::from_secs(30);

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

/// The IPv4 bind address for the direct underlay socket.
///
/// IPv4-only and ephemeral-port: per the anti-leak rules this socket is the only egress path
/// for the direct underlay, and IPv6 is disabled in our default deployment. This is the historical
/// (and `enable_ipv6 == false`) bind — byte-for-byte the original behavior.
const BIND_ADDR: &str = "0.0.0.0:0";

/// The dual-stack bind address used only when `Env::enable_ipv6` is `true`.
///
/// Binding `[::]:0` yields one socket that serves both native IPv6 and IPv4-mapped traffic when
/// the kernel's `IPV6_V6ONLY` is off (the Linux default on our a cloud VPS deployment, where
/// `/proc/sys/net/ipv6/bindv6only` is `0`). See [`bind_underlay_addr`] for the inert-fallback
/// posture when the host has IPv6 disabled at the kernel.
const BIND_ADDR_V6: &str = "[::]:0";

/// Choose the underlay UDP socket and the address it bound to, honoring the (default-off)
/// `enable_ipv6` overlay gate.
///
/// - `enable_ipv6 == false` (default): bind exactly [`BIND_ADDR`] (`0.0.0.0:0`) — byte-for-byte the
///   historical IPv4-only path, no new syscalls. This upholds the sacred IPv4-only invariant of the
///   privacy-proxy deployment.
/// - `enable_ipv6 == true`: attempt a dual-stack bind on [`BIND_ADDR_V6`] (`[::]:0`) so a single
///   socket serves both native v6 and v4-mapped traffic. **Fail inert, never panic**: if the v6
///   bind fails (e.g. a host with `net.ipv6.conf.all.disable_ipv6=1`), warn and fall back to the
///   IPv4 bind so the node still comes up — protective if the gate is mis-flagged on a hardened box.
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
    our_disco: ts_keys::DiscoPrivateKey,
    our_node_key: NodePublicKey,
) -> Result<MagicSock, ts_magicsock::Error> {
    // IPv4-only default: the historical path, unchanged.
    if !enable_ipv6 {
        let v4: SocketAddr = BIND_ADDR.parse().expect("valid bind address");
        return MagicSock::bind(v4, our_disco, our_node_key).await;
    }

    // Overlay IPv6 enabled: try the dual-stack bind first.
    let v6: SocketAddr = BIND_ADDR_V6.parse().expect("valid bind address");
    match MagicSock::bind(v6, our_disco, our_node_key).await {
        Ok(sock) => Ok(sock),
        Err(e) => {
            // Inert fallback: the host likely has IPv6 disabled at the kernel. Come up IPv4-only
            // rather than crash — protective on a hardened proxy box even if the gate is set.
            tracing::warn!(
                error = %e,
                %v6,
                "dual-stack underlay bind failed (host IPv6 disabled?); falling back to IPv4-only",
            );
            let v4: SocketAddr = BIND_ADDR.parse().expect("valid bind address");
            MagicSock::bind(v4, our_disco, our_node_key).await
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

    /// Of the given peers, return those that currently have a trusted direct path.
    ///
    /// A peer is included only if its disco key is known and [`MagicSock::best_addr`] returns
    /// `Some` for it right now (live query — never cached — so trust expiry downgrades
    /// immediately).
    #[message]
    pub fn peers_with_direct_path(&self, ids: Vec<PeerId>) -> HashSet<PeerId> {
        let mut ready = HashSet::new();

        // No bound underlay socket (bind failed => inert, DERP-only): no peer has a direct path.
        let Some(sock) = self.sock.as_ref() else {
            return ready;
        };

        let db = poisoned_read(&self.peer_db);
        let Some(db) = db.as_ref() else {
            return ready;
        };

        for id in ids {
            let Some((_, node)) = db.get(&id) else {
                continue;
            };
            let Some(disco) = node.disco_key else {
                continue;
            };
            if sock.best_addr(&disco).is_some() {
                ready.insert(id);
            }
        }

        ready
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
    multiderp: ActorRef<Multiderp>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(STUN_PROBE_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    while !*shutdown.borrow() {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = interval.tick() => {
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

/// Send one STUN Binding Request to each server in `servers` from the one bound socket.
///
/// Each send fails closed inside [`MagicSock::send_stun_request`] (a non-v4 server is refused, the
/// in-flight set is capped); a transient io error just skips that server for this round rather than
/// aborting the sweep. Factored out of [`run_stun_prober`]'s interval loop so the per-tick fan-out
/// (including the empty-list no-op when the derp map lists no FixedAddr-v4 STUN servers) is
/// unit-testable without the actor/interval machinery.
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
/// bound socket (peers echo our public `src`); we deliberately do **not** run an active
/// [`ts_netcheck::StunProber`] for self-endpoint discovery. That prober binds its own sockets
/// (including an IPv6 `[::]:0` egress that violates the IPv4-only invariant), so its reflexive
/// mapping would be both a different NAT path and a potential IPv6 leak. Pong-harvest is the
/// leak-safe, parity-correct source for Tier 1.
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
/// We only target peers that have a disco key and a known home DERP region (we relay to that
/// region). The frame carries our [`MagicSock::self_endpoints`] — the same set advertised to
/// control — so no host-identifying address beyond that is disclosed.
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
                let targets: Vec<(ts_keys::NodePublicKey, DiscoPublicKey, ts_derp::RegionId)> = {
                    let db = poisoned_read(&peer_db);
                    let Some(db) = db.as_ref() else { continue; };

                    db.peers()
                        .values()
                        .filter_map(|node| {
                            let disco = node.disco_key?;
                            let region = node.derp_region?;
                            // Only prompt peers that don't already have a confirmed direct path.
                            if sock.best_addr(&disco).is_some() {
                                return None;
                            }
                            Some((node.node_key, disco, region))
                        })
                        .collect()
                };

                for (node_key, disco, region) in targets {
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
            env.keys.disco_keys.private,
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
        // moved into run_call_me_maybe below.
        tasks.spawn(run_stun_prober(
            sock.clone(),
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
            tailnet: Some("ts.net".to_string()),
            tags: vec![],
            tailnet_address: TailnetAddress {
                ipv4: "100.64.0.9/32".parse().unwrap(),
                ipv6: "fd7a::9/128".parse().unwrap(),
            },
            node_key,
            node_key_expiry: None,
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

        assert_eq!(
            n, 20,
            "a STUN Binding Request is exactly the 20-byte header"
        );
        assert_eq!(
            &buf[0..2],
            &0x0001u16.to_be_bytes(),
            "message type must be Binding Request (0x0001)"
        );
        assert_eq!(
            &buf[4..8],
            &0x2112_A442u32.to_be_bytes(),
            "the STUN magic cookie must be present at bytes[4..8]"
        );
    }

    /// With `enable_ipv6 == false` (the default) the underlay socket binds the historical IPv4
    /// path: its local address is in the v4 family (`0.0.0.0`). This pins the sacred default — the
    /// privacy-proxy deployment must stay byte-for-byte IPv4-only when the gate is off.
    #[tokio::test]
    async fn bind_underlay_addr_v4_default_is_unchanged() {
        let sock = bind_underlay_addr(
            false,
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
}
