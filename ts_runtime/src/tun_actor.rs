//! TUN transport-mode actor: rides the same dataplane overlay seam as [`NetstackActor`], but
//! moves application packets between the dataplane and a real kernel TUN interface instead of a
//! userspace smoltcp netstack.
//!
//! In TUN mode there is no userspace application *transport* netstack: application packets flow
//! `OS-TUN <-> dataplane <-> overlay`. There IS, however, an in-datapath MagicDNS responder: the UP
//! pump peels off UDP queries destined to the MagicDNS service IP `100.100.100.100:53`, answers them
//! in-process via the shared [`magic_dns::decide`](crate::magic_dns::decide) responder, and writes
//! the reply back into the TUN — mirroring Go's `handleLocalPackets`. No host loopback socket and no
//! overlay egress is used for the DNS itself (anti-leak). Other netstack-only public APIs surface
//! [`ErrorKind::UnsupportedInTunMode`](crate::ErrorKind::UnsupportedInTunMode).

use core::num::NonZeroU16;
use std::{
    net::{Ipv4Addr, SocketAddrV4},
    sync::Arc,
};

use kameo::{
    actor::ActorRef,
    message::{Context, Message},
};
use netstack::netcore::Channel;
use tokio::{sync::watch, task::JoinSet};
use ts_transport::OverlayTransport;
use ts_transport_tun::{AsyncTunTransport, Config as TunDeviceConfig};

use crate::{
    Error,
    dataplane::{OverlayFromDataplane, OverlayToDataplane},
    env::Env,
    magic_dns::{Decision, DnsView, RecursivePlan, decide, forward_query, recursive_plan},
    peer_tracker::PeerState,
};

/// The MagicDNS service IP. Mirrors `magic_dns::MAGIC_DNS_IP` (kept private to that module). In TUN
/// mode the host routes queries to this address into the TUN (see [`host_routes_from_node`]) where
/// the UP pump intercepts them.
const MAGIC_DNS_IP: Ipv4Addr = Ipv4Addr::new(100, 100, 100, 100);
/// The DNS service port.
const MAGIC_DNS_PORT: u16 = 53;
/// TTL for the synthesized IPv4 response packet written back into the TUN. The response is consumed
/// by the local host one hop away (the TUN endpoint), so the exact value is immaterial; 64 is the
/// conventional default.
const DNS_REPLY_TTL: u8 = 64;

/// The TUN transport-mode actor.
///
/// Lazily creates the TUN device on the first [`ts_control::StateUpdate`] that carries a self-node
/// (the device prefix is the runtime-assigned tailnet `/32`, unknown before then). Once created,
/// two pump tasks held in the [`JoinSet`] move packets up to and down from the dataplane; they die
/// with the actor.
pub struct TunActor {
    /// Tasks pumping packets between the device and the dataplane. Dropped with the actor, which
    /// aborts them — the device handle they hold is then dropped, tearing down the interface.
    _joinset: JoinSet<()>,

    /// The runtime [`Env`], retained so the StateUpdate handler can resolve the configured exit
    /// node against the live peer set when rebuilding the MagicDNS [`DnsView`] (populating
    /// `exit_doh` for recursive / exit-node-DoH forwarding). See [`build_dns_view`].
    env: Env,

    /// The control-supplied TUN knobs (name/MTU), used to build the device on the first
    /// StateUpdate. The tailnet prefix is supplied at that point from the self-node.
    tun_config: ts_control::TunConfig,

    /// `Some` until the device is created on the first StateUpdate; `.take()`n into the up-pump
    /// task at that point so the device is built exactly once.
    overlay_to_dataplane: Option<OverlayToDataplane>,

    /// `Some` until the device is created on the first StateUpdate; `.take()`n into the down-pump
    /// task at that point so the device is built exactly once.
    overlay_from_dataplane: Option<OverlayFromDataplane>,

    /// Host-route gating (accept-routes / exit-node), derived from [`Env`] at the spawn site and
    /// consumed by [`host_routes_from_node`] when the device is built.
    gating: HostRouteGating,

    /// Reverses host route/DNS programming on drop. `Some` once the device is built and the host
    /// has been programmed; shares the actor's lifetime with the pump tasks in `_joinset`.
    host_guard: Option<HostGuard>,

    /// The latest MagicDNS view, shared with the UP pump's in-datapath responder. Built here from
    /// the same control `StateUpdate` / peer `PeerState` the actor already subscribes to, mirroring
    /// [`MagicDnsActor`](crate::magic_dns)'s view construction. The UP task holds the receiver and
    /// reads it fresh for every intercepted query; `exit_doh` is populated from the active exit
    /// peer (see [`build_dns_view`]) so recursive / exit-node-DoH forwarding works in TUN mode.
    dns_view: watch::Sender<Arc<DnsView>>,

    /// The overlay netstack `Channel` (the forwarder netstack's, reused — TUN mode has no
    /// application netstack of its own) used by the UP pump's spawned [`run_forward`] to forward
    /// recursive / split-DNS queries over the overlay (anti-leak: a fresh `0.0.0.0:0` overlay UDP
    /// socket per query, never a host socket). Cloned into the UP pump when the device is built.
    channel: Channel,
}

/// Gating inputs for host-route programming, derived from [`Env`] at the spawn site. A named
/// carrier rather than two positional `bool`s: the two flags are same-typed and adjacent, so a
/// positional pair is a silent transposition hazard whose blast radius is a routing/leak
/// correctness bug (subnet gate vs `/0`-default gate) — exactly the class the fork's fail-closed
/// posture exists to prevent. A struct makes a swap a compile error and the next gating flag an
/// additive field.
// `pub` (not `pub(crate)`) because it surfaces through `Actor::Args`, a public trait associated
// type — a crate-private type there is an E0446 leak. The enclosing `tun_actor` module is private,
// so this stays crate-internal in practice.
#[derive(Clone, Copy, Debug)]
pub struct HostRouteGating {
    /// Whether the embedder set `--accept-routes`. Gates whether advertised subnet routes are
    /// steered into the TUN by [`host_routes_from_node`].
    pub accept_routes: bool,
    /// Whether the embedder configured an exit node (`env.exit_node.is_some()`). Gates whether the
    /// host `/0` default route is steered into the TUN by [`host_routes_from_node`].
    pub exit_node_configured: bool,
}

/// RAII wrapper that reverses host route/DNS programming when the actor dies. Held in
/// [`TunActor::host_guard`] alongside the device pump tasks in `_joinset`, so when the actor is
/// dropped the interface is torn down and its host-FIB/resolver state is reversed together.
struct HostGuard(Box<dyn ts_host_net::HostNet>);

impl Drop for HostGuard {
    fn drop(&mut self) {
        self.0.teardown();
    }
}

/// Build the device config from the control-supplied [`ts_control::TunConfig`] plus the
/// runtime-assigned tailnet `/32` prefix. Mirrors [`env::exit_proxy_to_forwarder`](crate::env)
/// (conversion at the `ts_runtime` boundary).
///
/// Defaults: name `"tailscale0"`, MTU `1280` (Tailscale's overlay MTU). `mtu` is `Option<u16>`;
/// `0` is invalid so `and_then(NonZeroU16::new)` rejects a stray `0` and falls back to `1280`.
pub(crate) fn tun_config_from_control(
    cfg: &ts_control::TunConfig,
    prefix: ipnet::Ipv4Net,
) -> TunDeviceConfig {
    TunDeviceConfig {
        name: cfg.name.clone().unwrap_or_else(|| "tailscale0".to_owned()),
        mtu: cfg
            .mtu
            .and_then(NonZeroU16::new)
            .unwrap_or(NonZeroU16::new(1280).unwrap()),
        prefix: ipnet::IpNet::V4(prefix),
    }
}

/// Translate the self-node's accepted routes into the host-FIB route set to steer into the TUN
/// (the `ts_runtime` boundary, mirroring [`tun_config_from_control`]).
///
/// IPv4-only by construction: every IPv6 prefix in `accepted_routes` is dropped here, enforcing the
/// fork's v4-only invariant (v6 on the tailnet is gated off) without a separate `enable_ipv6` flag.
///
/// The filter mirrors the spirit of [`ts_control::Node::routes_to_install`] but keys the `/0`
/// default route on `exit_node_configured` rather than peer StableId resolution. ASYMMETRY: the
/// TunActor only ever sees the **self** node, so it cannot resolve *which peer* is the exit node
/// (that is the overlay router / route_updater's job, which enforces the actual leak-free egress).
/// We only decide whether a host-side `/0` belongs in the route set at all — the self-node's
/// `accepted_routes` may echo a `/0`, but a host `/0` should only be installed when the embedder
/// actually configured an exit node. The Linux impl expands `/0` into the split-default pair;
/// macOS installs `/0` directly.
pub(crate) fn host_routes_from_node(
    node: &ts_control::Node,
    if_name: String,
    gating: HostRouteGating,
    magic_dns: bool,
) -> ts_host_net::HostRoutes {
    let self_v4 = node.tailnet_address.ipv4;

    let mut routed: Vec<ipnet::Ipv4Net> = node
        .accepted_routes
        .iter()
        .filter_map(|route| match route {
            // IPv4-only by construction: drop every v6 prefix unconditionally.
            ipnet::IpNet::V4(v4) => Some(*v4),
            ipnet::IpNet::V6(_) => None,
        })
        .filter(|v4| {
            // The device builder already owns the on-link self `/32`; never re-route it.
            if *v4 == self_v4 {
                return false;
            }
            if v4.prefix_len() == 0 {
                // Host-side `/0` only when the embedder configured an exit node (see fn doc).
                return gating.exit_node_configured;
            }
            // Other prefixes: subnet routes are gated on `--accept-routes`; non-self host routes
            // (e.g. additional tailnet addrs) are always installed. Mirrors `routes_to_install`.
            gating.accept_routes || !node.is_subnet_route(&ipnet::IpNet::V4(*v4))
        })
        .collect();

    // Steer the MagicDNS service IP `100.100.100.100/32` into the TUN so the host's quad-100 DNS
    // queries enter the datapath where the UP pump intercepts them ([`intercept_magic_dns`]). Added
    // unconditionally when MagicDNS is enabled — it's the device's own service IP, always
    // routed-to-self — unless control somehow advertised it as the self `/32` (it never is).
    if magic_dns {
        let magic_dns_net = ipnet::Ipv4Net::new(MAGIC_DNS_IP, 32).expect("/32 is a valid prefix");
        if magic_dns_net != self_v4 && !routed.contains(&magic_dns_net) {
            routed.push(magic_dns_net);
        }
    }

    ts_host_net::HostRoutes {
        if_name,
        self_v4,
        routed,
    }
}

/// Translate the control DNS config into the host resolver programming for the TUN (the
/// `ts_runtime` boundary, mirroring [`tun_config_from_control`]).
///
/// When MagicDNS is enabled the host resolver is pointed at the MagicDNS service IP
/// `100.100.100.100` — Go's model: the host sends queries to quad-100, the UP pump intercepts them
/// in the datapath and answers in-process via the shared responder ([`plan_intercept`]). There
/// is NO host loopback socket. When MagicDNS is disabled, `nameservers` stays empty (a documented
/// no-op in both the macOS and Linux `apply_dns` impls) so we never point the resolver at a dead
/// address — fail-closed.
///
/// `match_domains` carries the search domains only when MagicDNS is enabled in the control config.
pub(crate) fn host_dns_from_dns_config(
    dns: Option<&ts_control::DnsConfig>,
    if_name: String,
) -> ts_host_net::HostDns {
    let magic_dns = matches!(dns, Some(d) if d.magic_dns);
    let match_domains = if magic_dns {
        // `dns` is `Some(_)` here by construction of `magic_dns`.
        dns.map(|d| d.search_domains.clone()).unwrap_or_default()
    } else {
        vec![]
    };

    ts_host_net::HostDns {
        if_name,
        // Point the host resolver at the MagicDNS service IP when MagicDNS is enabled; the UP pump
        // intercepts quad-100/UDP/53 in the datapath and answers in-process. Empty (no-op) when
        // MagicDNS is off — never point at a dead address.
        nameservers: if magic_dns {
            vec![MAGIC_DNS_IP]
        } else {
            vec![]
        },
        match_domains,
    }
}

/// A MagicDNS query peeled off the TUN datapath: the inner DNS payload plus the original query's
/// source endpoint (so the synthesized reply can be addressed back to it). Returned by
/// [`classify_magic_dns`] when (and only when) an inbound packet is IPv4/UDP destined to
/// `100.100.100.100:53`.
struct MagicDnsQuery<'a> {
    /// The original query's source `IP:port` (the host stub resolver). The reply's destination.
    src: SocketAddrV4,
    /// The DNS wire-format query payload (UDP body), fed verbatim to [`decide`].
    dns_payload: &'a [u8],
}

/// Classify an inbound TUN packet: if it is an IPv4 UDP datagram destined to the MagicDNS service
/// `100.100.100.100:53`, return its DNS payload + source endpoint; otherwise `None` (the packet is
/// forwarded to the overlay unchanged). Pure (no I/O), parse mirrors
/// `ts_dataplane`'s inbound classify. A non-IPv4 / non-UDP / wrong-dest / unparseable packet is
/// `None` — never intercepted.
fn classify_magic_dns(pkt: &[u8]) -> Option<MagicDnsQuery<'_>> {
    let sliced = etherparse::SlicedPacket::from_ip(pkt).ok()?;

    let (src_ip, dst_ip) = match sliced.net {
        Some(etherparse::NetSlice::Ipv4(ipv4)) => (
            ipv4.header().source_addr(),
            ipv4.header().destination_addr(),
        ),
        // IPv4-only by construction (mirrors the host-route/v6 posture): never intercept v6.
        _ => return None,
    };

    if dst_ip != MAGIC_DNS_IP {
        return None;
    }

    let udp = match sliced.transport {
        Some(etherparse::TransportSlice::Udp(udp)) => udp,
        _ => return None,
    };
    if udp.destination_port() != MAGIC_DNS_PORT {
        return None;
    }

    Some(MagicDnsQuery {
        src: SocketAddrV4::new(src_ip, udp.source_port()),
        // The UDP payload is the DNS wire message.
        dns_payload: udp.payload(),
    })
}

/// Build the IPv4+UDP response packet carrying `dns_response` from `100.100.100.100:53` back to the
/// original query's source `dst` (the host stub resolver), recomputing IPv4 + UDP checksums.
/// Pure: the src/dst are swapped relative to the query (we answer FROM the service IP TO the
/// querier). The returned bytes are an IP packet ready to write into the TUN.
fn build_dns_response(dst: SocketAddrV4, dns_response: &[u8]) -> Vec<u8> {
    let builder =
        etherparse::PacketBuilder::ipv4(MAGIC_DNS_IP.octets(), dst.ip().octets(), DNS_REPLY_TTL)
            .udp(MAGIC_DNS_PORT, dst.port());

    let mut out = Vec::with_capacity(builder.size(dns_response.len()));
    // Writing into a `Vec<u8>` is infallible; `PacketBuilder::write` only errors on I/O write
    // failures, which a `Vec` never produces.
    builder
        .write(&mut out, dns_response)
        .expect("writing an IPv4+UDP packet into a Vec is infallible");
    out
}

/// Build a fresh [`DnsView`] from the latest control `StateUpdate` and (optional) peer database,
/// mirroring [`MagicDnsActor`](crate::magic_dns)'s view construction
/// (`magic_dns::MagicDnsActor`'s `StateUpdate`/`PeerState` handlers). `enable_ipv6` comes from the
/// runtime `Env`.
///
/// `exit_doh` is populated from the active exit peer's peerAPI DoH endpoint so recursive resolution
/// egresses from the exit node (not this host) — same source as the netstack
/// `MagicDnsActor`'s `ActiveExitNode` handler (`magic_dns.rs:751`:
/// `active_exit_peer.and_then(|n| n.peerapi_doh_addr())`). The netstack path receives the
/// already-resolved peer from the route updater's `ActiveExitNode` publication; the TunActor has no
/// such subscription, so it resolves the exit peer locally — exactly as the route updater does
/// (`route_updater.rs:191-272`): resolve [`Env::exit_node`](crate::env::Env::exit_node) against the
/// live peer set to a [`StableId`](ts_control::StableId), then find that peer in the db. No exit
/// node configured, an unmatched selector, or a peer that can't proxy DNS ⇒ `None` (recursion stays
/// local — fail-closed, no leak).
fn build_dns_view(
    env: &Env,
    update: &ts_control::StateUpdate,
    peers: Option<Arc<crate::peer_tracker::PeerDb>>,
    enable_ipv6: bool,
) -> DnsView {
    // Resolve the configured exit node to its peerAPI DoH address, mirroring the netstack path's
    // `active_exit_peer.and_then(|n| n.peerapi_doh_addr())` (`magic_dns.rs:751`). The two-line peer
    // resolution mirrors `route_updater.rs:191-272` (selector -> stable id -> peer); replicated
    // locally (no shared-fn extraction) to keep S3 inside `tun_actor.rs`.
    let exit_doh = env.exit_node().as_ref().and_then(|sel| {
        let peers = peers.as_ref()?;
        let id = sel.resolve(peers.peers().values())?;
        peers
            .peers()
            .values()
            .find(|peer| peer.stable_id == id)
            .and_then(|n| n.peerapi_doh_addr())
    });

    DnsView {
        cfg: update.dns_config.clone().unwrap_or_default(),
        peers,
        self_node: update.node.clone(),
        exit_doh,
        enable_ipv6,
    }
}

/// Outcome of classifying an inbound TUN packet against the in-datapath MagicDNS responder.
/// Produced by the PURE [`plan_intercept`] (no I/O, unit-testable without a TUN device) and acted on
/// by the UP pump: the slow [`Decision::Forward`] path is handed back as [`Self::Forward`] for the
/// pump to SPAWN, never awaited inline — so one slow upstream cannot head-of-line-block the uplink.
enum Intercept {
    /// Not a MagicDNS query; the pump should forward the original packet to the overlay unchanged.
    NotIntercepted,
    /// A malformed MagicDNS query — consumed (it was quad-100/UDP/53) but dropped silently with no
    /// reply. The pump must NOT forward it to the overlay.
    Dropped,
    /// An authoritative [`Decision::Reply`] (cache / in-tailnet name): the synthesized reply bytes
    /// are carried out for the pump to write back into the TUN INLINE (the fast path — no overlay
    /// round-trip). The pump must NOT forward the packet to the overlay.
    Reply {
        /// The DNS wire response to wrap in an IPv4+UDP packet and write back into the TUN.
        response: Vec<u8>,
        /// The reply's destination (the host stub resolver) — the query's source endpoint.
        src: SocketAddrV4,
    },
    /// A [`Decision::Forward`] (recursive / split-DNS). The slow overlay round-trip must be SPAWNED
    /// by the pump rather than awaited inline (anti-HOL-blocking). Carries the already-resolved
    /// [`RecursivePlan`] (computed while the view borrow was held), the original query bytes, the
    /// fail-closed `nxdomain` fallback, and the reply destination `src`. The pump must NOT forward
    /// the packet to the overlay.
    Forward {
        /// The resolved forwarding plan (UDP upstreams vs exit-node DoH over the overlay). The
        /// upstream `SocketAddr`s come only from `decide`/`recursive_plan`, which already
        /// `.filter(SocketAddr::is_ipv4)`; this path never constructs an upstream address, so the
        /// IPv4-only egress invariant is inherited.
        plan: RecursivePlan,
        /// The original query bytes to forward verbatim.
        query: Vec<u8>,
        /// Fail-closed NXDOMAIN response written back if every upstream fails.
        nxdomain: Vec<u8>,
        /// The reply's destination (the host stub resolver) — the query's source endpoint.
        src: SocketAddrV4,
    },
}

/// In-datapath MagicDNS classify+decide for the UP pump (Go's `handleLocalPackets`). PURE: no I/O,
/// factored out of the pump loop so the branch behavior — crucially, that a [`Decision::Forward`] is
/// handed back to be SPAWNED rather than awaited inline — is unit-testable without a TUN device
/// (mirrors `magic_dns::decide`'s "factored out of the socket loop" rationale).
///
/// Fast paths resolve synchronously: a non-MagicDNS packet ⇒ [`Intercept::NotIntercepted`]; a
/// malformed query ⇒ [`Intercept::Dropped`]; an authoritative [`Decision::Reply`] ⇒
/// [`Intercept::Reply`] carrying the response bytes for the pump to write back into the TUN INLINE
/// (no overlay round-trip — no host loopback socket, anti-leak).
///
/// The SLOW path — [`Decision::Forward`] (recursive / split-DNS forwarding, a full overlay DNS
/// round-trip bounded only by a ~5s timeout) — is NOT awaited here. It is returned as
/// [`Intercept::Forward`] carrying the already-resolved [`RecursivePlan`] so the pump can SPAWN it
/// onto a [`JoinSet`] (see the UP pump in the StateUpdate handler), mirroring the netstack serve
/// loop (`magic_dns.rs:598-632`): "a slow upstream never blocks other queries". Awaiting the forward
/// inline (as this did historically) stalls the ENTIRE TUN uplink — all application traffic, not
/// just DNS — for up to the forward timeout while the pump cannot pull the next packet.
///
/// The plan (UDP upstreams vs exit-node DoH) is computed here from the current view; both branches
/// route through `recursive_plan`/the `decide`-built upstreams, so the IPv4-only filter at
/// `magic_dns.rs:385,429` is inherited (we never build a `SocketAddr` here). The fail-closed
/// `nxdomain` fallback is carried into the spawned task and written on forward failure — same as
/// before, just from the spawned task rather than inline.
fn plan_intercept(view: &DnsView, pkt: &[u8]) -> Intercept {
    let Some(query) = classify_magic_dns(pkt) else {
        return Intercept::NotIntercepted;
    };
    // The reply destination (the query's source endpoint). Bound before the `Decision::Forward`
    // arm shadows `query` with the forward's own owned query bytes.
    let src = query.src;

    match decide(view, query.dns_payload) {
        // Malformed query: drop silently. We still consumed it (it was quad-100/UDP/53) so it must
        // NOT be forwarded to the overlay.
        None => Intercept::Dropped,
        Some(Decision::Reply(response)) => Intercept::Reply { response, src },
        // Forward over the overlay, mirroring the netstack serve loop (`magic_dns.rs:598-632`). The
        // plan (UDP upstreams vs exit-node DoH) is computed from the current view; both branches
        // route through `recursive_plan`/the `decide`-built upstreams, so the IPv4-only filter at
        // `magic_dns.rs:385,429` is inherited (we never build a `SocketAddr` here). The overlay
        // round-trip is NOT awaited here — it is handed back for the pump to SPAWN (anti-HOL).
        Some(Decision::Forward {
            upstreams,
            query,
            nxdomain,
            recursive,
        }) => {
            let plan = if recursive {
                recursive_plan(view, upstreams)
            } else {
                RecursivePlan::Udp(upstreams)
            };
            Intercept::Forward {
                plan,
                query,
                nxdomain,
                src,
            }
        }
    }
}

/// Write an authoritative MagicDNS reply (the fast path) back into the TUN inline. The synthesized
/// IPv4+UDP packet goes straight back to the querier via `device` — no host loopback socket and no
/// overlay egress for the DNS itself (anti-leak).
async fn send_dns_reply(device: &Arc<AsyncTunTransport>, src: SocketAddrV4, response: &[u8]) {
    let reply_pkt = build_dns_response(src, response);
    if let Err(e) = device
        .send(core::iter::once(ts_packet::PacketMut::from(reply_pkt)))
        .await
    {
        tracing::warn!(error = %e, "magic dns tun reply send failed");
    }
}

/// Run the SLOW [`Decision::Forward`] overlay round-trip and write the synthesized DNS reply back
/// into the TUN. Spawned onto the pump's `JoinSet` so it never blocks the uplink (see
/// [`plan_intercept`] / the UP pump). Mirrors the spawned forward in the netstack serve loop
/// (`magic_dns.rs:614-627`): forward over the overlay (anti-leak: never a host socket), falling back
/// to the pre-built `nxdomain` on failure (fail-closed), then write the reply packet into the TUN.
/// The upstreams are carried in `plan` (from `decide`/`recursive_plan`, already v4-only filtered);
/// this fn never constructs an upstream `SocketAddr`, so the IPv4-only egress invariant is inherited.
/// The TUN uplink pump: the highest-traffic datapath, run as a task spawned onto the actor's
/// [`JoinSet`] when the device is built (see the StateUpdate handler). It moves application
/// packets `device -> {in-datapath MagicDNS responder | dataplane}`:
///
/// - For every received packet it runs the PURE [`plan_intercept`] against the latest MagicDNS
///   [`DnsView`] (read fresh per packet; the borrow guard is never held across an `await`):
///   - [`Intercept::NotIntercepted`] — forward the original packet to the overlay (`up`) unchanged.
///   - [`Intercept::Dropped`] — a malformed quad-100 query: consumed, never forwarded.
///   - [`Intercept::Reply`] — an authoritative reply written straight back into the TUN INLINE
///     (the fast path — no overlay round-trip, no host socket; anti-leak).
///   - [`Intercept::Forward`] — the SLOW recursive / split-DNS overlay round-trip is SPAWNED onto
///     a local `JoinSet` ([`run_forward`]) so one slow upstream never head-of-line-blocks the
///     ENTIRE TUN uplink (all application traffic, not just DNS).
///
/// BACKPRESSURE: in-flight forwards are capped at `MAX_INFLIGHT_FORWARDS` to avoid trading
/// HOL-blocking for unbounded task growth under a DNS flood; at the cap one completed forward is
/// reaped synchronously (`join_next`) before spawning the next. This back-pressures *new DNS
/// forwards only* — the non-DNS uplink and the inline fast paths are never blocked. Returns when
/// the overlay send half (`up`) is closed (the dataplane went away).
async fn up_pump(
    dev_up: Arc<AsyncTunTransport>,
    up: OverlayToDataplane,
    dns_view_rx: watch::Receiver<Arc<DnsView>>,
    dns_channel: Channel,
) {
    // In-flight MagicDNS forward tasks. The slow `Decision::Forward` overlay round-trip
    // (bounded only by a ~5s timeout) is SPAWNED here rather than awaited inline, so one
    // slow/hung upstream never head-of-line-blocks the ENTIRE TUN uplink (all application
    // traffic, not just DNS). Mirrors the netstack serve loop's `JoinSet`
    // (`magic_dns.rs:577,614-632`): spawn each forward, reap with `try_join_next`.
    //
    // CONCURRENCY BOUND: a `JoinSet` reaped with `try_join_next` matches `magic_dns.rs`
    // for consistency (the pump owns the set across loop iterations, so no separate
    // semaphore is needed). To avoid trading HOL-blocking for unbounded task growth under a
    // DNS flood, in-flight forwards are capped at `MAX_INFLIGHT_FORWARDS`: at the cap we
    // synchronously reap one completed forward (`join_next`) before spawning the next.
    // Worst case is one forward's latency of back-pressure on *new DNS forwards only* — the
    // non-DNS uplink and the authoritative/no-intercept fast paths are never blocked.
    const MAX_INFLIGHT_FORWARDS: usize = 256;
    let mut forwards: JoinSet<()> = JoinSet::new();
    loop {
        // Drain the (non-`Send`) recv iterator into an owned batch first, so no part of it
        // is held across the intercept's `await` (the iterator is not `Send`; `PacketMut`
        // is). Then process the batch, peeling off MagicDNS queries.
        let batch: Vec<_> = dev_up.recv().await.into_iter().collect();
        for pkt in batch {
            match pkt {
                Ok(p) => {
                    // Peel off quad-100/UDP/53 DNS queries and answer them in-process: an
                    // authoritative reply is written straight back into the TUN via `dev_up`
                    // (no overlay egress, no host socket) INLINE; a Forward (recursive /
                    // split-DNS) is SPAWNED so its overlay round-trip never blocks the pump.
                    // Everything else forwards to the overlay unchanged. The view is read
                    // fresh per packet (mirrors the netstack serve loop); the borrow guard
                    // is dropped at the end of this statement, never held across an `await`.
                    let plan = plan_intercept(&dns_view_rx.borrow(), p.as_ref());
                    match plan {
                        Intercept::NotIntercepted => {
                            if up.send(vec![p]).is_err() {
                                return;
                            }
                        }
                        // Malformed query: consumed but dropped silently; never forward to
                        // the overlay.
                        Intercept::Dropped => {}
                        // Authoritative reply (fast path): write it back into the TUN inline.
                        Intercept::Reply { response, src } => {
                            send_dns_reply(&dev_up, src, &response).await;
                        }
                        // Spawn the slow overlay round-trip; it writes the reply (or the
                        // fail-closed nxdomain) back into the TUN when it completes.
                        Intercept::Forward {
                            plan,
                            query,
                            nxdomain,
                            src,
                        } => {
                            // Bound in-flight forwards: reap one completed task at the cap
                            // before spawning, so a DNS flood can't grow tasks without
                            // limit. This back-pressures *new DNS forwards only*, never the
                            // non-DNS uplink or the inline fast paths.
                            if forwards.len() >= MAX_INFLIGHT_FORWARDS {
                                // Reap exactly one completed forward; the join result is
                                // intentionally discarded (the task is `()` and logs its
                                // own send failures).
                                drop(forwards.join_next().await);
                            }
                            forwards.spawn(run_forward(
                                dev_up.clone(),
                                dns_channel.clone(),
                                plan,
                                query,
                                nxdomain,
                                src,
                            ));
                        }
                    }
                }
                Err(e) => tracing::warn!(error = %e, "tun recv error"),
            }
        }
        // Reap finished forward tasks without blocking (mirrors `magic_dns.rs:632`).
        while forwards.try_join_next().is_some() {}
    }
}

async fn run_forward(
    device: Arc<AsyncTunTransport>,
    channel: Channel,
    plan: RecursivePlan,
    query: Vec<u8>,
    nxdomain: Vec<u8>,
    src: SocketAddrV4,
) {
    let response = match plan {
        RecursivePlan::Udp(ups) => forward_query(&channel, &ups, &query, nxdomain).await,
        RecursivePlan::Doh(addr) => {
            crate::peerapi_doh::forward_doh(&channel, addr, &query, nxdomain).await
        }
    };
    let reply_pkt = build_dns_response(src, &response);
    if let Err(e) = device
        .send(core::iter::once(ts_packet::PacketMut::from(reply_pkt)))
        .await
    {
        tracing::warn!(error = %e, "magic dns tun forwarded reply send failed");
    }
}

impl kameo::Actor for TunActor {
    type Args = (
        Env,
        ts_control::TunConfig,
        OverlayToDataplane,
        OverlayFromDataplane,
        // Host-route gating, derived from `Env` at the spawn site. v6 needs no flag:
        // `host_routes_from_node` drops it by construction.
        HostRouteGating,
        // The overlay netstack `Channel` (the forwarder netstack's, reused) used by
        // `intercept_magic_dns` to forward recursive / split-DNS queries over the overlay.
        Channel,
    );
    type Error = Error;

    async fn on_start(
        (env, tun_config, overlay_to_dataplane, overlay_from_dataplane, gating, channel): Self::Args,
        slf: ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        // We need the tailnet /32 prefix to build the device, which control only assigns at
        // runtime. Subscribe and build the device lazily on the first StateUpdate carrying a node.
        env.subscribe::<Arc<ts_control::StateUpdate>>(&slf).await?;
        // Also track peer state so the in-datapath MagicDNS responder can resolve peer names
        // authoritatively — mirrors `MagicDnsActor`'s `PeerState` subscription.
        env.subscribe::<Arc<PeerState>>(&slf).await?;

        // Seed the MagicDNS view with the runtime IPv6 gate (default off); control/peer updates
        // clone-and-modify it. Mirrors `MagicDnsActor::on_start`.
        let (dns_view, _) = watch::channel(Arc::new(DnsView {
            enable_ipv6: env.enable_ipv6,
            ..DnsView::default()
        }));

        Ok(Self {
            _joinset: JoinSet::new(),
            env,
            tun_config,
            overlay_to_dataplane: Some(overlay_to_dataplane),
            overlay_from_dataplane: Some(overlay_from_dataplane),
            gating,
            host_guard: None,
            dns_view,
            channel,
        })
    }
}

impl Message<Arc<ts_control::StateUpdate>> for TunActor {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: Arc<ts_control::StateUpdate>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        // Refresh the MagicDNS view from this control update (DNS config + self node), preserving
        // the peer db and the IPv6 gate. Read by the UP pump's in-datapath responder. Done on EVERY
        // update, including ones with no node (so a DNS-config-only update still lands). The exit
        // node is re-resolved against the (preserved) peer db so `exit_doh` tracks the active exit.
        let env = &self.env;
        self.dns_view.send_modify(|view| {
            *view = Arc::new(build_dns_view(
                env,
                &msg,
                view.peers.clone(),
                view.enable_ipv6,
            ));
        });

        let Some(self_node) = &msg.node else {
            return;
        };

        // Build the device exactly once: the first StateUpdate with a node `.take()`s the overlay
        // halves; subsequent updates find them gone and short-circuit.
        let (Some(up), Some(down)) = (
            self.overlay_to_dataplane.take(),
            self.overlay_from_dataplane.take(),
        ) else {
            return;
        };

        let device_config =
            tun_config_from_control(&self.tun_config, self_node.tailnet_address.ipv4);

        // FAIL-CLOSED, no silent fallback: a message handler cannot return `Result` to propagate a
        // device-creation failure back to `Runtime::spawn`, and the device cannot be created
        // eagerly at spawn time (the tailnet prefix is unknown until this first StateUpdate). So on
        // failure we log a single clear error line and leave the actor up but idle — no packets
        // flow (no leak), and we never fall back to a netstack or a direct dial.
        let device = match AsyncTunTransport::new(&device_config) {
            Ok(d) => Arc::new(d),
            Err(e) => {
                tracing::error!(error = %e, "TUN device creation failed; no overlay data path (fail-closed)");
                return;
            }
        };

        let if_name = device.name();

        // FAIL-CLOSED host integration: program routes/DNS before any packet flows. If host
        // programming is unsupported or fails, tear down and stay idle — never pump on an
        // unrouted TUN (a half-configured host could leak or black-hole). `apply_*`/`teardown` are
        // synchronous (they shell out via `std::process`); called directly here rather than via
        // `block_in_place` because the commands are fast (device creation above is likewise
        // effectively blocking) and `block_in_place` would panic under a current-thread runtime.
        let mut host = match ts_host_net::host_net() {
            Ok(h) => h,
            Err(e) => {
                tracing::error!(error = %e, "host net unsupported; TUN idle (fail-closed)");
                return;
            }
        };
        // Whether MagicDNS is enabled drives both the `100.100.100.100/32` route (so quad-100
        // queries enter the TUN) and pointing the host resolver at the MagicDNS IP.
        let magic_dns = msg.dns_config.as_ref().is_some_and(|d| d.magic_dns);
        let routes = host_routes_from_node(self_node, if_name.clone(), self.gating, magic_dns);
        if let Err(e) = host.apply_routes(&routes) {
            tracing::error!(error = %e, "host route programming failed; TUN idle (fail-closed)");
            host.teardown();
            return; // device drops here -> interface torn down; overlay halves already taken -> idle.
        }
        if let Err(e) = host.apply_dns(&host_dns_from_dns_config(msg.dns_config.as_ref(), if_name))
        {
            // Best-effort: routes are already up. With MagicDNS on, the resolver now points at
            // `100.100.100.100` (intercepted in the UP pump below); with it off, nameservers are
            // empty (no-op).
            tracing::warn!(error = %e, "host dns programming failed (continuing; routes are up)");
        }
        self.host_guard = Some(HostGuard(host));

        // UP: device -> {in-datapath MagicDNS responder | dataplane}.
        let dev_up = device.clone();
        let dns_view_rx = self.dns_view.subscribe();
        // The overlay `Channel` used by the MagicDNS responder to forward recursive / split-DNS
        // queries (the forwarder netstack's; egresses over the overlay — anti-leak).
        let dns_channel = self.channel.clone();
        self._joinset
            .spawn(up_pump(dev_up, up, dns_view_rx, dns_channel));

        // DOWN: dataplane -> device.
        let dev_down = device.clone();
        let mut down = down;
        self._joinset.spawn(async move {
            while let Some(bufs) = down.recv().await {
                if let Err(e) = dev_down.send(bufs).await {
                    tracing::warn!(error = %e, "tun send error");
                }
            }

            tracing::warn!("tun downlink shut down!");
        });

        tracing::debug!(prefix = ?self_node.tailnet_address.ipv4, "TUN device created");
    }
}

impl Message<Arc<PeerState>> for TunActor {
    type Reply = ();

    async fn handle(&mut self, state: Arc<PeerState>, _ctx: &mut Context<Self, Self::Reply>) {
        // Feed the peer database into the MagicDNS view so the in-datapath responder resolves peer
        // names authoritatively. Mirrors `MagicDnsActor`'s `PeerState` handler. Also re-resolve
        // `exit_doh` against the new peer set: the netstack path learns the active exit node from a
        // separate `ActiveExitNode` message (route-updater-published), but the TunActor has no such
        // subscription, so it tracks the exit node by resolving the selector against the peer db
        // here (and on every StateUpdate) — fail-closed `None` if unmatched / can't proxy DNS.
        let exit_doh = self.env.exit_node().as_ref().and_then(|sel| {
            let id = sel.resolve(state.peers.peers().values())?;
            state
                .peers
                .peers()
                .values()
                .find(|peer| peer.stable_id == id)
                .and_then(|n| n.peerapi_doh_addr())
        });
        self.dns_view.send_modify(|view| {
            let mut next = (**view).clone();
            next.peers = Some(state.peers.clone());
            next.exit_doh = exit_doh;
            *view = Arc::new(next);
        });
    }
}

#[cfg(test)]
mod tests {
    use core::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::Arc;

    use ipnet::Ipv4Net;
    use tokio::sync::watch;
    use ts_control::TunConfig;

    use super::{
        HostRouteGating, Intercept, build_dns_view, host_dns_from_dns_config,
        host_routes_from_node, plan_intercept, tun_config_from_control,
    };
    use crate::{
        env::{Env, ForwarderConfig},
        magic_dns::{Decision, RecursivePlan, decide, recursive_plan},
        peer_tracker::PeerDb,
    };

    /// Build a benign [`Env`] for `build_dns_view`. Only `exit_node` matters for these tests; every
    /// other forwarding preference is a default. `exit_node` is the caller-supplied selector.
    fn test_env(exit_node: Option<ts_control::ExitNodeSelector>) -> Env {
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        Env::new(
            ts_keys::NodeState::generate(),
            shutdown_rx,
            ForwarderConfig {
                accept_routes: false,
                exit_node,
                forward_routes: Vec::new(),
                forward_tcp_ports: Vec::new(),
                forward_udp_ports: Vec::new(),
                forward_all_ports: false,
                forward_exit_egress: false,
                exit_proxy: None,
                peerapi_port: None,
                taildrop_dir: None,
                enable_ipv6: false,
                persistent_keepalive_interval: None,
                ingress_active: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            },
        )
    }

    /// A peer node that advertises a peerAPI DoH endpoint (so [`Node::peerapi_doh_addr`] is `Some`):
    /// `peerapi_port` set and `peerapi_dns_proxy` true. Stable id / address are caller-supplied so a
    /// selector can target it.
    fn exit_peer(stable_id: &str, ipv4: &str, peerapi_port: u16) -> ts_control::Node {
        use ts_control::{Node, StableNodeId, TailnetAddress};
        Node {
            id: 2,
            user_id: 0,
            stable_id: StableNodeId(stable_id.to_string()),
            hostname: stable_id.to_string(),
            tailnet: Some("ts.net".to_string()),
            tags: vec![],
            tailnet_address: TailnetAddress {
                ipv4: format!("{ipv4}/32").parse().unwrap(),
                ipv6: "fd7a::2/128".parse().unwrap(),
            },
            node_key: [1u8; 32].into(),
            node_key_expiry: None,
            key_signature: vec![],
            machine_key: None,
            disco_key: None,
            accepted_routes: vec!["0.0.0.0/0".parse().unwrap()],
            underlay_addresses: vec![],
            derp_region: None,
            cap: Default::default(),
            cap_map: Default::default(),
            peerapi_port: Some(peerapi_port),
            peerapi_dns_proxy: true,
            is_wireguard_only: false,
            exit_node_dns_resolvers: vec![],
            peer_relay: false,
            service_vips: Default::default(),
        }
    }

    /// A `PeerDb` containing exactly the given exit peer.
    fn peer_db_with(peer: &ts_control::Node) -> Arc<PeerDb> {
        let mut db = PeerDb::default();
        db.upsert(peer);
        Arc::new(db)
    }

    /// A UDP global resolver, for building a recursive-forward query in [`forward_decision`].
    fn udp_resolver(addr: &str) -> ts_control::DnsResolver {
        ts_control::DnsResolver {
            transport: ts_control::ResolverTransport::Udp(addr.parse().unwrap()),
            use_with_exit_node: false,
        }
    }

    /// Build a DNS A query for `labels` (mirrors `magic_dns::tests::build_query`).
    fn build_query(id: u16, labels: &[&str]) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes()); // flags: QR=0 (query)
        buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        for label in labels {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0); // root label
        buf.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
        buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
        buf
    }

    /// Both gates on — the common exit-node + accept-routes case.
    fn gating_all() -> HostRouteGating {
        HostRouteGating {
            accept_routes: true,
            exit_node_configured: true,
        }
    }

    fn prefix() -> Ipv4Net {
        Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 1), 32).unwrap()
    }

    /// A self-node fixture: own host `/32`, an advertised subnet `/24`, and the exit-node default
    /// route `/0` — plus a v6 prefix to prove the v4-only filter drops it. Field set mirrors
    /// `route_updater::tests::split_router_node`.
    fn fixture_node() -> ts_control::Node {
        use ts_control::{Node, StableNodeId, TailnetAddress};
        Node {
            id: 1,
            user_id: 0,
            stable_id: StableNodeId("n1".to_string()),
            hostname: "self".to_string(),
            tailnet: Some("ts.net".to_string()),
            tags: vec![],
            tailnet_address: TailnetAddress {
                ipv4: "100.64.0.1/32".parse().unwrap(),
                ipv6: "fd7a::1/128".parse().unwrap(),
            },
            node_key: [0u8; 32].into(),
            node_key_expiry: None,
            // Cross-stream coupling (S4): `Node` gains `key_signature: Vec<u8>`. Empty here so this
            // fixture compiles after S4 lands; no TKA enforcement is exercised by tun_actor tests.
            key_signature: vec![],
            machine_key: None,
            disco_key: None,
            accepted_routes: vec![
                "100.64.0.1/32".parse().unwrap(),
                "fd7a::1/128".parse().unwrap(),
                "192.168.1.0/24".parse().unwrap(),
                "0.0.0.0/0".parse().unwrap(),
            ],
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

    /// With `accept_routes` and an exit node configured, the routed set carries the subnet `/24`
    /// and the default `/0`, but never the self `/32` (the device builder owns the on-link prefix).
    #[test]
    fn host_routes_includes_subnet_and_default_excludes_self() {
        let node = fixture_node();
        let routes = host_routes_from_node(&node, "utun9".to_owned(), gating_all(), false);

        assert_eq!(routes.if_name, "utun9");
        assert_eq!(routes.self_v4, "100.64.0.1/32".parse::<Ipv4Net>().unwrap());
        assert!(
            routes.routed.contains(&"192.168.1.0/24".parse().unwrap()),
            "subnet /24 must be routed when accept_routes is set"
        );
        assert!(
            routes.routed.contains(&"0.0.0.0/0".parse().unwrap()),
            "default /0 must be routed when an exit node is configured"
        );
        assert!(
            !routes.routed.contains(&"100.64.0.1/32".parse().unwrap()),
            "self /32 must never be re-routed"
        );
    }

    /// `accept_routes = false` drops advertised subnet routes (fail-closed).
    #[test]
    fn host_routes_excludes_subnet_without_accept_routes() {
        let node = fixture_node();
        let routes = host_routes_from_node(
            &node,
            "utun9".to_owned(),
            HostRouteGating {
                accept_routes: false,
                exit_node_configured: true,
            },
            false,
        );
        assert!(
            !routes.routed.contains(&"192.168.1.0/24".parse().unwrap()),
            "subnet /24 must be excluded when accept_routes is false"
        );
    }

    /// `exit_node_configured = false` drops the host `/0` (no exit node ⇒ no host default route).
    #[test]
    fn host_routes_excludes_default_without_exit_node() {
        let node = fixture_node();
        let routes = host_routes_from_node(
            &node,
            "utun9".to_owned(),
            HostRouteGating {
                accept_routes: true,
                exit_node_configured: false,
            },
            false,
        );
        assert!(
            !routes.routed.contains(&"0.0.0.0/0".parse().unwrap()),
            "default /0 must be excluded when no exit node is configured"
        );
    }

    /// IPv6 prefixes in `accepted_routes` are dropped by construction (v4-only invariant).
    #[test]
    fn host_routes_drops_ipv6() {
        // `HostRoutes.routed` is `Vec<Ipv4Net>`, so v6 cannot even be represented; assert
        // behaviorally that adding a v6 subnet route leaves the v4-only routed set unchanged.
        let baseline =
            host_routes_from_node(&fixture_node(), "utun9".to_owned(), gating_all(), false);

        let mut node_v6 = fixture_node();
        node_v6
            .accepted_routes
            .push("2001:db8::/32".parse().unwrap());
        let routes_v6 = host_routes_from_node(&node_v6, "utun9".to_owned(), gating_all(), false);

        assert_eq!(
            routes_v6.routed, baseline.routed,
            "adding a v6 subnet must not change the v4-only routed set"
        );
    }

    /// DNS: with MagicDNS enabled the host resolver points at `100.100.100.100` and search domains
    /// map through; with it disabled both stay empty (fail-closed no-op).
    #[test]
    fn host_dns_nameservers_point_at_magic_dns_when_enabled() {
        // No DNS config ⇒ empty everything (MagicDNS not enabled).
        let none = host_dns_from_dns_config(None, "utun9".to_owned());
        assert!(none.nameservers.is_empty());
        assert!(none.match_domains.is_empty());

        // MagicDNS on ⇒ resolver points at the MagicDNS IP + search domains carried.
        let on = ts_control::DnsConfig {
            magic_dns: true,
            search_domains: vec!["user.ts.net.".to_owned()],
            ..Default::default()
        };
        let dns_on = host_dns_from_dns_config(Some(&on), "utun9".to_owned());
        assert_eq!(
            dns_on.nameservers,
            vec![Ipv4Addr::new(100, 100, 100, 100)],
            "nameservers must point at the MagicDNS IP when MagicDNS is enabled"
        );
        assert_eq!(dns_on.match_domains, vec!["user.ts.net.".to_owned()]);

        // MagicDNS off ⇒ empty nameservers (no dead address) AND no search domains.
        let off = ts_control::DnsConfig {
            magic_dns: false,
            search_domains: vec!["user.ts.net.".to_owned()],
            ..Default::default()
        };
        let dns_off = host_dns_from_dns_config(Some(&off), "utun9".to_owned());
        assert!(
            dns_off.nameservers.is_empty(),
            "nameservers must stay empty when MagicDNS is disabled"
        );
        assert!(dns_off.match_domains.is_empty());
    }

    /// The MagicDNS service IP `100.100.100.100/32` is steered into the TUN exactly when MagicDNS is
    /// enabled (so the host's quad-100 queries enter the datapath), and never when it is disabled.
    #[test]
    fn host_routes_includes_magic_dns_when_enabled() {
        let node = fixture_node();
        let magic_dns_net: Ipv4Net = "100.100.100.100/32".parse().unwrap();

        let with = host_routes_from_node(&node, "utun9".to_owned(), gating_all(), true);
        assert!(
            with.routed.contains(&magic_dns_net),
            "100.100.100.100/32 must be routed when MagicDNS is enabled"
        );

        let without = host_routes_from_node(&node, "utun9".to_owned(), gating_all(), false);
        assert!(
            !without.routed.contains(&magic_dns_net),
            "100.100.100.100/32 must not be routed when MagicDNS is disabled"
        );
    }

    /// `classify_magic_dns` extracts the DNS payload + source endpoint from a quad-100/UDP/53
    /// packet, and `build_dns_response` round-trips: the synthesized reply parses back as an
    /// IPv4/UDP datagram FROM `100.100.100.100:53` TO the original querier carrying the payload.
    #[test]
    fn classify_and_build_round_trip() {
        use super::{build_dns_response, classify_magic_dns};

        let client: SocketAddrV4 = "100.64.0.7:34567".parse().unwrap();
        let payload = b"hello-dns-query";

        // Hand-build an IPv4/UDP packet: client -> 100.100.100.100:53.
        let query_pkt = {
            let b = etherparse::PacketBuilder::ipv4(client.ip().octets(), [100, 100, 100, 100], 64)
                .udp(client.port(), 53);
            let mut out = Vec::with_capacity(b.size(payload.len()));
            b.write(&mut out, payload).unwrap();
            out
        };

        let q = classify_magic_dns(&query_pkt).expect("quad-100/udp/53 is classified as DNS");
        assert_eq!(q.src, client, "source endpoint extracted");
        assert_eq!(q.dns_payload, payload, "DNS payload extracted");

        // Build a response carrying a (different) payload and confirm src/dst swap + payload.
        let resp_payload = b"a-dns-answer";
        let reply_pkt = build_dns_response(client, resp_payload);
        let sliced = etherparse::SlicedPacket::from_ip(&reply_pkt).expect("reply parses");
        match sliced.net {
            Some(etherparse::NetSlice::Ipv4(ip)) => {
                assert_eq!(
                    ip.header().source_addr(),
                    Ipv4Addr::new(100, 100, 100, 100),
                    "reply is FROM the MagicDNS service IP"
                );
                assert_eq!(
                    ip.header().destination_addr(),
                    *client.ip(),
                    "reply is TO the original querier"
                );
            }
            _ => panic!("reply must be IPv4"),
        }
        match sliced.transport {
            Some(etherparse::TransportSlice::Udp(udp)) => {
                assert_eq!(udp.source_port(), 53, "reply source port is 53");
                assert_eq!(
                    udp.destination_port(),
                    client.port(),
                    "reply dest port is the querier's source port"
                );
                assert_eq!(udp.payload(), resp_payload, "reply carries the DNS answer");
            }
            _ => panic!("reply must be UDP"),
        }
    }

    /// Non-matching packets pass through (`classify_magic_dns` returns `None`): wrong destination
    /// IP, wrong port, and a non-UDP (TCP) packet to quad-100.
    #[test]
    fn classify_passthrough_for_non_dns() {
        use super::classify_magic_dns;

        let client: SocketAddrV4 = "100.64.0.7:1234".parse().unwrap();

        // UDP/53 but to a different IP (a real upstream resolver) — must pass through.
        let to_other_ip = {
            let b = etherparse::PacketBuilder::ipv4(client.ip().octets(), [8, 8, 8, 8], 64)
                .udp(client.port(), 53);
            let mut out = Vec::new();
            b.write(&mut out, b"x").unwrap();
            out
        };
        assert!(
            classify_magic_dns(&to_other_ip).is_none(),
            "UDP/53 to a non-quad-100 IP must pass through"
        );

        // UDP to quad-100 but a different port — must pass through.
        let wrong_port = {
            let b = etherparse::PacketBuilder::ipv4(client.ip().octets(), [100, 100, 100, 100], 64)
                .udp(client.port(), 443);
            let mut out = Vec::new();
            b.write(&mut out, b"x").unwrap();
            out
        };
        assert!(
            classify_magic_dns(&wrong_port).is_none(),
            "non-53 dport to quad-100 must pass through"
        );

        // TCP to quad-100:53 — must pass through (we only intercept UDP).
        let tcp = {
            let b = etherparse::PacketBuilder::ipv4(client.ip().octets(), [100, 100, 100, 100], 64)
                .tcp(client.port(), 53, 0, 1024);
            let mut out = Vec::new();
            b.write(&mut out, b"x").unwrap();
            out
        };
        assert!(
            classify_magic_dns(&tcp).is_none(),
            "TCP to quad-100:53 must pass through (UDP-only intercept)"
        );

        // Garbage / non-IP bytes — must pass through (unparseable).
        assert!(
            classify_magic_dns(&[0u8; 4]).is_none(),
            "unparseable bytes must pass through"
        );
    }

    /// Build a `StateUpdate` carrying the self node + a MagicDNS-on config with the given global
    /// resolvers (used to drive a recursive forward).
    fn dns_update(resolvers: Vec<ts_control::DnsResolver>) -> ts_control::StateUpdate {
        ts_control::StateUpdate {
            session_handle: None,
            seq: 0,
            derp: None,
            node: Some(fixture_node()),
            peer_update: None,
            peer_patches: Vec::new(),
            user_profiles: Vec::new(),
            ping: None,
            packetfilter: None,
            cap_grants: None,
            pop_browser_url: None,
            dial_plan: None,
            dns_config: Some(ts_control::DnsConfig {
                magic_dns: true,
                search_domains: vec!["user.ts.net".to_owned()],
                resolvers,
                ..Default::default()
            }),
            ssh_policy: None,
            tka: None,
        }
    }

    /// `build_dns_view` mirrors `MagicDnsActor`'s construction: cfg + self_node from the update,
    /// `enable_ipv6` threaded. `exit_doh` covers BOTH cases: no exit node configured (or unresolved)
    /// ⇒ `None`; a configured selector that resolves to an active exit peer with a peerAPI DoH
    /// endpoint ⇒ `Some(addr)`.
    #[tokio::test]
    async fn build_dns_view_maps_update() {
        let update = dns_update(vec![]);

        // No exit node configured ⇒ exit_doh None (even with a peer db present).
        let no_exit_env = test_env(None);
        let peer = exit_peer("exit", "100.64.0.9", 1080);
        let db = peer_db_with(&peer);
        let view = build_dns_view(&no_exit_env, &update, Some(db.clone()), true);
        assert!(view.cfg.magic_dns, "dns config carried");
        assert!(view.self_node.is_some(), "self node carried");
        assert!(view.peers.is_some(), "peer db passed through");
        assert!(
            view.exit_doh.is_none(),
            "no exit node configured ⇒ exit_doh None"
        );
        assert!(view.enable_ipv6, "ipv6 gate threaded from Env");

        // Active exit node configured + a peer with a peerAPI DoH endpoint ⇒ exit_doh Some(addr),
        // resolved from the selector against the peer db (mirrors magic_dns.rs:751 + route_updater).
        let exit_env = test_env(Some(ts_control::ExitNodeSelector::StableId(
            ts_control::StableNodeId("exit".to_owned()),
        )));
        let view = build_dns_view(&exit_env, &update, Some(db), true);
        assert_eq!(
            view.exit_doh,
            peer.peerapi_doh_addr(),
            "exit_doh resolves to the active exit peer's peerAPI DoH address"
        );
        assert_eq!(
            view.exit_doh,
            Some("100.64.0.9:1080".parse().unwrap()),
            "exit_doh is the peer's tailnet IPv4 + peerAPI port"
        );

        // A configured selector that matches no peer ⇒ exit_doh None (fail-closed, recursion local).
        let ghost_env = test_env(Some(ts_control::ExitNodeSelector::StableId(
            ts_control::StableNodeId("ghost".to_owned()),
        )));
        let view = build_dns_view(&ghost_env, &update, Some(peer_db_with(&peer)), true);
        assert!(
            view.exit_doh.is_none(),
            "unresolved selector ⇒ exit_doh None (fail-closed)"
        );
    }

    /// A `Decision::Forward` for a public name now produces a real forwarded plan (recursive ⇒
    /// `RecursivePlan::Udp` of the configured upstreams when no exit node is active, or
    /// `RecursivePlan::Doh` when one is). This asserts the plan branch the UP pump dispatches on, not
    /// live socket I/O (a full forward needs a netstack) — same convention as the `serve.rs` tests.
    /// Critically: the upstreams come only from `decide`/`recursive_plan`, both of which already
    /// `.filter(SocketAddr::is_ipv4)`, so this path never constructs an upstream `SocketAddr`.
    #[tokio::test]
    async fn forward_decision_produces_udp_then_doh_plan() {
        // Public name + a global UDP resolver ⇒ recursive Forward.
        let update = dns_update(vec![udp_resolver("8.8.8.8:53")]);
        let env = test_env(None);
        let peer = exit_peer("exit", "100.64.0.9", 1080);
        let view = build_dns_view(&env, &update, Some(peer_db_with(&peer)), true);
        let query = build_query(0x4242, &["example", "com"]);

        let (upstreams, recursive) = match decide(&view, &query).expect("decides") {
            Decision::Forward {
                upstreams,
                recursive,
                ..
            } => (upstreams, recursive),
            Decision::Reply(_) => panic!("a public name with a global resolver must Forward"),
        };
        assert!(recursive, "an unrouted public name is a recursive forward");
        assert_eq!(
            upstreams,
            vec!["8.8.8.8:53".parse().unwrap()],
            "the IPv4 global resolver is the upstream (v4-only filter inherited)"
        );

        // No exit node active ⇒ the recursive plan keeps the UDP upstreams.
        match recursive_plan(&view, upstreams.clone()) {
            RecursivePlan::Udp(ups) => assert_eq!(ups, upstreams, "no exit node ⇒ UDP plan"),
            RecursivePlan::Doh(_) => panic!("no exit node configured ⇒ must not delegate to DoH"),
        }

        // With an active exit node (DoH-capable) and no use-with-exit-node resolvers, the recursive
        // plan delegates to the exit node's DoH endpoint — the overlay-egress branch.
        let exit_env = test_env(Some(ts_control::ExitNodeSelector::StableId(
            ts_control::StableNodeId("exit".to_owned()),
        )));
        let exit_view = build_dns_view(&exit_env, &update, Some(peer_db_with(&peer)), true);
        match recursive_plan(&exit_view, upstreams) {
            RecursivePlan::Doh(addr) => assert_eq!(
                Some(addr),
                peer.peerapi_doh_addr(),
                "active exit node ⇒ delegate recursion to its peerAPI DoH endpoint"
            ),
            RecursivePlan::Udp(_) => panic!("active exit node with no kept-local resolvers ⇒ DoH"),
        }
    }

    /// Wrap a DNS payload in an IPv4/UDP packet `client -> 100.100.100.100:53` — a packet the UP
    /// pump's intercept classifies as a MagicDNS query.
    fn quad100_query_packet(client: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
        let b = etherparse::PacketBuilder::ipv4(client.ip().octets(), [100, 100, 100, 100], 64)
            .udp(client.port(), 53);
        let mut out = Vec::with_capacity(b.size(payload.len()));
        b.write(&mut out, payload).unwrap();
        out
    }

    /// HOL-blocking regression: the UP pump's intercept must hand a `Decision::Forward` back as
    /// [`Intercept::Forward`] (a plan to SPAWN) rather than awaiting the overlay round-trip inline —
    /// so one slow/hung upstream can never head-of-line-block the entire TUN uplink. `plan_intercept`
    /// is the pure, synchronous decision seam (no device, no `await`): if it ever returned only after
    /// the forward completed, a forward could not be a synchronous return value at all. This also
    /// pins the fast-path classifications the pump relies on: a non-MagicDNS packet forwards to the
    /// overlay, an authoritative reply is carried out for an inline write, and a malformed query is
    /// dropped. The forward's upstreams come only from `decide`/`recursive_plan` (v4-only filtered),
    /// so this path never constructs an upstream `SocketAddr` (IPv4-only egress invariant inherited).
    #[tokio::test]
    async fn intercept_plan_spawns_forward_and_classifies_fast_paths() {
        let client: SocketAddrV4 = "100.64.0.7:34567".parse().unwrap();

        // A public name with a global UDP resolver and no exit node ⇒ a recursive Forward whose plan
        // is `RecursivePlan::Udp` of the configured upstream. Crucially this is RETURNED, not awaited
        // — the pump spawns it (see the UP pump's `forwards.spawn(run_forward(...))`).
        let update = dns_update(vec![udp_resolver("8.8.8.8:53")]);
        let env = test_env(None);
        let peer = exit_peer("exit", "100.64.0.9", 1080);
        let view = build_dns_view(&env, &update, Some(peer_db_with(&peer)), true);

        let fwd_pkt = quad100_query_packet(client, &build_query(0x4242, &["example", "com"]));
        match plan_intercept(&view, &fwd_pkt) {
            Intercept::Forward {
                plan, src, query, ..
            } => {
                assert_eq!(
                    src, client,
                    "forward reply is addressed back to the querier"
                );
                assert!(
                    !query.is_empty(),
                    "the original query bytes are carried verbatim"
                );
                match plan {
                    RecursivePlan::Udp(ups) => assert_eq!(
                        ups,
                        vec!["8.8.8.8:53".parse().unwrap()],
                        "no exit node ⇒ UDP plan of the v4-only-filtered upstream (never built here)"
                    ),
                    RecursivePlan::Doh(_) => panic!("no exit node configured ⇒ must not be DoH"),
                }
            }
            _ => panic!("a public name with a global resolver must yield a SPAWNED Forward plan"),
        }

        // A tailnet self-name `A` query is answered authoritatively from the view (an INLINE Reply
        // carried out for the pump to write back), or — lacking overlay address data in this
        // fixture — Forwarded; either way it is consumed, never passed through.
        let reply_pkt =
            quad100_query_packet(client, &build_query(0x1, &["self", "user", "ts", "net"]));
        match plan_intercept(&view, &reply_pkt) {
            Intercept::Reply { src, response } => {
                assert_eq!(
                    src, client,
                    "the inline reply is addressed back to the querier"
                );
                assert!(
                    !response.is_empty(),
                    "an authoritative reply carries response bytes"
                );
            }
            other => assert!(
                matches!(other, Intercept::Forward { .. }),
                "a tailnet self-name is answered authoritatively (Reply) or, lacking overlay data, \
                 Forwarded — never NotIntercepted/Dropped"
            ),
        }

        // A non-MagicDNS packet (UDP/53 to a real upstream IP) forwards to the overlay unchanged.
        let passthrough = {
            let b = etherparse::PacketBuilder::ipv4(client.ip().octets(), [8, 8, 8, 8], 64)
                .udp(client.port(), 53);
            let mut out = Vec::new();
            b.write(&mut out, b"x").unwrap();
            out
        };
        assert!(
            matches!(
                plan_intercept(&view, &passthrough),
                Intercept::NotIntercepted
            ),
            "a packet not destined to quad-100:53 must pass through to the overlay"
        );

        // A malformed query to quad-100:53 is consumed but dropped silently (never forwarded).
        let malformed = quad100_query_packet(client, &[0xff, 0x00]);
        assert!(
            matches!(plan_intercept(&view, &malformed), Intercept::Dropped),
            "a malformed quad-100/UDP/53 query is dropped, never forwarded to the overlay"
        );
    }

    /// Defaults must apply when control supplies no knobs: name `tailscale0`, MTU `1280`, and the
    /// device prefix must be exactly the runtime-assigned `/32` passed in.
    #[test]
    fn defaults_and_prefix() {
        let cfg = TunConfig {
            name: None,
            mtu: None,
        };
        let dev = tun_config_from_control(&cfg, prefix());

        assert_eq!(dev.name, "tailscale0");
        assert_eq!(dev.mtu.get(), 1280);
        assert_eq!(dev.prefix, ipnet::IpNet::V4(prefix()));
    }

    /// `mtu = Some(0)` is invalid (NonZeroU16 rejects it) and must fall back to the 1280 default,
    /// while a real MTU is honored. A custom name is honored verbatim.
    #[test]
    fn mtu_zero_falls_back_and_overrides_honored() {
        let zero = TunConfig {
            name: Some("tun9".to_owned()),
            mtu: Some(0),
        };
        let dev_zero = tun_config_from_control(&zero, prefix());
        assert_eq!(dev_zero.name, "tun9");
        assert_eq!(
            dev_zero.mtu.get(),
            1280,
            "mtu=Some(0) must fall back to 1280"
        );

        let big = TunConfig {
            name: None,
            mtu: Some(9000),
        };
        let dev_big = tun_config_from_control(&big, prefix());
        assert_eq!(dev_big.mtu.get(), 9000, "a valid mtu must be honored");
    }
}
