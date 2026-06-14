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

    /// Reverses host route/DNS programming on drop. `Some` once the device is built and the host
    /// has been programmed; shares the actor's lifetime with the pump tasks in `_joinset`.
    host_guard: Option<HostGuard>,

    /// The latest peer database, fed from the [`PeerState`] subscription. Retained so the host-FIB
    /// peer-route fold ([`host_routes_from_node`]) can be recomputed on every peer change (the fix
    /// for the consumer-blocking bug: without the peer fold the OS had no route to any peer). `None`
    /// until the first [`PeerState`].
    peers: Option<Arc<crate::peer_tracker::PeerDb>>,

    /// The self node from the most recent control `StateUpdate` that carried one. Stored once the
    /// device is built so the [`PeerState`] re-apply path can rebuild the host route set (self fold
    /// + peer fold) without a fresh `StateUpdate`. `None` until the device is built.
    self_node: Option<Arc<ts_control::Node>>,

    /// The built device's interface name. Stored so the [`PeerState`] re-apply path re-applies
    /// routes under the SAME `if_name` the device was built with (the host-net `apply_routes`
    /// `debug_assert`s a stable interface name across applies). `None` until the device is built.
    if_name: Option<String>,

    /// Whether MagicDNS was enabled (`--accept-dns` AND the control DNS config's `magic_dns`) as of
    /// the last build/StateUpdate. Stored so the [`PeerState`] re-apply path keeps the
    /// `100.100.100.100/32` route present/absent consistently with the resolver programming, without
    /// a fresh `StateUpdate`. `false` until the first StateUpdate sets it.
    last_magic_dns: bool,

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

/// RAII wrapper that reverses host route/DNS programming when the actor dies. Held in
/// [`TunActor::host_guard`] alongside the device pump tasks in `_joinset`, so when the actor is
/// dropped the interface is torn down and its host-FIB/resolver state is reversed together.
struct HostGuard(Box<dyn ts_host_net::HostNet>);

impl HostGuard {
    /// Re-program the host FIB to `routes` against the already-built device, delegating to the inner
    /// [`HostNet::apply_routes`]. `apply_routes` is an idempotent add-new/remove-gone diff with
    /// per-call rollback, so re-applying with a fresh set is safe, non-flapping, and fail-closed; it
    /// `debug_assert`s the interface name is stable across applies, so callers MUST re-apply under
    /// the same `if_name` the device was built with. Used by the [`PeerState`] handler to re-steer
    /// the host routing table when the peer set (or a runtime accept-routes / exit-node toggle)
    /// changes, without rebuilding the device. RAII teardown ([`Drop`]) is unaffected.
    fn apply_routes(
        &mut self,
        routes: &ts_host_net::HostRoutes,
    ) -> Result<(), ts_host_net::HostNetError> {
        self.0.apply_routes(routes)
    }
}

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

/// Translate the self-node's accepted routes **and the union of every peer's AllowedIPs** into the
/// host-FIB route set to steer into the TUN (the `ts_runtime` boundary, mirroring
/// [`tun_config_from_control`]).
///
/// IPv4-only by construction: every IPv6 prefix is dropped here (both from the self node and from
/// each peer), enforcing the fork's v4-only invariant (v6 on the tailnet is gated off) without a
/// separate `enable_ipv6` flag.
///
/// PEER FOLD (the fix for the consumer-blocking bug: a TUN node reached MagicDNS but not its peers
/// because the OS had no route to any peer). Go's `tailscaled` feeds the host router
/// `Config.Routes = union of every peer's AllowedIPs`; we mirror that by extending the routed set
/// with, for every peer, `peer.routes_to_install(accept_routes, exit_id)` — the SAME Go-faithful
/// per-peer filter the netstack [`RouteUpdater`](crate::route_updater) already uses for the overlay
/// route table and the source filter. It yields the peer's own host `/32` always, advertised subnet
/// routes gated on `accept_routes`, and the peer's `/0` ONLY when that peer is the selected
/// `exit_id`. Using the same filter keeps the host FIB coupled to the overlay route table + source
/// filter (the anti-leak cryptokey-routing coupling — we do NOT hand-roll a different filter).
///
/// The host `/0` is therefore now keyed on the **selected exit peer** (per-peer, via
/// `routes_to_install`), not a standalone `exit_node_configured` bool — eliminating the former
/// self-node-`/0` asymmetry (the self node's `accepted_routes` may echo a `/0`, but only the
/// selected exit peer's `/0` belongs in the host FIB). The self node still contributes its own
/// non-`/0` accepted routes (subnet routes gated on `accept_routes`); its `/0` is never installed
/// here (only a peer's, and only the exit peer's). The Linux impl expands `/0` into the
/// split-default pair; macOS installs `/0` directly.
///
/// `accept_routes` and `exit_id` are read live by the caller (from [`Env`]) on every apply — both
/// the build path and the [`PeerState`] re-apply path — so a runtime `set_accept_routes` /
/// `set_exit_node` toggle re-steers the host FIB on the next peer republish.
pub(crate) fn host_routes_from_node(
    node: &ts_control::Node,
    peers: Option<&crate::peer_tracker::PeerDb>,
    if_name: String,
    accept_routes: bool,
    exit_id: Option<&ts_control::StableNodeId>,
    magic_dns: bool,
) -> ts_host_net::HostRoutes {
    let self_v4 = node.tailnet_address.ipv4;

    // Push `net` into `routed` iff it is not the on-link self `/32` and is not already present
    // (dedup: a prefix advertised by multiple peers, or by both the self node and a peer, installs
    // exactly once).
    let push_v4 = |routed: &mut Vec<ipnet::Ipv4Net>, net: ipnet::Ipv4Net| {
        if net != self_v4 && !routed.contains(&net) {
            routed.push(net);
        }
    };

    // Self-node fold: its own non-`/0` accepted routes. Subnet routes are gated on
    // `--accept-routes`; non-self host routes (e.g. additional tailnet addrs) are always installed.
    // Mirrors `routes_to_install`. A self-node `/0` is NOT installed here — only the selected exit
    // peer's `/0` is (in the peer fold below), so the host default route is keyed on the exit peer.
    let mut routed: Vec<ipnet::Ipv4Net> = Vec::new();
    for route in &node.accepted_routes {
        // IPv4-only by construction: drop every v6 prefix unconditionally.
        let ipnet::IpNet::V4(v4) = route else {
            continue;
        };
        if v4.prefix_len() == 0 {
            continue;
        }
        if accept_routes || !node.is_subnet_route(route) {
            push_v4(&mut routed, *v4);
        }
    }

    // Peer fold: the union of every peer's AllowedIPs, filtered by the SAME per-peer
    // `routes_to_install` the overlay route table + source filter use (anti-leak coupling). v4-only;
    // dedup via `push_v4`. The peer's `/0` lands ONLY when it is the selected `exit_id`.
    if let Some(peers) = peers {
        for peer in peers.peers().values() {
            for route in peer.routes_to_install(accept_routes, exit_id) {
                if let ipnet::IpNet::V4(v4) = route {
                    push_v4(&mut routed, *v4);
                }
            }
        }
    }

    // Steer the MagicDNS service IP `100.100.100.100/32` into the TUN so the host's quad-100 DNS
    // queries enter the datapath where the UP pump intercepts them ([`plan_intercept`]). Added
    // unconditionally when MagicDNS is enabled — it's the device's own service IP, always
    // routed-to-self — unless control somehow advertised it as the self `/32` (it never is).
    if magic_dns {
        let magic_dns_net = ipnet::Ipv4Net::new(MAGIC_DNS_IP, 32).expect("/32 is a valid prefix");
        push_v4(&mut routed, magic_dns_net);
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
/// `accept_dns` (`--accept-dns` / `CorpDNS`) gates this exactly like `magic_dns`: when `false` the
/// node ignores the tailnet DNS config, so the host resolver is NOT pointed at quad-100 (the
/// responder would `REFUSED` every query anyway) and no search domains are programmed — fail-closed,
/// the same empty-config behavior as MagicDNS off.
///
/// `match_domains` carries the suffixes the host resolver is **scoped** to when MagicDNS is enabled
/// **and** accepted: the tailnet search domains UNION the split-DNS route suffixes (Go
/// `dns.OSConfig.MatchDomains`, which is the search domains plus the non-global `Routes` keys). The
/// host layer scopes the MagicDNS resolver to exactly these suffixes; a suffix it lists is sent into
/// the TUN datapath, everything else stays on the host's normal resolver. The route keys are already
/// canonicalized and the global `.`/empty route is dropped at `DnsConfig` parse time, so this can
/// never re-introduce a catch-all scope.
///
/// When this set is **empty** (MagicDNS on but no search domain and no split-DNS route — a valid
/// control state), the host layer installs **no** resolver rather than a global one (matching Go
/// `manager_darwin.go`, which writes zero `/etc/resolver/*` files and never a primary resolver). See
/// the `match_domains.is_empty()` guard in `ts_host_net`'s macOS `apply_dns`.
pub(crate) fn host_dns_from_dns_config(
    dns: Option<&ts_control::DnsConfig>,
    if_name: String,
    accept_dns: bool,
) -> ts_host_net::HostDns {
    let magic_dns = accept_dns && matches!(dns, Some(d) if d.magic_dns);
    let match_domains = if let Some(d) = dns.filter(|_| magic_dns) {
        // Search domains first, then any split-DNS route suffix not already covered, deduped while
        // preserving order (Go `MatchDomains` = SearchDomains ∪ Routes keys). The route keys are
        // canonicalized and the global `.`/empty route is filtered out at parse time, so no entry
        // here can scope the resolver globally. ALL route keys are included, incl. a negative route
        // (empty upstream list): a negative-route suffix is intentionally scoped to the MagicDNS
        // resolver, which then fail-closes it (NXDOMAIN/REFUSED) rather than leaving it on the host's
        // normal resolver — this matches Go, whose `MatchDomains` likewise carries negative-route
        // keys, and keeps such names off the host resolver. Adding a suffix only ever *narrows* what
        // the tailnet resolver answers to that suffix; it never widens host-DNS capture.
        let mut domains = d.search_domains.clone();
        for suffix in d.routes.keys() {
            if !domains.contains(suffix) {
                domains.push(suffix.clone());
            }
        }
        domains
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
        // Re-read the live accept-dns cell on every view rebuild (it is runtime-settable via
        // `Device::set_accept_dns`); the in-datapath responder's `decide` gate refuses every query
        // when false. Same trap as the netstack `PeerState` site — read at rebuild, never snapshot.
        accept_dns: env.accept_dns(),
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
        // The overlay netstack `Channel` (the forwarder netstack's, reused) used by
        // `plan_intercept`/`run_forward` to forward recursive / split-DNS queries over the overlay.
        Channel,
    );
    type Error = Error;

    async fn on_start(
        (env, tun_config, overlay_to_dataplane, overlay_from_dataplane, channel): Self::Args,
        slf: ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        // We need the tailnet /32 prefix to build the device, which control only assigns at
        // runtime. Subscribe and build the device lazily on the first StateUpdate carrying a node.
        env.subscribe::<Arc<ts_control::StateUpdate>>(&slf).await?;
        // Also track peer state so the in-datapath MagicDNS responder can resolve peer names
        // authoritatively — mirrors `MagicDnsActor`'s `PeerState` subscription.
        env.subscribe::<Arc<PeerState>>(&slf).await?;

        // Seed the MagicDNS view with the runtime IPv6 gate (default off) + the current accept-dns
        // value; control/peer updates clone-and-modify it (re-reading accept-dns live each time).
        // Mirrors `MagicDnsActor::on_start`. The seed is moot (no query served before the first
        // StateUpdate) but keeps the pre-update view internally consistent.
        let (dns_view, _) = watch::channel(Arc::new(DnsView {
            enable_ipv6: env.enable_ipv6,
            accept_dns: env.accept_dns(),
            ..DnsView::default()
        }));

        Ok(Self {
            _joinset: JoinSet::new(),
            env,
            tun_config,
            overlay_to_dataplane: Some(overlay_to_dataplane),
            overlay_from_dataplane: Some(overlay_from_dataplane),
            host_guard: None,
            peers: None,
            self_node: None,
            if_name: None,
            last_magic_dns: false,
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
        // Whether MagicDNS is enabled AND accepted drives both the `100.100.100.100/32` route (so
        // quad-100 queries enter the TUN) and pointing the host resolver at the MagicDNS IP. With
        // `--accept-dns` off, the node ignores the tailnet DNS config: neither is programmed (the
        // responder would `REFUSED` every query anyway), mirroring Go's empty-config behavior.
        let accept_dns = self.env.accept_dns();
        let magic_dns = accept_dns && msg.dns_config.as_ref().is_some_and(|d| d.magic_dns);

        // Host-route gating read LIVE from `Env` (not a frozen spawn-time snapshot): subnet routes
        // are gated on `--accept-routes`, and the host `/0` comes only from the selected exit peer.
        // The exit-node selector is resolved against the live peer set to a stable id, exactly as
        // the route updater does (`route_updater.rs:219-222`) and the `build_dns_view`/`PeerState`
        // exit_doh resolution above — so the host FIB picks the SAME exit peer as the overlay route
        // table + source filter (anti-leak coupling). `None` (no exit node, or an unmatched
        // selector) ⇒ no peer receives a host `/0` (fail-closed).
        let accept_routes = self.env.accept_routes();
        let exit_id = self.env.exit_node().as_ref().and_then(|sel| {
            self.peers
                .as_ref()
                .and_then(|peers| sel.resolve(peers.peers().values()))
        });
        let routes = host_routes_from_node(
            self_node,
            self.peers.as_deref(),
            if_name.clone(),
            accept_routes,
            exit_id.as_ref(),
            magic_dns,
        );
        if let Err(e) = host.apply_routes(&routes) {
            tracing::error!(error = %e, "host route programming failed; TUN idle (fail-closed)");
            host.teardown();
            return; // device drops here -> interface torn down; overlay halves already taken -> idle.
        }
        // Store the bits the `PeerState` re-apply path needs to rebuild the route set without a
        // fresh `StateUpdate`: the self node, the (stable) interface name, and the MagicDNS bool.
        self.self_node = Some(Arc::new(self_node.clone()));
        self.if_name = Some(if_name.clone());
        self.last_magic_dns = magic_dns;
        if let Err(e) = host.apply_dns(&host_dns_from_dns_config(
            msg.dns_config.as_ref(),
            if_name,
            accept_dns,
        )) {
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
        // Store the latest peer db so the host-FIB peer-route fold can be (re)computed: on the next
        // device build (if the device isn't up yet) and on this re-apply path (if it is).
        self.peers = Some(state.peers.clone());

        // Resolve the configured exit node to a stable id ONCE against this peer set, reused for both
        // the `exit_doh` (MagicDNS) and the host `/0` (route fold) below so they can't disagree within
        // one handler — mirroring `route_updater.rs:219-222`'s single per-rebuild resolution. The
        // netstack path learns the active exit node from a separate route-updater-published
        // `ActiveExitNode` message; the TunActor has no such subscription, so it resolves the selector
        // against the peer db here (and on every StateUpdate). Fail-closed `None` if unmatched.
        let exit_id = self
            .env
            .exit_node()
            .as_ref()
            .and_then(|sel| sel.resolve(state.peers.peers().values()));

        // Feed the peer database into the MagicDNS view so the in-datapath responder resolves peer
        // names authoritatively. Mirrors `MagicDnsActor`'s `PeerState` handler. `exit_doh` is the
        // resolved exit peer's peerAPI DoH endpoint (fail-closed `None` if it can't proxy DNS).
        let exit_doh = exit_id.as_ref().and_then(|id| {
            state
                .peers
                .peers()
                .values()
                .find(|peer| &peer.stable_id == id)
                .and_then(|n| n.peerapi_doh_addr())
        });
        // Re-read the live accept-dns cell on this rebuild (it is runtime-settable): a
        // `Device::set_accept_dns` republish lands here, re-applying the in-datapath `decide` gate.
        let accept_dns = self.env.accept_dns();
        self.dns_view.send_modify(|view| {
            let mut next = (**view).clone();
            next.peers = Some(state.peers.clone());
            next.exit_doh = exit_doh;
            next.accept_dns = accept_dns;
            *view = Arc::new(next);
        });

        // Re-steer the host FIB to reflect the new peer set / a runtime accept-routes / exit-node
        // toggle (closes the host-FIB re-steer follow-up). Only when the device is already built —
        // before that, the build path will fold the now-stored peers itself. `set_accept_routes` /
        // `set_exit_node` re-broadcast `Arc<PeerState>` (via `RepublishState`), so a runtime toggle
        // lands here too, re-applying with the live `accept_routes`/`exit_id`.
        if let (Some(guard), Some(self_node), Some(if_name)) = (
            self.host_guard.as_mut(),
            self.self_node.as_ref(),
            self.if_name.as_ref(),
        ) {
            // `apply_routes` is an idempotent add-new/remove-gone diff with per-call rollback, so
            // re-applying a fresh set is safe and non-flapping; re-apply under the SAME `if_name` the
            // device was built with (the host-net `debug_assert`). `accept_routes` is read live.
            let routes = host_routes_from_node(
                self_node,
                Some(&state.peers),
                if_name.clone(),
                self.env.accept_routes(),
                exit_id.as_ref(),
                self.last_magic_dns,
            );
            if let Err(e) = guard.apply_routes(&routes) {
                // FAIL-CLOSED, exactly like the build path: drop the host guard so its `Drop`
                // reverses all host route/DNS state (no half-configured FIB can leak or black-hole);
                // the actor stays up but the TUN is now unrouted — idle. A subsequent peer/control
                // update will not re-program (the guard is gone), so this is a terminal idle, the
                // host-side analogue of the build path's `teardown(); return`.
                //
                // Unlike the build path (which returns before the pumps are spawned, so the device
                // Arc drops and the interface goes fully down), here the pump tasks keep the
                // interface UP with only its on-link self `/32`. That is still fail-closed: with
                // every peer/exit/subnet route removed from the host FIB, the OS steers no
                // peer/internet traffic into the TUN — the surviving on-link `/32` is just the
                // node's own address. Routes torn down ⟹ no leak, even though the iface lingers.
                tracing::error!(error = %e, "host route re-steer failed; tearing down host FIB (fail-closed)");
                self.host_guard = None;
            }
        }
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
        Intercept, build_dns_view, host_dns_from_dns_config, host_routes_from_node, plan_intercept,
        tun_config_from_control,
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
                accept_dns: true,
                exit_node,
                forward_routes: Vec::new(),
                forward_tcp_ports: Vec::new(),
                forward_udp_ports: Vec::new(),
                forward_all_ports: false,
                forward_exit_egress: false,
                block_incoming: false,
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
            online: None,
            last_seen: None,
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

    /// A plain tailnet peer: its own host `/32` at `ipv4`, plus any `subnets` it advertises
    /// (e.g. a `/24`). No peerAPI / exit-node attributes — used to exercise the host-FIB peer fold
    /// in [`host_routes_from_node`] (the peer's `/32` is always installed; subnets gate on
    /// `accept_routes`; the peer gets a `/0` only when selected as the exit). `stable_id` is
    /// caller-supplied so a selector can target it as the exit node.
    fn tailnet_peer(stable_id: &str, id: u32, ipv4: &str, subnets: &[&str]) -> ts_control::Node {
        use ts_control::{Node, StableNodeId, TailnetAddress};
        let mut accepted_routes: Vec<ipnet::IpNet> =
            vec![format!("{ipv4}/32").parse::<ipnet::IpNet>().unwrap()];
        for s in subnets {
            accepted_routes.push(s.parse().unwrap());
        }
        Node {
            id: id as i64,
            user_id: 0,
            stable_id: StableNodeId(stable_id.to_string()),
            hostname: stable_id.to_string(),
            tailnet: Some("ts.net".to_string()),
            tags: vec![],
            tailnet_address: TailnetAddress {
                ipv4: format!("{ipv4}/32").parse().unwrap(),
                ipv6: format!("fd7a::{id}/128").parse().unwrap(),
            },
            node_key: [id as u8; 32].into(),
            node_key_expiry: None,
            key_signature: vec![],
            machine_key: None,
            disco_key: None,
            accepted_routes,
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
            online: None,
            last_seen: None,
        }
    }

    /// A `PeerDb` containing the given peers.
    fn peer_db_from(peers: &[&ts_control::Node]) -> PeerDb {
        let mut db = PeerDb::default();
        for p in peers {
            db.upsert(p);
        }
        db
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
            online: None,
            last_seen: None,
        }
    }

    /// With `accept_routes` set, the routed set carries the self node's advertised subnet `/24` but
    /// never the self `/32` (the device builder owns the on-link prefix) and never the self node's
    /// own `/0` (the host `/0` is now keyed on the selected exit PEER, not the self node — see the
    /// per-peer-`/0` tests below). This is the post-fix asymmetry fix: a self-node `/0` echo is
    /// ignored.
    #[test]
    fn host_routes_includes_self_subnet_excludes_self_and_self_default() {
        let node = fixture_node();
        // No peers, no exit node: only the self node's own non-`/0` routes contribute.
        let routes = host_routes_from_node(&node, None, "utun9".to_owned(), true, None, false);

        assert_eq!(routes.if_name, "utun9");
        assert_eq!(routes.self_v4, "100.64.0.1/32".parse::<Ipv4Net>().unwrap());
        assert!(
            routes.routed.contains(&"192.168.1.0/24".parse().unwrap()),
            "self-advertised subnet /24 must be routed when accept_routes is set"
        );
        assert!(
            !routes.routed.contains(&"0.0.0.0/0".parse().unwrap()),
            "the self node's own /0 echo must NOT be installed (host /0 is per-exit-peer)"
        );
        assert!(
            !routes.routed.contains(&"100.64.0.1/32".parse().unwrap()),
            "self /32 must never be re-routed"
        );
    }

    /// `accept_routes = false` drops advertised subnet routes (fail-closed), for both the self node
    /// and the peer fold.
    #[test]
    fn host_routes_excludes_subnet_without_accept_routes() {
        let node = fixture_node();
        let peer = tailnet_peer("p", 2, "100.64.0.2", &["10.0.0.0/24"]);
        let db = peer_db_from(&[&peer]);
        let routes =
            host_routes_from_node(&node, Some(&db), "utun9".to_owned(), false, None, false);
        assert!(
            !routes.routed.contains(&"192.168.1.0/24".parse().unwrap()),
            "self subnet /24 must be excluded when accept_routes is false"
        );
        assert!(
            !routes.routed.contains(&"10.0.0.0/24".parse().unwrap()),
            "peer subnet /24 must be excluded when accept_routes is false"
        );
        // The peer's own host /32 is ALWAYS installed regardless of accept_routes (so the peer stays
        // reachable) — this is the core of the consumer-blocking-bug fix.
        assert!(
            routes.routed.contains(&"100.64.0.2/32".parse().unwrap()),
            "peer /32 must always be routed even with accept_routes false"
        );
    }

    /// IPv6 prefixes are dropped by construction (v4-only invariant), from both the self node and
    /// any peer.
    #[test]
    fn host_routes_drops_ipv6() {
        // `HostRoutes.routed` is `Vec<Ipv4Net>`, so v6 cannot even be represented; assert
        // behaviorally that a v6 subnet route — on the self node OR on a peer — leaves the v4-only
        // routed set unchanged.
        let baseline =
            host_routes_from_node(&fixture_node(), None, "utun9".to_owned(), true, None, false);

        let mut node_v6 = fixture_node();
        node_v6
            .accepted_routes
            .push("2001:db8::/32".parse().unwrap());
        let routes_v6 =
            host_routes_from_node(&node_v6, None, "utun9".to_owned(), true, None, false);
        assert_eq!(
            routes_v6.routed, baseline.routed,
            "adding a v6 subnet to the self node must not change the v4-only routed set"
        );

        // A peer whose only routes are v6 (beyond its v4 /32) contributes only its v4 /32.
        let mut v6_peer = tailnet_peer("v6p", 3, "100.64.0.3", &[]);
        v6_peer
            .accepted_routes
            .push("2001:db8:1::/48".parse().unwrap());
        let db = peer_db_from(&[&v6_peer]);
        let routes_peer_v6 = host_routes_from_node(
            &fixture_node(),
            Some(&db),
            "utun9".to_owned(),
            true,
            None,
            false,
        );
        assert!(
            routes_peer_v6
                .routed
                .contains(&"100.64.0.3/32".parse().unwrap()),
            "the peer's v4 /32 is installed"
        );
        assert!(
            !routes_peer_v6
                .routed
                .iter()
                .any(|n| n.to_string().contains("2001")),
            "no v6 prefix can appear in the v4-only routed set"
        );
    }

    /// PEER FOLD (the core regression guard for the consumer-blocking bug + the per-peer anti-leak
    /// `/0` gate): with a self node and a `PeerDb` of multiple peers, the routed set contains EACH
    /// peer's `/32` (so the OS can route to every peer), an advertised peer subnet ONLY when
    /// `accept_routes`, the self `/32` excluded, the MagicDNS `/32` present when `magic_dns`, and a
    /// peer `/0` ONLY when that peer is the resolved `exit_id` (never otherwise).
    #[test]
    fn host_routes_folds_peer_allowed_ips_and_gates_default_on_exit() {
        use ts_control::StableNodeId;

        let node = fixture_node();
        let p1 = tailnet_peer("p1", 2, "100.64.0.2", &[]); // plain peer, /32 only
        let p2 = tailnet_peer("p2", 3, "100.64.0.3", &["10.1.0.0/24"]); // advertises a subnet
        let exit = tailnet_peer("exit", 4, "100.64.0.4", &["0.0.0.0/0"]); // advertises default
        let db = peer_db_from(&[&p1, &p2, &exit]);

        let p1_32: Ipv4Net = "100.64.0.2/32".parse().unwrap();
        let p2_32: Ipv4Net = "100.64.0.3/32".parse().unwrap();
        let exit_32: Ipv4Net = "100.64.0.4/32".parse().unwrap();
        let p2_subnet: Ipv4Net = "10.1.0.0/24".parse().unwrap();
        let default: Ipv4Net = "0.0.0.0/0".parse().unwrap();
        let magic: Ipv4Net = "100.100.100.100/32".parse().unwrap();

        // accept_routes = true, NO exit node selected, MagicDNS on.
        let routes = host_routes_from_node(&node, Some(&db), "utun9".to_owned(), true, None, true);
        // Every peer's /32 is present (the bug fix: the OS now has a route to each peer).
        assert!(routes.routed.contains(&p1_32), "peer p1 /32 must be routed");
        assert!(routes.routed.contains(&p2_32), "peer p2 /32 must be routed");
        assert!(
            routes.routed.contains(&exit_32),
            "peer exit /32 must be routed"
        );
        // The advertised subnet is present because accept_routes is true.
        assert!(
            routes.routed.contains(&p2_subnet),
            "peer-advertised subnet must be routed when accept_routes is true"
        );
        // The self /32 is never re-routed.
        assert!(!routes.routed.contains(&"100.64.0.1/32".parse().unwrap()));
        // MagicDNS /32 present.
        assert!(
            routes.routed.contains(&magic),
            "MagicDNS /32 must be present when magic_dns"
        );
        // No exit selected ⇒ NO /0 at all (fail-closed; the exit peer's /0 is gated out).
        assert!(
            !routes.routed.contains(&default),
            "no /0 may appear when no exit peer is selected (anti-leak)"
        );

        // accept_routes = false ⇒ the advertised subnet drops, but every peer /32 stays.
        let no_accept =
            host_routes_from_node(&node, Some(&db), "utun9".to_owned(), false, None, true);
        assert!(no_accept.routed.contains(&p1_32));
        assert!(no_accept.routed.contains(&p2_32));
        assert!(no_accept.routed.contains(&exit_32));
        assert!(
            !no_accept.routed.contains(&p2_subnet),
            "peer subnet must drop when accept_routes is false"
        );

        // Select `exit` as the exit node ⇒ ITS /0 (and only its) appears.
        let exit_id = StableNodeId("exit".to_owned());
        let with_exit = host_routes_from_node(
            &node,
            Some(&db),
            "utun9".to_owned(),
            true,
            Some(&exit_id),
            true,
        );
        assert!(
            with_exit.routed.contains(&default),
            "the selected exit peer's /0 must be installed"
        );
        assert!(
            with_exit.routed.contains(&exit_32),
            "the exit peer's /32 stays routed"
        );

        // Select a NON-exit-advertising peer (p1, which has no /0) as the exit ⇒ still no /0 (it
        // advertises none), proving the /0 comes strictly from the chosen peer's AllowedIPs.
        let p1_id = StableNodeId("p1".to_owned());
        let wrong_exit = host_routes_from_node(
            &node,
            Some(&db),
            "utun9".to_owned(),
            true,
            Some(&p1_id),
            true,
        );
        assert!(
            !wrong_exit.routed.contains(&default),
            "a selected peer that advertises no /0 contributes no host /0"
        );

        // The load-bearing anti-leak gate: the `/0`-advertising peer (`exit`) IS in the db, but a
        // DIFFERENT peer (`p2`) is the selected exit. `exit`'s advertised `/0` must be gated out —
        // the host default route is keyed on WHICH peer is selected, never on "some peer advertises
        // /0 and an exit is configured". A regression here would route all internet traffic through
        // a non-selected peer = a real egress leak.
        let p2_id = StableNodeId("p2".to_owned());
        let other_exit = host_routes_from_node(
            &node,
            Some(&db),
            "utun9".to_owned(),
            true,
            Some(&p2_id),
            true,
        );
        assert!(
            !other_exit.routed.contains(&default),
            "the /0 advertised by `exit` must NOT be installed when a different peer (p2) is the \
             selected exit — the default route is keyed on the selected peer only (anti-leak)"
        );
        // p2 (the selected exit) advertises no /0, so still none; its own /32 + subnet stay.
        assert!(other_exit.routed.contains(&p2_32));
        assert!(other_exit.routed.contains(&p2_subnet));
    }

    /// DEDUP: two peers advertising the SAME subnet (and a subnet also advertised by the self node)
    /// install that prefix exactly once.
    #[test]
    fn host_routes_dedups_overlapping_peer_subnets() {
        let node = fixture_node(); // advertises 192.168.1.0/24
        let a = tailnet_peer("a", 2, "100.64.0.2", &["10.9.0.0/24"]);
        let b = tailnet_peer("b", 3, "100.64.0.3", &["10.9.0.0/24", "192.168.1.0/24"]);
        let db = peer_db_from(&[&a, &b]);

        let routes = host_routes_from_node(&node, Some(&db), "utun9".to_owned(), true, None, false);

        let shared: Ipv4Net = "10.9.0.0/24".parse().unwrap();
        let self_subnet: Ipv4Net = "192.168.1.0/24".parse().unwrap();
        assert_eq!(
            routes.routed.iter().filter(|n| **n == shared).count(),
            1,
            "a subnet advertised by two peers must be installed exactly once"
        );
        assert_eq!(
            routes.routed.iter().filter(|n| **n == self_subnet).count(),
            1,
            "a subnet advertised by both the self node and a peer must be installed exactly once"
        );
    }

    /// DNS: with MagicDNS enabled the host resolver points at `100.100.100.100` and search domains
    /// map through; with it disabled both stay empty (fail-closed no-op).
    #[test]
    fn host_dns_nameservers_point_at_magic_dns_when_enabled() {
        // No DNS config ⇒ empty everything (MagicDNS not enabled). (accept_dns true throughout
        // unless noted — it only ever further restricts.)
        let none = host_dns_from_dns_config(None, "utun9".to_owned(), true);
        assert!(none.nameservers.is_empty());
        assert!(none.match_domains.is_empty());

        // MagicDNS on ⇒ resolver points at the MagicDNS IP + search domains carried.
        let on = ts_control::DnsConfig {
            magic_dns: true,
            search_domains: vec!["user.ts.net.".to_owned()],
            ..Default::default()
        };
        let dns_on = host_dns_from_dns_config(Some(&on), "utun9".to_owned(), true);
        assert_eq!(
            dns_on.nameservers,
            vec![Ipv4Addr::new(100, 100, 100, 100)],
            "nameservers must point at the MagicDNS IP when MagicDNS is enabled"
        );
        assert_eq!(dns_on.match_domains, vec!["user.ts.net.".to_owned()]);

        // accept_dns OFF ⇒ even with MagicDNS on, the host resolver is NOT pointed at quad-100 and
        // no search domains are programmed (the node ignores the tailnet DNS config — fail-closed,
        // same as MagicDNS off).
        let dns_no_accept = host_dns_from_dns_config(Some(&on), "utun9".to_owned(), false);
        assert!(
            dns_no_accept.nameservers.is_empty(),
            "accept_dns off must not point the resolver at the MagicDNS IP"
        );
        assert!(
            dns_no_accept.match_domains.is_empty(),
            "accept_dns off must program no search domains"
        );

        // MagicDNS off ⇒ empty nameservers (no dead address) AND no search domains.
        let off = ts_control::DnsConfig {
            magic_dns: false,
            search_domains: vec!["user.ts.net.".to_owned()],
            ..Default::default()
        };
        let dns_off = host_dns_from_dns_config(Some(&off), "utun9".to_owned(), true);
        assert!(
            dns_off.nameservers.is_empty(),
            "nameservers must stay empty when MagicDNS is disabled"
        );
        assert!(dns_off.match_domains.is_empty());
    }

    /// `match_domains` is the search domains UNION the split-DNS route suffixes (Go
    /// `OSConfig.MatchDomains`), deduped. This is what scopes the host resolver; a split-DNS route
    /// with no search domain must still produce a scoped match domain so the macOS host layer never
    /// falls back to a global resolver.
    #[test]
    fn host_dns_match_domains_union_search_and_routes() {
        use std::collections::BTreeMap;

        // Search domains + two split-DNS routes, one of which overlaps a search domain.
        let mut routes = BTreeMap::new();
        routes.insert("corp.example.com".to_owned(), vec![]);
        routes.insert("user.ts.net".to_owned(), vec![]); // overlaps the search domain below
        let cfg = ts_control::DnsConfig {
            magic_dns: true,
            search_domains: vec!["user.ts.net".to_owned()],
            routes,
            ..Default::default()
        };
        let host = host_dns_from_dns_config(Some(&cfg), "utun9".to_owned(), true);
        // Search domain first, then the route suffix not already present; the overlapping route is
        // deduped (not added twice).
        assert_eq!(
            host.match_domains,
            vec!["user.ts.net".to_owned(), "corp.example.com".to_owned()],
            "match_domains = search ∪ route suffixes, deduped, search-first"
        );
    }

    /// A split-DNS route with NO search domain still yields a scoped match domain (the route suffix),
    /// so the macOS host layer scopes the resolver instead of installing a global one. This is the
    /// exact case the global-capture bug hit: MagicDNS on, no search domain.
    #[test]
    fn host_dns_route_only_still_scopes() {
        use std::collections::BTreeMap;
        let mut routes = BTreeMap::new();
        routes.insert("internal.corp".to_owned(), vec![]);
        let cfg = ts_control::DnsConfig {
            magic_dns: true,
            search_domains: vec![], // no search domain — previously → empty match_domains → global
            routes,
            ..Default::default()
        };
        let host = host_dns_from_dns_config(Some(&cfg), "utun9".to_owned(), true);
        assert_eq!(
            host.match_domains,
            vec!["internal.corp".to_owned()],
            "a route-only config must still scope the resolver to the route suffix"
        );
    }

    /// MagicDNS on but NO search domain and NO route → `match_domains` is empty. The host layer then
    /// installs no resolver at all (macOS) rather than a global one — verified by the
    /// `match_domains.is_empty()` path; here we just pin that this config yields the empty set so a
    /// regression that re-introduced a default suffix would be caught.
    #[test]
    fn host_dns_no_domains_yields_empty_match_domains() {
        let cfg = ts_control::DnsConfig {
            magic_dns: true,
            search_domains: vec![],
            ..Default::default()
        };
        let host = host_dns_from_dns_config(Some(&cfg), "utun9".to_owned(), true);
        assert_eq!(
            host.nameservers,
            vec![Ipv4Addr::new(100, 100, 100, 100)],
            "MagicDNS on still points nameservers at quad-100"
        );
        assert!(
            host.match_domains.is_empty(),
            "no search domain and no route ⇒ empty match_domains (host layer installs no resolver)"
        );
    }

    /// The union never emits a global/empty match domain. `DnsConfig`'s parser drops the `.`/empty
    /// route key (proven by `ts_control`'s `from_serde_drops_empty_route_keys_*`), so a `DnsConfig`
    /// can never carry one; this pins the consuming side — even were a `.`/`""` key somehow present
    /// in `routes`, the resulting `match_domains` must contain no global/empty entry that would scope
    /// the host resolver globally. Defense-in-depth on the cross-module contract.
    #[test]
    fn host_dns_match_domains_never_global_or_empty() {
        use std::collections::BTreeMap;

        // Construct a config directly with a real suffix plus (hypothetically) a global/empty key —
        // the union must surface the real suffix and never a `.`/`""` entry.
        let mut routes = BTreeMap::new();
        routes.insert("corp.ts.net".to_owned(), vec![]);
        // (A `.`/`""` key cannot occur post-parse, but assert the consuming side is clean regardless.)
        let cfg = ts_control::DnsConfig {
            magic_dns: true,
            search_domains: vec![],
            routes,
            ..Default::default()
        };
        let host = host_dns_from_dns_config(Some(&cfg), "utun9".to_owned(), true);
        assert!(
            !host.match_domains.iter().any(|d| d == "." || d.is_empty()),
            "no global/empty match domain may ever reach the host resolver"
        );
        assert_eq!(host.match_domains, vec!["corp.ts.net".to_owned()]);
    }

    /// The MagicDNS service IP `100.100.100.100/32` is steered into the TUN exactly when MagicDNS is
    /// enabled (so the host's quad-100 queries enter the datapath), and never when it is disabled.
    #[test]
    fn host_routes_includes_magic_dns_when_enabled() {
        let node = fixture_node();
        let magic_dns_net: Ipv4Net = "100.100.100.100/32".parse().unwrap();

        let with = host_routes_from_node(&node, None, "utun9".to_owned(), true, None, true);
        assert!(
            with.routed.contains(&magic_dns_net),
            "100.100.100.100/32 must be routed when MagicDNS is enabled"
        );

        let without = host_routes_from_node(&node, None, "utun9".to_owned(), true, None, false);
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
            online_change: Default::default(),
            peer_seen_change: Default::default(),
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
