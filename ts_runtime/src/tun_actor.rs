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
use tokio::{sync::watch, task::JoinSet};
use ts_transport::OverlayTransport;
use ts_transport_tun::{AsyncTunTransport, Config as TunDeviceConfig};

use crate::{
    Error,
    dataplane::{OverlayFromDataplane, OverlayToDataplane},
    env::Env,
    magic_dns::{Decision, DnsView, decide},
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
    /// reads it fresh for every intercepted query; `exit_doh` stays `None` in TUN mode (recursive /
    /// exit-node DoH forwarding is a deferred follow-up — see [`intercept_magic_dns`]).
    dns_view: watch::Sender<Arc<DnsView>>,
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
/// in the datapath and answers in-process via the shared responder ([`intercept_magic_dns`]). There
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
/// (`magic_dns::MagicDnsActor`'s `StateUpdate`/`PeerState` handlers). `exit_doh` is always `None`
/// in TUN mode: recursive / exit-node DoH forwarding over the overlay is a deferred follow-up (the
/// netstack path threads an overlay `Channel`; the TUN path has none yet). `enable_ipv6` comes from
/// the runtime `Env`.
fn build_dns_view(
    update: &ts_control::StateUpdate,
    peers: Option<Arc<crate::peer_tracker::PeerDb>>,
    enable_ipv6: bool,
) -> DnsView {
    DnsView {
        cfg: update.dns_config.clone().unwrap_or_default(),
        peers,
        self_node: update.node.clone(),
        // Deferred: recursive forwarding in TUN mode (needs an overlay Channel). See fn doc.
        exit_doh: None,
        enable_ipv6,
    }
}

/// In-datapath MagicDNS intercept for the UP pump (Go's `handleLocalPackets`). Returns `true` if
/// `pkt` was a MagicDNS query that we handled in-process (the caller must NOT forward it to the
/// overlay); `false` if it should be forwarded unchanged.
///
/// A matched query is answered via the SHARED [`decide`] responder against the latest [`DnsView`];
/// the reply IPv4+UDP packet is written straight back into the TUN via `device` — no host loopback
/// socket and no overlay egress for the DNS itself (anti-leak).
///
/// [`Decision::Forward`] handling — recursive / split-DNS forwarding — is DEFERRED in TUN mode: the
/// netstack path forwards over an overlay `Channel` the TunActor does not have. Until that Channel
/// is threaded in (follow-up), a Forward is answered with the pre-built `nxdomain` fallback bytes
/// `decide` already carries. This is FAIL-SAFE: a tailnet name is answered authoritatively, while a
/// public/off-tailnet name gets NXDOMAIN rather than hanging or leaking to a host resolver.
async fn intercept_magic_dns(
    device: &Arc<AsyncTunTransport>,
    dns_view_rx: &watch::Receiver<Arc<DnsView>>,
    pkt: &[u8],
) -> bool {
    let Some(query) = classify_magic_dns(pkt) else {
        return false;
    };

    // Read the freshest view per query (mirrors the netstack serve loop).
    let view = dns_view_rx.borrow().clone();

    let response = match decide(&view, query.dns_payload) {
        // Malformed query: drop silently. We still consumed it (it was quad-100/UDP/53) so it must
        // NOT be forwarded to the overlay.
        None => return true,
        Some(Decision::Reply(resp)) => resp,
        // DEFERRED: no overlay Channel for recursive forwarding in TUN mode. Fail-safe to the
        // pre-built NXDOMAIN the Forward arm carries (see fn doc).
        Some(Decision::Forward { nxdomain, .. }) => nxdomain,
    };

    let reply_pkt = build_dns_response(query.src, &response);
    if let Err(e) = device
        .send(core::iter::once(ts_packet::PacketMut::from(reply_pkt)))
        .await
    {
        tracing::warn!(error = %e, "magic dns tun reply send failed");
    }
    true
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
    );
    type Error = Error;

    async fn on_start(
        (env, tun_config, overlay_to_dataplane, overlay_from_dataplane, gating): Self::Args,
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
            tun_config,
            overlay_to_dataplane: Some(overlay_to_dataplane),
            overlay_from_dataplane: Some(overlay_from_dataplane),
            gating,
            host_guard: None,
            dns_view,
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
        // update, including ones with no node (so a DNS-config-only update still lands).
        self.dns_view.send_modify(|view| {
            *view = Arc::new(build_dns_view(&msg, view.peers.clone(), view.enable_ipv6));
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
        self._joinset.spawn(async move {
            loop {
                // Drain the (non-`Send`) recv iterator into an owned batch first, so no part of it
                // is held across the intercept's `await` (the iterator is not `Send`; `PacketMut`
                // is). Then process the batch, peeling off MagicDNS queries.
                let batch: Vec<_> = dev_up.recv().await.into_iter().collect();
                for pkt in batch {
                    match pkt {
                        Ok(p) => {
                            // Peel off quad-100/UDP/53 DNS queries and answer them in-process; the
                            // reply is written back into the TUN via `dev_up` (no overlay egress,
                            // no host socket). Everything else forwards to the overlay unchanged.
                            if intercept_magic_dns(&dev_up, &dns_view_rx, p.as_ref()).await {
                                continue;
                            }
                            if up.send(vec![p]).is_err() {
                                return;
                            }
                        }
                        Err(e) => tracing::warn!(error = %e, "tun recv error"),
                    }
                }
            }
        });

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
        // names authoritatively. Mirrors `MagicDnsActor`'s `PeerState` handler.
        self.dns_view.send_modify(|view| {
            let mut next = (**view).clone();
            next.peers = Some(state.peers.clone());
            *view = Arc::new(next);
        });
    }
}

#[cfg(test)]
mod tests {
    use core::net::{Ipv4Addr, SocketAddrV4};

    use ipnet::Ipv4Net;
    use ts_control::TunConfig;

    use super::{
        HostRouteGating, host_dns_from_dns_config, host_routes_from_node, tun_config_from_control,
    };

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

    /// `build_dns_view` mirrors `MagicDnsActor`'s construction: cfg + self_node from the update,
    /// `exit_doh` always `None` in TUN mode (recursive forward deferred), `enable_ipv6` threaded.
    #[test]
    fn build_dns_view_maps_update() {
        use super::build_dns_view;

        let update = ts_control::StateUpdate {
            session_handle: None,
            seq: 0,
            derp: None,
            node: Some(fixture_node()),
            peer_update: None,
            ping: None,
            packetfilter: None,
            pop_browser_url: None,
            dial_plan: None,
            dns_config: Some(ts_control::DnsConfig {
                magic_dns: true,
                search_domains: vec!["user.ts.net".to_owned()],
                ..Default::default()
            }),
            ssh_policy: None,
            tka: None,
        };

        let view = build_dns_view(&update, None, true);
        assert!(view.cfg.magic_dns, "dns config carried");
        assert!(view.self_node.is_some(), "self node carried");
        assert!(view.peers.is_none(), "no peer db passed");
        assert!(
            view.exit_doh.is_none(),
            "exit_doh stays None in TUN mode (recursive forward deferred)"
        );
        assert!(view.enable_ipv6, "ipv6 gate threaded from Env");
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
