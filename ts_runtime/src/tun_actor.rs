//! TUN transport-mode actor: rides the same dataplane overlay seam as [`NetstackActor`], but
//! moves application packets between the dataplane and a real kernel TUN interface instead of a
//! userspace smoltcp netstack.
//!
//! In TUN mode there is no userspace application netstack and no MagicDNS responder: packets flow
//! `OS-TUN <-> dataplane <-> overlay`. Netstack-only public APIs surface
//! [`ErrorKind::UnsupportedInTunMode`](crate::ErrorKind::UnsupportedInTunMode).

use core::num::NonZeroU16;
use std::sync::Arc;

use kameo::{
    actor::ActorRef,
    message::{Context, Message},
};
use tokio::task::JoinSet;
use ts_transport::OverlayTransport;
use ts_transport_tun::{AsyncTunTransport, Config as TunDeviceConfig};

use crate::{
    Error,
    dataplane::{OverlayFromDataplane, OverlayToDataplane},
    env::Env,
};

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
) -> ts_host_net::HostRoutes {
    let self_v4 = node.tailnet_address.ipv4;

    let routed = node
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

    ts_host_net::HostRoutes {
        if_name,
        self_v4,
        routed,
    }
}

/// Translate the control DNS config into the host resolver programming for the TUN (the
/// `ts_runtime` boundary, mirroring [`tun_config_from_control`]).
///
/// MVP / INERT-DNS SLICE: `nameservers` is **always empty** here. We deliberately do NOT point the
/// system resolver at the MagicDNS address `100.100.100.100`, because no TUN-mode MagicDNS
/// responder exists yet — pointing the resolver at that dead address would black-hole DNS and
/// violate the fail-closed posture. `apply_dns` with empty nameservers is a documented no-op in
/// both the macOS and Linux impls, so this wires the seam and the `match_domains` translation while
/// leaving actual resolver programming inert until a future responder bead lands.
///
/// `match_domains` carries the search domains only when MagicDNS is enabled in the control config.
pub(crate) fn host_dns_from_dns_config(
    dns: Option<&ts_control::DnsConfig>,
    if_name: String,
) -> ts_host_net::HostDns {
    let match_domains = match dns {
        Some(d) if d.magic_dns => d.search_domains.clone(),
        _ => vec![],
    };

    ts_host_net::HostDns {
        if_name,
        // Intentionally empty this slice — see fn doc (no TUN-mode MagicDNS responder yet).
        nameservers: vec![],
        match_domains,
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
    );
    type Error = Error;

    async fn on_start(
        (env, tun_config, overlay_to_dataplane, overlay_from_dataplane, gating): Self::Args,
        slf: ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        // We need the tailnet /32 prefix to build the device, which control only assigns at
        // runtime. Subscribe and build the device lazily on the first StateUpdate carrying a node.
        env.subscribe::<Arc<ts_control::StateUpdate>>(&slf).await?;

        Ok(Self {
            _joinset: JoinSet::new(),
            tun_config,
            overlay_to_dataplane: Some(overlay_to_dataplane),
            overlay_from_dataplane: Some(overlay_from_dataplane),
            gating,
            host_guard: None,
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
        let routes = host_routes_from_node(self_node, if_name.clone(), self.gating);
        if let Err(e) = host.apply_routes(&routes) {
            tracing::error!(error = %e, "host route programming failed; TUN idle (fail-closed)");
            host.teardown();
            return; // device drops here -> interface torn down; overlay halves already taken -> idle.
        }
        if let Err(e) = host.apply_dns(&host_dns_from_dns_config(msg.dns_config.as_ref(), if_name))
        {
            // DNS is best-effort in this slice (nameservers empty => no-op). Log, don't fail the
            // data path — routes are already up.
            tracing::warn!(error = %e, "host dns programming failed (continuing; routes are up)");
        }
        self.host_guard = Some(HostGuard(host));

        // UP: device -> dataplane.
        let dev_up = device.clone();
        self._joinset.spawn(async move {
            loop {
                for pkt in dev_up.recv().await {
                    match pkt {
                        Ok(p) => {
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

#[cfg(test)]
mod tests {
    use core::net::Ipv4Addr;

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
            peerapi_port: None,
            peerapi_dns_proxy: false,
            is_wireguard_only: false,
            exit_node_dns_resolvers: vec![],
        }
    }

    /// With `accept_routes` and an exit node configured, the routed set carries the subnet `/24`
    /// and the default `/0`, but never the self `/32` (the device builder owns the on-link prefix).
    #[test]
    fn host_routes_includes_subnet_and_default_excludes_self() {
        let node = fixture_node();
        let routes = host_routes_from_node(&node, "utun9".to_owned(), gating_all());

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
        let baseline = host_routes_from_node(&fixture_node(), "utun9".to_owned(), gating_all());

        let mut node_v6 = fixture_node();
        node_v6
            .accepted_routes
            .push("2001:db8::/32".parse().unwrap());
        let routes_v6 = host_routes_from_node(&node_v6, "utun9".to_owned(), gating_all());

        assert_eq!(
            routes_v6.routed, baseline.routed,
            "adding a v6 subnet must not change the v4-only routed set"
        );
    }

    /// DNS: nameservers are always empty this slice; search domains map through only when MagicDNS
    /// is enabled.
    #[test]
    fn host_dns_nameservers_empty_search_domains_gated() {
        // No DNS config ⇒ empty everything.
        let none = host_dns_from_dns_config(None, "utun9".to_owned());
        assert!(none.nameservers.is_empty());
        assert!(none.match_domains.is_empty());

        // MagicDNS on ⇒ search domains carried, nameservers still empty.
        let on = ts_control::DnsConfig {
            magic_dns: true,
            search_domains: vec!["user.ts.net.".to_owned()],
            ..Default::default()
        };
        let dns_on = host_dns_from_dns_config(Some(&on), "utun9".to_owned());
        assert!(
            dns_on.nameservers.is_empty(),
            "nameservers must stay empty this slice"
        );
        assert_eq!(dns_on.match_domains, vec!["user.ts.net.".to_owned()]);

        // MagicDNS off ⇒ no search domains even if present.
        let off = ts_control::DnsConfig {
            magic_dns: false,
            search_domains: vec!["user.ts.net.".to_owned()],
            ..Default::default()
        };
        let dns_off = host_dns_from_dns_config(Some(&off), "utun9".to_owned());
        assert!(dns_off.match_domains.is_empty());
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
