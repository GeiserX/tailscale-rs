use core::fmt::Debug;
use std::net::SocketAddr;

use url::Url;

lazy_static::lazy_static! {
    /// The default [`Url`] of the control plane server (aka "coordination server").
    pub static ref DEFAULT_CONTROL_SERVER: Url = Url::parse("https://controlplane.tailscale.com/").unwrap();
}

/// Upstream-proxy wire protocol for [`ExitProxyConfig`]. Mirrors `ts_forwarder::ProxyScheme`;
/// kept as a separate type here because `ts_control` must not depend on `ts_forwarder` (the
/// runtime converts between them at the boundary).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ExitProxyScheme {
    /// SOCKS5 (RFC 1928), with optional username/password auth (RFC 1929).
    Socks5,
    /// HTTP `CONNECT` tunnelling, with optional `Proxy-Authorization: Basic` auth.
    HttpConnect,
}

/// Transport-only description of an upstream proxy that exit-node egress is routed through, so a
/// cloud exit node egresses via the proxy's (e.g. residential) IP rather than its own origin IP.
///
/// This is **not** read inside `ts_control`; like the other dataplane fields on [`Config`] it is
/// carried for transport only and converted to a `ts_forwarder::ProxyConfig` by the runtime. It is
/// only consulted when [`Config::forward_exit_egress`] is `true` (the anti-leak opt-in); on its own
/// it changes nothing. See the proxy-egress docs in the repo's `AGENTS.md`/`CLAUDE.md`.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ExitProxyConfig {
    /// Address of the upstream proxy to connect to.
    pub addr: SocketAddr,
    /// Wire protocol to speak to the proxy.
    pub scheme: ExitProxyScheme,
    /// Optional `(username, password)` credentials for proxy auth.
    pub auth: Option<(String, String)>,
}

// Manual Debug that NEVER prints the proxy credentials, mirroring `ts_forwarder::ProxyConfig`. A
// stray `tracing!(?cfg)` or `{:?}` must not leak the residential-proxy username/password.
impl Debug for ExitProxyConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExitProxyConfig")
            .field("addr", &self.addr)
            .field("scheme", &self.scheme)
            .field("auth", &self.auth.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Default for [`Config::ephemeral`]: `true`, matching the historical behavior of this client.
fn default_ephemeral() -> bool {
    true
}

/// Configuration for the control server.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Config {
    /// The URL of the control server to connect to.
    pub server_url: Url,

    /// The hostname of the current node.
    pub hostname: Option<String>,

    /// A name for this type of client.
    ///
    /// This will be reported to the control server in the `HostInfo.App` field.
    pub client_name: Option<String>,

    /// Tags to request from the control server (`--advertise-tags` / `AdvertiseTags` in the Go
    /// client).
    ///
    /// Sent as `HostInfo.RequestTags` on registration and on every map request, so a
    /// tag-keyed control ACL (e.g. a a self-hosted control plane route auto-approver) can match this node. Each
    /// entry is a full tag string including the `tag:` prefix (e.g. `tag:exit`). Defaults to
    /// empty (claim no tags); an empty set omits the wire field entirely.
    #[serde(default)]
    pub tags: Vec<String>,

    /// Whether this node registers as *ephemeral* (`--ephemeral` / `Ephemeral` in the Go client).
    ///
    /// An ephemeral node is garbage-collected by the control server shortly after it
    /// disconnects. That is the right default for short-lived clients, but a persistent exit node
    /// or subnet router must set this to `false` or it will be GC'd out of the tailnet while
    /// briefly offline. Defaults to `true` to match the historical behavior of this client.
    #[serde(default = "default_ephemeral")]
    pub ephemeral: bool,

    /// Whether to accept subnet routes advertised by peers (`--accept-routes` / `RouteAll` in the
    /// Go client).
    ///
    /// When `false` (the default, matching the Go client on Linux/server platforms and our
    /// fail-closed posture), only each peer's own tailnet addresses are routed; larger advertised
    /// subnet routes are ignored. When `true`, traffic destined for an accepted subnet egresses
    /// via the advertising peer.
    ///
    /// This is a client-side preference and is not read inside `ts_control`: control always sends
    /// the full set of advertised routes, and the runtime trims them. It is carried here only to
    /// be threaded through to the runtime's route filter.
    #[serde(default)]
    pub accept_routes: bool,

    /// Which peer (if any) to use as an exit node (`--exit-node` / `ExitNodeID` in the Go client).
    ///
    /// The selector may name the peer by stable id, tailnet IP, or MagicDNS name (see
    /// [`ExitNodeSelector`](crate::ExitNodeSelector)); it is resolved against the live peer set on
    /// every route rebuild, so an IP/name selection follows the peer across netmap changes. When
    /// set and resolvable, the selected peer's advertised default route (`0.0.0.0/0` / `::/0`) is
    /// installed so internet-bound traffic egresses through it. When `None` (the default) or
    /// unresolvable, no peer receives a default route and internet-bound traffic is dropped
    /// (fail-closed).
    ///
    /// Like [`accept_routes`](Config::accept_routes), this is a client-side preference not read
    /// inside `ts_control`; it is carried here only to be threaded through to the runtime's route
    /// filter.
    #[serde(default)]
    pub exit_node: Option<crate::ExitNodeSelector>,

    /// Subnet routes to advertise to the control server (`--advertise-routes` / `RoutableIPs` in
    /// the Go client).
    ///
    /// Unlike [`accept_routes`](Config::accept_routes)/[`exit_node`](Config::exit_node), this field
    /// *is* read inside `ts_control`: it populates `HostInfo.RoutableIPs` on every map request so
    /// the control server can grant this node as a subnet router. Defaults to empty (advertise
    /// nothing — fail-closed). Only IPv4 prefixes are advertised; IPv6 prefixes are dropped to
    /// uphold the IPv6-off posture (advertising a route we won't forward would be a black hole).
    #[serde(default)]
    pub advertise_routes: Vec<ipnet::IpNet>,

    /// Whether to advertise this node as an exit node (`--advertise-exit-node` in the Go client).
    ///
    /// When `true`, the default route `0.0.0.0/0` is added to the advertised
    /// [`routable_ips`](Config::advertise_routes) so the control server can grant this node as an
    /// exit node, after which other peers may egress internet-bound traffic through our real IP.
    /// Defaults to `false` (fail-closed): being an exit node means *other* peers' traffic leaves
    /// via our real origin IP, so it must be explicit opt-in. IPv6 (`::/0`) is never advertised,
    /// per the IPv6-off posture.
    #[serde(default)]
    pub advertise_exit_node: bool,

    /// TCP ports the inbound forwarder accepts and splices to real OS sockets for every advertised
    /// route (`advertise_routes` / `advertise_exit_node`).
    ///
    /// smoltcp has no all-port accept mode (see the `ts_forwarder` crate docs), so the forwarder
    /// forwards a configured set of ports rather than the full 1–65535 range. Defaults to empty: a
    /// node that advertises routes but configures no forward ports accepts inbound flows into its
    /// dedicated forwarder netstack but forwards none of them (fail-closed — nothing is dialed).
    #[serde(default)]
    pub forward_tcp_ports: Vec<u16>,

    /// UDP ports the inbound forwarder accepts and splices to real OS sockets for every advertised
    /// route. See [`forward_tcp_ports`](Config::forward_tcp_ports); defaults to empty.
    #[serde(default)]
    pub forward_udp_ports: Vec<u16>,

    /// Forward **all** TCP/UDP ports (1–65535) on every advertised route, like a Go subnet router
    /// (`tailscale up --advertise-routes` forwards all ports), instead of the explicit
    /// [`forward_tcp_ports`](Config::forward_tcp_ports) /
    /// [`forward_udp_ports`](Config::forward_udp_ports) sets.
    ///
    /// smoltcp cannot wildcard-port-accept, so all-port mode is implemented with an on-demand
    /// per-port listener manager driven by a raw-socket port observer on the dedicated forwarder
    /// netstack (see the `ts_forwarder` crate docs). When `true`, the explicit port sets are
    /// ignored. Anti-leak is unchanged: every flow still routes through the same
    /// `RouteTable`→dialer chokepoint, so [`forward_exit_egress`](Config::forward_exit_egress) still
    /// governs exit-node egress. Defaults to `false`.
    #[serde(default)]
    pub forward_all_ports: bool,

    /// Whether exit-node (`0.0.0.0/0`) inbound flows are actually egressed via **this host's real
    /// origin IP**.
    ///
    /// This is the anti-leak opt-in, kept separate from
    /// [`advertise_exit_node`](Config::advertise_exit_node): advertising the default route only
    /// makes control *offer* this node as an exit; it does not by itself egress a peer's traffic.
    /// When `false` (the default, fail-closed), the forwarder uses a dialer that **structurally
    /// refuses** exit-node egress — a `0.0.0.0/0` flow is dropped at dial time, never leaked out our
    /// real IP. Set to `true` only on a node whose real IP *is* the intended egress (e.g. a
    /// residential exit), never on a node whose host IP must stay hidden (e.g. a cloud VPS). Subnet
    /// routes are dialed identically regardless of this flag.
    #[serde(default)]
    pub forward_exit_egress: bool,

    /// Optional upstream proxy that exit-node egress is routed through, so the node egresses via
    /// the proxy's IP rather than its own origin IP.
    ///
    /// Only consulted when [`forward_exit_egress`](Config::forward_exit_egress) is `true`. When
    /// set, the runtime wires the forwarder with a proxy dialer (SOCKS5 / HTTP `CONNECT`) that
    /// **fails closed** — any proxy connect or handshake failure drops the flow rather than falling
    /// back to a direct host-IP dial, so the real origin IP never leaks. When `None` (the default)
    /// and exit egress is enabled, egress uses this host's real IP (`HostExitDialer`).
    ///
    /// Like the other dataplane fields, this is a client-side preference not read inside
    /// `ts_control`; it is carried here only to be threaded through to the runtime's dialer
    /// selection. This is a product capability (residential-proxy egress) beyond strict tsnet
    /// parity — see the repo's `AGENTS.md`/`CLAUDE.md`.
    #[serde(default)]
    pub exit_proxy: Option<ExitProxyConfig>,

    /// Per-direction TCP send/receive buffer size (bytes) for the userspace netstack, or `None` to
    /// use the netstack default (256 KiB per direction, ~512 KiB per socket).
    ///
    /// smoltcp has no window auto-tuning, so this is the hard cap on a single flow's
    /// bandwidth-delay product; raising it helps large model-API responses on high-RTT links, at
    /// the cost of more memory per concurrent socket (each socket allocates this size for both rx
    /// and tx). Like the other dataplane fields, this is a client-side preference not read inside
    /// `ts_control`; it is carried here only to be threaded into the runtime's netstack
    /// configuration.
    #[serde(default)]
    pub tcp_buffer_size: Option<usize>,
}

impl Config {
    /// Get the full client name as a string.
    ///
    /// This takes the form `tailscale-rs ({client_name})`, where the parenthetical is only
    /// provided if self.client_name is set.
    pub fn format_client_name(&self) -> String {
        let mut full_name = "tailscale-rs".to_owned();
        if let Some(client_name) = &self.client_name {
            full_name.push_str(&format!(" ({client_name})"));
        }

        full_name
    }

    /// Compute the set of IP prefixes to advertise in `HostInfo.RoutableIPs`, combining
    /// [`advertise_routes`](Config::advertise_routes) with the exit-node default route when
    /// [`advertise_exit_node`](Config::advertise_exit_node) is set.
    ///
    /// IPv6 prefixes are filtered out (IPv6-off posture): we never forward IPv6, so advertising an
    /// IPv6 route would create a black hole. The exit-node default route is therefore `0.0.0.0/0`
    /// only, never `::/0`. The result is deduplicated and order-preserving; an empty result means
    /// "advertise nothing", and callers omit the wire field entirely.
    pub fn advertised_routes(&self) -> Vec<ipnet::IpNet> {
        let mut routes: Vec<ipnet::IpNet> = Vec::new();
        let mut push_unique = |net: ipnet::IpNet| {
            if !routes.contains(&net) {
                routes.push(net);
            }
        };

        for net in &self.advertise_routes {
            // IPv6-off: drop v6 prefixes so we never advertise a route we won't forward.
            if matches!(net, ipnet::IpNet::V4(_)) {
                push_unique(*net);
            } else {
                tracing::warn!(prefix = %net, "dropping IPv6 advertise_routes prefix (IPv6-off posture)");
            }
        }

        if self.advertise_exit_node {
            let default_v4 = ipnet::IpNet::V4(
                ipnet::Ipv4Net::new(core::net::Ipv4Addr::UNSPECIFIED, 0)
                    .expect("0.0.0.0/0 is a valid prefix"),
            );
            push_unique(default_v4);
        }

        routes
    }
}

impl Debug for Config {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Config")
            .field("hostname", &self.hostname)
            .field("server_url", &self.server_url.as_str())
            .field("client_name", &self.client_name)
            .finish()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_url: DEFAULT_CONTROL_SERVER.clone(),
            hostname: gethostname::gethostname().into_string().ok(),
            client_name: None,
            tags: Default::default(),
            ephemeral: default_ephemeral(),
            accept_routes: false,
            exit_node: None,
            advertise_routes: Vec::new(),
            advertise_exit_node: false,
            forward_tcp_ports: Vec::new(),
            forward_udp_ports: Vec::new(),
            forward_all_ports: false,
            forward_exit_egress: false,
            exit_proxy: None,
            tcp_buffer_size: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> ipnet::IpNet {
        ipnet::IpNet::V4(s.parse().unwrap())
    }

    fn v6(s: &str) -> ipnet::IpNet {
        ipnet::IpNet::V6(s.parse().unwrap())
    }

    #[test]
    fn default_advertises_nothing() {
        let cfg = Config::default();
        assert!(cfg.advertised_routes().is_empty());
    }

    #[test]
    fn advertises_v4_subnet_routes() {
        let cfg = Config {
            advertise_routes: vec![v4("10.0.0.0/24"), v4("192.168.1.0/24")],
            ..Default::default()
        };
        assert_eq!(
            cfg.advertised_routes(),
            vec![v4("10.0.0.0/24"), v4("192.168.1.0/24")]
        );
    }

    #[test]
    fn exit_node_adds_default_v4_route() {
        let cfg = Config {
            advertise_exit_node: true,
            ..Default::default()
        };
        assert_eq!(cfg.advertised_routes(), vec![v4("0.0.0.0/0")]);
    }

    #[test]
    fn v6_prefixes_are_dropped() {
        let cfg = Config {
            advertise_routes: vec![v4("10.0.0.0/24"), v6("fd00::/64")],
            ..Default::default()
        };
        // IPv6-off: only the v4 prefix survives.
        assert_eq!(cfg.advertised_routes(), vec![v4("10.0.0.0/24")]);
    }

    #[test]
    fn exit_node_never_advertises_v6_default() {
        let cfg = Config {
            advertise_routes: vec![v6("::/0")],
            advertise_exit_node: true,
            ..Default::default()
        };
        // ::/0 is dropped; only the v4 default route is advertised.
        assert_eq!(cfg.advertised_routes(), vec![v4("0.0.0.0/0")]);
    }

    #[test]
    fn default_is_ephemeral() {
        // Preserves the historical hardcoded behavior; persistent nodes must opt out explicitly.
        assert!(Config::default().ephemeral);
    }

    #[test]
    fn ephemeral_deserializes_default_true_when_absent() {
        // A config that predates the field still registers ephemeral.
        let cfg: Config = serde_json::from_str(r#"{"server_url":"https://example.com/"}"#).unwrap();
        assert!(cfg.ephemeral);
    }

    #[test]
    fn ephemeral_can_be_disabled_for_persistent_nodes() {
        let cfg: Config =
            serde_json::from_str(r#"{"server_url":"https://example.com/","ephemeral":false}"#)
                .unwrap();
        assert!(!cfg.ephemeral);
    }

    #[test]
    fn tags_default_empty_and_deserialize() {
        let cfg: Config =
            serde_json::from_str(r#"{"server_url":"https://example.com/","tags":["tag:exit"]}"#)
                .unwrap();
        assert_eq!(cfg.tags, vec!["tag:exit".to_owned()]);
        assert!(Config::default().tags.is_empty());
    }

    #[test]
    fn deduplicates_routes() {
        let cfg = Config {
            advertise_routes: vec![v4("0.0.0.0/0"), v4("10.0.0.0/24")],
            advertise_exit_node: true,
            ..Default::default()
        };
        // Explicit 0.0.0.0/0 plus the exit-node default route collapse to one entry.
        assert_eq!(
            cfg.advertised_routes(),
            vec![v4("0.0.0.0/0"), v4("10.0.0.0/24")]
        );
    }
}
