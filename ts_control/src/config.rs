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

/// How the node's **application** overlay data path is realized.
///
/// Defaults to [`Netstack`](TransportMode::Netstack), the userspace smoltcp netstack that needs no
/// privileges and is the right choice for the fork's primary deployment (a privacy proxy / cloud
/// exit node running unprivileged in a container). [`Tun`](TransportMode::Tun) instead hands the
/// node's overlay packets to a real kernel TUN interface, for embedders that want the host OS
/// networking stack (routes, sockets, DNS) to see the tailnet directly — closer to `tailscaled`'s
/// model than to Go `tsnet`'s in-process netstack.
///
/// Like the other dataplane fields this is **not read inside `ts_control`**: it is carried for
/// transport only and converted to a `ts_transport_tun` config by the runtime at the `ts_runtime`
/// boundary (`ts_control` must not depend on `ts_transport_tun`). The mode governs only the
/// application data path; it never changes the exit-node / forwarder egress path, which stays its
/// own IPv4-only userspace netstack regardless.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    /// Userspace smoltcp netstack (default). No privileges required.
    #[default]
    Netstack,
    /// Real kernel TUN interface. Requires privileges (root / `CAP_NET_ADMIN` on Linux) and a
    /// platform that supports TUN (Linux `/dev/net/tun`, macOS `utun`).
    Tun(TunConfig),
}

/// Transport-only parameters for [`TransportMode::Tun`].
///
/// The node's tailnet *prefix* is deliberately absent: it is assigned by control and only known at
/// runtime, so the runtime supplies it when it builds the real `ts_transport_tun::Config`. Only the
/// user-choosable knobs live here.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TunConfig {
    /// Desired interface name (e.g. `tailscale0`). `None` lets the OS pick (e.g. `utunN` on macOS).
    #[serde(default)]
    pub name: Option<String>,

    /// Interface MTU. `None` uses the transport's default. Tailscale's overlay MTU is 1280.
    #[serde(default)]
    pub mtu: Option<u16>,
}

/// Default for [`Config::ephemeral`]: `true`, matching the historical behavior of this client.
fn default_ephemeral() -> bool {
    true
}

/// Default for [`Config::accept_dns`]: `true`, matching Go's `NewPrefs()` (`CorpDNS: true`).
fn default_true() -> bool {
    true
}

/// Default WireGuard persistent-keepalive interval: 25s.
///
/// Matches Tailscale, which sets `PersistentKeepalive = 25` on a peer when control marks it
/// `KeepAlive=true`. 25s sits just under the ~30s lower bound for UDP NAT/firewall mapping
/// timeouts, so the mapping (and any DERP relay path) is refreshed before it can expire.
pub const DEFAULT_PERSISTENT_KEEPALIVE: std::time::Duration = std::time::Duration::from_secs(25);

/// Default for [`Config::persistent_keepalive_interval`]: `Some(25s)`
/// ([`DEFAULT_PERSISTENT_KEEPALIVE`]). On by default so a relayed, idle session keeps its path warm
/// and doesn't wedge the next dial.
fn default_persistent_keepalive() -> Option<std::time::Duration> {
    Some(DEFAULT_PERSISTENT_KEEPALIVE)
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
    /// tag-keyed control ACL (e.g. a self-hosted control plane's route auto-approver) can match this node. Each
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

    /// Whether to accept the tailnet's DNS configuration (MagicDNS + the pushed resolvers/search
    /// domains) — `--accept-dns` / the `CorpDNS` pref in the Go client. **Defaults to `true`**, matching
    /// Go's `NewPrefs()` (`CorpDNS: true`).
    ///
    /// When `true`, the MagicDNS responder serves the control-pushed [`DnsConfig`](crate::DnsConfig)
    /// (overlay-name answers + split-DNS routes + recursive forwarding). When `false`, the node
    /// **ignores the pushed DNS config** and the responder serves nothing (every query is `REFUSED`),
    /// mirroring Go applying an essentially-empty `dns.Config` when `CorpDNS` is off — so a node can
    /// join the tailnet for connectivity without taking over its DNS.
    ///
    /// Like [`accept_routes`](Config::accept_routes), this is a client-side preference not read inside
    /// `ts_control` (control always pushes the full `DNSConfig`; the runtime decides whether to honor
    /// it); it is carried here only to be threaded through to the runtime's MagicDNS responder, and is
    /// runtime-settable via `Device::set_accept_dns` (the analog of `tailscale set --accept-dns`).
    #[serde(default = "default_true")]
    pub accept_dns: bool,

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
    ///
    /// **Full-tunnel exit vs. just reaching a peer's port — leave this `None` unless you mean
    /// full-tunnel.** Set `exit_node` *only* to route **all** internet-bound traffic through a peer
    /// that advertises a default route (`advertise_exit_node`). To merely **reach a specific peer's
    /// service over the tailnet** — e.g. `Device::tcp_connect` to its `100.x.y.z:1080` — you do
    /// **not** set `exit_node` at all; direct peer dials need no exit node. Setting `exit_node` to a
    /// peer that is only a selective CONNECT proxy (advertises no `0.0.0.0/0`) leaves egress
    /// fail-closed and logs a warning that internet-bound traffic is dropped — which looks like a
    /// failure but is just "that peer isn't a full-tunnel exit." If you saw that warning while only
    /// trying to dial a peer's port, the fix is to unset `exit_node`.
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

    /// Shields-up (Go `ipn` prefs `ShieldsUp`): when `true`, refuse all **inbound** connections from
    /// peers that terminate on this node — the packet filter drops inbound packets aimed at this
    /// node's own addresses. Replies to connections this node itself initiated, and forwarded
    /// subnet/exit transit, are unaffected (the deny is scoped to self-destined packets; see
    /// `ts_packetfilter::ShieldsUpFilter`). Transport-only client preference — `ts_control` never
    /// reads it; the runtime's packet-filter updater consumes it. Defaults to `false`.
    #[serde(default)]
    pub block_incoming: bool,

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

    /// The IPv4 peerAPI port this node binds to serve exit-node DoH (DNS-over-HTTPS) proxying for
    /// peers that select it as their exit node (`peerapi4` + `peerapi-dns-proxy` services).
    ///
    /// When `Some(port)`, the runtime binds a peerAPI DoH server on this host's overlay IPv4
    /// address at `port`, and registration / map requests advertise both the `peerapi4` service
    /// (at `port`) and the `peerapi-dns-proxy` service (Go quirk: its advertised port is always
    /// `1`) so peers know they can delegate DNS to us. When `None` (the default, fail-closed), no
    /// peerAPI is run and no services are advertised — this node never offers DNS proxying.
    ///
    /// The DoH server always answers authoritative/overlay records (MagicDNS peer names,
    /// `ExtraRecords`, PTR); *recursive* resolution to real upstream resolvers is gated separately
    /// behind [`forward_exit_egress`](Config::forward_exit_egress), so a cloud exit node can serve
    /// overlay DNS without ever exposing its real origin IP via a recursive lookup.
    #[serde(default)]
    pub peerapi_port: Option<u16>,

    /// Filesystem directory that received Taildrop files land in, or `None` to disable Taildrop
    /// (the default, fail-closed).
    ///
    /// When `Some(dir)` **and** [`peerapi_port`](Config::peerapi_port) is also set, the runtime
    /// serves the Taildrop peerAPI route `PUT /v0/put/<name>` on the shared peerAPI listener, and
    /// incoming files are written under `dir` (created if absent). When `None`, no Taildrop server
    /// is run — a peer's `PUT` is refused. This is a pure on-disk destination: like the other
    /// dataplane fields it is not read inside `ts_control`; it is carried here only to be threaded
    /// into the runtime, which constructs the file store from it.
    ///
    /// Independently of the network server, the embedder consumes received files via the
    /// `Device::taildrop_*` methods (Go exposes these over LocalAPI; this fork exposes them on the
    /// device). With no `peerapi_port`, the store still exists for those read APIs but no peer can
    /// deliver to it.
    #[serde(default)]
    pub taildrop_dir: Option<std::path::PathBuf>,

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

    /// Whether IPv6 is enabled on the tailnet overlay. Defaults to `false` (IPv4-only).
    ///
    /// Like the other dataplane fields, this is a client-side preference not read inside
    /// `ts_control`; it is carried here only to be threaded into the runtime's underlay socket,
    /// disco candidate filter, netstack address assignment, and MagicDNS AAAA handling. It governs
    /// only the overlay and never the exit-node / forwarder egress path, which stays IPv4-only
    /// regardless to uphold the real-origin-IP isolation invariant.
    #[serde(default)]
    pub enable_ipv6: bool,

    /// WireGuard persistent-keepalive interval applied to every peer, or `None` to disable persistent
    /// keepalives (`PersistentKeepalive`; Tailscale uses 25s).
    ///
    /// When `Some(interval)`, each peer emits an empty authenticated keepalive every `interval` of
    /// outbound silence, holding the (typically DERP-relayed) path/NAT mapping warm so an idle
    /// session doesn't age past expiry and wedge the next dial — the failure this fork's primary
    /// userspace-netstack deployment hits, where the relay is the only path to a peer. Unlike the
    /// reactive WireGuard §6.5 keepalive (armed only by inbound traffic), this re-arms unconditionally
    /// and fires on a fully idle tunnel; the empty packet does not advance the session's
    /// rotation/expiry timers, so a genuinely dead peer is still detected. Defaults to `Some(25s)`
    /// ([`DEFAULT_PERSISTENT_KEEPALIVE`]). Like the other dataplane fields it is not read inside
    /// `ts_control`; it is carried here only to be threaded into the runtime's dataplane actor.
    #[serde(default = "default_persistent_keepalive")]
    pub persistent_keepalive_interval: Option<std::time::Duration>,

    /// How the application overlay data path is realized: userspace netstack (default) or a real
    /// kernel TUN interface. See [`TransportMode`].
    ///
    /// Like the other dataplane fields, this is a client-side preference not read inside
    /// `ts_control`; it is carried here only to be threaded into the runtime, which builds either a
    /// netstack actor or a TUN transport from it. `ts_control` must not depend on `ts_transport_tun`.
    #[serde(default)]
    pub transport_mode: TransportMode,

    /// Whether to ask control to wire this node up server-side for Tailscale Funnel
    /// (`HostInfo.WireIngress`, the capver-113 client→control Funnel signal), even when no Funnel
    /// endpoint is currently active.
    ///
    /// Unlike the dataplane fields above, this one *is* read inside `ts_control`: it sets
    /// `HostInfo.WireIngress` on registration and the streaming map request, asking control to
    /// provision the DNS / ingress records a Funnel node needs so a later `serve`/funnel session
    /// works immediately. It mirrors Go `tsnet`'s "would like to be wired up for Funnel" signal.
    ///
    /// This fork cannot yet *terminate* public Funnel ingress — [`crate::listen_funnel`] is
    /// fail-closed (no client-side ACME engine, and a self-hosted control plane provides no public
    /// ingress relay). So `HostInfo.IngressEnabled` (Funnel endpoints actually live) is never set;
    /// only `WireIngress` is, and only when this flag is `true`. Defaults to `false` (fail-closed):
    /// a node requests Funnel wiring only when explicitly opted in.
    #[serde(default)]
    pub wire_ingress: bool,

    /// Live signal that this node currently has an active Funnel ingress listener
    /// (`Device::listen_funnel` was called and its listener is up), driving `HostInfo.IngressEnabled`
    /// on the streaming map request.
    ///
    /// Unlike [`wire_ingress`](Self::wire_ingress) (a static "please provision Funnel records" hint),
    /// this is a *dynamic* flag: the runtime flips it `true` when a funnel listener starts serving and
    /// back to `false` when it stops, so the next map request advertises `IngressEnabled` accordingly
    /// (Go sets `HostInfo.IngressEnabled` only while Funnel endpoints are actually live, and
    /// `IngressEnabled` implies `WireIngress`). Shared (`Arc`) with the runtime so the device can flip
    /// it without rebuilding the config. Defaults to a fresh `false` (fail-closed: no live endpoint).
    /// Not serialized — it is process-local runtime state, not persisted configuration.
    #[serde(skip, default)]
    pub ingress_active: std::sync::Arc<std::sync::atomic::AtomicBool>,

    /// VIP services this node advertises that it **hosts** (`svc:<dns-label>` names), the
    /// advertise side of Tailscale VIP services (Go `tsnet`'s `Hostinfo.ServicesHash` +
    /// c2n `GET /vip-services`).
    ///
    /// Each entry is a full `svc:`-prefixed service name. This field *is* read inside `ts_control`:
    /// the valid names ([`validate_service_name`](crate::validate_service_name) is applied
    /// fail-closed; malformed names are dropped and logged) are hashed into `HostInfo.ServicesHash`
    /// on every map request, and answered when control fetches the list via the c2n
    /// `/vip-services` endpoint. Defaults to empty: with no entries the hash is `""` and behavior is
    /// byte-for-byte the historical non-advertising path. Hosting a service additionally requires
    /// control to assign it a VIP and the node to be tagged (the *consume* side, unchanged here).
    #[serde(default)]
    pub advertise_services: Vec<String>,

    /// Whether to automatically re-authenticate (rotate the node key + re-register with the stored
    /// auth key, Go `doLogin`) when control reports this node's node key has expired, instead of
    /// going terminally offline.
    ///
    /// Defaults to `true`: an auth-key-registered node whose key expires recovers itself without
    /// human intervention — the common reusable-auth-key case (a persistent exit node / subnet
    /// router) self-heals. Set to `false` for the most conservative posture (the historical behavior:
    /// an expired key surfaces the terminal "expired" state and the node stays offline until
    /// re-paired). Auto-reauth is additionally gated at runtime on a usable auth key being retained
    /// and Tailnet Lock NOT being enforced (a rotation on a locked tailnet would install an unsigned
    /// key); see the runtime's `expiry_action`. A one-shot auth key (already consumed by the first
    /// registration) cannot re-register and degrades to the terminal state regardless of this flag.
    ///
    /// Like the client-preference fields, this is **not read inside `ts_control`**: it is carried for
    /// transport only and consulted by the runtime's self-node expiry handler.
    #[serde(default = "default_true")]
    pub reauth_on_expiry: bool,

    /// Allow fetching the control server's machine public key (`GET /key`) over plain **http** when
    /// the [`server_url`](Config::server_url) is itself `http://`.
    ///
    /// By default (`false`) the `/key` fetch is always upgraded to `https`, even when the control
    /// URL is `http://` — matching Tailscale's posture that the unauthenticated key bootstrap must
    /// be TLS-protected. That upgrade makes registration **fail** against a control plane that only
    /// serves plain http (e.g. a self-hosted Headscale exposed over a `http://host:port` LAN
    /// endpoint / NodePort with no TLS), even though the rest of the control connection already
    /// honors the `http` scheme. Set this to `true` for such a deployment to fetch `/key` over the
    /// same `http` scheme as the control URL.
    ///
    /// Security: only enable this when you control both ends and the control plane is reachable
    /// over a trusted network path — an on-path attacker could otherwise substitute the control
    /// key. It has no effect when `server_url` is `https://` (the fetch stays https regardless).
    /// Fail-closed default is `false`.
    #[serde(default)]
    pub allow_http_key_fetch: bool,
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

    /// The services to advertise in `HostInfo.Services`, derived from
    /// [`peerapi_port`](Config::peerapi_port).
    ///
    /// When a peerAPI port is configured, we advertise the `peerapi4` service at that port plus the
    /// `peerapi-dns-proxy` service (whose advertised port is always `1`, matching the Go client's
    /// quirk) so peers learn they can delegate exit-node DNS to us. When `None`, the result is empty
    /// and callers omit the `HostInfo.Services` wire field entirely (advertise no services). IPv6
    /// peerAPI (`peerapi6`) is never advertised, per the IPv6-off posture.
    pub fn advertised_services(&self) -> Vec<ts_control_serde::Service<'static>> {
        use ts_control_serde::{Service, ServiceProto};

        let Some(port) = self.peerapi_port else {
            return Vec::new();
        };

        vec![
            Service {
                proto: ServiceProto::PeerApi4,
                port,
                description: "tailscale-rs".into(),
            },
            Service {
                // Go quirk: the peerapi-dns-proxy service always advertises port 1.
                proto: ServiceProto::PeerApiDnsProxy,
                port: 1,
                description: "tailscale-rs".into(),
            },
        ]
    }

    /// The validated set of VIP services this node advertises that it hosts, derived from
    /// [`advertise_services`](Config::advertise_services).
    ///
    /// Each configured name is validated with
    /// [`validate_service_name`](crate::validate_service_name) (fail-closed: a name that is not a
    /// well-formed `svc:<dns-label>` is dropped with a warning, never advertised). Each surviving
    /// service is advertised on **all ports** (a single `0/0..=65535`
    /// [`ProtoPortRange`](ts_control_serde::ProtoPortRange), matching
    /// Go's default `ServicePortRange()` when no explicit ports are configured) and marked active.
    /// The result is the canonical input to both [`services_hash`] and the c2n `/vip-services`
    /// response. An empty config yields an empty `Vec` (advertise nothing — the hash is `""`).
    pub fn advertised_vip_services(&self) -> Vec<ts_control_serde::VipServiceOwned> {
        use ts_control_serde::{ProtoPortRange, VipServiceOwned};

        self.advertise_services
            .iter()
            .filter_map(|name| {
                if crate::validate_service_name(name).is_none() {
                    tracing::warn!(
                        service = %name,
                        "dropping invalid advertise_services name (expected svc:<dns-label>)"
                    );
                    return None;
                }
                Some(VipServiceOwned {
                    name: name.clone(),
                    // All ports: proto 0 (all protocols), full 0..=65535 span — Go's default
                    // ServicePortRange() for a service with no explicit port restriction.
                    ports: vec![ProtoPortRange {
                        proto: 0,
                        first: 0,
                        last: 65535,
                    }],
                    active: true,
                })
            })
            .collect()
    }
}

/// Compute the `HostInfo.ServicesHash` for a node's advertised VIP services, mirroring Go's
/// `vipServiceHash`.
///
/// The services are sorted by name, serialized to canonical (whitespace-free) JSON as a
/// [`ts_control_serde::VipServiceOwned`] list, SHA-256'd, and hex-encoded. An empty list hashes to
/// the empty string `""` (the "no services advertised" sentinel, which omits/clears the wire
/// field). The hash is byte-stable and order-independent: the same set in any input order yields the
/// same value, so control reliably refetches only on a genuine change.
///
/// Uses `ring`'s SHA-256 (the same crypto backend the rest of the stack links — no aws-lc-rs /
/// openssl is introduced).
pub fn services_hash(services: &[ts_control_serde::VipServiceOwned]) -> String {
    if services.is_empty() {
        return String::new();
    }

    let mut sorted = services.to_vec();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));

    // Canonical, whitespace-free JSON so the digest is byte-stable across builds.
    let json = serde_json::to_vec(&sorted).expect("VipServiceOwned list always serializes");
    let digest = ring::digest::digest(&ring::digest::SHA256, &json);

    let mut hex = String::with_capacity(digest.as_ref().len() * 2);
    for byte in digest.as_ref() {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
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
            accept_dns: default_true(),
            exit_node: None,
            advertise_routes: Vec::new(),
            advertise_exit_node: false,
            forward_tcp_ports: Vec::new(),
            forward_udp_ports: Vec::new(),
            forward_all_ports: false,
            forward_exit_egress: false,
            block_incoming: false,
            exit_proxy: None,
            peerapi_port: None,
            taildrop_dir: None,
            tcp_buffer_size: None,
            enable_ipv6: false,
            persistent_keepalive_interval: default_persistent_keepalive(),
            transport_mode: TransportMode::default(),
            wire_ingress: false,
            ingress_active: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            advertise_services: Vec::new(),
            reauth_on_expiry: default_true(),
            allow_http_key_fetch: false,
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
    fn advertises_no_services_without_peerapi_port() {
        // Fail-closed default: no peerAPI port means no services advertised.
        assert!(Config::default().advertised_services().is_empty());
    }

    #[test]
    fn advertises_peerapi4_and_dns_proxy_when_port_set() {
        use ts_control_serde::ServiceProto;

        let cfg = Config {
            peerapi_port: Some(8080),
            ..Default::default()
        };
        let services = cfg.advertised_services();
        assert_eq!(services.len(), 2);

        // peerapi4 carries the real bind port.
        assert_eq!(services[0].proto, ServiceProto::PeerApi4);
        assert_eq!(services[0].port, 8080);

        // peerapi-dns-proxy always advertises port 1 (Go quirk).
        assert_eq!(services[1].proto, ServiceProto::PeerApiDnsProxy);
        assert_eq!(services[1].port, 1);
    }

    #[test]
    fn peerapi_port_deserializes_default_none() {
        let cfg: Config = serde_json::from_str(r#"{"server_url":"https://example.com/"}"#).unwrap();
        assert_eq!(cfg.peerapi_port, None);
    }

    #[test]
    fn advertise_services_default_empty() {
        assert!(Config::default().advertise_services.is_empty());
        assert!(Config::default().advertised_vip_services().is_empty());
    }

    #[test]
    fn advertise_services_deserializes() {
        let cfg: Config = serde_json::from_str(
            r#"{"server_url":"https://example.com/","advertise_services":["svc:samba"]}"#,
        )
        .unwrap();
        assert_eq!(cfg.advertise_services, vec!["svc:samba".to_owned()]);
    }

    #[test]
    fn advertised_vip_services_validates_and_drops_bad_names() {
        let cfg = Config {
            advertise_services: vec![
                "svc:good".to_owned(),
                "bad-no-prefix".to_owned(),
                "svc:-bad-label".to_owned(),
            ],
            ..Default::default()
        };
        let svcs = cfg.advertised_vip_services();
        assert_eq!(svcs.len(), 1);
        assert_eq!(svcs[0].name, "svc:good");
        // All-ports default range, active.
        assert_eq!(svcs[0].ports.len(), 1);
        assert_eq!(svcs[0].ports[0].first, 0);
        assert_eq!(svcs[0].ports[0].last, 65535);
        assert!(svcs[0].active);
    }

    #[test]
    fn services_hash_empty_is_empty_string() {
        assert_eq!(services_hash(&[]), "");
    }

    #[test]
    fn services_hash_is_order_independent() {
        let a = Config {
            advertise_services: vec!["svc:a".to_owned(), "svc:b".to_owned()],
            ..Default::default()
        };
        let b = Config {
            advertise_services: vec!["svc:b".to_owned(), "svc:a".to_owned()],
            ..Default::default()
        };
        let ha = services_hash(&a.advertised_vip_services());
        let hb = services_hash(&b.advertised_vip_services());
        assert_eq!(ha, hb);
        assert!(!ha.is_empty());
    }

    #[test]
    fn services_hash_changes_with_set() {
        let one = Config {
            advertise_services: vec!["svc:a".to_owned()],
            ..Default::default()
        };
        let two = Config {
            advertise_services: vec!["svc:a".to_owned(), "svc:b".to_owned()],
            ..Default::default()
        };
        assert_ne!(
            services_hash(&one.advertised_vip_services()),
            services_hash(&two.advertised_vip_services())
        );
    }

    #[test]
    fn services_hash_known_answer() {
        // KAT: pin the hash of a single all-ports `svc:samba` so a future serialization change
        // (field order, whitespace) that would silently break the node's own change-detection fails
        // this test. The hash is a SELF-CONSISTENCY TOKEN: this node computes it, sends it in
        // `HostInfo.ServicesHash`, and echoes the same value in `C2NVIPServicesResponse.ServicesHash`;
        // control treats it as opaque and only refetches when it CHANGES — control never recomputes
        // it, so the node only needs to be internally consistent (it is — one `services_hash`).
        //
        // It is NOT byte-equal to Go `vipServiceHash` and is not meant to be: Go does
        // `json.NewEncoder(sha256).Encode(services)` which (a) appends a trailing `\n` that
        // `serde_json::to_vec` here does not, and (b) Go's advertise path (`vipServicesFromPrefsLocked`)
        // leaves `Ports` nil → `"Ports":null`, whereas this fork injects an explicit all-ports
        // `ProtoPortRange` → `"Ports":["*"]`. (The element form IS now Go-correct — `ProtoPortRange`
        // serializes as the TextMarshaler string `"*"`, not a `{Proto,First,Last}` object — which is
        // what moved this value from the old object-form hash.) Full Go-faithful ServicesHash is
        // tracked separately; benign because the token is opaque to control.
        let cfg = Config {
            advertise_services: vec!["svc:samba".to_owned()],
            ..Default::default()
        };
        let hash = services_hash(&cfg.advertised_vip_services());
        // 64 hex chars = SHA-256.
        assert_eq!(hash.len(), 64);
        assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(
            hash,
            "9593a969d3df19c81e5c47a5caeca701ab60b732b99004f15aa00384d922c40c"
        );
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
