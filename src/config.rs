//! Types and utilities for configuring a Tailscale [`Device`](crate::Device).

use std::path::Path;

use serde::Serializer;
use ts_control::ExitProxyConfig;
use ts_keys::PersistState;

use crate::keys::NodeState;

const CONTROL_URL_VAR: &str = "TS_CONTROL_URL";
const HOSTNAME_VAR: &str = "TS_HOSTNAME";
const AUTHKEY_VAR: &str = "TS_AUTH_KEY";
const CLIENT_ID_VAR: &str = "TS_CLIENT_ID";
const CLIENT_SECRET_VAR: &str = "TS_CLIENT_SECRET";
const ID_TOKEN_VAR: &str = "TS_ID_TOKEN";
const AUDIENCE_VAR: &str = "TS_AUDIENCE";

/// Config for connecting to Tailscale.
pub struct Config {
    /// The cryptographic keys representing this node's identity.
    pub key_state: PersistState,

    // TODO(npry): let clients also define an app name once the sdk-level name moves
    //  to a dedicated field
    /// The name of this client.
    ///
    /// This is reported to control in the `Hostinfo.App` field.
    pub client_name: Option<String>,

    /// The URL of the control server to connect to.
    pub control_server_url: url::Url,

    /// Allow fetching the control server's machine public key (`GET /key`) over plain **http** when
    /// [`control_server_url`](Config::control_server_url) is `http://`.
    ///
    /// By default (`false`) the key bootstrap is always upgraded to `https`, even for an `http://`
    /// control URL — so registration **fails** against a control plane that only serves plain http
    /// (e.g. a self-hosted Headscale on a `http://host:port` LAN endpoint / NodePort with no TLS).
    /// Set `true` for such a deployment. Only safe when you control both ends over a trusted network
    /// path; no effect when the control URL is `https://`. Fail-closed default is `false`.
    pub allow_http_key_fetch: bool,

    /// The hostname this node will request.
    ///
    /// If left blank, uses the hostname reported by the OS.
    pub requested_hostname: Option<String>,

    /// Tags this node will request.
    pub requested_tags: Vec<String>,

    /// Whether this node registers as *ephemeral*.
    ///
    /// This is the equivalent of `tailscale up --ephemeral`. An ephemeral node is
    /// garbage-collected by the control server shortly after it disconnects, which is the right
    /// default for short-lived clients. A long-lived node that must survive brief disconnects —
    /// such as a persistent exit node or subnet router — should set this to `false`, or control
    /// will GC it out of the tailnet while it is momentarily offline. Defaults to `true`.
    pub ephemeral: bool,

    /// Whether to automatically re-authenticate when this node's node key expires (rotate the node
    /// key + re-register with the stored auth key, Go `doLogin`) instead of going terminally offline.
    ///
    /// Defaults to `true`: an auth-key-registered node whose key expires recovers itself
    /// automatically — the common reusable-auth-key deployment (a persistent exit node / subnet
    /// router) self-heals rather than requiring manual re-pairing. Set to `false` for the historical,
    /// most conservative behavior (an expired key surfaces
    /// [`DeviceState::Expired`](ts_runtime::DeviceState::Expired) and the node stays offline until
    /// re-paired). Even when `true`, auto-reauth is gated on a usable auth key being retained and
    /// Tailnet Lock NOT being enforced; a one-shot auth key that was already consumed cannot
    /// re-register and degrades to the terminal state.
    pub reauth_on_expiry: bool,

    /// Whether to accept (and route traffic to) subnet routes advertised by peers.
    ///
    /// This is the equivalent of `tailscale up --accept-routes`. Defaults to `false`: only each
    /// peer's own tailnet address is reachable. Set to `true` to use peers that act as subnet
    /// routers, so traffic destined for an advertised subnet egresses via the advertising peer.
    pub accept_routes: bool,

    /// Whether to accept the tailnet's DNS configuration (MagicDNS + pushed resolvers/search
    /// domains).
    ///
    /// This is the equivalent of `tailscale up --accept-dns` (the `CorpDNS` pref). **Defaults to
    /// `true`**, matching Go's `NewPrefs()`. When `true`, the MagicDNS responder serves the
    /// control-pushed DNS config. When `false`, the node ignores the pushed DNS config and the
    /// responder answers every query `REFUSED` — so a node can join the tailnet for connectivity
    /// without taking over its DNS. Runtime-settable via
    /// [`Device::set_accept_dns`](crate::Device::set_accept_dns).
    pub accept_dns: bool,

    /// The peer to route internet-bound traffic through (exit node).
    ///
    /// This is the equivalent of `tailscale up --exit-node`. The peer may be named by stable node
    /// ID, tailnet IP, or MagicDNS name via [`ExitNodeSelector`](crate::ExitNodeSelector) (a bare
    /// IP or name can be parsed with `selector.parse()`). Defaults to `None`: internet-bound
    /// traffic has no overlay route and is dropped (fail-closed). When set to a peer that
    /// advertises a default route, all traffic not matching a more-specific route egresses through
    /// that peer. The selection is re-resolved as the netmap changes.
    pub exit_node: Option<ts_control::ExitNodeSelector>,

    /// Subnet routes to advertise as a subnet router.
    ///
    /// This is the equivalent of `tailscale up --advertise-routes`. Defaults to empty: this node
    /// advertises no routes. Each prefix is sent to the control server in `HostInfo.RoutableIPs`;
    /// once the route is approved, peers with `accept_routes` may send traffic for that subnet
    /// through this node. Only IPv4 prefixes are advertised — IPv6 prefixes are dropped to uphold
    /// the IPv6-off posture (we never forward IPv6, so advertising it would be a black hole).
    pub advertise_routes: Vec<ipnet::IpNet>,

    /// Whether to advertise this node as an exit node.
    ///
    /// This is the equivalent of `tailscale up --advertise-exit-node`. Defaults to `false`. When
    /// `true`, the default route `0.0.0.0/0` is advertised so that, once approved, other peers may
    /// route their internet-bound traffic out through this node's real origin IP. Because that
    /// means *other* peers' traffic egresses via our IP, it is strictly opt-in. `::/0` is never
    /// advertised (IPv6-off).
    pub advertise_exit_node: bool,

    /// TCP ports the inbound forwarder accepts and splices to real OS sockets, for every advertised
    /// route ([`advertise_routes`](Config::advertise_routes) / [`advertise_exit_node`](Config::advertise_exit_node)).
    ///
    /// Acting as a subnet router or exit node means inbound overlay flows to advertised
    /// destinations are dialed out as real OS connections (mirroring Go `tsnet`'s forwarders). The
    /// underlying netstack has no all-port accept mode, so the set of forwarded ports is explicit
    /// rather than the full 1–65535 range. Defaults to empty: a node may advertise routes but
    /// forward nothing until ports are configured (fail-closed — nothing is dialed).
    pub forward_tcp_ports: Vec<u16>,

    /// UDP ports the inbound forwarder accepts and splices to real OS sockets, for every advertised
    /// route. See [`forward_tcp_ports`](Config::forward_tcp_ports); defaults to empty.
    pub forward_udp_ports: Vec<u16>,

    /// Forward **all** TCP/UDP ports (1–65535) on every advertised route, like a Go subnet router.
    ///
    /// This is the equivalent of a `tailscale up --advertise-routes` node forwarding every port,
    /// instead of the explicit [`forward_tcp_ports`](Config::forward_tcp_ports) /
    /// [`forward_udp_ports`](Config::forward_udp_ports) sets. When `true`, those explicit sets are
    /// ignored and the forwarder runs an on-demand per-port listener manager. Anti-leak is
    /// unchanged: every flow still routes through the same dialer chokepoint, so
    /// [`forward_exit_egress`](Config::forward_exit_egress) still governs exit-node egress. Defaults
    /// to `false`.
    pub forward_all_ports: bool,

    /// Whether exit-node (`0.0.0.0/0`) inbound flows are actually egressed via **this host's real
    /// origin IP**.
    ///
    /// Anti-leak opt-in, separate from [`advertise_exit_node`](Config::advertise_exit_node):
    /// advertising the default route only offers this node as an exit to control; it does not by
    /// itself egress a peer's internet-bound traffic. Defaults to `false` (fail-closed): the
    /// forwarder structurally refuses exit-node egress, dropping `0.0.0.0/0` flows at dial time
    /// rather than leaking them out our real IP. Set to `true` only on a node whose real IP *is* the
    /// intended egress (e.g. a residential exit), never on a host whose IP must stay hidden (e.g. a
    /// cloud VPS). Subnet routes are dialed identically regardless of this flag.
    pub forward_exit_egress: bool,

    /// Shields-up (Go `tailscale set --shields-up` / `ipn` `ShieldsUp`): when `true`, refuse all
    /// **inbound** connections from peers that terminate on this node. The packet filter drops
    /// inbound packets destined to this node's own addresses; forwarded subnet/exit transit and
    /// replies to connections this node itself initiated are unaffected. Defaults to `false`.
    pub block_incoming: bool,

    /// Optional upstream proxy that exit-node egress is routed through, so the node egresses via
    /// the proxy's IP rather than its own origin IP.
    ///
    /// This is a **product capability beyond strict Go `tsnet` parity**: it lets a cloud exit node
    /// route the traffic it egresses through a residential proxy provider configured by the
    /// deployer, so the cloud host's real IP never appears upstream. Only consulted when
    /// [`forward_exit_egress`](Config::forward_exit_egress) is `true`. When `Some`, the forwarder is
    /// wired with a SOCKS5 / HTTP `CONNECT` proxy dialer that **fails closed** — any proxy connect
    /// or handshake failure drops the flow rather than dialing direct, so the real IP never leaks.
    /// When `None` (the default) and exit egress is enabled, egress uses this host's real IP. See
    /// the proxy-egress section of the repo's `AGENTS.md`/`CLAUDE.md`.
    pub exit_proxy: Option<ExitProxyConfig>,

    /// Per-direction TCP send/receive buffer size (bytes) for the userspace netstack, or `None` to
    /// use the netstack default (256 KiB per direction, ~512 KiB per socket).
    ///
    /// The underlying smoltcp stack has no TCP window auto-tuning, so this value is the hard cap on
    /// a single flow's bandwidth-delay product: at an 80 ms RTT a 16 KiB window throttles a flow to
    /// ~1.6 Mbps, which visibly slows large model-API responses even at 1x. Each socket allocates
    /// this size for both its rx and tx buffer, so a socket consumes ~2× this value. The default
    /// (256 KiB) suits high-RTT links carrying a few large flows; lower it on memory-constrained
    /// deployments running many concurrent sockets. Applies to both the application and forwarder
    /// netstacks.
    pub tcp_buffer_size: Option<usize>,

    /// WireGuard persistent-keepalive interval applied to every peer, or `None` to disable
    /// (`PersistentKeepalive`; this is the equivalent of Tailscale setting `PersistentKeepalive=25`
    /// on a peer when control marks it `KeepAlive=true`).
    ///
    /// When `Some(interval)` (the default, `Some(25s)`), each peer emits an empty authenticated
    /// keepalive after `interval` of outbound silence, holding the path/NAT mapping warm. This is the
    /// load-bearing fix for **idle DERP-relayed sessions wedging**: on a userspace-netstack node whose
    /// only path to a peer is the relay, an idle session otherwise ages past expiry with no traffic to
    /// keep it warm and no timer to refresh it, so the next dial rehandshakes over a cold path and
    /// loops forever. The persistent keepalive re-arms unconditionally (unlike the reactive WireGuard
    /// §6.5 keepalive, which is armed only by inbound traffic and dies ~10s after the last inbound
    /// packet) and the empty packet deliberately does **not** advance the session's rotation/expiry
    /// timers, so a genuinely dead peer is still detected and rekey still fires on schedule.
    ///
    /// Set to `None` to opt out (e.g. an embedder that has its own keepalive strategy or only ever
    /// runs over a direct, always-warm path). The default is on because this fork's primary
    /// deployment is the relayed case the wedge bites.
    pub persistent_keepalive_interval: Option<std::time::Duration>,

    /// Whether to enable IPv6 **on the tailnet overlay** (peer-to-peer reachability over the node's
    /// Tailscale IPv6 address). Defaults to `false`: the node is IPv4-only on the overlay.
    ///
    /// This is an opt-in for general embedders that want Go `tsnet`-style dual-stack overlay
    /// reachability. It is deliberately **off by default** to preserve this fork's sacred anti-leak
    /// posture: its primary deployment is a privacy proxy / cloud exit node where IPv6 is disabled
    /// everywhere to prevent tunnel-bypass IP leakage. When `false`, behavior is byte-for-byte the
    /// historical IPv4-only path: the underlay binds `0.0.0.0:0`, IPv6 candidates/STUN are refused,
    /// the netstack is handed no IPv6 overlay address, and MagicDNS answers AAAA as NODATA.
    ///
    /// **This flag governs only the overlay.** It has NO effect on the exit-node / forwarder egress
    /// path: exit and subnet egress to the public internet stays hardcoded IPv4 in `ts_forwarder`
    /// regardless of this flag, so the residential-proxy / real-origin-IP isolation invariant can
    /// never be weakened by enabling overlay IPv6. On a host with IPv6 disabled at the kernel, the
    /// dual-stack overlay bind simply fails and the node stays inert on IPv6 rather than panicking.
    pub enable_ipv6: bool,

    /// Whether to run an internal OS network-link monitor that automatically re-binds the underlay
    /// socket and re-probes connectivity (re-ping, re-STUN, re-netcheck) on a link change — a Wi-Fi
    /// switch, sleep/wake, or default-route change. Defaults to `false`.
    ///
    /// Off by default to preserve this fork's pure-engine posture (per `AGENTS.md` this is a pure
    /// engine, not a daemon): the embedder normally owns OS network-monitoring and calls
    /// [`Device::rebind`](crate::Device::rebind) itself. When `false`, the runtime starts **zero**
    /// extra monitor threads or sockets and behaves byte-for-byte as before; the manual
    /// `Device::rebind` path is always available regardless of this flag.
    ///
    /// Enabling it requires the crate to be built with the `network-monitor` feature; setting this
    /// `true` without that feature is a hard error at device startup (never a silent no-op). In this
    /// slice the monitor has no OS backend wired yet, so enabling it spawns the supervisor against a
    /// no-op event source (the Linux/macOS backends land in later slices).
    pub network_monitor: bool,

    /// The fixed UDP port magicsock binds for WireGuard + disco, or `None` for an OS-chosen
    /// ephemeral port (Go `tailscaled --port`; Go's `ListenPort`). Defaults to `None`.
    ///
    /// `None` (the default) preserves the historical behavior: the underlay socket binds `0.0.0.0:0`
    /// and the OS picks an ephemeral port (Go's port `0`). `Some(p)` pins the bind to port `p` so the
    /// node's UDP endpoint is stable across restarts — what an operator behind a fixed-pinhole
    /// firewall needs (Go's daemon defaults this to `41641`, but the engine default stays `None` to
    /// keep today's behavior). If `p` is already taken at startup the bind **falls back to an
    /// ephemeral port** rather than failing bring-up (mirroring magicsock's rebind fallback): a port
    /// collision must not take the node down. A later [`Device::rebind`](crate::Device::rebind)
    /// re-prefers whatever port is currently bound, so a successful pin carries across rebinds.
    ///
    /// Governs **only** the bound port — never the bind family: the IPv4-only-by-default,
    /// fail-closed underlay posture (`enable_ipv6` alone widens the family) is unchanged.
    pub wireguard_listen_port: Option<u16>,

    /// How this node's **application** overlay data path is realized.
    ///
    /// Defaults to [`TransportMode::Netstack`](ts_control::TransportMode::Netstack), the userspace
    /// smoltcp netstack used by the fork's primary unprivileged proxy / exit-node deployment.
    /// [`TransportMode::Tun`](ts_control::TransportMode::Tun) instead routes the node's overlay
    /// packets through a real kernel TUN interface (for embedders that want the host OS networking
    /// stack to see the tailnet directly); it requires privileges (root / `CAP_NET_ADMIN`) and a
    /// platform with TUN support. This governs only the application data path — never the
    /// exit-node / forwarder egress path, which keeps its own IPv4-only userspace netstack.
    pub transport_mode: ts_control::TransportMode,

    /// Whether to ask control to wire this node up server-side for Tailscale Funnel, even when no
    /// Funnel endpoint is currently active (Go `tsnet`'s "would like to be wired up for Funnel"
    /// signal, `HostInfo.WireIngress`, capver 113).
    ///
    /// When `true`, registration and map requests set `HostInfo.WireIngress` so control provisions
    /// the DNS / ingress records a Funnel node needs, making a later
    /// [`Device::listen_funnel`](crate::Device::listen_funnel) (or
    /// `serve`) session work immediately. Defaults to `false` (fail-closed): a node requests Funnel
    /// wiring only when explicitly opted in.
    ///
    /// Note this fork cannot yet *terminate* public Funnel ingress — `Device::listen_funnel` is
    /// fail-closed (no client-side ACME engine, and a self-hosted control plane provides no public
    /// ingress relay). Setting this flag only requests server-side wiring; it does not by itself
    /// make Funnel live.
    pub wire_ingress: bool,

    /// VIP services this node advertises that it **hosts** (`svc:<dns-label>` names), the advertise
    /// side of Tailscale VIP services (Go `tsnet`'s `Hostinfo.ServicesHash` + c2n
    /// `GET /vip-services`).
    ///
    /// Each entry is a full `svc:`-prefixed name. The valid names (each validated as a well-formed
    /// `svc:<dns-label>`; malformed names are dropped and logged) are hashed into
    /// `HostInfo.ServicesHash` on registration and every map request, and reported when control
    /// fetches the hosted-service list via the c2n `/vip-services` endpoint. Defaults to empty:
    /// advertise nothing (the hash is `""`, behavior unchanged). Actually *hosting* a service still
    /// requires control to assign it a VIP and the node to be tagged.
    pub advertise_services: Vec<String>,

    /// Whether to advertise this node as an **app connector** (`tailscale set --advertise-connector`,
    /// Go `Prefs.AppConnector.Advertise`). Defaults to `false`.
    ///
    /// When `true`, registration and every map request set `HostInfo.AppConnector = Some(true)`,
    /// mirroring Go's `applyPrefsToHostinfoLocked` (`hi.AppConnector.Set(prefs.AppConnector().Advertise)`).
    /// This advertises only the *capability* to control — the faithful engine minimum, exactly the
    /// boundary Go draws between advertising and the data path. The app-connector data path itself
    /// (control-pushed connector domain routes, the 4via6 domain→route mapping, the per-domain DNS
    /// observation that learns target IPs) is a separate subsystem this fork does not implement, so a
    /// node advertising this serves no connector traffic until that layer exists — identical in effect
    /// to Go advertising the bool before control has assigned any domains.
    pub advertise_app_connector: bool,

    /// Whether this node opts in to admin-console-triggered auto-updates
    /// (`tailscale set --auto-update`, Go `Prefs.AutoUpdate.Apply`). Defaults to `None`.
    ///
    /// When `Some(true)`, registration and every map request set `HostInfo.AllowsUpdate = true`,
    /// mirroring Go's `applyPrefsToHostinfoLocked`
    /// (`hi.AllowsUpdate = … || prefs.AutoUpdate().Apply.EqualBool(true)`), so the admin console knows
    /// the node accepts remote update triggers. This advertises the bool only: **this fork runs no
    /// updater** (it is an embeddable engine, not a packaged daemon), so it never *applies* an update —
    /// the self-update machinery is a daemon / OS-package concern. `Some(false)` and `None` both leave
    /// `AllowsUpdate` unset (advertise that the node does not accept remote updates); the tri-state
    /// mirrors Go's `opt.Bool` (unset vs explicitly-off vs on).
    pub auto_update_apply: Option<bool>,

    /// Whether a background updater should *check* for available updates (Go `Prefs.AutoUpdate.Check`).
    /// Defaults to `false`.
    ///
    /// **Carried pref only — the engine never acts on it and it is never sent to control.** In Go this
    /// gates a purely local background update-check loop in the daemon; it is not part of `Hostinfo`
    /// and never crosses the control wire. This fork has no updater (engine, not daemon), so the value
    /// is stored and threaded through to [`ts_control::Config`] solely so a downstream daemon can carry
    /// the pref. Storing it (rather than dropping it) is the faithful mirror of tsnet's pref state.
    pub auto_update_check: bool,

    /// The OS username permitted to operate this node over a local management API
    /// (`tailscale set --operator`, Go `Prefs.OperatorUser`). Defaults to `None`.
    ///
    /// **Carried pref only — the engine never acts on it and it is never sent to control.** In Go this
    /// is purely a daemon-side LocalAPI authorization check (which Unix uid may drive the daemon
    /// without root); it never touches the control protocol. This fork is a pure engine with no local
    /// API to gate, so the value is stored and threaded through to [`ts_control::Config`] solely for a
    /// downstream daemon that exposes a local API to consult. Faithful mirror of tsnet pref state.
    pub operator_user: Option<String>,

    /// A local display label for this node's login profile (Go `Prefs.ProfileName`, set via
    /// `tailscale switch` / profile management). Defaults to `None`.
    ///
    /// **Carried pref only — the engine never acts on it and it is never sent to control.** In Go this
    /// is a client-local cosmetic name for the login profile; it is never advertised in `Hostinfo`
    /// (distinct from the [`requested_hostname`](Config::requested_hostname) the node requests). The
    /// value is stored and threaded through to [`ts_control::Config`] solely for a downstream daemon's
    /// profile UI. Faithful mirror of tsnet pref state.
    pub node_nickname: Option<String>,

    /// Whether device-posture identity collection is enabled (`tailscale set --posture-checking`,
    /// Go `Prefs.PostureChecking`). Defaults to `false`.
    ///
    /// **Carried pref only — the engine never acts on it and it is never sent to control.** There is
    /// deliberately **no `Hostinfo.PostureChecking` field** to wire it to: posture is a
    /// control-to-node (c2n) *pull* mechanism — control requests posture attributes (serial numbers,
    /// etc.) from the node on demand — which this fork does not implement. With no c2n posture
    /// responder, control simply never pulls posture identity, byte-for-byte identical to the
    /// posture-disabled case, so storing the pref is the faithful mirror. The value is threaded through
    /// to [`ts_control::Config`] for a downstream daemon that implements the c2n posture endpoint.
    pub posture_checking: bool,

    /// Whether this node runs a local web client (`tailscale set --webclient`,
    /// Go `Prefs.RunWebClient`). Defaults to `false`.
    ///
    /// **Carried pref only — the engine never acts on it and it is never sent to control.** In Go this
    /// gates a daemon-hosted local web-client HTTP server (the device-management web UI on
    /// `100.x:5252`); it is a separate subsystem, not advertised in `Hostinfo`. This fork has no
    /// web-client server, so the value is stored and threaded through to [`ts_control::Config`] solely
    /// for a downstream daemon that does. Faithful mirror of tsnet pref state.
    pub run_web_client: bool,

    /// Whether a peer using this node as an exit node may also reach this node's **local LAN**
    /// (`tailscale set --exit-node-allow-lan-access`, Go `Prefs.ExitNodeAllowLANAccess`). Defaults to
    /// `false`.
    ///
    /// **Carried pref only for now — the engine does not yet act on it and it is never sent to
    /// control.** In Go this is an **OS-router route-shaping** flag: when acting as an exit node it
    /// controls whether the host router excludes the local LAN ranges from the routes pulled through
    /// the tunnel. On a platform with no host router it has "no effect" — and this fork's default data
    /// path is the userspace netstack, which has no host-route layer to shape. The value is stored and
    /// threaded through to [`ts_control::Config`] so a downstream daemon (or a future host-route layer
    /// in this engine) can consume it; until such a layer exists it is inert. Never advertised.
    pub exit_node_allow_lan_access: bool,

    /// Filesystem directory that received Taildrop files land in, or `None` to disable Taildrop
    /// (the default, fail-closed).
    ///
    /// When `Some(dir)` **and** a peerAPI port is configured (Taildrop is served on the shared
    /// peerAPI listener, so it needs the same bind), the runtime serves the Taildrop peerAPI route
    /// `PUT /v0/put/<name>` and writes incoming files under `dir` (created if absent). When `None`,
    /// no Taildrop server is run and a peer's `PUT` is refused (`403`). The embedder consumes
    /// received files via the [`Device::taildrop_waiting_files`](crate::Device::taildrop_waiting_files)
    /// / [`taildrop_open_file`](crate::Device::taildrop_open_file) /
    /// [`taildrop_delete_file`](crate::Device::taildrop_delete_file) methods.
    pub taildrop_dir: Option<std::path::PathBuf>,

    /// Pre-auth key for non-interactive registration (Go `tsnet.Server.AuthKey`). When set, used as
    /// the registration auth key. If it is an OAuth client secret (prefix `tskey-client-`) and the
    /// `identity-federation` feature is enabled, it is exchanged for an auth key before registration.
    /// Falls back to the `TS_AUTH_KEY` env var (see [`auth_key_from_env`]). Defaults to `None`.
    pub auth_key: Option<String>,

    /// OAuth client ID for workload-identity federation (Go `tsnet.Server.ClientID`). SaaS-only;
    /// requires the `identity-federation` feature. With [`id_token`](Config::id_token) or
    /// [`audience`](Config::audience), the node exchanges an IdP-issued OIDC token for a Tailscale
    /// auth key. Defaults to `None` (`TS_CLIENT_ID` env fallback).
    pub client_id: Option<String>,

    /// OAuth client secret used to mint auth keys via OAuth (Go `tsnet.Server.ClientSecret`).
    /// SaaS-only; requires the `identity-federation` feature. Defaults to `None` (`TS_CLIENT_SECRET`).
    ///
    /// Treat as **fully operator-trusted input**: a `tskey-client-…?baseURL=…` secret redirects the
    /// credential exchange to that host, so a hostile value would exfiltrate the secret and the
    /// minted auth key. Never source it from a less-trusted origin.
    pub client_secret: Option<String>,

    /// IdP-issued OIDC ID token to exchange with control for an auth key via workload-identity
    /// federation (Go `tsnet.Server.IDToken`). SaaS-only; requires the `identity-federation` feature
    /// and [`client_id`](Config::client_id). Mutually exclusive with [`audience`](Config::audience).
    /// Defaults to `None` (`TS_ID_TOKEN`).
    pub id_token: Option<String>,

    /// Audience for requesting an OIDC ID token from the ambient workload identity (GitHub Actions /
    /// GCP / AWS), to exchange for an auth key via workload-identity federation (Go
    /// `tsnet.Server.Audience`). SaaS-only; requires the `identity-federation` feature +
    /// [`client_id`](Config::client_id). Mutually exclusive with [`id_token`](Config::id_token).
    /// Defaults to `None` (`TS_AUDIENCE`).
    pub audience: Option<String>,
}

impl Config {
    /// Create a new config with its [`key_state`](Config::key_state) populated from the specified key file and using
    /// default options for other configuration.
    ///
    /// See [`load_key_file`] for more details and an alternative with more options for reading
    /// the key file.
    pub async fn default_with_key_file(p: impl AsRef<Path>) -> Result<Self, crate::Error> {
        Ok(Config {
            key_state: load_key_file(p, Default::default()).await?,
            ..Default::default()
        })
    }

    /// Run the application overlay over a real kernel **TUN** interface instead of the default
    /// userspace netstack — a builder shortcut for setting
    /// [`transport_mode`](Config::transport_mode) to
    /// [`TransportMode::Tun`](ts_control::TransportMode::Tun).
    ///
    /// `name` is the desired interface name (`None` lets the OS pick, e.g. `utunN` on macOS); `mtu`
    /// is the interface MTU (`None` uses the transport default; Tailscale's overlay MTU is 1280).
    /// TUN mode requires root / `CAP_NET_ADMIN` and the engine's `tun` feature to be enabled.
    /// Chainable: `Config::default().use_tun(Some("tailscale0".into()), None)`.
    #[must_use]
    pub fn use_tun(mut self, name: Option<String>, mtu: Option<u16>) -> Self {
        self.transport_mode = ts_control::TransportMode::Tun(ts_control::TunConfig { name, mtu });
        self
    }

    /// Construct a default config, setting certain fields from environment variables.
    ///
    /// The fields are only set if the corresponding environment variable is present, using
    /// the default value otherwise.
    ///
    /// Loads:
    ///
    /// - `control_server_url` from `TS_CONTROL_URL`
    /// - `requested_hostname` from `TS_HOSTNAME`
    /// - `auth_key` from `TS_AUTH_KEY`
    /// - `client_id` from `TS_CLIENT_ID`
    /// - `client_secret` from `TS_CLIENT_SECRET`
    /// - `id_token` from `TS_ID_TOKEN`
    /// - `audience` from `TS_AUDIENCE`
    pub fn default_from_env() -> Config {
        let mut config = Config::default();

        if let Ok(u) = std::env::var(CONTROL_URL_VAR) {
            match u.parse() {
                Ok(u) => config.control_server_url = u,
                Err(e) => {
                    tracing::error!(error = %e, "parsing {CONTROL_URL_VAR} (fall back to default value)");
                }
            }
        };

        config.requested_hostname = std::env::var(HOSTNAME_VAR).ok();

        if let Some(auth_key) = auth_key_from_env() {
            config.auth_key = Some(auth_key);
        }
        if let Ok(client_id) = std::env::var(CLIENT_ID_VAR) {
            config.client_id = Some(client_id);
        }
        if let Ok(client_secret) = std::env::var(CLIENT_SECRET_VAR) {
            config.client_secret = Some(client_secret);
        }
        if let Ok(id_token) = std::env::var(ID_TOKEN_VAR) {
            config.id_token = Some(id_token);
        }
        if let Ok(audience) = std::env::var(AUDIENCE_VAR) {
            config.audience = Some(audience);
        }

        config
    }

    /// Rotate this config's node key in place for an embedder-driven re-registration, mirroring Go's
    /// `regen` flow: the current node key is recorded as the old key and a fresh node key is
    /// generated. Re-create the [`Device`](crate::Device) from this config to perform the rotation;
    /// the next registration sends the prior key as `OldNodeKey` for key continuity.
    ///
    /// Reactive and embedder-driven by design (you decide when to rotate, e.g. after observing
    /// [`Device::self_key_expired`](crate::Device::self_key_expired) flip, or on a policy of your
    /// own). This fork does not auto-rotate before expiry — neither does Go, which treats key expiry
    /// as a deliberate periodic re-authentication checkpoint. Rotation still requires a valid auth
    /// key, exactly like a fresh registration.
    pub fn rotate_node_key(&mut self) {
        self.key_state.rotate_node_key();
    }
}

/// Load an auth key from the `TS_AUTH_KEY` environment variable.
pub fn auth_key_from_env() -> Option<String> {
    std::env::var(AUTHKEY_VAR).ok()
}

/// Load key state from a path on the filesystem, or create a file with a new key state if
/// one doesn't exist.
///
/// The `bad_format` argument allows you to specify whether an existing file should be
/// overwritten if the contents can't be parsed.
pub async fn load_key_file(
    p: impl AsRef<Path>,
    bad_format: BadFormatBehavior,
) -> Result<PersistState, crate::Error> {
    let p = p.as_ref();

    tracing::trace!(key_file = %p.display(), "loading key file");

    let key_file = load_or_init::<KeyFile>(
        &p,
        Default::default,
        |x| match x {
            #[allow(deprecated)]
            KeyFile::Old(old) => Some(KeyFile::New(KeyFileNew {
                key_state: PersistState::from(&old.key_state),
            })),
            _ => None,
        },
        bad_format,
    )
    .await?;
    Ok(key_file.key_state())
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum KeyFile {
    #[deprecated]
    Old(KeyFileOld),
    New(KeyFileNew),
}

impl KeyFile {
    #[allow(deprecated)]
    pub fn key_state(&self) -> PersistState {
        match self {
            Self::Old(old) => (&old.key_state).into(),
            Self::New(new) => new.key_state.clone(),
        }
    }
}

impl Default for KeyFile {
    fn default() -> Self {
        KeyFile::New(KeyFileNew::default())
    }
}

impl serde::Serialize for KeyFile {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        KeyFileNew {
            key_state: self.key_state(),
        }
        .serialize(serializer)
    }
}

#[derive(serde::Deserialize, serde::Serialize, Default)]
struct KeyFileNew {
    key_state: PersistState,
}

#[derive(serde::Deserialize)]
struct KeyFileOld {
    key_state: NodeState,
}

impl From<&Config> for ts_control::Config {
    fn from(value: &Config) -> ts_control::Config {
        ts_control::Config {
            client_name: value.client_name.clone(),
            hostname: value.requested_hostname.clone(),
            server_url: value.control_server_url.clone(),
            tags: value.requested_tags.clone(),
            ephemeral: value.ephemeral,
            reauth_on_expiry: value.reauth_on_expiry,
            accept_routes: value.accept_routes,
            accept_dns: value.accept_dns,
            exit_node: value.exit_node.clone(),
            advertise_routes: value.advertise_routes.clone(),
            advertise_exit_node: value.advertise_exit_node,
            forward_tcp_ports: value.forward_tcp_ports.clone(),
            forward_udp_ports: value.forward_udp_ports.clone(),
            forward_all_ports: value.forward_all_ports,
            forward_exit_egress: value.forward_exit_egress,
            block_incoming: value.block_incoming,
            exit_proxy: value.exit_proxy.clone(),
            tcp_buffer_size: value.tcp_buffer_size,
            persistent_keepalive_interval: value.persistent_keepalive_interval,
            peerapi_port: None,
            taildrop_dir: value.taildrop_dir.clone(),
            enable_ipv6: value.enable_ipv6,
            network_monitor: value.network_monitor,
            wireguard_listen_port: value.wireguard_listen_port,
            transport_mode: value.transport_mode.clone(),
            wire_ingress: value.wire_ingress,
            // A fresh runtime-local flag (default `false`): the runtime flips it when
            // `Device::listen_funnel` starts a listener. Not derived from the embedder config.
            ingress_active: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            advertise_services: value.advertise_services.clone(),
            advertise_app_connector: value.advertise_app_connector,
            auto_update_apply: value.auto_update_apply,
            auto_update_check: value.auto_update_check,
            operator_user: value.operator_user.clone(),
            node_nickname: value.node_nickname.clone(),
            posture_checking: value.posture_checking,
            run_web_client: value.run_web_client,
            exit_node_allow_lan_access: value.exit_node_allow_lan_access,
            allow_http_key_fetch: value.allow_http_key_fetch,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            key_state: Default::default(),
            client_name: None,
            control_server_url: ts_control::DEFAULT_CONTROL_SERVER.clone(),
            allow_http_key_fetch: false,
            requested_hostname: None,
            requested_tags: vec![],
            ephemeral: true,
            reauth_on_expiry: true,
            accept_routes: false,
            accept_dns: true,
            exit_node: None,
            advertise_routes: vec![],
            advertise_exit_node: false,
            forward_tcp_ports: vec![],
            forward_udp_ports: vec![],
            forward_all_ports: false,
            forward_exit_egress: false,
            block_incoming: false,
            exit_proxy: None,
            tcp_buffer_size: None,
            persistent_keepalive_interval: Some(ts_control::DEFAULT_PERSISTENT_KEEPALIVE),
            enable_ipv6: false,
            network_monitor: false,
            wireguard_listen_port: None,
            transport_mode: ts_control::TransportMode::default(),
            wire_ingress: false,
            advertise_services: vec![],
            advertise_app_connector: false,
            auto_update_apply: None,
            auto_update_check: false,
            operator_user: None,
            node_nickname: None,
            posture_checking: false,
            run_web_client: false,
            exit_node_allow_lan_access: false,
            taildrop_dir: None,
            auth_key: None,
            client_id: None,
            client_secret: None,
            id_token: None,
            audience: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The `From<&Config> for ts_control::Config` impl hand-copies every field, so it silently
    // drops any field a future edit forgets to add. These tests assert each dataplane field
    // crosses the boundary, with special attention to the anti-leak ones (`forward_exit_egress`,
    // `exit_proxy`) whose loss would change egress behavior.
    #[test]
    fn from_config_threads_all_dataplane_fields() {
        let cfg = Config {
            accept_routes: true,
            // Set to the non-default (`false`) so its crossing is observable (default is `true`).
            accept_dns: false,
            advertise_exit_node: true,
            forward_all_ports: true,
            forward_exit_egress: true,
            forward_tcp_ports: vec![80, 443],
            forward_udp_ports: vec![53],
            tcp_buffer_size: Some(1024 * 128),
            persistent_keepalive_interval: Some(std::time::Duration::from_secs(17)),
            enable_ipv6: true,
            network_monitor: true,
            wireguard_listen_port: Some(41641),
            wire_ingress: true,
            transport_mode: ts_control::TransportMode::Tun(ts_control::TunConfig {
                name: Some("tailscale0".to_owned()),
                mtu: Some(1280),
            }),
            advertise_routes: vec!["10.0.0.0/24".parse().unwrap()],
            requested_tags: vec!["tag:exit".to_owned()],
            advertise_services: vec!["svc:samba".to_owned()],
            advertise_app_connector: true,
            auto_update_apply: Some(true),
            auto_update_check: true,
            operator_user: Some("alice".to_owned()),
            node_nickname: Some("laptop".to_owned()),
            posture_checking: true,
            run_web_client: true,
            exit_node_allow_lan_access: true,
            ephemeral: false,
            exit_proxy: Some(ExitProxyConfig {
                addr: "198.51.100.9:8080".parse().unwrap(),
                scheme: ts_control::ExitProxyScheme::Socks5,
                auth: Some(("u".to_owned(), "p".to_owned())),
            }),
            taildrop_dir: Some(std::path::PathBuf::from("/var/lib/taildrop")),
            ..Default::default()
        };

        let control: ts_control::Config = (&cfg).into();

        assert!(control.accept_routes);
        assert!(
            !control.accept_dns,
            "accept_dns crosses the boundary (set false)"
        );
        assert!(control.advertise_exit_node);
        assert!(control.forward_all_ports);
        assert!(control.forward_exit_egress);
        assert!(!control.ephemeral);
        assert_eq!(control.forward_tcp_ports, vec![80, 443]);
        assert_eq!(control.forward_udp_ports, vec![53]);
        assert_eq!(control.tcp_buffer_size, Some(1024 * 128));
        assert_eq!(
            control.persistent_keepalive_interval,
            Some(std::time::Duration::from_secs(17))
        );
        assert_eq!(control.tags, vec!["tag:exit".to_owned()]);
        let proxy = control.exit_proxy.expect("exit_proxy crosses the boundary");
        assert_eq!(proxy.addr, "198.51.100.9:8080".parse().unwrap());
        assert_eq!(proxy.scheme, ts_control::ExitProxyScheme::Socks5);
        assert_eq!(proxy.auth, Some(("u".to_owned(), "p".to_owned())));
        assert!(control.enable_ipv6);
        assert!(
            control.network_monitor,
            "network_monitor crosses the boundary (set true)"
        );
        assert_eq!(
            control.wireguard_listen_port,
            Some(41641),
            "wireguard_listen_port crosses the boundary"
        );
        assert!(control.wire_ingress);
        assert_eq!(control.advertise_services, vec!["svc:samba".to_owned()]);
        assert_eq!(
            control.taildrop_dir,
            Some(std::path::PathBuf::from("/var/lib/taildrop"))
        );
        assert_eq!(
            control.transport_mode,
            ts_control::TransportMode::Tun(ts_control::TunConfig {
                name: Some("tailscale0".to_owned()),
                mtu: Some(1280),
            })
        );
        // up/set pref fields cross the boundary: two advertise-side, six store-only carried prefs.
        assert!(control.advertise_app_connector);
        assert_eq!(control.auto_update_apply, Some(true));
        assert!(control.auto_update_check);
        assert_eq!(control.operator_user.as_deref(), Some("alice"));
        assert_eq!(control.node_nickname.as_deref(), Some("laptop"));
        assert!(control.posture_checking);
        assert!(control.run_web_client);
        assert!(control.exit_node_allow_lan_access);
    }

    /// All eight up/set pref fields default off/None on a fresh top-level `Config`, and the defaults
    /// cross the `From<&Config>` boundary unchanged. Fail-closed: a default node advertises no
    /// app-connector / auto-update and carries no operator/nickname/posture/webclient/LAN-access pref.
    #[test]
    fn from_config_default_up_set_pref_fields_off() {
        let cfg = Config::default();
        // Defaults on the top-level config.
        assert!(!cfg.advertise_app_connector);
        assert_eq!(cfg.auto_update_apply, None);
        assert!(!cfg.auto_update_check);
        assert_eq!(cfg.operator_user, None);
        assert_eq!(cfg.node_nickname, None);
        assert!(!cfg.posture_checking);
        assert!(!cfg.run_web_client);
        assert!(!cfg.exit_node_allow_lan_access);

        // And they cross the boundary defaulted off.
        let control: ts_control::Config = (&cfg).into();
        assert!(!control.advertise_app_connector);
        assert_eq!(control.auto_update_apply, None);
        assert!(!control.auto_update_check);
        assert_eq!(control.operator_user, None);
        assert_eq!(control.node_nickname, None);
        assert!(!control.posture_checking);
        assert!(!control.run_web_client);
        assert!(!control.exit_node_allow_lan_access);
    }

    #[test]
    fn from_config_default_is_netstack_transport() {
        // The unprivileged userspace netstack is the safe default; opting into a kernel TUN
        // interface (which needs root) must be explicit.
        let control: ts_control::Config = (&Config::default()).into();
        assert_eq!(control.transport_mode, ts_control::TransportMode::Netstack);
    }

    /// The WireGuard listen port defaults to `None` (OS-chosen ephemeral, today's behavior) and
    /// crosses the control boundary unchanged. A daemon that wants Go's `--port 41641` sets it
    /// explicitly; the engine never pins a port by default.
    #[test]
    fn from_config_default_wireguard_listen_port_is_none() {
        let cfg = Config::default();
        assert_eq!(cfg.wireguard_listen_port, None);
        let control: ts_control::Config = (&cfg).into();
        assert_eq!(control.wireguard_listen_port, None);
    }

    #[test]
    fn from_config_default_has_no_exit_proxy() {
        let control: ts_control::Config = (&Config::default()).into();
        assert!(control.exit_proxy.is_none());
        assert!(!control.forward_exit_egress);
    }

    /// Persistent keepalive is **on by default at 25s** — this is the idle-wedge fix's safe default
    /// for the relayed case (an idle DERP-relayed session would otherwise age out and wedge). The
    /// default mirrors `ts_control::DEFAULT_PERSISTENT_KEEPALIVE` and crosses the control boundary.
    #[test]
    fn from_config_default_enables_persistent_keepalive_25s() {
        let cfg = Config::default();
        assert_eq!(
            cfg.persistent_keepalive_interval,
            Some(std::time::Duration::from_secs(25))
        );
        let control: ts_control::Config = (&cfg).into();
        assert_eq!(
            control.persistent_keepalive_interval,
            Some(ts_control::DEFAULT_PERSISTENT_KEEPALIVE)
        );
    }

    #[test]
    fn wif_fields_default_none() {
        // Workload-identity-federation config is SaaS-only and opt-in: a default config never
        // carries an auth key or any OAuth/OIDC federation material.
        let cfg = Config::default();
        assert!(cfg.auth_key.is_none());
        assert!(cfg.client_id.is_none());
        assert!(cfg.client_secret.is_none());
        assert!(cfg.id_token.is_none());
        assert!(cfg.audience.is_none());
    }

    #[test]
    fn from_config_default_is_ipv4_only() {
        // The IPv6-off posture is the safe default: enabling overlay IPv6 must be an explicit opt-in.
        let control: ts_control::Config = (&Config::default()).into();
        assert!(!control.enable_ipv6);
    }

    /// `use_tun` is a chainable builder that sets `transport_mode` to `Tun(TunConfig { name, mtu })`,
    /// and the selection threads through to the control config. Also exercises the facade re-exports
    /// `tailscale::TransportMode` / `tailscale::TunConfig` by naming them without the `ts_control::`
    /// path (the whole point of the re-export — a downstream crate can use only the facade).
    #[test]
    fn use_tun_builder_sets_transport_mode() {
        use crate::{TransportMode, TunConfig};

        // Default is netstack.
        assert_eq!(Config::default().transport_mode, TransportMode::Netstack);

        let cfg = Config::default().use_tun(Some("tailscale0".to_string()), Some(1280));
        assert_eq!(
            cfg.transport_mode,
            TransportMode::Tun(TunConfig {
                name: Some("tailscale0".to_string()),
                mtu: Some(1280),
            })
        );

        // The selection crosses the From<&Config> boundary into the control config.
        let control: ts_control::Config = (&cfg).into();
        assert_eq!(
            control.transport_mode,
            TransportMode::Tun(TunConfig {
                name: Some("tailscale0".to_string()),
                mtu: Some(1280),
            })
        );
    }
}

/// What to do if the key file can't be parsed.
///
/// Default behavior: return an error.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub enum BadFormatBehavior {
    /// Return an error.
    #[default]
    Error,

    /// Overwrite the file with a newly-generated set of keys.
    Overwrite,
}

/// Attempt to load a file from a path. If it doesn't exist, create it with the
/// specified default value.
#[tracing::instrument(skip_all, fields(?bad_format_behavior, path = %path.as_ref().display()))]
async fn load_or_init<KeyState>(
    path: impl AsRef<Path>,
    default: impl FnOnce() -> KeyState,
    migrate: impl FnOnce(&KeyState) -> Option<KeyState>,
    bad_format_behavior: BadFormatBehavior,
) -> Result<KeyState, crate::Error>
where
    KeyState: serde::Serialize + serde::de::DeserializeOwned,
{
    let path = path.as_ref();

    tokio::fs::create_dir_all(path.parent().unwrap())
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "creating parent dirs for key file");
            crate::Error::KeyFileWrite
        })?;

    match tokio::fs::read(path).await {
        Ok(contents) => match serde_json::from_slice::<KeyState>(&contents) {
            Ok(state) => {
                if let Some(migrated) = migrate(&state) {
                    match try_write(path, &migrated).await {
                        Ok(_) => {
                            tracing::info!("migrated key file to new disco-less format");
                            return Ok(migrated);
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "unable to migrate key file");
                        }
                    }
                }

                return Ok(state);
            }
            Err(e) => match bad_format_behavior {
                BadFormatBehavior::Error => {
                    tracing::error!(error = %e, "parsing key file");
                    return Err(crate::Error::KeyFileRead);
                }
                BadFormatBehavior::Overwrite => {
                    tracing::warn!(
                        error = %e,
                        config_file_contents_len = contents.len(),
                        "failed loading version from key file, overwriting",
                    );
                }
            },
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            tracing::error!(error = %e, path = %path.display(), "reading key file");
            return Err(crate::Error::KeyFileRead);
        }
    }

    let value = default();
    try_write(path, &value).await?;
    Ok(value)
}

async fn try_write(
    path: impl AsRef<Path>,
    value: &impl serde::Serialize,
) -> Result<(), crate::Error> {
    tokio::fs::write(
        path,
        serde_json::to_vec(value).map_err(|e| {
            tracing::error!(error = %e, "serializing key state");
            crate::Error::KeyFileWrite
        })?,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "saving key state");
        crate::Error::KeyFileWrite
    })?;

    Ok(())
}
