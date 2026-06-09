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

    /// Whether to accept (and route traffic to) subnet routes advertised by peers.
    ///
    /// This is the equivalent of `tailscale up --accept-routes`. Defaults to `false`: only each
    /// peer's own tailnet address is reachable. Set to `true` to use peers that act as subnet
    /// routers, so traffic destined for an advertised subnet egresses via the advertising peer.
    pub accept_routes: bool,

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
            accept_routes: value.accept_routes,
            exit_node: value.exit_node.clone(),
            advertise_routes: value.advertise_routes.clone(),
            advertise_exit_node: value.advertise_exit_node,
            forward_tcp_ports: value.forward_tcp_ports.clone(),
            forward_udp_ports: value.forward_udp_ports.clone(),
            forward_all_ports: value.forward_all_ports,
            forward_exit_egress: value.forward_exit_egress,
            exit_proxy: value.exit_proxy.clone(),
            tcp_buffer_size: value.tcp_buffer_size,
            persistent_keepalive_interval: value.persistent_keepalive_interval,
            peerapi_port: None,
            taildrop_dir: value.taildrop_dir.clone(),
            enable_ipv6: value.enable_ipv6,
            transport_mode: value.transport_mode.clone(),
            wire_ingress: value.wire_ingress,
            // A fresh runtime-local flag (default `false`): the runtime flips it when
            // `Device::listen_funnel` starts a listener. Not derived from the embedder config.
            ingress_active: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            advertise_services: value.advertise_services.clone(),
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
            accept_routes: false,
            exit_node: None,
            advertise_routes: vec![],
            advertise_exit_node: false,
            forward_tcp_ports: vec![],
            forward_udp_ports: vec![],
            forward_all_ports: false,
            forward_exit_egress: false,
            exit_proxy: None,
            tcp_buffer_size: None,
            persistent_keepalive_interval: Some(ts_control::DEFAULT_PERSISTENT_KEEPALIVE),
            enable_ipv6: false,
            transport_mode: ts_control::TransportMode::default(),
            wire_ingress: false,
            advertise_services: vec![],
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
            advertise_exit_node: true,
            forward_all_ports: true,
            forward_exit_egress: true,
            forward_tcp_ports: vec![80, 443],
            forward_udp_ports: vec![53],
            tcp_buffer_size: Some(1024 * 128),
            persistent_keepalive_interval: Some(std::time::Duration::from_secs(17)),
            enable_ipv6: true,
            wire_ingress: true,
            transport_mode: ts_control::TransportMode::Tun(ts_control::TunConfig {
                name: Some("tailscale0".to_owned()),
                mtu: Some(1280),
            }),
            advertise_routes: vec!["10.0.0.0/24".parse().unwrap()],
            requested_tags: vec!["tag:exit".to_owned()],
            advertise_services: vec!["svc:samba".to_owned()],
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
    }

    #[test]
    fn from_config_default_is_netstack_transport() {
        // The unprivileged userspace netstack is the safe default; opting into a kernel TUN
        // interface (which needs root) must be explicit.
        let control: ts_control::Config = (&Config::default()).into();
        assert_eq!(control.transport_mode, ts_control::TransportMode::Netstack);
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
