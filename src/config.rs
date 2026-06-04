//! Types and utilities for configuring a Tailscale [`Device`](crate::Device).

use std::path::Path;

use serde::Serializer;
use ts_control::ExitProxyConfig;
use ts_keys::PersistState;

use crate::keys::NodeState;

const CONTROL_URL_VAR: &str = "TS_CONTROL_URL";
const HOSTNAME_VAR: &str = "TS_HOSTNAME";
const AUTHKEY_VAR: &str = "TS_AUTH_KEY";

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
    /// route the traffic it egresses through a residential proxy (currently a residential proxy provider; a residential proxy provider and
    /// a residential proxy provider are sunset), so the cloud host's real IP never appears upstream. Only consulted when
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

    /// Construct a default config, setting certain fields from environment variables.
    ///
    /// The fields are only set if the corresponding environment variable is present, using
    /// the default value otherwise.
    ///
    /// Loads:
    ///
    /// - `control_server_url` from `TS_CONTROL_URL`
    /// - `requested_hostname` from `TS_HOSTNAME`
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

        config
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
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            key_state: Default::default(),
            client_name: None,
            control_server_url: ts_control::DEFAULT_CONTROL_SERVER.clone(),
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
            advertise_routes: vec!["10.0.0.0/24".parse().unwrap()],
            requested_tags: vec!["tag:exit".to_owned()],
            ephemeral: false,
            exit_proxy: Some(ExitProxyConfig {
                addr: "198.51.100.9:8080".parse().unwrap(),
                scheme: ts_control::ExitProxyScheme::Socks5,
                auth: Some(("u".to_owned(), "p".to_owned())),
            }),
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
        assert_eq!(control.tags, vec!["tag:exit".to_owned()]);
        let proxy = control.exit_proxy.expect("exit_proxy crosses the boundary");
        assert_eq!(proxy.addr, "198.51.100.9:8080".parse().unwrap());
        assert_eq!(proxy.scheme, ts_control::ExitProxyScheme::Socks5);
        assert_eq!(proxy.auth, Some(("u".to_owned(), "p".to_owned())));
    }

    #[test]
    fn from_config_default_has_no_exit_proxy() {
        let control: ts_control::Config = (&Config::default()).into();
        assert!(control.exit_proxy.is_none());
        assert!(!control.forward_exit_egress);
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
