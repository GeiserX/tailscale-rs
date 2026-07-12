//! A Go-idiomatic [`tsnet.Server`](https://pkg.go.dev/tailscale.com/tsnet#Server)-shaped facade over
//! [`Device`](crate::Device) and [`Config`](crate::Config), behind the `tsnet` cargo feature.
//!
//! # Why this exists
//!
//! The fork's native embedding surface is [`Device`] + [`Config`]: you build a `Config`, then
//! `Device::new(&config, auth_key).await`. That is idiomatic Rust (construct-from-config, typed
//! errors) and is a documented *superset* of Go `tsnet` (see `docs/TSNET_PARITY.md`). But a large
//! body of existing code — and muscle memory — is written against Go's shape:
//!
//! ```go
//! srv := &tsnet.Server{Hostname: "web", AuthKey: key}
//! ln, _ := srv.Listen("tcp", ":80")
//! defer srv.Close()
//! ```
//!
//! [`Server`] is a **thin, Go-shaped ergonomics layer** over the existing engine. It changes *nothing*
//! about the dataplane, control, or netstack: it maps a set of Go-`tsnet.Server`-parity fields onto
//! [`Config`], defers construction of the wrapped [`Device`] until the first method call (Go's
//! "fields may be changed until the first method call"), and forwards every call straight to the
//! [`Device`] it wraps. It is deliberately **not** a re-implementation and **not** a new crate.
//!
//! # What stays Rust-native (on purpose)
//!
//! "Go-idiomatic" here means the **lifecycle model and method names** (settable fields, lazy
//! `start`, `up`/`close`, `Listen`/`Dial`/`Loopback`/`ListenFunnel`/`ListenService`), *not* Go's
//! return types. A thin facade must not re-wrap the engine's types into `net.Conn`/`net.Listener`
//! trait objects — that would be a translation layer, not a facade, and would throw away the fork's
//! typed returns. So:
//!
//! * inbound/outbound connections keep their engine types ([`DialConn`](crate::DialConn),
//!   [`netstack::TcpListener`](crate::netstack::TcpListener), …);
//! * specialized calls keep the fork's **typed** errors ([`ServiceError`](crate::ServiceError),
//!   [`FunnelError`](ts_control::FunnelError)); only the *lifecycle* path — which in Go is a single
//!   opaque `error` — is unified into [`Error`];
//! * addresses are accepted as Go-style `network, addr` **strings** (`"tcp"`, `":80"`) for
//!   familiarity, and parsed to the typed [`SocketAddr`] the engine wants.
//!
//! See `docs/TSNET_FACADE_DESIGN.md` for the full rationale, the field-by-field mapping table, and
//! the state-root (`Dir`/`Store`) design over [`Config::key_state`](crate::Config::key_state).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::OnceCell;
use ts_keys::PersistState;

use crate::config::Config;
use crate::netstack;
use crate::{Device, RegistrationError, ServiceError, ServiceMode, Status};

// ---------------------------------------------------------------------------------------------
// State store — the `Dir` / `Store` design (Go `ipn.StateStore` + `FileStore`), over `key_state`.
// ---------------------------------------------------------------------------------------------

/// Default on-disk state file name under [`Server::dir`] (Go persists node state to
/// `Dir/tailscaled.state`; this fork persists only node **identity keys**, see the module docs and
/// `docs/TSNET_FACADE_DESIGN.md` §"State root").
pub const STATE_FILE: &str = "tailscale-rs.state";

/// The well-known key under which the node identity blob ([`PersistState`]) is stored in a
/// [`StateStore`] (Go stores the machine key + profile under fixed keys in the `StateStore`).
pub const STATE_KEY: &str = "_tailscale-rs/persist";

/// A pluggable key/value state store — the Rust analog of Go's `ipn.StateStore`
/// ([`Server::store`]).
///
/// **Scope (be honest).** Unlike Go — which persists the *full* node state (prefs + netmap +
/// machine key) — this fork's engine only persists node **identity keys**. So a [`StateStore`] here
/// round-trips exactly one value: the [`PersistState`] identity blob under [`STATE_KEY`]. The trait
/// is intentionally the general KV shape so it stays forward-compatible: when the engine grows
/// prefs/netmap persistence, more keys slot in with no caller change. See the design doc.
pub trait StateStore: Send + Sync {
    /// Read the value for `id`, or `Ok(None)` if it has never been written.
    fn read_state(&self, id: &str) -> std::io::Result<Option<Vec<u8>>>;
    /// Durably write `value` for `id`.
    fn write_state(&self, id: &str, value: &[u8]) -> std::io::Result<()>;
}

/// An on-disk JSON [`StateStore`] rooted at a single file (Go `store.FileStore`).
///
/// Prefer setting [`Server::dir`] for the standard on-disk identity — that path reuses the engine's
/// own key-file format and migration ([`Config::default_with_key_file`]). Use an explicit
/// `FileStore`/custom [`StateStore`] only for a non-default location or a bespoke backend.
pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    /// A file store writing to `dir/`[`STATE_FILE`].
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            path: dir.into().join(STATE_FILE),
        }
    }

    /// A file store writing to an exact file path.
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl StateStore for FileStore {
    fn read_state(&self, _id: &str) -> std::io::Result<Option<Vec<u8>>> {
        match std::fs::read(&self.path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn write_state(&self, _id: &str, value: &[u8]) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.path, value)
    }
}

/// An in-memory [`StateStore`] (Go `mem.Store`): identity is regenerated every run and never
/// persisted. This is the implicit behavior when neither [`Server::dir`] nor [`Server::store`] is
/// set; provide it explicitly to be unambiguous.
#[derive(Default)]
pub struct MemStore {
    inner: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
}

impl StateStore for MemStore {
    fn read_state(&self, id: &str) -> std::io::Result<Option<Vec<u8>>> {
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned())
    }

    fn write_state(&self, id: &str, value: &[u8]) -> std::io::Result<()> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id.to_string(), value.to_vec());
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------
// Errors — unify only the *lifecycle* path (Go's single opaque `error`); preserve typed errors
// on the specialized calls (Funnel/Service), matching the engine.
// ---------------------------------------------------------------------------------------------

/// The unified error for [`Server`]'s lifecycle surface (`start`/`up`/`dial`/`listen`/…).
///
/// Go returns a single opaque `error` everywhere; this fork returns *typed* errors. [`Error`] is the
/// Go-shaped unification for the lifecycle path only — the specialized calls that already carry rich
/// typed errors keep them: [`Server::listen_funnel`] → [`ts_control::FunnelError`],
/// [`Server::listen_service`] → [`ServiceError`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The wrapped [`Device`]/engine returned an error.
    #[error("device error: {0}")]
    Device(#[from] crate::Error),

    /// Registration did not reach `Running` (Go `Up` failure). Carries the typed, actionable reason
    /// (permanent vs transient vs needs-login) — richer than Go's status blob.
    #[error("registration error: {0}")]
    Registration(#[from] RegistrationError),

    /// [`Server::control_url`] was set but is not a valid URL.
    #[error("invalid control URL: {0}")]
    InvalidControlUrl(url::ParseError),

    /// A Go-style `network, addr` string could not be parsed into a [`SocketAddr`].
    #[error("invalid address {addr:?}: {source}")]
    InvalidAddr {
        /// The offending address string.
        addr: String,
        /// The parse failure.
        source: std::net::AddrParseError,
    },

    /// The [`StateStore`] backing [`Server::dir`]/[`Server::store`] failed an I/O operation.
    #[error("state store I/O error: {0}")]
    Store(std::io::Error),

    /// The persisted node identity could not be (de)serialized.
    #[error("node identity (de)serialization error: {0}")]
    State(serde_json::Error),

    /// A [`Server::logout`] call failed.
    #[error("logout error: {0}")]
    Logout(#[from] crate::LogoutError),
}

// ---------------------------------------------------------------------------------------------
// Funnel / Service first-class types.
// ---------------------------------------------------------------------------------------------

/// Options for [`Server::listen_funnel`] — the Rust analog of Go's variadic `...FunnelOption`
/// (`FunnelOnly`, `FunnelTLSConfig`).
///
/// Go models funnel knobs as option functions; the Rust-idiomatic shape is one options value with
/// Go-named constructors. Build it with [`FunnelOptions::funnel_only`] / [`FunnelOptions::with_tls`]
/// or struct-literal syntax.
#[derive(Default)]
pub struct FunnelOptions {
    /// Reject tailnet-internal connections, serving *only* public Funnel ingress (Go `FunnelOnly()`).
    pub funnel_only: bool,

    /// Bring-your-own TLS termination (Go `FunnelTLSConfig(*tls.Config)`). `None` (the default) lets
    /// the engine terminate with the node's own `*.ts.net` certificate.
    ///
    /// **Engine gap (tracked).** The current engine [`Device::listen_funnel`](crate::Device::listen_funnel)
    /// always builds its own acceptor from the node cert and does not yet thread a caller-supplied
    /// one; a non-`None` value here is surfaced (a `warn!`) and otherwise ignored until the engine
    /// accepts an override. See `docs/TSNET_FACADE_DESIGN.md` §"Funnel".
    pub tls: Option<crate::TlsAcceptor>,
}

impl FunnelOptions {
    /// Go `FunnelOnly()` — serve only public Funnel ingress.
    pub fn funnel_only() -> Self {
        Self {
            funnel_only: true,
            ..Default::default()
        }
    }

    /// Go `FunnelTLSConfig(conf)` — supply the TLS acceptor to terminate Funnel ingress with.
    pub fn with_tls(mut self, acceptor: crate::TlsAcceptor) -> Self {
        self.tls = Some(acceptor);
        self
    }
}

impl From<FunnelOptions> for ts_control::FunnelOptions {
    fn from(o: FunnelOptions) -> Self {
        if o.tls.is_some() {
            tracing::warn!(
                "tsnet::FunnelOptions::tls (FunnelTLSConfig) is set but the engine terminates Funnel \
                 with the node's own certificate; the supplied acceptor is ignored (see design doc)"
            );
        }
        ts_control::FunnelOptions {
            funnel_only: o.funnel_only,
        }
    }
}

/// A listener for a hosted Tailscale VIP service, the Rust analog of Go's `*tsnet.ServiceListener`
/// (a `net.Listener` plus the service's `FQDN`).
///
/// Deref-forwards to the underlying overlay [`netstack::TcpListener`] so you can `.accept()` on it;
/// [`ServiceListener::fqdn`] adds the resolved fully-qualified service name.
pub struct ServiceListener {
    inner: netstack::TcpListener,
    fqdn: String,
}

impl ServiceListener {
    /// The fully-qualified domain name of the hosted service (Go `ServiceListener.FQDN`).
    pub fn fqdn(&self) -> &str {
        &self.fqdn
    }

    /// Consume the wrapper, yielding the underlying overlay listener.
    pub fn into_inner(self) -> netstack::TcpListener {
        self.inner
    }
}

impl std::ops::Deref for ServiceListener {
    type Target = netstack::TcpListener;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// The result of [`Server::loopback`] (Go `Loopback() (addr, proxyCred, localAPICred, err)`), minus
/// the second credential.
///
/// This fork's loopback serves the **SOCKS5** half with **one** credential; the in-process LocalAPI
/// HTTP server (and its `localAPICred`) is intentionally not served — the LocalClient surface lives
/// directly on [`Server`]/[`Device`] instead (see `docs/TSNET_PARITY.md` §5.1).
pub struct Loopback {
    /// The bound `127.0.0.1:<port>` address of the SOCKS5 proxy.
    pub address: SocketAddr,
    /// The SOCKS5 proxy credential (username is fixed to `"tsnet"`).
    pub proxy_cred: String,
    handle: crate::LoopbackHandle,
}

impl Loopback {
    /// Shut down the loopback proxy (the RAII handle also does this on drop).
    pub fn shutdown(self) {
        self.handle.shutdown()
    }
}

/// How to run the application overlay over a real kernel TUN interface (Go `Server.Tun`).
#[derive(Clone, Debug, Default)]
pub struct TunSpec {
    /// The desired interface name (`None` lets the OS pick, e.g. `utunN`).
    pub name: Option<String>,
    /// The interface MTU (`None` uses the transport default).
    pub mtu: Option<u16>,
}

// ---------------------------------------------------------------------------------------------
// Server — the facade.
// ---------------------------------------------------------------------------------------------

/// A hook to customize the derived [`Config`] after the field mapping and before the device is
/// built — the escape hatch to fork capabilities with no Go `tsnet` field. See [`Server::configure`].
pub type ConfigureHook = Box<dyn Fn(&mut Config) + Send + Sync>;

/// An embedded Tailscale node, shaped like Go's `tsnet.Server`.
///
/// Set the public fields (they map onto [`Config`]; see the table in `docs/TSNET_FACADE_DESIGN.md`),
/// then call any method — the wrapped [`Device`] is constructed lazily on the **first** method call
/// (Go: "fields may be changed until the first method call"). In Rust this ordering is enforced by
/// the borrow checker: methods borrow `&self`, so you cannot mutate a field after the first call.
///
/// For fork capabilities beyond Go `tsnet` parity (accept-routes, exit nodes, residential-proxy exit
/// egress, …), reach the underlying [`Config`] with [`Server::configure`], or drop to the full
/// engine surface with [`Server::device`].
#[derive(Default)]
pub struct Server {
    /// Hostname to present to control (Go `Hostname`) → [`Config::requested_hostname`]. Empty ⇒
    /// engine default.
    pub hostname: Option<String>,

    /// Auth key to register with (Go `AuthKey`) → [`Config::auth_key`] and the `auth_key` arg of
    /// [`Device::new`]. Falls back to `TS_AUTH_KEY`.
    pub auth_key: Option<String>,

    /// Coordination server URL (Go `ControlURL`) → [`Config::control_server_url`]. `None` ⇒ the
    /// fork's default control server.
    pub control_url: Option<String>,

    /// Register as an ephemeral node (Go `Ephemeral`) → [`Config::ephemeral`]. **Defaults to
    /// `false`** to match Go (note: bare [`Config::default`] defaults this to `true`).
    pub ephemeral: bool,

    /// ACL tags to advertise (Go `AdvertiseTags`) → [`Config::requested_tags`].
    pub advertise_tags: Vec<String>,

    /// WireGuard/peer-to-peer UDP port pin (Go `Port`) → [`Config::wireguard_listen_port`].
    pub port: Option<u16>,

    /// Run the node web client (Go `RunWebClient`) → [`Config::run_web_client`]. *Partial:* the pref
    /// is carried but no embedded web client runs (see `docs/TSNET_PARITY.md`).
    pub run_web_client: bool,

    /// OAuth/WIF client id (Go `ClientID`) → [`Config::client_id`].
    pub client_id: Option<String>,
    /// OAuth client secret (Go `ClientSecret`) → [`Config::client_secret`].
    pub client_secret: Option<String>,
    /// IdP-issued OIDC token (Go `IDToken`) → [`Config::id_token`].
    pub id_token: Option<String>,
    /// Audience for a requested ID token (Go `Audience`) → [`Config::audience`].
    pub audience: Option<String>,

    /// State directory (Go `Dir`). Persists node **identity keys** to `dir/`[`STATE_FILE`] via the
    /// engine's key-file format. Absent `store`, this is the standard on-disk identity.
    pub dir: Option<PathBuf>,

    /// A pluggable state store (Go `Store`). Takes precedence over [`Server::dir`]. `None` + no
    /// `dir` ⇒ an ephemeral in-memory identity (fresh every run).
    pub store: Option<Arc<dyn StateStore>>,

    /// Run over a real kernel TUN interface instead of the userspace netstack (Go `Tun`) →
    /// [`Config::use_tun`].
    pub tun: Option<TunSpec>,

    /// Optional hook to reach the full [`Config`] (fork supersets) after the field mapping and
    /// before [`Device::new`]. Set via [`Server::configure`].
    configure: Option<ConfigureHook>,

    /// The wrapped device, built once on first use.
    device: OnceCell<Device>,
}

impl Server {
    /// A new server with Go-default fields (not ephemeral, default control server, no persistence).
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a hook to customize the derived [`Config`] just before the device is built — the
    /// escape hatch to fork capabilities that have no Go `tsnet` field. Ignored if the server has
    /// already started.
    pub fn configure<F>(&mut self, f: F) -> &mut Self
    where
        F: Fn(&mut Config) + Send + Sync + 'static,
    {
        self.configure = Some(Box::new(f));
        self
    }

    /// Resolve the node identity [`PersistState`] from the configured store/dir, or `None` for an
    /// ephemeral in-memory identity.
    async fn resolve_key_state(&self) -> Result<Option<PersistState>, Error> {
        // Explicit custom store: round-trip the identity blob under STATE_KEY.
        if let Some(store) = &self.store {
            return match store.read_state(STATE_KEY).map_err(Error::Store)? {
                Some(bytes) => Ok(Some(serde_json::from_slice(&bytes).map_err(Error::State)?)),
                None => {
                    let fresh = PersistState::default();
                    let bytes = serde_json::to_vec(&fresh).map_err(Error::State)?;
                    store.write_state(STATE_KEY, &bytes).map_err(Error::Store)?;
                    Ok(Some(fresh))
                }
            };
        }
        // No store: `dir` is handled by reusing the engine key-file path in `build_config`.
        Ok(None)
    }

    /// Map the Go-`tsnet.Server`-parity fields onto a fresh [`Config`].
    async fn build_config(&self) -> Result<Config, Error> {
        // Base: reuse the engine's own key-file load-or-init when a `dir` is set and no custom store
        // is in play; otherwise start from `Config::default` and overlay any resolved identity.
        let mut config = match (&self.store, &self.dir) {
            (None, Some(dir)) => Config::default_with_key_file(dir.join(STATE_FILE)).await?,
            _ => {
                let mut c = Config::default();
                if let Some(ks) = self.resolve_key_state().await? {
                    c.key_state = ks;
                }
                c
            }
        };

        // Ephemeral defaults to Go's `false` here even though bare `Config::default` is `true`.
        config.ephemeral = self.ephemeral;
        config.requested_hostname = self.hostname.clone();
        config.requested_tags = self.advertise_tags.clone();
        config.wireguard_listen_port = self.port;
        config.run_web_client = self.run_web_client;
        config.auth_key = self.auth_key.clone();
        config.client_id = self.client_id.clone();
        config.client_secret = self.client_secret.clone();
        config.id_token = self.id_token.clone();
        config.audience = self.audience.clone();

        if let Some(raw) = &self.control_url {
            config.control_server_url = raw.parse().map_err(Error::InvalidControlUrl)?;
        }
        if let Some(tun) = &self.tun {
            config = config.use_tun(tun.name.clone(), tun.mtu);
        }
        if let Some(hook) = &self.configure {
            hook(&mut config);
        }
        Ok(config)
    }

    /// Build + start the wrapped device from the current fields.
    async fn build_and_start(&self) -> Result<Device, Error> {
        let config = self.build_config().await?;
        Ok(Device::new(&config, self.auth_key.clone()).await?)
    }

    /// Get the wrapped device, starting it on first call (Go's lazy `Start`).
    async fn started(&self) -> Result<&Device, Error> {
        self.device
            .get_or_try_init(|| self.build_and_start())
            .await
    }

    /// Connect to the tailnet (Go `Start`). Idempotent — subsequent calls are no-ops.
    pub async fn start(&self) -> Result<(), Error> {
        self.started().await.map(|_| ())
    }

    /// Connect and wait until the node is `Running`, returning its status (Go `Up`). `timeout`
    /// `None` waits forever.
    pub async fn up(&self, timeout: Option<Duration>) -> Result<Status, Error> {
        let dev = self.started().await?;
        dev.wait_until_running(timeout).await?;
        Ok(dev.status().await?)
    }

    /// The wrapped [`Device`] (Go `LocalClient`-and-more), starting it if needed. The escape hatch to
    /// the full engine surface (`whois`, `ping`, `set_*` prefs, taildrop, TKA, …).
    pub async fn device(&self) -> Result<&Device, Error> {
        self.started().await
    }

    /// Dial a tailnet address (Go `Dial`). `network` is `"tcp"`/`"udp"`; `addr` is `host:port`.
    pub async fn dial(&self, network: &str, addr: &str) -> Result<crate::DialConn, Error> {
        Ok(self.started().await?.dial(network, addr).await?)
    }

    /// Dial a tailnet TCP address, yielding the overlay stream.
    pub async fn dial_tcp(&self, addr: &str) -> Result<netstack::TcpStream, Error> {
        Ok(self.started().await?.dial_tcp(addr).await?)
    }

    /// Listen for inbound TCP on the tailnet (Go `Listen`). `addr` may be `":80"` (any host) or
    /// `"100.x.y.z:80"`.
    pub async fn listen(&self, _network: &str, addr: &str) -> Result<netstack::TcpListener, Error> {
        let sa = parse_socket_addr(addr)?;
        Ok(self.started().await?.tcp_listen(sa).await?)
    }

    /// Listen for inbound UDP on the tailnet (Go `ListenPacket`).
    pub async fn listen_packet(
        &self,
        network: &str,
        addr: &str,
    ) -> Result<netstack::UdpSocket, Error> {
        Ok(self.started().await?.listen_packet(network, addr).await?)
    }

    /// Expose a tailnet TLS service to the public internet via Tailscale Funnel (Go `ListenFunnel`).
    ///
    /// Keeps the fork's typed [`ts_control::FunnelError`] (fail-closed access gate + cert). `cfg`
    /// names the MagicDNS name + tailnet port; `opts` carries [`FunnelOptions`].
    pub async fn listen_funnel(
        &self,
        cfg: &crate::ServeConfig,
        opts: FunnelOptions,
    ) -> Result<ts_runtime::funnel::FunnelAcceptedReceiver, ts_control::FunnelError> {
        let dev = self
            .started()
            .await
            .map_err(|_| ts_control::FunnelError::NotAllowed)?;
        dev.listen_funnel(cfg, opts.into()).await
    }

    /// Host a Tailscale VIP service (Go `ListenService`), returning a Go-shaped [`ServiceListener`]
    /// (overlay listener + resolved FQDN). Keeps the fork's typed [`ServiceError`]
    /// (`UntaggedHost` == Go `ErrUntaggedServiceHost`).
    pub async fn listen_service(
        &self,
        name: &str,
        mode: ServiceMode,
    ) -> Result<ServiceListener, ServiceError> {
        let dev = self
            .started()
            .await
            .map_err(|e| ServiceError::Listen(format!("server failed to start: {e}")))?;
        let inner = dev.listen_service(name, mode).await?;
        let fqdn = dev
            .self_node()
            .await
            .map(|n| n.fqdn(false))
            .unwrap_or_default();
        Ok(ServiceListener { inner, fqdn })
    }

    /// Start a loopback SOCKS5 proxy onto the tailnet (Go `Loopback`).
    pub async fn loopback(&self) -> Result<Loopback, Error> {
        let (address, proxy_cred, handle) = self.started().await?.loopback().await?;
        Ok(Loopback {
            address,
            proxy_cred,
            handle,
        })
    }

    /// This node's tailnet addresses (Go `TailscaleIPs`). The tuple shape mirrors
    /// [`Device::tailscale_ips`](crate::Device::tailscale_ips) verbatim (v6 is `None` on an
    /// IPv4-only tailnet).
    pub async fn tailscale_ips(
        &self,
    ) -> Result<(std::net::Ipv4Addr, Option<std::net::Ipv6Addr>), Error> {
        Ok(self.started().await?.tailscale_ips().await?)
    }

    /// The cert domains for this node (Go `CertDomains`).
    pub async fn cert_domains(&self) -> Result<Vec<String>, Error> {
        Ok(self.started().await?.cert_domains().await?)
    }

    // --- folded LocalClient surface (Go `LocalClient().X`); the rest live on `Device`) ---

    /// Node + peer status (Go `LocalClient().Status`).
    pub async fn status(&self) -> Result<Status, Error> {
        Ok(self.started().await?.status().await?)
    }

    /// Log this node out (Go `LocalClient().Logout`).
    pub async fn logout(&self) -> Result<(), Error> {
        self.started().await?.logout().await?;
        Ok(())
    }

    /// Stop the server (Go `Close`). Consumes `self`; returns whether shutdown completed within
    /// `timeout` (`None` = wait forever). A never-started server closes cleanly.
    pub async fn close(self, timeout: Option<Duration>) -> bool {
        match self.device.into_inner() {
            Some(dev) => dev.shutdown(timeout).await,
            None => true,
        }
    }
}

/// Parse a Go-style listen address (`":80"` ⇒ `0.0.0.0:80`, or a full `ip:port`).
fn parse_socket_addr(addr: &str) -> Result<SocketAddr, Error> {
    let normalized = if addr.starts_with(':') {
        format!("0.0.0.0{addr}")
    } else {
        addr.to_string()
    };
    normalized.parse().map_err(|source| Error::InvalidAddr {
        addr: addr.to_string(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_colon_port_is_unspecified_host() {
        let sa = parse_socket_addr(":8080").unwrap();
        assert!(sa.ip().is_unspecified());
        assert_eq!(sa.port(), 8080);
    }

    #[test]
    fn parse_full_addr() {
        let sa = parse_socket_addr("100.64.0.1:443").unwrap();
        assert_eq!(sa.port(), 443);
        assert_eq!(sa.ip().to_string(), "100.64.0.1");
    }

    #[test]
    fn parse_bad_addr_is_typed_error() {
        let err = parse_socket_addr("not-an-addr").unwrap_err();
        assert!(matches!(err, Error::InvalidAddr { .. }));
    }

    #[test]
    fn server_default_is_go_shaped() {
        // Go's zero-value Server is not ephemeral and has no persistence.
        let s = Server::new();
        assert!(!s.ephemeral);
        assert!(s.dir.is_none());
        assert!(s.store.is_none());
        assert!(s.hostname.is_none());
    }

    #[test]
    fn mem_store_round_trips() {
        let store = MemStore::default();
        assert!(store.read_state(STATE_KEY).unwrap().is_none());
        store.write_state(STATE_KEY, b"blob").unwrap();
        assert_eq!(store.read_state(STATE_KEY).unwrap().as_deref(), Some(&b"blob"[..]));
    }

    #[test]
    fn funnel_options_map_to_engine() {
        let engine: ts_control::FunnelOptions = FunnelOptions::funnel_only().into();
        assert!(engine.funnel_only);
    }

    #[test]
    fn documented_construction_idiom_compiles() {
        // Mirrors docs/TSNET_FACADE_DESIGN.md §13: `Server::new()` + per-field assignment on the
        // public fields (the private lazy-state fields do not block this), plus the `configure`
        // escape hatch and a custom `store`. If this compiles, the documented idiom is valid.
        let mut srv = Server::new();
        srv.hostname = Some("web".into());
        srv.auth_key = Some("tskey-xxxx".into());
        srv.dir = Some("/var/lib/web".into());
        srv.ephemeral = false;
        srv.advertise_tags = vec!["tag:web".into()];
        srv.port = Some(41641);
        srv.configure(|c| c.accept_routes = true);
        srv.store = Some(Arc::new(MemStore::default()));
        assert_eq!(srv.hostname.as_deref(), Some("web"));
        assert!(!srv.ephemeral);
        assert!(srv.store.is_some());
        assert!(srv.configure.is_some());
    }

    // Compile-time assertion: a shared server must be usable across tasks (Arc<Server> + Send/Sync),
    // which requires the wrapped Device to be Send + Sync.
    fn _assert_send_sync<T: Send + Sync>() {}
    #[allow(dead_code)]
    fn _server_is_send_sync() {
        _assert_send_sync::<Server>();
    }

    // -----------------------------------------------------------------------------------------
    // Config surface: the Go-named `Server` fields → `Config` mapping (docs/TSNET_FACADE_DESIGN.md
    // §5) and the `Dir`/`Store` state-root shim over `Config::key_state` (§8). These exercise the
    // private async `build_config` directly (same-module access), so the field translation and the
    // identity round-trip are *asserted*, not merely compiled.
    // -----------------------------------------------------------------------------------------

    /// A unique, empty scratch dir for an on-disk state test. The facade adds **no** `tempfile`
    /// dependency (the zero-new-dep constraint), so this rolls its own: namespaced by pid + a
    /// per-test label (concurrent test binaries never collide) and wiped up front so a stale run
    /// can't mask a bug.
    fn scratch_dir(label: &str) -> PathBuf {
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("tsnet-rs-test-{pid}-{label}"));
        std::fs::remove_dir_all(&dir).ok();
        dir
    }

    #[tokio::test]
    async fn build_config_maps_every_go_field_onto_config() {
        // Every Go-parity field set to a non-default; assert build_config copies each onto the
        // matching Config field — the §5 mapping table, row by row.
        let mut srv = Server::new();
        srv.hostname = Some("web".into());
        srv.auth_key = Some("tskey-auth-xxxx".into());
        srv.control_url = Some("https://control.example.com".into());
        srv.ephemeral = false;
        srv.advertise_tags = vec!["tag:web".into(), "tag:prod".into()];
        srv.port = Some(41641);
        srv.run_web_client = true;
        srv.client_id = Some("cid".into());
        srv.client_secret = Some("csecret".into());
        srv.id_token = Some("idtok".into());
        srv.audience = Some("aud".into());

        let cfg = srv.build_config().await.unwrap();

        assert_eq!(cfg.requested_hostname.as_deref(), Some("web"));
        assert_eq!(cfg.auth_key.as_deref(), Some("tskey-auth-xxxx"));
        assert_eq!(cfg.control_server_url.scheme(), "https");
        assert_eq!(cfg.control_server_url.host_str(), Some("control.example.com"));
        assert_eq!(
            cfg.requested_tags,
            vec!["tag:web".to_string(), "tag:prod".to_string()]
        );
        assert_eq!(cfg.wireguard_listen_port, Some(41641));
        assert!(cfg.run_web_client);
        assert_eq!(cfg.client_id.as_deref(), Some("cid"));
        assert_eq!(cfg.client_secret.as_deref(), Some("csecret"));
        assert_eq!(cfg.id_token.as_deref(), Some("idtok"));
        assert_eq!(cfg.audience.as_deref(), Some("aud"));
        // Tun unset ⇒ the default userspace netstack transport is preserved.
        assert_eq!(cfg.transport_mode, crate::TransportMode::Netstack);
    }

    #[tokio::test]
    async fn build_config_forces_go_default_ephemeral() {
        // Go's zero-value Server is a *persistent* node, yet a bare Config::default() is ephemeral.
        // build_config must force Go's default by always writing config.ephemeral = self.ephemeral.
        assert!(
            Config::default().ephemeral,
            "precondition: a bare Config defaults to ephemeral=true"
        );
        let cfg = Server::new().build_config().await.unwrap();
        assert!(
            !cfg.ephemeral,
            "a default tsnet::Server maps to a non-ephemeral Config (Go parity)"
        );

        // …and an explicit opt-in is honored.
        let mut srv = Server::new();
        srv.ephemeral = true;
        assert!(srv.build_config().await.unwrap().ephemeral);
    }

    #[tokio::test]
    async fn build_config_none_control_url_keeps_engine_default() {
        let cfg = Server::new().build_config().await.unwrap();
        assert_eq!(cfg.control_server_url, Config::default().control_server_url);
    }

    #[tokio::test]
    async fn build_config_rejects_a_bad_control_url() {
        let mut srv = Server::new();
        srv.control_url = Some("not a url".into());
        // `Config` isn't `Debug`, so match on the result rather than `unwrap_err()`.
        assert!(matches!(
            srv.build_config().await,
            Err(Error::InvalidControlUrl(_))
        ));
    }

    #[tokio::test]
    async fn build_config_tun_selects_kernel_tun_transport() {
        let mut srv = Server::new();
        srv.tun = Some(TunSpec {
            name: Some("tailscale0".into()),
            mtu: Some(1280),
        });
        let cfg = srv.build_config().await.unwrap();
        assert_eq!(
            cfg.transport_mode,
            crate::TransportMode::Tun(crate::TunConfig {
                name: Some("tailscale0".into()),
                mtu: Some(1280),
            })
        );
    }

    #[tokio::test]
    async fn build_config_runs_configure_hook_after_mapping() {
        // The escape hatch reaches fork-superset Config knobs that have no Go tsnet field, and runs
        // after the field mapping — so both the hook's writes and the mapped fields are present.
        let mut srv = Server::new();
        srv.hostname = Some("exit".into());
        srv.configure(|c| {
            c.advertise_exit_node = true;
            c.accept_routes = true;
        });
        let cfg = srv.build_config().await.unwrap();
        assert!(cfg.advertise_exit_node);
        assert!(cfg.accept_routes);
        assert_eq!(cfg.requested_hostname.as_deref(), Some("exit"));
    }

    #[test]
    fn file_store_round_trips_on_disk() {
        // The on-disk StateStore (Go store.FileStore): write-then-read, and a fresh store over the
        // same dir still sees the value (identity survives a process restart).
        let dir = scratch_dir("filestore");
        let store = FileStore::new(dir.clone());
        assert!(
            store.read_state(STATE_KEY).unwrap().is_none(),
            "never-written ⇒ None (a missing file is not an error)"
        );
        store.write_state(STATE_KEY, b"identity-blob").unwrap();
        assert!(
            dir.join(STATE_FILE).exists(),
            "FileStore::new persists under dir/STATE_FILE"
        );
        assert_eq!(
            store.read_state(STATE_KEY).unwrap().as_deref(),
            Some(&b"identity-blob"[..])
        );
        assert_eq!(
            FileStore::new(dir.clone())
                .read_state(STATE_KEY)
                .unwrap()
                .as_deref(),
            Some(&b"identity-blob"[..]),
            "a fresh FileStore over the same dir reloads the persisted value"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn file_store_at_writes_the_exact_path() {
        let dir = scratch_dir("filestore-at");
        let path = dir.join("custom.state");
        FileStore::at(path.clone())
            .write_state(STATE_KEY, b"x")
            .unwrap();
        assert!(path.exists(), "FileStore::at writes to the exact path given");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn dir_persists_node_identity_across_builds() {
        // The headline `Dir` shim over Config::key_state (§8): a Dir-rooted node writes the engine
        // key file once and reloads the SAME identity on the next boot, instead of re-minting.
        let dir = scratch_dir("dir-state-root");

        let mut srv = Server::new();
        srv.dir = Some(dir.clone());
        let cfg1 = srv.build_config().await.unwrap();
        assert!(
            dir.join(STATE_FILE).exists(),
            "Dir persists identity to dir/STATE_FILE via the engine key-file format"
        );

        let mut srv2 = Server::new();
        srv2.dir = Some(dir.clone());
        let cfg2 = srv2.build_config().await.unwrap();
        assert_eq!(
            serde_json::to_vec(&cfg1.key_state).unwrap(),
            serde_json::to_vec(&cfg2.key_state).unwrap(),
            "a Dir-rooted node reloads a stable identity rather than re-minting each boot"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn custom_store_round_trips_identity_through_build_config() {
        // A custom StateStore is the pluggable backend (Go ipn.StateStore): build_config mints and
        // writes the identity blob under STATE_KEY, and a second server on the same store reloads it.
        let store: Arc<dyn StateStore> = Arc::new(MemStore::default());

        let mut srv = Server::new();
        srv.store = Some(store.clone());
        let cfg1 = srv.build_config().await.unwrap();
        assert!(
            store.read_state(STATE_KEY).unwrap().is_some(),
            "the store now holds the minted identity blob"
        );

        let mut srv2 = Server::new();
        srv2.store = Some(store.clone());
        let cfg2 = srv2.build_config().await.unwrap();
        assert_eq!(
            serde_json::to_vec(&cfg1.key_state).unwrap(),
            serde_json::to_vec(&cfg2.key_state).unwrap(),
            "a shared store yields a stable identity across servers"
        );
    }

    #[tokio::test]
    async fn store_takes_precedence_over_dir() {
        // §8 resolution order: an explicit `store` wins over `dir`. The identity lands in the store
        // and the Dir key file is never written.
        let dir = scratch_dir("store-precedence");
        let store: Arc<dyn StateStore> = Arc::new(MemStore::default());

        let mut srv = Server::new();
        srv.dir = Some(dir.clone());
        srv.store = Some(store.clone());
        srv.build_config().await.unwrap();

        assert!(store.read_state(STATE_KEY).unwrap().is_some());
        assert!(
            !dir.join(STATE_FILE).exists(),
            "store must take precedence over dir (design §8)"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    // --- focused lifecycle tests: start / up / close over
    //     Device::new → wait_until_running → status → shutdown ---
    //
    // The *successful* round-trip needs a live control server, so it stays in integration/e2e. The
    // hermetic, unit-testable half of the lifecycle is its fail-fast and no-op behavior: the lazy
    // build shared by `start`/`up` runs `build_config` *before* `Device::new`, so a bad config is
    // reported without any network I/O; and `close` on a server whose `OnceCell` never initialized
    // is a clean no-op. (The field→`Config` mapping itself is covered by the tests above.)

    #[tokio::test]
    async fn close_on_never_started_server_is_clean() {
        // Go `Close()` before any method call: the `OnceCell` is empty, so there is no `Device` to
        // `shutdown` and it reports success immediately (the `None => true` arm) — for both an
        // unbounded and a finite timeout.
        assert!(Server::new().close(None).await);
        assert!(Server::new().close(Some(Duration::from_millis(1))).await);
    }

    #[tokio::test]
    async fn start_fails_fast_on_bad_config_before_touching_the_network() {
        // `start` maps the fields onto a `Config` and only then calls `Device::new`; a bad
        // `control_url` fails in that mapping, so it surfaces as the typed `InvalidControlUrl` with
        // no network I/O — never a hang, never a panic. (`Config`/`Status` aren't `Debug`, so match
        // on the result rather than `unwrap`.)
        let mut s = Server::new();
        s.control_url = Some("not a url".into());
        assert!(matches!(s.start().await, Err(Error::InvalidControlUrl(_))));
    }

    #[tokio::test]
    async fn up_fails_fast_on_bad_config() {
        // `up` shares the same lazy-build entrypoint as `start`, so it fails fast on a bad config
        // instead of blocking in `wait_until_running`.
        let mut s = Server::new();
        s.control_url = Some("not a url".into());
        assert!(matches!(s.up(None).await, Err(Error::InvalidControlUrl(_))));
    }

    #[tokio::test]
    async fn close_is_clean_after_a_failed_start() {
        // A failed lazy start leaves the `OnceCell` uninitialized (`get_or_try_init` stores nothing
        // on error), so a subsequent `close` still finds no `Device` and returns cleanly.
        let mut s = Server::new();
        s.control_url = Some("not a url".into());
        assert!(matches!(s.start().await, Err(Error::InvalidControlUrl(_))));
        assert!(s.close(None).await);
    }
}
