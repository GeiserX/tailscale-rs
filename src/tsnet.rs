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
use std::sync::{Arc, Weak};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::OnceCell;
use tokio::task::AbortHandle;
use ts_keys::PersistState;

use crate::config::Config;
use crate::netstack;
use crate::{Device, RegistrationError, ServiceError, ServiceMode, Status, StatusNode};

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

    /// The loopback proxy / in-process LocalAPI HTTP server hit an I/O error (binding its
    /// `127.0.0.1` listener, or a [`LocalClient`] request to it).
    #[error("loopback I/O error: {0}")]
    Loopback(std::io::Error),
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

/// The result of [`Server::loopback`] — the full Go `Loopback() (addr, proxyCred, localAPICred,
/// err)` surface: **both** credentials, and an in-process LocalAPI HTTP server actually running.
///
/// # Go parity, and the one honest delta
///
/// Go serves the SOCKS5 proxy *and* the LocalAPI on a **single** muxed loopback listener. This fork
/// runs two `127.0.0.1` listeners instead — [`address`](Self::address) for the SOCKS5 proxy
/// ([`proxy_cred`](Self::proxy_cred)) and [`local_api_address`](Self::local_api_address) for the
/// LocalAPI HTTP server ([`local_api_cred`](Self::local_api_cred)) — because the SOCKS5 half is the
/// engine's own [`Device::loopback`](crate::Device::loopback) and the LocalAPI half is layered on
/// top without re-implementing (or first-byte-demuxing) the proven proxy path. The observable
/// contract is identical: a SOCKS5 proxy gated by `proxy_cred`, and a LocalAPI gated by
/// `local_api_cred`. This delta is surfaced, not faked (see `docs/TSNET_FACADE_DESIGN.md` §11).
///
/// # Lifecycle
///
/// Like Go's `s.loopbackListener`, both listeners live for the [`Server`]'s lifetime and are torn
/// down by [`Server::close`] — [`Server::loopback`] is idempotent and returns the same addresses and
/// credentials on every call. There is no per-result handle to drop.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Loopback {
    /// The bound `127.0.0.1:<port>` address of the SOCKS5 proxy (Go's `addr`, SOCKS5 half).
    pub address: SocketAddr,
    /// The SOCKS5 proxy credential (Go's `proxyCred`; username is fixed to `"tsnet"`).
    pub proxy_cred: String,
    /// The bound `127.0.0.1:<port>` address of the in-process LocalAPI HTTP server.
    pub local_api_address: SocketAddr,
    /// The LocalAPI credential (Go's `localAPICred`): the HTTP Basic-auth **password** the LocalAPI
    /// server requires (any username is accepted, matching Go). Reach it with [`LocalClient`].
    pub local_api_cred: String,
}

/// A minimal client for the in-process LocalAPI HTTP server started alongside the loopback proxy —
/// the Rust analog of what Go's `tsnet.Server.LocalClient()` returns (a `*local.Client` wired to the
/// node's own LocalAPI).
///
/// Obtain one with [`Server::local_client`]. It authenticates every request with the loopback's
/// `local_api_cred` (HTTP Basic auth, empty username) and speaks plain HTTP to `127.0.0.1`, so it is
/// dependency-free (no `hyper`) and needs only the `tsnet` feature.
///
/// The fork's [`Status`](crate::Status) is not a `serde` type, so [`status`](Self::status) returns
/// the server's raw JSON bytes rather than a deserialized struct; for typed status prefer
/// [`Server::status`] (the in-process path). For arbitrary endpoints use [`get`](Self::get).
#[derive(Clone, Debug)]
pub struct LocalClient {
    address: SocketAddr,
    cred: String,
}

impl LocalClient {
    /// The `127.0.0.1:<port>` address of the LocalAPI HTTP server this client talks to.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// The LocalAPI credential (HTTP Basic-auth password) this client sends.
    pub fn credential(&self) -> &str {
        &self.cred
    }

    /// `GET /localapi/v0/status` — the node + peer status as raw JSON bytes (Go
    /// `LocalClient().Status`, over the loopback). Errors if the server answers non-`200`.
    pub async fn status(&self) -> Result<Vec<u8>, Error> {
        match self.get("/localapi/v0/status").await? {
            (200, body) => Ok(body),
            (code, _) => Err(Error::Loopback(std::io::Error::other(format!(
                "localapi /status returned HTTP {code}"
            )))),
        }
    }

    /// Perform an authenticated `GET` against an arbitrary LocalAPI `path` (e.g.
    /// `"/localapi/v0/status"`), returning `(http_status_code, body_bytes)`.
    pub async fn get(&self, path: &str) -> Result<(u16, Vec<u8>), Error> {
        localapi_client_get(self.address, &self.cred, path)
            .await
            .map_err(Error::Loopback)
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

    /// The wrapped device, built once on first use. Held in an [`Arc`] so the in-process LocalAPI
    /// HTTP server (spawned by [`Server::loopback`]) can hold a [`Weak`] handle to it without
    /// blocking [`Server::close`] from reclaiming and gracefully shutting the device down.
    device: OnceCell<Arc<Device>>,

    /// The running loopback SOCKS5 proxy + in-process LocalAPI HTTP server, started once on the
    /// first [`Server::loopback`]/[`Server::local_client`] and torn down on [`Server::close`]
    /// (mirrors Go's `s.loopbackListener` living for the server's lifetime).
    loopback_rt: OnceCell<LoopbackRt>,
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
    async fn build_and_start(&self) -> Result<Arc<Device>, Error> {
        let config = self.build_config().await?;
        Ok(Arc::new(Device::new(&config, self.auth_key.clone()).await?))
    }

    /// Get the wrapped device (as the shared [`Arc`]), starting it on first call (Go's lazy
    /// `Start`).
    async fn started(&self) -> Result<&Arc<Device>, Error> {
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
        Ok(&**self.started().await?)
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

    /// Start (once) the loopback surface and return its addresses + both credentials (Go
    /// `Loopback() (addr, proxyCred, localAPICred, err)`).
    ///
    /// Brings up two things, living for the [`Server`]'s lifetime (torn down by [`Server::close`]):
    ///
    /// * a **SOCKS5 proxy** onto the tailnet (the engine's [`Device::loopback`](crate::Device::loopback)),
    ///   authenticated with [`Loopback::proxy_cred`]; and
    /// * an **in-process LocalAPI HTTP server** authenticated with the separate
    ///   [`Loopback::local_api_cred`] (HTTP Basic-auth password), serving `GET
    ///   /localapi/v0/status`.
    ///
    /// Idempotent: repeated calls return the same addresses and credentials. See [`Loopback`] for
    /// the one honest delta from Go (two `127.0.0.1` listeners rather than one muxed listener).
    pub async fn loopback(&self) -> Result<Loopback, Error> {
        let rt = self.ensure_loopback().await?;
        Ok(Loopback {
            address: rt.socks_address,
            proxy_cred: rt.proxy_cred.clone(),
            local_api_address: rt.local_api_address,
            local_api_cred: rt.local_api_cred.clone(),
        })
    }

    /// A [`LocalClient`] for this node's in-process LocalAPI HTTP server (Go
    /// `tsnet.Server.LocalClient()`), starting the loopback surface if needed.
    ///
    /// The returned client authenticates with the loopback's `local_api_cred` and speaks plain HTTP
    /// to `127.0.0.1` (no `hyper` dependency). For typed status prefer the in-process [`Server::status`];
    /// the `LocalClient` is the Go-shaped path that actually round-trips through the LocalAPI server.
    pub async fn local_client(&self) -> Result<LocalClient, Error> {
        let rt = self.ensure_loopback().await?;
        Ok(LocalClient {
            address: rt.local_api_address,
            cred: rt.local_api_cred.clone(),
        })
    }

    /// Start (once) and cache the loopback runtime: the engine SOCKS5 proxy plus a facade-owned
    /// in-process LocalAPI HTTP server on its own `127.0.0.1` listener.
    async fn ensure_loopback(&self) -> Result<&LoopbackRt, Error> {
        // Capture the device Arc first (outside the closure) so we can downgrade it to a `Weak` for
        // the LocalAPI backend — the server must not keep the device alive past `Server::close`.
        let device = self.started().await?.clone();
        self.loopback_rt
            .get_or_try_init(|| build_loopback_rt(device))
            .await
    }

    /// A `hyper` HTTP client whose every request egresses over the tailnet (Go
    /// `tsnet.Server.HTTPClient()`), built over [`Device::http_connector`](crate::Device::http_connector).
    ///
    /// The exact analog of Go's `&http.Client{Transport: &http.Transport{DialContext: s.Dial}}`: a
    /// pooled [`hyper_util`] client wired to the tailnet connector, with TLS/redirects/pooling left
    /// to the client (the connector is plaintext — see [`TailnetConnector`](crate::http::TailnetConnector)
    /// for wrapping it in TLS). `B` is your request body type (e.g. `String`, or
    /// `http_body_util::Full<Bytes>`).
    ///
    /// Available only with the **`hyper`** crate feature (as in the engine).
    #[cfg(feature = "hyper")]
    pub async fn http_client<B>(
        &self,
    ) -> Result<hyper_util::client::legacy::Client<crate::http::TailnetConnector, B>, Error>
    where
        B: hyper::body::Body + Send + 'static,
        B::Data: Send,
    {
        let connector = self.started().await?.http_connector().await?;
        Ok(
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(connector),
        )
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
    ///
    /// Tears down the loopback surface first (aborting the SOCKS5 and LocalAPI accept loops), then
    /// gracefully shuts the wrapped device down. The LocalAPI server holds only a [`Weak`] to the
    /// device, so this reclaims the sole strong reference for the graceful shutdown.
    pub async fn close(self, timeout: Option<Duration>) -> bool {
        // Abort the SOCKS5 + LocalAPI accept loops (and drop their `Weak` device refs) before
        // reclaiming the device by value.
        drop(self.loopback_rt);
        match self.device.into_inner() {
            None => true,
            Some(arc) => match Arc::into_inner(arc) {
                Some(dev) => dev.shutdown(timeout).await,
                // A LocalAPI request raced `close` and briefly holds the last strong ref; it is
                // released the instant that request returns, and the device tears down then — we
                // just could not reclaim it by value for a graceful shutdown.
                None => false,
            },
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Loopback runtime: the engine SOCKS5 proxy + the facade's in-process LocalAPI HTTP server.
// ---------------------------------------------------------------------------------------------

/// The running loopback surface, cached on [`Server`] and torn down on [`Server::close`].
struct LoopbackRt {
    socks_address: SocketAddr,
    proxy_cred: String,
    local_api_address: SocketAddr,
    local_api_cred: String,
    /// Aborts the engine SOCKS5 accept loop on drop (RAII).
    _socks_handle: crate::LoopbackHandle,
    /// Aborts the in-process LocalAPI accept loop on drop (via the [`Drop`] impl below).
    localapi_task: AbortHandle,
}

impl Drop for LoopbackRt {
    fn drop(&mut self) {
        // Stop accepting new LocalAPI connections. In-flight requests hold only a `Weak<Device>` and
        // finish on their own. (`_socks_handle` aborts the SOCKS5 loop via its own `Drop`.)
        self.localapi_task.abort();
    }
}

/// Build the loopback runtime: start the engine SOCKS5 proxy, bind a second `127.0.0.1` listener for
/// the LocalAPI, mint a *separate* credential, and spawn the in-process LocalAPI HTTP server backed
/// by a [`Weak`] handle to `device`.
async fn build_loopback_rt(device: Arc<Device>) -> Result<LoopbackRt, Error> {
    // SOCKS5 half — the engine's own loopback (address + proxy_cred + RAII handle), unchanged.
    let (socks_address, proxy_cred, socks_handle) = device.loopback().await?;

    // LocalAPI half — a facade-owned HTTP server on its own host-loopback listener.
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(Error::Loopback)?;
    let local_api_address = listener.local_addr().map_err(Error::Loopback)?;
    let local_api_cred = gen_cred();

    // Backend: a `Weak<Device>` so the spawned server never blocks `Server::close` from reclaiming
    // the device by value. Each request upgrades it just long enough to read status.
    let weak: Weak<Device> = Arc::downgrade(&device);
    let status: localapi::StatusFn = Arc::new(move || {
        let weak = weak.clone();
        Box::pin(async move {
            match weak.upgrade() {
                Some(dev) => dev
                    .status()
                    .await
                    .map(|s| status_json(&s))
                    .map_err(|e| e.to_string()),
                None => Err("device has shut down".to_string()),
            }
        })
    });

    let task = tokio::spawn(localapi::serve(listener, local_api_cred.clone(), status));

    Ok(LoopbackRt {
        socks_address,
        proxy_cred,
        local_api_address,
        local_api_cred,
        _socks_handle: socks_handle,
        localapi_task: task.abort_handle(),
    })
}

/// Generate a 16-byte random credential rendered as 32 lowercase-hex chars (Go uses
/// `hex.EncodeToString(crand[16])`; no new dependency — reuses `rand`, like the SOCKS5 half).
fn gen_cred() -> String {
    let bytes: [u8; 16] = rand::random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Serialize a [`StatusNode`] into a JSON value using explicit conversions (the fork's status types
/// are not `serde` types, and their field crates don't enable serde features here).
fn status_node_json(n: &StatusNode) -> serde_json::Value {
    serde_json::json!({
        "stable_id": n.stable_id.0,
        "display_name": n.display_name,
        "ipv4": n.ipv4.to_string(),
        "ipv6": n.ipv6.to_string(),
        "online": n.online,
        // Unix seconds — a feature-free encoding (chrono is `default-features = false` here, so the
        // `to_rfc3339`/`Display` formatters are unavailable; `timestamp()` is always present).
        "last_seen": n.last_seen.map(|t| t.timestamp()),
        "allowed_routes": n.allowed_routes.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
        "is_exit_node": n.is_exit_node,
        "cur_addr": n.cur_addr.map(|a| a.to_string()),
        "relay": n.relay,
        "ssh_host_keys": n.ssh_host_keys,
    })
}

/// Serialize a [`Status`] snapshot into the LocalAPI `/status` JSON body.
fn status_json(s: &Status) -> Vec<u8> {
    let value = serde_json::json!({
        "self": s.self_node.as_ref().map(status_node_json),
        "peers": s.peers.iter().map(status_node_json).collect::<Vec<_>>(),
        "active_exit_node": s.active_exit_node.as_ref().map(|id| id.0.clone()),
        "magic_dns_suffix": s.magic_dns_suffix,
    });
    serde_json::to_vec(&value).unwrap_or_else(|_| b"{}".to_vec())
}

/// Find the first occurrence of `needle` in `hay` (splits an HTTP head from its body — no dep).
fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Parse an HTTP/1.x response into `(status_code, body_bytes)`. Used by [`LocalClient`].
fn parse_response(resp: &[u8]) -> Option<(u16, Vec<u8>)> {
    let head_end = find_subslice(resp, b"\r\n\r\n")?;
    let head = std::str::from_utf8(&resp[..head_end]).ok()?;
    let status_line = head.split("\r\n").next()?;
    // "HTTP/1.1 200 OK" — the status code is the second whitespace-separated token.
    let code: u16 = status_line.split_whitespace().nth(1)?.parse().ok()?;
    Some((code, resp[head_end + 4..].to_vec()))
}

/// Perform an authenticated LocalAPI `GET` over plain HTTP to `127.0.0.1` (dependency-free client).
async fn localapi_client_get(
    addr: SocketAddr,
    cred: &str,
    path: &str,
) -> std::io::Result<(u16, Vec<u8>)> {
    let mut sock = TcpStream::connect(addr).await?;
    // HTTP Basic auth with an empty username (Go ignores the username; the password is the cred).
    let auth = STANDARD.encode(format!(":{cred}"));
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic {auth}\r\nConnection: close\r\n\r\n"
    );
    sock.write_all(req.as_bytes()).await?;
    // The server replies with `Connection: close`, so reading to EOF yields the whole response.
    let mut resp = Vec::new();
    sock.read_to_end(&mut resp).await?;
    parse_response(&resp).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed HTTP response")
    })
}

/// The in-process LocalAPI HTTP server (Go's `localapi.Handler` served on the loopback). A minimal,
/// dependency-free HTTP/1.1 server: the crate's `hyper` is HTTP/2-**client**-only, so this hand-rolls
/// request framing exactly as the SOCKS5 half hand-rolls its own protocol in `src/loopback.rs`.
mod localapi {
    use super::{Duration, STANDARD, TcpListener, TcpStream, find_subslice};
    use base64::Engine as _;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::sync::Semaphore;

    /// Upper bound on the buffered HTTP request head (request line + headers). LocalAPI requests are
    /// tiny; a client that floods the head is rejected rather than buffered unbounded.
    const MAX_HEAD: usize = 8 * 1024;
    /// Deadline for reading a full request head and writing the response.
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
    /// Cap on concurrent LocalAPI connections (loopback-only, but bounded for hygiene).
    const MAX_CONCURRENT: usize = 64;

    /// A cloneable, `'static` async backend for `GET /localapi/v0/status`: returns the JSON body
    /// bytes, or an error string mapped to HTTP 500. Boxed so tests can inject a mock backend
    /// without a live [`Device`](crate::Device).
    pub(super) type StatusFn =
        Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send>> + Send + Sync>;

    /// Serve the LocalAPI on `listener` until the task is aborted (by [`super::LoopbackRt`]'s drop).
    pub(super) async fn serve(listener: TcpListener, cred: String, status: StatusFn) {
        let sem = Arc::new(Semaphore::new(MAX_CONCURRENT));
        loop {
            // Back-pressure at the cap: acquire before accepting.
            let permit = match sem.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => return,
            };
            let (sock, _peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!(error = %e, "loopback LocalAPI accept failed; stopping accept loop");
                    return;
                }
            };
            let cred = cred.clone();
            let status = status.clone();
            tokio::spawn(async move {
                let _permit = permit;
                match tokio::time::timeout(REQUEST_TIMEOUT, handle(sock, &cred, &status)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => tracing::debug!(error = %e, "loopback LocalAPI connection ended"),
                    Err(_) => tracing::debug!("loopback LocalAPI request timed out"),
                }
            });
        }
    }

    /// Serve one LocalAPI connection: read the head, authenticate, route, respond, close.
    async fn handle(mut sock: TcpStream, cred: &str, status: &StatusFn) -> std::io::Result<()> {
        // Read up to the end of the header block (CRLF CRLF), capped.
        let mut buf = Vec::with_capacity(1024);
        let mut chunk = [0u8; 1024];
        let head_len = loop {
            if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                break pos;
            }
            if buf.len() > MAX_HEAD {
                let r = response(
                    431,
                    "Request Header Fields Too Large",
                    "text/plain",
                    b"header too large",
                    &[],
                );
                sock.write_all(&r).await?;
                return Ok(());
            }
            let n = sock.read(&mut chunk).await?;
            if n == 0 {
                return Ok(()); // client closed before sending a full head
            }
            buf.extend_from_slice(&chunk[..n]);
        };

        let Some((method, target, password)) = parse_head(&buf[..head_len]) else {
            let r = response(400, "Bad Request", "text/plain", b"bad request", &[]);
            sock.write_all(&r).await?;
            return Ok(());
        };

        // Auth: the Basic-auth password must equal the cred (any username, matching Go).
        if !password.as_deref().is_some_and(|p| cred_ok(p, cred)) {
            let r = response(
                401,
                "Unauthorized",
                "text/plain",
                b"unauthorized",
                &[("WWW-Authenticate", "Basic realm=\"tailscale localapi\"")],
            );
            sock.write_all(&r).await?;
            return Ok(());
        }

        // Route on method + path (any query string is ignored).
        let path = target.split('?').next().unwrap_or(&target);
        let resp = match (method.as_str(), path) {
            ("GET", "/localapi/v0/status") => match status().await {
                Ok(body) => response(200, "OK", "application/json", &body, &[]),
                Err(_) => response(
                    500,
                    "Internal Server Error",
                    "text/plain",
                    b"status error",
                    &[],
                ),
            },
            _ => response(404, "Not Found", "text/plain", b"not found", &[]),
        };
        sock.write_all(&resp).await?;
        Ok(())
    }

    /// Parse an HTTP request head into `(method, request_target, basic_auth_password)`. `None` when
    /// the request line is malformed.
    pub(super) fn parse_head(head: &[u8]) -> Option<(String, String, Option<String>)> {
        let text = std::str::from_utf8(head).ok()?;
        let mut lines = text.split("\r\n");
        let mut request_line = lines.next()?.split(' ');
        let method = request_line.next()?.to_string();
        let target = request_line.next()?.to_string();
        request_line.next()?; // require the HTTP-version token
        let mut password = None;
        for line in lines {
            if let Some((name, value)) = line.split_once(':')
                && name.trim().eq_ignore_ascii_case("authorization")
            {
                password = basic_auth_password(value.trim());
            }
        }
        Some((method, target, password))
    }

    /// Decode `Basic <base64(user:pass)>` into the password (Go ignores the username). `None` if the
    /// header is not Basic auth or is malformed.
    pub(super) fn basic_auth_password(value: &str) -> Option<String> {
        // The auth scheme is case-insensitive (RFC 7617; Go's `r.BasicAuth` uses `EqualFold`), so
        // `Basic`/`basic`/`BASIC`/… all authenticate.
        let (scheme, b64) = value.split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("basic") {
            return None;
        }
        let decoded = STANDARD.decode(b64.trim()).ok()?;
        let decoded = String::from_utf8(decoded).ok()?;
        // "user:pass" — the username (before the first colon) is ignored; a header with no colon at
        // all is malformed Basic auth and yields no password (→ 401).
        decoded.split_once(':').map(|(_user, pass)| pass.to_string())
    }

    /// Constant-time credential comparison (don't leak the cred via early-exit timing).
    pub(super) fn cred_ok(provided: &str, expected: &str) -> bool {
        let (a, b) = (provided.as_bytes(), expected.as_bytes());
        if a.len() != b.len() {
            return false;
        }
        let mut diff = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        diff == 0
    }

    /// Build a complete HTTP/1.1 response with `Connection: close`.
    pub(super) fn response(
        code: u16,
        reason: &str,
        content_type: &str,
        body: &[u8],
        extra_headers: &[(&str, &str)],
    ) -> Vec<u8> {
        let mut head = format!(
            "HTTP/1.1 {code} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        for (name, value) in extra_headers {
            head.push_str(name);
            head.push_str(": ");
            head.push_str(value);
            head.push_str("\r\n");
        }
        head.push_str("\r\n");
        let mut out = head.into_bytes();
        out.extend_from_slice(body);
        out
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

    // -----------------------------------------------------------------------------------------
    // Loopback dual-credential + in-process LocalAPI HTTP server (the headline gap this closes).
    // These are hermetic: the HTTP framing/auth/routing are pure functions, and the server is
    // exercised end-to-end over a real `127.0.0.1` socket with a *mock* status backend — no live
    // `Device`/tailnet needed. (The successful in-process `Server::loopback` round-trip needs a
    // running control server and stays in integration/e2e.)
    // -----------------------------------------------------------------------------------------

    /// A mock status backend returning a fixed JSON body — the stand-in for `Device::status`.
    fn mock_status(body: &'static [u8]) -> localapi::StatusFn {
        Arc::new(move || Box::pin(async move { Ok(body.to_vec()) }))
    }

    #[test]
    fn gen_cred_is_32_lowercase_hex() {
        let cred = gen_cred();
        assert_eq!(cred.len(), 32, "16 random bytes → 32 hex chars (Go parity)");
        assert!(
            cred.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_ne!(gen_cred(), gen_cred(), "credentials are random per call");
    }

    #[test]
    fn find_subslice_locates_header_terminator() {
        assert_eq!(find_subslice(b"ab\r\n\r\ncd", b"\r\n\r\n"), Some(2));
        assert_eq!(find_subslice(b"no terminator", b"\r\n\r\n"), None);
        assert_eq!(find_subslice(b"", b"\r\n\r\n"), None);
    }

    #[test]
    fn parse_response_extracts_code_and_body() {
        let (code, body) =
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi").unwrap();
        assert_eq!(code, 200);
        assert_eq!(body, b"hi");
        assert_eq!(parse_response(b"garbage without terminator"), None);
    }

    #[test]
    fn parse_head_reads_method_target_and_auth() {
        // "user:pass" base64 = dXNlcjpwYXNz
        let head = b"GET /localapi/v0/status HTTP/1.1\r\nHost: x\r\nAuthorization: Basic dXNlcjpwYXNz\r\nAccept: */*";
        let (method, target, password) = localapi::parse_head(head).unwrap();
        assert_eq!(method, "GET");
        assert_eq!(target, "/localapi/v0/status");
        assert_eq!(password.as_deref(), Some("pass"));
    }

    #[test]
    fn parse_head_rejects_malformed_request_line() {
        assert!(localapi::parse_head(b"GET-only-one-token").is_none());
        assert!(localapi::parse_head(b"GET /x").is_none(), "needs a version token");
    }

    #[test]
    fn basic_auth_password_ignores_username() {
        // Go authenticates on the password only; the username is ignored.
        // base64("anyuser:the-cred") and base64(":the-cred") both yield "the-cred".
        let with_user = STANDARD.encode("anyuser:the-cred");
        let no_user = STANDARD.encode(":the-cred");
        assert_eq!(
            localapi::basic_auth_password(&format!("Basic {with_user}")).as_deref(),
            Some("the-cred")
        );
        assert_eq!(
            localapi::basic_auth_password(&format!("Basic {no_user}")).as_deref(),
            Some("the-cred")
        );
        // The auth scheme is case-insensitive (RFC 7617 / Go `EqualFold`).
        assert_eq!(
            localapi::basic_auth_password(&format!("bAsIc {with_user}")).as_deref(),
            Some("the-cred")
        );
        // A non-Basic scheme, no scheme, or garbage base64 is not accepted.
        assert!(localapi::basic_auth_password("Bearer xyz").is_none());
        assert!(localapi::basic_auth_password("Basic !!!not-base64").is_none());
        assert!(localapi::basic_auth_password("no-space-token").is_none());
    }

    #[test]
    fn cred_ok_matches_only_exact_credentials() {
        assert!(localapi::cred_ok("abc123", "abc123"));
        assert!(!localapi::cred_ok("abc123", "abc124"));
        assert!(!localapi::cred_ok("abc", "abc123"), "length mismatch is a mismatch");
        assert!(!localapi::cred_ok("", "x"));
    }

    #[test]
    fn status_json_serializes_status_snapshot() {
        // Build a snapshot and assert the emitted JSON reflects it (the fork's `Status` is not a
        // serde type, so `status_json` builds the object by hand — this pins that mapping).
        use crate::StableNodeId;
        let node = StatusNode {
            stable_id: StableNodeId("nabc123".to_string()),
            display_name: "web.tail0.ts.net".to_string(),
            ipv4: "100.64.0.1".parse().unwrap(),
            ipv6: "fd7a:115c:a1e0::1".parse().unwrap(),
            online: Some(true),
            last_seen: None,
            allowed_routes: vec![],
            is_exit_node: false,
            cur_addr: None,
            relay: Some("nyc".to_string()),
            ssh_host_keys: vec![],
        };
        let status = Status {
            self_node: Some(node),
            peers: vec![],
            active_exit_node: None,
            magic_dns_suffix: Some("tail0.ts.net".to_string()),
        };
        let bytes = status_json(&status);
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
        assert_eq!(v["self"]["stable_id"], "nabc123");
        assert_eq!(v["self"]["display_name"], "web.tail0.ts.net");
        assert_eq!(v["self"]["ipv4"], "100.64.0.1");
        assert_eq!(v["self"]["online"], true);
        assert_eq!(v["self"]["relay"], "nyc");
        assert_eq!(v["magic_dns_suffix"], "tail0.ts.net");
        assert!(v["peers"].as_array().unwrap().is_empty());
        assert!(v["active_exit_node"].is_null());
    }

    #[tokio::test]
    async fn localapi_server_authenticates_and_routes_over_real_socket() {
        // Bind the real in-process LocalAPI server on 127.0.0.1 with a mock status backend, then
        // drive it with the dependency-free client — exercising accept → parse → auth → route →
        // respond end-to-end.
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let cred = "s3cr3t-cred".to_string();
        let task = tokio::spawn(localapi::serve(
            listener,
            cred.clone(),
            mock_status(br#"{"ok":true}"#),
        ));

        // Correct credential → 200 + the backend's JSON body.
        let (code, body) = localapi_client_get(addr, &cred, "/localapi/v0/status")
            .await
            .unwrap();
        assert_eq!(code, 200);
        assert_eq!(body, br#"{"ok":true}"#);

        // Authenticated but unknown path → 404.
        let (code, _) = localapi_client_get(addr, &cred, "/localapi/v0/nope")
            .await
            .unwrap();
        assert_eq!(code, 404);

        // Wrong credential → 401.
        let (code, _) = localapi_client_get(addr, "wrong-cred", "/localapi/v0/status")
            .await
            .unwrap();
        assert_eq!(code, 401);

        // Missing Authorization header entirely → 401.
        {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            let mut sock = TcpStream::connect(addr).await.unwrap();
            sock.write_all(
                b"GET /localapi/v0/status HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
            let mut resp = Vec::new();
            sock.read_to_end(&mut resp).await.unwrap();
            assert_eq!(parse_response(&resp).unwrap().0, 401);
        }

        task.abort();
    }

    #[tokio::test]
    async fn local_client_round_trips_through_the_localapi_server() {
        // `LocalClient` is what `Server::local_client()` hands back: point one at a running server
        // and assert its accessors + `status()`/`get()` round-trip through real HTTP.
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let cred = "local-api-cred".to_string();
        let task = tokio::spawn(localapi::serve(
            listener,
            cred.clone(),
            mock_status(br#"{"self":null,"peers":[]}"#),
        ));

        let client = LocalClient {
            address: addr,
            cred: cred.clone(),
        };
        assert_eq!(client.address(), addr);
        assert_eq!(client.credential(), cred);

        let body = client.status().await.unwrap();
        assert_eq!(body, br#"{"self":null,"peers":[]}"#);

        let (code, _) = client.get("/localapi/v0/status").await.unwrap();
        assert_eq!(code, 200);

        // A wrong-credential client sees the 401 surfaced as an error from `status()`.
        let bad = LocalClient {
            address: addr,
            cred: "nope".to_string(),
        };
        assert!(matches!(bad.status().await, Err(Error::Loopback(_))));

        task.abort();
    }

    #[test]
    fn loopback_result_carries_both_distinct_credentials() {
        // Shape assertion: the `Loopback` result exposes both Go credentials + both addresses, and
        // `Clone`/`Debug` derive (so it can be logged/stored). Distinctness of the two creds is the
        // point of this task.
        let lb = Loopback {
            address: "127.0.0.1:1080".parse().unwrap(),
            proxy_cred: "proxy".to_string(),
            local_api_address: "127.0.0.1:1081".parse().unwrap(),
            local_api_cred: "localapi".to_string(),
        };
        let cloned = lb.clone();
        assert_ne!(cloned.proxy_cred, cloned.local_api_cred);
        assert_ne!(cloned.address, cloned.local_api_address);
        assert!(format!("{cloned:?}").contains("local_api_cred"));
    }
}
