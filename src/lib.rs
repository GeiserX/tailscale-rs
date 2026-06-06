//! A work-in-progress [Tailscale](https://tailscale.com/blog/how-tailscale-works) library.
//!
//! `tailscale` allows Rust programs to connect to a tailnet and exchange traffic with peers over
//! TCP and UDP. It can communicate with other `tailscale`-based peers, `tailscaled` (the Tailscale
//! Go client), `tsnet`, and `libtailscale` via public DERP servers.
//!
//! <div class="warning">
//! `tailscale` is unstable and insecure.
//!
//! We welcome enthusiasm and interest, but please **do not** build production software using these
//! libraries or rely on it for data privacy until we have a chance to batten down some hatches and
//! complete a third-party audit.
//!
//! See the [Caveats section](#caveats) for more details.
//! </div>
//!
//! For language bindings, see the following crates:
//!
//! - C: [ts_ffi](https://docs.rs/ts_ffi)
//! - Python: [ts_python](https://docs.rs/ts_python)
//! - Elixir: [ts_elixir](https://docs.rs/ts_elixir)
//!
//! For instructions on how to run tests, lints, etc., see [CONTRIBUTING.md]. For the high-level
//! architecture and repository layout, see [ARCHITECTURE.md].
//!
//! ## Code Sample
//!
//! A simple UDP client that periodically sends messages to a tailnet peer at `100.64.0.1:5678`:
//!
//! ```no_run
//! # use std::{
//! #     time::Duration,
//! #     net::Ipv4Addr,
//! #     error::Error,
//! # };
//! #
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn Error>> {
//! // Open a new connection to the tailnet
//! let dev = tailscale::Device::new(
//!     &tailscale::Config::default_with_key_file("tsrs_keys.json").await?,
//!     Some("YOUR_AUTH_KEY_HERE".to_owned()),
//! ).await?;
//!
//! // Bind a UDP socket on our tailnet IP, port 1234
//! let sock = dev.udp_bind((dev.ipv4_addr().await?, 1234).into()).await?;
//!
//! // Send a packet containing "hello, world!" to 100.64.0.1:5678 once per second
//! loop {
//!     sock.send_to((Ipv4Addr::new(100, 64, 0, 1), 5678).into(), b"hello, world!").await?;
//!     tokio::time::sleep(Duration::from_secs(1)).await;
//! }
//! # }
//! ```
//!
//! Additional examples of using the `tailscale` crate can be found in the [`examples/`] directory.
//!
//! ## Using `tailscale`
//!
//! To use this crate or the language bindings, you will need to set the `TS_RS_EXPERIMENT` env var
//! to `this_is_unstable_software`. We'll remove this requirement after a third-party code/cryptography
//! audit and any necessary fixes.
//!
//! Under the hood, we use Tokio for our async runtime. You must also use Tokio, any kind and most
//! configurations of Tokio runtimes should work, but there must be one available when you call any
//! async API functions. The easiest way to do this is to use `#[tokio::main]`, see the
//! [Tokio docs](https://docs.rs/tokio) for more information. In the future, we would like to limit
//! our reliance on Tokio so that there are alternatives for users of other async runtimes.
//!
//! ## Caveats
//!
//! This software is still a work-in-progress! We are providing it in the open at this stage out of
//! a belief in open-source and to see where the community runs with it, but please be aware of a
//! few important considerations:
//!
//! - This implementation contains unaudited cryptography and hasn't undergone a comprehensive
//!   security analysis. Conservatively, assume there could be a critical security hole meaning
//!   anything you send or receive could be in the clear on the public Internet.
//! - There are no compatibility guarantees at the moment. This is early-days software - we may
//!   break dependent code in order to get things right.
//! - Direct peer-to-peer connections via NAT traversal are implemented (STUN-discovered endpoints
//!   and Disco, with `CallMeMaybe` hole-punching over DERP), with DERP relays as the fallback when
//!   no direct path is available. Hard/symmetric NATs get the same single fixed-local-port candidate
//!   (`EndpointSTUN4LocalPort`) Go Tailscale uses; behind a NAT with no static port mapping a flow
//!   may still stay relayed through DERP, which caps its throughput. (Upstream Go does **not** do a
//!   "256-port birthday-paradox spray" — that is a common misconception; the single-candidate guess
//!   is the actual behavior, and this fork matches it.)
//!
//! ## Feature Flags
//!
//! - `axum`: enables the [`axum`] module, which enables you to run an [`axum` HTTP server] on top
//!   of a [`netstack::TcpListener`].
//!
//! ## Platform Support
//!
//! `tailscale` currently supports the following platforms:
//!
//! - Linux (x86_64 and ARM64)
//! - macOS (ARM64)
//!
//! ## Component crates
//!
//! The following crates are part of the tailscale-rs project and are dependencies of this one. For
//! many tasks, just this crate should be sufficient and these other crates are an implementation detail.
//! There are other crates too, see [ARCHITECTURE.md]
//! or the [GitHub repo](https://github.com/tailscale/tailscale-rs).
//!
//! - [ts_runtime](https://docs.rs/ts_runtime): for each API-level `Device`, the runtime uses an actor
//!   architecture to manage the lifecycle of the control client, data plane components, netstack, etc.
//!   A message bus passes updates and communications between these top-level actors.
//! - [ts_netcheck](https://docs.rs/ts_netcheck): checks network availability and reports latency to
//!   DERP servers in different regions.
//! - [ts_netstack_smoltcp](https://docs.rs/ts_netstack_smoltcp): a [smoltcp](https://docs.rs/smoltcp)-based
//!   network stack that processes Layer 3+ packets to/from the overlay network.
//! - [ts_control](https://docs.rs/ts_control): control plane client that handles registration,
//!   authorization/authentication, configuration, and streaming updates.
//! - [ts_dataplane](https://docs.rs/ts_dataplane): wires all the individual data plane functions together,
//!   flowing inbound and outbound packets through the components in the correct order.
//! - [ts_tunnel](https://docs.rs/ts_tunnel): a partial implementation of the WireGuard specification
//!   that protects all data plane traffic, and is interoperable with other WireGuard clients, including Tailscale clients.
//! - [ts_cli_util](https://docs.rs/ts_cli_util): helpers for writing command line tools and initializing
//!   logging, used in examples.
//! - [ts_disco_protocol](https://docs.rs/ts_disco_protocol): incomplete implementation of Tailscale's
//!   discovery protocol (disco).
//!
//! [ARCHITECTURE.md]: https://github.com/tailscale/tailscale-rs/blob/main/ARCHITECTURE.md
//! [CONTRIBUTING.md]: https://github.com/tailscale/tailscale-rs/blob/main/CONTRIBUTING.md
//! [`examples/`]: https://github.com/tailscale/tailscale-rs/blob/main/examples/README.md
//! [open an issue]: https://github.com/tailscale/tailscale-rs/issues
//! [`axum` HTTP server]: https://docs.rs/axum/latest/axum/

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

#[doc(inline)]
pub use config::Config;
#[doc(inline)]
pub use error::{Error, InternalErrorKind};
#[doc(inline)]
pub use ts_control::ExitNodeSelector;
#[doc(inline)]
pub use ts_control::Node as NodeInfo;
#[doc(inline)]
pub use ts_control::tls::{CertifiedKey, TlsAcceptor, TlsStream};
#[doc(inline)]
pub use ts_control::{CertError, MISSING_CERT_RPC, ServeConfig, ServeState, ServeTarget};
#[doc(inline)]
pub use ts_control::{ExitProxyConfig, ExitProxyScheme};
pub use ts_control::{
    IdTokenError, ServiceError, ServiceMode, SshAccept, SshAction, SshConnIdentity, SshDecision,
    SshDenyReason, SshPolicy, SshPrincipal, SshRule,
};
#[doc(inline)]
pub use ts_netstack_smoltcp::PingError;
use ts_netstack_smoltcp::{CreateSocket, netcore::Channel};
#[doc(inline)]
pub use ts_runtime::fallback_tcp::{
    FallbackConnFuture, FallbackConnHandler, FallbackDecision, FallbackTcpHandle,
};
#[doc(inline)]
pub use ts_runtime::taildrop::WaitingFile;
#[doc(inline)]
pub use ts_runtime::{Status, StatusNode, WhoIs};

#[cfg(feature = "axum")]
pub mod axum;
pub mod config;
mod error;
mod loopback;
#[cfg(feature = "ssh")]
pub mod ssh;

#[doc(inline)]
pub use loopback::LoopbackHandle;

/// How a program connects to a tailnet and communicates with peers.
///
/// The `Device` connects to the control plane, registers itself with the tailnet, and communicates
/// with tailnet peers. Its tailnet identity is determined by the key state provided at
/// construction-time.
pub struct Device {
    runtime: ts_runtime::Runtime,
    /// Command channel to the application netstack. `None` in TUN transport mode, where there is
    /// no userspace application netstack; the channel-driven socket APIs ([`Device::udp_bind`],
    /// [`Device::tcp_listen`], [`Device::tcp_connect`], [`Device::ping`]) are unsupported there.
    channel: Option<Channel>,
    /// Whether IPv6 is enabled on the tailnet overlay (the `Config::enable_ipv6` gate, default
    /// `false`). Captured at construction; used by [`Device::listen_service`] to decide whether an
    /// IPv6 VIP-service address is bindable (the netstack only accepts IPv6 overlay addresses when
    /// this is set).
    enable_ipv6: bool,
    /// The stored Serve config + its live per-port accept loops (`tsnet`'s `Get/SetServeConfig` +
    /// serving runtime). Built lazily on the first [`Device::set_serve_config`] (it needs this
    /// node's overlay IPv4, only known after registration). Held here so its accept loops abort when
    /// the `Device` drops; `None` (empty config) until the first `set`.
    serve: std::sync::Mutex<Option<ts_runtime::serve::ServeManager>>,
    /// The live Funnel ingress manager (`tsnet`'s `ListenFunnel` data path), built on
    /// [`Device::listen_funnel`]. Held here so its TLS-termination pump and the installed peerAPI
    /// ingress sink stay alive for the device's life (and tear down when a new `listen_funnel`
    /// replaces it, or the `Device` drops). `None` until the first `listen_funnel`.
    funnel: std::sync::Mutex<Option<ts_runtime::funnel::FunnelManager>>,
}

/// Map a [`ts_runtime::taildrop::TaildropError`] to the device-facing [`Error`]. `Error` is a
/// `Copy` enum with no payload, so the I/O detail string is dropped, but the *kind* is preserved so
/// a caller can still distinguish the actionable cases: an invalid name →
/// [`InternalErrorKind::BadRequest`], an in-progress conflict → [`InternalErrorKind::AlreadyExists`],
/// a missing file → [`InternalErrorKind::NotFound`], and any other filesystem failure →
/// [`InternalErrorKind::Io`].
fn taildrop_err(e: ts_runtime::taildrop::TaildropError) -> Error {
    use ts_runtime::taildrop::TaildropError;
    match e {
        TaildropError::InvalidFileName => Error::Internal(InternalErrorKind::BadRequest),
        TaildropError::FileExists => Error::Internal(InternalErrorKind::AlreadyExists),
        TaildropError::Io(io) if io.kind() == std::io::ErrorKind::NotFound => {
            Error::Internal(InternalErrorKind::NotFound)
        }
        TaildropError::Io(_) => Error::Internal(InternalErrorKind::Io),
    }
}

/// Map a [`ts_runtime::taildrop_send::TaildropSendError`] (the Taildrop *sender*) to the
/// device-facing [`Error`]. The send-side conflict/forbidden/unexpected-status cases all reduce to
/// `BadRequest` (the peer refused the transfer for a request-level reason), a dial failure or
/// timeout to `Timeout`, an invalid name to `BadRequest`, and any stream I/O failure to `Io`.
fn taildrop_send_err(e: ts_runtime::taildrop_send::TaildropSendError) -> Error {
    use ts_runtime::taildrop_send::TaildropSendError;
    match e {
        TaildropSendError::Connect | TaildropSendError::Timeout => Error::Timeout,
        TaildropSendError::InvalidName
        | TaildropSendError::Forbidden
        | TaildropSendError::Conflict
        | TaildropSendError::UnexpectedStatus(_) => Error::Internal(InternalErrorKind::BadRequest),
        TaildropSendError::Io => Error::Internal(InternalErrorKind::Io),
    }
}

/// Resolve the effective registration auth key from `auth_key` plus the config's
/// workload-identity-federation (WIF) / OAuth-client fields.
///
/// With the `identity-federation` feature enabled, an OAuth client secret (`tskey-client-…`) or a
/// `client_id` + (`id_token` | `audience`) is exchanged for a Tailscale auth key against the SaaS
/// admin API before registration (Go `tsnet.Server`'s `resolveAuthKey`). Without the feature this is
/// a pure pass-through: `auth_key` is returned unchanged and the WIF config fields are ignored, so
/// the default build is byte-identical to before.
#[cfg(feature = "identity-federation")]
async fn resolve_auth_key(
    config: &Config,
    auth_key: Option<String>,
) -> Result<Option<String>, Error> {
    let wif = ts_control::WifConfig {
        auth_key,
        client_id: config.client_id.clone(),
        client_secret: config.client_secret.clone(),
        id_token: config.id_token.clone(),
        audience: config.audience.clone(),
        tags: config.requested_tags.clone(),
    };
    ts_control::resolve_auth_key(&wif, &config.control_server_url)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "resolving auth key via workload-identity federation");
            Error::Internal(InternalErrorKind::BadRequest)
        })
}

/// Pass-through when the `identity-federation` feature is disabled: the auth key is used as-is and
/// the WIF config fields have no effect (matching Go, where the federation path is compiled out
/// unless its optional feature is linked).
#[cfg(not(feature = "identity-federation"))]
async fn resolve_auth_key(
    _config: &Config,
    auth_key: Option<String>,
) -> Result<Option<String>, Error> {
    Ok(auth_key)
}

impl Device {
    /// Create a device from the given [`Config`] and auth key.
    ///
    /// Internally, this will spawn multiple asynchronous actors onto a Tokio runtime.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # use tailscale::*;
    /// let dev = Device::new(
    ///     &Config::default_with_key_file("tsrs_keys.json").await?,
    ///     Some("MY_AUTH_KEY".to_string()),
    /// ).await?;
    /// # Ok(()) }
    /// ```
    pub async fn new(config: &Config, auth_key: Option<String>) -> Result<Self, Error> {
        check_magic_env()?;

        // Resolve the effective registration auth key. The explicit `auth_key` argument wins; if it
        // is `None`, fall back to `config.auth_key` (Go `tsnet.Server.AuthKey`). When the
        // `identity-federation` feature is enabled, the resolved key is further passed through the
        // WIF / OAuth-client bootstrap, which exchanges an OAuth client secret (`tskey-client-…`) or
        // an IdP-issued OIDC token for a Tailscale auth key before registration (SaaS-only).
        let auth_key = auth_key.or_else(|| config.auth_key.clone());
        let auth_key = resolve_auth_key(config, auth_key).await?;

        let rt =
            ts_runtime::Runtime::spawn(config.into(), auth_key, (&config.key_state).into()).await?;
        // In TUN transport mode there is no application netstack, so the runtime has no command
        // channel: that surfaces as `UnsupportedInTunMode`, which we map to a `None` channel rather
        // than an error (the device is still usable for control-plane and peer-lookup APIs).
        let channel = match rt.channel().await {
            Ok(c) => Some(c),
            Err(e) if e.kind == ts_runtime::ErrorKind::UnsupportedInTunMode => None,
            Err(e) => return Err(e.into()),
        };

        Ok(Self {
            runtime: rt,
            channel,
            enable_ipv6: config.enable_ipv6,
            serve: std::sync::Mutex::new(None),
            funnel: std::sync::Mutex::new(None),
        })
    }

    /// The application netstack command channel, or an error in TUN transport mode (no application
    /// netstack exists).
    fn channel(&self) -> Result<&Channel, Error> {
        self.channel
            .as_ref()
            .ok_or(Error::Internal(InternalErrorKind::UnsupportedInTunMode))
    }

    /// Get this [`Device`]'s IPv4 tailnet address.
    pub async fn ipv4_addr(&self) -> Result<Ipv4Addr, Error> {
        self.runtime
            .control
            .ask(ts_runtime::control_runner::Ipv4)
            .await
            .map_err(ts_runtime::Error::from)?
            .ok_or(Error::Internal(InternalErrorKind::Actor))
    }

    /// Get this [`Device`]'s IPv6 tailnet address.
    pub async fn ipv6_addr(&self) -> Result<Ipv6Addr, Error> {
        self.runtime
            .control
            .ask(ts_runtime::control_runner::Ipv6)
            .await
            .map_err(ts_runtime::Error::from)?
            .ok_or(Error::Internal(InternalErrorKind::Actor))
    }

    /// Bind a UDP socket to the specified [`SocketAddr`].
    ///
    /// Returns an error in TUN transport mode (there is no application netstack to bind on).
    pub async fn udp_bind(&self, socket_addr: SocketAddr) -> Result<netstack::UdpSocket, Error> {
        self.channel()?
            .udp_bind(socket_addr)
            .await
            .map_err(Into::into)
    }

    /// Bind a TCP listener to the specified [`SocketAddr`].
    ///
    /// Returns an error in TUN transport mode (there is no application netstack to listen on).
    pub async fn tcp_listen(
        &self,
        socket_addr: SocketAddr,
    ) -> Result<netstack::TcpListener, Error> {
        self.channel()?
            .tcp_listen(socket_addr)
            .await
            .map_err(Into::into)
    }

    /// Register a fallback TCP handler (like `tsnet`'s `RegisterFallbackTCPHandler`).
    ///
    /// The callback is consulted for every inbound TCP flow that matches **no** explicit
    /// [`Device::tcp_listen`] listener, with the flow's `(src, dst)` addresses. It returns
    /// `(handler, intercept)`:
    /// - `(_, false)` — decline; the next registered callback is tried.
    /// - `(Some(h), true)` — claim the flow; `h` is handed the accepted [`netstack::TcpStream`].
    /// - `(None, true)` — claim and reject the flow (the connection is closed).
    ///
    /// Multiple handlers may be registered; they are consulted in registration order and the first
    /// to intercept wins. The returned [`FallbackTcpHandle`] deregisters the handler when dropped.
    ///
    /// Handlers serve flows over the overlay netstack only — never a host socket — and a flow no
    /// handler claims is closed (fail-closed), never direct-dialed.
    ///
    /// Returns an error in TUN transport mode (there is no application netstack to attach to).
    pub fn register_fallback_tcp_handler<F>(&self, cb: F) -> Result<FallbackTcpHandle, Error>
    where
        F: Fn(SocketAddr, SocketAddr) -> FallbackDecision + Send + Sync + 'static,
    {
        self.runtime
            .register_fallback_tcp_handler(std::sync::Arc::new(cb))
            .map_err(Into::into)
    }

    /// Resolve a tailnet peer (or this node) by MagicDNS name to its tailnet IPv4 address.
    ///
    /// This is an in-process lookup against the netmap we already hold — like `tsnet`'s in-memory
    /// `dnsMap`, it does not query any DNS server (there is no `100.100.100.100` resolver). The
    /// `name` may be a bare hostname or a fully-qualified MagicDNS name, with or without a trailing
    /// dot, in any case (matching is case-insensitive). Returns `Ok(None)` if no tailnet node has
    /// that name.
    ///
    /// Only MagicDNS names are resolved; names outside the tailnet are not looked up here, so the
    /// caller's system resolver remains responsible for them. IPv6 is intentionally not resolved —
    /// this fork operates IPv4-only on the tailnet.
    pub async fn resolve(&self, name: &str) -> Result<Option<Ipv4Addr>, Error> {
        if let Some(peer) = self.peer_by_name(name).await? {
            return Ok(Some(peer.tailnet_address.ipv4.addr()));
        }

        // tsnet's dnsMap also resolves our own name; fall back to self when no peer matches.
        let me = self.self_node().await?;
        if me.matches_name(name) {
            return Ok(Some(me.tailnet_address.ipv4.addr()));
        }

        Ok(None)
    }

    /// Connect to a tailnet peer by MagicDNS name and port over TCP.
    ///
    /// Resolves `name` via [`Device::resolve`] (an in-process netmap lookup, no DNS server), then
    /// dials the resulting tailnet IPv4 address. Returns [`InternalErrorKind::BadRequest`] if the
    /// name does not resolve to a tailnet node.
    pub async fn connect_by_name(
        &self,
        name: &str,
        port: u16,
    ) -> Result<netstack::TcpStream, Error> {
        let addr = self
            .resolve(name)
            .await?
            .ok_or(Error::Internal(InternalErrorKind::BadRequest))?;

        self.tcp_connect((addr, port).into()).await
    }

    /// Connect to a TCP socket at the remote address.
    ///
    /// Returns an error in TUN transport mode (there is no application netstack to dial from).
    pub async fn tcp_connect(&self, remote: SocketAddr) -> Result<netstack::TcpStream, Error> {
        let channel = self.channel()?;

        let ip: IpAddr = match remote.is_ipv4() {
            true => self.ipv4_addr().await?.into(),
            false => self.ipv6_addr().await?.into(),
        };

        // TODO(npry): collision checking
        let ephemeral_port = rand::random_range(49152..=u16::MAX);

        channel
            .tcp_connect((ip, ephemeral_port).into(), remote)
            .await
            .map_err(Into::into)
    }

    /// Start a SOCKS5 proxy on a host loopback address that dials into the tailnet (Go
    /// `tsnet.Server.Loopback`, SOCKS5 half).
    ///
    /// Binds a TCP listener on `127.0.0.1:0` (host loopback only — never an external interface) and
    /// serves SOCKS5 (RFC 1928) with required username/password auth (RFC 1929): username `tsnet`,
    /// password = the returned `proxy_cred`. Each `CONNECT` is dialed INTO the overlay via
    /// [`Device::connect_by_name`] / [`Device::tcp_connect`] and spliced to the accepted host socket, so
    /// a non-Rust host process can reach tailnet peers through the proxy. Returns the bound address, the
    /// proxy credential, and a [`LoopbackHandle`] whose drop stops the listener.
    ///
    /// Anti-leak: the listener is loopback-only and every connection egresses over the overlay, never a
    /// host socket — the host's real origin IP is never used to reach the destination. Unlike Go, the
    /// LocalAPI HTTP surface is not served (this fork exposes status/whois/id-token natively on
    /// `Device`); only the SOCKS5 proxy is provided.
    ///
    /// Returns an error in TUN transport mode (no application netstack to dial from).
    pub async fn loopback(&self) -> Result<(std::net::SocketAddr, String, LoopbackHandle), Error> {
        // Capture only cloneable pieces — never `&self` — for the spawned accept loop: a clone of the
        // netstack command channel, this device's own overlay IPv4 (fetched once), and a boxed
        // resolver closure over clones of the control + peer-tracker actor refs. The resolver
        // replicates `Device::resolve` (peer-by-name, falling back to this node's own name).
        let channel = self.channel()?.clone();
        let self_ipv4 = self.ipv4_addr().await?;

        let control = self.runtime.control.clone();
        let peer_tracker = self.runtime.peer_tracker.clone();
        let resolve: loopback::Resolver = std::sync::Arc::new(move |name: String| {
            let control = control.clone();
            let peer_tracker = peer_tracker.clone();
            Box::pin(async move {
                let pt = peer_tracker
                    .upgrade()
                    .ok_or(Error::Internal(InternalErrorKind::Actor))?;
                let peer = pt
                    .ask(ts_runtime::peer_tracker::PeerByName { name: name.clone() })
                    .await
                    .map_err(ts_runtime::Error::from)?;
                if let Some(peer) = peer {
                    return Ok(Some(peer.tailnet_address.ipv4.addr()));
                }
                // tsnet's dnsMap also resolves our own name; fall back to self.
                let me = control
                    .ask(ts_runtime::control_runner::SelfNode)
                    .await
                    .map_err(ts_runtime::Error::from)?
                    .ok_or(Error::Internal(InternalErrorKind::Actor))?;
                if me.matches_name(&name) {
                    Ok(Some(me.tailnet_address.ipv4.addr()))
                } else {
                    Ok(None)
                }
            }) as std::pin::Pin<Box<dyn std::future::Future<Output = _> + Send>>
        });

        let dialer = loopback::OverlayDialer::new(channel, self_ipv4, resolve);
        loopback::start(dialer).await
    }

    /// Get our node info.
    pub async fn self_node(&self) -> Result<NodeInfo, Error> {
        self.runtime
            .control
            .ask(ts_runtime::control_runner::SelfNode)
            .await
            .map_err(ts_runtime::Error::from)?
            .ok_or(Error::Internal(InternalErrorKind::Actor))
    }

    /// This node's key-expiry instant as Unix seconds (`Node.KeyExpiry` in Go), or `Ok(None)` if
    /// the key never expires.
    ///
    /// Like Go, this fork is **reactive** about key expiry — it reports it rather than rotating the
    /// node key in the background. A caller can schedule re-authentication around this time; on
    /// expiry, re-create the [`Device`] (which re-registers), supplying a fresh node key + the prior
    /// `old_node_key` to rotate, or the same key to refresh.
    pub async fn self_key_expiry_unix(&self) -> Result<Option<i64>, Error> {
        Ok(self.self_node().await?.key_expiry_unix())
    }

    /// Whether this node's key has expired as of now (`!KeyExpiry.IsZero() && KeyExpiry.Before(now)`
    /// in Go). A key with no expiry is never expired. See [`Device::self_key_expiry_unix`] for the
    /// reactive-rotation note.
    pub async fn self_key_expired(&self) -> Result<bool, Error> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            // An unreadable clock (pre-epoch) is treated as the far future so a time-limited key
            // looks expired — fail-safe toward prompting re-auth rather than trusting a stale key.
            .unwrap_or(i64::MAX);
        Ok(self.self_node().await?.key_expired_at_unix(now))
    }

    /// Fetch the current Tailscale SSH policy pushed by control, if any.
    ///
    /// Returns `Ok(None)` when control has not sent an SSH policy. The SSH server treats an absent
    /// or empty policy as **deny-all** (fail-closed). Used by the SSH auth path
    /// ([`SshPolicy::evaluate`][ts_control::SshPolicy::evaluate]) to authorize incoming
    /// connections.
    pub async fn ssh_policy(&self) -> Result<Option<ts_control::SshPolicy>, Error> {
        self.runtime
            .control
            .ask(ts_runtime::control_runner::CurrentSshPolicy)
            .await
            .map_err(ts_runtime::Error::from)
            .map_err(Into::into)
    }

    /// Look up a peer by name.
    pub async fn peer_by_name(&self, name: &str) -> Result<Option<NodeInfo>, Error> {
        let pt = self
            .runtime
            .peer_tracker
            .upgrade()
            .ok_or(Error::Internal(InternalErrorKind::Actor))?;

        pt.ask(ts_runtime::peer_tracker::PeerByName {
            name: name.to_string(),
        })
        .await
        .map_err(ts_runtime::Error::from)
        .map_err(Into::into)
    }

    /// Look up a peer by ip.
    pub async fn peer_by_tailnet_ip(&self, ip: IpAddr) -> Result<Option<NodeInfo>, Error> {
        let pt = self
            .runtime
            .peer_tracker
            .upgrade()
            .ok_or(Error::Internal(InternalErrorKind::Actor))?;

        pt.ask(ts_runtime::peer_tracker::PeerByTailnetIp { ip })
            .await
            .map_err(ts_runtime::Error::from)
            .map_err(Into::into)
    }

    /// Look up the peer(s) with the most-specific route matches for `ip`.
    ///
    /// This reports which peers *advertise* a route covering `ip`, independent of this device's
    /// `accept_routes` setting — analogous to the Go client's informational `PrimaryRoutes`. It is
    /// not a reachability oracle: with `accept_routes` off, the dataplane will not actually route
    /// to (or accept return traffic from) advertised subnet routes even if this returns a peer.
    pub async fn peers_with_route(&self, ip: IpAddr) -> Result<Vec<NodeInfo>, Error> {
        let pt = self
            .runtime
            .peer_tracker
            .upgrade()
            .ok_or(Error::Internal(InternalErrorKind::Actor))?;

        pt.ask(ts_runtime::peer_tracker::PeerByAcceptedRoute { ip })
            .await
            .map_err(ts_runtime::Error::from)
            .map_err(Into::into)
    }

    /// List the Taildrop files this device has fully received and not yet consumed (Go LocalAPI
    /// `WaitingFiles`).
    ///
    /// Returns the files waiting under the configured `taildrop_dir`, sorted by name. Returns an
    /// empty list when Taildrop is disabled (`Config::taildrop_dir` unset) — fail-closed, never an
    /// error for the disabled case. A filesystem error while listing surfaces as
    /// [`InternalErrorKind::Actor`].
    pub fn taildrop_waiting_files(&self) -> Result<Vec<WaitingFile>, Error> {
        let Some(store) = self.runtime.taildrop_store() else {
            return Ok(Vec::new());
        };
        store
            .waiting_files()
            .map_err(|_| Error::Internal(InternalErrorKind::Actor))
    }

    /// Open a received Taildrop file by name for reading, returning the handle and its size (Go
    /// LocalAPI `OpenFile`).
    ///
    /// The `name` is validated (path-traversal-safe) inside the store before any path is built.
    /// Returns [`InternalErrorKind::BadRequest`] when Taildrop is disabled or the name is invalid,
    /// and [`InternalErrorKind::Actor`] for a filesystem error (e.g. the file does not exist).
    pub fn taildrop_open_file(&self, name: &str) -> Result<(std::fs::File, u64), Error> {
        let store = self
            .runtime
            .taildrop_store()
            .ok_or(Error::Internal(InternalErrorKind::BadRequest))?;
        store.open_file(name).map_err(taildrop_err)
    }

    /// Delete a received Taildrop file by name (Go LocalAPI `DeleteFile`).
    ///
    /// The `name` is validated (path-traversal-safe) inside the store before any path is built.
    /// Returns [`InternalErrorKind::BadRequest`] when Taildrop is disabled or the name is invalid,
    /// and [`InternalErrorKind::Actor`] for a filesystem error (e.g. the file does not exist).
    pub fn taildrop_delete_file(&self, name: &str) -> Result<(), Error> {
        let store = self
            .runtime
            .taildrop_store()
            .ok_or(Error::Internal(InternalErrorKind::BadRequest))?;
        store.delete_file(name).map_err(taildrop_err)
    }

    /// Send a local file to a tailnet `peer` via Taildrop (Go `PushFile` / `tailscale file cp`).
    ///
    /// Pushes `content_length` bytes from `reader` to the peer's peerAPI as
    /// `PUT /v0/put/<name>` over the overlay netstack — the sending counterpart to the receive store
    /// surfaced by [`Device::taildrop_waiting_files`]. The transfer rides the encrypted WireGuard
    /// overlay, never a host socket. The body is streamed from offset 0 (no resume).
    ///
    /// The destination is derived **solely from `peer`'s own node record**
    /// ([`NodeInfo::peerapi_addr`][ts_control::Node::peerapi_addr]): its advertised tailnet IPv4 and
    /// `peerapi4` port. The caller obtains `peer` from [`Device::peer_by_name`] /
    /// [`Device::peer_by_tailnet_ip`], so it is always a current netmap peer — a raw control-supplied
    /// or attacker-chosen address can never be targeted. As defense in depth, the resolved address is
    /// additionally asserted to be a Tailscale CGNAT IP before dialing.
    ///
    /// Returns [`InternalErrorKind::BadRequest`] when the peer advertises no IPv4 peerAPI (so it
    /// cannot receive files), when the name is invalid, or when the peer refuses the transfer
    /// (`403`/`409`/unexpected status); [`Error::Timeout`] on a dial failure or timeout; and
    /// [`InternalErrorKind::Io`] on a mid-transfer stream error.
    pub async fn send_file<R>(
        &self,
        peer: &NodeInfo,
        name: &str,
        content_length: u64,
        reader: R,
    ) -> Result<(), Error>
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        let channel = self.channel()?;

        // Destination comes only from the peer's own node record — never an arbitrary address.
        let dst = peer
            .peerapi_addr()
            .ok_or(Error::Internal(InternalErrorKind::BadRequest))?;
        // Defense in depth: refuse to dial anything outside the Tailscale CGNAT range, so a
        // malformed node record can't steer the PUT at a non-tailnet host.
        if !ts_control::is_tailscale_ip(dst.ip()) {
            return Err(Error::Internal(InternalErrorKind::BadRequest));
        }

        let self_ipv4 = self.ipv4_addr().await?;

        ts_runtime::taildrop_send::send_file(channel, self_ipv4, dst, name, content_length, reader)
            .await
            .map_err(taildrop_send_err)
    }

    /// Begin a debug packet capture, streaming a pcap of every packet crossing the dataplane to
    /// `writer` (Go `tsnet.Server.CapturePcap`).
    ///
    /// Installs a capture hook on the running dataplane: from now until [`Device::stop_capture`] is
    /// called (or another capture replaces this one), a copy of every plaintext IP packet on the
    /// datapath — outbound (pre-encrypt) and inbound (post-decrypt) — is framed and written to
    /// `writer`. The 24-byte pcap global header is written immediately on success.
    ///
    /// The format is byte-faithful classic pcap with Tailscale's `LINKTYPE_USER0` + 4-byte path
    /// preamble per record (see [`ts_runtime::capture`]); a resulting file opens in Wireshark, and
    /// with Tailscale's `ts-dissector.lua` the direction/path of each packet decodes.
    ///
    /// The hook runs **inline on the single-threaded dataplane step**, so `writer` must not block for
    /// long — a slow writer back-pressures the datapath. Records are **not** flushed per packet (that
    /// would be a syscall on every packet on the dataplane thread); buffered bytes are flushed when
    /// the writer is dropped on [`Device::stop_capture`]. Wrap `writer` in a [`std::io::BufWriter`] if
    /// you want buffering. A write error is swallowed per-packet (the capture silently drops that
    /// record) rather than tearing down the datapath; call [`Device::stop_capture`] to end it. Returns
    /// an error only if the dataplane actor is unreachable or the initial global-header write fails.
    pub async fn capture_pcap<W>(&self, writer: W) -> Result<(), Error>
    where
        W: std::io::Write + Send + 'static,
    {
        let sink = std::sync::Arc::new(std::sync::Mutex::new(
            ts_runtime::capture::PcapSink::new(writer)
                .map_err(|_| Error::Internal(InternalErrorKind::Io))?,
        ));
        let hook: ts_runtime::CaptureHook = std::sync::Arc::new(move |path, pkt: &[u8]| {
            if let Ok(mut sink) = sink.lock() {
                // A per-packet write failure (e.g. a closed pipe) silently drops that record rather
                // than tearing down the datapath; the caller ends capture via `stop_capture`.
                drop(sink.log_packet(path.code(), pkt));
            }
        });
        self.runtime.install_capture(Some(hook)).await?;
        Ok(())
    }

    /// Stop a debug packet capture started by [`Device::capture_pcap`] (Go `ClearCaptureSink`).
    ///
    /// Clears the dataplane capture hook; the writer is dropped (its remaining buffered bytes are
    /// flushed by its own `Drop`). Idempotent — clearing when no capture is installed is a no-op.
    /// Returns an error only if the dataplane actor is unreachable.
    pub async fn stop_capture(&self) -> Result<(), Error> {
        self.runtime.install_capture(None).await?;
        Ok(())
    }

    /// Snapshot of this device and its tailnet peers (like `tailscale status`).
    ///
    /// Combines this node's self info with the current peer set: each [`StatusNode`] reports the
    /// stable id, display name, tailnet IPs, advertised routes, and exit-node flag. (Per-peer
    /// `online`/user/capabilities are honestly `None`/empty in this fork — the domain node model
    /// does not yet carry the wire-level liveness/login fields; see `ts_runtime::status` docs.)
    pub async fn status(&self) -> Result<Status, Error> {
        self.runtime.status().await.map_err(Into::into)
    }

    /// Fetch the current Tailnet Lock (TKA) status pushed by control, if any.
    ///
    /// Returns `Ok(None)` when control has sent no `TKAInfo` (tailnet lock not in use, or no change
    /// observed yet). The returned [`TkaStatus`][ts_control::TkaStatus] carries the authority head
    /// (a base32 `AUMHash`, decode with [`tka::AumHash::from_base32`][ts_tka::AumHash::from_base32])
    /// and the disablement signal. Signature verification of a peer's node-key signature against the
    /// authority is performed with the [`tka`] module's [`tka::Authority`][ts_tka::Authority].
    pub async fn tka_status(&self) -> Result<Option<ts_control::TkaStatus>, Error> {
        self.runtime
            .control
            .ask(ts_runtime::control_runner::CurrentTkaStatus)
            .await
            .map_err(ts_runtime::Error::from)
            .map_err(Into::into)
    }

    /// Request an OIDC **ID token** from control for this node, scoped to `audience` (workload-
    /// identity federation, like `tailscale`'s `id-token` LocalAPI).
    ///
    /// Returns a signed JWT whose `sub` claim is this node's MagicDNS name and whose `aud` claim is
    /// `audience`, suitable for presenting to a third-party relying party (e.g. AWS/GCP
    /// workload-identity federation). The node is the token *subject*, not the authenticator — this
    /// is token issuance over the Noise transport (`POST /machine/id-token`), not a login path.
    /// Requires the control plane to support capability version ≥ 30.
    pub async fn fetch_id_token(&self, audience: &str) -> Result<String, ts_control::IdTokenError> {
        self.runtime.fetch_id_token(audience.to_string()).await
    }

    /// Snapshot this node's client metrics in Prometheus text exposition format.
    ///
    /// Mirrors Go Tailscale's `clientmetric` registry: process-global counters/gauges incremented
    /// on the datapath hot loops (e.g. `magicsock_send_udp`, `magicsock_recv_data_bytes_udp`),
    /// rendered as `# TYPE <name> <kind>\n<name> <value>\n` per metric, sorted by name. (Go `tsnet`
    /// exposes no metrics method of its own, so this is the fork's clean public surface.) The
    /// registry is process-global, so the output covers every `Device` in the process.
    pub fn metrics(&self) -> String {
        ts_metrics::write_prometheus()
    }

    /// Map a tailnet source `addr` to the node that owns its IP (like `tsnet`'s `WhoIs`).
    ///
    /// Only the IP of `addr` is used; the port is ignored. Returns `Ok(None)` if no tailnet node
    /// owns that address.
    pub async fn whois(&self, addr: SocketAddr) -> Result<Option<WhoIs>, Error> {
        self.runtime.whois(addr).await.map_err(Into::into)
    }

    /// Watch for netmap changes: the returned receiver's value is the current set of peer
    /// [`StatusNode`]s and updates on every netmap change (like subscribing to `ipn` notifications).
    pub async fn watch_netmap(
        &self,
    ) -> Result<tokio::sync::watch::Receiver<Vec<StatusNode>>, Error> {
        self.runtime.watch_netmap().await.map_err(Into::into)
    }

    /// Ping a tailnet peer over the overlay with an ICMPv4 echo, returning the round-trip time
    /// (like `tailscale ping`).
    ///
    /// The echo is sent from this device's own tailnet IPv4 over the overlay netstack — never a
    /// host socket. IPv6 destinations return [`PingError::Ipv6Unsupported`] (this fork is
    /// IPv4-only on the tailnet). A peer answers from its own OS stack; this netstack does not
    /// auto-reply to echo requests.
    ///
    /// In TUN transport mode there is no application netstack to ping from; this surfaces as
    /// [`PingError::Timeout`] (the same error this method already uses for an unavailable source
    /// address — `PingError` carries no dedicated "unsupported" variant).
    pub async fn ping(&self, dst: IpAddr, timeout: Duration) -> Result<Duration, PingError> {
        let channel = self.channel().map_err(|_| PingError::Timeout)?;
        let src = self.ipv4_addr().await.map_err(|_| PingError::Timeout)?;
        ts_netstack_smoltcp::ping(channel, src, dst, timeout).await
    }

    /// Obtain a TLS certificate for a node's MagicDNS `name` (like `tsnet`'s `GetCertificate`).
    ///
    /// **Fail-closed without the `acme` feature.** By default this fork has no client-side ACME
    /// engine wired in, so this returns [`ts_control::CertError::Unimplemented`] (after a
    /// tailnet-name check) — it NEVER self-signs and NEVER returns a placeholder certificate
    /// ([`ts_control::MISSING_CERT_RPC`] names what is missing).
    ///
    /// **With the `acme` feature** this instead drives the client-side ACME DNS-01 engine to issue a
    /// real Let's Encrypt certificate for `name`, publishing the challenge TXT via the node's
    /// `POST /machine/set-dns` RPC (routed through the control runner). SaaS-only: a self-hosted control plane
    /// 501s on set-dns, surfaced as [`ts_control::CertError::Acme`].
    #[cfg(not(feature = "acme"))]
    pub async fn get_certificate(&self, name: &str) -> Result<CertifiedKey, ts_control::CertError> {
        ts_control::get_certificate(name).await
    }

    /// See the no-`acme` variant for the contract; with `acme` this issues a real cert via the
    /// runtime's ACME engine (`Device → Runtime → ControlRunner → issue_certificate_via_setdns`).
    #[cfg(feature = "acme")]
    pub async fn get_certificate(&self, name: &str) -> Result<CertifiedKey, ts_control::CertError> {
        self.runtime.get_certificate(name.to_string()).await
    }

    /// Build a [`TlsAcceptor`] terminating TLS for `cfg.name` on the overlay (like `tsnet`'s
    /// `ListenTLS`).
    ///
    /// Obtains the certificate via [`Device::get_certificate`] — so with the `acme` feature this
    /// issues a real Let's Encrypt cert (when the control plane answers `set-dns`), and without it
    /// (or when issuance is unavailable) it surfaces the same fail-closed
    /// [`ts_control::CertError`] rather than ever serving a self-signed cert or downgrading to
    /// plaintext. Terminate accepted overlay streams with [`ts_control::accept_tls`].
    pub async fn listen_tls(
        &self,
        cfg: &ts_control::ServeConfig,
    ) -> Result<TlsAcceptor, ts_control::CertError> {
        // Route through Device::get_certificate (the acme-aware issuance path) rather than
        // ts_control::listen_tls, which only knows the non-acme stub. Validate the serve config
        // first (same fail-closed checks ts_control::listen_tls applies), then assemble the acceptor.
        cfg.validate()?;
        let cert = self.get_certificate(&cfg.name).await?;
        ts_control::tls_acceptor(cert)
    }

    /// The currently-stored Serve config (like `tsnet`'s `GetServeConfig`).
    ///
    /// Returns the config last passed to [`Device::set_serve_config`], or an empty
    /// [`ts_control::ServeState`] (no ports) if none was ever set. Pure read — does not touch the
    /// network.
    pub fn get_serve_config(&self) -> ts_control::ServeState {
        match &*self.serve.lock().unwrap_or_else(|e| e.into_inner()) {
            Some(mgr) => mgr.get(),
            None => ts_control::ServeState::default(),
        }
    }

    /// Replace this node's Serve config and (re)bind its tailnet ports (like `tsnet`'s
    /// `SetServeConfig`, REPLACE semantics).
    ///
    /// `state` becomes the **whole** config (full-replace reconcile: every previously-bound serve
    /// port's accept loop is torn down and the new config's ports are bound from scratch). For each
    /// configured port the manager binds an overlay listener on this node's tailnet IPv4 and
    /// dispatches per [`ts_control::ServeTarget`]:
    /// - [`Accept`](ts_control::ServeTarget::Accept) — the TLS-terminated stream is handed back over
    ///   the returned [`ServeAcceptedReceiver`](ts_runtime::serve::ServeAcceptedReceiver) (the
    ///   in-process stand-in for `ListenTLS`'s `net.Listener`).
    /// - [`Proxy`](ts_control::ServeTarget::Proxy) — reverse-proxy the decrypted stream to a local
    ///   host backend.
    /// - [`Text`](ts_control::ServeTarget::Text) — write a fixed body and close.
    /// - [`TcpForward`](ts_control::ServeTarget::TcpForward) — forward the **raw** (non-TLS) stream
    ///   to a local host backend.
    ///
    /// **Fail-closed.** `state.validate()` runs first. Every TLS-terminating port's acceptor is
    /// obtained up-front via [`Device::listen_tls`] (the ACME-aware cert path); if any cert cannot be
    /// issued the whole call fails with that [`ts_control::CertError`] and **nothing is bound** — a
    /// TLS port never downgrades to plaintext.
    ///
    /// **Anti-leak.** Listeners bind the overlay netstack only (never a host socket). The
    /// `Proxy`/`TcpForward` backend dial is a local host socket to the embedder's own backend (like
    /// Go's reverse-proxy to `127.0.0.1`), intentionally NOT routed through the exit-egress
    /// forwarder. A backend dial failure drops that connection; it never falls back.
    ///
    /// Returns an error in TUN transport mode (there is no application netstack to bind on). The
    /// previous config's accept loops (and any earlier `ServeAcceptedReceiver`) stop when this
    /// returns; the new receiver delivers every `Accept`-port connection.
    pub async fn set_serve_config(
        &self,
        state: ts_control::ServeState,
    ) -> Result<ts_runtime::serve::ServeAcceptedReceiver, Error> {
        state
            .validate()
            .map_err(|_| Error::Internal(InternalErrorKind::BadRequest))?;

        // Fail-closed: build every TLS-terminating port's acceptor up-front via the ACME-aware cert
        // path. If any cert can't be issued, return before binding anything (no plaintext downgrade).
        let mut resolved = std::collections::BTreeMap::new();
        for (port, target) in &state.ports {
            let acceptor = if target.terminates_tls() {
                let cfg = ts_control::ServeConfig {
                    name: state.name.clone(),
                    port: *port,
                    target: target.clone(),
                };
                Some(self.listen_tls(&cfg).await.map_err(|_| {
                    // Cert issuance is fail-closed in this fork; surface as a request error rather
                    // than ever binding a plaintext TLS port.
                    Error::Internal(InternalErrorKind::BadRequest)
                })?)
            } else {
                None
            };
            resolved.insert(
                *port,
                ts_runtime::serve::ResolvedPort {
                    target: target.clone(),
                    acceptor,
                },
            );
        }

        // The manager binds the OVERLAY netstack on this node's own tailnet IPv4.
        let self_ipv4 = self.ipv4_addr().await?;
        let channel = self.channel()?.clone();

        let mut slot = self.serve.lock().unwrap_or_else(|e| e.into_inner());
        let mgr =
            slot.get_or_insert_with(|| ts_runtime::serve::ServeManager::new(channel, self_ipv4));
        Ok(mgr.set(state, resolved))
    }

    /// Expose a tailnet TLS service to the public internet via Tailscale Funnel (like `tsnet`'s
    /// `ListenFunnel`), returning a [`FunnelAcceptedReceiver`](ts_runtime::funnel::FunnelAcceptedReceiver)
    /// that delivers each TLS-terminated public connection.
    ///
    /// **Two fail-closed gates, then the live ingress listener.** First the node-attribute gate is
    /// fully enforced from this node's own capability map (mirroring Go `ipn.NodeCanFunnel` +
    /// `ipn.CheckFunnelPort`): the tailnet admin must have enabled HTTPS and granted the `funnel`
    /// node attribute, and `cfg.port` must be in the set the `funnel-ports` capability allows —
    /// otherwise this returns [`ts_control::FunnelError::NotAllowed`] /
    /// [`ts_control::FunnelError::PortNotAllowed`] before touching any cert or network. Then the
    /// node's `*.ts.net` certificate is obtained via the ACME-aware [`Device::get_certificate`] (the
    /// Funnel hostname *is* the node's MagicDNS name, so its DNS-01 cert matches); fail-closed on
    /// [`ts_control::FunnelError::Cert`] — no self-signed or plaintext fallback.
    ///
    /// On success a [`FunnelManager`](ts_runtime::funnel::FunnelManager) is registered: its ingress
    /// sink is installed into the runtime's peerAPI `/v0/ingress` slot (making that route live without
    /// restarting the peerAPI server), and the `HostInfo.IngressEnabled` map-request signal is set so
    /// control routes Funnel traffic to this node. Public Funnel bytes arrive as a relay POST to
    /// `/v0/ingress`, are membership-gated + `101`-hijacked into a raw stream, TLS-terminated by the
    /// manager, and delivered over the returned receiver.
    ///
    /// **Where the relay comes from.** The public ingress **relay + DNS mapping** that feed
    /// `/v0/ingress` are Tailscale infrastructure ([`ts_control::MISSING_FUNNEL_RELAY`]), provisioned
    /// automatically against real Tailscale SaaS with a Funnel-enabled ACL; against a self-hosted
    /// control plane (a self-hosted control plane) no relay exists, so the listener is correct but never fed.
    ///
    /// Anti-leak: Funnel TLS terminates only on the overlay netstack (the hijacked ingress stream
    /// arrives on the overlay peerAPI listener), never a host socket; there is no self-signed or
    /// plaintext fallback. A new `listen_funnel` replaces the previous manager (its pump + sink tear
    /// down); dropping the `Device` tears it down too.
    pub async fn listen_funnel(
        &self,
        cfg: &ts_control::ServeConfig,
        opts: ts_control::FunnelOptions,
    ) -> Result<ts_runtime::funnel::FunnelAcceptedReceiver, ts_control::FunnelError> {
        // Gate 1 (fail-closed, no network): node-attribute + funnel-port access from our cap map.
        let me = self
            .self_node()
            .await
            .map_err(|_| ts_control::FunnelError::NotAllowed)?;
        cfg.validate()?;
        ts_control::funnel_access(&me, cfg.port)?;

        // Gate 2 (fail-closed): obtain the node's `*.ts.net` cert via the ACME-aware path and build
        // the TLS acceptor. A cert failure surfaces as FunnelError::Cert — never a plaintext listener.
        let cert = self
            .get_certificate(&cfg.name)
            .await
            .map_err(ts_control::FunnelError::Cert)?;
        let acceptor = ts_control::tls_acceptor(cert).map_err(ts_control::FunnelError::Cert)?;

        // `opts.funnel_only` (reject tailnet-internal connections) is accepted for surface stability;
        // the ingress data path only ever carries relay-delivered public traffic, so there is no
        // tailnet-internal leg on this listener to reject. Documented as a no-op here for now.
        let _ = opts;

        // Build the funnel manager + its ingress sink + the hand-back receiver, install the sink into
        // the runtime's shared peerAPI `/v0/ingress` slot (making the route live), and flip the
        // IngressEnabled map signal. Hold the manager on the device so its pump/sink live as long as
        // the listener; replacing a prior manager tears the old one down on drop at end of scope.
        let (manager, sink, receiver) = ts_runtime::funnel::FunnelManager::new(acceptor);
        {
            let slot = self.runtime.funnel_ingress_slot();
            *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(sink);
        }
        self.runtime
            .ingress_active_flag()
            .store(true, std::sync::atomic::Ordering::Relaxed);

        let old = {
            let mut held = self.funnel.lock().unwrap_or_else(|e| e.into_inner());
            held.replace(manager)
        };
        drop(old);

        Ok(receiver)
    }

    /// Host a Tailscale **VIP service** (`svc:<label>`) by binding an overlay listener on the
    /// service's control-assigned virtual IP (like `tsnet`'s `ListenService`).
    ///
    /// **Fail-closed.** Mirrors Go `tsnet.Server.ListenService`'s preconditions, enforced from this
    /// node's own netmap state ([`ts_control::resolve_service_listen`]): the `name` must be a valid
    /// `svc:<dns-label>`, this node must be **tagged** (Go `ErrUntaggedServiceHost`), and control
    /// must have assigned the service a VIP address on this node (delivered via the `service-host`
    /// node-capability — see [`ts_control::Node::service_addresses`]). Any unmet precondition
    /// returns a typed [`ts_control::ServiceError`] before binding anything.
    ///
    /// When all hold, this binds a [`tcp_listen`][Device::tcp_listen] on the service VIP and the
    /// configured `mode` port over the **overlay netstack** (never a host socket) and returns the
    /// listener. The netstack already accepts packets for control-assigned VIPs (they are injected
    /// alongside the node's own tailnet address), so the listener is reachable by tailnet peers.
    ///
    /// The `Tun`/L3 service mode is unsupported (a TODO in upstream tsnet); only TCP/HTTP modes
    /// (which bind the same VIP:port at the listen layer) are offered. Returns an error in TUN
    /// transport mode (there is no application netstack to bind on).
    pub async fn listen_service(
        &self,
        name: &str,
        mode: ts_control::ServiceMode,
    ) -> Result<netstack::TcpListener, ts_control::ServiceError> {
        let me = self
            .self_node()
            .await
            .map_err(|e| ts_control::ServiceError::Listen(e.to_string()))?;
        let listen_addr = ts_control::resolve_service_listen(&me, name, mode, self.enable_ipv6)?;
        self.tcp_listen(listen_addr)
            .await
            .map_err(|e| ts_control::ServiceError::Listen(e.to_string()))
    }

    /// Attempt to gracefully shut down this device's runtime.
    ///
    /// Reports whether the device was fully shut down before the timeout. It is still shut
    /// down if it timed out, just more violently and with potential resource leaks.
    ///
    /// If `timeout` is `None`, then shutdown will never time-out.
    pub async fn shutdown(self, timeout: Option<Duration>) -> bool {
        self.runtime.graceful_shutdown(timeout).await
    }
}

/// Command-channel-driven userspace network stack.
///
/// This is an opinionated wrapper around [smoltcp](https://docs.rs/smoltcp) that provides an
/// easier-to-integrate, more-portable API.
pub mod netstack {
    #[doc(inline)]
    pub use ts_netstack_smoltcp::netcore::Error;
    #[doc(inline)]
    pub use ts_netstack_smoltcp::netcore::InternalErrorKind;
    #[doc(inline)]
    pub use ts_netstack_smoltcp::netsock::{TcpListener, TcpStream, UdpSocket};
}

/// Geneve (RFC 8926) framing for Tailscale **peer-relay** traffic. A peer that advertises
/// [`NodeInfo::is_peer_relay`] runs a UDP relay server; relayed disco + WireGuard frames are
/// Geneve-encapsulated with a VNI. This module exposes the header codec so the framing is
/// recognizable. NOTE: the active relay *data path* (the relay-allocation handshake +
/// magicsock integration) is **not yet implemented** in this fork — this is the wire-aware slice.
pub mod geneve {
    #[doc(inline)]
    pub use ts_packet::geneve::{
        GENEVE_FIXED_HEADER_LEN, GENEVE_PROTOCOL_DISCO, GENEVE_PROTOCOL_WIREGUARD, GeneveError,
        GeneveHeader,
    };
}

/// Tailnet Lock (TKA) verification: the [`tka::Authority`] checks a peer's node-key signature
/// against the trusted-key state, mirroring Go's `tka` package. Pair with [`Device::tka_status`]
/// (the control-pushed head/disablement signal).
pub mod tka {
    #[doc(inline)]
    pub use ts_tka::{
        AumHash, AumKind, Authority, Key, KeyKind, NodeKeySignature, SigKind, State, TkaError,
        aum_hash,
    };
}

/// Tailscale cryptographic key types.
pub mod keys {
    #[doc(inline)]
    pub use ts_keys::{
        DiscoKeyPair, DiscoPrivateKey, DiscoPublicKey, MachineKeyPair, MachinePrivateKey,
        MachinePublicKey, NetworkLockKeyPair, NetworkLockPrivateKey, NetworkLockPublicKey,
        NodeKeyPair, NodePrivateKey, NodePublicKey, NodeState, PersistState,
    };
}

const ENV_MAGIC_VAR: &str = "TS_RS_EXPERIMENT";
const ENV_MAGIC_VALUE: &str = "this_is_unstable_software";

fn check_magic_env() -> Result<(), Error> {
    if std::env::var(ENV_MAGIC_VAR).as_deref() != Ok(ENV_MAGIC_VALUE) {
        let warning = format!(
            "
check failed: set {ENV_MAGIC_VAR}={ENV_MAGIC_VALUE} to acknowledge that tailscale-rs is early-days
experimental software containing bugs, unvalidated cryptography, and no stability or compatibility
guarantees.
            "
        );

        eprintln!("{}", warning.trim());

        return Err(Error::UnstableEnvVar);
    };

    Ok(())
}
