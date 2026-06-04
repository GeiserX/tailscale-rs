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
//!   no direct path is available. Symmetric-NAT birthday-paradox hole-punching is not yet
//!   implemented, so behind some NATs a flow stays relayed through DERP, which caps its throughput.
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
pub use ts_control::{CertError, MISSING_CERT_RPC, ServeConfig, ServeTarget};
#[doc(inline)]
pub use ts_control::{ExitProxyConfig, ExitProxyScheme};
#[doc(inline)]
pub use ts_netstack_smoltcp::PingError;
use ts_netstack_smoltcp::{CreateSocket, netcore::Channel};
#[doc(inline)]
pub use ts_runtime::fallback_tcp::{
    FallbackConnFuture, FallbackConnHandler, FallbackDecision, FallbackTcpHandle,
};
#[doc(inline)]
pub use ts_runtime::{Status, StatusNode, WhoIs};

#[cfg(feature = "axum")]
pub mod axum;
pub mod config;
mod error;
#[cfg(feature = "ssh")]
pub mod ssh;

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
        })
    }

    /// The application netstack command channel, or an error in TUN transport mode (no application
    /// netstack exists). `InternalErrorKind::Actor` is the closest existing "internal component
    /// unavailable" sentinel; see the channel field docs.
    fn channel(&self) -> Result<&Channel, Error> {
        self.channel
            .as_ref()
            .ok_or(Error::Internal(InternalErrorKind::Actor))
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

    /// Get our node info.
    pub async fn self_node(&self) -> Result<NodeInfo, Error> {
        self.runtime
            .control
            .ask(ts_runtime::control_runner::SelfNode)
            .await
            .map_err(ts_runtime::Error::from)?
            .ok_or(Error::Internal(InternalErrorKind::Actor))
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

    /// Snapshot of this device and its tailnet peers (like `tailscale status`).
    ///
    /// Combines this node's self info with the current peer set: each [`StatusNode`] reports the
    /// stable id, display name, tailnet IPs, advertised routes, and exit-node flag. (Per-peer
    /// `online`/user/capabilities are honestly `None`/empty in this fork — the domain node model
    /// does not yet carry the wire-level liveness/login fields; see `ts_runtime::status` docs.)
    pub async fn status(&self) -> Result<Status, Error> {
        self.runtime.status().await.map_err(Into::into)
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
    /// **Fail-closed.** This fork has no client-side ACME engine and no `set-dns` RPC to publish
    /// the DNS-01 challenge (and the a self-hosted control plane control target 501s on `set-dns`), so this currently
    /// always returns [`ts_control::CertError::Unimplemented`] (after a tailnet-name check). It
    /// NEVER self-signs and NEVER returns a placeholder certificate. When issuance lands
    /// ([`ts_control::MISSING_CERT_RPC`] names what is missing), this starts returning a real
    /// [`CertifiedKey`] with no caller change.
    pub async fn get_certificate(&self, name: &str) -> Result<CertifiedKey, ts_control::CertError> {
        ts_control::get_certificate(name).await
    }

    /// Build a [`TlsAcceptor`] terminating TLS for `cfg.name` on the overlay (like `tsnet`'s
    /// `ListenTLS`).
    ///
    /// **Fail-closed.** Delegates to [`Device::get_certificate`]; because no real certificate can
    /// be issued in this fork, this returns the same [`ts_control::CertError::Unimplemented`]
    /// rather than ever serving a self-signed cert or downgrading to plaintext. Terminate accepted
    /// overlay streams with [`ts_control::accept_tls`].
    pub async fn listen_tls(
        &self,
        cfg: &ts_control::ServeConfig,
    ) -> Result<TlsAcceptor, ts_control::CertError> {
        ts_control::listen_tls(cfg).await
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
