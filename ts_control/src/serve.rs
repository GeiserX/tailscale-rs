//! TLS termination on the tailnet (`tsnet`'s `Serve` / `ListenTLS`).
//!
//! [`ServeConfig`] is a scoped-down mirror of upstream Tailscale's
//! `ipn.ServeConfig`: it describes terminating TLS for the node's MagicDNS name
//! on a tailnet port and what to do with the decrypted stream. [`tls_acceptor`]
//! turns a [`CertifiedKey`] (obtained via [`crate::cert::get_certificate`]) into
//! a [`tokio_rustls::TlsAcceptor`] using the same `ring` provider as the rest of
//! the stack ([`ts_tls_util`]), and [`accept_tls`] wraps an accepted overlay
//! stream.
//!
//! # Anti-leak
//!
//! TLS is terminated only for tailnet (`*.ts.net`) names (enforced by
//! [`crate::cert::is_tailnet_name`] at certificate-acquisition time) and only on
//! the **overlay** netstack — never a host socket. There is no plaintext
//! downgrade and no self-signed fallback: if a certificate cannot be obtained,
//! [`listen_tls`] surfaces the same fail-closed [`CertError`] as
//! [`crate::cert::get_certificate`].

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ServerConfig,
        crypto::ring::default_provider,
        server::{ClientHello, ResolvesServerCert},
        sign::CertifiedKey,
    },
    server::TlsStream,
};

use crate::{
    cert::{self, CertError},
    node::Node,
};

/// What to do with a stream once TLS is terminated (or, for [`ServeTarget::TcpForward`], a raw TCP
/// stream with no TLS).
///
/// Mirrors the handler shapes of upstream `ipn.ServeConfig`'s `HTTPHandler`/`TCPPortHandler`
/// (`Proxy`/`Text`/`TCPForward`/`Path`/`Redirect`), plus an `Accept` hand-back the in-process Rust
/// embedder uses in place of Go's `net.Listener`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
#[non_exhaustive]
pub enum ServeTarget {
    /// Hand the accepted, decrypted stream back to the embedder (like
    /// `tsnet`'s `ListenTLS` returning a `net.Listener`).
    Accept,
    /// Reverse-proxy the decrypted stream to a local address (like a `Serve`
    /// `Proxy` handler). The address is a real OS socket target on this host.
    Proxy {
        /// `host:port` to dial for the proxied backend.
        to: String,
    },
    /// Serve a fixed plaintext body to every connection, then close (Go `HTTPHandler.Text`). The
    /// bytes are written as-is after TLS termination — the embedder supplies any HTTP framing.
    Text {
        /// The exact bytes to write to each accepted stream.
        body: String,
    },
    /// Forward the **raw** (non-TLS-terminated) TCP stream to a local backend (Go
    /// `TCPPortHandler.TCPForward`). Unlike [`ServeTarget::Proxy`], no TLS is terminated — bytes are
    /// spliced through verbatim to `to` (a real OS socket on this host).
    TcpForward {
        /// `host:port` to dial for the raw-TCP backend.
        to: String,
    },
    /// HTTP path-prefix mux (Go `HTTPHandler` path map). Terminates TLS, reads the request line, and
    /// dispatches the longest-matching path prefix's nested target on the already-decrypted stream.
    Path {
        /// Path-prefix → nested target. Longest-prefix wins at dispatch; an unmatched path is a
        /// fail-closed 404. Nested `Path` is rejected by [`validate`](ServeState::validate) to bound
        /// recursion (one level of nesting only).
        handlers: alloc::collections::BTreeMap<String, ServeTarget>,
    },
    /// HTTP redirect response (Go `HTTPHandler` redirect). Terminates TLS, then writes a bodyless
    /// `status`/`Location: to` response and closes.
    Redirect {
        /// Absolute or relative `Location` header value.
        to: String,
        /// HTTP redirect status; [`validate`](ServeState::validate) rejects anything outside
        /// `300..=399`.
        status: u16,
    },
}

impl ServeTarget {
    /// Whether this target requires TLS termination on the serve port. `Accept`/`Proxy`/`Text`/
    /// `Path`/`Redirect` ride an HTTPS port and terminate TLS; only `TcpForward` is a raw passthrough
    /// with no TLS. Explicit arms (not a single `matches!`) so the `#[non_exhaustive]` intent — every
    /// future variant must declare its TLS posture deliberately — is clear at the call site.
    pub fn terminates_tls(&self) -> bool {
        match self {
            ServeTarget::Accept
            | ServeTarget::Proxy { .. }
            | ServeTarget::Text { .. }
            | ServeTarget::Path { .. }
            | ServeTarget::Redirect { .. } => true,
            ServeTarget::TcpForward { .. } => false,
        }
    }
}

/// A complete multi-port Serve configuration for one node (mirrors upstream `ipn.ServeConfig`'s
/// per-port `TCP` map). Stored on the device and reconciled into one accept loop per port by the
/// Serve runtime; `set_serve_config` REPLACES the whole config (Go semantics).
///
/// All TLS-terminating ports share the node's single MagicDNS [`name`](ServeState::name)
/// certificate (obtained via the ACME path). `TcpForward` ports need no cert.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ServeState {
    /// The node's MagicDNS name the TLS-terminating ports' certificate is for (e.g.
    /// `host.tailnet.ts.net`). Must be a tailnet name when any TLS-terminating port is configured.
    pub name: String,
    /// Map of tailnet (overlay) port → what to serve on it.
    pub ports: alloc::collections::BTreeMap<u16, ServeTarget>,
}

impl ServeState {
    /// Validate the whole config. Fail-closed: rejects port 0, empty proxy/forward targets, and —
    /// when any TLS-terminating port is present — a non-tailnet `name` (anti-leak: we never mint a
    /// cert for an off-tailnet name). An empty config (no ports) is valid (serves nothing).
    pub fn validate(&self) -> Result<(), CertError> {
        let any_tls = self.ports.values().any(ServeTarget::terminates_tls);
        if any_tls && !cert::is_tailnet_name(&self.name) {
            return Err(CertError::NotTailnetName(self.name.clone()));
        }
        for (port, target) in &self.ports {
            if *port == 0 {
                return Err(CertError::Acme("serve port must be non-zero".into()));
            }
            validate_target(target, 0)?;
        }
        Ok(())
    }
}

/// Maximum depth of nested [`ServeTarget::Path`] handlers. A top-level `Path` (depth 0) may hold
/// non-`Path` nested targets; a `Path` nested inside another `Path` is rejected. This bounds
/// validation (and dispatch) recursion so an attacker-supplied config can't blow the stack.
const MAX_PATH_NESTING_DEPTH: usize = 1;

/// Fail-closed validation for one [`ServeTarget`], shared by [`ServeState::validate`] and
/// [`ServeConfig::validate`]. `depth` is the current `Path` nesting level (0 at the top).
///
/// Rejects: empty `Proxy`/`TcpForward` targets; `Redirect` with an out-of-`300..=399` status, an
/// empty `to`, or a `to` containing CR/LF (the value is written verbatim into a `Location:` response
/// header, so embedded CR/LF would allow HTTP response-header injection / response splitting);
/// `Path` with empty `handlers`, a `Path` nested deeper than [`MAX_PATH_NESTING_DEPTH`]
/// (no unbounded recursion), or any nested target that itself fails validation.
fn validate_target(target: &ServeTarget, depth: usize) -> Result<(), CertError> {
    match target {
        ServeTarget::Proxy { to } | ServeTarget::TcpForward { to } if to.trim().is_empty() => Err(
            CertError::Acme("serve proxy/forward target must not be empty".into()),
        ),
        ServeTarget::Redirect { to, status } => {
            if to.trim().is_empty() {
                return Err(CertError::Acme(
                    "serve redirect target must not be empty".into(),
                ));
            }
            // The redirect `to` is written verbatim into a `Location:` response header at runtime.
            // A CR or LF would terminate the header line and allow injection of arbitrary headers
            // or a response body (response splitting). Reject it fail-closed.
            if to.contains(['\r', '\n']) {
                return Err(CertError::Acme(
                    "serve redirect target must not contain CR/LF".into(),
                ));
            }
            if !(300..=399).contains(status) {
                return Err(CertError::Acme(
                    "serve redirect status must be in 300..=399".into(),
                ));
            }
            Ok(())
        }
        ServeTarget::Path { handlers } => {
            if depth >= MAX_PATH_NESTING_DEPTH {
                return Err(CertError::Acme(
                    "serve path handlers must not nest more than one level".into(),
                ));
            }
            if handlers.is_empty() {
                return Err(CertError::Acme(
                    "serve path handlers must not be empty".into(),
                ));
            }
            for nested in handlers.values() {
                validate_target(nested, depth + 1)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Configuration for terminating TLS on one tailnet port for one MagicDNS name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServeConfig {
    /// The node's MagicDNS name the certificate is for (e.g.
    /// `host.tailnet.ts.net`). Must be a tailnet name.
    pub name: String,
    /// The tailnet (overlay) port to terminate TLS on.
    pub port: u16,
    /// What to do with each decrypted stream.
    pub target: ServeTarget,
}

impl ServeConfig {
    /// Validate the config. Fail-closed: rejects non-tailnet names, port 0, and
    /// empty proxy targets, so a misconfiguration can't silently serve the wrong
    /// thing.
    pub fn validate(&self) -> Result<(), CertError> {
        if !cert::is_tailnet_name(&self.name) {
            return Err(CertError::NotTailnetName(self.name.clone()));
        }
        if self.port == 0 {
            return Err(CertError::Acme("serve port must be non-zero".into()));
        }
        validate_target(&self.target, 0)
    }
}

/// A [`ResolvesServerCert`] that always answers with one pre-obtained
/// [`CertifiedKey`]. The cert is for a single MagicDNS name, so SNI selection is
/// trivial — every `ClientHello` gets the same key.
#[derive(Debug)]
struct SingleCert(Arc<CertifiedKey>);

impl ResolvesServerCert for SingleCert {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// Build a [`TlsAcceptor`] for an already-obtained [`CertifiedKey`].
///
/// Pins the `ring` provider explicitly (matching [`ts_tls_util`]); never
/// auto-detects the process-default provider, which panics under ring+aws-lc
/// feature unification.
pub fn tls_acceptor(cert: CertifiedKey) -> Result<TlsAcceptor, CertError> {
    let config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(CertError::Rustls)?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCert(Arc::new(cert))));

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Terminate TLS on a single already-accepted overlay stream.
///
/// Generic over the stream type so the orchestrator can pass an overlay netstack
/// `TcpStream` (this crate does not depend on the netstack). The acceptor is
/// built from [`tls_acceptor`]; reuse one acceptor across many connections.
pub async fn accept_tls<Io>(acceptor: &TlsAcceptor, io: Io) -> Result<TlsStream<Io>, CertError>
where
    Io: AsyncRead + AsyncWrite + Unpin,
{
    acceptor.accept(io).await.map_err(CertError::Io)
}

/// Obtain a certificate for `cfg.name` and build a [`TlsAcceptor`] for it.
///
/// **Fail-closed.** Delegates to [`crate::cert::get_certificate`], which in this
/// fork returns [`CertError::Unimplemented`] (no client-side ACME engine / no
/// `set-dns` DNS-01 publish RPC, and a self-hosted control plane typically 501s on `set-dns`). This function
/// therefore returns the same error rather than ever falling back to plaintext or
/// a self-signed certificate. When issuance lands, this starts returning a
/// working acceptor with no caller change.
pub async fn listen_tls(cfg: &ServeConfig) -> Result<TlsAcceptor, CertError> {
    cfg.validate()?;
    let cert = cert::get_certificate(&cfg.name).await?;
    tls_acceptor(cert)
}

/// Options for a Funnel listener (mirrors `tsnet.FunnelOption`).
///
/// Funnel exposes a tailnet TLS service to the *public* internet via Tailscale's ingress relays.
/// These knobs scope down from upstream to what this fork models; the listener itself is
/// fail-closed in this fork (see [`listen_funnel`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FunnelOptions {
    /// Reject tailnet-internal connections, serving *only* public Funnel ingress (`tsnet`'s
    /// `FunnelOnly`). When `false`, the same listener accepts both tailnet and Funnel traffic.
    pub funnel_only: bool,
}

/// Why a Funnel listen request was denied or could not be served.
///
/// Fail-closed by construction: the access-gate variants ([`FunnelError::NotAllowed`],
/// [`FunnelError::PortNotAllowed`]) deny before any listener is built, and the terminal
/// [`FunnelError::Cert`] carries the same fail-closed [`CertError`] as [`listen_tls`] (no
/// self-signed/plaintext fallback). [`FunnelError::Unsupported`] marks the public-relay leg that
/// this fork cannot stand up against its control plane.
#[derive(Debug)]
pub enum FunnelError {
    /// The node is not permitted to funnel: it lacks the `https` and/or `funnel` node attributes
    /// (Go `ipn.NodeCanFunnel`). The tailnet admin must enable HTTPS and grant the `funnel`
    /// attribute via the ACL policy.
    NotAllowed,
    /// The node may funnel, but `port` is not in the set granted by the `funnel-ports` capability
    /// (Go `ipn.CheckFunnelPort`).
    PortNotAllowed(u16),
    /// Certificate acquisition / TLS material assembly failed. Funnel terminates public TLS with the
    /// node's `*.ts.net` cert (the Funnel hostname *is* the node's MagicDNS name, so the existing
    /// DNS-01 cert matches — no TLS-ALPN-01 needed). Without the `acme` feature (or before a cert is
    /// issued) this carries the same fail-closed [`CertError`] as [`listen_tls`] — no self-signed or
    /// plaintext fallback.
    Cert(CertError),
    /// The public ingress relay leg is unavailable. Funnel ingress arrives as a tailnet-peer POST to
    /// this node's peerAPI `/v0/ingress` (the relay is a Tailscale-operated peer that the control
    /// plane stands up); against a self-hosted control plane no such relay exists, so no
    /// public traffic is ever delivered. This is *not* returned by [`listen_funnel`] anymore (the
    /// listener is built and works against real SaaS); it remains for callers that want to surface
    /// the relay gap explicitly. `detail` names what is missing.
    Unsupported {
        /// Names exactly what is missing to serve public Funnel ingress.
        detail: String,
    },
}

impl core::fmt::Display for FunnelError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FunnelError::NotAllowed => write!(
                f,
                "Funnel not available: node lacks the \"https\" and/or \"funnel\" attributes"
            ),
            FunnelError::PortNotAllowed(port) => {
                write!(f, "port {port} is not allowed for funnel")
            }
            FunnelError::Cert(e) => write!(f, "Funnel certificate error: {e}"),
            FunnelError::Unsupported { detail } => {
                write!(f, "Funnel ingress is unsupported in this fork: {detail}")
            }
        }
    }
}

impl std::error::Error for FunnelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FunnelError::Cert(e) => Some(e),
            FunnelError::NotAllowed
            | FunnelError::PortNotAllowed(_)
            | FunnelError::Unsupported { .. } => None,
        }
    }
}

impl From<CertError> for FunnelError {
    fn from(e: CertError) -> Self {
        FunnelError::Cert(e)
    }
}

/// Names what is needed to actually receive public Funnel ingress on a node whose client-side
/// listener is up. This is **Tailscale infrastructure, not buildable in this fork**: the public DNS
/// `<node>.<tailnet>.ts.net:443` → relay mapping plus the ingress relay itself (a Tailscale-operated
/// tailnet peer that POSTs the public client's bytes to this node's peerAPI `/v0/ingress`). Against
/// real Tailscale SaaS (with a Funnel-enabled ACL) control stands these up automatically and
/// [`listen_funnel`]'s listener serves real public traffic; against a self-hosted control plane
/// no relay exists, so the listener is correct but never fed. Surfaced verbatim in
/// [`FunnelError::Unsupported`] for callers that want to flag the relay gap.
pub const MISSING_FUNNEL_RELAY: &str = "the Tailscale-operated public ingress relay + the public DNS \
     <node>.<tailnet>.ts.net:443 -> relay mapping that POST public client bytes to this node's peerAPI \
     /v0/ingress; these are Tailscale infrastructure (provisioned automatically against real Tailscale \
     SaaS with a Funnel-enabled ACL) and a self-hosted control plane provides no such relay";

/// Check whether `node` may funnel on `port`, mirroring Go's `ipn.NodeCanFunnel` +
/// `ipn.CheckFunnelPort` gate. Pure and fail-closed: a missing attribute or out-of-range port
/// denies. This is the access decision; it does not build a listener.
pub fn funnel_access(node: &Node, port: u16) -> Result<(), FunnelError> {
    if !node.can_funnel() {
        return Err(FunnelError::NotAllowed);
    }
    if !node.check_funnel_port(port) {
        return Err(FunnelError::PortNotAllowed(port));
    }
    Ok(())
}

/// Build a [`TlsAcceptor`] terminating public Funnel ingress for `cfg.name` on `cfg.port` (like
/// `tsnet`'s `ListenFunnel`).
///
/// **Fail-closed gates, then the working TLS acceptor.** First the node-attribute gate
/// ([`funnel_access`], mirroring Go `NodeCanFunnel` + `CheckFunnelPort`) must pass — fully enforced
/// from the node's capability map. Then TLS material is obtained via [`cert::get_certificate`]: the
/// Funnel hostname *is* the node's MagicDNS `*.ts.net` name, so the node's existing DNS-01 cert
/// matches and no TLS-ALPN-01 is required. Without the `acme` feature this fork's stub still returns
/// [`CertError::Unimplemented`] (carried as [`FunnelError::Cert`]); the device-level
/// `listen_funnel` routes through the ACME-aware cert path instead, so with `acme` (and a control
/// plane that answers `set-dns`) this yields a real acceptor.
///
/// Unlike the previous fail-closed stub, an allowed request with a cert now returns a usable
/// acceptor (the caller — `Device::listen_funnel` — registers a funnel manager that TLS-terminates
/// hijacked `/v0/ingress` streams with it and hands the decrypted streams back). The public ingress
/// **relay + DNS mapping** that feed `/v0/ingress` are Tailscale infrastructure
/// ([`MISSING_FUNNEL_RELAY`]) provisioned automatically against real Tailscale SaaS; against a
/// self-hosted control plane no relay exists, so the listener is correct but never fed.
///
/// Anti-leak: Funnel TLS terminates only on the overlay netstack (the hijacked ingress stream
/// arrives on the peerAPI overlay listener), never a host socket; there is no self-signed or
/// plaintext fallback. `_opts` is accepted now so the public surface is stable as ingress wiring
/// evolves.
pub async fn listen_funnel(
    node: &Node,
    cfg: &ServeConfig,
    _opts: FunnelOptions,
) -> Result<TlsAcceptor, FunnelError> {
    cfg.validate()?;
    funnel_access(node, cfg.port)?;

    // Access granted. Build the TLS acceptor from the node's `*.ts.net` cert (the Funnel hostname is
    // the node's MagicDNS name, so the existing DNS-01 cert matches). Fail-closed on CertError — no
    // self-signed/plaintext fallback. The cert path here is the non-acme stub; the device-level
    // listen_funnel routes through the acme-aware Device::get_certificate.
    let cert = cert::get_certificate(&cfg.name).await?;
    Ok(tls_acceptor(cert)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(name: &str, port: u16) -> ServeConfig {
        ServeConfig {
            name: name.into(),
            port,
            target: ServeTarget::Accept,
        }
    }

    #[test]
    fn validate_accepts_tailnet_name() {
        assert!(cfg("host.tail1.ts.net", 443).validate().is_ok());
    }

    #[test]
    fn validate_rejects_offtailnet_name() {
        let err = cfg("example.com", 443).validate().unwrap_err();
        assert!(matches!(err, CertError::NotTailnetName(_)));
    }

    #[test]
    fn validate_rejects_zero_port() {
        assert!(cfg("host.tail1.ts.net", 0).validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_proxy_target() {
        let c = ServeConfig {
            name: "host.tail1.ts.net".into(),
            port: 443,
            target: ServeTarget::Proxy { to: "  ".into() },
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn serve_config_roundtrips_json() {
        let c = ServeConfig {
            name: "host.tail1.ts.net".into(),
            port: 8443,
            target: ServeTarget::Proxy {
                to: "127.0.0.1:8080".into(),
            },
        };
        let json = serde_json::to_string(&c).unwrap();
        let back: ServeConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn serve_target_path_redirect_roundtrips_json() {
        let mut handlers = alloc::collections::BTreeMap::new();
        handlers.insert(
            "/".to_string(),
            ServeTarget::Redirect {
                to: "https://host.tail1.ts.net/app".into(),
                status: 308,
            },
        );
        handlers.insert(
            "/api".to_string(),
            ServeTarget::Proxy {
                to: "127.0.0.1:8080".into(),
            },
        );
        let c = ServeConfig {
            name: "host.tail1.ts.net".into(),
            port: 443,
            target: ServeTarget::Path { handlers },
        };
        let json = serde_json::to_string(&c).unwrap();
        let back: ServeConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
        assert!(c.validate().is_ok());
    }

    #[test]
    fn validate_rejects_bad_redirect_status() {
        let c = ServeConfig {
            name: "host.tail1.ts.net".into(),
            port: 443,
            target: ServeTarget::Redirect {
                to: "/elsewhere".into(),
                status: 200,
            },
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_redirect_target() {
        let c = ServeConfig {
            name: "host.tail1.ts.net".into(),
            port: 443,
            target: ServeTarget::Redirect {
                to: "  ".into(),
                status: 302,
            },
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_redirect_with_crlf() {
        // CR/LF in the `to` would terminate the `Location:` header line and allow response-header
        // injection / response splitting. Must be rejected (bare CR, bare LF, and CRLF), via the
        // shared validate_target used by ServeConfig::validate and ServeState::validate.
        for bad in [
            "https://host.tail1.ts.net/\r\nSet-Cookie: evil=1",
            "https://host.tail1.ts.net/\rX",
            "https://host.tail1.ts.net/\nX",
        ] {
            let c = ServeConfig {
                name: "host.tail1.ts.net".into(),
                port: 443,
                target: ServeTarget::Redirect {
                    to: bad.into(),
                    status: 302,
                },
            };
            assert!(
                c.validate().is_err(),
                "ServeConfig must reject CR/LF redirect target: {bad:?}"
            );

            let mut ports = alloc::collections::BTreeMap::new();
            ports.insert(
                443u16,
                ServeTarget::Redirect {
                    to: bad.into(),
                    status: 302,
                },
            );
            let st = ServeState {
                name: "host.tail1.ts.net".into(),
                ports,
            };
            assert!(
                st.validate().is_err(),
                "ServeState must reject CR/LF redirect target: {bad:?}"
            );
        }

        // A normal redirect target (no CR/LF) still passes.
        let ok = ServeConfig {
            name: "host.tail1.ts.net".into(),
            port: 443,
            target: ServeTarget::Redirect {
                to: "https://host.tail1.ts.net/app".into(),
                status: 308,
            },
        };
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn validate_rejects_empty_path_handlers() {
        let c = ServeConfig {
            name: "host.tail1.ts.net".into(),
            port: 443,
            target: ServeTarget::Path {
                handlers: alloc::collections::BTreeMap::new(),
            },
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_nested_path() {
        let mut inner = alloc::collections::BTreeMap::new();
        inner.insert("/deep".to_string(), ServeTarget::Accept);
        let mut handlers = alloc::collections::BTreeMap::new();
        handlers.insert("/".to_string(), ServeTarget::Path { handlers: inner });
        let c = ServeConfig {
            name: "host.tail1.ts.net".into(),
            port: 443,
            target: ServeTarget::Path { handlers },
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_recurses_into_nested_path_target() {
        // A nested target that is itself invalid (empty proxy) must fail through the recursion.
        let mut handlers = alloc::collections::BTreeMap::new();
        handlers.insert("/".to_string(), ServeTarget::Proxy { to: "  ".into() });
        let c = ServeConfig {
            name: "host.tail1.ts.net".into(),
            port: 443,
            target: ServeTarget::Path { handlers },
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn serve_state_validate_accepts_path_and_redirect() {
        let mut handlers = alloc::collections::BTreeMap::new();
        handlers.insert(
            "/api".to_string(),
            ServeTarget::Proxy {
                to: "127.0.0.1:8080".into(),
            },
        );
        let mut ports = alloc::collections::BTreeMap::new();
        ports.insert(443u16, ServeTarget::Path { handlers });
        ports.insert(
            8443u16,
            ServeTarget::Redirect {
                to: "/api".into(),
                status: 307,
            },
        );
        let st = ServeState {
            name: "host.tail1.ts.net".into(),
            ports,
        };
        assert!(st.validate().is_ok());
    }

    #[tokio::test]
    async fn listen_tls_is_fail_closed() {
        // No ACME RPC in this fork: must surface Unimplemented, never a usable
        // acceptor, never a plaintext/self-signed fallback.
        let err = match listen_tls(&cfg("host.tail1.ts.net", 443)).await {
            Ok(_) => panic!("must not build an acceptor without a real cert"),
            Err(e) => e,
        };
        assert!(matches!(err, CertError::Unimplemented { .. }));
    }

    // TEST-ONLY: prove the rustls acceptor wiring works when a CertifiedKey IS
    // available, using an ephemeral self-signed cert. This never runs in
    // production (get_certificate is fail-closed); it only exercises tls_acceptor.
    #[test]
    fn tls_acceptor_builds_from_certified_key() {
        let cert = rcgen::generate_simple_self_signed(vec!["host.tail1.ts.net".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();
        let ck = cert::certified_key_from_pem(cert_pem.as_bytes(), key_pem.as_bytes()).unwrap();
        assert!(tls_acceptor(ck).is_ok());
    }

    // ---- Funnel gating ----

    use crate::node::{Node, NodeCapMap, StableId, TailnetAddress};

    /// Build a minimal node with the given cap-map keys, for funnel-gate tests.
    fn funnel_node(caps: &[&str]) -> Node {
        let mut cap_map = NodeCapMap::new();
        for c in caps {
            cap_map.insert((*c).to_string(), vec![]);
        }
        Node {
            id: 1,
            stable_id: StableId("n1".to_string()),
            hostname: "host".to_string(),
            tailnet: Some("tail1.ts.net".to_string()),
            tags: vec![],
            tailnet_address: TailnetAddress {
                ipv4: "100.64.0.1/32".parse().unwrap(),
                ipv6: "fd7a::1/128".parse().unwrap(),
            },
            node_key: [0u8; 32].into(),
            node_key_expiry: None,
            machine_key: None,
            disco_key: None,
            accepted_routes: vec![],
            underlay_addresses: vec![],
            derp_region: None,
            cap: Default::default(),
            cap_map,
            peerapi_port: None,
            peerapi_dns_proxy: false,
            is_wireguard_only: false,
            exit_node_dns_resolvers: vec![],
            peer_relay: false,
            service_vips: Default::default(),
            // Cross-stream coupling (S4): `Node` gains `key_signature: Vec<u8>`. Empty here so this
            // exhaustive literal compiles once S4's field lands.
            key_signature: vec![],
        }
    }

    const FUNNEL_PORTS_443_8443: &str =
        "https://tailscale.com/cap/funnel-ports?ports=443,8443,10000-10010";

    #[test]
    fn funnel_access_denies_without_both_attrs() {
        // Neither attr.
        assert!(matches!(
            funnel_access(&funnel_node(&[]), 443),
            Err(FunnelError::NotAllowed)
        ));
        // Only https.
        assert!(matches!(
            funnel_access(&funnel_node(&["https", FUNNEL_PORTS_443_8443]), 443),
            Err(FunnelError::NotAllowed)
        ));
        // Only funnel.
        assert!(matches!(
            funnel_access(&funnel_node(&["funnel", FUNNEL_PORTS_443_8443]), 443),
            Err(FunnelError::NotAllowed)
        ));
    }

    #[test]
    fn funnel_access_denies_disallowed_port() {
        let node = funnel_node(&["https", "funnel", FUNNEL_PORTS_443_8443]);
        assert!(matches!(
            funnel_access(&node, 22),
            Err(FunnelError::PortNotAllowed(22))
        ));
    }

    #[test]
    fn funnel_access_allows_listed_single_and_range_ports() {
        let node = funnel_node(&["https", "funnel", FUNNEL_PORTS_443_8443]);
        // Single ports.
        assert!(funnel_access(&node, 443).is_ok());
        assert!(funnel_access(&node, 8443).is_ok());
        // Range endpoints + interior.
        assert!(funnel_access(&node, 10000).is_ok());
        assert!(funnel_access(&node, 10005).is_ok());
        assert!(funnel_access(&node, 10010).is_ok());
        // Just outside the range.
        assert!(funnel_access(&node, 9999).is_err());
        assert!(funnel_access(&node, 10011).is_err());
    }

    #[test]
    fn check_funnel_port_denies_without_ports_cap() {
        // Can funnel, but no funnel-ports cap at all => every port denied.
        let node = funnel_node(&["https", "funnel"]);
        assert!(node.can_funnel());
        assert!(!node.check_funnel_port(443));
    }

    #[test]
    fn check_funnel_port_denies_empty_ports_query() {
        let node = funnel_node(&[
            "https",
            "funnel",
            "https://tailscale.com/cap/funnel-ports?ports=",
        ]);
        assert!(!node.check_funnel_port(443));
    }

    #[test]
    fn check_funnel_port_rejects_wrong_url_with_ports_query() {
        // A look-alike host carrying ?ports= must NOT be honored: after stripping the query the
        // URL must equal the exact funnel-ports cap. (starts_with the cap prefix is the scan
        // filter, but parse_attr re-validates the full URL.)
        let node = funnel_node(&[
            "https",
            "funnel",
            "https://tailscale.com/cap/funnel-ports-evil?ports=443",
        ]);
        assert!(!node.check_funnel_port(443));
    }

    #[tokio::test]
    async fn listen_funnel_is_fail_closed_unsupported_when_allowed() {
        // Node is allowed to funnel on 443, but the public relay leg + real cert don't exist in
        // this fork: must surface Unsupported (or Cert), never a usable acceptor.
        let node = funnel_node(&["https", "funnel", FUNNEL_PORTS_443_8443]);
        let cfg = ServeConfig {
            name: "host.tail1.ts.net".into(),
            port: 443,
            target: ServeTarget::Accept,
        };
        let err = match listen_funnel(&node, &cfg, FunnelOptions::default()).await {
            Ok(_) => panic!("must not build a Funnel acceptor without relay + real cert"),
            Err(e) => e,
        };
        assert!(matches!(
            err,
            FunnelError::Unsupported { .. } | FunnelError::Cert(_)
        ));
    }

    #[tokio::test]
    async fn listen_funnel_denies_before_cert_when_not_allowed() {
        // Access gate must run first: a node that can't funnel never reaches the cert path.
        let node = funnel_node(&[]);
        let cfg = ServeConfig {
            name: "host.tail1.ts.net".into(),
            port: 443,
            target: ServeTarget::Accept,
        };
        let err = match listen_funnel(&node, &cfg, FunnelOptions::default()).await {
            Ok(_) => panic!("must deny a node that cannot funnel"),
            Err(e) => e,
        };
        assert!(matches!(err, FunnelError::NotAllowed));
    }
}
