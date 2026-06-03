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

use crate::cert::{self, CertError};

/// What to do with a stream once TLS is terminated.
///
/// Scoped down from upstream `ipn.ServeConfig` to the two shapes this fork needs:
/// hand the decrypted bytes to the embedder, or reverse-proxy to a local target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
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
        if let ServeTarget::Proxy { to } = &self.target
            && to.trim().is_empty()
        {
            return Err(CertError::Acme("proxy target must not be empty".into()));
        }
        Ok(())
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
/// fork returns [`CertError::Unimplemented`] (no ACME-over-control RPC exists).
/// This function therefore returns the same error rather than ever falling back
/// to plaintext or a self-signed certificate. When the cert RPC lands, this
/// starts returning a working acceptor with no caller change.
pub async fn listen_tls(cfg: &ServeConfig) -> Result<TlsAcceptor, CertError> {
    cfg.validate()?;
    let cert = cert::get_certificate(&cfg.name).await?;
    tls_acceptor(cert)
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
}
