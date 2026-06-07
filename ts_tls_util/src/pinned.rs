//! TLS connections to a server whose leaf certificate is pinned by SHA-256 of
//! its DER encoding.
//!
//! This is how a self-hosted / self-signed DERP server (e.g. one embedded in a
//! self-hosted control plane) is trusted without a public CA: the control plane distributes a
//! `sha256-raw:<hex>` pin in the DERP map, and we accept exactly the cert whose
//! DER hashes to that pin. Unlike [`crate::connect_insecure`], this still proves
//! the peer holds the certificate's private key (the handshake signature is
//! verified against the pinned cert's public key), so a MITM that cannot present
//! the exact pinned cert is rejected — fail-closed.

use std::sync::Arc;

use ring::digest::{SHA256, digest};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{
    TlsConnector,
    client::TlsStream,
    rustls::{
        self, ClientConfig, DigitallySignedStruct, SignatureScheme,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        crypto::{
            CryptoProvider, ring::default_provider, verify_tls12_signature, verify_tls13_signature,
        },
        pki_types::{CertificateDer, ServerName, UnixTime},
    },
};

/// Establish a TLS stream to a server, accepting exactly the leaf certificate
/// whose DER encoding has the given SHA-256 digest.
///
/// `server_name` is still sent in the ClientHello SNI, but the certificate's
/// name and chain are **not** validated against the public PKI — only the pin is
/// enforced. The handshake signature is still verified against the presented
/// (pinned) certificate, so this is not equivalent to skipping verification.
pub async fn connect_pinned<Io>(
    server_name: ServerName<'static>,
    pin_sha256: [u8; 32],
    io: Io,
) -> tokio::io::Result<TlsStream<Io>>
where
    Io: AsyncRead + AsyncWrite + Unpin,
{
    let provider = Arc::new(default_provider());
    let verifier = Arc::new(PinnedCertVerifier::with_provider(
        pin_sha256,
        provider.clone(),
    ));

    // Pin the provider to ring explicitly via `builder_with_provider` rather than
    // `ClientConfig::builder()`. The latter auto-detects the process-default
    // provider and PANICS when feature unification enables both ring and
    // aws-lc-rs (which happens whenever any other dependency in the final binary
    // pulls aws-lc-rs). Being explicit keeps this path ring-only and panic-free
    // regardless of the surrounding crate graph.
    let rustls_config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("rustls provider/protocol setup failed: {e}"),
            )
        })?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(rustls_config));
    connector.connect(server_name, io).await
}

/// A rustls certificate verifier that accepts a server iff its leaf certificate's
/// DER encoding matches a pinned SHA-256 digest. Chain and name validation are
/// replaced by the pin; handshake-signature verification is delegated to the
/// crypto provider so the peer must still prove possession of the cert's key.
#[derive(Debug)]
struct PinnedCertVerifier {
    pin_sha256: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl PinnedCertVerifier {
    fn with_provider(pin_sha256: [u8; 32], provider: Arc<CryptoProvider>) -> Self {
        Self {
            pin_sha256,
            provider,
        }
    }

    #[cfg(test)]
    fn new(pin_sha256: [u8; 32]) -> Self {
        Self::with_provider(pin_sha256, Arc::new(default_provider()))
    }

    /// Constant-time check that `end_entity`'s DER hashes to the pin.
    fn pin_matches(&self, end_entity: &CertificateDer<'_>) -> bool {
        let got = digest(&SHA256, end_entity.as_ref());
        got.as_ref().ct_eq(&self.pin_sha256).into()
    }
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if self.pin_matches(end_entity) {
            Ok(ServerCertVerified::assertion())
        } else {
            // Fail-closed: an unpinned/mismatched cert is a hard error, never a
            // silent downgrade to public-CA or no validation.
            Err(rustls::Error::General(
                "self-signed DERP cert does not match the configured SHA-256 pin".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn self_signed() -> (rcgen::Certificate, rcgen::KeyPair, [u8; 32]) {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["derp.test".to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let der = cert.der();
        let pin: [u8; 32] = digest(&SHA256, der.as_ref()).as_ref().try_into().unwrap();
        (cert, key, pin)
    }

    #[test]
    fn pin_matches_exact_cert() {
        let (cert, _key, pin) = self_signed();
        let verifier = PinnedCertVerifier::new(pin);
        assert!(verifier.pin_matches(cert.der()));
    }

    #[test]
    fn pin_rejects_different_cert() {
        let (cert_a, _ka, _pin_a) = self_signed();
        let (_cert_b, _kb, pin_b) = self_signed();
        // Verifier pinned to cert B must reject cert A.
        let verifier = PinnedCertVerifier::new(pin_b);
        assert!(!verifier.pin_matches(cert_a.der()));
    }

    #[test]
    fn pin_rejects_truncated_or_zero_pin() {
        let (cert, _key, _pin) = self_signed();
        let verifier = PinnedCertVerifier::new([0u8; 32]);
        assert!(!verifier.pin_matches(cert.der()));
    }

    #[test]
    fn verify_server_cert_errors_on_mismatch() {
        let (cert, _key, _pin) = self_signed();
        let verifier = PinnedCertVerifier::new([0u8; 32]);
        let now = UnixTime::now();
        let res = verifier.verify_server_cert(
            cert.der(),
            &[],
            &ServerName::try_from("derp.test").unwrap(),
            &[],
            now,
        );
        assert!(res.is_err());
    }

    #[test]
    fn verify_server_cert_accepts_pinned() {
        let (cert, _key, pin) = self_signed();
        let verifier = PinnedCertVerifier::new(pin);
        let now = UnixTime::now();
        let res = verifier.verify_server_cert(
            cert.der(),
            &[],
            &ServerName::try_from("derp.test").unwrap(),
            &[],
            now,
        );
        assert!(res.is_ok());
    }
}
