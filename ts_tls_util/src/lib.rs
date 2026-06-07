#![doc = include_str!("../README.md")]

use std::sync::{Arc, LazyLock};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{
    TlsConnector,
    rustls::{ClientConfig, RootCertStore, crypto::ring::default_provider},
};
pub use tokio_rustls::{client::TlsStream, rustls::pki_types::ServerName};
use url::Url;

#[cfg(feature = "insecure")]
mod insecure;

#[cfg(feature = "insecure")]
pub use insecure::connect_insecure;

mod pinned;

pub use pinned::connect_pinned;

/// Env var naming a PEM file of additional trust-anchor certificate(s) to add to
/// the root store, on top of the public webpki roots. This is how a self-hosted
/// control server with a private/self-signed CA is trusted
/// without disabling verification. Unset ⇒ public roots only (unchanged default).
const EXTRA_CA_PEM_VAR: &str = "TS_RS_EXTRA_CA_PEM";

static ROOT_CERT_STORE: LazyLock<Arc<RootCertStore>> = LazyLock::new(|| {
    let mut store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };

    // Additively trust a private control-plane CA when configured. Failures are
    // logged but non-fatal: the public roots still stand, and a genuinely
    // unreachable/invalid CA surfaces as a handshake error at connect time
    // rather than silently weakening trust.
    if let Ok(path) = std::env::var(EXTRA_CA_PEM_VAR) {
        match load_pem_certs(&path) {
            Ok(certs) => {
                let (added, ignored) = store.add_parsable_certificates(certs);
                tracing::info!(
                    %path, added, ignored,
                    "loaded extra control-plane CA cert(s) into root store"
                );
            }
            Err(e) => {
                tracing::error!(error = %e, %path, "failed to load {EXTRA_CA_PEM_VAR}");
            }
        }
    }

    Arc::new(store)
});

/// Read and PEM-decode all certificates from `path`.
fn load_pem_certs(
    path: &str,
) -> std::io::Result<Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>>> {
    let pem = std::fs::read(path)?;
    let mut reader = std::io::BufReader::new(&pem[..]);
    rustls_pemfile::certs(&mut reader).collect()
}

/// Establishes a TLS stream with a server over an existing connection.
///
/// See module-level documentation for information on root certificates.
pub async fn connect<Io>(server_name: ServerName<'_>, io: Io) -> std::io::Result<TlsStream<Io>>
where
    Io: AsyncRead + AsyncWrite + Unpin,
{
    connect_alpn::<Io>(server_name, io, []).await
}

/// Establishes a TLS stream with a server over an existing connection, with an optional set of
/// ALPN protocols to negotiate.
///
/// See module-level documentation for information on root certificates.
pub async fn connect_alpn<Io>(
    server_name: ServerName<'_>,
    io: Io,
    alpn: impl IntoIterator<Item = Vec<u8>>,
) -> tokio::io::Result<TlsStream<Io>>
where
    Io: AsyncRead + AsyncWrite + Unpin,
{
    // Pin the ring provider explicitly. `ClientConfig::builder()` auto-detects the
    // process-default provider and panics when feature unification enables both
    // ring and aws-lc-rs (e.g. another dependency pulls aws-lc-rs into the final
    // binary). Being explicit keeps this ring-only and panic-free.
    let mut rustls_config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("rustls provider/protocol setup failed: {e}"),
            )
        })?
        .with_root_certificates(ROOT_CERT_STORE.clone())
        .with_no_client_auth();

    rustls_config
        .alpn_protocols
        .extend(alpn.into_iter().map(|x| x.to_owned()));

    let connector = TlsConnector::from(Arc::new(rustls_config));

    let stream = connector.connect(server_name.to_owned(), io).await?;

    Ok(stream)
}

/// If possible, converts the host portion of the given [`Url`] to a [`ServerName`] for establishing
/// TLS streams.
pub fn server_name(url: &Url) -> Option<ServerName<'_>> {
    ServerName::try_from(url.host_str()?).ok()
}
