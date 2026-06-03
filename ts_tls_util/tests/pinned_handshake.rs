//! End-to-end TLS handshake tests for the self-signed DERP cert-pinning path.
//!
//! Stands up a real rustls server with a self-signed cert over a TCP loopback,
//! then drives `ts_tls_util::connect_pinned` against it. This exercises the full
//! handshake — including the TLS signature verification delegated to ring — not
//! just the digest comparison in the verifier's unit tests.

use std::sync::Arc;

use ring::digest::{SHA256, digest};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ServerConfig,
        crypto::ring::default_provider,
        pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    },
};

/// Make a self-signed cert/key and return (server-config, der, sha256-pin).
fn server_material() -> (ServerConfig, CertificateDer<'static>, [u8; 32]) {
    let key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec!["derp.test".to_string()]).unwrap();
    let cert = params.self_signed(&key).unwrap();

    let cert_der = cert.der().clone();
    let pin: [u8; 32] = digest(&SHA256, cert_der.as_ref())
        .as_ref()
        .try_into()
        .unwrap();

    let key_der = PrivateKeyDer::try_from(key.serialize_der()).unwrap();
    // Pin ring explicitly so the server side doesn't hit rustls' multi-provider
    // auto-detect panic when aws-lc-rs is also unified into the test binary.
    let config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();

    (config, cert_der, pin)
}

/// Spawn a one-shot TLS echo-ish server: accept one conn, send a known byte
/// after the handshake, then drop. Returns the bound address.
async fn spawn_server(config: ServerConfig) -> std::net::SocketAddr {
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await
            && let Ok(mut tls) = acceptor.accept(tcp).await
        {
            let _w = tls.write_all(b"OK").await;
            let _f = tls.flush().await;
        }
    });

    addr
}

#[tokio::test]
async fn correct_pin_handshakes_and_reads() {
    let (config, _der, pin) = server_material();
    let addr = spawn_server(config).await;

    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from("derp.test").unwrap();

    let mut tls = ts_tls_util::connect_pinned(name, pin, tcp)
        .await
        .expect("handshake with correct pin should succeed");

    let mut buf = [0u8; 2];
    tls.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"OK");
}

#[tokio::test]
async fn wrong_pin_fails_closed() {
    let (config, _der, _real_pin) = server_material();
    let addr = spawn_server(config).await;

    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from("derp.test").unwrap();

    // Pin to all-zeros: the server's real cert can never match. The handshake
    // must error (fail-closed), never silently succeed.
    let res = ts_tls_util::connect_pinned(name, [0u8; 32], tcp).await;
    assert!(
        res.is_err(),
        "handshake with a mismatched pin must fail closed, got Ok"
    );
}
