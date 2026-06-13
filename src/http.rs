//! A [`hyper`]-compatible connector that routes outbound HTTP requests over the tailnet.
//!
//! This is the analog of Go `tsnet.Server.HTTPClient`, whose entire mechanism is
//! `&http.Client{Transport: &http.Transport{DialContext: s.Dial}}` — a bare dialer injection with no
//! extra client defaults. [`TailnetConnector`] is that injection for the Rust `hyper` ecosystem:
//! given an `http://` request [`Uri`], it resolves the host as a MagicDNS name (or IPv4 literal) and
//! dials it into the overlay (default port 80), so the request egresses over the tailnet rather than
//! the host's network. Redirects, pooling, and timeouts are the hyper client's concern — the
//! connector only supplies the transport, exactly like Go's `DialContext`.
//!
//! Obtain one from [`Device::http_connector`](crate::Device::http_connector) and hand it to
//! `hyper_util::client::legacy::Client::builder(...).build(connector)`.
//!
//! Available only with the **`hyper`** crate feature.
//!
//! # TLS — this is a PLAINTEXT connector
//!
//! [`TailnetConnector`] yields a **plain** overlay TCP stream and performs **no TLS**. Unlike Go's
//! `http.Transport` (which wraps the `DialContext` conn in TLS for `https://` itself), hyper's legacy
//! `Client` does no TLS — it speaks HTTP directly over whatever stream the connector returns. So an
//! `https://` request through a bare `TailnetConnector` would be sent **cleartext onto port 443**;
//! this connector therefore **rejects** `https`/`wss` URIs (with `BadRequest`) rather than dial them
//! into a silent plaintext-on-TLS-port failure. Traffic over the tailnet is still WireGuard-encrypted
//! hop-to-hop (the host's origin IP never leaks), but there is no end-to-end TLS / peer-certificate
//! validation.
//!
//! For real HTTPS over the tailnet, wrap this connector in a TLS connector — e.g.
//! `hyper_rustls::HttpsConnectorBuilder::new().with_native_roots()?.https_or_http().enable_http1().wrap_connector(connector)`
//! — which performs the TLS handshake over the tailnet stream this connector supplies.
//!
//! # IPv4-only
//!
//! Like the rest of this fork's tailnet surface, the connector is IPv4-only: hosts resolve to a
//! tailnet IPv4 (or are dialed as an IPv4 literal). An IPv6-only destination is not reachable even
//! with [`Config::enable_ipv6`](crate::Config), unlike [`Device::dial`](crate::Device::dial).
//!
//! # Example
//!
//! ```rust,no_run
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn core::error::Error>> {
//! # use tailscale::{Config, Device};
//! use hyper_util::{client::legacy::Client, rt::TokioExecutor};
//!
//! let dev = Device::new(
//!     &Config::default_with_key_file("tsrs_keys.json").await?,
//!     Some("YOUR_AUTH_KEY".to_owned()),
//! ).await?;
//!
//! // A hyper client that dials every (http://) request over the tailnet — the analog of Go
//! // `tsnet.Server.HTTPClient`. (Body type `String` here just to name the generic; use whatever
//! // `http_body::Body` your requests carry. For https, wrap `connector` in a TLS connector first.)
//! let connector = dev.http_connector().await?;
//! let client: Client<_, String> = Client::builder(TokioExecutor::new()).build(connector);
//!
//! let resp = client.get("http://my-peer:8080/".parse()?).await?;
//! println!("status: {}", resp.status());
//! #   Ok(())
//! # }
//! ```

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use hyper::Uri;
use hyper_util::{
    client::legacy::connect::{Connected, Connection},
    rt::TokioIo,
};
use tower_service::Service;

use crate::{Error, InternalErrorKind, loopback::OverlayDialer, netstack};

/// A [`hyper`] connector that dials over the tailnet (the analog of Go `http.Transport.DialContext =
/// tsnet.Server.Dial`). Build one with [`Device::http_connector`](crate::Device::http_connector) and
/// pass it to `hyper_util::client::legacy::Client::builder(...).build(connector)`.
///
/// Cloneable and `Send`/`'static` (it holds only the `&Device`-free [`OverlayDialer`]), so it
/// satisfies hyper-util's connector bounds and can back a pooled `Client`.
#[derive(Clone)]
pub struct TailnetConnector {
    dialer: OverlayDialer,
}

impl TailnetConnector {
    pub(crate) fn new(dialer: OverlayDialer) -> Self {
        Self { dialer }
    }
}

/// The connection [`TailnetConnector`] yields: a tailnet [`netstack::TcpStream`] wrapped so it
/// satisfies hyper's IO + [`Connection`] requirements. [`TokioIo`] adapts the stream's tokio
/// `AsyncRead`/`AsyncWrite` to hyper's `rt::{Read,Write}`, and the [`Connection`] impl reports the
/// (unremarkable) connection metadata hyper needs.
pub struct TailnetStream(TokioIo<netstack::TcpStream>);

impl hyper::rt::Read for TailnetStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl hyper::rt::Write for TailnetStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

impl Connection for TailnetStream {
    fn connected(&self) -> Connected {
        // A plain overlay TCP connection: no proxy, and no ALPN to advertise (this connector does no
        // TLS — if a caller wraps it in a TLS connector for https, that wrapper reports its own
        // negotiated ALPN). `Connected::new()` is the correct unremarkable default.
        Connected::new()
    }
}

impl Service<Uri> for TailnetConnector {
    type Response = TailnetStream;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<TailnetStream, Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // The dialer is always ready; back-pressure (port allocation, handshake) is per-call inside
        // `call`, matching how Go's `DialContext` does all its work per connection.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let dialer = self.dialer.clone();
        Box::pin(async move {
            let (host, port) = host_port(&uri)?;
            dialer.dial_host_port(&host, port).await.map(|stream| {
                TailnetStream(TokioIo::new(stream))
            })
        })
    }
}

/// Extract the `(host, port)` to dial from an **`http://`** request [`Uri`], defaulting the port to
/// 80 when none is given. The host has any IPv6 brackets stripped (a literal `[::1]`-style authority
/// must not reach the resolver with its brackets).
///
/// This connector is **plaintext-only** (it yields a bare overlay TCP stream and does no TLS — see
/// [`TailnetConnector`]). A secure scheme (`https`/`wss`) is therefore **rejected** with
/// [`InternalErrorKind::BadRequest`] rather than dialed: hyper's legacy `Client` does not wrap the
/// returned stream in TLS, so honoring `https` here would send a cleartext request onto port 443 and
/// silently fail. For HTTPS over the tailnet, wrap this connector in a TLS connector (see the module
/// docs). The scheme is validated even when an explicit port is present, so `https://peer:443` /
/// `wss://peer:443` cannot slip a plaintext dial onto a TLS port.
///
/// Distinct from [`crate::dial`]'s `split_host_port`: a `Uri` arrives already split into host + port,
/// and HTTP supplies a scheme-default port (which the string dialer deliberately does not).
fn host_port(uri: &Uri) -> Result<(String, u16), Error> {
    // Plaintext connector: only the cleartext HTTP scheme (or a scheme-less authority, treated as
    // http) is dialable. Reject https/wss (would be cleartext-on-TLS-port) and anything unknown.
    match uri.scheme_str() {
        Some("http") | None => {}
        _ => return Err(Error::Internal(InternalErrorKind::BadRequest)),
    }
    let host = uri
        .host()
        .ok_or(Error::Internal(InternalErrorKind::BadRequest))?;
    // `Uri::host` returns an IPv6 literal WITH its brackets (`[::1]`); strip them so the host is a
    // bare address/name for the dialer.
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
        .to_string();
    // Default the cleartext-HTTP port to 80 when unspecified (what Go's `http.Transport` computes
    // before calling `DialContext`).
    let port = uri.port_u16().unwrap_or(80);
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_port_defaults_http_to_80() {
        let (h, p) = host_port(&"http://peer/path".parse().unwrap()).unwrap();
        assert_eq!((h.as_str(), p), ("peer", 80));
    }

    #[test]
    fn host_port_rejects_https() {
        // Plaintext connector: https must be rejected (not dialed cleartext onto 443), even with an
        // explicit port, so it can't slip a plaintext dial onto a TLS port.
        for uri in [
            "https://peer.tailnet.ts.net/",
            "https://peer:443/",
            "https://peer:8443/",
        ] {
            assert!(
                matches!(
                    host_port(&uri.parse().unwrap()).unwrap_err(),
                    Error::Internal(InternalErrorKind::BadRequest)
                ),
                "https must be rejected: {uri}"
            );
        }
    }

    #[test]
    fn host_port_rejects_wss_even_with_explicit_port() {
        // wss with an explicit port must NOT bypass scheme validation into a plaintext dial.
        let err = host_port(&"wss://peer:443/".parse().unwrap()).unwrap_err();
        assert!(matches!(err, Error::Internal(InternalErrorKind::BadRequest)));
    }

    #[test]
    fn host_port_explicit_port_wins() {
        let (h, p) = host_port(&"http://peer:8080/".parse().unwrap()).unwrap();
        assert_eq!((h.as_str(), p), ("peer", 8080));
    }

    #[test]
    fn host_port_ipv4_literal() {
        let (h, p) = host_port(&"http://100.64.0.1:9000/".parse().unwrap()).unwrap();
        assert_eq!((h.as_str(), p), ("100.64.0.1", 9000));
    }

    #[test]
    fn host_port_strips_ipv6_brackets() {
        // `http://[::1]:80/` — the dialer must see `::1`, not `[::1]` (it will then fail the v4-only
        // resolve, but the bracket-stripping itself must be correct).
        let (h, p) = host_port(&"http://[::1]:80/".parse().unwrap()).unwrap();
        assert_eq!((h.as_str(), p), ("::1", 80));
    }

    #[test]
    fn host_port_unknown_scheme_without_port_rejected() {
        // A non-http(s) scheme with no explicit port can't be dialed without guessing.
        let err = host_port(&"ftp://peer/".parse().unwrap()).unwrap_err();
        assert!(matches!(
            err,
            Error::Internal(InternalErrorKind::BadRequest)
        ));
    }
}
