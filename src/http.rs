//! A [`hyper`]-compatible connector that routes outbound HTTP requests over the tailnet.
//!
//! This is the analog of Go `tsnet.Server.HTTPClient`, whose entire mechanism is
//! `&http.Client{Transport: &http.Transport{DialContext: s.Dial}}` — a bare dialer injection with no
//! extra client defaults. [`TailnetConnector`] is that injection for the Rust `hyper` ecosystem:
//! given a request [`Uri`], it resolves the host as a MagicDNS name (or IPv4 literal) and dials it
//! into the overlay (default port 80 for `http`, 443 for `https`), so the request egresses over the
//! tailnet rather than the host's network. TLS, redirects, pooling, and timeouts are the hyper
//! client's concern — the connector only supplies the transport, exactly like Go's `DialContext`.
//!
//! Obtain one from [`Device::http_connector`](crate::Device::http_connector) and hand it to
//! `hyper_util::client::legacy::Client::builder(...).build(connector)`.
//!
//! Available only with the **`hyper`** crate feature.
//!
//! # Example
//!
//! ```rust,no_run
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn core::error::Error>> {
//! # use tailscale::{Config, Device};
//! use http_body_util::Empty;
//! use hyper::body::Bytes;
//! use hyper_util::{client::legacy::Client, rt::TokioExecutor};
//!
//! let dev = Device::new(
//!     &Config::default_with_key_file("tsrs_keys.json").await?,
//!     Some("YOUR_AUTH_KEY".to_owned()),
//! ).await?;
//!
//! // A hyper client that dials every request over the tailnet (Go `tsnet.Server.HTTPClient`).
//! let connector = dev.http_connector().await?;
//! let client: Client<_, Empty<Bytes>> =
//!     Client::builder(TokioExecutor::new()).build(connector);
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
        // A plain overlay TCP connection — no proxy, no ALPN negotiated here (HTTPS ALPN is the
        // hyper TLS layer's concern, layered above this transport).
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

/// Extract the `(host, port)` to dial from a request [`Uri`], applying the scheme's default port
/// (`http` → 80, `https` → 443) when none is given — mirroring what Go's `http.Transport` computes
/// before calling `DialContext`. The host has any IPv6 brackets stripped (the overlay is IPv4-only,
/// but a literal `[::1]`-style authority must not reach the resolver with its brackets).
fn host_port(uri: &Uri) -> Result<(String, u16), Error> {
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
    let port = match uri.port_u16() {
        Some(p) => p,
        None => match uri.scheme_str() {
            Some("http") | None => 80,
            Some("https") => 443,
            // An unknown scheme with no explicit port is ambiguous — Go would not know how to dial
            // it either. Reject rather than guess.
            Some(_) => return Err(Error::Internal(InternalErrorKind::BadRequest)),
        },
    };
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
    fn host_port_defaults_https_to_443() {
        let (h, p) = host_port(&"https://peer.tailnet.ts.net/".parse().unwrap()).unwrap();
        assert_eq!((h.as_str(), p), ("peer.tailnet.ts.net", 443));
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
