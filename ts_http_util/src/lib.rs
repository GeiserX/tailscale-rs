#![doc = include_str!("../README.md")]
#![deny(unsafe_code)]

use bytes::Bytes;
use http::header::{CONNECTION, UPGRADE};
pub use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, header::HOST,
};
use http_body_util::{Empty, Full};
use hyper::body::Incoming;
use tokio::net::TcpStream;

mod client;
mod error;
pub mod http1;
pub mod http2;

pub use client::{Client, ClientExt};
pub use error::Error;
pub use http1::Http1;
pub use http2::Http2;
pub use hyper::upgrade::on as upgrade;
pub use sealed::ResponseExt;

/// The body of an HTTP [`Request`] or [`Response`] that's always empty; i.e., the body will always
/// be zero bytes in length.
pub type EmptyBody = Empty<Bytes>;

/// The body of an HTTP [`Request`] or [`Response`] that may contain one or more bytes; i.e., a body
/// may be present.
pub type BytesBody = Full<Bytes>;

/// A connection that has been upgraded from HTTP/1.1 to a different protocol, such as HTTP/2 or
/// DERP, via HTTP/1.1's upgrade mechanism.protocol upgrade
pub type Upgraded = hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>;

/// Upgrade a [`Response`] from HTTP/1.1 to the requested protocol.
pub async fn do_upgrade(resp: Response<Incoming>) -> hyper::Result<Upgraded> {
    let upgraded = hyper::upgrade::on(resp).await?;
    Ok(hyper_util::rt::TokioIo::new(upgraded))
}

mod sealed {
    use futures::TryStreamExt;
    use http_body_util::{BodyExt, Limited};
    use tokio::io::AsyncRead;
    use tokio_util::io::StreamReader;

    use crate::Error;

    /// Helper methods for [`http::Response`].
    pub trait ResponseExt {
        /// Collect the response body into a [`bytes::Bytes`] with **no size limit**.
        ///
        /// Use this only when the body is locally generated or otherwise trusted to be small. For
        /// any body read from a network peer (a control/DERP/upstream server response — all of which
        /// this fork treats as hostile-capable), prefer
        /// [`collect_bytes_limited`][Self::collect_bytes_limited]: `collect()` here buffers the
        /// *entire* body into memory before returning, so a malicious or MITM'd server answering a
        /// short request with a multi-gigabyte streamed body would OOM the client (a length check
        /// *after* `collect_bytes` is too late — the allocation already happened).
        fn collect_bytes(self) -> impl Future<Output = Result<bytes::Bytes, Error>> + Send;
        /// Collect the response body into a [`bytes::Bytes`], failing if it exceeds `max` bytes.
        ///
        /// The body is wrapped in [`http_body_util::Limited`], which aborts collection as soon as
        /// more than `max` bytes arrive — so the allocation is bounded *during* the read, mirroring
        /// Go's `io.LimitedReader`-bounded body reads. An over-limit body yields
        /// [`Error::BodyTooLarge`] (distinct from a transient [`Error::Io`], so callers can treat it
        /// as terminal). This is the body reader every network-response caller should use; pick `max`
        /// to comfortably fit the largest legitimate response for that endpoint.
        fn collect_bytes_limited(
            self,
            max: usize,
        ) -> impl Future<Output = Result<bytes::Bytes, Error>> + Send;
        /// Convert the response body into an [`AsyncRead`].
        fn into_read(self) -> impl AsyncRead + Send + Unpin + 'static;
    }

    impl<B> ResponseExt for http::Response<B>
    where
        B: hyper::body::Body + Send + Unpin + 'static,
        B::Data: Send + 'static,
        B::Error: core::error::Error + Send + Sync + 'static,
    {
        async fn collect_bytes(self) -> Result<bytes::Bytes, Error> {
            let buf = self
                .into_body()
                .collect()
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "collecting response body");
                    Error::Io
                })?
                .to_bytes();

            Ok(buf)
        }

        async fn collect_bytes_limited(self, max: usize) -> Result<bytes::Bytes, Error> {
            // `Limited` errors (with a boxed `LengthLimitError`) once the body exceeds `max`, so
            // collection stops there instead of buffering an unbounded body — the cap binds the
            // allocation, not just a post-hoc length check.
            let buf = Limited::new(self.into_body(), max)
                .collect()
                .await
                .map_err(|e| {
                    // Distinguish "the peer exceeded the cap" (terminal — an attack/misconfig signal,
                    // not worth retrying) from a transient mid-read I/O failure. `Limited` boxes a
                    // `LengthLimitError` for the former.
                    if e.downcast_ref::<http_body_util::LengthLimitError>()
                        .is_some()
                    {
                        tracing::error!(max, "response body exceeded the size limit");
                        Error::BodyTooLarge
                    } else {
                        tracing::error!(error = %e, max, "collecting response body (limited)");
                        Error::Io
                    }
                })?
                .to_bytes();

            Ok(buf)
        }

        fn into_read(self) -> impl AsyncRead + Send + Unpin + 'static {
            StreamReader::new(
                self.into_body()
                    .into_data_stream()
                    .map_err(tokio::io::Error::other),
            )
        }
    }
}

/// Create a [`Request`] to upgrade from HTTP/1.1 to the given `protocol`, which can be sent to the
/// server via an [`Http1`] client to start the [HTTP/1.1 protocol upgrade] process.
///
/// Some protocols, such as TS2021, require additional headers in the initial request to
/// successfully upgrade; these can be provided via `extra_headers`.
///
/// [HTTP/1.1 protocol upgrade]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Protocol_upgrade_mechanism
pub fn make_upgrade_req(
    u: &url::Url,
    protocol: &str,
    extra_headers: impl IntoIterator<Item = (HeaderName, HeaderValue)>,
) -> Result<Request<EmptyBody>, Error> {
    // Use POST for the upgrade request. Some server implementations accept both
    // GET and POST, but others (e.g. Go's testcontrol) only accept POST. POST
    // is what Go's controlhttp client sends, so use it for widest compatibility.
    let mut req = Request::post(u.as_str())
        .header(HOST, u.host_str().ok_or(Error::InvalidInput)?)
        .header(UPGRADE, protocol)
        .header(CONNECTION, "Upgrade")
        .body(EmptyBody::new())
        .map_err(|e| {
            tracing::error!(error = %e, "creating upgrade request");
            Error::InvalidInput
        })?;

    req.headers_mut().extend(extra_headers);

    Ok(req)
}

/// Produce a `Host` header for the given URL.
///
/// Includes the port when the URL carries a non-default one (`u.port()` is `Some`), per
/// RFC 7230 §5.4 — e.g. `localhost:14000`. Origin servers that reconstruct their own absolute
/// URLs from the `Host` header (such as an ACME directory emitting `newNonce`/`newAccount`
/// endpoints) would otherwise drop the port and advertise unreachable `:443` URLs.
///
/// Returns `None` if `u.host_str()` is `None` or includes non-ascii-printable characters.
pub fn host_header(u: &url::Url) -> Option<(HeaderName, HeaderValue)> {
    let host = match u.port() {
        Some(port) => format!("{}:{port}", u.host_str()?),
        None => u.host_str()?.to_owned(),
    };
    Some((HOST, HeaderValue::from_str(&host).ok()?))
}

async fn dial_tcp(url: &url::Url) -> Result<TcpStream, Error> {
    let conn = TcpStream::connect((
        url.host_str().ok_or(Error::InvalidInput)?,
        url.port_or_known_default()
            .ok_or(Error::InvalidInput)
            .inspect_err(|_err| tracing::error!("unknown url port"))?,
    ))
    .await
    .map_err(|e| {
        tracing::error!(error = %e, %url, "dialing tcp");
        Error::Io
    })?;

    Ok(conn)
}

async fn dial_tls(
    url: &url::Url,
    alpn: impl IntoIterator<Item = Vec<u8>>,
) -> Result<ts_tls_util::TlsStream<TcpStream>, Error> {
    let server_name = ts_tls_util::server_name(url)
        .ok_or_else(|| {
            tracing::error!(%url, "parsing server name");
            Error::InvalidInput
        })?
        .to_owned();

    let conn = dial_tcp(url).await?;

    ts_tls_util::connect_alpn(server_name, conn, alpn)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "dialing tls connection");

            Error::Io
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> url::Url {
        url::Url::parse(s).unwrap()
    }

    #[test]
    fn host_header_omits_default_https_port() {
        let (name, value) = host_header(&url("https://h/")).unwrap();
        assert_eq!(name, HOST);
        assert_eq!(value, "h");
        assert!(!value.to_str().unwrap().contains(":443"));
    }

    #[test]
    fn host_header_omits_default_http_port() {
        let (name, value) = host_header(&url("http://h/")).unwrap();
        assert_eq!(name, HOST);
        assert_eq!(value, "h");
        assert!(!value.to_str().unwrap().contains(":80"));
    }

    #[test]
    fn host_header_includes_non_default_port() {
        let (name, value) = host_header(&url("https://localhost:14000/")).unwrap();
        assert_eq!(name, HOST);
        assert_eq!(value, "localhost:14000");
    }

    /// `collect_bytes_limited` must accept a body up to and including `max` bytes and reject anything
    /// larger, bounding the allocation during the read (a control/DERP/upstream server can't OOM the
    /// client by streaming an oversized body to a small request). Pins the boundary: `< max` and
    /// `== max` succeed, `max + 1` errors.
    #[tokio::test]
    async fn collect_bytes_limited_caps_the_body() {
        use http_body_util::Full;

        async fn collect(len: usize, max: usize) -> Result<bytes::Bytes, Error> {
            let body = Full::new(Bytes::from(vec![0u8; len]));
            Response::new(body).collect_bytes_limited(max).await
        }

        const MAX: usize = 1024;

        // Below the cap: ok, full body returned.
        let under = collect(MAX - 1, MAX)
            .await
            .expect("a body under the cap is collected");
        assert_eq!(under.len(), MAX - 1);

        // Exactly at the cap: ok (Limited allows == max, rejects only > max).
        let at = collect(MAX, MAX)
            .await
            .expect("a body exactly at the cap is collected");
        assert_eq!(at.len(), MAX);

        // Over the cap: rejected with the distinct BodyTooLarge (not a generic Io), allocation
        // bounded — never buffers the whole oversized body.
        let over = collect(MAX + 1, MAX).await;
        assert!(
            matches!(over, Err(Error::BodyTooLarge)),
            "a body over the cap must be rejected as BodyTooLarge, got {over:?}"
        );
    }
}
