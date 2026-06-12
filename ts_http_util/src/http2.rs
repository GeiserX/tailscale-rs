//! HTTP/2 client implementation, and utilities to establish an HTTP/2 connection over TCP or
//! TLS.
use std::{
    fmt::{Debug, Formatter},
    sync::Arc,
};

use http::{Request, Response};
use hyper::{
    body::{Body, Incoming},
    client::conn::http2::SendRequest,
};
use hyper_util::rt::{TokioExecutor, TokioTimer, tokio::WithHyperIo};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::Mutex,
    task::JoinSet,
};

use crate::{Client, Error};

/// An HTTP/2 client that can connect to a server and send HTTP requests/receive HTTP responses.
#[derive(Clone)]
pub struct Http2<B> {
    inner: Arc<Inner<B>>,
}

impl<B> Debug for Http2<B> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http2").finish_non_exhaustive()
    }
}

struct Inner<B> {
    client: Mutex<SendRequest<B>>,
    _runner: JoinSet<()>,
}

impl<B> Client<B> for Http2<B>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Send + Sync + 'static,
{
    async fn send(&self, req: Request<B>) -> Result<Response<Incoming>, Error> {
        let mut client = self.inner.client.lock().await;

        client
            .send_request(req)
            .await
            .inspect_err(|e| {
                tracing::error!(error = %e, "sending request");
            })
            .map_err(Error::from)
    }
}

/// Establish a connection to an HTTP/2 server over an existing connection.
pub async fn connect<B>(
    io: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
) -> Result<Http2<B>, Error>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: core::error::Error + Send + Sync + 'static,
{
    // Configure HTTP/2 protocol-level keep-alive PINGs. The control map poll is a long-lived
    // stream that can sit idle between netmap updates (control sends an application keep-alive only
    // ~once a minute), so without PINGs a half-open/silently-dead connection is never detected at
    // the transport layer and the poll hangs indefinitely. `keep_alive_while_idle(true)` makes
    // hyper PING even when no request body is in flight, and `keep_alive_timeout` tears the
    // connection down if a PING goes unanswered — turning a dead connection into a read error the
    // caller reconnects from. This is defense-in-depth alongside the read watchdog in the map-poll
    // reader: the PING (≈80s to tear-down) usually wins, and the read watchdog is the backstop for
    // the case where PINGs are answered but no application frame ever flows (a control server stuck
    // *above* the h2 layer). Interval/timeout mirror Go's ~60s keep-alive cadence.
    //
    // The settings apply to every `connect` caller, not just the long poll, but they are inert for
    // the short request/response callers (key fetch, register, set-dns, tka-sync, logout, ACME):
    // each issues one RPC and drops the connection within milliseconds — far inside the 60s
    // interval — so no idle PING is ever emitted on them. PING is a connection-level frame an
    // RFC-9113 §6.7 server MUST answer and never carries a stream id, so it cannot RST a request.
    let (client, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .timer(TokioTimer::new())
        .keep_alive_interval(core::time::Duration::from_secs(60))
        .keep_alive_timeout(core::time::Duration::from_secs(20))
        .keep_alive_while_idle(true)
        .handshake(WithHyperIo::new(io))
        .await
        .inspect_err(|e| {
            tracing::error!(error = %e, "http2 handshake");
        })
        .map_err(Error::from)?;

    let mut tasks = JoinSet::new();

    tasks.spawn(async move {
        if let Err(e) = conn.await {
            tracing::error!(?e, "error in http/2 connection; closing connection");
        }
    });

    Ok(Http2 {
        inner: Arc::new(Inner {
            client: Mutex::new(client),
            _runner: tasks,
        }),
    })
}

/// Establish an HTTP/2 connection to the server at the given `url` over plaintext TCP.
pub async fn connect_tcp<B>(url: &url::Url) -> Result<Http2<B>, Error>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: core::error::Error + Send + Sync + 'static,
{
    let conn = crate::dial_tcp(url).await?;
    connect(conn).await
}

/// Establish an HTTP/2 connection to the server at the given `url` over encrypted TLS.
pub async fn connect_tls<B>(url: &url::Url) -> Result<Http2<B>, Error>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: core::error::Error + Send + Sync + 'static,
{
    let conn = crate::dial_tls(url, [b"h2".to_vec()]).await?;
    connect(conn).await
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http_body_util::Empty;
    use tracing_test::traced_test;

    use super::*;
    use crate::ClientExt;

    #[tokio::test]
    #[traced_test]
    async fn http2_over_tls_over_tcp() {
        if !ts_test_util::run_net_tests() {
            return;
        }

        let url: url::Url = "https://controlplane.tailscale.com/key".parse().unwrap();
        let client = connect_tls::<Empty<Bytes>>(&url).await.unwrap();

        let resp = client.get(&url, []).await.unwrap();
        tracing::info!("{:?}", resp);
    }
}
