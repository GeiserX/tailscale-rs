//! A fake control server for tests: an HTTP/2 connection over an in-memory duplex whose server
//! side records every request body, so a test can check what the client actually sends.

use std::convert::Infallible;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::body::{Frame, Incoming};
use tokio::sync::mpsc;
use ts_http_util::{BytesBody, Http2, Request, Response};

/// A request the fake control server received: its path and its JSON body.
pub(crate) type Received = (String, serde_json::Value);

/// Connect to a fake control server. It accepts every registration, keeps a streaming map
/// request open without sending a frame, and answers every other request with an empty `200`.
/// Each request is sent on the returned channel before it is answered.
pub(crate) async fn connect() -> (Http2<BytesBody>, mpsc::UnboundedReceiver<Received>) {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (tx, rx) = mpsc::unbounded_channel();
    let service = hyper::service::service_fn(move |req: Request<Incoming>| {
        let tx = tx.clone();
        async move {
            let path = req.uri().path().to_owned();
            let body = req.into_body().collect().await?.to_bytes();
            let json: serde_json::Value = serde_json::from_slice(&body).expect("a JSON body");
            let streaming = json["Stream"] == true;
            drop(tx.send((path.clone(), json)));
            let body = if path == "/machine/register" {
                full(
                    r#"{"User":{"ID":1},"Login":{"ID":2,"Provider":"","LoginName":""},"NodeKeyExpired":false,"MachineAuthorized":true,"AuthURL":"","Error":""}"#,
                )
            } else if streaming {
                StreamBody::new(futures_util::stream::pending::<
                    Result<Frame<Bytes>, Infallible>,
                >())
                .boxed()
            } else {
                full("")
            };
            Ok::<_, hyper::Error>(Response::new(body))
        }
    });
    tokio::spawn(
        hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
            .serve_connection(hyper_util::rt::TokioIo::new(server_io), service),
    );
    let client = ts_http_util::http2::connect(client_io)
        .await
        .expect("http2 handshake");
    (client, rx)
}

fn full(body: &'static str) -> BoxBody<Bytes, Infallible> {
    Full::new(Bytes::from_static(body.as_bytes())).boxed()
}
