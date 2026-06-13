//! Control RPCs for Tailnet-Lock (TKA) chain sync: `GET /machine/tka/sync/offer` and
//! `GET /machine/tka/sync/send`, over the Noise (ts2021) transport.
//!
//! Mirrors Go's `tkaDoSyncOffer` / `tkaDoSyncSend` (`ipn/ipnlocal/tailnet-lock.go`, v1.100.0): the
//! node sends its [`TkaSyncOfferRequest`] (head + ancestor sample), control replies with the AUMs
//! the node is missing + control's own offer; the node then sends control the AUMs *it* is missing
//! in a [`TkaSyncSendRequest`]. Both are HTTP `GET`s carrying a JSON body (yes — a GET with a body,
//! matching upstream), and both responses are read behind a 10 MiB limit.
//!
//! Transport only: these functions speak the [`ts_control_serde`] wire types (base32 head strings,
//! base64'd raw-CBOR AUM bytes). Converting to/from the domain `ts_tka::{Aum, AumHash, SyncOffer}`
//! and driving the offer→Inform→send handshake is the runtime layer's job — keeping `ts_control`
//! free of a `ts_tka` dependency (it is the wire crate, `ts_tka` is the chain-logic crate).

use core::time::Duration;
use std::fmt;

use bytes::Bytes;
use ts_capabilityversion::CapabilityVersion;
use ts_control_serde::{
    TkaBootstrapRequest, TkaBootstrapResponse, TkaSyncOfferRequest, TkaSyncOfferResponse,
    TkaSyncSendRequest, TkaSyncSendResponse,
};
use ts_http_util::{BytesBody, ClientExt, Http2, ResponseExt, StatusCode};
use ts_keys::NodePublicKey;
use url::Url;

use crate::tokio::connect::ConnectionError;

const LOAD_BALANCER_HEADER_KEY: &str = "Ts-Lb";

/// Upper bound on a single TKA-sync RPC (fresh Noise connect + GET + response read). A hung control
/// plane is abandoned and reported as a transient [`TkaSyncError::NetworkError`] rather than pinning
/// a half-open connection. Matches the id-token RPC's 30s bound.
pub(crate) const TKA_SYNC_TIMEOUT: Duration = Duration::from_secs(30);

/// Cap on a TKA-sync response body (Go reads these behind a 10 MiB `io.LimitedReader`). A sync batch
/// of AUMs is small in practice; the cap stops a hostile/buggy control plane from streaming an
/// unbounded body into memory.
pub(crate) const MAX_TKA_SYNC_RESPONSE: usize = 10 * 1024 * 1024;

/// The internal failure kinds a TKA-sync request can surface (kept coarse for the public surface).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TkaSyncInternalErrorKind {
    /// Failed to build/parse a URL for the request.
    Url,
    /// Failed to serialize the request or deserialize the response body.
    SerDe,
    /// An unsuccessful (non-2xx) HTTP request, or an HTTP/transport error not classed as transient.
    Http,
    /// The response body was not valid UTF-8.
    Utf8,
    /// The response body exceeded `MAX_TKA_SYNC_RESPONSE`.
    TooLarge,
}

impl fmt::Display for TkaSyncInternalErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TkaSyncInternalErrorKind::Url => write!(f, "URL parsing error"),
            TkaSyncInternalErrorKind::SerDe => write!(f, "serialization/deserialization error"),
            TkaSyncInternalErrorKind::Http => write!(f, "unsuccessful HTTP request"),
            TkaSyncInternalErrorKind::Utf8 => write!(f, "invalid UTF8"),
            TkaSyncInternalErrorKind::TooLarge => write!(f, "response body too large"),
        }
    }
}

/// Errors from a TKA-sync RPC.
#[derive(Debug, thiserror::Error, Clone, Eq, PartialEq)]
pub enum TkaSyncError {
    /// A transient network error; the request may succeed on retry.
    #[error("network error during TKA sync")]
    NetworkError,
    /// Control does not support TKA sync at this endpoint (404/501) — the tailnet has no lock, or the
    /// control plane is too old. Callers treat this as "no Authority obtained" and stay inert; it is
    /// **not** an error to surface up the netmap stream.
    #[error("control does not support TKA sync")]
    Unsupported,
    /// An internal failure (URL/serde/HTTP/UTF-8/size). Detail kept coarse for the public surface.
    #[error("error during TKA sync: {0}")]
    Internal(TkaSyncInternalErrorKind),
}

impl From<url::ParseError> for TkaSyncError {
    fn from(error: url::ParseError) -> Self {
        tracing::error!(%error, "bad URL building TKA-sync request");
        TkaSyncError::Internal(TkaSyncInternalErrorKind::Url)
    }
}

impl From<serde_json::Error> for TkaSyncError {
    fn from(error: serde_json::Error) -> Self {
        tracing::error!(%error, "serde error in TKA-sync request");
        TkaSyncError::Internal(TkaSyncInternalErrorKind::SerDe)
    }
}

impl From<core::str::Utf8Error> for TkaSyncError {
    fn from(error: core::str::Utf8Error) -> Self {
        tracing::error!(%error, "invalid utf8 in TKA-sync response");
        TkaSyncError::Internal(TkaSyncInternalErrorKind::Utf8)
    }
}

impl From<ts_http_util::Error> for TkaSyncError {
    fn from(error: ts_http_util::Error) -> Self {
        tracing::error!(%error, "http error in TKA-sync request");
        if crate::http_error_is_recoverable(error) {
            TkaSyncError::NetworkError
        } else {
            TkaSyncError::Internal(TkaSyncInternalErrorKind::Http)
        }
    }
}

impl From<ConnectionError> for TkaSyncError {
    fn from(error: ConnectionError) -> Self {
        use crate::tokio::connect::InternalErrorKind as Conn;
        match error {
            ConnectionError::NetworkError => TkaSyncError::NetworkError,
            ConnectionError::Internal(k) => TkaSyncError::Internal(match k {
                Conn::Url => TkaSyncInternalErrorKind::Url,
                Conn::SerDe => TkaSyncInternalErrorKind::SerDe,
                Conn::Http
                | Conn::MessageFormat
                | Conn::Io
                | Conn::ChallengeLength
                | Conn::NoiseHandshake => TkaSyncInternalErrorKind::Http,
            }),
        }
    }
}

/// Send a TKA `sync/offer` to control: our chain `offer`, returning control's response (its own
/// offer + the AUMs we are missing). Opens a fresh Noise channel, bounded by `TKA_SYNC_TIMEOUT`.
pub async fn tka_sync_offer(
    control_url: &Url,
    node_keystate: &ts_keys::NodeState,
    offer: TkaSyncOfferRequest,
    allow_http_key_fetch: bool,
) -> Result<TkaSyncOfferResponse, TkaSyncError> {
    let run = async {
        let http2_conn = crate::tokio::connect(
            control_url,
            &node_keystate.machine_keys,
            allow_http_key_fetch,
        )
        .await?;
        tka_sync_offer_with(control_url, node_keystate, offer, &http2_conn).await
    };
    match tokio::time::timeout(TKA_SYNC_TIMEOUT, run).await {
        Ok(result) => result,
        Err(_elapsed) => {
            tracing::error!(timeout = ?TKA_SYNC_TIMEOUT, "TKA sync/offer timed out");
            Err(TkaSyncError::NetworkError)
        }
    }
}

/// The offer RPC over an already-established Noise channel (factored out so the connect + send is
/// timeout-wrappable and the send is testable against a mock `Http2`).
pub(crate) async fn tka_sync_offer_with(
    control_url: &Url,
    node_keystate: &ts_keys::NodeState,
    mut offer: TkaSyncOfferRequest,
    http2_conn: &Http2<BytesBody>,
) -> Result<TkaSyncOfferResponse, TkaSyncError> {
    let node_public_key = node_keystate.node_keys.public;
    // The request always carries this node's identity + the current capability version, regardless
    // of how the caller built the offer body.
    offer.node_key = node_public_key;
    offer.version = CapabilityVersion::CURRENT;

    let body = serde_json::to_string(&offer)?;
    let url = control_url.join("machine/tka/sync/offer")?;
    tracing::debug!(url = %url.as_str(), "TKA sync/offer to control");

    let response = http2_conn
        .get_with_body(
            &url,
            [lb_header(&node_public_key)],
            Bytes::from(body).into(),
        )
        .await?;
    let status = response.status();
    let body = response
        .collect_bytes_limited(MAX_TKA_SYNC_RESPONSE)
        .await?;
    parse_offer_response(status, &body)
}

/// Send a TKA `sync/send` to control: our (post-Inform) `send` request with the AUMs control is
/// missing, returning control's resulting head. Fresh Noise channel, bounded by `TKA_SYNC_TIMEOUT`.
pub async fn tka_sync_send(
    control_url: &Url,
    node_keystate: &ts_keys::NodeState,
    send: TkaSyncSendRequest,
    allow_http_key_fetch: bool,
) -> Result<TkaSyncSendResponse, TkaSyncError> {
    let run = async {
        let http2_conn = crate::tokio::connect(
            control_url,
            &node_keystate.machine_keys,
            allow_http_key_fetch,
        )
        .await?;
        tka_sync_send_with(control_url, node_keystate, send, &http2_conn).await
    };
    match tokio::time::timeout(TKA_SYNC_TIMEOUT, run).await {
        Ok(result) => result,
        Err(_elapsed) => {
            tracing::error!(timeout = ?TKA_SYNC_TIMEOUT, "TKA sync/send timed out");
            Err(TkaSyncError::NetworkError)
        }
    }
}

/// The send RPC over an already-established Noise channel.
pub(crate) async fn tka_sync_send_with(
    control_url: &Url,
    node_keystate: &ts_keys::NodeState,
    mut send: TkaSyncSendRequest,
    http2_conn: &Http2<BytesBody>,
) -> Result<TkaSyncSendResponse, TkaSyncError> {
    let node_public_key = node_keystate.node_keys.public;
    send.node_key = node_public_key;
    send.version = CapabilityVersion::CURRENT;

    let body = serde_json::to_string(&send)?;
    let url = control_url.join("machine/tka/sync/send")?;
    tracing::debug!(url = %url.as_str(), "TKA sync/send to control");

    let response = http2_conn
        .get_with_body(
            &url,
            [lb_header(&node_public_key)],
            Bytes::from(body).into(),
        )
        .await?;
    let status = response.status();
    let body = response
        .collect_bytes_limited(MAX_TKA_SYNC_RESPONSE)
        .await?;
    parse_send_response(status, &body)
}

/// Fetch the TKA bootstrap (genesis AUM) from control: the entry point that gives a node with no
/// chain yet the initial AUM to build its `Authority` from, before the offer/send catch-up
/// (Go `tkaFetchBootstrap`). `head` is the node's current known head (empty when it has none).
/// Fresh Noise channel, bounded by `TKA_SYNC_TIMEOUT`.
pub async fn tka_bootstrap(
    control_url: &Url,
    node_keystate: &ts_keys::NodeState,
    head: alloc::string::String,
    allow_http_key_fetch: bool,
) -> Result<TkaBootstrapResponse, TkaSyncError> {
    let run = async {
        let http2_conn = crate::tokio::connect(
            control_url,
            &node_keystate.machine_keys,
            allow_http_key_fetch,
        )
        .await?;
        tka_bootstrap_with(control_url, node_keystate, head, &http2_conn).await
    };
    match tokio::time::timeout(TKA_SYNC_TIMEOUT, run).await {
        Ok(result) => result,
        Err(_elapsed) => {
            tracing::error!(timeout = ?TKA_SYNC_TIMEOUT, "TKA bootstrap timed out");
            Err(TkaSyncError::NetworkError)
        }
    }
}

/// The bootstrap RPC over an already-established Noise channel.
pub(crate) async fn tka_bootstrap_with(
    control_url: &Url,
    node_keystate: &ts_keys::NodeState,
    head: alloc::string::String,
    http2_conn: &Http2<BytesBody>,
) -> Result<TkaBootstrapResponse, TkaSyncError> {
    let node_public_key = node_keystate.node_keys.public;
    let req = TkaBootstrapRequest {
        version: CapabilityVersion::CURRENT,
        node_key: node_public_key,
        head,
    };
    let body = serde_json::to_string(&req)?;
    let url = control_url.join("machine/tka/bootstrap")?;
    tracing::debug!(url = %url.as_str(), "TKA bootstrap to control");

    let response = http2_conn
        .get_with_body(
            &url,
            [lb_header(&node_public_key)],
            Bytes::from(body).into(),
        )
        .await?;
    let status = response.status();
    let body = response
        .collect_bytes_limited(MAX_TKA_SYNC_RESPONSE)
        .await?;
    parse_bootstrap_response(status, &body)
}

/// The `Ts-Lb` load-balancer header (the node public key), as every other `/machine/*` RPC sets.
pub(crate) fn lb_header(
    node_public_key: &NodePublicKey,
) -> (ts_http_util::HeaderName, ts_http_util::HeaderValue) {
    (
        LOAD_BALANCER_HEADER_KEY.parse().unwrap(),
        node_public_key.to_string().parse().unwrap(),
    )
}

/// Map a non-2xx status to the right error: 404/501 ⇒ [`TkaSyncError::Unsupported`] (control has no
/// TKA endpoint — stay inert), anything else ⇒ a coarse HTTP internal error. Pure (no I/O), so the
/// status/body branch logic is unit-testable without a live stream.
pub(crate) fn classify_status(status: StatusCode, body: &[u8]) -> Option<TkaSyncError> {
    if status.is_success() {
        return None;
    }
    if status == StatusCode::NOT_FOUND || status == StatusCode::NOT_IMPLEMENTED {
        tracing::info!(%status, "control has no TKA-sync endpoint; staying inert");
        return Some(TkaSyncError::Unsupported);
    }
    let mut truncated = body.to_vec();
    truncated.truncate(512);
    let preview = core::str::from_utf8(&truncated).unwrap_or("<invalid utf8>");
    tracing::error!(body = %preview, %status, "TKA-sync request failed");
    Some(TkaSyncError::Internal(TkaSyncInternalErrorKind::Http))
}

fn parse_offer_response(
    status: StatusCode,
    body: &[u8],
) -> Result<TkaSyncOfferResponse, TkaSyncError> {
    if let Some(err) = classify_status(status, body) {
        return Err(err);
    }
    // Defense-in-depth: the network read now uses `collect_bytes_limited(MAX_TKA_SYNC_RESPONSE)`, so
    // an over-cap body is already rejected (as `BodyTooLarge`) before reaching here. This length
    // guard still covers the pure-`&[u8]` parse path (e.g. unit tests, or any future non-limited
    // caller) and keeps the typed `TooLarge` outcome for it.
    if body.len() > MAX_TKA_SYNC_RESPONSE {
        return Err(TkaSyncError::Internal(TkaSyncInternalErrorKind::TooLarge));
    }
    let body = core::str::from_utf8(body)?;
    Ok(serde_json::from_str(body)?)
}

fn parse_send_response(
    status: StatusCode,
    body: &[u8],
) -> Result<TkaSyncSendResponse, TkaSyncError> {
    if let Some(err) = classify_status(status, body) {
        return Err(err);
    }
    if body.len() > MAX_TKA_SYNC_RESPONSE {
        return Err(TkaSyncError::Internal(TkaSyncInternalErrorKind::TooLarge));
    }
    let body = core::str::from_utf8(body)?;
    Ok(serde_json::from_str(body)?)
}

fn parse_bootstrap_response(
    status: StatusCode,
    body: &[u8],
) -> Result<TkaBootstrapResponse, TkaSyncError> {
    if let Some(err) = classify_status(status, body) {
        return Err(err);
    }
    if body.len() > MAX_TKA_SYNC_RESPONSE {
        return Err(TkaSyncError::Internal(TkaSyncInternalErrorKind::TooLarge));
    }
    let body = core::str::from_utf8(body)?;
    Ok(serde_json::from_str(body)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_offer_response_ok() {
        let json = br#"{"Head":"AEBAGBAF","Ancestors":["MFRGGZDF"],"MissingAUMs":["AQID"]}"#;
        let resp = parse_offer_response(StatusCode::OK, json).expect("parse");
        assert_eq!(resp.head, "AEBAGBAF");
        assert_eq!(resp.ancestors, alloc::vec!["MFRGGZDF".to_string()]);
        assert_eq!(resp.missing_aums, alloc::vec![alloc::vec![1u8, 2, 3]]);
    }

    #[test]
    fn parse_offer_response_empty_missing_is_up_to_date() {
        let json = br#"{"Head":"AEBAGBAF","Ancestors":[]}"#;
        let resp = parse_offer_response(StatusCode::OK, json).expect("parse");
        assert!(resp.missing_aums.is_empty());
    }

    #[test]
    fn unsupported_status_maps_to_unsupported() {
        assert_eq!(
            parse_offer_response(StatusCode::NOT_FOUND, b"nope").unwrap_err(),
            TkaSyncError::Unsupported
        );
        assert_eq!(
            parse_send_response(StatusCode::NOT_IMPLEMENTED, b"").unwrap_err(),
            TkaSyncError::Unsupported
        );
    }

    #[test]
    fn other_non_2xx_is_http_internal() {
        assert_eq!(
            parse_offer_response(StatusCode::INTERNAL_SERVER_ERROR, b"boom").unwrap_err(),
            TkaSyncError::Internal(TkaSyncInternalErrorKind::Http)
        );
    }

    #[test]
    fn malformed_body_is_serde_error() {
        let err = parse_offer_response(StatusCode::OK, b"not json").unwrap_err();
        assert_eq!(err, TkaSyncError::Internal(TkaSyncInternalErrorKind::SerDe));
    }

    #[test]
    fn parse_send_response_ok() {
        let resp = parse_send_response(StatusCode::OK, br#"{"Head":"MFRGGZDF"}"#).expect("parse");
        assert_eq!(resp.head, "MFRGGZDF");
    }

    #[test]
    fn parse_bootstrap_response_ok() {
        // GenesisAUM "AQID" = bytes {1,2,3}.
        let json = br#"{"GenesisAUM":"AQID","DisablementSecret":"/w=="}"#;
        let resp = parse_bootstrap_response(StatusCode::OK, json).expect("parse");
        assert_eq!(resp.genesis_aum, alloc::vec![1u8, 2, 3]);
        assert_eq!(resp.disablement_secret, alloc::vec![0xffu8]);
    }

    #[test]
    fn parse_bootstrap_response_empty_when_no_genesis() {
        let resp = parse_bootstrap_response(StatusCode::OK, b"{}").expect("parse");
        assert!(
            resp.genesis_aum.is_empty(),
            "no genesis ⇒ empty (TKA not enabled)"
        );
    }

    #[test]
    fn parse_bootstrap_unsupported_status() {
        assert_eq!(
            parse_bootstrap_response(StatusCode::NOT_FOUND, b"").unwrap_err(),
            TkaSyncError::Unsupported
        );
    }
}
