//! Control RPC to publish a DNS record for this node (`POST /machine/set-dns`).
//!
//! Mirrors Go's `POST /machine/set-dns` over the Noise (ts2021) transport: the node sends a
//! [`SetDnsRequest`] (`{Version, NodeKey, Name, Type, Value}`) and control publishes the record
//! into the tailnet's `ts.net` zone, returning an empty [`SetDnsResponse`] on success.
//!
//! The product use is the ACME **DNS-01** challenge: publish a
//! `_acme-challenge.<host>.<tailnet>.ts.net` `TXT` record so an ACME CA can verify domain control.
//! This RPC is a generic control primitive (not itself `acme`-gated), but in this fork it is only
//! exercised by the (feature-gated) ACME engine.

use core::time::Duration;
use std::fmt;

use bytes::Bytes;
use ts_capabilityversion::CapabilityVersion;
use ts_control_serde::{SetDnsRequest, SetDnsResponse};
use ts_http_util::{BytesBody, ClientExt, Http2, ResponseExt, StatusCode};
use url::Url;

use crate::tokio::connect::ConnectionError;

const LOAD_BALANCER_HEADER_KEY: &str = "Ts-Lb";

/// Upper bound on a single set-dns RPC (fresh Noise connect + POST + response read).
///
/// A hung control plane must not leave a half-open connection pinned forever; on expiry the RPC
/// is abandoned and reported as a transient [`SetDnsError::NetworkError`].
const SET_DNS_TIMEOUT: Duration = Duration::from_secs(30);

/// The internal failure kinds a set-dns request can surface.
///
/// Private to this module: `SetDnsError` owns its own internal vocabulary rather than borrowing a
/// sibling module's. Only the generic kinds this RPC actually produces are represented.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SetDnsInternalErrorKind {
    /// Failed to build/parse a URL for the request.
    Url,
    /// Failed to serialize the request or deserialize the response body.
    SerDe,
    /// An unsuccessful (non-2xx) HTTP request, or an HTTP/transport error not classed as transient.
    Http,
    /// The response body was not valid UTF-8.
    Utf8,
}

impl fmt::Display for SetDnsInternalErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SetDnsInternalErrorKind::Url => write!(f, "URL parsing error"),
            SetDnsInternalErrorKind::SerDe => write!(f, "serialization/deserialization error"),
            SetDnsInternalErrorKind::Http => write!(f, "unsuccessful HTTP request"),
            SetDnsInternalErrorKind::Utf8 => write!(f, "invalid UTF8"),
        }
    }
}

/// Errors from a set-dns request.
#[derive(Debug, thiserror::Error, Clone, Eq, PartialEq)]
pub enum SetDnsError {
    /// A transient network error; the request may succeed on retry.
    #[error("network error publishing dns record")]
    NetworkError,
    /// An internal failure (URL/serde/HTTP/UTF-8). Detail kept coarse for the public surface.
    #[error("error publishing dns record: {0}")]
    Internal(SetDnsInternalErrorKind),
}

impl From<url::ParseError> for SetDnsError {
    fn from(error: url::ParseError) -> Self {
        tracing::error!(%error, "bad URL building set-dns request");
        SetDnsError::Internal(SetDnsInternalErrorKind::Url)
    }
}

impl From<serde_json::Error> for SetDnsError {
    fn from(error: serde_json::Error) -> Self {
        tracing::error!(%error, "serde error in set-dns request");
        SetDnsError::Internal(SetDnsInternalErrorKind::SerDe)
    }
}

impl From<core::str::Utf8Error> for SetDnsError {
    fn from(error: core::str::Utf8Error) -> Self {
        tracing::error!(%error, "invalid utf8 in set-dns response");
        SetDnsError::Internal(SetDnsInternalErrorKind::Utf8)
    }
}

impl From<ts_http_util::Error> for SetDnsError {
    fn from(error: ts_http_util::Error) -> Self {
        tracing::error!(%error, "http error in set-dns request");
        if crate::http_error_is_recoverable(error) {
            SetDnsError::NetworkError
        } else {
            SetDnsError::Internal(SetDnsInternalErrorKind::Http)
        }
    }
}

// The shared Noise `connect` surfaces a `ConnectionError`; fold it into our error. The connect
// crate's richer `InternalErrorKind` is collapsed onto the coarser set-dns kinds.
impl From<ConnectionError> for SetDnsError {
    fn from(error: ConnectionError) -> Self {
        use crate::tokio::connect::InternalErrorKind as Conn;
        match error {
            ConnectionError::NetworkError => SetDnsError::NetworkError,
            ConnectionError::Internal(k) => SetDnsError::Internal(match k {
                Conn::Url => SetDnsInternalErrorKind::Url,
                Conn::SerDe => SetDnsInternalErrorKind::SerDe,
                // Everything else is an unsuccessful request/handshake at the Noise layer.
                Conn::Http
                | Conn::MessageFormat
                | Conn::Io
                | Conn::ChallengeLength
                | Conn::NoiseHandshake => SetDnsInternalErrorKind::Http,
            }),
        }
    }
}

/// Publish a DNS record for this node via control (`POST /machine/set-dns`).
///
/// `name`/`record_type`/`value` are the record to publish — e.g.
/// `("_acme-challenge.host.tailnet.ts.net", "TXT", "<base64url-digest>")` for an ACME DNS-01
/// challenge. Opens a fresh Noise channel and POSTs the request. Returns `Ok(())` on a 2xx
/// (the response body is an empty [`SetDnsResponse`]).
///
/// The whole connect + POST + response read is bounded by [`SET_DNS_TIMEOUT`]: a hung control
/// plane is abandoned and reported as [`SetDnsError::NetworkError`] rather than pinning a
/// half-open connection.
pub async fn set_dns(
    config: &crate::Config,
    node_keystate: &ts_keys::NodeState,
    name: &str,
    record_type: &str,
    value: &str,
) -> Result<(), SetDnsError> {
    let control_url = &config.server_url;
    let rpc = async {
        let http2_conn = crate::tokio::connect(control_url, &node_keystate.machine_keys).await?;
        set_dns_with(
            control_url,
            node_keystate,
            name,
            record_type,
            value,
            &http2_conn,
        )
        .await
    };

    match tokio::time::timeout(SET_DNS_TIMEOUT, rpc).await {
        Ok(result) => result,
        Err(_elapsed) => {
            tracing::error!(timeout = ?SET_DNS_TIMEOUT, "set-dns request timed out");
            Err(SetDnsError::NetworkError)
        }
    }
}

/// Inner: send the `/machine/set-dns` POST over an already-established Noise channel.
///
/// Split out from [`set_dns`] so the response-checking logic ([`check_set_dns_status`]) is
/// unit-testable independent of the Noise connect.
pub(crate) async fn set_dns_with(
    control_url: &Url,
    node_keystate: &ts_keys::NodeState,
    name: &str,
    record_type: &str,
    value: &str,
    http2_conn: &Http2<BytesBody>,
) -> Result<(), SetDnsError> {
    let node_public_key = node_keystate.node_keys.public;

    let req = SetDnsRequest {
        version: CapabilityVersion::CURRENT,
        node_key: node_public_key,
        name: name.to_string(),
        r#type: record_type.to_string(),
        value: value.to_string(),
    };

    let body = serde_json::to_string(&req)?;
    let url = control_url.join("machine/set-dns")?;

    tracing::debug!(url = %url.as_str(), name, record_type, "publishing dns record via control");

    let response = http2_conn
        .post(
            &url,
            [(
                LOAD_BALANCER_HEADER_KEY.parse().unwrap(),
                node_public_key.to_string().parse().unwrap(),
            )],
            Bytes::from(body).into(),
        )
        .await?;

    let status = response.status();
    let body = response.collect_bytes().await?;
    check_set_dns_status(status, &body)
}

/// Turn a `/machine/set-dns` HTTP response into a success/failure verdict.
///
/// Pure (no I/O): factored out of [`set_dns_with`] so the status/body branch logic is
/// unit-testable without a live stream. A non-2xx status is [`SetDnsInternalErrorKind::Http`]
/// (logging a truncated body). On 2xx the body is an empty [`SetDnsResponse`]; an empty body is
/// tolerated as success, and a non-empty body is parsed to confirm the shape (Go's
/// `SetDnsResponse{}`).
fn check_set_dns_status(status: StatusCode, body: &[u8]) -> Result<(), SetDnsError> {
    if !status.is_success() {
        let mut truncated = body.to_vec();
        truncated.truncate(512);
        let preview = core::str::from_utf8(&truncated).unwrap_or("<invalid utf8>");
        tracing::error!(body = %preview, %status, "set-dns request failed");
        return Err(SetDnsError::Internal(SetDnsInternalErrorKind::Http));
    }

    let body = core::str::from_utf8(body)?;
    // An empty body is a valid success signal (no `{}` payload required).
    if body.trim().is_empty() {
        return Ok(());
    }
    // Otherwise confirm the body deserializes to the empty `SetDnsResponse` shape.
    let _resp: SetDnsResponse = serde_json::from_str(body)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokio::connect::{ConnectionError, InternalErrorKind as ConnKind};

    // --- Error `From` conversions ---

    #[test]
    fn connection_error_network_maps_to_network() {
        assert_eq!(
            SetDnsError::from(ConnectionError::NetworkError),
            SetDnsError::NetworkError
        );
    }

    #[test]
    fn connection_error_internal_kinds_map_correctly() {
        use SetDnsInternalErrorKind as Sd;
        let cases = [
            (ConnKind::Url, Sd::Url),
            (ConnKind::SerDe, Sd::SerDe),
            (ConnKind::Http, Sd::Http),
            (ConnKind::MessageFormat, Sd::Http),
            (ConnKind::Io, Sd::Http),
            (ConnKind::ChallengeLength, Sd::Http),
            (ConnKind::NoiseHandshake, Sd::Http),
        ];
        for (conn, expected) in cases {
            assert_eq!(
                SetDnsError::from(ConnectionError::Internal(conn)),
                SetDnsError::Internal(expected),
                "ConnectionError::Internal({conn:?}) should map to Internal({expected:?})"
            );
        }
    }

    #[test]
    fn serde_error_maps_to_internal_serde() {
        let err = serde_json::from_str::<SetDnsResponse>("not json").unwrap_err();
        assert_eq!(
            SetDnsError::from(err),
            SetDnsError::Internal(SetDnsInternalErrorKind::SerDe)
        );
    }

    #[test]
    fn url_parse_error_maps_to_internal_url() {
        let err = Url::parse("not a url").unwrap_err();
        assert_eq!(
            SetDnsError::from(err),
            SetDnsError::Internal(SetDnsInternalErrorKind::Url)
        );
    }

    #[test]
    fn utf8_error_maps_to_internal_utf8() {
        // Route the invalid bytes through a runtime Vec so the `invalid_from_utf8` lint (which only
        // fires on compile-time-known literals) doesn't flag a genuinely intentional bad input.
        let bytes = vec![0xffu8, 0xfe];
        let err = core::str::from_utf8(&bytes).unwrap_err();
        assert_eq!(
            SetDnsError::from(err),
            SetDnsError::Internal(SetDnsInternalErrorKind::Utf8)
        );
    }

    #[test]
    fn http_util_error_non_recoverable_maps_to_internal_http() {
        let err = ts_http_util::Error::InvalidResponse;
        assert_eq!(
            SetDnsError::from(err),
            SetDnsError::Internal(SetDnsInternalErrorKind::Http)
        );
    }

    #[test]
    fn http_util_error_recoverable_maps_to_network() {
        let err = ts_http_util::Error::Io;
        assert_eq!(SetDnsError::from(err), SetDnsError::NetworkError);
    }

    // --- Status check ---

    #[test]
    fn check_set_dns_status_ok_empty_body() {
        // The success contract: HTTP 200 with an empty body.
        check_set_dns_status(StatusCode::OK, b"").unwrap();
    }

    #[test]
    fn check_set_dns_status_ok_empty_json() {
        // A `{}` body deserializes to the empty `SetDnsResponse`.
        check_set_dns_status(StatusCode::OK, b"{}").unwrap();
    }

    #[test]
    fn check_set_dns_status_self_hosted_501_is_error() {
        // a self-hosted control plane may not implement `/machine/set-dns` and returns 501 Not Implemented; document
        // that DOA reality — it must surface as an error, never a silent success.
        let err =
            check_set_dns_status(StatusCode::NOT_IMPLEMENTED, b"not implemented").unwrap_err();
        assert_eq!(err, SetDnsError::Internal(SetDnsInternalErrorKind::Http));
    }

    #[test]
    fn check_set_dns_status_500_is_error() {
        let err =
            check_set_dns_status(StatusCode::INTERNAL_SERVER_ERROR, b"upstream boom").unwrap_err();
        assert_eq!(err, SetDnsError::Internal(SetDnsInternalErrorKind::Http));
    }
}
