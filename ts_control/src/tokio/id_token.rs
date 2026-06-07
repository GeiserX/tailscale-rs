//! Control RPC to mint an OIDC ID token for this node (workload-identity federation).
//!
//! Mirrors Go's `POST /machine/id-token` over the Noise (ts2021) transport: the node sends a
//! [`TokenRequest`] (`{CapVersion, NodeKey, Audience}`) and control returns a [`TokenResponse`]
//! carrying a signed JWT whose `aud` claim is the requested audience. The node is the token
//! *subject*, not the authenticator — this is token issuance for presenting to a third-party relying
//! party (e.g. AWS/GCP workload-identity federation), not a registration auth path.
//!
//! Requires control capability version ≥ 30 (Go: "2022-03-22: client can request id tokens").

use core::time::Duration;
use std::fmt;

use bytes::Bytes;
use ts_capabilityversion::CapabilityVersion;
use ts_control_serde::{TokenRequest, TokenResponse};
use ts_http_util::{BytesBody, ClientExt, Http2, ResponseExt, StatusCode};
use url::Url;

use crate::tokio::connect::ConnectionError;

const LOAD_BALANCER_HEADER_KEY: &str = "Ts-Lb";

/// Upper bound on a single id-token RPC (fresh Noise connect + POST + response read).
///
/// A hung control plane must not leave a half-open connection pinned forever; on expiry the RPC
/// is abandoned and reported as a transient [`IdTokenError::NetworkError`].
const ID_TOKEN_TIMEOUT: Duration = Duration::from_secs(30);

/// The internal failure kinds an id-token request can surface.
///
/// Private to this module: `IdTokenError` owns its own internal vocabulary rather than borrowing a
/// sibling module's (e.g. registration's). Only the generic kinds this RPC actually produces are
/// represented.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum IdTokenInternalErrorKind {
    /// Failed to build/parse a URL for the request.
    Url,
    /// Failed to serialize the request or deserialize the response body.
    SerDe,
    /// An unsuccessful (non-2xx) HTTP request, or an HTTP/transport error not classed as transient.
    Http,
    /// The response body was not valid UTF-8.
    Utf8,
}

impl fmt::Display for IdTokenInternalErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdTokenInternalErrorKind::Url => write!(f, "URL parsing error"),
            IdTokenInternalErrorKind::SerDe => write!(f, "serialization/deserialization error"),
            IdTokenInternalErrorKind::Http => write!(f, "unsuccessful HTTP request"),
            IdTokenInternalErrorKind::Utf8 => write!(f, "invalid UTF8"),
        }
    }
}

/// Errors from an ID-token request.
#[derive(Debug, thiserror::Error, Clone, Eq, PartialEq)]
pub enum IdTokenError {
    /// A transient network error; the request may succeed on retry.
    #[error("network error requesting id token")]
    NetworkError,
    /// An internal failure (URL/serde/HTTP/UTF-8). Detail kept coarse for the public surface.
    #[error("error requesting id token: {0}")]
    Internal(IdTokenInternalErrorKind),
}

impl From<url::ParseError> for IdTokenError {
    fn from(error: url::ParseError) -> Self {
        tracing::error!(%error, "bad URL building id-token request");
        IdTokenError::Internal(IdTokenInternalErrorKind::Url)
    }
}

impl From<serde_json::Error> for IdTokenError {
    fn from(error: serde_json::Error) -> Self {
        tracing::error!(%error, "serde error in id-token request");
        IdTokenError::Internal(IdTokenInternalErrorKind::SerDe)
    }
}

impl From<core::str::Utf8Error> for IdTokenError {
    fn from(error: core::str::Utf8Error) -> Self {
        tracing::error!(%error, "invalid utf8 in id-token response");
        IdTokenError::Internal(IdTokenInternalErrorKind::Utf8)
    }
}

impl From<ts_http_util::Error> for IdTokenError {
    fn from(error: ts_http_util::Error) -> Self {
        tracing::error!(%error, "http error in id-token request");
        if crate::http_error_is_recoverable(error) {
            IdTokenError::NetworkError
        } else {
            IdTokenError::Internal(IdTokenInternalErrorKind::Http)
        }
    }
}

// The shared Noise `connect` surfaces a `ConnectionError`; fold it into our error. The connect
// crate's richer `InternalErrorKind` is collapsed onto the coarser id-token kinds.
impl From<ConnectionError> for IdTokenError {
    fn from(error: ConnectionError) -> Self {
        use crate::tokio::connect::InternalErrorKind as Conn;
        match error {
            ConnectionError::NetworkError => IdTokenError::NetworkError,
            ConnectionError::Internal(k) => IdTokenError::Internal(match k {
                Conn::Url => IdTokenInternalErrorKind::Url,
                Conn::SerDe => IdTokenInternalErrorKind::SerDe,
                // Everything else is an unsuccessful request/handshake at the Noise layer.
                Conn::Http
                | Conn::MessageFormat
                | Conn::Io
                | Conn::ChallengeLength
                | Conn::NoiseHandshake => IdTokenInternalErrorKind::Http,
            }),
        }
    }
}

/// Request an OIDC ID token for this node from control, scoped to `audience` (the `aud` claim of the
/// returned JWT). Opens a fresh Noise channel and POSTs to `/machine/id-token`. Returns the signed
/// JWT string on success.
///
/// The whole connect + POST + response read is bounded by `ID_TOKEN_TIMEOUT`: a hung control
/// plane is abandoned and reported as [`IdTokenError::NetworkError`] rather than pinning a
/// half-open connection.
pub async fn fetch_id_token(
    config: &crate::Config,
    node_keystate: &ts_keys::NodeState,
    audience: &str,
) -> Result<String, IdTokenError> {
    let control_url = &config.server_url;
    let rpc = async {
        let http2_conn = crate::tokio::connect(control_url, &node_keystate.machine_keys).await?;
        fetch_id_token_with(control_url, node_keystate, audience, &http2_conn).await
    };

    match tokio::time::timeout(ID_TOKEN_TIMEOUT, rpc).await {
        Ok(result) => result,
        Err(_elapsed) => {
            tracing::error!(timeout = ?ID_TOKEN_TIMEOUT, "id-token request timed out");
            Err(IdTokenError::NetworkError)
        }
    }
}

/// Inner: send the `/machine/id-token` POST over an already-established Noise channel.
///
/// Split out from [`fetch_id_token`] so the response-parsing logic ([`parse_token_response`]) is
/// unit-testable independent of the Noise connect.
pub(crate) async fn fetch_id_token_with(
    control_url: &Url,
    node_keystate: &ts_keys::NodeState,
    audience: &str,
    http2_conn: &Http2<BytesBody>,
) -> Result<String, IdTokenError> {
    let node_public_key = node_keystate.node_keys.public;

    let req = TokenRequest {
        cap_version: CapabilityVersion::CURRENT,
        node_key: node_public_key,
        audience: audience.to_string(),
    };

    let body = serde_json::to_string(&req)?;
    let url = control_url.join("machine/id-token")?;

    tracing::debug!(url = %url.as_str(), "requesting id token from control");

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
    parse_token_response(status, &body)
}

/// Turn a `/machine/id-token` HTTP response into the signed JWT string.
///
/// Pure (no I/O): factored out of [`fetch_id_token_with`] so the status/body branch logic is
/// unit-testable without a live stream. A non-2xx status is [`IdTokenInternalErrorKind::Http`]
/// (logging a truncated body); a 2xx body must be UTF-8 JSON deserializing to a [`TokenResponse`].
fn parse_token_response(status: StatusCode, body: &[u8]) -> Result<String, IdTokenError> {
    if !status.is_success() {
        let mut truncated = body.to_vec();
        truncated.truncate(512);
        let preview = core::str::from_utf8(&truncated).unwrap_or("<invalid utf8>");
        tracing::error!(body = %preview, %status, "id-token request failed");
        return Err(IdTokenError::Internal(IdTokenInternalErrorKind::Http));
    }

    let body = core::str::from_utf8(body)?;
    let resp: TokenResponse = serde_json::from_str(body)?;

    Ok(resp.id_token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokio::connect::{ConnectionError, InternalErrorKind as ConnKind};

    // --- Error `From` conversions ---

    #[test]
    fn connection_error_network_maps_to_network() {
        assert_eq!(
            IdTokenError::from(ConnectionError::NetworkError),
            IdTokenError::NetworkError
        );
    }

    #[test]
    fn connection_error_internal_kinds_map_correctly() {
        use IdTokenInternalErrorKind as Id;
        let cases = [
            (ConnKind::Url, Id::Url),
            (ConnKind::SerDe, Id::SerDe),
            (ConnKind::Http, Id::Http),
            (ConnKind::MessageFormat, Id::Http),
            (ConnKind::Io, Id::Http),
            (ConnKind::ChallengeLength, Id::Http),
            (ConnKind::NoiseHandshake, Id::Http),
        ];
        for (conn, expected) in cases {
            assert_eq!(
                IdTokenError::from(ConnectionError::Internal(conn)),
                IdTokenError::Internal(expected),
                "ConnectionError::Internal({conn:?}) should map to Internal({expected:?})"
            );
        }
    }

    #[test]
    fn serde_error_maps_to_internal_serde() {
        let err = serde_json::from_str::<TokenResponse>("not json").unwrap_err();
        assert_eq!(
            IdTokenError::from(err),
            IdTokenError::Internal(IdTokenInternalErrorKind::SerDe)
        );
    }

    #[test]
    fn url_parse_error_maps_to_internal_url() {
        let err = Url::parse("not a url").unwrap_err();
        assert_eq!(
            IdTokenError::from(err),
            IdTokenError::Internal(IdTokenInternalErrorKind::Url)
        );
    }

    #[test]
    fn utf8_error_maps_to_internal_utf8() {
        // Route the invalid bytes through a runtime Vec so the `invalid_from_utf8` lint (which only
        // fires on compile-time-known literals) doesn't flag a genuinely intentional bad input.
        let bytes = vec![0xffu8, 0xfe];
        let err = core::str::from_utf8(&bytes).unwrap_err();
        assert_eq!(
            IdTokenError::from(err),
            IdTokenError::Internal(IdTokenInternalErrorKind::Utf8)
        );
    }

    #[test]
    fn http_util_error_non_recoverable_maps_to_internal_http() {
        // A non-recoverable http error (e.g. an invalid response) folds onto Internal(Http).
        let err = ts_http_util::Error::InvalidResponse;
        assert_eq!(
            IdTokenError::from(err),
            IdTokenError::Internal(IdTokenInternalErrorKind::Http)
        );
    }

    #[test]
    fn http_util_error_recoverable_maps_to_network() {
        // A recoverable http error (transient I/O) is surfaced as a transient NetworkError.
        let err = ts_http_util::Error::Io;
        assert_eq!(IdTokenError::from(err), IdTokenError::NetworkError);
    }

    // --- Response parse ---

    #[test]
    fn parse_token_response_ok() {
        let body = br#"{"id_token":"abc.def.ghi"}"#;
        let token = parse_token_response(StatusCode::OK, body).unwrap();
        assert_eq!(token, "abc.def.ghi");
    }

    #[test]
    fn parse_token_response_non_success_is_http() {
        let err =
            parse_token_response(StatusCode::INTERNAL_SERVER_ERROR, b"upstream boom").unwrap_err();
        assert_eq!(err, IdTokenError::Internal(IdTokenInternalErrorKind::Http));
    }

    #[test]
    fn parse_token_response_invalid_json_is_serde() {
        let err = parse_token_response(StatusCode::OK, b"{not json").unwrap_err();
        assert_eq!(err, IdTokenError::Internal(IdTokenInternalErrorKind::SerDe));
    }

    #[test]
    fn parse_token_response_invalid_utf8_is_utf8() {
        let err = parse_token_response(StatusCode::OK, &[0xff, 0xfe, 0xfd]).unwrap_err();
        assert_eq!(err, IdTokenError::Internal(IdTokenInternalErrorKind::Utf8));
    }

    #[test]
    fn parse_token_response_missing_id_token_errors() {
        let err = parse_token_response(StatusCode::OK, b"{}").unwrap_err();
        // Missing required `id_token` field is a deserialization failure.
        assert_eq!(err, IdTokenError::Internal(IdTokenInternalErrorKind::SerDe));
    }
}
