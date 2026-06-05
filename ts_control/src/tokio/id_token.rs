//! Control RPC to mint an OIDC ID token for this node (workload-identity federation).
//!
//! Mirrors Go's `POST /machine/id-token` over the Noise (ts2021) transport: the node sends a
//! [`TokenRequest`] (`{CapVersion, NodeKey, Audience}`) and control returns a [`TokenResponse`]
//! carrying a signed JWT whose `aud` claim is the requested audience. The node is the token
//! *subject*, not the authenticator — this is token issuance for presenting to a third-party relying
//! party (e.g. AWS/GCP workload-identity federation), not a registration auth path.
//!
//! Requires control capability version ≥ 30 (Go: "2022-03-22: client can request id tokens").

use bytes::Bytes;
use ts_capabilityversion::CapabilityVersion;
use ts_control_serde::{TokenRequest, TokenResponse};
use ts_http_util::{BytesBody, ClientExt, Http2, ResponseExt};
use url::Url;

use crate::tokio::{connect::ConnectionError, register::InternalErrorKind};

const LOAD_BALANCER_HEADER_KEY: &str = "Ts-Lb";

/// Errors from an ID-token request.
#[derive(Debug, thiserror::Error, Clone, Eq, PartialEq)]
pub enum IdTokenError {
    /// A transient network error; the request may succeed on retry.
    #[error("network error requesting id token")]
    NetworkError,
    /// An internal failure (URL/serde/HTTP/UTF-8). Detail kept coarse for the public surface.
    #[error("error requesting id token: {0}")]
    Internal(InternalErrorKind),
}

impl From<url::ParseError> for IdTokenError {
    fn from(error: url::ParseError) -> Self {
        tracing::error!(%error, "bad URL building id-token request");
        IdTokenError::Internal(InternalErrorKind::Url)
    }
}

impl From<serde_json::Error> for IdTokenError {
    fn from(error: serde_json::Error) -> Self {
        tracing::error!(%error, "serde error in id-token request");
        IdTokenError::Internal(InternalErrorKind::SerDe)
    }
}

impl From<core::str::Utf8Error> for IdTokenError {
    fn from(error: core::str::Utf8Error) -> Self {
        tracing::error!(%error, "invalid utf8 in id-token response");
        IdTokenError::Internal(InternalErrorKind::Utf8)
    }
}

impl From<ts_http_util::Error> for IdTokenError {
    fn from(error: ts_http_util::Error) -> Self {
        tracing::error!(%error, "http error in id-token request");
        if crate::http_error_is_recoverable(error) {
            IdTokenError::NetworkError
        } else {
            IdTokenError::Internal(InternalErrorKind::Http)
        }
    }
}

// The shared Noise `connect` surfaces a `ConnectionError`; fold it into our error. The connect
// crate's richer `InternalErrorKind` is collapsed onto the coarser registration kinds.
impl From<ConnectionError> for IdTokenError {
    fn from(error: ConnectionError) -> Self {
        use crate::tokio::connect::InternalErrorKind as Conn;
        match error {
            ConnectionError::NetworkError => IdTokenError::NetworkError,
            ConnectionError::Internal(k) => IdTokenError::Internal(match k {
                Conn::Url => InternalErrorKind::Url,
                Conn::SerDe => InternalErrorKind::SerDe,
                // Everything else is an unsuccessful request/handshake at the Noise layer.
                Conn::Http
                | Conn::MessageFormat
                | Conn::Io
                | Conn::ChallengeLength
                | Conn::NoiseHandshake => InternalErrorKind::Http,
            }),
        }
    }
}

/// Request an OIDC ID token for this node from control, scoped to `audience` (the `aud` claim of the
/// returned JWT). Opens a fresh Noise channel and POSTs to `/machine/id-token`. Returns the signed
/// JWT string on success.
pub async fn fetch_id_token(
    config: &crate::Config,
    node_keystate: &ts_keys::NodeState,
    audience: &str,
) -> Result<String, IdTokenError> {
    let control_url = &config.server_url;
    let http2_conn = crate::tokio::connect(control_url, &node_keystate.machine_keys).await?;
    fetch_id_token_with(control_url, node_keystate, audience, &http2_conn).await
}

/// Inner: send the `/machine/id-token` POST over an already-established Noise channel. Split out so
/// the request/response handling is unit-testable independent of the Noise connect.
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
    if !status.is_success() {
        let mut body = response.collect_bytes().await.unwrap_or_default();
        body.truncate(512);
        let body = core::str::from_utf8(&body).unwrap_or("<invalid utf8>");
        tracing::error!(%body, %status, "id-token request failed");
        return Err(IdTokenError::Internal(InternalErrorKind::Http));
    }

    let body = response.collect_bytes().await?;
    let body = core::str::from_utf8(&body)?;
    let resp: TokenResponse = serde_json::from_str(body)?;

    Ok(resp.id_token)
}
