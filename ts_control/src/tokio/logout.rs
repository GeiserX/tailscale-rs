//! Control RPC to log this node out of the tailnet (deregister / expire the node key).
//!
//! Mirrors Go `tsnet`'s `LocalClient.Logout` at the control-protocol layer: re-`POST`s
//! `/machine/register` over a fresh Noise (ts2021) channel with the node's **current** node key and
//! an [`expiry`](ts_control_serde::RegisterRequest::expiry) set in the past. Per the Tailscale
//! control protocol, when `expiry` is in the past *and* `node_key` is the current key for this node,
//! control expires the node immediately — it drops out of every peer's netmap and must re-register
//! (re-authenticate) to rejoin.
//!
//! This matters for **non-ephemeral** nodes: an ephemeral node is GC'd by control shortly after it
//! disconnects, but a persistent node lingers in the tailnet (visible to peers, counting against the
//! machine limit) for ~24h after the process exits unless it is explicitly logged out. Calling this
//! before teardown deregisters it now. Ephemeral nodes may call it too — it just brings the GC
//! forward.
//!
//! This is a control-plane state change only: it does not tear down the local datapath (the caller
//! does that via the normal runtime shutdown). It also does not delete or rotate the on-disk node
//! key — re-registering with the same key (e.g. a fresh `Device::new`) is the re-login path.

use core::time::Duration;
use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use ts_capabilityversion::CapabilityVersion;
use ts_control_serde::{HostInfo, RegisterRequest};
use ts_http_util::{BytesBody, ClientExt, Http2, ResponseExt, StatusCode};
use url::Url;

use crate::tokio::connect::ConnectionError;

const LOAD_BALANCER_HEADER_KEY: &str = "Ts-Lb";

/// Upper bound on a single logout RPC (fresh Noise connect + POST + response read).
///
/// A hung control plane must not pin a half-open connection forever; on expiry the RPC is abandoned
/// and reported as a transient [`LogoutError::NetworkError`]. Same budget as the id-token RPC.
const LOGOUT_TIMEOUT: Duration = Duration::from_secs(30);

/// How far in the past to backdate the node-key expiry, in seconds. Any past instant deregisters the
/// node; a small fixed skew avoids a borderline "is now in the past yet?" race against control's
/// clock (and tolerates minor client/server clock skew).
const EXPIRY_BACKDATE_SECS: u64 = 10;

/// A `DateTime<Utc>` a few seconds in the past, used as the logout expiry. Built from `SystemTime`
/// (chrono's `clock` feature / `Utc::now()` is not enabled in this workspace, so the timestamp is
/// derived from the std clock and converted). Falls back to the Unix epoch if the system clock is
/// before 1970 (control still treats epoch as "in the past", so logout still works) or if the
/// backdated value somehow overflows the representable range.
fn past_expiry() -> DateTime<Utc> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .saturating_sub(EXPIRY_BACKDATE_SECS);
    DateTime::<Utc>::from_timestamp(secs as i64, 0).unwrap_or(DateTime::<Utc>::UNIX_EPOCH)
}

/// The internal failure kinds a logout request can surface.
///
/// Private vocabulary for this RPC (mirrors `id_token`'s), covering only the kinds this path
/// actually produces.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum LogoutInternalErrorKind {
    /// Failed to build/parse a URL for the request.
    Url,
    /// Failed to serialize the request body.
    SerDe,
    /// An unsuccessful (non-2xx) HTTP request, or an HTTP/transport error not classed as transient.
    Http,
}

impl fmt::Display for LogoutInternalErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogoutInternalErrorKind::Url => write!(f, "URL parsing error"),
            LogoutInternalErrorKind::SerDe => write!(f, "serialization error"),
            LogoutInternalErrorKind::Http => write!(f, "unsuccessful HTTP request"),
        }
    }
}

/// Errors from a logout request.
#[derive(Debug, thiserror::Error, Clone, Eq, PartialEq)]
pub enum LogoutError {
    /// A transient network error; the request may succeed on retry. The node may or may not have
    /// been expired — logout is idempotent, so retrying is safe.
    #[error("network error logging out")]
    NetworkError,
    /// An internal failure (URL/serde/HTTP). Detail kept coarse for the public surface.
    #[error("error logging out: {0}")]
    Internal(LogoutInternalErrorKind),
}

impl From<url::ParseError> for LogoutError {
    fn from(error: url::ParseError) -> Self {
        tracing::error!(%error, "bad URL building logout request");
        LogoutError::Internal(LogoutInternalErrorKind::Url)
    }
}

impl From<serde_json::Error> for LogoutError {
    fn from(error: serde_json::Error) -> Self {
        tracing::error!(%error, "serde error in logout request");
        LogoutError::Internal(LogoutInternalErrorKind::SerDe)
    }
}

impl From<ts_http_util::Error> for LogoutError {
    fn from(error: ts_http_util::Error) -> Self {
        tracing::error!(%error, "http error in logout request");
        if crate::http_error_is_recoverable(error) {
            LogoutError::NetworkError
        } else {
            LogoutError::Internal(LogoutInternalErrorKind::Http)
        }
    }
}

// The shared Noise `connect` surfaces a `ConnectionError`; fold it into our error (same collapse as
// `id_token`).
impl From<ConnectionError> for LogoutError {
    fn from(error: ConnectionError) -> Self {
        use crate::tokio::connect::InternalErrorKind as Conn;
        match error {
            ConnectionError::NetworkError => LogoutError::NetworkError,
            ConnectionError::Internal(k) => LogoutError::Internal(match k {
                Conn::Url => LogoutInternalErrorKind::Url,
                Conn::SerDe => LogoutInternalErrorKind::SerDe,
                Conn::Http
                | Conn::MessageFormat
                | Conn::Io
                | Conn::ChallengeLength
                | Conn::NoiseHandshake => LogoutInternalErrorKind::Http,
            }),
        }
    }
}

/// Log this node out of the tailnet: deregister it by expiring its current node key.
///
/// Opens a fresh Noise channel and re-`POST`s `/machine/register` with the node's current node key
/// and a past [`expiry`](RegisterRequest::expiry), which control honors by expiring the node now.
/// The whole connect + POST + response read is bounded by [`LOGOUT_TIMEOUT`]; a hung control plane
/// is abandoned and reported as [`LogoutError::NetworkError`].
///
/// Idempotent: logging out an already-expired/unknown node is a no-op as far as the caller is
/// concerned (control accepts the request; the node is simply already gone).
pub async fn logout(
    config: &crate::Config,
    node_keystate: &ts_keys::NodeState,
) -> Result<(), LogoutError> {
    let control_url = &config.server_url;
    let rpc = async {
        let http2_conn = crate::tokio::connect(
            control_url,
            &node_keystate.machine_keys,
            config.allow_http_key_fetch,
        )
        .await?;
        logout_with(config, control_url, node_keystate, &http2_conn).await
    };

    match tokio::time::timeout(LOGOUT_TIMEOUT, rpc).await {
        Ok(result) => result,
        Err(_elapsed) => {
            tracing::error!(timeout = ?LOGOUT_TIMEOUT, "logout request timed out");
            Err(LogoutError::NetworkError)
        }
    }
}

/// Inner: send the deregistering `/machine/register` POST over an already-established Noise channel.
///
/// Split out from [`logout`] so the response handling ([`classify_logout_response`]) is unit-testable
/// independent of the Noise connect.
pub(crate) async fn logout_with(
    config: &crate::Config,
    control_url: &Url,
    node_keystate: &ts_keys::NodeState,
    http2_conn: &Http2<BytesBody>,
) -> Result<(), LogoutError> {
    let node_public_key = node_keystate.node_keys.public;

    // A logout is a *registration* of the CURRENT node key with a past expiry. Control rejects a
    // skeleton request (a near-empty RegisterRequest 500s on Tailscale SaaS), so this mirrors the
    // normal `register()` request shape — same node key, NL key, and HostInfo identity — and only
    // adds the backdated `expiry` that tells control to expire the node now. Auth/ephemeral are
    // omitted: re-authentication is not part of a logout, and the node already exists.
    let logout_req = RegisterRequest {
        version: CapabilityVersion::CURRENT,
        node_key: node_public_key,
        nl_key: Some(node_keystate.network_lock_keys.public),
        expiry: Some(past_expiry()),
        hostinfo: HostInfo {
            hostname: config.hostname.as_deref().map(std::borrow::Cow::Borrowed),
            app: &config.format_client_name(),
            ipn_version: crate::PKG_VERSION,
            ..Default::default()
        },
        ..Default::default()
    };

    let body = serde_json::to_string(&logout_req)?;
    let url = control_url.join("machine/register")?;

    tracing::debug!(url = %url.as_str(), "logging out (expiring node key) via control");

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
    let body = response
        .collect_bytes_limited(crate::MAX_CONTROL_RESPONSE)
        .await
        .unwrap_or_default();
    classify_logout_response(status, &body)
}

/// Turn a logout `/machine/register` HTTP response into a result.
///
/// Pure (no I/O): factored out of [`logout_with`] so the status branch is unit-testable without a
/// live stream. Any 2xx is success (control accepted the expiry); a non-2xx is
/// [`LogoutInternalErrorKind::Http`], logging a truncated body for diagnosis.
///
/// Note: unlike registration we do NOT inspect the `RegisterResponse` body for `MachineAuthorized` —
/// expiring a node needs no authorization decision, and an already-gone node still answers 2xx.
fn classify_logout_response(status: StatusCode, body: &[u8]) -> Result<(), LogoutError> {
    if !status.is_success() {
        tracing::error!(%status, "logout request failed");
        // The response body is logged only at debug to keep any control-side diagnostic text out of
        // default-level logs (defense-in-depth; control's /machine/register error bodies are
        // status text, not credentials, but we don't surface them by default).
        let mut truncated = body.to_vec();
        truncated.truncate(512);
        let preview = core::str::from_utf8(&truncated).unwrap_or("<invalid utf8>");
        tracing::debug!(body = %preview, %status, "logout failure response body");
        return Err(LogoutError::Internal(LogoutInternalErrorKind::Http));
    }
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
            LogoutError::from(ConnectionError::NetworkError),
            LogoutError::NetworkError
        );
    }

    #[test]
    fn connection_error_internal_kinds_map_correctly() {
        use LogoutInternalErrorKind as L;
        let cases = [
            (ConnKind::Url, L::Url),
            (ConnKind::SerDe, L::SerDe),
            (ConnKind::Http, L::Http),
            (ConnKind::MessageFormat, L::Http),
            (ConnKind::Io, L::Http),
            (ConnKind::ChallengeLength, L::Http),
            (ConnKind::NoiseHandshake, L::Http),
        ];
        for (conn, expected) in cases {
            assert_eq!(
                LogoutError::from(ConnectionError::Internal(conn)),
                LogoutError::Internal(expected),
                "ConnectionError::Internal({conn:?}) should map to Internal({expected:?})"
            );
        }
    }

    #[test]
    fn http_util_error_recoverable_maps_to_network() {
        assert_eq!(
            LogoutError::from(ts_http_util::Error::Io),
            LogoutError::NetworkError
        );
    }

    #[test]
    fn http_util_error_non_recoverable_maps_to_internal_http() {
        assert_eq!(
            LogoutError::from(ts_http_util::Error::InvalidResponse),
            LogoutError::Internal(LogoutInternalErrorKind::Http)
        );
    }

    // --- Response classification ---

    #[test]
    fn classify_logout_response_2xx_is_ok() {
        assert!(classify_logout_response(StatusCode::OK, b"{}").is_ok());
        // An empty body on success is fine — we don't parse the body on logout.
        assert!(classify_logout_response(StatusCode::NO_CONTENT, b"").is_ok());
    }

    #[test]
    fn classify_logout_response_non_success_is_http() {
        let err = classify_logout_response(StatusCode::INTERNAL_SERVER_ERROR, b"boom").unwrap_err();
        assert_eq!(err, LogoutError::Internal(LogoutInternalErrorKind::Http));
    }

    #[test]
    fn classify_logout_response_invalid_utf8_body_still_classifies() {
        // A non-2xx with a non-UTF8 body must not panic; it logs a placeholder and returns Http.
        let err = classify_logout_response(StatusCode::BAD_GATEWAY, &[0xff, 0xfe]).unwrap_err();
        assert_eq!(err, LogoutError::Internal(LogoutInternalErrorKind::Http));
    }

    /// The computed expiry must be strictly in the past so control expires the node (not schedule a
    /// future expiry). Guards against an accidental sign flip in [`past_expiry`].
    #[test]
    fn expiry_is_in_the_past() {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let expiry = past_expiry();
        assert!(
            expiry.timestamp() < now_secs,
            "logout expiry ({}) must be before now ({now_secs})",
            expiry.timestamp()
        );
    }
}
