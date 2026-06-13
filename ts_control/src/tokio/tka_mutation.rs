//! Control RPCs for Tailnet-Lock (TKA) **mutation**: `GET /machine/tka/init/begin`,
//! `/machine/tka/init/finish`, `/machine/tka/sign`, and `/machine/tka/disable`, over the Noise
//! (ts2021) transport.
//!
//! Mirrors Go's `tkaInitBegin` / `tkaInitFinish` / `tkaSubmitSignature` / `tkaDoDisablement`
//! (`ipn/ipnlocal/tailnet-lock.go`, v1.100.0). Same shape as the sync RPCs in [`super::tka_sync`]: an
//! HTTP `GET` carrying a JSON body (matching upstream), response read behind the 10 MiB limit, 404/501
//! mapped to [`TkaSyncError::Unsupported`] (the tailnet has no lock / control is too old). They share
//! [`TkaSyncError`] and the `classify_status`/`lb_header`/timeout/limit helpers — these are sibling
//! `/machine/tka/*` endpoints with an identical failure surface.
//!
//! Transport only: these speak the [`ts_control_serde`] wire types. Building the request bodies
//! (signing AUMs/NKS, computing heads) and applying the results to the live `ts_tka::Authority` is the
//! runtime layer's job — keeping `ts_control` free of a `ts_tka` dependency.

use bytes::Bytes;
use ts_capabilityversion::CapabilityVersion;
use ts_control_serde::{
    TkaDisableRequest, TkaDisableResponse, TkaInitBeginRequest, TkaInitBeginResponse,
    TkaInitFinishRequest, TkaInitFinishResponse, TkaSubmitSignatureRequest,
    TkaSubmitSignatureResponse,
};
use ts_http_util::{BytesBody, ClientExt, Http2, ResponseExt, StatusCode};
use url::Url;

use super::tka_sync::{
    MAX_TKA_SYNC_RESPONSE, TKA_SYNC_TIMEOUT, TkaSyncError, classify_status, lb_header,
};

/// Submit the `init/begin` proposal (the genesis AUM) to control, returning the set of nodes that
/// must be (re)signed before `init/finish` (Go `tkaInitBegin`). Fresh Noise channel, bounded by
/// `TKA_SYNC_TIMEOUT`.
pub async fn tka_init_begin(
    control_url: &Url,
    node_keystate: &ts_keys::NodeState,
    req: TkaInitBeginRequest,
    allow_http_key_fetch: bool,
) -> Result<TkaInitBeginResponse, TkaSyncError> {
    let run = async {
        let http2_conn = crate::tokio::connect(
            control_url,
            &node_keystate.machine_keys,
            allow_http_key_fetch,
        )
        .await?;
        tka_init_begin_with(control_url, node_keystate, req, &http2_conn).await
    };
    timeout(run, "init/begin").await
}

pub(crate) async fn tka_init_begin_with(
    control_url: &Url,
    node_keystate: &ts_keys::NodeState,
    mut req: TkaInitBeginRequest,
    http2_conn: &Http2<BytesBody>,
) -> Result<TkaInitBeginResponse, TkaSyncError> {
    let node_public_key = node_keystate.node_keys.public;
    req.node_key = node_public_key;
    req.version = CapabilityVersion::CURRENT;
    let body = serde_json::to_string(&req)?;
    let url = control_url.join("machine/tka/init/begin")?;
    tracing::debug!(url = %url.as_str(), "TKA init/begin to control");
    let (status, body) = send(http2_conn, &url, &node_public_key, body).await?;
    parse_response(status, &body)
}

/// Submit the `init/finish` per-node signatures to control, finalizing the lock (Go
/// `tkaInitFinish`). Fresh Noise channel, bounded by `TKA_SYNC_TIMEOUT`.
pub async fn tka_init_finish(
    control_url: &Url,
    node_keystate: &ts_keys::NodeState,
    req: TkaInitFinishRequest,
    allow_http_key_fetch: bool,
) -> Result<TkaInitFinishResponse, TkaSyncError> {
    let run = async {
        let http2_conn = crate::tokio::connect(
            control_url,
            &node_keystate.machine_keys,
            allow_http_key_fetch,
        )
        .await?;
        tka_init_finish_with(control_url, node_keystate, req, &http2_conn).await
    };
    timeout(run, "init/finish").await
}

pub(crate) async fn tka_init_finish_with(
    control_url: &Url,
    node_keystate: &ts_keys::NodeState,
    mut req: TkaInitFinishRequest,
    http2_conn: &Http2<BytesBody>,
) -> Result<TkaInitFinishResponse, TkaSyncError> {
    let node_public_key = node_keystate.node_keys.public;
    req.node_key = node_public_key;
    req.version = CapabilityVersion::CURRENT;
    let body = serde_json::to_string(&req)?;
    let url = control_url.join("machine/tka/init/finish")?;
    tracing::debug!(url = %url.as_str(), "TKA init/finish to control");
    let (status, body) = send(http2_conn, &url, &node_public_key, body).await?;
    parse_response(status, &body)
}

/// Submit a node-key signature (a Direct/Rotation `NodeKeySignature`) to control (Go
/// `tkaSubmitSignature`). Fresh Noise channel, bounded by `TKA_SYNC_TIMEOUT`.
pub async fn tka_submit_signature(
    control_url: &Url,
    node_keystate: &ts_keys::NodeState,
    req: TkaSubmitSignatureRequest,
    allow_http_key_fetch: bool,
) -> Result<TkaSubmitSignatureResponse, TkaSyncError> {
    let run = async {
        let http2_conn = crate::tokio::connect(
            control_url,
            &node_keystate.machine_keys,
            allow_http_key_fetch,
        )
        .await?;
        tka_submit_signature_with(control_url, node_keystate, req, &http2_conn).await
    };
    timeout(run, "sign").await
}

pub(crate) async fn tka_submit_signature_with(
    control_url: &Url,
    node_keystate: &ts_keys::NodeState,
    mut req: TkaSubmitSignatureRequest,
    http2_conn: &Http2<BytesBody>,
) -> Result<TkaSubmitSignatureResponse, TkaSyncError> {
    let node_public_key = node_keystate.node_keys.public;
    req.node_key = node_public_key;
    req.version = CapabilityVersion::CURRENT;
    let body = serde_json::to_string(&req)?;
    let url = control_url.join("machine/tka/sign")?;
    tracing::debug!(url = %url.as_str(), "TKA sign to control");
    let (status, body) = send(http2_conn, &url, &node_public_key, body).await?;
    parse_response(status, &body)
}

/// Submit the disablement secret to turn the lock off (Go `tkaDoDisablement`). Fresh Noise channel,
/// bounded by `TKA_SYNC_TIMEOUT`.
pub async fn tka_disable(
    control_url: &Url,
    node_keystate: &ts_keys::NodeState,
    req: TkaDisableRequest,
    allow_http_key_fetch: bool,
) -> Result<TkaDisableResponse, TkaSyncError> {
    let run = async {
        let http2_conn = crate::tokio::connect(
            control_url,
            &node_keystate.machine_keys,
            allow_http_key_fetch,
        )
        .await?;
        tka_disable_with(control_url, node_keystate, req, &http2_conn).await
    };
    timeout(run, "disable").await
}

pub(crate) async fn tka_disable_with(
    control_url: &Url,
    node_keystate: &ts_keys::NodeState,
    mut req: TkaDisableRequest,
    http2_conn: &Http2<BytesBody>,
) -> Result<TkaDisableResponse, TkaSyncError> {
    let node_public_key = node_keystate.node_keys.public;
    req.node_key = node_public_key;
    req.version = CapabilityVersion::CURRENT;
    let body = serde_json::to_string(&req)?;
    let url = control_url.join("machine/tka/disable")?;
    tracing::debug!(url = %url.as_str(), "TKA disable to control");
    let (status, body) = send(http2_conn, &url, &node_public_key, body).await?;
    parse_response(status, &body)
}

/// Wrap an RPC future in the shared TKA timeout, mapping an elapsed timer to a transient
/// [`TkaSyncError::NetworkError`] (a hung control plane is abandoned, not pinned).
async fn timeout<T>(
    run: impl core::future::Future<Output = Result<T, TkaSyncError>>,
    what: &str,
) -> Result<T, TkaSyncError> {
    match tokio::time::timeout(TKA_SYNC_TIMEOUT, run).await {
        Ok(result) => result,
        Err(_elapsed) => {
            tracing::error!(timeout = ?TKA_SYNC_TIMEOUT, rpc = what, "TKA mutation RPC timed out");
            Err(TkaSyncError::NetworkError)
        }
    }
}

/// Issue the `GET`-with-JSON-body and read the (capped) response — the shared transport step.
async fn send(
    http2_conn: &Http2<BytesBody>,
    url: &Url,
    node_public_key: &ts_keys::NodePublicKey,
    body: alloc::string::String,
) -> Result<(StatusCode, Bytes), TkaSyncError> {
    let response = http2_conn
        .get_with_body(url, [lb_header(node_public_key)], Bytes::from(body).into())
        .await?;
    let status = response.status();
    let body = response
        .collect_bytes_limited(MAX_TKA_SYNC_RESPONSE)
        .await?;
    Ok((status, body))
}

/// Parse a mutation response: status first (404/501 ⇒ [`TkaSyncError::Unsupported`], other non-2xx ⇒
/// a coarse HTTP error), then the (typically empty `{}`) JSON body. Generic over the response type so
/// all four RPCs share it; pure (no I/O), so the branch logic is unit-testable.
fn parse_response<T: serde::de::DeserializeOwned>(
    status: StatusCode,
    body: &[u8],
) -> Result<T, TkaSyncError> {
    if let Some(err) = classify_status(status, body) {
        return Err(err);
    }
    // Defense-in-depth: the network read already caps at MAX_TKA_SYNC_RESPONSE; this still guards the
    // pure-`&[u8]` parse path (unit tests / any future non-limited caller).
    if body.len() > MAX_TKA_SYNC_RESPONSE {
        return Err(TkaSyncError::Internal(
            super::tka_sync::TkaSyncInternalErrorKind::TooLarge,
        ));
    }
    let body = core::str::from_utf8(body)?;
    Ok(serde_json::from_str(body)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ts_control_serde::TkaSignInfo;

    #[test]
    fn parse_init_begin_response_ok() {
        let json = br#"{"NeedSignatures":[{"NodeID":42,"NodePublic":"nodekey:0707070707070707070707070707070707070707070707070707070707070707","RotationPubkey":"AQID"}]}"#;
        let resp: TkaInitBeginResponse = parse_response(StatusCode::OK, json).expect("parse");
        assert_eq!(resp.need_signatures.len(), 1);
        assert_eq!(resp.need_signatures[0].node_id, 42);
    }

    #[test]
    fn parse_init_begin_empty_need_signatures() {
        let resp: TkaInitBeginResponse = parse_response(StatusCode::OK, b"{}").expect("parse");
        assert!(resp.need_signatures.is_empty());
    }

    #[test]
    fn parse_empty_responses_ok() {
        // The finish/sign/disable responses are empty objects on success.
        let _: TkaInitFinishResponse = parse_response(StatusCode::OK, b"{}").expect("finish");
        let _: TkaSubmitSignatureResponse = parse_response(StatusCode::OK, b"{}").expect("sign");
        let _: TkaDisableResponse = parse_response(StatusCode::OK, b"{}").expect("disable");
    }

    #[test]
    fn unsupported_status_maps_to_unsupported() {
        assert_eq!(
            parse_response::<TkaInitBeginResponse>(StatusCode::NOT_FOUND, b"nope").unwrap_err(),
            TkaSyncError::Unsupported
        );
        assert_eq!(
            parse_response::<TkaDisableResponse>(StatusCode::NOT_IMPLEMENTED, b"").unwrap_err(),
            TkaSyncError::Unsupported
        );
    }

    #[test]
    fn other_non_2xx_is_http_internal() {
        assert_eq!(
            parse_response::<TkaInitFinishResponse>(StatusCode::INTERNAL_SERVER_ERROR, b"boom")
                .unwrap_err(),
            TkaSyncError::Internal(super::super::tka_sync::TkaSyncInternalErrorKind::Http)
        );
    }

    #[test]
    fn malformed_body_is_serde_error() {
        let err = parse_response::<TkaInitBeginResponse>(StatusCode::OK, b"not json").unwrap_err();
        assert_eq!(
            err,
            TkaSyncError::Internal(super::super::tka_sync::TkaSyncInternalErrorKind::SerDe)
        );
    }

    #[test]
    fn need_signatures_carries_rotation_pubkey() {
        // Sanity that the TkaSignInfo re-export decodes the RotationPubkey base64.
        let json = br#"{"NeedSignatures":[{"NodeID":7,"NodePublic":"nodekey:0101010101010101010101010101010101010101010101010101010101010101","RotationPubkey":"/w=="}]}"#;
        let resp: TkaInitBeginResponse = parse_response(StatusCode::OK, json).expect("parse");
        let info: &TkaSignInfo = &resp.need_signatures[0];
        assert_eq!(info.rotation_pubkey, alloc::vec![0xffu8]);
    }
}
