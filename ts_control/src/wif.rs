//! Workload-identity-federation (WIF) + OAuth-client auth-key bootstrap.
//!
//! Resolves an effective pre-auth key from OAuth-client credentials or ambient workload-identity
//! federation *before* node registration. Faithfully ports Go Tailscale's
//! `feature/oauthkey` + `feature/identityfederation` (+ `wif`): given an OAuth client secret or a
//! WIF client ID plus an OIDC ID token (or an audience to fetch one for), it exchanges those for a
//! short-lived API access token and then mints a fresh tailnet auth key via the public Tailscale
//! API.
//!
//! This is **SaaS-only**: the fork's a self-hosted control plane control plane does not implement the
//! `/api/v2/oauth/token`, `/api/v2/oauth/token-exchange`, or `/api/v2/tailnet/-/keys` endpoints
//! (a self-hosted control plane issue #3081, closed unimplemented). The whole subsystem therefore lives behind the
//! off-by-default `identity-federation` cargo feature, mirroring Go's optional `feature/`
//! blank-import gating.
//!
//! ## Resolution precedence (Go `tsnet.go resolveAuthKey`)
//!
//! 1. An `auth_key` beginning with `tskey-client-` is itself an OAuth client secret → OAuth path.
//! 2. Else a `client_secret` beginning with `tskey-client-` → OAuth path with that secret.
//! 3. Else a `client_id` set (with an ID token or an audience) → WIF token-exchange path.
//! 4. Else the `auth_key` is returned unchanged (a plain pre-auth key, or `None`).
//!
//! All HTTP is done over the crate's existing `ts_http_util` substrate (ring-based TLS via
//! `ts_tls_util`); no new TLS/HTTP/AWS-SDK dependencies are introduced.
//!
//! ## Trust note
//!
//! The OAuth client secret string may carry a `?baseURL=` query that redirects the token-mint and
//! CreateKey calls to that host — so the secret and the minted auth key are sent there. This matches
//! Go's behavior, and the secret is the operator's own credential, so it is a self-directed choice
//! rather than an injection vector. Still: treat the OAuth secret / `client_secret` config value as
//! **fully operator-trusted input** — never accept it from a less-trusted source, since a hostile
//! `baseURL` would exfiltrate the credential and the minted key to an attacker-chosen host.

use bytes::Bytes;
use ts_http_util::{BytesBody, ClientExt, ResponseExt, StatusCode};
use url::Url;

/// Prefix that marks a secret/client-id string as an OAuth client credential (Go `oauthkey`).
const OAUTH_CLIENT_PREFIX: &str = "tskey-client-";

/// Default Tailscale API base URL used by the OAuth-client and CreateKey paths (Go default).
const DEFAULT_API_BASE_URL: &str = "https://api.tailscale.com";

/// GCP instance-metadata server host (Go `identityfederation` GCP detector).
const GCP_METADATA_URL: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity";

/// Errors resolving an auth key via OAuth-client credentials or workload-identity federation.
#[derive(Debug, thiserror::Error)]
pub enum WifError {
    /// A WIF input combination that is structurally invalid (mirrors Go's verbatim messages).
    #[error("{0}")]
    Validation(String),

    /// An HTTP request failed to send, returned a non-2xx status, or its body could not be read.
    #[error("http error in workload-identity request: {0}")]
    Http(String),

    /// No ambient workload identity (GitHub Actions / GCP / AWS) could be detected to mint a token.
    #[error("no ambient workload identity available to obtain an ID token")]
    NoAmbientIdentity,

    /// A response body could not be parsed (bad JSON, missing field, or invalid UTF-8).
    #[error("failed to parse response: {0}")]
    Parse(String),
}

impl From<ts_http_util::Error> for WifError {
    fn from(error: ts_http_util::Error) -> Self {
        WifError::Http(error.to_string())
    }
}

impl From<url::ParseError> for WifError {
    fn from(error: url::ParseError) -> Self {
        WifError::Http(format!("bad URL: {error}"))
    }
}

/// Inputs for resolving an auth key (Go `tsnet.Server` WIF fields).
#[derive(Debug, Default, Clone)]
pub struct WifConfig {
    /// An explicit auth key. If it begins with `tskey-client-` it is treated as an OAuth client
    /// secret; otherwise it is returned unchanged as a plain pre-auth key.
    pub auth_key: Option<String>,
    /// OAuth/WIF client ID (itself a `tskey-client-...` string for the WIF path).
    pub client_id: Option<String>,
    /// OAuth client secret (a `tskey-client-...` string for the OAuth path).
    pub client_secret: Option<String>,
    /// A pre-obtained OIDC ID token (JWT) for the WIF path.
    pub id_token: Option<String>,
    /// An audience to mint an ambient OIDC ID token for, when `id_token` is not supplied.
    pub audience: Option<String>,
    /// Tags applied to the minted auth key. Required non-empty for the OAuth/WIF CreateKey call.
    pub tags: Vec<String>,
}

/// A parsed OAuth client secret / client ID: the bare `tskey-client-...` value plus the
/// query-string options that follow it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OAuthSecret {
    /// The `tskey-client-...` value with any `?...` query stripped.
    stripped: String,
    /// Whether the minted key should be ephemeral (default `true`).
    ephemeral: bool,
    /// Whether the minted key should be pre-authorized (default `false`).
    preauthorized: bool,
    /// Optional API base URL override (default [`DEFAULT_API_BASE_URL`]).
    base_url: String,
}

impl OAuthSecret {
    /// Parse a `tskey-client-XXXX[?ephemeral=BOOL&preauthorized=BOOL&baseURL=URL]` string.
    ///
    /// Pure (no I/O). Defaults: `ephemeral=true`, `preauthorized=false`,
    /// `base_url=https://api.tailscale.com`. The query string is stripped from `stripped`.
    fn parse(secret: &str) -> Self {
        let (value, query) = match secret.split_once('?') {
            Some((v, q)) => (v, Some(q)),
            None => (secret, None),
        };

        let mut ephemeral = true;
        let mut preauthorized = false;
        let mut base_url = DEFAULT_API_BASE_URL.to_string();

        if let Some(query) = query {
            for (key, val) in url::form_urlencoded::parse(query.as_bytes()) {
                match key.as_ref() {
                    "ephemeral" => ephemeral = val == "true",
                    "preauthorized" => preauthorized = val == "true",
                    "baseURL" if !val.is_empty() => base_url = val.into_owned(),
                    _ => {}
                }
            }
        }

        OAuthSecret {
            stripped: value.to_string(),
            ephemeral,
            preauthorized,
            base_url,
        }
    }
}

/// Validate the workload-identity-federation input combination (Go, verbatim error conditions).
///
/// Pure (no I/O). Assumes a `client_id` is present (the WIF path). Returns the four Go error
/// strings for the invalid combinations, `Ok(())` otherwise.
fn validate_wif(id_token: Option<&str>, audience: Option<&str>) -> Result<(), WifError> {
    let has_id_token = id_token.is_some();
    let has_audience = audience.is_some();

    if !has_id_token && !has_audience {
        return Err(WifError::Validation(
            "client ID for workload identity federation found, but ID token and audience are empty"
                .to_string(),
        ));
    }
    if has_id_token && has_audience {
        return Err(WifError::Validation(
            "only one of ID token and audience should be set for workload identity federation"
                .to_string(),
        ));
    }
    Ok(())
}

/// Validate WIF inputs when a `client_id` is *not* present but an `id_token`/`audience` is
/// (Go: the dangling-field error conditions).
fn validate_wif_no_client_id(
    id_token: Option<&str>,
    audience: Option<&str>,
) -> Result<(), WifError> {
    if id_token.is_some() {
        return Err(WifError::Validation(
            "ID token for workload identity federation found, but client ID is empty".to_string(),
        ));
    }
    if audience.is_some() {
        return Err(WifError::Validation(
            "audience for workload identity federation found, but client ID is empty".to_string(),
        ));
    }
    Ok(())
}

/// Build the `client_credentials` token-request form body (Go OAuth path).
///
/// Pure (no I/O). Produces `grant_type=client_credentials&client_id=some-client-id&client_secret=…`.
fn client_credentials_body(stripped_secret: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "client_credentials")
        .append_pair("client_id", "some-client-id")
        .append_pair("client_secret", stripped_secret)
        .finish()
}

/// Build the WIF `token-exchange` form body (Go's BESPOKE form — NOT RFC 8693).
///
/// Pure (no I/O). Produces `grant_type=authorization_code&code=&client_id=…&jwt=<idToken>`.
fn token_exchange_body(stripped_client_id: &str, id_token: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", "")
        .append_pair("client_id", stripped_client_id)
        .append_pair("jwt", id_token)
        .finish()
}

/// Build the CreateKey JSON request body (Go `client/tailscale/keys.go`).
///
/// Pure (no I/O). Serializes the exact
/// `{"capabilities":{"devices":{"create":{...}}}}` shape.
fn create_key_body(ephemeral: bool, preauthorized: bool, tags: &[String]) -> String {
    let create = serde_json::json!({
        "reusable": false,
        "ephemeral": ephemeral,
        "preauthorized": preauthorized,
        "tags": tags,
    });
    let body = serde_json::json!({
        "capabilities": { "devices": { "create": create } }
    });
    // Serialization of a `serde_json::Value` cannot fail.
    body.to_string()
}

/// Extract the `access_token` field from an OAuth/token-exchange response body.
///
/// Pure (no I/O).
fn parse_token_response(body: &[u8]) -> Result<String, WifError> {
    let value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| WifError::Parse(format!("token response JSON: {e}")))?;
    value
        .get("access_token")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| WifError::Parse("token response missing access_token".to_string()))
}

/// Extract the `key` field from a CreateKey response body.
///
/// Pure (no I/O).
fn parse_create_key_response(body: &[u8]) -> Result<String, WifError> {
    let value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| WifError::Parse(format!("create-key response JSON: {e}")))?;
    value
        .get("key")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| WifError::Parse("create-key response missing key".to_string()))
}

/// Extract the GitHub Actions OIDC token (`value` field) from its token-request response body.
///
/// Pure (no I/O).
fn parse_github_token(body: &[u8]) -> Result<String, WifError> {
    let value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| WifError::Parse(format!("github oidc JSON: {e}")))?;
    value
        .get("value")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| WifError::Parse("github oidc response missing value".to_string()))
}

/// POST a body to `url` over TLS and return the response body bytes if the status is 2xx.
async fn post_form_tls(
    url: &Url,
    content_type: &str,
    extra_headers: Vec<(ts_http_util::HeaderName, ts_http_util::HeaderValue)>,
    body: String,
) -> Result<Bytes, WifError> {
    let client = ts_http_util::http1::connect_tls::<BytesBody>(url).await?;
    let mut headers = vec![(
        ts_http_util::HeaderName::from_static("content-type"),
        ts_http_util::HeaderValue::from_str(content_type)
            .map_err(|e| WifError::Http(format!("bad content-type header: {e}")))?,
    )];
    headers.extend(extra_headers);

    let response = client.post(url, headers, Bytes::from(body).into()).await?;
    let status = response.status();
    let body = response.collect_bytes().await?;
    check_status(status, body)
}

/// Map a non-2xx `status` to [`WifError::Http`] (with a truncated body preview), else return the
/// body bytes unchanged.
///
/// Pure (no I/O): the body is already collected by the caller, keeping this off the generic
/// `Incoming` response type that `ts_http_util` does not re-export.
fn check_status(status: StatusCode, body: Bytes) -> Result<Bytes, WifError> {
    if !status.is_success() {
        let mut preview = body.to_vec();
        preview.truncate(512);
        let preview = String::from_utf8_lossy(&preview);
        return Err(WifError::Http(format!("status {status}: {preview}")));
    }
    Ok(body)
}

/// Mint a tailnet auth key via the public API using a bearer `access_token` (Go CreateKey).
async fn create_key(
    base_url: &str,
    access_token: &str,
    ephemeral: bool,
    preauthorized: bool,
    tags: &[String],
) -> Result<String, WifError> {
    let url = Url::parse(base_url)?.join("/api/v2/tailnet/-/keys")?;
    let body = create_key_body(ephemeral, preauthorized, tags);

    let client = ts_http_util::http1::connect_tls::<BytesBody>(&url).await?;
    let headers = [
        (
            ts_http_util::HeaderName::from_static("authorization"),
            ts_http_util::HeaderValue::from_str(&format!("Bearer {access_token}"))
                .map_err(|e| WifError::Http(format!("bad authorization header: {e}")))?,
        ),
        (
            ts_http_util::HeaderName::from_static("content-type"),
            ts_http_util::HeaderValue::from_static("application/json"),
        ),
    ];
    let response = client.post(&url, headers, Bytes::from(body).into()).await?;
    let status = response.status();
    let body = response.collect_bytes().await?;
    let body = check_status(status, body)?;
    parse_create_key_response(&body)
}

/// OAuth-client path (Go `feature/oauthkey/oauthkey.go`): exchange the client secret for an access
/// token, then mint an auth key.
async fn resolve_oauth_client(secret: &OAuthSecret, tags: &[String]) -> Result<String, WifError> {
    let token_url = Url::parse(&secret.base_url)?.join("/api/v2/oauth/token")?;
    let body = client_credentials_body(&secret.stripped);
    let resp = post_form_tls(
        &token_url,
        "application/x-www-form-urlencoded",
        Vec::new(),
        body,
    )
    .await?;
    let access_token = parse_token_response(&resp)?;
    create_key(
        &secret.base_url,
        &access_token,
        secret.ephemeral,
        secret.preauthorized,
        tags,
    )
    .await
}

/// Obtain an ambient OIDC ID token for `audience` by detecting the workload environment
/// (GitHub Actions → GCP → AWS), mirroring Go's `feature/identityfederation` detectors.
async fn obtain_ambient_id_token(audience: &str) -> Result<String, WifError> {
    // GitHub Actions.
    if let (Ok(request_url), Ok(request_token)) = (
        std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL"),
        std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
    ) {
        let mut url = Url::parse(&request_url)?;
        url.query_pairs_mut().append_pair("audience", audience);
        let client = ts_http_util::http1::connect_tls::<BytesBody>(&url).await?;
        let headers = [
            (
                ts_http_util::HeaderName::from_static("authorization"),
                ts_http_util::HeaderValue::from_str(&format!("Bearer {request_token}"))
                    .map_err(|e| WifError::Http(format!("bad authorization header: {e}")))?,
            ),
            (
                ts_http_util::HeaderName::from_static("accept"),
                ts_http_util::HeaderValue::from_static("application/json"),
            ),
        ];
        let response = client.get(&url, headers).await?;
        let status = response.status();
        let body = response.collect_bytes().await?;
        let body = check_status(status, body)?;
        return parse_github_token(&body);
    }

    // GCP instance metadata server.
    if let Ok(token) = obtain_gcp_id_token(audience).await {
        return Ok(token);
    }

    // AWS: read the OIDC JWT from the web-identity token file.
    if let Ok(path) = std::env::var("AWS_WEB_IDENTITY_TOKEN_FILE") {
        let token = std::fs::read_to_string(&path)
            .map_err(|e| WifError::Http(format!("reading AWS_WEB_IDENTITY_TOKEN_FILE: {e}")))?;
        return Ok(token.trim().to_string());
    }

    Err(WifError::NoAmbientIdentity)
}

/// GCP detector: `GET` the instance-metadata identity endpoint; the response body is the raw JWT.
async fn obtain_gcp_id_token(audience: &str) -> Result<String, WifError> {
    let mut url = Url::parse(GCP_METADATA_URL)?;
    url.query_pairs_mut()
        .append_pair("audience", audience)
        .append_pair("format", "full");
    let client = ts_http_util::http1::connect_tcp::<BytesBody>(&url).await?;
    let headers = [(
        ts_http_util::HeaderName::from_static("metadata-flavor"),
        ts_http_util::HeaderValue::from_static("Google"),
    )];
    let response = client.get(&url, headers).await?;
    let status = response.status();
    let body = response.collect_bytes().await?;
    let body = check_status(status, body)?;
    let token = core::str::from_utf8(&body)
        .map_err(|e| WifError::Parse(format!("gcp id token utf8: {e}")))?;
    Ok(token.trim().to_string())
}

/// WIF path (Go `feature/identityfederation`): obtain/accept an ID token, exchange it for an access
/// token at the control server, then mint an auth key.
async fn resolve_wif(
    client_id: &OAuthSecret,
    id_token: Option<&str>,
    audience: Option<&str>,
    control_url: &Url,
    tags: &[String],
) -> Result<String, WifError> {
    let id_token = match id_token {
        Some(t) => t.to_string(),
        None => {
            // Validation guarantees `audience` is Some here.
            let audience = audience.expect("validation ensures audience is present");
            obtain_ambient_id_token(audience).await?
        }
    };

    let exchange_url = control_url.join("/api/v2/oauth/token-exchange")?;
    let body = token_exchange_body(&client_id.stripped, &id_token);
    let resp = post_form_tls(
        &exchange_url,
        "application/x-www-form-urlencoded",
        Vec::new(),
        body,
    )
    .await?;
    let access_token = parse_token_response(&resp)?;

    // CreateKey runs against the control server (SaaS base) for the WIF path.
    let base_url = control_url.as_str().trim_end_matches('/');
    create_key(
        base_url,
        &access_token,
        client_id.ephemeral,
        client_id.preauthorized,
        tags,
    )
    .await
}

/// Resolve the effective pre-auth key, performing the OAuth-client or WIF exchange if configured.
///
/// Returns `Ok(Some(authkey))` when an exchange produced (or an explicit key was given) a key,
/// `Ok(None)` when no credentials were supplied (caller proceeds keyless), or `Err` on
/// validation/HTTP failure. `control_url` is the configured control-server base used for the WIF
/// token-exchange and CreateKey calls.
///
/// Precedence faithfully mirrors Go `tsnet.go resolveAuthKey`:
/// 1. An `auth_key` starting with `tskey-client-` is an OAuth client secret.
/// 2. Else a `client_secret` starting with `tskey-client-` is used as the OAuth secret.
/// 3. Else a set `client_id` selects the WIF token-exchange path.
/// 4. Else the `auth_key` is returned unchanged.
pub async fn resolve_auth_key(
    cfg: &WifConfig,
    control_url: &Url,
) -> Result<Option<String>, WifError> {
    // 1. auth_key is itself an OAuth client secret.
    if let Some(auth_key) = cfg.auth_key.as_deref()
        && auth_key.starts_with(OAUTH_CLIENT_PREFIX)
    {
        let secret = OAuthSecret::parse(auth_key);
        return resolve_oauth_client(&secret, &cfg.tags).await.map(Some);
    }

    // 2. client_secret is an OAuth client secret.
    if let Some(client_secret) = cfg.client_secret.as_deref()
        && client_secret.starts_with(OAUTH_CLIENT_PREFIX)
    {
        let secret = OAuthSecret::parse(client_secret);
        return resolve_oauth_client(&secret, &cfg.tags).await.map(Some);
    }

    // 3. client_id selects the WIF token-exchange path.
    if let Some(client_id) = cfg.client_id.as_deref() {
        validate_wif(cfg.id_token.as_deref(), cfg.audience.as_deref())?;
        let parsed = OAuthSecret::parse(client_id);
        let key = resolve_wif(
            &parsed,
            cfg.id_token.as_deref(),
            cfg.audience.as_deref(),
            control_url,
            &cfg.tags,
        )
        .await?;
        return Ok(Some(key));
    }

    // No client_id: a dangling id_token/audience is an error (Go).
    validate_wif_no_client_id(cfg.id_token.as_deref(), cfg.audience.as_deref())?;

    // 4. Return the (plain pre-auth key or None) unchanged; no exchange.
    Ok(cfg.auth_key.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- OAuth secret parsing ---

    #[test]
    fn parse_oauth_secret_with_query() {
        let s = OAuthSecret::parse("tskey-client-abc?ephemeral=false&preauthorized=true");
        assert_eq!(s.stripped, "tskey-client-abc");
        assert!(!s.ephemeral);
        assert!(s.preauthorized);
        assert_eq!(s.base_url, DEFAULT_API_BASE_URL);
    }

    #[test]
    fn parse_oauth_secret_defaults() {
        let s = OAuthSecret::parse("tskey-client-xyz");
        assert_eq!(s.stripped, "tskey-client-xyz");
        assert!(s.ephemeral);
        assert!(!s.preauthorized);
        assert_eq!(s.base_url, DEFAULT_API_BASE_URL);
    }

    #[test]
    fn parse_oauth_secret_base_url_override() {
        let s = OAuthSecret::parse("tskey-client-abc?baseURL=https://example.com");
        assert_eq!(s.stripped, "tskey-client-abc");
        assert_eq!(s.base_url, "https://example.com");
    }

    // --- WIF validation (the 4 Go error conditions + valid cases) ---

    #[test]
    fn wif_validation_both_empty_errors() {
        let err = validate_wif(None, None).unwrap_err();
        assert!(matches!(err, WifError::Validation(m)
            if m == "client ID for workload identity federation found, but ID token and audience are empty"));
    }

    #[test]
    fn wif_validation_both_set_errors() {
        let err = validate_wif(Some("jwt"), Some("aud")).unwrap_err();
        assert!(matches!(err, WifError::Validation(m)
            if m == "only one of ID token and audience should be set for workload identity federation"));
    }

    #[test]
    fn wif_validation_id_token_only_passes() {
        validate_wif(Some("jwt"), None).unwrap();
    }

    #[test]
    fn wif_validation_audience_only_passes() {
        validate_wif(None, Some("aud")).unwrap();
    }

    #[test]
    fn wif_validation_no_client_id_with_id_token_errors() {
        let err = validate_wif_no_client_id(Some("jwt"), None).unwrap_err();
        assert!(matches!(err, WifError::Validation(m)
            if m == "ID token for workload identity federation found, but client ID is empty"));
    }

    #[test]
    fn wif_validation_no_client_id_with_audience_errors() {
        let err = validate_wif_no_client_id(None, Some("aud")).unwrap_err();
        assert!(matches!(err, WifError::Validation(m)
            if m == "audience for workload identity federation found, but client ID is empty"));
    }

    // --- Body builders ---

    #[test]
    fn create_key_body_json() {
        let body = create_key_body(true, false, &["tag:server".to_string()]);
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        let expected = serde_json::json!({
            "capabilities": {
                "devices": {
                    "create": {
                        "reusable": false,
                        "ephemeral": true,
                        "preauthorized": false,
                        "tags": ["tag:server"],
                    }
                }
            }
        });
        assert_eq!(value, expected);
    }

    #[test]
    fn token_form_body_client_credentials() {
        let body = client_credentials_body("tskey-client-abc");
        assert_eq!(
            body,
            "grant_type=client_credentials&client_id=some-client-id&client_secret=tskey-client-abc"
        );
    }

    #[test]
    fn token_form_body_token_exchange() {
        let body = token_exchange_body("tskey-client-abc", "header.payload.sig");
        assert_eq!(
            body,
            "grant_type=authorization_code&code=&client_id=tskey-client-abc&jwt=header.payload.sig"
        );
    }

    // --- Response parsing ---

    #[test]
    fn parse_token_response_ok() {
        let body = br#"{"access_token":"ABC","token_type":"Bearer","expires_in":3600}"#;
        assert_eq!(parse_token_response(body).unwrap(), "ABC");
    }

    #[test]
    fn parse_token_response_missing_field() {
        let err = parse_token_response(br#"{"token_type":"Bearer"}"#).unwrap_err();
        assert!(matches!(err, WifError::Parse(_)));
    }

    #[test]
    fn parse_create_key_response_ok() {
        let body = br#"{"id":"k1","key":"tskey-auth-XYZ","created":"now"}"#;
        assert_eq!(parse_create_key_response(body).unwrap(), "tskey-auth-XYZ");
    }

    #[test]
    fn parse_create_key_response_missing_field() {
        let err = parse_create_key_response(br#"{"id":"k1"}"#).unwrap_err();
        assert!(matches!(err, WifError::Parse(_)));
    }

    #[test]
    fn parse_github_token_ok() {
        let body = br#"{"value":"gha.jwt.token","count":1}"#;
        assert_eq!(parse_github_token(body).unwrap(), "gha.jwt.token");
    }

    // --- Precedence / short-circuit (no network) ---

    #[tokio::test]
    async fn precedence_plain_auth_key_returned_unchanged() {
        let cfg = WifConfig {
            auth_key: Some("tskey-auth-PLAIN".to_string()),
            ..Default::default()
        };
        let control = Url::parse("https://api.tailscale.com").unwrap();
        let resolved = resolve_auth_key(&cfg, &control).await.unwrap();
        assert_eq!(resolved, Some("tskey-auth-PLAIN".to_string()));
    }

    #[tokio::test]
    async fn precedence_no_credentials_returns_none() {
        let cfg = WifConfig::default();
        let control = Url::parse("https://api.tailscale.com").unwrap();
        let resolved = resolve_auth_key(&cfg, &control).await.unwrap();
        assert_eq!(resolved, None);
    }

    #[tokio::test]
    async fn precedence_dangling_id_token_without_client_id_errors() {
        let cfg = WifConfig {
            id_token: Some("jwt".to_string()),
            ..Default::default()
        };
        let control = Url::parse("https://api.tailscale.com").unwrap();
        let err = resolve_auth_key(&cfg, &control).await.unwrap_err();
        assert!(matches!(err, WifError::Validation(_)));
    }
}
