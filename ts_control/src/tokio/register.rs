use std::fmt;

use bytes::Bytes;
use ts_capabilityversion::CapabilityVersion;
use ts_control_serde::{HostInfo, RegisterAuth, RegisterRequest, RegisterResponse};
use ts_http_util::{BytesBody, ClientExt, Http2, ResponseExt};
use url::Url;

const LOAD_BALANCER_HEADER_KEY: &str = "Ts-Lb";

#[derive(Debug, thiserror::Error, Clone, Eq, PartialEq)]
pub enum RegistrationError {
    #[error("machine was not authorized by control to join tailnet")]
    MachineNotAuthorized(Option<Url>),

    /// Control rejected registration with a specific reason (the RegisterResponse `Error` field),
    /// e.g. "invalid key: API key does not exist". No interactive auth URL was offered.
    #[error("control rejected registration: {0}")]
    Rejected(String),

    /// Control rate-limited registration (HTTP 429). The [`Duration`](core::time::Duration) is how
    /// long to wait before retrying, taken from the server's `Retry-After` header (mirroring Go's
    /// `parseRateLimitError`); the caller should sleep exactly this before re-registering rather than
    /// using its own backoff, so we never re-hit control inside the cooldown it asked for.
    #[error("control rate limited registration; retry after {0:?}")]
    RateLimited(core::time::Duration),

    #[error("Network error")]
    NetworkError,

    #[error("error during registration: {0}")]
    Internal(InternalErrorKind),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum InternalErrorKind {
    Url,
    SerDe,
    Utf8,
    Http,
}

impl fmt::Display for InternalErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InternalErrorKind::Url => write!(f, "URL parsing error"),
            InternalErrorKind::SerDe => write!(f, "serialization/deserialization error"),
            InternalErrorKind::Utf8 => write!(f, "invalid UTF8"),
            InternalErrorKind::Http => write!(f, "unsuccessful HTTP request or upgrade"),
        }
    }
}

impl From<url::ParseError> for RegistrationError {
    fn from(error: url::ParseError) -> Self {
        tracing::error!(%error, "bad URL");
        RegistrationError::Internal(InternalErrorKind::Url)
    }
}

impl From<serde_json::Error> for RegistrationError {
    fn from(error: serde_json::Error) -> Self {
        tracing::error!(%error, "serialization/deserialization error in registration");
        RegistrationError::Internal(InternalErrorKind::SerDe)
    }
}

impl From<ts_http_util::Error> for RegistrationError {
    fn from(error: ts_http_util::Error) -> Self {
        tracing::error!(%error, "http error sending registration request");

        if crate::http_error_is_recoverable(error) {
            RegistrationError::NetworkError
        } else {
            RegistrationError::Internal(InternalErrorKind::Http)
        }
    }
}

impl From<core::str::Utf8Error> for RegistrationError {
    fn from(error: core::str::Utf8Error) -> Self {
        tracing::error!(%error, "utf8 error in registration response");
        RegistrationError::Internal(InternalErrorKind::Utf8)
    }
}

impl From<RegistrationError> for crate::Error {
    fn from(e: RegistrationError) -> Self {
        match e {
            RegistrationError::MachineNotAuthorized(Some(u)) => {
                crate::Error::MachineNotAuthorized(u)
            }
            // "Not authorized, no URL, no error" = awaiting admin approval on an approval-gated
            // tailnet (a TRANSIENT state — the node holds a valid key and must poll until approved,
            // then comes up with no re-registration; Go's `NeedsMachineAuth`). Surface it as the
            // distinct `NeedsMachineAuth` so the control runner polls instead of stopping, rather
            // than collapsing it into the generic `Internal(MachineAuthorization, _)` (which the
            // runner treats as a hard failure → terminal `Failed`).
            RegistrationError::MachineNotAuthorized(None) => crate::Error::NeedsMachineAuth,
            RegistrationError::Rejected(msg) => crate::Error::Registration(msg),
            RegistrationError::RateLimited(d) => crate::Error::RateLimited(d),
            RegistrationError::Internal(k) => {
                crate::Error::Internal(k.into(), crate::Operation::Registration)
            }
            RegistrationError::NetworkError => {
                crate::Error::NetworkError(crate::Operation::Registration)
            }
        }
    }
}

impl From<InternalErrorKind> for crate::InternalErrorKind {
    fn from(e: InternalErrorKind) -> Self {
        match e {
            InternalErrorKind::Url => crate::InternalErrorKind::Url,
            InternalErrorKind::SerDe => crate::InternalErrorKind::SerDe,
            InternalErrorKind::Utf8 => crate::InternalErrorKind::Utf8,
            InternalErrorKind::Http => crate::InternalErrorKind::Http,
        }
    }
}

/// Classify a parsed [`RegisterResponse`] into success or a typed [`RegistrationError`].
///
/// Pure and side-effect-free so it can be unit-tested directly (the network round-trip in
/// [`register`] is not). When the machine is not authorized:
/// - a non-empty `auth_url` means interactive auth is pending -> `MachineNotAuthorized(Some(url))`;
/// - otherwise control gave a hard rejection. Surface its `error` reason verbatim if present
///   (e.g. "invalid key: API key does not exist") instead of a generic error (tsr-kqj);
/// - an empty `error` with no auth URL falls back to `MachineNotAuthorized(None)`.
fn classify_register_response(resp: &RegisterResponse) -> Result<(), RegistrationError> {
    if !resp.machine_authorized {
        if !resp.auth_url.is_empty() {
            return Err(RegistrationError::MachineNotAuthorized(Some(
                resp.auth_url.parse()?,
            )));
        }
        // No interactive auth URL — control gave a hard rejection. Surface its reason verbatim if
        // present (e.g. "invalid key: API key does not exist") instead of a generic error.
        if !resp.error.is_empty() {
            return Err(RegistrationError::Rejected(resp.error.to_string()));
        }
        return Err(RegistrationError::MachineNotAuthorized(None));
    }
    Ok(())
}

#[tracing::instrument(skip_all, fields(%control_url))]
pub async fn register(
    config: &crate::Config,
    control_url: &Url,
    auth_key: Option<&str>,
    node_keystate: &ts_keys::NodeState,
    http2_conn: &Http2<BytesBody>,
) -> Result<(), RegistrationError> {
    let node_public_key = node_keystate.node_keys.public;
    let network_lock_public_key = node_keystate.network_lock_keys.public;

    if node_keystate.old_node_key.is_some() {
        tracing::debug!("re-registering with OldNodeKey set (node-key rotation)");
    }

    // Advertise-side VIP services: register with the same `HostInfo.ServicesHash` the map request
    // sends, so control's view is consistent from the first contact. Empty advertise set -> empty
    // hash -> field omitted (unchanged registration).
    let advertised_vip_services = config.advertised_vip_services();
    let services_hash = crate::services_hash(&advertised_vip_services);

    // Host-environment facts (OS / version / arch / machine / a Tailscale-shaped IPNVersion), so the
    // advertised Hostinfo matches a genuine Tailscale/tsnet node rather than an empty shell. Bound
    // before the request so its owned strings outlive the borrowing `HostInfo`.
    let host = crate::hostinfo::HostInfoData::detect();
    let client_name = config.format_client_name();

    let register_req = RegisterRequest {
        version: CapabilityVersion::CURRENT,
        node_key: node_public_key,
        old_node_key: node_keystate.old_node_key,
        hostinfo: HostInfo {
            hostname: config.hostname.as_deref().map(std::borrow::Cow::Borrowed),
            app: &client_name,
            ipn_version: &host.ipn_version,
            os: &host.os,
            os_version: &host.os_version,
            go_arch: &host.go_arch,
            go_version: &host.go_version,
            machine: &host.machine,
            package: crate::hostinfo::PACKAGE_TSNET,
            userspace: Some(true),
            routable_ips: {
                let routes = config.advertised_routes();
                (!routes.is_empty()).then_some(routes)
            },
            request_tags: {
                let tags: Vec<&str> = config.tags.iter().map(String::as_str).collect();
                (!tags.is_empty()).then_some(tags)
            },
            services: {
                let services = config.advertised_services();
                (!services.is_empty()).then_some(services)
            },
            // capver-113 Funnel "wire me up server-side" signal. IngressEnabled stays false:
            // listen_funnel is fail-closed in this fork, so no Funnel endpoint ever goes live.
            wire_ingress: config.wire_ingress,
            // Advertise-side VIP services hash (empty when no services are advertised).
            services_hash: &services_hash,
            ..Default::default()
        },
        nl_key: Some(network_lock_public_key),
        auth: auth_key.map(RegisterAuth::from),
        ephemeral: config.ephemeral,
        ..Default::default()
    };

    let body = if cfg!(debug_assertions) {
        serde_json::to_string_pretty(&register_req)?
    } else {
        serde_json::to_string(&register_req)?
    };

    let register_url = control_url.join("machine/register")?;
    tracing::trace!(
        url = %register_url.as_str(),
        %body,
        "sending registration request"
    );

    let response = http2_conn
        .post(
            &register_url,
            [(
                LOAD_BALANCER_HEADER_KEY.parse().unwrap(),
                node_public_key.to_string().parse().unwrap(),
            )],
            Bytes::from(body).into(),
        )
        .await?;

    let status = response.status();

    tracing::debug!(%status, "received registration response");

    // Honor an explicit rate-limit (HTTP 429) the way Go's `doLogin`/`parseRateLimitError` does:
    // read the server's requested cooldown from `Retry-After` and surface it as a typed
    // `RateLimited` so the caller waits exactly that long instead of its own backoff. Checked before
    // the generic non-2xx arm so a 429 never collapses into an opaque `Http` error.
    if status.as_u16() == 429 {
        // `HeaderMap::get` accepts a `&str` key (case-insensitive), so we avoid pulling in `http`
        // directly just for the `RETRY_AFTER` constant.
        let retry_after = parse_retry_after(
            response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok()),
        );
        tracing::warn!(
            ?retry_after,
            "control rate-limited registration (429); will retry after the server-requested delay"
        );
        return Err(RegistrationError::RateLimited(retry_after));
    }

    if !status.is_success() {
        // Attempt to collect the body to log the error, truncating to prevent spamming the logs.
        let mut body = response
            .collect_bytes_limited(crate::MAX_CONTROL_RESPONSE)
            .await
            .unwrap_or_default();
        body.truncate(512);
        let body = core::str::from_utf8(&body).unwrap_or("<invalid utf8>");
        tracing::error!(%body, %status, "registration failed");

        return Err(RegistrationError::Internal(InternalErrorKind::Http));
    }

    let body = response
        .collect_bytes_limited(crate::MAX_CONTROL_RESPONSE)
        .await?;
    let body = core::str::from_utf8(&body)?;

    tracing::trace!(registration_response_body = %body);

    let register_resp: RegisterResponse = serde_json::from_str(body)?;

    classify_register_response(&register_resp)
}

/// Upper bound on a `Retry-After` we will honor. A server (or a buggy/hostile one) that asks us to
/// wait longer than this is clamped to the default, mirroring Go's `parseRateLimitError`
/// (`retryAfter > time.Hour` → default).
const MAX_RETRY_AFTER: core::time::Duration = core::time::Duration::from_secs(60 * 60);

/// Parse an HTTP `Retry-After` header value into a wait duration, mirroring Go's
/// `parseRateLimitError` (`control/controlclient/direct.go`):
///
/// 1. an integer number of seconds (`Retry-After: 120`), or
/// 2. an HTTP-date (`Retry-After: Wed, 21 Oct 2026 07:28:00 GMT`), in which case the wait is the time
///    until that instant.
///
/// If the header is absent, unparseable, non-positive, or longer than [`MAX_RETRY_AFTER`], fall back
/// to Go's default of `5s + rand[0, 5s)` — a short jittered wait that neither hammers control nor
/// stalls indefinitely on a bogus value.
fn parse_retry_after(header: Option<&str>) -> core::time::Duration {
    let parsed = header.and_then(|raw| {
        let raw = raw.trim();
        // Integer seconds — the common case.
        if let Ok(secs) = raw.parse::<i64>() {
            return (secs > 0).then(|| core::time::Duration::from_secs(secs as u64));
        }
        // Otherwise an HTTP-date: wait until that instant (RFC 1123 / IMF-fixdate, the form servers
        // actually emit, e.g. `Wed, 21 Oct 2026 07:28:00 GMT`). `chrono`'s `clock` feature is not
        // enabled in this workspace (no `Utc::now()`), so we take "now" from `SystemTime` and diff
        // the parsed instant's unix timestamp against it. Only `parse_from_rfc2822` (pure parsing,
        // no clock) is used from chrono.
        let when = chrono::DateTime::parse_from_rfc2822(raw).ok()?;
        let when_unix = when.timestamp();
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs() as i64;
        let delta_secs = when_unix - now_unix;
        (delta_secs > 0).then(|| core::time::Duration::from_secs(delta_secs as u64))
    });

    match parsed {
        Some(d) if d > core::time::Duration::ZERO && d <= MAX_RETRY_AFTER => d,
        // Absent / unparseable / non-positive / absurdly large → Go's `5s + rand[0,5s)` default.
        _ => {
            use rand::RngExt as _;
            let jitter_ms = (rand::rng().random::<f64>() * 5000.0) as u64;
            core::time::Duration::from_secs(5) + core::time::Duration::from_millis(jitter_ms)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The jittered default Go falls back to when `Retry-After` is absent/unusable: `5s + [0,5s)`.
    const DEFAULT_LO: core::time::Duration = core::time::Duration::from_secs(5);
    const DEFAULT_HI: core::time::Duration = core::time::Duration::from_secs(10);

    #[test]
    fn retry_after_integer_seconds_is_honored() {
        assert_eq!(
            parse_retry_after(Some("120")),
            core::time::Duration::from_secs(120)
        );
        // Surrounding whitespace is tolerated (header values are trimmed).
        assert_eq!(
            parse_retry_after(Some("  30 ")),
            core::time::Duration::from_secs(30)
        );
    }

    #[test]
    fn retry_after_absent_or_garbage_falls_back_to_jittered_default() {
        // Each of these is unusable and must yield a value in Go's `5s + [0,5s)` default band.
        for header in [None, Some("not-a-number"), Some(""), Some("   ")] {
            let d = parse_retry_after(header);
            assert!(
                d >= DEFAULT_LO && d < DEFAULT_HI,
                "{header:?} must fall back to the [5s,10s) default, got {d:?}"
            );
        }
    }

    #[test]
    fn retry_after_nonpositive_falls_back_to_default() {
        // Zero and negative second counts are not positive waits → default band.
        for header in ["0", "-5"] {
            let d = parse_retry_after(Some(header));
            assert!(
                d >= DEFAULT_LO && d < DEFAULT_HI,
                "{header:?} must fall back to the default, got {d:?}"
            );
        }
    }

    #[test]
    fn retry_after_over_one_hour_is_clamped_to_default() {
        // A server asking for > 1h is clamped to the default (mirrors Go's `> time.Hour` guard), so a
        // bogus/hostile value can't stall the client for hours.
        let d = parse_retry_after(Some("7200")); // 2h
        assert!(
            d >= DEFAULT_LO && d < DEFAULT_HI,
            "a >1h Retry-After must clamp to the default, got {d:?}"
        );
        // Exactly 1h is the boundary and IS honored (Go clamps only `> time.Hour`).
        assert_eq!(
            parse_retry_after(Some("3600")),
            core::time::Duration::from_secs(3600)
        );
    }

    #[test]
    fn retry_after_http_date_in_the_future_is_honored() {
        // An HTTP-date (RFC 1123 / IMF-fixdate) far in the future parses to a positive wait. Use a
        // fixed far-future date so the assertion is stable: the wait must be positive and (being
        // decades out) clamped to the default by the > 1h guard — proving the date path is exercised
        // and the clamp protects against an absurd far-future value.
        let d = parse_retry_after(Some("Wed, 21 Oct 2099 07:28:00 GMT"));
        assert!(
            d >= DEFAULT_LO && d < DEFAULT_HI,
            "a far-future HTTP-date is clamped to the default, got {d:?}"
        );
    }

    #[test]
    fn retry_after_http_date_in_the_past_falls_back_to_default() {
        // A past HTTP-date yields a non-positive delta → default band (never a zero/negative wait).
        let d = parse_retry_after(Some("Wed, 21 Oct 1998 07:28:00 GMT"));
        assert!(
            d >= DEFAULT_LO && d < DEFAULT_HI,
            "a past HTTP-date must fall back to the default, got {d:?}"
        );
    }

    /// A minimal-but-valid `RegisterResponse` wire body. The `MachineAuthorized`/`AuthURL`/`Error`
    /// fields are interpolated so each test can mirror a real control response shape.
    fn register_response_json(machine_authorized: bool, auth_url: &str, error: &str) -> String {
        format!(
            r#"{{
                "User": {{ "ID": 1 }},
                "Login": {{ "ID": 2, "Provider": "", "LoginName": "" }},
                "NodeKeyExpired": false,
                "MachineAuthorized": {machine_authorized},
                "AuthURL": "{auth_url}",
                "Error": "{error}"
            }}"#
        )
    }

    /// A hard rejection (no auth URL) with a populated `Error` must surface control's verbatim
    /// reason as `RegistrationError::Rejected`, not a generic error (tsr-kqj).
    #[test]
    fn rejection_with_error_surfaces_reason() {
        let body = register_response_json(false, "", "invalid key: API key does not exist");
        let resp: RegisterResponse = serde_json::from_str(&body).unwrap();

        let err = classify_register_response(&resp).unwrap_err();
        assert_eq!(
            err,
            RegistrationError::Rejected("invalid key: API key does not exist".to_string())
        );
    }

    /// A not-authorized response with neither an auth URL nor an `Error` falls back to
    /// `MachineNotAuthorized(None)`.
    #[test]
    fn rejection_without_error_yields_machine_not_authorized_none() {
        let body = register_response_json(false, "", "");
        let resp: RegisterResponse = serde_json::from_str(&body).unwrap();

        let err = classify_register_response(&resp).unwrap_err();
        assert_eq!(err, RegistrationError::MachineNotAuthorized(None));
    }

    /// A not-authorized response with a non-empty `AuthURL` means interactive auth is pending and
    /// yields `MachineNotAuthorized(Some(url))` (the auth URL takes precedence).
    #[test]
    fn rejection_with_auth_url_yields_machine_not_authorized_some() {
        let body = register_response_json(false, "https://login.example.com/a/abc123", "");
        let resp: RegisterResponse = serde_json::from_str(&body).unwrap();

        let err = classify_register_response(&resp).unwrap_err();
        assert_eq!(
            err,
            RegistrationError::MachineNotAuthorized(Some(
                "https://login.example.com/a/abc123".parse().unwrap()
            ))
        );
    }

    /// An authorized response classifies as success.
    #[test]
    fn authorized_response_is_ok() {
        let body = register_response_json(true, "", "");
        let resp: RegisterResponse = serde_json::from_str(&body).unwrap();

        assert!(classify_register_response(&resp).is_ok());
    }

    /// `MachineNotAuthorized(None)` — the await-admin-approval case — must map to the DISTINCT
    /// `crate::Error::NeedsMachineAuth`, NOT the generic `Internal(MachineAuthorization, _)` (tsr-dvu).
    /// This is what lets the control runner tell "awaiting approval, poll" apart from a hard internal
    /// failure: the runner matches `NeedsMachineAuth` as a transient poll arm, while `Internal` would
    /// fall into its terminal `Failed` arm and permanently stop the runner.
    #[test]
    fn machine_not_authorized_none_maps_to_needs_machine_auth() {
        let err = crate::Error::from(RegistrationError::MachineNotAuthorized(None));
        assert!(
            matches!(err, crate::Error::NeedsMachineAuth),
            "MachineNotAuthorized(None) must map to the distinct NeedsMachineAuth, got {err:?}"
        );
        // Specifically NOT the generic internal machine-auth error (the pre-tsr-dvu mapping that the
        // runner treated as a hard failure).
        assert!(!matches!(
            err,
            crate::Error::Internal(crate::InternalErrorKind::MachineAuthorization, _)
        ));
    }

    /// `MachineNotAuthorized(Some(url))` — the interactive-login case — is UNCHANGED by tsr-dvu: it
    /// still maps to the URL-carrying `crate::Error::MachineNotAuthorized(url)` (the runner surfaces
    /// `NeedsLogin`).
    #[test]
    fn machine_not_authorized_some_maps_to_machine_not_authorized_url() {
        let url: Url = "https://login.example.com/a/abc123".parse().unwrap();
        let err = crate::Error::from(RegistrationError::MachineNotAuthorized(Some(url.clone())));
        assert_eq!(err, crate::Error::MachineNotAuthorized(url));
    }

    /// Regression: a hard `Rejected(msg)` (bad/expired/unknown key — what `classify_register_response`
    /// returns for not-authorized WITH an error reason) maps to `crate::Error::Registration(msg)`,
    /// which is DISTINCT from the transient `NeedsMachineAuth`. The runner routes `Registration` to
    /// its terminal `Failed` arm, so a genuine auth failure still terminates — tsr-dvu must NOT turn
    /// real rejections into infinite polls.
    #[test]
    fn rejected_maps_to_registration_not_needs_machine_auth() {
        let err = crate::Error::from(RegistrationError::Rejected("invalid key".to_string()));
        assert_eq!(err, crate::Error::Registration("invalid key".to_string()));
        assert!(
            !matches!(err, crate::Error::NeedsMachineAuth),
            "a hard rejection must NOT be the transient await-approval variant"
        );
    }
}
