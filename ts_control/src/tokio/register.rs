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
            RegistrationError::MachineNotAuthorized(None) => crate::Error::Internal(
                crate::InternalErrorKind::MachineAuthorization,
                crate::Operation::Registration,
            ),
            RegistrationError::Rejected(msg) => crate::Error::Registration(msg),
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

    let register_req = RegisterRequest {
        version: CapabilityVersion::CURRENT,
        node_key: node_public_key,
        old_node_key: node_keystate.old_node_key,
        hostinfo: HostInfo {
            hostname: config.hostname.as_deref().map(std::borrow::Cow::Borrowed),
            app: &config.format_client_name(),
            ipn_version: crate::PKG_VERSION,
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

    if !status.is_success() {
        // Attempt to collect the body to log the error, truncating to prevent spamming the logs.
        let mut body = response.collect_bytes().await.unwrap_or_default();
        body.truncate(512);
        let body = core::str::from_utf8(&body).unwrap_or("<invalid utf8>");
        tracing::error!(%body, %status, "registration failed");

        return Err(RegistrationError::Internal(InternalErrorKind::Http));
    }

    let body = response.collect_bytes().await?;
    let body = core::str::from_utf8(&body)?;

    tracing::trace!(registration_response_body = %body);

    let register_resp: RegisterResponse = serde_json::from_str(body)?;

    classify_register_response(&register_resp)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
