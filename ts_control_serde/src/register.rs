use alloc::borrow::Cow;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ts_keys::{NetworkLockPublicKey, NodePublicKey};
use url::Url;

use crate::{
    host_info::HostInfo,
    user::{Login, User},
};

/// Authentication information for a Tailscale node, allowing it to register with the control
/// plane and join a specific Tailnet.
///
/// In the Go codebase, this struct is named `RegisterResponseAuth` and contains another field
/// named `Oauth2Token`; this field was only used for Tailscale v1.66 and earlier on Android, so
/// is not present in `tailscale-rs`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RegisterAuth<'a> {
    /// A Tailscale auth key that can register a node to a specific Tailnet.
    pub auth_key: &'a str,
}

impl<'a> From<&'a str> for RegisterAuth<'a> {
    fn from(value: &'a str) -> Self {
        Self { auth_key: value }
    }
}

/// Historical; should always be [`SignatureType::None`] today.
///
/// Specifies a scheme for signing [`RegisterRequest`]s. It specifies the crypto algorithms to use,
/// the contents of what is signed, and any other relevant details.
#[repr(isize)]
#[derive(Clone, Debug, Default, PartialEq, serde_repr::Serialize_repr)]
pub enum SignatureType {
    /// No signature is present.
    #[default]
    None = 0,
    /// Signature type is unknown.
    Unknown = 1,
    /// Signed in the v1 format.
    V1 = 2,
    /// Signed in the v2 format.
    V2 = 3,
}

/// A request from a Tailscale node to the control plane, asking to register the node with the
/// given node key.
///
/// This is JSON-encoded and sent over the control plane connection to
/// `POST https://<control-plane>/machine/register`.
#[serde_with::apply(
    bool => #[serde(skip_serializing_if = "crate::util::is_default")],
    &str => #[serde(borrow)] #[serde(skip_serializing_if = "str::is_empty")],
    Option => #[serde(skip_serializing_if = "Option::is_none")],
    Vec => #[serde(skip_serializing_if = "Vec::is_empty")],
     _ => #[serde(default)],
)]
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RegisterRequest<'a> {
    /// This Tailscale node's capabilities when using the Noise transport. When using the original
    /// nacl `crypto_box` transport, the value must be `1`.
    pub version: ts_capabilityversion::CapabilityVersion,

    /// The current public key of this Tailscale node. In the case of node key rotation, this is
    /// the "new" node public key, and [`RegisterRequest::old_node_key`] contains the expired
    /// public node key.
    pub node_key: NodePublicKey,
    /// The expired public key of this Tailscale node. Only populated when the node key has expired
    /// and needs to be rotated.
    pub old_node_key: Option<NodePublicKey>,
    /// The new Tailnet Lock public key for this Tailscale node. Only populated when the key has
    /// been changed, or has never been set for this node.
    #[serde(rename = "NLKey")]
    pub nl_key: Option<NetworkLockPublicKey>,
    /// Authentication information that allows this Tailscale node to register with the control
    /// plane and join a specific Tailnet.
    #[serde(borrow)]
    pub auth: Option<RegisterAuth<'a>>,
    /// Optionally specifies the requested node key expiry. The control server policy may override
    /// this value.
    ///
    /// If [`RegisterRequest::expiry`] is in the past and [`RegisterRequest::node_key`] is the
    /// current node key for this Tailscale node, the node key is expired immediately.
    pub expiry: Option<DateTime<Utc>>,
    /// If populated, indicates that this is a followup request, and the Tailscale node has
    /// presented this URL to the user for interactive authentication. The control server will
    /// not send a [`RegisterResponse`] until this followup URL has been visited and the user
    /// successfully authenticated.
    pub followup: Option<Url>,
    /// Summary of the Tailscale host that this Tailscale node is running on.
    #[serde(borrow)]
    pub hostinfo: HostInfo<'a>,
    /// If `true`, this Tailscale node should be considered ephemeral and deleted automatically
    /// from the control plane/Tailnet when it becomes inactive.
    pub ephemeral: bool,

    /// Historical; refers to how [`RegisterRequest`]s were signed with RSA certificates. Should
    /// always be [`SignatureType::None`].
    #[serde(skip_serializing_if = "crate::util::is_default")]
    pub signature_type: SignatureType,
    /// Historical; part of old request signing mechanism. Should always be `None`.
    pub timestamp: Option<DateTime<Utc>>,
    /// Historical; part of old request signing mechanism. Should always be `None`.
    #[serde(borrow)]
    pub device_cert: Option<&'a [u8]>,
    /// Historical; part of old request signing mechanism. Should always be `None`.
    #[serde(borrow)]
    pub signature: Option<&'a [u8]>,

    /// This Tailscale node's own node-key signature, re-signed for its new node key using its
    /// network-lock key.
    ///
    /// This field must be set to the new signature when the node retries registration after
    /// learning its node key signature has expired and needs to be rotated.
    #[serde(borrow)]
    pub node_key_signature: Option<&'a str>,

    /// Optional identifier specifying the name of the recommended or required Tailnet that this
    /// Tailscale node should join. Do not attempt to parse this field or rely on its format; new
    /// forms are being added.
    ///
    /// The identifier is generally a domain name (for an organization) or e-mail address (for a
    /// personal account on a shared e-mail provider). It is the same name used by the API. If the
    /// identifier begins with the prefix "required:", then the control server should prevent
    /// logging in to a different Tailnet than the one specified. Otherwise, the control server
    /// should recommend the specified Tailnet but still permit logging in to other networks. If
    /// empty, no recommendation is offered to the control server, and the login page should show
    /// all options.
    #[serde(borrow)]
    pub tailnet: Option<&'a str>,
}

/// A response from the control plane to a Tailscale node, with the result of a previously-sent
/// [`RegisterRequest`].
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RegisterResponse<'a> {
    /// The Tailscale user that this node was registered with. A single user may be associated with
    /// multiple logins, such as GitHub OAuth and Google.
    ///
    /// See [`RegisterResponse::login`] for the specific login this node was registered with.
    #[serde(borrow)]
    pub user: User<'a>,
    /// The specific login of the [`RegisterResponse::user`] this Tailscale node was registered
    /// with; this login is associated with a specific identity provider.
    #[serde(borrow)]
    pub login: Login<'a>,
    /// If `true`, this Tailscale node's node key has expired and needs to be regenerated.
    pub node_key_expired: bool,
    /// If `true`, registration was successful and this Tailscale node is authorized to join and
    /// communicate on the tailnet. If `false`, registration is pending or failed, and this node
    /// will not be able to communicate with peers.
    pub machine_authorized: bool,
    /// If populated, registration is pending. The user must visit the given link in a browser and
    /// interactively log in to Tailscale via an identity provider; if successful, the node will be
    /// registered and the control plane will send another [`RegisterResponse`] where
    /// `machine_authorized` is `true`.
    #[serde(rename = "AuthURL", borrow)]
    pub auth_url: Cow<'a, str>,
    /// If set, this is the current node key signature that needs to be re-signed for the node's new
    /// node key.
    pub node_key_signature: Option<&'a str>,
    /// If populated, indicates that authorization failed; all other fields must be ignored.
    #[serde(borrow)]
    pub error: Cow<'a, str>,
}

#[cfg(test)]
mod tests {
    use alloc::format;

    use ts_keys::NodePublicKey;

    use super::*;

    /// The `old_node_key` field MUST serialize under the wire name `OldNodeKey` (PascalCase) with
    /// the `nodekey:`+hex string Display form. If the rename/casing drifts, Go control treats a
    /// rotated node as brand-new and silently breaks `regen` key-continuity.
    #[test]
    fn register_request_serializes_old_node_key() {
        let key = NodePublicKey::from([7u8; 32]);
        let req = RegisterRequest {
            old_node_key: Some(key),
            ..Default::default()
        };

        let value = serde_json::to_value(&req).unwrap();
        let obj = value.as_object().expect("serializes to a JSON object");

        let wire = obj
            .get("OldNodeKey")
            .expect("OldNodeKey key present on the wire");
        assert_eq!(wire.as_str().unwrap(), format!("{key}"));
        // Sanity-check the wire value matches the `nodekey:`+hex Display form.
        assert!(wire.as_str().unwrap().starts_with("nodekey:"));
    }

    /// When `old_node_key` is `None`, the `skip_serializing_if = "Option::is_none"` attribute MUST
    /// omit the `OldNodeKey` key entirely (not emit `null`).
    #[test]
    fn register_request_omits_old_node_key_when_none() {
        let req = RegisterRequest {
            old_node_key: None,
            ..Default::default()
        };

        let value = serde_json::to_value(&req).unwrap();
        let obj = value.as_object().expect("serializes to a JSON object");

        assert!(
            !obj.contains_key("OldNodeKey"),
            "OldNodeKey must be omitted when None, got: {obj:?}"
        );
    }

    /// `RegisterResponse::error` is a control-authored failure message typed `Cow<'a, str>`. A
    /// rejection message containing a newline/quote (escaped on the wire) decodes and unescapes; a
    /// bare `&'a str` would fail the whole `RegisterResponse` decode (`expected a borrowed string`),
    /// masking the rejection reason behind a parse error.
    #[test]
    fn register_response_error_with_escape_sequence_decodes() {
        const TEST: &str = r#"{
            "User": { "ID": 1 },
            "Login": { "ID": 2, "Provider": "google", "LoginName": "alice@example.com" },
            "NodeKeyExpired": false,
            "MachineAuthorized": false,
            "AuthURL": "",
            "Error": "denied:\n\"node not permitted\"\\see logs"
        }"#;
        let resp = serde_json::from_str::<RegisterResponse>(TEST)
            .expect("RegisterResponse with an escaped Error must decode");
        assert_eq!(resp.error, "denied:\n\"node not permitted\"\\see logs");
        assert!(!resp.machine_authorized);
    }

    /// The no-escape fast path still decodes: a plain `AuthURL` yields its value unchanged (and
    /// borrows zero-copy, though that is not observable from outside).
    #[test]
    fn register_response_auth_url_without_escape_decodes() {
        const TEST: &str = r#"{
            "User": { "ID": 1 },
            "Login": { "ID": 2, "Provider": "google", "LoginName": "alice@example.com" },
            "NodeKeyExpired": false,
            "MachineAuthorized": false,
            "AuthURL": "https://login.example.com/a/abc123",
            "Error": ""
        }"#;
        let resp = serde_json::from_str::<RegisterResponse>(TEST)
            .expect("RegisterResponse with a plain AuthURL must decode");
        assert_eq!(resp.auth_url, "https://login.example.com/a/abc123");
        assert!(resp.error.is_empty());
    }
}
