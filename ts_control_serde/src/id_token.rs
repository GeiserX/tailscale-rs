//! Wire types for control-issued OIDC **ID tokens** (workload-identity federation).
//!
//! A node that is already registered can ask control to mint a short-lived JWT it can present to a
//! third-party relying party (e.g. AWS/GCP workload-identity federation). The node is the token
//! *subject*, not the authenticator — this is token **issuance**, not a new registration auth path.
//!
//! Mirrors Go `tailcfg.TokenRequest` / `tailcfg.TokenResponse`, exchanged over the Noise transport
//! via `POST /machine/id-token`. Capability version ≥ 30 is required (Go: "2022-03-22: client can
//! request id tokens").

use alloc::string::String;

use serde::{Deserialize, Serialize};
use ts_capabilityversion::CapabilityVersion;
use ts_keys::NodePublicKey;

/// Request to control to mint an OIDC ID token for this node (Go `tailcfg.TokenRequest`).
///
/// Go encodes this struct with default (capitalized) field names — `CapVersion`, `NodeKey`,
/// `Audience` — so it is `PascalCase`, matching the rest of this crate's control wire types.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct TokenRequest {
    /// The client's current capability version (Go `CapVersion`). Control uses this to gate the
    /// feature (≥ 30).
    pub cap_version: CapabilityVersion,
    /// The client's current node public key (Go `NodeKey`); identifies the requesting node.
    pub node_key: NodePublicKey,
    /// The audience (`aud` claim) the minted token is requested for — the relying party that will
    /// verify it. A per-call runtime input, not static config.
    pub audience: String,
}

/// Control's response carrying the minted ID token (Go `tailcfg.TokenResponse`).
///
/// The single field uses the JSON tag `id_token` (the only tagged field in the Go struct), so it is
/// renamed explicitly rather than relying on a case convention.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct TokenResponse {
    /// The signed JWT. Its claims include `sub` = this node's MagicDNS name and `aud` = the
    /// requested [`TokenRequest::audience`], plus node/user/tailnet metadata. Opaque to this crate.
    #[serde(rename = "id_token")]
    pub id_token: String,
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn token_request_serializes_pascalcase() {
        let req = TokenRequest {
            cap_version: CapabilityVersion::CURRENT,
            node_key: NodePublicKey::from([7u8; 32]),
            audience: "sts.amazonaws.com".to_string(),
        };
        let json = serde_json::to_value(&req).unwrap();
        // Field names are capitalized (Go default encoding), and Audience round-trips verbatim.
        assert!(json.get("CapVersion").is_some());
        assert!(json.get("NodeKey").is_some());
        assert_eq!(
            json.get("Audience").and_then(|v| v.as_str()),
            Some("sts.amazonaws.com")
        );
    }

    #[test]
    fn token_response_deserializes_id_token() {
        let resp: TokenResponse =
            serde_json::from_str(r#"{"id_token":"eyJhbGciOi.payload.sig"}"#).unwrap();
        assert_eq!(resp.id_token, "eyJhbGciOi.payload.sig");
    }
}
