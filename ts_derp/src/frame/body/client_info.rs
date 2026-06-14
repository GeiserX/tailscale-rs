use ts_keys::NodePublicKey;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::{
    Nonce,
    frame::{Body, FrameType},
};

/// Sent from client to server as part of the initial handshake, containing the client's
/// public key and capabilities.
///
/// An encrypted JSON-formatted [`ClientInfoPayload`] follows this message immediately.
#[derive(Debug, Copy, Clone, PartialEq, KnownLayout, Immutable, IntoBytes, FromBytes)]
#[repr(C)]
pub struct ClientInfo {
    /// The client's public key.
    pub key: NodePublicKey,
    /// A nonce to decrypt the payload.
    pub nonce: Nonce,
}

impl Body for ClientInfo {
    const FRAME_TYPE: FrameType = FrameType::ClientInfo;
}

/// Payload associated with [`ClientInfo`].
///
/// The JSON field names mirror Go `derp.ClientInfo` exactly: Go's `encoding/json` uses the literal
/// Go field name when a field has no rename tag, so `CanAckPings`/`IsProber` are PascalCase on the
/// wire, while `meshKey`/`version` carry lowercase JSON tags. The keys are therefore a deliberate
/// mix — not uniformly camelCase — so each field is renamed individually rather than via a blanket
/// `rename_all`. `meshKey` and `isProber` are omitted when empty/false, matching Go's `omitempty`.
#[derive(serde::Serialize)]
pub struct ClientInfoPayload {
    /// Whether this client can ack pings. Go field `CanAckPings` (no JSON tag → PascalCase on wire);
    /// not `omitempty` in Go, so it is always serialized.
    #[serde(rename = "CanAckPings")]
    pub can_ack_pings: bool,
    /// Whether this client is a prober. Go field `IsProber` with `json:",omitempty"` → PascalCase
    /// key, omitted when false.
    #[serde(rename = "IsProber", skip_serializing_if = "core::ops::Not::not")]
    pub is_prober: bool,
    /// Mesh pre-shared key, used only for trusted server-to-server (mesh) conns; empty for a regular
    /// leaf client. Go field `MeshKey key.DERPMesh` with `json:"meshKey,omitempty,omitzero"` →
    /// camelCase key, omitted when empty. A leaf client sends no mesh key, so this is `None` (the
    /// key is absent from the JSON), matching Go omitting a zero `DERPMesh`. Carried as an optional
    /// hex string rather than the old `"none"` sentinel, which was never a valid Go `DERPMesh`.
    #[serde(rename = "meshKey", skip_serializing_if = "Option::is_none")]
    pub mesh_key: Option<String>,
    /// Protocol version the client is using. Go field `Version` with `json:"version,omitempty"`.
    #[serde(rename = "version")]
    pub version: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The leaf-client payload must serialize to exactly Go `derp.ClientInfo`'s wire keys: PascalCase
    /// `CanAckPings` (no Go JSON tag), lowercase `version`, with `meshKey` and `IsProber` omitted
    /// (Go `omitempty`). A regression here (e.g. snake_case keys, or a `"none"` mesh sentinel) is the
    /// latent wire fragility this guards: it only "works" against a server that ignores unknown keys.
    #[test]
    fn leaf_client_payload_matches_go_wire_keys() {
        let json = serde_json::to_value(ClientInfoPayload {
            can_ack_pings: false,
            is_prober: false,
            mesh_key: None,
            version: 2,
        })
        .unwrap();

        // Exactly two keys for a leaf client: CanAckPings and version. No meshKey, no IsProber.
        assert_eq!(
            json,
            serde_json::json!({ "CanAckPings": false, "version": 2 }),
            "leaf-client ClientInfo must serialize to Go's exact wire keys with omitempty fields absent"
        );
    }

    /// When set, the optional fields use Go's exact keys: `meshKey` (camelCase) and `IsProber`
    /// (PascalCase). Pins the mix of casing so a future blanket `rename_all` can't silently break it.
    #[test]
    fn populated_payload_uses_go_keys_for_optional_fields() {
        let json = serde_json::to_value(ClientInfoPayload {
            can_ack_pings: true,
            is_prober: true,
            mesh_key: Some("abc123".to_string()),
            version: 2,
        })
        .unwrap();

        assert_eq!(
            json,
            serde_json::json!({
                "CanAckPings": true,
                "IsProber": true,
                "meshKey": "abc123",
                "version": 2,
            }),
            "populated ClientInfo must use Go's mixed-case keys: meshKey + IsProber + CanAckPings"
        );
    }
}
