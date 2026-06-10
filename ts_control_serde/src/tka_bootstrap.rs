//! Wire types for the Tailnet-Lock (TKA) **bootstrap** RPC (`GET /machine/tka/bootstrap`,
//! Noise-tunnelled).
//!
//! Bootstrap is the *entry* to TKA sync: before a node can run the offer/send catch-up handshake it
//! needs an initial chain to offer. It sends control its current head (empty on first run) and
//! control returns the **genesis AUM** — the node verifies it (`ts_tka::VerifiedAumChain::verify`)
//! and builds its initial `Authority` from it, then syncs forward to the current head.
//!
//! Mirrors Go `tailcfg.TKABootstrapRequest` / `TKABootstrapResponse` (`tailcfg/tka.go`, v1.100.0).
//! Wire encodings:
//! - `Head` is the node's current head as a base32 (no-pad) AUM-hash string, **empty** when the node
//!   has no chain yet (Go: "if tailnet lock is enabled"). Carried as `String`.
//! - `GenesisAUM` (Go `tkatype.MarshaledAUM` = `[]byte`, `json:",omitempty"`) and `DisablementSecret`
//!   (Go `[]byte`, `json:",omitempty"`) are **single** values that Go's `encoding/json`
//!   base64-encodes (not arrays, unlike the sync `MissingAUMs`). The [`marshaled_bytes`] serde module
//!   maps `Vec<u8>` ⇄ a single standard-base64 string, and an absent/empty field ⇄ an empty `Vec`.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use ts_capabilityversion::CapabilityVersion;
use ts_keys::NodePublicKey;

/// Request body for `GET /machine/tka/bootstrap` (Go `tailcfg.TKABootstrapRequest`): ask control for
/// the genesis AUM needed to initialize TKA.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TkaBootstrapRequest {
    /// Client capability version (serializes as `Version`).
    pub version: CapabilityVersion,
    /// This node's public key (serializes as `NodeKey` → `nodekey:`+hex).
    pub node_key: NodePublicKey,
    /// The node's current head, base32 (no-pad) AUM-hash text — **empty** when TKA is not yet
    /// initialized locally (the first-run case).
    pub head: String,
}

/// Response to `GET /machine/tka/bootstrap` (Go `tailcfg.TKABootstrapResponse`): the genesis AUM (so
/// the node can build its initial `Authority`) and the disablement secret.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TkaBootstrapResponse {
    /// The initial AUM needed to initialize TKA — raw CBOR bytes, base64 on the wire (Go
    /// `tkatype.MarshaledAUM`, `omitempty`). Empty when control sends none (e.g. TKA not enabled).
    #[serde(rename = "GenesisAUM", with = "marshaled_bytes", default)]
    pub genesis_aum: Vec<u8>,
    /// A secret needed to disable TKA — base64 on the wire (Go `[]byte`, `omitempty`). Not used by a
    /// read-only sync client, but decoded for completeness. Empty when absent.
    #[serde(with = "marshaled_bytes", default)]
    pub disablement_secret: Vec<u8>,
}

/// Serde for a single Go `[]byte` (`omitempty`): a standard-base64 JSON string ⇄ `Vec<u8>`. Go's
/// `encoding/json` base64-encodes a `[]byte`; an absent or `null` field decodes to the empty `Vec`
/// (the field's zero value), and an empty `Vec` serializes to an empty base64 string. Distinct from
/// `tka_sync`'s `marshaled_aums`, which handles an *array* of such values.
mod marshaled_bytes {
    use super::*;

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: Option<String> = Option::deserialize(deserializer)?;
        let Some(s) = s else {
            return Ok(Vec::new());
        };
        if s.is_empty() {
            return Ok(Vec::new());
        }
        STANDARD
            .decode(s.as_bytes())
            .map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_request_pascalcase_nodekey_and_head() {
        let req = TkaBootstrapRequest {
            version: CapabilityVersion::CURRENT,
            node_key: NodePublicKey::from([7u8; 32]),
            head: String::new(), // first-run: empty head
        };
        let json = serde_json::to_value(&req).unwrap();
        assert!(json.get("Version").is_some());
        assert_eq!(json.get("Head").and_then(|v| v.as_str()), Some(""));
        let nk = json.get("NodeKey").and_then(|v| v.as_str()).unwrap();
        assert!(
            nk.starts_with("nodekey:"),
            "NodeKey is nodekey:+hex, got {nk}"
        );
    }

    #[test]
    fn bootstrap_response_genesis_aum_is_base64() {
        // GenesisAUM {1,2,3} must encode as a single base64 string "AQID" and round-trip.
        let resp = TkaBootstrapResponse {
            genesis_aum: alloc::vec![1u8, 2, 3],
            disablement_secret: alloc::vec![0xffu8],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(
            json.get("GenesisAUM").and_then(|v| v.as_str()),
            Some("AQID")
        );
        assert_eq!(
            json.get("DisablementSecret").and_then(|v| v.as_str()),
            Some("/w==")
        );
        let back: TkaBootstrapResponse = serde_json::from_value(json).unwrap();
        assert_eq!(back, resp);
    }

    #[test]
    fn bootstrap_response_absent_genesis_is_empty() {
        // Control sends nothing (TKA not enabled / omitempty) → empty Vec, not an error.
        let resp: TkaBootstrapResponse = serde_json::from_str("{}").unwrap();
        assert!(resp.genesis_aum.is_empty());
        assert!(resp.disablement_secret.is_empty());
        // Explicit null also decodes to empty.
        let resp2: TkaBootstrapResponse =
            serde_json::from_str(r#"{"GenesisAUM":null,"DisablementSecret":null}"#).unwrap();
        assert!(resp2.genesis_aum.is_empty());
    }

    #[test]
    fn bootstrap_request_roundtrips_with_head() {
        let req = TkaBootstrapRequest {
            version: CapabilityVersion::CURRENT,
            node_key: NodePublicKey::from([3u8; 32]),
            head: "MFRGGZDF".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: TkaBootstrapRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, req);
    }
}
