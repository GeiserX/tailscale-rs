//! Wire types for the Tailnet-Lock (TKA) **mutation** RPCs, all Noise-tunnelled `GET`-with-JSON-body
//! to `/machine/tka/*` (same transport shape as the sync RPCs in [`crate::tka_sync`]):
//!
//! - `GET /machine/tka/init/begin`  — [`TkaInitBeginRequest`]  → [`TkaInitBeginResponse`]
//! - `GET /machine/tka/init/finish` — [`TkaInitFinishRequest`] → [`TkaInitFinishResponse`]
//! - `GET /machine/tka/sign`        — [`TkaSubmitSignatureRequest`] → [`TkaSubmitSignatureResponse`]
//! - `GET /machine/tka/disable`     — [`TkaDisableRequest`] → [`TkaDisableResponse`]
//!
//! Mirrors Go `tailcfg.TKAInitBeginRequest`/`Response`, `TKAInitFinishRequest`/`Response`,
//! `TKASubmitSignatureRequest`/`Response`, `TKADisableRequest`/`Response` and the `TKASignInfo`
//! element (`tailcfg/tka.go`, v1.100.0). Go uses no `json:"..."` rename tags on these, so the wire
//! field names are the Go field names verbatim → `PascalCase` here.
//!
//! Wire encodings to get byte-exact (Go `encoding/json` over the underlying types):
//! - `Version` is `CapabilityVersion` (`int`) → plain JSON number.
//! - `NodeKey`/`NodePublic` are `key.NodePublic` → the `nodekey:`+lowercase-hex string
//!   ([`NodePublicKey`]'s own serde).
//! - `GenesisAUM`/`Signature`/`RotationPubkey`/`SupportDisablement`/`DisablementSecret` are
//!   `[]byte`-underlying (`tkatype.MarshaledAUM`/`MarshaledSignature`/plain `[]byte`), which Go's
//!   `encoding/json` emits as **standard base64 (padded)** — the [`crate::marshaled_bytes`] module.
//! - `Head` is a Go `string` already holding the **base32 (std alphabet, no padding)** text form of a
//!   32-byte AUM hash (`tka.AUMHash.MarshalText`); carried as a `String` verbatim (the RPC client
//!   converts to/from [`AumHash`](ts_tka)).
//! - `Signatures` is Go `map[NodeID]tkatype.MarshaledSignature`. Go's `encoding/json` encodes an
//!   integer-keyed map as a JSON object with **decimal-string keys** (e.g. `"42"`) → base64 values.
//!   Modeled as a `BTreeMap<String, Vec<u8>>` (string keys = the decimal `NodeID`, base64 values) —
//!   the faithful mirror, with deterministic key ordering.
//! - `SupportDisablement` is the one `omitempty` field — skipped when empty so it disappears from the
//!   JSON, matching Go.

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use ts_capabilityversion::CapabilityVersion;
use ts_keys::NodePublicKey;

/// Request body for `GET /machine/tka/init/begin` (Go `tailcfg.TKAInitBeginRequest`): the node
/// proposes the genesis AUM that would establish the lock.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TkaInitBeginRequest {
    /// Client capability version (serializes as `Version`).
    pub version: CapabilityVersion,
    /// This node's public key (`nodekey:`+hex).
    pub node_key: NodePublicKey,
    /// The proposed genesis AUM, raw CBOR bytes (Go `tkatype.MarshaledAUM`), base64 on the wire.
    #[serde(rename = "GenesisAUM", with = "marshaled_bytes")]
    pub genesis_aum: Vec<u8>,
}

/// One entry in [`TkaInitBeginResponse::need_signatures`] (Go `tailcfg.TKASignInfo`): a node control
/// needs a fresh network-lock signature for before the lock can be finalized.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TkaSignInfo {
    /// The node's stable id (Go `NodeID`, an `int64`) — a plain JSON number here (it is a field, not
    /// a map key).
    #[serde(rename = "NodeID")]
    pub node_id: i64,
    /// The node's public key (`nodekey:`+hex).
    pub node_public: NodePublicKey,
    /// The node's rotation public key — raw ed25519 public-key bytes (Go `[]byte`), base64 on the
    /// wire. Empty/absent when the node has none.
    #[serde(with = "marshaled_bytes", default)]
    pub rotation_pubkey: Vec<u8>,
}

/// Response to `GET /machine/tka/init/begin` (Go `tailcfg.TKAInitBeginResponse`): the set of nodes
/// that must be (re)signed under the proposed lock before `init/finish` will be accepted.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TkaInitBeginResponse {
    /// The nodes needing signatures. Empty when none are required.
    #[serde(default)]
    pub need_signatures: Vec<TkaSignInfo>,
}

/// Request body for `GET /machine/tka/init/finish` (Go `tailcfg.TKAInitFinishRequest`): the
/// per-node signatures produced for the nodes named in the begin response, finalizing the lock.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TkaInitFinishRequest {
    /// Client capability version.
    pub version: CapabilityVersion,
    /// This node's public key (`nodekey:`+hex).
    pub node_key: NodePublicKey,
    /// The signatures, keyed by `NodeID`. Go's `map[NodeID]MarshaledSignature` JSON-encodes as an
    /// object with **decimal-string keys** (the `int64` `NodeID`) → base64 NKS bytes; modeled as a
    /// `BTreeMap<String, Vec<u8>>` so the wire object round-trips byte-for-byte (deterministic order).
    #[serde(with = "node_id_keyed_sigs")]
    pub signatures: BTreeMap<String, Vec<u8>>,
    /// The disablement secret(s) the lock should support, raw bytes (Go `[]byte`), base64 on the
    /// wire. The only `omitempty` field — skipped entirely when empty, matching Go.
    #[serde(
        rename = "SupportDisablement",
        with = "marshaled_bytes",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub support_disablement: Vec<u8>,
}

/// Response to `GET /machine/tka/init/finish` (Go `tailcfg.TKAInitFinishResponse`): empty
/// (`// Nothing. (yet?)` in Go) — an empty JSON object on success.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TkaInitFinishResponse {}

/// Request body for `GET /machine/tka/sign` (Go `tailcfg.TKASubmitSignatureRequest`): submit a
/// node-key signature (Direct or Rotation) to authorize a node under the lock.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TkaSubmitSignatureRequest {
    /// Client capability version.
    pub version: CapabilityVersion,
    /// The **submitter's** node key (`nodekey:`+hex) — not necessarily the node being signed (the
    /// signed node key is embedded inside the NKS at `signature`).
    pub node_key: NodePublicKey,
    /// The signature: raw CBOR bytes of a `NodeKeySignature` (Go `tkatype.MarshaledSignature`),
    /// base64 on the wire.
    #[serde(with = "marshaled_bytes")]
    pub signature: Vec<u8>,
}

/// Response to `GET /machine/tka/sign` (Go `tailcfg.TKASubmitSignatureResponse`): empty
/// (`// Nothing. (yet?)`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TkaSubmitSignatureResponse {}

/// Request body for `GET /machine/tka/disable` (Go `tailcfg.TKADisableRequest`): present the
/// disablement secret to turn the lock off.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TkaDisableRequest {
    /// Client capability version.
    pub version: CapabilityVersion,
    /// This node's public key (`nodekey:`+hex).
    pub node_key: NodePublicKey,
    /// The chain head the disablement targets, base32 (std, no-pad) text form of the 32-byte AUM
    /// hash. A plain `String` (Go carries the already-encoded text, not re-encoded).
    pub head: String,
    /// The disablement secret, raw bytes (Go `[]byte`), base64 on the wire.
    #[serde(rename = "DisablementSecret", with = "marshaled_bytes")]
    pub disablement_secret: Vec<u8>,
}

/// Response to `GET /machine/tka/disable` (Go `tailcfg.TKADisableResponse`): empty
/// (`// Nothing. (yet?)`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TkaDisableResponse {}

/// Serde for Go `map[NodeID]tkatype.MarshaledSignature`: a JSON object whose keys are the decimal
/// `int64` `NodeID`s (as strings, per Go `encoding/json`) and whose values are standard-base64 of the
/// raw CBOR NKS bytes. Bridges `BTreeMap<String, Vec<u8>>` ⇄ that object without an intermediate type.
mod node_id_keyed_sigs {
    use super::*;

    pub fn serialize<S>(map: &BTreeMap<String, Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut m = serializer.serialize_map(Some(map.len()))?;
        for (k, v) in map {
            m.serialize_entry(k, &STANDARD.encode(v))?;
        }
        m.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BTreeMap<String, Vec<u8>>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // A `null` (Go nil map) deserializes to the empty map; otherwise an object of base64 strings.
        let raw: Option<BTreeMap<String, String>> = Option::deserialize(deserializer)?;
        let Some(raw) = raw else {
            return Ok(BTreeMap::new());
        };
        raw.into_iter()
            .map(|(k, s)| {
                STANDARD
                    .decode(s.as_bytes())
                    .map(|bytes| (k, bytes))
                    .map_err(|e| serde::de::Error::custom(e.to_string()))
            })
            .collect()
    }
}

/// Serde for a single Go `[]byte`: a standard-base64 JSON string ⇄ `Vec<u8>` (Go `encoding/json`
/// base64-encodes a `[]byte`). An absent/`null` field decodes to the empty `Vec`. The same shape as
/// `tka_bootstrap`'s private `marshaled_bytes` and `tka_sync`'s `marshaled_aums` (per-element);
/// duplicated here as a small self-contained module, matching this crate's per-module serde pattern.
/// Used for `omitempty` fields too (paired with `skip_serializing_if`, which drops an empty field).
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
    fn init_begin_request_wire_shape() {
        let req = TkaInitBeginRequest {
            version: CapabilityVersion::CURRENT,
            node_key: NodePublicKey::from([7u8; 32]),
            genesis_aum: alloc::vec![1u8, 2, 3],
        };
        let json = serde_json::to_value(&req).unwrap();
        assert!(json.get("Version").is_some(), "Version present");
        assert!(
            json.get("NodeKey")
                .and_then(|v| v.as_str())
                .unwrap()
                .starts_with("nodekey:"),
            "NodeKey is nodekey:+hex"
        );
        assert_eq!(
            json.get("GenesisAUM").and_then(|v| v.as_str()).unwrap(),
            "AQID",
            "GenesisAUM is base64(0x01 0x02 0x03)"
        );
        // Round-trips.
        let back: TkaInitBeginRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn init_begin_response_need_signatures() {
        let json = r#"{"NeedSignatures":[{"NodeID":42,"NodePublic":"nodekey:0707070707070707070707070707070707070707070707070707070707070707","RotationPubkey":"AQID"}]}"#;
        let resp: TkaInitBeginResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.need_signatures.len(), 1);
        let info = &resp.need_signatures[0];
        assert_eq!(info.node_id, 42, "NodeID is a plain number field");
        assert_eq!(info.rotation_pubkey, alloc::vec![1u8, 2, 3]);
        // null / absent NeedSignatures → empty.
        let empty: TkaInitBeginResponse = serde_json::from_str("{}").unwrap();
        assert!(empty.need_signatures.is_empty());
    }

    #[test]
    fn init_finish_signatures_map_has_decimal_string_keys() {
        let mut signatures = BTreeMap::new();
        signatures.insert("42".to_string(), alloc::vec![0xffu8]);
        signatures.insert("7".to_string(), alloc::vec![1u8, 2]);
        let req = TkaInitFinishRequest {
            version: CapabilityVersion::CURRENT,
            node_key: NodePublicKey::from([3u8; 32]),
            signatures,
            support_disablement: Vec::new(),
        };
        let json = serde_json::to_value(&req).unwrap();
        let sigs = json.get("Signatures").and_then(|v| v.as_object()).unwrap();
        // Keys are the decimal NodeIDs as strings; values base64.
        assert_eq!(sigs.get("42").and_then(|v| v.as_str()).unwrap(), "/w==");
        assert_eq!(sigs.get("7").and_then(|v| v.as_str()).unwrap(), "AQI=");
        // SupportDisablement is omitted when empty (Go omitempty).
        assert!(
            json.get("SupportDisablement").is_none(),
            "empty SupportDisablement must be omitted"
        );
        let back: TkaInitFinishRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn init_finish_support_disablement_present_when_set() {
        let req = TkaInitFinishRequest {
            version: CapabilityVersion::CURRENT,
            node_key: NodePublicKey::from([3u8; 32]),
            signatures: BTreeMap::new(),
            support_disablement: alloc::vec![9u8, 9, 9],
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(
            json.get("SupportDisablement")
                .and_then(|v| v.as_str())
                .unwrap(),
            "CQkJ",
            "SupportDisablement present + base64 when non-empty"
        );
        // An empty Signatures map serializes as an empty object and round-trips.
        let back: TkaInitFinishRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn init_finish_response_is_empty_object() {
        let resp: TkaInitFinishResponse = serde_json::from_str("{}").unwrap();
        assert_eq!(resp, TkaInitFinishResponse {});
        assert_eq!(serde_json::to_string(&resp).unwrap(), "{}");
    }

    #[test]
    fn submit_signature_request_roundtrips() {
        let req = TkaSubmitSignatureRequest {
            version: CapabilityVersion::CURRENT,
            node_key: NodePublicKey::from([5u8; 32]),
            signature: alloc::vec![1u8, 2, 3, 4],
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(
            json.get("Signature").and_then(|v| v.as_str()).unwrap(),
            "AQIDBA==",
            "Signature is base64(CBOR NKS bytes)"
        );
        let back: TkaSubmitSignatureRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn disable_request_head_is_plain_string_secret_is_base64() {
        let req = TkaDisableRequest {
            version: CapabilityVersion::CURRENT,
            node_key: NodePublicKey::from([1u8; 32]),
            head: "AEBAGBAF".to_string(),
            disablement_secret: alloc::vec![0xde, 0xad],
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(
            json.get("Head").and_then(|v| v.as_str()).unwrap(),
            "AEBAGBAF",
            "Head is the base32 text carried verbatim as a plain string"
        );
        assert_eq!(
            json.get("DisablementSecret")
                .and_then(|v| v.as_str())
                .unwrap(),
            "3q0=",
            "DisablementSecret is base64(0xde 0xad)"
        );
        let back: TkaDisableRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn empty_responses_serialize_as_empty_objects() {
        assert_eq!(
            serde_json::to_string(&TkaSubmitSignatureResponse {}).unwrap(),
            "{}"
        );
        assert_eq!(serde_json::to_string(&TkaDisableResponse {}).unwrap(), "{}");
    }
}
