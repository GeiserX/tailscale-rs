//! Wire types for the Tailnet-Lock (TKA) chain-sync RPCs (`GET /machine/tka/sync/offer` and
//! `GET /machine/tka/sync/send`, both Noise-tunnelled).
//!
//! A node catches its local TKA chain up to control's via a two-step handshake: it POSTs — actually
//! a `GET` carrying a JSON body, matching Go — its [`TkaSyncOfferRequest`] (its head + a sparse
//! ancestor sample), control replies with the AUMs the node is missing plus control's own offer
//! ([`TkaSyncOfferResponse`]); the node then sends control the AUMs *it* is missing in a
//! [`TkaSyncSendRequest`].
//!
//! Mirrors Go `tailcfg.TKASyncOfferRequest`/`Response` + `TKASyncSendRequest`/`Response`
//! (`tailcfg/tka.go`, v1.100.0). Wire encodings to get byte-exact:
//! - `Head` / `Ancestors[]` are **base32** (RFC4648 standard alphabet, no padding) text forms of the
//!   32-byte AUM hashes (Go `AUMHash.MarshalText`). Carried here as `String` — the RPC client
//!   converts to/from `ts_tka::AumHash`.
//! - `MissingAUMs` is Go `[]tkatype.MarshaledAUM` = `[][]byte`, which Go's `encoding/json`
//!   **base64-encodes** (standard) per element. So on the wire it is a JSON array of base64 strings,
//!   each decoding to a raw CBOR-serialized AUM. The [`marshaled_aums`] serde module does exactly
//!   that (no intermediate type): `Vec<Vec<u8>>` ⇄ JSON array of base64 strings.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use ts_capabilityversion::CapabilityVersion;
use ts_keys::NodePublicKey;

/// Request body for `GET /machine/tka/sync/offer` (Go `tailcfg.TKASyncOfferRequest`): the node's
/// current chain head + a sparse ancestor sample, so control can compute what to send back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TkaSyncOfferRequest {
    /// Client capability version (serializes as `Version`).
    pub version: CapabilityVersion,
    /// This node's public key (serializes as `NodeKey` → `nodekey:`+hex).
    pub node_key: NodePublicKey,
    /// The node's current chain head, base32 (no-pad) text form of the 32-byte AUM hash.
    pub head: String,
    /// An exponentially-spaced sample of ancestors, newest-first, ending with the oldest-known AUM;
    /// each is a base32 (no-pad) AUM-hash text form.
    pub ancestors: Vec<String>,
}

/// Response to `GET /machine/tka/sync/offer` (Go `tailcfg.TKASyncOfferResponse`): control's own
/// offer (its head + ancestors) plus the AUMs it computed the node is missing.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TkaSyncOfferResponse {
    /// Control's current chain head (base32 no-pad).
    pub head: String,
    /// Control's ancestor sample (base32 no-pad each).
    pub ancestors: Vec<String>,
    /// The AUMs the node is missing — each raw CBOR bytes, base64 on the wire (Go
    /// `[]tkatype.MarshaledAUM`). Empty/absent when the node is already up to date.
    #[serde(rename = "MissingAUMs", with = "marshaled_aums", default)]
    pub missing_aums: Vec<Vec<u8>>,
}

/// Request body for `GET /machine/tka/sync/send` (Go `tailcfg.TKASyncSendRequest`): the node's
/// (post-`Inform`) head plus the AUMs control is missing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TkaSyncSendRequest {
    /// Client capability version.
    pub version: CapabilityVersion,
    /// This node's public key (`nodekey:`+hex).
    pub node_key: NodePublicKey,
    /// The node's head after applying the AUMs from the offer response (base32 no-pad).
    pub head: String,
    /// The AUMs control is missing — raw CBOR bytes, base64 on the wire.
    #[serde(rename = "MissingAUMs", with = "marshaled_aums", default)]
    pub missing_aums: Vec<Vec<u8>>,
    /// Whether this sync is interactive (Go `Interactive`). Always `false` for a background catch-up.
    pub interactive: bool,
}

/// Response to `GET /machine/tka/sync/send` (Go `tailcfg.TKASyncSendResponse`): control's resulting
/// head after applying the node's AUMs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TkaSyncSendResponse {
    /// Control's chain head after the send (base32 no-pad).
    pub head: String,
}

/// Serde for Go `[]tkatype.MarshaledAUM` (= `[][]byte`): a JSON array of **standard-base64** strings,
/// each the raw CBOR bytes of one AUM. Go's `encoding/json` base64-encodes a `[]byte`; serde's
/// default would emit an array-of-ints, so this module bridges the two without an intermediate type.
mod marshaled_aums {
    use super::*;

    pub fn serialize<S>(aums: &[Vec<u8>], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(aums.len()))?;
        for aum in aums {
            seq.serialize_element(&STANDARD.encode(aum))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // A `null` (Go nil slice) deserializes to the empty vec; otherwise a list of base64 strings.
        let strs: Option<Vec<String>> = Option::deserialize(deserializer)?;
        let Some(strs) = strs else {
            return Ok(Vec::new());
        };
        strs.into_iter()
            .map(|s| {
                STANDARD
                    .decode(s.as_bytes())
                    .map_err(|e| serde::de::Error::custom(e.to_string()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offer_request_serializes_pascalcase_with_nodekey_and_base32_head() {
        let req = TkaSyncOfferRequest {
            version: CapabilityVersion::CURRENT,
            node_key: NodePublicKey::from([7u8; 32]),
            head: "AEBAGBAF".to_string(),
            ancestors: alloc::vec!["AEBAGBAF".to_string(), "MFRGGZDF".to_string()],
        };
        let json = serde_json::to_value(&req).unwrap();
        assert!(json.get("Version").is_some());
        assert!(json.get("Head").is_some());
        assert!(json.get("Ancestors").is_some());
        let nk = json.get("NodeKey").and_then(|v| v.as_str()).unwrap();
        assert!(
            nk.starts_with("nodekey:"),
            "NodeKey is nodekey:+hex, got {nk}"
        );
    }

    #[test]
    fn offer_response_missing_aums_are_base64() {
        // A response carrying two AUMs (raw bytes {1,2,3} and {0xff}) must encode them as base64
        // strings, and round-trip back to the same bytes.
        let resp = TkaSyncOfferResponse {
            head: "AEBAGBAF".to_string(),
            ancestors: Vec::new(),
            missing_aums: alloc::vec![alloc::vec![1u8, 2, 3], alloc::vec![0xffu8]],
        };
        let json = serde_json::to_value(&resp).unwrap();
        let arr = json.get("MissingAUMs").and_then(|v| v.as_array()).unwrap();
        assert_eq!(arr[0].as_str().unwrap(), "AQID"); // base64(0x01 0x02 0x03)
        assert_eq!(arr[1].as_str().unwrap(), "/w=="); // base64(0xff)
        let back: TkaSyncOfferResponse = serde_json::from_value(json).unwrap();
        assert_eq!(back.missing_aums, resp.missing_aums);
    }

    #[test]
    fn offer_response_missing_aums_null_is_empty() {
        // Go sends `null` (or omits) MissingAUMs when nothing is missing → empty vec, not an error.
        let resp: TkaSyncOfferResponse =
            serde_json::from_str(r#"{"Head":"AEBAGBAF","Ancestors":[],"MissingAUMs":null}"#)
                .unwrap();
        assert!(resp.missing_aums.is_empty());
        // Absent entirely (default) also works.
        let resp2: TkaSyncOfferResponse =
            serde_json::from_str(r#"{"Head":"AEBAGBAF","Ancestors":[]}"#).unwrap();
        assert!(resp2.missing_aums.is_empty());
    }

    #[test]
    fn send_request_roundtrips() {
        let req = TkaSyncSendRequest {
            version: CapabilityVersion::CURRENT,
            node_key: NodePublicKey::from([3u8; 32]),
            head: "MFRGGZDF".to_string(),
            missing_aums: alloc::vec![alloc::vec![9u8, 9]],
            interactive: false,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: TkaSyncSendRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, req);
        assert!(json.contains("\"Interactive\":false"));
    }

    #[test]
    fn send_response_deserializes() {
        let resp: TkaSyncSendResponse = serde_json::from_str(r#"{"Head":"MFRGGZDF"}"#).unwrap();
        assert_eq!(resp.head, "MFRGGZDF");
    }
}
