//! Wire types for control-side DNS record publishing (`POST /machine/set-dns`).
//!
//! A registered node can ask control to publish a DNS record into the tailnet's `ts.net` zone.
//! The product use is the ACME **DNS-01** challenge: the node publishes a
//! `_acme-challenge.<host>.<tailnet>.ts.net` `TXT` record carrying the base64url challenge digest,
//! lets the ACME CA verify it, then obtains a certificate.
//!
//! Mirrors Go `tailcfg.SetDNSRequest` / `tailcfg.SetDNSResponse`, exchanged over the Noise
//! (ts2021) transport.

use alloc::string::String;

use serde::{Deserialize, Serialize};
use ts_capabilityversion::CapabilityVersion;
use ts_keys::NodePublicKey;

/// Request body for `POST /machine/set-dns` (Go `tailcfg.SetDNSRequest`): ask control to publish a
/// DNS record (used for the ACME DNS-01 `_acme-challenge` TXT) into the tailnet's `ts.net` zone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct SetDnsRequest {
    /// Client capability version (serializes as `Version`).
    pub version: CapabilityVersion,
    /// This node's public key (serializes as `NodeKey` → `nodekey:`+hex), carried in the BODY.
    pub node_key: NodePublicKey,
    /// The full record name, e.g. `_acme-challenge.host.tailnet.ts.net`.
    pub name: String,
    /// The DNS record type, e.g. `TXT`.
    ///
    /// The raw-identifier `r#type` is renamed explicitly so the wire key is `Type` (PascalCase
    /// alone is not relied upon to strip the `r#` prefix).
    #[serde(rename = "Type")]
    pub r#type: String,
    /// The record value (the base64url DNS-01 digest for a TXT challenge).
    pub value: String,
}

/// Response to `POST /machine/set-dns` (Go `tailcfg.SetDNSResponse`): currently empty; HTTP 200 with
/// an empty/`{}` body signals success.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SetDnsResponse {}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn set_dns_request_serializes_pascalcase() {
        let req = SetDnsRequest {
            version: CapabilityVersion::CURRENT,
            node_key: NodePublicKey::from([7u8; 32]),
            name: "_acme-challenge.host.tailnet.ts.net".to_string(),
            r#type: "TXT".to_string(),
            value: "base64url-digest".to_string(),
        };
        let json = serde_json::to_value(&req).unwrap();
        // Go default (capitalized) encoding for every field, incl. the raw-ident `Type`.
        assert!(json.get("Version").is_some());
        assert!(json.get("Name").is_some());
        assert!(json.get("Type").is_some());
        assert!(json.get("Value").is_some());
        // NodeKey is the `nodekey:`+hex string form (carried in the body).
        let node_key = json.get("NodeKey").and_then(|v| v.as_str()).unwrap();
        assert!(
            node_key.starts_with("nodekey:"),
            "NodeKey should serialize as nodekey:+hex, got {node_key}"
        );
    }

    #[test]
    fn set_dns_response_deserializes_empty() {
        let resp: SetDnsResponse = serde_json::from_str("{}").unwrap();
        assert_eq!(resp, SetDnsResponse::default());
    }
}
