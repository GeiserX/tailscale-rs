use alloc::{string::String, vec::Vec};
use core::{fmt, net::IpAddr};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::util::{deserialize_base64_string, deserialize_string_list, deserialize_string_option};

/// Represents the kind of ping to perform.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub enum PingType {
    /// Control-to-Node (C2N). Special type of ping sent from the control plane to the local node.
    #[serde(rename = "c2n")]
    C2N,
    /// Ping across DERP servers with disco ping/pong, without involving IP at either end.
    #[serde(rename = "disco")]
    Disco,
    /// Ping using the IP layer, but avoiding the OS IP stack.
    #[serde(rename = "TSMP")]
    Tsmp,
    /// Ping between two Tailscale nodes using ICMP that is received by the target system's IP
    /// stack.
    #[serde(rename = "ICMP")]
    Icmp,
    /// Ping between two Tailscale nodes using PeerAPI via HTTP requests to the target system's
    /// Peer API endpoint.
    #[serde(rename = "peerapi")]
    PeerApi,
}

/// Request from the control plane to the local node to probe something.
///
/// A [`PingRequest`] with empty [`PingRequest::ip`] and [`PingRequest::types`] fields is a request
/// from the control plane to the local node to send an HTTP request to a URL to prove the long-
/// polling client is still connected.
///
/// A [`PingRequest`] with populated [`PingRequest::ip`] and [`PingRequest::types`] fields will
/// send a ping to the IP and send a `POST` request containing a [`PingResponse`] to the URL
/// containing results.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PingRequest {
    /// The URL to reply to the [`PingRequest`] to.
    ///
    /// It will be a unique URL each time. No auth headers are necessary. If the client receives
    /// multiple [`PingRequest`]s with the same URL, subsequent ones should be ignored.
    ///
    /// The HTTP method that the node should make back to URL depends on the other fields of the
    /// [`PingRequest`]. If [`PingRequest::types`] is defined, then [`PingRequest::url`] is the URL
    /// to send a `POST` request to. Otherwise, the node should just make a `HEAD` request to
    /// [`PingRequest::url`].
    #[serde(rename = "URL")]
    pub url: Url,
    /// If `true`, indicates the client should connect to [`PingRequest::url`] over the Noise
    /// transport instead of TLS.
    ///
    /// `#[serde(default)]` is REQUIRED: Go tags this `json:",omitzero"` (`omitempty` before
    /// upstream `5b0c57f49`), so control omits the key entirely whenever the flag is false — which
    /// is every ping that is not control-to-node. Without the default, serde fails the field with
    /// `missing field \`URLIsNoise\``, and because a [`PingRequest`] is nested inside a
    /// [`MapResponse`][crate::MapResponse] that failure sinks the WHOLE map response, ending the
    /// map-poll stream.
    #[serde(rename = "URLIsNoise", default)]
    pub url_is_noise: bool,
    /// If `true`, the client should log this ping in the success case. The client should log
    /// failures regardless of this flag's value.
    #[serde(default)]
    pub log: bool,
    /// A comma-separated list of [`PingType`]s to initiate, e.g. "disco,TSMP". Can be any
    /// [`PingType`].
    ///
    /// As a special case, if `types` is `"c2n"`, then this [`PingRequest`] is a control-to-node
    /// HTTP request. The HTTP request should be handled by this node's c2n handler and the HTTP
    /// response sent in a `POST` to `url`. For c2n, the value of the `url_is_noise` field should
    /// be ignored and only the Noise transport (back to the control plane) should be used, as if
    /// `url_is_noise` were set to `true`.
    ///
    /// `#[serde(default)]` is REQUIRED for the same reason as [`PingRequest::url_is_noise`]: Go
    /// tags this `json:",omitzero"` (`omitempty` before upstream `5b0c57f49`), so control omits the
    /// key when it has no types to request. That is exactly the liveness ping described above — the
    /// most common [`PingRequest`] of all — and without the default it failed the entire
    /// [`MapResponse`][crate::MapResponse] decode with `missing field \`Types\``.
    #[serde(deserialize_with = "deserialize_string_list", default)]
    pub types: Vec<PingType>,
    /// The ping target IP, if required by the [`PingType`(s)][PingType] given in [`PingRequest::types`].
    #[serde(rename = "IP", deserialize_with = "deserialize_string_option", default)]
    pub ip: Option<IpAddr>,
    /// The ping payload.
    ///
    /// Only used for c2n requests, in which case it's an HTTP/1.0 or HTTP/1.1-formatted HTTP
    /// request.
    #[serde(deserialize_with = "deserialize_base64_string", default)]
    pub payload: Option<String>,
}

impl fmt::Debug for PingRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PingRequest")
            .field("url", &self.url.as_str())
            .field("url_is_noise", &self.url_is_noise)
            .field("log", &self.log)
            .field("types", &self.types)
            .field("ip", &self.ip)
            .field("payload", &self.payload)
            .finish()
    }
}

/// Response to a [`PingRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
#[allow(dead_code)]
pub struct PingResponse;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c2n_ping_request_deserialize() {
        let request_json = r#"{
            "URL": "https://unused/c2n/s1/nLzY4qgWws11CNTRL/f84a9d4d06bc5c09fb9806e78f73d6fa",
            "URLIsNoise": true,
            "Types": "c2n",
            "IP": "",
            "Payload": "UE9TVCAvZWNobyBIVFRQLzEuMQ0KSG9zdDogDQpVc2VyLUFnZW50OiBHby1odHRwLWNsaWVudC8xLjENClRyYW5zZmVyLUVuY29kaW5nOiBjaHVua2VkDQpDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZA0KDQphDQpwaW5nPWhlbGxvDQowDQoNCg=="
        }"#;
        let req: PingRequest =
            serde_json::from_str(request_json).expect("could deserialize valid C2N PingRequest");
        assert_eq!(
            req.url,
            Url::parse("https://unused/c2n/s1/nLzY4qgWws11CNTRL/f84a9d4d06bc5c09fb9806e78f73d6fa")
                .expect("could parse valid C2N URL")
        );
        assert!(req.url_is_noise);
        assert_eq!(req.types.len(), 1);
        assert_eq!(req.types[0], PingType::C2N);
        assert!(req.ip.is_none());
        assert_eq!(req.payload, Some("POST /echo HTTP/1.1\r\nHost: \r\nUser-Agent: Go-http-client/1.1\r\nTransfer-Encoding: chunked\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\na\r\nping=hello\r\n0\r\n\r\n".into()));
    }

    /// The liveness ping — `tailcfg.PingRequest`'s documented "no IP and no Types" shape, sent by
    /// control to prove the long-polling client is still connected — arrives as `{"URL": …}` and
    /// NOTHING else: Go tags `URLIsNoise`, `Types`, `IP` and `Payload` so that a false/empty value
    /// is omitted from the wire (`json:",omitzero"` at upstream `1e69418c2`; `,omitempty"` for
    /// `URLIsNoise`/`Types`/`Payload` before `5b0c57f49`, which omits the same values). Every one of
    /// those keys must therefore be optional here. Before this was fixed, `URLIsNoise` and `Types`
    /// had no `#[serde(default)]` and this decode failed with `missing field \`URLIsNoise\``.
    #[test]
    fn liveness_ping_request_carries_url_only() {
        const WIRE: &str = r#"{"URL":"https://controlplane.example.com/ping/abc123"}"#;

        let req: PingRequest =
            serde_json::from_str(WIRE).expect("a URL-only liveness PingRequest must decode");

        assert_eq!(
            req.url,
            Url::parse("https://controlplane.example.com/ping/abc123").unwrap()
        );
        // Each omitted key falls back to the Go zero value it stands for.
        assert!(!req.url_is_noise, "an omitted URLIsNoise means false (TLS)");
        assert!(req.types.is_empty(), "an omitted Types means no ping types");
        assert!(req.ip.is_none(), "an omitted IP means no ping target");
        assert!(req.payload.is_none(), "an omitted Payload means no payload");
    }

    /// A `PingRequest` is nested inside a [`MapResponse`][crate::MapResponse], so a failed field
    /// decode is not contained: it fails the WHOLE map response, and the map-poll reader treats a
    /// `MapResponse` deserialize error as end-of-stream. A netmap frame carrying the URL-only
    /// liveness ping must therefore decode, ping and all.
    #[test]
    fn map_response_carrying_a_liveness_ping_decodes() {
        const WIRE: &str = r#"{
            "Seq": 7,
            "PingRequest": { "URL": "https://controlplane.example.com/ping/abc123" }
        }"#;

        let resp: crate::MapResponse = serde_json::from_str(WIRE)
            .expect("a MapResponse carrying a URL-only PingRequest must decode");

        assert_eq!(resp.seq, 7);
        let ping = resp.ping_request.expect("the ping request must be present");
        assert!(ping.types.is_empty());
        assert!(!ping.url_is_noise);
    }

    /// A non-c2n ping (`disco`/`TSMP`) names its types and target but leaves `URLIsNoise` false, so
    /// control omits that key while sending the others. The remaining fields must still land.
    #[test]
    fn disco_ping_request_without_url_is_noise_decodes() {
        const WIRE: &str = r#"{
            "URL": "https://controlplane.example.com/ping/def456",
            "Types": "disco,TSMP",
            "IP": "100.64.0.9"
        }"#;

        let req: PingRequest =
            serde_json::from_str(WIRE).expect("a disco PingRequest without URLIsNoise must decode");

        assert!(!req.url_is_noise);
        assert_eq!(req.types, [PingType::Disco, PingType::Tsmp]);
        assert_eq!(req.ip, Some("100.64.0.9".parse().unwrap()));
    }
}
