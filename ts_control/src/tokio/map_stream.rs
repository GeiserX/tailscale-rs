use alloc::collections::BTreeMap;
use core::net::SocketAddr;

use bytes::Bytes;
use futures_util::Stream;
use tokio::io::{AsyncRead, AsyncReadExt};
use ts_control_serde::{MapRequest, MapResponse, PingRequest};
use ts_http_util::{BytesBody, ClientExt, Http2, ResponseExt};
use ts_packet::PacketMut;
use ts_packetfilter as pf;
use ts_packetfilter_state as pf_state;
use url::Url;

use crate::{DialPlan, NodeId};

#[derive(Debug, thiserror::Error, Clone, Copy, Eq, PartialEq)]
pub enum MapStreamError {
    #[error("serialization error")]
    SerDe,
    #[error("unsuccessful HTTP request or upgrade")]
    Http,
    #[error("Network error")]
    NetworkError,
}

impl From<serde_json::Error> for MapStreamError {
    fn from(error: serde_json::Error) -> Self {
        tracing::error!(%error, "serialization error sending map request");
        MapStreamError::SerDe
    }
}

impl From<ts_http_util::Error> for MapStreamError {
    fn from(error: ts_http_util::Error) -> Self {
        tracing::error!(%error, "http error sending map request");

        if crate::http_error_is_recoverable(error) {
            MapStreamError::NetworkError
        } else {
            MapStreamError::Http
        }
    }
}

impl From<MapStreamError> for crate::Error {
    fn from(e: MapStreamError) -> Self {
        match e {
            MapStreamError::SerDe => crate::Error::Internal(
                crate::InternalErrorKind::SerDe,
                crate::Operation::MapRequest,
            ),
            MapStreamError::Http => {
                crate::Error::Internal(crate::InternalErrorKind::Http, crate::Operation::MapRequest)
            }
            MapStreamError::NetworkError => {
                crate::Error::NetworkError(crate::Operation::MapRequest)
            }
        }
    }
}

/// An update to the peers recorded in the netmap.
#[derive(Debug)]
pub enum PeerUpdate {
    /// Complete peer state.
    Full(Vec<crate::Node>),

    /// Delta update to the peer state.
    Delta {
        /// Peers added to or changed in the state.
        upsert: Vec<crate::Node>,
        /// Peer [`NodeId`]s removed from the state.
        remove: Vec<NodeId>,
    },

    /// Field-level patch updates to already-known peers (`MapResponse.PeersChangedPatch`).
    ///
    /// Each [`PeerPatch`] mutates only the fields it carries on the peer identified by
    /// [`PeerPatch::node_id`], leaving the rest untouched. Per the Go semantics
    /// (`tailcfg.PeerChange`), a patch for a node **not** in the current netmap is **ignored**, not
    /// inserted (the consumer enforces this). This is the lightweight sibling of [`Self::Delta`]:
    /// control normally sends patches on their own, without the `peers*` fields also set.
    Patch(Vec<PeerPatch>),
}

/// A field-level patch to a single already-known peer, decoded from a
/// [`ts_control_serde::PeerChange`] (`MapResponse.PeersChangedPatch`).
///
/// Only the fields the domain [`Node`](crate::Node) actually stores **and** that affect peer
/// reachability/trust are carried; each is `Some` exactly when control sent a new value for it. The
/// consumer ([`PeerUpdate::Patch`] handling in the peer tracker) looks the peer up by
/// [`node_id`](Self::node_id) and overwrites only the present (`Some`) fields.
///
/// Wire fields deliberately **not** carried:
/// - `online` and `last_seen` — the domain [`Node`](crate::Node) has no field for either (online
///   status lives on the runtime's status snapshot, not the tracked node), so there is nothing to
///   merge.
#[derive(Debug, Clone)]
pub struct PeerPatch {
    /// The control-assigned id of the node being patched (`PeerChange.NodeID`). Used to look up the
    /// existing peer; if no peer with this id is known, the patch is ignored.
    pub node_id: NodeId,
    /// New home DERP region, when changed (`PeerChange.DERPRegion`). Governs reachability — an idle
    /// peer that moved DERP regions can only be re-reached once this is applied.
    pub derp_region: Option<ts_derp::RegionId>,
    /// New UDP underlay endpoints, when changed (`PeerChange.Endpoints`). Governs reachability —
    /// maps onto [`Node::underlay_addresses`](crate::Node::underlay_addresses).
    pub endpoints: Option<Vec<SocketAddr>>,
    /// New WireGuard node key, when changed (`PeerChange.Key`). A key change must be re-validated
    /// against tailnet lock exactly like a `Delta`/`Full` upsert, so it is paired with
    /// [`key_signature`](Self::key_signature) below.
    pub key: Option<ts_keys::NodePublicKey>,
    /// New marshalled TKA node-key signature, when changed (`PeerChange.KeySignature`). Owned copy
    /// of the borrow-bound wire signature; maps onto [`Node::key_signature`](crate::Node).
    pub key_signature: Option<alloc::vec::Vec<u8>>,
    /// New disco key, when changed (`PeerChange.DiscoKey`). Needed for direct-path (magicsock)
    /// endpoint reconciliation, which keys netmap endpoints by disco key.
    pub disco_key: Option<ts_keys::DiscoPublicKey>,
    /// New node-key expiry, when changed (`PeerChange.KeyExpiry`).
    pub key_expiry: Option<chrono::DateTime<chrono::Utc>>,
    /// New advertised capability version, when changed (`PeerChange.Cap`).
    pub cap: Option<ts_capabilityversion::CapabilityVersion>,
}

impl From<&ts_control_serde::PeerChange<'_>> for PeerPatch {
    fn from(change: &ts_control_serde::PeerChange<'_>) -> Self {
        Self {
            node_id: change.node_id,
            // Wire `DerpRegionId` (NonZeroU32 newtype) -> domain `ts_derp::RegionId`, exactly as the
            // `Node` `From` impl converts `home_derp`.
            derp_region: change.derp_region.map(|x| ts_derp::RegionId(x.into())),
            endpoints: change.endpoints.clone(),
            key: change.key,
            // `MarshaledSignature<'a>` is `&[u8]`; the domain node stores it owned.
            key_signature: change.key_signature.map(<[u8]>::to_vec),
            disco_key: change.disco_key,
            key_expiry: change.key_expiry,
            cap: change.cap,
        }
    }
}

/// The components of a packet filter update.
///
/// These can't be merged into a single map due to the update rules.
pub type FilterUpdate = (Option<pf::Ruleset>, BTreeMap<String, Option<pf::Ruleset>>);

/// An update to the netmap state produced from a mapresponse.
#[derive(Debug)]
pub struct StateUpdate {
    /// The opaque map-session handle, set only when control assigns one (the first
    /// [`MapResponse`] of a session). Carried so a reconnect can request stream resumption via
    /// `MapRequestBuilder::map_session`. `None` on
    /// responses that don't (re)establish a session.
    pub session_handle: Option<alloc::string::String>,
    /// The sequence number of this [`MapResponse`] within its session, or `0` when control omits
    /// it (e.g. keep-alives). The last non-zero value is what a reconnect resumes after.
    pub seq: i64,
    /// New derp map is available.
    pub derp: Option<crate::DerpMap>,
    /// New self-node.
    pub node: Option<crate::Node>,
    /// Updates to the set of peers in the netmap.
    pub peer_update: Option<PeerUpdate>,
    /// User profiles (`MapResponse.UserProfiles`) carried by this response: the owner identity for
    /// nodes, keyed by user id. Control sends these incrementally — only new or changed profiles
    /// per response — so the consumer (the runtime's peer tracker) must **accumulate** them across
    /// updates, not replace. Empty when this response carried none.
    pub user_profiles: Vec<crate::UserProfile>,
    /// Send a ping request.
    pub ping: Option<PingRequest>,
    /// Update to the packet filter.
    pub packetfilter: Option<FilterUpdate>,
    /// This URL should be displayed to the user or opened in their browser automatically.
    pub pop_browser_url: Option<Url>,
    /// New dial plan sent by control.
    pub dial_plan: Option<DialPlan>,
    /// New DNS configuration for the MagicDNS responder. `None` means no change.
    pub dns_config: Option<crate::DnsConfig>,
    /// New Tailscale SSH policy pushed by control. `None` means no change in this response;
    /// `Some` replaces the active policy (an empty rule set means "deny all", fail-closed).
    pub ssh_policy: Option<crate::SshPolicy>,
    /// New Tailnet Lock (TKA) status from control (`MapResponse.TKAInfo`). `None` means no change in
    /// this response; `Some` carries the current authority head + disablement signal.
    pub tka: Option<crate::TkaStatus>,
}

pub fn map_stream(reader: impl AsyncRead + Unpin) -> impl Stream<Item = StateUpdate> {
    futures_util::stream::unfold(reader, async |mut reader| {
        let msg_len = reader
            .read_u32_le()
            .await
            .inspect_err(|e| {
                tracing::error!(error = %e, "could not read netmap length");
            })
            .ok()?;

        let mut buf = PacketMut::new(msg_len as usize);
        tracing::trace!(?msg_len, "reading netmap");

        reader
            .read_exact(buf.as_mut())
            .await
            .inspect_err(|e| {
                tracing::error!(error = %e, "could not read netmap");
            })
            .ok()?;

        let map_response: MapResponse = serde_json::from_slice(buf.as_ref())
            .inspect_err(|e| {
                tracing::error!(error = %e, "deserializing netmap");
            })
            .ok()?;

        tracing::trace!(?msg_len, ?map_response);

        let packetfilter = packet_filter(&map_response);

        fn nonempty<T>(x: &Option<Vec<T>>) -> bool {
            x.as_ref().is_some_and(|x| !x.is_empty())
        }

        // A patch list with all-`None` entries carries no actual changes.
        let has_patch = map_response.peers_changed_patch.iter().any(Option::is_some);

        let peer_update = if let Some(full_map) = map_response.peers {
            // A full map replaces the entire peer set, so any patch in the same response is moot
            // (the new peers already carry the latest fields). Mirror the wire contract: `peers`
            // takes precedence over `peers_changed`/`peers_removed`, and likewise over a patch.
            if has_patch {
                tracing::debug!(
                    "MapResponse carried both a full peer map and a patch; \
                     the full map supersedes the patch"
                );
            }
            Some(PeerUpdate::Full(full_map.iter().map(Into::into).collect()))
        } else if nonempty(&map_response.peers_removed) || nonempty(&map_response.peers_changed) {
            // Control should send patches on their own, not alongside `peers_changed`/`peers_removed`
            // (the wire docs note the patch "should only [be sent] on their own"). If a response
            // somehow carries both, prefer the heavier delta (it can add/remove whole peers, which a
            // patch cannot) and skip the patch rather than apply two updates with ambiguous ordering.
            if has_patch {
                tracing::warn!(
                    peers_changed_patch = ?map_response.peers_changed_patch,
                    "MapResponse carried both a peer delta and a patch; applying the delta and \
                     skipping the patch (control should not send both)"
                );
            }
            Some(PeerUpdate::Delta {
                remove: map_response.peers_removed.unwrap_or_default(),
                upsert: map_response
                    .peers_changed
                    .unwrap_or_default()
                    .iter()
                    .map(Into::into)
                    .collect(),
            })
        } else if has_patch {
            // The common case for a patch: it arrives on its own. Apply each `PeerChange` as a
            // field-level merge onto the already-known peer (unknown nodes are ignored downstream).
            Some(PeerUpdate::Patch(
                map_response
                    .peers_changed_patch
                    .iter()
                    .flatten()
                    .map(PeerPatch::from)
                    .collect(),
            ))
        } else {
            None
        };

        Some((
            StateUpdate {
                session_handle: (!map_response.map_session_handle.is_empty())
                    .then(|| map_response.map_session_handle.to_owned()),
                seq: map_response.seq,
                peer_update,
                user_profiles: map_response
                    .user_profiles
                    .iter()
                    .map(crate::UserProfile::from)
                    .collect(),
                node: map_response.node.as_ref().map(Into::into),
                derp: map_response
                    .derp_map
                    .as_ref()
                    .map(|x| crate::convert_derp_map(x).collect()),
                ping: map_response.ping_request,
                packetfilter,
                pop_browser_url: map_response.pop_browser_url.and_then(|u| {
                    u.parse()
                        .inspect_err(|e| tracing::error!(error = %e, "invalid pop browser url"))
                        .ok()
                }),
                dial_plan: map_response.control_dial_plan.map(Into::into),
                dns_config: map_response
                    .dns_config
                    .as_ref()
                    .map(crate::DnsConfig::from_serde),
                ssh_policy: map_response
                    .ssh_policy
                    .as_ref()
                    .map(crate::SshPolicy::from_serde),
                tka: map_response
                    .tka_info
                    .as_ref()
                    .map(crate::TkaStatus::from_serde),
            },
            reader,
        ))
    })
}

fn packet_filter(map_response: &MapResponse<'_>) -> Option<FilterUpdate> {
    if map_response.packet_filter.is_none() && map_response.packet_filters.is_empty() {
        return None;
    }

    Some((
        map_response
            .packet_filter
            .as_ref()
            .map(|x| pf_state::rules_to_pf(x).collect()),
        map_response
            .packet_filters
            .iter()
            .map(|(rule_name, rules)| {
                (
                    rule_name.to_string(),
                    rules
                        .as_ref()
                        .map(|x| Some(pf_state::rules_to_pf(x).collect()))
                        .unwrap_or_default(),
                )
            })
            .collect(),
    ))
}

#[tracing::instrument(skip_all, fields(map_url = %url.as_str()))]
pub async fn send_map_request(
    map_request: MapRequest<'_>,
    url: &Url,
    http2_conn: &Http2<BytesBody>,
) -> Result<impl AsyncRead + 'static, MapStreamError> {
    tracing::debug!("sending map request to control server...");

    let body = if cfg!(debug_assertions) {
        serde_json::to_string_pretty(&map_request)?
    } else {
        serde_json::to_string(&map_request)?
    };
    tracing::trace!(
        %body,
        "sending map request"
    );

    let resp = http2_conn.post(url, None, Bytes::from(body).into()).await?;

    let status = resp.status();
    tracing::trace!(?status, "received map response");

    if !status.is_success() {
        tracing::error!(
            status = status.as_u16(),
            "failed to register map updates with unsuccessful HTTP status code"
        );
        return Err(MapStreamError::Http);
    }

    Ok(resp.into_read())
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use futures_util::StreamExt;

    use super::*;

    /// Frame each JSON body the way control does: a little-endian u32 length prefix followed by the
    /// JSON bytes. Returns a single buffer the `map_stream` reader can consume.
    fn frame(bodies: &[&str]) -> Vec<u8> {
        let mut buf = Vec::new();
        for body in bodies {
            buf.extend_from_slice(&(body.len() as u32).to_le_bytes());
            buf.extend_from_slice(body.as_bytes());
        }
        buf
    }

    #[tokio::test]
    async fn map_stream_carries_session_handle_and_seq() {
        let buf = frame(&[r#"{"MapSessionHandle":"sess-xyz","Seq":12}"#]);

        let mut stream = core::pin::pin!(map_stream(&buf[..]));
        let update = stream.next().await.expect("one update");

        assert_eq!(update.session_handle.as_deref(), Some("sess-xyz"));
        assert_eq!(update.seq, 12);
    }

    #[tokio::test]
    async fn map_stream_empty_handle_maps_to_none() {
        // A keep-alive-style response with no session handle and seq 0 must surface as None/0 so
        // the resume cursor is left untouched.
        let buf = frame(&[r#"{"KeepAlive":true}"#]);

        let mut stream = core::pin::pin!(map_stream(&buf[..]));
        let update = stream.next().await.expect("one update");

        assert_eq!(update.session_handle, None);
        assert_eq!(update.seq, 0);
    }

    #[tokio::test]
    async fn map_stream_decodes_peers_changed_patch() {
        // A MapResponse carrying `PeersChangedPatch` (and no full map / delta) must decode into a
        // `PeerUpdate::Patch`, not be dropped. This is the regression guard for the bug where the
        // patch was logged-and-discarded, wedging idle sessions whose endpoints/DERP changed.
        let buf = frame(&[r#"{
            "PeersChangedPatch": [
                {
                    "NodeID": 42,
                    "DERPRegion": 7,
                    "Endpoints": ["84.54.25.89:5175", "10.0.0.2:41641"]
                }
            ]
        }"#]);

        let mut stream = core::pin::pin!(map_stream(&buf[..]));
        let update = stream.next().await.expect("one update");

        let Some(PeerUpdate::Patch(patches)) = update.peer_update else {
            panic!("expected PeerUpdate::Patch, got {:?}", update.peer_update);
        };
        assert_eq!(patches.len(), 1);
        let p = &patches[0];
        assert_eq!(p.node_id, 42);
        assert_eq!(
            p.derp_region,
            Some(ts_derp::RegionId(core::num::NonZeroU32::new(7).unwrap()))
        );
        assert_eq!(
            p.endpoints.as_deref(),
            Some(
                [
                    "84.54.25.89:5175".parse().unwrap(),
                    "10.0.0.2:41641".parse().unwrap()
                ]
                .as_slice()
            )
        );
    }

    #[tokio::test]
    async fn map_stream_full_map_supersedes_patch() {
        // When a response carries BOTH a full peer map and a patch, the full map wins (it already
        // reflects the latest state); the patch is not separately surfaced.
        let buf = frame(&[r#"{
            "Peers": [],
            "PeersChangedPatch": [{"NodeID": 42, "DERPRegion": 7}]
        }"#]);

        let mut stream = core::pin::pin!(map_stream(&buf[..]));
        let update = stream.next().await.expect("one update");

        assert!(
            matches!(update.peer_update, Some(PeerUpdate::Full(_))),
            "full map must win over a patch, got {:?}",
            update.peer_update
        );
    }

    #[tokio::test]
    async fn map_stream_all_none_patch_is_no_update() {
        // A `PeersChangedPatch` array of only `null`s carries no real change and must produce no
        // peer update (rather than an empty `Patch`).
        let buf = frame(&[r#"{"PeersChangedPatch": [null, null]}"#]);

        let mut stream = core::pin::pin!(map_stream(&buf[..]));
        let update = stream.next().await.expect("one update");

        assert!(update.peer_update.is_none());
    }
}
