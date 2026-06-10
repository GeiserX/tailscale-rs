use alloc::collections::BTreeMap;

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

    /// Incremental field-level patches to peers already in the netmap
    /// ([`MapResponse::peers_changed_patch`][crate::MapResponse::peers_changed_patch]). Unlike
    /// [`Delta`][PeerUpdate::Delta] (which carries whole nodes), each [`PeerChange`] sets only the
    /// fields it carries on the matching node, leaving the rest untouched; a patch whose node id is
    /// unknown to the current netmap is ignored. Control uses these for mid-session reachability
    /// changes — chiefly a peer's UDP endpoints / home DERP when it re-establishes connectivity —
    /// so they MUST be applied or the netmap keeps stale endpoints and the peer can't re-handshake.
    Patch(Vec<crate::PeerChange>),
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
    /// Per-peer online-status flips (`MapResponse.OnlineChange`), keyed by control node [`NodeId`](crate::NodeId).
    /// The dominant standalone channel for online transitions (control sends these far more often
    /// than a full [`PeerChange`](crate::PeerChange)). Each entry *sets* `Node::online` to the given
    /// value; empty when this response carried none.
    pub online_change: alloc::collections::BTreeMap<crate::NodeId, bool>,
    /// Per-peer last-seen flips (`MapResponse.PeerSeenChange`), keyed by control node [`NodeId`](crate::NodeId).
    /// `true` ⇒ the peer was just seen (update last-seen to now); `false` ⇒ the peer is gone
    /// (mark offline). Empty when this response carried none.
    pub peer_seen_change: alloc::collections::BTreeMap<crate::NodeId, bool>,
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

        // `peers_changed_patch` carries field-level patches to already-known peers (Go applies them
        // *after* the `peers*` fields). In practice control sends patches on their own, and our
        // single `peer_update` slot carries one update per response — so a full/delta resync takes
        // precedence (it already conveys the freshest whole nodes) and patches are surfaced only
        // when no full/delta is present. If both ever arrive together we keep the resync and warn,
        // rather than silently dropping the patches (the pre-fix behavior dropped them always).
        let patches: Vec<crate::PeerChange> = map_response
            .peers_changed_patch
            .iter()
            .flatten()
            .map(crate::PeerChange::from)
            .collect();
        let n_patches = patches.len();

        let peer_update = if let Some(full_map) = map_response.peers {
            Some(PeerUpdate::Full(full_map.iter().map(Into::into).collect()))
        } else if nonempty(&map_response.peers_removed) || nonempty(&map_response.peers_changed) {
            Some(PeerUpdate::Delta {
                remove: map_response.peers_removed.unwrap_or_default(),
                upsert: map_response
                    .peers_changed
                    .unwrap_or_default()
                    .iter()
                    .map(Into::into)
                    .collect(),
            })
        } else if n_patches > 0 {
            Some(PeerUpdate::Patch(patches))
        } else {
            None
        };

        // Surface the rare both-present case (a resync chosen above while patches were also sent)
        // so it's observable rather than silent.
        if n_patches > 0 && !matches!(peer_update, Some(PeerUpdate::Patch(_))) {
            tracing::warn!(
                n_patches,
                "peer patches arrived alongside a full/delta peer update; resync takes precedence"
            );
        }

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
                // Online/last-seen delta maps (channels C/D). `NodeId` is the control node id
                // (`Id`), so these copy across directly. The peer tracker applies them on every
                // update — including responses that carry NO peer_update — so a standalone online
                // flip (the common case) isn't lost. (Control sends these on their own, never
                // alongside a `peers*` set for the same node, so apply-order vs the peer set is moot.)
                online_change: map_response.online_change.clone(),
                peer_seen_change: map_response.peer_seen_change.clone(),
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
    async fn map_stream_surfaces_peers_changed_patch() {
        // A response carrying only `PeersChangedPatch` (control's mid-session reachability update)
        // must surface as `PeerUpdate::Patch`, not be dropped. Regression for the pre-fix code that
        // logged + discarded these, wedging idle peers that moved (stale endpoints → no re-handshake).
        let buf = frame(&[r#"{
            "Seq": 7,
            "PeersChangedPatch": [
                { "NodeID": 42, "Endpoints": ["203.0.113.7:41641"], "DERPRegion": 5 }
            ]
        }"#]);

        let mut stream = core::pin::pin!(map_stream(&buf[..]));
        let update = stream.next().await.expect("one update");

        match update.peer_update {
            Some(PeerUpdate::Patch(patches)) => {
                assert_eq!(patches.len(), 1);
                assert_eq!(patches[0].id, 42);
                assert_eq!(
                    patches[0].underlay_addresses.as_deref(),
                    Some(&["203.0.113.7:41641".parse().unwrap()][..])
                );
                assert_eq!(
                    patches[0].derp_region,
                    Some(ts_derp::RegionId(core::num::NonZeroU32::new(5).unwrap()))
                );
            }
            other => panic!("expected PeerUpdate::Patch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn map_stream_resync_takes_precedence_over_patch() {
        // If a full/delta resync and patches arrive together, the resync wins (it conveys the
        // freshest whole nodes); the patch is not separately surfaced. `peers_changed` (a Delta)
        // alongside a patch ⇒ the update is the Delta.
        let buf = frame(&[r#"{
            "Seq": 8,
            "PeersChanged": [
                { "ID": 1, "StableID": "n1", "Name": "a.ts.net.", "User": 1,
                  "Key": "nodekey:0000000000000000000000000000000000000000000000000000000000000000" }
            ],
            "PeersChangedPatch": [ { "NodeID": 1, "DERPRegion": 9 } ]
        }"#]);

        let mut stream = core::pin::pin!(map_stream(&buf[..]));
        let update = stream.next().await.expect("one update");

        assert!(matches!(update.peer_update, Some(PeerUpdate::Delta { .. })));
    }
}
