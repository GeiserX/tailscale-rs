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
    /// it (e.g. keep-alives). The last non-zero value is what a reconnect resumes after. NOTE: `seq`
    /// is only assigned within a *named* map session (one whose first response carried a
    /// `MapSessionHandle`) and may be `0` on a substantive response — a control plane that does not
    /// implement map-session resumption (e.g. Headscale) leaves it `0` on *every* response. So `seq`
    /// is a resume cursor, NOT a keep-alive discriminator; use [`keep_alive`](Self::keep_alive) for
    /// that.
    pub seq: i64,
    /// Whether this is a bare keep-alive heartbeat (`MapResponse.KeepAlive`), carrying no netmap
    /// content. Control sends these periodically to keep the long-poll connection live. This is the
    /// authoritative "is this a substantive response?" signal (Go's `controlclient` classifies
    /// keep-alives solely by this flag, never by `seq`): a non-keep-alive response is one that
    /// (re)establishes or updates the netmap, and is what resets the reconnect backoff.
    pub keep_alive: bool,
    /// New derp map is available.
    pub derp: Option<crate::DerpMap>,
    /// New self-node.
    pub node: Option<crate::Node>,
    /// Updates to the set of peers in the netmap (a full re-sync or a whole-node delta).
    pub peer_update: Option<PeerUpdate>,
    /// Field-level patches to peers already in the netmap (`MapResponse.PeersChangedPatch`). Each
    /// [`PeerChange`][crate::PeerChange] sets only the fields it carries on the matching node,
    /// leaving the rest untouched; a patch whose node id is unknown to the current netmap is
    /// ignored (the wire contract — a patch never creates a node). Control uses these for
    /// mid-session reachability changes — chiefly a peer's UDP endpoints / home DERP when it
    /// re-establishes connectivity — so they MUST be applied or the netmap keeps stale endpoints and
    /// the peer can't re-handshake. A **separate channel** from [`peer_update`](Self::peer_update):
    /// Go's `controlclient` applies the `Peers*` set first and then `PeersChangedPatch`, so when a
    /// response carries both they are *both* applied in that order (the consumer applies
    /// `peer_update` then `peer_patches`). Empty when this response carried no patches.
    pub peer_patches: Vec<crate::PeerChange>,
    /// User profiles (`MapResponse.UserProfiles`) carried by this response: the owner identity for
    /// nodes, keyed by user id. Control sends these incrementally — only new or changed profiles
    /// per response — so the consumer (the runtime's peer tracker) must **accumulate** them across
    /// updates, not replace. Empty when this response carried none.
    pub user_profiles: Vec<crate::UserProfile>,
    /// Send a ping request.
    pub ping: Option<PingRequest>,
    /// Update to the packet filter.
    pub packetfilter: Option<FilterUpdate>,
    /// The peer-capability grants retained from this response's packet-filter application rules
    /// (Go `tailcfg.FilterRule` cap-grants), which the network-rule compile in `packetfilter` drops.
    /// `Some` exactly when `packetfilter` is `Some` (the same source rules); the consumer keeps
    /// these for flow-scoped WhoIs (`apitype.WhoIsResponse.CapMap`). Empty `Vec` when the response's
    /// rules carried no application/cap-grant rule.
    pub cap_grants: Option<Vec<ts_packetfilter_state::CapGrant>>,
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
    /// `true` ⇒ the peer was just seen (set last-seen to now); `false` ⇒ clear last-seen (unknown).
    /// This drives ONLY `last_seen`, never `online` — online is driven solely by `online_change`
    /// (conflating them re-introduces a fixed bug). Empty when this response carried none.
    pub peer_seen_change: alloc::collections::BTreeMap<crate::NodeId, bool>,
}

/// Upper bound on a single netmap frame, checked before allocating the read buffer.
///
/// The frame length is a `u32` read straight off the (authenticated, ts2021-Noise) control stream;
/// without a cap, `PacketMut::new(msg_len)` eagerly zero-allocates up to ~4 GiB, so a malformed or
/// hostile control frame OOMs the client. Every other framed path in the fork bounds before
/// allocating (DERP 64 KiB, TKA-sync 10 MiB, control-noise `MAX_MESSAGE_SIZE`); this matches that
/// discipline. 16 MiB is comfortably above any real netmap (Go bounds this similarly) and `compress`
/// is sent empty, so the on-wire length equals the buffer size with no decompression amplification.
const MAX_NETMAP_FRAME: u32 = 16 * 1024 * 1024;

/// Long-poll read watchdog: if no frame (not even a keep-alive) arrives within this window, end the
/// stream so the caller reconnects. Control sends a keep-alive roughly every minute on a streaming
/// map poll, so silence past this bound means the connection is dead-but-not-closed (a half-open
/// socket after NAT/firewall state eviction, a silently-dropping middlebox, or a control server
/// that hung without sending FIN/RST). Without it, `read_u32_le`/`read_exact` await forever and the
/// node silently stops receiving netmap updates (missed peer/DERP/key-expiry/ACL/TKA changes) with
/// no reconnect ever attempted. Mirrors Go `controlclient` `direct.go`'s `watchdogTimeout = 120s`.
const MAP_READ_WATCHDOG: core::time::Duration = core::time::Duration::from_secs(120);

pub fn map_stream(reader: impl AsyncRead + Unpin) -> impl Stream<Item = StateUpdate> {
    futures_util::stream::unfold(reader, async |mut reader| {
        // Watchdog the length read: this is where the stream idles between frames, so a silently
        // dead long poll blocks here. A timeout ends the stream (returns `None`) → reconnect.
        let msg_len = match tokio::time::timeout(MAP_READ_WATCHDOG, reader.read_u32_le()).await {
            Ok(res) => res
                .inspect_err(|e| {
                    tracing::error!(error = %e, "could not read netmap length");
                })
                .ok()?,
            Err(_elapsed) => {
                tracing::error!(
                    watchdog_secs = MAP_READ_WATCHDOG.as_secs(),
                    "no netmap frame within the keep-alive watchdog; ending stream to reconnect"
                );
                return None;
            }
        };

        // Bound the frame before allocating: a `u32` length of `0xFFFF_FFFF` would otherwise force a
        // ~4 GiB zeroed allocation (OOM). End the stream on an over-large frame rather than abort.
        if msg_len > MAX_NETMAP_FRAME {
            tracing::error!(
                ?msg_len,
                max = MAX_NETMAP_FRAME,
                "netmap frame too large; ending stream"
            );
            return None;
        }

        let mut buf = PacketMut::new(msg_len as usize);
        tracing::trace!(?msg_len, "reading netmap");

        // Watchdog the body read too: once the length is in, the body should follow promptly. A
        // stall here (announced length, body never delivered) is the same dead-connection signal.
        match tokio::time::timeout(MAP_READ_WATCHDOG, reader.read_exact(buf.as_mut())).await {
            Ok(res) => res
                .inspect_err(|e| {
                    tracing::error!(error = %e, "could not read netmap");
                })
                .ok()?,
            Err(_elapsed) => {
                tracing::error!(
                    watchdog_secs = MAP_READ_WATCHDOG.as_secs(),
                    "netmap body did not arrive within the watchdog; ending stream to reconnect"
                );
                return None;
            }
        };

        let map_response: MapResponse = serde_json::from_slice(buf.as_ref())
            .inspect_err(|e| {
                tracing::error!(error = %e, "deserializing netmap");
            })
            .ok()?;

        tracing::trace!(?msg_len, ?map_response);

        let packetfilter = packet_filter(&map_response);
        let cap_grants = cap_grants(&map_response);

        fn nonempty<T>(x: &Option<Vec<T>>) -> bool {
            x.as_ref().is_some_and(|x| !x.is_empty())
        }

        // `peers_changed_patch` carries field-level patches to already-known peers. Go's
        // `controlclient` applies the whole-node `Peers*` set first and then `PeersChangedPatch`, so
        // patches are a SEPARATE always-populated channel (`peer_patches`) rather than a third
        // `peer_update` variant: when a response carries both a full/delta AND patches, the consumer
        // applies the peer set then the patches, in that order. (Previously patches shared the single
        // `peer_update` slot and a co-occurring full/delta took precedence, silently dropping them.)
        let peer_patches: Vec<crate::PeerChange> = map_response
            .peers_changed_patch
            .iter()
            .flatten()
            .map(crate::PeerChange::from)
            .collect();

        // A full peer set is signalled by a NON-EMPTY `peers`, matching Go `controlclient`
        // `updatePeersStateFromResponse` (`if len(resp.Peers) > 0`): Go treats a nil OR zero-length
        // `Peers` identically as "not a full set" and falls through to delta handling. A
        // present-but-empty `"Peers": []` (which a non-Go control plane — Headscale, a custom server,
        // or a `nil`->`[]` re-encoder — can emit, since Go's own `omitempty` never serializes one)
        // must NOT be read as a full reset: gating on `Some` rather than non-empty here would build a
        // `PeerUpdate::Full(empty)` and the peer tracker's `Full` path would evict EVERY peer,
        // blackholing the tailnet datapath until the next full resync. Gate on non-empty so `[]`
        // becomes a no-op delta instead. (`tailcfg.go`: "Peers, if non-empty, is the complete list".)
        let peer_update = if nonempty(&map_response.peers) {
            let full_map = map_response.peers.unwrap_or_default();
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
        } else {
            None
        };

        Some((
            StateUpdate {
                session_handle: (!map_response.map_session_handle.is_empty())
                    .then(|| map_response.map_session_handle.to_owned()),
                seq: map_response.seq,
                // `KeepAlive` is `omitempty` on the wire, so an absent value means "not a
                // keep-alive" (a substantive response). Default `None` to `false` accordingly.
                keep_alive: map_response.keep_alive.unwrap_or(false),
                peer_update,
                peer_patches,
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
                cap_grants,
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

/// Retain the peer-capability grants from the same packet-filter rules [`packet_filter`] compiles —
/// the application-rule cap-grants that the network-rule compile discards. Collected across the
/// legacy `packet_filter` and every named `packet_filters` ruleset. `Some` exactly when
/// [`packet_filter`] is `Some`; an empty `Vec` means the rules carried no cap-grant. Backs
/// flow-scoped WhoIs.
fn cap_grants(map_response: &MapResponse<'_>) -> Option<Vec<ts_packetfilter_state::CapGrant>> {
    if map_response.packet_filter.is_none() && map_response.packet_filters.is_empty() {
        return None;
    }

    let mut grants = Vec::new();
    if let Some(rules) = map_response.packet_filter.as_ref() {
        grants.extend(pf_state::retain_cap_grants(rules));
    }
    for rules in map_response.packet_filters.values().flatten() {
        grants.extend(pf_state::retain_cap_grants(rules));
    }
    Some(grants)
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

    /// An `AsyncRead` that serves `prefix` bytes and then stalls forever (always `Pending`),
    /// modelling a half-open/silently-dead long-poll connection: bytes flowed, then the peer went
    /// silent without closing. Used to prove the read watchdog ends the stream instead of hanging.
    struct StallAfter {
        prefix: alloc::collections::VecDeque<u8>,
    }

    impl StallAfter {
        fn new(prefix: &[u8]) -> Self {
            Self {
                prefix: prefix.iter().copied().collect(),
            }
        }
    }

    impl tokio::io::AsyncRead for StallAfter {
        fn poll_read(
            mut self: core::pin::Pin<&mut Self>,
            _cx: &mut core::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> core::task::Poll<std::io::Result<()>> {
            if self.prefix.is_empty() {
                // Drained: stall forever. With a paused test clock the watchdog `timeout` is the
                // only timer left, so it advances and fires — exactly the dead-connection case.
                return core::task::Poll::Pending;
            }
            while buf.remaining() > 0 {
                let Some(b) = self.prefix.pop_front() else {
                    break;
                };
                buf.put_slice(&[b]);
            }
            core::task::Poll::Ready(Ok(()))
        }
    }

    /// A long poll that delivers a frame and then goes silent (no further bytes, no close) must end
    /// the stream once the read watchdog elapses, so the caller reconnects. Without the watchdog
    /// the second `next()` would await forever (the node would silently stop getting updates).
    /// `start_paused` makes the 120s watchdog fire instantly (auto-advanced virtual time).
    #[tokio::test(start_paused = true)]
    async fn map_stream_watchdog_ends_stream_on_silent_connection() {
        let reader = StallAfter::new(&frame(&[r#"{"MapSessionHandle":"sess-1","Seq":1}"#]));

        let mut stream = core::pin::pin!(map_stream(reader));

        // First frame arrives normally.
        let update = stream.next().await.expect("first frame");
        assert_eq!(update.seq, 1);

        // The connection then goes silent: the watchdog must end the stream (None), not hang.
        assert!(
            stream.next().await.is_none(),
            "watchdog must end the stream on a silent connection"
        );
    }

    /// A connection that never delivers even the first frame must also be bounded by the watchdog
    /// (the idle-from-the-start case — e.g. control accepted the request then went silent).
    #[tokio::test(start_paused = true)]
    async fn map_stream_watchdog_ends_stream_when_no_frame_ever_arrives() {
        let reader = StallAfter::new(&[]);

        let mut stream = core::pin::pin!(map_stream(reader));

        assert!(
            stream.next().await.is_none(),
            "watchdog must end a stream that never produces a frame"
        );
    }

    /// A frame whose length prefix arrives but whose body stalls mid-way must be bounded by the
    /// body-read watchdog (announced length, body never completes — a torn connection).
    #[tokio::test(start_paused = true)]
    async fn map_stream_watchdog_ends_stream_on_partial_body() {
        // 4-byte LE length says 64 bytes follow, but we supply only the prefix + 3 body bytes.
        let mut bytes = 64u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(b"abc");
        let reader = StallAfter::new(&bytes);

        let mut stream = core::pin::pin!(map_stream(reader));

        assert!(
            stream.next().await.is_none(),
            "watchdog must end the stream when the body never completes"
        );
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
        // the resume cursor is left untouched, and `keep_alive` must surface as `true` so the
        // backoff-reset gate can tell it apart from a substantive netmap.
        let buf = frame(&[r#"{"KeepAlive":true}"#]);

        let mut stream = core::pin::pin!(map_stream(&buf[..]));
        let update = stream.next().await.expect("one update");

        assert_eq!(update.session_handle, None);
        assert_eq!(update.seq, 0);
        assert!(
            update.keep_alive,
            "a KeepAlive response must surface keep_alive=true"
        );
    }

    #[tokio::test]
    async fn map_stream_substantive_response_has_keep_alive_false() {
        // A response that omits `KeepAlive` (the wire default) is substantive and must surface
        // `keep_alive == false` even when it carries no `Seq` — this is the Headscale-style case the
        // backoff-reset gate must treat as progress (gating on `seq` would wrongly skip it).
        let buf = frame(&[r#"{ "Node": { "Name": "n" } }"#]);

        let mut stream = core::pin::pin!(map_stream(&buf[..]));
        let update = stream.next().await.expect("one update");

        assert_eq!(update.seq, 0, "this fixture omits Seq (Headscale-style)");
        assert!(
            !update.keep_alive,
            "a response without KeepAlive must surface keep_alive=false (substantive)"
        );
    }

    #[tokio::test]
    async fn map_stream_surfaces_peers_changed_patch() {
        // A response carrying only `PeersChangedPatch` (control's mid-session reachability update)
        // must surface in `peer_patches`, not be dropped. Regression for the pre-fix code that
        // logged + discarded these, wedging idle peers that moved (stale endpoints → no re-handshake).
        let buf = frame(&[r#"{
            "Seq": 7,
            "PeersChangedPatch": [
                { "NodeID": 42, "Endpoints": ["203.0.113.7:41641"], "DERPRegion": 5 }
            ]
        }"#]);

        let mut stream = core::pin::pin!(map_stream(&buf[..]));
        let update = stream.next().await.expect("one update");

        // Patches ride their own channel; with no `Peers*` set there is no `peer_update`.
        assert!(
            update.peer_update.is_none(),
            "no whole-node set in this response"
        );
        assert_eq!(update.peer_patches.len(), 1);
        assert_eq!(update.peer_patches[0].id, 42);
        assert_eq!(
            update.peer_patches[0].underlay_addresses.as_deref(),
            Some(&["203.0.113.7:41641".parse().unwrap()][..])
        );
        assert_eq!(
            update.peer_patches[0].derp_region,
            Some(ts_derp::RegionId(core::num::NonZeroU32::new(5).unwrap()))
        );
    }

    #[tokio::test]
    async fn map_stream_carries_both_delta_and_patch_when_co_occurring() {
        // Regression for `tsr-5u0`: when a full/delta resync and patches arrive in the SAME response,
        // BOTH must be surfaced — the resync in `peer_update`, the patches in `peer_patches` — so the
        // consumer can apply the peer set then the patches (Go's `controlclient` order). The pre-fix
        // code kept only the resync in the single `peer_update` slot and silently dropped the patch.
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

        // The whole-node delta is present...
        assert!(matches!(update.peer_update, Some(PeerUpdate::Delta { .. })));
        // ...AND the patch is no longer dropped — it rides `peer_patches` alongside it.
        assert_eq!(update.peer_patches.len(), 1, "patch must not be dropped");
        assert_eq!(update.peer_patches[0].id, 1);
        assert_eq!(
            update.peer_patches[0].derp_region,
            Some(ts_derp::RegionId(core::num::NonZeroU32::new(9).unwrap()))
        );
    }

    /// Regression for `tsr-x2a`: a present-but-empty `"Peers": []` must NOT be read as a full peer
    /// reset. Go `controlclient` gates the full set on `len(resp.Peers) > 0`, treating nil and
    /// zero-length identically as "not a full set"; the pre-fix code gated on `Some`, so `[]` built a
    /// `PeerUpdate::Full(empty)` and the peer tracker evicted every peer (blackholing the datapath).
    /// A non-Go control plane (Headscale / custom / a `nil`->`[]` re-encoder) can emit `[]`, so this
    /// is reachable. With no `PeersChanged`/`PeersRemoved` either, the response is a pure no-op.
    #[tokio::test]
    async fn empty_peers_array_is_noop_not_full_wipe() {
        let buf = frame(&[r#"{ "Seq": 9, "Peers": [] }"#]);
        let mut stream = core::pin::pin!(map_stream(&buf[..]));
        let update = stream.next().await.expect("one update");
        assert!(
            update.peer_update.is_none(),
            "an empty Peers:[] must be a no-op, NOT PeerUpdate::Full(empty) which would wipe all peers"
        );
    }

    /// Positive control: a NON-empty `Peers` is still a full reset (`PeerUpdate::Full`), so the
    /// non-empty gate did not break the real full-resync path.
    #[tokio::test]
    async fn nonempty_peers_array_is_full_reset() {
        let buf = frame(&[r#"{
            "Seq": 10,
            "Peers": [
                { "ID": 1, "StableID": "n1", "Name": "a.ts.net.", "User": 1,
                  "Key": "nodekey:0000000000000000000000000000000000000000000000000000000000000000" }
            ]
        }"#]);
        let mut stream = core::pin::pin!(map_stream(&buf[..]));
        let update = stream.next().await.expect("one update");
        match update.peer_update {
            Some(PeerUpdate::Full(peers)) => {
                assert_eq!(peers.len(), 1, "the one peer is the full set")
            }
            other => panic!("a non-empty Peers must be PeerUpdate::Full, got {other:?}"),
        }
    }

    /// The subtle fallthrough edge: an empty `"Peers": []` co-present with a delta must produce a
    /// `Delta`, NOT `None` and NOT `Full`. Go ignores `PeersChanged`/`PeersRemoved` only when `Peers`
    /// is NON-empty; when `Peers` is empty the delta fields are honored. A future refactor that
    /// short-circuited `[]`→`None` before checking the delta fields would pass the other two tests
    /// but silently drop the delta (a netmap-staleness regression) — this pins that it doesn't.
    #[tokio::test]
    async fn empty_peers_with_delta_is_delta_not_noop() {
        let buf = frame(&[r#"{ "Seq": 11, "Peers": [], "PeersRemoved": [42] }"#]);
        let mut stream = core::pin::pin!(map_stream(&buf[..]));
        let update = stream.next().await.expect("one update");
        match update.peer_update {
            Some(PeerUpdate::Delta { remove, upsert }) => {
                assert_eq!(
                    remove.len(),
                    1,
                    "the PeersRemoved entry is honored as a delta removal"
                );
                assert!(upsert.is_empty(), "no PeersChanged ⇒ no upserts");
            }
            other => {
                panic!("empty Peers + PeersRemoved must be Delta (delta honored), got {other:?}")
            }
        }
    }
}
