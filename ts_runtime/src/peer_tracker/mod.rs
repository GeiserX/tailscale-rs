//! Peer delta update tracking.

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::Arc,
};

use kameo::{
    actor::ActorRef,
    message::{Context, Message},
    reply::ReplySender,
};
use tokio::sync::watch;
use ts_control::{Node, UserId, UserProfile};
use ts_transport::PeerId;

use crate::{Error, env::Env, status::StatusNode};

mod peer_db;

pub use peer_db::PeerDb;

/// Actor that tracks peer delta updates and emits new states.
pub struct PeerTracker {
    peer_db: PeerDb,
    seen_state_update: bool,
    pending_requests: Vec<Pending>,
    /// Latest peer snapshot, published on every netmap update so embedders can watch for peer
    /// changes ([`WatchNetmap`]).
    peer_watch: watch::Sender<Vec<StatusNode>>,
    /// Accumulated netmap user profiles (`MapResponse.UserProfiles`), keyed by user id, joined
    /// against a node's [`Node::user_id`](ts_control::Node::user_id) to resolve the owning user's
    /// login/display name for a [`WhoIs`](crate::status::WhoIs). Control sends these incrementally
    /// (only new/changed profiles per response), so this map **accumulates** across updates rather
    /// than being replaced — a peer upserted in one response may reference a profile delivered in an
    /// earlier one.
    user_profiles: HashMap<UserId, UserProfile>,
    /// Tailnet-Lock (TKA) authority used to verify each peer's `key_signature` at the peer-trust
    /// chokepoint. When `Some`, enforcement is **active**: every upserted peer must present a
    /// signature this authority authorizes, or it is rejected (fail-closed). When `None` (always,
    /// this wave) enforcement is **inactive** and every peer is upserted — identical to pre-TKA
    /// behavior. There is no live `Authority` source yet: building one requires the
    /// `/machine/tka/sync` Noise RPC + AUM-chain replayer (deferred, see SECURITY.md). The
    /// enforcement path below is wired and unit-tested, and flips on the instant an authority is
    /// supplied; it is explicitly gated, not a silent no-op.
    tka_authority: Option<ts_tka::Authority>,
    env: Env,
}

impl PeerTracker {
    fn peer_by_name_opt(&self, name: &str) -> Option<&Node> {
        // Canonicalization (case + trailing dot) is handled inside the name index lookup.
        self.peer_db.get(&name).map(|(_id, node)| node)
    }

    fn peer_by_tailnet_ip_opt(&self, ip: IpAddr) -> Option<&Node> {
        self.peer_db.get(&ip).map(|(_id, node)| node)
    }

    /// Build the peer entries for a [`Status`](crate::Status) snapshot from the current peer db.
    fn status_peers(&self) -> Vec<StatusNode> {
        self.peer_db
            .peers()
            .values()
            .map(StatusNode::from_node)
            .collect()
    }

    fn whois_opt(&self, addr: std::net::SocketAddr) -> Option<crate::status::WhoIs> {
        let ip = crate::status::whois_addr(addr);
        let node = self.peer_by_tailnet_ip_opt(ip).cloned()?;
        // Join the node's owning user id against the accumulated UserProfiles table to resolve a
        // login/display name. `None` when control sent no profile for that user (e.g. tagged nodes
        // with no human owner, or a profile not yet delivered).
        let user = self.resolve_user(node.user_id);
        Some(crate::status::WhoIs::from_node_with_user(node, user))
    }

    /// Resolve a user id to its best display label from the accumulated profile table.
    fn resolve_user(&self, user_id: UserId) -> Option<String> {
        self.user_profiles
            .get(&user_id)
            .and_then(UserProfile::best_label)
    }

    /// Whether `node` may be admitted to the peer db under the current Tailnet-Lock posture.
    ///
    /// Fail-closed and gated:
    /// - No [`tka_authority`](Self::tka_authority) ⇒ enforcement inactive ⇒ always admit (today's
    ///   behavior; this is the always-taken branch this wave).
    /// - Authority present + peer carries a `key_signature` that the authority authorizes for the
    ///   peer's node key ⇒ admit.
    /// - Authority present + signature missing or unauthorized/invalid ⇒ **reject** (Go denies
    ///   network access to unsigned peers under tailnet lock; we do not upsert them).
    fn tka_admits(&self, node: &Node) -> bool {
        let Some(auth) = &self.tka_authority else {
            return true;
        };

        if node.key_signature.is_empty() {
            // TKA active but peer presented no signature: reject (Go denies network access to
            // unsigned peers under tailnet lock, unless UnsignedPeerAPIOnly — out of scope here).
            tracing::warn!(
                stable_id = ?node.stable_id,
                "TKA: rejecting unsigned peer under tailnet lock"
            );
            return false;
        }

        if let Err(e) = auth.node_key_authorized(&node.node_key.to_bytes(), &node.key_signature) {
            tracing::warn!(
                stable_id = ?node.stable_id,
                error = %e,
                "TKA: rejecting peer with unauthorized node key"
            );
            return false;
        }

        true
    }
}

impl kameo::Actor for PeerTracker {
    type Args = Env;
    type Error = Error;

    async fn on_start(env: Self::Args, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        env.subscribe::<Arc<ts_control::StateUpdate>>(&slf).await?;

        let (peer_watch, _) = watch::channel(Vec::new());

        Ok(Self {
            peer_db: PeerDb::default(),
            pending_requests: Default::default(),
            seen_state_update: false,
            peer_watch,
            user_profiles: HashMap::new(),
            // No live TKA authority source this wave (the `/machine/tka/sync` RPC + AUM replayer are
            // deferred); enforcement stays inactive until one is supplied. See `tka_authority`.
            tka_authority: None,
            env,
        })
    }
}

enum Pending {
    PeerByName(PeerByName, ReplySender<Option<Node>>),
    AcceptedRoute(PeerByAcceptedRoute, ReplySender<Vec<Node>>),
    TailnetIp(PeerByTailnetIp, ReplySender<Option<Node>>),
    Status(ReplySender<Vec<StatusNode>>),
    WhoIs(Whois, ReplySender<Option<crate::status::WhoIs>>),
}

// For messages with arguments, a struct is generated with the args as fields. They aren't
// documented, and we can't apply attributes directly to the fields. Hence, wrap in a module where
// docs are turned off everywhere.
#[allow(missing_docs)]
mod msg_impl {
    use std::net::IpAddr;

    use kameo::prelude::DelegatedReply;

    use super::*;

    #[kameo::messages]
    impl PeerTracker {
        /// Lookup a peer by name.
        ///
        /// Waits until we've received at least one peer update from control.
        #[message(ctx)]
        pub async fn peer_by_name(
            &mut self,
            ctx: &mut Context<Self, DelegatedReply<Option<Node>>>,
            name: String,
        ) -> DelegatedReply<Option<Node>> {
            let (deleg, sender) = ctx.reply_sender();
            let Some(sender) = sender else { return deleg };

            if !self.seen_state_update {
                tracing::debug!(query = name, "no peer state seen yet, queueing request");

                self.pending_requests
                    .push(Pending::PeerByName(PeerByName { name }, sender));

                return deleg;
            }

            sender.send(self.peer_by_name_opt(&name).cloned());

            deleg
        }

        /// Lookup all peers that accept packets addressed to the given IP.
        ///
        /// This includes the peer's tailnet address and any subnet routes it provides. Only
        /// the peers with the most specific subnet route match that covers `ip` will be
        /// returned.
        ///
        /// E.g., suppose:
        ///
        /// - We're querying for `10.1.2.3`
        /// - `PeerA` and `PeerB` have accepted routes for `10.1.2.0/24`
        /// - `PeerC` has an accepted route for `10.1.0.0/16`
        ///
        /// Only `PeerA` and `PeerB` will be returned, since they have the most specific
        /// prefix match.
        #[message(ctx)]
        pub fn peer_by_accepted_route(
            &mut self,
            ctx: &mut Context<Self, DelegatedReply<Vec<Node>>>,
            ip: IpAddr,
        ) -> DelegatedReply<Vec<Node>> {
            let (deleg, sender) = ctx.reply_sender();
            let Some(sender) = sender else { return deleg };

            if !self.seen_state_update {
                tracing::debug!(query = %ip, "no peer state seen yet, queueing request");

                self.pending_requests
                    .push(Pending::AcceptedRoute(PeerByAcceptedRoute { ip }, sender));

                return deleg;
            }

            sender.send(
                self.peer_db
                    .get_route(ip.into())
                    .map(|(_id, node)| node.clone())
                    .collect(),
            );

            deleg
        }

        /// Lookup the peer that has the given tailnet IP address.
        #[message(ctx)]
        pub fn peer_by_tailnet_ip(
            &mut self,
            ctx: &mut Context<Self, DelegatedReply<Option<Node>>>,
            ip: IpAddr,
        ) -> DelegatedReply<Option<Node>> {
            let (deleg, sender) = ctx.reply_sender();
            let Some(sender) = sender else { return deleg };

            if !self.seen_state_update {
                tracing::debug!(query = %ip, "no peer state seen yet, queueing request");

                self.pending_requests
                    .push(Pending::TailnetIp(PeerByTailnetIp { ip }, sender));

                return deleg;
            }

            sender.send(self.peer_by_tailnet_ip_opt(ip).cloned());

            deleg
        }

        /// Build the peer entries of a [`Status`](crate::Status) snapshot.
        ///
        /// Returns one [`StatusNode`] per known peer. The self node is *not* included here (it
        /// lives in the control runner); [`Runtime::status`](crate::Runtime::status) combines both.
        ///
        /// Waits until we've received at least one peer update from control.
        #[message(ctx)]
        pub fn get_status(
            &mut self,
            ctx: &mut Context<Self, DelegatedReply<Vec<StatusNode>>>,
        ) -> DelegatedReply<Vec<StatusNode>> {
            let (deleg, sender) = ctx.reply_sender();
            let Some(sender) = sender else { return deleg };

            if !self.seen_state_update {
                tracing::debug!("no peer state seen yet, queueing status request");
                self.pending_requests.push(Pending::Status(sender));
                return deleg;
            }

            sender.send(self.status_peers());

            deleg
        }

        /// Resolve which node owns a tailnet source address.
        ///
        /// Maps the source IP of `addr` to the owning node via the tailnet-IP index, returning a
        /// [`WhoIs`](crate::WhoIs). The port is ignored (a tailnet IP uniquely identifies a node).
        ///
        /// The resulting [`WhoIs`](crate::WhoIs) carries no user/login or capability data: this
        /// fork's domain [`Node`](ts_control::Node) does not retain those wire fields. See the
        /// [`status`](crate::status) module docs for the gap.
        ///
        /// Waits until we've received at least one peer update from control.
        #[message(ctx)]
        pub fn whois(
            &mut self,
            ctx: &mut Context<Self, DelegatedReply<Option<crate::status::WhoIs>>>,
            addr: std::net::SocketAddr,
        ) -> DelegatedReply<Option<crate::status::WhoIs>> {
            let (deleg, sender) = ctx.reply_sender();
            let Some(sender) = sender else { return deleg };

            if !self.seen_state_update {
                tracing::debug!(query = %addr, "no peer state seen yet, queueing whois request");
                self.pending_requests
                    .push(Pending::WhoIs(Whois { addr }, sender));
                return deleg;
            }

            sender.send(self.whois_opt(addr));

            deleg
        }

        /// Subscribe to netmap peer-change events.
        ///
        /// Returns a [`watch::Receiver`] whose value is the current set of peer
        /// [`StatusNode`]s, updated on every netmap state update from control. Embedders can await
        /// changes via [`watch::Receiver::changed`] to react to peers joining, leaving, or changing.
        ///
        /// The receiver's initial value is the peer set at subscription time (empty before the
        /// first netmap update). This is a peer-only view; combine with the self node from
        /// [`Runtime::status`](crate::Runtime::status) when a full snapshot is needed.
        #[message(derive(Clone))]
        pub fn watch_netmap(&self) -> watch::Receiver<Vec<StatusNode>> {
            self.peer_watch.subscribe()
        }
    }
}

pub use msg_impl::*;

#[derive(Debug, Clone)]
pub(crate) struct PeerState {
    #[allow(unused)]
    pub deletions: HashSet<PeerId>,
    #[allow(unused)]
    pub upserts: HashSet<PeerId>,
    pub peers: Arc<PeerDb>,
}

impl Message<Arc<ts_control::StateUpdate>> for PeerTracker {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: Arc<ts_control::StateUpdate>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        // Accumulate user profiles first — control sends them incrementally and a response may
        // carry profiles with no peer delta (or peers that reference a profile from an earlier
        // response), so this must happen before the no-peer-update early return below.
        for profile in &msg.user_profiles {
            self.user_profiles.insert(profile.id, profile.clone());
        }

        // Apply the standalone online/last-seen delta maps (channels C/D, `MapResponse.OnlineChange`
        // / `PeerSeenChange`). These arrive keyed by control node id and may ride a response that
        // carries NO `peer_update` (a bare online flip is the common case), so they must be applied
        // *before* the no-peer-update early return — otherwise online status freezes at the last
        // full-node/patch value. Each entry only ever *sets* a value (never back to unknown).
        let liveness_changed =
            self.apply_liveness_changes(&msg.online_change, &msg.peer_seen_change);

        let Some(peer_update) = &msg.peer_update else {
            // No peer set/patch this response. If a liveness delta still mutated the netmap, publish
            // the refreshed snapshot so watchers (and `GetStatus`) see the new online state.
            if liveness_changed {
                self.service_pending_requests();
                self.peer_watch.send_replace(self.status_peers());
                if let Err(e) = self
                    .env
                    .publish(Arc::new(PeerState {
                        upserts: HashSet::default(),
                        deletions: HashSet::default(),
                        peers: Arc::new(self.peer_db.clone()),
                    }))
                    .await
                {
                    tracing::error!(error = %e, "publishing liveness-only peer state update");
                }
            }
            return;
        };

        let (upserts, deletions) = self.apply_peer_update(peer_update);

        tracing::debug!(
            n_upsert = upserts.len(),
            n_delete = deletions.len(),
            peer_count = self.peer_db.peers().len(),
            "new peer state"
        );

        self.service_pending_requests();

        // Publish the latest peer snapshot to netmap watchers. `send_replace` keeps the receiver's
        // value current even when there are no subscribers, so a late subscriber sees fresh state.
        self.peer_watch.send_replace(self.status_peers());

        if let Err(e) = self
            .env
            .publish(Arc::new(PeerState {
                upserts,
                deletions,
                peers: Arc::new(self.peer_db.clone()),
            }))
            .await
        {
            tracing::error!(error = %e, "publishing peer state update");
        }
    }
}

/// Ask the peer tracker to re-broadcast its current peer snapshot on the bus, without any peer
/// change. `Device::set_exit_node` sends this after changing the exit-node selector so the route
/// updater and source filter (both `Arc<PeerState>` subscribers) re-resolve the new selector
/// immediately, rather than waiting for the next netmap update.
#[derive(Debug, Clone, Copy)]
pub struct RepublishState;

impl Message<RepublishState> for PeerTracker {
    type Reply = ();

    async fn handle(&mut self, _msg: RepublishState, _ctx: &mut Context<Self, Self::Reply>) {
        // An empty upsert/deletion set: this is a re-broadcast of the unchanged peer set, not a
        // delta. Subscribers recompute their routes/filters against the current peers and the
        // (just-updated) exit-node selector.
        if let Err(e) = self
            .env
            .publish(Arc::new(PeerState {
                upserts: HashSet::default(),
                deletions: HashSet::default(),
                peers: Arc::new(self.peer_db.clone()),
            }))
            .await
        {
            tracing::error!(error = %e, "re-publishing peer state after exit-node change");
        }
    }
}

impl PeerTracker {
    /// Apply a single [`PeerUpdate`](ts_control::PeerUpdate) to the peer db, enforcing the
    /// Tailnet-Lock peer-trust chokepoint ([`tka_admits`](Self::tka_admits)) at every upsert site.
    ///
    /// This is the **single source of truth** for the peer-trust enforcement loop: the actor's
    /// netmap [`handle`](Message::handle) calls it, and so do the TKA enforcement tests, so the two
    /// real upsert sites (`Full` and `Delta { upsert }`) cannot diverge from what is tested.
    ///
    /// Returns `(upserts, deletions)` — the [`PeerId`]s touched — for downstream bookkeeping.
    fn apply_peer_update(
        &mut self,
        peer_update: &ts_control::PeerUpdate,
    ) -> (HashSet<PeerId>, HashSet<PeerId>) {
        let mut upserts = HashSet::default();
        let mut deletions = HashSet::default();

        match peer_update {
            ts_control::PeerUpdate::Full(new_nodes) => {
                tracing::trace!("full peer update");

                // Only stable_ids that PASS the Tailnet-Lock gate survive a full re-sync. This makes
                // revocation evict: if a peer is re-included with a now-invalid (or missing)
                // signature under an active authority, it is excluded from `retained_ids`, so
                // `retain` drops the stale (previously-admitted) entry rather than leaving it in the
                // db unverified. With no authority, `tka_admits` is always `true`, so `retained_ids`
                // is exactly the set of re-included stable_ids — the inactive path is byte-for-byte
                // the pre-TKA behavior (no regression).
                let retained_ids = new_nodes
                    .iter()
                    .filter(|node| self.tka_admits(node))
                    .map(|x| &x.stable_id)
                    .collect::<HashSet<_>>();

                self.peer_db.retain(|id, peer| {
                    let retain = retained_ids.contains(&peer.stable_id);

                    if !retain {
                        deletions.insert(id);
                    }

                    retain
                });

                for node in new_nodes {
                    if !self.tka_admits(node) {
                        continue; // fail-CLOSED: do not upsert a peer rejected by tailnet lock
                    }
                    let peer_id = self.peer_db.upsert(node);
                    upserts.insert(peer_id);
                }
            }

            ts_control::PeerUpdate::Delta { remove, upsert } => {
                tracing::trace!("delta peer update");

                for peer in upsert {
                    if !self.tka_admits(peer) {
                        continue; // fail-CLOSED: do not upsert a peer rejected by tailnet lock
                    }
                    let id = self.peer_db.upsert(peer);

                    upserts.insert(id);
                }

                for peer in remove {
                    let Some((id, _node)) = self.peer_db.remove(peer) else {
                        tracing::error!(control_node_id = peer, "removed peer was unknown");
                        continue;
                    };

                    deletions.insert(id);
                }
            }

            ts_control::PeerUpdate::Patch(patches) => {
                tracing::trace!(n = patches.len(), "peer patch update");

                for patch in patches {
                    // A patch only mutates a peer already in the netmap; an unknown node id is
                    // ignored (the wire contract — a patch never creates a node). Clone the current
                    // node, apply the present fields, and re-upsert through the same path as a
                    // delta so indexes/routes stay consistent.
                    let Some((_id, existing)) = self.peer_db.get(&patch.id) else {
                        tracing::debug!(
                            control_node_id = patch.id,
                            "peer patch for unknown node; ignoring"
                        );
                        continue;
                    };

                    let mut node = existing.clone();
                    if let Some(endpoints) = &patch.underlay_addresses {
                        node.underlay_addresses = endpoints.clone();
                    }
                    if let Some(derp) = patch.derp_region {
                        node.derp_region = Some(derp);
                    }
                    if let Some(cap) = patch.cap {
                        node.cap = cap;
                    }
                    if let Some(cap_map) = &patch.cap_map {
                        node.cap_map = cap_map.clone();
                    }
                    if let Some(disco_key) = patch.disco_key {
                        node.disco_key = Some(disco_key);
                    }
                    if let Some(expiry) = patch.node_key_expiry {
                        node.node_key_expiry = Some(expiry);
                    }
                    // Online/last-seen liveness deltas (`PeerChange.Online`/`LastSeen`) — the
                    // dominant channel by which peer online transitions arrive mid-session. A patch
                    // only ever *sets* a value (never patches back to unknown), so apply when present.
                    if let Some(online) = patch.online {
                        node.online = Some(online);
                    }
                    if let Some(last_seen) = patch.last_seen {
                        node.last_seen = Some(last_seen);
                    }
                    // Key rotation: a patch may swap the node key (and its TKA signature). Apply
                    // both together so the trust gate below verifies the new signature against the
                    // new key, never a mismatched pair.
                    if let Some(node_key) = patch.node_key {
                        node.node_key = node_key;
                    }
                    if let Some(sig) = &patch.key_signature {
                        node.key_signature = sig.clone();
                    }

                    // Re-run the tailnet-lock gate on the patched node: a patch that rotates the key
                    // must satisfy the active authority, exactly like a `Delta` upsert, or it would
                    // be a trust-enforcement bypass. fail-CLOSED — if the patched node is no longer
                    // admitted, evict it rather than keep the stale (now-unverified) entry.
                    if !self.tka_admits(&node) {
                        if let Some((id, _)) = self.peer_db.remove(&patch.id) {
                            tracing::warn!(
                                control_node_id = patch.id,
                                "peer patch rejected by tailnet lock; evicting peer"
                            );
                            deletions.insert(id);
                        }
                        continue;
                    }

                    let id = self.peer_db.upsert(&node);
                    upserts.insert(id);
                }
            }
        }

        (upserts, deletions)
    }

    /// Apply the standalone online/last-seen delta maps (`MapResponse.OnlineChange` /
    /// `PeerSeenChange`, channels C/D) onto the retained netmap. Returns `true` if any node was
    /// actually mutated (so the caller knows whether to re-publish).
    ///
    /// Mirrors Go's post-`peers*` application of these maps. Each entry is keyed by control node id
    /// and only ever *sets* a value (never back to unknown). An entry for an unknown node id is
    /// ignored (like a patch — these maps never create a node). `peer_seen_change`'s `false` ("the
    /// peer is gone") is applied as `online = Some(false)` — the node stays in the netmap, it is
    /// merely marked offline; the `last_seen = now` update for the `true` case is intentionally not
    /// performed here (it needs a wall clock this actor does not hold, and `last_seen` is the
    /// low-value half — `online` is the `tailscale status` column that matters; see the iter-5
    /// research note §5.5).
    fn apply_liveness_changes(
        &mut self,
        online_change: &std::collections::BTreeMap<ts_control::NodeId, bool>,
        peer_seen_change: &std::collections::BTreeMap<ts_control::NodeId, bool>,
    ) -> bool {
        let mut changed = false;

        // Channel C — direct online flips.
        for (&node_id, &online) in online_change {
            if let Some((_pid, existing)) = self.peer_db.get(&node_id)
                && existing.online != Some(online)
            {
                let mut node = existing.clone();
                node.online = Some(online);
                self.peer_db.upsert(&node);
                changed = true;
            }
        }

        // Channel D — peer-seen flips. `false` ⇒ "the peer is gone" ⇒ mark offline (the node is
        // retained, not removed). `true` ⇒ "seen just now"; the online half is unknown from this
        // signal alone, so we leave `online` untouched (a `true` here does not assert connectivity to
        // control, only recent contact) and defer the `last_seen = now` timestamp (no clock here).
        for (&node_id, &seen) in peer_seen_change {
            if !seen
                && let Some((_pid, existing)) = self.peer_db.get(&node_id)
                && existing.online != Some(false)
            {
                let mut node = existing.clone();
                node.online = Some(false);
                self.peer_db.upsert(&node);
                changed = true;
            }
        }

        changed
    }

    /// Test-only constructor: build a [`PeerTracker`] with a chosen [`tka_authority`](Self::tka_authority)
    /// without going through the actor `on_start` path. Used by the TKA enforcement unit tests to
    /// exercise the peer-trust chokepoint ([`tka_admits`](Self::tka_admits)) directly.
    #[cfg(test)]
    fn for_test(env: Env, tka_authority: Option<ts_tka::Authority>) -> Self {
        let (peer_watch, _) = watch::channel(Vec::new());
        Self {
            peer_db: PeerDb::default(),
            seen_state_update: false,
            pending_requests: Vec::new(),
            peer_watch,
            user_profiles: HashMap::new(),
            tka_authority,
            env,
        }
    }

    fn service_pending_requests(&mut self) {
        if self.seen_state_update {
            return;
        }

        self.seen_state_update = true;

        if !self.pending_requests.is_empty() {
            tracing::debug!(
                n_pending = self.pending_requests.len(),
                "state update received, servicing pending requests"
            );
        }

        for req in core::mem::take(&mut self.pending_requests) {
            match req {
                Pending::PeerByName(PeerByName { name }, reply) => {
                    reply.send(self.peer_by_name_opt(&name).cloned());
                }
                Pending::TailnetIp(PeerByTailnetIp { ip }, reply) => {
                    reply.send(self.peer_by_tailnet_ip_opt(ip).cloned());
                }
                Pending::AcceptedRoute(PeerByAcceptedRoute { ip }, reply) => {
                    reply.send(
                        self.peer_db
                            .get_route(ip.into())
                            .map(|(_id, node)| node.clone())
                            .collect(),
                    );
                }
                Pending::Status(reply) => {
                    reply.send(self.status_peers());
                }
                Pending::WhoIs(Whois { addr }, reply) => {
                    reply.send(self.whois_opt(addr));
                }
            }
        }
    }
}

#[cfg(test)]
mod tka_tests {
    //! Tailnet-Lock (TKA) enforcement tests for the peer-trust chokepoint.
    //!
    //! These exercise [`PeerTracker::tka_admits`] and the `tka_admits ⇒ upsert` loop the netmap
    //! handler runs. The test [`ts_tka::Authority`] is built with [`ts_tka::Authority::from_state`]
    //! over a known Ed25519 trusted key, and the signed node-key signature CBOR is produced through
    //! `ts_tka`'s public `cbor` encoder + `aum_hash` (the exact same canonical bytes `ts_tka`'s own
    //! `direct_signature_verifies_end_to_end` test signs, with no new crypto vectors invented and no
    //! private `ts_tka` API used).

    use ed25519_dalek::{Signer, SigningKey};
    use ts_control::{Node, StableNodeId, TailnetAddress};
    use ts_tka::{
        AumHash, Authority, Key, KeyKind, State,
        cbor::{self, Value},
    };

    use super::*;

    /// `SigKind::Direct` wire value (Go `SigKind`; `ts_tka::SigKind::Direct = 1`).
    const SIG_KIND_DIRECT: u64 = 1;

    /// The 32-byte node key used across the signed-peer fixtures.
    const NODE_KEY_BYTES: [u8; 32] = [7u8; 32];

    /// Build a real [`Env`] for the tracker. Only the bus/keys/shutdown plumbing matters here; the
    /// TKA gate reads neither, so the forwarding preferences are all benign defaults.
    fn test_env() -> Env {
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        Env::new(
            ts_keys::NodeState::generate(),
            shutdown_rx,
            crate::env::ForwarderConfig {
                accept_routes: false,
                exit_node: None,
                forward_routes: Vec::new(),
                forward_tcp_ports: Vec::new(),
                forward_udp_ports: Vec::new(),
                forward_all_ports: false,
                forward_exit_egress: false,
                exit_proxy: None,
                peerapi_port: None,
                taildrop_dir: None,
                enable_ipv6: false,
                persistent_keepalive_interval: None,
                ingress_active: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            },
        )
    }

    /// A minimal peer [`Node`] carrying `node_key` and the given `key_signature`.
    fn peer_node(stable_id: &str, node_key: [u8; 32], key_signature: Vec<u8>) -> Node {
        Node {
            id: 1,
            stable_id: StableNodeId(stable_id.to_string()),
            hostname: stable_id.to_string(),
            user_id: 0,
            tailnet: Some("ts.net".to_string()),
            tags: Vec::new(),
            tailnet_address: TailnetAddress {
                ipv4: "100.64.0.1/32".parse().unwrap(),
                ipv6: "fd7a:115c:a1e0::1/128".parse().unwrap(),
            },
            node_key: node_key.into(),
            node_key_expiry: None,
            online: None,
            last_seen: None,
            key_signature,
            machine_key: None,
            disco_key: None,
            accepted_routes: Vec::new(),
            underlay_addresses: Vec::new(),
            derp_region: None,
            cap: Default::default(),
            cap_map: Default::default(),
            peerapi_port: None,
            peerapi_dns_proxy: false,
            is_wireguard_only: false,
            exit_node_dns_resolvers: Vec::new(),
            peer_relay: false,
            service_vips: Default::default(),
        }
    }

    /// Encode a `Direct` [`ts_tka::NodeKeySignature`] CBOR exactly as `ts_tka`'s private `to_cbor`
    /// does (int-map keys: 1=kind, 2=pubkey, 3=key_id, 4=signature; empty byte fields omitted),
    /// using only the crate's *public* `cbor` encoder. `signature` of `None` produces the
    /// signing-digest preimage (the `SigHash` form).
    fn direct_sig_cbor(node_key: &[u8], key_id: &[u8], signature: Option<&[u8]>) -> Vec<u8> {
        let mut pairs = alloc_pairs(node_key, key_id);
        if let Some(sig) = signature {
            pairs.push((4, Some(Value::Bytes(sig.to_vec()))));
        }
        cbor::int_map(pairs).to_vec()
    }

    fn alloc_pairs(node_key: &[u8], key_id: &[u8]) -> Vec<(u64, Option<Value>)> {
        vec![
            (1, Some(Value::Uint(SIG_KIND_DIRECT))),
            (2, Some(Value::Bytes(node_key.to_vec()))),
            (3, Some(Value::Bytes(key_id.to_vec()))),
        ]
    }

    /// Build a TKA [`Authority`] that trusts `signing.verifying_key()`, plus a valid `Direct`
    /// node-key signature CBOR authorizing [`NODE_KEY_BYTES`] under it.
    fn authority_and_valid_sig() -> (Authority, Vec<u8>) {
        // A fixed, known Ed25519 trusted key (mirrors ts_tka's own end-to-end test seed).
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let trusted_pub = signing.verifying_key().to_bytes().to_vec();

        let authority = Authority::from_state(
            AumHash([0; 32]),
            State {
                keys: vec![Key {
                    kind: KeyKind::Ed25519,
                    votes: 1,
                    public: trusted_pub.clone(),
                }],
            },
        );

        // SigHash preimage = canonical CBOR with the signature field omitted; sign its blake2s hash.
        let preimage = direct_sig_cbor(&NODE_KEY_BYTES, &trusted_pub, None);
        let sig_hash = ts_tka::aum_hash(&preimage).0;
        let signature = signing.sign(&sig_hash).to_bytes().to_vec();

        let signed_cbor = direct_sig_cbor(&NODE_KEY_BYTES, &trusted_pub, Some(&signature));
        // Sanity: the authority accepts the signature we just built (same path the gate uses).
        assert!(
            authority
                .node_key_authorized(&NODE_KEY_BYTES, &signed_cbor)
                .is_ok()
        );

        (authority, signed_cbor)
    }

    #[tokio::test]
    async fn tka_inactive_upserts_all_peers() {
        // No authority ⇒ enforcement inactive ⇒ both a signed and an unsigned peer are admitted.
        let mut tracker = PeerTracker::for_test(test_env(), None);

        let signed = peer_node("signed", [1u8; 32], vec![0xde, 0xad, 0xbe, 0xef]);
        let unsigned = peer_node("unsigned", [2u8; 32], vec![]);

        assert!(tracker.tka_admits(&signed));
        assert!(tracker.tka_admits(&unsigned));

        tracker.peer_db.upsert(&signed);
        tracker.peer_db.upsert(&unsigned);
        assert_eq!(tracker.peer_db.peers().len(), 2);
    }

    #[tokio::test]
    async fn tka_active_rejects_unsigned_peer() {
        // Authority present + peer presents no signature ⇒ rejected (fail-closed), not in peer_db.
        let (authority, _sig) = authority_and_valid_sig();
        let mut tracker = PeerTracker::for_test(test_env(), Some(authority));

        let unsigned = peer_node("unsigned", NODE_KEY_BYTES, vec![]);
        assert!(!tracker.tka_admits(&unsigned));

        // Mirror the handler's `if !tka_admits { continue }` loop.
        if tracker.tka_admits(&unsigned) {
            tracker.peer_db.upsert(&unsigned);
        }
        assert_eq!(tracker.peer_db.peers().len(), 0);
        assert!(tracker.peer_db.get(&unsigned.node_key).is_none());
    }

    #[tokio::test]
    async fn tka_active_rejects_bad_signature() {
        // Authority present + a signature that fails to verify ⇒ rejected, not in peer_db.
        let (authority, mut sig) = authority_and_valid_sig();
        // Tamper the last byte (the trailing signature byte) so verification fails.
        let last = sig.len() - 1;
        sig[last] ^= 0xff;

        let mut tracker = PeerTracker::for_test(test_env(), Some(authority));
        let bad = peer_node("bad", NODE_KEY_BYTES, sig);
        assert!(!tracker.tka_admits(&bad));

        if tracker.tka_admits(&bad) {
            tracker.peer_db.upsert(&bad);
        }
        assert_eq!(tracker.peer_db.peers().len(), 0);
    }

    #[tokio::test]
    async fn tka_active_admits_authorized_peer() {
        // Authority present + correctly-signed node key ⇒ admitted and upserted.
        let (authority, sig) = authority_and_valid_sig();
        let mut tracker = PeerTracker::for_test(test_env(), Some(authority));

        let good = peer_node("good", NODE_KEY_BYTES, sig);
        assert!(tracker.tka_admits(&good));

        if tracker.tka_admits(&good) {
            tracker.peer_db.upsert(&good);
        }
        assert_eq!(tracker.peer_db.peers().len(), 1);
        assert!(tracker.peer_db.get(&good.node_key).is_some());
    }

    // ---------------------------------------------------------------------------------------------
    // Tests that drive REAL `PeerUpdate`s through the shared handler body
    // ([`PeerTracker::apply_peer_update`], the single source of truth the actor's netmap `handle`
    // also calls), so the two real upsert sites (`Full` and `Delta { upsert }`) are exercised via
    // the actual enforcement path — not by hand-mirroring `if !tka_admits { continue }`.
    // ---------------------------------------------------------------------------------------------

    #[tokio::test]
    async fn tka_active_delta_upsert_rejects_unauthorized() {
        // Drive a real `Delta { upsert }` whose peer carries no signature. The Delta upsert site
        // must reject it under an active authority ⇒ not present in peer_db after the handler runs.
        let (authority, _sig) = authority_and_valid_sig();
        let mut tracker = PeerTracker::for_test(test_env(), Some(authority));

        let unsigned = peer_node("unsigned", NODE_KEY_BYTES, vec![]);
        let update = ts_control::PeerUpdate::Delta {
            upsert: vec![unsigned.clone()],
            remove: Vec::new(),
        };

        tracker.apply_peer_update(&update);

        assert_eq!(tracker.peer_db.peers().len(), 0);
        assert!(tracker.peer_db.get(&unsigned.node_key).is_none());
    }

    #[tokio::test]
    async fn tka_active_delta_upsert_admits_authorized() {
        // Drive a real `Delta { upsert }` with a correctly-signed peer ⇒ present in peer_db.
        let (authority, sig) = authority_and_valid_sig();
        let mut tracker = PeerTracker::for_test(test_env(), Some(authority));

        let good = peer_node("good", NODE_KEY_BYTES, sig);
        let update = ts_control::PeerUpdate::Delta {
            upsert: vec![good.clone()],
            remove: Vec::new(),
        };

        tracker.apply_peer_update(&update);

        assert_eq!(tracker.peer_db.peers().len(), 1);
        assert!(tracker.peer_db.get(&good.node_key).is_some());
    }

    #[tokio::test]
    async fn tka_active_full_admits_only_authorized_in_mixed_batch() {
        // Drive a real `Full` carrying a MIX of authorized + unauthorized peers. Only the
        // correctly-signed peer survives the Full upsert site; the unsigned and bad-sig peers are
        // dropped fail-closed.
        let (authority, sig) = authority_and_valid_sig();
        // A bad-sig variant of the same authorized signature (tamper the trailing byte).
        let mut bad_sig = sig.clone();
        let last = bad_sig.len() - 1;
        bad_sig[last] ^= 0xff;

        let mut tracker = PeerTracker::for_test(test_env(), Some(authority));

        // Only the authorized peer carries NODE_KEY_BYTES (the key the authority signed); the
        // rejected peers use distinct node keys so the survivor is unambiguous.
        let good = peer_node("good", NODE_KEY_BYTES, sig);
        let unsigned = peer_node("unsigned", [8u8; 32], vec![]);
        let bad = peer_node("bad", [9u8; 32], bad_sig);

        let update =
            ts_control::PeerUpdate::Full(vec![good.clone(), unsigned.clone(), bad.clone()]);

        tracker.apply_peer_update(&update);

        assert_eq!(tracker.peer_db.peers().len(), 1);
        assert!(tracker.peer_db.get(&good.node_key).is_some());
        assert!(tracker.peer_db.get(&unsigned.node_key).is_none());
        assert!(tracker.peer_db.get(&bad.node_key).is_none());
    }

    #[tokio::test]
    async fn tka_full_resync_revocation_behavior() {
        // Revocation-on-resync: admit a peer, then re-include the SAME stable_id in a `Full` with a
        // now-invalid signature. Per the Logic review finding, the pre-fix `retain` kept the stale
        // (previously-admitted) entry because membership was decided purely by stable_id.
        //
        // FIXED (not merely documented): the `Full` `retain` now keys on `tka_admits`-passing
        // stable_ids, so a peer whose re-included signature no longer verifies under the active
        // authority is EVICTED. This test asserts eviction. The inactive (authority=None) path is
        // provably unchanged — `tka_admits` always returns `true` there, so the retained set equals
        // the set of re-included stable_ids exactly (see `tka_inactive_full_resync_keeps_*`).
        let (authority, sig) = authority_and_valid_sig();
        let mut tracker = PeerTracker::for_test(test_env(), Some(authority));

        // 1) Admit the peer with a valid signature via a real `Full`.
        let good = peer_node("revoked", NODE_KEY_BYTES, sig.clone());
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![good.clone()]));
        assert_eq!(tracker.peer_db.peers().len(), 1);
        assert!(tracker.peer_db.get(&good.node_key).is_some());

        // 2) Re-sync the SAME stable_id, but with a now-invalid signature (tamper trailing byte).
        let mut bad_sig = sig;
        let last = bad_sig.len() - 1;
        bad_sig[last] ^= 0xff;
        let revoked = peer_node("revoked", NODE_KEY_BYTES, bad_sig);
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![revoked.clone()]));

        // Eviction: the stale entry is dropped because its re-included signature fails the gate.
        assert_eq!(tracker.peer_db.peers().len(), 0);
        assert!(tracker.peer_db.get(&revoked.node_key).is_none());
    }

    #[tokio::test]
    async fn tka_inactive_full_resync_keeps_reincluded_peer() {
        // Guard the inactive (authority=None) path against the revocation fix: with no authority,
        // a peer re-included in a `Full` survives regardless of its signature bytes — byte-for-byte
        // pre-TKA behavior, proving the `Full` `retain` change does not regress the always-taken
        // branch this wave.
        let mut tracker = PeerTracker::for_test(test_env(), None);

        let peer = peer_node("p", NODE_KEY_BYTES, vec![0xde, 0xad]);
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![peer.clone()]));
        assert_eq!(tracker.peer_db.peers().len(), 1);

        // Re-sync the same stable_id with garbage signature bytes; inactive enforcement keeps it.
        let resynced = peer_node("p", NODE_KEY_BYTES, vec![0x00]);
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![resynced.clone()]));
        assert_eq!(tracker.peer_db.peers().len(), 1);
        assert!(tracker.peer_db.get(&resynced.node_key).is_some());
    }

    /// A `Patch` for a peer already in the netmap merges only the fields it carries — here new UDP
    /// endpoints and a new home DERP — leaving the rest of the node intact. This is the fix for
    /// dropped `peers_changed_patch`: without it the netmap keeps stale endpoints and the peer can
    /// never re-handshake after it moves.
    #[tokio::test]
    async fn patch_merges_endpoints_and_derp_into_existing_peer() {
        let mut tracker = PeerTracker::for_test(test_env(), None);

        // Seed a peer (id == 1, per `peer_node`) with no endpoints / no DERP.
        let peer = peer_node("mover", [1u8; 32], vec![]);
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![peer.clone()]));
        let (_pid, before) = tracker.peer_db.get(&(1 as ts_control::NodeId)).unwrap();
        assert!(before.underlay_addresses.is_empty());
        assert!(before.derp_region.is_none());

        // Patch in fresh reachability (the idle-peer-reconnect case).
        let new_ep: std::net::SocketAddr = "203.0.113.7:41641".parse().unwrap();
        let patch = ts_control::PeerChange {
            id: 1,
            derp_region: Some(ts_derp::RegionId(core::num::NonZeroU32::new(5).unwrap())),
            cap: None,
            cap_map: None,
            underlay_addresses: Some(vec![new_ep]),
            node_key: None,
            key_signature: None,
            disco_key: None,
            node_key_expiry: None,
            online: None,
            last_seen: None,
        };
        let (upserts, deletions) =
            tracker.apply_peer_update(&ts_control::PeerUpdate::Patch(vec![patch]));

        assert_eq!(upserts.len(), 1);
        assert_eq!(deletions.len(), 0);
        // Same peer, now carrying the patched endpoint + DERP; node key untouched.
        assert_eq!(tracker.peer_db.peers().len(), 1);
        let (_pid, after) = tracker.peer_db.get(&(1 as ts_control::NodeId)).unwrap();
        assert_eq!(after.underlay_addresses, vec![new_ep]);
        assert_eq!(
            after.derp_region,
            Some(ts_derp::RegionId(core::num::NonZeroU32::new(5).unwrap()))
        );
        assert_eq!(after.node_key, peer.node_key);
    }

    /// A `Patch` whose node id is not in the current netmap is ignored (the wire contract: a patch
    /// never creates a node). No upsert, no deletion, peer set unchanged.
    #[tokio::test]
    async fn patch_for_unknown_node_is_ignored() {
        let mut tracker = PeerTracker::for_test(test_env(), None);
        let known = peer_node("known", [1u8; 32], vec![]); // id == 1
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![known]));

        let patch = ts_control::PeerChange {
            id: 999, // not in the netmap
            derp_region: None,
            cap: None,
            cap_map: None,
            underlay_addresses: Some(vec!["198.51.100.9:1".parse().unwrap()]),
            node_key: None,
            key_signature: None,
            disco_key: None,
            node_key_expiry: None,
            online: None,
            last_seen: None,
        };
        let (upserts, deletions) =
            tracker.apply_peer_update(&ts_control::PeerUpdate::Patch(vec![patch]));

        assert_eq!(upserts.len(), 0);
        assert_eq!(deletions.len(), 0);
        assert_eq!(tracker.peer_db.peers().len(), 1);
        assert!(tracker.peer_db.get(&(999 as ts_control::NodeId)).is_none());
    }

    /// An expiry-only `Patch` updates `node_key_expiry` on the matching peer (Go
    /// `PeerChange.KeyExpiry`), rather than being silently dropped until the next full resync.
    #[tokio::test]
    async fn patch_updates_node_key_expiry() {
        let mut tracker = PeerTracker::for_test(test_env(), None);
        let peer = peer_node("expiring", [1u8; 32], vec![]); // id == 1, node_key_expiry: None
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![peer]));

        let expiry = "2027-01-01T00:00:00Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap();
        let patch = ts_control::PeerChange {
            id: 1,
            derp_region: None,
            cap: None,
            cap_map: None,
            underlay_addresses: None,
            node_key: None,
            key_signature: None,
            disco_key: None,
            node_key_expiry: Some(expiry),
            online: None,
            last_seen: None,
        };
        tracker.apply_peer_update(&ts_control::PeerUpdate::Patch(vec![patch]));

        let (_pid, after) = tracker.peer_db.get(&(1 as ts_control::NodeId)).unwrap();
        assert_eq!(after.node_key_expiry, Some(expiry));
    }

    /// Channel B: a `PeerChange.online` patch flips a peer's online state without a full node.
    #[tokio::test]
    async fn patch_updates_online() {
        let mut tracker = PeerTracker::for_test(test_env(), None);
        let peer = peer_node("p", [1u8; 32], vec![]); // id == 1, online: None
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![peer]));
        assert_eq!(
            tracker
                .peer_db
                .get(&(1 as ts_control::NodeId))
                .unwrap()
                .1
                .online,
            None
        );

        let mut patch = ts_control::PeerChange {
            id: 1,
            derp_region: None,
            cap: None,
            cap_map: None,
            underlay_addresses: None,
            node_key: None,
            key_signature: None,
            disco_key: None,
            node_key_expiry: None,
            online: Some(true),
            last_seen: None,
        };
        tracker.apply_peer_update(&ts_control::PeerUpdate::Patch(vec![patch.clone()]));
        assert_eq!(
            tracker
                .peer_db
                .get(&(1 as ts_control::NodeId))
                .unwrap()
                .1
                .online,
            Some(true),
            "PeerChange.online=Some(true) marks the peer online"
        );

        // A subsequent patch flips it offline.
        patch.online = Some(false);
        tracker.apply_peer_update(&ts_control::PeerUpdate::Patch(vec![patch]));
        assert_eq!(
            tracker
                .peer_db
                .get(&(1 as ts_control::NodeId))
                .unwrap()
                .1
                .online,
            Some(false)
        );
    }

    /// Channel C/D: the `online_change` map flips online directly; `peer_seen_change: false`
    /// ("the peer is gone") marks the peer offline. Both apply to a peer already in the netmap and
    /// ignore unknown ids.
    #[tokio::test]
    async fn liveness_change_maps_apply_online() {
        let mut tracker = PeerTracker::for_test(test_env(), None);
        let peer = peer_node("p", [1u8; 32], vec![]); // id == 1
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![peer]));

        // Channel C: online_change sets online=true.
        let mut online_change = std::collections::BTreeMap::new();
        online_change.insert(1 as ts_control::NodeId, true);
        online_change.insert(999 as ts_control::NodeId, true); // unknown id — ignored
        let changed = tracker.apply_liveness_changes(&online_change, &Default::default());
        assert!(changed);
        assert_eq!(
            tracker
                .peer_db
                .get(&(1 as ts_control::NodeId))
                .unwrap()
                .1
                .online,
            Some(true)
        );

        // Channel D: peer_seen_change=false marks the peer offline (gone), node retained.
        let mut peer_seen_change = std::collections::BTreeMap::new();
        peer_seen_change.insert(1 as ts_control::NodeId, false);
        let changed = tracker.apply_liveness_changes(&Default::default(), &peer_seen_change);
        assert!(changed);
        assert_eq!(
            tracker
                .peer_db
                .get(&(1 as ts_control::NodeId))
                .unwrap()
                .1
                .online,
            Some(false),
            "peer_seen_change=false marks offline (the node stays in the netmap)"
        );
        assert_eq!(
            tracker.peer_db.peers().len(),
            1,
            "the node is retained, not removed"
        );

        // No-op when nothing matches / changes.
        assert!(!tracker.apply_liveness_changes(&Default::default(), &Default::default()));
    }

    /// Security: a `Patch` that rotates the node key must re-satisfy the tailnet-lock authority,
    /// exactly like a `Delta` upsert. A key-rotation patch whose new signature does NOT verify
    /// evicts the peer (fail-closed) rather than leaving a now-unverified entry — closing what would
    /// otherwise be a trust-enforcement bypass via the patch path.
    #[tokio::test]
    async fn patch_key_rotation_failing_tka_evicts_peer() {
        let (authority, sig) = authority_and_valid_sig();
        let mut tracker = PeerTracker::for_test(test_env(), Some(authority));

        // Admit a correctly-signed peer (id == 1).
        let good = peer_node("rotator", NODE_KEY_BYTES, sig.clone());
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![good.clone()]));
        assert_eq!(tracker.peer_db.peers().len(), 1);

        // Patch a new node key whose signature is garbage under the active authority.
        let patch = ts_control::PeerChange {
            id: 1,
            derp_region: None,
            cap: None,
            cap_map: None,
            underlay_addresses: None,
            node_key: Some([0x33u8; 32].into()),
            key_signature: Some(vec![0x00, 0x01, 0x02]),
            disco_key: None,
            node_key_expiry: None,
            online: None,
            last_seen: None,
        };
        let (upserts, deletions) =
            tracker.apply_peer_update(&ts_control::PeerUpdate::Patch(vec![patch]));

        assert_eq!(upserts.len(), 0);
        assert_eq!(deletions.len(), 1);
        assert_eq!(tracker.peer_db.peers().len(), 0);
    }

    /// A node's `user_id` joins against the accumulated UserProfiles table to resolve the owning
    /// user's login name in `WhoIs.user`. With no matching profile, `user` is `None` (the
    /// pre-existing behavior); once a profile arrives, the same node resolves to its login. This
    /// proves the accumulate-then-join path the netmap handler builds.
    fn profile(id: ts_control::UserId, login: &str) -> ts_control::UserProfile {
        ts_control::UserProfile {
            id,
            login_name: login.to_string(),
            display_name: None,
        }
    }

    #[tokio::test]
    async fn whois_resolves_user_from_accumulated_profiles() {
        let mut tracker = PeerTracker::for_test(test_env(), None);

        // A peer owned by user id 42 at 100.64.0.1 (the peer_node fixture's address).
        let mut peer = peer_node("p", NODE_KEY_BYTES, Vec::new());
        peer.user_id = 42;
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![peer]));
        let addr = "100.64.0.1:0".parse().unwrap();

        // No profile yet: the node resolves but its owner is unknown.
        let who = tracker.whois_opt(addr).expect("peer is known");
        assert_eq!(who.user, None);

        // Profile for a DIFFERENT user must not match.
        tracker
            .user_profiles
            .insert(7, profile(7, "someone-else@example.com"));
        assert_eq!(tracker.whois_opt(addr).unwrap().user, None);

        // The owning user's profile arrives (as the netmap handler would accumulate it): now the
        // login resolves.
        tracker
            .user_profiles
            .insert(42, profile(42, "alice@example.com"));
        assert_eq!(
            tracker.whois_opt(addr).unwrap().user,
            Some("alice@example.com".to_string())
        );
    }

    /// `UserProfile::best_label` prefers the login name, falling back to display name, else `None`.
    #[test]
    fn user_profile_best_label_prefers_login() {
        assert_eq!(
            profile(1, "alice@example.com").best_label(),
            Some("alice@example.com".to_string())
        );
        let display_only = ts_control::UserProfile {
            id: 2,
            login_name: String::new(),
            display_name: Some("Bob".to_string()),
        };
        assert_eq!(display_only.best_label(), Some("Bob".to_string()));
        let empty = ts_control::UserProfile {
            id: 3,
            login_name: String::new(),
            display_name: None,
        };
        assert_eq!(empty.best_label(), None);
    }
}
