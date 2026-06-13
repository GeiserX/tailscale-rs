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
    /// Tailnet-Lock (TKA) authority enforced at the peer-trust chokepoint, matching Go
    /// `tkaFilterNetmapLocked`. Read on demand from a [`watch`] cell the control runner owns: when it
    /// holds `Some` (a verified lock has been synced from control), enforcement is **active** — every
    /// upserted peer must present a `key_signature` this authority authorizes, or it is dropped
    /// (fail-closed), exactly as Go drops peers with a missing or failing signature. When it holds
    /// `None` (no lock, or the lock was disabled) enforcement is **inactive** and every peer is
    /// upserted, identical to pre-TKA behavior and to Go's `b.tka == nil` early return.
    ///
    /// A `watch::Receiver` (not the bus) is the transport on purpose: the authority is a single
    /// security-critical state cell, and `watch` is last-write-wins, never-dropped, and ordered by
    /// the control runner's own writes — so a disable (`None`) can never be reordered behind or
    /// silently dropped before a stale `Some` (which a best-effort broadcast bus could do, leaving a
    /// defunct lock enforcing forever). The control runner is the sole writer; we only ever read.
    ///
    /// The authority always passes through `VerifiedAumChain::verify` before the control runner
    /// publishes it, so enforcement only engages on a chain we have cryptographically verified.
    /// Connectivity now depends on `ts_tka` verifying genuinely-good signatures correctly (see
    /// SECURITY.md). Self is structurally never filtered here (the self node never enters `peer_db` —
    /// it is routed to the control runner's `self_node` cell), so a node cannot lock itself out of
    /// its own netmap.
    tka_authority: watch::Receiver<Option<Arc<ts_tka::Authority>>>,
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
    ///
    /// Connectivity fields (`cur_addr`/`relay`) are left at their `from_node` defaults (`None`) here:
    /// this is the live-watch/hot path and must stay magicsock-free and synchronous. The explicit
    /// [`GetStatus`] snapshot enriches them ([`status_peers_with_ids`](Self::status_peers_with_ids)).
    fn status_peers(&self) -> Vec<StatusNode> {
        self.peer_db
            .peers()
            .values()
            .map(StatusNode::from_node)
            .collect()
    }

    /// Like [`status_peers`](Self::status_peers) but pairs each entry with its [`PeerId`], so the
    /// caller can join per-peer connectivity (the direct manager's `best_addrs`, keyed by `PeerId`)
    /// onto the `StatusNode` before returning it. Order is unspecified (a `HashMap` walk).
    fn status_peers_with_ids(&self) -> Vec<(PeerId, StatusNode)> {
        self.peer_db
            .peers()
            .iter()
            .map(|(id, node)| (*id, StatusNode::from_node(node)))
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

    /// Whether `node` may be admitted to the peer db under Tailnet Lock, matching Go
    /// `tkaFilterNetmapLocked`'s per-peer verdict (drop unsigned / failed-signature peers).
    ///
    /// This consults the live [`tka_authority`](Self::tka_authority) cell on each call (one `borrow`,
    /// held only for the duration of the verdict). For a `Full` resync — which checks every peer —
    /// prefer [`tka_authority_snapshot`](Self::tka_authority_snapshot) +
    /// [`tka_snapshot_admits`](Self::tka_snapshot_admits) to borrow once and verify each peer a single
    /// time; this method is the convenience wrapper for the single-peer (`Delta`/patch) sites.
    ///
    /// Fail-closed and gated:
    /// - No authority ⇒ no lock synced ⇒ always admit (Go's `b.tka == nil` early return; identical to
    ///   pre-TKA behavior).
    /// - **Empty trusted-key state** ⇒ always admit (logged at `error!` — see
    ///   [`tka_snapshot_admits`](Self::tka_snapshot_admits) for the full rationale).
    /// - Authority present + peer carries a `key_signature` the authority authorizes for the peer's
    ///   node key ⇒ admit.
    /// - Authority present + signature missing or unauthorized/invalid ⇒ **drop** (Go drops peers
    ///   with a missing signature or failed `NodeKeyAuthorized` under tailnet lock).
    fn tka_admits(&self, node: &Node) -> bool {
        // Single-peer sites (`Delta`/patch) only need the admit bool; the rotation details are used
        // exclusively by the cross-peer `Full` filter (rotation obsolescence is whole-netmap).
        Self::tka_snapshot_admits(self.tka_authority.borrow().as_deref(), node).admitted
    }

    /// Borrow the current TKA authority once (cloning the cheap `Arc`) for a batch verdict. Returns
    /// `None` when no lock is synced (admit-all). Used by the `Full` path so a netmap of N peers
    /// reads the cell once and runs at most one signature verify per peer (not two).
    fn tka_authority_snapshot(&self) -> Option<Arc<ts_tka::Authority>> {
        self.tka_authority.borrow().clone()
    }

    /// The per-peer Tailnet-Lock verdict against an already-borrowed `authority` snapshot. Factored
    /// out so both the single-peer [`tka_admits`](Self::tka_admits) and the `Full` batch path share
    /// one verdict implementation (no divergence) while the batch path verifies each peer exactly
    /// once.
    ///
    /// Returns whether the peer is admitted AND, for an admitted peer signed by a rotation chain, the
    /// [`RotationDetails`](ts_tka::RotationDetails) of that chain — so the `Full` path can run the
    /// cross-peer rotation filter (Go's `rotationTracker`) without a second verify per peer. A peer
    /// that is dropped, unsigned, or signed by a non-rotation chain carries `rotation == None`.
    ///
    /// Never logs key/signature bytes — only the `stable_id` and the `TkaError` Display (static
    /// descriptors). One documented parity gap remains vs Go (under-enforcement, in PARITY_ROADMAP):
    /// no `UnsignedPeerAPIOnly` exemption (our node model lacks the field).
    fn tka_snapshot_admits(authority: Option<&ts_tka::Authority>, node: &Node) -> TkaVerdict {
        let Some(auth) = authority else {
            return TkaVerdict::admit();
        };

        // Brick-guard: an authority with no trusted keys would drop every peer. A verified chain is
        // structurally guaranteed ≥1 key (genesis rejects an empty key set, and the last key cannot
        // be removed), so reaching here means a `ts_tka` invariant was violated — admit rather than
        // black-hole the whole netmap, and log at `error!` because it signals a real bug, not an
        // expected runtime input. This is OUR fail-safe, not a Go behavior. NOTE: it only catches the
        // empty-keyset shape; a non-empty authority that authorizes none of the offered peers still
        // (correctly) drops them — that is what a lock that revoked everyone means. The
        // "authorized-zero-peers" isolation case is surfaced separately by the caller.
        if auth.state().keys.is_empty() {
            tracing::error!(
                "TKA: authority has an empty trusted-key set (verified chains never do — likely a \
                 ts_tka bug); not enforcing (admitting all) to avoid isolating the node"
            );
            return TkaVerdict::admit();
        }

        if node.key_signature.is_empty() {
            tracing::warn!(
                stable_id = ?node.stable_id,
                "TKA: dropping unsigned peer under tailnet lock"
            );
            return TkaVerdict::drop();
        }

        match auth.node_key_authorized_with_details(&node.node_key.to_bytes(), &node.key_signature)
        {
            Ok(rotation) => {
                tracing::debug!(stable_id = ?node.stable_id, "TKA: peer node-key authorized");
                TkaVerdict {
                    admitted: true,
                    rotation,
                }
            }
            Err(e) => {
                tracing::warn!(
                    stable_id = ?node.stable_id,
                    error = %e,
                    "TKA: dropping peer with unauthorized node key"
                );
                TkaVerdict::drop()
            }
        }
    }
}

/// The outcome of a per-peer Tailnet-Lock check: whether the peer is admitted, plus (for an admitted
/// peer signed by a rotation chain) the chain's [`RotationDetails`](ts_tka::RotationDetails) so the
/// `Full` path can run the cross-peer rotation filter from the SAME verify pass (no second verify).
struct TkaVerdict {
    admitted: bool,
    rotation: Option<ts_tka::RotationDetails>,
}

impl TkaVerdict {
    /// Admitted, no rotation details (no lock / brick-guard / non-rotation signature).
    fn admit() -> Self {
        Self {
            admitted: true,
            rotation: None,
        }
    }
    /// Dropped.
    fn drop() -> Self {
        Self {
            admitted: false,
            rotation: None,
        }
    }
}

/// Cross-peer rotation-obsolescence tracker, mirroring Go `ipnlocal.rotationTracker`. Fed the
/// [`RotationDetails`](ts_tka::RotationDetails) of every admitted, rotation-signed peer in a `Full`
/// netmap; [`obsolete_keys`](Self::obsolete_keys) then returns the node keys to drop on top of the
/// per-peer verdict. Two rules (Go `tkaFilterNetmapLocked` + `rotationTracker.obsoleteKeys`):
///
/// 1. Every prior node key named in any rotation chain is obsolete (a newer chain rotated it away).
/// 2. Among `Direct`-rooted chains sharing one wrapping pubkey (a clone signal), only the
///    longest-chain peer survives; if the two longest are tied, ALL in that group are dropped (we
///    cannot tell which is the latest, so reject for safety). `Credential`-rooted chains are exempt
///    from rule 2 — several nodes can legitimately join under one reusable auth key (same wrapping
///    pubkey), so sharing it is not a clone signal there. (Rule 1 still applies to them.)
///
/// Node keys are tracked as raw `Vec<u8>` (the verified 32-byte node-public bytes).
#[derive(Default)]
struct RotationTracker {
    obsolete: HashSet<Vec<u8>>,
    by_wrapping_key: HashMap<Vec<u8>, Vec<SigRotation>>,
}

/// One admitted peer's rotation entry within a wrapping-key group.
struct SigRotation {
    node_key: Vec<u8>,
    num_prev_keys: usize,
}

impl RotationTracker {
    /// Record an admitted peer `node_key` and its rotation `details` (Go `addRotationDetails`).
    fn add(&mut self, node_key: Vec<u8>, details: &ts_tka::RotationDetails) {
        // Rule 1: every prior key is obsolete — applied for ALL chains (incl. credential-rooted),
        // matching Go's ungated `obsolete.AddSlice(d.PrevNodeKeys)`.
        self.obsolete.extend(details.prev_node_keys.iter().cloned());
        // Rule 2 (clone-uniqueness) is gated to Direct-rooted chains only.
        if details.initial_sig_kind != ts_tka::SigKind::Direct {
            return;
        }
        self.by_wrapping_key
            .entry(details.initial_wrapping_pubkey.clone())
            .or_default()
            .push(SigRotation {
                node_key,
                num_prev_keys: details.prev_node_keys.len(),
            });
    }

    /// Compute the full obsolete node-key set (Go `rotationTracker.obsoleteKeys`). Processes each
    /// wrapping-key group, mutating the shared `obsolete` set as it goes (so a key obsoleted by one
    /// group is seen as obsolete by later groups via the `retain` below — Go's
    /// `slices.DeleteFunc(... Contains)`). Group iteration order (a `HashMap` drain) is
    /// nondeterministic, but the result is order-INDEPENDENT: this only ever *inserts* into
    /// `obsolete` (never removes), and rule 1 already obsoleted every prior key before this loop, so
    /// the final set is a union that does not depend on which group runs first (as in Go).
    fn obsolete_keys(mut self) -> HashSet<Vec<u8>> {
        // Drain only the group map so the loop can mutate `self.obsolete` without aliasing it; the
        // shared `obsolete` set itself is NOT drained, preserving the cross-group visibility above.
        let groups: Vec<Vec<SigRotation>> = self.by_wrapping_key.drain().map(|(_k, v)| v).collect();
        for mut group in groups {
            // Drop entries already obsoleted (rotated away) by another chain.
            group.retain(|rd| !self.obsolete.contains(&rd.node_key));
            if group.is_empty() {
                continue;
            }
            // Longest chain (most prior keys) is the newest ⇒ the survivor; sort decreasing.
            // `sort_by_key` is stable (like Go's `SortStableFunc`); `Reverse` gives descending order.
            group.sort_by_key(|rd| core::cmp::Reverse(rd.num_prev_keys));
            if group.len() >= 2 && group[0].num_prev_keys == group[1].num_prev_keys {
                // Tie for longest ⇒ cannot disambiguate the latest ⇒ drop the WHOLE group.
                tracing::warn!(
                    "TKA: multiple peers share a wrapping key with equal rotation depth; dropping all (cannot determine the latest)"
                );
                for rd in &group {
                    self.obsolete.insert(rd.node_key.clone());
                }
            } else {
                // Only the longest-chain peer survives; the rest are obsolete.
                for rd in &group[1..] {
                    self.obsolete.insert(rd.node_key.clone());
                }
            }
        }
        self.obsolete
    }
}

impl kameo::Actor for PeerTracker {
    /// `(env, tka_authority)`: the bus/keys env, plus the read end of the control runner's TKA
    /// enforcement-authority cell (Go `tkaFilterNetmapLocked`). The control runner is the sole
    /// writer; it publishes the verified `Authority` after a successful `/machine/tka/sync` and
    /// `None` when the lock is disabled. A `watch` cell (not a bus message) so the latest value is
    /// always readable on demand, never dropped, and never reordered (see [`tka_authority`]).
    type Args = (Env, watch::Receiver<Option<Arc<ts_tka::Authority>>>);
    type Error = Error;

    async fn on_start(
        (env, tka_authority): Self::Args,
        slf: ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        env.subscribe::<Arc<ts_control::StateUpdate>>(&slf).await?;

        let (peer_watch, _) = watch::channel(Vec::new());

        Ok(Self {
            peer_db: PeerDb::default(),
            pending_requests: Default::default(),
            seen_state_update: false,
            peer_watch,
            user_profiles: HashMap::new(),
            // The cell starts `None` (no lock synced ⇒ enforcement inactive, admit all, matching
            // Go's `b.tka == nil`); the control runner flips it to `Some` on the first sync.
            tka_authority,
            env,
        })
    }
}

enum Pending {
    PeerByName(PeerByName, ReplySender<Option<Node>>),
    AcceptedRoute(PeerByAcceptedRoute, ReplySender<Vec<Node>>),
    TailnetIp(PeerByTailnetIp, ReplySender<Option<Node>>),
    Status(ReplySender<Vec<(PeerId, StatusNode)>>),
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

        /// Build the peer entries of a [`Status`](crate::Status) snapshot, each paired with its
        /// [`PeerId`] so [`Runtime::status`](crate::Runtime::status) can join per-peer connectivity
        /// (`cur_addr`/`relay`) from the direct manager before returning. The self node is *not*
        /// included here (it lives in the control runner); `Runtime::status` combines both and drops
        /// the ids.
        ///
        /// Waits until we've received at least one peer update from control.
        #[message(ctx)]
        pub fn get_status(
            &mut self,
            ctx: &mut Context<Self, DelegatedReply<Vec<(PeerId, StatusNode)>>>,
        ) -> DelegatedReply<Vec<(PeerId, StatusNode)>> {
            let (deleg, sender) = ctx.reply_sender();
            let Some(sender) = sender else { return deleg };

            if !self.seen_state_update {
                tracing::debug!("no peer state seen yet, queueing status request");
                self.pending_requests.push(Pending::Status(sender));
                return deleg;
            }

            sender.send(self.status_peers_with_ids());

            deleg
        }

        /// Return every known peer's full domain [`Node`] (not the lossy [`StatusNode`]).
        ///
        /// Used by [`Runtime::file_targets`](crate::Runtime::file_targets), which needs the full node
        /// (peerAPI address, owning user id, cap map) to compute Taildrop send targets. The self node
        /// is not included (it lives in the control runner). Returns empty before the first netmap —
        /// the natural "not connected yet" analog (an immediate answer, no queueing needed: callers
        /// that need a populated list await `Running` first).
        #[message]
        pub fn all_peers(&self) -> Vec<Node> {
            self.peer_db.peers().values().cloned().collect()
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
        // Wall clock for a `PeerSeenChange: true` (Go uses `clock.Now()`). chrono is built without
        // its `clock` feature in this workspace, so derive it from `SystemTime` the same way the
        // control runner / ssh-policy paths do (unix secs → `DateTime::from_timestamp`).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| chrono::DateTime::from_timestamp(d.as_secs() as i64, d.subsec_nanos()))
            .unwrap_or_default();
        let liveness_changed =
            self.apply_liveness_changes(&msg.online_change, &msg.peer_seen_change, now);

        if msg.peer_update.is_none() && msg.peer_patches.is_empty() {
            // No peer set or patch this response. If a liveness delta still mutated the netmap,
            // publish the refreshed snapshot so watchers (and `GetStatus`) see the new online state.
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
        }

        // Apply the whole-node peer set (if any) FIRST, then the field-level patches on top —
        // mirroring Go's `controlclient` order (`Peers*` then `PeersChangedPatch`). A response may
        // carry either, both, or (with a liveness-only delta) neither. Merge the upsert/deletion sets
        // so the published `PeerState` reflects every node touched by both passes; a node both
        // upserted by the set and patched stays in `upserts` (the patch removes it from `deletions`).
        let (mut upserts, mut deletions) = msg
            .peer_update
            .as_ref()
            .map(|u| self.apply_peer_update(u))
            .unwrap_or_default();

        if !msg.peer_patches.is_empty() {
            let (patch_upserts, patch_deletions) = self.apply_peer_patches(&msg.peer_patches);
            // A patch can evict a node the set just upserted (TKA rejection after key rotation), or
            // re-admit/patch one not in the set — reconcile so each id lands in exactly one set.
            for id in &patch_upserts {
                deletions.remove(id);
            }
            for id in &patch_deletions {
                upserts.remove(id);
            }
            upserts.extend(patch_upserts);
            deletions.extend(patch_deletions);
        }

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
/// change. Sent after a runtime preference change so the route updater and source filter (both
/// `Arc<PeerState>` subscribers) re-resolve against the new value immediately, rather than waiting
/// for the next netmap update: `Device::set_exit_node` (new exit-node selector) and
/// `Device::set_accept_routes` (new accept-routes flag) both send it.
#[derive(Debug, Clone, Copy)]
pub struct RepublishState;

impl Message<RepublishState> for PeerTracker {
    type Reply = ();

    async fn handle(&mut self, _msg: RepublishState, _ctx: &mut Context<Self, Self::Reply>) {
        // An empty upsert/deletion set: this is a re-broadcast of the unchanged peer set, not a
        // delta. Subscribers recompute their routes/filters against the current peers and the
        // (just-updated) runtime preferences (exit-node selector, accept-routes flag).
        if let Err(e) = self
            .env
            .publish(Arc::new(PeerState {
                upserts: HashSet::default(),
                deletions: HashSet::default(),
                peers: Arc::new(self.peer_db.clone()),
            }))
            .await
        {
            tracing::error!(error = %e, "re-publishing peer state after a runtime preference change");
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

                // Borrow the authority ONCE for the whole batch and verify each peer EXACTLY once
                // (Go runs `tkaFilterNetmapLocked` once over the assembled netmap; an earlier draft
                // verified every peer twice — once for `retained_ids`, once in the upsert loop —
                // doubling the ed25519 cost on the hot resync path). The per-node verdict vector
                // `admits` is computed once and drives both the `retain` (evict revoked peers, keyed
                // by stable_id) and the upsert loop (skip rejected peers, by the node's OWN verdict).
                // Keeping a per-node verdict (not just a stable_id set) means a node whose own
                // signature fails is never admitted on the strength of a different node that happens
                // to share its stable_id — matching the old per-node re-verify for that degenerate
                // (malformed-control) input.
                //
                // Revocation evicts: a peer re-included with a now-invalid/missing signature under an
                // active authority fails its verdict, so it is excluded from `retained_ids` and
                // `retain` drops the stale (previously-admitted) entry. With no authority the snapshot
                // is `None`, so every node passes — byte-for-byte the pre-TKA behavior (no regression).
                let authority = self.tka_authority_snapshot();
                let verdicts = new_nodes
                    .iter()
                    .map(|node| Self::tka_snapshot_admits(authority.as_deref(), node))
                    .collect::<Vec<_>>();

                // Cross-peer rotation filter (Go `rotationTracker`): from the SAME verify pass above,
                // feed every admitted, rotation-signed peer's details to the tracker, then drop any
                // peer presenting a node key a newer rotation has superseded (or a tied clone). This
                // is whole-netmap by nature — one peer's chain obsoletes another's key — so it lives
                // here, not in the per-peer verdict, matching Go's single pass over `nm.Peers`.
                let mut rotation = RotationTracker::default();
                for (node, verdict) in new_nodes.iter().zip(&verdicts) {
                    if verdict.admitted
                        && let Some(details) = &verdict.rotation
                    {
                        rotation.add(node.node_key.to_bytes().to_vec(), details);
                    }
                }
                let obsolete = rotation.obsolete_keys();

                // Final per-node keep verdict: admitted by the per-peer check AND not rotation-obsolete.
                // Drives both the `retain` (evict) and the upsert loop, so a node whose own signature
                // fails — or whose key was rotated away — is never admitted on the strength of a
                // stable_id twin.
                let keep = new_nodes
                    .iter()
                    .zip(&verdicts)
                    .map(|(node, v)| {
                        // `contains` takes `&[u8]` (HashSet<Vec<u8>> borrows as a slice) — no alloc.
                        v.admitted && !obsolete.contains(&node.node_key.to_bytes()[..])
                    })
                    .collect::<Vec<bool>>();

                // `retained_ids` is the set of stable_ids that survive (drives `retain` to evict the
                // rest). It must agree with what the upsert loop below will leave in the db. Control
                // should never send two distinct nodes with the same `stable_id` in one `Full`, but if
                // it does, `peer_db.upsert` is last-writer-wins on `stable_id`, so the db ends holding
                // the LAST kept node for that id. Build `retained_ids` from kept nodes only — a
                // stable_id is retained iff at least one of its (possibly duplicate) nodes is kept, so
                // the upsert loop's last-kept node lands and `retain` never evicts a just-upserted id.
                let retained_ids = new_nodes
                    .iter()
                    .zip(keep.iter().copied())
                    .filter(|(_, k)| *k)
                    .map(|(node, _)| &node.stable_id)
                    .collect::<HashSet<_>>();

                // Isolation diagnostic: an ACTIVE lock that authorized none of the offered peers
                // leaves this node with no peers — surface it loudly so a self-lockout (vs an attack)
                // is diagnosable. `authority.is_some()` means a real keyed lock (the empty-keyset
                // brick-guard admits-all, so it never reaches here with zero retained).
                if authority.is_some() && !new_nodes.is_empty() && retained_ids.is_empty() {
                    tracing::error!(
                        offered = new_nodes.len(),
                        "TKA: active lock authorized ZERO of the offered peers; node is isolated \
                         (verify the lock state, or disable tailnet lock to recover)"
                    );
                }

                self.peer_db.retain(|id, peer| {
                    let retain = retained_ids.contains(&peer.stable_id);

                    if !retain {
                        deletions.insert(id);
                    }

                    retain
                });

                for (node, k) in new_nodes.iter().zip(keep.iter().copied()) {
                    if !k {
                        continue; // fail-CLOSED: rejected by tailnet lock or rotation-obsolete (above)
                    }
                    let peer_id = self.peer_db.upsert(node);
                    upserts.insert(peer_id);
                }
            }

            ts_control::PeerUpdate::Delta { remove, upsert } => {
                tracing::trace!("delta peer update");

                for peer in upsert {
                    if !self.tka_admits(peer) {
                        // fail-CLOSED: do not upsert a peer rejected by tailnet lock. If the peer is
                        // ALREADY in the db (a delta re-upserting an existing peer whose signature is
                        // now invalid — e.g. revoked between syncs), evict the stale entry rather than
                        // leaving an unverified peer admitted; Go re-filters the whole netmap each map
                        // response, so a now-unsigned peer would not survive there either.
                        if let Some((id, _)) = self.peer_db.remove(&peer.stable_id) {
                            tracing::warn!(
                                stable_id = ?peer.stable_id,
                                "TKA: delta re-upsert rejected; evicting now-unauthorized peer"
                            );
                            deletions.insert(id);
                        }
                        continue;
                    }
                    let id = self.peer_db.upsert(peer);

                    upserts.insert(id);
                }

                for peer in remove {
                    let Some((id, _node)) = self.peer_db.remove(peer) else {
                        // A benign, expected race: the peer may already be gone (dropped in a prior
                        // `Full`, or fail-closed by TKA — whose now-"unknown" ids commonly reappear in
                        // a trailing `peers_removed`). Go treats an unknown removal as a no-op; log at
                        // debug, not error, to avoid false-alarm noise on a healthy node (matches the
                        // unknown-node handling in `apply_peer_patches`).
                        tracing::debug!(
                            control_node_id = peer,
                            "removed peer was unknown; ignoring"
                        );
                        continue;
                    };

                    deletions.insert(id);
                }
            }
        }

        (upserts, deletions)
    }

    /// Apply field-level peer patches (`MapResponse.PeersChangedPatch`), returning the upserted /
    /// deleted [`PeerId`]s.
    ///
    /// This is a SEPARATE channel from [`apply_peer_update`](Self::apply_peer_update): Go's
    /// `controlclient` applies the whole-node `Peers*` set first and then `PeersChangedPatch`, so a
    /// response that carries both has the peer set applied first (by the caller) and these patches
    /// applied second, on top of the freshly-synced nodes. A patch only mutates a peer already in the
    /// netmap; an unknown node id is ignored (the wire contract — a patch never creates a node).
    fn apply_peer_patches(
        &mut self,
        patches: &[ts_control::PeerChange],
    ) -> (HashSet<PeerId>, HashSet<PeerId>) {
        let mut upserts = HashSet::default();
        let mut deletions = HashSet::default();

        tracing::trace!(n = patches.len(), "peer patch update");

        for patch in patches {
            // Clone the current node, apply the present fields, and re-upsert through the same path
            // as a delta so indexes/routes stay consistent.
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
            // Online/last-seen liveness deltas (`PeerChange.Online`/`LastSeen`) — the dominant
            // channel by which peer online transitions arrive mid-session. A patch only ever *sets*
            // a value (never patches back to unknown), so apply when present.
            if let Some(online) = patch.online {
                node.online = Some(online);
            }
            if let Some(last_seen) = patch.last_seen {
                node.last_seen = Some(last_seen);
            }
            // Key rotation: a patch may swap the node key (and its TKA signature). Apply both
            // together so the trust gate below verifies the new signature against the new key, never
            // a mismatched pair.
            if let Some(node_key) = patch.node_key {
                node.node_key = node_key;
            }
            if let Some(sig) = &patch.key_signature {
                node.key_signature = sig.clone();
            }

            // Re-run the tailnet-lock gate on the patched node: a patch that rotates the key must
            // satisfy the active authority, exactly like a `Delta` upsert, or it would be a
            // trust-enforcement bypass. fail-CLOSED — if the patched node is no longer admitted,
            // evict it rather than keep the stale (now-unverified) entry.
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

        (upserts, deletions)
    }

    /// Apply the standalone online/last-seen delta maps (`MapResponse.OnlineChange` /
    /// `PeerSeenChange`, channels C/D) onto the retained netmap. Returns `true` if any node was
    /// actually mutated (so the caller knows whether to re-publish).
    ///
    /// Mirrors Go `controlclient/map.go:updatePeersStateFromResponse` (the two channels are
    /// semantically DISTINCT and must not be conflated):
    /// - `OnlineChange` (channel C) is the sole driver of a peer's `online` flag (`mut.Online = v`).
    /// - `PeerSeenChange` (channel D) is the sole driver of `last_seen`: `true ⇒ LastSeen = now`,
    ///   `false ⇒ LastSeen = nil` (cleared). It NEVER touches `online` — "not seen recently" is not
    ///   the same as "offline", which only `OnlineChange` asserts.
    ///
    /// Each entry is keyed by control node id and applies to a peer already in the netmap; an unknown
    /// node id is ignored (these maps never create a node). `now` is the wall-clock timestamp for a
    /// `PeerSeenChange: true` (Go uses `clock.Now()`); the caller passes it so this stays a pure
    /// function of its inputs. Returns `true` if any node was actually mutated.
    fn apply_liveness_changes(
        &mut self,
        online_change: &std::collections::BTreeMap<ts_control::NodeId, bool>,
        peer_seen_change: &std::collections::BTreeMap<ts_control::NodeId, bool>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let mut changed = false;

        // Channel C — direct online flips (the only writer of `online`).
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

        // Channel D — peer-seen flips (the only writer of `last_seen`; never touches `online`).
        // `true` ⇒ last-seen is now; `false` ⇒ last-seen cleared (Go map.go:820-830).
        for (&node_id, &seen) in peer_seen_change {
            let new_last_seen = if seen { Some(now) } else { None };
            if let Some((_pid, existing)) = self.peer_db.get(&node_id)
                && existing.last_seen != new_last_seen
            {
                let mut node = existing.clone();
                node.last_seen = new_last_seen;
                self.peer_db.upsert(&node);
                changed = true;
            }
        }

        changed
    }

    /// Test-only constructor: build a [`PeerTracker`] with a chosen initial TKA authority without
    /// going through the actor `on_start` path. Returns the tracker plus the **`watch::Sender`** for
    /// its enforcement-authority cell, so a test can drive the exact enable/disable transitions the
    /// control runner drives at runtime (`tx.send_replace(Some(..))` ⇒ enforce, `tx.send_replace(None)`
    /// ⇒ clear). The initial `Some` exercises the fail-closed chokepoint
    /// ([`tka_admits`](Self::tka_admits)); `None` is the no-lock admit-all path. The returned sender
    /// must be kept alive for the tracker to read updated values.
    #[cfg(test)]
    fn for_test(
        env: Env,
        tka_authority: Option<ts_tka::Authority>,
    ) -> (Self, watch::Sender<Option<Arc<ts_tka::Authority>>>) {
        let (peer_watch, _) = watch::channel(Vec::new());
        let (tka_tx, tka_rx) = watch::channel(tka_authority.map(Arc::new));
        let tracker = Self {
            peer_db: PeerDb::default(),
            seen_state_update: false,
            pending_requests: Vec::new(),
            peer_watch,
            user_profiles: HashMap::new(),
            tka_authority: tka_rx,
            env,
        };
        (tracker, tka_tx)
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
                    reply.send(self.status_peers_with_ids());
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
                accept_dns: true,
                exit_node: None,
                forward_routes: Vec::new(),
                forward_tcp_ports: Vec::new(),
                forward_udp_ports: Vec::new(),
                forward_all_ports: false,
                forward_exit_egress: false,
                block_incoming: false,
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
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), None);

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
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), Some(authority));

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

        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), Some(authority));
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
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), Some(authority));

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
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), Some(authority));

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
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), Some(authority));

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

        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), Some(authority));

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

    /// End-to-end through the REAL enforcement-authority transport (the `watch` cell the control
    /// runner writes), not a direct field poke: writing `Some(authority)` flips enforcement on so a
    /// mixed batch drops the unsigned/bad peers, and a subsequent `None` (lock disabled) clears
    /// enforcement so a peer DROPPED while enforced is re-admitted. Exercises the exact `borrow`-based
    /// read path `tka_admits` uses — a broken receiver wiring would pass every for_test-field test but
    /// fail here.
    #[tokio::test]
    async fn tka_authority_watch_enables_then_clears_enforcement() {
        let (authority, sig) = authority_and_valid_sig();
        let mut bad_sig = sig.clone();
        let last = bad_sig.len() - 1;
        bad_sig[last] ^= 0xff;

        let (mut tracker, tka_tx) = PeerTracker::for_test(test_env(), None);

        // 1) No authority yet ⇒ admit-all (Go b.tka == nil).
        let good = peer_node("good", NODE_KEY_BYTES, sig.clone());
        let unsigned = peer_node("unsigned", [8u8; 32], vec![]);
        let bad = peer_node("bad", [9u8; 32], bad_sig);
        let batch = ts_control::PeerUpdate::Full(vec![good.clone(), unsigned.clone(), bad.clone()]);
        tracker.apply_peer_update(&batch);
        assert_eq!(tracker.peer_db.peers().len(), 3, "no lock ⇒ admit all");

        // 2) Publish the verified authority over the watch cell (exactly what the control runner does
        //    on a successful sync) ⇒ enforcement ON. A re-applied Full now drops unsigned + bad.
        tka_tx.send_replace(Some(Arc::new(authority)));
        tracker.apply_peer_update(&batch);
        assert_eq!(
            tracker.peer_db.peers().len(),
            1,
            "lock active ⇒ only the signed peer survives"
        );
        assert!(tracker.peer_db.get(&good.node_key).is_some());
        assert!(tracker.peer_db.get(&unsigned.node_key).is_none());
        assert!(tracker.peer_db.get(&bad.node_key).is_none());

        // 3) Lock disabled (None) ⇒ enforcement cleared ⇒ a peer that was DROPPED while enforced is
        //    re-admitted by a fresh netmap. Assert the specific previously-dropped key returns (not
        //    merely a count), so this proves the drop→clear→re-admit transition, not "admit-all-fresh".
        tka_tx.send_replace(None);
        tracker.apply_peer_update(&batch);
        assert_eq!(
            tracker.peer_db.peers().len(),
            3,
            "lock disabled ⇒ admit all again"
        );
        assert!(
            tracker.peer_db.get(&unsigned.node_key).is_some(),
            "the peer dropped under enforcement must come back once the lock is cleared"
        );
        assert!(tracker.peer_db.get(&bad.node_key).is_some());
    }

    /// Degenerate input: two DISTINCT nodes sharing one `stable_id` in a single `Full`, one with a
    /// valid signature and one unsigned, under an active lock. Each node is judged by its OWN verdict
    /// (the per-node `admits` vector), so the unsigned node is never admitted on the strength of its
    /// signed twin. The single-verify `Full` refactor keeps this per-node semantics (a stable_id-set
    /// alone would have admitted whichever node was upserted last). Malformed control input; asserted
    /// only to lock the verdict-per-node behavior against regression.
    #[tokio::test]
    async fn tka_full_duplicate_stable_id_judges_each_node_on_its_own_signature() {
        let (authority, sig) = authority_and_valid_sig();
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), Some(authority));

        // Both carry stable_id "dup"; the signed one authorizes NODE_KEY_BYTES, the other is unsigned
        // and uses a different node key. Order them unsigned-last so a last-writer-wins stable_id set
        // would (wrongly) leave the unsigned node's key in the db.
        let signed = peer_node("dup", NODE_KEY_BYTES, sig);
        let unsigned = peer_node("dup", [8u8; 32], vec![]);
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![
            signed.clone(),
            unsigned.clone(),
        ]));

        // The unsigned node's own verdict failed, so its key must NOT be present, regardless of the
        // shared stable_id. (The signed twin retained the stable_id; the db holds the signed key.)
        assert!(
            tracker.peer_db.get(&unsigned.node_key).is_none(),
            "a node whose own signature fails must not be admitted via a stable_id twin"
        );
        assert!(tracker.peer_db.get(&signed.node_key).is_some());
    }

    /// Full-path consistency under two KEPT nodes sharing a `stable_id`: `peer_db.upsert` is
    /// last-writer-wins on `stable_id`, so the db ends holding exactly one node for that id (the last
    /// kept), and `retain` never evicts that just-upserted id (`retained_ids` contains the shared id
    /// because at least one of its nodes was kept). No lock here, so both nodes are "kept". This pins
    /// the published-state invariant the whole-surface audit flagged: `retain` and the upsert loop
    /// agree on the surviving stable_id. Malformed control input; asserted for robustness.
    #[tokio::test]
    async fn tka_full_duplicate_stable_id_both_kept_is_consistent() {
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), None);
        let first = peer_node("dup", [1u8; 32], vec![]);
        let last = peer_node("dup", [2u8; 32], vec![]);
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![
            first.clone(),
            last.clone(),
        ]));

        // Exactly one db entry for the shared stable_id, holding the LAST node (upsert is
        // last-writer-wins on stable_id); the first node's key was transparently superseded.
        assert_eq!(
            tracker.peer_db.peers().len(),
            1,
            "one entry for the shared stable_id"
        );
        assert!(
            tracker.peer_db.get(&last.node_key).is_some(),
            "the db holds the last-upserted node for the shared id"
        );
        assert!(
            tracker.peer_db.get(&first.node_key).is_none(),
            "the first node's key was superseded by the last at the shared id"
        );
    }

    /// A peer admitted in one `Full`, then in a later `Full` presenting a key that a co-resident
    /// peer's rotation chain has rotated away, is EVICTED — the cross-peer rotation filter applies on
    /// every resync, not only at first admission. Exercises the rotation filter through two
    /// sequential `Full` updates with real signing.
    #[tokio::test]
    async fn tka_full_rotation_obsolete_evicts_on_resync() {
        use ed25519_dalek::SigningKey;
        use ts_tka::NodeKeySignature;

        let trusted = SigningKey::from_bytes(&[42u8; 32]);
        let trusted_pub = trusted.verifying_key().to_bytes().to_vec();
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
        let pivot = SigningKey::from_bytes(&[9u8; 32]);
        let pivot_pub: [u8; 32] = pivot.verifying_key().to_bytes();

        // First Full: the soon-to-be-stale peer presents the pivot key with a valid Direct sig.
        let stale_sig = NodeKeySignature::sign_direct(&pivot_pub, &trusted).serialize();
        let stale_peer = peer_node("stale", pivot_pub, stale_sig);
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), Some(authority));
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![stale_peer.clone()]));
        assert!(
            tracker.peer_db.get(&stale_peer.node_key).is_some(),
            "the stale peer is admitted while no rotation has superseded it yet"
        );

        // Second Full: a freshly-rotated peer (whose chain rotated AWAY the pivot key) joins, and the
        // stale peer is re-included. The rotation filter now obsoletes the pivot key ⇒ stale evicted.
        let new_key = [4u8; 32];
        let new_sig = NodeKeySignature::sign_rotation(&new_key, &trusted, &pivot).serialize();
        let new_peer = peer_node("rotated", new_key, new_sig);
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![
            new_peer.clone(),
            stale_peer.clone(),
        ]));
        assert!(
            tracker.peer_db.get(&new_peer.node_key).is_some(),
            "the freshly-rotated peer is admitted"
        );
        assert!(
            tracker.peer_db.get(&stale_peer.node_key).is_none(),
            "the stale peer is EVICTED on the resync once a rotation supersedes its key"
        );
    }

    /// The empty-trusted-key-state brick-guard: an authority with no keys must NOT drop the whole
    /// netmap (a `ts_tka` invariant violation / replayer edge). A verified chain always carries ≥1
    /// key, so this never weakens a genuine lock — it only prevents a black-hole. Uses ≥2 peers
    /// (one signed, one unsigned) to prove it admits **all**, not accidentally just one.
    #[tokio::test]
    async fn tka_empty_keyset_authority_admits_all() {
        use ts_tka::{AumHash, Authority, State};
        let empty_auth = Authority::from_state(AumHash([0u8; 32]), State { keys: Vec::new() });
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), Some(empty_auth));
        let signed = peer_node("signed", [7u8; 32], vec![0xde, 0xad]);
        let unsigned = peer_node("unsigned", [8u8; 32], vec![]);
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![
            signed.clone(),
            unsigned.clone(),
        ]));
        assert_eq!(
            tracker.peer_db.peers().len(),
            2,
            "an empty-keyset authority must admit ALL peers (brick-guard), not enforce"
        );
    }

    /// Signature-replay / `NodeKeyMismatch`: a structurally-valid signature that authorizes
    /// `NODE_KEY_BYTES` must NOT admit a DIFFERENT node key carrying that same signature blob. This is
    /// the highest-value bypass — if the sig↔node-key binding in `verify_signature` were dropped, this
    /// is the only test that would catch it (the other "bad" peers only flip a byte ⇒ `BadSignature`).
    #[tokio::test]
    async fn tka_active_rejects_valid_sig_for_wrong_node_key() {
        let (authority, sig) = authority_and_valid_sig();
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), Some(authority));

        // The signature authorizes NODE_KEY_BYTES; attach it to an imposter with a different key.
        let imposter = peer_node("imposter", [0x55u8; 32], sig);
        assert!(
            !tracker.tka_admits(&imposter),
            "a signature bound to one node key must not authorize a different node key"
        );
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![imposter.clone()]));
        assert!(tracker.peer_db.get(&imposter.node_key).is_none());
    }

    /// `UntrustedKey`: a signature produced by a well-formed Ed25519 key that is NOT in the
    /// authority's trusted-key state must be rejected — distinct from a tampered-byte `BadSignature`.
    #[tokio::test]
    async fn tka_active_rejects_sig_from_untrusted_key() {
        use ed25519_dalek::{Signer, SigningKey};
        let (authority, _sig) = authority_and_valid_sig();
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), Some(authority));

        // Sign a valid CBOR with a DIFFERENT key (not the one the authority trusts). The key_id in
        // the signature names this untrusted key, so `get_key` misses ⇒ UntrustedKey.
        let rogue = SigningKey::from_bytes(&[99u8; 32]);
        let rogue_pub = rogue.verifying_key().to_bytes().to_vec();
        let preimage = direct_sig_cbor(&NODE_KEY_BYTES, &rogue_pub, None);
        let sig_hash = ts_tka::aum_hash(&preimage).0;
        let signature = rogue.sign(&sig_hash).to_bytes().to_vec();
        let rogue_cbor = direct_sig_cbor(&NODE_KEY_BYTES, &rogue_pub, Some(&signature));

        let peer = peer_node("rogue-signed", NODE_KEY_BYTES, rogue_cbor);
        assert!(
            !tracker.tka_admits(&peer),
            "a signature from a key outside the trusted set must be rejected"
        );
        // Drive the real upsert path too (match the sibling replay test's depth): an untrusted-key
        // signature must keep the peer out of the db, not merely fail the verdict in isolation.
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![peer.clone()]));
        assert!(tracker.peer_db.get(&peer.node_key).is_none());
    }

    /// Bus-enable analogue for `Delta`: enforcement engaged via the watch cell must also gate a
    /// `Delta { upsert }` (not only `Full`). Closes the "authority arrived over the transport AND the
    /// next update is a Delta" combination.
    #[tokio::test]
    async fn tka_watch_enable_enforces_delta_upsert() {
        let (authority, sig) = authority_and_valid_sig();
        let (mut tracker, tka_tx) = PeerTracker::for_test(test_env(), None);
        tka_tx.send_replace(Some(Arc::new(authority)));

        let good = peer_node("good", NODE_KEY_BYTES, sig);
        let unsigned = peer_node("unsigned", [8u8; 32], vec![]);
        tracker.apply_peer_update(&ts_control::PeerUpdate::Delta {
            remove: vec![],
            upsert: vec![good.clone(), unsigned.clone()],
        });
        assert!(tracker.peer_db.get(&good.node_key).is_some());
        assert!(
            tracker.peer_db.get(&unsigned.node_key).is_none(),
            "delta upsert under an active lock must drop the unsigned peer"
        );
    }

    /// A `Delta` re-upsert of an ALREADY-ADMITTED peer whose signature is now invalid must EVICT the
    /// stale entry (revocation-via-delta), not leave it admitted. Go re-filters the whole netmap each
    /// response, so a now-unsigned peer would not survive there either.
    #[tokio::test]
    async fn tka_delta_reupsert_with_invalid_sig_evicts_existing() {
        let (authority, sig) = authority_and_valid_sig();
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), Some(authority));

        // Admit the signed peer.
        let good = peer_node("good", NODE_KEY_BYTES, sig.clone());
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![good.clone()]));
        assert!(tracker.peer_db.get(&good.node_key).is_some());

        // Re-upsert the SAME stable_id (now with no signature) via a delta ⇒ evicted, not retained.
        let revoked = peer_node("good", NODE_KEY_BYTES, vec![]);
        tracker.apply_peer_update(&ts_control::PeerUpdate::Delta {
            remove: vec![],
            upsert: vec![revoked],
        });
        assert!(
            tracker.peer_db.get(&good.node_key).is_none(),
            "a delta re-upsert that fails the lock must evict the previously-admitted peer"
        );
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
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), Some(authority));

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
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), None);

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
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), None);

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
        let (upserts, deletions) = tracker.apply_peer_patches(std::slice::from_ref(&patch));

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

    /// Regression for `tsr-5u0`: when a whole-node set (`Delta`/`Full`) and a patch co-occur in one
    /// response, the patch is applied *on top of* the node the set just upserted — mirroring the
    /// handler's apply-order (peer set first, then `peer_patches`). Before the fix the patch shared
    /// the single `peer_update` slot and the co-occurring set silently dropped it, so a peer brought
    /// in by the delta kept stale (empty) reachability.
    #[tokio::test]
    async fn patch_applies_on_top_of_co_occurring_delta() {
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), None);

        // The whole-node delta upserts a brand-new peer (id == 1) with no reachability.
        let peer = peer_node("mover", [1u8; 32], vec![]);
        let (set_upserts, _) = tracker.apply_peer_update(&ts_control::PeerUpdate::Delta {
            upsert: vec![peer.clone()],
            remove: vec![],
        });
        assert_eq!(set_upserts.len(), 1, "delta upserts the new peer");

        // The patch from the SAME response then sets that peer's endpoints + DERP. This is exactly
        // the consumer order the handler runs (apply_peer_update then apply_peer_patches).
        let new_ep: std::net::SocketAddr = "203.0.113.7:41641".parse().unwrap();
        let patch = ts_control::PeerChange {
            id: 1,
            derp_region: Some(ts_derp::RegionId(core::num::NonZeroU32::new(7).unwrap())),
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
        let (patch_upserts, patch_deletions) =
            tracker.apply_peer_patches(std::slice::from_ref(&patch));

        assert_eq!(
            patch_upserts.len(),
            1,
            "patch re-upserts the just-added peer"
        );
        assert_eq!(patch_deletions.len(), 0);
        // The peer added by the delta now carries the patched reachability — the patch was NOT lost.
        let (_pid, after) = tracker.peer_db.get(&(1 as ts_control::NodeId)).unwrap();
        assert_eq!(after.underlay_addresses, vec![new_ep]);
        assert_eq!(
            after.derp_region,
            Some(ts_derp::RegionId(core::num::NonZeroU32::new(7).unwrap()))
        );
    }

    /// A `Patch` whose node id is not in the current netmap is ignored (the wire contract: a patch
    /// never creates a node). No upsert, no deletion, peer set unchanged.
    #[tokio::test]
    async fn patch_for_unknown_node_is_ignored() {
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), None);
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
        let (upserts, deletions) = tracker.apply_peer_patches(std::slice::from_ref(&patch));

        assert_eq!(upserts.len(), 0);
        assert_eq!(deletions.len(), 0);
        assert_eq!(tracker.peer_db.peers().len(), 1);
        assert!(tracker.peer_db.get(&(999 as ts_control::NodeId)).is_none());
    }

    /// An expiry-only `Patch` updates `node_key_expiry` on the matching peer (Go
    /// `PeerChange.KeyExpiry`), rather than being silently dropped until the next full resync.
    #[tokio::test]
    async fn patch_updates_node_key_expiry() {
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), None);
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
        tracker.apply_peer_patches(std::slice::from_ref(&patch));

        let (_pid, after) = tracker.peer_db.get(&(1 as ts_control::NodeId)).unwrap();
        assert_eq!(after.node_key_expiry, Some(expiry));
    }

    /// Channel B: a `PeerChange.online` patch flips a peer's online state without a full node.
    #[tokio::test]
    async fn patch_updates_online() {
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), None);
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
        tracker.apply_peer_patches(std::slice::from_ref(&patch));
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
        tracker.apply_peer_patches(std::slice::from_ref(&patch));
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

    /// Channel C/D (Go `map.go:updatePeersStateFromResponse`): `online_change` is the sole driver of
    /// `online`; `peer_seen_change` is the sole driver of `last_seen` (true ⇒ now, false ⇒ cleared)
    /// and must NEVER touch `online`. Both apply to a peer already in the netmap and ignore unknown
    /// ids. This pins the fix for the prior bug where channel D wrote `online=false` (conflating
    /// "not seen recently" with "offline" — distinct signals in Go).
    #[tokio::test]
    async fn liveness_change_maps_apply_online() {
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), None);
        let peer = peer_node("p", [1u8; 32], vec![]); // id == 1
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![peer]));
        // A fixed timestamp (chrono is built without its `clock` feature, so no `Utc::now()`).
        let now = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();

        // Channel C: online_change sets online=true.
        let mut online_change = std::collections::BTreeMap::new();
        online_change.insert(1 as ts_control::NodeId, true);
        online_change.insert(999 as ts_control::NodeId, true); // unknown id — ignored
        let changed = tracker.apply_liveness_changes(&online_change, &Default::default(), now);
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

        // Channel D: peer_seen_change=true sets last_seen=now and leaves online UNTOUCHED.
        let mut seen_true = std::collections::BTreeMap::new();
        seen_true.insert(1 as ts_control::NodeId, true);
        let changed = tracker.apply_liveness_changes(&Default::default(), &seen_true, now);
        assert!(changed);
        {
            let (_id, node) = tracker.peer_db.get(&(1 as ts_control::NodeId)).unwrap();
            assert_eq!(
                node.last_seen,
                Some(now),
                "peer_seen_change=true sets last_seen=now"
            );
            assert_eq!(
                node.online,
                Some(true),
                "channel D must NOT touch online (still true from channel C)"
            );
        }

        // Channel D: peer_seen_change=false clears last_seen, still leaving online untouched.
        let mut seen_false = std::collections::BTreeMap::new();
        seen_false.insert(1 as ts_control::NodeId, false);
        let changed = tracker.apply_liveness_changes(&Default::default(), &seen_false, now);
        assert!(changed);
        {
            let (_id, node) = tracker.peer_db.get(&(1 as ts_control::NodeId)).unwrap();
            assert_eq!(
                node.last_seen, None,
                "peer_seen_change=false clears last_seen"
            );
            assert_eq!(node.online, Some(true), "channel D must NOT mark offline");
        }
        assert_eq!(
            tracker.peer_db.peers().len(),
            1,
            "the node is retained, not removed"
        );

        // No-op when nothing matches / changes.
        assert!(!tracker.apply_liveness_changes(&Default::default(), &Default::default(), now));
    }

    /// Security: a `Patch` that rotates the node key must re-satisfy the tailnet-lock authority,
    /// exactly like a `Delta` upsert. A key-rotation patch whose new signature does NOT verify
    /// evicts the peer (fail-closed) rather than leaving a now-unverified entry — closing what would
    /// otherwise be a trust-enforcement bypass via the patch path.
    #[tokio::test]
    async fn patch_key_rotation_failing_tka_evicts_peer() {
        let (authority, sig) = authority_and_valid_sig();
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), Some(authority));

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
        let (upserts, deletions) = tracker.apply_peer_patches(std::slice::from_ref(&patch));

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
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), None);

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

    // ----- tsr-jo1: RotationTracker (Go ipnlocal.rotationTracker.obsoleteKeys) -----

    /// A `RotationDetails` for a `Direct`-rooted chain with the given prior keys + wrapping key.
    fn rot_details(
        prev: &[&[u8]],
        wrapping: &[u8],
        kind: ts_tka::SigKind,
    ) -> ts_tka::RotationDetails {
        ts_tka::RotationDetails {
            prev_node_keys: prev.iter().map(|p| p.to_vec()).collect(),
            initial_sig_kind: kind,
            initial_wrapping_pubkey: wrapping.to_vec(),
        }
    }

    /// Rule 1: every prior node key named by any rotation chain is obsolete, regardless of the
    /// chain's root kind (Go's ungated `obsolete.AddSlice(d.PrevNodeKeys)`).
    #[test]
    fn rotation_tracker_prev_keys_always_obsolete() {
        let mut t = RotationTracker::default();
        // A Direct-rooted chain that rotated away OLD1, and a Credential-rooted one that rotated OLD2.
        t.add(
            b"newA".to_vec(),
            &rot_details(&[b"OLD1"], b"wrapA", ts_tka::SigKind::Direct),
        );
        t.add(
            b"newB".to_vec(),
            &rot_details(&[b"OLD2"], b"wrapB", ts_tka::SigKind::Credential),
        );
        let obsolete = t.obsolete_keys();
        assert!(
            obsolete.contains(b"OLD1".as_slice()),
            "Direct chain's prior key obsolete"
        );
        assert!(
            obsolete.contains(b"OLD2".as_slice()),
            "Credential chain's prior key obsolete too (rule 1 is ungated)"
        );
        // The current keys themselves are not obsolete (only one peer per wrapping key here).
        assert!(!obsolete.contains(b"newA".as_slice()));
        assert!(!obsolete.contains(b"newB".as_slice()));
    }

    /// Rule 2: among `Direct`-rooted chains sharing a wrapping key, only the longest survives; the
    /// shorter (older) clone's key is obsolete.
    #[test]
    fn rotation_tracker_unequal_chain_keeps_longest() {
        let mut t = RotationTracker::default();
        // Same wrapping key; "long" has 2 prior keys, "short" has 1 ⇒ "short" is the older clone.
        t.add(
            b"long".to_vec(),
            &rot_details(&[b"p1", b"p2"], b"wrap", ts_tka::SigKind::Direct),
        );
        t.add(
            b"short".to_vec(),
            &rot_details(&[b"q1"], b"wrap", ts_tka::SigKind::Direct),
        );
        let obsolete = t.obsolete_keys();
        assert!(
            obsolete.contains(b"short".as_slice()),
            "the shorter-chain clone is obsolete"
        );
        assert!(
            !obsolete.contains(b"long".as_slice()),
            "the longest-chain peer survives"
        );
    }

    /// Rule 2 tie: two `Direct`-rooted chains sharing a wrapping key with EQUAL chain length cannot
    /// be disambiguated ⇒ BOTH are dropped (Go's safety branch).
    #[test]
    fn rotation_tracker_equal_chain_drops_both() {
        let mut t = RotationTracker::default();
        t.add(
            b"cloneA".to_vec(),
            &rot_details(&[b"p1"], b"wrap", ts_tka::SigKind::Direct),
        );
        t.add(
            b"cloneB".to_vec(),
            &rot_details(&[b"p2"], b"wrap", ts_tka::SigKind::Direct),
        );
        let obsolete = t.obsolete_keys();
        assert!(
            obsolete.contains(b"cloneA".as_slice()),
            "tied clone A dropped"
        );
        assert!(
            obsolete.contains(b"cloneB".as_slice()),
            "tied clone B dropped"
        );
    }

    /// `Credential`-rooted chains sharing a wrapping key are EXEMPT from rule 2 (reusable-authkey
    /// carve-out): both are kept even with equal chain length.
    #[test]
    fn rotation_tracker_credential_root_clones_both_kept() {
        let mut t = RotationTracker::default();
        t.add(
            b"credA".to_vec(),
            &rot_details(&[b"p1"], b"wrap", ts_tka::SigKind::Credential),
        );
        t.add(
            b"credB".to_vec(),
            &rot_details(&[b"p2"], b"wrap", ts_tka::SigKind::Credential),
        );
        let obsolete = t.obsolete_keys();
        assert!(
            !obsolete.contains(b"credA".as_slice()),
            "credential-rooted clone A kept"
        );
        assert!(
            !obsolete.contains(b"credB".as_slice()),
            "credential-rooted clone B kept"
        );
    }

    /// A peer that another chain already rotated away does not also act as a surviving clone: it is
    /// removed from its wrapping-key group before the longest-survivor pick (Go's `DeleteFunc`).
    #[test]
    fn rotation_tracker_already_obsolete_peer_not_a_survivor() {
        let mut t = RotationTracker::default();
        // "victim" is rotated away by "rotator" (different wrapping key), AND shares wrapping key
        // "w" with "other". Because "victim" is already obsolete, only "other" is in play for "w" and
        // survives (no spurious tie-drop of "other").
        t.add(
            b"rotator".to_vec(),
            &rot_details(&[b"victim"], b"wRot", ts_tka::SigKind::Direct),
        );
        t.add(
            b"victim".to_vec(),
            &rot_details(&[b"x"], b"w", ts_tka::SigKind::Direct),
        );
        t.add(
            b"other".to_vec(),
            &rot_details(&[b"y"], b"w", ts_tka::SigKind::Direct),
        );
        let obsolete = t.obsolete_keys();
        assert!(
            obsolete.contains(b"victim".as_slice()),
            "victim rotated away by rotator"
        );
        assert!(
            !obsolete.contains(b"other".as_slice()),
            "other survives — victim was removed from the group before the tie check"
        );
    }

    /// Empty tracker (no rotation-signed peers) ⇒ no obsolete keys (the non-rotation netmap path).
    #[test]
    fn rotation_tracker_empty_is_noop() {
        let t = RotationTracker::default();
        assert!(t.obsolete_keys().is_empty());
    }

    /// End-to-end through the real `Full` path: a peer presenting a freshly-rotated key (a Rotation
    /// chain) is admitted, while a second peer still presenting the rotated-AWAY pivot key — even with
    /// that key's own still-valid Direct signature — is DROPPED by the cross-peer rotation filter.
    /// This is the gap closed here: Go `tkaFilterNetmapLocked` drops the stale clone; we used to admit
    /// it. Uses real `ts_tka` signing (`sign_direct` + `sign_rotation`) so the whole
    /// verify → details → filter pipeline runs.
    ///
    /// Construction: the trusted key signs an inner `Direct` over the PIVOT keypair's public key; the
    /// pivot key then signs an outer `Rotation` authorizing `new_key`. That chain's `prev_node_keys`
    /// names the pivot pubkey — so a peer presenting the pivot pubkey as its node key is the
    /// rotated-away key the filter must drop.
    #[tokio::test]
    async fn tka_full_drops_rotated_away_key_e2e() {
        use ed25519_dalek::SigningKey;
        use ts_tka::NodeKeySignature;

        let trusted = SigningKey::from_bytes(&[42u8; 32]);
        let trusted_pub = trusted.verifying_key().to_bytes().to_vec();
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

        // The rotation pivot: a keypair whose public key the inner Direct authorizes and whose
        // private key signs the outer rotation wrap. This pivot pubkey IS the key being rotated away.
        let pivot = SigningKey::from_bytes(&[9u8; 32]);
        let pivot_pub: [u8; 32] = pivot.verifying_key().to_bytes();

        let new_key = [4u8; 32]; // the freshly-rotated node key

        // Fresh peer: a Rotation chain authorizing `new_key`, inner Direct over the pivot signed by
        // trusted, outer wrap signed by the pivot. Its prev_node_keys names `pivot_pub`.
        let new_sig = NodeKeySignature::sign_rotation(&new_key, &trusted, &pivot).serialize();
        let new_peer = peer_node("rotated", new_key, new_sig);

        // Stale peer: still presents the pivot pubkey (the rotated-away key) with its own valid
        // Direct signature — valid in isolation, but obsoleted by the fresh peer's rotation chain.
        let stale_sig = NodeKeySignature::sign_direct(&pivot_pub, &trusted).serialize();
        let stale_peer = peer_node("stale", pivot_pub, stale_sig);

        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), Some(authority));
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![
            new_peer.clone(),
            stale_peer.clone(),
        ]));

        assert!(
            tracker.peer_db.get(&new_peer.node_key).is_some(),
            "the freshly-rotated peer is admitted"
        );
        assert!(
            tracker.peer_db.get(&stale_peer.node_key).is_none(),
            "the peer presenting the rotated-away key is dropped (Go tkaFilterNetmapLocked)"
        );
    }
}
