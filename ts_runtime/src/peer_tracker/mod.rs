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

        let Some(peer_update) = &msg.peer_update else {
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
                tracing::trace!("patch peer update");

                for patch in patches {
                    // Go semantic (`tailcfg.PeerChange`): a patch for a node not in the current
                    // netmap is ignored, NOT inserted. Look the peer up by its control node id; if
                    // unknown, drop the patch (fail-closed — never guess a peer into existence).
                    let Some((_id, existing)) = self.peer_db.get(&patch.node_id) else {
                        tracing::debug!(
                            control_node_id = patch.node_id,
                            "ignoring peer patch for unknown node"
                        );
                        continue;
                    };

                    // Merge: start from the existing peer and overwrite only the fields the patch
                    // carries (each `Some`). Absent (`None`) fields are left untouched, so an
                    // all-`None` patch is a no-op rather than clobbering state.
                    let mut merged = existing.clone();
                    apply_patch(&mut merged, patch);

                    // Re-validate through the SAME tailnet-lock chokepoint as the `Full`/`Delta`
                    // upsert sites. This matters when the patch changes the node key: the merged
                    // node must still be authorized (a new key with no matching signature, or a
                    // signature the authority rejects, is refused). On rejection we skip the upsert,
                    // leaving the prior (already-admitted) entry intact — identical to how a `Delta`
                    // upsert of a rejected peer is dropped without disturbing existing state.
                    if !self.tka_admits(&merged) {
                        continue; // fail-CLOSED
                    }

                    let id = self.peer_db.upsert(&merged);
                    upserts.insert(id);
                }
            }
        }

        (upserts, deletions)
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

/// Apply a [`PeerPatch`](ts_control::PeerPatch) onto an existing [`Node`] in place, overwriting only
/// the fields the patch carries (`Some`) and leaving every absent (`None`) field untouched.
///
/// The patch's `node_id` is the lookup key, not a mutated field, so it is not copied here. The wire
/// `online`/`last_seen` fields are intentionally absent from [`PeerPatch`] — the domain [`Node`] has
/// no field for either — so there is nothing to merge for them. Reachability-governing fields
/// (`endpoints` → [`Node::underlay_addresses`], `derp_region`) are updated so an idle peer that
/// moved endpoints/DERP can be re-reached on the next [`PeerState`] publish.
fn apply_patch(node: &mut Node, patch: &ts_control::PeerPatch) {
    if let Some(endpoints) = &patch.endpoints {
        node.underlay_addresses = endpoints.clone();
    }
    if let Some(derp_region) = patch.derp_region {
        node.derp_region = Some(derp_region);
    }
    if let Some(key) = patch.key {
        node.node_key = key;
    }
    if let Some(key_signature) = &patch.key_signature {
        node.key_signature = key_signature.clone();
    }
    if let Some(disco_key) = patch.disco_key {
        node.disco_key = Some(disco_key);
    }
    if let Some(key_expiry) = patch.key_expiry {
        node.node_key_expiry = Some(key_expiry);
    }
    if let Some(cap) = patch.cap {
        node.cap = cap;
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

    // ---------------------------------------------------------------------------------------------
    // `PeerUpdate::Patch` (incremental peer "patch" updates, `MapResponse.PeersChangedPatch`).
    //
    // These drive real `PeerUpdate::Patch`es through the shared `apply_peer_update` handler and
    // assert the field-level merge, the unknown-node-ignore (Go semantic), no-op behavior, and that
    // a node-key change goes through the same tailnet-lock validation the upsert sites enforce. This
    // is the regression coverage for the dropped-patch bug that wedged idle sessions.
    // ---------------------------------------------------------------------------------------------

    /// Build an empty [`ts_control::PeerPatch`] for `node_id` with all optional fields `None`.
    fn empty_patch(node_id: ts_control::NodeId) -> ts_control::PeerPatch {
        ts_control::PeerPatch {
            node_id,
            derp_region: None,
            endpoints: None,
            key: None,
            key_signature: None,
            disco_key: None,
            key_expiry: None,
            cap: None,
        }
    }

    #[tokio::test]
    async fn patch_updates_endpoints_and_derp_on_known_peer() {
        // A patch for a KNOWN peer updates its endpoints + home DERP region; every other field is
        // left exactly as it was. This is the reachability fix: an idle peer whose endpoints/region
        // changed must be re-reachable after the patch is applied.
        let mut tracker = PeerTracker::for_test(test_env(), None);

        // `peer_node` assigns control id 1; seed it, capturing the untouched fields.
        let peer = peer_node("p", NODE_KEY_BYTES, vec![]);
        let original_node_key = peer.node_key;
        let original_addr = peer.tailnet_address.clone();
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![peer.clone()]));

        let new_endpoints: Vec<std::net::SocketAddr> = vec![
            "84.54.25.89:5175".parse().unwrap(),
            "10.0.0.2:41641".parse().unwrap(),
        ];
        let new_region = ts_derp::RegionId(std::num::NonZeroU32::new(7).unwrap());

        let patch = ts_control::PeerPatch {
            node_id: 1,
            derp_region: Some(new_region),
            endpoints: Some(new_endpoints.clone()),
            ..empty_patch(1)
        };
        tracker.apply_peer_update(&ts_control::PeerUpdate::Patch(vec![patch]));

        // Still exactly one peer (merge, not insert).
        assert_eq!(tracker.peer_db.peers().len(), 1);
        let (_id, merged) = tracker
            .peer_db
            .get(&original_node_key)
            .expect("peer still present");

        // Reachability fields updated.
        assert_eq!(merged.underlay_addresses, new_endpoints);
        assert_eq!(merged.derp_region, Some(new_region));
        // Untouched fields preserved.
        assert_eq!(merged.node_key, original_node_key);
        assert_eq!(merged.tailnet_address, original_addr);
        assert_eq!(merged.hostname, "p");
    }

    #[tokio::test]
    async fn patch_for_unknown_node_is_ignored() {
        // Go semantic: a patch whose `node_id` is not in the current netmap is IGNORED, never
        // inserted. The peer db must stay byte-for-byte unchanged.
        let mut tracker = PeerTracker::for_test(test_env(), None);

        let peer = peer_node("known", NODE_KEY_BYTES, vec![]); // control id 1
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![peer.clone()]));
        assert_eq!(tracker.peer_db.peers().len(), 1);

        // A patch for an unrelated control id 999.
        let patch = ts_control::PeerPatch {
            node_id: 999,
            endpoints: Some(vec!["203.0.113.7:5000".parse().unwrap()]),
            ..empty_patch(999)
        };
        let (upserts, deletions) =
            tracker.apply_peer_update(&ts_control::PeerUpdate::Patch(vec![patch]));

        // Nothing inserted, nothing touched.
        assert!(upserts.is_empty());
        assert!(deletions.is_empty());
        assert_eq!(tracker.peer_db.peers().len(), 1);
        let (_id, unchanged) = tracker
            .peer_db
            .get(&peer.node_key)
            .expect("known peer intact");
        assert_eq!(unchanged.underlay_addresses, peer.underlay_addresses);
    }

    #[tokio::test]
    async fn patch_all_none_is_a_noop() {
        // A patch carrying no changed fields (all `None`) must not clobber any existing field.
        let mut tracker = PeerTracker::for_test(test_env(), None);

        let mut peer = peer_node("p", NODE_KEY_BYTES, vec![0xab, 0xcd]); // control id 1
        peer.underlay_addresses = vec!["198.51.100.4:5555".parse().unwrap()];
        peer.derp_region = Some(ts_derp::RegionId(std::num::NonZeroU32::new(3).unwrap()));
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![peer.clone()]));

        tracker.apply_peer_update(&ts_control::PeerUpdate::Patch(vec![empty_patch(1)]));

        let (_id, after) = tracker.peer_db.get(&peer.node_key).expect("peer present");
        // Every field the patch could have touched is unchanged.
        assert_eq!(after.underlay_addresses, peer.underlay_addresses);
        assert_eq!(after.derp_region, peer.derp_region);
        assert_eq!(after.node_key, peer.node_key);
        assert_eq!(after.key_signature, peer.key_signature);
        assert_eq!(after.node_key_expiry, peer.node_key_expiry);
    }

    #[tokio::test]
    async fn patch_changing_key_revalidates_under_tka() {
        // Under an active authority, a patch that rotates the node key to NODE_KEY_BYTES but carries
        // the matching valid signature is admitted (same validation the upsert sites run); a patch
        // that rotates the key WITHOUT a matching signature is rejected fail-closed, leaving the
        // prior entry intact.
        let (authority, sig) = authority_and_valid_sig();
        let mut tracker = PeerTracker::for_test(test_env(), Some(authority));

        // Seed an authorized peer (control id 1) carrying NODE_KEY_BYTES + its valid signature.
        let seed = peer_node("p", NODE_KEY_BYTES, sig.clone());
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![seed.clone()]));
        assert_eq!(tracker.peer_db.peers().len(), 1);

        // Rejected: rotate to a DIFFERENT key with no matching signature. The merged node fails the
        // gate (the old signature does not authorize the new key) → skipped, prior entry intact.
        let bad_key: ts_keys::NodePublicKey = [123u8; 32].into();
        let reject_patch = ts_control::PeerPatch {
            node_id: 1,
            key: Some(bad_key),
            ..empty_patch(1)
        };
        let (upserts, _del) =
            tracker.apply_peer_update(&ts_control::PeerUpdate::Patch(vec![reject_patch]));
        assert!(
            upserts.is_empty(),
            "key change with no valid signature must be rejected"
        );
        // The original authorized key is still the one in the db (not rotated to the bad key).
        assert!(tracker.peer_db.get(&seed.node_key).is_some());
        assert!(tracker.peer_db.get(&bad_key).is_none());

        // Admitted: a no-op-key patch (the key already matches) that only updates endpoints passes
        // the gate (the existing valid signature still authorizes NODE_KEY_BYTES).
        let ok_patch = ts_control::PeerPatch {
            node_id: 1,
            endpoints: Some(vec!["192.0.2.10:5000".parse().unwrap()]),
            ..empty_patch(1)
        };
        let (upserts, _del) =
            tracker.apply_peer_update(&ts_control::PeerUpdate::Patch(vec![ok_patch]));
        assert_eq!(upserts.len(), 1);
        let (_id, merged) = tracker.peer_db.get(&seed.node_key).expect("peer present");
        assert_eq!(
            merged.underlay_addresses,
            vec!["192.0.2.10:5000".parse::<std::net::SocketAddr>().unwrap()]
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
