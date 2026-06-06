//! Peer delta update tracking.

use std::{collections::HashSet, net::IpAddr, sync::Arc};

use kameo::{
    actor::ActorRef,
    message::{Context, Message},
    reply::ReplySender,
};
use tokio::sync::watch;
use ts_control::Node;
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
        self.peer_by_tailnet_ip_opt(ip)
            .cloned()
            .map(crate::status::WhoIs::from_node)
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
        let Some(peer_update) = &msg.peer_update else {
            return;
        };

        let mut upserts = HashSet::default();
        let mut deletions = HashSet::default();

        match peer_update {
            ts_control::PeerUpdate::Full(new_nodes) => {
                tracing::trace!("full peer update");

                let new_ids = new_nodes
                    .iter()
                    .map(|x| &x.stable_id)
                    .collect::<HashSet<_>>();

                self.peer_db.retain(|id, peer| {
                    let retain = new_ids.contains(&peer.stable_id);

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

impl PeerTracker {
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
}
