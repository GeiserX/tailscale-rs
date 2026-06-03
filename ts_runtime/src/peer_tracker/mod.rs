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
                    let peer_id = self.peer_db.upsert(node);
                    upserts.insert(peer_id);
                }
            }

            ts_control::PeerUpdate::Delta { remove, upsert } => {
                tracing::trace!("delta peer update");

                for peer in upsert {
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
