//! Route reconciliation: turns peer/control state into the overlay+underlay route tables.
//!
//! [`RouteUpdater`] resolves the exit-node selector against the live peer set, builds the outbound
//! cryptokey-routing table and the DERP/direct underlay map, splits inbound self-routes between the
//! application and forwarder netstacks, and republishes on every peer/control update plus a periodic
//! recompute that upgrades/downgrades peers as direct paths come and go.
//!
//! Fail-closed: a peer is routed direct only while it holds a live confirmed path (else DERP), and
//! a stale/typo'd exit-node selector grants no `/0` (internet-bound traffic is dropped, not leaked).

use core::time::Duration;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use kameo::{
    actor::ActorRef,
    message::{Context, Message},
};
use tokio::sync::watch;
use ts_bart::RoutingTable;
use ts_overlay_router::{
    inbound::RouteAction as InboundRouteAction, outbound::RouteAction as OutboundRouteAction,
};
use ts_transport::{OverlayTransportId, PeerId, UnderlayTransportId};

use crate::{
    Error,
    direct::{self, DirectManager},
    env::Env,
    multiderp,
    multiderp::Multiderp,
    peer_tracker::PeerState,
};

/// How often to recompute routes to re-evaluate direct-path availability.
///
/// Direct paths are confirmed/expired asynchronously by the disco machinery, so we poll on
/// this interval to upgrade peers onto a freshly-confirmed direct path and (critically)
/// downgrade them back to DERP the moment a path's trust lapses. Matched to the disco pinger
/// interval; `TRUST_DURATION` (6s) is the actual bound on staleness.
const RECOMPUTE_INTERVAL: Duration = Duration::from_secs(2);

pub struct RouteUpdater {
    multiderp: ActorRef<Multiderp>,
    direct: ActorRef<DirectManager>,
    /// The direct underlay transport id, fetched once at startup. It is fixed for the life of the
    /// `DirectManager`, so caching it avoids a second `ask` (and its TOCTOU) on every recompute.
    /// `None` only if the direct manager was unreachable at startup — in which case we never route
    /// direct (fail-closed to DERP).
    direct_tid: Option<UnderlayTransportId>,
    default_overlay_transport: OverlayTransportId,
    /// The forwarder netstack's overlay transport. Inbound packets for advertised subnet routes /
    /// the exit-node default route are delivered here (the any-IP forwarder netstack), while the
    /// node's own tailnet addresses go to [`default_overlay_transport`](Self::default_overlay_transport)
    /// (the application netstack). The split is by [`Node::is_subnet_route`](ts_control::Node::is_subnet_route),
    /// not prefix-equality, so it doesn't depend on control echoing advertised prefixes verbatim.
    forwarder_overlay_transport: OverlayTransportId,
    env: Env,
    /// The most recent peer state, cached so periodic recomputes can re-evaluate direct paths
    /// without waiting for a new control update.
    last_peer_state: Option<Arc<PeerState>>,
    /// The underlay map we last published, so a periodic recompute that produces no change can
    /// skip republishing.
    last_underlay: HashMap<PeerId, UnderlayTransportId>,
    /// The stable id of the exit node we last published via [`ActiveExitNode`], so an unchanged
    /// recompute doesn't republish it. `None` means we last published "no exit node".
    last_exit_node_id: Option<ts_control::StableNodeId>,
    /// Live cell mirroring the *active* (resolved + fail-closed) exit node's stable id for
    /// [`Runtime::status`](crate::Runtime::status). The route updater is the single authoritative
    /// resolver of [`Env::exit_node`](crate::env::Env::exit_node) against the live peer set, so it is
    /// the only correct source of "which exit node is engaged right now"; `Status` reads this rather
    /// than re-resolving (which would miss the `/0`-advertised fail-closed gate). `None` whenever no
    /// exit node is configured, the selector matches no peer, or the matched peer advertises no
    /// default route.
    active_exit_tx: watch::Sender<Option<ts_control::StableNodeId>>,
}

/// Self-message asking the route updater to recompute routes from cached state.
#[derive(Clone)]
struct RecomputeRoutes;

impl kameo::Actor for RouteUpdater {
    type Args = (
        ActorRef<Multiderp>,
        ActorRef<DirectManager>,
        Env,
        OverlayTransportId,
        OverlayTransportId,
        watch::Sender<Option<ts_control::StableNodeId>>,
    );
    type Error = Error;

    async fn on_start(
        (multiderp, direct, env, default_transport, forwarder_transport, active_exit_tx): Self::Args,
        actor_ref: ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        env.subscribe::<Arc<PeerState>>(&actor_ref).await?;
        env.subscribe::<Arc<ts_control::StateUpdate>>(&actor_ref)
            .await?;

        // The direct transport id is fixed once the direct manager has started; fetch it once.
        // On failure we leave it None and stay DERP-only (fail-closed) rather than retrying.
        let direct_tid = match direct.ask(direct::DirectTransportId).await {
            Ok(tid) => tid,
            Err(e) => {
                tracing::error!(error = %e, "direct transport id unavailable at startup, staying on derp");
                None
            }
        };

        // Periodically poke ourselves to re-evaluate direct-path availability. Holds a weak
        // ref so the loop exits once the actor is gone.
        let weak = actor_ref.downgrade();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(RECOMPUTE_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let Some(aref) = weak.upgrade() else {
                    break;
                };
                if aref.tell(RecomputeRoutes).await.is_err() {
                    break;
                }
            }
        });

        Ok(Self {
            multiderp,
            direct,
            direct_tid,
            default_overlay_transport: default_transport,
            forwarder_overlay_transport: forwarder_transport,
            env,
            last_peer_state: None,
            last_underlay: HashMap::default(),
            last_exit_node_id: None,
            active_exit_tx,
        })
    }
}

#[derive(Clone)]
pub struct SelfRouteUpdate {
    pub overlay_in_routes: Arc<ts_bart::Table<InboundRouteAction>>,
}

/// The peer currently selected and resolved as this node's exit node, republished whenever it
/// changes.
///
/// The route updater is the single place that resolves [`Env::exit_node`](crate::env::Env::exit_node)
/// against the live peer set (it also installs the matching peer's default route and warns on a
/// stale/typo'd selector), so it is the authoritative source of "which peer is the exit node right
/// now". The MagicDNS responder subscribes to this to delegate recursive DNS to the exit node's
/// peerAPI DoH server ([`Node::peerapi_doh_url`](ts_control::Node::peerapi_doh_url)); resolving the
/// selector here rather than re-resolving it in the responder keeps a single deterministic answer.
///
/// `node` is `None` when no exit node is configured, the selector matches no peer, or the matched
/// peer advertises no default route (all fail-closed: no DoH delegation, recursion stays local).
#[derive(Clone)]
pub struct ActiveExitNode {
    pub node: Option<Arc<ts_control::Node>>,
}

#[derive(Clone)]
pub struct PeerRouteUpdate {
    pub inner: Arc<PeerRoutesInner>,
}

pub struct PeerRoutesInner {
    pub underlay_routes: HashMap<PeerId, UnderlayTransportId>,
    pub overlay_out_routes: ts_bart::Table<OutboundRouteAction>,
}

/// Overlay confirmed direct paths on top of a DERP-derived underlay map.
///
/// Every peer in `direct_ready` is (re)pointed at the direct transport; peers absent from
/// `direct_ready` keep whatever DERP route `derp_underlay` already gave them. This is the
/// fail-closed upgrade/downgrade: a peer is routed direct *only* while it has a live confirmed
/// path, and falls back to DERP the instant it drops out of `direct_ready`.
fn overlay_direct(
    mut derp_underlay: HashMap<PeerId, UnderlayTransportId>,
    direct_ready: &HashSet<PeerId>,
    direct_tid: UnderlayTransportId,
) -> HashMap<PeerId, UnderlayTransportId> {
    for id in direct_ready {
        derp_underlay.insert(*id, direct_tid);
    }
    derp_underlay
}

impl RouteUpdater {
    /// Rebuild and (conditionally) publish the peer route update from cached peer state.
    ///
    /// `force` republishes even if the underlay map is unchanged — used when peer state itself
    /// changed (so overlay routes may differ). Periodic recomputes pass `force = false` and
    /// only republish when the direct overlay actually flipped.
    async fn rebuild_and_publish(&mut self, force: bool) {
        let Some(state) = self.last_peer_state.clone() else {
            return;
        };

        let mut overlay_out = ts_bart::Table::default();
        let mut derp_underlay = HashMap::default();
        let mut peer_ids = Vec::new();

        // Resolve the exit-node selector against the live peer set once per rebuild. The source
        // filter resolves the same selector the same (deterministic) way, so both agree on the
        // chosen peer — the cryptokey-routing coupling the comment below depends on.
        // Snapshot the live exit-node selector once per rebuild (it can change at runtime via
        // `Device::set_exit_node`); use this single value for resolution + the satisfied check + the
        // trace below so they can't disagree within one rebuild. Across a back-to-back runtime
        // switch this actor and the source filter may briefly read different selector values (each
        // reads the cell when it processes the re-broadcast `PeerState`), but both converge on the
        // next queued message and both only ever resolve to a validly-selected exit — the anti-leak
        // coupling never admits a non-exit peer.
        let exit_node_selector = self.env.exit_node();
        let exit_node_id = exit_node_selector
            .as_ref()
            .and_then(|sel| sel.resolve(state.peers.peers().values()));
        // Whether the configured exit node (if any) was matched to a peer that actually advertises
        // a default route. Stays false on a typo'd/stale selector or a peer that dropped its `/0`,
        // which is fail-closed (internet-bound traffic is dropped) but otherwise silent — we warn
        // below so the black-hole is diagnosable in the field.
        let mut exit_node_satisfied = exit_node_selector.is_none();

        for (id, peer) in state.peers.peers() {
            peer_ids.push(*id);

            let span = tracing::trace_span!(
                "peer_update",
                peer_key = %peer.node_key,
                region = ?peer.derp_region,
                peer_id = ?id,
            );

            // Outbound peer-selection. This MUST use the same filtered set as the inbound source
            // filter in `src_filter.rs` (both call `Node::routes_to_install` with the same
            // `env.accept_routes` and the exit node resolved from `env.exit_node`), so a peer can
            // only source traffic from the exact subnets we route to it. Don't change the filter
            // here without changing it there.
            for route in peer.routes_to_install(self.env.accept_routes, exit_node_id.as_ref()) {
                if route.prefix_len() == 0 {
                    exit_node_satisfied = true;
                }
                overlay_out.insert(*route, OutboundRouteAction::Wireguard(*id));
            }

            let Some(region) = peer.derp_region else {
                tracing::trace!(parent: &span, "peer has no derp region");
                continue;
            };

            match self
                .multiderp
                .ask(multiderp::TransportIdForRegion { id: region })
                .await
            {
                Ok(Some(transport_id)) => {
                    derp_underlay.insert(*id, transport_id);
                }
                Ok(None) => {
                    tracing::error!(parent: &span, "no region stored in multiderp, no underlay route");
                }
                Err(e) => {
                    tracing::error!(error = %e, "multiderp unavailable");
                }
            }
        }

        if !exit_node_satisfied {
            // An exit node is configured but no peer matched the selector (or the matched peer
            // advertises no default route). Egress is fail-closed (internet-bound traffic dropped),
            // not leaked — surface it so the operator can spot a stale/typo'd exit-node selection.
            tracing::warn!(
                exit_node = ?exit_node_selector,
                resolved = ?exit_node_id,
                "configured exit node not found among peers (or it advertises no default route); \
                 internet-bound traffic will be dropped"
            );
        }

        // Republish the active exit node for the MagicDNS responder's DoH delegation. Only an exit
        // node that was actually satisfied (matched a peer advertising a default route) is eligible;
        // a stale/typo'd selector publishes `None` so recursion stays local (fail-closed, no leak).
        let active_exit_id = exit_node_satisfied.then(|| exit_node_id.clone()).flatten();
        if active_exit_id != self.last_exit_node_id {
            self.last_exit_node_id = active_exit_id.clone();
            // Mirror the resolved id into the watch cell `Runtime::status` reads. `send_replace`
            // keeps the value current even with no active borrowers (the receiver lives on the
            // Runtime for the whole session).
            self.active_exit_tx.send_replace(active_exit_id.clone());
            let node = active_exit_id.and_then(|id| {
                state
                    .peers
                    .peers()
                    .values()
                    .find(|peer| peer.stable_id == id)
                    .cloned()
                    .map(Arc::new)
            });
            if let Err(e) = self.env.publish(ActiveExitNode { node }).await {
                tracing::error!(error = %e, "publishing active exit node");
            }
        }

        // Query the direct manager for which peers have a live confirmed direct path and the
        // id of the direct transport to point them at. On any failure we fall back to the
        // DERP-only map (fail-closed: never route direct without a confirmed path).
        let direct_ready = match self
            .direct
            .ask(direct::PeersWithDirectPath { ids: peer_ids })
            .await
        {
            Ok(ready) => ready,
            Err(e) => {
                tracing::error!(error = %e, "direct manager unavailable, staying on derp");
                HashSet::new()
            }
        };

        let underlay_out = match self.direct_tid {
            Some(direct_tid) if !direct_ready.is_empty() => {
                overlay_direct(derp_underlay, &direct_ready, direct_tid)
            }
            _ => derp_underlay,
        };

        if !force && underlay_out == self.last_underlay {
            tracing::trace!("routes unchanged, skipping republish");
            return;
        }

        self.last_underlay = underlay_out.clone();

        if let Err(e) = self
            .env
            .publish(PeerRouteUpdate {
                inner: Arc::new(PeerRoutesInner {
                    underlay_routes: underlay_out,
                    overlay_out_routes: overlay_out,
                }),
            })
            .await
        {
            tracing::error!(error = %e, "publishing peer route update");
        }
    }
}

impl Message<Arc<PeerState>> for RouteUpdater {
    type Reply = ();

    async fn handle(&mut self, msg: Arc<PeerState>, _ctx: &mut Context<Self, Self::Reply>) {
        tracing::trace!(
            n_peers = msg.peers.peers().len(),
            "reconstructing routes for peer update"
        );

        self.last_peer_state = Some(msg);
        self.rebuild_and_publish(true).await;
    }
}

impl Message<RecomputeRoutes> for RouteUpdater {
    type Reply = ();

    async fn handle(&mut self, _msg: RecomputeRoutes, _ctx: &mut Context<Self, Self::Reply>) {
        self.rebuild_and_publish(false).await;
    }
}

/// Build the inbound self-route table, splitting each accepted route between the application
/// netstack and the any-IP forwarder netstack.
///
/// The node's own tailnet host addresses ([`Node::is_subnet_route`] == `false`) terminate in the
/// application netstack (`app_transport`); advertised subnet routes and the exit-node default
/// route (`is_subnet_route` == `true`) are delivered to the forwarder netstack
/// (`forwarder_transport`), which splices them to real OS sockets. Splitting on `is_subnet_route`
/// (the same Go-mirroring predicate `nmcfg.go` uses) rather than matching the advertised prefix set
/// by equality keeps the split independent of how control echoes prefixes back to us.
fn split_inbound_routes(
    node: &ts_control::Node,
    app_transport: OverlayTransportId,
    forwarder_transport: OverlayTransportId,
) -> ts_bart::Table<InboundRouteAction> {
    let mut out = ts_bart::Table::default();

    for &accepted_route in &node.accepted_routes {
        let transport = if node.is_subnet_route(&accepted_route) {
            forwarder_transport
        } else {
            app_transport
        };

        out.insert(accepted_route, InboundRouteAction::ToOverlay(transport));
    }

    out
}

impl Message<Arc<ts_control::StateUpdate>> for RouteUpdater {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: Arc<ts_control::StateUpdate>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        let Some(node) = msg.node.as_ref() else {
            return;
        };

        tracing::debug!(accepted_routes = ?node.accepted_routes, "populating accepted routes");

        let out = split_inbound_routes(
            node,
            self.default_overlay_transport,
            self.forwarder_overlay_transport,
        );

        if let Err(e) = self
            .env
            .publish(SelfRouteUpdate {
                overlay_in_routes: Arc::new(out),
            })
            .await
        {
            tracing::error!(error = %e, "publishing self route update");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_ready_peers_are_upgraded_others_keep_derp() {
        let derp_a = UnderlayTransportId(1);
        let derp_b = UnderlayTransportId(2);
        let direct_tid = UnderlayTransportId(99);

        let peer_a = PeerId(10);
        let peer_b = PeerId(20);
        let peer_c = PeerId(30); // direct-ready but had no derp route

        let mut derp_underlay = HashMap::new();
        derp_underlay.insert(peer_a, derp_a);
        derp_underlay.insert(peer_b, derp_b);

        // a and c are direct-ready; b is not.
        let ready: HashSet<PeerId> = [peer_a, peer_c].into_iter().collect();

        let out = overlay_direct(derp_underlay, &ready, direct_tid);

        assert_eq!(out.get(&peer_a), Some(&direct_tid), "a upgraded to direct");
        assert_eq!(out.get(&peer_b), Some(&derp_b), "b stays on derp");
        assert_eq!(
            out.get(&peer_c),
            Some(&direct_tid),
            "c routed direct even with no derp route"
        );
    }

    /// A subnet-router node: own host /32 + /128, plus an advertised subnet and the exit-node
    /// default route. The split must send host addresses to the app netstack and the
    /// subnet/default routes to the forwarder netstack.
    fn split_router_node() -> ts_control::Node {
        use ts_control::{Node, StableNodeId, TailnetAddress};
        Node {
            id: 1,
            stable_id: StableNodeId("n1".to_string()),
            hostname: "router".to_string(),
            user_id: 0,
            tailnet: Some("ts.net".to_string()),
            tags: vec![],
            tailnet_address: TailnetAddress {
                ipv4: "100.64.0.7/32".parse().unwrap(),
                ipv6: "fd7a::7/128".parse().unwrap(),
            },
            node_key: [0u8; 32].into(),
            node_key_expiry: None,
            key_signature: vec![],
            machine_key: None,
            disco_key: None,
            accepted_routes: vec![
                "100.64.0.7/32".parse().unwrap(),
                "fd7a::7/128".parse().unwrap(),
                "192.168.1.0/24".parse().unwrap(),
                "0.0.0.0/0".parse().unwrap(),
            ],
            underlay_addresses: vec![],
            derp_region: None,
            cap: Default::default(),
            cap_map: Default::default(),
            peerapi_port: None,
            peerapi_dns_proxy: false,
            is_wireguard_only: false,
            exit_node_dns_resolvers: vec![],
            peer_relay: false,
            service_vips: Default::default(),
        }
    }

    fn routed_transport(
        table: &ts_bart::Table<InboundRouteAction>,
        ip: &str,
    ) -> Option<OverlayTransportId> {
        match table.lookup(ip.parse().unwrap()) {
            Some(InboundRouteAction::ToOverlay(id)) => Some(*id),
            _ => None,
        }
    }

    #[test]
    fn inbound_split_sends_subnets_to_forwarder_and_host_addrs_to_app() {
        let app = OverlayTransportId(0);
        let fwd = OverlayTransportId(1);
        let node = split_router_node();

        let table = split_inbound_routes(&node, app, fwd);

        // Own tailnet host addresses terminate in the application netstack.
        assert_eq!(routed_transport(&table, "100.64.0.7"), Some(app));
        assert_eq!(routed_transport(&table, "fd7a::7"), Some(app));

        // Advertised subnet route -> forwarder netstack (any-IP, dials real sockets).
        assert_eq!(routed_transport(&table, "192.168.1.5"), Some(fwd));

        // Exit-node default route -> forwarder netstack. (DirectDialer structurally refuses the
        // egress, so this is leak-free until an exit-capable dialer is explicitly wired.)
        assert_eq!(routed_transport(&table, "8.8.8.8"), Some(fwd));
    }

    #[test]
    fn empty_ready_set_is_pure_derp() {
        let derp_a = UnderlayTransportId(1);
        let peer_a = PeerId(10);

        let mut derp_underlay = HashMap::new();
        derp_underlay.insert(peer_a, derp_a);

        let out = overlay_direct(
            derp_underlay.clone(),
            &HashSet::new(),
            UnderlayTransportId(99),
        );

        assert_eq!(
            out, derp_underlay,
            "no direct-ready peers => unchanged derp map"
        );
    }
}
