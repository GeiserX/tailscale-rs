use std::sync::Arc;

use kameo::{
    actor::ActorRef,
    message::{Context, Message},
};
use ts_bart::{RoutingTable, Table};
use ts_transport::PeerId;

use crate::{Error, env::Env, peer_tracker::PeerState};

pub struct SourceFilterUpdater {
    env: Env,
}

impl kameo::Actor for SourceFilterUpdater {
    type Args = Env;
    type Error = Error;

    async fn on_start(env: Self::Args, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        env.subscribe::<Arc<PeerState>>(&slf).await?;

        Ok(Self { env })
    }
}

#[derive(Clone)]
pub struct SourceFilterState(pub Arc<Table<PeerId>>);

impl Message<Arc<PeerState>> for SourceFilterUpdater {
    type Reply = ();

    async fn handle(
        &mut self,
        state_update: Arc<PeerState>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        let mut src_filter = Table::default();

        // Resolve the exit-node selector against the live peer set once. The route updater resolves
        // the same selector the same (deterministic) way, so both agree on the chosen peer — the
        // cryptokey-routing coupling the comment below depends on.
        let exit_node_id = self
            .env
            .exit_node
            .as_ref()
            .and_then(|sel| sel.resolve(state_update.peers.peers().values()));

        for (id, node) in state_update.peers.peers() {
            // Inbound source validation. This MUST use the same filtered set as the outbound
            // route table in `route_updater.rs` (both call `Node::routes_to_install` with the same
            // `env.accept_routes` and the exit node resolved from `env.exit_node`), so a peer can
            // only source traffic from the exact subnets we route to it. Don't change the filter
            // here without changing it there.
            for route in node.routes_to_install(self.env.accept_routes, exit_node_id.as_ref()) {
                src_filter.insert(route.to_owned(), *id);
            }
        }

        tracing::trace!(updated_source_filter = ?src_filter);

        if let Err(e) = self
            .env
            .publish(SourceFilterState(Arc::new(src_filter)))
            .await
        {
            tracing::error!(error = %e, "publishing source filter state");
        }
    }
}

#[cfg(test)]
mod tests {
    use ts_control::{Node, StableNodeId, TailnetAddress};

    use super::*;

    fn subnet_router_node() -> Node {
        Node {
            id: 1,
            stable_id: StableNodeId("n1".to_string()),
            hostname: "router".to_string(),
            tailnet: Some("ts.net".to_string()),
            tags: vec![],
            tailnet_address: TailnetAddress {
                ipv4: "100.64.0.7/32".parse().unwrap(),
                ipv6: "fd7a::7/128".parse().unwrap(),
            },
            node_key: [0u8; 32].into(),
            node_key_expiry: None,
            machine_key: None,
            disco_key: None,
            // Own tailnet addresses plus an advertised LAN subnet.
            accepted_routes: vec![
                "100.64.0.7/32".parse().unwrap(),
                "fd7a::7/128".parse().unwrap(),
                "192.168.1.0/24".parse().unwrap(),
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

    /// Build the source-filter table the same way the `Arc<PeerState>` handler does, for a single
    /// peer, under the given `accept_routes` and exit-node selection.
    fn build_table(
        node: &Node,
        accept_routes: bool,
        exit_node: Option<&StableNodeId>,
    ) -> Table<PeerId> {
        let mut t = Table::default();
        for route in node.routes_to_install(accept_routes, exit_node) {
            t.insert(route.to_owned(), PeerId(node.id as u32));
        }
        t
    }

    #[test]
    fn subnet_source_rejected_unless_accept_routes() {
        let node = subnet_router_node();
        let peer = PeerId(node.id as u32);

        // accept_routes off: the peer may source its own tailnet addresses, but a packet sourced
        // from inside its advertised subnet is NOT attributable to it (anti-spoof, fail-closed).
        let off = build_table(&node, false, None);
        assert_eq!(off.lookup("100.64.0.7".parse().unwrap()), Some(&peer));
        assert_eq!(off.lookup("fd7a::7".parse().unwrap()), Some(&peer));
        assert_eq!(off.lookup("192.168.1.5".parse().unwrap()), None);

        // accept_routes on: the peer may now source the advertised subnet too.
        let on = build_table(&node, true, None);
        assert_eq!(on.lookup("192.168.1.5".parse().unwrap()), Some(&peer));
    }

    /// A peer advertising a default route may only source arbitrary internet IPs when it is the
    /// selected exit node — the inbound source filter is coupled to the outbound route table.
    fn exit_router_node() -> Node {
        let mut n = subnet_router_node();
        n.stable_id = StableNodeId("exit1".to_string());
        n.accepted_routes = vec![
            "100.64.0.7/32".parse().unwrap(),
            "fd7a::7/128".parse().unwrap(),
            "0.0.0.0/0".parse().unwrap(),
            "::/0".parse().unwrap(),
        ];
        n
    }

    #[test]
    fn internet_source_rejected_unless_peer_is_exit_node() {
        let node = exit_router_node();
        let peer = PeerId(node.id as u32);
        let arbitrary_internet_ip = "8.8.8.8".parse().unwrap();

        // No exit node selected: the peer may source its own tailnet address, but NOT an arbitrary
        // internet IP — return traffic from the internet is not attributable to it (fail-closed).
        let none = build_table(&node, false, None);
        assert_eq!(none.lookup("100.64.0.7".parse().unwrap()), Some(&peer));
        assert_eq!(none.lookup(arbitrary_internet_ip), None);

        // A different peer is the exit node: this peer still may not source internet IPs.
        let other = StableNodeId("exit2".to_string());
        let other_sel = build_table(&node, false, Some(&other));
        assert_eq!(other_sel.lookup(arbitrary_internet_ip), None);

        // This peer is the selected exit node: it may now source arbitrary internet IPs (return
        // traffic), matched by its installed default route.
        let me = StableNodeId("exit1".to_string());
        let sel = build_table(&node, false, Some(&me));
        assert_eq!(sel.lookup(arbitrary_internet_ip), Some(&peer));
    }

    /// End-to-end of the runtime path: an `ExitNodeSelector` (by IP or name) is resolved against
    /// the peer set first, then fed to `routes_to_install` — exactly as the `Arc<PeerState>`
    /// handler does. Proves IP/name selection actually installs the exit peer's default route.
    fn build_table_resolved(
        node: &Node,
        accept_routes: bool,
        selector: Option<&ts_control::ExitNodeSelector>,
    ) -> Table<PeerId> {
        let peers = [node.clone()];
        let resolved = selector.and_then(|s| s.resolve(peers.iter()));
        let mut t = Table::default();
        for route in node.routes_to_install(accept_routes, resolved.as_ref()) {
            t.insert(route.to_owned(), PeerId(node.id as u32));
        }
        t
    }

    #[test]
    fn exit_node_selected_by_ip_or_name_installs_default_route() {
        use ts_control::ExitNodeSelector;

        let node = exit_router_node(); // stable_id "exit1", tailnet ipv4 100.64.0.7
        let peer = PeerId(node.id as u32);
        let arbitrary_internet_ip = "8.8.8.8".parse().unwrap();

        // Selected by tailnet IP: resolves to this peer, default route installed.
        let by_ip = build_table_resolved(
            &node,
            false,
            Some(&ExitNodeSelector::Ip("100.64.0.7".parse().unwrap())),
        );
        assert_eq!(by_ip.lookup(arbitrary_internet_ip), Some(&peer));

        // Selected by MagicDNS name (the helper's hostname is "router" in tailnet "ts.net").
        let by_name = build_table_resolved(
            &node,
            false,
            Some(&ExitNodeSelector::Name("router.ts.net".into())),
        );
        assert_eq!(by_name.lookup(arbitrary_internet_ip), Some(&peer));

        // A non-matching IP selector resolves to None => fail-closed, no internet source allowed.
        let by_wrong_ip = build_table_resolved(
            &node,
            false,
            Some(&ExitNodeSelector::Ip("100.64.0.99".parse().unwrap())),
        );
        assert_eq!(by_wrong_ip.lookup(arbitrary_internet_ip), None);
    }
}
