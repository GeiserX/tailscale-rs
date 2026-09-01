use std::{collections::HashMap, net::IpAddr, sync::Arc};

use kameo::{
    actor::ActorRef,
    message::{Context, Message},
};
use tokio::sync::mpsc;
use ts_dataplane::{AdvertisementTarget, DiscoAdvertisementState};
use ts_packet::PacketMut;
use ts_transport::{OverlayTransportId, PeerId, UnderlayTransportId};

use crate::{
    Error,
    env::Env,
    packetfilter::PacketFilterState,
    peer_tracker::PeerState,
    route_updater::{PeerRouteUpdate, SelfRouteUpdate},
    src_filter::SourceFilterState,
};

/// Queue for packets sent from the overlay to the dataplane.
pub type OverlayToDataplane = mpsc::UnboundedSender<Vec<PacketMut>>;

/// Queue for packets entering the overlay from the dataplane.
pub type OverlayFromDataplane = mpsc::UnboundedReceiver<Vec<PacketMut>>;

/// Queue for packets leaving the underlay to the dataplane.
pub type UnderlayToDataplane = mpsc::UnboundedSender<(PeerId, Vec<PacketMut>)>;

/// Queue for packets entering an underlay from the dataplane.
pub type UnderlayFromDataplane = mpsc::UnboundedReceiver<(PeerId, Vec<PacketMut>)>;

/// A peer's disco public key, learned from a TSMP disco-key advertisement it sent us inside the
/// WireGuard tunnel (Go `packet.TSMPDiscoKeyAdvertisement`, upstream capability version 144).
///
/// Published on the bus by [`DataplaneActor`] and consumed by the peer tracker, which applies it to
/// the peer. This is the Rust shape of Go's `events.PeerDiscoKeyUpdate`, which `wgengine` turns
/// into a `magicsock.Conn.HandleDiscoKeyAdvertisement` call.
///
/// `peer` is the WireGuard peer whose session decrypted the advertisement — the dataplane's source
/// filter has already bound that peer's source addresses — so a peer can only ever advertise a key
/// for itself. Go arrives at the same peer by looking the advertisement's source IP up in the
/// netmap (`wgengine.userspaceEngine.peerForIP`).
#[derive(Debug, Clone, Copy)]
pub struct PeerDiscoKeyAdvertisement {
    /// The peer that advertised the key.
    pub peer: PeerId,
    /// The disco public key it advertised. Never the zero key: the dataplane drops those, as Go
    /// does, before they get this far.
    pub key: ts_keys::DiscoPublicKey,
}

pub struct DataplaneActor {
    dataplane: Arc<ts_dataplane::async_tokio::DataPlane>,
    task: tokio::task::JoinHandle<()>,
    /// Forwards TSMP-learned peer disco keys from the dataplane onto the bus.
    disco_key_task: tokio::task::JoinHandle<()>,
    /// Persistent-keepalive interval applied to every upserted peer (or `None` to disable). Snapshot
    /// of [`Env::persistent_keepalive_interval`] taken at actor start. See the peer-upsert handler.
    persistent_keepalive_interval: Option<std::time::Duration>,
    /// Working copy of the netmap state the dataplane needs to send a TSMP disco-key advertisement
    /// when a WireGuard session comes up (Go capability version 144). Two independent sources feed
    /// it — the self node (our own tailnet addresses) and the peer set (each peer's destination
    /// address) — so it is assembled here and pushed into the dataplane whole on every change.
    disco_advertisement: DiscoAdvertisementState,
}

impl Drop for DataplaneActor {
    fn drop(&mut self) {
        self.task.abort();
        self.disco_key_task.abort();
    }
}

#[kameo::messages]
impl DataplaneActor {
    #[message]
    pub async fn new_overlay_transport(
        &self,
    ) -> (OverlayTransportId, OverlayToDataplane, OverlayFromDataplane) {
        self.dataplane.new_overlay_transport().await
    }

    #[message]
    pub async fn new_underlay_transport(
        &self,
    ) -> (
        UnderlayTransportId,
        UnderlayFromDataplane,
        UnderlayToDataplane,
    ) {
        self.dataplane.new_underlay_transport().await
    }

    /// Install (`Some`) or clear (`None`) the debug packet-capture hook on the running dataplane.
    /// `Some(hook)` begins teeing every plaintext packet crossing the datapath to `hook`; `None`
    /// stops capture. Mirrors Go `tstun.Wrapper.InstallCaptureHook` / `ClearCaptureSink`.
    #[message]
    pub async fn install_capture(&self, hook: Option<ts_dataplane::CaptureHook>) {
        let dp = &mut *self.dataplane.inner().await;
        dp.capture = hook;
    }
}

impl kameo::Actor for DataplaneActor {
    type Args = Env;
    type Error = Error;

    async fn on_start(env: Self::Args, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        let dataplane = Arc::new(ts_dataplane::async_tokio::DataPlane::new(
            // `.clone()`: `node_keys` is no longer `Copy` and `env` is a shared `Arc`.
            env.keys.node_keys.clone(),
        ));

        let persistent_keepalive_interval = env.persistent_keepalive_interval;

        // Peers advertise their disco key over TSMP immediately after an eligible WireGuard
        // session is established, so the sink must be installed before the dataplane starts
        // running or the first advertisement is lost.
        let (disco_key_tx, mut disco_key_rx) = mpsc::unbounded_channel();
        dataplane.install_disco_key_sink(Some(disco_key_tx)).await;

        let disco_key_env = env.clone();
        let disco_key_task = tokio::task::spawn(async move {
            while let Some((peer, advert)) = disco_key_rx.recv().await {
                let key = ts_keys::DiscoPublicKey::from(advert.key);

                tracing::debug!(?peer, %key, "publishing TSMP-advertised peer disco key");

                if let Err(e) = disco_key_env
                    .publish(PeerDiscoKeyAdvertisement { peer, key })
                    .await
                {
                    tracing::error!(error = %e, "publishing TSMP disco-key advertisement");
                }
            }
        });

        env.subscribe::<PeerRouteUpdate>(&slf).await?;
        env.subscribe::<SelfRouteUpdate>(&slf).await?;
        env.subscribe::<PacketFilterState>(&slf).await?;
        env.subscribe::<SourceFilterState>(&slf).await?;
        env.subscribe::<Arc<PeerState>>(&slf).await?;
        // The self node, for the source address of our own TSMP disco-key advertisements. Peers
        // arrive via `PeerState`; this is the other half of `disco_advertisement`.
        env.subscribe::<Arc<ts_control::StateUpdate>>(&slf).await?;

        let task_dataplane = dataplane.clone();

        let task = tokio::task::spawn(async move {
            task_dataplane.run().await;
        });

        tracing::trace!("dataplane running");

        Ok(Self {
            dataplane,
            task,
            disco_key_task,
            persistent_keepalive_interval,
            // Our disco key is generated once per run and never rotates (unlike the node key), so
            // it is snapshotted here rather than re-read per advertisement. Go reads it per call
            // (`Conn.DiscoPublicKey()`) because its disco key *can* be regenerated on rebind.
            disco_advertisement: DiscoAdvertisementState {
                disco_key: env.keys.disco_keys.public.to_bytes(),
                ..Default::default()
            },
        })
    }
}

impl Message<PeerRouteUpdate> for DataplaneActor {
    type Reply = ();

    async fn handle(&mut self, msg: PeerRouteUpdate, _ctx: &mut Context<Self, Self::Reply>) {
        tracing::trace!("applying peer route update");

        let dp = &mut *self.dataplane.inner().await;
        dp.or_out.swap(msg.inner.overlay_out_routes.clone());

        dp.ur_out.table = msg.inner.underlay_routes.clone();
    }
}

impl Message<SelfRouteUpdate> for DataplaneActor {
    type Reply = ();

    async fn handle(&mut self, msg: SelfRouteUpdate, _ctx: &mut Context<Self, Self::Reply>) {
        {
            let dp = &mut *self.dataplane.inner().await;
            dp.or_in.swap(msg.overlay_in_routes.as_ref().clone());
        }

        tracing::trace!("applied self route update");
    }
}

impl Message<PacketFilterState> for DataplaneActor {
    type Reply = ();

    async fn handle(&mut self, msg: PacketFilterState, _ctx: &mut Context<Self, Self::Reply>) {
        {
            let dp = &mut *self.dataplane.inner().await;
            dp.packet_filter = msg.0;
        }

        tracing::trace!("applied new packet filter");
    }
}

impl Message<SourceFilterState> for DataplaneActor {
    type Reply = ();

    async fn handle(&mut self, msg: SourceFilterState, _ctx: &mut Context<Self, Self::Reply>) {
        {
            let dp = &mut *self.dataplane.inner().await;
            dp.src_filter_in = msg.0;
        }

        tracing::trace!("applied new source filter");
    }
}

/// This node's own tailnet addresses, in the order Go's `self.Addresses()` presents them and
/// narrowed to the single-IP prefixes `magicsock.selfIPMatchingFamily` accepts.
///
/// Control lists a node's IPv4 address first, so that is the order kept here. The unspecified
/// placeholder [`ts_control::TailnetAddress`] synthesizes for a family the tailnet does not assign
/// (`0.0.0.0/32` / `::/128`) is not an address and is skipped — advertising it as our source would
/// name an address no peer can answer.
fn advertisement_self_addrs(node: &ts_control::Node) -> Vec<IpAddr> {
    let v4 = node.tailnet_address.ipv4.addr();
    let v6 = node.tailnet_address.ipv6.addr();

    let mut addrs = Vec::with_capacity(2);
    if !v4.is_unspecified() {
        addrs.push(IpAddr::from(v4));
    }
    if !v6.is_unspecified() {
        addrs.push(IpAddr::from(v6));
    }
    addrs
}

/// Where to send `node` a TSMP disco-key advertisement, or `None` if it has no usable tailnet
/// address at all.
///
/// The destination is Go's `endpoint.nodeAddr`, "the node's first tailscale address" — IPv4 on a
/// dual-stack tailnet, falling back to IPv6 for a tailnet that assigns no IPv4. `wireguard_only`
/// carries Go's `endpoint.isWireguardOnly` through to the refusal in
/// [`DiscoAdvertisementState::advertisement_for`].
fn advertisement_target(node: &ts_control::Node) -> Option<AdvertisementTarget> {
    let v4 = node.tailnet_address.ipv4.addr();
    let v6 = node.tailnet_address.ipv6.addr();

    let node_addr = if !v4.is_unspecified() {
        IpAddr::from(v4)
    } else if !v6.is_unspecified() {
        IpAddr::from(v6)
    } else {
        return None;
    };

    Some(AdvertisementTarget {
        node_addr,
        wireguard_only: node.is_wireguard_only,
    })
}

/// Rebuild the per-peer advertisement destinations from a peer snapshot.
///
/// Rebuilt wholesale rather than patched from the upsert/deletion sets: the snapshot is the
/// authoritative peer set, so a peer that left the netmap stops being advertised to without any
/// separate bookkeeping.
fn advertisement_targets(
    peers: &crate::peer_tracker::PeerDb,
) -> HashMap<PeerId, AdvertisementTarget> {
    peers
        .peers()
        .iter()
        .filter_map(|(&id, node)| Some((id, advertisement_target(node)?)))
        .collect()
}

impl Message<Arc<ts_control::StateUpdate>> for DataplaneActor {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: Arc<ts_control::StateUpdate>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        // Only a response that carried a self node says anything about our own addresses; a
        // keep-alive or a peers-only update leaves the previous snapshot in place.
        let Some(node) = msg.node.as_ref() else {
            return;
        };

        let self_addrs = advertisement_self_addrs(node);
        if self_addrs == self.disco_advertisement.self_addrs {
            return;
        }
        self.disco_advertisement.self_addrs = self_addrs;

        let mut dp = self.dataplane.inner().await;
        dp.disco_advertisement = Some(Arc::new(self.disco_advertisement.clone()));

        tracing::trace!("applied self addresses for TSMP disco-key advertisement");
    }
}

impl Message<Arc<PeerState>> for DataplaneActor {
    type Reply = ();

    async fn handle(&mut self, msg: Arc<PeerState>, _ctx: &mut Context<Self, Self::Reply>) {
        self.disco_advertisement.peers = advertisement_targets(&msg.peers);

        {
            let mut dp = self.dataplane.inner().await;
            dp.disco_advertisement = Some(Arc::new(self.disco_advertisement.clone()));
            let wg = &mut dp.wireguard;

            for &upsert in &msg.upserts {
                let Some((_, node)) = msg.peers.get(&upsert) else {
                    tracing::error!(
                        ?upsert,
                        "dataplane: upsert id missing from peer snapshot; skipping"
                    );
                    continue;
                };

                wg.upsert_peer(
                    ts_tunnel::PeerId(upsert.0),
                    ts_tunnel::PeerConfig {
                        key: node.node_key,
                        psk: [0u8; 32].into(),
                        // Persistent keepalive holds the (often DERP-relayed) path to every peer
                        // warm so an idle session doesn't age out and wedge the next dial. Applied
                        // to all peers because this fork's primary deployment is a userspace-netstack
                        // node whose only path to peers is via the relay. `None` (embedder opt-out)
                        // disables it. See `Env::persistent_keepalive_interval`.
                        persistent_keepalive_interval: self.persistent_keepalive_interval,
                    },
                );
            }

            for delete in &msg.deletions {
                wg.remove_peer(ts_tunnel::PeerId(delete.0));
            }
        }

        tracing::trace!("applied new peer state");
    }
}

#[cfg(test)]
mod tests {
    use ts_control::{Node, StableNodeId, TailnetAddress};

    use super::*;

    /// A node with the given tailnet addresses. `ipv4`/`ipv6` are prefix strings so a test can hand
    /// in the unspecified placeholders `TailnetAddress` synthesizes for a family the tailnet does
    /// not assign.
    fn node(stable: &str, ipv4: &str, ipv6: &str, is_wireguard_only: bool) -> Node {
        Node {
            id: 1,
            stable_id: StableNodeId(stable.to_string()),
            hostname: stable.to_string(),
            user_id: 0,
            tailnet: None,
            tags: vec![],
            addresses: vec![ipv4.parse().unwrap(), ipv6.parse().unwrap()],
            tailnet_address: TailnetAddress {
                ipv4: ipv4.parse().unwrap(),
                ipv6: ipv6.parse().unwrap(),
            },
            node_key: [0u8; 32].into(),
            node_key_expiry: None,
            online: None,
            last_seen: None,
            key_signature: vec![],
            machine_key: None,
            disco_key: None,
            accepted_routes: vec![],
            underlay_addresses: vec![],
            derp_region: None,
            cap: Default::default(),
            cap_map: Default::default(),
            peerapi_port: None,
            peerapi_dns_proxy: false,
            is_wireguard_only,
            exit_node_dns_resolvers: vec![],
            peer_relay: false,
            ssh_host_keys: vec![],
            service_vips: Default::default(),
        }
    }

    /// This node's advertisement source addresses (Go `self.Addresses()` as
    /// `selfIPMatchingFamily` walks it): IPv4 first, IPv6 second, and the unspecified placeholder
    /// for a family the tailnet does not assign left out entirely.
    #[test]
    fn self_advertisement_addrs_skip_the_unassigned_family() {
        let dual = node("self", "100.64.0.1/32", "fd7a:115c:a1e0::1/128", false);
        assert_eq!(
            advertisement_self_addrs(&dual),
            vec![
                IpAddr::from([100, 64, 0, 1]),
                "fd7a:115c:a1e0::1".parse::<IpAddr>().unwrap(),
            ],
            "IPv4 comes first, the order control sends"
        );

        let v4_only = node("self", "100.64.0.1/32", "::/128", false);
        assert_eq!(
            advertisement_self_addrs(&v4_only),
            vec![IpAddr::from([100, 64, 0, 1])],
            "the unspecified IPv6 placeholder is not an address"
        );

        let v6_only = node("self", "0.0.0.0/32", "fd7a:115c:a1e0::1/128", false);
        assert_eq!(
            advertisement_self_addrs(&v6_only),
            vec!["fd7a:115c:a1e0::1".parse::<IpAddr>().unwrap()],
            "an IPv6-only tailnet still has a source address"
        );

        assert!(
            advertisement_self_addrs(&node("self", "0.0.0.0/32", "::/128", false)).is_empty(),
            "a node with no addresses at all advertises from nowhere"
        );
    }

    /// A peer's advertisement destination is Go's `endpoint.nodeAddr`, "the node's first tailscale
    /// address" — IPv4 where the tailnet assigns one — and it carries `IsWireGuardOnly` through to
    /// the refusal in the dataplane.
    #[test]
    fn peer_advertisement_target_is_the_nodes_first_address() {
        let dual = node("peer", "100.64.0.2/32", "fd7a:115c:a1e0::2/128", false);
        assert_eq!(
            advertisement_target(&dual),
            Some(AdvertisementTarget {
                node_addr: IpAddr::from([100, 64, 0, 2]),
                wireguard_only: false,
            }),
        );

        let v6_only = node("peer", "0.0.0.0/32", "fd7a:115c:a1e0::2/128", false);
        assert_eq!(
            advertisement_target(&v6_only),
            Some(AdvertisementTarget {
                node_addr: "fd7a:115c:a1e0::2".parse().unwrap(),
                wireguard_only: false,
            }),
            "a peer with no IPv4 is addressed over IPv6",
        );

        assert_eq!(
            advertisement_target(&node("peer", "100.64.0.3/32", "::/128", true)),
            Some(AdvertisementTarget {
                node_addr: IpAddr::from([100, 64, 0, 3]),
                wireguard_only: true,
            }),
            "IsWireGuardOnly is carried, not filtered out here",
        );

        assert_eq!(
            advertisement_target(&node("peer", "0.0.0.0/32", "::/128", false)),
            None,
            "a peer with no address at all cannot be advertised to",
        );
    }

    /// The per-peer map is rebuilt from the snapshot, so a peer that left the netmap stops being
    /// advertised to without any separate deletion bookkeeping.
    #[test]
    fn advertisement_targets_follow_the_peer_snapshot() {
        let mut db = crate::peer_tracker::PeerDb::default();
        let a = db.upsert(&node("a", "100.64.0.2/32", "::/128", false));
        let b = db.upsert(&node("b", "100.64.0.3/32", "::/128", false));

        let targets = advertisement_targets(&db);
        assert_eq!(targets.len(), 2);
        assert_eq!(
            targets.get(&a).map(|t| t.node_addr),
            Some(IpAddr::from([100, 64, 0, 2]))
        );

        db.remove(&StableNodeId("b".to_string()));
        let targets = advertisement_targets(&db);
        assert_eq!(targets.len(), 1, "a departed peer is no longer a target");
        assert!(targets.contains_key(&a));
        assert!(!targets.contains_key(&b));
    }
}
