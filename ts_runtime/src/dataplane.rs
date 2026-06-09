use std::sync::Arc;

use kameo::{
    actor::ActorRef,
    message::{Context, Message},
};
use tokio::sync::mpsc;
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

pub struct DataplaneActor {
    dataplane: Arc<ts_dataplane::async_tokio::DataPlane>,
    task: tokio::task::JoinHandle<()>,
    /// Persistent-keepalive interval applied to every upserted peer (or `None` to disable). Snapshot
    /// of [`Env::persistent_keepalive_interval`] taken at actor start. See the peer-upsert handler.
    persistent_keepalive_interval: Option<std::time::Duration>,
}

impl Drop for DataplaneActor {
    fn drop(&mut self) {
        self.task.abort();
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
            env.keys.node_keys,
        ));

        let persistent_keepalive_interval = env.persistent_keepalive_interval;

        env.subscribe::<PeerRouteUpdate>(&slf).await?;
        env.subscribe::<SelfRouteUpdate>(&slf).await?;
        env.subscribe::<PacketFilterState>(&slf).await?;
        env.subscribe::<SourceFilterState>(&slf).await?;
        env.subscribe::<Arc<PeerState>>(&slf).await?;

        let task_dataplane = dataplane.clone();

        let task = tokio::task::spawn(async move {
            task_dataplane.run().await;
        });

        tracing::trace!("dataplane running");

        Ok(Self {
            dataplane,
            task,
            persistent_keepalive_interval,
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

impl Message<Arc<PeerState>> for DataplaneActor {
    type Reply = ();

    async fn handle(&mut self, msg: Arc<PeerState>, _ctx: &mut Context<Self, Self::Reply>) {
        {
            let mut dp = self.dataplane.inner().await;
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
