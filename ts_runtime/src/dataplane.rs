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
            // `.clone()`: `node_keys` is no longer `Copy` and `env` is a shared `Arc`.
            env.keys.node_keys.clone(),
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

        // Hybrid data plane (KERNEL_WG_DESIGN.md seam #1): mirror peers that have a direct underlay
        // endpoint into the kernel WireGuard interface so the kernel does their crypto + sends UDP
        // direct (much cheaper on 32-bit MIPS). Relay-only / not-yet-direct peers are excluded by
        // `kernel_wg::sync` and stay on the userspace ts_tunnel + DERP path above. First cut: the
        // local interface name/key/port come from env (TS_KERNEL_WG_{IFNAME,KEYFILE,PORT}); the full
        // integration threads the node's own WG key from config (see KERNEL_WG_DESIGN.md).
        #[cfg(all(feature = "kernel-wg", target_os = "linux"))]
        {
            use defguard_wireguard_rs::net::IpAddrMask;

            use crate::kernel_wg::{self, KernelPeer};

            let ifname =
                std::env::var("TS_KERNEL_WG_IFNAME").unwrap_or_else(|_| "wg-ts".to_string());
            let port: u32 = std::env::var("TS_KERNEL_WG_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(51820);
            let privkey: [u8; 32] = std::env::var("TS_KERNEL_WG_KEYFILE")
                .ok()
                .and_then(|p| std::fs::read(p).ok())
                .filter(|b| b.len() == 32)
                .map(|b| {
                    let mut k = [0u8; 32];
                    k.copy_from_slice(&b);
                    k
                })
                .unwrap_or([0u8; 32]);

            let mut peers = Vec::new();
            for &upsert in &msg.upserts {
                let Some((_, node)) = msg.peers.get(&upsert) else {
                    continue;
                };
                let mut allowed = vec![
                    IpAddrMask::new(
                        node.tailnet_address.ipv4.addr().into(),
                        node.tailnet_address.ipv4.prefix_len(),
                    ),
                    IpAddrMask::new(
                        node.tailnet_address.ipv6.addr().into(),
                        node.tailnet_address.ipv6.prefix_len(),
                    ),
                ];
                for r in &node.accepted_routes {
                    allowed.push(IpAddrMask::new(r.addr(), r.prefix_len()));
                }
                peers.push(KernelPeer {
                    public_key: node.node_key.to_bytes(),
                    allowed_ips: allowed,
                    // best_addr (disco-verified, seam #2) is not plumbed to this synchronous seam
                    // yet, so pass None and use the control-distributed underlay candidate. The
                    // periodic seam-#2 task (KERNEL_WG_DESIGN.md) will supply the live best_addr.
                    endpoint: kernel_wg::select_endpoint(None, &node.underlay_addresses),
                });
            }
            if let Err(e) = kernel_wg::sync(&ifname, privkey, port, &peers) {
                tracing::warn!(error = %e, "kernel-wg: sync failed (needs root + kmod-wireguard)");
            }
        }

        tracing::trace!("applied new peer state");
    }
}
