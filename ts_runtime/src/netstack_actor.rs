use core::net::IpAddr;
use std::sync::Arc;

use kameo::{
    actor::ActorRef,
    message::{Context, Message},
};
use netstack::{
    HasChannel,
    netcore::{Channel, NetstackControl},
};
use tokio::task::JoinSet;
use ts_packet::PacketMut;

use crate::{
    Error,
    dataplane::{OverlayFromDataplane, OverlayToDataplane},
    env::Env,
};

pub struct NetstackActor {
    _joinset: JoinSet<()>,
    channel: Channel,

    /// Whether IPv6 is enabled on the tailnet overlay (captured from [`Env::enable_ipv6`] at
    /// spawn). Gates whether the node's IPv6 overlay address is assigned to the netstack. When
    /// `false` (the default IPv4-only posture) the netstack is handed no IPv6 overlay address, so
    /// behavior is byte-for-byte the historical IPv4-only path.
    enable_ipv6: bool,
}

/// Assemble the overlay address list to hand the netstack for a given self-node.
///
/// Always includes the node's IPv4 tailnet address and the MagicDNS service IP
/// (`100.100.100.100`, which lets the in-netstack DNS responder bind `:53`). The IPv6 tailnet
/// address is included **only** when `enable_ipv6` is `true`; when `false` (the default) it is
/// dropped, keeping the assigned set byte-for-byte the historical IPv4-only path.
fn overlay_addresses(
    tailnet_address: &ts_control::TailnetAddress,
    enable_ipv6: bool,
) -> Vec<IpAddr> {
    let mut addrs = vec![tailnet_address.ipv4.addr().into()];

    if enable_ipv6 {
        addrs.push(tailnet_address.ipv6.addr().into());
    }

    // MagicDNS service IP (100.100.100.100) — lets the in-netstack DNS responder bind :53.
    addrs.push(core::net::Ipv4Addr::new(100, 100, 100, 100).into());

    addrs
}

impl kameo::Actor for NetstackActor {
    type Args = (
        Env,
        netstack::netcore::Config,
        OverlayToDataplane,
        OverlayFromDataplane,
    );
    type Error = Error;

    async fn on_start(
        (env, config, netstack_up, mut netstack_down): Self::Args,
        slf: ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        env.subscribe::<Arc<ts_control::StateUpdate>>(&slf).await?;

        // Capture the gate up-front: the netstack is handed an IPv6 overlay address only when
        // IPv6 is enabled on the tailnet overlay (default `false`, IPv4-only).
        let enable_ipv6 = env.enable_ipv6;

        let (
            mut netstack,
            netstack::WakingPipe {
                rx: mut netstack_down_rx,
                tx: netstack_down_tx,
            },
        ) = netstack::piped(config);
        let channel = netstack.command_channel();

        let mut joinset = JoinSet::new();

        joinset.spawn(async move {
            netstack.run_tokio().await;
        });

        joinset.spawn(async move {
            while let Some(buf) = netstack_down_rx.recv_async().await {
                if netstack_up.send(vec![buf.to_vec().into()]).is_err() {
                    break;
                }
            }

            tracing::warn!("netstack downlink shut down!");
        });

        joinset.spawn(async move {
            while let Some(bufs) = netstack_down.recv().await {
                for buf in bufs {
                    let buf: PacketMut = buf;
                    netstack_down_tx.send_async(buf.as_ref()).await;
                }
            }

            tracing::warn!("netstack uplink shut down!");
        });

        Ok(Self {
            _joinset: joinset,
            channel,
            enable_ipv6,
        })
    }
}

#[kameo::messages]
impl NetstackActor {
    #[message]
    pub fn get_channel(&self) -> (Channel,) {
        (self.channel.clone(),)
    }
}

impl Message<Arc<ts_control::StateUpdate>> for NetstackActor {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: Arc<ts_control::StateUpdate>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        let Some(self_node) = &msg.node else {
            return;
        };

        tracing::debug!(new_tailnet_ips = ?self_node.tailnet_address, self.enable_ipv6);

        let ips = overlay_addresses(&self_node.tailnet_address, self.enable_ipv6);

        if let Err(e) = self.channel.set_ips(ips).await {
            tracing::error!(error = %e, "setting netstack ips");
        }
    }
}

#[cfg(test)]
mod tests {
    use ipnet::{Ipv4Net, Ipv6Net};
    use ts_control::TailnetAddress;

    use super::overlay_addresses;

    fn tailnet_address() -> TailnetAddress {
        TailnetAddress {
            ipv4: Ipv4Net::new(core::net::Ipv4Addr::new(100, 64, 0, 1), 32).unwrap(),
            ipv6: Ipv6Net::new(
                core::net::Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 1),
                128,
            )
            .unwrap(),
        }
    }

    /// Gate OFF (the default IPv4-only posture): the assembled address list must contain NO IPv6
    /// overlay address — byte-for-byte the historical IPv4-only path (v4 + MagicDNS service IP).
    #[test]
    fn gate_off_drops_ipv6_overlay_address() {
        let addr = tailnet_address();
        let ips = overlay_addresses(&addr, false);

        assert!(
            !ips.iter().any(|ip| ip.is_ipv6()),
            "gate-off address list must contain no IPv6 address: {ips:?}"
        );
        assert_eq!(
            ips,
            vec![
                core::net::IpAddr::V4(addr.ipv4.addr()),
                core::net::IpAddr::V4(core::net::Ipv4Addr::new(100, 100, 100, 100)),
            ],
            "gate-off list must be exactly [ipv4, 100.100.100.100]"
        );
    }

    /// Gate ON: the node's IPv6 overlay address is included.
    #[test]
    fn gate_on_includes_ipv6_overlay_address() {
        let addr = tailnet_address();
        let ips = overlay_addresses(&addr, true);

        assert!(
            ips.contains(&core::net::IpAddr::V6(addr.ipv6.addr())),
            "gate-on address list must contain the IPv6 overlay address: {ips:?}"
        );
        assert_eq!(
            ips,
            vec![
                core::net::IpAddr::V4(addr.ipv4.addr()),
                core::net::IpAddr::V6(addr.ipv6.addr()),
                core::net::IpAddr::V4(core::net::Ipv4Addr::new(100, 100, 100, 100)),
            ],
            "gate-on list must be exactly [ipv4, ipv6, 100.100.100.100]"
        );
    }
}
