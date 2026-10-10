//! The application netstack actor: the userspace TCP/IP stack carrying this node's own tailnet
//! traffic.
//!
//! [`NetstackActor`] pumps packets between the dataplane overlay queues and an in-process netstack,
//! and on each control update assigns the node's overlay addresses ([`overlay_addresses`]): its IPv4
//! tailnet address, the MagicDNS service IP, and any hosted VIP-service addresses.
//!
//! IPv6-off by default: the node's IPv6 overlay address (and any v6 VIP) is assigned only when
//! [`Env::enable_ipv6`] is set, keeping the default posture byte-for-byte the IPv4-only path.

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

/// The most packets the dataplane may have queued for one netstack before further ingress is
/// dropped — the depth of the netstack's receive ring.
///
/// A peer can deliver packets faster than the single netstack task drains them. Before this bound
/// the backlog grew without limit, so an authenticated peer flooding small packets could exhaust the
/// host's memory. Now the queue sheds load the way a NIC with a full rx ring does: TCP retransmits
/// what was dropped and UDP is lossy by contract.
pub(crate) const INGRESS_QUEUE_PACKETS: usize = 4096;

/// Build a netstack whose ingress queue holds at most [`INGRESS_QUEUE_PACKETS`] packets and that
/// many MTU-sized packets' worth of bytes.
///
/// The byte cap is separate from the count because a packet from a peer is not limited to this
/// stack's MTU — over DERP it can be up to 64 KiB — so the count alone would not cap memory. With
/// the default 1280-byte overlay MTU the cap is 5 MiB per netstack.
pub(crate) fn piped_ingress_bounded(
    config: netstack::netcore::Config,
) -> (
    netstack::Netstack<netstack::WakingPipeDev>,
    netstack::WakingPipe,
) {
    let max_bytes = INGRESS_QUEUE_PACKETS.saturating_mul(config.mtu);
    netstack::piped_ingress_bounded(config, INGRESS_QUEUE_PACKETS, max_bytes)
}

/// Move packets the dataplane routed to a netstack into that netstack's ingress queue, dropping
/// any packet the queue has no room for. Returns how many it dropped, once the dataplane side
/// closes.
///
/// It never waits on the netstack. Waiting would only move the backlog upstream into the
/// dataplane's unbounded per-transport queue, which is the growth this exists to stop.
///
/// Drops are logged at `debug!` only, once when a run of drops starts and once when it ends: the
/// rate is peer-driven, so it must not be able to drive an operator's default-level log.
pub(crate) async fn pump_ingress(
    mut from_dataplane: OverlayFromDataplane,
    to_netstack: netstack::WakingPipeSender,
    netstack_name: &'static str,
) -> u64 {
    let mut dropped: u64 = 0;
    let mut dropping = false;

    while let Some(bufs) = from_dataplane.recv().await {
        for buf in bufs {
            let buf: PacketMut = buf;
            if to_netstack.try_send(buf.as_ref()) {
                if dropping {
                    dropping = false;
                    tracing::debug!(
                        netstack = netstack_name,
                        dropped_total = dropped,
                        "netstack ingress queue has room again"
                    );
                }
            } else {
                dropped += 1;
                if !dropping {
                    dropping = true;
                    tracing::debug!(
                        netstack = netstack_name,
                        max_packets = INGRESS_QUEUE_PACKETS,
                        "netstack ingress queue full; dropping inbound packets"
                    );
                }
            }
        }
    }

    dropped
}

/// Assemble the overlay address list to hand the netstack for a given self-node.
///
/// Always includes the node's IPv4 tailnet address and the MagicDNS service IP
/// (`100.100.100.100`, which lets the in-netstack DNS responder bind `:53`). The IPv6 tailnet
/// address is included **only** when `enable_ipv6` is `true`; when `false` (the default) it is
/// dropped, keeping the assigned set byte-for-byte the historical IPv4-only path.
pub(crate) fn overlay_addresses(self_node: &ts_control::Node, enable_ipv6: bool) -> Vec<IpAddr> {
    let tailnet_address = &self_node.tailnet_address;
    let mut addrs = vec![tailnet_address.ipv4.addr().into()];

    if enable_ipv6 {
        addrs.push(tailnet_address.ipv6.addr().into());
    }

    // MagicDNS service IP (100.100.100.100) — lets the in-netstack DNS responder bind :53.
    addrs.push(core::net::Ipv4Addr::new(100, 100, 100, 100).into());

    // Tailscale VIP-service addresses control assigned this host (`service-host` cap). The netstack
    // must accept packets for these so a `Device::listen_service`-bound listener can answer; they
    // are control-assigned and also injected into the node's AllowedIPs. When IPv6 is disabled on
    // the overlay, drop any v6 VIP — the fork is IPv4-only by default and the netstack holds no v6
    // address to bind. Deduplicated against the addresses already added.
    for vip in self_node.service_addresses() {
        if vip.is_ipv6() && !enable_ipv6 {
            continue;
        }
        if !addrs.contains(&vip) {
            addrs.push(vip);
        }
    }

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
        (env, config, netstack_up, netstack_down): Self::Args,
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
        ) = piped_ingress_bounded(config);
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
            pump_ingress(netstack_down, netstack_down_tx, "application").await;

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

        let ips = overlay_addresses(self_node, self.enable_ipv6);

        if let Err(e) = self.channel.set_ips(ips).await {
            tracing::error!(error = %e, "setting netstack ips");
        }
    }
}

#[cfg(test)]
mod tests {
    use core::net::{IpAddr, Ipv4Addr};

    use ipnet::{Ipv4Net, Ipv6Net};
    use ts_control::{Node, NodeCapMap, StableNodeId, TailnetAddress};

    use super::overlay_addresses;

    fn tailnet_address() -> TailnetAddress {
        TailnetAddress {
            ipv4: Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 1), 32).unwrap(),
            ipv6: Ipv6Net::new(
                core::net::Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 1),
                128,
            )
            .unwrap(),
        }
    }

    /// Build a minimal self-node hosting the given VIP service addresses under a single service.
    /// `overlay_addresses` reads the flattened `Node::service_addresses()` set, so the exact service
    /// name is irrelevant here; the cap map is left empty.
    fn self_node(service_addresses: Vec<IpAddr>) -> Node {
        let addr = tailnet_address();
        let mut service_vips: std::collections::BTreeMap<String, Vec<IpAddr>> =
            std::collections::BTreeMap::new();
        if !service_addresses.is_empty() {
            service_vips.insert("svc:test".to_string(), service_addresses);
        }
        Node {
            id: 1,
            stable_id: StableNodeId("n1".to_string()),
            hostname: "host".to_string(),
            user_id: 0,
            tailnet: Some("tail1.ts.net".to_string()),
            tags: vec![],
            addresses: vec![addr.ipv4.into(), addr.ipv6.into()],
            tailnet_address: addr,
            node_key: [0u8; 32].into(),
            node_key_expiry: None,
            expired: false,
            online: None,
            last_seen: None,
            key_signature: vec![],
            machine_key: None,
            disco_key: None,
            accepted_routes: vec![],
            underlay_addresses: vec![],
            derp_region: None,
            cap: Default::default(),
            cap_map: NodeCapMap::new(),
            peerapi_port: None,
            peerapi_dns_proxy: false,
            is_wireguard_only: false,
            exit_node_dns_resolvers: vec![],
            peer_relay: false,
            ssh_host_keys: vec![],
            service_vips,
            unsigned_peer_api_only: false,
        }
    }

    /// Gate OFF (the default IPv4-only posture): the assembled address list must contain NO IPv6
    /// overlay address — byte-for-byte the historical IPv4-only path (v4 + MagicDNS service IP).
    #[test]
    fn gate_off_drops_ipv6_overlay_address() {
        let node = self_node(vec![]);
        let addr = &node.tailnet_address;
        let ips = overlay_addresses(&node, false);

        assert!(
            !ips.iter().any(|ip| ip.is_ipv6()),
            "gate-off address list must contain no IPv6 address: {ips:?}"
        );
        assert_eq!(
            ips,
            vec![
                IpAddr::V4(addr.ipv4.addr()),
                IpAddr::V4(Ipv4Addr::new(100, 100, 100, 100)),
            ],
            "gate-off list must be exactly [ipv4, 100.100.100.100]"
        );
    }

    /// Gate ON: the node's IPv6 overlay address is included.
    #[test]
    fn gate_on_includes_ipv6_overlay_address() {
        let node = self_node(vec![]);
        let addr = &node.tailnet_address;
        let ips = overlay_addresses(&node, true);

        assert!(
            ips.contains(&IpAddr::V6(addr.ipv6.addr())),
            "gate-on address list must contain the IPv6 overlay address: {ips:?}"
        );
        assert_eq!(
            ips,
            vec![
                IpAddr::V4(addr.ipv4.addr()),
                IpAddr::V6(addr.ipv6.addr()),
                IpAddr::V4(Ipv4Addr::new(100, 100, 100, 100)),
            ],
            "gate-on list must be exactly [ipv4, ipv6, 100.100.100.100]"
        );
    }

    /// A hosted IPv4 VIP-service address is appended so the netstack accepts packets for it.
    #[test]
    fn vip_service_v4_address_is_accepted() {
        let vip = IpAddr::V4(Ipv4Addr::new(100, 65, 32, 1));
        let node = self_node(vec![vip]);
        let ips = overlay_addresses(&node, false);
        assert!(
            ips.contains(&vip),
            "the VIP-service address must be in the accepted set: {ips:?}"
        );
    }

    /// With IPv6 disabled on the overlay (default), an IPv6 VIP is dropped — the netstack holds no
    /// v6 address to bind and the fork is IPv4-only by default.
    #[test]
    fn vip_service_v6_address_dropped_when_ipv6_disabled() {
        let vip6: IpAddr = "fd7a:115c:a1e0::1234".parse().unwrap();
        let vip4 = IpAddr::V4(Ipv4Addr::new(100, 65, 32, 1));
        let node = self_node(vec![vip4, vip6]);
        let ips = overlay_addresses(&node, false);
        assert!(ips.contains(&vip4));
        assert!(
            !ips.contains(&vip6),
            "IPv6 VIP must be dropped when IPv6 is disabled: {ips:?}"
        );
    }

    /// With IPv6 enabled, an IPv6 VIP is accepted.
    #[test]
    fn vip_service_v6_address_accepted_when_ipv6_enabled() {
        let vip6: IpAddr = "fd7a:115c:a1e0::1234".parse().unwrap();
        let node = self_node(vec![vip6]);
        let ips = overlay_addresses(&node, true);
        assert!(ips.contains(&vip6));
    }

    /// A dataplane feeding a netstack that is not draining: the pump keeps the ring's worth and
    /// drops the rest, and it finishes rather than waiting for room. Before the bound every one of
    /// these packets stayed queued.
    #[tokio::test]
    async fn pump_ingress_drops_past_the_ring_and_never_waits() {
        // Never run, so nothing takes packets off its ingress queue.
        let (_stack, pipe) = super::piped_ingress_bounded(netstack::netcore::Config::default());

        let (to_pump, from_dataplane) = tokio::sync::mpsc::unbounded_channel();
        let extra = 100;
        for _ in 0..super::INGRESS_QUEUE_PACKETS + extra {
            to_pump
                .send(vec![ts_packet::PacketMut::from(vec![0u8; 40])])
                .unwrap();
        }
        drop(to_pump);

        let dropped = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            super::pump_ingress(from_dataplane, pipe.tx, "test"),
        )
        .await
        .expect("the pump must drop on a full queue, not wait for the netstack");

        assert_eq!(dropped, extra as u64);
    }

    /// Packets bigger than the MTU (a DERP-relayed peer can send up to 64 KiB) hit the byte cap long
    /// before the packet count, so a flood of them still queues at most `INGRESS_QUEUE_PACKETS` MTUs.
    #[tokio::test]
    async fn pump_ingress_caps_bytes_for_oversized_packets() {
        let config = netstack::netcore::Config {
            mtu: 1280,
            ..Default::default()
        };
        let (_stack, pipe) = super::piped_ingress_bounded(config);

        let packet_len = 64 * 1024;
        let fits = super::INGRESS_QUEUE_PACKETS * 1280 / packet_len;
        let sent = fits + 50;

        let (to_pump, from_dataplane) = tokio::sync::mpsc::unbounded_channel();
        for _ in 0..sent {
            to_pump
                .send(vec![ts_packet::PacketMut::from(vec![0u8; packet_len])])
                .unwrap();
        }
        drop(to_pump);

        let dropped = super::pump_ingress(from_dataplane, pipe.tx, "test").await;

        assert_eq!(dropped, (sent - fits) as u64);
    }

    /// Dropping at the ingress queue is safe for TCP: with a ring so shallow that a burst overflows
    /// it, a transfer still arrives whole, because the sender retransmits what was dropped.
    ///
    /// The sender here is smoltcp, which recovers a lost burst by retransmission timeout with
    /// exponential backoff, so each overflow costs it seconds. The sizes are picked so the opening
    /// burst (about 16 segments into 8 slots) overflows once; a larger transfer through this ring
    /// still completes, just slower than a unit test should be.
    #[tokio::test]
    async fn tcp_transfer_completes_through_a_dropping_ingress_queue() {
        use core::net::{SocketAddr, SocketAddrV4};

        use netstack::{CreateSocket, HasChannel, netcore::NetstackControl};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        const CLIENT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(100, 64, 0, 1), 40000);
        const SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(100, 64, 0, 2), 8080);
        const LEN: usize = 20_000;

        let config = netstack::netcore::Config {
            mtu: 1280,
            ..Default::default()
        };

        let mut joinset = tokio::task::JoinSet::new();

        // The receiving stack sits behind the bounded ingress queue and the production pump.
        let (mut server_stack, server_pipe) =
            netstack::piped_ingress_bounded(config.clone(), 8, 8 * 1280);
        let server_channel = server_stack.command_channel();
        joinset.spawn(async move { server_stack.run_tokio().await });
        server_channel
            .set_ips([IpAddr::V4(*SERVER.ip())])
            .await
            .unwrap();

        let (mut client_stack, client_pipe) = netstack::piped(config);
        let client_channel = client_stack.command_channel();
        joinset.spawn(async move { client_stack.run_tokio().await });
        client_channel
            .set_ips([IpAddr::V4(*CLIENT.ip())])
            .await
            .unwrap();

        // Client -> server: through the dataplane-shaped channel into `pump_ingress`.
        let (to_pump, from_dataplane) = tokio::sync::mpsc::unbounded_channel();
        let mut client_rx = client_pipe.rx;
        let client_to_server = tokio::spawn(async move {
            while let Some(pkt) = client_rx.recv_async().await {
                if to_pump
                    .send(vec![ts_packet::PacketMut::from(pkt.to_vec())])
                    .is_err()
                {
                    break;
                }
            }
        });
        let pump = tokio::spawn(super::pump_ingress(from_dataplane, server_pipe.tx, "test"));

        // Server -> client: unbounded, so every drop in this test is on the bounded side.
        let mut server_rx = server_pipe.rx;
        let client_tx = client_pipe.tx;
        joinset.spawn(async move {
            while let Some(pkt) = server_rx.recv_async().await {
                client_tx.send_async(&pkt).await;
            }
        });

        let listener = server_channel
            .tcp_listen(SocketAddr::V4(SERVER))
            .await
            .unwrap();
        let reader = tokio::spawn(async move {
            let mut stream = listener.accept().await.unwrap();
            let mut got = Vec::with_capacity(LEN);
            stream.read_to_end(&mut got).await.unwrap();
            got
        });

        let sent: Vec<u8> = (0..LEN).map(|i| (i % 251) as u8).collect();
        let transfer = async {
            let mut stream = client_channel
                .tcp_connect(SocketAddr::V4(CLIENT), SocketAddr::V4(SERVER))
                .await
                .unwrap();
            stream.write_all(&sent).await.unwrap();
            stream.shutdown().await.unwrap();
            reader.await.unwrap()
        };
        let got = tokio::time::timeout(std::time::Duration::from_secs(60), transfer)
            .await
            .expect("the transfer completes despite ingress drops");

        assert!(got == sent, "the server receives exactly what was sent");

        client_to_server.abort();
        let dropped = pump.await.unwrap();
        assert!(
            dropped > 0,
            "the ingress queue overflowed, so the transfer exercised retransmission"
        );
    }
}
