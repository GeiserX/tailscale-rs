//! UDP per-flow relay with source-spoofed replies and idle-flow expiry.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use tokio::time::Instant;
use ts_netstack_smoltcp::{CreateSocket, netcore::Channel, netsock::UdpSocket as OverlayUdpSocket};

use crate::{class::RouteTable, dialer::RealDialer};

/// How long a UDP flow may sit idle before it is reaped.
const UDP_IDLE: Duration = Duration::from_secs(30);
/// Max payload we read from a real reply socket in one go.
const MAX_DATAGRAM: usize = 65_535;

/// State for one active UDP flow, keyed by `(peer, dst)`.
struct FlowState {
    real: Arc<tokio::net::UdpSocket>,
    pump: tokio::task::AbortHandle,
    last: Instant,
}

impl Drop for FlowState {
    fn drop(&mut self) {
        self.pump.abort();
    }
}

/// Run a UDP forwarder for a single port.
///
/// Binds the wildcard address `0.0.0.0:port` on the forwarder's any-IP netstack, capturing
/// inbound datagrams to any destination IP on this port. Maintains a per-`(peer, dst)` flow to
/// a real OS UDP socket; replies are sent back with the source spoofed as the original
/// destination so the peer sees answers from the address it targeted.
///
/// Loops until the netstack channel closes.
pub(crate) async fn run_udp_port<D: RealDialer>(
    channel: Channel,
    port: u16,
    routes: tokio::sync::watch::Receiver<RouteTable>,
    dialer: Arc<D>,
) -> Result<(), ts_netstack_smoltcp::netcore::Error> {
    let bind_addr = SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), port);
    let overlay = Arc::new(channel.udp_bind(bind_addr).await?);
    tracing::debug!(%port, "udp forwarder listening");

    let mut flows: HashMap<(SocketAddr, SocketAddr), FlowState> = HashMap::new();
    let mut reap = tokio::time::interval(UDP_IDLE);
    reap.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            recv = overlay.recv_from_with_dst_bytes() => {
                let (peer, dst, payload) = recv?;

                let real = match flows.get_mut(&(peer, dst)) {
                    Some(flow) => {
                        flow.last = Instant::now();
                        flow.real.clone()
                    }
                    None => {
                        let Some(class) = routes.borrow().classify(dst.ip()) else {
                            tracing::warn!(%dst, %peer, "drop: destination not advertised");
                            continue;
                        };
                        let dialed = match dialer.dial_udp(class, dst).await {
                            Ok(d) => d,
                            Err(e) => {
                                tracing::warn!(%dst, %peer, ?class, error = %e, "udp dial refused or failed");
                                continue;
                            }
                        };
                        let real = Arc::new(dialed.sock);
                        let pump = spawn_reply_pump(
                            real.clone(),
                            overlay.clone(),
                            peer,
                            dialed.spoof_src,
                        );
                        flows.insert(
                            (peer, dst),
                            FlowState { real: real.clone(), pump, last: Instant::now() },
                        );
                        real
                    }
                };

                if let Err(e) = real.send(&payload).await {
                    tracing::debug!(%dst, %peer, error = %e, "udp forward send failed");
                    flows.remove(&(peer, dst));
                }
            }
            _ = reap.tick() => {
                let before = flows.len();
                flows.retain(|_, f| f.last.elapsed() < UDP_IDLE);
                let reaped = before - flows.len();
                if reaped > 0 {
                    tracing::trace!(reaped, "reaped idle udp flows");
                }
            }
        }
    }
}

/// Relay replies from a real UDP socket back over the overlay, spoofing the source address as
/// the original destination the peer targeted.
fn spawn_reply_pump(
    real: Arc<tokio::net::UdpSocket>,
    overlay: Arc<OverlayUdpSocket>,
    peer: SocketAddr,
    spoof_src: IpAddr,
) -> tokio::task::AbortHandle {
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            match real.recv(&mut buf).await {
                Ok(n) => {
                    if let Err(e) = overlay.send_to_from(peer, spoof_src, &buf[..n]).await {
                        tracing::debug!(%peer, %spoof_src, error = %e, "udp reply send failed");
                        return;
                    }
                }
                Err(e) => {
                    tracing::debug!(%peer, error = %e, "udp reply recv failed");
                    return;
                }
            }
        }
    })
    .abort_handle()
}
