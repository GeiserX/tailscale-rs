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
/// How often the idle reaper runs. Set to half [`UDP_IDLE`] so the worst-case idle lifetime of a
/// flow is ~`UDP_IDLE * 1.5` rather than ~`2 * UDP_IDLE` (the granularity error of reaping only
/// once per idle window).
const UDP_REAP_INTERVAL: Duration = Duration::from_secs(15);
/// Max time to wait for the real backend UDP dial to complete before dropping the flow.
///
/// `dial_udp` binds + `connect`s a real socket; a stalled dial must not block the per-port recv
/// loop indefinitely. On timeout the datagram is dropped (fail-closed) — never direct-dialed.
const UDP_DIAL_TIMEOUT: Duration = Duration::from_secs(10);
/// Max payload we read from a real reply socket in one go.
const MAX_DATAGRAM: usize = 65_535;
/// Max concurrent UDP flows per port. Each flow holds a real OS socket (an fd) plus a reply-pump
/// task, so without a cap a peer sweeping many distinct `(peer, dst)` pairs on one port would
/// materialize an unbounded number of sockets/tasks between reap cycles — process-wide fd
/// exhaustion. At the cap a datagram that would open a *new* flow is dropped (fail-closed, never
/// dialed), so existing flows keep working and the reaper frees slots as flows idle out. Mirrors
/// the TCP path's `MAX_INFLIGHT_SPLICES`; comparable to Go's bounded UDP conntrack table.
const MAX_UDP_FLOWS: usize = 512;

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
    let mut reap = tokio::time::interval(UDP_REAP_INTERVAL);
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
                        // Bound concurrent flows per port: at the cap, drop a datagram that would
                        // open a NEW flow (fail-closed — no dial, no socket/task) rather than let a
                        // dst-sweep exhaust fds. Existing flows are unaffected; the reaper frees
                        // slots as flows idle out.
                        if flows.len() >= MAX_UDP_FLOWS {
                            tracing::warn!(
                                %dst, %peer, max = MAX_UDP_FLOWS,
                                "drop: at max concurrent udp flows"
                            );
                            continue;
                        }
                        let Some(class) = routes.borrow().classify(dst.ip()) else {
                            tracing::warn!(%dst, %peer, "drop: destination not advertised");
                            continue;
                        };
                        let dialed = match tokio::time::timeout(
                            UDP_DIAL_TIMEOUT,
                            dialer.dial_udp(class, dst),
                        )
                        .await
                        {
                            Ok(Ok(d)) => d,
                            Ok(Err(e)) => {
                                tracing::warn!(%dst, %peer, ?class, error = %e, "udp dial refused or failed");
                                continue;
                            }
                            Err(_elapsed) => {
                                tracing::warn!(%dst, %peer, ?class, "drop: udp dial timed out");
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
