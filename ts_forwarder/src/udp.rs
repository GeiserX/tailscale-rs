//! UDP per-flow relay with source-spoofed replies and idle-flow expiry.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    time::Instant,
};
use ts_netstack_smoltcp::{CreateSocket, netcore::Channel, netsock::UdpSocket as OverlayUdpSocket};

use crate::{class::RouteTable, dialer::RealDialer};

/// How long a UDP flow may go without a datagram in either direction before it is reaped. Matches
/// Go's netstack forwarder: 2 minutes, so QUIC/streaming flows survive quiet stretches.
const UDP_IDLE: Duration = Duration::from_secs(120);
/// [`UDP_IDLE`] for port 53: DNS flows are one-shot, so their sockets are released sooner (Go's
/// value too).
const UDP_IDLE_DNS: Duration = Duration::from_secs(30);

/// The idle timeout for flows on `port`.
fn udp_idle(port: u16) -> Duration {
    if port == 53 { UDP_IDLE_DNS } else { UDP_IDLE }
}
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
///
/// `pub(crate)` so the all-port manager's global-cap sizing invariant can be asserted in tests.
pub(crate) const MAX_UDP_FLOWS: usize = 512;

/// State for one active UDP flow, keyed by `(peer, dst)`.
struct FlowState {
    real: Arc<tokio::net::UdpSocket>,
    pump: tokio::task::AbortHandle,
    /// Last datagram in either direction, in milliseconds since the port's epoch. The reply pump
    /// updates it too, so a flow that mostly receives (a stream answering a quiet client) is not
    /// reaped while replies are still flowing.
    last: Arc<AtomicU64>,
    /// Owned permit from the optional process-wide (cross-port) flow semaphore, held for the
    /// flow's lifetime: it is released when this `FlowState` is dropped (i.e. when the flow is
    /// reaped for idleness or removed on a send error), freeing a slot in the global budget.
    /// `None` when no global cap is configured (the explicit-port path).
    _global_permit: Option<OwnedSemaphorePermit>,
    /// The port's live-flow count, decremented when this flow ends.
    live: Option<Arc<AtomicUsize>>,
}

impl Drop for FlowState {
    fn drop(&mut self) {
        self.pump.abort();
        if let Some(live) = &self.live {
            live.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Run a UDP forwarder for a single port.
///
/// Binds the wildcard address `0.0.0.0:port` on the forwarder's any-IP netstack, capturing
/// inbound datagrams to any destination IP on this port. Maintains a per-`(peer, dst)` flow to
/// a real OS UDP socket; replies are sent back with the source spoofed as the original
/// destination so the peer sees answers from the address it targeted.
///
/// `global_flows` is an optional process-wide flow semaphore shared across *all* port relays of
/// an all-port forwarder. When `Some`, opening a NEW flow must acquire a global permit (in
/// addition to this relay's per-port [`MAX_UDP_FLOWS`] bound); at the global cap the datagram is
/// dropped (fail-closed). The permit is stored in the flow's [`FlowState`] and released when the
/// flow ends, so it bounds the *aggregate* flow count across the up-to-`MAX_PORTS` relays
/// all-port mode can spawn. When `None` (the explicit-port path) only the per-port cap applies.
///
/// `ready` fires once the port is bound. `live`, if given, tracks this port's open flow count,
/// so an owner can tell a quiet port from one that is still relaying replies.
///
/// Loops until the netstack channel closes.
pub(crate) async fn run_udp_port<D: RealDialer>(
    channel: Channel,
    port: u16,
    routes: tokio::sync::watch::Receiver<RouteTable>,
    dialer: Arc<D>,
    global_flows: Option<Arc<Semaphore>>,
    ready: Option<tokio::sync::oneshot::Sender<()>>,
    live: Option<Arc<AtomicUsize>>,
) -> Result<(), ts_netstack_smoltcp::netcore::Error> {
    let bind_addr = SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), port);
    let overlay = Arc::new(channel.udp_bind(bind_addr).await?);
    tracing::debug!(%port, "udp forwarder listening");
    if let Some(ready) = ready {
        let _ = ready.send(());
    }

    let idle = udp_idle(port);
    let epoch = Instant::now();
    let now_ms = move || u64::try_from(epoch.elapsed().as_millis()).unwrap_or(u64::MAX);
    let mut flows: HashMap<(SocketAddr, SocketAddr), FlowState> = HashMap::new();
    // Reap at half the idle window so a flow lives at most ~1.5x `idle` after its last datagram.
    let mut reap = tokio::time::interval(idle / 2);
    reap.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            recv = overlay.recv_from_with_dst_bytes() => {
                let (peer, dst, payload) = recv?;

                let real = match flows.get_mut(&(peer, dst)) {
                    Some(flow) => {
                        flow.last.store(now_ms(), Ordering::Relaxed);
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
                        // Then, if a global (cross-port) cap is configured, reserve a global slot
                        // for this new flow. Non-blocking `try_acquire_owned` so the recv loop is
                        // never stalled; at the global cap we DROP the datagram (fail-closed, no
                        // dial/socket), exactly like the per-port drop. The permit is held in the
                        // flow's `FlowState` and released when the flow ends. `None` => no global
                        // gate (behaves as before). Acquired before the dial so an over-cap flow
                        // opens no real socket.
                        let global_permit = match &global_flows {
                            Some(sem) => {
                                let Ok(gp) = sem.clone().try_acquire_owned() else {
                                    tracing::warn!(
                                        %dst, %peer,
                                        "drop: at max GLOBAL udp flows"
                                    );
                                    continue;
                                };
                                Some(gp)
                            }
                            None => None,
                        };
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
                        let last = Arc::new(AtomicU64::new(now_ms()));
                        let pump = spawn_reply_pump(
                            real.clone(),
                            overlay.clone(),
                            peer,
                            dialed.spoof_src,
                            last.clone(),
                            now_ms,
                        );
                        flows.insert(
                            (peer, dst),
                            FlowState {
                                real: real.clone(),
                                pump,
                                last,
                                _global_permit: global_permit,
                                live: live.clone().inspect(|l| {
                                    l.fetch_add(1, Ordering::Relaxed);
                                }),
                            },
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
                // Age, not a `now - idle` cutoff: near the epoch that cutoff saturates to 0, and a
                // flow created in the port's first millisecond (`last == 0`, e.g. the gate's held
                // first datagram) would be reaped by `interval`'s immediate first tick.
                let (now, idle_ms) = (now_ms(), u64::try_from(idle.as_millis()).unwrap_or(u64::MAX));
                flows.retain(|_, f| now.saturating_sub(f.last.load(Ordering::Relaxed)) < idle_ms);
                let reaped = before - flows.len();
                if reaped > 0 {
                    tracing::trace!(reaped, "reaped idle udp flows");
                }
            }
        }
    }
}

/// Relay replies from a real UDP socket back over the overlay, spoofing the source address as
/// the original destination the peer targeted. Each reply refreshes the flow's `last` activity.
///
/// A reply the overlay socket can't send (e.g. larger than its buffer) is dropped; the pump keeps
/// running, so one oversized datagram doesn't silence the rest of the flow.
fn spawn_reply_pump(
    real: Arc<tokio::net::UdpSocket>,
    overlay: Arc<OverlayUdpSocket>,
    peer: SocketAddr,
    spoof_src: IpAddr,
    last: Arc<AtomicU64>,
    now_ms: impl Fn() -> u64 + Send + 'static,
) -> tokio::task::AbortHandle {
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            match real.recv(&mut buf).await {
                Ok(n) => {
                    last.store(now_ms(), Ordering::Relaxed);
                    if let Err(e) = overlay.send_to_from(peer, spoof_src, &buf[..n]).await {
                        tracing::debug!(%peer, %spoof_src, len = n, error = %e, "udp reply dropped");
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Go's netstack forwarder timeouts: 2 min for UDP flows, 30 s for DNS.
    #[test]
    fn idle_timeouts_match_go() {
        assert_eq!(udp_idle(53), Duration::from_secs(30));
        assert_eq!(udp_idle(443), Duration::from_secs(120));
        assert_eq!(udp_idle(3478), Duration::from_secs(120));
    }
}
