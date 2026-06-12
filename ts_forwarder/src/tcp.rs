//! TCP accept → classify → dial → splice loop.

use std::{sync::Arc, time::Duration};

use tokio::sync::Semaphore;
use ts_netstack_smoltcp::{CreateSocket, netcore::Channel, netsock::TcpStream as OverlayTcpStream};

use crate::{class::RouteTable, dialer::RealDialer};

/// Max time to wait for the real backend dial to complete before dropping the flow.
///
/// A backend that accepts-then-stalls (or never completes the handshake) must not pin a task and
/// its sockets indefinitely. On timeout the flow is dropped (fail-closed) — never direct-dialed.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Max concurrent in-flight spliced TCP connections per port listener.
///
/// Bounds the per-flow `tokio::spawn` fan-out so a flood of accepts (especially under all-port
/// mode) cannot grow tasks/sockets without limit. When saturated, new flows are dropped rather
/// than queued — dropping an over-cap flow is fail-closed (it is never direct-dialed).
///
/// `pub(crate)` so the all-port manager's global-cap sizing invariant can be asserted in tests.
pub(crate) const MAX_INFLIGHT_SPLICES: usize = 512;

/// Run a TCP forwarder for a single port.
///
/// Listens on the wildcard address `0.0.0.0:port` of the forwarder's any-IP netstack, so it
/// captures inbound flows to *any* destination IP on this port. Each accepted flow is
/// classified against `routes`, dialed through `dialer`, and spliced.
///
/// `global_inflight` is an optional process-wide flow semaphore shared across *all* port
/// listeners of an all-port forwarder. When `Some`, each accepted flow must acquire a global
/// permit (in addition to this listener's per-port [`MAX_INFLIGHT_SPLICES`] bound) before it is
/// spliced; at the global cap the flow is dropped (fail-closed). This bounds the *aggregate*
/// concurrent flow count across the up-to-`MAX_PORTS` listeners all-port mode can spawn, whose
/// per-port caps would otherwise multiply into a multi-hundred-GiB ceiling. When `None` (the
/// explicit-port path, whose port set is operator-bounded) only the per-port cap applies.
///
/// Loops until the netstack channel closes.
pub(crate) async fn run_tcp_port<D: RealDialer>(
    channel: Channel,
    port: u16,
    routes: tokio::sync::watch::Receiver<RouteTable>,
    dialer: Arc<D>,
    global_inflight: Option<Arc<Semaphore>>,
) -> Result<(), ts_netstack_smoltcp::netcore::Error> {
    let listen_addr = std::net::SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), port);
    let listener = channel.tcp_listen(listen_addr).await?;
    tracing::debug!(%port, "tcp forwarder listening");

    // Bounds concurrent spliced flows on this listener; saturated => drop new flows.
    let inflight = Arc::new(Semaphore::new(MAX_INFLIGHT_SPLICES));

    loop {
        let overlay = listener.accept().await?;
        // Acquire a slot up front; if none is free we are at capacity, so drop the flow rather
        // than spawn an unbounded task. Dropping is fail-closed: it never direct-dials.
        let Ok(permit) = inflight.clone().try_acquire_owned() else {
            tracing::warn!(
                %port,
                peer = %overlay.remote_addr(),
                "drop: at max in-flight tcp splices ({MAX_INFLIGHT_SPLICES})"
            );
            continue;
        };
        // Then, if a global (cross-port) cap is configured, acquire an owned global permit too.
        // Ordering is per-port first (above) then global (here): both are non-blocking
        // `try_acquire_owned`, so neither can stall the accept loop and there is no lock held
        // across an await. At the global cap we DROP the flow (fail-closed, never direct-dial),
        // exactly like the per-port drop. `None` => no global gate (behaves as before).
        let global_permit = match &global_inflight {
            Some(sem) => {
                let Ok(gp) = sem.clone().try_acquire_owned() else {
                    tracing::warn!(
                        %port,
                        peer = %overlay.remote_addr(),
                        "drop: at max GLOBAL in-flight tcp splices"
                    );
                    continue;
                };
                Some(gp)
            }
            None => None,
        };
        let routes = routes.borrow().clone();
        let dialer = dialer.clone();
        tokio::spawn(async move {
            // Hold both permits for the whole splice lifetime; released on drop.
            let _permit = permit;
            let _global = global_permit;
            splice_one(overlay, routes, dialer).await;
        });
    }
}

/// Classify, dial, and bidirectionally splice a single accepted overlay flow.
async fn splice_one<D: RealDialer>(
    mut overlay: OverlayTcpStream,
    routes: RouteTable,
    dialer: Arc<D>,
) {
    // The original packet destination, captured under any-IP acceptance. This is what the peer
    // intended to reach, and what we must dial.
    let dst = overlay.local_addr();
    let peer = overlay.remote_addr();

    let Some(class) = routes.classify(dst.ip()) else {
        tracing::warn!(%dst, %peer, "drop: destination not advertised");
        return;
    };

    // Bound the dial: a backend that accepts-then-stalls must not pin this task forever. On
    // timeout we drop the flow (fail-closed) — never fall back to a direct dial.
    let dialed = match tokio::time::timeout(DIAL_TIMEOUT, dialer.dial_tcp(class, dst)).await {
        Ok(result) => result,
        Err(_elapsed) => {
            tracing::warn!(%dst, %peer, ?class, "drop: tcp dial timed out");
            return;
        }
    };

    let mut real = match dialed {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(%dst, %peer, ?class, error = %e, "tcp dial refused or failed");
            return;
        }
    };

    match tokio::io::copy_bidirectional(&mut overlay, &mut real).await {
        Ok((to_real, to_peer)) => {
            tracing::debug!(%dst, %peer, to_real, to_peer, "tcp splice finished");
        }
        Err(e) => {
            tracing::debug!(%dst, %peer, error = %e, "tcp splice ended");
        }
    }
}

#[cfg(test)]
mod tests {
    use core::{
        net::{Ipv4Addr, SocketAddr},
        sync::atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;

    use ts_netstack_smoltcp::{
        CreateSocket, Netstack, WakingPipe, WakingPipeDev,
        netcore::{self, Channel, HasChannel, NetstackControl, smoltcp},
    };

    use super::*;
    use crate::dialer::DirectDialer;

    const PEER_IP: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);

    /// Piped peer/forwarder netstacks: the forwarder stack has any-IP acceptance (captures flows to
    /// destinations it does not own); the peer stack owns `PEER_IP`. Mirrors the integration-test
    /// harness so the cross-port global-cap test exercises the real accept→classify→dial path.
    async fn spawn_pair() -> (Channel, Channel) {
        let config = netcore::Config::default();
        let (p1, p2) = WakingPipe::new(None);
        let dev1 = WakingPipeDev {
            pipe: p1,
            mtu: 1500,
            medium: smoltcp::phy::Medium::Ip,
        };
        let dev2 = WakingPipeDev {
            pipe: p2,
            mtu: 1500,
            medium: smoltcp::phy::Medium::Ip,
        };
        let mut peer = Netstack::new(dev1, config.clone());
        let mut fwd = Netstack::new(dev2, config);
        let peer_ch = peer.command_channel();
        let fwd_ch = fwd.command_channel();
        tokio::spawn(async move { peer.run_tokio().await });
        tokio::spawn(async move { fwd.run_tokio().await });
        peer_ch.set_ips([PEER_IP.into()]).await.unwrap();
        fwd_ch.set_any_ip(true).await.unwrap();
        (peer_ch, fwd_ch)
    }

    /// A loopback TCP server that counts accepted connections and then HOLDS each open (never reads
    /// to EOF, never replies), so every spliced flow stays in-flight and keeps holding its permits.
    /// Returns `(addr, accept_count)`. The count is the number of flows that reached a real dial —
    /// the quantity the global cap must bound across ports.
    async fn spawn_holding_counting_sink() -> (SocketAddr, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let count_for_task = count.clone();
        tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                let (sock, _) = listener.accept().await.unwrap();
                count_for_task.fetch_add(1, Ordering::SeqCst);
                held.push(sock); // hold the socket open so the splice never finishes
            }
        });
        (addr, count)
    }

    /// End-to-end cross-port global cap: two `run_tcp_port` listeners (distinct ports) share ONE
    /// small global semaphore sized BELOW `2 × MAX_INFLIGHT_SPLICES`. Many more flows than the
    /// global cap are opened across BOTH ports and held; the real sink must accept at MOST the
    /// global cap (the aggregate ceiling held across ports) yet at LEAST one (forwarding works).
    /// This proves the shared semaphore caps aggregate concurrent flows across ports — the gap a
    /// per-port-only cap leaves open.
    #[tokio::test]
    async fn global_cap_bounds_aggregate_inflight_across_two_ports() {
        // A small global cap so the test is fast and the bound is unambiguous (and far below the
        // 2×512 a per-port-only scheme would permit across two ports).
        const GLOBAL: usize = 4;
        // Sanity: the global cap is below what two ports could admit on per-port caps alone, so any
        // ceiling at GLOBAL must come from the shared semaphore, not the per-port caps.
        const { assert!(GLOBAL < 2 * MAX_INFLIGHT_SPLICES) };

        let (sink_addr, accepts) = spawn_holding_counting_sink().await;
        let (peer_ch, fwd_ch) = spawn_pair().await;

        // 127.0.0.0/8 is a subnet route -> DirectDialer dials it (no exit-egress refusal).
        let routes = RouteTable::new(["127.0.0.0/8".parse().unwrap()]);
        let (routes_tx, routes_rx) = tokio::sync::watch::channel(routes);
        let _routes_tx = routes_tx; // keep the watch channel open for the listeners' lifetime
        let dialer = Arc::new(DirectDialer);
        let global = Arc::new(Semaphore::new(GLOBAL));

        // Two listeners on DIFFERENT ports, both sharing the SAME global semaphore — exactly how
        // the all-port manager wires every on-demand port to one shared cap.
        let port_a = sink_addr.port();
        let port_b = port_a.checked_add(1).expect("port + 1 fits u16");
        for port in [port_a, port_b] {
            let ch = fwd_ch.clone();
            let rx = routes_rx.clone();
            let d = dialer.clone();
            let g = global.clone();
            tokio::spawn(async move {
                let _ = run_tcp_port(ch, port, rx, d, Some(g)).await;
            });
        }

        // Open many more flows than the global cap, split across the two ports, and HOLD them all
        // open (drop nothing) so their permits stay held. The sink address is the same for both
        // ports (the dst the peer targets); only the dst PORT differs, hitting the two listeners.
        let mut clients = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        for i in 0..(GLOBAL * 3) {
            let port = if i % 2 == 0 { port_a } else { port_b };
            let dst = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port);
            // Each flow uses a distinct peer source port so they are independent overlay flows.
            let local = SocketAddr::new(PEER_IP.into(), 20000 + i as u16);
            loop {
                match peer_ch.tcp_connect(local, dst).await {
                    Ok(stream) => {
                        clients.push(stream); // hold it open
                        break;
                    }
                    Err(_) if tokio::time::Instant::now() < deadline => {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    // Over the global cap the listener accepts the overlay flow but drops it before
                    // dial; the overlay connect itself still succeeds (it is the splice that is
                    // dropped), so a connect error here is only a not-yet-ready listener. Give up
                    // this one flow past the deadline rather than hang the test.
                    Err(_) => break,
                }
            }
        }

        // Let every admitted flow reach its real dial (the sink increments on accept). A settle for
        // a bounded assertion: the count can only rise toward the cap, never past it, so a generous
        // wait cannot cause a spurious failure.
        tokio::time::sleep(Duration::from_millis(800)).await;

        let dialed = accepts.load(Ordering::SeqCst);
        assert!(
            dialed >= 1,
            "forwarding must work: at least one flow should reach the real sink"
        );
        assert!(
            dialed <= GLOBAL,
            "global cap must bound AGGREGATE in-flight flows across both ports to <= {GLOBAL}, \
             but the real sink accepted {dialed} (a per-port-only cap would allow up to {})",
            2 * MAX_INFLIGHT_SPLICES
        );
    }
}
