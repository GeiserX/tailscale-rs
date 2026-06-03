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
const MAX_INFLIGHT_SPLICES: usize = 512;

/// Run a TCP forwarder for a single port.
///
/// Listens on the wildcard address `0.0.0.0:port` of the forwarder's any-IP netstack, so it
/// captures inbound flows to *any* destination IP on this port. Each accepted flow is
/// classified against `routes`, dialed through `dialer`, and spliced.
///
/// Loops until the netstack channel closes.
pub(crate) async fn run_tcp_port<D: RealDialer>(
    channel: Channel,
    port: u16,
    routes: tokio::sync::watch::Receiver<RouteTable>,
    dialer: Arc<D>,
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
        let routes = routes.borrow().clone();
        let dialer = dialer.clone();
        tokio::spawn(async move {
            // Hold the permit for the whole splice lifetime; released on drop.
            let _permit = permit;
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
