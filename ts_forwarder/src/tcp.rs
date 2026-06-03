//! TCP accept → classify → dial → splice loop.

use std::sync::Arc;

use ts_netstack_smoltcp::{CreateSocket, netcore::Channel, netsock::TcpStream as OverlayTcpStream};

use crate::{class::RouteTable, dialer::RealDialer};

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

    loop {
        let overlay = listener.accept().await?;
        let routes = routes.borrow().clone();
        let dialer = dialer.clone();
        tokio::spawn(async move {
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

    let mut real = match dialer.dial_tcp(class, dst).await {
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
