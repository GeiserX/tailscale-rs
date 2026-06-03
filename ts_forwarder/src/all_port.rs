//! On-demand all-port forwarding.
//!
//! See the crate-level "All-port forwarding and the smoltcp-0.13.1 constraint" docs for why a
//! single wildcard-port listener is impossible. This module implements the closest mechanism
//! smoltcp 0.13.1 supports: a manager that **lazily** materializes a per-port any-IP listener
//! the first time a flow to that port is observed, so steady-state socket count is the number
//! of *active* ports — not the full 1..=65535 range (which would make every packet's accept
//! scan `O(65535)` and is unusably slow).
//!
//! ## How the port is observed
//!
//! smoltcp RSTs an inbound SYN to a port with no matching listener *inside* its ingress loop,
//! before any of our code runs (`iface/interface/tcp.rs`), so we cannot react to the unmatched
//! SYN after the fact. The one lever smoltcp gives us: a `raw` socket that `accepts()` a packet
//! sets `handled_by_raw_socket = true`, which **suppresses that RST** (`process_tcp` returns
//! `None` instead of `rst_reply`). A raw `(Ipv4, Tcp)` socket therefore (a) stops the netstack
//! from RSTing SYNs to not-yet-listened ports and (b) hands us a copy of every inbound TCP
//! packet so we can read the destination port of each SYN and spin up the real listener. The
//! peer's SYN retransmit (or a SYN already buffered for re-processing) is then accepted by the
//! freshly created listener and spliced through the *same* classify → dial chokepoint as the
//! per-port path. UDP is handled analogously with a raw `(Ipv4, Udp)` observer.
//!
//! ## Anti-leak
//!
//! The raw observer never creates a host socket and never dials anything; it only learns ports.
//! Every actual flow is still accepted by an any-IP listener and routed through
//! [`run_tcp_port`] / [`run_udp_port`], i.e. the unchanged [`RouteTable`] classification and
//! [`RealDialer`] chokepoint. Opening a port on demand does not bypass exit-node refusal.

use std::{collections::BTreeSet, sync::Arc};

use ts_netstack_smoltcp::{
    CreateSocket,
    netcore::{
        Channel,
        smoltcp::wire::{IpProtocol, Ipv4Packet, TcpPacket, UdpPacket},
    },
};

use crate::{class::RouteTable, dialer::RealDialer, tcp::run_tcp_port, udp::run_udp_port};

/// Run the TCP all-port manager: observe inbound SYNs via a raw socket and lazily start a
/// per-port any-IP listener for each new destination port.
///
/// Loops until the netstack channel closes.
pub(crate) async fn run_tcp_all_ports<D: RealDialer>(
    channel: Channel,
    routes: tokio::sync::watch::Receiver<RouteTable>,
    dialer: Arc<D>,
) -> Result<(), ts_netstack_smoltcp::netcore::Error> {
    // The raw observer both suppresses the unmatched-SYN RST and reveals each SYN's dst port.
    let raw = channel.raw_open(true, IpProtocol::Tcp).await?;
    tracing::debug!("tcp all-port manager listening (raw SYN observer)");

    let mut started: BTreeSet<u16> = BTreeSet::new();

    loop {
        let packet = raw.recv_bytes().await?;
        let Some(port) = syn_dst_port(&packet) else {
            continue;
        };
        if started.insert(port) {
            tracing::debug!(%port, "all-port: starting tcp listener on demand");
            let channel = channel.clone();
            let routes = routes.clone();
            let dialer = dialer.clone();
            tokio::spawn(async move {
                if let Err(e) = run_tcp_port(channel, port, routes, dialer).await {
                    tracing::debug!(%port, error = %e, "all-port tcp listener exited");
                }
            });
        }
    }
}

/// Run the UDP all-port manager: observe inbound datagrams via a raw socket and lazily bind a
/// per-port relay for each new destination port.
///
/// Loops until the netstack channel closes.
pub(crate) async fn run_udp_all_ports<D: RealDialer>(
    channel: Channel,
    routes: tokio::sync::watch::Receiver<RouteTable>,
    dialer: Arc<D>,
) -> Result<(), ts_netstack_smoltcp::netcore::Error> {
    let raw = channel.raw_open(true, IpProtocol::Udp).await?;
    tracing::debug!("udp all-port manager listening (raw datagram observer)");

    let mut started: BTreeSet<u16> = BTreeSet::new();

    loop {
        let packet = raw.recv_bytes().await?;
        let Some(port) = udp_dst_port(&packet) else {
            continue;
        };
        if started.insert(port) {
            tracing::debug!(%port, "all-port: binding udp relay on demand");
            let channel = channel.clone();
            let routes = routes.clone();
            let dialer = dialer.clone();
            tokio::spawn(async move {
                if let Err(e) = run_udp_port(channel, port, routes, dialer).await {
                    tracing::debug!(%port, error = %e, "all-port udp relay exited");
                }
            });
        }
    }
}

/// Parse a raw IPv4 packet and return its TCP destination port iff it is a connection-initiating
/// SYN (SYN set, ACK clear). Non-TCP, malformed, or non-SYN packets yield `None`.
fn syn_dst_port(packet: &[u8]) -> Option<u16> {
    let ip = Ipv4Packet::new_checked(packet).ok()?;
    if ip.next_header() != IpProtocol::Tcp {
        return None;
    }
    let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
    // A connection-initiating SYN has SYN set and ACK clear; only those need a fresh listener.
    if tcp.syn() && !tcp.ack() {
        Some(tcp.dst_port())
    } else {
        None
    }
}

/// Parse a raw IPv4 packet and return its UDP destination port. Non-UDP or malformed packets
/// yield `None`.
fn udp_dst_port(packet: &[u8]) -> Option<u16> {
    let ip = Ipv4Packet::new_checked(packet).ok()?;
    if ip.next_header() != IpProtocol::Udp {
        return None;
    }
    let udp = UdpPacket::new_checked(ip.payload()).ok()?;
    Some(udp.dst_port())
}
