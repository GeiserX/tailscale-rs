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

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use ts_netstack_smoltcp::{
    CreateSocket,
    netcore::{
        Channel,
        smoltcp::wire::{IpProtocol, Ipv4Packet, TcpPacket, UdpPacket},
    },
};

use crate::{class::RouteTable, dialer::RealDialer, tcp::run_tcp_port, udp::run_udp_port};

/// Maximum number of distinct ports that may have a live on-demand listener at once.
///
/// Without a cap a remote could scan all 65,535 ports and permanently materialize that many
/// tasks + netstack sockets (remote FD/memory-exhaustion DoS). Once this many ports are active,
/// SYNs/datagrams to *new* ports are dropped (no listener spawned) until a port is evicted.
/// Dropping an over-cap port is fail-closed: nothing is dialed.
const MAX_PORTS: usize = 1024;

/// How long an on-demand per-port listener may go without any observed inbound packet before it
/// is reaped (its task aborted and the port freed so a later packet can re-trigger it). Bounds
/// dormant per-port listeners after a scan.
const PORT_IDLE: Duration = Duration::from_secs(120);

/// How often the idle-port reaper runs (half [`PORT_IDLE`] to keep worst-case dormant lifetime
/// near `PORT_IDLE` rather than double it).
const PORT_REAP_INTERVAL: Duration = Duration::from_secs(60);

/// Bookkeeping for one on-demand per-port listener owned by an all-port manager.
struct PortEntry {
    /// Aborts the listener task on eviction / manager drop.
    handle: tokio::task::AbortHandle,
    /// Last time an inbound packet for this port was observed (for idle eviction).
    last: Instant,
}

impl Drop for PortEntry {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

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

    // (port, exited) channel: a per-port listener task sends its port back when it exits so the
    // manager removes it from the active set (so a retransmit re-triggers it). See [`#2`].
    let (exit_tx, mut exit_rx) = tokio::sync::mpsc::unbounded_channel::<u16>();
    let mut ports: HashMap<u16, PortEntry> = HashMap::new();
    let mut reap = tokio::time::interval(PORT_REAP_INTERVAL);
    reap.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            packet = raw.recv_bytes() => {
                let packet = packet?;
                let Some(port) = syn_dst_port(&packet) else {
                    continue;
                };
                if let Some(entry) = ports.get_mut(&port) {
                    entry.last = Instant::now();
                    continue;
                }
                if ports.len() >= MAX_PORTS {
                    tracing::warn!(%port, "all-port: at max active tcp ports ({MAX_PORTS}); dropping new port");
                    continue;
                }
                tracing::debug!(%port, "all-port: starting tcp listener on demand");
                let channel = channel.clone();
                let routes = routes.clone();
                let dialer = dialer.clone();
                let exit_tx = exit_tx.clone();
                let handle = tokio::spawn(async move {
                    if let Err(e) = run_tcp_port(channel, port, routes, dialer).await {
                        // Listener bind/accept error: free the port so a retransmit re-triggers it.
                        tracing::warn!(%port, error = %e, "all-port tcp listener exited");
                    }
                    let _ = exit_tx.send(port);
                })
                .abort_handle();
                ports.insert(port, PortEntry { handle, last: Instant::now() });
            }
            Some(port) = exit_rx.recv() => {
                // The listener task exited; drop bookkeeping so the port can re-trigger (#2).
                ports.remove(&port);
            }
            _ = reap.tick() => {
                let before = ports.len();
                // Aborts each evicted listener via PortEntry::drop, freeing the port (#1).
                ports.retain(|_, e| e.last.elapsed() < PORT_IDLE);
                let reaped = before - ports.len();
                if reaped > 0 {
                    tracing::debug!(reaped, "all-port: reaped idle tcp listeners");
                }
            }
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

    let (exit_tx, mut exit_rx) = tokio::sync::mpsc::unbounded_channel::<u16>();
    let mut ports: HashMap<u16, PortEntry> = HashMap::new();
    let mut reap = tokio::time::interval(PORT_REAP_INTERVAL);
    reap.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            packet = raw.recv_bytes() => {
                let packet = packet?;
                let Some(port) = udp_dst_port(&packet) else {
                    continue;
                };
                if let Some(entry) = ports.get_mut(&port) {
                    entry.last = Instant::now();
                    continue;
                }
                if ports.len() >= MAX_PORTS {
                    tracing::warn!(%port, "all-port: at max active udp ports ({MAX_PORTS}); dropping new port");
                    continue;
                }
                tracing::debug!(%port, "all-port: binding udp relay on demand");
                let channel = channel.clone();
                let routes = routes.clone();
                let dialer = dialer.clone();
                let exit_tx = exit_tx.clone();
                let handle = tokio::spawn(async move {
                    if let Err(e) = run_udp_port(channel, port, routes, dialer).await {
                        // Relay bind error: free the port so a later datagram re-triggers it.
                        tracing::warn!(%port, error = %e, "all-port udp relay exited");
                    }
                    let _ = exit_tx.send(port);
                })
                .abort_handle();
                ports.insert(port, PortEntry { handle, last: Instant::now() });
            }
            Some(port) = exit_rx.recv() => {
                ports.remove(&port);
            }
            _ = reap.tick() => {
                let before = ports.len();
                ports.retain(|_, e| e.last.elapsed() < PORT_IDLE);
                let reaped = before - ports.len();
                if reaped > 0 {
                    tracing::debug!(reaped, "all-port: reaped idle udp relays");
                }
            }
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

#[cfg(test)]
mod tests {
    use ts_netstack_smoltcp::netcore::smoltcp::wire::Ipv4Address;

    use super::*;

    /// Build a minimal IPv4 packet carrying `payload` for `proto`. Checksums are left zero — the
    /// parsers use `new_checked` (length validation), not checksum verification.
    fn ipv4(proto: IpProtocol, payload: &[u8]) -> Vec<u8> {
        const IHL: usize = 20;
        let total = IHL + payload.len();
        let mut buf = vec![0u8; total];
        let mut ip = Ipv4Packet::new_unchecked(&mut buf);
        ip.set_version(4);
        ip.set_header_len(IHL as u8);
        ip.set_total_len(total as u16);
        ip.set_hop_limit(64);
        ip.set_next_header(proto);
        ip.set_src_addr(Ipv4Address::new(10, 0, 0, 1));
        ip.set_dst_addr(Ipv4Address::new(10, 0, 0, 2));
        ip.payload_mut().copy_from_slice(payload);
        buf
    }

    fn tcp_segment(dst_port: u16, syn: bool, ack: bool) -> Vec<u8> {
        let mut seg = vec![0u8; 20];
        let mut tcp = TcpPacket::new_unchecked(&mut seg);
        tcp.set_src_port(12345);
        tcp.set_dst_port(dst_port);
        tcp.set_header_len(20);
        tcp.set_syn(syn);
        tcp.set_ack(ack);
        seg
    }

    fn udp_datagram(dst_port: u16) -> Vec<u8> {
        let mut dg = vec![0u8; 8];
        let mut udp = UdpPacket::new_unchecked(&mut dg);
        udp.set_src_port(12345);
        udp.set_dst_port(dst_port);
        udp.set_len(8);
        dg
    }

    #[test]
    fn syn_dst_port_reads_connection_initiating_syn() {
        let pkt = ipv4(IpProtocol::Tcp, &tcp_segment(443, true, false));
        assert_eq!(syn_dst_port(&pkt), Some(443));
    }

    #[test]
    fn syn_dst_port_ignores_syn_ack_and_non_syn() {
        // SYN+ACK is a handshake reply, not a new connection — no fresh listener needed.
        let synack = ipv4(IpProtocol::Tcp, &tcp_segment(443, true, true));
        assert_eq!(syn_dst_port(&synack), None);
        // A plain ACK (established traffic) also yields no new port.
        let ack = ipv4(IpProtocol::Tcp, &tcp_segment(443, false, true));
        assert_eq!(syn_dst_port(&ack), None);
    }

    #[test]
    fn syn_dst_port_ignores_non_tcp_and_malformed() {
        let udp = ipv4(IpProtocol::Udp, &udp_datagram(443));
        assert_eq!(syn_dst_port(&udp), None);
        assert_eq!(syn_dst_port(&[0u8; 4]), None);
    }

    #[test]
    fn udp_dst_port_reads_dst_and_rejects_non_udp() {
        let pkt = ipv4(IpProtocol::Udp, &udp_datagram(53));
        assert_eq!(udp_dst_port(&pkt), Some(53));
        let tcp = ipv4(IpProtocol::Tcp, &tcp_segment(53, true, false));
        assert_eq!(udp_dst_port(&tcp), None);
        assert_eq!(udp_dst_port(&[0u8; 4]), None);
    }

    /// Guard rails on the DoS caps: the active-port cap is bounded and the reaper runs at least
    /// twice per idle window so worst-case dormant lifetime stays near `PORT_IDLE`, not double it.
    #[test]
    fn port_caps_are_bounded() {
        // Cap must stay well below the full 1..=65535 range so a port scan can't materialize a
        // listener per port (the DoS this guards against).
        assert_eq!(MAX_PORTS, 1024);
        // Reaper must run at least twice per idle window so worst-case dormant lifetime stays
        // near PORT_IDLE rather than ~2x it.
        assert!(PORT_REAP_INTERVAL <= PORT_IDLE / 2);
    }
}
