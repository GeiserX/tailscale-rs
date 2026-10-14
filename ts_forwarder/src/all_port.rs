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
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use tokio::sync::Semaphore;
use ts_netstack_smoltcp::{
    CreateSocket,
    netcore::{
        Channel,
        smoltcp::wire::{IpProtocol, Ipv4Packet, TcpPacket, UdpPacket},
    },
};

use crate::{
    class::RouteTable,
    dialer::RealDialer,
    port_gate::{OpenRequests, PortGate, PortRef, Proto},
    tcp::run_tcp_port,
    udp::run_udp_port,
};

/// Maximum number of distinct ports that may have a live on-demand listener at once.
///
/// Without a cap a remote could scan all 65,535 ports and permanently materialize that many
/// tasks + netstack sockets (remote FD/memory-exhaustion DoS). Once this many ports are active,
/// SYNs/datagrams to *new* ports are dropped (no listener spawned) until a port is evicted.
/// Dropping an over-cap port is fail-closed: nothing is dialed.
pub(crate) const MAX_PORTS: usize = 1024;

/// How long an on-demand per-port listener may go without any observed inbound packet before it
/// is reaped (its task aborted and the port freed so a later packet can re-trigger it). Bounds
/// dormant per-port listeners after a scan.
const PORT_IDLE: Duration = Duration::from_secs(120);

/// How often the idle-port reaper runs (half [`PORT_IDLE`] to keep worst-case dormant lifetime
/// near `PORT_IDLE` rather than double it).
const PORT_REAP_INTERVAL: Duration = Duration::from_secs(60);

/// Process-wide cap on concurrent in-flight TCP splices summed across *all* on-demand ports.
///
/// The per-port [`MAX_INFLIGHT_SPLICES`](crate::tcp) (512) bounds one listener, but all-port mode
/// can spawn up to [`MAX_PORTS`] (1024) listeners, so the per-port caps multiply: 1024 × 512 ≈
/// 524,288 concurrent splices. At ~512 KiB of netstack buffers per flow (≈256 KiB per direction,
/// see AGENTS.md) that is a ≈256 GiB ceiling — a port-sweeping peer in all-port mode could OOM the
/// node. This shared cap bounds the *aggregate* instead. It is acquired in addition to (underneath)
/// the per-port cap, so a single port still cannot exceed its own 512 even when the global budget
/// is free. Sized to the AGENTS.md envelope — ~1000 concurrent TCP flows ≈ ~512 MB — rounded up to
/// 2048 (a ≈1 GiB ceiling: generous but bounded, and 256× below the old ≈524K/≈256 GiB ceiling).
const MAX_GLOBAL_TCP_SPLICES: usize = 2048;

/// Process-wide cap on concurrent UDP flows summed across *all* on-demand ports.
///
/// The UDP analogue of [`MAX_GLOBAL_TCP_SPLICES`]: the per-port [`MAX_UDP_FLOWS`](crate::udp) (512)
/// bounds one relay, but up to [`MAX_PORTS`] relays multiply it, so without a global cap a UDP
/// port-sweep could materialize ≈524,288 real OS sockets (process-wide fd exhaustion). Set to 2048
/// to match the TCP ceiling; the per-port 512 still applies underneath so a single port cannot hog
/// the whole global budget.
const MAX_GLOBAL_UDP_FLOWS: usize = 2048;

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

    // One global flow semaphore shared across every on-demand port listener of this manager, so
    // the aggregate in-flight splice count is capped regardless of how many ports go active. Each
    // `run_tcp_port` gets a clone; a flow holds a global permit for its lifetime (in addition to
    // the per-port cap). Bounds the per-port × MAX_PORTS multiplier (see [`MAX_GLOBAL_TCP_SPLICES`]).
    let global_inflight = Arc::new(Semaphore::new(MAX_GLOBAL_TCP_SPLICES));

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
                let global_inflight = global_inflight.clone();
                let handle = tokio::spawn(async move {
                    if let Err(e) =
                        run_tcp_port(channel, port, routes, dialer, Some(global_inflight), None).await
                    {
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

    // One global flow semaphore shared across every on-demand UDP relay of this manager (the UDP
    // analogue of the TCP manager's `global_inflight`); caps aggregate concurrent UDP flows across
    // all ports. See [`MAX_GLOBAL_UDP_FLOWS`].
    let global_flows = Arc::new(Semaphore::new(MAX_GLOBAL_UDP_FLOWS));

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
                let global_flows = global_flows.clone();
                let handle = tokio::spawn(async move {
                    if let Err(e) =
                        run_udp_port(channel, port, routes, dialer, Some(global_flows), None, None).await
                    {
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

/// How long a gated port may stay opening (listener not yet registered) before it is torn down
/// and its held packets dropped. Registering a listener is one netstack round trip.
const PORT_OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// Run the gated all-port manager: open a per-port listener for each port the [`PortGate`] asks
/// for, tell the gate once it is registered (releasing the held packets), and tear down idle
/// ports.
///
/// Serves TCP and UDP together. The active-port cap ([`MAX_PORTS`]) and the global flow caps are
/// the same as in raw-observer mode; the gate enforces the port cap before asking.
///
/// Every listener is identified by a generation ([`PortRef`]) and owned by this function's
/// `JoinSet`: dropping or cancelling the manager aborts all of them, and every way a listener can
/// end (exit, error, panic, abort) is reported to the gate exactly once, for its own generation.
///
/// Returns when the netstack channel closes (a listener fails with `InternalChannelClosed`).
pub(crate) async fn run_gated_all_ports<D: RealDialer>(
    channel: Channel,
    routes: tokio::sync::watch::Receiver<RouteTable>,
    dialer: Arc<D>,
    gate: PortGate,
    mut requests: OpenRequests,
) -> Result<(), ts_netstack_smoltcp::netcore::Error> {
    use ts_netstack_smoltcp::netcore::{Error, InternalErrorKind};

    let global_tcp = Arc::new(Semaphore::new(MAX_GLOBAL_TCP_SPLICES));
    let global_udp = Arc::new(Semaphore::new(MAX_GLOBAL_UDP_FLOWS));
    let (ready_tx, mut ready_rx) = tokio::sync::mpsc::unbounded_channel::<PortRef>();

    // The current listener per port: its generation, abort handle and (UDP) live-flow count. A UDP
    // port's flows live in its task, so it is not torn down while it has any; TCP flows outlive
    // their listener.
    struct Listener {
        generation: u32,
        abort: tokio::task::AbortHandle,
        live_flows: Option<Arc<AtomicUsize>>,
    }
    let mut listeners: HashMap<(Proto, u16), Listener> = HashMap::new();
    let mut tasks = tokio::task::JoinSet::new();
    let mut task_ports: HashMap<tokio::task::Id, PortRef> = HashMap::new();

    let start = |port_ref: PortRef,
                 tasks: &mut tokio::task::JoinSet<Result<(), Error>>,
                 task_ports: &mut HashMap<tokio::task::Id, PortRef>,
                 listeners: &mut HashMap<(Proto, u16), Listener>| {
        let (proto, port, generation) = port_ref;
        tracing::debug!(?proto, %port, generation, "all-port: opening listener for gated port");
        let live_flows = (proto == Proto::Udp).then(|| Arc::new(AtomicUsize::new(0)));
        let (channel, routes, dialer) = (channel.clone(), routes.clone(), dialer.clone());
        let (global_tcp, global_udp) = (global_tcp.clone(), global_udp.clone());
        let (port_live, ready_tx) = (live_flows.clone(), ready_tx.clone());
        let abort = tasks.spawn(async move {
            let (registered_tx, registered_rx) = tokio::sync::oneshot::channel();
            let listener = async move {
                match proto {
                    Proto::Tcp => {
                        run_tcp_port(
                            channel,
                            port,
                            routes,
                            dialer,
                            Some(global_tcp),
                            Some(registered_tx),
                        )
                        .await
                    }
                    Proto::Udp => {
                        run_udp_port(
                            channel,
                            port,
                            routes,
                            dialer,
                            Some(global_udp),
                            Some(registered_tx),
                            port_live,
                        )
                        .await
                    }
                }
            };
            tokio::pin!(listener);
            tokio::select! {
                biased;
                res = &mut listener => return res,
                registered = registered_rx => {
                    if registered.is_ok() {
                        let _ = ready_tx.send(port_ref);
                    }
                }
            }
            listener.await
        });
        task_ports.insert(abort.id(), port_ref);
        let old = listeners.insert(
            (proto, port),
            Listener {
                generation,
                abort,
                live_flows,
            },
        );
        // The gate only asks for a new generation once the previous one has ended.
        debug_assert!(old.is_none(), "port {port} opened twice");
    };

    let mut reap = tokio::time::interval(PORT_REAP_INTERVAL.min(PORT_OPEN_TIMEOUT));
    reap.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            req = requests.0.recv() => {
                // The gate keeps a sender while it exists, and we hold the gate.
                let Some(port_ref) = req else { return Ok(()) };
                start(port_ref, &mut tasks, &mut task_ports, &mut listeners);
            }
            Some(port_ref) = ready_rx.recv() => {
                let refused = gate.mark_open(port_ref);
                if refused > 0 {
                    tracing::debug!(port = port_ref.1, refused, "all-port: ingress full; held packets dropped");
                }
            }
            Some(done) = tasks.join_next_with_id() => {
                let (id, outcome) = match done {
                    Ok((id, res)) => (id, Ok(res)),
                    Err(e) => (e.id(), Err(e)),
                };
                let Some(port_ref @ (proto, port, generation)) = task_ports.remove(&id) else {
                    continue;
                };
                if listeners.get(&(proto, port)).is_some_and(|l| l.generation == generation) {
                    listeners.remove(&(proto, port));
                }
                match outcome {
                    Ok(Err(e @ Error::Internal(InternalErrorKind::InternalChannelClosed))) => return Err(e),
                    Ok(Err(e)) => tracing::warn!(?proto, %port, error = %e, "all-port listener exited"),
                    Ok(Ok(())) => {}
                    Err(e) if e.is_cancelled() => {}
                    Err(e) => tracing::error!(?proto, %port, error = %e, "all-port listener panicked"),
                }
                if let Some(reopen) = gate.listener_ended(port_ref) {
                    start(reopen, &mut tasks, &mut task_ports, &mut listeners);
                }
            }
            _ = reap.tick() => {
                let busy = |proto, port| {
                    listeners
                        .get(&(proto, port))
                        .and_then(|l| l.live_flows.as_ref())
                        .is_some_and(|n| n.load(Ordering::Relaxed) > 0)
                };
                for (proto, port, generation) in
                    gate.claim_for_teardown(PORT_IDLE, PORT_OPEN_TIMEOUT, busy)
                {
                    // Completion is reported through `join_next_with_id` above, which tells the
                    // gate and re-opens the port if packets arrived during teardown.
                    if let Some(l) = listeners.get(&(proto, port)).filter(|l| l.generation == generation) {
                        l.abort.abort();
                    }
                    tracing::debug!(?proto, %port, generation, "all-port: tearing down gated port");
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

    /// Sizing rationale for the global (cross-port) caps. They must be:
    ///   - **bounded far below** the old per-port × MAX_PORTS product (the ≈524K / ≈256 GiB
    ///     ceiling this whole change exists to close), and
    ///   - **at least one per-port cap** (so a single busy port is never starved by the global
    ///     budget), yet
    ///   - **well under** that product (otherwise the global cap would be vacuous).
    #[test]
    fn global_caps_are_bounded_and_sized() {
        let old_tcp_product = crate::tcp::MAX_INFLIGHT_SPLICES * MAX_PORTS;
        let old_udp_product = crate::udp::MAX_UDP_FLOWS * MAX_PORTS;

        // Documented values (a regression guard on the chosen ≈1 GiB ceiling).
        assert_eq!(MAX_GLOBAL_TCP_SPLICES, 2048);
        assert_eq!(MAX_GLOBAL_UDP_FLOWS, 2048);

        // At least one per-port cap so a single port can fill its own 512 even when alone.
        // (Compile-time invariants: these are pure-const comparisons.)
        const { assert!(MAX_GLOBAL_TCP_SPLICES >= crate::tcp::MAX_INFLIGHT_SPLICES) };
        const { assert!(MAX_GLOBAL_UDP_FLOWS >= crate::udp::MAX_UDP_FLOWS) };

        // …but far below the unbounded per-port × MAX_PORTS product (256× headroom here).
        assert!(MAX_GLOBAL_TCP_SPLICES < old_tcp_product);
        assert!(MAX_GLOBAL_UDP_FLOWS < old_udp_product);
        assert_eq!(old_tcp_product / MAX_GLOBAL_TCP_SPLICES, 256);
        assert_eq!(old_udp_product / MAX_GLOBAL_UDP_FLOWS, 256);
    }

    /// The global semaphore caps the AGGREGATE flow count across ports, independently of the
    /// per-port cap. Models the exact admission logic of `run_tcp_port`/`run_udp_port` — per-port
    /// `try_acquire` first, then a shared global `try_acquire` — across two simulated ports, with
    /// the global cap set BELOW `2 × per_port` so it must bite before either port reaches its own
    /// per-port limit. Proves the global gate is what stops the (global+1)th flow, and that a flow
    /// on a fresh port is refused too once the global budget is spent.
    #[tokio::test]
    async fn global_cap_bites_across_ports_independently_of_per_port() {
        // Per-port cap is comfortably large; the global cap is the binding constraint here and is
        // set below 2× per-port so neither port could hit it on its own.
        const PER_PORT: usize = 4;
        const GLOBAL: usize = 6; // < 2 * PER_PORT (8): a single port (max 4) can't exhaust it.

        // One global semaphore shared across both ports (what the all-port manager creates once).
        let global = Arc::new(Semaphore::new(GLOBAL));
        // Each port owns its independent per-port semaphore (what `run_tcp_port` creates locally).
        let port_a = Arc::new(Semaphore::new(PER_PORT));
        let port_b = Arc::new(Semaphore::new(PER_PORT));

        // Admit one flow exactly as the accept loop does: per-port first, then global. Returns the
        // held permits on success (held = the flow is "in flight"); `None` models a dropped flow.
        fn admit(
            per_port: &Arc<Semaphore>,
            global: &Arc<Semaphore>,
        ) -> Option<(
            tokio::sync::OwnedSemaphorePermit,
            tokio::sync::OwnedSemaphorePermit,
        )> {
            let p = per_port.clone().try_acquire_owned().ok()?;
            let g = global.clone().try_acquire_owned().ok()?;
            Some((p, g))
        }

        let mut held = Vec::new();

        // Open 3 flows on port A and 3 on port B = 6 total. Each port stays within its per-port cap
        // (3 < 4), so every per-port acquire succeeds; all 6 fit the global budget exactly.
        for _ in 0..3 {
            held.push(admit(&port_a, &global).expect("port A flow within global budget"));
        }
        for _ in 0..3 {
            held.push(admit(&port_b, &global).expect("port B flow within global budget"));
        }
        assert_eq!(
            held.len(),
            GLOBAL,
            "global budget should be exactly full now"
        );

        // The 7th flow (global+1) on port A is refused by the GLOBAL gate, NOT the per-port gate:
        // port A has used only 3 of its 4 per-port slots, so per-port still has room. The drop is
        // purely the global cap biting — proving cross-port aggregation independent of per-port.
        assert!(
            port_a.clone().try_acquire_owned().is_ok(),
            "per-port A still has a free slot (3 of 4 used) — so a drop here is the GLOBAL cap, not per-port"
        );
        assert!(
            admit(&port_a, &global).is_none(),
            "global cap must drop the (global+1)th flow even though per-port A has room"
        );

        // A flow on a FRESH, fully-idle port is ALSO refused: its per-port semaphore is untouched
        // (all 4 slots free) yet the shared global budget is spent. Fail-closed at the global cap.
        let port_c = Arc::new(Semaphore::new(PER_PORT));
        assert!(
            admit(&port_c, &global).is_none(),
            "a flow on a fresh idle port must still be refused once the global budget is spent"
        );

        // Releasing one in-flight flow frees exactly one global slot, which a new flow can reuse —
        // the cap tracks live flows, it is not a permanent counter.
        held.pop();
        assert!(
            admit(&port_c, &global).is_some(),
            "after one flow ends, the freed global slot admits a new flow"
        );
    }

    /// No-regression: with `global = None` (the explicit-port path), admission falls through to the
    /// per-port cap alone — there is no global gate, so a port may fill its full per-port budget and
    /// nothing caps the aggregate beyond that. Mirrors how `forwarder.rs` passes `None`.
    #[test]
    fn no_global_cap_when_none_uses_per_port_only() {
        const PER_PORT: usize = 4;
        let port = Arc::new(Semaphore::new(PER_PORT));
        let global: Option<Arc<Semaphore>> = None;

        // Admit with an OPTIONAL global, exactly as `run_tcp_port` does: when `None`, only the
        // per-port acquire gates the flow.
        let admit = |per_port: &Arc<Semaphore>, global: &Option<Arc<Semaphore>>| {
            let p = per_port.clone().try_acquire_owned().ok()?;
            let g = match global {
                Some(sem) => Some(sem.clone().try_acquire_owned().ok()?),
                None => None,
            };
            Some((p, g))
        };

        // The port fills its full per-port budget with no global interference…
        let mut held = Vec::new();
        for _ in 0..PER_PORT {
            held.push(admit(&port, &global).expect("within per-port cap, no global gate"));
        }
        assert_eq!(held.len(), PER_PORT);
        // …and only the per-port cap stops the next flow (not any global gate).
        assert!(
            admit(&port, &global).is_none(),
            "per-port cap still bounds the port when global is None"
        );
    }
}
