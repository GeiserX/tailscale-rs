//! Fallback TCP handler registry (`tsnet.Server.RegisterFallbackTCPHandler` parity).
//!
//! Go `tsnet` lets an embedder register a callback consulted for every inbound TCP flow that
//! matches **no** explicit [`Listener`]. The callback inspects the `(src, dst)` tuple and either
//! declines (`intercept = false`, try the next handler) or claims the flow (`intercept = true`),
//! optionally returning a per-connection handler. This module is the faithful equivalent on the
//! **application** netstack.
//!
//! ## How an unmatched flow is observed
//!
//! smoltcp RSTs an inbound SYN to a port with no matching listener *inside* its ingress loop,
//! before any of our code runs. The single lever it gives us is the same one
//! [`ts_forwarder::all_port`] uses: a `raw` `(Ipv4, Tcp)` socket whose `accepts()` sets
//! `handled_by_raw_socket = true`, which **suppresses that RST** and hands us a copy of every
//! inbound TCP packet. We read each SYN's destination port and lazily materialize a per-port
//! any-IP listener; the peer's SYN retransmit is then accepted by that listener and dispatched to
//! the registered handlers.
//!
//! ## The observer runs **only** while a handler is registered
//!
//! Because the raw observer suppresses the unmatched-SYN RST for the whole netstack, it must not
//! be running when there are no fallback handlers — otherwise a node with zero handlers would stop
//! RSTing unrouted SYNs (silently swallowing them) instead of cleanly refusing. So the observer is
//! started on the *first* registration and torn down on the *last* deregistration, leaving the
//! default fail-closed RST behavior pristine whenever no handler is installed.
//!
//! ## Anti-leak
//!
//! The raw observer never creates a host socket and never dials anything; it only learns ports.
//! Every accepted flow is handed to the embedder's own handler over the overlay netstack — never a
//! host socket. Ports already owned by an explicit `tcp_listen`er are skipped (queried read-only
//! via [`CreateSocket::bound_tcp_ports`]) so a fallback listener never competes with a real one. A
//! flow no handler claims is closed (fail-closed), never direct-dialed. IPv4-only.

use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant},
};

use netstack::{
    CreateSocket,
    netcore::{
        Channel,
        smoltcp::wire::{IpProtocol, Ipv4Packet, TcpPacket},
    },
    netsock::TcpStream,
};
use tokio::sync::Semaphore;

/// Maximum number of distinct ports that may have a live on-demand fallback listener at once.
///
/// Mirrors [`ts_forwarder::all_port`]'s cap: without it a remote could scan all 65,535 ports and
/// permanently materialize that many tasks + netstack sockets (remote FD/memory-exhaustion DoS).
/// Over the cap, SYNs to *new* ports are dropped (no listener spawned) until a port is evicted.
const MAX_PORTS: usize = 1024;

/// How long an on-demand per-port listener may go without any observed inbound packet before it is
/// reaped (its task aborted and the port freed so a later packet can re-trigger it).
const PORT_IDLE: Duration = Duration::from_secs(120);

/// How often the idle-port reaper runs (half [`PORT_IDLE`] to keep worst-case dormant lifetime
/// near `PORT_IDLE` rather than double it).
const PORT_REAP_INTERVAL: Duration = Duration::from_secs(60);

/// Max concurrent in-flight handled flows per fallback port listener. Bounds the per-flow spawn
/// fan-out so a flood of accepts cannot grow tasks without limit; saturated => drop (fail-closed).
const MAX_INFLIGHT: usize = 512;

/// The future returned by a [`FallbackConnHandler`]; spawned to service one accepted flow.
pub type FallbackConnFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Per-connection handler returned by a fallback callback that claims a flow. Consumes the
/// accepted overlay [`TcpStream`] and returns a future the manager spawns. Mirrors the
/// `func(net.Conn)` Go `tsnet` returns from its fallback callback.
pub type FallbackConnHandler = Box<dyn FnOnce(TcpStream) -> FallbackConnFuture + Send>;

/// A fallback callback's decision for one `(src, dst)` flow: an optional per-connection handler
/// and whether this callback intercepts the flow. Matches Go's `(handler func(net.Conn), intercept
/// bool)`:
/// - `(_, false)` — decline; the manager tries the next registered callback.
/// - `(Some(h), true)` — claim the flow; `h` services the connection.
/// - `(None, true)` — claim the flow and reject it (the connection is closed).
pub type FallbackDecision = (Option<FallbackConnHandler>, bool);

/// A registered fallback callback. Invoked per unmatched inbound TCP flow with `(src, dst)`.
type Handler = Arc<dyn Fn(SocketAddr, SocketAddr) -> FallbackDecision + Send + Sync>;

/// Bookkeeping for one on-demand per-port fallback listener.
struct PortEntry {
    /// Aborts the listener task on eviction / observer drop.
    handle: tokio::task::AbortHandle,
    /// Last time an inbound packet for this port was observed (for idle eviction).
    last: Instant,
}

impl Drop for PortEntry {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Shared manager state behind a single lock.
struct Inner {
    /// Registered callbacks keyed by monotonic id. Iteration order (ascending id ≈ registration
    /// order) is the dispatch order; the first callback to intercept wins.
    handlers: BTreeMap<u64, Handler>,
    /// Next callback id to hand out.
    next_id: u64,
    /// The running raw-SYN observer task, present iff `handlers` is non-empty.
    observer: Option<tokio::task::AbortHandle>,
    /// Application-netstack channel the observer and per-port listeners run on.
    channel: Channel,
}

/// Manages the fallback-TCP handler registry and the lifecycle of the raw-SYN observer.
///
/// Built once from the application netstack channel and held by the runtime. Registering the first
/// handler starts the observer; dropping the last [`FallbackTcpHandle`] stops it.
pub struct FallbackTcpManager {
    inner: Arc<Mutex<Inner>>,
}

impl FallbackTcpManager {
    /// Build a manager bound to the application netstack `channel`. The observer is not started
    /// until the first handler is registered.
    pub fn new(channel: Channel) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                handlers: BTreeMap::new(),
                next_id: 0,
                observer: None,
                channel,
            })),
        }
    }

    /// Register a fallback callback, returning a RAII handle that deregisters it on drop.
    ///
    /// The first registration starts the raw-SYN observer; the last deregistration stops it.
    pub fn register(&self, cb: Handler) -> FallbackTcpHandle {
        // Recover from a poisoned lock rather than cascading a panic across flows (matches the
        // reliability posture of the rest of the dataplane).
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let id = inner.next_id;
        inner.next_id += 1;
        inner.handlers.insert(id, cb);

        if inner.observer.is_none() {
            let channel = inner.channel.clone();
            let weak = Arc::downgrade(&self.inner);
            let task = tokio::spawn(async move {
                if let Err(e) = run_observer(channel, weak).await {
                    tracing::warn!(error = %e, "fallback-tcp observer exited");
                }
            });
            inner.observer = Some(task.abort_handle());
            tracing::debug!("fallback-tcp: started raw SYN observer (first handler registered)");
        }

        FallbackTcpHandle {
            id,
            inner: Arc::downgrade(&self.inner),
        }
    }
}

/// RAII deregistration handle for a fallback callback (mirrors the `unregister func()` Go returns).
///
/// Dropping it removes the callback; dropping the last handle also tears down the raw observer, so
/// the netstack's default fail-closed RST behavior returns when no handler is installed.
#[must_use = "dropping the handle immediately deregisters the fallback handler"]
pub struct FallbackTcpHandle {
    id: u64,
    inner: Weak<Mutex<Inner>>,
}

impl FallbackTcpHandle {
    /// Explicitly deregister the handler now. Equivalent to dropping the handle.
    pub fn unregister(self) {
        // Drop runs the deregistration.
    }
}

impl Drop for FallbackTcpHandle {
    fn drop(&mut self) {
        let Some(inner) = self.inner.upgrade() else {
            return;
        };
        let mut g = inner.lock().unwrap_or_else(|e| e.into_inner());
        g.handlers.remove(&self.id);
        if g.handlers.is_empty()
            && let Some(observer) = g.observer.take()
        {
            // Last handler gone: stop suppressing the unmatched-SYN RST. Aborting the observer
            // drops its per-port `PortEntry`s, which abort the per-port listener tasks.
            observer.abort();
            tracing::debug!("fallback-tcp: stopped raw SYN observer (last handler deregistered)");
        }
    }
}

/// Observe inbound SYNs via a raw socket and lazily start a per-port any-IP listener for each new
/// destination port that is not already served by an explicit listener.
async fn run_observer(
    channel: Channel,
    inner: Weak<Mutex<Inner>>,
) -> Result<(), netstack::netcore::Error> {
    // The raw observer both suppresses the unmatched-SYN RST and reveals each SYN's dst port.
    let raw = channel.raw_open(true, IpProtocol::Tcp).await?;

    // A per-port listener task sends its port back when it exits so the observer removes it from
    // the active set (so a retransmit re-triggers it).
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
                    tracing::warn!(%port, "fallback-tcp: at max active ports ({MAX_PORTS}); dropping new port");
                    continue;
                }
                // Cold path only: skip ports an explicit listener already owns so a fallback
                // listener never competes with a real one. Read-only registry query.
                match channel.bound_tcp_ports().await {
                    Ok(bound) if bound.contains(&port) => continue,
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!(%port, error = %e, "fallback-tcp: bound-ports query failed; skipping port");
                        continue;
                    }
                }
                let Some(inner) = inner.upgrade() else {
                    // Manager dropped; nothing left to serve.
                    return Ok(());
                };
                tracing::debug!(%port, "fallback-tcp: starting listener on demand");
                let channel = channel.clone();
                let exit_tx = exit_tx.clone();
                let handle = tokio::spawn(async move {
                    if let Err(e) = run_port(channel, port, inner).await {
                        tracing::warn!(%port, error = %e, "fallback-tcp listener exited");
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
                    tracing::debug!(reaped, "fallback-tcp: reaped idle listeners");
                }
            }
        }
    }
}

/// Accept flows on `0.0.0.0:port` of the application netstack and dispatch each to the registered
/// fallback callbacks in order; the first to intercept wins.
async fn run_port(
    channel: Channel,
    port: u16,
    inner: Arc<Mutex<Inner>>,
) -> Result<(), netstack::netcore::Error> {
    let listen_addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port);
    let listener = channel.tcp_listen(listen_addr).await?;
    tracing::debug!(%port, "fallback-tcp listener accepting");

    let inflight = Arc::new(Semaphore::new(MAX_INFLIGHT));

    loop {
        let overlay = listener.accept().await?;
        let Ok(permit) = inflight.clone().try_acquire_owned() else {
            tracing::warn!(
                %port,
                peer = %overlay.remote_addr(),
                "fallback-tcp drop: at max in-flight flows ({MAX_INFLIGHT})"
            );
            // Dropping `overlay` closes the flow; fail-closed, never direct-dialed.
            continue;
        };

        // Snapshot the callbacks under the lock, then release it before invoking them.
        let handlers: Vec<Handler> = {
            let g = inner.lock().unwrap_or_else(|e| e.into_inner());
            g.handlers.values().cloned().collect()
        };

        let src = overlay.remote_addr();
        let dst = overlay.local_addr();

        match dispatch(&handlers, src, dst) {
            Some(conn_handler) => {
                tokio::spawn(async move {
                    let _permit = permit; // released when the handler future completes
                    conn_handler(overlay).await;
                });
            }
            // No handler claimed with a connection handler: either every handler declined, or one
            // intercepted to reject (intercept=true, handler=None). Either way the flow is closed
            // by dropping `overlay`. Fail-closed.
            None => {
                drop(overlay);
            }
        }
    }
}

/// Consult `handlers` in order for the flow `(src, dst)` and return the per-connection handler of
/// the first callback that intercepts, if any.
///
/// Mirrors Go `tsnet`: the first callback returning `intercept = true` wins; a `true` with no
/// connection handler (reject) and an exhausted handler list (decline) both yield `None`, which the
/// caller treats as "close the flow".
fn dispatch(handlers: &[Handler], src: SocketAddr, dst: SocketAddr) -> Option<FallbackConnHandler> {
    for handler in handlers {
        let (conn_handler, intercept) = handler(src, dst);
        if intercept {
            return conn_handler;
        }
    }
    None
}

/// Parse a raw IPv4 packet and return its TCP destination port iff it is a connection-initiating
/// SYN (SYN set, ACK clear). Non-TCP, malformed, or non-SYN packets yield `None`.
fn syn_dst_port(packet: &[u8]) -> Option<u16> {
    let ip = Ipv4Packet::new_checked(packet).ok()?;
    if ip.next_header() != IpProtocol::Tcp {
        return None;
    }
    let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
    if tcp.syn() && !tcp.ack() {
        Some(tcp.dst_port())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use netstack::netcore::smoltcp::wire::Ipv4Address;

    use super::*;

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

    #[test]
    fn syn_dst_port_reads_connection_initiating_syn() {
        let pkt = ipv4(IpProtocol::Tcp, &tcp_segment(8443, true, false));
        assert_eq!(syn_dst_port(&pkt), Some(8443));
    }

    #[test]
    fn syn_dst_port_ignores_syn_ack_and_non_syn() {
        let synack = ipv4(IpProtocol::Tcp, &tcp_segment(8443, true, true));
        assert_eq!(syn_dst_port(&synack), None);
        let ack = ipv4(IpProtocol::Tcp, &tcp_segment(8443, false, true));
        assert_eq!(syn_dst_port(&ack), None);
    }

    #[test]
    fn syn_dst_port_ignores_malformed() {
        assert_eq!(syn_dst_port(&[0u8; 4]), None);
    }

    #[test]
    fn caps_are_bounded() {
        assert_eq!(MAX_PORTS, 1024);
        assert!(PORT_REAP_INTERVAL <= PORT_IDLE / 2);
        assert_eq!(MAX_INFLIGHT, 512);
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(Ipv4Addr::new(100, 64, 0, 1).into(), port)
    }

    /// A handler that returns the given decision and records that it was consulted.
    fn handler(decision: impl Fn() -> FallbackDecision + Send + Sync + 'static) -> Handler {
        Arc::new(move |_src, _dst| decision())
    }

    #[test]
    fn dispatch_declines_when_no_handler_intercepts() {
        let handlers = vec![handler(|| (None, false)), handler(|| (None, false))];
        assert!(dispatch(&handlers, addr(1), addr(8443)).is_none());
    }

    #[test]
    fn dispatch_empty_handler_list_yields_none() {
        assert!(dispatch(&[], addr(1), addr(8443)).is_none());
    }

    #[test]
    fn dispatch_intercept_with_handler_is_returned() {
        let handlers = vec![handler(|| {
            let h: FallbackConnHandler = Box::new(|_stream| Box::pin(async {}));
            (Some(h), true)
        })];
        assert!(dispatch(&handlers, addr(1), addr(8443)).is_some());
    }

    #[test]
    fn dispatch_intercept_reject_yields_none_and_stops() {
        // First handler intercepts to reject (handler=None, intercept=true). The second handler
        // would intercept-with-handler, but must NOT be consulted — first intercept wins.
        let second_consulted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = second_consulted.clone();
        let handlers = vec![
            handler(|| (None, true)),
            Arc::new(move |_s: SocketAddr, _d: SocketAddr| {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
                let h: FallbackConnHandler = Box::new(|_stream| Box::pin(async {}));
                (Some(h), true)
            }) as Handler,
        ];
        assert!(
            dispatch(&handlers, addr(1), addr(8443)).is_none(),
            "intercept=true with no handler must reject (None)"
        );
        assert!(
            !second_consulted.load(std::sync::atomic::Ordering::SeqCst),
            "first intercept must win; later handlers must not be consulted"
        );
    }

    #[test]
    fn dispatch_first_interceptor_wins_over_later() {
        // A declining handler is skipped; the first that intercepts (here the second) wins.
        let handlers = vec![
            handler(|| (None, false)),
            handler(|| {
                let h: FallbackConnHandler = Box::new(|_stream| Box::pin(async {}));
                (Some(h), true)
            }),
        ];
        assert!(dispatch(&handlers, addr(1), addr(8443)).is_some());
    }
}
