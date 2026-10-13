//! Ingress port gate for all-port forwarding: hold the first packets to a cold port until its
//! listener exists, instead of losing them.
//!
//! smoltcp answers a SYN to a port with no listener with an RST (and an unmatched UDP datagram
//! with ICMP port-unreachable) inside its ingress loop, so a per-port listener must exist
//! *before* the netstack sees the flow's first packet. The raw-socket observer in `all_port`
//! learns the port only after the netstack has swallowed that packet, so every new destination
//! port costs the client a SYN retransmit (~1 s) or a lost DNS query / QUIC Initial, and the
//! observer copies every inbound packet to do it.
//!
//! [`PortGate`] sits in front of the forwarder netstack's ingress queue instead. Packets to an
//! open port pass straight through; a connection-initiating packet (TCP SYN, or any UDP datagram)
//! to a closed port is held and the manager is asked to open the port. Once the listener is
//! registered the held packets are released in order, ahead of anything that arrives later, and
//! the port is open. Nothing is copied on the hot path and no raw socket is needed.
//!
//! Everything else passes unchanged: non-IPv4 packets, IPv4 fragments (smoltcp reassembles them;
//! a fragmented *first* datagram to a cold UDP port is the one case still answered with
//! port-unreachable), and non-SYN TCP to a closed port (smoltcp RSTs it, which is correct for a
//! flow this netstack doesn't know).
//!
//! The gate never dials anything and does not classify routes; every flow still goes through the
//! per-port listener's classify → [`RealDialer`](crate::RealDialer) chokepoint.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use ts_netstack_smoltcp::{
    WakingPipeSender,
    netcore::smoltcp::wire::{IpProtocol, Ipv4Packet, TcpPacket, UdpPacket},
};

/// Transport protocol of a gated port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Proto {
    Tcp,
    Udp,
}

/// Max packets held for one port while its listener is being opened. A browser opening a page
/// sends a handful of parallel SYNs to the same cold port; far more than this is a flood.
const MAX_HELD_PER_PORT: usize = 32;

/// Max bytes held across all opening ports. Bounds what a port sweep can pin in the gate.
const MAX_HELD_BYTES: usize = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Closed,
    /// A listener is being started; initiating packets are held.
    Opening,
    /// The listener is registered; everything passes.
    Open,
    /// The listener is being torn down (idle reap or open timeout); initiating packets are held
    /// and re-open the port once teardown completes.
    Closing,
}

#[derive(Clone, Copy)]
struct Slot {
    state: State,
    /// Listener generation this slot's state refers to. Every open bumps it, so events from an
    /// earlier listener on the same port are recognized as stale and ignored.
    generation: u32,
    /// Last packet seen for this port (or when it started opening), in seconds since the epoch.
    last: u32,
}

/// One port's listener generation: what the manager is asked to open and reports back about.
pub(crate) type PortRef = (Proto, u16, u32);

struct Inner {
    ingress: WakingPipeSender,
    batch_ingress: bool,
    epoch: Instant,
    tcp: Vec<Slot>,
    udp: Vec<Slot>,
    held: HashMap<(Proto, u16), Vec<Vec<u8>>>,
    held_bytes: usize,
    next_generation: u32,
    /// Ports that are opening, open or closing, across both protocols.
    active: usize,
    max_active: usize,
    open_requests: tokio::sync::mpsc::UnboundedSender<PortRef>,
}

/// What the gate did with a packet.
#[derive(Debug, PartialEq, Eq)]
pub enum Admit {
    /// Handed to the netstack's ingress queue.
    Passed,
    /// Held until its port's listener is up.
    Held,
    /// Dropped: the ingress queue was full, or the hold budget / active-port cap was reached.
    Dropped,
}

type AdmissionCallback<'a> = &'a dyn Fn(&[u8]) -> bool;

/// Ingress gate in front of an all-port forwarder netstack. See the module docs.
///
/// Cheap to clone; all clones share one state.
#[derive(Clone)]
pub struct PortGate {
    inner: Arc<Mutex<Inner>>,
}

/// The manager side of a [`PortGate`]: open requests to serve.
pub(crate) struct OpenRequests(pub(crate) tokio::sync::mpsc::UnboundedReceiver<PortRef>);

impl PortGate {
    /// A gate feeding `ingress` (the forwarder netstack's ingress queue), allowing at most
    /// `max_active` ports (TCP and UDP together) to be opening, open or closing at once.
    pub(crate) fn new(ingress: WakingPipeSender, max_active: usize) -> (Self, OpenRequests) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let closed = Slot {
            state: State::Closed,
            generation: 0,
            last: 0,
        };
        let inner = Inner {
            ingress,
            batch_ingress: match std::env::var("TS_EXPERIMENT_RX_BATCH").as_deref() {
                Ok("1") => true,
                Ok("0") => false,
                _ => cfg!(target_vendor = "apple"),
            },
            epoch: Instant::now(),
            tcp: vec![closed; 1 << 16],
            udp: vec![closed; 1 << 16],
            held: HashMap::new(),
            held_bytes: 0,
            next_generation: 1,
            active: 0,
            max_active,
            open_requests: tx,
        };
        (
            Self {
                inner: Arc::new(Mutex::new(inner)),
            },
            OpenRequests(rx),
        )
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Offer one inbound packet to the forwarder netstack.
    pub fn ingress(&self, packet: &[u8]) -> Admit {
        self.ingress_impl(packet, None)
    }

    /// Apply the port gate, admitting passed packets through a nonblocking callback.
    /// Held packets retain their original release path and ordering under the gate lock.
    pub fn ingress_with(&self, packet: &[u8], admit: impl Fn(&[u8]) -> bool) -> Admit {
        self.ingress_impl(packet, Some(&admit))
    }

    fn ingress_impl(&self, packet: &[u8], admit: Option<AdmissionCallback<'_>>) -> Admit {
        let mut inner = self.lock();

        let Some((proto, port, initiating)) = classify(packet) else {
            return inner.pass(packet, admit);
        };
        let now = inner.now();
        let slot = &mut inner.slots(proto)[port as usize];
        match slot.state {
            State::Open => {
                slot.last = now;
                inner.pass(packet, admit)
            }
            State::Opening | State::Closing if initiating => inner.hold(proto, port, packet),
            State::Opening | State::Closing | State::Closed if !initiating => {
                inner.pass(packet, admit)
            }
            _ => {
                if inner.active >= inner.max_active {
                    tracing::debug!(?proto, %port, "port gate: at max active ports; dropping");
                    return Admit::Dropped;
                }
                if inner.held_bytes + packet.len() > MAX_HELD_BYTES {
                    return Admit::Dropped;
                }
                let Some(generation) = inner.request_open(proto, port, now) else {
                    return Admit::Dropped;
                };
                inner.active += 1;
                tracing::trace!(?proto, %port, generation, "port gate: opening");
                inner.hold(proto, port, packet)
            }
        }
    }

    /// Listener `port_ref` is registered: release its held packets, then open the port. Ignored
    /// unless that exact generation is still opening.
    ///
    /// Releasing under the lock keeps ordering: anything arriving meanwhile waits and is passed
    /// after the held packets. Returns how many held packets the ingress queue refused.
    pub(crate) fn mark_open(&self, (proto, port, generation): PortRef) -> usize {
        let mut inner = self.lock();
        let slot = inner.slots(proto)[port as usize];
        if slot.state != State::Opening || slot.generation != generation {
            return 0;
        }
        let held = inner.take_held(proto, port);
        let refused = held
            .iter()
            .filter(|p| {
                !(if inner.batch_ingress {
                    inner.ingress.try_send_deferred(p)
                } else {
                    inner.ingress.try_send(p)
                })
            })
            .count();
        let now = inner.now();
        let slot = &mut inner.slots(proto)[port as usize];
        slot.state = State::Open;
        slot.last = now;
        if inner.batch_ingress && !held.is_empty() {
            inner.ingress.notify_receive();
        }
        tracing::debug!(?proto, %port, generation, released = held.len(), refused, "port gate: open");
        refused
    }

    /// Listener `port_ref` has ended (exited, failed, panicked or was aborted). Ignored unless it
    /// is the port's current generation. If the port was closing and packets arrived meanwhile, it
    /// re-opens right away with a new generation, returned for the manager to start; otherwise the
    /// port closes and anything still held for it is dropped.
    pub(crate) fn listener_ended(&self, (proto, port, generation): PortRef) -> Option<PortRef> {
        let mut inner = self.lock();
        let slot = inner.slots(proto)[port as usize];
        if slot.state == State::Closed || slot.generation != generation {
            return None;
        }
        let has_held = inner
            .held
            .get(&(proto, port))
            .is_some_and(|h| !h.is_empty());
        if slot.state == State::Closing && has_held {
            let now = inner.now();
            let new_generation = inner.bump_generation();
            let slot = &mut inner.slots(proto)[port as usize];
            slot.state = State::Opening;
            slot.generation = new_generation;
            slot.last = now;
            return Some((proto, port, new_generation));
        }
        inner.take_held(proto, port);
        inner.slots(proto)[port as usize].state = State::Closed;
        inner.active -= 1;
        None
    }

    /// Claim the listeners to tear down, moving each to `Closing` atomically with the check: open
    /// ports idle for at least `idle` (and not `busy`), and ports stuck opening for at least
    /// `open_timeout`, whose held packets are dropped. The manager aborts each returned
    /// generation and reports it back through [`listener_ended`](Self::listener_ended).
    pub(crate) fn claim_for_teardown(
        &self,
        idle: Duration,
        open_timeout: Duration,
        busy: impl Fn(Proto, u16) -> bool,
    ) -> Vec<PortRef> {
        let mut inner = self.lock();
        let now = inner.now();
        let secs = |d: Duration| u32::try_from(d.as_secs()).unwrap_or(u32::MAX);
        let (idle, open_timeout) = (secs(idle), secs(open_timeout));
        let mut claimed = Vec::new();
        let mut stale_opening = Vec::new();
        for proto in [Proto::Tcp, Proto::Udp] {
            for (port, slot) in inner.slots(proto).iter_mut().enumerate() {
                let port = port as u16;
                let age = now.saturating_sub(slot.last);
                match slot.state {
                    State::Open if age >= idle && !busy(proto, port) => {}
                    State::Opening if age >= open_timeout => stale_opening.push((proto, port)),
                    _ => continue,
                }
                slot.state = State::Closing;
                claimed.push((proto, port, slot.generation));
            }
        }
        for (proto, port) in stale_opening {
            tracing::warn!(?proto, %port, "port gate: listener never came up; dropping held packets");
            inner.take_held(proto, port);
        }
        claimed
    }
}

impl Inner {
    fn now(&self) -> u32 {
        u32::try_from(self.epoch.elapsed().as_secs()).unwrap_or(u32::MAX)
    }

    fn slots(&mut self, proto: Proto) -> &mut [Slot] {
        match proto {
            Proto::Tcp => &mut self.tcp,
            Proto::Udp => &mut self.udp,
        }
    }

    fn bump_generation(&mut self) -> u32 {
        let g = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1).max(1);
        g
    }

    /// Move a closed port to `Opening` under a new generation and ask the manager to open it.
    fn request_open(&mut self, proto: Proto, port: u16, now: u32) -> Option<u32> {
        let generation = self.bump_generation();
        // Manager gone: nothing will ever open the port.
        self.open_requests.send((proto, port, generation)).ok()?;
        let slot = &mut self.slots(proto)[port as usize];
        slot.state = State::Opening;
        slot.generation = generation;
        slot.last = now;
        Some(generation)
    }

    fn take_held(&mut self, proto: Proto, port: u16) -> Vec<Vec<u8>> {
        let held = self.held.remove(&(proto, port)).unwrap_or_default();
        self.held_bytes -= held.iter().map(Vec::len).sum::<usize>();
        held
    }

    fn pass(&self, packet: &[u8], admit: Option<AdmissionCallback<'_>>) -> Admit {
        let sent = match admit {
            Some(admit) => admit(packet),
            None => self.ingress.try_send(packet),
        };
        if sent { Admit::Passed } else { Admit::Dropped }
    }

    fn hold(&mut self, proto: Proto, port: u16, packet: &[u8]) -> Admit {
        let budget_left = MAX_HELD_BYTES - self.held_bytes;
        let held = self.held.entry((proto, port)).or_default();
        if held.len() >= MAX_HELD_PER_PORT || packet.len() > budget_left {
            return Admit::Dropped;
        }
        held.push(packet.to_vec());
        self.held_bytes += packet.len();
        Admit::Held
    }
}

/// `(protocol, destination port, opens a flow)` for an unfragmented IPv4 TCP/UDP packet; `None`
/// for anything the gate passes through untouched.
fn classify(packet: &[u8]) -> Option<(Proto, u16, bool)> {
    let ip = Ipv4Packet::new_checked(packet).ok()?;
    if ip.more_frags() || ip.frag_offset() != 0 {
        return None;
    }
    match ip.next_header() {
        IpProtocol::Tcp => {
            let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
            Some((Proto::Tcp, tcp.dst_port(), tcp.syn() && !tcp.ack()))
        }
        IpProtocol::Udp => {
            let udp = UdpPacket::new_checked(ip.payload()).ok()?;
            Some((Proto::Udp, udp.dst_port(), true))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use ts_netstack_smoltcp::{WakingPipe, netcore::smoltcp::wire::Ipv4Address};

    use super::*;

    fn ipv4(proto: IpProtocol, payload: &[u8], frag_offset: u16) -> Vec<u8> {
        let total = 20 + payload.len();
        let mut buf = vec![0u8; total];
        let mut ip = Ipv4Packet::new_unchecked(&mut buf);
        ip.set_version(4);
        ip.set_header_len(20);
        ip.set_total_len(total as u16);
        ip.set_hop_limit(64);
        ip.set_next_header(proto);
        ip.set_frag_offset(frag_offset);
        ip.set_src_addr(Ipv4Address::new(100, 64, 0, 1));
        ip.set_dst_addr(Ipv4Address::new(1, 1, 1, 1));
        ip.payload_mut().copy_from_slice(payload);
        buf
    }

    fn tcp(dst_port: u16, syn: bool, ack: bool) -> Vec<u8> {
        let mut seg = vec![0u8; 20];
        let mut tcp = TcpPacket::new_unchecked(&mut seg);
        tcp.set_src_port(40000);
        tcp.set_dst_port(dst_port);
        tcp.set_header_len(20);
        tcp.set_syn(syn);
        tcp.set_ack(ack);
        ipv4(IpProtocol::Tcp, &seg, 0)
    }

    fn udp(dst_port: u16) -> Vec<u8> {
        let mut dg = vec![0u8; 8];
        let mut udp = UdpPacket::new_unchecked(&mut dg);
        udp.set_src_port(40000);
        udp.set_dst_port(dst_port);
        udp.set_len(8);
        ipv4(IpProtocol::Udp, &dg, 0)
    }

    fn gate(max_active: usize) -> (PortGate, OpenRequests, WakingPipe) {
        let (ours, netstack_side) = WakingPipe::unbounded();
        let (g, reqs) = PortGate::new(ours.tx, max_active);
        (g, reqs, netstack_side)
    }

    fn drain(rx: &mut WakingPipe) -> Vec<Vec<u8>> {
        std::iter::from_fn(|| rx.rx.try_recv().map(|b| b.to_vec())).collect()
    }

    fn never_busy(_: Proto, _: u16) -> bool {
        false
    }

    #[test]
    fn cold_syn_is_held_then_released_in_order() {
        let (g, mut reqs, mut ns) = gate(16);
        let syn1 = tcp(443, true, false);
        let syn2 = tcp(443, true, false);

        assert_eq!(g.ingress(&syn1), Admit::Held);
        assert_eq!(g.ingress(&syn2), Admit::Held);
        // Exactly one open request for the port, however many SYNs raced it.
        let r = reqs.0.try_recv().unwrap();
        assert_eq!((r.0, r.1), (Proto::Tcp, 443));
        assert!(reqs.0.try_recv().is_err());
        assert!(drain(&mut ns).is_empty());

        assert_eq!(g.mark_open(r), 0);
        assert_eq!(drain(&mut ns), vec![syn1, syn2]);

        let data = tcp(443, false, true);
        assert_eq!(g.ingress(&data), Admit::Passed);
        assert_eq!(drain(&mut ns), vec![data]);
    }

    #[test]
    fn cold_udp_is_held_then_released() {
        let (g, mut reqs, mut ns) = gate(16);
        let q = udp(53);
        assert_eq!(g.ingress(&q), Admit::Held);
        let r = reqs.0.try_recv().unwrap();
        assert_eq!((r.0, r.1), (Proto::Udp, 53));
        g.mark_open(r);
        assert_eq!(drain(&mut ns), vec![q]);
    }

    #[test]
    fn non_syn_and_non_ipv4_pass_through_closed_ports() {
        let (g, mut reqs, mut ns) = gate(16);
        let ack = tcp(443, false, true);
        assert_eq!(g.ingress(&ack), Admit::Passed);
        let v6 = {
            let mut p = vec![0u8; 40];
            p[0] = 0x60;
            p
        };
        assert_eq!(g.ingress(&v6), Admit::Passed);
        let mut frag = udp(53);
        Ipv4Packet::new_unchecked(&mut frag).set_frag_offset(8);
        assert_eq!(g.ingress(&frag), Admit::Passed);
        assert!(reqs.0.try_recv().is_err());
        assert_eq!(drain(&mut ns).len(), 3);
    }

    #[test]
    fn listener_failure_drops_held_and_next_syn_reopens() {
        let (g, mut reqs, mut ns) = gate(16);
        assert_eq!(g.ingress(&tcp(8080, true, false)), Admit::Held);
        let r = reqs.0.try_recv().unwrap();
        assert_eq!(g.listener_ended(r), None);
        // A late Ready for the failed listener releases nothing.
        g.mark_open(r);
        assert!(drain(&mut ns).is_empty());
        assert_eq!(g.ingress(&tcp(8080, true, false)), Admit::Held);
        let r2 = reqs.0.try_recv().unwrap();
        assert_ne!(r2.2, r.2, "a re-open is a new generation");
    }

    /// Review finding: a delayed Ready from an old listener must not release packets held for a
    /// newer one that isn't registered yet.
    #[test]
    fn stale_ready_does_not_release_new_generation() {
        let (g, mut reqs, mut ns) = gate(16);
        g.ingress(&tcp(443, true, false));
        let old = reqs.0.try_recv().unwrap();
        g.listener_ended(old);
        let new_syn = tcp(443, true, false);
        assert_eq!(g.ingress(&new_syn), Admit::Held);
        let new = reqs.0.try_recv().unwrap();
        g.mark_open(old);
        assert!(
            drain(&mut ns).is_empty(),
            "released SYN before the new listener registered"
        );
        g.mark_open(new);
        assert_eq!(drain(&mut ns), vec![new_syn]);
    }

    /// Review finding: a delayed exit of an old listener must not close the port's newer listener
    /// or drop what it holds.
    #[test]
    fn stale_exit_does_not_close_new_generation() {
        let (g, mut reqs, mut ns) = gate(16);
        g.ingress(&tcp(443, true, false));
        let old = reqs.0.try_recv().unwrap();
        g.mark_open(old);
        drain(&mut ns);
        // Reaped idle, then torn down; a new SYN arrives after teardown.
        assert_eq!(
            g.claim_for_teardown(Duration::ZERO, Duration::MAX, never_busy),
            vec![old]
        );
        assert_eq!(g.listener_ended(old), None);
        let new_syn = tcp(443, true, false);
        g.ingress(&new_syn);
        let new = reqs.0.try_recv().unwrap();
        // A second, stale report for the old generation changes nothing.
        assert_eq!(g.listener_ended(old), None);
        g.mark_open(new);
        assert_eq!(drain(&mut ns), vec![new_syn]);
    }

    /// Review finding: a SYN that arrives while an idle port is being torn down is held and
    /// re-opens the port once teardown completes, instead of racing the old listener's removal.
    #[test]
    fn syn_during_teardown_is_held_and_reopens() {
        let (g, mut reqs, mut ns) = gate(16);
        g.ingress(&tcp(443, true, false));
        let old = reqs.0.try_recv().unwrap();
        g.mark_open(old);
        drain(&mut ns);
        assert_eq!(
            g.claim_for_teardown(Duration::ZERO, Duration::MAX, never_busy),
            vec![old]
        );
        let syn = tcp(443, true, false);
        assert_eq!(g.ingress(&syn), Admit::Held);
        // Non-initiating traffic for flows that outlive the listener still passes.
        assert_eq!(g.ingress(&tcp(443, false, true)), Admit::Passed);
        drain(&mut ns);
        let new = g.listener_ended(old).expect("held SYN re-opens the port");
        assert_eq!((new.0, new.1), (Proto::Tcp, 443));
        assert_ne!(new.2, old.2);
        g.mark_open(new);
        assert_eq!(drain(&mut ns), vec![syn]);
    }

    #[test]
    fn teardown_claims_only_idle_open_ports_not_busy_or_opening() {
        let (g, mut reqs, _ns) = gate(16);
        g.ingress(&tcp(443, true, false));
        g.ingress(&udp(443));
        g.ingress(&tcp(80, true, false));
        let a = reqs.0.try_recv().unwrap();
        let b = reqs.0.try_recv().unwrap();
        let _opening = reqs.0.try_recv().unwrap();
        g.mark_open(a);
        g.mark_open(b);
        // UDP 443 is busy (live flows); TCP 80 is still opening and within its open timeout.
        let claimed = g.claim_for_teardown(Duration::ZERO, Duration::MAX, |p, _| p == Proto::Udp);
        assert_eq!(claimed, vec![a]);
        // Claimed ports aren't claimed twice.
        assert!(
            g.claim_for_teardown(Duration::ZERO, Duration::MAX, |p, _| p == Proto::Udp)
                .is_empty()
        );
        // Nothing is idle for an hour.
        assert!(
            g.claim_for_teardown(Duration::from_secs(3600), Duration::MAX, never_busy)
                .is_empty()
        );
    }

    #[test]
    fn stuck_opening_is_claimed_and_its_held_packets_dropped() {
        let (g, mut reqs, mut ns) = gate(16);
        g.ingress(&tcp(9000, true, false));
        let r = reqs.0.try_recv().unwrap();
        assert_eq!(
            g.claim_for_teardown(Duration::MAX, Duration::ZERO, never_busy),
            vec![r]
        );
        assert_eq!(
            g.listener_ended(r),
            None,
            "dropped packets don't re-open the port"
        );
        g.mark_open(r);
        assert!(drain(&mut ns).is_empty());
    }

    #[test]
    fn caps_bound_active_ports_and_held_packets() {
        let (g, mut reqs, _ns) = gate(2);
        assert_eq!(g.ingress(&tcp(1, true, false)), Admit::Held);
        assert_eq!(g.ingress(&udp(2)), Admit::Held);
        assert_eq!(g.ingress(&tcp(3, true, false)), Admit::Dropped);
        let first = reqs.0.try_recv().unwrap();
        assert!(reqs.0.try_recv().is_ok());
        assert!(reqs.0.try_recv().is_err());

        for _ in 1..MAX_HELD_PER_PORT {
            assert_eq!(g.ingress(&tcp(1, true, false)), Admit::Held);
        }
        assert_eq!(g.ingress(&tcp(1, true, false)), Admit::Dropped);

        // Ending a listener frees its active slot.
        g.listener_ended(first);
        assert_eq!(g.ingress(&tcp(3, true, false)), Admit::Held);
    }
}
