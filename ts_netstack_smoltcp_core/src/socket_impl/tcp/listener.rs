use alloc::collections::VecDeque;
use core::net::SocketAddr;

use smoltcp::{iface::SocketHandle, socket::tcp, wire::IpListenEndpoint};

use crate::{
    Netstack,
    command::{
        Error, Response,
        tcp::listen::{Command as TcpListenCommand, Response as TcpListenResponse},
    },
};

/// Translate a listen [`SocketAddr`] into a smoltcp [`IpListenEndpoint`].
///
/// A wildcard address (`0.0.0.0` / `::`) must become `addr: None` so smoltcp's `accepts()`
/// matches *any* destination IP. The blanket `From<SocketAddr>` instead yields
/// `addr: Some(0.0.0.0)`, which only matches a literal `0.0.0.0` destination and silently
/// breaks any-IP forwarding (every SYN gets RST). Keep the explicit address for non-wildcard
/// binds so a normal listener stays pinned to its own IP.
fn listen_endpoint(addr: SocketAddr) -> IpListenEndpoint {
    if addr.ip().is_unspecified() {
        IpListenEndpoint {
            addr: None,
            port: addr.port(),
        }
    } else {
        addr.into()
    }
}

/// Opaque handle to a TCP listener.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ListenerHandle(usize);

/// State for a particular TCP listener, supporting the abstraction of a single persistent
/// listener object that can spin off connections by calling `accept`.
///
/// `smoltcp` doesn't provide a TCP listener abstraction, just plain sockets. Each one has
/// its own state machine, which can be in the `LISTENING` state, i.e. waiting for a
/// connection. But once it's `ESTABLISHED`, you need to create a new `LISTENING` socket in
/// order to accept a new connection.
pub struct TcpListenerState {
    /// The local endpoint on which this listener is listening.
    local_endpoint: SocketAddr,

    /// Socket currently in listening state and waiting for a new connection.
    ///
    /// `pub(super)` so the sibling `stream` module's `reap_orphaned_closed_tcp` (tsr-9ue) can read
    /// the listener-owned handles it must exclude from the orphan reap.
    pub(super) current_socket_handle: SocketHandle,

    /// Sockets which have transitioned from `LISTEN` to `SYN-RECEIVED` (half-open) and are waiting
    /// to become `ESTABLISHED`; in other words, the socket received a `SYN` and replied with a
    /// `SYN-ACK`, and is awaiting an `ACK` to complete the handshake.
    ///
    /// Note that sockets in this queue can [transition back to the `LISTEN` state if the remote
    /// replies with a `RST` rather than an `ACK`](https://www.rfc-editor.org/rfc/rfc793#page-70).
    /// Sockets that return to `LISTEN` should be removed from this queue/dropped (not `close()`d);
    /// the listener has already opened a new socket in the `LISTEN` state.
    ///
    /// `pub(super)`: see [`Self::current_socket_handle`] (excluded from the tsr-9ue orphan reap).
    pub(super) half_open_queue: VecDeque<SocketHandle>,

    /// Sockets which have transitioned from `SYN-RECEIVED` (half-open) to `ESTABLISHED`
    /// (full-open); in other words, the socket has received an `ACK` from the remote completing the
    /// three-way handshake. Sockets in this queue are waiting for a call to
    /// [`Netstack::process_tcp_listen()`] with a [`TcpListenCommand::Accept`] command, which will
    /// dequeue a socket and return it to become a [`TcpStream`].
    ///
    /// [`TcpStream`]: [::ts_netstack_smoltcp_socket::tcp::stream::TcpStream]
    ///
    /// `pub(super)`: see [`Self::current_socket_handle`] (excluded from the tsr-9ue orphan reap).
    pub(super) accept_queue: VecDeque<SocketHandle>,
}

impl Netstack {
    /// Process a TCP listener command.
    #[tracing::instrument(skip_all, fields(?cmd), level = "debug")]
    pub(crate) fn process_tcp_listen(
        &mut self,
        cmd: TcpListenCommand,
        handle: Option<SocketHandle>,
    ) -> Response {
        debug_assert!(handle.is_none());

        match cmd {
            TcpListenCommand::Listen { local_endpoint } => {
                let mut listener = self.new_tcp_socket();

                if let Err(e) = listener.listen(listen_endpoint(local_endpoint)) {
                    return Response::Error(e.into());
                }

                let socket_handle = self.add_socket(listener);

                let listener_handle = ListenerHandle(self.next_tcp_listener_id);
                self.next_tcp_listener_id += 1;

                self.tcp_listeners.insert(
                    listener_handle,
                    TcpListenerState {
                        current_socket_handle: socket_handle,
                        local_endpoint,
                        half_open_queue: Default::default(),
                        accept_queue: Default::default(),
                    },
                );

                TcpListenResponse::Listening {
                    handle: listener_handle,
                }
                .into()
            }
            TcpListenCommand::Accept { handle } => {
                if !self.tcp_listeners.contains_key(&handle) {
                    tracing::error!(?handle, "listener does not exist");
                    return Error::missing_listener().into();
                }
                self.prune_reset_half_open(handle);
                let listener = self
                    .tcp_listeners
                    .get_mut(&handle)
                    .expect("listener present");

                // A peer may send data and FIN before accept runs, including on the final
                // handshake ACK. CLOSE-WAIT still has a writable transmit half and buffered RX.
                // Reset/expired sockets are reclaimed explicitly, even when RX is nonempty.
                listener.half_open_queue.retain(|half_open| {
                    let sock = self.socket_set.get_mut::<tcp::Socket>(*half_open);
                    let state = sock.state();
                    let _span = tracing::trace_span!(
                        "half_open_queue",
                        accept_queue_len = listener.accept_queue.len(),
                        pending_closes = self.pending_tcp_closes.len(),
                        ?half_open,
                        ?state
                    )
                    .entered();

                    match state {
                        tcp::State::SynReceived => {
                            tracing::trace!("half-open socket unchanged, re-queueing");
                            true
                        }
                        tcp::State::Established | tcp::State::CloseWait => {
                            tracing::trace!(
                                ?state,
                                "half-open socket ready, moving to accept queue"
                            );
                            listener.accept_queue.push_back(*half_open);
                            false
                        }
                        tcp::State::Closed => {
                            tracing::debug!(
                                ?half_open,
                                ?state,
                                "half-open socket closed; reclaiming"
                            );
                            self.pending_tcp_closes.insert(*half_open);
                            false
                        }
                        tcp::State::Listen
                        | tcp::State::SynSent
                        | tcp::State::FinWait1
                        | tcp::State::FinWait2
                        | tcp::State::Closing
                        | tcp::State::TimeWait
                        | tcp::State::LastAck => {
                            // LISTEN is normally removed by prune_reset_half_open. The other
                            // states require a local close/connect and have no accepting consumer.
                            tracing::warn!(
                                ?half_open,
                                ?state,
                                "half-open socket in unexpected state; aborting and reclaiming"
                            );
                            sock.abort();
                            self.pending_tcp_closes.insert(*half_open);
                            false
                        }
                    }
                });

                // De-queue a socket in ESTABLISHED or CLOSE-WAIT from the accept queue and
                // return it to become a `TcpStream`.
                while let Some(accept) = listener.accept_queue.pop_front() {
                    let sock = self.socket_set.get_mut::<tcp::Socket>(accept);
                    let state = sock.state();
                    let _span = tracing::trace_span!(
                        "accept_queue",
                        half_open_queue_len = listener.half_open_queue.len(),
                        accept_queue_len = listener.accept_queue.len(),
                        pending_closes = self.pending_tcp_closes.len(),
                        ?accept,
                        ?state
                    )
                    .entered();

                    match state {
                        tcp::State::Established | tcp::State::CloseWait => {
                            tracing::trace!(?state, "accept socket accepted, returning")
                        }
                        tcp::State::Closed => {
                            tracing::debug!(?accept, ?state, "accept socket closed; reclaiming");
                            self.pending_tcp_closes.insert(accept);
                            continue;
                        }
                        tcp::State::Listen
                        | tcp::State::SynSent
                        | tcp::State::SynReceived
                        | tcp::State::FinWait1
                        | tcp::State::FinWait2
                        | tcp::State::Closing
                        | tcp::State::TimeWait
                        | tcp::State::LastAck => {
                            tracing::warn!(
                                ?accept,
                                ?state,
                                "accept socket in unexpected state; aborting and reclaiming"
                            );
                            sock.abort();
                            self.pending_tcp_closes.insert(accept);
                            continue;
                        }
                    }

                    let remote = sock.remote_endpoint().unwrap();
                    // Under any-IP acceptance, `local_endpoint` is the original packet
                    // destination -- possibly an address the netstack doesn't own. A forwarder
                    // dials this to splice the flow to a real OS socket.
                    let local = sock.local_endpoint().unwrap();
                    return TcpListenResponse::Accepted {
                        handle: accept,
                        remote: SocketAddr::new(remote.addr.into(), remote.port),
                        local: SocketAddr::new(local.addr.into(), local.port),
                    }
                    .into();
                }

                tracing::trace!("accept queue empty");

                Response::WouldBlock {
                    handle: None,
                    command: TcpListenCommand::Accept { handle }.into(),
                }
            }
            TcpListenCommand::Close { handle } => {
                let Some(listener) = self.tcp_listeners.remove(&handle) else {
                    tracing::error!(?handle, "listener does not exist");
                    return Error::missing_listener().into();
                };

                let sock = self
                    .socket_set
                    .get_mut::<tcp::Socket>(listener.current_socket_handle);

                sock.close();

                self.pending_tcp_closes
                    .insert(listener.current_socket_handle);

                let accept_handles = listener
                    .half_open_queue
                    .iter()
                    .chain(listener.accept_queue.iter())
                    .copied();
                for pending_accept in accept_handles {
                    let sock = self.socket_set.get_mut::<tcp::Socket>(pending_accept);
                    sock.close();

                    self.pending_tcp_closes.insert(pending_accept);
                }

                Response::Ok
            }
            TcpListenCommand::BoundPorts => {
                // Read-only: snapshot the local ports of every explicit listener. Never touches
                // the packet ingress / accept path, so it can't perturb the RST behavior the
                // fallback-handler manager relies on.
                let ports = self
                    .tcp_listeners
                    .values()
                    .map(|l| l.local_endpoint.port())
                    .collect();
                TcpListenResponse::BoundPorts { ports }.into()
            }
        }
    }

    /// Attempt to accept a TCP connection for all TCP listeners.
    #[tracing::instrument(level = "trace", skip_all)]
    pub(crate) fn pump_tcp_accept(&mut self) {
        // Iterate listener handles (not `values_mut()`) so the body holds a full `&mut self` and can
        // call `&self`/`&mut self` helpers (`new_tcp_socket`, the backlog enforcement). The listener
        // set isn't mutated during the loop (listeners are only added/removed by `process_tcp_listen`,
        // which never runs concurrently with a pump), so a snapshot of handles is stable.
        let handles: alloc::vec::Vec<ListenerHandle> = self.tcp_listeners.keys().copied().collect();
        for handle in handles {
            self.pump_one_tcp_listener(handle);
        }
    }

    /// Pump a single listener: promote its current socket out of `LISTEN`, enforce the accept
    /// backlog, and open a fresh `LISTEN` socket to replace it.
    fn pump_one_tcp_listener(&mut self, handle: ListenerHandle) {
        self.prune_reset_half_open(handle);
        let Some(listener) = self.tcp_listeners.get_mut(&handle) else {
            return;
        };
        let current = listener.current_socket_handle;
        let local_endpoint = listener.local_endpoint;

        let sock = self.socket_set.get_mut::<tcp::Socket>(current);
        let state = sock.state();
        let _span = tracing::trace_span!(
            "pump_one_tcp_listener",
            current_socket = ?current,
            current_socket_state = %state,
            listening_on = %local_endpoint,
        )
        .entered();

        match state {
            tcp::State::Listen => {
                tracing::trace!("listening");
                return;
            }

            tcp::State::SynReceived => {
                tracing::trace!("socket pending, not yet established");
                // Enforce the accept backlog BEFORE enqueuing: a SYN/handshake flood would otherwise
                // grow `half_open_queue` + the global socket set without bound. At the cap, abort
                // (RST) and drop the oldest half-open to make room — mirroring a kernel/gVisor accept
                // backlog. Established-but-unaccepted sockets count toward the same bound.
                self.enforce_listen_backlog(handle);
                let listener = self
                    .tcp_listeners
                    .get_mut(&handle)
                    .expect("listener present");
                listener.half_open_queue.push_back(current);
            }

            // ESTABLISHED and CLOSE-WAIT cannot reach the current socket here. One segment moves a
            // LISTEN socket no further than SYN-RECEIVED (smoltcp rejects SYN together with FIN as
            // malformed), smoltcp 0.14 reports a state change for every received frame, and every
            // ingress path pumps the listeners after each one. So a connection is always seen in
            // SYN-RECEIVED first and moves on to ESTABLISHED/CLOSE-WAIT from the half-open queue.
            state => {
                tracing::warn!(
                    current_socket = ?current,
                    current_socket_state = %state,
                    listening_on = %local_endpoint,
                    "partially-established listening socket reset or closed");
                self.socket_set.get_mut::<tcp::Socket>(current).close();
                self.pending_tcp_closes.insert(current);
            }
        }

        // fallthrough: socket has either closed or been established -- create a new listen socket
        let mut new_listener = self.new_tcp_socket();

        if let Err(e) = new_listener.listen(listen_endpoint(local_endpoint)) {
            // invariant failure: the only variants for ListenError are
            // InvalidState and Unaddressable. InvalidState isn't possible here because we just
            // created the socket. Unaddressable only occurs if local_endpoint has
            // an unspecified (zero) port and/or address. but we're currently replacing a socket
            // with the _same_ local_endpoint, and it clearly wasn't invalid before, so
            // Unaddressable shouldn't be possible either. this should always succeed.
            panic!("opening new listen socket for accept: {e}");
        }

        let socket_handle = self.add_socket(new_listener);
        self.tcp_listeners
            .get_mut(&handle)
            .expect("listener present")
            .current_socket_handle = socket_handle;
        tracing::trace!(new_handle = ?socket_handle, "replaced active listen socket");
    }

    /// Remove half-open sockets that a RST sent back to `LISTEN`.
    ///
    /// smoltcp returns a listener-born socket in `SYN-RECEIVED` to `LISTEN` when it gets a RST
    /// (`vendor/smoltcp/src/socket/tcp.rs`, RFC 793). Such a socket is no longer tracked as a
    /// connection, but it still listens on this port, and smoltcp hands each SYN to the first
    /// matching socket. If it stays in the socket set it completes later handshakes that no
    /// `Accept` ever returns: the client sees a connection that nobody serves. Every listener pump
    /// (after each socket-changing packet) removes them, before the next SYN can arrive.
    fn prune_reset_half_open(&mut self, handle: ListenerHandle) {
        let Some(listener) = self.tcp_listeners.get_mut(&handle) else {
            return;
        };
        let mut reset = alloc::vec::Vec::new();
        listener.half_open_queue.retain(|&h| {
            let back_to_listen =
                self.socket_set.get::<tcp::Socket>(h).state() == tcp::State::Listen;
            if back_to_listen {
                reset.push(h);
            }
            !back_to_listen
        });
        for h in reset {
            tracing::trace!(?h, "half-open socket reset back to LISTEN; removing");
            self.remove_socket(h);
        }
    }

    /// If the listener is at or over its accept backlog (half-open + established-unaccepted), abort
    /// (RST) and drop the oldest queued sockets until there is room for one more. Half-open sockets
    /// are shed first (they are the cheapest to discard and the SYN-flood vector); only if the
    /// half-open queue is empty are established-but-unaccepted sockets shed. Aborted sockets are
    /// pushed to `pending_tcp_closes` so `drain_tcp_closes` reclaims them once they reach `Closed`.
    fn enforce_listen_backlog(&mut self, handle: ListenerHandle) {
        let backlog = self.config.tcp_listen_backlog.max(1);
        loop {
            let listener = match self.tcp_listeners.get_mut(&handle) {
                Some(l) => l,
                None => return,
            };
            // Room for the one about to be enqueued?
            if listener.half_open_queue.len() + listener.accept_queue.len() < backlog {
                return;
            }
            // Shed the oldest half-open first; only when none remain shed the oldest
            // established-but-unaccepted (it carries real buffered data, so it is the costlier drop).
            let victim = listener
                .half_open_queue
                .pop_front()
                .or_else(|| listener.accept_queue.pop_front());
            let Some(victim) = victim else {
                // Both queues empty but the sum still >= backlog is impossible; guard anyway.
                return;
            };
            tracing::debug!(
                ?victim,
                backlog,
                "accept backlog full; aborting oldest pending connection to make room"
            );
            // `abort()` (RST) rather than `close()` (FIN) so the slot frees on the next
            // `drain_tcp_closes` without a `FinWait` lifetime: abort moves the socket to `Closed`
            // synchronously, which is exactly the state `drain_tcp_closes` reaps.
            self.socket_set.get_mut::<tcp::Socket>(victim).abort();
            self.pending_tcp_closes.insert(victim);
            // Same diagnostic guard as the accept-path close: under a sustained flood every shed
            // victim lands here, and `drain_tcp_closes` only runs once per poll, so a burst can
            // pile up between drains.
            if self.pending_tcp_closes.len() > 10000 {
                tracing::warn!("large number of pending closes");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use core::net::SocketAddr;

    use smoltcp::time::Instant;

    use super::*;
    use crate::{Config, Netstack};

    /// Build a listener registered in the stack with an empty current listen socket, returning its
    /// handle. Mirrors what `process_tcp_listen(Listen)` does, without needing the command channel.
    fn register_listener(stack: &mut Netstack, port: u16) -> ListenerHandle {
        let local_endpoint = SocketAddr::from(([0, 0, 0, 0], port));
        let mut sock = stack.new_tcp_socket();
        sock.listen(listen_endpoint(local_endpoint)).unwrap();
        let current = stack.add_socket(sock);
        let lh = ListenerHandle(stack.next_tcp_listener_id);
        stack.next_tcp_listener_id += 1;
        stack.tcp_listeners.insert(
            lh,
            TcpListenerState {
                current_socket_handle: current,
                local_endpoint,
                half_open_queue: VecDeque::new(),
                accept_queue: VecDeque::new(),
            },
        );
        lh
    }

    /// Push `n` freshly-created sockets onto the listener's half-open queue and return their handles
    /// oldest-first, so a test can assert which one the backlog sheds.
    fn fill_half_open(stack: &mut Netstack, lh: ListenerHandle, n: usize) -> Vec<SocketHandle> {
        let mut handles = Vec::new();
        for _ in 0..n {
            let sock = stack.new_tcp_socket();
            let h = stack.add_socket(sock);
            stack
                .tcp_listeners
                .get_mut(&lh)
                .unwrap()
                .half_open_queue
                .push_back(h);
            handles.push(h);
        }
        handles
    }

    fn queue_len(stack: &Netstack, lh: ListenerHandle) -> usize {
        let l = &stack.tcp_listeners[&lh];
        l.half_open_queue.len() + l.accept_queue.len()
    }

    /// At the backlog bound, enqueuing one more sheds the OLDEST half-open socket (FIFO) and queues
    /// it for close, keeping the listener at `backlog - 1` so the caller's push lands at exactly
    /// `backlog`. This is the SYN/handshake-flood bound: the queue can never grow without limit.
    #[test]
    fn enforce_listen_backlog_sheds_oldest_half_open_at_the_bound() {
        let mut stack = Netstack::new(
            Config {
                tcp_listen_backlog: 4,
                ..Default::default()
            },
            Instant::ZERO,
        );
        let lh = register_listener(&mut stack, 8443);

        // Fill to exactly the bound (4). enforce makes room for one more → drops the oldest.
        let handles = fill_half_open(&mut stack, lh, 4);
        assert_eq!(queue_len(&stack, lh), 4);

        stack.enforce_listen_backlog(lh);

        // One shed (room for the incoming one), and it's the OLDEST (FIFO).
        assert_eq!(queue_len(&stack, lh), 3, "must leave room for one more");
        assert!(
            stack.pending_tcp_closes.contains(&handles[0]),
            "the oldest half-open must be the one aborted + queued for close"
        );
        let remaining: Vec<_> = stack.tcp_listeners[&lh]
            .half_open_queue
            .iter()
            .copied()
            .collect();
        assert_eq!(remaining, handles[1..].to_vec(), "newer sockets are kept");
    }

    /// Below the bound, enforce is a no-op: nothing is shed, nothing is queued for close.
    #[test]
    fn enforce_listen_backlog_is_noop_below_the_bound() {
        let mut stack = Netstack::new(
            Config {
                tcp_listen_backlog: 8,
                ..Default::default()
            },
            Instant::ZERO,
        );
        let lh = register_listener(&mut stack, 8443);
        fill_half_open(&mut stack, lh, 3);

        stack.enforce_listen_backlog(lh);

        assert_eq!(queue_len(&stack, lh), 3, "below bound: nothing shed");
        assert!(stack.pending_tcp_closes.is_empty());
    }

    /// A wildly over-full queue (e.g. backlog lowered at runtime, or many arrivals between pumps) is
    /// drained back down to `backlog - 1` in one enforce call, not just by one.
    #[test]
    fn enforce_listen_backlog_drains_down_to_the_bound() {
        let mut stack = Netstack::new(
            Config {
                tcp_listen_backlog: 2,
                ..Default::default()
            },
            Instant::ZERO,
        );
        let lh = register_listener(&mut stack, 8443);
        fill_half_open(&mut stack, lh, 10);

        stack.enforce_listen_backlog(lh);

        assert_eq!(
            queue_len(&stack, lh),
            1,
            "drained to backlog-1 so the incoming push lands at the bound"
        );
        assert_eq!(
            stack.pending_tcp_closes.len(),
            9,
            "every shed socket is queued for close"
        );
    }

    /// When the half-open queue is empty, the backlog sheds the oldest *established-but-unaccepted*
    /// socket instead (the `.or_else(accept_queue)` branch) — the costlier drop, so it's the
    /// fallback, but it must still happen so an app that stops calling `accept()` can't grow the
    /// accept queue without bound either.
    #[test]
    fn enforce_listen_backlog_sheds_oldest_established_when_no_half_open() {
        let mut stack = Netstack::new(
            Config {
                tcp_listen_backlog: 3,
                ..Default::default()
            },
            Instant::ZERO,
        );
        let lh = register_listener(&mut stack, 8443);

        // Fill the ACCEPT queue (established-unaccepted) to the bound, leaving half-open empty.
        let mut established = Vec::new();
        for _ in 0..3 {
            let sock = stack.new_tcp_socket();
            let h = stack.add_socket(sock);
            stack
                .tcp_listeners
                .get_mut(&lh)
                .unwrap()
                .accept_queue
                .push_back(h);
            established.push(h);
        }
        assert_eq!(queue_len(&stack, lh), 3);

        stack.enforce_listen_backlog(lh);

        assert_eq!(queue_len(&stack, lh), 2, "one established socket shed");
        assert!(
            stack.pending_tcp_closes.contains(&established[0]),
            "the OLDEST established-unaccepted socket is shed when no half-open remain"
        );
    }

    /// End-to-end reclamation: a socket aborted by the backlog reaches `Closed` synchronously, so
    /// the very next `drain_tcp_closes` removes it from the `socket_set` — proving the shed actually
    /// frees the socket's buffers, not just dequeues the handle. This pins the load-bearing
    /// `abort()`-not-`close()` invariant: `close()` transitions through `FinWait` (not `Closed`), so
    /// a future change to `close()` here would leave the victim un-reaped and this test would fail.
    #[test]
    fn shed_socket_is_reclaimed_from_socket_set_by_drain() {
        let mut stack = Netstack::new(
            Config {
                tcp_listen_backlog: 2,
                ..Default::default()
            },
            Instant::ZERO,
        );
        let lh = register_listener(&mut stack, 8443);
        let handles = fill_half_open(&mut stack, lh, 2);

        stack.enforce_listen_backlog(lh);

        // The oldest was shed and queued for close...
        let victim = handles[0];
        assert!(stack.pending_tcp_closes.contains(&victim));
        // ...and `abort()` put it in `Closed` synchronously, so the socket is still present now.
        assert_eq!(
            stack.socket_set.get::<tcp::Socket>(victim).state(),
            tcp::State::Closed,
            "abort() reaches Closed synchronously"
        );

        stack.drain_tcp_closes(stack.next_orphan_sweep);

        // After drain, the handle is gone from both the pending list and the socket set (its
        // buffers are freed). A `get` on a removed handle would panic, so assert via the registry.
        assert!(
            !stack.pending_tcp_closes.contains(&victim),
            "drain removed the victim from the pending list"
        );
        // `socket_set.get(victim)` would panic on a removed handle, so check membership via `iter`.
        assert!(
            !stack.socket_set.iter().any(|(h, _)| h == victim),
            "drain removed the victim from the socket set (buffers freed)"
        );
    }

    const CLIENT: core::net::Ipv4Addr = core::net::Ipv4Addr::new(203, 0, 113, 2);
    const SERVER: core::net::Ipv4Addr = core::net::Ipv4Addr::new(203, 0, 113, 1);

    fn packet(
        control: smoltcp::wire::TcpControl,
        seq: u32,
        ack: Option<u32>,
        payload: &[u8],
    ) -> bytes::Bytes {
        use smoltcp::{
            phy::ChecksumCapabilities,
            wire::{IpProtocol, Ipv4Packet, Ipv4Repr, TcpPacket, TcpRepr, TcpSeqNumber},
        };
        let tcp = TcpRepr {
            src_port: 1000,
            dst_port: 80,
            control,
            seq_number: TcpSeqNumber(seq as i32),
            ack_number: ack.map(|n| TcpSeqNumber(n as i32)),
            window_len: 65535,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload,
        };
        let ip = Ipv4Repr {
            src_addr: CLIENT,
            dst_addr: SERVER,
            next_header: IpProtocol::Tcp,
            payload_len: tcp.buffer_len(),
            hop_limit: 64,
        };
        let caps = ChecksumCapabilities::default();
        let mut buf = alloc::vec![0; ip.buffer_len() + tcp.buffer_len()];
        ip.emit(&mut Ipv4Packet::new_unchecked(&mut buf[..]), &caps);
        tcp.emit(
            &mut TcpPacket::new_unchecked(&mut buf[ip.buffer_len()..]),
            &CLIENT.into(),
            &SERVER.into(),
            &caps,
        );
        bytes::Bytes::from(buf)
    }

    struct PendingConnection {
        stack: Netstack,
        listener: ListenerHandle,
        handle: SocketHandle,
        phy: crate::Pipe,
        dev: crate::PipeDev,
        ack: u32,
    }

    impl PendingConnection {
        fn new() -> Self {
            use smoltcp::{
                phy::Medium,
                wire::{Ipv4Packet, TcpControl, TcpPacket},
            };
            let mut stack = Netstack::new(Config::default(), Instant::ZERO);
            assert!(stack.direct_set_ips([SERVER.into()]));
            let listener = register_listener(&mut stack, 80);
            let (net, phy) = crate::Pipe::unbounded();
            let mut dev = crate::PipeDev {
                pipe: net,
                medium: Medium::Ip,
                mtu: 1500,
            };
            phy.tx
                .try_send(packet(TcpControl::Syn, 100, None, &[]))
                .unwrap();
            stack.poll_device_io(Instant::ZERO, &mut dev);
            let syn_ack = phy.rx.try_recv().unwrap();
            let ip = Ipv4Packet::new_checked(&syn_ack[..]).unwrap();
            let ack = (TcpPacket::new_checked(ip.payload()).unwrap().seq_number().0 as u32)
                .wrapping_add(1);
            let handle = stack.tcp_listeners[&listener].half_open_queue[0];
            Self {
                stack,
                listener,
                handle,
                phy,
                dev,
                ack,
            }
        }

        fn send(&mut self, control: smoltcp::wire::TcpControl, ack: u32, payload: &[u8]) {
            self.phy
                .tx
                .try_send(packet(control, 101, Some(ack), payload))
                .unwrap();
            self.stack.poll_device_io(Instant::ZERO, &mut self.dev);
        }

        fn move_to_accept_queue(&mut self) {
            let listener = self.stack.tcp_listeners.get_mut(&self.listener).unwrap();
            assert_eq!(listener.half_open_queue.pop_front(), Some(self.handle));
            listener.accept_queue.push_back(self.handle);
        }

        fn accept(&mut self) -> Response {
            self.stack.process_tcp_listen(
                TcpListenCommand::Accept {
                    handle: self.listener,
                },
                None,
            )
        }

        fn assert_reclaimed(&mut self) {
            assert!(matches!(self.accept(), Response::WouldBlock { .. }));
            self.stack.drain_tcp_closes(self.stack.next_orphan_sweep);
            assert!(
                !self.stack.socket_set.iter().any(|(h, _)| h == self.handle),
                "dequeued socket must release its buffers"
            );
        }
    }

    #[test]
    fn fin_before_accept_preserves_request_eof_and_reply() {
        use smoltcp::wire::TcpControl;
        for accept_queue in [false, true] {
            let mut c = PendingConnection::new();
            if accept_queue {
                c.send(TcpControl::None, c.ack, &[]);
                c.move_to_accept_queue();
            }
            // Also tests ACK + data + FIN completing the handshake directly into CLOSE-WAIT.
            c.send(TcpControl::Fin, c.ack, b"request");
            assert_eq!(
                c.stack.socket_set.get::<tcp::Socket>(c.handle).state(),
                tcp::State::CloseWait
            );
            assert!(
                matches!(c.accept(), Response::TcpListen(TcpListenResponse::Accepted { handle, .. })
                if handle == c.handle),
                "CLOSE-WAIT must be accepted"
            );
            let sock = c.stack.socket_set.get_mut::<tcp::Socket>(c.handle);
            let mut buf = [0; 32];
            let n = sock.recv_slice(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"request");
            assert_eq!(sock.recv_slice(&mut buf), Err(tcp::RecvError::Finished));
            assert_eq!(sock.send_slice(b"response"), Ok(8));
        }
    }

    /// An Accept whose caller went away must not take a connection nobody will serve: the
    /// connection stays queued for the next Accept. Covers an Accept that blocked before the
    /// handshake completed (it is replayed) and one that first runs after it.
    #[test]
    fn abandoned_accept_leaves_the_connection_for_the_next_accept() {
        use smoltcp::wire::TcpControl;
        for blocked in [true, false] {
            let mut c = PendingConnection::new();
            let (resp, reply) = flume::bounded(1);
            let abandoned = crate::Request {
                handle: None,
                command: TcpListenCommand::Accept { handle: c.listener }.into(),
                resp,
            };
            if blocked {
                c.stack.process_one_cmd(abandoned);
                assert_eq!(c.stack.blocked_commands.len(), 1, "accept blocks");
                drop(reply);
                // The handshake completes and the abandoned Accept is replayed.
                c.send(TcpControl::None, c.ack, &[]);
            } else {
                c.send(TcpControl::None, c.ack, &[]);
                drop(reply);
                c.stack.process_one_cmd(abandoned);
            }
            assert!(c.stack.blocked_commands.is_empty());
            assert!(
                matches!(c.accept(), Response::TcpListen(TcpListenResponse::Accepted { handle, .. })
                if handle == c.handle),
                "the next Accept must get the connection (blocked: {blocked})"
            );
        }
    }

    #[test]
    fn reset_with_unread_data_is_reclaimed_from_both_queues() {
        use smoltcp::wire::TcpControl;
        for accept_queue in [false, true] {
            let mut c = PendingConnection::new();
            c.send(TcpControl::None, c.ack, b"unread");
            if accept_queue {
                c.move_to_accept_queue();
            }
            // Advance sequence beyond the buffered request for an in-window reset.
            c.phy
                .tx
                .try_send(packet(TcpControl::Rst, 107, Some(c.ack), &[]))
                .unwrap();
            c.stack.poll_device_io(Instant::ZERO, &mut c.dev);
            assert_eq!(
                c.stack.socket_set.get::<tcp::Socket>(c.handle).state(),
                tcp::State::Closed
            );
            assert!(c.stack.socket_set.get::<tcp::Socket>(c.handle).can_recv());
            c.assert_reclaimed();
        }
    }

    #[test]
    fn locally_closed_unaccepted_sockets_are_reclaimed_in_every_closing_state() {
        use smoltcp::wire::TcpControl;
        for state in [
            tcp::State::FinWait1,
            tcp::State::FinWait2,
            tcp::State::Closing,
            tcp::State::TimeWait,
            tcp::State::LastAck,
        ] {
            for accept_queue in [false, true] {
                let mut c = PendingConnection::new();
                c.send(TcpControl::None, c.ack, &[]);
                if accept_queue {
                    c.move_to_accept_queue();
                }
                if state == tcp::State::LastAck {
                    c.send(TcpControl::Fin, c.ack, &[]);
                }
                c.stack.socket_set.get_mut::<tcp::Socket>(c.handle).close();
                match state {
                    tcp::State::FinWait2 => c.send(TcpControl::None, c.ack.wrapping_add(1), &[]),
                    tcp::State::Closing => c.send(TcpControl::Fin, c.ack, &[]),
                    tcp::State::TimeWait => c.send(TcpControl::Fin, c.ack.wrapping_add(1), &[]),
                    _ => {}
                }
                assert_eq!(
                    c.stack.socket_set.get::<tcp::Socket>(c.handle).state(),
                    state
                );
                c.assert_reclaimed();
            }
        }
    }

    #[test]
    fn accidental_active_open_in_half_open_queue_is_reclaimed() {
        let mut stack = Netstack::new(Config::default(), Instant::ZERO);
        assert!(stack.direct_set_ips([SERVER.into()]));
        let listener = register_listener(&mut stack, 80);
        let mut sock = stack.new_tcp_socket();
        sock.connect(stack.iface.context(), (CLIENT, 443), (SERVER, 1000))
            .unwrap();
        assert_eq!(sock.state(), tcp::State::SynSent);
        let handle = stack.add_socket(sock);
        stack
            .tcp_listeners
            .get_mut(&listener)
            .unwrap()
            .half_open_queue
            .push_back(handle);
        assert!(matches!(
            stack.process_tcp_listen(TcpListenCommand::Accept { handle: listener }, None),
            Response::WouldBlock { .. }
        ));
        stack.drain_tcp_closes(stack.next_orphan_sweep);
        assert!(!stack.socket_set.iter().any(|(h, _)| h == handle));
    }

    /// A client RST during the handshake sends smoltcp's half-open socket back to `LISTEN`. It
    /// must be removed, not left as a second, untracked listener on the port: that socket would
    /// complete the next client's handshake and no `Accept` would ever return it.
    #[test]
    fn reset_half_open_socket_does_not_capture_the_next_connection() {
        use core::net::{IpAddr, Ipv4Addr};

        use bytes::Bytes;
        use smoltcp::{
            phy::{ChecksumCapabilities, Medium},
            wire::{
                IpProtocol, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
            },
        };

        use crate::{Pipe, PipeDev};

        const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
        const SERVER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
        fn segment(src_port: u16, control: TcpControl, seq: u32, ack: Option<u32>) -> Bytes {
            let tcp = TcpRepr {
                src_port,
                dst_port: 80,
                control,
                seq_number: TcpSeqNumber(seq as i32),
                ack_number: ack.map(|a| TcpSeqNumber(a as i32)),
                window_len: 65535,
                window_scale: None,
                max_seg_size: None,
                sack_permitted: false,
                sack_ranges: [None; 3],
                timestamp: None,
                payload: &[],
            };
            let ip = Ipv4Repr {
                src_addr: CLIENT,
                dst_addr: SERVER,
                next_header: IpProtocol::Tcp,
                payload_len: tcp.buffer_len(),
                hop_limit: 64,
            };
            let caps = ChecksumCapabilities::default();
            let mut buf = alloc::vec![0u8; ip.buffer_len() + tcp.buffer_len()];
            ip.emit(&mut Ipv4Packet::new_unchecked(&mut buf[..]), &caps);
            tcp.emit(
                &mut TcpPacket::new_unchecked(&mut buf[ip.buffer_len()..]),
                &CLIENT.into(),
                &SERVER.into(),
                &caps,
            );
            Bytes::from(buf)
        }
        /// The server's sequence number from the next segment it sent.
        fn server_seq(phy: &Pipe) -> u32 {
            let pkt = phy.rx.try_recv().expect("server segment");
            let ip = Ipv4Packet::new_checked(&pkt[..]).unwrap();
            TcpPacket::new_checked(ip.payload()).unwrap().seq_number().0 as u32
        }

        let mut stack = Netstack::new(Config::default(), Instant::ZERO);
        assert!(stack.direct_set_ips([IpAddr::V4(SERVER)]));
        let lh = register_listener(&mut stack, 80);
        let (net, phy) = Pipe::unbounded();
        let mut dev = PipeDev {
            pipe: net,
            medium: Medium::Ip,
            mtu: 1500,
        };

        // Client A: SYN, then RST before completing the handshake.
        phy.tx
            .try_send(segment(1000, TcpControl::Syn, 100, None))
            .unwrap();
        stack.poll_device_io(Instant::ZERO, &mut dev);
        let _ = server_seq(&phy);
        phy.tx
            .try_send(segment(1000, TcpControl::Rst, 101, None))
            .unwrap();
        stack.poll_device_io(Instant::ZERO, &mut dev);

        let listening = stack
            .socket_set
            .iter()
            .filter_map(|(_, s)| <tcp::Socket as smoltcp::socket::AnySocket>::downcast(s))
            .filter(|s| s.state() == tcp::State::Listen)
            .count();
        assert_eq!(
            listening, 1,
            "a reset half-open socket must not stay listening"
        );

        // Client B connects normally and must be the connection `Accept` returns.
        phy.tx
            .try_send(segment(2000, TcpControl::Syn, 500, None))
            .unwrap();
        stack.poll_device_io(Instant::ZERO, &mut dev);
        let isn = server_seq(&phy);
        phy.tx
            .try_send(segment(
                2000,
                TcpControl::None,
                501,
                Some(isn.wrapping_add(1)),
            ))
            .unwrap();
        stack.poll_device_io(Instant::ZERO, &mut dev);
        match stack.process_tcp_listen(TcpListenCommand::Accept { handle: lh }, None) {
            Response::TcpListen(TcpListenResponse::Accepted { remote, .. }) => {
                assert_eq!(remote, SocketAddr::from((CLIENT, 2000)));
            }
            other => panic!("client B's connection must be accepted, got {other:?}"),
        }
    }
}
