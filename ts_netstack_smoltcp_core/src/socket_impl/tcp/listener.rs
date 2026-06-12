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
    current_socket_handle: SocketHandle,

    /// Sockets which have transitioned from `LISTEN` to `SYN-RECEIVED` (half-open) and are waiting
    /// to become `ESTABLISHED`; in other words, the socket received a `SYN` and replied with a
    /// `SYN-ACK`, and is awaiting an `ACK` to complete the handshake.
    ///
    /// Note that sockets in this queue can [transition back to the `LISTEN` state if the remote
    /// replies with a `RST` rather than an `ACK`](https://www.rfc-editor.org/rfc/rfc793#page-70).
    /// Sockets that return to `LISTEN` should be removed from this queue/dropped (not `close()`d);
    /// the listener has already opened a new socket in the `LISTEN` state.
    half_open_queue: VecDeque<SocketHandle>,

    /// Sockets which have transitioned from `SYN-RECEIVED` (half-open) to `ESTABLISHED`
    /// (full-open); in other words, the socket has received an `ACK` from the remote completing the
    /// three-way handshake. Sockets in this queue are waiting for a call to
    /// [`Netstack::process_tcp_listen()`] with a [`TcpListenCommand::Accept`] command, which will
    /// dequeue a socket and return it to become a [`TcpStream`].
    ///
    /// [`TcpStream`]: [::ts_netstack_smoltcp_socket::tcp::stream::TcpStream]
    accept_queue: VecDeque<SocketHandle>,
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
                let Some(listener) = self.tcp_listeners.get_mut(&handle) else {
                    tracing::error!(?handle, "listener does not exist");
                    return Error::missing_listener().into();
                };

                // Iterate the half-open queue, re-queueing any sockets that are still in
                // `SYN-RECEIVED`. Move any sockets in `ESTABLISHED` to the `accept_queue`, close
                // any sockets in `CLOSE-WAIT`, and drop any sockets that moved back to `LISTEN`.
                // All other states are unexpected.
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
                        tcp::State::Established => {
                            tracing::trace!("half-open socket ready, moving to accept queue");
                            listener.accept_queue.push_back(*half_open);
                            false
                        }
                        tcp::State::CloseWait => {
                            tracing::trace!("half-open socket moved to CLOSE-WAIT, closing");
                            sock.close();
                            self.pending_tcp_closes.push(*half_open);
                            if self.pending_tcp_closes.len() > 10000 {
                                tracing::warn!("large number of pending closes");
                            }
                            false
                        }
                        tcp::State::Listen => {
                            tracing::trace!("half-open socket moved to LISTEN, dropping");
                            false
                        }
                        _ => {
                            tracing::warn!("half-open socket in unexpected state, dropping");
                            false
                        }
                    }
                });

                // De-queue a single socket in the `ESTABLISHED` state from the `accept_queue` and
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
                        tcp::State::Established => {
                            tracing::trace!("accept socket accepted, returning")
                        }
                        tcp::State::CloseWait => {
                            tracing::trace!(?state, "accept socket no longer established, closing");
                            sock.close();
                            self.pending_tcp_closes.push(accept);
                            continue;
                        }
                        _ => {
                            tracing::warn!(?state, "accept socket in unexpected state, dropping");
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

                self.pending_tcp_closes.push(listener.current_socket_handle);

                let accept_handles = listener
                    .half_open_queue
                    .iter()
                    .chain(listener.accept_queue.iter())
                    .copied();
                for pending_accept in accept_handles {
                    let sock = self.socket_set.get_mut::<tcp::Socket>(pending_accept);
                    sock.close();

                    self.pending_tcp_closes.push(pending_accept);
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
    #[tracing::instrument(skip_all)]
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

            tcp::State::Established => {
                tracing::trace!("connection established");
                self.enforce_listen_backlog(handle);
                let listener = self
                    .tcp_listeners
                    .get_mut(&handle)
                    .expect("listener present");
                listener.accept_queue.push_back(current);
            }

            state => {
                tracing::warn!(
                    current_socket = ?current,
                    current_socket_state = %state,
                    listening_on = %local_endpoint,
                    "partially-established listening socket reset or closed");
                self.socket_set.get_mut::<tcp::Socket>(current).close();
                self.pending_tcp_closes.push(current);
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
            self.pending_tcp_closes.push(victim);
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

        stack.drain_tcp_closes();

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
}
