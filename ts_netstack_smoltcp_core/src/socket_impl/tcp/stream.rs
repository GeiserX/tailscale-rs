use bytes::Bytes;
use smoltcp::{
    iface::SocketHandle,
    socket::{AnySocket, tcp},
};

use crate::{
    Netstack,
    command::{
        Error, Response,
        tcp::stream::{Command as TcpStreamCommand, Response as TcpStreamResponse},
    },
};

impl Netstack {
    /// Process a TCP stream command.
    #[tracing::instrument(skip_all, fields(?cmd, ?handle), level = "debug")]
    pub(crate) fn process_tcp_stream(
        &mut self,
        cmd: TcpStreamCommand,
        handle: Option<SocketHandle>,
    ) -> Response {
        match cmd {
            TcpStreamCommand::Connect {
                remote_endpoint,
                local_endpoint,
            } => {
                if remote_endpoint.is_ipv4() != local_endpoint.is_ipv4() {
                    return Response::Error(Error::wrong_ip_version());
                }

                // Only occurs if we're polling a `WouldBlock`.
                if let Some(handle) = handle {
                    return self.check_conn(
                        handle,
                        TcpStreamCommand::Connect {
                            local_endpoint,
                            remote_endpoint,
                        },
                    );
                }

                let mut sock = self.new_tcp_socket();

                if let Err(e) = sock.connect(self.iface.context(), remote_endpoint, local_endpoint)
                {
                    tracing::error!(error = %e, "tcp connect");
                    return Response::Error(e.into());
                }

                let handle = self.add_socket(sock);

                Response::WouldBlock {
                    handle: Some(handle),
                    command: TcpStreamCommand::Connect {
                        local_endpoint,
                        remote_endpoint,
                    }
                    .into(),
                }
            }

            TcpStreamCommand::Send { buf } => {
                let handle = unwrap_handle!(handle);
                // A consumer's first-touch `Send` (the direct, non-blocked path) can race the
                // reaper (tsr-9ue): if the socket was driven to `Closed` by the idle/keep-alive
                // timeout and reaped before this command runs, a raw `get_mut` would panic the
                // netstack actor. `get_socket_mut!` checks existence and returns `missing_socket`.
                let sock = get_socket_mut!(self, tcp::Socket, Some(handle));

                match sock.send_slice(&buf) {
                    Ok(0) => Response::WouldBlock {
                        handle: Some(handle),
                        command: TcpStreamCommand::Send { buf }.into(),
                    },
                    Ok(n) => TcpStreamResponse::Sent { n }.into(),
                    Err(tcp::SendError::InvalidState) => {
                        tracing::error!(state = %sock.state(), "invalid socket state for send");
                        Response::Error(Error::invalid_socket_state())
                    }
                }
            }

            TcpStreamCommand::Recv { max_len } => {
                let handle = unwrap_handle!(handle);
                // See `Send` above: guard against a reaped/closed handle so a first-touch `Recv`
                // returns a clean `missing_socket` (mapped to EOF at the `TcpStream` boundary)
                // instead of panicking the actor (tsr-9ue).
                let sock = get_socket_mut!(self, tcp::Socket, Some(handle));

                match sock.recv(|buf| {
                    let mut len = buf.len();

                    if let Some(max_len) = max_len {
                        len = len.min(max_len);
                    }

                    (len, Bytes::copy_from_slice(&buf[..len]))
                }) {
                    Ok(buf) if buf.is_empty() => Response::WouldBlock {
                        handle: Some(handle),
                        command: TcpStreamCommand::Recv { max_len }.into(),
                    },
                    Ok(buf) => TcpStreamResponse::Recv { buf }.into(),
                    Err(tcp::RecvError::Finished) => TcpStreamResponse::Finished.into(),
                    Err(tcp::RecvError::InvalidState) => {
                        tracing::error!(state = %sock.state(), "invalid socket state for recv");
                        Response::Error(Error::invalid_socket_state())
                    }
                }
            }

            TcpStreamCommand::Close => {
                let handle = unwrap_handle!(handle);

                // Guard against a handle the reaper (tsr-9ue) already removed: a `TcpStream`'s
                // `Drop`-time `Close` can arrive after the idle/keep-alive timeout drove the socket
                // to `Closed` and `reap_orphaned_closed_tcp` freed it. The socket is already gone,
                // so a raw `get_mut` would panic the actor; `missing_socket` is the right answer and
                // the `pending_tcp_closes.push` is correctly skipped by the early return.
                let sock = get_socket_mut!(self, tcp::Socket, Some(handle));
                sock.close();

                self.pending_tcp_closes.push(handle);

                Response::Ok
            }
            TcpStreamCommand::ShutdownWrite => {
                // smoltcp's `close()` is a write-half close: it sends a FIN and moves the socket to
                // `FinWait1`/`CloseWait`, but the receive side stays open until the peer FINs. This
                // is exactly `shutdown(SHUT_WR)`. Crucially we do NOT push to `pending_tcp_closes`
                // here (unlike `Close`): the socket must live on so the caller can keep reading the
                // peer's remaining data. It is reaped later by the consumer's `Close` (on `Drop`) or
                // by the idle/keep-alive timeout once both sides are done.
                //
                // Guard the handle (tsr-9ue): the reaper can free a timeout-`Closed` socket before a
                // first-touch `ShutdownWrite` runs, so existence-check rather than panic the actor.
                let sock = get_socket_mut!(self, tcp::Socket, handle);
                sock.close();

                Response::Ok
            }
        }
    }

    /// Drop all TCP sockets that have finished closing.
    #[tracing::instrument(skip_all)]
    pub(crate) fn drain_tcp_closes(&mut self) {
        // Take the list out so the `retain` closure doesn't hold a borrow of `*self`: removing a
        // socket now goes through `remove_socket` (which needs `&mut self` for the gen-map), and a
        // method call inside a `pending_tcp_closes.retain` closure would conflict with that borrow.
        let mut pending = core::mem::take(&mut self.pending_tcp_closes);
        pending.retain(|&handle| {
            let state = {
                let sock = self.socket_set.get::<tcp::Socket>(handle);
                sock.state()
            };

            let should_remove = state == tcp::State::Closed;
            if should_remove {
                self.remove_socket(handle);
            }

            !should_remove
        });
        self.pending_tcp_closes = pending;

        // Second pass (tsr-9ue): reap consumer-owned sockets that smoltcp drove to `Closed` on its
        // own (the iter42 idle/keep-alive timeout firing on a dead/idle accepted stream). The first
        // pass only scans `pending_tcp_closes`, so a socket the consumer never explicitly closed —
        // and never polls — would otherwise pin its slot + ~512 KiB of buffers forever.
        self.reap_orphaned_closed_tcp();
    }

    /// Reclaim consumer-owned TCP sockets that reached `Closed` without ever being queued for close.
    ///
    /// The idle/keep-alive timeout (iter42, applied by [`Netstack::new_tcp_socket`]) tears down the
    /// *wire* of a dead/idle accepted connection — smoltcp moves the socket to `Closed` and emits a
    /// RST — but the in-memory socket lingers until the consumer next touches its [`TcpStream`]
    /// (`Drop` → `Close` → `pending_tcp_closes`). An idle, non-polling consumer never triggers that,
    /// so [`Netstack::drain_tcp_closes`]'s `pending_tcp_closes`-only scan never reclaims it. This
    /// second pass closes that gap.
    ///
    /// A reaped handle is freed via [`Netstack::remove_socket`], so its generation is cleared in
    /// `handle_gens`; any blocked command still referencing it is dropped on replay by the
    /// generation guard (iter65, ABA fix). A consumer's *next* first-touch command against the
    /// reaped handle returns `missing_socket` rather than panicking — the four direct handlers in
    /// [`Netstack::process_tcp_stream`] route through `get_socket_mut!` for exactly this.
    ///
    /// The predicate is deliberately conservative — only reap a socket that is ALL of:
    /// - a TCP socket (the heterogeneous `socket_set` also holds Raw/Icmp/Udp; downcast + skip),
    /// - **fully** `Closed` (NOT a half-closed `FinWait*`/`CloseWait`/`Closing`/`TimeWait`/`LastAck`
    ///   — per iter48 a half-closed socket's receive side may still be open, so it is not orphaned),
    /// - rx-empty (`!can_recv()`): a timeout-`Closed` socket can still hold unread RX the consumer
    ///   is entitled to read; reaping it would silently lose that data, so gate on an empty buffer,
    /// - not already in `pending_tcp_closes` (the first pass owns those), and
    /// - not referenced by any listener (a listener's current/half-open/accept-queue sockets are
    ///   netstack-owned, not consumer-owned — reaping one would desync the listener).
    fn reap_orphaned_closed_tcp(&mut self) {
        // Exclusion set: every handle a listener still owns is netstack-internal, never orphaned.
        let mut owned: alloc::collections::BTreeSet<SocketHandle> = Default::default();
        for l in self.tcp_listeners.values() {
            owned.insert(l.current_socket_handle);
            owned.extend(l.half_open_queue.iter().copied());
            owned.extend(l.accept_queue.iter().copied());
        }

        // Collect victims first (immutable `iter()` borrow), then remove (needs `&mut self`): the
        // collect must finish — releasing the borrow — before the `remove_socket` loop. smoltcp's
        // `socket_set.iter()` yields `(SocketHandle, &Socket)` over a heterogeneous set, so downcast
        // to `tcp::Socket` and skip non-TCP. Never use `socket_set.get::<tcp::Socket>(h)` here: it
        // panics on a non-TCP or stale handle.
        let victims: alloc::vec::Vec<SocketHandle> = self
            .socket_set
            .iter()
            .filter_map(|(h, s)| tcp::Socket::downcast(s).map(|t| (h, t)))
            .filter(|(h, t)| {
                t.state() == tcp::State::Closed
                    && !t.can_recv()
                    && !owned.contains(h)
                    && !self.pending_tcp_closes.contains(h)
            })
            .map(|(h, _)| h)
            .collect();

        for h in victims {
            tracing::debug!(
                handle = ?h,
                "reaping autonomously-closed consumer-owned TCP socket (tsr-9ue)"
            );
            // `remove_socket` (not raw `socket_set.remove`) so `handle_gens` stays consistent.
            self.remove_socket(h);
        }
    }

    fn check_conn(&mut self, handle: SocketHandle, orig_cmd: TcpStreamCommand) -> Response {
        let sock = self.socket_set.get_mut::<tcp::Socket>(handle);

        match sock.state() {
            tcp::State::Established => {
                tracing::trace!("connection succeeded");
                TcpStreamResponse::Connected { handle }.into()
            }

            tcp::State::SynReceived | tcp::State::SynSent => Response::WouldBlock {
                handle: Some(handle),
                command: orig_cmd.into(),
            },

            _ => {
                tracing::warn!("connecting socket was reset or closed");
                self.pending_tcp_closes.push(handle);
                Response::Error(Error::ConnectionReset)
            }
        }
    }
}

#[cfg(test)]
mod reap_tests {
    use core::net::SocketAddr;

    use bytes::Bytes;
    use smoltcp::{phy::Medium, socket::tcp, time::Instant};

    use super::*;
    use crate::{Config, Netstack, Pipe, PipeDev};

    /// True iff `handle` still occupies a slot in the socket set. `socket_set.get(handle)` panics on
    /// a removed handle, so membership must be probed via the non-panicking `iter()`.
    fn present(stack: &Netstack, handle: SocketHandle) -> bool {
        stack.socket_set.iter().any(|(h, _)| h == handle)
    }

    /// A self-looping L3 device: whatever the stack transmits is handed straight back on the next
    /// receive (`tx` and `rx` are the two ends of a *single* channel). This is a true loopback NIC,
    /// which is exactly what a `127.0.0.1 → 127.0.0.1` handshake needs — smoltcp egresses every
    /// packet to the device even for a local address (it does no internal loopback), so the device
    /// must return it for ingress.
    fn loopback_dev() -> PipeDev {
        let (tx, rx) = flume::unbounded();
        PipeDev {
            pipe: Pipe { tx, rx },
            medium: Medium::Ip,
            mtu: 1536,
        }
    }

    /// Drive the stack against the loopback device until socket state stops changing (bounded), so a
    /// multi-packet TCP handshake / data exchange converges. `Instant::ZERO` never advances, so the
    /// idle/keep-alive timeout cannot fire here — state only changes from real packet exchange.
    fn pump(stack: &mut Netstack, dev: &mut PipeDev) {
        for _ in 0..64 {
            if !stack.poll_device_io(Instant::ZERO, dev) {
                break;
            }
        }
    }

    /// Establish a real loopback TCP connection inside one stack and return the **consumer-owned**
    /// accepted socket handle (the half a `TcpStream` would own). A listener on `127.0.0.1:port`
    /// plus a `Connect` to it completes over the loopback device; `Accept` then hands back the
    /// established socket, which `process_tcp_listen` removes from the listener's queues — so the
    /// returned handle is no longer listener-owned and is a legitimate orphan-reap candidate once it
    /// closes. Also returns the device so the caller can pump further exchanges (e.g. inbound data).
    fn establish_accepted(port: u16) -> (Netstack, PipeDev, SocketHandle) {
        let mut stack = Netstack::new(
            Config {
                loopback: true,
                ..Default::default()
            },
            Instant::ZERO,
        );
        let mut dev = loopback_dev();

        let listener = match stack.process_tcp_listen(
            crate::command::tcp::listen::Command::Listen {
                local_endpoint: SocketAddr::from(([127, 0, 0, 1], port)),
            },
            None,
        ) {
            Response::TcpListen(crate::command::tcp::listen::Response::Listening { handle }) => {
                handle
            }
            other => panic!("expected Listening, got {other:?}"),
        };

        // Dial the listener from an ephemeral local port. `Connect` returns `WouldBlock` with the
        // freshly-added connecting socket's handle; the handshake completes as we pump the device.
        let local = SocketAddr::from(([127, 0, 0, 1], 50000));
        let remote = SocketAddr::from(([127, 0, 0, 1], port));
        assert!(matches!(
            stack.process_tcp_stream(
                TcpStreamCommand::Connect {
                    local_endpoint: local,
                    remote_endpoint: remote,
                },
                None,
            ),
            Response::WouldBlock { .. }
        ));

        pump(&mut stack, &mut dev);

        // Accept the now-established connection; this dequeues it from the listener so the handle
        // becomes consumer-owned.
        let accepted = match stack.process_tcp_listen(
            crate::command::tcp::listen::Command::Accept { handle: listener },
            None,
        ) {
            Response::TcpListen(crate::command::tcp::listen::Response::Accepted {
                handle, ..
            }) => handle,
            other => panic!("expected Accepted after handshake, got {other:?}"),
        };

        assert_eq!(
            stack.socket_set.get::<tcp::Socket>(accepted).state(),
            tcp::State::Established,
            "accepted socket must be established"
        );
        (stack, dev, accepted)
    }

    /// Test 1 — the headline reap: an accepted socket that the netstack drove to `Closed` on its own
    /// (modelled by `abort()`, exactly what the idle/keep-alive timeout does) with an empty RX, not
    /// in `pending_tcp_closes` and not listener-owned, is reaped by `drain_tcp_closes` WITHOUT any
    /// consumer poll/Close.
    #[test]
    fn idle_autonomously_closed_accepted_socket_is_reaped() {
        let (mut stack, _dev, accepted) = establish_accepted(8001);

        // The netstack tears the wire down on its own (timeout) → Closed, RX empty. No `Close` from
        // the consumer, so the handle is NOT in `pending_tcp_closes`.
        stack.socket_set.get_mut::<tcp::Socket>(accepted).abort();
        assert_eq!(
            stack.socket_set.get::<tcp::Socket>(accepted).state(),
            tcp::State::Closed
        );
        assert!(!stack.socket_set.get::<tcp::Socket>(accepted).can_recv());
        assert!(!stack.pending_tcp_closes.contains(&accepted));

        stack.drain_tcp_closes();

        assert!(
            !present(&stack, accepted),
            "an orphaned, autonomously-Closed, rx-empty accepted socket must be reaped"
        );
        assert!(
            stack.handle_gen(accepted).is_none(),
            "reap must clear the handle's generation (went through remove_socket)"
        );
    }

    /// Test 2 — data-loss guard: a `Closed` socket that still holds unread RX is NOT reaped (the
    /// consumer is entitled to read it). After the RX is drained, the next drain reaps it.
    #[test]
    fn closed_socket_with_unread_rx_is_not_reaped_until_drained() {
        let (mut stack, mut dev, accepted) = establish_accepted(8002);

        // Push inbound bytes to the accepted socket over the loopback: the *connector* side (the
        // other end of the same connection) sends, and pumping delivers it into `accepted`'s RX.
        // The connector handle isn't directly addressable, but the established socket on the
        // ephemeral local port is its peer; send from the accepted socket's peer by writing to the
        // connector. Simplest: send from `accepted` to its peer is the wrong direction — instead we
        // drive data peer→accepted by sending on the connector socket. Locate it by handle scan: the
        // only other Established TCP socket is the connector.
        let connector = stack
            .socket_set
            .iter()
            .filter_map(|(h, s)| tcp::Socket::downcast(s).map(|t| (h, t)))
            .find(|(h, t)| *h != accepted && t.state() == tcp::State::Established)
            .map(|(h, _)| h)
            .expect("the connector socket is the established peer");

        stack
            .socket_set
            .get_mut::<tcp::Socket>(connector)
            .send_slice(b"unread-bytes")
            .expect("connector can send");
        pump(&mut stack, &mut dev);

        // Now tear the accepted socket's wire down (timeout) while its RX still holds the bytes.
        assert!(
            stack.socket_set.get::<tcp::Socket>(accepted).can_recv(),
            "accepted socket must hold the inbound bytes before we close it"
        );
        stack.socket_set.get_mut::<tcp::Socket>(accepted).abort();
        assert_eq!(
            stack.socket_set.get::<tcp::Socket>(accepted).state(),
            tcp::State::Closed
        );
        assert!(
            stack.socket_set.get::<tcp::Socket>(accepted).can_recv(),
            "abort() must not discard unread RX"
        );

        stack.drain_tcp_closes();
        assert!(
            present(&stack, accepted),
            "a Closed socket with unread RX must NOT be reaped (data-loss guard)"
        );

        // Drain the RX, then re-drain: now it is rx-empty + Closed → reaped.
        let _ = stack
            .socket_set
            .get_mut::<tcp::Socket>(accepted)
            .recv(|buf| (buf.len(), ()));
        assert!(!stack.socket_set.get::<tcp::Socket>(accepted).can_recv());

        stack.drain_tcp_closes();
        assert!(
            !present(&stack, accepted),
            "once RX is drained, the orphaned Closed socket is reaped"
        );
    }

    /// Test 3 — half-closed states are NOT reaped (only fully `Closed`): `close()` on an established
    /// socket moves it to `FinWait1` (write-half closed, read side still open), which must survive
    /// the reap.
    #[test]
    fn half_closed_finwait_socket_is_not_reaped() {
        let (mut stack, _dev, accepted) = establish_accepted(8003);

        stack.socket_set.get_mut::<tcp::Socket>(accepted).close();
        assert_eq!(
            stack.socket_set.get::<tcp::Socket>(accepted).state(),
            tcp::State::FinWait1,
            "close() on an established socket yields FinWait1 (half-closed)"
        );

        stack.drain_tcp_closes();
        assert!(
            present(&stack, accepted),
            "a half-closed (FinWait1) socket must NOT be reaped — its read side may still be open"
        );
    }

    /// Test 4 — listener-owned handles are excluded even when `Closed`. A handle sitting in a
    /// listener's `half_open_queue` (and likewise its current/accept-queue slots) is netstack-owned;
    /// reaping it would desync the listener, so it must survive even after being aborted to `Closed`.
    #[test]
    fn listener_owned_closed_socket_is_not_reaped() {
        let mut stack = Netstack::new(Config::default(), Instant::ZERO);

        // Create a real listener via the public path so its `current_socket_handle` is populated.
        let lh = match stack.process_tcp_listen(
            crate::command::tcp::listen::Command::Listen {
                local_endpoint: SocketAddr::from(([0, 0, 0, 0], 8004)),
            },
            None,
        ) {
            Response::TcpListen(crate::command::tcp::listen::Response::Listening { handle }) => {
                handle
            }
            other => panic!("expected Listening, got {other:?}"),
        };

        // A socket parked in the listener's half-open queue, aborted to Closed.
        let half_open = {
            let sock = stack.new_tcp_socket();
            stack.add_socket(sock)
        };
        stack.socket_set.get_mut::<tcp::Socket>(half_open).abort();
        stack
            .tcp_listeners
            .get_mut(&lh)
            .unwrap()
            .half_open_queue
            .push_back(half_open);
        assert_eq!(
            stack.socket_set.get::<tcp::Socket>(half_open).state(),
            tcp::State::Closed
        );

        // The listener's current (LISTEN) socket is also owned; capture it to assert it survives.
        let current = stack.tcp_listeners[&lh].current_socket_handle;

        stack.drain_tcp_closes();

        assert!(
            present(&stack, half_open),
            "a Closed socket owned by a listener's half_open_queue must NOT be reaped"
        );
        assert!(
            present(&stack, current),
            "the listener's current LISTEN socket must NOT be reaped"
        );
    }

    /// Test 5 — the TCP reap leaves non-TCP sockets untouched: a bound UDP socket (heterogeneous
    /// entry in the same socket set) must survive the downcast-gated scan.
    #[test]
    fn non_tcp_udp_socket_is_untouched_by_reap() {
        let mut stack = Netstack::new(Config::default(), Instant::ZERO);

        let udp_handle = match stack.process_udp(
            crate::command::udp::Command::Bind {
                endpoint: SocketAddr::from(([127, 0, 0, 1], 9001)),
            },
            None,
        ) {
            Response::Udp(crate::command::udp::Response::Bound { handle, .. }) => handle,
            other => panic!("expected Bound, got {other:?}"),
        };
        // The `Bound` response already proves this slot holds a UDP socket; the reap's downcast to
        // `tcp::Socket` returns `None` for it, so it is skipped rather than reaped.

        stack.drain_tcp_closes();

        assert!(
            present(&stack, udp_handle),
            "the TCP reap must not touch a UDP socket"
        );
    }

    /// Test 6 (Part 2) — a consumer first-touch (direct, non-blocked) command against a reaped
    /// handle returns a clean `missing_socket` error and does NOT panic the netstack actor. Covers
    /// `Recv`/`Send`/`Close` (the four direct handlers now route through `get_socket_mut!`).
    #[test]
    fn first_touch_command_on_reaped_handle_returns_error_not_panic() {
        let (mut stack, _dev, accepted) = establish_accepted(8005);

        // Reap it (autonomously Closed + drained).
        stack.socket_set.get_mut::<tcp::Socket>(accepted).abort();
        stack.drain_tcp_closes();
        assert!(!present(&stack, accepted), "socket must be reaped first");

        use crate::command::InternalErrorKind;
        let missing = |r: &Response| {
            matches!(
                r,
                Response::Error(Error::Internal(InternalErrorKind::BadSocketHandle))
            )
        };

        let recv =
            stack.process_tcp_stream(TcpStreamCommand::Recv { max_len: None }, Some(accepted));
        assert!(
            missing(&recv),
            "first-touch Recv must be missing_socket, got {recv:?}"
        );

        let send = stack.process_tcp_stream(
            TcpStreamCommand::Send {
                buf: Bytes::copy_from_slice(b"x"),
            },
            Some(accepted),
        );
        assert!(
            missing(&send),
            "first-touch Send must be missing_socket, got {send:?}"
        );

        let close = stack.process_tcp_stream(TcpStreamCommand::Close, Some(accepted));
        assert!(
            missing(&close),
            "first-touch Close must be missing_socket, got {close:?}"
        );

        let shutdown = stack.process_tcp_stream(TcpStreamCommand::ShutdownWrite, Some(accepted));
        assert!(
            missing(&shutdown),
            "first-touch ShutdownWrite must be missing_socket, got {shutdown:?}"
        );
    }

    /// Test 8 (no-regression sibling) — a plain `Connect` socket left in `SynSent` (never reaches
    /// `Closed`) is untouched by the reap. Guards against the reap accidentally widening to
    /// connecting sockets.
    #[test]
    fn connecting_synsent_socket_is_not_reaped() {
        let mut stack = Netstack::new(
            Config {
                loopback: true,
                ..Default::default()
            },
            Instant::ZERO,
        );

        let connecting = match stack.process_tcp_stream(
            TcpStreamCommand::Connect {
                local_endpoint: SocketAddr::from(([127, 0, 0, 1], 50001)),
                remote_endpoint: SocketAddr::from(([127, 0, 0, 1], 9100)),
            },
            None,
        ) {
            Response::WouldBlock {
                handle: Some(h), ..
            } => h,
            other => panic!("expected WouldBlock with a handle, got {other:?}"),
        };
        // No device pumping: the SYN is never answered, the socket stays SynSent (not Closed).
        assert_eq!(
            stack.socket_set.get::<tcp::Socket>(connecting).state(),
            tcp::State::SynSent
        );

        stack.drain_tcp_closes();
        assert!(
            present(&stack, connecting),
            "a SynSent connecting socket is not Closed, so the reap must leave it alone"
        );
    }
}
