use bytes::{Bytes, BytesMut};
use smoltcp::{iface::SocketHandle, socket::tcp};

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
                self.connecting_tcp_sockets.insert(handle);

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

            cmd @ (TcpStreamCommand::Recv { .. } | TcpStreamCommand::RecvCoalesced { .. }) => {
                let handle = unwrap_handle!(handle);
                // See `Send` above: guard against a reaped/closed handle so a first-touch `Recv`
                // returns a clean `missing_socket` (mapped to EOF at the `TcpStream` boundary)
                // instead of panicking the actor (tsr-9ue).
                let sock = get_socket_mut!(self, tcp::Socket, Some(handle));

                let result = if let TcpStreamCommand::RecvCoalesced { max_len } = cmd {
                    // One command drains the ready RX snapshot across ring wrap. No extra
                    // runtime round trip and no wait for a future segment to fill the buffer.
                    let mut out = BytesMut::with_capacity(sock.recv_queue().min(max_len));
                    loop {
                        let result = sock.recv(|buf| {
                            let n = buf.len().min(max_len - out.len());
                            out.extend_from_slice(&buf[..n]);
                            (n, n)
                        });
                        match result {
                            Ok(n) if n == 0 || out.len() == max_len || sock.recv_queue() == 0 => {
                                break Ok(out.freeze());
                            }
                            Ok(_) => {}
                            Err(e) => break Err(e),
                        }
                    }
                } else {
                    let TcpStreamCommand::Recv { max_len } = cmd else {
                        unreachable!()
                    };
                    sock.recv(|buf| {
                        let mut len = buf.len();

                        if let Some(max_len) = max_len {
                            len = len.min(max_len);
                        }

                        (len, Bytes::copy_from_slice(&buf[..len]))
                    })
                };
                match result {
                    Ok(buf) if buf.is_empty() => Response::WouldBlock {
                        handle: Some(handle),
                        command: cmd.into(),
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
                // the `pending_tcp_closes.insert` is correctly skipped by the early return.
                let sock = get_socket_mut!(self, tcp::Socket, Some(handle));
                sock.close();

                self.pending_tcp_closes.insert(handle);

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
    #[tracing::instrument(level = "trace", skip_all)]
    pub(crate) fn drain_tcp_closes(&mut self, now: smoltcp::time::Instant) -> bool {
        let before = self.tcp_socket_count;
        // Reset connects historically disappeared before the next replay, producing missing_socket.
        // Check only outstanding connects so the bounded orphan cadence preserves that behavior.
        let mut connecting = core::mem::take(&mut self.connecting_tcp_sockets);
        connecting.retain(|&handle| {
            if !self.socket_matches::<tcp::Socket>(handle) {
                return false;
            }
            let sock = self.socket_set.get::<tcp::Socket>(handle);
            if sock.state() == tcp::State::Closed && !sock.can_recv() {
                self.remove_socket(handle);
                return false;
            }
            matches!(sock.state(), tcp::State::SynSent | tcp::State::SynReceived)
        });
        self.connecting_tcp_sockets = connecting;

        // Take the deduplicated set out to allow removal through the registry wrapper.
        let mut pending = core::mem::take(&mut self.pending_tcp_closes);
        pending.retain(|&handle| {
            // Covers a removed slot and #297's recycled slot of another socket type.
            if !self.socket_matches::<tcp::Socket>(handle) {
                return false;
            }

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
        //
        // The pass runs at most once per interval. A drive inside the interval arms one trailing
        // pass at its deadline instead, so a socket closed by that drive is still reclaimed on
        // time, while an idle stack wakes only for smoltcp's own timers, as main and Go do.
        if self.tcp_socket_count > 0 {
            if now >= self.next_orphan_sweep {
                self.next_orphan_sweep = now + crate::ORPHAN_SWEEP_INTERVAL;
                self.orphan_sweep_armed = false;
                self.reap_orphaned_closed_tcp();
            } else {
                self.orphan_sweep_armed = true;
            }
        }
        self.tcp_socket_count != before
    }

    /// Reclaim consumer-owned TCP sockets that reached `Closed` without ever being queued for close.
    ///
    /// The idle/keep-alive timeout (iter42, applied by [`Netstack::new_tcp_socket`]) tears down the
    /// *wire* of a dead/idle accepted connection — smoltcp moves the socket to `Closed` and emits a
    /// RST — but the in-memory socket lingers until the consumer next touches its [`TcpStream`]
    /// (`Drop` → `Close` → `pending_tcp_closes`). An idle, non-polling consumer never triggers that,
    /// so [`Netstack::drain_tcp_closes`]'s `pending_tcp_closes`-only scan never reclaims it. This
    /// second pass closes that gap. It runs at most once per 100 ms; after a drive that fell inside
    /// that window `poll_at` includes its deadline, and I/O pollers call the drain even without
    /// packet progress.
    ///
    /// A reaped handle is freed via [`Netstack::remove_socket`], so its generation is cleared in
    /// `socket_registry`; any blocked command still referencing it is dropped on replay by the
    /// generation guard (iter65, ABA fix). A consumer's *next* first-touch command against the
    /// reaped handle returns `missing_socket` rather than panicking — the four direct handlers in
    /// [`Netstack::process_tcp_stream`] route through `get_socket_mut!` for exactly this.
    ///
    /// The predicate is deliberately conservative — only reap a socket that is ALL of:
    /// - a TCP socket (kind checked in the heterogeneous registry),
    /// - **fully** `Closed` (NOT a half-closed `FinWait*`/`CloseWait`/`Closing`/`TimeWait`/`LastAck`
    ///   — per iter48 a half-closed socket's receive side may still be open, so it is not orphaned),
    /// - rx-empty (`!can_recv()`): a timeout-`Closed` socket can still hold unread RX the consumer
    ///   is entitled to read; reaping it would silently lose that data, so gate on an empty buffer,
    /// - not already in `pending_tcp_closes` (the first pass owns those), and
    /// - not referenced by any listener (a listener's current/half-open/accept-queue sockets are
    ///   netstack-owned, not consumer-owned — reaping one would desync the listener).
    fn reap_orphaned_closed_tcp(&mut self) {
        self.metrics.record(crate::Metric::OrphanSweeps, 1);

        // Exclusion set: every handle a listener still owns is netstack-internal, never orphaned.
        let mut owned: alloc::collections::BTreeSet<SocketHandle> = Default::default();
        for l in self.tcp_listeners.values() {
            owned.insert(l.current_socket_handle);
            owned.extend(l.half_open_queue.iter().copied());
            owned.extend(l.accept_queue.iter().copied());
        }

        // Iterate live registry entries rather than the socket storage high-water mark.
        // Collect victims before removing them through the wrappers.
        let victims: alloc::vec::Vec<SocketHandle> = self
            .socket_registry
            .iter()
            .filter_map(|(&h, entry)| {
                self.metrics.record(crate::Metric::OrphanSocketVisits, 1);
                if entry.kind != crate::SocketKind::Tcp {
                    return None;
                }
                let t = self.socket_set.get::<tcp::Socket>(h);
                (t.state() == tcp::State::Closed
                    && !t.can_recv()
                    && !owned.contains(&h)
                    && !self.pending_tcp_closes.contains(&h))
                .then_some(h)
            })
            .collect();

        for h in victims {
            tracing::debug!(
                handle = ?h,
                "reaping autonomously-closed consumer-owned TCP socket (tsr-9ue)"
            );
            // `remove_socket` (not raw `socket_set.remove`) so `socket_registry` stays consistent.
            self.remove_socket(h);
        }
    }

    fn check_conn(&mut self, handle: SocketHandle, orig_cmd: TcpStreamCommand) -> Response {
        let sock = get_socket_mut!(self, tcp::Socket, Some(handle));

        match sock.state() {
            // The peer can answer and close (data, then FIN) before this replay runs. The socket
            // is then in CLOSE-WAIT with the reply buffered and its send half still open: the
            // connect succeeded, exactly as for a listener socket accepted in CLOSE-WAIT.
            tcp::State::Established | tcp::State::CloseWait => {
                self.connecting_tcp_sockets.remove(&handle);
                tracing::trace!("connection succeeded");
                TcpStreamResponse::Connected { handle }.into()
            }

            tcp::State::SynReceived | tcp::State::SynSent => Response::WouldBlock {
                handle: Some(handle),
                command: orig_cmd.into(),
            },

            _ => {
                tracing::warn!("connecting socket was reset or closed");
                self.pending_tcp_closes.insert(handle);
                Response::Error(Error::ConnectionReset)
            }
        }
    }
}

#[cfg(test)]
mod connect_tests {
    use core::net::{Ipv4Addr, SocketAddr};

    use smoltcp::{
        phy::{ChecksumCapabilities, Medium},
        time::Instant,
        wire::{IpProtocol, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber},
    };

    use super::*;
    use crate::{Config, Netstack, Pipe, PipeDev, Request};

    const LOCAL: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
    const PEER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 2);
    const PEER_ISN: u32 = 5000;

    fn connect_cmd() -> TcpStreamCommand {
        TcpStreamCommand::Connect {
            local_endpoint: SocketAddr::from((LOCAL, 50000)),
            remote_endpoint: SocketAddr::from((PEER, 80)),
        }
    }

    /// A segment from the peer to the connecting socket.
    fn from_peer(control: TcpControl, seq: u32, ack: u32, payload: &[u8]) -> Bytes {
        let tcp = TcpRepr {
            src_port: 80,
            dst_port: 50000,
            control,
            seq_number: TcpSeqNumber(seq as i32),
            ack_number: Some(TcpSeqNumber(ack as i32)),
            window_len: 65535,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload,
        };
        let ip = Ipv4Repr {
            src_addr: PEER,
            dst_addr: LOCAL,
            next_header: IpProtocol::Tcp,
            payload_len: tcp.buffer_len(),
            hop_limit: 64,
        };
        let caps = ChecksumCapabilities::default();
        let mut buf = alloc::vec![0; ip.buffer_len() + tcp.buffer_len()];
        ip.emit(&mut Ipv4Packet::new_unchecked(&mut buf[..]), &caps);
        tcp.emit(
            &mut TcpPacket::new_unchecked(&mut buf[ip.buffer_len()..]),
            &PEER.into(),
            &LOCAL.into(),
            &caps,
        );
        Bytes::from(buf)
    }

    /// Control flag and sequence number of a segment the connecting socket sent.
    fn parse_sent(pkt: &[u8]) -> (TcpControl, u32) {
        let ip = Ipv4Packet::new_checked(pkt).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        let control = if tcp.rst() {
            TcpControl::Rst
        } else if tcp.syn() {
            TcpControl::Syn
        } else if tcp.fin() {
            TcpControl::Fin
        } else {
            TcpControl::None
        };
        (control, tcp.seq_number().0 as u32)
    }

    fn present(stack: &Netstack, handle: SocketHandle) -> bool {
        stack.socket_set.iter().any(|(h, _)| h == handle)
    }

    /// A Connect that has sent its SYN and is blocked waiting for the peer.
    struct Connecting {
        stack: Netstack,
        handle: SocketHandle,
        reply: flume::Receiver<Response>,
        phy: Pipe,
        dev: PipeDev,
        /// Acknowledgement of the connecting socket's SYN.
        ack: u32,
    }

    impl Connecting {
        fn start() -> Self {
            let mut stack = Netstack::new(Config::default(), Instant::ZERO);
            stack.targeted_replay = None;
            assert!(stack.direct_set_ips([LOCAL.into()]));
            let (resp, reply) = flume::bounded(1);
            stack.process_one_cmd(Request {
                handle: None,
                command: connect_cmd().into(),
                resp,
            });
            let handle = stack
                .blocked_commands
                .front()
                .expect("connect blocks until the peer answers")
                .0
                .handle
                .expect("connect opened a socket");
            let (net, phy) = Pipe::unbounded();
            let mut dev = PipeDev {
                pipe: net,
                medium: Medium::Ip,
                mtu: 1500,
            };
            stack.poll_device_io(Instant::ZERO, &mut dev);
            let (control, isn) = parse_sent(&phy.rx.try_recv().expect("the SYN"));
            assert_eq!(control, TcpControl::Syn);
            Self {
                stack,
                handle,
                reply,
                phy,
                dev,
                ack: isn.wrapping_add(1),
            }
        }

        /// Deliver the peer's segments in one ingress pass, so all of them land before the
        /// blocked Connect is replayed.
        fn deliver(&mut self, segments: &[Bytes]) {
            for seg in segments {
                self.phy.tx.try_send(seg.clone()).unwrap();
            }
            self.stack.poll_device_io(Instant::ZERO, &mut self.dev);
        }

        fn syn_ack(&self) -> Bytes {
            from_peer(TcpControl::Syn, PEER_ISN, self.ack, &[])
        }
    }

    /// The peer's SYN-ACK, its reply and its FIN can all arrive before the blocked Connect is
    /// replayed. The socket is then in CLOSE-WAIT; Connect must succeed with the reply readable,
    /// EOF after it, and the send half writable.
    #[test]
    fn connect_completes_when_the_peer_replies_and_closes_first() {
        let mut c = Connecting::start();
        c.deliver(&[
            c.syn_ack(),
            from_peer(TcpControl::None, PEER_ISN + 1, c.ack, b"reply"),
            from_peer(TcpControl::Fin, PEER_ISN + 6, c.ack, &[]),
        ]);

        match c.reply.try_recv() {
            Ok(Response::TcpStream(TcpStreamResponse::Connected { handle })) => {
                assert_eq!(handle, c.handle)
            }
            other => panic!("connect must complete, got {other:?}"),
        }
        let sock = c.stack.socket_set.get_mut::<tcp::Socket>(c.handle);
        assert_eq!(sock.state(), tcp::State::CloseWait);
        let mut buf = [0; 32];
        let n = sock.recv_slice(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"reply");
        assert_eq!(sock.recv_slice(&mut buf), Err(tcp::RecvError::Finished));
        assert_eq!(sock.send_slice(b"request"), Ok(7));
    }

    /// A Connect whose caller went away while it was blocked must not complete a connection
    /// nobody owns: the socket is aborted, the peer gets a RST, and the socket is reclaimed.
    #[test]
    fn abandoned_blocked_connect_is_aborted_and_reclaimed() {
        let Connecting {
            mut stack,
            handle,
            reply,
            phy,
            mut dev,
            ack,
        } = Connecting::start();
        drop(reply);
        phy.tx
            .try_send(from_peer(TcpControl::Syn, PEER_ISN, ack, &[]))
            .unwrap();
        stack.poll_device_io(Instant::ZERO, &mut dev);

        assert!(stack.blocked_commands.is_empty());
        assert!(
            !present(&stack, handle),
            "the abandoned connection must be reclaimed"
        );
        let sent: alloc::vec::Vec<_> = phy.rx.try_iter().map(|p| parse_sent(&p).0).collect();
        assert!(
            sent.contains(&TcpControl::Rst),
            "the peer must get a RST, sent {sent:?}"
        );
    }

    /// A Connect whose caller went away before the actor first ran it opens no socket at all.
    #[test]
    fn abandoned_connect_that_never_ran_opens_no_socket() {
        let mut stack = Netstack::new(Config::default(), Instant::ZERO);
        stack.targeted_replay = None;
        assert!(stack.direct_set_ips([LOCAL.into()]));
        let (resp, reply) = flume::bounded(1);
        drop(reply);
        stack.process_one_cmd(Request {
            handle: None,
            command: connect_cmd().into(),
            resp,
        });
        assert!(stack.blocked_commands.is_empty());
        assert_eq!(stack.tcp_socket_count, 0, "no socket may be opened");
    }

    /// The caller can also go away after the check and before the reply is sent. A connection
    /// whose reply could not be delivered is aborted and reclaimed.
    #[test]
    fn undelivered_connection_is_aborted_and_reclaimed() {
        let mut c = Connecting::start();
        c.deliver(&[c.syn_ack()]);
        assert!(matches!(
            c.reply.try_recv(),
            Ok(Response::TcpStream(TcpStreamResponse::Connected { .. }))
        ));

        c.stack
            .reclaim_undelivered(&TcpStreamResponse::Connected { handle: c.handle }.into());
        assert_eq!(
            c.stack.socket_set.get::<tcp::Socket>(c.handle).state(),
            tcp::State::Closed
        );
        c.stack.drain_tcp_closes(c.stack.next_orphan_sweep);
        assert!(!present(&c.stack, c.handle));
    }
}

#[cfg(test)]
mod reap_tests {
    use core::net::SocketAddr;

    use bytes::Bytes;
    use smoltcp::{
        phy::Medium,
        socket::{AnySocket, tcp},
        time::Instant,
    };

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

        stack.drain_tcp_closes(stack.next_orphan_sweep);

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

        stack.drain_tcp_closes(stack.next_orphan_sweep);
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

        stack.drain_tcp_closes(stack.next_orphan_sweep);
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

        stack.drain_tcp_closes(stack.next_orphan_sweep);
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

        stack.drain_tcp_closes(stack.next_orphan_sweep);

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

        stack.drain_tcp_closes(stack.next_orphan_sweep);

        assert!(
            present(&stack, udp_handle),
            "the TCP reap must not touch a UDP socket"
        );
    }

    /// Test 6 (Part 2) — a consumer first-touch (direct, non-blocked) command against a reaped
    /// handle returns a clean `missing_socket` error and does NOT panic the netstack actor. Covers
    /// `Recv`/`Send`/`Close` (the four direct handlers now route through `get_socket_mut!`).
    ///
    /// Also covers the recycled-slot half of #297: the reaped slot is deliberately re-filled, first
    /// by a UDP socket and then by a TCP one, so each stale command meets a handle that still
    /// EXISTS but holds the wrong type. An identity-only guard passes that check and the typed
    /// getter then panics, so this exercises both directions — a stale TCP command finding UDP, and
    /// a stale UDP command finding TCP — plus the hand-rolled guard on the UDP `Close` arm.
    #[test]
    fn first_touch_command_on_reaped_handle_returns_error_not_panic() {
        let (mut stack, _dev, accepted) = establish_accepted(8005);

        // Reap it (autonomously Closed + drained).
        stack.socket_set.get_mut::<tcp::Socket>(accepted).abort();
        stack.drain_tcp_closes(stack.next_orphan_sweep);
        assert!(!present(&stack, accepted), "socket must be reaped first");

        let udp_handle = match stack.process_udp(
            crate::command::udp::Command::Bind {
                endpoint: SocketAddr::from(([127, 0, 0, 1], 9002)),
            },
            None,
        ) {
            Response::Udp(crate::command::udp::Response::Bound { handle, .. }) => handle,
            other => panic!("expected Bound, got {other:?}"),
        };
        assert_eq!(udp_handle, accepted, "the freed TCP slot must be reused");

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
        assert!(
            stack
                .socket_set
                .get::<smoltcp::socket::udp::Socket>(udp_handle)
                .is_open(),
            "stale TCP commands must not alter the replacement UDP socket"
        );

        assert!(matches!(
            stack.process_udp(crate::command::udp::Command::Close, Some(udp_handle)),
            Response::Ok
        ));
        let replacement = stack.new_tcp_socket();
        let replacement = stack.add_socket(replacement);
        assert_eq!(replacement, udp_handle, "the freed UDP slot must be reused");
        assert!(matches!(
            stack.process_udp(crate::command::udp::Command::Close, Some(udp_handle)),
            Response::Ok
        ));
        // Load-bearing, despite looking inert. With the pre-#297 identity-only guard, the `Close`
        // just above would have removed THIS TCP socket rather than no-oping on the stale UDP
        // handle it targeted, and `get` panics on a vanished handle. Asserting the state (rather
        // than `let _ = ...`) keeps the check visible so a future cleanup cannot quietly delete
        // the only regression signal for the UDP-Close half of the fix.
        assert_eq!(
            stack.socket_set.get::<tcp::Socket>(replacement).state(),
            tcp::State::Closed,
            "a stale UDP Close on a recycled-into-TCP slot must not remove the new TCP socket"
        );

        // The mirror direction, which nothing else covers: the macro instantiated at
        // `udp::Socket` (udp.rs:118 `Recv`, udp.rs:65 `Send`) must also reject a handle whose slot
        // now holds a TCP socket. Without the type check these panic in `get_mut::<udp::Socket>`.
        let recv = stack.process_udp(
            crate::command::udp::Command::Recv { max_len: None },
            Some(replacement),
        );
        assert!(
            missing(&recv),
            "stale UDP Recv on a recycled-into-TCP slot must be missing_socket, got {recv:?}"
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

        // The sweep deadline must not hide an earlier SYN/retransmit deadline.
        assert_eq!(stack.poll_at(Instant::ZERO), Some(Instant::ZERO));
        stack.drain_tcp_closes(stack.next_orphan_sweep);
        assert!(
            present(&stack, connecting),
            "a SynSent connecting socket is not Closed, so the reap must leave it alone"
        );
    }
    #[test]
    fn orphan_sweeps_are_bounded_and_closed_socket_is_reaped_by_deadline() {
        let (mut stack, mut dev, accepted) = establish_accepted(8010);
        stack.socket_set.get_mut::<tcp::Socket>(accepted).abort();
        let before = stack.metrics.counts();
        for millis in 0..100 {
            assert!(!stack.drain_tcp_closes(Instant::from_millis(millis)));
            assert!(stack.handle_gen(accepted).is_some());
        }
        assert_eq!(stack.metrics.counts().orphan_sweeps, before.orphan_sweeps);
        assert_eq!(
            stack.metrics.counts().orphan_socket_visits,
            before.orphan_socket_visits
        );
        stack.poll_device_io(Instant::from_millis(100), &mut dev);
        assert_eq!(stack.handle_gen(accepted), None);
        assert_eq!(
            stack.metrics.counts().orphan_sweeps,
            before.orphan_sweeps + 1
        );
        let visits = stack.metrics.counts().orphan_socket_visits;
        for _ in 0..100 {
            stack.drain_tcp_closes(Instant::from_millis(100));
        }
        assert_eq!(stack.metrics.counts().orphan_socket_visits, visits);
        assert_eq!(stack.next_orphan_sweep, Instant::from_millis(200));
    }

    #[test]
    fn an_idle_stack_sets_no_orphan_timer_after_its_sweep() {
        let (mut stack, mut dev, accepted) = establish_accepted(8012);
        let sweep = stack.next_orphan_sweep;
        stack.poll_device_io(sweep, &mut dev);
        let next = stack.next_orphan_sweep;
        assert_eq!(next, sweep + crate::ORPHAN_SWEEP_INTERVAL, "the sweep ran");
        assert!(stack.handle_gen(accepted).is_some());
        // Nothing happened since that sweep: only smoltcp's own timers may wake the stack.
        let own = stack.iface.poll_at(sweep, &stack.socket_set);
        assert_eq!(stack.poll_at(sweep), own);

        // A drive inside the interval arms one trailing sweep at the deadline, and that sweep
        // disarms it again.
        let inside = sweep + smoltcp::time::Duration::from_millis(10);
        stack.poll_device_io(inside, &mut dev);
        let own = stack.iface.poll_at(inside, &stack.socket_set);
        assert_eq!(
            stack.poll_at(inside),
            Some(own.map_or(next, |d| d.min(next)))
        );
        stack.poll_device_io(next, &mut dev);
        let own = stack.iface.poll_at(next, &stack.socket_set);
        assert_eq!(stack.poll_at(next), own);
    }

    #[test]
    fn idle_sync_poller_reclaims_without_packet_progress() {
        let mut stack = Netstack::new(Config::default(), Instant::ZERO);
        assert_eq!(stack.poll_at(Instant::ZERO), None);
        let socket = stack.new_tcp_socket();
        let handle = stack.add_socket(socket);
        assert_eq!(
            stack.poll_at(Instant::ZERO),
            Some(Instant::from_millis(100))
        );
        assert_eq!(
            stack.poll_delay(Instant::from_millis(25)),
            Some(core::time::Duration::from_millis(75))
        );
        assert_eq!(
            stack.poll_delay(Instant::from_millis(110)),
            Some(core::time::Duration::ZERO)
        );
        let mut dev = loopback_dev();
        assert!(!stack.poll_device_io(Instant::ZERO, &mut dev));
        assert!(stack.poll_device_io(Instant::from_millis(100), &mut dev));
        assert!(stack.handle_gen(handle).is_none());
        assert_eq!(stack.poll_at(Instant::from_millis(100)), None);
    }

    #[test]
    fn idle_async_poller_reclaims_without_device_capacity() {
        use core::{
            pin::Pin,
            task::{Context, Poll, Waker},
        };

        use crate::AsyncWakeDevice;
        struct IdleDev(crate::util::NoopCapDev);
        impl smoltcp::phy::Device for IdleDev {
            type RxToken<'a> = <crate::util::NoopCapDev as smoltcp::phy::Device>::RxToken<'a>;
            type TxToken<'a> = <crate::util::NoopCapDev as smoltcp::phy::Device>::TxToken<'a>;
            fn receive(&mut self, _: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
                None
            }
            fn transmit(&mut self, _: Instant) -> Option<Self::TxToken<'_>> {
                None
            }
            fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
                self.0.capabilities()
            }
        }
        impl AsyncWakeDevice for IdleDev {
            fn poll_rx(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
                Poll::Pending
            }
            fn poll_tx(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
                Poll::Pending
            }
        }
        let mut stack = Netstack::new(Config::default(), Instant::ZERO);
        let socket = stack.new_tcp_socket();
        let handle = stack.add_socket(socket);
        let mut dev = IdleDev(crate::util::NoopCapDev::with_caps(|_| {}));
        let mut cx = Context::from_waker(Waker::noop());
        {
            let mut io = stack.wait_io_async(Instant::ZERO, &mut dev);
            assert!(Pin::new(&mut io).poll(&mut cx).is_pending());
        }
        {
            let mut io = stack.wait_io_async(Instant::from_millis(100), &mut dev);
            assert!(Pin::new(&mut io).poll(&mut cx).is_ready());
        }
        assert!(stack.handle_gen(handle).is_none());
        assert_eq!(stack.metrics.counts().orphan_sweeps, 1);
    }
    #[test]
    fn reset_connect_is_reclaimed_promptly_without_an_orphan_sweep() {
        let mut stack = Netstack::new(
            Config {
                loopback: true,
                ..Default::default()
            },
            Instant::ZERO,
        );
        let handle = match stack.process_tcp_stream(
            TcpStreamCommand::Connect {
                local_endpoint: SocketAddr::from(([127, 0, 0, 1], 50000)),
                remote_endpoint: SocketAddr::from(([127, 0, 0, 1], 80)),
            },
            None,
        ) {
            Response::WouldBlock {
                handle: Some(h), ..
            } => h,
            other => panic!("expected blocked connect, got {other:?}"),
        };
        assert!(stack.connecting_tcp_sockets.contains(&handle));
        stack.socket_set.get_mut::<tcp::Socket>(handle).abort();
        assert!(stack.drain_tcp_closes(Instant::ZERO));
        assert!(stack.handle_gen(handle).is_none());
        assert!(stack.connecting_tcp_sockets.is_empty());
        assert_eq!(stack.metrics.counts().orphan_sweeps, 0);
        assert_eq!(stack.metrics.counts().orphan_socket_visits, 0);
    }
}
