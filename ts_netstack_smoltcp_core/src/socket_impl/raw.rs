use alloc::vec;

use bytes::Bytes;
use smoltcp::{
    iface::SocketHandle,
    socket::{AnySocket, raw},
};

use crate::{
    Netstack, Response,
    command::Error,
    raw::{Command as RawSocketCommand, Response as RawSocketResponse},
};

impl Netstack {
    /// Process a raw socket command.
    #[tracing::instrument(skip_all, fields(?raw, ?handle), level = "debug")]
    pub(crate) fn process_raw(
        &mut self,
        raw: RawSocketCommand,
        handle: Option<SocketHandle>,
    ) -> Response {
        match raw {
            RawSocketCommand::Open {
                ip_version,
                protocol,
            } => {
                let sock = raw::Socket::new(
                    Some(ip_version),
                    Some(protocol),
                    self.raw_buffer(),
                    self.raw_buffer(),
                );
                let handle = self.add_socket(sock);

                RawSocketResponse::Opened { handle }.into()
            }
            RawSocketCommand::Send { buf } => {
                let sock = get_socket_mut!(self, raw::Socket, handle);

                if buf.len() > sock.payload_send_capacity() {
                    tracing::error!(
                        len = buf.len(),
                        capacity = sock.payload_send_capacity(),
                        "send can never succeed, packet size is greater than socket buffer cap"
                    );

                    return Response::Error(Error::big_packet());
                }

                match sock.send_slice(&buf) {
                    Ok(()) => Response::Ok,
                    Err(raw::SendError::BufferFull) => Response::WouldBlock {
                        command: RawSocketCommand::Send { buf }.into(),
                        handle,
                    },
                }
            }
            RawSocketCommand::Recv { max_len } => {
                let sock = get_socket_mut!(self, raw::Socket, handle);

                match sock.recv() {
                    Ok(mut buf) => {
                        let mut trunc = None;

                        if let Some(max_len) = max_len {
                            let max_len = max_len.get();

                            if max_len < buf.len() {
                                tracing::warn!(max_len, pkt_len = buf.len(), "truncating packet");

                                trunc = Some(buf.len());
                                buf = &buf[..max_len];
                            }
                        }

                        RawSocketResponse::Recv {
                            buf: Bytes::copy_from_slice(buf),
                            truncated: trunc,
                        }
                        .into()
                    }
                    Err(raw::RecvError::Exhausted) => Response::WouldBlock {
                        command: RawSocketCommand::Recv { max_len }.into(),
                        handle,
                    },
                    Err(raw::RecvError::Truncated) => {
                        // this can't occur for recv()
                        unreachable!()
                    }
                }
            }
            RawSocketCommand::Close => {
                // `remove` also panics on a stale handle. A `Close` is never re-queued (it returns
                // `Response::Ok`, never `WouldBlock`), but a caller could send it twice, so guard
                // the double-close rather than panic the netstack actor.
                //
                // Identity alone is not enough: `SocketHandle` is a bare slot index, so a freed raw
                // slot can come back holding a TCP or UDP socket. Matching on the handle only would
                // then remove that live socket instead of doing nothing, and nothing panics at the
                // point of damage. Check the type too, as the UDP `Close` arm does (#297).
                let handle = unwrap_handle!(handle);
                let matches_type = self
                    .socket_set
                    .iter()
                    .any(|(h, socket)| h == handle && raw::Socket::downcast(socket).is_some());
                if matches_type {
                    self.remove_socket(handle);
                }
                Response::Ok
            }
        }
    }

    fn raw_buffer(&self) -> raw::PacketBuffer<'static> {
        raw::PacketBuffer::new(
            vec![raw::PacketMetadata::EMPTY; self.config.raw_message_count],
            vec![0; self.config.raw_buffer_size],
        )
    }
}

#[cfg(test)]
mod tests {
    use smoltcp::{
        time::Instant,
        wire::{IpProtocol, IpVersion},
    };

    use crate::{
        Config, Netstack, Response,
        command::{Error, InternalErrorKind},
        raw::{Command as RawSocketCommand, Response as RawSocketResponse},
    };

    /// Regression test for tsr-02e: a blocked raw `Recv` can be re-run after its socket is closed
    /// (e.g. ping's raw ICMP socket dropped while a `Recv` is still queued). The re-run must NOT
    /// panic the netstack actor — it must return a clean missing-socket error response.
    #[test]
    fn recv_on_closed_raw_socket_returns_error_not_panic() {
        let mut stack = Netstack::new(Config::default(), Instant::ZERO);

        // Open a raw ICMP socket and capture its handle.
        let handle = match stack.process_raw(
            RawSocketCommand::Open {
                ip_version: IpVersion::Ipv4,
                protocol: IpProtocol::Icmp,
            },
            None,
        ) {
            Response::Raw(RawSocketResponse::Opened { handle }) => handle,
            other => panic!("expected Opened, got {other:?}"),
        };

        // A `Recv` on the empty socket should block (the live, pre-close behavior).
        assert!(matches!(
            stack.process_raw(RawSocketCommand::Recv { max_len: None }, Some(handle)),
            Response::WouldBlock { .. }
        ));

        // Close the socket, removing the handle from the socket set.
        assert!(matches!(
            stack.process_raw(RawSocketCommand::Close, Some(handle)),
            Response::Ok
        ));

        // Re-running the blocked `Recv` against the now-stale handle must not panic; it must
        // return a clean missing-socket error response.
        let resp = stack.process_raw(RawSocketCommand::Recv { max_len: None }, Some(handle));
        assert!(
            matches!(
                resp,
                Response::Error(Error::Internal(InternalErrorKind::BadSocketHandle))
            ),
            "expected missing-socket error, got {resp:?}"
        );

        // A double-close against the stale handle must also not panic.
        assert!(matches!(
            stack.process_raw(RawSocketCommand::Close, Some(handle)),
            Response::Ok
        ));
    }

    /// Regression test for the raw half of #297: a freed raw slot can be recycled by a socket of
    /// another type, and `SocketHandle` is a bare slot index, so a stale raw `Close` that checks
    /// only handle identity removes somebody else's live socket. Nothing panics at the point of
    /// damage, which is what makes this quieter than the TCP case and worse for it.
    #[test]
    fn stale_raw_close_does_not_remove_recycled_socket_of_another_type() {
        use core::net::SocketAddr;

        let mut stack = Netstack::new(Config::default(), Instant::ZERO);

        let raw_handle = match stack.process_raw(
            RawSocketCommand::Open {
                ip_version: IpVersion::Ipv4,
                protocol: IpProtocol::Icmp,
            },
            None,
        ) {
            Response::Raw(RawSocketResponse::Opened { handle }) => handle,
            other => panic!("expected Opened, got {other:?}"),
        };

        assert!(matches!(
            stack.process_raw(RawSocketCommand::Close, Some(raw_handle)),
            Response::Ok
        ));

        let udp_handle = match stack.process_udp(
            crate::command::udp::Command::Bind {
                endpoint: SocketAddr::from(([127, 0, 0, 1], 9101)),
            },
            None,
        ) {
            Response::Udp(crate::command::udp::Response::Bound { handle, .. }) => handle,
            other => panic!("expected Bound, got {other:?}"),
        };
        assert_eq!(udp_handle, raw_handle, "the freed raw slot must be reused");

        assert!(matches!(
            stack.process_raw(RawSocketCommand::Close, Some(raw_handle)),
            Response::Ok
        ));
        assert!(
            stack
                .socket_set
                .get::<smoltcp::socket::udp::Socket>(udp_handle)
                .is_open(),
            "a stale raw Close must not remove the replacement UDP socket"
        );
    }
}
