use alloc::vec;
use core::net::SocketAddr;

use bytes::Bytes;
use smoltcp::{
    iface::SocketHandle,
    socket::udp,
    wire::{IpListenEndpoint, IpVersion},
};

use crate::command::{
    Error, Response,
    udp::{Command as UdpCommand, Response as UdpResponse},
};

impl crate::Netstack {
    /// Process a UDP socket command.
    #[tracing::instrument(skip_all, fields(?handle, ?cmd), level = "debug")]
    pub(crate) fn process_udp(
        &mut self,
        cmd: UdpCommand,
        handle: Option<SocketHandle>,
    ) -> Response {
        match cmd {
            UdpCommand::Bind { endpoint } => {
                let mut sock = udp::Socket::new(self.udp_buffer(), self.udp_buffer());

                if endpoint.port() == 0 {
                    tracing::error!(?endpoint, "udp bind: zero port");
                    return Response::Error(Error::unaddressable());
                }

                // A wildcard bind (`0.0.0.0` / `::`) must become `addr: None` so smoltcp's
                // `accepts()` matches datagrams to *any* destination IP (any-IP forwarding).
                // The blanket `From<SocketAddr>` would yield `addr: Some(0.0.0.0)`, which only
                // matches a literal `0.0.0.0` destination and silently drops forwarded flows.
                let listen = if endpoint.ip().is_unspecified() {
                    IpListenEndpoint {
                        addr: None,
                        port: endpoint.port(),
                    }
                } else {
                    endpoint.into()
                };

                // The two possible failure cases for `bind` are that the port is zero or the socket
                // was already open. Those are handled, so failure is impossible here.
                sock.bind(listen).unwrap();

                let handle = self.socket_set.add(sock);

                UdpResponse::Bound {
                    local: endpoint,
                    handle,
                }
                .into()
            }
            UdpCommand::Send {
                endpoint,
                local,
                buf,
            } => {
                let handle = unwrap_handle!(handle);

                let sock = get_socket_mut!(self, udp::Socket, Some(handle));

                // Enforce IP-version parity only when the socket is bound to a concrete address.
                // A wildcard bind (`addr: None`, used for any-IP forwarding) carries no version,
                // so it may legitimately send to either family; smoltcp rejects a genuinely
                // unaddressable send below.
                if let Some(bound) = sock.endpoint().addr {
                    let sock_is_v4 = bound.version() == IpVersion::Ipv4;
                    if endpoint.is_ipv4() != sock_is_v4 {
                        return Response::Error(Error::wrong_ip_version());
                    }
                }

                if buf.len() > sock.payload_send_capacity() {
                    tracing::error!(
                        len = buf.len(),
                        socket_capacity = sock.payload_send_capacity(),
                        "requested message size overflows socket capacity",
                    );

                    return Response::Error(Error::big_packet());
                }

                // Spoof the source address when requested, so reply datagrams from a forwarder
                // appear to originate from the original destination the peer expected. smoltcp
                // honors `local_address` natively when emitting (udp.rs source selection).
                let meta = udp::UdpMetadata {
                    endpoint: endpoint.into(),
                    local_address: local.map(Into::into),
                    ..udp::UdpMetadata::from(endpoint)
                };

                match sock.send_slice(&buf, meta) {
                    Ok(_n) => Response::Ok,
                    // This means that the _current_ buffer is too full, but since we checked if we
                    // had send capacity, it should be available in the future, so just punt and
                    // wouldblock until then.
                    Err(udp::SendError::BufferFull) => Response::WouldBlock {
                        command: UdpCommand::Send {
                            buf,
                            endpoint,
                            local,
                        }
                        .into(),
                        handle: Some(handle),
                    },
                    Err(udp::SendError::Unaddressable) => {
                        tracing::error!(?endpoint, "invalid endpoint");
                        Response::Error(Error::unaddressable())
                    }
                }
            }
            UdpCommand::Recv { max_len } => {
                let sock = get_socket_mut!(self, udp::Socket, handle);

                // The socket's bound port -- the local address of received datagrams uses the
                // captured original destination IP but this socket's port.
                let local_port = sock.endpoint().port;

                match sock.recv() {
                    Ok((b, meta)) => {
                        let mut len = b.len();
                        let mut truncated = None;

                        if let Some(max_len) = max_len {
                            let max_len = max_len.get();

                            if len > max_len {
                                truncated = Some(len);
                                tracing::warn!(len, max_len, "udp read truncated");
                            }

                            len = max_len.min(len);
                        }

                        // smoltcp always sets `local_address` on incoming datagrams to the
                        // original packet destination; this is the forwarder's dial target.
                        let local_addr = meta
                            .local_address
                            .expect("smoltcp sets local_address on every received datagram");

                        UdpResponse::RecvFrom {
                            remote: SocketAddr::new(meta.endpoint.addr.into(), meta.endpoint.port),
                            local: SocketAddr::new(local_addr.into(), local_port),
                            buf: Bytes::copy_from_slice(&b[..len]),
                            truncated,
                        }
                        .into()
                    }
                    Err(udp::RecvError::Exhausted) => Response::WouldBlock {
                        command: UdpCommand::Recv { max_len }.into(),
                        handle,
                    },
                    Err(udp::RecvError::Truncated) => {
                        // this can't occur for recv() as we have a view into the backing
                        // socketbuffer storage. truncated only occurs for recv_slice().
                        unreachable!()
                    }
                }
            }
            UdpCommand::Close => {
                // NOTE(npry): smoltcp supports socket reuse via `socket.close()`, which puts the
                // socket in a valid state to re-bound. We don't support that for API simplicity,
                // but we could in principle if there was a motivating reason.
                //
                // `remove` panics on a stale handle. A `Close` is never re-queued, but a caller
                // could send it twice, so guard the double-close rather than panic the netstack.
                let handle = unwrap_handle!(handle);
                if self.socket_set.iter().any(|(h, _)| h == handle) {
                    self.socket_set.remove(handle);
                }

                Response::Ok
            }
        }
    }

    fn udp_buffer(&self) -> udp::PacketBuffer<'static> {
        udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; self.config.udp_message_count],
            vec![0; self.config.udp_buffer_size],
        )
    }
}
