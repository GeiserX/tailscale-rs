use bytes::Bytes;
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
                let handle = handle.unwrap();
                let sock = self.socket_set.get_mut::<tcp::Socket>(handle);

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
                let handle = handle.unwrap();
                let sock = self.socket_set.get_mut::<tcp::Socket>(handle);

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
                let handle = handle.unwrap();

                let sock = self.socket_set.get_mut::<tcp::Socket>(handle);
                sock.close();

                self.pending_tcp_closes.push(handle);

                Response::Ok
            }
            TcpStreamCommand::ShutdownWrite => {
                let handle = handle.unwrap();

                // smoltcp's `close()` is a write-half close: it sends a FIN and moves the socket to
                // `FinWait1`/`CloseWait`, but the receive side stays open until the peer FINs. This
                // is exactly `shutdown(SHUT_WR)`. Crucially we do NOT push to `pending_tcp_closes`
                // here (unlike `Close`): the socket must live on so the caller can keep reading the
                // peer's remaining data. It is reaped later by the consumer's `Close` (on `Drop`) or
                // by the idle/keep-alive timeout once both sides are done.
                let sock = self.socket_set.get_mut::<tcp::Socket>(handle);
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
