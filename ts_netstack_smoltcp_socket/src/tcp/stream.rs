use core::{
    fmt::{Debug, Formatter},
    net::SocketAddr,
};

use bytes::Bytes;
use netcore::{DisplayExt, HasChannel, Response, smoltcp::iface::SocketHandle, tcp};

#[cfg(any(feature = "tokio", feature = "futures-io"))]
type PinBoxFut<T> = core::pin::Pin<alloc::boxed::Box<dyn Future<Output = T> + Send + Sync>>;

/// A TCP stream.
pub struct TcpStream {
    sender: netcore::Channel,
    handle: SocketHandle,

    local: SocketAddr,
    remote: SocketAddr,

    #[cfg(any(feature = "tokio", feature = "futures-io"))]
    read_fut: Option<PinBoxFut<Result<Bytes, netcore::Error>>>,
    /// Bytes received from a completed `Recv` that did not fit the caller's buffer on the poll that
    /// produced them, carried to the next `poll_read`. A `Recv` is sized by the buffer length at
    /// future-creation, but the `AsyncRead` contract permits the caller to re-poll with a *smaller*
    /// buffer, so the response can exceed the live buffer — copying it whole would panic
    /// (`copy_from_slice` length mismatch). We copy what fits and stash the tail here (lossless),
    /// draining it before issuing the next `Recv`.
    #[cfg(any(feature = "tokio", feature = "futures-io"))]
    read_remainder: Option<Bytes>,
    #[cfg(any(feature = "tokio", feature = "futures-io"))]
    write_fut: Option<PinBoxFut<Result<usize, netcore::Error>>>,
}

impl TcpStream {
    pub(crate) const fn new(
        sender: netcore::Channel,
        handle: SocketHandle,
        remote: SocketAddr,
        local: SocketAddr,
    ) -> Self {
        Self {
            sender,
            handle,
            remote,
            local,

            #[cfg(any(feature = "tokio", feature = "futures-io"))]
            read_fut: None,

            #[cfg(any(feature = "tokio", feature = "futures-io"))]
            read_remainder: None,

            #[cfg(any(feature = "tokio", feature = "futures-io"))]
            write_fut: None,
        }
    }
}

impl Debug for TcpStream {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TcpStream")
            .field("handle", &self.handle.as_display_debug())
            .field("local_endpoint", &self.local)
            .field("remote_endpoint", &self.remote)
            .finish()
    }
}

impl TcpStream {
    /// Report the local endpoint to which this stream is connected.
    pub const fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Report the remote endpoint to which this stream is connected.
    pub const fn remote_addr(&self) -> SocketAddr {
        self.remote
    }

    /// Half-close the write side: send a FIN to the peer (`shutdown(SHUT_WR)` / `CloseWrite`) while
    /// keeping the read side open so the peer's remaining data can still be received. Fire-and-forget
    /// (non-blocking, like the `Drop`-time `Close`): the FIN is emitted by the netstack in the
    /// background, so this returns immediately and a caller using shutdown for signaling (e.g. a
    /// bidirectional splice half-closing one direction) no longer hangs waiting for a FIN that was
    /// never sent.
    ///
    /// After this, **writes fail** (`InvalidState`): the socket has left the sendable state — this is
    /// the intended `shutdown(SHUT_WR)` POSIX behavior (previously, when this was a no-op, a write
    /// after shutdown still succeeded). Reads continue until the peer's FIN.
    ///
    /// Best-effort delivery: `request_nonblocking` treats a *full* command channel as success and
    /// drops the command, so under channel saturation the FIN may not be sent — the socket then
    /// teardown-degrades to the idle/keep-alive timeout reaper instead of a prompt FIN (never a hard
    /// leak). A channel-*closed* error means the netstack is gone; the socket is already moot.
    pub fn shutdown_write(&self) {
        if let Err(e) = self
            .sender
            .request_nonblocking(Some(self.handle), tcp::stream::Command::ShutdownWrite)
        {
            tracing::debug!(err = %e, "shutdown_write: netstack channel closed");
        }
    }

    /// Send bytes to the remote.
    ///
    /// Blocks until at least one byte can be queued. The return value is the number of
    /// bytes actually sent.
    pub fn send_blocking(&self, b: &[u8]) -> Result<usize, netcore::Error> {
        let resp = self.request_blocking(tcp::stream::Command::Send {
            buf: Bytes::copy_from_slice(b),
        })?;

        self._send(resp)
    }

    /// Send bytes to the remote.
    ///
    /// Blocks until at least one byte can be queued. The return value is the number of
    /// bytes actually sent.
    pub async fn send(&self, b: &[u8]) -> Result<usize, netcore::Error> {
        let resp = self
            .request(tcp::stream::Command::Send {
                buf: Bytes::copy_from_slice(b),
            })
            .await?;

        self._send(resp)
    }

    fn _send(&self, resp: Response) -> Result<usize, netcore::Error> {
        netcore::try_response_as!(resp, tcp::stream::Response::Sent { n });
        Ok(n)
    }

    /// Receive bytes from the remote.
    ///
    /// Returns the number of bytes actually received (blocks until there is at least one).
    pub fn recv_blocking(&self, b: &mut [u8]) -> Result<usize, netcore::Error> {
        let resp = self.request_blocking(tcp::stream::Command::Recv {
            max_len: Some(b.len()),
        })?;

        self._recv(resp, b)
    }

    /// Receive bytes from the remote into the supplied buffer.
    ///
    /// Returns the number of bytes actually received (blocks until there is at least one).
    pub async fn recv(&self, b: &mut [u8]) -> Result<usize, netcore::Error> {
        let resp = self
            .request(tcp::stream::Command::Recv {
                max_len: Some(b.len()),
            })
            .await?;

        self._recv(resp, b)
    }

    /// Receive bytes from the remote.
    ///
    /// Returns the number of bytes actually received (blocks until there is at least one).
    pub fn recv_bytes_blocking(&self) -> Result<Bytes, netcore::Error> {
        let resp = self.request_blocking(tcp::stream::Command::Recv { max_len: None })?;

        self._recv_bytes(resp)
    }

    /// Receive bytes from the remote.
    pub async fn recv_bytes(&self) -> Result<Bytes, netcore::Error> {
        let resp = self
            .request(tcp::stream::Command::Recv { max_len: None })
            .await?;

        self._recv_bytes(resp)
    }

    fn _recv(&self, resp: Response, b: &mut [u8]) -> Result<usize, netcore::Error> {
        let buf = self._recv_bytes(resp)?;

        let n = buf.len().min(b.len());
        b[..n].copy_from_slice(&buf[..n]);

        Ok(n)
    }

    fn _recv_bytes(&self, resp: Response) -> Result<Bytes, netcore::Error> {
        if matches!(resp, Response::TcpStream(tcp::stream::Response::Finished)) {
            return Ok(Bytes::new());
        }

        netcore::try_response_as!(resp, tcp::stream::Response::Recv { buf });
        Ok(buf)
    }

    #[cfg(any(feature = "tokio", feature = "futures-io"))]
    fn poll_read(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context,
        buf: &mut [u8],
    ) -> core::task::Poll<std::io::Result<usize>> {
        use netcore::HasChannel;

        // Callers must pass a non-empty buffer: an `Ok(0)` return is `AsyncRead`'s EOF signal, so
        // returning it while `read_remainder` still holds bytes (which a zero-length `buf` would
        // force) would silently truncate the stream. Every in-tree caller passes a non-empty buffer;
        // this guards the invariant for the public type so a zero-length read can't be mistaken for
        // EOF-with-data-pending. `tokio`/`futures-io` themselves never poll a read with an empty buf.
        debug_assert!(
            !buf.is_empty() || self.read_remainder.is_none(),
            "poll_read called with an empty buffer while bytes are buffered — Ok(0) would look like EOF"
        );

        // Copy up to `buf.len()` bytes out of `data` into `buf`, returning `(written, remainder)`
        // where `remainder` is the unwritten tail (empty if it all fit). `Bytes::split_to` is a
        // cheap refcount split, so carrying a remainder is allocation-free. Free fn (not a
        // self-capturing closure) so it doesn't conflict with the `&mut self.read_fut` borrow below.
        fn copy_into_buf(mut data: Bytes, buf: &mut [u8]) -> (usize, Bytes) {
            let n = data.len().min(buf.len());
            buf[..n].copy_from_slice(&data.split_to(n));
            (n, data)
        }

        // Drain any stashed remainder first — never issue a fresh `Recv` while bytes are buffered.
        if let Some(rem) = self.read_remainder.take() {
            let (n, tail) = copy_into_buf(rem, buf);
            if !tail.is_empty() {
                self.read_remainder = Some(tail);
            }
            return core::task::Poll::Ready(Ok(n));
        }

        let handle = self.handle;
        let cap = buf.len();

        loop {
            match self.read_fut.as_mut() {
                None => {
                    let sender = self.sender.clone();

                    let _ret = self.read_fut.insert(alloc::boxed::Box::pin(async move {
                        let resp = sender
                            .request(
                                Some(handle),
                                tcp::stream::Command::Recv { max_len: Some(cap) },
                            )
                            .await?;

                        // A reaped socket (tsr-9ue: the netstack autonomously closed + freed an
                        // idle/dead accepted stream) answers a first-touch `Recv` with
                        // `missing_socket`. Surface it as a clean end-of-stream — an empty `Bytes`,
                        // exactly like `Finished` — so it reads as a normal `Ok(0)` EOF rather than
                        // a confusing generic internal `io::Error`.
                        if matches!(
                            resp,
                            netcore::Response::Error(netcore::Error::Internal(
                                netcore::InternalErrorKind::BadSocketHandle
                            ))
                        ) {
                            return Ok(Bytes::new());
                        }

                        match resp.try_into()? {
                            tcp::stream::Response::Recv { buf } => Ok(buf),
                            tcp::stream::Response::Finished => Ok(Bytes::new()),
                            _ => Err(netcore::Error::wrong_type()),
                        }
                    }));
                }

                Some(x) => {
                    let poll_result = x.as_mut().poll(cx);
                    let ret = core::task::ready!(poll_result)?;

                    self.read_fut.take();

                    // Copy what fits into the CURRENT buffer (which the caller may have shrunk since
                    // the `Recv` was issued at `cap`); stash any tail. A whole-`ret` copy would panic
                    // when `ret.len() > buf.len()`.
                    let (n, tail) = copy_into_buf(ret, buf);
                    if !tail.is_empty() {
                        self.read_remainder = Some(tail);
                    }

                    break core::task::Poll::Ready(Ok(n));
                }
            }
        }
    }

    #[cfg(any(feature = "tokio", feature = "futures-io"))]
    fn poll_write(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        buf: &[u8],
    ) -> core::task::Poll<std::io::Result<usize>> {
        use netcore::HasChannel;

        let handle = self.handle;

        loop {
            match &mut self.write_fut {
                None => {
                    let b = Bytes::copy_from_slice(buf);
                    let sender = self.sender.clone();

                    let _ret = self.write_fut.insert(alloc::boxed::Box::pin(async move {
                        let resp = sender
                            .request(Some(handle), tcp::stream::Command::Send { buf: b })
                            .await?;

                        // A reaped socket (tsr-9ue) answers a first-touch `Send` with
                        // `missing_socket`. Writing to a torn-down connection is POSIX
                        // `ECONNRESET`, so remap to `ConnectionReset` — `From<Error> for
                        // io::Error` then yields `ErrorKind::ConnectionReset` — instead of letting
                        // it fall through `try_response_as!` as a generic internal error.
                        if matches!(
                            resp,
                            netcore::Response::Error(netcore::Error::Internal(
                                netcore::InternalErrorKind::BadSocketHandle
                            ))
                        ) {
                            return Err(netcore::Error::ConnectionReset);
                        }

                        netcore::try_response_as!(resp, tcp::stream::Response::Sent { n });
                        Ok(n)
                    }));
                }

                Some(x) => {
                    let poll_result = x.as_mut().poll(cx);
                    let ret = core::task::ready!(poll_result)?;

                    self.write_fut.take();

                    break core::task::Poll::Ready(Ok(ret));
                }
            }
        }
    }

    socket_requestor_impl!();
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        if let Err(e) = self
            .sender
            .request_nonblocking(Some(self.handle), tcp::stream::Command::Close)
        {
            tracing::warn!(err = %e, "possible socket leak");
        }
    }
}

#[cfg(feature = "std")]
impl std::io::Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.recv_blocking(buf).map_err(netcore::Error::into)
    }
}

#[cfg(feature = "std")]
impl std::io::Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.send_blocking(buf).map_err(netcore::Error::into)
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        let mut buf = Bytes::copy_from_slice(buf);

        while !buf.is_empty() {
            let resp = self.request_blocking(tcp::stream::Command::Send { buf: buf.clone() })?;
            netcore::try_response_as!(resp, tcp::stream::Response::Sent { n });

            let _consumed = buf.split_to(n);
        }

        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(feature = "tokio")]
impl tokio::io::AsyncRead for TcpStream {
    fn poll_read(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> core::task::Poll<tokio::io::Result<()>> {
        let n = core::task::ready!(self.poll_read(cx, buf.initialize_unfilled()))?;
        buf.advance(n);

        core::task::Poll::Ready(Ok(()))
    }
}

#[cfg(feature = "tokio")]
impl tokio::io::AsyncWrite for TcpStream {
    fn poll_write(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        buf: &[u8],
    ) -> core::task::Poll<std::io::Result<usize>> {
        self.poll_write(cx, buf)
    }

    fn poll_flush(
        self: core::pin::Pin<&mut Self>,
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<std::io::Result<()>> {
        core::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: core::pin::Pin<&mut Self>,
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<std::io::Result<()>> {
        self.shutdown_write();
        core::task::Poll::Ready(Ok(()))
    }
}

#[cfg(feature = "tokio")]
#[cfg(test)]
mod reaped_socket_mapping_tests {
    use core::net::SocketAddr;

    use netcore::{HasChannel, Netstack, smoltcp::iface::SocketHandle, udp};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::TcpStream;

    /// Spawn a real netstack on a background thread that continuously processes commands, and return
    /// a `TcpStream` wired to a freed `SocketHandle`. The handle comes from a UDP bind that is then
    /// closed, so its slot is empty: every TCP command the stream issues for it hits
    /// `get_socket_mut!`'s existence check (which fails) and is answered `missing_socket` — exactly
    /// the post-reap (tsr-9ue) state seen from the consumer's side. The driver thread answers the
    /// stream's async `Recv`/`Send` so the awaited future actually resolves.
    fn stream_over_reaped_handle() -> TcpStream {
        let mut stack = Netstack::new(
            netcore::Config::default(),
            netcore::smoltcp::time::Instant::ZERO,
        );
        let chan = stack.command_channel();

        // Drive the stack from a background thread so EVERY command (the setup bind/close AND the
        // stream's later async `Recv`/`Send`) is answered. `request_blocking` below blocks on its
        // response, so the driver must already be running or it would deadlock.
        std::thread::spawn(move || {
            while let Ok(cmd) = stack.wait_for_cmd_blocking(None) {
                stack.process_one_cmd(cmd);
            }
        });

        // A real handle value from a UDP bind (answered by the driver thread)...
        let handle: SocketHandle = match chan
            .request_blocking(
                None,
                udp::Command::Bind {
                    endpoint: SocketAddr::from(([127, 0, 0, 1], 9200)),
                },
            )
            .expect("channel open")
        {
            netcore::Response::Udp(udp::Response::Bound { handle, .. }) => handle,
            other => panic!("expected Bound, got {other:?}"),
        };
        // ...then close it so the slot is freed: the handle now refers to nothing — the reaped state
        // a first-touch TCP command then sees as `missing_socket`.
        assert!(matches!(
            chan.request_blocking(Some(handle), udp::Command::Close)
                .expect("channel open"),
            netcore::Response::Ok
        ));

        let local = SocketAddr::from(([127, 0, 0, 1], 50100));
        let remote = SocketAddr::from(([127, 0, 0, 1], 9200));
        TcpStream::new(chan, handle, remote, local)
    }

    /// Part 3: a reaped socket's `Recv` resolves to `missing_socket`, which `poll_read` maps to a
    /// clean end-of-stream — `Ok(0)` — not a generic internal `io::Error`.
    #[tokio::test]
    async fn poll_read_on_reaped_socket_is_eof() {
        let mut stream = stream_over_reaped_handle();
        let mut buf = [0u8; 64];
        let n = stream
            .read(&mut buf)
            .await
            .expect("read on a reaped socket must be Ok(0), not an error");
        assert_eq!(n, 0, "a reaped socket must read as EOF (Ok(0))");
    }

    /// Part 3: a reaped socket's `Send` resolves to `missing_socket`, which `poll_write` maps to
    /// `ErrorKind::ConnectionReset` (POSIX `ECONNRESET` for writing to a torn-down connection).
    #[tokio::test]
    async fn poll_write_on_reaped_socket_is_connection_reset() {
        let mut stream = stream_over_reaped_handle();
        let err = stream
            .write(b"payload")
            .await
            .expect_err("write to a reaped socket must error");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::ConnectionReset,
            "writing to a reaped socket must surface as ConnectionReset"
        );
    }
}

#[cfg(feature = "futures-io")]
impl futures_io::AsyncRead for TcpStream {
    fn poll_read(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        buf: &mut [u8],
    ) -> core::task::Poll<std::io::Result<usize>> {
        self.poll_read(cx, buf)
    }
}

#[cfg(feature = "futures-io")]
impl futures_io::AsyncWrite for TcpStream {
    fn poll_write(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        buf: &[u8],
    ) -> core::task::Poll<std::io::Result<usize>> {
        self.poll_write(cx, buf)
    }

    fn poll_flush(
        self: core::pin::Pin<&mut Self>,
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<std::io::Result<()>> {
        core::task::Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: core::pin::Pin<&mut Self>,
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<std::io::Result<()>> {
        self.shutdown_write();
        core::task::Poll::Ready(Ok(()))
    }
}
