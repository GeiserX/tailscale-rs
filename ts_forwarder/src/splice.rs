//! Bounded, ready-only coalescing around Tokio's bidirectional EOF/shutdown state machine.
use std::{
    io,
    pin::Pin,
    sync::OnceLock,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const COALESCE_BYTES: usize = 128 * 1024;

#[derive(Clone, Copy)]
struct CopyPolicy {
    overlay_bytes: usize,
    host_bytes: usize,
    drain: bool,
}
impl CopyPolicy {
    const APPLE: Self = Self {
        overlay_bytes: COALESCE_BYTES,
        host_bytes: COALESCE_BYTES,
        drain: true,
    };
    // Uploads still take one large ready netstack snapshot (including ring wrap). Downloads
    // publish smaller Send commands to the stack/WG owner, returning window/ACK progress
    // sooner on a fast host socket. Neither direction speculatively polls another ready read.
    const LINUX: Self = Self {
        overlay_bytes: COALESCE_BYTES,
        host_bytes: 16 * 1024,
        drain: false,
    };
}

pub(crate) fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        ts_netstack_smoltcp::netcore::experiment::enabled(
            ts_netstack_smoltcp::netcore::experiment::SPLICE_COALESCE,
        )
    })
}

/// No extra storage: reads fill Tokio's bounded copy buffer. A pending overlay command stays
/// owned by the stream (including its read remainder), rather than being cancelled or awaited.
struct Io<T> {
    inner: T,
    drain: bool,
    eof: bool,
    host_metrics: bool,
}
impl<T> Io<T> {
    fn new(inner: T, drain: bool, host_metrics: bool) -> Self {
        Self {
            inner,
            drain,
            eof: false,
            host_metrics,
        }
    }
}
impl<T: AsyncRead + Unpin> AsyncRead for Io<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.eof || buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let start = buf.filled().len();
        loop {
            let before = buf.filled().len();
            match Pin::new(&mut self.inner).poll_read(cx, buf) {
                Poll::Ready(Ok(())) => {
                    if buf.filled().len() == before {
                        self.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    if !self.drain || buf.remaining() == 0 {
                        return Poll::Ready(Ok(()));
                    }
                }
                // Match copy_bidirectional: any I/O error terminates both directions immediately.
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    return if buf.filled().len() > start {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Pending
                    };
                }
            }
        }
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for Io<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if self.host_metrics {
            crate::splice_metrics::record(&result, buf.len());
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub(crate) async fn copy<A, B>(
    overlay: &mut A,
    host: &mut B,
    coalesce: bool,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let metrics = crate::splice_metrics::enabled();
    if coalesce {
        let policy = if cfg!(target_os = "linux") {
            CopyPolicy::LINUX
        } else {
            CopyPolicy::APPLE
        };
        copy_coalesced(overlay, host, policy, metrics).await
    } else if metrics {
        tokio::io::copy_bidirectional(overlay, &mut Io::new(host, false, true)).await
    } else {
        tokio::io::copy_bidirectional(overlay, host).await
    }
}

async fn copy_coalesced<A, B>(
    overlay: &mut A,
    host: &mut B,
    policy: CopyPolicy,
    metrics: bool,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut overlay = Io::new(overlay, policy.drain, false);
    let mut host = Io::new(host, policy.drain, metrics);
    tokio::io::copy_bidirectional_with_sizes(
        &mut overlay,
        &mut host,
        policy.overlay_bytes,
        policy.host_bytes,
    )
    .await
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, task::Waker};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    enum Read {
        Data(Vec<u8>),
        Pending,
        Error,
    }
    struct Script(VecDeque<Read>);
    impl AsyncRead for Script {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.0.pop_front() {
                Some(Read::Data(mut data)) => {
                    let n = data.len().min(buf.remaining());
                    buf.put_slice(&data[..n]);
                    if n < data.len() {
                        self.0.push_front(Read::Data(data.split_off(n)));
                    }
                    Poll::Ready(Ok(()))
                }
                Some(Read::Pending) => Poll::Pending,
                Some(Read::Error) => Poll::Ready(Err(io::ErrorKind::ConnectionReset.into())),
                None => Poll::Ready(Ok(())),
            }
        }
    }
    #[test]
    fn linux_returns_each_ready_snapshot_without_polling_the_next_read() {
        let mut io = Io::new(
            Script(VecDeque::from([
                Read::Data(b"ab".to_vec()),
                Read::Data(b"cd".to_vec()),
                Read::Pending,
                Read::Error,
            ])),
            CopyPolicy::LINUX.drain,
            false,
        );
        let mut cx = Context::from_waker(Waker::noop());
        let mut storage = [0; 16];
        let mut buf = ReadBuf::new(&mut storage);
        for expected in [b"ab", b"cd"] {
            buf.clear();
            assert!(matches!(
                Pin::new(&mut io).poll_read(&mut cx, &mut buf),
                Poll::Ready(Ok(()))
            ));
            assert_eq!(buf.filled(), expected);
        }
        buf.clear();
        assert!(Pin::new(&mut io).poll_read(&mut cx, &mut buf).is_pending());
        assert!(
            matches!(Pin::new(&mut io).poll_read(&mut cx, &mut buf), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::ConnectionReset)
        );
    }

    #[tokio::test]
    async fn linux_bounds_download_commands_and_writes_before_the_next_snapshot() {
        struct Endpoint {
            data: Vec<u8>,
            offset: usize,
            written: Vec<u8>,
            reads: Vec<usize>,
            events: std::sync::Arc<std::sync::Mutex<Vec<char>>>,
            id: char,
        }
        impl AsyncRead for Endpoint {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                self.reads.push(buf.remaining());
                let n = buf.remaining().min(self.data.len() - self.offset);
                if n > 0 {
                    self.events.lock().unwrap().push(self.id);
                    buf.put_slice(&self.data[self.offset..self.offset + n]);
                    self.offset += n;
                }
                Poll::Ready(Ok(()))
            }
        }
        impl AsyncWrite for Endpoint {
            fn poll_write(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                self.events
                    .lock()
                    .unwrap()
                    .push(self.id.to_ascii_uppercase());
                self.written.extend_from_slice(buf);
                Poll::Ready(Ok(buf.len()))
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let endpoint = |id, value| Endpoint {
            data: vec![value; 2 * COALESCE_BYTES + 37],
            offset: 0,
            written: Vec::new(),
            reads: Vec::new(),
            events: events.clone(),
            id,
        };
        let mut overlay = endpoint('o', 3);
        let mut host = endpoint('h', 7);
        let lengths = copy_coalesced(&mut overlay, &mut host, CopyPolicy::LINUX, false)
            .await
            .unwrap();
        assert_eq!(lengths, (overlay.data.len() as u64, host.data.len() as u64));
        assert_eq!(overlay.written, host.data);
        assert_eq!(host.written, overlay.data);
        assert!(overlay.reads.iter().all(|n| *n <= COALESCE_BYTES));
        assert!(host.reads.iter().all(|n| *n <= 16 * 1024));
        assert_eq!(overlay.reads[0], COALESCE_BYTES);
        assert_eq!(host.reads[0], 16 * 1024);
        for pair in events.lock().unwrap().chunks_exact(2) {
            assert!(pair == ['o', 'H'] || pair == ['h', 'O']);
        }
    }
    #[test]
    fn drains_ready_data_but_returns_immediately_on_pending() {
        let mut io = Io::new(
            Script(VecDeque::from([
                Read::Data(b"ab".to_vec()),
                Read::Data(b"cd".to_vec()),
                Read::Pending,
                Read::Data(b"ef".to_vec()),
            ])),
            true,
            false,
        );
        let mut cx = Context::from_waker(Waker::noop());
        let mut storage = [0; 16];
        let mut buf = ReadBuf::new(&mut storage);
        assert!(matches!(
            Pin::new(&mut io).poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(buf.filled(), b"abcd");
        buf.clear();
        assert!(matches!(
            Pin::new(&mut io).poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(buf.filled(), b"ef");
        buf.clear();
        assert!(matches!(
            Pin::new(&mut io).poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert!(buf.filled().is_empty());
    }
    #[test]
    fn bounded_drain_preserves_tail_and_read_errors_are_immediate() {
        let mut io = Io::new(
            Script(VecDeque::from([Read::Data(vec![7; COALESCE_BYTES + 13])])),
            true,
            false,
        );
        let mut cx = Context::from_waker(Waker::noop());
        let mut storage = vec![0; COALESCE_BYTES];
        let mut buf = ReadBuf::new(&mut storage);
        assert!(matches!(
            Pin::new(&mut io).poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(buf.filled().len(), COALESCE_BYTES);
        buf.clear();
        assert!(matches!(
            Pin::new(&mut io).poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(buf.filled(), &[7; 13]);
        let mut io = Io::new(
            Script(VecDeque::from([Read::Data(vec![1]), Read::Error])),
            true,
            false,
        );
        buf.clear();
        assert!(
            matches!(Pin::new(&mut io).poll_read(&mut cx, &mut buf), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::ConnectionReset)
        );
    }
    #[test]
    fn host_metrics_count_actual_short_writes_and_exclude_retries_errors_and_zero() {
        struct Writer(VecDeque<Poll<io::Result<usize>>>);
        impl AsyncWrite for Writer {
            fn poll_write(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
                _: &[u8],
            ) -> Poll<io::Result<usize>> {
                self.0.pop_front().unwrap()
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        let enabled = crate::splice_metrics::enabled();
        let mut io = Io::new(
            Writer(VecDeque::from([
                Poll::Ready(Ok(3)),
                Poll::Pending,
                Poll::Ready(Ok(9)),
                Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
                Poll::Ready(Ok(0)),
            ])),
            false,
            enabled,
        );
        let before = crate::splice_metrics::snapshot();
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..5 {
            drop(Pin::new(&mut io).poll_write(&mut cx, &[0; 9]));
        }
        let after = crate::splice_metrics::snapshot();
        if enabled {
            // Other splice tests can update the process-wide counters concurrently.
            assert!(after.host_write_bytes >= before.host_write_bytes + 12);
            assert!(after.host_write_sizes[0] >= before.host_write_sizes[0] + 2);
            assert!(after.host_write_pending > before.host_write_pending);
            assert!(after.host_write_partial > before.host_write_partial);
        } else {
            assert_eq!(after.host_write_bytes, 0);
            assert_eq!(after.host_write_sizes, [0; 9]);
            assert_eq!(after.host_write_pending, 0);
            assert_eq!(after.host_write_partial, 0);
        }
    }
    /// Tiny duplex capacities force repeated short writes / Pending, and the payload crosses
    /// many copy-buffer boundaries. The response begins only after the first FIN is received.
    #[tokio::test]
    async fn backpressure_and_both_fin_orders_are_lossless() {
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            for policy in [None, Some(CopyPolicy::APPLE), Some(CopyPolicy::LINUX)] {
                for host_first in [false, true] {
                    let (peer, mut overlay) = tokio::io::duplex(517);
                    let (mut host, backend) = tokio::io::duplex(1031);
                    let payload: Vec<_> = (0..(2 * COALESCE_BYTES + 37))
                        .map(|i| (i % 251) as u8)
                        .collect();
                    let expected = payload.clone();
                    let splice = tokio::spawn(async move {
                        if let Some(policy) = policy {
                            copy_coalesced(&mut overlay, &mut host, policy, false).await
                        } else {
                            copy(&mut overlay, &mut host, false).await
                        }
                    });
                    let (mut initiator, mut responder) = if host_first {
                        (backend, peer)
                    } else {
                        (peer, backend)
                    };
                    let sender = tokio::spawn(async move {
                        initiator.write_all(&payload).await.unwrap();
                        initiator.shutdown().await.unwrap();
                        let mut reply = Vec::new();
                        initiator.read_to_end(&mut reply).await.unwrap();
                        assert_eq!(reply, b"reply-after-fin");
                    });
                    let mut received = Vec::new();
                    responder.read_to_end(&mut received).await.unwrap();
                    assert_eq!(received, expected);
                    responder.write_all(b"reply-after-fin").await.unwrap();
                    responder.shutdown().await.unwrap();
                    sender.await.unwrap();
                    let lengths = (expected.len() as u64, 15);
                    assert_eq!(
                        splice.await.unwrap().unwrap(),
                        if host_first {
                            (lengths.1, lengths.0)
                        } else {
                            lengths
                        }
                    );
                }
            }
        })
        .await
        .unwrap();
    }
}
