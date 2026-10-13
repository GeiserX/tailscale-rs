//! Bounded, ready-only coalescing around Tokio's bidirectional EOF/shutdown state machine.
use std::{
    io,
    pin::Pin,
    sync::OnceLock,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const COALESCE_BYTES: usize = 128 * 1024;

pub(crate) fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var("TS_EXPERIMENT_SPLICE_COALESCE").as_deref() == Ok("1"))
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
        let mut overlay = Io::new(overlay, true, false);
        let mut host = Io::new(host, true, metrics);
        tokio::io::copy_bidirectional_with_sizes(
            &mut overlay,
            &mut host,
            COALESCE_BYTES,
            COALESCE_BYTES,
        )
        .await
    } else if metrics {
        tokio::io::copy_bidirectional(overlay, &mut Io::new(host, false, true)).await
    } else {
        tokio::io::copy_bidirectional(overlay, host).await
    }
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
            for coalesce in [false, true] {
                for host_first in [false, true] {
                    let (peer, mut overlay) = tokio::io::duplex(517);
                    let (mut host, backend) = tokio::io::duplex(1031);
                    let payload: Vec<_> = (0..(2 * COALESCE_BYTES + 37))
                        .map(|i| (i % 251) as u8)
                        .collect();
                    let expected = payload.clone();
                    let splice =
                        tokio::spawn(async move { copy(&mut overlay, &mut host, coalesce).await });
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
