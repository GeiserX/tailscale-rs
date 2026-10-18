//! Hold exchange/worker deadlines still while lifecycle tests arrange an interleaving.
//!
//! A router reply barrier does not stop the client's exchange timeout. Plain `time::pause`
//! is insufficient too: Tokio may auto-advance while loopback I/O or our detached OS worker
//! is pending. A blocking task inhibits auto-advance (see Tokio's `time::pause` docs). Keep
//! one alive until the test explicitly releases time; `advance` still works for deadline cuts.

use std::time::Duration;

pub(crate) struct FrozenTime(std::sync::mpsc::Sender<()>);

impl FrozenTime {
    pub(crate) fn new() -> Self {
        let (tx, rx) = std::sync::mpsc::channel();
        tokio::task::spawn_blocking(move || {
            let _ = rx.recv();
        });
        tokio::time::pause();
        Self(tx)
    }
}

impl Drop for FrozenTime {
    fn drop(&mut self) {
        tokio::time::resume();
        // Also releases the blocking task on panic; runtime teardown must never wait for us.
        let _ = self.0.send(());
    }
}

/// Exercise a deadline with time frozen, after the future has installed its timers/claims.
pub(crate) async fn finish_at_deadline<F: std::future::Future>(
    future: F,
    budget: Duration,
) -> F::Output {
    use std::{future::poll_fn, task::Poll};
    let mut future = std::pin::pin!(future);
    poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    // Tokio rounds timer-wheel deadlines up to the next millisecond.
    tokio::time::advance(budget + Duration::from_millis(1)).await;
    future.await
}
