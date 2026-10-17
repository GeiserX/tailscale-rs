//! Bounded OS work, independent of Tokio's worker and runtime-shutdown threads.
//!
//! A cancelled waiter leaves its permit with the OS operation until it ends. Thus repeated
//! cancellation cannot grow the number of blocked threads. Threads are detached so a stuck
//! syscall cannot hold up dropping a Tokio runtime; results still require a generation check.
//! Waiters give up after one second, including time waiting for a worker slot.

use tokio::sync::{Semaphore, oneshot};

static SLOTS: Semaphore = Semaphore::const_new(4);

pub(crate) async fn run<R: Send + 'static>(f: impl FnOnce() -> R + Send + 'static) -> Option<R> {
    run_on(&SLOTS, f).await
}

async fn run_on<R: Send + 'static>(
    slots: &'static Semaphore,
    f: impl FnOnce() -> R + Send + 'static,
) -> Option<R> {
    tokio::time::timeout(std::time::Duration::from_secs(1), async move {
        let permit = slots.acquire().await.ok()?;
        let (tx, rx) = oneshot::channel();
        std::thread::Builder::new()
            .name("portmapper-os".to_owned())
            .spawn(move || {
                let _permit = permit;
                drop(tx.send(f()));
            })
            .ok()?;
        rx.await.ok()
    })
    .await
    .ok()
    .flatten()
}

#[cfg(test)]
mod tests {
    use crate::test_time::{FrozenTime, finish_at_deadline};
    use std::{
        sync::Arc,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    #[tokio::test]
    async fn os_wait_is_bounded_when_worker_keeps_running() {
        // A private pool and an explicit gate avoid a sleeping detached worker consuming a
        // production-pool slot after this test has returned.
        static SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
        let _frozen = FrozenTime::new();
        let (entered, received) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let job = tokio::spawn(super::run_on(&SLOTS, move || {
            let _ = entered.send(());
            let _ = wait.recv();
            42
        }));
        received.await.unwrap();
        assert_eq!(SLOTS.available_permits(), 0);
        tokio::time::advance(Duration::from_millis(1001)).await;
        assert_eq!(
            job.await.unwrap(),
            None,
            "a slow OS call must not hold its async waiter indefinitely"
        );
        assert_eq!(
            SLOTS.available_permits(),
            0,
            "timed-out OS work keeps its slot"
        );
        drop(release); // also unblocks the worker if an assertion unwinds
        while SLOTS.available_permits() != 1 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn cancelled_workers_keep_slots_and_recover() {
        static SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);
        let _frozen = FrozenTime::new();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut releases = Vec::new();
        let mut jobs = Vec::new();
        for _ in 0..4 {
            let tx = tx.clone();
            let (release, wait) = std::sync::mpsc::channel::<()>();
            releases.push(release);
            jobs.push(tokio::spawn(super::run_on(&SLOTS, move || {
                tx.send(()).unwrap();
                let _ = wait.recv();
            })));
        }
        for _ in 0..4 {
            rx.recv().await.unwrap();
        }
        for job in &jobs {
            job.abort();
        }
        for job in jobs {
            drop(job.await);
        }
        let fifth_started = Arc::new(AtomicUsize::new(0));
        let count = fifth_started.clone();
        let blocked = finish_at_deadline(
            super::run_on(&SLOTS, move || count.fetch_add(1, Ordering::SeqCst)),
            Duration::from_secs(1),
        )
        .await;
        assert!(blocked.is_none());
        assert_eq!(
            fifth_started.load(Ordering::SeqCst),
            0,
            "aborted waiters must not release running OS slots"
        );
        drop(releases);
        // Observe permit return itself, rather than a flag set just before its destructor.
        while SLOTS.available_permits() != 4 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            super::run_on(&SLOTS, || 42).await,
            Some(42),
            "completion must return slots without a lost wakeup"
        );
    }
}
