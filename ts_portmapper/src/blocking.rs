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
    #[tokio::test]
    async fn os_wait_is_bounded_when_worker_keeps_running() {
        let result = super::run(|| {
            std::thread::sleep(std::time::Duration::from_millis(1500));
            42
        })
        .await;
        assert_eq!(
            result, None,
            "a slow OS call must not hold its async waiter indefinitely"
        );
    }
}

#[cfg(test)]
mod worker_tests {
    static TEST_SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);

    #[tokio::test]
    async fn cancelled_workers_keep_slots_and_recover() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Condvar, Mutex};
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let finished = Arc::new(AtomicUsize::new(0));
        let mut jobs = Vec::new();
        for _ in 0..4 {
            let gate = gate.clone();
            let tx = tx.clone();
            let finished = finished.clone();
            jobs.push(tokio::spawn(super::run_on(&TEST_SLOTS, move || {
                tx.send(()).unwrap();
                let ready = gate.0.lock().unwrap();
                drop(gate.1.wait_while(ready, |open| !*open).unwrap());
                finished.fetch_add(1, Ordering::SeqCst);
            })));
        }
        for _ in 0..4 {
            tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
                .await
                .unwrap()
                .unwrap();
        }
        for job in &jobs {
            job.abort();
        }
        for job in jobs {
            drop(job.await);
        }
        let fifth_started = Arc::new(AtomicUsize::new(0));
        let count = fifth_started.clone();
        let blocked =
            super::run_on(&TEST_SLOTS, move || count.fetch_add(1, Ordering::SeqCst)).await;
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        assert!(blocked.is_none());
        assert_eq!(
            fifth_started.load(Ordering::SeqCst),
            0,
            "aborted waiters must not release running OS slots"
        );
        while finished.load(Ordering::SeqCst) != 4 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            super::run_on(&TEST_SLOTS, || 42).await,
            Some(42),
            "completion must return slots without a lost wakeup"
        );
    }
}
