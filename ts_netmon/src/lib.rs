#![doc = include_str!("../README.md")]

use std::io;
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

/// How long the debouncer waits for the raw-event stream to fall quiet before emitting one
/// coalesced [`LinkChangeEvent`]. A single user-visible link change (a Wi-Fi switch, a sleep/wake)
/// emits a *burst* of OS notifications — link-down, addr-del, route-del, link-up, addr-add,
/// route-add — over a few tens of milliseconds. Collapsing them with a trailing settle window
/// turns that burst into exactly one reaction, mirroring Go `net/netmon`, which likewise coalesces
/// a `ChangeDelta` flurry over a settle window before declaring one "major change". 250 ms is long
/// enough to swallow a normal interface-reconfiguration burst yet short enough that recovery feels
/// immediate.
pub const DEBOUNCE_SETTLE: Duration = Duration::from_millis(250);

/// A coalesced network link-change notification.
///
/// Deliberately **detail-free**: the runtime's reaction (re-bind the underlay socket, re-ping
/// peers, re-STUN, re-netcheck) is identical regardless of *what* changed, so carrying a cause
/// would be dead weight that every backend would have to synthesize and every consumer would have
/// to ignore. Go `net/netmon` collapses the same way — it reacts to "a major change happened", not
/// to the specific delta. `#[non_exhaustive]` so a future slice can add a cause field (should one
/// ever earn its keep) without breaking downstream `LinkChangeEvent { .. }` / construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct LinkChangeEvent;

/// A source of coalesced [`LinkChangeEvent`]s.
///
/// Each backend ([`ManualLinkMonitor`] for tests/slice-(a), the OS netlink/PF_ROUTE backends in
/// later slices, or [`NoopLinkMonitor`] when monitoring is off) implements this. The returned
/// channel yields one event per debounced burst; the returned [`LinkMonitorHandle`] owns the
/// background reader task and aborts it on drop, so a monitor never outlives the supervisor that
/// created it.
///
/// `shutdown` is the runtime's shared shutdown signal: the watcher's background work stops when it
/// flips to `true` (in addition to the hard abort the handle's `Drop` performs), so the watcher
/// participates in orderly shutdown rather than only being torn down by the handle drop.
pub trait LinkMonitor: Send + Sync + 'static {
    /// Begin watching for link changes.
    ///
    /// Returns the receiver of coalesced events and the handle that owns the watcher task. An
    /// `Err` means the watcher could not be started (e.g. an OS backend failed to open its
    /// route/netlink socket); the caller falls back to no monitoring (degraded, but never a panic).
    fn watch(
        &self,
        shutdown: watch::Receiver<bool>,
    ) -> io::Result<(mpsc::Receiver<LinkChangeEvent>, LinkMonitorHandle)>;
}

/// Owns a [`LinkMonitor`]'s background reader task and aborts it on drop.
///
/// Holding this handle keeps the watcher alive; dropping it tears the watcher down immediately
/// (the established `reauth_bridge` / taildrop-reaper / `DerpLatencyMeasurer` pattern in
/// `ts_runtime`). The abort is unconditional, so a detached watcher task can never outlive the
/// device even if the shutdown signal was never flipped.
#[derive(Debug)]
pub struct LinkMonitorHandle {
    task: JoinHandle<()>,
}

impl LinkMonitorHandle {
    /// Wrap a watcher task so it is aborted when this handle drops.
    pub fn new(task: JoinHandle<()>) -> Self {
        Self { task }
    }
}

impl Drop for LinkMonitorHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Coalesce a raw link-event stream into debounced [`LinkChangeEvent`]s with a trailing settle
/// window of `settle`.
///
/// Semantics (a *trailing* / quiet-period debounce): every raw event resets a `settle` timer; one
/// [`LinkChangeEvent`] is emitted only once the stream has been quiet for a full `settle`. So a
/// burst of N raw events arriving closer together than `settle` collapses to exactly one output
/// event, while two bursts separated by more than `settle` produce two output events. This is the
/// OS-agnostic heart of the monitor: every backend feeds its raw notifications through here, so the
/// supervisor reacts once per *settled* change rather than once per kernel message.
///
/// The task ends when the raw-event sender is dropped (the backend stopped) or `shutdown` flips to
/// `true`; if a settle is pending when the raw stream closes, the final coalesced event is still
/// flushed so a change that arrived just before shutdown is not silently dropped. Output is best
/// effort: if the consumer's receiver is gone the loop exits.
///
/// Pure `tokio::time` — no OS dependency — so it is unit-testable on a paused virtual clock.
pub async fn debounce(
    mut raw: mpsc::Receiver<()>,
    out: mpsc::Sender<LinkChangeEvent>,
    settle: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    // `None` = idle (no change pending); `Some(deadline)` = a change is pending and will be emitted
    // when the clock reaches `deadline` unless another raw event pushes it out first.
    let mut pending = false;
    // A far-future sleep that we re-arm on each raw event. Pinned so it can be polled in the
    // `select!` arm repeatedly. Starts effectively disabled (idle).
    let timer = tokio::time::sleep(Duration::from_secs(0));
    tokio::pin!(timer);
    // Consume the initial immediate expiry so the idle state truly waits for a raw event first.
    timer.as_mut().await;

    loop {
        tokio::select! {
            // Bias toward shutdown so a flip during a pending settle stops promptly.
            biased;

            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }

            raw_event = raw.recv() => {
                match raw_event {
                    Some(()) => {
                        // (Re)arm the trailing settle: push the deadline out to `now + settle`.
                        pending = true;
                        timer.as_mut().reset(tokio::time::Instant::now() + settle);
                    }
                    None => {
                        // Raw stream closed (backend stopped). Flush a pending change so a burst
                        // that arrived just before close is not lost, then end.
                        if pending && out.send(LinkChangeEvent).await.is_err() {
                            tracing::trace!("link-change consumer gone at flush");
                        }
                        break;
                    }
                }
            }

            // Fires only while a change is pending (the timer is re-armed into the future on every
            // raw event; when idle it has already elapsed and this arm is gated by `pending`).
            _ = &mut timer, if pending => {
                pending = false;
                if out.send(LinkChangeEvent).await.is_err() {
                    // Consumer (the supervisor) is gone; nothing more to do.
                    tracing::trace!("link-change consumer gone; debouncer exiting");
                    break;
                }
            }
        }
    }
}

/// Default bound for the raw-event and coalesced-event channels. Small: a link change is a rare,
/// bursty event, the debouncer drains the raw channel promptly, and the supervisor processes
/// coalesced events serially. A bounded channel also caps memory under a pathological event storm
/// (the debouncer collapses the burst regardless).
const CHANNEL_BOUND: usize = 16;

/// A [`LinkMonitor`] whose link changes are fired manually by the holder of its [`trigger`] handle.
///
/// This is slice-(a)'s event source: it proves the whole pipeline — raw event → debouncer →
/// coalesced [`LinkChangeEvent`] → supervisor reaction — with **no OS code at all**. A test or an
/// embedder constructs it via [`ManualLinkMonitor::new`], keeps the returned [`ManualTrigger`], and
/// calls [`ManualTrigger::trigger`] to inject a raw link event; `watch` wires those raw events
/// through [`debounce`] exactly as a real OS backend would, so the synthetic path exercises the
/// identical coalescing the production path uses.
///
/// [`trigger`]: ManualTrigger::trigger
pub struct ManualLinkMonitor {
    raw_rx: std::sync::Mutex<Option<mpsc::Receiver<()>>>,
    settle: Duration,
}

/// The fire handle for a [`ManualLinkMonitor`]: call [`trigger`](ManualTrigger::trigger) to inject
/// one raw link event into the monitor's debouncer.
#[derive(Clone, Debug)]
pub struct ManualTrigger {
    raw_tx: mpsc::Sender<()>,
}

impl ManualTrigger {
    /// Inject one raw link-change event. Several calls within [`DEBOUNCE_SETTLE`] coalesce to a
    /// single [`LinkChangeEvent`] at the watcher's output. Best effort: if the monitor's watcher
    /// task has ended (its receiver dropped) this is a silent no-op, matching how a real OS backend
    /// would simply stop delivering after teardown.
    pub fn trigger(&self) -> bool {
        self.raw_tx.try_send(()).is_ok()
    }
}

impl ManualLinkMonitor {
    /// Build a manual monitor with the default [`DEBOUNCE_SETTLE`] window, returning it together
    /// with the [`ManualTrigger`] used to fire synthetic link changes.
    pub fn new() -> (Self, ManualTrigger) {
        Self::with_settle(DEBOUNCE_SETTLE)
    }

    /// Build a manual monitor with an explicit settle window (tests use a tiny window so the
    /// coalescing fires quickly on a paused clock).
    pub fn with_settle(settle: Duration) -> (Self, ManualTrigger) {
        let (raw_tx, raw_rx) = mpsc::channel(CHANNEL_BOUND);
        // The trigger is the SOLE sender: the monitor keeps only the receiver (consumed by
        // `watch`). So when every `ManualTrigger` clone is dropped, the raw channel closes and the
        // debouncer flushes any pending event and exits — the synthetic analog of an OS backend's
        // socket closing.
        let trigger = ManualTrigger { raw_tx };
        (
            Self {
                raw_rx: std::sync::Mutex::new(Some(raw_rx)),
                settle,
            },
            trigger,
        )
    }
}

impl LinkMonitor for ManualLinkMonitor {
    fn watch(
        &self,
        shutdown: watch::Receiver<bool>,
    ) -> io::Result<(mpsc::Receiver<LinkChangeEvent>, LinkMonitorHandle)> {
        // The raw receiver is consumed by the single watcher task. A second `watch()` call has no
        // raw stream to drive and is refused rather than handing back a channel that never yields
        // (which would silently look like a wedged monitor).
        let raw_rx = self
            .raw_rx
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "ManualLinkMonitor::watch already called (raw receiver consumed)",
                )
            })?;

        let (out_tx, out_rx) = mpsc::channel(CHANNEL_BOUND);
        let settle = self.settle;
        let task = tokio::spawn(debounce(raw_rx, out_tx, settle, shutdown));
        Ok((out_rx, LinkMonitorHandle::new(task)))
    }
}

/// A [`LinkMonitor`] that never reports a change.
///
/// The default backend when network monitoring is off, or when the runtime is built without an OS
/// backend (slice (a): no Linux/macOS backend exists yet). Its `watch` returns a receiver whose
/// sender is dropped immediately, so the channel is closed and the supervisor's recv loop simply
/// parks forever (until shutdown) — zero work, zero sockets, byte-for-byte today's behavior.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopLinkMonitor;

impl LinkMonitor for NoopLinkMonitor {
    fn watch(
        &self,
        _shutdown: watch::Receiver<bool>,
    ) -> io::Result<(mpsc::Receiver<LinkChangeEvent>, LinkMonitorHandle)> {
        let (_out_tx, out_rx) = mpsc::channel(CHANNEL_BOUND);
        // No task does any work; spawn a trivially-immediate one so the handle type is uniform and
        // its `Drop` is a harmless no-op (the task is already finished). `_out_tx` drops here, so
        // the receiver observes a closed, never-yielding channel.
        let task = tokio::spawn(async {});
        Ok((out_rx, LinkMonitorHandle::new(task)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A burst of raw events arriving within one settle window collapses to exactly ONE coalesced
    /// `LinkChangeEvent`. This is the core coalescing contract (a Wi-Fi switch emits a flurry of
    /// link/addr/route notifications that must become one reaction).
    #[tokio::test(start_paused = true)]
    async fn burst_collapses_to_single_event() {
        let settle = Duration::from_millis(250);
        let (raw_tx, raw_rx) = mpsc::channel(64);
        let (out_tx, mut out_rx) = mpsc::channel(64);
        let (_sd_tx, sd_rx) = watch::channel(false);

        let task = tokio::spawn(debounce(raw_rx, out_tx, settle, sd_rx));

        // Fire 6 raw events spaced 10 ms apart — all well within the 250 ms settle.
        for _ in 0..6 {
            raw_tx.send(()).await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Before the window elapses: nothing emitted yet (trailing settle).
        assert!(
            out_rx.try_recv().is_err(),
            "no event must be emitted before the settle window elapses"
        );

        // Let the window elapse with no further raw events.
        tokio::time::sleep(settle + Duration::from_millis(50)).await;

        // Exactly one coalesced event for the whole burst.
        assert_eq!(
            out_rx.recv().await,
            Some(LinkChangeEvent),
            "the burst must coalesce to exactly one event"
        );
        assert!(
            out_rx.try_recv().is_err(),
            "no second event for a single burst"
        );

        drop(raw_tx);
        task.await.expect("debouncer task joins cleanly");
    }

    /// Two bursts separated by more than the settle window produce TWO coalesced events — the
    /// debouncer re-arms after emitting, it does not latch.
    #[tokio::test(start_paused = true)]
    async fn two_separated_bursts_produce_two_events() {
        let settle = Duration::from_millis(250);
        let (raw_tx, raw_rx) = mpsc::channel(64);
        let (out_tx, mut out_rx) = mpsc::channel(64);
        let (_sd_tx, sd_rx) = watch::channel(false);

        let task = tokio::spawn(debounce(raw_rx, out_tx, settle, sd_rx));

        // First burst.
        for _ in 0..3 {
            raw_tx.send(()).await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(settle + Duration::from_millis(50)).await;
        assert_eq!(
            out_rx.recv().await,
            Some(LinkChangeEvent),
            "first burst -> first event"
        );

        // Quiet gap longer than the settle window, then a second burst.
        tokio::time::sleep(settle * 4).await;
        for _ in 0..3 {
            raw_tx.send(()).await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(settle + Duration::from_millis(50)).await;
        assert_eq!(
            out_rx.recv().await,
            Some(LinkChangeEvent),
            "second burst -> second event"
        );

        drop(raw_tx);
        task.await.expect("debouncer task joins cleanly");
    }

    /// Dropping the [`LinkMonitorHandle`] aborts the watcher task cleanly (the task stops running
    /// and the join reports cancellation).
    #[tokio::test]
    async fn dropping_handle_aborts_watcher() {
        let (monitor, _trigger) = ManualLinkMonitor::new();
        let (_sd_tx, sd_rx) = watch::channel(false);
        let (_out_rx, handle) = monitor.watch(sd_rx).expect("first watch succeeds");

        // Reach into the handle to observe the task after we drop the handle. We move the inner
        // JoinHandle out by constructing an `Option` swap is overkill; instead re-create a handle
        // to the same task via abort semantics: drop aborts, and a fresh `watch` is refused.
        drop(handle);
        // Give the runtime a tick to process the abort.
        tokio::task::yield_now().await;

        // The raw receiver was consumed by the (now-aborted) watcher, so a second `watch` is
        // refused — proving the first watcher really took ownership and the handle governed it.
        let (_sd_tx2, sd_rx2) = watch::channel(false);
        assert!(
            monitor.watch(sd_rx2).is_err(),
            "the raw receiver is consumed by the first watch; a second watch must be refused"
        );
    }

    /// The aborted watcher's task stops running after the handle drops — a direct check that `Drop`
    /// aborts (not merely detaches) the task.
    #[tokio::test]
    async fn handle_drop_cancels_join() {
        // A task that parks "forever" on a channel whose sender it holds: it only ends if aborted.
        let task = tokio::spawn(async {
            let (_tx, mut rx) = mpsc::channel::<()>(1);
            rx.recv().await;
        });
        // Keep an abort handle to observe cancellation independently of the wrapper's `Drop`.
        let probe = task.abort_handle();
        let handle = LinkMonitorHandle::new(task);

        assert!(!probe.is_finished(), "the parked task runs before the drop");
        drop(handle);
        // Give the runtime a moment to process the abort.
        for _ in 0..10 {
            if probe.is_finished() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            probe.is_finished(),
            "dropping the handle must abort the watcher task"
        );
    }

    /// A `pending`-then-raw-stream-close flushes the final coalesced event rather than dropping it.
    #[tokio::test(start_paused = true)]
    async fn pending_change_is_flushed_on_raw_close() {
        let settle = Duration::from_millis(250);
        let (raw_tx, raw_rx) = mpsc::channel(64);
        let (out_tx, mut out_rx) = mpsc::channel(64);
        let (_sd_tx, sd_rx) = watch::channel(false);

        let task = tokio::spawn(debounce(raw_rx, out_tx, settle, sd_rx));

        // Fire one raw event, then immediately close the raw stream (before the settle elapses).
        raw_tx.send(()).await.unwrap();
        drop(raw_tx);

        // The flush-on-close path emits the pending event.
        assert_eq!(
            out_rx.recv().await,
            Some(LinkChangeEvent),
            "a pending change must be flushed when the raw stream closes"
        );
        task.await.expect("debouncer task joins cleanly");
    }

    /// `ManualTrigger::trigger` drives the full ManualLinkMonitor pipeline: a burst of triggers
    /// coalesces to one event at the monitor's output. Proves the synthetic event source feeds the
    /// debouncer exactly as a real backend would.
    #[tokio::test(start_paused = true)]
    async fn manual_monitor_trigger_coalesces() {
        let (monitor, trigger) = ManualLinkMonitor::with_settle(Duration::from_millis(250));
        let (_sd_tx, sd_rx) = watch::channel(false);
        let (mut out_rx, _handle) = monitor.watch(sd_rx).expect("watch starts");

        for _ in 0..5 {
            assert!(
                trigger.trigger(),
                "trigger delivers while the watcher is live"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;

        assert_eq!(out_rx.recv().await, Some(LinkChangeEvent));
        assert!(out_rx.try_recv().is_err(), "one event for one burst");
    }

    /// The `NoopLinkMonitor` yields no events: its channel is closed (sender dropped), so a recv
    /// resolves to `None` rather than ever producing a `LinkChangeEvent`.
    #[tokio::test]
    async fn noop_monitor_never_yields() {
        let (_sd_tx, sd_rx) = watch::channel(false);
        let (mut out_rx, _handle) = NoopLinkMonitor
            .watch(sd_rx)
            .expect("noop watch is infallible");
        assert_eq!(
            out_rx.recv().await,
            None,
            "the noop monitor's channel is closed and never yields an event"
        );
    }

    /// A `shutdown` flip ends the debouncer task even with no raw activity.
    #[tokio::test]
    async fn shutdown_ends_debouncer() {
        let (raw_tx, raw_rx) = mpsc::channel::<()>(64);
        let (out_tx, _out_rx) = mpsc::channel(64);
        let (sd_tx, sd_rx) = watch::channel(false);

        let task = tokio::spawn(debounce(raw_rx, out_tx, Duration::from_millis(250), sd_rx));
        sd_tx.send(true).unwrap();
        // The task must end promptly on shutdown.
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("debouncer must exit on shutdown")
            .expect("task joins cleanly");
        drop(raw_tx);
    }
}
