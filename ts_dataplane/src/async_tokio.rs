//! The packet processing dataplane, as a tokio task.

use std::{collections::HashMap, convert::Infallible, ops::DerefMut, sync::atomic::AtomicU32};

use tokio::sync::{Mutex, mpsc};
use ts_packet::PacketMut;
use ts_transport::{OverlayTransportId, PeerId, UnderlayTransportId};
use ts_tunnel::NodeKeyPair;

use crate::{EventResult, InboundResult, OutboundResult};

/// Queue for packets leaving the data plane "up" into an overlay transport.
pub type DataplaneToOverlay = mpsc::UnboundedSender<Vec<PacketMut>>;

/// Queue for packets entering the data plane "down" from an overlay transport.
pub type DataplaneFromOverlay = mpsc::UnboundedReceiver<Vec<PacketMut>>;

/// Queue for packets leaving the data plane "down" into an underlay transport.
pub type DataplaneToUnderlay = mpsc::UnboundedSender<(PeerId, Vec<PacketMut>)>;

/// Queue for packets entering the data plane "up" from an underlay transport.
pub type DataplaneFromUnderlay = mpsc::UnboundedReceiver<(PeerId, Vec<PacketMut>)>;

// TODO: wire in overlay/underlay transport traits

/// Transforms packets to make tailscale happen.
pub struct DataPlane {
    core_state: Mutex<CoreState>,
    poll_state: Mutex<PollState>,

    transports_changed: tokio::sync::Notify,

    underlay_down: DataplaneToUnderlay,
    overlay_up: DataplaneToOverlay,

    next_underlay_transport: AtomicU32,
    next_overlay_transport: AtomicU32,
}

struct CoreState {
    /// The synchronous core of the data plane.
    sync: crate::DataPlane,

    /// Queues to write packets to overlay transports.
    overlay_transports: HashMap<OverlayTransportId, DataplaneToOverlay>,
    /// Queues to write packets to underlay transports.
    underlay_transports: HashMap<UnderlayTransportId, DataplaneToUnderlay>,
}

/// State that must be held during async polling.
struct PollState {
    /// Queue for packets entering the data plane ("coming down") from overlay transports.
    from_overlay: DataplaneFromOverlay,
    /// Queue for packets entering the data plane ("coming up") from underlay transports.
    from_underlay: DataplaneFromUnderlay,
}

impl DataPlane {
    /// Create a new data plane for a wireguard node key.
    ///
    /// The caller must configure overlay/underlay output queues for the data plane to be useful,
    /// otherwise all it can do is drop packets.
    pub fn new(my_key: NodeKeyPair) -> Self {
        let (overlay_up, overlay_down) = mpsc::unbounded_channel();
        let (underlay_down, underlay_up) = mpsc::unbounded_channel();

        let sync = crate::DataPlane::new(my_key);

        Self {
            underlay_down,
            overlay_up,

            next_overlay_transport: Default::default(),
            next_underlay_transport: Default::default(),

            transports_changed: tokio::sync::Notify::new(),

            core_state: Mutex::new(CoreState {
                sync,
                overlay_transports: Default::default(),
                underlay_transports: Default::default(),
            }),

            poll_state: Mutex::new(PollState {
                from_overlay: overlay_down,
                from_underlay: underlay_up,
            }),
        }
    }

    /// Allocate a new underlay transport.
    pub async fn new_underlay_transport(
        &self,
    ) -> (
        UnderlayTransportId,
        DataplaneFromUnderlay,
        DataplaneToUnderlay,
    ) {
        let id = self
            .next_underlay_transport
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .into();

        let (tx, rx) = mpsc::unbounded_channel();

        {
            let mut rest = self.core_state.lock().await;
            rest.underlay_transports.insert(id, tx);
        }

        self.transports_changed.notify_waiters();

        (id, rx, self.underlay_down.clone())
    }

    /// Allocate a new overlay transport.
    pub async fn new_overlay_transport(
        &self,
    ) -> (OverlayTransportId, DataplaneToOverlay, DataplaneFromOverlay) {
        let id = self
            .next_overlay_transport
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .into();

        let (tx, rx) = mpsc::unbounded_channel();

        {
            let mut rest = self.core_state.lock().await;
            rest.overlay_transports.insert(id, tx);
        }

        self.transports_changed.notify_waiters();

        (id, self.overlay_up.clone(), rx)
    }

    /// Run the data plane forever, moving packets from the input queues to output queues.
    pub async fn run(&self) -> Infallible {
        loop {
            self.step().await;
        }
    }

    /// Run the data plane for a single step.
    #[tracing::instrument(skip_all)]
    pub async fn step(&self) {
        enum SelectResult {
            OverlayDown(Vec<PacketMut>),
            UnderlayUp(PeerId, Vec<PacketMut>),
            TransportsChanged,
            Event,
        }

        // process in two phases:
        //
        // - SELECT: wait for underlying i/o or timer to make progress: don't lock the
        //      user-modifiable (core) state. self.transports_changed is used to break out of this
        //      state if the caller changes the underlying transports
        // - UPDATE: lock the user-modifiable state and actually write out the packets produced
        //      in the SELECT phase (if any)
        //
        // designed this way to ensure that users can add and remove transports at any time without
        // having to wait for the network or a timer to make progress (which may never happen)

        let select_result = {
            let next_event = {
                let state = self.core_state.lock().await;
                state.sync.next_event()
            };

            let mut poll_state = self.poll_state.lock().await;

            let PollState {
                from_overlay: overlay_down,
                from_underlay: underlay_up,
                ..
            } = &mut *poll_state;

            tokio::select! {
                overlay_pkts = overlay_down.recv() => {
                    let overlay_pkts = overlay_pkts.unwrap();
                    tracing::trace!(n_overlay_pkts = overlay_pkts.len());

                    SelectResult::OverlayDown(overlay_pkts)
                }

                underlay_pkts = underlay_up.recv() => {
                    let (peer_id, underlay_pkts) = underlay_pkts.unwrap();
                    tracing::trace!(%peer_id, n_underlay_pkts = underlay_pkts.len());

                    SelectResult::UnderlayUp(peer_id, underlay_pkts)
                }

                _ = self.transports_changed.notified() => {
                    tracing::trace!("transports changed");

                    SelectResult::TransportsChanged
                }

                _ = sleep_until_event(next_event.map(Into::into)) => {
                    tracing::trace!("event");

                    SelectResult::Event
                }
            }
        };

        let mut core = self.core_state.lock().await;

        let (to_peers, to_local) = match select_result {
            SelectResult::OverlayDown(overlay_down) => {
                let OutboundResult { to_peers, loopback } =
                    core.sync.process_outbound(overlay_down);

                (Some(to_peers), Some(loopback))
            }
            SelectResult::UnderlayUp(_peer_id, underlay_up) => {
                let InboundResult { to_local, to_peers } = core.sync.process_inbound(underlay_up);

                (Some(to_peers), Some(to_local))
            }
            SelectResult::Event => {
                let EventResult { to_peers } = core.sync.process_events();
                (Some(to_peers), None)
            }
            SelectResult::TransportsChanged => (None, None),
        };

        if let Some(to_peers) = to_peers {
            write_to_underlay(&core, to_peers).await;
        }

        if let Some(to_local) = to_local {
            write_to_overlay(&core, to_local).await;
        }
    }

    /// Get a mutable reference to the inner [`crate::DataPlane`].
    ///
    /// Primarily intended for mutating the routing tables.
    ///
    /// The returned value is a mutex guard, so limit how long it's held.
    pub async fn inner(&self) -> impl DerefMut<Target = crate::DataPlane> {
        let core = self.core_state.lock().await;
        tokio::sync::MutexGuard::map(core, |x| &mut x.sync)
    }
}

async fn write_to_overlay(slf: &CoreState, packets: HashMap<OverlayTransportId, Vec<PacketMut>>) {
    for (id, packets) in packets {
        if let Some(queue) = slf.overlay_transports.get(&id) {
            tracing::trace!(overlay_id = ?id, n_packets = packets.len());
            queue.send(packets).unwrap();
        }
    }
}

async fn write_to_underlay(
    slf: &CoreState,
    packets: impl IntoIterator<Item = ((UnderlayTransportId, PeerId), Vec<PacketMut>)>,
) {
    for ((tid, peer_id), packets) in packets {
        tracing::trace!(underlay_id = ?tid, %peer_id, n_packets = packets.len());

        if let Some(queue) = slf.underlay_transports.get(&tid) {
            queue.send((peer_id, packets)).unwrap();
        }
    }
}

/// The longest the dataplane will sleep waiting for a timer when *no* event is scheduled, before
/// re-checking the wireguard state machine.
///
/// The primary driver of timer progress is a real scheduled event: an endpoint with persistent
/// keepalive enabled (the default) always reports a next-event deadline via
/// [`crate::DataPlane::next_event`], so `step` wakes exactly on it and the keepalive / rekey / expiry
/// timers fire on schedule even on an otherwise idle, fully-relayed tunnel. When such a deadline
/// exists we sleep all the way to it (it is itself the coalesced *soonest* timer), so an idle tunnel
/// with a keepalive due in ~25s sleeps ~25s and wakes *once* — not once per second.
///
/// This bound is purely a defensive safety net for the *no-event* case: it guarantees the dataplane
/// can never block *forever* on I/O with nothing scheduled — the wedge where `next_event() == None`
/// turned the sleep into `future::pending()`, so an idle session aged past expiry with nothing to
/// refresh it. A spurious wakeup with no due event is harmless (the dispatch finds nothing and writes
/// nothing); a few-second bound keeps that idle-wakeup overhead negligible (≈17k wakeups/day vs the
/// old unconditional 1 Hz floor's ≈86k) while still bounding the wedge window.
const MAX_IDLE_SLEEP: core::time::Duration = core::time::Duration::from_secs(5);

/// Sleep until the next scheduled event deadline; if none is scheduled, sleep at most
/// [`MAX_IDLE_SLEEP`] rather than blocking forever.
///
/// When `deadline` is `Some`, this wakes exactly on it (a finite instant, so it can never block
/// forever and never wakes later than the deadline). When `deadline` is `None` (no event scheduled)
/// it sleeps for [`MAX_IDLE_SLEEP`] so the dataplane periodically re-services the wireguard state
/// machine even with zero traffic and zero scheduled events.
async fn sleep_until_event(deadline: Option<tokio::time::Instant>) {
    let until = next_wakeup(deadline, tokio::time::Instant::now(), MAX_IDLE_SLEEP);
    tokio::time::sleep_until(until).await;
}

/// Compute the next wakeup instant.
///
/// - `Some(deadline)`: wake exactly on the next scheduled event. Real timers (persistent keepalive /
///   rekey / expiry) are always reported as events, and `next_event` already returns the *soonest*
///   one, so honoring it directly means an idle tunnel with a keepalive due in 25s sleeps ~25s and
///   wakes *once*. We deliberately do **not** clamp the deadline down to an idle floor — that would
///   wake ~25× more often for no benefit, since nothing is due before the deadline. The deadline is
///   itself a finite instant, so this can never block forever, and we never wake *later* than it.
/// - `None` (nothing scheduled): collapse to the bounded floor `now + max_idle_sleep` so the result
///   is *always* a finite instant — the dataplane can never sleep forever even with no events.
///
/// Pure so the cadence (and the "never block forever" guarantee) is unit-testable without a runtime.
fn next_wakeup<I: core::ops::Add<core::time::Duration, Output = I> + Copy>(
    deadline: Option<I>,
    now: I,
    max_idle_sleep: core::time::Duration,
) -> I {
    match deadline {
        Some(deadline) => deadline,
        None => now + max_idle_sleep,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wedge fix, distilled: with no event scheduled, the dataplane must still wake within the
    /// bounded floor instead of `future::pending()` (block forever). This is what guarantees an idle
    /// endpoint's timers (persistent keepalive / rekey / expiry) keep getting serviced.
    #[test]
    fn no_scheduled_event_still_wakes_within_floor() {
        let now = std::time::Instant::now();
        let woke = next_wakeup(None, now, MAX_IDLE_SLEEP);
        assert_eq!(
            woke,
            now + MAX_IDLE_SLEEP,
            "a None deadline must collapse to the bounded floor, never block forever"
        );
    }

    /// A soon scheduled event is honored exactly: the idle floor only applies when *no* event is
    /// scheduled, it never delays (or hurries) a due event.
    #[test]
    fn near_event_is_honored_exactly() {
        let now = std::time::Instant::now();
        let soon = now + core::time::Duration::from_millis(50);
        assert_eq!(
            next_wakeup(Some(soon), now, MAX_IDLE_SLEEP),
            soon,
            "an event sooner than the floor must wake exactly on its deadline"
        );
    }

    /// A far-future scheduled event is honored exactly, *not* clamped down to the idle floor: the
    /// floor exists only to bound the no-event wedge. `next_event` already reports the soonest timer,
    /// so nothing is due before the deadline — clamping it would just burn ~floor-cadence wakeups on
    /// an idle tunnel (the battery regression this fix removes). Sleeping to a far real deadline is
    /// safe precisely because it is finite (never `pending()`).
    #[test]
    fn far_event_is_honored_not_clamped() {
        let now = std::time::Instant::now();
        let far = now + core::time::Duration::from_secs(3600);
        assert_eq!(
            next_wakeup(Some(far), now, MAX_IDLE_SLEEP),
            far,
            "a far-off scheduled event must be honored exactly, not clamped to the idle floor"
        );
    }

    /// An idle tunnel with a persistent keepalive due in ~25s must sleep ~25s and wake *once*, not
    /// once per [`MAX_IDLE_SLEEP`] — this is the battery/wakeup regression the fix targets.
    #[test]
    fn keepalive_in_25s_sleeps_to_the_deadline_not_the_floor() {
        let now = std::time::Instant::now();
        let keepalive_due = now + core::time::Duration::from_secs(25);
        let woke = next_wakeup(Some(keepalive_due), now, MAX_IDLE_SLEEP);
        assert_eq!(
            woke, keepalive_due,
            "a 25s keepalive deadline must be slept to directly (one wakeup), not capped at the idle floor"
        );
        assert!(
            woke > now + MAX_IDLE_SLEEP,
            "the wakeup must be well past the idle floor: the floor must not shorten a real deadline"
        );
    }

    /// The anti-busy-spin invariant of the wedge fix, stated as a bound: a fully-idle dataplane (no
    /// scheduled event) must always wake **strictly in the future**, on the coarse floor — never at
    /// `now` or earlier (which would make `sleep_until` return instantly and turn `step()` into a
    /// tight, CPU-burning sub-millisecond loop) and never `future::pending()` (the original
    /// block-forever wedge). Swept over several base instants against the *real* `MAX_IDLE_SLEEP` so
    /// the production idle cadence itself is what's pinned, not a toy value.
    ///
    /// Scope note: this is the deepest layer testable without a runtime. A full `#[tokio::test]`
    /// driving [`DataPlane::step`] under `tokio::time::pause()` / `advance()` would require tokio's
    /// `test-util` feature, which `ts_dataplane` does not enable (turning it on is a non-test
    /// dependency change, out of scope here). [`sleep_until_event`] is a thin wrapper that feeds this
    /// exact instant straight to `tokio::time::sleep_until`, so the integration-level idle cadence —
    /// wake every `MAX_IDLE_SLEEP`, never sooner, never never — is fully determined by (and thus
    /// covered through) this helper's boundedness.
    #[test]
    fn idle_wakeup_is_coarse_and_never_busy_spins() {
        // A zero floor would let an idle step() spin; the production cadence must be positive.
        assert!(
            MAX_IDLE_SLEEP > core::time::Duration::ZERO,
            "the idle floor must be a positive cadence, else step() would busy-spin"
        );

        let base = std::time::Instant::now();
        for offset_ms in [0u64, 1, 250, 5_000, 60_000] {
            let now = base + core::time::Duration::from_millis(offset_ms);
            let woke = next_wakeup(None, now, MAX_IDLE_SLEEP);

            // Strictly after `now`: an idle wakeup at or before `now` would busy-spin step().
            assert!(
                woke > now,
                "idle wakeup must be strictly after now (no busy-spin); got {woke:?} <= {now:?}"
            );
            // Bounded to exactly the coarse floor: never sooner (tight loop), always finite
            // (never the old `future::pending()` block-forever).
            assert_eq!(
                woke,
                now + MAX_IDLE_SLEEP,
                "idle wakeup must land on the bounded coarse floor, never sooner and never never"
            );
        }
    }
}
