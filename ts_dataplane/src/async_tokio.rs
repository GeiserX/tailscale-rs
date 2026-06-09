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

/// The longest the dataplane will ever sleep waiting for a timer before re-checking the wireguard
/// state machine, even when no event is scheduled.
///
/// The primary driver of timer progress is a real scheduled event: an endpoint with persistent
/// keepalive enabled (the default) always reports a next-event deadline via
/// [`crate::DataPlane::next_event`], so `step` wakes on it and the keepalive / rekey / expiry timers
/// fire on schedule even on an otherwise idle, fully-relayed tunnel. This floor is a defensive safety
/// net: it guarantees the dataplane can never block *forever* on I/O with timers due — the bug where
/// `next_event() == None` turned the sleep into `future::pending()`, so an idle session aged past
/// expiry with nothing to refresh it. A spurious wakeup with no due event is harmless (the dispatch
/// finds nothing and writes nothing); 1s keeps idle-wakeup overhead negligible.
const MAX_TIMER_SLEEP: core::time::Duration = core::time::Duration::from_secs(1);

/// Sleep until the next scheduled event deadline, but never longer than [`MAX_TIMER_SLEEP`].
///
/// When `deadline` is `None` (no event scheduled) this sleeps for [`MAX_TIMER_SLEEP`] rather than
/// blocking forever, so the dataplane periodically re-services the wireguard state machine even with
/// zero traffic and zero scheduled events.
async fn sleep_until_event(deadline: Option<tokio::time::Instant>) {
    let until = next_wakeup(deadline, tokio::time::Instant::now(), MAX_TIMER_SLEEP);
    tokio::time::sleep_until(until).await;
}

/// Compute the next wakeup instant: the earlier of the next scheduled event `deadline` and the
/// bounded floor `now + max_sleep`. A `None` deadline (nothing scheduled) collapses to the floor, so
/// the result is *always* a finite instant — the dataplane can never sleep forever. Pure so the
/// "never block forever" decision is unit-testable without a runtime.
fn next_wakeup<I: Ord + core::ops::Add<core::time::Duration, Output = I> + Copy>(
    deadline: Option<I>,
    now: I,
    max_sleep: core::time::Duration,
) -> I {
    let floor = now + max_sleep;
    match deadline {
        Some(deadline) => deadline.min(floor),
        None => floor,
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
        let woke = next_wakeup(None, now, MAX_TIMER_SLEEP);
        assert_eq!(
            woke,
            now + MAX_TIMER_SLEEP,
            "a None deadline must collapse to the bounded floor, never block forever"
        );
    }

    /// A soon scheduled event is honored exactly (the floor only caps far-off / absent deadlines, it
    /// never delays a due event).
    #[test]
    fn near_event_is_honored_exactly() {
        let now = std::time::Instant::now();
        let soon = now + core::time::Duration::from_millis(50);
        assert_eq!(
            next_wakeup(Some(soon), now, MAX_TIMER_SLEEP),
            soon,
            "an event sooner than the floor must wake exactly on its deadline"
        );
    }

    /// A far-future scheduled event is clamped to the floor, so we re-service the state machine at
    /// least once per [`MAX_TIMER_SLEEP`] even when the only scheduled event is distant.
    #[test]
    fn far_event_is_clamped_to_floor() {
        let now = std::time::Instant::now();
        let far = now + core::time::Duration::from_secs(3600);
        assert_eq!(
            next_wakeup(Some(far), now, MAX_TIMER_SLEEP),
            now + MAX_TIMER_SLEEP,
            "a far-off event must be clamped to the floor"
        );
    }
}
