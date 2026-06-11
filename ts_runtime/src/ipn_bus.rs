//! Unified IPN notification bus: a single push-style stream that coalesces the device's
//! connection-[`DeviceState`] and netmap peer-set changes into one [`Notify`] feed, mirroring Go
//! `ipn` `LocalBackend.WatchNotifications` / the `WatchIPNBus` LocalAPI.
//!
//! Go delivers one `ipn.Notify` struct per event in which **only the changed fields are populated**
//! (a nil field means "unchanged"); an optional subscribe-time mask ([`NotifyWatchOpt`]) front-loads
//! an initial snapshot of the current state. [`Notify`] is the faithful Rust shape of that struct —
//! a struct of `Option`s, not a per-event enum.
//!
//! # Coalescing: initial snapshot vs. streamed events
//!
//! The struct-of-`Option`s shape lets one `Notify` carry several changed fields at once. This bus
//! exploits that **for the initial snapshot only**: the subscribe-time snapshot reads every source
//! cell synchronously and packs the masked fields into one `Notify`. Post-subscribe, the merge loop
//! is per-source — each source cell's change produces its own single-field `Notify` (a state change
//! yields `state: Some`, a peer change yields `net_map: Some`), because the cells are independent
//! `watch` channels with no cross-cell synchronization point to coalesce on. A consumer therefore
//! sees at most one coalesced snapshot followed by single-field deltas. (Go can pack several fields
//! into one streamed `Notify` because a single `MapResponse` updates several things together under
//! one lock; the fork has already split those into separate cells, so the equivalent streamed events
//! arrive separately here. The `Option` shape is still the right type — it keeps the snapshot
//! faithful and leaves room for a future single source to set multiple fields.)
//!
//! # Why these sources
//!
//! The fork already decomposes Go's single notification channel into separate, individually-correct
//! `watch` surfaces ([`Runtime::watch_state`](crate::Runtime::watch_state),
//! [`Runtime::watch_netmap`](crate::Runtime::watch_netmap)). This bus *composes* the same cells (one
//! source of truth — it cannot diverge from the narrow views) into the merged feed an embedder
//! porting from Go's `WatchIPNBus` expects. The two cells it reads map onto Go `Notify` fields:
//!
//! - [`DeviceState`] → `Notify.State`, and the **registration-time** interactive-login URL carried
//!   by [`DeviceState::NeedsLogin`] (`Notify.browse_to_url`, derived from that state — control's
//!   `MachineNotAuthorized`).
//! - the running-node consent URL (`MapResponse.PopBrowserURL`) → `Notify.browse_to_url` as a
//!   mid-session event. Go also forwards this `BrowseToURL` for an already-`Running` node (re-auth /
//!   forced-re-login nudges). The fork's backing cell is **sticky** (the producer updates it only on
//!   a new non-empty URL, never resets it to `None` on an empty update — Go's `direct.go` guard
//!   `u != "" && u != sess.lastPopBrowserURL`), so a `watch` subscriber is not thrashed. It is
//!   streamed post-subscribe but **not** front-loaded into the initial snapshot — Go replays only the
//!   registration `b.authURL` (the `NeedsLogin`-derived URL above) on a new watcher, never the
//!   running-node `PopBrowserURL`; a consumer wanting the current pending URL at subscribe time reads
//!   the sticky `pop_browser_url` pull API.
//! - the peer set (`Vec<StatusNode>`) → `Notify.NetMap` (the embedder-facing peer view).
//!
//! Go's `Notify` has no packet-filter cap-grant field (caps are an internal `WhoIs` input, not an
//! embedder notification), so the retained cap-grants cell is intentionally **not** surfaced here.
//!
//! # Lossy by design
//!
//! Like Go's bus (a bounded 128-deep channel drained with a non-blocking `select { case ch<-n:
//! default: drop }`), delivery is best-effort: the per-watcher [`mpsc`] is bounded at
//! [`NOTIFY_BUFFER`] and a notification for a watcher whose buffer is full is **dropped**, never
//! blocking the producer. The underlying `watch` cells are themselves coalescing, so a slow consumer
//! observes the latest state, not every intermediate — the right semantics for state/netmap
//! snapshots (and the reason this bus is not used for any at-least-once delivery).

use tokio::sync::{mpsc, watch};

use crate::{device_state::DeviceState, status::StatusNode};

/// Per-watcher notification buffer depth. Matches Go's `ipn` bus channel size
/// (`make(chan *ipn.Notify, 128)`): a bounded queue that the producer never blocks on — a full
/// buffer drops the notification (see module docs).
pub const NOTIFY_BUFFER: usize = 128;

/// Selects which initial-state fields are front-loaded into the first [`Notify`] when a watcher
/// subscribes (Go `ipn.NotifyWatchOpt`). A bitfield; combine with `|`.
///
/// The numeric values match Go's `NotifyWatchOpt` literals exactly (`NotifyInitialState = 1 << 1`,
/// `NotifyInitialNetMap = 1 << 3`), so a mask built from Go's integer constants is wire-compatible.
/// Bits Go defines but this bus does not yet surface (initial prefs/health/etc.) are simply not
/// honored — passing them is harmless, exactly as an unrecognized bit is in Go.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NotifyWatchOpt(u64);

impl NotifyWatchOpt {
    /// No initial snapshot: the watcher receives only changes that occur after it subscribes.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Front-load the current [`DeviceState`] (and, when it is [`DeviceState::NeedsLogin`], the
    /// auth URL as `browse_to_url`) into the first [`Notify`]. Go `NotifyInitialState` (`1 << 1`).
    pub const INITIAL_STATE: Self = Self(1 << 1);

    /// Front-load the current peer set (`net_map`) into the first [`Notify`]. Go
    /// `NotifyInitialNetMap` (`1 << 3`).
    pub const INITIAL_NETMAP: Self = Self(1 << 3);

    /// Whether all bits in `other` are set in `self`.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl core::ops::BitOr for NotifyWatchOpt {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// A single notification from the [IPN bus](self), mirroring Go `ipn.Notify`: each field is `Some`
/// only when it changed in this event (a `None` field means "unchanged"). One event may populate
/// several fields at once (e.g. a netmap update that also moves the device state).
///
/// `#[non_exhaustive]` so future Go-parity fields (prefs, engine status, health) can be added
/// without breaking embedders that match on it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Notify {
    /// The new device connection-state, if it changed (Go `Notify.State`).
    pub state: Option<DeviceState>,
    /// The new peer set, if the netmap changed (Go `Notify.NetMap`, embedder-facing peer view).
    pub net_map: Option<Vec<StatusNode>>,
    /// An interactive-login / consent URL the embedder should open (Go `Notify.BrowseToURL`). Two
    /// sources feed it: the **registration-time** auth URL, derived from [`DeviceState::NeedsLogin`]
    /// and set alongside `state` when the device enters that state; and the **mid-session**
    /// `MapResponse.PopBrowserURL` (re-auth / consent on an already-running node), streamed on its own
    /// as a standalone event. See the module docs for which is front-loaded into the initial snapshot
    /// (only the registration URL) vs. streamed (both).
    pub browse_to_url: Option<url::Url>,
}

impl Notify {
    /// Whether this notification carries no populated field. An all-`None` `Notify` is never
    /// delivered (the bus skips it), so observing one from [`IpnBusWatcher::next`] is impossible;
    /// the predicate exists for the bus's own "is there anything to send?" check.
    fn is_empty(&self) -> bool {
        self.state.is_none() && self.net_map.is_none() && self.browse_to_url.is_none()
    }
}

/// A handle to a live [IPN bus](self) subscription, mirroring Go's `IPNBusWatcher`. Await
/// [`next`](Self::next) to receive [`Notify`] events; it returns `None` when the stream ends (the
/// runtime shut down, or this watcher was dropped).
#[derive(Debug)]
pub struct IpnBusWatcher {
    rx: mpsc::Receiver<Notify>,
}

impl IpnBusWatcher {
    /// Await the next [`Notify`]. Returns `None` once the bus has terminated (runtime shutdown or
    /// every source cell's sender dropped) — the clean end-of-stream signal, like Go's watcher
    /// channel closing.
    pub async fn next(&mut self) -> Option<Notify> {
        self.rx.recv().await
    }
}

/// Spawn the bus task feeding `tx` and return the consumer handle. Reads cloned `watch` receivers
/// (so it never contends with the runtime's own readers) and a `shutdown` receiver that terminates
/// the task. The task self-terminates on shutdown, on any source sender dropping, or when the
/// returned [`IpnBusWatcher`] is dropped (the `tx` send then reports the channel closed) — so it
/// cannot leak past the runtime or a discarded watcher.
pub(crate) fn spawn_watcher(
    mask: NotifyWatchOpt,
    state_rx: watch::Receiver<DeviceState>,
    peer_rx: watch::Receiver<Vec<StatusNode>>,
    browser_rx: watch::Receiver<Option<url::Url>>,
    shutdown_rx: watch::Receiver<bool>,
) -> IpnBusWatcher {
    let (tx, rx) = mpsc::channel(NOTIFY_BUFFER);
    tokio::spawn(run_bus(
        mask,
        state_rx,
        peer_rx,
        browser_rx,
        shutdown_rx,
        tx,
    ));
    IpnBusWatcher { rx }
}

/// Try to deliver `n`, returning `true` when the bus should stop (the consumer is gone).
///
/// Mirrors Go's non-blocking `select { case ch <- n: default: /* drop */ }`: a `Full` buffer drops
/// the notification and keeps streaming (best-effort delivery, never block the producer); a `Closed`
/// channel means the watcher was dropped, so the task is done.
fn deliver(tx: &mpsc::Sender<Notify>, n: Notify) -> bool {
    match tx.try_send(n) {
        Ok(()) => false,
        Err(mpsc::error::TrySendError::Full(_)) => false,
        Err(mpsc::error::TrySendError::Closed(_)) => true,
    }
}

/// The interactive-login URL implied by a device state: `Some` only for [`DeviceState::NeedsLogin`].
/// The single derivation rule for `browse_to_url`, shared by the initial snapshot and the streaming
/// state arm so the two can never drift (see module docs on the registration-time URL).
fn browse_url_for(state: &DeviceState) -> Option<url::Url> {
    match state {
        DeviceState::NeedsLogin(u) => Some(u.clone()),
        _ => None,
    }
}

/// Build the `Notify` for a device-state transition: the state plus its derived `browse_to_url`.
fn state_notify(state: DeviceState) -> Notify {
    let browse_to_url = browse_url_for(&state);
    Notify {
        state: Some(state),
        net_map: None,
        browse_to_url,
    }
}

/// The bus loop, factored out of [`spawn_watcher`] so the (subtle) ordering — the masked initial
/// snapshot, the `borrow_and_update` that prevents an initial-value busy-loop, the shutdown arm, and
/// sender-drop termination — is unit-testable against plain `watch`/`mpsc` channels without standing
/// up a runtime (mirrors [`device_state::wait_for_running`](crate::device_state::wait_for_running)).
pub(crate) async fn run_bus(
    mask: NotifyWatchOpt,
    mut state_rx: watch::Receiver<DeviceState>,
    mut peer_rx: watch::Receiver<Vec<StatusNode>>,
    mut browser_rx: watch::Receiver<Option<url::Url>>,
    mut shutdown_rx: watch::Receiver<bool>,
    tx: mpsc::Sender<Notify>,
) {
    // If the runtime is already shutting down, end before doing anything. This also marks the
    // shutdown cell's initial `false` as *seen* so the `select!` arm below doesn't fire spuriously
    // on the unobserved initial value (the classic `watch`-in-`select!` busy-loop).
    if *shutdown_rx.borrow_and_update() {
        return;
    }

    // Initial snapshot: ONE coalesced `Notify` carrying whichever masked fields are requested
    // (Go front-loads State+NetMap into a single `ini` struct). `borrow_and_update` reads the
    // current value AND marks it seen, so the streaming loop's first `changed()` waits for a real
    // transition instead of re-emitting the value we just snapshotted.
    let mut initial = Notify::default();
    {
        let state = state_rx.borrow_and_update();
        if mask.contains(NotifyWatchOpt::INITIAL_STATE) {
            initial.browse_to_url = browse_url_for(&state);
            initial.state = Some(state.clone());
        }
    }
    {
        let peers = peer_rx.borrow_and_update();
        if mask.contains(NotifyWatchOpt::INITIAL_NETMAP) {
            initial.net_map = Some(peers.clone());
        }
    }
    // Mark the running-node browser-URL cell's initial value seen so the streaming arm waits for a
    // real post-subscribe change (busy-loop prevention, same as the cells above). Its current value
    // is deliberately NOT front-loaded into the initial snapshot: Go replays only the
    // registration-time auth URL (the `NeedsLogin`-derived `browse_to_url` above), never the
    // running-node `MapResponse.PopBrowserURL`, on a new watcher's initial state. A consumer wanting
    // the current pending consent URL at subscribe time reads the sticky `pop_browser_url` pull API;
    // the bus streams future transitions.
    browser_rx.borrow_and_update();
    if !initial.is_empty() && deliver(&tx, initial) {
        return;
    }

    // Stream subsequent changes. `biased` makes shutdown take priority over data so a teardown is
    // observed promptly. Each data arm re-reads with `borrow_and_update().clone()` into an owned
    // value and drops the borrow guard *before* the next await — never holding a `watch` read guard
    // across `.changed()` (which would deadlock). A sender-drop (`changed()` => `Err`) ends the
    // stream, exactly as `wait_for_running` treats it.
    loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => return,
            // The consumer dropped its `IpnBusWatcher`: reclaim the task immediately rather than
            // waiting for the next source change to surface a `Closed` on the next `deliver`. On an
            // idle (quiet) device that next change might be far off, so without this arm a dropped
            // watcher would leave the task parked until shutdown. `Sender::closed()` resolves once
            // every receiver is gone.
            _ = tx.closed() => return,
            changed = state_rx.changed() => {
                if changed.is_err() {
                    return;
                }
                let state = state_rx.borrow_and_update().clone();
                if deliver(&tx, state_notify(state)) {
                    return;
                }
            }
            changed = peer_rx.changed() => {
                if changed.is_err() {
                    return;
                }
                let peers = peer_rx.borrow_and_update().clone();
                let notify = Notify {
                    state: None,
                    net_map: Some(peers),
                    browse_to_url: None,
                };
                if deliver(&tx, notify) {
                    return;
                }
            }
            changed = browser_rx.changed() => {
                if changed.is_err() {
                    return;
                }
                // The running-node consent URL (`MapResponse.PopBrowserURL`). The producer cell is
                // de-thrashed (updated only on a new non-empty URL, never reset to `None`), so a
                // change here carries a fresh `Some(url)`; skip the defensive `None` case rather than
                // emit an empty `browse_to_url`.
                let url = browser_rx.borrow_and_update().clone();
                if let Some(url) = url {
                    let notify = Notify {
                        state: None,
                        net_map: None,
                        browse_to_url: Some(url),
                    };
                    if deliver(&tx, notify) {
                        return;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use tokio::sync::{mpsc, watch};

    use super::*;

    /// The hand-made channel senders (state, peer, browser-URL, shutdown) plus the consumer handle
    /// that [`harness`] returns — the four source senders let a test drive `run_bus`, and the
    /// `IpnBusWatcher` observes what it emits.
    type Harness = (
        watch::Sender<DeviceState>,
        watch::Sender<Vec<StatusNode>>,
        watch::Sender<Option<url::Url>>,
        watch::Sender<bool>,
        IpnBusWatcher,
    );

    /// Drive `run_bus` on a task against hand-made channels, returning the senders (state, peer,
    /// browser-URL, shutdown) and the consumer handle. Mirrors how `device_state` tests drive
    /// `wait_for_running` off a plain `watch`.
    fn harness(mask: NotifyWatchOpt, state: DeviceState, peers: Vec<StatusNode>) -> Harness {
        let (state_tx, state_rx) = watch::channel(state);
        let (peer_tx, peer_rx) = watch::channel(peers);
        let (browser_tx, browser_rx) = watch::channel(None);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (tx, rx) = mpsc::channel(NOTIFY_BUFFER);
        tokio::spawn(run_bus(
            mask,
            state_rx,
            peer_rx,
            browser_rx,
            shutdown_rx,
            tx,
        ));
        (
            state_tx,
            peer_tx,
            browser_tx,
            shutdown_tx,
            IpnBusWatcher { rx },
        )
    }

    fn login_url() -> url::Url {
        "https://login.example/auth".parse().unwrap()
    }

    fn consent_url() -> url::Url {
        "https://login.example/consent".parse().unwrap()
    }

    /// A minimal non-empty peer, so a `net_map` payload assertion exercises a real value rather than
    /// the degenerate empty-vec round-trip.
    fn peer(id: &str) -> StatusNode {
        use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        StatusNode {
            stable_id: ts_control::StableNodeId(id.to_owned()),
            display_name: id.to_owned(),
            ipv4: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
            ipv6: IpAddr::V6(Ipv6Addr::LOCALHOST),
            online: Some(true),
            last_seen: None,
            allowed_routes: Vec::new(),
            is_exit_node: false,
            cur_addr: None,
            relay: None,
        }
    }

    /// A negative-assertion window: long enough that a real-but-slow event would still arrive within
    /// it on a loaded CI box (so "nothing arrived" is trustworthy, not just "nothing arrived *yet*").
    const QUIET_WINDOW: Duration = Duration::from_millis(250);

    /// `NotifyWatchOpt` is a faithful bitfield: Go's literal values, `contains`, and `|` compose.
    #[test]
    fn mask_bitfield_semantics() {
        assert!(NotifyWatchOpt::empty().contains(NotifyWatchOpt::empty()));
        assert!(!NotifyWatchOpt::empty().contains(NotifyWatchOpt::INITIAL_STATE));
        let both = NotifyWatchOpt::INITIAL_STATE | NotifyWatchOpt::INITIAL_NETMAP;
        assert!(both.contains(NotifyWatchOpt::INITIAL_STATE));
        assert!(both.contains(NotifyWatchOpt::INITIAL_NETMAP));
        // Wire-compatible with Go's NotifyWatchOpt integer literals.
        assert_eq!(NotifyWatchOpt::INITIAL_STATE, NotifyWatchOpt(1 << 1));
        assert_eq!(NotifyWatchOpt::INITIAL_NETMAP, NotifyWatchOpt(1 << 3));
    }

    /// `NotifyInitialState` front-loads the current state into the first `Notify` (state only, no
    /// net_map).
    #[tokio::test]
    async fn initial_state_snapshot_emitted_when_masked() {
        let (_s, _p, _b, _sd, mut w) = harness(
            NotifyWatchOpt::INITIAL_STATE,
            DeviceState::Running,
            Vec::new(),
        );
        let n = w.next().await.expect("initial snapshot");
        assert_eq!(n.state, Some(DeviceState::Running));
        assert_eq!(n.net_map, None);
        assert_eq!(n.browse_to_url, None);
    }

    /// `NotifyInitialNetMap` front-loads the current peer set (net_map only, no state).
    #[tokio::test]
    async fn initial_netmap_snapshot_emitted_when_masked() {
        let (_s, _p, _b, _sd, mut w) = harness(
            NotifyWatchOpt::INITIAL_NETMAP,
            DeviceState::Running,
            Vec::new(),
        );
        let n = w.next().await.expect("initial snapshot");
        assert_eq!(n.net_map, Some(Vec::new()));
        assert_eq!(n.state, None);
    }

    /// Both initial bits coalesce into ONE `Notify` (Go builds a single `ini` struct), not two
    /// separate events.
    #[tokio::test]
    async fn initial_snapshot_coalesces_both_fields() {
        let (_s, _p, _b, _sd, mut w) = harness(
            NotifyWatchOpt::INITIAL_STATE | NotifyWatchOpt::INITIAL_NETMAP,
            DeviceState::Running,
            Vec::new(),
        );
        let n = w.next().await.expect("initial snapshot");
        assert_eq!(n.state, Some(DeviceState::Running));
        assert_eq!(n.net_map, Some(Vec::new()));
    }

    /// An empty mask sends NO initial snapshot; the watcher then receives the next real transition.
    #[tokio::test]
    async fn empty_mask_skips_initial_then_streams_change() {
        let (state_tx, _p, _b, _sd, mut w) =
            harness(NotifyWatchOpt::empty(), DeviceState::Connecting, Vec::new());
        // No initial snapshot: nothing within the quiet window.
        assert!(
            tokio::time::timeout(QUIET_WINDOW, w.next()).await.is_err(),
            "empty mask must not emit an initial snapshot"
        );
        // Positive anchor: the watcher is still live and delivers the next real transition (so the
        // negative assertion above was "nothing to send", not "stream already dead").
        state_tx.send_replace(DeviceState::Running);
        let n = w.next().await.expect("change after subscribe");
        assert_eq!(n.state, Some(DeviceState::Running));
    }

    /// A `NeedsLogin` transition derives `browse_to_url` alongside `state` — one source of truth for
    /// the auth URL.
    #[tokio::test]
    async fn needs_login_transition_derives_browse_to_url() {
        // Subscribe with INITIAL_STATE so awaiting the first `next()` (the snapshot) is a
        // deterministic barrier proving the bus task has finished its init borrows and entered the
        // streaming loop — only then is a post-subscribe send guaranteed to be observed (no sleeps,
        // no spawn-vs-send race). Any change after `.changed()`'s seen-version is detected even if
        // the loop is not yet parked on `.changed()`.
        let (state_tx, _p, _b, _sd, mut w) = harness(
            NotifyWatchOpt::INITIAL_STATE,
            DeviceState::Connecting,
            Vec::new(),
        );
        let snap = w.next().await.expect("initial snapshot");
        assert_eq!(snap.state, Some(DeviceState::Connecting));
        assert_eq!(snap.browse_to_url, None);
        state_tx.send_replace(DeviceState::NeedsLogin(login_url()));
        let n = w.next().await.expect("needs-login event");
        assert_eq!(n.state, Some(DeviceState::NeedsLogin(login_url())));
        assert_eq!(n.browse_to_url, Some(login_url()));
    }

    /// `NeedsLogin` present at subscribe is front-loaded with its `browse_to_url` (matches Go: the
    /// initial snapshot carries `BrowseToURL` only when `state == NeedsLogin`).
    #[tokio::test]
    async fn initial_needs_login_includes_browse_to_url() {
        let (_s, _p, _b, _sd, mut w) = harness(
            NotifyWatchOpt::INITIAL_STATE,
            DeviceState::NeedsLogin(login_url()),
            Vec::new(),
        );
        let n = w.next().await.expect("initial snapshot");
        assert_eq!(n.browse_to_url, Some(login_url()));
    }

    /// A peer-set change streams as a `net_map` notification (no state field), carrying the actual
    /// new peer payload (not just the degenerate empty round-trip).
    #[tokio::test]
    async fn peer_change_streams_netmap() {
        // INITIAL_NETMAP snapshot is the barrier (proves the task finished its init borrows and is
        // in the streaming loop) before we send — avoids the spawn-vs-send race.
        let (_s, peer_tx, _b, _sd, mut w) = harness(
            NotifyWatchOpt::INITIAL_NETMAP,
            DeviceState::Running,
            Vec::new(),
        );
        let snap = w.next().await.expect("initial netmap snapshot");
        assert_eq!(snap.net_map, Some(Vec::new()));
        // Send a NON-EMPTY peer set so the assertion proves the payload is actually carried through,
        // not merely that a notification fires.
        let peers = vec![peer("peer-a"), peer("peer-b")];
        peer_tx.send_replace(peers.clone());
        let n = w.next().await.expect("netmap change");
        assert_eq!(n.net_map, Some(peers));
        assert_eq!(n.state, None);
    }

    /// After the initial snapshot, with no further changes, the bus does NOT re-emit — proving the
    /// `borrow_and_update` correctly marks the snapshotted values seen (no initial-value busy-loop).
    #[tokio::test]
    async fn no_spurious_reemit_after_initial() {
        let (state_tx, _p, _b, _sd, mut w) = harness(
            NotifyWatchOpt::INITIAL_STATE | NotifyWatchOpt::INITIAL_NETMAP,
            DeviceState::Running,
            Vec::new(),
        );
        let _initial = w.next().await.expect("initial snapshot");
        assert!(
            tokio::time::timeout(QUIET_WINDOW, w.next()).await.is_err(),
            "no change occurred, so no further notification must arrive"
        );
        // Positive liveness anchor: prove the watcher was genuinely alive during the quiet window
        // (not dropped/dead, which would ALSO deliver nothing and make the assertion above vacuous).
        // A real transition after the silence must still be delivered.
        state_tx.send_replace(DeviceState::Expired);
        let n = w
            .next()
            .await
            .expect("watcher still live after the quiet window");
        assert_eq!(n.state, Some(DeviceState::Expired));
    }

    /// Flipping the shutdown cell terminates the stream: `next()` returns `None`.
    #[tokio::test]
    async fn shutdown_terminates_stream() {
        let (_s, _p, _b, shutdown_tx, mut w) =
            harness(NotifyWatchOpt::empty(), DeviceState::Running, Vec::new());
        shutdown_tx.send_replace(true);
        assert_eq!(w.next().await, None, "shutdown must end the stream");
    }

    /// If the runtime is already shutting down at subscribe time, the stream ends immediately.
    #[tokio::test]
    async fn already_shutdown_ends_immediately() {
        let (state_tx, state_rx) = watch::channel(DeviceState::Running);
        let (peer_tx, peer_rx) = watch::channel(Vec::new());
        let (browser_tx, browser_rx) = watch::channel(None);
        let (_shutdown_tx, shutdown_rx) = watch::channel(true);
        let (tx, rx) = mpsc::channel(NOTIFY_BUFFER);
        tokio::spawn(run_bus(
            NotifyWatchOpt::INITIAL_STATE,
            state_rx,
            peer_rx,
            browser_rx,
            shutdown_rx,
            tx,
        ));
        let mut w = IpnBusWatcher { rx };
        assert_eq!(w.next().await, None, "already-shutdown must emit nothing");
        // Keep the source senders alive until after the assertion so termination is attributable to
        // the shutdown flag, not a sender drop.
        drop((state_tx, peer_tx, browser_tx));
    }

    /// Dropping every source sender (runtime tearing down without the graceful flag) also ends the
    /// stream rather than hanging.
    #[tokio::test]
    async fn source_sender_drop_terminates_stream() {
        let (state_tx, _p, _b, _sd, mut w) =
            harness(NotifyWatchOpt::empty(), DeviceState::Running, Vec::new());
        drop((state_tx, _p, _b, _sd));
        assert_eq!(w.next().await, None, "all senders gone must end the stream");
    }

    /// Streamed (post-subscribe) events are delivered per-source: a state change and a peer change
    /// arrive as TWO single-field `Notify`s, not one coalesced event. This pins the documented
    /// contract (only the *initial snapshot* coalesces; the loop is per-cell) so a future change to
    /// the merge loop can't silently alter it.
    #[tokio::test]
    async fn streamed_events_are_per_source_not_coalesced() {
        let (state_tx, peer_tx, _b, _sd, mut w) = harness(
            NotifyWatchOpt::INITIAL_STATE,
            DeviceState::Connecting,
            Vec::new(),
        );
        let _snap = w.next().await.expect("initial snapshot barrier");
        // Move two distinct sources. They are independent watch cells, so the bus emits one Notify
        // per source — never a single Notify carrying both `state` and `net_map`.
        state_tx.send_replace(DeviceState::Running);
        peer_tx.send_replace(vec![peer("peer-a")]);
        let first = w.next().await.expect("first event");
        let second = w.next().await.expect("second event");
        for n in [&first, &second] {
            assert!(
                n.state.is_some() ^ n.net_map.is_some(),
                "each streamed Notify carries exactly one of state / net_map, got {n:?}"
            );
        }
        // Both fields were delivered, just across two events (order is biased-but-unspecified here).
        assert!(
            first.state.is_some() || second.state.is_some(),
            "a state event arrived"
        );
        assert!(
            first.net_map.is_some() || second.net_map.is_some(),
            "a net_map event arrived"
        );
    }

    /// A sequence of state transitions yields one ordered `Notify` per transition, with
    /// `browse_to_url` set only on the `NeedsLogin` one — proving the loop re-arms correctly across
    /// more than a single cycle and preserves order.
    #[tokio::test]
    async fn sequential_state_transitions_stream_in_order() {
        let (state_tx, _p, _b, _sd, mut w) = harness(
            NotifyWatchOpt::INITIAL_STATE,
            DeviceState::Connecting,
            Vec::new(),
        );
        assert_eq!(
            w.next().await.expect("snapshot").state,
            Some(DeviceState::Connecting)
        );
        for next in [
            DeviceState::Running,
            DeviceState::NeedsLogin(login_url()),
            DeviceState::Expired,
        ] {
            state_tx.send_replace(next.clone());
            let n = w.next().await.expect("transition");
            assert_eq!(n.state, Some(next.clone()));
            assert_eq!(n.net_map, None);
            let expect_url = matches!(next, DeviceState::NeedsLogin(_)).then(login_url);
            assert_eq!(n.browse_to_url, expect_url);
        }
    }

    /// Each non-login state flows through as `state: Some(..)` with `browse_to_url: None` — closes
    /// the enum (the earlier tests only exercised Connecting / Running / NeedsLogin).
    #[tokio::test]
    async fn expired_and_failed_states_stream_without_url() {
        for state in [
            DeviceState::Expired,
            DeviceState::Failed(crate::RegistrationError::AuthRejected("bad key".into())),
        ] {
            let (state_tx, _p, _b, _sd, mut w) = harness(
                NotifyWatchOpt::INITIAL_STATE,
                DeviceState::Connecting,
                Vec::new(),
            );
            let _snap = w.next().await.expect("snapshot barrier");
            state_tx.send_replace(state.clone());
            let n = w.next().await.expect("state event");
            assert_eq!(n.state, Some(state));
            assert_eq!(n.browse_to_url, None);
        }
    }

    /// "Lossy by design": when the consumer never drains, a flood of changes fills the bounded
    /// buffer and excess notifications are DROPPED — the producer (`send_replace` on the source
    /// cell + the bus task) must never block. If `deliver` were changed to a blocking `send().await`,
    /// the bus task would wedge and the subsequent shutdown would never be observed → this test would
    /// hang (caught by the suite timeout). Proves the non-blocking `try_send` contract.
    #[tokio::test]
    async fn full_buffer_drops_and_never_blocks_producer() {
        let (state_tx, _p, _b, shutdown_tx, mut w) =
            harness(NotifyWatchOpt::empty(), DeviceState::Connecting, Vec::new());
        // Never call w.next(): the per-watcher mpsc fills to NOTIFY_BUFFER then drops the rest.
        // Push well past the buffer depth; yield so the bus task runs each send.
        for _ in 0..(NOTIFY_BUFFER * 2 + 16) {
            state_tx.send_replace(DeviceState::Running);
            state_tx.send_replace(DeviceState::Connecting);
            tokio::task::yield_now().await;
        }
        // The producer never blocked (we got here). The bus task is also not wedged: a shutdown is
        // still observed promptly and ends the stream once the buffer drains.
        shutdown_tx.send_replace(true);
        // Drain whatever buffered (≤ NOTIFY_BUFFER) then the stream must terminate with None.
        let mut drained = 0usize;
        while let Some(_n) = w.next().await {
            drained += 1;
            assert!(
                drained <= NOTIFY_BUFFER,
                "buffer must be bounded at NOTIFY_BUFFER ({NOTIFY_BUFFER}), drained {drained}"
            );
        }
    }

    /// Dropping the `IpnBusWatcher` reclaims the bus task PROMPTLY via the `tx.closed()` select arm —
    /// no subsequent source change is needed (the regression guard for the idle-device leak the
    /// `tx.closed()` arm fixes). Proven by observing the task drop its cloned `state_rx`, which falls
    /// the sender's `receiver_count` back to 0 once the task returns.
    #[tokio::test]
    async fn consumer_drop_terminates_task() {
        let (state_tx, _p, _b, _sd, w) =
            harness(NotifyWatchOpt::empty(), DeviceState::Connecting, Vec::new());
        // Sanity: the bus task is live and holds a clone of the state receiver.
        assert_eq!(
            state_tx.receiver_count(),
            1,
            "bus task holds the source receiver"
        );
        // Drop the consumer with NO further change: its mpsc Receiver is gone, so `tx.closed()`
        // resolves and the task must return on its own (not wait for an event).
        drop(w);
        // Poll until the task has returned (and thus dropped its state_rx). Bounded: a real leak
        // never reaches 0 and fails by timing out under the suite cap. yield_now lets the task run.
        while state_tx.receiver_count() != 0 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            state_tx.receiver_count(),
            0,
            "bus task must reclaim (drop its source receiver) once the consumer is gone"
        );
    }

    /// A running-node consent URL (`MapResponse.PopBrowserURL`, via the de-thrashed browser cell)
    /// streams as a standalone `browse_to_url` event — no `state`, no `net_map`.
    #[tokio::test]
    async fn running_node_browser_url_streams_standalone() {
        // INITIAL_STATE snapshot is the barrier proving the task is in its streaming loop.
        let (_s, _p, browser_tx, _sd, mut w) = harness(
            NotifyWatchOpt::INITIAL_STATE,
            DeviceState::Running,
            Vec::new(),
        );
        let snap = w.next().await.expect("initial snapshot");
        assert_eq!(snap.state, Some(DeviceState::Running));
        assert_eq!(
            snap.browse_to_url, None,
            "running-node URL is not front-loaded"
        );
        // Control pushes a consent URL mid-session (the producer sends Some on a new URL).
        browser_tx.send_replace(Some(consent_url()));
        let n = w.next().await.expect("browse-to-url event");
        assert_eq!(n.browse_to_url, Some(consent_url()));
        assert_eq!(n.state, None);
        assert_eq!(n.net_map, None);
    }

    /// The running-node consent URL is NOT front-loaded into the initial snapshot even when present
    /// at subscribe time (Go replays only the registration `b.authURL`, never `PopBrowserURL`). The
    /// sticky value is reachable via the pull API, not the bus snapshot.
    #[tokio::test]
    async fn running_node_browser_url_not_in_initial_snapshot() {
        let (state_tx, state_rx) = watch::channel(DeviceState::Running);
        let (peer_tx, peer_rx) = watch::channel(Vec::new());
        // Browser cell already holds a URL at subscribe time.
        let (browser_tx, browser_rx) = watch::channel(Some(consent_url()));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (tx, rx) = mpsc::channel(NOTIFY_BUFFER);
        tokio::spawn(run_bus(
            NotifyWatchOpt::INITIAL_STATE | NotifyWatchOpt::INITIAL_NETMAP,
            state_rx,
            peer_rx,
            browser_rx,
            shutdown_rx,
            tx,
        ));
        let mut w = IpnBusWatcher { rx };
        let snap = w.next().await.expect("initial snapshot");
        // The snapshot carries state + net_map (masked) but NOT the pre-existing browser URL.
        assert_eq!(snap.state, Some(DeviceState::Running));
        assert_eq!(snap.net_map, Some(Vec::new()));
        assert_eq!(
            snap.browse_to_url, None,
            "pre-existing running-node URL must not be front-loaded"
        );
        // It only arrives once it CHANGES post-subscribe.
        let next = consent_url();
        let mut next2 = next.clone();
        next2.set_path("/consent2");
        browser_tx.send_replace(Some(next2.clone()));
        let n = w.next().await.expect("browser-url change after subscribe");
        assert_eq!(n.browse_to_url, Some(next2));
        drop((state_tx, peer_tx, shutdown_tx));
    }

    /// Two distinct consent URLs in sequence stream as two `browse_to_url` events.
    #[tokio::test]
    async fn sequential_browser_urls_stream_each() {
        let (_s, _p, browser_tx, _sd, mut w) = harness(
            NotifyWatchOpt::INITIAL_STATE,
            DeviceState::Running,
            Vec::new(),
        );
        let _snap = w.next().await.expect("snapshot barrier");
        let url_a = consent_url();
        let mut url_b = consent_url();
        url_b.set_path("/consent-b");
        browser_tx.send_replace(Some(url_a.clone()));
        assert_eq!(
            w.next().await.expect("first url").browse_to_url,
            Some(url_a)
        );
        browser_tx.send_replace(Some(url_b.clone()));
        assert_eq!(
            w.next().await.expect("second url").browse_to_url,
            Some(url_b)
        );
    }

    /// A browser-URL change and a state change arrive as TWO distinct single-field events (the new
    /// browser arm doesn't coalesce into, or clobber, a concurrent state transition). Companion to
    /// `streamed_events_are_per_source_not_coalesced` (state+peer), for the browser+state pair.
    #[tokio::test]
    async fn browser_url_and_state_change_interleave() {
        let (state_tx, _p, browser_tx, _sd, mut w) = harness(
            NotifyWatchOpt::INITIAL_STATE,
            DeviceState::Running,
            Vec::new(),
        );
        let _snap = w.next().await.expect("snapshot barrier");
        browser_tx.send_replace(Some(consent_url()));
        state_tx.send_replace(DeviceState::Expired);
        let a = w.next().await.expect("first event");
        let b = w.next().await.expect("second event");
        for n in [&a, &b] {
            assert!(
                n.state.is_some() ^ n.browse_to_url.is_some(),
                "each streamed event carries exactly one of state / browse_to_url, got {n:?}"
            );
            assert_eq!(n.net_map, None);
        }
        assert!(
            a.browse_to_url.is_some() || b.browse_to_url.is_some(),
            "a browse_to_url event arrived"
        );
        assert!(
            a.state.is_some() || b.state.is_some(),
            "a state event arrived"
        );
    }
}
