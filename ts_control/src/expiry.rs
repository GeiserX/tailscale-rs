//! Node-key expiry enforcement — the port of Go's `expiryManager` (`ipn/ipnlocal/expiry.go`).
//!
//! [`Node::key_expired`](crate::Node::key_expired) only *reports* expiry. This module is what acts
//! on it, and it does the three things upstream's `expiryManager` does:
//!
//! 1. [`ExpiryManager::flag_expired_peer`] — Go `flagExpiredPeers`: mark a peer whose `KeyExpiry`
//!    has passed as [`Node::expired`](crate::Node::expired), clear its endpoints and home DERP, and
//!    break its node key. The peer is deliberately **kept** in the netmap so callers can say *why*
//!    it is unreachable ("peer's node key has expired") instead of "no such peer".
//! 2. [`ExpiryManager::next_peer_expiry`] — Go `nextPeerExpiry`: the soonest *future* expiry across
//!    the peers and the self node, so a caller can arm a timer and re-evaluate when a key actually
//!    expires rather than whenever the next netmap happens to arrive.
//! 3. [`ExpiryManager::on_control_time`] — Go `onControlTime`: remember the delta between the local
//!    clock and `MapResponse.ControlTime`, and make every expiry comparison against the adjusted
//!    time. Without it every comparison silently trusts the local clock.
//!
//! The clock correction is bounded in both directions. A delta smaller than
//! [`MIN_CLOCK_DELTA_SECS`] is stored as zero (control and this node agree closely enough), and a
//! delta-adjusted "now" that
//! lands before [`flag_expired_peers_epoch`] is refused outright — so a control server (or a
//! Headscale) sending a wildly past `ControlTime` cannot expire the whole tailnet.
//!
//! Note that a peer with no expiry at all — `node_key_expiry` is `None`, Go's zero `KeyExpiry`,
//! which is what a tagged node carries — is never expired, however far the clock moves.

use alloc::collections::BTreeMap;

use chrono::{DateTime, TimeDelta, Utc};
use ts_keys::NodePublicKey;

use crate::{Node, node::StableId};

/// The hardcoded epoch a delta-adjusted "now" must not precede — Go `flagExpiredPeersEpoch`
/// (`ipn/ipnlocal/expiry.go`), the approximate time upstream wrote that code (2023-01-10).
///
/// Extra defence in depth: if control sends a `ControlTime` far enough in the past that the
/// adjusted clock lands before this, we refuse to reason about expiry at all rather than expire
/// every peer in the tailnet.
pub const FLAG_EXPIRED_PEERS_EPOCH_UNIX: i64 = 1_673_373_066;

/// [`FLAG_EXPIRED_PEERS_EPOCH_UNIX`] as a timestamp.
///
/// # Panics
/// Never: the constant is a valid Unix second.
#[must_use]
pub fn flag_expired_peers_epoch() -> DateTime<Utc> {
    DateTime::from_timestamp(FLAG_EXPIRED_PEERS_EPOCH_UNIX, 0)
        .expect("FLAG_EXPIRED_PEERS_EPOCH_UNIX is a representable timestamp")
}

/// Below this, the offset between local time and control's `ControlTime` is treated as zero — Go
/// `minClockDelta` (`ipn/ipnlocal/expiry.go`), one minute.
pub const MIN_CLOCK_DELTA_SECS: i64 = 60;

/// How far past a computed next-expiry a caller should aim its timer, so the peer is unambiguously
/// expired by the time the timer runs — Go's `nextExpiry.Sub(now) + 10*time.Second`
/// (`ipn/ipnlocal/local.go`, `setControlClientStatusLocked`).
pub const EXPIRY_TIMER_SLACK_SECS: i64 = 10;

/// The floor a clock-skewed next-expiry is pushed to, so a timer built from it cannot fire
/// immediately — Go's `localNow.Add(30 * time.Second)` in `nextPeerExpiry`.
pub const CLOCK_SKEW_EXPIRY_FLOOR_SECS: i64 = 30;

/// The error a peerAPI dial to an expired peer is refused with — Go
/// `errors.New("peer's node key has expired")` (`ipn/ipnlocal/local.go`).
pub const PEER_KEY_EXPIRED: &str = "peer's node key has expired";

/// The outcome of an expiry pass over one peer — [`ExpiryManager::flag_expired_peer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlaggedPeer {
    /// The rewritten peer, for the caller to re-install in place of the one it passed in.
    pub peer: Node,
    /// Whether this is the *first* pass that found this peer in its new state, and so the one worth
    /// logging.
    ///
    /// Go keeps a `previouslyExpired` set for exactly this: on a full netmap, control restates an
    /// expired peer unflagged every time, so the rewrite has to be redone on every response while
    /// the log line must appear once. `false` means "same episode, already reported".
    pub first_transition: bool,
}

/// Tracks expired peers and the local-to-control clock delta, and mutates peers to reflect expiry.
///
/// Go `ipnlocal.expiryManager`. One instance per node, owned by whatever holds the peer set (here:
/// `ts_runtime`'s peer tracker), and driven from the netmap stream.
#[derive(Debug, Default, Clone)]
pub struct ExpiryManager {
    /// Peers already flagged expired, so a transition is logged (and acted on) once rather than on
    /// every netmap — Go `previouslyExpired`, which maps a stable id to a `bool`.
    ///
    /// This fork stores the peer's **pristine node key** instead of a bare `true`. Upstream can
    /// afford a `bool` because `controlclient` keeps an unmutated peer store and `flagExpiredPeers`
    /// only ever mutates a freshly-derived netmap; here the peer db *is* the store, so breaking the
    /// key in place would be unrecoverable. Remembering it under the same key, with the same
    /// lifetime (dropped the moment the peer is no longer expired), restores upstream's behaviour
    /// when control extends a peer's expiry with a field-level patch that does not restate the key.
    previously_expired: BTreeMap<StableId, NodePublicKey>,

    /// The offset to add to local time to get control's time — Go `clockDelta`, such that
    /// `now() + clock_delta == MapResponse.ControlTime`. Zero until control sends a `ControlTime`
    /// that differs by more than [`MIN_CLOCK_DELTA_SECS`].
    clock_delta: TimeDelta,
}

impl ExpiryManager {
    /// A manager with no known expired peers and no clock correction.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a `MapResponse.ControlTime` — Go `onControlTime`.
    ///
    /// Stores the delta between control's clock and `local_now` when it exceeds
    /// [`MIN_CLOCK_DELTA_SECS`] in either direction, and **clears** it back to zero when it does
    /// not (control and this node agree; a previously-recorded skew has been corrected). Returns
    /// the delta now in effect.
    pub fn on_control_time(
        &mut self,
        control_time: DateTime<Utc>,
        local_now: DateTime<Utc>,
    ) -> TimeDelta {
        let delta = control_time - local_now;
        self.clock_delta = if delta.abs() > TimeDelta::seconds(MIN_CLOCK_DELTA_SECS) {
            delta
        } else {
            TimeDelta::zero()
        };
        self.clock_delta
    }

    /// The stored local-to-control clock offset (Go `clockDelta`). Zero when control's clock is
    /// within [`MIN_CLOCK_DELTA_SECS`] of this node's, or before any `ControlTime` has arrived.
    #[must_use]
    pub fn clock_delta(&self) -> TimeDelta {
        self.clock_delta
    }

    /// Control's estimated current time — Go `LocalBackend.ControlNow`: `local_now` shifted by the
    /// stored [`clock_delta`](Self::clock_delta). Every expiry comparison is made against this, not
    /// against the raw local clock.
    #[must_use]
    pub fn control_now(&self, local_now: DateTime<Utc>) -> DateTime<Utc> {
        local_now + self.clock_delta
    }

    /// Control's estimated current time, or `None` when it lands before
    /// [`flag_expired_peers_epoch`] — the guard both `flagExpiredPeers` and `nextPeerExpiry` apply
    /// before doing anything at all.
    fn usable_control_now(&self, local_now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        let control_now = self.control_now(local_now);
        (control_now >= flag_expired_peers_epoch()).then_some(control_now)
    }

    /// Apply the expiry pass to one peer — the body of Go's `flagExpiredPeers` loop.
    ///
    /// Returns the rewritten peer when it had to be changed, and `None` when nothing changed — so a
    /// caller walking a large peer set clones only the handful of peers it has to re-install and
    /// re-publish. [`FlaggedPeer::first_transition`] separates "this peer just expired" from "this
    /// peer was already expired and control restated it unflagged", which is the difference between
    /// a log line and a silent rewrite.
    ///
    /// On expiry the peer is **flagged, never dropped**: `expired` is set, its underlay endpoints
    /// and home DERP are cleared (control does the same for expired nodes), and its node key is
    /// broken with [`ts_keys::node_public_with_bad_old_prefix`] so nothing can handshake with it.
    /// Keeping the row is the point — a caller that tries to reach the peer can then answer
    /// [`PEER_KEY_EXPIRED`] instead of "no such peer".
    ///
    /// Skipped, returning `None`:
    /// - a peer with no expiry at all (`node_key_expiry` is `None` — a tagged node; Go's zero
    ///   `KeyExpiry`), and a peer whose expiry is still in the future. Either way the peer is *not*
    ///   expired, so a remembered pristine key is put back (see the manager's own docs) and the
    ///   memo dropped, exactly where Go does its `delete(em.previouslyExpired, ...)`.
    /// - a peer already marked [`Node::expired`](crate::Node::expired) — by control, or by an
    ///   earlier pass. Re-flagging would repeat the log and the invalidation on every netmap.
    /// - every peer, when the delta-adjusted clock is before [`flag_expired_peers_epoch`].
    pub fn flag_expired_peer(
        &mut self,
        peer: &Node,
        local_now: DateTime<Utc>,
    ) -> Option<FlaggedPeer> {
        let control_now = self.usable_control_now(local_now)?;

        // Not expired: nothing to flag. Drop any memo we hold for this peer — and if the peer we
        // are holding is the one whose key we broke, put the pristine key back, so a control-sent
        // expiry extension recovers the peer's data path the way it does upstream.
        if peer
            .node_key_expiry
            .is_none_or(|expiry| expiry > control_now)
        {
            let pristine = self.previously_expired.remove(&peer.stable_id)?;
            if peer.node_key != ts_keys::node_public_with_bad_old_prefix(pristine) {
                // The peer has since been restated by control with a key of its own; leave it be.
                return None;
            }
            let mut peer = peer.clone();
            peer.node_key = pristine;
            peer.expired = false;
            return Some(FlaggedPeer {
                peer,
                // The memo is gone, so this direction can only be reported once.
                first_transition: true,
            });
        }

        // Already expired (control said so, or we flagged it on an earlier pass). Re-running the
        // mutation would re-log and re-invalidate on every netmap, so stop here.
        if peer.expired {
            return None;
        }

        // Go's `previouslyExpired` bookkeeping: remember the peer so the transition is reported
        // once, not on every netmap that restates it. This fork remembers the peer's pristine node
        // key rather than a bare `true`, so the break below can be undone — see the field's docs.
        let first_transition = self
            .previously_expired
            .insert(peer.stable_id.clone(), peer.node_key)
            .is_none();

        let mut peer = peer.clone();
        peer.expired = true;
        // Control clears these on an expired node; do it here too, as defence in depth against a
        // control server handing us an expired node that still looks live.
        peer.underlay_addresses.clear();
        peer.derp_region = None;
        // And break the key itself, in case something still tries to talk to the peer.
        peer.node_key = ts_keys::node_public_with_bad_old_prefix(peer.node_key);

        Some(FlaggedPeer {
            peer,
            first_transition,
        })
    }

    /// The soonest *future* key expiry across `peers` and `self_node` — Go `nextPeerExpiry`.
    ///
    /// The result is in **local** time (the caller's clock), so `next - local_now` is directly the
    /// delay to arm a timer for; see [`EXPIRY_TIMER_SLACK_SECS`] for the slack upstream adds on
    /// top. `None` when nothing is due to expire, i.e. every peer is tagged (no expiry), already
    /// expired, or already past its expiry without having been flagged.
    ///
    /// Two guards, both upstream's:
    /// - the delta-adjusted clock must not precede [`flag_expired_peers_epoch`], else `None`.
    /// - the answer is never before `local_now`. A local clock running *fast* relative to control
    ///   would otherwise produce a negative delay and a timer that fires immediately in a loop; in
    ///   that case the answer is floored at `local_now + `[`CLOCK_SKEW_EXPIRY_FLOOR_SECS`].
    #[must_use]
    pub fn next_peer_expiry<'a>(
        &self,
        peers: impl IntoIterator<Item = &'a Node>,
        self_node: Option<&Node>,
        local_now: DateTime<Utc>,
    ) -> Option<DateTime<Utc>> {
        let control_now = self.usable_control_now(local_now)?;

        let mut next: Option<DateTime<Utc>> = None;
        let mut consider = |node: &Node| {
            let Some(expiry) = node.node_key_expiry else {
                return; // tagged node: never expires
            };
            if node.expired || expiry < control_now {
                // Already expired — flagged, or past its expiry for some other reason. Either way
                // there is no future event here and we must not return a time in the past.
                return;
            }
            if next.is_none_or(|soonest| expiry < soonest) {
                next = Some(expiry);
            }
        };

        for peer in peers {
            consider(peer);
        }
        // Fire this timer for our own key expiry too, exactly as Go folds in `nm.SelfNode`.
        if let Some(self_node) = self_node {
            consider(self_node);
        }

        let next = next?;
        if next < local_now {
            // The local clock is ahead of control's: `next` is a real future control-time but a
            // past local time. Push it out so a timer built from it does not fire immediately.
            return Some(local_now + TimeDelta::seconds(CLOCK_SKEW_EXPIRY_FLOOR_SECS));
        }
        Some(next)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec, vec::Vec};

    use chrono::{DateTime, TimeDelta, Utc};
    use ts_keys::NodePublicKey;

    use super::{
        CLOCK_SKEW_EXPIRY_FLOOR_SECS, ExpiryManager, MIN_CLOCK_DELTA_SECS, flag_expired_peers_epoch,
    };
    use crate::{
        Node,
        node::{StableId, tests::test_node},
    };

    /// A well-after-the-epoch "now" so the epoch guard is never the thing under test.
    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000, 0).unwrap()
    }

    fn peer(stable_id: &str, key: u8, expiry: Option<DateTime<Utc>>) -> Node {
        let mut node = test_node();
        node.stable_id = StableId(stable_id.to_string());
        node.node_key = NodePublicKey::from([key; 32]);
        node.node_key_expiry = expiry;
        node.underlay_addresses = vec!["192.0.2.7:41641".parse().unwrap()];
        node.derp_region = Some(ts_derp::RegionId(core::num::NonZeroU32::new(2).unwrap()));
        node
    }

    #[test]
    fn flags_a_peer_whose_expiry_has_passed() {
        let mut em = ExpiryManager::new();
        let original_key = NodePublicKey::from([7u8; 32]);
        let p = peer("nOdE1", 7, Some(now() - TimeDelta::hours(1)));

        let flagged = em.flag_expired_peer(&p, now()).expect("peer is flagged");
        assert!(
            flagged.first_transition,
            "the first pass is the log-worthy one"
        );
        let p = flagged.peer;

        assert!(p.expired);
        assert!(p.underlay_addresses.is_empty());
        assert_eq!(p.derp_region, None);
        assert_eq!(
            p.node_key,
            ts_keys::node_public_with_bad_old_prefix(original_key)
        );
        // The peer is kept, not dropped: its identity is still resolvable so a caller can report
        // *why* it is unreachable.
        assert_eq!(p.stable_id, StableId("nOdE1".to_string()));
    }

    #[test]
    fn does_not_reflag_an_already_expired_peer() {
        let mut em = ExpiryManager::new();
        let p = peer("nOdE1", 7, Some(now() - TimeDelta::hours(1)));

        let flagged = em
            .flag_expired_peer(&p, now())
            .expect("peer is flagged")
            .peer;

        // Second pass over the peer we already rewrote: no change at all, so nothing is
        // re-installed and, in particular, the already-broken key is never broken a second time.
        assert_eq!(em.flag_expired_peer(&flagged, now()), None);

        // Control restating the peer unflagged (every full netmap does) still has to be rewritten,
        // but is no longer a transition, so it is not reported a second time.
        let restated = em
            .flag_expired_peer(&p, now())
            .expect("a restated expired peer is rewritten again");
        assert!(restated.peer.expired);
        assert!(
            !restated.first_transition,
            "the log line appears once per episode, not once per netmap"
        );
    }

    /// A control-sent `Expired` is honoured as-is: we must not stamp a bad prefix over the key
    /// control gave us, and we must not log the transition a second time.
    #[test]
    fn control_sent_expired_is_left_alone() {
        let mut em = ExpiryManager::new();
        let mut p = peer("nOdE1", 7, Some(now() - TimeDelta::hours(1)));
        p.expired = true;

        assert_eq!(em.flag_expired_peer(&p, now()), None);
    }

    /// The negative case the bead calls out: a tagged node has no expiry at all and is never
    /// flagged, however far the clock moves.
    #[test]
    fn a_peer_with_no_expiry_is_never_flagged() {
        let mut em = ExpiryManager::new();
        let p = peer("tAgGeD", 7, None);

        assert_eq!(em.flag_expired_peer(&p, now()), None);
        assert_eq!(
            em.flag_expired_peer(&p, now() + TimeDelta::days(3650)),
            None
        );
        assert!(!p.expired);
        assert_eq!(em.next_peer_expiry([&p], None, now()), None);
    }

    #[test]
    fn a_future_expiry_is_not_flagged() {
        let mut em = ExpiryManager::new();
        let p = peer("nOdE1", 7, Some(now() + TimeDelta::hours(1)));

        assert_eq!(em.flag_expired_peer(&p, now()), None);
    }

    /// Control extending a peer's expiry (e.g. a `PeersChangedPatch` that restates only
    /// `KeyExpiry`) must give the peer its real node key back, not leave it permanently broken.
    #[test]
    fn extending_the_expiry_restores_the_pristine_key() {
        let mut em = ExpiryManager::new();
        let original_key = NodePublicKey::from([7u8; 32]);
        let p = peer("nOdE1", 7, Some(now() - TimeDelta::hours(1)));
        let mut p = em
            .flag_expired_peer(&p, now())
            .expect("peer is flagged")
            .peer;
        assert_ne!(p.node_key, original_key);

        p.node_key_expiry = Some(now() + TimeDelta::days(30));
        let p = em
            .flag_expired_peer(&p, now())
            .expect("peer is un-flagged")
            .peer;

        assert!(!p.expired);
        assert_eq!(p.node_key, original_key);
    }

    /// A delta-adjusted clock before the hardcoded epoch disables the whole subsystem: a control
    /// server sending a wildly past `ControlTime` must not be able to expire the tailnet.
    #[test]
    fn a_vast_backwards_clock_jump_flags_nothing() {
        let mut em = ExpiryManager::new();
        // Control claims it is 2001; the delta drags the adjusted "now" before the epoch.
        let control_time = DateTime::from_timestamp(1_000_000_000, 0).unwrap();
        em.on_control_time(control_time, now());
        assert!(em.control_now(now()) < flag_expired_peers_epoch());

        let p = peer("nOdE1", 7, Some(now() - TimeDelta::hours(1)));
        assert_eq!(em.flag_expired_peer(&p, now()), None);

        let future = peer("nOdE2", 8, Some(now() + TimeDelta::hours(1)));
        assert_eq!(em.next_peer_expiry([&future], None, now()), None);
    }

    #[test]
    fn a_small_control_time_offset_is_ignored() {
        let mut em = ExpiryManager::new();
        let delta = em.on_control_time(now() + TimeDelta::seconds(MIN_CLOCK_DELTA_SECS), now());

        assert_eq!(delta, TimeDelta::zero());
        assert_eq!(em.control_now(now()), now());
    }

    #[test]
    fn a_large_control_time_offset_shifts_every_comparison() {
        let mut em = ExpiryManager::new();
        let skew = TimeDelta::hours(2);
        assert_eq!(em.on_control_time(now() + skew, now()), skew);

        // Local time says the key expires in an hour; control's clock says it went an hour ago.
        let p = peer("nOdE1", 7, Some(now() + TimeDelta::hours(1)));
        let p = em
            .flag_expired_peer(&p, now())
            .expect("expired against control's clock");
        assert!(p.peer.expired);
    }

    /// A later `ControlTime` that agrees with the local clock clears a previously stored skew.
    #[test]
    fn a_corrected_control_time_clears_the_delta() {
        let mut em = ExpiryManager::new();
        em.on_control_time(now() + TimeDelta::hours(2), now());
        assert_ne!(em.clock_delta(), TimeDelta::zero());

        em.on_control_time(now(), now());
        assert_eq!(em.clock_delta(), TimeDelta::zero());
    }

    #[test]
    fn next_peer_expiry_picks_the_soonest_future_expiry() {
        let em = ExpiryManager::new();
        let soon = now() + TimeDelta::minutes(5);
        let peers: Vec<Node> = vec![
            peer("a", 1, Some(now() + TimeDelta::hours(4))),
            peer("b", 2, Some(soon)),
            peer("c", 3, None),
        ];

        assert_eq!(em.next_peer_expiry(peers.iter(), None, now()), Some(soon));
    }

    #[test]
    fn next_peer_expiry_skips_expired_and_past_peers() {
        let em = ExpiryManager::new();
        let mut flagged = peer("a", 1, Some(now() - TimeDelta::hours(1)));
        flagged.expired = true;
        // Past its expiry but never flagged — Go skips this too rather than returning a past time.
        let stale = peer("b", 2, Some(now() - TimeDelta::minutes(1)));

        assert_eq!(
            em.next_peer_expiry([&flagged, &stale], None, now()),
            None,
            "no future event: the answer must not be a time in the past"
        );
    }

    #[test]
    fn next_peer_expiry_folds_in_the_self_node() {
        let em = ExpiryManager::new();
        let self_expiry = now() + TimeDelta::minutes(2);
        let self_node = peer("self", 9, Some(self_expiry));
        let p = peer("a", 1, Some(now() + TimeDelta::hours(4)));

        assert_eq!(
            em.next_peer_expiry([&p], Some(&self_node), now()),
            Some(self_expiry)
        );

        // An already-passed self expiry is skipped, leaving the peer's.
        let expired_self = peer("self", 9, Some(now() - TimeDelta::minutes(2)));
        assert_eq!(
            em.next_peer_expiry([&p], Some(&expired_self), now()),
            p.node_key_expiry
        );
    }

    /// The local clock running fast makes a genuinely-future control-time expiry look past. Go
    /// floors the answer instead of returning a negative delay that spins the timer.
    #[test]
    fn next_peer_expiry_floors_a_clock_skewed_answer() {
        let mut em = ExpiryManager::new();
        // Control is two hours behind us, so an expiry 30 minutes out in control time is 90
        // minutes in our past.
        em.on_control_time(now() - TimeDelta::hours(2), now());
        let p = peer("a", 1, Some(now() - TimeDelta::minutes(90)));

        assert_eq!(
            em.next_peer_expiry([&p], None, now()),
            Some(now() + TimeDelta::seconds(CLOCK_SKEW_EXPIRY_FLOOR_SECS))
        );
    }
}
