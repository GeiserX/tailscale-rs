//! Retry spacing, renewal and expiry for the lifecycle client: pure arithmetic over instants, so
//! every rule here is unit-tested with a manual clock.
//!
//! Three instants are kept apart on purpose:
//!
//! - [`Schedule::next_attempt_at`]: the earliest time **any** create or renew may start, whatever
//!   the trigger (driver timer, kick, rebind, ReSTUN, `get_cached…`). Failures push it out by a
//!   jittered backoff; router refusals push it further.
//! - [`Lease::renew_after`]: when a healthy mapping should be renewed.
//! - [`Lease::expires_at`]: the end of local trust. After it the mapping is dropped and its endpoint
//!   withdrawn, whether or not anything else happens.
//!
//! [`Lease::router_expiry`] records what the router actually granted, which may be longer than we
//! trust (PCP may grant more than requested).

use std::time::Duration;

use tokio::time::Instant;

use crate::oneshot::lease_deadline;

/// The lifetime requested for every mapping (Go's `pmpMapLifetimeSec` / `pcpMapLifetimeSec`).
pub const REQUESTED_LIFETIME: u32 = 7200;
/// The longest lease trusted locally, whatever the router grants.
pub const MAX_TRUSTED: Duration = Duration::from_secs(7200);
/// Bounds on the renewal point, as a delay after the commit.
pub const MIN_RENEW_DELAY: Duration = Duration::from_secs(10);
/// See [`MIN_RENEW_DELAY`].
pub const MAX_RENEW_DELAY: Duration = Duration::from_secs(3600);
/// Backoff after consecutive failures; the last step is the cap.
pub const BACKOFF_STEPS: [Duration; 6] = [
    Duration::from_secs(10),
    Duration::from_secs(30),
    Duration::from_secs(60),
    Duration::from_secs(120),
    Duration::from_secs(300),
    Duration::from_secs(600),
];
/// The least time between any two attempt starts, even across a network change.
pub const ATTEMPT_FLOOR: Duration = Duration::from_secs(2);
/// How long a "not authorized" refusal holds off the next attempt.
pub const NOT_AUTHORIZED_HOLD: Duration = Duration::from_secs(30 * 60);
/// The longest hold taken from a PCP error lifetime (RFC 6887 §7.4, §11.4).
pub const MAX_ERROR_HOLD: Duration = Duration::from_secs(30 * 60);

/// A mapping's lease, computed once at commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lease {
    /// When the router's reply was committed.
    pub committed_at: Instant,
    /// The lifetime the router granted, in seconds (never 0 for a live mapping).
    pub granted: u32,
    /// `min(granted, MAX_TRUSTED)`.
    pub trusted: Duration,
    /// When to renew: `committed_at + clamp(trusted / 2, 10 s, 3600 s)`.
    pub renew_after: Instant,
    /// When local trust ends: `committed_at + trusted`.
    pub expires_at: Instant,
    /// When the router's grant ends: `committed_at + granted` (the full wire lifetime).
    pub router_expiry: Instant,
}

impl Lease {
    /// The lease for a mapping granted `granted` seconds at `now`.
    pub fn new(now: Instant, granted: u32) -> Self {
        let trusted = Duration::from_secs(u64::from(granted)).min(MAX_TRUSTED);
        let renew_delay = (trusted / 2).clamp(MIN_RENEW_DELAY, MAX_RENEW_DELAY);
        let at = |d: Duration| now.checked_add(d).unwrap_or(now);
        Self {
            committed_at: now,
            granted,
            trusted,
            // A lease shorter than 20 s would renew at or after its own expiry; renewal still
            // starts no later than expiry.
            renew_after: at(renew_delay.min(trusted)),
            expires_at: at(trusted),
            router_expiry: lease_deadline(now, granted),
        }
    }

    /// Whether local trust has ended at `now`.
    pub fn expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }

    /// Whether the mapping is due for renewal at `now`.
    pub fn renew_due(&self, now: Instant) -> bool {
        now >= self.renew_after
    }

    /// The host slept for `by` (or the wall clock jumped forward) and it is now `now`: the
    /// router's clock kept running while [`Instant`] did not, so the renewal point, local trust and
    /// the router's grant all move earlier by `by`. `committed_at` stays: it orders events on the
    /// monotonic clock.
    pub fn age(&mut self, by: Duration, now: Instant) {
        self.renew_after = earlier(self.renew_after, by, now);
        self.expires_at = earlier(self.expires_at, by, now);
        self.router_expiry = earlier(self.router_expiry, by, now);
    }
}

/// `t - by`. When that is not representable it lies before the clock's origin, so before `now`,
/// and `now` stands in for it (every "has it passed" comparison then holds).
pub(crate) fn earlier(t: Instant, by: Duration, now: Instant) -> Instant {
    t.checked_sub(by).unwrap_or(now)
}

/// Why an attempt failed, for spacing the next one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// Timeout, no responder, no services, an OS error or a malformed exchange.
    Transient,
    /// NAT-PMP result 2 or PCP `NOT_AUTHORIZED`: hold off for at least [`NOT_AUTHORIZED_HOLD`].
    NotAuthorized,
    /// Another router refusal; `hold` is a PCP error lifetime, if any.
    Refused {
        /// How long the router says the error stays current.
        hold: Option<Duration>,
    },
}

/// Attempt spacing. See the module docs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Schedule {
    /// The earliest next attempt start, or `None` for "now".
    pub next_attempt_at: Option<Instant>,
    /// When the last attempt started (for the [`ATTEMPT_FLOOR`]).
    pub last_start: Option<Instant>,
    /// Consecutive failures since the last success or network change.
    pub failures: u32,
}

/// The backoff after `n` consecutive failures (`n ≥ 1`), before jitter.
pub fn backoff(n: u32) -> Duration {
    let i = usize::try_from(n.saturating_sub(1)).unwrap_or(usize::MAX);
    BACKOFF_STEPS[i.min(BACKOFF_STEPS.len() - 1)]
}

/// Scale `d` by `jitter`, clamped to the ±20 % band.
pub fn jittered(d: Duration, jitter: f64) -> Duration {
    d.mul_f64(jitter.clamp(0.8, 1.2))
}

impl Schedule {
    /// The earliest instant an attempt may start: `max(next_attempt_at, last_start + floor)`.
    pub fn earliest_start(&self) -> Option<Instant> {
        let floor = self.last_start.map(|t| t + ATTEMPT_FLOOR);
        match (self.next_attempt_at, floor) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        }
    }

    /// Whether an attempt may start at `now`.
    pub fn may_start(&self, now: Instant) -> bool {
        self.earliest_start().is_none_or(|t| now >= t)
    }

    /// Record an attempt start.
    pub fn note_start(&mut self, now: Instant) {
        self.last_start = Some(now);
    }

    /// Record a success: the failure count resets and nothing holds off the next attempt but
    /// the floor.
    pub fn note_success(&mut self) {
        self.failures = 0;
        self.next_attempt_at = None;
    }

    /// Record a failure at `now`; `jitter` is a factor in `[0.8, 1.2]`.
    pub fn note_failure(&mut self, now: Instant, why: Failure, jitter: f64) {
        self.failures = self.failures.saturating_add(1);
        let mut hold = jittered(backoff(self.failures), jitter);
        match why {
            Failure::Transient => {}
            Failure::NotAuthorized => hold = hold.max(NOT_AUTHORIZED_HOLD),
            Failure::Refused { hold: Some(h) } => hold = hold.max(h.min(MAX_ERROR_HOLD)),
            Failure::Refused { hold: None } => {}
        }
        self.next_attempt_at = Some(now.checked_add(hold).unwrap_or(now));
    }

    /// A network change: the failure count and any hold reset, the floor stays.
    pub fn note_network_change(&mut self) {
        self.failures = 0;
        self.next_attempt_at = None;
    }

    /// When the driver should try a renewal: `max(renew_after, earliest_start)`, never a bare
    /// past instant that would make it spin.
    pub fn renewal_due(&self, lease: &Lease) -> Instant {
        self.earliest_start()
            .map_or(lease.renew_after, |t| t.max(lease.renew_after))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn lease_uses_min_of_granted_and_two_hours() {
        let t0 = Instant::now();
        let l = Lease::new(t0, 7200);
        assert_eq!(l.trusted, secs(7200));
        assert_eq!(l.renew_after, t0 + secs(3600));
        assert_eq!(l.expires_at, t0 + secs(7200));
        assert_eq!(l.router_expiry, t0 + secs(7200));

        // Longer than requested: trust stays 2 h, the router's bound is recorded.
        let l = Lease::new(t0, 86_400);
        assert_eq!(l.trusted, secs(7200));
        assert_eq!(l.expires_at, t0 + secs(7200));
        assert_eq!(l.router_expiry, t0 + secs(86_400));

        // Shorter: renew at half, at least 10 s.
        let l = Lease::new(t0, 60);
        assert_eq!(l.renew_after, t0 + secs(30));
        assert_eq!(l.expires_at, t0 + secs(60));
        let l = Lease::new(t0, 12);
        assert_eq!(l.renew_after, t0 + secs(10));
        // Shorter than the 10 s floor: renewal starts at expiry at the latest.
        let l = Lease::new(t0, 4);
        assert_eq!(l.renew_after, t0 + secs(4));
        assert!(l.renew_after <= l.expires_at);
    }

    /// A sleep ages renewal, trust and the router's grant, never the commit instant; an age past
    /// what the clock can represent lands on `now` (expired).
    #[test]
    fn age_moves_every_deadline_but_the_commit() {
        let t0 = Instant::now();
        let mut l = Lease::new(t0, 7200);
        l.age(secs(1800), t0);
        assert_eq!(l.committed_at, t0);
        assert_eq!(l.renew_after, t0 + secs(1800));
        assert_eq!(l.expires_at, t0 + secs(5400));
        assert_eq!(l.router_expiry, t0 + secs(5400));
        let now = t0 + secs(1);
        let mut l = Lease::new(t0, 7200);
        l.age(Duration::MAX, now);
        assert!(l.expired(now) && l.renew_due(now));
    }

    /// Lifetimes 0, 1 and `u32::MAX` never panic.
    #[test]
    fn extreme_lifetimes() {
        let t0 = Instant::now();
        for g in [0, 1, u32::MAX] {
            let l = Lease::new(t0, g);
            assert!(l.renew_after <= l.expires_at);
            assert!(l.expires_at <= l.router_expiry);
        }
        assert!(Lease::new(t0, 0).expired(t0));
    }

    #[test]
    fn backoff_steps_and_cap() {
        let got: Vec<u64> = (1..=8).map(|n| backoff(n).as_secs()).collect();
        assert_eq!(got, [10, 30, 60, 120, 300, 600, 600, 600]);
        assert_eq!(backoff(0).as_secs(), 10);
        assert_eq!(backoff(u32::MAX).as_secs(), 600);
        assert_eq!(jittered(secs(100), 0.0), secs(80));
        assert_eq!(jittered(secs(100), 9.0), secs(120));
    }

    #[test]
    fn floor_applies_across_all_triggers() {
        let t0 = Instant::now();
        let mut s = Schedule::default();
        assert!(s.may_start(t0));
        s.note_start(t0);
        s.note_success();
        assert!(!s.may_start(t0 + secs(1)));
        assert!(s.may_start(t0 + ATTEMPT_FLOOR));
        // A network change resets the backoff but not the floor.
        s.note_failure(t0, Failure::Transient, 1.0);
        s.note_network_change();
        assert!(!s.may_start(t0 + secs(1)));
        assert!(s.may_start(t0 + secs(2)));
    }

    #[test]
    fn failures_back_off_and_refusals_hold_longer() {
        let t0 = Instant::now();
        let mut s = Schedule::default();
        s.note_failure(t0, Failure::Transient, 1.0);
        assert_eq!(s.next_attempt_at, Some(t0 + secs(10)));
        s.note_failure(t0, Failure::Transient, 1.0);
        assert_eq!(s.next_attempt_at, Some(t0 + secs(30)));
        s.note_failure(t0, Failure::NotAuthorized, 1.0);
        assert_eq!(s.next_attempt_at, Some(t0 + NOT_AUTHORIZED_HOLD));

        let mut s = Schedule::default();
        // A PCP error lifetime above the backoff holds, capped at 30 min.
        s.note_failure(
            t0,
            Failure::Refused {
                hold: Some(secs(120)),
            },
            1.0,
        );
        assert_eq!(s.next_attempt_at, Some(t0 + secs(120)));
        s.note_failure(
            t0,
            Failure::Refused {
                hold: Some(secs(86_400)),
            },
            1.0,
        );
        assert_eq!(s.next_attempt_at, Some(t0 + MAX_ERROR_HOLD));
        // A short error lifetime still respects the backoff floor.
        let mut s = Schedule::default();
        s.note_failure(
            t0,
            Failure::Refused {
                hold: Some(secs(1)),
            },
            1.0,
        );
        assert_eq!(s.next_attempt_at, Some(t0 + secs(10)));
        s.note_success();
        assert_eq!((s.failures, s.next_attempt_at), (0, None));
    }

    /// At the schedule level, a failed renewal with a past `renew_after` is spaced by backoff,
    /// however often the driver asks.
    #[test]
    fn past_renew_after_never_spins() {
        let t0 = Instant::now();
        let lease = Lease::new(t0, 60);
        let mut s = Schedule::default();
        let mut now = t0 + secs(30);
        let mut starts = 0;
        // Ask every 100 ms for 10 simulated minutes.
        while now < t0 + secs(630) {
            assert!(s.renewal_due(&lease) >= lease.renew_after);
            if s.may_start(now) {
                starts += 1;
                s.note_start(now);
                s.note_failure(now, Failure::Transient, 1.0);
                assert!(s.renewal_due(&lease) > now);
            }
            now += Duration::from_millis(100);
        }
        // 10 + 30 + 60 + 120 + 300 s fit in 600 s: six starts, not thousands.
        assert_eq!(starts, 6);
    }
}
