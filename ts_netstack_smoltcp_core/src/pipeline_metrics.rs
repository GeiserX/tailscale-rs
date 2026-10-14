//! Cumulative process-wide netstack counters, enabled by TS_DEBUG_PIPELINE_METRICS=1.
//! Environment is read once with `std`; builds without `std` leave counters disabled.
use core::sync::atomic::{AtomicUsize, Ordering};

static COUNTERS: [AtomicUsize; 15] = [const { AtomicUsize::new(0) }; 15];

#[derive(Clone, Copy)]
pub(crate) enum Metric {
    ReplayAttempts,
    ReplayCompletions,
    ValidationLookups,
    OrphanSweeps,
    OrphanSocketVisits,
    DirtyHandlesPumped,
    TargetedReplayAttempts,
    TargetedReplayCompletions,
    SafetyNetSweeps,
    SafetyNetAttempts,
    SafetyNetCompletions,
    IoPolls,
    IoReady,
    IngressBudgetHits,
    EgressPasses,
}

/// All netstacks in the process, cumulative since startup. Read deltas over matched windows.
#[derive(Clone, Copy, Debug, Default)]
pub struct Snapshot {
    /// Blocked commands actually executed again (excludes abandoned receives / stale generations).
    pub replay_attempts: u64,
    /// Executed replays returning a terminal response, including errors.
    pub replay_completions: u64,
    /// Registry membership/type and generation lookups, each O(log n).
    pub validation_lookups: u64,
    /// Full orphan passes, bounded to once per 100 ms per stack with TCP sockets.
    pub orphan_sweeps: u64,
    /// Live sockets visited by orphan passes (excludes vacant storage slots).
    pub orphan_socket_visits: u64,
    /// Distinct dirty socket generations pumped (including spurious wakes).
    pub dirty_handles_pumped: u64,
    /// Commands executed from dirty queues.
    pub targeted_replay_attempts: u64,
    /// Dirty-queue replays returning a terminal response.
    pub targeted_replay_completions: u64,
    /// Full targeted-queue passes at the 50 ms maintenance deadline.
    pub safety_net_sweeps: u64,
    /// Commands executed by the safety net after draining dirty queues.
    pub safety_net_attempts: u64,
    /// Terminal safety-net responses: investigate missed wake paths when nonzero.
    pub safety_net_completions: u64,
    /// Async I/O future polls, including polls returning Pending.
    pub io_polls: u64,
    /// Async I/O polls returning Ready.
    pub io_ready: u64,
    /// Receive drains hitting their receive-only limit, even if the queue is then empty.
    pub ingress_budget_hits: u64,
    /// smoltcp egress passes with a transmit-ready device, including passes emitting nothing.
    pub egress_passes: u64,
}

fn from_counts(c: [u64; 15]) -> Snapshot {
    Snapshot {
        replay_attempts: c[0],
        replay_completions: c[1],
        validation_lookups: c[2],
        orphan_sweeps: c[3],
        orphan_socket_visits: c[4],
        dirty_handles_pumped: c[5],
        targeted_replay_attempts: c[6],
        targeted_replay_completions: c[7],
        safety_net_sweeps: c[8],
        safety_net_attempts: c[9],
        safety_net_completions: c[10],
        io_polls: c[11],
        io_ready: c[12],
        ingress_budget_hits: c[13],
        egress_passes: c[14],
    }
}

/// Read without actor messaging. Disabled counters remain zero.
pub fn snapshot() -> Snapshot {
    from_counts(core::array::from_fn(|i| {
        COUNTERS[i].load(Ordering::Relaxed) as u64
    }))
}

/// Cached once per process and copied into each stack, so disabled hot paths only test a bool.
#[cfg(feature = "std")]
fn enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var("TS_DEBUG_PIPELINE_METRICS").as_deref() == Ok("1"))
}
#[cfg(not(feature = "std"))]
fn enabled() -> bool {
    false
}

pub(crate) struct Metrics {
    enabled: bool,
    #[cfg(test)]
    counts: [core::cell::Cell<u64>; 15],
}
impl Metrics {
    pub fn new() -> Self {
        Self {
            enabled: enabled(),
            #[cfg(test)]
            counts: core::array::from_fn(|_| core::cell::Cell::new(0)),
        }
    }
    #[inline]
    pub fn record(&self, metric: Metric, n: usize) {
        let i = metric as usize;
        if self.enabled {
            COUNTERS[i].fetch_add(n, Ordering::Relaxed);
        }
        #[cfg(test)]
        self.counts[i].set(self.counts[i].get() + n as u64);
    }
    #[cfg(test)]
    pub fn counts(&self) -> Snapshot {
        from_counts(core::array::from_fn(|i| self.counts[i].get()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_respects_gate_and_reports_enabled_updates() {
        let metrics = Metrics::new();
        let before = snapshot();
        metrics.record(Metric::ReplayAttempts, 1);
        metrics.record(Metric::ReplayCompletions, 1);
        metrics.record(Metric::ValidationLookups, 2);
        metrics.record(Metric::OrphanSweeps, 1);
        metrics.record(Metric::OrphanSocketVisits, 3);
        for metric in [
            Metric::DirtyHandlesPumped,
            Metric::TargetedReplayAttempts,
            Metric::TargetedReplayCompletions,
            Metric::SafetyNetSweeps,
            Metric::SafetyNetAttempts,
            Metric::SafetyNetCompletions,
            Metric::IoPolls,
            Metric::IoReady,
            Metric::IngressBudgetHits,
            Metric::EgressPasses,
        ] {
            metrics.record(metric, 1);
        }
        let after = snapshot();
        for (before, after) in [
            (before.dirty_handles_pumped, after.dirty_handles_pumped),
            (
                before.targeted_replay_attempts,
                after.targeted_replay_attempts,
            ),
            (
                before.targeted_replay_completions,
                after.targeted_replay_completions,
            ),
            (before.safety_net_sweeps, after.safety_net_sweeps),
            (before.safety_net_attempts, after.safety_net_attempts),
            (before.safety_net_completions, after.safety_net_completions),
            (before.io_polls, after.io_polls),
            (before.io_ready, after.io_ready),
            (before.ingress_budget_hits, after.ingress_budget_hits),
            (before.egress_passes, after.egress_passes),
        ] {
            if metrics.enabled {
                assert!(after > before);
            } else {
                assert_eq!(after, 0);
            }
        }
        if metrics.enabled {
            // Other test threads may also update the process-wide counters.
            assert!(after.replay_attempts > before.replay_attempts);
            assert!(after.replay_completions > before.replay_completions);
            assert!(after.validation_lookups >= before.validation_lookups + 2);
            assert!(after.orphan_sweeps > before.orphan_sweeps);
            assert!(after.orphan_socket_visits >= before.orphan_socket_visits + 3);
        } else {
            assert_eq!(after.replay_attempts, 0);
            assert_eq!(after.replay_completions, 0);
            assert_eq!(after.validation_lookups, 0);
            assert_eq!(after.orphan_sweeps, 0);
            assert_eq!(after.orphan_socket_visits, 0);
        }
    }
}
