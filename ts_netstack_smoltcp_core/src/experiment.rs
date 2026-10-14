//! Opt-in data-path experiments, switched by environment variables.
//!
//! Every experiment is off unless its variable is exactly `1`, on every platform. None of them is
//! in Go's reference implementation, and none has been measured against the default build, so the
//! default build keeps the behaviour Go has.

/// Kernel receive batching (`recvmmsg`, or `recvmsg_x` on Apple), deferred netstack ingress wakes
/// and a per-poll netstack receive budget.
pub const RX_BATCH: &str = "TS_EXPERIMENT_RX_BATCH";
/// Coalesced reads and host writes in the exit-node TCP splice.
pub const SPLICE_COALESCE: &str = "TS_EXPERIMENT_SPLICE_COALESCE";
/// Replay only the blocked socket commands whose socket woke, with a 50 ms safety sweep.
pub const TARGETED_REPLAY: &str = "TS_EXPERIMENT_TARGETED_REPLAY";

/// Whether the experiment switched by the environment variable `var` is on (its value is `1`).
///
/// Without the `std` feature there is no environment, and every experiment is off.
pub fn enabled(var: &str) -> bool {
    #[cfg(feature = "std")]
    {
        is_on(std::env::var(var).ok().as_deref())
    }
    #[cfg(not(feature = "std"))]
    {
        let _ = var;
        is_on(None)
    }
}

/// The parse behind [`enabled`]: on only for exactly `1`.
fn is_on(value: Option<&str>) -> bool {
    value == Some("1")
}

#[cfg(test)]
mod tests {
    #[test]
    fn an_experiment_is_off_unless_its_value_is_exactly_one() {
        assert!(!super::is_on(None));
        for off in ["0", "", "true", "yes", "01", " 1"] {
            assert!(
                !super::is_on(Some(off)),
                "{off:?} must leave the experiment off"
            );
        }
        assert!(super::is_on(Some("1")));
    }

    #[test]
    fn an_unset_experiment_is_off() {
        assert!(!super::enabled("TS_EXPERIMENT_NEVER_SET_BY_ANYTHING"));
    }
}
