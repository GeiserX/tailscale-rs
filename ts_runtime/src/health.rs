//! Local health warnings, surfaced to embedders through [`Status::health`](crate::Status::health).
//!
//! A narrow port of Go's `health` package (`health/health.go`): a [`Warnable`] names one condition
//! the node can be unhealthy in, and a [`Tracker`] records which of them are currently raised.
//! Only what a raised warning needs to reach the operator is ported — `SetUnhealthy`,
//! `SetHealthy`, and the legacy `Strings` view that `ipnstate.Status.Health` is built from. Go's
//! args, visibility delays, dependency suppression and change publication are not: no warnable
//! registered here uses any of them.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

/// How urgently a [`Warnable`] should be shown to the user (Go `health.Severity`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Go `health.SeverityLow`.
    Low,
    /// Go `health.SeverityMedium`.
    Medium,
    /// Go `health.SeverityHigh`: a critical error that needs immediate attention.
    High,
}

/// One condition this node can be unhealthy in (Go `health.Warnable`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Warnable {
    /// Identifies the warnable across the whole backend; stable, and what a UI keys on.
    pub code: &'static str,
    /// A short title for any message involving this warnable.
    pub title: &'static str,
    /// How urgently it should be shown.
    pub severity: Severity,
    /// The message shown to the user while the warnable is raised.
    pub text: &'static str,
}

/// Control sent a packet filter granting network access to a peer outside tailnet lock, so every
/// inbound packet is being dropped instead (Go `invalidPacketFilterWarnable` in
/// `ipn/ipnlocal/local.go`).
pub const INVALID_PACKET_FILTER: Warnable = Warnable {
    code: "invalid-packet-filter",
    title: "Invalid packet filter",
    severity: Severity::High,
    text: "The coordination server sent an invalid packet filter permitting traffic to unlocked \
           nodes; rejecting all packets for safety",
};

/// The set of currently raised [`Warnable`]s (Go `health.Tracker`).
///
/// Cheap to clone; every clone shares one set, so an actor raising a warning through its copy of
/// the runtime environment is seen by [`Runtime::status`](crate::Runtime::status).
#[derive(Debug, Clone, Default)]
pub struct Tracker {
    raised: Arc<Mutex<BTreeMap<&'static str, Warnable>>>,
}

impl Tracker {
    /// Raise `w` (Go `Tracker.SetUnhealthy`). Raising an already-raised warnable is a no-op.
    pub fn set_unhealthy(&self, w: &Warnable) {
        self.lock().insert(w.code, *w);
    }

    /// Clear `w` (Go `Tracker.SetHealthy`). Clearing a warnable that is not raised is a no-op.
    pub fn set_healthy(&self, w: &Warnable) {
        self.lock().remove(w.code);
    }

    /// The raised warnables, ordered by code.
    pub fn warnings(&self) -> Vec<Warnable> {
        self.lock().values().copied().collect()
    }

    /// The text of every raised warnable (Go `Tracker.Strings`), ordered by code. Empty means no
    /// known problem.
    pub fn strings(&self) -> Vec<String> {
        self.lock().values().map(|w| w.text.to_owned()).collect()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<&'static str, Warnable>> {
        // The map is only ever inserted into or removed from under the lock, so a panic while it
        // was held cannot have left it half-written.
        self.raised.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raising_and_clearing_a_warnable_round_trips() {
        let tracker = Tracker::default();
        let shared = tracker.clone();
        assert!(tracker.strings().is_empty());

        tracker.set_unhealthy(&INVALID_PACKET_FILTER);
        tracker.set_unhealthy(&INVALID_PACKET_FILTER);
        assert_eq!(shared.warnings(), vec![INVALID_PACKET_FILTER]);
        assert_eq!(
            shared.strings(),
            vec![INVALID_PACKET_FILTER.text.to_owned()]
        );

        tracker.set_healthy(&INVALID_PACKET_FILTER);
        tracker.set_healthy(&INVALID_PACKET_FILTER);
        assert!(shared.strings().is_empty());
    }
}
