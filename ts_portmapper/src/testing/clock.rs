//! A manual lease clock in whole seconds, shared by the fake router (mapping expiry, epoch) and
//! the tests that drive it.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

/// A manually advanced clock, in seconds.
#[derive(Debug, Clone, Default)]
pub struct LeaseClock(Arc<AtomicU64>);

impl LeaseClock {
    /// A clock reading `start` seconds.
    pub fn new(start: u64) -> Self {
        Self(Arc::new(AtomicU64::new(start)))
    }

    /// The current reading.
    pub fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }

    /// Move the clock forward by `secs`.
    pub fn advance(&self, secs: u64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}
