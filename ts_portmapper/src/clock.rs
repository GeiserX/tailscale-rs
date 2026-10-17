//! The time source the lifecycle client schedules against.
//!
//! [`SystemClock`] is the monotonic clock plus the wall clock. Tests use a manual clock (in
//! `testing`) that adds an offset to the real monotonic clock, so lease arithmetic can jump hours
//! while the loopback exchanges still run against real 250 ms deadlines.
//!
//! Neither macOS (`CLOCK_UPTIME_RAW`) nor Linux (`CLOCK_MONOTONIC`) advances [`Instant`] while the
//! host sleeps, so the client compares the wall clock's progress with the monotonic clock's to
//! notice a resume or a wall-clock jump.

use std::time::SystemTime;

use tokio::time::Instant;

/// A monotonic clock and a wall clock.
pub trait Clock: Send + Sync + 'static {
    /// The monotonic time the schedule runs on.
    fn now(&self) -> Instant;

    /// The wall-clock time, only for noticing suspend/resume and clock jumps.
    fn wall(&self) -> SystemTime;

    /// The real monotonic instant that corresponds to `t` on this clock (for arming timers and for
    /// consumers that compare against the real clock).
    fn to_real(&self, t: Instant) -> Instant {
        let now = self.now();
        let real = Instant::now();
        if t >= now {
            real + (t - now)
        } else {
            real.checked_sub(now - t).unwrap_or(real)
        }
    }
}

/// The real clocks.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn wall(&self) -> SystemTime {
        SystemTime::now()
    }

    fn to_real(&self, t: Instant) -> Instant {
        t
    }
}
