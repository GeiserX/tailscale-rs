//! A bounded burst pacer at 1.2 * cwnd / smoothed RTT. No heap or per-packet timers.
use crate::time::{Duration, Instant};

#[derive(Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(super) struct Pacer {
    next: Option<Instant>,
    congested: bool,
}

impl Pacer {
    pub fn on_loss(&mut self) {
        self.congested = true;
        self.next = None;
    }

    fn rate_window(window: usize) -> usize {
        window.saturating_add(window / 5)
    }

    fn burst(&self, window: usize, mss: usize) -> usize {
        let burst = (window / 8).max(2 * mss);
        if self.congested {
            burst.min(32 * mss)
        } else {
            burst
        }
    }

    pub fn allowance(&self, now: Instant, window: usize, mss: usize, rtt: u32) -> usize {
        let burst = self.burst(window, mss);
        let ahead = self
            .next
            .filter(|&next| next > now)
            .map_or(0, |next| (next - now).total_micros());
        let scheduled =
            ahead.saturating_mul(Self::rate_window(window) as u64) / (rtt as u64 * 1000);
        let budget = burst.saturating_sub(scheduled.min(burst as u64) as usize);
        if budget >= mss { budget } else { 0 }
    }

    pub fn ready_at(&self, now: Instant, window: usize, mss: usize, rtt: u32) -> Instant {
        let credit = (self.burst(window, mss) - mss) as u64 * rtt as u64 * 1000
            / Self::rate_window(window) as u64;
        self.next
            .map_or(now, |next| (next - Duration::from_micros(credit)).max(now))
    }

    pub fn sent(&mut self, now: Instant, len: usize, window: usize, rtt: u32) {
        let delay = (len as u64 * rtt as u64 * 1000).div_ceil(Self::rate_window(window) as u64);
        self.next = Some(self.next.unwrap_or(now).max(now) + Duration::from_micros(delay));
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn large_future_debt_cannot_wrap_credit_on_32_bit_targets() {
        let p = Pacer {
            next: Some(Instant::from_secs(100)),
            ..Pacer::default()
        };
        assert_eq!(p.allowance(Instant::ZERO, u32::MAX as usize, 1200, 20), 0);
    }

    #[test]
    fn loss_caps_burst_without_capping_uncongested_links() {
        let mut p = Pacer::default();
        let now = Instant::from_millis(0);
        assert_eq!(p.allowance(now, 4 * 1024 * 1024, 1200, 40), 512 * 1024);
        p.on_loss();
        assert_eq!(p.allowance(now, 4 * 1024 * 1024, 1200, 40), 32 * 1200);
    }

    #[test]
    fn bounded_burst_and_refill() {
        let mut p = Pacer::default();
        let now = Instant::from_micros(0);
        assert_eq!(p.allowance(now, 80000, 1000, 20), 10000);
        p.sent(now, 10000, 80000, 20);
        assert_eq!(p.allowance(now, 80000, 1000, 20), 0);
        assert_eq!(p.ready_at(now, 80000, 1000, 20), Instant::from_micros(209));
        assert_eq!(
            p.allowance(Instant::from_micros(209), 80000, 1000, 20),
            1000
        );
        assert_eq!(
            p.allowance(Instant::from_millis(100), 80000, 1000, 20),
            10000
        );
        // Long idle periods cannot accumulate an unbounded burst.
        p.sent(Instant::from_secs(10), 10000, 80000, 20);
        assert_eq!(p.allowance(Instant::from_secs(10), 80000, 1000, 20), 0);
    }
}
