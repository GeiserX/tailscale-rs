use crate::{socket::tcp::RttEstimator, time::Instant};

use super::Controller;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Reno {
    cwnd: usize,
    min_cwnd: usize,
    ssthresh: usize,
    rwnd: usize,
    ack_credit: usize,
}

impl Reno {
    pub fn new() -> Self {
        Reno {
            cwnd: 1024 * 2,
            min_cwnd: 1024 * 2,
            ssthresh: usize::MAX,
            rwnd: 64 * 1024,
            ack_credit: 0,
        }
    }
}

impl Controller for Reno {
    fn window(&self) -> usize {
        self.cwnd
    }

    fn on_ack(&mut self, _now: Instant, len: usize, _rtt: &RttEstimator) {
        if len == 0 {
            return;
        }
        if self.cwnd < self.ssthresh {
            self.cwnd = self.cwnd.saturating_add(len.min(self.min_cwnd));
        } else {
            // Congestion avoidance grows by one MSS per window acknowledged,
            // rather than one MSS per ACK (or duplicate ACK).
            self.ack_credit = self.ack_credit.saturating_add(len);
            if self.ack_credit >= self.cwnd {
                self.ack_credit -= self.cwnd;
                self.cwnd = self.cwnd.saturating_add(self.min_cwnd);
            }
        }
        self.cwnd = self.cwnd.min(self.rwnd).max(self.min_cwnd);
    }

    fn on_duplicate_ack(&mut self, _now: Instant) {
        self.ssthresh = (self.cwnd / 2).max(2 * self.min_cwnd);
        self.cwnd = self.ssthresh;
        self.ack_credit = 0;
    }

    fn on_retransmit(&mut self, _now: Instant) {
        self.ssthresh = (self.cwnd / 2).max(2 * self.min_cwnd);
        self.cwnd = self.min_cwnd;
        self.ack_credit = 0;
    }

    fn set_mss(&mut self, mss: usize) {
        // RFC 6928 initial window; do not reset a running connection.
        if self.ssthresh == usize::MAX && self.ack_credit == 0 && self.cwnd == 2048 {
            self.cwnd = (10 * mss).min(14600).max(2 * mss);
        }
        self.min_cwnd = mss;
    }

    fn set_remote_window(&mut self, remote_window: usize) {
        if self.rwnd < remote_window {
            self.rwnd = remote_window;
        }
    }
}

#[cfg(test)]
mod test {
    use crate::time::Instant;

    use super::*;

    #[test]
    fn reno_ack_clock_and_timeout_restart() {
        let now = Instant::from_millis(0);
        let mut reno = Reno::new();
        reno.set_mss(1200);
        assert_eq!(reno.window(), 12000);
        reno.on_duplicate_ack(now);
        assert_eq!(reno.window(), 6000);
        for _ in 0..100 {
            reno.on_ack(now, 0, &RttEstimator::default());
        }
        assert_eq!(reno.window(), 6000);
        for _ in 0..4 {
            reno.on_ack(now, 1200, &RttEstimator::default());
        }
        assert_eq!(reno.window(), 6000);
        reno.on_ack(now, 1200, &RttEstimator::default());
        assert_eq!(reno.window(), 7200);
        reno.on_retransmit(now);
        assert_eq!(reno.window(), 1200);
        assert_eq!(reno.ssthresh, 3600);
        reno.on_ack(now, 1200, &RttEstimator::default());
        assert_eq!(reno.window(), 2400);
    }

    #[test]
    fn test_reno() {
        let remote_window = 64 * 1024;
        let now = Instant::from_millis(0);

        for i in 0..10 {
            for j in 0..9 {
                let mut reno = Reno::new();
                reno.set_mss(1480);

                // Set remote window.
                reno.set_remote_window(remote_window);

                reno.on_ack(now, 4096, &RttEstimator::default());

                let mut n = i;
                for _ in 0..j {
                    n *= i;
                }

                if i & 1 == 0 {
                    reno.on_retransmit(now);
                } else {
                    reno.on_duplicate_ack(now);
                }

                let elapsed = Instant::from_millis(1000);
                reno.on_ack(elapsed, n, &RttEstimator::default());

                let cwnd = reno.window();
                println!("Reno: elapsed = {}, cwnd = {}", elapsed, cwnd);

                assert!(cwnd >= reno.min_cwnd);
                assert!(reno.window() <= remote_window);
            }
        }
    }

    #[test]
    fn reno_min_cwnd() {
        let remote_window = 64 * 1024;
        let now = Instant::from_millis(0);

        let mut reno = Reno::new();
        reno.set_remote_window(remote_window);

        for _ in 0..100 {
            reno.on_retransmit(now);
            assert!(reno.window() >= reno.min_cwnd);
        }
    }

    #[test]
    fn reno_set_rwnd() {
        let mut reno = Reno::new();
        reno.set_remote_window(64 * 1024 * 1024);

        println!("{reno:?}");
    }
}
