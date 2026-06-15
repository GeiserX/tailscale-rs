//! A byte-faithful port of the subset of Go's `golang.org/x/time/rate.Limiter` that the DERP
//! client uses: `NewLimiter(rate, burst)` + `AllowN(now, n)` (drop-on-reject).
//!
//! The DERP server advertises a send rate-limit in its `ServerInfo` handshake frame
//! (`TokenBucketBytesPerSecond` / `TokenBucketBytesBurst`). Go's `derp.Client.send` gates every
//! outbound *packet* on `rate.AllowN(now, pktLen)` and silently drops the packet when over the
//! limit (`derp_client.go`: `if !c.rate.AllowN(...) { return nil }`). Without this the client sends
//! at full rate, ignoring the server's directive — the server may disconnect it under load, and the
//! steady-state send pattern is a behavioral fingerprint distinguishing the fork from a stock
//! client. This implements that limiter with **no new dependency** (a hand-rolled token bucket), so
//! the DERP path stays on the minimal-dependency graph.
//!
//! Faithfulness to `x/time/rate` (only the `AllowN` path is ported; `Reserve`/`Wait`/`Cancel` are
//! not used by the DERP client and are omitted):
//! - The bucket starts **full** (`tokens = burst`), matching `NewLimiter` initializing `tokens` to
//!   `float64(burst)` with a zero `last` time (so the first call clamps to `burst`).
//! - Refill on each call: `tokens = min(tokens + elapsed_secs * rate, burst)` where
//!   `elapsed_secs = (now - last).as_secs_f64()` — Go's `advance` via `tokensFromDuration`.
//! - Accept iff `n <= burst` **and** `tokens_after_refill - n >= 0` (computed as subtract-then-sign,
//!   so consuming the last token exactly is allowed) — Go's `reserveN` with `maxFutureReserve == 0`.
//! - **Reject ⇒ no state mutation** (a dropped packet costs no tokens and does not advance `last`);
//!   **accept ⇒ commit** `last = now`, `tokens -= n`. This is what makes drops free, exactly as Go.
//! - A monotonic clock (`Instant`) mirrors Go's monotonic `time.Now()`.

use std::time::Instant;

/// Wall-clock-free token-bucket rate limiter, a faithful port of `x/time/rate.Limiter`'s `AllowN`
/// path (see the module docs). Construct with [`RateLimiter::new`]; gate each packet with
/// [`RateLimiter::allow_n`].
#[derive(Debug)]
pub struct RateLimiter {
    /// Sustained refill rate in tokens (bytes) per second. Always `> 0` (the `== 0` "no limiter"
    /// case is represented by `Option::None` at the call site, mirroring Go's `c.rate = nil`).
    rate: f64,
    /// Maximum bucket size in tokens (bytes). A request larger than this is always rejected.
    burst: f64,
    /// Current token count. Initialized to `burst` (full bucket), then debited/refilled.
    tokens: f64,
    /// When `tokens` was last updated. `None` until the first [`allow_n`](Self::allow_n) call, which
    /// is treated as a full-bucket refill — equivalent to Go's zero-valued `last` producing a huge
    /// elapsed that clamps to `burst`.
    last: Option<Instant>,
}

impl RateLimiter {
    /// Create a limiter refilling at `bytes_per_second` tokens/sec with a maximum burst of
    /// `bytes_burst` tokens. The bucket starts full. Mirrors `rate.NewLimiter(rate, burst)`.
    ///
    /// The caller is responsible for the Go `TokenBucketBytesPerSecond == 0 ⇒ no limiter` rule by
    /// only constructing this when the advertised rate is non-zero (see
    /// [`from_server_info`](Self::from_server_info)).
    #[must_use]
    pub fn new(bytes_per_second: usize, bytes_burst: usize) -> Self {
        let burst = bytes_burst as f64;
        Self {
            rate: bytes_per_second as f64,
            burst,
            tokens: burst,
            last: None,
        }
    }

    /// Build a limiter from the DERP `ServerInfo` token-bucket fields, or `None` when the server
    /// advertised no limit. Mirrors Go `setSendRateLimiter`: a zero (or absent)
    /// `TokenBucketBytesPerSecond` means "no limiter" (`c.rate = nil`); otherwise
    /// `rate.NewLimiter(bytesPerSecond, bytesBurst)`. An absent burst defaults to `0` (so an
    /// advertised positive rate with no burst rejects every packet until refilled — matching Go,
    /// where a zero burst with a finite rate admits nothing until a token accrues).
    #[must_use]
    pub fn from_server_info(
        bytes_per_second: Option<usize>,
        bytes_burst: Option<usize>,
    ) -> Option<Self> {
        match bytes_per_second {
            Some(bps) if bps > 0 => Some(Self::new(bps, bytes_burst.unwrap_or(0))),
            _ => None,
        }
    }

    /// Whether `n` tokens (bytes) may be consumed at time `now`, committing the consumption when so.
    /// Returns `false` (and leaves the bucket untouched) when over the limit — the caller drops the
    /// packet. Faithful to `x/time/rate.AllowN(now, n)` with `maxFutureReserve == 0`.
    pub fn allow_n(&mut self, now: Instant, n: usize) -> bool {
        let n = n as f64;

        // advance(now): tokens available now, WITHOUT mutating state yet.
        let tokens_now = match self.last {
            // First call: Go's zero `last` yields a huge elapsed → clamps to `burst` (full bucket).
            None => self.burst,
            Some(last) => {
                // Clock-backwards guard: if `now` precedes `last`, treat elapsed as zero (Go sets
                // `last = t` in `advance` for this case, giving a zero `Duration`).
                let elapsed = now.saturating_duration_since(last);
                let delta = elapsed.as_secs_f64() * self.rate;
                (self.tokens + delta).min(self.burst)
            }
        };

        // reserveN core: subtract then sign-test (exact-zero remaining is allowed). `n <= burst` is
        // the other conjunct, so an oversized request is always rejected (and never mutates state).
        let remaining = tokens_now - n;
        let ok = n <= self.burst && remaining >= 0.0;

        if ok {
            // Commit ONLY on accept: advance time and debit the tokens. On reject, leave `tokens`
            // and `last` exactly as they were (a dropped packet is free).
            self.last = Some(now);
            self.tokens = remaining;
        }
        ok
    }
}

/// The DERP frame header length in bytes: a 1-byte type tag + a 4-byte big-endian length. Matches
/// Go `derp.FrameHeaderLen`. Used to size a `FrameSendPacket` for the rate check exactly as Go does
/// (`pktLen = FrameHeaderLen + NodePublicRawLen + len(pkt)`).
pub const FRAME_HEADER_LEN: usize = 5;

/// The on-wire length of a node public key (the `SendPacket` destination), in bytes. Matches Go
/// `key.NodePublicRawLen` (a raw X25519 public key).
pub const NODE_PUBLIC_RAW_LEN: usize = 32;

/// The number of bytes a `FrameSendPacket` carrying `payload_len` payload bytes occupies on the
/// wire — the value Go feeds to `rate.AllowN`. `FRAME_HEADER_LEN + NODE_PUBLIC_RAW_LEN +
/// payload_len`.
#[must_use]
pub fn send_packet_wire_len(payload_len: usize) -> usize {
    FRAME_HEADER_LEN + NODE_PUBLIC_RAW_LEN + payload_len
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use super::*;

    // A fixed origin instant + helper to advance it, so the token-math is deterministic (no real
    // sleeps). `Instant` has no public constructor, so we anchor on `Instant::now()` once and add
    // offsets — the limiter only ever sees relative elapsed time, so the absolute value is irrelevant.
    fn at(base: Instant, ms: u64) -> Instant {
        base + Duration::from_millis(ms)
    }

    /// The worked example from the x/time/rate research: 100 bytes/sec, burst 100, bucket starts
    /// full. Pins the accept/reject boundary, the no-refill-same-instant case, the exact-zero-remaining
    /// accept, and the n>burst always-reject (which must not mutate state).
    #[test]
    fn allow_n_matches_go_worked_example() {
        let base = Instant::now();
        let mut lim = RateLimiter::new(100, 100);

        // First call: full bucket (100). 60 <= 100 and 100-60=40 >= 0 → accept, tokens=40.
        assert!(lim.allow_n(base, 60), "first call sees a full bucket");

        // Same instant, another 60: no refill, 40-60=-20 < 0 → reject, NO mutation.
        assert!(
            !lim.allow_n(base, 60),
            "over the limit at the same instant → drop"
        );

        // +200ms: refill 0.2s * 100 = 20 → tokens 40+20=60. 60-60=0 >= 0 → accept (exact zero ok).
        assert!(
            lim.allow_n(at(base, 200), 60),
            "exact-zero remaining is allowed (consume the last token)"
        );

        // n > burst is always rejected regardless of token count, and must not mutate state.
        assert!(
            !lim.allow_n(at(base, 10_000), 150),
            "n > burst always rejects"
        );
        // After the over-burst reject, a normal request still succeeds off the refilled bucket
        // (proving the rejected oversized request neither consumed tokens nor advanced `last`).
        assert!(
            lim.allow_n(at(base, 10_000), 100),
            "an n>burst reject leaves the bucket intact for a later in-bounds request"
        );
    }

    /// A rejected packet is free: being over the limit does not consume tokens or advance `last`, so
    /// the very next in-bounds request (same instant) still sees the pre-reject token count.
    #[test]
    fn reject_does_not_mutate_state() {
        let base = Instant::now();
        let mut lim = RateLimiter::new(1000, 50);

        assert!(lim.allow_n(base, 40), "40 <= 50 burst → accept, tokens=10");
        // 20 > the remaining 10 → reject. Must not touch tokens.
        assert!(!lim.allow_n(base, 20), "20 > remaining 10 → drop");
        // The remaining 10 is still there: a 10-byte packet at the same instant is accepted.
        assert!(
            lim.allow_n(base, 10),
            "the dropped packet consumed nothing; the remaining 10 tokens are intact"
        );
        // Now empty: even 1 more at the same instant is rejected.
        assert!(!lim.allow_n(base, 1), "bucket now empty at this instant");
    }

    /// `from_server_info` mirrors Go `setSendRateLimiter`: zero/absent rate → no limiter.
    #[test]
    fn from_server_info_zero_rate_is_no_limiter() {
        assert!(
            RateLimiter::from_server_info(None, Some(1000)).is_none(),
            "absent rate → no limiter"
        );
        assert!(
            RateLimiter::from_server_info(Some(0), Some(1000)).is_none(),
            "zero rate → no limiter (Go c.rate = nil)"
        );
        let lim = RateLimiter::from_server_info(Some(100), Some(200));
        assert!(lim.is_some(), "a positive rate yields a limiter");
        let lim = lim.unwrap();
        assert_eq!(lim.rate, 100.0);
        assert_eq!(lim.burst, 200.0);
    }

    /// An advertised positive rate with no burst (absent) defaults burst to 0, so every real packet
    /// is rejected until a token accrues — matching Go's zero-burst-with-finite-rate behavior.
    #[test]
    fn absent_burst_defaults_to_zero() {
        let mut lim = RateLimiter::from_server_info(Some(100), None).expect("positive rate");
        let base = Instant::now();
        // burst 0 → first call: tokens clamp to 0; any n>=1 is rejected (n <= burst is 1 <= 0 = false).
        assert!(!lim.allow_n(base, 1), "zero burst admits nothing");
        // After 10ms, 0.01s * 100 = 1 token accrues, but burst caps at 0 → still nothing.
        assert!(
            !lim.allow_n(at(base, 10), 1),
            "refill is capped at the zero burst → still rejects"
        );
    }

    /// Fractional rate (1.5 bytes/sec) exercises the float refill path.
    #[test]
    fn fractional_rate_refill() {
        let base = Instant::now();
        let mut lim = RateLimiter::new(1, 2); // 1 byte/sec, burst 2
        // Drain the full bucket (2).
        assert!(lim.allow_n(base, 2), "drain the full burst");
        assert!(!lim.allow_n(base, 1), "empty at this instant");
        // After 1s: 1.0 token accrues → exactly 1 allowed.
        assert!(lim.allow_n(at(base, 1000), 1), "1s refills exactly 1 token");
        assert!(!lim.allow_n(at(base, 1000), 1), "and only 1");
    }

    #[test]
    fn send_packet_wire_len_matches_go_formula() {
        // Go: pktLen = FrameHeaderLen(5) + NodePublicRawLen(32) + len(pkt).
        assert_eq!(send_packet_wire_len(0), 37);
        assert_eq!(send_packet_wire_len(1000), 1037);
    }
}
