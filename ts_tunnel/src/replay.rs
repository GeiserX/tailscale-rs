//! Implementation of the packet replay protection algorithm from RFC 6479.
//!
//! The overall goal of replay protection is to only accept new packets in an established session,
//! and reject attempts at playing back older packets.
//!
//! We could naively do this by tracking the highest packet counter we've seen on a valid packet,
//! and reject all packets presenting an older counter. However, this is overly conservative in
//! the face of packet reordering on the network, wherein a burst of packets may arrive slightly
//! out of order.
//!
//! Precisely tracking all previously seen packet IDs for all time is prohibitively expensive, so
//! practical systems compromise and track both the highest counter seen so far, and a sliding
//! window of the N packets prior to the latest. Packets in that window can be received out
//! of order while still rejecting replays. Packets that fall earlier than the window are rejected
//! unconditionally, on the assumption that sufficiently old packets have all been received or lost
//! permanently.
//!
//! The window can be implemented with a regular bitset, with each bit tracking one packet in the
//! window of recent counters. The downside of the naive implementation is that whenever a newer
//! packet is accepted, sliding the window forward involves doing a bit shift operation on the
//! entire bitset. This is fairly expensive to do at high packet line rates.
//!
//! The first idea of RFC 6479 is that, if we make the window a power of two, we can directly map
//! a counter value to a bit index by masking the higher order bits of the counter. This turns
//! the bitset into a ring buffer, where the bit position of the highest seen counter is the head
//! pointer. As the highest seen counter value increments when receiving packets, the window's head
//! position automatically slides forward.
//!
//! Here's a visual representation of what that looks like in a small 32-bit window:
//!
//! | 0 0 0 1 1 0 1 0 1 0 0 1 1 1 1 1 1 1 0 1 0 1 1 1 1 1 1 1 1 1 1 1 |
//!                   ^     ^ ^
//!                   |     | \
//!                   |     |  Current tail: 144_844
//!                   |     |  Bit index after masking: 12
//!                   |     \
//!                   |      Current head: 144_875
//!                   |      Bit index after masking: 11
//!                   \
//!                    Counter 144_872 has already been received
//!                    Bit index after masking: 8
//!
//! This approach introduces a new issue: when advancing the head of the window, we have to take
//! care to zero out bits that have wrapped around from the window's tail. We want this operation
//! to be cheaper than bit shifting, since that's what we've been trying to avoid this whole time.
//!
//! RFC 6479's second idea is to observe that replay windows usually span several machine words.
//! The window is represented as an array of blocks, for example a `[u64; 8]` for 512 bits total.
//! If we shrink the usable window to leave one of those blocks unused, then the ring's head and
//! tail pointers never occupy the same block.
//!
//! This lets us advance the head pointer very cheaply: whenever the head position crosses over
//! into a new block, we zero that block entirely. This may result in zeroing several consecutive
//! blocks if the head advances by a large amount, or even the entire ring if the head advances
//! more than the window size. Finally, once the appropriate blocks have been zeroed, the bit
//! corresponding to the new highest counter is set.
//!
//! The resulting window after sliding has exactly the same content as in the bit-shift
//! implementation, but the cost of advancing has been reduced to zeroing a few machine words.
//! Similarly, the cost of setting a bit within the window is a clean bit masking operation
//! (because the overall ring size is a power of 2), followed by a bit set operation within a
//! single machine word. The cost of checking an arbitrary counter value consists of a few
//! comparisons to check if the counter is before or after the current window, and as mask+bit test
//! for counters within the window.

use std::fmt::Debug;

/// A packet replay tracker.
///
/// In the abstract, the tracker rejects previously seen counter values. However, to
/// do this perfectly would require a large amount of storage. Instead, the tracker assumes
/// that counter values are seen mostly in ascending order, and only explicitly tracks seen
/// counter values in a short window behind the latest seen value.
///
/// Values that fall before this window are unconditionally rejected; values larger than any seen
/// so far are unconditionally accepted (and advance the tracker's sliding window); values that
/// fall within the window are tracked explicitly with a bitset, to ensure they are accepted once
/// only.
pub struct ReplayWindow {
    // nonce counter value of the end of the sliding window
    last: u64,
    blocks: [u64; ReplayWindow::N_BLOCKS as usize],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        // `#[derive(Default)]` can't be used here: the std `Default` impl for `[T; N]` is provided
        // by macro only up to length 32, and the 128-block ring (Go parity) exceeds that. Hand-write
        // the obvious zero-init. A fresh window has seen nothing: `last = 0` and every block clear.
        Self {
            last: 0,
            blocks: [0; Self::N_BLOCKS as usize],
        }
    }
}

impl Debug for ReplayWindow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        struct BlockFormatter<'b>(&'b [u64]);

        impl<'b> Debug for BlockFormatter<'b> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                for b in self.0 {
                    write!(f, "{:08b} ", b.reverse_bits())?;
                }

                Ok(())
            }
        }

        f.debug_struct("ReplayWindow")
            .field("last", &self.last)
            .field("bits", &BlockFormatter(&self.blocks))
            .finish()
    }
}

impl ReplayWindow {
    /// Total bits in the ring, matching wireguard-go `replay/replay.go`:
    /// `ringBlocks = 1 << 7 = 128` blocks of `blockBits = 1 << 6 = 64` bits, so `128 * 64 = 8192`.
    /// One block is held back as the unused gap (so [`WINDOW_SIZE`] is `(128 - 1) * 64 = 8128`),
    /// which is what lets the head advance by zeroing whole blocks without aliasing a still-live
    /// counter. The prior 256-bit ring gave only a 192-counter window — spec-legal, but it rejects
    /// legitimately-reordered packets more than 192 behind the head, far tighter than the
    /// 8128-counter tolerance Go and the kernel allow, which bites on fast/bursty links.
    const TOTAL_BITS: u64 = 8192;
    const N_BLOCKS: u64 = Self::TOTAL_BITS / u64::BITS as u64;
    const BIT_IDX_BITMASK: u64 = (u64::BITS - 1) as u64;
    const BIT_IDX_SHIFT: u32 = u64::BITS.ilog2();
    const BLOCK_IDX_BITMASK: u64 = Self::N_BLOCKS - 1;

    pub const WINDOW_SIZE: u64 = (Self::N_BLOCKS - 1) * u64::BITS as u64;

    /// The oldest counter still acceptable given the current head ([`last`](Self::last)).
    ///
    /// Matches wireguard-go `ValidateCounter`, which rejects a counter only when
    /// `last - counter > windowSize` (strict `>`). So a counter exactly `WINDOW_SIZE` behind the
    /// head is still accepted, and `smallest_valid == last - WINDOW_SIZE` (NOT `WINDOW_SIZE - 1`,
    /// which would be one counter tighter than Go — a prior off-by-one this corrects). The held-back
    /// block guarantees no aliasing even at this deepest-accepted distance.
    fn smallest_valid(&self) -> u64 {
        self.last.saturating_sub(Self::WINDOW_SIZE)
    }

    fn block_idx_unbounded(&self, counter: u64) -> u64 {
        counter >> Self::BIT_IDX_SHIFT
    }

    fn bit_idx(&self, counter: u64) -> u64 {
        counter & Self::BIT_IDX_BITMASK
    }

    fn block_idx_and_bit_mask(&self, counter: u64) -> (usize, u64) {
        let block_idx = self.block_idx_unbounded(counter) & Self::BLOCK_IDX_BITMASK;
        (block_idx as usize, 1 << self.bit_idx(counter))
    }

    /// Report whether counter is a new value that can be processed.
    ///
    /// Does not update the replay window state, so should be called prior to doing
    /// expensive processing. After processing, you must call `ReplayWindow::set` to
    /// update the replay window state.
    pub fn check(&self, counter: u64) -> bool {
        if counter > self.last {
            return true;
        }
        if counter < self.smallest_valid() {
            return false;
        }
        let (block_idx, bit_mask) = self.block_idx_and_bit_mask(counter);
        self.blocks[block_idx] & bit_mask == 0
    }

    /// Update the replay window to mark the given counter as seen and accepted
    ///
    /// # Panics
    ///
    /// If [`ReplayWindow::check(counter)`] is false.
    pub fn set(&mut self, counter: u64) {
        if counter < self.smallest_valid() {
            panic!(
                "invalid set: counter {} is older than smallest valid {}",
                counter,
                self.smallest_valid()
            );
        }
        if counter > self.last {
            let cur_block = self.block_idx_unbounded(self.last);
            let new_block = self.block_idx_unbounded(counter);
            let delta = new_block - cur_block;
            if delta >= Self::N_BLOCKS {
                self.blocks = [0; Self::N_BLOCKS as usize];
            } else {
                for i in cur_block..new_block {
                    let idx = (i + 1) & Self::BLOCK_IDX_BITMASK;
                    self.blocks[idx as usize] = 0;
                }
            }
            self.last = counter;
        }
        let (block_idx, bit_mask) = self.block_idx_and_bit_mask(counter);
        if self.blocks[block_idx] & bit_mask != 0 {
            panic!(
                "invalid set: counter {} was already set previously",
                counter
            );
        }
        self.blocks[block_idx] |= bit_mask;
    }

    #[cfg(test)]
    fn check_and_set(&mut self, counter: u64) -> bool {
        let accept = self.check(counter);
        if accept {
            self.set(counter);
        }
        accept
    }

    #[cfg(test)]
    fn received_in_window(&self) -> u64 {
        let counters = self.smallest_valid()..self.last + 1;
        // `check(ctr) == false` means the counter has already been seen, i.e. it counts as received.
        counters
            .map(|ctr| if self.check(ctr) { 0 } else { 1 })
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use std::{cmp::max, collections::HashSet};

    use super::*;

    #[test]
    fn just_advance() {
        let mut window = ReplayWindow::default();

        for counter in 0..600 {
            assert!(window.check_and_set(counter));
            assert_eq!(
                window.received_in_window(),
                (counter + 1).clamp(0, ReplayWindow::WINDOW_SIZE)
            );
        }
    }

    #[test]
    fn out_of_order() {
        let mut window = ReplayWindow::default();
        // Expressed relative to WINDOW_SIZE so the scenario holds for any ring size: pick a head
        // past the window so that `head - WINDOW_SIZE` (the deepest still-acceptable counter) and
        // `head - WINDOW_SIZE - 1` (the first too-old counter) both exist as non-negative values.
        let w = ReplayWindow::WINDOW_SIZE;
        let head = w + 100;

        assert!(window.check_and_set(head));
        assert!(!window.check(head)); // replay of the head is rejected
        assert!(window.check(head - w)); // distance exactly WINDOW_SIZE -> still accepted (Go strict >)
        assert!(!window.check(head - w - 1)); // distance WINDOW_SIZE + 1 -> too old
        assert_eq!(window.received_in_window(), 1);
        // The 50 counters [head-100, head-50) arriving newest-first, all within the window.
        for (i, counter) in ((head - 100)..(head - 50)).rev().enumerate() {
            assert!(window.check_and_set(counter));
            assert_eq!(window.received_in_window(), (i + 2) as u64);
        }
        // The 49 counters [head-49, head) filling the remaining gap below the head.
        for (i, counter) in ((head - 49)..head).enumerate() {
            assert!(window.check_and_set(counter));
            assert_eq!(window.received_in_window(), (i + 52) as u64);
        }
    }

    /// Pins the ring geometry to wireguard-go `replay/replay.go`'s values: `ringBlocks = 1 << 7 =
    /// 128` 64-bit blocks (`TOTAL_BITS = 8192`), one block held back, `windowSize = 127 * 64 =
    /// 8128`. `N_BLOCKS`/`WINDOW_SIZE` are derived from `TOTAL_BITS`, so this guards against an
    /// accidental edit to `TOTAL_BITS` or the derivation; the runtime-behaviour parity (the boundary
    /// itself) is proven against Go's own test vectors in [`replay_matches_wireguard_go_vectors`].
    #[test]
    fn window_geometry_matches_wireguard_go() {
        assert_eq!(ReplayWindow::TOTAL_BITS, 8192);
        assert_eq!(ReplayWindow::N_BLOCKS, 128);
        assert_eq!(ReplayWindow::WINDOW_SIZE, 8128);
        // The backing storage is exactly Go's `[128]uint64` (1024 bytes).
        assert_eq!(ReplayWindow::default().blocks.len(), 128);
    }

    /// The reorder tolerance matches wireguard-go `ValidateCounter` exactly: it rejects only when
    /// `last - counter > windowSize` (strict `>`), so a packet exactly `WINDOW_SIZE` behind the head
    /// is still accepted and one `WINDOW_SIZE + 1` behind is rejected as too old. The 256 -> 8192
    /// bump restores Go's 8128-counter tolerance (the old ring rejected anything past 192 behind).
    #[test]
    fn reorder_tolerance_is_exactly_window_size() {
        let w = ReplayWindow::WINDOW_SIZE;
        let head = w + 1_000; // comfortably clear of zero so the tail does not saturate

        let mut window = ReplayWindow::default();
        assert!(window.check_and_set(head));
        // smallest_valid == head - WINDOW_SIZE: the oldest still-acceptable counter (Go's strict >).
        assert!(
            window.check(head - w),
            "distance == WINDOW_SIZE must be accepted (matches Go's strict `>`)"
        );
        assert!(
            !window.check(head - w - 1),
            "distance == WINDOW_SIZE + 1 must be rejected as too old"
        );
    }

    /// Authoritative parity oracle: a direct port of wireguard-go `replay/replay_test.go`
    /// `TestReplay`. `check_and_set` has the same accept-and-advance semantics as Go's
    /// `ValidateCounter`, minus the separate `counter >= limit` (`RejectAfterMessages`) guard, which
    /// in this crate lives on the nonce ceiling in `session.rs` — so we port the pure sliding-window
    /// vectors (Go tests 1..=24 and the reset-and-bulk loops). The decisive ones are the
    /// distance-exactly-`WINDOW_SIZE` cases (Go test 18, bulk 6's `T(0, true)` at head ==
    /// `WINDOW_SIZE`): Go accepts them via its strict `last - counter > windowSize`. They fail under
    /// a `WINDOW_SIZE - 1` boundary, so this test is what pins the boundary to Go's exact value.
    #[test]
    fn replay_matches_wireguard_go_vectors() {
        fn t(window: &mut ReplayWindow, n: u64, expected: bool) {
            assert_eq!(
                window.check_and_set(n),
                expected,
                "ValidateCounter({n}) should be {expected}"
            );
        }

        // T_LIM = windowSize + 1 in Go's test.
        let t_lim = ReplayWindow::WINDOW_SIZE + 1;

        // Linear sequence (Go tests 1..=24); 25..=34 exercise the RejectAfterMessages limit, which
        // is enforced outside the window in this crate, so they are intentionally not ported here.
        let mut w = ReplayWindow::default();
        t(&mut w, 0, true); // 1
        t(&mut w, 1, true); // 2
        t(&mut w, 1, false); // 3
        t(&mut w, 9, true); // 4
        t(&mut w, 8, true); // 5
        t(&mut w, 7, true); // 6
        t(&mut w, 7, false); // 7
        t(&mut w, t_lim, true); // 8
        t(&mut w, t_lim - 1, true); // 9
        t(&mut w, t_lim - 1, false); // 10
        t(&mut w, t_lim - 2, true); // 11
        t(&mut w, 2, true); // 12
        t(&mut w, 2, false); // 13
        t(&mut w, t_lim + 16, true); // 14
        t(&mut w, 3, false); // 15
        t(&mut w, t_lim + 16, false); // 16
        t(&mut w, t_lim * 4, true); // 17
        t(&mut w, t_lim * 4 - (t_lim - 1), true); // 18 — distance == WINDOW_SIZE, accepted
        t(&mut w, 10, false); // 19
        t(&mut w, t_lim * 4 - t_lim, false); // 20 — distance == WINDOW_SIZE + 1, rejected
        t(&mut w, t_lim * 4 - (t_lim + 1), false); // 21
        t(&mut w, t_lim * 4 - (t_lim - 2), true); // 22 — distance == WINDOW_SIZE - 1, accepted
        t(&mut w, t_lim * 4 + 1 - t_lim, false); // 23 — replay of test 18's counter
        t(&mut w, 0, false); // 24 — far too old

        let ws = ReplayWindow::WINDOW_SIZE;

        // Bulk 1: fill 1..=windowSize ascending, then 0 is still in range (head == windowSize).
        let mut w = ReplayWindow::default();
        for i in 1..=ws {
            t(&mut w, i, true);
        }
        t(&mut w, 0, true);
        t(&mut w, 0, false);

        // Bulk 3: fill windowSize+1 down to 1 — the all-descending case that walks the window to its
        // full depth; the final `T(1, true)` sits exactly WINDOW_SIZE behind the head (t_lim).
        let mut w = ReplayWindow::default();
        for i in (1..=(ws + 1)).rev() {
            t(&mut w, i, true);
        }

        // Bulk 5: windowSize..=1 descending, then advance one past the window, then 0 is too old.
        let mut w = ReplayWindow::default();
        for i in (1..=ws).rev() {
            t(&mut w, i, true);
        }
        t(&mut w, ws + 1, true);
        t(&mut w, 0, false);

        // Bulk 6: windowSize..=1 descending (head == windowSize), then 0 is accepted at distance
        // exactly WINDOW_SIZE — the vector that fails under an off-by-one tighter boundary.
        let mut w = ReplayWindow::default();
        for i in (1..=ws).rev() {
            t(&mut w, i, true);
        }
        t(&mut w, 0, true);
        t(&mut w, ws + 1, true);
    }

    proptest::proptest! {
        #[test]
        fn any_order(counters in proptest::collection::vec(0u64..1000, 0..2000)) {
            let mut seen = HashSet::new();
            let mut latest = None;
            let mut window = ReplayWindow::default();
            for counter in counters {
                let accepted = window.check_and_set(counter);
                if accepted {
                    assert!(!seen.contains(&counter));
                    if let Some(latest_ctr) = latest {
                        assert!(counter >= window.smallest_valid());
                        latest = Some(max(latest_ctr, counter))
                    } else {
                        latest = Some(counter);
                    }
                    seen.insert(counter);
                } else {
                    assert!(seen.contains(&counter) || counter < window.smallest_valid());
                }
            }
        }
    }
}
