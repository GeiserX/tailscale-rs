//! Bounded sender SACK scoreboard. Forgetting a range causes redundant retransmission,
//! never premature retirement of transmit data. Only cumulative ACKs free the buffer.
use heapless::Vec;

use crate::wire::TcpSeqNumber;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(super) struct Scoreboard {
    ranges: Vec<(TcpSeqNumber, TcpSeqNumber), 32>,
}

impl Scoreboard {
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    pub fn clear(&mut self) {
        self.ranges.clear();
    }

    pub fn update(&mut self, ack: TcpSeqNumber, sent: TcpSeqNumber, blocks: &[Option<(u32, u32)>]) {
        self.ranges.retain(|&(_, right)| right > ack);
        for (left, _) in &mut self.ranges {
            *left = (*left).max(ack);
        }
        for &(left, right) in blocks.iter().flatten() {
            let mut left = TcpSeqNumber(left as i32);
            let mut right = TcpSeqNumber(right as i32);
            // Ignore DSACK, reversed ranges and claims beyond data actually sent.
            if left <= ack || right <= left || right > sent {
                continue;
            }
            let mut i = 0;
            while i < self.ranges.len() {
                let (start, end) = self.ranges[i];
                if start <= right && left <= end {
                    left = left.min(start);
                    right = right.max(end);
                    self.ranges.swap_remove(i);
                    // A merge can now overlap a range visited earlier.
                    i = 0;
                } else {
                    i += 1;
                }
            }
            let _ = self.ranges.push((left, right));
        }
    }

    pub fn sacked(&self, start: TcpSeqNumber, end: TcpSeqNumber) -> usize {
        self.ranges
            .iter()
            .map(|&(left, right)| {
                let left = left.max(start);
                let right = right.min(end);
                if right > left { right - left } else { 0 }
            })
            .sum()
    }

    /// Next unsacked interval, stopping at the first SACK block or flight end.
    pub fn hole(
        &self,
        mut cursor: TcpSeqNumber,
        end: TcpSeqNumber,
    ) -> Option<(TcpSeqNumber, TcpSeqNumber)> {
        loop {
            let covering = self
                .ranges
                .iter()
                .find(|&&(left, right)| left <= cursor && cursor < right);
            if let Some(&(_, right)) = covering {
                cursor = right;
            } else {
                break;
            }
        }
        if cursor >= end {
            return None;
        }
        let right = self
            .ranges
            .iter()
            .filter_map(|&(left, _)| (left > cursor).then_some(left))
            .fold(end, TcpSeqNumber::min);
        Some((cursor, right))
    }

    /// RFC 6675 IsLost: three discontiguous blocks, or more than two MSS SACKed above.
    pub fn is_lost(&self, seq: TcpSeqNumber, mss: usize) -> bool {
        let mut bytes = 0;
        let mut blocks = 0;
        for &(left, right) in &self.ranges {
            if right > seq {
                bytes += right - left.max(seq);
                blocks += 1;
            }
        }
        blocks >= 3 || bytes > 2 * mss
    }

    /// Estimate Pipe: exclude received bytes and unsent repairs inferred lost.
    /// Repairs below cursor still count until ACKed or SACKed.
    pub fn pipe(
        &self,
        ack: TcpSeqNumber,
        cursor: TcpSeqNumber,
        end: TcpSeqNumber,
        mss: usize,
    ) -> usize {
        let mut pipe = 0;
        let mut next = ack;
        while let Some((left, right)) = self.hole(next, end) {
            if !self.is_lost(left, mss) {
                pipe += right - left;
            }
            let repaired = right.min(cursor);
            if repaired > left {
                pipe += repaired - left;
            }
            next = right;
        }
        pipe
    }
}

#[cfg(test)]
mod test {
    use super::*;
    fn seq(n: u32) -> TcpSeqNumber {
        TcpSeqNumber(n as i32)
    }

    #[test]
    fn merge_trim_and_validate() {
        let mut s = Scoreboard::new();
        s.update(
            seq(100),
            seq(1000),
            &[Some((200, 400)), Some((300, 600)), Some((600, 800))],
        );
        assert_eq!(s.ranges.len(), 1);
        assert_eq!(s.sacked(seq(100), seq(1000)), 600);
        assert_eq!(s.hole(seq(100), seq(1000)), Some((seq(100), seq(200))));
        assert_eq!(s.hole(seq(300), seq(1000)), Some((seq(800), seq(1000))));
        s.update(
            seq(500),
            seq(1000),
            &[Some((100, 200)), Some((800, 700)), Some((900, 1100))],
        );
        assert_eq!(s.sacked(seq(500), seq(1000)), 300);
        s.update(seq(800), seq(1000), &[]);
        assert_eq!(s.sacked(seq(800), seq(1000)), 0);
    }

    #[test]
    fn loss_and_pipe_across_sequence_wrap() {
        let base = seq(u32::MAX - 99);
        let mut s = Scoreboard::new();
        s.update(
            base,
            base + 1000,
            &[Some(((base + 400).0 as u32, (base + 800).0 as u32))],
        );
        assert!(s.is_lost(base, 100));
        assert_eq!(s.pipe(base, base, base + 1000, 100), 200);
        assert_eq!(s.pipe(base, base + 200, base + 1000, 100), 400);
        assert!(!s.is_lost(base + 800, 100));
    }

    #[test]
    fn full_scoreboard_forgets_safely() {
        let mut s = Scoreboard::new();
        for i in 0..64 {
            s.update(seq(0), seq(2000), &[Some((i * 20 + 10, i * 20 + 20))]);
        }
        assert_eq!(s.ranges.len(), 32);
        assert_eq!(s.sacked(seq(0), seq(2000)), 320);
        s.clear();
        assert_eq!(s.hole(seq(0), seq(1000)), Some((seq(0), seq(1000))));
    }
}
