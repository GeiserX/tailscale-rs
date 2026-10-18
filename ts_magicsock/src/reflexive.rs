//! Our reflexive (NAT-mapped) addresses: where the outside world sees the bound socket, with how
//! each was learned and when it was last confirmed.
//!
//! Two sources feed it. Active STUN asks a STUN server; a disco pong carries the source address
//! the peer saw our ping arrive from. Go advertises only the first: it keeps a pong's `Src` as
//! per-path reply information (`wgengine/magicsock/endpoint.go` `handlePongConnLocked`,
//! `pongReply.pongSrc`) and never publishes it. This fork also advertises pong observations so a
//! node still learns its public address when no STUN server is reachable. The set therefore keeps
//! each address's provenance, ages entries out like Go's `endpointTracker`
//! (`wgengine/magicsock/endpoint_tracker.go`), and when full lets a new address replace the
//! stalest one, never letting a peer observation displace a STUN result.

use core::net::SocketAddr;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

/// Cap on the number of distinct reflexive addresses we retain.
///
/// A malicious-but-authenticated peer could pong with many spoofed `src` values to inflate the set
/// (each is advertised to control and in every `CallMeMaybe`). A real node sits behind a small
/// number of NAT mappings, so a modest cap bounds the memory and the advertised endpoint set.
pub(crate) const MAX_REFLEXIVE_ADDRS: usize = 16;

/// How long an address stays advertised after it was last observed: Go's
/// `endpointTrackerLifetime` ("slightly longer than a full netcheck period"). STUN re-probes
/// every ~23 s and every solicited pong re-observes its address, so a live mapping never lapses;
/// a mapping the NAT has dropped stops being advertised within this window.
pub(crate) const REFLEXIVE_LIFETIME: Duration = Duration::from_secs(5 * 60 + 10);

/// How a reflexive address was learned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReflexiveSource {
    /// A STUN Binding Response to a request we sent.
    Stun,
    /// The `src` a netmap peer echoed in a pong to our ping.
    PeerPong,
}

#[derive(Clone, Copy, Debug, Default)]
struct Entry {
    /// When STUN last reported this address.
    stun: Option<Instant>,
    /// When a peer's pong last reported this address.
    pong: Option<Instant>,
}

impl Entry {
    fn last_seen(&self) -> Instant {
        // At least one is set: an entry is created by an observation.
        self.stun.max(self.pong).expect("entry has an observation")
    }

    fn is_live(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_seen()) <= REFLEXIVE_LIFETIME
    }

    /// The provenance that keeps this entry: STUN while a STUN observation is live.
    fn source(&self, now: Instant) -> ReflexiveSource {
        match self.stun {
            Some(at) if now.saturating_duration_since(at) <= REFLEXIVE_LIFETIME => {
                ReflexiveSource::Stun
            }
            _ => ReflexiveSource::PeerPong,
        }
    }
}

/// The reflexive addresses of the one bound socket. See the module docs.
#[derive(Debug, Default)]
pub(crate) struct ReflexiveSet {
    entries: HashMap<SocketAddr, Entry>,
}

impl ReflexiveSet {
    /// Record that `source` observed `addr` at `now`. Returns `true` when `addr` is new.
    ///
    /// Expired entries are dropped first. When the set is still full, the stalest peer-only
    /// entry (no live STUN observation) makes room; for a STUN result, failing that, the stalest
    /// STUN entry. A peer observation never replaces an entry with a live STUN observation, so
    /// peers cannot flush what STUN learned.
    pub(crate) fn note(&mut self, addr: SocketAddr, source: ReflexiveSource, now: Instant) -> bool {
        self.entries.retain(|_, e| e.is_live(now));
        if let Some(entry) = self.entries.get_mut(&addr) {
            entry.observe(source, now);
            return false;
        }
        if self.entries.len() >= MAX_REFLEXIVE_ADDRS {
            let stalest = |want: Option<ReflexiveSource>| {
                self.entries
                    .iter()
                    .filter(|(_, e)| want.is_none_or(|w| e.source(now) == w))
                    .min_by_key(|(_, e)| e.last_seen())
                    .map(|(a, _)| *a)
            };
            let victim = match source {
                ReflexiveSource::PeerPong => stalest(Some(ReflexiveSource::PeerPong)),
                ReflexiveSource::Stun => {
                    stalest(Some(ReflexiveSource::PeerPong)).or_else(|| stalest(None))
                }
            };
            let Some(victim) = victim else {
                tracing::debug!(%addr, "reflexive set full of STUN results, ignoring peer observation");
                return false;
            };
            tracing::debug!(%addr, %victim, "reflexive set full, replacing the stalest entry");
            self.entries.remove(&victim);
        }
        let mut entry = Entry::default();
        entry.observe(source, now);
        self.entries.insert(addr, entry);
        true
    }

    /// The addresses still live at `now`, sorted.
    pub(crate) fn live(&self, now: Instant) -> Vec<SocketAddr> {
        let mut live: Vec<SocketAddr> = self
            .entries
            .iter()
            .filter(|(_, e)| e.is_live(now))
            .map(|(a, _)| *a)
            .collect();
        live.sort();
        live
    }

    /// How `addr` is known at `now`, or `None` if it is not live.
    #[cfg(test)]
    pub(crate) fn source(&self, addr: &SocketAddr, now: Instant) -> Option<ReflexiveSource> {
        self.entries
            .get(addr)
            .filter(|e| e.is_live(now))
            .map(|e| e.source(now))
    }

    /// Forget every address (the socket was rebound, so its mappings are gone).
    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }

    /// The number of stored addresses, live or not yet pruned.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no address is stored.
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The stored addresses, in no particular order.
    #[cfg(test)]
    pub(crate) fn iter(&self) -> impl Iterator<Item = &SocketAddr> {
        self.entries.keys()
    }

    /// Test shorthand: record `addr` as a STUN result observed now.
    #[cfg(test)]
    pub(crate) fn insert(&mut self, addr: SocketAddr) -> bool {
        self.note(addr, ReflexiveSource::Stun, Instant::now())
    }
}

impl Entry {
    fn observe(&mut self, source: ReflexiveSource, now: Instant) {
        let slot = match source {
            ReflexiveSource::Stun => &mut self.stun,
            ReflexiveSource::PeerPong => &mut self.pong,
        };
        *slot = Some(slot.map_or(now, |at| at.max(now)));
    }
}
