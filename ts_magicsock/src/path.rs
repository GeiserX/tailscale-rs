//! Per-peer path state and best-address selection.
//!
//! Mirrors the core of Go magicsock's `endpoint`/`addrSet`: for each peer we track a set of
//! candidate UDP endpoints (learned from the control netmap and from disco `CallMeMaybe`),
//! send disco pings to them, and promote the endpoint that pongs first/lowest-latency to be
//! the peer's "best address". WireGuard data for that peer is then sent to the best address.
//!
//! Selection rules (subset of Go's, sufficient for the known-public-VPS topology):
//! - A path becomes *usable* when we receive a pong for a ping we sent to it.
//! - The best address is the usable path with the lowest measured round-trip latency.
//! - IPv6 wins ties (matches Go), though IPv6 is disabled in our deployment.
//! - A best address is *trusted* until `trust_until`; after that it must be re-confirmed by
//!   a fresh pong or the peer falls back to DERP (the caller's responsibility).

use core::net::SocketAddr;
use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use crate::disco::TxId;

/// How long a confirmed best path is trusted before it must be re-validated by a new pong.
///
/// Matches Go magicsock's `trustUDPAddrDuration` (6.5s).
pub const TRUST_DURATION: Duration = Duration::from_millis(6500);

/// Re-ping the best path once it is within this much of its `trust_until` expiry — *before* trust
/// lapses, not after. Go magicsock re-pings the active best path on a `heartbeatInterval` (3s)
/// cadence so trust is refreshed well inside the 6.5s `trustUDPAddrDuration` and an active direct
/// path never goes dark. With `TRUST_DURATION = 6.5s` a `3.5s` lead means a path is re-pinged once
/// it is ~3s old (= Go's heartbeat), leaving ample room for the global pinger (every
/// `PING_INTERVAL`, 2s in `ts_runtime::direct`) to re-ping and the pong to re-confirm before the
/// old trust window closes. Without this the path was re-pinged only *after* `trust_until` had
/// already passed, so `best_addr` returned `None` for a ping-interval + RTT every trust window and
/// the peer flapped direct↔DERP every ~6s.
const REFRESH_BEFORE_EXPIRY: Duration = Duration::from_millis(3500);

/// A ping with no pong after this long is presumed lost; its in-flight record is pruned so the
/// `in_flight` map cannot grow unbounded for a peer whose paths never confirm (it would otherwise
/// gain an entry per candidate every `PING_INTERVAL`, forever). Mirrors the STUN in-flight TTL
/// discipline. Sized above any realistic RTT and the re-ping cadence.
const PING_TIMEOUT: Duration = Duration::from_secs(5);

/// Where a candidate endpoint came from, which decides how it is reconciled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum CandidateSource {
    /// Advertised by the control netmap. Authoritative and reconciled on every netmap update:
    /// a netmap candidate that control stops advertising is pruned.
    Netmap,
    /// Learned from authenticated disco traffic (an inbound ping's source, or a CallMeMaybe).
    /// Preserved across netmap updates — only dropped when the whole peer leaves the netmap.
    #[default]
    Learned,
}

/// State of a single candidate endpoint for a peer.
#[derive(Debug, Clone, Default)]
struct Candidate {
    /// Round-trip latency from the most recent successful ping/pong, if any.
    latency: Option<Duration>,
    /// How this endpoint was learned (decides reconcile behavior).
    source: CandidateSource,
}

/// A ping we sent and are awaiting a pong for.
#[derive(Debug, Clone, Copy)]
struct InFlight {
    to: SocketAddr,
    sent: Instant,
}

/// Tracks all candidate paths to a single peer and which one is currently best.
#[derive(Debug, Default)]
pub struct PeerPaths {
    candidates: HashMap<SocketAddr, Candidate>,
    in_flight: HashMap<TxId, InFlight>,
    best: Option<SocketAddr>,
    trust_until: Option<Instant>,
}

impl PeerPaths {
    /// Add candidate endpoints from the given source. New endpoints start unconfirmed; existing
    /// ones keep their measured state. A netmap-advertised endpoint upgrades a previously-learned
    /// one to [`CandidateSource::Netmap`] (so control's authority subsumes the learned path), but
    /// a learned endpoint never downgrades a netmap one.
    fn add_candidates(
        &mut self,
        endpoints: impl IntoIterator<Item = SocketAddr>,
        source: CandidateSource,
    ) {
        for ep in endpoints {
            let cand = self.candidates.entry(ep).or_default();
            if source == CandidateSource::Netmap {
                cand.source = CandidateSource::Netmap;
            }
        }
    }

    /// Add candidate endpoints advertised by the control netmap.
    pub fn add_netmap_candidates(&mut self, endpoints: impl IntoIterator<Item = SocketAddr>) {
        self.add_candidates(endpoints, CandidateSource::Netmap);
    }

    /// Add candidate endpoints learned from authenticated disco traffic.
    pub fn add_learned_candidates(&mut self, endpoints: impl IntoIterator<Item = SocketAddr>) {
        self.add_candidates(endpoints, CandidateSource::Learned);
    }

    /// Drop the confirmed best path and its trust, **keeping the candidate set**. Used on a socket
    /// rebind ([`MagicSock::rebind`]): the local NAT mapping changed, so any previously-confirmed
    /// direct `best` is stale and must be re-validated by a fresh pong — but the candidate endpoints
    /// (where the peer *might* be reachable) are still valid and should be re-probed, not forgotten.
    /// The peer fails closed back to DERP (best `None`) until a candidate re-confirms over the new
    /// socket. Mirrors Go magicsock's `resetEndpointStates` on rebind (clears best-addr, keeps
    /// candidates), the in-flight probes are also cleared since they were sent from the old socket.
    pub fn invalidate_best(&mut self) {
        self.best = None;
        self.trust_until = None;
        self.in_flight.clear();
    }

    /// Reconcile the netmap-advertised candidate set to exactly `endpoints`.
    ///
    /// Netmap candidates absent from `endpoints` are removed (control revoked them); endpoints
    /// not yet known are added as netmap candidates. Learned candidates (inbound-ping sources,
    /// CallMeMaybe) are left untouched. If the current best address is pruned, the best path and
    /// its trust are cleared so the peer fails closed back to DERP until a surviving candidate
    /// re-confirms.
    ///
    /// Returns the set of addresses removed, so the socket can prune its reverse `addr -> disco`
    /// attribution map.
    pub fn reconcile_netmap_candidates(
        &mut self,
        endpoints: impl IntoIterator<Item = SocketAddr>,
    ) -> Vec<SocketAddr> {
        let wanted: HashSet<SocketAddr> = endpoints.into_iter().collect();

        let mut removed = Vec::new();
        self.candidates.retain(|addr, cand| {
            let keep = cand.source != CandidateSource::Netmap || wanted.contains(addr);
            if !keep {
                removed.push(*addr);
            }
            keep
        });

        for ep in wanted {
            let cand = self.candidates.entry(ep).or_default();
            cand.source = CandidateSource::Netmap;
        }

        if let Some(best) = self.best
            && !self.candidates.contains_key(&best)
        {
            self.best = None;
            self.trust_until = None;
        }

        // Drop any in-flight pings aimed at removed addresses so a late pong can't resurrect a
        // pruned path.
        let candidates = &self.candidates;
        self.in_flight
            .retain(|_, inflight| candidates.contains_key(&inflight.to));

        removed
    }

    /// All candidate endpoints currently known, for sending disco pings.
    pub fn candidate_addrs(&self) -> Vec<SocketAddr> {
        self.candidates.keys().copied().collect()
    }

    /// Record that we sent a ping with `tx_id` to `to` at time `sent`.
    ///
    /// First prunes any in-flight probe older than [`PING_TIMEOUT`] (presumed lost — its pong will
    /// never arrive, or arrived from the wrong source and was dropped). Without this the map grows
    /// unbounded for a peer whose candidates never pong: it would gain an entry per candidate every
    /// ping cycle, forever. A genuinely-late pong for a pruned tx_id is simply treated as
    /// unsolicited (`note_pong` returns `None`), which is correct — we've already given up on it.
    pub fn note_ping_sent(&mut self, tx_id: TxId, to: SocketAddr, sent: Instant) {
        self.in_flight
            .retain(|_, inflight| sent.saturating_duration_since(inflight.sent) < PING_TIMEOUT);
        self.in_flight.insert(tx_id, InFlight { to, sent });
    }

    /// Record a pong for `tx_id` received from `from`. Returns the measured latency if the tx id
    /// was in flight *and* the pong arrived from the address we pinged.
    ///
    /// The `from == to` check binds the pong to the path it confirms: a pong is only meaningful as
    /// proof that the address we pinged answered, so a pong arriving from a different source (a
    /// peer echoing a tx_id from an address we never probed) must not confirm a path. Without this
    /// a malicious-but-authenticated peer could confirm `best_addr` for an address that never
    /// actually responded. Updates the candidate's latency and recomputes the best address.
    pub fn note_pong(&mut self, tx_id: TxId, from: SocketAddr, now: Instant) -> Option<Duration> {
        let InFlight { to, sent } = self.in_flight.remove(&tx_id)?;
        if to != from {
            // Pong came from an address other than the one we pinged for this tx_id: drop it. The
            // in-flight entry is already consumed, so a replayed/forged tx_id can't be reused.
            return None;
        }
        let latency = now.saturating_duration_since(sent);

        let cand = self.candidates.entry(to).or_default();
        cand.latency = Some(latency);

        self.recompute_best(now);
        Some(latency)
    }

    /// The current best (confirmed, trusted) direct address for this peer, if any.
    ///
    /// Returns `None` once trust expires, which is the signal for the caller to fall back to
    /// DERP — never to dial the host network directly.
    pub fn best_addr(&self, now: Instant) -> Option<SocketAddr> {
        match self.trust_until {
            Some(until) if now <= until => self.best,
            _ => None,
        }
    }

    /// The current best direct address **and its last-measured round-trip latency**, if a trusted
    /// direct path is confirmed. `None` under the same condition as [`best_addr`](Self::best_addr)
    /// (no path / trust expired). The latency is the RTT from the most recent ping/pong that
    /// confirmed this path — up to one probe interval stale, not a fresh on-demand measurement.
    /// Backs the per-peer direct-path latency a status/ping reporter surfaces (Go
    /// `ipnstate.PeerStatus`-style RTT).
    pub fn best_addr_and_latency(&self, now: Instant) -> Option<(SocketAddr, Duration)> {
        let best = self.best_addr(now)?;
        // The best addr is only ever set by `recompute_best` from a candidate that has a measured
        // latency, so this lookup is `Some` whenever `best_addr` is — but resolve it through the map
        // rather than assume, so a future change to `best` selection can't silently desync.
        let latency = self.candidates.get(&best).and_then(|c| c.latency)?;
        Some((best, latency))
    }

    /// Whether the best path warrants a re-ping. Fires once the path is within
    /// [`REFRESH_BEFORE_EXPIRY`] of its `trust_until` — *proactively, before* trust lapses — so a
    /// fresh pong re-confirms the path inside the current trust window and `best_addr` never goes
    /// dark for an active peer (Go magicsock's heartbeat-before-expiry behavior). Always `true` when
    /// there is no trusted path yet (nothing to lose by probing).
    pub fn needs_refresh(&self, now: Instant) -> bool {
        match self.trust_until {
            Some(until) => now + REFRESH_BEFORE_EXPIRY >= until,
            None => true,
        }
    }

    /// Number of in-flight (awaiting-pong) probes. Test-only: pins the `in_flight` prune invariant.
    #[cfg(test)]
    fn in_flight_len(&self) -> usize {
        self.in_flight.len()
    }

    fn recompute_best(&mut self, now: Instant) {
        // Lowest latency wins; IPv6 breaks ties (Go parity). Only confirmed candidates
        // (those with a measured latency) are eligible.
        let best = self
            .candidates
            .iter()
            .filter_map(|(addr, c)| c.latency.map(|l| (*addr, l)))
            .min_by(|(a_addr, a_lat), (b_addr, b_lat)| {
                a_lat
                    .cmp(b_lat)
                    .then_with(|| b_addr.is_ipv6().cmp(&a_addr.is_ipv6()))
            })
            .map(|(addr, _)| addr);

        if let Some(addr) = best {
            self.best = Some(addr);
            self.trust_until = Some(now + TRUST_DURATION);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx(n: u8) -> TxId {
        [n; 12]
    }

    #[test]
    fn pong_confirms_and_trusts_path() {
        let mut p = PeerPaths::default();
        let addr: SocketAddr = "203.0.113.1:41641".parse().unwrap();
        p.add_netmap_candidates([addr]);

        let now = Instant::now();
        assert_eq!(p.best_addr(now), None, "no path before any pong");

        p.note_ping_sent(tx(1), addr, now);
        let lat = p.note_pong(tx(1), addr, now + Duration::from_millis(10));
        assert_eq!(lat, Some(Duration::from_millis(10)));

        let after = now + Duration::from_millis(11);
        assert_eq!(p.best_addr(after), Some(addr), "pong should confirm path");
    }

    /// `best_addr_and_latency` returns the confirmed best addr together with its measured RTT, and
    /// `None` under exactly the same conditions as `best_addr` (no path yet / trust expired).
    #[test]
    fn best_addr_and_latency_reports_rtt() {
        let mut p = PeerPaths::default();
        let addr: SocketAddr = "203.0.113.1:41641".parse().unwrap();
        p.add_netmap_candidates([addr]);

        let now = Instant::now();
        assert_eq!(
            p.best_addr_and_latency(now),
            None,
            "no addr+latency before any pong"
        );

        p.note_ping_sent(tx(1), addr, now);
        p.note_pong(tx(1), addr, now + Duration::from_millis(10));

        let after = now + Duration::from_millis(11);
        assert_eq!(
            p.best_addr_and_latency(after),
            Some((addr, Duration::from_millis(10))),
            "a confirmed path reports its addr and measured RTT"
        );

        // Past the trust window it falls back to None, in lockstep with best_addr.
        let expired = now + TRUST_DURATION + Duration::from_secs(1);
        assert_eq!(p.best_addr(expired), None);
        assert_eq!(
            p.best_addr_and_latency(expired),
            None,
            "expired trust drops addr+latency just like best_addr"
        );
    }

    #[test]
    fn lowest_latency_path_wins() {
        let mut p = PeerPaths::default();
        let slow: SocketAddr = "203.0.113.1:1".parse().unwrap();
        let fast: SocketAddr = "203.0.113.2:2".parse().unwrap();
        p.add_netmap_candidates([slow, fast]);

        let now = Instant::now();
        p.note_ping_sent(tx(1), slow, now);
        p.note_ping_sent(tx(2), fast, now);
        p.note_pong(tx(1), slow, now + Duration::from_millis(50));
        p.note_pong(tx(2), fast, now + Duration::from_millis(5));

        assert_eq!(p.best_addr(now + Duration::from_millis(51)), Some(fast));
    }

    #[test]
    fn trust_expires_and_falls_back() {
        let mut p = PeerPaths::default();
        let addr: SocketAddr = "203.0.113.1:41641".parse().unwrap();
        p.add_netmap_candidates([addr]);

        let now = Instant::now();
        p.note_ping_sent(tx(1), addr, now);
        p.note_pong(tx(1), addr, now);

        assert_eq!(p.best_addr(now + Duration::from_secs(1)), Some(addr));
        // Past the trust window the path is dropped — caller must use DERP, not host route.
        assert_eq!(
            p.best_addr(now + TRUST_DURATION + Duration::from_secs(1)),
            None
        );
        assert!(p.needs_refresh(now + TRUST_DURATION + Duration::from_secs(1)));
    }

    #[test]
    fn reconcile_prunes_revoked_netmap_endpoint_and_clears_best() {
        let mut p = PeerPaths::default();
        let revoked: SocketAddr = "203.0.113.1:41641".parse().unwrap();
        let kept: SocketAddr = "203.0.113.2:41641".parse().unwrap();
        p.add_netmap_candidates([revoked, kept]);

        let now = Instant::now();
        // Confirm the path that is about to be revoked.
        p.note_ping_sent(tx(1), revoked, now);
        p.note_pong(tx(1), revoked, now + Duration::from_millis(5));
        assert_eq!(
            p.best_addr(now + Duration::from_millis(6)),
            Some(revoked),
            "revoked path should be best before reconcile"
        );

        // Control stops advertising `revoked`.
        let removed = p.reconcile_netmap_candidates([kept]);
        assert_eq!(
            removed,
            vec![revoked],
            "revoked endpoint reported as removed"
        );
        assert_eq!(
            p.best_addr(now + Duration::from_millis(7)),
            None,
            "pruning the best path must fail closed to DERP"
        );
        assert_eq!(
            p.candidate_addrs(),
            vec![kept],
            "only kept endpoint remains"
        );
    }

    #[test]
    fn reconcile_preserves_learned_candidates() {
        let mut p = PeerPaths::default();
        let netmap: SocketAddr = "203.0.113.1:41641".parse().unwrap();
        let learned: SocketAddr = "198.51.100.7:55000".parse().unwrap();
        p.add_netmap_candidates([netmap]);
        p.add_learned_candidates([learned]);

        // Control advertises a fresh, disjoint set; the learned path must survive.
        let removed = p.reconcile_netmap_candidates([]);
        assert_eq!(removed, vec![netmap], "only the netmap candidate is pruned");
        assert_eq!(
            p.candidate_addrs(),
            vec![learned],
            "learned candidate survives netmap reconciliation"
        );
    }

    #[test]
    fn unsolicited_pong_is_ignored() {
        let mut p = PeerPaths::default();
        let addr: SocketAddr = "203.0.113.1:41641".parse().unwrap();
        let now = Instant::now();
        // No ping was sent for tx(9): the pong must not confirm anything.
        assert_eq!(p.note_pong(tx(9), addr, now), None);
        assert_eq!(p.best_addr(now), None);
    }

    /// Regression for `tsr-73g`: an active best path is re-pinged *before* its trust lapses, while
    /// `best_addr` is still trusted — so a fresh pong re-confirms it inside the current window and
    /// the path never goes dark. The old code only set `needs_refresh` true *after* `trust_until`
    /// had already passed, causing a direct↔DERP flap every trust window.
    #[test]
    fn refresh_fires_before_trust_lapses_while_still_trusted() {
        let mut p = PeerPaths::default();
        let addr: SocketAddr = "203.0.113.1:41641".parse().unwrap();
        p.add_netmap_candidates([addr]);

        let now = Instant::now();
        p.note_ping_sent(tx(1), addr, now);
        p.note_pong(tx(1), addr, now); // confirmed at `now`, trusted until now + TRUST_DURATION

        // Just inside the refresh lead window (well before expiry): a re-ping is already warranted,
        // yet the path is STILL trusted (best_addr returns it) — the two conditions overlap, which
        // is exactly what prevents the flap.
        let refresh_at = now + TRUST_DURATION - REFRESH_BEFORE_EXPIRY + Duration::from_millis(1);
        assert!(
            p.needs_refresh(refresh_at),
            "re-ping must be warranted before trust lapses"
        );
        assert_eq!(
            p.best_addr(refresh_at),
            Some(addr),
            "path must remain trusted while the proactive re-ping is in flight"
        );

        // Early in the trust window (before the lead): no re-ping yet (don't ping every tick).
        let early = now + Duration::from_millis(100);
        assert!(
            !p.needs_refresh(early),
            "no re-ping early in the trust window"
        );
        assert_eq!(p.best_addr(early), Some(addr));
    }

    /// Regression for `tsr-v6t`: the `in_flight` map prunes probes older than `PING_TIMEOUT` on each
    /// new ping, so it cannot grow unbounded for a peer whose candidates never pong.
    #[test]
    fn in_flight_prunes_presumed_lost_probes() {
        let mut p = PeerPaths::default();
        let addr: SocketAddr = "203.0.113.1:41641".parse().unwrap();

        let now = Instant::now();
        // A stale probe that will never pong.
        p.note_ping_sent(tx(1), addr, now);
        assert_eq!(p.in_flight_len(), 1);

        // A fresh probe sent past the timeout prunes the stale one (map stays bounded at 1, not 2).
        p.note_ping_sent(tx(2), addr, now + PING_TIMEOUT + Duration::from_millis(1));
        assert_eq!(
            p.in_flight_len(),
            1,
            "a probe older than PING_TIMEOUT must be pruned, not accumulated"
        );

        // The pruned tx_id can no longer confirm a path (treated as unsolicited) — correct, we gave up.
        assert_eq!(
            p.note_pong(tx(1), addr, now + PING_TIMEOUT + Duration::from_millis(2)),
            None,
            "a pong for a pruned probe is unsolicited"
        );
    }

    /// A pong that echoes a tx_id we have in flight but arrives from a *different* source address
    /// than the one we pinged must not confirm the path (anti-spoofing: the pong only proves the
    /// pinged address answered). The in-flight entry is still consumed so the tx_id can't be reused.
    #[test]
    fn pong_from_wrong_source_is_ignored() {
        let mut p = PeerPaths::default();
        let pinged: SocketAddr = "203.0.113.1:41641".parse().unwrap();
        let attacker: SocketAddr = "203.0.113.99:41641".parse().unwrap();
        p.add_netmap_candidates([pinged]);

        let now = Instant::now();
        p.note_ping_sent(tx(1), pinged, now);

        // Pong for our tx_id, but from an address we never pinged: rejected.
        assert_eq!(
            p.note_pong(tx(1), attacker, now + Duration::from_millis(5)),
            None
        );
        assert_eq!(
            p.best_addr(now + Duration::from_millis(6)),
            None,
            "a pong from the wrong source must not confirm a path"
        );

        // The tx_id was consumed by the first (rejected) pong, so the legitimate address can no
        // longer be confirmed by replaying that tx_id — the peer must ping afresh.
        assert_eq!(
            p.note_pong(tx(1), pinged, now + Duration::from_millis(7)),
            None
        );
        assert_eq!(p.best_addr(now + Duration::from_millis(8)), None);
    }
}
