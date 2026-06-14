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

/// Hysteresis for switching the trusted best path to a different confirmed candidate: a challenger
/// must be at least this much faster than the *current* trusted best before we switch to it.
///
/// Mirrors Go magicsock `betterAddr`, which keeps the current best unless the latency improvement
/// clears a band (it treats an improvement below ~1% as not better). Without this, `recompute_best`
/// picked the strict latency minimum on every pong, so with two viable public endpoints to a peer
/// (common once a CallMeMaybe address and a netmap address both confirm) sub-millisecond RTT jitter
/// made `best` ping-pong between them on every pong — churning the WireGuard send 5-tuple
/// (`MagicSock` sends to `best_addr`) and resetting `trust_until` to a different endpoint each time.
/// This is the spatial (which-address) analog of the temporal (when-to-reping) flap that
/// [`REFRESH_BEFORE_EXPIRY`] fixed. The fork is IPv4-public / ring-only with no MTU/Geneve/private-IP
/// scoring, so only Go's latency-percentage branch of `betterAddr` is in scope here.
const BETTER_ADDR_IMPROVEMENT: f64 = 0.01;

/// A ping with no pong after this long is presumed lost; its in-flight record is pruned so the
/// `in_flight` map cannot grow unbounded for a peer whose paths never confirm (it would otherwise
/// gain an entry per candidate every `PING_INTERVAL`, forever). Mirrors the STUN in-flight TTL
/// discipline. Sized above any realistic RTT and the re-ping cadence.
const PING_TIMEOUT: Duration = Duration::from_secs(5);

/// Minimum time between *discovery* pings to a single non-best candidate, matching Go magicsock's
/// `discoPingInterval` (= `tsconst.DefaultPingInterval`, 5s; applied in `sendDiscoPingsLocked` at
/// `endpoint.go`). The global pinger runs every 2s (`ts_runtime::direct::PING_INTERVAL`), but a
/// candidate that is NOT the confirmed best is re-pinged at most once per this interval, so an
/// unconfirmed/rival path is probed on Go's 5s cadence rather than every 2s tick (a fingerprint).
///
/// CRITICAL: this floor applies to discovery only — the confirmed **best** path is exempt and is
/// still re-pinged on the [`REFRESH_BEFORE_EXPIRY`] schedule (Go heartbeats the best addr with no
/// interval floor, `endpoint.go`). Flooring the best would delay its re-ping from ~3s to the 6s tick,
/// leaving < 0.5s before `TRUST_DURATION` lapses — one missed tick would take the path dark, exactly
/// the flap [`REFRESH_BEFORE_EXPIRY`] was added to fix.
const DISCO_PING_INTERVAL: Duration = Duration::from_secs(5);

/// Latency at or below which the confirmed best path is "good enough" that we stop full-pinging the
/// other candidates — Go magicsock `goodEnoughLatency` (5ms), the `wantFullPingLocked` quiet-down.
/// On a good direct path (e.g. same-DC / LAN <5ms — common for the fork's public-VPS topology) this
/// reduces steady-state ping volume to just the best-path refresh, matching a stock client. The best
/// path is still refreshed (so trust never lapses), and the periodic upgrade probe
/// ([`UPGRADE_UDP_DIRECT_INTERVAL`]) still re-discovers a better path.
const GOOD_ENOUGH_LATENCY: Duration = Duration::from_millis(5);

/// Even on a good-enough best path, full-ping every candidate this often to discover a better one —
/// Go magicsock `upgradeUDPDirectInterval` (1 min). This is the escape hatch for the
/// [`GOOD_ENOUGH_LATENCY`] quiet-down: without it, a peer that confirmed a <5ms path would never
/// re-probe its other candidates and could be locked onto a no-longer-optimal path. Bounds the quiet
/// period so path selection stays responsive without per-2s-tick chatter.
const UPGRADE_UDP_DIRECT_INTERVAL: Duration = Duration::from_secs(60);

/// Maximum number of [`CandidateSource::Learned`] candidate endpoints tracked per peer.
///
/// Anti-amplification (the per-peer accumulation bound complementing the per-message
/// [`MAX_INBOUND_CALLMEMAYBE_ENDPOINTS`][crate::disco::MAX_INBOUND_CALLMEMAYBE_ENDPOINTS] cap):
/// learned candidates (from `CallMeMaybe` / inbound-ping sources) persist across netmap reconcile,
/// so without this a peer drip-feeding fresh addresses across many messages could grow this node's
/// disco-ping target set (each emitted from the real host socket) without limit. Sized at 2× the
/// per-message cap: a real peer advertises at most its own reflexive set, itself bounded by
/// `MAX_REFLEXIVE_ADDRS` (16) — so 32 admits roughly two full legitimate advertisements before
/// clamping, while bounding abuse. Netmap candidates are not counted (control-authoritative,
/// already bounded by reconcile).
const MAX_LEARNED_CANDIDATES_PER_PEER: usize = 32;

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
    /// When we last *sent* a discovery ping to this endpoint, if ever. Gates the per-candidate
    /// [`DISCO_PING_INTERVAL`] floor so a non-best candidate is re-probed on Go's 5s cadence rather
    /// than every 2s pinger tick. Stamped at send time (in [`PeerPaths::note_ping_sent`]) — matching
    /// Go's `st.lastPing = now` at ping dispatch — so a candidate whose pong is lost still waits the
    /// full interval before the next probe.
    last_ping: Option<Instant>,
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
    /// When we last full-pinged *every* candidate (the discovery sweep), if ever. Gates the
    /// [`UPGRADE_UDP_DIRECT_INTERVAL`] periodic re-probe that overrides the [`GOOD_ENOUGH_LATENCY`]
    /// quiet-down (Go magicsock's `lastFullPing` feeding `wantFullPingLocked`).
    last_full_ping: Option<Instant>,
}

impl PeerPaths {
    /// Add candidate endpoints from the given source. New endpoints start unconfirmed; existing
    /// ones keep their measured state. A netmap-advertised endpoint upgrades a previously-learned
    /// one to [`CandidateSource::Netmap`] (so control's authority subsumes the learned path), but
    /// a learned endpoint never downgrades a netmap one.
    ///
    /// Anti-amplification: the number of [`CandidateSource::Learned`] candidates a single peer can
    /// accumulate is bounded by [`MAX_LEARNED_CANDIDATES_PER_PEER`]. The per-message cap in
    /// `disco::open` bounds one `CallMeMaybe`, but a peer could otherwise send many of them over
    /// time (each carrying fresh addresses) to grow the learned set without limit — and learned
    /// candidates persist across netmap reconcile, so they'd never be pruned. Once at the cap, *new*
    /// learned endpoints are dropped (existing candidates stay — an established/confirmed path must
    /// not be evicted by a flood of junk). Netmap (control-authoritative) candidates are never
    /// capped: control is trusted and `reconcile_netmap_candidates` already bounds them to the
    /// advertised set.
    /// Returns the addresses that were actually accepted into the candidate set (newly inserted, or
    /// already present) — i.e. *not* the ones dropped at the learned cap. The caller uses this to
    /// keep the socket's reverse `addr -> disco` attribution map in lockstep, so a flood of
    /// over-cap learned addresses can't grow that map with entries the path set never accepted.
    fn add_candidates(
        &mut self,
        endpoints: impl IntoIterator<Item = SocketAddr>,
        source: CandidateSource,
    ) -> Vec<SocketAddr> {
        let mut accepted = Vec::new();
        for ep in endpoints {
            // For learned candidates, refuse to grow the learned set past the cap. Updating an
            // endpoint we already track is always fine (no growth); only a brand-new learned address
            // is gated.
            if source == CandidateSource::Learned
                && !self.candidates.contains_key(&ep)
                && self.learned_candidate_count() >= MAX_LEARNED_CANDIDATES_PER_PEER
            {
                tracing::debug!(
                    %ep,
                    "dropping learned candidate: peer at MAX_LEARNED_CANDIDATES_PER_PEER"
                );
                continue;
            }
            let cand = self.candidates.entry(ep).or_default();
            if source == CandidateSource::Netmap {
                cand.source = CandidateSource::Netmap;
            }
            accepted.push(ep);
        }
        accepted
    }

    /// The number of candidates currently tracked with [`CandidateSource::Learned`].
    fn learned_candidate_count(&self) -> usize {
        self.candidates
            .values()
            .filter(|c| c.source == CandidateSource::Learned)
            .count()
    }

    /// Add candidate endpoints advertised by the control netmap.
    pub fn add_netmap_candidates(&mut self, endpoints: impl IntoIterator<Item = SocketAddr>) {
        self.add_candidates(endpoints, CandidateSource::Netmap);
    }

    /// Add candidate endpoints learned from authenticated disco traffic, returning the addresses
    /// actually accepted (those not dropped at `MAX_LEARNED_CANDIDATES_PER_PEER`). The caller
    /// (`MagicSock::add_peer_endpoints`) inserts only the accepted addresses into the reverse
    /// `addr -> disco` map, keeping it bounded in lockstep with the capped candidate set — so a flood
    /// of over-cap learned addresses can't grow the attribution map with entries the path set
    /// dropped. (Not `#[must_use]`: the lone production caller consumes the return, and the test
    /// seams legitimately ignore it.)
    pub fn add_learned_candidates(
        &mut self,
        endpoints: impl IntoIterator<Item = SocketAddr>,
    ) -> Vec<SocketAddr> {
        self.add_candidates(endpoints, CandidateSource::Learned)
    }

    /// Drop the confirmed best path and its trust, **keeping the candidate set**. Used on a socket
    /// rebind (`MagicSock::rebind`): the local NAT mapping changed, so any previously-confirmed
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

    /// The candidate endpoints to disco-ping this cycle, applying Go magicsock's cadence gates so
    /// the on-wire ping rate matches a stock client instead of pinging every candidate every 2s
    /// tick. `now` is the pinger tick instant. The caller should already have checked
    /// [`needs_refresh`](Self::needs_refresh); this method assumes a ping cycle is warranted and
    /// decides *which* candidates.
    ///
    /// The gates (each only ever *reduces* ping volume, so a path is never starved of confirmation):
    /// - The confirmed **best** path is ALWAYS included (un-floored) — it is the heartbeat refresh
    ///   that keeps trust alive; flooring it would risk the path going dark (see
    ///   [`DISCO_PING_INTERVAL`]).
    /// - A **good-enough** best (latency ≤ [`GOOD_ENOUGH_LATENCY`]) quiets the discovery of the other
    ///   candidates (Go `wantFullPingLocked` → false), UNLESS the periodic
    ///   [`UPGRADE_UDP_DIRECT_INTERVAL`] re-probe is due — in which case all candidates are pinged to
    ///   look for a better path, and `last_full_ping` is stamped.
    /// - Otherwise (no good-enough best yet, or the upgrade is due) every candidate is eligible, but a
    ///   non-best candidate is skipped if it was pinged within [`DISCO_PING_INTERVAL`] (the 5s
    ///   discovery floor).
    ///
    /// Stamps `last_full_ping` whenever it returns the full candidate set, so the upgrade interval is
    /// measured from the last full sweep.
    pub fn candidates_to_ping(&mut self, now: Instant) -> Vec<SocketAddr> {
        let best = self.best_addr(now);
        let best_latency = best.and_then(|b| self.candidates.get(&b).and_then(|c| c.latency));
        let good_enough = best_latency.is_some_and(|l| l <= GOOD_ENOUGH_LATENCY);

        let upgrade_due = match self.last_full_ping {
            Some(t) => now.saturating_duration_since(t) >= UPGRADE_UDP_DIRECT_INTERVAL,
            None => true,
        };

        // Full sweep when we are NOT quieted by a good-enough best, or when the periodic upgrade
        // re-probe is due. In a full sweep every candidate is eligible (subject to the per-candidate
        // discovery floor for the non-best ones); the best is always included regardless.
        let full_sweep = !good_enough || upgrade_due;
        if full_sweep {
            self.last_full_ping = Some(now);
        }

        let mut out = Vec::new();
        for (addr, cand) in &self.candidates {
            let is_best = Some(*addr) == best;
            if is_best {
                // The confirmed best is the heartbeat refresh — always pinged, never floored.
                out.push(*addr);
                continue;
            }
            if !full_sweep {
                // Quieted by a good-enough best and no upgrade due: skip non-best candidates.
                continue;
            }
            // Non-best discovery ping: honor the per-candidate 5s floor.
            let floored = cand
                .last_ping
                .is_some_and(|t| now.saturating_duration_since(t) < DISCO_PING_INTERVAL);
            if !floored {
                out.push(*addr);
            }
        }
        out
    }

    /// Record that we sent a ping with `tx_id` to `to` at time `sent`.
    ///
    /// First prunes any in-flight probe older than `PING_TIMEOUT` (presumed lost — its pong will
    /// never arrive, or arrived from the wrong source and was dropped). Without this the map grows
    /// unbounded for a peer whose candidates never pong: it would gain an entry per candidate every
    /// ping cycle, forever. A genuinely-late pong for a pruned tx_id is simply treated as
    /// unsolicited (`note_pong` returns `None`), which is correct — we've already given up on it.
    pub fn note_ping_sent(&mut self, tx_id: TxId, to: SocketAddr, sent: Instant) {
        self.in_flight
            .retain(|_, inflight| sent.saturating_duration_since(inflight.sent) < PING_TIMEOUT);
        self.in_flight.insert(tx_id, InFlight { to, sent });
        // Stamp the candidate's last-ping time so the per-candidate `DISCO_PING_INTERVAL` discovery
        // floor measures from send (matching Go's `st.lastPing = now`). A ping to an address not yet
        // in the candidate set (shouldn't happen on the discovery path) creates a default entry.
        self.candidates.entry(to).or_default().last_ping = Some(sent);
    }

    /// Record a pong for `tx_id` received from `from`. Returns the measured latency if the tx id
    /// was in flight (a matching, single-use transaction id).
    ///
    /// We confirm the address we **pinged** (`to`), never the pong's UDP source `from` — mirroring
    /// Go magicsock `handlePongConnLocked`, which promotes the pinged `sentPing.to` and uses the
    /// pong source only for logging / peer-attribution, not path selection. The anti-spoof
    /// primitives are the disco-key seal (the frame is opened with an authenticated peer's shared
    /// key before this is reached) plus the single-use 96-bit `tx_id` (consumed on use → no replay);
    /// a source match adds nothing over them, since `best_addr` is keyed on `to` (a candidate *we*
    /// selected from the netmap / CallMeMaybe), not on `from`. Requiring `to == from` would instead
    /// drop legitimate cross-mapping pongs — our own hard-NAT `Stun4LocalPort` guess (the peer
    /// replies from its real mapped port, not the local port we targeted) and asymmetric-NAT reply
    /// routing — forcing those peers onto DERP where Go connects directly. So accept any source for a
    /// matched tx_id and confirm the pinged path. (See tsr-ugm.) Updates the pinged candidate's
    /// latency and recomputes the best address.
    pub fn note_pong(&mut self, tx_id: TxId, from: SocketAddr, now: Instant) -> Option<Duration> {
        // `from` is intentionally not used for path selection (see the doc above): a matched tx_id
        // confirms the address we pinged. Kept in the signature for the caller's recv path, and so
        // the deliberate non-use is documented at the boundary rather than silently dropped.
        let _ = from;
        let InFlight { to, sent } = self.in_flight.remove(&tx_id)?;
        let latency = now.saturating_duration_since(sent);

        let cand = self.candidates.entry(to).or_default();
        cand.latency = Some(latency);

        self.recompute_best(now, to);
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
    /// `REFRESH_BEFORE_EXPIRY` of its `trust_until` — *proactively, before* trust lapses — so a
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

    /// Recompute the best path after a pong confirmed `confirmed` (the address whose latency was
    /// just updated). `confirmed` is used to decide whether a *hold* (keeping the current best
    /// against a near-equal challenger) may also refresh the held best's trust window — see below.
    fn recompute_best(&mut self, now: Instant, confirmed: SocketAddr) {
        // Lowest latency wins; IPv6 breaks ties (Go parity). Only confirmed candidates
        // (those with a measured latency) are eligible.
        let challenger = self
            .candidates
            .iter()
            .filter_map(|(addr, c)| c.latency.map(|l| (*addr, l)))
            .min_by(|(a_addr, a_lat), (b_addr, b_lat)| {
                a_lat
                    .cmp(b_lat)
                    .then_with(|| b_addr.is_ipv6().cmp(&a_addr.is_ipv6()))
            });

        let Some((challenger_addr, challenger_lat)) = challenger else {
            // No confirmed candidate — nothing to trust. Leave `best`/`trust_until` as-is (an
            // expired best is reported as untrusted by `best_addr`; a rebind clears them).
            return;
        };

        // Hysteresis: if the current best is still trusted AND still a confirmed candidate, only
        // switch to a different challenger when it is more than `BETTER_ADDR_IMPROVEMENT` faster
        // (Go `betterAddr`). This stops `best` from flapping between near-equal endpoints on RTT
        // jitter.
        if let (Some(current), Some(until)) = (self.best, self.trust_until)
            && now < until
            && current != challenger_addr
            && let Some(current_lat) = self.candidates.get(&current).and_then(|c| c.latency)
        {
            // Switch only when the challenger is *strictly* more than 1% faster. The
            // `current_lat > ZERO` guard means a (degenerate) 0-latency best is never pinned
            // un-switchably: with a 0 threshold every challenger would otherwise read as "not
            // faster enough" and the best could never be displaced.
            let threshold = current_lat.mul_f64(1.0 - BETTER_ADDR_IMPROVEMENT);
            let challenger_wins = current_lat > Duration::ZERO && challenger_lat < threshold;
            if !challenger_wins {
                // Keep the current best. Only refresh its trust window if the pong that triggered
                // this recompute was *for the best itself* — a pong for a rival proves some path
                // works but does NOT prove the best is still alive, so refreshing on a rival's pong
                // could keep a silently-dead best trusted up to a full `TRUST_DURATION` longer. The
                // best is independently re-pinged every refresh cycle (`send_pings` pings all
                // candidates), so its own pong is what legitimately extends trust here.
                if confirmed == current {
                    self.trust_until = Some(now + TRUST_DURATION);
                }
                return;
            }
        }

        self.best = Some(challenger_addr);
        self.trust_until = Some(now + TRUST_DURATION);
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
    /// than the one we pinged still confirms the **pinged** path — matching Go magicsock, which keys
    /// on `sentPing.to`, not the pong source. The anti-spoof binding is the (authenticated) disco
    /// seal + single-use tx_id, not a source match; and `best_addr` is the address *we* pinged, never
    /// the source. This is exactly the cross-mapping case our hard-NAT `Stun4LocalPort` guess relies
    /// on (the peer replies from its real mapped port, not the local port we targeted): the old
    /// `to == from` drop forced those peers to DERP. (tsr-ugm)
    #[test]
    fn pong_from_different_source_confirms_pinged_path() {
        let mut p = PeerPaths::default();
        // We pinged the peer's hard-NAT local-port guess; the pong egresses its real mapped port —
        // same IP, different port (the common `Stun4LocalPort` traversal shape).
        let pinged: SocketAddr = "203.0.113.1:41641".parse().unwrap();
        let reply_source: SocketAddr = "203.0.113.1:51820".parse().unwrap();
        p.add_netmap_candidates([pinged]);

        let now = Instant::now();
        p.note_ping_sent(tx(1), pinged, now);

        // A matched tx_id from a different source still measures latency and confirms the path.
        let lat = p.note_pong(tx(1), reply_source, now + Duration::from_millis(5));
        assert_eq!(
            lat,
            Some(Duration::from_millis(5)),
            "matched tx_id must confirm regardless of source"
        );
        assert_eq!(
            p.best_addr(now + Duration::from_millis(6)),
            Some(pinged),
            "best_addr must be the address we PINGED, never the pong's source"
        );
    }

    /// The tx_id is the single-use anti-replay token: it is consumed on the first matching pong, so a
    /// second pong with the same tx_id (a replay) finds no in-flight entry and confirms nothing.
    #[test]
    fn pong_tx_id_is_single_use() {
        let mut p = PeerPaths::default();
        let pinged: SocketAddr = "203.0.113.1:41641".parse().unwrap();
        p.add_netmap_candidates([pinged]);

        let now = Instant::now();
        p.note_ping_sent(tx(1), pinged, now);

        // First pong confirms.
        assert!(
            p.note_pong(tx(1), pinged, now + Duration::from_millis(5))
                .is_some()
        );
        // Replaying the same tx_id finds no in-flight entry → None (no second confirmation).
        assert_eq!(
            p.note_pong(tx(1), pinged, now + Duration::from_millis(7)),
            None
        );
    }

    /// Anti-amplification: learned candidates per peer are bounded by
    /// `MAX_LEARNED_CANDIDATES_PER_PEER`. Feeding more (as a peer drip-feeding CallMeMaybes over
    /// time would) does not grow the set past the cap — excess new learned addresses are dropped.
    #[test]
    fn learned_candidates_capped_per_peer() {
        let mut p = PeerPaths::default();
        let over = MAX_LEARNED_CANDIDATES_PER_PEER + 40;
        // Feed in several batches (mimicking repeated CallMeMaybes), each with fresh addresses.
        for i in 0..over {
            let addr: SocketAddr = format!("203.0.113.7:{}", 40000 + i as u16).parse().unwrap();
            p.add_learned_candidates([addr]);
        }
        assert_eq!(
            p.candidate_addrs().len(),
            MAX_LEARNED_CANDIDATES_PER_PEER,
            "learned candidates must be bounded by MAX_LEARNED_CANDIDATES_PER_PEER"
        );
    }

    /// The learned cap must NOT block netmap candidates (control-authoritative): even with the
    /// learned set full, control's advertised endpoints are still installed. Nor does re-adding an
    /// already-tracked learned address count as growth.
    #[test]
    fn learned_cap_does_not_block_netmap_or_dedup() {
        let mut p = PeerPaths::default();
        // Saturate the learned set.
        for i in 0..MAX_LEARNED_CANDIDATES_PER_PEER {
            let addr: SocketAddr = format!("203.0.113.7:{}", 40000 + i as u16).parse().unwrap();
            p.add_learned_candidates([addr]);
        }
        let learned = p.candidate_addrs().len();
        assert_eq!(learned, MAX_LEARNED_CANDIDATES_PER_PEER);

        // Re-adding an existing learned address is a no-op (no growth, not rejected as "new").
        let existing: SocketAddr = "203.0.113.7:40000".parse().unwrap();
        p.add_learned_candidates([existing]);
        assert_eq!(
            p.candidate_addrs().len(),
            learned,
            "re-add must not grow the set"
        );

        // A NEW netmap candidate is still installed despite the full learned set.
        let netmap_ep: SocketAddr = "198.51.100.9:3478".parse().unwrap();
        p.add_netmap_candidates([netmap_ep]);
        assert!(
            p.candidate_addrs().contains(&netmap_ep),
            "netmap (control-authoritative) candidates must not be capped by the learned limit"
        );
    }

    /// Hysteresis: once a best path is confirmed and trusted, a *second* confirmed candidate that is
    /// only marginally faster (within `BETTER_ADDR_IMPROVEMENT`) must NOT steal `best` — otherwise
    /// RTT jitter flaps the WireGuard send 5-tuple between two near-equal public endpoints. Mirrors
    /// Go `betterAddr`.
    #[test]
    fn near_equal_challenger_does_not_steal_trusted_best() {
        let mut p = PeerPaths::default();
        let a: SocketAddr = "203.0.113.1:41641".parse().unwrap();
        let b: SocketAddr = "203.0.113.2:41641".parse().unwrap();
        p.add_netmap_candidates([a, b]);

        let now = Instant::now();
        // `a` confirms first at 10ms → becomes the trusted best.
        p.note_ping_sent(tx(1), a, now);
        p.note_pong(tx(1), a, now + Duration::from_millis(10));
        assert_eq!(p.best_addr(now + Duration::from_millis(11)), Some(a));

        // `b` confirms at 9.95ms — faster, but by <1% → must NOT switch (best stays `a`).
        let t1 = now + Duration::from_millis(20);
        p.note_ping_sent(tx(2), b, t1);
        p.note_pong(tx(2), b, t1 + Duration::from_micros(9_950));
        assert_eq!(
            p.best_addr(t1 + Duration::from_millis(10)),
            Some(a),
            "a near-equal challenger must not steal the trusted best"
        );
    }

    /// The flip side: a challenger that IS decisively faster (clears the band) DOES become the new
    /// best, so the hysteresis doesn't pin a genuinely worse path.
    #[test]
    fn decisively_faster_challenger_takes_best() {
        let mut p = PeerPaths::default();
        let a: SocketAddr = "203.0.113.1:41641".parse().unwrap();
        let b: SocketAddr = "203.0.113.2:41641".parse().unwrap();
        p.add_netmap_candidates([a, b]);

        let now = Instant::now();
        // `a` confirms first at 50ms → trusted best.
        p.note_ping_sent(tx(1), a, now);
        p.note_pong(tx(1), a, now + Duration::from_millis(50));
        assert_eq!(p.best_addr(now + Duration::from_millis(51)), Some(a));

        // `b` confirms at 10ms — far below the 1% band of 50ms → must switch.
        let t1 = now + Duration::from_millis(60);
        p.note_ping_sent(tx(2), b, t1);
        p.note_pong(tx(2), b, t1 + Duration::from_millis(10));
        assert_eq!(
            p.best_addr(t1 + Duration::from_millis(11)),
            Some(b),
            "a decisively faster challenger must take the best path"
        );
    }

    /// A pong for the *current* best (no rival) still refreshes trust — the hysteresis branch must
    /// not accidentally stop the held path from re-confirming and going dark.
    #[test]
    fn pong_for_current_best_refreshes_trust() {
        let mut p = PeerPaths::default();
        let a: SocketAddr = "203.0.113.1:41641".parse().unwrap();
        p.add_netmap_candidates([a]);

        let now = Instant::now();
        p.note_ping_sent(tx(1), a, now);
        p.note_pong(tx(1), a, now + Duration::from_millis(10));

        // Re-ping/re-pong `a` later; trust must extend to the new `now + TRUST_DURATION`.
        let t1 = now + Duration::from_millis(20);
        p.note_ping_sent(tx(2), a, t1);
        p.note_pong(tx(2), a, t1 + Duration::from_millis(10));

        // Just before the SECOND confirmation's trust window closes, the path is still trusted —
        // proving the re-pong refreshed trust (the first window would have closed earlier).
        let near_second_expiry =
            t1 + Duration::from_millis(10) + TRUST_DURATION - Duration::from_millis(1);
        assert_eq!(
            p.best_addr(near_second_expiry),
            Some(a),
            "a re-pong for the current best must refresh its trust window"
        );
    }

    /// When the current best's trust has EXPIRED, the hysteresis hold does not apply: a faster
    /// confirmed candidate is taken immediately (the `now < until` conjunct gates the hold, so an
    /// untrusted best never blocks a switch). Selection is still strict-min over confirmed
    /// candidates, so the faster `b` wins here regardless.
    #[test]
    fn expired_best_does_not_block_switch_to_faster_candidate() {
        let mut p = PeerPaths::default();
        let a: SocketAddr = "203.0.113.1:41641".parse().unwrap();
        let b: SocketAddr = "203.0.113.2:41641".parse().unwrap();
        p.add_netmap_candidates([a, b]);

        let now = Instant::now();
        p.note_ping_sent(tx(1), a, now);
        p.note_pong(tx(1), a, now + Duration::from_millis(10)); // a best @10ms

        // Let a's trust fully lapse, then b confirms at 5ms (faster than a). Even though the
        // improvement is well past the 1% band, this asserts the EXPIRY path specifically: with a
        // untrusted, the hold branch is skipped entirely (not merely overridden by the band).
        let t1 = now + TRUST_DURATION + Duration::from_secs(1);
        p.note_ping_sent(tx(2), b, t1);
        p.note_pong(tx(2), b, t1 + Duration::from_millis(5));
        assert_eq!(
            p.best_addr(t1 + Duration::from_millis(6)),
            Some(b),
            "a faster candidate must win once the prior best's trust has expired"
        );
    }

    /// A near-equal *rival's* pong must NOT refresh the held best's trust window — only a pong for
    /// the best itself does. This stops a silently-dead best from being kept trusted by a rival that
    /// keeps answering within the 1% band. Here `a` is best, then only `b` (a near-equal rival)
    /// keeps ponging; `a`'s trust must still expire on schedule.
    #[test]
    fn rival_pong_does_not_refresh_held_best_trust() {
        let mut p = PeerPaths::default();
        let a: SocketAddr = "203.0.113.1:41641".parse().unwrap();
        let b: SocketAddr = "203.0.113.2:41641".parse().unwrap();
        p.add_netmap_candidates([a, b]);

        let now = Instant::now();
        // a's pong arrives at `a_confirmed`, so a's trust runs until `a_confirmed + TRUST_DURATION`.
        let a_confirmed = now + Duration::from_millis(10);
        p.note_ping_sent(tx(1), a, now);
        p.note_pong(tx(1), a, a_confirmed);

        // A near-equal rival `b` pongs partway through a's window (9.95ms, within the 1% band → hold,
        // and confirmed != current so trust is NOT refreshed).
        let t1 = now + Duration::from_millis(20);
        p.note_ping_sent(tx(2), b, t1);
        p.note_pong(tx(2), b, t1 + Duration::from_micros(9_950));
        assert_eq!(
            p.best_addr(t1 + Duration::from_millis(10)),
            Some(a),
            "near-equal rival must not steal best"
        );

        // a's trust runs until `a_confirmed + TRUST_DURATION`; just AFTER that it must have lapsed —
        // the rival's later pong did not extend it. (If the rival had wrongly refreshed trust, a
        // would still be reported as best here.)
        let just_after_a_expiry = a_confirmed + TRUST_DURATION + Duration::from_millis(1);
        assert_eq!(
            p.best_addr(just_after_a_expiry),
            None,
            "a rival's pong must not extend the held best's trust window"
        );
    }

    // ---- cadence gates (tsr-7s3, matching Go magicsock) ----

    /// An unconfirmed candidate is pinged at most once per `DISCO_PING_INTERVAL` (5s), not every
    /// pinger tick — the discovery floor. The first call pings it; a call < 5s later does not; a
    /// call ≥ 5s later does again.
    #[test]
    fn discovery_floor_throttles_unconfirmed_candidate_to_5s() {
        let mut p = PeerPaths::default();
        let a: SocketAddr = "203.0.113.1:41641".parse().unwrap();
        p.add_netmap_candidates([a]);
        let now = Instant::now();

        // First tick: pinged (never pinged before → no floor).
        assert_eq!(p.candidates_to_ping(now), vec![a]);
        p.note_ping_sent(tx(1), a, now);

        // 2s later (next pinger tick): still inside the 5s floor → not pinged.
        assert!(
            p.candidates_to_ping(now + Duration::from_secs(2))
                .is_empty(),
            "unconfirmed candidate must not be re-pinged within DISCO_PING_INTERVAL"
        );

        // 5s later: floor elapsed → pinged again.
        assert_eq!(p.candidates_to_ping(now + Duration::from_secs(5)), vec![a]);
    }

    /// The confirmed BEST path is EXEMPT from the discovery floor — it is re-pinged whenever a ping
    /// cycle runs (the heartbeat refresh), even moments after its confirming ping. This is the
    /// load-bearing regression guard: flooring the best would delay its re-ping past the trust
    /// window and flap the path to DERP. Removing the best-exemption in `candidates_to_ping` makes
    /// this assertion fail (the best would be floored for 5s like any other candidate).
    #[test]
    fn confirmed_best_is_exempt_from_the_discovery_floor() {
        let mut p = PeerPaths::default();
        let a: SocketAddr = "203.0.113.1:41641".parse().unwrap();
        p.add_netmap_candidates([a]);
        let now = Instant::now();

        // Confirm `a` as the (sole, trusted) best at a non-good-enough latency (>5ms) so the
        // good-enough quiet-down does not also apply — we are isolating the floor exemption.
        p.note_ping_sent(tx(1), a, now);
        p.note_pong(tx(1), a, now + Duration::from_millis(50)); // 50ms RTT → best, not good-enough
        assert_eq!(p.best_addr(now + Duration::from_millis(50)), Some(a));

        // Only ~1s after the confirming ping — well inside the 5s discovery floor — the best must
        // STILL be returned for a re-ping (heartbeat), because the best is exempt from the floor.
        let soon = now + Duration::from_secs(1);
        assert_eq!(
            p.candidates_to_ping(soon),
            vec![a],
            "the confirmed best must be re-pinged despite being inside the 5s discovery floor"
        );
    }

    /// A good-enough best (≤5ms) quiets discovery of the OTHER candidates (no full-ping), while the
    /// best itself is still refreshed. The non-best candidate is skipped until the upgrade interval.
    #[test]
    fn good_enough_best_quiets_nonbest_candidates() {
        let mut p = PeerPaths::default();
        let a: SocketAddr = "203.0.113.1:41641".parse().unwrap();
        let b: SocketAddr = "203.0.113.2:41641".parse().unwrap();
        p.add_netmap_candidates([a, b]);
        let now = Instant::now();

        // Confirm `a` at 3ms (≤ GOOD_ENOUGH_LATENCY) → best + good-enough.
        p.note_ping_sent(tx(1), a, now);
        p.note_pong(tx(1), a, now + Duration::from_millis(3));
        let t = now + Duration::from_millis(3);
        assert_eq!(p.best_addr(t), Some(a));

        // The FIRST cycle is always a full discovery sweep — Go `wantFullPingLocked` returns true
        // while `lastFullPing` is zero, regardless of a good-enough best. (In the live pinger this
        // has long since happened by the time a path is good-enough-confirmed.) It stamps
        // `last_full_ping`, arming the good-enough quiet-down for subsequent cycles.
        let first = p.candidates_to_ping(t + Duration::from_millis(1));
        assert!(
            first.contains(&a) && first.contains(&b),
            "first cycle (lastFullPing zero) is a full sweep, matching Go wantFullPingLocked"
        );

        // The NEXT cycle, still inside the upgrade interval, returns ONLY the best (a); the rival b
        // is now quieted by the good-enough best.
        let pinged = p.candidates_to_ping(t + Duration::from_secs(1));
        assert_eq!(
            pinged,
            vec![a],
            "good-enough best quiets non-best discovery; only the best is refreshed"
        );
    }

    /// Even on a good-enough best, the periodic `UPGRADE_UDP_DIRECT_INTERVAL` (60s) re-probe full-
    /// pings every candidate so a better path can still be discovered (the escape hatch for the
    /// good-enough quiet-down).
    #[test]
    fn upgrade_interval_reprobes_all_candidates_on_good_enough_best() {
        let mut p = PeerPaths::default();
        let a: SocketAddr = "203.0.113.1:41641".parse().unwrap();
        let b: SocketAddr = "203.0.113.2:41641".parse().unwrap();
        p.add_netmap_candidates([a, b]);
        let now = Instant::now();

        // Confirm `a` good-enough; the confirming cycle stamps `last_full_ping`.
        p.note_ping_sent(tx(1), a, now);
        p.note_pong(tx(1), a, now + Duration::from_millis(3));
        let t = now + Duration::from_millis(3);
        // The first cycle is the full sweep that stamps `last_full_ping` (lastFullPing zero ⇒ full
        // ping), arming the upgrade interval. It pings both candidates.
        let first = p.candidates_to_ping(t);
        assert!(
            first.contains(&a) && first.contains(&b),
            "first cycle is a full sweep that stamps last_full_ping"
        );

        // 61s later the upgrade is due → both candidates pinged (a as best, b as the re-probe).
        let mut pinged = p.candidates_to_ping(t + Duration::from_secs(61));
        pinged.sort();
        let mut want = vec![a, b];
        want.sort();
        assert_eq!(
            pinged, want,
            "after UPGRADE_UDP_DIRECT_INTERVAL, all candidates are re-probed despite good-enough"
        );
    }
}
