//! Per-peer path state and best-address selection.
//!
//! Mirrors the core of Go magicsock's `endpoint`/`addrSet`: for each peer we track a set of
//! candidate UDP endpoints (learned from the control netmap and from disco `CallMeMaybe`),
//! send disco pings to them, and promote the endpoint whose pong wins to be the peer's "best
//! address". WireGuard data for that peer is then sent to the best address.
//!
//! Selection rules, as Go's `handlePongConnLocked` applies them (`endpoint.go`):
//! - A path is *confirmed* when we receive a pong for a ping we sent to it.
//! - Only the path that just ponged is compared with the current best, through [`better_addr`]
//!   (Go `betterAddr`: latency with hysteresis, plus a bonus for a private, link-local or IPv6
//!   address). No other candidate's remembered latency takes part: a remembered reading does not
//!   prove a path is still alive, so scanning them would keep re-electing a dead path.
//! - The pong's path becomes the best when it is better than the current best, or when the
//!   current best is no longer trusted (the next confirmed pong replaces an untrusted best,
//!   whatever its old reading was).
//! - A best address is *trusted* until `trust_until`; after that it must be re-confirmed by
//!   a fresh pong or the peer falls back to DERP (the caller's responsibility). Only the best's
//!   own pong renews its trust; a rival's pong proves the rival works, not that the best is alive.
//! - Control can switch the keep-the-best-path-alive ping off entirely with the `silent-disco`
//!   node attribute, in which case an inbound packet on the best address is what keeps it trusted
//!   instead — see [`PeerPaths::set_heartbeat_disabled`].

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
///
/// No-flap timing invariant (spans crates): this must stay comfortably greater than
/// `ts_runtime::direct::PING_INTERVAL` (2s) plus a realistic best-path RTT, so the best is re-pinged
/// *and* re-pong-confirmed before `TRUST_DURATION` (6.5s) lapses. With 3.5s lead, 2s tick, and a
/// sub-second RTT the slack is ~1.5s. Changing `PING_INTERVAL` up, this down, or `TRUST_DURATION`
/// down can break it; keep the three in step (the `direct.rs` `PING_INTERVAL` doc carries the
/// reciprocal note).
const REFRESH_BEFORE_EXPIRY: Duration = Duration::from_millis(3500);

/// Whether path `a` (address, measured latency) is better than path `b`: Go magicsock `betterAddr`
/// (wgengine/magicsock/endpoint.go), minus its MTU and Geneve-relay branches, which do not apply to
/// direct candidates here.
///
/// Each side gets points for how much faster it is than the slower one, in percent, plus a bonus
/// for its address kind: loopback +50, link-local +30, private (RFC 1918 / ULA) +20, IPv6 +10. So a
/// LAN path beats a public one (often a hairpin through the local NAT) unless the public one is
/// clearly faster. An improvement of 1 point or less with no bonus on the other side is not
/// better, the hysteresis that stops the best path flapping between near-equal candidates.
pub(crate) fn better_addr(a: (SocketAddr, Duration), b: (SocketAddr, Duration)) -> bool {
    let ((a_addr, a_lat), (b_addr, b_lat)) = (a, b);
    if a_addr == b_addr {
        return false;
    }
    let pct = |fast: Duration, slow: Duration| -> i64 {
        // `100 - fast*100/slow`, in integer arithmetic like Go's.
        100 - i64::try_from(fast.as_nanos() * 100 / slow.as_nanos()).unwrap_or(100)
    };
    let (mut a_points, mut b_points) = (0i64, 0i64);
    if a_lat > b_lat && !a_lat.is_zero() {
        b_points = pct(b_lat, a_lat);
    } else if !b_lat.is_zero() {
        a_points = pct(a_lat, b_lat);
    }
    let kind = |ip: std::net::IpAddr| -> i64 {
        let class = if ip.is_loopback() {
            50
        } else if is_link_local_unicast(ip) {
            30
        } else if is_private(ip) {
            20
        } else {
            0
        };
        class + if ip.is_ipv6() { 10 } else { 0 }
    };
    a_points += kind(a_addr.ip());
    b_points += kind(b_addr.ip());
    if a_points <= 1 && b_points == 0 {
        return false;
    }
    a_points > b_points
}

/// Go `netip.Addr.IsLinkLocalUnicast`.
fn is_link_local_unicast(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_link_local(),
        std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// Go `netip.Addr.IsPrivate`: RFC 1918 and RFC 4193 (fc00::/7).
fn is_private(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_private(),
        std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// A ping with no pong after this long is presumed lost; its in-flight record is pruned so the
/// `in_flight` map cannot grow unbounded for a peer whose paths never confirm (it would otherwise
/// gain an entry per candidate every `PING_INTERVAL`, forever). Mirrors the STUN in-flight TTL
/// discipline. Sized above any realistic RTT and the re-ping cadence.
const PING_TIMEOUT: Duration = Duration::from_secs(5);

/// Minimum time between *discovery* pings to a single candidate, matching Go magicsock's
/// `discoPingInterval` (= `tsconst.DefaultPingInterval`, 5s; the per-candidate
/// `now.Sub(st.lastPing) < discoPingInterval` skip in `sendDiscoPingsLocked`, `endpoint.go`). The
/// global pinger runs every 2s (`ts_runtime::direct::PING_INTERVAL`), but a candidate is re-pinged at
/// most once per this interval, so an unconfirmed/rival path is probed on Go's 5s cadence rather than
/// every 2s tick (a fingerprint).
///
/// In Go this floor is applied *uniformly* to every candidate inside `sendDiscoPingsLocked`,
/// including the best; Go keeps the best alive on a **separate, un-floored** path — `heartbeat`
/// pings `addrForSendLocked` (the trusted best) every `heartbeatInterval` via `pingHeartbeat`,
/// independent of the floor. [`candidates_to_ping`](PeerPaths::candidates_to_ping) folds those two Go
/// paths into one and so exempts the confirmed **best** from this floor explicitly: the best is still
/// re-pinged on the [`REFRESH_BEFORE_EXPIRY`] schedule. Flooring the best would delay its re-ping from
/// ~3s to the 6s tick, leaving < 0.5s before `TRUST_DURATION` lapses — one missed tick would take the
/// path dark, exactly the flap [`REFRESH_BEFORE_EXPIRY`] was added to fix. (Go's best-ping runs on the
/// 3s `heartbeatInterval`; this fork's 2s `PING_INTERVAL` is a slightly tighter, pre-existing cadence.)
///
/// The exemption is therefore also where control's `silent-disco` attribute lands: because it *is*
/// this fork's heartbeat, switching the heartbeat off is exactly withdrawing it, and the best then
/// falls back to being floored like any other candidate. See
/// [`set_heartbeat_disabled`](PeerPaths::set_heartbeat_disabled).
const DISCO_PING_INTERVAL: Duration = Duration::from_secs(5);

/// Latency at or below which the confirmed best path is "good enough" that we stop full-pinging the
/// other candidates — Go magicsock `goodEnoughLatency` (5ms), the `wantFullPingLocked` quiet-down.
/// On a good direct path (e.g. same-DC / LAN <5ms — common for the fork's public-VPS topology) this
/// reduces steady-state ping volume to just the best-path refresh, matching a stock client.
///
/// Matching Go's `wantFullPingLocked` precedence ladder exactly: once the best is good-enough, Go
/// returns `false` and **short-circuits before** the `UPGRADE_UDP_DIRECT_INTERVAL` rung — so a
/// good-enough best is quieted *indefinitely* (no periodic re-probe of the other candidates) until
/// either its trust lapses or its measured latency rises above this threshold. The best path itself
/// is still refreshed every cycle, so trust never lapses while it stays good. (A newly-learned
/// candidate is still probed once promptly even during the quiet period — see
/// [`candidates_to_ping`](PeerPaths::candidates_to_ping) — mirroring Go's ping-on-`CallMeMaybe`.)
const GOOD_ENOUGH_LATENCY: Duration = Duration::from_millis(5);

/// How often to full-ping every candidate to discover a better path when the best is *working but
/// mediocre* — Go magicsock `upgradeUDPDirectInterval` (1 min), the final rung of
/// `wantFullPingLocked`. This rung is reached **only when the best's latency is above**
/// `GOOD_ENOUGH_LATENCY` (the good-enough rung short-circuits first), so it does NOT re-probe a
/// good-enough (≤5ms) path — it periodically looks for an upgrade away from a usable-but-slow direct
/// path without per-2s-tick chatter.
const UPGRADE_UDP_DIRECT_INTERVAL: Duration = Duration::from_secs(60);

/// How long after the last traffic with a peer this node keeps discovering and heartbeating its
/// paths — Go magicsock `sessionActiveTimeout` (45s, `magicsock.go`).
///
/// Go only runs `endpoint.heartbeat` while `now.Sub(de.lastSendExt) <= sessionActiveTimeout`
/// (`endpoint.go`). Once a peer goes quiet, no more discovery pings or `CallMeMaybe`s are sent to
/// it, its direct path's trust lapses, and it rides DERP until traffic resumes.
pub const SESSION_ACTIVE_TIMEOUT: Duration = Duration::from_secs(45);

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
///
/// At the cap a new learned endpoint evicts the one the peer named least recently (never the
/// current best), so the cap bounds the set without locking out a peer that moved. Refusing the new
/// endpoint instead, as this tree used to, left a peer that had filled the set with stale
/// symmetric-NAT mappings unable to be learned anywhere new: its pings were answered, but its
/// WireGuard from the new address had no `addr -> disco` attribution and was dropped.
///
/// Go expires learned endpoints by time instead (`endpointState.shouldDeleteLocked`,
/// wgengine/magicsock/endpoint.go:510-521: 45 s since `lastGotPing`, `sessionActiveTimeout` at
/// magicsock.go:4068; `CallMeMaybe` endpoints are replaced per message, endpoint.go:2165-2209) and
/// prunes past 100 endpoints (endpoint.go:1840-1848). This tree does not, because here a learned
/// candidate also carries the address's attribution, without which WireGuard from it is dropped.
/// Go's address-to-peer map (`peerMap.setNodeKeyForEpAddr`, magicsock.go:2598) does not expire
/// with the candidate, and Go hands WireGuard from an unknown address to wireguard-go anyway
/// (`lazyEndpoint`, magicsock.go:1893). Expiring by time here would drop the WireGuard of a peer
/// that sends data without pinging, as one under `silent-disco` does.
pub(crate) const MAX_LEARNED_CANDIDATES_PER_PEER: usize = 32;

/// Where a candidate endpoint came from, which decides how it is reconciled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum CandidateSource {
    /// Advertised by the control netmap. Authoritative and reconciled on every netmap update:
    /// a netmap candidate that control stops advertising is pruned.
    Netmap,
    /// Learned from authenticated disco traffic (an inbound ping's source, or a CallMeMaybe).
    /// Preserved across netmap updates. Dropped when the whole peer leaves the netmap, or evicted
    /// when the peer's learned set is full and the peer names a new address (the one it named
    /// least recently goes; see [`MAX_LEARNED_CANDIDATES_PER_PEER`]). Go expires these by time
    /// instead (`shouldDeleteLocked`, 45 s since `lastGotPing`; `CallMeMaybe` endpoints are
    /// replaced per message).
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
    /// `DISCO_PING_INTERVAL` floor so a non-best candidate is re-probed on Go's 5s cadence rather
    /// than every 2s pinger tick. Stamped at send time (in [`PeerPaths::note_ping_sent`]) — matching
    /// Go's `st.lastPing = now` at ping dispatch — so a candidate whose pong is lost still waits the
    /// full interval before the next probe.
    last_ping: Option<Instant>,
    /// When an authenticated disco message (an inbound ping from this address, or a `CallMeMaybe`
    /// listing it) last named this endpoint. Learned candidates only; decides which one is evicted
    /// when the learned set is full.
    last_learned: Option<Instant>,
}

/// The outcome of adding learned candidates: the addresses now in the candidate set, and the
/// learned addresses evicted to keep the set within [`MAX_LEARNED_CANDIDATES_PER_PEER`].
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LearnedCandidates {
    /// Addresses in the candidate set after the call (newly inserted, or already present).
    pub accepted: Vec<SocketAddr>,
    /// Learned addresses removed to make room.
    pub evicted: Vec<SocketAddr>,
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
    /// `UPGRADE_UDP_DIRECT_INTERVAL` periodic re-probe that overrides the `GOOD_ENOUGH_LATENCY`
    /// quiet-down (Go magicsock's `lastFullPing` feeding `wantFullPingLocked`).
    last_full_ping: Option<Instant>,
    /// Control has told this node to stop heartbeating this peer — Go magicsock's per-endpoint
    /// `heartbeatDisabled`, which `Conn.debugFlagsLocked` fills from the `silent-disco` node
    /// attribute and `endpoint.updateFromNode` stamps onto every endpoint.
    ///
    /// Two reads, and the second is not optional:
    ///
    /// - [`candidates_to_ping`](Self::candidates_to_ping) stops exempting the confirmed best from
    ///   the `DISCO_PING_INTERVAL` floor. That exemption *is* this fork's heartbeat (see
    ///   [`DISCO_PING_INTERVAL`]), so dropping it is Go's `heartbeat` returning early and
    ///   `noteTxActivityExtTriggerLocked` never arming the timer, folded into the one place this
    ///   tree schedules pings.
    /// - [`note_recv_activity`](Self::note_recv_activity) extends `trust_until` when a packet
    ///   arrives from the best address. With the heartbeat gone nothing else re-confirms the path,
    ///   so without this arm `TRUST_DURATION` would lapse on a path carrying live data and the peer
    ///   would be demoted to DERP — strictly worse than not porting the flag at all.
    ///
    /// Set by the netmap push ([`set_heartbeat_disabled`](Self::set_heartbeat_disabled)); `false`
    /// (the default) is byte-for-byte the previous behaviour.
    heartbeat_disabled: bool,
    /// When this peer last had traffic, or an explicit ping — Go magicsock's `lastSendExt`. `None`
    /// until the first one. Discovery and the heartbeat run only while this is within
    /// [`SESSION_ACTIVE_TIMEOUT`]; see [`pings_due`](Self::pings_due).
    last_active: Option<Instant>,
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
    /// time (each carrying fresh addresses) to grow the learned set without limit. Once at the cap,
    /// a *new* learned endpoint evicts the learned candidate that an authenticated disco message
    /// named least recently, so the set stays bounded and a peer that moved is still learned at its
    /// new address. The current best path is never evicted. Netmap (control-authoritative)
    /// candidates are never capped or evicted: control is trusted and
    /// `reconcile_netmap_candidates` already bounds them to the advertised set.
    ///
    /// Returns the addresses accepted into the candidate set (newly inserted, or already present)
    /// and the learned addresses evicted to make room. The caller uses both to keep the socket's
    /// reverse `addr -> disco` attribution map in lockstep with the candidate set.
    fn add_candidates(
        &mut self,
        endpoints: impl IntoIterator<Item = SocketAddr>,
        source: CandidateSource,
        now: Instant,
    ) -> LearnedCandidates {
        let mut out = LearnedCandidates::default();
        // Every address this call names is protected from eviction by it, wherever it sits in the
        // list: evicting one named later would only drop its state and re-add it.
        let endpoints: Vec<SocketAddr> = endpoints.into_iter().collect();
        for &ep in &endpoints {
            if source == CandidateSource::Learned
                && !self.candidates.contains_key(&ep)
                && self.learned_candidate_count() >= MAX_LEARNED_CANDIDATES_PER_PEER
            {
                let Some(stalest) = self.stalest_evictable_learned(&endpoints) else {
                    tracing::debug!(
                        %ep,
                        "dropping learned candidate: peer at MAX_LEARNED_CANDIDATES_PER_PEER"
                    );
                    continue;
                };
                tracing::debug!(
                    %ep,
                    evicted = %stalest,
                    "learned set full; evicting the least recently named learned candidate"
                );
                self.candidates.remove(&stalest);
                self.in_flight.retain(|_, inflight| inflight.to != stalest);
                out.evicted.push(stalest);
            }
            let cand = self.candidates.entry(ep).or_default();
            match source {
                CandidateSource::Netmap => cand.source = CandidateSource::Netmap,
                CandidateSource::Learned => cand.last_learned = Some(now),
            }
            out.accepted.push(ep);
        }
        out
    }

    /// The learned candidate an authenticated disco message named least recently, excluding the
    /// current best path and the addresses `named_now` (every address the message being added
    /// names, so it never evicts its own endpoints). Ties (and candidates with no stamp) break on
    /// the address so the choice is deterministic.
    fn stalest_evictable_learned(&self, named_now: &[SocketAddr]) -> Option<SocketAddr> {
        self.candidates
            .iter()
            .filter(|(addr, c)| {
                c.source == CandidateSource::Learned
                    && self.best != Some(**addr)
                    && !named_now.contains(addr)
            })
            .min_by_key(|(addr, c)| (c.last_learned, **addr))
            .map(|(addr, _)| *addr)
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
        self.add_candidates(endpoints, CandidateSource::Netmap, Instant::now());
    }

    /// Add candidate endpoints learned from authenticated disco traffic, returning the addresses
    /// accepted. See [`add_learned_candidates_at`](Self::add_learned_candidates_at), which also
    /// reports the addresses evicted at `MAX_LEARNED_CANDIDATES_PER_PEER`.
    pub fn add_learned_candidates(
        &mut self,
        endpoints: impl IntoIterator<Item = SocketAddr>,
    ) -> Vec<SocketAddr> {
        self.add_learned_candidates_at(endpoints, Instant::now())
            .accepted
    }

    /// Add candidate endpoints learned from authenticated disco traffic at `now`. Each one is
    /// stamped as named at `now`, so a source the peer keeps pinging from ranks ahead of every
    /// address it named earlier when the full set must evict one. No address named in this call is
    /// evicted by it. The caller (`MagicSock::add_peer_endpoints`) attributes the accepted
    /// addresses in the reverse `addr -> disco` map and releases the evicted ones, keeping that map
    /// bounded in lockstep with the capped candidate set.
    pub fn add_learned_candidates_at(
        &mut self,
        endpoints: impl IntoIterator<Item = SocketAddr>,
        now: Instant,
    ) -> LearnedCandidates {
        self.add_candidates(endpoints, CandidateSource::Learned, now)
    }

    /// Set whether control has switched this node's disco heartbeat off for this peer — Go
    /// magicsock `endpoint.setHeartbeatDisabled`, called from `Conn.SetSilentDisco` and from the
    /// netmap push `endpoint.updateFromNode`.
    ///
    /// Idempotent, and it deliberately touches nothing else: turning the flag on does not clear the
    /// best path, its trust or the candidate set (Go's setter is likewise a bare assignment), and
    /// turning it off simply restores the heartbeat on the next pinger tick — the path is already
    /// trusted, so nothing has to be re-discovered either way.
    pub fn set_heartbeat_disabled(&mut self, disabled: bool) {
        self.heartbeat_disabled = disabled;
    }

    /// Record an inbound packet from `src` for this peer — Go magicsock `endpoint.noteRecvActivity`,
    /// of which this is the `heartbeatDisabled` arm and nothing else.
    ///
    /// Ported verbatim, including its narrowness:
    ///
    /// ```go
    /// if de.heartbeatDisabled && de.bestAddr.epAddr == src {
    ///     de.trustBestAddrUntil = now.Add(trustUDPAddrDuration)
    /// }
    /// ```
    ///
    /// So: **only** when the heartbeat is disabled (with the heartbeat running, the pong it draws is
    /// what extends trust, and extending it here as well would keep a silently-dead path trusted on
    /// the strength of packets that may be in flight from before it died), and **only** for the
    /// current best address (a packet from some other candidate says nothing about the best). Note
    /// the comparison is against the *stored* best, not [`best_addr`](Self::best_addr) — Go compares
    /// `de.bestAddr` without consulting the trust window, so data arriving on a best whose trust has
    /// just lapsed re-trusts it rather than forcing a DERP round trip to rediscover a path that is
    /// demonstrably carrying traffic.
    ///
    /// Upstream marks the arm provisional ("subject to change as part of silent disco effort"),
    /// which is the reason to port it as written rather than to improve on it.
    pub fn note_recv_activity(&mut self, src: SocketAddr, now: Instant) {
        if self.heartbeat_disabled && self.best == Some(src) {
            self.trust_until = Some(now + TRUST_DURATION);
        }
    }

    /// Record traffic with this peer, or an explicit ping to it — Go magicsock
    /// `endpoint.noteTxActivityExtTriggerLocked`, which stamps `lastSendExt` and arms the
    /// heartbeat.
    ///
    /// Returns `true` when the peer was idle until now (never active, or quiet for longer than
    /// [`SESSION_ACTIVE_TIMEOUT`]). The caller then starts discovery straight away rather than on
    /// the next pinger tick, as Go's `endpoint.send` does when it has no trusted direct path.
    pub fn note_active(&mut self, now: Instant) -> bool {
        let was_active = self.is_active(now);
        self.last_active = Some(self.last_active.map_or(now, |t| t.max(now)));
        !was_active
    }

    /// Whether this peer has had traffic within [`SESSION_ACTIVE_TIMEOUT`] — the condition Go's
    /// `endpoint.heartbeat` checks before it pings anything (`endpoint.go`).
    pub fn is_active(&self, now: Instant) -> bool {
        self.last_active
            .is_some_and(|t| now.saturating_duration_since(t) <= SESSION_ACTIVE_TIMEOUT)
    }

    /// The candidates the periodic pinger should ping now: Go magicsock's `endpoint.heartbeat`.
    ///
    /// Nothing while the peer is idle ([`is_active`](Self::is_active)): Go stops heartbeating a
    /// session once it has been quiet for [`SESSION_ACTIVE_TIMEOUT`], so neither the best path nor
    /// any other candidate is pinged, and the best path's trust lapses until traffic resumes.
    /// Otherwise the best-path refresh gate ([`needs_refresh`](Self::needs_refresh)) and Go's
    /// discovery cadence ([`candidates_to_ping`](Self::candidates_to_ping)) apply as before.
    ///
    /// Event-driven pings do not come through here and are not gated on activity: an inbound
    /// `CallMeMaybe` ([`force_ping_sweep`](Self::force_ping_sweep)) pings an idle peer too, as Go's
    /// `handleCallMeMaybe` does.
    pub fn pings_due(&mut self, now: Instant) -> Vec<SocketAddr> {
        if !self.is_active(now) || !self.needs_refresh(now) {
            return Vec::new();
        }
        self.candidates_to_ping(now)
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

    /// Invalidate the *disco path* for this peer after its active disco key changed, **keeping the
    /// best address** — Go magicsock `endpoint.changedActiveDiscoLocked`
    /// (`wgengine/magicsock/endpoint.go`), which every disco-key transition funnels through:
    /// control-side (`endpoint.updateFromNode`), TSMP-side (`Conn.HandleDiscoKeyAdvertisement`) and
    /// on an active-slot switch (`endpoint.checkAndUpdateDiscoKey`).
    ///
    /// Everything this peer's path state records was established by disco frames sealed under the
    /// key the peer has just stopped using: the pong that confirmed `best`, the measured latencies,
    /// and the pings still awaiting an answer. None of it says anything about the key the peer uses
    /// now, so all of it is reset:
    ///
    /// - `trust_until` is dropped (Go `trustBestAddrUntil = 0`), so [`best_addr`](Self::best_addr)
    ///   reports no trusted direct path and the peer relays over DERP until a fresh pong lands;
    /// - in-flight probes are dropped — their tx ids were sent to the old key, and a matching pong
    ///   must not re-confirm a path across the rotation;
    /// - each candidate's measured `latency` is cleared so diagnostics contain no
    ///   pre-rotation RTTs. Go retains its latency history, but both implementations select
    ///   only the address that just ponged and promote it unconditionally when best is untrusted;
    /// - each candidate's `last_ping` and `last_full_ping` are cleared, so the re-probe is a full
    ///   sweep of every candidate instead of one that waits out the `DISCO_PING_INTERVAL` floor —
    ///   whether it is the caller's immediate sweep or the next pinger tick behind it (Go's
    ///   `invalidateDiscoPathLocked`, whose point is to re-discover the path now rather than coast
    ///   until trust lapses on its own).
    ///
    /// Each candidate's `last_learned` stamp is kept, as Go keeps `lastGotPing`: it records when
    /// the peer named the address, not a measurement, and it decides which learned candidate a
    /// full set evicts.
    ///
    /// `best` itself and the candidate set are deliberately **kept**, which is the whole shape of
    /// the upstream call: "keep bestAddr so that we can still send data while we find a new path".
    /// The addresses are still where the peer is believed to live — control advertised them, or the
    /// peer itself did over an authenticated `CallMeMaybe` — and a disco-key rotation is no evidence
    /// against them. Note the fork-local limit: [`best_addr`](Self::best_addr) gates on trust, so
    /// this node does not keep *sending* to the retained best the way Go's `addrForSendLocked`
    /// dual-sends to an untrusted `bestAddr`; here the retained address is what the immediate
    /// re-probe targets, and traffic rides DERP for the one round trip it takes to re-confirm.
    /// (One round trip, not one pinger tick: the caller that invalidates,
    /// `MagicSock::changed_active_disco`, reports that it did so and `ts_runtime::direct` re-probes
    /// the peer straight away. Dual-sending is not open to this tree at all — the dataplane routes
    /// each peer through exactly one underlay transport — so a prompt re-confirmation is the whole
    /// of what the retention can buy on the data path.)
    ///
    /// Keeping `best` is not bookkeeping, either: [`note_recv_activity`](Self::note_recv_activity)
    /// compares inbound data against the *stored* best, so under control's `silent-disco` attribute
    /// a peer that is carrying traffic re-trusts its path across the rotation with no pong at all.
    /// Clear `best` here and that arm goes dead: the `sock.rs` test
    /// `inbound_data_re_trusts_the_best_path_under_silent_disco` builds its starting state by
    /// calling this very function, and asserts the retained best is what the data re-trusts.
    ///
    /// Contrast [`invalidate_best`](Self::invalidate_best), the rebind case: there the *local* NAT
    /// mapping changed, so the best address is stale as an address and is cleared outright.
    pub fn invalidate_disco_path(&mut self) {
        self.trust_until = None;
        self.in_flight.clear();
        self.last_full_ping = None;
        for cand in self.candidates.values_mut() {
            // Keep where the candidate came from and when the peer last named it; every measurement
            // is pre-rotation. Go keeps `lastGotPing` across the rotation too (it only zeroes
            // `lastPing`, `invalidateDiscoPathLocked`), so a source the peer named just before it
            // rotated still outranks one it named a day ago when the learned set is full.
            *cand = Candidate {
                source: cand.source,
                last_learned: cand.last_learned,
                ..Candidate::default()
            };
        }
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

    /// Whether to run a *full discovery sweep* of every candidate this cycle, mirroring Go magicsock
    /// `wantFullPingLocked` (`endpoint.go`) as a strict precedence ladder. Read-only; the caller
    /// ([`candidates_to_ping`](Self::candidates_to_ping)) stamps `last_full_ping` when this returns
    /// true.
    ///
    /// Go's ladder, in order (the first matching rung decides):
    /// 1. no trusted direct best → **full** (Go `!bestAddr.isDirect()`; also Go's separate
    ///    `now.After(trustBestAddrUntil)` rung — both collapse here because [`best_addr`] already
    ///    returns `None` once trust lapses);
    /// 2. `last_full_ping` never stamped → **full** (Go `lastFullPing.IsZero()`: the first cycle is
    ///    always a full sweep, even with a good-enough best);
    /// 3. best latency ≤ `GOOD_ENOUGH_LATENCY` → **quiet** (Go short-circuits here and *never*
    ///    consults the upgrade interval for a good-enough path — a ≤5ms best is left alone until
    ///    trust lapses or its latency rises);
    /// 4. best is working-but-mediocre (> good-enough) and the last full sweep was ≥
    ///    `UPGRADE_UDP_DIRECT_INTERVAL` ago → **full** (periodically look for a better path);
    /// 5. otherwise → **quiet**.
    fn want_full_ping(&self, now: Instant) -> bool {
        // Rung 1: no trusted direct best (no path yet, or trust expired).
        let Some(best) = self.best_addr(now) else {
            return true;
        };
        // Rung 2: first sweep (Go `lastFullPing.IsZero()`) — checked before good-enough.
        let Some(last_full) = self.last_full_ping else {
            return true;
        };
        // Rung 3: a good-enough best quiets discovery indefinitely (Go returns false here and
        // short-circuits — the upgrade interval in rung 4 is unreachable for a ≤5ms path). Resolve
        // the latency through the map rather than assume, so a future change to `best` selection
        // can't silently desync; a (impossible) latency-less best falls through to rung 4, the safe
        // direction (more probing, not less).
        let best_latency = self.candidates.get(&best).and_then(|c| c.latency);
        if best_latency.is_some_and(|l| l <= GOOD_ENOUGH_LATENCY) {
            return false;
        }
        // Rung 4: mediocre best — re-probe every UPGRADE_UDP_DIRECT_INTERVAL to find a better path.
        now.saturating_duration_since(last_full) >= UPGRADE_UDP_DIRECT_INTERVAL
    }

    /// The candidate endpoints to disco-ping this cycle, applying Go magicsock's cadence so the
    /// on-wire ping rate matches a stock client instead of pinging every candidate every 2s tick.
    /// `now` is the pinger tick instant. The caller should already have checked
    /// [`needs_refresh`](Self::needs_refresh); this decides *which* candidates.
    ///
    /// **Decision-and-mark:** when it commits to a full sweep (`want_full_ping`)
    /// it stamps `last_full_ping`, mirroring Go `sendDiscoPingsLocked` setting `lastFullPing = now` on
    /// entry. Call it exactly once per pinger tick (a second call in the same tick would advance the
    /// upgrade clock). The stamp tracks sweep *intent*, not emission — like Go it is set even if every
    /// non-best candidate is then floored and the returned set is best-only or empty.
    ///
    /// Three rules combine; the best path is never throttled, so an active path cannot go dark:
    /// - The confirmed **best** is ALWAYS pinged (un-floored). Go pings the best via a *separate*
    ///   un-floored `pingHeartbeat` in `heartbeat` (`endpoint.go`), independent of `wantFullPingLocked`
    ///   and of the per-candidate floor that `sendDiscoPingsLocked` applies uniformly to all
    ///   candidates; this method folds that into one place via the explicit best-exemption. Flooring
    ///   the best would risk the path going dark (see `DISCO_PING_INTERVAL`).
    /// - On a **quiet** cycle (good-enough best, no full sweep due) non-best candidates are skipped —
    ///   EXCEPT a candidate never yet pinged (`last_ping == None`), which gets one prompt probe. Go
    ///   pings a freshly-learned endpoint immediately via the event-driven `CallMeMaybe`
    ///   `sendDiscoPingsLocked`; this fork pings only on the periodic path, so the never-pinged
    ///   exemption stands in for that trigger and keeps a new (possibly better) candidate from being
    ///   starved while a good-enough best holds.
    /// - On a **full** cycle every non-best candidate is eligible but skipped if pinged within
    ///   `DISCO_PING_INTERVAL` (the 5s discovery floor). A never-pinged candidate has no `last_ping`,
    ///   so it is never floored — it is always probed promptly.
    ///
    /// **Silent disco** ([`heartbeat_disabled`](Self::set_heartbeat_disabled)) removes the first of
    /// those three rules and only the first: the best loses its exemption and is treated as an
    /// ordinary candidate, floored and quieted like any other. That is the whole suppression, and it
    /// is where it belongs — the exemption is this fork's fold of Go's separate `pingHeartbeat`, so
    /// dropping it is Go's `heartbeat` early return. Go keeps its *discovery* pings under the flag
    /// too (`sendDiscoPingsLocked` is still reachable when trust lapses), which is why the other two
    /// rules are untouched; in practice they go quiet as well, because
    /// [`note_recv_activity`](Self::note_recv_activity) keeps an active path trusted and the
    /// caller's [`needs_refresh`](Self::needs_refresh) gate then never lets this method run.
    pub fn candidates_to_ping(&mut self, now: Instant) -> Vec<SocketAddr> {
        // Silent disco: no heartbeat, so there is no exempt best this cycle.
        let best = (!self.heartbeat_disabled)
            .then(|| self.best_addr(now))
            .flatten();
        let full_sweep = self.want_full_ping(now);
        if full_sweep {
            self.last_full_ping = Some(now);
        }

        let mut out = Vec::new();
        for (addr, cand) in &self.candidates {
            if Some(*addr) == best {
                // The confirmed best is the heartbeat refresh — always pinged, never floored.
                out.push(*addr);
                continue;
            }
            let never_pinged = cand.last_ping.is_none();
            if !full_sweep && !never_pinged {
                // Quieted by a good-enough best: skip non-best candidates we've already probed.
                continue;
            }
            // Honor the per-candidate 5s floor (a never-pinged candidate has no `last_ping`, so it
            // is never floored and is always probed promptly).
            let floored = cand
                .last_ping
                .is_some_and(|t| now.saturating_duration_since(t) < DISCO_PING_INTERVAL);
            if !floored {
                out.push(*addr);
            }
        }
        out
    }

    /// Force an immediate discovery sweep of **every** candidate, bypassing the per-candidate
    /// `DISCO_PING_INTERVAL` floor, and return the addresses to ping now.
    ///
    /// This is the event-driven counterpart to [`candidates_to_ping`](Self::candidates_to_ping)'s
    /// periodic gating. It mirrors Go magicsock `endpoint.handleCallMeMaybe`, which on receipt of a
    /// `CallMeMaybe` zeroes `st.lastPing` for every endpoint and then calls `sendDiscoPingsLocked`
    /// "to force sendPingsLocked to send new ones, even if it's been less than 5 seconds ago"
    /// (`endpoint.go`). A `CallMeMaybe` is the peer's explicit "I just opened my firewall, ping me
    /// now" signal, so the 5s discovery floor (which exists only to bound the *unsolicited*
    /// periodic probe rate) must not delay the hole-punch.
    ///
    /// Stamps `last_full_ping = now` — this *is* a full sweep, matching Go's unconditional
    /// `de.lastFullPing = now` at the top of `sendDiscoPingsLocked`, which arms the
    /// `GOOD_ENOUGH_LATENCY` quiet-down / `UPGRADE_UDP_DIRECT_INTERVAL` re-probe schedule. The
    /// caller stamps each returned address via [`note_ping_sent`](Self::note_ping_sent) as it sends,
    /// so the per-candidate floor is re-established from this send (a periodic
    /// [`candidates_to_ping`](Self::candidates_to_ping) in the same window will then correctly skip
    /// them rather than double-ping).
    ///
    /// Mechanism note: Go zeroes each `st.lastPing` and lets `sendDiscoPingsLocked` re-send (the
    /// `!st.lastPing.IsZero()` floor check is bypassed because the value is now zero); this fork
    /// instead enumerates every candidate here and floors via the caller's `note_ping_sent` stamp.
    /// The on-wire effect is identical: one ping per candidate now, with the 5s floor restarting
    /// from this send. Note this is deliberately **not** coalesced across repeated `CallMeMaybe`s —
    /// that, too, is Go-faithful: Go re-zeroes `lastPing` on *every* `handleCallMeMaybe`, so each
    /// `CallMeMaybe` re-pings the full candidate set with no per-event rate limit (the
    /// `DISCO_PING_INTERVAL` floor exists only to pace the *unsolicited* periodic prober, and an
    /// explicit "ping me now" solicitation is exactly the case it yields to). The fan-out is bounded
    /// by `MAX_LEARNED_CANDIDATES_PER_PEER` and the sender's netmap-membership gate; the pings are
    /// self-targeted (the soliciting peer's own advertised, sanitized endpoints), never a reflector.
    pub fn force_ping_sweep(&mut self, now: Instant) -> Vec<SocketAddr> {
        self.last_full_ping = Some(now);
        self.candidates.keys().copied().collect()
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
    ///
    /// Under silent disco ([`set_heartbeat_disabled`](Self::set_heartbeat_disabled)) the lead is
    /// dropped and the gate opens only once there is no trusted path at all. The lead exists solely
    /// to get the heartbeat in *ahead of* expiry; with no heartbeat to schedule there is nothing to
    /// be early for, and keeping it would reopen this gate every trust window on a peer control
    /// asked this node to go quiet to. What is left is Go's own trigger for the suppressed case —
    /// `send()` calls `sendDiscoPingsLocked` when `!bestAddr.isValid() || now.After(
    /// trustBestAddrUntil)` — so a silenced peer whose path really has lapsed still rediscovers one.
    pub fn needs_refresh(&self, now: Instant) -> bool {
        if self.heartbeat_disabled {
            return self.best_addr(now).is_none();
        }
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

    /// The best address as *stored*, ignoring the trust window. Test-only: `best_addr` cannot tell
    /// "no best" apart from "best kept but untrusted", which is exactly the distinction
    /// [`invalidate_disco_path`](Self::invalidate_disco_path) turns on.
    #[cfg(test)]
    fn stored_best(&self) -> Option<SocketAddr> {
        self.best
    }

    /// A candidate's measured latency as stored. Test-only: pins that a disco-key change clears
    /// it ([`invalidate_disco_path`](Self::invalidate_disco_path)).
    #[cfg(test)]
    fn stored_latency(&self, addr: SocketAddr) -> Option<Duration> {
        self.candidates.get(&addr).and_then(|c| c.latency)
    }

    /// Compare only the address that just ponged with the current best, as Go's
    /// `handlePongConnLocked` does. Historical RTTs do not prove a path is still alive.
    fn recompute_best(&mut self, now: Instant, confirmed: SocketAddr) {
        let Some(latency) = self.candidates.get(&confirmed).and_then(|c| c.latency) else {
            return;
        };
        let previous = self.best;
        let best_untrusted = self.best_addr(now).is_none();
        let better = self
            .best
            .and_then(|addr| {
                self.candidates
                    .get(&addr)
                    .and_then(|c| c.latency)
                    .map(|rtt| (addr, rtt))
            })
            .is_none_or(|current| better_addr((confirmed, latency), current));
        if best_untrusted || better {
            self.best = Some(confirmed);
        }
        // A rival's pong cannot refresh the held best. Once that trust expires, the first
        // matching pong wins even if the dead best had a much faster RTT.
        if self.best == Some(confirmed) {
            self.trust_until = Some(now + TRUST_DURATION);
        }
        // Per-pong detail at trace, like every other per-message line in this crate; the one event
        // an operator wants at debug is the best path changing (Go logs only that: "node %v now
        // using %v" in `handlePongConnLocked`).
        if self.best != previous {
            tracing::debug!(
                ?previous,
                best = ?self.best,
                ?latency,
                best_untrusted,
                "magicsock: best path changed"
            );
        }
        tracing::trace!(%confirmed, ?latency, ?previous, best = ?self.best, best_untrusted,
            "magicsock: pong path selection");
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

    /// A port-dependent NAT advertises an unreachable endpoint but sends authenticated pings
    /// from a different mapping. Only that source accepts our probes after the peer moves.
    #[test]
    fn network_move_recovers_via_learned_source_after_trust_expires() {
        let old = "203.0.113.1:41641".parse().unwrap();
        let advertised = "203.0.113.2:41641".parse().unwrap();
        let source = "203.0.113.2:53000".parse().unwrap();
        let mut paths = PeerPaths::default();
        let start = Instant::now();
        paths.add_netmap_candidates([old]);
        paths.note_ping_sent(tx(1), old, start);
        paths.note_pong(tx(1), old, start + Duration::from_millis(2));

        // The peer moves. Its ping reaches us (and our pong reaches it), but only a pong
        // to OUR probe grants outbound trust. Repeated netmaps must keep the learned source.
        paths.add_learned_candidates([source]);
        paths.reconcile_netmap_candidates([old, advertised]);
        let early = start + Duration::from_secs(1);
        assert!(paths.candidates_to_ping(early).contains(&source));
        paths.note_ping_sent(tx(2), source, early);
        paths.note_pong(tx(2), source, early + Duration::from_millis(60));
        assert_eq!(
            paths.best_addr(early + Duration::from_millis(60)),
            Some(old)
        );

        // Neither the dead old mapping nor the STUN mapping accepts packets. The simulated
        // NAT only answers probes addressed to its current ping source. Use virtual time.
        for round in 0..151u8 {
            let now = start + Duration::from_secs(8 + u64::from(round) * 6);
            paths.reconcile_netmap_candidates([old, advertised]);
            let mut answered = false;
            for (index, addr) in paths.candidates_to_ping(now).into_iter().enumerate() {
                let mut id = [round.wrapping_add(3); 12];
                id[11] = index as u8;
                paths.note_ping_sent(id, addr, now);
                if addr == source {
                    paths.note_pong(id, source, now + Duration::from_millis(60));
                    answered = true;
                }
            }
            assert!(answered, "the learned source must keep being probed");
            assert_eq!(
                paths.best_addr(now + Duration::from_millis(60)),
                Some(source),
                "a fresh slower pong must replace the expired fast path"
            );
        }
    }

    #[test]
    fn fresh_pong_never_resurrects_a_dead_historical_rival() {
        let old = "203.0.113.1:41641".parse().unwrap();
        let current = "203.0.113.2:41641".parse().unwrap();
        let mut paths = PeerPaths::default();
        let start = Instant::now();
        paths.add_netmap_candidates([old, current]);
        paths.note_ping_sent(tx(1), old, start);
        paths.note_pong(tx(1), old, start + Duration::from_millis(10));
        paths.note_ping_sent(tx(2), current, start);
        paths.note_pong(tx(2), current, start + Duration::from_millis(2));
        let later = start + Duration::from_secs(3);
        paths.note_ping_sent(tx(3), current, later);
        paths.note_pong(tx(3), current, later + Duration::from_millis(60));
        assert_eq!(
            paths.best_addr(later + Duration::from_millis(60)),
            Some(current),
            "a pong must only promote the address it confirms"
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
    /// time would) does not grow the set past the cap — each new one evicts a stale one.
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

    /// At the cap, a new learned address evicts the one the peer named least recently, never the
    /// confirmed best path and never a netmap candidate, and the eviction is reported so the socket
    /// can drop the address's attribution. A source the peer keeps naming is refreshed and kept.
    #[test]
    fn full_learned_set_evicts_the_least_recently_named() {
        let mut p = PeerPaths::default();
        let t0 = Instant::now();
        let addr =
            |i: usize| -> SocketAddr { format!("203.0.113.7:{}", 40000 + i).parse().unwrap() };
        for i in 0..MAX_LEARNED_CANDIDATES_PER_PEER {
            p.add_learned_candidates_at([addr(i)], t0 + Duration::from_secs(i as u64));
        }
        let netmap: SocketAddr = "198.51.100.9:3478".parse().unwrap();
        p.add_netmap_candidates([netmap]);

        // addr(0) is the oldest but is the confirmed best; addr(1) was named again just now.
        let now = t0 + Duration::from_secs(100);
        let tx = tx(9);
        p.note_ping_sent(tx, addr(0), now);
        p.note_pong(tx, addr(0), now);
        assert_eq!(p.best_addr(now), Some(addr(0)));
        p.add_learned_candidates_at([addr(1)], now);

        let moved: SocketAddr = "198.51.100.7:41641".parse().unwrap();
        let out = p.add_learned_candidates_at([moved], now);
        assert_eq!(out.accepted, vec![moved]);
        assert_eq!(
            out.evicted,
            vec![addr(2)],
            "the least recently named, non-best learned"
        );

        let cands = p.candidate_addrs();
        assert!(cands.contains(&moved) && cands.contains(&addr(0)) && cands.contains(&addr(1)));
        assert!(
            cands.contains(&netmap),
            "netmap candidates are never evicted"
        );
        assert_eq!(p.learned_candidate_count(), MAX_LEARNED_CANDIDATES_PER_PEER);
        assert_eq!(p.best_addr(now), Some(addr(0)));
    }

    /// Neither a disco-key change nor the message being added decides eviction order wrongly: the
    /// rotation keeps each learned candidate's stamp (Go keeps `lastGotPing`), so the source the
    /// peer named just before it rotated outlives older ones, and a message that names more new
    /// addresses than there is room for never evicts its own.
    #[test]
    fn learned_eviction_keeps_recency_across_a_disco_key_change() {
        let mut p = PeerPaths::default();
        let t0 = Instant::now();
        let addr =
            |i: usize| -> SocketAddr { format!("203.0.113.8:{}", 40000 + i).parse().unwrap() };
        // addr(0) is named last, so it is the freshest despite the lowest address.
        for i in (0..MAX_LEARNED_CANDIDATES_PER_PEER).rev() {
            let at = t0 + Duration::from_secs((MAX_LEARNED_CANDIDATES_PER_PEER - i) as u64);
            p.add_learned_candidates_at([addr(i)], at);
        }
        p.invalidate_disco_path();

        let now = t0 + Duration::from_secs(100);
        let moved: SocketAddr = "198.51.100.8:41641".parse().unwrap();
        let out = p.add_learned_candidates_at([moved], now);
        assert_eq!(
            out.evicted,
            vec![addr(MAX_LEARNED_CANDIDATES_PER_PEER - 1)],
            "the oldest pre-rotation source goes, not the one the peer named just before rotating"
        );
        assert!(p.candidate_addrs().contains(&addr(0)));

        // One message naming new addresses when every tracked one is just as fresh: each is
        // admitted, and none evicts another the same message named (they tie on the stamp and
        // sort lowest, so only the exclusion keeps them).
        p.add_learned_candidates_at(p.candidate_addrs(), now);
        let burst: Vec<SocketAddr> = (0..16)
            .map(|i| format!("198.51.100.9:{}", 50000 + i).parse().unwrap())
            .collect();
        let out = p.add_learned_candidates_at(burst.iter().copied(), now);
        assert_eq!(out.accepted, burst);
        assert_eq!(out.evicted.len(), burst.len());
        assert!(out.evicted.iter().all(|e| !burst.contains(e)));
        let cands = p.candidate_addrs();
        assert!(burst.iter().all(|b| cands.contains(b)));
        assert_eq!(p.learned_candidate_count(), MAX_LEARNED_CANDIDATES_PER_PEER);

        // Protection covers the whole message, not just the addresses before the one being added:
        // `[new, stalest]` must not evict `stalest` for `new` and then re-add it, which would drop
        // its in-flight probe and state.
        let later = now + Duration::from_secs(10);
        let stalest = p.stalest_evictable_learned(&[]).unwrap();
        p.note_ping_sent(tx(7), stalest, later);
        let fresh: SocketAddr = "198.51.100.10:41641".parse().unwrap();
        let out = p.add_learned_candidates_at([fresh, stalest], later);
        assert_eq!(out.accepted, vec![fresh, stalest]);
        assert_eq!(out.evicted.len(), 1);
        assert!(!out.evicted.contains(&stalest) && !out.evicted.contains(&fresh));
        assert_eq!(
            p.note_pong(tx(7), stalest, later + Duration::from_millis(5)),
            Some(Duration::from_millis(5)),
            "the named address kept its in-flight probe"
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
    /// only marginally faster (within `better_addr`'s 1-point band) must NOT steal `best` — otherwise
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

    /// Go `betterAddr`'s address-kind bonus: a private (LAN) path beats a public one of similar
    /// latency, e.g. the same peer reached through a NAT hairpin; a public path only wins when it is
    /// clearly faster (by more than the 20-point private bonus).
    #[test]
    fn better_addr_prefers_private_over_public_at_similar_latency() {
        let lan: SocketAddr = "192.168.50.76:41644".parse().unwrap();
        let public: SocketAddr = "203.0.113.34:41644".parse().unwrap();
        let ms = Duration::from_millis;
        assert!(better_addr((lan, ms(10)), (public, ms(9))));
        assert!(!better_addr((public, ms(9)), (lan, ms(10))));
        // 30% faster beats the 20-point bonus.
        assert!(better_addr((public, ms(7)), (lan, ms(10))));
        // Loopback beats link-local beats private.
        let lo: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let ll: SocketAddr = "169.254.1.1:1".parse().unwrap();
        assert!(better_addr((lo, ms(10)), (ll, ms(10))));
        assert!(better_addr((ll, ms(10)), (lan, ms(10))));
        // Hysteresis: <= 1% better and no bonus on the other side is not better.
        let p2: SocketAddr = "203.0.113.2:1".parse().unwrap();
        assert!(!better_addr(
            (p2, Duration::from_micros(9_950)),
            (public, ms(10))
        ));
        assert!(better_addr((p2, ms(9)), (public, ms(10))));
    }

    /// The path selection uses it: a confirmed public hairpin path that is marginally faster does
    /// not take over from the LAN path.
    #[test]
    fn lan_path_stays_best_against_faster_public_hairpin() {
        let mut p = PeerPaths::default();
        let lan: SocketAddr = "192.168.50.76:41644".parse().unwrap();
        let public: SocketAddr = "203.0.113.34:41644".parse().unwrap();
        p.add_netmap_candidates([lan, public]);
        let now = Instant::now();
        p.note_ping_sent(tx(1), lan, now);
        p.note_pong(tx(1), lan, now + Duration::from_millis(2));
        p.note_ping_sent(tx(2), public, now);
        p.note_pong(tx(2), public, now + Duration::from_micros(1_800));
        assert_eq!(p.best_addr(now + Duration::from_millis(3)), Some(lan));
    }

    /// A LAN path that stops answering must not hold the peer on DERP while a live public path
    /// keeps answering. The LAN path wins on its private-address bonus while both answer; once it
    /// goes silent and its trust lapses, the public path's next pong takes over (Go promotes the
    /// ponging address whenever the best is untrusted). A selection that re-elected the LAN path
    /// from its remembered latency and bonus left the peer on DERP here, with the public path
    /// answering every ping.
    #[test]
    fn live_public_path_takes_over_from_a_silent_lan_best() {
        let mut p = PeerPaths::default();
        let lan: SocketAddr = "192.168.50.76:41644".parse().unwrap();
        let public: SocketAddr = "203.0.113.34:41644".parse().unwrap();
        p.add_netmap_candidates([lan, public]);
        let now = Instant::now();
        p.note_ping_sent(tx(1), lan, now);
        p.note_pong(tx(1), lan, now + Duration::from_millis(2));
        p.note_ping_sent(tx(2), public, now);
        p.note_pong(tx(2), public, now + Duration::from_micros(1_800));
        // The LAN path is best here (`lan_path_stays_best_against_faster_public_hairpin`). Not
        // asserted, so the test also holds on a latency-only selection, which picks the public path.

        // The LAN path goes silent. Only the public path answers, past the LAN path's trust window.
        let t1 = now + TRUST_DURATION + Duration::from_secs(1);
        p.note_ping_sent(tx(3), lan, t1);
        p.note_ping_sent(tx(4), public, t1);
        p.note_pong(tx(4), public, t1 + Duration::from_micros(1_800));
        assert_eq!(
            p.best_addr(t1 + Duration::from_millis(3)),
            Some(public),
            "a live public path must take over once the silent LAN best's trust lapses"
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

    /// A good-enough best (≤5ms) quiets discovery of the OTHER (already-probed) candidates: once the
    /// first full sweep has probed every candidate, a subsequent quiet cycle refreshes only the best.
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
        // has long since happened by the time a path is good-enough-confirmed.) It pings both and
        // stamps `last_full_ping`, arming the good-enough quiet-down. Stamp the sends, as the real
        // `send_pings` caller does, so `b` is no longer a never-pinged candidate.
        let t1 = t + Duration::from_millis(1);
        let first = p.candidates_to_ping(t1);
        assert!(
            first.contains(&a) && first.contains(&b),
            "first cycle (lastFullPing zero) is a full sweep, matching Go wantFullPingLocked"
        );
        p.note_ping_sent(tx(2), a, t1);
        p.note_ping_sent(tx(3), b, t1);

        // The NEXT cycle, still inside the upgrade interval, returns ONLY the best (a); the rival b
        // is now quieted by the good-enough best (and has been probed, so the never-pinged
        // exemption does not apply to it).
        let pinged = p.candidates_to_ping(t + Duration::from_secs(1));
        assert_eq!(
            pinged,
            vec![a],
            "good-enough best quiets non-best discovery; only the best is refreshed"
        );
    }

    /// A good-enough best (≤5ms) is quieted **indefinitely** — matching Go `wantFullPingLocked`,
    /// whose good-enough rung returns `false` and short-circuits *before* the upgrade-interval rung.
    /// So even long after `UPGRADE_UDP_DIRECT_INTERVAL`, an already-probed rival is NOT re-probed: Go
    /// never upgrades away from a ≤5ms path (only a trust lapse or a latency rise re-opens
    /// discovery). Asserting the opposite would encode non-Go behavior as if it were parity.
    #[test]
    fn good_enough_best_is_quieted_indefinitely() {
        let mut p = PeerPaths::default();
        let a: SocketAddr = "203.0.113.1:41641".parse().unwrap();
        let b: SocketAddr = "203.0.113.2:41641".parse().unwrap();
        p.add_netmap_candidates([a, b]);
        let now = Instant::now();

        // Confirm `a` good-enough (3ms); first cycle full-sweeps both and arms the quiet-down.
        p.note_ping_sent(tx(1), a, now);
        p.note_pong(tx(1), a, now + Duration::from_millis(3));
        let t = now + Duration::from_millis(3);
        let first = p.candidates_to_ping(t);
        assert!(first.contains(&a) && first.contains(&b));
        p.note_ping_sent(tx(2), a, t);
        p.note_ping_sent(tx(3), b, t);

        // Keep `a` trusted across the upgrade interval by re-confirming it (the heartbeat the real
        // pinger performs every PING_INTERVAL). Without this `a`'s trust would lapse and rung 1
        // (no trusted best) would force a full sweep for the wrong reason.
        let late = t + Duration::from_secs(61);
        p.note_ping_sent(tx(4), a, late - Duration::from_millis(3));
        p.note_pong(tx(4), a, late); // still 3ms → good-enough, trust refreshed
        assert_eq!(p.best_addr(late), Some(a));

        // 61s after the only full sweep, with `a` still good-enough: the rival b is STILL quieted —
        // no upgrade re-probe (Go's good-enough rung short-circuited the upgrade rung).
        let pinged = p.candidates_to_ping(late);
        assert_eq!(
            pinged,
            vec![a],
            "a good-enough best is quieted indefinitely; the upgrade interval never fires for it"
        );
    }

    /// A working-but-MEDIOCRE best (latency > GOOD_ENOUGH_LATENCY) IS re-probed every
    /// `UPGRADE_UDP_DIRECT_INTERVAL` — Go `wantFullPingLocked`'s final rung, reached only because the
    /// good-enough rung does NOT short-circuit. This is where Go periodically hunts for a better path
    /// away from a usable-but-slow direct path.
    #[test]
    fn mediocre_best_reprobes_candidates_on_upgrade_interval() {
        let mut p = PeerPaths::default();
        let a: SocketAddr = "203.0.113.1:41641".parse().unwrap();
        let b: SocketAddr = "203.0.113.2:41641".parse().unwrap();
        p.add_netmap_candidates([a, b]);
        let now = Instant::now();

        // Confirm `a` at 50ms (> GOOD_ENOUGH_LATENCY) → best, but NOT good-enough.
        p.note_ping_sent(tx(1), a, now);
        p.note_pong(tx(1), a, now + Duration::from_millis(50));
        let t = now + Duration::from_millis(50);
        let first = p.candidates_to_ping(t);
        assert!(first.contains(&a) && first.contains(&b));
        p.note_ping_sent(tx(2), a, t);
        p.note_ping_sent(tx(3), b, t);

        // Keep `a` trusted (and still mediocre) across the interval via re-confirmation.
        let late = t + Duration::from_secs(61);
        p.note_ping_sent(tx(4), a, late - Duration::from_millis(50));
        p.note_pong(tx(4), a, late); // still 50ms → mediocre, trust refreshed
        assert_eq!(p.best_addr(late), Some(a));

        // 61s after the last full sweep, with a mediocre best: the upgrade is due → b is re-probed
        // alongside the best a.
        let mut pinged = p.candidates_to_ping(late);
        pinged.sort();
        let mut want = vec![a, b];
        want.sort();
        assert_eq!(
            pinged, want,
            "a mediocre best re-probes all candidates after UPGRADE_UDP_DIRECT_INTERVAL"
        );
    }

    /// A candidate learned DURING the good-enough quiet period (never yet pinged) still gets one
    /// prompt probe — mirroring Go pinging a freshly-learned endpoint via the event-driven
    /// `CallMeMaybe` `sendDiscoPingsLocked`, rather than starving it until trust lapses. An
    /// already-probed rival stays quiet; only the never-pinged newcomer is exempt.
    #[test]
    fn never_pinged_candidate_probed_promptly_during_quiet() {
        let mut p = PeerPaths::default();
        let a: SocketAddr = "203.0.113.1:41641".parse().unwrap();
        let b: SocketAddr = "203.0.113.2:41641".parse().unwrap();
        p.add_netmap_candidates([a, b]);
        let now = Instant::now();

        // Confirm `a` good-enough; first cycle full-sweeps a+b and arms the quiet-down; stamp sends.
        p.note_ping_sent(tx(1), a, now);
        p.note_pong(tx(1), a, now + Duration::from_millis(3));
        let t = now + Duration::from_millis(3);
        let first = p.candidates_to_ping(t);
        assert!(first.contains(&a) && first.contains(&b));
        p.note_ping_sent(tx(2), a, t);
        p.note_ping_sent(tx(3), b, t);

        // A brand-new candidate `c` arrives mid-quiet-period (e.g. a fresh CallMeMaybe address).
        let c: SocketAddr = "203.0.113.3:41641".parse().unwrap();
        p.add_learned_candidates([c]);

        // Next quiet cycle (good-enough a, within the upgrade interval): the already-probed rival b
        // stays quiet, but the never-pinged c is probed promptly alongside the best a.
        let pinged = p.candidates_to_ping(t + Duration::from_secs(1));
        assert!(pinged.contains(&a), "best still refreshed");
        assert!(
            pinged.contains(&c),
            "never-pinged newcomer probed promptly during the good-enough quiet period"
        );
        assert!(
            !pinged.contains(&b),
            "an already-probed rival stays quieted by the good-enough best"
        );
    }

    /// A disco-key change drops the trust window and resets path discovery, but KEEPS the best
    /// address and the candidate set — Go `endpoint.changedActiveDiscoLocked`.
    ///
    /// The positive half: `best_addr` reports no trusted path (so the caller falls back to DERP),
    /// and the peer is immediately re-probed — the candidate is returned by `candidates_to_ping`
    /// even though it was pinged well inside the `DISCO_PING_INTERVAL` floor, which without the
    /// reset would have deferred re-discovery by up to 5s.
    #[test]
    fn disco_key_change_drops_trust_and_reprobes_now() {
        let mut p = PeerPaths::default();
        let addr: SocketAddr = "203.0.113.1:41641".parse().unwrap();
        p.add_netmap_candidates([addr]);

        let now = Instant::now();
        p.note_ping_sent(tx(1), addr, now);
        p.note_pong(tx(1), addr, now + Duration::from_millis(10));
        // A second probe still awaiting its pong, to pin that in-flight state is dropped too.
        p.note_ping_sent(tx(2), addr, now + Duration::from_millis(20));
        let t = now + Duration::from_millis(30);
        assert_eq!(
            p.best_addr(t),
            Some(addr),
            "precondition: a trusted direct path"
        );
        assert_eq!(p.in_flight_len(), 1, "precondition: a probe is in flight");

        p.invalidate_disco_path();

        assert_eq!(
            p.best_addr(t),
            None,
            "a pong sealed under the peer's old disco key must no longer be trusted"
        );
        assert_eq!(
            p.best_addr_and_latency(t),
            None,
            "and the reported direct-path RTT goes with it"
        );
        assert_eq!(
            p.in_flight_len(),
            0,
            "a probe sent to the old key must not be able to confirm a path across the rotation"
        );
        assert!(
            p.needs_refresh(t),
            "an untrusted path always wants a re-ping"
        );
        assert_eq!(
            p.candidates_to_ping(t),
            vec![addr],
            "the candidate is re-probed now, not after the DISCO_PING_INTERVAL floor"
        );
    }

    /// The negative half, which is what gives the change its value: the disco-key change does NOT
    /// clear `best` or the candidate set. Upstream keeps `bestAddr` "so that we can still send data
    /// while we find a new path"; here the retained address is the one the immediate re-probe
    /// targets, and a single fresh pong on it restores the trusted direct path.
    #[test]
    fn disco_key_change_keeps_the_best_address_and_candidates() {
        let mut p = PeerPaths::default();
        let best: SocketAddr = "203.0.113.1:41641".parse().unwrap();
        let other: SocketAddr = "198.51.100.4:41641".parse().unwrap();
        p.add_netmap_candidates([best]);
        p.add_learned_candidates([other]);

        let now = Instant::now();
        p.note_ping_sent(tx(1), best, now);
        p.note_pong(tx(1), best, now + Duration::from_millis(5));
        let t = now + Duration::from_millis(6);
        assert_eq!(
            p.best_addr(t),
            Some(best),
            "precondition: `best` is confirmed"
        );

        p.invalidate_disco_path();

        assert_eq!(
            p.stored_best(),
            Some(best),
            "the best address is kept across a disco-key change (only its trust is dropped)"
        );
        let mut candidates = p.candidate_addrs();
        candidates.sort();
        let mut want = vec![best, other];
        want.sort();
        assert_eq!(
            candidates, want,
            "both control-advertised and learned candidates survive the rotation"
        );

        // One fresh pong under the new key re-confirms the same path: traffic returns to it after a
        // single round trip rather than after a full TRUST_DURATION.
        let reping = t + Duration::from_millis(1);
        p.note_ping_sent(tx(2), best, reping);
        assert_eq!(
            p.note_pong(tx(2), best, reping + Duration::from_millis(5)),
            Some(Duration::from_millis(5))
        );
        assert_eq!(
            p.best_addr(reping + Duration::from_millis(6)),
            Some(best),
            "a pong under the new disco key restores the trusted direct path"
        );
    }

    /// A pre-rotation latency must not be able to re-trust a path without a fresh pong for it: the
    /// disco-key change clears every measurement (asserted directly), and a pong for a *slower*
    /// rival then makes that rival the best rather than promoting the remembered (and possibly
    /// dead) fast address.
    ///
    /// The selection part is upstream's outcome by upstream's mechanism: `handlePongConnLocked`
    /// compares only the address that just ponged with the best and promotes it whenever the best
    /// is out of trust (`betterAddr(thisPong, de.bestAddr) || bestUntrusted`), and
    /// `changedActiveDiscoLocked` is precisely what puts it out of trust; `recompute_best` does the
    /// same, so a remembered latency can never take part. Go keeps its `recentPongs` across
    /// `invalidateDiscoPathLocked` and this tree clears them, which only diagnostics can tell
    /// apart. What must never happen in either tree is the thing this asserts against: a path
    /// trusted again without having answered under the key the peer is using now.
    #[test]
    fn disco_key_change_forgets_pre_rotation_latencies() {
        let mut p = PeerPaths::default();
        let fast: SocketAddr = "203.0.113.1:41641".parse().unwrap();
        let slow: SocketAddr = "198.51.100.4:41641".parse().unwrap();
        p.add_netmap_candidates([fast, slow]);

        let now = Instant::now();
        p.note_ping_sent(tx(1), fast, now);
        p.note_pong(tx(1), fast, now + Duration::from_millis(2));
        assert_eq!(p.best_addr(now + Duration::from_millis(3)), Some(fast));

        p.invalidate_disco_path();
        assert_eq!(
            p.stored_latency(fast),
            None,
            "a disco-key change must clear every pre-rotation latency"
        );
        assert!(
            p.candidate_addrs().contains(&fast),
            "...while the candidate itself stays, to be re-probed under the new key"
        );

        // Only `slow` answers under the new key.
        let t = now + Duration::from_millis(10);
        p.note_ping_sent(tx(2), slow, t);
        p.note_pong(tx(2), slow, t + Duration::from_millis(60));
        assert_eq!(
            p.best_addr(t + Duration::from_millis(61)),
            Some(slow),
            "only a path re-confirmed under the new key may be trusted, even if a stale \
             measurement for another candidate was faster"
        );
    }

    /// The rebind invalidation is the stricter sibling and must stay that way: a rebind changed the
    /// *local* mapping, so the best address is stale as an address and is cleared outright, whereas
    /// a disco-key change keeps it.
    #[test]
    fn rebind_clears_the_best_address_unlike_a_disco_key_change() {
        let mut p = PeerPaths::default();
        let addr: SocketAddr = "203.0.113.1:41641".parse().unwrap();
        p.add_netmap_candidates([addr]);

        let now = Instant::now();
        p.note_ping_sent(tx(1), addr, now);
        p.note_pong(tx(1), addr, now + Duration::from_millis(5));
        assert_eq!(p.best_addr(now + Duration::from_millis(6)), Some(addr));

        p.invalidate_best();

        assert_eq!(
            p.stored_best(),
            None,
            "a rebind drops the best address itself, not just its trust"
        );
        assert_eq!(
            p.candidate_addrs(),
            vec![addr],
            "but the candidate set survives a rebind too"
        );
    }

    /// A peer with one confirmed, trusted, good-enough best path, plus the instant at which the
    /// caller's `needs_refresh` gate first fires for it — i.e. the tick on which the best-path
    /// heartbeat would go out. Shared by the silent-disco tests so each one differs only in the
    /// flag and in what arrives.
    fn confirmed_best(addr: SocketAddr, t0: Instant) -> (PeerPaths, Instant) {
        let mut p = PeerPaths::default();
        p.add_netmap_candidates([addr]);
        p.note_ping_sent(tx(1), addr, t0);
        p.note_pong(tx(1), addr, t0 + Duration::from_millis(1));
        // `needs_refresh` fires REFRESH_BEFORE_EXPIRY ahead of `trust_until`; one ms past that is
        // the first tick on which the caller would ask for candidates.
        let refresh_at = t0 + TRUST_DURATION - REFRESH_BEFORE_EXPIRY + Duration::from_millis(1);
        (p, refresh_at)
    }

    /// The suppression half of silent disco, and its control: the *only* difference between the two
    /// halves of this test is the flag. Without it the confirmed best is re-pinged on the refresh
    /// tick, which is this fork's heartbeat; with it nothing is sent at all. Go
    /// `endpoint.heartbeat`'s `if de.heartbeatDisabled { return }`, folded into the one place this
    /// tree decides what to ping.
    #[test]
    fn silent_disco_suppresses_the_best_path_heartbeat() {
        let addr: SocketAddr = "203.0.113.1:41641".parse().unwrap();
        let t0 = Instant::now();

        let (mut heartbeating, refresh_at) = confirmed_best(addr, t0);
        assert!(
            heartbeating.needs_refresh(refresh_at),
            "precondition: the caller's gate is open, so this tick really does reach \
             candidates_to_ping — otherwise the silent half below would be vacuous"
        );
        assert_eq!(
            heartbeating.candidates_to_ping(refresh_at),
            vec![addr],
            "without the attribute the best path is re-pinged on the refresh tick, unfloored"
        );

        let (mut silent, _) = confirmed_best(addr, t0);
        silent.set_heartbeat_disabled(true);
        assert!(
            !silent.needs_refresh(refresh_at),
            "control set silent-disco: the prober's gate stays shut while the path is trusted, \
             so the peer is not even considered on this tick"
        );
        assert!(
            silent.candidates_to_ping(refresh_at).is_empty(),
            "and were it considered anyway, no disco ping is emitted to this peer"
        );

        // Withdrawing the attribute restores the heartbeat on the very next tick — the attribute is
        // live, not start-time, and nothing had to be rediscovered.
        silent.set_heartbeat_disabled(false);
        assert_eq!(
            silent.candidates_to_ping(refresh_at),
            vec![addr],
            "withdrawing the attribute returns the peer to the heartbeat cadence"
        );
    }

    /// The compensating half, and the reason it is not optional: with the heartbeat suppressed and
    /// data flowing, the best path stays trusted — it is NOT demoted to DERP — and still nothing is
    /// pinged. Every tick here is past the point at which the unported flag alone would have let
    /// `TRUST_DURATION` lapse on a path that is demonstrably alive.
    #[test]
    fn silent_disco_keeps_the_best_trusted_while_data_flows() {
        let addr: SocketAddr = "203.0.113.1:41641".parse().unwrap();
        let t0 = Instant::now();
        let (mut p, _) = confirmed_best(addr, t0);
        p.set_heartbeat_disabled(true);

        // Data every 2s for 20s — four times the trust window, so a lapse anywhere would show.
        for secs in [2, 4, 6, 8, 10, 12, 14, 16, 18, 20] {
            let now = t0 + Duration::from_secs(secs);
            p.note_recv_activity(addr, now);
            assert_eq!(
                p.best_addr(now),
                Some(addr),
                "at {secs}s the path carrying data must still be the trusted best, not DERP"
            );
            assert!(
                !p.needs_refresh(now),
                "at {secs}s inbound data has refreshed trust, so the caller never even asks for \
                 candidates"
            );
            assert!(
                p.candidates_to_ping(now).is_empty(),
                "at {secs}s no disco ping may be emitted to this peer"
            );
        }
    }

    /// What the compensating arm is compensating for. With the attribute set and NO inbound data
    /// the path lapses exactly as it always did and discovery resumes — so the arm above is what
    /// holds an active path up, not some incidental side effect of the flag.
    #[test]
    fn silent_disco_without_inbound_data_still_lets_trust_lapse() {
        let addr: SocketAddr = "203.0.113.1:41641".parse().unwrap();
        let t0 = Instant::now();
        let (mut p, _) = confirmed_best(addr, t0);
        p.set_heartbeat_disabled(true);

        let lapsed = t0 + TRUST_DURATION + Duration::from_secs(1);
        assert_eq!(
            p.best_addr(lapsed),
            None,
            "no data arrived, so nothing refreshed trust and the peer falls back to DERP"
        );
        assert!(
            p.needs_refresh(lapsed),
            "with no trusted path left the prober's gate reopens even under the attribute"
        );
        assert_eq!(
            p.candidates_to_ping(lapsed),
            vec![addr],
            "and discovery still probes the candidate, as it does in Go when trust has lapsed"
        );
    }

    /// The arm is narrow in both directions, as upstream writes it. Without the attribute inbound
    /// data does not extend trust at all (the heartbeat's pong is what does that), and with the
    /// attribute only the *best* address counts — a packet from a rival candidate proves nothing
    /// about the best.
    #[test]
    fn note_recv_activity_only_fires_for_the_best_under_the_attribute() {
        let best: SocketAddr = "203.0.113.1:41641".parse().unwrap();
        let rival: SocketAddr = "203.0.113.2:41641".parse().unwrap();
        let t0 = Instant::now();
        let lapsed = t0 + TRUST_DURATION + Duration::from_secs(1);
        let data_at = t0 + Duration::from_secs(5);

        // Heartbeat running: data on the best changes nothing.
        let (mut heartbeating, _) = confirmed_best(best, t0);
        heartbeating.note_recv_activity(best, data_at);
        assert_eq!(
            heartbeating.best_addr(lapsed),
            None,
            "with the heartbeat running, trust is extended by pongs and not by data"
        );

        // Attribute set, but the data came from a different candidate.
        let (mut silent, _) = confirmed_best(best, t0);
        silent.add_netmap_candidates([rival]);
        silent.set_heartbeat_disabled(true);
        silent.note_recv_activity(rival, data_at);
        assert_eq!(
            silent.best_addr(lapsed),
            None,
            "data from a non-best candidate must not extend the best path's trust"
        );
    }

    /// Ported verbatim, including the part that looks like an oversight and is not: Go compares
    /// against `de.bestAddr` without consulting the trust window, so data arriving on a best whose
    /// trust has *just* lapsed re-trusts it rather than forcing a DERP round trip to rediscover a
    /// path that is plainly carrying traffic.
    #[test]
    fn note_recv_activity_re_trusts_a_best_whose_trust_lapsed() {
        let addr: SocketAddr = "203.0.113.1:41641".parse().unwrap();
        let t0 = Instant::now();
        let (mut p, _) = confirmed_best(addr, t0);
        p.set_heartbeat_disabled(true);

        let lapsed = t0 + TRUST_DURATION + Duration::from_secs(1);
        assert_eq!(p.best_addr(lapsed), None, "precondition: trust has lapsed");

        p.note_recv_activity(addr, lapsed);
        assert_eq!(
            p.best_addr(lapsed),
            Some(addr),
            "a datagram on the stored best re-trusts it for a full TRUST_DURATION"
        );
    }

    /// Go `endpoint.heartbeat` (`endpoint.go`): while a peer has traffic its best path is re-pinged
    /// and never loses trust; once the traffic has been gone for `SESSION_ACTIVE_TIMEOUT` the
    /// heartbeat ends, nothing more is pinged, and the path's trust lapses so the peer rides DERP
    /// until traffic resumes.
    #[test]
    fn an_active_peer_keeps_its_direct_path_through_heartbeats_until_it_goes_idle() {
        let addr: SocketAddr = "203.0.113.1:41641".parse().unwrap();
        let mut p = PeerPaths::default();
        p.add_netmap_candidates([addr]);

        let t0 = Instant::now();
        let traffic_stops = Duration::from_secs(60);
        let heartbeat_ends = traffic_stops + SESSION_ACTIVE_TIMEOUT;
        let rtt = Duration::from_millis(1);
        let mut next_tx = 0u8;
        let mut last_ping = None;

        // The periodic pinger's 2s ticks, for three minutes.
        for secs in (0..=180).step_by(2) {
            let at = Duration::from_secs(secs);
            let now = t0 + at;
            if at <= traffic_stops {
                p.note_active(now);
            }
            for to in p.pings_due(now) {
                next_tx = next_tx.wrapping_add(1);
                p.note_ping_sent(tx(next_tx), to, now);
                p.note_pong(tx(next_tx), to, now + rtt);
                last_ping = Some(at);
            }

            let trusted = p.best_addr(now + rtt).is_some();
            if at <= heartbeat_ends {
                assert!(
                    trusted,
                    "an active peer's direct path must stay trusted at {at:?}"
                );
            }
            if at > heartbeat_ends + TRUST_DURATION {
                assert!(
                    !trusted,
                    "an idle peer's path must not be kept alive by heartbeats at {at:?}"
                );
            }
        }

        let last_ping = last_ping.expect("the active peer was heartbeated");
        assert!(
            last_ping <= heartbeat_ends,
            "the heartbeat must stop {SESSION_ACTIVE_TIMEOUT:?} after the traffic does; last ping \
             at {last_ping:?}"
        );
    }
}
