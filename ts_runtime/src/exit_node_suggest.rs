//! Exit-node suggestion: pick a reasonably good exit node from the netmap + latest netcheck report.
//!
//! This is the Rust port of Go `ipnlocal`'s `suggestExitNodeUsingDERP` (the classic DERP-region
//! -latency path; tailscale v1.100.0 `ipn/ipnlocal/local.go`), surfaced as
//! [`Runtime::suggest_exit_node`](crate::Runtime::suggest_exit_node) and consumed by the daemon's
//! `tnet exit-node suggest`. The traffic-steering path (`NodeAttrTrafficSteering`) and the Mullvad
//! geo-distance path are **Phase 2** and deliberately not ported here (see `suggest_exit_node`).
//!
//! ## Determinism contract (this corrects a common misconception)
//!
//! There is **no** seed/hash tiebreak. Determinism comes from exactly two places, mirroring Go:
//! 1. the lowest-latency region wins, with the lowest region id as the tiebreak
//!    (`min_latency_derp_region`); and
//! 2. `prev_suggestion` **stickiness** — if the previously-suggested node is still among the
//!    region's candidates it is kept (see `random_node`).
//!
//! The final pick among equally-good ties is *uniform random* and varies run-to-run (Go's own doc
//! says "the result is not stable"). So that the algorithm stays unit-testable, the region pick and
//! the node pick are taken as **injected closures** ([`SelectRegion`](crate::exit_node_suggest::SelectRegion)
//! / [`SelectNode`](crate::exit_node_suggest::SelectNode)); production passes the uniform-random
//! `random_region` / `random_node`, and tests pass deterministic stubs. This is a direct port of
//! Go's `selectRegionFunc` / `selectNodeFunc` parameters.

use ts_control::StableNodeId;
use ts_derp::RegionId;

use crate::status::NetcheckReport;

/// A peer being considered as an exit-node suggestion, carrying exactly the inputs the suggestion
/// algorithm reads. Built (in [`Runtime::suggest_exit_node`](crate::Runtime::suggest_exit_node))
/// from a domain [`Node`](ts_control::Node); kept as a small standalone struct so the algorithm is a
/// pure function over its inputs (unit-testable without the actor graph, mirroring how the runtime's
/// `build_file_targets` factors out the file-target rules).
///
/// The eligibility predicate (`is_eligible`) is applied *inside* the `suggest_exit_node` function,
/// so callers pass every peer and the pure function does the filtering — this keeps the predicate
/// itself covered by the same tests as the selection logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitNodeCandidate {
    /// The peer's stable node id (`Node.StableID()`), the identity returned in the suggestion and
    /// matched against `prev_suggestion` for stickiness.
    pub stable_id: StableNodeId,
    /// The peer's display name (`Node.Name()`), echoed into the suggestion.
    pub name: String,
    /// The peer's home DERP region (`Node.HomeDERP()`), or `None` when it has no DERP home (Go
    /// `HomeDERP == 0`; typically a Mullvad node). A region-less candidate is only ever selected
    /// when *no* DERP-homed candidate exists (the Phase-2 geo path), so under Phase 1 it falls back
    /// to a region-less [`SelectNode`] pick. Mirrors the domain
    /// [`Node::derp_region`](ts_control::Node::derp_region).
    pub derp_region: Option<RegionId>,
    /// Whether control reports the peer online (`Node.Online == Some(true)`). The default
    /// reachability gate (Go `PeerIsReachable` without `NodeAttrClientSideReachability`) is
    /// `online == Some(true)`; a tri-state `None`/`Some(false)` is treated as *not reachable*
    /// (fail-closed — never suggest a peer control has not asserted is up).
    pub online: Option<bool>,
    /// Whether the peer advertises an exit route. Per the IPv4-only fork parity decision (see the
    /// `suggest_exit_node` function) this is `true` when the peer advertises `0.0.0.0/0`
    /// (`prefix_len == 0`), matching the fork's family-agnostic
    /// [`StatusNode::is_exit_node`](crate::status::StatusNode::is_exit_node) check — *not* Go's
    /// strict both-`0.0.0.0/0`-and-`::/0` `tsaddr.ContainsExitRoutes`.
    pub advertises_exit_route: bool,
    /// Whether the peer carries the `suggest-exit-node` node-capability
    /// ([`NODE_ATTR_SUGGEST_EXIT_NODE`](ts_control::NODE_ATTR_SUGGEST_EXIT_NODE)) in its `CapMap` —
    /// control's marker that the peer may be auto-suggested. Checked via
    /// [`Node::has_node_attr`](ts_control::Node::has_node_attr).
    pub has_suggest_cap: bool,
}

impl ExitNodeCandidate {
    /// Whether this peer is eligible to be suggested, mirroring Go's `AppendMatchingPeers` predicate
    /// in `suggestExitNodeUsingDERP`: it must be reachable (online), carry the `suggest-exit-node`
    /// cap, and advertise an exit route. (Go also requires `peer.Valid()` and an allow-list
    /// membership check; a domain [`Node`](ts_control::Node) we hold is always valid, and this fork
    /// has no `AllowedSuggestedExitNodes` policy yet, so that gate is allow-all — both are noted on
    /// the `suggest_exit_node` function.) Fail-closed: any missing condition excludes the peer.
    fn is_eligible(&self) -> bool {
        self.online == Some(true) && self.has_suggest_cap && self.advertises_exit_route
    }
}

/// The result of an exit-node suggestion — the Rust analog of Go
/// `apitype.ExitNodeSuggestionResponse`.
///
/// Carries the suggested peer's [`stable id`](Self::id) and [`name`](Self::name). Go also carries a
/// `Location` (`omitempty`); this fork's domain [`Node`](ts_control::Node) does not retain a peer
/// location yet, so **Location is deferred to Phase 2** (when the Mullvad geo path lands) and is
/// omitted here. A `None` suggestion (no eligible candidate) is represented by the caller returning
/// `Ok(None)`, exactly as Go returns an empty response with a nil error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitNodeSuggestion {
    /// The suggested exit node's stable id (`apitype.ExitNodeSuggestionResponse.ID`). Pass this to
    /// [`Config::exit_node`](ts_control::Config) / `set_exit_node` as a
    /// [`StableId`](ts_control::ExitNodeSelector::StableId) selector to engage it.
    pub id: StableNodeId,
    /// The suggested exit node's display name (`apitype.ExitNodeSuggestionResponse.Name`), for
    /// surfacing to the user (the daemon prints it with a `--exit-node=` hint).
    pub name: String,
}

/// Why an exit-node suggestion could not be produced — the Rust analog of Go's `ErrNoPreferredDERP`.
///
/// This is distinct from "no suggestion": an empty result (no eligible candidate) is `Ok(None)`,
/// not an error (mirroring Go returning an empty response with a nil error). The only error state in
/// the Phase-1 DERP path is the precondition failure below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuggestExitNodeError {
    /// No usable netcheck report yet: there is no measured preferred DERP region
    /// ([`NetcheckReport::preferred_derp`] is `None`/`0`), so the latency-based region ranking can't
    /// run. Go returns `ErrNoPreferredDERP` ("no preferred DERP, try again later"); callers tolerate
    /// it and retry once a netcheck has completed.
    NoPreferredDerp,
}

impl core::fmt::Display for SuggestExitNodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoPreferredDerp => write!(f, "no preferred DERP, try again later"),
        }
    }
}

impl core::error::Error for SuggestExitNodeError {}

/// A region-selection closure: given the candidate regions (those with at least one DERP-homed
/// candidate), return one to draw the suggestion from. Port of Go's `selectRegionFunc`. Only invoked
/// as the fallback when no region has a usable measured latency (`min_latency_derp_region` returns
/// `None`); production passes the uniform `random_region`, tests pass a deterministic stub.
pub type SelectRegion<'a> = dyn Fn(&[RegionId]) -> RegionId + 'a;

/// A node-selection closure: given a region's candidates and the previous suggestion, return the
/// chosen one. Port of Go's `selectNodeFunc`. Encapsulates the `prev_suggestion` **stickiness** plus
/// the uniform-random fallback; production passes `random_node`, tests pass a deterministic stub.
/// The slice is always non-empty when invoked.
pub type SelectNode<'a> =
    dyn Fn(&[ExitNodeCandidate], Option<&StableNodeId>) -> ExitNodeCandidate + 'a;

/// Suggest an exit node from `candidates` given the latest netcheck `report` and the previous
/// suggestion (for stickiness). Pure port of Go `suggestExitNodeUsingDERP` (v1.100.0), the classic
/// DERP-region-latency path.
///
/// `select_region` / `select_node` are injected (Go's `selectRegionFunc` / `selectNodeFunc`) so the
/// algorithm is deterministic under test; production passes `random_region` / `random_node`.
///
/// Returns:
/// - `Err(`[`SuggestExitNodeError::NoPreferredDerp`]`)` when `report.preferred_derp` is `None`/`0`
///   (Go's `ErrNoPreferredDERP` precondition — no netcheck yet).
/// - `Ok(None)` when no candidate is eligible (Go's empty response + nil error — *not* an error).
/// - `Ok(Some(suggestion))` otherwise.
///
/// ## Algorithm (faithful to Go)
/// 1. Precondition: a preferred DERP region must exist, else `NoPreferredDerp`.
/// 2. Filter to eligible candidates (`ExitNodeCandidate::is_eligible`). 0 ⇒ `Ok(None)`.
/// 3. Exactly 1 ⇒ return it directly (no region/RNG logic), as Go does.
/// 4. 2+ ⇒ partition by home DERP region. If any candidate is DERP-homed: `min_region` =
///    lowest-latency region (tiebreak lowest id); if no region has a usable latency, fall back to
///    `select_region`. Then `select_node` picks within `min_region` (stickiness or random). A
///    region-less candidate is only considered when *no* DERP-homed candidate exists.
///
/// ## Phase-1 scope / deviations from Go (documented, deliberate)
/// - **IPv4-only exit-route check.** Go's candidate predicate requires `tsaddr.ContainsExitRoutes`
///   = advertising *both* `0.0.0.0/0` **and** `::/0`. This fork is IPv4-only (a SACRED invariant),
///   so its peers advertise only `0.0.0.0/0`; a verbatim port would suggest nothing on every fork
///   tailnet. Per the resolved parity decision (`docs/DEFERRED-QUESTIONS.md`), a candidate is
///   accepted on `0.0.0.0/0` alone ([`ExitNodeCandidate::advertises_exit_route`]), matching the
///   fork's family-agnostic exit-node check.
/// - **No traffic-steering path.** Go's `suggestExitNode` first dispatches to
///   `suggestExitNodeUsingTrafficSteering` when the tailnet sets `NodeAttrTrafficSteering`; that
///   path is Phase 2 and not ported (this is the `else` branch only).
/// - **No Mullvad geo path / no `AllowedSuggestedExitNodes` policy.** When *no* candidate has a DERP
///   home, Go ranks region-less (Mullvad) candidates by geographic distance + location priority.
///   This fork's domain node carries no location, so the geo weighting is deferred to Phase 2;
///   under Phase 1 a purely region-less candidate set falls back to `select_node` over all
///   candidates *without* geo weighting (the simplest faithful behavior). The allow-list gate is
///   likewise absent (allow-all) since the fork has no such policy yet.
/// - **`Location` omitted** from the result (the domain node has none yet) — see
///   [`ExitNodeSuggestion`].
pub(crate) fn suggest_exit_node(
    report: &NetcheckReport,
    candidates: &[ExitNodeCandidate],
    prev_suggestion: Option<&StableNodeId>,
    select_region: &SelectRegion<'_>,
    select_node: &SelectNode<'_>,
) -> Result<Option<ExitNodeSuggestion>, SuggestExitNodeError> {
    // 1. Precondition: a measured preferred DERP region must exist (Go: report == nil ||
    //    report.PreferredDERP == 0 || no DERPMap ⇒ ErrNoPreferredDERP). The fork's report carries no
    //    DERPMap (it isn't needed for the DERP-latency path), so the gate is "preferred_derp set and
    //    non-zero". A `Some(0)` is impossible (region ids are NonZeroU32-derived) but guarded anyway.
    match report.preferred_derp {
        None | Some(0) => return Err(SuggestExitNodeError::NoPreferredDerp),
        Some(_) => {}
    }

    // 2. Filter to eligible candidates (Go's AppendMatchingPeers predicate).
    let eligible: Vec<&ExitNodeCandidate> = candidates.iter().filter(|c| c.is_eligible()).collect();

    // 3. 0 ⇒ no suggestion (Go: empty response, nil error). 1 ⇒ return it directly (no RNG).
    match eligible.as_slice() {
        [] => return Ok(None),
        [only] => {
            return Ok(Some(ExitNodeSuggestion {
                id: only.stable_id.clone(),
                name: only.name.clone(),
            }));
        }
        _ => {}
    }

    // 4. Partition the 2+ eligible candidates by home DERP region. Region-less candidates are held
    //    separately and only used when NO DERP-homed candidate exists (Go: "never select a candidate
    //    without a DERP home if there is a candidate available with a DERP home").
    let mut by_region: std::collections::BTreeMap<RegionId, Vec<ExitNodeCandidate>> =
        std::collections::BTreeMap::new();
    let mut region_less: Vec<ExitNodeCandidate> = Vec::new();
    for c in eligible {
        match c.derp_region {
            Some(region) => by_region.entry(region).or_default().push(c.clone()),
            None => region_less.push(c.clone()),
        }
    }

    if !by_region.is_empty() {
        // DERP-homed path (the Phase-1 common case). Pick the lowest-latency region (tiebreak lowest
        // id); if none has a usable latency, fall back to the injected region selector.
        let regions: Vec<RegionId> = by_region.keys().copied().collect();
        let min_region = match min_latency_derp_region(&regions, report) {
            Some(region) => region,
            None => select_region(&regions),
        };
        // `min_region` is always a key of `by_region` (it came from `regions`, the key set, whether
        // via the latency ranking or the selector restricted to those keys). The selectors never
        // invent a region — Go treats a miss here as "this is a bug".
        let region_candidates = by_region
            .get(&min_region)
            .expect("selected region must be a candidate region");
        let chosen = select_node(region_candidates, prev_suggestion);
        return Ok(Some(ExitNodeSuggestion {
            id: chosen.stable_id,
            name: chosen.name,
        }));
    }

    // No DERP-homed candidate: Phase-1 fallback over the region-less set without geo weighting (the
    // Mullvad geo-distance + priority ranking is Phase 2 — see the doc comment). `region_less` is
    // non-empty here (we had 2+ eligible candidates and none was DERP-homed).
    let chosen = select_node(&region_less, prev_suggestion);
    Ok(Some(ExitNodeSuggestion {
        id: chosen.stable_id,
        name: chosen.name,
    }))
}

/// The region with the lowest measured latency in `report`, tiebroken by the lowest region id;
/// `None` when the winner has no usable latency. Pure port of Go `minLatencyDERPRegion`.
///
/// Mirrors Go's `slices.MinFunc` semantics exactly: a region missing from the report's latency map
/// is treated as the maximum latency (so a region with *any* measurement always beats one with
/// none), ties on latency break to the lower region id, and if the winning region's latency is
/// missing *or* exactly zero the function returns `None` (Go returns `0`) — signalling the caller to
/// fall back to a uniform region pick. `regions` is the candidate region set and is never empty when
/// called.
fn min_latency_derp_region(regions: &[RegionId], report: &NetcheckReport) -> Option<RegionId> {
    // Latency lookup keyed by region id. The report stores an ordered Vec (sorted ascending), but we
    // index by id to mirror Go's `report.RegionLatency[region]` map access.
    let latency_of = |region: RegionId| -> Option<core::time::Duration> {
        report
            .region_latencies
            .iter()
            .find(|rl| rl.region_id == region.0.get())
            .map(|rl| rl.latency)
    };

    // `slices.MinFunc`: a missing latency sorts as the largest possible value; ties break to the
    // lower region id. Using `core::cmp::max` as the "missing" sentinel matches Go's
    // `largeDuration = math.MaxInt64` semantics (any real measurement is smaller).
    let max_duration = core::time::Duration::MAX;
    let min = regions.iter().copied().min_by(|&i, &j| {
        let il = latency_of(i).unwrap_or(max_duration);
        let jl = latency_of(j).unwrap_or(max_duration);
        il.cmp(&jl).then_with(|| i.0.get().cmp(&j.0.get()))
    })?;

    // Go: if the winner's latency is missing or 0, return 0 (⇒ caller does a uniform pick).
    match latency_of(min) {
        Some(latency) if !latency.is_zero() => Some(min),
        _ => None,
    }
}

/// A uniformly-random region from `regions` — the production [`SelectRegion`](crate::exit_node_suggest::SelectRegion).
/// Port of Go `randomRegion`. `regions` must be non-empty (it always is when the algorithm invokes
/// the selector).
pub(crate) fn random_region(regions: &[RegionId]) -> RegionId {
    regions[rand::random_range(0..regions.len())]
}

/// A node from `nodes`, preferring `prefer` (the previous suggestion) when it is still present —
/// otherwise a uniformly-random node. The production
/// [`SelectNode`](crate::exit_node_suggest::SelectNode) and a verbatim port of Go `randomNode`: this
/// is where `prev_suggestion` **stickiness** lives. `nodes` must be non-empty.
pub(crate) fn random_node(
    nodes: &[ExitNodeCandidate],
    prefer: Option<&StableNodeId>,
) -> ExitNodeCandidate {
    // Go `randomNode` guards `if !prefer.IsZero()` — an empty StableNodeID is "no preference", never
    // a match target. `prev_suggestion` is only ever set from a real peer's id, so an empty id is
    // unreachable in practice, but mirror Go's guard exactly so a stray empty id can't stick.
    if let Some(prefer) = prefer.filter(|p| !p.0.is_empty())
        && let Some(found) = nodes.iter().find(|n| &n.stable_id == prefer)
    {
        return found.clone();
    }
    nodes[rand::random_range(0..nodes.len())].clone()
}

/// Compute the next sticky `prev_suggestion` value from the previous one and a suggestion outcome,
/// mirroring Go `suggestExitNodeLocked` (`ipn/ipnlocal/local.go`): it assigns `b.lastSuggestedExitNode
/// = res.ID` on **every** no-error return, so a successful suggestion sets the sticky id, an empty
/// result (`res.ID == ""`) clears it, and only an error returns before the assignment (leaving the
/// prior value in place). Pure + testable so the [`Runtime`](crate::Runtime)-level stickiness
/// lifecycle is covered without standing up an actor.
pub(crate) fn next_sticky(
    prev: Option<StableNodeId>,
    outcome: &Result<Option<ExitNodeSuggestion>, SuggestExitNodeError>,
) -> Option<StableNodeId> {
    match outcome {
        // No-error path (Go: `lastSuggestedExitNode = res.ID`). `Some` sets it; `None` clears it.
        Ok(maybe) => maybe.as_ref().map(|s| s.id.clone()),
        // Go returns before the assignment on `ErrNoPreferredDERP` — keep the prior sticky value.
        Err(_) => prev,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::RegionLatency;

    fn region(id: u32) -> RegionId {
        RegionId(core::num::NonZeroU32::new(id).unwrap())
    }

    /// Build a netcheck report from `(region_id, latency_ms)` pairs with the given preferred region.
    /// The first pair is treated as preferred only via the explicit `preferred` arg (the latency map
    /// drives ranking, not order).
    fn report(preferred: Option<u32>, latencies: &[(u32, u64)]) -> NetcheckReport {
        NetcheckReport {
            preferred_derp: preferred,
            region_latencies: latencies
                .iter()
                .map(|&(region_id, ms)| RegionLatency {
                    region_id,
                    latency: core::time::Duration::from_millis(ms),
                })
                .collect(),
        }
    }

    /// An eligible candidate (online + suggest-cap + exit-route) in `derp` region, named `peer<id>`
    /// with stable id `stable<id>`. Mirrors Go's `makePeer(id, withExitRoutes(), withSuggest())`
    /// where `HomeDERP` defaults to the id unless overridden.
    fn candidate(id: u32, derp: Option<u32>) -> ExitNodeCandidate {
        ExitNodeCandidate {
            stable_id: StableNodeId(format!("stable{id}")),
            name: format!("peer{id}"),
            derp_region: derp.map(region),
            online: Some(true),
            advertises_exit_route: true,
            has_suggest_cap: true,
        }
    }

    /// A deterministic [`SelectRegion`] stub asserting the offered region set equals `want` (any
    /// order) and returning `use_region`. Port of Go's `deterministicRegionForTest`.
    fn pick_region(want: Vec<RegionId>, use_region: RegionId) -> impl Fn(&[RegionId]) -> RegionId {
        move |got: &[RegionId]| {
            let mut got_sorted = got.to_vec();
            got_sorted.sort();
            let mut want_sorted = want.clone();
            want_sorted.sort();
            assert_eq!(got_sorted, want_sorted, "candidate regions mismatch");
            assert!(want.contains(&use_region), "use_region must be in want");
            use_region
        }
    }

    /// A deterministic [`SelectNode`] stub asserting the offered candidate id set equals `want` (any
    /// order) and that `last` equals `want_last`, then returning the candidate whose id is `use_id`.
    /// Port of Go's `deterministicNodeForTest` (which also calls the real `randomNode` and checks it
    /// returns a member — replicated here to exercise the production selector).
    fn pick_node(
        want: Vec<&'static str>,
        want_last: Option<&'static str>,
        use_id: &'static str,
    ) -> impl Fn(&[ExitNodeCandidate], Option<&StableNodeId>) -> ExitNodeCandidate {
        move |got: &[ExitNodeCandidate], last: Option<&StableNodeId>| {
            // Exercise the real uniform selector and confirm it returns a member (Go does this too).
            let via_random = random_node(got, last);
            assert!(
                got.iter().any(|c| c.stable_id == via_random.stable_id),
                "random_node returned a non-member"
            );

            let got_ids: Vec<String> = got.iter().map(|c| c.stable_id.0.clone()).collect();
            let mut got_sorted = got_ids.clone();
            got_sorted.sort();
            let mut want_sorted: Vec<String> = want.iter().map(|s| s.to_string()).collect();
            want_sorted.sort();
            assert_eq!(got_sorted, want_sorted, "candidate nodes mismatch");

            let last_str = last.map(|s| s.0.as_str());
            assert_eq!(last_str, want_last, "last (prev suggestion) mismatch");

            got.iter()
                .find(|c| c.stable_id.0 == use_id)
                .cloned()
                .expect("use_id must be among candidates")
        }
    }

    /// A selector that must never be called (the path under test bypasses it). Panics if invoked.
    fn unused_region() -> impl Fn(&[RegionId]) -> RegionId {
        |_: &[RegionId]| panic!("select_region must not be called on this path")
    }
    fn unused_node() -> impl Fn(&[ExitNodeCandidate], Option<&StableNodeId>) -> ExitNodeCandidate {
        |_: &[ExitNodeCandidate], _: Option<&StableNodeId>| {
            panic!("select_node must not be called on this path")
        }
    }

    /// `preferred_derp == None` ⇒ `ErrNoPreferredDERP` (Go's nil-report / no-preferred-DERP cases).
    #[test]
    fn no_preferred_derp_errors() {
        let r = report(None, &[(1, 10)]);
        let cands = [candidate(1, Some(1)), candidate(2, Some(2))];
        let err = suggest_exit_node(&r, &cands, None, &unused_region(), &unused_node())
            .expect_err("no preferred DERP must error");
        assert_eq!(err, SuggestExitNodeError::NoPreferredDerp);

        // `Some(0)` is likewise the no-preferred-DERP precondition (Go `PreferredDERP == 0`).
        let r0 = report(Some(0), &[(1, 10)]);
        assert_eq!(
            suggest_exit_node(&r0, &cands, None, &unused_region(), &unused_node()),
            Err(SuggestExitNodeError::NoPreferredDerp)
        );
    }

    /// 0 eligible candidates ⇒ `Ok(None)` (Go: empty response, nil error — NOT an error).
    #[test]
    fn no_candidates_returns_none() {
        let r = report(Some(1), &[(1, 10)]);
        assert_eq!(
            suggest_exit_node(&r, &[], None, &unused_region(), &unused_node()),
            Ok(None)
        );
    }

    /// Exactly 1 eligible candidate ⇒ returned directly, no region/node selector invoked.
    #[test]
    fn single_candidate_returned_directly() {
        let r = report(Some(1), &[(1, 10)]);
        let cands = [candidate(7, Some(2))];
        let got = suggest_exit_node(&r, &cands, None, &unused_region(), &unused_node())
            .expect("ok")
            .expect("some");
        assert_eq!(got.id, StableNodeId("stable7".into()));
        assert_eq!(got.name, "peer7");
    }

    /// 2 candidates in different regions, region 1 lower latency ⇒ the region-1 candidate wins.
    /// (Go `large-netmap`-style: lowest-latency region selected, then the sole node in it.)
    #[test]
    fn two_regions_lower_latency_wins() {
        // peer2 in region 1 (10ms), peer4 in region 3 (30ms) ⇒ region 1 wins ⇒ peer2.
        let r = report(Some(1), &[(1, 10), (2, 20), (3, 30)]);
        let cands = [candidate(2, Some(1)), candidate(4, Some(3))];
        let select_node = pick_node(vec!["stable2"], None, "stable2");
        let got = suggest_exit_node(&r, &cands, None, &unused_region(), &select_node)
            .expect("ok")
            .expect("some");
        assert_eq!(got.id, StableNodeId("stable2".into()));
        assert_eq!(got.name, "peer2");
    }

    /// 2 candidates in the same region ⇒ `select_node` picks deterministically among both.
    /// (Go `2-exits-same-region`.)
    #[test]
    fn two_candidates_same_region_select_node_picks() {
        let r = report(Some(1), &[(1, 10), (2, 20), (3, 30)]);
        let cands = [candidate(1, Some(1)), candidate(2, Some(1))];
        let select_node = pick_node(vec!["stable1", "stable2"], None, "stable1");
        let got = suggest_exit_node(&r, &cands, None, &unused_region(), &select_node)
            .expect("ok")
            .expect("some");
        assert_eq!(got.id, StableNodeId("stable1".into()));
        assert_eq!(got.name, "peer1");
    }

    /// `prev_suggestion` stickiness: prev is in the winning region's list ⇒ it is returned (the prev
    /// id is threaded to `select_node` as `last`). Go `prefer-last-node`.
    #[test]
    fn prev_suggestion_sticky_when_present() {
        let r = report(Some(1), &[(1, 10), (2, 20), (3, 30)]);
        let cands = [candidate(1, Some(1)), candidate(2, Some(1))];
        let prev = StableNodeId("stable2".into());
        // select_node sees both, `last == stable2`, and (via real random_node stickiness) returns it.
        let select_node = pick_node(vec!["stable1", "stable2"], Some("stable2"), "stable2");
        let got = suggest_exit_node(&r, &cands, Some(&prev), &unused_region(), &select_node)
            .expect("ok")
            .expect("some");
        assert_eq!(got.id, StableNodeId("stable2".into()));
        assert_eq!(got.name, "peer2");
    }

    /// Stickiness does NOT override a better region: prev suggestion is in a higher-latency region,
    /// so the lower-latency region still wins (prev isn't even offered to `select_node`). Go
    /// `found-better-derp-node` (lastSuggestion stable3 in region 3, but region 1 wins ⇒ stable2).
    #[test]
    fn better_region_beats_stale_prev_suggestion() {
        let r = report(Some(1), &[(1, 10), (2, 20), (3, 30)]);
        // peer2 region 1 (10ms), peer3 region 3 (30ms). prev = stable3 (region 3, higher latency).
        let cands = [candidate(2, Some(1)), candidate(3, Some(3))];
        let prev = StableNodeId("stable3".into());
        // Region 1 wins; only peer2 is in it; `last` is still threaded through as stable3.
        let select_node = pick_node(vec!["stable2"], Some("stable3"), "stable2");
        let got = suggest_exit_node(&r, &cands, Some(&prev), &unused_region(), &select_node)
            .expect("ok")
            .expect("some");
        assert_eq!(got.id, StableNodeId("stable2".into()));
    }

    /// Region latency tiebreak: two regions with equal latency ⇒ the lower region id wins (no
    /// selector fallback, since the latencies are usable/non-zero). Go
    /// `2-derp-exits-different-regions-equal-latency` (regions 1 & 3 both 10 ⇒ region 1).
    #[test]
    fn equal_latency_lower_region_id_wins() {
        // peer1 region 1, peer3 region 3, both 10ms ⇒ region 1 (lower id) ⇒ peer1.
        let r = report(Some(1), &[(1, 10), (2, 20), (3, 10)]);
        let cands = [candidate(1, Some(1)), candidate(3, Some(3))];
        let select_node = pick_node(vec!["stable1"], None, "stable1");
        let got = suggest_exit_node(&r, &cands, None, &unused_region(), &select_node)
            .expect("ok")
            .expect("some");
        assert_eq!(got.id, StableNodeId("stable1".into()));
        assert_eq!(got.name, "peer1");
    }

    /// All candidate regions have zero/unknown latency ⇒ `min_latency_derp_region` returns `None`
    /// and `select_region` is the fallback (uniform region pick), then `select_node` within it. Go
    /// `2-exits-different-regions-unknown-latency` (regions 1 & 3, all-zero latencies ⇒ selectRegion).
    #[test]
    fn no_usable_latency_falls_back_to_select_region() {
        // peer2 region 1, peer4 region 3, all latencies 0 ⇒ region ranking unusable ⇒ select_region
        // (offered {1,3}, returns 1) ⇒ peer2.
        let r = report(Some(1), &[(1, 0), (2, 0), (3, 0)]);
        let cands = [candidate(2, Some(1)), candidate(4, Some(3))];
        let select_region = pick_region(vec![region(1), region(3)], region(1));
        let select_node = pick_node(vec!["stable2"], None, "stable2");
        let got = suggest_exit_node(&r, &cands, None, &select_region, &select_node)
            .expect("ok")
            .expect("some");
        assert_eq!(got.id, StableNodeId("stable2".into()));
        assert_eq!(got.name, "peer2");
    }

    /// A region missing from the latency map is treated as max latency, so a region WITH a
    /// measurement always wins — even a higher id beats a missing one only when... no: lower latency
    /// wins. Here region 3 has 10ms, region 1 is missing ⇒ region 3 wins despite the higher id.
    #[test]
    fn missing_latency_loses_to_measured_region() {
        let r = report(Some(3), &[(3, 10)]); // region 1 absent from the map
        let cands = [candidate(1, Some(1)), candidate(3, Some(3))];
        let select_node = pick_node(vec!["stable3"], None, "stable3");
        let got = suggest_exit_node(&r, &cands, None, &unused_region(), &select_node)
            .expect("ok")
            .expect("some");
        assert_eq!(got.id, StableNodeId("stable3".into()));
    }

    /// Candidate predicate — a peer WITHOUT the suggest-exit-node cap is excluded. With only one
    /// other eligible peer left, that one is returned directly (proves the non-eligible one was
    /// dropped before the count check).
    #[test]
    fn predicate_excludes_missing_suggest_cap() {
        let r = report(Some(1), &[(1, 10)]);
        let mut no_cap = candidate(1, Some(1));
        no_cap.has_suggest_cap = false;
        let cands = [no_cap, candidate(2, Some(2))];
        // Only peer2 is eligible ⇒ single-candidate direct return (no selector).
        let got = suggest_exit_node(&r, &cands, None, &unused_region(), &unused_node())
            .expect("ok")
            .expect("some");
        assert_eq!(got.id, StableNodeId("stable2".into()));
    }

    /// Candidate predicate — a peer NOT advertising an exit route (`0.0.0.0/0`) is excluded.
    #[test]
    fn predicate_excludes_no_exit_route() {
        let r = report(Some(1), &[(1, 10)]);
        let mut no_route = candidate(1, Some(1));
        no_route.advertises_exit_route = false;
        let cands = [no_route, candidate(2, Some(2))];
        let got = suggest_exit_node(&r, &cands, None, &unused_region(), &unused_node())
            .expect("ok")
            .expect("some");
        assert_eq!(got.id, StableNodeId("stable2".into()));
    }

    /// Candidate predicate — an offline peer (online != Some(true)) is excluded; a tri-state `None`
    /// is also excluded (fail-closed).
    #[test]
    fn predicate_excludes_offline_and_unknown() {
        let r = report(Some(1), &[(1, 10)]);
        let mut offline = candidate(1, Some(1));
        offline.online = Some(false);
        let mut unknown = candidate(3, Some(3));
        unknown.online = None;
        let cands = [offline, unknown, candidate(2, Some(2))];
        // Only peer2 survives ⇒ direct return.
        let got = suggest_exit_node(&r, &cands, None, &unused_region(), &unused_node())
            .expect("ok")
            .expect("some");
        assert_eq!(got.id, StableNodeId("stable2".into()));

        // If the ONLY candidate is offline ⇒ no eligible candidates ⇒ Ok(None).
        let r2 = report(Some(1), &[(1, 10)]);
        let mut lone_offline = candidate(9, Some(1));
        lone_offline.online = Some(false);
        assert_eq!(
            suggest_exit_node(&r2, &[lone_offline], None, &unused_region(), &unused_node()),
            Ok(None)
        );
    }

    /// All eligible candidates are region-less (no DERP home) ⇒ Phase-1 fallback selects over the
    /// whole region-less set via `select_node` (no geo weighting; geo is Phase 2). `select_region`
    /// is never called.
    #[test]
    fn all_region_less_falls_back_to_select_node() {
        let r = report(Some(1), &[(1, 10)]);
        let cands = [candidate(5, None), candidate(6, None)];
        let select_node = pick_node(vec!["stable5", "stable6"], None, "stable5");
        let got = suggest_exit_node(&r, &cands, None, &unused_region(), &select_node)
            .expect("ok")
            .expect("some");
        assert_eq!(got.id, StableNodeId("stable5".into()));
        assert_eq!(got.name, "peer5");
    }

    /// A region-less candidate is NOT selected when a DERP-homed candidate exists (Go: "never select
    /// a candidate without a DERP home if there is a candidate available with a DERP home"). Here a
    /// region-less peer6 + a DERP-homed peer2 ⇒ only peer2's region is considered.
    #[test]
    fn region_less_skipped_when_derp_homed_exists() {
        let r = report(Some(1), &[(1, 10)]);
        let cands = [candidate(6, None), candidate(2, Some(1))];
        // Only region 1 (peer2) is offered to select_node; peer6 (region-less) is dropped.
        let select_node = pick_node(vec!["stable2"], None, "stable2");
        let got = suggest_exit_node(&r, &cands, None, &unused_region(), &select_node)
            .expect("ok")
            .expect("some");
        assert_eq!(got.id, StableNodeId("stable2".into()));
    }

    /// `random_node` stickiness in isolation: prefer present ⇒ returned; prefer absent ⇒ a member is
    /// still returned.
    #[test]
    fn random_node_prefers_then_falls_back() {
        let cands = [candidate(1, Some(1)), candidate(2, Some(1))];
        let prefer = StableNodeId("stable2".into());
        assert_eq!(random_node(&cands, Some(&prefer)).stable_id, prefer);

        // Absent prefer ⇒ a uniform pick that is still one of the candidates.
        let absent = StableNodeId("stableX".into());
        let got = random_node(&cands, Some(&absent));
        assert!(cands.iter().any(|c| c.stable_id == got.stable_id));

        // No prefer ⇒ likewise a member.
        let got2 = random_node(&cands, None);
        assert!(cands.iter().any(|c| c.stable_id == got2.stable_id));
    }

    /// `min_latency_derp_region` direct unit checks: lowest wins, equal ⇒ lower id, all-zero ⇒ None,
    /// missing-on-winner ⇒ None.
    #[test]
    fn min_latency_region_semantics() {
        let r = report(Some(1), &[(1, 30), (2, 10), (3, 20)]);
        assert_eq!(
            min_latency_derp_region(&[region(1), region(2), region(3)], &r),
            Some(region(2))
        );
        // Equal latency ⇒ lower id.
        let req = report(Some(1), &[(1, 10), (2, 10)]);
        assert_eq!(
            min_latency_derp_region(&[region(1), region(2)], &req),
            Some(region(1))
        );
        // All zero ⇒ None (caller falls back to select_region).
        let rz = report(Some(1), &[(1, 0), (2, 0)]);
        assert_eq!(min_latency_derp_region(&[region(1), region(2)], &rz), None);
        // Winner missing from map ⇒ None. (region 5 not in the map; it's the only candidate.)
        let rm = report(Some(1), &[(1, 10)]);
        assert_eq!(min_latency_derp_region(&[region(5)], &rm), None);
    }

    /// `next_sticky` mirrors Go `suggestExitNodeLocked`'s `lastSuggestedExitNode = res.ID` on every
    /// no-error return: a suggestion SETS the sticky id, an empty result CLEARS it, and an error
    /// leaves the prior value untouched. This covers the `Runtime`-level stickiness lifecycle (the
    /// actor reads `prev`, calls `suggest_exit_node`, then stores `next_sticky(prev, &outcome)`).
    #[test]
    fn next_sticky_matches_go_last_suggested() {
        let sugg = ExitNodeSuggestion {
            id: StableNodeId("stable2".to_owned()),
            name: "peer2".to_owned(),
        };
        let prev = || Some(StableNodeId("stable1".to_owned()));

        // Ok(Some) ⇒ take the new id (overwrites any prior).
        assert_eq!(
            next_sticky(prev(), &Ok(Some(sugg.clone()))),
            Some(StableNodeId("stable2".to_owned()))
        );
        assert_eq!(
            next_sticky(None, &Ok(Some(sugg))),
            Some(StableNodeId("stable2".to_owned()))
        );

        // Ok(None) ⇒ CLEAR (Go assigns res.ID == ""), even with a prior sticky value.
        assert_eq!(next_sticky(prev(), &Ok(None)), None);

        // Err ⇒ keep the prior (Go returns before the assignment).
        assert_eq!(
            next_sticky(prev(), &Err(SuggestExitNodeError::NoPreferredDerp)),
            prev()
        );
        assert_eq!(
            next_sticky(None, &Err(SuggestExitNodeError::NoPreferredDerp)),
            None
        );
    }

    /// The empty-id guard in `random_node` (Go's `!prefer.IsZero()`): an empty `prefer` is never a
    /// match target — selection falls through to the uniform pick (here a single-element list).
    #[test]
    fn random_node_ignores_empty_prefer_id() {
        let only = candidate(7, Some(1));
        let empty = StableNodeId(String::new());
        // Empty prefer ⇒ no sticky match; with one candidate the uniform pick returns it.
        let picked = random_node(std::slice::from_ref(&only), Some(&empty));
        assert_eq!(picked.stable_id, only.stable_id);
    }
}
