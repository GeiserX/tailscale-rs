//! The owned-rule ledger: every rule this process may have created on a router, so that a rule
//! whose reply was lost, or whose commit arrived after an invalidation, can still be deleted.
//!
//! An entry is added **before** each MAP is sent. A rule is enough to delete it: NAT-PMP needs
//! only the internal port, PCP also the nonce it was created with. The ledger is bounded
//! ([`MAX_OWNED`]), which bounds the router state one process can leave behind, not just its tasks.

use std::sync::Arc;

use tokio::time::Instant;

use crate::{
    cap::{NetGen, SendEvidence},
    gateway::Gateway,
    oneshot::{Proto, Rule},
};

/// The most rules one client tracks at once. New attempts are refused while it is full.
pub(crate) const MAX_OWNED: usize = 4;
/// Initial unacknowledged deletes before switching to infrequent recovery attempts.
pub(crate) const MAX_DELETE_TRIES: u32 = 3;
/// After the initial attempts, at most one delete per rule per ten minutes, with fresh gateway
/// validation each time. An unanswered MAP keeps its admission slot for the requested lifetime
/// from its last send attempt (RFC 6886 §3.3), unless per-rule evidence (a matched reply/delete
/// or accepted reset) resolves it first.
pub(crate) const DELETE_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(600);

/// Where an owned rule stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuleState {
    /// A MAP for it was (or is about to be) sent; no reply committed yet.
    Pending,
    /// A committed reply backs the current mapping.
    Active,
    /// No longer wanted: to be deleted (when allowed) or left to router expiry.
    Orphaned,
}

/// Opaque handle to a ledger entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct RuleId(u64);

/// One rule this process may own on a router.
#[derive(Debug, Clone)]
pub(crate) struct OwnedRule {
    /// Handle.
    pub(crate) id: RuleId,
    /// What it takes to delete it.
    pub(crate) rule: Rule,
    /// The network it was created on.
    pub(crate) net_gen: NetGen,
    /// That network's gateway, self address and interface.
    pub(crate) gateway: Gateway,
    ownership: Ownership,
    release: Release,
    /// Admission time, used only by the independent ownership journal.
    #[cfg(test)]
    pub(crate) sent_at: Instant,
    /// Prior settled possible ownership. A live MAP can expand this bound only with syscall
    /// evidence; a matched grant replaces it. Fresh unsent reservations start with no grant.
    settled_expiry: Instant,
    /// Deletes already sent without an acknowledgement.
    pub(crate) delete_tries: u32,
    /// Recovery/validation cooldown, independent of possible router expiry.
    pub(crate) retry_at: Option<Instant>,
}

/// Reservations are exclusive by construction; a delete can only own an orphan.
#[derive(Debug, Clone)]
enum Ownership {
    Idle(RuleState),
    Map(RuleState, MapGrant),
    Delete,
}

#[derive(Debug, Clone)]
enum MapGrant {
    Pending {
        evidence: Arc<SendEvidence>,
        existed: bool,
    },
    Settled,
}

#[derive(Debug, Clone, Copy)]
enum FinalDuty {
    None,
    Owed,
}

#[derive(Debug, Clone, Copy)]
enum Release {
    Allowed(FinalDuty),
    Fenced(FinalDuty),
}

impl Release {
    fn duty(self) -> FinalDuty {
        match self {
            Self::Allowed(d) | Self::Fenced(d) => d,
        }
    }
}

impl OwnedRule {
    pub(crate) fn state(&self) -> RuleState {
        match &self.ownership {
            Ownership::Idle(s) | Ownership::Map(s, _) => *s,
            Ownership::Delete => RuleState::Orphaned,
        }
    }

    pub(crate) fn mapping(&self) -> bool {
        matches!(self.ownership, Ownership::Map(..))
    }
    pub(crate) fn deleting(&self) -> bool {
        matches!(self.ownership, Ownership::Delete)
    }
    pub(crate) fn releasable(&self) -> bool {
        matches!(self.release, Release::Allowed(_))
    }
    fn reserved(&self) -> bool {
        self.mapping() || self.deleting()
    }
    fn set_state(&mut self, state: RuleState) {
        match &mut self.ownership {
            Ownership::Map(s, _) | Ownership::Idle(s) => *s = state,
            Ownership::Delete => debug_assert_eq!(state, RuleState::Orphaned),
        }
    }

    /// A live reservation owns no additional grant until its MAP syscall may have run.
    pub(crate) fn router_expiry(&self) -> Instant {
        match &self.ownership {
            Ownership::Map(_, MapGrant::Pending { evidence, .. }) => evidence
                .possible_until()
                .map_or(self.settled_expiry, |until| self.settled_expiry.max(until)),
            _ => self.settled_expiry,
        }
    }

    fn grant_observed(&mut self, until: Instant) {
        self.settled_expiry = until;
        if let Ownership::Map(_, grant) = &mut self.ownership {
            *grant = MapGrant::Settled;
        }
    }

    fn unclaim_delete(&mut self) {
        if self.deleting() {
            self.ownership = Ownership::Idle(RuleState::Orphaned);
        }
    }
    fn fence(&mut self) {
        self.release = Release::Fenced(self.release.duty());
    }
}

/// Why a rule left the ledger without a delete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LeftReason {
    /// Its network no longer validates, or is down: a delete could reach the wrong router.
    NetworkGone,
    /// The router's grant already ended.
    Expired,
}

/// The ledger. See the module docs.
#[derive(Debug, Default)]
pub(crate) struct OwnedRules {
    entries: Vec<OwnedRule>,
    next_id: u64,
    #[cfg(test)]
    pub(crate) model: crate::ownership_model::OwnershipModel,
}

// Prefix length and interface name are validation metadata, not fields on a router's UDP
// mapping key. A rename/prefix update must not split a live operation's reservation.
fn same_wire_gateway(a: &Gateway, b: &Gateway) -> bool {
    a.gw == b.gw && a.self_ip == b.self_ip && a.if_index == b.if_index
}

impl OwnedRules {
    /// All entries.
    pub(crate) fn entries(&self) -> &[OwnedRule] {
        &self.entries
    }

    /// Number of entries in any state.
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the ledger is empty.
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether a new entry fits.
    pub(crate) fn has_room(&self) -> bool {
        self.entries.len() < MAX_OWNED
    }

    fn find(&self, id: RuleId) -> Option<usize> {
        self.entries.iter().position(|e| e.id == id)
    }

    /// The entry with this id.
    pub(crate) fn get(&self, id: RuleId) -> Option<&OwnedRule> {
        self.find(id).map(|i| &self.entries[i])
    }

    /// The live (pending or active) entry for exactly this rule on this network, if any: a renewal
    /// reuses it in place.
    pub(crate) fn live_for(&self, rule: &Rule, net_gen: NetGen) -> Option<RuleId> {
        self.entries
            .iter()
            .find(|e| e.state() != RuleState::Orphaned && e.net_gen == net_gen && e.rule == *rule)
            .map(|e| e.id)
    }

    /// The UDP wire identity, independent of protocol, nonce and local network generation.
    /// A router may share one table between PCP and PMP.
    pub(crate) fn for_identity(
        &self,
        internal: std::num::NonZeroU16,
        gateway: &Gateway,
    ) -> Option<&OwnedRule> {
        self.entries
            .iter()
            .find(|e| e.rule.internal() == internal && same_wire_gateway(&e.gateway, gateway))
    }

    /// Reserve a MAP through completion/cancellation. All callers hold the client state lock.
    pub(crate) fn claim_map(
        &mut self,
        id: RuleId,
        now: Instant,
        existed: bool,
    ) -> Option<Arc<SendEvidence>> {
        let i = self.find(id)?;
        let e = &mut self.entries[i];
        if e.reserved() {
            return None;
        }
        let evidence = Arc::new(SendEvidence::new(
            if e.rule.proto() == Proto::Pmp { 1 } else { 0 },
            now,
        ));
        e.ownership = Ownership::Map(
            e.state(),
            MapGrant::Pending {
                evidence: evidence.clone(),
                existed,
            },
        );
        #[cfg(test)]
        self.model.map_started(id, evidence.clone());
        Some(evidence)
    }

    /// Settle only after the transport future ended or was dropped, so its evidence cannot
    /// change concurrently. Local absence affects this attempt only; retain prior ownership.
    pub(crate) fn discard_unsent(&mut self, id: RuleId) {
        let Some(i) = self.find(id) else {
            return;
        };
        let Ownership::Map(_, MapGrant::Pending { evidence, existed }) = &self.entries[i].ownership
        else {
            return;
        };
        if evidence.possible_until().is_some() {
            return;
        }
        if *existed {
            if let Ownership::Map(_, grant) = &mut self.entries[i].ownership {
                *grant = MapGrant::Settled;
            }
        } else {
            #[cfg(test)]
            self.record_retirement(id, crate::ownership_model::Retirement::ProvenUnsent);
            self.entries.remove(i);
        }
    }

    /// Release a completed/cancelled MAP. Retire fresh never-sent identities; otherwise return
    /// unsettled entries to cleanup, materializing any attempted MAP's possible grant. Active
    /// renewals retain their held mapping and no unsent attempt extends ownership.
    pub(crate) fn finish_map(&mut self, id: RuleId) {
        self.discard_unsent(id);
        if let Some(i) = self.find(id) {
            let e = &mut self.entries[i];
            if e.mapping() {
                e.settled_expiry = e.router_expiry();
                e.ownership = Ownership::Idle(match e.state() {
                    RuleState::Pending => RuleState::Orphaned,
                    s => s,
                });
            }
        }
    }

    /// Reserve an identity before I/O. No router grant is recorded until a MAP syscall is
    /// attempted. Returns `None` when the ledger is full.
    pub(crate) fn add_pending(
        &mut self,
        rule: Rule,
        net_gen: NetGen,
        gateway: Gateway,
        now: Instant,
    ) -> Option<RuleId> {
        if !self.has_room() || self.for_identity(rule.internal(), &gateway).is_some() {
            return None;
        }
        let id = RuleId(self.next_id);
        self.next_id += 1;
        self.entries.push(OwnedRule {
            id,
            rule,
            net_gen,
            gateway,
            ownership: Ownership::Idle(RuleState::Pending),
            release: Release::Allowed(FinalDuty::None),
            #[cfg(test)]
            sent_at: now,
            settled_expiry: now,
            delete_tries: 0,
            retry_at: None,
        });
        #[cfg(test)]
        self.model.admit(self.entries.last().unwrap().clone());
        Some(id)
    }

    /// A reply committed for `id`: it is active until `router_expiry`.
    pub(crate) fn commit(&mut self, id: RuleId, router_expiry: Instant) {
        if let Some(i) = self.find(id) {
            let e = &mut self.entries[i];
            e.set_state(RuleState::Active);
            e.grant_observed(router_expiry);
        }
    }

    /// A reply arrived but is stale: the router holds the rule until `router_expiry`, and nobody
    /// wants it.
    pub(crate) fn orphan_committed(&mut self, id: RuleId, router_expiry: Instant) {
        if let Some(i) = self.find(id) {
            let e = &mut self.entries[i];
            e.set_state(RuleState::Orphaned);
            e.grant_observed(router_expiry);
        }
    }

    /// Mark one entry orphaned.
    pub(crate) fn orphan(&mut self, id: RuleId) {
        if let Some(i) = self.find(id) {
            self.entries[i].set_state(RuleState::Orphaned);
        }
    }

    /// Mark every pending and active entry orphaned (an invalidation: nothing is in use any more).
    pub(crate) fn orphan_all(&mut self) {
        for e in &mut self.entries {
            e.set_state(RuleState::Orphaned);
        }
    }

    /// Remove `id` without a delete (the router refused the create, or lost the rule).
    pub(crate) fn remove(&mut self, id: RuleId) -> Option<OwnedRule> {
        self.find(id).map(|i| self.entries.remove(i))
    }

    #[cfg(test)]
    pub(crate) fn record_retirement(
        &mut self,
        id: RuleId,
        reason: crate::ownership_model::Retirement,
    ) {
        if let Some(e) = self.get(id).cloned() {
            self.model.retire(e, reason);
        }
    }

    /// Mark every orphaned entry as never to be deleted (a network-down); returns those that
    /// changed, for logging.
    pub(crate) fn forget_orphans(&mut self) -> Vec<OwnedRule> {
        let mut out = Vec::new();
        for e in &mut self.entries {
            if e.state() == RuleState::Orphaned && e.releasable() {
                e.fence();
                out.push(e.clone());
            }
        }
        out
    }

    /// An orphaned entry for the same protocol and internal port on the same network
    /// (`gateway`), not being deleted: a new create adopts it (and, for PCP, its nonce) instead of
    /// asking for a second rule. It becomes pending again, on `net_gen`.
    pub(crate) fn adopt(
        &mut self,
        proto: Proto,
        internal: std::num::NonZeroU16,
        gateway: &Gateway,
        net_gen: NetGen,
    ) -> Option<(RuleId, Rule)> {
        let e = self.entries.iter_mut().find(|e| {
            e.state() == RuleState::Orphaned
                && !e.reserved()
                && e.rule.proto() == proto
                && e.rule.internal() == internal
                && same_wire_gateway(&e.gateway, gateway)
        })?;
        e.set_state(RuleState::Pending);
        e.release = Release::Allowed(e.release.duty());
        e.delete_tries = 0;
        e.retry_at = None;
        e.net_gen = net_gen;
        e.gateway = gateway.clone();
        Some((e.id, e.rule.clone()))
    }

    /// Remove this reporting router's entries for `proto` on an accepted epoch rollback,
    /// except `keep`. A different gateway's reset says nothing about this rule's ownership:
    /// the rule of an attempt in flight, whose MAP may reach the restarted router and be committed
    /// there. It stays, so an invalidation orphans it and a cleanup deletes it.
    pub(crate) fn drop_proto(
        &mut self,
        proto: Proto,
        gateway: &Gateway,
        keep: Option<RuleId>,
    ) -> Vec<OwnedRule> {
        let (gone, kept): (Vec<OwnedRule>, Vec<OwnedRule>) = std::mem::take(&mut self.entries)
            .into_iter()
            .partition(|e| {
                e.rule.proto() == proto
                    && same_wire_gateway(&e.gateway, gateway)
                    && !e.reserved()
                    && Some(e.id) != keep
            });
        #[cfg(test)]
        for e in &gone {
            self.model.retire(
                e.clone(),
                crate::ownership_model::Retirement::Reset {
                    observation: self.model.latest_reset(),
                    gateway: gateway.clone(),
                    proto,
                },
            );
        }
        self.entries = kept;
        gone
    }

    /// Remove every orphaned entry whose router grant has ended by `now`.
    pub(crate) fn drop_expired(&mut self, now: Instant) -> Vec<OwnedRule> {
        let (gone, keep): (Vec<OwnedRule>, Vec<OwnedRule>) = std::mem::take(&mut self.entries)
            .into_iter()
            .partition(|e| {
                e.state() == RuleState::Orphaned && !e.reserved() && now >= e.router_expiry()
            });
        #[cfg(test)]
        for e in &gone {
            self.model.retire(
                e.clone(),
                crate::ownership_model::Retirement::Expiry { observed_at: now },
            );
        }
        self.entries = keep;
        gone
    }

    /// Releasable orphaned entries that are not being deleted yet; each is marked as being
    /// deleted.
    pub(crate) fn claim_orphans(&mut self, now: Instant) -> Vec<OwnedRule> {
        self.claim_orphans_inner(now, false)
    }

    /// Shutdown gets one final attempt, even when ordinary recovery is cooling down.
    pub(crate) fn claim_for_close(&mut self, now: Instant) -> Vec<OwnedRule> {
        self.claim_orphans_inner(now, true)
    }

    fn claim_orphans_inner(&mut self, now: Instant, closing: bool) -> Vec<OwnedRule> {
        let mut out = Vec::new();
        for e in &mut self.entries {
            if e.state() == RuleState::Orphaned
                && e.releasable()
                && !e.reserved()
                && (closing || e.retry_at.is_none_or(|at| now >= at))
            {
                e.ownership = Ownership::Delete;
                // Reserve the recovery interval before awaiting OS work or sending, so
                // cancellation cannot bypass its spacing.
                if e.delete_tries >= MAX_DELETE_TRIES {
                    e.retry_at = Some(now + DELETE_RETRY_INTERVAL);
                }
                out.push(e.clone());
            }
        }
        out
    }

    /// Transfer final-release duty to each operation (or claim idle entries immediately).
    pub(crate) fn request_final_release(&mut self) {
        for e in &mut self.entries {
            e.release = match e.release {
                Release::Allowed(_) => Release::Allowed(FinalDuty::Owed),
                Release::Fenced(_) => Release::Fenced(FinalDuty::Owed),
            };
        }
    }

    /// Any operation still holds a reservation.
    pub(crate) fn has_claims(&self) -> bool {
        self.entries.iter().any(|e| e.reserved())
    }

    /// Claim one final best-effort send per rule, independent of normal recovery cooldowns.
    /// Existing operations keep their reservations until their finalizers hand them back.
    pub(crate) fn claim_final_releases(&mut self, now: Instant) -> Vec<OwnedRule> {
        let mut out = Vec::new();
        for e in &mut self.entries {
            if matches!(e.release.duty(), FinalDuty::Owed)
                && e.releasable()
                && !e.reserved()
                && e.state() == RuleState::Orphaned
                && now < e.router_expiry()
            {
                e.release = Release::Allowed(FinalDuty::None);
                e.ownership = Ownership::Delete;
                out.push(e.clone());
            }
        }
        out
    }

    /// Stop deleting an unreachable rule, retaining its admission slot until expiry.
    pub(crate) fn abandon(&mut self, id: RuleId) {
        if let Some(i) = self.find(id) {
            self.entries[i].fence();
            self.entries[i].unclaim_delete();
        }
    }

    /// A delete finished. Only an acknowledgement retires ownership. After the initial
    /// attempts, keep the admission slot and try once per recovery interval, indefinitely.
    /// Returns an entry just once when its fast attempts are exhausted (for logging).
    pub(crate) fn finish_delete(
        &mut self,
        id: RuleId,
        acked: bool,
        now: Instant,
    ) -> Option<OwnedRule> {
        let i = self.find(id)?;
        if acked {
            #[cfg(test)]
            self.record_retirement(
                id,
                crate::ownership_model::Retirement::Delete { matched: acked },
            );
            self.entries.remove(i);
            return None;
        }
        let e = &mut self.entries[i];
        e.unclaim_delete();
        e.delete_tries = e.delete_tries.saturating_add(1);
        if e.delete_tries >= MAX_DELETE_TRIES {
            e.retry_at = Some(now + DELETE_RETRY_INTERVAL);
        }
        (e.delete_tries == MAX_DELETE_TRIES).then(|| e.clone())
    }

    /// Validation failed or its worker timed out. Keep ownership and allow another fresh
    /// validation later; an unavailable worker is not evidence that the network is gone.
    pub(crate) fn defer_delete(&mut self, id: RuleId, now: Instant) {
        if let Some(i) = self.find(id) {
            let e = &mut self.entries[i];
            e.unclaim_delete();
            e.retry_at = Some(now + DELETE_RETRY_INTERVAL);
        }
    }

    /// Earliest cleanup worth waking for, independent of node activity or peers. Network-down
    /// rules and reservations owned by other operations cannot be sent by this timer.
    pub(crate) fn next_cleanup(&self, now: Instant) -> Option<Instant> {
        self.entries
            .iter()
            .filter(|e| e.state() == RuleState::Orphaned && e.releasable() && !e.reserved())
            .map(|e| e.retry_at.unwrap_or(now))
            .min()
    }

    /// Give a claimed entry back without a delete attempt.
    pub(crate) fn unclaim(&mut self, id: RuleId) {
        if let Some(i) = self.find(id) {
            self.entries[i].unclaim_delete();
        }
    }

    /// Whether any entry is orphaned and may be deleted.
    pub(crate) fn has_orphans(&self) -> bool {
        self.entries
            .iter()
            .any(|e| e.state() == RuleState::Orphaned && e.releasable())
    }
}

#[cfg(test)]
mod tests {
    use std::{num::NonZeroU16, time::Duration};

    use crate::oneshot::Proto;

    use super::*;

    fn gw() -> Gateway {
        Gateway {
            gw: "192.168.1.1".parse().unwrap(),
            self_ip: "192.168.1.20".parse().unwrap(),
            prefix_len: 24,
            if_index: 4,
            if_name: "en0".to_owned(),
        }
    }

    fn pmp(port: u16) -> Rule {
        Rule::Pmp {
            internal: NonZeroU16::new(port).unwrap(),
        }
    }

    #[test]
    fn bounded_and_renewals_reuse_the_entry() {
        let now = Instant::now();
        let mut l = OwnedRules::default();
        let a = l.add_pending(pmp(1), NetGen(1), gw(), now).unwrap();
        assert_eq!(l.live_for(&pmp(1), NetGen(1)), Some(a));
        assert_eq!(l.live_for(&pmp(1), NetGen(2)), None);
        assert_eq!(l.live_for(&pmp(2), NetGen(1)), None);
        for p in 2..=4 {
            assert!(l.add_pending(pmp(p), NetGen(1), gw(), now).is_some());
        }
        assert!(!l.has_room());
        assert!(l.add_pending(pmp(5), NetGen(1), gw(), now).is_none());
        assert_eq!(l.len(), MAX_OWNED);
    }

    #[test]
    fn orphans_are_claimed_once_and_retried_a_bounded_number_of_times() {
        let now = Instant::now();
        let mut l = OwnedRules::default();
        let a = l.add_pending(pmp(1), NetGen(1), gw(), now).unwrap();
        l.commit(a, now + Duration::from_secs(60));
        assert!(l.claim_orphans(now).is_empty());
        l.orphan_all();
        assert_eq!(l.claim_orphans(now).len(), 1);
        // Claimed: a second cleanup does not see it.
        assert!(l.claim_orphans(now).is_empty());
        assert!(l.finish_delete(a, false, now).is_none());
        for _ in 1..MAX_DELETE_TRIES - 1 {
            assert_eq!(l.claim_orphans(now).len(), 1);
            assert!(l.finish_delete(a, false, now).is_none());
        }
        assert_eq!(l.claim_orphans(now).len(), 1);
        assert!(l.finish_delete(a, false, now).is_some());
        assert_eq!(l.len(), 1, "unacknowledged rule remains a tombstone");
        assert!(l.claim_orphans(now).is_empty());
        assert_eq!(l.drop_expired(now + Duration::from_secs(60)).len(), 1);

        let b = l.add_pending(pmp(2), NetGen(1), gw(), now).unwrap();
        l.orphan(b);
        l.claim_orphans(now);
        assert!(l.finish_delete(b, true, now).is_none());
        assert!(l.is_empty());
    }

    #[test]
    fn forgotten_rules_are_never_claimed_but_can_be_adopted_and_count() {
        let now = Instant::now();
        let mut l = OwnedRules::default();
        let a = l.add_pending(pmp(1), NetGen(1), gw(), now).unwrap();
        l.orphan_all();
        assert_eq!(l.forget_orphans().len(), 1);
        assert!(!l.has_orphans());
        assert!(l.claim_orphans(now).is_empty());
        // Same rule, same network, a later generation: adopted.
        let p1 = NonZeroU16::new(1).unwrap();
        let mut other = gw();
        other.gw = "10.0.0.1".parse().unwrap();
        assert!(l.adopt(Proto::Pmp, p1, &other, NetGen(2)).is_none());
        assert!(l.adopt(Proto::Pcp, p1, &gw(), NetGen(2)).is_none());
        let mut refreshed = gw();
        refreshed.prefix_len = 23;
        refreshed.if_name = "renamed-interface".to_owned();
        let (id, rule) = l.adopt(Proto::Pmp, p1, &refreshed, NetGen(2)).unwrap();
        assert_eq!(
            l.get(id).unwrap().gateway,
            refreshed,
            "adoption uses the fresh validated snapshot"
        );
        assert_eq!((id, rule), (a, pmp(1)));
        assert_eq!(l.live_for(&pmp(1), NetGen(2)), Some(a));
        // Forgotten rules still count against admission until expiry.
        l.orphan_all();
        l.forget_orphans();
        for p in 2..=4 {
            l.add_pending(pmp(p), NetGen(2), gw(), now + Duration::from_secs(1))
                .unwrap();
        }
        assert!(l.add_pending(pmp(5), NetGen(2), gw(), now).is_none());
        assert!(l.get(a).is_some());
        assert!(l.add_pending(pmp(6), NetGen(2), gw(), now).is_none());
    }

    #[test]
    fn stale_commit_records_the_grant() {
        let now = Instant::now();
        let mut l = OwnedRules::default();
        let a = l.add_pending(pmp(1), NetGen(1), gw(), now).unwrap();
        l.orphan_committed(a, now + Duration::from_secs(86_400));
        let e = l.get(a).unwrap();
        assert_eq!(e.state(), RuleState::Orphaned);
        assert_eq!(e.router_expiry(), now + Duration::from_secs(86_400));
        assert!(l.drop_expired(now + Duration::from_secs(60)).is_empty());
        assert_eq!(l.drop_expired(now + Duration::from_secs(86_400)).len(), 1);
    }
}
