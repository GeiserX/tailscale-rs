//! Serialized settlement owner. See the transition table in `docs/PORTMAPPER.md`.
//!
//! This module performs no asynchronous I/O. A caller holds the client state mutex for one
//! event; reservations outlive handle cancellation and are returned only by finalizers.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Phase {
    Running,
    Closing,
    Closed,
}

pub(super) struct NetSnapshot<T> {
    pub(super) net_gen: NetGen,
    pub(super) cap: Arc<T>,
    pub(super) release_cap: Arc<T>,
    pub(super) gateway: Gateway,
}

#[derive(Debug, Default)]
pub(super) struct ProbeCache {
    pub(super) pmp_seen_at: Option<Instant>,
    pub(super) pmp_public_ip: Option<Ipv4Addr>,
    pub(super) pcp_seen_at: Option<Instant>,
    pub(super) last_probe_at: Option<Instant>,
    /// The last probe that sent anything found no service. Until the attempt backoff allows the
    /// next attempt, a probe then sends nothing either, so repeated kicks cannot turn a router
    /// without NAT-PMP or PCP into a probe storm.
    pub(super) found_nothing: bool,
}

impl ProbeCache {
    pub(super) fn fresh(t: Option<Instant>, now: Instant) -> bool {
        t.is_some_and(|t| now.saturating_duration_since(t) < PROBE_CACHE)
    }

    pub(super) fn saw_pmp(&self, now: Instant) -> bool {
        Self::fresh(self.pmp_seen_at, now)
    }

    pub(super) fn saw_pcp(&self, now: Instant) -> bool {
        Self::fresh(self.pcp_seen_at, now)
    }
}

#[derive(Debug, Clone)]
pub(super) struct Held {
    pub(super) m: oneshot::Mapping,
    pub(super) lease: Lease,
    pub(super) net_gen: NetGen,
    pub(super) rule_id: RuleId,
}

pub(super) struct Inflight {
    pub(super) id: u64,
    pub(super) rule_id: RuleId,
    pub(super) abort: Option<AbortHandle>,
}

/// Evidence available when withdrawing the held owner. Reservations survive every variant.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Invalidation {
    /// None: every orphan is deleted once allowed.
    Orphan,
    /// All of them: a delete could reach the wrong router (network down). They stay in the
    /// ledger, never deleted, so a create for the same rule on the same network can adopt them.
    Fence,
    /// This protocol's: the router lost them (epoch rollback). The rule of an attempt in flight
    /// (the `RuleId`) is kept: its MAP may still be committed by the restarted router.
    Reset(Proto, Gateway, Option<RuleId>),
}

pub(super) struct Lifecycle<T> {
    data: View<T>,
}

/// Read projections only. Production callers cannot bypass settlement with a mutable view.
pub(super) struct View<T> {
    pub(super) generation: u64,
    pub(super) phase: Phase,
    pub(super) local_port: Option<NonZeroU16>,
    pub(super) net: Option<NetSnapshot<T>>,
    pub(super) next_net_gen: u64,
    pub(super) probe: ProbeCache,
    pub(super) facets: ProbeFacets,
    pub(super) mapping: Option<Held>,
    pub(super) sched: Schedule,
    pub(super) owned: OwnedRules,
    pub(super) release_caps: HashMap<RuleId, Arc<T>>,
    pub(super) rebind_pending: bool,
    pub(super) inflight: Option<Inflight>,
    pub(super) next_attempt_id: u64,
    /// A caller wanted an attempt that spacing refused or that failed; the driver may retry at
    /// the earliest start.
    pub(super) retry_wanted: bool,
    pub(super) disabled: Option<DisableReason>,
    pub(super) last_clock: Option<(Instant, SystemTime)>,
    /// Distinct operational warnings (lookup, gateway, OS errors, ledger, nonce-verified PCP
    /// refusals) already logged in this network generation.
    pub(super) warned: HashSet<String>,
    /// Distinct warnings about router replies anyone on the LAN can forge (NAT-PMP codes,
    /// unverified PCP headers, malformed replies): a separate budget, so a noisy router or a
    /// spoofer cannot use up the operational one.
    pub(super) warned_router: HashSet<String>,
    /// Info lines already logged in this network generation (suppressed advertisements).
    pub(super) noted: HashSet<String>,
}

impl<T> std::ops::Deref for Lifecycle<T> {
    type Target = View<T>;
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

// Fault-injection tests deliberately violate transitions to audit the independent oracle.
#[cfg(test)]
impl<T> std::ops::DerefMut for Lifecycle<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<T: PxpTransport + 'static> Lifecycle<T> {
    pub(super) fn warn_once(&mut self, key: String) -> bool {
        Self::once(&mut self.data.warned, key)
    }

    /// [`warn_once`](Self::warn_once) for warnings about forgeable router replies.
    pub(super) fn warn_once_router(&mut self, key: String) -> bool {
        Self::once(&mut self.data.warned_router, key)
    }

    pub(super) fn once(set: &mut HashSet<String>, key: String) -> bool {
        if set.contains(&key) || set.len() >= MAX_WARNED {
            return false;
        }
        set.insert(key);
        true
    }

    pub(super) fn note_once(&mut self, key: String) -> bool {
        if self.data.noted.contains(&key) || self.data.noted.len() >= MAX_WARNED {
            return false;
        }
        self.data.noted.insert(key);
        true
    }
}
impl<T: PxpTransport + 'static> Lifecycle<T> {
    pub(super) fn new() -> Self {
        Self {
            data: View {
                generation: 0,
                phase: Phase::Running,
                local_port: None,
                net: None,
                next_net_gen: 1,
                probe: ProbeCache::default(),
                facets: ProbeFacets::default(),
                mapping: None,
                sched: Schedule::default(),
                owned: OwnedRules::default(),
                release_caps: HashMap::new(),
                rebind_pending: false,
                inflight: None,
                next_attempt_id: 0,
                retry_wanted: false,
                disabled: None,
                last_clock: None,
                warned: HashSet::new(),
                warned_router: HashSet::new(),
                noted: HashSet::new(),
            },
        }
    }
    fn invalidate(&mut self, why: &str, evidence: Invalidation) {
        self.cancel_map_handle();
        let had = self.data.mapping.take();
        self.data.owned.orphan_all();
        let gone = match evidence {
            Invalidation::Orphan => Vec::new(),
            Invalidation::Fence => self.data.owned.forget_orphans(),
            Invalidation::Reset(p, gateway, keep) => self.data.owned.drop_proto(p, &gateway, keep),
        };
        for e in &gone {
            log_left(e, LeftReason::NetworkGone);
        }
        if let Some(h) = had {
            tracing::info!(
                proto = %h.m.proto,
                external = %h.m.external,
                reason = why,
                "portmapper: mapping lost"
            );
        }
    }

    pub(super) fn network_down(&mut self, why: &str) {
        self.invalidate(why, Invalidation::Fence);
        if let Some(net) = self.data.net.take() {
            net.cap.invalidate();
        }
        for cap in self.data.release_caps.values() {
            cap.invalidate();
        }
        self.data.rebind_pending = false;
        self.data.probe = ProbeCache::default();
        if self.data.disabled.is_none() {
            self.data.facets = ProbeFacets::default();
        }
        self.data.warned.clear();
        self.data.warned_router.clear();
        self.data.noted.clear();
    }

    pub(super) fn lease_expired(&mut self, now: Instant) {
        let Some(h) = self.data.mapping.take() else {
            return;
        };
        tracing::info!(
            proto = %h.m.proto,
            external = %h.m.external,
            "portmapper: mapping expired"
        );
        // Removing the held lease removes its owner, even while a renewal reserves the wire
        // identity. Keep that reservation and the possible grant; a success may still commit.
        self.data.owned.orphan(h.rule_id);
        let renewing = self
            .data
            .inflight
            .as_ref()
            .is_some_and(|i| i.rule_id == h.rule_id);
        if renewing {
            return;
        }
        // The router may hold it longer than we trusted it (PCP may grant more than asked): then
        // it is deleted like any leftover; otherwise it is simply gone.
        if self
            .data
            .owned
            .get(h.rule_id)
            .is_some_and(|e| e.mapping() || e.router_expiry() > now)
        {
            self.data.owned.orphan(h.rule_id);
        } else {
            #[cfg(test)]
            self.data.owned.record_retirement(
                h.rule_id,
                crate::ownership_model::Retirement::Expiry { observed_at: now },
            );
            self.data.owned.remove(h.rule_id);
        }
    }

    pub(super) fn router_reset(
        &mut self,
        proto: Proto,
        epoch: u32,
        started: Instant,
        gateway: &Gateway,
    ) -> bool {
        if epoch == 0 {
            return false;
        }
        let Some(h) = &self.data.mapping else {
            return false;
        };
        if h.m.proto != proto || epoch >= h.m.epoch || h.lease.committed_at > started {
            return false;
        }
        #[cfg(test)]
        let reset_owner = (h.m.epoch, h.lease.committed_at);
        tracing::info!(
            %proto,
            epoch,
            stored = h.m.epoch,
            "portmapper: router epoch went back; it restarted and lost the mapping"
        );
        let inflight = self.data.inflight.as_ref().map(|i| i.rule_id).filter(|id| {
            self.data
                .owned
                .get(*id)
                .is_some_and(|e| e.rule.proto() == proto)
        });
        #[cfg(test)]
        self.data.owned.model.accept_reset(
            gateway.clone(),
            proto,
            reset_owner.0,
            epoch,
            reset_owner.1,
            started,
        );
        self.invalidate(
            "router restarted",
            Invalidation::Reset(proto, gateway.clone(), inflight),
        );
        if let Some(id) = inflight {
            // The in-flight request may receive an unobserved grant longer than requested.
            self.data.owned.orphan(id);
        }
        match proto {
            Proto::Pmp => {
                self.data.probe.pmp_seen_at = None;
                self.data.probe.pmp_public_ip = None;
            }
            Proto::Pcp => self.data.probe.pcp_seen_at = None,
        }
        true
    }

    pub(super) fn map_success(
        &mut self,
        ctx: &AttemptCtx<T>,
        m: oneshot::Mapping,
        now: Instant,
    ) -> (bool, bool) {
        let mut need_cleanup = false;
        let mut publish = false;
        let stale = self.attempt_stale(ctx);

        let lease = Lease::new(now, m.lifetime);
        if stale {
            self.data
                .owned
                .orphan_committed(ctx.rule_id, lease.router_expiry);
            tracing::info!(
                proto = %m.proto,
                external = %m.external,
                "portmapper: discarding a mapping that arrived after an \
                 invalidation; deleting it"
            );
            need_cleanup = true;
        } else {
            self.data.owned.commit(ctx.rule_id, lease.router_expiry);
            let old = self.data.mapping.take();
            if let Some(old) = &old
                && old.rule_id != ctx.rule_id
            {
                // A protocol switch or a new internal port: the old rule is released.
                self.data.owned.orphan(old.rule_id);
                need_cleanup = true;
            }
            match &old {
                Some(o) if o.m.external == m.external => tracing::debug!(
                    proto = %m.proto,
                    external = %m.external,
                    lease = m.lifetime,
                    "portmapper: mapping renewed"
                ),
                Some(o) => tracing::info!(
                    proto = %m.proto,
                    external = %m.external,
                    previous = %o.m.external,
                    lease = m.lifetime,
                    "portmapper: mapping renewed with a new external address"
                ),
                None => tracing::info!(
                    proto = %m.proto,
                    external = %m.external,
                    lease = m.lifetime,
                    "portmapper: mapping obtained"
                ),
            }
            self.data.mapping = Some(Held {
                m,
                lease,
                net_gen: ctx.net_gen,
                rule_id: ctx.rule_id,
            });
            self.data.sched.note_success();
            publish = true;
        }
        (publish, need_cleanup)
    }

    fn attempt_stale(&self, ctx: &AttemptCtx<T>) -> bool {
        ctx.generation != self.data.generation
            || self.data.phase != Phase::Running
            || self.data.disabled.is_some()
    }
    pub(super) fn map_refused(&mut self, ctx: &AttemptCtx<T>, e: MapError, now: Instant) -> bool {
        let mut need_cleanup = false;
        let stale = self.attempt_stale(ctx);
        // A renewal whose mapping is gone (expired meanwhile) settles like a create.
        let renewal = ctx.prev.is_some()
            && self
                .data
                .mapping
                .as_ref()
                .is_some_and(|h| h.rule_id == ctx.rule_id);

        self.data.owned.discard_unsent(ctx.rule_id);
        if !renewal {
            match &e {
                MapError::PmpAddr { map: Some(r), .. } => self
                    .data
                    .owned
                    .orphan_committed(ctx.rule_id, lease_deadline(now, r.lifetime)),
                e if ctx.existed || may_exist(e) => self.data.owned.orphan(ctx.rule_id),
                _ => {
                    #[cfg(test)]
                    self.data.owned.record_retirement(
                        ctx.rule_id,
                        crate::ownership_model::Retirement::Refusal(match &e {
                            MapError::Pmp { .. } => {
                                crate::ownership_model::RefusalEvidence::MatchedMap(Proto::Pmp)
                            }
                            MapError::Pcp { .. } => {
                                crate::ownership_model::RefusalEvidence::MatchedMap(Proto::Pcp)
                            }
                            _ => crate::ownership_model::RefusalEvidence::Unproven,
                        }),
                    );
                    self.data.owned.remove(ctx.rule_id);
                }
            }
            need_cleanup |= self.data.owned.has_orphans();
        }
        if !stale {
            self.data
                .sched
                .note_failure(now, failure_kind(&e), jitter());
            // The wanted mapping is still missing (or due): retry at the backoff.
            self.data.retry_wanted = true;
            let (key, router) = warn_key(&e);
            let key = format!("map {key}");
            let first = if router {
                self.warn_once_router(key)
            } else {
                self.warn_once(key)
            };
            if first {
                tracing::warn!(
                    proto = %ctx.rule.proto(),
                    error = %e,
                    "portmapper: mapping attempt failed"
                );
            } else {
                tracing::debug!(error = %e, "portmapper: mapping attempt failed");
            }
        }
        need_cleanup
    }
}

/// The guard carries an event, not a second copy of lifecycle state.
pub(super) enum FinalizerEvent {
    Map { id: u64, rule_id: RuleId },
    Delete(Vec<RuleId>),
    FinalRelease(Vec<RuleId>),
    Close,
}

impl<T: PxpTransport + 'static> Lifecycle<T> {
    fn cancel_map_handle(&mut self) {
        self.data.generation += 1;
        if let Some(i) = self.data.inflight.take()
            && let Some(a) = i.abort
        {
            a.abort();
        }
    }
    pub(super) fn map_task_attached(&mut self, id: u64, abort: AbortHandle) {
        if let Some(i) = &mut self.data.inflight
            && i.id == id
        {
            i.abort = Some(abort);
        }
    }
    pub(super) fn map_finished(&mut self, id: u64, rule_id: RuleId) {
        self.data.owned.finish_map(rule_id);
        if self.data.inflight.as_ref().is_some_and(|i| i.id == id) {
            self.data.inflight = None;
        }
    }
    pub(super) fn cleanup_cancelled(&mut self, ids: &[RuleId]) {
        for id in ids {
            self.data.owned.unclaim(*id);
        }
    }
    pub(super) fn final_release_finished(&mut self, ids: &[RuleId]) {
        // No acknowledgement was awaited: release the reservation, never the admission slot.
        self.cleanup_cancelled(ids);
    }
    pub(super) fn delete_validation_failed(&mut self, id: RuleId, closing: bool, now: Instant) {
        if closing {
            self.data.owned.abandon(id);
        } else {
            self.data.owned.defer_delete(id, now);
        }
    }
    pub(super) fn delete_fenced(&mut self, id: RuleId) {
        self.data.owned.abandon(id);
    }
    pub(super) fn final_release_started(
        &mut self,
        policy: &PolicyHandle,
        now: Instant,
    ) -> Vec<OwnedRule> {
        if !policy.lan_sends_allowed() {
            return Vec::new();
        }
        self.data.owned.claim_final_releases(now)
    }
    pub(super) fn rebind_failed(&mut self) {
        self.data.local_port = None;
        self.invalidate("rebind failed", Invalidation::Orphan);
    }
    pub(super) fn map_started(
        &mut self,
        cfg: &Config<T>,
        policy: &PolicyHandle,
        now: Instant,
    ) -> Result<(u64, AttemptCtx<T>), Error> {
        // Only a refusal by attempt spacing or a failure asks the driver to come back; any other
        // outcome of this request (started, busy, disabled, offline) does not.
        self.data.retry_wanted = false;
        if self.data.phase != Phase::Running || tokio::runtime::Handle::try_current().is_err() {
            return Err(Error::Closed);
        }
        if self.data.disabled.is_some() || !policy.lan_sends_allowed() {
            return Err(Error::Disabled);
        }
        let local_port = self.data.local_port.ok_or(Error::NoLocalPort)?;
        let Some(net) = &self.data.net else {
            return Err(Error::NoNetwork);
        };
        let (cap, net_gen, gateway) = (net.cap.clone(), net.net_gen, net.gateway.clone());
        if self.data.inflight.is_some() || !cap.is_valid() || self.data.rebind_pending {
            return Err(Error::Busy);
        }
        if !self.data.sched.may_start(now) {
            self.data.retry_wanted = true;
            return Err(Error::Backoff);
        }
        let protos = cfg.protos;
        let recent_pmp = self.data.probe.saw_pmp(now);
        let recent_pcp = self.data.probe.saw_pcp(now);
        let probed_recently = self
            .data
            .probe
            .last_probe_at
            .is_some_and(|t| now.saturating_duration_since(t) < RECENT_PROBE);
        if (!protos.pmp && !protos.pcp) || (probed_recently && !recent_pmp && !recent_pcp) {
            self.data.sched.note_start(now);
            self.data
                .sched
                .note_failure(now, Failure::Transient, jitter());
            self.data.retry_wanted = true;
            return Err(Error::NoServices);
        }
        let prefer_pcp = protos.pcp && (!protos.pmp || (!recent_pmp && recent_pcp));
        let mut proto = if prefer_pcp { Proto::Pcp } else { Proto::Pmp };
        // An orphan still owns the same UDP wire identity. Adopt its protocol and nonce;
        // never create an alias while any MAP or delete (including OS validation) owns it.
        if let Some(e) = self.data.owned.for_identity(local_port, &gateway) {
            if e.mapping() || e.deleting() {
                self.data.retry_wanted = true;
                return Err(Error::Busy);
            }
            proto = e.rule.proto();
            if !match proto {
                Proto::Pmp => protos.pmp,
                Proto::Pcp => protos.pcp,
            } {
                return Err(Error::Busy);
            }
        }

        // A renewal: the same rule (protocol, internal port, nonce) on the same network.
        let prev = self
            .data
            .mapping
            .as_ref()
            .filter(|h| h.net_gen == net_gen && h.m.proto == proto && h.m.internal == local_port)
            .cloned();
        let adopted = match &prev {
            Some(_) => None,
            None => self.data.owned.adopt(proto, local_port, &gateway, net_gen),
        };
        let rule = match (&prev, &adopted) {
            (Some(h), _) => h.m.rule(),
            (None, Some((_, rule))) => rule.clone(),
            (None, None) => Rule::new(proto, local_port).map_err(Error::Nonce)?,
        };
        let existing = adopted
            .map(|(id, _)| id)
            .or_else(|| self.data.owned.live_for(&rule, net_gen));
        let existed = existing.is_some();
        let rule_id = match existing {
            Some(id) => id,
            None => match self
                .data
                .owned
                .add_pending(rule.clone(), net_gen, gateway, now)
            {
                Some(id) => id,
                None => {
                    if self.warn_once("ledger full".to_owned()) {
                        tracing::warn!(
                            "portmapper: too many router rules outstanding; not mapping until \
                             they are deleted or expire"
                        );
                    }
                    return Err(Error::LedgerFull);
                }
            },
        };
        let ids: HashSet<_> = self.data.owned.entries().iter().map(|e| e.id).collect();
        self.data.release_caps.retain(|id, _| ids.contains(id));
        if let Some(net) = &self.data.net {
            self.data
                .release_caps
                .insert(rule_id, net.release_cap.clone());
        }
        let evidence = self
            .data
            .owned
            .claim_map(rule_id, now, existed)
            .ok_or(Error::Busy)?;
        self.data.sched.note_start(now);
        let id = self.data.next_attempt_id;
        self.data.next_attempt_id += 1;
        let ctx = AttemptCtx {
            generation: self.data.generation,
            cap,
            net_gen,
            rule,
            rule_id,
            existed,
            evidence,
            prev: prev.map(|h| h.m),
        };
        self.data.inflight = Some(Inflight {
            id,
            rule_id,
            abort: None,
        });
        Ok((id, ctx))
    }

    pub(super) fn network_validated(
        &mut self,
        gw: Gateway,
        net_gen: NetGen,
        cap: Arc<T>,
        release_cap: Arc<T>,
    ) -> bool {
        let same = self
            .data
            .net
            .as_ref()
            .is_some_and(|n| n.gateway.same_network(&gw));
        if let Some(old) = self.data.net.take() {
            old.cap.invalidate();
        }
        if !same {
            self.invalidate("network changed", Invalidation::Orphan);
            self.data.probe = ProbeCache::default();
            if self.data.disabled.is_none() {
                self.data.facets = ProbeFacets::default();
            }
            self.data.sched.note_network_change();
            self.data.warned.clear();
            self.data.warned_router.clear();
            self.data.noted.clear();
            tracing::info!(gateway = %gw, "portmapper: gateway found or changed");
        }
        // A same-network rebind restores the trusted mapping only after this fresh validation.
        let ids: Vec<_> = self
            .data
            .owned
            .entries()
            .iter()
            .filter(|e| e.gateway.same_network(&gw))
            .map(|e| e.id)
            .collect();
        for id in ids {
            self.data.release_caps.insert(id, release_cap.clone());
        }
        self.data.rebind_pending = false;
        self.data.net = Some(NetSnapshot {
            net_gen,
            cap,
            release_cap,
            gateway: gw,
        });
        same
    }

    pub(super) fn clock_aged(&mut self, now: Instant, slept: Duration) -> bool {
        self.data.probe = ProbeCache::default();
        // Wall-clock movement may be a correction rather than real sleep. Age trusted
        // advertisements, but never free ownership slots using that unverified evidence.
        let mut changed = false;
        if let Some(h) = &mut self.data.mapping {
            if !slept.is_zero() {
                h.lease.age(slept, now);
                changed = true;
            }
            h.lease.renew_after = h.lease.renew_after.min(now);
        }
        if self
            .data
            .mapping
            .as_ref()
            .is_some_and(|h| h.lease.expired(now))
        {
            self.lease_expired(now);
        }
        changed
    }

    pub(super) fn port_changed(&mut self, new: Option<NonZeroU16>) -> bool {
        if self.data.local_port == new {
            false
        } else {
            let had = self.data.local_port.is_some()
                || self.data.mapping.is_some()
                || self.data.inflight.is_some();
            self.data.local_port = new;
            if had {
                self.invalidate("local port changed", Invalidation::Orphan);
            }
            had
        }
    }

    pub(super) fn rebind_started(&mut self, same: bool) {
        if same {
            self.cancel_map_handle();
        }
        self.data.rebind_pending = true;
        if let Some(net) = &self.data.net {
            net.cap.invalidate();
        }
    }

    pub(super) fn policy_disabled(&mut self, why: DisableReason) -> bool {
        if self.data.disabled == Some(why) {
            return false;
        }
        self.data.disabled = Some(why);
        self.invalidate("disabled", Invalidation::Orphan);
        self.data.facets.pmp = Some(false);
        self.data.facets.pcp = Some(false);
        if self.data.owned.has_orphans() {
            tracing::info!(
                rules = self.data.owned.len(),
                "portmapper: disabled; router rules are left until re-enabled or until they expire"
            );
        } else {
            tracing::info!("portmapper: disabled");
        }
        true
    }

    pub(super) fn policy_enabled(&mut self, policy: &PolicyHandle) -> bool {
        if self.data.disabled.is_none() {
            return false;
        }
        self.data.disabled = None;
        if self.data.phase == Phase::Running {
            policy.set_lan_sends_allowed(true);
        }
        self.data.facets = ProbeFacets::default();
        tracing::info!("portmapper: re-enabled");
        true
    }

    pub(super) fn cleanup_started(
        &mut self,
        closing: bool,
        policy: &PolicyHandle,
        now: Instant,
    ) -> Vec<OwnedRule> {
        for e in self.data.owned.drop_expired(now) {
            log_left(&e, LeftReason::Expired);
        }
        if !policy.lan_sends_allowed()
            || self.data.phase
                != if closing {
                    Phase::Closing
                } else {
                    Phase::Running
                }
        {
            return Vec::new();
        }
        if closing {
            self.data.owned.claim_for_close(now)
        } else {
            self.data.owned.claim_orphans(now)
        }
    }

    pub(super) fn delete_acknowledged(&mut self, id: RuleId, now: Instant) {
        self.data.owned.finish_delete(id, true, now);
    }

    pub(super) fn delete_unacknowledged(&mut self, id: RuleId, now: Instant) {
        if let Some(gone) = self.data.owned.finish_delete(id, false, now) {
            tracing::info!(internal = gone.rule.internal().get(), proto = %gone.rule.proto(),
                    "portmapper: rule retained; cleanup retries slowed to ten minutes");
        }
    }

    pub(super) fn close_started(&mut self) -> bool {
        if self.data.phase != Phase::Running {
            return false;
        }
        self.data.phase = Phase::Closing;
        self.invalidate("closing", Invalidation::Orphan);
        if let Some(net) = &self.data.net {
            net.cap.invalidate();
        }
        true
    }

    pub(super) fn close_finished(&mut self) {
        if self.data.phase == Phase::Closing {
            self.data.phase = Phase::Closed;
            // An operation may hand back its claim just as the deadline expires. Give every
            // unresolved entry the final duty, rather than testing a transient busy flag here.
            // A concurrent Drop may already have consumed that duty: never rearm it.
            self.data.owned.request_final_release();
        }
        if !self.data.owned.is_empty() {
            tracing::info!(
                rules = self.data.owned.len(),
                "portmapper: closed with router rules left to expire"
            );
        }
    }

    pub(super) fn drop_requested(&mut self) -> bool {
        if self.data.phase == Phase::Closed {
            return false;
        }
        self.data.phase = Phase::Closed;
        self.invalidate("closing", Invalidation::Orphan);
        if let Some(net) = &self.data.net {
            net.cap.invalidate();
        }
        self.data.owned.request_final_release();
        true
    }
}

impl<T: PxpTransport + 'static> Lifecycle<T> {
    pub(super) fn probe_observed(
        &mut self,
        r: &oneshot::ProbeReport,
        want: ProtoSet,
        protos: ProtoSet,
        started: Instant,
        now: Instant,
        gateway: &Gateway,
    ) -> bool {
        let mut rolled_back = false;
        let before = self.data.facets;
        if want.pmp {
            if r.pmp {
                // The reset check runs before the fresh answer is recorded, since a reset clears
                // what it would record (Go: "must be before we write to c.pmp*",
                // net/portmapper/portmapper.go:1138-1141).
                if let Some(e) = r.pmp_epoch {
                    rolled_back |= self.router_reset(Proto::Pmp, e, started, gateway);
                }
                self.data.probe.pmp_seen_at = Some(now);
                self.data.probe.pmp_public_ip = r.pmp_public_ip;
            }
            self.data.facets.pmp = Some(r.pmp);
        } else if protos.pmp {
            self.data.facets.pmp = Some(true);
        }
        if want.pcp {
            if r.pcp {
                // Before the write, as Go does (net/portmapper/portmapper.go:1098-1101).
                if let Some(e) = r.pcp_epoch {
                    rolled_back |= self.router_reset(Proto::Pcp, e, started, gateway);
                }
                self.data.probe.pcp_seen_at = Some(now);
            }
            self.data.facets.pcp = Some(r.pcp);
            if let Some(code @ (pcp::ResultCode::NotAuthorized | pcp::ResultCode::AddressMismatch)) =
                r.pcp_result
                && self.warn_once_router(format!("announce {}", pcp_code_key(code)))
            {
                tracing::warn!(result = %code, "portmapper: PCP server will not map for us");
            }
        } else if protos.pcp {
            self.data.facets.pcp = Some(true);
        }
        self.data.probe.last_probe_at = Some(now);
        self.data.probe.found_nothing =
            !self.data.probe.saw_pmp(now) && !self.data.probe.saw_pcp(now);
        if self.data.facets != before {
            tracing::info!(
                pmp = ?self.data.facets.pmp,
                pcp = ?self.data.facets.pcp,
                "portmapper: probe result changed"
            );
        }
        rolled_back
    }
    pub(super) fn clock_observed(&mut self, now: Instant, wall: SystemTime) -> Option<Duration> {
        // (whether the clocks disagree, how much further the wall clock moved)
        let seen = self.data.last_clock.map(|(n0, w0)| {
            let mono = now.saturating_duration_since(n0);
            match wall.duration_since(w0) {
                Ok(real) => (real.abs_diff(mono) > CLOCK_SKEW, real.saturating_sub(mono)),
                Err(e) => (e.duration() + mono > CLOCK_SKEW, Duration::ZERO),
            }
        });
        self.data.last_clock = Some((now, wall));
        match seen {
            Some((true, slept)) => Some(slept),
            _ => None,
        }
    }
    pub(super) fn delete_validated(&mut self, id: RuleId, closing: bool, cap: Arc<T>) -> bool {
        // A fresh lookup cannot revive a fenced entry or a closed operation.
        if (!closing && self.data.phase != Phase::Running)
            || !self
                .data
                .owned
                .get(id)
                .is_some_and(|r| r.releasable() && r.deleting())
        {
            return false;
        }
        self.data.release_caps.insert(id, cap);
        true
    }
    pub(super) fn network_lookup_started(&mut self) -> NetGen {
        let g = NetGen(self.data.next_net_gen);
        self.data.next_net_gen += 1;
        g
    }
    pub(super) fn probe_cached(&mut self, now: Instant) {
        self.data.probe.last_probe_at = Some(now);
    }
}
