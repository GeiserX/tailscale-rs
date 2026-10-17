//! Test-only conservation model. Admission and retirement are separate observations: removing
//! an entry cannot manufacture its own evidence. Fenced/terminal unacknowledged orphans remain
//! possible ownership and count against admission; sending a final delete is not retirement.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use tokio::time::Instant;

use crate::{
    Gateway,
    oneshot::Proto,
    owned::{OwnedRule, RuleId},
};

#[derive(Debug, Clone)]
pub(crate) enum RefusalEvidence {
    MatchedMap(Proto),
    Unproven,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ResetId(usize);

impl ResetId {
    pub(crate) const MISSING: Self = Self(usize::MAX);
}

#[derive(Debug, Clone)]
pub(crate) enum Retirement {
    /// A matched refusal of the MAP request.
    Refusal(RefusalEvidence),
    /// Every recorded MAP attempt for a fresh identity stopped before its syscall boundary.
    ProvenUnsent,
    Delete {
        matched: bool,
    },
    Expiry {
        observed_at: Instant,
    },
    Reset {
        observation: ResetId,
        gateway: Gateway,
        proto: Proto,
    },
}

#[derive(Debug)]
struct AcceptedReset {
    sequence: usize,
    gateway: Gateway,
    proto: Proto,
    previous: u32,
    reported: u32,
    committed: Instant,
    probe_started: Instant,
}

#[derive(Debug, Default)]
pub(crate) struct OwnershipModel {
    admitted: HashMap<RuleId, OwnedRule>,
    retired: HashMap<RuleId, (OwnedRule, Retirement, usize)>,
    last_map: HashMap<RuleId, usize>,
    sequence: usize,
    attempts: HashMap<RuleId, Vec<Arc<crate::SendEvidence>>>,
    resets: Vec<AcceptedReset>,
}

fn wire_gateway(a: &Gateway, b: &Gateway) -> bool {
    a.gw == b.gw && a.self_ip == b.self_ip && a.if_index == b.if_index
}

impl OwnershipModel {
    pub(crate) fn admit(&mut self, entry: OwnedRule) {
        self.sequence += 1;
        self.last_map.insert(entry.id, self.sequence);
        assert!(
            self.admitted.insert(entry.id, entry).is_none(),
            "reused admission id"
        );
    }

    pub(crate) fn map_started(&mut self, id: RuleId, evidence: Arc<crate::SendEvidence>) {
        self.attempts.entry(id).or_default().push(evidence);
        self.sequence += 1;
        self.last_map.insert(id, self.sequence);
    }

    pub(crate) fn latest_reset(&self) -> ResetId {
        self.resets
            .len()
            .checked_sub(1)
            .map(ResetId)
            .unwrap_or(ResetId::MISSING)
    }

    pub(crate) fn retire(&mut self, entry: OwnedRule, evidence: Retirement) {
        self.sequence += 1;
        assert!(
            self.retired
                .insert(entry.id, (entry, evidence, self.sequence))
                .is_none(),
            "double retirement"
        );
    }

    pub(crate) fn accept_reset(
        &mut self,
        gateway: Gateway,
        proto: Proto,
        previous: u32,
        reported: u32,
        committed: Instant,
        probe_started: Instant,
    ) -> ResetId {
        self.sequence += 1;
        let id = ResetId(self.resets.len());
        self.resets.push(AcceptedReset {
            sequence: self.sequence,
            gateway,
            proto,
            previous,
            reported,
            committed,
            probe_started,
        });
        id
    }

    pub(crate) fn check(&self, entries: &[OwnedRule]) {
        let live: HashSet<_> = entries.iter().map(|e| e.id).collect();
        assert_eq!(live.len(), entries.len(), "duplicate live id");
        assert_eq!(
            self.admitted.len(),
            live.len() + self.retired.len(),
            "possible ownership disappeared without retirement evidence"
        );
        for (id, admitted) in &self.admitted {
            let entry = if let Some(entry) = entries.iter().find(|e| e.id == *id) {
                assert!(
                    !self.retired.contains_key(id),
                    "retired entry is still live"
                );
                entry
            } else {
                let (entry, reason, retired_sequence) =
                    self.retired.get(id).expect("unexplained retirement");
                match reason {
                    Retirement::Refusal(evidence) => match evidence {
                        RefusalEvidence::MatchedMap(proto) => {
                            assert_eq!(*proto, entry.rule.proto(), "foreign MAP refusal")
                        }
                        RefusalEvidence::Unproven => panic!("unmatched refusal"),
                    },
                    Retirement::ProvenUnsent => {
                        let attempts = self
                            .attempts
                            .get(id)
                            .expect("unsent retirement has no attempt evidence");
                        assert!(
                            !attempts.is_empty()
                                && attempts.iter().all(|e| e.possible_until().is_none()),
                            "attempted MAP cannot retire as proven unsent"
                        );
                    }
                    Retirement::Delete { matched } => assert!(*matched, "unacknowledged delete"),
                    Retirement::Expiry { observed_at } => assert!(
                        entry.router_expiry() <= *observed_at,
                        "requested lifetime/trust expiry is not proven router expiry"
                    ),
                    Retirement::Reset {
                        observation,
                        gateway,
                        proto,
                    } => {
                        assert!(
                            wire_gateway(gateway, &entry.gateway) && *proto == entry.rule.proto(),
                            "foreign router/protocol reset cannot retire this entry"
                        );
                        let r = self
                            .resets
                            .get(observation.0)
                            .expect("unknown reset observation");
                        assert!(
                            wire_gateway(&r.gateway, gateway)
                                && r.proto == *proto
                                && r.reported > 0
                                && r.reported < r.previous
                                && r.committed <= r.probe_started
                                && admitted.sent_at <= r.probe_started
                                && self.last_map[id] <= r.sequence
                                && r.sequence < *retired_sequence,
                            "reset observation falls outside this ownership lifetime"
                        );
                    }
                }
                entry
            };
            assert_eq!(
                admitted.rule, entry.rule,
                "ownership changed protocol/nonce in place"
            );
            assert!(
                wire_gateway(&admitted.gateway, &entry.gateway),
                "ownership moved to another wire gateway"
            );
        }
        assert!(
            self.retired.keys().all(|id| self.admitted.contains_key(id)),
            "retired unknown id"
        );
    }
}
