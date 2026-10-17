//! The minimal one-shot client: a single probe, map or delete over a [`PxpTransport`], with no
//! state machine, no retries and no caching.
//!
//! The lifecycle client performs its I/O through these same functions, so there is only
//! one implementation of the wire exchanges. Each call is one exchange against an absolute
//! [`EXCHANGE_TIMEOUT`] deadline. Replies that do not validate are ignored (and remembered for
//! diagnostics) until the deadline. A router error ends the exchange at once only when it is tied
//! to our request: a NAT-PMP MAP reply for our internal port, or a PCP response that echoes our
//! nonce. A nonce-less PCP error (or a NAT-PMP "unsupported version" answer to PCP) is only a
//! fallback, reported if nothing better arrives by the deadline.

use std::{
    fmt,
    net::{Ipv4Addr, SocketAddrV4},
    num::{NonZeroU16, NonZeroU32},
    time::Duration,
};

use tokio::time::Instant;

use crate::{
    cap::{CapError, EXCHANGE_TIMEOUT, ExchangeStats, Flow, LanDest, PxpTransport},
    pcp, pmp,
};

/// At most this many distinct malformed-reply reasons are kept per exchange.
const MAX_NOTES: usize = 4;
/// The longest error lifetime taken from a PCP error that carries no nonce (anyone on the LAN
/// could have sent it), in seconds.
pub const MAX_UNVERIFIED_ERROR_LIFETIME: u32 = 1800;

/// A port-mapping protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    /// NAT-PMP (RFC 6886).
    Pmp,
    /// PCP (RFC 6887).
    Pcp,
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pmp => "pmp",
            Self::Pcp => "pcp",
        })
    }
}

/// Which protocols to exercise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtoSet {
    /// NAT-PMP.
    pub pmp: bool,
    /// PCP.
    pub pcp: bool,
}

impl ProtoSet {
    /// Both protocols.
    pub const BOTH: Self = Self {
        pmp: true,
        pcp: true,
    };

    /// The selected protocols, NAT-PMP first.
    pub fn iter(self) -> impl Iterator<Item = Proto> {
        [(self.pmp, Proto::Pmp), (self.pcp, Proto::Pcp)]
            .into_iter()
            .filter_map(|(on, p)| on.then_some(p))
    }
}

/// What a probe learned.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProbeReport {
    /// A NAT-PMP server answered the public-address request with success.
    pub pmp: bool,
    /// The NAT-PMP epoch from the reply (success or error).
    pub pmp_epoch: Option<u32>,
    /// The public address NAT-PMP reported.
    pub pmp_public_ip: Option<Ipv4Addr>,
    /// The NAT-PMP result code, if a reply arrived.
    pub pmp_result: Option<pmp::ResultCode>,
    /// A PCP server answered ANNOUNCE with success. `NOT_AUTHORIZED`, `ADDRESS_MISMATCH` and
    /// other codes mean a PCP server exists but will not map for us.
    pub pcp: bool,
    /// The PCP ANNOUNCE result code, if a reply arrived.
    pub pcp_result: Option<pcp::ResultCode>,
    /// The PCP epoch from the reply.
    pub pcp_epoch: Option<u32>,
    /// Malformed replies and receive errors, verbatim.
    pub errors: Vec<String>,
}

/// A mapping the router granted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    /// The protocol that created it.
    pub proto: Proto,
    /// Our internal port.
    pub internal: NonZeroU16,
    /// The router's public address and assigned external port: never port 0, and always a
    /// plausible external address ([`crate::is_plausible_external`]). It may still be private or
    /// shared (a double NAT): check [`crate::is_advertisable`] before offering it to peers.
    pub external: SocketAddrV4,
    /// The granted lifetime in seconds (never 0). May differ from the requested lifetime.
    pub lifetime: u32,
    /// The router's epoch in the reply.
    pub epoch: u32,
    /// The PCP nonce that owns the mapping (renewals and the delete must reuse it).
    pub nonce: Option<pcp::Nonce>,
}

impl Mapping {
    /// What it takes to delete this mapping.
    pub fn rule(&self) -> Rule {
        match &self.nonce {
            Some(nonce) if self.proto == Proto::Pcp => Rule::Pcp {
                internal: self.internal,
                nonce: nonce.clone(),
            },
            _ => Rule::Pmp {
                internal: self.internal,
            },
        }
    }

    /// When the router's grant ends, counted from `granted_at`.
    pub fn expires_at(&self, granted_at: Instant) -> Instant {
        lease_deadline(granted_at, self.lifetime)
    }
}

/// `now + secs`, covering the full wire lifetime range without arithmetic overflow.
pub fn lease_deadline(now: Instant, secs: u32) -> Instant {
    let d = Duration::from_secs(u64::from(secs));
    now.checked_add(d).unwrap_or(now)
}

/// Enough to delete a rule, even one whose create reply was lost: NAT-PMP needs only the
/// internal port, PCP also the nonce the create was sent with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    /// A NAT-PMP rule.
    Pmp {
        /// Internal port.
        internal: NonZeroU16,
    },
    /// A PCP rule.
    Pcp {
        /// Internal port.
        internal: NonZeroU16,
        /// The nonce it was created with.
        nonce: pcp::Nonce,
    },
}

impl Rule {
    /// A new rule for `internal`; PCP gets a fresh nonce from the OS CSPRNG.
    pub fn new(proto: Proto, internal: NonZeroU16) -> Result<Self, pcp::NonceError> {
        Ok(match proto {
            Proto::Pmp => Self::Pmp { internal },
            Proto::Pcp => Self::Pcp {
                internal,
                nonce: pcp::Nonce::random()?,
            },
        })
    }

    /// The rule's internal port.
    pub fn internal(&self) -> NonZeroU16 {
        match self {
            Self::Pmp { internal } | Self::Pcp { internal, .. } => *internal,
        }
    }

    /// The rule's protocol.
    pub fn proto(&self) -> Proto {
        match self {
            Self::Pmp { .. } => Proto::Pmp,
            Self::Pcp { .. } => Proto::Pcp,
        }
    }
}

/// Why a map or delete failed.
#[derive(Debug, thiserror::Error)]
pub enum MapError {
    /// The capability refused or the OS failed (verbatim).
    #[error("{0}")]
    Cap(CapError),
    /// No acceptable reply before the deadline.
    #[error("no port-mapping service answered{}", .malformed.as_ref().map(|m| format!(" (ignored: {m})")).unwrap_or_default())]
    NoServices {
        /// The last malformed or receive problem seen, if any.
        malformed: Option<String>,
    },
    /// A NAT-PMP error reply to the MAP request itself (or, for a PCP rule, a NAT-PMP server's
    /// "unsupported version" answer).
    #[error("NAT-PMP {code} (epoch {epoch})")]
    Pmp {
        /// Result code.
        code: pmp::ResultCode,
        /// Router epoch.
        epoch: u32,
    },
    /// An identity-free NAT-PMP error; it does not prove a MAP was refused.
    #[error("NAT-PMP {code} without request identity (epoch {epoch})")]
    PmpUnverified {
        /// Result code.
        code: pmp::ResultCode,
        /// Claimed router epoch.
        epoch: u32,
    },
    /// A PCP error reply; `lifetime` is how long the error stays current.
    #[error("PCP {code} (error lifetime {lifetime} s, epoch {epoch})")]
    Pcp {
        /// Result code.
        code: pcp::ResultCode,
        /// Error lifetime in seconds.
        lifetime: u32,
        /// Router epoch.
        epoch: u32,
    },
    /// A NAT-PMP error reply to the public-address request sent alongside the MAP. The MAP was
    /// sent too and may have been committed (MiniUPnPd adds the redirect without checking the WAN
    /// address), so the rule must be treated as possibly existing. `map` is the MAP's success
    /// reply, if one arrived.
    #[error("NAT-PMP public address: {code} (epoch {epoch}); the MAP may exist")]
    PmpAddr {
        /// Result code of the public-address reply.
        code: pmp::ResultCode,
        /// Router epoch.
        epoch: u32,
        /// The MAP's success reply, if it arrived before the deadline.
        map: Option<pmp::MapReply>,
    },
    /// A header-only PCP error that arrived with no nonce-matched reply by the deadline. It is not
    /// tied to our request (anyone on the LAN could have sent it), so the MAP may still have been
    /// committed. `lifetime` is capped at [`MAX_UNVERIFIED_ERROR_LIFETIME`].
    #[error("PCP {code} without a nonce (error lifetime {lifetime} s, epoch {epoch})")]
    PcpUnverified {
        /// Result code.
        code: pcp::ResultCode,
        /// Error lifetime in seconds, capped.
        lifetime: u32,
        /// Router epoch.
        epoch: u32,
    },
    /// The OS random source failed while making a PCP nonce.
    #[error("{0}")]
    Nonce(pcp::NonceError),
}

impl From<CapError> for MapError {
    fn from(e: CapError) -> Self {
        Self::Cap(e)
    }
}

/// Remember a malformed reply or receive problem, bounded.
fn note(notes: &mut Vec<String>, what: String) {
    if notes.len() < MAX_NOTES && !notes.contains(&what) {
        notes.push(what);
    }
}

fn finish_notes(stats: &ExchangeStats, notes: &mut Vec<String>) {
    if let Some(e) = &stats.recv_error {
        note(notes, e.to_string());
    }
    if stats.oversize > 0 {
        note(notes, format!("{} oversize datagram(s)", stats.oversize));
    }
    if stats.wrong_source > 0 {
        note(
            notes,
            format!(
                "{} datagram(s) from a source other than the gateway",
                stats.wrong_source
            ),
        );
    }
    if stats.hit_cap {
        note(notes, "too many datagrams; stopped reading".to_owned());
    }
}

fn deadline() -> Instant {
    Instant::now() + EXCHANGE_TIMEOUT
}

/// The outcome of one datagram in a PCP MAP or delete exchange: an authoritative answer, a
/// fallback, or nothing.
enum PcpSeen<T> {
    Answer(Result<T, MapError>),
    Fallback(MapError),
    Ignored,
}

/// Classify one reply to a PCP MAP or delete sent with `nonce` for `internal`.
fn pcp_seen<T>(
    b: &[u8],
    nonce: &pcp::Nonce,
    internal: NonZeroU16,
    kind: pcp::MapKind,
    ok: impl FnOnce(pcp::MapReply) -> T,
    notes: &mut Vec<String>,
) -> PcpSeen<T> {
    match b.first() {
        Some(&pcp::VERSION) => match pcp::parse_map_reply(b, nonce, internal, kind) {
            Ok(r) => PcpSeen::Answer(Ok(ok(r))),
            Err(pcp::ReplyError::Router {
                code,
                lifetime,
                epoch,
            }) => PcpSeen::Answer(Err(MapError::Pcp {
                code,
                lifetime,
                epoch,
            })),
            Err(pcp::ReplyError::Unmatched {
                code,
                lifetime,
                epoch,
            }) => PcpSeen::Fallback(MapError::PcpUnverified {
                code,
                lifetime: lifetime.min(MAX_UNVERIFIED_ERROR_LIFETIME),
                epoch,
            }),
            Err(pcp::ReplyError::Malformed(m)) => {
                note(notes, format!("pcp: {m}"));
                PcpSeen::Ignored
            }
        },
        // A NAT-PMP-only router answers a PCP request with "unsupported version". It carries no
        // nonce either, so it is a fallback too.
        Some(&pmp::VERSION) => match pmp::reply_result(b) {
            Some((code @ pmp::ResultCode::UnsupportedVersion, epoch)) => {
                PcpSeen::Fallback(MapError::PmpUnverified { code, epoch })
            }
            _ => {
                note(notes, "pcp: unexpected NAT-PMP reply".to_owned());
                PcpSeen::Ignored
            }
        },
        _ => {
            note(notes, "pcp: not a PCP reply".to_owned());
            PcpSeen::Ignored
        }
    }
}

/// Probe for NAT-PMP (public-address request) and PCP (ANNOUNCE) in one exchange from one
/// socket. Returns early once every requested protocol has a definitive answer.
pub async fn probe<T: PxpTransport>(t: &T, protos: ProtoSet) -> Result<ProbeReport, CapError> {
    let mut report = ProbeReport::default();
    let pmp_req = pmp::public_address_request();
    let pcp_req = pcp::announce_request(t.gateway().self_ip);
    let mut reqs: Vec<&[u8]> = Vec::new();
    if protos.pmp {
        reqs.push(&pmp_req);
    }
    if protos.pcp {
        reqs.push(&pcp_req);
    }
    if reqs.is_empty() {
        return Ok(report);
    }
    let mut pmp_decided = !protos.pmp;
    let mut pcp_decided = !protos.pcp;
    let mut notes = Vec::new();
    let mut on_reply = |b: &[u8]| {
        match b.first() {
            Some(&pmp::VERSION) if protos.pmp => match pmp::parse_public_addr_reply(b) {
                Ok(r) => {
                    report.pmp = true;
                    report.pmp_epoch = Some(r.epoch);
                    report.pmp_public_ip = Some(r.public_ip);
                    report.pmp_result = Some(pmp::ResultCode::Success);
                    pmp_decided = true;
                }
                Err(
                    pmp::ReplyError::Router { code, epoch }
                    | pmp::ReplyError::Unmatched { code, epoch },
                ) => {
                    if !report.pmp {
                        report.pmp_result = Some(code);
                        report.pmp_epoch = Some(epoch);
                    }
                    // A NAT-PMP-only router answers our PCP request with "unsupported
                    // version"; that says nothing about NAT-PMP itself.
                    if code != pmp::ResultCode::UnsupportedVersion {
                        pmp_decided = true;
                    }
                }
                Err(pmp::ReplyError::Malformed(m)) => note(&mut notes, format!("pmp: {m}")),
            },
            Some(&pcp::VERSION) if protos.pcp => match pcp::parse_announce_reply(b) {
                Ok(a) => {
                    report.pcp = a.result == pcp::ResultCode::Success;
                    report.pcp_result = Some(a.result);
                    report.pcp_epoch = Some(a.epoch);
                    // Any ANNOUNCE reply decides PCP (Go's early-exit rule).
                    pcp_decided = true;
                }
                Err(m) => note(&mut notes, format!("pcp: {m}")),
            },
            Some(v) => note(&mut notes, format!("unexpected version {v}")),
            None => note(&mut notes, "empty datagram".to_owned()),
        }
        if pmp_decided && pcp_decided {
            Flow::Done
        } else {
            Flow::Continue
        }
    };
    let stats = t
        .exchange(LanDest::Pxp, &reqs, deadline(), &mut on_reply)
        .await?;
    finish_notes(&stats, &mut notes);
    report.errors = notes;
    Ok(report)
}

/// Ask for a UDP mapping for `rule` (its protocol, internal port and, for PCP, nonce) lasting
/// `lifetime` seconds. The rule is chosen before sending, so it can be deleted even if the reply
/// is lost. `prev`, a mapping this client holds for the same rule, makes it a renewal: its external
/// port is suggested. NAT-PMP always asks for the public address in the same exchange (one extra
/// datagram), so a renewed mapping never carries a stale WAN address.
pub async fn map<T: PxpTransport>(
    t: &T,
    rule: &Rule,
    lifetime: NonZeroU32,
    prev: Option<&Mapping>,
) -> Result<Mapping, MapError> {
    map_inner(t, rule, lifetime, prev, None).await
}

pub(crate) async fn map_with_evidence<T: PxpTransport>(
    t: &T,
    rule: &Rule,
    lifetime: NonZeroU32,
    prev: Option<&Mapping>,
    evidence: &crate::SendEvidence,
) -> Result<Mapping, MapError> {
    map_inner(t, rule, lifetime, prev, Some(evidence)).await
}

async fn map_inner<T: PxpTransport>(
    t: &T,
    rule: &Rule,
    lifetime: NonZeroU32,
    prev: Option<&Mapping>,
    evidence: Option<&crate::SendEvidence>,
) -> Result<Mapping, MapError> {
    let prev = prev.filter(|p| p.rule() == *rule);
    match rule {
        Rule::Pmp { internal } => map_pmp(t, *internal, lifetime, prev, evidence).await,
        Rule::Pcp { internal, nonce } => {
            map_pcp(t, *internal, lifetime, prev, nonce.clone(), evidence).await
        }
    }
}

async fn map_pmp<T: PxpTransport>(
    t: &T,
    internal: NonZeroU16,
    lifetime: NonZeroU32,
    prev: Option<&Mapping>,
    evidence: Option<&crate::SendEvidence>,
) -> Result<Mapping, MapError> {
    let suggested = prev.map_or(0, |p| p.external.port());
    let addr_req = pmp::public_address_request();
    let map_req = pmp::map_request(internal, suggested, lifetime);
    let reqs: [&[u8]; 2] = [&addr_req, &map_req];

    let mut public_ip: Option<Ipv4Addr> = None;
    let mut granted: Option<pmp::MapReply> = None;
    // An error to the MAP itself ends the exchange; an error to the address request does not,
    // since the MAP was sent too and its reply says whether it was committed.
    let mut map_refused: Option<MapError> = None;
    let mut fallback: Option<MapError> = None;
    let mut addr_error: Option<(pmp::ResultCode, u32)> = None;
    let mut notes = Vec::new();
    let mut on_reply = |b: &[u8]| {
        match b.get(..2) {
            Some(&[pmp::VERSION, op]) if op == pmp::OP_PUBLIC_ADDR | pmp::OP_REPLY => {
                match pmp::parse_public_addr_reply(b) {
                    Ok(r) => public_ip = Some(r.public_ip),
                    Err(
                        pmp::ReplyError::Router { code, epoch }
                        | pmp::ReplyError::Unmatched { code, epoch },
                    ) => {
                        addr_error.get_or_insert((code, epoch));
                    }
                    Err(pmp::ReplyError::Malformed(m)) => note(&mut notes, format!("pmp: {m}")),
                }
            }
            Some(&[pmp::VERSION, _]) => {
                match pmp::parse_map_reply(b, internal, pmp::MapKind::Map) {
                    Ok(r) => granted = Some(r),
                    Err(pmp::ReplyError::Router { code, epoch }) => {
                        map_refused = Some(MapError::Pmp { code, epoch });
                    }
                    Err(pmp::ReplyError::Unmatched { code, epoch }) => {
                        fallback.get_or_insert(MapError::PmpUnverified { code, epoch });
                    }
                    Err(pmp::ReplyError::Malformed(m)) => note(&mut notes, format!("pmp: {m}")),
                }
            }
            _ => note(&mut notes, "pmp: not a NAT-PMP reply".to_owned()),
        }
        let answered = granted.is_some() && (public_ip.is_some() || addr_error.is_some());
        if map_refused.is_some() || answered {
            Flow::Done
        } else {
            Flow::Continue
        }
    };
    let stats = t
        .exchange_with_evidence(LanDest::Pxp, &reqs, deadline(), &mut on_reply, evidence)
        .await?;
    if let Some(f) = map_refused {
        return Err(f);
    }
    finish_notes(&stats, &mut notes);
    if let (Some((code, epoch)), None) = (addr_error, public_ip) {
        return Err(MapError::PmpAddr {
            code,
            epoch,
            map: granted,
        });
    }
    match (granted, public_ip) {
        (Some(r), Some(ip)) => Ok(Mapping {
            proto: Proto::Pmp,
            internal,
            external: SocketAddrV4::new(ip, r.external),
            lifetime: r.lifetime,
            epoch: r.epoch,
            nonce: None,
        }),
        _ => Err(fallback.unwrap_or(MapError::NoServices {
            malformed: notes.pop(),
        })),
    }
}

async fn map_pcp<T: PxpTransport>(
    t: &T,
    internal: NonZeroU16,
    lifetime: NonZeroU32,
    prev: Option<&Mapping>,
    nonce: pcp::Nonce,
    evidence: Option<&crate::SendEvidence>,
) -> Result<Mapping, MapError> {
    let suggested = prev.map_or(0, |p| p.external.port());
    let req = pcp::map_request(t.gateway().self_ip, internal, suggested, lifetime, &nonce);
    let mut outcome: Option<Result<pcp::MapReply, MapError>> = None;
    let mut fallback: Option<MapError> = None;
    let mut notes = Vec::new();
    let mut on_reply = |b: &[u8]| {
        match pcp_seen(b, &nonce, internal, pcp::MapKind::Map, |r| r, &mut notes) {
            PcpSeen::Answer(a) => outcome = Some(a),
            PcpSeen::Fallback(e) => {
                fallback.get_or_insert(e);
            }
            PcpSeen::Ignored => {}
        }
        if outcome.is_some() {
            Flow::Done
        } else {
            Flow::Continue
        }
    };
    let stats = t
        .exchange_with_evidence(LanDest::Pxp, &[&req], deadline(), &mut on_reply, evidence)
        .await?;
    finish_notes(&stats, &mut notes);
    match outcome {
        Some(Ok(r)) => Ok(Mapping {
            proto: Proto::Pcp,
            internal,
            external: r.external,
            lifetime: r.lifetime,
            epoch: r.epoch,
            nonce: Some(nonce),
        }),
        Some(Err(e)) => Err(e),
        None => Err(fallback.unwrap_or(MapError::NoServices {
            malformed: notes.pop(),
        })),
    }
}

/// The delete request for `rule`, sent from `self_ip`: NAT-PMP lifetime 0 with suggested port 0;
/// PCP lifetime 0 with the rule's original nonce.
pub fn delete_request_bytes(rule: &Rule, self_ip: Ipv4Addr) -> Vec<u8> {
    match rule {
        Rule::Pmp { internal } => pmp::delete_request(*internal).to_vec(),
        Rule::Pcp { internal, nonce } => pcp::delete_request(self_ip, *internal, nonce).to_vec(),
    }
}

/// Delete `rule` and wait for the router's acknowledgement (lifetime 0). NAT-PMP sends lifetime 0
/// with suggested port 0; PCP also sends the rule's original nonce.
pub async fn delete<T: PxpTransport>(t: &T, rule: &Rule) -> Result<(), MapError> {
    let req = delete_request_bytes(rule, t.gateway().self_ip);
    let internal = rule.internal();
    let mut outcome: Option<Result<(), MapError>> = None;
    let mut fallback: Option<MapError> = None;
    let mut notes = Vec::new();
    let mut on_reply = |b: &[u8]| {
        match rule {
            Rule::Pmp { .. } => match pmp::parse_map_reply(b, internal, pmp::MapKind::Delete) {
                Ok(_) => outcome = Some(Ok(())),
                Err(pmp::ReplyError::Router { code, epoch }) => {
                    outcome = Some(Err(MapError::Pmp { code, epoch }));
                }
                Err(pmp::ReplyError::Unmatched { code, epoch }) => {
                    fallback.get_or_insert(MapError::PmpUnverified { code, epoch });
                }
                Err(pmp::ReplyError::Malformed(m)) => note(&mut notes, format!("pmp: {m}")),
            },
            Rule::Pcp { nonce, .. } => {
                match pcp_seen(b, nonce, internal, pcp::MapKind::Delete, |_| (), &mut notes) {
                    PcpSeen::Answer(a) => outcome = Some(a),
                    PcpSeen::Fallback(e) => {
                        fallback.get_or_insert(e);
                    }
                    PcpSeen::Ignored => {}
                }
            }
        }
        if outcome.is_some() {
            Flow::Done
        } else {
            Flow::Continue
        }
    };
    let stats = t
        .exchange(LanDest::Pxp, &[&req], deadline(), &mut on_reply)
        .await?;
    finish_notes(&stats, &mut notes);
    outcome.unwrap_or_else(|| {
        Err(fallback.unwrap_or(MapError::NoServices {
            malformed: notes.pop(),
        }))
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{
        Gateway, GatewayCap, PolicyHandle,
        testing::{
            AssignPort, Corruption, FakeRouter, RequestKind, ResultOverride, RouterOptions, TestCap,
        },
    };

    const P1234: NonZeroU16 = NonZeroU16::new(1234).unwrap();
    const LIFE: NonZeroU32 = NonZeroU32::new(7200).unwrap();

    fn gateway(self_ip: Ipv4Addr) -> Gateway {
        Gateway {
            gw: Ipv4Addr::new(192, 168, 1, 1),
            self_ip,
            prefix_len: 24,
            if_index: 4,
            if_name: "en0".to_owned(),
        }
    }

    fn rule(proto: Proto, internal: NonZeroU16) -> Rule {
        Rule::new(proto, internal).unwrap()
    }

    async fn setup(opts: RouterOptions) -> (FakeRouter, Arc<TestCap>) {
        let router = FakeRouter::start(opts).await.unwrap();
        let cap = TestCap::new(
            gateway(Ipv4Addr::LOCALHOST),
            &router,
            PolicyHandle::new(true),
        );
        (router, cap)
    }

    /// Port of Go's `TestProbeIntegration` (PxP half): one request of each kind, and both seen
    /// (Rust's harness answers NAT-PMP; Go's does not).
    #[tokio::test]
    async fn probe_integration() {
        let (router, cap) = setup(RouterOptions::default()).await;
        let r = probe(&*cap, ProtoSet::BOTH).await.unwrap();
        assert!(r.pmp && r.pcp, "{r:?}");
        assert_eq!(r.pmp_public_ip, Some(Ipv4Addr::new(203, 0, 113, 7)));
        assert_eq!(r.pmp_epoch, Some(3600));
        assert_eq!(r.pcp_result, Some(pcp::ResultCode::Success));
        let c = router.counters();
        assert_eq!(
            (
                c.num_pmp_recv,
                c.num_pmp_public_addr_recv,
                c.num_pcp_recv,
                c.num_pcp_disco_recv
            ),
            (1, 1, 1, 1)
        );
        router.shutdown().await;
    }

    /// Port of Go's `TestPCPIntegration` (the one-shot part): a PCP-only router; the probe sees
    /// only PCP and a PCP map yields a valid external address.
    #[tokio::test]
    async fn pcp_integration() {
        let (router, cap) = setup(RouterOptions {
            pmp: false,
            ..RouterOptions::default()
        })
        .await;
        let r = probe(&*cap, ProtoSet::BOTH).await.unwrap();
        assert!(!r.pmp && r.pcp, "{r:?}");
        let m = map(&*cap, &rule(Proto::Pcp, P1234), LIFE, None)
            .await
            .unwrap();
        assert!(!m.external.ip().is_unspecified() && m.external.port() != 0);
        assert!(m.nonce.is_some());
        router.shutdown().await;
    }

    /// A NAT-PMP-only router: its "unsupported version" answer to ANNOUNCE does not spoil PMP.
    #[tokio::test]
    async fn pmp_only_router() {
        let (router, cap) = setup(RouterOptions {
            pcp: false,
            ..RouterOptions::default()
        })
        .await;
        let r = probe(&*cap, ProtoSet::BOTH).await.unwrap();
        assert!(r.pmp && !r.pcp, "{r:?}");
        assert_eq!(r.pmp_result, Some(pmp::ResultCode::Success));
        assert!(
            map(&*cap, &rule(Proto::Pmp, P1234), LIFE, None)
                .await
                .is_ok()
        );
        assert!(matches!(
            map(&*cap, &rule(Proto::Pcp, P1234), LIFE, None).await,
            Err(MapError::PmpUnverified {
                code: pmp::ResultCode::UnsupportedVersion,
                ..
            })
        ));
        router.shutdown().await;
    }

    /// No responder: the probe returns all false within the exchange budget and a map
    /// gives `NoServices`.
    #[tokio::test]
    async fn no_responder() {
        let (router, cap) = setup(RouterOptions {
            pmp: false,
            pcp: false,
            ..RouterOptions::default()
        })
        .await;
        let start = std::time::Instant::now();
        let r = probe(&*cap, ProtoSet::BOTH).await.unwrap();
        assert!(!r.pmp && !r.pcp && r.pmp_result.is_none() && r.pcp_result.is_none());
        assert!(start.elapsed() >= EXCHANGE_TIMEOUT);
        assert!(start.elapsed() < Duration::from_secs(2));
        for proto in [Proto::Pmp, Proto::Pcp] {
            assert!(matches!(
                map(&*cap, &rule(proto, P1234), LIFE, None).await,
                Err(MapError::NoServices { .. })
            ));
        }
        router.shutdown().await;
    }

    #[tokio::test]
    async fn pmp_map_renew_delete() {
        let (router, cap) = setup(RouterOptions::default()).await;
        router.set_assign_port(AssignPort::InternalPlus(1000));
        let m = map(&*cap, &rule(Proto::Pmp, P1234), LIFE, None)
            .await
            .unwrap();
        // External ≠ internal flows through.
        assert_eq!(m.external, "203.0.113.7:2234".parse().unwrap());
        assert_eq!((m.lifetime, m.nonce.clone()), (7200, None));
        let c = router.counters();
        assert_eq!((c.num_pmp_public_addr_recv, c.num_pmp_map_recv), (1, 1));

        // Renewal: the previous external port is suggested and the address is asked again.
        let r = map(&*cap, &m.rule(), LIFE, Some(&m)).await.unwrap();
        assert_eq!(r.external, m.external);
        let c = router.counters();
        assert_eq!((c.num_pmp_public_addr_recv, c.num_pmp_map_recv), (2, 2));
        assert_eq!(
            router.requests().last().unwrap().suggested_external,
            Some(2234)
        );

        delete(&*cap, &m.rule()).await.unwrap();
        let del = router.requests().last().unwrap().clone();
        assert_eq!(
            (del.internal, del.suggested_external, del.lifetime),
            (Some(1234), Some(0), Some(0))
        );
        assert!(router.mappings().is_empty());
        router.shutdown().await;
    }

    #[tokio::test]
    async fn pcp_map_renew_delete_reuse_the_nonce() {
        let (router, cap) = setup(RouterOptions {
            enforce_pcp_client_ip: true,
            ..RouterOptions::default()
        })
        .await;
        let m = map(&*cap, &rule(Proto::Pcp, P1234), LIFE, None)
            .await
            .unwrap();
        let nonce = *m.nonce.as_ref().unwrap().as_bytes();
        let r = map(&*cap, &m.rule(), LIFE, Some(&m)).await.unwrap();
        assert_eq!(r.external, m.external);
        let renew = router.requests().last().unwrap().clone();
        assert_eq!(renew.nonce, Some(nonce));
        assert_eq!(renew.suggested_external, Some(m.external.port()));
        // The client IP field is self_ip (source-consistent loopback mode).
        assert_eq!(renew.pcp_client_ip, Some(Ipv4Addr::LOCALHOST));

        delete(&*cap, &m.rule()).await.unwrap();
        let del = router.requests().last().unwrap().clone();
        assert_eq!((del.nonce, del.lifetime), (Some(nonce), Some(0)));
        assert!(router.mappings().is_empty());
        router.shutdown().await;
    }

    /// A client IP field that differs from the source gets `ADDRESS_MISMATCH`.
    #[tokio::test]
    async fn pcp_address_mismatch() {
        let router = FakeRouter::start(RouterOptions {
            enforce_pcp_client_ip: true,
            ..RouterOptions::default()
        })
        .await
        .unwrap();
        let cap = TestCap::new(
            gateway(Ipv4Addr::new(198, 51, 100, 4)),
            &router,
            PolicyHandle::new(true),
        );
        let r = probe(&*cap, ProtoSet::BOTH).await.unwrap();
        assert!(!r.pcp);
        assert_eq!(r.pcp_result, Some(pcp::ResultCode::AddressMismatch));
        assert!(matches!(
            map(&*cap, &rule(Proto::Pcp, P1234), LIFE, None).await,
            Err(MapError::Pcp {
                code: pcp::ResultCode::AddressMismatch,
                ..
            })
        ));
        router.shutdown().await;
    }

    /// A PCP reply with a wrong nonce followed by the correct one: the correct one wins.
    #[tokio::test]
    async fn wrong_nonce_then_correct_reply() {
        let (router, cap) = setup(RouterOptions::default()).await;
        router.corrupt_next(Corruption::WrongNonce);
        router.duplicate_next(1);
        let m = map(&*cap, &rule(Proto::Pcp, P1234), LIFE, None)
            .await
            .unwrap();
        assert_eq!(m.external.port(), 4242);
        router.shutdown().await;
    }

    /// Hostile replies end in `NoServices` with the reason kept, never a mapping.
    #[tokio::test]
    async fn hostile_replies() {
        let (router, cap) = setup(RouterOptions::default()).await;
        for (i, c) in [
            Corruption::Truncate,
            Corruption::BadVersion,
            Corruption::WrongOpcode,
            Corruption::NoRBit,
            Corruption::WrongNonce,
            Corruption::WrongProto,
            Corruption::WrongInternalPort,
            Corruption::Garbage,
            Corruption::Oversize,
        ]
        .into_iter()
        .enumerate()
        {
            // A fresh internal port each time: the router committed the previous rule under
            // another nonce.
            let port = NonZeroU16::new(2000 + u16::try_from(i).unwrap()).unwrap();
            router.corrupt_next(c);
            let r = map(&*cap, &rule(Proto::Pcp, port), LIFE, None).await;
            assert!(
                matches!(r, Err(MapError::NoServices { malformed: Some(_) })),
                "{c:?}: {r:?}"
            );
        }
        router.reply_from_wrong_port_next(1);
        let r = map(&*cap, &rule(Proto::Pmp, P1234), LIFE, None).await;
        assert!(matches!(r, Err(MapError::NoServices { .. })), "{r:?}");
        router.shutdown().await;
    }

    /// A NAT-PMP renewal carries the router's current WAN address, not the one from the create.
    #[tokio::test]
    async fn pmp_renewal_refreshes_the_public_ip() {
        let (router, cap) = setup(RouterOptions::default()).await;
        let mut m = map(&*cap, &rule(Proto::Pmp, P1234), LIFE, None)
            .await
            .unwrap();
        assert_eq!(m.external, "203.0.113.7:4242".parse().unwrap());
        router.set_public_ip(Ipv4Addr::new(198, 51, 100, 9));
        for _ in 0..3 {
            m = map(&*cap, &m.rule(), LIFE, Some(&m)).await.unwrap();
            assert_eq!(m.external, "198.51.100.9:4242".parse().unwrap());
        }
        router.shutdown().await;
    }

    /// An error to the public-address request (here NETWORK_FAILURE, the WAN is down) is not a
    /// refusal of the MAP: the MAP was sent alongside and committed, so the error says so.
    #[tokio::test]
    async fn pmp_address_error_is_not_a_map_refusal() {
        let (router, cap) = setup(RouterOptions::default()).await;
        router.set_result(
            RequestKind::PmpPublicAddr,
            Some(ResultOverride {
                code: 3,
                lifetime: 0,
            }),
        );
        let r = map(&*cap, &rule(Proto::Pmp, P1234), LIFE, None).await;
        assert!(
            matches!(
                r,
                Err(MapError::PmpAddr {
                    code: pmp::ResultCode::NetworkFailure,
                    map: Some(pmp::MapReply { external: 4242, .. }),
                    ..
                })
            ),
            "{r:?}"
        );
        assert_eq!(router.mappings().len(), 1, "the MAP was committed");
        // The MAP's own refusal is still a plain `Pmp` error.
        router.set_result(RequestKind::PmpPublicAddr, None);
        router.set_result(
            RequestKind::PmpMap,
            Some(ResultOverride {
                code: 2,
                lifetime: 0,
            }),
        );
        let r = map(&*cap, &rule(Proto::Pmp, P1234), LIFE, None).await;
        assert!(matches!(r, Err(MapError::Pmp { .. })), "{r:?}");
        router.shutdown().await;
    }

    /// At the one-shot level, router errors are typed, with PCP error lifetimes.
    #[tokio::test]
    async fn router_errors_are_typed() {
        let (router, cap) = setup(RouterOptions::default()).await;
        for code in 1..=5u16 {
            router.set_result(
                RequestKind::PmpMap,
                Some(ResultOverride { code, lifetime: 0 }),
            );
            let r = map(&*cap, &rule(Proto::Pmp, P1234), LIFE, None).await;
            assert!(
                matches!(r, Err(MapError::Pmp { code: c, .. }) if u16::from(c) == code),
                "{r:?}"
            );
        }
        // A full-length error echoing our nonce is authoritative and keeps its lifetime.
        router.set_result(
            RequestKind::PcpMap,
            Some(ResultOverride {
                code: 2,
                lifetime: 86_400,
            }),
        );
        let r = map(&*cap, &rule(Proto::Pcp, P1234), LIFE, None).await;
        assert!(
            matches!(
                r,
                Err(MapError::Pcp {
                    code: pcp::ResultCode::NotAuthorized,
                    lifetime: 86_400,
                    ..
                })
            ),
            "{r:?}"
        );
        // A header-only error has no nonce: reported only after the deadline, as unverified,
        // with its lifetime capped.
        router.set_short_pcp_errors(true);
        let start = std::time::Instant::now();
        let r = map(&*cap, &rule(Proto::Pcp, P1234), LIFE, None).await;
        assert!(start.elapsed() >= EXCHANGE_TIMEOUT);
        assert!(
            matches!(
                r,
                Err(MapError::PcpUnverified {
                    code: pcp::ResultCode::NotAuthorized,
                    lifetime: MAX_UNVERIFIED_ERROR_LIFETIME,
                    ..
                })
            ),
            "{r:?}"
        );
        router.shutdown().await;
    }

    /// A spoofed header-only PCP error from `gateway:5351` (here 24 bytes, NOT_AUTHORIZED, error
    /// lifetime `u32::MAX`) that beats the real reply cannot end the exchange: the nonce-matched
    /// reply that follows wins, for a map and for a delete.
    #[tokio::test]
    async fn spoofed_short_pcp_error_does_not_win() {
        let (router, cap) = setup(RouterOptions::default()).await;
        let mut spoof = vec![0u8; 24];
        spoof[0] = pcp::VERSION;
        spoof[1] = pcp::R_BIT | pcp::OP_MAP;
        spoof[3] = 2;
        spoof[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
        router.spoof_before_next_reply(spoof.clone());
        let rule = rule(Proto::Pcp, P1234);
        let m = map(&*cap, &rule, LIFE, None).await.unwrap();
        assert_eq!(m.external.port(), 4242);
        router.spoof_before_next_reply(spoof);
        delete(&*cap, &rule).await.unwrap();
        assert!(router.mappings().is_empty());
        router.shutdown().await;
    }

    /// The granted lifetime can differ from the requested one, both ways.
    #[tokio::test]
    async fn granted_lifetime_is_reported() {
        let (router, cap) = setup(RouterOptions::default()).await;
        for granted in [60, 86_400] {
            router.set_lifetime_override(Some(granted));
            for proto in [Proto::Pmp, Proto::Pcp] {
                let m = map(&*cap, &rule(proto, P1234), LIFE, None).await.unwrap();
                assert_eq!(m.lifetime, granted);
                delete(&*cap, &m.rule()).await.unwrap();
            }
        }
        router.shutdown().await;
    }

    /// Commit-then-lost-reply: the rule is still deletable from what the client sent.
    #[tokio::test]
    async fn lost_reply_rule_is_deletable() {
        let (router, cap) = setup(RouterOptions::default()).await;
        router.commit_then_drop_next(1);
        let rule = rule(Proto::Pcp, P1234);
        let r = map(&*cap, &rule, LIFE, None).await;
        assert!(matches!(r, Err(MapError::NoServices { .. })));
        assert_eq!(router.mappings().len(), 1);
        delete(&*cap, &rule).await.unwrap();
        assert!(router.mappings().is_empty());
        router.shutdown().await;
    }

    /// Lease arithmetic never panics and is clamped.
    #[test]
    fn lease_deadlines() {
        let now = Instant::now();
        assert_eq!(lease_deadline(now, 0), now);
        assert_eq!(lease_deadline(now, 1), now + Duration::from_secs(1));
        assert_eq!(
            lease_deadline(now, u32::MAX),
            now + Duration::from_secs(u64::from(u32::MAX))
        );
    }

    /// The production `GatewayCap` runs the same probe/map/delete against a loopback router: the
    /// real socket, interface binding and gate code, with no packet leaving the host.
    #[tokio::test]
    async fn real_gateway_cap_against_loopback_router() {
        let router = FakeRouter::start(RouterOptions {
            enforce_pcp_client_ip: true,
            ..RouterOptions::default()
        })
        .await
        .unwrap();
        let cap = GatewayCap::loopback_for_test(router.addr().port(), PolicyHandle::new(true))
            .expect("loopback capability construction must succeed");
        let r = probe(&*cap, ProtoSet::BOTH).await.unwrap();
        assert!(r.pmp && r.pcp, "{r:?}");
        for proto in [Proto::Pmp, Proto::Pcp] {
            let m = map(&*cap, &rule(proto, P1234), LIFE, None).await.unwrap();
            delete(&*cap, &m.rule()).await.unwrap();
        }
        assert!(router.mappings().is_empty());
        router.shutdown().await;
    }
}

#[cfg(test)]
mod identity_error_tests {
    use super::*;
    use crate::testing::{FakeRouter, RequestKind, RouterOptions, TestCap};
    use crate::{Gateway, PolicyHandle};

    #[tokio::test]
    async fn pmp_unmatched_errors_do_not_beat_success() {
        let router = FakeRouter::start(RouterOptions::default()).await.unwrap();
        let cap = TestCap::new(
            Gateway {
                gw: "192.168.1.1".parse().unwrap(),
                self_ip: Ipv4Addr::LOCALHOST,
                prefix_len: 24,
                if_index: 4,
                if_name: "en0".to_owned(),
            },
            &router,
            PolicyHandle::new(true),
        );
        let internal = NonZeroU16::new(1234).unwrap();
        for short in [false, true] {
            let mut error = vec![0, 0x81, 0, 2, 0, 0, 0, 1];
            if !short {
                error.extend_from_slice(&[0x12, 0x34, 0, 0, 0, 0, 0, 0]);
            }
            router.knobs_for(Some(RequestKind::PmpMap));
            router.spoof_before_next_reply(error);
            let rule = Rule::new(Proto::Pmp, internal).unwrap();
            let m = map(&*cap, &rule, NonZeroU32::new(7200).unwrap(), None).await;
            assert!(m.is_ok(), "unmatched error beat success: {m:?}");
            delete(&*cap, &rule).await.unwrap();
        }
        router.shutdown().await;
    }
}
