//! A fake NAT-PMP (RFC 6886) and PCP (RFC 6887) router on loopback.
//!
//! Its request decoder is written from the RFCs and shares no code with the crate's codecs. It
//! keeps a mapping table keyed by `(client ip, protocol, internal port)` with PCP nonce
//! ownership, expires entries on a [`LeaseClock`], and has runtime knobs for the failure modes the
//! client must survive: delays, drops, duplicates, reordering, commit-then-drop-reply, replies
//! from the wrong port or address, corrupted replies, junk bursts and trickles, result-code
//! overrides and request barriers.
//!
//! Requests are decoded and committed one at a time, in arrival order, under the state lock. Each
//! reply (barrier wait, delay, junk, send, duplicate) then runs in its own task, so a paused or
//! delayed reply holds back only itself: a later request is still decoded, committed and answered.
//! [`FakeRouter::shutdown`] aborts and joins every reply task.

use std::{
    collections::{HashMap, VecDeque},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use tokio::{
    net::UdpSocket,
    sync::{Notify, oneshot},
    task::{JoinHandle, JoinSet},
};

use super::LeaseClock;

/// How the router's epoch ("seconds since start of epoch") evolves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochMode {
    /// Always this value.
    Fixed(u32),
    /// `clock.now() - zero_at`: advances with the lease clock.
    Clock {
        /// Clock reading at which the epoch was 0.
        zero_at: u64,
    },
}

/// How the router assigns external ports to new mappings. A port already used by another
/// mapping is bumped to the next free one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignPort {
    /// The suggested port if nonzero, else `fallback`.
    Suggested {
        /// Port used when no port is suggested.
        fallback: u16,
    },
    /// Always this port.
    Fixed(u16),
    /// The internal port plus this offset (so external ≠ internal).
    InternalPlus(u16),
}

/// A forced result for one kind of request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResultOverride {
    /// The result code to answer with (PMP codes are u16, PCP codes u8).
    pub code: u16,
    /// The lifetime in the reply (PCP: the error lifetime).
    pub lifetime: u32,
}

/// A one-shot corruption applied to the next reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Corruption {
    /// Drop the last byte.
    Truncate,
    /// Change the version byte.
    BadVersion,
    /// Change the opcode.
    WrongOpcode,
    /// Clear the R bit (PCP) or reply bit (PMP).
    NoRBit,
    /// Change the PCP nonce.
    WrongNonce,
    /// Change the PCP protocol to TCP.
    WrongProto,
    /// Change the internal port.
    WrongInternalPort,
    /// Replace the reply with garbage of the same length.
    Garbage,
    /// Pad the reply to 1200 bytes (over the 1101-byte receive buffer).
    Oversize,
}

/// The kind of a decoded request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestKind {
    /// NAT-PMP public-address request.
    PmpPublicAddr,
    /// NAT-PMP MAP (create, renew or delete).
    PmpMap,
    /// PCP ANNOUNCE.
    PcpAnnounce,
    /// PCP MAP (create, renew or delete).
    PcpMap,
    /// Anything else.
    Other,
}

/// Request counters. Names follow Go's `igdCounters` where they exist.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counters {
    /// Every datagram that reached the router's socket.
    pub num_total_recv: u64,
    /// NAT-PMP requests handled.
    pub num_pmp_recv: u64,
    /// NAT-PMP public-address requests.
    pub num_pmp_public_addr_recv: u64,
    /// NAT-PMP MAP requests.
    pub num_pmp_map_recv: u64,
    /// Malformed NAT-PMP requests.
    pub num_pmp_bogus_recv: u64,
    /// PCP requests handled.
    pub num_pcp_recv: u64,
    /// PCP ANNOUNCE requests.
    pub num_pcp_disco_recv: u64,
    /// PCP MAP requests.
    pub num_pcp_map_recv: u64,
    /// PCP requests with other opcodes or malformed headers.
    pub num_pcp_other_recv: u64,
    /// Malformed PCP MAP requests.
    pub invalid_pcp_map_pkt: u64,
    /// Delete requests (PMP or PCP lifetime 0).
    pub num_deletes: u64,
}

/// A request as the router decoded it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedRequest {
    /// Where it came from.
    pub src: SocketAddr,
    /// What it was.
    pub kind: RequestKind,
    /// Version byte.
    pub version: u8,
    /// Opcode (PCP: without the R bit).
    pub opcode: u8,
    /// MAP internal port.
    pub internal: Option<u16>,
    /// MAP suggested external port.
    pub suggested_external: Option<u16>,
    /// Requested lifetime.
    pub lifetime: Option<u32>,
    /// PCP MAP nonce.
    pub nonce: Option<[u8; 12]>,
    /// PCP client IP field, if IPv4-mapped.
    pub pcp_client_ip: Option<Ipv4Addr>,
}

/// One live mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingEntry {
    /// The owner's address (the request's source address).
    pub client_ip: Ipv4Addr,
    /// IANA protocol (17 for UDP).
    pub proto: u8,
    /// Internal port.
    pub internal: u16,
    /// Assigned external port.
    pub external: u16,
    /// PCP nonce that owns it (None if created by NAT-PMP).
    pub nonce: Option<[u8; 12]>,
    /// Lease-clock second at which it expires.
    pub expires_at: u64,
}

/// Options for [`FakeRouter::start`].
#[derive(Debug, Clone)]
pub struct RouterOptions {
    /// Answer NAT-PMP.
    pub pmp: bool,
    /// Answer PCP.
    pub pcp: bool,
    /// The public address it reports.
    pub public_ip: Ipv4Addr,
    /// Loopback address to bind (port 0 is always used). Anything else is refused by
    /// [`FakeRouter::start`].
    pub bind_ip: Ipv4Addr,
    /// Lease clock for expiry and epoch.
    pub clock: LeaseClock,
    /// Epoch behaviour.
    pub epoch: EpochMode,
    /// Answer PCP requests whose client IP field differs from the source address with
    /// `ADDRESS_MISMATCH`.
    pub enforce_pcp_client_ip: bool,
    /// Send PCP errors as header-only (24-byte) responses.
    pub short_pcp_errors: bool,
}

impl Default for RouterOptions {
    fn default() -> Self {
        Self {
            pmp: true,
            pcp: true,
            public_ip: Ipv4Addr::new(203, 0, 113, 7),
            bind_ip: Ipv4Addr::LOCALHOST,
            clock: LeaseClock::new(1_000_000),
            epoch: EpochMode::Clock {
                zero_at: 1_000_000 - 3600,
            },
            enforce_pcp_client_ip: false,
            short_pcp_errors: false,
        }
    }
}

struct BarrierInner {
    reached: Arc<Notify>,
    release: oneshot::Receiver<()>,
}

/// Pauses the router before it replies to the next request of one kind.
#[derive(Debug)]
pub struct Barrier {
    reached: Arc<Notify>,
    release: Option<oneshot::Sender<()>>,
}

impl Barrier {
    /// Wait until the router has received (and committed) the request and paused.
    pub async fn reached(&self) {
        self.reached.notified().await;
    }

    /// Let the router send its reply.
    pub fn release(mut self) {
        if let Some(tx) = self.release.take() {
            tx.send(()).ok();
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Via {
    Main,
    WrongPort,
    WrongIp,
}

struct State {
    opts: RouterOptions,
    table: Vec<MappingEntry>,
    overrides: HashMap<RequestKind, ResultOverride>,
    lifetime_override: Option<u32>,
    assign: AssignPort,
    delay: Duration,
    drop_next: u32,
    drop_deletes: bool,
    duplicate_next: u32,
    reorder_next: bool,
    commit_then_drop_next: u32,
    wrong_port_next: u32,
    wrong_ip_next: u32,
    corrupt: VecDeque<Corruption>,
    junk_before_next: usize,
    trickle_next: Option<(usize, Duration)>,
    spoof_next: Option<Vec<u8>>,
    knobs_for: Option<RequestKind>,
    counters: Counters,
    requests: Vec<DecodedRequest>,
    barriers: Vec<(RequestKind, BarrierInner)>,
    held: Option<(Vec<u8>, SocketAddr)>,
}

struct ReplyPlan {
    reply: Vec<u8>,
    /// The uncorrupted reply, sent after `reply` when duplicating.
    original: Vec<u8>,
    barrier: Option<BarrierInner>,
    delay: Duration,
    drop: bool,
    via: Via,
    duplicate: bool,
    junk: usize,
    /// Send this many junk datagrams this far apart, then drop the real reply.
    trickle: Option<(usize, Duration)>,
    /// Sent from the router's own address just before the real reply.
    spoof: Option<Vec<u8>>,
    /// The reply was parked in `State::held`; this task sends nothing.
    hold: bool,
}

impl ReplyPlan {
    /// A reply with no one-shot knob applied.
    fn plain(reply: Vec<u8>, barrier: Option<BarrierInner>, delay: Duration) -> Self {
        Self {
            original: reply.clone(),
            reply,
            barrier,
            delay,
            drop: false,
            via: Via::Main,
            duplicate: false,
            junk: 0,
            trickle: None,
            spoof: None,
            hold: false,
        }
    }
}

/// A router's loopback addresses (see [`FakeRouter::endpoint`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouterEndpoint {
    /// Where requests go and replies come from.
    pub addr: SocketAddr,
    /// Where replies "from the wrong port" come from.
    pub wrong_port_addr: SocketAddr,
    /// Where replies "from the wrong address" come from.
    pub wrong_ip_addr: SocketAddr,
}

/// A fake NAT-PMP/PCP router. See the module docs.
pub struct FakeRouter {
    addr: SocketAddr,
    wrong_port_addr: SocketAddr,
    wrong_ip_addr: SocketAddr,
    state: Arc<Mutex<State>>,
    shutdown: Arc<Notify>,
    task: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for FakeRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeRouter")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

fn be16(b: &[u8], at: usize) -> u16 {
    b.get(at..at + 2)
        .map_or(0, |s| u16::from_be_bytes([s[0], s[1]]))
}

fn be32(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4)
        .map_or(0, |s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn v4_mapped(ip: Ipv4Addr) -> [u8; 16] {
    ip.to_ipv6_mapped().octets()
}

impl State {
    fn epoch(&self) -> u32 {
        match self.opts.epoch {
            EpochMode::Fixed(e) => e,
            EpochMode::Clock { zero_at } => {
                u32::try_from(self.opts.clock.now().saturating_sub(zero_at)).unwrap_or(u32::MAX)
            }
        }
    }

    fn find(&self, client: Ipv4Addr, proto: u8, internal: u16) -> Option<usize> {
        self.table
            .iter()
            .position(|e| e.client_ip == client && e.proto == proto && e.internal == internal)
    }

    fn assign(&self, internal: u16, suggested: u16) -> u16 {
        let mut p = match self.assign {
            AssignPort::Suggested { fallback } if suggested == 0 => fallback,
            AssignPort::Suggested { .. } => suggested,
            AssignPort::Fixed(p) => p,
            AssignPort::InternalPlus(d) => internal.wrapping_add(d),
        };
        for _ in 0..u16::MAX {
            if p != 0 && !self.table.iter().any(|e| e.external == p) {
                break;
            }
            p = p.wrapping_add(1);
        }
        p
    }

    fn granted(&self, requested: u32) -> u32 {
        self.lifetime_override.unwrap_or(requested)
    }

    /// Create or renew `(client, proto, internal)`; returns the external port and lifetime.
    fn upsert(
        &mut self,
        client: Ipv4Addr,
        proto: u8,
        internal: u16,
        suggested: u16,
        requested: u32,
        nonce: Option<[u8; 12]>,
    ) -> (u16, u32) {
        let lifetime = self.granted(requested);
        let expires_at = self.opts.clock.now().saturating_add(u64::from(lifetime));
        if let Some(i) = self.find(client, proto, internal) {
            let e = &mut self.table[i];
            e.expires_at = expires_at;
            if e.nonce.is_none() {
                e.nonce = nonce;
            }
            return (e.external, lifetime);
        }
        let external = self.assign(internal, suggested);
        self.table.push(MappingEntry {
            client_ip: client,
            proto,
            internal,
            external,
            nonce,
            expires_at,
        });
        (external, lifetime)
    }

    fn handle(&mut self, req: &[u8], src: SocketAddr) -> Option<ReplyPlan> {
        self.counters.num_total_recv += 1;
        let now = self.opts.clock.now();
        self.table.retain(|e| e.expires_at > now);
        if self.drop_next > 0 {
            self.drop_next -= 1;
            return None;
        }
        let client = match src {
            SocketAddr::V4(a) => *a.ip(),
            SocketAddr::V6(_) => return None,
        };
        let (kind, reply) = match req.first() {
            Some(0) => self.handle_pmp(req, src, client)?,
            Some(2) => self.handle_pcp(req, src, client)?,
            _ => {
                // An unknown version: a NAT-PMP server answers "unsupported version".
                if !self.opts.pmp || req.len() < 2 {
                    return None;
                }
                (RequestKind::Other, self.pmp_error_reply(req[1], 1))
            }
        };
        let original = reply.clone();
        let mut reply = reply;
        let barrier = self
            .barriers
            .iter()
            .position(|(k, _)| *k == kind)
            .map(|i| self.barriers.remove(i).1);
        if self.knobs_for.is_some_and(|k| k != kind) {
            // The one-shot knobs wait for a request of their kind.
            return Some(ReplyPlan::plain(reply, barrier, self.delay));
        }
        if let Some(c) = self.corrupt.pop_front() {
            corrupt(&mut reply, c);
        }
        let take = |n: &mut u32| {
            let hit = *n > 0;
            *n = n.saturating_sub(1);
            hit
        };
        let dropped_delete = self.drop_deletes
            && match req.first() {
                Some(0) => req.len() == 12 && be32(req, 8) == 0,
                Some(2) => req.len() >= 60 && req[1] == 1 && be32(req, 4) == 0,
                _ => false,
            };
        let drop = take(&mut self.commit_then_drop_next) || dropped_delete;
        let hold = std::mem::take(&mut self.reorder_next);
        if hold {
            // Parked now, in arrival order, so the next request's reply task finds it.
            self.held = Some((reply.clone(), src));
        }
        let via = if take(&mut self.wrong_port_next) {
            Via::WrongPort
        } else if take(&mut self.wrong_ip_next) {
            Via::WrongIp
        } else {
            Via::Main
        };
        Some(ReplyPlan {
            reply,
            original,
            barrier,
            delay: self.delay,
            drop,
            via,
            duplicate: take(&mut self.duplicate_next),
            junk: std::mem::take(&mut self.junk_before_next),
            trickle: self.trickle_next.take(),
            spoof: self.spoof_next.take(),
            hold,
        })
    }

    /// An 8-byte NAT-PMP error reply.
    fn pmp_error_reply(&self, op: u8, code: u16) -> Vec<u8> {
        let mut r = vec![0, op | 0x80];
        r.extend_from_slice(&code.to_be_bytes());
        r.extend_from_slice(&self.epoch().to_be_bytes());
        r
    }

    fn handle_pmp(
        &mut self,
        req: &[u8],
        src: SocketAddr,
        client: Ipv4Addr,
    ) -> Option<(RequestKind, Vec<u8>)> {
        if req.len() < 2 {
            self.counters.num_pmp_bogus_recv += 1;
            return None;
        }
        if !self.opts.pmp {
            return None;
        }
        self.counters.num_pmp_recv += 1;
        let op = req[1];
        let mut log = DecodedRequest {
            src,
            kind: RequestKind::Other,
            version: 0,
            opcode: op,
            internal: None,
            suggested_external: None,
            lifetime: None,
            nonce: None,
            pcp_client_ip: None,
        };
        let epoch = self.epoch();
        let out = match op {
            0 => {
                self.counters.num_pmp_public_addr_recv += 1;
                log.kind = RequestKind::PmpPublicAddr;
                let code = self.overrides.get(&log.kind).map_or(0, |o| o.code);
                let mut r = vec![0, 0x80];
                r.extend_from_slice(&code.to_be_bytes());
                r.extend_from_slice(&epoch.to_be_bytes());
                let ip = if code == 0 {
                    self.opts.public_ip
                } else {
                    Ipv4Addr::UNSPECIFIED
                };
                r.extend_from_slice(&ip.octets());
                r
            }
            1 | 2 => {
                if req.len() != 12 {
                    self.counters.num_pmp_bogus_recv += 1;
                    return None;
                }
                self.counters.num_pmp_map_recv += 1;
                log.kind = RequestKind::PmpMap;
                let proto = if op == 1 { 17 } else { 6 };
                let internal = be16(req, 4);
                let suggested = be16(req, 6);
                let lifetime = be32(req, 8);
                log.internal = Some(internal);
                log.suggested_external = Some(suggested);
                log.lifetime = Some(lifetime);
                let (code, ext, granted) = if lifetime == 0 && self.drop_deletes {
                    (0, 0, 0) // logged and barrier-observable, but never committed or replied
                } else if let Some(o) = self.overrides.get(&log.kind) {
                    (o.code, 0, o.lifetime)
                } else if lifetime == 0 {
                    self.counters.num_deletes += 1;
                    if internal == 0 {
                        self.table
                            .retain(|e| !(e.client_ip == client && e.proto == proto));
                    } else if let Some(i) = self.find(client, proto, internal) {
                        self.table.remove(i);
                    }
                    (0, 0, 0)
                } else {
                    let (ext, granted) =
                        self.upsert(client, proto, internal, suggested, lifetime, None);
                    (0, ext, granted)
                };
                let mut r = vec![0, op | 0x80];
                r.extend_from_slice(&code.to_be_bytes());
                r.extend_from_slice(&epoch.to_be_bytes());
                r.extend_from_slice(&internal.to_be_bytes());
                r.extend_from_slice(&ext.to_be_bytes());
                r.extend_from_slice(&granted.to_be_bytes());
                r
            }
            _ => self.pmp_error_reply(op, 5),
        };
        let kind = log.kind;
        self.requests.push(log);
        Some((kind, out))
    }

    /// A PCP response header.
    fn pcp_header(&self, op: u8, code: u8, lifetime: u32) -> Vec<u8> {
        let mut r = vec![2, op | 0x80, 0, code];
        r.extend_from_slice(&lifetime.to_be_bytes());
        r.extend_from_slice(&self.epoch().to_be_bytes());
        r.extend_from_slice(&[0; 12]);
        r
    }

    fn handle_pcp(
        &mut self,
        req: &[u8],
        src: SocketAddr,
        client: Ipv4Addr,
    ) -> Option<(RequestKind, Vec<u8>)> {
        if !self.opts.pcp {
            // A NAT-PMP-only server answers a PCP request with "unsupported version".
            return (self.opts.pmp && req.len() >= 2)
                .then(|| (RequestKind::Other, self.pmp_error_reply(req[1], 1)));
        }
        if req.len() < 24 || req.len() > 1100 || !req.len().is_multiple_of(4) || req[1] & 0x80 != 0
        {
            self.counters.num_pcp_other_recv += 1;
            return None;
        }
        self.counters.num_pcp_recv += 1;
        let op = req[1];
        let lifetime = be32(req, 4);
        let mut client_field = [0u8; 16];
        client_field.copy_from_slice(&req[8..24]);
        let client_ip = Ipv6Addr::from(client_field).to_ipv4_mapped();
        let mismatch = self.opts.enforce_pcp_client_ip && client_ip != Some(client);
        let mut log = DecodedRequest {
            src,
            kind: RequestKind::Other,
            version: 2,
            opcode: op,
            internal: None,
            suggested_external: None,
            lifetime: Some(lifetime),
            nonce: None,
            pcp_client_ip: client_ip,
        };
        let out = match op {
            0 => {
                self.counters.num_pcp_disco_recv += 1;
                log.kind = RequestKind::PcpAnnounce;
                let code = match self.overrides.get(&log.kind) {
                    Some(o) => u8::try_from(o.code).unwrap_or(u8::MAX),
                    None if mismatch => 12,
                    None => 0,
                };
                self.pcp_header(0, code, 0)
            }
            1 => {
                self.counters.num_pcp_map_recv += 1;
                log.kind = RequestKind::PcpMap;
                if req.len() < 60 {
                    self.counters.invalid_pcp_map_pkt += 1;
                    self.requests.push(log);
                    return Some((RequestKind::PcpMap, self.pcp_header(1, 3, 30)));
                }
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(&req[24..36]);
                let proto = req[36];
                let internal = be16(req, 40);
                let suggested = be16(req, 42);
                log.nonce = Some(nonce);
                log.internal = Some(internal);
                log.suggested_external = Some(suggested);
                let existing = self.find(client, proto, internal);
                let foreign_nonce =
                    existing.is_some_and(|i| self.table[i].nonce.is_some_and(|n| n != nonce));
                let result: Result<(u16, u32), (u8, u32)> = if lifetime == 0 && self.drop_deletes {
                    Ok((0, 0))
                } else if let Some(o) = self.overrides.get(&log.kind) {
                    Err((u8::try_from(o.code).unwrap_or(u8::MAX), o.lifetime))
                } else if mismatch {
                    Err((12, 30))
                } else if proto != 17 && proto != 6 {
                    Err((9, 30))
                } else if internal == 0 {
                    self.counters.invalid_pcp_map_pkt += 1;
                    Err((3, 30))
                } else if foreign_nonce {
                    Err((2, 30))
                } else if lifetime == 0 {
                    self.counters.num_deletes += 1;
                    if let Some(i) = existing {
                        self.table.remove(i);
                    }
                    Ok((0, 0))
                } else {
                    Ok(self.upsert(client, proto, internal, suggested, lifetime, Some(nonce)))
                };
                match result {
                    Err((code, err_lifetime)) if self.opts.short_pcp_errors => {
                        self.pcp_header(1, code, err_lifetime)
                    }
                    Err((code, err_lifetime)) => {
                        let mut r = self.pcp_header(1, code, err_lifetime);
                        r.extend_from_slice(&nonce);
                        r.extend_from_slice(&[proto, 0, 0, 0]);
                        r.extend_from_slice(&internal.to_be_bytes());
                        r.extend_from_slice(&[0, 0]);
                        r.extend_from_slice(&v4_mapped(Ipv4Addr::UNSPECIFIED));
                        r
                    }
                    Ok((ext, granted)) => {
                        let mut r = self.pcp_header(1, 0, granted);
                        r.extend_from_slice(&nonce);
                        r.extend_from_slice(&[proto, 0, 0, 0]);
                        r.extend_from_slice(&internal.to_be_bytes());
                        r.extend_from_slice(&ext.to_be_bytes());
                        let ip = if granted == 0 {
                            Ipv4Addr::UNSPECIFIED
                        } else {
                            self.opts.public_ip
                        };
                        r.extend_from_slice(&v4_mapped(ip));
                        r
                    }
                }
            }
            _ => {
                self.counters.num_pcp_other_recv += 1;
                self.pcp_header(op, 4, 30)
            }
        };
        let kind = log.kind;
        self.requests.push(log);
        Some((kind, out))
    }
}

fn corrupt(r: &mut Vec<u8>, c: Corruption) {
    let pcp = r.first() == Some(&2);
    match c {
        Corruption::Truncate => {
            r.pop();
        }
        Corruption::BadVersion => {
            if let Some(v) = r.first_mut() {
                *v ^= 1;
            }
        }
        Corruption::WrongOpcode => {
            if let Some(o) = r.get_mut(1) {
                *o ^= 0x01;
            }
        }
        Corruption::NoRBit => {
            if let Some(o) = r.get_mut(1) {
                *o &= 0x7f;
            }
        }
        Corruption::WrongNonce => {
            if let Some(n) = r.get_mut(24) {
                *n ^= 0xff;
            }
        }
        Corruption::WrongProto => {
            if let Some(p) = r.get_mut(36) {
                *p = 6;
            }
        }
        Corruption::WrongInternalPort => {
            let at = if pcp { 41 } else { 9 };
            if let Some(p) = r.get_mut(at) {
                *p = p.wrapping_add(1);
            }
        }
        Corruption::Garbage => r.fill(0xa5),
        Corruption::Oversize => r.resize(1200, 0),
    }
}

impl FakeRouter {
    /// Start a router on `opts.bind_ip`, ports chosen by the OS. A non-loopback `bind_ip` is
    /// refused with [`std::io::ErrorKind::InvalidInput`]: the harness never listens on a real
    /// network.
    pub async fn start(opts: RouterOptions) -> std::io::Result<Self> {
        if !opts.bind_ip.is_loopback() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "the fake router binds loopback only",
            ));
        }
        let main = UdpSocket::bind((opts.bind_ip, 0)).await?;
        let wrong_port = UdpSocket::bind((opts.bind_ip, 0)).await?;
        let wrong_ip = UdpSocket::bind((opts.bind_ip, 0)).await?;
        let addr = main.local_addr()?;
        let wrong_port_addr = wrong_port.local_addr()?;
        let wrong_ip_addr = wrong_ip.local_addr()?;
        let state = Arc::new(Mutex::new(State {
            opts,
            table: Vec::new(),
            overrides: HashMap::new(),
            lifetime_override: None,
            assign: AssignPort::Suggested { fallback: 4242 },
            delay: Duration::ZERO,
            drop_next: 0,
            drop_deletes: false,
            duplicate_next: 0,
            reorder_next: false,
            commit_then_drop_next: 0,
            wrong_port_next: 0,
            wrong_ip_next: 0,
            corrupt: VecDeque::new(),
            junk_before_next: 0,
            trickle_next: None,
            spoof_next: None,
            knobs_for: None,
            counters: Counters::default(),
            requests: Vec::new(),
            barriers: Vec::new(),
            held: None,
        }));
        let shutdown = Arc::new(Notify::new());
        let task = tokio::spawn(run(
            main,
            wrong_port,
            wrong_ip,
            state.clone(),
            shutdown.clone(),
        ));
        Ok(Self {
            addr,
            wrong_port_addr,
            wrong_ip_addr,
            state,
            shutdown,
            task: Some(task),
        })
    }

    /// The addresses a [`super::TestCap`] needs to talk to this router, detached from the router
    /// itself (so a cap factory can outlive a borrow of it).
    pub fn endpoint(&self) -> RouterEndpoint {
        RouterEndpoint {
            addr: self.addr,
            wrong_port_addr: self.wrong_port_addr,
            wrong_ip_addr: self.wrong_ip_addr,
        }
    }

    /// The router's loopback address (presented to clients as `gateway:5351`).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Where replies routed "from the wrong port" come from.
    pub fn wrong_port_addr(&self) -> SocketAddr {
        self.wrong_port_addr
    }

    /// Where replies routed "from the wrong address" come from.
    pub fn wrong_ip_addr(&self) -> SocketAddr {
        self.wrong_ip_addr
    }

    fn st(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The lease clock.
    pub fn clock(&self) -> LeaseClock {
        self.st().opts.clock.clone()
    }

    /// The counters so far.
    pub fn counters(&self) -> Counters {
        self.st().counters.clone()
    }

    /// Every decoded request so far.
    pub fn requests(&self) -> Vec<DecodedRequest> {
        self.st().requests.clone()
    }

    /// The live mapping table (expired entries removed).
    pub fn mappings(&self) -> Vec<MappingEntry> {
        let mut st = self.st();
        let now = st.opts.clock.now();
        st.table.retain(|e| e.expires_at > now);
        st.table.clone()
    }

    /// Drop delete requests before committing them (create/renew requests still work).
    pub fn set_drop_deletes(&self, on: bool) {
        self.st().drop_deletes = on;
    }

    /// Answer NAT-PMP or not.
    pub fn set_pmp(&self, on: bool) {
        self.st().opts.pmp = on;
    }

    /// Answer PCP or not.
    pub fn set_pcp(&self, on: bool) {
        self.st().opts.pcp = on;
    }

    /// Change the reported public address.
    pub fn set_public_ip(&self, ip: Ipv4Addr) {
        self.st().opts.public_ip = ip;
    }

    /// Fix the epoch at `epoch`.
    pub fn set_epoch(&self, epoch: u32) {
        self.st().opts.epoch = EpochMode::Fixed(epoch);
    }

    /// Simulate a reboot: the table is cleared and the epoch restarts from 0 on the clock.
    pub fn reboot(&self) {
        let mut st = self.st();
        st.table.clear();
        let now = st.opts.clock.now();
        st.opts.epoch = EpochMode::Clock { zero_at: now };
    }

    /// Force (or with `None`, stop forcing) the result for `kind`.
    pub fn set_result(&self, kind: RequestKind, result: Option<ResultOverride>) {
        let mut st = self.st();
        match result {
            Some(r) => st.overrides.insert(kind, r),
            None => st.overrides.remove(&kind),
        };
    }

    /// Grant this lifetime instead of the requested one (shorter or longer).
    pub fn set_lifetime_override(&self, lifetime: Option<u32>) {
        self.st().lifetime_override = lifetime;
    }

    /// Change how external ports are assigned.
    pub fn set_assign_port(&self, assign: AssignPort) {
        self.st().assign = assign;
    }

    /// Wait this long before every reply. Each reply waits on its own; later requests are still
    /// handled meanwhile.
    pub fn set_delay(&self, delay: Duration) {
        self.st().delay = delay;
    }

    /// Ignore the next `n` requests entirely (nothing is committed).
    pub fn drop_next(&self, n: u32) {
        self.st().drop_next = n;
    }

    /// Send each of the next `n` replies twice. With a pending [`Corruption`], only the first
    /// copy is corrupted, so a bad reply is followed by a good one.
    pub fn duplicate_next(&self, n: u32) {
        self.st().duplicate_next = n;
    }

    /// Hold the next reply and send it after the one that follows.
    pub fn reorder_next(&self) {
        self.st().reorder_next = true;
    }

    /// Commit the next `n` requests but drop their replies.
    pub fn commit_then_drop_next(&self, n: u32) {
        self.st().commit_then_drop_next = n;
    }

    /// Send the next `n` replies from another port.
    pub fn reply_from_wrong_port_next(&self, n: u32) {
        self.st().wrong_port_next = n;
    }

    /// Send the next `n` replies from a socket a `TestCap` presents as another address.
    pub fn reply_from_wrong_ip_next(&self, n: u32) {
        self.st().wrong_ip_next = n;
    }

    /// Corrupt the next reply (queued; one corruption per reply).
    pub fn corrupt_next(&self, c: Corruption) {
        self.st().corrupt.push_back(c);
    }

    /// Before the next reply, send `n` junk datagrams from the router's own address.
    pub fn junk_before_next_reply(&self, n: usize) {
        self.st().junk_before_next = n;
    }

    /// For the next request, send `n` junk datagrams from the router's own address, `interval`
    /// apart (the first after one `interval`), and then drop the real reply. With `n` below
    /// [`crate::MAX_EXAMINED`] and `n * interval` well past the exchange timeout, this shows
    /// whether junk can extend an exchange's deadline.
    pub fn junk_trickle_next(&self, n: usize, interval: Duration) {
        self.st().trickle_next = Some((n, interval));
    }

    /// Before the next reply, send `datagram` from the router's own address: an on-LAN spoofer
    /// that wins the race against the real reply.
    pub fn spoof_before_next_reply(&self, datagram: Vec<u8>) {
        self.st().spoof_next = Some(datagram);
    }

    /// Apply the one-shot reply knobs (corruption, commit-then-drop, wrong source, duplicate,
    /// reorder, junk, trickle, spoof) only to requests of `kind`; `None` (the default) applies
    /// them to whatever request comes next. Barriers, delays and [`FakeRouter::drop_next`] are
    /// unaffected.
    pub fn knobs_for(&self, kind: Option<RequestKind>) {
        self.st().knobs_for = kind;
    }

    /// Enforce that the PCP client IP field equals the source address.
    pub fn set_enforce_pcp_client_ip(&self, on: bool) {
        self.st().opts.enforce_pcp_client_ip = on;
    }

    /// Send PCP errors header-only.
    pub fn set_short_pcp_errors(&self, on: bool) {
        self.st().opts.short_pcp_errors = on;
    }

    /// Pause before replying to the next request of `kind` (after committing it). Only that reply
    /// waits; other requests are handled and answered meanwhile.
    pub fn barrier(&self, kind: RequestKind) -> Barrier {
        let reached = Arc::new(Notify::new());
        let (tx, rx) = oneshot::channel();
        self.st().barriers.push((
            kind,
            BarrierInner {
                reached: reached.clone(),
                release: rx,
            },
        ));
        Barrier {
            reached,
            release: Some(tx),
        }
    }

    /// Stop the router and wait for its task and every reply task to finish. Nothing runs
    /// afterwards.
    pub async fn shutdown(mut self) {
        self.shutdown.notify_one();
        if let Some(task) = self.task.take() {
            task.await.ok();
        }
    }
}

impl Drop for FakeRouter {
    fn drop(&mut self) {
        // A backstop only; tests call `shutdown().await`.
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

/// The router's three sockets.
struct Socks {
    main: UdpSocket,
    wrong_port: UdpSocket,
    wrong_ip: UdpSocket,
}

async fn run(
    main: UdpSocket,
    wrong_port: UdpSocket,
    wrong_ip: UdpSocket,
    state: Arc<Mutex<State>>,
    shutdown: Arc<Notify>,
) {
    let socks = Arc::new(Socks {
        main,
        wrong_port,
        wrong_ip,
    });
    let mut replies = JoinSet::new();
    let mut buf = vec![0u8; 2048];
    loop {
        let (n, src) = tokio::select! {
            () = shutdown.notified() => break,
            // Reap finished reply tasks so the set stays small.
            Some(_) = replies.join_next(), if !replies.is_empty() => continue,
            r = socks.main.recv_from(&mut buf) => match r {
                Ok(v) => v,
                Err(_) => continue,
            },
        };
        // Decode and commit synchronously, in arrival order.
        let plan = {
            let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
            st.handle(&buf[..n], src)
        };
        if let Some(plan) = plan {
            replies.spawn(reply(plan, src, socks.clone(), state.clone()));
        }
    }
    // Abort and join every reply still paused, delayed or trickling.
    replies.shutdown().await;
}

/// Send one reply per its plan. Runs in its own task.
async fn reply(plan: ReplyPlan, src: SocketAddr, socks: Arc<Socks>, state: Arc<Mutex<State>>) {
    if let Some(b) = plan.barrier {
        b.reached.notify_one();
        // A dropped `Barrier` releases too.
        b.release.await.ok();
    }
    if !plan.delay.is_zero() {
        tokio::time::sleep(plan.delay).await;
    }
    if let Some((n, interval)) = plan.trickle {
        for _ in 0..n {
            tokio::time::sleep(interval).await;
            socks.main.send_to(&[0xa5; 16], src).await.ok();
        }
        return;
    }
    // Junk and a spoof are not the reply: they go out even when the reply is dropped or held.
    for _ in 0..plan.junk {
        socks.main.send_to(&[0xa5; 16], src).await.ok();
    }
    if let Some(d) = &plan.spoof {
        socks.main.send_to(d, src).await.ok();
    }
    if plan.drop || plan.hold {
        return;
    }
    let sock = match plan.via {
        Via::Main => &socks.main,
        Via::WrongPort => &socks.wrong_port,
        Via::WrongIp => &socks.wrong_ip,
    };
    sock.send_to(&plan.reply, src).await.ok();
    if plan.duplicate {
        sock.send_to(&plan.original, src).await.ok();
    }
    let held = state.lock().unwrap_or_else(|p| p.into_inner()).held.take();
    if let Some((r, to)) = held {
        socks.main.send_to(&r, to).await.ok();
    }
}
