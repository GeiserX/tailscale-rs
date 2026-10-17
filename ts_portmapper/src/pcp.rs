//! PCP codec (RFC 6887), IPv4 only.
//!
//! Pure functions over byte slices: no I/O, no panics (fuzzed). Every reply must carry version 2,
//! the R (response) bit, the request's opcode and a length that is at least 24, at most 1100 and
//! a multiple of 4. A MAP success must echo our nonce, protocol 17 and internal port, and assign
//! an IPv4-mapped, nonzero external address and port with a nonzero lifetime. A nonzero result
//! code in a full-length response that echoes our nonce is a typed [`ReplyError::Router`] that
//! carries the error lifetime (how long the client should treat the error as current, RFC 6887
//! §7.4). A header-only (shorter than 60 bytes) error carries no nonce, so it cannot be tied to
//! our request: it is [`ReplyError::Unmatched`], which callers treat as a fallback only, never as
//! an answer that ends an exchange.
//!
//! ```compile_fail
//! // The internal port is a `NonZeroU16`: a request for internal port 0 ("all ports") cannot be
//! // built.
//! let nonce = ts_portmapper::pcp::Nonce::from_bytes([0; 12]);
//! let _ = ts_portmapper::pcp::map_request(
//!     std::net::Ipv4Addr::LOCALHOST, 0, 0, std::num::NonZeroU32::MIN, &nonce);
//! ```

use std::{
    fmt,
    net::{Ipv4Addr, SocketAddrV4},
    num::{NonZeroU16, NonZeroU32},
};

/// PCP protocol version.
pub const VERSION: u8 = 2;
/// The R bit: set in responses, clear in requests.
pub const R_BIT: u8 = 0x80;
/// Opcode ANNOUNCE.
pub const OP_ANNOUNCE: u8 = 0;
/// Opcode MAP.
pub const OP_MAP: u8 = 1;
/// IANA protocol number for UDP, the only protocol we map.
pub const PROTO_UDP: u8 = 17;
/// Length of the common header.
pub const HEADER_LEN: usize = 24;
/// Length of a MAP request or response without options.
pub const MAP_LEN: usize = 60;
/// Largest PCP message (RFC 6887 §7).
pub const MAX_LEN: usize = 1100;

/// A PCP result code (RFC 6887 §7.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResultCode {
    /// 0
    Success,
    /// 1
    UnsuppVersion,
    /// 2: PCP is implemented but refuses this client (mapping turned off).
    NotAuthorized,
    /// 3
    MalformedRequest,
    /// 4
    UnsuppOpcode,
    /// 5
    UnsuppOption,
    /// 6
    MalformedOption,
    /// 7
    NetworkFailure,
    /// 8
    NoResources,
    /// 9
    UnsuppProtocol,
    /// 10
    UserExQuota,
    /// 11
    CannotProvideExternal,
    /// 12: the request's source differs from its client IP field (a NAT in between).
    AddressMismatch,
    /// 13
    ExcessiveRemotePeers,
    /// Any other value.
    Unknown(u8),
}

impl From<u8> for ResultCode {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Success,
            1 => Self::UnsuppVersion,
            2 => Self::NotAuthorized,
            3 => Self::MalformedRequest,
            4 => Self::UnsuppOpcode,
            5 => Self::UnsuppOption,
            6 => Self::MalformedOption,
            7 => Self::NetworkFailure,
            8 => Self::NoResources,
            9 => Self::UnsuppProtocol,
            10 => Self::UserExQuota,
            11 => Self::CannotProvideExternal,
            12 => Self::AddressMismatch,
            13 => Self::ExcessiveRemotePeers,
            n => Self::Unknown(n),
        }
    }
}

impl From<ResultCode> for u8 {
    fn from(c: ResultCode) -> u8 {
        match c {
            ResultCode::Success => 0,
            ResultCode::UnsuppVersion => 1,
            ResultCode::NotAuthorized => 2,
            ResultCode::MalformedRequest => 3,
            ResultCode::UnsuppOpcode => 4,
            ResultCode::UnsuppOption => 5,
            ResultCode::MalformedOption => 6,
            ResultCode::NetworkFailure => 7,
            ResultCode::NoResources => 8,
            ResultCode::UnsuppProtocol => 9,
            ResultCode::UserExQuota => 10,
            ResultCode::CannotProvideExternal => 11,
            ResultCode::AddressMismatch => 12,
            ResultCode::ExcessiveRemotePeers => 13,
            ResultCode::Unknown(n) => n,
        }
    }
}

impl fmt::Display for ResultCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Success => "success",
            Self::UnsuppVersion => "unsupp-version",
            Self::NotAuthorized => "not-authorized",
            Self::MalformedRequest => "malformed-request",
            Self::UnsuppOpcode => "unsupp-opcode",
            Self::UnsuppOption => "unsupp-option",
            Self::MalformedOption => "malformed-option",
            Self::NetworkFailure => "network-failure",
            Self::NoResources => "no-resources",
            Self::UnsuppProtocol => "unsupp-protocol",
            Self::UserExQuota => "user-ex-quota",
            Self::CannotProvideExternal => "cannot-provide-external",
            Self::AddressMismatch => "address-mismatch",
            Self::ExcessiveRemotePeers => "excessive-remote-peers",
            Self::Unknown(_) => "unknown",
        };
        write!(f, "{name}({})", u8::from(*self))
    }
}

/// A MAP nonce (RFC 6887 §11.1). Its `Debug` output is redacted: nonces are never logged.
#[derive(Clone, PartialEq, Eq)]
pub struct Nonce([u8; 12]);

/// The OS random source failed.
#[derive(Debug, thiserror::Error)]
#[error("OS random number generator failed: {0}")]
pub struct NonceError(getrandom::Error);

impl Nonce {
    /// A fresh nonce from the OS CSPRNG.
    pub fn random() -> Result<Self, NonceError> {
        let mut b = [0u8; 12];
        getrandom::fill(&mut b).map_err(NonceError)?;
        Ok(Self(b))
    }

    /// A nonce with the given bytes (tests, fuzzing and parsing only; use [`Nonce::random`] for
    /// requests).
    pub const fn from_bytes(b: [u8; 12]) -> Self {
        Self(b)
    }

    /// The nonce bytes.
    pub const fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Nonce(..)")
    }
}

/// Why a datagram is not an acceptable reply to the request it was matched against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Malformed {
    /// Shorter than required.
    TooShort(usize),
    /// Longer than 1100 bytes.
    TooLong(usize),
    /// Length not a multiple of 4.
    NotMultipleOf4(usize),
    /// Not version 2.
    BadVersion(u8),
    /// The R bit is clear (a request, not a response).
    NoRBit,
    /// Not the request's opcode.
    WrongOpcode(u8),
    /// A MAP response with another nonce (another client's or a spoofer's).
    WrongNonce,
    /// A MAP response for another protocol.
    WrongProtocol(u8),
    /// A MAP response for another internal port.
    InternalPortMismatch {
        /// Internal port in the reply.
        got: u16,
        /// Internal port we asked for.
        want: u16,
    },
    /// The assigned external address is not IPv4-mapped.
    NotIpv4Mapped,
    /// The assigned external address is `0.0.0.0`.
    ZeroAddress,
    /// An external address no router can have (see [`crate::is_plausible_external`]).
    ImplausibleAddress(Ipv4Addr),
    /// The assigned external port is 0.
    ZeroExternalPort,
    /// A success with lifetime 0 for a create or renew.
    ZeroLifetime,
    /// A reply to a delete that still carries a lifetime.
    NonZeroLifetimeOnDelete(u32),
    /// An option runs past the end of the message.
    BadOption(usize),
}

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort(n) => write!(f, "too short ({n} bytes)"),
            Self::TooLong(n) => write!(f, "too long ({n} bytes)"),
            Self::NotMultipleOf4(n) => write!(f, "length {n} is not a multiple of 4"),
            Self::BadVersion(v) => write!(f, "version {v}, not 2"),
            Self::NoRBit => f.write_str("R bit clear"),
            Self::WrongOpcode(o) => write!(f, "unexpected opcode {o}"),
            Self::WrongNonce => f.write_str("nonce mismatch"),
            Self::WrongProtocol(p) => write!(f, "protocol {p}, not 17"),
            Self::InternalPortMismatch { got, want } => {
                write!(f, "internal port {got}, expected {want}")
            }
            Self::NotIpv4Mapped => f.write_str("external address not IPv4-mapped"),
            Self::ZeroAddress => f.write_str("external address 0.0.0.0"),
            Self::ImplausibleAddress(ip) => write!(f, "implausible external address {ip}"),
            Self::ZeroExternalPort => f.write_str("external port 0"),
            Self::ZeroLifetime => f.write_str("lifetime 0 on a create"),
            Self::NonZeroLifetimeOnDelete(l) => write!(f, "lifetime {l} on a delete"),
            Self::BadOption(at) => write!(f, "option at offset {at} overruns the message"),
        }
    }
}

/// A MAP reply that is not a success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReplyError {
    /// A well-formed response with a nonzero result code.
    #[error("PCP {code} (error lifetime {lifetime} s, epoch {epoch})")]
    Router {
        /// The result code.
        code: ResultCode,
        /// For how long the error should be considered current, in seconds.
        lifetime: u32,
        /// The server's epoch time.
        epoch: u32,
    },
    /// A header-only error response (shorter than a MAP response). It carries no nonce, so
    /// anyone on the LAN who can send from `gateway:5351` could have forged it: callers must not
    /// end an exchange on it, and must cap the error lifetime they act on.
    #[error("PCP {code} without a nonce (error lifetime {lifetime} s, epoch {epoch})")]
    Unmatched {
        /// The result code.
        code: ResultCode,
        /// The claimed error lifetime, in seconds (unverified).
        lifetime: u32,
        /// The claimed epoch.
        epoch: u32,
    },
    /// Not an acceptable reply.
    #[error("malformed PCP reply: {0}")]
    Malformed(Malformed),
}

impl From<Malformed> for ReplyError {
    fn from(m: Malformed) -> Self {
        Self::Malformed(m)
    }
}

/// A validated response common header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The opcode without the R bit.
    pub opcode: u8,
    /// The result code.
    pub result: ResultCode,
    /// Lifetime in seconds (mapping lifetime, or error lifetime on failure).
    pub lifetime: u32,
    /// The server's epoch time.
    pub epoch: u32,
}

/// An ANNOUNCE response. Any result code is returned as data: `Success` means PCP is usable,
/// `NotAuthorized` and `AddressMismatch` mean a PCP server exists but won't help us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnnounceReply {
    /// The result code.
    pub result: ResultCode,
    /// The server's epoch time.
    pub epoch: u32,
}

/// A successful MAP response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapReply {
    /// The server's epoch time.
    pub epoch: u32,
    /// Granted lifetime in seconds: nonzero for a create, 0 for a delete.
    pub lifetime: u32,
    /// The internal port; always the one requested.
    pub internal: u16,
    /// The assigned external address. For a delete reply it may be `0.0.0.0:0`.
    pub external: SocketAddrV4,
}

/// Whether a MAP request creates/renews a mapping or deletes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapKind {
    /// Create or renew (lifetime > 0).
    Map,
    /// Delete (lifetime 0).
    Delete,
}

/// The IPv4-mapped IPv6 form of `ip` (`::ffff:a.b.c.d`).
const fn mapped(ip: Ipv4Addr) -> [u8; 16] {
    let o = ip.octets();
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, o[0], o[1], o[2], o[3],
    ]
}

fn header_bytes(op: u8, lifetime: u32, client: Ipv4Addr) -> [u8; HEADER_LEN] {
    let mut p = [0u8; HEADER_LEN];
    p[0] = VERSION;
    p[1] = op;
    p[4..8].copy_from_slice(&lifetime.to_be_bytes());
    p[8..24].copy_from_slice(&mapped(client));
    p
}

/// An ANNOUNCE request from `client` (this host's own LAN address).
pub fn announce_request(client: Ipv4Addr) -> [u8; HEADER_LEN] {
    header_bytes(OP_ANNOUNCE, 0, client)
}

/// A MAP request for UDP `internal` on `client`, suggesting `suggested_external_port` (0 for
/// none) and the all-zeros external address `::ffff:0.0.0.0`.
pub fn map_request(
    client: Ipv4Addr,
    internal: NonZeroU16,
    suggested_external_port: u16,
    lifetime: NonZeroU32,
    nonce: &Nonce,
) -> [u8; MAP_LEN] {
    build_map(
        client,
        internal.get(),
        suggested_external_port,
        lifetime.get(),
        nonce,
    )
}

/// A MAP delete for UDP `internal` on `client`: lifetime 0, suggested port 0, suggested address
/// `::ffff:0.0.0.0`, and the mapping's **original** nonce (RFC 6887 §15.1, Errata 3621).
pub fn delete_request(client: Ipv4Addr, internal: NonZeroU16, nonce: &Nonce) -> [u8; MAP_LEN] {
    build_map(client, internal.get(), 0, 0, nonce)
}

fn build_map(
    client: Ipv4Addr,
    internal: u16,
    suggested_port: u16,
    lifetime: u32,
    nonce: &Nonce,
) -> [u8; MAP_LEN] {
    let mut p = [0u8; MAP_LEN];
    p[..HEADER_LEN].copy_from_slice(&header_bytes(OP_MAP, lifetime, client));
    p[24..36].copy_from_slice(nonce.as_bytes());
    p[36] = PROTO_UDP;
    p[40..42].copy_from_slice(&internal.to_be_bytes());
    p[42..44].copy_from_slice(&suggested_port.to_be_bytes());
    p[44..60].copy_from_slice(&mapped(Ipv4Addr::UNSPECIFIED));
    p
}

fn be16(b: &[u8], at: usize) -> u16 {
    match b.get(at..at + 2) {
        Some(&[x, y]) => u16::from_be_bytes([x, y]),
        _ => 0,
    }
}

fn be32(b: &[u8], at: usize) -> u32 {
    match b.get(at..at + 4) {
        Some(&[w, x, y, z]) => u32::from_be_bytes([w, x, y, z]),
        _ => 0,
    }
}

/// Validate a response's common header: length, version and R bit.
pub fn parse_header(b: &[u8]) -> Result<Header, Malformed> {
    if b.len() < HEADER_LEN {
        return Err(Malformed::TooShort(b.len()));
    }
    if b.len() > MAX_LEN {
        return Err(Malformed::TooLong(b.len()));
    }
    if !b.len().is_multiple_of(4) {
        return Err(Malformed::NotMultipleOf4(b.len()));
    }
    if b[0] != VERSION {
        return Err(Malformed::BadVersion(b[0]));
    }
    if b[1] & R_BIT == 0 {
        return Err(Malformed::NoRBit);
    }
    Ok(Header {
        opcode: b[1] & !R_BIT,
        result: ResultCode::from(b[3]),
        lifetime: be32(b, 4),
        epoch: be32(b, 8),
    })
}

/// Parse a response to [`announce_request`].
pub fn parse_announce_reply(b: &[u8]) -> Result<AnnounceReply, Malformed> {
    let h = parse_header(b)?;
    if h.opcode != OP_ANNOUNCE {
        return Err(Malformed::WrongOpcode(h.opcode));
    }
    Ok(AnnounceReply {
        result: h.result,
        epoch: h.epoch,
    })
}

/// Check that the options after the MAP payload stay inside the message. We send none, so their
/// content is ignored.
fn check_options(b: &[u8]) -> Result<(), Malformed> {
    let mut off = MAP_LEN;
    while off < b.len() {
        if b.len() - off < 4 {
            return Err(Malformed::BadOption(off));
        }
        let len = usize::from(be16(b, off + 2));
        // Option data is padded to a multiple of 4 (RFC 6887 §7.3).
        let total = 4 + len.div_ceil(4) * 4;
        if total > b.len() - off {
            return Err(Malformed::BadOption(off));
        }
        off += total;
    }
    Ok(())
}

/// Parse a response to a MAP request for UDP `internal` sent with `nonce`.
pub fn parse_map_reply(
    b: &[u8],
    nonce: &Nonce,
    internal: NonZeroU16,
    kind: MapKind,
) -> Result<MapReply, ReplyError> {
    let h = parse_header(b)?;
    if h.opcode != OP_MAP {
        return Err(Malformed::WrongOpcode(h.opcode).into());
    }
    if b.len() < MAP_LEN {
        if h.result == ResultCode::Success {
            return Err(Malformed::TooShort(b.len()).into());
        }
        // A header-only error cannot be matched by nonce (RFC 6887 §7.2 has a server that parsed
        // our request copy its fields): not authoritative.
        return Err(ReplyError::Unmatched {
            code: h.result,
            lifetime: h.lifetime,
            epoch: h.epoch,
        });
    }
    if b.get(24..36) != Some(nonce.as_bytes().as_slice()) {
        return Err(Malformed::WrongNonce.into());
    }
    if b[36] != PROTO_UDP {
        return Err(Malformed::WrongProtocol(b[36]).into());
    }
    let got_internal = be16(b, 40);
    if got_internal != internal.get() {
        return Err(Malformed::InternalPortMismatch {
            got: got_internal,
            want: internal.get(),
        }
        .into());
    }
    if h.result != ResultCode::Success {
        return Err(ReplyError::Router {
            code: h.result,
            lifetime: h.lifetime,
            epoch: h.epoch,
        });
    }
    check_options(b)?;
    let ext_port = be16(b, 42);
    let ext = &b[44..60];
    let ext_ip = match ext {
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b2, c, d] => Ipv4Addr::new(*a, *b2, *c, *d),
        _ if kind == MapKind::Delete => Ipv4Addr::UNSPECIFIED,
        _ => return Err(Malformed::NotIpv4Mapped.into()),
    };
    match kind {
        MapKind::Map => {
            if h.lifetime == 0 {
                return Err(Malformed::ZeroLifetime.into());
            }
            if ext_ip.is_unspecified() {
                return Err(Malformed::ZeroAddress.into());
            }
            if !crate::is_plausible_external(ext_ip) {
                return Err(Malformed::ImplausibleAddress(ext_ip).into());
            }
            if ext_port == 0 {
                return Err(Malformed::ZeroExternalPort.into());
            }
        }
        MapKind::Delete if h.lifetime != 0 => {
            return Err(Malformed::NonZeroLifetimeOnDelete(h.lifetime).into());
        }
        MapKind::Delete => {}
    }
    Ok(MapReply {
        epoch: h.epoch,
        lifetime: h.lifetime,
        internal: got_internal,
        external: SocketAddrV4::new(ext_ip, ext_port),
    })
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const P1234: NonZeroU16 = NonZeroU16::new(1234).unwrap();
    const L7200: NonZeroU32 = NonZeroU32::new(7200).unwrap();
    const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 20);

    /// Go's `examplePCPMapResponse` (`net/portmapper/pcp_test.go`) with its public external
    /// address rewritten into 203.0.113.0/24. PCP has no checksum, so the rewrite is the last
    /// four bytes only. Nonce = bytes 24..36, internal = external = 1234, lifetime 7200.
    const GOLDEN_MAP_RESPONSE: [u8; 60] = [
        2, 129, 0, 0, 0, 0, 28, 32, 0, 2, 155, 237, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 129, 112,
        9, 24, 241, 208, 251, 45, 157, 76, 10, 188, 17, 0, 0, 0, 4, 210, 4, 210, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 255, 255, 203, 0, 113, 246,
    ];

    fn golden_nonce() -> Nonce {
        let mut n = [0u8; 12];
        n.copy_from_slice(&GOLDEN_MAP_RESPONSE[24..36]);
        Nonce::from_bytes(n)
    }

    /// Port of Go's `TestParsePCPMapResponse`.
    #[test]
    fn golden_map_response() {
        let r =
            parse_map_reply(&GOLDEN_MAP_RESPONSE, &golden_nonce(), P1234, MapKind::Map).unwrap();
        assert_eq!(r.external, "203.0.113.246:1234".parse().unwrap());
        assert_eq!(r.lifetime, 7200);
        assert_eq!(r.epoch, 0x29bed);
        assert_eq!(r.internal, 1234);
    }

    /// Golden ANNOUNCE, MAP and delete requests.
    #[test]
    fn golden_requests() {
        let mut want = [0u8; 24];
        want[0] = 2;
        want[18..24].copy_from_slice(&[0xff, 0xff, 192, 168, 1, 20]);
        assert_eq!(announce_request(CLIENT), want);

        let nonce = golden_nonce();
        let m = map_request(CLIENT, P1234, 41641, L7200, &nonce);
        let mut want = [0u8; 60];
        want[0] = 2;
        want[1] = 1;
        want[4..8].copy_from_slice(&7200u32.to_be_bytes());
        want[18..24].copy_from_slice(&[0xff, 0xff, 192, 168, 1, 20]);
        want[24..36].copy_from_slice(nonce.as_bytes());
        want[36] = 17;
        want[40..42].copy_from_slice(&1234u16.to_be_bytes());
        want[42..44].copy_from_slice(&41641u16.to_be_bytes());
        want[54..56].copy_from_slice(&[0xff, 0xff]);
        assert_eq!(m, want);

        // Delete (Errata 3621): lifetime 0, port 0, ::ffff:0.0.0.0, the ORIGINAL nonce.
        let d = delete_request(CLIENT, P1234, &nonce);
        want[4..8].copy_from_slice(&[0; 4]);
        want[42..44].copy_from_slice(&[0, 0]);
        assert_eq!(d, want);
    }

    fn response(op: u8, result: u8, lifetime: u32, epoch: u32) -> Vec<u8> {
        let mut b = vec![0u8; 24];
        b[0] = 2;
        b[1] = op | R_BIT;
        b[3] = result;
        b[4..8].copy_from_slice(&lifetime.to_be_bytes());
        b[8..12].copy_from_slice(&epoch.to_be_bytes());
        b
    }

    fn map_response(result: u8, lifetime: u32, nonce: &Nonce, ext: [u8; 16], port: u16) -> Vec<u8> {
        let mut b = response(OP_MAP, result, lifetime, 3);
        b.extend_from_slice(nonce.as_bytes());
        b.extend_from_slice(&[17, 0, 0, 0]);
        b.extend_from_slice(&1234u16.to_be_bytes());
        b.extend_from_slice(&port.to_be_bytes());
        b.extend_from_slice(&ext);
        b
    }

    const EXT: [u8; 16] = mapped(Ipv4Addr::new(203, 0, 113, 7));

    #[test]
    fn announce_results_are_data() {
        for code in [0u8, 2, 12, 99] {
            let r = parse_announce_reply(&response(OP_ANNOUNCE, code, 0, 7)).unwrap();
            assert_eq!(r.result, ResultCode::from(code));
            assert_eq!(r.epoch, 7);
        }
        // A MAP response is not an ANNOUNCE response.
        assert_eq!(
            parse_announce_reply(&response(OP_MAP, 0, 0, 7)),
            Err(Malformed::WrongOpcode(OP_MAP))
        );
    }

    /// Header validation.
    #[test]
    fn header_rejects() {
        let ok = response(OP_ANNOUNCE, 0, 0, 1);
        assert_eq!(parse_header(&ok[..23]), Err(Malformed::TooShort(23)));
        let mut v = ok.clone();
        v[0] = 1;
        assert_eq!(parse_header(&v), Err(Malformed::BadVersion(1)));
        let mut r = ok.clone();
        r[1] = OP_ANNOUNCE;
        assert_eq!(parse_header(&r), Err(Malformed::NoRBit));
        let mut odd = ok.clone();
        odd.extend_from_slice(&[0, 0]);
        assert_eq!(parse_header(&odd), Err(Malformed::NotMultipleOf4(26)));
        let mut long = ok.clone();
        long.resize(1104, 0);
        assert_eq!(parse_header(&long), Err(Malformed::TooLong(1104)));
        let mut max = ok;
        max.resize(1100, 0);
        assert!(parse_header(&max).is_ok());
    }

    /// MAP validation of nonce, protocol, internal port, external address and port.
    #[test]
    fn map_rejects() {
        let n = golden_nonce();
        let other = Nonce::from_bytes([7; 12]);
        let parse = |b: &[u8]| parse_map_reply(b, &n, P1234, MapKind::Map);
        assert!(parse(&map_response(0, 60, &n, EXT, 4242)).is_ok());
        assert_eq!(
            parse(&map_response(0, 60, &other, EXT, 4242)),
            Err(Malformed::WrongNonce.into())
        );
        let mut proto = map_response(0, 60, &n, EXT, 4242);
        proto[36] = 6;
        assert_eq!(parse(&proto), Err(Malformed::WrongProtocol(6).into()));
        let mut port = map_response(0, 60, &n, EXT, 4242);
        port[40..42].copy_from_slice(&1235u16.to_be_bytes());
        assert_eq!(
            parse(&port),
            Err(Malformed::InternalPortMismatch {
                got: 1235,
                want: 1234
            }
            .into())
        );
        let v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(
            parse(&map_response(0, 60, &n, v6, 4242)),
            Err(Malformed::NotIpv4Mapped.into())
        );
        assert_eq!(
            parse(&map_response(
                0,
                60,
                &n,
                mapped(Ipv4Addr::UNSPECIFIED),
                4242
            )),
            Err(Malformed::ZeroAddress.into())
        );
        let lo = Ipv4Addr::LOCALHOST;
        assert_eq!(
            parse(&map_response(0, 60, &n, mapped(lo), 4242)),
            Err(Malformed::ImplausibleAddress(lo).into())
        );
        assert_eq!(
            parse(&map_response(0, 60, &n, EXT, 0)),
            Err(Malformed::ZeroExternalPort.into())
        );
        assert_eq!(
            parse(&map_response(0, 0, &n, EXT, 4242)),
            Err(Malformed::ZeroLifetime.into())
        );
        let mut no_r = map_response(0, 60, &n, EXT, 4242);
        no_r[1] = OP_MAP;
        assert_eq!(parse(&no_r), Err(Malformed::NoRBit.into()));
        // A MAP parser rejects an ANNOUNCE opcode (stronger than Go, which ignores the opcode).
        let mut announce = map_response(0, 60, &n, EXT, 4242);
        announce[1] = R_BIT | OP_ANNOUNCE;
        assert_eq!(parse(&announce), Err(Malformed::WrongOpcode(0).into()));
    }

    /// A short (header-only) error carries no nonce, so it is `Unmatched`, never an
    /// authoritative `Router` error, whatever its code or lifetime.
    #[test]
    fn short_error_is_unmatched() {
        let n = golden_nonce();
        let short = response(OP_MAP, 2, 1800, 9);
        assert_eq!(
            parse_map_reply(&short, &n, P1234, MapKind::Map),
            Err(ReplyError::Unmatched {
                code: ResultCode::NotAuthorized,
                lifetime: 1800,
                epoch: 9
            })
        );
        // Any length from 24 to 56 bytes, any code, any lifetime: never `Router`.
        for len in (HEADER_LEN..MAP_LEN).step_by(4) {
            let mut b = response(OP_MAP, 8, u32::MAX, 1);
            b.resize(len, 0);
            for kind in [MapKind::Map, MapKind::Delete] {
                assert!(
                    matches!(
                        parse_map_reply(&b, &n, P1234, kind),
                        Err(ReplyError::Unmatched {
                            code: ResultCode::NoResources,
                            lifetime: u32::MAX,
                            ..
                        })
                    ),
                    "{len}"
                );
            }
        }
        // A full-length error with our nonce is also typed; with another nonce it is not ours.
        let full = map_response(8, 30, &n, EXT, 0);
        assert!(matches!(
            parse_map_reply(&full, &n, P1234, MapKind::Map),
            Err(ReplyError::Router {
                code: ResultCode::NoResources,
                lifetime: 30,
                ..
            })
        ));
        let theirs = map_response(8, 30, &Nonce::from_bytes([1; 12]), EXT, 0);
        assert_eq!(
            parse_map_reply(&theirs, &n, P1234, MapKind::Map),
            Err(Malformed::WrongNonce.into())
        );
        // A header-only success is not a mapping.
        assert_eq!(
            parse_map_reply(&response(OP_MAP, 0, 60, 1), &n, P1234, MapKind::Map),
            Err(Malformed::TooShort(24).into())
        );
    }

    #[test]
    fn delete_reply() {
        let n = golden_nonce();
        let zero = mapped(Ipv4Addr::UNSPECIFIED);
        let r = parse_map_reply(&map_response(0, 0, &n, zero, 0), &n, P1234, MapKind::Delete);
        assert_eq!(r.unwrap().lifetime, 0);
        assert_eq!(
            parse_map_reply(&map_response(0, 5, &n, EXT, 1), &n, P1234, MapKind::Delete),
            Err(Malformed::NonZeroLifetimeOnDelete(5).into())
        );
    }

    #[test]
    fn options_are_bounds_checked() {
        let n = golden_nonce();
        let mut b = map_response(0, 60, &n, EXT, 4242);
        // One well-formed option: code 1, length 4, 4 bytes of data.
        b.extend_from_slice(&[1, 0, 0, 4, 9, 9, 9, 9]);
        assert!(parse_map_reply(&b, &n, P1234, MapKind::Map).is_ok());
        // An option claiming 8 data bytes with only 4 present.
        let len = b.len();
        b[len - 6..len - 4].copy_from_slice(&8u16.to_be_bytes());
        assert_eq!(
            parse_map_reply(&b, &n, P1234, MapKind::Map),
            Err(Malformed::BadOption(60).into())
        );
    }

    /// Lifetimes 1 and `u32::MAX` parse without panicking.
    #[test]
    fn extreme_lifetimes() {
        let n = golden_nonce();
        for l in [1, u32::MAX] {
            let r = parse_map_reply(&map_response(0, l, &n, EXT, 1), &n, P1234, MapKind::Map);
            assert_eq!(r.unwrap().lifetime, l);
        }
    }

    #[test]
    fn nonces_are_random_and_redacted() {
        let a = Nonce::random().unwrap();
        let b = Nonce::random().unwrap();
        assert_ne!(a, b);
        assert_eq!(format!("{a:?}"), "Nonce(..)");
    }

    /// The seeds of Go's `FuzzParsePCPResponse` and `FuzzParsePCPMapResponse`
    /// (`net/portmapper/fuzz_test.go`), with stronger expectations: a MAP parser rejects the
    /// ANNOUNCE-opcode seed and the IPv6 external address, and the result is always exactly one of
    /// a mapping or an error (guaranteed by `Result`).
    #[test]
    fn go_fuzz_seeds() {
        let mut header_seeds: Vec<Vec<u8>> = vec![
            [
                &[
                    2, 129, 0, 7, 28, 32, 155, 237, 10, 188, 17, 255, 135, 180, 175, 246,
                ][..],
                &[0; 8],
            ]
            .concat(),
            [
                &[
                    2, 129, 0, 0, 210, 3, 241, 208, 251, 45, 157, 76, 10, 188, 17, 255,
                ][..],
                &[0; 8],
            ]
            .concat(),
            vec![
                2, 129, 0, 7, 28, 32, 155, 237, 10, 188, 17, 255, 135, 180, 175, 246,
            ],
            vec![2],
            vec![
                1, 129, 0, 0, 0, 0, 0x30, 0x39, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2,
            ],
            vec![
                2, 129, 0, 0, 0, 0, 0x30, 0x39, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
            ],
            vec![
                2, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            vec![
                2, 0x80, 0, 12, 0, 0, 0x30, 0x39, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2,
            ],
            vec![
                2, 129, 0, 1, 0, 0, 0x30, 0x39, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2,
            ],
            vec![
                2, 129, 0, 0xff, 0, 0, 0x30, 0x39, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2,
            ],
            vec![
                2, 129, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
            ],
        ];
        // Go's `{2, 0, ...}` seed has no R bit; ours rejects it.
        let no_r = vec![
            2, 0, 0, 0, 0, 0, 0x30, 0x39, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2,
        ];
        assert_eq!(parse_header(&no_r), Err(Malformed::NoRBit));
        header_seeds.push(no_r);
        for s in &header_seeds {
            let _ = parse_header(s);
            let _ = parse_announce_reply(s);
        }
        // Announce reply opcode, accepted by ANNOUNCE and rejected by MAP.
        let announce = vec![
            2, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert!(parse_announce_reply(&announce).is_ok());

        let nonce = Nonce::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        let tail = |result: u8, op: u8, lifetime: [u8; 4], ext_port: [u8; 2]| -> Vec<u8> {
            let mut b = vec![2, op, 0, result];
            b.extend_from_slice(&lifetime);
            b.extend_from_slice(&[0, 0, 0, 1]);
            b.extend_from_slice(&[0; 12]);
            b.extend_from_slice(nonce.as_bytes());
            b.extend_from_slice(&[17, 0, 0, 0, 0x04, 0xd2]);
            b.extend_from_slice(&ext_port);
            b.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
            b
        };
        let p = |b: &[u8]| parse_map_reply(b, &nonce, P1234, MapKind::Map);
        let ok = tail(0, 129, [0, 0, 0x1c, 0x20], [0x12, 0x34]);
        // Go accepts this seed's IPv6 external address; the port mapper is IPv4-only.
        assert_eq!(p(&ok), Err(Malformed::NotIpv4Mapped.into()));
        assert!(matches!(
            p(&tail(2, 129, [0, 0, 0x1c, 0x20], [0x12, 0x34])),
            Err(ReplyError::Router {
                code: ResultCode::NotAuthorized,
                ..
            })
        ));
        assert!(matches!(
            p(&tail(12, 129, [0, 0, 0x1c, 0x20], [0x12, 0x34])),
            Err(ReplyError::Router {
                code: ResultCode::AddressMismatch,
                ..
            })
        ));
        assert_eq!(p(&ok[..59]), Err(Malformed::NotMultipleOf4(59).into()));
        let mut v1 = ok.clone();
        v1[0] = 1;
        assert_eq!(p(&v1), Err(Malformed::BadVersion(1).into()));
        assert_eq!(
            p(&tail(0, 0x80, [0, 0, 0x1c, 0x20], [0x12, 0x34])),
            Err(Malformed::WrongOpcode(0).into())
        );
        let _ = p(&tail(0, 129, [0; 4], [0x12, 0x34]));
        let _ = p(&tail(0, 129, [0xff; 4], [0xff, 0xff]));
        let _ = p(&GOLDEN_MAP_RESPONSE);
    }

    proptest! {
        #[test]
        fn parsers_never_panic(b in proptest::collection::vec(any::<u8>(), 0..1200), port in 1u16..) {
            let port = NonZeroU16::new(port).unwrap();
            let n = Nonce::from_bytes([0; 12]);
            let _ = parse_header(&b);
            let _ = parse_announce_reply(&b);
            for kind in [MapKind::Map, MapKind::Delete] {
                let r = parse_map_reply(&b, &n, port, kind);
                // Only a full-length response with our nonce is a success or a router error.
                if matches!(r, Ok(_) | Err(ReplyError::Router { .. })) {
                    prop_assert!(b.len() >= MAP_LEN && b[24..36] == [0; 12]);
                }
            }
        }

        /// The same invariant on inputs shaped like MAP responses (version 2, MAP opcode with the
        /// R bit, a valid length), so the error paths are actually reached.
        #[test]
        fn only_nonce_matched_replies_are_authoritative(
            words in 6usize..20, code in any::<u8>(), lifetime in any::<u32>(),
            body in proptest::collection::vec(any::<u8>(), 80), ours in any::<bool>()
        ) {
            let n = Nonce::from_bytes([9; 12]);
            let mut b = response(OP_MAP, code, lifetime, 1);
            b.extend_from_slice(&body);
            b.truncate(words * 4);
            if ours && b.len() >= MAP_LEN {
                b[24..36].copy_from_slice(n.as_bytes());
            }
            for kind in [MapKind::Map, MapKind::Delete] {
                match parse_map_reply(&b, &n, P1234, kind) {
                    Ok(_) | Err(ReplyError::Router { .. }) => {
                        prop_assert!(b.len() >= MAP_LEN && b[24..36] == *n.as_bytes());
                    }
                    Err(ReplyError::Unmatched { .. }) => {
                        prop_assert!(b.len() < MAP_LEN && code != 0);
                    }
                    Err(ReplyError::Malformed(_)) => {}
                }
            }
        }

        #[test]
        fn map_roundtrip(
            nonce in any::<[u8; 12]>(), ip in any::<[u8; 4]>(), port in 1u16.., lifetime in 1u32..
        ) {
            let ip = Ipv4Addr::from(ip);
            prop_assume!(crate::is_plausible_external(ip));
            let n = Nonce::from_bytes(nonce);
            let b = map_response(0, lifetime, &n, mapped(ip), port);
            let r = parse_map_reply(&b, &n, P1234, MapKind::Map).unwrap();
            prop_assert_eq!(r.external, SocketAddrV4::new(ip, port));
            prop_assert_eq!(r.lifetime, lifetime);
        }
    }
    /// Even a nonce-matched error must identify our protocol/internal port.
    #[test]
    fn error_replies_validate_full_request_identity() {
        for at in [36, 41] {
            let mut packet = GOLDEN_MAP_RESPONSE;
            packet[3] = 2;
            packet[at] ^= 1;
            assert!(
                matches!(
                    parse_map_reply(&packet, &golden_nonce(), P1234, MapKind::Map),
                    Err(ReplyError::Malformed(_))
                ),
                "wrong field {at} was authoritative"
            );
        }
    }
}
