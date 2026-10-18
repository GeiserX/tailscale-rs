//! NAT-PMP codec (RFC 6886).
//!
//! Pure functions over byte slices: no I/O, no allocation, no panics (fuzzed). Parsing is strict:
//! a reply must carry version 0, the request's opcode plus 128, and for success the exact RFC
//! length; anything else is [`Malformed`]. A nonzero result code is a typed
//! [`ReplyError::Router`], never a success.
//!
//! ```compile_fail
//! // The internal port is a `NonZeroU16`: a request for internal port 0 ("all ports") cannot be
//! // built.
//! let _ = ts_portmapper::pmp::map_request(0, 0, std::num::NonZeroU32::MIN);
//! ```

use std::{
    fmt,
    net::Ipv4Addr,
    num::{NonZeroU16, NonZeroU32},
};

/// NAT-PMP protocol version.
pub const VERSION: u8 = 0;
/// Opcode: request the gateway's public address.
pub const OP_PUBLIC_ADDR: u8 = 0;
/// Opcode: map a UDP port.
pub const OP_MAP_UDP: u8 = 1;
/// Added to a request's opcode in its reply.
pub const OP_REPLY: u8 = 0x80;
/// Exact length of a successful public-address reply.
pub const PUBLIC_ADDR_REPLY_LEN: usize = 12;
/// Exact length of a successful MAP reply.
pub const MAP_REPLY_LEN: usize = 16;
/// Length of a MAP request.
pub const MAP_REQUEST_LEN: usize = 12;
/// Shortest reply that carries a result code and epoch.
pub const MIN_REPLY_LEN: usize = 8;

/// A NAT-PMP result code (RFC 6886 §3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResultCode {
    /// 0: success.
    Success,
    /// 1: unsupported version.
    UnsupportedVersion,
    /// 2: not authorized/refused (for example, mapping turned off on the router).
    NotAuthorized,
    /// 3: network failure (for example, the router has no DHCP lease).
    NetworkFailure,
    /// 4: out of resources.
    OutOfResources,
    /// 5: unsupported opcode.
    UnsupportedOpcode,
    /// Any other value.
    Unknown(u16),
}

impl From<u16> for ResultCode {
    fn from(v: u16) -> Self {
        match v {
            0 => Self::Success,
            1 => Self::UnsupportedVersion,
            2 => Self::NotAuthorized,
            3 => Self::NetworkFailure,
            4 => Self::OutOfResources,
            5 => Self::UnsupportedOpcode,
            n => Self::Unknown(n),
        }
    }
}

impl From<ResultCode> for u16 {
    fn from(c: ResultCode) -> u16 {
        match c {
            ResultCode::Success => 0,
            ResultCode::UnsupportedVersion => 1,
            ResultCode::NotAuthorized => 2,
            ResultCode::NetworkFailure => 3,
            ResultCode::OutOfResources => 4,
            ResultCode::UnsupportedOpcode => 5,
            ResultCode::Unknown(n) => n,
        }
    }
}

impl fmt::Display for ResultCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Success => "success",
            Self::UnsupportedVersion => "unsupported-version",
            Self::NotAuthorized => "not-authorized",
            Self::NetworkFailure => "network-failure",
            Self::OutOfResources => "out-of-resources",
            Self::UnsupportedOpcode => "unsupported-opcode",
            Self::Unknown(_) => "unknown",
        };
        write!(f, "{name}({})", u16::from(*self))
    }
}

/// Why a datagram is not an acceptable reply to the request it was matched against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Malformed {
    /// Shorter than the 8-byte common reply header.
    TooShort(usize),
    /// Not NAT-PMP version 0.
    BadVersion(u8),
    /// Not the request's opcode plus 128.
    WrongOpcode(u8),
    /// A success reply with the wrong length.
    BadLength(usize),
    /// A public-address reply of `0.0.0.0`.
    ZeroAddress,
    /// A public address no router can have (see [`crate::is_plausible_external`]).
    ImplausibleAddress(Ipv4Addr),
    /// A MAP reply for a different internal port.
    InternalPortMismatch {
        /// Internal port in the reply.
        got: u16,
        /// Internal port we asked for.
        want: u16,
    },
    /// A MAP success with external port 0.
    ZeroExternalPort,
    /// A MAP success with lifetime 0 for a create or renew.
    ZeroLifetime,
    /// A reply to a delete that still carries a lifetime.
    NonZeroLifetimeOnDelete(u32),
}

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort(n) => write!(f, "too short ({n} bytes)"),
            Self::BadVersion(v) => write!(f, "version {v}, not 0"),
            Self::WrongOpcode(o) => write!(f, "unexpected opcode {o:#04x}"),
            Self::BadLength(n) => write!(f, "success reply of {n} bytes"),
            Self::ZeroAddress => f.write_str("public address 0.0.0.0"),
            Self::ImplausibleAddress(ip) => write!(f, "implausible public address {ip}"),
            Self::InternalPortMismatch { got, want } => {
                write!(f, "internal port {got}, expected {want}")
            }
            Self::ZeroExternalPort => f.write_str("external port 0"),
            Self::ZeroLifetime => f.write_str("lifetime 0 on a create"),
            Self::NonZeroLifetimeOnDelete(l) => write!(f, "lifetime {l} on a delete"),
        }
    }
}

/// A reply that is not a success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReplyError {
    /// A well-formed reply with a nonzero result code.
    #[error("NAT-PMP {code} (epoch {epoch})")]
    Router {
        /// The result code.
        code: ResultCode,
        /// Seconds since the router's start of epoch.
        epoch: u32,
    },
    /// A header-only error has no internal port and cannot identify a MAP request.
    #[error("NAT-PMP {code} without an internal port (epoch {epoch})")]
    Unmatched {
        /// Result code.
        code: ResultCode,
        /// Router epoch.
        epoch: u32,
    },
    /// Not an acceptable reply.
    #[error("malformed NAT-PMP reply: {0}")]
    Malformed(Malformed),
}

impl From<Malformed> for ReplyError {
    fn from(m: Malformed) -> Self {
        Self::Malformed(m)
    }
}

/// A successful public-address reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicAddrReply {
    /// Seconds since the router's start of epoch.
    pub epoch: u32,
    /// The router's public address; never `0.0.0.0`.
    pub public_ip: Ipv4Addr,
}

/// A successful MAP reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapReply {
    /// Seconds since the router's start of epoch.
    pub epoch: u32,
    /// The internal port; always the one requested.
    pub internal: u16,
    /// The assigned external port. Nonzero for a create; 0 is allowed in a delete reply.
    pub external: u16,
    /// Granted lifetime in seconds. Nonzero for a create; 0 for a delete.
    pub lifetime: u32,
}

/// Whether a MAP request creates/renews a mapping or deletes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapKind {
    /// Create or renew (lifetime > 0).
    Map,
    /// Delete (lifetime 0).
    Delete,
}

/// The public-address request: `{version 0, opcode 0}`.
pub const fn public_address_request() -> [u8; 2] {
    [VERSION, OP_PUBLIC_ADDR]
}

/// A MAP-UDP request for `internal`, suggesting `suggested_external` (0 for none), with a
/// nonzero lifetime.
pub fn map_request(
    internal: NonZeroU16,
    suggested_external: u16,
    lifetime: NonZeroU32,
) -> [u8; MAP_REQUEST_LEN] {
    build_map(internal.get(), suggested_external, lifetime.get())
}

/// A delete request for `internal`: lifetime 0 and suggested external port 0, as RFC 6886 §3.4
/// requires. (Go sends the current external port instead; routers ignore it.)
pub fn delete_request(internal: NonZeroU16) -> [u8; MAP_REQUEST_LEN] {
    build_map(internal.get(), 0, 0)
}

fn build_map(internal: u16, suggested_external: u16, lifetime: u32) -> [u8; MAP_REQUEST_LEN] {
    let mut p = [0u8; MAP_REQUEST_LEN];
    p[0] = VERSION;
    p[1] = OP_MAP_UDP;
    p[4..6].copy_from_slice(&internal.to_be_bytes());
    p[6..8].copy_from_slice(&suggested_external.to_be_bytes());
    p[8..12].copy_from_slice(&lifetime.to_be_bytes());
    p
}

/// Read a big-endian u16 at `at`; the caller has checked the length.
fn be16(b: &[u8], at: usize) -> u16 {
    match b.get(at..at + 2) {
        Some(&[x, y]) => u16::from_be_bytes([x, y]),
        _ => 0,
    }
}

/// Read a big-endian u32 at `at`; the caller has checked the length.
fn be32(b: &[u8], at: usize) -> u32 {
    match b.get(at..at + 4) {
        Some(&[w, x, y, z]) => u32::from_be_bytes([w, x, y, z]),
        _ => 0,
    }
}

/// Check the common header against `op` and return the epoch, or the router's error.
fn header(b: &[u8], op: u8) -> Result<u32, ReplyError> {
    if b.len() < MIN_REPLY_LEN {
        return Err(Malformed::TooShort(b.len()).into());
    }
    if b[0] != VERSION {
        return Err(Malformed::BadVersion(b[0]).into());
    }
    if b[1] != op | OP_REPLY {
        return Err(Malformed::WrongOpcode(b[1]).into());
    }
    let code = ResultCode::from(be16(b, 2));
    let epoch = be32(b, 4);
    if code != ResultCode::Success {
        return Err(ReplyError::Router { code, epoch });
    }
    Ok(epoch)
}

/// The result code and epoch of any well-formed NAT-PMP reply header (version 0, reply bit set,
/// at least 8 bytes), whatever its opcode. Used to recognise a NAT-PMP server's "unsupported
/// version" answer to a PCP request (RFC 6887 Appendix A).
pub fn reply_result(b: &[u8]) -> Option<(ResultCode, u32)> {
    match b {
        [VERSION, op, ..] if b.len() >= MIN_REPLY_LEN && op & OP_REPLY != 0 => {
            Some((ResultCode::from(be16(b, 2)), be32(b, 4)))
        }
        _ => None,
    }
}

/// Parse a reply to [`public_address_request`].
pub fn parse_public_addr_reply(b: &[u8]) -> Result<PublicAddrReply, ReplyError> {
    let epoch = match header(b, OP_PUBLIC_ADDR) {
        Err(e @ ReplyError::Router { .. })
            if matches!(b.len(), MIN_REPLY_LEN | PUBLIC_ADDR_REPLY_LEN) =>
        {
            return Err(e);
        }
        Err(ReplyError::Router { .. }) => return Err(Malformed::BadLength(b.len()).into()),
        other => other?,
    };
    if b.len() != PUBLIC_ADDR_REPLY_LEN {
        return Err(Malformed::BadLength(b.len()).into());
    }
    let public_ip = Ipv4Addr::from(be32(b, 8));
    if public_ip.is_unspecified() {
        return Err(Malformed::ZeroAddress.into());
    }
    if !crate::is_plausible_external(public_ip) {
        return Err(Malformed::ImplausibleAddress(public_ip).into());
    }
    Ok(PublicAddrReply { epoch, public_ip })
}

/// Parse a reply to a MAP request for `internal` (see [`map_request`] and [`delete_request`]).
pub fn parse_map_reply(
    b: &[u8],
    internal: NonZeroU16,
    kind: MapKind,
) -> Result<MapReply, ReplyError> {
    let (epoch, refusal) = match header(b, OP_MAP_UDP) {
        Ok(epoch) => (epoch, None),
        Err(ReplyError::Router { code, epoch }) => (epoch, Some(code)),
        Err(e) => return Err(e),
    };
    if b.len() == MIN_REPLY_LEN
        && let Some(code) = refusal
    {
        return Err(ReplyError::Unmatched { code, epoch });
    }
    if b.len() != MAP_REPLY_LEN {
        return Err(Malformed::BadLength(b.len()).into());
    }
    let reply = MapReply {
        epoch,
        internal: be16(b, 8),
        external: be16(b, 10),
        lifetime: be32(b, 12),
    };
    if reply.internal != internal.get() {
        return Err(Malformed::InternalPortMismatch {
            got: reply.internal,
            want: internal.get(),
        }
        .into());
    }
    if let Some(code) = refusal {
        return Err(ReplyError::Router { code, epoch });
    }
    match kind {
        MapKind::Map if reply.lifetime == 0 => Err(Malformed::ZeroLifetime.into()),
        MapKind::Map if reply.external == 0 => Err(Malformed::ZeroExternalPort.into()),
        MapKind::Delete if reply.lifetime != 0 => {
            Err(Malformed::NonZeroLifetimeOnDelete(reply.lifetime).into())
        }
        _ => Ok(reply),
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const P1234: NonZeroU16 = NonZeroU16::new(1234).unwrap();
    const L7200: NonZeroU32 = NonZeroU32::new(7200).unwrap();

    fn map_reply(code: u16, epoch: u32, internal: u16, external: u16, lifetime: u32) -> Vec<u8> {
        let mut b = vec![VERSION, OP_MAP_UDP | OP_REPLY];
        b.extend_from_slice(&code.to_be_bytes());
        b.extend_from_slice(&epoch.to_be_bytes());
        b.extend_from_slice(&internal.to_be_bytes());
        b.extend_from_slice(&external.to_be_bytes());
        b.extend_from_slice(&lifetime.to_be_bytes());
        b
    }

    fn addr_reply(code: u16, epoch: u32, ip: [u8; 4]) -> Vec<u8> {
        let mut b = vec![VERSION, OP_PUBLIC_ADDR | OP_REPLY];
        b.extend_from_slice(&code.to_be_bytes());
        b.extend_from_slice(&epoch.to_be_bytes());
        b.extend_from_slice(&ip);
        b
    }

    /// Golden request bytes.
    #[test]
    fn build_golden() {
        assert_eq!(public_address_request(), [0, 0]);
        assert_eq!(
            map_request(P1234, 0, L7200),
            [0, 1, 0, 0, 0x04, 0xd2, 0, 0, 0, 0, 0x1c, 0x20]
        );
        assert_eq!(
            map_request(P1234, 41641, L7200),
            [0, 1, 0, 0, 0x04, 0xd2, 0xa2, 0xa9, 0, 0, 0x1c, 0x20]
        );
        // Delete: lifetime 0 AND suggested external port 0 (RFC 6886 §3.4).
        assert_eq!(
            delete_request(P1234),
            [0, 1, 0, 0, 0x04, 0xd2, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn public_addr_ok() {
        let r = parse_public_addr_reply(&addr_reply(0, 77, [203, 0, 113, 7])).unwrap();
        assert_eq!(r.epoch, 77);
        assert_eq!(r.public_ip, Ipv4Addr::new(203, 0, 113, 7));
    }

    /// Header and length validation.
    #[test]
    fn public_addr_rejects() {
        let good = addr_reply(0, 1, [203, 0, 113, 7]);
        let mut bad_ver = good.clone();
        bad_ver[0] = 2;
        assert_eq!(
            parse_public_addr_reply(&bad_ver),
            Err(Malformed::BadVersion(2).into())
        );
        let mut bad_op = good.clone();
        bad_op[1] = OP_MAP_UDP | OP_REPLY;
        assert_eq!(
            parse_public_addr_reply(&bad_op),
            Err(Malformed::WrongOpcode(0x81).into())
        );
        // A request echoed back (no reply bit) is not a reply.
        let mut no_reply_bit = good.clone();
        no_reply_bit[1] = OP_PUBLIC_ADDR;
        assert!(matches!(
            parse_public_addr_reply(&no_reply_bit),
            Err(ReplyError::Malformed(Malformed::WrongOpcode(0)))
        ));
        assert_eq!(
            parse_public_addr_reply(&good[..11]),
            Err(Malformed::BadLength(11).into())
        );
        let mut long = good.clone();
        long.push(0);
        assert_eq!(
            parse_public_addr_reply(&long),
            Err(Malformed::BadLength(13).into())
        );
        assert_eq!(
            parse_public_addr_reply(&good[..7]),
            Err(Malformed::TooShort(7).into())
        );
        assert_eq!(
            parse_public_addr_reply(&addr_reply(0, 1, [0, 0, 0, 0])),
            Err(Malformed::ZeroAddress.into())
        );
        for bad in [
            [127, 0, 0, 1],
            [255, 255, 255, 255],
            [224, 0, 0, 1],
            [169, 254, 0, 1],
        ] {
            assert_eq!(
                parse_public_addr_reply(&addr_reply(0, 1, bad)),
                Err(Malformed::ImplausibleAddress(bad.into()).into())
            );
        }
        // A double NAT's private or shared WAN address is reported (diagnostics), not rejected.
        for ok in [[192, 168, 0, 2], [100, 64, 0, 9]] {
            assert!(parse_public_addr_reply(&addr_reply(0, 1, ok)).is_ok());
        }
    }

    /// Result codes 1–5 and an unknown code are typed errors, never a success, even in a
    /// short 8-byte reply.
    #[test]
    fn result_codes_are_errors() {
        for (raw, code) in [
            (1, ResultCode::UnsupportedVersion),
            (2, ResultCode::NotAuthorized),
            (3, ResultCode::NetworkFailure),
            (4, ResultCode::OutOfResources),
            (5, ResultCode::UnsupportedOpcode),
            (99, ResultCode::Unknown(99)),
        ] {
            let full = addr_reply(raw, 9, [203, 0, 113, 7]);
            let want = ReplyError::Router { code, epoch: 9 };
            assert_eq!(parse_public_addr_reply(&full), Err(want));
            assert_eq!(parse_public_addr_reply(&full[..8]), Err(want));
            let m = map_reply(raw, 9, 1234, 0, 0);
            assert_eq!(parse_map_reply(&m, P1234, MapKind::Map), Err(want));
            assert_eq!(
                parse_map_reply(&m[..8], P1234, MapKind::Map),
                Err(ReplyError::Unmatched { code, epoch: 9 })
            );
            assert_eq!(u16::from(code), raw);
        }
    }

    #[test]
    fn map_ok_and_renew_with_new_port() {
        let r = parse_map_reply(&map_reply(0, 5, 1234, 4242, 3600), P1234, MapKind::Map).unwrap();
        assert_eq!(
            r,
            MapReply {
                epoch: 5,
                internal: 1234,
                external: 4242,
                lifetime: 3600
            }
        );
    }

    /// MAP-specific rejections.
    #[test]
    fn map_rejects() {
        assert_eq!(
            parse_map_reply(&map_reply(0, 5, 1235, 4242, 7200), P1234, MapKind::Map),
            Err(Malformed::InternalPortMismatch {
                got: 1235,
                want: 1234
            }
            .into())
        );
        assert_eq!(
            parse_map_reply(&map_reply(0, 5, 1234, 0, 7200), P1234, MapKind::Map),
            Err(Malformed::ZeroExternalPort.into())
        );
        // Lifetime 0 on a create is a failure.
        assert_eq!(
            parse_map_reply(&map_reply(0, 5, 1234, 4242, 0), P1234, MapKind::Map),
            Err(Malformed::ZeroLifetime.into())
        );
        let good = map_reply(0, 5, 1234, 4242, 7200);
        assert_eq!(
            parse_map_reply(&good[..15], P1234, MapKind::Map),
            Err(Malformed::BadLength(15).into())
        );
        // A public-address reply is not a MAP reply.
        assert_eq!(
            parse_map_reply(&addr_reply(0, 1, [203, 0, 113, 7]), P1234, MapKind::Map),
            Err(Malformed::WrongOpcode(0x80).into())
        );
    }

    #[test]
    fn delete_reply() {
        let r = parse_map_reply(&map_reply(0, 5, 1234, 0, 0), P1234, MapKind::Delete).unwrap();
        assert_eq!((r.external, r.lifetime), (0, 0));
        assert_eq!(
            parse_map_reply(&map_reply(0, 5, 1234, 4242, 60), P1234, MapKind::Delete),
            Err(Malformed::NonZeroLifetimeOnDelete(60).into())
        );
    }

    #[test]
    fn reply_result_any_opcode() {
        assert_eq!(
            reply_result(&[0, 0x81, 0, 1, 0, 0, 0, 9]),
            Some((ResultCode::UnsupportedVersion, 9))
        );
        assert_eq!(reply_result(&[0, 0x01, 0, 1, 0, 0, 0, 9]), None);
        assert_eq!(reply_result(&[0, 0x81, 0, 1]), None);
        assert_eq!(reply_result(&[2, 0x81, 0, 1, 0, 0, 0, 9]), None);
    }

    /// Lifetimes 0, 1 and `u32::MAX` parse without panicking.
    #[test]
    fn extreme_lifetimes() {
        for l in [1, u32::MAX] {
            let r = parse_map_reply(&map_reply(0, u32::MAX, 1234, 1, l), P1234, MapKind::Map);
            assert_eq!(r.unwrap().lifetime, l);
        }
        assert!(parse_map_reply(&map_reply(0, 0, 1234, 1, 0), P1234, MapKind::Delete).is_ok());
    }

    proptest! {
        #[test]
        fn parsers_never_panic(b in proptest::collection::vec(any::<u8>(), 0..64), port in 1u16..) {
            let port = NonZeroU16::new(port).unwrap();
            let _ = parse_public_addr_reply(&b);
            let _ = parse_map_reply(&b, port, MapKind::Map);
            let _ = parse_map_reply(&b, port, MapKind::Delete);
        }

        #[test]
        fn map_reply_roundtrip(
            epoch in any::<u32>(), internal in 1u16.., external in 1u16.., lifetime in 1u32..
        ) {
            let b = map_reply(0, epoch, internal, external, lifetime);
            let r = parse_map_reply(&b, NonZeroU16::new(internal).unwrap(), MapKind::Map).unwrap();
            prop_assert_eq!(r, MapReply { epoch, internal, external, lifetime });
        }

        #[test]
        fn map_request_layout(internal in 1u16.., ext in any::<u16>(), lifetime in 1u32..) {
            let p = map_request(
                NonZeroU16::new(internal).unwrap(), ext, NonZeroU32::new(lifetime).unwrap());
            prop_assert_eq!(&p[..4], &[0, 1, 0, 0]);
            prop_assert_eq!(be16(&p, 4), internal);
            prop_assert_eq!(be16(&p, 6), ext);
            prop_assert_eq!(be32(&p, 8), lifetime);
        }
    }
    #[test]
    fn public_error_lengths_are_validated() {
        let packet = addr_reply(2, 1, [203, 0, 113, 7]);
        for len in [9, 11, 13] {
            let mut error = packet.clone();
            error.resize(len, 0);
            assert!(matches!(
                parse_public_addr_reply(&error),
                Err(ReplyError::Malformed(Malformed::BadLength(_)))
            ));
        }
    }
}
