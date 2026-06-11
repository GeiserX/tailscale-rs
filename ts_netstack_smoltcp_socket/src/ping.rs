//! Overlay ICMPv4 echo (`ping`) over a netstack [`Channel`][netcore::Channel].
//!
//! This is the raw-socket analogue of tsnet's `LocalClient.Ping`: it opens a raw ICMP socket
//! on the overlay netstack, emits an ICMPv4 Echo Request to a peer's tailnet IP, and waits for
//! the matching Echo Reply, returning the round-trip time.
//!
//! Anti-leak: this rides the overlay netstack only (via the [`CreateSocket`] channel); it never
//! touches a host socket. ICMPv4 only — IPv6 is rejected (IPv6-off posture).

// The echo-build/match helpers (and their smoltcp wire imports + `Ipv4Addr` + `alloc::vec`) are used
// only by the `tokio`-gated `ping` entry point and the tests; `IpAddr`/`Duration`/`CreateSocket`
// only by `ping` itself. Gating the imports to match their users keeps the default (no-`tokio`) lib
// build free of unused-import warnings under `-D warnings`.
#[cfg(any(feature = "tokio", test))]
use alloc::vec;
#[cfg(any(feature = "tokio", test))]
use core::net::Ipv4Addr;
#[cfg(feature = "tokio")]
use core::{net::IpAddr, time::Duration};

#[cfg(any(feature = "tokio", test))]
use netcore::smoltcp::{
    phy::ChecksumCapabilities,
    wire::{IPV4_HEADER_LEN, Icmpv4Packet, Icmpv4Repr, IpProtocol, Ipv4Packet, Ipv4Repr},
};

#[cfg(feature = "tokio")]
use crate::CreateSocket;

/// Errors returned by [`ping`].
#[derive(Debug)]
pub enum PingError {
    /// No matching Echo Reply arrived before the timeout elapsed.
    Timeout,
    /// The destination was an IPv6 address; only ICMPv4 is supported.
    Ipv6Unsupported,
    /// An underlying netstack error occurred.
    Net(netcore::Error),
}

impl core::fmt::Display for PingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Timeout => f.write_str("ping timed out"),
            Self::Ipv6Unsupported => f.write_str("ICMPv6 ping is unsupported (IPv6 is off)"),
            Self::Net(e) => write!(f, "netstack error: {e}"),
        }
    }
}

impl core::error::Error for PingError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Net(e) => Some(e),
            _ => None,
        }
    }
}

impl From<netcore::Error> for PingError {
    fn from(e: netcore::Error) -> Self {
        Self::Net(e)
    }
}

// Only the `tokio`-gated `ping` path (and its tests) build/scan ICMP echo packets; gate these so
// the lib builds clean without the `tokio` feature (they'd otherwise be dead code under `-D warnings`).
#[cfg(any(feature = "tokio", test))]
const PING_PAYLOAD: &[u8] = b"ts_netstack_smoltcp ping";

/// Per-call counter mixed into the ICMP `ident`.
///
/// The raw ICMP socket each `ping` call opens intercepts *all* ICMPv4, so two concurrent calls
/// on the same netstack would otherwise share a fixed ident+seq and cross-match each other's
/// replies (resolving the wrong awaiter with the wrong RTT). To avoid same-process collisions we
/// derive a unique `ident` per call: the low byte of `std::process::id()` (non-deterministic
/// across runs, no crate dependency) combined with a monotonically incrementing `AtomicU16`. Two
/// in-flight pings in the same process get distinct idents (the counter differs), and pings from
/// different processes are unlikely to share the high byte. We do not depend on the `rand` crate
/// because it is not a dependency of this `no-std`-flavored crate (see `Cargo.toml`); the
/// `tokio`-gated `ping` path enables `std`, so `std::process::id()` is available.
#[cfg(feature = "tokio")]
static PING_IDENT_COUNTER: core::sync::atomic::AtomicU16 = core::sync::atomic::AtomicU16::new(0);

/// Produce a per-call ICMP `ident` that does not collide with other concurrent `ping` calls in
/// this process. See [`PING_IDENT_COUNTER`] for the rationale and source of (weak) randomness.
#[cfg(feature = "tokio")]
fn next_ident() -> u16 {
    let counter = PING_IDENT_COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    // High byte: process-randomized seed; low byte: per-call counter. The counter guarantees
    // distinct idents for concurrent in-process calls regardless of the seed.
    let seed = (std::process::id() as u16) & 0xFF00;
    seed ^ counter
}

/// Send an ICMPv4 Echo Request from `src` to `dst` over the overlay netstack `chan` and wait
/// for the matching Echo Reply, returning the round-trip time.
///
/// `src` must be a tailnet IPv4 address owned by this netstack (the raw send path emits a full
/// IPv4 packet, so the source address goes on the wire verbatim). `dst` must be IPv4; an IPv6
/// `dst` returns [`PingError::Ipv6Unsupported`].
///
/// Non-matching ICMP traffic (wrong ident/seq, or non-EchoReply messages) is ignored. If no
/// reply arrives within `timeout`, returns [`PingError::Timeout`].
#[cfg(feature = "tokio")]
pub async fn ping<C: CreateSocket + Sync>(
    chan: &C,
    src: Ipv4Addr,
    dst: IpAddr,
    timeout: Duration,
) -> Result<Duration, PingError> {
    let dst = match dst {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => return Err(PingError::Ipv6Unsupported),
    };

    // The raw socket intercepts *all* ICMPv4, so a fixed ident/seq would cross-match concurrent
    // pings on the same netstack. Use a per-call unique ident (see `next_ident`) and match strictly
    // on both ident and seq, so concurrent calls never resolve each other's replies.
    let ident: u16 = next_ident();
    let seq_no: u16 = 1;

    let sock = chan.raw_open(true, IpProtocol::Icmp).await?;

    let request = build_echo_request(src, dst, ident, seq_no, PING_PAYLOAD);

    let start = tokio::time::Instant::now();
    sock.send(&request).await?;

    let deadline = start + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(PingError::Timeout);
        }

        let recv = tokio::time::timeout(remaining, sock.recv_bytes()).await;
        let bytes = match recv {
            Err(_elapsed) => return Err(PingError::Timeout),
            Ok(Ok(b)) => b,
            Ok(Err(e)) => return Err(PingError::Net(e)),
        };

        if matches_reply(&bytes, src, dst, ident, seq_no) {
            return Ok(start.elapsed());
        }
        // Not our reply (or not an EchoReply) -- keep waiting.
    }
}

/// Build a complete ICMPv4 Echo Request IPv4 datagram (IP header + ICMP message).
///
/// The raw socket send path parses the buffer as a full IPv4 packet and fills the IPv4 header
/// checksum on dispatch, but the ICMP checksum and the rest of the IPv4 header must be valid
/// here.
#[cfg(any(feature = "tokio", test))]
fn build_echo_request(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    ident: u16,
    seq_no: u16,
    payload: &[u8],
) -> vec::Vec<u8> {
    let checksum_caps = ChecksumCapabilities::default();

    let icmp_repr = Icmpv4Repr::EchoRequest {
        ident,
        seq_no,
        data: payload,
    };

    let ipv4_repr = Ipv4Repr {
        src_addr: src,
        dst_addr: dst,
        next_header: IpProtocol::Icmp,
        payload_len: icmp_repr.buffer_len(),
        hop_limit: 64,
    };

    let total = IPV4_HEADER_LEN + icmp_repr.buffer_len();
    let mut buf = vec![0u8; total];

    {
        let mut ip_packet = Ipv4Packet::new_unchecked(&mut buf[..]);
        ipv4_repr.emit(&mut ip_packet, &checksum_caps);
    }

    {
        let mut icmp_packet = Icmpv4Packet::new_unchecked(&mut buf[IPV4_HEADER_LEN..]);
        icmp_repr.emit(&mut icmp_packet, &checksum_caps);
    }

    buf
}

/// Parse a received raw IPv4 datagram and check whether it is the Echo Reply we are waiting for.
#[cfg(any(feature = "tokio", test))]
fn matches_reply(
    bytes: &[u8],
    expect_src: Ipv4Addr,
    expect_dst: Ipv4Addr,
    ident: u16,
    seq_no: u16,
) -> bool {
    let checksum_caps = ChecksumCapabilities::default();

    let Ok(ip_packet) = Ipv4Packet::new_checked(bytes) else {
        return false;
    };
    let Ok(ipv4_repr) = Ipv4Repr::parse(&ip_packet, &checksum_caps) else {
        return false;
    };
    if ipv4_repr.next_header != IpProtocol::Icmp {
        return false;
    }
    // Reply travels dst -> src.
    if ipv4_repr.src_addr != expect_dst || ipv4_repr.dst_addr != expect_src {
        return false;
    }

    let Ok(icmp_packet) = Icmpv4Packet::new_checked(ip_packet.payload()) else {
        return false;
    };
    let Ok(icmp_repr) = Icmpv4Repr::parse(&icmp_packet, &checksum_caps) else {
        return false;
    };

    matches!(
        icmp_repr,
        Icmpv4Repr::EchoReply { ident: i, seq_no: s, .. } if i == ident && s == seq_no
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
    const DST: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);

    /// Build a full IPv4 Echo *Reply* datagram travelling `from` -> `to` with the given
    /// ident/seq, mirroring what a peer responder emits.
    fn build_echo_reply(from: Ipv4Addr, to: Ipv4Addr, ident: u16, seq_no: u16) -> vec::Vec<u8> {
        let checksum_caps = ChecksumCapabilities::default();
        let icmp_repr = Icmpv4Repr::EchoReply {
            ident,
            seq_no,
            data: PING_PAYLOAD,
        };
        let ipv4_repr = Ipv4Repr {
            src_addr: from,
            dst_addr: to,
            next_header: IpProtocol::Icmp,
            payload_len: icmp_repr.buffer_len(),
            hop_limit: 64,
        };
        let mut buf = vec![0u8; IPV4_HEADER_LEN + icmp_repr.buffer_len()];
        {
            let mut p = Ipv4Packet::new_unchecked(&mut buf[..]);
            ipv4_repr.emit(&mut p, &checksum_caps);
        }
        {
            let mut p = Icmpv4Packet::new_unchecked(&mut buf[IPV4_HEADER_LEN..]);
            icmp_repr.emit(&mut p, &checksum_caps);
        }
        buf
    }

    #[test]
    fn matches_reply_accepts_matching_ident_and_seq() {
        let reply = build_echo_reply(DST, SRC, 0xABCD, 7);
        assert!(matches_reply(&reply, SRC, DST, 0xABCD, 7));
    }

    #[test]
    fn matches_reply_rejects_foreign_ident() {
        // A concurrent ping's reply: correct addressing and seq, but a different ident. It must
        // NOT satisfy this call (otherwise concurrent pings cross-match).
        let foreign = build_echo_reply(DST, SRC, 0x1111, 7);
        assert!(!matches_reply(&foreign, SRC, DST, 0xABCD, 7));
    }

    #[test]
    fn matches_reply_rejects_foreign_seq() {
        let foreign = build_echo_reply(DST, SRC, 0xABCD, 99);
        assert!(!matches_reply(&foreign, SRC, DST, 0xABCD, 7));
    }

    #[test]
    fn matches_reply_rejects_non_echo_reply() {
        // An Echo *Request* with our exact ident/seq must not be accepted as our reply.
        let request = build_echo_request(DST, SRC, 0xABCD, 7, PING_PAYLOAD);
        assert!(!matches_reply(&request, SRC, DST, 0xABCD, 7));
    }

    #[cfg(feature = "tokio")]
    #[test]
    fn next_ident_is_unique_for_concurrent_calls() {
        // Distinct calls get distinct idents (the per-call counter differs), so concurrent pings
        // never share an ident and thus never cross-match.
        let a = next_ident();
        let b = next_ident();
        let c = next_ident();
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }
}
