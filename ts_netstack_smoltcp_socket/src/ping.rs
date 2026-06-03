//! Overlay ICMPv4 echo (`ping`) over a netstack [`Channel`][netcore::Channel].
//!
//! This is the raw-socket analogue of tsnet's `LocalClient.Ping`: it opens a raw ICMP socket
//! on the overlay netstack, emits an ICMPv4 Echo Request to a peer's tailnet IP, and waits for
//! the matching Echo Reply, returning the round-trip time.
//!
//! Anti-leak: this rides the overlay netstack only (via the [`CreateSocket`] channel); it never
//! touches a host socket. ICMPv4 only — IPv6 is rejected (IPv6-off posture).

use alloc::vec;
use core::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use netcore::smoltcp::{
    phy::ChecksumCapabilities,
    wire::{IPV4_HEADER_LEN, Icmpv4Packet, Icmpv4Repr, IpProtocol, Ipv4Packet, Ipv4Repr},
};

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

const PING_PAYLOAD: &[u8] = b"ts_netstack_smoltcp ping";

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

    // A fixed ident/seq is fine: the raw socket intercepts all ICMPv4, but we only match on our
    // own ident+seq, so a single in-flight echo is unambiguous.
    let ident: u16 = 0x7473;
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
