//! The L4 header bytes Go's `net/packet.Parsed` keeps beyond the four-tuple, and the constants its
//! reply predicates read them against.

/// The L4 header detail a [`PacketInfo`](crate::PacketInfo) carries beyond `{src, dst, ip_proto,
/// port}`: Go `packet.Parsed`'s `TCPFlags` field and the ICMP type/code bytes behind its
/// `IsEchoResponse`/`IsError` methods.
///
/// Go's filter is handed the whole `*packet.Parsed` and reads these off it directly. This fork's
/// [`Filter`](crate::Filter) is handed a `PacketInfo`, so the same bytes have to travel in the
/// struct — the reply carve-outs of `runIn4`/`runIn6` are otherwise not merely missing but
/// inexpressible.
///
/// Nothing in a [`Rule`](crate::Rule) matches on this. It exists solely for the three accepts Go
/// applies *before* any rule is consulted.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub enum L4Header {
    /// No L4 header was decoded for this packet.
    ///
    /// This is the fail-closed default, and it is a different statement from Go's zero-valued
    /// `Parsed`: Go always reaches its filter with the header parsed (`decode4`/`decode6` demote a
    /// packet too short to hold one to `ipproto.Unknown`, which `pre()` drops), whereas a caller
    /// here can legitimately hold a packet whose L4 header it never read — a later IP fragment, or
    /// a first IPv4 fragment, whose transport bytes are simply not present. Every reply predicate
    /// answers `false` for this variant, so such a packet takes the ordinary rule match.
    #[default]
    Unknown,
    /// TCP: the flags byte, Go `Parsed.TCPFlags`, read from `sub[13]` by both `decode4` and
    /// `decode6`.
    Tcp {
        /// Go `packet.TCPFlag`, one bit each for FIN, SYN, RST, PSH, ACK, URG, ECN-Echo and CWR,
        /// from bit 0 upwards. Stored raw rather than as booleans so it stays the byte upstream
        /// stores.
        flags: u8,
    },
    /// ICMP or ICMPv6: the type and code bytes. Which of the two protocols they are to be read as
    /// is decided by [`PacketInfo::ip_proto`](crate::PacketInfo::ip_proto), exactly as Go's
    /// `IsEchoResponse`/`IsError` switch on `q.IPProto` before reading the same two bytes.
    ///
    /// Constructing this asserts that at least 8 bytes of ICMP header were present — Go guards
    /// every one of those reads with `len(q.b) >= q.subofs+8`, and a shorter message is therefore
    /// never a "response" to upstream either. A caller that has fewer bytes must use
    /// [`Unknown`](Self::Unknown), which leaves the packet to the IPs-only rule match Go's `else
    /// if f.matches4.matchIPsOnly(q, …)` arm gives it.
    Icmp {
        /// Go `ICMP4Type`/`ICMP6Type` — `q.b[q.subofs]`.
        icmp_type: u8,
        /// Go `ICMP4Code`/`ICMP6Code` — `q.b[q.subofs+1]`.
        icmp_code: u8,
    },
}

/// Go `packet.TCPSyn`.
pub(crate) const TCP_SYN: u8 = 0x02;
/// Go `packet.TCPAck`.
pub(crate) const TCP_ACK: u8 = 0x10;
/// Go `packet.TCPSynAck`, the mask `IsTCPSyn` applies before comparing against [`TCP_SYN`].
pub(crate) const TCP_SYN_ACK: u8 = TCP_SYN | TCP_ACK;

/// Go `packet.ICMP4NoCode` and `packet.ICMP6NoCode`, both 0.
pub(crate) const ICMP_NO_CODE: u8 = 0;

/// Go `packet.ICMP4EchoReply`.
pub(crate) const ICMP4_ECHO_REPLY: u8 = 0x00;
/// Go `packet.ICMP4Unreachable`.
pub(crate) const ICMP4_UNREACHABLE: u8 = 0x03;
/// Go `packet.ICMP4TimeExceeded`.
pub(crate) const ICMP4_TIME_EXCEEDED: u8 = 0x0b;
/// Go `packet.ICMP4ParamProblem`.
///
/// Upstream's value, ported as it stands. IANA's Parameter Problem is type 12 (`0x0c`) and 18
/// (`0x12`) is Address Mask Reply, so upstream's constant names one message and holds another.
/// Correcting it here would be a divergence, and in the *permissive* direction for type 12 traffic
/// — an ICMP Parameter Problem this node has no rule for would be admitted where upstream drops it.
/// Whatever upstream admits, this admits.
pub(crate) const ICMP4_PARAM_PROBLEM: u8 = 0x12;

/// Go `packet.ICMP6Unreachable`.
pub(crate) const ICMP6_UNREACHABLE: u8 = 1;
/// Go `packet.ICMP6PacketTooBig`.
pub(crate) const ICMP6_PACKET_TOO_BIG: u8 = 2;
/// Go `packet.ICMP6TimeExceeded`.
pub(crate) const ICMP6_TIME_EXCEEDED: u8 = 3;
/// Go `packet.ICMP6ParamProblem`.
pub(crate) const ICMP6_PARAM_PROBLEM: u8 = 4;
/// Go `packet.ICMP6EchoReply`.
pub(crate) const ICMP6_ECHO_REPLY: u8 = 129;
