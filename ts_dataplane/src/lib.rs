#![doc = include_str!("../README.md")]

use std::{collections::HashMap, sync::Arc, time::Instant};

use ts_bart::RoutingTable;
use ts_overlay_router as or;
use ts_packet::PacketMut;
use ts_packetfilter::{FilterExt, IpProto};
use ts_time::{Handle, Scheduler};
use ts_transport::{OverlayTransportId, PeerId, UnderlayTransportId};
use ts_tunnel::{Endpoint, NodeKeyPair};
use ts_underlay_router as ur;

pub mod async_tokio;

mod flowtrack;

/// The single link-local destination Go's filter `pre()` exempts from the link-local drop: the
/// cloud-metadata address `169.254.169.254` (Go `isAllowedLinkLocal`).
const ALLOWED_LINK_LOCAL_V4: std::net::Ipv4Addr = std::net::Ipv4Addr::new(169, 254, 169, 254);

/// Whether an inbound packet to destination `dst` must be dropped BEFORE consulting the ACL rules,
/// mirroring Go's filter `pre()`: drop multicast destinations (`ReasonMulticast`) and link-local
/// unicast destinations that are not the allowlisted cloud-metadata address (`ReasonLinkLocalUnicast`).
/// Returning `true` means drop. This runs ahead of `can_access` so a permissive ACL cannot admit the
/// multicast / link-local traffic Go rejects unconditionally.
///
/// Go's `isAllowedLinkLocal` is `dst == gcpDNSAddr || any(LinkLocalAllowHooks)`; only the static
/// `gcpDNSAddr` arm is modeled here. The dynamic `LinkLocalAllowHooks` slice is empty in a plain
/// engine/tsnet embedding (its only upstream producer is the GCP metadata path), so the omission is
/// behaviorally equivalent for this fork; a feature that needs a dynamic link-local allowlist would
/// have to extend this. Like Go's `netip.Addr` predicates, an IPv4-mapped-IPv6 destination (e.g.
/// `::ffff:224.0.0.1`) matches NEITHER arm and falls through to the ACL — we deliberately do not
/// canonicalize/unmap, to stay byte-faithful to Go (see the mapped-v6 test cases).
fn drop_before_rules(dst: std::net::IpAddr) -> bool {
    if dst.is_multicast() {
        return true;
    }
    match dst {
        // IPv4 link-local is 169.254.0.0/16; allow only the cloud-metadata address (Go parity).
        std::net::IpAddr::V4(v4) => v4.is_link_local() && v4 != ALLOWED_LINK_LOCAL_V4,
        // IPv6 unicast link-local is fe80::/10. (`Ipv6Addr::is_unicast_link_local` is unstable, so
        // test the prefix directly.) This fork is IPv4-only by default, but match Go for any v6.
        std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// IPv4 fragment state read from the base header (Go `net/packet.decode4` reads `b[6:8]`): the
/// fragment offset in 8-byte blocks and the more-fragments flag. A non-first fragment carries no L4
/// header, so it needs its own verdict path rather than the (always-port-0) ACL match.
#[derive(Debug, Clone, Copy)]
struct Ipv4Fragment {
    /// Fragment offset in 8-byte blocks (the 13-bit IPv4 field), 0 for the first/only fragment.
    offset_blocks: u16,
    /// The "more fragments" (MF) flag.
    more_fragments: bool,
}

/// Minimum fragment offset (in 8-byte blocks) Go permits for a non-first fragment — Go
/// `net/packet.minFragBlks = (60 + 20) / 8 = 10` (max IPv4 header + a basic TCP header). A later
/// fragment starting before this could overlap a transport header (the RFC 1858 overlapping-fragment
/// evasion), so Go demotes it to `unknown` and drops it; only fragments at or beyond this offset are
/// allowed to "slide through".
///
/// Upstream reuses this one bound for IPv6 too (Go `net/packet` `26b2ed0a6` documents the reuse):
/// it is sized for IPv4 and is therefore *conservative* for IPv6, whose fragments carry no
/// per-fragment IP header — so on the v6 side it only ever rejects more later fragments as
/// `unknown`, never fewer. Keep the single constant for both, exactly as Go does.
const MIN_FRAG_BLKS: u16 = (60 + 20) / 8;

/// Minimum IPv4 base header length (Go `net/packet.ip4HeaderLength`). A buffer shorter than this
/// is not a decodable IPv4 packet at all (Go `decode4` returns `unknown`).
const IP4_HEADER_LEN: usize = 20;

/// Fixed IPv6 base header length (Go `net/packet.ip6HeaderLength`).
const IP6_HEADER_LEN: usize = 40;

/// IANA protocol number of the IPv6 Fragment extension header, "IPv6-Frag" (Go
/// `net/packet.ip6FragHeader`). It appears as the **base** header's Next Header on a
/// source-fragmented IPv6 packet, and is distinct from Go's internal `ipproto.Fragment` sentinel
/// (0xff), which marks a non-first fragment whose sub-protocol header is not present.
const IP6_FRAG_HEADER: u8 = 44;

/// Go's `ipproto.Unknown` (0). Go's decoders assign it to every packet they refuse to classify, and
/// filter `pre()` drops it — `if q.IPProto == ipproto.Unknown { return Drop }` — before the ACL can
/// see the packet. It is also the real IANA number of the IPv6 Hop-by-Hop Options extension header,
/// which is why an IPv6 packet that leads with Hop-by-Hop is dropped by upstream: `decode6` reads
/// the base header's Next Header byte straight into `q.IPProto`, and 0 *is* "unknown".
const IPPROTO_UNKNOWN: IpProto = IpProto::new(0);

/// TCP's IP protocol number as a single byte, for the one place it is written onto the wire rather
/// than matched against: the `Proto` field of a TSMP rejected-connection message, which is a byte
/// (Go `ipproto.Proto`) where this fork's [`IpProto`] is `i64`-wide.
const IPPROTO_TCP_BYTE: u8 = 6;

/// Go's internal `ipproto.Fragment` sentinel (0xff), which `decode6Fragment` assigns to a later
/// fragment. Seeing it as a real Next Header on the wire is suspicious, so Go's `decode6` switch
/// maps it back to [`IPPROTO_UNKNOWN`] (`case ipproto.Fragment: q.IPProto = unknown`) — whether it
/// arrived as the base header's Next Header or as a Fragment header's.
const IPPROTO_FRAGMENT_SENTINEL: IpProto = IpProto::new(0xff);

/// Length of the IPv6 Fragment extension header (Go `net/packet.ip6FragHeaderLength`): Next Header,
/// Reserved, a 13-bit Fragment Offset in 8-byte blocks plus two reserved bits and the
/// More-Fragments flag, then a 32-bit Identification.
const IP6_FRAG_HEADER_LEN: usize = 8;

/// Length of the SCTP common header (Go `net/packet.sctpHeaderLength`): source port, destination
/// port, verification tag, checksum. Go's `decode4`/`decode6` refuse an SCTP packet shorter than
/// this rather than guess at its ports.
const SCTP_HEADER_LEN: usize = 12;

/// How an IPv6 packet whose base header's Next Header is the Fragment extension header classifies —
/// the port of Go `net/packet.Parsed.decode6Fragment` plus the sub-protocol switch `decode6` runs
/// when it reports `continueDecode` (upstream `4c4ec3d46`, clarified by `26b2ed0a6`).
///
/// This is the IPv6 half of the RFC 1858 fragment rules [`Ipv4Fragment`] already carries. It only
/// matters on the opt-in `Config::enable_ipv6` path — the tailnet is IPv4-only by default — but
/// without it a source-fragmented IPv6 datagram reaches the ACL with no sub-protocol and port 0,
/// so an allow-all rule admits the very low-offset fragments upstream drops, and a port-scoped rule
/// blackholes the later fragments upstream passes through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ipv6Fragment {
    /// Go's `unknown`, which filter `pre()` drops outright: a Fragment header truncated by the
    /// packet, a *first* fragment too short to hold its own transport header, a later fragment at
    /// an offset small enough to overlap that transport header on reassembly (RFC 1858), the
    /// on-the-wire use of Go's internal `ipproto.Fragment` sentinel, or a Fragment header reached
    /// through a chained extension header rather than as the base header's immediate Next Header
    /// ([`fragment_header_is_chained`]).
    Unknown,
    /// Go's `ipproto.Fragment`: a later fragment at a safe offset. It carries no sub-protocol
    /// header, so there is nothing for a rule to match on and filter `pre()` passes it through
    /// ahead of the ACL — statelessly, exactly as for IPv4. RFC 8200 §4.5 requires the receiver to
    /// reassemble, and its kernel drops the pieces if the head fragment never arrives.
    Later,
    /// Go's `continueDecode == true`: the first fragment. `decode6` steps over the 8-byte Fragment
    /// header and parses the real sub-protocol's header, so the ACL matches this datagram on the
    /// same rule it would match unfragmented.
    First {
        /// The Fragment header's Next Header — the real sub-protocol (Go `q.IPProto = nextHdr`).
        proto: IpProto,
        /// The source port read from that sub-protocol's header, 0 for a protocol Go does not
        /// port-match (Go `withPort(q.Src, ...)`). Only the reverse-flow cache
        /// ([`flowtrack::FlowCache`]) reads it — the ACL matches on the destination port alone —
        /// but Go's `flowtrack.Tuple` keys on both, so both have to be carried.
        src_port: u16,
        /// The destination port read from that sub-protocol's header, 0 for a protocol Go does not
        /// port-match (Go `withPort(q.Dst, ...)`).
        dst_port: u16,
        /// The rest of what Go's `decode6` reads out of that same sub-protocol header: the TCP
        /// flags byte (`q.TCPFlags = TCPFlag(sub[13])`) or the ICMPv6 type/code. The inbound
        /// filter's reply carve-outs consult it, so a first fragment carrying the SYN-ACK for this
        /// node's own connection is admitted on exactly the terms an unfragmented one is.
        l4: ts_packetfilter::L4Header,
    },
}

/// Classify a whole IPv6 packet `b` whose base header's Next Header is [`IP6_FRAG_HEADER`], as Go
/// `net/packet.Parsed.decode6` does when it dispatches to `decode6Fragment`.
///
/// Callers must have already checked that immediate Next Header byte: Go parses the Fragment header
/// **only** as the base header's immediate next header (upstream `26b2ed0a6` added a test locking
/// that scoping in). No other extension header, and no IPSec AH/ESP header, is parsed here either —
/// same as Go. A Fragment header reached through a chained extension header is *not* this
/// function's business; it is [`fragment_header_is_chained`]'s, which classifies it
/// [`Ipv6Fragment::Unknown`] so it is dropped.
fn decode6_fragment(b: &[u8]) -> Ipv6Fragment {
    // Go `q.length = BE16(b[4:6]) + ip6HeaderLength; if len(b) < q.length` — a packet cut off before
    // its declared payload is `unknown`.
    if b.len() < IP6_HEADER_LEN {
        return Ipv6Fragment::Unknown;
    }
    let length = usize::from(u16::from_be_bytes([b[4], b[5]])) + IP6_HEADER_LEN;
    if b.len() < length {
        return Ipv6Fragment::Unknown;
    }

    // Go `if len(b) < q.subofs+ip6FragHeaderLength` with `q.subofs == 40`.
    let Some(frag) = b.get(IP6_HEADER_LEN..) else {
        return Ipv6Fragment::Unknown;
    };
    if frag.len() < IP6_FRAG_HEADER_LEN {
        return Ipv6Fragment::Unknown;
    }

    let next_header = frag[0];
    // Go `fragOfs := binary.BigEndian.Uint16(frag[2:4]) >> 3`: the top 13 bits are the offset in
    // 8-byte blocks; the low 3 are two reserved bits and the More-Fragments flag. Go reads no MF
    // flag here at all — unlike `decode4`, `decode6` has no more-fragments guard on the first
    // fragment, so a first IPv6 fragment is decoded exactly like an unfragmented packet (TSMP
    // included, where `decode4` instead demotes a fragmented first packet to `unknown`).
    let frag_ofs = u16::from_be_bytes([frag[2], frag[3]]) >> 3;

    // Go steps `q.subofs += ip6FragHeaderLength` before branching; `sub` is what follows.
    let sub = &frag[IP6_FRAG_HEADER_LEN..];

    if frag_ofs == 0 {
        return decode6_first_fragment(IpProto::new(i64::from(next_header)), sub);
    }
    if frag_ofs < MIN_FRAG_BLKS {
        // RFC 1858: this fragment's bytes could land on top of the transport header the ACL matched
        // the head fragment on. Go `q.IPProto = unknown`, same guard as `decode4`.
        return Ipv6Fragment::Unknown;
    }
    Ipv6Fragment::Later
}

/// The sub-protocol switch Go `decode6` runs on a first fragment once `decode6Fragment` has stepped
/// over the Fragment header. `sub` is the buffer from the sub-protocol's header onwards (Go's
/// `sub := b[q.subofs:]`, measured against the buffer, not the IPv6 length field).
///
/// Each arm's bounds check is Go's, and each failure is Go's `unknown`: a first fragment too short
/// to hold the transport header must be **dropped**, never guessed at, or a follow-up fragment
/// supplying the rest of that header would carry the flow past a rule the filter never really
/// matched (RFC 1858, the same reason `decode4` rejects a short first fragment).
fn decode6_first_fragment(proto: IpProto, sub: &[u8]) -> Ipv6Fragment {
    /// Go `net/packet.icmp6HeaderLength`.
    const ICMP6_HEADER_LEN: usize = 4;
    /// Go `net/packet.tcpHeaderLength`.
    const TCP_HEADER_LEN: usize = 20;
    /// Go `net/packet.udpHeaderLength`.
    const UDP_HEADER_LEN: usize = 8;
    /// Go `net/packet.minTSMPSize` — the shortest TSMP body (a 7-byte rejected-connection message).
    const MIN_TSMP_SIZE: usize = 7;

    // Go's port-ful arms: bounds-check, then read the source port from `sub[0:2]` and the
    // destination port from `sub[2:4]`. `l4` is whatever else Go reads out of that same header —
    // only the TCP arm reads anything (`q.TCPFlags = TCPFlag(sub[13])`).
    let ported = |min_len: usize, l4: ts_packetfilter::L4Header| {
        if sub.len() < min_len {
            return Ipv6Fragment::Unknown;
        }
        Ipv6Fragment::First {
            proto,
            src_port: u16::from_be_bytes([sub[0], sub[1]]),
            dst_port: u16::from_be_bytes([sub[2], sub[3]]),
            l4,
        }
    };
    // Go's portless arms: bounds-check only, both ports left at 0.
    let portless = |min_len: usize, l4: ts_packetfilter::L4Header| {
        if sub.len() < min_len {
            return Ipv6Fragment::Unknown;
        }
        Ipv6Fragment::First {
            proto,
            src_port: 0,
            dst_port: 0,
            l4,
        }
    };
    // Go's `IsEchoResponse`/`IsError` read `q.b[q.subofs]` and `q.b[q.subofs+1]` behind
    // `len(q.b) >= q.subofs+8` — eight bytes, not the four `decode6`'s ICMPv6 arm bounds-checks.
    // A shorter first fragment is decoded (and matched IPs-only) but is no "response" to upstream
    // either, so it carries no ICMP header here.
    let icmp6 = || match (sub.first(), sub.get(1)) {
        (Some(&icmp_type), Some(&icmp_code)) if sub.len() >= 8 => ts_packetfilter::L4Header::Icmp {
            icmp_type,
            icmp_code,
        },
        _ => ts_packetfilter::L4Header::Unknown,
    };
    // Go `q.TCPFlags = TCPFlag(sub[13])`, guarded by the same 20-byte bounds check `ported` runs.
    let tcp_flags = || match sub.get(13) {
        Some(&flags) => ts_packetfilter::L4Header::Tcp { flags },
        None => ts_packetfilter::L4Header::Unknown,
    };

    match proto {
        IpProto::ICMPV6 => portless(ICMP6_HEADER_LEN, icmp6()),
        IpProto::TCP => ported(TCP_HEADER_LEN, tcp_flags()),
        IpProto::UDP => ported(UDP_HEADER_LEN, ts_packetfilter::L4Header::Unknown),
        IpProto::SCTP => ported(SCTP_HEADER_LEN, ts_packetfilter::L4Header::Unknown),
        IpProto::TSMP => portless(MIN_TSMP_SIZE, ts_packetfilter::L4Header::Unknown),
        IPPROTO_FRAGMENT_SENTINEL => Ipv6Fragment::Unknown,
        // Go's switch has no default arm: any other protocol keeps its number and port 0, and the
        // ACL matches it IPs-only (`IpProto::is_port_ful`).
        //
        // Protocol 0 is carried here like any other, which is Go's `q.IPProto = nextHdr` followed
        // by a switch with no case for it. It is not an admission: 0 is `ipproto.Unknown`, so the
        // packet dies on `inbound_filter_verdict`'s [`IPPROTO_UNKNOWN`] arm before a rule sees it,
        // exactly where Go's `pre()` kills it. Pinned by
        // `first_ipv6_fragment_with_unknown_next_header_is_dropped_before_the_acl`.
        _ => Ipv6Fragment::First {
            proto,
            src_port: 0,
            dst_port: 0,
            l4: ts_packetfilter::L4Header::Unknown,
        },
    }
}

/// The transport-header fields Go's `decode4` reads out of a **first** IPv4 fragment — the
/// `(source port, destination port, L4 header)` of the sub-protocol switch it runs under
/// `if fragOfs == 0`, from the same bytes Go calls `sub`.
///
/// `None` is Go's `q.IPProto = unknown` for a fragment too short to hold the whole transport header
/// it claims to carry, which filter `pre()` drops before any rule is consulted. Upstream spells out
/// why every arm bounds-checks:
///
/// ```text
/// // This is the first fragment
/// // Every protocol below MUST check that it has at least one entire
/// // transport header in order to protect against fragment confusion.
/// ```
///
/// Falling back to port 0 instead would be the fragment-confusion bug itself: a first fragment cut
/// off before its ports would be matched (and possibly admitted) on a port it never carried, with
/// the follow-up fragments supplying the real header after the verdict was taken.
///
/// This exists for the same reason [`sctp_ports`] does — etherparse cannot supply the header. It
/// deliberately refuses to descend into a *fragmenting* payload, so `SlicedPacket::transport` is
/// empty for a first fragment even though the fragment does carry the full header, where Go's
/// `decode4` parses it exactly as it parses an unfragmented packet's.
///
/// Only the protocols whose header `decode4` reads are listed. Everything else keeps its protocol
/// number and both ports 0 — Go's switch has no `default` arm — which is what
/// [`IpProto::is_port_ful`] already gives such a packet on the unfragmented path. Go's `ipproto.IGMP`
/// arm is the one omission: it bounds-checks the IGMP header and reads nothing out of it, and IGMP is
/// addressed to a multicast group, so [`drop_before_rules`] has already refused any packet that arm
/// could speak about. `ipproto.TSMP`'s `if moreFrags` refusal lives in [`inbound_filter_verdict`],
/// which is where this fork already carried it.
fn decode4_first_fragment(
    proto: IpProto,
    sub: &[u8],
) -> Option<(u16, u16, ts_packetfilter::L4Header)> {
    /// Go `net/packet.icmp4HeaderLength`.
    const ICMP4_HEADER_LEN: usize = 4;
    /// Go `net/packet.tcpHeaderLength`.
    const TCP_HEADER_LEN: usize = 20;
    /// Go `net/packet.udpHeaderLength`.
    const UDP_HEADER_LEN: usize = 8;

    // Go's port-ful arms: bounds-check the whole header, then `sub[0:2]` and `sub[2:4]`.
    let ported = |min_len: usize, l4: ts_packetfilter::L4Header| {
        if sub.len() < min_len {
            return None;
        }
        Some((
            u16::from_be_bytes([sub[0], sub[1]]),
            u16::from_be_bytes([sub[2], sub[3]]),
            l4,
        ))
    };

    match proto {
        // Go `q.TCPFlags = TCPFlag(sub[13])`, behind the same 20-byte bounds check.
        IpProto::TCP => ported(
            TCP_HEADER_LEN,
            match sub.get(13) {
                Some(&flags) => ts_packetfilter::L4Header::Tcp { flags },
                None => ts_packetfilter::L4Header::Unknown,
            },
        ),
        IpProto::UDP => ported(UDP_HEADER_LEN, ts_packetfilter::L4Header::Unknown),
        IpProto::SCTP => sctp_ports(sub).map(|(s, d)| (s, d, ts_packetfilter::L4Header::Unknown)),
        // Go `case ipproto.ICMPv4`: bounds-check four bytes, then `withPort(…, 0)` on both. The
        // type/code pair its `IsEchoResponse`/`IsError` read is guarded by a *wider* bound —
        // `len(q.b) >= q.subofs+8` — so a first fragment between 4 and 7 bytes long is decoded and
        // matched IPs-only, but is no "response" to upstream and carries no header here either.
        IpProto::ICMP => {
            if sub.len() < ICMP4_HEADER_LEN {
                return None;
            }
            let l4 = match (sub.first(), sub.get(1)) {
                (Some(&icmp_type), Some(&icmp_code)) if sub.len() >= 8 => {
                    ts_packetfilter::L4Header::Icmp {
                        icmp_type,
                        icmp_code,
                    }
                }
                _ => ts_packetfilter::L4Header::Unknown,
            };
            Some((0, 0, l4))
        }
        // Go's internal later-fragment sentinel, seen as a real protocol number on the wire: Go
        // `case ipproto.Fragment: q.IPProto = unknown`, so this is a drop, not a port-0 pass.
        IPPROTO_FRAGMENT_SENTINEL => None,
        _ => Some((0, 0, ts_packetfilter::L4Header::Unknown)),
    }
}

/// The `(source, destination)` ports of the SCTP packet whose common header starts at `sub` — Go's
/// `case ipproto.SCTP` arm, which both `decode4` and `decode6` carry verbatim: bounds-check the
/// 12-byte common header, then read `sub[0:2]` and `sub[2:4]`.
///
/// `None` is Go's refusal in that same arm (`q.IPProto = unknown`), which filter `pre()` turns into
/// a drop. It must never be read as "port 0": a truncated SCTP header carries no port for a rule to
/// match, and admitting it as port 0 would let an all-ports rule pass the packet Go throws away.
///
/// This exists because etherparse's `TransportSlice` has arms for ICMPv4/ICMPv6/TCP/UDP and nothing
/// else, so an SCTP packet leaves `SlicedPacket::transport` empty and its ports have to be read the
/// way Go reads them.
fn sctp_ports(sub: &[u8]) -> Option<(u16, u16)> {
    if sub.len() < SCTP_HEADER_LEN {
        return None;
    }
    Some((
        u16::from_be_bytes([sub[0], sub[1]]),
        u16::from_be_bytes([sub[2], sub[3]]),
    ))
}

/// Whether `ipv6` carries a Fragment extension header somewhere in its extension-header chain
/// *other than* as the base header's immediate Next Header — the case [`decode6_fragment`] is
/// deliberately not scoped to, and which must therefore fail closed here.
///
/// Callers must only ask this when the base header's Next Header is **not** [`IP6_FRAG_HEADER`];
/// otherwise the leading Fragment header itself answers `true` and would shadow its own
/// classification.
///
/// Why a drop and not a pass. Go's `decode6` steps over *only* a leading Fragment header, so a
/// chained one is never classified at all: the packet is filtered as whatever extension header the
/// base Next Header names, and its fragment offset is never read. Anything this tree said about
/// such a packet would therefore be its own invention, so it says the one thing that cannot be an
/// invention in the permissive direction — [`Ipv6Fragment::Unknown`], a drop.
///
/// This never admits what upstream refuses. Where the chain leads with Hop-by-Hop Options, Go's
/// `q.IPProto` is 0 == `ipproto.Unknown` and `pre()` drops it too. Where it leads with Routing (43)
/// or Destination Options (60), Go carries that number to `runIn6`'s `default` arm, so it can be
/// admitted only by an all-ports rule that names protocol 43 or 60 IPs-only
/// (`matchProtoAndIPsOnlyIfAllPorts`) — an ACL nobody writes by accident, and the sole case where
/// this drop is stricter than upstream. Refusing it cannot break a real Tailscale, `wireguard-go`
/// or kernel-WireGuard peer: none of them source-fragments behind a chained extension header, and
/// no peer can be relying on delivery of a packet whose fragment offset upstream never looked at.
fn fragment_header_is_chained(ipv6: &etherparse::Ipv6Slice<'_>) -> bool {
    ipv6.extensions()
        .clone()
        .into_iter()
        .any(|ext| matches!(ext, etherparse::Ipv6ExtensionSlice::Fragment(_)))
}

/// Which address family's fragment rules apply to a packet, so [`inbound_filter_verdict`] can run
/// Go's `decode4` and `decode6` fragment classifications on the packets each actually governs.
#[derive(Debug, Clone, Copy)]
enum Fragment {
    /// IPv4: the offset and MF flag straight out of the base header (Go `decode4`).
    V4(Ipv4Fragment),
    /// IPv6: the already-resolved classification of a Fragment extension header (Go `decode6`).
    V6(Ipv6Fragment),
}

/// The inbound packet-filter verdict for an already-parsed packet (`true` = admit). This is the
/// proto-switch of Go's filter `runIn4`/`runIn6`, applied after `pre()` and after this fork's
/// source-attribution and local-destination routing (the analogues of Go's `local4`/`local6`
/// precondition) have run:
///
/// 1. `drop_before_rules` — Go `pre()`'s unconditional multicast / link-local-unicast drops.
/// 2. **Fragment classification** (Go `net/packet.decode4`/`decode6` + filter `pre()`): a non-first
///    fragment carries no L4 header, so it cannot be port-matched. Go classifies it by offset — a
///    fragment at offset `>= MIN_FRAG_BLKS` is mapped to `ipproto.Fragment` and `pre()` **accepts**
///    it (stateless pass-through; the receiver's kernel discards it if the head fragment was
///    dropped), while a fragment at a smaller offset is dropped (RFC 1858). On IPv4 a *fragmented*
///    TSMP is additionally disallowed (`moreFrags` on a first TSMP fragment → drop). Without this,
///    etherparse leaves the transport `None` and the port reads as 0, so a normal ACL rule would
///    silently drop every valid later fragment — breaking large/fragmented inbound traffic on the
///    1280-MTU overlay. The IPv6 half ([`Ipv6Fragment`], Go `decode6Fragment`) additionally folds in
///    the sub-protocol decode of a *first* fragment, so `proto`/`dst_port` here are already the ones
///    read past the Fragment extension header, and `Ipv6Fragment::Unknown` — a truncated or
///    short-first fragment, or one whose Fragment header sits behind a chained extension header
///    ([`fragment_header_is_chained`]) — is dropped where Go's `pre()` drops `ipproto.Unknown`.
///    A *first* IPv4 fragment is decoded the same way ([`decode4_first_fragment`], Go `decode4`'s
///    `fragOfs == 0` switch), so `dst_port` and `l4` here are the fragmented datagram's own and it
///    faces the rules — and the reply carve-outs below — on the terms an unfragmented one does.
/// 3. **Unknown protocol** ([`IPPROTO_UNKNOWN`]) — Go `pre()`'s `if q.IPProto == ipproto.Unknown`
///    drop. `proto` is whatever the *base* header declared (Go `decode4`'s `b[9]`, `decode6`'s
///    `b[6]`), so this is the arm that refuses an IPv6 packet leading with Hop-by-Hop Options,
///    which is literally protocol 0.
/// 4. TSMP (proto 99) is always admitted, bypassing the ACL — Go `case ipproto.TSMP: return Accept`.
///    TSMP carries in-band control messages between nodes, so it must reach the local stack
///    regardless of the ACL rules. The two TSMP messages this fork understands never get here:
///    [`filter_inbound_from_peer`] consumes them ahead of this call, as Go does.
/// 5. **A UDP or SCTP reply to a flow this node started** is admitted from `flows` — Go's
///    `case ipproto.UDP, ipproto.SCTP` arm, which consults the `flowtrack` LRU and returns
///    `Accept, "cached"` *before* the rule match. See [`flowtrack`].
/// 6. **A TCP segment that is not a SYN**, and **an ICMP echo response or ICMP error**, are
///    admitted with no rule consulted — Go's `return Accept, "tcp non-syn"` and
///    `return Accept, "icmp response ok"`, the other two thirds of the reply admission step 5
///    starts. All three exist for the same reason: the answer to a connection *this node* opened
///    arrives at an ephemeral port, so no ACL control can write will ever name it. Without them a
///    policy that grants this node outbound access to a peer without granting that peer inbound
///    access back hangs every TCP connection on its SYN-ACK and silently eats every ping reply.
///    The predicates are [`ts_packetfilter::PacketInfo`]'s, and each fails closed when the L4
///    header was not decoded, so a **SYN** — or any packet whose flags this fork never read —
///    still faces the rules.
/// 7. Everything else consults the control-derived ACL via `can_access` — Go's `matches4.match`.
///    A protocol Go's `runIn4`/`runIn6` switch has no arm for (an IPv6 Routing or
///    Destination-Options header, say) lands in its `default`, which admits IPs-only and only
///    under an all-ports rule naming that protocol (`matchProtoAndIPsOnlyIfAllPorts`); that
///    per-protocol port semantics lives in [`ts_packetfilter::Rule`]. ICMP that is *not* a
///    response reaches the same call and is matched IPs-only there, which is Go's
///    `else if f.matches4.matchIPsOnly(q, …)`.
///
/// `src` and `dst` carry ports because Go's `packet.Parsed` does (`q.Src`/`q.Dst` are
/// `netip.AddrPort`) and because the flow cache in step 5 keys on all four fields. The ACL itself
/// still sees only the destination port, which is all Go's `matches4.match` reads. `l4` is the rest
/// of what Go's `packet.Parsed` holds — `TCPFlags` and the ICMP type/code — and only step 6 reads
/// it.
fn inbound_filter_verdict(
    filter: &(dyn ts_packetfilter::Filter + Send + Sync),
    flows: &mut flowtrack::FlowCache,
    proto: IpProto,
    src: std::net::SocketAddr,
    dst: std::net::SocketAddr,
    l4: ts_packetfilter::L4Header,
    frag: Option<Fragment>,
) -> bool {
    if drop_before_rules(dst.ip()) {
        tracing::trace!(?dst, "dropping multicast/link-local dst (pre-rule)");
        return false;
    }

    match frag {
        Some(Fragment::V4(frag)) => {
            if frag.offset_blocks > 0 {
                // A non-first fragment (Go `decode4`'s `fragOfs != 0` branch). It has no transport
                // header to match, so the verdict is decided purely by offset:
                if frag.offset_blocks < MIN_FRAG_BLKS {
                    // Potentially overlaps a transport header (RFC 1858); Go demotes to `unknown` → drop.
                    tracing::trace!(?dst, "dropping low-offset IPv4 fragment (RFC 1858)");
                    return false;
                }
                // A valid later fragment — Go maps it to `ipproto.Fragment`, which `pre()` accepts
                // ahead of the ACL. Stateless: if the head fragment was filtered the receiver's kernel
                // drops this on reassembly timeout. Accepting here is what large fragmented inbound
                // traffic relies on.
                tracing::trace!(
                    ?dst,
                    "accepting later IPv4 fragment (Go pre() pass-through)"
                );
                return true;
            }
            // `frag.offset_blocks == 0`: the first fragment (or an unfragmented packet). Go disallows a
            // *fragmented* TSMP (a first fragment with MF set) — without the whole message it can't be a
            // valid inter-node control packet. Fall through to the normal proto-switch for everything
            // else; the first fragment of TCP/UDP carries its L4 header, so `dst_port` was parsed above.
            if proto == IpProto::TSMP && frag.more_fragments {
                tracing::trace!(?dst, "dropping fragmented TSMP (Go parity)");
                return false;
            }
        }
        // The IPv6 Fragment extension header (Go `decode6Fragment`, upstream `4c4ec3d46`). Only
        // reachable on the opt-in `Config::enable_ipv6` path; the classification itself already ran
        // Go's offset and bounds checks, so all that is left is Go's `pre()` disposition of the
        // three protocol values `decode6` can end up with.
        Some(Fragment::V6(Ipv6Fragment::Unknown)) => {
            // Go `pre()`: `if q.IPProto == ipproto.Unknown { return Drop }`. This is the
            // security-relevant arm — a short first fragment, an RFC 1858 low-offset later
            // fragment, or a Fragment header hidden behind a chained extension header must never
            // reach the ACL, where an allow-all rule would admit it.
            tracing::trace!(
                ?dst,
                "dropping IPv6 fragment classified unknown (Go pre() drop)"
            );
            return false;
        }
        Some(Fragment::V6(Ipv6Fragment::Later)) => {
            // Go `pre()`: `case ipproto.Fragment: return Accept`, same stateless pass-through as
            // IPv4 — and required by RFC 8200 §4.5, which puts reassembly on the receiver.
            tracing::trace!(
                ?dst,
                "accepting later IPv6 fragment (Go pre() pass-through)"
            );
            return true;
        }
        // A first IPv6 fragment: `proto` and `dst_port` were read past the Fragment header, so it
        // takes the ordinary proto switch below and matches the rule an unfragmented datagram would.
        // Note the deliberate asymmetry with IPv4: `decode6` has no more-fragments guard at all, so
        // — unlike `decode4` — upstream does not demote a fragmented first TSMP packet to `unknown`.
        // Falling through is also what refuses a first fragment whose Fragment header names
        // protocol 0: it arrives here as `proto == IPPROTO_UNKNOWN` and the shared arm below drops
        // it pre-rules, which is the same fall-through Go gets from a switch with no case for 0.
        Some(Fragment::V6(Ipv6Fragment::First { .. })) | None => {}
    }

    // Go filter `pre()`: `if q.IPProto == ipproto.Unknown { return Drop }`. A protocol number
    // upstream's decoder refused to classify never reaches the ACL, so no rule — however
    // permissive — can admit it. The check sits after the fragment arms above rather than at the
    // top of the function only because those arms use `IPPROTO_UNKNOWN` as their own "no
    // sub-protocol here" placeholder; in Go the two are distinct values (`ipproto.Fragment` is
    // 0xff) and `pre()` tests them in either order to the same effect.
    //
    // The common way to land here is an IPv6 packet whose base Next Header is Hop-by-Hop Options,
    // which *is* protocol 0: `decode6` copies it into `q.IPProto` and never looks past it.
    if proto == IPPROTO_UNKNOWN {
        tracing::trace!(?dst, "dropping unknown-proto packet (Go pre() drop)");
        return false;
    }

    if proto == IpProto::TSMP {
        tracing::trace!(?dst, "accepting TSMP inbound (bypasses ACL, Go parity)");
        return true;
    }

    // Go `runIn4`/`runIn6`, at the top of the UDP/SCTP arm and ahead of the rule match:
    //
    //     case ipproto.UDP, ipproto.SCTP:
    //         t := flowtrack.MakeTuple(q.IPProto, q.Src, q.Dst)
    //         f.state.mu.Lock()
    //         _, ok := f.state.lru.Get(t)
    //         f.state.mu.Unlock()
    //         if ok {
    //             return Accept, "cached"
    //         }
    //
    // This is the reply to a datagram `process_outbound` sent, so no ACL rule can be expected to
    // name it: our source port was ephemeral. A miss falls straight through to the rule match
    // below, which is exactly what Go does — the cache only ever admits, it never denies.
    if flows.admits_inbound(proto, src, dst) {
        tracing::trace!(
            ?src,
            ?dst,
            "accepting reply to a tracked outbound flow (cached)"
        );
        return true;
    }

    let info = ts_packetfilter::PacketInfo {
        ip_proto: proto,
        port: dst.port(),
        src: src.ip(),
        dst: dst.ip(),
        l4,
    };

    // Go `runIn4`/`runIn6`, `case ipproto.TCP`, ahead of the rule match:
    //
    //     // For TCP, we want to allow *outgoing* connections, which means we want to allow
    //     // return packets on those connections. To make this restriction work, we need to
    //     // allow non-SYN packets (continuation of an existing session) to arrive. This
    //     // should be okay since a new incoming session can't be initiated without first
    //     // sending a SYN.
    //     if !q.IsTCPSyn() {
    //         return Accept, "tcp non-syn"
    //     }
    //
    // The SYN-ACK answering a connection `process_outbound` opened is a non-SYN, and it lands on
    // our ephemeral source port, so no rule from control can name it. A SYN is the one segment this
    // must never admit: it is the only way to *start* an inbound session, and admitting it would
    // turn the carve-out into an open door. See `PacketInfo::is_tcp_non_syn`, which demands a
    // decoded flags byte rather than treating "no flags" as "not a SYN".
    if info.is_tcp_non_syn() {
        tracing::trace!(
            ?src,
            ?dst,
            "accepting inbound TCP non-SYN (Go 'tcp non-syn')"
        );
        return true;
    }

    // Go `runIn4`'s `case ipproto.ICMPv4` and `runIn6`'s `case ipproto.ICMPv6`, ahead of the same
    // rule match:
    //
    //     if q.IsEchoResponse() || q.IsError() {
    //         // ICMP responses are allowed.
    //         return Accept, "icmp response ok"
    //     } else if f.matches4.matchIPsOnly(q, f.srcIPHasCap) {
    //         // If any port is open to an IP, allow ICMP to it.
    //         return Accept, "icmp ok"
    //     }
    //
    // The `else if` is already in place: `ts_packetfilter::Rule` matches ICMP IPs-only, so an echo
    // *request* — and anything else that is not a response — falls through to `can_access` below
    // and is admitted only if a rule opens some port to this destination. Only the unconditional
    // arm is added here.
    if info.is_icmp_echo_response() || info.is_icmp_error() {
        tracing::trace!(
            ?src,
            ?dst,
            "accepting inbound ICMP response (Go 'icmp response ok')"
        );
        return true;
    }

    // TODO(npry): wire in nodecaps
    let caps = [];
    let verdict = filter.can_access(&info, caps);
    tracing::trace!(?info, ?caps, verdict);
    verdict
}

/// The knobs [`filter_inbound_from_peer`] reads that come from this node's configuration rather
/// than from the packet in front of it — everything Go's `tstun.Wrapper` holds on itself for the
/// TSMP rejected-connection reply.
#[derive(Debug, Clone, Copy, Default)]
struct RejectConfig {
    /// Go `tstun.Wrapper.disableTSMPRejected`: when set, this node tells a peer nothing about an
    /// ACL drop, exactly as before this existed.
    disabled: bool,
    /// Go `tstun.Wrapper.PeerAPIPort`: the TCP port this node's peerAPI listens on, if it runs one.
    /// A SYN to it never produces a reject — see [`tsmp_reject_for_drop`].
    peerapi_port: Option<u16>,
}

/// Everything a filtered inbound batch produces besides the packets it keeps.
///
/// Grouped into one out-parameter because all three are appended to across a whole
/// [`DataPlane::process_inbound_from`] call, never per packet, and because every one of them is a
/// TSMP message either consumed or synthesized by the filter step.
#[derive(Debug, Default)]
struct InboundHarvest {
    /// Disco keys peers advertised (Go `packet.TSMPDiscoKeyAdvertisement`). See
    /// [`InboundResult::learned_disco_keys`].
    learned_disco_keys: Vec<(PeerId, ts_packet::tsmp::DiscoKeyAdvertisement)>,
    /// Rejected-connection messages peers sent us. See [`InboundResult::rejected_flows`].
    rejected_flows: Vec<(PeerId, ts_packet::tsmp::TailscaleRejectedHeader)>,
    /// Rejected-connection messages *this* node is sending back, already marshalled into complete
    /// IP packets, each addressed to the peer whose packet was dropped. The caller encrypts and
    /// queues them (Go `tstun.Wrapper.InjectOutbound`).
    rejects_to_send: Vec<(PeerId, PacketMut)>,
}

/// The TSMP rejected-connection message to send back for an inbound packet the filter just
/// dropped, marshalled into a complete IP packet — or `None` when this drop must stay silent.
///
/// Go `tstun.Wrapper.filterPacketInboundFromWireGuard`, the block that runs on `outcome !=
/// filter.Accept`:
///
/// ```text
/// // Tell them, via TSMP, we're dropping them due to the ACL.
/// // Their host networking stack can translate this into ICMP
/// // or whatnot as required. But notably, their GUI or tailscale CLI
/// // can show them a rejection history with reasons.
/// if p.IPVersion == 4 && p.IPProto == ipproto.TCP && p.TCPFlags&packet.TCPSyn != 0 && !t.disableTSMPRejected {
/// ```
///
/// Every clause of that guard is a refusal that has to come with the message, because each one is a
/// packet upstream stays **silent** about:
///
/// 1. **`disableTSMPRejected`** ([`RejectConfig::disabled`]) — the node-wide off switch.
/// 2. **IPv4 only.** An IPv6 packet dropped by the ACL produces nothing. Upstream's guard is
///    `p.IPVersion == 4` and the message itself is family-agnostic, so this is a deliberate
///    upstream scoping and not a limitation of the encoding.
/// 3. **TCP only, and only a segment with the SYN bit set.** A dropped UDP datagram, a dropped
///    non-SYN segment and a dropped ICMP packet are all silent: the message names a *connection*
///    being refused, and only a SYN is a connection being opened. See
///    [`ts_packetfilter::L4Header::tcp_syn_flag_set`] for why this is not `is_tcp_non_syn`'s
///    negation.
/// 4. **Never for the peerAPI port.** Go's carve-out immediately above — "Let peerapi through the
///    filter; its ACLs are handled at L7, not at the packet level" — flips an ACL-refused peerAPI
///    SYN back to `Accept` *before* this block runs, so upstream never emits a reject for one. This
///    fork has no such carve-out (its peerAPI is reachable only through the ordinary rules), so the
///    same outcome is reached by suppressing the message here rather than by admitting the packet:
///    the verdict on the packet is untouched, and, as upstream, the peer is told nothing.
///
/// The reason is [`RejectReason::SHIELDS_UP`] when the live filter has shields up (Go
/// `if t.filter.ShieldsUp() { rj.Reason = packet.RejectedDueToShieldsUp }`) and
/// [`RejectReason::ACLS`] otherwise. `maybe_broken` stays false: both reasons are terminal
/// verdicts about this node's own policy, and Go sets neither of the non-terminal reasons here.
///
/// [`RejectReason::SHIELDS_UP`]: ts_packet::tsmp::RejectReason::SHIELDS_UP
/// [`RejectReason::ACLS`]: ts_packet::tsmp::RejectReason::ACLS
fn tsmp_reject_for_drop(
    proto: IpProto,
    src: std::net::SocketAddr,
    dst: std::net::SocketAddr,
    l4: ts_packetfilter::L4Header,
    shields_up: bool,
    cfg: RejectConfig,
) -> Option<Vec<u8>> {
    if cfg.disabled {
        return None;
    }
    // Go `p.IPVersion == 4`. `src` and `dst` come from one IP header, so testing either is testing
    // the header; both are spelled out because the marshal below refuses a mixed pair anyway.
    if !src.is_ipv4() || !dst.is_ipv4() {
        return None;
    }
    if proto != IpProto::TCP || !l4.tcp_syn_flag_set() {
        return None;
    }
    if cfg.peerapi_port == Some(dst.port()) {
        tracing::trace!(?dst, "not rejecting a peerAPI SYN (Go's peerapi carve-out)");
        return None;
    }

    let reason = if shields_up {
        ts_packet::tsmp::RejectReason::SHIELDS_UP
    } else {
        ts_packet::tsmp::RejectReason::ACLS
    };

    // Go: `IPSrc: p.Dst.Addr(), IPDst: p.Src.Addr(), Src: p.Src, Dst: p.Dst`. The IP pair is
    // reversed — the reject travels back the way the packet came — while the four-tuple keeps the
    // *rejected connection's* own direction, so the dialer can match it against the flow it opened.
    ts_packet::tsmp::TailscaleRejectedHeader {
        ip_src: dst.ip(),
        ip_dst: src.ip(),
        src,
        dst,
        // Go `Proto: p.IPProto`, which the guard above has already pinned to TCP.
        proto: IPPROTO_TCP_BYTE,
        reason,
        maybe_broken: false,
    }
    .marshal()
    .inspect_err(|e| tracing::debug!(?dst, error = %e, "not sending a TSMP reject"))
    .ok()
}

/// Apply the inbound packet filter to one peer's already-source-attributed batch of decrypted
/// packets, in place, and harvest any TSMP disco-key advertisements it carried.
///
/// This is the body of Go's `tstun.Wrapper.filterPacketInboundFromWireGuard`, in Go's order:
///
/// 1. **TSMP consumption.** Go inspects TSMP *before* running the ACL filter and returns
///    `filter.DropSilently` for the messages it consumes itself. The one consumed here is the
///    disco-key advertisement (Go `packet.TSMPDiscoKeyAdvertisement`, upstream capability version
///    144): a peer announces its disco public key right after an eligible WireGuard session comes
///    up, so the receiver learns it without waiting for a netmap update or restarting WireGuard.
///    A real Go peer sends this unprompted. The other message consumed here is the
///    **rejected-connection** message (Go `packet.TailscaleRejectedHeader`), which Go consumes in
///    `wgengine.userspaceEngine.trackOpenPreFilterIn` — also ahead of the ACL, also with
///    `filter.DropSilently`. Every *remaining* TSMP message (ping, pong, a type this fork does not
///    know) is left in the batch and falls through to step 2, which admits it — exactly as Go's
///    filter does for the TSMP types it does not consume.
/// 2. **The ACL verdict**, [`inbound_filter_verdict`] (Go `runIn4`/`runIn6`).
/// 3. **The rejected-connection reply**, on a drop: Go answers a dropped IPv4 TCP SYN by injecting
///    a `packet.TailscaleRejectedHeader` back to the peer, so the far side learns *why* its dial
///    failed instead of waiting out a TCP timeout. See [`tsmp_reject_for_drop`], which carries the
///    whole of upstream's guard — including the drops that must stay silent.
///
/// `harvest` is appended to, never cleared, so one batch can carry messages from several peers. A
/// learned key is attributed to `peer_id` — the WireGuard peer whose session
/// decrypted the packet, and whose source addresses the caller's source filter has already bound.
/// Go reaches the same peer the long way round, looking the advertisement's source IP up in the
/// netmap (`wgengine.userspaceEngine.peerForIP`). Either way a peer can only advertise a key for
/// *itself*: it cannot speak for another peer.
fn filter_inbound_from_peer(
    filter: &(dyn ts_packetfilter::Filter + Send + Sync),
    flows: &mut flowtrack::FlowCache,
    peer_id: PeerId,
    packets: &mut Vec<PacketMut>,
    reject_cfg: RejectConfig,
    harvest: &mut InboundHarvest,
) {
    packets.retain(|packet| {
        let bytes = packet.as_ref();
        let Ok(pkt) = etherparse::SlicedPacket::from_ip(bytes) else {
            tracing::trace!("does not look like ip packet");
            return false;
        };

        // Go's `sub` in `decode4`/`decode6`: the packet from the sub-protocol's header onwards
        // (`b[q.subofs:]`, the bytes after the IPv4 header or after the IPv6 base header and any
        // extension headers). Taken here because the classification below consumes `pkt.net`; only
        // the SCTP arm of `dst_port` reads it, for the ports etherparse does not parse itself.
        let sub = match &pkt.net {
            Some(etherparse::NetSlice::Ipv4(ipv4)) => ipv4.payload().payload,
            Some(etherparse::NetSlice::Ipv6(ipv6)) => ipv6.payload().payload,
            _ => &[][..],
        };

        let (proto, src, dst, frag) = match pkt.net {
            Some(etherparse::NetSlice::Ipv4(ipv4)) => {
                // IPv4 fragment state (Go `net/packet.decode4` reads `b[6:8]`): a
                // non-first fragment carries no L4 header, so etherparse leaves
                // `transport == None` and the port would read as 0 below — which a normal
                // ACL rule never admits. Without classifying the fragment that silently
                // drops valid later fragments Go *accepts* (breaking large/fragmented
                // inbound traffic on the 1280-MTU overlay). Capture the offset (in 8-byte
                // blocks) + the more-fragments bit so the verdict can mirror Go's
                // `decode4`/`pre()` fragment handling.
                let hdr = ipv4.header();
                (
                    IpProto::new(ipv4.payload().ip_number.0 as _),
                    hdr.source_addr().into(),
                    hdr.destination_addr().into(),
                    Some(Fragment::V4(Ipv4Fragment {
                        offset_blocks: hdr.fragments_offset().value(),
                        more_fragments: hdr.more_fragments(),
                    })),
                )
            }
            Some(etherparse::NetSlice::Ipv6(ipv6)) => {
                let hdr = ipv6.header();
                // Go `decode6` reads the protocol out of the base header and only the base
                // header (`q.IPProto = ipproto.Proto(b[6])`). `next_header()` is that byte.
                // Its one remapping is `decode6`'s switch arm `case ipproto.Fragment:
                // q.IPProto = unknown` — Go's internal later-fragment sentinel has no business
                // being on the wire, and `decode6_first_fragment` already refuses it in the
                // other place it can appear.
                let base_proto = match IpProto::new(i64::from(hdr.next_header().0)) {
                    IPPROTO_FRAGMENT_SENTINEL => IPPROTO_UNKNOWN,
                    other => other,
                };
                // IPv6 fragmentation is carried in a Fragment extension header, not the
                // base header. Go `decode6` parses that header — and *only* when it is the
                // base header's immediate Next Header. `next_header()` is exactly that
                // immediate byte, so testing it here reproduces upstream's scoping. Only
                // reachable under the opt-in `Config::enable_ipv6`; the tailnet is IPv4-only
                // by default.
                //
                // A Fragment header reached through a *chained* hop-by-hop / routing /
                // destination-options / AH header is outside that scope, and fails closed
                // rather than falling through to the ACL as a fragment Go never classified.
                // See `fragment_header_is_chained`.
                let frag = if hdr.next_header().0 == IP6_FRAG_HEADER {
                    Some(decode6_fragment(bytes))
                } else if fragment_header_is_chained(&ipv6) {
                    Some(Ipv6Fragment::Unknown)
                } else {
                    None
                };
                let proto = match frag {
                    // Go `q.IPProto = nextHdr`: the first fragment's real sub-protocol, read
                    // past the 8-byte Fragment header.
                    Some(Ipv6Fragment::First { proto, .. }) => proto,
                    // A later or malformed fragment has no sub-protocol at all (Go's
                    // `ipproto.Fragment` / `unknown`); the verdict decides on the
                    // classification alone and never consults this.
                    Some(Ipv6Fragment::Later | Ipv6Fragment::Unknown) => IPPROTO_UNKNOWN,
                    // Go `decode6`: `q.IPProto = ipproto.Proto(b[6])` — the **base** header's
                    // Next Header byte, and nothing after that line resolves it any further.
                    // `decode6` steps over exactly one header, the leading Fragment header
                    // handled above; every other extension header is left unparsed, so the
                    // protocol Go matches on is the extension header's own number. Reading
                    // `ipv6.payload().ip_number` instead would take etherparse's walk *through*
                    // the whole chain to the real transport number, which is a different packet
                    // than the one upstream filters: a chain that leads with Hop-by-Hop (0) is
                    // `ipproto.Unknown` and `pre()` drops it, and one that leads with Routing
                    // (43) or Destination Options (60) reaches the ACL as protocol 43/60 —
                    // never matched against a TCP or UDP rule, and admitted only by an
                    // all-ports rule naming that protocol (Go `matchProtoAndIPsOnlyIfAllPorts`).
                    None => base_proto,
                };
                (
                    proto,
                    hdr.source_addr().into(),
                    hdr.destination_addr().into(),
                    frag.map(Fragment::V6),
                )
            }
            _ => {
                // A packet that parsed as IP but is neither IPv4 nor IPv6 (e.g. a
                // future/odd `NetSlice` shape). These bytes are attacker-controlled
                // post-decrypt, so fail closed — drop it — rather than `unreachable!`,
                // which would panic the single-threaded dataplane on a crafted packet.
                // Go's filter `pre()` likewise returns Drop/"not-ip" here, never panics.
                tracing::trace!("parsed packet is neither IPv4 nor IPv6; dropping");
                return false;
            }
        };

        // Go `decode4`, `if fragOfs == 0`: a *first* IPv4 fragment carries the whole transport
        // header, and Go parses it exactly as it parses an unfragmented packet's — ports, TCP flags
        // and all. etherparse refuses to descend into a fragmenting payload and leaves
        // `pkt.transport` empty, so those bytes have to be read out of `sub` the way Go reads them.
        //
        // Without this a fragmented inbound datagram reaches the ACL as port 0 and misses the
        // reverse-flow cache, while its *later* fragments — accepted on their offset alone, as Go
        // accepts them — arrive and can never be reassembled. `process_outbound` already reads a
        // first fragment's ports this way (see `outbound_udp_or_sctp_flow`), so the flow this node
        // opened was recorded and only the reply's head fragment was thrown away.
        //
        // Scoped to a fragmented first fragment (MF set, offset 0), which is exactly the shape
        // etherparse withholds the transport header for; an unfragmented packet keeps the
        // etherparse-parsed header it has always had.
        let v4_first_frag = match frag {
            Some(Fragment::V4(v4)) if v4.more_fragments && v4.offset_blocks == 0 => {
                let Some(decoded) = decode4_first_fragment(proto, sub) else {
                    // Go's `q.IPProto = unknown`, dropped by `pre()` before any rule is consulted:
                    // a first fragment too short to hold the transport header it claims, or one
                    // carrying Go's internal later-fragment sentinel as its protocol number.
                    tracing::trace!(
                        ?dst,
                        "dropping first IPv4 fragment Go decodes as unknown (fragment confusion)"
                    );
                    return false;
                };
                Some(decoded)
            }
            _ => None,
        };

        // The rest of what Go's `packet.Parsed` holds about the L4 header — `q.TCPFlags`, and the
        // ICMP type/code its `IsEchoResponse`/`IsError` read — for the reply carve-outs
        // `inbound_filter_verdict` applies ahead of the rules. Taken before the port match below,
        // which consumes `pkt.transport`.
        //
        // Every arm is guarded on `proto`, the number the *base* IP header declared. That is what
        // Go's `runIn4`/`runIn6` switch on, and it is load-bearing here: etherparse walks an IPv6
        // extension-header chain through to the real transport, so a packet leading with a Routing
        // (43) or Destination Options (60) header can hand us a `TransportSlice::Tcp` for a
        // protocol upstream never treats as TCP. Without the guard, burying a non-SYN segment under
        // an extension header would be enough to skip the rules entirely.
        let l4 = match frag {
            // Go `decode6` parses a first fragment's real sub-protocol header past the Fragment
            // extension header, TCP flags and ICMPv6 type included.
            Some(Fragment::V6(Ipv6Fragment::First { l4, .. })) => l4,
            // A later or malformed fragment has no L4 header to read at all, and the verdict
            // decides on the classification alone.
            Some(Fragment::V6(Ipv6Fragment::Later | Ipv6Fragment::Unknown)) => {
                ts_packetfilter::L4Header::Unknown
            }
            // Any IPv4 packet, and any IPv6 packet with no Fragment header.
            //
            // A *first* IPv4 fragment has no transport slice — etherparse will not descend into a
            // fragmenting payload — so its header comes from the Go-shaped decode above instead,
            // and the reply carve-outs see the same TCP flags or ICMP type they would see on the
            // unfragmented datagram.
            Some(Fragment::V4(_)) | None => match v4_first_frag {
                Some((_, _, l4)) => l4,
                None => match &pkt.transport {
                    // Go `decode4`/`decode6`: `q.TCPFlags = TCPFlag(sub[13])`. `TcpSlice::from_slice`
                    // has already bounds-checked a 20-byte header, so the `None` is unreachable — but
                    // it is spelled out rather than indexed, because these bytes are attacker
                    // controlled post-decrypt and `L4Header::Unknown` fails closed where a panic would
                    // take down the dataplane.
                    Some(etherparse::TransportSlice::Tcp(tcp)) if proto == IpProto::TCP => {
                        match tcp.header_slice().get(13) {
                            Some(&flags) => ts_packetfilter::L4Header::Tcp { flags },
                            None => ts_packetfilter::L4Header::Unknown,
                        }
                    }
                    // Go's `IsEchoResponse`/`IsError` read `q.b[q.subofs]` and `q.b[q.subofs+1]` behind
                    // `len(q.b) >= q.subofs+8`; etherparse's ICMP slices refuse anything shorter than
                    // those same 8 bytes, so reaching this arm at all satisfies upstream's guard.
                    Some(etherparse::TransportSlice::Icmpv4(icmp)) if proto == IpProto::ICMP => {
                        ts_packetfilter::L4Header::Icmp {
                            icmp_type: icmp.type_u8(),
                            icmp_code: icmp.code_u8(),
                        }
                    }
                    Some(etherparse::TransportSlice::Icmpv6(icmp)) if proto == IpProto::ICMPV6 => {
                        ts_packetfilter::L4Header::Icmp {
                            icmp_type: icmp.type_u8(),
                            icmp_code: icmp.code_u8(),
                        }
                    }
                    _ => ts_packetfilter::L4Header::Unknown,
                },
            },
        };

        // Go `decode6` reads a *first* IPv6 fragment's transport ports past the Fragment
        // extension header, so a fragmented datagram matches the same rule as an
        // unfragmented one. etherparse deliberately refuses to descend into a fragmenting
        // payload and leaves `transport == None`, so that port comes from the
        // classification above instead.
        let (src_port, dst_port) = match frag {
            Some(Fragment::V6(Ipv6Fragment::First {
                src_port, dst_port, ..
            })) => (src_port, dst_port),
            // Go reads a destination port in exactly three arms of `decode4`/`decode6` — TCP,
            // UDP and SCTP — and which arm runs is decided by the protocol number the *base*
            // header declared, not by what a header walk can reach. So an IPv6 packet that
            // leads with an extension header takes the switch's `default` (in `decode6`, no
            // arm at all) and keeps port 0 even though a transport header does sit further
            // down its chain. Reading that buried port here is what let a chained packet be
            // matched against a port-scoped TCP/UDP rule it is not upstream's to match.
            _ if !proto.is_port_ful() => (0, 0),
            // A later IPv4 fragment carries no transport header at all: Go `decode4` leaves both
            // ports 0 and classifies it `ipproto.Fragment`, and the verdict below decides on the
            // offset alone. `sub` is continued payload here, not a header, so the SCTP arm must
            // not read it — that would invent a port, and would drop a short later fragment Go
            // passes through.
            Some(Fragment::V4(v4)) if v4.offset_blocks > 0 => (0, 0),
            // SCTP. etherparse's `TransportSlice` parses ICMPv4, ICMPv6, TCP and UDP and nothing
            // else, so `pkt.transport` is `None` for SCTP and the arm below would report port 0
            // for every SCTP packet on the wire — a match Go never makes. Go has an SCTP arm in
            // both `decode4` and `decode6` that reads `sub[2:4]`, so read it there too, from the
            // same bytes Go calls `sub`. (An IPv6 *first fragment* carrying SCTP is already
            // handled by the first arm, out of `decode6_first_fragment`'s own SCTP arm.)
            _ if proto == IpProto::SCTP => {
                let Some(ports) = sctp_ports(sub) else {
                    // Go's `q.IPProto = unknown` for a header too short to hold the ports, which
                    // `pre()` drops before any rule is consulted. Falling back to port 0 instead
                    // would hand the packet to an all-ports SCTP rule.
                    tracing::trace!(?dst, "dropping SCTP packet shorter than its own header");
                    return false;
                };
                ports
            }
            // A *first* IPv4 fragment carrying TCP or UDP: Go's `fragOfs == 0` arms read its ports
            // like any other packet's, and etherparse cannot, because it hands over no transport
            // slice for a fragmenting payload. Without this the ACL sees port 0 and the
            // reverse-flow cache is asked about a flow nobody opened.
            _ => match (v4_first_frag, pkt.transport) {
                (Some((src_port, dst_port, _)), _) => (src_port, dst_port),
                (None, Some(etherparse::TransportSlice::Udp(udp))) => {
                    (udp.source_port(), udp.destination_port())
                }
                (None, Some(etherparse::TransportSlice::Tcp(tcp))) => {
                    (tcp.source_port(), tcp.destination_port())
                }
                _ => (0, 0),
            },
        };

        // TSMP disco-key advertisement (Go `packet.TSMPDiscoKeyAdvertisement`,
        // upstream capability version 144). Go handles TSMP in
        // `tstun.filterPacketInboundFromWireGuard` *before* the ACL filter runs, and
        // returns `filter.DropSilently` for an advertisement: it is an inter-node
        // control message consumed here, never delivered to the local stack. Mirror
        // both the position (after source attribution, before the ACL) and the drop.
        //
        if proto == IpProto::TSMP
            && let Some(advert) = ts_packet::tsmp::DiscoKeyAdvertisement::parse(bytes)
        {
            if advert.key_is_zero() {
                // Go publishes only `if !discoKeyAdvert.Key.IsZero()`. Still a
                // well-formed advertisement, so it is still dropped.
                tracing::debug!(
                    ?peer_id,
                    "TSMP disco-key advertisement carried the zero key; ignoring"
                );
            } else {
                tracing::debug!(?peer_id, %src, "learned peer disco key over TSMP");
                harvest.learned_disco_keys.push((peer_id, advert));
            }
            return false;
        }

        // TSMP rejected-connection message (Go `packet.TailscaleRejectedHeader`): a peer telling us
        // it refused a connection *we* opened, and why. Go consumes it in
        // `wgengine.userspaceEngine.trackOpenPreFilterIn`, a pre-filter hook that runs ahead of the
        // ACL and returns `filter.DropSilently` — the message is an inter-node control message
        // addressed to the engine, never traffic for the local stack. Consumed in the same position
        // and dropped the same way here; without this it reaches `smoltcp` as an IP-proto-99
        // datagram it has no handler for.
        //
        // Narrower than Go's hook, which drops *every* TSMP packet it sees: only a well-formed
        // rejected-connection message is consumed here, so the TSMP types this fork does not
        // implement keep the unconditional accept `inbound_filter_verdict` has always given them.
        if proto == IpProto::TSMP
            && let Some(reject) = ts_packet::tsmp::TailscaleRejectedHeader::parse(bytes)
        {
            // Go `wgengine/pendopen.go`:
            //     e.logf("open-conn-track: flow %v %v > %v rejected due to %v", ...)
            // Go looks the flow up in its pending-open table first and logs only for a flow it was
            // actually waiting on (or, on `MaybeBroken`, marks that flow problematic instead of
            // removing it). This fork keeps no pending-open table, so the message is logged
            // unconditionally and handed to the caller with `MaybeBroken` intact, for the embedder
            // to match against whatever it has open.
            //
            // `debug!`, not the `info!` Go's `logf` amounts to, precisely *because* the
            // pending-open lookup is missing: Go's log volume is bounded by the flows this node
            // opened, and an unconditional log's is bounded only by what a peer chooses to send.
            // Every field below is peer-supplied, and reaching here needs nothing but a WireGuard
            // session and a well-formed TSMP body — no pending-flow match, no rate limit — so at
            // `info!` any authenticated peer can drive an operator's default-level log as fast as
            // the link allows and bury real events under it. The same reasoning already puts the
            // sibling TSMP branches (the disco-key advertisement above, the reject *send* below)
            // at `debug!`. Nothing is lost: `rejected_flows` still carries the whole record, and
            // the embedder is the layer that *can* do Go's match, so it is the layer that gets to
            // decide a rejection is worth an `info!`.
            tracing::debug!(
                ?peer_id,
                maybe_broken = reject.maybe_broken,
                "open-conn-track: flow {} {} > {} rejected due to {}",
                reject.proto,
                reject.src,
                reject.dst,
                reject.reason,
            );
            harvest.rejected_flows.push((peer_id, reject));
            return false;
        }

        // The inbound proto-switch (Go `runIn4`/`runIn6`): Go `pre()` multicast/link-local
        // drops, then the fragment classification (Go `decode4` + `pre()`), then
        // unconditional TSMP accept, then the control-derived ACL. The caller's source
        // attribution and `or_in.route` bound this to attributable peers and local
        // destinations (Go's `local4`/`local6` precondition).
        let src = std::net::SocketAddr::new(src, src_port);
        let dst = std::net::SocketAddr::new(dst, dst_port);

        let verdict = inbound_filter_verdict(filter, flows, proto, src, dst, l4, frag);

        // Go, on any non-`Accept` outcome: "Tell them, via TSMP, we're dropping them due to the
        // ACL. Their host networking stack can translate this into ICMP or whatnot as required. But
        // notably, their GUI or tailscale CLI can show them a rejection history with reasons."
        // Almost every drop stays silent — see `tsmp_reject_for_drop` for the guard, and for the
        // one shape (a peerAPI SYN) upstream silences by admitting rather than by suppressing.
        if !verdict
            && let Some(reject) =
                tsmp_reject_for_drop(proto, src, dst, l4, filter.shields_up(), reject_cfg)
        {
            tracing::debug!(
                ?peer_id,
                ?src,
                ?dst,
                "sending a TSMP reject for a dropped SYN"
            );
            harvest.rejects_to_send.push((peer_id, reject.into()));
        }

        verdict
    });
}

/// Where this node sends a TSMP disco-key advertisement, and what it puts in one.
///
/// The send half of Go's capability version 144 (`packet.TSMPDiscoKeyAdvertisement`): when a
/// WireGuard session with a peer is established, this node announces its own disco public key to
/// that peer over TSMP, so the peer can learn (or re-learn) the key without waiting for a netmap
/// update from control. It is the mirror image of the receive half in
/// `filter_inbound_from_peer`, and both are unconditional — a real Go peer sends us one whether
/// or not we send one back.
///
/// This is the netmap state Go's [`magicsock.Conn.PriorityMessageForPeer`] reads, snapshotted into
/// the dataplane so building the message stays a cheap, synchronous, allocation-only step on the
/// datapath. wireguard-go requires the same of its callback: "must be cheap and must not call back
/// into the [`Device`]". The runtime refreshes the snapshot whenever the netmap changes.
///
/// [`magicsock.Conn.PriorityMessageForPeer`]: https://github.com/tailscale/tailscale/blob/main/wgengine/magicsock/magicsock.go
/// [`Device`]: https://github.com/tailscale/wireguard-go/blob/main/device/device.go
#[derive(Debug, Clone, Default)]
pub struct DiscoAdvertisementState {
    /// This node's own disco public key, raw (Go `Conn.DiscoPublicKey()`). The all-zero key means
    /// "no disco key", and nothing is ever advertised — Go's first refusal.
    pub disco_key: [u8; ts_packet::tsmp::DISCO_KEY_LEN],
    /// This node's own tailnet addresses, in the order control sent them (Go `self.Addresses()`,
    /// already narrowed to the single-IP prefixes `selfIPMatchingFamily` accepts). The
    /// advertisement's source is the first entry matching the destination's family.
    pub self_addrs: Vec<std::net::IpAddr>,
    /// Where to send an advertisement, per peer. A peer absent from this map is never advertised
    /// to — Go's `endpointForNodeKey` miss.
    pub peers: HashMap<PeerId, AdvertisementTarget>,
}

/// One peer's advertisement destination, as [`DiscoAdvertisementState`] holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdvertisementTarget {
    /// The peer's first tailnet address (Go `endpoint.nodeAddr`), which is the advertisement's
    /// destination address.
    pub node_addr: std::net::IpAddr,
    /// Whether this is a plain WireGuard peer rather than a Tailscale node (Go
    /// `endpoint.isWireguardOnly`). Such a peer speaks no TSMP, so Go never sends it one — and a
    /// kernel-WireGuard or `wireguard-go` peer would hand the advertisement straight to its host
    /// network stack as an unknown-protocol packet.
    pub wireguard_only: bool,
}

impl DiscoAdvertisementState {
    /// The marshalled TSMP disco-key advertisement to send `peer` on session establishment, or
    /// `None` if this node must not advertise to it.
    ///
    /// Go [`magicsock.Conn.PriorityMessageForPeer`], refusal for refusal — every one of these is a
    /// silent "send nothing", never a fallback to some other message:
    ///
    /// 1. **No disco key of our own** (`disco.IsZero()`): there is nothing to advertise.
    /// 2. **Unknown peer** (`endpointForNodeKey` miss, or `!self.Valid()`): the netmap snapshot has
    ///    no destination address for this WireGuard peer, so any address we invented would be a
    ///    guess.
    /// 3. **A WireGuard-only peer** (`ep.isWireguardOnly`): "Do not send TSMP messages to peers
    ///    that only speaks wireguard."
    /// 4. **No source address in the destination's family** (`selfIPMatchingFamily` returning the
    ///    zero `Addr`): an IPv4-only node has nothing to put in the source field of a packet to a
    ///    peer's IPv6 address.
    /// 5. A marshal refusal, which by construction of (4) cannot happen — see
    ///    [`ts_packet::tsmp::DiscoKeyAdvertisement::marshal`].
    ///
    /// [`magicsock.Conn.PriorityMessageForPeer`]: https://github.com/tailscale/tailscale/blob/main/wgengine/magicsock/magicsock.go
    pub fn advertisement_for(&self, peer: PeerId) -> Option<Vec<u8>> {
        if self.disco_key == [0u8; ts_packet::tsmp::DISCO_KEY_LEN] {
            tracing::debug!(?peer, "no disco key of our own; not advertising");
            return None;
        }

        let target = self.peers.get(&peer)?;

        if target.wireguard_only {
            return None;
        }

        let src = self_ip_matching_family(&self.self_addrs, target.node_addr)?;

        ts_packet::tsmp::DiscoKeyAdvertisement {
            src,
            dst: target.node_addr,
            key: self.disco_key,
        }
        .marshal()
        .inspect_err(|e| tracing::debug!(?peer, error = %e, "not advertising our disco key"))
        .ok()
    }
}

/// This node's first tailnet address whose family matches `want`, or `None`.
///
/// Go `magicsock.selfIPMatchingFamily`, which walks `self.Addresses()` and returns the first
/// single-IP prefix with `Addr().BitLen() == want.BitLen()`. `addrs` is already narrowed to
/// single IPs by the caller that builds the snapshot, so only the family test remains.
fn self_ip_matching_family(
    addrs: &[std::net::IpAddr],
    want: std::net::IpAddr,
) -> Option<std::net::IpAddr> {
    addrs
        .iter()
        .copied()
        .find(|addr| addr.is_ipv4() == want.is_ipv4())
}

/// The `tstun_out_to_wg_drop_tsmp` counter (Go `metricPacketOutDropTSMP`), registered into the
/// process-global registry on first use and exported by `ts_metrics::write_prometheus`. This is the
/// durable signal for [`outbound_packet_carries_tsmp`] firing: the datapath log below it is
/// `debug!`, because a local process can write these as fast as it likes and this tree has no
/// rate-limited logger to put behind Go's `limitedLogf`.
fn metric_out_to_wg_drop_tsmp() -> &'static ts_metrics::Metric {
    static M: std::sync::OnceLock<&'static ts_metrics::Metric> = std::sync::OnceLock::new();
    M.get_or_init(|| ts_metrics::Metric::new_counter("tstun_out_to_wg_drop_tsmp"))
}

/// Whether the IP packet `b`, written into the TUN by a local host process, carries TSMP and must
/// therefore be dropped before it reaches WireGuard.
///
/// Go `tstun.filterPacketOutboundToWireGuard`: "TSMP traffic should only originate from tailscaled,
/// not from the host itself." TSMP is the inter-node control channel — capability version 144's
/// disco-key advertisement rides it — so a TSMP packet the host writes is either a confused
/// networking stack or a local process forging a control message in this node's name. A peer cannot
/// tell a forged advertisement from one this node meant to send: both arrive inside this node's
/// WireGuard session, from this node's tailnet address. It would bind whatever disco key the forger
/// chose.
///
/// The advertisements this node legitimately sends never pass through here. They are built in
/// [`DiscoAdvertisementState::advertisement_for`] and injected straight into the WireGuard session
/// by [`DataPlane::process_inbound`] (the priority-message path), which is *below* this check —
/// the same relationship Go has, where `injectedRead` bypasses the outbound filter entirely.
///
/// # Where this is a superset of Go's classification, and why
///
/// Go tests the decoded `p.IPProto`, so a *malformed* proto-99 packet decodes to `ipproto.Unknown`
/// rather than TSMP and slips past this particular check — only to be dropped one step later by the
/// outbound ACL, whose `pre()` refuses `ipproto.Unknown` outright. This tree has no outbound ACL at
/// all, so there is no second refusal to fall through to; testing the header's protocol byte
/// reaches Go's *net* verdict (nothing carrying proto 99 leaves the host) in one step instead of
/// two. Concretely, three shapes are dropped here that Go's TSMP arm alone would not:
///
/// - an IPv4 TSMP packet that is fragmented, truncated, or shorter than `minTSMPSize`;
/// - an IPv6 packet whose Fragment extension header names TSMP but whose first fragment is too
///   short to hold a TSMP body;
/// - a *later* IPv6 fragment of a TSMP datagram (Go classifies it `ipproto.Fragment` and does put
///   it on the wire). This is the one shape Go sends and we do not, and it is unreachable in
///   practice: its head fragment is dropped by Go and by us alike, so no peer could ever reassemble
///   the datagram, and nothing in a Tailscale node ever emits a fragmented TSMP message in the
///   first place. No real peer can be relying on one arriving.
///
/// A Fragment header reached through a *chained* extension header (hop-by-hop, routing, destination
/// options) is deliberately not chased: Go's `decode6` only steps over a Fragment header that is the
/// base header's immediate Next Header, so such a packet decodes to `ipproto.Unknown` at every
/// Tailscale receiver — including [`ts_packet::tsmp::DiscoKeyAdvertisement::parse`] here — and is
/// discarded rather than read as a control message. It is not a forgery vector.
fn outbound_packet_carries_tsmp(b: &[u8]) -> bool {
    match b.first().map(|first| first >> 4) {
        // Go `decode4`: `q.IPProto = ipproto.Proto(b[9])`.
        Some(4) => b.len() >= IP4_HEADER_LEN && b[9] == ts_packet::tsmp::IP_PROTO_TSMP,
        Some(6) => {
            if b.len() < IP6_HEADER_LEN {
                return false;
            }
            // Go `decode6`: `q.IPProto = ipproto.Proto(b[6])`, then step over a leading Fragment
            // extension header and take its Next Header instead. Every fragment of one datagram
            // repeats that Next Header, so this catches the head fragment (which is what Go's TSMP
            // arm catches) and its followers alike.
            match b[6] {
                ts_packet::tsmp::IP_PROTO_TSMP => true,
                IP6_FRAG_HEADER => b
                    .get(IP6_HEADER_LEN)
                    .is_some_and(|next| *next == ts_packet::tsmp::IP_PROTO_TSMP),
                _ => false,
            }
        }
        // Not an IP packet at all: `or_out.route` drops it a moment later for want of a
        // destination address. Nothing to classify.
        _ => false,
    }
}

/// The UDP or SCTP flow an outbound packet belongs to — `(proto, src, dst)` with the packet's own
/// source and destination — or `None` for anything Go's `UpdateOutboundFlowState` switch would not
/// record. The caller hands it to [`flowtrack::FlowCache::record_outbound`], which stores the
/// reverse.
///
/// This is Go's `net/packet.Parsed.decode4`/`decode6` narrowed to the two protocols that switch has
/// arms for, and it keeps that decoder's refusals rather than guessing:
///
/// - **The protocol comes from the base header only** — `decode4`'s `b[9]`, `decode6`'s `b[6]` —
///   so an IPv6 packet behind a chained extension header is not recorded even though etherparse can
///   walk to its UDP header. Go never reaches that header either, so recording it would be this
///   tree inventing a flow upstream does not track.
/// - **A non-first IPv4 fragment is not a flow.** `decode4` classifies it `ipproto.Fragment`, which
///   matches neither arm of Go's switch; it also has no transport header, so its ports would be
///   invented.
/// - **A leading IPv6 Fragment header is stepped over**, exactly as `decode6` does, so the *first*
///   fragment of an outbound datagram records the same tuple an unfragmented one would.
/// - **A truncated SCTP common header records nothing** (Go's `q.IPProto = unknown`), rather than
///   recording a flow on ports read as 0 — an entry keyed on port 0 would admit inbound SCTP that
///   no outbound packet ever justified.
fn outbound_udp_or_sctp_flow(
    b: &[u8],
) -> Option<(IpProto, std::net::SocketAddr, std::net::SocketAddr)> {
    let pkt = etherparse::SlicedPacket::from_ip(b).ok()?;

    // Go's `sub`: the bytes from the sub-protocol header onwards. Only the SCTP arm reads it,
    // because etherparse's `TransportSlice` has no SCTP variant.
    let sub = match &pkt.net {
        Some(etherparse::NetSlice::Ipv4(ipv4)) => ipv4.payload().payload,
        Some(etherparse::NetSlice::Ipv6(ipv6)) => ipv6.payload().payload,
        _ => &[][..],
    };

    let (proto, src_ip, dst_ip, v6_first_fragment_ports) = match &pkt.net {
        Some(etherparse::NetSlice::Ipv4(ipv4)) => {
            let hdr = ipv4.header();
            if hdr.fragments_offset().value() > 0 {
                return None;
            }
            (
                IpProto::new(i64::from(ipv4.payload().ip_number.0)),
                std::net::IpAddr::from(hdr.source_addr()),
                std::net::IpAddr::from(hdr.destination_addr()),
                None,
            )
        }
        Some(etherparse::NetSlice::Ipv6(ipv6)) => {
            let hdr = ipv6.header();
            let src_ip = std::net::IpAddr::from(hdr.source_addr());
            let dst_ip = std::net::IpAddr::from(hdr.destination_addr());
            if hdr.next_header().0 == IP6_FRAG_HEADER {
                // Go `decode6Fragment`: a first fragment yields the real sub-protocol and its
                // ports; a later or malformed one yields no flow at all.
                let Ipv6Fragment::First {
                    proto,
                    src_port,
                    dst_port,
                    // The flow cache keys on Go's `flowtrack.Tuple` — proto and both address/port
                    // pairs — and nothing else, so the L4 header is not part of an outbound flow.
                    l4: _,
                } = decode6_fragment(b)
                else {
                    return None;
                };
                (proto, src_ip, dst_ip, Some((src_port, dst_port)))
            } else {
                (
                    IpProto::new(i64::from(hdr.next_header().0)),
                    src_ip,
                    dst_ip,
                    None,
                )
            }
        }
        // Not an IP packet at all; `or_out.route` drops it a moment later for want of a
        // destination address.
        _ => return None,
    };

    /// Go `net/packet.udpHeaderLength`.
    const UDP_HEADER_LEN: usize = 8;

    // Go's `decode4`/`decode6` read both ports straight out of `sub` — `sub[0:2]` and `sub[2:4]` —
    // after a bounds check, for exactly the protocols below. Reading them here rather than from
    // etherparse's `TransportSlice` is not a shortcut: etherparse deliberately refuses to descend
    // into a fragmenting payload, so a *first* IPv4 fragment would otherwise surface no ports at
    // all, where Go reads them and records the flow like an unfragmented datagram's.
    let (src_port, dst_port) = match (proto, v6_first_fragment_ports) {
        (IpProto::UDP | IpProto::SCTP, Some(ports)) => ports,
        (IpProto::UDP, None) => {
            if sub.len() < UDP_HEADER_LEN {
                return None;
            }
            (
                u16::from_be_bytes([sub[0], sub[1]]),
                u16::from_be_bytes([sub[2], sub[3]]),
            )
        }
        (IpProto::SCTP, None) => sctp_ports(sub)?,
        // Every other protocol: Go's switch has no arm for it, so nothing is recorded.
        _ => return None,
    };

    Some((
        proto,
        std::net::SocketAddr::new(src_ip, src_port),
        std::net::SocketAddr::new(dst_ip, dst_port),
    ))
}

/// A data plane subsystem that can be the subject of timer events.
pub enum Subsystem {
    /// The wireguard component.
    Wireguard,
}

/// The direction/path of a captured packet, mirroring Go Tailscale's `capture.Path`. The numeric
/// values are the on-wire path codes written into each pcap record's Tailscale preamble.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapturePath {
    /// A packet from the local device, heading out to a peer (pre-encrypt).
    FromLocal = 0,
    /// A packet received from a peer, decrypted, heading to the local device.
    FromPeer = 1,
    /// A packet synthesized by us toward the local device. Retained for Go `capture.Path` on-wire
    /// code parity (so captured pcap path codes match Go's, and a future synthesized-packet tee
    /// point can emit it); not currently emitted — the tee only produces `FromLocal`/`FromPeer`.
    SynthesizedToLocal = 2,
    /// A packet synthesized by us toward a peer. Retained for Go `capture.Path` on-wire code parity
    /// (see [`Self::SynthesizedToLocal`]); not currently emitted.
    SynthesizedToPeer = 3,
}

impl CapturePath {
    /// The on-wire path code (the `uint16` written into the pcap record preamble).
    pub fn code(self) -> u16 {
        self as u16
    }
}

/// A debug packet-capture hook. When installed on a [`DataPlane`], it is invoked with the path and
/// the raw IP packet bytes for every plaintext packet crossing the datapath. It must be cheap and
/// non-blocking — it runs inline on the single-threaded dataplane step, so a slow hook backs up the
/// datapath. Wrapped in `Arc` so it is cheap to clone and `Send + Sync` for the actor that installs
/// it.
pub type CaptureHook = std::sync::Arc<dyn Fn(CapturePath, &[u8]) + Send + Sync>;

/// Transforms packets to make tailscale happen.
pub struct DataPlane {
    /// Wireguard encryption/decryption.
    pub wireguard: Endpoint,

    /// Outbound overlay router.
    pub or_out: or::outbound::Router,
    /// Outbound underlay router.
    pub ur_out: ur::outbound::Router,

    /// Inbound source filter.
    pub src_filter_in: Arc<ts_bart::Table<PeerId>>,
    /// Inbound overlay router.
    pub or_in: or::inbound::Router,

    /// The packet filter.
    pub packet_filter: Arc<dyn ts_packetfilter::Filter + Send + Sync>,

    /// Events queued for future processing.
    pub events: Scheduler<Subsystem>,

    /// Next event for the wireguard subsystem.
    pub wg_next: Option<Handle<Subsystem>>,

    /// Optional debug packet-capture hook (Go `tstun.Wrapper` capture hook). `None` (the default)
    /// means no capture and zero datapath overhead. Installed/cleared at runtime by the dataplane
    /// actor; see [`DataPlane::process_outbound`]/[`DataPlane::process_inbound`] for the tee points.
    pub capture: Option<CaptureHook>,

    /// Reverse-flow connection tracking for outbound UDP and SCTP, so a peer's reply to a
    /// datagram this node sent is admitted without an ACL rule naming our ephemeral source port
    /// (Go `filter.Filter.state`). Filled by [`DataPlane::process_outbound`] and consulted by the
    /// inbound filter; bounded at Go's `lruMax`. Private because it is derived datapath state, not
    /// configuration — nothing outside this crate has anything to set it to.
    flows: flowtrack::FlowCache,

    /// Netmap snapshot for the TSMP disco-key advertisement this node sends on session
    /// establishment (Go capability version 144). `None` (the default) advertises nothing at all,
    /// which is what an embedder that never populates it gets — the same position this fork was in
    /// before the send side existed, and still fully interoperable, since a peer's own
    /// advertisement is unsolicited. Refreshed from the netmap by the runtime's dataplane actor.
    pub disco_advertisement: Option<Arc<DiscoAdvertisementState>>,

    /// The TCP port this node's peerAPI listens on, if it runs one (Go `tstun.Wrapper.PeerAPIPort`).
    /// Read only when a dropped packet is about to be answered with a TSMP rejected-connection
    /// message: a SYN to the peerAPI port never produces one, because upstream's peerAPI carve-out
    /// has already flipped it back to `Accept` by that point. See `tsmp_reject_for_drop`.
    ///
    /// `None` (the default) means no peerAPI, and is also what an embedder that never sets it gets
    /// — the same position this fork was in before the message existed. Refreshed by the runtime's
    /// dataplane actor.
    pub peerapi_port: Option<u16>,

    /// Go `tstun.Wrapper.disableTSMPRejected`: when `true`, an ACL drop tells the peer nothing.
    /// `false` (the default) is upstream's default and the interoperable one — a Go peer expects
    /// to be told.
    pub disable_tsmp_rejected: bool,
}

impl DataPlane {
    /// Creates a new data plane for a wireguard node key.
    pub fn new(my_key: NodeKeyPair) -> Self {
        DataPlane {
            wireguard: Endpoint::new(my_key),
            or_out: Default::default(),
            ur_out: Default::default(),
            src_filter_in: Default::default(),
            or_in: Default::default(),
            events: Default::default(),
            packet_filter: Arc::new(ts_packetfilter::DropAllFilter),
            wg_next: None,
            capture: None,
            flows: flowtrack::FlowCache::default(),
            disco_advertisement: None,
            peerapi_port: None,
            disable_tsmp_rejected: false,
        }
    }

    /// Processes packets originating from the local device.
    ///
    /// Packets carrying TSMP are refused here (Go `tstun.filterPacketOutboundToWireGuard`): the
    /// inter-node control channel must only ever carry messages this node built, never bytes a host
    /// process handed us. See `outbound_packet_carries_tsmp` for why, and for the one shape Go
    /// forwards that this refuses.
    #[tracing::instrument(skip_all, fields(n_packets = packets.len()))]
    pub fn process_outbound(&mut self, mut packets: Vec<PacketMut>) -> OutboundResult {
        // The capture tee runs first, and so still sees the packets dropped just below — Go tees to
        // its capture hook in `Wrapper.Read` before calling the outbound filter, so a pcap taken on
        // either implementation shows the refused packet.
        if let Some(hook) = &self.capture {
            for p in &packets {
                hook(CapturePath::FromLocal, p.as_ref());
            }
        }

        packets.retain(|p| {
            if outbound_packet_carries_tsmp(p.as_ref()) {
                tracing::debug!("[unexpected] TSMP packet written into the tun; dropping");
                metric_out_to_wg_drop_tsmp().inc();
                return false;
            }
            true
        });

        // Go `filter.Filter.UpdateOutboundFlowState`, called from `RunOut` for every packet read
        // off the TUN and — since upstream `e0677ccc7` — from `net/tstun`'s injected path too,
        // because packets produced by netstack never pass `RunOut` and "a netstack-side dial of UDP
        // would send fine but the reply would be dropped as `no matching rule`". Every outbound
        // packet in this engine comes from the netstack, so this is that call site. It runs after
        // the TSMP refusal above, matching Go's order in `filterPacketOutboundToWireGuard`, and
        // before `or_out.route` consumes the batch.
        for p in &packets {
            if let Some((proto, src, dst)) = outbound_udp_or_sctp_flow(p.as_ref()) {
                self.flows.record_outbound(proto, src, dst);
            }
        }

        let or::outbound::Result {
            to_wireguard,
            loopback,
        } = self.or_out.route(packets);

        let to_wireguard = to_wireguard
            .into_iter()
            .map(|(k, v)| (ts_tunnel::PeerId(k.0), v))
            .collect::<Vec<_>>();

        let ts_tunnel::SendResult {
            to_peers: encrypted,
        } = self.wireguard.send(to_wireguard);

        let to_peers = self
            .ur_out
            .route(encrypted.into_iter().map(|(k, v)| (PeerId(k.0), v)));

        if let Some(next) = self.wireguard.next_event()
            && let Some(prev) = self
                .wg_next
                .replace(self.events.add(next, Subsystem::Wireguard))
        {
            prev.cancel();
        }

        OutboundResult { to_peers, loopback }
    }

    /// Processes packets received from elsewhere, with no information about which peer sent them.
    ///
    /// Equivalent to [`DataPlane::process_inbound_from`] with no attribution; see there for what
    /// the attribution buys.
    pub fn process_inbound(
        &mut self,
        packets: impl IntoIterator<Item = PacketMut>,
    ) -> InboundResult {
        self.process_inbound_from(None, packets)
    }

    /// Processes packets an underlay transport received and attributed to peer `from`.
    ///
    /// The attribution is what lets the WireGuard layer answer a handshake initiation with a
    /// cookie while it is under load: the reply has to go back where the initiation came from, and
    /// in this stack that origin is a peer, not a source address. See
    /// [`ts_tunnel::Endpoint::recv_from`].
    pub fn process_inbound_from(
        &mut self,
        from: Option<PeerId>,
        packets: impl IntoIterator<Item = PacketMut>,
    ) -> InboundResult {
        let ts_tunnel::RecvResult {
            to_local,
            to_peers,
            sessions_established,
        } = self
            .wireguard
            .recv_from(from.map(|p| ts_tunnel::PeerId(p.0)), packets);

        if let Some(hook) = &self.capture {
            for packets in to_local.values() {
                for p in packets {
                    hook(CapturePath::FromPeer, p.as_ref());
                }
            }
        }

        // The TSMP messages this batch consumes or synthesizes (Go `tstun.Wrapper`'s
        // `discoKeyAdvertisementPub` publisher, its `trackOpenPreFilterIn` hook, and its
        // `InjectOutbound` of a rejected-connection reply). Filled in by the packet-filter stage
        // below, which is the point at which a packet has both been attributed to a peer and been
        // decoded far enough to know it is TSMP.
        let mut harvest = InboundHarvest::default();

        // Hoisted out of the filter closure below, which borrows `self.flows` mutably.
        let reject_cfg = RejectConfig {
            disabled: self.disable_tsmp_rejected,
            peerapi_port: self.peerapi_port,
        };

        let to_local = to_local
            .into_iter()
            .map(|(peer_id, mut packets)| -> (PeerId, Vec<PacketMut>) {
                let _span = tracing::trace_span!(
                    "src_filter_inbound",
                    peer_id = ?peer_id,
                    n_packet = packets.len(),
                )
                .entered();

                packets.retain(|packet| {
                    let Some(src) = packet.get_src_addr() else {
                        tracing::trace!("does not look like ip packet");
                        return false;
                    };
                    let verdict = if let Some(allowed_peer) = self.src_filter_in.lookup(src) {
                        *allowed_peer == PeerId(peer_id.0)
                    } else {
                        tracing::trace!(remote_ip = %src, "unknown peer address");
                        false
                    };
                    tracing::trace!(?src, verdict);
                    verdict
                });

                (PeerId(peer_id.0), packets)
            })
            .map(|(peer_id, mut v)| {
                let _span = tracing::trace_span!(
                    "packet_filter_inbound",
                    peer_id = ?peer_id,
                    n_packet = v.len()
                )
                .entered();

                filter_inbound_from_peer(
                    self.packet_filter.as_ref(),
                    &mut self.flows,
                    peer_id,
                    &mut v,
                    reject_cfg,
                    &mut harvest,
                );

                v
            })
            // Forced here rather than left lazy: the TSMP rejected-connection replies the filter
            // stage synthesizes have to be encrypted and merged into `to_peers` below, and that
            // cannot happen while the iterator that produces them is still unconsumed.
            .collect::<Vec<_>>();

        // TSMP disco-key advertisement, send side (Go capability version 144). wireguard-go calls
        // `peer.SendPriorityMessage()` the moment a keypair becomes current for forward
        // transmission — on the initiator when the handshake response lands, and on the responder
        // when the first transport packet authenticates on the new keypair (`device/receive.go`).
        // `sessions_established` is exactly those two moments; the message is Go's
        // `magicsock.Conn.PriorityMessageForPeer` return value. A peer we must not advertise to
        // (see [`DiscoAdvertisementState::advertisement_for`]) simply gets nothing, and the fresh
        // session is otherwise untouched.
        let mut to_peers = to_peers;

        // TSMP rejected-connection replies, send side (Go `tstun.Wrapper.InjectOutbound`, called
        // from `filterPacketInboundFromWireGuard` on an ACL drop). Each goes to the peer whose own
        // packet was dropped — the peer whose session decrypted it, which the source filter has
        // already bound to that packet's source address, so this is the same node Go reaches by
        // routing the injected packet on its destination IP.
        //
        // These deliberately bypass `process_outbound`'s TSMP refusal: that refusal exists to stop
        // a *host process* writing TSMP into the tun, and upstream's injected packets skip the
        // outbound filter for the same reason.
        if !harvest.rejects_to_send.is_empty() {
            let mut by_peer: HashMap<ts_tunnel::PeerId, Vec<PacketMut>> = HashMap::new();
            for (peer, packet) in std::mem::take(&mut harvest.rejects_to_send) {
                by_peer
                    .entry(ts_tunnel::PeerId(peer.0))
                    .or_default()
                    .push(packet);
            }
            let ts_tunnel::SendResult { to_peers: sealed } = self.wireguard.send(by_peer);
            for (peer, packets) in sealed {
                to_peers.entry(peer).or_default().extend(packets);
            }
        }

        if let Some(advert) = self.disco_advertisement.clone() {
            // Held apart from what `recv` already queued for these peers so it can be spliced in
            // FRONT of it below, rather than appended behind it.
            let mut priority: HashMap<ts_tunnel::PeerId, Vec<PacketMut>> = HashMap::new();
            for peer in sessions_established {
                let Some(msg) = advert.advertisement_for(PeerId(peer.0)) else {
                    continue;
                };
                tracing::debug!(peer_id = ?peer, "advertising our disco key over TSMP");
                for (peer, packets) in self.wireguard.send_priority_message(peer, &msg).to_peers {
                    priority.entry(peer).or_default().extend(packets);
                }
            }
            // A priority message leads the traffic the same establishment released. wireguard-go
            // hands it straight to the peer's *outbound* queue (`SendPriorityMessage` →
            // `queueOutboundIfRunning`), never to the staged queue, and both call sites run it
            // before the flush that follows — `peer.SendPriorityMessage()` ahead of
            // `peer.SendKeepalive()` on the initiator and ahead of `peer.SendStagedPackets()` on
            // the responder (`device/receive.go`). Here the flush has already happened inside
            // [`Endpoint::recv`] (`activate` encrypts whatever was queued), so restoring Go's wire
            // order means splicing the advertisement in front of it.
            //
            // Only the wire order is restored, not Go's nonce order: those flushed packets were
            // sealed first and so hold the lower nonces, where Go would have numbered the priority
            // message first. That is invisible to the peer. A WireGuard receiver accepts an
            // earlier counter after a later one by construction, and the inversion is bounded by
            // the send queue a session flushes on activation (`MAX_QUEUED_PER_PEER`, 32 packets) —
            // two orders of magnitude inside the 8128-packet anti-replay window WireGuard
            // receivers carry (`ts_tunnel`'s `ReplayWindow::WINDOW_SIZE`, wireguard-go parity).
            for (peer, mut packets) in priority {
                let queued = to_peers.entry(peer).or_default();
                packets.append(queued);
                *queued = packets;
            }
        }

        let to_peers = to_peers
            .into_iter()
            .map(|(k, v)| (ts_transport::PeerId(k.0), v));

        let to_local = self.or_in.route(to_local.into_iter().flatten());
        let to_peers = self.ur_out.route(to_peers);

        if let Some(next) = self.wireguard.next_event()
            && let Some(prev) = self
                .wg_next
                .replace(self.events.add(next, Subsystem::Wireguard))
        {
            prev.cancel();
        }

        InboundResult {
            to_local,
            to_peers,
            learned_disco_keys: harvest.learned_disco_keys,
            rejected_flows: harvest.rejected_flows,
        }
    }

    /// Return the next time at which [`DataPlane::process_events`] must be called.
    ///
    /// [`DataPlane::process_outbound`], [`DataPlane::process_inbound`] and
    /// [`DataPlane::process_events`] may all update the next event time. Callers should prefer
    /// calling `next_event` as needed to get a correct result, rather than store the returned
    /// value.
    pub fn next_event(&self) -> Option<Instant> {
        self.events.next_dispatch()
    }

    /// Process all queued events that are due for processing.
    ///
    /// Must be called at least as often as dictated by [`DataPlane::next_event`] for the
    /// data plane to function correctly. It is harmless to call it more frequently.
    pub fn process_events(&mut self) -> EventResult {
        let mut to_peers = HashMap::new();
        let now = Instant::now();
        for event in self.events.dispatch(now) {
            match event {
                Subsystem::Wireguard => {
                    let res = self.wireguard.dispatch_events(now);
                    to_peers.extend(
                        res.to_peers
                            .into_iter()
                            .map(|(id, pkts)| (ts_transport::PeerId(id.0), pkts)),
                    );
                }
            }
        }
        let to_peers = self.ur_out.route(to_peers);

        if let Some(next) = self.wireguard.next_event()
            && let Some(prev) = self
                .wg_next
                .replace(self.events.add(next, Subsystem::Wireguard))
        {
            prev.cancel();
        }

        EventResult { to_peers }
    }
}

/// The result of processing outbound packets.
pub struct OutboundResult {
    /// Packets to be sent into underlay transports for transmission.
    pub to_peers: HashMap<(UnderlayTransportId, PeerId), Vec<PacketMut>>,
    /// Packets to be looped back and delivered to overlay transports.
    pub loopback: HashMap<OverlayTransportId, Vec<PacketMut>>,
}

/// The result of processing inbound packets.
pub struct InboundResult {
    /// Decrypted packets to be delivered to overlay transports.
    pub to_local: HashMap<OverlayTransportId, Vec<PacketMut>>,
    /// Encrypted packets to be sent to wireguard peers by the underlay.
    pub to_peers: HashMap<(UnderlayTransportId, PeerId), Vec<PacketMut>>,
    /// Disco keys peers advertised over TSMP in this batch, each paired with the WireGuard peer
    /// whose session carried it (Go `tstun.Wrapper` publishing `events.PeerDiscoKeyUpdate`, which
    /// `wgengine` turns into a `magicsock.Conn.HandleDiscoKeyAdvertisement` call).
    ///
    /// The advertisement packets themselves are dropped: they are inter-node control messages, not
    /// traffic for the local stack. Zero keys are already filtered out. Empty for a batch that
    /// carried none, which is the overwhelmingly common case.
    pub learned_disco_keys: Vec<(PeerId, ts_packet::tsmp::DiscoKeyAdvertisement)>,
    /// Connections peers refused, as they told us over TSMP (Go `packet.TailscaleRejectedHeader`,
    /// which `wgengine.userspaceEngine.trackOpenPreFilterIn` matches against its pending-open
    /// flows), each paired with the WireGuard peer whose session carried it.
    ///
    /// This engine is always the dialing client, so this is the answer to a connection *this node*
    /// opened: without it a dial into a peer's ACL drop waits out a TCP timeout with no reason
    /// available anywhere. `src` is this node's own address and ephemeral port and `dst` is the
    /// peer's, so an embedder can match the message against the flow it opened;
    /// [`maybe_broken`](ts_packet::tsmp::TailscaleRejectedHeader::maybe_broken) says whether the
    /// refusal is terminal.
    ///
    /// The messages themselves are dropped rather than delivered — they are inter-node control
    /// messages, and the local stack has no handler for IP protocol 99. Empty for a batch that
    /// carried none, which is the overwhelmingly common case.
    pub rejected_flows: Vec<(PeerId, ts_packet::tsmp::TailscaleRejectedHeader)>,
}

/// The result of processing an event.
#[derive(Default)]
pub struct EventResult {
    /// Encrypted packets to be sent to wireguard peers by the underlay.
    pub to_peers: HashMap<(UnderlayTransportId, PeerId), Vec<PacketMut>>,
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// Records `(path, bytes)` for each capture-hook invocation in a test.
    type CaptureLog = Arc<Mutex<Vec<(CapturePath, Vec<u8>)>>>;

    /// [`inbound_filter_verdict`] against an **empty** flow cache and with **no decoded L4 header**,
    /// which is the verdict for a packet that is not a reply to anything this node sent. Every case
    /// that predates the reverse-flow cache is exactly that case, so they all go through here and
    /// stay pinned to the stateless decision; the tests that do record an outbound flow call
    /// `inbound_filter_verdict` directly.
    ///
    /// [`ts_packetfilter::L4Header::Unknown`] is also the assertion that the reply carve-outs fail
    /// closed: a TCP packet whose flags were never read must still face the rules here, and it does.
    fn stateless_verdict(
        filter: &(dyn ts_packetfilter::Filter + Send + Sync),
        proto: IpProto,
        src: std::net::IpAddr,
        dst: std::net::IpAddr,
        dst_port: u16,
        frag: Option<Fragment>,
    ) -> bool {
        inbound_filter_verdict(
            filter,
            &mut flowtrack::FlowCache::default(),
            proto,
            std::net::SocketAddr::new(src, 0),
            std::net::SocketAddr::new(dst, dst_port),
            ts_packetfilter::L4Header::Unknown,
            frag,
        )
    }

    #[test]
    fn capture_path_codes() {
        assert_eq!(CapturePath::FromLocal.code(), 0);
        assert_eq!(CapturePath::FromPeer.code(), 1);
        assert_eq!(CapturePath::SynthesizedToLocal.code(), 2);
        assert_eq!(CapturePath::SynthesizedToPeer.code(), 3);
    }

    /// The pre-rule destination screen (Go filter `pre()`): multicast and non-allowlisted link-local
    /// destinations are dropped before the ACL; ordinary unicast and the cloud-metadata link-local
    /// exception pass through to the rules.
    #[test]
    fn pre_rule_drop_matches_go() {
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        // Dropped pre-rules:
        assert!(drop_before_rules(ip("224.0.0.1")), "IPv4 multicast dropped");
        assert!(
            drop_before_rules(ip("239.255.255.250")),
            "IPv4 multicast (SSDP) dropped"
        );
        assert!(
            drop_before_rules(ip("169.254.1.1")),
            "IPv4 link-local dropped"
        );
        assert!(drop_before_rules(ip("ff02::1")), "IPv6 multicast dropped");
        assert!(drop_before_rules(ip("fe80::1")), "IPv6 link-local dropped");
        assert!(
            drop_before_rules(ip("febf:ffff::1")),
            "top of fe80::/10 dropped (locks the 0xffc0/0xfe80 mask)"
        );
        // Passed through to the rules:
        assert!(
            !drop_before_rules(ip("fec0::1")),
            "just past fe80::/10 passes (locks the 0xffc0/0xfe80 mask)"
        );
        // IPv4-mapped-IPv6 destinations match NEITHER arm and fall through to the ACL, exactly as
        // Go's `netip.Addr` predicates do (no unmap/canonicalize). Pinning this guards against a
        // future "canonicalize to be safe" refactor silently diverging from Go.
        assert!(
            !drop_before_rules(ip("::ffff:224.0.0.1")),
            "4in6-mapped multicast falls through to the ACL, matching Go"
        );
        assert!(
            !drop_before_rules(ip("::ffff:169.254.1.1")),
            "4in6-mapped link-local falls through to the ACL, matching Go"
        );
        assert!(
            !drop_before_rules(ip("100.64.0.5")),
            "ordinary tailnet unicast passes"
        );
        assert!(
            !drop_before_rules(ip("8.8.8.8")),
            "ordinary public unicast passes"
        );
        assert!(
            !drop_before_rules(ip("169.254.169.254")),
            "the cloud-metadata link-local address is the Go-allowlisted exception"
        );
        assert!(
            !drop_before_rules(ip("fd7a:115c:a1e0::1")),
            "IPv6 ULA (tailnet) passes"
        );
    }

    /// A filter that drops everything (returns `None` for every packet). Lets a test prove that TSMP
    /// is admitted by bypassing the ACL — not by the ACL happening to allow it.
    struct DenyAll;
    impl ts_packetfilter::Filter for DenyAll {
        fn match_for(
            &self,
            _info: &ts_packetfilter::PacketInfo,
            _caps: ts_packetfilter::filter::CapIter,
        ) -> Option<&str> {
            None
        }
    }

    /// The inbound proto-switch (Go `runIn4`/`runIn6`): TSMP is always admitted, bypassing the ACL;
    /// `pre()` drops still win over TSMP; non-TSMP defers to the ACL.
    #[test]
    fn tsmp_bypasses_acl_matches_go() {
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        let src = ip("100.64.0.9");
        let dst = ip("100.64.0.1");
        let tsmp = IpProto::new(99);

        // TSMP is accepted even though the ACL denies everything — Go `case TSMP: return Accept`.
        assert!(
            stateless_verdict(&DenyAll, tsmp, src, dst, 0, None),
            "TSMP admitted by bypassing the (deny-all) ACL"
        );
        // A non-TSMP proto under the same deny-all ACL is dropped — proves the bypass is TSMP-specific.
        assert!(
            !stateless_verdict(&DenyAll, IpProto::TCP, src, dst, 443, None),
            "TCP still consults the ACL (deny-all → dropped)"
        );
        // `pre()` drops outrank the TSMP accept: TSMP to a multicast/link-local dst is still dropped,
        // exactly as Go runs `pre()` before the proto switch.
        assert!(
            !stateless_verdict(&DenyAll, tsmp, src, ip("224.0.0.1"), 0, None),
            "TSMP to a multicast dst is still dropped (pre() before the switch)"
        );
        assert!(
            !stateless_verdict(&DenyAll, tsmp, src, ip("169.254.1.1"), 0, None),
            "TSMP to a link-local dst is still dropped (pre() before the switch)"
        );
        // IpProto::TSMP is the named constant for proto 99.
        assert_eq!(IpProto::TSMP, tsmp, "IpProto::TSMP == 99");
    }

    /// IPv4 fragment handling, mirroring Go `net/packet.decode4` + filter `pre()`:
    /// - a valid later fragment (offset ≥ `MIN_FRAG_BLKS`) is ACCEPTED ahead of the ACL (Go maps it
    ///   to `ipproto.Fragment`, which `pre()` admits) — even under a deny-all ACL and even though its
    ///   parsed port is 0, which a normal rule would never match;
    /// - a low-offset later fragment (offset < `MIN_FRAG_BLKS`) is DROPPED (RFC 1858);
    /// - a first fragment (offset 0) defers to the normal proto-switch/ACL on its real port;
    /// - a *fragmented* TSMP first fragment (offset 0, MF set) is DROPPED (Go disallows it), unlike a
    ///   non-fragmented TSMP which bypasses the ACL.
    #[test]
    fn ipv4_fragment_handling_matches_go_decode4() {
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        let src = ip("100.64.0.9");
        let dst = ip("100.64.0.1");
        let frag = |offset_blocks: u16, more_fragments: bool| {
            Some(Fragment::V4(Ipv4Fragment {
                offset_blocks,
                more_fragments,
            }))
        };

        // A valid later fragment is accepted under a DENY-ALL ACL with port 0 — proves the accept is
        // the Go `pre()` Fragment pass-through, not the ACL happening to allow it.
        assert!(
            stateless_verdict(
                &DenyAll,
                IpProto::TCP,
                src,
                dst,
                0,
                frag(MIN_FRAG_BLKS, false)
            ),
            "a valid later fragment (offset >= MIN_FRAG_BLKS) is accepted ahead of the ACL"
        );
        assert!(
            stateless_verdict(
                &DenyAll,
                IpProto::UDP,
                src,
                dst,
                0,
                frag(MIN_FRAG_BLKS + 50, true)
            ),
            "a later fragment well past the floor (MF set) is also accepted"
        );

        // A low-offset later fragment (could overlap a transport header) is dropped — RFC 1858.
        assert!(
            !stateless_verdict(
                &DenyAll,
                IpProto::TCP,
                src,
                dst,
                0,
                frag(MIN_FRAG_BLKS - 1, false)
            ),
            "a low-offset later fragment is dropped (RFC 1858)"
        );
        assert!(
            !stateless_verdict(&DenyAll, IpProto::TCP, src, dst, 0, frag(1, false)),
            "the smallest non-zero offset is dropped"
        );

        // A first fragment (offset 0) defers to the normal ACL on its real port: deny-all drops a
        // TCP first fragment, exactly as it drops a non-fragmented TCP packet.
        assert!(
            !stateless_verdict(&DenyAll, IpProto::TCP, src, dst, 443, frag(0, true)),
            "a first fragment defers to the ACL (deny-all -> dropped) on its parsed port"
        );

        // A fragmented TSMP first fragment (offset 0, MF set) is dropped — Go disallows it — even
        // though a non-fragmented TSMP bypasses the ACL.
        assert!(
            !stateless_verdict(&DenyAll, IpProto::TSMP, src, dst, 0, frag(0, true)),
            "a fragmented TSMP first fragment is dropped (Go parity)"
        );
        assert!(
            stateless_verdict(&DenyAll, IpProto::TSMP, src, dst, 0, frag(0, false)),
            "a non-fragmented TSMP (offset 0, MF clear) still bypasses the ACL"
        );

        // A *later* TSMP fragment (offset >= MIN_FRAG_BLKS) is accepted via the offset-based
        // fragment pass-through, NOT dropped by the fragmented-TSMP rule — that rule is offset-0
        // only (a first fragment with MF). This proves the later-fragment branch is proto-independent
        // and wins over the TSMP-specific logic (Go maps any offset>=minFragBlks to ipproto.Fragment
        // regardless of the L4 proto byte), locking the branch ordering against regression.
        assert!(
            stateless_verdict(
                &DenyAll,
                IpProto::TSMP,
                src,
                dst,
                0,
                frag(MIN_FRAG_BLKS, true)
            ),
            "a later TSMP fragment is accepted via the fragment path (proto-independent)"
        );
    }

    /// The head fragment of a fragmented IPv4/UDP datagram from `src` to `dst`: the same 8-byte UDP
    /// header an unfragmented datagram carries, plus the More-Fragments bit, plus the UDP length
    /// field a real sender writes — the length of the **whole** reassembled datagram, not of the
    /// piece on the wire. That is the shape etherparse hands over with `transport == None`, and the
    /// one Go `decode4` parses under `if fragOfs == 0`.
    fn v4_udp_first_fragment(
        src: std::net::SocketAddr,
        dst: std::net::SocketAddr,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut buf = v4_udp_packet(src, dst, payload);
        // Fragment offset 0, More Fragments set.
        buf[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        let whole_datagram = u16::try_from(8 + payload.len() + 512).unwrap();
        buf[24..26].copy_from_slice(&whole_datagram.to_be_bytes());
        buf
    }

    /// A fragmented reply to a UDP flow *this node* opened is admitted whole — head fragment
    /// included — with no rule naming it.
    ///
    /// A DNS answer larger than the 1280-byte overlay MTU arrives as a head fragment plus later
    /// ones. The later fragments were already accepted on their offset alone (Go `pre()`'s
    /// `ipproto.Fragment` pass-through), but the head fragment carries the ports, and it reached
    /// the reverse-flow cache with both of them 0 — so it missed the entry `process_outbound` had
    /// just recorded, was dropped as "no matching rule", and the pieces that did arrive could never
    /// be reassembled. Go `decode4` reads that header (`if fragOfs == 0`, the `case ipproto.UDP`
    /// arm) exactly as it reads an unfragmented datagram's.
    ///
    /// Ported from github.com/tailscale/tailscale `net/packet/packet.go` (`decode4`) and
    /// `wgengine/filter/filter.go` (`pre`, `runIn4`) at
    /// `9ea7cba44591e0cd840c6c94d23274dd222059bf`.
    #[test]
    fn a_fragmented_reply_to_our_own_udp_flow_is_admitted_head_fragment_included() {
        let peer = PeerId(1);
        let me = std::net::IpAddr::from([100, 64, 0, 1]);
        let them = std::net::IpAddr::from([100, 64, 0, 2]);
        let sa = |ip, port| std::net::SocketAddr::new(ip, port);
        let mut dp = dataplane_routing_to(peer, &[them]);

        let query = v4_udp_packet(sa(me, 41234), sa(them, 53), b"query");
        let head = v4_udp_first_fragment(sa(them, 53), sa(me, 41234), b"answer");
        // The rest of the same answer: a later fragment at a safe offset, carrying no header at all.
        let mut tail = head.clone();
        tail[6..8].copy_from_slice(&MIN_FRAG_BLKS.to_be_bytes());

        assert!(
            !admitted(&DenyAll, &mut dp.flows, head.clone()),
            "before we send anything the head fragment is unsolicited, and a deny-all ACL drops it"
        );

        let out = dp.process_outbound(vec![PacketMut::from(query)]);
        assert!(
            !out.to_peers.is_empty(),
            "the query really did route to the peer, so this is the live outbound path"
        );

        assert!(
            admitted(&DenyAll, &mut dp.flows, head),
            "the head fragment of the reply rides the flow we opened (Go's `Accept, \"cached\"`)"
        );
        assert!(
            admitted(&DenyAll, &mut dp.flows, tail),
            "its later fragments still pass on their offset alone"
        );
        assert!(
            !admitted(
                &DenyAll,
                &mut dp.flows,
                v4_udp_first_fragment(sa(them, 53), sa(me, 41235), b"x")
            ),
            "a head fragment to a port we never sent from is not carried by the entry"
        );
    }

    /// A first IPv4 fragment faces the rules — and the reply carve-outs — on the header it really
    /// carries, and is refused outright when it is too short to carry one.
    ///
    /// Go `decode4`, `if fragOfs == 0`: "Every protocol below MUST check that it has at least one
    /// entire transport header in order to protect against fragment confusion." A fragment cut off
    /// inside its own transport header is `q.IPProto = unknown`, which filter `pre()` drops before
    /// any rule is consulted — never a fallback to port 0, which an all-ports rule would admit
    /// while the follow-up fragments supplied the real header afterwards.
    ///
    /// Ported from github.com/tailscale/tailscale `net/packet/packet.go` (`decode4`) at
    /// `9ea7cba44591e0cd840c6c94d23274dd222059bf`.
    #[test]
    fn first_ipv4_fragment_is_decoded_like_go_decode4() {
        let flows = &mut flowtrack::FlowCache::default();
        let sa = |ip: std::net::Ipv4Addr, port| std::net::SocketAddr::new(ip.into(), port);
        let from = sa(IPV4_FIXTURE_SRC, 41234);

        // The ACL matches on the port the fragment carries, both ways round.
        assert!(
            admitted(
                &AllowPort(443),
                flows,
                v4_udp_first_fragment(from, sa(IPV4_FIXTURE_DST, 443), b"x")
            ),
            "a head fragment to an allowed port is admitted on the port it carries"
        );
        assert!(
            !admitted(
                &AllowPort(443),
                flows,
                v4_udp_first_fragment(from, sa(IPV4_FIXTURE_DST, 8443), b"x")
            ),
            "a head fragment to any other port is not — the port is read, not assumed"
        );

        // And the TCP flags byte with it, so the non-SYN carve-out applies to a fragmented segment
        // on exactly the terms it applies to an unfragmented one.
        let tcp_head = |flags| v4_packet(6, 0, true, &tcp_header(443, 41234, flags));
        assert!(
            admitted(&DenyAll, flows, tcp_head(TCP_SYN | TCP_ACK)),
            "a fragmented SYN-ACK takes the non-SYN carve-out"
        );
        assert!(
            !admitted(&DenyAll, flows, tcp_head(TCP_SYN)),
            "a fragmented SYN still faces the rules"
        );

        // Go's fragment-confusion refusal, asserted under an ALLOW-ALL ACL: the drop can only be
        // the bounds check, because there is no rule left to refuse it.
        for (why, packet) in [
            (
                "a UDP head fragment one byte short of its own header",
                v4_packet(17, 0, true, &udp_header(443)[..7]),
            ),
            (
                "a TCP head fragment one byte short of its own header",
                v4_packet(6, 0, true, &tcp_header(443, 41234, TCP_ACK)[..19]),
            ),
            (
                "an ICMP head fragment shorter than its four-byte header",
                v4_packet(1, 0, true, &icmp_header(0, 0)[..3]),
            ),
            (
                "an SCTP head fragment shorter than its common header",
                v4_packet(132, 0, true, &sctp_header(443, SCTP_HEADER_LEN - 1)),
            ),
        ] {
            assert!(!admitted(&AllowAll, flows, packet), "{why} is dropped");
        }
        // The controls: at full length every one of those is admitted by the same ACL, so the
        // drops above are the bounds checks and not the fixtures.
        for (why, packet) in [
            (
                "UDP",
                v4_udp_first_fragment(from, sa(IPV4_FIXTURE_DST, 443), b"x"),
            ),
            ("TCP", tcp_head(TCP_SYN)),
            ("ICMP", v4_packet(1, 0, true, &icmp_header(8, 0))),
            (
                "SCTP",
                v4_packet(132, 0, true, &sctp_header(443, SCTP_HEADER_LEN)),
            ),
        ] {
            assert!(
                admitted(&AllowAll, flows, packet),
                "a full-length {why} head fragment is admitted"
            );
        }

        // The decode itself, beside the verdicts it feeds: Go's `sub[0:2]`/`sub[2:4]` and
        // `sub[13]`, and its refusals.
        assert_eq!(
            decode4_first_fragment(IpProto::UDP, &udp_header(443)),
            Some((54276, 443, ts_packetfilter::L4Header::Unknown)),
            "`decode4`'s UDP arm reads both ports"
        );
        assert_eq!(
            decode4_first_fragment(IpProto::TCP, &tcp_header(443, 41234, TCP_SYN | TCP_ACK)),
            Some((
                443,
                41234,
                ts_packetfilter::L4Header::Tcp {
                    flags: TCP_SYN | TCP_ACK
                }
            )),
            "`decode4`'s TCP arm reads the flags byte beside the ports"
        );
        assert_eq!(
            decode4_first_fragment(IpProto::ICMP, &icmp_header(0, 0)),
            Some((
                0,
                0,
                ts_packetfilter::L4Header::Icmp {
                    icmp_type: 0,
                    icmp_code: 0
                }
            )),
            "`decode4`'s ICMPv4 arm reads the type/code and leaves both ports 0"
        );
        assert_eq!(
            decode4_first_fragment(IpProto::UDP, &udp_header(443)[..7]),
            None,
            "a short UDP header is Go's `unknown`, not a port-0 pass"
        );
        assert_eq!(
            decode4_first_fragment(IPPROTO_FRAGMENT_SENTINEL, &udp_header(443)),
            None,
            "Go's internal later-fragment sentinel seen on the wire is `unknown` too"
        );
        assert_eq!(
            decode4_first_fragment(IpProto::new(89), &udp_header(443)),
            Some((0, 0, ts_packetfilter::L4Header::Unknown)),
            "a protocol Go's switch has no arm for keeps its number and both ports 0"
        );
    }

    /// An ACL that admits everything, the shape a permissive "allow the whole tailnet" policy has.
    /// Under it, a DROP can only have come from a rule the filter applies *ahead* of the ACL — which
    /// is exactly what makes it the right control for the fragment classification's negative cases.
    struct AllowAll;
    impl ts_packetfilter::Filter for AllowAll {
        fn match_for(
            &self,
            _info: &ts_packetfilter::PacketInfo,
            _caps: ts_packetfilter::filter::CapIter,
        ) -> Option<&str> {
            Some("allow-all")
        }
    }

    /// An ACL that admits exactly one destination port. An admitted packet therefore proves the
    /// filter read that port off the wire — the point of Go `decode6` reaching past the Fragment
    /// extension header to the first fragment's real transport header.
    struct AllowPort(u16);
    impl ts_packetfilter::Filter for AllowPort {
        fn match_for(
            &self,
            info: &ts_packetfilter::PacketInfo,
            _caps: ts_packetfilter::filter::CapIter,
        ) -> Option<&str> {
            (info.port == self.0).then_some("allow-port")
        }
    }

    /// Source/destination for the IPv6 fixtures: RFC 3849 documentation addresses, standing in for
    /// the real ones upstream's `udp6*FragmentBuffer` fixtures use. Neither is multicast or
    /// link-local, so `drop_before_rules` never fires and every verdict below is the fragment
    /// classification's own.
    const IPV6_FIXTURE_SRC: std::net::Ipv6Addr =
        std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5);
    const IPV6_FIXTURE_DST: std::net::Ipv6Addr =
        std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

    /// The IPv6 packet a source-fragmenting host puts on the wire, in the shape of upstream's
    /// `udp6FirstFragmentBuffer` / `udp6NonFirstFragmentBuffer` fixtures (Go
    /// `net/packet/packet_test.go`): a 40-byte base header whose Next Header is the Fragment
    /// extension header (44), the 8-byte Fragment header itself, then `rest` — the real
    /// sub-protocol header on a first fragment, or continued payload on a later one.
    fn ipv6_fragment_packet(
        next_header: u8,
        offset_blocks: u16,
        more_fragments: bool,
        rest: &[u8],
    ) -> Vec<u8> {
        let mut buf = vec![0u8; IP6_HEADER_LEN + IP6_FRAG_HEADER_LEN + rest.len()];
        buf[0] = 0x60; // version 6, traffic class/flow label 0
        let payload_len = u16::try_from(IP6_FRAG_HEADER_LEN + rest.len()).unwrap();
        buf[4..6].copy_from_slice(&payload_len.to_be_bytes());
        buf[6] = IP6_FRAG_HEADER;
        buf[7] = 64; // hop limit
        buf[8..24].copy_from_slice(&IPV6_FIXTURE_SRC.octets());
        buf[24..40].copy_from_slice(&IPV6_FIXTURE_DST.octets());
        // Fragment extension header: Next Header, Reserved, offset<<3 | MF, Identification.
        buf[40] = next_header;
        let offset_field = (offset_blocks << 3) | u16::from(more_fragments);
        buf[42..44].copy_from_slice(&offset_field.to_be_bytes());
        buf[44..48].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        buf[48..].copy_from_slice(rest);
        buf
    }

    /// A plain, unfragmented IPv6 packet: the same 40-byte base header the fragment fixtures use,
    /// with `payload` sitting directly behind it as the protocol `next_header` names.
    fn ipv6_packet(next_header: u8, payload: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; IP6_HEADER_LEN + payload.len()];
        buf[0] = 0x60; // version 6, traffic class/flow label 0
        buf[4..6].copy_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
        buf[6] = next_header;
        buf[7] = 64; // hop limit
        buf[8..24].copy_from_slice(&IPV6_FIXTURE_SRC.octets());
        buf[24..40].copy_from_slice(&IPV6_FIXTURE_DST.octets());
        buf[IP6_HEADER_LEN..].copy_from_slice(payload);
        buf
    }

    /// A plain, unfragmented IPv6/UDP packet: [`ipv6_packet`] with UDP as its immediate Next
    /// Header. The control for the chained-extension-header fixtures below.
    fn ipv6_udp_packet(udp: &[u8]) -> Vec<u8> {
        let mut buf = ipv6_packet(17, udp);
        // Unlike a fragment fixture, this datagram is actually parsed as UDP, so its Length field
        // has to agree with the bytes present or etherparse rejects the packet outright.
        let udp_len = u16::try_from(udp.len()).unwrap();
        buf[IP6_HEADER_LEN + 4..IP6_HEADER_LEN + 6].copy_from_slice(&udp_len.to_be_bytes());
        buf
    }

    /// Push one 8-byte extension header of protocol `ext_proto` in front of `inner`'s payload, so
    /// whatever `inner`'s base header pointed at directly is now reached through a *chain*. The
    /// generic Next-Header / Hdr-Ext-Len-0 / six-bytes-of-body shape is the on-the-wire layout of
    /// Hop-by-Hop Options (0), Routing (43) and Destination Options (60) alike.
    ///
    /// Those six body bytes are chosen so the header is well formed under *every* one of those
    /// three readings, not merely one etherparse happens not to look at:
    ///
    /// - as Options (0 / 60) they are a TLV stream — `1, 0` is a zero-length PadN, and the four
    ///   trailing zeros are four Pad1s, filling the 8-byte header exactly;
    /// - as Routing (43) they are Routing Type 1, **Segments Left 0**, and four bytes of
    ///   type-specific data. Segments Left must stay 0: `Hdr Ext Len` is 0, so there is no room
    ///   for a single 16-byte segment, and RFC 8200 §4.4 has a receiver that meets a non-zero
    ///   Segments Left on an unrecognized Routing Type discard the packet and answer ICMP
    ///   Parameter Problem. etherparse walks a Routing header as a raw ext header and never reads
    ///   the field, so a non-zero value parses here today — but a fixture that only survives
    ///   because the parser is lenient is one parser release away from turning the negative
    ///   assertions below into vacuous passes.
    fn ipv6_with_prepended_ext_header(ext_proto: u8, inner: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(inner.len() + 8);
        buf.extend_from_slice(&inner[..IP6_HEADER_LEN]);
        // The header we are displacing becomes the extension header's Next Header.
        let displaced = buf[6];
        buf[6] = ext_proto;
        let payload_len = u16::try_from(inner.len() - IP6_HEADER_LEN + 8).unwrap();
        buf[4..6].copy_from_slice(&payload_len.to_be_bytes());
        buf.extend_from_slice(&[displaced, 0, 1, 0, 0, 0, 0, 0]);
        buf.extend_from_slice(&inner[IP6_HEADER_LEN..]);
        buf
    }

    /// An 8-byte UDP header carrying `dst_port`, as a first fragment's `rest`.
    fn udp_header(dst_port: u16) -> Vec<u8> {
        let mut hdr = vec![0u8; 8];
        hdr[0..2].copy_from_slice(&54276u16.to_be_bytes());
        hdr[2..4].copy_from_slice(&dst_port.to_be_bytes());
        hdr[4..6].copy_from_slice(&16u16.to_be_bytes());
        hdr
    }

    /// The IPv6 Fragment extension-header classification, mirroring Go
    /// `net/packet.Parsed.decode6Fragment` plus the sub-protocol switch `decode6` runs when it
    /// reports `continueDecode` (upstream `4c4ec3d46`, clarified by `26b2ed0a6`). Cases are
    /// upstream's own `TestDecode` fixtures: `ipv6_frag_first`, `ipv6_frag_nonfirst`,
    /// `ipv6_frag_short_first` and `ipv6_frag_small_offset`.
    #[test]
    fn ipv6_fragment_classification_matches_go_decode6() {
        // `ipv6_frag_first`: offset 0 with MF set, and a whole UDP header behind the fragment
        // header — Go steps over the 8 bytes and reads the ports, so the ACL matches this datagram
        // on the same rule it would match unfragmented.
        assert_eq!(
            decode6_fragment(&ipv6_fragment_packet(17, 0, true, &udp_header(443))),
            Ipv6Fragment::First {
                proto: IpProto::UDP,
                // `udp_header` writes 54276 as its source port; Go reads `sub[0:2]` for it, and the
                // reverse-flow cache is the only thing that consults it.
                src_port: 54276,
                dst_port: 443,
                // UDP is one of Go's port-ful arms and nothing else is read out of its header.
                l4: ts_packetfilter::L4Header::Unknown,
            },
            "a first fragment is decoded past the Fragment header, ports and all"
        );

        // `ipv6_frag_nonfirst`: a later fragment at offset 185 blocks has no transport header at
        // all, so Go marks it `ipproto.Fragment` for `pre()` to pass through.
        assert_eq!(
            decode6_fragment(&ipv6_fragment_packet(17, 185, false, &[0x61; 8])),
            Ipv6Fragment::Later,
            "a later fragment at a safe offset classifies as a pass-through fragment"
        );
        // The floor itself is safe; one block below it is not. `MIN_FRAG_BLKS` is the IPv4-sized
        // bound upstream deliberately reuses for IPv6 (Go `26b2ed0a6`).
        assert_eq!(
            decode6_fragment(&ipv6_fragment_packet(17, MIN_FRAG_BLKS, false, &[0x61; 8])),
            Ipv6Fragment::Later,
            "offset == MIN_FRAG_BLKS is the first accepted later fragment"
        );

        // `ipv6_frag_small_offset`: a later fragment whose bytes could land on top of the transport
        // header the head fragment was matched on — RFC 1858. Go rejects it as `unknown`.
        assert_eq!(
            decode6_fragment(&ipv6_fragment_packet(17, 1, false, &[0x61; 8])),
            Ipv6Fragment::Unknown,
            "a later fragment at offset 1 block is rejected (RFC 1858)"
        );
        assert_eq!(
            decode6_fragment(&ipv6_fragment_packet(
                17,
                MIN_FRAG_BLKS - 1,
                false,
                &[0x61; 8]
            )),
            Ipv6Fragment::Unknown,
            "one block below the floor is still rejected (RFC 1858)"
        );

        // `ipv6_frag_short_first`: a first fragment truncated before its full transport header. Go
        // refuses to guess at the ports, because a follow-up fragment supplying the rest of that
        // header would otherwise carry the flow past a rule the filter never really matched.
        assert_eq!(
            decode6_fragment(&ipv6_fragment_packet(17, 0, true, &udp_header(443)[..4])),
            Ipv6Fragment::Unknown,
            "a first fragment with only half a UDP header is rejected"
        );
        assert_eq!(
            decode6_fragment(&ipv6_fragment_packet(6, 0, true, &[0u8; 19])),
            Ipv6Fragment::Unknown,
            "a first fragment one byte short of a TCP header is rejected"
        );
        // ...and the same header one byte longer is accepted, so the rejection is the bounds check
        // and not the protocol.
        let mut tcp = vec![0u8; 20];
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        assert_eq!(
            decode6_fragment(&ipv6_fragment_packet(6, 0, true, &tcp)),
            Ipv6Fragment::First {
                proto: IpProto::TCP,
                src_port: 0,
                dst_port: 443,
                // Go `q.TCPFlags = TCPFlag(sub[13])`, which is 0 in this all-zero header. A
                // fragment carrying real flags is exercised by
                // `ipv6_first_fragment_carries_its_tcp_flags_to_the_reply_carve_out`.
                l4: ts_packetfilter::L4Header::Tcp { flags: 0 },
            },
            "a complete TCP header in the first fragment is read normally"
        );

        // A Fragment header truncated by the packet itself (Go's `len(b) < q.subofs+8` guard).
        let mut short = ipv6_fragment_packet(17, 0, true, &[]);
        short.truncate(IP6_HEADER_LEN + 4);
        short[4..6].copy_from_slice(&4u16.to_be_bytes());
        assert_eq!(
            decode6_fragment(&short),
            Ipv6Fragment::Unknown,
            "a truncated Fragment extension header is rejected"
        );
        // A packet cut off before its declared payload length (Go `len(b) < q.length`).
        let mut cut = ipv6_fragment_packet(17, 0, true, &udp_header(443));
        cut.truncate(cut.len() - 1);
        assert_eq!(
            decode6_fragment(&cut),
            Ipv6Fragment::Unknown,
            "a packet cut off before its declared IPv6 length is rejected"
        );

        // Go's portless arms bounds-check but leave the port at 0, and the on-the-wire use of Go's
        // internal `ipproto.Fragment` sentinel (0xff) maps back to `unknown`.
        assert_eq!(
            decode6_fragment(&ipv6_fragment_packet(58, 0, true, &[0u8; 4])),
            Ipv6Fragment::First {
                proto: IpProto::ICMPV6,
                src_port: 0,
                dst_port: 0,
                // Go bounds-checks 4 bytes here but reads the type/code behind `len(q.b) >=
                // q.subofs+8`, so a 4-byte first fragment is no "response" upstream either.
                l4: ts_packetfilter::L4Header::Unknown,
            },
            "a first ICMPv6 fragment keeps port 0 and is matched IPs-only"
        );
        assert_eq!(
            decode6_fragment(&ipv6_fragment_packet(58, 0, true, &[0u8; 3])),
            Ipv6Fragment::Unknown,
            "a first ICMPv6 fragment shorter than the ICMPv6 header is rejected"
        );
        assert_eq!(
            decode6_fragment(&ipv6_fragment_packet(0xff, 0, true, &[0u8; 8])),
            Ipv6Fragment::Unknown,
            "Go's internal Fragment sentinel seen on the wire maps back to unknown"
        );
    }

    /// The verdict Go's filter `pre()` reaches for each IPv6 fragment classification, asserted
    /// against an ACL that would otherwise decide the packet the other way — so each assertion can
    /// only be the fragment rule, never the ACL:
    ///
    /// - `Unknown` is DROPPED under an ALLOW-ALL ACL (Go `pre()`: `IPProto == Unknown → Drop`).
    ///   This is the security-relevant direction: an allow-all tailnet policy must not admit a
    ///   short-first or RFC-1858 low-offset fragment.
    /// - `Later` is ACCEPTED under a DENY-ALL ACL (Go `pre()`: `case ipproto.Fragment: Accept`).
    /// - `First` consults the ACL normally on the port read past the Fragment header.
    #[test]
    fn ipv6_fragment_verdict_matches_go_pre() {
        let src = std::net::IpAddr::V6(IPV6_FIXTURE_SRC);
        let dst = std::net::IpAddr::V6(IPV6_FIXTURE_DST);
        let v6 = |class| Some(Fragment::V6(class));

        // The negative case, stated explicitly: allow-all cannot rescue an `unknown` fragment.
        assert!(
            !stateless_verdict(
                &AllowAll,
                IpProto::new(0),
                src,
                dst,
                0,
                v6(Ipv6Fragment::Unknown)
            ),
            "an unknown IPv6 fragment is dropped even under an allow-all ACL"
        );
        // The control: the same allow-all ACL admits an ordinary non-fragment packet, so the drop
        // above is the classification and not the harness.
        assert!(
            stateless_verdict(&AllowAll, IpProto::UDP, src, dst, 443, None),
            "the allow-all ACL does admit an ordinary packet"
        );

        // A safe later fragment slides through ahead of the ACL, with nothing but port 0 to match.
        assert!(
            stateless_verdict(
                &DenyAll,
                IpProto::new(0),
                src,
                dst,
                0,
                v6(Ipv6Fragment::Later)
            ),
            "a later IPv6 fragment is accepted ahead of a deny-all ACL"
        );

        // A first fragment is an ordinary packet again: admitted on the port the ACL allows,
        // dropped on one it does not.
        let first = |dst_port| {
            v6(Ipv6Fragment::First {
                proto: IpProto::UDP,
                src_port: 0,
                dst_port,
                l4: ts_packetfilter::L4Header::Unknown,
            })
        };
        assert!(
            stateless_verdict(&AllowPort(443), IpProto::UDP, src, dst, 443, first(443)),
            "a first IPv6 fragment is matched on the port behind the Fragment header"
        );
        assert!(
            !stateless_verdict(&AllowPort(443), IpProto::UDP, src, dst, 444, first(444)),
            "a first IPv6 fragment on a disallowed port is dropped by the ACL"
        );
        // Control: the same ACL decides an unfragmented packet the same way, so the two results
        // above are the ACL being consulted on a real port and not a fragment-specific shortcut.
        assert!(
            stateless_verdict(&AllowPort(443), IpProto::UDP, src, dst, 443, None),
            "control: the port-scoped ACL admits an unfragmented packet to 443"
        );
        assert!(
            !stateless_verdict(&AllowPort(443), IpProto::UDP, src, dst, 0, None),
            "control: port 0 - what a v6 fragment used to read as - is not admitted"
        );

        // `pre()`'s multicast/link-local drops still outrank the fragment pass-through, exactly as
        // Go runs them before `case ipproto.Fragment`.
        assert!(
            !stateless_verdict(
                &AllowAll,
                IpProto::new(0),
                src,
                "ff02::1".parse().unwrap(),
                0,
                v6(Ipv6Fragment::Later)
            ),
            "a later fragment to a multicast dst is still dropped by pre()"
        );
        assert!(
            !stateless_verdict(
                &AllowAll,
                IpProto::new(0),
                src,
                "fe80::1".parse().unwrap(),
                0,
                v6(Ipv6Fragment::Later)
            ),
            "a later fragment to a link-local dst is still dropped by pre()"
        );
    }

    /// The whole inbound path on real IPv6 bytes — parse, classify, verdict — which is the shape
    /// the bypass had: before the Fragment extension header was classified, every source-fragmented
    /// IPv6 datagram reached the ACL with no sub-protocol and port 0, so an allow-all rule admitted
    /// the RFC 1858 fragments upstream drops and a port-scoped rule blackholed the later fragments
    /// upstream passes through.
    #[test]
    fn ipv6_fragments_are_filtered_end_to_end() {
        let keep = |filter: &(dyn ts_packetfilter::Filter + Send + Sync), packet: Vec<u8>| {
            let mut packets = vec![PacketMut::from(packet)];
            let mut harvest = InboundHarvest::default();
            filter_inbound_from_peer(
                filter,
                &mut flowtrack::FlowCache::default(),
                PeerId(3),
                &mut packets,
                RejectConfig::default(),
                &mut harvest,
            );
            assert!(
                harvest.learned_disco_keys.is_empty(),
                "no TSMP advertisement in these fixtures"
            );
            !packets.is_empty()
        };

        // Under an ALLOW-ALL ACL — the permissive policy the bypass needs — the RFC 1858 fragment
        // must still be dropped, while the legitimate later fragment must still be delivered.
        assert!(
            !keep(&AllowAll, ipv6_fragment_packet(17, 1, false, &[0x61; 8])),
            "a low-offset later IPv6 fragment is dropped even by an allow-all ACL (RFC 1858)"
        );
        assert!(
            !keep(
                &AllowAll,
                ipv6_fragment_packet(17, 0, true, &udp_header(443)[..4])
            ),
            "a first IPv6 fragment too short to hold its UDP header is dropped by an allow-all ACL"
        );
        assert!(
            keep(&AllowAll, ipv6_fragment_packet(17, 185, false, &[0x61; 8])),
            "a legitimate later IPv6 fragment is delivered"
        );

        // ...and the later fragment is delivered even under a DENY-ALL ACL, which is the Go
        // `pre()` pass-through and not the ACL agreeing.
        assert!(
            keep(&DenyAll, ipv6_fragment_packet(17, 185, false, &[0x61; 8])),
            "a legitimate later IPv6 fragment slides through a deny-all ACL (Go pre())"
        );
        assert!(
            !keep(&DenyAll, ipv6_fragment_packet(17, 1, false, &[0x61; 8])),
            "a low-offset later IPv6 fragment is dropped under a deny-all ACL too"
        );

        // A first fragment is matched on the port that lives behind the Fragment extension header,
        // which is the whole point of stepping over it: 443 is admitted, 444 is not, under the same
        // port-scoped ACL. Before the port was read past the header both read as port 0 and both
        // were dropped.
        assert!(
            keep(
                &AllowPort(443),
                ipv6_fragment_packet(17, 0, true, &udp_header(443))
            ),
            "a first IPv6 fragment to an allowed port is delivered"
        );
        assert!(
            !keep(
                &AllowPort(443),
                ipv6_fragment_packet(17, 0, true, &udp_header(444))
            ),
            "a first IPv6 fragment to a disallowed port is dropped"
        );

        // Scoping (Go `26b2ed0a6`): the Fragment header is parsed here ONLY as the base header's
        // immediate Next Header. What happens to one reached through a chained extension header —
        // it must fail closed, not fall through to the ACL — is
        // `chained_extension_header_cannot_bypass_the_ipv6_fragment_rules`.
    }

    /// An allow-all ACL that also records whether it was consulted at all.
    ///
    /// [`AllowAll`] alone can show that a packet was dropped; it cannot show *where*. Under an ACL
    /// that admits everything, "dropped AND never consulted" is the signature of a `pre()` drop and
    /// of nothing else — which is the guarantee the fragment classification exists to keep, so it
    /// is worth asserting directly rather than inferring from the verdict.
    #[derive(Default)]
    struct RecordingAllowAll(std::sync::atomic::AtomicBool);

    impl RecordingAllowAll {
        /// Whether the ACL was asked about any packet since this filter was made.
        fn consulted(&self) -> bool {
            self.0.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    impl ts_packetfilter::Filter for RecordingAllowAll {
        fn match_for(
            &self,
            _info: &ts_packetfilter::PacketInfo,
            _caps: ts_packetfilter::filter::CapIter,
        ) -> Option<&str> {
            self.0.store(true, std::sync::atomic::Ordering::Relaxed);
            Some("allow-all")
        }
    }

    /// A *first* IPv6 fragment whose Fragment header's Next Header is 0 is dropped ahead of the
    /// rules, never matched by them.
    ///
    /// Go `net/packet.decode6Fragment` copies that byte into `q.IPProto` (`q.IPProto = nextHdr`)
    /// and reports `continueDecode`, so the packet goes back through `decode6`'s sub-protocol
    /// switch — which has no case for 0. `ipproto.Unknown` *is* 0, so `q.IPProto` is left at
    /// Unknown and filter `pre()`'s `if q.IPProto == ipproto.Unknown { return Drop }` fires before
    /// any rule is consulted. (Protocol 0 on the wire is Hop-by-Hop Options; an IPv6 packet whose
    /// *base* header declares it is refused by that same arm, and always has been.)
    ///
    /// This tree reaches the same drop by the same route: `decode6_first_fragment`'s catch-all arm
    /// keeps the number, exactly as Go's absent switch case does, and the drop comes from
    /// `inbound_filter_verdict`'s shared [`IPPROTO_UNKNOWN`] arm — which a first fragment falls
    /// through to for the same reason an unfragmented packet does. Nothing about that is specific
    /// to fragments, which is why there is no fragment-specific arm for it; this test is what pins
    /// the fall-through, at each of the three levels the packet passes through.
    #[test]
    fn first_ipv6_fragment_with_unknown_next_header_is_dropped_before_the_acl() {
        // 1. Classification. Go's `q.IPProto = nextHdr` on a first fragment, verbatim: the 0 is
        //    carried, not translated. `dst_port` is 0 because Go reads a port in the TCP/UDP/SCTP
        //    arms only, and protocol 0 is in none of them.
        assert_eq!(
            decode6_fragment(&ipv6_fragment_packet(0, 0, true, &udp_header(443))),
            Ipv6Fragment::First {
                proto: IPPROTO_UNKNOWN,
                src_port: 0,
                dst_port: 0,
                l4: ts_packetfilter::L4Header::Unknown,
            },
            "a first fragment carries its Fragment header's Next Header, 0 included"
        );

        // 2. Verdict. The allow-all ACL is the control that makes this a pre-rule drop and not a
        //    rule saying no.
        let src = std::net::IpAddr::V6(IPV6_FIXTURE_SRC);
        let dst = std::net::IpAddr::V6(IPV6_FIXTURE_DST);
        assert!(
            !stateless_verdict(
                &AllowAll,
                IPPROTO_UNKNOWN,
                src,
                dst,
                0,
                Some(Fragment::V6(Ipv6Fragment::First {
                    proto: IPPROTO_UNKNOWN,
                    src_port: 0,
                    dst_port: 0,
                    l4: ts_packetfilter::L4Header::Unknown,
                })),
            ),
            "a first IPv6 fragment declaring protocol 0 is dropped under an allow-all ACL"
        );

        // 3. The whole inbound path on real bytes, and the part the ACL never sees. The two
        //    fixtures differ in exactly one byte — the Fragment header's Next Header — so the
        //    control proves the drop is the protocol number and not the packet shape: the same
        //    fragment naming UDP is parsed, matched and delivered.
        let keep = |filter: &(dyn ts_packetfilter::Filter + Send + Sync), packet: Vec<u8>| {
            let mut packets = vec![PacketMut::from(packet)];
            let mut harvest = InboundHarvest::default();
            filter_inbound_from_peer(
                filter,
                &mut flowtrack::FlowCache::default(),
                PeerId(5),
                &mut packets,
                RejectConfig::default(),
                &mut harvest,
            );
            assert!(
                harvest.learned_disco_keys.is_empty(),
                "no TSMP advertisement in these fixtures"
            );
            !packets.is_empty()
        };

        let acl = RecordingAllowAll::default();
        assert!(
            !keep(&acl, ipv6_fragment_packet(0, 0, true, &udp_header(443))),
            "a crafted first IPv6 fragment naming protocol 0 is dropped by an allow-all ACL"
        );
        assert!(
            !acl.consulted(),
            "and it is dropped ahead of the rules: the ACL is never asked about it"
        );

        let control = RecordingAllowAll::default();
        assert!(
            keep(
                &control,
                ipv6_fragment_packet(17, 0, true, &udp_header(443))
            ),
            "control: the same fragment naming UDP is delivered"
        );
        assert!(
            control.consulted(),
            "control: and it got there by being matched against the rules"
        );
    }

    /// Prepending an extension header must not defeat the fragment rules.
    ///
    /// [`decode6_fragment`] is scoped exactly as Go scopes it: the Fragment header is parsed only
    /// as the base header's immediate Next Header. Go can afford that narrow scope because
    /// everything it does not parse *keeps the base header's Next Header* as `q.IPProto`, so a
    /// chained fragment is filtered as the extension header it leads with and its fragment offset
    /// is never read at all. This tree does classify the chain
    /// ([`fragment_header_is_chained`]), and the only classification that cannot be an invention
    /// in the permissive direction is [`Ipv6Fragment::Unknown`] — a drop. Without it, eight bytes
    /// of Hop-by-Hop Options were enough to walk every RFC 1858 fragment straight past the rules
    /// the rest of this file exists to enforce.
    ///
    /// Every assertion is against an ALLOW-ALL ACL, so a drop can only be the fragment rule and
    /// never the ACL — and each extension type carries its own control that proves it: the same
    /// chain shape with no Fragment header in it is still walked to its UDP header by the parser.
    /// That control is per-type rather than once at the end because `keep` cannot tell a
    /// fragment-rule drop from a parser rejection, so a fixture malformed for only one of the
    /// three protocols would otherwise turn that protocol's four drops into vacuous passes with
    /// the suite still green.
    #[test]
    fn chained_extension_header_cannot_bypass_the_ipv6_fragment_rules() {
        let keep = |filter: &(dyn ts_packetfilter::Filter + Send + Sync), packet: Vec<u8>| {
            let mut packets = vec![PacketMut::from(packet)];
            let mut harvest = InboundHarvest::default();
            filter_inbound_from_peer(
                filter,
                &mut flowtrack::FlowCache::default(),
                PeerId(4),
                &mut packets,
                RejectConfig::default(),
                &mut harvest,
            );
            assert!(
                harvest.learned_disco_keys.is_empty(),
                "no TSMP advertisement in these fixtures"
            );
            !packets.is_empty()
        };

        // Hop-by-Hop Options (0), Routing (43) and Destination Options (60): the fragment rules
        // must not depend on which header the sender chose to hide behind.
        for ext in [0u8, 43, 60] {
            // The RFC 1858 evasion itself: a later fragment whose bytes can land on top of the
            // transport header the head fragment was matched on.
            assert!(
                !keep(
                    &AllowAll,
                    ipv6_with_prepended_ext_header(
                        ext,
                        &ipv6_fragment_packet(17, 1, false, &[0x61; 8])
                    )
                ),
                "a low-offset later fragment behind extension header {ext} is dropped (RFC 1858)"
            );
            // A first fragment truncated before its own transport header, which a follow-up
            // fragment can then complete.
            assert!(
                !keep(
                    &AllowAll,
                    ipv6_with_prepended_ext_header(
                        ext,
                        &ipv6_fragment_packet(17, 0, true, &udp_header(443)[..4])
                    )
                ),
                "a short first fragment behind extension header {ext} is dropped"
            );
            // A *well-formed* chained fragment is dropped too — Go drops this whole class, so
            // failing closed here can never admit something upstream refuses.
            assert!(
                !keep(
                    &AllowAll,
                    ipv6_with_prepended_ext_header(
                        ext,
                        &ipv6_fragment_packet(17, 185, false, &[0x61; 8])
                    )
                ),
                "a chained later fragment behind extension header {ext} gets no pass-through"
            );
            assert!(
                !keep(
                    &AllowAll,
                    ipv6_with_prepended_ext_header(
                        ext,
                        &ipv6_fragment_packet(17, 0, true, &udp_header(443))
                    )
                ),
                "a chained first fragment behind extension header {ext} is dropped"
            );

            // Control for THIS extension type. Every assertion above is a `!keep`, and `keep`
            // reports a packet the parser rejected exactly as it reports a packet the fragment
            // rule dropped — so on its own the block above would also pass if this builder simply
            // produced eight bytes etherparse refuses to walk. It does not: the same chain shape
            // with no Fragment header behind it is walked all the way to its UDP header. The drops
            // above are therefore this file refusing a packet it could perfectly well have read,
            // which is the whole claim.
            //
            // The control is a parser assertion and not a `keep`, because what the *filter* does
            // with a chained non-fragment is no longer "deliver it on the port behind the chain" —
            // it is Go's base-Next-Header disposition, which
            // `ipv6_extension_header_chain_is_matched_on_the_base_next_header` covers in full.
            let plain = ipv6_with_prepended_ext_header(ext, &ipv6_udp_packet(&udp_header(443)));
            let parsed = etherparse::SlicedPacket::from_ip(&plain)
                .unwrap_or_else(|e| panic!("extension header {ext} fixture must parse: {e:?}"));
            assert!(
                matches!(parsed.transport, Some(etherparse::TransportSlice::Udp(_))),
                "extension header {ext} fixture must chain to a UDP header the parser can reach"
            );
        }

        // Contrast: the very same later fragment, reached as the base header's immediate Next
        // Header, is still delivered. Only the 8 prepended bytes separate this from the third
        // assertion above, so the drops really are the chain and not the fragment fixtures.
        assert!(
            keep(&AllowAll, ipv6_fragment_packet(17, 185, false, &[0x61; 8])),
            "an unchained later fragment is still delivered"
        );
    }

    /// A filter that admits everything and records the [`ts_packetfilter::PacketInfo`] it was asked
    /// about, so a test can assert on the protocol and port the dataplane actually derived — and on
    /// a packet never reaching the ACL at all.
    #[derive(Default)]
    struct Recording(Mutex<Vec<ts_packetfilter::PacketInfo>>);
    impl ts_packetfilter::Filter for Recording {
        fn match_for(
            &self,
            info: &ts_packetfilter::PacketInfo,
            _caps: ts_packetfilter::filter::CapIter,
        ) -> Option<&str> {
            self.0.lock().unwrap().push(*info);
            Some("recording")
        }
    }

    /// A real control-derived ACL — one rule built out of [`ts_packetfilter::Rule`] itself rather
    /// than a hand-written stub, so the assertions run through the same per-protocol port semantics
    /// as production: TCP/UDP/SCTP are port-matched, and any other protocol matches IPs-only and
    /// only under an all-ports rule (Go `matchProtoAndIPsOnlyIfAllPorts`).
    fn ipv6_acl(
        protos: &[i64],
        ports: std::ops::RangeInclusive<u16>,
    ) -> std::collections::BTreeMap<String, ts_packetfilter::Ruleset> {
        acl("2001:db8::/32", protos, ports)
    }

    /// [`ipv6_acl`] for either family: one rule whose source and destination are both `net`.
    fn acl(
        net: &str,
        protos: &[i64],
        ports: std::ops::RangeInclusive<u16>,
    ) -> std::collections::BTreeMap<String, ts_packetfilter::Ruleset> {
        let net: ipnet::IpNet = net.parse().unwrap();
        std::collections::BTreeMap::from([(
            ts_packetfilter::DEFAULT_RULESET_NAME.to_string(),
            vec![ts_packetfilter::Rule {
                src: ts_packetfilter::SrcMatch {
                    pfxs: vec![net],
                    caps: Vec::new(),
                },
                protos: protos.iter().copied().map(IpProto::new).collect(),
                dst: vec![ts_packetfilter::DstMatch {
                    ports,
                    ips: vec![net],
                }],
            }],
        )])
    }

    /// An IPv6 extension-header chain is filtered on the **base** header's Next Header, never on
    /// the transport the chain resolves to.
    ///
    /// Go `net/packet.decode6` assigns `q.IPProto = ipproto.Proto(b[6])` and — apart from a leading
    /// Fragment header — parses nothing further, so the number that reaches `wgengine/filter` is
    /// the extension header's own. Two consequences, both asserted here:
    ///
    /// * Hop-by-Hop Options **is** protocol 0, which is `ipproto.Unknown`, so filter `pre()` drops
    ///   the packet outright before any rule is consulted.
    /// * Routing (43) and Destination Options (60) reach `runIn6`'s `default` arm, where the only
    ///   way in is `matchProtoAndIPsOnlyIfAllPorts` — an all-ports rule naming protocol 43 or 60.
    ///   Such a packet is never matched against a TCP or UDP rule and its transport port is never
    ///   read.
    ///
    /// Reading the protocol out of etherparse's extension-header walk instead resolves straight
    /// through the chain to the real transport number and reads that transport's destination port,
    /// which is a strictly more permissive filter than upstream's: an ordinary `udp:443` ACL
    /// admitted a packet Go matches IPs-only, and would admit it for any protocol an attacker
    /// chose to bury the chain under.
    ///
    /// Ported from github.com/tailscale/tailscale `net/packet/packet.go` (`decode6`) and
    /// `wgengine/filter/filter.go` (`pre`, `runIn6`) at
    /// `9ea7cba44591e0cd840c6c94d23274dd222059bf`.
    #[test]
    fn ipv6_extension_header_chain_is_matched_on_the_base_next_header() {
        let keep = |filter: &(dyn ts_packetfilter::Filter + Send + Sync), packet: Vec<u8>| {
            let mut packets = vec![PacketMut::from(packet)];
            let mut harvest = InboundHarvest::default();
            filter_inbound_from_peer(
                filter,
                &mut flowtrack::FlowCache::default(),
                PeerId(5),
                &mut packets,
                RejectConfig::default(),
                &mut harvest,
            );
            assert!(
                harvest.learned_disco_keys.is_empty(),
                "no TSMP advertisement in these fixtures"
            );
            !packets.is_empty()
        };
        // What the ACL was asked about, or `None` if the packet never got that far.
        let seen = |packet: Vec<u8>| {
            let recording = Recording::default();
            keep(&recording, packet);
            let seen = recording.0.into_inner().unwrap();
            assert!(seen.len() <= 1, "one packet in, at most one ACL question");
            seen.into_iter().next()
        };

        let unchained = ipv6_udp_packet(&udp_header(443));

        // The baseline this is all measured against: with UDP as the base header's Next Header,
        // `decode6` takes its UDP arm, so the ACL sees protocol 17 on port 443.
        let info = seen(unchained.clone()).expect("an unchained UDP datagram reaches the ACL");
        assert_eq!(info.ip_proto, IpProto::UDP, "unchained: protocol is UDP");
        assert_eq!(
            info.port, 443,
            "unchained: the UDP destination port is read"
        );

        // Routing (43) and Destination Options (60): the base header now says "extension header",
        // so that is the protocol the ACL is asked about — and no port is read, even though the
        // very same UDP header still sits 8 bytes further down the chain.
        for ext in [43u8, 60] {
            let chained = ipv6_with_prepended_ext_header(ext, &unchained);
            let info = seen(chained.clone()).unwrap_or_else(|| {
                panic!("a packet behind extension header {ext} reaches the ACL")
            });
            assert_eq!(
                info.ip_proto,
                IpProto::new(i64::from(ext)),
                "behind extension header {ext}: the ACL sees the base Next Header, not the transport"
            );
            assert_eq!(
                info.port, 0,
                "behind extension header {ext}: no port is read past the chain"
            );

            // And what that means for a real ACL. An ordinary `udp:443` rule admits the unchained
            // datagram and refuses the chained one, because protocol 43/60 is not UDP...
            let udp443 = ipv6_acl(&[i64::from(IpProto::UDP)], 443..=443);
            assert!(
                keep(&udp443, unchained.clone()),
                "a udp:443 rule admits the unchained datagram"
            );
            assert!(
                !keep(&udp443, chained.clone()),
                "a udp:443 rule does not admit a packet behind extension header {ext}"
            );

            // ...and the one rule that does admit it is Go's `matchProtoAndIPsOnlyIfAllPorts`:
            // the protocol named, IPs-only, all ports open. A narrower port range on the same
            // protocol opens nothing, because a portless protocol carries no port to match.
            assert!(
                keep(&ipv6_acl(&[i64::from(ext)], 0..=u16::MAX), chained.clone()),
                "an all-ports rule naming protocol {ext} admits it IPs-only"
            );
            assert!(
                !keep(&ipv6_acl(&[i64::from(ext)], 443..=443), chained),
                "a port-scoped rule naming protocol {ext} opens nothing (matchProtoAndIPsOnlyIfAllPorts)"
            );
        }

        // Hop-by-Hop Options is protocol 0, and protocol 0 is `ipproto.Unknown`: Go's `pre()`
        // drops it before the ACL exists, so not even an allow-everything filter is consulted.
        let hop_by_hop = ipv6_with_prepended_ext_header(0, &unchained);
        assert!(
            seen(hop_by_hop.clone()).is_none(),
            "a hop-by-hop-led packet never reaches the ACL"
        );
        assert!(
            !keep(&AllowAll, hop_by_hop),
            "a hop-by-hop-led packet is dropped by an allow-all ACL (Go pre() unknown-proto drop)"
        );

        // The same drop for Go's internal later-fragment sentinel used as a real Next Header:
        // `decode6`'s `case ipproto.Fragment: q.IPProto = unknown`.
        let mut sentinel = unchained.clone();
        sentinel[6] = 0xff;
        assert!(
            seen(sentinel.clone()).is_none(),
            "a packet whose base Next Header is the 0xff sentinel never reaches the ACL"
        );
        assert!(
            !keep(&AllowAll, sentinel),
            "...and is dropped by an allow-all ACL"
        );
    }

    /// Source/destination for the IPv4 fixtures: ordinary tailnet unicast, so `drop_before_rules`
    /// never fires and every verdict below is the decode's own.
    const IPV4_FIXTURE_SRC: std::net::Ipv4Addr = std::net::Ipv4Addr::new(100, 64, 0, 9);
    const IPV4_FIXTURE_DST: std::net::Ipv4Addr = std::net::Ipv4Addr::new(100, 64, 0, 1);
    /// The tailnet range both IPv4 fixture addresses sit in, for [`acl`].
    const IPV4_FIXTURE_NET: &str = "100.64.0.0/10";

    /// A minimal IPv4 packet: a 20-byte header carrying protocol `proto`, the fragment offset (in
    /// 8-byte blocks) and More-Fragments flag asked for, and `payload` behind it. The header
    /// checksum is left zero — nothing on this path verifies it, and neither does Go's decoder.
    fn v4_packet(proto: u8, offset_blocks: u16, more_fragments: bool, payload: &[u8]) -> Vec<u8> {
        let total_len = u16::try_from(IP4_HEADER_LEN + payload.len()).unwrap();
        let mut buf = vec![0u8; usize::from(total_len)];
        buf[0] = 0x45; // version 4, IHL 5 (no options)
        buf[2..4].copy_from_slice(&total_len.to_be_bytes());
        let frag_field = (offset_blocks & 0x1fff) | if more_fragments { 0x2000 } else { 0 };
        buf[6..8].copy_from_slice(&frag_field.to_be_bytes());
        buf[8] = 64; // TTL
        buf[9] = proto;
        buf[12..16].copy_from_slice(&IPV4_FIXTURE_SRC.octets());
        buf[16..20].copy_from_slice(&IPV4_FIXTURE_DST.octets());
        buf[IP4_HEADER_LEN..].copy_from_slice(payload);
        buf
    }

    /// An SCTP common header carrying `dst_port`, truncated to `len` bytes so a test can hand the
    /// decoder the short header Go refuses.
    fn sctp_header(dst_port: u16, len: usize) -> Vec<u8> {
        let mut hdr = vec![0u8; SCTP_HEADER_LEN];
        hdr[0..2].copy_from_slice(&54276u16.to_be_bytes()); // source port
        hdr[2..4].copy_from_slice(&dst_port.to_be_bytes());
        hdr[4..8].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // verification tag
        hdr.truncate(len);
        hdr
    }

    /// An SCTP packet is filtered on its real destination port, on both families — Go
    /// `net/packet.decode4` and `decode6` each carry a `case ipproto.SCTP` arm that bounds-checks
    /// the 12-byte common header and reads `sub[2:4]`, exactly as their TCP and UDP arms do.
    ///
    /// etherparse parses no SCTP header of its own (its `TransportSlice` has ICMPv4, ICMPv6, TCP
    /// and UDP arms and nothing else), so leaving the port to `SlicedPacket::transport` reported
    /// port 0 for every SCTP packet on the wire. That is wrong in both directions: an `sctp:443`
    /// rule blackholed the SCTP traffic it was written to admit, and any rule whose port range
    /// happens to contain 0 admitted SCTP to *every* port. Both are asserted below through a real
    /// control-derived rule, not just through the recorded `PacketInfo`.
    ///
    /// The refusals come with it. A header too short to hold the ports is Go's
    /// `q.IPProto = unknown`, which filter `pre()` drops before any rule is consulted — never a
    /// fallback to port 0, which an all-ports rule would admit. And a *later* fragment is not an
    /// SCTP header at all: Go leaves its ports 0 and passes it through on its offset alone.
    ///
    /// Ported from github.com/tailscale/tailscale `net/packet/packet.go` (`decode4`, `decode6`) and
    /// `wgengine/filter/filter.go` (`pre`, `runIn4`, `runIn6`) at
    /// `9ea7cba44591e0cd840c6c94d23274dd222059bf`.
    #[test]
    fn sctp_destination_port_is_read_before_the_acl() {
        let keep = |filter: &(dyn ts_packetfilter::Filter + Send + Sync), packet: Vec<u8>| {
            let mut packets = vec![PacketMut::from(packet)];
            let mut harvest = InboundHarvest::default();
            filter_inbound_from_peer(
                filter,
                &mut flowtrack::FlowCache::default(),
                PeerId(11),
                &mut packets,
                RejectConfig::default(),
                &mut harvest,
            );
            assert!(
                harvest.learned_disco_keys.is_empty(),
                "no TSMP advertisement in these fixtures"
            );
            !packets.is_empty()
        };
        // What the ACL was asked about, or `None` if the packet never got that far.
        let seen = |packet: Vec<u8>| {
            let recording = Recording::default();
            keep(&recording, packet);
            let seen = recording.0.into_inner().unwrap();
            assert!(seen.len() <= 1, "one packet in, at most one ACL question");
            seen.into_iter().next()
        };

        let sctp = i64::from(IpProto::SCTP);
        let whole = sctp_header(443, SCTP_HEADER_LEN);
        let v4 = v4_packet(132, 0, false, &whole);
        let v6 = ipv6_packet(132, &whole);

        for (family, packet) in [("IPv4", &v4), ("IPv6", &v6)] {
            let info = seen(packet.clone())
                .unwrap_or_else(|| panic!("{family}: an SCTP packet reaches the ACL"));
            assert_eq!(
                info.ip_proto,
                IpProto::SCTP,
                "{family}: the protocol is SCTP"
            );
            assert_eq!(
                info.port, 443,
                "{family}: the SCTP destination port is read off the wire"
            );
        }

        // And what that means for a real control-derived rule. An `sctp:443` rule admits the
        // packet; a rule whose range covers port 0 but not 443 does not — the ACL bypass a
        // hard-coded port 0 would have opened.
        assert!(
            keep(&acl(IPV4_FIXTURE_NET, &[sctp], 443..=443), v4.clone()),
            "IPv4: an sctp:443 rule admits an SCTP packet to port 443"
        );
        assert!(
            !keep(&acl(IPV4_FIXTURE_NET, &[sctp], 0..=442), v4.clone()),
            "IPv4: an sctp:0-442 rule does not admit an SCTP packet to port 443"
        );
        assert!(
            keep(&ipv6_acl(&[sctp], 443..=443), v6.clone()),
            "IPv6: an sctp:443 rule admits an SCTP packet to port 443"
        );
        assert!(
            !keep(&ipv6_acl(&[sctp], 0..=442), v6),
            "IPv6: an sctp:0-442 rule does not admit an SCTP packet to port 443"
        );

        // A *first* fragment carries the whole common header, so Go reads its ports like an
        // unfragmented packet's (`decode4` only skips the transport header when `fragOfs != 0`).
        let info = seen(v4_packet(132, 0, true, &whole))
            .expect("IPv4: a first SCTP fragment reaches the ACL");
        assert_eq!(
            info.port, 443,
            "IPv4: a first fragment's SCTP port is read, as decode4 does"
        );

        // A later fragment is continued payload, not a header: Go leaves its ports 0 and `pre()`
        // passes it through on its offset alone. Reading `sub[2:4]` here would invent a port, and
        // the short-header refusal would drop a fragment upstream delivers — so a deny-all ACL is
        // the control, proving the accept came from the fragment path and not from a rule.
        assert!(
            keep(
                &DenyAll,
                v4_packet(132, MIN_FRAG_BLKS, false, &[0x01, 0x02, 0x03, 0x04])
            ),
            "IPv4: a valid later SCTP fragment is passed through ahead of the ACL"
        );

        // Go's short-header refusal: `q.IPProto = unknown`, dropped by `pre()` before the ACL
        // exists, so not even an allow-everything filter is consulted.
        let short = sctp_header(443, SCTP_HEADER_LEN - 1);
        for (family, packet) in [
            ("IPv4", v4_packet(132, 0, false, &short)),
            ("IPv6", ipv6_packet(132, &short)),
        ] {
            assert!(
                seen(packet.clone()).is_none(),
                "{family}: an SCTP header too short to hold its ports never reaches the ACL"
            );
            assert!(
                !keep(&AllowAll, packet),
                "{family}: ...and an allow-all ACL does not admit it"
            );
        }
    }

    /// Build the IPv4 packet a Go peer puts on the wire for a TSMP message: a 20-byte IPv4
    /// header with proto 99 and `body` appended (Go `packet.Generate(IP4Header{...}, body)`,
    /// which is what `TSMPDiscoKeyAdvertisement.Marshal` calls). The header checksum is left
    /// zero — nothing on this path verifies it, and neither does Go's decoder.
    fn tsmp_packet4(src: [u8; 4], dst: [u8; 4], body: &[u8]) -> PacketMut {
        let mut buf = vec![0u8; 20 + body.len()];
        buf[20..].copy_from_slice(body);
        buf[0] = 0x45;
        let total_len = buf.len() as u16;
        buf[2..4].copy_from_slice(&total_len.to_be_bytes());
        buf[8] = 64;
        buf[9] = 99;
        buf[12..16].copy_from_slice(&src);
        buf[16..20].copy_from_slice(&dst);
        PacketMut::from(buf)
    }

    /// A body a real Go peer sends: `'a'` then its 32-byte disco key.
    fn advertisement_body(key: [u8; 32]) -> Vec<u8> {
        let mut body = vec![ts_packet::tsmp::TSMP_TYPE_DISCO_ADVERTISEMENT];
        body.extend_from_slice(&key);
        body
    }

    /// The receive side of the TSMP disco-key advertisement, at the point Go handles it: a
    /// well-formed advertisement is CONSUMED — the peer's key is learned and the packet is
    /// dropped rather than delivered to the local stack (Go `filter.DropSilently`) — while every
    /// other TSMP body is left alone and still admitted by the TSMP ACL bypass.
    ///
    /// The ACL here denies everything, so an admitted packet can only have come through the
    /// TSMP bypass, and a learned key can only have come from the advertisement path.
    #[test]
    fn tsmp_disco_key_advertisement_is_learned_and_dropped() {
        let peer = PeerId(7);
        let src = [100, 64, 0, 2];
        let dst = [100, 64, 0, 1];
        let key = [0xa5u8; 32];

        let mut packets = vec![tsmp_packet4(src, dst, &advertisement_body(key))];
        let mut harvest = InboundHarvest::default();
        filter_inbound_from_peer(
            &DenyAll,
            &mut flowtrack::FlowCache::default(),
            peer,
            &mut packets,
            RejectConfig::default(),
            &mut harvest,
        );

        assert!(
            packets.is_empty(),
            "a consumed advertisement must not be delivered to the local stack"
        );
        let learned = &harvest.learned_disco_keys;
        assert_eq!(learned.len(), 1, "the advertisement must be harvested");
        assert_eq!(
            learned[0].0, peer,
            "attributed to the sending wireguard peer"
        );
        assert_eq!(learned[0].1.key, key, "the advertised disco key is learned");
        assert_eq!(learned[0].1.src, std::net::IpAddr::from(src));

        // A TSMP message that is NOT an advertisement stays in the batch (Go leaves the types it
        // does not consume to the filter, which accepts TSMP) and teaches us nothing.
        let mut ping = vec![ts_packet::tsmp::TSMP_TYPE_PING];
        ping.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let mut packets = vec![tsmp_packet4(src, dst, &ping)];
        let mut harvest = InboundHarvest::default();
        filter_inbound_from_peer(
            &DenyAll,
            &mut flowtrack::FlowCache::default(),
            peer,
            &mut packets,
            RejectConfig::default(),
            &mut harvest,
        );
        assert_eq!(packets.len(), 1, "a TSMP ping still bypasses the ACL");
        assert!(
            harvest.learned_disco_keys.is_empty(),
            "a ping advertises no disco key"
        );
    }

    /// The negative case, at the dataplane boundary: a TSMP body that is *nearly* an
    /// advertisement must not be half-parsed into a learned key. None of these may put anything
    /// in the harvest — a truncated key that was zero-padded, or a zero key that was accepted,
    /// would be a wrong disco key bound to a real peer.
    #[test]
    fn malformed_tsmp_disco_key_advertisements_teach_nothing() {
        let peer = PeerId(7);
        let src = [100, 64, 0, 2];
        let dst = [100, 64, 0, 1];

        // A truncated advertisement: the type byte and only 31 of 32 key bytes.
        let mut truncated = advertisement_body([0xa5u8; 32]);
        truncated.truncate(32);

        for (name, body, still_delivered) in [
            ("truncated advertisement", truncated, true),
            (
                "unknown TSMP type byte",
                {
                    let mut b = advertisement_body([0xa5u8; 32]);
                    b[0] = b'Z';
                    b
                },
                true,
            ),
            // A well-formed advertisement of the zero key: Go parses it but publishes only
            // `if !discoKeyAdvert.Key.IsZero()`, so it teaches nothing — and it is still a TSMP
            // message we consumed, so it is still dropped.
            (
                "zero-key advertisement",
                advertisement_body([0u8; 32]),
                false,
            ),
        ] {
            let mut packets = vec![tsmp_packet4(src, dst, &body)];
            let mut harvest = InboundHarvest::default();
            filter_inbound_from_peer(
                &DenyAll,
                &mut flowtrack::FlowCache::default(),
                peer,
                &mut packets,
                RejectConfig::default(),
                &mut harvest,
            );

            assert!(
                harvest.learned_disco_keys.is_empty(),
                "a {name} must not be half-parsed into a learned disco key"
            );
            assert_eq!(
                packets.len(),
                usize::from(still_delivered),
                "a {name} must {} be delivered",
                if still_delivered { "still" } else { "not" }
            );
        }
    }

    /// Our own disco key, the one this node advertises. Asymmetric so a reversed or offset slice
    /// would be visible in the marshalled bytes.
    const SELF_DISCO_KEY: [u8; 32] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x9c, 0x5f, 0x3a, 0x01, 0x7d, 0xe2, 0x44, 0xb8, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a,
        0x69, 0x78,
    ];

    /// An advertisement state with one peer, a v4 and a v6 address of our own, and a real disco key.
    fn advertisement_state(peer: PeerId, target: AdvertisementTarget) -> DiscoAdvertisementState {
        DiscoAdvertisementState {
            disco_key: SELF_DISCO_KEY,
            self_addrs: vec![
                std::net::IpAddr::from([100, 64, 0, 1]),
                std::net::IpAddr::from([
                    0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                ]),
            ],
            peers: HashMap::from([(peer, target)]),
        }
    }

    /// What this node advertises, and to whom (Go `magicsock.Conn.PriorityMessageForPeer`): the
    /// happy path emits the exact bytes `TSMPDiscoKeyAdvertisement.Marshal` emits, and each of Go's
    /// refusals emits nothing at all.
    #[test]
    fn disco_advertisement_matches_priority_message_for_peer() {
        let peer = PeerId(3);
        let peer_v4 = std::net::IpAddr::from([100, 64, 0, 2]);
        let target = AdvertisementTarget {
            node_addr: peer_v4,
            wireguard_only: false,
        };
        let state = advertisement_state(peer, target);

        // Happy path: a v4 peer gets a v4 advertisement sourced from our v4 address — the first
        // self address in the destination's family (Go `selfIPMatchingFamily`).
        let msg = state
            .advertisement_for(peer)
            .expect("a Tailscale peer with a matching-family address must be advertised to");
        let parsed = ts_packet::tsmp::DiscoKeyAdvertisement::parse(&msg)
            .expect("what we emit must parse as an advertisement");
        assert_eq!(parsed.key, SELF_DISCO_KEY, "we advertise OUR disco key");
        assert_eq!(parsed.src, std::net::IpAddr::from([100, 64, 0, 1]));
        assert_eq!(parsed.dst, peer_v4);
        assert_eq!(
            msg,
            ts_packet::tsmp::DiscoKeyAdvertisement {
                src: std::net::IpAddr::from([100, 64, 0, 1]),
                dst: peer_v4,
                key: SELF_DISCO_KEY,
            }
            .marshal()
            .unwrap(),
            "the emitted bytes are exactly what Marshal produces"
        );

        // A v6 peer is sourced from our v6 address, not our v4 one.
        let peer_v6 = std::net::IpAddr::from([
            0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        ]);
        let v6_state = advertisement_state(
            peer,
            AdvertisementTarget {
                node_addr: peer_v6,
                wireguard_only: false,
            },
        );
        let parsed = v6_state
            .advertisement_for(peer)
            .and_then(|m| ts_packet::tsmp::DiscoKeyAdvertisement::parse(&m))
            .expect("a v6 peer must be advertised to over v6");
        assert!(parsed.src.is_ipv6(), "source must match the peer's family");
        assert_eq!(parsed.dst, peer_v6);

        // Refusal 1 (Go `disco.IsZero()`): no disco key of our own, nothing to advertise.
        let mut no_key = advertisement_state(peer, target);
        no_key.disco_key = [0u8; 32];
        assert!(
            no_key.advertisement_for(peer).is_none(),
            "the zero disco key must never be advertised"
        );

        // Refusal 2 (Go `endpointForNodeKey` miss / `!self.Valid()`): a peer the netmap snapshot
        // does not cover, and a node with no addresses of its own.
        assert!(
            state.advertisement_for(PeerId(0xbad)).is_none(),
            "an unknown peer must not be advertised to"
        );
        let mut no_self = advertisement_state(peer, target);
        no_self.self_addrs.clear();
        assert!(
            no_self.advertisement_for(peer).is_none(),
            "a node with no tailnet address of its own has no source to advertise from"
        );

        // Refusal 3 (Go `ep.isWireguardOnly`): "Do not send TSMP messages to peers that only speaks
        // wireguard" — such a peer would hand it to its host stack as an unknown protocol.
        let wg_only = advertisement_state(
            peer,
            AdvertisementTarget {
                node_addr: peer_v4,
                wireguard_only: true,
            },
        );
        assert!(
            wg_only.advertisement_for(peer).is_none(),
            "a WireGuard-only peer must never be sent TSMP"
        );

        // Refusal 4 (Go `selfIPMatchingFamily` returning the zero Addr): an IPv4-only node has no
        // source address for a packet to a peer's IPv6 address.
        let mut v4_only = advertisement_state(
            peer,
            AdvertisementTarget {
                node_addr: peer_v6,
                wireguard_only: false,
            },
        );
        v4_only.self_addrs = vec![std::net::IpAddr::from([100, 64, 0, 1])];
        assert!(
            v4_only.advertisement_for(peer).is_none(),
            "no self address in the peer's family means no advertisement"
        );
    }

    /// End to end, over a real WireGuard handshake: when a session with a peer comes up, this
    /// node's dataplane emits its own TSMP disco-key advertisement to that peer — and the peer's
    /// dataplane learns the key from it and drops the packet.
    ///
    /// This is the send side (Go capability version 144) meeting the receive side already in this
    /// tree, so the assertion is not "some bytes went out" but "the far side learned exactly the
    /// disco key we hold". B is deliberately left with no advertisement state, which also pins the
    /// unconfigured case: it establishes the same session and sends nothing back.
    #[test]
    fn session_establishment_advertises_our_disco_key_to_the_peer() {
        let underlay: UnderlayTransportId = 0.into();
        let wg_peer = ts_tunnel::PeerId(1);
        let peer = PeerId(1);
        let a_addr = std::net::IpAddr::from([100, 64, 0, 1]);
        let b_addr = std::net::IpAddr::from([100, 64, 0, 2]);

        let (a_static, b_static) = (NodeKeyPair::new(), NodeKeyPair::new());
        let (mut a, mut b) = (
            DataPlane::new(a_static.clone()),
            DataPlane::new(b_static.clone()),
        );

        for (dp, key) in [(&mut a, b_static.public), (&mut b, a_static.public)] {
            dp.wireguard.upsert_peer(
                wg_peer,
                ts_tunnel::PeerConfig {
                    key,
                    psk: [0u8; 32].into(),
                    persistent_keepalive_interval: None,
                },
            );
            dp.ur_out.table.insert(peer, underlay);
        }

        // Only A knows how to advertise: its own disco key, its own address, and B's address.
        a.disco_advertisement = Some(Arc::new(advertisement_state(
            peer,
            AdvertisementTarget {
                node_addr: b_addr,
                wireguard_only: false,
            },
        )));

        // B attributes A's tailnet address to the WireGuard peer that carries it, as the runtime's
        // source filter does — without that, B drops the advertisement before parsing it.
        let mut src_filter = ts_bart::Table::default();
        src_filter.insert(ipnet::IpNet::from(a_addr), peer);
        b.src_filter_in = Arc::new(src_filter);

        // Drive the handshake. Only the initiation is kicked off directly (the dataplane starts one
        // from routed outbound traffic, which is not what this test is about); everything after it
        // goes through `process_inbound`, the path under test.
        let take = |out: HashMap<(UnderlayTransportId, PeerId), Vec<PacketMut>>| {
            out.into_values().flatten().collect::<Vec<_>>()
        };
        let init = a
            .wireguard
            .send([(wg_peer, vec![PacketMut::from(&b"hello"[..])])])
            .to_peers
            .remove(&wg_peer)
            .expect("handshake initiation");

        let resp = take(b.process_inbound(init).to_peers);
        assert!(!resp.is_empty(), "B must answer the handshake initiation");

        // A completes the handshake. Its session is now current, so alongside the queued data it
        // emits the advertisement.
        let from_a = take(a.process_inbound(resp).to_peers);
        assert_eq!(
            from_a.len(),
            2,
            "A must emit the queued data AND its disco-key advertisement"
        );

        // B learns A's disco key from it, and the advertisement itself is consumed rather than
        // delivered to B's local stack.
        let inbound = b.process_inbound(from_a);
        assert_eq!(
            inbound
                .learned_disco_keys
                .iter()
                .map(|(peer, advert)| (*peer, advert.key))
                .collect::<Vec<_>>(),
            vec![(peer, SELF_DISCO_KEY)],
            "B must learn exactly the disco key A holds, attributed to A's wireguard peer"
        );
        assert!(
            inbound.to_peers.is_empty(),
            "B has no advertisement state, so it advertises nothing back"
        );
    }

    /// Order regression: the advertisement must LEAD the traffic the same establishment released,
    /// not trail it.
    ///
    /// wireguard-go hands a priority message straight to the peer's *outbound* queue
    /// (`SendPriorityMessage` → `queueOutboundIfRunning`) and runs it before the flush that
    /// follows at both call sites — `peer.SendPriorityMessage()` ahead of `peer.SendKeepalive()`
    /// on the initiator and ahead of `peer.SendStagedPackets()` on the responder
    /// (`device/receive.go`) — so the advertisement is the first thing on the wire once a keypair
    /// becomes current. In this tree the flush has already happened inside `Endpoint::recv` by the
    /// time the advertisement exists, so `process_inbound` has to splice it in front; appending it
    /// would put it behind up to `MAX_QUEUED_PER_PEER` packets of queued traffic.
    ///
    /// The order is read off B's *decrypted* stream — its capture tee, which sees every inbound
    /// packet before any filtering — so what is pinned is the order the peer actually observes,
    /// not the order of a local vector.
    #[test]
    fn the_advertisement_leads_the_traffic_released_by_the_same_establishment() {
        let underlay: UnderlayTransportId = 0.into();
        let wg_peer = ts_tunnel::PeerId(1);
        let peer = PeerId(1);
        let a_addr = std::net::IpAddr::from([100, 64, 0, 1]);
        let b_addr = std::net::IpAddr::from([100, 64, 0, 2]);

        let (a_static, b_static) = (NodeKeyPair::new(), NodeKeyPair::new());
        let (mut a, mut b) = (
            DataPlane::new(a_static.clone()),
            DataPlane::new(b_static.clone()),
        );

        for (dp, key) in [(&mut a, b_static.public), (&mut b, a_static.public)] {
            dp.wireguard.upsert_peer(
                wg_peer,
                ts_tunnel::PeerConfig {
                    key,
                    psk: [0u8; 32].into(),
                    persistent_keepalive_interval: None,
                },
            );
            dp.ur_out.table.insert(peer, underlay);
        }

        a.disco_advertisement = Some(Arc::new(advertisement_state(
            peer,
            AdvertisementTarget {
                node_addr: b_addr,
                wireguard_only: false,
            },
        )));

        let mut src_filter = ts_bart::Table::default();
        src_filter.insert(ipnet::IpNet::from(a_addr), peer);
        b.src_filter_in = Arc::new(src_filter);

        // Everything B decrypts, in arrival order, before any filtering runs.
        let recorded: CaptureLog = Arc::new(Mutex::new(Vec::new()));
        let sink = recorded.clone();
        b.capture = Some(Arc::new(move |path: CapturePath, bytes: &[u8]| {
            sink.lock().unwrap().push((path, bytes.to_vec()));
        }));

        let take = |out: HashMap<(UnderlayTransportId, PeerId), Vec<PacketMut>>| {
            out.into_values().flatten().collect::<Vec<_>>()
        };

        // Traffic for a peer with no session yet: it stages, and a handshake starts.
        const QUEUED: &[u8] = b"staged while the session was still coming up";
        let init = a
            .wireguard
            .send([(wg_peer, vec![PacketMut::from(QUEUED)])])
            .to_peers
            .remove(&wg_peer)
            .expect("handshake initiation");
        let resp = take(b.process_inbound(init).to_peers);

        // A's keypair becomes current here, which both flushes the staged packet and produces the
        // advertisement — the batch whose order is under test.
        let from_a = take(a.process_inbound(resp).to_peers);
        assert_eq!(
            from_a.len(),
            2,
            "A must emit the queued data AND its disco-key advertisement"
        );

        // Hand them to B in exactly the order A produced them.
        let learned = b.process_inbound(from_a).learned_disco_keys;
        assert_eq!(
            learned
                .iter()
                .map(|(peer, advert)| (*peer, advert.key))
                .collect::<Vec<_>>(),
            vec![(peer, SELF_DISCO_KEY)],
            "B must still learn A's disco key"
        );

        let advertisement = ts_packet::tsmp::DiscoKeyAdvertisement {
            src: a_addr,
            dst: b_addr,
            key: SELF_DISCO_KEY,
        }
        .marshal()
        .expect("a v4 advertisement between two v4 addresses marshals");

        let captured = recorded.lock().unwrap();
        let from_peer = captured
            .iter()
            .filter(|(path, _)| *path == CapturePath::FromPeer)
            .map(|(_, bytes)| bytes.as_slice())
            .collect::<Vec<_>>();
        assert_eq!(from_peer.len(), 2, "B must decrypt both of A's packets");
        // The send path zero-pads each payload up to a 16-byte boundary and the receiver delivers
        // it with that padding intact (see `session::PADDING_MULTIPLE`), so compare on the leading
        // bytes rather than for equality.
        assert!(
            from_peer[0].starts_with(&advertisement),
            "the advertisement must reach the peer FIRST, ahead of the traffic the same \
             establishment released"
        );
        assert!(
            from_peer[1].starts_with(QUEUED),
            "the queued traffic follows the advertisement"
        );
    }

    /// Behavioral guard: an installed capture hook MUST be invoked with `CapturePath::FromLocal`
    /// and the exact packet bytes for every outbound packet. The tee sits at the top of
    /// `process_outbound`, before `or_out.route` consumes the packets, so it fires regardless of
    /// whether a wireguard peer exists (an empty router just drops the routed packets afterward).
    /// This is the only end-to-end guard that the dataplane capture tee actually fires; a refactor
    /// that drops the tee would leave every byte-layout test green.
    #[test]
    fn capture_hook_fires_on_outbound() {
        let mut dp = DataPlane::new(NodeKeyPair::new());

        let recorded: CaptureLog = Arc::new(Mutex::new(Vec::new()));
        let sink = recorded.clone();
        dp.capture = Some(Arc::new(move |path: CapturePath, bytes: &[u8]| {
            sink.lock().unwrap().push((path, bytes.to_vec()));
        }));

        // The outbound tee passes `p.as_ref()` as-given; the bytes need not be a valid IP packet.
        let payload: Vec<u8> = vec![0xde, 0xad, 0xbe, 0xef];
        let packet = PacketMut::from(payload.clone());

        drop(dp.process_outbound(vec![packet]));

        let captured = recorded.lock().unwrap();
        assert_eq!(captured.len(), 1, "hook must fire exactly once per packet");
        assert_eq!(captured[0].0, CapturePath::FromLocal);
        assert_eq!(captured[0].1, payload);
    }

    /// A minimal IPv4/UDP datagram from `src` to `dst`. The control for the outbound TSMP refusal:
    /// same source, same destination, same batch as the forged advertisement — only the protocol
    /// byte differs.
    fn v4_udp_packet(
        src: std::net::SocketAddr,
        dst: std::net::SocketAddr,
        payload: &[u8],
    ) -> Vec<u8> {
        let (std::net::IpAddr::V4(src_ip), std::net::IpAddr::V4(dst_ip)) = (src.ip(), dst.ip())
        else {
            panic!("v4_udp_packet needs two IPv4 addresses");
        };
        let total_len = u16::try_from(IP4_HEADER_LEN + 8 + payload.len()).unwrap();
        let mut buf = vec![0u8; usize::from(total_len)];
        buf[0] = 0x45; // version 4, IHL 5 (no options)
        buf[2..4].copy_from_slice(&total_len.to_be_bytes());
        buf[8] = 64; // TTL
        buf[9] = 17; // UDP
        buf[12..16].copy_from_slice(&src_ip.octets());
        buf[16..20].copy_from_slice(&dst_ip.octets());
        buf[20..22].copy_from_slice(&src.port().to_be_bytes());
        buf[22..24].copy_from_slice(&dst.port().to_be_bytes());
        let udp_len = u16::try_from(8 + payload.len()).unwrap();
        buf[24..26].copy_from_slice(&udp_len.to_be_bytes());
        // UDP checksum left 0 ("not computed"), which is legal for IPv4.
        buf[IP4_HEADER_LEN + 8..].copy_from_slice(payload);
        buf
    }

    /// What `process_outbound` refuses, mirroring the `p.IPProto == ipproto.TSMP` arm of Go
    /// `tstun.filterPacketOutboundToWireGuard` — plus the three shapes this tree drops that Go's
    /// TSMP arm alone does not, because there is no outbound ACL behind it here to refuse them as
    /// `ipproto.Unknown`. See [`outbound_packet_carries_tsmp`].
    #[test]
    fn outbound_tsmp_classification_matches_go_decode() {
        let v4_src = std::net::IpAddr::from([100, 64, 0, 1]);
        let v4_dst = std::net::IpAddr::from([100, 64, 0, 2]);
        let v4 = ts_packet::tsmp::DiscoKeyAdvertisement {
            src: v4_src,
            dst: v4_dst,
            key: SELF_DISCO_KEY,
        }
        .marshal()
        .expect("a v4 advertisement between two v4 addresses marshals");
        let v6 = ts_packet::tsmp::DiscoKeyAdvertisement {
            src: std::net::IpAddr::V6(IPV6_FIXTURE_SRC),
            dst: std::net::IpAddr::V6(IPV6_FIXTURE_DST),
            key: SELF_DISCO_KEY,
        }
        .marshal()
        .expect("a v6 advertisement between two v6 addresses marshals");

        // The forgery this exists to stop, in both families: bytes byte-identical to what this node
        // would itself emit, handed to us by the host instead.
        assert!(
            outbound_packet_carries_tsmp(&v4),
            "an IPv4 TSMP packet from the host is refused"
        );
        assert!(
            outbound_packet_carries_tsmp(&v6),
            "an IPv6 TSMP packet from the host is refused"
        );

        // Ordinary traffic is untouched — the refusal is protocol-specific, not a blanket drop.
        assert!(
            !outbound_packet_carries_tsmp(&v4_udp_packet(
                std::net::SocketAddr::new(v4_src, 4242),
                std::net::SocketAddr::new(v4_dst, 4343),
                b"hello"
            )),
            "IPv4 UDP passes"
        );
        assert!(
            !outbound_packet_carries_tsmp(&ipv6_udp_packet(&udp_header(53))),
            "IPv6 UDP passes"
        );

        // Go demotes a *fragmented* IPv4 TSMP packet to `ipproto.Unknown`, which its outbound ACL
        // then drops for "unknown proto". With no outbound ACL here the protocol byte is the whole
        // verdict, so the refusal happens one step earlier and the packet still never ships.
        let mut fragmented = v4.clone();
        fragmented[6] = 0x20; // More Fragments
        assert!(
            outbound_packet_carries_tsmp(&fragmented),
            "a fragmented IPv4 TSMP packet is refused too"
        );

        // An IPv6 Fragment extension header naming TSMP: Go classifies the head fragment TSMP and
        // its followers `ipproto.Fragment`. Both are refused here — every fragment of one datagram
        // repeats the same Next Header, and with the head refused no peer could reassemble anyway.
        assert!(
            outbound_packet_carries_tsmp(&ipv6_fragment_packet(
                ts_packet::tsmp::IP_PROTO_TSMP,
                0,
                true,
                &[b'a'; 33],
            )),
            "the head fragment of an IPv6 TSMP datagram is refused"
        );
        assert!(
            outbound_packet_carries_tsmp(&ipv6_fragment_packet(
                ts_packet::tsmp::IP_PROTO_TSMP,
                MIN_FRAG_BLKS,
                false,
                &[0u8; 8],
            )),
            "so are its later fragments"
        );
        assert!(
            !outbound_packet_carries_tsmp(&ipv6_fragment_packet(17, 0, true, &udp_header(53))),
            "a fragmented IPv6 UDP datagram is not TSMP and still passes"
        );

        // Nothing to classify: not IP at all, or truncated before the protocol byte can be trusted.
        assert!(
            !outbound_packet_carries_tsmp(&[]),
            "the empty buffer passes"
        );
        assert!(
            !outbound_packet_carries_tsmp(&[0xde, 0xad, 0xbe, 0xef]),
            "a non-IP buffer passes (the router drops it for want of a destination)"
        );
        assert!(
            !outbound_packet_carries_tsmp(&v4[..IP4_HEADER_LEN - 1]),
            "an IPv4 packet cut off inside its header passes"
        );
        assert!(
            !outbound_packet_carries_tsmp(&v6[..IP6_HEADER_LEN - 1]),
            "an IPv6 packet cut off inside its header passes"
        );
    }

    /// The whole point of the outbound TSMP refusal, end to end, together with the negative case
    /// that keeps it from silently disabling capability version 144.
    ///
    /// A local process writes a well-formed disco-key advertisement — naming a disco key of its own
    /// choosing, addressed to a peer whose route really does resolve to a live WireGuard session —
    /// into the tun. The peer must never see it: it arrives inside this node's session from this
    /// node's tailnet address, so it is indistinguishable from one this node meant to send, and the
    /// peer would bind the forger's key for us. Ordinary traffic in the same batch to the same
    /// destination must be untouched.
    ///
    /// And the advertisement this node itself sends must still go out. It is built by
    /// `DiscoAdvertisementState::advertisement_for` and injected by `process_inbound` on session
    /// establishment, *below* the refusal — Go has the same relationship, where `injectedRead`
    /// bypasses the outbound filter. Without this half of the test a drop placed one layer too low
    /// would look green.
    #[test]
    fn host_written_tsmp_is_dropped_while_our_own_advertisement_still_goes_out() {
        let underlay: UnderlayTransportId = 0.into();
        let wg_peer = ts_tunnel::PeerId(1);
        let peer = PeerId(1);
        let a_addr = std::net::IpAddr::from([100, 64, 0, 1]);
        let b_addr = std::net::IpAddr::from([100, 64, 0, 2]);

        let (a_static, b_static) = (NodeKeyPair::new(), NodeKeyPair::new());
        let (mut a, mut b) = (
            DataPlane::new(a_static.clone()),
            DataPlane::new(b_static.clone()),
        );

        for (dp, key) in [(&mut a, b_static.public), (&mut b, a_static.public)] {
            dp.wireguard.upsert_peer(
                wg_peer,
                ts_tunnel::PeerConfig {
                    key,
                    psk: [0u8; 32].into(),
                    persistent_keepalive_interval: None,
                },
            );
            dp.ur_out.table.insert(peer, underlay);
        }

        a.disco_advertisement = Some(Arc::new(advertisement_state(
            peer,
            AdvertisementTarget {
                node_addr: b_addr,
                wireguard_only: false,
            },
        )));

        // A routes B's tailnet address to the wireguard peer, so a host-written packet addressed to
        // B really would be encrypted and shipped were it not refused. Without this the test would
        // pass on an empty routing table and prove nothing.
        let mut routes = ts_bart::Table::default();
        routes.insert(
            ipnet::IpNet::from(b_addr),
            or::outbound::RouteAction::Wireguard(peer),
        );
        a.or_out.swap(routes);

        // B attributes A's tailnet address to the wireguard peer that carries it, as the runtime's
        // source filter does.
        let mut src_filter = ts_bart::Table::default();
        src_filter.insert(ipnet::IpNet::from(a_addr), peer);
        b.src_filter_in = Arc::new(src_filter);

        // Everything B decrypts, in arrival order, before any filtering runs.
        let recorded: CaptureLog = Arc::new(Mutex::new(Vec::new()));
        let sink = recorded.clone();
        b.capture = Some(Arc::new(move |path: CapturePath, bytes: &[u8]| {
            sink.lock().unwrap().push((path, bytes.to_vec()));
        }));

        let take = |out: HashMap<(UnderlayTransportId, PeerId), Vec<PacketMut>>| {
            out.into_values().flatten().collect::<Vec<_>>()
        };

        // Establish the session. A's own advertisement rides the establishment.
        let init = a
            .wireguard
            .send([(wg_peer, vec![PacketMut::from(&b"hello"[..])])])
            .to_peers
            .remove(&wg_peer)
            .expect("handshake initiation");
        let resp = take(b.process_inbound(init).to_peers);
        let from_a = take(a.process_inbound(resp).to_peers);
        let learned = b.process_inbound(from_a).learned_disco_keys;
        assert_eq!(
            learned
                .iter()
                .map(|(peer, advert)| (*peer, advert.key))
                .collect::<Vec<_>>(),
            vec![(peer, SELF_DISCO_KEY)],
            "our own advertisement must still reach the peer: it is injected below process_outbound"
        );

        // Now the forgery, alongside ordinary traffic to the same destination in the same batch.
        const FORGED_KEY: [u8; 32] = [0xff; 32];
        let forged = ts_packet::tsmp::DiscoKeyAdvertisement {
            src: a_addr,
            dst: b_addr,
            key: FORGED_KEY,
        }
        .marshal()
        .expect("a v4 advertisement between two v4 addresses marshals");
        const CARRIED: &[u8] = b"ordinary traffic in the same batch";
        let control = v4_udp_packet(
            std::net::SocketAddr::new(a_addr, 4242),
            std::net::SocketAddr::new(b_addr, 4343),
            CARRIED,
        );

        // This is the only test that increments this counter, so the delta is exact.
        let counted_before = metric_out_to_wg_drop_tsmp().value();
        let out = a.process_outbound(vec![
            PacketMut::from(&forged[..]),
            PacketMut::from(&control[..]),
        ]);

        let mark = recorded.lock().unwrap().len();
        let inbound = b.process_inbound(take(out.to_peers));
        assert!(
            inbound.learned_disco_keys.is_empty(),
            "the forged advertisement must never reach the peer, or it binds the forger's key for us"
        );

        let captured = recorded.lock().unwrap();
        let delivered = captured[mark..]
            .iter()
            .filter(|(path, _)| *path == CapturePath::FromPeer)
            .map(|(_, bytes)| bytes.as_slice())
            .collect::<Vec<_>>();
        assert_eq!(
            delivered.len(),
            1,
            "exactly the one non-TSMP packet of the batch crosses the tunnel"
        );
        // The send path zero-pads each payload up to a 16-byte boundary and the receiver delivers it
        // with that padding intact (see `session::PADDING_MULTIPLE`), so compare on the leading bytes.
        assert!(
            delivered[0].starts_with(&control),
            "and it is the ordinary traffic, unaltered"
        );

        assert_eq!(
            metric_out_to_wg_drop_tsmp().value(),
            counted_before + 1,
            "the drop is counted in tstun_out_to_wg_drop_tsmp (Go metricPacketOutDropTSMP)"
        );
    }

    /// Run one inbound packet through the real inbound filter with `flows` as the connection-
    /// tracking state, and report whether it survived.
    fn admitted(
        filter: &(dyn ts_packetfilter::Filter + Send + Sync),
        flows: &mut flowtrack::FlowCache,
        packet: Vec<u8>,
    ) -> bool {
        let mut packets = vec![PacketMut::from(packet)];
        let mut harvest = InboundHarvest::default();
        filter_inbound_from_peer(
            filter,
            flows,
            PeerId(1),
            &mut packets,
            RejectConfig::default(),
            &mut harvest,
        );
        assert!(
            harvest.learned_disco_keys.is_empty(),
            "no TSMP advertisement in these fixtures"
        );
        !packets.is_empty()
    }

    /// A dataplane wired up well enough that `process_outbound` really routes a packet to a peer,
    /// so the flow-tracking tests exercise the live outbound path rather than a stub.
    fn dataplane_routing_to(peer: PeerId, dsts: &[std::net::IpAddr]) -> DataPlane {
        let mut dp = DataPlane::new(NodeKeyPair::new());
        dp.wireguard.upsert_peer(
            ts_tunnel::PeerId(peer.0),
            ts_tunnel::PeerConfig {
                key: NodeKeyPair::new().public,
                psk: [0u8; 32].into(),
                persistent_keepalive_interval: None,
            },
        );
        dp.ur_out.table.insert(peer, 0.into());
        let mut routes = ts_bart::Table::default();
        for dst in dsts {
            routes.insert(
                ipnet::IpNet::from(*dst),
                or::outbound::RouteAction::Wireguard(peer),
            );
        }
        dp.or_out.swap(routes);
        dp
    }

    /// Go's reverse-flow connection tracking (`wgengine/filter`'s `Filter.state`), across the two
    /// paths it spans: `process_outbound` records the reversed tuple of every outbound UDP
    /// datagram (Go `UpdateOutboundFlowState`, which upstream `e0677ccc7` had to start calling on
    /// the netstack-injected path — the only path this engine has), and the inbound filter admits
    /// the reply on it ahead of any rule (Go `runIn4`'s `return Accept, "cached"`).
    ///
    /// Every verdict here is taken under a **deny-all** ACL, so an admission can only have come
    /// from the flow cache. The refusals are the point of the test as much as the admission is: a
    /// conntrack that admits too much is an open door, so each of the four fields of Go's
    /// `flowtrack.Tuple` is varied in turn and must miss.
    #[test]
    fn an_outbound_udp_flow_admits_its_own_reply_and_nothing_else() {
        let peer = PeerId(1);
        let me = std::net::IpAddr::from([100, 64, 0, 1]);
        let them = std::net::IpAddr::from([100, 64, 0, 2]);
        let elsewhere = std::net::IpAddr::from([100, 64, 0, 3]);
        let sa = |ip, port| std::net::SocketAddr::new(ip, port);

        let mut dp = dataplane_routing_to(peer, &[them, elsewhere]);

        // Our datagram out, and the reply it should get: the same tuple, reversed. Our source port
        // is ephemeral, which is exactly why no ACL from control can name it.
        let query = v4_udp_packet(sa(me, 41234), sa(them, 53), b"query");
        let reply = v4_udp_packet(sa(them, 53), sa(me, 41234), b"answer");

        // Before anything is sent the reply is an unsolicited datagram to an ephemeral port, and a
        // deny-all ACL drops it. That is what every UDP reply used to get in this fork.
        assert!(
            !admitted(&DenyAll, &mut dp.flows, reply.clone()),
            "an inbound datagram matching no outbound flow and no rule is dropped"
        );

        let out = dp.process_outbound(vec![PacketMut::from(query)]);
        assert!(
            !out.to_peers.is_empty(),
            "the datagram really did route to the peer, so this is the live outbound path"
        );

        assert!(
            admitted(&DenyAll, &mut dp.flows, reply.clone()),
            "the reply to our own datagram is admitted with no rule matching it"
        );

        // One field of Go's tuple differs in each of these, and each must miss. Without them the
        // cache would be a blanket "any inbound UDP is fine once we have sent one".
        for (why, packet) in [
            (
                "a different source PORT",
                v4_udp_packet(sa(them, 5353), sa(me, 41234), b"x"),
            ),
            (
                "a different source ADDRESS",
                v4_udp_packet(sa(elsewhere, 53), sa(me, 41234), b"x"),
            ),
            (
                "a different destination PORT",
                v4_udp_packet(sa(them, 53), sa(me, 41235), b"x"),
            ),
            (
                "a different destination ADDRESS",
                v4_udp_packet(sa(them, 53), sa(elsewhere, 41234), b"x"),
            ),
        ] {
            assert!(
                !admitted(&DenyAll, &mut dp.flows, packet),
                "{why} does not ride the recorded entry"
            );
        }

        // And the entry admits, it never denies: the ACL still decides everything the cache misses.
        assert!(
            admitted(
                &AllowAll,
                &mut dp.flows,
                v4_udp_packet(sa(elsewhere, 53), sa(me, 41234), b"x")
            ),
            "a cache miss falls through to the rule match, exactly as Go does"
        );
    }

    /// SCTP is the second arm of Go's `case ipproto.UDP, ipproto.SCTP` — on both the recording and
    /// the admitting side — and the protocol is part of the tuple, so a UDP entry cannot carry an
    /// SCTP datagram or the other way round.
    #[test]
    fn outbound_sctp_flows_are_tracked_and_do_not_cross_protocols() {
        let peer = PeerId(1);
        let dst = std::net::IpAddr::V4(IPV4_FIXTURE_DST);
        let mut dp = dataplane_routing_to(peer, &[dst]);

        // `v4_packet` addresses this fixture src -> dst, so the reply is dst -> src. `sctp_header`
        // writes source port 54276.
        let out = v4_packet(132, 0, false, &sctp_header(443, SCTP_HEADER_LEN));
        let mut reply = v4_packet(132, 0, false, &sctp_header(54276, SCTP_HEADER_LEN));
        reply[12..16].copy_from_slice(&IPV4_FIXTURE_DST.octets());
        reply[16..20].copy_from_slice(&IPV4_FIXTURE_SRC.octets());
        reply[20..22].copy_from_slice(&443u16.to_be_bytes());

        assert!(
            !admitted(&DenyAll, &mut dp.flows, reply.clone()),
            "an unsolicited SCTP packet with no rule is dropped"
        );
        drop(dp.process_outbound(vec![PacketMut::from(out)]));
        assert!(
            admitted(&DenyAll, &mut dp.flows, reply.clone()),
            "the SCTP reply to our own packet is admitted (Go's second switch arm)"
        );

        // Same addresses, same ports, UDP instead of SCTP: the protocol is part of Go's tuple.
        //
        // Reinterpreting the SCTP header as a UDP one puts the verification tag where the UDP
        // length field belongs, and `UdpSlice::from_slice` refuses a length field the slice cannot
        // satisfy — so the datagram has to be given a real length here, or the drop below is the
        // parse failing and says nothing at all about the protocol in the tuple.
        let mut as_udp = reply.clone();
        as_udp[9] = 17;
        as_udp[24..26].copy_from_slice(&u16::try_from(SCTP_HEADER_LEN).unwrap().to_be_bytes());
        assert!(
            admitted(&AllowAll, &mut dp.flows, as_udp.clone()),
            "the fixture is a datagram the filter can parse, so the drop below is the tuple's"
        );
        assert!(
            !admitted(&DenyAll, &mut dp.flows, as_udp),
            "a UDP datagram does not ride an SCTP entry"
        );
    }

    /// What [`outbound_udp_or_sctp_flow`] records and — the half that keeps the cache honest —
    /// what it refuses to record, carrying Go's `decode4`/`decode6` refusals into
    /// `UpdateOutboundFlowState`. Everything this function declines leaves the reply where it was
    /// before: needing an ACL rule.
    #[test]
    fn outbound_flow_decoding_matches_go_decode() {
        let me = std::net::IpAddr::from([100, 64, 0, 1]);
        let them = std::net::IpAddr::from([100, 64, 0, 2]);
        let sa = |ip, port| std::net::SocketAddr::new(ip, port);

        // UDP: both ports off the wire, addresses in packet order — reversing them is the cache's
        // job (Go `MakeTuple(q.IPProto, q.Dst, q.Src)`), not the decoder's.
        assert_eq!(
            outbound_udp_or_sctp_flow(&v4_udp_packet(sa(me, 41234), sa(them, 53), b"q")),
            Some((IpProto::UDP, sa(me, 41234), sa(them, 53))),
            "an outbound UDP datagram yields its own tuple"
        );

        // SCTP: etherparse has no arm for it, so the ports come from Go's `sub[0:2]`/`sub[2:4]`.
        let v4_fixture_src = std::net::IpAddr::V4(IPV4_FIXTURE_SRC);
        let v4_fixture_dst = std::net::IpAddr::V4(IPV4_FIXTURE_DST);
        assert_eq!(
            outbound_udp_or_sctp_flow(&v4_packet(
                132,
                0,
                false,
                &sctp_header(443, SCTP_HEADER_LEN)
            )),
            Some((
                IpProto::SCTP,
                sa(v4_fixture_src, 54276),
                sa(v4_fixture_dst, 443)
            )),
            "an outbound SCTP packet yields its tuple, ports read the way Go reads them"
        );
        assert_eq!(
            outbound_udp_or_sctp_flow(&v4_packet(
                132,
                0,
                false,
                &sctp_header(443, SCTP_HEADER_LEN - 1)
            )),
            None,
            "an SCTP common header too short to hold its ports records nothing, not a port-0 flow"
        );

        // Go's switch has exactly two arms; TCP, ICMP and TSMP fall through it.
        for (proto, name) in [(6u8, "TCP"), (1, "ICMP"), (99, "TSMP")] {
            assert_eq!(
                outbound_udp_or_sctp_flow(&v4_packet(proto, 0, false, &[0u8; 20])),
                None,
                "{name} is not tracked (Go tracks UDP and SCTP only)"
            );
        }

        // A *first* IPv4 fragment carries its whole UDP header, so `decode4` reads its ports and
        // the flow is recorded like an unfragmented datagram's...
        let mut head = v4_udp_packet(sa(me, 41234), sa(them, 53), b"payload!");
        head[6] = 0x20; // More Fragments, offset 0
        assert_eq!(
            outbound_udp_or_sctp_flow(&head),
            Some((IpProto::UDP, sa(me, 41234), sa(them, 53))),
            "the head fragment of an outbound datagram records the same tuple"
        );
        // ...while a non-first fragment is `ipproto.Fragment` to Go, matching neither arm, and has
        // no transport header whose ports could be invented.
        let mut later = v4_udp_packet(sa(me, 41234), sa(them, 53), b"payload!");
        later[6..8].copy_from_slice(&MIN_FRAG_BLKS.to_be_bytes());
        assert_eq!(
            outbound_udp_or_sctp_flow(&later),
            None,
            "a non-first IPv4 fragment records nothing"
        );

        // IPv6: the protocol comes from the base header only (Go `decode6`'s `b[6]`), so a UDP
        // header buried behind a chained extension header is not a flow upstream tracks either —
        // even though etherparse could walk to it.
        assert_eq!(
            outbound_udp_or_sctp_flow(&ipv6_udp_packet(&udp_header(53))),
            Some((
                IpProto::UDP,
                sa(std::net::IpAddr::V6(IPV6_FIXTURE_SRC), 54276),
                sa(std::net::IpAddr::V6(IPV6_FIXTURE_DST), 53)
            )),
            "an outbound IPv6 UDP datagram yields its tuple"
        );
        assert_eq!(
            outbound_udp_or_sctp_flow(&ipv6_with_prepended_ext_header(
                60,
                &ipv6_udp_packet(&udp_header(53))
            )),
            None,
            "a UDP header behind a chained extension header is not a tracked flow"
        );

        // A leading IPv6 Fragment header IS stepped over, exactly as `decode6` does.
        assert_eq!(
            outbound_udp_or_sctp_flow(&ipv6_fragment_packet(17, 0, true, &udp_header(53))),
            Some((
                IpProto::UDP,
                sa(std::net::IpAddr::V6(IPV6_FIXTURE_SRC), 54276),
                sa(std::net::IpAddr::V6(IPV6_FIXTURE_DST), 53)
            )),
            "a first IPv6 fragment records the tuple behind its Fragment header"
        );
        assert_eq!(
            outbound_udp_or_sctp_flow(&ipv6_fragment_packet(17, MIN_FRAG_BLKS, false, &[0u8; 8])),
            None,
            "a later IPv6 fragment records nothing"
        );

        // Nothing to decode at all.
        assert_eq!(outbound_udp_or_sctp_flow(&[]), None, "the empty buffer");
        assert_eq!(
            outbound_udp_or_sctp_flow(&[0xde, 0xad, 0xbe, 0xef]),
            None,
            "a non-IP buffer"
        );
    }

    /// Go `packet.TCPFin`, the flag bit `tcp_header` writes into the byte Go reads as `q.TCPFlags`.
    const TCP_FIN: u8 = 0x01;
    /// Go `packet.TCPSyn`.
    const TCP_SYN: u8 = 0x02;
    /// Go `packet.TCPRst`.
    const TCP_RST: u8 = 0x04;
    /// Go `packet.TCPAck`.
    const TCP_ACK: u8 = 0x10;

    /// A minimal 20-byte TCP header: the two ports, a data offset of 5 (no options, which is what
    /// makes it 20 bytes and what etherparse bounds-checks), and `flags` in `sub[13]` — the byte Go
    /// `decode4`/`decode6` copy into `q.TCPFlags`. The checksum is left zero; nothing on this path
    /// verifies it, and neither does Go's decoder.
    fn tcp_header(src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
        let mut hdr = vec![0u8; 20];
        hdr[0..2].copy_from_slice(&src_port.to_be_bytes());
        hdr[2..4].copy_from_slice(&dst_port.to_be_bytes());
        hdr[12] = 0x50; // data offset 5 (a 20-byte header), no options
        hdr[13] = flags;
        hdr
    }

    /// A minimal 8-byte ICMP/ICMPv6 message: type, code, a zero checksum, and four bytes of
    /// rest-of-header. Eight is the length Go guards every one of its type/code reads with
    /// (`len(q.b) >= q.subofs+8`), and etherparse's ICMP slices refuse anything shorter too.
    fn icmp_header(icmp_type: u8, icmp_code: u8) -> Vec<u8> {
        let mut hdr = vec![0u8; 8];
        hdr[0] = icmp_type;
        hdr[1] = icmp_code;
        hdr
    }

    /// Go's TCP reply carve-out, on real bytes through the whole inbound filter: `runIn4`/`runIn6`
    /// accept an inbound TCP segment that is not a SYN *before* any rule is consulted.
    ///
    /// ```text
    /// if !q.IsTCPSyn() {
    ///     return Accept, "tcp non-syn"
    /// }
    /// ```
    ///
    /// Every accept below is taken under a **deny-all** filter, so it can only have come from the
    /// carve-out. The motivating case is the first one: this node dials out, the peer answers with
    /// a SYN-ACK aimed at our ephemeral source port, and no ACL control can write will ever name
    /// that port. Without the carve-out the handshake never completes and the failure reads as a
    /// network fault rather than as a filter decision.
    ///
    /// The refusals are what keep it from being an open door, and they are the point of the test as
    /// much as the accepts are. A SYN — the one segment that can *start* an inbound session — still
    /// faces the rules, and so does a non-SYN segment buried under an IPv6 extension header, which
    /// upstream filters as protocol 43 rather than as TCP. The third refusal, a segment whose flags
    /// this fork never decoded, is pinned by every case that goes through [`stateless_verdict`]:
    /// they all carry [`ts_packetfilter::L4Header::Unknown`].
    ///
    /// Ported from github.com/tailscale/tailscale `wgengine/filter/filter.go` (`runIn4`, `runIn6`)
    /// and `net/packet/packet.go` (`IsTCPSyn`, `decode4`, `decode6`) at
    /// `3945b82f8a9550b54c33e61d4ed2227862d53e8a`.
    #[test]
    fn inbound_tcp_non_syn_is_admitted_without_a_rule_but_a_syn_is_not() {
        let flows = &mut flowtrack::FlowCache::default();
        // Source port 443, destination port 41234: the shape of a reply to a connection this node
        // opened. No rule in `DenyAll` names it, and none in a real tailnet ACL could.
        let v4 = |flags| v4_packet(6, 0, false, &tcp_header(443, 41234, flags));
        let v6 = |flags| ipv6_packet(6, &tcp_header(443, 41234, flags));

        for (why, flags) in [
            (
                "a SYN-ACK — the answer to our own outbound connection",
                TCP_SYN | TCP_ACK,
            ),
            (
                "a bare ACK — the continuation of an established session",
                TCP_ACK,
            ),
            ("a FIN-ACK closing that session", TCP_FIN | TCP_ACK),
            ("an RST tearing it down", TCP_RST),
            // Go's test is `(flags & (SYN|ACK)) == SYN`, so a segment with neither bit set is a
            // non-SYN as well. Ported as it stands rather than tightened.
            ("a segment with no flags at all", 0x00),
        ] {
            assert!(
                admitted(&DenyAll, flows, v4(flags)),
                "{why} is admitted with no rule matching it"
            );
            assert!(
                admitted(&DenyAll, flows, v6(flags)),
                "{why} is admitted on IPv6 too (Go `runIn6` carries the same arm)"
            );
        }

        // The negative that gives the carve-out its value: SYN set and ACK clear is Go's
        // `IsTCPSyn`, and it is the only way to open an inbound session.
        assert!(
            !admitted(&DenyAll, flows, v4(TCP_SYN)),
            "an inbound SYN with no matching rule is still dropped"
        );
        assert!(
            !admitted(&DenyAll, flows, v6(TCP_SYN)),
            "an inbound SYN with no matching rule is still dropped on IPv6"
        );
        // ...and it is admitted when a rule really does open the port, so the drop above is the
        // rules speaking and not the carve-out swallowing the packet.
        assert!(
            admitted(
                &acl(IPV4_FIXTURE_NET, &[6], 41234..=41234),
                flows,
                v4(TCP_SYN)
            ),
            "a rule opening the destination port admits the SYN"
        );

        // The protocol number the carve-out is scoped to is the one the **base** IP header
        // declares, which is what Go's `runIn4`/`runIn6` switch dispatches on. etherparse walks an
        // IPv6 extension-header chain through to the real transport, so a non-SYN segment behind a
        // Routing header hands this code a TCP transport slice for a packet upstream filters as
        // protocol 43. Admitting it would make "prepend an extension header" a way past the rules.
        for ext in [43u8, 60] {
            assert!(
                !admitted(
                    &DenyAll,
                    flows,
                    ipv6_with_prepended_ext_header(ext, &v6(TCP_ACK))
                ),
                "a non-SYN segment behind extension header {ext} is not TCP to the filter"
            );
        }
    }

    /// Go's ICMP reply carve-out, on real bytes through the whole inbound filter: `runIn4`/`runIn6`
    /// accept an ICMP echo *response* or an ICMP *error* before any rule is consulted.
    ///
    /// ```text
    /// if q.IsEchoResponse() || q.IsError() {
    ///     // ICMP responses are allowed.
    ///     return Accept, "icmp response ok"
    /// } else if f.matches4.matchIPsOnly(q, f.srcIPHasCap) {
    ///     // If any port is open to an IP, allow ICMP to it.
    ///     return Accept, "icmp ok"
    /// }
    /// ```
    ///
    /// The reply to a ping this node sent is unsolicited as far as any ACL is concerned, and so is
    /// the Packet Too Big that path-MTU discovery needs; both were silently dropped under a policy
    /// that does not grant the peer inbound access back.
    ///
    /// The negative half is the `else if`, which this fork already had: ICMP that is *not* a
    /// response must still go to the rules and be matched IPs-only, never admitted as a "response".
    /// An echo request is the case that matters — it is how an inbound ICMP session starts.
    ///
    /// Ported from github.com/tailscale/tailscale `wgengine/filter/filter.go` (`runIn4`, `runIn6`)
    /// and `net/packet/packet.go` (`IsEchoResponse`, `IsError`) at
    /// `3945b82f8a9550b54c33e61d4ed2227862d53e8a`.
    #[test]
    fn inbound_icmp_responses_are_admitted_without_a_rule_but_requests_are_not() {
        let flows = &mut flowtrack::FlowCache::default();
        let v4 = |icmp_type, icmp_code| v4_packet(1, 0, false, &icmp_header(icmp_type, icmp_code));
        let v6 = |icmp_type, icmp_code| ipv6_packet(58, &icmp_header(icmp_type, icmp_code));

        // Go `IsEchoResponse` and `IsError` on ICMPv4.
        for (why, icmp_type, icmp_code) in [
            ("an echo reply — the answer to our own ping", 0x00u8, 0u8),
            ("destination unreachable", 0x03, 1),
            ("time exceeded", 0x0b, 0),
            // Upstream's `ICMP4ParamProblem` is 0x12. IANA's Parameter Problem is 12 (0x0c) and
            // 0x12 is Address Mask Reply, so the constant names one message and holds another —
            // ported as it stands, because "fixing" it would admit type 12 traffic upstream drops.
            (
                "upstream's ICMP4ParamProblem constant, whatever IANA calls it",
                0x12,
                0,
            ),
        ] {
            assert!(
                admitted(&DenyAll, flows, v4(icmp_type, icmp_code)),
                "{why} is admitted with no rule matching it"
            );
        }

        // ...and on ICMPv6, where the type numbers are entirely different and Packet Too Big is an
        // error class of its own.
        for (why, icmp_type, icmp_code) in [
            ("an ICMPv6 echo reply", 129u8, 0u8),
            ("ICMPv6 destination unreachable", 1, 3),
            (
                "ICMPv6 packet too big — what path-MTU discovery rides on",
                2,
                0,
            ),
            ("ICMPv6 time exceeded", 3, 0),
            ("ICMPv6 parameter problem", 4, 0),
        ] {
            assert!(
                admitted(&DenyAll, flows, v6(icmp_type, icmp_code)),
                "{why} is admitted with no rule matching it"
            );
        }

        // The negatives. None of these is a "response", so each falls through to the rules — and a
        // deny-all filter says no.
        for (why, packet) in [
            (
                "an echo REQUEST is how an inbound session starts",
                v4(0x08, 0),
            ),
            (
                "an echo reply with a non-zero code is not one (Go tests the code)",
                v4(0x00, 1),
            ),
            (
                "IANA's Parameter Problem (12) is not upstream's constant (0x12)",
                v4(0x0c, 0),
            ),
            ("an ICMPv6 echo REQUEST", v6(128, 0)),
            ("an ICMPv6 echo reply with a non-zero code", v6(129, 1)),
            (
                "an ICMPv6 router advertisement is neither response nor error",
                v6(134, 0),
            ),
        ] {
            assert!(!admitted(&DenyAll, flows, packet), "{why}: still dropped");
        }

        // And what "still faces the rules" means: Go's `matchIPsOnly`, which this fork already
        // ported. A rule that opens *any* port to this destination admits the echo request, ports
        // ignored — so the drop above is the deny-all ruleset speaking, not the decode failing.
        assert!(
            admitted(&acl(IPV4_FIXTURE_NET, &[1], 443..=443), flows, v4(0x08, 0)),
            "an echo request is matched IPs-only, so a port-scoped ICMP rule admits it"
        );
    }

    /// The reply carve-outs sit inside Go's proto switch, and `pre()` runs *before* that switch. So
    /// the unconditional multicast and link-local drops outrank both of them: a SYN-ACK or an echo
    /// reply addressed somewhere `pre()` refuses is still dropped, however much of a reply it is.
    ///
    /// This pins the branch ordering, which is the only thing keeping the carve-outs from
    /// re-opening destinations upstream closes unconditionally.
    #[test]
    fn pre_rule_drops_outrank_the_reply_carve_outs() {
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        let src = ip("100.64.0.9");
        let verdict = |proto, dst, l4| {
            inbound_filter_verdict(
                &AllowAll,
                &mut flowtrack::FlowCache::default(),
                proto,
                std::net::SocketAddr::new(src, 443),
                std::net::SocketAddr::new(dst, 41234),
                l4,
                None,
            )
        };
        let syn_ack = ts_packetfilter::L4Header::Tcp {
            flags: TCP_SYN | TCP_ACK,
        };
        let echo_reply = ts_packetfilter::L4Header::Icmp {
            icmp_type: 0x00,
            icmp_code: 0,
        };

        // The controls: to an ordinary tailnet address both are admitted.
        assert!(verdict(IpProto::TCP, ip("100.64.0.1"), syn_ack));
        assert!(verdict(IpProto::ICMP, ip("100.64.0.1"), echo_reply));

        for dst in ["224.0.0.1", "169.254.1.1"] {
            assert!(
                !verdict(IpProto::TCP, ip(dst), syn_ack),
                "a non-SYN segment to {dst} is still dropped by pre()"
            );
            assert!(
                !verdict(IpProto::ICMP, ip(dst), echo_reply),
                "an echo reply to {dst} is still dropped by pre()"
            );
        }
        // The one link-local address `pre()` allows through is still allowed through.
        assert!(
            verdict(IpProto::ICMP, ip("169.254.169.254"), echo_reply),
            "the cloud-metadata exception is unaffected"
        );
    }

    /// A *first* IPv6 fragment is decoded past its Fragment extension header, TCP flags included —
    /// Go `decode6` reaches `q.TCPFlags = TCPFlag(sub[13])` through exactly the same switch a
    /// unfragmented segment takes — so the reply carve-out applies to it on the same terms.
    ///
    /// Without this a peer that source-fragments could not complete a handshake this node started
    /// under a restrictive ACL; with it wrong, a fragmented SYN would slip past the rules. Both
    /// directions are asserted, on real bytes and on the classification itself.
    #[test]
    fn ipv6_first_fragment_carries_its_tcp_flags_to_the_reply_carve_out() {
        let flows = &mut flowtrack::FlowCache::default();
        let frag = |flags| ipv6_fragment_packet(6, 0, true, &tcp_header(443, 41234, flags));

        assert!(
            admitted(&DenyAll, flows, frag(TCP_SYN | TCP_ACK)),
            "a fragmented SYN-ACK takes the non-SYN carve-out like an unfragmented one"
        );
        assert!(
            !admitted(&DenyAll, flows, frag(TCP_SYN)),
            "a fragmented SYN does not"
        );

        // The classification carries the byte, not merely the verdict — this is the value the
        // verdict reads, and the ports are still Go's `sub[0:2]`/`sub[2:4]` beside it.
        assert_eq!(
            decode6_first_fragment(IpProto::TCP, &tcp_header(443, 41234, TCP_SYN | TCP_ACK)),
            Ipv6Fragment::First {
                proto: IpProto::TCP,
                src_port: 443,
                dst_port: 41234,
                l4: ts_packetfilter::L4Header::Tcp {
                    flags: TCP_SYN | TCP_ACK
                },
            },
            "`decode6` reads the flags byte past the Fragment header"
        );
    }

    /// A dropped inbound packet's four-tuple, as `filter_inbound_from_peer` hands it to
    /// [`tsmp_reject_for_drop`]: the fixture peer dialling this node's SSH port.
    fn dropped_syn_tuple() -> (std::net::SocketAddr, std::net::SocketAddr) {
        (
            std::net::SocketAddr::new(IPV4_FIXTURE_SRC.into(), 41234),
            std::net::SocketAddr::new(IPV4_FIXTURE_DST.into(), 22),
        )
    }

    /// The happy path of the send half, at the function Go's guard lives in: a dropped IPv4 TCP SYN
    /// produces a rejected-connection message addressed back at the dialer, carrying the four-tuple
    /// with the *connection's* own direction and `RejectedDueToACLs`.
    ///
    /// The assertion runs the emitted bytes back through the production parser, which is the far
    /// side's view of them — the peer has to read out the flow it opened, not the one we saw.
    #[test]
    fn an_acl_dropped_syn_produces_a_reject_addressed_back_to_the_dialer() {
        let (src, dst) = dropped_syn_tuple();

        let bytes = tsmp_reject_for_drop(
            IpProto::TCP,
            src,
            dst,
            ts_packetfilter::L4Header::Tcp { flags: TCP_SYN },
            false,
            RejectConfig::default(),
        )
        .expect("a dropped IPv4 TCP SYN must be answered");

        let reject = ts_packet::tsmp::TailscaleRejectedHeader::parse(&bytes)
            .expect("what we emit must parse as a rejected-connection message");

        // Go `IPSrc: p.Dst.Addr(), IPDst: p.Src.Addr()`: the reply travels back the way the SYN
        // came, so the IP pair is reversed...
        assert_eq!(reject.ip_src, dst.ip(), "sourced from the address dialled");
        assert_eq!(reject.ip_dst, src.ip(), "addressed to the dialer");
        // ...while the four-tuple keeps the rejected connection's own direction, which is what lets
        // the dialer match it against the flow it opened.
        assert_eq!(reject.src, src);
        assert_eq!(reject.dst, dst);
        assert_eq!(reject.proto, IPPROTO_TCP_BYTE);
        assert_eq!(reject.reason, ts_packet::tsmp::RejectReason::ACLS);
        assert!(!reject.maybe_broken, "an ACL deny is a terminal verdict");
    }

    /// Go: `if t.filter.ShieldsUp() { rj.Reason = packet.RejectedDueToShieldsUp }`. The two reasons
    /// render differently in a peer's connection history, so a shields-up deny must not be reported
    /// as an ACL deny.
    #[test]
    fn shields_up_is_a_distinct_reject_reason() {
        let (src, dst) = dropped_syn_tuple();
        let syn = ts_packetfilter::L4Header::Tcp { flags: TCP_SYN };

        let reason = |shields_up| {
            ts_packet::tsmp::TailscaleRejectedHeader::parse(
                &tsmp_reject_for_drop(
                    IpProto::TCP,
                    src,
                    dst,
                    syn,
                    shields_up,
                    RejectConfig::default(),
                )
                .expect("emitted"),
            )
            .expect("parses")
            .reason
        };

        assert_eq!(reason(true), ts_packet::tsmp::RejectReason::SHIELDS_UP);
        assert_eq!(reason(false), ts_packet::tsmp::RejectReason::ACLS);
    }

    /// Everything Go stays **silent** about. Each of these is a packet the ACL drops just the same;
    /// the drop is unchanged and only the reply is withheld, which is what makes them the part of
    /// the port worth testing.
    #[test]
    fn most_drops_produce_no_reject_at_all() {
        let (src, dst) = dropped_syn_tuple();
        let syn = ts_packetfilter::L4Header::Tcp { flags: TCP_SYN };
        let v6_src = std::net::SocketAddr::new(std::net::IpAddr::V6(IPV6_FIXTURE_SRC), 41234);
        let v6_dst = std::net::SocketAddr::new(std::net::IpAddr::V6(IPV6_FIXTURE_DST), 22);

        for (name, proto, src, dst, l4, cfg) in [
            // Go `p.TCPFlags&packet.TCPSyn != 0`: a segment with no SYN bit is not a connection
            // being opened, so there is nothing to refuse.
            (
                "a non-SYN segment",
                IpProto::TCP,
                src,
                dst,
                ts_packetfilter::L4Header::Tcp {
                    flags: TCP_ACK | TCP_FIN,
                },
                RejectConfig::default(),
            ),
            (
                "a RST",
                IpProto::TCP,
                src,
                dst,
                ts_packetfilter::L4Header::Tcp { flags: TCP_RST },
                RejectConfig::default(),
            ),
            // Go `p.IPProto == ipproto.TCP`: a datagram protocol has no SYN and no connection.
            (
                "a UDP datagram",
                IpProto::UDP,
                src,
                dst,
                ts_packetfilter::L4Header::Unknown,
                RejectConfig::default(),
            ),
            // A UDP datagram whose 14th payload byte happens to have the SYN bit pattern must not
            // be read as a TCP header: the protocol number decides, as it does in Go's guard.
            (
                "a UDP datagram carrying SYN-shaped bytes",
                IpProto::UDP,
                src,
                dst,
                syn,
                RejectConfig::default(),
            ),
            (
                "an ICMP echo request",
                IpProto::ICMP,
                src,
                dst,
                ts_packetfilter::L4Header::Icmp {
                    icmp_type: 8,
                    icmp_code: 0,
                },
                RejectConfig::default(),
            ),
            // Go `p.IPVersion == 4`: an IPv6 drop is silent, even though the message itself is
            // family-agnostic and `TailscaleRejectedHeader::marshal` would happily emit one.
            (
                "an IPv6 SYN",
                IpProto::TCP,
                v6_src,
                v6_dst,
                syn,
                RejectConfig::default(),
            ),
            // A packet whose L4 header was never decoded — a first IPv4 fragment, say — is not
            // known to be a SYN. Go reaches the same place: a header it could not decode leaves
            // `q.TCPFlags` zero.
            (
                "a SYN whose TCP header was never decoded",
                IpProto::TCP,
                src,
                dst,
                ts_packetfilter::L4Header::Unknown,
                RejectConfig::default(),
            ),
            // Go's peerAPI carve-out, which flips an ACL-refused peerAPI SYN back to `Accept`
            // before the reject block runs. Same outcome reached here by withholding the reply.
            (
                "a SYN to the peerAPI port",
                IpProto::TCP,
                src,
                dst,
                syn,
                RejectConfig {
                    disabled: false,
                    peerapi_port: Some(dst.port()),
                },
            ),
            // Go `!t.disableTSMPRejected`, the node-wide off switch.
            (
                "any SYN at all, with rejects disabled",
                IpProto::TCP,
                src,
                dst,
                syn,
                RejectConfig {
                    disabled: true,
                    peerapi_port: None,
                },
            ),
        ] {
            assert!(
                tsmp_reject_for_drop(proto, src, dst, l4, false, cfg).is_none(),
                "{name} must be dropped silently"
            );
        }

        // Control: with the peerAPI on some *other* port, the same SYN is answered — the carve-out
        // is scoped to the port, not a blanket mute.
        assert!(
            tsmp_reject_for_drop(
                IpProto::TCP,
                src,
                dst,
                syn,
                false,
                RejectConfig {
                    disabled: false,
                    peerapi_port: Some(dst.port() + 1),
                },
            )
            .is_some(),
            "a SYN to a port that is not the peerAPI's is still answered"
        );
    }

    /// The send half through the real filter step, on real bytes: an ACL that denies everything
    /// drops the SYN *and* queues a reject for the peer that sent it, while the packets Go stays
    /// silent about queue nothing. This is the assertion that the guard is wired into the drop
    /// path at all, not merely correct in isolation.
    #[test]
    fn the_filter_step_queues_a_reject_only_for_a_dropped_ipv4_syn() {
        let peer = PeerId(7);

        // Returns `(survived, harvest)`: whether the ACL admitted the packet, and what the filter
        // step produced alongside it.
        let run = |packet: Vec<u8>| {
            let mut packets = vec![PacketMut::from(packet)];
            let mut harvest = InboundHarvest::default();
            filter_inbound_from_peer(
                &DenyAll,
                &mut flowtrack::FlowCache::default(),
                peer,
                &mut packets,
                RejectConfig::default(),
                &mut harvest,
            );
            (!packets.is_empty(), harvest)
        };

        let (survived, harvest) = run(v4_packet(6, 0, false, &tcp_header(41234, 22, TCP_SYN)));
        assert!(!survived, "the deny-all ACL drops the SYN");
        assert_eq!(
            harvest.rejects_to_send.len(),
            1,
            "a dropped SYN is answered"
        );
        assert_eq!(harvest.rejects_to_send[0].0, peer, "back to the sender");
        let reject =
            ts_packet::tsmp::TailscaleRejectedHeader::parse(harvest.rejects_to_send[0].1.as_ref())
                .expect("the queued packet is a rejected-connection message");
        assert_eq!(reject.src.port(), 41234);
        assert_eq!(reject.dst.port(), 22);
        assert_eq!(reject.reason, ts_packet::tsmp::RejectReason::ACLS);

        // A segment that is not a SYN never produces one. Under this deny-all ACL it is in fact
        // *admitted*, by the "tcp non-syn" reply carve-out that runs ahead of the rules — which is
        // the more useful assertion anyway: the reject path must not fire on a packet that was
        // never dropped in the first place.
        let (survived, harvest) = run(v4_packet(6, 0, false, &tcp_header(41234, 22, TCP_RST)));
        assert!(survived, "Go's 'tcp non-syn' carve-out admits it");
        assert!(harvest.rejects_to_send.is_empty(), "and answers nothing");

        for (name, packet) in [
            ("a UDP datagram", v4_packet(17, 0, false, &udp_header(22))),
            (
                "an IPv6 SYN",
                ipv6_packet(6, &tcp_header(41234, 22, TCP_SYN)),
            ),
        ] {
            let (survived, harvest) = run(packet);
            assert!(!survived, "{name} is dropped by the deny-all ACL");
            assert!(
                harvest.rejects_to_send.is_empty(),
                "{name} must be dropped in silence"
            );
        }
    }

    /// The peerAPI ordering, through the real filter step: a SYN to the peerAPI port is dropped by
    /// the ACL exactly as before — this fork has no L7 carve-out that admits it — but the peer is
    /// told nothing, because upstream's carve-out has already turned that packet into an `Accept`
    /// by the time its reject block runs.
    #[test]
    fn a_peerapi_syn_is_dropped_without_a_reject() {
        let mut packets = vec![PacketMut::from(v4_packet(
            6,
            0,
            false,
            &tcp_header(41234, 8089, TCP_SYN),
        ))];
        let mut harvest = InboundHarvest::default();
        filter_inbound_from_peer(
            &DenyAll,
            &mut flowtrack::FlowCache::default(),
            PeerId(7),
            &mut packets,
            RejectConfig {
                disabled: false,
                peerapi_port: Some(8089),
            },
            &mut harvest,
        );

        assert!(packets.is_empty(), "the verdict on the packet is unchanged");
        assert!(
            harvest.rejects_to_send.is_empty(),
            "a peerAPI SYN must never produce a reject"
        );
    }

    /// The receive half through the real filter step: a peer's rejected-connection message is
    /// consumed — harvested for the embedder and **dropped**, never handed to the local stack,
    /// which has no handler for IP protocol 99 (Go `filter.DropSilently`).
    ///
    /// The ACL denies everything, so the packet surviving could only have come from the TSMP
    /// bypass; asserting it does *not* survive is the whole point.
    #[test]
    fn a_received_reject_is_consumed_and_not_delivered() {
        let peer = PeerId(7);

        // The bytes a Go peer puts on the wire when its ACL refuses our dial: it marshals from its
        // own side, we read it from ours.
        let wire = ts_packet::tsmp::TailscaleRejectedHeader {
            ip_src: IPV4_FIXTURE_SRC.into(),
            ip_dst: IPV4_FIXTURE_DST.into(),
            src: std::net::SocketAddr::new(IPV4_FIXTURE_DST.into(), 41234),
            dst: std::net::SocketAddr::new(IPV4_FIXTURE_SRC.into(), 22),
            proto: IPPROTO_TCP_BYTE,
            reason: ts_packet::tsmp::RejectReason::ACLS,
            maybe_broken: false,
        }
        .marshal()
        .expect("marshals");

        let mut packets = vec![PacketMut::from(wire)];
        let mut harvest = InboundHarvest::default();
        filter_inbound_from_peer(
            &DenyAll,
            &mut flowtrack::FlowCache::default(),
            peer,
            &mut packets,
            RejectConfig::default(),
            &mut harvest,
        );

        assert!(
            packets.is_empty(),
            "a reject must be consumed, not delivered to the local stack"
        );
        assert_eq!(harvest.rejected_flows.len(), 1);
        assert_eq!(harvest.rejected_flows[0].0, peer);
        let reject = harvest.rejected_flows[0].1;
        assert_eq!(
            reject.src,
            std::net::SocketAddr::new(IPV4_FIXTURE_DST.into(), 41234),
            "src is OUR address and ephemeral port — the flow we opened"
        );
        assert_eq!(
            reject.dst,
            std::net::SocketAddr::new(IPV4_FIXTURE_SRC.into(), 22)
        );
        assert_eq!(reject.reason, ts_packet::tsmp::RejectReason::ACLS);
        assert!(!reject.maybe_broken);
        assert!(
            harvest.rejects_to_send.is_empty(),
            "consuming a reject must not answer it with another one"
        );

        // The `MaybeBroken` bit reaches the embedder intact: Go treats such a rejection as
        // non-terminal (it marks the flow problematic instead of removing it), so flattening the
        // bit would turn a transient problem into a hard failure.
        let broken = ts_packet::tsmp::TailscaleRejectedHeader {
            ip_src: IPV4_FIXTURE_SRC.into(),
            ip_dst: IPV4_FIXTURE_DST.into(),
            src: std::net::SocketAddr::new(IPV4_FIXTURE_DST.into(), 41234),
            dst: std::net::SocketAddr::new(IPV4_FIXTURE_SRC.into(), 22),
            proto: IPPROTO_TCP_BYTE,
            reason: ts_packet::tsmp::RejectReason::IP_FORWARDING,
            maybe_broken: true,
        }
        .marshal()
        .expect("marshals");
        let mut packets = vec![PacketMut::from(broken)];
        let mut harvest = InboundHarvest::default();
        filter_inbound_from_peer(
            &DenyAll,
            &mut flowtrack::FlowCache::default(),
            peer,
            &mut packets,
            RejectConfig::default(),
            &mut harvest,
        );
        assert!(packets.is_empty());
        assert!(harvest.rejected_flows[0].1.maybe_broken);
        assert_eq!(
            harvest.rejected_flows[0].1.reason,
            ts_packet::tsmp::RejectReason::IP_FORWARDING
        );
    }

    /// A peer cannot drive the default-level log with rejected-connection messages.
    ///
    /// Go logs `open-conn-track` only for a flow sitting in its pending-open table, so its volume
    /// is bounded by the dials *this* node made. This fork keeps no such table and logs every
    /// well-formed reject it can attribute to a peer, which bounds the volume by what the peer
    /// chooses to send instead — nothing here matches a pending flow and nothing rate-limits it.
    /// At `info!` that is an authenticated peer holding the operator's default-level log open;
    /// `debug!` keeps the diagnostic without putting it there.
    ///
    /// The record itself must keep flowing regardless: `rejected_flows` is the path the embedder
    /// uses to do the pending-open match this layer cannot, so quieting the log must not quiet it.
    #[test]
    #[tracing_test::traced_test]
    fn a_flood_of_rejects_stays_off_the_default_log_level() {
        let peer = PeerId(7);
        // More than a real flow-refusal burst, few enough to keep the test cheap: what matters is
        // that the count of default-level lines does not track it.
        const FLOOD: usize = 32;

        let wire = ts_packet::tsmp::TailscaleRejectedHeader {
            ip_src: IPV4_FIXTURE_SRC.into(),
            ip_dst: IPV4_FIXTURE_DST.into(),
            src: std::net::SocketAddr::new(IPV4_FIXTURE_DST.into(), 41234),
            dst: std::net::SocketAddr::new(IPV4_FIXTURE_SRC.into(), 22),
            proto: IPPROTO_TCP_BYTE,
            reason: ts_packet::tsmp::RejectReason::ACLS,
            maybe_broken: false,
        }
        .marshal()
        .expect("marshals");

        let mut packets: Vec<PacketMut> =
            (0..FLOOD).map(|_| PacketMut::from(wire.clone())).collect();
        let mut harvest = InboundHarvest::default();
        filter_inbound_from_peer(
            &DenyAll,
            &mut flowtrack::FlowCache::default(),
            peer,
            &mut packets,
            RejectConfig::default(),
            &mut harvest,
        );

        assert!(packets.is_empty(), "every reject is consumed");
        assert_eq!(
            harvest.rejected_flows.len(),
            FLOOD,
            "the embedder must still receive every record — quieting the log is not dropping it"
        );

        logs_assert(|lines: &[&str]| {
            let tracked: Vec<&&str> = lines
                .iter()
                .filter(|l| l.contains("open-conn-track"))
                .collect();
            if tracked.len() != FLOOD {
                return Err(format!(
                    "expected {FLOOD} open-conn-track lines at debug, got {}",
                    tracked.len()
                ));
            }
            // `INFO` and above is what an operator sees by default; a peer must not reach it.
            let loud: Vec<&&&str> = tracked.iter().filter(|l| !l.contains(" DEBUG ")).collect();
            if let Some(first) = loud.first() {
                return Err(format!(
                    "{} of {FLOOD} peer-driven reject line(s) above debug, e.g. {first}",
                    loud.len()
                ));
            }
            Ok(())
        });
    }

    /// A *fragmented* rejected-connection message is refused before the ACL ever sees it, and is
    /// not consumed either: Go's `decode4` demotes a first TSMP fragment with More-Fragments set to
    /// `ipproto.Unknown`, which `pre()` drops, and classifies a later fragment as
    /// `ipproto.Fragment`. Without the whole message in hand it cannot be a valid control packet,
    /// and half a reject must never be read as a flow being refused.
    #[test]
    fn a_fragmented_reject_is_refused_before_the_acl() {
        let body = {
            let mut b = vec![
                ts_packet::tsmp::TSMP_TYPE_REJECTED_CONN,
                IPPROTO_TCP_BYTE,
                b'A',
            ];
            b.extend_from_slice(&41234u16.to_be_bytes());
            b.extend_from_slice(&22u16.to_be_bytes());
            b.push(0);
            b
        };

        // Control: unfragmented, the same body is consumed as a reject.
        let mut packets = vec![PacketMut::from(v4_packet(99, 0, false, &body))];
        let mut harvest = InboundHarvest::default();
        filter_inbound_from_peer(
            &DenyAll,
            &mut flowtrack::FlowCache::default(),
            PeerId(7),
            &mut packets,
            RejectConfig::default(),
            &mut harvest,
        );
        assert!(packets.is_empty() && harvest.rejected_flows.len() == 1);

        // A first fragment with More-Fragments set, and a later fragment. Neither is parsed as a
        // reject. What happens to the bytes afterwards is the fragment rule this tree already
        // had, unchanged: the first fragment is demoted to `unknown` and dropped, the later
        // fragment takes Go's stateless pass-through (`pre()`'s `case ipproto.Fragment: Accept`).
        for (name, offset, more, delivered) in [
            ("first fragment, MF set", 0, true, false),
            ("later fragment", MIN_FRAG_BLKS, false, true),
        ] {
            let mut packets = vec![PacketMut::from(v4_packet(99, offset, more, &body))];
            let mut harvest = InboundHarvest::default();
            filter_inbound_from_peer(
                &DenyAll,
                &mut flowtrack::FlowCache::default(),
                PeerId(7),
                &mut packets,
                RejectConfig::default(),
                &mut harvest,
            );
            assert!(
                harvest.rejected_flows.is_empty(),
                "{name}: half a reject is not a rejected flow"
            );
            assert_eq!(
                packets.len(),
                usize::from(delivered),
                "{name}: the existing fragment rule decides what happens to the bytes"
            );
        }
    }

    /// Both halves meeting over a real WireGuard session, which is the only test that proves the
    /// reject is actually *sent*: A dials B, B's ACL refuses the SYN, and A learns why.
    ///
    /// This engine is always the dialing client, so A's side is the one that matters day to day —
    /// without it a dial into a peer's ACL drop waits out a TCP timeout with no reason anywhere.
    /// B's side is the peer-observable one: a real Go node dialling into our ACL drop expects to be
    /// told, and was not.
    #[test]
    fn a_refused_dial_is_answered_over_the_wire_and_understood() {
        let underlay: UnderlayTransportId = 0.into();
        let wg_peer = ts_tunnel::PeerId(1);
        let peer = PeerId(1);
        let a_addr = std::net::IpAddr::from(IPV4_FIXTURE_SRC);
        let b_addr = std::net::IpAddr::from(IPV4_FIXTURE_DST);

        let (a_static, b_static) = (NodeKeyPair::new(), NodeKeyPair::new());
        let (mut a, mut b) = (
            DataPlane::new(a_static.clone()),
            DataPlane::new(b_static.clone()),
        );

        for (dp, key, remote) in [
            (&mut a, b_static.public, b_addr),
            (&mut b, a_static.public, a_addr),
        ] {
            dp.wireguard.upsert_peer(
                wg_peer,
                ts_tunnel::PeerConfig {
                    key,
                    psk: [0u8; 32].into(),
                    persistent_keepalive_interval: None,
                },
            );
            dp.ur_out.table.insert(peer, underlay);
            // Each side attributes the other's tailnet address to the WireGuard peer carrying it,
            // as the runtime's source filter does.
            let mut src_filter = ts_bart::Table::default();
            src_filter.insert(ipnet::IpNet::from(remote), peer);
            dp.src_filter_in = Arc::new(src_filter);
        }

        // B refuses everything: this is the ACL drop the message exists to explain.
        b.packet_filter = Arc::new(DenyAll);

        let take = |out: HashMap<(UnderlayTransportId, PeerId), Vec<PacketMut>>| {
            out.into_values().flatten().collect::<Vec<_>>()
        };

        // A dials B. The SYN rides the handshake this send starts.
        let syn = PacketMut::from(v4_packet(6, 0, false, &tcp_header(41234, 22, TCP_SYN)));
        let init = a
            .wireguard
            .send([(wg_peer, vec![syn])])
            .to_peers
            .remove(&wg_peer)
            .expect("handshake initiation");
        let resp = take(b.process_inbound(init).to_peers);
        let from_a = take(a.process_inbound(resp).to_peers);

        // B drops the SYN on its ACL and answers with a rejected-connection message.
        let at_b = b.process_inbound(from_a);
        assert!(
            at_b.to_local.values().all(|v| v.is_empty()),
            "the SYN itself must not reach B's local stack"
        );
        let to_a = take(at_b.to_peers);
        assert!(
            !to_a.is_empty(),
            "B must tell A why it dropped the connection"
        );

        // A consumes it: it learns the flow was refused and the message never reaches its stack.
        let at_a = a.process_inbound(to_a);
        assert!(
            at_a.to_local.values().all(|v| v.is_empty()),
            "the reject must be consumed, not delivered to A's local stack"
        );
        assert_eq!(at_a.rejected_flows.len(), 1, "A must learn of the refusal");
        let (from_peer, reject) = at_a.rejected_flows[0];
        assert_eq!(from_peer, peer);
        assert_eq!(
            reject.src,
            std::net::SocketAddr::new(a_addr, 41234),
            "the flow A opened, from A's own address and ephemeral port"
        );
        assert_eq!(reject.dst, std::net::SocketAddr::new(b_addr, 22));
        assert_eq!(reject.proto, IPPROTO_TCP_BYTE);
        assert_eq!(reject.reason, ts_packet::tsmp::RejectReason::ACLS);
        assert!(!reject.maybe_broken);

        // And A does not answer the reject with a reject of its own — that would be a loop between
        // two nodes that both deny.
        assert!(
            take(at_a.to_peers).is_empty(),
            "consuming a reject must put nothing back on the wire"
        );
    }
}
