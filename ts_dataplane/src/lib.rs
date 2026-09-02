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

/// Fixed IPv6 base header length (Go `net/packet.ip6HeaderLength`).
const IP6_HEADER_LEN: usize = 40;

/// IANA protocol number of the IPv6 Fragment extension header, "IPv6-Frag" (Go
/// `net/packet.ip6FragHeader`). It appears as the **base** header's Next Header on a
/// source-fragmented IPv6 packet, and is distinct from Go's internal `ipproto.Fragment` sentinel
/// (0xff), which marks a non-first fragment whose sub-protocol header is not present.
const IP6_FRAG_HEADER: u8 = 44;

/// Length of the IPv6 Fragment extension header (Go `net/packet.ip6FragHeaderLength`): Next Header,
/// Reserved, a 13-bit Fragment Offset in 8-byte blocks plus two reserved bits and the
/// More-Fragments flag, then a 32-bit Identification.
const IP6_FRAG_HEADER_LEN: usize = 8;

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
        /// The destination port read from that sub-protocol's header, 0 for a protocol Go does not
        /// port-match (Go `withPort(q.Dst, ...)`).
        dst_port: u16,
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
    /// Go `net/packet.sctpHeaderLength`.
    const SCTP_HEADER_LEN: usize = 12;
    /// Go `net/packet.minTSMPSize` — the shortest TSMP body (a 7-byte rejected-connection message).
    const MIN_TSMP_SIZE: usize = 7;
    /// Go's internal `ipproto.Fragment` sentinel. Seeing it as a real Next Header is suspicious, so
    /// Go maps it back to `unknown`.
    const IPPROTO_FRAGMENT_SENTINEL: IpProto = IpProto::new(0xff);

    // Go's port-ful arms: bounds-check, then read the destination port from `sub[2:4]`.
    let ported = |min_len: usize| {
        if sub.len() < min_len {
            return Ipv6Fragment::Unknown;
        }
        Ipv6Fragment::First {
            proto,
            dst_port: u16::from_be_bytes([sub[2], sub[3]]),
        }
    };
    // Go's portless arms: bounds-check only, both ports left at 0.
    let portless = |min_len: usize| {
        if sub.len() < min_len {
            return Ipv6Fragment::Unknown;
        }
        Ipv6Fragment::First { proto, dst_port: 0 }
    };

    match proto {
        IpProto::ICMPV6 => portless(ICMP6_HEADER_LEN),
        IpProto::TCP => ported(TCP_HEADER_LEN),
        IpProto::UDP => ported(UDP_HEADER_LEN),
        IpProto::SCTP => ported(SCTP_HEADER_LEN),
        IpProto::TSMP => portless(MIN_TSMP_SIZE),
        IPPROTO_FRAGMENT_SENTINEL => Ipv6Fragment::Unknown,
        // Go's switch has no default arm: any other protocol keeps its number and port 0, and the
        // ACL matches it IPs-only (`IpProto::is_port_ful`).
        _ => Ipv6Fragment::First { proto, dst_port: 0 },
    }
}

/// Whether `ipv6` carries a Fragment extension header somewhere in its extension-header chain
/// *other than* as the base header's immediate Next Header — the case [`decode6_fragment`] is
/// deliberately not scoped to, and which must therefore fail closed here.
///
/// Callers must only ask this when the base header's Next Header is **not** [`IP6_FRAG_HEADER`];
/// otherwise the leading Fragment header itself answers `true` and would shadow its own
/// classification.
///
/// Why a drop and not a pass. Go's `decode6` sets `q.IPProto` from the base header's Next Header
/// and steps over *only* a leading Fragment header, so a hop-by-hop-chained fragment leaves
/// `q.IPProto == 0 == ipproto.Unknown` and filter `pre()` drops it before the ACL ever runs. This
/// tree instead reads the sub-protocol out of etherparse's extension-header walk, which resolves
/// straight through the chain to the real transport number — so without this check the packet
/// reaches the ACL looking like an ordinary TCP/UDP datagram whose port merely happens to be 0
/// (etherparse refuses to descend into a fragmenting payload), and a permissive "allow the whole
/// tailnet" rule *admits* it. That re-opens the entire RFC 1858 hole this classification exists to
/// close: prepend an 8-byte Hop-by-Hop Options header and a low-offset later fragment — the one
/// whose bytes can land on top of the transport header the head fragment was matched on — slides
/// past, as does a first fragment truncated before its own transport header. The fragment rules
/// must not be defeatable by an extension header the attacker chooses to prepend, so anything
/// carrying a chained Fragment header is [`Ipv6Fragment::Unknown`].
///
/// This drops a strict subset of what Go drops here (Go rejects the whole chained-extension-header
/// class, fragmenting or not), so it cannot admit anything upstream refuses and cannot break a real
/// Tailscale, `wireguard-go` or kernel-WireGuard peer: upstream would discard such a packet too, so
/// no peer can already be relying on one being delivered.
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
/// 3. TSMP (proto 99) is always admitted, bypassing the ACL — Go `case ipproto.TSMP: return Accept`.
///    TSMP carries in-band control messages between nodes, so it must reach the local stack
///    regardless of the ACL rules.
/// 4. Everything else consults the control-derived ACL via `can_access` — Go's `matches4.match`.
fn inbound_filter_verdict(
    filter: &(dyn ts_packetfilter::Filter + Send + Sync),
    proto: IpProto,
    src: std::net::IpAddr,
    dst: std::net::IpAddr,
    dst_port: u16,
    frag: Option<Fragment>,
) -> bool {
    if drop_before_rules(dst) {
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
        Some(Fragment::V6(Ipv6Fragment::First { .. })) | None => {}
    }

    if proto == IpProto::TSMP {
        tracing::trace!(?dst, "accepting TSMP inbound (bypasses ACL, Go parity)");
        return true;
    }

    let info = ts_packetfilter::PacketInfo {
        ip_proto: proto,
        port: dst_port,
        src,
        dst,
    };
    // TODO(npry): wire in nodecaps
    let caps = [];
    let verdict = filter.can_access(&info, caps);
    tracing::trace!(?info, ?caps, verdict);
    verdict
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
///    A real Go peer sends this unprompted. Every *other* TSMP message (ping, pong,
///    rejected-connection) is left in the batch and falls through to step 2, which admits it —
///    exactly as Go's filter does for the TSMP types it does not consume.
/// 2. **The ACL verdict**, [`inbound_filter_verdict`] (Go `runIn4`/`runIn6`).
///
/// `learned_disco_keys` is appended to, never cleared, so one batch can carry advertisements from
/// several peers. A learned key is attributed to `peer_id` — the WireGuard peer whose session
/// decrypted the packet, and whose source addresses the caller's source filter has already bound.
/// Go reaches the same peer the long way round, looking the advertisement's source IP up in the
/// netmap (`wgengine.userspaceEngine.peerForIP`). Either way a peer can only advertise a key for
/// *itself*: it cannot speak for another peer.
fn filter_inbound_from_peer(
    filter: &(dyn ts_packetfilter::Filter + Send + Sync),
    peer_id: PeerId,
    packets: &mut Vec<PacketMut>,
    learned_disco_keys: &mut Vec<(PeerId, ts_packet::tsmp::DiscoKeyAdvertisement)>,
) {
    packets.retain(|packet| {
        let bytes = packet.as_ref();
        let Ok(pkt) = etherparse::SlicedPacket::from_ip(bytes) else {
            tracing::trace!("does not look like ip packet");
            return false;
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
                // IPv6 fragmentation is carried in a Fragment extension header, not the
                // base header. Go `decode6` parses that header — and *only* when it is the
                // base header's immediate Next Header. `next_header()` is exactly that
                // immediate byte, so testing it here reproduces upstream's scoping. Only
                // reachable under the opt-in `Config::enable_ipv6`; the tailnet is IPv4-only
                // by default.
                //
                // A Fragment header reached through a *chained* hop-by-hop / routing /
                // destination-options / AH header is outside that scope, and must fail
                // closed rather than fall through to the ACL: Go drops it (the base Next
                // Header leaves `q.IPProto` at `ipproto.Unknown`, which `pre()` refuses),
                // whereas etherparse resolves the real sub-protocol through the chain, so an
                // allow-all rule would otherwise admit exactly the RFC 1858 fragments this
                // classification exists to reject. See `fragment_header_is_chained`.
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
                    Some(Ipv6Fragment::Later | Ipv6Fragment::Unknown) => IpProto::new(0),
                    None => IpProto::new(ipv6.payload().ip_number.0 as _),
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

        // Go `decode6` reads a *first* IPv6 fragment's transport ports past the Fragment
        // extension header, so a fragmented datagram matches the same rule as an
        // unfragmented one. etherparse deliberately refuses to descend into a fragmenting
        // payload and leaves `transport == None`, so that port comes from the
        // classification above instead.
        let dst_port = match frag {
            Some(Fragment::V6(Ipv6Fragment::First { dst_port, .. })) => dst_port,
            _ => match pkt.transport {
                Some(etherparse::TransportSlice::Udp(udp)) => udp.destination_port(),
                Some(etherparse::TransportSlice::Tcp(tcp)) => tcp.destination_port(),
                _ => 0,
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
                learned_disco_keys.push((peer_id, advert));
            }
            return false;
        }

        // The inbound proto-switch (Go `runIn4`/`runIn6`): Go `pre()` multicast/link-local
        // drops, then the fragment classification (Go `decode4` + `pre()`), then
        // unconditional TSMP accept, then the control-derived ACL. The caller's source
        // attribution and `or_in.route` bound this to attributable peers and local
        // destinations (Go's `local4`/`local6` precondition).
        inbound_filter_verdict(filter, proto, src, dst, dst_port, frag)
    });
}

/// Where this node sends a TSMP disco-key advertisement, and what it puts in one.
///
/// The send half of Go's capability version 144 (`packet.TSMPDiscoKeyAdvertisement`): when a
/// WireGuard session with a peer is established, this node announces its own disco public key to
/// that peer over TSMP, so the peer can learn (or re-learn) the key without waiting for a netmap
/// update from control. It is the mirror image of the receive half in
/// [`filter_inbound_from_peer`], and both are unconditional — a real Go peer sends us one whether
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

    /// Netmap snapshot for the TSMP disco-key advertisement this node sends on session
    /// establishment (Go capability version 144). `None` (the default) advertises nothing at all,
    /// which is what an embedder that never populates it gets — the same position this fork was in
    /// before the send side existed, and still fully interoperable, since a peer's own
    /// advertisement is unsolicited. Refreshed from the netmap by the runtime's dataplane actor.
    pub disco_advertisement: Option<Arc<DiscoAdvertisementState>>,
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
            disco_advertisement: None,
        }
    }

    /// Processes packets originating from the local device.
    #[tracing::instrument(skip_all, fields(n_packets = packets.len()))]
    pub fn process_outbound(&mut self, packets: Vec<PacketMut>) -> OutboundResult {
        if let Some(hook) = &self.capture {
            for p in &packets {
                hook(CapturePath::FromLocal, p.as_ref());
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

    /// Processes packets received from elsewhere.
    pub fn process_inbound(
        &mut self,
        packets: impl IntoIterator<Item = PacketMut>,
    ) -> InboundResult {
        let ts_tunnel::RecvResult {
            to_local,
            to_peers,
            sessions_established,
        } = self.wireguard.recv(packets);

        if let Some(hook) = &self.capture {
            for packets in to_local.values() {
                for p in packets {
                    hook(CapturePath::FromPeer, p.as_ref());
                }
            }
        }

        // TSMP disco-key advertisements learned from this batch (Go `tstun.Wrapper`'s
        // `discoKeyAdvertisementPub` publisher). Filled in by the packet-filter stage below, which
        // is the point at which a packet has both been attributed to a peer and decoded far enough
        // to know it is TSMP.
        let mut learned_disco_keys: Vec<(PeerId, ts_packet::tsmp::DiscoKeyAdvertisement)> =
            Vec::new();

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
                    peer_id,
                    &mut v,
                    &mut learned_disco_keys,
                );

                v
            });

        // TSMP disco-key advertisement, send side (Go capability version 144). wireguard-go calls
        // `peer.SendPriorityMessage()` the moment a keypair becomes current for forward
        // transmission — on the initiator when the handshake response lands, and on the responder
        // when the first transport packet authenticates on the new keypair (`device/receive.go`).
        // `sessions_established` is exactly those two moments; the message is Go's
        // `magicsock.Conn.PriorityMessageForPeer` return value. A peer we must not advertise to
        // (see [`DiscoAdvertisementState::advertisement_for`]) simply gets nothing, and the fresh
        // session is otherwise untouched.
        let mut to_peers = to_peers;
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

        let to_local = self.or_in.route(to_local.flatten());
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
            learned_disco_keys,
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
            inbound_filter_verdict(&DenyAll, tsmp, src, dst, 0, None),
            "TSMP admitted by bypassing the (deny-all) ACL"
        );
        // A non-TSMP proto under the same deny-all ACL is dropped — proves the bypass is TSMP-specific.
        assert!(
            !inbound_filter_verdict(&DenyAll, IpProto::TCP, src, dst, 443, None),
            "TCP still consults the ACL (deny-all → dropped)"
        );
        // `pre()` drops outrank the TSMP accept: TSMP to a multicast/link-local dst is still dropped,
        // exactly as Go runs `pre()` before the proto switch.
        assert!(
            !inbound_filter_verdict(&DenyAll, tsmp, src, ip("224.0.0.1"), 0, None),
            "TSMP to a multicast dst is still dropped (pre() before the switch)"
        );
        assert!(
            !inbound_filter_verdict(&DenyAll, tsmp, src, ip("169.254.1.1"), 0, None),
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
            inbound_filter_verdict(
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
            inbound_filter_verdict(
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
            !inbound_filter_verdict(
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
            !inbound_filter_verdict(&DenyAll, IpProto::TCP, src, dst, 0, frag(1, false)),
            "the smallest non-zero offset is dropped"
        );

        // A first fragment (offset 0) defers to the normal ACL on its real port: deny-all drops a
        // TCP first fragment, exactly as it drops a non-fragmented TCP packet.
        assert!(
            !inbound_filter_verdict(&DenyAll, IpProto::TCP, src, dst, 443, frag(0, true)),
            "a first fragment defers to the ACL (deny-all -> dropped) on its parsed port"
        );

        // A fragmented TSMP first fragment (offset 0, MF set) is dropped — Go disallows it — even
        // though a non-fragmented TSMP bypasses the ACL.
        assert!(
            !inbound_filter_verdict(&DenyAll, IpProto::TSMP, src, dst, 0, frag(0, true)),
            "a fragmented TSMP first fragment is dropped (Go parity)"
        );
        assert!(
            inbound_filter_verdict(&DenyAll, IpProto::TSMP, src, dst, 0, frag(0, false)),
            "a non-fragmented TSMP (offset 0, MF clear) still bypasses the ACL"
        );

        // A *later* TSMP fragment (offset >= MIN_FRAG_BLKS) is accepted via the offset-based
        // fragment pass-through, NOT dropped by the fragmented-TSMP rule — that rule is offset-0
        // only (a first fragment with MF). This proves the later-fragment branch is proto-independent
        // and wins over the TSMP-specific logic (Go maps any offset>=minFragBlks to ipproto.Fragment
        // regardless of the L4 proto byte), locking the branch ordering against regression.
        assert!(
            inbound_filter_verdict(
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

    /// A plain, unfragmented IPv6/UDP packet: the same 40-byte base header the fragment fixtures
    /// use, but with UDP as its immediate Next Header. The control for the chained-extension-header
    /// fixtures below.
    fn ipv6_udp_packet(udp: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; IP6_HEADER_LEN + udp.len()];
        buf[0] = 0x60; // version 6, traffic class/flow label 0
        buf[4..6].copy_from_slice(&u16::try_from(udp.len()).unwrap().to_be_bytes());
        buf[6] = 17; // Next Header = UDP
        buf[7] = 64; // hop limit
        buf[8..24].copy_from_slice(&IPV6_FIXTURE_SRC.octets());
        buf[24..40].copy_from_slice(&IPV6_FIXTURE_DST.octets());
        buf[IP6_HEADER_LEN..].copy_from_slice(udp);
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
                dst_port: 443,
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
                dst_port: 443,
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
                dst_port: 0,
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
            !inbound_filter_verdict(
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
            inbound_filter_verdict(&AllowAll, IpProto::UDP, src, dst, 443, None),
            "the allow-all ACL does admit an ordinary packet"
        );

        // A safe later fragment slides through ahead of the ACL, with nothing but port 0 to match.
        assert!(
            inbound_filter_verdict(
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
                dst_port,
            })
        };
        assert!(
            inbound_filter_verdict(&AllowPort(443), IpProto::UDP, src, dst, 443, first(443)),
            "a first IPv6 fragment is matched on the port behind the Fragment header"
        );
        assert!(
            !inbound_filter_verdict(&AllowPort(443), IpProto::UDP, src, dst, 444, first(444)),
            "a first IPv6 fragment on a disallowed port is dropped by the ACL"
        );
        // Control: the same ACL decides an unfragmented packet the same way, so the two results
        // above are the ACL being consulted on a real port and not a fragment-specific shortcut.
        assert!(
            inbound_filter_verdict(&AllowPort(443), IpProto::UDP, src, dst, 443, None),
            "control: the port-scoped ACL admits an unfragmented packet to 443"
        );
        assert!(
            !inbound_filter_verdict(&AllowPort(443), IpProto::UDP, src, dst, 0, None),
            "control: port 0 - what a v6 fragment used to read as - is not admitted"
        );

        // `pre()`'s multicast/link-local drops still outrank the fragment pass-through, exactly as
        // Go runs them before `case ipproto.Fragment`.
        assert!(
            !inbound_filter_verdict(
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
            !inbound_filter_verdict(
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
            let mut learned = Vec::new();
            filter_inbound_from_peer(filter, PeerId(3), &mut packets, &mut learned);
            assert!(
                learned.is_empty(),
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

    /// Prepending an extension header must not defeat the fragment rules.
    ///
    /// [`decode6_fragment`] is scoped exactly as Go scopes it: the Fragment header is parsed only
    /// as the base header's immediate Next Header. Go can afford that narrow scope because
    /// everything it does not parse *keeps the base header's Next Header* as `q.IPProto`, so a
    /// hop-by-hop-chained fragment is `ipproto.Unknown` and filter `pre()` drops it before the ACL
    /// ever runs. This tree reads the sub-protocol out of etherparse's extension-header walk
    /// instead, which resolves straight through the chain to the real transport number — so the
    /// same packet reached the ACL looking like an ordinary UDP datagram that merely happened to
    /// carry port 0, and a permissive "allow the whole tailnet" rule ADMITTED it. Eight bytes of
    /// Hop-by-Hop Options were enough to walk every RFC 1858 fragment straight past the rules the
    /// rest of this file exists to enforce.
    ///
    /// Every assertion is against an ALLOW-ALL ACL, so a drop can only be the fragment rule and
    /// never the ACL — and each extension type carries its own control that proves it: the same
    /// chain shape with no Fragment header in it is still delivered, on the port read past the
    /// extension header. That control is per-type rather than once at the end because `keep`
    /// cannot tell a fragment-rule drop from a parser rejection, so a fixture malformed for only
    /// one of the three protocols would otherwise turn that protocol's four drops into vacuous
    /// passes with the suite still green.
    #[test]
    fn chained_extension_header_cannot_bypass_the_ipv6_fragment_rules() {
        let keep = |filter: &(dyn ts_packetfilter::Filter + Send + Sync), packet: Vec<u8>| {
            let mut packets = vec![PacketMut::from(packet)];
            let mut learned = Vec::new();
            filter_inbound_from_peer(filter, PeerId(4), &mut packets, &mut learned);
            assert!(
                learned.is_empty(),
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
            // produced eight bytes etherparse refuses to walk. The same chain shape with no
            // Fragment header behind it is still parsed, still admitted, and still matched on the
            // port read past the extension header, which pins the drops to the fragment rule.
            let plain = ipv6_with_prepended_ext_header(ext, &ipv6_udp_packet(&udp_header(443)));
            assert!(
                keep(&AllowAll, plain.clone()),
                "an unfragmented packet behind extension header {ext} is still delivered"
            );
            assert!(
                keep(&AllowPort(443), plain),
                "...and is still matched on the port read past extension header {ext}"
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
        let mut learned = Vec::new();
        filter_inbound_from_peer(&DenyAll, peer, &mut packets, &mut learned);

        assert!(
            packets.is_empty(),
            "a consumed advertisement must not be delivered to the local stack"
        );
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
        let mut learned = Vec::new();
        filter_inbound_from_peer(&DenyAll, peer, &mut packets, &mut learned);
        assert_eq!(packets.len(), 1, "a TSMP ping still bypasses the ACL");
        assert!(learned.is_empty(), "a ping advertises no disco key");
    }

    /// The negative case, at the dataplane boundary: a TSMP body that is *nearly* an
    /// advertisement must not be half-parsed into a learned key. None of these may put anything
    /// in `learned` — a truncated key that was zero-padded, or a zero key that was accepted,
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
            let mut learned = Vec::new();
            filter_inbound_from_peer(&DenyAll, peer, &mut packets, &mut learned);

            assert!(
                learned.is_empty(),
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
}
