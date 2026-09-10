#![doc = include_str!("../README.md")]
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(any(feature = "std", test))]
extern crate std;

use alloc::{collections::BTreeMap, string::String};
use core::net::IpAddr;

#[cfg(feature = "checking-filter")]
mod checking_filter;
pub mod filter;
mod ip_proto;
mod l4;
mod rule;
mod state;

#[cfg(feature = "checking-filter")]
pub use checking_filter::CheckingFilter;
#[doc(inline)]
pub use filter::{Filter, FilterAndStorage, FilterExt, FilterStorage, FilterStorageExt};
#[doc(inline)]
pub use ip_proto::IpProto;
#[doc(inline)]
pub use l4::L4Header;
#[doc(inline)]
pub use rule::{DstMatch, Rule, Ruleset, SrcMatch};
#[doc(inline)]
pub use state::apply_update;

use crate::filter::CapIter;

/// The name of the default ruleset, i.e. the key the filter in
/// `MapResponse::packet_filter` should use.
pub const DEFAULT_RULESET_NAME: &str = "base";

/// The special ruleset name that clears the packet filter state if it's present
/// with a `null` value.
pub const CLEAR_MAP_KEY: &str = "*";

/// Metadata about an IP packet.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct PacketInfo {
    /// The address of the sender of the packet.
    pub src: IpAddr,
    /// The address of the receiver of the packet.
    pub dst: IpAddr,
    /// The IP protocol number.
    pub ip_proto: IpProto,
    /// The port number.
    pub port: u16,
    /// The L4 header bytes beyond the four-tuple — Go `packet.Parsed`'s `TCPFlags` and the ICMP
    /// type/code. No [`Rule`] reads these; they exist for the reply carve-outs Go's
    /// `wgengine/filter` `runIn4`/`runIn6` apply *ahead* of any rule, which the caller runs through
    /// [`Self::is_tcp_non_syn`], [`Self::is_icmp_echo_response`] and [`Self::is_icmp_error`].
    ///
    /// [`L4Header::Unknown`] — the [`Default`] — means "not decoded", and every one of those three
    /// predicates answers `false` for it, so a caller that cannot decode an L4 header gets the
    /// ordinary rule match and never a carve-out.
    pub l4: L4Header,
}

impl PacketInfo {
    /// Whether this is the inbound TCP segment Go's `runIn4`/`runIn6` accept before consulting any
    /// rule: a TCP segment that is **not** a SYN.
    ///
    /// ```text
    /// case ipproto.TCP:
    ///     // For TCP, we want to allow *outgoing* connections, which means we want to
    ///     // allow return packets on those connections. To make this restriction work,
    ///     // we need to allow non-SYN packets (continuation of an existing session) to
    ///     // arrive. This should be okay since a new incoming session can't be initiated
    ///     // without first sending a SYN.
    ///     if !q.IsTCPSyn() {
    ///         return Accept, "tcp non-syn"
    ///     }
    /// ```
    ///
    /// Go's `Parsed.IsTCPSyn` is `(q.TCPFlags & TCPSynAck) == TCPSyn` — SYN set *and* ACK clear —
    /// so the SYN-ACK answering this node's own outbound connection is a "non-SYN" and is admitted,
    /// which is the whole point of the carve-out.
    ///
    /// This is deliberately **not** the negation of a `is_tcp_syn`. Go reaches the TCP arm only
    /// after `decode4`/`decode6` has parsed the flags byte (a TCP header too short to hold it is
    /// demoted to `ipproto.Unknown` and dropped), so its zero-valued `TCPFlags` never reaches
    /// `IsTCPSyn`. Here a caller may legitimately not have decoded the header, and answering "not a
    /// SYN" for a packet whose flags were never read would turn the carve-out into an open door.
    /// So the carve-out demands a decoded [`L4Header::Tcp`], and the protocol number to agree with
    /// it — an IPv6 packet whose base header names an extension header carries protocol 43 or 60 to
    /// the filter even when a TCP header sits further down its chain, and must not be admitted as
    /// TCP.
    pub fn is_tcp_non_syn(&self) -> bool {
        match self.l4 {
            L4Header::Tcp { flags } => {
                self.ip_proto == IpProto::TCP && (flags & l4::TCP_SYN_ACK) != l4::TCP_SYN
            }
            _ => false,
        }
    }

    /// Go `packet.Parsed.IsEchoResponse`: an ICMPv4 Echo Reply or an ICMPv6 Echo Reply, in either
    /// case with a zero code. Together with [`Self::is_icmp_error`] this is the `q.IsEchoResponse()
    /// || q.IsError()` that opens Go's `case ipproto.ICMPv4` / `case ipproto.ICMPv6` arm with
    /// `return Accept, "icmp response ok"`.
    ///
    /// The reply to a ping this node sent arrives with no ACL rule naming it, so without this the
    /// ping simply times out under any policy that does not grant the peer inbound access back.
    pub fn is_icmp_echo_response(&self) -> bool {
        let L4Header::Icmp {
            icmp_type,
            icmp_code,
        } = self.l4
        else {
            return false;
        };
        icmp_code == l4::ICMP_NO_CODE
            && match self.ip_proto {
                IpProto::ICMP => icmp_type == l4::ICMP4_ECHO_REPLY,
                IpProto::ICMPV6 => icmp_type == l4::ICMP6_ECHO_REPLY,
                _ => false,
            }
    }

    /// Go `packet.Parsed.IsError`: an ICMP *error* message — the Destination Unreachable / Time
    /// Exceeded / Parameter Problem class, plus Packet Too Big on ICMPv6. Unlike an echo response
    /// the code is not tested, exactly as upstream does not test it: an error's code is what says
    /// *which* error it is.
    ///
    /// Path MTU discovery depends on this one: the Packet Too Big that shrinks a connection's MTU
    /// is unsolicited as far as any ACL is concerned.
    pub fn is_icmp_error(&self) -> bool {
        let L4Header::Icmp { icmp_type, .. } = self.l4 else {
            return false;
        };
        match self.ip_proto {
            IpProto::ICMP => matches!(
                icmp_type,
                l4::ICMP4_UNREACHABLE | l4::ICMP4_TIME_EXCEEDED | l4::ICMP4_PARAM_PROBLEM
            ),
            IpProto::ICMPV6 => matches!(
                icmp_type,
                l4::ICMP6_UNREACHABLE
                    | l4::ICMP6_PACKET_TOO_BIG
                    | l4::ICMP6_TIME_EXCEEDED
                    | l4::ICMP6_PARAM_PROBLEM
            ),
            _ => false,
        }
    }
}

/// Trivial filter that drops all traffic.
///
/// Can be used as an initial filter before the actual filter has been downloaded from
/// control.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct DropAllFilter;

impl Filter for DropAllFilter {
    fn match_for(&self, info: &PacketInfo, caps: CapIter) -> Option<&str> {
        tracing::trace!(?info, caps = ?caps.into_iter().collect::<alloc::vec::Vec<_>>(), "drop all: drop!");

        None
    }
}

/// A [`Filter`] wrapper that enforces **shields-up** (Go `ipn` `ShieldsUp` / `block_incoming`): drop
/// every inbound packet destined to **one of this node's own addresses**, while delegating all other
/// packets to the wrapped `inner` filter.
///
/// Scoping the deny to `self_addrs` (rather than dropping everything) is deliberate, because this
/// filter itself is **stateless** — it holds no flow table, so on its own it could not tell a new
/// inbound TCP connection from a reply to one we initiated. Dropping only packets aimed at our own
/// host addresses means:
/// - new inbound connections *terminating on this node* are refused (the shields-up intent), but
/// - **forwarded transit** (subnet-route / exit-node traffic, whose `dst` is some other route, never
///   a self address) is unaffected, and
/// - reply admission for our own outbound flows is decided before this filter is ever consulted:
///   `ts_dataplane` admits a TCP segment that is not a SYN, an ICMP echo response or ICMP error, and
///   a UDP/SCTP datagram matching a tracked outbound flow, all ahead of the rule match — which is
///   exactly where Go's `runIn4`/`runIn6` apply the same three accepts. Shields-up blocks inbound
///   *connections*, not the answers to ours — same as upstream, whose shields-up filter is likewise
///   a ruleset behind those carve-outs rather than in front of them.
///
/// This is the honest stateless-filter approximation of Go's stateful ShieldsUp: it blocks inbound
/// *to self* and leaves everything else to the real filter. Mirrors `DropAllFilter`'s "deny by
/// returning `None`" pattern, scoped by destination.
#[derive(Debug, Clone)]
pub struct ShieldsUpFilter<F> {
    /// The underlying (control-derived) filter consulted for any packet not denied by shields-up.
    pub inner: F,
    /// This node's own addresses; an inbound packet whose `dst` is in this set is dropped.
    pub self_addrs: alloc::vec::Vec<IpAddr>,
}

impl<F: Filter> Filter for ShieldsUpFilter<F> {
    fn match_for(&self, info: &PacketInfo, caps: CapIter) -> Option<&str> {
        if self.self_addrs.contains(&info.dst) {
            tracing::trace!(
                ?info,
                "shields-up: dropping inbound packet to a self address"
            );
            return None;
        }
        self.inner.match_for(info, caps)
    }
}

/// Alias representing a BTreeMap-based filter.
pub type BTreeFilter = BTreeMap<String, Ruleset>;

/// Alias representing a [`hashbrown::HashMap`]-based filter.
pub type HashbrownFilter = hashbrown::HashMap<String, Ruleset>;

/// Alias representing a [`HashMap`][std::collections::HashMap]-based filter.
#[cfg(feature = "std")]
pub type HashMapFilter = std::collections::HashMap<String, Ruleset>;

static_assertions::assert_impl_all!(BTreeFilter: Filter, FilterStorage);
static_assertions::assert_impl_all!(HashbrownFilter: Filter, FilterStorage);
#[cfg(feature = "std")]
static_assertions::assert_impl_all!(HashMapFilter: Filter, FilterStorage);

#[cfg(test)]
mod reply_tests {
    use super::*;

    fn info(ip_proto: IpProto, l4: L4Header) -> PacketInfo {
        PacketInfo {
            src: "100.64.0.9".parse().unwrap(),
            dst: "100.64.0.1".parse().unwrap(),
            ip_proto,
            port: 41234,
            l4,
        }
    }

    /// Go `Parsed.IsTCPSyn` is `(q.TCPFlags & TCPSynAck) == TCPSyn`, so "not a SYN" covers the
    /// SYN-ACK that answers an outbound connection, every mid-session segment, and — because that
    /// is what the mask says — a segment with neither bit set.
    #[test]
    fn is_tcp_non_syn_follows_gos_syn_ack_mask() {
        for flags in [0x12u8, 0x10, 0x11, 0x04, 0x18, 0x00] {
            assert!(
                info(IpProto::TCP, L4Header::Tcp { flags }).is_tcp_non_syn(),
                "flags {flags:#04x} is not a SYN"
            );
        }
        // SYN set, ACK clear — the one segment that opens an inbound session.
        for flags in [0x02u8, 0x03, 0x42, 0xc2] {
            assert!(
                !info(IpProto::TCP, L4Header::Tcp { flags }).is_tcp_non_syn(),
                "flags {flags:#04x} IS a SYN"
            );
        }
        // Fail-closed, both ways round: no decoded header is not "no flags set", and a decoded TCP
        // header does not make a packet TCP if the IP header said protocol 43.
        assert!(!info(IpProto::TCP, L4Header::Unknown).is_tcp_non_syn());
        assert!(!info(IpProto::new(43), L4Header::Tcp { flags: 0x10 }).is_tcp_non_syn());
        assert!(
            !info(
                IpProto::TCP,
                L4Header::Icmp {
                    icmp_type: 0,
                    icmp_code: 0
                }
            )
            .is_tcp_non_syn()
        );
    }

    /// Go `Parsed.IsEchoResponse` and `Parsed.IsError`, whose type numbers differ entirely between
    /// the two families and are read against whichever `q.IPProto` says.
    #[test]
    fn icmp_response_predicates_follow_gos_type_and_code_tests() {
        let icmp = |ip_proto, icmp_type, icmp_code| {
            info(
                ip_proto,
                L4Header::Icmp {
                    icmp_type,
                    icmp_code,
                },
            )
        };

        assert!(icmp(IpProto::ICMP, 0x00, 0).is_icmp_echo_response());
        assert!(icmp(IpProto::ICMPV6, 129, 0).is_icmp_echo_response());
        // The code is part of the test for an echo response, and only for an echo response.
        assert!(!icmp(IpProto::ICMP, 0x00, 1).is_icmp_echo_response());
        assert!(icmp(IpProto::ICMP, 0x03, 1).is_icmp_error());
        // Each family's numbers are read only against its own protocol: ICMPv4 type 3 is
        // Unreachable, ICMPv6 type 3 is Time Exceeded, and ICMPv6 129 is nothing at all on v4.
        assert!(icmp(IpProto::ICMPV6, 3, 0).is_icmp_error());
        assert!(!icmp(IpProto::ICMP, 129, 0).is_icmp_echo_response());
        assert!(!icmp(IpProto::ICMPV6, 0x00, 0).is_icmp_echo_response());
        assert!(!icmp(IpProto::ICMPV6, 0x0b, 0).is_icmp_error());
        // An echo request is neither, on either family — it is how an inbound session starts.
        assert!(!icmp(IpProto::ICMP, 0x08, 0).is_icmp_echo_response());
        assert!(!icmp(IpProto::ICMP, 0x08, 0).is_icmp_error());
        assert!(!icmp(IpProto::ICMPV6, 128, 0).is_icmp_echo_response());
        assert!(!icmp(IpProto::ICMPV6, 128, 0).is_icmp_error());
        // Fail-closed: an undecoded header is no response, and a TCP packet is never one however
        // its flags byte happens to read.
        assert!(!info(IpProto::ICMP, L4Header::Unknown).is_icmp_echo_response());
        assert!(!info(IpProto::ICMP, L4Header::Unknown).is_icmp_error());
        assert!(!icmp(IpProto::TCP, 0x00, 0).is_icmp_echo_response());
        assert!(!info(IpProto::ICMP, L4Header::Tcp { flags: 0 }).is_icmp_error());
    }
}

#[cfg(test)]
mod shields_tests {
    use super::*;

    /// A trivial inner filter that accepts everything — so the wrapper's deny is the only thing that
    /// can drop a packet (isolates `ShieldsUpFilter`'s behavior from any ruleset).
    struct AllowAll;
    impl Filter for AllowAll {
        fn match_for(&self, _info: &PacketInfo, _caps: CapIter) -> Option<&str> {
            Some("allow-all")
        }
    }

    fn pkt(dst: &str) -> PacketInfo {
        PacketInfo {
            src: "100.64.0.9".parse().unwrap(),
            dst: dst.parse().unwrap(),
            ip_proto: IpProto::TCP,
            port: 22,
            l4: L4Header::Unknown,
        }
    }

    #[test]
    fn shields_up_drops_inbound_to_self_address() {
        let f = ShieldsUpFilter {
            inner: AllowAll,
            self_addrs: alloc::vec!["100.64.0.1".parse().unwrap()],
        };
        // Destined to our own address → dropped, even though the inner filter would allow it.
        assert!(
            f.match_for(&pkt("100.64.0.1"), &mut core::iter::empty())
                .is_none()
        );
    }

    #[test]
    fn shields_up_passes_non_self_dst_to_inner() {
        let f = ShieldsUpFilter {
            inner: AllowAll,
            self_addrs: alloc::vec!["100.64.0.1".parse().unwrap()],
        };
        // A forwarded/subnet dst (not one of our addresses) → delegated to the inner filter, which
        // accepts. This is why shields-up doesn't break subnet/exit transit.
        assert_eq!(
            f.match_for(&pkt("10.0.0.5"), &mut core::iter::empty()),
            Some("allow-all")
        );
    }

    #[test]
    fn shields_up_empty_self_addrs_is_transparent() {
        // Before the first netmap (no self addresses known yet), the wrapper denies nothing — it is
        // a pass-through to the inner filter, never a blanket drop.
        let f = ShieldsUpFilter {
            inner: AllowAll,
            self_addrs: alloc::vec![],
        };
        assert_eq!(
            f.match_for(&pkt("100.64.0.1"), &mut core::iter::empty()),
            Some("allow-all")
        );
    }
}
