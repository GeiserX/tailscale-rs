use alloc::{string::String, vec::Vec};
use core::ops::RangeInclusive;

use crate::{IpProto, PacketInfo};

/// Alias for a collection of filter [`Rule`]s, typically stored under a single key
/// in a [`Filter`](crate::Filter).
pub type Ruleset = Vec<Rule>;

/// A network packet filter rule. Permits tailnet peers to access specific IPs
/// and ports.
///
/// Conjunctive: `src` _and_ `protos` _and_ `dst` must match for this rule to accept a
/// packet.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Rule {
    /// Sender info this rule applies to.
    pub src: SrcMatch,
    /// The IP protocol numbers this rule applies to.
    pub protos: Vec<IpProto>,
    /// Destination info this rule applies to.
    pub dst: Vec<DstMatch>,
}

impl Rule {
    /// Report whether this rule matches the given [`PacketInfo`] and `caps`.
    ///
    /// This implementation is not optimized for speed.
    pub fn matches<'cap>(
        &self,
        info: &PacketInfo,
        caps: impl IntoIterator<Item = &'cap str>,
    ) -> bool {
        // Whether the destination port participates in the match, mirroring Go's `runIn4`/`runIn6`:
        // TCP/UDP/SCTP match against the rule's port range; ICMP/ICMPv6 match IPs-only (ports are
        // ignored — a portless packet surfaces as port 0, which must not be tested against a
        // `1..=65535`-style range); any other ("portless") protocol matches IPs-only too but only
        // when the rule opens *all* ports (Go's `matchProtoAndIPsOnlyIfAllPorts`).
        let port_mode = PortMode::for_proto(info.ip_proto);
        self.protos.contains(&info.ip_proto)
            && self.src.matches(info, caps)
            && self.dst.iter().any(|dst| dst.matches(info, port_mode))
    }
}

/// How a [`DstMatch`]'s port range participates in a match for a given protocol — the fork's
/// equivalent of Go's per-protocol dispatch in `wgengine/filter`'s `runIn4`/`runIn6`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum PortMode {
    /// The packet carries an L4 port (TCP/UDP/SCTP): the rule's port range is checked normally.
    Check,
    /// ICMP/ICMPv6: match IPs only, ignoring the rule's port range entirely.
    IpsOnly,
    /// Any other protocol: match IPs only, but *only* if the rule opens all ports (`0..=65535`).
    IpsOnlyIfAllPorts,
}

impl PortMode {
    fn for_proto(proto: IpProto) -> Self {
        if proto.is_port_ful() {
            PortMode::Check
        } else if proto == IpProto::ICMP || proto == IpProto::ICMPV6 {
            PortMode::IpsOnly
        } else {
            PortMode::IpsOnlyIfAllPorts
        }
    }
}

/// The inclusive port range that means "all ports" (Go `filtertype.AllPorts` = `{0, 0xffff}`).
const ALL_PORTS: RangeInclusive<u16> = 0..=u16::MAX;

/// Matcher for the source of a given packet.
///
/// Disjunctive: either `pfxs` or `caps` may match for this matcher to accept a packet.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct SrcMatch {
    /// The IP prefixes to match for this rule.
    pub pfxs: Vec<ipnet::IpNet>,

    /// The node capabilities to match for this rule.
    ///
    /// These are arbitrary strings provided out-of-band.
    pub caps: Vec<String>,
}

impl SrcMatch {
    /// Report whether this matcher matches the given [`PacketInfo`].
    ///
    /// This implementation is not optimized for speed.
    pub fn matches<'cap>(
        &self,
        info: &PacketInfo,
        caps: impl IntoIterator<Item = &'cap str>,
    ) -> bool {
        self.pfxs.iter().any(|pfx| pfx.contains(&info.src))
            || caps
                .into_iter()
                .any(|cap| self.caps.iter().any(|c| c == cap))
    }
}

/// Matcher for the destination of a given packet.
///
/// Conjunctive: _all_ of `protos`, `ports`, and `ips` must match for this matcher to
/// accept a packet.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DstMatch {
    /// The range of ports this match applies to.
    pub ports: RangeInclusive<u16>,

    /// The destination IP prefixes this match applies to.
    pub ips: Vec<ipnet::IpNet>,
}

impl DstMatch {
    /// Report whether this matcher matches the given [`PacketInfo`], with the port test applied
    /// according to `port_mode` (see [`PortMode`] — the per-protocol port semantics from Go's
    /// `runIn4`/`runIn6`).
    fn matches(&self, info: &PacketInfo, port_mode: PortMode) -> bool {
        let port_ok = match port_mode {
            PortMode::Check => self.ports.contains(&info.port),
            PortMode::IpsOnly => true,
            // Go `matchProtoAndIPsOnlyIfAllPorts`: an "other" protocol matches only when the rule
            // grants all ports; a narrower port range never opens a portless non-ICMP protocol.
            PortMode::IpsOnlyIfAllPorts => self.ports == ALL_PORTS,
        };
        port_ok && self.ips.iter().any(|pfx| pfx.contains(&info.dst))
    }
}

/// Report whether `rules` grant network access to an *unlocked* node — a peer control marked
/// `UnsignedPeerAPIOnly`, which by definition carries no tailnet-lock signature and is therefore
/// outside the lock's coverage.
///
/// `unlocked_allowed_ips` is the union of those peers' allowed-IP prefixes (Go
/// `tailcfg.Node.AllowedIPs` — **not only their addresses**; a peer's advertised routes count too).
/// A rule grants such a peer access when one of its source prefixes overlaps that union *and* the
/// rule names at least one destination.
///
/// If this reports `true` the packet filter is invalid — control is either broken or malicious —
/// and the caller must ignore it wholesale rather than install it. Mirrors Go's
/// `packetFilterPermitsUnlockedNodes` in `ipn/ipnlocal/local.go`, reached from
/// `nodeBackend.unlockedNodesPermitted`, at
/// `023255e8a27ec9f6a21d24e3eda21c052ff72af3`.
///
/// The comparison is deliberately *overlap*, not containment in either direction: a rule whose
/// source is `0.0.0.0/0` grants an unlocked peer access just as surely as one naming its /32, and
/// so does one naming a /24 inside a route the peer advertises.
///
/// Only [`SrcMatch::pfxs`] participates, never [`SrcMatch::caps`] — the same choice upstream makes
/// by looking at `Match.Srcs` alone. A node-capability source is not a statement about an address,
/// so it cannot be resolved to one here.
pub fn permits_unlocked_nodes<'r>(
    rules: impl IntoIterator<Item = &'r Rule>,
    unlocked_allowed_ips: &[ipnet::IpNet],
) -> bool {
    // Go returns early when no peer is unlocked. Nothing below would report `true` for an empty
    // set anyway; this keeps the common case (no unlocked peers at all) free of the rule walk.
    if unlocked_allowed_ips.is_empty() {
        return false;
    }

    rules.into_iter().any(|rule| {
        !rule.dst.is_empty()
            && rule.src.pfxs.iter().any(|src| {
                unlocked_allowed_ips
                    .iter()
                    .any(|allowed| prefixes_overlap(src, allowed))
            })
    })
}

/// Whether two CIDR prefixes share any address (Go `netipx.IPSet.OverlapsPrefix`, specialized to a
/// single prefix). Two prefixes either nest or are disjoint, so "one contains the other" is exactly
/// overlap. Cross-family pairs never overlap, which `ipnet` already answers `false` for.
fn prefixes_overlap(a: &ipnet::IpNet, b: &ipnet::IpNet) -> bool {
    a.contains(b) || b.contains(a)
}

#[cfg(test)]
mod unlocked_node_tests {
    use alloc::{vec, vec::Vec};

    use super::*;

    fn pfxs(list: &[&str]) -> Vec<ipnet::IpNet> {
        list.iter().map(|p| p.parse().unwrap()).collect()
    }

    /// A rule granting `srcs` access to `dsts` on all ports.
    fn rule(srcs: &[&str], dsts: &[&str]) -> Rule {
        Rule {
            src: SrcMatch {
                pfxs: pfxs(srcs),
                caps: Vec::new(),
            },
            protos: vec![crate::IpProto::TCP],
            dst: vec![DstMatch {
                ports: ALL_PORTS,
                ips: pfxs(dsts),
            }],
        }
    }

    /// The case the check exists for: control marks a peer unsigned (so tailnet lock never covers
    /// it) and then writes that peer's own address into the ACL as a source. The route clamp does
    /// not help here — the peer is reaching us at its *assigned* address.
    #[test]
    fn an_acl_naming_an_unlocked_peers_address_invalidates_the_filter() {
        let rules = vec![rule(&["100.64.0.9/32"], &["100.64.0.1/32"])];
        assert!(permits_unlocked_nodes(&rules, &pfxs(&["100.64.0.9/32"])));
    }

    /// The same ACL with no unlocked peer in the netmap is an ordinary, valid filter.
    #[test]
    fn an_acl_with_no_unlocked_peer_is_left_alone() {
        let rules = vec![rule(&["100.64.0.9/32"], &["100.64.0.1/32"])];
        assert!(!permits_unlocked_nodes(&rules, &[]));
    }

    /// Go's "not only addresses!": the union is built from `AllowedIPs`, so a rule whose source
    /// falls inside a *route* the unlocked peer carries counts, even though no address matches.
    #[test]
    fn a_rule_inside_an_unlocked_peers_route_counts_too() {
        let rules = vec![rule(&["192.0.2.128/25"], &["100.64.0.1/32"])];
        assert!(permits_unlocked_nodes(&rules, &pfxs(&["192.0.2.0/24"])));
    }

    /// Overlap, not containment: a rule that opens the whole internet as a source subsumes the
    /// unlocked peer even though the peer's prefix is the narrower of the two.
    #[test]
    fn a_default_route_source_overlaps_an_unlocked_peer() {
        let rules = vec![rule(&["0.0.0.0/0"], &["100.64.0.1/32"])];
        assert!(permits_unlocked_nodes(&rules, &pfxs(&["100.64.0.9/32"])));
    }

    /// A rule that names the peer but no destination grants nothing, so it does not invalidate the
    /// filter. Upstream tests `len(m.Dsts) != 0` for exactly this reason.
    #[test]
    fn a_source_only_rule_grants_nothing() {
        let mut r = rule(&["100.64.0.9/32"], &["100.64.0.1/32"]);
        r.dst.clear();
        assert!(!permits_unlocked_nodes(&[r], &pfxs(&["100.64.0.9/32"])));
    }

    /// A rule naming some other peer is not the unlocked one, and disjoint families never overlap.
    #[test]
    fn unrelated_sources_do_not_invalidate_the_filter() {
        let rules = vec![
            rule(&["100.64.0.10/32"], &["100.64.0.1/32"]),
            rule(&["fd7a:115c:a1e0::/48"], &["100.64.0.1/32"]),
        ];
        assert!(!permits_unlocked_nodes(&rules, &pfxs(&["100.64.0.9/32"])));
    }

    /// A capability-sourced rule is not an address statement, so it is not read as one — the same
    /// line upstream draws by looking only at `Match.Srcs`.
    #[test]
    fn a_capability_source_is_not_read_as_an_address() {
        let rules = vec![Rule {
            src: SrcMatch {
                pfxs: Vec::new(),
                caps: vec!["tailscale.com/cap/test".into()],
            },
            protos: vec![crate::IpProto::TCP],
            dst: vec![DstMatch {
                ports: ALL_PORTS,
                ips: pfxs(&["100.64.0.1/32"]),
            }],
        }];
        assert!(!permits_unlocked_nodes(&rules, &pfxs(&["100.64.0.9/32"])));
    }
}
