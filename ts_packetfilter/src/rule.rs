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
