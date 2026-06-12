/// An IP protocol number.
///
/// Typically, these would be `u8`, but Tailscale packet filters accept arbitrary `int`
/// values beyond the `u8` range to define Tailscale-specific semantics.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IpProto(i64);

impl IpProto {
    /// Protocol number for ICMP.
    pub const ICMP: Self = Self(1);
    /// Protocol number for ICMPv6.
    pub const ICMPV6: Self = Self(58);
    /// Protocol number for TCP.
    pub const TCP: Self = Self(6);
    /// Protocol number for UDP.
    pub const UDP: Self = Self(17);
    /// Protocol number for SCTP.
    pub const SCTP: Self = Self(132);

    /// Construct a new [`IpProto`] of the given value.
    pub const fn new(value: i64) -> Self {
        Self(value)
    }

    /// Whether this protocol carries L4 ports, so a packet-filter rule's port range applies to it.
    ///
    /// Go's `wgengine/filter` matches TCP/UDP/SCTP against a rule's port range (`match`), but routes
    /// ICMP/ICMPv6 — and every other "portless" protocol — through an IPs-only match that ignores
    /// ports entirely ("if any port is open to an IP, allow ICMP to it"). Mirroring that split is
    /// load-bearing: a packet with no L4 port surfaces as port `0`, which would spuriously fail a
    /// rule's `1..=65535`-style port range if it were port-checked like TCP/UDP.
    pub const fn is_port_ful(self) -> bool {
        matches!(self, Self::TCP | Self::UDP | Self::SCTP)
    }
}

impl From<i64> for IpProto {
    fn from(value: i64) -> Self {
        Self(value)
    }
}

impl From<IpProto> for i64 {
    fn from(value: IpProto) -> Self {
        value.0
    }
}
