use core::{
    cmp::Ordering,
    hash::Hash,
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
};

use zerocopy::NetworkEndian;

/// An endpoint included in a [`CallMeMaybe`][crate::CallMeMaybe] message: a socket address
/// on which this node believes it's reachable.
///
/// All addresses are encoded as IPv6: IPv4 is mapped.
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    Hash,
    zerocopy::Immutable,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Unaligned,
    zerocopy::KnownLayout,
)]
#[repr(C, packed)]
pub struct Endpoint {
    addr: [zerocopy::U16<NetworkEndian>; 8],
    port: zerocopy::U16<NetworkEndian>,
}

impl Endpoint {
    /// Report the address part of this endpoint.
    ///
    /// Does not unwrap IPv4-mapped IPv6: this is just the literal value in the endpoint.
    pub const fn addr_v6(&self) -> Ipv6Addr {
        Ipv6Addr::new(
            self.addr[0].get(),
            self.addr[1].get(),
            self.addr[2].get(),
            self.addr[3].get(),
            self.addr[4].get(),
            self.addr[5].get(),
            self.addr[6].get(),
            self.addr[7].get(),
        )
    }

    /// Report the address part of this endpoint with any IPv4-in-IPv6 mapping unwrapped.
    pub const fn addr(&self) -> IpAddr {
        let addr = self.addr_v6();

        match addr.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(addr),
        }
    }

    /// Report the port part of this endpoint.
    pub const fn port(&self) -> u16 {
        self.port.get()
    }

    /// Return this endpoint as a [`SocketAddrV6`].
    pub const fn socket_addr_v6(&self) -> SocketAddrV6 {
        SocketAddrV6::new(self.addr_v6(), self.port(), 0, 0)
    }

    /// Return this endpoint as a [`SocketAddr`] with any IPv4-in-IPv6 mapping unwrapped.
    pub const fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.addr(), self.port())
    }

    /// Construct a new value from a socket addr.
    ///
    /// Applies IPv4 to IPv6 mapping.
    pub const fn from_socket_addr(sa: SocketAddr) -> Self {
        let ip = match sa.ip() {
            IpAddr::V4(sa) => sa.to_ipv6_mapped(),
            IpAddr::V6(sa) => sa,
        };

        Self {
            addr: addr_segments(ip),
            port: zerocopy::U16::new(sa.port()),
        }
    }
}

/// Encode IPv6 segments as big-endian wire values.
///
/// Built element-by-element via [`U16::new`][zerocopy::U16::new] rather than a bitwise
/// transmute of [`Ipv6Addr::segments`]: the segments are in host byte order, and a transmute
/// would skip the byte swap, corrupting every address on little-endian hosts.
const fn addr_segments(ip: Ipv6Addr) -> [zerocopy::U16<NetworkEndian>; 8] {
    let s = ip.segments();
    [
        zerocopy::U16::new(s[0]),
        zerocopy::U16::new(s[1]),
        zerocopy::U16::new(s[2]),
        zerocopy::U16::new(s[3]),
        zerocopy::U16::new(s[4]),
        zerocopy::U16::new(s[5]),
        zerocopy::U16::new(s[6]),
        zerocopy::U16::new(s[7]),
    ]
}

impl PartialOrd for Endpoint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Endpoint {
    fn cmp(&self, other: &Self) -> Ordering {
        self.socket_addr().cmp(&other.socket_addr())
    }
}

impl From<Endpoint> for SocketAddrV6 {
    fn from(value: Endpoint) -> Self {
        value.socket_addr_v6()
    }
}

impl From<Endpoint> for SocketAddr {
    fn from(value: Endpoint) -> Self {
        value.socket_addr()
    }
}

impl From<SocketAddrV6> for Endpoint {
    fn from(value: SocketAddrV6) -> Self {
        Self {
            addr: addr_segments(*value.ip()),
            port: value.port().into(),
        }
    }
}

impl From<SocketAddr> for Endpoint {
    fn from(value: SocketAddr) -> Self {
        Self::from_socket_addr(value)
    }
}

#[cfg(test)]
mod tests {
    use zerocopy::{FromBytes, IntoBytes};

    use super::*;

    #[test]
    fn ipv4_roundtrips_through_bytes() {
        // Encoding then decoding through the on-wire bytes must preserve the address: a
        // naive transmute of the host-order segments would byte-swap on little-endian hosts.
        let sa: SocketAddr = "203.0.113.7:41641".parse().unwrap();
        let ep = Endpoint::from(sa);

        let bytes = ep.as_bytes().to_vec();
        let decoded = Endpoint::ref_from_bytes(&bytes).unwrap();

        assert_eq!(decoded.socket_addr(), sa);
    }

    #[test]
    fn ipv6_roundtrips_through_bytes() {
        let sa: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let ep = Endpoint::from(sa);

        let bytes = ep.as_bytes().to_vec();
        let decoded = Endpoint::ref_from_bytes(&bytes).unwrap();

        assert_eq!(decoded.socket_addr(), sa);
    }
}
