use core::num::NonZeroU16;

/// Configuration for setting up a tun device.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Config {
    /// The name of the network interface.
    pub name: String,

    /// The MTU (Maximum Transmission Unit) of the network interface. Must be between 1
    /// (inclusive) and 65535 (inclusive).
    pub mtu: NonZeroU16,

    /// The prefix for the interface, non-truncated (full address + subnet mask), e.g.
    /// `192.168.100.32/24`.
    pub prefix: ipnet::IpNet,
}
