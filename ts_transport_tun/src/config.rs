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

#[cfg(test)]
mod tests {
    use core::num::NonZeroU16;

    use super::Config;
    use crate::Error;

    #[test]
    fn config_field_round_trip() {
        let mtu = NonZeroU16::new(1280).unwrap();
        let prefix = "100.64.0.1/32".parse::<ipnet::IpNet>().unwrap();
        let config = Config {
            name: "tun-test".to_string(),
            mtu,
            prefix,
        };

        assert_eq!(config.name, "tun-test");
        assert_eq!(config.mtu, mtu);
        assert_eq!(config.mtu.get(), 1280);
        assert_eq!(config.prefix, prefix);
    }

    #[test]
    fn root_required_display_mentions_root() {
        assert!(Error::RootUserRequired.to_string().contains("root"));
    }

    #[test]
    fn io_error_displays_transparently() {
        let io = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let expected = io.to_string();
        let err = Error::IoError(io);
        assert_eq!(err.to_string(), expected);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn config_serde_round_trip() {
        let config = Config {
            name: "tun-test".to_string(),
            mtu: NonZeroU16::new(1280).unwrap(),
            prefix: "100.64.0.1/32".parse::<ipnet::IpNet>().unwrap(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, config.name);
        assert_eq!(back.mtu, config.mtu);
        assert_eq!(back.prefix, config.prefix);
    }
}
