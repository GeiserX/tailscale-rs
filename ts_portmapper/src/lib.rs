//! NAT port mapping for the node's underlay UDP socket: NAT-PMP (RFC 6886) and PCP (RFC 6887).
//!
//! The port mapper asks the LAN gateway for an inbound UDP mapping so that a peer behind a hard
//! NAT can reach this node directly instead of through DERP. It is modelled on Go Tailscale's
//! `net/portmapper`. UPnP-IGD is not implemented.
//!
//! # LAN boundary
//!
//! Every packet this crate sends goes through a [`GatewayCap`], a capability built from a
//! validated [`Gateway`]: the gateway must be private (RFC 1918) and on-link, sockets are bound
//! to the host's own address and, where the OS allows it, to its interface (see [`BindMode`]), the
//! only destination is `gateway:5351` ([`LanDest::Pxp`]), and a [`PolicyHandle`] is checked before
//! every send. No API in this crate takes an arbitrary destination address. (The gateway lookup's
//! kernel source-address check connects a UDP socket but never sends on it.)
//!
//! # Layout
//!
//! - [`gateway`]: default-route lookup and validation (macOS routing-socket dump, Linux
//!   `/proc/net/route`, `Unsupported` elsewhere).
//! - [`pmp`] and [`pcp`]: pure, strictly validating codecs.
//! - [`oneshot`]: single-attempt probe, map and delete.
//! - [`probe_tool`]: the `--portmap-probe` diagnostic used to validate a deployment.
//! - `testing` (feature `test-harness`): a fake NAT-PMP/PCP router and `TestCap`, a loopback
//!   transport that production code cannot construct.

mod blocking;
mod cap;
pub mod gateway;
pub mod oneshot;
pub mod pcp;
pub mod pmp;
pub mod probe_tool;
#[cfg(any(test, feature = "test-harness"))]
pub mod testing;

/// Without the `test-harness` feature the test transport does not exist, so production code
/// cannot construct it:
#[cfg_attr(
    not(feature = "test-harness"),
    doc = "```compile_fail\nlet _ = ts_portmapper::testing::TestCap::new;\n```"
)]
#[cfg_attr(
    feature = "test-harness",
    doc = "(The compile-fail check runs in builds without the feature.)"
)]
pub const TEST_HARNESS_ENABLED: bool = cfg!(feature = "test-harness");

pub use cap::{
    BindMode, CapError, DenyReason, EXCHANGE_TIMEOUT, ExchangeStats, Flow, GatewayCap, LanDest,
    MAX_EXAMINED, NetGen, PolicyHandle, ProbeListener, PxpTransport, RECV_BUF, errno_name,
};
pub use gateway::{Gateway, GatewayLookup, LookupError};

/// The UDP port NAT-PMP and PCP servers listen on (RFC 6886 §3, RFC 6887 §19.1).
pub const PXP_PORT: u16 = 5351;

/// Whether `ip` can be a router's external address at all. The codecs reject anything else as
/// malformed: unspecified, `0.0.0.0/8`, loopback, link-local, multicast, and `240.0.0.0/4`
/// (which includes the limited broadcast address). Private (RFC 1918) and shared (`100.64.0.0/10`)
/// addresses are plausible: they are a double NAT's honest answer and worth reporting.
pub fn is_plausible_external(ip: std::net::Ipv4Addr) -> bool {
    let [a, ..] = ip.octets();
    !(a == 0 || ip.is_loopback() || ip.is_link_local() || ip.is_multicast() || a >= 240)
}

/// Whether `ip` may be advertised to peers as a reachable endpoint: plausible
/// ([`is_plausible_external`]) and neither private (RFC 1918, a double NAT) nor shared
/// (`100.64.0.0/10`: carrier-grade NAT, and the tailnet's own range).
pub fn is_advertisable(ip: std::net::Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    let shared = a == 100 && (64..128).contains(&b);
    is_plausible_external(ip) && !ip.is_private() && !shared
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn external_address_classes() {
        let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        for bad in [
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "239.255.255.250",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            assert!(!is_plausible_external(ip(bad)), "{bad}");
            assert!(!is_advertisable(ip(bad)), "{bad}");
        }
        for double_nat in [
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.0",
            "100.127.255.255",
        ] {
            assert!(is_plausible_external(ip(double_nat)), "{double_nat}");
            assert!(!is_advertisable(ip(double_nat)), "{double_nat}");
        }
        for public in ["203.0.113.7", "198.51.100.9", "192.0.2.1"] {
            assert!(is_advertisable(ip(public)), "{public}");
        }
        // The shared range is exactly 100.64.0.0/10.
        for b in 0..=255u8 {
            let shared = (64..128).contains(&b);
            assert_eq!(!is_advertisable(Ipv4Addr::new(100, b, 0, 1)), shared, "{b}");
        }
    }
}
