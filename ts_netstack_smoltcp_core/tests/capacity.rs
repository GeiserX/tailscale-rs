//! Regression test for the interface address-storage capacity.
//!
//! The gated-on IPv6 overlay address set is `[v4/32, v6/128, 100.100.100.100/32]` plus the two
//! loopback addresses (`127.0.0.1/8`, `::1/128`) automatically appended when `Config::loopback`
//! is set — five entries total. smoltcp stores interface addresses in a fixed-capacity
//! `heapless::Vec<IpCidr, IFACE_MAX_ADDR_COUNT>`; if that capacity is below five,
//! [`Netstack::direct_set_ips`] silently returns `false` (overflow) and the netstack is left with
//! no usable addresses. This converts that silent overflow into a caught regression: the test is
//! compiled with the crate's `iface-max-addr-count-5` dev feature, so it asserts the full
//! five-address set is accepted.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use smoltcp::time::Instant;

extern crate ts_netstack_smoltcp_core as netcore;

use netcore::Netstack;

/// `direct_set_ips` must accept the full five-address overlay set: the IPv4 tailnet address, the
/// IPv6 tailnet address, the MagicDNS service IP, and (auto-appended via `loopback`) the IPv4 and
/// IPv6 loopback addresses. A `false` return means smoltcp's `IFACE_MAX_ADDR_COUNT` is below five
/// and overlay address assignment silently fails.
#[test]
fn direct_set_ips_holds_five_addresses() {
    let mut stack = Netstack::new(
        netcore::Config {
            loopback: true,
            ..Default::default()
        },
        Instant::ZERO,
    );

    // The three overlay addresses; `direct_set_ips` appends 127.0.0.1 and ::1 itself because
    // `loopback` is set, yielding five interface addresses in total.
    let overlay: [IpAddr; 3] = [
        IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(100, 100, 100, 100)),
    ];

    assert!(
        stack.direct_set_ips(overlay),
        "direct_set_ips must accept the 5-address overlay+loopback set; a false return means \
         smoltcp's IFACE_MAX_ADDR_COUNT is < 5 and overlay address assignment silently overflows"
    );
}
