//! Integration test for overlay ICMPv4 ping over a piped pair of netstacks.
//!
//! Stack A pings stack B's tailnet IP. The netstack is built with smoltcp's `auto-icmp-echo-reply`
//! feature (matching Go's gVisor `icmp.NewProtocol4`), so stack B's iface answers the Echo Request
//! for its OWN registered address with no application code — this test asserts that auto-reply
//! happens (it is the regression guard for the feature). A ping to an address the netstack does NOT
//! own gets no reply (smoltcp gates the reply behind `has_ip_addr(dst)`), so `ping_times_out_*`
//! pings an unassigned IP to confirm the scoping.

use core::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use ts_netstack_smoltcp_socket::ping;

extern crate ts_netstack_smoltcp_core as netcore;

#[path = "../examples/common/mod.rs"]
pub mod common;

#[tokio::test]
async fn ping_peer_returns_rtt() -> common::Result<()> {
    common::init();

    // stack_b owns NETSTACK_IP2 and, with `auto-icmp-echo-reply` enabled, answers the Echo Request
    // for that address itself — no manual responder needed (this is the feature's regression test).
    let (stack_a, _stack_b) = common::spawn_piped_netstacks(Default::default(), None).await?;

    let rtt = ping(
        &stack_a,
        common::NETSTACK_IP,
        IpAddr::V4(common::NETSTACK_IP2),
        Duration::from_secs(5),
    )
    .await
    .expect("ping should succeed via smoltcp auto-icmp-echo-reply (Go gVisor parity)");

    assert!(rtt <= Duration::from_secs(5), "rtt within timeout: {rtt:?}");
    Ok(())
}

#[tokio::test]
async fn ping_rejects_ipv6() -> common::Result<()> {
    common::init();

    let (stack_a, _stack_b) = common::spawn_piped_netstacks(Default::default(), None).await?;

    let err = ping(
        &stack_a,
        common::NETSTACK_IP,
        "::1".parse::<IpAddr>().unwrap(),
        Duration::from_millis(200),
    )
    .await
    .expect_err("ipv6 ping must be rejected");

    assert!(matches!(
        err,
        ts_netstack_smoltcp_socket::PingError::Ipv6Unsupported
    ));
    Ok(())
}

#[tokio::test]
async fn ping_times_out_to_unowned_address() -> common::Result<()> {
    common::init();

    // Ping an address NO netstack owns. `auto-icmp-echo-reply` only answers Echo Requests destined
    // to one of the iface's own registered addresses (smoltcp gates on `has_ip_addr(dst)`), so a
    // ping to an unassigned IP gets no reply and must time out — confirming the auto-reply is scoped
    // to the node's own address and does NOT blanket-answer arbitrary destinations.
    let (stack_a, _stack_b) = common::spawn_piped_netstacks(Default::default(), None).await?;
    let unowned = Ipv4Addr::new(192, 168, 32, 99); // neither NETSTACK_IP nor NETSTACK_IP2

    let err = ping(
        &stack_a,
        common::NETSTACK_IP,
        IpAddr::V4(unowned),
        Duration::from_millis(300),
    )
    .await
    .expect_err("a ping to an address no netstack owns must time out (auto-reply is dst-scoped)");

    assert!(matches!(
        err,
        ts_netstack_smoltcp_socket::PingError::Timeout
    ));
    Ok(())
}
