//! Integration test for overlay ICMPv4 ping over a piped pair of netstacks.
//!
//! Stack A pings stack B's tailnet IP. smoltcp's iface does NOT auto-reply to echo requests in
//! this build (`auto-icmp-echo-reply` is not enabled), so stack B runs a tiny responder task
//! that raw-opens ICMP, receives the Echo Request, and emits the matching Echo Reply.

use core::{net::IpAddr, time::Duration};

use ts_netstack_smoltcp_socket::{CreateSocket, ping};

extern crate ts_netstack_smoltcp_core as netcore;

use netcore::smoltcp::{
    phy::ChecksumCapabilities,
    wire::{IPV4_HEADER_LEN, Icmpv4Packet, Icmpv4Repr, IpProtocol, Ipv4Packet, Ipv4Repr},
};

#[path = "../examples/common/mod.rs"]
pub mod common;

/// Run an ICMPv4 echo responder on `chan`: receive Echo Requests and reply with Echo Replies
/// (swapping src/dst), forever.
async fn run_responder(chan: netcore::Channel) {
    let sock = chan.raw_open(true, IpProtocol::Icmp).await.unwrap();
    let checksum_caps = ChecksumCapabilities::default();

    loop {
        let bytes = match sock.recv_bytes().await {
            Ok(b) => b,
            Err(_) => return,
        };

        let Ok(ip_packet) = Ipv4Packet::new_checked(&bytes[..]) else {
            continue;
        };
        let Ok(ip_repr) = Ipv4Repr::parse(&ip_packet, &checksum_caps) else {
            continue;
        };
        if ip_repr.next_header != IpProtocol::Icmp {
            continue;
        }

        let Ok(icmp_packet) = Icmpv4Packet::new_checked(ip_packet.payload()) else {
            continue;
        };
        let (ident, seq_no) = match Icmpv4Repr::parse(&icmp_packet, &checksum_caps) {
            Ok(Icmpv4Repr::EchoRequest { ident, seq_no, .. }) => (ident, seq_no),
            _ => continue,
        };

        let reply_icmp = Icmpv4Repr::EchoReply {
            ident,
            seq_no,
            data: b"reply",
        };
        let reply_ip = Ipv4Repr {
            src_addr: ip_repr.dst_addr,
            dst_addr: ip_repr.src_addr,
            next_header: IpProtocol::Icmp,
            payload_len: reply_icmp.buffer_len(),
            hop_limit: 64,
        };

        let mut out = std::vec![0u8; IPV4_HEADER_LEN + reply_icmp.buffer_len()];
        {
            let mut p = Ipv4Packet::new_unchecked(&mut out[..]);
            reply_ip.emit(&mut p, &checksum_caps);
        }
        {
            let mut p = Icmpv4Packet::new_unchecked(&mut out[IPV4_HEADER_LEN..]);
            reply_icmp.emit(&mut p, &checksum_caps);
        }

        sock.send(&out).await.unwrap();
    }
}

#[tokio::test]
async fn ping_peer_returns_rtt() -> common::Result<()> {
    common::init();

    let (stack_a, stack_b) = common::spawn_piped_netstacks(Default::default(), None).await?;

    // stack_b owns NETSTACK_IP2; run its echo responder.
    tokio::spawn(run_responder(stack_b));

    let rtt = ping(
        &stack_a,
        common::NETSTACK_IP,
        IpAddr::V4(common::NETSTACK_IP2),
        Duration::from_secs(5),
    )
    .await
    .expect("ping should succeed");

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
async fn ping_times_out_without_responder() -> common::Result<()> {
    common::init();

    // No responder on stack_b -> echo request goes unanswered.
    let (stack_a, _stack_b) = common::spawn_piped_netstacks(Default::default(), None).await?;

    let err = ping(
        &stack_a,
        common::NETSTACK_IP,
        IpAddr::V4(common::NETSTACK_IP2),
        Duration::from_millis(300),
    )
    .await
    .expect_err("ping must time out with no responder");

    assert!(matches!(
        err,
        ts_netstack_smoltcp_socket::PingError::Timeout
    ));
    Ok(())
}
