//! Isolated wire-level and netstack-pair rejection probes.
use std::{net::Ipv6Addr, time::Duration};

use smoltcp::{phy::ChecksumCapabilities, wire::*};
use ts_forwarder::reject_ipv6;
use ts_netstack_smoltcp::{
    CreateSocket, Netstack, WakingPipe, WakingPipeDev,
    netcore::{self, HasChannel, NetstackControl, smoltcp},
};

const SRC: &str = "fd7a:115c:a1e0::123";
const DST: &str = "2001:4860:4860::8888";

fn syn() -> Vec<u8> {
    let b = etherparse::PacketBuilder::ipv6(
        SRC.parse::<Ipv6Addr>().unwrap().octets(),
        DST.parse::<Ipv6Addr>().unwrap().octets(),
        64,
    )
    .tcp(1234, 443, u32::MAX, 65535)
    .syn();
    let mut out = Vec::new();
    b.write(&mut out, &[]).unwrap();
    out
}

#[test]
fn reset_has_reversed_tuple_wrapped_ack_and_valid_checksum() {
    let out = reject_ipv6(&syn()).unwrap();
    let ip = Ipv6Packet::new_checked(&out[..]).unwrap();
    assert_eq!(ip.src_addr(), DST.parse::<Ipv6Addr>().unwrap());
    assert_eq!(ip.dst_addr(), SRC.parse::<Ipv6Addr>().unwrap());
    let p = TcpPacket::new_checked(ip.payload()).unwrap();
    assert!(p.rst() && p.ack());
    assert_eq!((p.src_port(), p.dst_port()), (443, 1234));
    assert_eq!(p.ack_number().0 as u32, 0);
    TcpRepr::parse(
        &p,
        &ip.src_addr().into(),
        &ip.dst_addr().into(),
        &ChecksumCapabilities::default(),
    )
    .unwrap();
    assert!(reject_ipv6(&out).is_none(), "never reset a reset");
    let mut bad = syn();
    bad[56] ^= 1; // TCP checksum
    assert!(reject_ipv6(&bad).is_none());
}

#[test]
fn udp_error_quotes_original_and_is_bounded_with_valid_checksum() {
    let b = etherparse::PacketBuilder::ipv6(
        SRC.parse::<Ipv6Addr>().unwrap().octets(),
        DST.parse::<Ipv6Addr>().unwrap().octets(),
        64,
    )
    .udp(1234, 443);
    let mut input = Vec::new();
    b.write(&mut input, &[7; 1400]).unwrap();
    let out = reject_ipv6(&input).unwrap();
    assert_eq!(out.len(), 1280);
    let ip = Ipv6Packet::new_checked(&out[..]).unwrap();
    let p = Icmpv6Packet::new_checked(ip.payload()).unwrap();
    assert_eq!(
        (p.msg_type(), p.msg_code()),
        (Icmpv6Message::DstUnreachable, 1)
    );
    assert!(p.verify_checksum(&ip.src_addr(), &ip.dst_addr()));
    assert_eq!(&out[48..], &input[..1232]);
}

#[test]
fn extensions_and_first_fragment_syn_reset_but_later_fragments_drop() {
    let orig = syn();
    let mut ext = orig[..40].to_vec();
    ext[6] = 60; // Destination Options
    ext[4..6].copy_from_slice(&28u16.to_be_bytes());
    ext.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0]);
    ext.extend_from_slice(&orig[40..]);
    assert!(reject_ipv6(&ext).is_some());
    ext[6] = 44; // Fragment: more-fragments bit
    ext[43] = 1;
    assert!(
        reject_ipv6(&ext).is_some(),
        "first fragment contains the complete SYN header"
    );
    ext[42..44].copy_from_slice(&0x0011u16.to_be_bytes()); // nonzero offset
    assert!(reject_ipv6(&ext).is_none());
    for len in 0..60 {
        assert!(reject_ipv6(&orig[..len]).is_none());
    }
}

#[tokio::test]
async fn peer_observes_connection_refused_on_first_syn() {
    let (p1, mut p2) = WakingPipe::new(None);
    let mut peer = Netstack::new(
        WakingPipeDev {
            pipe: p1,
            mtu: 1280,
            medium: smoltcp::phy::Medium::Ip,
        },
        netcore::Config::default(),
    );
    let ch = peer.command_channel();
    let run = tokio::spawn(async move { peer.run_tokio().await });
    ch.set_ips([SRC.parse::<Ipv6Addr>().unwrap().into()])
        .await
        .unwrap();
    let reject = tokio::spawn(async move {
        let syn = p2.rx.recv_async().await.unwrap();
        let reply = reject_ipv6(&syn).unwrap();
        p2.tx.send(&reply);
        // Keep the virtual link open until the test ends.
        std::future::pending::<()>().await;
    });
    let result = tokio::time::timeout(
        Duration::from_millis(250),
        ch.tcp_connect(
            format!("[{SRC}]:1234").parse().unwrap(),
            format!("[{DST}]:443").parse().unwrap(),
        ),
    )
    .await
    .expect("must reject first SYN, before a retransmission timer");
    assert!(result.is_err(), "must never complete the IPv6 handshake");
    // The reset completes connect promptly. The existing channel API currently reports
    // BadSocketHandle when its blocked connect observes the removed, reset socket.
    let error = result.err().unwrap();
    assert!(
        format!("{error:?}").contains("BadSocketHandle"),
        "error: {error:?}"
    );
    reject.abort();
    run.abort();
}

#[tokio::test]
async fn baseline_any_ip_resets_unmatched_ipv6_but_wildcard_listener_accepts() {
    let (p1, mut p2) = WakingPipe::new(None);
    let mut fwd = Netstack::new(
        WakingPipeDev {
            pipe: p1,
            mtu: 1280,
            medium: smoltcp::phy::Medium::Ip,
        },
        netcore::Config::default(),
    );
    let ch = fwd.command_channel();
    let run = tokio::spawn(async move { fwd.run_tokio().await });
    ch.set_any_ip(true).await.unwrap();
    p2.tx.send(&syn());
    let first = tokio::time::timeout(Duration::from_millis(250), p2.rx.recv_async())
        .await
        .unwrap()
        .unwrap();
    let ip = Ipv6Packet::new_checked(&first[..]).unwrap();
    assert!(TcpPacket::new_checked(ip.payload()).unwrap().rst());
    // A wildcard "0.0.0.0" listener has addr=None and also accepts IPv6!
    let _listener = ch.tcp_listen("0.0.0.0:443".parse().unwrap()).await.unwrap();
    p2.tx.send(&syn());
    let reply = tokio::time::timeout(Duration::from_millis(250), p2.rx.recv_async())
        .await
        .unwrap()
        .unwrap();
    let ip = Ipv6Packet::new_checked(&reply[..]).unwrap();
    let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
    assert!(tcp.syn() && tcp.ack() && !tcp.rst());
    run.abort();
}
