//! Tests of the fake router, `TestCap`, and the shared exchange loop's acceptance rules.

use std::{
    net::Ipv4Addr,
    num::{NonZeroU16, NonZeroU32},
    sync::Arc,
    time::Duration,
};

use tokio::time::Instant;

use super::*;
use crate::{
    CapError, DenyReason, ExchangeStats, Flow, Gateway, LanDest, MAX_EXAMINED, PolicyHandle,
    PxpTransport, pcp, pmp,
};

const P1234: NonZeroU16 = NonZeroU16::new(1234).unwrap();
const LIFE: NonZeroU32 = NonZeroU32::new(7200).unwrap();

fn gateway(self_ip: Ipv4Addr) -> Gateway {
    Gateway {
        gw: Ipv4Addr::new(192, 168, 1, 1),
        self_ip,
        prefix_len: 24,
        if_index: 4,
        if_name: "en0".to_owned(),
    }
}

async fn setup(opts: RouterOptions) -> (FakeRouter, Arc<TestCap>, PolicyHandle) {
    let router = FakeRouter::start(opts).await.unwrap();
    let policy = PolicyHandle::new(true);
    let cap = TestCap::new(gateway(Ipv4Addr::LOCALHOST), &router, policy.clone());
    (router, cap, policy)
}

/// Send `reqs` and collect accepted replies until `want` arrived or `wait` passed.
async fn collect(
    cap: &TestCap,
    reqs: &[&[u8]],
    want: usize,
    wait: Duration,
) -> (Vec<Vec<u8>>, ExchangeStats) {
    let mut got = Vec::new();
    let mut on = |b: &[u8]| {
        got.push(b.to_vec());
        if got.len() >= want {
            Flow::Done
        } else {
            Flow::Continue
        }
    };
    let stats = cap
        .exchange(LanDest::Pxp, reqs, Instant::now() + wait, &mut on)
        .await
        .unwrap();
    (got, stats)
}

const WAIT: Duration = Duration::from_secs(2);

#[tokio::test]
async fn pmp_address_map_renew_delete() {
    let (router, cap, _) = setup(RouterOptions::default()).await;
    let (r, _) = collect(&cap, &[&pmp::public_address_request()], 1, WAIT).await;
    let a = pmp::parse_public_addr_reply(&r[0]).unwrap();
    assert_eq!(a.public_ip, Ipv4Addr::new(203, 0, 113, 7));
    assert_eq!(a.epoch, 3600);

    let req = pmp::map_request(P1234, 0, LIFE);
    let (r, _) = collect(&cap, &[&req], 1, WAIT).await;
    let m = pmp::parse_map_reply(&r[0], P1234, pmp::MapKind::Map).unwrap();
    assert_eq!((m.external, m.lifetime), (4242, 7200));
    // A renewal keeps the rule and its external port.
    let req = pmp::map_request(P1234, m.external, LIFE);
    let (r, _) = collect(&cap, &[&req], 1, WAIT).await;
    let m2 = pmp::parse_map_reply(&r[0], P1234, pmp::MapKind::Map).unwrap();
    assert_eq!(m2.external, 4242);
    assert_eq!(router.mappings().len(), 1);
    assert_eq!(router.mappings()[0].client_ip, Ipv4Addr::LOCALHOST);

    let (r, _) = collect(&cap, &[&pmp::delete_request(P1234)], 1, WAIT).await;
    pmp::parse_map_reply(&r[0], P1234, pmp::MapKind::Delete).unwrap();
    assert!(router.mappings().is_empty());
    let c = router.counters();
    assert_eq!(
        (
            c.num_pmp_recv,
            c.num_pmp_public_addr_recv,
            c.num_pmp_map_recv,
            c.num_deletes
        ),
        (4, 1, 3, 1)
    );
    let reqs = router.requests();
    assert_eq!(reqs[3].suggested_external, Some(0));
    assert_eq!(reqs[3].lifetime, Some(0));
    router.shutdown().await;
}

#[tokio::test]
async fn pcp_announce_map_delete_with_nonce_ownership() {
    let (router, cap, _) = setup(RouterOptions::default()).await;
    let me = Ipv4Addr::LOCALHOST;
    let (r, _) = collect(&cap, &[&pcp::announce_request(me)], 1, WAIT).await;
    assert_eq!(
        pcp::parse_announce_reply(&r[0]).unwrap().result,
        pcp::ResultCode::Success
    );

    let nonce = pcp::Nonce::random().unwrap();
    let req = pcp::map_request(me, P1234, 0, LIFE, &nonce);
    let (r, _) = collect(&cap, &[&req], 1, WAIT).await;
    let m = pcp::parse_map_reply(&r[0], &nonce, P1234, pcp::MapKind::Map).unwrap();
    assert_eq!(m.external, "203.0.113.7:4242".parse().unwrap());
    assert_eq!(router.mappings()[0].nonce, Some(*nonce.as_bytes()));

    // Another nonce can neither renew nor delete the rule.
    let thief = pcp::Nonce::random().unwrap();
    let (r, _) = collect(&cap, &[&pcp::delete_request(me, P1234, &thief)], 1, WAIT).await;
    assert!(matches!(
        pcp::parse_map_reply(&r[0], &thief, P1234, pcp::MapKind::Delete),
        Err(pcp::ReplyError::Router {
            code: pcp::ResultCode::NotAuthorized,
            ..
        })
    ));
    assert_eq!(router.mappings().len(), 1);

    let (r, _) = collect(&cap, &[&pcp::delete_request(me, P1234, &nonce)], 1, WAIT).await;
    pcp::parse_map_reply(&r[0], &nonce, P1234, pcp::MapKind::Delete).unwrap();
    assert!(router.mappings().is_empty());
    let c = router.counters();
    assert_eq!(
        (c.num_pcp_recv, c.num_pcp_disco_recv, c.num_pcp_map_recv),
        (4, 1, 3)
    );
    router.shutdown().await;
}

/// The router enforces the PCP client IP; the source-consistent loopback mode passes.
#[tokio::test]
async fn pcp_client_ip_enforcement() {
    let opts = RouterOptions {
        enforce_pcp_client_ip: true,
        ..RouterOptions::default()
    };
    let (router, ok_cap, policy) = setup(opts).await;
    let (r, _) = collect(
        &ok_cap,
        &[&pcp::announce_request(Ipv4Addr::LOCALHOST)],
        1,
        WAIT,
    )
    .await;
    assert_eq!(
        pcp::parse_announce_reply(&r[0]).unwrap().result,
        pcp::ResultCode::Success
    );
    // The "inconsistent" mode: the client IP field says 198.51.100.4, the source is loopback.
    let other = Ipv4Addr::new(198, 51, 100, 4);
    let bad_cap = TestCap::new(gateway(other), &router, policy);
    let (r, _) = collect(&bad_cap, &[&pcp::announce_request(other)], 1, WAIT).await;
    assert_eq!(
        pcp::parse_announce_reply(&r[0]).unwrap().result,
        pcp::ResultCode::AddressMismatch
    );
    router.shutdown().await;
}

/// A NAT-PMP-only router answers a PCP request with a NAT-PMP "unsupported version".
#[tokio::test]
async fn pmp_only_router_answers_pcp_with_unsupported_version() {
    let opts = RouterOptions {
        pcp: false,
        ..RouterOptions::default()
    };
    let (router, cap, _) = setup(opts).await;
    let (r, _) = collect(
        &cap,
        &[&pcp::announce_request(Ipv4Addr::LOCALHOST)],
        1,
        WAIT,
    )
    .await;
    assert_eq!(r[0][0], 0);
    assert!(matches!(
        pmp::parse_public_addr_reply(&r[0]),
        Err(pmp::ReplyError::Router {
            code: pmp::ResultCode::UnsupportedVersion,
            ..
        })
    ));
    router.shutdown().await;
}

#[tokio::test]
async fn expiry_reboot_and_epoch() {
    let (router, cap, _) = setup(RouterOptions::default()).await;
    let clock = router.clock();
    router.set_lifetime_override(Some(60));
    let (r, _) = collect(&cap, &[&pmp::map_request(P1234, 0, LIFE)], 1, WAIT).await;
    assert_eq!(
        pmp::parse_map_reply(&r[0], P1234, pmp::MapKind::Map)
            .unwrap()
            .lifetime,
        60
    );
    clock.advance(59);
    assert_eq!(router.mappings().len(), 1);
    clock.advance(1);
    assert!(router.mappings().is_empty());

    router.set_lifetime_override(None);
    collect(&cap, &[&pmp::map_request(P1234, 0, LIFE)], 1, WAIT).await;
    router.reboot();
    assert!(router.mappings().is_empty());
    clock.advance(5);
    let (r, _) = collect(&cap, &[&pmp::public_address_request()], 1, WAIT).await;
    assert_eq!(pmp::parse_public_addr_reply(&r[0]).unwrap().epoch, 5);
    router.set_epoch(9);
    let (r, _) = collect(&cap, &[&pmp::public_address_request()], 1, WAIT).await;
    assert_eq!(pmp::parse_public_addr_reply(&r[0]).unwrap().epoch, 9);
    router.shutdown().await;
}

/// At the harness level, a delete is scoped to its internal port, so a co-resident client's
/// rule (here internal 41644, like a Go tailscaled) survives.
#[tokio::test]
async fn delete_is_scoped_to_internal_port() {
    let (router, cap, _) = setup(RouterOptions::default()).await;
    let go = NonZeroU16::new(41644).unwrap();
    collect(&cap, &[&pmp::map_request(go, 0, LIFE)], 1, WAIT).await;
    collect(&cap, &[&pmp::map_request(P1234, 0, LIFE)], 1, WAIT).await;
    assert_eq!(router.mappings().len(), 2);
    collect(&cap, &[&pmp::delete_request(P1234)], 1, WAIT).await;
    let left = router.mappings();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].internal, 41644);
    router.shutdown().await;
}

#[tokio::test]
async fn drop_commit_duplicate_and_reorder_knobs() {
    let (router, cap, _) = setup(RouterOptions::default()).await;
    let short = Duration::from_millis(150);

    router.drop_next(1);
    let (r, _) = collect(&cap, &[&pmp::map_request(P1234, 0, LIFE)], 1, short).await;
    assert!(r.is_empty());
    assert!(
        router.mappings().is_empty(),
        "a dropped request commits nothing"
    );

    router.commit_then_drop_next(1);
    let (r, _) = collect(&cap, &[&pmp::map_request(P1234, 0, LIFE)], 1, short).await;
    assert!(r.is_empty());
    assert_eq!(
        router.mappings().len(),
        1,
        "commit-then-drop keeps the rule"
    );

    router.duplicate_next(1);
    let (r, _) = collect(&cap, &[&pmp::public_address_request()], 3, short).await;
    assert_eq!(r.len(), 2);

    // Reorder: the first reply is held until after the second.
    router.reorder_next();
    let (r, _) = collect(
        &cap,
        &[
            &pmp::public_address_request(),
            &pmp::map_request(P1234, 0, LIFE),
        ],
        2,
        WAIT,
    )
    .await;
    assert_eq!(r.len(), 2);
    assert_eq!(r[0][1], pmp::OP_MAP_UDP | pmp::OP_REPLY);
    assert_eq!(r[1][1], pmp::OP_PUBLIC_ADDR | pmp::OP_REPLY);
    router.shutdown().await;
}

/// Replies from the wrong port or address never reach the handler.
#[tokio::test]
async fn wrong_source_replies_are_dropped() {
    let (router, cap, _) = setup(RouterOptions::default()).await;
    let short = Duration::from_millis(150);
    router.reply_from_wrong_port_next(1);
    let (r, s) = collect(&cap, &[&pmp::public_address_request()], 1, short).await;
    assert!(r.is_empty());
    assert_eq!(s.wrong_source, 1);
    router.reply_from_wrong_ip_next(1);
    let (r, s) = collect(&cap, &[&pmp::public_address_request()], 1, short).await;
    assert!(r.is_empty());
    assert_eq!(s.wrong_source, 1);
    router.shutdown().await;
}

/// An oversize datagram fills the 1101-byte buffer and is dropped; other corruptions
/// arrive and are rejected by the codecs.
#[tokio::test]
async fn corrupted_replies() {
    let (router, cap, _) = setup(RouterOptions::default()).await;
    let short = Duration::from_millis(150);
    router.corrupt_next(Corruption::Oversize);
    let (r, s) = collect(&cap, &[&pmp::public_address_request()], 1, short).await;
    assert!(r.is_empty());
    assert_eq!(s.oversize, 1);

    let nonce = pcp::Nonce::random().unwrap();
    let me = Ipv4Addr::LOCALHOST;
    for c in [
        Corruption::Truncate,
        Corruption::BadVersion,
        Corruption::WrongOpcode,
        Corruption::NoRBit,
        Corruption::WrongNonce,
        Corruption::WrongProto,
        Corruption::WrongInternalPort,
        Corruption::Garbage,
    ] {
        router.corrupt_next(c);
        let req = pcp::map_request(me, P1234, 0, LIFE, &nonce);
        let (r, _) = collect(&cap, &[&req], 1, WAIT).await;
        assert!(
            matches!(
                pcp::parse_map_reply(&r[0], &nonce, P1234, pcp::MapKind::Map),
                Err(pcp::ReplyError::Malformed(_))
            ),
            "{c:?}"
        );
    }
    router.shutdown().await;
}

/// A burst of 1000 junk datagrams from the right source is bounded: the exchange stops
/// after examining `MAX_EXAMINED` of them.
#[tokio::test]
async fn junk_burst_is_bounded() {
    let (router, cap, _) = setup(RouterOptions::default()).await;
    router.junk_before_next_reply(1000);
    let start = std::time::Instant::now();
    let deadline = Instant::now() + crate::EXCHANGE_TIMEOUT;
    let mut accepted = 0;
    let mut on = |_: &[u8]| {
        accepted += 1;
        Flow::Continue
    };
    let s = cap
        .exchange(
            LanDest::Pxp,
            &[&pmp::public_address_request()],
            deadline,
            &mut on,
        )
        .await
        .unwrap();
    assert!(s.examined <= MAX_EXAMINED);
    assert!(s.hit_cap || Instant::now() >= deadline);
    assert!(start.elapsed() < Duration::from_secs(2));
    assert!(accepted <= MAX_EXAMINED);
    router.shutdown().await;
}

/// Junk that trickles in from the right source (fewer datagrams than `MAX_EXAMINED`, spread
/// over six times the exchange timeout) cannot extend the absolute deadline. A per-receive
/// timeout would keep waiting for 1.5 s; the absolute deadline ends the exchange at 250 ms.
#[tokio::test]
async fn junk_trickle_cannot_extend_the_deadline() {
    let (router, cap, _) = setup(RouterOptions::default()).await;
    let n = 30;
    let interval = Duration::from_millis(50);
    assert!(n < MAX_EXAMINED);
    assert!(interval * u32::try_from(n).unwrap() > crate::EXCHANGE_TIMEOUT * 4);
    router.junk_trickle_next(n, interval);
    let start = std::time::Instant::now();
    let mut accepted = 0;
    let mut on = |_: &[u8]| {
        accepted += 1;
        Flow::Continue
    };
    let s = cap
        .exchange(
            LanDest::Pxp,
            &[&pmp::public_address_request()],
            Instant::now() + crate::EXCHANGE_TIMEOUT,
            &mut on,
        )
        .await
        .unwrap();
    let elapsed = start.elapsed();
    assert!(!s.hit_cap && s.examined < MAX_EXAMINED, "{s:?}");
    assert!(
        accepted >= 1,
        "some junk arrived before the deadline: {s:?}"
    );
    assert!(
        elapsed < Duration::from_millis(600),
        "junk extended the exchange to {elapsed:?}"
    );
    router.shutdown().await;
}

/// Staging: while one reply is paused at a barrier, a later request is decoded, committed
/// and answered.
#[tokio::test]
async fn barrier_holds_only_its_own_reply() {
    let (router, cap, _) = setup(RouterOptions::default()).await;
    let other = NonZeroU16::new(4321).unwrap();
    collect(&cap, &[&pmp::map_request(other, 0, LIFE)], 1, WAIT).await;
    let b = router.barrier(RequestKind::PmpMap);
    let cap2 = cap.clone();
    let pending = tokio::spawn(async move {
        collect(&cap2, &[&pmp::map_request(P1234, 0, LIFE)], 1, WAIT)
            .await
            .0
    });
    b.reached().await;
    let before = router.requests().len();
    // A delete of the other rule commits and is answered while the first reply is held.
    let (r, _) = collect(&cap, &[&pmp::delete_request(other)], 1, WAIT).await;
    assert_eq!(r.len(), 1, "the second request was answered");
    pmp::parse_map_reply(&r[0], other, pmp::MapKind::Delete).unwrap();
    assert_eq!(router.requests().len(), before + 1);
    let left = router.mappings();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].internal, 1234);
    assert!(!pending.is_finished(), "the first reply is still held");
    b.release();
    assert_eq!(pending.await.unwrap().len(), 1);
    router.shutdown().await;
}

/// The harness refuses to listen on, or send to, anything but loopback.
#[tokio::test]
async fn harness_is_loopback_only() {
    for ip in [Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(192, 168, 1, 1)] {
        let r = FakeRouter::start(RouterOptions {
            bind_ip: ip,
            ..RouterOptions::default()
        })
        .await;
        assert_eq!(
            r.map(drop).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput,
            "{ip}"
        );
    }
    let to = std::net::SocketAddr::from((Ipv4Addr::new(192, 168, 1, 1), 5351));
    assert_eq!(
        send_datagrams(to, 1, 1).await.unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
}

#[tokio::test]
async fn barrier_pauses_after_commit() {
    let (router, cap, _) = setup(RouterOptions::default()).await;
    let b = router.barrier(RequestKind::PmpMap);
    let cap2 = cap.clone();
    let pending = tokio::spawn(async move {
        collect(&cap2, &[&pmp::map_request(P1234, 0, LIFE)], 1, WAIT)
            .await
            .0
    });
    b.reached().await;
    assert_eq!(router.mappings().len(), 1, "committed before the pause");
    b.release();
    assert_eq!(pending.await.unwrap().len(), 1);
    router.shutdown().await;
}

#[tokio::test]
async fn result_overrides_and_short_errors() {
    let (router, cap, _) = setup(RouterOptions::default()).await;
    router.set_result(
        RequestKind::PmpMap,
        Some(ResultOverride {
            code: 2,
            lifetime: 0,
        }),
    );
    let (r, _) = collect(&cap, &[&pmp::map_request(P1234, 0, LIFE)], 1, WAIT).await;
    assert!(matches!(
        pmp::parse_map_reply(&r[0], P1234, pmp::MapKind::Map),
        Err(pmp::ReplyError::Router {
            code: pmp::ResultCode::NotAuthorized,
            ..
        })
    ));
    router.set_short_pcp_errors(true);
    router.set_result(
        RequestKind::PcpMap,
        Some(ResultOverride {
            code: 8,
            lifetime: 120,
        }),
    );
    let nonce = pcp::Nonce::random().unwrap();
    let req = pcp::map_request(Ipv4Addr::LOCALHOST, P1234, 0, LIFE, &nonce);
    let (r, _) = collect(&cap, &[&req], 1, WAIT).await;
    assert_eq!(r[0].len(), 24);
    assert_eq!(
        pcp::parse_map_reply(&r[0], &nonce, P1234, pcp::MapKind::Map),
        Err(pcp::ReplyError::Unmatched {
            code: pcp::ResultCode::NoResources,
            lifetime: 120,
            epoch: 3600
        })
    );
    router.shutdown().await;
}

/// With the test transport, a refused send writes nothing (router counter 0), and injected
/// OS errors surface verbatim.
#[tokio::test]
async fn test_cap_gate_and_injected_errors() {
    let (router, cap, policy) = setup(RouterOptions::default()).await;
    let deadline = Instant::now() + Duration::from_millis(100);
    let mut ignore = |_: &[u8]| Flow::Continue;
    let req = pmp::public_address_request();

    policy.set_lan_sends_allowed(false);
    let r = cap
        .exchange(LanDest::Pxp, &[&req], deadline, &mut ignore)
        .await;
    assert!(matches!(r, Err(CapError::Denied(DenyReason::Policy))));
    assert!(cap.send_nowait(LanDest::Pxp, &req).is_err());
    policy.set_lan_sends_allowed(true);

    cap.inject_send_error(Some(65));
    let r = cap
        .exchange(LanDest::Pxp, &[&req], deadline, &mut ignore)
        .await;
    let msg = r.unwrap_err().to_string();
    assert!(msg.contains("os error 65"), "{msg}");
    cap.inject_send_error(None);

    cap.invalidate();
    let r = cap
        .exchange(LanDest::Pxp, &[&req], deadline, &mut ignore)
        .await;
    assert!(matches!(r, Err(CapError::Denied(DenyReason::Invalidated))));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(router.counters().num_total_recv, 0);
    router.shutdown().await;
}

/// Two routers stand in for two gateways that both use port 5351.
#[tokio::test]
async fn two_routers() {
    let a = FakeRouter::start(RouterOptions::default()).await.unwrap();
    let b = FakeRouter::start(RouterOptions {
        public_ip: Ipv4Addr::new(198, 51, 100, 9),
        ..RouterOptions::default()
    })
    .await
    .unwrap();
    let p = PolicyHandle::new(true);
    let mut gb = gateway(Ipv4Addr::LOCALHOST);
    gb.gw = Ipv4Addr::new(10, 0, 0, 1);
    let ca = TestCap::new(gateway(Ipv4Addr::LOCALHOST), &a, p.clone());
    let cb = TestCap::new(gb, &b, p);
    let (r, _) = collect(&cb, &[&pmp::public_address_request()], 1, WAIT).await;
    assert_eq!(
        pmp::parse_public_addr_reply(&r[0]).unwrap().public_ip,
        Ipv4Addr::new(198, 51, 100, 9)
    );
    collect(&ca, &[&pmp::public_address_request()], 1, WAIT).await;
    assert_eq!(a.counters().num_pmp_recv, 1);
    assert_eq!(b.counters().num_pmp_recv, 1);
    a.shutdown().await;
    b.shutdown().await;
}

/// Shutdown also ends replies that are still paused at a barrier or delayed.
#[tokio::test]
async fn shutdown_aborts_paused_replies() {
    let (router, cap, _) = setup(RouterOptions::default()).await;
    let b = router.barrier(RequestKind::PmpPublicAddr);
    router.set_delay(Duration::from_secs(30));
    let cap2 = cap.clone();
    let pending = tokio::spawn(async move {
        collect(
            &cap2,
            &[&pmp::public_address_request()],
            1,
            Duration::from_millis(500),
        )
        .await
        .0
    });
    b.reached().await;
    let start = std::time::Instant::now();
    router.shutdown().await;
    assert!(start.elapsed() < Duration::from_secs(2));
    // The barrier is never released and the reply never sent.
    assert!(pending.await.unwrap().is_empty());
    drop(b);
}

/// After `shutdown().await` the router is gone.
#[tokio::test]
async fn shutdown_stops_the_router() {
    let (router, cap, _) = setup(RouterOptions::default()).await;
    let counters = router.counters();
    router.shutdown().await;
    let (r, _) = collect(
        &cap,
        &[&pmp::public_address_request()],
        1,
        Duration::from_millis(100),
    )
    .await;
    assert!(r.is_empty());
    assert_eq!(counters.num_total_recv, 0);
}

/// Linux has the whole 127/8 on loopback, so a router can bind a second loopback address for
/// real.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn router_on_another_loopback_address() {
    let opts = RouterOptions {
        bind_ip: Ipv4Addr::new(127, 0, 0, 2),
        ..RouterOptions::default()
    };
    let (router, cap, _) = setup(opts).await;
    let (r, _) = collect(&cap, &[&pmp::public_address_request()], 1, WAIT).await;
    assert!(pmp::parse_public_addr_reply(&r[0]).is_ok());
    router.shutdown().await;
}
