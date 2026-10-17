//! Lifecycle client tests: every case runs against the fake router on loopback through
//! [`TestCap`], with a manual clock for the lease arithmetic. Nothing here reaches a real gateway.

use std::{
    net::{Ipv4Addr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use super::*;
use crate::{
    oneshot::ProtoSet,
    test_time::{FrozenTime, finish_at_deadline},
    testing::{
        AssignPort, Corruption, FakeRouter, LeaseClock, ManualClock, RequestKind, ResultOverride,
        RouterOptions, ScriptedLookup, TestCap, TestCaps,
    },
};

/// The OS error a bind to a vanished local address returns.
#[cfg(unix)]
const ADDR_NOT_AVAILABLE: i32 = libc::EADDRNOTAVAIL;
#[cfg(windows)]
const ADDR_NOT_AVAILABLE: i32 = 10049; // WSAEADDRNOTAVAIL

const GW1: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
const GW2: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const PORT: u16 = 41641;

fn gateway(gw: Ipv4Addr) -> Gateway {
    Gateway {
        gw,
        // Source-consistent loopback mode: the PCP client IP is the real source address.
        self_ip: Ipv4Addr::LOCALHOST,
        prefix_len: 24,
        if_index: 4,
        if_name: "en0".to_owned(),
    }
}

struct Rig {
    router: FakeRouter,
    caps: Arc<TestCaps>,
    lookup: Arc<ScriptedLookup>,
    clock: Arc<ManualClock>,
    lease_clock: LeaseClock,
    client: Client<TestCap>,
    rx: watch::Receiver<PortmapState>,
}

struct Opts {
    router: RouterOptions,
    protos: ProtoSet,
    advertise_nonpublic: bool,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            router: RouterOptions {
                enforce_pcp_client_ip: true,
                ..RouterOptions::default()
            },
            protos: ProtoSet::BOTH,
            advertise_nonpublic: true,
        }
    }
}

async fn rig_with(o: Opts) -> Rig {
    let lease_clock = o.router.clock.clone();
    let router = FakeRouter::start(o.router).await.unwrap();
    let caps = TestCaps::new();
    caps.add(GW1, router.endpoint());
    let lookup = ScriptedLookup::new(gateway(GW1));
    let clock = ManualClock::new();
    let (client, rx) = Client::new(Config {
        lookup: lookup.clone(),
        caps: caps.clone(),
        clock: clock.clone(),
        protos: o.protos,
        advertise_nonpublic_external: o.advertise_nonpublic,
        lifetime: requested_lifetime(),
    });
    Rig {
        router,
        caps,
        lookup,
        clock,
        lease_clock,
        client,
        rx,
    }
}

/// Observe the lifecycle transition instead of guessing when a spawned close was polled.
async fn wait_for_close(client: &Client<TestCap>) {
    tokio::time::timeout(secs(2), async {
        while client.state().phase == Phase::Running {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("close did not start");
}

async fn rig() -> Rig {
    rig_with(Opts::default()).await
}

impl Rig {
    /// Advance the client's clock and the router's lease clock together.
    fn advance(&self, d: Duration) {
        self.clock.advance(d);
        self.lease_clock.advance(d.as_secs());
    }

    /// Wait until no attempt or cleanup is in flight.
    async fn settle(&self) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            assert_owned_invariant(&self.client);
            if !self.client.attempt_in_flight() && self.client.reap() == 0 {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "client did not settle"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Set the port, run one tick and wait for the attempt.
    async fn map(&self) -> Option<SocketAddrV4> {
        self.client.set_local_port(PORT).ok();
        assert_owned_invariant(&self.client);
        self.client.tick().await;
        assert_owned_invariant(&self.client);
        self.settle().await;
        self.client.subscribe().borrow().mapping.map(|m| m.external)
    }

    fn state(&self) -> PortmapState {
        self.client.subscribe().borrow().clone()
    }

    fn maps(&self) -> u64 {
        let c = self.router.counters();
        c.num_pmp_map_recv + c.num_pcp_map_recv
    }

    fn creates_and_renewals(&self) -> Vec<(Option<u16>, Option<u16>, Option<u32>)> {
        self.router
            .requests()
            .into_iter()
            .filter(|r| {
                matches!(r.kind, RequestKind::PmpMap | RequestKind::PcpMap)
                    && r.lifetime.is_some_and(|n| n > 0)
            })
            .map(|r| (r.internal, r.suggested_external, r.lifetime))
            .collect()
    }

    async fn shutdown(self) {
        self.client.close(Duration::from_millis(500)).await;
        self.router.shutdown().await;
    }
}

const fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

// ---------------------------------------------------------------------------------------------
// Protocol selection, caching, renewal, expiry

/// Protocol selection parity (`preferPCP`) over which services were seen and which
/// protocols are allowed; nothing seen → `NoServices` and backoff, with no MAP sent.
#[tokio::test]
async fn protocol_selection_matrix() {
    for (pmp_on, pcp_on, protos, want) in [
        (true, true, ProtoSet::BOTH, Some(Proto::Pmp)),
        (true, false, ProtoSet::BOTH, Some(Proto::Pmp)),
        (false, true, ProtoSet::BOTH, Some(Proto::Pcp)),
        (
            true,
            true,
            ProtoSet {
                pmp: false,
                pcp: true,
            },
            Some(Proto::Pcp),
        ),
        (
            true,
            true,
            ProtoSet {
                pmp: true,
                pcp: false,
            },
            Some(Proto::Pmp),
        ),
        (false, false, ProtoSet::BOTH, None),
    ] {
        let r = rig_with(Opts {
            router: RouterOptions {
                pmp: pmp_on,
                pcp: pcp_on,
                ..RouterOptions::default()
            },
            protos,
            ..Opts::default()
        })
        .await;
        let got = r.map().await;
        let st = r.state();
        assert_eq!(
            st.mapping.map(|m| m.proto),
            want,
            "{pmp_on} {pcp_on} {protos:?}"
        );
        if want.is_none() {
            assert!(got.is_none());
            assert_eq!(r.maps(), 0, "no MAP without a service");
            let s = r.client.schedule();
            assert!(s.next_attempt.unwrap() > r.clock.now() + secs(5), "backoff");
        }
        r.shutdown().await;
    }
}

/// A call before `renew_after` sends nothing; no probe traffic within 10 min
/// of "seen"; probe traffic again after the cache expires and after an invalidation.
#[tokio::test]
async fn caches_respect_renewal_and_probe_windows() {
    let r = rig().await;
    assert!(r.map().await.is_some());
    let c0 = r.router.counters();
    assert_eq!((c0.num_pmp_public_addr_recv, c0.num_pcp_disco_recv), (2, 1));
    for _ in 0..20 {
        r.advance(secs(10));
        r.client.tick().await;
        r.settle().await;
    }
    let c = r.router.counters();
    assert_eq!(
        c.num_pmp_map_recv, c0.num_pmp_map_recv,
        "no renewal before renew_after"
    );
    assert_eq!(c.num_pcp_disco_recv, 1, "probe cached");
    assert_eq!(c.num_pmp_public_addr_recv, c0.num_pmp_public_addr_recv);
    // Past the 10-minute cache: probed again.
    r.advance(secs(11 * 60));
    r.client.tick().await;
    r.settle().await;
    assert_eq!(r.router.counters().num_pcp_disco_recv, 2);
    // An invalidation clears the cache.
    r.client.note_network_down();
    r.client.check_network().await;
    r.client.tick().await;
    r.settle().await;
    assert_eq!(r.router.counters().num_pcp_disco_recv, 3);
    r.shutdown().await;
}

/// Renewal past `trusted / 2` suggests the previous external port; a router-assigned new
/// port updates the published state; external ≠ internal flows through to the delete.
#[tokio::test]
async fn renewal_suggests_previous_port_and_publishes_changes() {
    let r = rig().await;
    r.router.set_assign_port(AssignPort::InternalPlus(1000));
    let ext = r.map().await.unwrap();
    assert_eq!(
        ext,
        SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), PORT + 1000)
    );
    let st = r.state();
    assert!(st.advertise);
    assert_eq!(st.advertised().unwrap().external, ext);

    r.advance(secs(3601));
    let mut rx = r.client.subscribe();
    rx.borrow_and_update();
    assert_eq!(
        r.client.get_cached_mapping_or_start_creating_one(),
        Some(ext)
    );
    r.settle().await;
    let last = *r.creates_and_renewals().last().unwrap();
    assert_eq!(last, (Some(PORT), Some(PORT + 1000), Some(7200)));
    assert_eq!(
        r.state().mapping.unwrap().external,
        ext,
        "unchanged external"
    );

    // The router moves the mapping on the next renewal: the change is published.
    r.router.set_public_ip(Ipv4Addr::new(198, 51, 100, 9));
    r.advance(secs(3601));
    r.client.get_cached_mapping_or_start_creating_one();
    r.settle().await;
    assert!(rx.has_changed().unwrap());
    assert_eq!(
        r.state().mapping.unwrap().external,
        SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 9), PORT + 1000)
    );

    // The delete carries the internal port, not the external one, and suggested port 0.
    r.client.close(secs(1)).await;
    let del = r.router.requests().last().cloned().unwrap();
    assert_eq!(
        (del.internal, del.suggested_external, del.lifetime),
        (Some(PORT), Some(0), Some(0))
    );
    assert!(r.router.mappings().is_empty());
    r.router.shutdown().await;
}

/// PCP renewals and the delete reuse the creating nonce.
#[tokio::test]
async fn pcp_renewal_and_delete_reuse_the_nonce() {
    let r = rig_with(Opts {
        router: RouterOptions {
            pmp: false,
            enforce_pcp_client_ip: true,
            ..RouterOptions::default()
        },
        ..Opts::default()
    })
    .await;
    r.map().await.unwrap();
    let nonce = r.router.requests().last().unwrap().nonce.unwrap();
    r.advance(secs(3601));
    r.client.get_cached_mapping_or_start_creating_one();
    r.settle().await;
    let renew = r.router.requests().last().cloned().unwrap();
    assert_eq!(renew.nonce, Some(nonce));
    assert_eq!(renew.suggested_external, Some(4242));
    r.client.close(secs(1)).await;
    let del = r.router.requests().last().cloned().unwrap();
    assert_eq!((del.nonce, del.lifetime), (Some(nonce), Some(0)));
    // Every PCP packet carried self_ip as the client IP, from self_ip.
    for q in r.router.requests() {
        if q.version == 2 {
            assert_eq!(q.pcp_client_ip, Some(Ipv4Addr::LOCALHOST));
            assert_eq!(q.src.ip(), std::net::IpAddr::from(Ipv4Addr::LOCALHOST));
        }
    }
    assert!(r.router.mappings().is_empty());
    r.router.shutdown().await;
}

/// Past `expires_at` the mapping is withdrawn with no tick and no peer activity;
/// the next call starts a create.
#[tokio::test]
async fn expiry_is_independent_of_activity() {
    let r = rig().await;
    r.router.set_lifetime_override(Some(60));
    r.map().await.unwrap();
    let mut rx = r.client.subscribe();
    rx.borrow_and_update();
    let s = r.client.schedule();
    assert_eq!(s.expires_at, Some(r.state().mapping.unwrap().expires_at));
    r.advance(secs(59));
    assert!(!r.client.expire_if_due());
    assert!(r.client.have_mapping());
    r.advance(secs(2));
    assert!(!r.client.have_mapping());
    assert!(r.client.expire_if_due());
    assert!(rx.has_changed().unwrap());
    assert!(r.state().mapping.is_none());
    // Nothing to release: the router's grant ended too.
    assert_eq!(r.client.owned_rules(), 0);
    let before = r.maps();
    assert!(
        r.client
            .get_cached_mapping_or_start_creating_one()
            .is_none()
    );
    r.settle().await;
    assert_eq!(r.maps(), before + 1, "a new create");
    r.shutdown().await;
}

/// The granted lifetime may differ from the request; the schedule trusts at most 2 h and the
/// ledger records the router's real bound.
#[tokio::test]
async fn granted_lifetimes_shape_the_schedule() {
    for (granted, trusted) in [(600u32, 600u64), (86_400, 7200)] {
        let r = rig().await;
        r.router.set_lifetime_override(Some(granted));
        r.map().await.unwrap();
        let now = r.clock.now();
        let s = r.client.schedule();
        let exp = s.expires_at.unwrap();
        assert!(exp > now + secs(trusted - 2) && exp <= now + secs(trusted));
        let renew = s.renewal_due.unwrap();
        assert!(renew <= now + secs(trusted / 2));
        let owned = r.client.owned_snapshot();
        let router_expiry = owned[0].router_expiry();
        assert!(router_expiry > now + secs(u64::from(granted) - 2));
        r.shutdown().await;
    }
}

// ---------------------------------------------------------------------------------------------
// Single-flight, races, stale commits

/// 50 concurrent calls start exactly one MAP; single-flight resets after success, error,
/// a panic in the attempt and an abort; the task set is reaped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_flight() {
    let r = rig().await;
    r.client.set_local_port(PORT).unwrap();
    r.client.check_network().await;
    r.client.probe().await.unwrap();
    let barrier = r.router.barrier(RequestKind::PmpMap);
    let mut joins = Vec::new();
    for _ in 0..50 {
        let c = r.client.clone();
        joins.push(tokio::spawn(async move {
            c.get_cached_mapping_or_start_creating_one()
        }));
    }
    for j in joins {
        j.await.unwrap();
    }
    barrier.reached().await;
    assert!(r.client.attempt_in_flight());
    barrier.release();
    r.settle().await;
    assert_eq!(r.router.counters().num_pmp_map_recv, 1);
    assert!(r.client.have_mapping());

    // Error: the router refuses the renewal; single-flight resets.
    r.router.set_result(
        RequestKind::PmpMap,
        Some(ResultOverride {
            code: 3,
            lifetime: 0,
        }),
    );
    r.advance(secs(3601));
    r.client.get_cached_mapping_or_start_creating_one();
    r.settle().await;
    assert!(!r.client.attempt_in_flight());
    r.router.set_result(RequestKind::PmpMap, None);

    // Panic inside the attempt future.
    r.advance(secs(601));
    for cap in r.caps.built() {
        cap.panic_next_exchange();
    }
    r.client.get_cached_mapping_or_start_creating_one();
    r.settle().await;
    assert!(!r.client.attempt_in_flight());

    // Abort: an invalidation while the attempt waits on the router.
    r.advance(secs(601));
    let barrier = r.router.barrier(RequestKind::PmpMap);
    r.client.get_cached_mapping_or_start_creating_one();
    barrier.reached().await;
    r.client.note_network_down();
    assert!(!r.client.attempt_in_flight());
    barrier.release();
    r.settle().await;
    assert_eq!(r.client.reap(), 0);
    r.shutdown().await;
}

/// A success that lands after a local-port change, a network change, a disable or a close is
/// rejected: nothing stale is installed, the rule is orphaned and deleted, the newer state wins.
#[tokio::test]
async fn stale_commits_are_rejected_and_cleaned_up() {
    for case in ["port", "network", "disable", "close"] {
        let r = rig().await;
        let caps2_router = FakeRouter::start(RouterOptions::default()).await.unwrap();
        r.caps.add(GW2, caps2_router.endpoint());
        r.client.set_local_port(PORT).unwrap();
        r.client.check_network().await;
        r.client.probe().await.unwrap();
        let barrier = r.router.barrier(RequestKind::PmpMap);
        r.client.get_cached_mapping_or_start_creating_one();
        barrier.reached().await;
        assert_eq!(
            r.router.mappings().len(),
            1,
            "{case}: committed at the router"
        );
        match case {
            "port" => r.client.set_local_port(PORT + 1).unwrap(),
            "network" => {
                r.lookup.set(gateway(GW2));
                assert_eq!(r.client.check_network().await, NetCheck::Changed);
            }
            "disable" => r.client.disable(DisableReason::OnlyTcp443),
            _ => {}
        }
        if case == "close" {
            let c = r.client.clone();
            let close = tokio::spawn(async move { c.close(secs(2)).await });
            wait_for_close(&r.client).await;
            barrier.release();
            close.await.unwrap();
        } else {
            barrier.release();
        }
        r.settle().await;
        let st = r.state();
        assert!(st.mapping.is_none(), "{case}: stale mapping installed");
        match case {
            "disable" => {
                // No delete while disabled: the rule waits in the ledger.
                assert_eq!(r.router.mappings().len(), 1);
                assert_eq!(r.client.owned_rules(), 1);
                r.client.enable();
                r.client.cleanup().await;
                assert!(r.router.mappings().is_empty(), "deleted once re-enabled");
            }
            _ => assert!(
                r.router.mappings().iter().all(|m| m.internal != PORT),
                "{case}: the stale rule was deleted"
            ),
        }
        if case == "port" {
            r.advance(secs(2));
            r.client.tick().await;
            r.settle().await;
            assert_eq!(r.state().mapping.unwrap().proto, Proto::Pmp);
            assert_eq!(
                r.router.mappings()[0].internal,
                PORT + 1,
                "newer state wins"
            );
        }
        caps2_router.shutdown().await;
        r.shutdown().await;
    }
}

/// A router that commits but whose reply is lost, and an attempt aborted after the router
/// committed: the ledger holds the rule and cleanup or close deletes it.
#[tokio::test]
async fn rules_committed_without_a_reply_are_deleted() {
    for proto_pcp in [false, true] {
        let r = rig_with(Opts {
            router: RouterOptions {
                pmp: !proto_pcp,
                ..RouterOptions::default()
            },
            ..Opts::default()
        })
        .await;
        let kind = if proto_pcp {
            RequestKind::PcpMap
        } else {
            RequestKind::PmpMap
        };
        r.router.knobs_for(Some(kind));
        r.router.commit_then_drop_next(1);
        assert!(r.map().await.is_none());
        assert_eq!(
            r.router.mappings().len(),
            0,
            "cleanup ran after the lost reply"
        );
        assert_eq!(r.client.owned_rules(), 0);

        // Abort after send: committed, then invalidated before the reply.
        r.advance(secs(60));
        let barrier = r.router.barrier(kind);
        r.client.get_cached_mapping_or_start_creating_one();
        barrier.reached().await;
        r.client.set_local_port(PORT + 7).unwrap();
        barrier.release();
        r.settle().await;
        assert!(r.router.mappings().iter().all(|m| m.internal != PORT));
        r.shutdown().await;
    }
}

// ---------------------------------------------------------------------------------------------
// Network changes, local port, down, rebind

/// A new gateway releases the old rule to the old router only and maps through
/// the new one; when the old network no longer validates, no delete is sent anywhere.
#[tokio::test]
async fn network_change_releases_only_to_a_validating_old_network() {
    for old_validates in [true, false] {
        let r = rig().await;
        let router2 = FakeRouter::start(RouterOptions::default()).await.unwrap();
        r.caps.add(GW2, router2.endpoint());
        r.map().await.unwrap();
        assert_eq!(r.router.mappings().len(), 1);
        r.caps.set_present(GW1, old_validates);
        r.lookup.set(gateway(GW2));
        assert_eq!(r.client.check_network().await, NetCheck::Changed);
        assert!(r.state().mapping.is_none());
        r.settle().await;
        r.advance(secs(2));
        r.client.tick().await;
        r.settle().await;
        assert_eq!(
            r.router.counters().num_deletes,
            u64::from(old_validates),
            "old_validates={old_validates}"
        );
        assert_eq!(r.router.mappings().len(), usize::from(!old_validates));
        assert_eq!(
            router2.counters().num_deletes,
            0,
            "nothing for the old rule"
        );
        assert_eq!(
            router2.mappings().len(),
            1,
            "new mapping via the new router"
        );
        assert!(r.state().mapping.is_some());
        assert_eq!(r.client.owned_rules(), if old_validates { 1 } else { 2 });
        router2.shutdown().await;
        r.shutdown().await;
    }
}

/// No default route, a lookup error, or network-down invalidates without
/// any release.
#[tokio::test]
async fn down_invalidates_without_release() {
    for how in ["no-route", "error", "down"] {
        let r = rig().await;
        r.map().await.unwrap();
        match how {
            "no-route" => {
                r.lookup.set_no_route();
                assert_eq!(r.client.check_network().await, NetCheck::Down);
            }
            "error" => {
                r.lookup.set_error();
                assert_eq!(r.client.check_network().await, NetCheck::Down);
            }
            _ => r.client.note_network_down(),
        }
        r.settle().await;
        r.client.cleanup().await;
        assert!(r.state().mapping.is_none(), "{how}");
        assert_eq!(r.router.counters().num_deletes, 0, "{how}: no release");
        // Kept (never deleted) only so a create on the same network can adopt it.
        assert!(
            r.client.owned_snapshot().iter().all(|e| !e.releasable()),
            "{how}"
        );
        assert!(!r.client.has_network());
        r.client.close(secs(1)).await;
        assert_eq!(
            r.router.counters().num_deletes,
            0,
            "{how}: not even on close"
        );
        r.router.shutdown().await;
    }
}

/// The same port is a no-op; a new port releases the old rule and maps the new one; port
/// 0 is refused, invalidates, and no MAP ever carries internal port 0.
#[tokio::test]
async fn local_port_changes() {
    let r = rig().await;
    r.map().await.unwrap();
    let before = r.router.requests().len();
    r.client.set_local_port(PORT).unwrap();
    r.settle().await;
    assert_eq!(r.router.requests().len(), before, "same port: no I/O");
    assert!(r.client.have_mapping());

    r.client.set_local_port(PORT + 1).unwrap();
    assert!(r.state().mapping.is_none(), "invalidated synchronously");
    r.settle().await;
    // The 2 s floor between attempt starts holds across invalidations.
    assert!(r.client.tick().await.is_none());
    let retry = r.client.schedule().retry_at.unwrap();
    assert!(!r.client.schedule().backing_off);
    assert!(retry <= r.clock.now() + secs(2));
    r.advance(secs(2));
    r.client.tick().await;
    r.settle().await;
    let table: Vec<u16> = r.router.mappings().iter().map(|m| m.internal).collect();
    assert_eq!(table, [PORT + 1]);

    assert!(matches!(
        r.client.set_local_port(0),
        Err(Error::LocalPortZero)
    ));
    assert!(r.state().mapping.is_none());
    r.settle().await;
    for _ in 0..3 {
        r.advance(secs(700));
        r.client.tick().await;
        r.settle().await;
    }
    assert!(r.state().mapping.is_none());
    for (internal, _, _) in r.creates_and_renewals() {
        assert_ne!(internal, Some(0), "a MAP with internal port 0");
    }
    assert!(r.router.mappings().is_empty(), "the old rule was released");
    r.shutdown().await;
}

/// Client half of the rebind behaviour: a rebind on the same port and network restores the mapping with no I/O;
/// a rebind to a new port invalidates, releases and maps again; a failed rebind invalidates.
#[tokio::test]
async fn rebind_keeps_or_replaces_the_mapping() {
    let r = rig().await;
    let ext = r.map().await.unwrap();
    let mut rx = r.client.subscribe();
    rx.borrow_and_update();
    let before = r.router.requests().len();
    r.client.note_rebind(Some(PORT));
    assert!(
        r.state().mapping.is_none(),
        "withdrawn before OS validation"
    );
    r.client.check_network().await;
    assert!(rx.has_changed().unwrap(), "re-published for the magicsock");
    assert_eq!(r.state().mapping.unwrap().external, ext);
    r.settle().await;
    assert_eq!(r.router.requests().len(), before, "no I/O");

    r.client.note_rebind(Some(PORT + 2));
    assert!(r.state().mapping.is_none());
    r.settle().await;
    r.advance(secs(2));
    let before = r.creates_and_renewals().len();
    r.client.get_cached_mapping_or_start_creating_one();
    r.settle().await;
    assert_eq!(
        r.creates_and_renewals().len(),
        before,
        "changed-port rebind requires fresh network validation"
    );
    r.client.tick().await;
    r.settle().await;
    let table: Vec<u16> = r.router.mappings().iter().map(|m| m.internal).collect();
    assert_eq!(table, [PORT + 2]);

    r.client.note_rebind(None);
    assert!(r.state().mapping.is_none());
    r.settle().await;
    assert!(r.router.mappings().is_empty(), "released: the port is gone");
    r.shutdown().await;
}

// ---------------------------------------------------------------------------------------------
// Close and the Drop path

/// Close deletes (PMP: internal port, external 0; PCP: lifetime 0 and the nonce), is
/// idempotent, stops new work before awaiting, and finishes within its budget with the router
/// gone.
#[tokio::test]
async fn close_releases_within_budget() {
    let r = rig().await;
    r.map().await.unwrap();
    r.client.close(secs(1)).await;
    assert!(r.router.mappings().is_empty());
    let deletes = r.router.counters().num_deletes;
    assert_eq!(deletes, 1);
    r.client.close(secs(1)).await;
    r.client.release_blocking_best_effort();
    assert_eq!(r.router.counters().num_deletes, deletes, "idempotent");
    assert!(r.client.tick().await.is_none());
    assert!(
        r.client
            .get_cached_mapping_or_start_creating_one()
            .is_none()
    );
    assert_eq!(r.router.counters().num_deletes, deletes);
    r.router.shutdown().await;

    // Router gone: close still ends within its budget.
    let r = rig().await;
    r.map().await.unwrap();
    r.router.drop_next(1000);
    let t = std::time::Instant::now();
    r.client.close(Duration::from_millis(300)).await;
    assert!(
        t.elapsed() < Duration::from_millis(600),
        "{:?}",
        t.elapsed()
    );
    r.router.shutdown().await;

    // Close while an attempt waits on the router: no new work starts after it began.
    let r = rig().await;
    r.client.set_local_port(PORT).unwrap();
    r.client.check_network().await;
    r.client.probe().await.unwrap();
    let barrier = r.router.barrier(RequestKind::PmpMap);
    r.client.get_cached_mapping_or_start_creating_one();
    barrier.reached().await;
    let c = r.client.clone();
    let close = tokio::spawn(async move { c.close(secs(2)).await });
    wait_for_close(&r.client).await;
    let maps = r.creates_and_renewals().len();
    assert!(
        r.client
            .get_cached_mapping_or_start_creating_one()
            .is_none()
    );
    barrier.release();
    close.await.unwrap();
    assert_eq!(
        r.creates_and_renewals().len(),
        maps,
        "nothing started after close began"
    );
    assert!(
        r.router.mappings().is_empty(),
        "the in-flight rule was deleted"
    );
    r.router.shutdown().await;
}

/// The Drop-path release sends the deletes without a tokio runtime and without waiting
/// for replies; it does nothing after close.
#[tokio::test]
async fn drop_path_release_needs_no_runtime() {
    for pcp in [false, true] {
        let r = rig_with(Opts {
            router: RouterOptions {
                pmp: !pcp,
                ..RouterOptions::default()
            },
            ..Opts::default()
        })
        .await;
        r.map().await.unwrap();
        let c = r.client.clone();
        std::thread::spawn(move || {
            assert!(tokio::runtime::Handle::try_current().is_err());
            c.release_blocking_best_effort();
        })
        .join()
        .unwrap();
        let deadline = std::time::Instant::now() + secs(2);
        while !r.router.mappings().is_empty() {
            assert!(std::time::Instant::now() < deadline, "delete not received");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let del = r.router.requests().last().cloned().unwrap();
        assert_eq!(del.lifetime, Some(0));
        r.client.close(secs(1)).await;
        assert_eq!(
            r.router.counters().num_deletes,
            1,
            "nothing after the Drop path"
        );
        r.router.shutdown().await;
    }
}

// ---------------------------------------------------------------------------------------------
// Router errors, hostile replies, backoff

/// Router refusals map to no mapping and backoff; NOT_AUTHORIZED holds ≥ 30 min; a PCP
/// error lifetime is honoured; ANNOUNCE refusals report `pcp = false`.
#[tokio::test]
async fn router_errors_back_off() {
    for code in 1..=5u16 {
        let r = rig().await;
        r.router.set_result(
            RequestKind::PmpMap,
            Some(ResultOverride { code, lifetime: 0 }),
        );
        assert!(r.map().await.is_none());
        assert_eq!(r.client.owned_rules(), 0, "a refused create left nothing");
        let wait = r.client.schedule().next_attempt.unwrap() - r.clock.now();
        if code == 2 {
            assert!(wait >= secs(30 * 60) - secs(1), "{code}: {wait:?}");
        } else {
            assert!(wait >= secs(7) && wait <= secs(13), "{code}: {wait:?}");
        }
        // No hot loop: many ticks inside the backoff send nothing.
        for _ in 0..50 {
            r.client.tick().await;
        }
        r.settle().await;
        assert_eq!(r.router.counters().num_pmp_map_recv, 1);
        r.shutdown().await;
    }

    // PCP MAP refusal with an error lifetime: the next attempt honours it.
    let r = rig_with(Opts {
        router: RouterOptions {
            pmp: false,
            ..RouterOptions::default()
        },
        ..Opts::default()
    })
    .await;
    r.router.set_result(
        RequestKind::PcpMap,
        Some(ResultOverride {
            code: 8,
            lifetime: 600,
        }),
    );
    assert!(r.map().await.is_none());
    let wait = r.client.schedule().next_attempt.unwrap() - r.clock.now();
    assert!(wait >= secs(598), "{wait:?}");
    r.router.set_result(
        RequestKind::PcpMap,
        Some(ResultOverride {
            code: 2,
            lifetime: 5,
        }),
    );
    r.advance(secs(601));
    r.client.tick().await;
    r.settle().await;
    let wait = r.client.schedule().next_attempt.unwrap() - r.clock.now();
    assert!(wait >= secs(30 * 60) - secs(1), "NOT_AUTHORIZED: {wait:?}");
    r.shutdown().await;

    // ANNOUNCE refused: PCP present but unusable.
    for code in [2u16, 12] {
        let r = rig().await;
        r.router.set_result(
            RequestKind::PcpAnnounce,
            Some(ResultOverride { code, lifetime: 0 }),
        );
        r.client.check_network().await;
        let f = r.client.probe().await.unwrap();
        assert_eq!((f.pmp, f.pcp, f.upnp), (Some(true), Some(false), None));
        r.shutdown().await;
    }
}

/// Hostile replies in create, renew and delete never install or roll back
/// state; a failed renewal keeps the mapping until it expires.
#[tokio::test]
async fn hostile_replies_through_the_lifecycle() {
    let corruptions = [
        Corruption::Truncate,
        Corruption::BadVersion,
        Corruption::WrongOpcode,
        Corruption::NoRBit,
        Corruption::WrongNonce,
        Corruption::WrongProto,
        Corruption::WrongInternalPort,
        Corruption::Garbage,
        Corruption::Oversize,
    ];
    for pcp in [false, true] {
        let kind = if pcp {
            RequestKind::PcpMap
        } else {
            RequestKind::PmpMap
        };
        for c in corruptions {
            if !pcp && matches!(c, Corruption::WrongNonce | Corruption::WrongProto) {
                // NAT-PMP replies have no nonce or protocol field.
                continue;
            }
            let r = rig_with(Opts {
                router: RouterOptions {
                    pmp: !pcp,
                    ..RouterOptions::default()
                },
                ..Opts::default()
            })
            .await;
            // Create.
            r.router.knobs_for(Some(kind));
            r.router.corrupt_next(c);
            assert!(r.map().await.is_none(), "{pcp} {c:?}: create");
            // The rule may exist: the ledger deleted it.
            assert!(r.router.mappings().is_empty(), "{pcp} {c:?}");
            // A good create, then a corrupted renewal: the mapping stays.
            r.advance(secs(700));
            let ext = r.map().await.unwrap();
            r.advance(secs(3601));
            r.router.corrupt_next(c);
            r.client.get_cached_mapping_or_start_creating_one();
            r.settle().await;
            assert_eq!(
                r.state().mapping.unwrap().external,
                ext,
                "{pcp} {c:?}: renew"
            );
            assert!(r.client.have_mapping());
            // A corrupted delete acknowledgement: retried by close.
            r.router.corrupt_next(c);
            r.client.close(secs(2)).await;
            assert!(r.router.mappings().is_empty(), "{pcp} {c:?}: delete");
            r.router.shutdown().await;
        }
    }

    // Short (header-only) PCP errors and wrong-port replies: no mapping.
    let r = rig_with(Opts {
        router: RouterOptions {
            pmp: false,
            short_pcp_errors: true,
            ..RouterOptions::default()
        },
        ..Opts::default()
    })
    .await;
    r.router.set_result(
        RequestKind::PcpMap,
        Some(ResultOverride {
            code: 8,
            lifetime: 60,
        }),
    );
    assert!(r.map().await.is_none());
    r.router.set_result(RequestKind::PcpMap, None);
    r.router.knobs_for(Some(RequestKind::PcpMap));
    // Every reply (the leftover's delete too) comes from the wrong port.
    r.router.reply_from_wrong_port_next(10);
    r.advance(secs(1800));
    r.client.tick().await;
    r.settle().await;
    assert!(r.state().mapping.is_none());
    r.shutdown().await;
}

/// A duplicate of an earlier success arriving after a renewal does not roll state back.
#[tokio::test]
async fn duplicate_success_after_renewal_does_not_roll_back() {
    let r = rig().await;
    r.router.set_assign_port(AssignPort::Fixed(5000));
    r.router.knobs_for(Some(RequestKind::PmpMap));
    r.router.duplicate_next(1);
    let first = r.map().await.unwrap();
    assert_eq!(first.port(), 5000);
    r.advance(secs(3601));
    r.router.set_public_ip(Ipv4Addr::new(198, 51, 100, 9));
    r.client.get_cached_mapping_or_start_creating_one();
    r.settle().await;
    let renewed = r.state().mapping.unwrap();
    assert_eq!(*renewed.external.ip(), Ipv4Addr::new(198, 51, 100, 9));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(r.state().mapping.unwrap(), renewed);
    r.shutdown().await;
}

/// A failed renewal with a past `renew_after` is spaced by backoff: count MAPs over ten
/// simulated minutes of repeated kicks.
#[tokio::test]
async fn failed_renewal_never_storms() {
    let r = rig().await;
    r.router.set_lifetime_override(Some(7200));
    let ext = r.map().await.unwrap();
    r.advance(secs(3601));
    r.router.set_pmp(false);
    r.router.set_pcp(false);
    let maps = r.maps();
    let requests = r.router.counters().num_total_recv;
    for _ in 0..600 {
        r.advance(secs(1));
        r.client.get_cached_mapping_or_start_creating_one();
        r.client.get_cached_mapping_or_start_creating_one();
        r.settle().await;
        assert!(r.client.schedule().renewal_due.unwrap() >= r.clock.now() - secs(1));
    }
    let sent = r.router.counters().num_total_recv - requests;
    assert_eq!(r.maps(), maps, "the router is silent");
    // 10 + 30 + 60 + 120 + 300 s (±20 %) fit in 600 s: at most 6 attempts, 2 datagrams each.
    assert!(sent <= 12, "{sent} datagrams in 10 min");
    assert_eq!(
        r.state().mapping.unwrap().external,
        ext,
        "kept until expiry"
    );
    r.shutdown().await;
}

/// With the router never answering a MAP, outstanding rules never exceed the ledger cap and
/// new attempts are refused while it is full.
#[tokio::test]
async fn ledger_bounds_outstanding_rules() {
    let r = rig().await;
    r.router.knobs_for(Some(RequestKind::PmpMap));
    r.router.commit_then_drop_next(10_000);
    r.client.set_local_port(PORT).unwrap();
    let mut max = 0;
    for i in 0..40u16 {
        // A different port each round, so each create is a new rule.
        r.client.set_local_port(PORT + i).unwrap();
        r.advance(secs(700));
        r.client.tick().await;
        r.settle().await;
        max = max.max(r.client.owned_rules());
        assert!(r.client.owned_rules() <= crate::owned::MAX_OWNED);
    }
    assert!(max >= 1);
    assert!(r.router.mappings().len() <= 40);
    r.shutdown().await;
}

/// A delete is scoped to our internal port: a second client on the same host with another
/// internal port (Go's tailscaled on 41644) keeps its mapping.
#[tokio::test]
async fn delete_is_scoped_to_our_internal_port() {
    let r = rig().await;
    r.map().await.unwrap();
    let lookup = ScriptedLookup::new(gateway(GW1));
    let (other, _rx) = Client::new(Config {
        lookup,
        caps: r.caps.clone(),
        clock: r.clock.clone(),
        protos: ProtoSet::BOTH,
        advertise_nonpublic_external: true,
        lifetime: requested_lifetime(),
    });
    other.set_local_port(41644).unwrap();
    other.tick().await;
    while other.attempt_in_flight() {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(r.router.mappings().len(), 2);
    r.client.close(secs(1)).await;
    let left: Vec<u16> = r.router.mappings().iter().map(|m| m.internal).collect();
    assert_eq!(left, [41644]);
    other.close(secs(1)).await;
    assert!(r.router.mappings().is_empty());
    r.router.shutdown().await;
}

// ---------------------------------------------------------------------------------------------
// Epochs, clocks

/// The probe-only epoch rule, for both protocols.
#[tokio::test]
async fn epoch_rollback_drops_without_release() {
    for pcp in [false, true] {
        let r = rig_with(Opts {
            router: RouterOptions {
                pmp: !pcp,
                ..RouterOptions::default()
            },
            ..Opts::default()
        })
        .await;
        r.router.set_epoch(5000);
        r.map().await.unwrap();
        // 0 is ignored; equal and higher are fine (the cache must expire for a probe to be sent).
        for epoch in [0, 5000, 9000] {
            r.router.set_epoch(epoch);
            r.advance(secs(601));
            r.client.probe().await.unwrap();
            assert!(r.client.have_mapping(), "{pcp} epoch {epoch}");
        }
        // Reboot: the table is cleared, then the epoch restarts small and nonzero.
        r.router.reboot();
        r.advance(secs(601));
        let mut rx = r.client.subscribe();
        rx.borrow_and_update();
        r.client.probe().await.unwrap();
        assert!(!r.client.have_mapping(), "{pcp}: rollback detected");
        assert!(rx.has_changed().unwrap());
        assert_eq!(r.router.counters().num_deletes, 0, "no release");
        assert_eq!(r.client.owned_rules(), 0);
        // The cache was cleared: the next tick probes and maps again.
        r.client.tick().await;
        r.settle().await;
        assert!(r.client.have_mapping());
        r.shutdown().await;
    }
}

/// A stale probe's epoch cannot drop a newer mapping.
#[tokio::test]
async fn stale_probe_cannot_drop_a_newer_mapping() {
    let r = rig().await;
    r.client.set_local_port(PORT).unwrap();
    r.client.check_network().await;
    let frozen = FrozenTime::new();
    let barrier = r.router.barrier(RequestKind::PmpPublicAddr);
    r.router.set_epoch(10);
    let c = r.client.clone();
    let probe = tokio::spawn(async move { c.probe().await });
    barrier.reached().await;
    // Meanwhile the network is re-found (an invalidation) and a mapping made at epoch 9000.
    r.client.note_network_down();
    r.client.check_network().await;
    r.router.set_epoch(9000);
    barrier.release();
    assert!(matches!(probe.await.unwrap(), Err(Error::Stale)));
    drop(frozen);
    r.client.tick().await;
    r.settle().await;
    assert!(r.client.have_mapping());
    r.shutdown().await;
}

/// A wall-clock jump or a resume re-probes and renews; a false positive costs exactly one
/// renewal.
#[tokio::test]
async fn clock_jump_forces_one_renewal() {
    let r = rig().await;
    r.map().await.unwrap();
    assert!(!r.client.check_clock());
    r.advance(secs(10));
    assert!(!r.client.check_clock(), "both clocks moved together");
    let maps = r.creates_and_renewals().len();
    let probes = r.router.counters().num_pcp_disco_recv;
    r.clock.suspend(secs(3 * 3600));
    assert!(r.client.check_clock());
    r.advance(secs(3));
    r.client.tick().await;
    r.settle().await;
    assert_eq!(r.creates_and_renewals().len(), maps + 1, "renewed once");
    assert_eq!(
        r.router.counters().num_pcp_disco_recv,
        probes + 1,
        "re-probed"
    );
    for _ in 0..10 {
        r.advance(secs(5));
        assert!(!r.client.check_clock());
        r.client.tick().await;
        r.settle().await;
    }
    assert_eq!(r.creates_and_renewals().len(), maps + 1, "exactly one");
    r.shutdown().await;
}

// ---------------------------------------------------------------------------------------------
// Policy, disable, notifications

/// The advertising policy, both settings: a private or shared external address is
/// advertised by default (Go); with suppression it is kept, renewed (not recreated) and released
/// on close, but never advertised.
#[tokio::test]
async fn advertising_policy() {
    for ip in [Ipv4Addr::new(10, 1, 2, 3), Ipv4Addr::new(100, 64, 1, 1)] {
        for nonpublic in [true, false] {
            let r = rig_with(Opts {
                router: RouterOptions {
                    public_ip: ip,
                    ..Opts::default().router
                },
                advertise_nonpublic: nonpublic,
                ..Opts::default()
            })
            .await;
            r.map().await.unwrap();
            let st = r.state();
            assert!(st.mapping.is_some());
            assert_eq!(st.advertise, nonpublic, "{ip} {nonpublic}");
            assert_eq!(st.advertised().is_some(), nonpublic);
            for _ in 0..3 {
                r.advance(secs(3601));
                r.client.tick().await;
                r.settle().await;
            }
            let creates = r
                .creates_and_renewals()
                .iter()
                .filter(|(_, suggested, _)| *suggested == Some(0))
                .count();
            assert_eq!(creates, 1, "renewed, not recreated");
            assert_eq!(r.router.mappings().len(), 1);
            r.client.close(secs(1)).await;
            assert!(r.router.mappings().is_empty(), "released on close");
            r.router.shutdown().await;
        }
    }
}

/// Live `only-tcp-443`: it aborts the in-flight attempt, refuses the next send at the
/// cap, withdraws the mapping, sends no delete and reports `Some(false)`; re-enabling on the same
/// network deletes leftovers first.
#[tokio::test]
async fn only_tcp_443_disables_all_lan_io() {
    let r = rig().await;
    r.map().await.unwrap();
    r.advance(secs(3601));
    let frozen = FrozenTime::new();
    let barrier = r.router.barrier(RequestKind::PmpMap);
    r.client.get_cached_mapping_or_start_creating_one();
    barrier.reached().await;
    let mut rx = r.client.subscribe();
    rx.borrow_and_update();
    r.client.disable(DisableReason::OnlyTcp443);
    assert!(!r.client.attempt_in_flight(), "aborted");
    assert!(rx.has_changed().unwrap());
    let st = r.state();
    assert!(st.mapping.is_none());
    assert_eq!((st.facets.pmp, st.facets.pcp), (Some(false), Some(false)));
    barrier.release();
    drop(frozen);
    r.settle().await;
    let total = r.router.counters().num_total_recv;
    for _ in 0..5 {
        r.advance(secs(700));
        r.client.tick().await;
        r.client.cleanup().await;
        r.settle().await;
    }
    r.client.close(secs(1)).await;
    assert_eq!(
        r.router.counters().num_total_recv,
        total,
        "no packet while disabled"
    );
    assert_eq!(r.router.counters().num_deletes, 0);
    // The cap itself refuses: a direct exchange through a built cap is denied by the policy.
    let cap = r.caps.built().pop().unwrap();
    assert!(matches!(
        oneshot::probe(&*cap, ProtoSet::BOTH).await,
        Err(CapError::Denied(crate::DenyReason::Policy))
    ));
    r.router.shutdown().await;

    // Re-enable on the same network: leftovers are deleted before anything else.
    let r = rig().await;
    r.map().await.unwrap();
    r.client.disable(DisableReason::OnlyTcp443);
    assert_eq!(r.router.mappings().len(), 1, "left in place");
    r.client.enable();
    r.advance(secs(2));
    let n = r.router.requests().len();
    r.client.tick().await;
    r.settle().await;
    let after = r.router.requests();
    assert_eq!(after[n].lifetime, Some(0), "the delete went first");
    assert!(r.client.have_mapping());
    r.shutdown().await;
}

/// Like Go's `TestUpdateEvent`, strengthened: state changes are observed for PMP and PCP success,
/// and for loss, expiry and disable.
#[tokio::test]
async fn notifications_for_every_protocol_and_loss() {
    for pcp in [false, true] {
        let r = rig_with(Opts {
            router: RouterOptions {
                pmp: !pcp,
                ..RouterOptions::default()
            },
            ..Opts::default()
        })
        .await;
        let mut rx = r.rx.clone();
        rx.borrow_and_update();
        r.map().await.unwrap();
        assert!(rx.has_changed().unwrap(), "{pcp}: success");
        assert_eq!(
            rx.borrow_and_update().mapping.unwrap().proto,
            if pcp { Proto::Pcp } else { Proto::Pmp }
        );
        r.client.note_network_down();
        assert!(rx.has_changed().unwrap(), "{pcp}: loss");
        assert!(rx.borrow_and_update().mapping.is_none());
        r.router.set_lifetime_override(Some(30));
        r.client.check_network().await;
        r.advance(secs(2));
        let got = r.map().await;
        assert!(
            got.is_some(),
            "{pcp}: {:?} {:?}",
            r.client.schedule(),
            r.router.counters()
        );
        rx.borrow_and_update();
        r.advance(secs(31));
        assert!(r.client.expire_if_due());
        assert!(rx.has_changed().unwrap(), "{pcp}: expiry");
        rx.borrow_and_update();
        r.client.disable(DisableReason::OnlyTcp443);
        assert!(rx.has_changed().unwrap(), "{pcp}: disable");
        r.shutdown().await;
    }
}

/// Lifecycle lines at INFO, one WARN for 100 identical failures, no nonce in any line.
#[tokio::test]
#[tracing_test::traced_test]
async fn logging_is_informative_and_rate_limited() {
    let r = rig_with(Opts {
        router: RouterOptions {
            pmp: false,
            ..RouterOptions::default()
        },
        ..Opts::default()
    })
    .await;
    r.router.set_assign_port(AssignPort::Fixed(6000));
    r.map().await.unwrap();
    let nonce = r.router.requests().last().unwrap().nonce.unwrap();
    r.router.set_assign_port(AssignPort::Fixed(6001));
    // Force a new port at renewal: delete the router's rule first.
    r.router.reboot();
    r.router.set_epoch(u32::MAX);
    r.advance(secs(3601));
    r.client.tick().await;
    r.settle().await;
    r.client.close(secs(1)).await;
    r.router.shutdown().await;
    // Left to expire: a network-down never deletes.
    let r = rig().await;
    r.map().await.unwrap();
    r.client.note_network_down();
    r.shutdown().await;
    logs_assert(|lines: &[&str]| {
        for want in [
            "mapping obtained",
            "renewed with a new external address",
            "mapping lost",
            "router rule released",
            "router rule left to expire",
        ] {
            if !lines
                .iter()
                .any(|l| l.contains(" INFO ") && l.contains(want))
            {
                return Err(format!("no INFO line with {want:?}"));
            }
        }
        Ok(())
    });

    let r = rig().await;
    r.router.set_result(
        RequestKind::PmpMap,
        Some(ResultOverride {
            code: 3,
            lifetime: 0,
        }),
    );
    r.client.set_local_port(PORT).unwrap();
    // A stale retry request never outlives the next attempt request.
    r.client.tick().await;
    r.settle().await;
    r.client.disable(DisableReason::OnlyTcp443);
    r.client.get_cached_mapping_or_start_creating_one();
    assert!(r.client.schedule().retry_at.is_none());
    r.client.enable();
    for _ in 0..100 {
        r.advance(secs(700));
        r.client.tick().await;
        r.settle().await;
    }
    r.client.note_network_down();
    r.shutdown().await;
    logs_assert(|lines: &[&str]| {
        let warns = lines
            .iter()
            .filter(|l| l.contains("WARN") && l.contains("mapping attempt failed"))
            .count();
        if warns != 1 {
            return Err(format!("{warns} warnings for 100 identical failures"));
        }
        let hex: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let dec = format!("{nonce:?}");
        if lines.iter().any(|l| l.contains(&hex) || l.contains(&dec)) {
            return Err("a nonce was logged".to_owned());
        }
        Ok(())
    });
}

/// The `PortMapper` trait object drives the same client (the runtime holds only that).
#[tokio::test]
async fn trait_object_drives_the_client() {
    let r = rig().await;
    let m: Arc<dyn PortMapper> = Arc::new(r.client.clone());
    m.set_local_port(PORT).unwrap();
    assert_eq!(m.check_network().await, NetCheck::Changed);
    m.tick().await;
    r.settle().await;
    assert!(m.subscribe().borrow().mapping.is_some());
    assert!(m.schedule().expires_at.is_some());
    m.close(secs(1)).await;
    assert!(r.router.mappings().is_empty());
    assert!(r.lookup.calls() >= 1);
    r.router.shutdown().await;
}

// ---------------------------------------------------------------------------------------------
// Ownership, cleanup and cancellation regressions

/// A failed create asks the driver for a retry at the backoff (so runner mode retries while
/// idle); the request is withdrawn while no attempt could start (disabled, no local port).
#[tokio::test]
async fn failed_create_asks_for_a_retry() {
    let r = rig_with(Opts {
        router: RouterOptions {
            pcp: false,
            ..RouterOptions::default()
        },
        ..Opts::default()
    })
    .await;
    r.router.set_result(
        RequestKind::PmpMap,
        Some(ResultOverride {
            code: 3,
            lifetime: 0,
        }),
    );
    assert!(r.map().await.is_none());
    let s = r.client.schedule();
    assert!(s.backing_off);
    assert_eq!(s.retry_at, s.next_attempt, "retry at the backoff");
    assert!(s.retry_at.unwrap() > r.clock.now());
    r.client.disable(DisableReason::OnlyTcp443);
    assert_eq!(r.client.schedule().retry_at, None, "nothing can start");
    r.client.enable();
    assert!(r.client.schedule().retry_at.is_some());
    assert!(r.client.set_local_port(0).is_err());
    assert_eq!(r.client.schedule().retry_at, None, "no port to map");

    // No service at all (NoServices) asks for a retry too.
    let r2 = rig_with(Opts {
        router: RouterOptions {
            pmp: false,
            pcp: false,
            ..RouterOptions::default()
        },
        ..Opts::default()
    })
    .await;
    assert!(r2.map().await.is_none());
    assert!(r2.client.schedule().retry_at.is_some());
    r2.shutdown().await;
    r.shutdown().await;
}

/// Same generation: a probe whose reply was built before a renewal committed, but
/// processed after it, cannot roll the renewed mapping back (renewals do not bump the
/// generation). For PCP, the next tick still has the mapping and the router holds one rule.
#[tokio::test]
async fn same_generation_probe_cannot_roll_back_a_renewal() {
    for pcp in [false, true] {
        let r = rig_with(Opts {
            router: RouterOptions {
                pmp: !pcp,
                enforce_pcp_client_ip: true,
                ..RouterOptions::default()
            },
            ..Opts::default()
        })
        .await;
        r.router.set_epoch(5000);
        r.map().await.unwrap();
        r.advance(secs(3601)); // renewal due; probe cache stale
        let kind = if pcp {
            RequestKind::PcpAnnounce
        } else {
            RequestKind::PmpPublicAddr
        };
        let frozen = FrozenTime::new();
        let barrier = r.router.barrier(kind);
        let c = r.client.clone();
        let probe = tokio::spawn(async move { c.probe().await });
        barrier.reached().await; // the probe's reply carries epoch 5000, held
        tokio::time::advance(Duration::from_millis(1)).await; // renewal is strictly newer
        r.router.set_epoch(5001); // a second later at the router
        r.client.get_cached_mapping_or_start_creating_one(); // the renewal
        while r.client.reap() != 0 {
            tokio::task::yield_now().await;
        }
        assert!(r.client.have_mapping());
        barrier.release();
        drop(frozen);
        probe.await.unwrap().unwrap();
        assert!(r.client.have_mapping(), "pcp={pcp}: renewal rolled back");
        assert_eq!(r.client.owned_rules(), 1, "pcp={pcp}");
        r.advance(secs(3));
        r.client.tick().await;
        r.settle().await;
        assert!(r.client.have_mapping(), "pcp={pcp}");
        assert!(!r.client.schedule().backing_off, "pcp={pcp}");
        assert_eq!(r.router.mappings().len(), 1, "pcp={pcp}");
        r.shutdown().await;
    }
}

/// An epoch rollback seen by a probe while an attempt of the same protocol is in flight keeps
/// that attempt's rule in the ledger as an orphan: the restarted router may commit it, and close
/// deletes it.
#[tokio::test]
async fn rollback_during_an_attempt_keeps_its_rule_deletable() {
    // PCP only on both sides: a probe that also asked for NAT-PMP would wait out its whole
    // 250 ms deadline for the silent NAT-PMP side, racing the held renewal's own 250 ms deadline,
    // so the renewal could time out before the probe saw the rollback.
    let r = rig_with(Opts {
        router: RouterOptions {
            pmp: false,
            enforce_pcp_client_ip: true,
            ..RouterOptions::default()
        },
        protos: ProtoSet {
            pmp: false,
            pcp: true,
        },
        ..Opts::default()
    })
    .await;
    r.router.set_epoch(5000);
    r.map().await.unwrap();
    // The router reboots (table cleared, small epoch). The renewal falls due and is committed by
    // the rebooted router, whose reply is held.
    r.router.reboot();
    r.router.set_epoch(10);
    r.advance(secs(3601));
    let frozen = FrozenTime::new();
    let barrier = r.router.barrier(RequestKind::PcpMap);
    r.client.get_cached_mapping_or_start_creating_one();
    barrier.reached().await;
    assert_eq!(r.router.mappings().len(), 1, "committed by the router");
    // A probe (another kick) sees the lower epoch while the renewal is in flight.
    r.client.probe().await.unwrap();
    assert!(!r.client.have_mapping(), "rollback detected");
    assert_eq!(r.client.owned_rules(), 1, "the in-flight rule is kept");
    barrier.release();
    drop(frozen);
    r.settle().await;
    r.client.close(secs(1)).await;
    assert!(r.router.mappings().is_empty(), "deleted on close");
    assert!(r.router.counters().num_deletes >= 1);
    r.router.shutdown().await;
}

/// A resume after the router's grant ended withdraws the mapping at once, even when the forced
/// renewal gets no answer; a shorter sleep keeps only what is left of the lease (Instant stops
/// during sleep, the router's clock does not).
#[tokio::test]
async fn resume_ages_the_lease() {
    // Longer than the grant: withdrawn by check_clock itself, before any renewal.
    let r = rig().await;
    r.map().await.unwrap();
    assert!(!r.client.check_clock());
    let mut rx = r.client.subscribe();
    rx.borrow_and_update();
    r.clock.suspend(secs(5 * 3600));
    r.router.drop_next(10_000);
    assert!(r.client.check_clock(), "resume noticed");
    assert!(!r.client.have_mapping());
    assert!(rx.has_changed().unwrap(), "published");
    assert_eq!(rx.borrow_and_update().advertised(), None);
    r.advance(secs(3));
    r.client.tick().await;
    r.settle().await;
    assert_eq!(r.state().advertised(), None, "no renewal answered");
    r.shutdown().await;

    // Shorter than the grant: the lease is aged by the sleep, then expires on schedule.
    let r = rig().await;
    r.map().await.unwrap();
    let before = r.client.schedule().expires_at.unwrap();
    assert!(!r.client.check_clock());
    r.clock.suspend(secs(30 * 60));
    r.router.drop_next(10_000);
    assert!(r.client.check_clock());
    let after = r.client.schedule().expires_at.unwrap();
    let aged = before.saturating_duration_since(after);
    assert!(
        aged > secs(30 * 60 - 1) && aged < secs(30 * 60 + 5),
        "aged by {aged:?}"
    );
    assert_eq!(r.state().mapping.unwrap().expires_at, after, "published");
    let entry = &r.client.owned_snapshot()[0];
    assert!(
        entry.router_expiry() >= before,
        "possible ownership remains conservative"
    );
    assert!(r.client.have_mapping(), "still within the grant");
    r.advance(secs(3));
    r.client.tick().await;
    r.settle().await;
    assert!(
        r.client.have_mapping(),
        "a failed renewal keeps it until expiry"
    );
    r.clock
        .advance(after.saturating_duration_since(r.clock.now()) + secs(1));
    assert!(r.client.expire_if_due());
    assert_eq!(r.state().advertised(), None);
    r.shutdown().await;
}

/// A cleanup cancelled while its delete is in flight hands the entry back, so close sends the
/// delete again instead of leaving the rule on the router.
#[tokio::test]
async fn cancelled_cleanup_hands_the_rule_back() {
    let r = rig().await;
    r.map().await.unwrap();
    assert_eq!(r.router.mappings().len(), 1);
    // The first delete is observable at a request barrier, but does not commit.
    r.router.set_drop_deletes(true);
    let frozen = FrozenTime::new();
    let barrier = r.router.barrier(RequestKind::PmpMap);
    r.client.set_local_port(PORT + 1).unwrap();
    barrier.reached().await;
    r.router.set_drop_deletes(false);
    // Abort and join the cleanup before close: the RAII guard itself must return the claim.
    let mut tasks = std::mem::take(&mut *lock(&r.client.inner.tasks));
    tasks.shutdown().await;
    assert!(
        !r.client.owned_snapshot()[0].deleting(),
        "cancelled cleanup returned its claim"
    );
    r.client.close(secs(1)).await;
    barrier.release();
    drop(frozen);
    assert!(r.router.mappings().is_empty(), "close re-sent the delete");
    assert_eq!(r.client.owned_rules(), 0);
    r.router.shutdown().await;
}

/// Simultaneous renewal: a renewal in flight when the local port changes or the socket is
/// rebound to a new port is stale; a rebind to the same port keeps the generation, and the
/// renewal commits.
#[tokio::test]
async fn renewal_racing_a_port_change_or_rebind() {
    for case in ["port", "rebind", "rebind-same-port"] {
        let r = rig().await;
        r.map().await.unwrap();
        r.advance(secs(3601));
        let maps = r.maps();
        let frozen = FrozenTime::new();
        let barrier = r.router.barrier(RequestKind::PmpMap);
        r.client.get_cached_mapping_or_start_creating_one();
        barrier.reached().await;
        match case {
            "port" => r.client.set_local_port(PORT + 1).unwrap(),
            "rebind" => r.client.note_rebind(Some(PORT + 1)),
            _ => r.client.note_rebind(Some(PORT)),
        }
        barrier.release();
        while r.client.reap() != 0 {
            tokio::task::yield_now().await;
        }
        drop(frozen);
        r.settle().await;
        if case == "rebind-same-port" {
            r.client.check_network().await;
            assert_eq!(r.maps(), maps + 1, "{case}: one renewal, no delete");
            assert!(r.client.have_mapping(), "{case}: renewed");
            assert_eq!(r.client.owned_rules(), 1, "{case}");
        } else {
            assert!(
                r.state().mapping.is_none(),
                "{case}: stale renewal installed"
            );
            assert!(
                r.router.mappings().iter().all(|m| m.internal != PORT),
                "{case}: the old rule was deleted"
            );
            r.advance(secs(2));
            r.client.tick().await;
            r.settle().await;
            assert_eq!(
                r.router.mappings()[0].internal,
                PORT + 1,
                "{case}: newer state wins"
            );
        }
        r.shutdown().await;
    }
}

/// Through `tick`, repeated kicks (two ticks a second for ten simulated minutes) against a
/// router that stopped answering send a bounded number of datagrams, probes included.
#[tokio::test]
async fn repeated_kicks_never_storm() {
    let r = rig().await;
    r.router.set_lifetime_override(Some(7200));
    let ext = r.map().await.unwrap();
    r.advance(secs(3601));
    r.router.set_pmp(false);
    r.router.set_pcp(false);
    let total = r.router.counters().num_total_recv;
    for _ in 0..600 {
        r.advance(secs(1));
        r.client.tick().await;
        r.client.tick().await;
        r.settle().await;
    }
    let sent = r.router.counters().num_total_recv - total;
    // Probes and attempts follow the backoff (10 + 30 + 60 + 120 + 300 s, ±20 %): a handful of
    // two-datagram probes, not one per kick.
    assert!(sent <= 16, "{sent} datagrams in 10 min");
    assert_eq!(
        r.state().mapping.unwrap().external,
        ext,
        "kept until expiry"
    );
    r.shutdown().await;
}

/// Warn-once keys are bounded (no counts, reply text or unknown code values), and forgeable
/// router replies have their own budget, so they cannot use up the operational one.
#[tokio::test]
async fn warn_budgets_are_bounded_and_separate() {
    let unknown = |c| MapError::Pmp {
        code: pmp::ResultCode::Unknown(c),
        epoch: 1,
    };
    assert_eq!(warn_key(&unknown(100)), warn_key(&unknown(200)));
    assert_eq!(
        warn_key(&MapError::NoServices {
            malformed: Some("3 datagram(s) from a source other than the gateway".to_owned()),
        }),
        warn_key(&MapError::NoServices {
            malformed: Some("4 oversize datagram(s)".to_owned()),
        }),
    );
    assert!(warn_key(&unknown(1)).1, "NAT-PMP codes are forgeable");
    let pcp_refusal = MapError::Pcp {
        code: pcp::ResultCode::NotAuthorized,
        lifetime: 1,
        epoch: 1,
    };
    assert!(
        !warn_key(&pcp_refusal).1,
        "a nonce-verified refusal is operational"
    );

    let r = rig().await;
    {
        let mut st = r.client.state();
        for i in 0..1000 {
            st.warn_once_router(format!("spoofed {i}"));
        }
        assert!(st.warned_router.len() <= MAX_WARNED);
        assert!(
            st.warn_once("lookup failed".to_owned()),
            "operational budget untouched"
        );
        assert!(!st.warn_once("lookup failed".to_owned()));
    }
    r.shutdown().await;
}

/// Rules whose deletes never commit still count against admission.
#[tokio::test]
async fn outstanding_router_rules_are_bounded_when_deletes_fail() {
    for refused in [false, true] {
        let r = rig().await;
        r.client.set_local_port(PORT).unwrap();
        r.client.check_network().await;
        r.client.probe().await.unwrap();
        for i in 0..4 {
            r.router.set_result(RequestKind::PmpMap, None);
            r.client.get_cached_mapping_or_start_creating_one();
            r.settle().await;
            assert!(r.client.have_mapping(), "slot {i}");
            r.router.set_drop_deletes(!refused);
            if refused {
                r.router.set_result(
                    RequestKind::PmpMap,
                    Some(ResultOverride {
                        code: 3,
                        lifetime: 0,
                    }),
                );
            }
            r.client.set_local_port(PORT + i + 1).unwrap();
            r.settle().await;
            for _ in 0..4 {
                r.client.cleanup().await;
            }
            r.advance(secs(3));
        }
        assert_eq!(r.router.mappings().len(), 4);
        r.router.set_result(RequestKind::PmpMap, None);
        r.client.get_cached_mapping_or_start_creating_one();
        r.settle().await;
        assert_eq!(r.router.mappings().len(), 4, "fifth MAP must be refused");
        assert_eq!(r.client.owned_rules(), 4);
        assert!(!r.client.have_mapping());
        r.advance(secs(7201));
        r.client.tick().await;
        r.settle().await;
        assert_eq!(r.router.mappings().len(), 1, "expiry frees admission");
        r.router.set_drop_deletes(false);
        r.shutdown().await;
    }
}

/// Discovery of PMP must not delete an aliased live PCP mapping.
#[tokio::test]
async fn renewal_keeps_pcp_when_pmp_becomes_available() {
    let r = rig_with(Opts {
        router: RouterOptions {
            pmp: false,
            ..RouterOptions::default()
        },
        ..Opts::default()
    })
    .await;
    r.map().await.unwrap();
    let nonce = r.router.mappings()[0].nonce;
    r.router.set_pmp(true);
    r.advance(secs(3601));
    r.client.tick().await;
    r.settle().await;
    let table = r.router.mappings();
    assert_eq!(
        table.len(),
        1,
        "renewal must remain installed at the router"
    );
    assert_eq!(table[0].nonce, nonce);
    assert_eq!(r.state().mapping.unwrap().proto, Proto::Pcp);
    assert_eq!(r.router.counters().num_deletes, 0);
    r.shutdown().await;
}

/// Losing a renewal reply must not lose the rule or its PCP nonce at expiry.
#[tokio::test]
async fn lost_renewal_preserves_ownership_through_expiry_and_close() {
    for pcp in [false, true] {
        let r = rig_with(Opts {
            router: RouterOptions {
                pmp: !pcp,
                ..RouterOptions::default()
            },
            ..Opts::default()
        })
        .await;
        r.router.set_lifetime_override(Some(60));
        r.map().await.unwrap();
        let nonce = r.router.mappings()[0].nonce;
        r.advance(secs(31));
        r.router.set_lifetime_override(Some(7200));
        r.router.knobs_for(Some(if pcp {
            RequestKind::PcpMap
        } else {
            RequestKind::PmpMap
        }));
        r.router.commit_then_drop_next(1);
        r.client.get_cached_mapping_or_start_creating_one();
        r.settle().await;
        assert_eq!(r.router.mappings()[0].nonce, nonce);
        r.advance(secs(31));
        r.client.expire_if_due();
        assert!(!r.client.have_mapping());
        assert_eq!(r.client.owned_rules(), 1, "renewed router rule still owned");
        r.client.close(secs(1)).await;
        assert!(
            r.router.mappings().is_empty(),
            "close deletes the renewed rule"
        );
        r.router.shutdown().await;
    }
}

/// A nonce-less PMP fallback is not proof a PCP create was refused.
#[tokio::test]
async fn committed_pcp_with_only_pmp_fallback_is_cleaned_up() {
    let r = rig_with(Opts {
        router: RouterOptions {
            pmp: false,
            ..RouterOptions::default()
        },
        ..Opts::default()
    })
    .await;
    r.router.knobs_for(Some(RequestKind::PcpMap));
    r.router
        .spoof_before_next_reply(vec![0, 0x81, 0, 1, 0, 0, 0, 1]);
    r.router.commit_then_drop_next(1);
    assert!(r.map().await.is_none());
    assert!(
        r.router.mappings().is_empty(),
        "possibly committed PCP rule must be deleted"
    );
    assert_eq!(r.router.counters().num_deletes, 1);
    r.shutdown().await;
}

/// A slow OS lookup/build cannot block a task heartbeat or timed release.
#[tokio::test]
async fn slow_discovery_does_not_block_heartbeat_or_shutdown() {
    struct SlowLookup {
        inner: Arc<ScriptedLookup>,
        caps: Arc<PausedCleanupCaps>,
    }
    impl GatewayLookup for SlowLookup {
        fn lookup(&self) -> Result<Option<Gateway>, LookupError> {
            self.caps.wait_if_paused();
            self.inner.lookup()
        }
    }
    let r = rig().await;
    let caps = Arc::new(PausedCleanupCaps {
        inner: r.caps.clone(),
        pause: std::sync::atomic::AtomicBool::new(false),
        entered: tokio::sync::Notify::new(),
        gate: (Mutex::new(false), std::sync::Condvar::new()),
    });
    let opener = OpenCapsOnDrop(caps.clone());
    let (client, _rx) = Client::new(Config {
        lookup: Arc::new(SlowLookup {
            inner: r.lookup.clone(),
            caps: caps.clone(),
        }),
        caps: caps.clone(),
        clock: r.clock.clone(),
        protos: ProtoSet::BOTH,
        advertise_nonpublic_external: true,
        lifetime: requested_lifetime(),
    });
    client.set_local_port(PORT).unwrap();
    client.tick().await;
    settle_checked(&client).await;
    assert!(client.have_mapping());
    let frozen = FrozenTime::new();
    caps.pause.store(true, std::sync::atomic::Ordering::SeqCst);
    let c = client.clone();
    let lookup = tokio::spawn(async move { c.check_network().await });
    caps.entered.notified().await;
    // The heartbeat and release must finish while discovery is still blocked, rather than
    // inferring overlap from a 10 ms sleep and comparing noisy wall-clock durations.
    let heartbeat = tokio::spawn(async {});
    heartbeat.await.unwrap();
    let started = tokio::time::Instant::now();
    client.close(Duration::from_millis(80)).await;
    assert_eq!(started.elapsed(), Duration::ZERO);
    assert!(
        !lookup.is_finished(),
        "lookup must still be blocked during release"
    );
    assert!(
        r.router.mappings().is_empty(),
        "release used its validated snapshot"
    );
    drop(opener);
    assert_eq!(
        lookup.await.unwrap(),
        NetCheck::Inactive,
        "late discovery cannot reopen a closed client"
    );
    drop(frozen);
    r.shutdown().await;
}

/// Force a completed I/O future through the stale commit branch, without aborting it.
#[tokio::test]
async fn completed_stale_attempt_cannot_publish_after_invalidation() {
    for pcp in [false, true] {
        let r = rig().await;
        r.client.set_local_port(PORT).unwrap();
        r.client.check_network().await;
        let rule = Rule::new(
            if pcp { Proto::Pcp } else { Proto::Pmp },
            NonZeroU16::new(PORT).unwrap(),
        )
        .unwrap();
        let ctx = {
            let mut st = r.client.state();
            let n = st.net.as_ref().unwrap();
            let (cap, gw, ng) = (n.cap.clone(), n.gateway.clone(), n.net_gen);
            let id = st
                .owned
                .add_pending(rule.clone(), ng, gw, r.clock.now())
                .unwrap();
            AttemptCtx {
                generation: st.generation,
                cap,
                net_gen: ng,
                rule,
                rule_id: id,
                existed: false,
                evidence: st.owned.claim_map(id, r.clock.now(), false).unwrap(),
                prev: None,
            }
        };
        let frozen = FrozenTime::new();
        let barrier = r.router.barrier(if pcp {
            RequestKind::PcpMap
        } else {
            RequestKind::PmpMap
        });
        let c = r.client.clone();
        // Deliberately outside the client's abort set: models I/O completing before abort wins.
        let guard = SettlementGuard {
            client: r.client.clone(),
            event: FinalizerEvent::Map {
                id: u64::MAX,
                rule_id: ctx.rule_id,
            },
        };
        let completion = tokio::spawn(async move {
            let _guard = guard;
            c.run_attempt(ctx).await
        });
        barrier.reached().await;
        r.client.policy().set_lan_sends_allowed(false);
        r.client.set_local_port(PORT + 1).unwrap();
        barrier.release();
        assert!(
            completion.await.unwrap(),
            "stale completion requests orphan cleanup"
        );
        assert!(
            r.state().mapping.is_none(),
            "stale result must not be published"
        );
        assert_eq!(
            r.client.owned_snapshot()[0].state(),
            crate::owned::RuleState::Orphaned
        );
        drop(frozen);
        r.client.policy().set_lan_sends_allowed(true);
        r.client.cleanup().await;
        assert!(r.router.mappings().is_empty());
        r.shutdown().await;
    }
}

/// An unobserved grant may exceed the request: tombstones must not expire at the request alone.
#[tokio::test]
async fn lost_long_grants_still_count_after_requested_lifetime() {
    let r = rig_with(Opts {
        router: RouterOptions {
            pmp: false,
            ..RouterOptions::default()
        },
        ..Opts::default()
    })
    .await;
    r.router.set_lifetime_override(Some(86_400));
    r.router.set_drop_deletes(true);
    r.router.knobs_for(Some(RequestKind::PcpMap));
    r.router.commit_then_drop_next(1000);
    for i in 0..4 {
        r.client.set_local_port(PORT + i).unwrap();
        r.advance(secs(700));
        r.client.tick().await;
        r.settle().await;
        for _ in 0..4 {
            r.client.cleanup().await;
        }
    }
    assert_eq!(r.router.mappings().len(), 4);
    r.advance(secs(7201));
    r.client.set_local_port(PORT + 4).unwrap();
    r.client.tick().await;
    r.settle().await;
    assert_eq!(
        r.router.mappings().len(),
        4,
        "unknown long grants still occupy their slots"
    );
    assert_eq!(r.client.owned_rules(), 4);
    r.shutdown().await;
}

/// A lost adopted PCP create extends possible ownership and retains its nonce.
#[tokio::test]
async fn lost_adoption_preserves_nonce_until_close() {
    let r = rig_with(Opts {
        router: RouterOptions {
            pmp: false,
            ..RouterOptions::default()
        },
        ..Opts::default()
    })
    .await;
    r.router.set_lifetime_override(Some(60));
    r.map().await.unwrap();
    let nonce = r.router.mappings()[0].nonce;
    r.client.note_network_down();
    r.advance(secs(31));
    r.client.check_network().await;
    r.client.probe().await.unwrap();
    r.router.set_lifetime_override(Some(7200));
    r.router.set_drop_deletes(true);
    r.router.knobs_for(Some(RequestKind::PcpMap));
    r.router.commit_then_drop_next(1);
    r.client.get_cached_mapping_or_start_creating_one();
    r.settle().await;
    assert_eq!(r.router.mappings()[0].nonce, nonce);
    r.advance(secs(31));
    assert_eq!(
        r.router.mappings().len(),
        1,
        "adopted grant outlives the original lease"
    );
    r.router.set_drop_deletes(false);
    r.client.close(secs(1)).await;
    assert!(
        r.router.mappings().is_empty(),
        "adopted rule remains deletable after the old grant ends"
    );
    r.router.shutdown().await;
}

/// An adopted rule can predate a matched refusal: refusal does not prove the old rule is gone.
#[tokio::test]
async fn refused_adoption_keeps_existing_rule_owned() {
    let r = rig_with(Opts {
        router: RouterOptions {
            pmp: false,
            ..RouterOptions::default()
        },
        ..Opts::default()
    })
    .await;
    r.map().await.unwrap();
    let nonce = r.router.mappings()[0].nonce;
    r.client.note_network_down();
    r.advance(secs(3));
    r.router.set_result(
        RequestKind::PcpMap,
        Some(ResultOverride {
            code: 7,
            lifetime: 30,
        }),
    );
    r.client.tick().await;
    r.settle().await;
    assert_eq!(
        r.client.owned_rules(),
        1,
        "refused adoption retains pre-existing ownership"
    );
    assert_eq!(r.router.mappings()[0].nonce, nonce);
    r.router.set_result(RequestKind::PcpMap, None);
    r.shutdown().await;
}

/// A forward wall-clock correction must withdraw trust without pretending router rules expired.
#[tokio::test]
async fn wall_clock_jump_cannot_free_owned_rule_slots() {
    let r = rig().await;
    r.map().await.unwrap();
    r.client.check_clock();
    let expiry = r.client.owned_snapshot()[0].router_expiry();
    r.clock.suspend(secs(4 * 3600)); // also models a false positive wall-clock step
    assert!(r.client.check_clock());
    assert!(!r.client.have_mapping());
    assert_eq!(
        r.router.mappings().len(),
        1,
        "router did not advance with the wall clock"
    );
    assert_eq!(
        r.client.owned_rules(),
        1,
        "ownership is conservative across an unverified clock jump"
    );
    assert_eq!(r.client.owned_snapshot()[0].router_expiry(), expiry);
    r.shutdown().await;
}

/// A lookup captured before synchronous invalidation cannot install its snapshot.
#[tokio::test]
async fn discovery_snapshot_is_rejected_after_port_generation_changes() {
    struct PausedLookup {
        entered: Arc<tokio::sync::Notify>,
        gate: Arc<(Mutex<bool>, std::sync::Condvar)>,
    }
    impl GatewayLookup for PausedLookup {
        fn lookup(&self) -> Result<Option<Gateway>, LookupError> {
            self.entered.notify_one();
            let (gate, cv) = &*self.gate;
            let ready = lock(gate);
            drop(cv.wait_while(ready, |open| !*open).unwrap());
            Ok(Some(gateway(GW1)))
        }
    }
    let r = rig().await;
    let entered = Arc::new(tokio::sync::Notify::new());
    let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    let (client, _rx) = Client::new(Config {
        lookup: Arc::new(PausedLookup {
            entered: entered.clone(),
            gate: gate.clone(),
        }),
        caps: r.caps.clone(),
        clock: r.clock.clone(),
        protos: ProtoSet::BOTH,
        advertise_nonpublic_external: true,
        lifetime: requested_lifetime(),
    });
    client.set_local_port(PORT).unwrap();
    let c = client.clone();
    let frozen = FrozenTime::new();
    let discovery = tokio::spawn(async move { c.check_network().await });
    tokio::time::timeout(secs(2), entered.notified())
        .await
        .unwrap();
    client.set_local_port(PORT + 1).unwrap();
    *lock(&gate.0) = true;
    gate.1.notify_one();
    assert_eq!(discovery.await.unwrap(), NetCheck::Inactive);
    assert!(!client.has_network(), "stale gateway was never installed");
    drop(frozen);
    client.close(secs(1)).await;
    r.shutdown().await;
}

/// Repeated validation failures without a network do not reset the warning budget.
#[tokio::test]
#[tracing_test::traced_test]
async fn offline_gateway_rejections_warn_once() {
    let r = rig().await;
    r.caps.set_present(GW1, false);
    for _ in 0..10 {
        assert_eq!(r.client.check_network().await, NetCheck::Down);
    }
    logs_assert(|lines: &[&str]| {
        assert_eq!(
            lines
                .iter()
                .filter(|line| line.contains("gateway rejected"))
                .count(),
            1
        );
        Ok(())
    });
    r.shutdown().await;
}

// Pause OS capability construction before cleanup can send its DELETE.
struct PausedCleanupCaps {
    inner: Arc<TestCaps>,
    pause: std::sync::atomic::AtomicBool,
    entered: tokio::sync::Notify,
    gate: (Mutex<bool>, std::sync::Condvar),
}
impl PausedCleanupCaps {
    fn wait_if_paused(&self) {
        if self.pause.swap(false, std::sync::atomic::Ordering::SeqCst) {
            self.entered.notify_one();
            let ready = lock(&self.gate.0);
            drop(self.gate.1.wait_while(ready, |open| !*open).unwrap());
        }
    }
}
impl CapFactory<TestCap> for PausedCleanupCaps {
    fn build(&self, g: &Gateway, n: NetGen, p: &PolicyHandle) -> Result<Arc<TestCap>, CapError> {
        self.wait_if_paused();
        self.inner.build(g, n, p)
    }
}

async fn alias_cleanup_case(initial_pcp: bool, port_roundtrip: bool, metadata_change: bool) {
    let r = rig_with(Opts {
        router: RouterOptions {
            pmp: !initial_pcp,
            ..RouterOptions::default()
        },
        ..Opts::default()
    })
    .await;
    let caps = Arc::new(PausedCleanupCaps {
        inner: r.caps.clone(),
        pause: std::sync::atomic::AtomicBool::new(false),
        entered: tokio::sync::Notify::new(),
        gate: (Mutex::new(false), std::sync::Condvar::new()),
    });
    let (client, _) = Client::new(Config {
        lookup: r.lookup.clone(),
        caps: caps.clone(),
        clock: r.clock.clone(),
        protos: ProtoSet::BOTH,
        advertise_nonpublic_external: true,
        lifetime: requested_lifetime(),
    });
    client.set_local_port(PORT).unwrap();
    r.router.set_lifetime_override(Some(86_400));
    client.tick().await;
    while client.attempt_in_flight() || client.reap() != 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(client.have_mapping());
    if !port_roundtrip {
        r.advance(secs(7201));
        assert!(client.expire_if_due());
    }
    assert_eq!(
        r.router.mappings().len(),
        1,
        "router grant outlives local trust"
    );
    r.router.set_pmp(true);
    client.probe().await.unwrap();
    let frozen = FrozenTime::new();
    let opener = OpenCapsOnDrop(caps.clone());
    caps.pause.store(true, std::sync::atomic::Ordering::SeqCst);
    if port_roundtrip {
        client.set_local_port(PORT + 1).unwrap();
    }
    let c = client.clone();
    let cleanup = tokio::spawn(async move { c.cleanup().await });
    tokio::time::timeout(secs(2), caps.entered.notified())
        .await
        .unwrap();
    if port_roundtrip {
        client.set_local_port(PORT).unwrap();
        r.advance(secs(3));
    }
    if metadata_change {
        let mut gw = gateway(GW1);
        gw.prefix_len = 23;
        r.lookup.set(gw);
        assert_eq!(client.check_network().await, NetCheck::Changed);
    }
    // A driver tick must not create an alias while cleanup owns the wire identity.
    client.tick().await;
    while client.attempt_in_flight() {
        tokio::task::yield_now().await;
    }
    let during_delete = client.subscribe().borrow().mapping;
    drop(opener);
    cleanup.await.unwrap();
    drop(frozen);
    while client.reap() != 0 {
        tokio::task::yield_now().await;
    }
    // Retirement permits the next create, including a protocol switch. Its following cleanup
    // must leave the advertised rule intact.
    r.advance(secs(3));
    client.tick().await;
    while client.attempt_in_flight() || client.reap() != 0 {
        tokio::task::yield_now().await;
    }
    client.cleanup().await;
    let advertised = client.subscribe().borrow().mapping.unwrap();
    let table = r.router.mappings();
    client.close(secs(1)).await;
    r.shutdown().await;
    assert!(
        during_delete.is_none(),
        "MAP aliased a reserved delete identity"
    );
    assert_eq!(
        advertised.proto,
        Proto::Pmp,
        "retired PCP identity can switch"
    );
    assert_eq!(table.len(), 1, "next cleanup must preserve advertisement");
    assert_eq!(table[0].internal, PORT);
    assert_eq!(table[0].external, advertised.external.port());
}
#[tokio::test]
async fn pcp_cleanup_cannot_delete_pmp_replacement() {
    alias_cleanup_case(true, false, false).await;
}
#[tokio::test]
async fn pmp_cleanup_cannot_delete_pmp_replacement() {
    alias_cleanup_case(false, false, false).await;
}

#[tokio::test]
async fn port_away_and_back_during_cleanup() {
    alias_cleanup_case(true, true, false).await;
    alias_cleanup_case(false, true, false).await;
}

#[tokio::test]
async fn pcp_outstanding_rules_bounded() {
    for refused in [false, true] {
        let r = rig_with(Opts {
            router: RouterOptions {
                pmp: false,
                ..RouterOptions::default()
            },
            ..Opts::default()
        })
        .await;
        r.client.set_local_port(PORT).unwrap();
        r.client.check_network().await;
        r.client.probe().await.unwrap();
        for i in 0..4 {
            r.router.set_result(RequestKind::PcpMap, None);
            r.client.get_cached_mapping_or_start_creating_one();
            r.settle().await;
            assert!(r.client.have_mapping(), "slot {i}");
            r.router.set_drop_deletes(!refused);
            if refused {
                r.router.set_result(
                    RequestKind::PcpMap,
                    Some(ResultOverride {
                        code: 3,
                        lifetime: 0,
                    }),
                );
            }
            r.client.set_local_port(PORT + i + 1).unwrap();
            r.settle().await;
            for _ in 0..4 {
                r.client.cleanup().await;
            }
            r.advance(secs(3));
        }
        assert_eq!(r.router.mappings().len(), 4);
        r.router.set_result(RequestKind::PcpMap, None);
        r.client.get_cached_mapping_or_start_creating_one();
        r.settle().await;
        assert_eq!(r.router.mappings().len(), 4, "fifth MAP must be refused");
        assert_eq!(r.client.owned_rules(), 4);
        assert!(!r.client.have_mapping());
        r.advance(secs(7201));
        r.client.tick().await;
        r.settle().await;
        assert_eq!(r.router.mappings().len(), 1, "expiry frees admission");
        r.router.set_drop_deletes(false);
        r.shutdown().await;
    }
}

#[tokio::test]
async fn failed_old_delete_cannot_delete_protocol_replacement() {
    let r = rig_with(Opts {
        router: RouterOptions {
            pmp: false,
            ..RouterOptions::default()
        },
        ..Opts::default()
    })
    .await;
    r.router.set_lifetime_override(Some(86_400));
    r.map().await.unwrap();
    r.advance(secs(7201));
    assert!(r.client.expire_if_due());
    r.router.set_pmp(true);
    r.router.set_drop_deletes(true);
    r.client.tick().await;
    r.settle().await;
    let interim = r.state().mapping;
    assert_eq!(r.router.mappings().len(), 1);
    r.router.set_drop_deletes(false);
    r.advance(secs(700));
    r.client.tick().await;
    r.settle().await;
    r.client.cleanup().await;
    let table = r.router.mappings();
    let advertised = r.state().mapping.unwrap();
    r.shutdown().await;
    assert!(
        interim.is_none_or(|m| m.proto == Proto::Pcp),
        "orphan must retain its protocol"
    );
    assert_eq!(table.len(), 1, "next cleanup must preserve advertisement");
    assert_eq!(table[0].internal, PORT);
    assert_eq!(table[0].external, advertised.external.port());
}
#[tokio::test]
async fn refused_old_delete_cannot_delete_protocol_replacement() {
    let r = rig_with(Opts {
        router: RouterOptions {
            pmp: false,
            ..RouterOptions::default()
        },
        ..Opts::default()
    })
    .await;
    r.router.set_lifetime_override(Some(86_400));
    r.map().await.unwrap();
    r.advance(secs(7201));
    assert!(r.client.expire_if_due());
    r.router.set_pmp(true);
    r.router.set_result(
        RequestKind::PcpMap,
        Some(ResultOverride {
            code: 7,
            lifetime: 30,
        }),
    );
    r.client.tick().await;
    r.settle().await;
    let interim = r.state().mapping;
    assert_eq!(r.router.mappings().len(), 1);
    r.router.set_result(RequestKind::PcpMap, None);
    r.advance(secs(700));
    r.client.tick().await;
    r.settle().await;
    r.client.cleanup().await;
    let table = r.router.mappings();
    let advertised = r.state().mapping.unwrap();
    r.shutdown().await;
    assert!(
        interim.is_none_or(|m| m.proto == Proto::Pcp),
        "orphan must retain its protocol"
    );
    assert_eq!(table.len(), 1, "next cleanup must preserve advertisement");
    assert_eq!(table[0].internal, PORT);
    assert_eq!(table[0].external, advertised.external.port());
}

#[tokio::test]
async fn pcp_variant_network_change_releases_only_to_a_validating_old_network() {
    for old_validates in [true, false] {
        let r = rig_with(Opts {
            router: RouterOptions {
                pmp: false,
                ..RouterOptions::default()
            },
            ..Opts::default()
        })
        .await;
        let router2 = FakeRouter::start(RouterOptions {
            pmp: false,
            ..RouterOptions::default()
        })
        .await
        .unwrap();
        r.caps.add(GW2, router2.endpoint());
        r.map().await.unwrap();
        assert_eq!(r.router.mappings().len(), 1);
        r.caps.set_present(GW1, old_validates);
        r.lookup.set(gateway(GW2));
        assert_eq!(r.client.check_network().await, NetCheck::Changed);
        assert!(r.state().mapping.is_none());
        r.settle().await;
        r.advance(secs(2));
        r.client.tick().await;
        r.settle().await;
        assert_eq!(
            r.router.counters().num_deletes,
            u64::from(old_validates),
            "old_validates={old_validates}"
        );
        assert_eq!(r.router.mappings().len(), usize::from(!old_validates));
        assert_eq!(
            router2.counters().num_deletes,
            0,
            "nothing for the old rule"
        );
        assert_eq!(
            router2.mappings().len(),
            1,
            "new mapping via the new router"
        );
        assert!(r.state().mapping.is_some());
        assert_eq!(r.client.owned_rules(), if old_validates { 1 } else { 2 });
        router2.shutdown().await;
        r.shutdown().await;
    }
}

#[tokio::test]
async fn pcp_variant_down_invalidates_without_release() {
    for how in ["no-route", "error", "down"] {
        let r = rig_with(Opts {
            router: RouterOptions {
                pmp: false,
                ..RouterOptions::default()
            },
            ..Opts::default()
        })
        .await;
        r.map().await.unwrap();
        match how {
            "no-route" => {
                r.lookup.set_no_route();
                assert_eq!(r.client.check_network().await, NetCheck::Down);
            }
            "error" => {
                r.lookup.set_error();
                assert_eq!(r.client.check_network().await, NetCheck::Down);
            }
            _ => r.client.note_network_down(),
        }
        r.settle().await;
        r.client.cleanup().await;
        assert!(r.state().mapping.is_none(), "{how}");
        assert_eq!(r.router.counters().num_deletes, 0, "{how}: no release");
        // Kept (never deleted) only so a create on the same network can adopt it.
        assert!(
            r.client.owned_snapshot().iter().all(|e| !e.releasable()),
            "{how}"
        );
        assert!(!r.client.has_network());
        r.client.close(secs(1)).await;
        assert_eq!(
            r.router.counters().num_deletes,
            0,
            "{how}: not even on close"
        );
        r.router.shutdown().await;
    }
}

#[tokio::test]
async fn pcp_variant_rebind_keeps_or_replaces_the_mapping() {
    let r = rig_with(Opts {
        router: RouterOptions {
            pmp: false,
            ..RouterOptions::default()
        },
        ..Opts::default()
    })
    .await;
    let ext = r.map().await.unwrap();
    let mut rx = r.client.subscribe();
    rx.borrow_and_update();
    let before = r.router.requests().len();
    r.client.note_rebind(Some(PORT));
    assert!(
        r.state().mapping.is_none(),
        "withdrawn before OS validation"
    );
    r.client.check_network().await;
    assert!(rx.has_changed().unwrap(), "re-published for the magicsock");
    assert_eq!(r.state().mapping.unwrap().external, ext);
    r.settle().await;
    assert_eq!(r.router.requests().len(), before, "no I/O");

    r.client.note_rebind(Some(PORT + 2));
    assert!(r.state().mapping.is_none());
    r.settle().await;
    r.advance(secs(2));
    let before = r.creates_and_renewals().len();
    r.client.get_cached_mapping_or_start_creating_one();
    r.settle().await;
    assert_eq!(
        r.creates_and_renewals().len(),
        before,
        "changed-port rebind requires fresh network validation"
    );
    r.client.tick().await;
    r.settle().await;
    let table: Vec<u16> = r.router.mappings().iter().map(|m| m.internal).collect();
    assert_eq!(table, [PORT + 2]);

    r.client.note_rebind(None);
    assert!(r.state().mapping.is_none());
    r.settle().await;
    assert!(r.router.mappings().is_empty(), "released: the port is gone");
    r.shutdown().await;
}

#[tokio::test]
async fn pcp_variant_close_releases_within_budget() {
    let r = rig_with(Opts {
        router: RouterOptions {
            pmp: false,
            ..RouterOptions::default()
        },
        ..Opts::default()
    })
    .await;
    r.map().await.unwrap();
    r.client.close(secs(1)).await;
    assert!(r.router.mappings().is_empty());
    let deletes = r.router.counters().num_deletes;
    assert_eq!(deletes, 1);
    r.client.close(secs(1)).await;
    r.client.release_blocking_best_effort();
    assert_eq!(r.router.counters().num_deletes, deletes, "idempotent");
    assert!(r.client.tick().await.is_none());
    assert!(
        r.client
            .get_cached_mapping_or_start_creating_one()
            .is_none()
    );
    assert_eq!(r.router.counters().num_deletes, deletes);
    r.router.shutdown().await;

    // Router gone: close still ends within its budget.
    let r = rig_with(Opts {
        router: RouterOptions {
            pmp: false,
            ..RouterOptions::default()
        },
        ..Opts::default()
    })
    .await;
    r.map().await.unwrap();
    r.router.drop_next(1000);
    let t = std::time::Instant::now();
    r.client.close(Duration::from_millis(300)).await;
    assert!(
        t.elapsed() < Duration::from_millis(600),
        "{:?}",
        t.elapsed()
    );
    r.router.shutdown().await;

    // Close while an attempt waits on the router: no new work starts after it began.
    let r = rig_with(Opts {
        router: RouterOptions {
            pmp: false,
            ..RouterOptions::default()
        },
        ..Opts::default()
    })
    .await;
    r.client.set_local_port(PORT).unwrap();
    r.client.check_network().await;
    r.client.probe().await.unwrap();
    let barrier = r.router.barrier(RequestKind::PcpMap);
    r.client.get_cached_mapping_or_start_creating_one();
    barrier.reached().await;
    let c = r.client.clone();
    let close = tokio::spawn(async move { c.close(secs(2)).await });
    wait_for_close(&r.client).await;
    let maps = r.creates_and_renewals().len();
    assert!(
        r.client
            .get_cached_mapping_or_start_creating_one()
            .is_none()
    );
    barrier.release();
    close.await.unwrap();
    assert_eq!(
        r.creates_and_renewals().len(),
        maps,
        "nothing started after close began"
    );
    assert!(
        r.router.mappings().is_empty(),
        "the in-flight rule was deleted"
    );
    r.router.shutdown().await;
}

/// Invalidation clears the single-flight handle before a completed send's future is dropped.
/// Keep the ledger reservation until that future actually finishes, not until invalidation.
#[tokio::test]
async fn map_reservation_survives_invalidation() {
    for pcp in [false, true] {
        let r = rig_with(Opts {
            router: RouterOptions {
                pmp: !pcp,
                ..RouterOptions::default()
            },
            ..Opts::default()
        })
        .await;
        r.client.set_local_port(PORT).unwrap();
        r.client.check_network().await;
        r.client.probe().await.unwrap();
        let frozen = FrozenTime::new();
        let barrier = r.router.barrier(if pcp {
            RequestKind::PcpMap
        } else {
            RequestKind::PmpMap
        });
        r.client.get_cached_mapping_or_start_creating_one();
        barrier.reached().await;
        // Model an operation whose completion has won the abort race. It remains in the JoinSet.
        r.client.state().inflight.as_mut().unwrap().abort.take();
        r.client.set_local_port(PORT + 1).unwrap();
        r.client.set_local_port(PORT).unwrap();
        r.advance(secs(3));
        // PCP-only discovery left PMP uncached. Answer the tick's probe immediately: a silent
        // probe would need time to advance, and race the MAP's equally long exchange deadline.
        r.router.set_pmp(true);
        r.client.tick().await;
        assert!(r.client.owned_snapshot()[0].mapping(), "MAP is still live");
        assert_owned_invariant(&r.client);
        let during = r.state().mapping;
        let sends = r.router.requests();
        barrier.release();
        while r.client.reap() != 0 {
            tokio::task::yield_now().await;
        }
        drop(frozen);
        r.settle().await;
        r.advance(secs(3));
        r.client.tick().await;
        r.settle().await;
        r.client.cleanup().await;
        let advertised = r.state().mapping.unwrap();
        let table = r.router.mappings();
        r.shutdown().await;
        assert!(during.is_none(), "pending MAP identity was aliased");
        assert_eq!(
            sends
                .iter()
                .filter(
                    |q| matches!(q.kind, RequestKind::PmpMap | RequestKind::PcpMap)
                        && q.lifetime == Some(0)
                )
                .count(),
            0,
            "delete raced pending MAP"
        );
        assert_eq!(
            sends
                .iter()
                .filter(|q| q.lifetime.is_some_and(|t| t > 0))
                .count(),
            1,
            "second MAP raced pending MAP"
        );
        assert_eq!(table.len(), 1);
        assert_eq!(table[0].internal, PORT);
        assert_eq!(table[0].external, advertised.external.port());
    }
}

#[tokio::test]
async fn timed_out_map_returns_reservation_before_late_reply() {
    for pcp in [false, true] {
        let r = rig_with(Opts {
            protos: ProtoSet { pmp: !pcp, pcp },
            ..Opts::default()
        })
        .await;
        r.client.set_local_port(PORT).unwrap();
        r.client.check_network().await;
        r.client.probe().await.unwrap();
        let frozen = FrozenTime::new();
        let reply = r.router.barrier(if pcp {
            RequestKind::PcpMap
        } else {
            RequestKind::PmpMap
        });
        r.client.get_cached_mapping_or_start_creating_one();
        reply.reached().await;
        r.client.state().inflight.as_mut().unwrap().abort.take();
        r.client.set_local_port(PORT + 1).unwrap();
        r.client.set_local_port(PORT).unwrap();
        assert!(r.client.owned_snapshot()[0].mapping());
        assert_owned_invariant(&r.client);
        assert_eq!(delete_requests(&r.router), 0);

        // The server's reply is still held, but the client operation has timed out. Cleanup
        // may now delete; a reply barrier alone cannot establish a live MAP reservation.
        tokio::time::advance(crate::cap::EXCHANGE_TIMEOUT + Duration::from_millis(1)).await;
        while r.client.reap() != 0 {
            assert_owned_invariant(&r.client);
            tokio::task::yield_now().await;
        }
        assert_eq!(delete_requests(&r.router), 1);
        assert!(r.client.owned_snapshot().is_empty());
        assert!(r.router.mappings().is_empty());
        assert_router_inventory(&r.client, GW1, &r.router);
        reply.release();
        drop(frozen);
        r.shutdown().await;
    }
}

#[tokio::test]
async fn unknown_slots_recover_when_router_recovers() {
    let r = rig().await;
    r.router.set_drop_deletes(true);
    r.router.knobs_for(Some(RequestKind::PmpMap));
    r.router.commit_then_drop_next(1000);
    for i in 0..4 {
        r.client.set_local_port(PORT + i).unwrap();
        r.advance(secs(700));
        r.client.tick().await;
        r.settle().await;
        for _ in 0..4 {
            r.client.cleanup().await;
        }
    }
    assert_eq!(r.client.owned_rules(), 4);
    r.advance(secs(7201));
    assert!(
        r.router.mappings().is_empty(),
        "all actual router grants expired"
    );
    r.router.set_drop_deletes(false);
    r.router.commit_then_drop_next(0);
    r.client.set_local_port(PORT + 4).unwrap();
    r.client.tick().await;
    r.settle().await;
    let recovered = r.client.have_mapping();
    let tombstones = r.client.owned_rules();
    r.shutdown().await;
    assert!(
        recovered,
        "healthy empty router remains blocked by {tombstones} tombstones"
    );
}

fn delete_requests(router: &FakeRouter) -> usize {
    router
        .requests()
        .iter()
        .filter(|q| {
            matches!(q.kind, RequestKind::PmpMap | RequestKind::PcpMap) && q.lifetime == Some(0)
        })
        .count()
}

// Lose a committed create and all its initial deletes, leaving an unknown grant.
async fn exhaust_unknown_slots(r: &Rig, pcp: bool) {
    r.router.set_drop_deletes(true);
    r.router.knobs_for(Some(if pcp {
        RequestKind::PcpMap
    } else {
        RequestKind::PmpMap
    }));
    r.router.commit_then_drop_next(1);
    r.client.set_local_port(PORT).unwrap();
    r.client.tick().await;
    r.settle().await;
    for _ in 0..4 {
        r.client.cleanup().await;
    }
    assert!(!r.client.have_mapping());
    assert_eq!(r.client.owned_rules(), 1);
    assert_eq!(r.router.mappings().len(), 1);
    assert_eq!(delete_requests(&r.router), 3);
}

#[tokio::test]
async fn lost_cleanup_retries_are_infrequent_and_keep_slots() {
    for pcp in [false, true] {
        let r = rig_with(Opts {
            router: RouterOptions {
                pmp: !pcp,
                ..RouterOptions::default()
            },
            ..Opts::default()
        })
        .await;
        exhaust_unknown_slots(&r, pcp).await;
        let before = delete_requests(&r.router);
        for _ in 0..599 {
            r.advance(secs(1));
            r.client.cleanup().await;
        }
        assert_eq!(delete_requests(&r.router), before, "no hot retry loop");
        r.advance(secs(1));
        r.client.cleanup().await;
        let after = delete_requests(&r.router);
        assert_eq!(
            after,
            before + 1,
            "exhaustion must allow a recovery attempt"
        );
        for _ in 0..599 {
            r.advance(secs(1));
            r.client.cleanup().await;
        }
        assert_eq!(
            delete_requests(&r.router),
            after,
            "one attempt per cooldown"
        );
        assert_eq!(r.client.owned_rules(), 1, "loss is not retirement evidence");
        assert_eq!(r.router.mappings().len(), 1);
        r.advance(secs(1));
        // A refused delete is also insufficient evidence; subsequent success may retire it.
        r.router.set_drop_deletes(false);
        r.router.set_result(
            if pcp {
                RequestKind::PcpMap
            } else {
                RequestKind::PmpMap
            },
            Some(ResultOverride {
                code: 2,
                lifetime: 0,
            }),
        );
        r.client.cleanup().await;
        assert_eq!(r.client.owned_rules(), 1);
        assert_eq!(r.router.mappings().len(), 1);
        r.router.set_result(
            if pcp {
                RequestKind::PcpMap
            } else {
                RequestKind::PmpMap
            },
            None,
        );
        r.caps.set_present(GW1, false);
        r.advance(secs(600));
        assert_eq!(
            r.client.cleanup().await,
            0,
            "failed fresh validation sends nothing"
        );
        assert_eq!(r.client.owned_rules(), 1);
        r.caps.set_present(GW1, true);
        r.advance(secs(599));
        assert_eq!(
            r.client.cleanup().await,
            0,
            "failed validation also has a cooldown"
        );
        r.advance(secs(1));
        assert_eq!(
            r.client.cleanup().await,
            1,
            "validation failure must remain recoverable"
        );
        assert_eq!(r.client.owned_rules(), 0);
        assert!(r.router.mappings().is_empty());
        r.shutdown().await;
    }
}

#[tokio::test]
async fn network_down_fences_a_late_recovery_validation() {
    let r = rig().await;
    let caps = Arc::new(PausedCleanupCaps {
        inner: r.caps.clone(),
        pause: std::sync::atomic::AtomicBool::new(false),
        entered: tokio::sync::Notify::new(),
        gate: (Mutex::new(false), std::sync::Condvar::new()),
    });
    let (client, _) = Client::new(Config {
        lookup: r.lookup.clone(),
        caps: caps.clone(),
        clock: r.clock.clone(),
        protos: ProtoSet::BOTH,
        advertise_nonpublic_external: true,
        lifetime: requested_lifetime(),
    });
    r.router.set_drop_deletes(true);
    r.router.knobs_for(Some(RequestKind::PmpMap));
    r.router.commit_then_drop_next(1);
    client.set_local_port(PORT).unwrap();
    client.tick().await;
    while client.attempt_in_flight() || client.reap() != 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    for _ in 0..4 {
        client.cleanup().await;
    }
    assert_eq!(delete_requests(&r.router), 3);
    r.advance(secs(600));
    r.router.set_drop_deletes(false);
    let frozen = FrozenTime::new();
    let opener = OpenCapsOnDrop(caps.clone());
    caps.pause.store(true, std::sync::atomic::Ordering::SeqCst);
    let c = client.clone();
    let cleanup = tokio::spawn(async move { c.cleanup().await });
    let entered = tokio::time::timeout(secs(2), caps.entered.notified()).await;
    client.note_network_down();
    drop(opener);
    assert_eq!(cleanup.await.unwrap(), 0);
    drop(frozen);
    entered.expect("exhausted entry must reach fresh validation before retry");
    for _ in 0..5 {
        r.advance(secs(7200));
        client.cleanup().await;
    }
    assert!(client.owned_snapshot().iter().all(|e| !e.releasable()));
    assert_eq!(
        client.owned_rules(),
        1,
        "network loss is not retirement evidence"
    );
    assert!(!client.have_mapping());
    client.close(secs(1)).await;
    assert_eq!(
        delete_requests(&r.router),
        3,
        "network-down entries stay unsent, even after validation finishes or on close"
    );
    r.shutdown().await;
}

/// A cleanup capability must join synchronous invalidation, just like the active capability.
#[tokio::test]
async fn network_down_invalidates_validated_cleanup_cap() {
    let r = rig().await;
    exhaust_unknown_slots(&r, false).await;
    r.advance(secs(600));
    r.router.set_drop_deletes(false);
    let frozen = FrozenTime::new();
    let barrier = r.router.barrier(RequestKind::PmpMap);
    let c = r.client.clone();
    let cleanup = tokio::spawn(async move { c.cleanup().await });
    tokio::time::timeout(secs(2), barrier.reached())
        .await
        .unwrap();
    let cap = r.caps.built().last().unwrap().clone();
    assert!(cap.is_valid());
    r.client.note_network_down();
    let still_valid = cap.is_valid();
    barrier.release();
    assert_eq!(
        cleanup.await.unwrap(),
        1,
        "a matched acknowledgement may still retire the already sent delete"
    );
    drop(frozen);
    r.client.cleanup().await;
    assert!(r.router.mappings().is_empty());
    assert!(!r.client.have_mapping());
    r.shutdown().await;
    assert!(
        !still_valid,
        "network-down must invalidate an already validated cleanup cap before its next send"
    );
}

#[tokio::test]
async fn prefix_change_does_not_split_a_wire_identity() {
    alias_cleanup_case(true, false, true).await;
    alias_cleanup_case(false, false, true).await;
}

#[tokio::test]
async fn cancel_initial_pcp_by_same_port_rebind() {
    let r = rig_with(Opts {
        router: RouterOptions {
            pmp: false,
            ..RouterOptions::default()
        },
        ..Opts::default()
    })
    .await;
    r.client.set_local_port(PORT).unwrap();
    r.client.check_network().await;
    r.client.probe().await.unwrap();
    let frozen = FrozenTime::new();
    let barrier = r.router.barrier(RequestKind::PcpMap);
    r.client.get_cached_mapping_or_start_creating_one();
    barrier.reached().await;
    let original = r.client.owned_snapshot()[0].clone();
    r.client.note_rebind(Some(PORT));
    barrier.release();
    while r.client.reap() != 0 {
        tokio::task::yield_now().await;
    }
    drop(frozen);
    r.settle().await;
    let orphan = &r.client.owned_snapshot()[0];
    assert_eq!(orphan.state(), crate::owned::RuleState::Orphaned);
    assert_eq!(orphan.rule, original.rule, "retain the original PCP nonce");
    assert_eq!(orphan.router_expiry(), original.router_expiry());
    r.client.check_network().await;
    for _ in 0..3 {
        r.advance(secs(700));
        r.client.tick().await;
        r.settle().await;
    }
    let recovered = r.client.have_mapping();
    let entries = r.client.owned_snapshot();
    r.shutdown().await;
    assert!(
        recovered,
        "cancelled PCP identity never recovered: {entries:?}"
    );
}

// Drop during a live MAP claim, extended to renewals and an operation runtime torn down
// outside any runtime context. Request barriers replace timing sleeps.
async fn drop_claim_case(pcp: bool, renewal: bool, no_runtime: bool) {
    let r = rig_with(Opts {
        router: RouterOptions {
            pmp: !pcp,
            ..RouterOptions::default()
        },
        ..Opts::default()
    })
    .await;
    if renewal {
        r.map().await.unwrap();
        r.advance(secs(3601));
    } else {
        r.client.set_local_port(PORT).unwrap();
        r.client.check_network().await;
        r.client.probe().await.unwrap();
    }
    let kind = if pcp {
        RequestKind::PcpMap
    } else {
        RequestKind::PmpMap
    };
    let map_reply = r.router.barrier(kind);
    let delete = r.router.barrier(kind);
    let c = r.client.clone();
    if no_runtime {
        tokio::task::spawn_blocking(move || {
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(async {
                    let _frozen = FrozenTime::new();
                    c.get_cached_mapping_or_start_creating_one();
                    map_reply.reached().await;
                    assert!(c.owned_snapshot()[0].mapping());
                });
                assert!(tokio::runtime::Handle::try_current().is_err());
                c.release_blocking_best_effort();
                drop(rt); // aborts/drains the operation finalizer without an entered runtime
                drop(map_reply);
            })
            .join()
            .unwrap()
        })
        .await
        .unwrap();
    } else {
        let _frozen = FrozenTime::new();
        c.get_cached_mapping_or_start_creating_one();
        map_reply.reached().await;
        assert!(c.owned_snapshot()[0].mapping());
        c.release_blocking_best_effort();
        map_reply.release();
    }
    r.settle().await;
    let released = tokio::time::timeout(secs(1), delete.reached())
        .await
        .is_ok();
    delete.release();
    let table = r.router.mappings();
    let sends = delete_requests(&r.router);
    let creates = r.creates_and_renewals().len();
    r.client.release_blocking_best_effort();
    r.client.cleanup().await;
    assert!(!r.client.have_mapping());
    r.shutdown().await;
    assert!(
        released,
        "finalizer skipped delete: pcp={pcp}, renewal={renewal}, no_runtime={no_runtime}"
    );
    assert!(table.is_empty());
    assert_eq!(sends, 1);
    assert_eq!(
        creates,
        if renewal { 2 } else { 1 },
        "no post-release create"
    );
}

#[tokio::test]
async fn drop_during_live_map_claim() {
    for pcp in [false, true] {
        for renewal in [false, true] {
            drop_claim_case(pcp, renewal, false).await;
        }
    }
}

#[tokio::test]
async fn drop_claim_during_no_runtime_teardown() {
    for pcp in [false, true] {
        for renewal in [false, true] {
            drop_claim_case(pcp, renewal, true).await;
        }
    }
}

#[tokio::test]
async fn close_during_external_cleanup_validation() {
    let mut observed = Vec::new();
    for pcp in [false, true] {
        let r = rig_with(Opts {
            router: RouterOptions {
                pmp: !pcp,
                ..RouterOptions::default()
            },
            ..Opts::default()
        })
        .await;
        let caps = Arc::new(PausedCleanupCaps {
            inner: r.caps.clone(),
            pause: std::sync::atomic::AtomicBool::new(false),
            entered: tokio::sync::Notify::new(),
            gate: (Mutex::new(false), std::sync::Condvar::new()),
        });
        let (client, _) = Client::new(Config {
            lookup: r.lookup.clone(),
            caps: caps.clone(),
            clock: r.clock.clone(),
            protos: ProtoSet::BOTH,
            advertise_nonpublic_external: true,
            lifetime: requested_lifetime(),
        });
        r.router.set_lifetime_override(Some(86_400));
        client.set_local_port(PORT).unwrap();
        client.tick().await;
        while client.attempt_in_flight() || client.reap() != 0 {
            tokio::task::yield_now().await;
        }
        r.advance(secs(7201));
        client.expire_if_due();
        let frozen = FrozenTime::new();
        let opener = OpenCapsOnDrop(caps.clone());
        caps.pause.store(true, std::sync::atomic::Ordering::SeqCst);
        let c = client.clone();
        let cleanup = tokio::spawn(async move { c.cleanup().await });
        tokio::time::timeout(secs(1), caps.entered.notified())
            .await
            .unwrap();
        let c = client.clone();
        let close = tokio::spawn(async move { c.close(secs(1)).await });
        wait_for_close(&client).await;
        drop(opener);
        cleanup.await.unwrap();
        close.await.unwrap();
        drop(frozen);
        let deletes = delete_requests(&r.router);
        let entries = client.owned_snapshot();
        r.shutdown().await;
        observed.push((pcp, deletes, entries));
    }
    assert!(
        observed.iter().all(|(_, deletes, _)| *deletes == 1),
        "close skipped externally claimed rule: {observed:?}"
    );
}

#[tokio::test]
async fn cancel_cleanup_reservations_and_recovery_spacing() {
    for pcp in [false, true] {
        for exhausted in [false, true] {
            let r = rig_with(Opts {
                router: RouterOptions {
                    pmp: !pcp,
                    ..RouterOptions::default()
                },
                ..Opts::default()
            })
            .await;
            r.map().await.unwrap();
            // Make a real owned orphan without scheduling a background cleanup.
            let id = r.client.owned_snapshot()[0].id;
            {
                let mut st = r.client.state();
                st.mapping = None;
                st.owned.orphan(id);
            }
            if exhausted {
                r.router.set_drop_deletes(true);
                for _ in 0..3 {
                    r.client.cleanup().await;
                }
                r.advance(secs(600));
            }
            let frozen = FrozenTime::new();
            let before = delete_requests(&r.router);
            let barrier = r.router.barrier(if pcp {
                RequestKind::PcpMap
            } else {
                RequestKind::PmpMap
            });
            let c = r.client.clone();
            let job = tokio::spawn(async move { c.cleanup().await });
            barrier.reached().await;
            job.abort();
            drop(job.await);
            barrier.release();
            drop(frozen);
            assert!(
                r.client
                    .owned_snapshot()
                    .iter()
                    .all(|e| !e.deleting() && !e.mapping())
            );
            assert_eq!(delete_requests(&r.router), before + 1);
            r.router.set_drop_deletes(false);
            if exhausted {
                let sent = delete_requests(&r.router);
                for _ in 0..599 {
                    r.advance(secs(1));
                    r.client.cleanup().await;
                }
                assert_eq!(delete_requests(&r.router), sent);
                r.advance(secs(1));
            }
            assert_eq!(r.client.cleanup().await, 1);
            assert_eq!(r.client.owned_rules(), 0);
            r.shutdown().await;
        }
    }
}

#[tokio::test]
async fn reset_on_other_gateway_must_not_retire_old_rule() {
    let mut observed = Vec::new();
    for pcp in [false, true] {
        let r = rig_with(Opts {
            router: RouterOptions {
                pmp: !pcp,
                ..RouterOptions::default()
            },
            protos: ProtoSet { pmp: !pcp, pcp },
            ..Opts::default()
        })
        .await;
        exhaust_unknown_slots(&r, pcp).await;
        let original = r.client.owned_snapshot()[0].clone();
        let old = original.id;
        r.caps.set_present(GW1, false);
        let router2 = FakeRouter::start(RouterOptions {
            pmp: !pcp,
            ..RouterOptions::default()
        })
        .await
        .unwrap();
        r.caps.add(GW2, router2.endpoint());
        r.lookup.set(gateway(GW2));
        r.client.check_network().await;
        r.settle().await;
        r.advance(secs(3));
        r.client.tick().await;
        r.settle().await;
        assert!(r.client.have_mapping());
        assert_eq!(r.client.owned_rules(), 2);
        assert_router_inventories(&r.client, &[(GW1, &r.router), (GW2, &router2)]);
        router2.reboot();
        router2.set_epoch(10);
        r.advance(secs(601));
        r.client.probe().await.unwrap();
        r.settle().await;
        assert_router_inventories(&r.client, &[(GW1, &r.router), (GW2, &router2)]);
        let retained = r.client.owned_snapshot().iter().any(|e| e.id == old);
        if let Some(retained) = r.client.owned_snapshot().iter().find(|e| e.id == old) {
            assert_eq!(
                retained.rule, original.rule,
                "other-router reset must retain the PCP nonce"
            );
            assert_eq!(retained.router_expiry(), original.router_expiry());
        }
        assert!(
            r.client
                .owned_snapshot()
                .iter()
                .all(|e| e.gateway.gw == GW1),
            "B's lost rules should retire"
        );
        let old_still_exists = r.router.mappings().len();
        observed.push((pcp, retained, old_still_exists));
        router2.shutdown().await;
        r.shutdown().await;
    }
    assert!(
        observed
            .iter()
            .all(|(_, retained, actual)| *retained && *actual == 1),
        "other-router reset freed unrelated ownership: {observed:?}"
    );
}

/// Conservation of possible router ownership, not just endpoint trust: an active lease is
/// owned by its held mapping; a MAP or
/// delete claim is owned by its future; all other entries must be cleanup orphans. Fenced and
/// terminal unacknowledged orphans remain counted, never classified as acknowledged gone.
fn assert_owned_invariant(client: &Client<TestCap>) {
    use crate::owned::{MAX_OWNED, RuleState};
    let st = client.state();
    st.owned.model.check(st.owned.entries());
    assert!(st.owned.len() <= MAX_OWNED);
    for (i, e) in st.owned.entries().iter().enumerate() {
        assert!(!(e.mapping() && e.deleting()), "two live operations: {e:?}");
        for other in &st.owned.entries()[..i] {
            assert!(
                !(e.gateway.gw == other.gateway.gw
                    && e.gateway.self_ip == other.gateway.self_ip
                    && e.gateway.if_index == other.gateway.if_index
                    && e.rule.internal() == other.rule.internal()),
                "aliased ownership"
            );
        }
        if e.deleting() {
            assert_eq!(e.state(), RuleState::Orphaned);
        } else if !e.mapping() {
            match e.state() {
                RuleState::Pending => panic!("unclaimed pending rule: {e:?}"),
                RuleState::Active => assert!(
                    st.mapping.as_ref().is_some_and(|h| h.rule_id == e.id),
                    "active rule has no lease owner"
                ),
                RuleState::Orphaned => {
                    if st.phase == Phase::Running && e.releasable() && st.disabled.is_none() {
                        assert!(
                            st.owned.next_cleanup(client.now()).is_some(),
                            "orphan has no cleanup schedule"
                        );
                    }
                }
            }
        }
    }
    if let Some(h) = &st.mapping {
        let e = st
            .owned
            .get(h.rule_id)
            .expect("held mapping lost ownership");
        assert_eq!(e.state(), RuleState::Active);
        assert_eq!(e.rule, h.m.rule());
    }
    if st.phase == Phase::Closed {
        assert!(st.mapping.is_none());
    }
}

/// Check conservation against all participating routers. Only use real fake-router reboots
/// here: older unit tests also inject an epoch rollback without actually clearing its table.
fn assert_router_inventory(client: &Client<TestCap>, gw: Ipv4Addr, router: &FakeRouter) {
    assert_router_inventories(client, &[(gw, router)]);
}

#[tokio::test]
async fn cancel_close_preserves_final_release() {
    for pcp in [false, true] {
        let r = rig_with(Opts {
            router: RouterOptions {
                pmp: !pcp,
                ..RouterOptions::default()
            },
            ..Opts::default()
        })
        .await;
        r.map().await.unwrap();
        r.router.set_drop_deletes(true);
        let kind = if pcp {
            RequestKind::PcpMap
        } else {
            RequestKind::PmpMap
        };
        let frozen = FrozenTime::new();
        let first = r.router.barrier(kind);
        let c = r.client.clone();
        let close = tokio::spawn(async move { c.close(secs(10)).await });
        first.reached().await;
        assert_owned_invariant(&r.client);
        let final_delete = r.router.barrier(kind);
        r.router.set_drop_deletes(false);
        close.abort();
        assert!(close.await.unwrap_err().is_cancelled());
        first.release();
        let phase = r.client.state().phase;
        let released = tokio::time::timeout(secs(1), final_delete.reached())
            .await
            .is_ok();
        final_delete.release();
        drop(frozen);
        assert_router_inventory(&r.client, GW1, &r.router);
        let table = r.router.mappings();
        r.client.release_blocking_best_effort(); // clean up if the final release was lost
        r.shutdown().await;
        assert_eq!(
            phase,
            Phase::Closed,
            "cancelled close left a half-closed owner"
        );
        assert!(released, "cancelled close discarded release duty");
        assert!(table.is_empty());
    }
}

#[tokio::test]
async fn close_deadline_preserves_unpolled_cleanup_handoff() {
    for pcp in [false, true] {
        let r = rig_with(Opts {
            router: RouterOptions {
                pmp: !pcp,
                ..RouterOptions::default()
            },
            ..Opts::default()
        })
        .await;
        let caps = Arc::new(PausedCleanupCaps {
            inner: r.caps.clone(),
            pause: std::sync::atomic::AtomicBool::new(false),
            entered: tokio::sync::Notify::new(),
            gate: (Mutex::new(false), std::sync::Condvar::new()),
        });
        let (client, _) = Client::new(Config {
            lookup: r.lookup.clone(),
            caps: caps.clone(),
            clock: r.clock.clone(),
            protos: ProtoSet::BOTH,
            advertise_nonpublic_external: true,
            lifetime: requested_lifetime(),
        });
        client.set_local_port(PORT).unwrap();
        client.tick().await;
        while client.attempt_in_flight() || client.reap() != 0 {
            tokio::task::yield_now().await;
        }
        {
            let mut st = client.state();
            let id = st.mapping.take().unwrap().rule_id;
            st.owned.orphan(id);
            client.publish(&mut st);
        }
        let frozen = FrozenTime::new();
        let opener = OpenCapsOnDrop(caps.clone());
        caps.pause.store(true, std::sync::atomic::Ordering::SeqCst);
        let mut cleanup = Box::pin(client.cleanup());
        tokio::select! { _ = caps.entered.notified() => {}, _ = &mut cleanup => panic!("cleanup did not pause") }
        assert_owned_invariant(&client);
        let budget = Duration::from_millis(20);
        let start = tokio::time::Instant::now();
        finish_at_deadline(client.close(budget), budget).await;
        assert_eq!(start.elapsed(), budget + Duration::from_millis(1));
        assert_eq!(client.state().phase, Phase::Closed);
        assert!(
            client.owned_snapshot()[0].deleting(),
            "close stole a live reservation"
        );
        assert_owned_invariant(&client);
        let delete = r.router.barrier(if pcp {
            RequestKind::PcpMap
        } else {
            RequestKind::PmpMap
        });
        drop(cleanup); // a caller which was not polled during close now returns the claim
        drop(opener);
        let released = tokio::time::timeout(secs(1), delete.reached())
            .await
            .is_ok();
        delete.release();
        drop(frozen);
        assert_router_inventory(&client, GW1, &r.router);
        assert!(!client.have_mapping());
        let table = r.router.mappings();
        r.shutdown().await;
        assert!(released, "deadline discarded a deferred release");
        assert!(table.is_empty());
    }
}

/// Exhaustive MAP cancellation cuts: before the future's first poll and after the router
/// commits but before its reply, for create/renew/adopt, every invalidation and both protocols.
#[tokio::test]
async fn exhaustive_map_cancellation_points() {
    for pcp in [false, true] {
        for mode in 0..3 {
            for sent in [false, true] {
                for action in 0..8 {
                    let r = rig_with(Opts {
                        router: RouterOptions {
                            pmp: !pcp,
                            ..RouterOptions::default()
                        },
                        ..Opts::default()
                    })
                    .await;
                    if mode != 0 {
                        r.map().await.unwrap();
                        r.advance(secs(if mode == 1 { 3601 } else { 3 }));
                        if mode == 2 {
                            let mut st = r.client.state();
                            let id = st.mapping.take().unwrap().rule_id;
                            st.owned.orphan(id);
                            r.client.publish(&mut st);
                        }
                    } else {
                        r.client.set_local_port(PORT).unwrap();
                        r.client.check_network().await;
                        r.client.probe().await.unwrap();
                    }
                    assert_router_inventory(&r.client, GW1, &r.router);
                    let kind = if pcp {
                        RequestKind::PcpMap
                    } else {
                        RequestKind::PmpMap
                    };
                    let frozen = FrozenTime::new();
                    let reply = sent.then(|| r.router.barrier(kind));
                    r.client.get_cached_mapping_or_start_creating_one();
                    assert!(
                        r.client.owned_snapshot()[0].mapping(),
                        "mode={mode},sent={sent},action={action}"
                    );
                    assert_owned_invariant(&r.client);
                    if let Some(reply) = &reply {
                        reply.reached().await;
                    }
                    assert_router_inventory(&r.client, GW1, &r.router);
                    let router2 = if action == 3 {
                        Some(
                            FakeRouter::start(RouterOptions {
                                pmp: !pcp,
                                ..RouterOptions::default()
                            })
                            .await
                            .unwrap(),
                        )
                    } else {
                        None
                    };
                    let possible_rule = sent || mode != 0;
                    let final_delete =
                        (action == 5 && possible_rule).then(|| r.router.barrier(kind));
                    let before = delete_requests(&r.router);
                    match action {
                        0 => r.client.note_rebind(Some(PORT)),
                        1 => {
                            r.client.set_local_port(PORT + 1).unwrap();
                        }
                        2 => r.client.note_network_down(),
                        3 => {
                            r.router.set_drop_deletes(true);
                            r.caps.add(GW2, router2.as_ref().unwrap().endpoint());
                            r.lookup.set(gateway(GW2));
                            r.client.check_network().await;
                        }
                        4 => r.client.disable(DisableReason::OnlyTcp443),
                        5 => r.client.release_blocking_best_effort(),
                        6 => r.client.close(secs(1)).await,
                        _ => r
                            .client
                            .state()
                            .inflight
                            .as_ref()
                            .unwrap()
                            .abort
                            .as_ref()
                            .unwrap()
                            .abort(),
                    }
                    assert_owned_invariant(&r.client);
                    if let Some(reply) = reply {
                        reply.release();
                    }
                    // Once the MAP guard settled, unrelated cleanup may legitimately need its
                    // timeout (the network-change cut deliberately loses DELETE replies).
                    while r.client.owned_snapshot().iter().any(|e| e.mapping()) {
                        assert_owned_invariant(&r.client);
                        tokio::task::yield_now().await;
                    }
                    drop(frozen);
                    r.settle().await;
                    if let Some(delete) = final_delete {
                        tokio::time::timeout(secs(1), delete.reached())
                            .await
                            .unwrap();
                        delete.release();
                    }
                    assert_router_inventory(&r.client, GW1, &r.router);
                    if !possible_rule && action != 3 {
                        assert_eq!(
                            r.client.owned_rules(),
                            0,
                            "unsent fresh reservation must retire"
                        );
                        assert_eq!(
                            delete_requests(&r.router),
                            before,
                            "unsent identity must not be deleted"
                        );
                    }
                    if action == 2 || action == 4 {
                        assert_eq!(delete_requests(&r.router), before, "fenced release sent");
                    }
                    if action == 2 {
                        // A down network remains unsent even through terminal teardown.
                        r.client.close(secs(1)).await;
                        assert_eq!(delete_requests(&r.router), before);
                    } else if action != 5 && action != 6 {
                        if action == 4 {
                            r.client.enable();
                        }
                        r.client.check_network().await;
                        assert_owned_invariant(&r.client);
                        r.advance(secs(700));
                        r.client.tick().await;
                        r.settle().await;
                        assert!(
                            r.client.have_mapping(),
                            "recovery failed: pcp={pcp}, mode={mode}, sent={sent}, action={action}"
                        );
                        r.client.cleanup().await;
                        assert_router_inventory(&r.client, GW1, &r.router);
                    }
                    if let Some(router2) = router2 {
                        assert_router_inventories(&r.client, &[(GW1, &r.router), (GW2, &router2)]);
                        let originals: Vec<_> = r
                            .client
                            .owned_snapshot()
                            .into_iter()
                            .filter(|e| e.gateway.gw == GW1)
                            .map(|e| (e.id, e.rule))
                            .collect();
                        router2.reboot();
                        router2.set_epoch(10);
                        r.advance(secs(601));
                        r.client.probe().await.unwrap();
                        r.settle().await;
                        for (id, rule) in originals {
                            assert_eq!(r.client.state().owned.get(id).unwrap().rule, rule);
                        }
                        assert_router_inventory(&r.client, GW1, &r.router);
                        assert_router_inventories(&r.client, &[(GW1, &r.router), (GW2, &router2)]);
                        r.client.close(secs(1)).await;
                        assert_router_inventories(&r.client, &[(GW1, &r.router), (GW2, &router2)]);
                        router2.shutdown().await;
                    }
                    assert_owned_invariant(&r.client);
                    r.shutdown().await;
                }
            }
        }
    }
}

#[tokio::test]
async fn network_down_fences_deferred_drop_release() {
    for pcp in [false, true] {
        let r = rig_with(Opts {
            router: RouterOptions {
                pmp: !pcp,
                ..RouterOptions::default()
            },
            ..Opts::default()
        })
        .await;
        r.map().await.unwrap();
        r.advance(secs(3601));
        r.client.get_cached_mapping_or_start_creating_one(); // guard captured, future not polled
        assert!(r.client.owned_snapshot()[0].mapping());
        r.client.release_blocking_best_effort();
        assert_owned_invariant(&r.client);
        r.client.note_network_down(); // must fence finalizers even though phase is Closed
        r.settle().await;
        // Drain loopback work without relying on a fixed delay.
        r.client.cleanup().await;
        assert_router_inventory(&r.client, GW1, &r.router);
        let down = r.client.owned_snapshot().iter().all(|e| !e.releasable());
        let cap_valid = r.caps.built().iter().any(|cap| cap.is_valid());
        let deletes = delete_requests(&r.router);
        r.shutdown().await;
        assert!(
            down && !cap_valid,
            "closed client did not fence its pending release capability"
        );
        assert_eq!(deletes, 0);
    }
}

struct OpenCapsOnDrop(Arc<PausedCleanupCaps>);
impl Drop for OpenCapsOnDrop {
    fn drop(&mut self) {
        *lock(&self.0.gate.0) = true;
        self.0.gate.1.notify_all();
    }
}

async fn settle_checked(client: &Client<TestCap>) {
    tokio::time::timeout(secs(5), async {
        loop {
            assert_owned_invariant(client);
            if !client.attempt_in_flight() && client.reap() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("operation failed to return ownership");
}

/// Each cleanup await cut, with one/three simultaneous claims and every teardown route.
#[tokio::test]
async fn exhaustive_cleanup_claim_handoffs() {
    for pcp in [false, true] {
        for batch in [1, 3] {
            for validation in [false, true] {
                for action in 0..4 {
                    let r = rig_with(Opts {
                        router: RouterOptions {
                            pmp: !pcp,
                            ..RouterOptions::default()
                        },
                        ..Opts::default()
                    })
                    .await;
                    let caps = Arc::new(PausedCleanupCaps {
                        inner: r.caps.clone(),
                        pause: std::sync::atomic::AtomicBool::new(false),
                        entered: tokio::sync::Notify::new(),
                        gate: (Mutex::new(false), std::sync::Condvar::new()),
                    });
                    let opener = OpenCapsOnDrop(caps.clone());
                    let (client, _) = Client::new(Config {
                        lookup: r.lookup.clone(),
                        caps: caps.clone(),
                        clock: r.clock.clone(),
                        protos: ProtoSet::BOTH,
                        advertise_nonpublic_external: true,
                        lifetime: requested_lifetime(),
                    });
                    client.check_network().await;
                    client.probe().await.unwrap();
                    // Build several real router rules without scheduling background cleanup between them.
                    for i in 0..batch {
                        {
                            let mut st = client.state();
                            st.local_port = NonZeroU16::new(PORT + i);
                        }
                        r.advance(secs(3));
                        assert_owned_invariant(&client);
                        client.get_cached_mapping_or_start_creating_one();
                        settle_checked(&client).await;
                        {
                            let mut st = client.state();
                            let id = st.mapping.take().unwrap().rule_id;
                            st.owned.orphan(id);
                            client.publish(&mut st);
                        }
                        assert_router_inventory(&client, GW1, &r.router);
                    }
                    let frozen = FrozenTime::new();
                    let reply = (!validation).then(|| {
                        r.router.barrier(if pcp {
                            RequestKind::PcpMap
                        } else {
                            RequestKind::PmpMap
                        })
                    });
                    caps.pause
                        .store(validation, std::sync::atomic::Ordering::SeqCst);
                    let c = client.clone();
                    let cleanup = tokio::spawn(async move { c.cleanup().await });
                    if let Some(reply) = &reply {
                        reply.reached().await;
                    } else {
                        tokio::time::timeout(secs(1), caps.entered.notified())
                            .await
                            .unwrap();
                    }
                    assert!(client.owned_snapshot().iter().all(|e| e.deleting()));
                    assert_router_inventory(&client, GW1, &r.router);
                    let before = delete_requests(&r.router);
                    match action {
                        0 => cleanup.abort(),
                        1 => client.release_blocking_best_effort(),
                        2 => client.close(secs(1)).await,
                        _ => client.note_network_down(),
                    }
                    assert_owned_invariant(&client);
                    drop(opener);
                    if let Some(reply) = reply {
                        reply.release();
                    }
                    drop(cleanup.await);
                    drop(frozen);
                    assert!(
                        client
                            .owned_snapshot()
                            .iter()
                            .all(|e| !e.deleting() && !e.mapping())
                    );
                    assert_router_inventory(&client, GW1, &r.router);
                    if action == 0 {
                        assert_eq!(client.cleanup().await, usize::from(batch));
                        assert!(client.owned_snapshot().is_empty());
                    } else if action == 1 {
                        tokio::time::timeout(secs(1), async {
                            while delete_requests(&r.router) < before + usize::from(batch) {
                                tokio::task::yield_now().await;
                            }
                        })
                        .await
                        .unwrap();
                        assert_eq!(
                            delete_requests(&r.router),
                            before + usize::from(batch),
                            "one final send per claimed rule"
                        );
                    } else if action == 2 {
                        assert!(
                            client.owned_snapshot().is_empty(),
                            "close did not retire handed-back claims"
                        );
                    } else {
                        assert_eq!(
                            delete_requests(&r.router),
                            before,
                            "network-down sent another delete"
                        );
                    }
                    client.cleanup().await;
                    assert_router_inventory(&client, GW1, &r.router);
                    if action != 3 {
                        assert!(r.router.mappings().is_empty());
                    }
                    assert!(!client.have_mapping());
                    client.close(secs(1)).await;
                    assert_router_inventory(&client, GW1, &r.router);
                    r.shutdown().await;
                }
            }
        }
    }
}

#[tokio::test]
async fn drop_during_close_consumes_final_duty_once() {
    for pcp in [false, true] {
        let r = rig_with(Opts {
            router: RouterOptions {
                pmp: !pcp,
                ..RouterOptions::default()
            },
            ..Opts::default()
        })
        .await;
        r.map().await.unwrap();
        let kind = if pcp {
            RequestKind::PcpMap
        } else {
            RequestKind::PmpMap
        };
        r.router.set_drop_deletes(true);
        let frozen = FrozenTime::new();
        let in_close = r.router.barrier(kind);
        let c = r.client.clone();
        let close = tokio::spawn(async move { c.close(secs(2)).await });
        in_close.reached().await;
        assert_owned_invariant(&r.client);
        assert!(r.client.owned_snapshot()[0].deleting());
        let final_delete = r.router.barrier(kind);
        let duplicate = r.router.barrier(kind);
        r.client.release_blocking_best_effort();
        r.router.set_drop_deletes(false);
        in_close.release();
        tokio::time::advance(crate::cap::EXCHANGE_TIMEOUT + Duration::from_millis(1)).await;
        close.await.unwrap();
        tokio::time::timeout(secs(1), final_delete.reached())
            .await
            .unwrap();
        final_delete.release();
        drop(frozen);
        let duplicated = tokio::time::timeout(secs(1), duplicate.reached())
            .await
            .is_ok();
        duplicate.release();
        assert_router_inventory(&r.client, GW1, &r.router);
        assert!(!r.client.have_mapping());
        assert!(r.router.mappings().is_empty());
        let count = delete_requests(&r.router);
        r.shutdown().await;
        assert!(
            !duplicated,
            "close rearmed a final duty already consumed by Drop"
        );
        assert_eq!(count, 2, "one interrupted close send plus one final send");
    }
}

async fn expired_renewal_cancel_case(pcp: bool, clock_aging: bool, unpolled: bool) {
    let r = rig_with(Opts {
        router: RouterOptions {
            pmp: !pcp,
            ..RouterOptions::default()
        },
        ..Opts::default()
    })
    .await;
    r.map().await.unwrap();
    r.advance(secs(3601));
    r.client.check_clock();
    let frozen = FrozenTime::new();
    let reply = (!unpolled).then(|| {
        r.router.barrier(if pcp {
            RequestKind::PcpMap
        } else {
            RequestKind::PmpMap
        })
    });
    r.client.get_cached_mapping_or_start_creating_one();
    if let Some(reply) = &reply {
        reply.reached().await;
    }
    let original = r.client.owned_snapshot()[0].clone();
    if clock_aging {
        r.clock.suspend(secs(3600));
        r.lease_clock.advance(3600);
        assert!(r.client.check_clock());
    } else {
        r.advance(secs(3600));
        assert!(r.client.expire_if_due());
    }
    let expired = &r.client.owned_snapshot()[0];
    assert!(
        expired.mapping(),
        "expiry must retain the operation reservation"
    );
    assert_eq!(
        expired.rule, original.rule,
        "expiry must retain the PCP nonce"
    );
    assert_eq!(
        expired.router_expiry(),
        original.router_expiry(),
        "trust expiry is not ownership expiry"
    );
    assert!(!r.client.have_mapping());
    r.client.note_rebind(Some(PORT));
    if let Some(reply) = reply {
        reply.release();
    }
    while r.client.reap() != 0 {
        tokio::task::yield_now().await;
    }
    drop(frozen);
    let state = r.client.owned_snapshot()[0].state();
    let cleanup_due = r.client.schedule().cleanup_due;
    r.client.check_network().await;
    for _ in 0..3 {
        r.advance(secs(700));
        r.client.tick().await;
        while r.client.reap() != 0 {
            tokio::task::yield_now().await;
        }
    }
    let recovered = r.client.have_mapping();
    r.shutdown().await;
    assert_eq!(
        state,
        crate::owned::RuleState::Orphaned,
        "unowned Active; cleanup={cleanup_due:?}, recovered={recovered}"
    );
    assert!(
        cleanup_due.is_some(),
        "ownerless entry has no cleanup deadline"
    );
    assert!(recovered);
}

#[tokio::test]
async fn expired_pcp_renewal_cancel() {
    expired_renewal_cancel_case(true, false, false).await;
}
#[tokio::test]
async fn expired_pmp_renewal_cancel() {
    expired_renewal_cancel_case(false, false, false).await;
}

#[tokio::test]
async fn cancel_close_waiting_external_cleanup_then_foreign_drop() {
    use std::{
        future::{Future, poll_fn},
        task::Poll,
    };
    for pcp in [false, true] {
        for network_down in [false, true] {
            let r = rig_with(Opts {
                router: RouterOptions {
                    pmp: !pcp,
                    ..RouterOptions::default()
                },
                ..Opts::default()
            })
            .await;
            let caps = Arc::new(PausedCleanupCaps {
                inner: r.caps.clone(),
                pause: std::sync::atomic::AtomicBool::new(false),
                entered: tokio::sync::Notify::new(),
                gate: (Mutex::new(false), std::sync::Condvar::new()),
            });
            let opener = OpenCapsOnDrop(caps.clone());
            let (client, _) = Client::new(Config {
                lookup: r.lookup.clone(),
                caps: caps.clone(),
                clock: r.clock.clone(),
                protos: ProtoSet::BOTH,
                advertise_nonpublic_external: true,
                lifetime: requested_lifetime(),
            });
            client.set_local_port(PORT).unwrap();
            client.tick().await;
            settle_checked(&client).await;
            {
                let mut st = client.state();
                let id = st.mapping.take().unwrap().rule_id;
                st.owned.orphan(id);
                client.publish(&mut st);
            }
            let frozen = FrozenTime::new();
            caps.pause.store(true, std::sync::atomic::Ordering::SeqCst);
            let mut cleanup = Box::pin(client.cleanup());
            tokio::select! {
                _ = caps.entered.notified() => {},
                _ = &mut cleanup => panic!("cleanup did not pause"),
            }
            let mut close = Box::pin(client.close(secs(10)));
            poll_fn(|cx| {
                assert!(close.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            assert_eq!(client.state().phase, Phase::Closing);
            assert!(client.owned_snapshot()[0].deleting());
            drop(close);
            assert_eq!(client.state().phase, Phase::Closed);
            if network_down {
                client.note_network_down();
            }
            let delete = (!network_down).then(|| {
                r.router.barrier(if pcp {
                    RequestKind::PcpMap
                } else {
                    RequestKind::PmpMap
                })
            });
            std::thread::scope(|scope| {
                scope
                    .spawn(move || {
                        assert!(tokio::runtime::Handle::try_current().is_err());
                        drop(cleanup);
                    })
                    .join()
                    .unwrap();
            });
            drop(opener);
            if let Some(delete) = delete {
                tokio::time::timeout(secs(1), delete.reached())
                    .await
                    .unwrap();
                delete.release();
            }
            drop(frozen);
            assert_owned_invariant(&client);
            assert_eq!(delete_requests(&r.router), usize::from(!network_down));
            client.release_blocking_best_effort();
            r.shutdown().await;
        }
    }
}

#[tokio::test]
async fn clock_aged_renewal_cancel() {
    for pcp in [false, true] {
        expired_renewal_cancel_case(pcp, true, false).await;
    }
}

#[tokio::test]
async fn expired_unpolled_renewal_cancel() {
    for pcp in [false, true] {
        for aged in [false, true] {
            expired_renewal_cancel_case(pcp, aged, true).await;
        }
    }
}

#[tokio::test]
async fn final_release_fenced_before_socket_send() {
    for pcp in [false, true] {
        for disable in [false, true] {
            let r = rig_with(Opts {
                router: RouterOptions {
                    pmp: !pcp,
                    ..RouterOptions::default()
                },
                ..Opts::default()
            })
            .await;
            r.map().await.unwrap();
            let before = delete_requests(&r.router);
            let entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let (c, hit) = (r.client.clone(), entered.clone());
            let hook = crate::cap::send_tests::set_send_hook(move || {
                if disable {
                    c.disable(DisableReason::OnlyTcp443);
                } else {
                    c.note_network_down();
                }
                hit.store(true, std::sync::atomic::Ordering::SeqCst);
            });
            r.client.release_blocking_best_effort();
            drop(hook);
            r.settle().await;
            assert!(
                entered.load(std::sync::atomic::Ordering::SeqCst),
                "final-send cut not reached"
            );
            // A loopback-only marker round drains earlier datagrams; its independent policy
            // cannot un-fence the client's release capability. Count every post-fence delete.
            let marker = TestCap::new(gateway(GW1), &r.router, PolicyHandle::new(true));
            oneshot::probe(
                &*marker,
                ProtoSet {
                    pmp: true,
                    pcp: false,
                },
            )
            .await
            .unwrap();
            let deletes = delete_requests(&r.router);
            assert_router_inventory(&r.client, GW1, &r.router);
            assert!(!r.client.have_mapping());
            let table = r.router.mappings();
            r.shutdown().await;
            assert_eq!(
                deletes, before,
                "final release emitted a datagram after its fence returned"
            );
            assert_eq!(table.len(), 1);
        }
    }
}

/// Aggregate physical router state, deduplicating aliases of the same fake endpoint. The
/// assignment must be injective: one ledger entry cannot explain rules on two routers, even
/// when their logical gateway/source/port/nonce values coincide. Unknown ledger slots need
/// not have a confirmed router rule, but they remain counted.
fn assert_router_inventories(client: &Client<TestCap>, routers: &[(Ipv4Addr, &FakeRouter)]) {
    assert_owned_invariant(client);
    let entries = client.owned_snapshot();
    let mut physical = HashMap::new();
    for (gw, router) in routers {
        let (aliases, _) = physical
            .entry(router.endpoint().addr)
            .or_insert_with(|| (Vec::new(), router.mappings()));
        aliases.push(*gw);
    }
    let actual: Vec<_> = physical
        .values()
        .flat_map(|(aliases, rules)| rules.iter().map(move |rule| (aliases, rule)))
        .collect();
    assert!(
        actual.len() <= entries.len() && actual.len() <= crate::owned::MAX_OWNED,
        "aggregate router ownership exceeds counted slots"
    );
    let candidates: Vec<Vec<usize>> = actual
        .iter()
        .map(|(aliases, rule)| {
            entries
                .iter()
                .enumerate()
                .filter_map(|(i, e)| {
                    (aliases.contains(&e.gateway.gw)
                        && rule.proto == 17
                        && e.gateway.self_ip == rule.client_ip
                        && e.rule.internal().get() == rule.internal
                        && match &e.rule {
                            Rule::Pcp { nonce, .. } => rule.nonce == Some(*nonce.as_bytes()),
                            Rule::Pmp { .. } => rule.nonce.is_none(),
                        })
                    .then_some(i)
                })
                .collect()
        })
        .collect();
    fn assign(row: usize, choices: &[Vec<usize>], used: &mut HashSet<usize>) -> bool {
        if row == choices.len() {
            return true;
        }
        for &owner in &choices[row] {
            if used.insert(owner) {
                if assign(row + 1, choices, used) {
                    return true;
                }
                used.remove(&owner);
            }
        }
        false
    }
    assert!(
        assign(0, &candidates, &mut HashSet::new()),
        "router rules have no injective ledger attribution: {actual:?}; ledger={entries:?}"
    );
}

#[tokio::test]
async fn oracle_rejects_unexplained_retirement() {
    use crate::ownership_model::{RefusalEvidence, Retirement};
    for fault in 0..7 {
        let r = rig().await;
        r.map().await.unwrap();
        r.router.reboot(); // true router state alone is not accepted client reset evidence
        {
            let mut st = r.client.state();
            let h = st.mapping.take().unwrap();
            let reason = match fault {
                0 => None,
                1 => Some(Retirement::Delete { matched: false }),
                2 => Some(Retirement::Expiry {
                    observed_at: r.clock.now(),
                }),
                3 => Some(Retirement::Reset {
                    observation: crate::ownership_model::ResetId::MISSING,
                    gateway: gateway(GW2),
                    proto: Proto::Pmp,
                }),
                4 => Some(Retirement::Reset {
                    observation: crate::ownership_model::ResetId::MISSING,
                    gateway: gateway(GW1),
                    proto: Proto::Pmp,
                }),
                5 => Some(Retirement::Refusal(RefusalEvidence::Unproven)),
                _ => Some(Retirement::ProvenUnsent),
            };
            if let Some(reason) = reason {
                st.owned.record_retirement(h.rule_id, reason);
            }
            st.owned.remove(h.rule_id); // inject a disappearance, with missing/false evidence
            r.client.publish(&mut st);
        }
        let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_owned_invariant(&r.client)
        }));
        r.shutdown().await;
        assert!(
            observed.is_err(),
            "oracle accepted unexplained/false retirement: fault={fault}"
        );
    }
}

#[tokio::test]
async fn oracle_injective_across_routers() {
    let r = rig().await;
    r.map().await.unwrap();
    let original = r.client.owned_snapshot()[0].rule.clone();
    {
        let mut st = r.client.state();
        let id = st.mapping.take().unwrap().rule_id;
        st.owned.orphan(id);
        st.local_port = NonZeroU16::new(PORT + 1);
        r.client.publish(&mut st);
    }
    r.advance(secs(3));
    r.client.get_cached_mapping_or_start_creating_one();
    r.settle().await;
    let unused = r
        .client
        .owned_snapshot()
        .into_iter()
        .find(|e| e.rule.internal().get() == PORT + 1)
        .unwrap()
        .rule;
    let cap1 = TestCap::new(gateway(GW1), &r.router, r.client.policy().clone());
    oneshot::delete(&*cap1, &unused).await.unwrap();
    // Two possible owners and two actual rules: a count bound alone cannot catch reuse.
    let router2 = FakeRouter::start(RouterOptions::default()).await.unwrap();
    let cap2 = TestCap::new(gateway(GW1), &router2, r.client.policy().clone());
    let rule = original;
    oneshot::map(&*cap2, &rule, requested_lifetime(), None)
        .await
        .unwrap();
    // The old per-router oracle attributes both physical rules to the same one entry.
    let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_router_inventories(&r.client, &[(GW1, &r.router), (GW1, &router2)])
    }));
    oneshot::delete(&*cap2, &rule).await.unwrap();
    router2.shutdown().await;
    r.shutdown().await;
    assert!(
        observed.is_err(),
        "oracle reused one ledger entry for two physical router rules"
    );
}

#[tokio::test]
async fn ownership_oracle_rejects_reset_before_admission() {
    use crate::ownership_model::Retirement;
    let r = rig().await;
    r.map().await.unwrap();
    {
        let mut st = r.client.state();
        let h = st.mapping.take().unwrap();
        let committed = h.lease.committed_at - secs(20);
        let observation = st.owned.model.accept_reset(
            gateway(GW1),
            Proto::Pmp,
            100,
            10,
            committed,
            committed + secs(1),
        );
        st.owned.record_retirement(
            h.rule_id,
            Retirement::Reset {
                observation,
                gateway: gateway(GW1),
                proto: Proto::Pmp,
            },
        );
        st.owned.remove(h.rule_id);
    }
    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let st = r.client.state();
        st.owned.model.check(st.owned.entries());
    }));
    assert_eq!(r.router.mappings().len(), 1, "the rule is still live");
    r.shutdown().await;
    assert!(
        rejected.is_err(),
        "historical reset cannot retire a later rule"
    );
}

#[tokio::test]
async fn expired_renewal_success_preserves_identity() {
    for pcp in [false, true] {
        for aged in [false, true] {
            let r = rig_with(Opts {
                router: RouterOptions {
                    pmp: !pcp,
                    ..RouterOptions::default()
                },
                ..Opts::default()
            })
            .await;
            r.map().await.unwrap();
            r.advance(secs(3601));
            r.client.check_clock();
            let frozen = FrozenTime::new();
            let reply = r.router.barrier(if pcp {
                RequestKind::PcpMap
            } else {
                RequestKind::PmpMap
            });
            r.client.get_cached_mapping_or_start_creating_one();
            reply.reached().await;
            let before = r.client.owned_snapshot()[0].clone();
            if aged {
                r.clock.suspend(secs(3600));
                r.lease_clock.advance(3600);
                assert!(r.client.check_clock());
            } else {
                r.advance(secs(3600));
                assert!(r.client.expire_if_due());
            }
            assert!(!r.client.have_mapping());
            assert_owned_invariant(&r.client);
            reply.release();
            while r.client.reap() != 0 {
                tokio::task::yield_now().await;
            }
            drop(frozen);
            r.settle().await;
            assert!(r.client.have_mapping());
            let after = r.client.owned_snapshot()[0].clone();
            assert_eq!(before.id, after.id);
            assert_eq!(before.rule, after.rule);
            assert_router_inventory(&r.client, GW1, &r.router);
            r.shutdown().await;
        }
    }
}

/// Close cannot replace an invalid cached capability: retain and fence ownership without I/O.
#[tokio::test]
async fn close_with_invalid_cached_capability_fences_retained_rule() {
    for pcp in [false, true] {
        let r = rig_with(Opts {
            router: RouterOptions {
                pmp: !pcp,
                ..RouterOptions::default()
            },
            ..Opts::default()
        })
        .await;
        r.map().await.unwrap();
        let builds = r.caps.builds();
        let lookups = r.lookup.calls();
        let received = r.router.counters().num_total_recv;
        let original = r.client.owned_snapshot()[0].clone();
        for cap in r.client.state().release_caps.values() {
            cap.invalidate();
        }

        r.client.close(secs(1)).await;
        assert_eq!(r.client.state().phase, Phase::Closed);
        assert!(!r.client.have_mapping());
        assert_eq!(r.client.owned_rules(), 1);
        let e = r.client.owned_snapshot()[0].clone();
        assert_eq!(e.id, original.id);
        assert_eq!(e.rule, original.rule);
        assert_eq!(e.state(), crate::owned::RuleState::Orphaned);
        assert!(!e.releasable(), "close must terminally fence the orphan");
        assert!(!e.mapping() && !e.deleting(), "reservation returned");
        assert!(
            e.retry_at.is_none(),
            "terminal validation failure must not schedule recovery"
        );
        assert_owned_invariant(&r.client);

        r.client.release_blocking_best_effort();
        assert_eq!(r.client.cleanup().await, 0);
        assert_eq!(
            r.caps.builds(),
            builds,
            "no replacement capability discovery"
        );
        assert_eq!(r.lookup.calls(), lookups, "no fresh gateway discovery");
        assert_eq!(r.router.counters().num_total_recv, received, "no sends");
        assert_eq!(delete_requests(&r.router), 0);
        assert_eq!(r.router.mappings().len(), 1, "router rule remains owned");
        assert_router_inventory(&r.client, GW1, &r.router);
        r.shutdown().await;
    }
}

#[tokio::test]
async fn fresh_bind_failure_releases_reservation() {
    let mut observed = Vec::new();
    for pcp in [false, true] {
        let r = rig_with(Opts {
            router: RouterOptions {
                pmp: !pcp,
                ..RouterOptions::default()
            },
            protos: ProtoSet { pmp: !pcp, pcp },
            ..Opts::default()
        })
        .await;
        r.client.set_local_port(PORT).unwrap();
        r.client.check_network().await;
        r.client.probe().await.unwrap();
        for cap in r.caps.built() {
            cap.inject_bind_error(Some(ADDR_NOT_AVAILABLE));
        }
        // A failed setup must not depend on successful cleanup to recover its slot.
        r.caps.set_present(GW1, false);
        let received = r.router.counters().num_total_recv;
        for offset in 0..5 {
            r.client.set_local_port(PORT + offset).unwrap();
            r.advance(secs(700));
            r.client.get_cached_mapping_or_start_creating_one();
            let started = r.client.attempt_in_flight();
            if started {
                assert_eq!(
                    r.client.owned_snapshot().last().unwrap().rule.proto(),
                    if pcp { Proto::Pcp } else { Proto::Pmp }
                );
            }
            r.settle().await;
            observed.push((pcp, offset, started, r.client.owned_rules()));
            assert!(r.router.mappings().is_empty());
            assert_router_inventory(&r.client, GW1, &r.router);
        }
        assert_eq!(delete_requests(&r.router), 0, "never delete an unsent rule");
        assert_eq!(
            r.router.counters().num_total_recv,
            received,
            "no MAP or DELETE"
        );
        r.shutdown().await;
    }
    assert!(
        observed
            .iter()
            .all(|(_, _, started, slots)| *started && *slots == 0),
        "failed setup pinned admission, including the fifth identity: {observed:?}"
    );
}

#[tokio::test]
async fn unsent_adoption_preserves_prior_expiry() {
    for pcp in [false, true] {
        for renewal in [false, true] {
            let r = rig_with(Opts {
                router: RouterOptions {
                    pmp: !pcp,
                    ..RouterOptions::default()
                },
                ..Opts::default()
            })
            .await;
            r.map().await.unwrap();
            let before = r.client.owned_snapshot()[0].clone();
            r.advance(secs(if renewal { 3601 } else { 3 }));
            if !renewal {
                r.client.note_network_down();
                r.client.check_network().await;
            }
            for cap in r.caps.built() {
                cap.inject_bind_error(Some(ADDR_NOT_AVAILABLE));
            }
            r.caps.set_present(GW1, false);
            let received = r.router.counters().num_total_recv;
            r.client.get_cached_mapping_or_start_creating_one();
            r.settle().await;
            let after = r.client.owned_snapshot()[0].clone();
            assert_eq!(after.id, before.id);
            assert_eq!(after.rule, before.rule, "retain protocol and PCP nonce");
            assert_eq!(
                after.router_expiry(),
                before.router_expiry(),
                "unsent operation inflated grant"
            );
            assert_eq!(
                r.client.have_mapping(),
                renewal,
                "do not extend advertisement trust"
            );
            assert_eq!(r.router.counters().num_total_recv, received);
            assert_router_inventory(&r.client, GW1, &r.router);
            r.client.note_network_down();
            r.shutdown().await;
        }
    }
}

#[tokio::test]
async fn send_evidence_survives_cancellation() {
    for pcp in [false, true] {
        for sent in [false, true] {
            let r = rig_with(Opts {
                router: RouterOptions {
                    pmp: !pcp,
                    ..RouterOptions::default()
                },
                ..Opts::default()
            })
            .await;
            r.client.set_local_port(PORT).unwrap();
            r.client.check_network().await;
            r.client.probe().await.unwrap();
            let kind = if pcp {
                RequestKind::PcpMap
            } else {
                RequestKind::PmpMap
            };
            let frozen = FrozenTime::new();
            let reply = sent.then(|| r.router.barrier(kind));
            r.client.get_cached_mapping_or_start_creating_one();
            let rule = r.client.owned_snapshot()[0].rule.clone();
            if let Some(reply) = &reply {
                reply.reached().await;
            }
            // Same-port rebind cancels the operation without deleting its possible grant.
            r.client.note_rebind(Some(PORT));
            if let Some(reply) = reply {
                reply.release();
            }
            while r.client.reap() != 0 {
                tokio::task::yield_now().await;
            }
            drop(frozen);
            r.settle().await;
            assert_eq!(
                r.client.owned_rules(),
                usize::from(sent),
                "pcp={pcp},sent={sent}"
            );
            assert_eq!(r.router.mappings().len(), usize::from(sent));
            if sent {
                let entry = r.client.owned_snapshot()[0].clone();
                assert_eq!(entry.rule, rule);
                assert!(entry.router_expiry() >= r.clock.now() + secs(u64::from(u32::MAX) - 1));
                assert!(!entry.mapping() && !entry.deleting());
            }
            assert_eq!(delete_requests(&r.router), 0);
            assert_router_inventory(&r.client, GW1, &r.router);
            r.shutdown().await;
        }
    }
}
