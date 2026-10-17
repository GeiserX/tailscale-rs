//! The NAT port-mapper driver: runs the [`ts_portmapper`] lifecycle client for the direct
//! underlay socket and turns its state into a port-mapped endpoint and NetInfo facets.
//!
//! Spawned by [`DirectManager`](crate::direct::DirectManager) on start unless the port mapper is
//! disabled (config `disable_port_mapper`, `TS_DISABLE_PORTMAPPER`); with it disabled no client,
//! driver or socket exists. The client's sockets are LAN control sockets to the gateway's
//! NAT-PMP/PCP port only: they never carry forwarded traffic and are not a `RealDialer` path.
//!
//! What wakes the driver:
//!
//! - a 10 s poll, independent of the STUN idle gate, that re-reads the default route (a routing
//!   table read, no packet) and compares the wall clock with the monotonic clock to notice a
//!   resume or a clock jump; a network found or changed, or a resume, kicks a round;
//! - orphan cleanup/recovery deadlines, independent of peers/activity, with fresh owning-network
//!   validation and per-rule cooldowns;
//! - the mapping's local expiry, whatever the activity, so an expired endpoint is withdrawn even
//!   on an idle, peerless node;
//! - with `renew_while_idle` and at least one peer, the renewal point and the retry after a failed
//!   or refused attempt (its backoff);
//! - the periodic ReSTUN cadence (20–26 s) while Go's `shouldDoPeriodicReSTUN` holds, and kicks
//!   (start, first peer, rebind, `re_stun`, `only-tcp-443` lifted).
//!
//! The release on shutdown is done by the runtime through the client's [`PortMapper`] handle, not
//! here.

use core::{
    net::SocketAddr,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use std::sync::Arc;

use tokio::{
    sync::{Notify, watch},
    time::Instant,
};
use ts_control::PortMapFacets;
use ts_magicsock::MagicSock;
use ts_portmapper::{DisableReason, PortMapper, PortmapState};

/// Builds the port-mapper client (tests inject a harness-backed one).
pub type MapperFactory = Arc<dyn Fn() -> Arc<dyn PortMapper> + Send + Sync>;

/// How often the network identity and the clocks are checked.
pub(crate) const POLL_INTERVAL: Duration = Duration::from_secs(10);
/// The least time between two timer-driven ticks, so a stale instant can never spin the loop.
const MIN_WAKE_SPACING: Duration = Duration::from_secs(1);

/// The production client for `options`. In this crate's own tests the gateway lookup is a stub
/// that panics: a test that turns the mapper on without injecting a harness fails loudly instead
/// of probing the real network.
pub(crate) fn system_client(options: &ts_control::PortMapperOptions) -> Arc<dyn PortMapper> {
    let gateway_override = options
        .gateway_override
        .map(|(gw, self_ip)| ts_portmapper::gateway::GatewayOverride { gw, self_ip });
    #[cfg_attr(test, allow(unused_mut))]
    let mut cfg = ts_portmapper::Config::system(gateway_override);
    cfg.advertise_nonpublic_external = options.advertise_nonpublic_external;
    #[cfg(test)]
    {
        cfg.lookup = Arc::new(tests::NeverLookup);
    }
    tracing::debug!("port mapper client built");
    #[cfg(test)]
    tests::CLIENTS_BUILT.fetch_add(1, Ordering::SeqCst);
    let (client, _rx) = ts_portmapper::Client::new(cfg);
    Arc::new(client)
}

/// The driver's handle, held by the direct manager: synchronous invalidation on rebind, kicks,
/// and the `only-tcp-443` switch.
#[derive(Clone)]
pub(crate) struct PortmapHandle {
    mapper: Arc<dyn PortMapper>,
    kick: Arc<Notify>,
    only_tcp_443: Arc<AtomicBool>,
}

impl PortmapHandle {
    pub(crate) fn new(mapper: Arc<dyn PortMapper>) -> Self {
        Self {
            mapper,
            kick: Arc::new(Notify::new()),
            only_tcp_443: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The client, for the runtime's shutdown release and status.
    pub(crate) fn mapper(&self) -> Arc<dyn PortMapper> {
        self.mapper.clone()
    }

    /// Ask the driver for a round (cleanup, probe, mapping) soon.
    pub(crate) fn kick(&self) {
        self.kick.notify_one();
    }

    /// The underlay socket was rebound (`Some(port)`) or the rebind left none (`None`).
    /// Synchronous: the mapping is invalidated (or re-installed) before this returns.
    pub(crate) fn note_rebind(&self, port: Option<u16>) {
        self.mapper.note_rebind(port);
        self.kick();
    }

    /// Control's `only-tcp-443`: on, every LAN send stops at once (deletes included); off again,
    /// leftovers are deleted and mapping resumes.
    pub(crate) fn set_only_tcp_443(&self, on: bool) {
        if self.only_tcp_443.swap(on, Ordering::SeqCst) == on {
            return;
        }
        if on {
            self.mapper.disable(DisableReason::OnlyTcp443);
        } else {
            self.mapper.enable();
            self.kick();
        }
    }
}

/// The runtime's hold on the port mapper for shutdown: [`close`](Self::close) within the shutdown
/// budget, and on drop the best-effort release (one unacknowledged delete per rule, no runtime
/// needed; a no-op after the close). Holding the client only through this guard means no way of
/// dropping the runtime can skip the release.
pub(crate) struct PortmapRelease(Option<Arc<dyn PortMapper>>);

impl PortmapRelease {
    pub(crate) fn new(mapper: Option<Arc<dyn PortMapper>>) -> Self {
        Self(mapper)
    }

    /// The client, for status.
    pub(crate) fn get(&self) -> Option<&Arc<dyn PortMapper>> {
        self.0.as_ref()
    }

    /// The first step of a graceful shutdown: close within [`crate::portmap_budget`].
    pub(crate) async fn close(&self, timeout: Option<Duration>) {
        crate::close_portmap(self.0.as_ref(), timeout).await;
    }

    /// The `Drop`-path release, now.
    pub(crate) fn release_now(&mut self) {
        if let Some(pm) = self.0.take() {
            pm.release_blocking_best_effort();
        }
    }
}

impl Drop for PortmapRelease {
    fn drop(&mut self) {
        self.release_now();
    }
}

/// The NetInfo facets for a published state. `HavePortMap` means an advertised mapping.
pub(crate) fn facets(state: &PortmapState) -> PortMapFacets {
    PortMapFacets {
        upnp: state.facets.upnp,
        pmp: state.facets.pmp,
        pcp: state.facets.pcp,
        have_port_map: state.advertised().is_some(),
    }
}

/// What the driver reads from the rest of the direct manager.
pub(crate) struct DriverArgs {
    pub handle: PortmapHandle,
    pub sock: Arc<MagicSock>,
    /// Whether the node has at least one peer.
    pub has_peers: Arc<dyn Fn() -> bool + Send + Sync>,
    /// Go's `shouldDoPeriodicReSTUN`: peers and a datapath not idle (or control's override).
    pub restun_gate: Arc<dyn Fn() -> bool + Send + Sync>,
    /// Where the facets go (the advertiser wakes on every send).
    pub port_map_tx: watch::Sender<Option<PortMapFacets>>,
    /// Renew at the renewal point while idle, as long as there are peers.
    pub renew_while_idle: bool,
    /// The ReSTUN cadence (jittered 20–26 s in production).
    pub restun_delay: fn() -> Duration,
    /// The network and clock poll interval ([`POLL_INTERVAL`] in production).
    pub poll: Duration,
    pub shutdown: watch::Receiver<bool>,
}

/// Install the published state on the socket and hand the facets to the advertiser.
fn apply_state(a: &DriverArgs, state: &PortmapState) {
    let mapper = &a.handle.mapper;
    let pm = state.advertised().map(|m| {
        (
            SocketAddr::V4(m.external),
            mapper.to_real(m.expires_at).into_std(),
        )
    });
    a.sock.set_portmapped(pm);
    a.port_map_tx.send_replace(Some(facets(state)));
}

/// One activity-driven round.
async fn tick(a: &DriverArgs, warned_port_zero: &mut bool) {
    if a.handle.only_tcp_443.load(Ordering::SeqCst) || a.sock.only_tcp_443() {
        return;
    }
    // Nothing bound (a rebind's gap, or a rebind that failed to bind): the cached address has no
    // socket behind it, so it is not mapped. The rebind already told the client.
    if !a.sock.is_bound() {
        return;
    }
    let mapper = &a.handle.mapper;
    let port = a.sock.local_addr().map(|addr| addr.port()).unwrap_or(0);
    match mapper.set_local_port(port) {
        Ok(()) => *warned_port_zero = false,
        Err(e) => {
            if !*warned_port_zero {
                tracing::warn!(error = %e, "portmapper: underlay socket has no port; not mapping");
                *warned_port_zero = true;
            }
            return;
        }
    }
    mapper.tick().await;
}

fn later(t: Option<Instant>, floor: Instant) -> Option<Instant> {
    t.map(|t| t.max(floor))
}

/// Run the driver until shutdown. See the module docs.
pub(crate) async fn run_driver(mut a: DriverArgs) {
    let mapper = a.handle.mapper.clone();
    let mut state_rx = mapper.subscribe();
    apply_state(&a, &state_rx.borrow_and_update().clone());
    let mut poll = tokio::time::interval(a.poll);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut restun = Box::pin(tokio::time::sleep((a.restun_delay)()));
    let mut warned_port_zero = false;
    let mut last_wake = Instant::now() - MIN_WAKE_SPACING;
    a.handle.kick();

    while !*a.shutdown.borrow() {
        let sched = mapper.schedule();
        let floor = last_wake + MIN_WAKE_SPACING;
        let cleanup = later(sched.cleanup_due.map(|t| mapper.to_real(t)), floor);
        let expiry = later(sched.expires_at.map(|t| mapper.to_real(t)), floor);
        let idle_renewal = a.renew_while_idle && (a.has_peers)();
        let renew = sched
            .renewal_due
            .filter(|_| idle_renewal)
            .map(|t| mapper.to_real(t));
        // A wanted start refused only by spacing is retried when allowed; a failure backoff is
        // retried by the timer only when idle renewal is on (otherwise activity retries it).
        let retry = sched
            .retry_at
            .filter(|_| !sched.backing_off || idle_renewal)
            .map(|t| mapper.to_real(t));
        let wake = later(
            match (renew, retry) {
                (Some(x), Some(y)) => Some(x.min(y)),
                (x, y) => x.or(y),
            },
            floor,
        );

        tokio::select! {
            biased;
            _ = a.shutdown.changed() => break,
            r = state_rx.changed() => {
                if r.is_err() {
                    break;
                }
                let state = state_rx.borrow_and_update().clone();
                apply_state(&a, &state);
            }
            _ = poll.tick() => {
                // A network found or changed is a link change: Go re-runs endpoint discovery
                // (and so the port mapper) for it, idle or not.
                let found = mapper.check_network().await == ts_portmapper::NetCheck::Changed;
                if mapper.check_clock() || found {
                    a.handle.kick();
                }
                mapper.reap();
            }
            _ = tokio::time::sleep_until(cleanup.unwrap_or_else(Instant::now)), if cleanup.is_some() => {
                last_wake = Instant::now();
                mapper.cleanup().await;
                // Retired rules may have freed admission for a wanted mapping.
                a.handle.kick();
            }
            _ = tokio::time::sleep_until(expiry.unwrap_or_else(Instant::now)), if expiry.is_some() => {
                last_wake = Instant::now();
                mapper.expire_if_due();
            }
            _ = tokio::time::sleep_until(wake.unwrap_or_else(Instant::now)), if wake.is_some() => {
                last_wake = Instant::now();
                tick(&a, &mut warned_port_zero).await;
            }
            _ = &mut restun => {
                restun.set(tokio::time::sleep((a.restun_delay)()));
                if (a.restun_gate)() {
                    tick(&a, &mut warned_port_zero).await;
                }
            }
            _ = a.handle.kick.notified() => {
                tick(&a, &mut warned_port_zero).await;
            }
        }
    }
    a.sock.set_portmapped(None);
}

#[cfg(test)]
pub(crate) mod tests {
    use core::sync::atomic::AtomicUsize;

    use ts_keys::{DiscoPrivateKey, NodePrivateKey};
    use ts_portmapper::{
        Client, Gateway, GatewayLookup, LookupError, PortMapper,
        oneshot::ProtoSet,
        testing::{FakeRouter, ManualClock, RouterOptions, ScriptedLookup, TestCap, TestCaps},
    };

    use super::*;

    /// Clients built by [`system_client`] in this test binary.
    pub(crate) static CLIENTS_BUILT: AtomicUsize = AtomicUsize::new(0);
    /// Lookups attempted through [`NeverLookup`].
    pub(crate) static NEVER_LOOKUPS: AtomicUsize = AtomicUsize::new(0);

    /// The lookup `system_client` gets in this crate's tests: counting, then panicking.
    pub(crate) struct NeverLookup;

    impl GatewayLookup for NeverLookup {
        fn lookup(&self) -> Result<Option<Gateway>, LookupError> {
            NEVER_LOOKUPS.fetch_add(1, Ordering::SeqCst);
            panic!("a ts_runtime test reached the real gateway lookup");
        }
    }

    pub(crate) const GW: core::net::Ipv4Addr = core::net::Ipv4Addr::new(192, 168, 1, 1);

    pub(crate) fn gateway() -> Gateway {
        Gateway {
            gw: GW,
            self_ip: core::net::Ipv4Addr::LOCALHOST,
            prefix_len: 24,
            if_index: 4,
            if_name: "en0".to_owned(),
        }
    }

    /// A harness-backed client: a fake router on loopback behind a `TestCap` for `GW`.
    pub(crate) async fn harness_client(
        router: RouterOptions,
        advertise_nonpublic: bool,
    ) -> (
        FakeRouter,
        Client<TestCap>,
        Arc<ScriptedLookup>,
        Arc<ManualClock>,
    ) {
        let router = FakeRouter::start(router).await.unwrap();
        let caps = TestCaps::new();
        caps.add(GW, router.endpoint());
        let lookup = ScriptedLookup::new(gateway());
        let clock = ManualClock::new();
        let (client, _rx) = Client::new(ts_portmapper::Config {
            lookup: lookup.clone(),
            caps,
            clock: clock.clone(),
            protos: ProtoSet::BOTH,
            advertise_nonpublic_external: advertise_nonpublic,
            lifetime: ts_portmapper::client::requested_lifetime(),
        });
        (router, client, lookup, clock)
    }

    struct Driver {
        handle: PortmapHandle,
        sock: Arc<MagicSock>,
        peers: Arc<AtomicBool>,
        restun: Arc<AtomicBool>,
        facets: watch::Receiver<Option<PortMapFacets>>,
        shutdown: watch::Sender<bool>,
        task: tokio::task::JoinHandle<()>,
    }

    fn fast_restun() -> Duration {
        Duration::from_millis(100)
    }

    fn never_restun() -> Duration {
        Duration::from_secs(3600)
    }

    /// The test poll: fast, so a manual-clock jump is noticed quickly.
    const POLL: Duration = Duration::from_millis(100);

    async fn driver(
        client: Arc<dyn PortMapper>,
        renew_while_idle: bool,
        restun_delay: fn() -> Duration,
    ) -> Driver {
        let sock = Arc::new(
            MagicSock::bind(
                "127.0.0.1:0".parse().unwrap(),
                DiscoPrivateKey::random(),
                NodePrivateKey::random().public_key(),
            )
            .await
            .unwrap(),
        );
        let handle = PortmapHandle::new(client);
        let peers = Arc::new(AtomicBool::new(true));
        let restun = Arc::new(AtomicBool::new(false));
        let (port_map_tx, facets) = watch::channel(None);
        let (shutdown, shutdown_rx) = watch::channel(false);
        let (p, r) = (peers.clone(), restun.clone());
        let task = tokio::spawn(run_driver(DriverArgs {
            handle: handle.clone(),
            sock: sock.clone(),
            has_peers: Arc::new(move || p.load(Ordering::SeqCst)),
            restun_gate: Arc::new(move || r.load(Ordering::SeqCst)),
            port_map_tx,
            renew_while_idle,
            restun_delay,
            poll: POLL,
            shutdown: shutdown_rx,
        }));
        Driver {
            handle,
            sock,
            peers,
            restun,
            facets,
            shutdown,
            task,
        }
    }

    async fn until(what: &str, f: impl Fn() -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !f() {
            assert!(std::time::Instant::now() < deadline, "timed out: {what}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    impl Driver {
        async fn stop(self) {
            self.shutdown.send_replace(true);
            self.task.await.unwrap();
            assert!(self.sock.portmapped().is_none(), "withdrawn on stop");
        }
    }

    /// The driver maps on start, installs the endpoint on the socket with the facets, and
    /// withdraws it at expiry with no ReSTUN tick and no peer.
    #[tokio::test]
    async fn driver_maps_then_withdraws_at_expiry_while_idle_and_peerless() {
        let (router, client, _lookup, _clock) =
            harness_client(RouterOptions::default(), true).await;
        router.set_lifetime_override(Some(2));
        let d = driver(Arc::new(client.clone()), false, never_restun).await;
        d.peers.store(false, Ordering::SeqCst);
        until("mapped", || d.sock.portmapped().is_some()).await;
        let pm = d.sock.portmapped().unwrap();
        assert_eq!(pm.ip().to_string(), "203.0.113.7");
        let f = d.facets.borrow().unwrap();
        assert!(f.have_port_map && f.pmp == Some(true));
        assert_eq!(
            d.sock.self_endpoints()[0].ty,
            ts_magicsock::SelfEndpointType::PortMapped
        );
        // No ReSTUN, no peers, lazy renewal: nothing renews; the expiry timer withdraws it.
        until("withdrawn", || {
            d.sock.portmapped().is_none() && !d.facets.borrow().unwrap().have_port_map
        })
        .await;
        assert_eq!(router.counters().num_pmp_map_recv, 1, "never renewed");
        d.stop().await;
        client.close(Duration::from_secs(1)).await;
        router.shutdown().await;
    }

    /// Exhausted unknown ownership must recover with no peers, ReSTUN or idle renewal.
    #[tokio::test]
    async fn cleanup_recovers_unknown_grant_while_idle_and_peerless() {
        use ts_portmapper::testing::RequestKind;
        let (router, client, _lookup, clock) = harness_client(RouterOptions::default(), true).await;
        router.knobs_for(Some(RequestKind::PmpMap));
        router.commit_then_drop_next(1000);
        router.set_drop_deletes(true);
        let d = driver(Arc::new(client.clone()), false, never_restun).await;
        d.peers.store(false, Ordering::SeqCst);
        until("unknown grant settled", || {
            client.owned_rules() == 1 && !client.attempt_in_flight() && client.reap() == 0
        })
        .await;
        for _ in 0..4 {
            client.cleanup().await;
        }
        until("initial deletes exhausted", || {
            client
                .cleanup_snapshot()
                .iter()
                .all(|e| e.delete_tries >= 3 && !e.deleting)
        })
        .await;
        assert!(!client.have_mapping());
        router.commit_then_drop_next(0);
        router.set_drop_deletes(false);
        clock.advance(Duration::from_secs(600));
        until("cleanup timer recovered mapping without activity", || {
            client.have_mapping() && d.sock.portmapped().is_some()
        })
        .await;
        client.cleanup().await;
        let table = router.mappings();
        let advertised = d.sock.portmapped().unwrap();
        assert_eq!(table.len(), 1, "next cleanup must preserve advertisement");
        assert_eq!(table[0].internal, d.sock.local_addr().unwrap().port());
        assert_eq!(table[0].external, advertised.port());
        d.stop().await;
        client.close(Duration::from_secs(1)).await;
        router.shutdown().await;
    }

    /// With idle renewal on, the renewal point is honoured while idle with peers; with no
    /// peers there is no renewal (the mapping expires); with idle renewal off, none either.
    #[tokio::test]
    async fn renew_while_idle_policy() {
        for (renew_while_idle, peers, want_renewal) in [
            (true, true, true),
            (true, false, false),
            (false, true, false),
        ] {
            let (router, client, _lookup, clock) =
                harness_client(RouterOptions::default(), true).await;
            let d = driver(Arc::new(client.clone()), renew_while_idle, never_restun).await;
            d.peers.store(peers, Ordering::SeqCst);
            until("mapped", || client.have_mapping()).await;
            // Past the renewal point (1 h for a 2 h grant), well before expiry.
            clock.advance(Duration::from_secs(3601));
            tokio::time::sleep(Duration::from_millis(800)).await;
            let maps = router.counters().num_pmp_map_recv;
            assert_eq!(
                maps > 1,
                want_renewal,
                "renew_while_idle={renew_while_idle} peers={peers}: {maps} MAPs"
            );
            d.stop().await;
            client.close(Duration::from_secs(1)).await;
            router.shutdown().await;
        }
    }

    /// Lazy mode: the periodic ReSTUN tick renews a due mapping when its gate is open, and
    /// nothing happens while it is closed.
    #[tokio::test]
    async fn restun_ticks_follow_the_gate() {
        let (router, client, _lookup, clock) = harness_client(RouterOptions::default(), true).await;
        let d = driver(Arc::new(client.clone()), false, fast_restun).await;
        until("mapped", || client.have_mapping()).await;
        clock.advance(Duration::from_secs(3601));
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            router.counters().num_pmp_map_recv,
            1,
            "gate closed: no renewal"
        );
        d.restun.store(true, Ordering::SeqCst);
        until("renewed on a ReSTUN tick", || {
            router.counters().num_pmp_map_recv == 2
        })
        .await;
        d.stop().await;
        client.close(Duration::from_secs(1)).await;
        router.shutdown().await;
    }

    /// The network identity changes while idle (no ReSTUN, no kick): the poll detects it
    /// within one interval and the mapping is withdrawn, with no release on network-down.
    #[tokio::test]
    async fn poll_detects_a_network_change_while_idle() {
        let (router, client, lookup, _clock) = harness_client(RouterOptions::default(), true).await;
        let d = driver(Arc::new(client.clone()), false, never_restun).await;
        until("mapped", || client.have_mapping()).await;
        lookup.set_no_route();
        let t = std::time::Instant::now();
        until("withdrawn", || d.sock.portmapped().is_none()).await;
        assert!(t.elapsed() <= POLL + Duration::from_millis(500));
        assert_eq!(
            router.counters().num_deletes,
            0,
            "no release on network-down"
        );
        d.stop().await;
        client.close(Duration::from_secs(1)).await;
        router.shutdown().await;
    }

    /// Through the driver, a resume (wall clock jumps, monotonic does not) is noticed by the
    /// poll and renews the mapping once.
    #[tokio::test]
    async fn poll_notices_a_resume_and_renews_once() {
        let (router, client, _lookup, clock) = harness_client(RouterOptions::default(), true).await;
        let d = driver(Arc::new(client.clone()), false, never_restun).await;
        until("mapped", || client.have_mapping()).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mappings = || {
            router
                .requests()
                .iter()
                .filter(|r| {
                    r.kind == ts_portmapper::testing::RequestKind::PmpMap
                        && r.lifetime.is_some_and(|n| n > 0)
                })
                .count()
        };
        clock.suspend(Duration::from_secs(4 * 3600));
        until("renewed after resume", || mappings() == 2).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            mappings(),
            2,
            "exactly one replacement, excluding cleanup deletes"
        );
        d.stop().await;
        client.close(Duration::from_secs(1)).await;
        router.shutdown().await;
    }

    /// `only-tcp-443` through the handle: no LAN packet while on, deletes included; off again,
    /// the leftover is deleted and mapping resumes.
    #[tokio::test]
    async fn only_tcp_443_through_the_handle() {
        let (router, client, _lookup, clock) = harness_client(RouterOptions::default(), true).await;
        let d = driver(Arc::new(client.clone()), false, never_restun).await;
        until("mapped", || client.have_mapping()).await;
        d.handle.set_only_tcp_443(true);
        assert!(!client.have_mapping(), "withdrawn synchronously");
        until("facets false", || {
            d.facets
                .borrow()
                .is_some_and(|f| f.pmp == Some(false) && !f.have_port_map)
        })
        .await;
        let total = router.counters().num_total_recv;
        d.handle.kick();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(router.counters().num_total_recv, total, "silent");
        clock.advance(Duration::from_secs(3));
        d.handle.set_only_tcp_443(false);
        until("re-mapped", || client.have_mapping()).await;
        assert_eq!(router.counters().num_deletes, 1, "the leftover went first");
        d.stop().await;
        client.close(Duration::from_secs(1)).await;
        router.shutdown().await;
    }

    /// Runner mode (idle renewal, peers): a failed first create is retried at its backoff by the
    /// driver's timer while idle, with no activity or kick.
    #[tokio::test]
    async fn failed_create_is_retried_while_idle_with_peers() {
        let (router, client, _lookup, clock) = harness_client(
            RouterOptions {
                pcp: false,
                ..RouterOptions::default()
            },
            true,
        )
        .await;
        router.set_result(
            ts_portmapper::testing::RequestKind::PmpMap,
            Some(ts_portmapper::testing::ResultOverride {
                code: 3,
                lifetime: 0,
            }),
        );
        let d = driver(Arc::new(client.clone()), true, never_restun).await;
        until("first create refused", || {
            router.counters().num_pmp_map_recv == 1 && client.schedule().backing_off
        })
        .await;
        router.set_result(ts_portmapper::testing::RequestKind::PmpMap, None);
        // Past the longest first backoff (10 s + 20 %).
        clock.advance(Duration::from_secs(60));
        until("retried and mapped", || client.have_mapping()).await;
        d.stop().await;
        client.close(Duration::from_secs(1)).await;
        router.shutdown().await;
    }

    /// The poll finds a network while idle (none at start, as for a launchd job at boot): it kicks
    /// a round, so the mapping is made without any activity.
    #[tokio::test]
    async fn network_found_by_the_poll_kicks_a_round() {
        let (router, client, lookup, _clock) = harness_client(RouterOptions::default(), true).await;
        lookup.set_no_route();
        let d = driver(Arc::new(client.clone()), true, never_restun).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!client.has_network());
        lookup.set(gateway());
        until("mapped after the poll found the network", || {
            client.have_mapping()
        })
        .await;
        d.stop().await;
        client.close(Duration::from_secs(1)).await;
        router.shutdown().await;
    }

    /// A [`PortMapper`] that counts how often the driver reads the schedule (once per loop).
    struct Counting {
        inner: Arc<dyn PortMapper>,
        schedules: Arc<AtomicUsize>,
    }

    impl PortMapper for Counting {
        fn subscribe(&self) -> watch::Receiver<PortmapState> {
            self.inner.subscribe()
        }
        fn set_local_port(&self, port: u16) -> Result<(), ts_portmapper::client::Error> {
            self.inner.set_local_port(port)
        }
        fn note_rebind(&self, port: Option<u16>) {
            self.inner.note_rebind(port);
        }
        fn note_network_down(&self) {
            self.inner.note_network_down();
        }
        fn check_network(&self) -> BoxFuture<'_, ts_portmapper::NetCheck> {
            self.inner.check_network()
        }
        fn check_clock(&self) -> bool {
            self.inner.check_clock()
        }
        fn disable(&self, why: DisableReason) {
            self.inner.disable(why);
        }
        fn enable(&self) {
            self.inner.enable();
        }
        fn expire_if_due(&self) -> bool {
            self.inner.expire_if_due()
        }
        fn schedule(&self) -> ts_portmapper::ScheduleSnapshot {
            self.schedules.fetch_add(1, Ordering::SeqCst);
            self.inner.schedule()
        }
        fn to_real(&self, t: Instant) -> Instant {
            self.inner.to_real(t)
        }
        fn tick(&self) -> BoxFuture<'_, Option<core::net::SocketAddrV4>> {
            self.inner.tick()
        }
        fn cleanup(&self) -> BoxFuture<'_, usize> {
            self.inner.cleanup()
        }
        fn close(&self, budget: Duration) -> BoxFuture<'_, ()> {
            self.inner.close(budget)
        }
        fn release_blocking_best_effort(&self) {
            self.inner.release_blocking_best_effort();
        }
        fn reap(&self) -> usize {
            self.inner.reap()
        }
    }

    type BoxFuture<'a, T> = core::pin::Pin<Box<dyn core::future::Future<Output = T> + Send + 'a>>;

    /// A retry request left over when `only-tcp-443` turns mapping off does not wake the driver
    /// every second: no attempt could start, so none is scheduled.
    #[tokio::test]
    async fn no_wakeups_while_only_tcp_443() {
        let (router, client, _lookup, _clock) =
            harness_client(RouterOptions::default(), true).await;
        let schedules = Arc::new(AtomicUsize::new(0));
        let mapper: Arc<dyn PortMapper> = Arc::new(Counting {
            inner: Arc::new(client.clone()),
            schedules: schedules.clone(),
        });
        let sock = Arc::new(
            MagicSock::bind(
                "127.0.0.1:0".parse().unwrap(),
                DiscoPrivateKey::random(),
                NodePrivateKey::random().public_key(),
            )
            .await
            .unwrap(),
        );
        let handle = PortmapHandle::new(mapper);
        let (port_map_tx, _facets) = watch::channel(None);
        let (shutdown, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(run_driver(DriverArgs {
            handle: handle.clone(),
            sock: sock.clone(),
            has_peers: Arc::new(|| false),
            restun_gate: Arc::new(|| false),
            port_map_tx,
            renew_while_idle: false,
            restun_delay: never_restun,
            poll: Duration::from_secs(3600),
            shutdown: shutdown_rx,
        }));
        until("mapped", || client.have_mapping()).await;
        // A port change, then a request refused by the 2 s floor: a retry is wanted.
        let port = sock.local_addr().unwrap().port();
        client.set_local_port(port.wrapping_add(1)).unwrap();
        assert!(client.get_cached_mapping_or_start_creating_one().is_none());
        assert!(client.schedule().retry_at.is_some());
        handle.set_only_tcp_443(true);
        tokio::time::sleep(Duration::from_millis(500)).await;
        let before = schedules.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(3)).await;
        let n = schedules.load(Ordering::SeqCst) - before;
        shutdown.send_replace(true);
        task.await.unwrap();
        client.close(Duration::from_secs(1)).await;
        router.shutdown().await;
        assert!(
            n <= 1,
            "the driver woke {n} times in 3 s with only-tcp-443 on"
        );
    }

    /// The runtime's release guard: dropping it (every drop of the runtime does) sends the
    /// delete with no reply awaited; after a close it sends nothing more.
    #[tokio::test]
    async fn release_guard_deletes_on_drop_and_once_after_close() {
        for close_first in [false, true] {
            let (router, client, _lookup, _clock) =
                harness_client(RouterOptions::default(), true).await;
            client.set_local_port(41641).unwrap();
            client.tick().await;
            until("mapped", || client.have_mapping()).await;
            let guard = PortmapRelease::new(Some(Arc::new(client.clone()) as Arc<dyn PortMapper>));
            assert!(guard.get().is_some());
            if close_first {
                guard.close(Some(Duration::from_millis(500))).await;
                assert!(router.mappings().is_empty(), "closed: deleted");
            }
            drop(guard);
            until("deleted", || router.mappings().is_empty()).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(
                router.counters().num_deletes,
                1,
                "close_first={close_first}"
            );
            router.shutdown().await;
        }
    }

    // -----------------------------------------------------------------------------------------
    // Through the real DirectManager

    use kameo::{
        actor::{ActorRef, Spawn},
        message::{Context, Message},
    };

    use crate::{
        Env, Error,
        direct::{EndpointAdvertisement, PortmapClient, RebindAndReprobe, SockHandle},
        env::{ForwarderConfig, PortMapperSettings},
    };

    fn forwarder(port_mapper: Option<PortMapperSettings>) -> ForwarderConfig {
        ForwarderConfig {
            accept_routes: false,
            accept_dns: true,
            exit_node: None,
            forward_routes: vec![],
            forward_tcp_ports: vec![],
            forward_udp_ports: vec![],
            forward_all_ports: false,
            forward_exit_egress: false,
            block_incoming: false,
            exit_proxy: None,
            exit_node_dns: None,
            peerapi_port: None,
            taildrop_dir: None,
            enable_ipv6: false,
            wireguard_listen_port: None,
            network_monitor: false,
            port_mapper,
            persistent_keepalive_interval: None,
            ingress_active: Arc::new(AtomicBool::new(false)),
        }
    }

    struct Stack {
        env: Env,
        direct: ActorRef<crate::direct::DirectManager>,
        _shutdown: watch::Sender<bool>,
    }

    async fn stack(port_mapper: Option<PortMapperSettings>) -> Stack {
        let (shutdown, shutdown_rx) = watch::channel(false);
        let env = Env::new(
            ts_keys::NodeState::generate(),
            shutdown_rx,
            forwarder(port_mapper),
        );
        let dataplane = crate::dataplane::DataplaneActor::spawn(env.clone());
        let (_home_tx, home_rx) = watch::channel(None);
        let multiderp =
            crate::multiderp::Multiderp::spawn((env.clone(), dataplane.clone(), home_rx));
        let direct =
            crate::direct::DirectManager::spawn((env.clone(), dataplane.clone(), multiderp));
        direct.ask(SockHandle).await.unwrap().expect("bound");
        Stack {
            env,
            direct,
            _shutdown: shutdown,
        }
    }

    /// The shared runtime test configuration builds no client, constructs no socket for
    /// it and never runs the gateway lookup; the lookup stub this crate's tests get instead of the
    /// real one panics, so turning the mapper on without a harness cannot reach the network. (The
    /// feature combinations are covered by building with `portmapper` off, on, and with the
    /// harness as a dev-dependency.)
    #[tokio::test]
    async fn shared_test_config_never_builds_a_client() {
        let built = CLIENTS_BUILT.load(Ordering::SeqCst);
        let lookups = NEVER_LOOKUPS.load(Ordering::SeqCst);
        let s = stack(None).await;
        assert!(s.direct.ask(PortmapClient).await.unwrap().is_none());
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(CLIENTS_BUILT.load(Ordering::SeqCst), built, "no client");
        assert_eq!(NEVER_LOOKUPS.load(Ordering::SeqCst), lookups, "no lookup");

        // The library default is on: a config that does not disable it builds the (stubbed)
        // client, whose first lookup hits the panicking stub, never the routing table.
        let s = stack(Some(PortMapperSettings {
            options: ts_control::PortMapperOptions::default(),
            factory: None,
        }))
        .await;
        assert!(s.direct.ask(PortmapClient).await.unwrap().is_some());
        until("stub lookup", || {
            NEVER_LOOKUPS.load(Ordering::SeqCst) > lookups
        })
        .await;
        assert_eq!(CLIENTS_BUILT.load(Ordering::SeqCst), built + 1);
    }

    /// `disable_port_mapper` and `TS_DISABLE_PORTMAPPER` (read through
    /// an injected reader, parsed like Go's `ParseBool`) both mean no client at all.
    #[test]
    fn config_and_env_disable() {
        let mut cfg = ts_control::Config::default();
        let on = ForwarderConfig::from_control_config(&cfg);
        assert!(on.port_mapper.is_some(), "library default: on");
        cfg.disable_port_mapper = true;
        assert!(
            ForwarderConfig::from_control_config(&cfg)
                .port_mapper
                .is_none()
        );
        for (v, disabled) in [
            ("1", true),
            ("true", true),
            ("T", true),
            ("0", false),
            ("false", false),
            ("", false),
            ("yes", true),
        ] {
            let mut f = ForwarderConfig::from_control_config(&ts_control::Config::default());
            f.apply_env_knobs(|k| (k == "TS_DISABLE_PORTMAPPER").then(|| v.to_owned()));
            assert_eq!(f.port_mapper.is_none(), disabled, "{v:?}");
        }
        let mut f = ForwarderConfig::from_control_config(&ts_control::Config::default());
        f.apply_env_knobs(|_| None);
        assert!(f.port_mapper.is_some());
    }

    struct AdvTap(Arc<std::sync::Mutex<Vec<EndpointAdvertisement>>>);

    impl kameo::Actor for AdvTap {
        type Args = Arc<std::sync::Mutex<Vec<EndpointAdvertisement>>>;
        type Error = Error;
        async fn on_start(seen: Self::Args, _s: ActorRef<Self>) -> Result<Self, Self::Error> {
            Ok(Self(seen))
        }
    }

    impl Message<EndpointAdvertisement> for AdvTap {
        type Reply = ();
        async fn handle(&mut self, m: EndpointAdvertisement, _c: &mut Context<Self, Self::Reply>) {
            self.0.lock().unwrap().push(m);
        }
    }

    /// Through the real direct manager with a harness-backed client injected, a mapping is
    /// obtained, the type-3 endpoint and the facets are advertised for control (wire type 3), a
    /// same-port rebind keeps the mapping with no I/O, and the shutdown release makes the router see
    /// the delete within the timeout, with no second added.
    #[tokio::test]
    async fn end_to_end_through_the_direct_manager() {
        let (router, client, _lookup, _clock) =
            harness_client(RouterOptions::default(), true).await;
        let injected = client.clone();
        let s = stack(Some(PortMapperSettings {
            options: ts_control::PortMapperOptions::default(),
            factory: Some(Arc::new(move || {
                Arc::new(injected.clone()) as Arc<dyn PortMapper>
            })),
        }))
        .await;
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let tap = AdvTap::spawn(seen.clone());
        s.env
            .subscribe::<EndpointAdvertisement>(&tap)
            .await
            .unwrap();

        until("advertised", || {
            seen.lock().unwrap().last().is_some_and(|a| {
                a.endpoints.first().map(|e| e.ty)
                    == Some(ts_magicsock::SelfEndpointType::PortMapped)
                    && a.port_map.is_some_and(|f| f.have_port_map)
            })
        })
        .await;
        let adv = seen.lock().unwrap().last().cloned().unwrap();
        let wire = crate::control_runner::wire_endpoints(&adv.endpoints);
        // Go's MapRequest carries `EndpointTypes` as integers: PortMapped is 3.
        assert_eq!(wire[0].ty, ts_control_serde::EndpointType::PortMapped);
        assert_eq!(serde_json::to_string(&wire[0].ty).unwrap(), "3");
        assert_eq!(wire[0].endpoint, "203.0.113.7:4242".parse().unwrap());
        assert!(!adv.stun.working_udp, "a port mapping is not STUN evidence");
        let f = adv.port_map.unwrap();
        assert_eq!((f.pmp, f.pcp, f.upnp), (Some(true), Some(true), None));

        // A rebind on the same port and network: the mapping survives with no router traffic.
        let before = router.counters().num_total_recv;
        s.direct.ask(RebindAndReprobe).await.unwrap();
        assert!(client.have_mapping());
        let sock = s.direct.ask(SockHandle).await.unwrap().unwrap();
        until("re-installed", || sock.portmapped().is_some()).await;
        assert_eq!(router.counters().num_total_recv, before, "no I/O");

        // The runtime's shutdown step: within the timeout, and the router saw the delete.
        let mapper = s.direct.ask(PortmapClient).await.unwrap().unwrap();
        let t = std::time::Instant::now();
        let timeout = Duration::from_millis(400);
        assert!(
            tokio::time::timeout(timeout, crate::close_portmap(Some(&mapper), Some(timeout)))
                .await
                .is_ok()
        );
        assert!(t.elapsed() < timeout);
        assert!(router.mappings().is_empty());
        assert_eq!(router.counters().num_deletes, 1);
        router.shutdown().await;
    }

    /// The shutdown budget is at most 1 s and never more than the caller's timeout (no added
    /// second), even with the router gone.
    #[tokio::test]
    async fn shutdown_release_stays_within_the_timeout() {
        assert_eq!(crate::portmap_budget(None), Duration::from_secs(1));
        assert_eq!(
            crate::portmap_budget(Some(Duration::from_millis(200))),
            Duration::from_millis(200)
        );
        assert_eq!(
            crate::portmap_budget(Some(Duration::from_secs(5))),
            Duration::from_secs(1)
        );
        let (router, client, _lookup, _clock) =
            harness_client(RouterOptions::default(), true).await;
        client.set_local_port(41641).unwrap();
        client.tick().await;
        until("mapped", || client.have_mapping()).await;
        router.drop_next(1000);
        let mapper: Arc<dyn PortMapper> = Arc::new(client);
        let t = std::time::Instant::now();
        crate::close_portmap(Some(&mapper), Some(Duration::from_millis(300))).await;
        assert!(
            t.elapsed() < Duration::from_millis(450),
            "{:?}",
            t.elapsed()
        );
        router.shutdown().await;
    }
}
