//! Network-link-change supervisor (opt-in, `network-monitor` feature).
//!
//! Bridges an OS [`LinkMonitor`](ts_netmon::LinkMonitor) to the engine's auto-recovery path. On
//! each coalesced [`LinkChangeEvent`](ts_netmon::LinkChangeEvent) — a Wi-Fi switch, sleep/wake, or
//! default-route change — it fires the engine's three "kicks" so the node recovers a direct path
//! instead of silently degrading to DERP until the periodic timers eventually re-probe:
//!
//! 1. **Re-bind + re-ping + immediate STUN** — `direct.ask(`[`RebindAndReprobe`]`)`. The single
//!    message swaps the underlay socket, re-pings all candidates on it, and fires an immediate STUN
//!    sweep, all atomically inside [`DirectManager`] (which owns the socket, peer db, and multiderp
//!    ref). Folding all three into one message keeps every magicsock/STUN touch inside the manager
//!    and makes this supervisor trivially thin — it never threads a `MagicSock` or a STUN server
//!    list itself.
//! 2. **Re-netcheck** — `env.publish(`[`MeasureNow`]`)`. The [`DerpLatencyMeasurer`] subscribes to
//!    this on the same bus and re-measures DERP latency against its cached derp map, which feeds the
//!    downstream home-region re-selection (in `control_runner`). Using the bus means no
//!    `ActorRef<DerpLatencyMeasurer>` has to be threaded here.
//!
//! Events are processed **serially** (the `ask` completes before the next event is handled) and a
//! **minimum interval between rebinds** ([`MIN_REBIND_INTERVAL`]) drops any event that arrives too
//! soon after the last completed rebind, so an event storm (a sleep-wake can emit a long flurry
//! even after the debouncer) cannot drive a rebind loop. The loop ends on `env.shutdown`, and the
//! [`LinkMonitorHandle`](ts_netmon::LinkMonitorHandle) (held for the actor's life) aborts the
//! monitor's watcher task on drop, so no monitor task outlives the device.
//!
//! [`RebindAndReprobe`]: crate::direct::RebindAndReprobe
//! [`DirectManager`]: crate::direct::DirectManager
//! [`MeasureNow`]: crate::derp_latency::MeasureNow
//! [`DerpLatencyMeasurer`]: crate::derp_latency::DerpLatencyMeasurer

use std::sync::Arc;
use std::time::Duration;

use kameo::actor::ActorRef;
use kameo::message::Message;
use ts_netmon::{LinkMonitor, LinkMonitorHandle};

use crate::derp_latency::MeasureNow;
use crate::direct::{DirectManager, RebindAndReprobe};
use crate::{Env, Error};

/// Minimum wall-clock interval between two rebinds. An event arriving within this window of the
/// **last completed** rebind is dropped (logged at trace). This is the event-storm backstop: a
/// sleep-wake or a flapping link can emit notifications faster than the underlay can usefully be
/// re-bound, and re-binding mid-recovery would just re-clear paths that are still re-confirming.
/// 1s is comfortably longer than a rebind+reprobe round-trip yet short enough that a genuine second
/// change a moment later is still honored on the next event.
const MIN_REBIND_INTERVAL: Duration = Duration::from_secs(1);

/// Supervises an OS link monitor and fires the engine's re-bind / re-probe / re-netcheck kicks on
/// each coalesced link change. See the [module docs](self).
pub struct NetmonSupervisor {
    /// Held for the actor's life: its `Drop` aborts the monitor's watcher task (clean shutdown).
    _handle: LinkMonitorHandle,
}

/// Construction args: the link monitor to watch, the direct manager to drive, and the env (bus +
/// shutdown).
pub struct NetmonSupervisorArgs {
    /// The OS (or, in this slice, synthetic / no-op) link-change source.
    pub monitor: Arc<dyn LinkMonitor>,
    /// The direct underlay manager — `ask`ed [`RebindAndReprobe`] on each event.
    pub direct: ActorRef<DirectManager>,
    /// Bus + shutdown signal. `MeasureNow` is published here; the loop exits when `shutdown` flips.
    pub env: Env,
}

impl kameo::Actor for NetmonSupervisor {
    type Args = NetmonSupervisorArgs;
    type Error = Error;

    async fn on_start(args: Self::Args, _slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        let NetmonSupervisorArgs {
            monitor,
            direct,
            env,
        } = args;

        // Start the monitor's watcher, wired to the runtime shutdown signal. A failure to start the
        // OS watcher (e.g. a route/netlink socket could not be opened) is non-fatal: log and run a
        // never-yielding loop so the actor still exists (and tears down cleanly on shutdown) rather
        // than failing the whole device for an opt-in convenience.
        let (mut events, handle) = match monitor.watch(env.shutdown.clone()) {
            Ok(pair) => pair,
            Err(e) => {
                tracing::error!(error = %e, "network monitor failed to start; link-change auto-rebind disabled");
                // A no-op monitor's watch is infallible, but a real OS backend's may fail; keep the
                // actor alive with a closed event stream so its lifecycle matches the others.
                let (mut events, handle) = ts_netmon::NoopLinkMonitor
                    .watch(env.shutdown.clone())
                    .expect("noop monitor watch is infallible");
                let loop_env = env.clone();
                tokio::spawn(async move {
                    run(&mut events, &direct, &loop_env).await;
                });
                return Ok(Self { _handle: handle });
            }
        };

        tracing::debug!("network-monitor supervisor running");

        // The reaction loop runs detached; it observes `env.shutdown` and ends when the event
        // stream closes (handle dropped on actor stop) or shutdown flips. `direct`/`env` are moved
        // in; the handle stays on `Self` so dropping the actor aborts the watcher.
        tokio::spawn(async move {
            run(&mut events, &direct, &env).await;
        });

        Ok(Self { _handle: handle })
    }
}

/// The reaction loop, factored out of `on_start` so the success and watch-failure paths share it.
///
/// For each coalesced event: enforce the [`MIN_REBIND_INTERVAL`] backstop, then
/// `direct.ask(RebindAndReprobe)` (serially) and `env.publish(MeasureNow)`. Exits when the event
/// stream closes or `env.shutdown` flips to `true`.
///
/// Generic over the target actor purely so the unit tests can drive this **exact** production loop
/// with a lightweight `RebindAndReprobe`-counting stand-in instead of standing up the whole
/// dataplane; in production `A` is always [`DirectManager`].
async fn run<A>(
    events: &mut tokio::sync::mpsc::Receiver<ts_netmon::LinkChangeEvent>,
    direct: &ActorRef<A>,
    env: &Env,
) where
    A: kameo::Actor + Message<RebindAndReprobe, Reply = Result<(), ts_magicsock::Error>>,
{
    let mut shutdown = env.shutdown.clone();
    // `None` until the first rebind completes; then the `Instant` the last rebind finished.
    let mut last_rebind: Option<tokio::time::Instant> = None;

    loop {
        tokio::select! {
            // Bias toward shutdown so a flip is honored even if events are pending.
            biased;

            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }

            event = events.recv() => {
                match event {
                    Some(_link_change) => {
                        // Event-storm backstop: skip an event that lands too soon after the last
                        // completed rebind. (The debouncer already coalesces a single change's
                        // burst; this guards against distinct settled events arriving back-to-back,
                        // e.g. a long sleep-wake sequence.)
                        if last_rebind.is_some_and(|prev| prev.elapsed() < MIN_REBIND_INTERVAL) {
                            tracing::trace!("link change within min-rebind interval; skipping");
                            continue;
                        }

                        tracing::debug!("link change: rebinding + re-probing connectivity");

                        // (1) Rebind + re-ping + immediate STUN, atomically in DirectManager.
                        //     Serial: this completes before the next event is processed.
                        if let Err(e) = direct.ask(RebindAndReprobe).await {
                            tracing::warn!(error = %e, "rebind-and-reprobe on link change");
                        }

                        // Mark completion AFTER the rebind so the interval measures quiet-since-done.
                        last_rebind = Some(tokio::time::Instant::now());

                        // (2) Re-netcheck: ask the derp-latency measurer to re-measure now (it
                        //     subscribes to MeasureNow on the bus). Best-effort.
                        if let Err(e) = env.publish(MeasureNow).await {
                            tracing::warn!(error = %e, "publishing MeasureNow on link change");
                        }
                    }
                    None => {
                        // Event stream closed (monitor watcher ended, e.g. handle dropped on actor
                        // stop, or a no-op monitor). Nothing more to react to.
                        tracing::trace!("link-change event stream closed; supervisor loop exiting");
                        break;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kameo::actor::Spawn;
    use kameo::message::{Context, Message};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::watch;
    use ts_netmon::ManualLinkMonitor;

    /// Build a minimal `Env` for the supervisor tests (only the bus + shutdown matter here).
    fn test_env(shutdown_rx: watch::Receiver<bool>) -> Env {
        Env::new(
            ts_keys::NodeState::generate(),
            shutdown_rx,
            crate::env::ForwarderConfig {
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
                peerapi_port: None,
                taildrop_dir: None,
                enable_ipv6: false,
                network_monitor: true,
                persistent_keepalive_interval: None,
                ingress_active: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            },
        )
    }

    /// A stand-in for `DirectManager` that counts `RebindAndReprobe` messages, so the reaction loop
    /// can be tested with a real `ActorRef` without standing up the whole dataplane. The supervisor
    /// only ever `ask`s `RebindAndReprobe`, so a counter actor answering that one message suffices.
    struct RebindCounter {
        count: Arc<AtomicUsize>,
    }
    impl kameo::Actor for RebindCounter {
        type Args = Arc<AtomicUsize>;
        type Error = Error;
        async fn on_start(count: Self::Args, _s: ActorRef<Self>) -> Result<Self, Self::Error> {
            Ok(Self { count })
        }
    }
    impl Message<RebindAndReprobe> for RebindCounter {
        type Reply = Result<(), ts_magicsock::Error>;
        async fn handle(
            &mut self,
            _m: RebindAndReprobe,
            _c: &mut Context<Self, Self::Reply>,
        ) -> Self::Reply {
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Counts `MeasureNow`s published on the bus.
    struct MeasureNowTap {
        count: Arc<AtomicUsize>,
    }
    impl kameo::Actor for MeasureNowTap {
        type Args = Arc<AtomicUsize>;
        type Error = Error;
        async fn on_start(count: Self::Args, _s: ActorRef<Self>) -> Result<Self, Self::Error> {
            Ok(Self { count })
        }
    }
    impl Message<MeasureNow> for MeasureNowTap {
        type Reply = ();
        async fn handle(&mut self, _m: MeasureNow, _c: &mut Context<Self, Self::Reply>) {
            self.count.fetch_add(1, Ordering::SeqCst);
        }
    }

    async fn wait_until(counter: &AtomicUsize, want: usize, what: &str) {
        for _ in 0..300 {
            if counter.load(Ordering::SeqCst) >= want {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!(
            "timed out waiting for {what}: got {} want {want}",
            counter.load(Ordering::SeqCst)
        );
    }

    /// The KEY property: one synthetic link event drives EXACTLY one `RebindAndReprobe` AND one
    /// `MeasureNow`. Proves the whole pipeline end-to-end (ManualLinkMonitor → debouncer →
    /// supervisor → both kicks) with no OS code.
    #[tokio::test]
    async fn one_link_event_fires_one_rebind_and_one_measure_now() {
        let (_sd_tx, sd_rx) = watch::channel(false);
        let env = test_env(sd_rx);

        let rebinds = Arc::new(AtomicUsize::new(0));
        let measures = Arc::new(AtomicUsize::new(0));

        // A real `ActorRef` answering only `RebindAndReprobe` — the one message the supervisor
        // sends. Because the production `run` is generic over the actor type, the test drives the
        // EXACT production loop with this stand-in (no dataplane required, no logic duplicated).
        let direct = RebindCounter::spawn(rebinds.clone());

        let tap = MeasureNowTap::spawn(measures.clone());
        env.subscribe::<MeasureNow>(&tap).await.unwrap();

        // Use a short settle so the test is quick.
        let (monitor, trigger) = ManualLinkMonitor::with_settle(Duration::from_millis(50));
        let (mut events, _handle) = monitor.watch(env.shutdown.clone()).unwrap();

        // Drive the production reaction loop directly against the stand-in ref.
        let loop_env = env.clone();
        let loop_task = tokio::spawn(async move { run(&mut events, &direct, &loop_env).await });

        // Fire ONE synthetic link change (a small burst that coalesces to one event).
        for _ in 0..4 {
            assert!(trigger.trigger());
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        wait_until(&rebinds, 1, "one RebindAndReprobe").await;
        wait_until(&measures, 1, "one MeasureNow").await;

        // No spurious extra reactions for a single coalesced event.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(rebinds.load(Ordering::SeqCst), 1, "exactly one rebind");
        assert_eq!(
            measures.load(Ordering::SeqCst),
            1,
            "exactly one measure-now"
        );

        drop(trigger);
        drop(tokio::time::timeout(Duration::from_secs(1), loop_task).await);
    }

    /// The 1s min-rebind backstop: two coalesced events arriving back-to-back (within 1s) drive
    /// only ONE rebind; the second is dropped because it lands inside `MIN_REBIND_INTERVAL`. A third
    /// event after the interval elapses is honored. Driven through a real `ManualLinkMonitor` (so
    /// `LinkChangeEvent`s are produced by the legitimate event source, not synthesized — the type is
    /// `#[non_exhaustive]` and can't be constructed outside `ts_netmon`). Uses real (short) time;
    /// the one unavoidable ~1s wait exercises the real backstop interval.
    #[tokio::test]
    async fn min_interval_drops_back_to_back_events() {
        let (_sd_tx, sd_rx) = watch::channel(false);
        let env = test_env(sd_rx);

        let rebinds = Arc::new(AtomicUsize::new(0));
        let direct = RebindCounter::spawn(rebinds.clone());

        // Real monitor with a tiny settle so each burst coalesces quickly into one real event.
        let (monitor, trigger) = ManualLinkMonitor::with_settle(Duration::from_millis(30));
        let (mut events, _handle) = monitor.watch(env.shutdown.clone()).unwrap();
        let loop_env = env.clone();
        let loop_task = tokio::spawn(async move { run(&mut events, &direct, &loop_env).await });

        // First coalesced event → rebind #1.
        trigger.trigger();
        wait_until(&rebinds, 1, "first rebind").await;

        // A second coalesced event lands ~30ms later, well inside the 1s backstop → dropped.
        trigger.trigger();
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            rebinds.load(Ordering::SeqCst),
            1,
            "the back-to-back event must be dropped by the min-rebind backstop"
        );

        // After the full interval elapses, a third coalesced event is honored → rebind #2.
        tokio::time::sleep(MIN_REBIND_INTERVAL + Duration::from_millis(100)).await;
        trigger.trigger();
        wait_until(&rebinds, 2, "rebind after the interval elapsed").await;

        drop(trigger);
        drop(tokio::time::timeout(Duration::from_secs(1), loop_task).await);
    }

    /// A shutdown flip ends the reaction loop even with the monitor still alive (no events fired).
    #[tokio::test]
    async fn shutdown_ends_loop() {
        let (sd_tx, sd_rx) = watch::channel(false);
        let env = test_env(sd_rx);
        let rebinds = Arc::new(AtomicUsize::new(0));
        let direct = RebindCounter::spawn(rebinds.clone());

        // A real monitor's event stream that we never trigger — the loop should still end on the
        // shutdown flip alone.
        let (monitor, _trigger) = ManualLinkMonitor::new();
        let (mut events, _handle) = monitor.watch(env.shutdown.clone()).unwrap();
        let loop_env = env.clone();
        let loop_task = tokio::spawn(async move { run(&mut events, &direct, &loop_env).await });

        sd_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), loop_task)
            .await
            .expect("loop must end on shutdown")
            .expect("loop task joins");
    }

    /// End-to-end through the REAL `NetmonSupervisor` actor and a REAL `ManualLinkMonitor`, driving
    /// a REAL `DirectManager` (full underlay stack: dataplane + multiderp + direct). Fires ONE
    /// synthetic link event and asserts the reaction actually happened: the underlay socket is
    /// rebound (its local port changes) AND a `MeasureNow`-driven re-measure path is exercised (the
    /// supervisor publishes `MeasureNow` on the bus). This proves the whole slice-(a) pipeline with
    /// no OS code — the manual monitor stands in for the (later-slice) OS backend.
    #[tokio::test]
    async fn supervisor_reacts_end_to_end_with_manual_monitor() {
        let (_sd_tx, sd_rx) = watch::channel(false);
        let env = test_env(sd_rx);

        // Stand up the real underlay stack the supervisor drives.
        let dataplane = crate::dataplane::DataplaneActor::spawn(env.clone());
        let (_home_tx, home_rx) = watch::channel(None);
        let multiderp =
            crate::multiderp::Multiderp::spawn((env.clone(), dataplane.clone(), home_rx));
        let direct = crate::direct::DirectManager::spawn((
            env.clone(),
            dataplane.clone(),
            multiderp.clone(),
        ));

        // The underlay socket's local port before the link event.
        let sock_before = direct
            .ask(crate::direct::SockHandle)
            .await
            .expect("direct manager up");
        let port_before = sock_before.as_ref().map(|s| {
            s.local_addr()
                .expect("bound socket has a local addr")
                .port()
        });

        // Tap MeasureNow on the bus.
        let measures = Arc::new(AtomicUsize::new(0));
        let tap = MeasureNowTap::spawn(measures.clone());
        env.subscribe::<MeasureNow>(&tap).await.unwrap();

        // The REAL supervisor actor + a REAL manual monitor (short settle for a quick test).
        let (monitor, trigger) = ManualLinkMonitor::with_settle(Duration::from_millis(50));
        let monitor: Arc<dyn ts_netmon::LinkMonitor> = Arc::new(monitor);
        let _supervisor = NetmonSupervisor::spawn(NetmonSupervisorArgs {
            monitor,
            direct: direct.clone(),
            env: env.clone(),
        });

        // Fire ONE synthetic link change (a small burst → one coalesced event).
        for _ in 0..4 {
            assert!(trigger.trigger());
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        // The re-netcheck kick must reach the bus exactly once.
        wait_until(&measures, 1, "MeasureNow published end-to-end").await;

        // The rebind kick must have swapped the underlay socket: a fresh ephemeral port.
        let sock_after = direct
            .ask(crate::direct::SockHandle)
            .await
            .expect("direct manager up");
        let port_after = sock_after.as_ref().map(|s| {
            s.local_addr()
                .expect("bound socket has a local addr")
                .port()
        });
        assert!(
            port_before.is_some() && port_after.is_some(),
            "the underlay socket must be bound before and after (not inert)"
        );
        assert_ne!(
            port_before, port_after,
            "RebindAndReprobe must have rebound the underlay socket to a new ephemeral port"
        );

        // A single coalesced event must not produce a second re-netcheck.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            measures.load(Ordering::SeqCst),
            1,
            "exactly one MeasureNow for one coalesced link event"
        );

        drop(trigger);
    }
}
