use std::sync::Arc;

use kameo::{
    actor::ActorRef,
    message::{Context, Message},
};
use ts_netcheck::RegionResult;

use crate::{Error, env::Env};

#[derive(Clone)]
pub struct DerpLatencyMeasurement {
    pub measurement: Arc<Vec<RegionResult>>,
}

/// Bus request to re-measure DERP latency **now**, against the most recently seen derp map.
///
/// Published by the [`NetmonSupervisor`](crate::netmon::NetmonSupervisor) on a coalesced link
/// change: today the measurer only re-measures when control pushes a *new* derp map, so without
/// this a Wi-Fi switch / sleep-wake would leave the home-region selection (driven downstream off
/// `DerpLatencyMeasurement`) stale until the next map arrives. This keeps the decoupled bus
/// architecture — the supervisor needs no `ActorRef<DerpLatencyMeasurer>`, it just publishes this
/// onto the same bus the measurer already subscribes to. A no-op if no derp map has been seen yet
/// (there is nothing to measure against).
#[derive(Clone, Copy, Debug)]
pub struct MeasureNow;

pub struct DerpLatencyMeasurer {
    env: Env,
    /// The most recently observed derp map, cached so [`MeasureNow`] can re-measure on demand
    /// (e.g. after a link change) without waiting for control to push a fresh map. `None` until the
    /// first map arrives. Cloning a [`ts_control::DerpMap`] (a `BTreeMap`) is cheap relative to the
    /// network measurement it gates.
    last_derp_map: Option<ts_control::DerpMap>,
}

impl DerpLatencyMeasurer {
    /// Run a DERP-latency measurement against `derp_map` and publish the result on the bus. Shared
    /// by the new-map path and the on-demand [`MeasureNow`] path so both emit an identical
    /// [`DerpLatencyMeasurement`] (the home-region re-selection downstream treats them the same).
    async fn measure_and_publish(&self, derp_map: &ts_control::DerpMap) {
        let latencies = ts_netcheck::measure_derp_map(derp_map, &Default::default()).await;

        tracing::trace!(?latencies, "measurement complete");

        if let Err(e) = self
            .env
            .publish(DerpLatencyMeasurement {
                measurement: Arc::new(latencies),
            })
            .await
        {
            tracing::error!(error = %e, "publishing");
        };
    }
}

impl kameo::Actor for DerpLatencyMeasurer {
    type Args = Env;
    type Error = Error;

    async fn on_start(env: Env, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        env.subscribe::<Arc<ts_control::StateUpdate>>(&slf).await?;
        // Also listen for on-demand re-measure requests (the supervisor publishes `MeasureNow` on a
        // link change). Same bus, no extra ActorRef threading.
        env.subscribe::<MeasureNow>(&slf).await?;

        tracing::trace!("derp latency measurer running");

        Ok(Self {
            env,
            last_derp_map: None,
        })
    }
}

impl Message<Arc<ts_control::StateUpdate>> for DerpLatencyMeasurer {
    type Reply = ();

    async fn handle(
        &mut self,
        state_update: Arc<ts_control::StateUpdate>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let Some(derp_map) = &state_update.derp else {
            return;
        };

        tracing::trace!("new derp map: beginning measurement");

        // Cache the map so a later `MeasureNow` (link change) can re-measure against it without a
        // fresh map from control.
        self.last_derp_map = Some(derp_map.clone());

        self.measure_and_publish(derp_map).await;
    }
}

impl Message<MeasureNow> for DerpLatencyMeasurer {
    type Reply = ();

    async fn handle(&mut self, _msg: MeasureNow, _ctx: &mut Context<Self, Self::Reply>) {
        let Some(derp_map) = self.last_derp_map.clone() else {
            // No derp map seen yet — nothing to measure against. The next new-map update will
            // measure and cache; a subsequent `MeasureNow` will then have a map.
            tracing::trace!("MeasureNow with no cached derp map; skipping on-demand re-measure");
            return;
        };

        tracing::trace!("on-demand re-measure (MeasureNow) against cached derp map");

        self.measure_and_publish(&derp_map).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kameo::actor::Spawn;
    use std::time::Duration;
    use tokio::sync::watch;

    /// A minimal `ForwarderConfig` for standing up an `Env` in these bus tests (mirrors the inline
    /// configs the sibling actor tests use; nothing here depends on the forwarding fields).
    fn forwarder_cfg() -> crate::env::ForwarderConfig {
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
            network_monitor: false,
            persistent_keepalive_interval: None,
            ingress_active: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// A `StateUpdate` carrying only an (empty) derp map. An empty derp map measures instantly (no
    /// regions to probe), so this exercises the cache + publish path without any network.
    fn derp_update() -> Arc<ts_control::StateUpdate> {
        Arc::new(ts_control::StateUpdate {
            session_handle: None,
            seq: 0,
            keep_alive: false,
            derp: Some(ts_control::DerpMap::new()),
            node: None,
            peer_update: None,
            peer_patches: Vec::new(),
            user_profiles: Vec::new(),
            ping: None,
            packetfilter: None,
            cap_grants: None,
            pop_browser_url: None,
            dial_plan: None,
            dns_config: None,
            ssh_policy: None,
            tka: None,
            online_change: Default::default(),
            peer_seen_change: Default::default(),
        })
    }

    /// Feeding a derp map then publishing `MeasureNow` produces a SECOND `DerpLatencyMeasurement`
    /// (the on-demand re-measure fires against the cached map). With an empty derp map the
    /// measurement completes immediately (no regions to probe), so this exercises the cache + the
    /// `MeasureNow` re-publish without any network.
    #[tokio::test]
    async fn measure_now_re_publishes_against_cached_map() {
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let env = Env::new(ts_keys::NodeState::generate(), shutdown_rx, forwarder_cfg());

        // A tap actor that counts published DerpLatencyMeasurements.
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let tap = MeasurementTap::spawn((env.clone(), counter.clone()));
        env.subscribe::<DerpLatencyMeasurement>(&tap).await.unwrap();

        let measurer = DerpLatencyMeasurer::spawn(env.clone());

        // Push an (empty) derp map: this measures + publishes once and caches the map.
        measurer
            .tell(derp_update())
            .await
            .expect("state update delivered to measurer");

        // Wait for the first publish to land at the tap.
        wait_until(&counter, 1, "first measurement (new derp map)").await;

        // Now publish MeasureNow on the bus: the measurer must re-measure against the cached map
        // and publish a second measurement.
        env.publish(MeasureNow).await.unwrap();
        wait_until(&counter, 2, "second measurement (MeasureNow re-measure)").await;
    }

    /// `MeasureNow` with no derp map ever seen is a no-op: no measurement is published.
    #[tokio::test]
    async fn measure_now_without_cached_map_is_noop() {
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let env = Env::new(ts_keys::NodeState::generate(), shutdown_rx, forwarder_cfg());

        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let tap = MeasurementTap::spawn((env.clone(), counter.clone()));
        env.subscribe::<DerpLatencyMeasurement>(&tap).await.unwrap();

        let _measurer = DerpLatencyMeasurer::spawn(env.clone());

        env.publish(MeasureNow).await.unwrap();

        // Give the bus + actor time to (not) publish. A short sleep is enough: with no cached map
        // the handler returns without publishing.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "MeasureNow with no cached derp map must not publish a measurement"
        );
    }

    /// Counts `DerpLatencyMeasurement`s published on the bus.
    struct MeasurementTap {
        count: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl kameo::Actor for MeasurementTap {
        type Args = (Env, Arc<std::sync::atomic::AtomicUsize>);
        type Error = Error;

        async fn on_start(
            (_env, count): Self::Args,
            _slf: ActorRef<Self>,
        ) -> Result<Self, Self::Error> {
            Ok(Self { count })
        }
    }

    impl Message<DerpLatencyMeasurement> for MeasurementTap {
        type Reply = ();

        async fn handle(
            &mut self,
            _msg: DerpLatencyMeasurement,
            _ctx: &mut Context<Self, Self::Reply>,
        ) {
            self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Poll `counter` until it reaches `want` or a generous timeout elapses (the bus + actor mailbox
    /// hops are async). Fails the test with `what` on timeout rather than hanging.
    async fn wait_until(counter: &std::sync::atomic::AtomicUsize, want: usize, what: &str) {
        for _ in 0..200 {
            if counter.load(std::sync::atomic::Ordering::SeqCst) >= want {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!(
            "timed out waiting for {what}: count={} want={want}",
            counter.load(std::sync::atomic::Ordering::SeqCst)
        );
    }
}
