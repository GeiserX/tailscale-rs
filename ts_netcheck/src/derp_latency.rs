//! Calculate latency to collections of derp servers.

use core::{fmt::Debug, net::SocketAddr, time::Duration};

use ts_control::DerpMap;
use ts_derp::RegionId;

/// Configuration for probing derp map latency.
#[derive(Debug, Copy, Clone)]
pub struct Config {
    /// The number of region probes that must succeed for the probe to end.
    ///
    /// After `complete_threshold` and `min_timeout` are met (or all region probes
    /// complete, or [`report_timeout`](Self::report_timeout) elapses), the derp map measurement
    /// ends.
    pub complete_threshold: usize,

    /// The shortest duration for a derp map probe.
    ///
    /// After `complete_threshold` and `min_timeout` are met (or all region probes complete, or
    /// [`report_timeout`](Self::report_timeout) elapses), the derp map measurement ends.
    pub min_timeout: Duration,

    /// Hard upper bound on a whole derp-map measurement — the measurement returns whatever results
    /// it has once this elapses, regardless of `complete_threshold`. Without it the harvest loop
    /// could only end on `complete_threshold` results *or* every spawned probe completing, so a
    /// derp map with fewer than `complete_threshold` reachable regions (a small/partial map) would
    /// block until the slowest probe finished — and a probe to a black-holed server can hang for
    /// the OS-default connect timeout (minutes). Since `measure_derp_map` is awaited inside the
    /// latency-measurer actor, that stalls the actor. Mirrors Go netcheck's `ReportTimeout` (5s).
    pub report_timeout: Duration,

    /// Per-region probe timeout — a single region's measurement is abandoned (counts as a failed
    /// probe) after this long, so one slow/black-holed server can't consume the whole
    /// [`report_timeout`](Self::report_timeout) budget on its own. Mirrors Go netcheck's
    /// `httpsProbeTimeout`.
    pub probe_timeout: Duration,

    /// Config for HTTP probes.
    pub https: crate::https::Config,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            complete_threshold: 3,
            min_timeout: Duration::from_millis(250),
            report_timeout: Duration::from_secs(5),
            probe_timeout: Duration::from_secs(5),

            https: Default::default(),
        }
    }
}

/// Result of measuring latency for a particular derp region.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RegionResult {
    // NOTE(npry): field order is load-bearing wrt. *Ord derives. `latency` must come first to
    // ensure results are primarily sorted by latency.
    /// The measured latency.
    pub latency: Duration,
    /// The id of the region.
    pub id: RegionId,
    /// The latency map key (in the format to be submitted to control).
    pub latency_map_key: String,
    /// The remote peer we successfully ran the measurement against.
    pub connected_remote: SocketAddr,
}

/// Measure all regions in the supplied [`DerpMap`] and return a binary heap sorted by
/// mean per-region sample time.
#[tracing::instrument(skip_all)]
pub async fn measure_derp_map(map: &DerpMap, config: &Config) -> Vec<RegionResult> {
    let mut joinset = tokio::task::JoinSet::new();

    for (&id, region) in map {
        if region.info.no_measure_no_home {
            tracing::trace!(region_id = %id, "skip! region is no_measure_no_home");
            continue;
        }

        let servers = region.servers.clone();
        let latency_map_key = format!("{id}-v4");

        let https_config = config.https;
        let probe_timeout = config.probe_timeout;

        joinset.spawn(async move {
            let sample_info = probe_with_timeout(
                id,
                probe_timeout,
                crate::measure_https_latency(&servers, https_config),
            )
            .await;

            Result::<_, crate::https::Error>::Ok((id, latency_map_key, sample_info))
        });
    }

    harvest_results(&mut joinset, map.len(), config).await
}

/// Bound a single region's latency probe by `probe_timeout`, collapsing its result to the
/// `(latency, remote)` pair `harvest_results` consumes. A black-holed server otherwise hangs on the
/// OS-default TCP connect timeout (minutes), which would consume the whole report budget; on timeout
/// the region is treated as having no reachable server (a failed probe), matching the
/// `measure_https_latency` -> `None` path. Generic over the probe future's `Server` so it doesn't
/// name the borrowed `ServerConnInfo` lifetime, and so the timeout behavior is unit-testable with a
/// virtual-time future (a real dial does not respect a paused clock).
async fn probe_with_timeout<Server, F>(
    id: RegionId,
    probe_timeout: Duration,
    probe: F,
) -> Option<(Duration, SocketAddr)>
where
    F: core::future::Future<Output = Option<(Duration, Server, SocketAddr)>>,
{
    match tokio::time::timeout(probe_timeout, probe).await {
        Ok(res) => res.map(|(dur, _info, addr)| (dur, addr)),
        Err(_elapsed) => {
            tracing::debug!(region_id = %id, ?probe_timeout, "region probe timed out");
            None
        }
    }
}

/// The probe-task result type spawned by [`measure_derp_map`]: `(region id, latency map key,
/// Some((latency, remote)) on success or None when no server was reachable)`, wrapped in the HTTPS
/// probe `Result`.
type ProbeResult = Result<(RegionId, String, Option<(Duration, SocketAddr)>), crate::https::Error>;

/// Harvest spawned region-probe results into a sorted [`RegionResult`] list, bounded three ways:
/// stop once `complete_threshold` results have arrived AND `min_timeout` elapsed (the fast path on a
/// healthy map), or when every probe completes, or — the hard backstop — when `report_timeout`
/// elapses. The last is what prevents a stall: the `complete_threshold`+`min_timeout` condition can
/// never be met by a map with fewer than `complete_threshold` reachable regions, so without the
/// deadline the loop would wait for the slowest probe, and a probe to a black-holed server hangs for
/// the OS-default connect timeout — stalling the latency-measurer actor that awaits this.
///
/// Split out of [`measure_derp_map`] so the deadline logic is unit-testable with virtual-time tasks
/// (a real network dial does not respect a paused clock).
async fn harvest_results(
    joinset: &mut tokio::task::JoinSet<ProbeResult>,
    capacity: usize,
    config: &Config,
) -> Vec<RegionResult> {
    let mut out = Vec::with_capacity(capacity);

    let process_joinset_result = |out: &mut Vec<_>, ret| {
        match ret {
            Ok(Ok((id, latency_map_key, Some((dur, addr))))) => {
                out.push(RegionResult {
                    latency: dur,
                    connected_remote: addr,
                    id,
                    latency_map_key,
                });
            }
            Ok(Err(e)) => {
                tracing::error!(error = %e, "measuring region failed");
            }
            Ok(Ok((id, ..))) => {
                tracing::error!(%id, "region had no reachable servers");
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to join");
            }
        };
    };

    let mut timeout = core::pin::pin![tokio::time::sleep(config.min_timeout)];
    // Hard upper bound on the whole measurement (Go netcheck `ReportTimeout`). The loop's own
    // condition can only end on `complete_threshold` results plus `min_timeout`, or on every probe
    // completing — neither bounds a map with fewer than `complete_threshold` reachable regions whose
    // slowest probe hangs. This deadline guarantees the loop returns with whatever it has.
    let mut report_deadline = core::pin::pin![tokio::time::sleep(config.report_timeout)];

    while !(out.len() >= config.complete_threshold && timeout.is_elapsed()) {
        tokio::select! {
            ret = joinset.join_next() => {
                let Some(ret) = ret else {
                    break;
                };

                process_joinset_result(&mut out, ret);
            },
            // The `if !timeout.is_elapsed()` precondition is load-bearing: a completed `sleep`
            // polled again returns `Ready` immediately, so without the guard this arm would fire on
            // every iteration once `min_timeout` elapsed — busy-spinning at 100% CPU (and never
            // parking, so the report deadline below would never get a chance to fire) for the whole
            // window between `min_timeout` elapsing and the last probe completing. Disabling the arm
            // once elapsed lets the loop park on `join_next` + `report_deadline`.
            _ = &mut timeout, if !timeout.is_elapsed() => {},
            // No `is_elapsed` guard is needed on this arm precisely because it unconditionally
            // `break`s — a completed `report_deadline` is therefore never re-polled, so it can't
            // busy-spin the way the empty-bodied `timeout` arm above would. If this arm ever gains a
            // `continue` or loses the `break`, it MUST get the same `if !…is_elapsed()` guard.
            _ = &mut report_deadline => {
                tracing::debug!(
                    report_timeout = ?config.report_timeout,
                    collected = out.len(),
                    "derp-map measurement hit the report deadline; returning partial results"
                );
                break;
            },
        }
    }

    // If there are any more ready results available without waiting, add them.
    while let Some(x) = joinset.try_join_next() {
        process_joinset_result(&mut out, x);
    }

    out.sort();

    out
}

#[cfg(test)]
mod test {
    use super::*;

    /// Spawn `n` probe tasks that never resolve in virtual time (`sleep(1h)`), modelling regions
    /// whose dial hangs (a black-holed server). Virtual-time `sleep` respects the paused clock — a
    /// real network dial would not, which is why these tests drive `harvest_results` directly rather
    /// than `measure_derp_map`'s real `measure_https_latency` probes.
    fn hanging_joinset(n: usize) -> tokio::task::JoinSet<ProbeResult> {
        let mut js = tokio::task::JoinSet::new();
        for i in 0..n {
            js.spawn(async move {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                // Never reached within the test's virtual-time horizon.
                Ok((
                    RegionId(core::num::NonZeroU32::new((i + 1) as u32).unwrap()),
                    format!("{}-v4", i + 1),
                    None,
                ))
            });
        }
        js
    }

    /// The report deadline bounds the harvest even when fewer than `complete_threshold` probes ever
    /// complete (the bug: the loop's `complete_threshold` + `min_timeout` condition is unsatisfiable
    /// with too few reachable regions, so without the deadline it waits for the slowest probe — and a
    /// black-holed connect hangs for the OS-default timeout, stalling the latency-measurer actor that
    /// awaits this). `start_paused` fires the deadline in virtual time. Without the `report_deadline`
    /// arm this test would hang (the tasks sleep for 1h), so it is a real regression guard.
    #[tokio::test(start_paused = true)]
    async fn report_deadline_bounds_hanging_probes() {
        // One hanging probe < the default complete_threshold of 3, so only the deadline can end it.
        let mut js = hanging_joinset(1);
        let config = Config {
            report_timeout: Duration::from_secs(5),
            probe_timeout: Duration::from_secs(30),
            ..Default::default()
        };

        let result = harvest_results(&mut js, 1, &config).await;
        assert!(
            result.is_empty(),
            "hanging probes yield no results; the deadline returns an empty report"
        );
    }

    /// The genuine fast-path exit: the `out.len() >= complete_threshold && min_timeout elapsed`
    /// `while` condition (not the empty-joinset `join_next() -> None` break). To reach it the set
    /// must still be NON-empty when the threshold is met, so this spawns `complete_threshold` fast
    /// probes PLUS one that hangs past the deadline: the threshold is hit with the hanger still
    /// pending, the loop parks until `min_timeout` elapses, then the `while` condition exits — well
    /// before the report deadline, and without waiting on the hanger. This is the common-case path
    /// the deadline must not penalize.
    #[tokio::test(start_paused = true)]
    async fn fast_results_return_on_the_threshold_fast_path() {
        let mut js: tokio::task::JoinSet<ProbeResult> = tokio::task::JoinSet::new();
        for i in 0..3u32 {
            js.spawn(async move {
                Ok((
                    RegionId(core::num::NonZeroU32::new(i + 1).unwrap()),
                    format!("{}-v4", i + 1),
                    Some((Duration::from_millis(10 * u64::from(i + 1)), addr())),
                ))
            });
        }
        // A 4th probe that never resolves before the deadline keeps the set non-empty after the
        // first 3 are collected, forcing the exit through the threshold+min_timeout `while`
        // condition rather than the empty-set break.
        js.spawn(async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            Ok((
                RegionId(core::num::NonZeroU32::new(99).unwrap()),
                "99-v4".to_owned(),
                None,
            ))
        });

        let config = Config {
            complete_threshold: 3,
            min_timeout: Duration::from_millis(250),
            report_timeout: Duration::from_secs(5),
            ..Default::default()
        };

        let result = harvest_results(&mut js, 4, &config).await;
        assert_eq!(
            result.len(),
            3,
            "the three fast probes are collected at the threshold"
        );
        // Sorted by latency (the Ord on RegionResult): region 1 (10ms) first.
        assert_eq!(
            result[0].id,
            RegionId(core::num::NonZeroU32::new(1).unwrap())
        );
    }

    /// `probe_with_timeout` (the per-region bound — the *other* half of the fix from the report
    /// deadline) abandons a hanging probe and reports it as a failed probe (`None`), in virtual
    /// time. Without the `tokio::time::timeout` wrapper this would hang on the 1h sleep.
    #[tokio::test(start_paused = true)]
    async fn probe_with_timeout_abandons_a_hanging_probe() {
        let id = RegionId(core::num::NonZeroU32::new(1).unwrap());
        // A probe future that never produces a result within the test horizon.
        let hanging = async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            Some((Duration::from_millis(1), "server", addr()))
        };

        let result = probe_with_timeout(id, Duration::from_secs(2), hanging).await;
        assert_eq!(
            result, None,
            "a probe that exceeds probe_timeout is a failed probe"
        );
    }

    /// `probe_with_timeout` passes through a probe that completes before the timeout, collapsing the
    /// `(latency, server, remote)` triple to the `(latency, remote)` pair the harvester consumes.
    #[tokio::test(start_paused = true)]
    async fn probe_with_timeout_passes_through_a_fast_probe() {
        let id = RegionId(core::num::NonZeroU32::new(1).unwrap());
        let fast = async { Some((Duration::from_millis(7), "server", addr())) };

        let result = probe_with_timeout(id, Duration::from_secs(5), fast).await;
        assert_eq!(result, Some((Duration::from_millis(7), addr())));
    }

    /// Mixed: some probes resolve fast, the rest hang. The fast ones are collected and the deadline
    /// caps the wait for the hangers — the harvest returns the partial set rather than blocking on
    /// the stuck probes (with `complete_threshold` above the number of fast results, so the fast
    /// path can't end it and the deadline must).
    #[tokio::test(start_paused = true)]
    async fn partial_results_returned_at_deadline_when_some_probes_hang() {
        let mut js: tokio::task::JoinSet<ProbeResult> = tokio::task::JoinSet::new();
        // Two fast successes...
        for i in 0..2u32 {
            js.spawn(async move {
                Ok((
                    RegionId(core::num::NonZeroU32::new(i + 1).unwrap()),
                    format!("{}-v4", i + 1),
                    Some((Duration::from_millis(20), addr())),
                ))
            });
        }
        // ...and one that hangs past the deadline.
        js.spawn(async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            Ok((
                RegionId(core::num::NonZeroU32::new(9).unwrap()),
                "9-v4".to_owned(),
                None,
            ))
        });

        let config = Config {
            // 3 required but only 2 will ever succeed → the fast path can't fire; the deadline must.
            complete_threshold: 3,
            report_timeout: Duration::from_secs(5),
            ..Default::default()
        };

        let result = harvest_results(&mut js, 3, &config).await;
        assert_eq!(
            result.len(),
            2,
            "the two fast probes are returned; the hanger is dropped"
        );
    }

    fn addr() -> SocketAddr {
        "203.0.113.1:443".parse().unwrap()
    }

    #[tracing_test::traced_test]
    #[tokio::test]
    async fn map() {
        if !ts_test_util::run_net_tests() {
            return;
        }

        let map = load_derp_map().await;
        let result = measure_derp_map(&map, &Default::default()).await;

        tracing::info!("measured latencies:\n{result:#?}");
    }

    async fn load_derp_map() -> DerpMap {
        const DERP_MAP_URL: &str = "https://login.tailscale.com/derpmap/default";

        let result = reqwest::get(DERP_MAP_URL).await.unwrap();
        let body = result.bytes().await.unwrap();

        let map = serde_json::from_slice::<ts_control_serde::DerpMap>(&body).unwrap();

        ts_control::convert_derp_map(&map).collect()
    }
}
