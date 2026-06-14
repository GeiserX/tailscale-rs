use alloc::{collections::BTreeMap, sync::Arc};

use futures_util::{Stream, StreamExt};
use tokio::{
    sync::{broadcast, mpsc, watch},
    task::JoinSet,
};
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use url::Url;

use crate::{
    ControlDialer, Error,
    map_request_builder::MapRequestBuilder,
    tokio::{
        map_stream::{StateUpdate, map_stream, send_map_request},
        ping::handle_ping,
    },
};

/// A client to communicate with control.
#[derive(Debug)]
pub struct AsyncControlClient {
    base_url: Url,
    state_tx: broadcast::Sender<Arc<StateUpdate>>,
    command_tx: mpsc::Sender<Command>,
    _tasks: JoinSet<()>,
}

impl AsyncControlClient {
    /// Check whether it is possible to login with the given config, node keys, and auth
    /// key.
    pub async fn check_auth(
        config: &crate::Config,
        node_keys: &ts_keys::NodeState,
        auth_key: Option<&str>,
    ) -> Result<(), Error> {
        let control_url = &config.server_url;

        let h2_client = crate::tokio::connect(
            control_url,
            &node_keys.machine_keys,
            config.allow_http_key_fetch,
        )
        .await?;

        crate::tokio::register(config, control_url, auth_key, node_keys, &h2_client).await?;

        Ok(())
    }

    /// Connects to the control plane, registers this Tailscale node, and starts handling the
    /// message stream from control.
    ///
    /// The second element of the return value is a netmap stream which started listening
    /// _before_ the client connected, i.e. it will not miss any updates from control.
    ///
    /// `auth_url_tx` is the embedder-owned "current pending re-auth URL" cell: if the live
    /// map-poll loop hits a mid-session re-auth (control returns
    /// [`MachineNotAuthorized`](crate::Error::MachineNotAuthorized) on a re-register because the
    /// node key expired or was revoked), `run` publishes that URL here without tearing the loop
    /// down, so the embedder can prompt the user to re-authorize while registration keeps retrying.
    /// The caller creates the channel and keeps the [`Receiver`](watch::Receiver) (this crate must
    /// not depend on the embedder's device-state types, so the cell carries a bare `Option<Url>`).
    #[tracing::instrument(skip_all, fields(control_url = %config.server_url))]
    pub async fn connect(
        config: &crate::Config,
        node_keys: &ts_keys::NodeState,
        auth_key: Option<&str>,
        auth_url_tx: watch::Sender<Option<Url>>,
    ) -> Result<
        (
            Self,
            impl Stream<Item = Arc<StateUpdate>> + Send + Sync + use<>,
        ),
        Error,
    > {
        let control_url = &config.server_url;
        let mut tasks = JoinSet::new();

        let h2_client = crate::tokio::connect(
            control_url,
            &node_keys.machine_keys,
            config.allow_http_key_fetch,
        )
        .await?;
        tracing::info!("connected to control, registering");

        crate::tokio::register(config, control_url, auth_key, node_keys, &h2_client).await?;

        tracing::info!("registered, starting netmap stream");

        let (state_tx, state_rx) = broadcast::channel(32);
        let (command_tx, command_rx) = mpsc::channel(32);

        tasks.spawn({
            let state_tx = state_tx.clone();
            let control_url = control_url.clone();
            let node_keys = node_keys.clone();
            let auth_key = auth_key.map(ToOwned::to_owned);
            let config = config.clone();

            async move {
                run(
                    state_tx,
                    command_rx,
                    control_url.clone(),
                    node_keys.clone(),
                    auth_key,
                    config,
                    auth_url_tx,
                )
                .await
            }
        });

        Ok((
            Self {
                base_url: control_url.clone(),
                state_tx,
                command_tx,
                _tasks: tasks,
            },
            netmap_stream(state_rx),
        ))
    }

    /// Set the DERP home region for this node.
    #[tracing::instrument(skip_all, fields(map_url = %self.map_url(), %region_id), level = "trace")]
    pub async fn set_home_region<'c>(
        &mut self,
        region_id: ts_derp::RegionId,
        latencies: impl IntoIterator<Item = (&'c str, f64)>,
    ) {
        tracing::trace!(region = %region_id, "reporting home derp to control server");

        if let Err(e) = self
            .command_tx
            .send(Command::SetDerpHomeRegion {
                id: region_id,
                latencies: latencies
                    .into_iter()
                    .map(|(name, sample)| (name.to_owned(), sample))
                    .collect(),
            })
            .await
        {
            tracing::error!(error = %e, "setting home derp region");
        }
    }

    /// Advertise this node's magicsock UDP endpoints (ip:port candidates) to the control server
    /// so peers can learn where to attempt direct connections.
    #[tracing::instrument(skip_all, fields(map_url = %self.map_url(), n_endpoints), level = "trace")]
    pub async fn set_endpoints(&mut self, endpoints: Vec<ts_control_serde::Endpoint>) {
        tracing::Span::current().record("n_endpoints", endpoints.len());
        tracing::trace!("reporting magicsock endpoints to control server");

        if let Err(e) = self
            .command_tx
            .send(Command::SetEndpoints { endpoints })
            .await
        {
            tracing::error!(error = %e, "setting endpoints");
        }
    }

    /// Re-advertise this node's routable IP prefixes (`Hostinfo.RoutableIPs`) to control mid-session
    /// — the wire half of a runtime `set_advertise_routes`. `routes` is the final advertised set
    /// (already filtered); it is sent on the live map-poll connection without tearing down the
    /// long-poll, exactly like [`set_endpoints`](Self::set_endpoints).
    #[tracing::instrument(skip_all, fields(map_url = %self.map_url(), n_routes = routes.len()), level = "trace")]
    pub async fn set_routable_ips(&mut self, routes: Vec<ipnet::IpNet>) {
        tracing::trace!("reporting routable IPs to control server");

        if let Err(e) = self
            .command_tx
            .send(Command::SetRoutableIPs { routes })
            .await
        {
            tracing::error!(error = %e, "setting routable IPs");
        }
    }

    /// Update this node's `Hostinfo.Hostname` to `hostname` at control mid-session — the wire half of
    /// a runtime `set_hostname`. Sent on the live map-poll connection without tearing down the
    /// long-poll, exactly like [`set_routable_ips`](Self::set_routable_ips).
    #[tracing::instrument(skip_all, fields(map_url = %self.map_url()), level = "trace")]
    pub async fn set_hostname(&mut self, hostname: String) {
        tracing::trace!("reporting hostname to control server");

        if let Err(e) = self
            .command_tx
            .send(Command::SetHostname { hostname })
            .await
        {
            tracing::error!(error = %e, "setting hostname");
        }
    }

    /// Construct the URL that should be used to fetch the netmap.
    pub fn map_url(&self) -> Url {
        self.base_url
            .join("machine/map")
            .expect("map_url was parsed without issue before")
    }

    /// Get a stream of all netmap updates.
    pub fn netmap_stream(&self) -> impl Stream<Item = Arc<StateUpdate>> + Send + Sync + use<> {
        netmap_stream(self.state_tx.subscribe())
    }
}

// Every variant is a "set X on the next map request" command, so they all legitimately share the
// `Set` prefix (each mirrors a control-side field a side MapRequest carries). The shared prefix is
// the point, not an accident — silence the variant-name lint rather than rename to something less
// clear.
#[allow(clippy::enum_variant_names)]
#[derive(Debug)]
pub enum Command {
    SetDerpHomeRegion {
        id: ts_derp::RegionId,
        latencies: BTreeMap<String, f64>,
    },
    SetEndpoints {
        endpoints: Vec<ts_control_serde::Endpoint>,
    },
    /// Re-advertise this node's routable IP prefixes (`Hostinfo.RoutableIPs`) mid-session — the wire
    /// half of a runtime `set_advertise_routes`. The routes travel IN the command (not read from the
    /// run-loop's frozen `config` clone), already filtered to the final advertised set the caller
    /// wants control to see.
    SetRoutableIPs { routes: Vec<ipnet::IpNet> },
    /// Update this node's `Hostinfo.Hostname` mid-session — the wire half of a runtime
    /// `set_hostname`. The hostname travels IN the command (the run-loop's `config` clone is frozen,
    /// so a runtime change can only reach here through the command). Hostname is display-only, so
    /// there is no local/dataplane half; control reflects the new name on the next netmap.
    SetHostname { hostname: String },
}

/// Identifies a map-poll session so a reconnect can resume the delta stream instead of
/// cold-restarting. Control assigns the `handle` in the first [`MapResponse`] of a session and
/// stamps each response with a monotonically increasing `seq`; on reconnect we offer the last
/// `(handle, seq)` we processed and control either resumes after `seq` or ignores it and starts a
/// fresh session with a full netmap (both are safe — see [`MapRequestBuilder::map_session`]).
#[derive(Clone, Default)]
struct MapSession {
    handle: String,
    seq: i64,
}

/// Upper bound on the control-supplied session handle we will store/echo. The handle is an opaque
/// token; anything beyond this is rejected to avoid unbounded memory growth and log injection.
const MAX_SESSION_HANDLE_LEN: usize = 256;

/// Advance the resume cursor from a freshly received [`StateUpdate`]. The handle is assigned once
/// (first response of a session); `seq` advances on substantive responses and is 0 on keep-alives.
///
/// If control issues a *new* handle (a fresh session), `seq` is reset to 0 so we never carry a
/// stale cursor from the prior session into the new one. A control-supplied handle that is empty,
/// over [`MAX_SESSION_HANDLE_LEN`], or contains non-`ascii_graphic` bytes is rejected (the cursor
/// is left unchanged) to bound memory and prevent log injection.
fn advance_session(session: &mut MapSession, update: &StateUpdate) {
    if let Some(handle) = &update.session_handle {
        let valid = !handle.is_empty()
            && handle.len() <= MAX_SESSION_HANDLE_LEN
            && handle.bytes().all(|b| b.is_ascii_graphic());
        if valid && *handle != session.handle {
            session.handle = handle.clone();
            session.seq = 0;
        } else if !valid {
            tracing::warn!(
                handle_len = handle.len(),
                "control sent an invalid map-session handle; ignoring it"
            );
        }
    }
    if update.seq != 0 {
        session.seq = update.seq;
    }
}

/// Whether a received [`StateUpdate`] is a **substantive** netmap response (not a bare keep-alive)
/// and so should reset the reconnect backoff. The discriminator is the `KeepAlive` flag, NOT `seq`:
/// `seq` is a map-session resume cursor that is only assigned within a named session and is left `0`
/// on *every* response by a control plane that doesn't implement resumption (e.g. Headscale), so a
/// substantive netmap can legitimately carry `seq == 0` — gating on `seq` would wrongly withhold the
/// reset against such a server and let the backoff climb to its cap against a perfectly healthy
/// control plane. This mirrors Go exactly: its map-poll backoff resets only in `UpdateFullNetmap`
/// (`controlclient/auto.go`), reached only from `HandleNonKeepAliveMapResponse`, while a keep-alive
/// is consumed with `metricMapResponseKeepAlives.Add(1); continue` (`direct.go`) and never resets —
/// classified solely by the `KeepAlive` bool, never by `seq`. So a keep-alive-only-then-close
/// control server escalates the backoff in both Go and this fork rather than pinning it at the
/// bottom.
fn frame_resets_backoff(update: &StateUpdate) -> bool {
    !update.keep_alive
}

/// Reconnect backoff for the map-poll loop, mirroring Go's `util/backoff` (the schedule
/// `controlclient`'s `mapRoutine` uses): the delay grows as `n²·10ms`, is capped at
/// [`MAP_BACKOFF_MAX`], and is jittered to a uniform `[0.5×, 1.5×)` to avoid a thundering herd of
/// clients reconnecting in lock-step against a control server that just came back. `n` increments
/// on each consecutive failed poll and resets to 0 once a poll has delivered a **substantive**
/// (non-keep-alive) netmap response, so a flaky control plane is retried with increasing spacing
/// instead of a flat 2 Hz storm (or, on the clean-EOF path, an unthrottled hot loop).
///
/// This is the same shape as `ts_runtime`'s `DerpBackoff`; it is duplicated here (rather than
/// shared) because `ts_control` is an upstream crate that cannot depend on `ts_runtime`, and the
/// cap differs (Go passes `30*time.Second` to `NewBackoff` for `mapRoutine`, vs `5s` for the DERP
/// readers).
///
/// Reset granularity matches Go: a bare keep-alive does **not** reset the schedule. Go resets its
/// map-poll backoff only in `UpdateFullNetmap` (`controlclient/auto.go` `bo.Reset()`), which is
/// reached only from `HandleNonKeepAliveMapResponse`; a keep-alive frame is consumed with
/// `metricMapResponseKeepAlives.Add(1); continue` (`direct.go`) and never touches the backoff, after
/// which Go runs `bo.BackOff` on the poll's end (a non-paused poll always backs off). So a control
/// server that sends only keep-alives then closes the body escalates the `n²·10ms` schedule in both
/// Go and this fork — it cannot pin the backoff at the bottom. The reset is gated at the receive
/// site on [`frame_resets_backoff`], i.e. the `KeepAlive` flag — NOT on `seq` (which is a resume
/// cursor a non-resuming control plane like Headscale leaves `0` on every response, including real
/// netmaps; gating on `seq` would never reset against such a server). Go relies on the existing
/// machine-key relationship (no max-consecutive-reconnect cap), and so does this fork: a substantive
/// netmap resets and reconnects promptly, a keep-alive-only stream escalates.
#[derive(Debug, Default)]
struct ControlBackoff {
    n: u32,
}

/// Cap on the map-poll reconnect backoff delay (Go `controlclient` passes `30*time.Second` to
/// `NewBackoff` for `mapRoutine`).
const MAP_BACKOFF_MAX: core::time::Duration = core::time::Duration::from_secs(30);

impl ControlBackoff {
    /// Reset the backoff after a poll that actually received a response, so the next failure starts
    /// from the bottom of the schedule again. Crucially this is driven by *receiving a frame*, not
    /// by the poll merely ending: a control server that accepts the request then closes the body
    /// with zero frames never resets, so the clean-EOF path still backs off and escalates.
    fn reset(&mut self) {
        self.n = 0;
    }

    /// The next backoff delay, advancing the counter. `n²·10ms` capped at [`MAP_BACKOFF_MAX`], then
    /// scaled by a random factor in `[0.5, 1.5)` (matching Go's `rand.Float64()+0.5`).
    fn next_delay(&mut self, rng: &mut impl rand::RngExt) -> core::time::Duration {
        // n² growth on a 10ms base, saturating so a long outage can't overflow the multiply.
        let base_ms = u64::from(self.n)
            .saturating_mul(u64::from(self.n))
            .saturating_mul(10);
        let capped = core::time::Duration::from_millis(base_ms).min(MAP_BACKOFF_MAX);
        self.n = self.n.saturating_add(1);
        let factor = rng.random::<f64>() + 0.5;
        capped.mul_f64(factor)
    }
}

/// Decide how long to wait before the next map-poll reconnect, resetting the schedule when the poll
/// made progress. This is the **single, tested site of the load-bearing anti-DoS gate**: a poll
/// that delivered at least one frame (`received_frame`) proves the whole connect→register→poll path
/// works, so it resets the backoff and the next reconnect is immediate (Go resets its backoff on a
/// received netmap); a poll that delivered **zero** frames — a clean-EOF hot-loop, a watchdog kill,
/// or a frame the stream swallowed to `None` — does **not** reset, so a zero-progress control server
/// escalates up the `n²·10ms` schedule instead of being hammered at full speed.
///
/// The gate lives in this named function rather than as a bare `backoff.reset()` buried in the poll
/// loop precisely so it cannot be silently relocated: moving the reset onto the poll-*end* path
/// (e.g. resetting unconditionally on `Ok(())`) would reintroduce the clean-EOF hot loop, and
/// [`reconnect_delay_resets_only_when_a_frame_arrived`] would fail. The reset granularity is
/// observationally identical to resetting the instant a frame arrives: the backoff is only ever
/// read here (after the poll returns), so deferring the reset to this point changes nothing the
/// schedule can observe.
fn reconnect_delay_after_poll(
    received_frame: bool,
    backoff: &mut ControlBackoff,
    rng: &mut impl rand::RngExt,
) -> core::time::Duration {
    if received_frame {
        backoff.reset();
    }
    backoff.next_delay(rng)
}

/// Surface a mid-session re-auth URL to the embedder without disturbing the retry loop.
///
/// On a live map-poll re-register, control returning [`Error::MachineNotAuthorized`] means the
/// node key lapsed (expiry/revoke) and the user must re-authorize at the carried URL. Unlike the
/// initial-registration path (which the runtime's `check_auth` loop already surfaces), the live
/// `run` loop only logs and backs off, dropping the URL — so we publish it into the
/// embedder-owned `auth_url_tx` cell here (→ the runtime maps it to its "needs login" state). The
/// caller still propagates the error so `run` backs off and retries; a later successful
/// re-register clears the state for free (Go's `authRoutine` keeps `urlToVisit` and keeps polling).
///
/// **Only `MachineNotAuthorized` sets the cell.** `MachineNotAuthorized(None)` (no auth URL on
/// offer) maps upstream to [`Error::Internal`]`(MachineAuthorization, _)`, not this variant, so it
/// correctly does *not* set a (nonexistent) URL. The write is sticky via
/// [`send_if_modified`](watch::Sender::send_if_modified): the cell is updated only when the URL
/// actually differs from its current value, so a re-auth URL that persists across several failed
/// re-register attempts does not thrash the cell or wake the runtime's bridge spuriously.
///
/// Factored out of [`run_once`] so this classify-then-surface decision is unit-testable against a
/// plain `watch` channel without the real network round-trip [`crate::tokio::register`] performs.
fn surface_reauth_url(err: &Error, auth_url_tx: &watch::Sender<Option<Url>>) {
    if let Error::MachineNotAuthorized(url) = err {
        auth_url_tx.send_if_modified(|current| {
            if current.as_ref() == Some(url) {
                false
            } else {
                *current = Some(url.clone());
                true
            }
        });
    }
}

/// Clear any pending re-auth URL (set the cell back to `None`), used when a re-register succeeds or
/// a poll delivers a frame — both prove the node is authorized again so the surfaced URL is stale.
/// Sticky `send_if_modified` so an already-`None` cell never wakes the runtime bridge. Clearing at
/// register-success (rather than only at stream end) is what prevents a recovering poll from leaving
/// a stale `Some(url)` for the bridge to re-read and clobber the netmap's `Running` flip with.
fn clear_reauth_url(auth_url_tx: &watch::Sender<Option<Url>>) {
    auth_url_tx.send_if_modified(|current| {
        if current.is_some() {
            *current = None;
            true
        } else {
            false
        }
    });
}

pub async fn run(
    state_tx: broadcast::Sender<Arc<StateUpdate>>,
    mut command_rx: mpsc::Receiver<Command>,
    control_url: Url,
    node_keys: ts_keys::NodeState,
    auth_key: Option<String>,
    config: crate::Config,
    auth_url_tx: watch::Sender<Option<Url>>,
) {
    let mut dialer = ControlDialer::default();
    let mut session = MapSession::default();
    let mut backoff = ControlBackoff::default();

    loop {
        // `run_once` sets this to `true` the moment it receives its first frame on this poll, so
        // the flag survives an error that occurs *after* frames flowed (a poll that worked then
        // dropped still counts as progress and reconnects promptly).
        let mut received_frame = false;
        let outcome = run_once(
            &state_tx,
            &mut command_rx,
            &control_url,
            &node_keys,
            auth_key.as_deref(),
            &config,
            &mut dialer,
            &mut session,
            &mut received_frame,
            &auth_url_tx,
        )
        .await;

        // A poll that delivered any frame proves the connect→register→poll path works again, so a
        // re-auth URL surfaced by an earlier failed re-register is stale: clear the cell. The
        // primary clear is at register-success above (so the cell empties before the bridge can
        // re-read a stale `Some(url)` on recovery); this is a secondary clear for the case where the
        // stream itself delivered frames after a register that did not need re-auth. Sticky
        // `send_if_modified` so we never wake the bridge unless the cell actually changes.
        if received_frame {
            clear_reauth_url(&auth_url_tx);
        }

        // Decide how long to wait before reconnecting. A control-issued rate-limit (HTTP 429 →
        // `Error::RateLimited`) overrides the local backoff: wait EXACTLY the server-requested
        // cooldown and do NOT advance the backoff counter, mirroring Go's `authRoutine`, which sleeps
        // `time.After(rle.retryAfter)` *instead of* `bo.BackOff`. Otherwise back off before every
        // reconnect on BOTH the clean-EOF and error paths — Go's `mapRoutine` runs `bo.BackOff` after
        // every poll regardless of how it ended. The clean-EOF arm (`Ok(())`) previously reconnected
        // with ZERO delay: a control server that returns 200 then closes the body (or sends one frame
        // the stream swallows to `None`) would spin a full-speed connect→TLS→Noise→register loop,
        // hammering control and pinning CPU. The reset is gated on `received_frame` (see
        // `reconnect_delay_after_poll`), so a healthy long-lived poll that delivered frames reconnects
        // promptly while a zero-progress server escalates up the n²·10ms schedule.
        let delay = match &outcome {
            Err(Error::RateLimited(retry_after)) => *retry_after,
            _ => reconnect_delay_after_poll(received_frame, &mut backoff, &mut rand::rng()),
        };
        match outcome {
            Ok(()) => {
                tracing::warn!(
                    resume_handle = %session.handle,
                    resume_seq = session.seq,
                    backoff_ms = delay.as_millis() as u64,
                    "netmap stream ended without error, attempting restart"
                );
            }
            Err(Error::RateLimited(retry_after)) => {
                tracing::warn!(
                    ?retry_after,
                    resume_handle = %session.handle,
                    resume_seq = session.seq,
                    "control rate-limited the map-poll re-register; waiting the server-requested delay"
                );
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    resume_handle = %session.handle,
                    resume_seq = session.seq,
                    backoff_ms = delay.as_millis() as u64,
                    "netmap stream failed, attempting restart"
                );
            }
        }
        tokio::time::sleep(delay).await;
    }
}

async fn run_once(
    state_tx: &broadcast::Sender<Arc<StateUpdate>>,
    command_rx: &mut mpsc::Receiver<Command>,
    control_url: &Url,
    node_keys: &ts_keys::NodeState,
    auth_key: Option<&str>,
    config: &crate::Config,
    control_dialer: &mut ControlDialer,
    session: &mut MapSession,
    received_frame: &mut bool,
    auth_url_tx: &watch::Sender<Option<Url>>,
) -> Result<(), Error> {
    let h2_client = control_dialer
        .full_connect_next(
            control_url,
            &node_keys.machine_keys,
            config.allow_http_key_fetch,
        )
        .await?;

    // Re-register on every reconnect. On a mid-session re-auth (key expiry/revoke) control answers
    // `MachineNotAuthorized(Some(url))`: surface that URL to the embedder (→ "needs login") via
    // `surface_reauth_url`, then still propagate the error so `run` backs off and retries — Go's
    // `authRoutine` keeps the URL and keeps polling, and a later successful re-register recovers.
    match crate::tokio::register(config, control_url, auth_key, node_keys, &h2_client).await {
        Ok(()) => {
            // Re-register succeeded — clear any pending re-auth URL NOW (not at stream end), so a
            // recovering poll empties the cell BEFORE the runtime bridge can wake and re-read a
            // stale `Some(url)`. Without this, the bridge could clobber the netmap's `Running` flip
            // back to `NeedsLogin` on recovery (a recovered node would show "needs login" until the
            // next keep-alive).
            clear_reauth_url(auth_url_tx);
        }
        Err(e) => {
            let err = Error::from(e);
            surface_reauth_url(&err, auth_url_tx);
            return Err(err);
        }
    }

    let client_name = config.format_client_name();
    // Advertise-side VIP services: hash the validated hosted-service set into
    // `HostInfo.ServicesHash`. Empty config -> empty hash -> wire field omitted (unchanged behavior).
    let advertised_vip_services = config.advertised_vip_services();
    let services_hash = crate::services_hash(&advertised_vip_services);
    let builder = MapRequestBuilder::new(node_keys)
        .keep_alive(true)
        .omit_peers(false)
        .stream(true)
        .routable_ips(config.advertised_routes())
        .client_info(&client_name, crate::PKG_VERSION)
        .request_tags(config.tags.iter().map(String::as_str))
        .services(config.advertised_services())
        .services_hash(&services_hash)
        .wire_ingress(config.wire_ingress)
        .ingress_enabled(
            config
                .ingress_active
                .load(core::sync::atomic::Ordering::Relaxed),
        )
        .map_session(&session.handle, session.seq);

    let request = if let Some(hostname) = &config.hostname {
        builder.hostname(hostname)
    } else {
        builder
    }
    .build();

    let map_url = control_url.join("machine/map").unwrap();

    let reader = send_map_request(request, &map_url, &h2_client).await?;

    let mut stream = core::pin::pin!(map_stream(reader));
    tracing::info!("netmap stream started");

    loop {
        tokio::select! {
            state_update = stream.next() => {
                let Some(state_update) = state_update else {
                    break;
                };

                // A *substantive* (non-keep-alive) frame proves the full
                // connect→register→poll→netmap path works, so record it and `run` resets the
                // reconnect backoff. This mirrors Go, which resets its map-poll backoff only in
                // `UpdateFullNetmap` (control/controlclient/auto.go `bo.Reset()`), reached only via
                // `HandleNonKeepAliveMapResponse`; a bare keep-alive does
                // `metricMapResponseKeepAlives.Add(1); continue` in Go (direct.go) and never resets.
                // The discriminator is the `KeepAlive` flag, NOT `seq` (see `frame_resets_backoff`) —
                // a substantive netmap can carry `seq == 0` on a control plane without map-session
                // resumption (e.g. Headscale), so gating on `seq` would wrongly withhold the reset.
                // Gating on `!keep_alive` keeps a keep-alive-only-then-close control server from
                // pinning the backoff at the bottom while still resetting on every real netmap. The
                // reset decision itself lives in `reconnect_delay_after_poll` (the single tested
                // gate); here we only flag substantive progress.
                if frame_resets_backoff(&state_update) {
                    *received_frame = true;
                }

                // Track the session cursor so a reconnect can resume after the last processed
                // message instead of cold-restarting.
                advance_session(session, &state_update);

                let _ = handle_ping(&state_update, control_url, &h2_client, config).await;

                if let Some(dial_plan) = &state_update.dial_plan
                    && control_dialer.update_dial_plan(dial_plan)
                {
                    tracing::trace!(new_dial_plan = ?dial_plan);
                }

                // This errors only if there are no receivers. That's not semantically an error for
                // us, so just ignore it.
                let _ignore = state_tx.send(Arc::new(state_update));
            }

            command = command_rx.recv() => {
                match command.unwrap() {
                    Command::SetDerpHomeRegion { id, latencies } => {
                        let mut builder = MapRequestBuilder::new(node_keys)
                            .keep_alive(false)
                            .omit_peers(true)
                            .stream(false)
                            .routable_ips(config.advertised_routes())
                            .preferred_derp(id)
                            .derp_latencies(latencies.iter().map(|(k, v)| (k.as_str(), *v)));

                        if let Some(hostname) = &config.hostname {
                            builder = builder.hostname(hostname);
                        }
                        let req = builder.build();

                        drop(send_map_request(req, &map_url, &h2_client).await?);
                    },
                    Command::SetEndpoints { endpoints } => {
                        let mut builder = MapRequestBuilder::new(node_keys)
                            .keep_alive(false)
                            .omit_peers(true)
                            .stream(false)
                            .routable_ips(config.advertised_routes())
                            .endpoints(endpoints);

                        if let Some(hostname) = &config.hostname {
                            builder = builder.hostname(hostname);
                        }
                        let req = builder.build();

                        drop(send_map_request(req, &map_url, &h2_client).await?);
                    },
                    Command::SetRoutableIPs { routes } => {
                        // The routes come from the command payload, NOT `config.advertised_routes()`:
                        // `config` is a frozen clone captured when this loop started, so a runtime
                        // route change can only reach here through the command itself.
                        let mut builder = MapRequestBuilder::new(node_keys)
                            .keep_alive(false)
                            .omit_peers(true)
                            .stream(false)
                            .routable_ips(routes);

                        if let Some(hostname) = &config.hostname {
                            builder = builder.hostname(hostname);
                        }
                        let req = builder.build();

                        drop(send_map_request(req, &map_url, &h2_client).await?);
                    },
                    Command::SetHostname { hostname } => {
                        // The hostname comes from the command payload, NOT `config.hostname`: the
                        // run-loop's `config` is a frozen clone, so a runtime hostname change can only
                        // reach here through the command. Preserve the advertised routes on this
                        // request so a hostname update doesn't transiently withdraw them.
                        let req = MapRequestBuilder::new(node_keys)
                            .keep_alive(false)
                            .omit_peers(true)
                            .stream(false)
                            .routable_ips(config.advertised_routes())
                            .hostname(&hostname)
                            .build();

                        drop(send_map_request(req, &map_url, &h2_client).await?);
                    },
                }
            }
        }
    }

    Ok(())
}

fn netmap_stream(
    rx: broadcast::Receiver<Arc<StateUpdate>>,
) -> impl Stream<Item = Arc<StateUpdate>> + Send + Sync {
    tokio_stream::wrappers::BroadcastStream::new(rx).filter_map(async |x| {
        if let Err(BroadcastStreamRecvError::Lagged(n)) = &x {
            tracing::warn!(messages_missed = n, "map_stream lagged");
        }

        x.ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A substantive (non-keep-alive) response with the given session handle + seq.
    fn update(handle: Option<&str>, seq: i64) -> StateUpdate {
        update_ka(handle, seq, false)
    }

    /// A response with an explicit keep-alive flag, for the backoff-reset gate tests.
    fn update_ka(handle: Option<&str>, seq: i64, keep_alive: bool) -> StateUpdate {
        StateUpdate {
            session_handle: handle.map(ToOwned::to_owned),
            seq,
            keep_alive,
            derp: None,
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
        }
    }

    #[test]
    fn advance_session_captures_handle_and_seq() {
        let mut session = MapSession::default();

        advance_session(&mut session, &update(Some("sess-1"), 5));

        assert_eq!(session.handle, "sess-1");
        assert_eq!(session.seq, 5);
    }

    #[test]
    fn advance_session_keepalive_preserves_cursor() {
        let mut session = MapSession {
            handle: "sess-1".to_owned(),
            seq: 7,
        };

        // Keep-alive: no handle, seq == 0. The cursor must not regress.
        advance_session(&mut session, &update(None, 0));

        assert_eq!(session.handle, "sess-1");
        assert_eq!(session.seq, 7);
    }

    #[test]
    fn advance_session_resets_seq_on_new_handle() {
        let mut session = MapSession {
            handle: "sess-1".to_owned(),
            seq: 42,
        };

        // Control started a fresh session: a new handle must reset seq so we never carry a stale
        // cursor from the prior session.
        advance_session(&mut session, &update(Some("sess-2"), 0));

        assert_eq!(session.handle, "sess-2");
        assert_eq!(session.seq, 0);
    }

    #[test]
    fn advance_session_same_handle_keeps_seq() {
        let mut session = MapSession {
            handle: "sess-1".to_owned(),
            seq: 10,
        };

        // Re-issuing the same handle (not a new session) must not reset the cursor.
        advance_session(&mut session, &update(Some("sess-1"), 0));

        assert_eq!(session.handle, "sess-1");
        assert_eq!(session.seq, 10);
    }

    /// The backoff-reset gate keys on the `KeepAlive` flag, NOT on `seq`. A bare keep-alive must NOT
    /// flag progress (else a keep-alive-only-then-close server pins the backoff at the bottom — the
    /// deviation this fixes). A substantive netmap MUST reset **even when its `seq` is 0** — a
    /// control plane without map-session resumption (e.g. Headscale) leaves `seq == 0` on every
    /// response including full netmaps, so gating on `seq` would never reset the backoff against a
    /// healthy such server (a silent regression worse than the original bug). Mirrors Go, which
    /// classifies keep-alives solely by the `KeepAlive` bool and resets on every non-keep-alive
    /// netmap (`UpdateFullNetmap`), never consulting `seq`.
    #[test]
    fn backoff_reset_keys_on_keepalive_not_seq() {
        // Keep-alives never reset, regardless of seq or handle.
        assert!(
            !frame_resets_backoff(&update_ka(None, 0, true)),
            "a keep-alive must not reset the backoff"
        );
        assert!(
            !frame_resets_backoff(&update_ka(Some("sess-1"), 0, true)),
            "a session-opening keep-alive must not reset the backoff"
        );

        // Substantive responses reset — INCLUDING seq == 0 (the Headscale / no-resumption case).
        // This is the regression guard: gating on `seq != 0` would FAIL this assertion.
        assert!(
            frame_resets_backoff(&update_ka(None, 0, false)),
            "a substantive netmap with seq==0 (Headscale-style) MUST reset the backoff"
        );
        assert!(
            frame_resets_backoff(&update_ka(Some("sess-1"), 0, false)),
            "a session-opening substantive netmap with seq==0 MUST reset the backoff"
        );
        // And the seq-bearing (SaaS resume-cursor) case still resets.
        assert!(
            frame_resets_backoff(&update_ka(Some("sess-1"), 1, false)),
            "a substantive response with a resume cursor (seq==1) must reset the backoff"
        );
    }

    #[test]
    fn advance_session_rejects_overlong_handle() {
        let mut session = MapSession::default();
        let huge = "a".repeat(MAX_SESSION_HANDLE_LEN + 1);

        advance_session(&mut session, &update(Some(&huge), 3));

        // The handle is rejected (cursor handle stays empty); seq still advances.
        assert_eq!(session.handle, "");
        assert_eq!(session.seq, 3);
    }

    #[test]
    fn advance_session_rejects_non_graphic_handle() {
        let mut session = MapSession::default();

        // A handle with control/whitespace bytes (log-injection risk) is rejected.
        advance_session(&mut session, &update(Some("bad\nhandle"), 1));

        assert_eq!(session.handle, "");
        assert_eq!(session.seq, 1);
    }

    /// The backoff delay for a given `n` must always land in `[0.5, 1.5)` of the unjittered
    /// `min(n²·10ms, MAP_BACKOFF_MAX)` — the Go `util/backoff` envelope. Probing each `n` with a
    /// fresh fixed-`n` `ControlBackoff` (the same technique `ts_runtime` uses for `DerpBackoff`)
    /// keeps the assertion independent of the process RNG.
    #[test]
    fn control_backoff_delay_is_within_the_go_jitter_envelope() {
        let mut rng = rand::rng();
        for n in 0u32..80 {
            let unjittered_ms = u64::from(n)
                .saturating_mul(u64::from(n))
                .saturating_mul(10)
                .min(MAP_BACKOFF_MAX.as_millis() as u64);
            let unjittered = core::time::Duration::from_millis(unjittered_ms);

            // 100 draws per n to exercise the jitter range.
            for _ in 0..100 {
                let mut probe = ControlBackoff { n };
                let d = probe.next_delay(&mut rng);
                if unjittered.is_zero() {
                    // n=0: the unjittered base is 0, so any jitter factor still yields exactly 0.
                    assert_eq!(d, core::time::Duration::ZERO, "n=0 delay must be zero");
                } else {
                    assert!(
                        d >= unjittered.mul_f64(0.5) && d < unjittered.mul_f64(1.5),
                        "n={n}: delay {d:?} outside [0.5,1.5) x {unjittered:?}"
                    );
                }
            }
        }
    }

    /// The delay grows monotonically (in expectation) until the cap, then is bounded by the cap's
    /// jitter envelope. We assert the *unjittered* schedule directly via the cap: by `n` large
    /// enough that `n²·10ms >= 30s`, every draw is `< 1.5 × 30s` and `>= 0.5 × 30s`.
    #[test]
    fn control_backoff_saturates_at_the_cap() {
        let mut rng = rand::rng();
        // 30_000ms / 10 = 3000 = 55² (54.7..), so n >= 55 is past the cap.
        let mut probe = ControlBackoff { n: 1000 };
        let d = probe.next_delay(&mut rng);
        assert!(
            d >= MAP_BACKOFF_MAX.mul_f64(0.5) && d < MAP_BACKOFF_MAX.mul_f64(1.5),
            "saturated delay {d:?} outside the cap's jitter envelope"
        );
        // A huge `n` must not overflow the n²·10 multiply (saturating math).
        let mut probe = ControlBackoff { n: u32::MAX };
        let d = probe.next_delay(&mut rng);
        assert!(d < MAP_BACKOFF_MAX.mul_f64(1.5), "overflowed at u32::MAX");
    }

    /// `reset()` returns the schedule to the bottom: after several advances, a reset makes the next
    /// delay the `n=0` delay (which is zero — `0²·10ms`), and the counter climbs again from there.
    #[test]
    fn control_backoff_reset_returns_to_bottom() {
        let mut rng = rand::rng();
        let mut bo = ControlBackoff::default();

        // Advance a few times.
        for _ in 0..5 {
            let _ = bo.next_delay(&mut rng);
        }
        assert!(bo.n > 0, "counter advanced");

        bo.reset();
        assert_eq!(bo.n, 0, "reset zeroes the counter");

        // The n=0 draw is 0ms (0²·10ms · jitter == 0), and the counter advances to 1 afterward.
        let d = bo.next_delay(&mut rng);
        assert_eq!(d, core::time::Duration::ZERO, "n=0 delay is zero");
        assert_eq!(bo.n, 1, "counter advances after the n=0 draw");
    }

    /// The load-bearing anti-DoS gate: [`reconnect_delay_after_poll`] resets the schedule ONLY when
    /// the poll delivered a frame. A poll that delivered ZERO frames (the clean-EOF hot-loop, a
    /// watchdog kill, or a frame swallowed to `None`) must NOT reset, so a zero-progress control
    /// server escalates up the schedule instead of being hammered at full speed.
    ///
    /// This pins the gate that protects the whole fix: if a future change resets the backoff on the
    /// poll-*end* path (e.g. unconditionally on `Ok(())`) instead of on frame receipt, this test
    /// fails — the frameless branch would start returning the `n=0` (zero) delay.
    #[test]
    fn reconnect_delay_resets_only_when_a_frame_arrived() {
        let mut rng = rand::rng();
        let mut backoff = ControlBackoff::default();

        // A run of frameless polls (zero progress) must escalate: each delay strictly larger than
        // the last in expectation, and crucially NONE collapses back to the n=0 zero delay.
        let mut last_n = backoff.n;
        for i in 0..6 {
            let d = reconnect_delay_after_poll(false, &mut backoff, &mut rng);
            assert!(
                backoff.n > last_n,
                "frameless poll {i} must advance the counter (no reset)"
            );
            last_n = backoff.n;
            if i > 0 {
                // Past n=0, a frameless reconnect is never the zero delay (the hot-loop we fixed).
                assert!(
                    d > core::time::Duration::ZERO,
                    "frameless reconnect {i} must be delayed, not a 0ms spin"
                );
            }
        }

        // Now a poll that DID receive a frame resets the schedule: the next delay is the n=0 zero
        // delay (immediate reconnect for a healthy, progressing poll), and the counter is back to 1.
        let d = reconnect_delay_after_poll(true, &mut backoff, &mut rng);
        assert_eq!(
            d,
            core::time::Duration::ZERO,
            "a poll that delivered a frame resets to the immediate (n=0) reconnect"
        );
        assert_eq!(backoff.n, 1, "reset then one draw leaves the counter at 1");
    }

    fn auth_url() -> Url {
        "https://login.example/a/abc123".parse().unwrap()
    }

    /// A mid-session `MachineNotAuthorized(url)` sets the re-auth cell to `Some(url)` — the exact
    /// drop the bug fixes (the live `run` loop used to discard this URL and only log+backoff).
    #[test]
    fn mid_session_machine_not_authorized_sets_auth_url_cell() {
        let (tx, rx) = watch::channel(None);
        let url = auth_url();

        surface_reauth_url(&Error::MachineNotAuthorized(url.clone()), &tx);

        assert_eq!(*rx.borrow(), Some(url));
    }

    /// `MachineNotAuthorized(None)` (control offered no auth URL) maps upstream to
    /// `Error::Internal(MachineAuthorization, _)`, NOT `Error::MachineNotAuthorized`, so the helper
    /// must leave the cell untouched. Built from the *exact* upstream mapping (register.rs
    /// `From<RegistrationError> for Error`) so this stays honest if that mapping ever changes.
    #[test]
    fn machine_not_authorized_none_does_not_set_url_cell() {
        let (tx, rx) = watch::channel(None);
        let err =
            Error::from(crate::tokio::register::RegistrationError::MachineNotAuthorized(None));
        // Confirm the mapping is the non-URL internal variant (the precondition for the assertion).
        assert!(matches!(
            err,
            Error::Internal(crate::InternalErrorKind::MachineAuthorization, _)
        ));

        surface_reauth_url(&err, &tx);

        assert_eq!(
            *rx.borrow(),
            None,
            "no auth URL on offer must not set the cell"
        );
    }

    /// A non-auth error (e.g. a transient network failure) must never set the cell either — only
    /// `MachineNotAuthorized` is a re-auth signal.
    #[test]
    fn non_auth_error_does_not_set_url_cell() {
        let (tx, rx) = watch::channel(None);

        surface_reauth_url(&Error::NetworkError(crate::Operation::Registration), &tx);

        assert_eq!(*rx.borrow(), None);
    }

    /// The clear path: a re-register success (or a poll that delivered a frame) means a
    /// previously-surfaced re-auth URL is stale, so `clear_reauth_url` resets the cell to `None`.
    /// This is the recovery half of the fix — clearing at register-success (run_once's `Ok` arm)
    /// empties the cell before the runtime bridge can re-read a stale `Some(url)` and clobber the
    /// netmap's `Running` flip back to `NeedsLogin` (the review's recovery-race finding).
    #[test]
    fn clear_reauth_url_resets_a_pending_url() {
        let (tx, rx) = watch::channel(Some(auth_url()));
        clear_reauth_url(&tx);
        assert_eq!(*rx.borrow(), None);
    }

    /// Clearing an already-`None` cell is a no-op that does NOT notify (so the runtime bridge isn't
    /// woken spuriously on every frame of a healthy, never-deauthorized session).
    #[test]
    fn clear_reauth_url_on_empty_cell_does_not_notify() {
        let (tx, rx) = watch::channel::<Option<Url>>(None);
        clear_reauth_url(&tx);
        // No change was published, so the receiver sees nothing new.
        assert!(!rx.has_changed().unwrap());
        assert_eq!(*rx.borrow(), None);
    }

    /// Recovery sequence at the cell level: surface a URL (failed re-register), then clear it
    /// (the next re-register succeeds). The terminal cell state is `None`, so when the bridge next
    /// reads it there is no stale `Some(url)` to re-assert `NeedsLogin` from.
    #[test]
    fn surface_then_clear_leaves_cell_empty() {
        let (tx, rx) = watch::channel(None);
        let url = auth_url();

        surface_reauth_url(&Error::MachineNotAuthorized(url.clone()), &tx);
        assert_eq!(*rx.borrow(), Some(url));

        clear_reauth_url(&tx); // models run_once's `Ok(())` arm on the recovering poll
        assert_eq!(*rx.borrow(), None);
    }
}
