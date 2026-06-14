use core::{
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};
use std::sync::Arc;

use futures::StreamExt;
use kameo::{
    actor::{ActorRef, Spawn},
    message::{Context, StreamMessage},
    prelude::Message,
};
use tokio::sync::watch;
use ts_control::{
    AsyncControlClient, Endpoint, EndpointType, Error as ControlError, IdTokenError, LogoutError,
    Node, SetDnsError, SshPolicy, StateUpdate, TkaStatus, TkaSyncError, tka_disable,
    tka_init_begin, tka_init_finish, tka_submit_signature,
};
use ts_magicsock::SelfEndpointType;

use crate::{
    derp_latency::{DerpLatencyMeasurement, DerpLatencyMeasurer},
    direct::EndpointAdvertisement,
};

/// Actor responsible for maintaining the connection to control.
///
/// This actor is responsible for proxying the map response stream onto the message bus.
pub struct ControlRunner {
    client: AsyncControlClient,
    params: Params,

    self_node: watch::Sender<Option<Node>>,
    /// Latest Tailscale SSH policy pushed by control, or `None` until control sends one. The SSH
    /// server reads this to authorize incoming connections; absent policy means deny-all.
    ssh_policy: watch::Sender<Option<SshPolicy>>,
    /// Latest Tailnet Lock status pushed by control, or `None` until control sends one.
    tka: watch::Sender<Option<TkaStatus>>,
    /// The locally-synced Tailnet-Lock state (verified `Authority` + AUM store), or `None` until a
    /// successful bootstrap+sync. Held here because `ControlRunner` owns the netmap stream that
    /// triggers resync. Mutated only on the actor thread (the netmap handler spawns the sync RPC and
    /// the result returns via the [`TkaSynced`] self-message).
    tka_synced: Option<crate::tka_sync::SyncedTka>,
    /// The verified TKA [`Authority`](ts_tka::Authority) the peer tracker **enforces** (Go
    /// `tkaFilterNetmapLocked`). `None` until the first successful sync, and reset to `None` when the
    /// lock is disabled. This is the SOLE delivery channel to the peer tracker (which holds the
    /// matching `Receiver` and reads it on every peer upsert): a `watch` cell, not a bus message, so
    /// the latest value is always readable, never dropped under load, and writes are strictly ordered
    /// by this actor — a disable (`None`) can never be reordered behind or dropped before a stale
    /// `Some`. Written only from [`apply_tka_synced`] (enable) and [`maybe_sync_tka`] (disable), both
    /// on the actor thread. The published `Authority` has always passed `VerifiedAumChain::verify`.
    tka_authority: watch::Sender<Option<Arc<ts_tka::Authority>>>,
    /// In-flight guard: `true` while a sync RPC task is running, so a burst of netmap updates does
    /// not spawn overlapping syncs (Go serializes sync under `b.mu`).
    tka_syncing: bool,
    /// Monotonic generation stamped when a disable (or a fresh sync) supersedes any in-flight sync.
    /// `maybe_sync_tka` bumps this on a disable transition and captures it into each spawned sync;
    /// [`apply_tka_synced`] discards a sync result whose captured generation is stale, so a lock
    /// disabled *while a sync was in flight* is never re-enabled by that sync's late `Ok(Some)`
    /// (the in-flight window the `tka_synced.is_some()` disable guard alone does not cover).
    tka_generation: u64,
    /// Latest cert-domain list from control's netmap DNS config (Go `nm.DNS.CertDomains`), or empty
    /// until control sends a DNS config carrying one. The facade reads this for `Device::cert_domains`.
    cert_domains: watch::Sender<Vec<String>>,
    /// Latest full DNS config from control's netmap (Go `netmap.NetworkMap.DNS`), or `None` until
    /// control sends one. The facade reads this for `Device::dns_config` (the daemon's
    /// `tnet dns status`). A superset of [`cert_domains`](Self::cert_domains), which is kept as its
    /// own cell for the narrower TLS-cert use.
    dns_config: watch::Sender<Option<ts_control::DnsConfig>>,
    /// Latest interactive-login / consent URL control asked this node to open
    /// (`MapResponse.PopBrowserURL`), or `None` until control sends one. The facade reads this for
    /// `Device::pop_browser_url` (a daemon driving a non-authkey login surfaces it to the user), and
    /// [`Runtime::watch_ipn_bus`](crate::Runtime::watch_ipn_bus) subscribes to it for the bus's
    /// `browse_to_url` running-node events.
    ///
    /// **Sticky, not per-update** (Go `controlclient` `sess.lastPopBrowserURL`): control sends
    /// `MapResponse.PopBrowserURL` empty on nearly every netmap tick, so this cell is updated ONLY on
    /// a non-empty URL that differs from its current value (`sticky_update_pop_browser_url`, via
    /// `send_if_modified` — the cell's own value is the "last URL seen", so no separate mirror is
    /// needed). It is never reset to `None` by an empty update — matching Go's `direct.go` guard
    /// `u != "" && u != sess.lastPopBrowserURL`. Updating on every tick would thrash the cell to
    /// `None` and coalesce the URL away for a `watch` subscriber.
    pop_browser_url: watch::Sender<Option<url::Url>>,
    /// Latest network-conditions report (preferred DERP region + per-region latencies), updated each
    /// time the DERP-latency measurer reports in. The facade reads this for `Device::netcheck` (the
    /// daemon's `tnet netcheck`). Empty until the first measurement.
    netcheck: watch::Sender<crate::status::NetcheckReport>,
    /// The DERP home region currently selected, with the latency measured for it at selection time.
    /// `None` until the first home region is chosen. Used to apply selection **hysteresis** (Go
    /// `netcheck.addReportHistoryAndSetPreferredDERP`): the home region is only switched when a new
    /// region is *meaningfully* lower-latency than the current one, so jitter between near-equal
    /// regions does not flap the home relay (which would cause repeated reconnects + brief loss).
    home_region: Option<(ts_derp::RegionId, core::time::Duration)>,
    /// Background task that bridges the control client's mid-session re-auth URL cell onto
    /// [`Self::params`]'s device-state cell (sets [`DeviceState::NeedsLogin`] when control returns
    /// `MachineNotAuthorized` on a live re-register — see [`bridge_reauth_url_to_state`]). Aborted on
    /// [`Drop`] so it cannot outlive the actor (the [`DataplaneActor`](crate::dataplane) pattern).
    reauth_bridge: tokio::task::JoinHandle<()>,
}

impl Drop for ControlRunner {
    fn drop(&mut self) {
        // Stop the re-auth bridge so it does not outlive the actor (mirrors `DataplaneActor`).
        self.reauth_bridge.abort();
    }
}

/// Control runner args.
pub struct Params {
    /// Control config.
    pub(crate) config: ts_control::Config,

    /// Auth key (if needed).
    pub(crate) auth_key: Option<String>,

    /// The [`crate::Env`] for this actor.
    pub(crate) env: crate::Env,

    /// Sender for the device connection-state cell. Created in [`Runtime::spawn`](crate::Runtime)
    /// so it outlives the actor's `on_start` (which may publish [`DeviceState::Failed`] and then
    /// return `Err`, before `Self` exists). The runtime keeps the matching `Receiver` for
    /// [`watch_state`](crate::Runtime::watch_state) / [`wait_until_running`](crate::Runtime::wait_until_running).
    pub(crate) state_tx: watch::Sender<crate::DeviceState>,

    /// Sender for the TKA enforcement-authority cell the peer tracker reads (Go
    /// `tkaFilterNetmapLocked`). Created in [`Runtime::spawn`](crate::Runtime) and threaded into BOTH
    /// the peer tracker (the `Receiver`) and this runner (the `Sender`), so the runner is the sole
    /// writer and the tracker reads the latest verified `Authority` on demand. `None` = no lock /
    /// disabled (admit all).
    pub(crate) tka_authority: watch::Sender<Option<Arc<ts_tka::Authority>>>,
}

#[doc(hidden)]
#[derive(Debug, thiserror::Error)]
pub enum ControlRunnerError {
    #[error(transparent)]
    Control(#[from] ControlError),

    #[error(transparent)]
    Crate(#[from] crate::Error),
}

impl kameo::Actor for ControlRunner {
    type Args = Params;
    type Error = ControlRunnerError;

    async fn on_start(params: Params, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        loop {
            match AsyncControlClient::check_auth(
                &params.config,
                &params.env.keys,
                params.auth_key.as_deref(),
            )
            .await
            {
                Ok(()) => break,
                Err(ControlError::MachineNotAuthorized(u)) => {
                    tracing::info!(auth_url = %u, "please authorize this machine or pass an auth key");
                    // Surface "interactive login required" so a watcher / `wait_until_running` can
                    // tell the user to authorize, instead of seeing an opaque timeout. Registration
                    // keeps retrying (transient), so this is not a terminal `Failed`.
                    params
                        .state_tx
                        .send_replace(crate::DeviceState::NeedsLogin(u.clone()));
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                Err(e) => {
                    // A hard registration failure (bad/expired/unknown auth key, etc.). Log the
                    // specific reason control gave AND publish it as a typed `Failed` state so
                    // `Device::wait_until_running` returns the actionable reason (tsr-kqj) instead
                    // of the opaque `Internal(Actor)` the caller would otherwise see once the
                    // stopped actor is next asked. Publishing before `return Err` is why the state
                    // sender lives on `Runtime`, not on `Self` (which never gets constructed here).
                    let reason = crate::RegistrationError::from(&e);
                    tracing::error!(error = %e, "registration failed; control runner stopping");
                    params
                        .state_tx
                        .send_replace(crate::DeviceState::Failed(reason));
                    return Err(e.into());
                }
            }
        }
        // check_auth succeeded, but the node is not "up" until the netmap stream is actually
        // attached below. Publish `Running` only AFTER `attach_stream` so `wait_until_running` never
        // resolves `Ok` for a device whose stream connect failed (which would leave a stopped actor
        // behind). If the connect/subscribe steps fail, publish a transient `Failed` first so the
        // waiter sees an actionable reason instead of the opaque post-mortem `Internal(Actor)`.
        // The control client's live map-poll loop publishes a mid-session re-auth URL here (set when
        // a re-register returns `MachineNotAuthorized` because the node key expired/was revoked). The
        // runtime owns the receiver; `connect` takes the sender. Created before `connect` so the
        // sender is in place for the very first poll, and so the receiver outlives `bring_up`.
        let (auth_url_tx, auth_url_rx) = watch::channel::<Option<url::Url>>(None);

        let bring_up = async {
            let (client, stream) = AsyncControlClient::connect(
                &params.config,
                &params.env.keys,
                params.auth_key.as_deref(),
                auth_url_tx,
            )
            .await?;

            DerpLatencyMeasurer::spawn_link(&slf, params.env.clone()).await;

            params.env.subscribe::<DerpLatencyMeasurement>(&slf).await?;
            params.env.subscribe::<EndpointAdvertisement>(&slf).await?;
            slf.attach_stream(stream.boxed(), (), ());
            Ok::<_, ControlRunnerError>(client)
        };

        let client = match bring_up.await {
            Ok(client) => client,
            Err(e) => {
                tracing::error!(error = %e, "bringing up the control session failed");
                // The control session never came up; surface it as a transient registration
                // failure (a retry / fresh `Device::new` may succeed) rather than leaving the state
                // stuck at `Connecting`.
                params.state_tx.send_replace(crate::DeviceState::Failed(
                    crate::RegistrationError::NetworkUnreachable,
                ));
                return Err(e);
            }
        };

        // The netmap stream is attached: the node is up. The stream `Next` handler keeps this
        // current (and flips to `Expired` if the self-node's key lapses).
        params.state_tx.send_replace(crate::DeviceState::Running);

        // Bridge the control client's mid-session re-auth URL cell onto the device-state cell: a
        // `Some(url)` (control returned `MachineNotAuthorized` on a live re-register) becomes
        // `DeviceState::NeedsLogin(url)` so the IPN bus surfaces `browse_to_url` and the embedder can
        // prompt the user — the live-session analogue of the initial `check_auth` loop above. The
        // recovery to `Running` is the netmap self-node handler's job (next good self-node), so this
        // bridge only forwards `Some`. The task ends when the sender drops (the client's `run` task
        // ended) and is aborted on actor `Drop`, so it cannot leak past the actor.
        let reauth_bridge = {
            let state_tx = params.state_tx.clone();
            let mut auth_url_rx = auth_url_rx;
            tokio::spawn(async move {
                while auth_url_rx.changed().await.is_ok() {
                    let url = auth_url_rx.borrow_and_update().clone();
                    bridge_reauth_url_to_state(&state_tx, url.as_ref());
                }
            })
        };

        // Clone the TKA authority publisher before `params` moves into `Self` below. The matching
        // `Receiver` lives on the peer tracker; this sender is the sole writer (enforce on sync,
        // clear on disable).
        let tka_authority = params.tka_authority.clone();

        Ok(Self {
            client,
            params,
            self_node: Default::default(),
            ssh_policy: Default::default(),
            tka: Default::default(),
            tka_synced: None,
            tka_authority,
            tka_syncing: false,
            tka_generation: 0,
            cert_domains: Default::default(),
            dns_config: Default::default(),
            pop_browser_url: Default::default(),
            netcheck: Default::default(),
            home_region: None,
            reauth_bridge,
        })
    }
}

impl ControlRunner {
    /// Decide whether the latest netmap's Tailnet-Lock status warrants a (re)sync and, if so, spawn
    /// the bootstrap+sync RPC off the actor thread (so the netmap stream never blocks on a control
    /// round-trip). The result returns via the [`TkaSynced`] self-message.
    ///
    /// Triggers when control reports TKA enabled (`is_enabled`) AND we are not already syncing AND
    /// either we hold no `Authority` yet (→ bootstrap) or control's head differs from ours (→ catch
    /// up). When TKA is disabled, clears any synced state (the lock was turned off). Mirrors Go's
    /// `tkaSyncIfNeeded`: a no-op when our head already matches.
    fn maybe_sync_tka(&mut self, tka: &TkaStatus, self_ref: ActorRef<Self>) {
        if !tka.is_enabled() {
            // Lock disabled (or never enabled): clear enforcement by writing `None` to the authority
            // cell the peer tracker reads — synchronously, so it can never be reordered behind or
            // dropped before a stale `Some` (the failure a best-effort broadcast had). Always bump the
            // generation so ANY sync currently in flight is invalidated: without this, a disable that
            // races an in-flight sync (whose `take()` already cleared `tka_synced`) would be a no-op
            // here, and the sync's late `Ok(Some)` would silently re-enable a lock control just turned
            // off (the in-flight window the `tka_synced.is_some()` guard alone misses). Cheap and
            // idempotent: clearing an already-`None` cell and bumping the generation are harmless.
            self.tka_generation = self.tka_generation.wrapping_add(1);
            if self.tka_synced.is_some() {
                tracing::info!("TKA lock disabled; clearing enforcement (admitting all peers)");
                self.tka_synced = None;
            }
            self.tka_authority.send_replace(None);
            return;
        }
        if self.tka_syncing {
            return; // a sync is already in flight; the next netmap will re-trigger if still stale
        }
        // Up-to-date check: if we already have an Authority whose head matches control's, nothing to
        // do. A malformed control head is treated as "different" (we'll attempt a sync, which
        // fail-closes harmlessly).
        if let Some(synced) = &self.tka_synced
            && let Some(control_head) = ts_tka::AumHash::from_base32(&tka.head)
            && synced.authority.head_matches(&control_head)
        {
            return;
        }

        // Spawn the sync. Move the current synced state out (the driver takes it by value and returns
        // the advanced state); `tka_synced` stays `None` until the result lands, guarded by
        // `tka_syncing` so we don't spawn a second concurrent sync. Capture the current generation so
        // `apply_tka_synced` can discard this result if a disable bumped the generation while the sync
        // was in flight (H1: don't re-enable a lock that was disabled mid-sync).
        self.tka_syncing = true;
        let generation = self.tka_generation;
        let current = self.tka_synced.take();
        let config = self.params.config.clone();
        let keys = self.params.env.keys.clone();
        tokio::spawn(async move {
            let result = crate::tka_sync::sync_tka(&config, &keys, current).await;
            // Hand the outcome back to the actor thread to apply (mutating actor state off-thread is
            // not allowed). A send failure just means the actor is gone — nothing to do.
            if let Err(e) = self_ref.tell(TkaSynced { result, generation }).await {
                tracing::debug!(error = ?e, "TKA sync result not delivered (actor gone)");
            }
        });
    }

    /// Apply the outcome of a spawned [`maybe_sync_tka`] task on the actor thread: store the advanced
    /// state + publish the `Authority` to the peer tracker's enforcement cell (or, on inert/failed
    /// sync, leave peers unaffected). Always clears the in-flight guard.
    ///
    /// `generation` is the value captured when the sync was spawned. If it no longer matches
    /// `self.tka_generation`, the lock was disabled (or re-synced) while this sync was in flight, so
    /// the result is discarded — never re-enabling an authority control has since turned off.
    async fn apply_tka_synced(
        &mut self,
        result: Result<Option<crate::tka_sync::SyncedTka>, crate::tka_sync::TkaSyncDriverError>,
        generation: u64,
    ) {
        self.tka_syncing = false;

        // H1 guard: a disable (or a superseding sync) bumped the generation while this sync ran. Drop
        // the stale result — `maybe_sync_tka`'s disable branch already cleared enforcement to `None`,
        // and re-applying this `Some` would re-enforce a lock that is no longer active.
        if generation != self.tka_generation {
            tracing::info!(
                "TKA sync result superseded (lock disabled or re-synced mid-flight); discarding"
            );
            return;
        }

        match result {
            Ok(Some(synced)) => {
                tracing::info!(
                    head = %synced.authority.head().to_base32(),
                    "TKA sync succeeded; enforcing verified Authority (Go tkaFilterNetmapLocked)"
                );
                // Deliver the verified Authority to the peer tracker's enforcement cell. The tracker
                // reads it on every peer upsert and drops unauthorized peers. `Some(..)` = enforce; a
                // `None` is written on disable. `watch` is the sole channel (last-write-wins, never
                // dropped, ordered by this actor) — no bus, no re-publish-for-replay needed.
                self.tka_authority
                    .send_replace(Some(synced.authority.clone()));

                // Observability (Go `tkaFilterNetmapLocked`'s self check → `LockedOut` health
                // warning): verify SELF's own node-key signature against the freshly-synced
                // Authority and warn if self is NOT authorized. We never FILTER self (self never
                // enters the peer db, so enforcement can't lock us out of our own netmap), but Go
                // raises an operator-facing warning here because a self that the lock does not
                // authorize means this node's key-signature is missing/invalid for the current lock
                // — it will be unable to prove itself to locked peers. This fork has no health
                // subsystem, so the signal is a `tracing::warn!` (its observability channel).
                if let Some(self_node) = self.self_node.borrow().as_ref() {
                    log_self_lockout(self_node, &synced.authority);
                }

                self.tka_synced = Some(synced);
            }
            Ok(None) => {
                // Control has no lock for us (no genesis / disabled). Clear any authority we were
                // previously enforcing — symmetric with the disable path — so a transition to
                // "no lock" stops dropping peers. Not an error.
                if self.tka_synced.is_some() {
                    tracing::info!("TKA sync: control reports no lock; clearing enforcement");
                    self.tka_synced = None;
                }
                self.tka_authority.send_replace(None);
            }
            Err(e) => {
                // Transport or verify failure: log and leave the prior authority in place (a failed
                // sync must not drop enforcement — that would fail OPEN). NEVER errors the netmap.
                // The next netmap update re-triggers a sync attempt.
                tracing::warn!(error = %e, "TKA sync failed; keeping prior enforcement state");
            }
        }
    }

    fn with_self_node<F, R>(&self, f: F) -> impl Future<Output = Option<R>> + use<F, R>
    where
        F: FnOnce(&Node) -> R,
    {
        let mut sub = self.self_node.subscribe();
        let mut shutdown = self.params.env.shutdown.clone();

        async move {
            tokio::select! {
                _ = shutdown.wait_for(|x| *x) => {
                    None
                },
                node = sub.wait_for(Option::is_some) => {
                    Some(f(node.ok()?.as_ref()?))
                },
            }
        }
    }
}

/// Apply Go's sticky `PopBrowserURL` semantics to the consent-URL `watch` cell.
///
/// Control sends `MapResponse.PopBrowserURL` empty on nearly every netmap update, so the cell is
/// updated ONLY when `incoming` is a non-empty URL that differs from the cell's current value —
/// Go's `direct.go` guard `u != "" && u != sess.lastPopBrowserURL`. The cell is **never reset to
/// `None`** by an empty/absent update — the running-node consent URL is sticky for the session.
/// Updating unconditionally would thrash the cell to `None` on every tick and coalesce the URL away
/// for a `watch`/bus subscriber.
///
/// The dedupe is in-place via [`watch::Sender::send_if_modified`] — the cell's own value is the
/// "last URL sent" (this sticky path is its only writer), so no separate mirror field is needed and
/// the watch is woken only on a genuine change (Go's `sess.lastPopBrowserURL` role, for free). This
/// matches the [`send_if_modified`](watch::Sender::send_if_modified) idiom already used for the
/// device-state cell in this handler.
///
/// Factored out of the netmap-update handler so the (easy-to-regress) sticky logic is unit-testable
/// against a plain `watch` channel without standing up the actor.
fn sticky_update_pop_browser_url(
    cell: &watch::Sender<Option<url::Url>>,
    incoming: Option<&url::Url>,
) {
    if let Some(url) = incoming {
        cell.send_if_modified(|current| {
            if current.as_ref() == Some(url) {
                false
            } else {
                *current = Some(url.clone());
                true
            }
        });
    }
}

/// Map a mid-session re-auth URL surfaced by the control client onto the device-state cell.
///
/// The control client's live map-poll loop publishes an `Option<url::Url>` into a `watch` cell when
/// a re-register hits `MachineNotAuthorized` (the node key expired/was revoked mid-session — see
/// [`ts_control::AsyncControlClient::connect`]'s `auth_url_tx`). `ts_control` cannot name
/// [`DeviceState`] (it must not depend on this crate), so this bridge fn does the translation:
/// a `Some(url)` sets [`DeviceState::NeedsLogin`]`(url)` so the IPN bus derives `browse_to_url` and
/// the embedder can prompt the user, exactly like the initial-registration `check_auth` path.
///
/// **Only `Some` drives a transition; `None` is ignored here.** The clear back to
/// [`DeviceState::Running`] is owned by the netmap self-node handler (the next good self-node flips
/// it — see the `StreamMessage::Next` arm), which is the authoritative "we are up again" signal; an
/// independent `None`-clear in this bridge could race that and is unnecessary. The
/// [`send_if_modified`](watch::Sender::send_if_modified) guard fires the watch only on a genuine
/// state change (it is a no-op when the cell already holds `NeedsLogin(url)` for the same URL), so a
/// re-auth URL re-surfaced across retries does not thrash the cell — mirroring the device-state
/// dedupe in the netmap handler.
///
/// Factored out so the (regress-prone) map-and-guard is unit-testable against a plain `watch`
/// channel without standing up the actor (mirrors [`sticky_update_pop_browser_url`]).
pub(crate) fn bridge_reauth_url_to_state(
    state_tx: &watch::Sender<crate::DeviceState>,
    incoming: Option<&url::Url>,
) {
    if let Some(url) = incoming {
        let next = crate::DeviceState::NeedsLogin(url.clone());
        state_tx.send_if_modified(|current| {
            if *current == next {
                false
            } else {
                *current = next.clone();
                true
            }
        });
    }
}

/// The classification of SELF against the active network lock — the observability analog of Go
/// `tkaFilterNetmapLocked`'s self check (which raises a `LockedOut` health warning).
#[derive(Debug, Clone, PartialEq, Eq)]
enum SelfLockVerdict {
    /// Self carries no key-signature at all (empty). The common "not signed yet" case: the node
    /// simply has not been signed for this lock — not locked out, just unsigned.
    Unsigned,
    /// Self's key-signature is authorized by the active lock; nothing to warn about.
    Authorized,
    /// Self has a key-signature but the lock does NOT authorize it (the message is the verify
    /// error). The operator-facing `LockedOut` condition: locked peers will reject this node.
    LockedOut(String),
}

/// Classify a node key + its key-signature against `authority` (pure: verify-and-classify, no
/// logging, no I/O). Takes only the two fields it needs — not the whole `Node` — so the decision is
/// unit-testable without constructing a full `Node` or standing up the actor.
fn self_lock_verdict(
    node_key: &ts_keys::NodePublicKey,
    key_signature: &[u8],
    authority: &ts_tka::Authority,
) -> SelfLockVerdict {
    if key_signature.is_empty() {
        return SelfLockVerdict::Unsigned;
    }
    match authority.node_key_authorized(&node_key.to_bytes(), key_signature) {
        Ok(()) => SelfLockVerdict::Authorized,
        Err(e) => SelfLockVerdict::LockedOut(e.to_string()),
    }
}

/// Emit the self-locked-out observability signal (Go `tkaFilterNetmapLocked`'s self check → a
/// `LockedOut` health warning): classify SELF against the freshly-synced `authority` and log.
///
/// This is **observability, not enforcement** — self never enters the peer db, so the lock can never
/// filter our own node out of the netmap. But a self the lock does not authorize means this node's
/// key-signature is absent or invalid for the active lock, so it cannot prove itself to locked peers
/// (they will drop it); surfacing that lets an operator notice and re-sign. A never-signed node
/// (empty signature) logs at `info`, distinct from a present-but-invalid signature (`warn`), so the
/// common unsigned case does not spam a warning. This fork has no health subsystem, so the operator
/// signal is a `tracing` event (its observability channel).
fn log_self_lockout(self_node: &Node, authority: &ts_tka::Authority) {
    match self_lock_verdict(&self_node.node_key, &self_node.key_signature, authority) {
        SelfLockVerdict::Unsigned => tracing::info!(
            "TKA: this node has no key-signature for the active lock; it cannot prove itself to \
             locked peers until control signs it (not locked out, just unsigned)"
        ),
        SelfLockVerdict::Authorized => {
            tracing::debug!("TKA: self node-key is authorized by the active lock")
        }
        SelfLockVerdict::LockedOut(error) => tracing::warn!(
            %error,
            "TKA self locked out: this node's key-signature is not authorized by the active \
             network lock; locked peers will reject it until control re-signs this node \
             (Go LockedOut)"
        ),
    }
}

// The `#[kameo::messages]` macro generates message structs whose fields mirror the method params;
// those generated fields carry no doc and can't take attributes, so wrap in a module where
// missing-docs is allowed (same pattern as PeerTracker's `msg_impl`). The generated message structs
// are re-exported so callers keep referencing them at `control_runner::<Name>`.
pub use msg_impl::*;

#[allow(missing_docs)]
mod msg_impl {
    use kameo::{message::Context, reply::DelegatedReply};

    use super::*;

    #[kameo::messages]
    impl ControlRunner {
        /// Fetch the IPv4 address for this tailscale device.
        #[message(ctx)]
        pub fn ipv4(
            &self,
            ctx: &mut Context<Self, DelegatedReply<Option<Ipv4Addr>>>,
        ) -> DelegatedReply<Option<Ipv4Addr>> {
            let (deleg, replier) = ctx.reply_sender();

            if let Some(replier) = replier {
                let fut = self.with_self_node(|node| node.tailnet_address.ipv4.addr());

                tokio::spawn(async move {
                    let ip = fut.await;
                    replier.send(ip);
                });
            }

            deleg
        }

        /// Fetch the IPv6 address for this tailscale device.
        #[message(ctx)]
        pub fn ipv6(
            &self,
            ctx: &mut Context<Self, DelegatedReply<Option<Ipv6Addr>>>,
        ) -> DelegatedReply<Option<Ipv6Addr>> {
            let (deleg, replier) = ctx.reply_sender();

            if let Some(replier) = replier {
                let fut = self.with_self_node(|node| node.tailnet_address.ipv6.addr());

                tokio::spawn(async move {
                    let ip = fut.await;
                    replier.send(ip);
                });
            }

            deleg
        }

        /// Fetch the self node for this tailscale device.
        #[message(ctx)]
        pub fn self_node(
            &self,
            ctx: &mut Context<Self, DelegatedReply<Option<Node>>>,
        ) -> DelegatedReply<Option<Node>> {
            let (deleg, replier) = ctx.reply_sender();

            if let Some(replier) = replier {
                let node = self.with_self_node(|node| node.clone());

                tokio::spawn(async move {
                    let node = node.await;
                    replier.send(node)
                });
            }

            deleg
        }

        /// Fetch the current Tailscale SSH policy, if control has pushed one.
        ///
        /// Returns `None` when control has not sent an SSH policy (the SSH server treats this as
        /// deny-all — fail-closed). Unlike `self_node` this does not block waiting
        /// for a value: an absent policy is a legitimate, immediate answer.
        #[message]
        pub fn current_ssh_policy(&self) -> Option<SshPolicy> {
            self.ssh_policy.borrow().clone()
        }

        /// Fetch the current Tailnet Lock status, if control has pushed one.
        ///
        /// Returns `None` when control has sent no `TKAInfo` (tailnet lock not in use / no change seen).
        #[message]
        pub fn current_tka_status(&self) -> Option<TkaStatus> {
            self.tka.borrow().clone()
        }

        /// Sign `node_key` directly with this node's network-lock key and submit the signature to
        /// control (Go `tka.sign` for the Direct case → `tkaSubmitSignature`).
        ///
        /// Builds a `Direct` [`NodeKeySignature`](ts_tka::NodeKeySignature) via
        /// [`sign_direct`](ts_tka::NodeKeySignature::sign_direct) over this node's inner ed25519
        /// network-lock signing key, serializes it (raw CBOR), and POSTs it to `/machine/tka/sign`.
        /// Mirrors `set_dns`/`get_certificate`: clones the control config + node keys into a spawned
        /// task (delegated reply, so the round-trip doesn't block the mailbox) over a fresh Noise
        /// channel.
        ///
        /// **Posture: this only *submits* a signature to control — it does NOT mutate the local
        /// [`Authority`](ts_tka::Authority).** The local trusted-key state advances solely through the
        /// existing verified-sync path (`sync_tka` → `VerifiedAumChain::verify`); a `tka_sign` success
        /// is acknowledged to the caller, and the resulting AUM is picked up on the next netmap-driven
        /// sync. Verify-and-log is unchanged.
        #[message(ctx)]
        pub fn tka_sign(
            &self,
            ctx: &mut Context<Self, DelegatedReply<Result<(), TkaSyncError>>>,
            node_key: [u8; 32],
        ) -> DelegatedReply<Result<(), TkaSyncError>> {
            let (deleg, replier) = ctx.reply_sender();

            if let Some(replier) = replier {
                let config = self.params.config.clone();
                let keys = self.params.env.keys.clone();
                tokio::spawn(async move {
                    // Sign the node key with our network-lock key, then submit the raw-CBOR NKS.
                    let nks = ts_tka::NodeKeySignature::sign_direct(
                        &node_key,
                        &keys.network_lock_keys.private.signing_key(),
                    );
                    let req = ts_control::TkaSubmitSignatureRequest {
                        // node_key + version are stamped by the RPC client from `keys`.
                        version: Default::default(),
                        node_key: keys.node_keys.public,
                        signature: nks.serialize(),
                    };
                    let result = tka_submit_signature(
                        &config.server_url,
                        &keys,
                        req,
                        config.allow_http_key_fetch,
                    )
                    .await
                    .map(|_response| ());
                    replier.send(result);
                });
            }

            deleg
        }

        /// Disable Tailnet Lock by presenting the disablement secret to control (Go
        /// `tka.disable` → `/machine/tka/disable`).
        ///
        /// Targets the **current** authority head (read from the cached [`TkaStatus`]); the caller
        /// supplies the `disablement_secret` out of band (it is the operator-held capability that
        /// authorizes turning the lock off). Mirrors `tka_sign`: clones config + keys into a spawned
        /// task (delegated reply). Returns [`TkaSyncError::Unsupported`] when there is no known TKA
        /// head (lock not in use / control hasn't pushed a status), since there is nothing to disable.
        ///
        /// **Submit-only, like `tka_sign`:** this POSTs the disablement to control and does NOT mutate
        /// the local [`Authority`](ts_tka::Authority). Control acts on the disablement; this node
        /// observes the result through the existing verified-sync path. Verify-and-log unchanged.
        #[message(ctx)]
        pub fn tka_disable(
            &self,
            ctx: &mut Context<Self, DelegatedReply<Result<(), TkaSyncError>>>,
            disablement_secret: Vec<u8>,
        ) -> DelegatedReply<Result<(), TkaSyncError>> {
            let (deleg, replier) = ctx.reply_sender();

            if let Some(replier) = replier {
                // Read the current head from the cached status BEFORE the spawn (can't borrow &self
                // across the await). No head ⇒ no lock to disable ⇒ Unsupported.
                let head = self.tka.borrow().as_ref().map(|s| s.head.clone());
                let config = self.params.config.clone();
                let keys = self.params.env.keys.clone();
                tokio::spawn(async move {
                    let result = match head {
                        Some(head) => {
                            let req = ts_control::TkaDisableRequest {
                                // node_key + version are stamped by the RPC client from `keys`.
                                version: Default::default(),
                                node_key: keys.node_keys.public,
                                head,
                                disablement_secret,
                            };
                            tka_disable(&config.server_url, &keys, req, config.allow_http_key_fetch)
                                .await
                                .map(|_response| ())
                        }
                        None => Err(TkaSyncError::Unsupported),
                    };
                    replier.send(result);
                });
            }

            deleg
        }

        /// Initialize Tailnet Lock with this node as the sole initial trusted key, gated by
        /// `disablement_secret` (Go `LocalClient.NetworkLockInit` — the "lock yourself in" case).
        ///
        /// Builds + signs a genesis Checkpoint AUM whose only trusted key is this node's network-lock
        /// public key (votes 1) and whose single DisablementValue is `disablement_value(secret)`, then
        /// drives the two-phase init: `tka/init/begin` (submit the genesis) → if control needs no
        /// further node signatures (`NeedSignatures` empty, the case when this node is the only key) →
        /// `tka/init/finish` carrying the raw `disablement_secret` as `SupportDisablement`. Mirrors
        /// `tka_sign`/`tka_disable`: cloned config + keys into a spawned task (delegated reply).
        ///
        /// If control returns a non-empty `NeedSignatures` (other nodes must be re-signed under the new
        /// lock — a multi-node tailnet), this returns [`TkaSyncError::Unsupported`]: re-signing each
        /// listed node (incl. the Rotation-key case) is a larger flow deferred to a fuller
        /// `tka_init(keys, secrets)` — the single-node lock-init is the shipped subset.
        ///
        /// **Submit-only**, like `tka_sign`/`tka_disable`: this creates the lock at control and does
        /// NOT seed the local [`Authority`](ts_tka::Authority) — the node picks up the new lock through
        /// the existing verified netmap-sync (control pushes a `TKAInfo`, `maybe_sync_tka` bootstraps
        /// the genesis through `VerifiedAumChain::verify`). Verify-and-log posture unchanged.
        #[message(ctx)]
        pub fn tka_init(
            &self,
            ctx: &mut Context<Self, DelegatedReply<Result<(), TkaSyncError>>>,
            disablement_secret: Vec<u8>,
        ) -> DelegatedReply<Result<(), TkaSyncError>> {
            let (deleg, replier) = ctx.reply_sender();

            if let Some(replier) = replier {
                let config = self.params.config.clone();
                let keys = self.params.env.keys.clone();
                tokio::spawn(async move {
                    let result = tka_init_run(&config, &keys, disablement_secret).await;
                    replier.send(result);
                });
            }

            deleg
        }

        /// The cert-eligible DNS names from control's netmap DNS config (Go `nm.DNS.CertDomains`).
        ///
        /// Returns an empty `Vec` when control has sent no DNS config, or one carrying no cert
        /// domains (an empty list is a legitimate, immediate answer — like `current_ssh_policy`, this
        /// does not block waiting for a value).
        #[message]
        pub fn cert_domains(&self) -> Vec<String> {
            self.cert_domains.borrow().clone()
        }

        /// The full DNS config from control's netmap (Go `netmap.NetworkMap.DNS`), or `None` when
        /// control has sent no DNS config yet. An immediate answer (does not block); the facade
        /// surfaces this for `Device::dns_config` (the daemon's `tnet dns status`).
        #[message]
        pub fn dns_config(&self) -> Option<ts_control::DnsConfig> {
            self.dns_config.borrow().clone()
        }

        /// The interactive-login / consent URL control last asked this node to open
        /// (`MapResponse.PopBrowserURL`), or `None` when control has sent none. An immediate answer
        /// (does not block); the facade surfaces this for `Device::pop_browser_url`.
        #[message]
        pub fn pop_browser_url(&self) -> Option<url::Url> {
            self.pop_browser_url.borrow().clone()
        }

        /// Subscribe to the interactive-login / consent URL cell (`MapResponse.PopBrowserURL`).
        ///
        /// Returns a [`watch::Receiver`] whose value is the latest running-node consent URL, used by
        /// [`Runtime::watch_ipn_bus`](crate::Runtime::watch_ipn_bus) to surface `browse_to_url`
        /// events mid-session. The cell is sticky (updated only on a new non-empty URL, never reset
        /// to `None` by an empty update — see the field docs), so a subscriber is not thrashed and a
        /// late subscriber sees the current URL. The initial value is `None` until control sends one.
        #[message(derive(Clone))]
        pub fn watch_browser_url(&self) -> watch::Receiver<Option<url::Url>> {
            self.pop_browser_url.subscribe()
        }

        /// The latest network-conditions report (preferred DERP region + per-region latencies). An
        /// immediate answer (does not block); empty before the first DERP-latency measurement. The
        /// facade surfaces this for `Device::netcheck` (the daemon's `tnet netcheck`).
        #[message]
        pub fn netcheck(&self) -> crate::status::NetcheckReport {
            self.netcheck.borrow().clone()
        }

        /// Request an OIDC ID token from control scoped to `audience` (workload-identity federation).
        ///
        /// Opens a fresh Noise channel and POSTs `/machine/id-token`; returns the signed JWT or an
        /// [`IdTokenError`]. Runs on a spawned task (delegated reply) so the actor mailbox isn't blocked
        /// for the round-trip.
        #[message(ctx)]
        pub fn fetch_id_token(
            &self,
            ctx: &mut Context<Self, DelegatedReply<Result<String, IdTokenError>>>,
            audience: String,
        ) -> DelegatedReply<Result<String, IdTokenError>> {
            let (deleg, replier) = ctx.reply_sender();

            if let Some(replier) = replier {
                let config = self.params.config.clone();
                let keys = self.params.env.keys.clone();
                tokio::spawn(async move {
                    let result = ts_control::fetch_id_token(&config, &keys, &audience).await;
                    replier.send(result);
                });
            }

            deleg
        }

        /// Log this node out of the tailnet: deregister it by expiring its current node key.
        ///
        /// Mirrors `fetch_id_token`: clones the control config + node keys
        /// into a spawned task (delegated reply, so the round-trip doesn't block the mailbox) and
        /// re-POSTs `/machine/register` with a past expiry over a fresh Noise channel. This is a
        /// control-plane state change only — it does NOT stop this actor or tear down the datapath
        /// (the caller follows up with the normal runtime shutdown), and it does not touch the
        /// on-disk node key, so re-registering with the same key is the re-login path.
        #[message(ctx)]
        pub fn logout(
            &self,
            ctx: &mut Context<Self, DelegatedReply<Result<(), LogoutError>>>,
        ) -> DelegatedReply<Result<(), LogoutError>> {
            let (deleg, replier) = ctx.reply_sender();

            if let Some(replier) = replier {
                let config = self.params.config.clone();
                let keys = self.params.env.keys.clone();
                tokio::spawn(async move {
                    let result = ts_control::logout(&config, &keys).await;
                    replier.send(result);
                });
            }

            deleg
        }

        /// Publish a DNS record for this node via control's `/machine/set-dns` (Go
        /// `LocalClient.SetDNS`).
        ///
        /// Mirrors `fetch_id_token`: clones the control config + node keys
        /// into a spawned task (delegated reply, so the round-trip doesn't block the mailbox) and
        /// POSTs the record over a fresh Noise channel. Go's `SetDNS` is `TXT`-only (its sole use is
        /// the ACME DNS-01 `_acme-challenge` record); the record type is fixed to `"TXT"` here to
        /// match, so the surfaced API takes only `name` + `value`.
        #[message(ctx)]
        pub fn set_dns(
            &self,
            ctx: &mut Context<Self, DelegatedReply<Result<(), SetDnsError>>>,
            name: String,
            value: String,
        ) -> DelegatedReply<Result<(), SetDnsError>> {
            let (deleg, replier) = ctx.reply_sender();

            if let Some(replier) = replier {
                let config = self.params.config.clone();
                let keys = self.params.env.keys.clone();
                tokio::spawn(async move {
                    let result = ts_control::set_dns(&config, &keys, &name, "TXT", &value).await;
                    replier.send(result);
                });
            }

            deleg
        }
    }

    /// The reply type of the [`get_cert_pair`](ControlRunner::get_cert_pair) message: the issued
    /// `(cert_chain_pem, key_pem)` PEM pair (the `tnet cert` surface) or a [`ts_control::CertError`].
    /// Aliased so the message's `Context` type stays under clippy's `type_complexity` bar (the
    /// nested `Result<(String, String), _>` trips it inline).
    #[cfg(feature = "acme")]
    pub type CertPairReply = Result<(String, String), ts_control::CertError>;

    // The `acme`-gated cert-issuance message lives in its own `#[kameo::messages]` impl block so the
    // proc-macro never sees it in a non-`acme` build (a `#[cfg]` *inside* a single messages-impl
    // block is not honored by the macro's generated dispatch — it would emit a `GetCertificate`
    // handler calling a `get_certificate` method that the same `#[cfg]` strips). A separate gated
    // block keeps the default build clean.
    #[cfg(feature = "acme")]
    #[kameo::messages]
    impl ControlRunner {
        /// Issue a real Let's Encrypt certificate for this node's MagicDNS `name` via the
        /// client-side ACME DNS-01 engine (`acme` feature).
        ///
        /// Mirrors `fetch_id_token`: clones the control config + node keys
        /// into a spawned task (delegated reply, so the round-trip doesn't block the mailbox), loads
        /// or generates the ACME account key, and runs issuance against Let's Encrypt production,
        /// publishing the DNS-01 challenge TXT through the node's `POST /machine/set-dns` RPC.
        ///
        /// The account key is loaded from [`ts_keys::NodeState::acme_account_key`] (PKCS#8 DER) when
        /// present, so the same ACME account persists across renewals; otherwise an ephemeral key is
        /// generated for this call only (a fresh ACME account each issuance — acceptable for v1; LE
        /// allows it). Persisting a generated key back into the key file is the embedder's job (no
        /// write-back path here). SaaS-only: against a self-hosted control plane the set-dns
        /// publish 501s.
        #[message(ctx)]
        pub fn get_certificate(
            &self,
            ctx: &mut Context<
                Self,
                DelegatedReply<Result<ts_control::tls::CertifiedKey, ts_control::CertError>>,
            >,
            name: String,
        ) -> DelegatedReply<Result<ts_control::tls::CertifiedKey, ts_control::CertError>> {
            let (deleg, replier) = ctx.reply_sender();

            if let Some(replier) = replier {
                let config = self.params.config.clone();
                let keys = self.params.env.keys.clone();
                tokio::spawn(async move {
                    let result = issue_certificate(&config, &keys, &name).await;
                    replier.send(result);
                });
            }

            deleg
        }

        /// Issue a real Let's Encrypt certificate for this node's MagicDNS `name` and return the
        /// **PEM pair** — `(cert_chain_pem, key_pem)` — for writing the on-disk `.crt` + `.key`
        /// (the daemon's `tnet cert`, Go's `LocalClient.CertPair`). `acme` feature.
        ///
        /// Identical issuance to [`get_certificate`](Self::get_certificate) (same client-side ACME
        /// DNS-01 flow, same set-dns publish, same account-key handling), only the *shape* of the
        /// result differs: this surfaces the raw chain + leaf-key PEMs instead of the opaque
        /// [`CertifiedKey`](ts_control::tls::CertifiedKey). The leaf **private key** PEM is the
        /// second tuple element and is NEVER logged — the spawned task sends it straight back to the
        /// replier. SaaS-only: against a self-hosted control plane the set-dns publish 501s.
        #[message(ctx)]
        pub fn get_cert_pair(
            &self,
            ctx: &mut Context<Self, DelegatedReply<CertPairReply>>,
            name: String,
        ) -> DelegatedReply<CertPairReply> {
            let (deleg, replier) = ctx.reply_sender();

            if let Some(replier) = replier {
                let config = self.params.config.clone();
                let keys = self.params.env.keys.clone();
                tokio::spawn(async move {
                    let result = issue_cert_pair(&config, &keys, &name).await;
                    replier.send(result);
                });
            }

            deleg
        }
    }
}

/// The `tka_init` body (the genesis-build + two-phase init/begin→init/finish choreography),
/// factored out of the actor handler so it runs in the spawned task. See [`ControlRunner::tka_init`].
///
/// "Lock yourself in": the genesis trusts only this node's network-lock key (votes 1) and stores one
/// DisablementValue = `disablement_value(secret)`. On a non-empty `NeedSignatures` (multi-node
/// tailnet needing re-signs) it returns [`TkaSyncError::Unsupported`] — the single-node subset.
async fn tka_init_run(
    config: &ts_control::Config,
    keys: &ts_keys::NodeState,
    disablement_secret: Vec<u8>,
) -> Result<(), TkaSyncError> {
    // Build the genesis: this node's NL public key as the sole trusted key, one disablement value.
    let nl_public = keys.network_lock_keys.public.to_bytes().to_vec();
    let genesis_key = ts_tka::AumKey {
        kind: ts_tka::KeyKind::Ed25519,
        votes: 1,
        public: nl_public,
        meta: Vec::new(),
    };
    let dvalue = ts_tka::disablement_value(&disablement_secret).to_vec();
    let mut genesis = ts_tka::Aum::new_genesis_checkpoint(vec![genesis_key], vec![dvalue])
        // A malformed genesis is a local construction bug, not a transient RPC failure — surface it as a
        // coarse internal error rather than NetworkError (which would invite a pointless retry).
        .map_err(|_| TkaSyncError::Internal(ts_control::TkaSyncInternalErrorKind::SerDe))?;
    genesis.sign(&keys.network_lock_keys.private.signing_key());

    // Phase 1: submit the genesis. node_key + version are stamped by the RPC client from `keys`.
    let begin_req = ts_control::TkaInitBeginRequest {
        version: Default::default(),
        node_key: keys.node_keys.public,
        genesis_aum: genesis.serialize(),
    };
    let begin_resp = tka_init_begin(
        &config.server_url,
        keys,
        begin_req,
        config.allow_http_key_fetch,
    )
    .await?;

    // Single-node case only: control must need no further node signatures. A non-empty
    // NeedSignatures means other nodes must be re-signed under the new lock — deferred.
    if !begin_resp.need_signatures.is_empty() {
        tracing::warn!(
            need = begin_resp.need_signatures.len(),
            "tka_init: control requires re-signing other nodes; the multi-node init is not yet \
             implemented (single-node lock-init only)"
        );
        return Err(TkaSyncError::Unsupported);
    }

    // Phase 2: finish, carrying the raw disablement secret as SupportDisablement (Go sends the raw
    // secret here; only the genesis stores its Argon2i hash).
    let finish_req = ts_control::TkaInitFinishRequest {
        version: Default::default(),
        node_key: keys.node_keys.public,
        signatures: std::collections::BTreeMap::new(),
        support_disablement: disablement_secret,
    };
    tka_init_finish(
        &config.server_url,
        keys,
        finish_req,
        config.allow_http_key_fetch,
    )
    .await
    .map(|_response| ())
}

/// Load or generate the ACME account key, then issue a cert for `name` via set-dns DNS-01,
/// returning just the ready-to-serve [`CertifiedKey`](ts_control::tls::CertifiedKey) (the
/// `get_certificate` / `ListenTLS` path).
///
/// Thin wrapper over [`issue_cert_pair`] that drops the PEMs — one issuance, this caller just
/// doesn't need the on-disk pair. See [`issue_cert_pair`] for the account-key handling.
#[cfg(feature = "acme")]
async fn issue_certificate(
    config: &ts_control::Config,
    keys: &ts_keys::NodeState,
    name: &str,
) -> Result<ts_control::tls::CertifiedKey, ts_control::CertError> {
    issue_cert_pair_inner(config, keys, name)
        .await
        .map(|issued| issued.certified)
}

/// Load or generate the ACME account key, then issue a cert for `name` via set-dns DNS-01,
/// returning the **PEM pair** `(cert_chain_pem, key_pem)` for the daemon's on-disk `.crt`/`.key`
/// (`tnet cert`, Go `LocalClient.CertPair`).
///
/// Same single issuance as [`issue_certificate`]; only the result shape differs. The leaf
/// **private key** PEM is the second element and is NEVER logged here.
#[cfg(feature = "acme")]
async fn issue_cert_pair(
    config: &ts_control::Config,
    keys: &ts_keys::NodeState,
    name: &str,
) -> Result<(String, String), ts_control::CertError> {
    issue_cert_pair_inner(config, keys, name)
        .await
        .map(|issued| (issued.cert_chain_pem, issued.key_pem))
}

/// Shared issuance core for [`issue_certificate`] and [`issue_cert_pair`]: load (or generate) the
/// ACME account key, target Let's Encrypt production, and run one DNS-01 issuance, returning the
/// full [`IssuedCert`](ts_control::acme::IssuedCert) so each caller projects out what it needs (one
/// ACME order, two consumers).
///
/// Reuses the persisted [`ts_keys::NodeState::acme_account_key`] (PKCS#8 DER) when present so the
/// same Let's Encrypt account survives renewals; otherwise generates an ephemeral per-call key
/// (logged at debug — a new ACME account each issuance, with no write-back). Always targets Let's
/// Encrypt production ([`ts_control::acme::LETS_ENCRYPT_PRODUCTION_DIRECTORY`]). Never logs the leaf
/// private key.
#[cfg(feature = "acme")]
async fn issue_cert_pair_inner(
    config: &ts_control::Config,
    keys: &ts_keys::NodeState,
    name: &str,
) -> Result<ts_control::acme::IssuedCert, ts_control::CertError> {
    let account_key = match keys.acme_account_key.as_deref() {
        Some(der) => ts_control::acme::AcmeAccountKey::from_pkcs8(der)?,
        None => {
            tracing::debug!(
                "no persisted ACME account key in key state; generating an ephemeral per-call key \
                 (a new ACME account this issuance — not persisted back)"
            );
            ts_control::acme::AcmeAccountKey::generate()?.0
        }
    };
    let directory = ts_control::acme::LETS_ENCRYPT_PRODUCTION_DIRECTORY
        .parse()
        .map_err(|e| {
            ts_control::CertError::Acme(format!("parsing Let's Encrypt directory URL: {e}"))
        })?;
    ts_control::issue_cert_pair_via_setdns(config, keys, name, &account_key, &directory).await
}

impl Message<StreamMessage<Arc<StateUpdate>, (), ()>> for ControlRunner {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: StreamMessage<Arc<StateUpdate>, (), ()>,
        ctx: &mut Context<Self, Self::Reply>,
    ) {
        match msg {
            StreamMessage::Started(_) => {
                tracing::trace!("started listening to state updates");
            }

            StreamMessage::Next(msg) => {
                if let Some(node) = msg.node.as_ref() {
                    // Reflect node-key expiry into the device state: control delivering a self-node
                    // whose key is in the past means the node must re-authenticate. Otherwise the
                    // arrival of a fresh self-node confirms we are Running (recovers the state if a
                    // prior update had flipped it to Expired).
                    let now_unix = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    let next = if node.key_expired_at_unix(now_unix) {
                        crate::DeviceState::Expired
                    } else {
                        crate::DeviceState::Running
                    };
                    // `send_if_modified` avoids waking watchers when the state is unchanged (a fresh
                    // self-node arrives on every netmap update).
                    self.params.state_tx.send_if_modified(|s| {
                        if *s != next {
                            *s = next.clone();
                            true
                        } else {
                            false
                        }
                    });

                    self.self_node.send_replace(Some(node.clone()));
                }

                if let Some(policy) = msg.ssh_policy.as_ref() {
                    self.ssh_policy.send_replace(Some(policy.clone()));
                }

                if let Some(tka) = msg.tka.as_ref() {
                    self.tka.send_replace(Some(tka.clone()));
                    self.maybe_sync_tka(tka, ctx.actor_ref().clone());
                }

                // Track the cert-domain list from the netmap DNS config (Go `nm.DNS.CertDomains`).
                // An update with no DNS config, or one carrying no cert domains, means "none" — Go
                // reads an empty slice off an absent config too, so mirror that as an empty `Vec`.
                let cert_domains = msg
                    .dns_config
                    .as_ref()
                    .map(|d| d.cert_domains.clone())
                    .unwrap_or_default();
                self.cert_domains.send_replace(cert_domains);

                // Track the full DNS config for `Device::dns_config` (the daemon's `tnet dns status`).
                // `None` when control sent no DNS config on this update — distinct from a present but
                // empty config (Go `netmap.NetworkMap.DNS`).
                self.dns_config.send_replace(msg.dns_config.clone());

                // Track the interactive-login URL for `Device::pop_browser_url` /
                // `Runtime::watch_ipn_bus`. See `sticky_update_pop_browser_url` for the Go-faithful
                // sticky semantics (update only on a new non-empty URL; never reset to `None`).
                sticky_update_pop_browser_url(&self.pop_browser_url, msg.pop_browser_url.as_ref());

                if let Err(e) = self.params.env.publish(msg).await {
                    tracing::error!(error = %e, "publishing netmap update");
                }
            }

            StreamMessage::Finished(_) => {
                tracing::error!("state update stream terminated")
            }
        }
    }
}

/// The outcome of a spawned TKA bootstrap+sync task, delivered back to the actor thread so the
/// result can be applied to actor state (which a spawned task cannot touch directly). Sent by
/// [`ControlRunner::maybe_sync_tka`]; handled by applying via
/// [`ControlRunner::apply_tka_synced`](ControlRunner).
#[doc(hidden)]
pub struct TkaSynced {
    pub(crate) result:
        Result<Option<crate::tka_sync::SyncedTka>, crate::tka_sync::TkaSyncDriverError>,
    /// The [`ControlRunner::tka_generation`] captured when this sync was spawned; the handler
    /// discards the result if it no longer matches (the lock was disabled/re-synced mid-flight).
    pub(crate) generation: u64,
}

impl Message<TkaSynced> for ControlRunner {
    type Reply = ();

    async fn handle(&mut self, msg: TkaSynced, _ctx: &mut Context<Self, Self::Reply>) {
        self.apply_tka_synced(msg.result, msg.generation).await;
    }
}

impl Message<DerpLatencyMeasurement> for ControlRunner {
    type Reply = ();

    async fn handle(&mut self, msg: DerpLatencyMeasurement, _ctx: &mut Context<Self, Self::Reply>) {
        let measurements = msg.measurement.as_ref().clone();

        // Publish the net-report snapshot for `Device::netcheck` (the daemon's `tnet netcheck`) from
        // the same measurements, before the home-region short-circuit below — an empty set still
        // yields a (default/empty) report rather than a stale one.
        self.netcheck
            .send_replace(crate::status::NetcheckReport::from_region_results(
                &measurements,
            ));

        if measurements.is_empty() {
            tracing::debug!("derp latency measurements empty");
            return;
        };

        // Apply selection hysteresis (the pure decision lives in `select_home_region` for testability)
        // so jitter between near-equal regions does not flap the home relay. Copy the chosen id +
        // latency out of the borrowed result so nothing borrows `measurements` across the `.await`.
        let (selected_id, selected_latency) = {
            let selected = select_home_region(self.home_region.map(|(id, _)| id), &measurements)
                .expect("non-empty measurements always yield a selection");
            (selected.id, selected.latency)
        };

        let iter = measurements.iter().map(|result| {
            (
                result.latency_map_key.as_str(),
                result.latency.as_secs_f64(),
            )
        });

        if self.home_region.map(|(id, _)| id) != Some(selected_id) {
            tracing::debug!(selected_region_id = ?selected_id, "updating home region");
        }
        self.home_region = Some((selected_id, selected_latency));
        self.client.set_home_region(selected_id, iter).await;
    }
}

/// Choose the DERP home region from `measurements` (expected sorted by latency ascending, so
/// `measurements[0]` is the lowest-latency "best"), applying Go's selection hysteresis
/// (`netcheck.addReportHistoryAndSetPreferredDERP`). Pure so the decision is unit-testable.
///
/// Keeps the `current` home region (when it is still present in `measurements`) unless the new best
/// is *meaningfully* lower-latency — switching only when BOTH: the current region's fresh latency
/// exceeds the best by at least `PREFERRED_DERP_ABSOLUTE_DIFF` (10ms), AND the best is at most
/// two-thirds of the current region's latency (a >~33% improvement). This avoids flapping the home
/// relay between regions whose latencies jitter within ~10ms. On the first selection (`current` is
/// `None`), when the best already IS the current region, or when the current region dropped out of
/// the measurements, returns the best directly. `None` only if `measurements` is empty.
fn select_home_region(
    current: Option<ts_derp::RegionId>,
    measurements: &[ts_netcheck::RegionResult],
) -> Option<&ts_netcheck::RegionResult> {
    /// Go `netcheck.preferredDERPAbsoluteDiff`.
    const PREFERRED_DERP_ABSOLUTE_DIFF: core::time::Duration =
        core::time::Duration::from_millis(10);

    let best = measurements.first()?;

    let Some(old_id) = current.filter(|id| *id != best.id) else {
        // First selection, or the best already is the current home region.
        return Some(best);
    };

    // Compare against the current region's FRESH latency (not a stale one), if it is still present.
    match measurements.iter().find(|m| m.id == old_id) {
        Some(old) => {
            let keep_old = old.latency.saturating_sub(best.latency) < PREFERRED_DERP_ABSOLUTE_DIFF
                || best.latency.as_secs_f64() > old.latency.as_secs_f64() * 2.0 / 3.0;
            Some(if keep_old { old } else { best })
        }
        // The current region is no longer reachable this cycle: take the new best.
        None => Some(best),
    }
}

impl Message<EndpointAdvertisement> for ControlRunner {
    type Reply = ();

    async fn handle(&mut self, msg: EndpointAdvertisement, _ctx: &mut Context<Self, Self::Reply>) {
        let endpoints: Vec<Endpoint> = msg
            .endpoints
            .iter()
            .map(|ep| Endpoint {
                endpoint: ep.addr,
                ty: match ep.ty {
                    SelfEndpointType::Local => EndpointType::Local,
                    SelfEndpointType::Stun => EndpointType::Stun,
                    SelfEndpointType::Stun4LocalPort => EndpointType::Stun4LocalPort,
                },
            })
            .collect();

        tracing::debug!(
            n_endpoints = endpoints.len(),
            "advertising endpoints to control"
        );

        self.client.set_endpoints(endpoints).await;
    }
}

/// Re-advertise this node's routable IP prefixes (`Hostinfo.RoutableIPs`) to control — the wire
/// half of a runtime [`Runtime::set_advertise_routes`](crate::Runtime::set_advertise_routes). Sent
/// as a direct `ask` from the runtime (not over the bus), so the route change reaches the live
/// map-poll client. `routes` is the final advertised set the caller wants control to grant.
#[derive(Debug)]
pub struct SetAdvertiseRoutes {
    /// The prefixes to advertise to control (already filtered to the final set).
    pub routes: Vec<ipnet::IpNet>,
}

impl Message<SetAdvertiseRoutes> for ControlRunner {
    type Reply = ();

    async fn handle(&mut self, msg: SetAdvertiseRoutes, _ctx: &mut Context<Self, Self::Reply>) {
        tracing::debug!(n_routes = msg.routes.len(), "advertising routes to control");
        self.client.set_routable_ips(msg.routes).await;
    }
}

/// Update this node's `Hostinfo.Hostname` at control — the wire half of a runtime
/// [`Runtime::set_hostname`](crate::Runtime::set_hostname). A direct `ask` from the runtime, so the
/// change reaches the live map-poll client.
#[derive(Debug)]
pub struct SetHostname {
    /// The new hostname to report to control.
    pub hostname: String,
}

impl Message<SetHostname> for ControlRunner {
    type Reply = ();

    async fn handle(&mut self, msg: SetHostname, _ctx: &mut Context<Self, Self::Reply>) {
        tracing::debug!("updating hostname at control");
        self.client.set_hostname(msg.hostname).await;
    }
}

#[cfg(test)]
mod reauth_bridge_tests {
    use tokio::sync::watch;

    use super::bridge_reauth_url_to_state;
    use crate::DeviceState;

    fn url(s: &str) -> url::Url {
        s.parse().unwrap()
    }

    /// The bridge maps a surfaced re-auth URL onto `DeviceState::NeedsLogin(url)` — the fix's core:
    /// a mid-session `MachineNotAuthorized` (forwarded by the control client as `Some(url)`) becomes
    /// the "needs login" state the IPN bus turns into `browse_to_url`.
    #[test]
    fn bridge_maps_auth_url_to_needs_login() {
        let u = url("https://login.example/auth");
        let (tx, rx) = watch::channel(DeviceState::Running);

        bridge_reauth_url_to_state(&tx, Some(&u));

        assert_eq!(*rx.borrow(), DeviceState::NeedsLogin(u));
    }

    /// `None` never drives a transition — the recovery to `Running` is the netmap self-node
    /// handler's job, so the bridge ignores a `None` and leaves the state untouched.
    #[test]
    fn bridge_none_leaves_state_unchanged() {
        let (tx, rx) = watch::channel(DeviceState::Running);

        bridge_reauth_url_to_state(&tx, None);

        assert_eq!(*rx.borrow(), DeviceState::Running);
    }

    /// Re-surfacing the same URL across retries does not re-fire the watch (`send_if_modified`
    /// dedupe against the cell's current value), so a stuck re-auth does not thrash subscribers.
    #[test]
    fn bridge_same_url_does_not_refire() {
        let u = url("https://login.example/auth");
        let (tx, mut rx) = watch::channel(DeviceState::Running);

        bridge_reauth_url_to_state(&tx, Some(&u)); // first: fires
        assert!(rx.has_changed().unwrap(), "first NeedsLogin fires");
        rx.mark_unchanged();
        bridge_reauth_url_to_state(&tx, Some(&u)); // same URL: deduped
        assert!(
            !rx.has_changed().unwrap(),
            "the same re-auth URL must not re-fire the state watch"
        );
    }

    /// A genuinely different re-auth URL after a prior one fires again (the dedupe tracks changes,
    /// it does not pin the first URL forever).
    #[test]
    fn bridge_new_url_after_prior_fires() {
        let a = url("https://login.example/a");
        let b = url("https://login.example/b");
        let (tx, rx) = watch::channel(DeviceState::Running);

        bridge_reauth_url_to_state(&tx, Some(&a));
        bridge_reauth_url_to_state(&tx, Some(&b));

        assert_eq!(*rx.borrow(), DeviceState::NeedsLogin(b));
    }

    /// End-to-end of the *clear* contract: after the bridge sets `NeedsLogin`, the netmap self-node
    /// path (modeled here as a direct `send_replace(Running)`, the exact transition the
    /// `StreamMessage::Next` handler performs on the next good self-node) flips back to `Running`.
    /// This pins that the bridge does NOT need a `None`-clear arm — recovery is owned elsewhere.
    #[test]
    fn running_netmap_clears_needs_login() {
        let u = url("https://login.example/auth");
        let (tx, rx) = watch::channel(DeviceState::Running);

        bridge_reauth_url_to_state(&tx, Some(&u));
        assert_eq!(*rx.borrow(), DeviceState::NeedsLogin(u));

        // The self-node handler's recovery transition (next good netmap self-node → Running).
        tx.send_replace(DeviceState::Running);
        assert_eq!(*rx.borrow(), DeviceState::Running);
    }
}

#[cfg(test)]
mod sticky_pop_browser_url_tests {
    use tokio::sync::watch;

    use super::sticky_update_pop_browser_url;

    fn url(s: &str) -> url::Url {
        s.parse().unwrap()
    }

    /// A non-empty URL publishes to the cell.
    #[test]
    fn non_empty_url_publishes() {
        let (tx, rx) = watch::channel(None);
        let u = url("https://login.example/consent");
        sticky_update_pop_browser_url(&tx, Some(&u));
        assert_eq!(*rx.borrow(), Some(u));
    }

    /// An absent (`None`) update — the common netmap tick — must NOT reset the cell. This is the
    /// regression guard for the thrash bug (a reset-every-tick would coalesce the URL away on the bus).
    #[test]
    fn absent_update_does_not_reset() {
        let u = url("https://login.example/consent");
        let (tx, rx) = watch::channel(Some(u.clone()));
        // Simulate many empty netmap updates.
        for _ in 0..5 {
            sticky_update_pop_browser_url(&tx, None);
        }
        assert_eq!(
            *rx.borrow(),
            Some(u),
            "empty updates must not clear the URL"
        );
    }

    /// The same URL repeated does not re-fire the watch (in-place dedupe via `send_if_modified`), so
    /// a subscriber isn't woken spuriously. Proven by the borrow not having been marked changed.
    #[test]
    fn repeated_same_url_does_not_refire() {
        let u = url("https://login.example/consent");
        let (tx, mut rx) = watch::channel(None);
        sticky_update_pop_browser_url(&tx, Some(&u)); // first: fires
        assert!(rx.has_changed().unwrap(), "first non-empty URL fires");
        rx.mark_unchanged();
        sticky_update_pop_browser_url(&tx, Some(&u)); // same: deduped
        assert!(
            !rx.has_changed().unwrap(),
            "repeating the same URL must not re-fire the watch"
        );
    }

    /// A genuinely new URL after a prior one fires again (sticky but tracks changes).
    #[test]
    fn new_url_after_prior_fires() {
        let a = url("https://login.example/a");
        let b = url("https://login.example/b");
        let (tx, rx) = watch::channel(None);
        sticky_update_pop_browser_url(&tx, Some(&a));
        sticky_update_pop_browser_url(&tx, Some(&b));
        assert_eq!(*rx.borrow(), Some(b));
    }

    /// The realistic session sequence: a URL stays sticky through a run of `None` ticks, and a
    /// *different* URL after that gap still fires. Chains the legs the other tests cover in isolation
    /// (the actual control cadence is "URL, then many empty updates, then maybe a new URL").
    #[test]
    fn sticky_through_none_gap_then_new_url_fires() {
        let a = url("https://login.example/a");
        let b = url("https://login.example/b");
        let (tx, rx) = watch::channel(None);
        sticky_update_pop_browser_url(&tx, Some(&a));
        for _ in 0..3 {
            sticky_update_pop_browser_url(&tx, None);
        }
        assert_eq!(*rx.borrow(), Some(a), "stayed sticky through the None gap");
        sticky_update_pop_browser_url(&tx, Some(&b));
        assert_eq!(
            *rx.borrow(),
            Some(b),
            "a new URL after a None gap still fires"
        );
    }

    /// Returning to a previously-seen URL (A → B → A) re-fires: the dedupe is against the cell's
    /// *current* value, not a full history, so A after B is a genuine change.
    #[test]
    fn returning_to_prior_url_refires() {
        let a = url("https://login.example/a");
        let b = url("https://login.example/b");
        let (tx, mut rx) = watch::channel(None);
        sticky_update_pop_browser_url(&tx, Some(&a));
        sticky_update_pop_browser_url(&tx, Some(&b));
        rx.mark_unchanged();
        sticky_update_pop_browser_url(&tx, Some(&a)); // back to A: differs from current (B) → fires
        assert!(
            rx.has_changed().unwrap(),
            "returning to a prior URL re-fires"
        );
        assert_eq!(*rx.borrow(), Some(a));
    }

    /// End-to-end de-thrash: feed a realistic netmap cadence (empty, empty, URL, empty, empty)
    /// through the producer into a cell, and count the changes a `run_bus`-style subscriber would
    /// observe via `changed()`. The whole point of the fix is that exactly ONE change survives the
    /// surrounding `None` thrash — the pre-fix code (`send_replace` every tick) would have woken the
    /// subscriber on every empty tick and coalesced the URL away. This exercises the producer + the
    /// watch-subscribe path together (the two halves the unit tests cover in isolation).
    #[tokio::test]
    async fn end_to_end_one_change_survives_none_thrash() {
        let u = url("https://login.example/consent");
        let (tx, mut rx) = watch::channel(None);
        // The cadence control actually sends: mostly-empty MapResponses with one carrying the URL.
        let cadence = [None, None, Some(&u), None, None];
        for incoming in cadence {
            sticky_update_pop_browser_url(&tx, incoming);
        }
        // A subscriber sees exactly one change, and it carries the URL (not a coalesced `None`).
        let mut changes = 0;
        while rx.has_changed().unwrap() {
            let v = rx.borrow_and_update().clone();
            changes += 1;
            assert_eq!(v, Some(u.clone()), "the surviving change carries the URL");
        }
        assert_eq!(changes, 1, "exactly one change survives the None thrash");
    }
}

#[cfg(test)]
mod home_region_hysteresis_tests {
    use core::time::Duration;

    use ts_derp::RegionId;
    use ts_netcheck::RegionResult;

    use super::select_home_region;

    fn region(id: u32, latency_ms: u64) -> RegionResult {
        RegionResult {
            latency: Duration::from_millis(latency_ms),
            id: RegionId(core::num::NonZeroU32::new(id).unwrap()),
            latency_map_key: format!("region-{id}"),
            connected_remote: "127.0.0.1:0".parse().unwrap(),
        }
    }

    fn rid(id: u32) -> RegionId {
        RegionId(core::num::NonZeroU32::new(id).unwrap())
    }

    /// Empty measurements yield no selection.
    #[test]
    fn empty_measurements_select_none() {
        assert!(select_home_region(Some(rid(1)), &[]).is_none());
        assert!(select_home_region(None, &[]).is_none());
    }

    /// First selection (no current home region) takes the best (lowest-latency) region directly.
    #[test]
    fn first_selection_takes_best() {
        let m = [region(1, 20), region(2, 50)];
        assert_eq!(select_home_region(None, &m).unwrap().id, rid(1));
    }

    /// Jitter within the 10ms absolute-diff band keeps the current region (no flap). Current=region 2
    /// at 25ms; new best=region 1 at 20ms (only 5ms better) -> keep region 2.
    #[test]
    fn keeps_current_when_within_absolute_diff() {
        let m = [region(1, 20), region(2, 25)];
        let sel = select_home_region(Some(rid(2)), &m).unwrap();
        assert_eq!(
            sel.id,
            rid(2),
            "a 5ms improvement (< 10ms) must not flap the home region"
        );
    }

    /// A meaningful improvement (>10ms AND best <= 2/3 of current) switches. Current=region 2 at
    /// 100ms; new best=region 1 at 20ms -> switch to region 1.
    #[test]
    fn switches_on_meaningful_improvement() {
        let m = [region(1, 20), region(2, 100)];
        assert_eq!(
            select_home_region(Some(rid(2)), &m).unwrap().id,
            rid(1),
            "a large improvement must switch the home region"
        );
    }

    /// The two-thirds rule: even past the 10ms absolute diff, an improvement that does not beat 2/3
    /// of the current latency keeps the current region. Current=region 2 at 30ms; best=region 1 at
    /// 21ms: diff is 9ms (< 10ms keeps anyway) — use 30 vs 21 where diff=9ms. To isolate the 2/3 rule,
    /// use current=60ms, best=45ms: diff=15ms (>10ms, so the absolute test alone would switch), but
    /// 45 > 60*2/3=40, so keep.
    #[test]
    fn keeps_current_when_two_thirds_rule_not_met() {
        let m = [region(1, 45), region(2, 60)];
        let sel = select_home_region(Some(rid(2)), &m).unwrap();
        assert_eq!(
            sel.id,
            rid(2),
            "best (45ms) is not <= 2/3 of current (40ms), so keep current despite >10ms diff"
        );
    }

    /// When the current home region is no longer present in the measurements, take the new best.
    #[test]
    fn switches_when_current_region_absent() {
        let m = [region(1, 20), region(3, 25)];
        assert_eq!(
            select_home_region(Some(rid(2)), &m).unwrap().id,
            rid(1),
            "a current region absent from the measurements falls through to the best"
        );
    }

    /// When the best already IS the current home region, it is kept (no spurious change).
    #[test]
    fn keeps_current_when_it_is_already_best() {
        let m = [region(2, 20), region(1, 50)];
        assert_eq!(select_home_region(Some(rid(2)), &m).unwrap().id, rid(2));
    }
}

#[cfg(test)]
mod self_lockout_tests {
    use ts_tka::{AumHash, Authority, State};

    use super::{SelfLockVerdict, self_lock_verdict};

    fn node_key() -> ts_keys::NodePublicKey {
        ts_keys::NodePrivateKey::random().public_key()
    }

    /// An empty key-signature is the "not signed yet" case: `Unsigned`, never a lockout warning —
    /// so a tailnet that simply has not signed this node does not spam a `warn`.
    #[test]
    fn empty_signature_is_unsigned_not_locked_out() {
        let authority = Authority::from_state(AumHash([0; 32]), State::default());
        assert_eq!(
            self_lock_verdict(&node_key(), &[], &authority),
            SelfLockVerdict::Unsigned
        );
    }

    /// A non-empty key-signature that the active lock cannot authorize (here: an empty-state
    /// Authority trusts no key, so any signature fails to verify) classifies as `LockedOut` — the
    /// operator-facing condition. The verdict carries the verify error string for the log.
    #[test]
    fn unverifiable_signature_is_locked_out() {
        let authority = Authority::from_state(AumHash([0; 32]), State::default());
        // A bogus (non-empty) signature blob: it is non-empty so we attempt verification, and the
        // empty-state Authority rejects it (no trusted key / undecodable), yielding LockedOut.
        let verdict = self_lock_verdict(&node_key(), &[0x01, 0x02, 0x03], &authority);
        assert!(
            matches!(verdict, SelfLockVerdict::LockedOut(_)),
            "a signature the lock cannot authorize must classify as LockedOut, got {verdict:?}"
        );
    }
}
