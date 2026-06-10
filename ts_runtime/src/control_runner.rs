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
    Node, SshPolicy, StateUpdate, TkaStatus,
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
    /// Published copy of the synced TKA [`Authority`](ts_tka::Authority) for the verify-and-log
    /// consumer. `None` until the first successful sync. Observe-only: a reader uses it to *log*
    /// whether a peer's node-key signature verifies, never to drop a peer (enforcement is a separate
    /// gated decision).
    tka_authority: watch::Sender<Option<Arc<ts_tka::Authority>>>,
    /// In-flight guard: `true` while a sync RPC task is running, so a burst of netmap updates does
    /// not spawn overlapping syncs (Go serializes sync under `b.mu`).
    tka_syncing: bool,
    /// Latest cert-domain list from control's netmap DNS config (Go `nm.DNS.CertDomains`), or empty
    /// until control sends a DNS config carrying one. The facade reads this for `Device::cert_domains`.
    cert_domains: watch::Sender<Vec<String>>,
    /// Latest full DNS config from control's netmap (Go `netmap.NetworkMap.DNS`), or `None` until
    /// control sends one. The facade reads this for `Device::dns_config` (the daemon's
    /// `tnet dns status`). A superset of [`cert_domains`](Self::cert_domains), which is kept as its
    /// own cell for the narrower TLS-cert use.
    dns_config: watch::Sender<Option<ts_control::DnsConfig>>,
    /// Latest network-conditions report (preferred DERP region + per-region latencies), updated each
    /// time the DERP-latency measurer reports in. The facade reads this for `Device::netcheck` (the
    /// daemon's `tnet netcheck`). Empty until the first measurement.
    netcheck: watch::Sender<crate::status::NetcheckReport>,
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
        let bring_up = async {
            let (client, stream) = AsyncControlClient::connect(
                &params.config,
                &params.env.keys,
                params.auth_key.as_deref(),
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

        Ok(Self {
            client,
            params,
            self_node: Default::default(),
            ssh_policy: Default::default(),
            tka: Default::default(),
            tka_synced: None,
            tka_authority: Default::default(),
            tka_syncing: false,
            cert_domains: Default::default(),
            dns_config: Default::default(),
            netcheck: Default::default(),
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
            // Lock disabled (or never enabled): drop any synced state and stop publishing an
            // Authority. Never an error; peers are unaffected.
            if self.tka_synced.is_some() {
                self.tka_synced = None;
                self.tka_authority.send_replace(None);
            }
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
        // `tka_syncing` so we don't spawn a second concurrent sync.
        self.tka_syncing = true;
        let current = self.tka_synced.take();
        let config = self.params.config.clone();
        let keys = self.params.env.keys.clone();
        tokio::spawn(async move {
            let result = crate::tka_sync::sync_tka(&config, &keys, current).await;
            // Hand the outcome back to the actor thread to apply (mutating actor state off-thread is
            // not allowed). A send failure just means the actor is gone — nothing to do.
            if let Err(e) = self_ref.tell(TkaSynced { result }).await {
                tracing::debug!(error = ?e, "TKA sync result not delivered (actor gone)");
            }
        });
    }

    /// Apply the outcome of a spawned [`maybe_sync_tka`] task on the actor thread: store the advanced
    /// state + publish the `Authority` (or, on inert/failed sync, leave peers unaffected). Always
    /// clears the in-flight guard.
    fn apply_tka_synced(
        &mut self,
        result: Result<Option<crate::tka_sync::SyncedTka>, crate::tka_sync::TkaSyncDriverError>,
    ) {
        self.tka_syncing = false;
        match result {
            Ok(Some(synced)) => {
                tracing::info!(
                    head = %synced.authority.head().to_base32(),
                    "TKA sync succeeded; publishing verified Authority (observe-only)"
                );
                self.tka_authority
                    .send_replace(Some(synced.authority.clone()));
                self.tka_synced = Some(synced);
            }
            Ok(None) => {
                // Control has no lock for us (no genesis / disabled): stay inert. Not an error.
                tracing::debug!("TKA sync: control reported no lock for this node (inert)");
            }
            Err(e) => {
                // Transport or verify failure: log and stay inert. NEVER errors the netmap or drops a
                // peer. The next netmap update re-triggers a sync attempt.
                tracing::warn!(error = %e, "TKA sync failed; staying inert (no peer impact)");
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
        /// Mirrors [`fetch_id_token`](Self::fetch_id_token): clones the control config + node keys
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
    }

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
        /// Mirrors [`fetch_id_token`](Self::fetch_id_token): clones the control config + node keys
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
    }
}

/// Load or generate the ACME account key, then issue a cert for `name` via set-dns DNS-01.
///
/// Reuses the persisted [`ts_keys::NodeState::acme_account_key`] (PKCS#8 DER) when present so the
/// same Let's Encrypt account survives renewals; otherwise generates an ephemeral per-call key
/// (logged at debug — a new ACME account each issuance, with no write-back). Always targets Let's
/// Encrypt production ([`ts_control::acme::LETS_ENCRYPT_PRODUCTION_DIRECTORY`]).
#[cfg(feature = "acme")]
async fn issue_certificate(
    config: &ts_control::Config,
    keys: &ts_keys::NodeState,
    name: &str,
) -> Result<ts_control::tls::CertifiedKey, ts_control::CertError> {
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
    ts_control::issue_certificate_via_setdns(config, keys, name, &account_key, &directory).await
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
}

impl Message<TkaSynced> for ControlRunner {
    type Reply = ();

    async fn handle(&mut self, msg: TkaSynced, _ctx: &mut Context<Self, Self::Reply>) {
        self.apply_tka_synced(msg.result);
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

        let Some(result) = measurements.first() else {
            tracing::debug!("derp latency measurements empty");
            return;
        };

        let iter = measurements.iter().map(|result| {
            (
                result.latency_map_key.as_str(),
                result.latency.as_secs_f64(),
            )
        });

        tracing::debug!(selected_region_id = ?result.id, "updating home region");

        self.client.set_home_region(result.id, iter).await;
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
