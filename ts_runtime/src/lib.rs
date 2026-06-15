#![doc = include_str!("../README.md")]

extern crate ts_netstack_smoltcp as netstack;

use core::time::Duration;
use std::sync::Arc;

use kameo::{
    actor::{ActorRef, Spawn, WeakActorRef},
    mailbox::Signal,
};
use netstack::netcore::Channel;
use tokio::sync::watch;

use crate::{
    control_runner::ControlRunner, dataplane::DataplaneActor, direct::DirectManager,
    forwarder_actor::ForwarderActor, multiderp::Multiderp, netstack_actor::NetstackActor,
};

/// Pcap stream framer for debug packet capture (`CapturePcap`).
pub mod capture;
/// Control runner.
pub mod control_runner;
mod dataplane;
mod derp_latency;
/// Device connection-state tracking ([`DeviceState`]) and typed registration outcome
/// ([`RegistrationError`]).
pub mod device_state;
mod direct;
mod env;
mod error;
/// Fallback TCP handler registry (`tsnet.Server.RegisterFallbackTCPHandler` parity).
pub mod fallback_tcp;
mod forwarder_actor;
/// Client-side Funnel ingress termination (`tsnet`'s `ListenFunnel` data path).
pub mod funnel;
/// Unified IPN notification bus ([`Notify`] / [`watch_ipn_bus`](Runtime::watch_ipn_bus)), mirroring
/// Go `ipn` `LocalBackend.WatchNotifications` / the `WatchIPNBus` LocalAPI.
pub mod ipn_bus;
mod magic_dns;
pub use magic_dns::DnsQueryResult;
mod multiderp;
/// OS network-link-change supervisor (opt-in `network-monitor` feature): re-binds + re-probes
/// connectivity on a link change. Compiled out entirely when the feature is off.
#[cfg(feature = "network-monitor")]
mod netmon;
mod netstack_actor;
mod packetfilter;
pub mod peer_tracker;
mod peerapi;
mod peerapi_doh;
mod route_updater;
/// Stored Serve config + accept-loop runtime (`tsnet`'s `Get/SetServeConfig` + serving runtime).
pub mod serve;
mod src_filter;
/// Netmap status snapshot, WhoIs, and watcher types.
pub mod status;
/// Taildrop peer-to-peer file transfer store.
pub mod taildrop;
pub mod taildrop_send;
/// Tailnet-Lock (TKA) chain-sync orchestration: bootstrap + offer/send driver (the runtime layer
/// that bridges the `ts_control` sync RPCs and the `ts_tka` chain logic).
mod tka_sync;
#[cfg(feature = "tun")]
mod tun_actor;

pub use device_state::{DeviceState, RegistrationError};
pub(crate) use env::Env;
pub use error::{Error, ErrorKind};
pub use ipn_bus::{IpnBusWatcher, Notify, NotifyWatchOpt};
pub use status::{FileTarget, NetcheckReport, RegionLatency, Status, StatusNode, WhoIs};
pub use ts_dataplane::{CaptureHook, CapturePath};

use crate::peer_tracker::PeerTracker;

/// The runtime for a tailscale device.
pub struct Runtime {
    /// Reference to the control actor.
    pub control: ActorRef<ControlRunner>,
    dataplane: ActorRef<DataplaneActor>,
    /// Reference to the direct (disco/UDP underlay) manager, retained so [`Runtime::rebind`] can
    /// ask it to re-bind the underlay socket on a network/link change.
    direct: ActorRef<DirectManager>,
    /// Reference to the application netstack actor. `None` in TUN transport mode, where there is
    /// no userspace application netstack (the application data path is a real kernel TUN device).
    netstack: Option<WeakActorRef<NetstackActor>>,
    /// Reference to the peer tracker for peer lookups.
    pub peer_tracker: WeakActorRef<PeerTracker>,
    /// Fallback TCP handler registry, bound to the application netstack. `None` in TUN transport
    /// mode (no application netstack exists to attach it to).
    fallback_tcp: Option<fallback_tcp::FallbackTcpManager>,
    /// Reference to the MagicDNS responder, retained so [`Runtime::query_dns`] can run a query
    /// through the live `100.100.100.100` forward path. `None` in TUN transport mode (no
    /// `MagicDnsActor` is spawned there — TUN-mode MagicDNS is an in-packet intercept, not an actor).
    magic_dns: Option<ActorRef<magic_dns::MagicDnsActor>>,
    /// Reference to the forwarder actor, retained so [`Runtime::set_advertise_routes`] can push a
    /// new accept/dial route table onto the running forwarder (the local half of advertising
    /// routes). Without this the strong ref would drop after the startup `GetChannel` and the
    /// forwarder would be reachable only via the message bus.
    forwarder: ActorRef<ForwarderActor>,
    /// Reference to the multiderp manager, retained so [`Runtime::status`] can resolve each
    /// relayed peer's DERP region id to its region **code** (`ipnstate.PeerStatus.Relay`). Without
    /// this the strong ref would drop after startup (it is cloned into the direct manager + route
    /// updater) and the region-code map would be unreachable.
    multiderp: ActorRef<Multiderp>,
    env: Env,
    shutdown: watch::Sender<bool>,
    /// Sender side of the exit-node selector `watch` cell. Held privately here (not on the cloned
    /// `Env`, which keeps only the read side) so that only `Runtime::set_exit_node` can mutate the
    /// selection; the route updater and source filter re-read it via [`Env::exit_node`].
    exit_node_tx: watch::Sender<Option<ts_control::ExitNodeSelector>>,
    /// Sender side of the accept-routes preference `watch` cell. Held privately here (same rationale
    /// as [`exit_node_tx`](Self::exit_node_tx)) so that only [`Runtime::set_accept_routes`] can
    /// toggle it; the route updater and source filter re-read it via [`Env::accept_routes`].
    accept_routes_tx: watch::Sender<bool>,
    /// Sender side of the accept-dns preference `watch` cell. Held privately here (same rationale as
    /// [`accept_routes_tx`](Self::accept_routes_tx)) so that only [`Runtime::set_accept_dns`] can
    /// toggle it; the MagicDNS responder re-reads it via [`Env::accept_dns`] when it rebuilds its
    /// view (the republish that `set_accept_dns` triggers).
    accept_dns_tx: watch::Sender<bool>,
    /// Receiver mirroring the *active* (resolved + fail-closed) exit node's stable id, fed by the
    /// route updater. Read by [`Runtime::status`] / [`Runtime::active_exit_node`] to report which
    /// exit node traffic is actually egressing through (vs. the merely-configured selector).
    active_exit_rx: watch::Receiver<Option<ts_control::StableNodeId>>,
    /// Receiver for the device connection-state cell, fed by the control runner. Read by
    /// [`Runtime::watch_state`] and [`Runtime::wait_until_running`].
    state_rx: watch::Receiver<DeviceState>,
    /// Receiver for the retained peer-capability grants, fed by the packet-filter updater. Read by
    /// [`Runtime::whois`] to resolve the flow-scoped cap map (Go `apitype.WhoIsResponse.CapMap`).
    cap_grants_rx: watch::Receiver<packetfilter::CapGrants>,
    /// Live advertised-route preference (explicit subnet routes + the exit-node flag), seeded from
    /// the startup config. [`Runtime::set_advertise_routes`] and [`set_advertise_exit_node`] each
    /// mutate their part under this lock then re-send the composed set, so the two compose.
    advertise: std::sync::Mutex<AdvertiseState>,
    /// Background task that periodically reaps abandoned taildrop `.partial` files (Go
    /// `feature/taildrop/delete.go` `fileDeleter`). `None` when no taildrop store is configured.
    /// Aborted on [`Drop`] so it cannot outlive the runtime (the `reauth_bridge` pattern).
    taildrop_reaper: Option<tokio::task::JoinHandle<()>>,
    /// The opt-in OS network-link-change supervisor (`network-monitor` feature + the
    /// `Config::network_monitor` flag). Retained so the actor — and thus the
    /// `LinkMonitorHandle` it holds, which aborts the monitor's watcher task on drop — lives for the
    /// device's life and is torn down when the runtime drops. `None` when the flag is off. Only
    /// present when built with the `network-monitor` feature.
    #[cfg(feature = "network-monitor")]
    #[allow(dead_code)]
    netmon_supervisor: Option<ActorRef<netmon::NetmonSupervisor>>,
}

impl Runtime {
    /// Spawn a new runtime with the given parameters for connecting to a tailnet.
    pub async fn spawn(
        config: ts_control::Config,
        auth_key: Option<String>,
        keys: ts_keys::NodeState,
    ) -> Result<Self, Error> {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // The exit-node selector, accept-routes, and accept-dns preferences are live `watch` cells so
        // `Device::set_exit_node` / `set_accept_routes` / `set_accept_dns` can change them at runtime.
        // `new_with_runtime_txs` returns each `Sender` (mutation capability) grouped in `pref_cells`
        // so they are retained privately on the `Runtime`, while only the `Receiver`s (the readers'
        // contract) live on the cloned `Env`. Initial values come from `ForwarderConfig`.
        let (env, pref_cells) = Env::new_with_runtime_txs(
            keys,
            shutdown_rx,
            env::ForwarderConfig::from_control_config(&config),
        );

        // Both userspace netstacks (application + forwarder) share one netstack config. Honor the
        // per-deployment TCP buffer knob, and set the netstack MTU to the overlay/tunnel MTU so the
        // advertised MSS fits the tunnel — leaving it at the netstack's generic 1500 default would
        // emit over-1280 segments into the WireGuard path. The MTU comes from a `Tun` transport's
        // `TunConfig` when one is configured (so the netstack and the TUN agree), else the 1280
        // overlay default (the `Netstack` userspace mode — the common case — has no per-OS MTU knob,
        // but the tailnet overlay MTU is still 1280).
        let configured_mtu = match &config.transport_mode {
            ts_control::TransportMode::Tun(tun_cfg) => tun_cfg.mtu,
            ts_control::TransportMode::Netstack => None,
        };
        let netstack_config = netstack_config_from(config.tcp_buffer_size, configured_mtu);

        let dataplane = DataplaneActor::spawn(env.clone());

        let (netstack_id, netstack_up, netstack_down) =
            dataplane.ask(dataplane::NewOverlayTransport).await?;

        // A second overlay transport feeds the dedicated any-IP forwarder netstack. Inbound packets
        // for advertised subnet routes / the exit-node default route are routed here (see
        // `route_updater`), keeping forwarded flows off the application netstack.
        let (forwarder_id, forwarder_up, forwarder_down) =
            dataplane.ask(dataplane::NewOverlayTransport).await?;

        // The selected DERP home region (Go `report.PreferredDERP`): the control runner is the sole
        // writer (it applies the netcheck `bestRecent` + hysteresis smoothing), and `Multiderp`
        // reads it to drive the local home relay — so the relay follows the SAME smoothed home the
        // runner advertises to control, instead of picking it from the raw per-cycle latency minimum
        // (which flapped on jitter and could disagree with the advertised home). Created here so it
        // outlives both actors; `None` until the first home is chosen.
        let (home_region_tx, home_region_rx) = watch::channel::<Option<ts_derp::RegionId>>(None);

        let multiderp = Multiderp::spawn((env.clone(), dataplane.clone(), home_region_rx));

        // Spawn the direct (disco) underlay manager before the route updater. Its `on_start`
        // binds the UDP socket and registers its transport synchronously, so by the time the
        // route updater asks it for the direct transport id it is guaranteed to be available.
        let direct = DirectManager::spawn((env.clone(), dataplane.clone(), multiderp.clone()));

        // Spawn the forwarder before the route updater. Its `on_start` builds the forwarder
        // netstack, enables any-IP acceptance, and starts the per-port accept loops synchronously,
        // so by the time the route updater begins delivering advertised prefixes to
        // `forwarder_id` the netstack is already draining its transport.
        let forwarder = ForwarderActor::spawn((
            env.clone(),
            netstack_config.clone(),
            forwarder_up,
            forwarder_down,
        ));
        // Force `on_start` to finish (any-IP enabled, accept loops live) before the route updater
        // can route the first inbound flow to `forwarder_id`: an `ask` blocks until the actor has
        // started.
        //
        // The forwarder netstack's overlay `Channel` is reused by the TUN application path for
        // recursive / exit-node-DoH MagicDNS forwarding (TUN mode has no application netstack of its
        // own, but the forwarder netstack runs in both modes and egresses over the overlay — the
        // anti-leak property `forward_query`/`forward_doh` require). Only the `tun` Tun arm consumes
        // it, so it is unused when the `tun` feature is off — allow that without warn-as-error.
        #[cfg_attr(not(feature = "tun"), allow(unused_variables))]
        let (forwarder_channel,) = forwarder.ask(forwarder_actor::GetChannel).await?;

        // The route updater is the single authoritative resolver of the active (resolved,
        // fail-closed) exit node; it publishes the resolved stable id into this watch cell so
        // `Runtime::status` can report which exit is actually engaged (not just configured).
        let (active_exit_tx, active_exit_rx) = watch::channel(None);
        route_updater::RouteUpdater::spawn((
            multiderp.clone(),
            direct.clone(),
            env.clone(),
            netstack_id,
            forwarder_id,
            active_exit_tx,
        ));
        // The packet-filter updater also surfaces the retained cap-grants (for flow-scoped WhoIs)
        // through a `watch` cell whose receiver the `Runtime` holds — the bus has no replay, so a
        // `watch` is how `Runtime::whois` reads the current grants on demand.
        let (cap_grants_tx, cap_grants_rx) = watch::channel(Default::default());
        packetfilter::PacketfilterUpdater::spawn((env.clone(), cap_grants_tx));
        src_filter::SourceFilterUpdater::spawn(env.clone());
        // TKA enforcement-authority cell (Go `tkaFilterNetmapLocked`). Created here — before both
        // actors spawn — so the control runner (sole writer, `Sender`) and the peer tracker (reader,
        // `Receiver`) share one `watch` cell. A `watch` (not a bus message) is the transport for this
        // security-critical state: last-write-wins, never dropped under load, ordered by the control
        // runner's writes, so a disable (`None`) can never be reordered behind or dropped before a
        // stale `Some`. `None` = no lock synced / disabled (admit all).
        let (tka_authority_tx, tka_authority_rx) =
            watch::channel::<Option<std::sync::Arc<ts_tka::Authority>>>(None);
        let peer_tracker = PeerTracker::spawn((env.clone(), tka_authority_rx)).downgrade();

        // Select the application data path from the transport mode. The forwarder/egress path
        // above is UNCHANGED in both modes — TUN mode only swaps the application data path, never
        // the forwarder. `config` is moved into `ControlRunner::spawn` below, so branch on a
        // borrow and clone the small `TunConfig` where needed before the move.
        //
        // - Netstack (the default, and the only reachable arm when the `tun` feature is off):
        //   spawn the application netstack + MagicDNS responder + fallback-TCP registry, all on
        //   the `netstack_up`/`netstack_down` overlay seam.
        // - Tun: spawn `TunActor` on that same overlay seam instead; no application netstack and
        //   no MagicDNS responder exist, and `netstack`/`fallback_tcp` are `None`.
        // - Tun requested but built without the `tun` feature: hard-error (a config/build
        //   mismatch knowable at spawn time). NEVER silently fall back to netstack.
        let (netstack, fallback_tcp, magic_dns) = match &config.transport_mode {
            ts_control::TransportMode::Netstack => {
                let netstack = NetstackActor::spawn((
                    env.clone(),
                    netstack_config,
                    netstack_up,
                    netstack_down,
                ));

                // Fetch the netstack channel while we still hold the strong ActorRef, then spawn
                // the MagicDNS responder on it. Its ActorRef is retained on `Runtime` so
                // `query_dns` can drive the live forward path; the serve loop itself is owned by the
                // actor's internal JoinSet.
                let (channel,) = netstack.ask(netstack_actor::GetChannel).await?;
                // The fallback-TCP registry attaches to the application netstack — the same one
                // that carries the embedder's explicit `Device::tcp_listen` sockets — so a
                // fallback handler sees exactly the inbound flows no explicit listener matched.
                let fallback_tcp = fallback_tcp::FallbackTcpManager::new(channel.clone());
                let magic_dns = magic_dns::MagicDnsActor::spawn((env.clone(), channel));

                (
                    Some(netstack.downgrade()),
                    Some(fallback_tcp),
                    Some(magic_dns),
                )
            }

            #[cfg(feature = "tun")]
            ts_control::TransportMode::Tun(tun_cfg) => {
                // Reuse the same `netstack_up`/`netstack_down` overlay-transport pair that would
                // have fed the netstack — it is just the application-side overlay seam (the name
                // is historical). No NetstackActor / MagicDnsActor is spawned.
                tun_actor::TunActor::spawn((
                    env.clone(),
                    tun_cfg.clone(),
                    netstack_up,
                    netstack_down,
                    // Reuse the forwarder netstack's overlay `Channel` for recursive / exit-node-DoH
                    // MagicDNS forwarding in the TUN datapath (TUN mode has no application netstack
                    // Channel of its own). Egresses over the overlay — anti-leak preserved.
                    //
                    // Host-route gating (subnet routes gated on `--accept-routes`, the host `/0` from
                    // the selected exit peer) is no longer snapshotted here: `TunActor` reads the live
                    // `Env` cells (`accept_routes`/`exit_node`) on every host-FIB apply — both the
                    // device-build path and the `PeerState` re-apply path — and folds the union of
                    // peers' AllowedIPs (see `tun_actor::host_routes_from_node`). A runtime
                    // `set_accept_routes` / `set_exit_node` toggle re-broadcasts the peer state, so the
                    // host routing table is re-steered live (no device rebuild needed).
                    forwarder_channel.clone(),
                ));

                (None, None, None)
            }

            #[cfg(not(feature = "tun"))]
            ts_control::TransportMode::Tun(_) => {
                return Err(Error {
                    kind: ErrorKind::TunUnavailable,
                    target_actor: None,
                    message_ty: None,
                });
            }
        };

        // Device connection-state cell. Created here (not inside the actor) so the control runner's
        // `on_start` can publish `Failed`/`NeedsLogin` and still return `Err` without the sender
        // being tied to a `Self` that never gets constructed on a hard registration failure.
        let (state_tx, state_rx) = watch::channel(DeviceState::Connecting);

        // Seed the live advertised-route preference from the startup config before `config` moves
        // into the control runner, so the runtime setters compose against the configured baseline.
        let advertise = std::sync::Mutex::new(AdvertiseState {
            routes: config.advertise_routes.clone(),
            exit_node: config.advertise_exit_node,
        });

        // Unbounded mailbox (not the default bounded-64): the control runner SELF-messages — a
        // spawned TKA sync task delivers its result back via `self_ref.tell(TkaSynced)`, and the
        // netmap stream pump tells `StreamMessage::Next` onto the same mailbox. The stall path: the
        // netmap handler ends by parking on `env.publish().await` into the bounded-64 *bus* (a slow
        // bus subscriber, e.g. a busy TKA-enforcing peer tracker, holds the bus full); while it is
        // parked, a concurrently-finishing sync task's `TkaSynced` self-tell queues behind a full
        // *ControlRunner* mailbox and blocks waiting for capacity, delaying the verified-authority
        // (or lock-disable) write to the enforcement cell — i.e. stale TKA enforcement under churn.
        // kameo gates its self-tell deadlock warning on `is_current()`, which is false for the
        // detached sync task, so the stall is silent. An unbounded mailbox lets the self-tell and the
        // stream pump enqueue without ever awaiting capacity (kameo's documented choice for a
        // self-messaging actor); the runner's inputs are control-paced (the netmap stream + a few RPC
        // replies; the bus delivers best-effort and never backpressures this mailbox), not an attacker
        // flood, so unbounded growth is not a practical exposure.
        let control = ControlRunner::spawn_with_mailbox(
            control_runner::Params {
                config,
                auth_key,
                env: env.clone(),
                state_tx,
                tka_authority: tka_authority_tx,
                home_region: home_region_tx,
            },
            kameo::mailbox::unbounded(),
        );

        // Spawn the taildrop partial-reaper if a store is configured; it sweeps abandoned `.partial`
        // files every `DELETE_DELAY` and exits on shutdown (the handle is aborted in `Drop`).
        let taildrop_reaper = env.taildrop_store.as_ref().map(|store| {
            crate::taildrop::spawn_partial_reaper(store.clone(), shutdown_tx.subscribe())
        });

        // Opt-in OS network-link monitor (`Config::network_monitor`, default off). When enabled it
        // spawns a `NetmonSupervisor` that, on a coalesced link change, asks the direct manager to
        // rebind + re-probe and republishes `MeasureNow` for a re-netcheck — the auto-recovery a
        // real `tailscaled` performs and the engine otherwise leaves to the embedder. When the flag
        // is off this is a complete no-op: zero extra threads/sockets, byte-for-byte today's
        // behavior. The manual `Device::rebind` path is unchanged either way.
        //
        // Feature gating is strict and never silent: with the `network-monitor` feature ON the
        // supervisor (and its `ts_netmon` dep) compile in and spawn when the flag is set; with the
        // feature OFF, setting the flag is a HARD error at spawn (mirrors the `TransportMode::Tun`
        // without-`tun`-feature error above), so a build that cannot honor the request fails loudly
        // rather than booting a node that silently won't auto-recover.
        #[cfg(feature = "network-monitor")]
        let netmon_supervisor = if env.network_monitor {
            // Slice (a): no OS event-source backend is wired yet (the Linux netlink / macOS
            // PF_ROUTE backends are later slices), so the supervisor runs against a `NoopLinkMonitor`
            // — it is live and correctly shaped (it will react the moment a real backend feeds it),
            // it just never sees a synthetic/OS event in this build. Production end-to-end reaction
            // is proven in the integration test via a `ManualLinkMonitor`.
            let monitor: std::sync::Arc<dyn ts_netmon::LinkMonitor> =
                std::sync::Arc::new(ts_netmon::NoopLinkMonitor);
            Some(netmon::NetmonSupervisor::spawn(
                netmon::NetmonSupervisorArgs {
                    monitor,
                    direct: direct.clone(),
                    env: env.clone(),
                },
            ))
        } else {
            None
        };

        #[cfg(not(feature = "network-monitor"))]
        if env.network_monitor {
            // The flag is set but this build cannot honor it. Fail loudly (never a silent no-op).
            return Err(Error {
                kind: ErrorKind::NetworkMonitorUnavailable,
                target_actor: None,
                message_ty: None,
            });
        }

        Ok(Self {
            control,
            dataplane,
            direct,
            peer_tracker,
            fallback_tcp,
            magic_dns,
            forwarder,
            multiderp,
            netstack,
            env,
            shutdown: shutdown_tx,
            exit_node_tx: pref_cells.exit_node,
            accept_routes_tx: pref_cells.accept_routes,
            accept_dns_tx: pref_cells.accept_dns,
            active_exit_rx,
            state_rx,
            cap_grants_rx,
            advertise,
            taildrop_reaper,
            #[cfg(feature = "network-monitor")]
            netmon_supervisor,
        })
    }

    /// Register a fallback TCP handler consulted for every inbound TCP flow that matches no
    /// explicit listener (`tsnet.Server.RegisterFallbackTCPHandler` parity).
    ///
    /// The returned [`fallback_tcp::FallbackTcpHandle`] deregisters the handler when dropped. See
    /// [`fallback_tcp`] for the dispatch contract and anti-leak guarantees.
    ///
    /// Returns [`ErrorKind::UnsupportedInTunMode`] in TUN transport mode, where there is no
    /// application netstack to attach a fallback handler to.
    pub fn register_fallback_tcp_handler(
        &self,
        cb: Arc<
            dyn Fn(core::net::SocketAddr, core::net::SocketAddr) -> fallback_tcp::FallbackDecision
                + Send
                + Sync,
        >,
    ) -> Result<fallback_tcp::FallbackTcpHandle, Error> {
        Ok(self
            .fallback_tcp
            .as_ref()
            .ok_or(Error {
                kind: ErrorKind::UnsupportedInTunMode,
                target_actor: None,
                message_ty: None,
            })?
            .register(cb))
    }

    /// Get a channel to send commands to the netstack.
    ///
    /// Returns [`ErrorKind::UnsupportedInTunMode`] in TUN transport mode, where there is no
    /// application netstack.
    pub async fn channel(&self) -> Result<Channel, Error> {
        let (channel,) = self
            .netstack
            .as_ref()
            .ok_or(Error {
                kind: ErrorKind::UnsupportedInTunMode,
                target_actor: None,
                message_ty: None,
            })?
            .upgrade()
            .ok_or(Error {
                kind: ErrorKind::ActorGone,
                target_actor: None,
                message_ty: None,
            })?
            .ask(netstack_actor::GetChannel)
            .await?;

        Ok(channel)
    }

    /// Resolve `name` for `qtype` through the live MagicDNS responder (the `100.100.100.100`
    /// forward path), returning the raw DNS response, its RCODE, and the upstream resolver(s)
    /// consulted (analogue of Go `LocalClient.QueryDNS`).
    ///
    /// This drives the *real* responder — the same `decide`/forward logic an on-the-wire query
    /// hits — so the answer and its anti-leak posture (a tailnet-suffix name never egresses; a
    /// recursive forward delegates to the active exit node's DoH; only IPv4 upstreams are dialed)
    /// match exactly what a tailnet client observes. `qtype` is the raw RFC 1035 TYPE (`1`=A,
    /// `28`=AAAA, `12`=PTR, or any other).
    ///
    /// Returns [`ErrorKind::UnsupportedInTunMode`] in TUN transport mode, where MagicDNS is an
    /// in-packet intercept on the host's own resolver rather than an actor that can be queried, and
    /// [`ErrorKind::ActorGone`] if the responder has shut down.
    pub async fn query_dns(
        &self,
        name: &str,
        qtype: u16,
    ) -> Result<magic_dns::DnsQueryResult, Error> {
        let result = self
            .magic_dns
            .as_ref()
            .ok_or(Error {
                kind: ErrorKind::UnsupportedInTunMode,
                target_actor: None,
                message_ty: None,
            })?
            .ask(magic_dns::Query {
                name: name.to_owned(),
                qtype,
            })
            .await?;

        Ok(result)
    }

    /// The Taildrop file store, if Taildrop is enabled (`taildrop_dir` configured and the store
    /// initialized). `None` when disabled — fail-closed. Shared with the peerAPI Taildrop server so
    /// the embedder's read APIs and the receive path see the same on-disk store.
    pub fn taildrop_store(&self) -> Option<Arc<crate::taildrop::TaildropStore>> {
        self.env.taildrop_store.clone()
    }

    /// The shared Funnel ingress slot the peerAPI `/v0/ingress` route reads per connection.
    ///
    /// `Device::listen_funnel` installs a [`FunnelManager`](crate::funnel::FunnelManager)'s sink here
    /// to make the route live (the peerAPI server is already running from startup). Returns a clone of
    /// the runtime-lifetime `Arc` so the device can write the slot without restarting the server. See
    /// [`crate::funnel`] for the ingress data path.
    pub fn funnel_ingress_slot(&self) -> crate::funnel::FunnelIngressSlot {
        self.env.funnel_ingress.clone()
    }

    /// The shared "Funnel ingress listener active" flag (the same `Arc` the control session reads to
    /// set `HostInfo.IngressEnabled`). `Device::listen_funnel` flips it `true` while a funnel listener
    /// is up so control routes Funnel traffic to this node; clearing it advertises no live endpoint.
    pub fn ingress_active_flag(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        self.env.ingress_active.clone()
    }

    /// Install (`Some`) or clear (`None`) the debug packet-capture hook on the running dataplane.
    /// `Some(hook)` tees every plaintext packet crossing the datapath to `hook` until it is cleared;
    /// `None` stops capture. Mirrors Go `tstun.Wrapper.InstallCaptureHook` / `ClearCaptureSink`.
    pub async fn install_capture(
        &self,
        hook: Option<ts_dataplane::CaptureHook>,
    ) -> Result<(), Error> {
        self.dataplane
            .ask(dataplane::InstallCapture { hook })
            .await
            .map_err(Into::into)
    }

    /// Re-bind the underlay UDP socket after a network/link change (Wi-Fi switch, sleep/wake). The
    /// embedder's own link monitor calls this (the engine owns the socket re-bind; the embedder owns
    /// OS netmon). Re-binds the socket (same-port-preferred, IPv4-only invariant preserved) and
    /// resets the now-stale local NAT mapping — clearing learned reflexive addresses and every
    /// confirmed direct path while keeping candidate endpoints, so peers re-probe over the new socket
    /// and relay over DERP (never a direct host dial) until a path re-confirms. Peers, control, the
    /// netmap, disco state, and DERP are untouched. A no-op when the underlay is inert (bind failed
    /// at startup, DERP-only). Mirrors Go magicsock `Conn.Rebind` + `resetEndpointStates`.
    pub async fn rebind(&self) -> Result<(), Error> {
        self.direct.ask(direct::Rebind).await.map_err(Error::from)
    }

    /// Force an immediate STUN / endpoint re-probe **without** rebinding the underlay socket —
    /// Go magicsock's `Conn.ReSTUN`. Asks the `DirectManager` to run one STUN sweep now (re-learn
    /// our reflexive/public address) while leaving the socket, its NAT mapping, learned paths, peers,
    /// control, and DERP untouched. Lighter than [`rebind`](Self::rebind): no socket swap, no
    /// re-ping. A no-op when the underlay is inert (bind failed at startup, DERP-only). No control
    /// round-trip.
    pub async fn re_stun(&self) -> Result<(), Error> {
        self.direct.ask(direct::ReStun).await.map_err(Error::from)
    }

    /// A snapshot of the local netmap: this node plus every known peer.
    ///
    /// Combines the self node held by the control runner with the peer set held by the peer
    /// tracker. Mirrors tsnet's `LocalClient::Status`.
    ///
    /// `self_node` is `None` until the first netmap update has been received from control. Peer
    /// entries carry no online/user/capability data (see the [`status`] module docs for that gap).
    pub async fn status(&self) -> Result<Status, Error> {
        let self_node_domain = self.control.ask(control_runner::SelfNode).await?;
        // The MagicDNS suffix is the self node's FQDN minus its host label — already split into
        // `Node.tailnet` at decode time (Go derives it the same way in `NetworkMap.MagicDNSSuffix`).
        // Capture it before the domain `Node` is mapped away into a `StatusNode`.
        let magic_dns_suffix = self_node_domain.as_ref().and_then(|n| n.tailnet.clone());
        let self_node = self_node_domain.as_ref().map(StatusNode::from_node);

        let peers_with_ids = self
            .peer_tracker
            .upgrade()
            .ok_or(Error {
                kind: ErrorKind::ActorGone,
                target_actor: None,
                message_ty: None,
            })?
            .ask(peer_tracker::GetStatus)
            .await?;

        // Join per-peer connectivity (Go `PeerStatus.CurAddr`): one batched query to the direct
        // manager for every peer's current trusted direct endpoint, then fill `cur_addr` on each
        // `StatusNode`. A peer absent from the map is relayed via DERP (`cur_addr = None`). This is a
        // live snapshot — the direct path can expire/re-confirm between calls (matches Go's snapshot
        // semantics). The `watch_netmap` stream intentionally carries no connectivity (it is a netmap
        // watch, not a path-state watch, and does not re-fire on direct↔relay flips).
        let ids: Vec<ts_transport::PeerId> = peers_with_ids.iter().map(|(id, _)| *id).collect();
        let best_addrs = self
            .direct
            .ask(direct::BestAddrs { ids: ids.clone() })
            .await
            .unwrap_or_default();

        // For the peers with NO direct path (relayed via DERP), resolve the region CODE they relay
        // through (Go `PeerStatus.Relay`). One batched ask to multiderp; `cur_addr` and `relay` are
        // mutually exclusive for a routed peer, mirroring Go's empty-vs-set strings.
        let relay_ids: Vec<ts_transport::PeerId> = ids
            .into_iter()
            .filter(|id| !best_addrs.contains_key(id))
            .collect();
        let relay_codes = if relay_ids.is_empty() {
            Default::default()
        } else {
            self.multiderp
                .ask(multiderp::RelayCodesForPeers { ids: relay_ids })
                .await
                .unwrap_or_default()
        };

        let peers = peers_with_ids
            .into_iter()
            .map(|(id, mut node)| match best_addrs.get(&id).copied() {
                Some(addr) => {
                    node.cur_addr = Some(addr);
                    node
                }
                None => {
                    node.relay = relay_codes.get(&id).cloned();
                    node
                }
            })
            .collect();

        Ok(Status {
            self_node,
            peers,
            active_exit_node: self.active_exit_node(),
            magic_dns_suffix,
        })
    }

    /// List the tailnet peers this node can Taildrop a file *to* (Go LocalAPI `FileTargets`).
    ///
    /// Mirrors the upstream send-path filter (`feature/taildrop` `Extension::FileTargets`): a peer
    /// qualifies when it advertises a reachable peerAPI **and** is either owned by the same user as
    /// this node **or** explicitly granted the file-sharing-target capability. The whole list is
    /// gated on this node holding the file-sharing capability (control sets it when the admin enables
    /// Taildrop) — absent that, an empty list (fail-closed, not an error, matching how the receive
    /// store returns empty when disabled). Results are sorted by the peer's MagicDNS name.
    ///
    /// Targets are listed regardless of current online state (upstream's `FileTargets` does not gate
    /// on online either; an offline target's send will simply time out). The self node is never
    /// included. Returns empty before the first netmap.
    ///
    /// Divergence from Go: the upstream filter also excludes `tvOS` peers, which this fork cannot
    /// reproduce (the domain node carries no OS string); the impact is negligible — the actual send
    /// fail-closes if such a peer refused the transfer.
    pub async fn file_targets(&self) -> Result<Vec<FileTarget>, Error> {
        // Node-level gate: this node must hold the file-sharing capability (Taildrop enabled by the
        // admin). Read it off the self node's cap map, like Go's `hasCapFileSharing()`.
        let self_node = self.control.ask(control_runner::SelfNode).await?;
        let Some(self_node) = self_node else {
            return Ok(Vec::new()); // no netmap yet
        };
        if !self_node.can_share_files() {
            return Ok(Vec::new()); // Taildrop not enabled for the tailnet — fail-closed
        }
        let self_user_id = self_node.user_id;

        let peers = self
            .peer_tracker
            .upgrade()
            .ok_or(Error {
                kind: ErrorKind::ActorGone,
                target_actor: None,
                message_ty: None,
            })?
            .ask(peer_tracker::AllPeers)
            .await?;

        // Eligibility + ordering live in `build_file_targets` (pure, unit-tested in `status`).
        Ok(status::build_file_targets(peers, self_user_id))
    }

    /// The stable id of the exit node traffic is currently egressing through, or `None` if none is
    /// engaged. This is the route updater's resolved + fail-closed answer (see
    /// [`Status::active_exit_node`](crate::status::Status::active_exit_node)): it differs from the
    /// configured [`exit_node`](Self::exit_node) selector, which may name a peer that is absent or
    /// no longer advertising a default route (in which case egress is dropped and this returns
    /// `None`).
    pub fn active_exit_node(&self) -> Option<ts_control::StableNodeId> {
        self.active_exit_rx.borrow().clone()
    }

    /// Request an OIDC ID token from control scoped to `audience` (workload-identity federation).
    ///
    /// Returns the signed JWT, or the token RPC's own [`ts_control::IdTokenError`]. The kameo
    /// delegated-reply send error is flattened: a handler error carries the real `IdTokenError`,
    /// any other send failure (actor shutdown / mailbox closed) is surfaced as
    /// [`ts_control::IdTokenError::NetworkError`].
    pub async fn fetch_id_token(
        &self,
        audience: String,
    ) -> Result<String, ts_control::IdTokenError> {
        self.control
            .ask(control_runner::FetchIdToken { audience })
            .await
            .map_err(flatten_send_err)
    }

    /// Log this node out of the tailnet: deregister it by expiring its current node key.
    ///
    /// Forwards to the control runner, which re-POSTs `/machine/register` with a past expiry over a
    /// fresh Noise channel. This is a control-plane state change only — it does NOT shut the runtime
    /// down (the caller follows with [`graceful_shutdown`](Self::graceful_shutdown)) and does not
    /// touch the on-disk node key. The kameo delegated-reply send error is flattened the same way as
    /// `fetch_id_token`: a handler error carries the real
    /// [`ts_control::LogoutError`]; any other send failure (actor shutdown / mailbox closed) is
    /// surfaced as [`ts_control::LogoutError::NetworkError`].
    pub async fn logout(&self) -> Result<(), ts_control::LogoutError> {
        self.control
            .ask(control_runner::Logout)
            .await
            .map_err(flatten_logout_send_err)
    }

    /// Publish a `TXT` DNS record for this node via control's `/machine/set-dns` (Go
    /// `LocalClient.SetDNS`).
    ///
    /// Forwards to the control runner, which POSTs the record over a fresh Noise channel. The kameo
    /// delegated-reply send error is flattened the same way as `fetch_id_token`:
    /// a handler error carries the real [`ts_control::SetDnsError`]; any other send failure (actor
    /// shutdown / mailbox closed) is surfaced as [`ts_control::SetDnsError::NetworkError`].
    pub async fn set_dns(
        &self,
        name: String,
        value: String,
    ) -> Result<(), ts_control::SetDnsError> {
        self.control
            .ask(control_runner::SetDns { name, value })
            .await
            .map_err(flatten_set_dns_send_err)
    }

    /// Sign `node_key` with this node's network-lock key and submit the signature to control
    /// (Go `tka.sign` Direct case → `/machine/tka/sign`).
    ///
    /// Submits only — the local [`Authority`](ts_tka::Authority) is **not** mutated here; it advances
    /// via the existing verified-sync path. A handler error carries the real [`ts_control::TkaSyncError`];
    /// any other send failure (actor shutdown / mailbox closed) is surfaced as
    /// [`ts_control::TkaSyncError::NetworkError`].
    pub async fn tka_sign(&self, node_key: [u8; 32]) -> Result<(), ts_control::TkaSyncError> {
        self.control
            .ask(control_runner::TkaSign { node_key })
            .await
            .map_err(flatten_tka_send_err)
    }

    /// Disable Tailnet Lock by presenting the `disablement_secret` to control (Go `tka.disable` →
    /// `/machine/tka/disable`), targeting the current authority head.
    ///
    /// Submits only — the local [`Authority`](ts_tka::Authority) is **not** mutated here. A handler
    /// error carries the real [`ts_control::TkaSyncError`] (incl.
    /// [`Unsupported`](ts_control::TkaSyncError::Unsupported) when there is no known TKA head to
    /// disable); any other send failure collapses to
    /// [`NetworkError`](ts_control::TkaSyncError::NetworkError).
    pub async fn tka_disable(
        &self,
        disablement_secret: Vec<u8>,
    ) -> Result<(), ts_control::TkaSyncError> {
        self.control
            .ask(control_runner::TkaDisable { disablement_secret })
            .await
            .map_err(flatten_tka_send_err)
    }

    /// Initialize Tailnet Lock with this node as the sole initial trusted key, gated by
    /// `disablement_secret` (Go `tka` init → `/machine/tka/init/{begin,finish}`).
    ///
    /// Submits only — does not seed the local [`Authority`](ts_tka::Authority); the node picks up the
    /// new lock via the existing verified netmap-sync. A handler error carries the real
    /// [`ts_control::TkaSyncError`] ([`Unsupported`](ts_control::TkaSyncError::Unsupported) if
    /// control needs other nodes re-signed — the single-node "lock yourself in" subset only); any
    /// other send failure collapses to [`NetworkError`](ts_control::TkaSyncError::NetworkError).
    pub async fn tka_init(
        &self,
        disablement_secret: Vec<u8>,
    ) -> Result<(), ts_control::TkaSyncError> {
        self.control
            .ask(control_runner::TkaInit { disablement_secret })
            .await
            .map_err(flatten_tka_send_err)
    }

    /// Issue a real Let's Encrypt certificate for this node's MagicDNS `name` (`acme` feature).
    ///
    /// Mirrors `fetch_id_token`: forwards to the control runner, which runs
    /// the client-side ACME DNS-01 flow on a spawned task and publishes the challenge TXT via the
    /// node's set-dns RPC. The kameo delegated-reply send error is flattened — a handler error
    /// carries the real [`ts_control::CertError`]; any other send failure (actor shutdown / mailbox
    /// closed) is surfaced as a [`ts_control::CertError::Io`]. SaaS-only: a self-hosted control
    /// plane 501s on set-dns.
    #[cfg(feature = "acme")]
    pub async fn get_certificate(
        &self,
        name: String,
    ) -> Result<ts_control::tls::CertifiedKey, ts_control::CertError> {
        self.control
            .ask(control_runner::GetCertificate { name })
            .await
            .map_err(flatten_cert_send_err)
    }

    /// Issue a real Let's Encrypt certificate for this node's MagicDNS `name` and return the
    /// **PEM pair** `(cert_chain_pem, key_pem)` — the analog of Go's
    /// `LocalClient.CertPairWithValidity`, for writing the daemon's on-disk `.crt` + `.key`
    /// (`tnet cert`). `acme` feature.
    ///
    /// Same issuance as [`get_certificate`](Self::get_certificate) (one client-side ACME DNS-01
    /// order, challenge published via the node's set-dns RPC) — only the result shape differs: this
    /// returns the leaf+chain PEM and the leaf-key PEM instead of the opaque
    /// [`CertifiedKey`](ts_control::tls::CertifiedKey). The second element is the **leaf private
    /// key** PEM; it is never logged anywhere on this path.
    ///
    /// **`min_validity` (honest "always fresh").** Go's `CertPairWithValidity` reuses a cached cert
    /// when it has at least `min_validity` of its lifetime left, and re-issues otherwise. This fork
    /// has **no cert cache** — every call performs a fresh issuance — so `min_validity` is accepted
    /// for signature compatibility but does not change behavior: a freshly issued cert (full
    /// lifetime) trivially satisfies any `min_validity`. A reuse cache is separate future work; this
    /// does NOT fake one.
    ///
    /// Mirrors [`get_certificate`](Self::get_certificate)'s error handling: the kameo
    /// delegated-reply send error is flattened — a handler error carries the real
    /// [`ts_control::CertError`]; any other send failure (actor shutdown / mailbox closed) collapses
    /// to a [`ts_control::CertError::Io`]. SaaS-only: a self-hosted control plane 501s on set-dns.
    #[cfg(feature = "acme")]
    pub async fn cert_pair(
        &self,
        name: String,
        min_validity: Option<Duration>,
    ) -> Result<(String, String), ts_control::CertError> {
        // No cert cache exists in this fork (every issuance is fresh), so `min_validity` is honored
        // trivially by always issuing a full-lifetime cert. Bound (unused beyond this contract) so
        // the parameter is explicitly accounted for rather than silently ignored.
        let _ = min_validity;
        self.control
            .ask(control_runner::GetCertPair { name })
            .await
            .map_err(flatten_cert_send_err)
    }

    /// Resolve which node owns a tailnet source address.
    ///
    /// Maps the destination IP of `addr` to its owning node. Mirrors tsnet's `LocalClient::WhoIs`.
    /// Returns `None` if no peer holds that tailnet IP.
    ///
    /// The returned [`WhoIs`] additionally carries the **flow-scoped** peer-capability grants
    /// ([`WhoIs::cap_map`], Go `apitype.WhoIsResponse.CapMap`): the caps control's packet-filter
    /// application rules authorize for traffic from THIS node (the flow source) to `addr` (the
    /// destination). Empty when no grant matches. (The node-level cap map rides
    /// [`WhoIs::capabilities`].)
    pub async fn whois(&self, addr: core::net::SocketAddr) -> Result<Option<WhoIs>, Error> {
        let whois = self
            .peer_tracker
            .upgrade()
            .ok_or(Error {
                kind: ErrorKind::ActorGone,
                target_actor: None,
                message_ty: None,
            })?
            .ask(peer_tracker::Whois { addr })
            .await?;

        let Some(mut whois) = whois else {
            return Ok(None);
        };

        // Fill the flow-scoped cap map: src = this node's own tailnet IP (of the dst's family),
        // dst = the queried address. A grant applies when its source matches the flow source — `src`
        // ∈ its src prefixes OR this node holds one of its source node-caps — AND `dst` ∈ its dst
        // prefixes (Go `Filter.CapsWithValues`). Resolve our own IP + cap map from the self node; if
        // it isn't known yet, leave the map empty (no grants resolvable without a source).
        let dst = addr.ip();
        if let Some(self_node) = self.control.ask(control_runner::SelfNode).await? {
            let src: core::net::IpAddr = if dst.is_ipv6() {
                self_node.tailnet_address.ipv6.addr().into()
            } else {
                self_node.tailnet_address.ipv4.addr().into()
            };
            let grants = self.cap_grants_rx.borrow();
            whois.cap_map = ts_packetfilter_state::caps_for(&grants, src, dst, |cap| {
                self_node.has_node_attr(cap)
            });
        }

        Ok(Some(whois))
    }

    /// The current direct-path status to the peer holding tailnet IP `dst`: its confirmed direct UDP
    /// endpoint and that path's last-measured RTT, or `None` when there is no direct path right now
    /// (the peer is relayed via DERP, is unknown, or has no disco key).
    ///
    /// The latency is the RTT of the most recent disco ping/pong that confirmed the path — a live
    /// snapshot up to one probe interval stale, NOT a fresh on-demand round-trip (that is a separate,
    /// heavier capability). Mirrors the direct-path latency Go surfaces for `ipnstate.PeerStatus`.
    pub async fn direct_path(
        &self,
        dst: core::net::IpAddr,
    ) -> Result<Option<(core::net::SocketAddr, Duration)>, Error> {
        let peer_tracker = self.peer_tracker.upgrade().ok_or(Error {
            kind: ErrorKind::ActorGone,
            target_actor: None,
            message_ty: None,
        })?;

        // Resolve the tailnet IP to its node, then to its disco key. No node / no disco key ⇒ no
        // direct path is possible (a peer with no disco key can only be reached via DERP).
        let Some(node) = peer_tracker
            .ask(peer_tracker::PeerByTailnetIp { ip: dst })
            .await?
        else {
            return Ok(None);
        };
        let Some(disco) = node.disco_key else {
            return Ok(None);
        };

        self.direct
            .ask(direct::DirectPathLatency { disco })
            .await
            .map_err(Into::into)
    }

    /// Send a disco ping to the peer holding tailnet IP `dst` **now** and await the pong, returning
    /// the fresh round-trip latency and the endpoint that answered, or `None` if no pong arrives
    /// within `timeout` (or the peer is unknown / has no disco key / no candidate path). This is the
    /// true on-demand `PingType::Disco` (Go `tailscale ping`), as opposed to
    /// [`direct_path`](Self::direct_path) which reports the last periodic probe's RTT.
    ///
    /// The ping round-trip is awaited OFF the direct manager's mailbox (we take a `MagicSock` handle
    /// and await on it directly), so a slow/timing-out ping never blocks the actor.
    pub async fn ping_disco(
        &self,
        dst: core::net::IpAddr,
        timeout: Duration,
    ) -> Result<Option<(core::net::SocketAddr, Duration)>, Error> {
        let peer_tracker = self.peer_tracker.upgrade().ok_or(Error {
            kind: ErrorKind::ActorGone,
            target_actor: None,
            message_ty: None,
        })?;

        let Some(node) = peer_tracker
            .ask(peer_tracker::PeerByTailnetIp { ip: dst })
            .await?
        else {
            return Ok(None);
        };
        let Some(disco) = node.disco_key else {
            return Ok(None);
        };

        // Cheap synchronous handle fetch, then await the ping OFF the actor mailbox.
        let Some(sock) = self.direct.ask(direct::SockHandle).await? else {
            return Ok(None);
        };
        // A `ping_now` error is an underlay UDP send failure (not an actor problem); surface it as a
        // reply-level error. A timed-out / unanswered ping is `Ok(None)`, not an error.
        sock.ping_now(&disco, timeout).await.map_err(|_| Error {
            kind: ErrorKind::ReplyErr,
            target_actor: None,
            message_ty: None,
        })
    }

    /// Change the selected exit node at runtime (the equivalent of Go `tsnet`'s
    /// `LocalClient.EditPrefs(ExitNodeID/ExitNodeIP)`), without recreating the device.
    ///
    /// Updates the live exit-node selector, then asks the peer tracker to re-broadcast the current
    /// peer set so the route updater and source filter re-resolve the new selector immediately.
    /// `None` clears the exit node (internet-bound traffic is then dropped, fail-closed, unless this
    /// node egresses directly). The selection is re-resolved against the live peer set, so passing a
    /// selector for a peer not yet in the netmap simply takes effect once that peer appears.
    pub async fn set_exit_node(
        &self,
        selector: Option<ts_control::ExitNodeSelector>,
    ) -> Result<(), Error> {
        // Update the live cell every reader borrows from. `send_replace` keeps the value current
        // even with no active receivers (none can have dropped while the runtime is up, but it is
        // the right non-failing primitive here).
        self.exit_node_tx.send_replace(selector);

        // Trigger an immediate re-resolution: the route updater (outbound routes + DoH delegation)
        // and the source filter (inbound validation) both recompute on an `Arc<PeerState>`, so a
        // re-broadcast applies the new exit without waiting for the next netmap update.
        self.peer_tracker
            .upgrade()
            .ok_or(Error {
                kind: ErrorKind::ActorGone,
                target_actor: None,
                message_ty: None,
            })?
            .ask(peer_tracker::RepublishState)
            .await
            .map_err(Into::into)
    }

    /// The currently-selected exit node, or `None` if none is selected.
    pub fn exit_node(&self) -> Option<ts_control::ExitNodeSelector> {
        self.env.exit_node()
    }

    /// Toggle whether this node accepts peer-advertised subnet routes at runtime (the equivalent of
    /// Go `tsnet`'s `LocalClient.EditPrefs(RouteAll)` / `tailscale set --accept-routes`), without
    /// recreating the device.
    ///
    /// `accept-routes` is a purely **local** preference — unlike advertised routes it is never
    /// reported to control (no `Hostinfo` / MapRequest side), so this only re-runs the local
    /// route/source-filter recompute, mirroring [`set_exit_node`](Self::set_exit_node) rather than
    /// [`set_advertise_routes`](Self::set_advertise_routes). Updates the live cell, then asks the peer
    /// tracker to re-broadcast the current peer set so the route updater (outbound routes) and the
    /// source filter (inbound validation) re-filter against the new value immediately: turning it on
    /// installs newly-accepted subnet routes (and widens the source filter to match); turning it off
    /// removes them from BOTH in lock-step (never accepting a source for a route no longer installed).
    /// Self routes and the exit-node default `/0` are unaffected (the latter is gated by the exit-node
    /// selection, not this flag).
    ///
    /// In TUN transport mode the host routing table is also re-steered live: the `RepublishState`
    /// kicked below re-broadcasts the peer set to the `TunActor`, whose `PeerState` handler re-reads
    /// `accept_routes` (and the exit selection) from `Env` and re-applies the host routes — so the
    /// toggle takes effect without rebuilding the device (the apply is an idempotent add-new/
    /// remove-gone diff). The exit-node default `/0` is still keyed on the exit selection, not this flag.
    pub async fn set_accept_routes(&self, accept: bool) -> Result<(), Error> {
        // Update the live cell every reader borrows from (same primitive/rationale as set_exit_node).
        self.accept_routes_tx.send_replace(accept);

        // Trigger an immediate re-filter: the route updater and source filter both recompute on an
        // `Arc<PeerState>`, so a re-broadcast applies the new preference without waiting for the next
        // netmap update. Both re-read the same live cell, so the outbound route set and the inbound
        // source filter stay coupled (the anti-leak invariant).
        self.peer_tracker
            .upgrade()
            .ok_or(Error {
                kind: ErrorKind::ActorGone,
                target_actor: None,
                message_ty: None,
            })?
            .ask(peer_tracker::RepublishState)
            .await
            .map_err(Into::into)
    }

    /// Whether this node currently accepts peer-advertised subnet routes (`--accept-routes`).
    pub fn accept_routes(&self) -> bool {
        self.env.accept_routes()
    }

    /// Toggle whether this node accepts the tailnet's DNS configuration at runtime (the equivalent of
    /// Go `tsnet`'s `LocalClient.EditPrefs(CorpDNS)` / `tailscale set --accept-dns`), without
    /// recreating the device.
    ///
    /// Like [`set_accept_routes`](Self::set_accept_routes), `accept-dns` is a purely **local**
    /// preference — it is never reported to control (no `Hostinfo` / MapRequest side), so this only
    /// re-runs the local MagicDNS view rebuild. Updates the live cell, then asks the peer tracker to
    /// re-broadcast the current peer set; the resulting `PeerState` rebuild re-applies the gate on the
    /// MagicDNS responder (and the peerAPI DoH server that shares its view). When `false`, the
    /// responder ignores the control-pushed DNS config and answers every query `REFUSED`, mirroring Go
    /// applying an empty `dns.Config` when `CorpDNS` is off; flipping it back to `true` restores
    /// serving from the still-current config (the real config is never destroyed — only gated at the
    /// read site), so the OFF→ON restore is automatic.
    pub async fn set_accept_dns(&self, accept: bool) -> Result<(), Error> {
        // Update the live cell every reader borrows from (same primitive/rationale as set_accept_routes).
        self.accept_dns_tx.send_replace(accept);

        // Trigger an immediate view rebuild: the MagicDNS responder re-reads `Env::accept_dns()` when
        // it handles a `PeerState`, so a re-broadcast re-applies the gate on both the netstack
        // responder and the peerAPI DoH server (which share the view) without waiting for the next
        // control/peer update. Mirrors `set_accept_routes`'s republish.
        self.peer_tracker
            .upgrade()
            .ok_or(Error {
                kind: ErrorKind::ActorGone,
                target_actor: None,
                message_ty: None,
            })?
            .ask(peer_tracker::RepublishState)
            .await
            .map_err(Into::into)
    }

    /// Whether this node currently accepts the tailnet's DNS configuration (`--accept-dns` / `CorpDNS`).
    pub fn accept_dns(&self) -> bool {
        self.env.accept_dns()
    }

    /// Change the set of subnet routes this node advertises at runtime (Go `tailscale set
    /// --advertise-routes`). Applies BOTH halves together so the wire and the data path agree:
    ///
    /// 1. **Wire** — re-advertise `Hostinfo.RoutableIPs` to control on the live map-poll connection
    ///    (so control grants the node the subnet-router role for exactly these prefixes).
    /// 2. **Local** — swap the forwarder's accept/dial route table (so the node actually forwards the
    ///    prefixes it advertises). New flows see the new set; in-flight flows keep their routing.
    ///
    /// `routes` is filtered to the IPv4-only, deduplicated set this fork can honor (IPv6 prefixes are
    /// dropped under the IPv6-off posture — we never advertise a route we won't forward), so the wire
    /// and forwarder are fed the identical final set. This sets the explicit subnet prefixes only; it
    /// does NOT touch the exit-node `0.0.0.0/0` advertisement (a separate concern).
    pub async fn set_advertise_routes(&self, routes: Vec<ipnet::IpNet>) -> Result<(), Error> {
        // Update the explicit-subnet part of the live preference, keep the exit-node flag, and
        // re-send the composed set. Composes with `set_advertise_exit_node` (neither clobbers the
        // other's contribution to `Hostinfo.RoutableIPs`).
        let composed = {
            let mut adv = self.advertise.lock().unwrap_or_else(|p| p.into_inner());
            adv.routes = routes;
            compose_advertised_routes(adv.routes.clone(), adv.exit_node)
        };
        self.apply_advertised_routes(composed).await
    }

    /// Advertise (or stop advertising) this node as an **exit node** — the `0.0.0.0/0` default route
    /// (Go `tailscale set --advertise-exit-node`). Composes with
    /// [`set_advertise_routes`](Self::set_advertise_routes): toggling the exit node re-sends the
    /// explicit subnet routes plus (when `enable`) `0.0.0.0/0`, so the two preferences are
    /// independent. Like `set_advertise_routes`, this both re-advertises `Hostinfo.RoutableIPs` to
    /// control AND updates the forwarder's accept/dial set, applied together. Control still gates
    /// whether the advertised exit node is actually *usable* by peers (this only advertises it).
    pub async fn set_advertise_exit_node(&self, enable: bool) -> Result<(), Error> {
        let composed = {
            let mut adv = self.advertise.lock().unwrap_or_else(|p| p.into_inner());
            adv.exit_node = enable;
            compose_advertised_routes(adv.routes.clone(), adv.exit_node)
        };
        self.apply_advertised_routes(composed).await
    }

    /// Push a freshly-composed advertised-route set to BOTH halves: the forwarder's accept/dial
    /// table (local) FIRST — so the node forwards a prefix before control grants it, never the
    /// reverse — then re-advertise `Hostinfo.RoutableIPs` to control on the live map-poll connection
    /// (wire). `composed` is already filtered + exit-node-folded by [`compose_advertised_routes`].
    async fn apply_advertised_routes(&self, composed: Vec<ipnet::IpNet>) -> Result<(), Error> {
        self.forwarder
            .ask(forwarder_actor::UpdateRoutes {
                routes: composed.clone(),
            })
            .await?;
        self.control
            .ask(control_runner::SetAdvertiseRoutes { routes: composed })
            .await
            .map_err(Into::into)
    }

    /// Change this node's hostname at runtime (Go `tailscale set --hostname`), re-reporting
    /// `Hostinfo.Hostname` to control on the live map-poll connection. Hostname is display-only
    /// (control reflects it in the netmap), so there is no dataplane half. The new value is also
    /// what a subsequent re-registration reports, so it persists across a reconnect.
    pub async fn set_hostname(&self, hostname: String) -> Result<(), Error> {
        self.control
            .ask(control_runner::SetHostname { hostname })
            .await
            .map_err(Into::into)
    }

    /// Subscribe to netmap peer-change events: the **narrow** peer-set view.
    ///
    /// Returns a [`watch::Receiver`] whose value is the current set of peer [`StatusNode`]s,
    /// updated on every netmap state update from control. Await
    /// [`watch::Receiver::changed`](tokio::sync::watch::Receiver::changed) to react to peers
    /// joining, leaving, or changing. For the unified Go-`WatchIPNBus` feed that merges this with
    /// device-state and the interactive-login URL, see [`watch_ipn_bus`](Self::watch_ipn_bus); this
    /// method is the peer-only projection of the same underlying cell.
    pub async fn watch_netmap(&self) -> Result<watch::Receiver<Vec<StatusNode>>, Error> {
        self.peer_tracker
            .upgrade()
            .ok_or(Error {
                kind: ErrorKind::ActorGone,
                target_actor: None,
                message_ty: None,
            })?
            .ask(peer_tracker::WatchNetmap)
            .await
            .map_err(Into::into)
    }

    /// The current device connection-[`DeviceState`].
    pub fn device_state(&self) -> DeviceState {
        self.state_rx.borrow().clone()
    }

    /// Watch the device connection-[`DeviceState`] (`Connecting` → `Running` / `NeedsLogin` /
    /// `Expired` / `Failed`).
    ///
    /// Returns a [`watch::Receiver`]; await
    /// [`changed`](tokio::sync::watch::Receiver::changed) to react push-style to control connection
    /// transitions instead of polling [`status`](Self::status). The initial value is the current
    /// state. Note: a transient per-reconnect dip back to `Connecting` is **not** currently
    /// emitted (control transparently reconnects below this layer); the state reflects registration
    /// outcome and node-key expiry.
    pub fn watch_state(&self) -> watch::Receiver<DeviceState> {
        self.state_rx.clone()
    }

    /// Wait until the device finishes registering, returning a typed outcome.
    ///
    /// Resolves `Ok(())` once the device reaches [`DeviceState::Running`]. Returns a typed
    /// [`RegistrationError`] otherwise — the actionable distinction between "retry", "re-pair", and
    /// "drive interactive login" that replaces polling the device's `ipv4_addr` in a loop:
    /// - `AuthRejected` — bad/expired/unknown auth key. **Permanent** (re-pair).
    /// - `NeedsLogin(url)` — interactive authorization required (no usable auth key). **Not
    ///   permanent**: the runtime keeps retrying and will reach `Running` once the user authorizes
    ///   the URL. An **auth-key** caller should treat this as a failure; an **interactive** caller
    ///   should ignore this return and instead drive the flow via [`watch_state`](Self::watch_state)
    ///   (this method returns the URL eagerly rather than blocking for the whole login).
    /// - `NetworkUnreachable` — control unreachable. **Transient** (retry).
    /// - `Timeout` — no settled state within `timeout`.
    ///
    /// `KeyExpired` is not produced by this initial wait (a node key expires only *after* it has
    /// come up); observe post-registration expiry via [`watch_state`](Self::watch_state).
    /// `timeout` of `None` waits indefinitely for a settled state.
    pub async fn wait_until_running(
        &self,
        timeout: Option<Duration>,
    ) -> Result<(), RegistrationError> {
        device_state::wait_for_running(self.state_rx.clone(), timeout).await
    }

    /// Subscribe to the unified IPN notification bus (Go `ipn` `WatchIPNBus` /
    /// `LocalBackend.WatchNotifications`).
    ///
    /// Returns an [`IpnBusWatcher`]; await [`next`](IpnBusWatcher::next) to receive [`Notify`]
    /// events that coalesce device-[`DeviceState`] changes (including the interactive-login URL as
    /// `browse_to_url`) and netmap peer-set changes into one feed. `mask`
    /// ([`NotifyWatchOpt`]) selects which current-state fields are front-loaded as an initial
    /// snapshot on subscribe (`INITIAL_STATE` / `INITIAL_NETMAP`), exactly like Go's
    /// `NotifyInitialState` / `NotifyInitialNetMap`.
    ///
    /// This composes the same `watch` cells as [`watch_state`](Self::watch_state),
    /// [`watch_netmap`](Self::watch_netmap), and `pop_browser_url` — one source of truth, so the
    /// merged feed cannot diverge from those narrow views. Besides the registration-time login URL
    /// (carried by `NeedsLogin`), `browse_to_url` also streams the mid-session
    /// `MapResponse.PopBrowserURL` (re-auth / consent on an already-running node). Delivery is
    /// best-effort/lossy (a bounded per-watcher buffer; a notification is dropped rather than
    /// blocking the runtime if a slow consumer's buffer fills), matching Go's bus. The stream ends
    /// (`next` returns `None`) on runtime shutdown or when the watcher is dropped.
    pub async fn watch_ipn_bus(&self, mask: NotifyWatchOpt) -> Result<IpnBusWatcher, Error> {
        // The peer-set cell lives on the peer-tracker actor; obtain a receiver the same way
        // `watch_netmap` does. State + shutdown cells are held here.
        let peer_rx = self
            .peer_tracker
            .upgrade()
            .ok_or(Error {
                kind: ErrorKind::ActorGone,
                target_actor: None,
                message_ty: None,
            })?
            .ask(peer_tracker::WatchNetmap)
            .await?;
        // The running-node consent-URL cell lives on the control runner; obtain its receiver the
        // same way (the control actor ref is strong, so no upgrade needed).
        let browser_rx = self.control.ask(control_runner::WatchBrowserUrl).await?;
        Ok(ipn_bus::spawn_watcher(
            mask,
            self.state_rx.clone(),
            peer_rx,
            browser_rx,
            self.shutdown.subscribe(),
        ))
    }

    /// Attempt to shut down the runtime gracefully.
    ///
    /// Returns false if the shutdown timed out. It is still shut down if it timed out, just
    /// more violently and with possible resource leaks.
    pub async fn graceful_shutdown(self, timeout: Option<Duration>) -> bool {
        self.shutdown.send_replace(true);

        async fn _shutdown_all(runtime: Runtime) {
            // See the note in `Drop` for why we only need to stop these actors to bring down the
            // whole runtime.

            let _ignore = runtime.control.stop_gracefully().await;
            let _ignore = runtime.dataplane.stop_gracefully().await;
            let _ignore = runtime.env.bus.stop_gracefully().await;

            tokio::join![
                runtime.control.wait_for_shutdown(),
                runtime.dataplane.wait_for_shutdown(),
                runtime.env.bus.wait_for_shutdown(),
            ];
        }

        let fut = _shutdown_all(self);

        match timeout {
            Some(timeout) => tokio::time::timeout(timeout, fut).await.is_ok(),
            None => {
                fut.await;
                true
            }
        }
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        // Stop the taildrop reaper so it cannot outlive the runtime (the `reauth_bridge` pattern). It
        // also self-exits when `shutdown` flips below, but aborting is immediate and covers the
        // already-shutdown early-return path too.
        if let Some(reaper) = self.taildrop_reaper.take() {
            reaper.abort();
        }

        // We must have already run `graceful_shutdown`: on the happy path, this does nothing, but
        // if it timed out, we need to make sure the actors are dead so we don't leak them and their
        // dependents.
        if *self.shutdown.borrow() {
            self.control.kill();
            self.dataplane.kill();
            self.env.bus.kill();
            return;
        }

        self.shutdown.send_replace(true);

        // Actors shut down when the last ActorRef to them is dropped (as nothing can send them
        // messages anymore). If we don't hold an ActorRef in Runtime, in general the only thing
        // that has one is the MessageBus, which each actor subscribes to for a subset of messages.
        // Hence, if we shut down the bus, most actors die as well.

        // First shut down the actors we have an ActorRef to:
        try_shutdown(&self.control);
        try_shutdown(&self.dataplane);

        // Then shutdown the message bus, stopping the rest of the actors:
        try_shutdown(&self.env.bus);
    }
}

fn try_shutdown(a: &ActorRef<impl kameo::Actor>) {
    if let Err(e) = a.mailbox_sender().try_send(Signal::Stop) {
        tracing::error!(error = %e, "graceful shutdown failed, killing actor");
        a.kill();
    }
}

/// Tailscale's overlay MTU. The userspace netstacks MUST advertise an MSS that fits this so they
/// never hand the WireGuard encrypt path an IP packet larger than the tunnel can carry (the netstack
/// has no PMTU discovery and nothing re-segments between it and the 1280-MTU TUN). This is the same
/// default the TUN device uses (`tun_config_from_control`); both are derived from this value so the
/// netstack and the TUN always agree.
///
/// This is the **inner** IP-packet budget. The WireGuard transport header (a 16-byte
/// `TransportDataHeader` + the 16-byte AEAD tag = 32 bytes) is added by `TransmitSession::encrypt`
/// *after* the netstack produces the inner packet, and the outer UDP/IP headers ride on top of that.
/// So do NOT subtract the WireGuard overhead here — that would be a double-subtraction that
/// under-fills the tunnel and diverges from the TUN's MTU. The assert below documents that the outer
/// datagram still fits a conventional 1500-byte physical path with margin (1280 + 32 WG + 8 UDP +
/// 20 outer-IP = 1340).
const DEFAULT_OVERLAY_MTU: u16 = 1280;

const _: () = assert!(
    DEFAULT_OVERLAY_MTU as usize + 32 + 8 + 20 <= 1500,
    "inner overlay MTU + WireGuard(32) + UDP(8) + outer-IP(20) must fit a 1500-byte physical path"
);

/// Build the netstack config shared by both userspace netstacks (application + forwarder) from the
/// per-deployment `tcp_buffer_size` and `mtu` knobs.
///
/// `tcp_buffer_size`: `None` keeps the netstack default (256 KiB/direction); `Some(n)` overrides it
/// (e.g. a smaller window on a memory-constrained exit node forwarding many concurrent flows — see
/// [`netstack::netcore::Config::tcp_buffer_size`]).
///
/// `mtu`: the overlay/tunnel MTU. `None` (and a stray `0`) falls back to [`DEFAULT_OVERLAY_MTU`]
/// (1280), exactly as the TUN device does, so the netstack's advertised MSS fits the tunnel. Leaving
/// this at the netstack's generic 1500 default (the prior behavior) made smoltcp advertise MSS ~1460
/// and segment to ~1500 B, which then overflowed the 1280 TUN — a PMTU black-hole / throughput cliff.
///
/// Factored out of [`Runtime::spawn`] so the mapping is unit-testable without standing up the actors.
fn netstack_config_from(
    tcp_buffer_size: Option<usize>,
    mtu: Option<u16>,
) -> netstack::netcore::Config {
    let mut c = netstack::netcore::Config::default();
    if let Some(tcp_buffer_size) = tcp_buffer_size {
        c.tcp_buffer_size = tcp_buffer_size;
    }
    // `0` is not a usable MTU; treat it like `None` and fall back to the overlay default, mirroring
    // the TUN's `and_then(NonZeroU16::new).unwrap_or(1280)`.
    let mtu = mtu.filter(|&m| m != 0).unwrap_or(DEFAULT_OVERLAY_MTU);
    c.mtu = usize::from(mtu);
    c
}

/// Filter a requested advertise-route set to the IPv4-only, deduplicated set this fork can honor,
/// mirroring [`ts_control::Config::advertised_routes`] so a runtime `set_advertise_routes` feeds the
/// wire (control grant) and the forwarder (accept/dial table) the identical final set. IPv6 prefixes
/// are dropped under the IPv6-off posture — we never advertise a route we won't forward. Order is
/// preserved (first occurrence wins). Factored out so the filter is unit-testable without an actor.
fn filter_advertise_routes(routes: Vec<ipnet::IpNet>) -> Vec<ipnet::IpNet> {
    let mut filtered: Vec<ipnet::IpNet> = Vec::new();
    for net in routes {
        if matches!(net, ipnet::IpNet::V4(_)) {
            if !filtered.contains(&net) {
                filtered.push(net);
            }
        } else {
            tracing::warn!(prefix = %net, "dropping IPv6 advertise route (IPv6-off posture)");
        }
    }
    filtered
}

/// Compose the final advertised-route set from the explicit subnet `routes` and the exit-node flag,
/// mirroring [`ts_control::Config::advertised_routes`]: the IPv4-only, deduplicated subnet prefixes,
/// plus `0.0.0.0/0` appended when `exit_node` is set. This is the single source of truth both
/// runtime advertise mutators (`set_advertise_routes`, `set_advertise_exit_node`) feed, so the two
/// compose instead of clobbering. Factored out so the composition is unit-testable without an actor.
fn compose_advertised_routes(routes: Vec<ipnet::IpNet>, exit_node: bool) -> Vec<ipnet::IpNet> {
    let mut filtered = filter_advertise_routes(routes);
    if exit_node {
        let default_v4 = ipnet::IpNet::V4(
            ipnet::Ipv4Net::new(core::net::Ipv4Addr::UNSPECIFIED, 0)
                .expect("0.0.0.0/0 is a valid prefix"),
        );
        if !filtered.contains(&default_v4) {
            filtered.push(default_v4);
        }
    }
    filtered
}

/// The runtime's live advertised-route preference: the explicit subnet routes plus whether this node
/// advertises itself as an exit node. Held behind a `Mutex` on the [`Runtime`] so
/// [`Runtime::set_advertise_routes`] and [`Runtime::set_advertise_exit_node`] each mutate their own
/// part and re-send the composed set — they compose rather than clobber (Go `EditPrefs` keeps
/// `AdvertiseRoutes` and the exit-node advertisement as independent prefs that both feed
/// `Hostinfo.RoutableIPs`).
#[derive(Debug, Default, Clone)]
struct AdvertiseState {
    /// The explicit subnet prefixes (pre-filter; the last value passed to `set_advertise_routes`).
    routes: Vec<ipnet::IpNet>,
    /// Whether this node advertises the exit-node default route (`0.0.0.0/0`).
    exit_node: bool,
}

/// Flatten a kameo delegated-reply [`SendError`] for the id-token RPC into the RPC's own
/// [`ts_control::IdTokenError`].
///
/// A [`SendError::HandlerError`](kameo::error::SendError::HandlerError) carries the real
/// `IdTokenError` produced by the handler and is surfaced verbatim. Any other send failure (actor
/// not running / stopped, mailbox full, send timeout) is a delivery problem rather than an RPC
/// result, so it collapses to a transient [`ts_control::IdTokenError::NetworkError`]. Factored out
/// of [`Runtime::fetch_id_token`] so this mapping is unit-testable without standing up an actor.
fn flatten_send_err<M>(
    e: kameo::error::SendError<M, ts_control::IdTokenError>,
) -> ts_control::IdTokenError {
    match e {
        kameo::error::SendError::HandlerError(err) => err,
        _ => ts_control::IdTokenError::NetworkError,
    }
}

/// Flatten a kameo `SendError` from the `Logout` ask into a [`ts_control::LogoutError`].
///
/// A `HandlerError` carries the real `LogoutError` from the control RPC and is surfaced verbatim;
/// any other send failure (actor not running / stopped, mailbox full, send timeout) — a delivery
/// problem, not a logout result — collapses to the transient [`ts_control::LogoutError::NetworkError`]
/// (logout is idempotent, so a retry after a delivery failure is safe). Factored out of
/// [`Runtime::logout`] so the mapping is unit-testable without standing up an actor.
fn flatten_logout_send_err<M>(
    e: kameo::error::SendError<M, ts_control::LogoutError>,
) -> ts_control::LogoutError {
    match e {
        kameo::error::SendError::HandlerError(err) => err,
        _ => ts_control::LogoutError::NetworkError,
    }
}

/// Flatten a kameo `SendError` from the `SetDns` ask into a [`ts_control::SetDnsError`].
///
/// A `HandlerError` carries the real `SetDnsError` from the set-dns RPC and is surfaced verbatim;
/// any other send failure (actor not running / stopped, mailbox full, send timeout) — a delivery
/// problem, not a publish result — collapses to the transient
/// [`ts_control::SetDnsError::NetworkError`]. Factored out of [`Runtime::set_dns`] so the mapping is
/// unit-testable without standing up an actor.
fn flatten_set_dns_send_err<M>(
    e: kameo::error::SendError<M, ts_control::SetDnsError>,
) -> ts_control::SetDnsError {
    match e {
        kameo::error::SendError::HandlerError(err) => err,
        _ => ts_control::SetDnsError::NetworkError,
    }
}

/// Flatten a kameo `SendError` from a TKA mutation ask (`TkaSign`/`TkaDisable`) into a
/// [`ts_control::TkaSyncError`]. A `HandlerError` carries the real RPC error; any other send failure
/// (actor shutdown / mailbox closed) is surfaced as the transient
/// [`ts_control::TkaSyncError::NetworkError`]. Generic over the message type so both share it.
fn flatten_tka_send_err<M>(
    e: kameo::error::SendError<M, ts_control::TkaSyncError>,
) -> ts_control::TkaSyncError {
    match e {
        kameo::error::SendError::HandlerError(err) => err,
        _ => ts_control::TkaSyncError::NetworkError,
    }
}

/// Flatten a kameo `SendError` from the `GetCertificate` / `GetCertPair` ask into a
/// [`ts_control::CertError`].
///
/// A `HandlerError` carries the real `CertError` produced by the ACME issuance and is surfaced
/// verbatim. `CertError` has no transient-network variant, so any other send failure (actor not
/// running / stopped, mailbox full, send timeout) — a delivery problem rather than an issuance
/// result — collapses to a [`ts_control::CertError::Io`]. Generic over the message type, so it
/// serves both [`Runtime::get_certificate`] and [`Runtime::cert_pair`]; factored out so the mapping
/// is unit-testable without standing up an actor.
#[cfg(feature = "acme")]
fn flatten_cert_send_err<M>(
    e: kameo::error::SendError<M, ts_control::CertError>,
) -> ts_control::CertError {
    match e {
        kameo::error::SendError::HandlerError(err) => err,
        _ => ts_control::CertError::Io(std::io::Error::other(
            "control runner unavailable for certificate issuance",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `None` must leave the netstack's own default TCP window in place (the 256 KiB throughput
    /// default), and must not silently coerce to some other value.
    #[test]
    fn netstack_config_none_uses_netstack_default() {
        let default = netstack::netcore::Config::default();
        let built = netstack_config_from(None, None);
        assert_eq!(
            built.tcp_buffer_size, default.tcp_buffer_size,
            "None must inherit the netstack default TCP buffer size"
        );
    }

    #[test]
    fn netstack_config_mtu_defaults_to_overlay_not_generic_1500() {
        // The crux of the fix: with no explicit MTU, the netstack must use the 1280 overlay MTU, NOT
        // smoltcp's generic 1500 default — otherwise it advertises an MSS that overflows the tunnel.
        let built = netstack_config_from(None, None);
        assert_eq!(
            built.mtu,
            usize::from(DEFAULT_OVERLAY_MTU),
            "netstack MTU must default to the 1280 overlay MTU, not the 1500 netstack default"
        );
        assert_ne!(built.mtu, 1500, "must not leave the generic 1500 default");
    }

    #[test]
    fn netstack_config_honors_explicit_mtu_and_rejects_zero() {
        // An explicit (control-supplied) MTU is honored verbatim.
        assert_eq!(netstack_config_from(None, Some(1400)).mtu, 1400);
        // A stray 0 is not a usable MTU; fall back to the overlay default (mirrors the TUN).
        assert_eq!(
            netstack_config_from(None, Some(0)).mtu,
            usize::from(DEFAULT_OVERLAY_MTU)
        );
    }

    #[test]
    fn netstack_config_overlay_mtu_matches_tun_default() {
        // The netstack MTU default and the TUN MTU default must be the same value, or the two
        // netstacks and the TUN would disagree on the segment size budget.
        assert_eq!(
            DEFAULT_OVERLAY_MTU, 1280,
            "overlay MTU must match the TUN device default (tun_config_from_control)"
        );
    }

    /// `Some(n)` must override the TCP window (the memory-vs-throughput knob exit-node operators
    /// reach for), reaching the config that both netstacks are built from.
    #[test]
    fn netstack_config_some_overrides_buffer() {
        let built = netstack_config_from(Some(64 * 1024), None);
        assert_eq!(
            built.tcp_buffer_size,
            64 * 1024,
            "Some(n) must override the TCP buffer size that both netstacks use"
        );
    }

    /// `set_advertise_routes` must feed the wire and the forwarder the IDENTICAL filtered set:
    /// IPv4-only (IPv6 dropped under the IPv6-off posture), deduplicated, order preserved.
    #[test]
    fn filter_advertise_routes_keeps_v4_dedups_drops_v6() {
        let v4a: ipnet::IpNet = "10.0.0.0/24".parse().unwrap();
        let v4b: ipnet::IpNet = "192.168.1.0/24".parse().unwrap();
        let v6: ipnet::IpNet = "2001:db8::/32".parse().unwrap();

        // Mixed input with a duplicate v4 and a v6 prefix.
        let out = filter_advertise_routes(vec![v4a, v6, v4b, v4a]);

        assert_eq!(
            out,
            vec![v4a, v4b],
            "v6 dropped, duplicate v4 collapsed, first-occurrence order preserved"
        );
    }

    /// An all-IPv6 request filters to empty (we never advertise a route we won't forward) rather
    /// than erroring — clearing the advertised set is a legitimate outcome.
    #[test]
    fn filter_advertise_routes_all_v6_is_empty() {
        let v6: ipnet::IpNet = "2001:db8::/32".parse().unwrap();
        assert!(filter_advertise_routes(vec![v6]).is_empty());
    }

    /// `compose_advertised_routes` folds the exit-node `0.0.0.0/0` onto the filtered subnet routes
    /// when (and only when) the exit-node flag is set — so `set_advertise_routes` and
    /// `set_advertise_exit_node` compose. The two preferences are independent.
    #[test]
    fn compose_advertised_routes_folds_exit_node() {
        let subnet: ipnet::IpNet = "10.0.0.0/24".parse().unwrap();
        let default_v4: ipnet::IpNet = "0.0.0.0/0".parse().unwrap();

        // Exit node off: just the (filtered) subnet routes.
        assert_eq!(
            compose_advertised_routes(vec![subnet], false),
            vec![subnet],
            "exit-node off ⇒ no default route"
        );
        // Exit node on: subnet routes PLUS 0.0.0.0/0.
        assert_eq!(
            compose_advertised_routes(vec![subnet], true),
            vec![subnet, default_v4],
            "exit-node on ⇒ 0.0.0.0/0 appended"
        );
        // Exit node on with NO subnet routes: just the default route.
        assert_eq!(
            compose_advertised_routes(vec![], true),
            vec![default_v4],
            "exit-node alone advertises only 0.0.0.0/0"
        );
        // Idempotent: an explicit 0.0.0.0/0 already in the routes isn't duplicated by the fold.
        assert_eq!(
            compose_advertised_routes(vec![default_v4], true),
            vec![default_v4],
            "the exit-node fold dedups against an explicit default route"
        );
    }

    /// A `HandlerError` carries the real `IdTokenError` from the RPC handler and must pass through
    /// verbatim, not be flattened to a generic network error. Using an `Internal(_)` payload (not
    /// `NetworkError`) makes the passthrough observable: a buggy flatten that always returned
    /// `NetworkError` would fail this assertion.
    #[test]
    fn flatten_send_err_handler_error_passes_through() {
        // Build an `Internal(_)` payload via the public `From<Utf8Error>` conversion (no extra
        // deps): it is distinct from the `_ => NetworkError` fallback, so a buggy flatten that
        // always returned `NetworkError` would fail this assertion.
        // Route the invalid bytes through a runtime Vec so the `invalid_from_utf8` lint (which only
        // fires on compile-time-known literals) doesn't flag this intentional bad input.
        let bytes = vec![0xffu8, 0xfe];
        let utf8_err = core::str::from_utf8(&bytes).unwrap_err();
        let inner = ts_control::IdTokenError::from(utf8_err);
        assert!(matches!(inner, ts_control::IdTokenError::Internal(_)));
        let e: kameo::error::SendError<control_runner::FetchIdToken, ts_control::IdTokenError> =
            kameo::error::SendError::HandlerError(inner.clone());
        assert_eq!(flatten_send_err(e), inner);
    }

    /// A non-handler send failure (actor stopped) is a delivery problem, not an RPC result, so it
    /// must collapse to a transient `NetworkError`.
    #[test]
    fn flatten_send_err_actor_stopped_is_network_error() {
        let e: kameo::error::SendError<control_runner::FetchIdToken, ts_control::IdTokenError> =
            kameo::error::SendError::ActorStopped;
        assert_eq!(flatten_send_err(e), ts_control::IdTokenError::NetworkError);
    }

    /// `ActorNotRunning` (the message bounces back undelivered) is likewise a delivery failure and
    /// must map to a transient `NetworkError`.
    #[test]
    fn flatten_send_err_actor_not_running_is_network_error() {
        let e: kameo::error::SendError<control_runner::FetchIdToken, ts_control::IdTokenError> =
            kameo::error::SendError::ActorNotRunning(control_runner::FetchIdToken {
                audience: "sts.amazonaws.com".to_string(),
            });
        assert_eq!(flatten_send_err(e), ts_control::IdTokenError::NetworkError);
    }

    /// A `HandlerError` from the logout RPC carries the real `LogoutError` and must pass through
    /// verbatim. An `Internal(_)` payload (distinct from the `_ => NetworkError` fallback) makes the
    /// passthrough observable.
    #[test]
    fn flatten_logout_send_err_handler_error_passes_through() {
        let inner = ts_control::LogoutError::Internal(ts_control::LogoutInternalErrorKind::Http);
        assert!(matches!(inner, ts_control::LogoutError::Internal(_)));
        let e: kameo::error::SendError<control_runner::Logout, ts_control::LogoutError> =
            kameo::error::SendError::HandlerError(inner.clone());
        assert_eq!(flatten_logout_send_err(e), inner);
    }

    /// A non-handler send failure (actor stopped) is a delivery problem, not a logout result, and
    /// collapses to a transient `NetworkError` (logout is idempotent, so a retry is safe).
    #[test]
    fn flatten_logout_send_err_actor_stopped_is_network_error() {
        let e: kameo::error::SendError<control_runner::Logout, ts_control::LogoutError> =
            kameo::error::SendError::ActorStopped;
        assert_eq!(
            flatten_logout_send_err(e),
            ts_control::LogoutError::NetworkError
        );
    }

    /// A `HandlerError` from the set-dns RPC carries the real `SetDnsError` and must pass through
    /// verbatim. An `Internal(_)` payload (distinct from the `_ => NetworkError` fallback) makes the
    /// passthrough observable.
    #[test]
    fn flatten_set_dns_send_err_handler_error_passes_through() {
        let inner = ts_control::SetDnsError::Internal(ts_control::SetDnsInternalErrorKind::Http);
        assert!(matches!(inner, ts_control::SetDnsError::Internal(_)));
        let e: kameo::error::SendError<control_runner::SetDns, ts_control::SetDnsError> =
            kameo::error::SendError::HandlerError(inner.clone());
        assert_eq!(flatten_set_dns_send_err(e), inner);
    }

    /// A non-handler send failure (actor stopped) is a delivery problem, not a publish result, and
    /// collapses to a transient `NetworkError`.
    #[test]
    fn flatten_set_dns_send_err_actor_stopped_is_network_error() {
        let e: kameo::error::SendError<control_runner::SetDns, ts_control::SetDnsError> =
            kameo::error::SendError::ActorStopped;
        assert_eq!(
            flatten_set_dns_send_err(e),
            ts_control::SetDnsError::NetworkError
        );
    }

    /// A `HandlerError` from a TKA mutation RPC carries the real `TkaSyncError` and must pass through
    /// verbatim (an `Unsupported` payload makes the passthrough observable, distinct from the
    /// `_ => NetworkError` fallback).
    #[test]
    fn flatten_tka_send_err_handler_error_passes_through() {
        let e: kameo::error::SendError<control_runner::TkaSign, ts_control::TkaSyncError> =
            kameo::error::SendError::HandlerError(ts_control::TkaSyncError::Unsupported);
        assert_eq!(
            flatten_tka_send_err(e),
            ts_control::TkaSyncError::Unsupported
        );
    }

    /// A non-handler send failure (actor stopped) collapses to a transient `NetworkError`.
    #[test]
    fn flatten_tka_send_err_actor_stopped_is_network_error() {
        let e: kameo::error::SendError<control_runner::TkaSign, ts_control::TkaSyncError> =
            kameo::error::SendError::ActorStopped;
        assert_eq!(
            flatten_tka_send_err(e),
            ts_control::TkaSyncError::NetworkError
        );
    }

    /// The same flatten works for the `TkaDisable` message type (the helper is generic over `M`).
    #[test]
    fn flatten_tka_send_err_works_for_disable() {
        let e: kameo::error::SendError<control_runner::TkaDisable, ts_control::TkaSyncError> =
            kameo::error::SendError::HandlerError(ts_control::TkaSyncError::Unsupported);
        assert_eq!(
            flatten_tka_send_err(e),
            ts_control::TkaSyncError::Unsupported
        );
    }
}
