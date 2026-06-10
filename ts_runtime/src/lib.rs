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
mod magic_dns;
mod multiderp;
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
pub use status::{FileTarget, Status, StatusNode, WhoIs};
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
    env: Env,
    shutdown: watch::Sender<bool>,
    /// Sender side of the exit-node selector `watch` cell. Held privately here (not on the cloned
    /// `Env`, which keeps only the read side) so that only `Runtime::set_exit_node` can mutate the
    /// selection; the route updater and source filter re-read it via [`Env::exit_node`].
    exit_node_tx: watch::Sender<Option<ts_control::ExitNodeSelector>>,
    /// Receiver mirroring the *active* (resolved + fail-closed) exit node's stable id, fed by the
    /// route updater. Read by [`Runtime::status`] / [`Runtime::active_exit_node`] to report which
    /// exit node traffic is actually egressing through (vs. the merely-configured selector).
    active_exit_rx: watch::Receiver<Option<ts_control::StableNodeId>>,
    /// Receiver for the device connection-state cell, fed by the control runner. Read by
    /// [`Runtime::watch_state`] and [`Runtime::wait_until_running`].
    state_rx: watch::Receiver<DeviceState>,
}

impl Runtime {
    /// Spawn a new runtime with the given parameters for connecting to a tailnet.
    pub async fn spawn(
        config: ts_control::Config,
        auth_key: Option<String>,
        keys: ts_keys::NodeState,
    ) -> Result<Self, Error> {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // The exit-node selector is a live `watch` cell so `Device::set_exit_node` can change it at
        // runtime. `new_with_exit_tx` returns the `Sender` (mutation capability) separately so it is
        // retained privately on the `Runtime`, while only the `Receiver` (the readers' contract)
        // lives on the cloned `Env`. The initial value comes from `ForwarderConfig.exit_node`.
        let (env, exit_node_tx) = Env::new_with_exit_tx(
            keys,
            shutdown_rx,
            env::ForwarderConfig::from_control_config(&config),
        );

        // Both userspace netstacks (application + forwarder) share one netstack config. Honor the
        // per-deployment TCP buffer knob when set, otherwise fall back to the netstack default.
        let netstack_config = netstack_config_from(config.tcp_buffer_size);

        let dataplane = DataplaneActor::spawn(env.clone());

        let (netstack_id, netstack_up, netstack_down) =
            dataplane.ask(dataplane::NewOverlayTransport).await?;

        // A second overlay transport feeds the dedicated any-IP forwarder netstack. Inbound packets
        // for advertised subnet routes / the exit-node default route are routed here (see
        // `route_updater`), keeping forwarded flows off the application netstack.
        let (forwarder_id, forwarder_up, forwarder_down) =
            dataplane.ask(dataplane::NewOverlayTransport).await?;

        let multiderp = Multiderp::spawn((env.clone(), dataplane.clone()));

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
        packetfilter::PacketfilterUpdater::spawn(env.clone());
        src_filter::SourceFilterUpdater::spawn(env.clone());
        let peer_tracker = PeerTracker::spawn(env.clone()).downgrade();

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
        let (netstack, fallback_tcp) = match &config.transport_mode {
            ts_control::TransportMode::Netstack => {
                let netstack = NetstackActor::spawn((
                    env.clone(),
                    netstack_config,
                    netstack_up,
                    netstack_down,
                ));

                // Fetch the netstack channel while we still hold the strong ActorRef, then spawn
                // the MagicDNS responder on it. Fire-and-forget: like src_filter/route_updater,
                // it's owned by the message bus and isn't stored on `Runtime`.
                let (channel,) = netstack.ask(netstack_actor::GetChannel).await?;
                // The fallback-TCP registry attaches to the application netstack — the same one
                // that carries the embedder's explicit `Device::tcp_listen` sockets — so a
                // fallback handler sees exactly the inbound flows no explicit listener matched.
                let fallback_tcp = fallback_tcp::FallbackTcpManager::new(channel.clone());
                magic_dns::MagicDnsActor::spawn((env.clone(), channel));

                (Some(netstack.downgrade()), Some(fallback_tcp))
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
                    // Host-route gating inputs derived from `Env`: subnet routes are only steered
                    // into the TUN when `--accept-routes` is set, and the host `/0` only when the
                    // embedder configured an exit node. See `tun_actor::host_routes_from_node`.
                    tun_actor::HostRouteGating {
                        accept_routes: env.accept_routes,
                        exit_node_configured: env.exit_node().is_some(),
                    },
                    // Reuse the forwarder netstack's overlay `Channel` for recursive / exit-node-DoH
                    // MagicDNS forwarding in the TUN datapath (TUN mode has no application netstack
                    // Channel of its own). Egresses over the overlay — anti-leak preserved.
                    forwarder_channel.clone(),
                ));

                (None, None)
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

        let control = ControlRunner::spawn(control_runner::Params {
            config,
            auth_key,
            env: env.clone(),
            state_tx,
        });

        Ok(Self {
            control,
            dataplane,
            direct,
            peer_tracker,
            fallback_tcp,
            netstack,
            env,
            shutdown: shutdown_tx,
            exit_node_tx,
            active_exit_rx,
            state_rx,
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

        let peers = self
            .peer_tracker
            .upgrade()
            .ok_or(Error {
                kind: ErrorKind::ActorGone,
                target_actor: None,
                message_ty: None,
            })?
            .ask(peer_tracker::GetStatus)
            .await?;

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
    /// [`fetch_id_token`](Self::fetch_id_token): a handler error carries the real
    /// [`ts_control::LogoutError`]; any other send failure (actor shutdown / mailbox closed) is
    /// surfaced as [`ts_control::LogoutError::NetworkError`].
    pub async fn logout(&self) -> Result<(), ts_control::LogoutError> {
        self.control
            .ask(control_runner::Logout)
            .await
            .map_err(flatten_logout_send_err)
    }

    /// Issue a real Let's Encrypt certificate for this node's MagicDNS `name` (`acme` feature).
    ///
    /// Mirrors [`fetch_id_token`](Self::fetch_id_token): forwards to the control runner, which runs
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

    /// Resolve which node owns a tailnet source address.
    ///
    /// Maps the source IP of `addr` to its owning node. Mirrors tsnet's `LocalClient::WhoIs`.
    /// Returns `None` if no peer holds that tailnet IP. The returned [`WhoIs`] carries no
    /// user/login or capability data in this fork (see the [`status`] module docs).
    pub async fn whois(&self, addr: core::net::SocketAddr) -> Result<Option<WhoIs>, Error> {
        self.peer_tracker
            .upgrade()
            .ok_or(Error {
                kind: ErrorKind::ActorGone,
                target_actor: None,
                message_ty: None,
            })?
            .ask(peer_tracker::Whois { addr })
            .await
            .map_err(Into::into)
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

    /// Subscribe to netmap peer-change events.
    ///
    /// Returns a [`watch::Receiver`] whose value is the current set of peer [`StatusNode`]s,
    /// updated on every netmap state update from control. Mirrors tsnet's `WatchIPNBus`. Await
    /// [`watch::Receiver::changed`](tokio::sync::watch::Receiver::changed) to react to peers
    /// joining, leaving, or changing.
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
    /// "drive interactive login" that replaces polling [`ipv4_addr`](Self::ipv4_addr) in a loop:
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

/// Build the netstack config shared by both userspace netstacks (application + forwarder) from the
/// per-deployment `tcp_buffer_size` knob.
///
/// `None` keeps the netstack default (256 KiB/direction); `Some(n)` overrides it (e.g. a smaller
/// window on a memory-constrained exit node forwarding many concurrent flows — see
/// [`netstack::netcore::Config::tcp_buffer_size`]). Factored out of [`Runtime::spawn`] so the
/// None-default / Some-override mapping is unit-testable without standing up the actor system.
fn netstack_config_from(tcp_buffer_size: Option<usize>) -> netstack::netcore::Config {
    let mut c = netstack::netcore::Config::default();
    if let Some(tcp_buffer_size) = tcp_buffer_size {
        c.tcp_buffer_size = tcp_buffer_size;
    }
    c
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

/// Flatten a kameo `SendError` from the `GetCertificate` ask into a [`ts_control::CertError`].
///
/// A `HandlerError` carries the real `CertError` produced by the ACME issuance and is surfaced
/// verbatim. `CertError` has no transient-network variant, so any other send failure (actor not
/// running / stopped, mailbox full, send timeout) — a delivery problem rather than an issuance
/// result — collapses to a [`ts_control::CertError::Io`]. Factored out of
/// [`Runtime::get_certificate`] so this mapping is unit-testable without standing up an actor.
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
        let built = netstack_config_from(None);
        assert_eq!(
            built.tcp_buffer_size, default.tcp_buffer_size,
            "None must inherit the netstack default TCP buffer size"
        );
    }

    /// `Some(n)` must override the TCP window (the memory-vs-throughput knob exit-node operators
    /// reach for), reaching the config that both netstacks are built from.
    #[test]
    fn netstack_config_some_overrides_buffer() {
        let built = netstack_config_from(Some(64 * 1024));
        assert_eq!(
            built.tcp_buffer_size,
            64 * 1024,
            "Some(n) must override the TCP buffer size that both netstacks use"
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
}
