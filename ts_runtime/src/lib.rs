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

/// Control runner.
pub mod control_runner;
mod dataplane;
mod derp_latency;
mod direct;
mod env;
mod error;
/// Fallback TCP handler registry (`tsnet.Server.RegisterFallbackTCPHandler` parity).
pub mod fallback_tcp;
mod forwarder_actor;
mod magic_dns;
mod multiderp;
mod netstack_actor;
mod packetfilter;
pub mod peer_tracker;
mod peerapi;
mod peerapi_doh;
mod route_updater;
mod src_filter;
/// Netmap status snapshot, WhoIs, and watcher types.
pub mod status;
/// Taildrop peer-to-peer file transfer store.
pub mod taildrop;
#[cfg(feature = "tun")]
mod tun_actor;

pub(crate) use env::Env;
pub use error::{Error, ErrorKind};
pub use status::{Status, StatusNode, WhoIs};

use crate::peer_tracker::PeerTracker;

/// The runtime for a tailscale device.
pub struct Runtime {
    /// Reference to the control actor.
    pub control: ActorRef<ControlRunner>,
    dataplane: ActorRef<DataplaneActor>,
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
}

impl Runtime {
    /// Spawn a new runtime with the given parameters for connecting to a tailnet.
    pub async fn spawn(
        config: ts_control::Config,
        auth_key: Option<String>,
        keys: ts_keys::NodeState,
    ) -> Result<Self, Error> {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let env = Env::new(
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
        let (_forwarder_channel,) = forwarder.ask(forwarder_actor::GetChannel).await?;

        route_updater::RouteUpdater::spawn((
            multiderp.clone(),
            direct.clone(),
            env.clone(),
            netstack_id,
            forwarder_id,
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
                        exit_node_configured: env.exit_node.is_some(),
                    },
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

        let control = ControlRunner::spawn(control_runner::Params {
            config,
            auth_key,
            env: env.clone(),
        });

        Ok(Self {
            control,
            dataplane,
            peer_tracker,
            fallback_tcp,
            netstack,
            env,
            shutdown: shutdown_tx,
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

    /// A snapshot of the local netmap: this node plus every known peer.
    ///
    /// Combines the self node held by the control runner with the peer set held by the peer
    /// tracker. Mirrors tsnet's `LocalClient::Status`.
    ///
    /// `self_node` is `None` until the first netmap update has been received from control. Peer
    /// entries carry no online/user/capability data (see the [`status`] module docs for that gap).
    pub async fn status(&self) -> Result<Status, Error> {
        let self_node = self
            .control
            .ask(control_runner::SelfNode)
            .await?
            .as_ref()
            .map(StatusNode::from_node);

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

        Ok(Status { self_node, peers })
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
}
