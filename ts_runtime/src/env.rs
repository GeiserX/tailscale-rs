use std::sync::Arc;

use kameo::{
    actor::{ActorRef, Spawn},
    message::Message,
};
use kameo_actors::message_bus::{MessageBus, Publish, Register};
use tokio::sync::watch;

use crate::{Error, error::ResultExt};

/// The forwarding / routing preferences that flow from [`ts_control::Config`] into the runtime's
/// dataplane actors, grouped into one named-field struct.
///
/// These are pure client-side dataplane preferences: `ts_control` does not read them (control
/// always sends the full advertised route set; the runtime trims and forwards). Grouping them
/// here removes the positional-argument hazard of the old `Env::new` — in particular the two
/// adjacent `bool`s [`forward_all_ports`](ForwarderConfig::forward_all_ports) and
/// [`forward_exit_egress`](ForwarderConfig::forward_exit_egress), which a positional constructor
/// could silently swap. Named fields make a swap a compile error.
#[derive(Clone)]
pub struct ForwarderConfig {
    /// Whether to accept subnet routes advertised by peers (`--accept-routes` / `RouteAll`).
    ///
    /// Fixed for the life of the runtime. Consulted by the route updater (outbound routing) and
    /// the source filter (inbound source validation), which must agree so a peer can only source
    /// traffic from subnets we actually route to it.
    pub accept_routes: bool,

    /// Which peer (if any) is selected as this node's exit node (`ExitNodeID`).
    ///
    /// Fixed for the life of the runtime, but the selector is *unresolved*: the route updater and
    /// the source filter each call [`ExitNodeSelector::resolve`](ts_control::ExitNodeSelector::resolve)
    /// against the live peer set on every rebuild, so an IP/name selection follows the peer across
    /// netmap changes. Because `resolve` is deterministic, both actors resolve to the same stable
    /// id and stay coupled: only the selected exit peer gets a default route installed (outbound)
    /// and may legitimately source arbitrary internet IPs (inbound). `None` (or an unresolvable
    /// selector) means no exit node — internet-bound traffic is dropped (fail-closed).
    pub exit_node: Option<ts_control::ExitNodeSelector>,

    /// The set of prefixes the inbound forwarder accepts and dials to real OS sockets.
    ///
    /// This is exactly [`Config::advertised_routes`](ts_control::Config::advertised_routes): we
    /// forward precisely what we advertise (advertise == forward), so there is no prefix we
    /// advertise but won't forward (which would be a black hole) and none we forward but didn't
    /// advertise. v4-only (IPv6-off posture). Empty means "subnet-router/exit-node forwarding
    /// disabled" — the forwarder netstack still exists but its route table is empty.
    pub forward_routes: Vec<ipnet::IpNet>,

    /// TCP ports the inbound forwarder splices per advertised route. See
    /// [`Config::forward_tcp_ports`](ts_control::Config::forward_tcp_ports).
    pub forward_tcp_ports: Vec<u16>,

    /// UDP ports the inbound forwarder splices per advertised route. See
    /// [`Config::forward_udp_ports`](ts_control::Config::forward_udp_ports).
    pub forward_udp_ports: Vec<u16>,

    /// Whether the inbound forwarder forwards **all** TCP/UDP ports per advertised route.
    ///
    /// When `true`, the explicit [`forward_tcp_ports`](ForwarderConfig::forward_tcp_ports) /
    /// [`forward_udp_ports`](ForwarderConfig::forward_udp_ports) sets are ignored and the forwarder
    /// runs in all-port mode (driven by a raw-socket port observer). See
    /// [`Config::forward_all_ports`](ts_control::Config::forward_all_ports).
    pub forward_all_ports: bool,

    /// Whether exit-node (`0.0.0.0/0`) inbound flows are egressed via this host's real origin IP.
    ///
    /// Anti-leak opt-in. When `false` (the default, fail-closed), the forwarder is wired with a
    /// dialer that structurally refuses exit-node egress, so a `0.0.0.0/0` flow is dropped at dial
    /// time rather than leaking out our real IP. See
    /// [`Config::forward_exit_egress`](ts_control::Config::forward_exit_egress).
    pub forward_exit_egress: bool,

    /// Shields-up: when `true`, the packet-filter updater wraps the live filter so inbound packets
    /// destined to this node's own addresses are dropped (refuse inbound peer connections).
    /// See [`Config::block_incoming`](ts_control::Config::block_incoming).
    pub block_incoming: bool,

    /// Optional upstream proxy that exit-node egress is routed through (product capability beyond
    /// strict tsnet parity — residential-proxy egress).
    ///
    /// Only consulted when [`forward_exit_egress`](ForwarderConfig::forward_exit_egress) is `true`.
    /// When `Some`, the forwarder is wired with a [`ProxyExitDialer`](ts_forwarder::ProxyExitDialer)
    /// that tunnels exit-node flows through the proxy and **fails closed** (never falls back to a
    /// direct host-IP dial). When `None`, exit egress (if enabled) uses this host's real IP. This is
    /// already the `ts_forwarder` type: the conversion from the transport-only
    /// [`ts_control::ExitProxyConfig`] happens in [`from_control_config`](ForwarderConfig::from_control_config),
    /// since `ts_control` must not depend on `ts_forwarder`.
    pub exit_proxy: Option<ts_forwarder::ProxyConfig>,

    /// The IPv4 peerAPI port this node binds to serve exit-node DoH (`/dns-query`) to peers, if any.
    ///
    /// See [`Config::peerapi_port`](ts_control::Config::peerapi_port). `None` (the default) means
    /// this node advertises no peerAPI service and runs no DoH server — peers can't use it as a DNS
    /// proxy. The same value is advertised (`PeerApi4` service) and used to bind the server, so the
    /// advertised port always matches the actual bind.
    pub peerapi_port: Option<u16>,

    /// Filesystem directory received Taildrop files land in, or `None` to disable Taildrop.
    ///
    /// See [`Config::taildrop_dir`](ts_control::Config::taildrop_dir). When `Some`, the runtime
    /// constructs the [`TaildropStore`](crate::taildrop::TaildropStore) from it; the store is then
    /// served on the shared peerAPI listener (only if [`peerapi_port`](ForwarderConfig::peerapi_port)
    /// is also set) and exposed to the embedder's read APIs. `None` (the default) is fail-closed:
    /// no store, no Taildrop server.
    pub taildrop_dir: Option<std::path::PathBuf>,

    /// Whether IPv6 is enabled on the tailnet overlay. Defaults to `false` (IPv4-only).
    ///
    /// See [`Config::enable_ipv6`](ts_control::Config::enable_ipv6). Governs the underlay socket
    /// bind, disco candidate filtering, netstack overlay-address assignment, and MagicDNS AAAA
    /// handling. It NEVER governs the forwarder exit/subnet egress path, which stays IPv4-only
    /// regardless to uphold the real-origin-IP isolation invariant.
    pub enable_ipv6: bool,

    /// The WireGuard persistent-keepalive interval applied to every peer, or `None` to disable.
    ///
    /// See [`Config::persistent_keepalive_interval`](ts_control::Config::persistent_keepalive_interval).
    /// Threaded into the dataplane actor, which sets it on every upserted
    /// [`ts_tunnel::PeerConfig`] so an idle (typically DERP-relayed) session keeps its path warm and
    /// doesn't age out and wedge the next dial.
    pub persistent_keepalive_interval: Option<std::time::Duration>,

    /// The shared "Funnel ingress listener active" flag, the same `Arc` as
    /// [`Config::ingress_active`](ts_control::Config::ingress_active).
    ///
    /// `Device::listen_funnel` flips this `true` when its listener starts (and the dropped manager
    /// flips it back `false`); the control session reads it on each map request to set
    /// `HostInfo.IngressEnabled`. Cloned from the control config at `from_control_config` so the
    /// runtime and `ts_control` share one flag.
    pub ingress_active: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl ForwarderConfig {
    /// Extract the runtime's forwarding preferences from a [`ts_control::Config`].
    ///
    /// `ts_control::Config` carries these dataplane fields for transport only (it never reads
    /// them); this is the boundary where they are grouped for the runtime.
    pub fn from_control_config(config: &ts_control::Config) -> Self {
        Self {
            accept_routes: config.accept_routes,
            exit_node: config.exit_node.clone(),
            forward_routes: config.advertised_routes(),
            forward_tcp_ports: config.forward_tcp_ports.clone(),
            forward_udp_ports: config.forward_udp_ports.clone(),
            forward_all_ports: config.forward_all_ports,
            forward_exit_egress: config.forward_exit_egress,
            block_incoming: config.block_incoming,
            exit_proxy: config.exit_proxy.as_ref().map(exit_proxy_to_forwarder),
            peerapi_port: config.peerapi_port,
            taildrop_dir: config.taildrop_dir.clone(),
            enable_ipv6: config.enable_ipv6,
            persistent_keepalive_interval: config.persistent_keepalive_interval,
            ingress_active: config.ingress_active.clone(),
        }
    }
}

/// Convert the transport-only [`ts_control::ExitProxyConfig`] into the [`ts_forwarder::ProxyConfig`]
/// the dialer consumes. This boundary exists because `ts_control` must not depend on `ts_forwarder`
/// (they are independent crates joined only here in `ts_runtime`).
fn exit_proxy_to_forwarder(cfg: &ts_control::ExitProxyConfig) -> ts_forwarder::ProxyConfig {
    ts_forwarder::ProxyConfig {
        addr: cfg.addr,
        scheme: match cfg.scheme {
            ts_control::ExitProxyScheme::Socks5 => ts_forwarder::ProxyScheme::Socks5,
            ts_control::ExitProxyScheme::HttpConnect => ts_forwarder::ProxyScheme::HttpConnect,
        },
        auth: cfg.auth.clone(),
    }
}

#[derive(Clone)]
pub struct Env {
    pub bus: ActorRef<MessageBus>,
    pub keys: Arc<ts_keys::NodeState>,

    /// Whether to accept subnet routes advertised by peers (`--accept-routes` / `RouteAll`).
    ///
    /// See [`ForwarderConfig::accept_routes`].
    pub accept_routes: bool,

    /// Which peer (if any) is selected as this node's exit node (`ExitNodeID`).
    ///
    /// A live cell rather than a snapshot: `Device::set_exit_node` updates the backing
    /// [`watch::Sender`] (held privately on the runtime, not here) at runtime, and both readers
    /// (the route updater and the source filter) re-read it via [`Env::exit_node`](Env::exit_node)
    /// on their next recompute, so the selected exit can change without recreating the device. This
    /// is the readers' contract: `Env` is cloned into many actors, so only the read side lives here
    /// while the mutation capability stays narrowed to the runtime. See [`ForwarderConfig::exit_node`].
    pub exit_node_rx: watch::Receiver<Option<ts_control::ExitNodeSelector>>,

    /// The set of prefixes the inbound forwarder accepts and dials to real OS sockets.
    ///
    /// See [`ForwarderConfig::forward_routes`].
    pub forward_routes: Arc<Vec<ipnet::IpNet>>,

    /// TCP ports the inbound forwarder splices per advertised route. See
    /// [`ForwarderConfig::forward_tcp_ports`].
    pub forward_tcp_ports: Arc<Vec<u16>>,

    /// UDP ports the inbound forwarder splices per advertised route. See
    /// [`ForwarderConfig::forward_udp_ports`].
    pub forward_udp_ports: Arc<Vec<u16>>,

    /// Whether the inbound forwarder forwards **all** TCP/UDP ports per advertised route.
    ///
    /// See [`ForwarderConfig::forward_all_ports`].
    pub forward_all_ports: bool,

    /// Whether exit-node (`0.0.0.0/0`) inbound flows are egressed via this host's real origin IP.
    ///
    /// See [`ForwarderConfig::forward_exit_egress`].
    pub forward_exit_egress: bool,

    /// Shields-up: drop inbound peer connections terminating on this node (read by the
    /// packet-filter updater). See [`ForwarderConfig::block_incoming`].
    pub block_incoming: bool,

    /// Optional upstream proxy that exit-node egress is routed through.
    ///
    /// See [`ForwarderConfig::exit_proxy`].
    pub exit_proxy: Option<ts_forwarder::ProxyConfig>,

    /// The IPv4 peerAPI port this node binds to serve exit-node DoH to peers, if any.
    ///
    /// See [`ForwarderConfig::peerapi_port`].
    pub peerapi_port: Option<u16>,

    /// The Taildrop file store, constructed once at startup when
    /// [`ForwarderConfig::taildrop_dir`] is `Some` (and the on-disk root could be created), else
    /// `None` (Taildrop disabled — fail-closed). Shared (`Arc`) between the peerAPI Taildrop server
    /// (which writes received files) and the embedder's read APIs on the device.
    pub taildrop_store: Option<Arc<crate::taildrop::TaildropStore>>,

    /// Whether IPv6 is enabled on the tailnet overlay (default `false`, IPv4-only).
    ///
    /// See [`ForwarderConfig::enable_ipv6`]. Read by the underlay socket, disco candidate filter,
    /// netstack address assignment, and MagicDNS; never by the forwarder egress path.
    pub enable_ipv6: bool,

    /// The WireGuard persistent-keepalive interval applied to every peer, or `None` to disable.
    ///
    /// See [`ForwarderConfig::persistent_keepalive_interval`]. Read by the dataplane actor when it
    /// upserts peers.
    pub persistent_keepalive_interval: Option<std::time::Duration>,

    /// The shared "Funnel ingress listener active" flag, the same `Arc` as
    /// [`Config::ingress_active`](ts_control::Config::ingress_active).
    ///
    /// `Device::listen_funnel` flips this `true` when its listener starts; the control session reads
    /// it on each map request to set `HostInfo.IngressEnabled`. See [`ForwarderConfig::ingress_active`].
    pub ingress_active: std::sync::Arc<std::sync::atomic::AtomicBool>,

    /// The active Funnel ingress sink, shared (runtime-lifetime) between the peerAPI server and
    /// `Device::listen_funnel`.
    ///
    /// The peerAPI server (spawned at startup, before any `listen_funnel`) holds a clone of this
    /// `Arc` and reads it per connection: when a `FunnelManager` is registered (the embedder called
    /// `Device::listen_funnel`) the slot holds its [`FunnelIngressSink`](crate::funnel::FunnelIngressSink)
    /// and a `POST /v0/ingress` is membership-gated, `101`-hijacked, and pushed to the sink; when
    /// `None` (the default, no funnel listener active) the route fails closed (`404`) without
    /// hijacking. Installing the sink here at `listen_funnel` time makes the route live without
    /// restarting the peerAPI server.
    pub funnel_ingress: crate::funnel::FunnelIngressSlot,

    /// Whether the runtime is shutdown.
    ///
    /// This is provided so that actors can check whether a message send has failed because
    /// the runtime is closing, or if it's because the peer has panicked.
    ///
    /// It's not a bus message because we need a value that is guaranteed to be delivered
    /// to anyone who's interested. The bus is by definition unreliable during shutdown, so
    /// we need this independent mechanism.
    pub shutdown: watch::Receiver<bool>,
}

impl Env {
    /// The currently-selected exit-node selector, re-read live (it can change at runtime via
    /// `Device::set_exit_node`). Callers resolve it against the live peer set each time.
    pub fn exit_node(&self) -> Option<ts_control::ExitNodeSelector> {
        self.exit_node_rx.borrow().clone()
    }

    /// Build an [`Env`] and the exit-node [`watch::Sender`] separately, so the `Sender` (the
    /// mutation capability) can be retained privately by the runtime while only the read side
    /// (`exit_node_rx`) is cloned into the many actors that subscribe to `Env`. The `Sender` is
    /// seeded with [`ForwarderConfig::exit_node`]. The runtime uses this; callers that never mutate
    /// the exit node (e.g. tests) use [`Env::new`], which discards the `Sender`.
    pub fn new_with_exit_tx(
        keys: ts_keys::NodeState,
        shutdown: watch::Receiver<bool>,
        forwarding: ForwarderConfig,
    ) -> (Self, watch::Sender<Option<ts_control::ExitNodeSelector>>) {
        let (exit_node_tx, exit_node_rx) = watch::channel(forwarding.exit_node.clone());

        let ForwarderConfig {
            accept_routes,
            // Already consumed above to seed the `watch` channel; the `Sender` is returned so the
            // runtime can hold it privately, narrowing mutation away from the cloned `Env`.
            exit_node: _,
            forward_routes,
            forward_tcp_ports,
            forward_udp_ports,
            forward_all_ports,
            forward_exit_egress,
            block_incoming,
            exit_proxy,
            peerapi_port,
            taildrop_dir,
            enable_ipv6,
            persistent_keepalive_interval,
            ingress_active,
        } = forwarding;

        // Construct the Taildrop store once when a directory is configured. A construction failure
        // (e.g. the root can't be created) is non-fatal: the store stays `None` (Taildrop disabled,
        // fail-closed) so the runtime still starts, rather than taking it down for a feature the
        // node opted into but whose directory is unusable.
        let taildrop_store = taildrop_dir.and_then(|dir| {
            match crate::taildrop::TaildropStore::new(&dir) {
                Ok(store) => Some(Arc::new(store)),
                Err(e) => {
                    tracing::error!(error = %e, dir = %dir.display(), "taildrop: store init failed; disabled");
                    None
                }
            }
        });

        let env = Self {
            bus: MessageBus::spawn_default(),
            keys: Arc::new(keys),
            shutdown,
            accept_routes,
            exit_node_rx,
            forward_routes: Arc::new(forward_routes),
            forward_tcp_ports: Arc::new(forward_tcp_ports),
            forward_udp_ports: Arc::new(forward_udp_ports),
            forward_all_ports,
            forward_exit_egress,
            block_incoming,
            exit_proxy,
            peerapi_port,
            taildrop_store,
            enable_ipv6,
            persistent_keepalive_interval,
            ingress_active,
            funnel_ingress: Arc::new(std::sync::Mutex::new(None)),
        };

        (env, exit_node_tx)
    }

    /// Build an [`Env`] without retaining the exit-node [`watch::Sender`] — for callers that only
    /// read the exit node and never mutate it (e.g. tests). The selector is still seeded from
    /// [`ForwarderConfig::exit_node`] but becomes immutable since the `Sender` is dropped.
    pub fn new(
        keys: ts_keys::NodeState,
        shutdown: watch::Receiver<bool>,
        forwarding: ForwarderConfig,
    ) -> Self {
        Self::new_with_exit_tx(keys, shutdown, forwarding).0
    }

    pub async fn subscribe<M>(&self, slf: &ActorRef<impl Message<M>>) -> Result<(), Error>
    where
        M: Clone + Send + 'static,
    {
        self.bus
            .tell(Register(slf.clone().recipient::<M>()))
            .await
            .with_actor_info(&self.bus)?;

        Ok(())
    }

    pub async fn publish<M>(&self, msg: M) -> Result<(), Error>
    where
        M: Clone + Send + 'static,
    {
        self.bus
            .tell(Publish(msg))
            .await
            .with_actor_info(&self.bus)?;

        Ok(())
    }
}
