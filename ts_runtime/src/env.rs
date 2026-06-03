use std::sync::Arc;

use kameo::{
    actor::{ActorRef, Spawn},
    message::Message,
};
use kameo_actors::message_bus::{MessageBus, Publish, Register};
use tokio::sync::watch;

use crate::{Error, error::ResultExt};

#[derive(Clone)]
pub struct Env {
    pub bus: ActorRef<MessageBus>,
    pub keys: Arc<ts_keys::NodeState>,

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
    pub forward_routes: Arc<Vec<ipnet::IpNet>>,

    /// TCP ports the inbound forwarder splices per advertised route. See
    /// [`Config::forward_tcp_ports`](ts_control::Config::forward_tcp_ports).
    pub forward_tcp_ports: Arc<Vec<u16>>,

    /// UDP ports the inbound forwarder splices per advertised route. See
    /// [`Config::forward_udp_ports`](ts_control::Config::forward_udp_ports).
    pub forward_udp_ports: Arc<Vec<u16>>,

    /// Whether the inbound forwarder forwards **all** TCP/UDP ports per advertised route.
    ///
    /// When `true`, the explicit [`forward_tcp_ports`](Env::forward_tcp_ports) /
    /// [`forward_udp_ports`](Env::forward_udp_ports) sets are ignored and the forwarder runs in
    /// all-port mode (driven by a raw-socket port observer). See
    /// [`Config::forward_all_ports`](ts_control::Config::forward_all_ports).
    pub forward_all_ports: bool,

    /// Whether exit-node (`0.0.0.0/0`) inbound flows are egressed via this host's real origin IP.
    ///
    /// Anti-leak opt-in. When `false` (the default, fail-closed), the forwarder is wired with a
    /// dialer that structurally refuses exit-node egress, so a `0.0.0.0/0` flow is dropped at dial
    /// time rather than leaking out our real IP. See
    /// [`Config::forward_exit_egress`](ts_control::Config::forward_exit_egress).
    pub forward_exit_egress: bool,

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
    pub fn new(
        keys: ts_keys::NodeState,
        shutdown: watch::Receiver<bool>,
        accept_routes: bool,
        exit_node: Option<ts_control::ExitNodeSelector>,
        forward_routes: Vec<ipnet::IpNet>,
        forward_tcp_ports: Vec<u16>,
        forward_udp_ports: Vec<u16>,
        forward_all_ports: bool,
        forward_exit_egress: bool,
    ) -> Self {
        Self {
            bus: MessageBus::spawn_default(),
            keys: Arc::new(keys),
            shutdown,
            accept_routes,
            exit_node,
            forward_routes: Arc::new(forward_routes),
            forward_tcp_ports: Arc::new(forward_tcp_ports),
            forward_udp_ports: Arc::new(forward_udp_ports),
            forward_all_ports,
            forward_exit_egress,
        }
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
