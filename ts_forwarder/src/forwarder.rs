//! The forwarder orchestrator: owns the listener/bind tasks and route state.

use std::sync::Arc;

use ts_netstack_smoltcp::netcore::Channel;

use crate::{
    all_port::{run_tcp_all_ports, run_udp_all_ports},
    class::RouteTable,
    dialer::RealDialer,
    tcp::run_tcp_port,
    udp::run_udp_port,
};

/// Which destination ports a [`Forwarder`] forwards for advertised routes.
///
/// # All-port parity vs smoltcp 0.13.1
///
/// Go `tsnet`'s gVisor forwarders demultiplex *every* destination port through a single accept
/// hook. smoltcp 0.13.1 has no such hook (see the crate-level docs for the exact source
/// references): a SYN to a port with no listener is RST'd inside the iface ingress loop before
/// our code runs, and a socket can only listen/bind a *fixed* port (port 0 is rejected). So
/// there is no single-socket all-port accept, and eagerly opening 65535 listeners would make
/// every packet's accept scan `O(65535)` — unusably slow.
///
/// [`PortSpec::All`] is the closest *usable* mechanism: a raw-socket observer suppresses the
/// unmatched-SYN RST and reveals each new destination port, and a per-port any-IP listener is
/// started **on demand** for that port (see [`crate::all_port`]). Every port is forwarded
/// through the identical accept → classify → dial chokepoint; steady-state socket count is the
/// number of *active* ports, not the full range.
#[derive(Clone, Debug)]
pub enum PortSpec {
    /// Forward only this explicit set of ports (one eager listener/bind per port).
    Ports(Vec<u16>),
    /// Forward every port via the on-demand listener manager (see [`PortSpec`] docs).
    All,
}

/// Inbound subnet-router / exit-node forwarding dataplane.
///
/// Spawns one task per configured TCP and UDP port against a *dedicated any-IP netstack*
/// channel (see crate docs for why it must be dedicated). Each task accepts inbound overlay
/// flows to any destination IP on its port, classifies them against the current route table,
/// and dials a real OS socket through the injected [`RealDialer`] — the single anti-leak
/// chokepoint.
pub struct Forwarder<D: RealDialer> {
    channel: Channel,
    dialer: Arc<D>,
    routes_tx: tokio::sync::watch::Sender<RouteTable>,
    routes_rx: tokio::sync::watch::Receiver<RouteTable>,
    tcp: PortSpec,
    udp: PortSpec,
}

impl<D: RealDialer> Forwarder<D> {
    /// Construct a forwarder for an explicit set of TCP and UDP ports.
    ///
    /// `channel` must address a netstack with any-IP acceptance enabled (a dedicated forwarder
    /// netstack — never the application netstack). `tcp_ports` / `udp_ports` are the ports
    /// forwarded for every advertised route (see the per-port parity note in the crate docs).
    ///
    /// This is a thin wrapper over [`Forwarder::new_with_spec`] with
    /// [`PortSpec::Ports`]; existing callers/tests keep working unchanged.
    pub fn new(
        channel: Channel,
        routes: RouteTable,
        dialer: D,
        tcp_ports: Vec<u16>,
        udp_ports: Vec<u16>,
    ) -> Self {
        Self::new_with_spec(
            channel,
            routes,
            dialer,
            PortSpec::Ports(tcp_ports),
            PortSpec::Ports(udp_ports),
        )
    }

    /// Construct a forwarder that forwards **every** TCP and UDP port for advertised routes.
    ///
    /// This is the all-port subnet-router mode (gVisor-style coverage). It still classifies
    /// every destination IP through the [`RouteTable`] and gates every flow through the
    /// configured [`RealDialer`] — an all-port exit-node flow under [`DirectDialer`] is still
    /// dropped at dial time. See [`PortSpec::All`] for the smoltcp-0.13.1 cost tradeoff.
    ///
    /// [`DirectDialer`]: crate::DirectDialer
    pub fn all_ports(channel: Channel, routes: RouteTable, dialer: D) -> Self {
        Self::new_with_spec(channel, routes, dialer, PortSpec::All, PortSpec::All)
    }

    /// Construct a forwarder from explicit [`PortSpec`]s for TCP and UDP.
    pub fn new_with_spec(
        channel: Channel,
        routes: RouteTable,
        dialer: D,
        tcp: PortSpec,
        udp: PortSpec,
    ) -> Self {
        let (routes_tx, routes_rx) = tokio::sync::watch::channel(routes);
        Self {
            channel,
            dialer: Arc::new(dialer),
            routes_tx,
            routes_rx,
            tcp,
            udp,
        }
    }

    /// A handle for updating the advertised route table while the forwarder runs.
    ///
    /// In-flight flows keep the dialer they were already classified for; only new flows see the
    /// updated routes.
    pub fn route_updater(&self) -> RouteUpdater {
        RouteUpdater {
            tx: self.routes_tx.clone(),
        }
    }

    /// Run the forwarder.
    ///
    /// For [`PortSpec::Ports`] this spawns one eager listener/bind task per configured port.
    /// For [`PortSpec::All`] it spawns the on-demand all-port manager (see [`crate::all_port`]),
    /// which lazily starts a per-port listener the first time a flow to that port is seen.
    ///
    /// Returns when any spawned task exits (which only happens if the netstack channel closes),
    /// propagating its error.
    pub async fn run(self) -> Result<(), ts_netstack_smoltcp::netcore::Error> {
        let mut tasks = tokio::task::JoinSet::new();

        match self.tcp {
            PortSpec::Ports(ports) => {
                for port in ports {
                    let channel = self.channel.clone();
                    let routes = self.routes_rx.clone();
                    let dialer = self.dialer.clone();
                    tasks.spawn(async move { run_tcp_port(channel, port, routes, dialer).await });
                }
            }
            PortSpec::All => {
                let channel = self.channel.clone();
                let routes = self.routes_rx.clone();
                let dialer = self.dialer.clone();
                tasks.spawn(async move { run_tcp_all_ports(channel, routes, dialer).await });
            }
        }

        match self.udp {
            PortSpec::Ports(ports) => {
                for port in ports {
                    let channel = self.channel.clone();
                    let routes = self.routes_rx.clone();
                    let dialer = self.dialer.clone();
                    tasks.spawn(async move { run_udp_port(channel, port, routes, dialer).await });
                }
            }
            PortSpec::All => {
                let channel = self.channel.clone();
                let routes = self.routes_rx.clone();
                let dialer = self.dialer.clone();
                tasks.spawn(async move { run_udp_all_ports(channel, routes, dialer).await });
            }
        }

        // Keep the route sender alive for the lifetime of the run so receivers don't see the
        // channel close while tasks are live.
        let _routes_tx = self.routes_tx;

        if let Some(res) = tasks.join_next().await {
            // A spawned task finished; propagate its result (Ok is unexpected — they loop
            // forever — so any return is effectively shutdown).
            return res.expect("forwarder task panicked");
        }

        Ok(())
    }
}

/// Handle to update a running [`Forwarder`]'s advertised routes.
#[derive(Clone)]
pub struct RouteUpdater {
    tx: tokio::sync::watch::Sender<RouteTable>,
}

impl RouteUpdater {
    /// Replace the advertised route table seen by newly accepted flows.
    pub fn update(&self, routes: RouteTable) {
        // Ignore send error: it only fails if all receivers are gone, i.e. the forwarder has
        // shut down, in which case there is nothing to update.
        let _result = self.tx.send(routes);
    }
}
