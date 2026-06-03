//! Owns the inbound subnet-router / exit-node forwarder and its dedicated any-IP netstack.
//!
//! The forwarder netstack is *separate* from the application netstack ([`NetstackActor`]): it has
//! any-IP acceptance enabled so it captures inbound overlay flows addressed to destinations this
//! node does not own (the advertised subnet routes / exit-node default route), and splices them to
//! real OS sockets via [`ts_forwarder`]. Routing of inbound packets to this netstack's transport is
//! done in [`route_updater`](crate::route_updater): advertised prefixes resolve to this transport,
//! the node's own addresses to the application transport.
//!
//! [`NetstackActor`]: crate::netstack_actor::NetstackActor

use kameo::actor::ActorRef;
use netstack::{
    HasChannel,
    netcore::{Channel, NetstackControl},
};
use tokio::task::JoinSet;
use ts_forwarder::{DirectDialer, Forwarder, HostExitDialer, RealDialer, RouteTable};
use ts_packet::PacketMut;

use crate::{
    Error,
    dataplane::{OverlayFromDataplane, OverlayToDataplane},
    env::Env,
};

pub struct ForwarderActor {
    _joinset: JoinSet<()>,
    channel: Channel,
}

/// Build a [`Forwarder`] with the given dialer and spawn its run loop onto `joinset`.
///
/// Generic over the concrete [`RealDialer`] so the fail-closed [`DirectDialer`] and the opt-in
/// [`HostExitDialer`] share one run-loop body — only the dialer type differs, so the two gate arms
/// can't drift. When `all_ports` is set the explicit `tcp_ports`/`udp_ports` sets are ignored and
/// the forwarder runs in all-port mode (raw-socket port observer); otherwise it forwards exactly
/// the configured port sets.
fn spawn_forwarder<D: RealDialer>(
    joinset: &mut JoinSet<()>,
    channel: Channel,
    routes: RouteTable,
    dialer: D,
    all_ports: bool,
    tcp_ports: Vec<u16>,
    udp_ports: Vec<u16>,
) {
    let forwarder = match forwarder_mode(all_ports) {
        ForwarderMode::AllPorts => Forwarder::all_ports(channel, routes, dialer),
        ForwarderMode::Ports => Forwarder::new(channel, routes, dialer, tcp_ports, udp_ports),
    };
    joinset.spawn(async move {
        if let Err(e) = forwarder.run().await {
            tracing::error!(error = %e, "forwarder run loop exited");
        }
    });
}

/// Which concrete dialer the forwarder is wired with — the anti-leak gate's only output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DialerChoice {
    /// Fail-closed default: structurally refuses exit-node egress.
    Direct,
    /// Explicit opt-in: egresses exit-node flows via this host's real IP.
    HostExit,
}

/// Pure selection of the forwarder dialer from the `forward_exit_egress` gate, factored out of
/// `on_start` so it can be unit-tested without a netstack. `HostExitDialer` is chosen iff (and
/// only iff) exit egress is enabled; otherwise the fail-closed `DirectDialer`.
fn dialer_choice(forward_exit_egress: bool) -> DialerChoice {
    if forward_exit_egress {
        DialerChoice::HostExit
    } else {
        DialerChoice::Direct
    }
}

/// Whether the forwarder runs in all-port mode or forwards an explicit port set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ForwarderMode {
    /// All TCP/UDP ports per advertised route (raw-socket port observer).
    AllPorts,
    /// Exactly the configured TCP/UDP port sets.
    Ports,
}

/// Pure selection of the forwarder port mode from the `forward_all_ports` flag. All-port mode is
/// chosen iff (and only iff) `forward_all_ports` is set; otherwise the explicit port sets.
fn forwarder_mode(forward_all_ports: bool) -> ForwarderMode {
    if forward_all_ports {
        ForwarderMode::AllPorts
    } else {
        ForwarderMode::Ports
    }
}

impl kameo::Actor for ForwarderActor {
    type Args = (
        Env,
        netstack::netcore::Config,
        OverlayToDataplane,
        OverlayFromDataplane,
    );
    type Error = Error;

    async fn on_start(
        (env, config, netstack_up, mut netstack_down): Self::Args,
        _slf: ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        let (
            mut netstack,
            netstack::WakingPipe {
                rx: mut netstack_down_rx,
                tx: netstack_down_tx,
            },
        ) = netstack::piped(config);
        let channel = netstack.command_channel();

        let mut joinset = JoinSet::new();

        joinset.spawn(async move {
            netstack.run_tokio().await;
        });

        // Pump packets emitted by the forwarder netstack down into the dataplane (out the overlay).
        joinset.spawn(async move {
            while let Some(buf) = netstack_down_rx.recv_async().await {
                if netstack_up.send(vec![buf.to_vec().into()]).is_err() {
                    break;
                }
            }

            tracing::warn!("forwarder netstack downlink shut down!");
        });

        // Pump packets the dataplane routed to this transport up into the forwarder netstack.
        joinset.spawn(async move {
            while let Some(bufs) = netstack_down.recv().await {
                for buf in bufs {
                    let buf: PacketMut = buf;
                    netstack_down_tx.send_async(buf.as_ref()).await;
                }
            }

            tracing::warn!("forwarder netstack uplink shut down!");
        });

        // Enable any-IP acceptance BEFORE the forwarder starts accepting, so the first inbound flow
        // to a foreign destination is captured rather than rejected. This is the dedicated forwarder
        // netstack; never the application netstack (see `SetAnyIp` safety constraints). The netstack
        // run loop is already spawned above, so this round-trips. A failure here means the freshly
        // spawned netstack channel is already gone — a fatal startup error.
        if let Err(e) = channel.set_any_ip(true).await {
            tracing::error!(error = %e, "enabling any-IP on forwarder netstack");
            return Err(Error {
                kind: crate::ErrorKind::ActorGone,
                message_ty: None,
                target_actor: None,
            });
        }

        // The forwarder dials precisely the prefixes we advertise (advertise == forward). The dialer
        // is the single anti-leak chokepoint, selected here by the `forward_exit_egress` gate:
        //
        // - `DirectDialer` (default, fail-closed): dials real sockets bound to 0.0.0.0:0 for subnet
        //   routes and *structurally refuses* exit-node egress, so a 0.0.0.0/0 flow routed to this
        //   netstack is dropped at dial time, never leaked out our real IP.
        // - `HostExitDialer` (explicit opt-in): also egresses exit-node flows via this host's real
        //   IP. Chosen only when the operator set `forward_exit_egress`, which is an auditable,
        //   deliberate act (see its config docs).
        //
        // The two dialers are distinct concrete types (`Forwarder<D>` is generic), so we branch on
        // the gate to pick the dialer but funnel both through one `spawn_forwarder` helper — the
        // run-loop body lives in exactly one place so the fail-closed and opt-in arms can't drift.
        let routes = RouteTable::new(env.forward_routes.iter().copied());
        let all_ports = env.forward_all_ports;
        let tcp_ports = env.forward_tcp_ports.as_ref().clone();
        let udp_ports = env.forward_udp_ports.as_ref().clone();
        let n_routes = env.forward_routes.len();
        let n_tcp_ports = tcp_ports.len();
        let n_udp_ports = udp_ports.len();

        match dialer_choice(env.forward_exit_egress) {
            DialerChoice::HostExit => spawn_forwarder(
                &mut joinset,
                channel.clone(),
                routes,
                HostExitDialer,
                all_ports,
                tcp_ports,
                udp_ports,
            ),
            DialerChoice::Direct => spawn_forwarder(
                &mut joinset,
                channel.clone(),
                routes,
                DirectDialer,
                all_ports,
                tcp_ports,
                udp_ports,
            ),
        }

        tracing::debug!(
            n_routes,
            n_tcp_ports,
            n_udp_ports,
            all_ports,
            exit_egress = env.forward_exit_egress,
            "forwarder started"
        );

        Ok(Self {
            _joinset: joinset,
            channel,
        })
    }
}

#[kameo::messages]
impl ForwarderActor {
    #[message]
    pub fn get_channel(&self) -> (Channel,) {
        (self.channel.clone(),)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::ForwarderConfig;

    /// Build a `ForwarderConfig` toggling only the two gate bools (the historically swap-prone
    /// adjacent params), leaving everything else fail-closed/empty.
    fn cfg(forward_all_ports: bool, forward_exit_egress: bool) -> ForwarderConfig {
        ForwarderConfig {
            accept_routes: false,
            exit_node: None,
            forward_routes: vec![],
            forward_tcp_ports: vec![],
            forward_udp_ports: vec![],
            forward_all_ports,
            forward_exit_egress,
        }
    }

    #[test]
    fn host_exit_dialer_iff_forward_exit_egress() {
        // Fail-closed default: no exit egress => the direct (refusing) dialer.
        assert_eq!(
            dialer_choice(cfg(false, false).forward_exit_egress),
            DialerChoice::Direct
        );
        // Opt-in: exit egress => the host-exit dialer that egresses via the real IP.
        assert_eq!(
            dialer_choice(cfg(false, true).forward_exit_egress),
            DialerChoice::HostExit
        );
        // The all-ports flag is orthogonal: it must not affect the dialer gate.
        assert_eq!(
            dialer_choice(cfg(true, false).forward_exit_egress),
            DialerChoice::Direct
        );
        assert_eq!(
            dialer_choice(cfg(true, true).forward_exit_egress),
            DialerChoice::HostExit
        );
    }

    #[test]
    fn all_ports_mode_iff_forward_all_ports() {
        assert_eq!(
            forwarder_mode(cfg(false, false).forward_all_ports),
            ForwarderMode::Ports
        );
        assert_eq!(
            forwarder_mode(cfg(true, false).forward_all_ports),
            ForwarderMode::AllPorts
        );
        // Orthogonal to the exit-egress gate.
        assert_eq!(
            forwarder_mode(cfg(false, true).forward_all_ports),
            ForwarderMode::Ports
        );
        assert_eq!(
            forwarder_mode(cfg(true, true).forward_all_ports),
            ForwarderMode::AllPorts
        );
    }
}
