//! Commands that mutate network stack configuration.

use alloc::vec::Vec;
use core::net::IpAddr;

use crate::command;

/// Mutate the network stack's configuration.
#[derive(Debug)]
pub enum Command {
    /// Set the network interface's IPs.
    SetIps {
        /// IPs to assign to the netstack's interface.
        ///
        /// If the netstack was configured with
        /// [`Config::loopback`](crate::Config::loopback) enabled, the loopback addresses
        /// should not be included here.
        ///
        /// May fail if `smoltcp` was not configured with a sufficient
        /// `iface-max-addr-count-*` (feature flag).
        new_ips: Vec<IpAddr>,
    },

    /// Enable or disable "any-IP" acceptance on the interface.
    ///
    /// When enabled, the interface accepts inbound packets addressed to destinations it does
    /// not own (i.e. arbitrary non-local addresses), capturing the original destination so a
    /// forwarder can splice the flow to a real OS socket. This is the mechanism that lets a
    /// node act as a subnet router / exit node.
    ///
    /// This MUST only be enabled on a dedicated forwarder netstack -- never on the shared
    /// application netstack, where it would silently capture traffic not destined for us.
    SetAnyIp {
        /// Whether any-IP acceptance is enabled.
        enabled: bool,
    },
}

impl From<Command> for command::Command {
    fn from(command: Command) -> Self {
        command::Command::StackControl(command)
    }
}
