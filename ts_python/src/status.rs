//! Python marshaling for `status()`, `whois()`, and netmap snapshots.
//!
//! Mirrors `node_info.rs`: each returned struct derives [`IntoPyObject`] and exposes plain,
//! Python-friendly fields (`IpAddr`/`SocketAddr` become strings, `online` becomes `None`/`bool`,
//! routes become a list of CIDR strings, capabilities become a list of `(str, list[str])` tuples).

use pyo3::IntoPyObject;

use crate::node_info::NodeInfo;

/// A single node entry in a [`Status`] snapshot (mirrors `tailscale::StatusNode`).
///
/// Turned into a `dict` on the Python side via `IntoPyObject`.
#[derive(Debug, IntoPyObject)]
pub struct StatusNode {
    /// The node's stable id (stable across re-registration).
    pub stable_id: String,
    /// Display name: fqdn if a tailnet component is known, else the bare hostname.
    pub display_name: String,
    /// The node's tailnet IPv4 address, as a string.
    pub ipv4: String,
    /// The node's tailnet IPv6 address, as a string.
    pub ipv6: String,
    /// Whether the node is online, if known (`ipnstate.PeerStatus.Online`). Tri-state: `Some(true)`
    /// online, `Some(false)` offline, `None` unknown (control sent no status). Reflects control's
    /// liveness state; `None` is never fabricated to `false`.
    pub online: Option<bool>,
    /// The routes this node accepts traffic for, as a list of CIDR strings.
    pub allowed_routes: Vec<String>,
    /// Whether this node advertises a default route, making it eligible as an exit node.
    pub is_exit_node: bool,
}

impl From<&tailscale::StatusNode> for StatusNode {
    fn from(value: &tailscale::StatusNode) -> Self {
        Self {
            stable_id: value.stable_id.0.clone(),
            display_name: value.display_name.clone(),
            ipv4: value.ipv4.to_string(),
            ipv6: value.ipv6.to_string(),
            online: value.online,
            allowed_routes: value.allowed_routes.iter().map(|r| r.to_string()).collect(),
            is_exit_node: value.is_exit_node,
        }
    }
}

/// A snapshot of the local netmap: this node plus every known peer (mirrors `tailscale::Status`).
///
/// Turned into a `dict` on the Python side via `IntoPyObject`.
#[derive(Debug, IntoPyObject)]
pub struct Status {
    /// This node, if a netmap has been received from control yet.
    pub self_node: Option<StatusNode>,
    /// Every peer currently known in the netmap.
    pub peers: Vec<StatusNode>,
    /// The tailnet's MagicDNS suffix (e.g. `"tail0123.ts.net"`), or `None` before the first netmap.
    pub magic_dns_suffix: Option<String>,
}

impl From<&tailscale::Status> for Status {
    fn from(value: &tailscale::Status) -> Self {
        Self {
            self_node: value.self_node.as_ref().map(StatusNode::from),
            peers: value.peers.iter().map(StatusNode::from).collect(),
            magic_dns_suffix: value.magic_dns_suffix.clone(),
        }
    }
}

/// The result of a `whois()` lookup (mirrors `tailscale::WhoIs`).
///
/// Turned into a `dict` on the Python side via `IntoPyObject`.
#[derive(Debug, IntoPyObject)]
pub struct WhoIs {
    /// The node that owns the queried source IP.
    pub node: NodeInfo,
    /// The login/email of the user that owns the node, if known (always `None` in this fork).
    pub user: Option<String>,
    /// The node's capability map, as a list of `(capability, args)` tuples (always empty in this
    /// fork).
    pub capabilities: Vec<(String, Vec<String>)>,
}

impl From<&tailscale::WhoIs> for WhoIs {
    fn from(value: &tailscale::WhoIs) -> Self {
        Self {
            node: NodeInfo::from(&value.node),
            user: value.user.clone(),
            capabilities: value.capabilities.clone(),
        }
    }
}
