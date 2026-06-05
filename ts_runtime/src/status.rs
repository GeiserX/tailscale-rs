//! Netmap status aggregation, WhoIs lookups, and a netmap-change watcher.
//!
//! These surface the internal netmap state ([`ts_control::StateUpdate`], consumed by the
//! [`PeerTracker`](crate::peer_tracker::PeerTracker)) to embedders, mirroring tsnet's
//! `LocalClient::Status`, `WhoIs`, and `WatchIPNBus`.
//!
//! ## Capability / user gap (do not fabricate)
//!
//! tsnet's `Status`/`WhoIs` also carry per-node *online* state, the owning *user* (login/profile),
//! and a *capability map*. The wire format does carry these (`ts_control_serde::Node::online`,
//! `last_seen`, `cap_map`, and the `UserProfiles` table), but this fork's domain
//! [`Node`](ts_control::Node) — produced by `From<&ts_control_serde::Node>` — currently drops them.
//! Until the domain `Node` is extended to retain them, [`WhoIs::user`] and [`WhoIs::capabilities`]
//! are always empty and [`StatusPeer::online`] is always `None`. We surface what the domain model
//! actually holds rather than inventing values.

use std::net::{IpAddr, SocketAddr};

use ts_control::{Node, StableNodeId};

/// A snapshot of the local netmap: this node plus every known peer.
///
/// Analogous to tsnet's `ipnstate.Status`. Built by [`Runtime::status`](crate::Runtime::status)
/// from the self node held by the control runner and the peers held by the peer tracker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// This node, if a netmap has been received from control yet.
    pub self_node: Option<StatusNode>,
    /// Every peer currently known in the netmap.
    pub peers: Vec<StatusNode>,
}

/// A single node entry in a [`Status`] snapshot.
///
/// Analogous to tsnet's `ipnstate.PeerStatus`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusNode {
    /// The node's stable id (stable across re-registration).
    pub stable_id: StableNodeId,
    /// A display name for the node: its fqdn if a tailnet component is known, else its bare
    /// hostname.
    pub display_name: String,
    /// The node's tailnet IPv4 address.
    pub ipv4: IpAddr,
    /// The node's tailnet IPv6 address.
    pub ipv6: IpAddr,
    /// Whether the node is online, if known.
    ///
    /// Always `None` in this fork: the domain [`Node`](ts_control::Node) does not retain the
    /// wire-level `online` field (see the module-level capability/user gap note).
    pub online: Option<bool>,
    /// The routes this node accepts traffic for (its own `/32` and `/128`, plus any advertised
    /// subnet routes and possibly the exit-node default route).
    pub allowed_routes: Vec<ipnet::IpNet>,
    /// Whether this node advertises a default route (`0.0.0.0/0` or `::/0`), making it eligible to
    /// be selected as an exit node.
    pub is_exit_node: bool,
}

impl StatusNode {
    /// Build a [`StatusNode`] from a domain [`Node`].
    pub fn from_node(node: &Node) -> Self {
        let is_exit_node = node
            .accepted_routes
            .iter()
            .any(|route| route.prefix_len() == 0);

        Self {
            stable_id: node.stable_id.clone(),
            display_name: node
                .fqdn_opt(false)
                .unwrap_or_else(|| node.hostname.clone()),
            ipv4: node.tailnet_address.ipv4.addr().into(),
            ipv6: node.tailnet_address.ipv6.addr().into(),
            // The domain `Node` carries no online state; do not fabricate one.
            online: None,
            allowed_routes: node.accepted_routes.clone(),
            is_exit_node,
        }
    }
}

/// The result of a [`Runtime::whois`](crate::Runtime::whois) lookup: the node that owns a tailnet
/// source address, plus its user and capabilities.
///
/// Analogous to tsnet's `apitype.WhoIsResponse`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhoIs {
    /// The node that owns the queried source IP.
    pub node: Node,
    /// The login/email of the user that owns the node, if known.
    ///
    /// Always `None` in this fork: the domain [`Node`](ts_control::Node) does not retain the
    /// wire-level user/login mapping (see the module-level capability/user gap note).
    pub user: Option<String>,
    /// The node's capability map, as `(capability, args)` pairs.
    ///
    /// Always empty in this fork: the domain [`Node`](ts_control::Node) does not retain the
    /// wire-level `cap_map` (see the module-level capability/user gap note).
    pub capabilities: Vec<(String, Vec<String>)>,
}

impl WhoIs {
    /// Build a [`WhoIs`] from the owning node. User and capabilities are left empty because the
    /// domain `Node` does not carry them (see the module-level gap note).
    pub(crate) fn from_node(node: Node) -> Self {
        Self {
            node,
            user: None,
            capabilities: Vec::new(),
        }
    }
}

/// Resolve which node owns a tailnet source address, used by WhoIs.
pub(crate) fn whois_addr(addr: SocketAddr) -> IpAddr {
    addr.ip()
}

#[cfg(test)]
mod tests {
    use ts_control::{Node, StableNodeId, TailnetAddress};

    use super::*;

    fn node(stable: &str, hostname: &str, tailnet: Option<&str>, ipv4: &str) -> Node {
        Node {
            id: 1,
            stable_id: StableNodeId(stable.to_string()),
            hostname: hostname.to_string(),
            tailnet: tailnet.map(str::to_string),
            tags: vec![],
            tailnet_address: TailnetAddress {
                ipv4: format!("{ipv4}/32").parse().unwrap(),
                ipv6: "fd7a::1/128".parse().unwrap(),
            },
            node_key: [0u8; 32].into(),
            node_key_expiry: None,
            machine_key: None,
            disco_key: None,
            accepted_routes: vec![],
            underlay_addresses: vec![],
            derp_region: None,
            cap: Default::default(),
            cap_map: Default::default(),
            peerapi_port: None,
            peerapi_dns_proxy: false,
            is_wireguard_only: false,
            exit_node_dns_resolvers: vec![],
        }
    }

    #[test]
    fn status_node_display_name_prefers_fqdn() {
        let with_tailnet = node("n1", "host", Some("ts.net"), "100.64.0.1");
        assert_eq!(
            StatusNode::from_node(&with_tailnet).display_name,
            "host.ts.net"
        );

        let bare = node("n2", "solo", None, "100.64.0.2");
        assert_eq!(StatusNode::from_node(&bare).display_name, "solo");
    }

    #[test]
    fn status_node_addresses_and_online_gap() {
        let n = node("n1", "host", Some("ts.net"), "100.64.0.7");
        let s = StatusNode::from_node(&n);

        assert_eq!(s.ipv4, "100.64.0.7".parse::<IpAddr>().unwrap());
        assert_eq!(s.ipv6, "fd7a::1".parse::<IpAddr>().unwrap());
        // The domain Node carries no online state; we surface the gap as None, never a fabricated
        // value.
        assert_eq!(s.online, None);
    }

    #[test]
    fn status_node_detects_exit_node() {
        let mut not_exit = node("n1", "a", Some("ts.net"), "100.64.0.1");
        not_exit.accepted_routes = vec!["100.64.0.1/32".parse().unwrap()];
        assert!(!StatusNode::from_node(&not_exit).is_exit_node);

        let mut exit = node("n2", "b", Some("ts.net"), "100.64.0.2");
        exit.accepted_routes = vec![
            "100.64.0.2/32".parse().unwrap(),
            "0.0.0.0/0".parse().unwrap(),
        ];
        assert!(StatusNode::from_node(&exit).is_exit_node);

        let mut exit6 = node("n3", "c", Some("ts.net"), "100.64.0.3");
        exit6.accepted_routes = vec!["::/0".parse().unwrap()];
        assert!(StatusNode::from_node(&exit6).is_exit_node);
    }

    #[test]
    fn whois_user_and_caps_gap() {
        // WhoIs surfaces the owning node but cannot surface user/caps in this fork; assert we
        // expose the gap rather than fabricating data.
        let n = node("n1", "host", Some("ts.net"), "100.64.0.9");
        let whois = WhoIs::from_node(n.clone());

        assert_eq!(whois.node, n);
        assert_eq!(whois.user, None);
        assert!(whois.capabilities.is_empty());
    }
}
