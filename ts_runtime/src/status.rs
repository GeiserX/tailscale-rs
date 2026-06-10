//! Netmap status aggregation, WhoIs lookups, and a netmap-change watcher.
//!
//! These surface the internal netmap state ([`ts_control::StateUpdate`], consumed by the
//! [`PeerTracker`](crate::peer_tracker::PeerTracker)) to embedders, mirroring tsnet's
//! `LocalClient::Status`, `WhoIs`, and `WatchIPNBus`.
//!
//! ## Capability / user / online surfacing (do not fabricate)
//!
//! tsnet's `Status`/`WhoIs` also carry per-node *online* state, the owning *user* (login/profile),
//! and a *capability map*. Status of each in this fork:
//! - **Capabilities** — surfaced: [`WhoIs::capabilities`] is populated from the domain
//!   [`Node`](ts_control::Node)'s `cap_map` (the control-pushed `CapMap`), which the domain model
//!   retains.
//! - **User (login/profile)** — surfaced when the netmap provided it: [`WhoIs::user`] is the owning
//!   user's login/display name, resolved by joining the node's owning user id against the netmap's
//!   `UserProfiles` table (accumulated by the [`PeerTracker`](crate::peer_tracker::PeerTracker)
//!   across delta updates). `None` when control sent no profile for that user.
//! - **Online state** — surfaced: [`StatusNode::online`] / [`StatusNode::last_seen`] reflect the
//!   domain [`Node`](ts_control::Node)'s retained `online`/`last_seen`, populated from the netmap
//!   node and its online deltas (`PeerChange`, `MapResponse.online_change`/`peer_seen_change`).
//!   `online` stays tri-state (`None` = unknown), never fabricated to `false`.

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
    /// The stable id of the exit node traffic is **currently** egressing through, if any (Go's
    /// `Status.ExitNodeStatus.ID`). This is the *resolved + fail-closed* answer from the route
    /// updater — `None` when no exit node is configured, the configured selector matches no peer, or
    /// the matched peer no longer advertises a default route — so it reflects what is actually
    /// engaged, not merely what [`Config::exit_node`](ts_control::Config) requested. Find the peer's
    /// details by matching this id against [`peers`](Status::peers).
    pub active_exit_node: Option<StableNodeId>,
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
    /// Whether the node is online, if known (`ipnstate.PeerStatus.Online`). Tri-state: `Some(true)`
    /// connected to control, `Some(false)` offline, `None` unknown (control sent no online status or
    /// the local node lacks permission to know). Reflects control's liveness state, retained from the
    /// netmap node + its online deltas — `None` is *unknown*, never fabricated to `false`.
    pub online: Option<bool>,
    /// When control last saw this node online (`ipnstate.PeerStatus.LastSeen`). Per Go, only
    /// meaningful while the node is not currently online. `None` when unknown or never seen.
    pub last_seen: Option<chrono::DateTime<chrono::Utc>>,
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
            online: node.online,
            last_seen: node.last_seen,
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
    /// Populated from the domain [`Node`](ts_control::Node)'s `cap_map` (the control-pushed
    /// `CapMap`), sorted by capability name (the underlying map is a `BTreeMap`). Empty when control
    /// granted the node no capabilities. Mirrors tsnet's `WhoIsResponse.CapMap`.
    pub capabilities: Vec<(String, Vec<String>)>,
}

impl WhoIs {
    /// Build a [`WhoIs`] from the owning node and its resolved owner login/display name (if the
    /// netmap's `UserProfiles` table mapped the node's owning user id to a profile; `None` when
    /// control sent no profile — e.g. a tagged node with no human owner).
    ///
    /// `capabilities` is always populated from the node's `cap_map`.
    pub(crate) fn from_node_with_user(node: Node, user: Option<String>) -> Self {
        let capabilities = node
            .cap_map
            .iter()
            .map(|(cap, args)| (cap.clone(), args.clone()))
            .collect();
        Self {
            node,
            user,
            capabilities,
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
            user_id: 0,
            tailnet: tailnet.map(str::to_string),
            tags: vec![],
            tailnet_address: TailnetAddress {
                ipv4: format!("{ipv4}/32").parse().unwrap(),
                ipv6: "fd7a::1/128".parse().unwrap(),
            },
            node_key: [0u8; 32].into(),
            node_key_expiry: None,
            online: None,
            last_seen: None,
            key_signature: vec![],
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
            peer_relay: false,
            service_vips: Default::default(),
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
    fn status_node_addresses_and_online_surfaced() {
        let n = node("n1", "host", Some("ts.net"), "100.64.0.7");
        let s = StatusNode::from_node(&n);

        assert_eq!(s.ipv4, "100.64.0.7".parse::<IpAddr>().unwrap());
        assert_eq!(s.ipv6, "fd7a::1".parse::<IpAddr>().unwrap());
        // A node with no online data surfaces `None` (unknown) — never a fabricated `false`.
        assert_eq!(s.online, None);
        assert_eq!(s.last_seen, None);

        // A node whose domain online state is known surfaces it through StatusNode (no longer
        // hardwired to None).
        let mut online = node("n2", "up", Some("ts.net"), "100.64.0.8");
        online.online = Some(true);
        assert_eq!(StatusNode::from_node(&online).online, Some(true));

        let mut offline = node("n3", "down", Some("ts.net"), "100.64.0.9");
        offline.online = Some(false);
        assert_eq!(StatusNode::from_node(&offline).online, Some(false));
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
    fn whois_caps_empty_when_node_has_none() {
        // A node with no cap_map surfaces empty capabilities (not fabricated), and no user unless a
        // profile was joined in.
        let n = node("n1", "host", Some("ts.net"), "100.64.0.9");
        let whois = WhoIs::from_node_with_user(n.clone(), None);

        assert_eq!(whois.node, n);
        assert_eq!(whois.user, None);
        assert!(whois.capabilities.is_empty());
    }

    #[test]
    fn whois_populates_capabilities_from_cap_map() {
        // WhoIs surfaces the domain Node's cap_map verbatim, sorted by capability name (BTreeMap).
        let mut n = node("n1", "host", Some("ts.net"), "100.64.0.9");
        n.cap_map
            .insert("https://tailscale.com/cap/is-admin".to_string(), vec![]);
        n.cap_map.insert(
            "cap/ssh".to_string(),
            vec!["root".to_string(), "ubuntu".to_string()],
        );
        let whois = WhoIs::from_node_with_user(n, None);

        // BTreeMap iteration is sorted: "cap/ssh" < "https://…".
        assert_eq!(
            whois.capabilities,
            vec![
                (
                    "cap/ssh".to_string(),
                    vec!["root".to_string(), "ubuntu".to_string()]
                ),
                ("https://tailscale.com/cap/is-admin".to_string(), vec![]),
            ]
        );
    }

    #[test]
    fn whois_from_node_with_user_sets_user_and_caps() {
        let mut n = node("n1", "host", Some("ts.net"), "100.64.0.9");
        n.cap_map.insert("cap/x".to_string(), vec!["y".to_string()]);
        let whois = WhoIs::from_node_with_user(n, Some("alice@example.com".to_string()));

        assert_eq!(whois.user, Some("alice@example.com".to_string()));
        assert_eq!(
            whois.capabilities,
            vec![("cap/x".to_string(), vec!["y".to_string()])]
        );
    }
}
