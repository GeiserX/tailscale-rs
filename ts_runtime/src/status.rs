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

use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
};

use ts_control::{Node, StableNodeId, UserId};

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
    /// The tailnet's MagicDNS suffix (e.g. `"tail0123.ts.net"`) — Go `ipnstate.Status.MagicDNSSuffix`.
    /// Derived (like Go's `NetworkMap.MagicDNSSuffix`) from the self node's FQDN minus its host label,
    /// **not** from the DNS config and **not** from the tailnet `Domain` name. `None` before the first
    /// netmap, or when the self FQDN has no tailnet component (a bare hostname).
    pub magic_dns_suffix: Option<String>,
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
    /// The current trusted direct UDP endpoint for this peer, if a direct path is confirmed right now
    /// (Go `ipnstate.PeerStatus.CurAddr`). `Some` ⇒ traffic to this peer flows directly to this
    /// address; `None` ⇒ it relays via DERP (see [`relay`](Self::relay)). Mutually exclusive with a
    /// `relay` for a routed peer, mirroring Go's empty-vs-set `CurAddr`/`Relay` strings. A live
    /// snapshot — the direct path can expire/re-confirm between calls. Always `None` for the self node
    /// and a whois lookup (no path to oneself; whois is an ownership query).
    pub cur_addr: Option<SocketAddr>,
    /// The DERP region code this peer relays through when there is **no** direct path (Go
    /// `ipnstate.PeerStatus.Relay`, e.g. `"nyc"`). `Some` ⇔ [`cur_addr`](Self::cur_addr) is `None`
    /// and the peer's home DERP region is known; `None` when a direct path is confirmed, or the
    /// region code is unknown. Carries the region **code**, not its numeric id.
    pub relay: Option<String>,
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
            // A bare `Node` carries no live path state, so connectivity is unknown here. The peer
            // tracker overwrites these in `status_peers` by joining against the direct manager; the
            // self node and whois lookups (which also use `from_node`) correctly keep `None`.
            cur_addr: None,
            relay: None,
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
    /// Always `None` in this fork: the domain [`Node`] does not retain the
    /// wire-level user/login mapping (see the module-level capability/user gap note).
    pub user: Option<String>,
    /// The node's **node-level** capability map (Go `Node.CapMap` — node attributes like
    /// `can-funnel`), as `(capability, args)` pairs, populated from the domain
    /// [`Node`]'s `cap_map`, sorted by capability name. Distinct from
    /// [`cap_map`](Self::cap_map), which is the flow-scoped *peer-capability* grants.
    pub capabilities: Vec<(String, Vec<String>)>,
    /// The **flow-scoped** peer-capability grants for the queried `src -> dst` flow — Go
    /// `apitype.WhoIsResponse.CapMap` (`tailcfg.PeerCapMap`). The grants control's packet-filter
    /// application rules authorize for traffic from this node to the queried address, keyed by
    /// capability name with raw-JSON values. Empty when no grant matches the flow (or no scoped
    /// query was made). Distinct from the node-level [`capabilities`](Self::capabilities).
    pub cap_map: BTreeMap<String, Vec<String>>,
}

impl WhoIs {
    /// Build a [`WhoIs`] from the owning node and its resolved owner login/display name (if the
    /// netmap's `UserProfiles` table mapped the node's owning user id to a profile; `None` when
    /// control sent no profile — e.g. a tagged node with no human owner).
    ///
    /// `capabilities` is the node-level cap map; `cap_map` (the flow-scoped grants) is filled
    /// separately by [`Runtime::whois`](crate::Runtime::whois) and defaults to empty here.
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
            cap_map: BTreeMap::new(),
        }
    }
}

/// Resolve which node owns a tailnet source address, used by WhoIs.
pub(crate) fn whois_addr(addr: SocketAddr) -> IpAddr {
    addr.ip()
}

/// A measured-latency entry for one DERP region in a [`NetcheckReport`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionLatency {
    /// The DERP region id (Go `tailcfg.DERPRegionID`).
    pub region_id: u32,
    /// The measured round-trip latency to the region's closest DERP node.
    pub latency: std::time::Duration,
}

/// A snapshot of this node's latest network conditions report — the Rust analog of Go's
/// `netcheck.Report` as `tailscale netcheck` surfaces it.
///
/// ## Surfaced subset (do not fabricate)
/// Go's `netcheck.Report` also carries UDP/IPv4/IPv6 reachability, port-mapping support
/// (UPnP/PMP/PCP), `MappingVariesByDestIP`, global-address discovery, etc. This fork's net-report
/// path measures only **DERP-region latency** (the data that drives home-region selection), so the
/// report carries exactly that — the preferred (lowest-latency) region and the per-region latency
/// map — rather than inventing fields we never probe. Empty before the first measurement.
#[derive(Debug, Clone, PartialEq, Eq, Default, kameo::Reply)]
pub struct NetcheckReport {
    /// The id of the preferred DERP region — the lowest-latency region this node measured, the one it
    /// homes to (Go `Report.PreferredDERP`). `None` before the first measurement / when no region
    /// was reachable.
    pub preferred_derp: Option<u32>,
    /// Per-region measured latencies, sorted by latency ascending (Go `Report.RegionLatency`, here as
    /// an ordered list). The first entry, when present, is the [`preferred_derp`](Self::preferred_derp)
    /// region.
    pub region_latencies: Vec<RegionLatency>,
}

impl NetcheckReport {
    /// Build a report from the latest DERP-region measurements (the `RegionResult` set the latency
    /// measurer produces). `results` is expected sorted by latency ascending (the measurer's
    /// `RegionResult` `Ord` sorts on latency first), so the first entry is the preferred region; we
    /// do not re-sort beyond trusting that contract for `preferred_derp`, but the list is emitted in
    /// the order given. An empty `results` yields the default (no preferred region, empty list).
    pub(crate) fn from_region_results(results: &[ts_netcheck::RegionResult]) -> NetcheckReport {
        let region_latencies: Vec<RegionLatency> = results
            .iter()
            .map(|r| RegionLatency {
                // `ts_derp::RegionId` is a `NonZeroU32` newtype (its `.0` is the public inner).
                region_id: r.id.0.get(),
                latency: r.latency,
            })
            .collect();
        NetcheckReport {
            preferred_derp: region_latencies.first().map(|r| r.region_id),
            region_latencies,
        }
    }
}

/// A tailnet peer this node can send a Taildrop file *to*, plus the peerAPI base URL to reach it.
///
/// Analogous to tsnet's `apitype.FileTarget`. The set is produced by
/// [`Runtime::file_targets`](crate::Runtime::file_targets) (exposed as `Device::file_targets`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileTarget {
    /// The target peer's node record — pass straight to the Taildrop send path
    /// (`Device::send_file`), which re-derives the same peerAPI address.
    pub node: Node,
    /// The `http://ip:port` base URL of the peer's peerAPI, with no trailing path — the exact shape
    /// of Go's `apitype.FileTarget.PeerAPIURL`. Derived from
    /// [`Node::peerapi_addr`](ts_control::Node::peerapi_addr).
    pub peerapi_url: String,
}

/// Compute the sorted Taildrop send-target list from the peer set, given the local node's owning
/// user id. The pure core of [`Runtime::file_targets`](crate::Runtime::file_targets) — separated out
/// so the eligibility + ordering rules are unit-testable without spinning up the actor graph (the
/// node-level file-sharing gate is applied by the caller before this runs).
///
/// A peer is a target when it advertises a reachable peerAPI (Go `PeerAPIBase(p) != ""`) **and** is
/// either owned by `self_user_id` **or** carries the file-sharing-target capability — Go's two-way
/// OR. Sorted by MagicDNS name (Go sorts by `Node.Name`), falling back to the bare hostname.
pub(crate) fn build_file_targets(peers: Vec<Node>, self_user_id: UserId) -> Vec<FileTarget> {
    let mut targets: Vec<FileTarget> = peers
        .into_iter()
        .filter_map(|peer| {
            // Must advertise a reachable peerAPI (Go `PeerAPIBase(p) != ""`).
            let addr = peer.peerapi_addr()?;
            // Same owner OR explicitly an ACL file-sharing target (Go's two-way OR).
            let eligible = peer.user_id == self_user_id || peer.is_file_sharing_target();
            if !eligible {
                return None;
            }
            Some(FileTarget {
                peerapi_url: format!("http://{addr}"),
                node: peer,
            })
        })
        .collect();
    // Sort by MagicDNS name (Go sorts by `Node.Name`), bare hostname as the fallback key.
    targets.sort_by(|a, b| {
        let name = |t: &FileTarget| {
            t.node
                .fqdn_opt(false)
                .unwrap_or_else(|| t.node.hostname.clone())
        };
        name(a).cmp(&name(b))
    });
    targets
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

    /// `from_node` carries NO live connectivity: a bare domain `Node` has no path state, so
    /// `cur_addr`/`relay` default to `None`. `Runtime::status` overwrites `cur_addr` by joining the
    /// direct manager's `best_addrs`; the self node and whois (which also use `from_node`) keep
    /// `None`. This pins the default so the enrichment seam stays the single source of connectivity.
    #[test]
    fn status_node_from_node_has_no_connectivity_by_default() {
        let n = node("n1", "host", Some("ts.net"), "100.64.0.7");
        let s = StatusNode::from_node(&n);
        assert_eq!(s.cur_addr, None, "a bare Node has no direct endpoint");
        assert_eq!(s.relay, None, "a bare Node has no resolved relay");
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

    /// Build a peer with a reachable peerAPI on `ipv4`, owned by `user`.
    fn peer_with_peerapi(stable: &str, hostname: &str, ipv4: &str, user: UserId) -> Node {
        let mut n = node(stable, hostname, Some("ts.net"), ipv4);
        n.user_id = user;
        n.peerapi_port = Some(8089);
        n
    }

    #[test]
    fn file_targets_includes_same_owner_peer_with_peerapi() {
        let peer = peer_with_peerapi("p1", "host", "100.64.0.5", 42);
        let targets = build_file_targets(vec![peer], 42);

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].peerapi_url, "http://100.64.0.5:8089");
        assert_eq!(targets[0].node.hostname, "host");
    }

    #[test]
    fn file_targets_includes_cross_owner_peer_with_target_cap() {
        // Different owner, but carries the file-sharing-target cap → still a target (Go's OR).
        let mut peer = peer_with_peerapi("p1", "host", "100.64.0.5", 99);
        peer.cap_map
            .insert("tailscale.com/cap/file-sharing-target".to_string(), vec![]);
        let targets = build_file_targets(vec![peer], 42);

        assert_eq!(
            targets.len(),
            1,
            "cross-owner peer with the target cap qualifies"
        );
    }

    #[test]
    fn file_targets_excludes_cross_owner_peer_without_cap() {
        // Different owner and no target cap → excluded.
        let peer = peer_with_peerapi("p1", "host", "100.64.0.5", 99);
        let targets = build_file_targets(vec![peer], 42);

        assert!(
            targets.is_empty(),
            "a different owner without the cap is not a target"
        );
    }

    #[test]
    fn file_targets_excludes_peer_without_peerapi() {
        // Same owner, but advertises no peerAPI (no port) → excluded (Go `PeerAPIBase(p) == ""`).
        let mut peer = peer_with_peerapi("p1", "host", "100.64.0.5", 42);
        peer.peerapi_port = None;
        let targets = build_file_targets(vec![peer], 42);

        assert!(
            targets.is_empty(),
            "a peer with no peerAPI cannot be a Taildrop target"
        );
    }

    #[test]
    fn file_targets_sorted_by_magic_dns_name() {
        // Insert out of order; expect sorted by fqdn ("alpha.ts.net" < "zeta.ts.net").
        let zeta = peer_with_peerapi("p2", "zeta", "100.64.0.6", 42);
        let alpha = peer_with_peerapi("p1", "alpha", "100.64.0.5", 42);
        let targets = build_file_targets(vec![zeta, alpha], 42);

        let names: Vec<_> = targets.iter().map(|t| t.node.hostname.clone()).collect();
        assert_eq!(names, vec!["alpha", "zeta"]);
    }

    fn region_result(id: u32, latency_ms: u64) -> ts_netcheck::RegionResult {
        ts_netcheck::RegionResult {
            latency: std::time::Duration::from_millis(latency_ms),
            id: ts_derp::RegionId(std::num::NonZeroU32::new(id).unwrap()),
            latency_map_key: format!("{id}-v4"),
            connected_remote: "1.2.3.4:443".parse().unwrap(),
        }
    }

    #[test]
    fn netcheck_report_preferred_is_first_region() {
        // The measurer hands results sorted by latency ascending, so the first is the preferred
        // (home) region and every region is surfaced.
        let results = [
            region_result(5, 12),
            region_result(9, 40),
            region_result(2, 88),
        ];
        let report = NetcheckReport::from_region_results(&results);
        assert_eq!(
            report.preferred_derp,
            Some(5),
            "lowest-latency region is preferred"
        );
        assert_eq!(report.region_latencies.len(), 3);
        assert_eq!(report.region_latencies[0].region_id, 5);
        assert_eq!(
            report.region_latencies[0].latency,
            std::time::Duration::from_millis(12)
        );
        // Order is preserved as given (latency-ascending from the measurer).
        let ids: Vec<u32> = report
            .region_latencies
            .iter()
            .map(|r| r.region_id)
            .collect();
        assert_eq!(ids, vec![5, 9, 2]);
    }

    #[test]
    fn netcheck_report_empty_when_no_measurements() {
        // Before any measurement (or when none was reachable): no preferred region, empty list — not
        // a fabricated value.
        let report = NetcheckReport::from_region_results(&[]);
        assert_eq!(report, NetcheckReport::default());
        assert_eq!(report.preferred_derp, None);
        assert!(report.region_latencies.is_empty());
    }
}
