//! The parsed domain [`Node`] model: a tailnet node decoded from the wire (`tailcfg.Node`).
//!
//! [`Node`] is the owned, validated form the rest of the fork reasons about (addresses, keys, caps,
//! accepted routes, peerAPI/VIP services), built from the borrow-bound `ts_control_serde::Node` via
//! the [`From`] impl. It also carries the route/exit-node/funnel predicates ([`Node::is_subnet_route`],
//! [`Node::routes_to_install`], [`Node::can_funnel`]) and the [`ExitNodeSelector`] resolution.
//!
//! Fail-closed: route, funnel, and service-host gates all deny on a missing/malformed input.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use ts_capabilityversion::CapabilityVersion;
use ts_keys::{DiscoPublicKey, MachinePublicKey, NodePublicKey};

use crate::dns::Resolver;

/// An owned node-capability map (`Node.CapMap` in Go: `map[NodeCapability][]RawMessage`).
///
/// Keys are capability names or URLs (e.g. `"funnel"`, `"https"`, or
/// `"https://tailscale.com/cap/funnel-ports?ports=443,8443"`); values are the raw JSON-encoded
/// argument blobs for that capability (often empty). Stored *owned* because the wire form
/// ([`ts_control_serde::Node::cap_map`]) borrows from the decode buffer, whereas the domain
/// [`Node`] outlives it. Funnel gating only inspects the keys (see [`Node::can_funnel`] and
/// [`Node::check_funnel_port`]); the values are retained for capabilities that carry argument data.
pub type NodeCapMap = BTreeMap<String, Vec<String>>;

/// Whether `addr` falls in a range Tailscale assigns to nodes: the CGNAT range for IPv4
/// (`100.64.0.0/10`, excluding the ChromeOS VM carve-out `100.115.92.0/23`) and the Tailscale
/// ULA for IPv6 (`fd7a:115c:a1e0::/48`).
///
/// Mirrors `tsaddr.IsTailscaleIP` in the Go client. Used to tell a peer's own node addresses
/// (always single Tailscale IPs) apart from the larger subnet routes it advertises.
pub fn is_tailscale_ip(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            let cgnat = ipnet::Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 10).unwrap();
            let chromeos = ipnet::Ipv4Net::new(Ipv4Addr::new(100, 115, 92, 0), 23).unwrap();
            cgnat.contains(&v4) && !chromeos.contains(&v4)
        }
        IpAddr::V6(v6) => {
            let ula = ipnet::Ipv6Net::new(Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0), 48)
                .unwrap();
            ula.contains(&v6)
        }
    }
}

/// The unique id of a node.
pub type Id = i64;

/// The stable ID of a node.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct StableId(pub String);

/// How this node selects which peer to use as its exit node (`--exit-node` in the Go client).
///
/// Mirrors the Go client's `--exit-node`, which accepts a tailnet IP, a MagicDNS name, or a stable
/// node ID, and resolves it to a `StableNodeID` (`resolveExitNodeIPLocked`). We keep the selector
/// *unresolved* and re-run [`ExitNodeSelector::resolve`] against the live peer set on every route
/// rebuild, so an IP- or name-based selection follows the peer as the netmap changes (e.g. the
/// exit node re-registers under a new stable id).
///
/// A selector can be parsed from a string with [`str::parse`]/[`FromStr`](core::str::FromStr),
/// auto-detecting the variant the way the Go CLI's `--exit-node` does: a value that parses as an IP
/// address becomes [`ExitNodeSelector::Ip`], anything else becomes [`ExitNodeSelector::Name`].
/// Stable-id selection is available only by constructing [`ExitNodeSelector::StableId`] directly
/// (it is not auto-detected, since a stable id is otherwise indistinguishable from a hostname).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ExitNodeSelector {
    /// Select the peer with this exact stable node id.
    StableId(StableId),
    /// Select the peer whose tailnet address is this IP.
    Ip(IpAddr),
    /// Select the peer matching this bare hostname or MagicDNS name (case-insensitive, optional
    /// trailing dot), as per [`Node::matches_name`].
    Name(String),
}

impl core::str::FromStr for ExitNodeSelector {
    type Err = core::convert::Infallible;

    /// Parse a selector from a string, auto-detecting IP vs. name (matching the Go CLI's
    /// `--exit-node`). Parsing never fails: a non-IP string is taken as a MagicDNS name.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.parse::<IpAddr>() {
            Ok(ip) => ExitNodeSelector::Ip(ip),
            Err(_) => ExitNodeSelector::Name(s.to_owned()),
        })
    }
}

impl ExitNodeSelector {
    /// Resolve this selector to the stable id of the matching peer, if any, given the current set
    /// of peers.
    ///
    /// Resolution is **deterministic**: if a selector somehow matches more than one peer (e.g. two
    /// peers sharing a MagicDNS name during a transient netmap state), the peer with the smallest
    /// [`StableId`] is chosen. This matters because both the outbound route table and the inbound
    /// source filter resolve independently; a deterministic tiebreak guarantees they pick the
    /// *same* peer, preserving the cryptokey-routing coupling that prevents source-spoofing.
    ///
    /// Returns `None` when no peer matches (a stale/typo'd selector). Callers treat `None` as
    /// fail-closed: no peer is granted a default route, so internet-bound traffic is dropped.
    pub fn resolve<'a>(&self, peers: impl Iterator<Item = &'a Node>) -> Option<StableId> {
        peers
            .filter(|node| match self {
                ExitNodeSelector::StableId(id) => &node.stable_id == id,
                ExitNodeSelector::Ip(ip) => node.tailnet_address.contains(*ip),
                ExitNodeSelector::Name(name) => node.matches_name(name),
            })
            .map(|node| &node.stable_id)
            .min()
            .cloned()
    }
}

/// A node in a tailnet.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Node {
    /// The node's id.
    pub id: Id,
    /// The node's stable id.
    pub stable_id: StableId,

    /// This node's hostname.
    pub hostname: String,

    /// The integer id of the user that owns this node (`Node.User` in Go). `0` when control sends
    /// no owner (e.g. tagged/ACL nodes have no human owner). Join against the netmap's
    /// `UserProfiles` table (accumulated by the runtime's peer tracker) to resolve a login/display
    /// name — see the runtime `WhoIs` lookup.
    pub user_id: ts_control_serde::UserId,

    /// The tailnet this node belongs to.
    pub tailnet: Option<String>,

    /// The tags assigned to this node.
    pub tags: Vec<String>,

    /// The address of the node in the tailnet.
    pub tailnet_address: TailnetAddress,

    /// The node's [`NodePublicKey`].
    pub node_key: NodePublicKey,
    /// The node key's expiration.
    pub node_key_expiry: Option<DateTime<Utc>>,

    /// Marshalled TKA node-key signature (`tailcfg.Node.KeySignature`); empty when control sends
    /// none. Verified against a TKA `Authority` at the peer-trust chokepoint WHEN tailnet-lock
    /// enforcement is active.
    pub key_signature: Vec<u8>,

    /// The node's [`MachinePublicKey`], if known.
    pub machine_key: Option<MachinePublicKey>,
    /// The node's [`DiscoPublicKey`], if known.
    pub disco_key: Option<DiscoPublicKey>,

    /// The routes this node accepts traffic for.
    pub accepted_routes: Vec<ipnet::IpNet>,
    /// The underlay addresses this node is reachable on (`Endpoints` in Go).
    pub underlay_addresses: Vec<SocketAddr>,

    /// The DERP region for this node, if known.
    pub derp_region: Option<ts_derp::RegionId>,

    /// This node's advertised capability version (`Node.Cap` in Go). Old control servers may not
    /// send it, in which case it defaults to [`CapabilityVersion::default`]. Used to gate features
    /// that require a minimum peer capability, e.g. exit-node DNS proxying (`peerCanProxyDNS`).
    pub cap: CapabilityVersion,

    /// This node's capability map (`Node.CapMap` in Go). Keys are capability names/URLs; values are
    /// the raw JSON argument blobs (often empty). Threaded from the wire
    /// ([`ts_control_serde::Node::cap_map`]) as an owned copy. Used to gate node-level features such
    /// as Funnel ingress ([`Node::can_funnel`], [`Node::check_funnel_port`]).
    pub cap_map: NodeCapMap,

    /// The peerAPI port this node advertises over IPv4 (`peerapi4` service), if any.
    ///
    /// Derived from `HostInfo.Services`. `None` means the peer advertises no IPv4 peerAPI, so it
    /// cannot be reached for peerAPI DoH (DNS-over-HTTPS) exit-node delegation.
    pub peerapi_port: Option<u16>,

    /// Whether this peer advertises the `peerapi-dns-proxy` service (Go `PeerAPIDNSProxy`),
    /// indicating it will proxy DNS lookups for other nodes when used as an exit node.
    pub peerapi_dns_proxy: bool,

    /// Whether this is a non-Tailscale WireGuard-only peer (`IsWireGuardOnly` in Go). Such peers
    /// cannot run a peerAPI DoH server, so exit-node DNS for them comes from
    /// [`Node::exit_node_dns_resolvers`] instead.
    pub is_wireguard_only: bool,

    /// DNS resolvers to use when this WireGuard-only peer is selected as an exit node
    /// (`ExitNodeDNSResolvers` in Go). Only meaningful when [`Node::is_wireguard_only`] is set.
    /// Encrypted-transport resolvers are dropped (see `Resolver::from_serde`).
    pub exit_node_dns_resolvers: Vec<Resolver>,

    /// Whether this node advertises itself as a **peer relay** (Go `Hostinfo.PeerRelay`): it runs a
    /// UDP relay server other peers can allocate relay endpoints on. This fork is a relay client
    /// only and never sets this for itself; it is parsed off peers so a relay candidate can be
    /// recognized. Actually *using* a relay path (the Geneve data path + allocation handshake) is
    /// not yet implemented — see the crate docs.
    pub peer_relay: bool,

    /// Per-service virtual IP addresses of the Tailscale VIP services this node *hosts*, keyed by
    /// `svc:<label>` service name. Parsed from the `service-host`
    /// ([`ts_control_serde::NODE_ATTR_SERVICE_HOST`]) node-capability value
    /// (`tailcfg.ServiceIPMappings`). These VIPs are control-assigned and also injected into the
    /// node's `AllowedIPs`; the application netstack must accept packets for them so a
    /// `Device::listen_service`-bound listener can answer. Empty when the
    /// node hosts no VIP services (the common case). Per-service IP lists are deduplicated, source
    /// order otherwise preserved. Use [`Node::service_addresses`] for the flattened set (netstack
    /// accept list) and [`Node::service_addresses_for`] for a specific service's VIPs.
    pub service_vips: alloc::collections::BTreeMap<String, Vec<IpAddr>>,
}

impl Node {
    /// The fully-qualified domain name of the node.
    ///
    /// This is a string of the form `$HOST.$TAILNET_DOMAIN.`. For tailnets controlled by
    /// Tailscale's control plane, this usually means `$HOST.tail1234.ts.net.`
    ///
    /// The `trailing_dot` parameter specifies whether to include the trailing dot in the
    /// fqdn. This is included by the definition of FQDN, and is the way the Go codebase
    /// formats this field, but the parameter is included to allow turning it off for use
    /// in contexts that expect it to be absent.
    pub fn fqdn(&self, trailing_dot: bool) -> String {
        let dot = if trailing_dot { "." } else { "" };
        match &self.tailnet {
            Some(tailnet) => format!("{}.{tailnet}{dot}", self.hostname),
            None => format!("{}{dot}", self.hostname),
        }
    }

    /// Whether this node's key has expired as of `now`, mirroring Go's
    /// `netmap.NetworkMap.SelfKeyExpiry` + the `!expiry.IsZero() && expiry.Before(now)` check in
    /// `ipnlocal`. A node with no expiry ([`Node::node_key_expiry`] is `None`, the Go "zero value =
    /// does not expire") is never expired.
    ///
    /// Like Go, this fork is **reactive**: it reports expiry rather than auto-rotating in the
    /// background (Go transitions to `NeedsLogin` on expiry and re-registers via stored auth-key or
    /// interactive login). A caller observing `true` should re-register
    /// (`crate::tokio::register`) — supplying `RegisterRequest::old_node_key` (the prior key) and
    /// a fresh `node_key` when rotating the key, or the same key to merely refresh.
    pub fn key_expired(&self, now: DateTime<Utc>) -> bool {
        match self.node_key_expiry {
            None => false,
            Some(expiry) => expiry < now,
        }
    }

    /// The instant this node's key expires (`Node.KeyExpiry` in Go), or `None` if it never expires.
    /// A caller can schedule a re-evaluation/re-auth at this time.
    pub fn key_expiry(&self) -> Option<DateTime<Utc>> {
        self.node_key_expiry
    }

    /// Whether this node advertises itself as a peer relay (Go `Hostinfo.PeerRelay`): it runs a UDP
    /// relay server other peers may allocate relay endpoints on. Recognizing a relay candidate;
    /// actually traversing a relay path is not yet implemented in this fork.
    pub fn is_peer_relay(&self) -> bool {
        self.peer_relay
    }

    /// The key-expiry instant as **Unix seconds**, or `None` if the key never expires. Provided for
    /// callers (e.g. the root crate) that don't depend on `chrono`.
    pub fn key_expiry_unix(&self) -> Option<i64> {
        self.node_key_expiry.map(|t| t.timestamp())
    }

    /// Whether the key has expired as of `now_unix_secs` (Unix seconds). Equivalent to
    /// [`key_expired`](Self::key_expired) for `chrono`-free callers. A key with no expiry is never
    /// expired.
    pub fn key_expired_at_unix(&self, now_unix_secs: i64) -> bool {
        match self.key_expiry_unix() {
            None => false,
            Some(expiry) => expiry < now_unix_secs,
        }
    }

    /// The fully-qualified domain name of the node, only returning `Some` if the tailnet
    /// component is present.
    ///
    /// See [`Node::fqdn`].
    pub fn fqdn_opt(&self, trailing_dot: bool) -> Option<String> {
        let dot = if trailing_dot { "." } else { "" };
        let tailnet = self.tailnet.as_deref()?;

        Some(format!("{}.{tailnet}{dot}", self.hostname))
    }

    /// Report whether this node matches the given `name`.
    ///
    /// `name` is checked for equality with both this node's bare hostname and its fqdn. A
    /// trailing `.` may be present. Matching is case-insensitive (DNS names are
    /// case-insensitive), so this agrees with the canonicalized MagicDNS-name index used for
    /// peer lookups.
    pub fn matches_name(&self, name: &str) -> bool {
        // Strip an optional trailing root dot, then chop our `.tailnet` suffix off the end (if it
        // matches, case-insensitively) and compare the remainder to our hostname. If the tailnet
        // suffix doesn't match, the final case-insensitive compare against our bare hostname fails
        // naturally; if `name` was just the hostname, nothing is chopped and we compare directly.

        let name = name.strip_suffix('.').unwrap_or(name);

        let name = if let Some(tailnet) = &self.tailnet {
            name.get(name.len().saturating_sub(tailnet.len())..)
                .filter(|suffix| suffix.eq_ignore_ascii_case(tailnet))
                .and_then(|_| name.get(..name.len() - tailnet.len()))
                .and_then(|name| name.strip_suffix('.'))
                .unwrap_or(name)
        } else {
            name
        };

        name.eq_ignore_ascii_case(&self.hostname)
    }

    /// Report whether `route` is an advertised *subnet* route (as opposed to one of this node's
    /// own tailnet addresses).
    ///
    /// Mirrors `cidrIsSubnet` in the Go client (`wgengine/wgcfg/nmcfg/nmcfg.go`). A route is *not*
    /// a subnet route (i.e. it's a self-address) when it is a single host IP that is either a
    /// Tailscale-assigned IP or exactly one of this node's [`TailnetAddress`] addresses. Everything
    /// else — multi-IP CIDRs, and single IPs outside the Tailscale ranges — is a subnet route.
    ///
    /// The default route (`0.0.0.0/0` / `::/0`) is treated as a subnet route here; exit-node
    /// handling is a separate concern.
    pub fn is_subnet_route(&self, route: &ipnet::IpNet) -> bool {
        let host_prefix = match route {
            ipnet::IpNet::V4(_) => 32,
            ipnet::IpNet::V6(_) => 128,
        };

        if route.prefix_len() != host_prefix {
            // Any multi-IP CIDR (including the default route) is a subnet route.
            return true;
        }

        let addr = route.addr();
        !(is_tailscale_ip(addr) || self.tailnet_address.contains(addr))
    }

    /// The routes that should be installed for this peer, given whether this node accepts
    /// advertised subnet routes (`--accept-routes` / `RouteAll` in the Go client) and which peer
    /// (if any) is the selected exit node (`--exit-node` / `ExitNodeID` in the Go client).
    ///
    /// This node's own addresses (the peer's `/32` and `/128`) are always installed so the peer
    /// itself stays reachable. Larger advertised subnet routes are only installed when
    /// `accept_routes` is set; otherwise they are dropped (fail-closed). The same filtered set
    /// governs both outbound routing to the peer and inbound source validation, exactly as
    /// WireGuard cryptokey routing couples them in the Go client.
    ///
    /// The default route (`0.0.0.0/0` / `::/0`) is installed *only* for the peer whose
    /// [`StableId`] equals `exit_node`, mirroring `nmcfg.go`'s `if allowedIP.Bits()==0 &&
    /// peer.StableID()!=exitNode { skip }`. Exit-node use is gated behind this separate, explicit
    /// preference (`ExitNodeID`, not `RouteAll`): conflating the two would let enabling
    /// subnet-route acceptance silently route every packet through any peer advertising a default
    /// route — unacceptable for a fail-closed privacy posture. When `exit_node` is `None` (the
    /// default) no peer ever receives a `/0`, so internet-bound traffic has no overlay route and is
    /// dropped by the userspace netstack (fail-closed, no leak). Longest-prefix-match means a peer
    /// selected as the exit node still loses more-specific destinations to other peers; only
    /// residual default-route traffic egresses through it.
    pub fn routes_to_install<'a>(
        &'a self,
        accept_routes: bool,
        exit_node: Option<&StableId>,
    ) -> impl Iterator<Item = &'a ipnet::IpNet> + 'a {
        // Computed eagerly so the returned iterator doesn't borrow `exit_node`.
        let is_selected_exit = exit_node == Some(&self.stable_id);
        self.accepted_routes.iter().filter(move |route| {
            if route.prefix_len() == 0 {
                // Default route: installed only when this peer is the selected exit node. Both the
                // outbound route table and the inbound source filter call this, so the exit peer
                // may legitimately source arbitrary internet IPs on return traffic — and only it.
                return is_selected_exit;
            }
            accept_routes || !self.is_subnet_route(route)
        })
    }

    /// The capability version at and above which a peer can proxy DNS for nodes using it as an exit
    /// node (Go `tailcfg.CapabilityVersion` `peerCanProxyDNS`, introduced 2022-01-12 at V26).
    const PEER_CAN_PROXY_DNS: CapabilityVersion = CapabilityVersion::V26;

    /// The base URL of this peer's IPv4 peerAPI DoH endpoint for exit-node DNS proxying, if it can
    /// proxy DNS. Returns e.g. `http://100.64.0.5:8080/dns-query`.
    ///
    /// Mirrors Go `peerAPIBase(...)+"/dns-query"` gated by `exitNodeCanProxyDNS`: a peer can proxy
    /// DNS when it advertises an IPv4 peerAPI port **and** either advertises the explicit
    /// `peerapi-dns-proxy` service or is new enough ([`Node::cap`] ≥ `PEER_CAN_PROXY_DNS`). A
    /// WireGuard-only peer never runs a peerAPI, so it returns `None` here (its exit-node DNS comes
    /// from [`Node::exit_node_dns_resolvers`] instead).
    ///
    /// IPv4-only by deliberate design: the tailnet dataplane in this fork binds IPv4 only, so we
    /// never form a peerAPI URL on the peer's IPv6 address.
    pub fn peerapi_doh_url(&self) -> Option<String> {
        self.peerapi_doh_addr()
            .map(|addr| format!("http://{addr}/dns-query"))
    }

    /// The IPv4 socket address (`<tailnet-ipv4>:<peerapi-port>`) of this peer's peerAPI DoH endpoint
    /// for exit-node DNS proxying, if it can proxy DNS. Same gate as [`Node::peerapi_doh_url`]; this
    /// is the form the DoH *client* dials (over the overlay netstack) when delegating recursive
    /// resolution to a selected exit node. `SocketAddr`'s `Display` is `ip:port`, so
    /// `peerapi_doh_url` formats to `http://<ip>:<port>/dns-query` over this.
    pub fn peerapi_doh_addr(&self) -> Option<SocketAddr> {
        if self.is_wireguard_only {
            return None;
        }
        let port = self.peerapi_port?;
        if !(self.peerapi_dns_proxy || self.cap >= Self::PEER_CAN_PROXY_DNS) {
            return None;
        }
        Some(SocketAddr::new(
            IpAddr::V4(self.tailnet_address.ipv4.addr()),
            port,
        ))
    }

    /// The IPv4 peerAPI socket address (`<tailnet-ipv4>:<peerapi4-port>`) of this node, if it
    /// advertises an IPv4 peerAPI. Unlike [`Node::peerapi_doh_addr`], this is **not** gated on the
    /// DNS-proxy capability: it is the general base for any peerAPI request to this node (e.g. a
    /// Taildrop `PUT /v0/put/<name>` upload), mirroring Go's `peerAPIBase`/`peerAPIPorts`.
    ///
    /// IPv4-only by this fork's deliberate design (the tailnet dataplane binds IPv4 only, so we never
    /// form a peerAPI URL on the peer's IPv6 address). Returns `None` for a WireGuard-only peer (which
    /// runs no peerAPI) or a peer advertising no IPv4 peerAPI port.
    pub fn peerapi_addr(&self) -> Option<SocketAddr> {
        if self.is_wireguard_only {
            return None;
        }
        let port = self.peerapi_port?;
        Some(SocketAddr::new(
            IpAddr::V4(self.tailnet_address.ipv4.addr()),
            port,
        ))
    }

    /// The node attribute granting HTTPS (TLS cert provisioning) for this node (Go
    /// `tailcfg.CapabilityHTTPS`). One of the two caps [`Node::can_funnel`] requires.
    const CAP_HTTPS: &'static str = "https";

    /// The node attribute granting the ability to host Funnel ingress (Go `tailcfg.NodeAttrFunnel`).
    /// The other cap [`Node::can_funnel`] requires.
    const NODE_ATTR_FUNNEL: &'static str = "funnel";

    /// The capability URL whose `?ports=` query enumerates the ports Funnel may listen on (Go
    /// `tailcfg.CapabilityFunnelPorts`). The allowed ports live entirely in the *key's* query
    /// string, not the cap value.
    const CAP_FUNNEL_PORTS: &'static str = "https://tailscale.com/cap/funnel-ports";

    /// Report whether the cap map contains `cap` as a key (Go `NodeCapMap.Contains` / `HasCap`).
    pub fn has_node_attr(&self, cap: &str) -> bool {
        self.cap_map.contains_key(cap)
    }

    /// Report whether this node is permitted to host Tailscale Funnel ingress.
    ///
    /// Mirrors Go `ipn.NodeCanFunnel`: the node must advertise BOTH `CapabilityHTTPS` (`"https"`)
    /// AND `NodeAttrFunnel` (`"funnel"`) in its cap map. Fail-closed: a missing cap denies.
    pub fn can_funnel(&self) -> bool {
        self.has_node_attr(Self::CAP_HTTPS) && self.has_node_attr(Self::NODE_ATTR_FUNNEL)
    }

    /// Report whether `wanted_port` is allowed for Funnel on this node.
    ///
    /// Mirrors Go `ipn.CheckFunnelPort`: scan the cap-map keys for one prefixed by
    /// `Node::CAP_FUNNEL_PORTS`, URL-parse that key, read its `ports` query parameter, and match
    /// `wanted_port` against the comma-separated list of single ports and `first-last` ranges. The
    /// port list lives in the *key*, never the value. Fail-closed: no matching cap, an empty or
    /// unparseable `ports` query, or a key whose non-query part isn't exactly the funnel-ports URL
    /// all deny.
    pub fn check_funnel_port(&self, wanted_port: u16) -> bool {
        // Extract the `ports=` list from the first cap-map key that is the funnel-ports URL with a
        // non-empty `ports` query. Returns `None` (deny) if the key is unparseable, the query is
        // missing/empty, or the URL (sans query) isn't exactly the funnel-ports cap.
        let parse_attr = |attr: &str| -> Option<String> {
            let mut url = url::Url::parse(attr).ok()?;
            let ports = url
                .query_pairs()
                .find(|(k, _)| k == "ports")
                .map(|(_, v)| v.into_owned())?;
            if ports.is_empty() {
                return None;
            }
            url.set_query(None);
            // Go compares `u.String()` against the bare cap; `url`'s serializer keeps a trailing
            // `/` only if present in the input, and the funnel-ports cap has none, so a direct
            // string compare matches Go's behavior.
            if url.as_str() != Self::CAP_FUNNEL_PORTS {
                return None;
            }
            Some(ports)
        };

        let Some(ports_str) = self
            .cap_map
            .keys()
            .filter(|attr| attr.starts_with(Self::CAP_FUNNEL_PORTS))
            .find_map(|attr| parse_attr(attr))
        else {
            return false;
        };

        let wanted = wanted_port.to_string();
        for ps in ports_str.split(',') {
            if ps.is_empty() {
                continue;
            }
            match ps.split_once('-') {
                None => {
                    if ps == wanted {
                        return true;
                    }
                }
                Some((first, last)) => {
                    let (Ok(fp), Ok(lp)) = (first.parse::<u16>(), last.parse::<u16>()) else {
                        continue;
                    };
                    if fp <= wanted_port && wanted_port <= lp {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Report whether this node is permitted to host Tailscale VIP services.
    ///
    /// Mirrors the Go grant model: possession of the `service-host`
    /// ([`ts_control_serde::NODE_ATTR_SERVICE_HOST`]) node-capability **and** at least one assigned
    /// VIP address. Go additionally requires the host to be tagged
    /// (`ErrUntaggedServiceHost`); that tag gate is enforced at
    /// `Device::listen_service` using [`Node::tags`]. Fail-closed: no cap
    /// or no assigned VIP denies.
    pub fn is_service_host(&self) -> bool {
        self.has_node_attr(ts_control_serde::NODE_ATTR_SERVICE_HOST)
            && !self.service_vips.is_empty()
    }

    /// The control-assigned VIP addresses for one named service (`svc:<label>`), or an empty slice
    /// if this node does not host that service. This is the exact per-service mapping (so a
    /// multi-service co-host binds the right VIP for each service).
    pub fn service_addresses_for(&self, service: &str) -> &[IpAddr] {
        self.service_vips
            .get(service)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// The flattened, deduplicated set of every VIP address this node hosts across all services.
    /// Used to widen the netstack's accepted-address set so any hosted-service listener is
    /// reachable. Per-service binding uses [`Node::service_addresses_for`] instead.
    pub fn service_addresses(&self) -> Vec<IpAddr> {
        let mut seen = alloc::collections::BTreeSet::new();
        let mut out = Vec::new();
        for addr in self.service_vips.values().flatten() {
            if seen.insert(*addr) {
                out.push(*addr);
            }
        }
        out
    }
}

/// Validate a Tailscale VIP service name (`tailcfg.ServiceName.Validate`): it must carry the
/// `svc:` prefix ([`ts_control_serde::SERVICE_NAME_PREFIX`]) followed by a valid DNS label
/// (1–63 chars, ASCII alphanumeric or `-`, not starting/ending with `-`). Returns the bare label on
/// success. Fail-closed: anything malformed is rejected so a listener can never bind for a bogus
/// service name.
pub fn validate_service_name(name: &str) -> Option<&str> {
    let label = name.strip_prefix(ts_control_serde::SERVICE_NAME_PREFIX)?;
    if label.is_empty() || label.len() > 63 {
        return None;
    }
    if label.starts_with('-') || label.ends_with('-') {
        return None;
    }
    if label
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        Some(label)
    } else {
        None
    }
}

/// Parse the per-service VIP map this node hosts from the `service-host` node-capability value(s).
/// Each value is the raw JSON text of a [`ts_control_serde::ServiceIpMappings`] object (svc-name ->
/// VIP IPs); unparseable values are skipped (fail-closed: a malformed mapping contributes no VIPs).
/// Per-service IP lists are deduplicated, source order otherwise preserved.
fn service_vips_from_cap_map(
    cap_map: &NodeCapMap,
) -> alloc::collections::BTreeMap<String, Vec<IpAddr>> {
    let mut out: alloc::collections::BTreeMap<String, Vec<IpAddr>> =
        alloc::collections::BTreeMap::new();
    let Some(values) = cap_map.get(ts_control_serde::NODE_ATTR_SERVICE_HOST) else {
        return out;
    };

    for raw in values {
        let Ok(mappings) = serde_json::from_str::<ts_control_serde::ServiceIpMappings>(raw) else {
            continue;
        };
        for (name, addrs) in &mappings.0 {
            let entry = out.entry((*name).to_string()).or_default();
            for addr in addrs {
                if !entry.contains(addr) {
                    entry.push(*addr);
                }
            }
        }
    }
    out
}

/// Collect a wire ([`ts_control_serde`]) node cap map into an owned [`NodeCapMap`].
///
/// Keys are copied as owned strings; each value's raw JSON text is preserved verbatim. The wire map
/// borrows from the decode buffer, so an owned copy is required to outlive it on the domain
/// [`Node`].
fn cap_map_from_serde(wire: &ts_nodecapability::Map<'_>) -> NodeCapMap {
    wire.iter()
        .map(|(&key, values)| {
            let owned_values = values.0.iter().map(|v| v.get().to_owned()).collect();
            (key.to_owned(), owned_values)
        })
        .collect()
}

/// Extract the advertised IPv4 peerAPI port and whether the explicit `peerapi-dns-proxy` service is
/// advertised, from a peer's `HostInfo.Services` list.
fn peerapi_from_services(
    services: Option<&[ts_control_serde::Service<'_>]>,
) -> (Option<u16>, bool) {
    use ts_control_serde::ServiceProto;

    let Some(services) = services else {
        return (None, false);
    };
    let mut port = None;
    let mut dns_proxy = false;
    for svc in services {
        match svc.proto {
            ServiceProto::PeerApi4 => port = Some(svc.port),
            ServiceProto::PeerApiDnsProxy => dns_proxy = true,
            _ => {}
        }
    }
    (port, dns_proxy)
}

/// Addresses for a node within a tailnet.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TailnetAddress {
    /// The IPv4 address of the node in the tailnet.
    pub ipv4: ipnet::Ipv4Net,
    /// The IPv6 address of the node in the tailnet.
    pub ipv6: ipnet::Ipv6Net,
}

impl TailnetAddress {
    /// Report whether `addr` matches either address in this [`TailnetAddress`].
    pub fn contains(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(a) => self.ipv4.addr() == a,
            IpAddr::V6(a) => self.ipv6.addr() == a,
        }
    }
}

impl From<&ts_control_serde::Node<'_>> for Node {
    fn from(value: &ts_control_serde::Node) -> Self {
        let fqdn_without_trailing_dot = value.name.strip_suffix('.').unwrap_or(value.name);

        let (hostname, tailnet) = match fqdn_without_trailing_dot.split_once('.') {
            Some((hostname, tailnet)) => (hostname, Some(tailnet.to_owned())),
            None => (fqdn_without_trailing_dot, None),
        };

        let (peerapi_port, peerapi_dns_proxy) =
            peerapi_from_services(value.host_info.services.as_deref());

        let cap_map = cap_map_from_serde(&value.cap_map);
        let service_vips = service_vips_from_cap_map(&cap_map);

        // `addresses` is a variable-length `Vec<IpNet>` on the wire (Go `[]netip.Prefix`), not a
        // fixed (v4, v6) pair: an IPv6-off tailnet assigns only a v4 prefix. Pick the first of each
        // family. The v4 prefix is the node's tailnet identity (always present on a normal node);
        // if somehow absent we fall back to the unspecified `0.0.0.0/32` rather than panicking.
        // The v6 prefix is optional — when the tailnet is IPv4-only there is none, and the overlay
        // never reads `ipv6` in that mode (gated on `enable_ipv6`); we synthesize the unspecified
        // `::/128` placeholder so the domain `TailnetAddress` stays infallible.
        let ipv4 = value
            .addresses
            .iter()
            .find_map(|p| match p {
                ipnet::IpNet::V4(n) => Some(*n),
                ipnet::IpNet::V6(_) => None,
            })
            .unwrap_or_else(|| ipnet::Ipv4Net::new(core::net::Ipv4Addr::UNSPECIFIED, 32).unwrap());
        let ipv6 = value
            .addresses
            .iter()
            .find_map(|p| match p {
                ipnet::IpNet::V6(n) => Some(*n),
                ipnet::IpNet::V4(_) => None,
            })
            .unwrap_or_else(|| ipnet::Ipv6Net::new(core::net::Ipv6Addr::UNSPECIFIED, 128).unwrap());

        Self {
            id: value.id,
            stable_id: StableId(value.stable_id.0.to_string()),

            hostname: hostname.to_owned(),
            user_id: value.user,
            tailnet,

            tags: value
                .tags
                .as_ref()
                .map(|x| x.iter().map(|x| x.to_string()).collect())
                .unwrap_or_default(),

            tailnet_address: TailnetAddress { ipv4, ipv6 },
            node_key: value.key,
            node_key_expiry: value.key_expiry,
            key_signature: value.key_signature.to_vec(),
            machine_key: value.machine,
            disco_key: value.disco_key,

            // Per capver-112, `AllowedIPs` null/absent means "same as `addresses`". Fall back to the
            // node's own assigned prefixes verbatim (whatever families the wire carried), not a
            // synthesized v4+v6 pair.
            accepted_routes: value
                .allowed_ips
                .clone()
                .unwrap_or_else(|| value.addresses.clone()),
            underlay_addresses: value.endpoints.clone(),

            // legacy_derp_string is still in practical use as of 3/2026
            #[allow(deprecated)]
            derp_region: value
                .home_derp
                .or(value.legacy_derp_string)
                .or_else(|| value.host_info.net_info.as_ref()?.preferred_derp)
                .map(|x| ts_derp::RegionId(x.into())),

            cap: value.cap,
            cap_map,
            peerapi_port,
            peerapi_dns_proxy,
            is_wireguard_only: value.is_wireguard_only,
            exit_node_dns_resolvers: value
                .exit_node_dns_resolvers
                .iter()
                .filter_map(Resolver::from_serde)
                .collect(),
            peer_relay: value.host_info.peer_relay,
            service_vips,
        }
    }
}

/// Display-friendly identity for the user that owns a [`Node`], resolved from the netmap's
/// `UserProfiles` table (Go `tailcfg.UserProfile`). Owned counterpart of the borrow-bound
/// [`ts_control_serde::UserProfile`]. Keyed by [`UserProfile::id`] (== [`Node::user_id`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserProfile {
    /// The integer id of the Tailscale user this profile describes (matches [`Node::user_id`]).
    pub id: ts_control_serde::UserId,
    /// An email-ish login name for display (e.g. `alice@example.com` / `alice@github`). May be
    /// empty if control sent none.
    pub login_name: String,
    /// The user's display name (e.g. `Alice Smith`), if the IdP provided one.
    pub display_name: Option<String>,
}

impl From<&ts_control_serde::UserProfile<'_>> for UserProfile {
    fn from(value: &ts_control_serde::UserProfile) -> Self {
        Self {
            id: value.id,
            login_name: value.login_name.to_string(),
            display_name: value.display_name.map(str::to_string),
        }
    }
}

impl UserProfile {
    /// The best human-facing label for this user: the login name when present, else the display
    /// name, else `None`. This is what a `WhoIs` surfaces as the owning user.
    pub fn best_label(&self) -> Option<String> {
        if !self.login_name.is_empty() {
            Some(self.login_name.clone())
        } else {
            self.display_name.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire `Node.User` id must be carried onto the domain `Node.user_id` by the `From` impl
    /// (the field the runtime joins against the netmap `UserProfiles` table for `WhoIs.user`).
    /// Guards against the `From` impl wiring the wrong serde field or dropping it.
    #[test]
    fn from_wire_node_carries_user_id() {
        let mut wire = ts_control_serde::Node {
            user: 4242,
            ..Default::default()
        };
        wire.name = "host.tail.ts.net.";
        let domain: Node = (&wire).into();
        assert_eq!(domain.user_id, 4242);

        // Default (no owner / tagged node) stays 0.
        let tagged = ts_control_serde::Node::default();
        assert_eq!(Node::from(&tagged).user_id, 0);
    }

    /// A node from an **IPv4-only** tailnet (IPv6-off control plane / Headscale) carries a
    /// single-element `addresses` list. This used to fail deserialization ("invalid length 1,
    /// expected a tuple of size 2") when `addresses` was a fixed 2-tuple; it must now parse and
    /// derive the v4 identity, with the unused v6 a synthesized placeholder.
    #[test]
    fn from_wire_node_ipv4_only_addresses() {
        let wire = ts_control_serde::Node {
            addresses: vec!["100.64.0.5/32".parse().unwrap()],
            ..Default::default()
        };
        let domain: Node = (&wire).into();
        assert_eq!(
            domain.tailnet_address.ipv4,
            "100.64.0.5/32".parse().unwrap()
        );
        // No v6 on the wire → unspecified placeholder (never read in IPv4-only mode).
        assert_eq!(
            domain.tailnet_address.ipv6,
            ipnet::Ipv6Net::new(core::net::Ipv6Addr::UNSPECIFIED, 128).unwrap()
        );
        // AllowedIPs absent → falls back to the node's own assigned prefixes (just the v4 here).
        assert_eq!(
            domain.accepted_routes,
            vec!["100.64.0.5/32".parse::<ipnet::IpNet>().unwrap()]
        );
    }

    /// A dual-stack node carries both families (any order); the domain picks the first of each.
    #[test]
    fn from_wire_node_dual_stack_addresses() {
        let wire = ts_control_serde::Node {
            addresses: vec![
                "100.64.0.7/32".parse().unwrap(),
                "fd7a:115c:a1e0::7/128".parse().unwrap(),
            ],
            ..Default::default()
        };
        let domain: Node = (&wire).into();
        assert_eq!(
            domain.tailnet_address.ipv4,
            "100.64.0.7/32".parse().unwrap()
        );
        assert_eq!(
            domain.tailnet_address.ipv6,
            "fd7a:115c:a1e0::7/128".parse().unwrap()
        );
    }

    /// The deserialization regression itself: a MapResponse-style Node JSON with a 1-element
    /// `Addresses` array must parse (this is the exact shape the dev-Headscale sends).
    #[test]
    fn deserialize_node_with_single_address() {
        let json = r#"{
            "ID": 1,
            "StableID": "n1",
            "Name": "host.tail.ts.net.",
            "User": 1,
            "Addresses": ["100.64.0.9/32"],
            "Key": "nodekey:0000000000000000000000000000000000000000000000000000000000000000",
            "Machine": null,
            "DiscoKey": null,
            "AllowedIPs": null,
            "Endpoints": []
        }"#;
        let wire: ts_control_serde::Node = serde_json::from_str(json).expect("1-addr node parses");
        assert_eq!(wire.addresses.len(), 1);
        let domain: Node = (&wire).into();
        assert_eq!(
            domain.tailnet_address.ipv4,
            "100.64.0.9/32".parse().unwrap()
        );
    }

    #[test]
    fn key_expiry_semantics() {
        let now: DateTime<Utc> = "2026-06-05T00:00:00Z".parse().unwrap();
        let past: DateTime<Utc> = "2020-01-01T00:00:00Z".parse().unwrap();
        let future: DateTime<Utc> = "2099-01-01T00:00:00Z".parse().unwrap();

        let mut n = node("h", Some("t.ts.net"));

        // No expiry set => never expired (Go zero-value semantics).
        n.node_key_expiry = None;
        assert!(!n.key_expired(now));
        assert_eq!(n.key_expiry(), None);

        // Future expiry => not yet expired.
        n.node_key_expiry = Some(future);
        assert!(!n.key_expired(now));
        assert_eq!(n.key_expiry(), Some(future));

        // Past expiry => expired.
        n.node_key_expiry = Some(past);
        assert!(n.key_expired(now));
    }

    #[test]
    fn key_expiry_unix_agrees_with_chrono() {
        // The chrono-free variants (`key_expired_at_unix` / `key_expiry_unix`) must agree with the
        // chrono variants for the same none/future/past cases (Unix seconds of the same instants).
        let now: DateTime<Utc> = "2026-06-05T00:00:00Z".parse().unwrap();
        let past: DateTime<Utc> = "2020-01-01T00:00:00Z".parse().unwrap();
        let future: DateTime<Utc> = "2099-01-01T00:00:00Z".parse().unwrap();
        let now_unix = now.timestamp();

        let mut n = node("h", Some("t.ts.net"));

        // No expiry => never expired; the unix accessor reports `None`.
        n.node_key_expiry = None;
        assert_eq!(n.key_expired(now), n.key_expired_at_unix(now_unix));
        assert!(!n.key_expired_at_unix(now_unix));
        assert_eq!(n.key_expiry_unix(), None);

        // Future expiry => not yet expired; unix accessor matches the chrono timestamp.
        n.node_key_expiry = Some(future);
        assert_eq!(n.key_expired(now), n.key_expired_at_unix(now_unix));
        assert!(!n.key_expired_at_unix(now_unix));
        assert_eq!(n.key_expiry_unix(), Some(future.timestamp()));

        // Past expiry => expired; unix accessor matches the chrono timestamp.
        n.node_key_expiry = Some(past);
        assert_eq!(n.key_expired(now), n.key_expired_at_unix(now_unix));
        assert!(n.key_expired_at_unix(now_unix));
        assert_eq!(n.key_expiry_unix(), Some(past.timestamp()));
    }

    #[test]
    fn key_expiry_boundary_is_not_expired() {
        // A key whose expiry exactly equals `now` is NOT expired: the code uses strict `<`, matching
        // Go's `Before`. Both the chrono and chrono-free variants must agree at the boundary.
        let now: DateTime<Utc> = "2026-06-05T00:00:00Z".parse().unwrap();
        let now_unix = now.timestamp();

        let mut n = node("h", Some("t.ts.net"));
        n.node_key_expiry = Some(now);

        assert!(!n.key_expired(now));
        assert!(!n.key_expired_at_unix(now_unix));
    }

    #[test]
    fn is_peer_relay_returns_field() {
        let mut n = node("h", Some("t.ts.net"));

        n.peer_relay = true;
        assert!(n.is_peer_relay());

        n.peer_relay = false;
        assert!(!n.is_peer_relay());
    }

    fn node(hostname: &str, tailnet: Option<&str>) -> Node {
        Node {
            id: 1,
            stable_id: StableId("n1".to_string()),
            hostname: hostname.to_string(),
            user_id: 0,
            tailnet: tailnet.map(str::to_string),
            tags: vec![],
            tailnet_address: TailnetAddress {
                ipv4: "100.64.0.1/32".parse().unwrap(),
                ipv6: "fd7a::1/128".parse().unwrap(),
            },
            node_key: [0u8; 32].into(),
            node_key_expiry: None,
            key_signature: vec![],
            machine_key: None,
            disco_key: None,
            accepted_routes: vec![],
            underlay_addresses: vec![],
            derp_region: None,
            cap: CapabilityVersion::default(),
            cap_map: NodeCapMap::new(),
            peerapi_port: None,
            peerapi_dns_proxy: false,
            is_wireguard_only: false,
            exit_node_dns_resolvers: vec![],
            peer_relay: false,
            service_vips: Default::default(),
        }
    }

    #[test]
    fn matches_name_is_case_and_trailing_dot_insensitive() {
        let n = node("MyHost", Some("tail-scale.ts.net"));

        // bare hostname, any case
        assert!(n.matches_name("myhost"));
        assert!(n.matches_name("MYHOST"));
        assert!(n.matches_name("MyHost"));

        // fqdn, any case, with and without trailing dot
        assert!(n.matches_name("myhost.tail-scale.ts.net"));
        assert!(n.matches_name("MYHOST.TAIL-SCALE.TS.NET"));
        assert!(n.matches_name("myhost.tail-scale.ts.net."));
        assert!(n.matches_name("MyHost.Tail-Scale.TS.NET."));

        // wrong host / wrong tailnet must not match
        assert!(!n.matches_name("other"));
        assert!(!n.matches_name("myhost.other.ts.net"));
    }

    #[test]
    fn matches_name_no_tailnet() {
        let n = node("solo", None);
        assert!(n.matches_name("solo"));
        assert!(n.matches_name("SOLO."));
        assert!(!n.matches_name("solo.ts.net"));
    }

    #[test]
    fn is_tailscale_ip_ranges() {
        // CGNAT v4
        assert!(is_tailscale_ip("100.64.0.1".parse().unwrap()));
        assert!(is_tailscale_ip("100.127.255.254".parse().unwrap()));
        // ChromeOS carve-out is excluded
        assert!(!is_tailscale_ip("100.115.92.5".parse().unwrap()));
        // outside CGNAT
        assert!(!is_tailscale_ip("10.0.0.1".parse().unwrap()));
        assert!(!is_tailscale_ip("100.128.0.1".parse().unwrap()));
        // Tailscale ULA v6
        assert!(is_tailscale_ip("fd7a:115c:a1e0::1".parse().unwrap()));
        assert!(!is_tailscale_ip("fd00::1".parse().unwrap()));
    }

    /// Taildrop SSRF guard (defense-in-depth). `Device::send_file` rejects an upload destination
    /// unless `is_tailscale_ip(peer.peerapi_addr().ip())` holds. `Device::send_file` itself needs a
    /// live runtime (it goes through `self.channel()`), so it can't be unit-tested here; instead we
    /// test the exact composition the guard relies on — `is_tailscale_ip ∘ peerapi_addr` — against a
    /// `Node` whose `tailnet_address.ipv4` has been corrupted to a non-CGNAT (public) address. A
    /// well-formed peer always has a CGNAT 100.64.0.0/10 address, but the guard exists to catch a
    /// malformed/hostile node; this proves it would reject one.
    #[test]
    fn taildrop_ssrf_guard_rejects_non_cgnat_peerapi_addr() {
        let mut n = node("evil", Some("ts.net"));
        // Corrupt the peer to a public, non-CGNAT address and advertise a peerAPI port so
        // `peerapi_addr` returns `Some(_)`.
        n.tailnet_address.ipv4 = "1.2.3.4/32".parse().unwrap();
        n.peerapi_port = Some(443);

        let addr = n
            .peerapi_addr()
            .expect("peerapi_addr yields Some with a port set");
        assert_eq!(addr.ip(), Ipv4Addr::new(1, 2, 3, 4));
        // The guard `if !is_tailscale_ip(dst.ip()) { return Err(BadRequest) }` WOULD reject this.
        assert!(
            !is_tailscale_ip(addr.ip()),
            "SSRF guard must reject a peer whose peerAPI addr is not a Tailscale CGNAT IP"
        );

        // Conversely, a well-formed CGNAT peer passes the guard.
        let mut good = node("friend", Some("ts.net"));
        good.peerapi_port = Some(443);
        let good_addr = good.peerapi_addr().expect("peerapi_addr yields Some");
        assert!(is_tailscale_ip(good_addr.ip()));
    }

    #[test]
    fn is_subnet_route_distinguishes_self_from_subnet() {
        let n = node("host", Some("ts.net"));

        // The node's own /32 and /128 are self-addresses, not subnet routes.
        assert!(!n.is_subnet_route(&"100.64.0.1/32".parse().unwrap()));
        assert!(!n.is_subnet_route(&"fd7a::1/128".parse().unwrap()));
        // A different single Tailscale IP is still a self-address (Tailscale-assigned host).
        assert!(!n.is_subnet_route(&"100.64.5.5/32".parse().unwrap()));
        // A LAN /24 the node advertises is a subnet route.
        assert!(n.is_subnet_route(&"192.168.1.0/24".parse().unwrap()));
        // A single non-Tailscale host IP counts as a subnet route.
        assert!(n.is_subnet_route(&"8.8.8.8/32".parse().unwrap()));
        // The default route is treated as a subnet route.
        assert!(n.is_subnet_route(&"0.0.0.0/0".parse().unwrap()));
        assert!(n.is_subnet_route(&"::/0".parse().unwrap()));
    }

    #[test]
    fn routes_to_install_gates_subnets_on_accept_routes() {
        let mut n = node("host", Some("ts.net"));
        let self4: ipnet::IpNet = "100.64.0.1/32".parse().unwrap();
        let self6: ipnet::IpNet = "fd7a::1/128".parse().unwrap();
        let subnet: ipnet::IpNet = "192.168.1.0/24".parse().unwrap();
        n.accepted_routes = vec![self4, self6, subnet];

        // accept_routes off: only the self addresses are installed.
        let off: Vec<_> = n.routes_to_install(false, None).copied().collect();
        assert_eq!(off, vec![self4, self6]);

        // accept_routes on: the advertised subnet is installed too.
        let on: Vec<_> = n.routes_to_install(true, None).copied().collect();
        assert_eq!(on, vec![self4, self6, subnet]);
    }

    #[test]
    fn routes_to_install_default_route_only_for_selected_exit_node() {
        let mut n = node("host", Some("ts.net"));
        n.stable_id = StableId("exit1".to_string());
        let self4: ipnet::IpNet = "100.64.0.1/32".parse().unwrap();
        let default4: ipnet::IpNet = "0.0.0.0/0".parse().unwrap();
        let default6: ipnet::IpNet = "::/0".parse().unwrap();
        n.accepted_routes = vec![self4, default4, default6];

        // No exit node selected: default routes are excluded even with accept_routes on
        // (fail-closed — internet-bound traffic has no overlay route and is dropped).
        let none_off: Vec<_> = n.routes_to_install(false, None).copied().collect();
        assert_eq!(none_off, vec![self4]);
        let none_on: Vec<_> = n.routes_to_install(true, None).copied().collect();
        assert_eq!(none_on, vec![self4]);

        // A *different* peer selected as exit node: this peer still gets no default route.
        let other = StableId("exit2".to_string());
        let other_sel: Vec<_> = n.routes_to_install(false, Some(&other)).copied().collect();
        assert_eq!(other_sel, vec![self4]);

        // This peer selected as the exit node: its default routes are installed.
        let me = StableId("exit1".to_string());
        let sel: Vec<_> = n.routes_to_install(false, Some(&me)).copied().collect();
        assert_eq!(sel, vec![self4, default4, default6]);
    }

    fn exit_node_with(id: &str, ipv4: &str, hostname: &str, tailnet: Option<&str>) -> Node {
        let mut n = node(hostname, tailnet);
        n.stable_id = StableId(id.to_string());
        n.tailnet_address.ipv4 = format!("{ipv4}/32").parse().unwrap();
        n
    }

    #[test]
    fn exit_node_selector_resolves_by_id_ip_and_name() {
        let a = exit_node_with("nA", "100.64.0.5", "alpha", Some("ts.net"));
        let b = exit_node_with("nB", "100.64.0.6", "beta", Some("ts.net"));
        let peers = [a, b];
        let it = || peers.iter();

        // By stable id.
        assert_eq!(
            ExitNodeSelector::StableId(StableId("nB".into())).resolve(it()),
            Some(StableId("nB".into()))
        );
        // By tailnet IP.
        assert_eq!(
            ExitNodeSelector::Ip("100.64.0.5".parse().unwrap()).resolve(it()),
            Some(StableId("nA".into()))
        );
        // By MagicDNS name (fqdn, case-insensitive).
        assert_eq!(
            ExitNodeSelector::Name("BETA.ts.net".into()).resolve(it()),
            Some(StableId("nB".into()))
        );
        // By bare hostname.
        assert_eq!(
            ExitNodeSelector::Name("alpha".into()).resolve(it()),
            Some(StableId("nA".into()))
        );
        // Unresolvable selector => None (fail-closed at the call site).
        assert_eq!(
            ExitNodeSelector::Ip("100.64.0.99".parse().unwrap()).resolve(it()),
            None
        );
        assert_eq!(ExitNodeSelector::Name("ghost".into()).resolve(it()), None);
    }

    #[test]
    fn exit_node_selector_resolution_is_deterministic_on_ties() {
        // Two peers sharing a name (transient netmap state): the smallest stable id wins, so the
        // outbound table and inbound source filter — which resolve independently — agree.
        let a = exit_node_with("nZ", "100.64.0.5", "dup", Some("ts.net"));
        let b = exit_node_with("nA", "100.64.0.6", "dup", Some("ts.net"));
        let peers = [a, b];

        assert_eq!(
            ExitNodeSelector::Name("dup".into()).resolve(peers.iter()),
            Some(StableId("nA".into())),
            "smallest stable id wins the tie"
        );
        // Order of iteration must not change the result.
        assert_eq!(
            ExitNodeSelector::Name("dup".into()).resolve(peers.iter().rev()),
            Some(StableId("nA".into()))
        );
    }

    #[test]
    fn peerapi_doh_url_requires_port_and_capability() {
        let mut n = node("exit", Some("ts.net"));
        n.tailnet_address.ipv4 = "100.64.0.5/32".parse().unwrap();

        // No peerAPI port advertised: cannot proxy DNS.
        n.peerapi_port = None;
        n.cap = CapabilityVersion::V130;
        assert_eq!(n.peerapi_doh_url(), None);

        // Port advertised but capability too old and no explicit service: cannot proxy.
        n.peerapi_port = Some(8080);
        n.cap = CapabilityVersion::V25;
        n.peerapi_dns_proxy = false;
        assert_eq!(n.peerapi_doh_url(), None);

        // Port + new-enough capability: yields the DoH URL on the IPv4 address.
        n.cap = CapabilityVersion::V26;
        assert_eq!(
            n.peerapi_doh_url().as_deref(),
            Some("http://100.64.0.5:8080/dns-query")
        );

        // Port + explicit peerapi-dns-proxy service, even with an old capability.
        n.cap = CapabilityVersion::V25;
        n.peerapi_dns_proxy = true;
        assert_eq!(
            n.peerapi_doh_url().as_deref(),
            Some("http://100.64.0.5:8080/dns-query")
        );

        // WireGuard-only peers never run a peerAPI: no DoH URL even with a port.
        n.is_wireguard_only = true;
        assert_eq!(n.peerapi_doh_url(), None);
    }

    #[test]
    fn peerapi_doh_addr_matches_url_gate() {
        let mut n = node("exit", Some("ts.net"));
        n.tailnet_address.ipv4 = "100.64.0.5/32".parse().unwrap();
        n.peerapi_port = Some(8080);
        n.cap = CapabilityVersion::V26;

        // The addr form the DoH client dials is the same gated endpoint as the URL.
        assert_eq!(
            n.peerapi_doh_addr(),
            Some("100.64.0.5:8080".parse().unwrap())
        );
        // And it composes into exactly the URL form.
        assert_eq!(
            n.peerapi_doh_url().as_deref(),
            Some("http://100.64.0.5:8080/dns-query")
        );

        // Gated off the same way: no port => no addr.
        n.peerapi_port = None;
        assert_eq!(n.peerapi_doh_addr(), None);
    }

    #[test]
    fn peerapi_addr_returns_addr_when_advertised() {
        let mut n = node("peer", Some("ts.net"));
        n.tailnet_address.ipv4 = "100.64.0.5/32".parse().unwrap();
        n.peerapi_port = Some(8089);

        // Not gated on the DNS-proxy capability: a plain advertised peerAPI port is enough.
        assert_eq!(n.peerapi_addr(), Some("100.64.0.5:8089".parse().unwrap()));
    }

    #[test]
    fn peerapi_addr_none_when_no_port() {
        let mut n = node("peer", Some("ts.net"));
        n.tailnet_address.ipv4 = "100.64.0.5/32".parse().unwrap();
        n.peerapi_port = None;

        assert_eq!(n.peerapi_addr(), None);
    }

    #[test]
    fn peerapi_addr_none_for_wireguard_only() {
        let mut n = node("peer", Some("ts.net"));
        n.tailnet_address.ipv4 = "100.64.0.5/32".parse().unwrap();
        n.peerapi_port = Some(8089);
        n.is_wireguard_only = true;

        // WireGuard-only peers run no peerAPI, even with a port set.
        assert_eq!(n.peerapi_addr(), None);
    }

    #[test]
    fn peerapi_from_services_extracts_v4_port_and_dns_proxy_flag() {
        use ts_control_serde::{Service, ServiceProto};

        let services = [
            Service {
                proto: ServiceProto::PeerApi4,
                port: 8080,
                description: "peerapi",
            },
            Service {
                proto: ServiceProto::PeerApi6,
                port: 9090,
                description: "peerapi6",
            },
            Service {
                proto: ServiceProto::PeerApiDnsProxy,
                port: 1,
                description: "dns",
            },
        ];
        let (port, dns_proxy) = peerapi_from_services(Some(&services));
        assert_eq!(port, Some(8080), "only the IPv4 peerAPI port is taken");
        assert!(dns_proxy);

        // No services at all.
        assert_eq!(peerapi_from_services(None), (None, false));
    }

    #[test]
    fn exit_node_selector_parses_ip_vs_name() {
        assert_eq!(
            "100.64.0.5".parse::<ExitNodeSelector>().unwrap(),
            ExitNodeSelector::Ip("100.64.0.5".parse().unwrap())
        );
        assert_eq!(
            "fd7a::5".parse::<ExitNodeSelector>().unwrap(),
            ExitNodeSelector::Ip("fd7a::5".parse().unwrap())
        );
        assert_eq!(
            "my-exit.ts.net".parse::<ExitNodeSelector>().unwrap(),
            ExitNodeSelector::Name("my-exit.ts.net".into())
        );
    }
}
