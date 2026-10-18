//! Default-gateway lookup and validation.
//!
//! The port mapper only ever talks to one host: the gateway of the host's most preferred IPv4
//! default route, and only when that gateway is private (RFC 1918) and on-link. This module finds
//! it and proves those properties; [`crate::GatewayCap`] re-checks them before any socket exists.

use std::{
    fmt, io,
    net::{Ipv4Addr, SocketAddr},
    str::FromStr,
};

pub mod darwin;
pub mod linux;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod other;

#[cfg(target_os = "macos")]
use darwin as os;
#[cfg(target_os = "linux")]
use linux as os;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
use other as os;

/// A validated LAN gateway: where PMP/PCP requests go, and the host address and interface they
/// are sent from.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Gateway {
    /// The gateway (router) address. Private (RFC 1918) and on-link.
    pub gw: Ipv4Addr,
    /// This host's address on `if_index`. Private, and its prefix contains `gw`.
    pub self_ip: Ipv4Addr,
    /// Prefix length of `self_ip`'s subnet.
    pub prefix_len: u8,
    /// Interface index the default route uses.
    pub if_index: u32,
    /// Interface name the default route uses.
    pub if_name: String,
}

impl Gateway {
    /// Whether two gateways describe the same network: identical gateway, self address,
    /// interface and prefix. Two networks with the same identity are indistinguishable.
    pub fn same_network(&self, other: &Gateway) -> bool {
        self == other
    }
}

/// Why no gateway could be determined. `Ok(None)` from a lookup means "no IPv4 default route",
/// which is the normal offline state and not an error.
#[derive(Debug, thiserror::Error)]
pub enum LookupError {
    /// Gateway lookup is not implemented on this platform.
    #[error("gateway lookup is not supported on this platform")]
    Unsupported,
    /// The OS refused the routing-table read (`EPERM`/`EACCES`); the error is kept verbatim.
    #[error("routing table read not permitted: {0}")]
    Permission(io::Error),
    /// Another OS error from the routing-table read; kept verbatim.
    #[error("routing table read failed: {0}")]
    Os(io::Error),
    /// The routing table could not be parsed.
    #[error("routing table parse error at offset {offset}: {what}")]
    Parse {
        /// Byte (macOS) or line (Linux) offset of the problem.
        offset: usize,
        /// What was wrong.
        what: &'static str,
    },
    /// The routing table exceeded the size cap.
    #[error("routing table too large")]
    TooLarge,
    /// The only default route is IPv6; the port mapper is IPv4-only.
    #[error("the best default route is IPv6-only")]
    GatewayIpv6,
    /// The best default route's gateway (or this host's address) is not private.
    #[error("the best default route's gateway or self address is not private (RFC 1918)")]
    NotPrivate,
    /// No address on the route's interface has a prefix containing the gateway.
    #[error("no address on the default route's interface contains the gateway")]
    NotOnLink,
    /// The route's interface is down, loopback, point-to-point, or vanished.
    #[error("the default route's interface is unusable (down, loopback, point-to-point or gone)")]
    InterfaceUnusable,
    /// Equally preferred default routes or self addresses; refusing to guess.
    #[error("ambiguous default route or self address")]
    Ambiguous,
}

/// One usable IPv4 default route as the OS reports it, before any validation: destination
/// `0.0.0.0/0`, flags `UP` and `GATEWAY`, an IPv4 gateway, and (macOS) not interface-scoped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultRoute {
    /// The route's gateway.
    pub gw: Ipv4Addr,
    /// Interface index, when the OS reports one (macOS).
    pub if_index: Option<u32>,
    /// Interface name, when the OS reports one (Linux).
    pub if_name: Option<String>,
    /// Route metric; lower is preferred. Always 0 on macOS.
    pub metric: u32,
    /// The route's interface address (macOS `RTAX_IFA`), a hint for the self address.
    pub ifa: Option<Ipv4Addr>,
}

/// The default routes found in one routing-table read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DefaultRoutes {
    /// Usable IPv4 default routes.
    pub v4: Vec<DefaultRoute>,
    /// Whether a usable IPv6 default route exists (to tell "offline" from "IPv6-only").
    pub has_v6_default: bool,
}

/// A source of the current [`Gateway`].
pub trait GatewayLookup: Send + Sync {
    /// Look up the current gateway. `Ok(None)` means there is no IPv4 default route.
    fn lookup(&self) -> Result<Option<Gateway>, LookupError>;
}

impl fmt::Display for Gateway {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "gw={} self={}/{} if={}/{}",
            self.gw, self.self_ip, self.prefix_len, self.if_name, self.if_index
        )
    }
}

/// One interface as the gateway validation needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfInfo {
    /// Interface name.
    pub name: String,
    /// Interface index (0 if unknown).
    pub index: u32,
    /// Up and running.
    pub up: bool,
    /// A loopback interface.
    pub loopback: bool,
    /// A point-to-point interface (VPN tunnels such as utun or WireGuard).
    pub point_to_point: bool,
    /// IPv4 addresses with their prefix lengths.
    pub v4: Vec<(Ipv4Addr, u8)>,
}

impl IfInfo {
    /// Up, not loopback and not point-to-point.
    pub(crate) fn usable(&self) -> bool {
        self.up && !self.loopback && !self.point_to_point
    }
}

/// A configured gateway (`--portmap-gateway GW[,SELF]`). It replaces discovery only: the result
/// goes through the same private, on-link and interface validation as a discovered route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayOverride {
    /// The gateway address.
    pub gw: Ipv4Addr,
    /// This host's address on the gateway's subnet, if it should not be inferred.
    pub self_ip: Option<Ipv4Addr>,
}

impl FromStr for GatewayOverride {
    type Err = String;

    /// Parse `GW` or `GW,SELF`.
    fn from_str(s: &str) -> Result<Self, String> {
        let parse = |v: &str| {
            v.trim()
                .parse::<Ipv4Addr>()
                .map_err(|e| format!("{v:?} is not an IPv4 address: {e}"))
        };
        match s.split_once(',') {
            None => Ok(Self {
                gw: parse(s)?,
                self_ip: None,
            }),
            Some((gw, me)) => Ok(Self {
                gw: parse(gw)?,
                self_ip: Some(parse(me)?),
            }),
        }
    }
}

/// Whether `ip` is in RFC 1918 space. Link-local, CGNAT, loopback, unspecified and public
/// addresses are not.
pub(crate) fn is_private(ip: Ipv4Addr) -> bool {
    ip.is_private()
}

/// The prefix lengths a LAN self address may have: a `/0`..`/7` "subnet" would make any private
/// gateway look on-link, and a `/32` has no neighbours.
pub(crate) const LAN_PREFIX_LENS: std::ops::RangeInclusive<u8> = 8..=31;

/// Whether `net/prefix_len` contains `ip`.
pub(crate) fn prefix_contains(net: Ipv4Addr, prefix_len: u8, ip: Ipv4Addr) -> bool {
    if prefix_len > 32 {
        return false;
    }
    let mask = u32::MAX
        .checked_shl(32 - u32::from(prefix_len))
        .unwrap_or(0);
    u32::from(net) & mask == u32::from(ip) & mask
}

/// The kernel's preferred source address for `dst`, from a UDP socket that is `connect()`ed but
/// never sends: a UDP connect only runs the route lookup. Used to break a tie between several
/// candidate self addresses.
pub(crate) fn kernel_source(dst: Ipv4Addr) -> Option<Ipv4Addr> {
    let s = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    s.connect((dst, crate::PXP_PORT)).ok()?;
    match s.local_addr().ok()? {
        SocketAddr::V4(a) => Some(*a.ip()),
        SocketAddr::V6(_) => None,
    }
}

/// Pick this host's address on `iface` for talking to `gw`: an address whose prefix contains
/// `gw`, preferring the route's own interface address, then the kernel's source selection.
fn pick_self(
    gw: Ipv4Addr,
    iface: &IfInfo,
    hint: Option<Ipv4Addr>,
    kernel_source: &dyn Fn(Ipv4Addr) -> Option<Ipv4Addr>,
) -> Result<(Ipv4Addr, u8), LookupError> {
    let candidates: Vec<(Ipv4Addr, u8)> = iface
        .v4
        .iter()
        .copied()
        .filter(|&(a, p)| a != gw && LAN_PREFIX_LENS.contains(&p) && prefix_contains(a, p, gw))
        .collect();
    let chosen = match candidates.as_slice() {
        [] => return Err(LookupError::NotOnLink),
        [one] => *one,
        many => {
            let by_hint = hint.and_then(|h| many.iter().find(|(a, _)| *a == h));
            match by_hint {
                Some(c) => *c,
                None => {
                    let src = kernel_source(gw).ok_or(LookupError::Ambiguous)?;
                    *many
                        .iter()
                        .find(|(a, _)| *a == src)
                        .ok_or(LookupError::Ambiguous)?
                }
            }
        }
    };
    if !is_private(chosen.0) {
        return Err(LookupError::NotPrivate);
    }
    Ok(chosen)
}

/// Choose and validate the gateway from one routing-table read and the interface list.
///
/// The single most preferred IPv4 default route wins (lowest metric; ties are `Ambiguous`). Its
/// gateway must be private: a public best route is `NotPrivate`, never a fall-through to a less
/// preferred private one. Its interface must be up, not loopback and not point-to-point, and hold
/// a private address whose prefix contains the gateway.
pub fn select(
    routes: &DefaultRoutes,
    ifs: &[IfInfo],
    kernel_source: &dyn Fn(Ipv4Addr) -> Option<Ipv4Addr>,
) -> Result<Option<Gateway>, LookupError> {
    let Some(min_metric) = routes.v4.iter().map(|r| r.metric).min() else {
        return if routes.has_v6_default {
            Err(LookupError::GatewayIpv6)
        } else {
            Ok(None)
        };
    };
    let mut best: Vec<&DefaultRoute> = Vec::new();
    for r in routes.v4.iter().filter(|r| r.metric == min_metric) {
        // The same route reported twice is one route, not a tie.
        if !best
            .iter()
            .any(|b| b.gw == r.gw && b.if_index == r.if_index && b.if_name == r.if_name)
        {
            best.push(r);
        }
    }
    let [route] = best.as_slice() else {
        return Err(LookupError::Ambiguous);
    };
    if !is_private(route.gw) {
        return Err(LookupError::NotPrivate);
    }
    let iface = ifs
        .iter()
        .find(|i| {
            route.if_index.is_none_or(|x| x == i.index)
                && route.if_name.as_deref().is_none_or(|n| n == i.name)
                && (route.if_index.is_some() || route.if_name.is_some())
        })
        .ok_or(LookupError::InterfaceUnusable)?;
    if !iface.usable() {
        return Err(LookupError::InterfaceUnusable);
    }
    let (self_ip, prefix_len) = pick_self(route.gw, iface, route.ifa, kernel_source)?;
    Ok(Some(Gateway {
        gw: route.gw,
        self_ip,
        prefix_len,
        if_index: iface.index,
        if_name: iface.name.clone(),
    }))
}

/// Validate a configured gateway exactly like a discovered one: private, on-link on a usable
/// interface, with a private self address.
pub fn validate_override(
    o: &GatewayOverride,
    ifs: &[IfInfo],
    kernel_source: &dyn Fn(Ipv4Addr) -> Option<Ipv4Addr>,
) -> Result<Gateway, LookupError> {
    if !is_private(o.gw) {
        return Err(LookupError::NotPrivate);
    }
    let on_link = |i: &&IfInfo| {
        i.v4.iter().any(|&(a, p)| {
            a != o.gw && prefix_contains(a, p, o.gw) && o.self_ip.is_none_or(|s| s == a)
        })
    };
    let matching: Vec<&IfInfo> = ifs.iter().filter(on_link).collect();
    let usable: Vec<&IfInfo> = matching.iter().copied().filter(|i| i.usable()).collect();
    let iface = match usable.as_slice() {
        [] if matching.is_empty() => return Err(LookupError::NotOnLink),
        [] => return Err(LookupError::InterfaceUnusable),
        [one] => *one,
        many => {
            let src = kernel_source(o.gw).ok_or(LookupError::Ambiguous)?;
            *many
                .iter()
                .find(|i| i.v4.iter().any(|&(a, _)| a == src))
                .ok_or(LookupError::Ambiguous)?
        }
    };
    let mut only_self = iface.clone();
    if let Some(s) = o.self_ip {
        only_self.v4.retain(|&(a, _)| a == s);
    }
    let (self_ip, prefix_len) = pick_self(o.gw, &only_self, o.self_ip, kernel_source)?;
    Ok(Gateway {
        gw: o.gw,
        self_ip,
        prefix_len,
        if_index: iface.index,
        if_name: iface.name.clone(),
    })
}

/// The OS gateway lookup: the routing table plus the interface list, or a validated override.
///
/// Reading it sends no packet. On platforms other than macOS and Linux every lookup is
/// [`LookupError::Unsupported`], override or not.
#[derive(Debug, Clone, Default)]
pub struct SystemLookup {
    gateway_override: Option<GatewayOverride>,
}

impl SystemLookup {
    /// A lookup that discovers the gateway, or validates `gateway_override` instead.
    pub fn new(gateway_override: Option<GatewayOverride>) -> Self {
        Self { gateway_override }
    }

    /// Whether this lookup validates an override rather than discovering a route.
    pub fn is_override(&self) -> bool {
        self.gateway_override.is_some()
    }
}

impl GatewayLookup for SystemLookup {
    fn lookup(&self) -> Result<Option<Gateway>, LookupError> {
        if cfg!(not(any(target_os = "macos", target_os = "linux"))) {
            return Err(LookupError::Unsupported);
        }
        match &self.gateway_override {
            // An override replaces discovery only: the routing table is not read, but the
            // interface checks are the same.
            Some(o) => validate_override(o, &interfaces()?, &kernel_source).map(Some),
            None => {
                let routes = os::default_routes()?;
                select(&routes, &interfaces()?, &kernel_source)
            }
        }
    }
}

/// The host's interfaces, grouped by name, from `getifaddrs`.
pub fn interfaces() -> Result<Vec<IfInfo>, LookupError> {
    let raw = if_addrs::get_if_addrs().map_err(LookupError::Os)?;
    let mut out: Vec<IfInfo> = Vec::new();
    for a in raw {
        let pos = match out.iter().position(|i| i.name == a.name) {
            Some(p) => p,
            None => {
                out.push(IfInfo {
                    name: a.name.clone(),
                    index: a.index.unwrap_or(0),
                    up: true,
                    loopback: false,
                    point_to_point: false,
                    v4: Vec::new(),
                });
                out.len() - 1
            }
        };
        let i = &mut out[pos];
        i.up &= a.is_oper_up();
        i.loopback |= a.is_loopback();
        i.point_to_point |= a.is_p2p();
        if let if_addrs::IfAddr::V4(v4) = &a.addr {
            i.v4.push((v4.ip, v4.prefixlen));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn iface(name: &str, index: u32, addrs: &[(&str, u8)]) -> IfInfo {
        IfInfo {
            name: name.to_owned(),
            index,
            up: true,
            loopback: false,
            point_to_point: false,
            v4: addrs.iter().map(|(a, p)| (ip(a), *p)).collect(),
        }
    }

    fn route(gw: &str, index: u32, metric: u32) -> DefaultRoute {
        DefaultRoute {
            gw: ip(gw),
            if_index: Some(index),
            if_name: None,
            metric,
            ifa: None,
        }
    }

    fn routes(v4: Vec<DefaultRoute>) -> DefaultRoutes {
        DefaultRoutes {
            v4,
            has_v6_default: false,
        }
    }

    /// A kernel source lookup that must not be consulted.
    fn no_kernel(_: Ipv4Addr) -> Option<Ipv4Addr> {
        panic!("kernel source selection consulted unexpectedly")
    }

    /// Adapted from Go's `TestLikelyHomeRouterIP` (`net/netmon/interfaces_test.go`).
    #[test]
    fn likely_home_router_ip() {
        let mut down = iface("down0", 1, &[("10.0.0.100", 8)]);
        down.up = false;
        let ifs = vec![
            down,
            iface("ipsixonly0", 2, &[]),
            iface("fake0", 3, &[("192.168.7.100", 24)]),
        ];
        let got = select(&routes(vec![route("192.168.7.1", 3, 0)]), &ifs, &no_kernel)
            .unwrap()
            .unwrap();
        assert_eq!(got.gw, ip("192.168.7.1"));
        assert_eq!(got.self_ip, ip("192.168.7.100"));
        assert_eq!(
            (got.prefix_len, got.if_index, got.if_name.as_str()),
            (24, 3, "fake0")
        );

        // NoIPv4Addrs: the route's interface has only IPv6 addresses.
        let ifs = vec![iface("en0", 2, &[])];
        assert!(matches!(
            select(&routes(vec![route("192.168.7.1", 2, 0)]), &ifs, &no_kernel),
            Err(LookupError::NotOnLink)
        ));
    }

    /// Adapted from Go's `TestLikelyHomeRouterIP_Prefix` (tailscale/tailscale#10466): an earlier
    /// interface without the gateway on-link is never picked.
    #[test]
    fn likely_home_router_ip_prefix() {
        let ifs = vec![
            iface("docker0", 1, &[("172.17.0.0", 16)]),
            iface("fake0", 2, &[("192.168.7.100", 24)]),
        ];
        let got = select(&routes(vec![route("192.168.7.1", 2, 0)]), &ifs, &no_kernel)
            .unwrap()
            .unwrap();
        assert_eq!(got.self_ip, ip("192.168.7.100"));
        assert_eq!(got.if_name, "fake0");
    }

    #[test]
    fn no_default_route_is_offline() {
        assert!(matches!(select(&routes(vec![]), &[], &no_kernel), Ok(None)));
    }

    /// An IPv6-only default is a typed error.
    #[test]
    fn ipv6_only_default() {
        let r = DefaultRoutes {
            v4: vec![],
            has_v6_default: true,
        };
        assert!(matches!(
            select(&r, &[], &no_kernel),
            Err(LookupError::GatewayIpv6)
        ));
    }

    /// A public best default is `NotPrivate`, never a fall-through to the private one.
    #[test]
    fn public_best_route_does_not_fall_through() {
        let ifs = vec![
            iface("en0", 1, &[("203.0.113.5", 24)]),
            iface("en1", 2, &[("192.168.1.20", 24)]),
        ];
        let r = routes(vec![
            route("203.0.113.1", 1, 0),
            route("192.168.1.1", 2, 100),
        ]);
        assert!(matches!(
            select(&r, &ifs, &no_kernel),
            Err(LookupError::NotPrivate)
        ));
        // CGNAT and link-local gateways are not private either.
        for gw in ["100.64.0.1", "169.254.1.1"] {
            let r = routes(vec![route(gw, 2, 0)]);
            assert!(matches!(
                select(&r, &ifs, &no_kernel),
                Err(LookupError::NotPrivate)
            ));
        }
    }

    #[test]
    fn lowest_metric_wins_and_ties_are_ambiguous() {
        let ifs = vec![
            iface("eth0", 1, &[("192.168.1.20", 24)]),
            iface("eth1", 2, &[("10.0.0.20", 24)]),
        ];
        let r = routes(vec![
            route("10.0.0.1", 2, 600),
            route("192.168.1.1", 1, 100),
        ]);
        let got = select(&r, &ifs, &no_kernel).unwrap().unwrap();
        assert_eq!(got.gw, ip("192.168.1.1"));

        let tie = routes(vec![
            route("10.0.0.1", 2, 100),
            route("192.168.1.1", 1, 100),
        ]);
        assert!(matches!(
            select(&tie, &ifs, &no_kernel),
            Err(LookupError::Ambiguous)
        ));
        // The same route listed twice is not a tie.
        let dup = routes(vec![
            route("192.168.1.1", 1, 100),
            route("192.168.1.1", 1, 100),
        ]);
        assert!(select(&dup, &ifs, &no_kernel).unwrap().is_some());
    }

    /// Unusable interfaces are typed errors.
    #[test]
    fn unusable_interfaces() {
        let r = routes(vec![route("192.168.1.1", 1, 0)]);
        let mut p2p = iface("utun3", 1, &[("192.168.1.20", 24)]);
        p2p.point_to_point = true;
        let mut down = iface("en0", 1, &[("192.168.1.20", 24)]);
        down.up = false;
        let mut lo = iface("lo0", 1, &[("192.168.1.20", 24)]);
        lo.loopback = true;
        for i in [p2p, down, lo] {
            assert!(matches!(
                select(&r, &[i], &no_kernel),
                Err(LookupError::InterfaceUnusable)
            ));
        }
        // The interface vanished between the dump and the address scan.
        let gone = vec![iface("en1", 2, &[("192.168.1.20", 24)])];
        assert!(matches!(
            select(&r, &gone, &no_kernel),
            Err(LookupError::InterfaceUnusable)
        ));
        // A by-name route (Linux) resolves by name.
        let mut by_name = route("192.168.1.1", 0, 0);
        by_name.if_index = None;
        by_name.if_name = Some("en1".to_owned());
        assert!(
            select(&routes(vec![by_name]), &gone, &no_kernel)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn overlapping_subnets_use_the_route_interface() {
        let ifs = vec![
            iface("en0", 1, &[("192.168.1.10", 24)]),
            iface("en1", 2, &[("192.168.1.20", 24)]),
        ];
        let got = select(&routes(vec![route("192.168.1.1", 2, 0)]), &ifs, &no_kernel)
            .unwrap()
            .unwrap();
        assert_eq!((got.self_ip, got.if_index), (ip("192.168.1.20"), 2));
    }

    /// Self-IP selection with several candidates.
    #[test]
    fn self_ip_selection() {
        let ifs = vec![iface(
            "en0",
            1,
            &[("192.168.1.20", 24), ("192.168.1.21", 24), ("10.9.0.2", 16)],
        )];
        // The route's RTAX_IFA wins when it is a candidate.
        let mut r = route("192.168.1.1", 1, 0);
        r.ifa = Some(ip("192.168.1.21"));
        let got = select(&routes(vec![r.clone()]), &ifs, &no_kernel)
            .unwrap()
            .unwrap();
        assert_eq!(got.self_ip, ip("192.168.1.21"));
        // An RTAX_IFA that is not on the gateway's prefix is ignored; the kernel decides.
        r.ifa = Some(ip("10.9.0.2"));
        let kernel = |_| Some(ip("192.168.1.20"));
        let got = select(&routes(vec![r.clone()]), &ifs, &kernel)
            .unwrap()
            .unwrap();
        assert_eq!(got.self_ip, ip("192.168.1.20"));
        // The kernel picks an address that is not a candidate: ambiguous.
        let disagree = |_| Some(ip("10.9.0.2"));
        assert!(matches!(
            select(&routes(vec![r.clone()]), &ifs, &disagree),
            Err(LookupError::Ambiguous)
        ));
        assert!(matches!(
            select(&routes(vec![r]), &ifs, &|_| None),
            Err(LookupError::Ambiguous)
        ));
    }

    #[test]
    fn self_ip_must_be_private() {
        // 192.0.2.5/8 contains the private gateway 192.168.1.1, but 192.0.2.5 is not private.
        let ifs = vec![iface("en0", 1, &[("192.0.2.5", 8)])];
        assert!(matches!(
            select(&routes(vec![route("192.168.1.1", 1, 0)]), &ifs, &no_kernel),
            Err(LookupError::NotPrivate)
        ));
    }

    /// A self address with a /0../7 or /32 prefix never makes a gateway "on-link".
    #[test]
    fn implausible_prefixes_are_not_on_link() {
        for p in [0, 1, 7, 32] {
            let ifs = vec![iface("en0", 1, &[("192.168.1.20", p)])];
            assert!(
                matches!(
                    select(&routes(vec![route("10.0.0.1", 1, 0)]), &ifs, &no_kernel),
                    Err(LookupError::NotOnLink)
                ),
                "/{p}"
            );
        }
        let ifs = vec![iface("en0", 1, &[("10.1.2.3", 8)])];
        assert!(select(&routes(vec![route("10.0.0.1", 1, 0)]), &ifs, &no_kernel).is_ok());
    }

    /// The override goes through the same validation.
    #[test]
    fn override_validation() {
        let ifs = vec![
            iface("en0", 4, &[("192.168.1.20", 24)]),
            iface("en1", 5, &[("10.0.0.20", 8)]),
        ];
        let o = |s: &str| s.parse::<GatewayOverride>().unwrap();
        let got = validate_override(&o("192.168.1.1"), &ifs, &no_kernel).unwrap();
        assert_eq!((got.self_ip, got.if_index), (ip("192.168.1.20"), 4));
        let got = validate_override(&o("10.0.0.1,10.0.0.20"), &ifs, &no_kernel).unwrap();
        assert_eq!(got.if_name, "en1");
        // Public gateway: rejected.
        assert!(matches!(
            validate_override(&o("203.0.113.1"), &ifs, &no_kernel),
            Err(LookupError::NotPrivate)
        ));
        // Not on any interface, or the given self address does not hold it.
        assert!(matches!(
            validate_override(&o("172.16.0.1"), &ifs, &no_kernel),
            Err(LookupError::NotOnLink)
        ));
        assert!(matches!(
            validate_override(&o("192.168.1.1,10.0.0.20"), &ifs, &no_kernel),
            Err(LookupError::NotOnLink)
        ));
        // On-link only through a VPN interface.
        let mut vpn = iface("utun3", 9, &[("172.16.0.2", 24)]);
        vpn.point_to_point = true;
        assert!(matches!(
            validate_override(&o("172.16.0.1"), &[vpn], &no_kernel),
            Err(LookupError::InterfaceUnusable)
        ));
        assert!("192.168.1.1,".parse::<GatewayOverride>().is_err());
        assert!("x".parse::<GatewayOverride>().is_err());
    }

    #[test]
    fn prefix_math() {
        assert!(prefix_contains(ip("192.168.1.20"), 24, ip("192.168.1.1")));
        assert!(!prefix_contains(ip("192.168.1.20"), 24, ip("192.168.2.1")));
        assert!(prefix_contains(ip("192.168.1.20"), 0, ip("203.0.113.9")));
        assert!(prefix_contains(ip("192.168.1.20"), 32, ip("192.168.1.20")));
        assert!(!prefix_contains(ip("192.168.1.20"), 33, ip("192.168.1.20")));
    }

    /// Go's `TestLikelyHomeRouterIP_NoMocks`: the real interface scan works. A local read only;
    /// no packet is sent.
    #[test]
    fn interfaces_no_mocks() {
        let ifs = interfaces().unwrap();
        assert!(ifs.iter().any(|i| i.loopback), "{ifs:?}");
    }

    /// The real lookup runs end to end (routing-table read, interface scan, and at most a
    /// never-sending `connect()`); its result depends on the host, so it is only printed.
    #[test]
    fn system_lookup_no_mocks() {
        let got = SystemLookup::new(None).lookup();
        println!("SystemLookup: {got:?}");
        if cfg!(any(target_os = "macos", target_os = "linux")) {
            assert!(!matches!(got, Err(LookupError::Unsupported)));
        }
    }
}
