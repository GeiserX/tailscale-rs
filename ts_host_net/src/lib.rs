//! Host route + DNS programming for TUN transport mode.
//!
//! In TUN mode the kernel TUN interface exists but the OS has no FIB entries
//! steering tailnet/subnet/exit prefixes into it, and the stub resolver has no
//! MagicDNS pointer. This crate is the single host-integration chokepoint
//! (the host-side analogue of `ts_forwarder`'s `RealDialer`): it programs the
//! routing table and system resolver, and reverses them on teardown.
//!
//! IPv4-only by construction: there are no IPv6 fields. Programming is
//! fail-closed — a partial apply must roll back before returning `Err`, and an
//! unsupported platform returns a typed `Unsupported` error (never a silent
//! no-op success that would leave a TUN pumping on an unrouted interface).

use core::net::Ipv4Addr;

use ipnet::Ipv4Net;

#[cfg(target_os = "macos")]
mod macos;
// The Linux module is compiled everywhere so its pure argv builders and their
// unit tests are exercised on the (macOS) dev box and in CI; only the
// `Command`-using `LinuxHostNet` glue inside is `target_os = "linux"`-gated.
mod linux;
// Windows route/DNS programming is a future bead: `host_net()` returns
// `Unsupported` on Windows rather than a silent no-op success.

/// Host-FIB routes to steer into the TUN interface. IPv4-only by construction.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct HostRoutes {
    /// Name of the TUN interface routes are steered into (e.g. `utun9`).
    pub if_name: String,
    /// This node's own tailnet IPv4 address, as a host prefix.
    pub self_v4: Ipv4Net,
    /// Tailnet/subnet/exit IPv4 prefixes to route into the interface.
    pub routed: Vec<Ipv4Net>,
}

/// System-resolver programming for the TUN interface. IPv4 nameservers only.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct HostDns {
    /// Name of the TUN interface the resolver is programmed for (e.g. `utun9`).
    pub if_name: String,
    /// IPv4 nameservers (typically the MagicDNS address `100.100.100.100`).
    pub nameservers: Vec<Ipv4Addr>,
    /// Domains for which queries are directed to `nameservers`.
    pub match_domains: Vec<String>,
}

/// Errors that may be encountered during host networking operations.
#[derive(Debug, thiserror::Error)]
pub enum HostNetError {
    /// No host-networking implementation exists for this platform yet.
    #[error("host networking not supported on this platform yet")]
    Unsupported,
    /// A route programming command failed.
    #[error("route program command failed: {0}")]
    Route(String),
    /// A DNS programming command failed.
    #[error("dns program command failed: {0}")]
    Dns(String),
    /// Enumerating the host's network interfaces failed.
    #[error("interface enumeration failed: {0}")]
    Interfaces(String),
    /// An IO error was encountered.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// The single host-integration chokepoint. Implementations MUST be reversible
/// and fail-closed: `apply_*` rolls back its own partial state on error, and
/// `teardown` reverses everything installed.
pub trait HostNet: Send + Sync {
    /// Program host-FIB routes steering `routes` into the TUN interface.
    ///
    /// On error the implementation MUST roll back any partial state it
    /// installed before returning.
    fn apply_routes(&mut self, routes: &HostRoutes) -> Result<(), HostNetError>;

    /// Program the system resolver for the TUN interface.
    ///
    /// On error the implementation MUST roll back any partial state it
    /// installed before returning.
    fn apply_dns(&mut self, dns: &HostDns) -> Result<(), HostNetError>;

    /// Reverse everything previously installed via `apply_*`.
    fn teardown(&mut self);
}

/// The tailnet's CGNAT range `100.64.0.0/10` (Go `tsaddr.CGNATRange`), the range
/// [`has_cgnat_interface`] looks for on interfaces that are not ours.
const CGNAT_RANGE: Ipv4Net = Ipv4Net::new_assert(Ipv4Addr::new(100, 64, 0, 0), 10);

/// Whether any interface OTHER than `exclude_if_name` is operationally up and carries an IPv4
/// prefix overlapping `100.64.0.0/10`.
///
/// Ports Go `net/netmon`'s `HasCGNATInterface`, which walks the interface list and reports whether
/// a non-Tailscale, up interface uses the CGNAT range. The caller uses it to decide whether the
/// single `/10` host route may replace the per-peer `/32`s: if something else on this host already
/// routes part of CGNAT space, the coarse route would hijack it.
///
/// Enumeration is `if_addrs::get_if_addrs` — the same `getifaddrs(3)` wrapper `ts_magicsock` uses
/// to enumerate local disco candidates, so this adds no crate to the workspace and no process
/// spawn to the apply path. An enumeration failure is an `Err`, never a silent `false`: the caller
/// must be able to tell "nothing else uses CGNAT" from "could not look", and it treats the two
/// differently.
pub fn has_cgnat_interface(exclude_if_name: &str) -> Result<bool, HostNetError> {
    let ifaces = if_addrs::get_if_addrs()
        .map_err(|e| HostNetError::Interfaces(format!("get_if_addrs failed: {e}")))?;
    Ok(any_cgnat_interface(&ifaces, exclude_if_name))
}

/// The predicate half of [`has_cgnat_interface`], over an already-enumerated interface list.
///
/// Split out so the rule is unit-tested against fixed interface sets on every platform rather than
/// against whatever the build host happens to have plugged in (the same pure-core/thin-syscall
/// split the `route`/`scutil` argv builders use).
///
/// Three filters, each Go's:
///
/// * **not us** — our own TUN always holds a CGNAT `/32` (this node's tailnet address), so counting
///   it would make the answer unconditionally "yes" and the check a no-op. Go approximates this
///   with its `isTailscaleInterface` name/address heuristic; we can do it exactly, because the
///   caller knows the interface name it just created.
/// * **up** — Go skips `!i.IsUp()`. A down interface is not carrying anything for the `/10` to
///   steal. `is_oper_up` is POSIX `IFF_RUNNING` rather than Go's `IFF_UP`, so an administratively
///   up interface with no carrier is skipped here and counted there. That difference can only
///   *permit* the coarse route, and only for an interface that is not currently passing traffic.
/// * **overlapping** — Go compares with `Prefix.Overlaps`, not `Contains`, so an interface whose
///   prefix is shorter than `/10` and COVERS the CGNAT range counts as much as one sitting inside
///   it. IPv6 interface addresses cannot overlap a v4 prefix and are skipped.
pub(crate) fn any_cgnat_interface(ifaces: &[if_addrs::Interface], exclude_if_name: &str) -> bool {
    ifaces.iter().any(|iface| {
        if iface.name == exclude_if_name || !iface.is_oper_up() {
            return false;
        }
        let if_addrs::IfAddr::V4(v4) = &iface.addr else {
            return false;
        };
        // A prefix length the kernel reports as out of range is not a reason to answer "nothing
        // else uses CGNAT"; fall back to the address as a host route, which still catches the
        // common case of an address sitting inside the range.
        let net = Ipv4Net::new(v4.ip, v4.prefixlen)
            .unwrap_or_else(|_| Ipv4Net::new_assert(v4.ip, 32))
            .trunc();
        CGNAT_RANGE.contains(&net.network()) || net.contains(&CGNAT_RANGE.network())
    })
}

/// Expand a desired routed set for installation into the host FIB.
///
/// A literal default route `0.0.0.0/0` is NOT installed verbatim. On Linux that
/// would clobber the host's real default and be awkward to reverse; on macOS
/// `route add -inet 0.0.0.0/0` returns `EEXIST` when a default already exists,
/// which (under our fail-closed posture) would prevent the exit-node TUN from
/// coming up at all. Instead `/0` is expanded to the classic VPN split-default
/// pair `0.0.0.0/1` + `128.0.0.0/1`, which together cover the whole address
/// space and win by longest-prefix-match over the real `/0` without deleting it
/// — trivially reversible by removing the two halves. Any non-`/0` prefix passes
/// through unchanged. Shared by both platform impls so the behavior cannot drift.
pub(crate) fn expand_routes(routed: &[Ipv4Net]) -> Vec<Ipv4Net> {
    let mut out = Vec::with_capacity(routed.len() + 1);
    for net in routed {
        if net.prefix_len() == 0 {
            out.push(Ipv4Net::new(Ipv4Addr::new(0, 0, 0, 0), 1).expect("0.0.0.0/1 is valid"));
            out.push(Ipv4Net::new(Ipv4Addr::new(128, 0, 0, 0), 1).expect("128.0.0.0/1 is valid"));
        } else {
            out.push(*net);
        }
    }
    out
}

/// Validate a DNS match/search domain before it is placed into a privileged
/// resolver-programming argv or `scutil` stdin script.
///
/// This is the host-side anti-leak chokepoint's input guard: `match_domains`
/// originate from the (untrusted) control server, and the `scutil` script is a
/// newline-delimited interpreter — a domain containing a newline could inject a
/// `scutil` verb (e.g. repoint the system global resolver). A leading `-` could
/// be parsed by `resolvectl`/`ip` as an option, and `~.` is systemd-resolved's
/// "route all DNS here" wildcard. We accept only strict DNS names: non-empty,
/// `<= 253` bytes, dot-separated labels of `[a-z0-9-]` (`1..=63` bytes each),
/// and never a leading `-`. Anything else is rejected so `apply_dns` fails
/// closed rather than feeding the interpreter attacker-shaped input.
pub(crate) fn valid_dns_name(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 || s.starts_with('-') {
        return false;
    }
    s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// Validate a TUN interface name before it is placed into a route-programming
/// argv. The name is normally kernel-assigned (`utunN`/`tailscaleN`) but is
/// embedder-influenced via `TunConfig.name`, so guard it: `1..=15` bytes
/// (`IFNAMSIZ - 1`), ASCII-alphanumeric only, never a leading `-` (which
/// `ip`/`route` could parse as an option). Rejecting keeps `apply_*` fail-closed.
pub(crate) fn valid_if_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 15
        && !s.starts_with('-')
        && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Construct the platform implementation. Returns a typed `Unsupported` error
/// (NOT a silent success) on platforms without an implementation yet.
pub fn host_net() -> Result<Box<dyn HostNet>, HostNetError> {
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(macos::MacOsHostNet::new()))
    }
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(linux::LinuxHostNet::new()))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(HostNetError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn types_construct() {
        let routes = HostRoutes {
            if_name: "utun9".to_owned(),
            self_v4: "100.64.0.1/32".parse().unwrap(),
            routed: vec!["100.64.0.0/10".parse().unwrap()],
        };
        assert_eq!(routes.if_name, "utun9");
        assert_eq!(routes.routed.len(), 1);

        let dns = HostDns {
            if_name: "utun9".to_owned(),
            nameservers: vec![Ipv4Addr::new(100, 100, 100, 100)],
            match_domains: vec!["ts.net".to_owned()],
        };
        assert_eq!(dns.nameservers.len(), 1);
        assert_eq!(dns.match_domains, vec!["ts.net".to_owned()]);

        // Defaults are available for both types.
        let default_routes = HostRoutes::default();
        let default_dns = HostDns::default();
        assert!(default_routes.routed.is_empty());
        assert!(default_dns.nameservers.is_empty());
    }

    /// On macOS the platform implementation is wired (stream S2), so
    /// `host_net()` returns an `Ok` implementation rather than `Unsupported`.
    #[cfg(target_os = "macos")]
    #[test]
    fn host_net_is_supported_on_macos() {
        assert!(host_net().is_ok());
    }

    /// On Linux the platform implementation is wired (stream S3), so
    /// `host_net()` returns an `Ok` implementation rather than `Unsupported`.
    #[cfg(target_os = "linux")]
    #[test]
    fn host_net_is_supported_on_linux() {
        assert!(host_net().is_ok());
    }

    /// On platforms still without an implementation (e.g. Windows — a future
    /// bead), `host_net()` returns a typed `Unsupported` error, never a silent
    /// success.
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn host_net_is_unsupported_for_now() {
        assert!(matches!(host_net().err(), Some(HostNetError::Unsupported)));
    }

    /// Build an up IPv4 interface fixture. `prefixlen` is what the kernel reports; the netmask is
    /// derived from it so the two cannot disagree.
    fn iface(name: &str, ip: &str, prefixlen: u8) -> if_addrs::Interface {
        iface_with_status(name, ip, prefixlen, if_addrs::IfOperStatus::Up)
    }

    /// As [`iface`], with the operational status spelled out.
    fn iface_with_status(
        name: &str,
        ip: &str,
        prefixlen: u8,
        oper_status: if_addrs::IfOperStatus,
    ) -> if_addrs::Interface {
        let ip: Ipv4Addr = ip.parse().unwrap();
        if_addrs::Interface {
            name: name.to_owned(),
            addr: if_addrs::IfAddr::V4(if_addrs::Ifv4Addr {
                ip,
                netmask: Ipv4Net::new(ip, prefixlen).unwrap().netmask(),
                prefixlen,
                broadcast: None,
            }),
            index: None,
            oper_status,
            is_p2p: false,
            #[cfg(windows)]
            adapter_name: String::new(),
        }
    }

    /// A host running this fork: loopback, a LAN interface, and our own TUN holding this node's
    /// tailnet `/32`. Addresses outside CGNAT space come from the RFC 5737 documentation ranges.
    fn host_with_our_tun() -> Vec<if_addrs::Interface> {
        vec![
            iface("lo0", "127.0.0.1", 8),
            iface("en0", "192.0.2.17", 24),
            iface("utun9", "100.64.0.1", 32),
        ]
    }

    /// The base case, and the reason the exclusion exists: our own TUN always holds a CGNAT `/32`,
    /// so without excluding it by name the answer would be "yes" on every node and the coarse
    /// route would never be selected.
    #[test]
    fn cgnat_scan_ignores_our_own_tun() {
        assert!(
            !any_cgnat_interface(&host_with_our_tun(), "utun9"),
            "only our own TUN uses CGNAT space: nothing else can be hijacked by the /10"
        );
        assert!(
            any_cgnat_interface(&host_with_our_tun(), "utun7"),
            "with our TUN not excluded, its own CGNAT /32 reads as someone else's"
        );
    }

    /// Another VPN already routing part of CGNAT space is exactly what the probe is for:
    /// installing `100.64.0.0/10` would steal its traffic.
    #[test]
    fn cgnat_scan_finds_another_interfaces_cgnat_address() {
        let mut ifaces = host_with_our_tun();
        ifaces.push(iface("utun3", "100.72.0.9", 32));
        assert!(any_cgnat_interface(&ifaces, "utun9"));
    }

    /// A down interface is not using the range (Go skips `!i.IsUp()`), and a SUPERNET of CGNAT
    /// space counts even though none of its own addresses is inside the range (Go compares with
    /// `Prefix.Overlaps`, not `Contains`).
    #[test]
    fn cgnat_scan_honours_oper_status_and_overlapping_supernets() {
        let mut down = host_with_our_tun();
        down.push(iface_with_status(
            "utun3",
            "100.72.0.9",
            32,
            if_addrs::IfOperStatus::Down,
        ));
        assert!(
            !any_cgnat_interface(&down, "utun9"),
            "a down interface is not using the range"
        );

        // A /8 around a CGNAT address: its NETWORK address is outside the /10, so only the
        // second half of the overlap test (the interface prefix covering the range) can catch it.
        let mut supernet = host_with_our_tun();
        supernet.push(iface("en6", "100.64.0.9", 8));
        assert!(
            any_cgnat_interface(&supernet, "utun9"),
            "an interface whose prefix covers CGNAT space overlaps it"
        );
    }

    /// An IPv6 interface address cannot overlap a v4 prefix, and an empty list is simply "no".
    #[test]
    fn cgnat_scan_skips_v6_and_handles_an_empty_list() {
        assert!(!any_cgnat_interface(&[], "utun9"));
        let v6 = vec![if_addrs::Interface {
            name: "en0".to_owned(),
            addr: if_addrs::IfAddr::V6(if_addrs::Ifv6Addr {
                ip: "2001:db8::1".parse().unwrap(),
                netmask: "ffff:ffff:ffff:ffff::".parse().unwrap(),
                prefixlen: 64,
                broadcast: None,
            }),
            index: None,
            oper_status: if_addrs::IfOperStatus::Up,
            is_p2p: false,
            #[cfg(windows)]
            adapter_name: String::new(),
        }];
        assert!(!any_cgnat_interface(&v6, "utun9"));
    }

    /// The syscall half really runs on this host: enumeration succeeds and the answer is a plain
    /// bool, not an error. Asserting only that it is `Ok` keeps the test host-independent (what
    /// the box has plugged in is not ours to pin) while still exercising the real `getifaddrs`
    /// path the caller depends on.
    #[test]
    fn has_cgnat_interface_enumerates_this_host() {
        assert!(
            has_cgnat_interface("ts-rs-no-such-interface").is_ok(),
            "enumerating the host's interfaces must succeed on a supported platform"
        );
    }

    #[test]
    fn expand_routes_splits_default() {
        let routed: Vec<Ipv4Net> = vec!["0.0.0.0/0".parse().unwrap()];
        let split = expand_routes(&routed);
        assert_eq!(
            split,
            vec![
                "0.0.0.0/1".parse::<Ipv4Net>().unwrap(),
                "128.0.0.0/1".parse::<Ipv4Net>().unwrap(),
            ]
        );
        // Never a literal /0 reaches the FIB (would clobber the host default / EEXIST on macOS).
        assert!(!split.iter().any(|n| n.prefix_len() == 0));
    }

    #[test]
    fn expand_routes_passes_through_non_default() {
        let routed: Vec<Ipv4Net> = vec![
            "100.64.0.0/10".parse().unwrap(),
            "192.168.1.0/24".parse().unwrap(),
        ];
        assert_eq!(expand_routes(&routed), routed);
    }

    #[test]
    fn expand_routes_mixed() {
        let routed: Vec<Ipv4Net> =
            vec!["10.0.0.0/24".parse().unwrap(), "0.0.0.0/0".parse().unwrap()];
        assert_eq!(
            expand_routes(&routed),
            vec![
                "10.0.0.0/24".parse::<Ipv4Net>().unwrap(),
                "0.0.0.0/1".parse::<Ipv4Net>().unwrap(),
                "128.0.0.0/1".parse::<Ipv4Net>().unwrap(),
            ]
        );
    }

    #[test]
    fn valid_dns_name_accepts_real_domains() {
        assert!(valid_dns_name("ts.net"));
        assert!(valid_dns_name("user.example.com"));
        assert!(valid_dns_name("a-b.c-d.example"));
    }

    #[test]
    fn valid_dns_name_rejects_injection_and_wildcards() {
        // Newline (scutil verb injection), space, the `~.` resolved wildcard, leading `-`,
        // empty labels, and overlong input must all be rejected.
        assert!(!valid_dns_name("x\nd.add ServerAddresses * 6.6.6.6"));
        assert!(!valid_dns_name("a b"));
        assert!(!valid_dns_name("~."));
        assert!(!valid_dns_name("-evil.com"));
        assert!(!valid_dns_name(""));
        assert!(!valid_dns_name("a..b"));
        assert!(!valid_dns_name(&"a".repeat(254)));
    }

    #[test]
    fn valid_if_name_accepts_kernel_names_rejects_garbage() {
        assert!(valid_if_name("utun9"));
        assert!(valid_if_name("tailscale0"));
        assert!(!valid_if_name("")); // empty
        assert!(!valid_if_name("-i")); // option injection
        assert!(!valid_if_name("eth 0")); // space splits argv
        assert!(!valid_if_name("0123456789abcdef")); // 16 > IFNAMSIZ-1
    }
}
