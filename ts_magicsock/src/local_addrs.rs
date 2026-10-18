//! Host interface addresses for local self-endpoints, and the address classes that must never be
//! advertised.
//!
//! A socket bound to the unspecified address (`0.0.0.0:port`) has no address of its own a peer
//! could dial. Go's magicsock replaces such a bind with the host's interface addresses
//! (`wgengine/magicsock/magicsock.go` `determineEndpoints`, using `net/netmon/state.go`
//! `LocalAddresses`); [`local_addresses`] ports that selection.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::{collections::HashMap, io, sync::Arc};

/// One address assigned to a host interface: the parts of a `getifaddrs` entry that
/// [`local_addresses`] needs, in a form a test can build.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InterfaceAddr {
    /// The interface name, e.g. `en0`.
    pub(crate) name: String,
    /// The address assigned to the interface.
    pub(crate) ip: IpAddr,
    /// The address's prefix length.
    pub(crate) prefix_len: u8,
    /// Whether the interface is administratively up (Go: `net.FlagUp`).
    pub(crate) up: bool,
    /// Whether the interface is a loopback interface (Go: `net.FlagLoopback`), whatever the
    /// class of this address.
    pub(crate) loopback_iface: bool,
}

/// Where [`MagicSock`](crate::MagicSock) reads the host's interface addresses. Production reads
/// `getifaddrs` ([`system_interface_addrs`]); tests inject a fixed list.
pub(crate) type InterfaceAddrSource = Arc<dyn Fn() -> io::Result<Vec<InterfaceAddr>> + Send + Sync>;

/// The host's interface addresses, from `getifaddrs`.
///
/// `if_addrs` reports `IFF_RUNNING` as "up" on Unix and does not expose `IFF_LOOPBACK`, while Go
/// selects on `IFF_UP` and `IFF_LOOPBACK`; on Apple and Linux those two flags are read here
/// directly. Elsewhere (Windows, whose operational status is what Go uses there too) the
/// `if_addrs` view stands, with loopback judged by the address.
pub(crate) fn system_interface_addrs() -> io::Result<Vec<InterfaceAddr>> {
    let flags = interface_flags();
    Ok(if_addrs::get_if_addrs()?
        .into_iter()
        .map(|iface| {
            let (up, loopback_iface) = flags
                .get(&iface.name)
                .copied()
                .unwrap_or((iface.is_oper_up(), iface.is_loopback()));
            InterfaceAddr {
                ip: iface.ip(),
                prefix_len: match &iface.addr {
                    if_addrs::IfAddr::V4(a) => a.prefixlen,
                    if_addrs::IfAddr::V6(a) => a.prefixlen,
                },
                up,
                loopback_iface,
                name: iface.name,
            }
        })
        .collect())
}

/// `(IFF_UP, IFF_LOOPBACK)` for each interface name, from `getifaddrs`. Empty if the call fails;
/// the caller then falls back to the `if_addrs` view.
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn interface_flags() -> HashMap<String, (bool, bool)> {
    let mut out = HashMap::new();
    let mut head: *mut libc::ifaddrs = core::ptr::null_mut();
    // SAFETY: `getifaddrs` writes a list head to `head`, which we free once below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return out;
    }
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is a node of the list `getifaddrs` returned, live until `freeifaddrs`.
        let ifa = unsafe { &*cur };
        if !ifa.ifa_name.is_null() {
            // SAFETY: `ifa_name` is a NUL-terminated string owned by the list.
            let name = unsafe { core::ffi::CStr::from_ptr(ifa.ifa_name) };
            let flags = ifa.ifa_flags as libc::c_int;
            out.insert(
                name.to_string_lossy().into_owned(),
                (flags & libc::IFF_UP != 0, flags & libc::IFF_LOOPBACK != 0),
            );
        }
        cur = ifa.ifa_next;
    }
    // SAFETY: `head` came from a successful `getifaddrs` and is freed exactly once.
    unsafe { libc::freeifaddrs(head) };
    out
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn interface_flags() -> HashMap<String, (bool, bool)> {
    HashMap::new()
}

/// Go's `isProblematicInterface` (`net/netmon/state.go:38-53`): ZeroTier (`zt*`, or a Windows
/// name containing `ZeroTier`) and NetBird (`wt0`) interfaces carry overlay traffic that disco
/// must not be sent over.
fn is_problematic_interface(name: &str) -> bool {
    name.starts_with("zt") || name == "wt0" || (cfg!(windows) && name.contains("ZeroTier"))
}

/// Go's `tsaddr.IsTailscaleIP`: the CGNAT range `100.64.0.0/10` minus the ChromeOS VM range
/// `100.115.92.0/23`, and the Tailscale ULA `fd7a:115c:a1e0::/48`. A tailnet address is reachable
/// only through the tailnet, so offering it as an underlay endpoint is circular.
fn is_tailscale_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            let cgnat = o[0] == 100 && (o[1] & 0xc0) == 64;
            let chromeos_vm = o[0] == 100 && o[1] == 115 && (o[2] & 0xfe) == 92;
            cgnat && !chromeos_vm
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            s[0] == 0xfd7a && s[1] == 0x115c && s[2] == 0xa1e0
        }
    }
}

/// The interface addresses a wildcard-bound socket can be reached at, in Go's order: Go's
/// `LocalAddresses` "regular" set.
///
/// Skips down, loopback and problematic interfaces, Tailscale addresses, loopback addresses and
/// IPv6 link-local.
/// IPv4 link-local and IPv6 unique-local addresses are used only when nothing else is (Go: "AWS
/// Lambda and Azure App Services use NAT with these"). At most two IPv6 addresses per subnet are
/// kept. Go's further fallback to loopback when there is no address at all is not ported: a
/// loopback endpoint is useless to every remote peer (see [`is_advertisable`]).
pub(crate) fn local_addresses(ifaces: &[InterfaceAddr]) -> Vec<IpAddr> {
    let mut regular4 = Vec::new();
    let mut regular6 = Vec::new();
    let mut linklocal4 = Vec::new();
    let mut ula6 = Vec::new();
    let mut per_subnet6: HashMap<(String, Ipv6Addr), usize> = HashMap::new();

    for iface in ifaces {
        if !iface.up || is_problematic_interface(&iface.name) {
            continue;
        }
        let ip = iface.ip.to_canonical();
        if is_tailscale_ip(ip) || ip.is_loopback() || iface.loopback_iface {
            continue;
        }
        match ip {
            IpAddr::V4(v4) if v4.is_link_local() => linklocal4.push(ip),
            IpAddr::V6(v6) if v6.is_unicast_link_local() => {}
            IpAddr::V6(v6) if v6.is_unique_local() => ula6.push(ip),
            IpAddr::V4(_) => regular4.push(ip),
            IpAddr::V6(v6) => {
                let count = per_subnet6
                    .entry((iface.name.clone(), mask_v6(v6, iface.prefix_len)))
                    .or_default();
                if *count < 2 {
                    regular6.push(ip);
                }
                *count += 1;
            }
        }
    }
    if regular4.is_empty() && regular6.is_empty() {
        regular4 = linklocal4;
        regular6 = ula6;
    }
    let mut regular: Vec<IpAddr> = regular4.into_iter().chain(regular6).collect();
    regular.sort();
    regular.dedup();
    regular
}

/// `ip` masked to its first `prefix_len` bits.
fn mask_v6(ip: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
    let bits = u128::from(ip);
    let mask = match prefix_len {
        0 => 0,
        n if n >= 128 => u128::MAX,
        n => u128::MAX << (128 - u32::from(n)),
    };
    Ipv6Addr::from(bits & mask)
}

/// Whether `ip` may appear in an endpoint advertised to control or sent in a `CallMeMaybe`.
///
/// Never: the unspecified address, multicast, IPv4 broadcast. Loopback only when the socket is
/// itself bound to loopback, which only a same-host peer can use; this matches Go, which
/// advertises a concrete bind address as it is (`magicsock.go` `determineEndpoints`) and never
/// takes loopback from interface enumeration while any other address exists.
pub(crate) fn is_advertisable(ip: IpAddr, bound_to_loopback: bool) -> bool {
    let ip = ip.to_canonical();
    if ip.is_unspecified() || ip.is_multicast() || ip == IpAddr::V4(Ipv4Addr::BROADCAST) {
        return false;
    }
    !ip.is_loopback() || bound_to_loopback
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str, ip: &str, prefix_len: u8) -> InterfaceAddr {
        InterfaceAddr {
            name: name.into(),
            ip: ip.parse().unwrap(),
            prefix_len,
            up: true,
            loopback_iface: name.starts_with("lo"),
        }
    }

    #[test]
    fn local_addresses_follows_go_selection() {
        let mut down = iface("en7", "192.168.60.5", 24);
        down.up = false;
        let ifaces = [
            iface("lo0", "127.0.0.1", 8),
            iface("lo0", "::1", 128),
            iface("en0", "fe80::1", 64),
            iface("en0", "192.168.50.76", 24),
            iface("en0", "2001:db8:1::1", 64),
            iface("en0", "2001:db8:1::2", 64),
            iface("en0", "2001:db8:1::3", 64),
            iface("en0", "fd00::1", 64),
            iface("en5", "169.254.10.20", 16),
            iface("utun4", "100.101.102.103", 32),
            iface("utun4", "fd7a:115c:a1e0::1", 128),
            iface("zt0", "10.147.17.5", 24),
            // A private service address aliased onto the loopback interface.
            iface("lo0", "10.200.0.1", 32),
            down,
        ];
        let got: Vec<String> = local_addresses(&ifaces)
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(got, ["192.168.50.76", "2001:db8:1::1", "2001:db8:1::2"]);
    }

    #[test]
    fn local_addresses_falls_back_to_link_local_v4_and_ula() {
        let ifaces = [
            iface("lo0", "127.0.0.1", 8),
            iface("en0", "169.254.10.20", 16),
            iface("en0", "fd00::1", 64),
            iface("en0", "fe80::1", 64),
        ];
        let got: Vec<String> = local_addresses(&ifaces)
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(got, ["169.254.10.20", "fd00::1"]);
    }

    #[test]
    fn problematic_interfaces_follow_go() {
        assert!(is_problematic_interface("zt3jnx2ce"));
        assert!(is_problematic_interface("wt0"));
        assert!(!is_problematic_interface("en0"));
        assert_eq!(
            is_problematic_interface("ZeroTier One [8056c2e21c000001]"),
            cfg!(windows)
        );
    }

    /// The production source reports `IFF_UP` and `IFF_LOOPBACK` as Go reads them: the
    /// loopback interface is flagged as such and up. Only that invariant is checked, so the test
    /// does not depend on the host's other interfaces staying put.
    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    #[test]
    fn system_source_reads_up_and_loopback_flags() {
        let addrs = system_interface_addrs().unwrap();
        let lo = addrs
            .iter()
            .find(|a| a.ip.is_loopback())
            .expect("a loopback address");
        assert!(lo.loopback_iface && lo.up, "{lo:?}");
    }

    #[test]
    fn chromeos_vm_range_is_not_a_tailscale_ip() {
        assert!(is_tailscale_ip("100.64.0.1".parse().unwrap()));
        assert!(is_tailscale_ip("100.127.255.254".parse().unwrap()));
        assert!(!is_tailscale_ip("100.115.92.7".parse().unwrap()));
        assert!(!is_tailscale_ip("192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn is_advertisable_rejects_unusable_classes() {
        for s in ["0.0.0.0", "::", "224.0.0.1", "ff02::1", "255.255.255.255"] {
            assert!(!is_advertisable(s.parse().unwrap(), true), "{s}");
        }
        assert!(!is_advertisable("127.0.0.1".parse().unwrap(), false));
        assert!(!is_advertisable("::ffff:127.0.0.1".parse().unwrap(), false));
        assert!(is_advertisable("127.0.0.1".parse().unwrap(), true));
        assert!(is_advertisable("192.168.50.76".parse().unwrap(), false));
        assert!(is_advertisable("203.0.113.5".parse().unwrap(), false));
    }
}
