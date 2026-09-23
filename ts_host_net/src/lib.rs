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
