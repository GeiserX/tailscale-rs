//! Linux implementation of [`HostNet`].
//!
//! Shells out to the `ip(8)` (iproute2) binary for routing and, when present,
//! `resolvectl(1)` (systemd-resolved) for DNS. No new crate dependencies: pure
//! `std`. All argv construction is factored into pure free functions
//! ([`route_replace_argv`], [`route_del_argv`], [`resolvectl_dns_argv`],
//! [`resolvectl_domain_argv`], [`resolvectl_revert_argv`]) so they can be
//! unit-tested without root and on any platform (they carry no `cfg` gate); only
//! the `Command`-using glue is Linux-gated. `/0` split-default expansion lives in
//! the crate root ([`crate::expand_routes`]) so macOS and Linux cannot drift.
//!
//! IPv4-only by construction: every `ip` invocation forces `-4` and the types
//! carry no IPv6 fields, so a v6 route can never be emitted.

// The pure argv builders below are consumed by the Linux-gated `imp` module
// and by the (unconditional) unit tests. On non-Linux targets only the tests
// use them, so suppress the spurious dead-code lint there.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use core::net::Ipv4Addr;

use ipnet::Ipv4Net;

/// Build the argv for `ip` to idempotently install `net` via `if_name`.
///
/// `route replace` converges: re-applying an existing route succeeds rather
/// than erroring on a duplicate, so apply is naturally idempotent.
pub(crate) fn route_replace_argv(if_name: &str, net: &Ipv4Net) -> Vec<String> {
    vec![
        "-4".to_owned(),
        "route".to_owned(),
        "replace".to_owned(),
        net.to_string(),
        "dev".to_owned(),
        if_name.to_owned(),
    ]
}

/// Build the argv for `ip` to delete the `net` route via `if_name`.
pub(crate) fn route_del_argv(if_name: &str, net: &Ipv4Net) -> Vec<String> {
    vec![
        "-4".to_owned(),
        "route".to_owned(),
        "del".to_owned(),
        net.to_string(),
        "dev".to_owned(),
        if_name.to_owned(),
    ]
}

/// Build the argv for `resolvectl dns <if_name> <ns...>`.
pub(crate) fn resolvectl_dns_argv(if_name: &str, ns: &[Ipv4Addr]) -> Vec<String> {
    let mut argv = vec!["dns".to_owned(), if_name.to_owned()];
    argv.extend(ns.iter().map(Ipv4Addr::to_string));
    argv
}

/// Build the argv for `resolvectl domain <if_name> <dom...>`.
pub(crate) fn resolvectl_domain_argv(if_name: &str, domains: &[String]) -> Vec<String> {
    let mut argv = vec!["domain".to_owned(), if_name.to_owned()];
    argv.extend(domains.iter().cloned());
    argv
}

/// Build the argv for `resolvectl revert <if_name>` (DNS teardown).
pub(crate) fn resolvectl_revert_argv(if_name: &str) -> Vec<String> {
    vec!["revert".to_owned(), if_name.to_owned()]
}

#[cfg(target_os = "linux")]
mod imp {
    use std::process::Command;

    use ipnet::Ipv4Net;

    use super::{
        resolvectl_dns_argv, resolvectl_domain_argv, resolvectl_revert_argv, route_del_argv,
        route_replace_argv,
    };
    use crate::{
        HostDns, HostNet, HostNetError, HostRoutes, expand_routes, valid_dns_name, valid_if_name,
    };

    /// `ip(8)` binary (iproute2).
    const IP_BIN: &str = "ip";
    /// `resolvectl(1)` binary (systemd-resolved).
    const RESOLVECTL_BIN: &str = "resolvectl";

    /// Linux host-networking implementation.
    ///
    /// Tracks exactly what it installed so [`HostNet::teardown`] (and
    /// rollback-on-partial-failure) reverses precisely that and nothing else.
    pub(crate) struct LinuxHostNet {
        /// Expanded route prefixes currently installed in the host FIB.
        installed_routes: Vec<Ipv4Net>,
        /// Interface a `resolvectl` DNS config was applied to, if any.
        dns_if: Option<String>,
        /// Interface name of the most recent route apply (for teardown).
        if_name: String,
    }

    impl LinuxHostNet {
        /// Construct an empty instance that has installed nothing yet.
        pub(crate) fn new() -> Self {
            Self {
                installed_routes: Vec::new(),
                dns_if: None,
                if_name: String::new(),
            }
        }
    }

    /// Run `ip` with `argv`, returning `Err(Route)` on non-zero exit.
    fn run_ip(argv: &[String]) -> Result<(), HostNetError> {
        let status = Command::new(IP_BIN).args(argv).status()?;
        if status.success() {
            Ok(())
        } else {
            Err(HostNetError::Route(format!(
                "{IP_BIN} {} exited with {status}",
                argv.join(" ")
            )))
        }
    }

    /// Best-effort `ip route del`: ignore failures (used during rollback/teardown).
    fn run_ip_ignore(argv: &[String]) {
        if let Err(e) = run_ip(argv) {
            tracing::debug!(error = %e, "ignoring ip route del failure");
        }
    }

    /// Run `resolvectl` with `argv`. Returns `Ok(false)` (graceful skip) if the
    /// binary is absent (`ENOENT`); maps any other failure to `Err(Dns)`.
    fn run_resolvectl(argv: &[String]) -> Result<bool, HostNetError> {
        match Command::new(RESOLVECTL_BIN).args(argv).status() {
            Ok(status) if status.success() => Ok(true),
            Ok(status) => Err(HostNetError::Dns(format!(
                "{RESOLVECTL_BIN} {} exited with {status}",
                argv.join(" ")
            ))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(HostNetError::Io(e)),
        }
    }

    impl HostNet for LinuxHostNet {
        fn apply_routes(&mut self, routes: &HostRoutes) -> Result<(), HostNetError> {
            if !valid_if_name(&routes.if_name) {
                return Err(HostNetError::Route(format!(
                    "invalid interface name: {:?}",
                    routes.if_name
                )));
            }
            // The device is built once per actor and never rebuilt, so the
            // interface name is stable across applies; teardown deletes the kept
            // set on the stored `if_name`. Pin the invariant.
            debug_assert!(
                self.if_name.is_empty() || self.if_name == routes.if_name,
                "apply_routes if_name changed across applies: {} -> {}",
                self.if_name,
                routes.if_name
            );

            // `self_v4` is excluded: the TUN device builder owns the on-link
            // prefix. Expand `/0` to the split-default pair before installing.
            let desired = expand_routes(&routes.routed);

            // Remove prefixes no longer wanted (best-effort, on the old iface).
            for net in &self.installed_routes {
                if !desired.contains(net) {
                    run_ip_ignore(&route_del_argv(&self.if_name, net));
                }
            }
            let mut kept: Vec<Ipv4Net> = self
                .installed_routes
                .iter()
                .copied()
                .filter(|n| desired.contains(n))
                .collect();

            // Add prefixes not already present; roll back THIS call on failure.
            let mut added_this_call: Vec<Ipv4Net> = Vec::new();
            for net in &desired {
                if kept.contains(net) {
                    continue;
                }
                if let Err(e) = run_ip(&route_replace_argv(&routes.if_name, net)) {
                    // Fail closed: delete everything added in this call, error.
                    for done in &added_this_call {
                        run_ip_ignore(&route_del_argv(&routes.if_name, done));
                    }
                    self.installed_routes = kept;
                    self.if_name = routes.if_name.clone();
                    return Err(e);
                }
                added_this_call.push(*net);
            }

            kept.extend(added_this_call);
            self.installed_routes = kept;
            self.if_name = routes.if_name.clone();
            Ok(())
        }

        fn apply_dns(&mut self, dns: &HostDns) -> Result<(), HostNetError> {
            // Fail-closed MVP: never point the resolver at a dead server.
            if dns.nameservers.is_empty() {
                return Ok(());
            }
            if !valid_if_name(&dns.if_name) {
                return Err(HostNetError::Dns(format!(
                    "invalid interface name: {:?}",
                    dns.if_name
                )));
            }
            // Validate every control-supplied domain before it reaches the
            // resolvectl argv: reject `~.` (the "route all DNS here" wildcard),
            // leading `-` (option injection), and any non-DNS-name character.
            for d in &dns.match_domains {
                if !valid_dns_name(d) {
                    return Err(HostNetError::Dns(format!("invalid match domain: {d:?}")));
                }
            }
            // Program nameservers. A missing resolvectl is a graceful no-op +
            // warn: we never scribble /etc/resolv.conf (too easy to brick).
            if !run_resolvectl(&resolvectl_dns_argv(&dns.if_name, &dns.nameservers))? {
                tracing::warn!(
                    if_name = %dns.if_name,
                    "resolvectl not found; skipping DNS programming (resolv.conf write deferred)"
                );
                return Ok(());
            }
            // Record the interface NOW (before the domain step): the `dns` step
            // already installed state, so teardown must revert it even if the
            // following `domain` step fails. Otherwise DNS programming leaks on
            // partial failure (a fail-open the trait contract forbids).
            self.dns_if = Some(dns.if_name.clone());
            if !dns.match_domains.is_empty() {
                run_resolvectl(&resolvectl_domain_argv(&dns.if_name, &dns.match_domains))?;
            }
            Ok(())
        }

        fn teardown(&mut self) {
            for net in &self.installed_routes {
                run_ip_ignore(&route_del_argv(&self.if_name, net));
            }
            self.installed_routes.clear();

            if let Some(if_name) = self.dns_if.take() {
                if let Err(e) = run_resolvectl(&resolvectl_revert_argv(&if_name)) {
                    tracing::debug!(error = %e, "ignoring resolvectl revert failure");
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) use imp::LinuxHostNet;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_replace_argv_exact() {
        let net: Ipv4Net = "100.64.0.0/10".parse().unwrap();
        assert_eq!(
            route_replace_argv("tailscale0", &net),
            vec![
                "-4",
                "route",
                "replace",
                "100.64.0.0/10",
                "dev",
                "tailscale0"
            ]
        );
    }

    #[test]
    fn route_del_argv_exact() {
        let net: Ipv4Net = "100.64.0.0/10".parse().unwrap();
        assert_eq!(
            route_del_argv("tailscale0", &net),
            vec!["-4", "route", "del", "100.64.0.0/10", "dev", "tailscale0"]
        );
    }

    #[test]
    fn resolvectl_dns_argv_exact() {
        let ns = [Ipv4Addr::new(100, 100, 100, 100), Ipv4Addr::new(8, 8, 8, 8)];
        assert_eq!(
            resolvectl_dns_argv("tailscale0", &ns),
            vec!["dns", "tailscale0", "100.100.100.100", "8.8.8.8"]
        );
    }

    #[test]
    fn resolvectl_domain_argv_exact() {
        let domains = ["ts.net".to_owned(), "example.com".to_owned()];
        assert_eq!(
            resolvectl_domain_argv("tailscale0", &domains),
            vec!["domain", "tailscale0", "ts.net", "example.com"]
        );
    }

    #[test]
    fn resolvectl_revert_argv_exact() {
        assert_eq!(
            resolvectl_revert_argv("tailscale0"),
            vec!["revert", "tailscale0"]
        );
    }
}
