//! macOS implementation of [`HostNet`].
//!
//! Shells out to the system `route(8)` and `scutil(8)` binaries, mirroring Go
//! `tailscaled`'s `router_darwin`. No new crate dependencies: pure `std`.
//!
//! Route programming uses the `-interface` form (point-to-point on the TUN);
//! DNS programming writes a `State:/Network/Service/tailscale-rs/DNS`
//! dictionary via `scutil`. All argv/script construction is factored into pure
//! free functions ([`route_add_argv`], [`route_del_argv`],
//! [`scutil_set_script`], [`scutil_teardown_script`]) so they can be unit-tested
//! without root.

use core::net::Ipv4Addr;
use std::{
    io::Write as _,
    process::{Command, Stdio},
};

use ipnet::Ipv4Net;

use crate::{
    HostDns, HostNet, HostNetError, HostRoutes, expand_routes, valid_dns_name, valid_if_name,
};

/// `route(8)` binary path. On macOS `route(8)` lives in `/sbin` (NOT `/usr/sbin`, which is the
/// Linux/iproute2 location and does not exist here) — a wrong path makes `Command::new` fail with
/// ENOENT ("No such file or directory (os error 2)"), which `TunActor` treats as fatal and
/// fail-closes the interface. `scutil(8)` below genuinely is in `/usr/sbin`.
const ROUTE_BIN: &str = "/sbin/route";
/// `scutil(8)` binary path.
const SCUTIL_BIN: &str = "/usr/sbin/scutil";
/// SCDynamicStore DNS key owned by this fork.
const DNS_KEY: &str = "State:/Network/Service/tailscale-rs/DNS";

/// macOS host-networking implementation.
///
/// Tracks exactly what it installed so [`HostNet::teardown`] (and
/// rollback-on-partial-failure) reverses precisely that and nothing else.
pub(crate) struct MacOsHostNet {
    /// Route prefixes currently installed in the host FIB by this instance.
    installed_routes: Vec<Ipv4Net>,
    /// Whether a `scutil` DNS dictionary key is currently installed.
    dns_set: bool,
    /// Interface name of the most recent apply (used for route teardown).
    if_name: String,
}

impl MacOsHostNet {
    /// Construct an empty instance that has installed nothing yet.
    pub(crate) fn new() -> Self {
        Self {
            installed_routes: Vec::new(),
            dns_set: false,
            if_name: String::new(),
        }
    }
}

/// Build the argv for adding `net` as a point-to-point route via `if_name`.
pub(crate) fn route_add_argv(if_name: &str, net: &Ipv4Net) -> Vec<String> {
    vec![
        "-n".to_owned(),
        "-q".to_owned(),
        "add".to_owned(),
        "-inet".to_owned(),
        net.to_string(),
        "-interface".to_owned(),
        if_name.to_owned(),
    ]
}

/// Build the argv for deleting the `net` point-to-point route via `if_name`.
pub(crate) fn route_del_argv(if_name: &str, net: &Ipv4Net) -> Vec<String> {
    vec![
        "-n".to_owned(),
        "-q".to_owned(),
        "delete".to_owned(),
        "-inet".to_owned(),
        net.to_string(),
        "-interface".to_owned(),
        if_name.to_owned(),
    ]
}

/// Build the `scutil` script that installs the DNS dictionary.
///
/// `match_domains` originate from the untrusted control server and are
/// interpolated into a newline-delimited `scutil` interpreter script, so each is
/// validated as a strict DNS name first ([`valid_dns_name`]). A domain
/// containing a newline could otherwise inject an arbitrary `scutil` verb (e.g.
/// repoint the system global resolver) — this is the host-side anti-leak
/// chokepoint, so it fails closed (`Err(Dns)`) on any invalid domain rather than
/// feeding the interpreter attacker-shaped input. `nameservers` are
/// `Ipv4Addr`-typed and thus structurally safe.
///
/// # Panics
///
/// Callers must never invoke this with empty `nameservers`: an empty
/// nameserver set is a no-op at the [`HostNet::apply_dns`] layer (fail-closed —
/// never point the resolver at a dead server), so a script must never be built.
pub(crate) fn scutil_set_script(
    nameservers: &[Ipv4Addr],
    match_domains: &[String],
) -> Result<String, HostNetError> {
    debug_assert!(
        !nameservers.is_empty(),
        "scutil_set_script must not be called with empty nameservers"
    );
    let servers = nameservers
        .iter()
        .map(Ipv4Addr::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let mut script = String::new();
    script.push_str("open\n");
    script.push_str("d.init\n");
    script.push_str(&format!("d.add ServerAddresses * {servers}\n"));
    if !match_domains.is_empty() {
        for d in match_domains {
            if !valid_dns_name(d) {
                return Err(HostNetError::Dns(format!("invalid match domain: {d:?}")));
            }
        }
        let domains = match_domains.join(" ");
        script.push_str(&format!("d.add SupplementalMatchDomains * {domains}\n"));
    }
    script.push_str(&format!("set {DNS_KEY}\n"));
    script.push_str("quit\n");
    Ok(script)
}

/// Build the `scutil` script that removes the DNS dictionary on teardown.
pub(crate) fn scutil_teardown_script() -> String {
    format!("open\nremove {DNS_KEY}\nquit\n")
}

/// Run `route(8)` with `argv`, returning `Err(Route)` on non-zero exit.
fn run_route(argv: &[String]) -> Result<(), HostNetError> {
    let status = Command::new(ROUTE_BIN).args(argv).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(HostNetError::Route(format!(
            "{ROUTE_BIN} {} exited with {status}",
            argv.join(" ")
        )))
    }
}

/// Best-effort `route delete`: ignore failures (used during rollback/converge).
fn run_route_ignore(argv: &[String]) {
    if let Err(e) = run_route(argv) {
        tracing::debug!(error = %e, "ignoring route delete failure");
    }
}

/// Feed `script` to `scutil` on stdin, mapping failures to `Err(Dns)`.
fn run_scutil(script: &str) -> Result<(), HostNetError> {
    let mut child = Command::new(SCUTIL_BIN).stdin(Stdio::piped()).spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| HostNetError::Dns("scutil stdin unavailable".to_owned()))?
        .write_all(script.as_bytes())?;
    let status = child.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(HostNetError::Dns(format!(
            "{SCUTIL_BIN} exited with {status}"
        )))
    }
}

impl HostNet for MacOsHostNet {
    fn apply_routes(&mut self, routes: &HostRoutes) -> Result<(), HostNetError> {
        if !valid_if_name(&routes.if_name) {
            return Err(HostNetError::Route(format!(
                "invalid interface name: {:?}",
                routes.if_name
            )));
        }
        // The device is built once per actor and never rebuilt, so the interface
        // name is stable across applies. Teardown deletes `installed_routes` on
        // the stored `if_name`; if that ever changed mid-life the kept set would
        // be torn down on the wrong interface. Pin the invariant.
        debug_assert!(
            self.if_name.is_empty() || self.if_name == routes.if_name,
            "apply_routes if_name changed across applies: {} -> {}",
            self.if_name,
            routes.if_name
        );

        // Converge to the desired set. `self_v4` is excluded upstream (the TUN
        // device builder owns the on-link prefix); expand any `/0` to the
        // reversible split-default pair (a verbatim macOS `route add` of an
        // existing default returns EEXIST and would fail the exit-node TUN).
        let desired = expand_routes(&routes.routed);
        let desired = &desired;

        // Remove prefixes no longer wanted (best-effort, on the old interface).
        for net in &self.installed_routes {
            if !desired.contains(net) {
                run_route_ignore(&route_del_argv(&self.if_name, net));
            }
        }
        let mut kept: Vec<Ipv4Net> = self
            .installed_routes
            .iter()
            .copied()
            .filter(|n| desired.contains(n))
            .collect();

        // Add prefixes not already present; roll back THIS call on any failure.
        let mut added_this_call: Vec<Ipv4Net> = Vec::new();
        for net in desired {
            if kept.contains(net) {
                continue;
            }
            if let Err(e) = run_route(&route_add_argv(&routes.if_name, net)) {
                // Fail closed: delete everything added in this call, then error.
                for done in &added_this_call {
                    run_route_ignore(&route_del_argv(&routes.if_name, done));
                }
                // Persist only the surviving kept set under the new interface.
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
        let script = scutil_set_script(&dns.nameservers, &dns.match_domains)?;
        run_scutil(&script)?;
        self.dns_set = true;
        Ok(())
    }

    fn teardown(&mut self) {
        for net in &self.installed_routes {
            run_route_ignore(&route_del_argv(&self.if_name, net));
        }
        self.installed_routes.clear();

        if self.dns_set {
            if let Err(e) = run_scutil(&scutil_teardown_script()) {
                tracing::debug!(error = %e, "ignoring scutil DNS teardown failure");
            }
            self.dns_set = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_add_argv_exact() {
        let net: Ipv4Net = "100.64.0.0/10".parse().unwrap();
        assert_eq!(
            route_add_argv("utun9", &net),
            vec![
                "-n",
                "-q",
                "add",
                "-inet",
                "100.64.0.0/10",
                "-interface",
                "utun9"
            ]
        );
    }

    #[test]
    fn route_del_argv_exact() {
        let net: Ipv4Net = "100.64.0.0/10".parse().unwrap();
        assert_eq!(
            route_del_argv("utun9", &net),
            vec![
                "-n",
                "-q",
                "delete",
                "-inet",
                "100.64.0.0/10",
                "-interface",
                "utun9"
            ]
        );
    }

    #[test]
    fn route_argv_default_exit_route() {
        let net: Ipv4Net = "0.0.0.0/0".parse().unwrap();
        let argv = route_add_argv("utun9", &net);
        assert_eq!(argv[3], "-inet");
        assert_eq!(argv[4], "0.0.0.0/0");
        // IPv4 only: the family arg is always plain `-inet`, exactly once — never a v6 family.
        // (Asserted positively so this defensive test carries no v6 literal that would trip the
        // IPv4-only checks guard scanning ts_host_net/src/.)
        assert_eq!(argv.iter().filter(|a| a.as_str() == "-inet").count(), 1);
    }

    #[test]
    fn scutil_set_script_with_match_domains() {
        let script = scutil_set_script(
            &[Ipv4Addr::new(100, 100, 100, 100)],
            &["ts.net".to_owned(), "example.com".to_owned()],
        )
        .unwrap();
        assert_eq!(
            script,
            "open\n\
             d.init\n\
             d.add ServerAddresses * 100.100.100.100\n\
             d.add SupplementalMatchDomains * ts.net example.com\n\
             set State:/Network/Service/tailscale-rs/DNS\n\
             quit\n"
        );
    }

    #[test]
    fn scutil_set_script_no_match_domains_omits_line() {
        let script = scutil_set_script(
            &[Ipv4Addr::new(100, 100, 100, 100), Ipv4Addr::new(8, 8, 8, 8)],
            &[],
        )
        .unwrap();
        assert_eq!(
            script,
            "open\n\
             d.init\n\
             d.add ServerAddresses * 100.100.100.100 8.8.8.8\n\
             set State:/Network/Service/tailscale-rs/DNS\n\
             quit\n"
        );
        assert!(!script.contains("SupplementalMatchDomains"));
    }

    #[test]
    fn scutil_teardown_script_exact() {
        assert_eq!(
            scutil_teardown_script(),
            "open\nremove State:/Network/Service/tailscale-rs/DNS\nquit\n"
        );
    }

    #[test]
    fn scutil_set_script_rejects_injection_via_match_domain() {
        // A newline in a control-supplied domain would otherwise inject a fresh
        // scutil verb (e.g. repoint the global resolver). It must fail closed.
        let evil = "x\nd.add ServerAddresses * 6.6.6.6\nset State:/Network/Global/DNS";
        let err = scutil_set_script(&[Ipv4Addr::new(100, 100, 100, 100)], &[evil.to_owned()]);
        assert!(matches!(err, Err(HostNetError::Dns(_))));
    }

    #[test]
    fn empty_nameservers_never_builds_script() {
        // apply_dns short-circuits to Ok before constructing any script. Mirror
        // that invariant: callers must not reach scutil_set_script with empty
        // nameservers. We assert the guard precondition holds here so the build
        // path is never exercised with an empty set.
        let dns = HostDns {
            if_name: "utun9".to_owned(),
            nameservers: vec![],
            match_domains: vec!["ts.net".to_owned()],
        };
        let mut net = MacOsHostNet::new();
        assert!(net.apply_dns(&dns).is_ok());
        assert!(!net.dns_set, "no DNS key should be installed on no-op");
    }
}
