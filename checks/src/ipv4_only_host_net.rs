//! Leak firewall: the host route/DNS programming crate must stay IPv4-only.
//!
//! WHY: `ts_host_net` is the host-side anti-leak chokepoint (the host analogue of `ts_forwarder`'s
//! `RealDialer`). In TUN transport mode it programs the OS routing table and system resolver to
//! steer tailnet traffic into the kernel TUN interface. The fork's tailnet is IPv4-only by default
//! (IPv6 is a gated, default-off overlay feature that must never wire into host programming). The
//! `HostRoutes`/`HostDns` types carry only `Ipv4Net`/`Ipv4Addr`, so v6 cannot even be represented;
//! this check is defense-in-depth against a regression that re-introduces an IPv6 route family
//! (`-inet6`), an IPv6 `ip`/`route` selector, or an `Ipv6*` type into the argv builders — any of
//! which would steer host traffic at a v6 nexthop the egress path never isolates.
//!
//! WHAT THIS CHECKS: it scans every file under `ts_host_net/src/` for specific IPv6-API tokens and
//! fails if any are found:
//!   - `inet6`        : the macOS `route` IPv6 address family (`-inet6`).
//!   - `Ipv6`         : an IPv6 type (`Ipv6Addr`/`Ipv6Net`) in the route/DNS path. (Lowercase `p`,
//!                      so it matches Rust type names, not the prose "IPv6" in doc comments.)
//!   - `enable_ipv6`  : the runtime IPv6 gate must never be read by host programming.
//!   - `inet6` / `-6` family selectors that would put `ip`/`route` into IPv6 mode.
//!
//! These tokens are chosen to be false-positive-free against the legitimate v4-only code and its
//! doc comments (which spell IPv6 with an uppercase `P`). This check only OBSERVES
//! `ts_host_net/src/` — it never modifies it. A generic `::` scan was deliberately NOT used: Rust
//! path separators (`foo::bar`, `parse::<T>`) are ubiquitous and would false-positive, and the
//! v4-only types already make a literal v6 address unconstructable.

use crate::{Args, BoxResult};

/// Tokens whose presence in `ts_host_net/src/` means IPv6 may have leaked into the route/DNS path.
const FORBIDDEN: &[&str] = &["inet6", "Ipv6", "enable_ipv6"];

/// IPv6 family selectors for `ip`/`route` argv, matched only as standalone whitespace/quote-bounded
/// tokens so they never collide with substrings like `0.0.0.0/16` or `-64`.
const FORBIDDEN_ARGV_FLAGS: &[&str] = &["\"-6\"", "'-6'"];

pub fn run(_args: &Args) -> BoxResult<()> {
    let glob =
        globwalk::GlobWalkerBuilder::from_patterns("ts_host_net/src", &["**/*.rs"]).build()?;

    let mut hits: Vec<String> = Vec::new();
    for entry in glob {
        let entry = entry?;
        let path = entry.path();
        let contents = std::fs::read_to_string(path)?;
        for (lineno, line) in contents.lines().enumerate() {
            let flagged = FORBIDDEN.iter().any(|t| line.contains(t))
                || FORBIDDEN_ARGV_FLAGS.iter().any(|t| line.contains(t));
            if flagged {
                hits.push(format!(
                    "{}:{}: {}",
                    path.display(),
                    lineno + 1,
                    line.trim()
                ));
            }
        }
    }

    if !hits.is_empty() {
        eprintln!("IPv6 leaked into the host route/DNS path (ts_host_net/src/):");
        for hit in &hits {
            eprintln!("  {hit}");
        }
        eprintln!(
            "Host route/DNS programming must stay IPv4-only by construction. If this is \
             legitimate, the v4-only host-integration invariant is being broken — STOP."
        );
        return Err("IPv6 tokens found in ts_host_net/src/".into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{FORBIDDEN, FORBIDDEN_ARGV_FLAGS};

    /// The forbidden tokens flag the v6 patterns they target.
    #[test]
    fn forbidden_tokens_catch_v6_argv() {
        let leak_inet6 = r#"vec!["add", "-inet6", net.to_string()]"#;
        let leak_type = "let a: Ipv6Addr = ...;";
        let leak_gate = "if env.enable_ipv6 { ... }";
        let leak_flag = r#"vec!["-6".to_owned(), "route".to_owned()]"#;

        assert!(FORBIDDEN.iter().any(|t| leak_inet6.contains(t)));
        assert!(FORBIDDEN.iter().any(|t| leak_type.contains(t)));
        assert!(FORBIDDEN.iter().any(|t| leak_gate.contains(t)));
        assert!(FORBIDDEN_ARGV_FLAGS.iter().any(|t| leak_flag.contains(t)));
    }

    /// Legitimate v4-only code and prose doc comments do NOT trip the guard.
    #[test]
    fn legitimate_v4_lines_do_not_trip() {
        let ok_lines = [
            r#"vec!["-inet".to_owned(), net.to_string()]"#,
            "use crate::{HostDns, HostNet, HostNetError, HostRoutes};",
            r#"".collect::<Vec<_>>()""#,
            "//! IPv4-only by construction; IPv6 is gated off (prose, uppercase P).",
            r#"vec!["-4".to_owned(), "route".to_owned()]"#,
            r#""0.0.0.0/0".parse::<Ipv4Net>().unwrap()"#,
        ];
        for line in ok_lines {
            let flagged = FORBIDDEN.iter().any(|t| line.contains(t))
                || FORBIDDEN_ARGV_FLAGS.iter().any(|t| line.contains(t));
            assert!(!flagged, "false positive on legitimate v4 line: {line}");
        }
    }
}
