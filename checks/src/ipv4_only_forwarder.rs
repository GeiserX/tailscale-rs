//! Leak firewall: the forwarder exit/subnet egress path must stay IPv4-only.
//!
//! WHY: this fork's primary deployment is a privacy proxy / cloud exit node. The forwarder's
//! `RealDialer` chokepoint (`ts_forwarder/src/dialer.rs`) is the single place an overlay flow
//! becomes a real OS socket; it binds `0.0.0.0:0` (IPv4) only. The gated, default-off "IPv6 on the
//! tailnet overlay" feature must NEVER wire IPv6 into this egress path — that is the
//! real-origin-IP isolation invariant. A future regression that gives the dialer a v6 bind/connect
//! would silently leak (or break the isolation of) the host's real origin IP.
//!
//! WHAT THIS CHECKS: it scans every file under `ts_forwarder/src/` for tokens that indicate an
//! IPv6 bind/connect or the IPv6 gate leaking into the egress crate, and fails if any are found:
//!   - `enable_ipv6`        : the runtime IPv6 gate must never be read by the egress dialer.
//!   - `TcpSocket::new_v6`  : an IPv6 TCP socket in the dial path.
//!   - `UdpSocket::bind_v6` / `bind_v6` : helpers that bind a v6 socket.
//!   - `set_only_v6`        : toggling `IPV6_V6ONLY` implies a v6 socket exists here.
//!
//! These tokens are chosen to be false-positive-free against the legitimate v6-REJECT code already
//! in `dialer.rs` (which only *mentions* IPv6 to refuse it). This check only OBSERVES
//! `ts_forwarder/src/` — it never modifies it.

use crate::{Args, BoxResult};

/// Tokens whose presence in `ts_forwarder/src/` means IPv6 may have leaked into the dial/bind path.
const FORBIDDEN: &[&str] = &[
    "enable_ipv6",
    "TcpSocket::new_v6",
    "UdpSocket::bind_v6",
    "bind_v6",
    "set_only_v6",
];

pub fn run(_args: &Args) -> BoxResult<()> {
    let glob =
        globwalk::GlobWalkerBuilder::from_patterns("ts_forwarder/src", &["**/*.rs"]).build()?;

    let mut hits: Vec<String> = Vec::new();
    for entry in glob {
        let entry = entry?;
        let path = entry.path();
        let contents = std::fs::read_to_string(path)?;
        for (lineno, line) in contents.lines().enumerate() {
            for token in FORBIDDEN {
                if line.contains(token) {
                    hits.push(format!(
                        "{}:{}: {}",
                        path.display(),
                        lineno + 1,
                        line.trim()
                    ));
                }
            }
        }
    }

    if !hits.is_empty() {
        eprintln!("IPv6 leaked into the forwarder egress path (ts_forwarder/src/):");
        for hit in &hits {
            eprintln!("  {hit}");
        }
        eprintln!(
            "The exit/subnet dialer must stay IPv4-only regardless of the enable_ipv6 gate. \
             If this is legitimate, the real-origin-IP isolation invariant is being broken — STOP."
        );
        return Err("IPv6 tokens found in ts_forwarder/src/".into());
    }

    Ok(())
}
