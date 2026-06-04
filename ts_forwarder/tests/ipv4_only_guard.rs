//! Leak firewall: the forwarder exit/subnet **dial path is IPv4-only**, by construction.
//!
//! This fork's primary deployment is a privacy proxy / cloud exit node where the host's real
//! origin IP must never leak. The forwarder's `RealDialer` chokepoint
//! ([`DirectDialer`]/[`HostExitDialer`]/[`ProxyExitDialer`]) is the single place an overlay flow
//! becomes a real OS socket, and it binds `0.0.0.0:0` (IPv4) only — never `::`. The
//! "IPv6 on the tailnet overlay" feature is gated and default-off, but the exit/subnet egress path
//! is IPv4-only **regardless of that flag**: that is the real-origin-IP isolation invariant.
//!
//! These tests OBSERVE `ts_forwarder`'s public API only — they construct each public dialer and
//! assert that dialing an IPv6 destination ERRORS (never succeeds, never opens a v6 socket). They
//! do not (and must not) modify any `ts_forwarder/src/` source. If a future change wires IPv6 into
//! the dialer, these tests — plus the `checks` crate's `ipv4_only_forwarder` grep gate — fail
//! mechanically.
//!
//! Why an error (not a v6 socket) is the right assertion per dialer:
//! - [`DirectDialer`]: a v6 dst classified as `ExitNode` is structurally refused
//!   ([`DialError::ExitEgressRefused`]); a v6 dst as `Subnet` attempts an IPv4-only `0.0.0.0:0`
//!   bind + connect to a v6 address, which the OS rejects (`AddrNotAvailable`/`InvalidInput`).
//! - [`HostExitDialer`]: same IPv4-only `new_v4()` bind, so a v6 connect errors at the OS.
//! - [`ProxyExitDialer`]: an `ExitNode` v6 dst is rejected by the SSRF guard
//!   (`exit_dst_is_forbidden` treats every v6 as forbidden) before any socket; TCP yields a
//!   `ProxyHandshake` error and UDP fails closed (`ProxyUdpUnsupported`).

use std::net::SocketAddr;

use ts_forwarder::{
    DialError, DirectDialer, FlowClass, HostExitDialer, ProxyConfig, ProxyExitDialer, ProxyScheme,
    RealDialer,
};

/// A representative set of IPv6 destinations the dial path must never reach.
fn v6_dsts() -> Vec<SocketAddr> {
    [
        "[2001:db8::1]:80",
        "[::1]:80",
        "[fd7a:115c:a1e0::1]:443", // tailnet ULA shape
        "[::]:80",                 // unspecified v6
    ]
    .iter()
    .map(|s| s.parse().unwrap())
    .collect()
}

// We drive both the exit-node and subnet arms of each dialer directly via the public
// `dial_tcp`/`dial_udp` `FlowClass` argument. (The route table's `classify` strips v6 to `None`
// upstream, so v6 never reaches the dialer in production — these tests assert the dialer is safe
// even if it ever did.)

#[tokio::test]
async fn direct_dialer_never_dials_ipv6() {
    for dst in v6_dsts() {
        // ExitNode is structurally refused regardless of address family.
        let err = DirectDialer.dial_tcp(FlowClass::ExitNode, dst).await;
        assert!(
            matches!(err, Err(DialError::ExitEgressRefused)),
            "DirectDialer must refuse exit-node egress for v6 dst {dst}"
        );
        let err = DirectDialer.dial_udp(FlowClass::ExitNode, dst).await;
        assert!(
            matches!(err, Err(DialError::ExitEgressRefused)),
            "DirectDialer must refuse exit-node UDP egress for v6 dst {dst}"
        );

        // Subnet attempts an IPv4-only bind + connect; connecting an IPv4 socket to a v6 address
        // is an OS error. It must NEVER return Ok (which would mean a v6 socket was opened).
        let res = DirectDialer.dial_tcp(FlowClass::Subnet, dst).await;
        assert!(
            res.is_err(),
            "DirectDialer subnet dial to v6 dst {dst} must error, never open a v6 socket"
        );
        let res = DirectDialer.dial_udp(FlowClass::Subnet, dst).await;
        assert!(
            res.is_err(),
            "DirectDialer subnet UDP dial to v6 dst {dst} must error, never open a v6 socket"
        );
    }
}

#[tokio::test]
async fn host_exit_dialer_never_dials_ipv6() {
    for dst in v6_dsts() {
        // HostExitDialer binds an IPv4-only socket (`new_v4()`), so connecting it to a v6 dst
        // errors at the OS for both Subnet and ExitNode. It must never produce a v6 socket.
        for class in [FlowClass::Subnet, FlowClass::ExitNode] {
            let res = HostExitDialer.dial_tcp(class, dst).await;
            assert!(
                res.is_err(),
                "HostExitDialer ({class:?}) TCP dial to v6 dst {dst} must error, never open a v6 socket"
            );
            let res = HostExitDialer.dial_udp(class, dst).await;
            assert!(
                res.is_err(),
                "HostExitDialer ({class:?}) UDP dial to v6 dst {dst} must error, never open a v6 socket"
            );
        }
    }
}

#[tokio::test]
async fn proxy_exit_dialer_never_dials_ipv6() {
    // The proxy address is irrelevant: an exit-node v6 dst is rejected by the SSRF guard before any
    // socket is opened, and UDP fails closed. We use a parseable-but-unused loopback proxy addr.
    let dialer = ProxyExitDialer::new(ProxyConfig {
        addr: "127.0.0.1:1080".parse().unwrap(),
        scheme: ProxyScheme::Socks5,
        auth: None,
    });
    for dst in v6_dsts() {
        // ExitNode v6 dst: SSRF guard forbids every v6 destination => ProxyHandshake error, no
        // proxy connection, no v6 socket.
        let err = dialer.dial_tcp(FlowClass::ExitNode, dst).await;
        assert!(
            matches!(err, Err(DialError::ProxyHandshake(_))),
            "ProxyExitDialer must refuse exit-node v6 dst {dst} via SSRF guard"
        );
        // UDP through the proxy always fails closed — no v6 (or v4) UDP tunnel exists.
        let err = dialer.dial_udp(FlowClass::ExitNode, dst).await;
        assert!(
            matches!(err, Err(DialError::ProxyUdpUnsupported)),
            "ProxyExitDialer must refuse exit-node v6 UDP dst {dst} (fail closed)"
        );
    }
}
