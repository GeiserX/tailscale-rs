//! Runtime anti-leak assertions for the `RealDialer` chokepoint (black-box, public API only).
//!
//! # Why this file exists
//!
//! The fork's sacred invariant is: **the real origin IP never leaks; egress is fail-closed.**
//! There is already a *static* firewall (`cargo run -p checks`) that greps the source tree for
//! IPv6 tokens and other forbidden constructs. That static pass proves "the source does not
//! *mention* `::` / IPv6 bind constructs" — it can NOT prove anything about *runtime behavior*:
//! it cannot show that, given an exit-node flow at runtime, the dialer actually refuses to open
//! a real socket out the host's origin IP. A regression that, say, made `DirectDialer` quietly
//! dial exit traffic, or made `ProxyExitDialer` fall back to a direct dial on handshake failure,
//! would leave the source IPv6-clean and sail straight past `checks` while silently leaking the
//! origin IP. These tests close that gap by exercising the **runtime** dialer decisions through
//! the public `ts_forwarder` API only.
//!
//! Each case maps to a distinct facet of the invariant:
//!
//! 1. **`DirectDialer` structurally refuses exit egress** — the default dialer can never be the
//!    thing that leaks the origin IP for a peer's internet-bound (`ExitNode`) flow. Refusal is
//!    returned *before* any socket is opened, so the assertion is hermetic (no real network).
//!    We also assert a non-exit (`Subnet`) flow is NOT refused by the type system: it takes a
//!    different code path and fails (if at all) with a connect error, never `ExitEgressRefused`.
//!
//! 2. **`ProxyExitDialer` fails closed on a dead proxy** — when the upstream proxy is
//!    unreachable, the dial returns `Err`, it does NOT silently fall back to a direct host-IP
//!    dial. The "no direct fallback" property is also a *type-level* fact: `ProxyExitDialer`
//!    holds only a `ProxyConfig` and has no `DirectDialer`/`HostExitDialer` member to fall back
//!    through (see the struct definition in `dialer.rs`), so the only observable outcome of a
//!    failed handshake is the surfaced error, which is what we assert here.
//!
//! 3. **SSRF guard via the exit path** — for an `ExitNode` flow, forbidden destinations
//!    (loopback, cloud-metadata/link-local `169.254.169.254`, unspecified `0.0.0.0`, RFC1918
//!    private ranges, and *any* IPv6 destination) are refused. The guard runs at the very top
//!    of `ProxyExitDialer::dial_tcp` *before* the proxy is contacted, so each case is hermetic
//!    even though the configured proxy address is never actually listening.
//!
//! 4. **UDP over proxy fails closed** — there is no UDP tunnel, and a direct UDP dial would leak
//!    the origin IP, so proxy UDP egress is refused outright.
//!
//! All `RealDialer` methods are `async`, hence `#[tokio::test]`. No case performs real outbound
//! network I/O: exit refusals happen before a socket is opened, and the one connect that does run
//! targets a just-freed loopback port that is guaranteed to refuse.

use std::net::SocketAddr;

use ts_forwarder::{
    DialError, DirectDialer, FlowClass, ProxyConfig, ProxyExitDialer, ProxyScheme, RealDialer,
};

/// Case 1a — `DirectDialer` structurally refuses exit-node egress.
///
/// Dialing a normal *public* destination on an `ExitNode` flow must return
/// [`DialError::ExitEgressRefused`]. This is the core fail-closed guarantee: the default dialer
/// can never egress a peer's internet-bound traffic out our real origin IP. Refusal is returned at
/// the top of the match arm, *before* any socket is created, so dialing `1.1.1.1:443` here opens
/// no real connection — the assertion is fully hermetic.
#[tokio::test]
async fn direct_dialer_refuses_exit_egress_to_public_dst() {
    let dst: SocketAddr = "1.1.1.1:443".parse().unwrap();
    let result = DirectDialer.dial_tcp(FlowClass::ExitNode, dst).await;
    assert!(
        matches!(result, Err(DialError::ExitEgressRefused)),
        "DirectDialer must refuse ExitNode egress with ExitEgressRefused, got {result:?}"
    );

    // The same structural refusal applies to UDP exit egress. `DialedUdp` (the Ok type) does not
    // implement `Debug`, so we match the error out rather than debug-printing the whole `Result`.
    let err_udp = DirectDialer.dial_udp(FlowClass::ExitNode, dst).await.err();
    assert!(
        matches!(err_udp, Some(DialError::ExitEgressRefused)),
        "DirectDialer must refuse ExitNode UDP egress with ExitEgressRefused, got {err_udp:?}"
    );
}

/// Case 1a-DNS (tsr-c39) — a forwarded client's UDP **port-53 (DNS)** datagram is exit egress like
/// any other UDP, NOT a special DNS path that could leak the origin IP.
///
/// The forwarder deliberately does **not** special-case port 53: a forwarded client's DNS query to
/// a public resolver (`8.8.8.8:53`) is classified and dialed exactly like every other `ExitNode`
/// UDP flow, so it shares the forwarded-traffic egress (host IP, or a configured residential proxy)
/// — never a separate DNS egress. Under the default `DirectDialer` that means it is structurally
/// **refused** (`ExitEgressRefused`), fail-closed, identical to non-DNS exit UDP. This pins the
/// anti-leak invariant the exit-node-client-DNS analysis (tsr-c39) relies on: matching Go, exit-node
/// DNS for forwarded clients is the client's DoH redirect + raw forwarding, with no exit-side DNS
/// interception that could bypass the dialer's fail-closed gate.
#[tokio::test]
async fn direct_dialer_refuses_exit_dns_udp_no_special_case() {
    // Two public DNS resolvers on port 53; both must be refused as ordinary ExitNode UDP egress.
    for dst in ["8.8.8.8:53", "1.1.1.1:53"] {
        let dst: SocketAddr = dst.parse().unwrap();
        let err = DirectDialer.dial_udp(FlowClass::ExitNode, dst).await.err();
        assert!(
            matches!(err, Some(DialError::ExitEgressRefused)),
            "DirectDialer must refuse exit-node UDP:53 (DNS) exactly like any other UDP egress \
             (no DNS special-case bypass), got {err:?} for {dst}"
        );
    }
}

/// Case 1b — non-exit (`Subnet`) flows are NOT caught by the exit refusal.
///
/// A `Subnet`-class dial takes the legitimate egress path (it is a routed subnet, not the open
/// internet). To keep the test hermetic, we point it at a just-freed loopback port that is
/// guaranteed to refuse the connection: the dial therefore fails with a transport-level
/// [`DialError::Io`] error, NOT [`DialError::ExitEgressRefused`]. This proves the type system
/// does not blanket-refuse every flow — only `ExitNode` egress is structurally forbidden.
#[tokio::test]
async fn direct_dialer_does_not_refuse_subnet_flow() {
    // Bind then immediately drop to obtain a port that is reserved-then-closed, so connecting to
    // it is refused locally without ever touching the network.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dst = listener.local_addr().unwrap();
    drop(listener);

    let result = DirectDialer.dial_tcp(FlowClass::Subnet, dst).await;
    assert!(
        !matches!(result, Err(DialError::ExitEgressRefused)),
        "Subnet flow must not be refused as exit egress; got ExitEgressRefused"
    );
    // It is expected to fail (the port is closed), but with a transport error, not a policy refusal.
    assert!(
        matches!(result, Err(DialError::Io(_))),
        "Subnet dial to a closed loopback port should fail with an Io error, got {result:?}"
    );
}

/// Case 2 — `ProxyExitDialer` fails closed when the upstream proxy is unreachable.
///
/// We point the dialer at a loopback port that was reserved then freed, so the connect to the
/// proxy is refused. The dial must surface `Err` — it must NOT fall back to a direct host-IP dial
/// to `dst` (which would leak the origin IP). The destination here (`1.1.1.1:443`) is a legitimate
/// public exit target, so the SSRF guard does not short-circuit; the error we observe is purely the
/// proxy-connect failure. The absence of a direct fallback is additionally guaranteed at the type
/// level: `ProxyExitDialer` owns only a `ProxyConfig` and has no direct-dialer member to fall
/// through to, so a surfaced `Err` is the only possible fail-closed outcome.
#[tokio::test]
async fn proxy_dialer_fails_closed_on_dead_proxy() {
    let reserved = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_proxy = reserved.local_addr().unwrap();
    drop(reserved); // free the port so the proxy connect is refused

    let dialer = ProxyExitDialer::new(ProxyConfig {
        addr: dead_proxy,
        scheme: ProxyScheme::Socks5,
        auth: None,
    });

    let dst: SocketAddr = "1.1.1.1:443".parse().unwrap();
    let result = dialer.dial_tcp(FlowClass::ExitNode, dst).await;
    assert!(
        result.is_err(),
        "dead upstream proxy must fail closed, never fall back to a direct dial; got {result:?}"
    );
}

/// Case 3 — SSRF guard: forbidden exit destinations are refused via the exit path.
///
/// For an `ExitNode` flow, the dialer rejects destinations a malicious peer could use to make us
/// CONNECT the proxy at internal/loopback/metadata networks (SSRF). The guard runs at the top of
/// `dial_tcp` *before* any proxy connection, so even though the configured proxy address is not
/// listening, none of these cases touch it — they are fully hermetic.
///
/// The code returns [`DialError::ProxyHandshake`] for a forbidden destination (the message reads
/// `"exit destination forbidden (loopback/private/link-local)"`); there is no dedicated
/// `Forbidden` variant. We assert that exact variant. IPv6 destinations are forbidden wholesale
/// (the IPv6-off posture), so they are included here.
#[tokio::test]
async fn proxy_dialer_refuses_forbidden_exit_destinations() {
    let dialer = ProxyExitDialer::new(ProxyConfig {
        // Not listening — but the SSRF guard short-circuits before any connect is attempted.
        addr: "127.0.0.1:1".parse().unwrap(),
        scheme: ProxyScheme::Socks5,
        auth: None,
    });

    let forbidden: &[&str] = &[
        "127.0.0.1:443",         // loopback
        "169.254.169.254:80",    // cloud metadata / link-local
        "0.0.0.0:443",           // unspecified
        "10.0.0.1:443",          // RFC1918 private
        "192.168.1.1:443",       // RFC1918 private
        "[::1]:443",             // IPv6 loopback (IPv6 forbidden wholesale)
        "[2606:4700::1111]:443", // public IPv6 (still forbidden — IPv6-off posture)
    ];

    for raw in forbidden {
        let dst: SocketAddr = raw.parse().unwrap();
        let result = dialer.dial_tcp(FlowClass::ExitNode, dst).await;
        assert!(
            matches!(result, Err(DialError::ProxyHandshake(_))),
            "exit dial to forbidden dst {raw} must be refused with ProxyHandshake, got {result:?}"
        );
    }
}

/// Case 4 — UDP egress through the proxy fails closed.
///
/// There is no UDP tunnel (HTTP CONNECT cannot carry UDP; SOCKS5 UDP-ASSOCIATE is unimplemented),
/// and a direct UDP dial would leak the origin IP. So proxy UDP egress is refused outright with
/// [`DialError::ProxyUdpUnsupported`], with no direct fallback. The proxy address is never
/// contacted, so this is hermetic.
#[tokio::test]
async fn proxy_dialer_udp_fails_closed() {
    let dialer = ProxyExitDialer::new(ProxyConfig {
        addr: "127.0.0.1:1".parse().unwrap(),
        scheme: ProxyScheme::Socks5,
        auth: None,
    });

    let dst: SocketAddr = "1.1.1.1:53".parse().unwrap();
    // `DialedUdp` (the Ok type) is not `Debug`; match the error out instead of printing `Result`.
    let err = dialer.dial_udp(FlowClass::ExitNode, dst).await.err();
    assert!(
        matches!(err, Some(DialError::ProxyUdpUnsupported)),
        "proxy UDP egress must fail closed with ProxyUdpUnsupported, got {err:?}"
    );
}
