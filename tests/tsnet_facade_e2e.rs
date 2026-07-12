//! LIVE e2e for the Go-idiomatic [`tsnet::Server`] facade against **real** Tailscale.
//!
//! Companion to `tailnet_live.rs` / `tailnet_e2e_campaign.rs` (which drive the native
//! [`Device`](tailscale::Device)); this drives the **facade** — [`tsnet::Server`] — proving
//! `listen` / `dial` / `listen_tls` / `loopback` / `listen_funnel` behave with Go `tsnet.Server`
//! semantics end-to-end. Cross-referenced to `docs/TSNET_PARITY.md` (§3 method matrix) and
//! `docs/TSNET_FACADE_DESIGN.md` (§6 method mapping, §7 error split, §11 loopback).
//!
//! **Gating (identical to the sibling harness; compiles without live creds — runtime gate only).**
//! The whole file is behind the `tsnet` cargo feature, and every test **skips cleanly** (never
//! fails) unless BOTH `TS_RS_TEST_NET` is truthy (`ts_test_util::run_net_tests()`) AND
//! `TS_RS_TEST_AUTHKEY` is set (`ts_test_util::auth_key()`). The auth key is read from the
//! environment, never hardcoded. TUN is off (userspace netstack), so no root / host routing.
//!
//! Run:
//! ```sh
//! TS_RS_EXPERIMENT=this_is_unstable_software TS_RS_TEST_NET=1 \
//!   TS_RS_TEST_AUTHKEY=<reusable-ephemeral-key> \
//!   cargo test --features tsnet --test tsnet_facade_e2e -- --nocapture --test-threads=1
//! ```
#![cfg(feature = "tsnet")]

use std::{net::Ipv4Addr, time::Duration};

use tailscale::tsnet::{FunnelOptions, ListenFunnelError, Server};
use tailscale::{ServeConfig, ServeTarget};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::time::timeout;

/// Generous ceiling for a live registration/up against real Tailscale.
const JOIN_TIMEOUT: Duration = Duration::from_secs(60);

/// Shared gate, mirroring `tailnet_e2e_campaign.rs::gated()`: returns the reusable ephemeral auth
/// key, or `None` (each test then skips cleanly). Also sets `TS_RS_EXPERIMENT` so the experimental
/// build is acknowledged even if the runner forgot to export it.
fn gated() -> Option<String> {
    if !ts_test_util::run_net_tests() {
        eprintln!("[skip] TS_RS_TEST_NET not set");
        return None;
    }
    // SAFETY: set before this test spawns any worker thread that reads the env; the var is the
    // runtime gate for the experimental build (read in `Device::new`).
    unsafe { std::env::set_var("TS_RS_EXPERIMENT", "this_is_unstable_software") };
    match ts_test_util::auth_key() {
        Some(k) => Some(k),
        None => {
            eprintln!("[skip] TS_RS_TEST_AUTHKEY not set");
            None
        }
    }
}

/// Whether `ip` is in Tailscale's `100.64.0.0/10` CGNAT range (every real-Tailscale node IPv4).
fn is_cgnat(ip: Ipv4Addr) -> bool {
    let mask: u32 = u32::MAX << 22; // /10
    (u32::from(ip) & mask) == (u32::from(Ipv4Addr::new(100, 64, 0, 0)) & mask)
}

/// Build a facade [`Server`], set the Go-parity fields, and lazily start it via `up` (Go `Up`) until
/// Running. Returns the started server plus its assigned CGNAT IPv4. `ephemeral = true` so control
/// GCs the node shortly after disconnect (test hygiene, matching the native campaign).
async fn join(label: &str, auth: &str) -> (Server, Ipv4Addr) {
    let mut srv = Server::new();
    let suffix: u32 = rand::random();
    srv.hostname = Some(format!("tsrs-facade-{label}-{suffix:08x}"));
    srv.auth_key = Some(auth.to_string());
    srv.ephemeral = true;
    // `up` = Go `Up`: triggers the lazy `Start` (build_config → Device::new) then waits for Running.
    timeout(JOIN_TIMEOUT, srv.up(Some(JOIN_TIMEOUT)))
        .await
        .expect("facade up() within timeout")
        .expect("facade up() must reach Running against real Tailscale");
    let (ipv4, _v6) = srv.tailscale_ips().await.expect("tailscale_ips() after up()");
    assert!(is_cgnat(ipv4), "{label}: facade node IP {ipv4} must be CGNAT");
    eprintln!("[{label}] facade node up as {ipv4}");
    (srv, ipv4)
}

/// F1 — LIFECYCLE (`up`/`status`/`close`). Field-set → lazy `up` → Running; `status` (the folded Go
/// `LocalClient().Status`) reports the same assigned IP as `tailscale_ips`; `close` (Go `Close`,
/// consuming `self`) shuts the node down. Proves the field→`Config`→`Device::new` lazy start works
/// end-to-end through the facade.
#[tokio::test]
async fn f1_facade_up_status_close() {
    let Some(auth) = gated() else { return };
    let (srv, ipv4) = join("life", &auth).await;

    let status = srv.status().await.expect("facade status()");
    let me = status
        .self_node
        .as_ref()
        .expect("status().self_node populated once Running");
    eprintln!(
        "[f1] self={} ipv4={} peers={}",
        me.display_name,
        me.ipv4,
        status.peers.len()
    );
    assert_eq!(
        me.ipv4,
        std::net::IpAddr::V4(ipv4),
        "facade status self IP must match the assigned tailnet IP"
    );

    let closed = srv.close(Some(Duration::from_secs(10))).await;
    eprintln!("[f1] facade close() completed_gracefully={closed}");
    assert!(closed, "facade close() must complete a graceful shutdown in time");
}

/// F2 — LISTEN + DIAL across two facade nodes. `listen("tcp", ":port")` on node A (Go `Listen`)
/// announces a tailnet TCP listener; node B `dial_tcp` (Go `Dial("tcp", …)`) connects to A's tailnet
/// `IP:port` and a payload round-trips over the WireGuard overlay. Proves the facade's `listen` +
/// `dial` + data plane match Go tsnet — the canonical "listen on one tsnet node, dial from another".
#[tokio::test]
async fn f2_facade_listen_and_dial_two_nodes() {
    let Some(auth) = gated() else { return };
    let (srv_a, a_ip) = join("srv", &auth).await;
    let (srv_b, b_ip) = join("cli", &auth).await;

    let rnd: u16 = rand::random();
    let port: u16 = 40000 + (rnd % 20000);
    let listener = srv_a
        .listen("tcp", &format!(":{port}"))
        .await
        .expect("facade listen('tcp', ':port') must bind on the tailnet");
    eprintln!("[f2] node A listening on {a_ip}:{port}; node B is {b_ip}");

    let target = format!("{a_ip}:{port}");

    // A: accept exactly one overlay connection and echo its bytes back.
    let server_side = async {
        let mut conn = listener.accept().await.expect("A accepts an overlay connection");
        // The client sends a fixed 4-byte "ping". A single `read` may return a short prefix, which
        // would echo <4 bytes while the client's `read_exact` blocks forever waiting for the rest —
        // a false failure. `read_exact` pulls the whole fixed-size payload before echoing.
        let mut buf = [0u8; 4];
        conn.read_exact(&mut buf).await.expect("A reads the request");
        conn.write_all(&buf).await.expect("A echoes it back");
        conn.flush().await.ok();
        buf.len()
    };

    // B: retry the dial while its netmap converges to include A (fresh nodes can lag), then
    // round-trip a payload.
    let client_side = async {
        let mut waited = Duration::ZERO;
        let mut stream = loop {
            match timeout(Duration::from_secs(8), srv_b.dial_tcp(&target)).await {
                Ok(Ok(s)) => break s,
                Ok(Err(e)) => eprintln!("[f2] dial attempt err (netmap still converging?): {e:?}"),
                Err(_) => eprintln!("[f2] dial attempt timed out"),
            }
            assert!(
                waited < Duration::from_secs(45),
                "facade dial_tcp to the peer's tailnet listener never succeeded"
            );
            tokio::time::sleep(Duration::from_secs(2)).await;
            waited += Duration::from_secs(2);
        };
        stream.write_all(b"ping").await.expect("B writes 'ping' over the overlay");
        stream.flush().await.ok();
        let mut back = [0u8; 4];
        timeout(Duration::from_secs(10), stream.read_exact(&mut back))
            .await
            .expect("echo read within timeout")
            .expect("B reads the echoed bytes");
        back
    };

    // Drive both concurrently in one task (no spawn ⇒ no Send bound on the netstack handles).
    let (n, back) = tokio::join!(server_side, client_side);
    assert_eq!(n, 4, "A must have read the 4-byte request");
    assert_eq!(
        &back, b"ping",
        "facade dial ⇄ listen must round-trip bytes over the overlay"
    );
    eprintln!(
        "[f2] overlay round-trip OK: B sent 'ping', got back {:?}",
        std::str::from_utf8(&back).unwrap_or("<bin>")
    );

    srv_a.close(Some(Duration::from_secs(5))).await;
    srv_b.close(Some(Duration::from_secs(5))).await;
}

/// F3 — LOOPBACK dual-credential + live LocalAPI (Go `Loopback()` + `LocalClient()`). `loopback()`
/// brings up the SOCKS5 proxy + the in-process LocalAPI HTTP server on **two** `127.0.0.1` listeners
/// with **two distinct** credentials; `local_client().status()` round-trips an authenticated `GET
/// /localapi/v0/status` through the LIVE device and returns its status JSON (the hermetic tests use a
/// mock backend — this is the real one). Idempotent, matching Go's `if s.loopbackListener == nil`.
#[tokio::test]
async fn f3_facade_loopback_and_localclient() {
    let Some(auth) = gated() else { return };
    let (srv, ipv4) = join("loop", &auth).await;

    let lb = srv.loopback().await.expect("facade loopback() must start");
    eprintln!(
        "[f3] socks={} localapi={} creds_distinct={}",
        lb.address,
        lb.local_api_address,
        lb.proxy_cred != lb.local_api_cred
    );
    assert_ne!(lb.proxy_cred, lb.local_api_cred, "the two Go creds must be distinct");
    assert_ne!(lb.address, lb.local_api_address, "two separate 127.0.0.1 listeners");
    assert!(
        lb.address.ip().is_loopback() && lb.local_api_address.ip().is_loopback(),
        "both listeners bind 127.0.0.1"
    );

    // Idempotent: a second call returns the same surface (no second listener).
    let lb2 = srv.loopback().await.expect("loopback() is idempotent");
    assert_eq!(lb.address, lb2.address);
    assert_eq!(lb.local_api_cred, lb2.local_api_cred);

    // LocalClient round-trips authenticated status through the LIVE in-process LocalAPI server.
    let client = srv.local_client().await.expect("facade local_client()");
    let body = client.status().await.expect("LocalClient status() must round-trip 200");
    let text = String::from_utf8_lossy(&body);
    eprintln!("[f3] localapi status body ({} bytes)", body.len());
    assert!(
        text.contains(&ipv4.to_string()),
        "LocalAPI status must reflect the live device's assigned IP {ipv4}; got: {text}"
    );

    srv.close(Some(Duration::from_secs(5))).await;
}

/// F4 — LISTEN_TLS fail-closed + CERT_DOMAINS. `cert_domains()` (Go `CertDomains`) returns the
/// control-pushed names without error; `listen_tls(valid *.ts.net serve cfg)` (Go `ListenTLS` cert
/// path) delegates to the engine and is **fail-closed** — without the `acme` feature it surfaces a
/// typed [`tailscale::CertError::Unimplemented`], never a plaintext acceptor or a panic. This is the
/// Go-parity property "ListenTLS needs a real cert" (the fork never downgrades to self-signed).
#[tokio::test]
async fn f4_facade_listen_tls_failclosed() {
    let Some(auth) = gated() else { return };
    let (srv, _ip) = join("tls", &auth).await;

    let domains = srv.cert_domains().await.expect("facade cert_domains()");
    eprintln!("[f4] cert_domains = {domains:?}");

    // A valid `*.ts.net` cert name: prefer a control-pushed cert domain, else this node's FQDN.
    let name = match domains.first() {
        Some(d) => d.clone(),
        None => {
            let dev = srv.device().await.expect("device()");
            dev.self_node().await.expect("self_node").fqdn(false)
        }
    };
    let cfg = ServeConfig {
        name: name.clone(),
        port: 443,
        target: ServeTarget::Accept,
    };
    eprintln!("[f4] listen_tls(name={name:?}, port=443)");
    let res = srv.listen_tls(&cfg).await;
    if cfg!(feature = "acme") {
        // With `acme`, real issuance depends on the tailnet having HTTPS/certs enabled; accept Ok
        // (a real acceptor) or a typed Acme/Io error — either way typed and never plaintext.
        match res {
            Ok(_acceptor) => eprintln!("[f4] acme: issued a real TLS acceptor"),
            Err(e) => eprintln!("[f4] acme: typed CertError (tailnet HTTPS config dependent): {e:?}"),
        }
    } else {
        // Default build: the fork refuses to serve TLS without a real cert engine — fail-closed as
        // the documented typed `Unimplemented`, matching Go's "ListenTLS needs a cert".
        let fail_closed = matches!(res, Err(tailscale::CertError::Unimplemented { .. }));
        assert!(
            fail_closed,
            "without `acme`, facade listen_tls must fail-closed as CertError::Unimplemented"
        );
        eprintln!("[f4] listen_tls fail-closed as CertError::Unimplemented (no acme) — correct");
    }

    srv.close(Some(Duration::from_secs(5))).await;
}

/// F5 — LISTEN_FUNNEL fail-closed + typed lifecycle/access split (design §7). On a **registered**
/// node, `listen_funnel` (Go `ListenFunnel`) is fail-closed: a tailnet without the Funnel ACL yields
/// a *typed access denial* [`ListenFunnelError::Funnel`], and a Funnel-enabled tailnet yields `Ok`.
/// Crucially it is **never** [`ListenFunnelError::Start`] — the node DID register — proving the
/// facade's lifecycle-vs-access error split holds under real registration (the hermetic test proves
/// the `Start` side with a bad `control_url`; this proves the access side against real Tailscale).
#[tokio::test]
async fn f5_facade_listen_funnel_failclosed_typed() {
    let Some(auth) = gated() else { return };
    let (srv, _ip) = join("funnel", &auth).await;

    let name = {
        let dev = srv.device().await.expect("device()");
        dev.self_node().await.expect("self_node").fqdn(false)
    };
    let cfg = ServeConfig {
        name: name.clone(),
        port: 443,
        target: ServeTarget::Accept,
    };
    eprintln!("[f5] listen_funnel(name={name:?}, port=443)");
    match srv.listen_funnel(&cfg, FunnelOptions::default()).await {
        Ok(_rx) => eprintln!("[f5] Funnel enabled on this tailnet: got a live funnel receiver (Ok)"),
        Err(ListenFunnelError::Funnel(f)) => eprintln!(
            "[f5] fail-closed typed Funnel access denial: {f:?} (node registered ⇒ NOT a Start error) — correct"
        ),
        Err(ListenFunnelError::Start(e)) => panic!(
            "a REGISTERED node's funnel denial was misdiagnosed as a lifecycle Start error: {e:?}"
        ),
        // `ListenFunnelError` is `#[non_exhaustive]`; any future non-`Start` variant is still an
        // access/engine error (acceptable here) — the invariant under test is "not misreported as Start".
        Err(other) => eprintln!("[f5] other typed (non-Start) funnel error, acceptable: {other:?}"),
    }

    srv.close(Some(Duration::from_secs(5))).await;
}
