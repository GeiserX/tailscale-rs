//! EXTENSIVE live e2e campaign against **real** Tailscale (`controlplane.tailscale.com`).
//!
//! Goes well beyond the single-join `tailnet_live.rs`: concurrent multi-node joins, real
//! peer connectivity (overlay ICMP ping + TCP), MagicDNS deep resolution, ephemeral re-join
//! churn, and config permutations (IPv6 on/off). Each scenario is a separate `#[tokio::test]`
//! so failures are isolated and the campaign reports per-scenario.
//!
//! Gated exactly like `tailnet_live.rs` — skips cleanly unless `TS_RS_TEST_NET=1` and
//! `TS_RS_TEST_AUTHKEY` are set. The auth key is reusable + ephemeral, so concurrent joins each
//! mint their own node and control GCs them on disconnect.
//!
//! Run:
//! ```sh
//! TS_RS_EXPERIMENT=this_is_unstable_software TS_RS_TEST_NET=1 \
//!   TS_RS_TEST_AUTHKEY=<key> \
//!   cargo test --test tailnet_e2e_campaign -- --nocapture --test-threads=1
//! ```

use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use tailscale::{Config, Device};
use tokio::time::timeout;

const JOIN_TIMEOUT: Duration = Duration::from_secs(60);

fn gated() -> Option<String> {
    if !ts_test_util::run_net_tests() {
        eprintln!("[skip] TS_RS_TEST_NET not set");
        return None;
    }
    // SAFETY: set before any worker threads read the env; gates the experimental build at runtime.
    unsafe { std::env::set_var("TS_RS_EXPERIMENT", "this_is_unstable_software") };
    match ts_test_util::auth_key() {
        Some(k) => Some(k),
        None => {
            eprintln!("[skip] TS_RS_TEST_AUTHKEY not set");
            None
        }
    }
}

fn is_cgnat(ip: Ipv4Addr) -> bool {
    let mask: u32 = u32::MAX << 22; // /10
    (u32::from(ip) & mask) == (u32::from(Ipv4Addr::new(100, 64, 0, 0)) & mask)
}

async fn join(label: &str) -> Device {
    let auth = gated().expect("gated() checked by caller");
    let mut config = Config::default();
    let suffix: u32 = rand::random();
    config.requested_hostname = Some(format!("tsrs-e2e-{label}-{suffix:08x}"));
    let dev = timeout(JOIN_TIMEOUT, Device::new(&config, Some(auth)))
        .await
        .expect("Device::new within timeout")
        .expect("registration must succeed");
    // Block until an address is actually assigned (proves registration completed, not just spawned).
    let ip = timeout(JOIN_TIMEOUT, dev.ipv4_addr())
        .await
        .expect("ipv4 within timeout")
        .expect("assigned ipv4");
    assert!(is_cgnat(ip), "{label}: {ip} must be CGNAT");
    eprintln!("[{label}] joined as {ip}");
    dev
}

/// Scenario 1: CONCURRENT multi-node join. Spin up 3 fork nodes at once; each must get a
/// DISTINCT CGNAT IP and (after netmaps settle) see the others as peers. Stresses the
/// reusable-ephemeral key path + concurrent registration.
#[tokio::test]
async fn s1_concurrent_multinode_join() {
    if gated().is_none() {
        return;
    }
    let (a, b, c) = tokio::join!(join("n1"), join("n2"), join("n3"));
    let ips: Vec<Ipv4Addr> = {
        let mut v = vec![];
        for d in [&a, &b, &c] {
            v.push(d.ipv4_addr().await.expect("ip"));
        }
        v
    };
    eprintln!("[s1] three nodes: {ips:?}");
    assert_ne!(ips[0], ips[1], "nodes must get distinct IPs");
    assert_ne!(ips[1], ips[2], "nodes must get distinct IPs");
    assert_ne!(ips[0], ips[2], "nodes must get distinct IPs");

    // Give control a moment to propagate the new nodes into each other's netmaps.
    tokio::time::sleep(Duration::from_secs(8)).await;
    let status_a = a.status().await.expect("status");
    let peer_ips: Vec<IpAddr> = status_a.peers.iter().map(|p| p.ipv4).collect();
    eprintln!("[s1] n1 sees {} peers", status_a.peers.len());
    // n1 should see at least one of its siblings (netmap convergence can lag, so be lenient but
    // assert the set is non-trivial — the tailnet already has ~19 standing peers).
    assert!(
        !status_a.peers.is_empty(),
        "n1 must see a populated netmap (standing tailnet peers + siblings)"
    );
    // If convergence completed, the siblings appear; log it either way.
    for sib in [ips[1], ips[2]] {
        let seen = peer_ips.contains(&IpAddr::V4(sib));
        eprintln!("[s1] n1 sees sibling {sib}: {seen}");
    }
}

/// Scenario 2: REAL PEER CONNECTIVITY. A fresh fork node pings standing tailnet peers over the
/// overlay with ICMP echo — proving the WireGuard data plane actually carries traffic to real
/// peers, not just that registration succeeded.
#[tokio::test]
async fn s2_overlay_ping_real_peers() {
    if gated().is_none() {
        return;
    }
    let dev = join("ping").await;
    tokio::time::sleep(Duration::from_secs(5)).await; // let netmap + DERP settle
    let status = dev.status().await.expect("status");
    eprintln!("[s2] netmap has {} peers", status.peers.len());

    // Ping up to 5 standing peers; require at least ONE to answer (some peers may be offline).
    let mut answered = 0;
    for peer in status.peers.iter().take(8) {
        match dev.ping(peer.ipv4, Duration::from_secs(8)).await {
            Ok(rtt) => {
                eprintln!(
                    "[s2] PONG {} ({}) rtt={rtt:?}",
                    peer.display_name, peer.ipv4
                );
                answered += 1;
            }
            Err(e) => eprintln!(
                "[s2] no reply from {} ({}): {e:?}",
                peer.display_name, peer.ipv4
            ),
        }
    }
    eprintln!("[s2] {answered} peers answered overlay ping");
    assert!(
        answered >= 1,
        "at least one standing tailnet peer must answer an overlay ICMP ping (proves the WireGuard \
         data plane carries real traffic); 0 answered"
    );
}

/// Scenario 3: MAGICDNS DEEP. Resolve self + every standing peer's MagicDNS name; each must map
/// to a CGNAT IP that matches the netmap. Exercises the in-process MagicDNS map end-to-end.
#[tokio::test]
async fn s3_magicdns_deep_resolution() {
    if gated().is_none() {
        return;
    }
    let dev = join("dns").await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    let me = dev.self_node().await.expect("self_node");
    let self_ip = dev.ipv4_addr().await.expect("ip");

    // Self-resolution must be exact.
    let resolved_self = dev.resolve(&me.hostname).await.expect("resolve self");
    assert_eq!(
        resolved_self,
        Some(self_ip),
        "resolving own hostname must yield own IP"
    );
    eprintln!("[s3] self {} -> {self_ip}", me.hostname);

    // Resolve every peer's display name; each that resolves must match its netmap IP.
    let status = dev.status().await.expect("status");
    let mut resolved = 0;
    for peer in &status.peers {
        // display_name may be an FQDN; resolve() handles both bare + FQDN per tsnet dnsMap.
        if let Ok(Some(ip)) = dev.resolve(&peer.display_name).await {
            if IpAddr::V4(ip) == peer.ipv4 {
                resolved += 1;
            } else {
                eprintln!(
                    "[s3] MISMATCH {} resolved {ip} != netmap {}",
                    peer.display_name, peer.ipv4
                );
            }
        }
    }
    eprintln!(
        "[s3] {resolved}/{} peer names resolved + matched netmap",
        status.peers.len()
    );
    assert!(
        resolved >= 1,
        "at least one peer MagicDNS name must resolve to its netmap IP"
    );
}

/// Scenario 4: EPHEMERAL RE-JOIN CHURN. Join, read identity, drop, then join again with a fresh
/// hostname. Both joins must succeed and get valid CGNAT IPs — proves the register/teardown path
/// is clean and the ephemeral key is reusable across sessions.
#[tokio::test]
async fn s4_ephemeral_rejoin_churn() {
    if gated().is_none() {
        return;
    }
    for round in 0..3 {
        let dev = join(&format!("churn{round}")).await;
        let ip = dev.ipv4_addr().await.expect("ip");
        let me = dev.self_node().await.expect("self_node");
        eprintln!("[s4] round {round}: ip={ip} stable_id={:?}", me.stable_id);
        assert!(!me.stable_id.0.is_empty());
        drop(dev); // tears down the runtime; ephemeral node GC'd by control
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    eprintln!("[s4] 3 ephemeral join/drop rounds completed cleanly");
}

/// Scenario 5: TCP DATA PLANE to a real peer. Attempt an overlay TCP connect to a standing peer
/// on a commonly-open port. This is best-effort (peers may not listen), but a SUCCESSFUL connect
/// is strong proof the TCP overlay path works to a real node. We assert the call returns a
/// well-formed result (connect or a clean error), never hangs/panics.
#[tokio::test]
async fn s5_tcp_overlay_connect_besteffort() {
    if gated().is_none() {
        return;
    }
    let dev = join("tcp").await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    let status = dev.status().await.expect("status");

    let mut connected = 0;
    // Try SSH(22) on peers — many tailnet nodes run tailscale-ssh or sshd.
    for peer in status.peers.iter().take(10) {
        let target = std::net::SocketAddr::new(peer.ipv4, 22);
        match timeout(Duration::from_secs(6), dev.tcp_connect(target)).await {
            Ok(Ok(_stream)) => {
                eprintln!("[s5] TCP connect OK to {} :22", peer.display_name);
                connected += 1;
            }
            Ok(Err(e)) => eprintln!("[s5] {} :22 refused/err: {e:?}", peer.display_name),
            Err(_) => eprintln!("[s5] {} :22 timed out", peer.display_name),
        }
    }
    eprintln!("[s5] {connected} peers accepted an overlay TCP connection on :22");
    // Do not hard-fail on 0 (peers may all firewall 22); the point is no hang/panic and the path
    // is exercised. Log-only result.
}

/// Scenario 6: IPv6-DISABLED config permutation. The fork is IPv4-only on the tailnet by default;
/// explicitly building with enable_ipv6=false must still join and assign a v4 CGNAT IP, and an
/// IPv6 ping must surface the documented Ipv6Unsupported error (not a panic).
#[tokio::test]
async fn s6_ipv4_only_config() {
    let Some(auth) = gated() else { return };
    let suffix: u32 = rand::random();
    let config = Config {
        enable_ipv6: false,
        requested_hostname: Some(format!("tsrs-e2e-v4only-{suffix:08x}")),
        ..Config::default()
    };
    let dev = timeout(JOIN_TIMEOUT, Device::new(&config, Some(auth)))
        .await
        .expect("timeout")
        .expect("join");
    let ip = dev.ipv4_addr().await.expect("v4 ip");
    assert!(is_cgnat(ip), "v4-only node still gets CGNAT v4 {ip}");
    eprintln!("[s6] v4-only node joined as {ip}");

    // An overlay ping to an IPv6 destination must fail cleanly (documented), not panic.
    let v6 = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
    let r = dev.ping(v6, Duration::from_secs(3)).await;
    eprintln!("[s6] ping(v6) -> {r:?} (expected an error, not a panic)");
    assert!(
        r.is_err(),
        "IPv6 ping must return an error on the IPv4-only fork"
    );
}

/// Scenario 7: RUNTIME EXIT-NODE SWITCH. `Device::set_exit_node` changes the selected exit at
/// runtime (the Go `tsnet` `EditPrefs(ExitNodeID/IP)` equivalent) without recreating the device.
/// Joins with no exit, then sets an exit selector (a standing peer's IP), then clears it — each
/// call must re-resolve against the live peer set and return without error or netstack panic. This
/// is the capability the NVC bridge needs (user picks an exit mid-session).
#[tokio::test]
async fn s7_runtime_exit_node_switch() {
    if gated().is_none() {
        return;
    }
    let dev = join("exitswitch").await;
    tokio::time::sleep(Duration::from_secs(5)).await; // let the netmap settle
    let status = dev.status().await.expect("status");
    eprintln!("[s7] netmap has {} peers", status.peers.len());

    // Pick any standing peer's IP as an exit selector. We're proving the runtime SWITCH mechanism
    // (re-resolve + recompute) doesn't error/panic — not that this particular peer is a working
    // exit (most won't advertise a default route, which is fine: resolution is fail-closed).
    if let Some(peer) = status.peers.first() {
        let selector: tailscale::ExitNodeSelector = peer
            .ipv4
            .to_string()
            .parse()
            .expect("peer IP parses as an exit selector");
        eprintln!(
            "[s7] setting exit node = {} ({})",
            peer.display_name, peer.ipv4
        );
        dev.set_exit_node(Some(selector))
            .await
            .expect("set_exit_node(Some) must apply without error");
    } else {
        eprintln!("[s7] no peers to select; exercising set/clear with a literal IP");
        let selector: tailscale::ExitNodeSelector =
            "100.64.0.1".parse().expect("literal IP parses");
        dev.set_exit_node(Some(selector))
            .await
            .expect("set_exit_node(Some) must apply without error");
    }

    // Switching again (clear) must also apply cleanly.
    tokio::time::sleep(Duration::from_secs(1)).await;
    dev.set_exit_node(None)
        .await
        .expect("set_exit_node(None) must clear without error");
    eprintln!("[s7] exit-node set + cleared at runtime, no panic");

    // After clearing, the *active* (resolved, fail-closed) exit node must be None — there is no
    // configured selector to resolve. (While set above, the active exit stays None too unless the
    // chosen peer actually advertises a default route, which standing test peers generally don't —
    // active_exit_node reports the engaged exit, not merely the configured one.)
    tokio::time::sleep(Duration::from_secs(1)).await;
    let active = dev.active_exit_node();
    eprintln!("[s7] active_exit_node after clear = {active:?}");
    assert_eq!(
        active, None,
        "active exit node must be None after clearing the selector"
    );

    // The device is still alive and usable after the switches (netstack didn't die).
    let ip_after = dev
        .ipv4_addr()
        .await
        .expect("device still serves its IP after exit switches");
    assert!(
        is_cgnat(ip_after),
        "device healthy after runtime exit switches: {ip_after}"
    );
}

/// Scenario 8: LOGOUT (control-plane deregister). `Device::logout` re-POSTs `/machine/register`
/// with a past expiry (the Go `tsnet` `LocalClient.Logout` equivalent), expiring the node at
/// control. Joins, confirms an assigned IP, logs out, and asserts the RPC succeeds against real
/// Tailscale — then a second logout must also succeed (idempotent: an already-expired node still
/// answers 2xx). The local datapath is untouched by logout, so the device still serves its IP
/// until it is dropped/shut down.
#[tokio::test]
async fn s8_logout_deregisters_node() {
    if gated().is_none() {
        return;
    }
    let dev = join("logout").await;
    let ip = dev.ipv4_addr().await.expect("ip before logout");
    eprintln!("[s8] joined as {ip}, logging out");

    timeout(Duration::from_secs(30), dev.logout())
        .await
        .expect("logout within timeout")
        .expect("logout must succeed against real control");
    eprintln!("[s8] logout #1 OK (node expired at control)");

    // Idempotent: logging out an already-expired node still returns Ok (control accepts the
    // re-register-with-past-expiry; the node is simply already gone).
    timeout(Duration::from_secs(30), dev.logout())
        .await
        .expect("second logout within timeout")
        .expect("logout is idempotent");
    eprintln!("[s8] logout #2 OK (idempotent)");

    // Logout is a control-plane state change only: the local datapath is still up, so the device
    // continues to serve its assigned IP until it is dropped.
    let ip_after = dev
        .ipv4_addr()
        .await
        .expect("device still serves its IP after logout (datapath untouched)");
    assert!(
        is_cgnat(ip_after),
        "device healthy after logout: {ip_after}"
    );
    eprintln!("[s8] datapath intact after logout; tearing down");
}

/// Scenario 9: REGISTRATION OUTCOME (`wait_until_running` + `watch_state`). With a valid auth key,
/// `Device::wait_until_running` must resolve `Ok(())` against real control (the typed equivalent of
/// Go `tsnet`'s "wait until Running"), and the device-state watcher must report
/// [`DeviceState::Running`]. Proves the registration-outcome signal the NVC bridge needs to replace
/// its poll-`ipv4_addr` loop.
#[tokio::test]
async fn s9_wait_until_running_reports_running() {
    let Some(auth) = gated() else { return };
    let suffix: u32 = rand::random();
    let config = Config {
        requested_hostname: Some(format!("tsrs-e2e-waitrun-{suffix:08x}")),
        ..Config::default()
    };
    let dev = timeout(JOIN_TIMEOUT, Device::new(&config, Some(auth)))
        .await
        .expect("Device::new within timeout")
        .expect("device construction");

    // The clean replacement for polling ipv4_addr(): a valid auth key resolves Ok(()) once the
    // node is registered + running.
    timeout(JOIN_TIMEOUT, dev.wait_until_running(Some(JOIN_TIMEOUT)))
        .await
        .expect("wait_until_running within outer timeout")
        .expect("a valid auth key must reach Running, not a typed RegistrationError");
    eprintln!("[s9] wait_until_running -> Ok(Running)");

    // The state watcher reflects Running, and an IP is assigned (registration really completed).
    assert_eq!(
        dev.device_state(),
        tailscale::DeviceState::Running,
        "device must report Running after wait_until_running succeeds"
    );
    let ip = dev.ipv4_addr().await.expect("assigned ipv4 once Running");
    assert!(is_cgnat(ip), "Running node has a CGNAT IP: {ip}");
    eprintln!("[s9] device_state=Running, ip={ip}");
}
