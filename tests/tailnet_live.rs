//! LIVE tailnet integration test against **real** Tailscale (`controlplane.tailscale.com`).
//!
//! This is the headline OSS-release validation: it proves the pure-Rust fork can actually
//! register with real Tailscale, join a real tailnet, get a real `100.x` CGNAT IP, and read
//! its self-node / status / netmap — not just compile.
//!
//! It is **gated** and **skips cleanly** (does not fail) unless both:
//!   - `TS_RS_TEST_NET` is truthy (`ts_test_util::run_net_tests()`), and
//!   - `TS_RS_TEST_AUTHKEY` is set (`ts_test_util::auth_key()`).
//!
//! The auth key is read from the environment (never hardcoded). The fork runs an in-process
//! userspace netstack with TUN off by default, so this does **not** touch host routing/DNS and
//! does **not** require root.
//!
//! Run incantation:
//!
//! ```sh
//! TS_RS_EXPERIMENT=this_is_unstable_software TS_RS_TEST_NET=1 \
//!   TS_RS_TEST_AUTHKEY=<key> \
//!   cargo test --test tailnet_live -- --nocapture --test-threads=1
//! ```

use std::{net::IpAddr, time::Duration};

use tailscale::{Config, Device};
use tokio::time::timeout;

/// Tailscale's CGNAT range (`100.64.0.0/10`): every real-Tailscale node IPv4 lives here.
const CGNAT_BASE: [u8; 4] = [100, 64, 0, 0];
const CGNAT_PREFIX_LEN: u8 = 10;

/// Generous ceiling for the whole live exchange against real Tailscale: registration over the
/// Noise transport, the first map response, and netmap settling can each take several seconds.
const LIVE_TIMEOUT: Duration = Duration::from_secs(60);

/// Whether `ip` is inside Tailscale's `100.64.0.0/10` CGNAT range.
fn is_cgnat_ipv4(ip: std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    // /10 means the top 10 bits must match the base. Compare as a u32 masked to the prefix.
    let mask: u32 = u32::MAX << (32 - CGNAT_PREFIX_LEN);
    let base = u32::from_be_bytes(CGNAT_BASE);
    (u32::from_be_bytes(octets) & mask) == (base & mask)
}

#[tokio::test]
async fn live_tailnet_join() {
    // Gate exactly like tests/basic.rs: skip (not fail) when net tests are disabled or no auth
    // key is provided.
    if !ts_test_util::run_net_tests() {
        eprintln!("net tests disabled (set TS_RS_TEST_NET=1); skipping live tailnet test");
        return;
    }
    let Some(auth_key) = ts_test_util::auth_key() else {
        eprintln!("no TS_RS_TEST_AUTHKEY set; skipping live tailnet test");
        return;
    };

    // The crate requires this env var to be set to acknowledge the experimental status. The run
    // incantation sets it, but mirror tests/basic.rs's `make_ts_device` and set it defensively so
    // the test self-documents the requirement.
    // SAFETY: set at the very start of the test, before this test spawns any threads that read
    // the environment; `std::env::set_var` is `unsafe` in edition 2024 only because concurrent
    // env access is unsound, which does not occur here. The var gates the experimental build at
    // runtime (read in `Device::new`); a global `.cargo/config.toml [env]` was rejected because
    // it would defeat the deliberate `TS_RS_EXPERIMENT` opt-in for ordinary builds.
    unsafe { std::env::set_var("TS_RS_EXPERIMENT", "this_is_unstable_software") };

    // Build a default config: control defaults to `https://controlplane.tailscale.com/` — real
    // Tailscale, exactly what we want to validate against. Use an identifiable, unique hostname so
    // the node is easy to spot and deregister out-of-band.
    let mut config = Config::default();
    let rand_suffix: u32 = rand::random();
    let hostname = format!("tsrs-livetest-{rand_suffix:08x}");
    config.requested_hostname = Some(hostname.clone());
    // `ephemeral` already defaults to `true`, so the node is GC'd by control shortly after it
    // disconnects — belt-and-suspenders cleanup on top of the orchestrator's API deregistration.

    eprintln!(
        "[live] joining real Tailscale at {} as hostname {hostname:?}",
        config.control_server_url
    );

    let result = timeout(LIVE_TIMEOUT, async move {
        // ---- THE JOIN: registration against real Tailscale ----
        // `Device::new(..)` IS the join (no separate up/connect). If real Tailscale rejects our
        // Noise handshake / registration, this is where it fails — and that failure is itself the
        // critical result.
        let dev = Device::new(&config, Some(auth_key))
            .await
            .expect("Device::new (registration against real Tailscale) must succeed");

        // ---- assigned IPv4 must be a real Tailscale CGNAT address ----
        let ipv4 = dev
            .ipv4_addr()
            .await
            .expect("assigned tailnet IPv4 must be readable after registration");
        eprintln!("[live] assigned tailnet IPv4: {ipv4}");
        assert!(
            !ipv4.is_unspecified(),
            "assigned IPv4 must not be 0.0.0.0 (registration did not assign an address)"
        );
        assert!(
            is_cgnat_ipv4(ipv4),
            "assigned IPv4 {ipv4} must be in Tailscale's 100.64.0.0/10 CGNAT range (proof it is a \
             real Tailscale-assigned address)"
        );

        // ---- self_node() must be populated with a stable identity ----
        let me = dev
            .self_node()
            .await
            .expect("self_node() must be populated after registration");
        eprintln!(
            "[live] self_node: stable_id={:?} hostname={:?} node_key={:?} tailnet={:?}",
            me.stable_id, me.hostname, me.node_key, me.tailnet
        );
        assert!(
            !me.stable_id.0.is_empty(),
            "self node must have a non-empty stable id (real Tailscale node identity)"
        );
        // The self node's tailnet IPv4 must match what ipv4_addr() reported.
        assert_eq!(
            me.tailnet_address.ipv4.addr(),
            ipv4,
            "self_node tailnet IPv4 must match the device's assigned IPv4"
        );
        // FQDN (MagicDNS name) should be derivable once control sends the tailnet domain.
        let fqdn = me.fqdn_opt(false);
        eprintln!("[live] self MagicDNS fqdn: {fqdn:?}");

        // ---- status() must return; exercise peer accessors without hard-failing on empty set ----
        let status = dev.status().await.expect("status() must return");
        let self_status = status
            .self_node
            .as_ref()
            .expect("status().self_node must be populated after a netmap is received");
        eprintln!(
            "[live] status: self={} ({}), peers={}",
            self_status.display_name,
            self_status.ipv4,
            status.peers.len()
        );
        assert_eq!(
            self_status.ipv4,
            IpAddr::V4(ipv4),
            "status self IPv4 must match the assigned address"
        );
        for peer in &status.peers {
            eprintln!(
                "[live]   peer: {} {} exit_node={}",
                peer.display_name, peer.ipv4, peer.is_exit_node
            );
        }

        // ---- watch_netmap(): must yield the current peer set without hard-failing if empty ----
        let netmap = dev
            .watch_netmap()
            .await
            .expect("watch_netmap() must return a receiver");
        let peers_now = netmap.borrow().clone();
        eprintln!(
            "[live] watch_netmap current peer count: {}",
            peers_now.len()
        );
        // The tailnet may legitimately have zero other peers; do not hard-fail on an empty set.

        // ---- MagicDNS resolve: deterministic self-resolution ----
        // resolve() is an in-process netmap lookup that also resolves our own name (like tsnet's
        // dnsMap). Resolving our own hostname must yield our own assigned IPv4.
        let resolved_self = dev
            .resolve(&me.hostname)
            .await
            .expect("resolve() of our own hostname must not error");
        eprintln!("[live] resolve({:?}) -> {resolved_self:?}", me.hostname);
        assert_eq!(
            resolved_self,
            Some(ipv4),
            "resolving our own MagicDNS hostname must return our own assigned tailnet IPv4"
        );
        // If the tailnet has other peers, resolving the first peer's display name should also work,
        // but be lenient — peer names may be FQDNs and the set may be empty.
        if let Some(first_peer) = peers_now.first() {
            let peer_resolved = dev.resolve(&first_peer.display_name).await;
            eprintln!(
                "[live] resolve(peer {:?}) -> {peer_resolved:?}",
                first_peer.display_name
            );
        }

        // Return identity for reporting / out-of-band deregistration.
        (
            hostname,
            me.stable_id.0.clone(),
            format!("{:?}", me.node_key),
            ipv4,
            fqdn,
        )
    })
    .await
    .expect(
        "live tailnet join must complete within the timeout (real Tailscale was unreachable \
             or registration hung)",
    );

    let (hostname, stable_id, node_key, ipv4, fqdn) = result;

    // ---- best-effort clean shutdown of the device runtime ----
    // (Node deregistration via the Tailscale API is handled by the orchestrator outside this test;
    // the auth key for that is intentionally NOT present here. The node is also ephemeral, so
    // control GCs it shortly after this disconnect.)
    //
    // We've already moved `dev` into the timed block (so its accept loops stop at end of scope).
    // Nothing further to shut down here; report the identity for deregistration.
    eprintln!("================ LIVE TAILNET JOIN: PROOF OF REGISTRATION ================");
    eprintln!("hostname:   {hostname}");
    eprintln!("stable_id:  {stable_id}");
    eprintln!("node_key:   {node_key}");
    eprintln!("tailnet_ip: {ipv4}");
    eprintln!("fqdn:       {fqdn:?}");
    eprintln!("=========================================================================");
}
