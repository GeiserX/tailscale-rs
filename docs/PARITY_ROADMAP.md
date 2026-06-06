# tsnet Parity Roadmap

> **Goal:** rewrite Go `tsnet` completely into Rust. `tailscale-rs` is the committed
> pure-Rust Tailscale node that backs this project's the exit node egress path and the this project
> per-session client. This document is the durable plan; live status is tracked in beads
> (`bd list`, prefix `tsr`).

## Where we are (v0.5.39 — near-complete tsnet parity)

Crucially, the fork is **more mature than its own stale README suggests**:

- **Direct-path P2P is real** — disco Ping/Pong/CallMeMaybe, RTT-based best-addr selection, trust
  windows, DERP-as-fallback. It is **not** DERP-relay-only. IPv6 direct paths negotiate when
  `enable_ipv6` is set (v0.5.37).
- **No `panic=abort`** — kameo actors isolate per-flow panics; crash isolation is intact.
- **Anti-leak is type-encoded** — `DirectDialer` structurally refuses exit egress; egress
  fail-closes when no `/0` route matches; no host-socket fallback exists in `Device::tcp_connect`.
- **musl static + ring-only** — CI musl lane + `aws-lc-rs`-absence guard; aws-lc confined to the
  optional `ssh` feature.

Per-lane parity estimate (updated v0.5.39): A (Status/WhoIs) ~85%, B (MagicDNS) ~85% (full netstack
`100.100.100.100:53` server; host-resolver redirect only missing in TUN mode), C (forwarding) ~85%,
D (Ping/direct) ~90% (IPv6 direct paths land; only symmetric-NAT spray skipped),
E (TLS/Serve/ACME) ~80% (client-side ACME DNS-01 issuance shipped behind `acme`; `listen_tls` issues
real certs against a `set-dns`-capable control plane; only the stored Serve-state runtime + the
external Funnel relay leg remain), FFI/Python/Elixir bindings ~90% (full Device surface propagated).

### Shipped since v0.4.0 (the parity push)
Taildrop send/recv, CapturePcap, TKA Ed25519 fix, node-key rotation, WIF/OAuth bootstrap, loopback
SOCKS5 (v0.5.27–v0.5.32); a multi-reviewer hardening pass (v0.5.33); then the parity sweep:
**FFI/Python/Elixir lane propagation** (v0.5.34), **turnkey `listen_ssh` login-shell** (v0.5.35),
**disco/STUN observability counters** (v0.5.36), **IPv6 local disco candidates** (v0.5.37),
**client-side ACME (RFC 8555 DNS-01) + `set-dns` RPC** (v0.5.38), **`listen_tls`→ACME wiring**
(v0.5.39). Tier 1 (direct-path glue, disco↔node-key binding, musl lane) and Tier 2 (tags, ephemeral,
upstream-proxy dialer, netmap resumption) were verified already-complete in-tree.

### Remaining (deferred / external — beaded under `tsr-am9`)
- `tsr-am9.7` **TUN-mode MagicDNS** — deep host-DNS + dedicated-netstack change (netstack mode is
  fully functional; TUN mode's host DNS is inert). Supervised session.
- `tsr-am9.8` **Serve get/set_serve_config + accept-loop runtime** — awkward Accept-handback seam;
  needs a serve-state product decision.
- `tsr-am9.9` **Service advertise-to-control** — consume-side done; advertise-side low value
  (ACL-preassigned VIPs work), needs a wire-field decision.
- `tsr-am9.10` **Symmetric-NAT port spray** — deliberately skipped (low value for the DERP-acceptable
  k8s/proxy deployment; single-port guess already covers easy cases).
- `tsr-am9.11` **Funnel public ingress relay** — EXTERNAL infra dependency (Tailscale-operated
  relay); un-buildable against a self-hosted control plane; `listen_funnel` correctly fail-closed.
- `tsr-4pp` **Netstack sharding** — benchmark-gated; needs a real residential-exit measurement first.
- `Sys()` internals — satisfied via typed accessors (`self_node`/`status`/`watch_netmap`/`whois`).

## Consumers and the seams they need

- **this project egress** — holds a `Device` handle and obtains per-flow `AsyncRead+AsyncWrite`
  streams from `Device::tcp_connect`, gated by `Config::exit_node`. This **is** the dialer; do not
  reach for `ts_forwarder::RealDialer` (that is the *inbound* exit-node-server chokepoint, the wrong
  direction). Fail-closed composes because there is no host-socket fallback in the egress path.
- **this project per-pod client** — pure userspace netstack (no TUN/root), ephemeral auth-key join to
  a self-hosted control plane, exit-node selection, graceful teardown. Most of this exists; gaps are tags, ephemeral
  config, and the upstream residential-proxy hop.

## Roadmap (ranked by leverage)

### Tier 1 — Highest leverage (unblocks both consumers)
1. **Direct-path orchestration glue** — wire `ts_netcheck::StunProber` into
   `MagicSock::self_endpoints`; add a runtime loop that sends `CallMeMaybe` over DERP and runs
   periodic `send_disco_pings`. Core exists; only orchestration is missing. Skip the
   birthday-paradox symmetric-NAT spray (k8s pods are low-bandwidth, acceptably DERP-relayed).
2. **Enforce disco↔node-key binding** in the netmap-owning layer (`ts_magicsock/src/disco.rs:125`,
   `sock.rs:400`) — the one explicit `TODO(parity)`, security-relevant.
3. **musl static-build target + CI lane** — `ssh`/`aws-lc-rs` feature OFF (ring-only stays
   musl-clean). Required for minimal pod images and a self-contained proxy daemon.

### Tier 2 — Deployment-critical correctness
4. **Wire `config.tags` → `HostInfo.request_tags`** at registration (`ts_control/.../register.rs`).
   Currently dropped; silently breaks a self-hosted control plane tag-keyed route auto-approvers.
5. **Make `ephemeral` config-driven** (`register.rs` hardcodes `true`) — persistent exit nodes get
   GC'd otherwise.
6. **Upstream SOCKS/HTTP proxy dialer seam** for the exit hop — residential a residential proxy provider egress sits
   *behind* the exit node; `HostExitDialer` must dial via an upstream proxy.
7. **Netmap stream resumption on reconnect** (`ts_control/src/tokio/client.rs:211`).

### Tier 3 — Performance hardening (before production bulk traffic)
8. **`tcp_buffer_size` 16KiB → 256KiB** as a per-deployment knob — the 16KiB window caps a flow at
   ~1.6 Mbps@80ms RTT, throttling large model responses *at 1x*. Highest-ROI perf change.
9. **Shard the netstack** per ~50-100 sessions in k8s instead of one shared smoltcp poll loop.
   smoltcp has no SACK/auto-tune — **benchmark over a real residential exit before committing the
   dataplane**.

### Tier 4 — True tsnet API-surface gaps
10. **ACME-over-control cert RPC** (`POST /machine/<key>/cert/<domain>`) to unblock all of Lane E.
11. **Serve config** (`Get/SetServeConfig`) + `RegisterFallbackTCPHandler`.
12. **Propagate the 5 lanes into `ts_ffi`/`ts_python`/`ts_elixir`** (~30% today).

### Tier 5 — Full-parity completion (the "build everything" set)
Previously a "don't-build for egress" list; per direction we are pursuing **complete** tsnet parity,
so these are now in scope:
13. **IPv6 on the tailnet** — gated behind a build/runtime flag; default stays IPv4-only to preserve
    the IPv6-off leak invariant for the proxy/k8s deployments. Parity for general embedders.
14. **TUN-mode transport** (`ts_transport_tun`) to full parity — for embedders that want a real
    kernel interface.
15. **Full MagicDNS server** (`100.100.100.100` resolver) + exit-node DNS.
16. **`ListenFunnel`** (public ingress via relay, 443/8443/10000) + FunnelOptions.
17. **`ListenSSH`** (Tailscale SSH server, `feature/ssh`) — isolated in a non-musl binary.
18. **`ListenService` / Tailscale Services (VIP)** + ServiceMode TCP/HTTP.
19. **Symmetric-NAT birthday-paradox hole-punching** — full Go NAT-traversal parity.
20. **Taildrop / file transfer**, **Tailnet Lock**, **key rotation**, **private DERP / peer relays**,
    **observability/metrics**.
21. **Workload identity federation fields** (`ClientID`/`IDToken`/`Audience`) + `Sys()` internals.

## Cross-cutting doc-hygiene (must-fix — privacy product)
- Reconcile README: it claims both "DERP for all communication" and "direct NAT traversal
  implemented." Code says direct is real.
- Clarify `fallback_resolvers`: "never forwards upstream" is the **default**, not an invariant — a
  configured resolver *does* forward query names.

## Invariants that must never regress
- Real origin IP must never leak; no silent direct-dial fallback (fail-closed is sacred).
- IPv4-only on the tailnet by default (bind `0.0.0.0`, never `::`); any IPv6 work is opt-in and must
  not weaken the proxy/k8s deployment posture.
- Stay on `ring` for the tailnet/TLS path; confine `aws-lc-rs` to the optional `ssh` feature.
- Keep `panic=unwind` (actor model isolates per-flow panics; `panic=abort` would weaken isolation).
- Unaudited crypto is acceptable *only* because we own both ends (our a self-hosted control plane + our exits) and pin
  the capability version.
