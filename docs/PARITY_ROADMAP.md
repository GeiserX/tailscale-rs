# tsnet Parity Roadmap

> **Goal:** a complete pure-Rust port of Go `tsnet`. This document is the durable plan; live
> status is tracked in beads (`bd list`, prefix `tsr`).

## Recently closed (v0.6.4–v0.6.5)

The consumer-facing tsnet gaps the embedders actually hit are now closed and live-verified against
`controlplane.tailscale.com`:

- **Runtime exit-node switch** — `Device::set_exit_node` (Go `EditPrefs(ExitNodeID/IP)`). v0.6.4.
- **Logout / deregister** — `Device::logout` (Go `LocalClient.Logout`): re-register with a past
  expiry. v0.6.5.
- **Typed registration outcome** — `Device::wait_until_running(timeout) -> Result<(), RegistrationError>`
  + `Device::watch_state()` (`DeviceState` stream). Replaces poll-`ipv4_addr` loops; distinguishes
  permanent (`AuthRejected`/`KeyExpired`/`NeedsLogin`) from transient (`NetworkUnreachable`). v0.6.5.
- **Active exit node** — `Device::active_exit_node()` / `Status.active_exit_node` (Go
  `Status.ExitNodeStatus.ID`): the resolved, fail-closed engaged exit, not the configured selector.
  v0.6.5.
- **WhoIs user + capabilities** — `WhoIs.capabilities` from the node `CapMap`; `WhoIs.user` from the
  netmap `UserProfiles` join. v0.6.5. *(Per-node `online`/`last_seen` still not retained.)*

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

Most recent wave:
- **Serve `Path` / `Redirect` handlers** — HTTP path-prefix mux and HTTP 3xx redirect targets added
  to `ServeTarget`, validated and dispatched on the TLS-terminated stream, fail-closed (unmatched
  path → 404, backend dial failure → drop). Hand-rolled HTTP head parsing; no axum/hyper added.
- **Recursive MagicDNS in TUN mode** — the TUN-mode `100.100.100.100:53` resolver now forwards
  non-tailnet names recursively (previously inert in TUN mode), reusing the forwarder netstack's
  overlay-backed `Channel` and the same `decide`/`recursive_plan` path as netstack mode, so the
  IPv4-only egress filter and fail-closed NXDOMAIN default are inherited.
- **Tailnet Lock peer-key enforcement (partial)** — per-peer node-key signature verification is
  threaded through the domain `Node` and wired at the `ts_runtime` peer-trust chokepoint, gated
  behind an optional `ts_tka::Authority` and unit-tested. With no `Authority` (always, today)
  behavior is unchanged; when one is supplied the chokepoint fails closed on bad/missing signatures.
  Live `Authority` construction is **deferred** — see the deferred list below and
  [SECURITY.md](../SECURITY.md).

### Deferred (in-scope eventually, not blocked externally — with reasons)
- **AUM-sync RPC + live TKA `Authority`** — the `/machine/tka/sync/*` Noise RPC family plus the
  AUM-chain replayer that folds `AddKey`/`RemoveKey`/`UpdateKey`/`Checkpoint` into a trusted-key
  `State`. `MapResponse` carries only the AUM head hash and the per-peer signature, never the
  trusted keys, so the `Authority` cannot be derived from data the client already receives. Until
  this lands, the wired TKA enforcement is inert (see [SECURITY.md](../SECURITY.md)).
- **`ts_tka` CTAP2-CBOR cross-validation against Go test vectors** — byte-for-byte wire
  compatibility is asserted by construction, not proven; a *successful* TKA verification should be
  treated as advisory until vectors land.
- **`UnsignedPeerAPIOnly`** — the peerAPI-only network-access carve-out for unsigned peers under
  tailnet lock; today an active lock rejects unsigned peers outright.
- **DERP mesh / private DERP server** — running our own DERP relay mesh (consuming public relays as
  a fallback path is implemented).
- **TKA signing** — initiating/mutating tailnet-lock state (only client-side *verification* is in
  scope here).
- **UPnP / PCP / NAT-PMP portmapper** — gateway port-mapping for better direct connectivity.
- **App connector** — `4via6`-style application connectors.
- **`4via6`** subnet-route encoding.
- **Serve get/set_serve_config + accept-loop runtime** — the handler *types* ship (`Path`/`Redirect`/
  `Proxy`/`Text`/`TcpForward`); the stored serve-state runtime and the Accept-handback loop remain,
  pending a serve-state design decision.
- **Service advertise-to-control** — consume-side done; advertise-side is low value (ACL-preassigned
  VIPs work) and needs a wire-field decision.
- **Symmetric-NAT birthday-paradox port spray** — deliberately skipped (low value for the
  DERP-acceptable userspace-netstack deployment; the single-port guess already covers easy cases).
- **Netstack sharding** (`tsr-4pp`) — benchmark-gated; needs a real exit-egress measurement
  first.
- `Sys()` internals — satisfied via typed accessors (`self_node`/`status`/`watch_netmap`/`whois`).

### Blocked by external dependency
These cannot be built against a self-hosted control plane and depend on Tailscale-operated infra or
out-of-band setup:
- **Funnel public ingress relay** — depends on the Tailscale-operated public relay leg; un-buildable
  against a self-hosted control plane. `listen_funnel` correctly fail-closed.
- **ACME on a self-hosted control plane** — a self-hosted control plane may return `501` for the
  ACME-over-control cert RPC; client-side ACME (DNS-01) is implemented but the control-plane leg is
  not available there.
- **OIDC / SSO** — identity-provider integration is a control-plane/deployment concern.
- **Network flow logs** — depends on the control-plane log-collection pipeline.
- **Taildrop relay** — the relayed (non-direct) Taildrop path depends on Tailscale infra (direct
  send/recv is implemented).
- **Node sharing** — cross-tailnet sharing is a control-plane feature.

## Upstream tracking

Upstream [`tailscale/tailscale-rs`](https://github.com/tailscale/tailscale-rs) is now active. Going
forward this fork tracks upstream and aims to upstream or re-base fork-specific work where it makes
sense, while keeping the anti-leak/egress posture (see `AGENTS.md`).

## Consumers and the seams they need

- **Userspace egress client** — holds a `Device` handle and obtains per-flow `AsyncRead+AsyncWrite`
  streams from `Device::tcp_connect`, gated by `Config::exit_node`. This **is** the dialer; do not
  reach for `ts_forwarder::RealDialer` (that is the *inbound* exit-node-server chokepoint, the wrong
  direction). Fail-closed composes because there is no host-socket fallback in the egress path.
- **Per-pod userspace client** — pure userspace netstack (no TUN/root), ephemeral auth-key join to
  the control plane, exit-node selection, graceful teardown. Most of this exists; gaps are tags,
  ephemeral config, and the upstream residential-proxy hop.

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
   Currently dropped; silently breaks a self-hosted control plane's tag-keyed route auto-approvers.
5. **Make `ephemeral` config-driven** (`register.rs` hardcodes `true`) — persistent exit nodes get
   GC'd otherwise.
6. **Upstream SOCKS/HTTP proxy dialer seam** for the exit hop — residential proxy egress sits
   *behind* the exit node; `HostExitDialer` must dial via an upstream proxy.
7. **Netmap stream resumption on reconnect** (`ts_control/src/tokio/client.rs:211`).

### Tier 3 — Performance hardening (before bulk traffic)
8. **`tcp_buffer_size` 16KiB → 256KiB** as a per-deployment knob — the 16KiB window caps a flow at
   ~1.6 Mbps@80ms RTT, throttling large model responses *at 1x*. Highest-ROI perf change.
9. **Shard the netstack** per ~50-100 sessions instead of one shared smoltcp poll loop.
   smoltcp has no SACK/auto-tune — **benchmark over a real exit before committing the
   dataplane**.

### Tier 4 — True tsnet API-surface gaps
10. **ACME-over-control cert RPC** (`POST /machine/<key>/cert/<domain>`) to unblock all of Lane E.
11. **Serve config** (`Get/SetServeConfig`) + `RegisterFallbackTCPHandler`.
12. **Propagate the 5 lanes into `ts_ffi`/`ts_python`/`ts_elixir`** (~30% today).

### Tier 5 — Full-parity completion (the "build everything" set)
Previously a "don't-build for egress" list; per direction we are pursuing **complete** tsnet parity,
so these are now in scope:
13. **IPv6 on the tailnet** — gated behind a build/runtime flag; default stays IPv4-only to preserve
    the IPv6-off leak invariant. Parity for general embedders.
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

## Cross-cutting doc-hygiene
- ~~Reconcile README DERP-vs-direct~~ — **done.** The README now states direct NAT traversal is
  real and DERP is the fallback used only when no direct path is available.
- ~~Clarify `fallback_resolvers`~~ — **done.** The README states fail-closed NXDOMAIN is the
  *default* and that configuring a resolver opts in to forwarding query names upstream.
- Security posture is now documented in full in [SECURITY.md](../SECURITY.md) (unaudited crypto, the
  inert TKA enforcement, peerAPI capability gap, at-rest key handling, anti-leak posture).

## Invariants that must never regress
- Real origin IP must never leak; no silent direct-dial fallback (fail-closed is sacred).
- IPv4-only on the tailnet by default (bind `0.0.0.0`, never `::`); any IPv6 work is opt-in and must
  not weaken the deployment posture.
- Stay on `ring` for the tailnet/TLS path; confine `aws-lc-rs` to the optional `ssh` feature.
- Keep `panic=unwind` (actor model isolates per-flow panics; `panic=abort` would weaken isolation).
- Unaudited crypto is acceptable *only* because the deployer owns both ends (their control plane +
  their exits) and pins the capability version.
