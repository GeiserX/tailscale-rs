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
  permanent (`AuthRejected`/`KeyExpired`) from recoverable (`NeedsLogin` — keeps retrying) and
  transient (`NetworkUnreachable`). v0.6.5.
- **Active exit node** — `Device::active_exit_node()` / `Status.active_exit_node` (Go
  `Status.ExitNodeStatus.ID`): the resolved, fail-closed engaged exit, not the configured selector.
  v0.6.5.
- **WhoIs user + capabilities** — `WhoIs.capabilities` from the node `CapMap`; `WhoIs.user` from the
  netmap `UserProfiles` join. v0.6.5. *(Per-node `online`/`last_seen` still not retained.)*
- **`russh` 0.61.2 security bump** (GHSA-wwx6-x28x-8259), ssh-feature-only; ring-only invariant
  preserved. v0.6.5.

Recently landed (tracked): **live Tailnet-Lock (TKA) enforcement** — per-peer key-signature
verification is now **active and fail-closed** at the peer-trust chokepoint, matching Go's
`tkaFilterNetmapLocked`. Once a verified `Authority` has been synced from control (over the internal
watch channel, only after `VerifiedAumChain::verify`), peers with a missing or unauthorized signature
are dropped; with no lock synced every peer is admitted, and a disabled lock clears enforcement. The
remaining TKA parity items are narrower: disablement-secret verification, the two known
under-enforcement gaps (rotation-obsolete dropping, `UnsignedPeerAPIOnly`), and surfacing a
self-locked-out health warning — see the deferred list below and issue #7.

## Where we are (v0.8.1 — near-complete tsnet parity)

> Per-lane percentages below were last measured at v0.5.39; the numbered roadmap was reconciled
> against the tree at v0.8.1 (see "Roadmap" — 16/21 shipped, 1 genuinely open). Treat the lane
> percentages as a floor, not a ceiling.

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
- **Tailnet Lock peer-key enforcement (active)** — per-peer node-key signature verification is
  threaded through the domain `Node` and **enforcing** at the `ts_runtime` peer-trust chokepoint,
  matching Go's `tkaFilterNetmapLocked`. A verified `ts_tka::Authority` is delivered from the control
  runner over an internal watch channel — only after `VerifiedAumChain::verify` — and the chokepoint
  then fails closed on missing/unauthorized signatures (self is structurally never filtered). With no
  lock synced, behavior is unchanged (admit-all); a disabled lock clears enforcement. The narrower
  remaining items (disablement-secret verification, the rotation-obsolete and `UnsignedPeerAPIOnly`
  under-enforcement gaps, self-locked-out health warning) are in the deferred list below and
  [SECURITY.md](../SECURITY.md).

### Deferred (in-scope eventually, not blocked externally — with reasons)
- **TKA disablement-secret verification** — the cryptographic proof that a given lock *disable* is
  authorized is not yet checked, so a disable is currently taken at face value. Control is already
  trusted for the enable/disable toggle (it cannot forge-admit a peer either way — admission still
  requires a key in the verified chain), so this is a hardening item, not an open admit-all hole (see
  [SECURITY.md](../SECURITY.md)).
- **Rotation-obsolete peer dropping** — Go's `rotationTracker` drops a peer whose key was rotated
  away even when the old signature still validates (clone/replay defense); we currently admit such a
  key. This is genuine *under*-enforcement (more permissive than Go) and is not structurally
  closeable yet — it needs a `node_key_authorized_with_details` path plus a whole-netmap rotation
  pass.
- **Self-locked-out health warning** — Go surfaces a health warning when the node's own key is not
  authorized under an active lock. Self is structurally never filtered here (the self node never
  enters the peer db), so there is no lockout risk, but the advisory warning is not yet surfaced.
- **`ts_tka` CTAP2-CBOR cross-validation against Go test vectors** — byte-for-byte wire
  compatibility is asserted by construction, not proven; a *successful* TKA verification should be
  treated as advisory until vectors land.
- **`UnsignedPeerAPIOnly`** — the peerAPI-only network-access carve-out for unsigned peers under
  tailnet lock; Go admits such peers unsigned, whereas an active lock here rejects unsigned peers
  outright (*more* restrictive — a connectivity gap in the safe direction, surfacing only if the node
  model ever ingests that field).
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

> **Status reconciled at v0.8.1** (2026-06-10) against the actual tree. The original Tier-1..5
> numbered list (authored ~v0.5.39) is **badly stale**: of its 21 items, **16 shipped, 4 are partial
> by design / external-blocked, and only 1 is genuinely unbuilt**. The closed items are preserved
> below (struck, with the proof) so the history is legible; the live work is the short
> "**Actually remaining**" list. Don't re-investigate a struck item as if open — that mis-step is
> exactly what the closed `~~item~~` lines exist to prevent (it cost a misdiagnosis on #24).

### Actually remaining (the real backlog)

- **Netstack sharding** (was Tier-3 #9; bead `tsr-4pp`) — the one fully-unbuilt numbered item. One
  shared smoltcp poll loop serves all flows; shard per ~50–100 sessions. smoltcp has no SACK/auto-tune,
  so **benchmark over a real exit before committing the dataplane** (deliberately gated, not neglected).
- **Tailnet-Lock (TKA) enforcement hardening** (part of old #20; issue #7) — core enforcement now
  **ships active and fail-closed**, matching Go's `tkaFilterNetmapLocked`: a verified `Authority`
  reaches the `peer_tracker` over an internal watch channel (only after `VerifiedAumChain::verify`)
  and drops peers with a missing/unauthorized signature. What remains is narrower: disablement-secret
  verification, rotation-obsolete dropping, the `UnsignedPeerAPIOnly` carve-out, and a self-locked-out
  health warning (see the deferred list and "Invariants").
- **Own/private DERP server** (part of old #20) — `ts_derp` is client + mesh-frame types only (no
  server accept loop). Consuming public relays as fallback already works; running our own mesh is the
  open piece. Low priority for the egress use case.
- **DERP connectivity floor for no-region peers** — ✅ **shipped v0.8.1** (#24): a peer with no netmap
  home region was denied any underlay route; now the relay region is inferred (observed-route à la Go
  `c.derpRoute`, then home-region last resort). Listed here only as the most recent close.

A handful of **partial-by-design** items are NOT backlog (they are as-complete-as-they-can-be for our
deployment): client-side ACME is shipped but a self-hosted control plane 501s on `set-dns` (external,
old #10); TUN mode is shipped but userspace-only seams (`tcp_connect`/loopback) are `UnsupportedInTunMode`
by design (old #14); `listen_funnel` client leg is shipped but the public relay leg is Tailscale-operated
and external-blocked (old #16). These are environment limits, not engine work.

### Closed (shipped — verified in-tree at v0.8.1)

Tier 1 — ~~direct-path orchestration glue~~ (`direct.rs` `run_pinger`/`run_stun_prober`/`run_call_me_maybe`),
~~disco↔node-key binding~~ (`sock.rs` `BindingVerifier`, fail-closed; the `TODO(parity)` is gone),
~~musl static build + CI lane~~ (`ci.yml` `musl_static`, aws-lc-absence guard).
Tier 2 — ~~`config.tags`→`HostInfo.request_tags`~~ (`client.rs:298`, `register.rs`),
~~config-driven `ephemeral`~~ (`Config::ephemeral`), ~~upstream proxy dialer for the exit hop~~
(`ProxyExitDialer`, `ExitProxyConfig`), ~~netmap stream resumption~~ (`MapSession`/`advance_session`).
Tier 3 — ~~`tcp_buffer_size` knob~~ (default already 256 KiB; per-deployment `Config::tcp_buffer_size`).
Tier 4 — ~~Serve config + `RegisterFallbackTCPHandler`~~ (`ts_runtime/src/serve.rs` `ServeManager`),
~~bindings lane propagation~~ (FFI/Python/Elixir at ~90%, not the stale "~30%").
Tier 5 — ~~IPv6 on the tailnet (flag-gated)~~ (`Config::enable_ipv6`), ~~full MagicDNS server~~
(`magic_dns.rs`, `100.100.100.100:53` + exit-node DoH), ~~`ListenSSH`~~ (`src/ssh/`, feature-gated),
~~`ListenService`/VIP + ServiceMode~~ (consume + advertise), ~~symmetric-NAT traversal~~ (Go has no
256-port spray; the hard-NAT `Stun4LocalPort` guess **is** implemented — at parity), ~~Taildrop~~,
~~key rotation~~, ~~metrics/observability~~, ~~WIF fields + `Sys()` accessors~~.

> Reclassified, not "done by us": old #10 (ACME) — real Tailscale has no `cert/<domain>` RPC; the node
> is the ACME client, which is shipped. Old #19 (birthday-paradox spray) — a real spray was rejected as
> a Go divergence + SSRF risk; matching Go's actual `Stun4LocalPort` tactic is the parity bar and is met.

## Cross-cutting doc-hygiene
- ~~Reconcile README DERP-vs-direct~~ — **done.** The README now states direct NAT traversal is
  real and DERP is the fallback used only when no direct path is available.
- ~~Clarify `fallback_resolvers`~~ — **done.** The README states fail-closed NXDOMAIN is the
  *default* and that configuring a resolver opts in to forwarding query names upstream.
- Security posture is now documented in full in [SECURITY.md](../SECURITY.md) (unaudited crypto, the
  active TKA enforcement and its remaining gaps, peerAPI capability gap, at-rest key handling,
  anti-leak posture).

## Invariants that must never regress
- Real origin IP must never leak; no silent direct-dial fallback (fail-closed is sacred).
- IPv4-only on the tailnet by default (bind `0.0.0.0`, never `::`); any IPv6 work is opt-in and must
  not weaken the deployment posture.
- Stay on `ring` for the tailnet/TLS path; confine `aws-lc-rs` to the optional `ssh` feature.
- Keep `panic=unwind` (actor model isolates per-flow panics; `panic=abort` would weaken isolation).
- Unaudited crypto is acceptable *only* because the deployer owns both ends (their control plane +
  their exits) and pins the capability version.
