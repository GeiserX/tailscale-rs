# Changelog

Record breaking or significant changes here. All dates are UTC.

## Unreleased - June 2026

Put changes for the upcoming release here!

## [0.5.3](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.3) - 2026-06-04

Direct-path NAT-traversal completion plus a netstack throughput knob (`docs/PARITY_ROADMAP.md`).

- Added: **leak-safe active STUN** for reflexive-endpoint discovery. A periodic prober sends
  RFC 5389 Binding Requests over the *single existing bound IPv4 MagicSock socket* (no second
  socket, no IPv6, no DNS egress) and harvests the reflexive (public) endpoint from the response,
  feeding the same `note_reflexive` chokepoint as the disco pong-harvest path. The STUN codec is
  hand-rolled with zero new dependencies, fully bounds-checked, and fail-closed: only `FixedAddr`
  IPv4 STUN servers from the derp map are probed (`UseDns` servers are skipped to avoid a DNS-leak
  path), the 96-bit transaction id is the authoritative anti-spoof match, the in-flight set is
  bounded (16 entries, 5 s TTL), and an unknown/stale/malformed response learns nothing. This
  completes the direct-path orchestration so a node can discover its public endpoint without
  relying solely on DERP pong-harvest.
- Added: `Config::tcp_buffer_size`, a per-deployment knob for the userspace netstack's per-socket
  TCP send/receive window, threaded `tailscale::Config` → `ts_control::Config` (transport-only) →
  the runtime's netstack configuration (applies to both the application and forwarder netstacks).
  The default per-direction buffer is raised from 16 KiB to **256 KiB**: smoltcp has no TCP window
  auto-tuning, so the old 16 KiB window capped a single flow to ~1.6 Mbps at an 80 ms RTT, visibly
  throttling large model-API responses. `None` uses the netstack default; lower it on
  memory-constrained deployments running many concurrent sockets.
- Docs: corrected the README and crate-level docs that claimed all communication relies on DERP
  relays — direct peer-to-peer NAT traversal (STUN-discovered endpoints + disco, with `CallMeMaybe`
  hole-punching over DERP) is implemented, with DERP as the fallback when no direct path exists.
  Also clarified that MagicDNS only fails closed (NXDOMAIN, never forwarded upstream) *by default*;
  configuring `fallback_resolvers` opts in to forwarding non-tailnet names upstream.

## [0.5.2](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.2) - 2026-06-04

Tier 2 of the tsnet full-parity roadmap (`docs/PARITY_ROADMAP.md`).

- Added: control `MapRequest` now carries requested tags (`HostInfo.RequestTags`), wired from
  `Config::tags` through the map-request builder on both initial connect and reconnect, so a
  tag-keyed control ACL (e.g. a a self-hosted control plane route auto-approver) can match this node.
- Added: ephemeral registration is now config-driven (`Config::ephemeral`, default `true`)
  instead of hardcoded. A persistent exit node or subnet router can set it to `false` so
  control will not GC it out of the tailnet during a brief disconnect.
- Added: netmap stream resumption on reconnect. The client now tracks the control-issued map
  session handle and per-response sequence number, and offers the last `(handle, seq)` on
  reconnect so control can resume the netmap stream after a drop instead of always restarting
  a full netmap (both resume and full-restart paths are handled safely).
- Added (product capability, beyond strict tsnet parity): upstream **proxy egress** for exit
  nodes. `ProxyExitDialer` (a `RealDialer`) egresses exit-node flows via a SOCKS5
  (RFC 1928/1929) or HTTP `CONNECT` upstream — hand-rolled with zero new dependencies — so a
  cloud exit node can route the traffic it egresses through a residential proxy (a residential proxy provider;
  configured by the deployer) and never expose its own origin IP. It is now fully wired
  through the config chain: `Config::exit_proxy` (`ExitProxyConfig` / `ExitProxyScheme`) →
  `ts_control::Config` (transport-only) → `ForwarderConfig` → the forwarder's dialer selection.
  Strictly opt-in and **fail-closed**: only consulted when `forward_exit_egress` is set, and any
  proxy connect/handshake failure drops the flow rather than dialing direct (UDP fails closed
  with `ProxyUdpUnsupported`, handshake failures with `ProxyHandshake`), so the real origin IP
  never leaks. Without an `exit_proxy`, exit egress uses `HostExitDialer`; with neither, the
  default `DirectDialer` structurally refuses exit egress. See the proxy-egress section of
  `AGENTS.md`.
- Fixed: `HostInfo.App` / `HostInfo.IPNVersion` (the client build string the tailnet admin sees)
  were silently dropped on connect because the map-request builder rebuilt the request without
  them; they are now threaded through via a `client_info` builder setter.
- Hardened: the resumed map-session handle is bounded (≤256 bytes) and sanitized
  (ASCII-graphic) before being stored or logged, and `seq` resets to `0` on a handle change —
  closing a log-injection / unbounded-memory vector on a hostile control response.
- Security: the proxy dialer rejects forbidden exit destinations (loopback / link-local /
  unspecified) via an SSRF guard, and `ProxyConfig`'s `Debug` redacts proxy credentials.

## [0.5.1](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.1) - 2026-06-04

Hardening pass over the Tier 1 direct-path code (review-driven fixes).

- Security: `CallMeMaybe` over DERP is now gated on a netmap-membership check before its
  endpoints are learned; relayed Ping fails closed instead of being honored. The
  `BindingVerifier` signature is now `Fn(&DiscoPublicKey, Option<&NodePublicKey>) -> bool`:
  `Some(claimed)` demands an exact node-key match (Ping), `None` is membership-only
  (CallMeMaybe). An absent verifier fails closed (frame dropped), and the absence is warned
  once.
- Security: disco `Pong` is now rejected when its UDP source address differs from the address
  that was pinged, closing a path-confirmation spoofing vector; the learned reflexive-address
  set is capped (`MAX_REFLEXIVE_ADDRS`).
- Reliability: shared `RwLock`s recover from poisoning instead of cascading a single task
  panic into every other flow (kameo actors still isolate per-flow panics); periodic disco
  intervals use `MissedTickBehavior::Delay`.
- Tests: added coverage for fail-closed Ping with no verifier, membership-gated CallMeMaybe,
  relayed-Ping drop, source-address Pong rejection, and forbidden-endpoint filtering.

## [0.5.0](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.0) - 2026-06-04

Tier 1 of the tsnet full-parity roadmap (`docs/PARITY_ROADMAP.md`).

- Security: enforce the disco↔node-key binding in the netmap-owning layer. Inbound disco
  pings now cross-check `claimed_node_key` against the control netmap and fail closed on
  mismatch or unknown disco key (no pong, no learned path). Resolves the `TODO(parity)`.
- Added: inbound disco-over-DERP demux. DERP-relayed `CallMeMaybe` frames are now decoded
  and their endpoints learned (through the existing `is_pingable_candidate` sanitizer);
  relayed Ping/Pong are dropped and non-disco frames still reach the dataplane.
- Added (CI/build): static musl build lanes (`aarch64`/`x86_64-unknown-linux-musl`) with the
  `ssh`/`aws-lc-rs` feature off, keeping the ring-only egress path musl-clean; a guard fails
  the build if `aws-lc-rs` enters the graph.

## [0.4.0](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.4.0) - 2026-06-03

Initial tailscale-rs parity release (fork of tailscale/tailscale-rs).

- Added (Rust API): Experimental support for user-defined tailnet SSH servers using
  [`russh`](https://docs.rs/russh/latest/russh/) and (optionally)
  [`ratatui`](https://docs.rs/ratatui/latest/ratatui/).
  [#178](https://github.com/tailscale/tailscale-rs/pull/178).
- Hardened the tsnet-parity dataplane (anti-leak, bounds, panic-safety).

## [0.3.3](https://github.com/tailscale/tailscale-rs/releases/tag/v0.3.3) - 2026-05-20

- Fixed: don't generate `tailscale.h` on publish.
  [#196](https://github.com/tailscale/tailscale-rs/pull/196).
- Fixed: Elixir CI/CD publishing infrastructure.
  [#197](https://github.com/tailscale/tailscale-rs/pull/197).

## [0.3.2](https://github.com/tailscale/tailscale-rs/releases/tag/v0.3.2) - 2026-05-20

Partial release; this version is tagged and published to PyPI, but was not published to crates.io or hex.pm.

- Fixed: removed `std` dependency from `ts_netstack_smoltcp_core`.
  [#194](https://github.com/tailscale/tailscale-rs/pull/194).

## [0.3.1](https://github.com/tailscale/tailscale-rs/releases/tag/v0.3.1) - 2026-05-20

Partial release; this version is tagged and published to PyPI, but was not published to crates.io or hex.pm.

- Fixed: Python CI/CD publishing infrastructure.
  [#191](https://github.com/tailscale/tailscale-rs/pull/191).
- Fixed: Rust CI/CD publishing infrastructure.
  [#193](https://github.com/tailscale/tailscale-rs/pull/193).

## [0.3.0](https://github.com/tailscale/tailscale-rs/releases/tag/v0.3.0) - 2026-05-19

Internal release; this version is tagged, but was not published to any package repositories.

- **Breaking** (Rust API): exports `config`, `netstack`, and `keys` modules and moves some functionality
  from the crate root to these modules. Replaces `load_key_file` with `Config::default_with_key_file`.
  Exports a few more types so fewer users will have to depend on internal crates.
  [#105](https://github.com/tailscale/tailscale-rs/pull/105).
- **Breaking** (Rust API, ts_netstack_smoltcp, ts_control): errors have been refactored, some minor
  changes to APIs around errors.
  [#154](https://github.com/tailscale/tailscale-rs/pull/154).
- Added (Rust API): load configuration options from environment variables. Adds `config::auth_key_from_env`
  and `config::Config::default_from_env`.
  [#97](https://github.com/tailscale/tailscale-rs/pull/97).
- Added (Rust API, Python, Elixir): `Device::self_node`.
  [#147](https://github.com/tailscale/tailscale-rs/pull/147).
- Added (Python and Elixir bindings): optional configuration parameters.
  [#140](https://github.com/tailscale/tailscale-rs/pull/140) and [#148](https://github.com/tailscale/tailscale-rs/pull/148).
- Fixed (ts_netstack_smoltcp): big improvement to TCP accept performance.
  [#141](https://github.com/tailscale/tailscale-rs/pull/141).
- Updated MSRV to 1.94.1.
  [#181](https://github.com/tailscale/tailscale-rs/pull/181).

## [0.2.0](https://github.com/tailscale/tailscale-rs/releases/tag/v0.2.0) - 2026-04-15

Initial public release.

## 0.1.0

Hello, world!
