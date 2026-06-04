# Changelog

Record breaking or significant changes here. All dates are UTC.

## Unreleased - June 2026

Put changes for the upcoming release here!

## [0.5.11](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.11) - 2026-06-05

IPv6 **on the tailnet overlay**, gated and default-off. A new runtime flag `Config::enable_ipv6`
(`false` by default — the node stays IPv4-only) opts a node into native IPv6 overlay addressing,
disco candidates, and MagicDNS AAAA. This brings overlay IPv6 to parity with Go `tsnet`'s
`--ipv6`-style posture while keeping the fork's IPv4-only default intact.

**The flag governs only the overlay. It has no effect on the exit-node / forwarder egress path,
which stays hardcoded IPv4 regardless** — the real-origin-IP isolation invariant. This is now
enforced two ways: a public-API guard test (`ts_forwarder/tests/ipv4_only_guard.rs`) asserts every
dialer errors on an IPv6 destination, and a CI grep gate (`ipv4_only_forwarder` in the `checks`
crate, run by `cargo run -p checks`) fails the build if any IPv6 bind/connect/gate token appears in
`ts_forwarder/src/`.

- **Underlay bind** (`ts_runtime::direct`): with the gate on, binds dual-stack `[::]:0` (single
  socket serving native v6 and v4-mapped v4); with the gate off, binds `0.0.0.0:0` as before. The v6
  bind **fails inert** — if the host has IPv6 disabled at the kernel, it warns and falls back to
  IPv4-only rather than failing to come up.
- **Disco candidates** (`ts_magicsock`): with the gate on, IPv6 endpoints that are valid global
  unicast (not loopback / link-local / ULA / multicast / unspecified) become ping candidates; with
  the gate off, all IPv6 candidates are rejected. STUN stays IPv4-only.
- **Netstack addressing** (`ts_runtime::netstack_actor`): with the gate on, the node's IPv6 /128
  overlay address is assigned alongside the IPv4 /32. The `ts_netstack_smoltcp_core` interface
  address capacity was raised (`iface-max-addr-count-5`) so the v4 + v6 + MagicDNS + dual loopback
  address set no longer silently overflows.
- **MagicDNS** (`ts_runtime::magic_dns`): with the gate on, AAAA queries for tailnet names answer the
  peer's overlay IPv6; with the gate off, AAAA returns NODATA (`NOERROR` + empty answer) and tailnet
  AAAA is never forwarded upstream.

## [0.5.10](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.10) - 2026-06-04

Foreign-language binding parity: the C FFI (`ts_ffi`), Python (`ts_python`, PyO3), and Elixir
(`ts_elixir`, Rustler NIF) bindings now expose the same five capability lanes the native `tailscale`
crate already had, bringing each binding to feature parity with Go `tsnet`'s surface. Pure binding
plumbing — no change to the native API or its semantics.

- Lane 1 (Status/WhoIs): `status`, `whois`, and a one-shot `netmap` snapshot in all three bindings.
  Status/StatusNode/WhoIs are marshaled idiomatically (visitor-callback structs in C; `IntoPyObject`
  in Python; `NifStruct` in Elixir). `online` maps to tri-state (1/0/-1, None/bool, `true/false/nil`);
  `allowed_routes` to CIDR strings; `capabilities` to `(name, [values])` pairs.
- Lane 2 (MagicDNS): `resolve(name) -> Option<ipv4>` and `connect_by_name(name, port)` returning the
  binding's existing TCP-stream handle type.
- Lane 3 (Forwarding config): the 8 forwarding fields (`accept_routes`, `exit_node`,
  `advertise_routes`, `advertise_exit_node`, `forward_tcp_ports`, `forward_udp_ports`,
  `forward_all_ports`, `forward_exit_egress`) are accepted from each binding's config constructor and
  threaded into `tailscale::Config`.
- Lane 4 (Ping): `ping(addr, timeout_ms)` returning RTT in milliseconds.
- Lane 5 (TLS/Serve): full `ServeConfig`/`ServeTarget` marshaling plus `get_certificate` and
  `listen_tls`. **Fail-closed (sacred):** issuance is `Unimplemented` in this fork, so both surfaces
  always propagate the native `CertError` (negative return / raised exception / `{:error, reason}`)
  and never self-sign or fabricate success.
- C FFI exposes the new types without a doubled prefix (`status_node` → `ts_status_node` via
  cbindgen); `tailscale.h` is regenerated at build time (gitignored).

## [0.5.9](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.9) - 2026-06-04

Full exit-node DNS proxy (peerAPI DoH) parity with Go `tsnet`. When this node is selected as a
peer's exit node, it now answers that peer's recursive DNS over the overlay; and when this node has
selected an exit node, its own recursive lookups are delegated to that exit node's DoH endpoint
instead of leaking to a local resolver.

- Feat (server): a peerAPI DoH server (`/dns-query`, RFC 8484 over HTTP/1.1 on the encrypted overlay)
  shares the same `decide` path as the local MagicDNS responder, so authoritative MagicDNS records
  (peer names, control-pushed `ExtraRecords`, PTR) are answered identically. Binds the overlay IPv4
  at `Config::peerapi_port`. Supports `POST` (body is the raw DNS message) and
  `GET ?dns=<base64url>`.
- Feat (client): when an exit node is active, the MagicDNS responder delegates catch-all **recursive**
  forwards to the exit node's peerAPI DoH endpoint over the overlay (`forward_doh`). Deliberately
  configured split-DNS routes always stay on their configured upstreams (never delegated). Resolvers
  marked `use_with_exit_node` are kept local, mirroring Go's `UseWithExitNode`.
- Feat (control): `Node::peerapi_doh_url` / `peerapi_doh_addr` expose a peer's DoH endpoint
  (IPv4-only), gated on `peerapi_dns_proxy || cap >= PEER_CAN_PROXY_DNS` (CapabilityVersion 26) and a
  non-WireGuard-only peer. `route_updater` publishes the active exit node so the responder can
  resolve its DoH address once.
- Anti-leak / fail-closed (sacred): server recursion is gated behind `forward_exit_egress` — a node
  that hasn't opted into exit egress answers a recursive query `REFUSED`, never resolving a peer's
  public name through its own host resolver (the cloud host's real IP can't leak). Names in control's
  `ExitNodeFilteredSet` are `REFUSED`. Client delegation is fail-closed: any DoH connect/HTTP/timeout
  failure resolves to NXDOMAIN — **never a silent fallback to a local resolver**. All sockets are on
  the overlay netstack (`0.0.0.0:0`), never a host socket; IPv4-only. Requests and responses are
  size-capped; concurrent in-flight requests are bounded.

## [0.5.8](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.8) - 2026-06-04

`tsnet.Server.RegisterFallbackTCPHandler` parity: an embedder can now register a callback consulted
for every **inbound TCP flow that matches no explicit `Device::tcp_listen` listener**, mirroring Go
`tsnet`'s fallback-handler contract.

- Feat: `Device::register_fallback_tcp_handler(cb)` returns a `#[must_use]` `FallbackTcpHandle` that
  deregisters on drop (mirrors the `unregister func()` Go returns). The callback receives the
  `(src, dst)` `SocketAddr` pair and returns a `FallbackDecision` — `(None, false)` declines (the
  next handler is tried), `(Some(handler), true)` claims the flow, and `(None, true)` claims and
  rejects it. Multiple handlers dispatch in registration order; the first to intercept wins.
- Feat: read-only `BoundPorts` query on the netstack listener registry
  (`CreateSocket::bound_tcp_ports`) so the fallback manager never binds a competing any-IP listener
  on a port the embedder already serves with an explicit `tcp_listen`.
- How it works: a raw `(Ipv4, Tcp)` observer socket suppresses smoltcp's unmatched-SYN RST and
  reveals each SYN's destination port; the manager lazily materializes a per-port any-IP listener
  and dispatches accepted flows to the registered handlers. The observer runs **only while at least
  one handler is registered** — started on the first registration, torn down on the last
  deregistration — so the netstack's default **fail-closed RST** behavior stays pristine when no
  handler is installed.
- Anti-leak / DoS bounds: flows no handler claims are **closed (fail-closed), never direct-dialed**;
  the observer never creates a host socket. Per-port listeners are capped (`MAX_PORTS = 1024`),
  idle-reaped (120 s), and per-port in-flight flows are bounded (`MAX_INFLIGHT = 512`). IPv4-only.

## [0.5.7](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.7) - 2026-06-04

Documentation correction (no code change): the TLS-certificate seam (`ts_control::cert`) described
a control protocol that **does not exist** in real Tailscale, which would have led a future
implementer to build the wrong thing.

- Docs: corrected `ts_control/src/cert.rs` (and the matching `serve.rs` / `src/lib.rs` doc
  references) to describe the **actual** tsnet certificate protocol. There is **no**
  `POST /machine/<machineKey>/cert/<domain>` "ACME-over-control" endpoint — the node itself is the
  ACME client and talks **directly to Let's Encrypt**; control's only role is to publish the
  **DNS-01** challenge TXT (`_acme-challenge.<name>`) via `POST /machine/set-dns` over the Noise
  (ts2021) channel, with `NodeKey` carried in the request body (`SetDNSRequest`) and an empty
  `SetDNSResponse{}` on 200. (DNS-01 is for `*.ts.net`; TLS-ALPN-01 is for Funnel/BYO; HTTP-01 is
  unused.) Updated `MISSING_CERT_RPC` and the `CertError::Unimplemented` detail to name the real
  missing pieces: a client-side ACME engine plus a `set-dns` Noise RPC.
- Docs: recorded the **deployment caveat** explaining why issuance stays a fail-closed stub rather
  than being built now — the fork's control target is **a self-hosted control plane**, which returns **HTTP 501
  NotImplemented** for `/machine/set-dns`, so a client-side ACME engine could not complete a DNS-01
  challenge against a self-hosted control plane regardless. The fail-closed contract is unchanged:
  `get_certificate` / `listen_tls` still return `CertError::Unimplemented` after the tailnet-name
  check, never self-signing and never downgrading to plaintext.

## [0.5.6](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.6) - 2026-06-04

Documentation hygiene (no code change): the README's "Unsupported" list contradicted its own
"Implemented" section and the actual code.

- Docs: removed **Split DNS** and **upstream/recursive DNS forwarding** from the README's
  "Unsupported features" list — both are implemented and wired end-to-end (`ts_control::dns`
  longest-suffix `routes` + `fallback_resolvers`/`resolvers` recursive forwarding, decided in
  `ts_runtime::magic_dns`). The stale entry claimed "non-tailnet queries are not forwarded ...
  fail-closed by design", directly contradicting the "Implemented" MagicDNS entry, which correctly
  states that configuring `fallback_resolvers` opts in to forwarding. Added an explicit Split-DNS
  bullet to the "Implemented" list (longest-suffix route match; empty route list = negative route =
  NXDOMAIN; recursive forwarding applies only when no route matches). Fail-closed remains the
  default (NXDOMAIN, never forwarded) when no route and no resolver is configured.

## [0.5.5](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.5) - 2026-06-04

Review-driven test hardening of the v0.5.4 STUN cleanup (no behavior change; tests and one
signature/doc tidy).

- Tests: close the two coverage gaps a review found in the active-STUN receive path. A
  matched-transaction-id Binding Success whose body is hostile — wrong message type, wrong magic
  cookie, or a lying XOR-MAPPED-ADDRESS attribute length — is now asserted to be consumed (we did
  send that txid) yet learn no reflexive address, pinning that a matched-but-malformed frame can
  never inject a forged endpoint. A second test pins the v0.5.4 contract that the 96-bit
  transaction id is the *sole* anti-spoof match: a valid Binding Success for an in-flight txid is
  accepted even when its UDP source differs from the probed server (legitimate under NAT/hairpin),
  proving the server address is deliberately neither stored nor matched.
- Cleanup: `probe_stun_servers_once` now takes `&MagicSock` instead of `&Arc<MagicSock>` (the Arc
  was never cloned), and a redundant opening clause in the `tcp_buffer_size` memory-at-scale doc
  was tightened.

## [0.5.4](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.4) - 2026-06-04

Review-driven hardening of the v0.5.3 active-STUN + `tcp_buffer_size` work (no behavior change to
the shipped feature; tests, docs, and an internal cleanup).

- Cleanup: the STUN in-flight map (`MagicSock`) no longer stores the per-request server address —
  it was never read for response matching, and storing it falsely implied source-address pinning.
  The 96-bit transaction id is and remains the sole anti-spoof match (a STUN reply may legitimately
  arrive from a different source under NAT/hairpin); the map is now keyed `txid → sent-Instant` for
  TTL pruning only, and the field/TTL docs are corrected to say so.
- Tests: added coverage for the previously-untested seams — the `stun_servers_v4` anti-DNS-leak
  filter (FixedAddr-v4-with-port kept; `UseDns`/`Disable`/no-`stun_port` skipped), the per-tick STUN
  prober fan-out (emits a well-formed 20-byte Binding Request to a v4 server; empty server list is a
  no-op falling back to pong-harvest), and the `tcp_buffer_size` runtime seam (`None` ⇒ netstack
  default, `Some(n)` ⇒ override reaching both netstacks). Consolidated the duplicate STUN wire-format
  test encoders into one canonical `crate::stun::test_support` helper.
- Docs: documented the `tcp_buffer_size` memory cost at scale — buffers are allocated eagerly per
  socket (~512 KiB/socket at the 256 KiB default), so ~1,000 concurrent forwarded flows pin ~512 MB,
  a real fraction of a 4 GB exit node. Operators forwarding many concurrent flows on small boxes
  should lower the knob (see the new exit-node section of `AGENTS.md` and the
  `ts_netstack_smoltcp_core` config doc). The `stun_servers_from_regions` helper carries a loud
  "do not loosen to `UseDns`" anti-leak note.

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
