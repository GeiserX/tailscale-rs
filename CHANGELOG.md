# Changelog

Record breaking or significant changes here. All dates are UTC.

## Unreleased - June 2026

Put changes for the upcoming release here!

## [0.5.21](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.21) - 2026-06-05

Hardening from a multi-reviewer audit of the v0.5.15–v0.5.20 parity features. No behavior change to
the happy paths; tightens fail-closed posture, removes DoS levers, and adds coverage.

- **TKA: bound recursion on untrusted input** (`ts_tka`). A peer-supplied `NodeKeySignature` CBOR
  blob is now depth-capped (`MAX_SIG_NESTING_DEPTH = 16`) at **decode** time — both the
  signature-chain walk and generic CBOR container nesting — so a deeply-nested blob can no longer
  overflow the stack (DoS). The CBOR decoder also now rejects duplicate map keys (CTAP2/Go parity).
- **TKA: bind nested-credential pubkey** (`ts_tka`). A `SigKind::Credential` reached via a rotation
  wrap must now have its `pubkey` equal the rotation pivot, closing a latent soundness gap vs Go.
- **TKA tests**: added the previously-missing rotation-chain end-to-end test, the nested-credential
  bind test, and the depth-cap rejection test; documented the ZIP-215-vs-standard verifier split in
  `Cargo.toml`. Removed dead `text_string_map`/`Value::TextMap` encoder surface.
- **Taildrop: move blocking fsync off the async runtime** (`ts_runtime::taildrop`). The terminal
  `flush`+`sync_all`+atomic `rename` now run in `tokio::task::spawn_blocking`, so up to 512
  concurrent transfers no longer starve the tokio worker pool. Fail-closed preserved (a finalize
  failure leaves the partial in place, never publishes).
- **peerAPI/Taildrop tests**: added request→response coverage driving the production `BodyReader` +
  `put_file` over real async streams (200/403/400/405, the DoH-route regression guard, and the
  Content-Length cap), plus the previously-untested offset-resume path.
- **Device error fidelity**: `taildrop_*` errors now map to distinct `InternalErrorKind`
  (`BadRequest` / `AlreadyExists` / `NotFound` / `Io`) instead of collapsing every failure into the
  generic `Actor` kind, so callers can act on the actual cause.

## [0.5.20](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.20) - 2026-06-05

**Tailnet Lock (TKA) verification** (`tsr-77q-c`): the client-side signature-chain verification path
of Tailscale's Tailnet Lock, mirroring Go's `tka` package. Fail-closed.

- **`ts_tka` crate**: a dependency-light reimplementation of the TKA verification primitives —
  a CTAP2-canonical CBOR encoder (so a value's signing digest is byte-identical to Go's
  `fxamacker/cbor` CTAP2 output), `AumHash` (BLAKE2s-256 + RFC4648 base32-nopad, the type
  `TkaInfo.head` carries), the `Aum`/`Key`/`NodeKeySignature` wire vocabulary, and an `Authority`
  exposing `node_key_authorized` — the check that a peer's node key is signed by a key trusted under
  the current tailnet-lock state. Signature verification uses ZIP-215 (cofactored) Ed25519 for
  direct/credential signatures (matching Go `ed25519consensus`) and standard Ed25519 for the
  rotation wrap.
- **Netmap threading**: control's `TKAInfo` (head + disablement) is parsed into a domain `TkaStatus`,
  threaded `MapResponse` → `StateUpdate` → `ControlRunner`, and exposed via `Device::tka_status()`.
  The `tailscale::tka` module re-exports the verification engine for embedders.
- **Fail-closed**: any decode/shape/signature failure denies authorization; a credential-only
  signature can never authorize a node; an untrusted authorizing key denies.

**Validation caveat:** the CTAP2-CBOR byte-exactness is asserted by construction and exercised by an
end-to-end Ed25519 sign→verify roundtrip, but has **not** been cross-validated against Go-produced
TKA test vectors. A *failed* verification is always safe to act on (deny); treat a *successful* one
as advisory until vectors land. The node's own NL-key signing (admin side) is out of scope — the
fork's `NetworkLockPublicKey` is modelled as X25519 while Go TKA keys are Ed25519; only client-side
verification (against peers' Ed25519 keys in the authority state) is implemented here.

## [0.5.19](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.19) - 2026-06-05

**Client metrics / observability** (`tsr-77q-b`): a `clientmetric`-style in-process metric registry
plus a `Device::metrics()` Prometheus-text export. (Go `tsnet` exposes no metrics method of its own,
so this is the fork's clean public surface.)

- **`ts_metrics` crate**: a small, dependency-free reimplementation of Go's `util/clientmetric` — a
  process-global registry of named counters/gauges (`Metric::new_counter` / `new_gauge`, `add` /
  `inc` / `set`, single relaxed-atomic increments on hot paths) with a `write_prometheus` exporter
  emitting `# TYPE <name> <kind>\n<name> <value>\n` per metric, name-sorted. Metric names are
  validated to `[A-Za-z0-9_]` (Go `isIllegalMetricRune`).
- **magicsock counters**: the direct-UDP datapath now increments canonical `magicsock_*` counters
  (`magicsock_send_udp`, `magicsock_send_udp_bytes`, `magicsock_send_udp_error`,
  `magicsock_recv_data_udp`, `magicsock_recv_data_bytes_udp`), matching the Go naming convention.
- **`Device::metrics() -> String`** returns the full Prometheus text exposition for the embedder to
  scrape or forward.

## [0.5.18](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.18) - 2026-06-05

**Taildrop file transfer (receive side)** (`tsr-77q-a`): this node can now receive files from
tailnet peers over the peerAPI, mirroring Go Tailscale's Taildrop. Fail-closed and IPv4-only.

- **Path-safe file store** (`ts_runtime::taildrop`): a `TaildropStore` that writes each incoming
  transfer to a `<name>.partial` file and **atomically renames** it to the final name on success
  (non-clobbering ` (n)` suffix on conflict, Go `nextFilename`). `validate_base_name` is the
  security boundary — it rejects path separators, `..`, NUL/control chars, and the reserved
  `.partial`/`.deleted` suffixes before any path is constructed, so a malicious file name can never
  escape the store directory. Supports offset-resume.
- **peerAPI route + router** (`ts_runtime::peerapi`): the peerAPI listener is now a single
  path-routing server (mirroring Go's one-server-many-routes model). `PUT /v0/put/<name>` lands a
  Taildrop file (`200 OK` + `{}\n`; `400` invalid name, `409` in-progress conflict, `405` wrong
  method); `/dns-query` continues to the existing exit-node DoH handler byte-for-byte.
- **Fail-closed access gate**: a `PUT` is accepted only when a Taildrop directory is configured
  (`Config::taildrop_dir`, default `None` = disabled) **and** this node holds the
  `https://tailscale.com/cap/file-sharing` node capability **and** the source IP resolves to a known
  tailnet node. (The per-peer `file-send` peer-capability check is deferred until the packet-filter
  peer-cap map is threaded into the runtime node model — documented in `peerapi.rs`; the surface
  stays fail-closed without it.)
- **Embedder API** (`Device`): `taildrop_waiting_files()`, `taildrop_open_file(name)`, and
  `taildrop_delete_file(name)` let the host application consume received files. `WaitingFile` is
  re-exported from the crate root.

The sender side (`tailscale file cp` / push) and the LocalAPI long-poll are out of scope for this
slice; this is the receive half a peer pushes to.

## [0.5.17](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.17) - 2026-06-05

**Tailscale VIP services / `ListenService`** (`tsr-6b5`): a node can now host a Tailscale **VIP
service** (`svc:<label>`) by binding an overlay listener on the virtual IP address control assigned
that service, mirroring Go `tsnet.Server.ListenService`. Fail-closed throughout.

- **Wire types** (`ts_control_serde`): `ServiceName` (`svc:<label>`), `VipService`,
  `ProtoPortRange`, and `ServiceIpMappings` (the value of the `service-host` node-capability —
  `NODE_ATTR_SERVICE_HOST`), mirroring `tailcfg`. These are the control-assigned service→VIP
  mappings a host learns from its netmap.
- **Domain model** (`ts_control::Node`): a new `service_vips` map (svc-name → VIP IPs) parsed from
  the `service-host` cap, with `service_addresses()` (flattened set) / `service_addresses_for(name)`
  (per-service) accessors and an `is_service_host()` gate. A `validate_service_name` enforces the
  `svc:<dns-label>` shape.
- **Listen gate** (`ts_control::resolve_service_listen` + `Device::listen_service`): binds a
  listener on the service's control-assigned VIP only when the name is valid, the host is **tagged**
  (Go `ErrUntaggedServiceHost`), and control assigned that specific service a VIP — otherwise a
  typed `ServiceError` and the node serves nothing (never a host socket, never an unbound listen).
  Per-service VIP selection ensures a multi-service co-host binds the correct address for each
  service.
- **Netstack acceptance**: control-assigned VIPs are added to the application netstack's
  accepted-address set (the same mechanism as the MagicDNS `100.100.100.100` service IP) so a
  hosted-service listener is reachable by tailnet peers. IPv6 VIPs are dropped when IPv6 is disabled
  on the overlay (the default), consistently in both the accept-set and the listen resolver — the
  fork stays IPv4-only by default.

The advertise→`c2n`-fetch leg (`Hostinfo.ServicesHash` + control's `GET /vip-services`) and the
L3/`Tun` service mode (a TODO in upstream tsnet) are out of scope for this slice; VIP hosting works
from the control-assigned `service-host` mapping a node already receives.

## [0.5.16](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.16) - 2026-06-05

**Tailscale SSH server authorization** (`tsr-l24`): the in-process SSH server now enforces the
control-pushed `SSHPolicy`, brought to Go `tailssh` parity and made **fail-closed**. Previously the
SSH `ChannelServer` accepted *any* known tailnet peer with no policy evaluation; that gap is closed.

- **Wire types** (`ts_control_serde`): `SSHPolicy` / `SSHRule` / `SSHPrincipal` / `SSHAction` /
  `SSHRecorderFailureAction`, mirroring `tailcfg` field-for-field (verbatim lowerCamel JSON tags:
  `ruleExpires`, `sshUsers`, `nodeIP`, `userLogin`, `sessionDuration` (nanoseconds), `notifyURL`,
  …). `MapResponse.SSHPolicy` is now deserialized off the netmap.
- **Policy evaluator** (`ts_control::SshPolicy`): an owned domain model + `evaluate` that reproduces
  Go `evalSSHPolicy` / `matchRule` / `mapLocalUser` — **first-match-wins, default-deny**, with the
  exact `SSHUsers` map semantics (`"*"` wildcard key, `"="` identity map, empty-string value =
  rule does not apply). Principal matching by stable node id / node IP / `any`. Rule-expiry is
  honored and **fails closed**: an unreadable host clock makes time-limited rules look expired
  (deny) rather than perpetually live.
- **Server enforcement** (`Device::authorize_ssh`, `ssh` feature): resolves the connection's source
  IP to a known tailnet peer (unknown ⇒ deny), fetches the current policy (**absent ⇒ deny-all**),
  and evaluates it; `auth_none` rejects on any deny *or* any lookup error. The policy is threaded
  netmap → `StateUpdate` → `ControlRunner` (watch channel) → `Device`.
- **musl-clean isolation guard** (`checks::ssh_isolation`): a new build-gate asserting the `ssh`
  feature (which pulls `russh` → `aws-lc-rs`) stays OFF by default, `dep:russh`-gated, and that
  `aws-lc-rs` is never a direct dependency — so the core tailnet/egress path remains `ring`-only and
  cross-compiles cleanly to musl. The SSH server is meant to run isolated in a separate non-musl
  binary.

Advanced SSH features (session recording / `OnRecordingFailure`, the interactive `holdAndDelegate`
control round-trip) are intentionally out of scope for this basic `ListenSSH` parity slice.

## [0.5.15](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.15) - 2026-06-05

**`ListenFunnel`** (`tsr-jir`): the Tailscale Funnel public-ingress entry point, brought to the same
fail-closed posture as `ListenTLS`. `Device::listen_funnel` validates that the self node may funnel
before doing anything, then attempts to terminate TLS on the overlay netstack — never on a host
socket, never with a self-signed cert, never with a plaintext downgrade.

- **Capability gating mirrors Go `tsnet` exactly** (`ts_control::Node`): `NodeCanFunnel` requires
  BOTH `CapabilityHTTPS` (`"https"`) AND `NodeAttrFunnel` (`"funnel"`) in the node's CapMap, and
  `CheckFunnelPort` reads the allowed ports from the `funnel-ports` cap **key's** `?ports=` query —
  comma-separated single ports (string equality) plus `first-last` inclusive `uint16` ranges. An
  empty / unparseable / missing / wrong-URL ports query denies. The node carries an owned
  `NodeCapMap` populated from the netmap.
- **`FunnelError`** (`NotAllowed` / `PortNotAllowed` / `Cert` / `Unsupported`) and
  `FunnelOptions { funnel_only }` in `ts_control::serve`. `listen_funnel` runs the access check →
  `cert::get_certificate` (which is itself `Unimplemented` in this fork) → and, since a self-hosted
  control plane provides no Tailscale-operated public ingress relay, surfaces
  `FunnelError::Unsupported` rather than bringing a non-functional listener up. Fail-closed.
- **capver-113 ingress signalling**: a new default-`false` `wire_ingress` config knob threads
  through `tailscale::Config` → `ts_control::Config` → the registration and streaming map-request
  `HostInfo`. When set, it advertises `HostInfo.WireIngress` ("would like to be wired up for
  Funnel") to control. `HostInfo.IngressEnabled` is intentionally left `false` — no Funnel endpoint
  ever goes live in this fork, mirroring how Go suppresses `WireIngress` only once ingress is
  actually enabled.
- **`funnel_fail_closed` leak-firewall** (`checks` crate): a new build-gate that scans the
  production (non-test) portion of both `ts_control/src/serve.rs` and `ts_control/src/cert.rs` for
  self-signed cert-minting tokens (`rcgen` / `generate_simple_self_signed` / `self_signed`), so a
  self-signed fallback can never silently regress into the public-TLS termination path. The
  `#[cfg(test)]` cutoff is matched only at column 0 and the file must contain exactly one such
  boundary, closing an evasion vector.

## [0.5.14](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.14) - 2026-06-05

**TUN-mode host integration** (`tsr-248.1`): a new `ts_host_net` crate programs the host routing
table and system resolver so a TUN-mode node's traffic is actually steered into the kernel TUN
interface. Without it the TUN device exists but the OS has no FIB entries pointing tailnet / subnet
/ exit prefixes at it. This is the host-side analogue of `ts_forwarder`'s `RealDialer` anti-leak
chokepoint, and is **off the default (netstack) path** — it only runs in TUN transport mode.

- **`ts_host_net` crate**: a `HostNet` trait (`apply_routes` / `apply_dns` / `teardown`) with
  per-OS implementations — macOS (`route(8)` + `scutil(8)`), Linux (`ip(8)` + `resolvectl(1)`),
  and a typed `Unsupported` error on every other platform (never a silent no-op). Zero new heavy
  dependencies (`ipnet` / `thiserror` / `tracing` only), keeping the musl-clean posture intact.
- **IPv4-only by construction**: `HostRoutes` / `HostDns` carry only `Ipv4Net` / `Ipv4Addr`, so a
  v6 route can never be emitted. A new `ipv4_only_host_net` `checks`-crate grep gate enforces it.
- **Fail-closed**: a partial `apply_*` rolls back its own state before returning `Err`; `teardown`
  reverses exactly what was installed. The TUN actor never pumps packets on an unrouted interface
  and never silently falls back to the netstack.
- **`/0` split-default**: a literal `0.0.0.0/0` exit route is expanded to the reversible
  `0.0.0.0/1` + `128.0.0.0/1` pair (longest-prefix-match wins without clobbering the host default;
  avoids `EEXIST` from `route add default` on macOS). Shared between both platform impls so they
  cannot drift.
- **Host-route gating**: subnet routes are steered into the TUN only when `--accept-routes` is set,
  and the host `/0` only when an exit node is configured (`HostRouteGating`).
- **Anti-injection input guards**: control-supplied DNS match-domains and the (embedder-influenced)
  TUN interface name are validated as strict DNS / interface names before reaching a privileged
  argv or `scutil` stdin script — a domain containing a newline can no longer inject a `scutil`
  verb. DNS programming is inert this slice (empty nameservers ⇒ no-op) until a TUN-mode MagicDNS
  responder exists; pointing the resolver at a dead `100.100.100.100` would black-hole.

## [0.5.13](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.13) - 2026-06-05

Cleanup of two known compromises from the v0.5.12 TUN-mode work; no behavior change to the data or
egress paths.

- **Dedicated error variant** (root `tailscale`): added `InternalErrorKind::UnsupportedInTunMode`.
  Netstack-only `Device` APIs (and the internal `channel()` accessor) now surface this in TUN mode
  instead of overloading the generic `InternalErrorKind::Actor` "internal component unavailable"
  sentinel, so callers can distinguish "wrong transport mode" from a genuine actor failure. The
  `ts_runtime` `UnsupportedInTunMode` / `TunUnavailable` kinds map to it.
- **`ts_transport_tun` serde feature fixed**: the `serde` feature now also enables `ipnet/serde`, so
  the `Config` struct (which holds an `ipnet::IpNet`) actually derives working
  `Serialize`/`Deserialize`. Added a gated `config_serde_round_trip` test.

## [0.5.12](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.12) - 2026-06-05

**TUN-mode transport**, gated behind a new default-off `tun` Cargo feature. A node can now run its
application data path over a real kernel TUN interface (`utun` on macOS, `/dev/net/tun` on Linux)
instead of the userspace smoltcp netstack, selected via a new `Config::transport_mode`
(`TransportMode::Netstack` — the default — or `TransportMode::Tun(TunConfig { name, mtu })`). This
brings the fork toward Go `tsnet`'s TUN/`Up`-style data path while leaving the default userspace
posture byte-for-byte unchanged.

**The forwarder / exit-node egress path is UNCHANGED and stays hardcoded IPv4 in both modes** —
TUN mode swaps only the *application* data path, never the forwarder. The real-origin-IP isolation
invariant and its `checks`-crate grep gate are untouched.

- **Feature gate** (`ts_runtime`, root `tailscale`): the `tun` feature is **off by default**. With
  it off, no TUN code compiles and the default dependency graph is unchanged (`ts_transport_tun`
  does not enter it). `tun-rs` is off the `ring`-only egress path, so the musl-clean egress
  invariant holds.
- **Transport selection** (`ts_runtime::Runtime::spawn`): branches on `Config::transport_mode`.
  Netstack mode spawns the application netstack + MagicDNS responder + fallback-TCP registry as
  before; TUN mode spawns a `TunActor` on the same overlay seam instead. **Fail-closed, no silent
  fallback:** requesting `Tun` in a build without the `tun` feature is a hard error
  (`ErrorKind::TunUnavailable`), never a silent downgrade to netstack.
- **`TunActor`** (`ts_runtime::tun_actor`): creates the device lazily on the first netmap update
  (the tailnet `/32` prefix is assigned by control at runtime), then runs a two-task pump moving
  packets between the kernel interface and the dataplane. Device-creation failure (e.g. missing
  root / `CAP_NET_ADMIN`) logs a single error and leaves the actor idle — **no packets flow, no
  leak** — rather than falling back.
- **Crate hardening** (`ts_transport_tun`): `AsyncTunTransport::new` now maps a
  `PermissionDenied` device-open to the typed `Error::RootUserRequired` (previously a dead
  variant), dead code removed.
- **In TUN mode there is no application netstack**: netstack-only `Device` APIs (`udp_bind`,
  `tcp_listen`, `tcp_connect`, `register_fallback_tcp_handler`, …) return an error
  (`ErrorKind::UnsupportedInTunMode`); control-plane and peer-lookup APIs are unaffected.
  `register_fallback_tcp_handler` is now fallible (returns `Result`) to reflect this.

Note: true Go-`tsnet` TUN parity also requires host **route and DNS programming** (Go's
`router`/`dns` engines) so the OS actually sends overlay traffic to the interface; that is tracked
as a follow-up and is out of scope for this data-path seam.

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
