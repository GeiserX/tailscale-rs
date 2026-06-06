# Changelog

Record breaking or significant changes here. All dates are UTC.

## Unreleased - June 2026

Put changes for the upcoming release here!

## [0.5.50](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.50) - 2026-06-06

**Give the `hosted_test` lane enough disk to build.** With both clippy steps green, the
`ubuntu-latest` runner died with `ENOSPC` during `cargo build --all-targets`: this ~45-crate
workspace's clippy + build + test artifacts overflow the hosted runner's ~14 GB free disk. Added
a `Free disk space` step that removes the unused preinstalled SDKs (dotnet, Android, GHC, CodeQL,
boost, the agent toolcache) and prunes Docker images — hand-rolled, no third-party action, to
keep the OSS supply chain minimal — and set `CARGO_INCREMENTAL=0` to roughly halve `target/`.

## [0.5.49](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.49) - 2026-06-06

**Fix a Linux-only clippy lint the new `hosted_test` lane exposed.** `ts_host_net/src/linux.rs`
is `#[cfg(target_os = "linux")]`, so it never compiled under local macOS clippy — the
`ubuntu-latest` lane is the first thing to lint it. Collapsed a nested `if let Some(..) { if let
Err(..) }` into a single let-chain to satisfy `clippy::collapsible_if`. Verified the only two
crates carrying Linux-gated code (`ts_host_net`, `ts_netstack_smoltcp`) are clippy-clean for the
`aarch64-unknown-linux-musl` target.

## [0.5.48](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.48) - 2026-06-06

**Fix the `hosted_test` lane added in 0.5.47.** The shared `setup-rust` composite action bakes
the `components` input into an `actions/cache` key, and cache keys reject commas — so passing
`components: clippy,rustfmt` failed key validation in the `Setup rust` step before any
verification ran. Pass `components: ""` (as `musl_static` does) and install clippy + rustfmt in a
dedicated `rustup component add` step after the toolchain override is set.

## [0.5.47](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.47) - 2026-06-06

**CI now has a real green signal.** The inherited upstream workflow matrix targets self-hosted
runner labels (`linux-x86_64-16cpu`, `linux-arm64-16cpu`, `macos-26`, …) that do not exist on
this fork, so every `rust`-workflow job queued forever and never reported. Added a `hosted_test`
job that runs on GitHub-hosted `ubuntu-latest` and executes the same core verification (fmt,
clippy `-D warnings` for lib + other targets, `build --all-targets`, `test`, and the `checks`
anti-leak firewall) with default features (ring-only; no `ssh`/`acme`/`tun`). This is the only
lane in the `rust` workflow that actually executes; `musl_static` already covered the musl path.

Fixed three latent clippy lints that only surface under the full `--workspace --bins --tests`
pass the new lane runs (per-crate checks had missed them): a doc-list overindent in
`checks/src/ipv4_only_host_net.rs`, a `field_reassign_with_default` in a `ts_keys` test, and two
`let-underscore-drop`s in a `ts_host_net` test (now bound and asserted on).

## [0.5.46](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.46) - 2026-06-06

**Client-side Funnel ingress** (roadmap `tsr-am9.11`): `Device::listen_funnel` now returns a
**working** ingress listener — the final tsnet-parity item. Investigation corrected the model:
Funnel ingress is **not** a DERP-layer feature. Tailscale's ingress relay is a tailnet *peer* that
**POSTs to the node's peerAPI `/v0/ingress`** and the node HTTP-hijacks the connection — so the
node side is a peerAPI route, fully buildable. (The public DNS + the relay itself remain
Tailscale-operated infrastructure: this works against real Tailscale SaaS with a Funnel-enabled ACL;
a self-hosted a self-hosted control plane provides no relay, documented in `MISSING_FUNNEL_RELAY`.)

- New peerAPI `POST /v0/ingress` route (`ts_runtime::peerapi`): fail-closed netmap-membership gate
  (a non-member ingress POST is rejected `403`; the stricter relay-specific cap is a documented
  follow-up, same posture as Taildrop), parses `Tailscale-Ingress-Target`/`-Src`, replies
  `HTTP/1.1 101 Switching Protocols` to hijack the connection into a raw bidi stream, and hands it
  to the funnel manager. No active funnel listener ⇒ `404` (never hijack what won't be served).
- New `FunnelManager` (`ts_runtime::funnel`, mirrors the Serve runtime): TLS-terminates each hijacked
  stream with the node's `*.ts.net` cert (the ACME-issued DNS-01 cert matches the Funnel hostname —
  no TLS-ALPN-01 needed) and yields `FunnelAccepted { target, src, stream }` over a
  `FunnelAcceptedReceiver`.
- **API change**: `Device::listen_funnel` now returns `FunnelAcceptedReceiver` (was `TlsAcceptor`) —
  the working hand-back shape. The `funnel_access` (NodeCanFunnel + CheckFunnelPort) and cert gates
  stay fail-closed. While a funnel listener is active the node advertises `HostInfo.IngressEnabled`
  (new `MapRequestBuilder::ingress_enabled`) so control routes Funnel traffic to it.
- **Anti-leak**: ingress arrives on the overlay peerAPI listener and is TLS-terminated on the
  overlay — never a host socket, never routed through `ts_forwarder`; no plaintext/self-signed
  fallback. The Python/Elixir `listen_funnel` bindings were updated for the new return type.

## [0.5.45](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.45) - 2026-06-06

**VIP-service advertise side** (roadmap `tsr-am9.9`): a node can now tell control it hosts a
`svc:<name>` VIP service, completing Tailscale Services (the consume side — binding a control-assigned
VIP — already shipped). Mirrors Go's `Hostinfo.ServicesHash` + c2n `GET /vip-services` mechanism (not
an inline `Hostinfo.Services` entry — that struct can't carry a `svc:` name).

- New `Config::advertise_services: Vec<String>` (the `svc:<dns-label>` names this node hosts;
  validated with `validate_service_name`, invalid names dropped fail-closed). Threaded root →
  `ts_control::Config` like `requested_tags`.
- `ts_control::services_hash(...)` computes Go's `vipServiceHash`: the sorted `VIPService` list
  serialized to canonical JSON, SHA-256'd (via **ring** — the same provider the rest of the TLS
  stack uses, now an unconditional `ts_control` dep; **no aws-lc-rs / openssl**, confirmed absent
  from the default *and* `acme` graphs), hex-encoded; `""` when empty. It's set as
  `Hostinfo.ServicesHash` on both the register and every map request via a new
  `MapRequestBuilder::services_hash` setter.
- The existing inbound c2n dispatcher (`ping.rs`, previously only `/echo`) gains a `GET /vip-services`
  arm returning `C2NVIPServicesResponse { VIPServices, ServicesHash }` (new serde types;
  `VipService`/`ProtoPortRange`/`ServiceName` gained `Serialize`). Control fetches the full list on a
  hash change, validates the node may host it (ACL), and returns the VIP via the existing
  `service-host` capability the consume side already reads.
- Empty `advertise_services` ⇒ hash `""` ⇒ the wire field is omitted ⇒ behavior unchanged. The
  consume side (`service.rs` / `node.rs`) is untouched.

## [0.5.44](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.44) - 2026-06-06

**TUN-mode MagicDNS** (roadmap `tsr-am9.7`): TUN-transport nodes now get MagicDNS, closing the gap
where their host DNS was inert (`nameservers: vec![]`). Mirrors Go's model — an in-process packet
intercept, not a host socket.

- The TUN packet pump now intercepts outbound UDP queries to `100.100.100.100:53`, answers them
  in-process via the **same** `decide()` MagicDNS responder the netstack path uses (no second
  resolver), and writes the reply back into the TUN (parsed/rebuilt with `etherparse`, checksums
  recomputed). Non-matching packets pass through to the overlay unchanged.
- `host_dns_from_dns_config` now programs the host resolver with `nameservers = [100.100.100.100]`
  (when MagicDNS is enabled) via `ts_host_net::apply_dns` (macOS `scutil` / Linux `resolvectl`), and
  `host_routes_from_node` adds the `100.100.100.100/32` route so the host's queries actually enter
  the TUN. The `TunActor` builds its own `DnsView` from the control state (peers + DNS config),
  mirroring the netstack `MagicDnsActor`.
- **Fail-safe**: a `Decision::Forward` (recursive / exit-node DNS) answers NXDOMAIN in TUN mode — a
  tailnet name is answered authoritatively, a public name gets NXDOMAIN rather than hanging or
  leaking to a host resolver. Recursive/exit-node DoH forwarding in TUN mode is a documented
  follow-up (it needs an overlay `Channel` threaded into the TUN actor). The netstack-mode MagicDNS
  path is byte-identical. New `etherparse` dep is gated to the off-by-default `tun` feature.

## [0.5.43](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.43) - 2026-06-06

**Docs: correct the symmetric-NAT caveat** (`tsr-am9.10`). The crate-root README claimed
"symmetric-NAT birthday-paradox hole-punching is not yet implemented." Investigation against
`tailscale/tailscale` @ main **and** v1.30.0 found that **upstream Go has no 256-port spray** — the
"birthday-paradox spray" is a common misconception. Go's actual hard/symmetric-NAT tactic is a
**single `EndpointSTUN4LocalPort` candidate** (the reflexive IPv4 paired with the node's fixed local
port, gated on `MappingVariesByDestIP && port != 0`), which this fork already emits in
`self_endpoints` and advertises in every `CallMeMaybe`. So symmetric-NAT handling is at **parity with
Go**; the README is corrected to say so. Building an actual 256-port spray was rejected: it would
diverge from Go, be an SSRF-style host-sourced-UDP-spray (which `ts_magicsock` explicitly guards
against), and leak unbounded in-flight ping state. No behavior change.

## [0.5.42](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.42) - 2026-06-06

**Stored Serve config + accept-loop runtime** (roadmap `tsr-am9.8`): `Device::set_serve_config` /
`get_serve_config`, completing Go `tsnet`'s `Get/SetServeConfig` + serving runtime. Now that ACME
issuance landed (v0.5.38–39), serve ports terminate TLS with a real Let's Encrypt cert.

- New `ServeState { name, ports: BTreeMap<u16, ServeTarget> }` (multi-port, mirroring upstream
  `ipn.ServeConfig`'s per-port `TCP` map). `ServeTarget` gains, alongside `Accept`/`Proxy{to}`:
  `Text{body}` (Go `HTTPHandler.Text`) and `TcpForward{to}` (Go `TCPPortHandler.TCPForward`, raw
  passthrough, no TLS); the enum is now `#[non_exhaustive]`.
- `Device::set_serve_config(state)` validates, builds each TLS-terminating port's `TlsAcceptor`
  up-front via the ACME cert path (any cert failure fails the whole call **closed** — no port is
  bound, no plaintext downgrade), then binds one overlay accept loop per port and reconciles on
  re-set (full-replace, Go semantics). It returns a `ServeAcceptedReceiver` — the in-process Rust
  stand-in for `ListenTLS`'s `net.Listener` — over which `Accept`-target streams arrive.
- Per-connection dispatch: `Accept` → TLS-terminated stream handed to the receiver; `Proxy{to}` →
  TLS-terminate then `copy_bidirectional` to a local host backend; `Text{body}` → write + close;
  `TcpForward{to}` → raw overlay stream spliced to a local host backend (no TLS).
- **Anti-leak**: serve listeners bind the **overlay** netstack only; the Proxy/TcpForward backend
  dial is a local host socket to the embedder's own backend (like the loopback proxy / Go's
  reverse-proxy to `127.0.0.1`), never routed through the `ts_forwarder` egress path. Per-port
  concurrent-connection cap (256). The legacy single-port `ServeConfig` + `Device::listen_tls`
  /`listen_funnel` are unchanged.

## [0.5.41](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.41) - 2026-06-06

Hardening + coverage from a multi-reviewer audit of the v0.5.33–v0.5.40 parity sweep. No happy-path
behavior change.

- **Security (HIGH)**: stop logging private key bytes. `ts_ffi`'s key-state load logged the full
  `persisted_key_state` (node/machine/network-lock private keys) at INFO via a derived `Debug`. The
  log line now records only the file path, and the FFI `key` / `persisted_key_state` types get
  manual **redacting `Debug`** impls so a stray `{:?}` can never leak key bytes.
- **ACME robustness**: every Let's Encrypt HTTP request is now bounded by a 30s
  `ACME_HTTP_TIMEOUT` (a stalled CA connection previously hung issuance forever, defeating the
  bounded poll loop), and responses are capped at 256 KiB (`ACME_MAX_RESPONSE`) against an unbounded
  body. Added a doc note that finalize is issued once the last authz is `valid` without polling the
  order to `ready` (accepted by LE/Pebble; a future hardening for strict CAs).
- **SSH lifecycle**: `serve_ssh` now bounds concurrent connections with a 64-permit semaphore
  (defense-in-depth beside the per-connection 16-channel cap) and owns its per-connection sessions
  in a `JoinSet`, so dropping the `serve_ssh` future aborts in-flight sessions instead of leaking
  them. A signal-killed shell now reports `128 + signal` instead of a bogus `exit-status 0`.
- **Tests**: an RFC-7638-style **known-answer** JWK-thumbprint test + a `public_jwk` header
  member-order guard (catch silent ACME wire drift against Let's Encrypt); an inclusive SSH
  channel-cap boundary test (15→allow / 16→refuse); and a symmetric isolation guard on the
  bad-binding disco-ping path (a rejected ping delivers no pong / doesn't bump the accepted counter).
- **Docs**: the FFI `ts_taildrop_save_file` / `ts_capture_pcap` `dst_path` is documented as a
  trusted-embedder host path (sanitize untrusted input); the permissive IPv6 pingable-candidate
  predicate is documented as intentional (no stable `is_global`; worst case a dead candidate → DERP).

## [0.5.40](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.40) - 2026-06-06

**Docs**: refresh `docs/PARITY_ROADMAP.md` to reflect near-complete tsnet parity as of v0.5.39.
Updates the per-lane parity estimates (A ~85%, B ~85%, C ~85%, D ~90%, E ~80%, bindings ~90%),
records the v0.5.27–v0.5.39 parity push, and enumerates the remaining deferred/external items
(TUN-mode MagicDNS, Serve accept-loop runtime, Service advertise-to-control, symmetric-NAT spray,
the external Funnel relay leg, netstack sharding) with their bead IDs. No code change.

## [0.5.39](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.39) - 2026-06-06

**Route `Device::listen_tls` through the ACME-aware issuance path** (follow-up to v0.5.38). With the
`acme` feature, `Device::get_certificate` issues a real cert, but `Device::listen_tls` was still
delegating to `ts_control::listen_tls`, which only knows the non-`acme` fail-closed stub — so a
`--features acme` build still failed closed on `listen_tls`. `Device::listen_tls` now validates the
serve config, obtains the certificate via `Device::get_certificate` (the `acme`-routed path), and
assembles the acceptor with `ts_control::tls_acceptor`. Without `acme` the behavior is unchanged
(same fail-closed `CertError`); with `acme` (and a `set-dns`-capable control plane) `listen_tls` now
returns a working acceptor. `listen_funnel` remains fail-closed on `MISSING_FUNNEL_RELAY` — public
Funnel additionally requires a Tailscale-operated ingress relay that a self-hosted control plane
cannot provide.

## [0.5.38](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.38) - 2026-06-06

**Client-side ACME (Let's Encrypt) certificate issuance + `set-dns` RPC** (roadmap Tier 4 item 10 /
Tier 5 item 16 keystone): `Device::get_certificate` can now mint a *real* publicly-trusted
certificate for a node's `*.ts.net` MagicDNS name, completing the long-stubbed Lane E. Behind the
new off-by-default `acme` feature.

This is faithful to how Go `tsnet` does it — **the node is the ACME client talking directly to
Let's Encrypt**; control's only role is publishing the DNS-01 challenge TXT:

- **Hand-rolled ACME (RFC 8555) DNS-01 engine** (`ts_control::acme`): full new-account → new-order →
  authz → finalize → download flow over the existing **ring-based** `ts_http_util` HTTPS stack, with
  ES256 JWS signing via `ring`, the RFC 7638 JWK thumbprint + RFC 8555 §8.1/§8.4 key-authorization /
  TXT-value computation (unit-tested byte-exact), and a `rcgen` (ring) CSR. Deliberately **not**
  `instant-acme` — that bundles a second hyper/aws-lc-rs TLS stack; hand-rolling keeps the
  **ring-only invariant structural** (confirmed: `aws-lc-rs` absent from the `--features acme`
  graph). No second TLS stack, no `instant-acme`, no `openssl`.
- **`POST /machine/set-dns` Noise RPC** (`ts_control::tokio::set_dns` + `ts_control_serde::SetDnsRequest`):
  publishes the `_acme-challenge.<name>` TXT, mirroring the existing id-token RPC. A `SetDnsPublisher`
  bridges it to the engine's `PublishTxt` seam.
- **Wiring**: `Device::get_certificate` → `Runtime::get_certificate` → a ControlRunner message (holds
  the control URL + node keys) → `issue_certificate_via_setdns`. The ACME **account key** is
  persisted in the node key state (`PersistState::acme_account_key`, `#[serde(default)]` so existing
  key files load as `None`) to keep one Let's Encrypt account across renewals; absent, an ephemeral
  per-call account key is generated.
- **Off by default + fail-closed**: WITHOUT the `acme` feature, `Device::get_certificate` is
  byte-identical to before (`CertError::Unimplemented`, no self-signed/plaintext fallback). The
  issuance path is **SaaS-only / DOA against a self-hosted control plane**, which returns HTTP 501 for `set-dns`
  (built for full tsnet parity, like the WIF subsystem) — it works against real Let's Encrypt + a
  control plane that implements `set-dns`. When functional, it transparently unblocks
  `Device::listen_tls` and `listen_funnel`.

## [0.5.37](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.37) - 2026-06-06

**IPv6 direct-path candidates** (roadmap Tier 5, item 13): close the last gap to negotiating a direct
IPv6 underlay path when `Config::enable_ipv6` is set. The disco machinery was already v6-capable
(reflexive set, peer-candidate accept/ping, IPv6-wins best-addr tiebreak, the dual-stack `[::]:0`
underlay bind), but `self_endpoints` only ever advertised the bound socket address — which for a
dual-stack bind is the undialable unspecified `[::]`, so no usable local v6 candidate was offered
and a direct v6 path never formed.

- `MagicSock::self_endpoints` now enumerates the host's IPv6 interface addresses (via `if-addrs`,
  which pulls only `libc` — no TLS) and emits each **global-unicast** address as a `Local` candidate
  paired with the bound port, **only when `enable_ipv6` is set**. The candidates are filtered through
  the same `is_pingable_candidate` the peer-accept side uses (single source of truth — rejects `::`,
  `::1`, link-local `fe80::/10`, ULA `fc00::/7`, multicast), so what we advertise exactly matches
  what we'd accept.
- **Default unchanged**: with `enable_ipv6 = false` (the proxy / k8s deployment default) zero v6
  candidates are emitted and the path is byte-identical to before. STUN stays IPv4-only (v6 reflexive
  arrives only via peer pongs, by design).
- **Anti-leak intact**: this is the overlay underlay disco path, not the forwarder egress — the
  `ts_forwarder` IPv4-only egress is untouched and the `ipv4_only_forwarder` guard stays green.

## [0.5.36](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.36) - 2026-06-06

**Disco + STUN observability counters** (roadmap Tier 5, item 20): extend the client-metric registry
with the NAT-traversal counters that surface the operationally-critical direct-vs-DERP-relay signal.
Previously only 5 UDP-datapath counters were wired; the disco path had none.

New `magicsock_*` counters (exported via `Device::metrics()` Prometheus text):
`disco_ping_recv` / `disco_ping_recv_rejected` (passed vs. failed the disco↔node-key binding check),
`disco_pong_sent`, `disco_pong_recv` / `disco_pong_recv_solicited`,
`disco_call_me_maybe_recv` / `disco_call_me_maybe_recv_rejected` (membership-gate accept vs. drop),
`disco_ping_sent`, `disco_call_me_maybe_sealed`, `stun_recv`, and `reflexive_learned` (only on a new
reflexive address, deduped). Each is incremented at the precise disco/STUN handler site; the
binding/gating behavior is byte-identical (pure observation). 5 delta-based tests assert the
counters fire (and the rejected paths do NOT increment the accepted counters). No new dependencies;
counters are relaxed atomics off the hot-path locks.

## [0.5.35](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.35) - 2026-06-06

**Turnkey Tailscale SSH login-shell server** (roadmap Tier 5, item 17): `Device::listen_ssh` now
runs a complete SSH server on the tailnet that grants authorized connections an interactive login
shell as their policy-mapped local user, mirroring Go `tailssh`'s incubator shell path. Behind the
off-by-default, non-musl `ssh` feature.

Previously the fork had the authorization half (`authorize_ssh`, fail-closed, enforced in
`ChannelServer::auth_none`) and a generic `serve_ssh::<H>` accept loop, but the only `ChannelHandler`
was the TUI demo — an embedder had to hand-write a shell handler. This adds the missing piece.

- **`Device::listen_ssh(config, listen_addr)`** = `serve_ssh::<ChannelServer<ShellHandler>>`.
- **`ShellHandler`** (`src/ssh/shell.rs`): resolves the **policy-mapped** local user (from the single
  `auth_none` accept decision — never re-evaluated, never defaulted) against the local passwd db via
  `nix`, spawns the user's login shell (`<shell> -l`) in a PTY (`pty-process`), and pumps the PTY
  master ↔ the SSH channel; window-change sets `TIOCSWINSZ`; child exit reports `exit-status`.
- **Privilege drop** in the child `pre_exec`, in the exact order **initgroups → setgid → setuid**
  (uid last — the order is load-bearing), so the shell runs as the mapped user, never as the
  (root) daemon. **Fail-closed everywhere**: an unresolved user, a failed privilege-drop step, or a
  daemon lacking the privilege to setuid aborts the session rather than running a shell with the
  wrong/elevated identity.
- **Clean environment**: the shell gets only `HOME/USER/LOGNAME/SHELL/PATH/TERM` (env cleared first),
  so the daemon's environment (auth keys, proxy credentials) never leaks into a user shell.
- **Resource bound**: a per-connection cap of 16 concurrent channels prevents an
  authorized-but-hostile peer from fork-bombing the host with session handlers.
- The authorized `local_user` is threaded from the single `auth_none` policy decision through to the
  handler (the `ChannelHandler::new` signature gains the accept identity); the SSH `exec` request
  form is not yet surfaced (interactive login shell only).

New dependencies (`pty-process`, `nix`) are strictly under the `ssh` feature; the default
musl/ring-only egress graph is unchanged (confirmed `aws-lc-rs` absent without `ssh`).

## [0.5.34](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.34) - 2026-06-06

**Language-binding parity** (roadmap Tier 4, item 12): propagate the newer `Device` surface into all
three bindings (`ts_ffi` C ABI, `ts_python` pyo3, `ts_elixir` rustler), bringing them from ~lanes-A–E
coverage up to the full device API.

Each binding now exposes (mirroring its native idiom): `fetch_id_token`, `metrics` (Prometheus
text), `self_key_expiry_unix` / `self_key_expired`, Taildrop receive (`waiting_files`,
`delete_file`, `save_file`-to-path) + Taildrop **send** (`send_file` resolves the peer by name and
streams a local file over the overlay), `capture_pcap`-to-path + `stop_capture`, `loopback` (returns
the bound addr + proxy credential + a stop-on-drop handle), and `tka_status`.

- **C FFI** (`ts_ffi`): new `ts_fetch_id_token`, `ts_metrics`, `ts_self_key_expiry_unix`,
  `ts_self_key_expired`, `ts_tka_status`, `ts_send_file`, `ts_taildrop_{waiting_files,file_size,
  save_file,delete_file}`, `ts_capture_pcap`/`ts_stop_capture`, `ts_loopback`/`ts_loopback_stop`,
  `ts_listen_service` (+ `ts_service_mode`), and `ts_string_free` for library-allocated strings; the
  `tailscale.h` header is regenerated. `listen_funnel` is omitted from the C ABI (its
  `FunnelOptions` type would require a `ts_control` dependency the C crate deliberately avoids; Funnel
  is fail-closed regardless).
- **Python** (`ts_python`): the above as `Device` async methods plus `listen_funnel` /
  `listen_service`, and a `LoopbackHandle` pyclass whose `stop()`/`__del__` tears down the proxy.
- **Elixir** (`ts_elixir`): the above as NIFs plus `listen_funnel`/`listen_service` and a
  `rotate_node_key` on the `Keystate` struct; a `LoopbackHandleResource` is registered for teardown.

`register_fallback_tcp_handler` is intentionally not bridged into Python/Elixir (it takes a native
Rust closure with no clean cross-language callback seam). No new TLS/crypto dependencies — the
ring-only invariant is preserved; the two non-C bindings take an internal `ts_control` dependency for
`FunnelOptions` only.

## [0.5.33](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.33) - 2026-06-06

Hardening + coverage from a multi-reviewer audit of the v0.5.27–v0.5.32 safe-bucket features. No
happy-path behavior change.

- **Capture hot-path fix** (`ts_runtime::capture`): `PcapSink` no longer flushes per record — a
  per-packet `flush()` syscall on the single dataplane thread collapsed throughput under capture.
  Buffered records now flush when the writer is dropped (on `stop_capture`); a new
  `PcapSink::flush()` lets a caller flush periodically for live tailing. The doc comment, which
  wrongly claimed "periodic flush", is corrected. Byte-layout unchanged.
- **WIF blocking I/O fix** (`ts_control::wif`): the AWS web-identity token read now uses
  `tokio::fs::read_to_string` instead of the blocking `std::fs` call inside the async resolver.
- **Loopback connection cap** (`Device::loopback`): the SOCKS5 accept loop now bounds concurrent
  connections with a semaphore (256), so a local client cannot open unbounded overlay sockets
  (each pins ~512 KiB of netstack buffers); the accept loop back-pressures at the cap.
- **Regression tests added**: `RegisterRequest.OldNodeKey` wire (de)serialization (present-when-set,
  omitted-when-`None`); the dataplane capture tee actually firing with `FromLocal` on
  `process_outbound`; and the Taildrop SSRF guard composition (`is_tailscale_ip ∘ peerapi_addr`
  rejects a non-CGNAT peer address).
- **Docs**: `LoopbackHandle` now documents that it is not tied to `Device` shutdown (hold/drop it for
  the proxy's lifetime); the WIF `?baseURL=` is documented as intentionally inert on the `client_id`
  path; the `CapturePath::SynthesizedTo{Local,Peer}` variants are documented as retained for Go
  wire-parity and not yet emitted.

## [0.5.32](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.32) - 2026-06-05

**Loopback SOCKS5 proxy** (`tsr-am9.6`): `Device::loopback()`, porting the SOCKS5 half of Go
`tsnet.Server.Loopback`. Binds a host-loopback TCP listener and proxies SOCKS5 `CONNECT`s into the
tailnet, so a non-Rust host process can reach tailnet peers through the proxy.

- `Device::loopback() -> (SocketAddr, proxy_cred, LoopbackHandle)`: binds `127.0.0.1:0` (**host
  loopback only** — never an external interface), serves SOCKS5 (RFC 1928) with required
  username/password auth (RFC 1929): username `tsnet`, password = a fresh 128-bit random hex
  `proxy_cred`. Each `CONNECT` is dialed **into the overlay** (`ATYP=IPv4` → `tcp_connect`,
  `ATYP=DOMAINNAME` → in-process MagicDNS resolve → overlay dial) and spliced to the accepted
  socket. `ATYP=IPv6` is refused (the fork is IPv4-only on the tailnet); non-`CONNECT` commands are
  refused. The returned `LoopbackHandle` stops the accept loop on drop (`#[must_use]`).
- **Anti-leak**: every connection egresses over the overlay netstack — never a host socket to the
  destination — so the host's real origin IP is never used to reach the target; there is no
  direct-dial fallback. The listener is loopback-only, and name resolution uses the in-process
  netmap (never the host resolver, which would leak intent). The SOCKS5 negotiation is bounded by a
  30s timeout (a stalled local client can't park a task forever); the splice itself is unbounded
  (proxied connections are long-lived).
- The LocalAPI HTTP surface Go also serves on the loopback is intentionally **not** ported: the fork
  exposes status/whois/id-token natively on `Device`, and Go itself recommends the in-process client
  over the loopback LocalAPI — so there is no SOCKS-vs-HTTP demux, just SOCKS5.

## [0.5.31](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.31) - 2026-06-05

**Workload-identity federation (WIF) + OAuth-client auth-key bootstrap** (`tsr-am9.5`), behind the
new off-by-default `identity-federation` cargo feature. Ports Go Tailscale's `feature/oauthkey` +
`feature/identityfederation`: resolve a Tailscale auth key from OAuth-client credentials or an
ambient IdP OIDC token *before* registration.

- New `Config` fields mirroring Go `tsnet.Server`: `auth_key`, `client_id`, `client_secret`,
  `id_token`, `audience` (env fallbacks `TS_AUTH_KEY` / `TS_CLIENT_ID` / `TS_CLIENT_SECRET` /
  `TS_ID_TOKEN` / `TS_AUDIENCE`). `Device::new` resolves the effective key with Go's precedence
  (explicit arg → `config.auth_key` → OAuth/WIF exchange).
- `ts_control::wif` (feature-gated) implements the exact Go wire contract: OAuth client-credentials
  (`POST /api/v2/oauth/token`), the bespoke WIF token-exchange (`POST /api/v2/oauth/token-exchange`
  with `client_id`+`jwt`), and CreateKey (`POST /api/v2/tailnet/-/keys`), plus ambient OIDC-token
  fetch for GitHub Actions / GCP metadata / AWS web-identity-token-file. Validation matches Go
  (client_id requires exactly one of id_token/audience; each requires client_id).
- **SaaS-only** and off by default: a self-hosted control plane (the fork's usual control plane) does not implement
  these admin-API endpoints (a self-hosted control plane issue #3081, closed unimplemented), mirroring Go's optional
  `feature/` blank-import gating. With the feature off, auth-key resolution is a pure pass-through
  and the config fields are inert — zero behavior change, zero new dependency.
- **Anti-leak preserved**: all calls reuse the existing ring-based `ts_http_util`/`ts_tls_util` stack
  (no new TLS/HTTP/AWS-SDK deps, cert validation intact); credentials/tokens are never logged or
  embedded in error strings; any failure is **fail-closed** (registration aborts — no silent keyless
  fallback). The id-token *issuance* side (`Device::fetch_id_token`) was already shipped earlier;
  this adds the *consumption*/bootstrap half.

The OAuth secret may carry a `?baseURL=` that redirects the exchange host, so the `client_secret` /
`auth_key` value must be treated as fully operator-trusted input (documented on the fields).

## [0.5.30](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.30) - 2026-06-05

**Node-key rotation: wire `RegisterRequest.OldNodeKey` + add the rotation primitive** (`tsr-am9.4`).
Fixes a real bug and completes the embedder-driven rotation path.

The bug: `register()` always sent `OldNodeKey = None`, so the fork's documented "re-create the
Device with a fresh node key + prior `old_node_key`" rotation silently broke key continuity — control
saw each rotation as a brand-new node. There was also no seam to supply the prior key.

- `register()` now sends `RegisterRequest.OldNodeKey` from the key state (omitted, as before, on a
  normal first registration — no behavior change for the common path).
- `PersistState` / `NodeState` carry a new `old_node_key: Option<NodePublicKey>`
  (`#[serde(default)]`, so existing on-disk key files load unchanged → `None`).
- New `PersistState::rotate_node_key()` and `Config::rotate_node_key()` mirror Go's `regen` flow:
  record the current node public key as the old key, generate a fresh node key. Re-create the
  `Device` from the rotated config to perform the rotation.

**This is deliberately NOT a background pre-expiry auto-rotator.** Research confirmed Go tsnet does
**not** auto-rotate the node key before expiry — node-key expiry is an intentional periodic
human/IdP re-authentication control, and the supported posture for unattended servers is to *disable
key expiry* (or use an auth-key / tag), not to silently rotate. Re-registration still requires a
valid auth credential. The fork matches Go: it surfaces expiry (`Device::self_key_expired` /
`self_key_expiry_unix`) and exposes the rotation primitive for the embedder to trigger; it never
silently re-registers on a timer.

Known follow-up: on a tailnet-lock (TKA) enabled tailnet, a rotation must also re-sign the node key
with the network-lock key (`RegisterRequest.NodeKeySignature`); this release covers the non-TKA path
(marked with a `TODO(TKA)`).

## [0.5.29](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.29) - 2026-06-05

**Fix: Tailnet-Lock (TKA) node key is now Ed25519, not X25519** (`tsr-am9.3`). The node-side
network-lock key (`NetworkLockPublicKey`/`NetworkLockPrivateKey`/`NetworkLockKeyPair`) was being
generated as an **X25519** key, but Go Tailscale's `key.NLPrivate`/`NLPublic` are **Ed25519**
(RFC 8032). The X25519 public key sent in `RegisterRequest.NLKey` would never have matched what a
TKA authority expects. Now fixed to standards-conformant Ed25519.

- New `create_ed25519_keypair_types!` macro in `ts_keys`, reusing the existing crypto-agnostic
  byte/Display/FromStr/serde/zerocopy machinery; only the key derivation differs — the public is
  derived via the RFC 8032 seed→public path (`ed25519-dalek`), matching Go's
  `ed25519.PrivateKey.Public()`.
- The `nlpub:`+lowercase-hex wire encoding of the 32-byte Ed25519 public is **byte-identical** to
  Go's `key.NLPublic.MarshalText` (proven by an RFC 8032 §7.1 Test-1 known-answer test through the
  fork's own `NetworkLockPrivateKey`).
- Seed entropy is sourced from `getrandom` (32 uniformly-random bytes) — deliberately **not** from
  x25519's bit-clamped `StaticSecret`, which would reduce seed entropy.
- The persisted node-state key stays 32 bytes with the same `nlpriv:`/`nlpub:` serde form, so the
  change needs **no migration** (matches Go, which was always Ed25519): a pre-fix persisted key
  simply loads as a valid Ed25519 seed and the node re-registers its corrected public on next
  connect. The X25519 key path is unchanged for Disco/Machine/Node keys (those genuinely are
  X25519).

## [0.5.28](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.28) - 2026-06-05

**Debug packet capture / `CapturePcap`** (`tsr-am9.2`): tee a pcap of every packet crossing the
dataplane to a writer, for `tcpdump`/Wireshark debugging — the fork's equivalent of Go Tailscale's
`tsnet.Server.CapturePcap` (`tstun.Wrapper.InstallCaptureHook` + `feature/capture`).

- **`Device::capture_pcap(writer)` / `Device::stop_capture()`** (root crate): install a capture hook
  that streams a pcap to any `std::io::Write`, and clear it. The 24-byte global header is written on
  start; capture is **opt-in** (off by default) and writes **only** to the caller-supplied sink —
  never to the network.
- **Byte-faithful classic-pcap framer** (`ts_runtime::capture::PcapSink`): magic `0xA1B2C3D4`, v2.4,
  snaplen 65535, **`LINKTYPE_USER0` (147)**, with Tailscale's 4-byte per-record path preamble
  (`[path:u16 LE][snat_len=0][dnat_len=0]` — this fork never does SNAT/DNAT) before each raw IP
  packet. A produced file opens in Wireshark; with Tailscale's `ts-dissector.lua` the direction/path
  of each packet decodes. Each record is flushed so a reader tailing the stream sees packets promptly.
- **Read-only dataplane tee** (`ts_dataplane`): a `CapturePath` (`FromLocal`/`FromPeer`/
  `SynthesizedTo{Local,Peer}`, on-wire codes 0–3, matching Go) + an `Option<CaptureHook>` on the
  sync `DataPlane`. Packets are tee'd at two points — outbound pre-encrypt (`FromLocal`) and inbound
  post-decrypt, pre-filter (`FromPeer`) — strictly read-only (no drop/reorder/mutate). When no
  capture is installed the datapath is byte- and performance-identical to before (a single `Option`
  check). The hook is installed/cleared at runtime via the dataplane actor, mirroring the existing
  packet-filter hot-swap.

## [0.5.27](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.27) - 2026-06-05

**Taildrop file sender** (`tsr-am9.1`): the sending half of Tailscale's peer-to-peer file transfer,
mirroring Go's wire sender. The fork already implemented the *receiver* (peerAPI `PUT /v0/put/<name>`
server + path-safe store); this adds the *client* that pushes a local file to a tailnet peer.

- **`Device::send_file(peer, name, content_length, reader)`** (root crate): push `content_length`
  bytes from any `AsyncRead` to a peer as `PUT /v0/put/<name>`. The body streams from offset 0 (the
  Range/resume GET Go uses as an optimization is deliberately omitted — a fresh full PUT is always
  correct).
- **Anti-leak**: the transfer dials **exclusively** over the overlay netstack (`channel.tcp_connect`,
  bound to this node's tailnet IPv4) — never a host socket — reusing the same discipline as the
  peerAPI DoH client (`ts_runtime::peerapi_doh`).
- **SSRF-safe by construction**: the destination is derived **only** from the peer's own node record
  via the new `Node::peerapi_addr()` (`tailnet-ipv4 : peerapi4-port`, mirroring Go
  `peerAPIBase`/`peerAPIPorts`). The caller passes a `&NodeInfo` obtained from `peer_by_name` /
  `peer_by_tailnet_ip` (a current netmap peer), not a raw address; as defense in depth the resolved
  address is additionally asserted to be a Tailscale CGNAT IP before dialing.
- **Request-smuggling-safe**: the file name is validated by the receiver's `validate_base_name`
  (rejects `/`, `\`, NUL, control chars, `..`) **and** percent-escaped with a strict whitelist encoder
  (`path_escape`, the Go `url.PathEscape` counterpart to the receiver's `percent_decode`), so CRLF /
  header injection / path traversal are structurally impossible.
- **Bounded against a hostile peer**: 10s dial timeout, 60s per-write idle timeout (caps a stalled
  `write_all` if a peer accepts the connection but never drains its window), 30s response-head read
  bounded to 8 KiB. Every non-2xx status (`403`→denied, `409`→conflict, other) returns an error — no
  failure is ever masked as success.

## [0.5.26](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.26) - 2026-06-05

Hardening + coverage from a multi-reviewer audit of v0.5.22–v0.5.25. No happy-path behavior change.

- **Security: gate the disco Pong reflexive-harvest** (`ts_magicsock`). `note_reflexive(src)` on an
  inbound Pong is now performed only when the pong is **both** (1) from a current netmap member
  (verifier checked, same as CallMeMaybe) and (2) **solicited** — it matched an outstanding ping we
  actually sent for that `(tx_id, from)`. Previously any party knowing our control-advertised disco
  pubkey could seal a pong with an arbitrary `src` and pollute our reflexive set (advertised to
  control + in CallMeMaybe, and amplified into the new `Stun4LocalPort` guess). The legitimate
  NAT-traversal path is unchanged.
- **`is_symmetric_nat` predicate extracted** (`ts_magicsock`): symmetric-NAT detection is now a
  named, documented method separate from endpoint assembly; the `reflexive` lock no longer spans the
  candidate-build loop.
- **`IdTokenError` owns its error vocabulary** (`ts_control`): a private `IdTokenInternalErrorKind`
  replaces the cross-module reuse of registration's error kind. `parse_token_response` and
  `flatten_send_err` were extracted and a **30s timeout** now bounds the id-token RPC.
- **Coverage**: added the previously-missing tests for the id-token RPC error mapping + response
  parsing (15), the kameo send-error flatten (3), `peer_relay` wire (de)serialization (3), the
  chrono-free key-expiry variants + `expiry==now` boundary + `is_peer_relay` (4), symmetric-NAT edge
  cases (local-port-skip / dedup / IPv6-ignored / non-member + unsolicited pong, 5), and a byte-exact
  Geneve reference vector (2) closing the self-roundtrip-only blind spot.

## [0.5.25](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.25) - 2026-06-05

**Symmetric-NAT traversal: hard-NAT local-port candidate** (`tsr-bs7`): improve direct-connect
success behind symmetric (endpoint-dependent-mapping) NATs, mirroring **current** Go Tailscale.

- magicsock now detects a symmetric NAT when the one bound socket is observed at **two or more
  distinct reflexive IPv4 `addr:port`s** (endpoint-dependent mapping — exactly Go's
  `MappingVariesByDestIP` determination from multi-STUN-server observations), or when set explicitly
  via `MagicSock::set_symmetric_nat` (e.g. from control's `NetInfo`).
- When symmetric NAT is detected, `self_endpoints()` advertises an extra hard-NAT candidate pairing
  a reflexive IPv4 with the node's **local** bound port (`SelfEndpointType::Stun4LocalPort` →
  control `EndpointType::Stun4LocalPort`), mirroring Go's `EndpointSTUN4LocalPort`: if the router
  has a static port-mapping to the fixed local port, this `(reflexive_ip, local_port)` may be
  reachable where the per-destination reflexive port is not. It rides the existing
  Pong→`bestAddr` path-selection with no special handling.

**Scope note:** the classic *birthday-paradox port-spray* this bead was named for **no longer exists
in mainline Tailscale** — it was removed in favor of this single static-port-mapping guess + DERP
fallback. Porting the spray would reimplement dead upstream code, so this release matches what Go
actually does today; behind a hard NAT with no static mapping, a flow still falls back to DERP (as
in upstream).

## [0.5.24](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.24) - 2026-06-05

**Peer-relay awareness** (`tsr-77q-d`): make the fork wire-aware of Tailscale's peer-relay feature
(relaying traffic through a peer's UDP relay server, Geneve-encapsulated). This is the bounded,
client-aware slice; the **active relay data path is intentionally deferred** (see below).

- **Geneve codec** (`ts_packet::geneve`, re-exported as `tailscale::geneve`): parse/encode the
  RFC 8926 fixed Geneve header Tailscale uses for relayed disco + WireGuard frames (the C bit,
  protocol type `0x7A11`/`0x7A12`, 24-bit VNI). Rejects non-zero version / variable options so a
  foreign Geneve packet isn't mis-decoded.
- **`Hostinfo.PeerRelay`** is parsed into `ts_control::Node::peer_relay` with an
  `is_peer_relay()` accessor, so a relay-capable peer can be recognized. (The fork is a relay
  *client* only and never advertises itself as a relay server.)

**Deferred:** actually traversing a relay path — the `relayManager` allocation/handshake state
machine + magicsock Geneve data path — is a large subsystem (Go ~1700-2000 LOC of stateful client
code) and is **not implemented**. This release makes the fork recognize the framing and peer
capability without choking; the disco demux already gracefully ignores relayed control frames it
can't act on. (The private/custom **DERP map** half of this bead was already satisfied — the fork
honors control-pushed DERP maps.)

## [0.5.23](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.23) - 2026-06-05

**Node-key expiry handling** (`tsr-77q-e`): surface this node's key-expiry state so an embedder can
react (re-authenticate / rotate), mirroring Go's **reactive** model.

- `ts_control::Node::key_expired(now)` / `key_expiry()` (and `chrono`-free `key_expired_at_unix` /
  `key_expiry_unix`): compute expiry from the self-node's `KeyExpiry` exactly as Go does
  (`!KeyExpiry.IsZero() && KeyExpiry.Before(now)`; a key with no expiry never expires).
- `Device::self_key_expiry_unix()` / `Device::self_key_expired()`: expose the current node's expiry
  instant and expired flag.

Per Go, the fork does **not** auto-rotate the node key in the background — Go transitions to
`NeedsLogin` on expiry and re-registers via a stored auth-key or interactive login. The registration
wire path already carries `RegisterRequest::old_node_key` + `expiry` for rotation (set a fresh
`node_key` + the prior `old_node_key` to rotate, or the same key to refresh); this release adds the
client-side *detection* half.

## [0.5.22](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.22) - 2026-06-05

**OIDC ID-token issuance / workload-identity federation** (`tsr-cdv`): a node can now ask control
to mint a short-lived OIDC ID token (JWT) it can present to a third-party relying party (e.g.
AWS/GCP workload-identity federation), mirroring Go `tailscale`'s `id-token` LocalAPI.

- **Wire types** (`ts_control_serde`): `TokenRequest` (`{CapVersion, NodeKey, Audience}`) and
  `TokenResponse` (`{id_token}`), mirroring `tailcfg.TokenRequest`/`TokenResponse`.
- **Noise RPC** (`ts_control::fetch_id_token`): `POST /machine/id-token` over the ts2021 transport,
  returning the signed JWT whose `aud` claim is the requested audience. Requires control capability
  version ≥ 30.
- **API**: `Device::fetch_id_token(audience)` (via a `ControlRunner` delegated-reply message + a
  `Runtime` wrapper). The node is the token *subject*, not the authenticator — this is token
  issuance, not a registration/login path; `RegisterRequest` is unchanged.

(Note: Go has no `ClientID` field and no separate federated-registration wire path — the bead's
"ClientID/Audience" framing maps to this issuance flow, where `Audience` is a per-call runtime input
and there is no `ClientID`. `tsnet.Sys()` is an unrelated generic subsystem accessor and is not
modelled.)

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
