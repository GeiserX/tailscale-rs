# tsnet parity matrix — Go `tsnet.Server` vs Rust `tailscale::Device` / `Config`

A field-by-field and method-by-method parity matrix between Go
[`tsnet.Server`](https://pkg.go.dev/tailscale.com/tsnet#Server) and this fork's public embedding
surface, `tailscale::Device` + `tailscale::Config`. Where the two orienting docs
([`MIGRATION_STATUS.md`](MIGRATION_STATUS.md) = subsystem completeness,
[`PARITY_ROADMAP.md`](PARITY_ROADMAP.md) = durable plan) answer *"which subsystems work"*, this
document answers the narrower question **"for every exported knob and call on `tsnet.Server`, what is
the exact Rust equivalent, and where is the gap?"** It is the granular companion to those two; it does
not restate the subsystem story.

> **Bottom line.** The `Device` facade is a **near-complete `tsnet.Server` superset** on the
> lifecycle / dial / listen / status surface, and folds Go's separate `LocalClient` into typed
> methods on `Device` itself. The genuine deltas are a small, well-understood set. On `Device`, the
> loopback server ships the SOCKS5 half with **one** credential. The `tsnet::Server` facade
> (`src/tsnet.rs:576`) adds what this matrix first listed as absent: Go's second loopback credential,
> an in-process LocalAPI server that answers status only, a `LocalClient` handle, and a
> `Dir`/`Store`/`FileStore` state root that also holds a netmap cache. Still absent: `Sys()` and
> `GetRootPath` (by design) and `LogtailWriter` (a support-only convenience). `ListenSSH` is
> **present** as a first-class method (a superset), contrary to how it is sometimes filed.

*Compiled 2026-07-12. Corrected in place on 2026-10-14 against `f311bba`, where the facade had closed
rows this matrix listed as absent. The current gap list and backlog are in
[PARITY_ROADMAP.md](PARITY_ROADMAP.md#gap-audit-and-open-backlog-at-wind-down-2026-10-14).*

**Provenance.** Every line reference is against these exact trees, read directly:

| Side | Repo @ ref | Files read |
|---|---|---|
| **Go** | `tailscale/tailscale` `main` @ [`296f6c1f`](https://github.com/tailscale/tailscale/commit/296f6c1f78a5a50b79b8c8d6663431f9bc483a43) (2026-07-11) | `tsnet/tsnet.go` (2347 lines), `client/local/local.go` (1569 lines) |
| **Rust** | `GeiserX/tailscale-rs` `main` @ `6c7a1bd` (v0.42.1) | `src/lib.rs`, `src/config.rs`, `src/loopback.rs`, `src/ssh/mod.rs`, `src/dial.rs`, `src/http.rs` |

**Verdict legend.**

| Verdict | Meaning |
|---|---|
| **PRESENT** | Functionally equivalent surface exists (shape may differ; noted). |
| **SUPERSET** | Rust exposes strictly more than Go here. |
| **PARTIAL** | Exists with a named, material gap. |
| **ABSENT** | Genuinely unbuilt — a real gap on the roadmap. |
| **ABSENT (by design)** | Deliberately not provided; a documented Rust substitute covers the need. |
| **N/A (internal)** | Go-internal runtime state with no public surface on either side; listed for completeness. |

Open backlog items are cross-referenced to their bead (`bd show <id>`; `tsr-*` prefix), matching
`MIGRATION_STATUS.md` §3.

---

## 1. The five headline gaps (verdicts at a glance)

These are the capabilities singled out for this audit. Full technical detail for each is in §5.

| # | Capability (Go) | Verdict | One-line delta | Bead |
|---|---|---|---|---|
| 1 | **Loopback dual-credential + in-process LocalAPI server** | **PARTIAL** | On `Device` the SOCKS5 half ships with **one** credential. The `tsnet::Server` facade adds the second credential (`Loopback.local_api_cred`, `src/tsnet.rs:469`) and an in-process LocalAPI server (`src/tsnet.rs:1326-1332`) that answers `GET /localapi/v0/status` only (`:1577-1590`). The rest of the LocalAPI, the HTTP-CONNECT half and SOCKS5 UDP ASSOCIATE/BIND are missing. | `tsr-ask7` |
| 2 | **`LogtailWriter`** | **ABSENT** | No logtail uploader / support-log `io.Writer`. The whole logtail transport is absent; logging is local `tracing` only. | (under `tsr-reh3`) |
| 3 | **`Dir` / `FileStore` state-root** | **PRESENT** (facade) | The `tsnet::Server` facade has a `StateStore` trait (`src/tsnet.rs:140`), `FileStore` (`:152`), `MemStore` (`:191`), `Server.dir` and `Server.store` (`:614`, `:618`), and a netmap cache under the dir (`:709`). One difference: with no dir and no store the identity is fresh every run while `ephemeral` defaults to false, so stale nodes pile up (2026-10-14 row R8). | (see §5.3) |
| 4 | **`GetRootPath` / `Sys()`** | **ABSENT (by design)** | No state-root getter (there is no root path); `Sys()`'s subsystem handle is replaced by typed accessors (`self_node`/`status`/`watch_netmap`/`whois`/`netcheck`). | `tsr-reh3` |
| 5 | **First-class `ListenSSH` / `LocalClient` handle** | `ListenSSH` **PRESENT** (superset); `LocalClient` handle **PRESENT** (facade) | `Device::listen_ssh` is a first-class turnkey method (+ `serve_ssh`/`serve_ssh_tui`/`authorize_ssh`), feature-gated `ssh`, login-shell PTY only. The `tsnet::Server` facade returns a `LocalClient` from `Server::local_client` (`src/tsnet.rs:945`); on `Device` the LocalClient methods (Status/WhoIs/Ping/…) live directly on `Device`. | `tsr-v5gw` (SSH exec/SFTP) |

---

## 2. `tsnet.Server` struct fields → Rust

Go marks the exported `Server` fields as *"may be changed until the first method call"* (tsnet.go:205);
in Rust the equivalents are **`Config` fields set before `Device::new`** (identity is immutable after
construction). The internal (unexported) Go fields are listed after, for completeness.

### 2a. User-settable config fields

| Go field (tsnet.go) | Go type | Rust equivalent (`src/config.rs` unless noted) | Verdict | Notes |
|---|---|---|---|---|
| `Dir` :217 | `string` | `tsnet::Server.dir` (`src/tsnet.rs:614`) | **PRESENT** (facade) | Roots the identity and a netmap cache (`src/tsnet.rs:709`). `Config` alone still has only the keys-only JSON file via `Config::default_with_key_file` :438. See §5.3. |
| `Store` :227 | `ipn.StateStore` | `tsnet::Server.store` (`src/tsnet.rs:618`) over the `StateStore` trait (`:140`) | **PRESENT** (facade) | `FileStore` (`:152`) and `MemStore` (`:191`) ship. Go's rule that a memory store needs an ephemeral node is not enforced. See §5.3. |
| `Hostname` :231 | `string` | `requested_hostname` :47 | **PRESENT** | Also settable live via `Device::set_hostname` (lib.rs:1509) — a superset. |
| `UserLogf` :236 | `logger.Logf` | — | **ABSENT** | No injectable logger; uses the `tracing` crate. `tsr-reh3`. |
| `Logf` :241 | `logger.Logf` | — | **ABSENT** | Same. Backend verbosity is `tracing` targets, not a closure. `tsr-reh3`. |
| `Ephemeral` :245 | `bool` | `ephemeral` :59 | **PRESENT** | |
| `AuthKey` :252 | `string` | `auth_key` :402 **and** the `auth_key` arg of `Device::new(config, auth_key)` (lib.rs:324) | **PRESENT** | Env fallback `TS_AUTH_KEY` via `auth_key_from_env` (config.rs:523). |
| `ClientSecret` :260 | `string` | `client_secret` :416 | **PRESENT** | Workload-identity-federation / OAuth authkey mint (feature-gated). |
| `ClientID` :267 | `string` | `client_id` :408 | **PRESENT** | |
| `IDToken` :275 | `string` | `id_token` :422 | **PRESENT** | |
| `Audience` :283 | `string` | `audience` :429 | **PRESENT** | |
| `ControlURL` :289 | `string` | `control_server_url` :32 | **PRESENT** | Defaults to `ts_control::DEFAULT_CONTROL_SERVER` (config.rs:653). |
| `RunWebClient` :293 | `bool` | `run_web_client` :371 | **PARTIAL** | Pref is **carried through `Config`/`ts_control::Config` only — never sent to control** (config.rs:363–371), and no embedded web client runs (port 5252). Behaviorally absent. `tsr-reh3`. |
| `Port` :298 | `uint16` | `wireguard_listen_port` :254 | **PRESENT** | WireGuard/p2p UDP port pin. (Go treats `Port` as a pin; parity nuance tracked under `tsr-reh3`.) |
| `AdvertiseTags` :304 | `[]string` | `requested_tags` :50 | **PRESENT** | |
| `Tun` :309 | `tun.Device` | `Config::use_tun(name, mtu)` :455 → `transport_mode` :265 | **PRESENT** (different shape) | Rust selects TUN by name/MTU via `TransportMode` rather than accepting a caller `tun.Device` object. Userspace-only seams (`tcp_connect`/`loopback`) are `UnsupportedInTunMode` by design. |

### 2b. Internal runtime fields (Go unexported) — for completeness

| Go field (tsnet.go) | Purpose | Rust status | Notes |
|---|---|---|---|
| `sys *tsd.System` :314 | Subsystem DI hub | **ABSENT (by design)** | No `Sys()`. Typed accessors substitute. See §5.4. |
| `lb *ipnlocal.LocalBackend` :313 | Core node backend | **N/A (internal)** | Realized by the `ts_runtime` engine; not exposed as a handle. |
| `netstack` :315, `netMon` :316 | Userspace netstack, link monitor | **N/A (internal)** | `ts_netstack_smoltcp`, `ts_netmon`. |
| `rootPath` :317 | Resolved state dir (see `GetRootPath`) | **ABSENT** | No root path exists. See §5.4. |
| `proxyCred` :321 | SOCKS5 loopback password | **PRESENT** | Rust's single loopback `cred` (loopback.rs:257). |
| `localAPICred` :322 | LocalAPI loopback password | **PRESENT** (facade) | `Loopback.local_api_cred` (`src/tsnet.rs:469`). See §5.1. |
| `loopbackListener` :323 | SOCKS5 + LocalAPI TCP listener | **PARTIAL** | Rust binds a SOCKS5-only `127.0.0.1` listener (loopback.rs:250); no SOCKS-vs-HTTP demux. |
| `localAPIListener` :324, `localClient` :325, `localAPIServer` :326 | In-memory LocalAPI pipe + client + HTTP server | **PARTIAL** (facade) | The facade runs an in-process LocalAPI server (`src/tsnet.rs:1326-1332`) that answers status only, and hands out a `LocalClient` (`:945`). On `Device` there is no LocalAPI transport; `Device` **is** the in-process client. See §5.5b. |
| `logbuffer *filch.Filch` :328, `logtail *logtail.Logger` :329, `logid` :330 | On-disk log buffer + uploader + log id | **ABSENT** | No logtail. See §5.2. |
| `dialer *tsdial.Dialer` :336 | Tailnet dialer backing `Dial`/SOCKS5 | **N/A (internal)** | Rust dials via the netstack `Channel`; surfaced through `Device::dial`/`tcp_connect`. |
| `listeners` :333, `advertisedServices` :337 | Listener + Service bookkeeping | **N/A (internal)** | Backed by the runtime; surfaced via `tcp_listen`/`listen_service`. |

---

## 3. `tsnet.Server` methods → Rust `Device`

Go exposes a single `Server` type whose methods split into *lifecycle*, *dial*, *listen*, and
*handle-getters*. Rust folds the `LocalClient` getters into `Device` and splits some Go methods by
protocol (e.g. `Listen` → `tcp_listen` + `listen_packet`).

| Go method (tsnet.go) | Rust equivalent (`src/lib.rs` unless noted) | Verdict | Notes |
|---|---|---|---|
| `Dial(ctx, network, address)` :356 | `dial(network, addr) -> DialConn` :610; also `dial_tcp` :641, `dial_udp` :667, `connect_by_name` :547, `tcp_connect` :739 | **PRESENT** | Rust offers typed variants + `connect_by_name` (MagicDNS) as a superset. |
| `HTTPClient()` :399 | `http_connector() -> TailnetConnector` :838 (`src/http.rs`) | **PRESENT** | Hyper connector, feature-gated `hyper`. Same "HTTP over the tailnet" role. |
| `LocalClient() (*local.Client, …)` :411 | `tsnet::Server::local_client()` (`src/tsnet.rs:945`); on `Device`, methods directly | **PRESENT** (facade) | See §5.5b and §4. |
| `Loopback() (addr, proxyCred, localAPICred, …)` :445 | `loopback() -> (SocketAddr, String, LoopbackHandle)` :772 (`src/loopback.rs`); the facade's `Loopback` carries both credentials (`src/tsnet.rs:469`) | **PARTIAL** | `Device`: one cred, SOCKS5-only. Facade: two creds, LocalAPI answers status only. See §5.1. |
| `Start()` :527 | (implicit) `Device::new(config, auth_key)` :324 | **PRESENT** | Rust connects during async construction; no separate idempotent `Start`. |
| `Up(ctx) (*ipnstate.Status, …)` :535 | `wait_until_running(timeout) -> Result<(), RegistrationError>` :1626 (+ `watch_state` :1589, `status` :1207) | **PRESENT** (SUPERSET) | Rust returns a **typed** registration outcome (permanent vs recoverable vs transient) instead of a status blob. |
| `Close()` :603 | `shutdown(timeout) -> bool` :1961 | **PRESENT** | Consumes `self`; returns whether shutdown completed within the timeout. |
| `CertDomains()` :682 | `cert_domains() -> Vec<String>` :860 | **PRESENT** | |
| `TailscaleIPs()` :693 | `tailscale_ips() -> (Ipv4Addr, Option<Ipv6Addr>)` :434 (+ `ipv4_addr` :407, `ipv6_addr` :417) | **PRESENT** | |
| `LogtailWriter() io.Writer` :714 | — | **ABSENT** | No logtail. See §5.2. |
| `Listen(network, addr)` :1264 | `tcp_listen(...)` :457 | **PRESENT** | TCP announce on the tailnet. |
| `ListenSSH(addr)` :1282 | `listen_ssh(config, addr)` :194 (`src/ssh/mod.rs`) | **PRESENT** (SUPERSET) | First-class + turnkey login-shell; also `serve_ssh` :124, `serve_ssh_tui` :207, `authorize_ssh` :66. Feature `ssh`. Login-shell PTY only (`tsr-v5gw`). See §5.5a. |
| `ListenPacket(network, addr)` :1302 | `listen_packet(...)` :697 (+ `udp_bind` :447) | **PRESENT** | UDP listener on the tailnet. |
| `ListenTLS(network, addr)` :1361 | `listen_tls(...)` :1746 | **PRESENT** | Real cert issuance via ACME DNS-01 against a `set-dns`-capable control plane (feature `acme`). |
| `RegisterFallbackTCPHandler(cb)` :1393 | `register_fallback_tcp_handler(cb) -> FallbackTcpHandle` :483 | **PRESENT** | |
| `ListenFunnel(network, addr, opts…)` :1464 | `listen_funnel(...)` :1874 | **PARTIAL** | Client leg ships and fail-closes; the public ingress relay leg is Tailscale-operated (external-blocked, `tsr-am9.11`). |
| `ListenService(name, mode)` :1825 | `listen_service(...)` :1940 | **PARTIAL** | Consume only: it binds a VIP the netmap already granted (`src/lib.rs:2051-2063`). It does not advertise at runtime or withdraw on close, and `ServiceMode` carries a port only (2026-10-14 rows R4, R5). |
| `GetRootPath() string` :2201 | — | **ABSENT** | No root path. See §5.4. |
| `CapturePcap(ctx, file)` :2213 | `capture_pcap(writer)` :1172 (+ `stop_capture` :1196) | **PRESENT** | Rust streams to any `Write` sink and can stop; Go writes to a file until exit. |
| `Sys() *tsd.System` :2237 | — | **ABSENT (by design)** | Typed accessors substitute. See §5.4. |

---

## 4. `local.Client` (LocalClient) methods → Rust `Device`

Go's `Server.LocalClient()` hands back a `*local.Client` that speaks LocalAPI over an in-memory pipe.
This fork has **no `LocalClient` type**: `Device` itself is the in-process client, so each LocalClient
method maps to a `Device` method (or is ABSENT). This is the single biggest structural difference and
is deliberate (§5.5b). The most-used LocalClient surface:

| Go `local.Client` method (client/local/local.go) | Rust `Device` equivalent (`src/lib.rs`) | Verdict | Notes |
|---|---|---|---|
| `Status(ctx)` :715 | `status()` :1207 | **PRESENT** | Per-peer `online`/`last_seen` are kept and reported (`ts_runtime/src/status.rs:20-23`); `tsr-x72n` is closed in the tree. |
| `StatusWithoutPeers(ctx)` :725 | `status()` :1207 (self fields) | **PARTIAL** | No dedicated peerless variant; read self fields off `status()`. |
| `WhoIs(ctx, remoteAddr)` :320 | `whois(addr) -> Option<WhoIs>` :1383 | **PRESENT** | `WhoIs.user` + `WhoIs.capabilities` populated (v0.6.5). |
| `WhoIsForIP` :349 / `WhoIsForService` :334 | — | **ABSENT** | VIP/service-scoped WhoIs not surfaced. |
| `Ping(ctx, ip, type)` :1158 | `ping(dst, timeout)` :1644 (+ `ping_disco` :1675, `direct_path` :1661) | **PRESENT** (SUPERSET) | Rust adds disco-ping + direct-path introspection. |
| `StartLoginInteractive(ctx)` :962 | `pop_browser_url()` :903 + `watch_state` :1589 | **PRESENT** | Interactive-login URL is surfaced via state watch. |
| `Start(ctx, opts)` :969 | `Device::new` :324 | **PRESENT** | Construction applies config + starts. |
| `Logout(ctx)` :975 | `logout()` :1364 | **PRESENT** | Re-register with a past expiry (v0.6.5). |
| `GetPrefs` :901 / `EditPrefs` :918 / `CheckPrefs` :896 | typed setters: `set_exit_node` :1402, `set_accept_routes` :1429, `set_accept_dns` :1457, `set_advertise_routes` :1479, `set_advertise_exit_node` :1497, `set_hostname` :1509, `set_dns` :1341; readers `exit_node` :1410, `accept_routes` :1437, `accept_dns` :1465, `active_exit_node` :1563 | **PRESENT** (different shape) | No single masked-prefs blob; one typed method per pref. |
| `WatchIPNBus(ctx, mask)` :1368 | `watch_ipn_bus(mask) -> IpnBusWatcher` :1604 (+ `watch_netmap` :1571, `watch_state` :1589) | **PRESENT** | |
| `DialTCP(ctx, host, port)` :986 | `dial_tcp(addr)` :641 / `tcp_connect` :739 | **PRESENT** | |
| `CertDomains(ctx)` :1077 | `cert_domains()` :860 | **PRESENT** | |
| `IDToken(ctx, aud)` :740 | `fetch_id_token(audience)` :1328 | **PRESENT** | |
| `SetUseExitNode(ctx, on)` :1414 | `set_exit_node(...)` :1402 | **PRESENT** | |
| `GetDNSOSConfig` :928 / `QueryDNS` :946 | `dns_config()` :877 / `query_dns(...)` :535 (+ `resolve` :503) | **PRESENT** | |
| `SuggestExitNode(ctx)` :1508 | `suggest_exit_node()` :952 | **PRESENT** (SUPERSET vs plain tsnet embedding) | |
| `StreamDebugCapture` :1342 | `capture_pcap(writer)` :1172 | **PRESENT** | |
| Taildrop `WaitingFiles`/`PushFile`/`FileTargets` :752–806 | `taildrop_waiting_files` :1054, `taildrop_open_file` :1069, `taildrop_delete_file` :1082, `send_file` :1108, `file_targets` :1149 | **PRESENT** | Full send/recv data path. |
| `CheckUpdate` :1398, `CurrentDERPMap` :1061, `ProfileStatus` :1225, `SwitchProfile`/`DeleteProfile` :1267/1275, `BugReport` :601, `DisconnectControl` :1165, `GetServices` :1563, `DaemonMetrics`/`UserMetrics` :400/406 | mostly — (`metrics()` :1375 covers the metrics case) | **ABSENT** / **PARTIAL** | Multi-profile management, DERP-map introspection, update-check, bug-report, and control-disconnect are not surfaced. `metrics()` returns a Prometheus-text scrape. |

---

## 5. The five headline gaps — technical detail

### 5.1 Loopback dual-credential + in-process LocalAPI server — **PARTIAL** (`tsr-ask7`)

*Corrected 2026-10-14: the text below describes `Device::loopback`. The `tsnet::Server` facade now
adds the second credential (`src/tsnet.rs:469`) and an in-process LocalAPI that answers status only
(`src/tsnet.rs:1577-1590`).*

**Go** (`Loopback`, tsnet.go:445–508) mints **two** 16-byte credentials — `proxyCred` (:451–455) and
`localAPICred` (:457–461) — binds one `127.0.0.1:0` listener, and multiplexes it by first-byte sniff:

```go
socksLn, httpLn := proxymux.SplitSOCKSAndHTTP(ln)   // tsnet.go:469
```

- The **HTTP** side (:474–490) serves the **LocalAPI** via `localapi.NewHandler(...)` with
  `PermitRead`/`PermitWrite = true` and `RequiredPassword = s.localAPICred`, wrapped in a
  `localSecHandler` that *additionally* requires the header `Sec-Tailscale: localapi` (:516–523). So
  the powerful `/localapi/v0/...` surface needs **both** the header **and** Basic-auth `localAPICred`.
- The **SOCKS5** side (:491–500) is `socks5.Server{Username:"tsnet", Password: s.proxyCred,
  Dialer: s.dialer.UserDial}` — an *outbound* proxy onto the tailnet.

`Loopback()` returns `(addr, proxyCred, localAPICred, err)` (:508).

**Rust** (`Device::loopback`, lib.rs:772 → `loopback::start`, loopback.rs:245) binds `127.0.0.1:0`
(loopback.rs:250), generates **one** 32-hex credential (`gen_cred`, loopback.rs:257/273), and serves
**SOCKS5 directly with no demux**. Its own module doc states the omission is intentional:

> "The LocalAPI HTTP surface that Go also serves on the loopback is intentionally NOT provided here:
> this fork exposes status/whois/id-token natively on `Device`, and Go itself recommends the
> in-process client over the loopback LocalAPI." — `src/loopback.rs:9–12`

The return is `(SocketAddr, String, LoopbackHandle)` (loopback.rs:247) — **one** credential, username
fixed to `"tsnet"` (loopback.rs:68), `CONNECT` only. **Delta vs Go:** the second `localAPICred`, the
in-process LocalAPI **HTTP** server (`/localapi/v0/...`), the HTTP-`CONNECT` proxy half (Go's own
`TODO`, tsnet.go:471), and SOCKS5 `UDP ASSOCIATE`/`BIND` (loopback.rs:96 refuses them). IPv6 targets
are refused by design (loopback.rs:126, IPv4-only tailnet).

### 5.2 `LogtailWriter` — **ABSENT** (under `tsr-reh3`)

**Go** wires an on-disk `filch` buffer + a `logtail.Logger` that uploads to `log.tailscale.com`
(`startLogger`, tsnet.go:1043–1081) and exposes `LogtailWriter() io.Writer` (:714) so an embedder can
tee support logs into the same stream (support-team-only, not user-retrievable).

**Rust** has **no logtail transport, buffer, or writer** anywhere in `src/`, `ts_runtime`, or
`ts_control` (verified: no `logtail`/`filch`/log-upload implementation). Logging is the local `tracing`
crate. The only `logtail`-adjacent code is wire metadata sent to control (`FrontendLogID`/`BackendLogID`
in `ts_control_serde/src/host_info.rs:31,35`) and a capver note — no uploader. The paired `Logf`/`UserLogf`
injectable loggers (§2a) are likewise absent. Grouped under `tsr-reh3` ("tsnet API knobs").

### 5.3 `Dir` / `FileStore` state-root — **ABSENT** (design; keys-only persistence)

*Corrected 2026-10-14: this was true of `Device` and `Config` when written. The `tsnet::Server` facade
now has a `StateStore` trait, `FileStore`, `MemStore`, `dir` and `store`, and keeps a netmap cache under
the dir (`src/tsnet.rs:140-191`, `:614-618`, `:709`).*

**Go**: `Server.Dir` (tsnet.go:217) resolves to `rootPath` (defaulting to
`os.UserConfigDir()/tsnet-<binary>`, tsnet.go:809–814); `Store` (:227), if nil, becomes a `FileStore`
at `Dir/tailscaled.state` (`store.New`, tsnet.go:917–920). Under `Dir` Go persists the full node state
(`tailscaled.state`), the log policy (`tailscaled.log.conf`), and filch log buffers. A `*mem.Store` is
allowed only for `Ephemeral` nodes (:802–807).

**Rust**: there is **no state directory, no `StateStore`/`FileStore` trait, and no prefs/netmap
persistence.** The only durable state is **node identity keys** — `Config.key_state: PersistState`
(config.rs:22): `machine_key`, `node_key`, `old_node_key`, `network_lock_key`, `acme_account_key`
(`ts_keys`). The mechanism is a **single JSON key file, loaded once at construction, not a callback**:
`Config::default_with_key_file(path)` (config.rs:438) → `load_key_file` (config.rs:532) →
`load_or_init` writes only on first-init / bad-format; `Device::new` then consumes the blob once
(lib.rs:336). After `Config::rotate_node_key` (config.rs:517) the **caller** owns re-serialization and
re-construction. The only directory-typed `Config` field, `taildrop_dir` (config.rs:396), stores
Taildrop *payloads*, not node state. **Delta vs Go:** a directory state-root, a pluggable
`StateStore`/`FileStore`, and continuous persistence of prefs + full node state. This is the one
headline item that is a genuine unbuilt gap rather than a design substitution (no bead filed yet).

### 5.4 `GetRootPath` / `Sys()` — **ABSENT (by design)** (`tsr-reh3`)

**Go** exposes `GetRootPath() string` (tsnet.go:2201, returns `s.rootPath`) and `Sys() *tsd.System`
(tsnet.go:2237) — an explicitly-unstable handle to the subsystem registry (netstack, magicsock, DNS
manager, event bus, health tracker, store, logtail).

**Rust** has **neither**. There is no root path to get (§5.3), and no `Sys`-style handle: the fork's
own roadmap states *"`Sys()` internals — satisfied via typed accessors
(`self_node`/`status`/`watch_netmap`/`whois`)"* (`PARITY_ROADMAP.md:120`). Concretely, the subsystem
views Go reaches through `Sys()` are surfaced as flat, typed `Device` methods — `self_node` :845,
`status` :1207, `netcheck` :919, `watch_netmap` :1571, `watch_ipn_bus` :1604, `metrics` :1375,
`re_stun` :1551, `rebind` :1534 — rather than one downcastable registry. This is a deliberate,
type-safe substitution, not an unbuilt gap.

### 5.5 First-class `ListenSSH` / `LocalClient` handle — **SPLIT**

**(a) `ListenSSH` — PRESENT (superset).** Contrary to the "gap" framing, `ListenSSH` is a first-class
Rust method. `Device::listen_ssh(config, listen_addr)` (ssh/mod.rs:194) is a *turnkey* login-shell SSH
server; alongside it are `serve_ssh` (:124, bring-your-own handler), `serve_ssh_tui` (:207, ratatui
app), and `authorize_ssh` (:66, the SSH-policy check). It is **not** a `Config` flag — `Config` has
zero SSH fields — but is enabled by *calling* the method behind the `ssh` cargo feature
(`#[cfg(feature = "ssh")] pub mod ssh;`, lib.rs:197). The real gap here is narrower than "missing": the
server is **login-shell PTY only** — no exec, SFTP, or port-forwarding, and no session-recording
transport (`tsr-v5gw`; recorder is a separate engine-ask). This is the only sub-item with a functional
delta.

**(b) `LocalClient` handle — ABSENT (by design) on `Device`.** *Corrected 2026-10-14: the `tsnet::Server`
facade now returns one from `Server::local_client` (`src/tsnet.rs:945`).* Go returns a `*local.Client` handle whose ~40
methods are the LocalAPI surface. This fork has **no `LocalClient` struct**: `Device` *is* the
in-process client, with the LocalClient methods surfaced directly on it (the whole of §4). The upside
is no LocalAPI socket, credential, or serialization on the hot path — calls are direct typed method
calls. The downside is there is no single detachable client object to pass around, and the few
LocalClient methods not yet surfaced on `Device` (multi-profile management, `CurrentDERPMap`,
`CheckUpdate`, `BugReport`, `DisconnectControl`; see §4's last row) have no home yet.

---

## 6. Rust-only surface (supersets Go `tsnet` has no equivalent for)

Listed so the matrix is symmetric — these are *not* Go parity gaps; they are capabilities the fork
adds. Do not file them as missing on the Go side.

| Rust (`src/lib.rs` / `config.rs` / `AGENTS.md`) | What it adds |
|---|---|
| `Config::exit_proxy` (`ExitProxyConfig`/`ExitProxyScheme`) config.rs:174 | **Residential-proxy exit egress** — an exit node egresses forwarded traffic through an upstream SOCKS5/HTTP-CONNECT proxy so the host's origin IP never appears. Fail-closed, zero new deps. Go `tsnet` has no equivalent (`AGENTS.md`). |
| `Device::new_with_secret` :385 | Construct from a pre-supplied node secret (daemon engine-ask). |
| `Device::re_stun` :1551, `Device::rebind` :1534 | Force a STUN re-probe / socket rebind (live diagnostics). |
| `Device::suggest_exit_node` :952, `active_exit_node` :1563 | Exit-node suggestion + resolved-engaged exit (fail-closed). |
| `Device::watch_state` :1589 / `device_state` :1579 (`DeviceState` stream, typed `RegistrationError`) | Typed lifecycle stream distinguishing permanent / recoverable / transient registration outcomes — richer than `Up`'s status blob. |
| `Device::tka_status`/`tka_log`/`tka_sign`/`tka_disable`/`tka_init` :1218–1313 | Client-side Tailnet-Lock verification + mutation surface (active, fail-closed enforcement). |
| Live pref setters `set_accept_routes`/`set_accept_dns`/`set_advertise_routes`/… :1429–1509 | One typed method per pref, settable at runtime. |
| FFI / Python / Elixir bindings (`ts_ffi`, `ts_python`, `ts_elixir`) | Most public `Device` methods propagated to C/Python/Elixir. `ts_ffi` exports 59 functions against 77 public `Device` methods, and `set_exit_node`, `logout`, `watch_ipn_bus`, `suggest_exit_node`, `set_serve_config` and `listen_ssh` have no binding (2026-10-14 row R20). |

---

## 7. Consolidated gap ledger

Every delta in one place (headline gaps in **bold**), each with its verdict and bead. This unifies §5
with the remaining API-surface gaps already tracked in `MIGRATION_STATUS.md` §3.

| Gap | Verdict | Bead |
|---|---|---|
| **Loopback: LocalAPI beyond status + HTTP-CONNECT proxy half + SOCKS5 UDP/BIND** (the second credential and a status-only LocalAPI ship in the facade) | PARTIAL | `tsr-ask7` |
| **`LogtailWriter` + `Logf`/`UserLogf` injectable loggers** | ABSENT | `tsr-reh3` |
| ~~**`Dir` / `Store` / `FileStore` on-disk state-root**~~ | PRESENT in the facade (corrected 2026-10-14) | *(none needed)* |
| **`GetRootPath`** | ABSENT | `tsr-reh3` |
| **`Sys()` subsystem handle** | ABSENT (by design) | `tsr-reh3` |
| **`ListenSSH`: exec / SFTP / port-forward / session-recording** (method itself PRESENT) | PARTIAL | `tsr-v5gw`, `tsr-0h2` |
| ~~**`LocalClient` typed handle**~~ | PRESENT in the facade (`src/tsnet.rs:945`, corrected 2026-10-14) | — |
| `RunWebClient` embedded web client behavior (pref carried) | PARTIAL | `tsr-reh3` |
| `Port` pin equivalence nuance | PARTIAL | `tsr-reh3` |
| ~~Per-peer `Status`/`WhoIs` `online` / `last_seen`~~ | PRESENT (kept and reported, corrected 2026-10-14) | `tsr-x72n` (closed in the tree) |
| `WhoIsForIP` / `WhoIsForService` (VIP/service-scoped) | ABSENT | — |
| `LocalClient.Netcheck` full `netcheck.Report` | PARTIAL (DERP-latency + HTTPS only) | `tsr-dsjq` |
| Serve stored-state runtime + `ServeConfig` Go-wire-compat | PARTIAL (handlers ship; Go's `ipn.ServeConfig` wire shape since `50611ab`; deliberate refusals at `ts_control/src/serve/ipn.rs:386-394`) | `tsr-0xn` (closed) |
| `ListenFunnel` public ingress relay leg | PARTIAL (external-blocked, Tailscale infra) | `tsr-am9.11` |
| Multi-profile mgmt / `CurrentDERPMap` / `CheckUpdate` / `BugReport` / `DisconnectControl` | ABSENT | — |

---

## 8. How to read / maintain this matrix

- **Source of truth for status is the beads** (`bd list --status open`, prefix `tsr-`); this matrix is
  a point-in-time snapshot compiled from the trees named in *Provenance*. When Go or Rust moves, re-pull
  both files and re-diff — the line numbers here are anchors, not guarantees.
- **This doc is the granular companion**, not a replacement, for `MIGRATION_STATUS.md` (subsystem
  completeness) and `PARITY_ROADMAP.md` (durable plan + invariants). Verdicts here are reconciled with
  those docs; where a gap has a bead, that bead is authoritative.
- **The fork's invariants override naive "parity."** Several deltas above are *stricter* than Go by
  design — IPv4-only tailnet, fail-closed egress, ring-only crypto, `Sys()`→typed-accessors — and are
  documented as intentional supersets in `MIGRATION_STATUS.md` §2 and `PARITY_ROADMAP.md` "Invariants".
  Do not file those as regressions.
