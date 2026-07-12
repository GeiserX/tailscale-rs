# Design: a Go-idiomatic `tsnet.Server` facade over `Device`/`Config`

**Status:** design, with a compiling reference skeleton landed behind the `tsnet` cargo feature
(`src/tsnet.rs`).
**Scope:** a **thin** ergonomics layer only. No new engine, no new published crate, no dataplane /
control / netstack changes.
**Companion:** [`docs/TSNET_PARITY.md`](TSNET_PARITY.md) is the authoritative field/method parity
matrix; this doc designs the *shape* that wraps the surface that matrix enumerates. Where they
overlap, the matrix's verdicts are authoritative.

*Compiled 2026-07-12 against `GeiserX/tailscale-rs` `feat/tsnet-facade` (base `3ea6d32`, the parity
commit).*

---

## 1. Goal, and what "Go-idiomatic" means here

The fork's native embedding surface — [`Device`] + [`Config`] — is already a **near-complete
superset** of Go [`tsnet.Server`](https://pkg.go.dev/tailscale.com/tsnet#Server) (parity matrix
"Bottom line"). It is idiomatic *Rust*: build a `Config`, then

```rust
let dev = Device::new(&config, auth_key).await?;
```

Go's shape is different — a struct you fill in, then call:

```go
srv := &tsnet.Server{Hostname: "web", AuthKey: key}
ln, _ := srv.Listen("tcp", ":80")   // Start() happens lazily on first call
defer srv.Close()
```

A large body of code and muscle memory targets that shape. The goal is a `Server` type that presents
Go's **lifecycle model and names** while forwarding straight to the existing `Device`.

**"Go-idiomatic" is scoped to the *shape*, not the *types*.** A thin facade must not re-wrap the
engine's returns into `net.Conn` / `net.Listener` trait objects — that would be a translation layer,
not a facade, and would discard the fork's typed values. So the design draws a deliberate line:

| Mirrors Go | Stays Rust-native |
|---|---|
| Settable fields on `Server`, read at first use | Field **types** (`Option<String>`, `Vec<String>`, `PathBuf`) |
| Lazy `start`; `up` / `close`; `Listen`/`Dial`/`Loopback`/`ListenFunnel`/`ListenService` names | Return types: [`DialConn`], [`netstack::TcpListener`], … (no trait-object wrapping) |
| `network, addr` **strings** (`"tcp"`, `":80"`) accepted for familiarity | Parsed to typed [`SocketAddr`] before hitting the engine |
| A single lifecycle error (Go's opaque `error`) | Typed errors preserved on specialized calls (`FunnelError`, `ServiceError`) |

### Non-goals (explicit)

- **Not** a re-implementation. Every method is a one-liner delegation to `Device`.
- **Not** a new crate. It ships as `#[cfg(feature = "tsnet")] pub mod tsnet` in the root crate, so it
  can iterate against `Device`/`Config` in-tree with no versioning surface. Extracting a
  `tailscale-tsnet` crate later is a pure re-export move if ever wanted (see §12).
- **Not** an engine change. Where Go exposes a knob the engine doesn't yet thread (e.g.
  `FunnelTLSConfig`), the facade surfaces the option and documents the gap rather than faking it.

---

## 2. Naming

| Decision | Choice | Rationale |
|---|---|---|
| Module | `tailscale::tsnet` | Matches the Go package name; discoverable; `use tailscale::tsnet::Server`. |
| Wrapper type | `tsnet::Server` | Same name/role as Go's `tsnet.Server`. |
| Feature flag | `tsnet` (`Cargo.toml`: `tsnet = ["dep:base64"]`) | Off by default. Reuses the crate's existing `serde_json`/`tokio`/`thiserror`/`rand`; adds **one** new *optional, direct* dependency edge — `base64` (HTTP Basic-auth for the loopback LocalAPI). It was already in the workspace graph, so no new crate is compiled — but it is a new direct edge for `tailscale`, not literally "zero new deps". |
| Lifecycle error | `tsnet::Error` | One Go-shaped error for the lifecycle path (§7). |
| State store | `tsnet::StateStore` / `FileStore` / `MemStore` | Go `ipn.StateStore` / `store.FileStore` / `mem.Store` analogs (§8). |
| Funnel options | `tsnet::FunnelOptions` (`funnel_only`, `with_tls`) | Rust-idiomatic collapse of Go's variadic `...FunnelOption` (§9). |
| Service listener | `tsnet::ServiceListener` | Go's `*tsnet.ServiceListener` (`net.Listener` + `FQDN`) analog (§10). |
| Loopback result | `tsnet::Loopback` | Names Go's `(addr, proxyCred, localAPICred, err)` tuple — **both** creds + a running LocalAPI HTTP server (§11). |
| LocalAPI client | `tsnet::LocalClient` | Go's `LocalClient()` return — a client that round-trips through the loopback LocalAPI (§11). |

Methods keep Go's names in Rust snake_case: `start`, `up`, `close`, `dial`, `listen`,
`listen_packet`, `listen_funnel`, `listen_service`, `loopback`, `tailscale_ips`, `cert_domains`,
`status`, `logout`. The full `LocalClient` surface is reached via `Server::device()` (§6).

---

## 3. Lifecycle: field-set-then-lazy-start over `Device::new`

This is the crux. Go's `Server` fields "may be changed until the first method call" (tsnet.go:205);
the first `Dial`/`Listen`/… triggers a lazy `Start()`. The engine anchor is:

```rust
// src/lib.rs:324
pub async fn new(config: &Config, auth_key: Option<String>) -> Result<Device, Error>
```

`Device::new` **is** Go's `Start` (it spawns the runtime and connects during construction). So the
facade holds the settable fields plus a lazily-initialized `Device`:

```rust
pub struct Server {
    pub hostname: Option<String>,       // + the other Go-parity fields (§5)
    // …
    configure: Option<ConfigureHook>,   // escape hatch to Config (§5)
    device: tokio::sync::OnceCell<Device>,
}
```

- **First method call builds and starts.** Each method calls `self.started().await?`, which is
  `self.device.get_or_try_init(|| self.build_and_start()).await`. `build_and_start` maps the fields
  onto a `Config` (§5), applies the `configure` hook, then `Device::new(&config, auth_key)`.
- **`OnceCell`, not `Mutex<Option<Device>>`.** Async init-once with no re-lock on the hot path;
  methods borrow `&Device` for the device's life.
- **Rust enforces Go's ordering at compile time — for free.** Methods borrow `&self`; mutating a
  field needs `&mut self`. So "set fields *before* the first method call" becomes a borrow-checker
  guarantee for the common single-owner case, stricter (and safer) than Go's runtime looseness. For
  shared use (`Arc<Server>` across tasks for concurrent listeners), fields are simply frozen at share
  time — which is exactly the intended contract.

### Lifecycle method mapping

| Go | `tsnet::Server` | Delegates to | Note |
|---|---|---|---|
| `Start() error` | `start(&self) -> Result<(), Error>` | `Device::new` (once) | Idempotent via `OnceCell`. |
| `Up(ctx) (*Status, error)` | `up(&self, Option<Duration>) -> Result<Status, Error>` | `wait_until_running` + `status` | Typed [`RegistrationError`] on failure — richer than Go's status blob. |
| `Close() error` | `close(self, Option<Duration>) -> bool` | `Device::shutdown` | Consumes `self`; `OnceCell::into_inner()` reclaims the `Device`; never-started ⇒ `true`. |
| *(implicit)* | `device(&self) -> Result<&Device, Error>` | — | Escape hatch to the full engine surface. |

---

## 4. How the pieces fit (one diagram)

```
   caller sets fields            first method call                 delegation
   ┌────────────────┐   build_config()   ┌───────────┐  Device::new  ┌──────────┐
   │ tsnet::Server  │ ─────────────────▶ │  Config   │ ────────────▶ │  Device  │
   │  hostname …    │   (§5 mapping)     │ key_state │   (§3 lazy)   │ (engine) │
   │  dir / store ──┼── §8 StateStore ──▶│  = ident  │               └────┬─────┘
   └────────────────┘                    └───────────┘                    │
        │  listen()/dial()/loopback()/listen_funnel()/listen_service() …  │
        └────────────────────────────────────────────────────────────────┘
                       thin forwarding, engine types returned
```

---

## 5. Field → `Config` mapping

Go's exported `Server` fields become `Server` fields that are copied onto a fresh `Config` in
`build_config`. Line numbers are `src/config.rs` unless noted; verdicts reconcile with the parity
matrix §2.

| Go `Server` field | `tsnet::Server` field | → `Config` field / call | Verdict | Notes |
|---|---|---|---|---|
| `Hostname string` | `hostname: Option<String>` | `requested_hostname` :47 | **PRESENT** | |
| `AuthKey string` | `auth_key: Option<String>` | `auth_key` :402 **and** the `auth_key` arg of `Device::new` | **PRESENT** | Env fallback `TS_AUTH_KEY` still honored by the engine. |
| `ControlURL string` | `control_url: Option<String>` | `control_server_url` :32 (parsed) | **PRESENT** | Bad URL ⇒ `Error::InvalidControlUrl`. `None` ⇒ engine default. |
| `Ephemeral bool` | `ephemeral: bool` | `ephemeral` :59 | **PRESENT** | **Default nuance:** Go defaults `false`; bare `Config::default()` defaults **`true`** (:657). The facade forces Go's default by always writing `config.ephemeral = self.ephemeral` (default `false`). |
| `AdvertiseTags []string` | `advertise_tags: Vec<String>` | `requested_tags` :50 | **PRESENT** | |
| `Port uint16` | `port: Option<u16>` | `wireguard_listen_port` :254 | **PRESENT** | Pin nuance tracked under `tsr-reh3`. |
| `RunWebClient bool` | `run_web_client: bool` | `run_web_client` :371 | **PARTIAL** | Pref carried, no embedded web client runs (matrix §2a). |
| `ClientID string` | `client_id: Option<String>` | `client_id` :408 | **PRESENT** | |
| `ClientSecret string` | `client_secret: Option<String>` | `client_secret` :416 | **PRESENT** | |
| `IDToken string` | `id_token: Option<String>` | `id_token` :422 | **PRESENT** | |
| `Audience string` | `audience: Option<String>` | `audience` :429 | **PRESENT** | |
| `Tun tun.Device` | `tun: Option<TunSpec>` | `use_tun(name, mtu)` :455 → `transport_mode` :265 | **PRESENT** (diff. shape) | Rust selects TUN by name/MTU, not a caller `tun.Device`. |
| `Dir string` | `dir: Option<PathBuf>` | → `key_state` :22 via key file (§8) | **PARTIAL** (identity only) | Real gap designed over `key_state`; see §8. |
| `Store ipn.StateStore` | `store: Option<Arc<dyn StateStore>>` | → `key_state` :22 (§8) | **PARTIAL** (identity only) | Pluggable store trait; see §8. |
| `Logf` / `UserLogf logger.Logf` | — (omitted) | — | **ABSENT** | No injectable logger; backend uses `tracing`. Accepting-and-dropping a closure would be dishonest, so it is left off (matrix §2a, `tsr-reh3`). |

### The escape hatch: `configure`

Go's `Server` exposes *only* the tsnet knobs. The fork's `Config` has many more (accept-routes,
exit nodes, residential-proxy exit egress, TKA, `tcp_buffer_size`, …). To stay thin *without*
becoming lossy, the facade sets only the Go-parity subset and offers one hook:

```rust
pub fn configure<F: Fn(&mut Config) + Send + Sync + 'static>(&mut self, f: F) -> &mut Self
```

It runs after the field mapping and before `Device::new`, so power users reach the full `Config`
without leaving the facade. `Server::device()` remains the deeper escape hatch to the whole engine
surface.

---

## 6. Method → `Device` mapping

Every `Server` method is a thin forward. `LocalClient`'s ~40 methods are **not** re-wrapped (that
would bloat the facade); the headline ones are folded onto `Server`, and the rest are reached through
`Server::device()` — mirroring the fork's own "`Device` *is* the in-process client" decision
(matrix §4, §5.5b).

| Go | `tsnet::Server` | Delegates to (`src/lib.rs`) | Return |
|---|---|---|---|
| `Dial(ctx, net, addr)` | `dial(net, addr)` | `dial` :610 | [`DialConn`] |
| — | `dial_tcp(addr)` | `dial_tcp` :641 | `netstack::TcpStream` |
| `Listen(net, addr)` | `listen(net, addr)` | `tcp_listen` :457 (addr parsed) | `netstack::TcpListener` |
| `ListenPacket(net, addr)` | `listen_packet(net, addr)` | `listen_packet` :697 | `netstack::UdpSocket` |
| `ListenFunnel(net, addr, opts…)` | `listen_funnel(cfg, opts)` | `listen_funnel` :1874 | `FunnelAcceptedReceiver` (§9) |
| `ListenService(name, mode)` | `listen_service(name, mode)` | `listen_service` :1940 | [`ServiceListener`] (§10) |
| `Loopback()` | `loopback()` | `loopback` :774 + facade LocalAPI server | [`Loopback`] (§11) |
| `LocalClient()` | `local_client()` | facade LocalAPI HTTP client over the loopback | [`LocalClient`] (§11) |
| `TailscaleIPs()` | `tailscale_ips()` | `tailscale_ips` :434 | `(Ipv4Addr, Option<Ipv6Addr>)` |
| `CertDomains()` | `cert_domains()` | `cert_domains` :860 | `Vec<String>` |
| `LocalClient().Status` | `status()` | `status` :1207 | [`Status`] |
| `LocalClient().Logout` | `logout()` | `logout` :1364 | `()` |
| `Sys()` / `LocalClient()` | `device()` | — | `&Device` (full surface) |

Feature-gated (mirroring the engine's own gates), included in the design but exercised only with the
matching feature: `http_client()` → `Device::http_connector` (`hyper`), `listen_ssh(...)` →
`ssh::listen_ssh` (`ssh`, a documented **superset** — matrix §5.5a), `listen_tls(...)` →
`Device::listen_tls` (`acme` for real issuance; the acceptor is ring-only), and `cert_pair(...)` →
`Device::cert_pair` (`acme`-gated — Go `LocalClient().CertPair`, the on-disk `.crt`/`.key` PEM pair).
All three validate the cert name/serve config at the facade boundary (fail-fast, before the lazy
device start) and keep the fork's typed `ts_control::CertError`, not the unified lifecycle `Error`.

---

## 7. Error mapping

Go returns one opaque `error` everywhere. The fork returns *typed* errors. The design **unifies only
the lifecycle path** and **preserves the specialized typed errors** — because that is where the type
information is actually actionable and where the engine already draws the line.

```rust
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    Device(#[from] crate::Error),             // engine/device error
    Registration(#[from] RegistrationError),  // Up / wait_until_running (permanent vs transient vs needs-login)
    InvalidControlUrl(url::ParseError),        // building Config from a bad control_url
    InvalidAddr { addr: String, source: std::net::AddrParseError },  // parsing "tcp"/":80"
    Store(std::io::Error),                     // Dir/Store persistence
    State(serde_json::Error),                  // (de)serializing the identity blob
    Logout(#[from] crate::LogoutError),
}
```

- `#[from]` conversions make delegation one-liners (`Ok(dev.status().await?)`).
- `crate::Error` is `Copy` + `std::error::Error`; `RegistrationError`, `LogoutError` are
  `thiserror` enums — all compose cleanly.
- **Specialized calls keep their engine errors** as a variant of a thin wrapper that *also* keeps a
  lazy-start (lifecycle) failure distinct — the wrapper must start the node before it can funnel/serve,
  and a startup failure is not the same thing as an access/bind refusal, so it is never misreported as
  one:
  - `listen_funnel` → [`ListenFunnelError`]: the `Funnel(`[`ts_control::FunnelError`]`)` variant is the
    engine's fail-closed access gate (`NotAllowed` / `PortNotAllowed`, plus `Cert`) verbatim; the
    `Start(`[`Error`]`)` variant carries a lazy-start failure with its real cause — never flattened to
    `FunnelError::NotAllowed` (which would read as an ACL denial for a node that simply never registered).
  - `listen_service` → [`ListenServiceError`]: the `Service(`[`ServiceError`]`)` variant keeps the
    engine error (whose `UntaggedHost` variant **is** Go's `ErrUntaggedServiceHost`, §10); the
    `Start(`[`Error`]`)` variant carries a lazy-start failure — never flattened to `ServiceError::Listen`
    (a listener-bind failure).
- `#[non_exhaustive]` so new variants (e.g. when `Logf` or prefs-persistence land) are not a breaking
  change.
- `impl std::error::Error` means a caller who wants Go's "just an error" can still
  `Box<dyn Error>` / `?` it uniformly.

Rationale for *not* flattening everything into one enum: Go's single `error` loses the
`NotAllowed`-vs-`PortNotAllowed`-vs-`UntaggedHost` distinction that the fork worked to make typed and
fail-closed. Collapsing it in the facade would be a *regression in expressiveness* dressed as parity.

---

## 8. The `Dir` / `Store` state-root — the real gap, designed over `key_state`

The parity matrix flags this as the one **genuinely unbuilt** headline gap (§5.3): Go's `Dir`
resolves to a `FileStore` at `Dir/tailscaled.state` and persists the *full* node state (prefs +
netmap + machine key); the fork persists **only node identity keys**, via a JSON key file loaded once
at construction.

### What actually persists (verified)

`Config::key_state: PersistState` (`config.rs:22`) is the sole durable state.
`PersistState::default()` (`ts_keys/src/keystate.rs:96`) **mints fresh keys client-side** —
`MachinePrivateKey::random()`, `NodePrivateKey::random()`, `NetworkLockPrivateKey::random()` — so
identity is created at config time, not during registration. Persistence is therefore a simple
**load-or-init**: read the blob if present, else generate once and write. `Config::default_with_key_file`
(`config.rs:438`) already does exactly this for a file path.

### Design

```rust
pub trait StateStore: Send + Sync {
    fn read_state(&self, id: &str) -> std::io::Result<Option<Vec<u8>>>;
    fn write_state(&self, id: &str, value: &[u8]) -> std::io::Result<()>;
}
pub struct FileStore { /* dir/tailscale-rs.state */ }   // Go store.FileStore
#[derive(Default)] pub struct MemStore { /* HashMap */ } // Go mem.Store
pub const STATE_KEY: &str = "_tailscale-rs/persist";
```

Resolution order in `build_config` (honest and minimal):

1. **`store` set** → round-trip `PersistState` as JSON under `STATE_KEY` (`serde_json`). Absent ⇒
   mint (`PersistState::default()`) and write back. Enables DB / secret-manager / custom backends.
2. **`dir` set (no `store`)** → reuse `Config::default_with_key_file(dir/STATE_FILE)` — the engine's
   *own* key-file format and migration path (`KeyFileOld`→`KeyFileNew`), zero new serialization. This
   is the standard on-disk identity.
3. **neither** → `Config::default()` ⇒ an ephemeral in-memory identity (fresh every run), loudly
   documented. (A future refinement can mirror Go's default of `os.UserConfigDir()/tsnet-<binary>`;
   deferred to avoid adding a directory-resolution dependency now.)

The trait deliberately uses the general KV shape (not a `read_persist()/write_persist()` pair) so it
stays forward-compatible: when the engine grows prefs/netmap persistence, additional keys slot in
with **no caller change**. Node-key rotation (`Config::rotate_node_key`, `config.rs:517`) leaves
re-serialization to the owner; the facade's write-back point is construction, and a rotation is
modeled as "mutate identity → re-create the `Server`" (the `OnceCell` is single-shot by design).

### Honest scope statement (must ship in the rustdoc)

> A `tsnet` `Dir`/`Store` here persists node **identity keys** — the state that actually governs node
> continuity (a stable identity across restarts instead of re-registering every boot). Prefs and
> netmap persistence remain an **engine-level gap** (parity §5.3); the `StateStore` trait is shaped to
> absorb them later without an API break.

---

## 9. Funnel: first-class `FunnelOption` / `FunnelOnly` / `FunnelTLSConfig`

Go models funnel knobs as a variadic `...FunnelOption` with two constructors, both of which exist in
current Go (verified against the pinned commit):

```go
func FunnelOnly() FunnelOption                 // reject tailnet-internal conns
func FunnelTLSConfig(conf *tls.Config) FunnelOption  // bring-your-own TLS
```

The Rust-idiomatic collapse of variadic options is one options value with Go-named constructors:

```rust
#[derive(Default)]
pub struct FunnelOptions {
    pub funnel_only: bool,             // Go FunnelOnly()
    pub tls: Option<crate::TlsAcceptor>, // Go FunnelTLSConfig(conf) — see gap below
}
impl FunnelOptions {
    pub fn funnel_only() -> Self { /* funnel_only = true */ }
    pub fn with_tls(self, acceptor: crate::TlsAcceptor) -> Self { /* … */ }
}
impl From<FunnelOptions> for ts_control::FunnelOptions { /* funnel_only passthrough */ }
```

- **`funnel_only`** maps straight to the engine's existing `ts_control::FunnelOptions { funnel_only }`
  (`ts_control/src/serve.rs:287`).
- **`FunnelTLSConfig` is a designed-over engine gap.** The engine's `Device::listen_funnel`
  (`lib.rs:1874`) always builds its own acceptor from the node's `*.ts.net` cert and currently
  ignores `opts` for TLS. The facade therefore accepts `tls` for **surface stability**, `warn!`s if
  set, and documents the exact engine change needed to honor it (thread the acceptor into
  `FunnelManager::new`). This matches how the engine already treats `funnel_only` as partly a no-op on
  the relay-fed ingress path — the facade is faithful about it rather than silently dropping it.
- **Shape delta to document:** Go's `ListenFunnel(net, addr, opts…)` returns a `net.Listener`; the
  fork returns a [`FunnelAcceptedReceiver`] and takes a [`ServeConfig`] (MagicDNS name + port +
  target) instead of a bare `addr`. The facade forwards the fork's shape directly. A future
  convenience overload `listen_funnel_addr(net, addr, opts)` can synthesize the `ServeConfig` from
  `cert_domains()` + `ServeTarget::Accept`; kept out of the thin core to avoid guessing the target.

---

## 10. Service: first-class `ServiceMode` / `ServiceListener` / `ErrUntaggedServiceHost`

`ListenService` is where current Go has moved **ahead** of the fork, so the design both re-exports the
existing types and records the deltas precisely.

### `ServiceMode`

- **Fork (`ts_control::ServiceMode`, `service.rs:29`):** `enum { Tcp { port }, Http { port } }` —
  re-exported at the crate root already, so the facade re-exports it unchanged (thin).
- **Current Go:** `ServiceMode` is now an **interface** with richer structs —
  `ServiceModeTCP { Port, TerminateTLS, PROXYProtocolVersion }` and
  `ServiceModeHTTP { Port, HTTPS, AcceptAppCaps, PROXYProtocol }`. The fork covers only `Port`.
  `TerminateTLS`, `HTTPS`, `PROXYProtocol*`, and `AcceptAppCaps` are **engine-level gaps** documented
  here; the facade does not invent fields the engine can't honor. When the engine grows them, the
  enum variants gain fields and the facade re-export follows for free.

### `ServiceListener` (new facade type)

Current Go's `ListenService` returns `*ServiceListener` — a `net.Listener` **plus** an `FQDN`. The
fork's `Device::listen_service` returns a bare `netstack::TcpListener`. The facade adds the missing
newtype (thin — it wraps the returned listener and one resolved string):

```rust
pub struct ServiceListener { inner: netstack::TcpListener, fqdn: String }
impl ServiceListener { pub fn fqdn(&self) -> &str; pub fn into_inner(self) -> netstack::TcpListener; }
impl std::ops::Deref for ServiceListener { type Target = netstack::TcpListener; /* .accept() */ }
```

`fqdn` is filled from `Device::self_node().await?.fqdn(false)` (`ts_control/src/node.rs:248`). `Deref`
means callers keep `.accept()`-ing the overlay listener transparently.

### `ErrUntaggedServiceHost`

Go is a sentinel `var ErrUntaggedServiceHost = errors.New("service hosts must be tagged nodes")`. The
fork already models it as a **typed variant** — `ServiceError::UntaggedHost` (`service.rs:62`),
enforced in `resolve_service_listen` (`service.rs:115`). The facade preserves that typed variant
(better than a sentinel: `matches!(e, ServiceError::UntaggedHost)`), and its rustdoc names the Go
equivalence so a Go reader finds it.

---

## 11. Loopback — full Go parity: two credentials + a live LocalAPI HTTP server

`tsnet::Loopback { address, proxy_cred, local_api_address, local_api_cred }` implements the **full**
Go `Loopback() (addr, proxyCred, localAPICred, err)` surface: **both** credentials, plus an
in-process **LocalAPI HTTP server** that is actually running and serving (Go `localapi.Handler` on
the loopback). This closes the gap the parity matrix flagged (matrix §5.1, `tsr-ask7`).

- **SOCKS5 half** — the engine's own [`Device::loopback`](../src/lib.rs) (`lib.rs:774`) is unchanged:
  it binds `127.0.0.1:0` and serves SOCKS5 (RFC 1928/1929) gated by `proxy_cred` (username `tsnet`).
- **LocalAPI half** — `Server::loopback` layers a facade-owned HTTP/1.1 server on a **second**
  `127.0.0.1:0` listener, gated by a **separate** `local_api_cred` (HTTP Basic-auth password; any
  username, matching Go). It serves `GET /localapi/v0/status` backed by `Device::status`, returning
  its JSON. The server is hand-rolled over `tokio` TCP — the crate's `hyper` is HTTP/2-**client**-only
  (`Cargo.toml`), so there is no ready-made HTTP server to reuse; this mirrors how the SOCKS5 half
  hand-rolls its own protocol in `src/loopback.rs`. The `tsnet` feature adds one new *optional,
  direct* dependency edge — `base64` (Basic-auth decode; `tsnet = ["dep:base64"]`) — while `rand`
  (the credential) is already a direct dependency. `base64` was already in the workspace graph, so no
  new crate is compiled; it is a new direct edge for `tailscale`, not literally "zero new deps". No
  TLS, so the **ring-only** crypto invariant is untouched.
- **`Server::local_client()`** (Go `LocalClient()`) returns a dependency-free `LocalClient` that
  round-trips authenticated `GET`s through that server (`/localapi/v0/status`), and
  **`Server::http_client()`** (Go `HTTPClient()`, `#[cfg(feature = "hyper")]`) returns a `hyper_util`
  client over [`Device::http_connector`](../src/http.rs).

### The one honest delta (surfaced, not faked)

Go muxes SOCKS5 + LocalAPI on a **single** listener (first-byte demux). This fork runs **two**
`127.0.0.1` listeners — one per function — rather than re-implementing (or demuxing over) the proven
engine SOCKS5 path. The observable contract is identical: a proxy gated by `proxy_cred`, a LocalAPI
gated by `local_api_cred`. Both `SocketAddr`s are returned. This is documented at the [`Loopback`]
type, per the project's "surface the delta" rule.

### Lifecycle

Like Go's `s.loopbackListener`, both listeners live for the `Server`'s lifetime and are torn down by
`Server::close` (which aborts both accept loops and gracefully shuts the device down). `loopback()`
is **idempotent** (cached in a `OnceCell`), returning the same addresses + credentials each call —
also matching Go's `if s.loopbackListener == nil` guard. The device is held as `Arc<Device>` so the
LocalAPI server can carry a `Weak<Device>` without blocking `close` from reclaiming the device by
value for a graceful shutdown.

---

## 12. Feature & module wiring (verified)

```toml
# Cargo.toml [features]
tsnet = ["dep:base64"]   # one new optional *direct* dep edge: base64 (loopback LocalAPI Basic-auth),
                         # already in the workspace graph (no new crate compiled). Otherwise reuses
                         # serde_json / tokio / thiserror / rand already in [dependencies].
```

```rust
// src/lib.rs
#[cfg(feature = "tsnet")]
pub mod tsnet;
```

Because it is a gated module in the root crate, it compiles against `Device`/`Config` with no
version boundary. If a standalone `tailscale-tsnet` crate is ever wanted, it becomes a trivial
re-export shell over this module — deferred until the shape has settled in-tree, per the task's "NOT
a new published crate initially".

---

## 13. Usage — before / after

**Go:**
```go
srv := &tsnet.Server{Hostname: "web", AuthKey: key, Dir: "/var/lib/web"}
defer srv.Close()
ln, _ := srv.Listen("tcp", ":80")
```

**Facade (`tsnet::Server`):**
```rust
use tailscale::tsnet::Server;

let mut srv = Server::new();                 // Go's `&tsnet.Server{}`
srv.hostname = Some("web".into());           // set public fields (Go field assignment)
srv.auth_key = Some(key);
srv.dir = Some("/var/lib/web".into());
let ln = srv.listen("tcp", ":80").await?;    // builds Config, Device::new, tcp_listen — once
// … srv.close(None).await;
```

> **Rust nuance (documented, not incidental).** `Server` carries two **private** fields — the lazy
> `OnceCell<Device>` and the optional `configure` hook — so the Go-style *struct-literal*
> `Server { hostname: …, ..Default::default() }` is **not** available to external callers (Rust
> requires every field visible for literal syntax). The entry point is `Server::new()` followed by
> **per-field assignment** on the public fields, which is unaffected by the private fields and reads
> the same as Go's `s := &tsnet.Server{}; s.Hostname = …`. This is a deliberate trade: the private
> lazy-start state is what makes methods take `&self` (enabling `Arc<Server>` concurrent use), and it
> is what turns "set fields before first call" into a borrow-checker guarantee (§3).

**Reaching a fork superset without leaving the facade:**
```rust
let mut srv = Server::new();
srv.hostname = Some("exit".into());
srv.configure(|c| { c.advertise_exit_node = true; c.accept_routes = true; });
let status = srv.up(Some(Duration::from_secs(30))).await?;
```

**Native `Device` remains fully available** (the facade is additive, not a replacement).

---

## 14. Verification evidence

All commands run on the Rust 1.95.0 toolchain the repo pins (loopback/LocalAPI work on
`feat/tsnet-loopback`, based on `feat/tsnet-facade`).

| Check | Command | Result |
|---|---|---|
| Strict lint (lib + tests + examples) | `cargo clippy -p geiserx_tailscale --features tsnet --all-targets -- -D warnings` | ✅ clean (0 warnings) |
| Logic tests | `cargo test -p geiserx_tailscale --features tsnet tsnet::` | ✅ `33 passed; 0 failed` |
| Facade builds | `cargo build -p geiserx_tailscale --features tsnet` | ✅ `Finished` |
| `http_client` path (hyper) | `cargo clippy -p geiserx_tailscale --features tsnet,hyper --all-targets -- -D warnings` | ✅ clean (0 warnings) |

`src/tsnet.rs` implements the load-bearing shape end-to-end against the real engine — `Server` +
field→`Config` mapping + lazy `OnceCell` start + `Error` + `StateStore`/`FileStore`/`MemStore` +
`FunnelOptions` + `ServiceListener`, plus the **full loopback surface** (§11): `Loopback` (both
credentials), the in-process LocalAPI HTTP server, `LocalClient`, and the `hyper`-gated
`http_client`.

The 33 tests are hermetic (no live control server): address parsing, `MemStore`/`FileStore`/`Dir`
identity round-trips, `FunnelOptions` → engine mapping, the Go-default (`ephemeral == false`), the
`build_config` field mapping, and — new for the loopback work — the LocalAPI HTTP framing/auth as
pure functions (`parse_head`, `basic_auth_password` (username-ignored), constant-time `cred_ok`,
`parse_response`), the `status_json` serializer, and two **end-to-end** tests that drive the real
in-process LocalAPI server over a `127.0.0.1` socket with a mock status backend (200 with the right
cred, 401 without / wrong cred, 404 for unknown paths) and round-trip a `LocalClient` through it. A
`Server: Send + Sync` compile-time assertion guards `Arc<Server>` concurrent use.

---

## 15. Open follow-ups (engine work the facade is shaped to absorb)

Each is documented at its call site; none blocks the facade shape.

| Item | Where | Parity ref |
|---|---|---|
| Thread `FunnelTLSConfig` acceptor into `Device::listen_funnel` | `FunnelOptions::tls` warns until then | §9 |
| `ServiceMode` `TerminateTLS` / `HTTPS` / `PROXYProtocol*` / `AcceptAppCaps` | enum gains fields; re-export follows | §10, matrix §3 |
| Prefs + netmap persistence (full Go `Store` semantics) | `StateStore` KV already shaped for it | §8, matrix §5.3 |
| ~~`localAPICred` + in-process LocalAPI HTTP on loopback~~ **(done, §11)** — both creds + a live LocalAPI server now ship; only the single-listener mux remains a delta | resolved | §11, `tsr-ask7` |
| `Logf` / `UserLogf` injectable loggers, `LogtailWriter` | fields omitted rather than faked | matrix §5.2, `tsr-reh3` |
| `listen_funnel_addr(net, addr, opts)` convenience overload | synthesize `ServeConfig` from `cert_domains()` | §9 |

---

## 16. Summary

`tsnet::Server` gives Go users the exact shape they expect — settable fields, lazy start, `Up`/`Close`,
`Listen`/`Dial`/`ListenFunnel`/`ListenService`/`Loopback` — as a **thin, feature-gated, zero-new-dep**
wrapper that forwards to the existing `Device`/`Config` engine. It keeps Rust's typed returns and
fail-closed typed errors, turns Go's "set fields before first call" rule into a compile-time
guarantee, designs the one real gap (`Dir`/`Store`) honestly over `key_state`, and gives first-class
treatment to the Funnel/Service package-level types the parity matrix under-covers — surfacing, not
faking, the deltas that need engine work.

<!-- Design authored with reference to docs/TSNET_PARITY.md; reference skeleton in src/tsnet.rs. -->

[`Device`]: ../src/lib.rs
[`Config`]: ../src/config.rs
[`DialConn`]: ../src/dial.rs
[`netstack::TcpListener`]: ../src/lib.rs
[`SocketAddr`]: https://doc.rust-lang.org/std/net/enum.SocketAddr.html
[`RegistrationError`]: ../ts_runtime/src/device_state.rs
[`Status`]: ../ts_runtime/src/lib.rs
[`ServiceError`]: ../ts_control/src/service.rs
[`ts_control::FunnelError`]: ../ts_control/src/serve.rs
[`FunnelAcceptedReceiver`]: ../ts_runtime/src/funnel.rs
[`ServeConfig`]: ../ts_control/src/serve.rs
[`ServiceListener`]: ../src/tsnet.rs
[`Loopback`]: ../src/tsnet.rs
