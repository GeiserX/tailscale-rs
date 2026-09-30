# Getting started

The following instructions are for Rust! For other languages, see the language-specific README:

- [C](https://github.com/GeiserX/tailscale-rs/blob/main/ts_ffi/README.md)
- [Elixir](https://github.com/GeiserX/tailscale-rs/blob/main/ts_elixir/README.md)
- [Python](https://github.com/GeiserX/tailscale-rs/blob/main/ts_python/README.md)

Add the crate with `cargo add geiserx_tailscale --rename tailscale`, which writes the current
version into your `Cargo.toml`. The line it adds looks like this:

<!-- x-release-please-start-version -->

```toml
[dependencies]
# Published as `geiserx_tailscale`; imported as `tailscale`.
tailscale = { package = "geiserx_tailscale", version = "0.57.3" }
```

<!-- x-release-please-end -->

> Or depend on the latest from git:
>
> ```toml
> [dependencies]
> tailscale = { package = "geiserx_tailscale", git = "https://github.com/GeiserX/tailscale-rs" }
> ```

Either way, you import it as `tailscale` (e.g. `use tailscale::Device;`) — the crate name on
crates.io is `geiserx_tailscale`, but the library name is `tailscale`.

Examples of using the `tailscale` crate can be found in [`examples/`](https://github.com/GeiserX/tailscale-rs/blob/main/examples/README.md).

For instructions on how to run tests, lints, etc., see [CONTRIBUTING.md](https://github.com/GeiserX/tailscale-rs/blob/main/CONTRIBUTING.md). For the high-level architecture and
repository layout, see [ARCHITECTURE.md](https://github.com/GeiserX/tailscale-rs/blob/main/ARCHITECTURE.md).

## Code sample

A simple UDP client that periodically sends messages to a tailnet peer at `100.64.0.1:5678`:

```rust
use std::{
    time::Duration,
    net::Ipv4Addr,
    error::Error,
};
use tailscale::{Config, Device};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Open a new connection to tailscale
    let dev = Device::new(
        &Config::default_with_key_file("tsrs_keys.json").await?,
        Some("YOUR_AUTH_KEY_HERE".to_owned()),
    ).await?;

    // Bind a UDP socket on this node's tailnet IP, port 1234
    let sock = dev.udp_bind((dev.ipv4().await?, 1234).into()).await?;

    // Send a packet containing "ping" to 100.64.0.1:5678 once per second
    loop {
        sock.send_to((Ipv4Addr::new(100, 64, 0, 1), 5678).into(), b"ping").await?;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
```

## tsnet facade (Go-idiomatic `Server`)

If you're coming from Go's [`tsnet`](https://pkg.go.dev/tailscale.com/tsnet), the optional `tsnet`
feature adds a `tsnet::Server` facade with the shape you already know — settable fields, a lazy
`Start` on the first method call, and `Up`/`Listen`/`Dial`/`Loopback`/`ListenFunnel`/`ListenService`/
`Close`. It's a **thin ergonomics layer** over the same `Device`/`Config` engine — no new crate, same
typed returns — so you get Go's lifecycle *shape* without giving up Rust's typed values.

<!-- x-release-please-start-version -->

```toml
[dependencies]
tailscale = { package = "geiserx_tailscale", version = "0.57.3", features = ["tsnet"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

<!-- x-release-please-end -->

```rust
use tailscale::tsnet::Server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set fields where Go writes struct fields...
    let mut srv = Server::new();
    srv.hostname = Some("web".into());
    srv.auth_key = Some("YOUR_AUTH_KEY_HERE".into());
    srv.dir = Some("web_state".into());

    // ...then call a method: the wrapped Device is built and started lazily here.
    let listener = srv.listen("tcp", ":80").await?;
    loop {
        let conn = listener.accept().await?;
        // ...serve conn... (see the tsnet_echo example for a full echo server)
        drop(conn);
    }
}
```

The equivalent Go:

```go
srv := &tsnet.Server{Hostname: "web", AuthKey: key, Dir: "web_state"}
defer srv.Close()
ln, _ := srv.Listen("tcp", ":80")
```

See the runnable [`tsnet_echo` example](https://github.com/GeiserX/tailscale-rs/tree/main/examples/tsnet_echo) — the [`tcp_echo`](https://github.com/GeiserX/tailscale-rs/tree/main/examples/tcp_echo)
server rewritten against this facade — and the crate's `tsnet` module docs.

### Go `tsnet.Server` → `tsnet::Server` mapping

| Go `tsnet.Server` | `tsnet::Server` | Notes |
|---|---|---|
| struct fields (`Hostname`, `AuthKey`, `ControlURL`, `Ephemeral`, `AdvertiseTags`, `Port`, `Dir`, `Store`, `Tun`, …) | public fields on `Server` | Set before the first method call. |
| `Start()` / `Up(ctx)` | `start()` / `up(timeout)` | Lazy start; `up` waits until `Running`. |
| `Dial(ctx, net, addr)` | `dial(net, addr)` | Returns the typed `DialConn` (`dial_tcp`/`dial_udp` for the stream/socket directly). |
| `Listen(net, addr)` | `listen(net, addr)` | Returns the overlay `netstack::TcpListener`. |
| `ListenPacket(net, addr)` | `listen_packet(net, addr)` | Returns the overlay `netstack::UdpSocket`. |
| `ListenFunnel(...)` / `ListenService(name, mode)` | `listen_funnel(...)` / `listen_service(name, mode)` | Keep the fork-typed `FunnelError` / `ServiceError`. |
| `Loopback()` / `LocalClient()` | `loopback()` / `local_client()` | SOCKS5 proxy + in-process LocalAPI HTTP server. |
| `HTTPClient()` | `http_client()` | Requires the `hyper` feature. |
| `TailscaleIPs()` / `CertDomains()` | `tailscale_ips()` / `cert_domains()` | |
| `Close()` | `close(timeout)` | Consumes the server; reports whether it shut down cleanly in time. |

For fork capabilities beyond Go `tsnet` parity (accept-routes, exit nodes, residential-proxy exit
egress, …) reach the full `Config` via `Server::configure`, or drop to the whole engine surface with
`Server::device`. The complete field/method mapping (with parity verdicts) and the design rationale
live in [docs/TSNET_FACADE_DESIGN.md](https://github.com/GeiserX/tailscale-rs/blob/main/docs/TSNET_FACADE_DESIGN.md).

