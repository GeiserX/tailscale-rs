<p align="center">
  <img src="https://raw.githubusercontent.com/GeiserX/tailscale-rs/main/docs/images/banner.svg" alt="tailscale-rs" width="100%">
</p>

<h1 align="center">tailscale-rs</h1>

<p align="center">
  <a href="https://crates.io/crates/geiserx_tailscale"><img src="https://img.shields.io/crates/v/geiserx_tailscale" alt="crates.io"></a>
  <a href="https://github.com/GeiserX/tailscale-rs/actions/workflows/ci.yml"><img src="https://github.com/GeiserX/tailscale-rs/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/GeiserX/tailscale-rs" alt="License"></a>
  <a href="Cargo.toml"><img src="https://img.shields.io/badge/MSRV-1.94.1-orange.svg" alt="MSRV 1.94.1"></a>
  <a href="https://github.com/tailscale/tailscale-rs"><img src="https://img.shields.io/badge/fork%20of-tailscale%2Ftailscale--rs-purple" alt="fork of tailscale/tailscale-rs"></a>
</p>

A fork of [tailscale/tailscale-rs](https://github.com/tailscale/tailscale-rs).

`tailscale-rs` is a work-in-progress Tailscale library written in Rust, with language bindings to
C, Elixir, and Python.

> [!NOTE]
> This project is **not associated with Tailscale Inc.** — it is an independent, unofficial fork.
> See [Legal](#legal).

> [!CAUTION]
> This software is unstable and insecure.
>
> I welcome enthusiasm and interest, but please **do not** build production software using these
> libraries or rely on it for data privacy until I've had a chance to batten down some hatches
> and complete a third-party audit.
>
> See [Caveats](https://geiserx.github.io/tailscale-rs/caveats/) for more details.

## Features

- TCP and UDP sockets on the tailnet from an in-process WireGuard data plane.
- Direct peer-to-peer connections through NAT traversal (STUN, Disco, `CallMeMaybe`), falling back to DERP relays.
- MagicDNS and split DNS, fail-closed by default.
- Using subnet routers and exit nodes (opt-in), with the exit node changeable at runtime.
- Tailscale Serve handlers: `Proxy`, `Text`, `TcpForward`, `Path` and `Redirect`.
- Tailnet Lock peer signature enforcement (partial, see [SECURITY.md](SECURITY.md)).
- An optional Go-style `tsnet::Server` facade.
- C, Elixir and Python bindings. Talks to the Go client, `tsnet` and `libtailscale`.

## Quick start

Inside a binary crate, with Rust 1.94.1 or newer:

```bash
cargo add geiserx_tailscale --rename tailscale
TS_RS_EXPERIMENT=this_is_unstable_software cargo run
```

The crate is published as `geiserx_tailscale` and imported as `tailscale`, and every program linked against it needs `TS_RS_EXPERIMENT` set as above. A UDP client sample and the `tsnet` facade are in [Getting started](https://geiserx.github.io/tailscale-rs/getting-started/), and more in [`examples/`](examples/README.md).

## Documentation

The documentation is at [geiserx.github.io/tailscale-rs](https://geiserx.github.io/tailscale-rs/), and the API reference on [docs.rs](https://docs.rs/geiserx_tailscale).

- [Getting started](https://geiserx.github.io/tailscale-rs/getting-started/): dependency setup, a code sample, the `tsnet` facade and its Go mapping
- [Caveats, versioning and platform support](https://geiserx.github.io/tailscale-rs/caveats/), including MSRV and edition
- [How it works](https://geiserx.github.io/tailscale-rs/how-it-works/): control plane, WireGuard data plane and DERP
- [Status](https://geiserx.github.io/tailscale-rs/status/): what is implemented, coming soon and unsupported
- Language bindings: [C](ts_ffi/README.md), [Elixir](ts_elixir/README.md), [Python](ts_python/README.md)
- [ARCHITECTURE.md](ARCHITECTURE.md), [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), [CHANGELOG.md](CHANGELOG.md)
- Design notes: [tsnet facade](docs/TSNET_FACADE_DESIGN.md), [tsnet parity](docs/TSNET_PARITY.md), [parity roadmap](docs/PARITY_ROADMAP.md), [cryptography](docs/CRYPTOGRAPHY.md), [releasing](docs/RELEASING.md)

## Legal

**This project is not associated with Tailscale Inc.** It is an independent, unofficial fork.
"Tailscale" is a trademark of Tailscale Inc.; it is used here only to describe interoperability and
the upstream project this is forked from.

WireGuard is a registered trademark of Jason A. Donenfeld.

## License

[BSD-3-Clause](LICENSE).
