# Live-settable prefs vs. rebuild-required

> Which `Device` knobs can be changed on a **running** device, and which require tearing the device
> down and constructing a new one with an updated `Config`. This is the contract a daemon's
> `set`-style command (e.g. `tailscaled-rs`'s `tnet set`) uses to decide its **live fast-path** vs. a
> full rebuild. (Answers daemon ask `tsr-89s`.)

The pure-Rust engine (`tailscale`) exposes a small, deliberate set of **runtime mutators** on a live
`Device`. Anything not in that set is configured at construction (`Device::new(&Config, …)`); changing
it means building a new `Device`.

## Live-settable on a running `Device` (no rebuild)

| Pref / action | Method | How it applies live |
|---------------|--------|---------------------|
| **Exit node** (select / clear) | `Device::set_exit_node(Option<ExitNodeSelector>)` | Updates a `watch` cell every reader borrows, then asks the peer tracker to `RepublishState` — the route updater (outbound routes + DoH delegation) and the source filter (inbound validation) recompute against the current peer set immediately, without waiting for the next netmap poll. (`src/lib.rs` → `ts_runtime::Env::set_exit_node` → `peer_tracker::RepublishState`.) |
| **Serve config** (ports / TLS / Funnel targets) | `Device::set_serve_config(ServeState)` | Validates, then builds each TLS-terminating port's acceptor up-front (ACME-aware, fail-closed — no plaintext downgrade if a cert can't be issued) and (re)binds the serve listeners live. `get_serve_config()` reads the current state. |
| **Logout / deregister** | `Device::logout()` | Re-registers with a past expiry; the device stays up but transitions state. Not a pref mutation per se, but a live state change (no rebuild). |

State and identity that update live **from control** (not via a setter — they track the netmap
stream): the self address, peer set, DNS config, packet filter, SSH policy, DERP map, and TKA status
all refresh as `MapResponse`s arrive. Read them via `status()`, `self_node()`, `whois()`,
`peer_by_*()`, `ssh_policy()`, `tka_status()`, `watch_netmap()`, `watch_state()`.

## Rebuild-required (set at `Device::new`, not mutable on a live device)

These are fixed for the lifetime of a `Device`; to change one, construct a new `Device` with an
updated `Config`:

- **Transport mode** — `TransportMode::Netstack` vs `Tun(TunConfig{ name, mtu })` (`Config::use_tun`).
  The data path (netstack vs kernel TUN) is wired at startup.
- **Auth key** / control server URL / hostname / advertised tags (`Config` fields consumed during
  registration).
- **Exit-egress proxy** — `Config::exit_proxy` (`ExitProxyConfig`) and `forward_exit_egress`. The
  forwarder's dialer choice is fixed at construction (fail-closed anti-leak chokepoint).
- **`enable_ipv6`**, **`tcp_buffer_size`**, advertised routes / exit-node advertisement, and the other
  `Config`/`ForwarderConfig` transport knobs.
- **Persistent-keepalive interval** (`PeerConfig::persistent_keepalive_interval`) — per-peer, applied
  when the peer config is built.

## Guidance for a `set` command

1. **Fast-path** the two live mutators: route an `exit_node` change to `set_exit_node` and a serve
   change to `set_serve_config` — no `up`/`down` cycle.
2. For everything else, **preflight the rebuilt `Config` before tearing down the live device** (build
   the new config, validate it, only then drop-and-recreate) so a bad value doesn't leave the node
   down. (`tailscaled-rs` already does this.)
3. This list grows as the engine adds runtime mutators. If your `set` needs another pref live, file an
   engine ask — adding a setter is cheaper than you'd think when the underlying state is already a
   `watch` cell or actor-held (as `exit_node` was).

*Mirrors Go `tsnet`/`LocalClient`'s split: `EditPrefs` mutates a running backend for the live-settable
prefs; structural transport/identity changes restart the backend.*
