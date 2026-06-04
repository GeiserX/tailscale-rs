# AGENTS.md

- This project is written in Rust.
- Follow the guidelines in CONTRIBUTING.md.
- Use GitHub markdown for docs, summaries of your work, etc.
- Commits must be signed off by the user in the form `Signed-off-by: "COMMITTER" <COMMITTER_EMAIL>`.
- When submitting a PR or filing an issue, include the text `Created using AGENT_NAME` where AGENT_NAME is your name.

## Proxy egress for exit nodes (product capability, beyond strict tsnet parity)

This fork carries one capability Go `tsnet` does not: an exit node can egress the traffic it
forwards through an **upstream proxy** instead of out its own origin IP. We built this for our
product so a cloud exit node (e.g. a cloud VPS) can route a peer's internet-bound traffic
through a **residential proxy** — the cloud host's real IP never appears upstream.

- **Provider:** a residential proxy provider is the only currently-supported residential proxy. **a residential proxy provider and
  a residential proxy provider are sunset** — do not reintroduce them.
- **Where it lives:** the `RealDialer` trait in `ts_forwarder` is the single anti-leak
  chokepoint. `ProxyExitDialer` implements SOCKS5 (RFC 1928/1929) and HTTP `CONNECT`
  hand-rolled with **zero new dependencies** (keeps the `ring`-only, musl-clean egress path
  intact — never pull in `aws-lc-rs`/`openssl`/native-TLS on this path).
- **Config chain:** `tailscale::Config::exit_proxy` (`ExitProxyConfig` / `ExitProxyScheme`) →
  `ts_control::Config` (transport-only; `ts_control` never reads it and must not depend on
  `ts_forwarder`) → `ForwarderConfig::from_control_config` (converted to
  `ts_forwarder::ProxyConfig` at the `ts_runtime` boundary) → `forwarder_actor::dialer_choice`.
- **Fail-closed is sacred.** The proxy dialer is only selected when `forward_exit_egress` is
  set AND an `exit_proxy` is configured. Any proxy connect/handshake failure **drops the flow**
  — it never falls back to a direct host-IP dial. UDP over proxy fails closed. An SSRF guard
  rejects forbidden exit destinations (loopback / link-local / unspecified). Proxy credentials
  are redacted from `Debug`. The default `DirectDialer` structurally refuses exit egress, so the
  real origin IP can never leak by accident.

## Exit-node memory: `tcp_buffer_size` at scale

The userspace netstack has **no TCP window auto-tuning**, so `Config::tcp_buffer_size` (default
**256 KiB per direction**, raised from 16 KiB in v0.5.3 to stop a single flow being throttled to
~1.6 Mbps at 80 ms RTT) is allocated **eagerly per socket** — one rx buffer and one tx buffer, so
~512 KiB per TCP socket. The **forwarder** netstack opens one socket per forwarded exit/subnet
flow, so concurrent-flow count multiplies this directly: a host carrying ~1,000 simultaneous
forwarded flows pins ~512 MB in TCP buffers alone — a real fraction of a 4 GB a cloud VPS CAX11 exit
node, the fork's primary deployment. On a small box that forwards many concurrent flows, set
`Config::tcp_buffer_size` lower (e.g. `Some(64 * 1024)`) and accept the per-flow throughput cap as
the trade. `None` keeps the throughput-optimized 256 KiB default. Both the application and
forwarder netstacks share this one value (see `ts_runtime::netstack_config_from`).
