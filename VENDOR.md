# Vendored fork — `neutral-tsnet-rs`

This repo is a **vendored fork** of [`tailscale/tailscale-rs`](https://github.com/tailscale/tailscale-rs),
the official pure-Rust (no Go, no cgo) Tailscale node implementation. It exists to
back the `UpstreamStrategy::Tsnet` egress path in `this project` (the exit node /
`the exit node`), letting the proxy join a a self-hosted control plane tailnet and dial the
residential exit node in-process — unifying the Mac (LaunchAgent) and K8s
(sidecar) topologies onto one Rust binary.

See `this project/docs/research/tsnet-rust-port.md` for the full rationale.

## Provenance

- **Upstream:** https://github.com/tailscale/tailscale-rs (BSD-3-Clause)
- **Pinned at:** `29d87ee17e734c8d7c2dc5db60f4c67df566aa30` (2026-05-28)
- **Upstream remote** is preserved as `upstream`; this fork's `origin` is
  `GeiserX/neutral-tsnet-rs`.

## Why a fork, not a crates.io dependency

1. **Pin a known-good SHA.** Upstream is ~2 months old, fast-moving (58 open
   issues), and self-labels as *"unstable and insecure … unaudited cryptography"*
   (gated behind `TS_RS_EXPERIMENT=this_is_unstable_software`). We pin and rebase
   deliberately, never auto-bump.
2. **Carry anti-leak patches.** `this project`'s product invariant is that the
   real client/a cloud VPS IP never leaks. The fail-closed gating (gate on
   `Up()`-equivalent not `Start()`; no host-route fallback; IPv6 off; DERP/WG
   failure = drop; pin the exit node node key) may require patches the crate does not offer.

## Safety posture

"Unaudited crypto" is an acceptable risk **only because we control both ends** —
our own a self-hosted control plane control server and our own the exit node exit — so the handshake is never
exposed to a hostile control plane, and we pin a self-hosted control plane's capability version to
freeze the protocol. This is **not** a general-purpose endorsement of the crate
for production; it is scoped to our closed, both-ends-owned deployment.

## Updating from upstream

```sh
git fetch upstream
git log --oneline HEAD..upstream/main   # review every change before taking it
git rebase upstream/main                # deliberate, reviewed; then re-run cargo audit
```
