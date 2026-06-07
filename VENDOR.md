# Fork of `tailscale/tailscale-rs`

This repository is a personal fork of
[`tailscale/tailscale-rs`](https://github.com/tailscale/tailscale-rs), the official pure-Rust
(no Go, no cgo) Tailscale node implementation. I maintain it to track upstream deliberately, carry
a few additional patches, and explore the `tsnet`-in-Rust surface end to end.

## Provenance

- **Upstream:** https://github.com/tailscale/tailscale-rs (BSD-3-Clause)
- **Forked from:** `29d87ee17e734c8d7c2dc5db60f4c67df566aa30` (2026-05-28)
- **Remotes:** the upstream is preserved as `upstream`; this fork's `origin` is
  `GeiserX/tailscale-rs`.

## Why a fork, not a crates.io dependency

1. **Pin a known-good revision.** Upstream is young, fast-moving, and self-labels as
   *"unstable and insecure … unaudited cryptography"* (gated behind
   `TS_RS_EXPERIMENT=this_is_unstable_software`). Pinning and rebasing deliberately — never
   auto-bumping — keeps the surface stable while it matures.
2. **Carry local patches.** A core design goal here is a strict anti-leak property on the exit
   path: an exit node must never leak its real origin IP. The fail-closed gating (treat a session
   as live only after key confirmation, never fall back to a direct host-route dial, IPv6 off,
   DERP/WireGuard failure ⇒ drop) is maintained as patches on top of upstream.

## Safety posture

The "unaudited crypto" caveat is acceptable only for a closed, both-ends-owned deployment — where
the operator controls both the control plane and the exit, so the handshake is never exposed to a
hostile control plane, and the control plane's capability version is pinned to freeze the protocol.
This is **not** a general-purpose endorsement of the crate for production. See
[`SECURITY.md`](SECURITY.md).

## Updating from upstream

```sh
git fetch upstream
git log --oneline HEAD..upstream/main   # review every change before taking it
git rebase upstream/main                # deliberate, reviewed; then re-run cargo audit
```
