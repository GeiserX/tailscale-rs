# Security Policy

This is a pure-Rust, work-in-progress reimplementation of the Tailscale `tsnet` node. It is shared
in the open out of a belief in open source, but it is **experimental software**. This document is an
honest account of its current security posture so that anyone considering routing real traffic
through it can make an informed decision.

> [!CAUTION]
> All code linked against this library must set `TS_RS_EXPERIMENT=this_is_unstable_software` before
> the process starts. That gate exists *because* of the limitations below — most importantly the
> unaudited cryptography. **Do not remove the gate to make a build look production-ready.** It is
> meant to stay until an independent audit lands and any resulting fixes ship.

## Trust boundary

```mermaid
flowchart LR
    subgraph Embedder["Embedding application (your responsibility)"]
        State["State dir<br/>auth keys · WG private keys · ACME account keys<br/>(plaintext on disk)"]
    end

    subgraph Lib["tailscale-rs (this fork)"]
        CtrlNoise["Control plane (TS2021 Noise)<br/>hand-implemented"]
        DataNoise["Data plane (WireGuard Noise_IKpsk2)<br/>hand-implemented"]
        Acme["ACME / JWS (RFC 8555)<br/>hand-implemented"]
        TKA["Tailnet Lock verify<br/>wired, ENFORCEMENT INERT"]
        Dialer["RealDialer chokepoint<br/>fail-closed, IPv4-only"]
    end

    Control["Control plane<br/>(a self-hosted control plane / Tailscale)"]
    Peers["Tailnet peers"]
    Upstream["Upstream proxy / Internet"]

    State --> Lib
    CtrlNoise <--> Control
    DataNoise <--> Peers
    Acme <--> Control
    TKA -. "cannot yet block<br/>compromised control" .-> Control
    Dialer --> Upstream
```

The control plane is trusted today: Tailnet Lock, the mechanism that would let a client reject
peer node-keys injected by a malicious or compromised control plane, is wired but **not yet
enforcing** (see below).

## Unaudited cryptography

This fork hand-implements its cryptographic protocols and **has not undergone an independent
cryptographic or security audit**. The hand-rolled surfaces include:

- **WireGuard data-plane handshake** — `Noise_IKpsk2` (`ts_tunnel/src/handshake.rs`).
- **Control-plane handshake** — the TS2021 control Noise.
- **ACME / JWS** — RFC 8555 certificate issuance and JWS signing (`ts_control/src/acme.rs`).
- **Exit dialer** — a hand-rolled SOCKS5 (RFC 1928/1929) and HTTP `CONNECT` client (zero extra
  dependencies, to keep the egress path `ring`-only and musl-clean).
- **Tailnet Lock (TKA) CBOR** — the CTAP2-canonical CBOR encoding in `ts_tka` is **not**
  cross-validated against Go-produced test vectors. Byte-for-byte wire compatibility with a live
  Tailscale TKA is asserted by construction, not proven (see the `ts_tka` crate module docs). A
  *failed* verification is always safe to act on (deny); a *successful* verification should be
  treated as advisory until vectors land.

Conservatively, assume there could be a critical flaw in any of these paths. Do not rely on this
library for data privacy until the audit is complete.

## Tailnet Lock (TKA) status

Per-peer key-signature verification is **wired and unit-tested** at the peer-trust chokepoint
(`ts_runtime`'s `peer_tracker`). When an `Authority` carrying a non-empty trusted-key state is
supplied, the chokepoint fails **closed**: a peer with a bad signature is rejected, and a peer that
presents no signature under an active lock is also rejected. Neither is upserted into the peer
database.

However, **live enforcement is currently INERT.** No `Authority` is ever constructed at runtime,
because the AUM-chain sync RPC family (`/machine/tka/sync/*`) that would fetch the trusted-key set
from the control plane is **not yet implemented** in this fork. `MapResponse` only carries the AUM
*head* hash and the per-peer signature to be verified — never the trusted keys to verify against —
so the trusted-key `Authority` cannot be derived from data the client already receives.

**Consequence:** until the AUM-sync RPC and chain replayer are built and an `Authority` is supplied,
**do not rely on Tailnet Lock for control-plane-compromise protection.** A malicious or compromised
control plane can inject peer node-keys and the client will accept them. The enforcement code is
present and gated; it flips on the instant an `Authority` is supplied, with no further peer-trust
changes. Tracked as deferred work in [`docs/PARITY_ROADMAP.md`](docs/PARITY_ROADMAP.md).

## peerAPI capability gap

Taildrop and ingress authorization are currently **membership-only**: any node in the tailnet is
permitted, rather than being scoped to a per-peer capability as upstream does (e.g. the
`FILE_SHARING_SEND` / ingress capabilities). This is a known gap — peer capabilities are not yet
enforced for these surfaces.

## At-rest key handling is the embedder's responsibility

Auth keys, WireGuard private keys, and ACME account keys are persisted by `ts_keys` **without
at-rest encryption or in-memory zeroization**. The library does not protect this material on disk.
Securing the state directory (filesystem permissions, full-disk or directory encryption, restricting
access to the running user) is the **embedding application's** responsibility.

## Anti-leak posture (the strong part)

The product invariant this fork is built around — **the origin IP never leaks, egress is
fail-closed, and egress is IPv4-only** — is enforced both structurally and in CI:

- The `RealDialer` trait in `ts_forwarder` is the single anti-leak chokepoint. The default
  `DirectDialer` structurally refuses exit egress, so the real origin IP cannot leak by accident; the
  proxy dialer is selected only when exit egress is explicitly enabled and a proxy is configured.
- Any proxy connect/handshake failure **drops the flow** — there is never a fallback to a direct
  host-IP dial. UDP over the proxy fails closed. An SSRF guard rejects forbidden exit destinations
  (loopback / link-local / unspecified), and proxy credentials are redacted from `Debug` output.
- The `checks` crate runs in CI and statically guards these invariants: `ipv4_only_forwarder`,
  `ipv4_only_host_net`, `funnel_fail_closed`, `ssh_isolation`, and lint enablement. DNS forwarding is
  routed through filters that drop any non-IPv4 upstream, so a v6 upstream can never be constructed
  on the egress path.

## Reporting a Vulnerability

If you believe you have found a security vulnerability, please report it privately rather than
opening a public issue:

- Open a **private GitHub Security Advisory** at
  <https://github.com/GeiserX/tailscale-rs/security/advisories/new>
  (or via the repository's `Security` tab → `Report a vulnerability`).

Please include a description of the issue, the affected component(s), and steps to reproduce if
possible. We will acknowledge the report and work with you on a coordinated disclosure timeline.

## Not affiliated with Tailscale Inc.

This is an independent fork. "Tailscale" is a trademark of Tailscale Inc. This project is not
endorsed by, sponsored by, or affiliated with Tailscale Inc. WireGuard is a registered trademark of
Jason A. Donenfeld.
