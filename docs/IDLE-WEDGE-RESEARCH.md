# Idle-wedge root cause + fix research (DERP-relayed tunnel goes dead after idle)

> Research synthesis for the fix in this PR. Triangulated across three independent
> investigations (codebase explorer, causal tracer, WireGuard/boringtun prior-art
> doc-spec) — all converge on the same root cause. High confidence.

## Symptom (live evidence)

A DERP-relayed userspace-netstack node (the NEV `session-bridge`, geiserx_tailscale
v0.6.10) wedges deterministically after ~180s idle: every new dial → 504, permanent
until process restart (2/2 fresh sessions). `ts_tunnel/src/endpoint.rs:400`
`handshake failed to complete` loops ~every 5.5s. Warm/continuous traffic is perfect
(10/10). First failure appears 44–74s **into** the idle window. (Evidence:
`Darling-over-eBPF/infra/lima/nev-idle-reprove-v0610-evidence.txt`.) NOTE: v0.6.10's
`PeerUpdate::Patch` fix is unrelated — control sent zero patches; this is a different
bug.

## Root cause

**The WG data-plane endpoint is purely event-driven — its timers advance ONLY on
packet send/recv. There is no periodic timer tick and no persistent-keepalive.** On
an idle tunnel:

- The reactive WG keepalive (`KEEPALIVE_TIMEOUT=10s`, `endpoint.rs:29`) is armed
  ONLY from `recv_transport_data` (`endpoint.rs:427,438`) and `send_keepalive`
  re-arms only if more inbound traffic arrived (`endpoint.rs:489-502`). ~10s after
  the last received packet the WG layer toward the peer goes completely silent.
- Rekey is gated behind `needs_rotation()`, reachable only from `Peer::send`
  (`endpoint.rs:330-335`) — i.e. only on outbound traffic. No timer ever schedules a
  rekey.
- The tokio driver `ts_dataplane/src/async_tokio.rs:165-236` `step()` sleeps on
  `next_event()`; once the (reactive) keepalive event fires/cancels, `next_event()`
  returns `None` → `option_sleep_until(None)` becomes `future::pending()`
  (`async_tokio.rs:271-276`) → **the dataplane blocks forever on I/O with no timer
  wakeup.** This is the smoking gun.
- So the session silently ages past `stale()`=120s and `expired()`
  (`ts_tunnel/src/session.rs:151-157`) with no traffic to keep it warm and no timer
  to refresh it. When a dial finally retries, a rehandshake is triggered but loops at
  `HANDSHAKE_TIMEOUT`=5s + jitter ≈ 5.5s (`endpoint.rs:477-487,529-534`) and never
  completes — the relayed path/NAT mapping has gone cold.

### Standard WG timer audit (this fork)

| Timer | Canonical | This fork |
| --- | --- | --- |
| REKEY_AFTER_TIME (120s) | proactive initiator rekey | value present (`session.rs:152`) but checked only reactively on `send`, never on a timer |
| REJECT_AFTER_TIME (180s) | session dead past 180s | present but **240s** (`session.rs:156`); reactive-only |
| REKEY_ATTEMPT_TIME (90s) | give up after 90s | **ABSENT** — retry loops unbounded |
| KEEPALIVE_TIMEOUT (10s) | passive keepalive | present (`endpoint.rs:29`) but armed only by inbound traffic |
| **PERSISTENT_KEEPALIVE (25s)** | hold NAT/relay warm | **ABSENT entirely** ← the load-bearing gap |
| periodic timer tick | drives timers when idle | **ABSENT** — endpoint advanced only by traffic |

### Secondary latent bug (not the primary, fix separately/note)

`ts_tunnel/src/macs.rs:146-148` `verify_macs` rejects ANY non-zero mac2 cookie
(literal `// TODO: verify non-zero mac2`). If a cold relay / loaded responder enters
cookie mode, every `finish()` fails. Contributing failure mode under load; the
primary wedge is the missing keepalive + tick.

## The fix (canonical WG / boringtun pattern)

Two parts, both required:

1. **Persistent-keepalive (25s):** when no outgoing traffic for N seconds, emit one
   empty authenticated data packet (`encapsulate(&[])`) to hold the path/NAT/relay
   mapping warm. Per-peer, opt-in (Tailscale sets 25s when control marks the peer
   `KeepAlive=true`; 25s < the ~30s UDP NAT floor). Reset on any outgoing
   authenticated packet.
2. **Periodic timer tick:** a clock-driven driver that services the endpoint even
   with zero traffic (boringtun's `update_timers(&mut self, dst) -> TunnResult`,
   polled ~250ms–1s, reads the clock internally). Without this the keepalive timer
   would never fire on a truly idle tunnel (the `pending()`-forever bug above).

**Reference:** boringtun `src/noise/timers.rs` `update_timers` (the closest Rust prior
art) + wireguard-go `device/timers.go` `timersAnyAuthenticatedPacketTraversal` /
`expiredPersistentKeepalive`. Tailscale `wgengine/wgcfg/nmcfg`: `if peer.KeepAlive {
cpeer.PersistentKeepalive = 25 }`.

### Scope / what this does NOT fix

This PR ships **part 1 + part 2** (persistent-keepalive + periodic tick), which warms the
path/NAT/relay mapping on an idle tunnel. It does **not** make rekey timer-driven:

- The persistent keepalive holds the **path/NAT mapping** warm, not the **session keys**. It is
  an empty data packet on the *existing* session; it does not (and must not) advance the
  data-sent timers that gate rekey.
- Rekey remains **reactive** — driven by outbound application data / `Peer::send`'s
  `needs_rotation()` check (`endpoint.rs:330-335`), not by a timer. The keepalive deliberately
  does not trigger it (see "Invariants": an empty packet masking a dead peer is the failure mode
  we guard against).
- The scenario this fixes is **idle → dial**: a tunnel that went quiet and is then woken by a new
  outbound dial, where the cold NAT/relay mapping was the wedge.
- A tunnel kept alive **solely by keepalives** with **zero application traffic** past
  `REKEY_AFTER_TIME` / `REJECT_AFTER_TIME` (>~240s in this fork, `session.rs:152,156`) is a
  **separate, known case NOT addressed here**: the session keys still age out reactively. The
  follow-up for that is **timer-driven rekey** (proactive initiator rekey at `REKEY_AFTER_TIME`),
  which this PR does not add.

### Insertion points in this fork

- `ts_tunnel/src/endpoint.rs` — a persistent-keepalive timer that re-arms
  UNCONDITIONALLY (not gated on inbound traffic), reset on outgoing authenticated
  packets; new scheduler event variant. The empty-keepalive emit path
  (`send_keepalive`) already exists — reuse it.
- `ts_dataplane/src/async_tokio.rs` (`step()` loop) — ensure the endpoint is ticked
  on a periodic deadline even when `next_event()` would otherwise be `None` (so an
  idle endpoint is serviced; fixes the `pending()`-forever block).
- `ts_tunnel/src/config.rs` + the `ts_runtime` Config chain — expose
  `persistent_keepalive_interval: Option<Duration>` (default 25s for relayed/exit
  peers, mirroring Tailscale's per-peer `KeepAlive`). Keep it opt-in / configurable.

### Invariants to preserve

- **Fail-closed egress** (AGENTS.md): a keepalive must never cause traffic to leak to
  a wrong/stale endpoint. ring-only crypto, no new heavy deps.
- The keepalive is an empty packet and MUST NOT reset the "data sent" timers
  (boringtun guards `if !src.is_empty()`), or it would mask a genuinely-dead peer.
- Shared by every consumer (NEV session-bridge, NVC bridge-rs, exit nodes) — default
  must be safe; medium blast radius.
