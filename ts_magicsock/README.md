# ts_magicsock

A direct (disco) UDP underlay transport for the Tailscale runtime — the pure-Rust
equivalent of Go's `magicsock`.

It is the second implementation of `ts_transport::UnderlayTransport` alongside DERP. Where
DERP relays WireGuard datagrams over a TCP connection to a relay server, `ts_magicsock`
carries them directly over UDP to a peer's reachable endpoint. It uses the Tailscale
[disco protocol](../ts_disco_protocol) to discover, confirm, and select which endpoint is
reachable (NAT "hole punching" / path selection).

A single UDP socket carries both disco control traffic and WireGuard data; the two are
demultiplexed by the disco magic prefix.

## Anti-leak posture

The one bound UDP socket is the **only** permitted egress path for this transport. When no
direct path to a peer is confirmed — or a previously-confirmed path's trust expires —
`MagicSock` surfaces that as the absence of a best address and refuses to send (`Error::NoPath`).
It never dials the host network as a silent fallback. The route layer keeps such peers on
DERP. This is what keeps the real origin IP from leaking when direct connectivity is
unavailable.

## Status

Phase 1 (this crate): disco ping/pong send/recv over a real UDP socket, per-peer candidate
endpoint tracking, lowest-latency best-path selection with trust expiry, and a
`DirectTransport` that implements `UnderlayTransport` keyed on the peer's disco key.

Phase 2 (runtime wiring, separate change): STUN reflexive-address discovery over the shared
socket, `CallMeMaybe` exchange over DERP, DERP↔direct upgrade/downgrade in the route layer,
and advertising our own endpoints in the control `MapRequest`.
