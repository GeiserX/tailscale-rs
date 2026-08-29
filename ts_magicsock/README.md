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

It also implements the **peer-relay client**: when a peer offers a UDP relay endpoint in a
`CallMeMaybeVia`, `ts_magicsock` runs the 3-way bind handshake with that relay server and then
carries WireGuard data through it, Geneve-encapsulated, instead of falling back to DERP. A direct
path always takes priority over a relay one. This node never *serves* as a relay.

## Anti-leak posture

The one bound UDP socket is the **only** permitted egress path for this transport — the peer-relay
leg included; it is the same socket with a Geneve header in front. When neither a direct path nor a
confirmed relay path exists for a peer — or a previously-confirmed path's trust expires —
`MagicSock` refuses to send (`Error::NoPath`) rather than dialing the host network as a silent
fallback. The route layer keeps such peers on DERP. This is what keeps the real origin IP from
leaking when direct connectivity is unavailable.

A relay server learns our public address, but so does any peer we disco-ping: relay addresses are
peer-supplied and pass through the same `is_pingable_candidate` sanitizer a `CallMeMaybe` endpoint
does, and the announcing peer must be a current netmap member. The relay endpoint must also have
been allocated for exactly this pair of disco keys, so a peer cannot point us at an endpoint that
is not ours.

## Status

Phase 1 (this crate): disco ping/pong send/recv over a real UDP socket, per-peer candidate
endpoint tracking, lowest-latency best-path selection with trust expiry, and a
`DirectTransport` that implements `UnderlayTransport` keyed on the peer's disco key.

Phase 2 (runtime wiring, separate change): STUN reflexive-address discovery over the shared
socket, `CallMeMaybe` exchange over DERP, DERP↔direct upgrade/downgrade in the route layer,
and advertising our own endpoints in the control `MapRequest`.
