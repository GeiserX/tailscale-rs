# ts_disco_protocol

Implementation of Tailscale's peer-to-peer discovery ("disco") protocol.

Covers all nine upstream message types: `Ping`, `Pong` and `CallMeMaybe` (`0x01`–`0x03`), and the
peer-relay set (`0x04`–`0x09`) — the 3-way bind handshake with a UDP relay server, `CallMeMaybeVia`,
and relay endpoint allocation.
