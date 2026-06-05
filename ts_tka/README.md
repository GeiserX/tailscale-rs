# ts_tka

Tailnet Lock (TKA — Tailnet Key Authority) signature-chain verification, mirroring Go Tailscale's
`tka` package. Implements the client-side verification path: BLAKE2s-256 AUM hashing, a CTAP2
canonical CBOR encoder for byte-exact signing digests, the AUM/Key/NodeKeySignature wire types, and
`Authority::node_key_authorized` (the check that a peer's node key is trusted under the current
tailnet-lock state).

This is the **verification** half (what a client does to trust a peer). Building/mutating the
authority (admin/control side) is out of scope.
