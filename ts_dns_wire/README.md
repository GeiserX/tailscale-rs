# ts_dns_wire

Minimal RFC 1035 DNS wire-format codec for a MagicDNS responder.

`#![no_std]`, `alloc`-only. Provides a query parser ([`decode_query`]) and a
response encoder ([`encode_response`]) plus the supporting types (`Name`,
`Question`, `QType`, `RData`, `Rcode`, `SoaZone`, `Query`, `DecodeError`).

A negative answer this node is authoritative for can carry the zone's SOA in
the authority section (`SoaZone`), which bounds how long a downstream resolver
may cache the nonexistence (RFC 2308).

It performs no I/O and does no networking; it is pure wire-format codec. None
of the parsing functions panic on malformed input.
