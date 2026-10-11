# smoltcp 0.13.1 TCP recovery backport

Source: the published `smoltcp` 0.13.1 crate, under `LICENSE-0BSD.txt`.
The workspace patch keeps the existing version and feature selection, including
`no_std`. Cargo registry bookkeeping and the dependency's standalone lockfile
are omitted from this import.

`src/socket/tcp.rs` separates RTT-sample invalidation on any retransmission from
RTO backoff on an **expired retransmission timer**. Fast retransmit must not
double the RTO. This backports Joe Dye's upstream fix:
[29340b71ffca86f130746c7dd3c7a9a09495dda9](https://github.com/smoltcp-rs/smoltcp/commit/29340b71ffca86f130746c7dd3c7a9a09495dda9).
The call site is adapted to 0.13.1's combined retransmit branch; the upstream
revision has separate timeout and fast-retransmit branches. No other upstream
TCP changes are included.

The added socket regression simulates seven flights losing their first segment,
then a lost tail with no duplicate ACKs. With a virtual clock, the tail must be
retransmitted in one second rather than waiting for a spuriously inflated 60s
RTO. Actual timeout backoff and Karn's sample invalidation remain in place.

Remove this vendor override when adopting an upstream release containing that
fix. Further upstream TCP changes (including fast recovery and congestion
control) require separate review.
- `Cargo.toml`: a `[lints.rust]` table that allows the crate's existing unused/dead-code warnings in the fork's builds (no source change).
