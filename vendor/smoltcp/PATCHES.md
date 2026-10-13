# smoltcp 0.13.1 TCP sender recovery patches

Source: the published `smoltcp` 0.13.1 crate, under `LICENSE-0BSD.txt`.
The workspace patch keeps the existing version and feature selection, including
`no_std`. Cargo registry bookkeeping and the dependency's standalone lockfile
are omitted from this import.

`src/socket/tcp.rs` separates RTT-sample invalidation on any retransmission from
RTO backoff on an **expired retransmission timer**. Fast retransmit must not
double the RTO. This backports Joe Dye's upstream fix:
[29340b71ffca86f130746c7dd3c7a9a09495dda9](https://github.com/smoltcp-rs/smoltcp/commit/29340b71ffca86f130746c7dd3c7a9a09495dda9).
The call site is adapted to 0.13.1's combined retransmit branch; the upstream
revision has separate timeout and fast-retransmit branches. This original backport is retained alongside the local patches below.

The added socket regression simulates seven flights losing their first segment,
then a lost tail with no duplicate ACKs. With a virtual clock, the tail must be
retransmitted in one second rather than waiting for a spuriously inflated 60s
RTO. Actual timeout backoff and Karn's sample invalidation remain in place.

## Local sender patches (Brief 24)

Separate commits on `ts-exit/tcp-recovery`, keeping the 0.13.1 version and `no_std` support:

- Enforce cwnd over bytes in flight, including payloads emitted with an ACK.
- Preserve the original flight end during fast recovery; repair a partial ACK's next hole
  ([NewReno, RFC 6582](https://www.rfc-editor.org/rfc/rfc6582)). Fast retransmit sends one
  segment, and reports congestion once per recovery episode.
- Keep a 32-range, heap-free sender SACK scoreboard. Validate, merge and trim ranges; use
  [RFC 6675](https://www.rfc-editor.org/rfc/rfc6675)'s loss test and Pipe estimate to send
  selective repairs and fresh data. Cumulative ACKs alone free transmit data. Timeout clears
  advisory SACK state. This is a bounded recovery subset, without rescue retransmission/RACK.
- Correct Reno's ACK clock, additive increase and timeout restart; correct Cubic's slow start,
  segment units and immediate multiplicative decrease. Bound stretched-ACK growth after RTO.
- Add optional RTT-based pacing with bounded bursts, immediate ACKs and correct timer priority.
  Pacing stays disabled by default in upstream-facing smoltcp APIs.
- Add a per-socket minimum computed RTO; preserve the one-second default and initial handshake
  timeout, RTT variance and exponential backoff.
- Rust 1.95 lint/format hygiene; bound pacing credit before narrowing to `usize` on 32-bit targets.

The netstack integration selects Cubic, pacing, a 200 ms computed RTO floor and 32 receive
holes for both application and forwarder sockets. The upstream-facing defaults remain intact.

Validation (run inside this directory):

```sh
nice -n 10 cargo +1.95.0 test -j 4 --lib --features socket-tcp-reno,socket-tcp-cubic,assembler-max-segment-count-32
nice -n 10 cargo +1.95.0 test -j 4 --lib --no-default-features --features std,medium-ip,proto-ipv4,proto-ipv6,socket-tcp
nice -n 10 cargo +1.95.0 clippy -j 4 --lib --tests --features socket-tcp-reno,socket-tcp-cubic,assembler-max-segment-count-32 -- -D warnings
nice -n 10 cargo +1.95.0 fmt -- --check
```

Remove the override only when an upstream version includes the required fixes or an equivalent
sender implementation. The fork's `[lints.rust]` allowances for existing unused/dead-code
warnings are retained.
