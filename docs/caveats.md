# Caveats, versioning and platform support

## Caveats

This software is still a work-in-progress! I'm providing it in the open at this stage out of a
belief in open-source and to see where the community runs with it, but please be aware of a few
important considerations:

- This implementation contains unaudited cryptography and hasn't undergone a comprehensive security
  analysis. Conservatively, assume there could be a critical security hole meaning anything you send
  or receive could be in the clear on the public Internet.
- There are no compatibility guarantees at the moment. This is early-days software &mdash; I may
  break dependent code in order to get things right.
- Direct peer-to-peer connections via NAT traversal are implemented (STUN-discovered endpoints and
  Disco, with `CallMeMaybe` hole-punching over DERP), and traffic falls back to DERP relays when no
  direct path is available. Symmetric-NAT birthday-paradox hole-punching is not yet implemented,
  so behind some NATs a flow stays relayed through DERP, which caps its throughput.
- The `TS_RS_EXPERIMENT` environment variable is required to be set to `this_is_unstable_software`
  for all code linked against `tailscale-rs`; this includes Rust, C, Elixir, and Python code. I'll
  remove this requirement after a third-party code/cryptography audit and any necessary fixes.

For the full security posture — unaudited cryptography, the Tailnet Lock enforcement gap, peerAPI
capability limitations, at-rest key handling, and how to report a vulnerability — see
[SECURITY.md](../SECURITY.md).

## Versioning, Releases, and Compatability

I follow semver and aim to make a point release roughly monthly. Since this is pre-1.0, there are no
backwards-compatability guarantees. I'm aiming for a stable 1.0 release as soon as I can, but there's
currently no timeline.

## MSRV and Edition

The current MSRV is 1.94.1. The current edition is Rust 2024.

`tailscale-rs` has a rolling MSRV (Minimum Supported Rust Version) policy to support the current
and previous Rust compiler versions, and the latest
[edition of Rust](https://doc.rust-lang.org/edition-guide/editions/index.html).

I may lag the latest version/edition in rare cases to let dependencies catch up and to
perform any necessary fixes.

## Platform Support

The following platforms and architectures are supported:

- Linux (`x86_64`/`ARM64`)
- macOS (`ARM64`)
- Windows (`x86_64`)

