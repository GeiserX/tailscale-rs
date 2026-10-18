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
[SECURITY.md](https://github.com/GeiserX/tailscale-rs/blob/main/SECURITY.md).

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

### macOS: Local Network Privacy

On macOS 15 and later, a process needs the Local Network permission before it can send to other
devices on its own LAN. When a UDP send is blocked, it fails with `EHOSTUNREACH`. Apple's
[TN3179](https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy)
says macOS allows local network access automatically for any daemon started by `launchd`, any
program running as root, and command-line tools run from Terminal or over SSH (with their child
processes). The exception for `launchd` daemons does not apply to `launchd` agents.

A `launchd` daemon that sets `UserName` to a non-root user has still been reported blocked, and it
cannot show the permission prompt. This was reported against macOS 26.6.2 (issue #646). It
contradicts the technote, and we have not found an Apple statement that explains it. Sends to the
default gateway and to hosts outside the LAN still work. The reporter also observed that replies on
a UDP flow the LAN peer started get through; Apple's technote does not document that.

What this means for a node built on this library:

- Peers on the same LAN may not get a direct path, so they stay on DERP. Peers elsewhere are not
  affected.
- Go's `tailscaled install-system-daemon` installs a root LaunchDaemon, so it never runs into this.
  The Tailscale Mac app asks the user for the permission. Neither Go nor this library works around
  it in code.

To avoid it, do one of these:

1. Run the daemon as root: leave `UserName` out of the plist. This is what Go's `tailscaled` and
   [tailscaled-rs](https://github.com/GeiserX/tailscaled-rs) ship.
2. On macOS 15.5 or later, mark your LAN as allowed for every program on the Mac, then restart:

   ```bash
   sudo defaults write com.apple.network.local-network AllowedEthernetLocalNetworkAddresses -array "192.168.1.0/24"
   sudo defaults write com.apple.network.local-network AllowedWiFiLocalNetworkAddresses -array "192.168.1.0/24"
   ```

   Replace `192.168.1.0/24` with your LAN. This setting applies to the whole Mac, so only use it
   on a machine you manage.
3. Pending PR #639: if your router supports hairpin NAT, LAN peers can reach each other directly
   through the router's public address. That needs private and hairpin ping sources to be learned,
   which #639 adds.
