# Status

`tailscale-rs` is a work-in-progress. This page was last checked against the code on 2026-10-14, when
automated work on this repository stopped. The full list of what is still missing against Go
v1.102.4, the parity claims corrected that day, and the open backlog are in the
[parity roadmap](https://github.com/GeiserX/tailscale-rs/blob/main/docs/PARITY_ROADMAP.md#gap-audit-and-open-backlog-at-wind-down-2026-10-14). The
[issue tracker](https://github.com/GeiserX/tailscale-rs/issues) is the best way to see later updates.

## Implemented

These are features that are currently implemented:

- Basics
    - Create TCP and UDP sockets on the tailnet
    - Direct connections via NAT traversal (STUN-discovered endpoints and Disco, with `CallMeMaybe`
      hole-punching over DERP); traffic falls back to public DERP relays only when no direct path is
      available
    - Peer lookups (addressing peers by MagicDNS name, in-process)
    - MagicDNS (an in-netstack resolver on `100.100.100.100:53` answering A/AAAA/PTR for tailnet
      peers and control-pushed static records (`ExtraRecords`); by default fail-closed — with no
      `fallback_resolvers` configured, non-tailnet names get NXDOMAIN and are never forwarded
      upstream. Configuring `fallback_resolvers` opts in to forwarding non-tailnet query names to
      those upstream resolvers.)
    - Split DNS (per-domain `routes` from control: a query matching a route's suffix is forwarded to
      that route's resolvers by longest-suffix match; a route with an empty resolver list is a
      negative route answering NXDOMAIN. Recursive forwarding to `fallback_resolvers`/`resolvers`
      applies only when no route matches.)
    - Using a subnet router (accepting peer-advertised subnet routes via `accept_routes`; opt-in,
      fail-closed off by default)
    - Using an exit node (routing internet-bound traffic through a chosen peer via `exit_node`,
      selectable by Tailscale stable ID, tailnet IP, or MagicDNS name; opt-in, fail-closed off by
      default). The exit node can also be changed at runtime with `Device::set_exit_node` — the
      equivalent of Go `tsnet`'s `LocalClient.EditPrefs(ExitNodeID/ExitNodeIP)` — without recreating
      the device.
    - Recursive MagicDNS forwarding in TUN mode (the `100.100.100.100:53` resolver now forwards
      non-tailnet names recursively in TUN mode, matching the netstack-mode behavior; the same
      fail-closed default applies — without `fallback_resolvers`, non-tailnet names get NXDOMAIN)
    - Tailscale Serve: `Proxy`, `Text`, `TcpForward`, plus HTTP `Path` (path-prefix mux) and
      `Redirect` (HTTP 3xx) handlers; all TLS-terminating targets are validated and dispatched
      fail-closed (unmatched path → 404, backend dial failure → drop)
    - Tailnet Lock (TKA), **partial**: per-peer node-key signature verification is wired, unit-tested,
      and **actively enforcing** at the peer-trust chokepoint. The AUM-chain sync RPC that supplies the
      trusted-key `Authority` is implemented, so once a lock is synced the chokepoint fails **closed** —
      a peer with a missing or unauthorized `key_signature` is **dropped** (the `Authority` only ever
      reaches enforcement after `VerifiedAumChain::verify`, so control cannot forge a trusted key to
      admit a peer; it can only toggle the lock). Go's rotation-obsolete (clone/replay) peer dropping
      ships too. Remaining deferred gaps: multi-node `tka/init` enrollment, disablement-secret
      verification, and the node's own signature: it never sends `NodeKeySignature`, so it cannot join
      a locked tailnet with a pre-signed auth key and loses its signature at each key rotation. See [SECURITY.md](https://github.com/GeiserX/tailscale-rs/blob/main/SECURITY.md) before relying on it.
    - Communicate with the Tailscale Go client, `tsnet`, and `libtailscale`
- Node services
    - Being a subnet router or exit node (`advertise_routes`, `advertise_exit_node`, also settable at
      runtime); inbound flows are dialed out by the forwarder, and exit egress can go through an
      upstream proxy (`exit_proxy`)
    - Taildrop send and receive over a direct path
    - HTTPS certificates through ACME DNS-01 (`listen_tls`, `get_certificate`, feature `acme`)
    - Tailscale Serve: the stored config in Go's `ipn.ServeConfig` shape (`set_serve_config`)
    - Tailscale Funnel, the client leg (`listen_funnel`)
    - Tailscale SSH server, login shell only (`listen_ssh`, feature `ssh`)
    - Tailscale Services, the consuming side (`listen_service` binds a service the netmap granted)
    - Peer relays, the receiving side (answering a relay a peer allocated)
    - Client metrics as unlabelled counters (`Device::metrics`) and application capabilities in WhoIs
- Language support
    - Rust API
    - C, Elixir, and Python bindings

## Coming Soon

These are features or efforts I have in the pipeline and am actively working towards, but with
no guarantees on timeline or completion:

- Third-party code and cryptography audit

## Unsupported

This is an incomplete list of features in the Tailscale Go client, `tsnet`, and/or `libtailscale`
that are *not* currently supported. I'd like to add all of these eventually! If there's something
on this list you'd like to see supported, or something _not_ on this list you're not sure about,
please open an issue!

<details markdown>
<summary>
Unsupported features
</summary>

- Networking
    - Peer relays, the client side (finding a relay server and allocating one)
    - Exit Nodes, one gap when being one: a forwarded connection to a dead backend is closed instead
      of refused
    - Exit node DNS (`ExitNodeDNSResolvers` — routing DNS through the exit node)
    - Private DERP relays
    - Subnet Routers, two gaps when being one: a forwarded connection to a dead backend is closed
      instead of refused, and pings to hosts on the subnet get no answer
- Platforms
    - AIX
    - Android
    - BSDs
    - iOS
    - Plan9
    - QNAP
    - Synology DSM
- Observability
    - Client Metrics in Go's labelled `tailscaled_*` form
    - Endpoint Collection
    - Device Posture Collection
    - Log Streaming
    - Network Flow Logs
- Other Features
    - Application Capabilities in packet-filter rules (`cap:` rules never match)
    - Automatic Key Rotation
    - HTTPS certificate renewal (a running TLS listener keeps the certificate it started with)
    - Kubernetes
    - Mullvad VPN
    - Node Sharing
    - Taildrive
    - Taildrop through a relay, and arrival notifications
    - Tailnet Lock — *enforcement is supported* (per-peer key-signature verification is wired and
      actively fails closed once a lock is synced — an unsigned or unauthorized peer is dropped; see
      [SECURITY.md](https://github.com/GeiserX/tailscale-rs/blob/main/SECURITY.md)). What is **not** yet supported: multi-node `tka/init` enrollment,
      disablement-secret verification, adding or removing lock keys, and the node's own
      `NodeKeySignature` on register (pre-signed auth keys, re-signing after rotation).
    - Tailscale Funnel, the public relay leg (Tailscale-operated)
    - Tailscale Serve identity headers (`Tailscale-User-*`), and the Serve options this repository
      refuses on purpose (the stored config and its handlers are implemented)
    - Tailscale SSH beyond a login shell: exec, SFTP, port forwarding, check mode, session recording
    - Tailscale Services: advertising at runtime, and Go's TLS and app-capability service modes
    - Webhooks
- Any other features not listed in "Implemented" or "Coming Soon"

</details>

