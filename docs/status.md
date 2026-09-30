# Status

`tailscale-rs` is a work-in-progress - I'm still rapidly iterating, fixing bugs, and adding new
features. I aim to keep this section up-to-date, but the [issue tracker](https://github.com/GeiserX/tailscale-rs/issues)
is the best way to see the latest updates.

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
      admit a peer; it can only toggle the lock). Remaining deferred gaps: establishing/managing a lock
      from this node (multi-node `tka/init` enrollment), disablement-secret verification, and Go's
      rotation-obsolete (clone/replay) peer dropping. See [SECURITY.md](https://github.com/GeiserX/tailscale-rs/blob/main/SECURITY.md) before relying on it.
    - Communicate with the Tailscale Go client, `tsnet`, and `libtailscale`
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
    - Peer relays
    - Exit Nodes (being one — advertising a default route; *using* one is supported)
    - Exit node DNS (`ExitNodeDNSResolvers` — routing DNS through the exit node)
    - Private DERP relays
    - Subnet Routers (being one — advertising routes; *using* one is supported)
- Platforms
    - AIX
    - Android
    - BSDs
    - iOS
    - Plan9
    - QNAP
    - Synology DSM
- Observability
    - Client Metrics
    - Endpoint Collection
    - Device Posture Collection
    - Log Streaming
    - Network Flow Logs
- Other Features
    - Application Capabilities
    - Automatic Key Rotation
    - HTTPS Certificates
    - Kubernetes
    - Mullvad VPN
    - Node Sharing
    - Taildrive
    - Taildrop
    - Tailnet Lock — *enforcement is supported* (per-peer key-signature verification is wired and
      actively fails closed once a lock is synced — an unsigned or unauthorized peer is dropped; see
      [SECURITY.md](https://github.com/GeiserX/tailscale-rs/blob/main/SECURITY.md)). What is **not** yet supported: establishing/managing a lock from this
      node (multi-node `tka/init` enrollment), disablement-secret verification, and Go's
      rotation-obsolete (clone/replay) peer dropping.
    - Tailscale Funnel
    - Tailscale Serve — the stored serve-config runtime and accept-loop (the `Path`/`Redirect`/`Proxy`/
      `Text`/`TcpForward` handlers themselves are implemented)
    - Tailscale SSH
    - Tailscale Services
    - Webhooks
- Any other features not listed in "Implemented" or "Coming Soon"

</details>

