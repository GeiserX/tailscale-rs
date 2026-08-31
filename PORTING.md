# Porting ledger: upstream Go `tailscale` → this repository

| | |
| --- | --- |
| **Upstream source** | `https://github.com/tailscale/tailscale` (Go) |
| **Upstream commit this ledger was written against** | `49e148c4a30b4f8098f69468fd27a7021d85ea02` (2026-08-29, `tsnet: base HTTPClient's transport on http.DefaultTransport`) |
| **Upstream `tailcfg.CurrentCapabilityVersion` at that commit** | **145** (2026-08-04) — unchanged from the previous pin |
| **This repository at ledger time** | `6bddedb` — workspace version `0.44.0` |
| **`ts_capabilityversion::CapabilityVersion::CURRENT` here** | **125** (2025-08-11) — held below 126; see §B, *c2n endpoints behind the declared capability version* |
| **Gap window this ledger covers** | capability version **131 → 145**, i.e. upstream commits from 2025-10-06 to 2026-08-29 (the window is anchored to when capver 130 landed upstream; the declaration here being 125 rather than 130 does not change what upstream added) |
| **Previous pin** | `1e69418c298b680562a2fecd7020f7f58d17d166` (2026-08-27). Four upstream commits separate the two, three of them in mapped packages — see §B, *New at this revision* |

> This repository is also a fork of the Rust port `tailscale/tailscale-rs` — see
> [`VENDOR.md`](VENDOR.md) for that provenance. This ledger is about the *other* upstream: the Go
> client, which is the behavioural reference both of them are measured against.

## The parity mission

The mission of this repository is **100% behavioural parity with upstream Go Tailscale**
(`github.com/tailscale/tailscale`), maintained in Rust. "Behavioural" is the operative word: the
goal is not a line-by-line transliteration of Go, but a node that a real Tailscale control plane,
a real Go `tailscaled` peer, a `wireguard-go` peer and a kernel WireGuard peer cannot distinguish
from a Go client on the wire — same control-protocol requests and responses, same DERP and disco
framing, same WireGuard handshake and timer behaviour, same packet-filter verdicts, same
fail-closed decisions when something goes wrong. Where Rust idiom differs from Go (typed errors
instead of sentinel values, actors instead of goroutines-plus-mutexes, `smoltcp` instead of
gVisor), the internals may differ freely; what may never differ is what a peer or a control plane
observes. This engine is always the *dialing client* against implementations it does not control,
so a divergence is a bug even when the divergence looks like an improvement, and no change may
assume a peer implements a fork-specific behaviour.

## Adding the upstream source

Upstream Go Tailscale is not vendored into this tree, and git remotes are local configuration that
cannot be committed. Add it once per checkout:

```sh
git remote add upstream-go https://github.com/tailscale/tailscale.git
git fetch upstream-go
```

Every command in this document is reproducible against that remote, or against a standalone
clone. The pinned commit above is what every assessment below was checked against; re-derive the
window before cutting new porting beads (see [Re-deriving this ledger](#re-deriving-this-ledger)).

## Package mapping

Upstream Go package → the crate or module that carries its behaviour here. `→` means "this is
where that behaviour lives", not "this is a transliteration of that file".

### Control plane

| Upstream Go | Here |
| --- | --- |
| `control/controlclient` | [`ts_control`](ts_control/src/lib.rs) (register, map poll, session resumption, c2n ping responder) |
| `control/controlbase` (Noise IK) | [`ts_control_noise`](ts_control_noise/src/lib.rs) |
| `control/controlhttp` (dial + upgrade) | [`ts_control`](ts_control/src/lib.rs) dial path, on [`ts_http_util`](ts_http_util/src/lib.rs) + [`ts_tls_util`](ts_tls_util/src/lib.rs) |
| `tailcfg` (wire types) | [`ts_control_serde`](ts_control_serde/src/lib.rs) (+ [`ts_packetfilter_serde`](ts_packetfilter_serde/src/lib.rs) for filter rules) |
| `tailcfg.CapabilityVersion` | [`ts_capabilityversion`](ts_capabilityversion/src/lib.rs) |
| `tailcfg/nodecap` (split out upstream, #20639) | [`ts_nodecapability`](ts_nodecapability/src/lib.rs) |
| `tailcfg/peercap` | [`ts_peercapability`](ts_peercapability/src/lib.rs) |
| `types/key` | [`ts_keys`](ts_keys/src/lib.rs) |
| `tka` (tailnet lock) | [`ts_tka`](ts_tka/src/lib.rs) + the peer-trust chokepoint in [`ts_runtime`](ts_runtime/src/peer_tracker/mod.rs) |
| `feature/identityfederation` (WIF/OAuth bootstrap) | [`ts_control::wif`](ts_control/src/wif.rs) |
| `net/tlsdial`, `net/bakedroots` | [`ts_tls_util`](ts_tls_util/src/lib.rs) |

### Data plane

| Upstream Go | Here |
| --- | --- |
| `wgengine/magicsock` | [`ts_magicsock`](ts_magicsock/src/lib.rs) + [`ts_runtime::direct`](ts_runtime/src/direct.rs) |
| `disco` | [`ts_disco_protocol`](ts_disco_protocol/src/lib.rs) |
| `net/stun` | STUN parsing/probing inside [`ts_magicsock`](ts_magicsock/src/lib.rs) |
| `net/netcheck` | [`ts_netcheck`](ts_netcheck/src/lib.rs) |
| `derp`, `derp/derphttp` (client half only) | [`ts_derp`](ts_derp/src/lib.rs) |
| `net/packet` | [`ts_packet`](ts_packet/src/lib.rs) + the decode/classify path in [`ts_dataplane`](ts_dataplane/src/lib.rs) |
| `wgengine/filter` | [`ts_packetfilter`](ts_packetfilter/src/lib.rs), [`ts_bart_packetfilter`](ts_bart_packetfilter/src/lib.rs), [`ts_packetfilter_state`](ts_packetfilter_state/src/lib.rs) |
| `wgengine` packet flow + `wgengine/wgcfg` | [`ts_dataplane`](ts_dataplane/src/lib.rs) |
| `golang.zx2c4.com/wireguard` device (upstream dependency) | [`ts_tunnel`](ts_tunnel/src/lib.rs) (partial WireGuard implementation) |
| `net/tstun` | [`ts_transport_tun`](ts_transport_tun/src/lib.rs) behind the [`ts_transport`](ts_transport/src/lib.rs) traits |
| `wgengine/netstack` (gVisor) | [`ts_netstack_smoltcp`](ts_netstack_smoltcp/src/lib.rs), [`…_core`](ts_netstack_smoltcp_core/src/lib.rs), [`…_socket`](ts_netstack_smoltcp_socket/src/lib.rs) |
| `wgengine/netstack` forwarding (subnet router / exit node) + `net/tsdial` | [`ts_forwarder`](ts_forwarder/src/lib.rs) (plus the fork-only upstream-proxy egress, see [`AGENTS.md`](AGENTS.md)) |
| peer/route selection (Go keeps this inside `magicsock`/`wgengine`) | [`ts_overlay_router`](ts_overlay_router/src/lib.rs), [`ts_underlay_router`](ts_underlay_router/src/lib.rs) |
| `wgengine/router`, OS side of `net/dns` | [`ts_host_net`](ts_host_net/src/lib.rs) (Linux `ip`/`resolvectl`, macOS `route`/`scutil`) |
| `net/dns/resolver` wire encoding | [`ts_dns_wire`](ts_dns_wire/src/lib.rs) + the MagicDNS server in [`ts_runtime::magic_dns`](ts_runtime/src/magic_dns.rs) |
| `net/netmon` | [`ts_netmon`](ts_netmon/src/lib.rs) |
| `net/art` + `github.com/gaissmai/bart` | [`ts_bart`](ts_bart/src/lib.rs) (+ [`ts_array256`](ts_array256/src/lib.rs), [`ts_bitset`](ts_bitset/src/lib.rs), [`ts_dynbitset`](ts_dynbitset/src/lib.rs)) |

### Runtime, API and utilities

| Upstream Go | Here |
| --- | --- |
| `tsnet` | the [`tailscale`](src/lib.rs) crate; [`tailscale::tsnet`](src/tsnet.rs) is the Go-shaped facade (see [`docs/TSNET_PARITY.md`](docs/TSNET_PARITY.md)) |
| `ipn/ipnlocal`, `tsd` (backend wiring, netmap → engine) | [`ts_runtime`](ts_runtime/src/lib.rs) (actor-per-concern) |
| `ipn` bus / `ipn/ipnstate` | [`ts_runtime::ipn_bus`](ts_runtime/src/ipn_bus.rs), [`ts_runtime::status`](ts_runtime/src/status.rs) |
| `ipn/store` (`FileStore`), `types/persist` | [`tsnet::StateStore` / `FileStore`](src/tsnet.rs) over `Config::key_state` ([`ts_keys::PersistState`](ts_keys/src/lib.rs)) |
| `net/socks5` (as used by `tsnet.Server.Loopback`) | [`src/loopback.rs`](src/loopback.rs) |
| `feature/taildrop` | [`ts_runtime::taildrop`](ts_runtime/src/taildrop.rs), [`…::taildrop_send`](ts_runtime/src/taildrop_send.rs), [`ts_runtime::peerapi`](ts_runtime/src/peerapi.rs) |
| `feature/ssh` / `ssh/tailssh` | [`src/ssh/`](src/ssh/mod.rs) (behind the `ssh` feature) |
| `feature/acme` + serve/funnel | [`ts_runtime::serve`](ts_runtime/src/serve.rs) (+ the `acme` feature) |
| `util/clientmetric` | [`ts_metrics`](ts_metrics/src/lib.rs) |
| `tstime` | [`ts_time`](ts_time/src/lib.rs) |
| `tstest` | [`ts_test_util`](ts_test_util/src/lib.rs) |
| `tool/` + CI plumbing | [`checks`](checks/src/main.rs) / [`bin/check`](bin/check), [`ts_devtools`](ts_devtools/src), [`ts_cli_util`](ts_cli_util/src/lib.rs), [`ts_hexdump`](ts_hexdump/src/lib.rs) |

### Upstream packages with no counterpart here

Not a backlog — most of these are deliberate scope decisions. Listed so a future porting bead is
cut with its eyes open. Items already tracked in
[`docs/PARITY_ROADMAP.md`](docs/PARITY_ROADMAP.md) are marked *(roadmap)*.

- `derp/derpserver`, `cmd/derper` — DERP **server**/mesh. Client half only here *(roadmap)*.
- `net/udprelay`, `feature/relayserver` — peer-relay endpoint allocation and relay **serving**.
  The relay *client* half is here (`ts_magicsock`'s relay module: the disco `0x04`–`0x09` codecs,
  the 3-way bind handshake and the Geneve-framed relay data path); this node never serves as a
  relay itself, and does not send `AllocateUDPRelayEndpointRequest` — a relay-capable peer
  allocates on our behalf and announces the endpoint with a `CallMeMaybeVia`.
- `net/portmapper`, `feature/portmapper`, `feature/debugportmapper` — UPnP / PCP / NAT-PMP *(roadmap)*.
- `appc`, `feature/conn25`, `types/appctype` — app connectors (classic and conn25) *(roadmap)*.
- `drive`, `feature/drive` — Taildrive.
- `ipn/ipnserver`, `cmd/tailscaled`, `cmd/tailscale` — the daemon and its CLI. This is an embedded
  library; status/WhoIs/id-token are typed methods on `Device` instead.
- `ipn/localapi`, `client/local` — **partial**: the `tsnet` facade serves a one-route LocalAPI
  (`GET /localapi/v0/status`, with Go's `Sec-Tailscale: localapi` header check and Basic auth) in
  [`src/tsnet.rs`](src/tsnet.rs) `mod localapi`; Go's dozens of other endpoints return 404, and
  `Device::loopback` deliberately serves SOCKS5 only ([`src/loopback.rs`](src/loopback.rs)).
- `health` — the health tracker. `tailcfg.DisplayMessage` is modelled in `ts_control_serde`, but
  Go's tracker semantics (warnable state machine, self-diagnosis) are not.
- `logtail`, `logpolicy`, `feature/syslog` — client log upload.
- `wgengine/netlog`, `feature/netlog` — network flow logs *(roadmap: externally blocked)*.
- `net/captivedetection`, `feature/captiveportal` — captive-portal detection.
- `portlist`, `posture`, `feature/posture` — port-list and device-posture reporting to control.
- `net/tshttpproxy` — HTTP proxy support for *outbound control/DERP* dials. (The fork's
  `ProxyExitDialer` is the opposite direction — exit-node egress — and is not a port of this.)
- `sessionrecording`, `tsconsensus`, `prober`, `safeweb`, `tsweb`, `wf`, `util/syspolicy`,
  `clientupdate`, `feature/wakeonlan`, `feature/tap`, `feature/tpm`, `feature/bird`,
  `feature/linkspeed`, `feature/tundevstats`, `feature/routecheck`,
  `feature/favorites`, `feature/serviceclientprefs`, `k8s-operator`, `kube` — platform, operator
  and product surfaces outside the embedded-node scope.
- `feature/remoteconfig` — **partial**, and moved out of the list above at this revision: its
  `c2nPrefix`, `localAPIStrip` and `handleC2NRemoteAPI` (the c2n → LocalAPI proxy of capver 142) are
  ported into `ts_control/src/tokio/ping.rs`; the rest of the package — the remote-config prefs
  surface and its CLI — is not.
- `ts_ffi`, `ts_python`, `ts_elixir` have no upstream counterpart in `tailscale/tailscale` at all —
  Go's C bindings live in the separate `tailscale/libtailscale` repository.

## Gap list

Every row was checked against the pinned upstream commit **and** against this tree; the evidence
is named inline so a reviewer can re-check a single row without re-deriving the whole ledger.
Assessments are one of **needs port**, **not applicable**, **already covered**.

### A. Capability versions 131 → 145

This is the sharpest available axis: `tailcfg.CurrentCapabilityVersion` is upstream's own record of
every client behaviour change that control can observe. The window is anchored to capver 130, the
last version this port tracked before the ledger existed; the declaration here is **125**, held
below 126, see §B. Upstream is still at **145** at the new pin, so the window is the same fifteen
versions the previous revision covered — what moved is *this tree*, which has since ported three of
them (135, 142, 144). Descriptions are upstream's own (`tailcfg/tailcfg.go`, `tailcfg/nodecap`).

Three rows changed assessment since the previous revision, all in the same direction — **needs
port** → **already covered** — and all because work landed here, not because upstream moved. Each
says so inline.

| Ver | Date | Upstream change | Assessment |
| --- | --- | --- | --- |
| 131 | 2025-11-25 | Client respects `NodeAttrDefaultAutoUpdate` | **not applicable** — self-updating a client binary; this is an embedded library with no updatable binary (`Hostinfo.allows_update` is modelled and false by default) |
| 132 | 2026-02-13 | Client respects `NodeAttrDisableHostsFileUpdates` | **not applicable** — nothing here writes a hosts file; upstream notes the attr is Windows-only as of 2026-02, and there is no Windows `ts_host_net` backend |
| 133 | 2026-02-17 | `NodeAttrForceRegisterMagicDNSIPv4Only`; MagicDNS IPv6 registered with the OS by default | **needs port** — upstream `net/dns/config.go` `serviceIPs` registers **both** `100.100.100.100` and the IPv6 service IP with the OS resolver *by default*, and falls back to IPv4-only when control sets the attr. This tree registers IPv4 only *unconditionally* — which is upstream's attr-set branch, not its default — so the behaviours are not equivalent. Wider than a type signature: the IPv6 MagicDNS service IP is not served here at all (`ts_runtime::magic_dns` binds `100.100.100.100:53` only; `ts_host_net::HostDns::nameservers` is `Vec<Ipv4Addr>` for both the Linux and macOS backends), so registering it before serving it would point the host resolver at a dead address. The port is: serve MagicDNS on the IPv6 service IP, register both by default, honour the attr to drop back to IPv4-only. Host-OS-facing, not wire-facing — no peer or control plane observes it directly — and it pairs with `Config::enable_ipv6` |
| 134 | 2026-03-09 | Client understands `NodeAttrDisableAndroidBindToActiveNetwork` | **not applicable** — Android-only socket binding |
| 135 | 2026-03-30 | Client understands `NodeAttrCacheNetworkMaps` (and `DisableCacheNetworkMaps`, #19947) | **already covered** — *changed from "needs port (optional)"*: the cache landed here in #320 after the previous revision was written. `ts_control/src/tokio/netmap_cache.rs` persists the raw decompressed `MapResponse` to `<Config::netmap_cache_dir>/netmap.json` (0600 under a 0700 directory, temp-file rename), `ts_runtime/src/control_runner.rs:1472` loads it before the control client exists, and *both* attributes are honoured — `disable-cache-network-maps` takes precedence and discards an existing cache, as upstream documents. Inert unless the embedder configures storage **and** control grants the attribute |
| 136 | 2026-04-09 | Client understands `NodeAttrDisableLinuxCGNATDropRule` | **not applicable** — `ts_host_net` programs routes and DNS only; it never installs firewall rules, so there is no CGNAT DROP rule to disable |
| 137 | 2026-04-15 | Client handles 429 responses to `/machine/register` | **already covered** — `ts_control/src/tokio/register.rs:261` parses the 429 plus its retry delay into a typed rate-limit error instead of an opaque HTTP error |
| 138 | 2026-03-31 | Can handle c2n `/debug/tka` (`/debug/tka/log`) | **not applicable (declaration held below it)** — the c2n responder (`ts_control/src/tokio/ping.rs`) serves `/echo`, `GET /vip-services` and the `/remoteapi/localapi/*` prefix; `/debug/tka/log` is not among them and takes Go's own `400`/`unknown c2n path` fallthrough, which is asserted by test. The declared capability version is held below the versions that promise it, so control never asks. Resolved together with 127 and 128; see §B |
| 139 | 2026-05-22 | Client understands `NodeAttrEmitRuntimeMetrics` (emit Go `runtime/metrics` as clientmetrics) | **not applicable** — the attr exports the *Go runtime's* metrics; there is no Rust equivalent. `ts_metrics` already mirrors `util/clientmetric` itself |
| 140 | 2026-05-27 | Client understands `NodeAttrDisableUDPGRO` / `DisableUDPGSO` / `DisableTUNUDPGRO` / `DisableTUNTCPGRO` | **not applicable** — no GRO/GSO offload on this datapath (`ts_transport_tun` is single-queue, no offload), so there is nothing for control to disable |
| 141 | 2026-05-28 | Client understands `NodeAttrNeverGSOEqualTail` | **not applicable** — same: the attr is a workaround for kernel GSO batching this port does not do |
| 142 | 2026-07-06 | Client understands c2n `/remoteapi/localapi/*` proxy (`feature/remoteconfig`) | **already covered** — *changed from "needs port (narrow)"*: #317 gave the responder the prefix route it lacked. `ts_control/src/tokio/ping.rs` now walks Go's own dispatch order (exact method+path, exact path, then prefixes, then the 400), strips `/remoteapi`, and carries all four of `handleC2NRemoteAPI`'s refusals. Caveat worth keeping in view: control gates this request on the *declared* capability version, so with 125 declared the handler is implemented but unreachable. A capability version is a contiguous claim, so it becomes live only once 126 through 141 are all implementable — see §B for the full list standing in the way |
| 143 | 2026-07-22 | Client correctly ignores conn25 node attributes when not enabled by environment variable | **not applicable** — no app connector of either generation here, so conn25 attributes are already ignored |
| 144 | 2026-07-31 | Client sends `packet.TSMPDiscoKeyAdvertisement` around WireGuard handshakes | **already covered** — *changed from "needs port"*: the send half landed in #314 and #318, so both halves are now here. `ts_packet::tsmp` marshals against Go's own `TestTSMPDiscoKeyAdvertisementMarshal` vectors, `ts_tunnel` reports the two moments `wireguard-go` calls `SendPriorityMessage`, and `ts_dataplane` chooses the content (Go `magicsock.Conn.PriorityMessageForPeer`). Unlike 142 this is peer-observable regardless of the declared version — the client sends it unprompted — so it is the one changed row a real Go peer can see |
| 145 | 2026-08-04 | Client understands `NodeAttrScopeQuad100OnMacOS` | **not applicable** — the attr changes resolver ordering for the *sandboxed* macOS app; `ts_host_net::macos` installs a service-scoped `scutil` DNS dictionary and has no default-resolver behaviour to scope |

Net: of the fifteen versions upstream added, **one still needs a port** — 133, host-OS-facing —
**four are already covered** (135, 137, 142, 144), and the remaining ten are not applicable to an
embedded userspace node (138 among them, once the declaration was held below the version that
promises it). The previous revision counted five needing a port; three of those five landed here in
the interval and one (138) was resolved by the declaration, leaving 133.

### B. Behaviour upstream changed in the window that is not capver-gated

Derived from `git log --since=2025-10-06` over the packages that map to crates here, with
docs/typo/refactor commits filtered out. The sweep list itself was widened at this revision — see
*New at this revision* below and the note in [Re-deriving this ledger](#re-deriving-this-ledger).

- **TSMP disco-key advertisement** (`net/packet`, `net/tstun`, `wgengine/magicsock`,
  `control/controlclient`: `c54d24369`, `c870d3811`, `bf467727f`, `82a381e54`, `014d5bd9e`) —
  peers now advertise their disco key in a TSMP message around the WireGuard handshake, and learn a
  peer's disco key from it without restarting WireGuard. It is the one item here a real Go peer will
  *send us* unprompted. **Both halves are now covered** — *changed from "receive side covered, send
  side needs a port"*, because the send half landed here in #314 and #318 after the previous
  revision. Receive: `ts_packet::tsmp` decodes the advertisement (Go
  `Parsed.AsTSMPDiscoAdvertisement`), `ts_dataplane::filter_inbound_from_peer` consumes it ahead of
  the ACL and drops it rather than delivering it to the local stack (Go
  `tstun.filterPacketInboundFromWireGuard` returning `filter.DropSilently`), and
  `PeerTracker::learn_disco_key` applies it to the peer (Go
  `magicsock.Conn.HandleDiscoKeyAdvertisement`). Send: `ts_packet::tsmp` marshals it against Go's own
  `TestTSMPDiscoKeyAdvertisementMarshal` vectors, `ts_tunnel` reports the two moments `wireguard-go`
  calls `SendPriorityMessage` (`device/receive.go`) and carries its refusals (empty or oversize is
  dropped, not truncated; a peer with no live keypair sends nothing, so a priority message never
  triggers a handshake), and `ts_dataplane` decides the content (Go
  `magicsock.Conn.PriorityMessageForPeer`). Row 144 above is the capability-version view of the same
  work.
- **IPv6 fragment extension-header handling in the filter** (`net/packet`, `wgengine/filter`:
  `4c4ec3d46`, `26b2ed0a6`) — upstream extended its RFC 1858-style fragment classification to IPv6
  fragment extension headers. **Needs port only under `Config::enable_ipv6`**: `ts_dataplane`
  implements the classification for IPv4 only (`Ipv4Fragment`, `MIN_FRAG_BLKS`), which matches the
  default IPv4-only posture but leaves the opt-in IPv6 path without upstream's fragment rules.
- **Peer relay** (`disco` 0x04–0x09, `net/udprelay`, `feature/relayserver`; capver 120/121, i.e.
  *behind* the declared 125) — **ported (client half)**. All nine disco message types now have a
  codec (`ts_disco_protocol`'s relay module, checked against Go's own `disco_test.go` vectors), and
  `ts_magicsock` runs the client side end to end: an inbound `CallMeMaybeVia` starts the 3-way bind
  handshake with the named relay server, and a relayed ping/pong confirms a Geneve-framed path that
  carries WireGuard data instead of falling back to DERP. Direct paths still take priority over
  relay ones, as upstream requires. Not ported, and out of scope for an embedded client: **serving**
  as a relay (`net/udprelay.Server`, `feature/relayserver`) and *requesting* an allocation of our
  own — the `AllocateUDPRelayEndpointRequest`/`Response` pair is decoded but never originated,
  because a relay-capable peer allocates on our behalf.
- **c2n endpoints behind the declared capability version** — capver 127 (`/debug/netmap`), 128
  (`/debug/health`) and row 138 (`/debug/tka/log`) share one responder
  (`ts_control/src/tokio/ping.rs`), which serves `/echo`, `GET /vip-services` and — since #317 — the
  `/remoteapi/localapi/*` prefix of row 142. The three debug endpoints are **resolved by holding
  `CapabilityVersion::CURRENT`** below them, which was the alternative to porting the three handlers.
  Porting them was rejected on evidence, not preference: each needs a subsystem this tree does not
  have. `handleC2NDebugNetMap` marshals a whole `netmap.NetworkMap` (there is no netmap aggregate
  here — the netmap arrives as `StateUpdate` deltas accumulated by the runtime's peer tracker, which
  the responder cannot see, and control unmarshals the body back into Go's struct, so any field we
  could not fill would read as a zero value rather than as "unknown"); `handleC2NDebugHealth`
  marshals `health.Tracker.CurrentState()` and this fork has no health subsystem; and
  `handleC2NDebugTKALog` serves the AUM chain, which lives in `ts_runtime` because `ts_control`
  deliberately does not depend on `ts_tka`. All three now take Go's own `400`/`unknown c2n path`
  fallthrough (`handleC2N`, `ipn/ipnlocal/c2n.go`), which is asserted by test. The declaration
  landed at **125**, not 126: capver 126 (seamless key renewal) is not implemented here either —
  this tree's expiry recovery is a node-key rotation plus a full re-register
  (`ts_control::Config::reauth_on_expiry`), which is upstream's *non*-seamless path. 125 is also the
  capability version Tailscale `v1.88.0` declares, so it pairs with a real release for the
  `IPNVersion` in `ts_control::hostinfo`. **The declaration is now what gates row 142.** A capability
  version is a contiguous claim, not a set: to declare 142 a node must implement everything from 126
  up, so the c2n LocalAPI proxy that #317 ported sits behind 126 (seamless key renewal, not implemented),
  127 and 128 (two of the three c2n debug endpoints rejected on evidence above), 130
  (`key.HardwareAttestationPublic` / `…KeySignature` in `MapRequest`, no counterpart here) and 138.
  Control will not send `/remoteapi/localapi/*` to a node declaring 125, so that handler is correct,
  tested and dormant, and will stay dormant until that whole run is closed. Recording it here so the
  next reader does not mistake a dormant handler for a broken one — and so a future bead to raise the
  declaration is cut against the full list, not against 126 alone. (129 — a sleep/wake deadlock fix
  in Go's own peer-relay code — is a bug fix in an implementation this tree does not share, so it
  costs nothing.)
- **Services model extension** (`tailcfg`: `1cd8bcc82`, `6cd185bf3`, `fc9b18f50`) — upstream added
  client application *actions* (with attributes and `ServiceActionType` constants) to the VIP
  services model. **Needs port** only for the consume side to stay current:
  `ts_control_serde/src/service_vip.rs` models `VipService` and the c2n response with no action
  types.
- **`Node.IsRouter` / `PeerStatus.IsRouter`** (`8d830599b`) — **already covered** as of this
  ledger revision. Note the row's original wording ("a new status/netmap field") was wrong and is
  corrected here: upstream added no wire field. `tailcfg.Node.IsRouter` and
  `ipnstate.PeerStatus.IsRouter` are *derived predicates* — "does this node route addresses
  besides its own" — spelled as methods so IPN-bus watchers can classify routers out of the netmap
  they already hold. Control sends nothing new, so there was never a round-trip to match; adding
  an `IsRouter` JSON key would have been a divergence, not a port. Mirrored here as
  `ts_control::Node::is_router` (over `accepted_routes` vs `tailnet_address`) and
  `ts_runtime::status::StatusNode::is_router` (over `allowed_routes` vs `ipv4`/`ipv6`), both
  covering the present *and* absent case, and cross-checked against each other the way upstream's
  `TestNodeIsRouter` cross-checks its two definitions.
- **DERP `ClientInfo.AppName`** (`246c82a65`, `75519889f`) — clients may advertise an opaque app
  name (≤32 bytes printable ASCII) which servers relay to watchers and can ban on. **Not
  applicable** — the field is `omitempty` and optional, and `ts_derp`'s `ClientInfoPayload` simply
  omits it, which is what a Go client without the option does. Note the related `FramePeerPresent`
  extension (flags byte + app-name suffix) is mesh-only: `ts_derp` classifies `PeerPresent` as
  privileged and a leaf client never subscribes, so the fixed-size parser is not an interop risk.
- **`NodeAttrClientSideReachabilityRouteCheck` + `net/routecheck`** (`2fbd30824`) — client-side
  route reachability checking. **Not applicable** — no counterpart subsystem; the attribute is
  ignored, which is the correct behaviour for a client that does not implement it.
- **Upstream's `encoding/json/v2` compatibility fixes** (`82cfea90c`) — upstream adjusted JSON
  serialization for Go 1.27's finalized `encoding/json/v2`. **Needs an audit, not a port**:
  `ts_control_serde` hand-mirrors Go's PascalCase/`omitempty`/`omitzero` choices field by field, so
  any tag semantics upstream changed must be re-checked against the wire. Nothing observed to have
  broken; this row exists so the audit is not forgotten.

#### New at this revision

Two things produced this list. Upstream moved four commits (`1e69418` → `49e148c`), and the sweep
list itself was widened — `net/socks5`, `net/tsdial`, `net/tlsdial`, `net/bakedroots`,
`ipn/localapi`, `feature/remoteconfig` and `tsnet` are all covered by
[Package mapping](#package-mapping) above, whether as a table row or as a *partial* entry in the
no-counterpart list, and none of them was in the `for p in …` loop, so a whole class of upstream
change had been going unseen. All four new commits landed in packages that were unswept, which is
why three of them are here and not in the previous revision.
The loop is corrected in [Re-deriving this ledger](#re-deriving-this-ledger); the last three bullets
below predate the pin move and were surfaced only by the widening.

- **SOCKS5 proxy credentials compared in constant time** (`net/socks5`: `60576f8bd`) — upstream's
  SOCKS5 server checked the client-supplied username and password with plain string equality, which
  returns on the first differing byte, and replaced both comparisons with
  `subtle.ConstantTimeCompare`, evaluating both halves so the username result does not gate whether
  the password is examined. **Needs port** — and the same asymmetry upstream fixed exists here.
  `src/loopback.rs`'s `negotiate` does
  `uname.as_slice() == PROXY_USERNAME.as_bytes() && passwd.as_slice() == cred.as_bytes()`: two
  data-dependent comparisons, the second short-circuited by the first. The threat model is upstream's
  own and it transfers unchanged: `gen_cred` mints a 16-byte random credential that gates every dial
  into the tailnet, the listener is on `127.0.0.1`, and any local process may retry without limit, so
  a reject that is timeable leaks the credential a byte at a time. The fix needs no new dependency —
  `src/tsnet.rs`'s `localapi::cred_ok` is already a constant-time comparison (this fork's mirror of
  the `subtle.ConstantTimeCompare` Go's LocalAPI has always used), so the SOCKS5 path is the one
  place on the loopback that does not use it. Host-facing, not wire-facing; no peer or control plane
  observes it.
- **`tsnet.Server.HTTPClient` built from `http.DefaultTransport`** (`tsnet`: `49e148c4a`) — upstream
  stopped returning `&http.Client{Transport: &http.Transport{DialContext: s.Dial}}` and now clones
  `http.DefaultTransport`, overriding `DialContext` and setting `Proxy` to nil, so the client picks
  up `ForceAttemptHTTP2`, `MaxIdleConns`, `IdleConnTimeout`, `TLSHandshakeTimeout` and
  `ExpectContinueTimeout` — and any default Go adds later. **Needs port** (narrow, host-facing).
  `Server::http_client` (`src/tsnet.rs`) builds a `hyper_util` legacy client over the tailnet
  connector with the builder's own defaults, and its doc comment still calls itself "the exact
  analog of Go's `&http.Client{Transport: &http.Transport{DialContext: s.Dial}}`" — a sentence that
  described upstream accurately until this commit and no longer does. The port is to decide, per
  setting, what the `hyper` equivalent of each `http.DefaultTransport` default is, apply it, and
  correct the comment. The `Proxy = nil` half is already structurally true here: `TailnetConnector`
  dials the overlay directly and has no environment-proxy path to disable. Upstream's own test
  (`TestHTTPClientDefaultTransport`) fails on any unrecognised future field, which is the shape worth
  copying — a test that forces a decision rather than one that drifts.
- **`Dialer.Close` no longer touches the peerapi transport when omitted** (`net/tsdial`:
  `72780705e`) — **not applicable**. The bug is that Go's `Dialer.Close` called `PeerAPITransport()`
  unconditionally, which panics in a binary built with the `ts_omit_peerapiclient` build tag. There
  are no build tags here and no equivalent unconditional accessor; the peerapi client is ordinary
  Rust state whose absence is an `Option`, not a panic.
- **`Sys.ExtraRootCAs` plumbed through the TLS dial paths** (`net/tlsdial`: `a182b864a`) —
  **already covered**, and by an older mechanism than upstream's. `ts_tls_util` builds its
  `RootCertStore` from `webpki_roots::TLS_SERVER_ROOTS` and additively loads extra trust anchors from
  the PEM file named by `TS_RS_EXTRA_CA_PEM`, which is the same capability (trust a self-hosted
  control plane's private CA without disabling verification) reached by configuration rather than by
  a `tsd.Sys` field. Failure to load is logged and non-fatal, so a bad path cannot silently weaken
  trust — it surfaces as a handshake error. Recorded so the row is not re-cut as a gap.
- **LetsEncrypt Generation Y roots (`YE`, `YR`)** (`net/bakedroots`: `f65372c9b`) — **not
  applicable as a port**, but it names a real maintenance obligation. Go bakes a hand-curated root
  list into the binary because a Go client cannot rely on the OS trust store everywhere; this tree
  has no such list to append to, because `webpki-roots` (1.0.9 in `Cargo.lock`) *is* the compiled-in
  bundle and tracks Mozilla's set on the crate's own release cadence. So there is nothing to port —
  but the obligation upstream discharges by editing `bakedroots.go` is discharged here by keeping
  that dependency current, which is a `cargo update` in its own PR (see
  [`CONTRIBUTING.md`](CONTRIBUTING.md#dependencies)), not a code change. A stale `webpki-roots` is
  the failure mode this row exists to name: it looks like nothing until a CA rotates and control or
  DERP stops verifying.
- **`UserDial` happy eyeballs, and `UserDialPlan` for non-Tailscale addresses** (`net/tsdial`:
  `f3a117e81`, `0e10a3f58`; both predate the previous pin and were missed only because the package
  was unswept) — **not applicable as the tree stands**. Both are about `tailscaled` dialling *on
  behalf of a local user process*: racing A and AAAA candidates with a 300 ms delay when userspace
  networking sits behind an exit node, and letting the LocalAPI `/dial` handler tell a client to
  dial a non-Tailscale address itself. Neither has a target here. This fork's overlay is IPv4-only
  by default and its MagicDNS resolver returns a single `Option<Ipv4Addr>` (`loopback::Resolver`),
  so there is no second address family to race; and the one-route LocalAPI serves no `/dial`. The
  first would become live if IPv6 MagicDNS lands — it pairs with row 133 and `Config::enable_ipv6`,
  and is noted here so that port is not written IPv4-shaped a second time.

Deliberately **not** listed: upstream refactors with no observable behaviour (the
`tailcfg/{nodecap,selfcap}` package split, `DERPRegionID` typing, `NodeMutationAdd` →
`NodeMutationUpsert`, the `feature/` build-tag reorganization, removal of `LazyWG` and the engine
watchdog, `types/netmap` field removals), and upstream-internal locking/allocation fixes in
`control/controlclient`, `derp/derpserver` and `ipn/ipnlocal`. From the newly swept packages: the
tree-wide renames and modernizers that touched `net/socks5` (`bd2a2d53d`, `2810f0c6f`, `3ec5be3f5`,
`c2e474e72`) and the `net/tsdial` commits that only follow upstream's own refactors of
`types/netmap`, `netmon` and `syncs`. `tsnet` itself has 124 commits in the window and is **not**
re-derived here: that facade has its own line-by-line parity matrix in
[`docs/TSNET_PARITY.md`](docs/TSNET_PARITY.md), and duplicating it into this ledger would create two
records that disagree. Only `tsnet` changes that alter behaviour a mapped crate already implements
are pulled in, as `49e148c4a` was above.

### Re-deriving this ledger

```sh
# The capability-version window (§A): everything above CapabilityVersion::CURRENT here.
git -C <tailscale-go> grep -n 'CurrentCapabilityVersion CapabilityVersion' 49e148c -- tailcfg/tailcfg.go
git -C <tailscale-go> grep -nE '^//[[:space:]]*-[[:space:]]*1[3-9][0-9]:' 49e148c -- tailcfg/tailcfg.go

# What upstream touched per mapped package since capver 130 landed (§B).
for p in tailcfg disco derp net/packet net/tstun wgengine/filter wgengine/magicsock \
         net/netcheck net/stun control/controlclient control/controlbase tka \
         net/dns wgengine/netstack net/udprelay types/key \
         net/socks5 net/tsdial net/tlsdial net/bakedroots ipn/localapi \
         feature/remoteconfig tsnet; do
  echo "== $p"; git -C <tailscale-go> log --since=2025-10-06 --oneline -- "$p"
done

# Only what moved since the pin this ledger currently carries — the fast path on a re-derivation
# that follows soon after the last one. Read it *in addition to* the full sweep, never instead of
# it: a row's assessment can change because this tree moved, with upstream perfectly still.
git -C <tailscale-go> log --oneline 49e148c..<new-pin>
```

The capability-history pattern is deliberately whitespace-tolerant: upstream writes those entries as
`//   - 133: …`, but the exact indentation is a comment convention, not something `gofmt` enforces,
and a pattern that pins it would go silently empty the day it changes. Check the row count rather
than trusting the exit status — at the pinned commit the second command returns **16 lines**, 130
through 145, i.e. the fifteen-version window of §A plus the 130 row that anchors it. An empty or
short result means the pattern broke, not that upstream added nothing.

**The sweep list is part of the ledger, and it was wrong.** The loop above gained
`net/socks5`, `net/tsdial`, `net/tlsdial`, `net/bakedroots`, `ipn/localapi`,
`feature/remoteconfig` and `tsnet` at this revision. All seven are covered by
[Package mapping](#package-mapping) at the top of this document — five as table rows,
`ipn/localapi` and `feature/remoteconfig` as *partial* entries in the no-counterpart list below it —
and none of them was being swept, so upstream changes to the SOCKS5 loopback,
the user-facing dialer, the baked root certificates, the LocalAPI and the `tsnet` facade were
invisible to every previous re-derivation. That is how upstream's constant-time fix to the SOCKS5
credential comparison — the sharpest new row in §B — reached this ledger only at the revision that
widened the loop, rather than at the one after it landed. When [Package mapping](#package-mapping)
gains an upstream package — a table row or a *partial* entry alike — add it here too, or the mapping
is a claim the sweep never checks.
Two of the additions are noisy by nature and should be read with that in mind: `ipn/localapi` catches
every multi-package commit that also touched `cmd/tailscale`, most of which is the daemon CLI this
library deliberately does not have, and `tsnet` is swept but not itemised row-by-row in §B — see the
note at the end of §B for why.

When the pin is advanced, bump the header table, re-run the above, and rewrite §A and §B. A row
whose assessment changes should say *why* it changed — and note that "why" is as often *this* tree
moving as upstream moving: at this revision every changed row changed because a port landed here
while upstream stood still.

## The quality bar for port PRs

A port PR is a claim that a behaviour now matches upstream Go. The bar exists so the claim is
checkable.

1. **One focused area per PR.** One gap-list row, or one coherent slice of one row (the TSMP
   receive side is a fine PR; "TSMP plus services actions" is not). A PR that fixes two things
   cannot be reviewed against either. Anything else you find on the way goes in the PR body as a
   note, not in the diff.
2. **Real tests that exercise the ported behaviour.** Not "it compiles", not a test that only
   asserts the shape of a struct: a test that would fail if the behaviour were wrong. For wire
   formats, assert against bytes taken from the Go implementation or its test vectors; for
   decisions (filter verdicts, fail-closed drops, retry timing), assert the decision, and assert
   the negative case too — the drop that must still happen, the fallback that must *not* be taken.
3. **Cite the upstream source in the code.** Name the Go function, file or commit the behaviour
   comes from in a doc comment, the way the existing crates do — "Go `runIn4`", "Go
   `tkaFilterNetmapLocked`". That citation is what makes the next re-derivation of this ledger
   cheap.
4. **The full gate is green before you push:**
   ```sh
   TS_RS_EXPERIMENT=this_is_unstable_software bin/check
   ```
   `cargo +nightly fmt --check`, `cargo run -p checks` (the anti-leak check), `cargo clippy` over
   the lib and then over bins/tests/benches/examples with `-D warnings`, `cargo doc`,
   `cargo deny check all`, `cargo machete`, `cargo nextest run --all-features`,
   `cargo test --doc`, and `cargo build --all-targets`. Run it locally and mean it — it is
   strictly wider than what CI checks on this fork: the job carrying fmt/deny/machete
   (`arch_independent`) is gated to the upstream repository owner and never runs here, and
   `bin/check` passes `--all-features` where the hosted job passes only `--workspace`, so
   feature-gated code is linted and tested locally and nowhere else. The corollary: if a step
   fails on code your change does not touch, re-run it against the base commit before chasing it —
   the wider flags surface pre-existing, feature-gated findings that CI has never seen. The pair
   that answers "is this green" is the `rust` workflow's `hosted test` job plus
   `cargo run -p checks`.
   `ts_forwarder/tests/forwarding.rs::udp_forwarder_splices_subnet_route_to_real_socket` is a
   real-UDP timing test that flakes under load — re-run it, do not "fix" it.
5. **Interop first, and fail-closed stays fail-closed.** This engine is always the dialing client
   against real Tailscale, `wireguard-go` and kernel peers: never ship a change that assumes the
   peer implements a fork-specific behaviour. The invariants in
   [`docs/PARITY_ROADMAP.md`](docs/PARITY_ROADMAP.md#invariants-that-must-never-regress) — no
   origin-IP leak, no silent direct-dial fallback, `ring`-only on the tailnet/TLS path,
   `panic=unwind` — outrank parity: if upstream Go does something this fork's anti-leak posture
   forbids, document the divergence here rather than porting it.
6. **No new dependencies on the egress path**, and dependency changes ride in their own PR — see
   [`CONTRIBUTING.md`](CONTRIBUTING.md#dependencies).
