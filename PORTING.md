# Porting ledger: upstream Go `tailscale` → this repository

| | |
| --- | --- |
| **Upstream source** | `https://github.com/tailscale/tailscale` (Go) |
| **Upstream commit this ledger was written against** | `d9cc55e33b4a9f092e21b882df39aa4005cb0fa4` (2026-08-31, `tsnet: avoid depending on mutable DefaultTransport`) |
| **Upstream `tailcfg.CurrentCapabilityVersion` at that commit** | **145** (2026-08-04) — unchanged from the previous two pins |
| **This repository at ledger time** | `7c39ae0` — workspace version `0.44.0` |
| **`ts_capabilityversion::CapabilityVersion::CURRENT` here** | **125** (2025-08-11) — held below 126; see §B, *c2n endpoints behind the declared capability version* |
| **Gap window this ledger covers** | capability version **131 → 145**, i.e. upstream commits from 2025-10-06 to 2026-08-31 (the window is anchored to when capver 130 landed upstream; the declaration here being 125 rather than 130 does not change what upstream added) |
| **Previous pin** | `49e148c4a30b4f8098f69468fd27a7021d85ea02` (2026-08-30). Only two upstream commits separate the two, one of them in a mapped package — but the sweep list was widened again at this revision, which is where the new rows came from. See §B, *New at this revision* |

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
below 126, see §B. Upstream is still at **145** at the new pin — `tailcfg/tailcfg.go:197` — so the
window is the same fifteen versions the previous revision covered. Descriptions are upstream's own
(`tailcfg/tailcfg.go`, `tailcfg/nodecap`).

**No row changed assessment at this revision.** Both halves of the usual reason are absent:
upstream added no capability version between `49e148c4a` and `d9cc55e33`, and no port landed in
this tree in the interval either — the only two commits here since the last revision are the two
documentation passes that produced and then corrected it (#323, #324). The three rows the previous
revision flipped (135, 142, 144) still say why they flipped, because that history is what makes the
row re-checkable; they did not move again. §B is where this revision's changes are.

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
promises it). That is the same count the previous revision reached, and for the same reasons: this
axis stood still on both sides. Row 133 was re-checked against the tree at this pin and is still
open — `ts_host_net::HostDns::nameservers` is a `Vec<Ipv4Addr>`, and `ts_runtime::tun_actor` fills
it with the single IPv4 service IP, so there is still no IPv6 MagicDNS address to register.

### B. Behaviour upstream changed in the window that is not capver-gated

Derived from `git log --since=2025-10-06` over the packages that map to crates here, with
docs/typo/refactor commits filtered out. The sweep list itself was widened at this revision — see
*New at this revision* below and the note in [Re-deriving this ledger](#re-deriving-this-ledger).

- **TSMP disco-key advertisement** (`net/packet`, `net/tstun`, `wgengine/magicsock`,
  `control/controlclient`: `c54d24369`, `c870d3811`, `bf467727f`, `82a381e54`, `014d5bd9e`,
  `3799eaf26`, `fb27d87e0`) —
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
  Two upstream commits that the previous revision did not name are worth recording, because both
  turn out to *confirm* what is here rather than to open a gap. `3799eaf26`
  (`wgengine/magicsock`, `wgengine`) replaced the periodic advertiser — a 2-minute timer with
  suppression rules bolted on (`c76113ac7`, `92ab4866d`, `ee76a7d3f`, `54005752a`) — with the
  single `SetPriorityMessageOnEstablishmentFunc` callback that `wireguard-go` invokes on rekey. At
  the pin there is no periodic sender left in `wgengine/magicsock/magicsock.go`, so the
  establishment-only send this tree implements is upstream's current shape, not a subset of it.
  And `fb27d87e0` (`net/tstun/wrap.go`) removed the `buildfeatures.HasCacheNetMap &&
  envknob.BoolDefaultTrue("TS_USE_CACHED_NETMAP")` guard from the *receive* side, so a Go node now
  consumes any advertisement carrying a non-zero key regardless of whether it participates in
  netmap caching — which is exactly what `ts_dataplane::filter_inbound_from_peer` has always done
  (the only guard here is the zero-key check, and the advertisement is still dropped rather than
  delivered). Upstream converged on this tree's behaviour; nothing to do.
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

Upstream moved almost nothing: two commits (`49e148c` → `d9cc55e3`), one of them
(`2a4d74356`, `wgengine/netstack`) a data-race fix on a *test* logger in a Go test helper
(`makeHangDialer`) with no production counterpart, and the other (`d9cc55e33`) a revision of the
`tsnet` row already above. Everything else new here came from **widening the sweep list a second
time**.

The previous revision widened the loop by seven packages and wrote down the rule that produced
them: *every upstream package [Package mapping](#package-mapping) names must be in the sweep, or the
mapping is a claim the sweep never checks.* Applying that rule literally at this revision shows it
was not finished. Sixteen more mapped packages were still unswept: `wgengine` itself (only three of
its subdirectories were in the loop, so `wgengine/userspace.go`, `wgengine/wgcfg` and
`wgengine/router` were not), `ipn` (only `ipn/localapi` was, so `ipn/ipnlocal`, `ipn/ipnstate` and
`ipn/store` were not), and then `net/netmon`, `net/art`, `control/controlhttp`, `types/persist`,
`feature/identityfederation`, `feature/taildrop`, `feature/ssh`, `feature/acme`, `ssh/tailssh`,
`util/clientmetric`, `tstime`, `tstest`, `tool/` and `tsd`.
The loop in [Re-deriving this ledger](#re-deriving-this-ledger) is rewritten to cover all of them,
and is now built from parent paths (`wgengine`, `ipn`) so that a *new* subdirectory upstream adds
cannot fall outside it the way `wgengine/router` did.

Two of the rows the widening surfaced need a port; the rest are recorded so the next re-derivation
does not re-cut them.

- **Quad-100 traffic is absorbed locally regardless of port and protocol** (`wgengine/netstack`:
  `1b4091161`) — **needs port**, and it is the sharpest row at this revision. Upstream's
  `handleLocalPackets` used to intercept traffic to the Tailscale service IP only for an
  allow-list — TCP 53/80/8080, UDP 53 — and returned `filter.Accept` for everything else, letting
  the packet fall through to the ACL filter and on to `wireguard-go`. Upstream removed the
  allow-list: quad-100 is now absorbed into netstack unconditionally, "so such traffic never
  reaches the conntrack / peer-routing layers", and a companion `hittingServiceIP` case in
  `acceptTCP` RSTs an unserved quad-100 TCP port instead of falling through to the
  `isTailscaleIP` branch that rewrote the dial to `127.0.0.1:<port>`.
  This tree has the same allow-list, and in **TUN transport mode it has the leak upstream closed**.
  `ts_runtime::tun_actor`'s `classify_magic_dns` intercepts an inbound packet only when it is
  IPv4 **and** UDP **and** destined to `100.100.100.100:53`; every other packet takes
  `Intercept::NotIntercepted` and is handed to the overlay unchanged. `tun_actor` steers
  `100.100.100.100/32` into the TUN whenever MagicDNS is enabled, so the host really does emit such
  packets — a stub resolver speculatively trying DoT on `100.100.100.100:853` is upstream's own
  cited example. `ts_overlay_router` then resolves the destination against the outbound table, and
  that table carries a configured exit node's `0.0.0.0/0` as `RouteAction::Wireguard(peer)`
  (`ts_runtime::route_updater`), which matches `100.100.100.100`. With an exit node selected — the
  configuration this fork exists for — the node's own service-IP traffic is encrypted and sent to a
  peer. Without one it is merely dropped as unrouted, which is why this has not been visible.
  The **netstack** transport is already correct and needs no change: `ts_runtime::netstack_actor`
  gives the netstack interface `100.100.100.100` as a local address, so all quad-100 traffic
  terminates there whatever its port or protocol. The second half of upstream's fix is
  **not applicable**: this tree has no `isTailscaleIP` → host-loopback dial rewrite for an
  unserved port to fall through to, so there is nothing to guard.
- **The DNS forwarder sets TC against the *client's* size limit, not just its own read buffer**
  (`net/dns/resolver`: `8cac8b117`) — **needs port (narrow)**. Upstream added
  `checkResponseSizeAndSetTC` and calls it on every path that returns a UDP answer: if the response
  exceeds the EDNS buffer size the *request* advertised — or 512 bytes when the request carried no
  EDNS OPT record, per RFC 1035 — the TC bit is set (the body is left intact), so the stub resolver
  knows to retry over TCP.
  Here, `ts_dns_wire` already does this correctly for the answers this node *builds* itself: it
  caps an authoritative response at 512 and sets TC when it drops an answer, asserted by
  `oversized_answer_set_sets_tc_and_caps_512`. The gap is the **forwarded** path.
  `ts_runtime::magic_dns`'s `cap_response` sets TC only when the upstream reply exceeds
  `MAX_UPSTREAM_RESPONSE` (4096) and has to be chopped mid-message. A reply between the client's
  limit and 4096 — say 900 bytes for a client that sent a plain, non-EDNS query — is relayed
  verbatim with TC clear, where Go would set it. The port is to parse the forwarded request's OPT
  record for its advertised UDP size, default to 512 when absent, and set TC when the reply exceeds
  it; the existing 4096 cap stays as the read bound it already is. Narrow in practice, because the
  query is forwarded verbatim and a well-behaved upstream honours the EDNS size itself — but "the
  upstream is well-behaved" is exactly the assumption upstream stopped making. Host-facing, not
  wire-facing.
- **DNS is still configured when router programming fails** (`wgengine`: `cfd101f9d`) — **not
  applicable: deliberate divergence, and it should stay one.** Upstream's `Reconfig` returned on
  any `router.Set` error before its DNS block ran, so a host where route programming always fails
  never learned about MagicDNS at all; upstream now records the router error, still calls
  `dns.Set`, and joins the errors. This tree does the opposite on purpose: `ts_runtime::tun_actor`
  logs `"host route programming failed; TUN idle (fail-closed)"`, tears the host state down and
  returns, so the interface never carries traffic it cannot route. Pointing the host resolver at
  `100.100.100.100` while the TUN is being torn down would point it at an address nothing answers
  on. The fail-closed invariant outranks parity here — see the quality bar's rule 5 — and the
  Linux half of the same commit (per-interface IPv6 gating in `wgengine/router/osrouter`) is
  independently not applicable: `ts_host_net` programs routes and DNS and installs no netfilter
  rules. Recording the divergence rather than porting it.
- **SSH `acceptEnv` hardening** (`ssh/tailssh`: `651049ec1`, `9d48dbd56`) — **not applicable**, and
  the reason is structural. Upstream rejects `LD_*`/`DYLD_*` in `acceptEnv` filtering and keeps
  accepted variable names and values off the incubator command line. This fork's SSH server never
  reaches that hazard: `src/ssh/shell.rs` builds the child environment with `env_clear()` plus a
  fixed six-variable allow-list (`HOME`, `USER`, `LOGNAME`, `SHELL`, `PATH`, `TERM`), so no
  client-supplied variable — dangerous or benign — is ever placed in the shell's environment, and
  there is no incubator process whose argv could carry one. The visible divergence is that the
  policy's `acceptEnv` is modelled here — `ts_control::ssh_policy`'s `SshRule::accept_env`, carried
  through onto `SshAccept::accept_env` — and then deliberately never applied: Go passes accepted
  variables through to the session, this fork drops all of them. That is a scope decision in the
  safe direction, named here so it is not re-cut as a defect.
- **Digit-only SSH usernames refused** (`ssh/tailssh`: `f368a96e0`) — **not applicable**, narrowly.
  Upstream rejects a purely numeric SSH username with a banner because Go's user lookup falls back
  to resolving a numeric string as a UID, making `ssh 0@host` ambiguous with root. This tree's
  `resolve_user` calls `getpwnam` only and has no numeric-UID fallback, so a digit-only name
  matches nothing and already fails closed before a shell is spawned. The ambiguity the refusal
  exists to close cannot arise; what differs is only the message the client sees.
- **`net/netmon`'s `InterfaceIPDisappeared` predicate** (`5927c1864`) — **not applicable**.
  Upstream fixed a reversed predicate that reported addresses which had *appeared* as having
  disappeared. `ts_netmon` exposes no `ChangeDelta` equivalent — it emits a debounced link-changed
  signal and nothing that answers "which address went away" — so there is no predicate here to be
  reversed. Named because `net/netmon` is a mapped package that had never been swept.
- **`ipn/store`: `WriteState(id, nil)` deletes the key** (`7355116c0`) — **not applicable**.
  Upstream's stores wrote a nil value into their cache map, so a later `ReadState` returned
  `(nil, nil)` instead of `ErrStateNotExist` and a reset node could not log back in. The bug needs a
  nil/absent ambiguity to exist. `StateStore::write_state` (`src/tsnet.rs`) takes `&[u8]`, which has
  no nil, and `read_state` returns `Option<Vec<u8>>`, which distinguishes absent from present; the
  single call site writes a serialized identity blob and never an empty slice.
- **`feature/identityfederation`: query parameters stripped from the client ID** (`34e992f59`) —
  **already covered**. Upstream was sending the whole `tskey-client-…?ephemeral=…` string as the
  OAuth `client_id` in the JWT-for-token exchange, and now sends the part before the `?`.
  `ts_control::wif` has always split the secret at the first `?` into a `stripped` value plus its
  parsed attributes, and `token_exchange_body` takes that stripped id. Recorded because
  `feature/identityfederation` is a mapped package this sweep reached for the first time.

#### Carried from the previous revision's widening

The six bullets below were new when the loop first gained `net/socks5`, `net/tsdial`,
`net/tlsdial`, `net/bakedroots`, `ipn/localapi`, `feature/remoteconfig` and `tsnet`. All six were
re-checked against this pin and against this tree. Five are unchanged; the `tsnet.Server.HTTPClient`
row is the one upstream revised at this pin, and its bullet is rewritten in place to describe what
upstream now does rather than what it did for one day.

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
- **`tsnet.Server.HTTPClient` carries `http.DefaultTransport`'s settings** (`tsnet`: `49e148c4a`,
  then `d9cc55e33`) — **still needs a port** (narrow, host-facing), but *the port target changed at
  this revision*, so the row is rewritten rather than restated. `49e148c4a` stopped returning
  `&http.Client{Transport: &http.Transport{DialContext: s.Dial}}` and *cloned*
  `http.DefaultTransport`. `d9cc55e33` — the new pin, landed a day later — undid the clone: an
  application is permitted to replace or mutate the package-level `http.DefaultTransport`, so
  cloning it made `HTTPClient` inherit whatever an embedder had done to a global. Upstream now
  spells the transport out as a literal and pins the settings by hand: `ForceAttemptHTTP2: true`,
  `MaxIdleConns: 100`, `IdleConnTimeout: 90s`, `TLSHandshakeTimeout: 10s`,
  `ExpectContinueTimeout: 1s`, `DialContext: s.Dial`, and no `Proxy` — with a comment telling the
  next reader to keep it in sync with `http.DefaultTransport` by hand.
  That matters here twice over. First, the port is no longer "work out the `hyper` equivalent of
  whatever Go's global currently holds"; it is a fixed list — five settings, plus the tailnet
  dialer this tree already installs — to decide about one at a time. Second,
  the reason upstream backed the clone out — a mutable process-global leaking into a tailnet
  client — is a hazard this tree never had, because `hyper_util`'s builder has no such global; the
  divergence is only that `Server::http_client` (`src/tsnet.rs`) takes the builder's own defaults
  rather than Go's chosen ones, and its doc comment still calls itself "the exact analog" of the Go
  expression upstream stopped using at the previous pin. The `Proxy = nil` half stays structurally true:
  `TailnetConnector` dials the overlay directly and has no environment-proxy path to disable.
  Upstream's `TestHTTPClientDefaultTransport` still fails on any unrecognised future field — and now
  also asserts that `TLSClientConfig`, `TLSNextProto` and `HTTP2` are *nil*, since a literal
  transport must not pick up the lazily-populated state a shared global accumulates. That test shape
  is still the one worth copying: it forces a decision instead of drifting.
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
`types/netmap`, `netmon` and `syncs`. From the packages swept for the first time at this revision:
`wgengine/router`'s Linux netfilter, `ip rule` and connmark work (`ts_host_net` installs no firewall
rules), `wgengine/wgcfg`'s removal of `Peers` from its config struct and the `wireguard-go` bumps
that go with it, `ssh/tailssh`'s exit-status framing and incubator test fixes, `feature/acme`'s
per-domain locking, `ipn/ipnlocal`'s locking and delta-path rework, and `2a4d74356`, the new pin's
sibling commit, which fixes a data race on a *test* logger in a Go test helper. `tsnet` itself has
125 commits in the window and is **not** re-derived here: that facade has its own line-by-line
parity matrix in [`docs/TSNET_PARITY.md`](docs/TSNET_PARITY.md), and duplicating it into this ledger
would create two records that disagree. Only `tsnet` changes that alter behaviour a mapped crate
already implements are pulled in, as `49e148c4a` and `d9cc55e33` were above.

### Re-deriving this ledger

```sh
# The capability-version window (§A): everything above CapabilityVersion::CURRENT here.
git -C <tailscale-go> grep -n 'CurrentCapabilityVersion CapabilityVersion' d9cc55e3 -- tailcfg/tailcfg.go
git -C <tailscale-go> grep -nE '^//[[:space:]]*-[[:space:]]*1[3-9][0-9]:' d9cc55e3 -- tailcfg/tailcfg.go

# What upstream touched per mapped package since capver 130 landed (§B). Every upstream package
# named in "Package mapping" is in this list; parent paths (wgengine, ipn) are used where the
# mapping names several children, so a subdirectory upstream adds later cannot fall outside it.
for p in tailcfg disco derp net/packet net/tstun net/netcheck net/stun net/dns \
         net/udprelay net/socks5 net/tsdial net/tlsdial net/bakedroots net/netmon net/art \
         control/controlclient control/controlbase control/controlhttp \
         wgengine ipn tsd tka types/key types/persist tsnet \
         feature/remoteconfig feature/identityfederation feature/taildrop feature/ssh \
         feature/acme ssh/tailssh util/clientmetric tstime tstest tool/; do
  echo "== $p"; git -C <tailscale-go> log --since=2025-10-06 --oneline -- "$p"
done

# Only what moved since the pin this ledger currently carries — the fast path on a re-derivation
# that follows soon after the last one. Read it *in addition to* the full sweep, never instead of
# it: a row's assessment can change because this tree moved, with upstream perfectly still, and the
# sweep list itself can be wrong (it has been, twice).
git -C <tailscale-go> log --oneline d9cc55e3..<new-pin>
```

The capability-history pattern is deliberately whitespace-tolerant: upstream writes those entries as
`//   - 133: …`, but the exact indentation is a comment convention, not something `gofmt` enforces,
and a pattern that pins it would go silently empty the day it changes. Check the row count rather
than trusting the exit status — at the pinned commit the second command returns **16 lines**, 130
through 145, i.e. the fifteen-version window of §A plus the 130 row that anchors it. An empty or
short result means the pattern broke, not that upstream added nothing.

**The sweep list is part of the ledger, and it has been wrong twice.** The previous revision added
`net/socks5`, `net/tsdial`, `net/tlsdial`, `net/bakedroots`, `ipn/localapi`, `feature/remoteconfig`
and `tsnet`, and wrote down the rule that produced them: when
[Package mapping](#package-mapping) gains an upstream package — a table row or a *partial* entry
alike — add it here too, or the mapping is a claim the sweep never checks. Applying that rule
literally at this revision showed the list was still short by sixteen mapped packages, so the loop
above was rebuilt from the mapping rather than extended by hand. The additions are `net/netmon`,
`net/art`, `control/controlhttp`, `types/persist`, `feature/identityfederation`, `feature/taildrop`,
`feature/ssh`, `feature/acme`, `ssh/tailssh`, `util/clientmetric`, `tstime`, `tstest`, `tool/`, `tsd`,
and — the consequential ones — the parent paths `wgengine` and `ipn`.

`wgengine` is the lesson. The old loop swept `wgengine/filter`, `wgengine/magicsock` and
`wgengine/netstack` but not `wgengine` itself, so `wgengine/userspace.go`, `wgengine/wgcfg` and
`wgengine/router` — all three named in [Package mapping](#package-mapping) — were invisible, and a
subdirectory upstream created after the loop was written would have been invisible too. Sweeping
the parent removes that failure mode entirely. It is why the quad-100 row, the sharpest new row in
§B, is only reaching this ledger now: `1b4091161` landed upstream in April 2026, in a package that
*was* in the loop, but the pattern that hid `wgengine/router` is the same pattern that makes a
long-swept package's older commits easy to skim past. Re-derive against the list, not against
memory of the last derivation.

Two entries are noisy by nature and should be read with that in mind: `ipn` (which subsumes
`ipn/localapi` and `ipn/ipnlocal`) catches every multi-package commit that also touched
`cmd/tailscale`, most of which is the daemon CLI this library deliberately does not have, and
`tsnet` is swept but not itemised row-by-row in §B — see the note at the end of §B for why. One
mapping row has no upstream path to sweep at all: `golang.zx2c4.com/wireguard`'s device, which
`ts_tunnel` re-implements, is an upstream *dependency* rather than a package in this repository —
track it through upstream's `go.mod` bumps, not through this loop.

When the pin is advanced, bump the header table, re-run the above, and rewrite §A and §B. A row
whose assessment changes should say *why* it changed — and note that "why" has three sources, not
one. Upstream can move (as `d9cc55e33` moved the `tsnet.Server.HTTPClient` row at this revision,
revising its own previous commit a day later). This tree can move, with upstream perfectly still (as
it did at the previous revision, when three capability-version rows flipped to *already covered*).
Or the **sweep itself** can widen and surface something that was true all along — which is where
every new row at this revision came from.

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
