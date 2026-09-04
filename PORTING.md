# Porting ledger: upstream Go `tailscale` → this repository

| | |
| --- | --- |
| **Upstream source** | `https://github.com/tailscale/tailscale` (Go) |
| **Upstream commit this ledger was written against** | `9ea7cba44591e0cd840c6c94d23274dd222059bf` (2026-08-31, `licenses: update license notices`) |
| **Upstream `tailcfg.CurrentCapabilityVersion` at that commit** | **145** (2026-08-04) — unchanged from the previous three pins |
| **This repository at ledger time** | `610c596` — workspace version `0.47.0` |
| **`ts_capabilityversion::CapabilityVersion::CURRENT` here** | **125** (2025-08-11) — held below 126; see §B, *c2n endpoints behind the declared capability version* |
| **Gap window this ledger covers** | capability version **131 → 145**, i.e. upstream commits from 2025-10-06 to 2026-08-31 (the window is anchored to when capver 130 landed upstream; the declaration here being 125 rather than 130 does not change what upstream added) |
| **Previous pin** | `d9cc55e33b4a9f092e21b882df39aa4005cb0fa4` (2026-08-31). Twenty-five upstream commits separate the two, five of them in mapped packages. Unlike the previous two revisions, **this tree is where most of the movement was**: thirty-four commits landed here since `7c39ae0`, and they closed three §B rows outright. See §B, *What changed at this revision* |

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
| `sessionrecording` (client half only) | [`src/ssh/recording.rs`](src/ssh/recording.rs) — moved out of the no-counterpart list at this revision; a rule carrying `recorders` now streams the session to them and applies Go's `onRecordingFailure`, instead of refusing the session |
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
- `tsconsensus`, `prober`, `safeweb`, `tsweb`, `wf`, `util/syspolicy`,
  `clientupdate`, `feature/wakeonlan`, `feature/tap`, `feature/tpm`, `feature/bird`,
  `feature/linkspeed`, `feature/tundevstats`, `feature/routecheck`,
  `feature/favorites`, `feature/serviceclientprefs`, `k8s-operator`, `kube` — platform, operator
  and product surfaces outside the embedded-node scope.
- `feature/remoteconfig` — **partial**, and moved out of the list above at the previous revision: its
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
window is the same fifteen versions the previous two revisions covered. Descriptions are upstream's
own (`tailcfg/tailcfg.go`, `tailcfg/nodecap`).

**No row changed assessment at this revision, for the third revision running — but only one of the
two usual reasons is absent this time.** Upstream added no capability version between `d9cc55e33`
and `9ea7cba44`; the sixteen-row comment block in `tailcfg/tailcfg.go` is byte-identical. This tree,
by contrast, moved a great deal: thirty-four commits since `7c39ae0`, three of which closed §B rows
outright. None of them touched a capability-version row, which is worth stating rather than leaving
implicit — the work that landed here was on the *non*-capver axis, and §B is where it shows up.
The declaration itself was re-examined at #335, which gave it a lower bracket (121, the version a Go
peer tests before offering a relay path) as well as the upper one this ledger already recorded — see
§B, *c2n endpoints behind the declared capability version*.
The rows the previous revisions flipped (135, 142, 144)
still say why they flipped, because that history is what makes the row re-checkable.

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
promises it). That is the same count the previous two revisions reached. Row 133 was re-checked
against the tree at this pin and is still open: `ts_host_net::HostDns::nameservers`
([`ts_host_net/src/lib.rs`](ts_host_net/src/lib.rs)) is still a `Vec<Ipv4Addr>`, and
`ts_runtime::tun_actor` still fills it with the single IPv4 service IP, so there is still no IPv6
MagicDNS address to register. Note the row is *not* closed by #347 (the quad-100 absorption fix in
§B): that made the TUN transport absorb every quad-100 packet whatever its port and protocol, which
is about traffic already addressed to `100.100.100.100` — it neither serves nor registers the IPv6
service IP, which is what 133 asks for.

### B. Behaviour upstream changed in the window that is not capver-gated

Derived from `git log --since=2025-10-06` over the packages that map to crates here, with
docs/typo/refactor commits filtered out. The sweep list is unchanged at this revision — the previous
revision rebuilt it from [Package mapping](#package-mapping) and it still covers every mapped
package (`sessionrecording`, added to the mapping at this revision, is a client-half-only port with
no upstream commits in the window that change what a recorder observes; it is swept under
`ssh/tailssh`, which owns the calling code).

#### What changed at this revision

Read this first: it is the shortest honest summary of the diff between this ledger revision and the
last one.

- **Three rows closed because this tree moved.** The quad-100 absorption leak (#347), the forwarded
  DNS answer that did not set `TC` against the client's own EDNS size (#339), and the IPv6 fragment
  extension-header classification (#342, #343, #345) are all **already covered** now. Each was
  *needs port* at the previous revision; each says so inline below.
- **Three rows opened because upstream moved.** Ten of the twenty-five commits between
  `d9cc55e33` and `9ea7cba44` touched mapped packages once the `fuzz:`, toolchain and licence
  housekeeping is set aside. Two of them — `e1d17a6b9` and `f53c28101` — are one coherent change to
  how a peer's disco key is chosen, and this tree diverges from both halves; a third row falls out of
  the same change (the path invalidation `changedActiveDiscoLocked` performs, which `65d222674` had
  separately restored upstream). They are the second, third and fourth bullets under *Rows*. The
  other eight are the FreeBSD/PF routing work (five commits), a netcheck report race, a CLI
  serve-target parse and its natlab test — all **not applicable** here and recorded as such below.
- **Four rows opened because the sweep was read more carefully.** `0eb38dc2e`, `0bbe6394d`,
  `f6fa29463` and `9175fe267` all landed upstream *before* the previous pin, in packages that were
  already in the loop. They are here now for the same reason the quad-100 row was here at the
  previous revision: a package being swept is not the same as its commits being read. Each of the
  four is named with the tree evidence that shows the gap is real.
- **No row changed because of a divergence decision being revisited.** The two deliberate
  divergences recorded at the previous revision (DNS-after-router-failure, SSH `acceptEnv`) were
  re-checked and stand.

#### Rows

- **TSMP disco-key advertisement** (`net/packet`, `net/tstun`, `wgengine/magicsock`,
  `control/controlclient`: `c54d24369`, `c870d3811`, `bf467727f`, `82a381e54`, `014d5bd9e`,
  `3799eaf26`, `fb27d87e0`) —
  peers advertise their disco key in a TSMP message around the WireGuard handshake, and learn a
  peer's disco key from it without restarting WireGuard. It is the one item here a real Go peer will
  *send us* unprompted. **Both halves remain covered.** Receive: `ts_packet::tsmp` decodes the
  advertisement (Go `Parsed.AsTSMPDiscoAdvertisement`), `ts_dataplane::filter_inbound_from_peer`
  consumes it ahead of the ACL and drops it rather than delivering it to the local stack (Go
  `tstun.filterPacketInboundFromWireGuard` returning `filter.DropSilently`), and
  `PeerTracker::learn_disco_key` applies it to the peer. Send: `ts_packet::tsmp` marshals it against
  Go's own `TestTSMPDiscoKeyAdvertisementMarshal` vectors, `ts_tunnel` reports the two moments
  `wireguard-go` calls `SendPriorityMessage` (`device/receive.go`) and carries its refusals (empty or
  oversize is dropped, not truncated; a peer with no live keypair sends nothing), and `ts_dataplane`
  decides the content (Go `magicsock.Conn.PriorityMessageForPeer`). Row 144 above is the
  capability-version view of the same work. #329 additionally hardened the "unchanged" test so a
  netmap restating control's stale key cannot displace a TSMP-learned one.
  **What upstream did next is the next three bullets**: the single-active-key model this row
  describes is no longer upstream's, and the commits that changed it are the sharpest new rows at
  this pin.

- **A peer's *inactive* known disco key is now accepted on ingress, and becomes the active key**
  (`wgengine/magicsock/endpoint.go`, `wgengine/magicsock/magicsock.go`: `da1fc4fc8`, `e1d17a6b9`) —
  **needs port**, and it is peer-observable in both directions.
  `da1fc4fc8` gave `endpointDisco` two key slots with an origin each (`controlKey`, `tsmpKey`) and a
  `tsmpActive` flag choosing which one is *sent* to. That much this tree already mirrors:
  `ts_runtime::peer_tracker`'s `EndpointDisco` has `control`, `tsmp`, `tsmp_active` and the same
  `key()` / `key_from_control()` / `key_from_tsmp()` accessors, cited to Go by name.
  `e1d17a6b9` is the half that is missing. Upstream replaced every inbound
  `epDisco.key() != di.discoKey` comparison in `Conn.handleDiscoMessage` and
  `unambiguousNodeKeyOfPingLocked` with `endpoint.checkAndUpdateDiscoKey`, which returns true for
  **either** slot's key and, when the key seen is the currently-inactive one, compare-and-swaps
  `tsmpActive` so that key becomes the active one and calls `changedActiveDiscoLocked`.
  In other words: a peer that has told us key K2 over TSMP but is still sending disco under the K1
  control gave us is now understood, and we switch to K1 for sending because that is demonstrably
  what the peer is using.
  Here, ingress resolution is single-key by construction. `PeerDb` carries exactly one
  `disco_key` per node — the *effective* key `EndpointDisco::key()` — and indexes it
  (`peer_db.rs`'s `disco_idx`); `direct::DiscoPeerLookup` resolves an inbound disco frame's sender
  key through that one index. A frame arriving under the peer's other known key resolves to no peer
  and is dropped, with no way to recover except waiting for control or another advertisement.
  The port is: keep both keys reachable for *ingress* attribution, and switch the active key when
  the inactive one is what we actually receive.

- **A control disco-key update no longer preempts an active TSMP-learned key** (`wgengine/magicsock`,
  `control/controlclient`, `ipn/ipnlocal`: `f53c28101`) — **needs port**, and it must land *after*
  the bullet above, not before.
  At the previous pin `endpoint.updateDiscoKey` set `epDisco.tsmpActive = false` whenever control
  supplied a non-zero key, so control genuinely changing its mind always took the active slot back.
  `f53c28101` — the newest mapped-package commit at this pin — changed that line to
  `epDisco.tsmpActive = old.tsmpActive || key.IsZero()`: control's new key is still *recorded*, but
  a TSMP-learned key that is already active stays active, and the switch back to control's key
  happens only when we actually receive disco under it (the `checkAndUpdateDiscoKey` path above).
  The same commit routes TSMP-learned keys straight into the engine instead of through
  `controlClient`, and replaces the full peer reconfigure on a key change with `wireguard-go`'s new
  `ScheduleHandshakeOnUserSend` optimistic handshake.
  This tree still has the old rule: `EndpointDisco::update_from_control` does
  `self.tsmp_active = key.is_none()`, which hands the active slot back to control on any real
  control-side change. The doc comment on `PeerTracker::upsert_from_control` says "Control genuinely
  changing its mind still wins, exactly as it does upstream" — that sentence was true at the previous
  pin and is **false at this one**, and is the single most misleading line in the tree on this
  subject. Note the ordering hazard, which is why this is a second row and not a clause of the first:
  making TSMP sticky *without* first accepting ingress under the control key would strand a peer
  whose key control has legitimately rotated. The `ScheduleHandshakeOnUserSend` half has no target
  here — `ts_tunnel` is this fork's own WireGuard implementation and has no such callback — but the
  behaviour it replaced (tear down and re-establish on every disco-key change) is not what this tree
  does either, so nothing regresses by leaving it.

- **The trusted direct path is not invalidated when a peer's disco key changes**
  (`wgengine/magicsock/endpoint.go`: `65d222674`, `e1d17a6b9`'s `changedActiveDiscoLocked`) —
  **needs port**, narrow and independent of the two rows above.
  Upstream sets `trustBestAddrUntil = 0` and calls `invalidateDiscoPathLocked()` on *every* disco-key
  transition — control-side (`updateFromNode`), TSMP-side (`HandleDiscoKeyAdvertisement`) and
  active-slot switch (`checkAndUpdateDiscoKey`) — keeping `bestAddr` so data keeps flowing while a
  fresh path is confirmed. `65d222674` restored this after `85bb5f8` had removed it, with the
  rationale that otherwise we coast on a dead path until trust lapses on its own.
  Here, `ts_magicsock::path::PeerPaths::invalidate_best` exists and does exactly the right thing —
  but its only caller is `MagicSock::rebind` (`ts_magicsock/src/sock.rs`), and its doc comment says
  so. Nothing on the disco-key change path calls it, so after a peer rotates its disco key this node
  keeps trusting a `best` that was confirmed by a pong signed under the *old* key, for up to a full
  `TRUST_DURATION` (6.5 s), before re-probing.

- **Peer capabilities and routes are not withheld from `UnsignedPeerAPIOnly` peers**
  (`control/controlclient/map.go`, `ipn/ipnlocal/node_backend.go`, `wgengine/magicsock/magicsock.go`:
  `0eb38dc2e`) — **needs port**. Upstream's `upgradeNode` now clamps such a node's `AllowedIPs` back
  to its own `Addresses` ("a (possibly malicious) control server must not grant them network access
  via advertised routes"), `nodeBackend.peerCapsLocked` / `PeerCapsForIP` / `PeerCapsForService`
  return nil for them, and `magicsock.nodeHasCap` refuses them the relay-allocation/target caps.
  All three are unconditional — they do **not** depend on tailnet lock being enabled, because the
  point is that an unsigned peer is by definition outside the lock's coverage.
  This tree carries the field on the wire (`ts_control_serde::Node::unsigned_peer_api_only`) and then
  drops it: `ts_control::Node` has no such field, so nothing downstream can see it. The peer-trust
  chokepoint's own comment says as much — "no `UnsignedPeerAPIOnly` exemption (our node model lacks
  the field)". With tailnet lock **active** this tree is stricter than Go (it rejects unsigned peers
  outright, which [`docs/PARITY_ROADMAP.md`](docs/PARITY_ROADMAP.md) records as a deliberate,
  safe-direction divergence). With tailnet lock **off** — the default, and the common case — there is
  no clamp at all: control can hand an unsigned peer `0.0.0.0/0` in `AllowedIPs` and this node will
  route to it. That is the case upstream closed, and it is not the roadmap's deferred item; the
  roadmap entry is about *admission* under an active lock, this is about *routes and capabilities*
  with the lock off.

- **MagicDNS negative answers carry no SOA, and positive answers are cached for 600 s**
  (`net/dns/resolver/tsdns.go`: `0bbe6394d`) — **needs port**. Upstream attaches the zone's SOA to
  the authority section of every NXDOMAIN and NODATA response it is authoritative for, advertising a
  10-second negative-caching TTL (RFC 2308), and dropped the positive-answer TTL from 600 seconds to
  5. The motivating bug is concrete and reproduces off-tailnet: macOS's `mDNSResponder` caches an
  SOA-less negative answer on its own schedule, so a name queried shortly *before* a node was renamed
  to it does not start resolving until something flushes the cache.
  Here, `ts_dns_wire`'s `ANSWER_TTL` is still `600`, and neither `ts_dns_wire` nor
  `ts_runtime::magic_dns` ever emits an authority section — `encode_response` builds header,
  question and answers only. Both halves are one small change in `ts_dns_wire` plus its callers.
  Host-facing, not wire-facing.

- **Host-injected TSMP is forwarded to peers instead of being dropped** (`net/tstun/wrap.go`:
  `9175fe267`, and the older issue-1526 self-disco drop in the same function) — **needs port**.
  Upstream's `filterPacketOutboundToWireGuard` drops any packet the host writes into the TUN whose
  `IPProto` is TSMP, counting `tstun_out_to_wg_drop_tsmp`, on the rule that "TSMP traffic should only
  originate from tailscaled, not from the host itself"; the same function has long dropped
  host-originated disco for the same reason.
  This tree has no outbound protocol filter at all: `ts_dataplane::process_outbound` tees to the
  capture hook, routes by destination (`or_out.route`), encrypts and sends. So in TUN transport mode
  a local process that writes an IP-proto-99 packet addressed to a peer gets it delivered — and since
  #314/#318 gave this node a real TSMP disco-key advertisement sender, such a packet is
  indistinguishable to the peer from one this node meant to send. The port is a proto check at the
  top of the outbound path, with the negative case (a TSMP message this node generated itself, which
  is injected *below* this point via the priority-message path) asserted so the fix cannot silently
  disable our own advertisements.

- **TKA `SyncOffer` still samples ancestors exponentially** (`tka/sync.go`, `tka/limits.go`:
  `f6fa29463`) — **needs port**, and it is control-observable.
  Upstream replaced the exponential ancestor sampling (`ancestorsSkipStart = 4`,
  `ancestorsSkipShift = 2`, so 4th, 16th, 64th…) with "offer every ancestor whose `MessageKind` is
  `AUMCheckpoint`", and raised `maxSyncHeadIntersectionIter` from 400 to 1000. The reason is a real
  failure mode, not tidiness: nodes compact aggressively and may hold only ~50 AUMs, so exponential
  sampling can produce an offer *disjoint* from what the node kept, leaving it unable to find a
  common ancestor and stuck in a poll-and-fail loop with a permanently stale view of the tailnet.
  Every node is guaranteed to keep at least one checkpoint after compaction, which is why checkpoints
  are the right thing to offer.
  `ts_tka::Authority::sync_offer` still implements the old algorithm exactly, constants and all
  (`ANCESTORS_SKIP_START`, `ANCESTORS_SKIP_SHIFT`, `MAX_SYNC_HEAD_INTERSECTION_ITER = 400`), each
  cited to the Go name it mirrors. The port is small and self-contained, and the citation comments
  make it obvious; the trap is that the offer is also consumed by `missing_aums`, so both directions
  of `intersection` need re-checking against the new ancestor shape.

- **IPv6 fragment extension-header handling in the filter** (`net/packet`, `wgengine/filter`:
  `4c4ec3d46`, `26b2ed0a6`) — **already covered**, *changed from "needs port only under
  `Config::enable_ipv6`"*. #342 gave `ts_dataplane` the IPv6 half of the RFC 1858-style
  classification it had only for IPv4, #343 extended it to a Fragment header hidden behind a chained
  extension header, and #345 rewrote the tests so each extension header has its own control and its
  drop cannot pass vacuously. `decode6_fragment` / `decode6_first_fragment` now mirror Go's
  `minFragBlks` reuse for IPv6, and a first TSMP fragment with `MF` set is demoted to
  `Ipv6Fragment::Unknown` and dropped, as upstream requires.

- **Quad-100 traffic is absorbed locally regardless of port and protocol** (`wgengine/netstack`:
  `1b4091161`) — **already covered**, *changed from "needs port"*. #347 closed the TUN-mode leak this
  ledger opened at the previous revision. `ts_runtime::tun_actor::classify_service_ip` now returns
  `ServiceIpPacket::Absorbed` for **every** packet destined to `100.100.100.100` that is not the
  UDP/53 query it serves, so nothing addressed to the service IP reaches `ts_overlay_router` and can
  be matched by a configured exit node's `0.0.0.0/0`. The companion half of upstream's fix is present
  too and was not before: an unserved quad-100 **TCP** port is answered with a RST built by
  `build_tcp_reset` (RFC 9293 §3.10.7 CLOSED-state rules, matching what smoltcp already does on the
  netstack transport), rather than dropped into a retransmit loop — upstream's `hittingServiceIP`
  case in `acceptTCP`. The tests that pin it are `service_ip_absorbs_every_non_dns_packet`,
  `unserved_service_ip_tcp_port_is_reset`, `exit_node_default_route_never_sees_service_ip_traffic`
  and `both_transports_absorb_service_ip_traffic`.

- **The DNS forwarder sets TC against the *client's* size limit, not just its own read buffer**
  (`net/dns/resolver`: `8cac8b117`) — **already covered**, *changed from "needs port (narrow)"*.
  #339 added `set_tc_if_over_client_limit` to `ts_runtime::magic_dns`, called from `cap_response` on
  every forwarded answer: it parses the request's EDNS(0) OPT record for the advertised UDP payload
  size, defaults to 512 when there is no OPT record (RFC 1035 §4.2.1), floors an advertised size
  below 512 at 512 (RFC 6891 §6.2.3), and sets `TC` with the body left intact. The pre-existing
  `MAX_UPSTREAM_RESPONSE` (4096) relay cap stays as the separate bound it always was — #331 corrected
  the comment that had described it as a read bound.

- **Peer relay** (`disco` 0x04–0x09, `net/udprelay`, `feature/relayserver`; capver 120/121, i.e.
  *behind* the declared 125) — **ported (client half)**, unchanged at this revision. All nine disco
  message types have a codec (`ts_disco_protocol`'s relay module, checked against Go's own
  `disco_test.go` vectors), and `ts_magicsock` runs the client side end to end: an inbound
  `CallMeMaybeVia` starts the 3-way bind handshake with the named relay server, and a relayed
  ping/pong confirms a Geneve-framed path that carries WireGuard data instead of falling back to
  DERP. Direct paths still take priority over relay ones. Not ported, and out of scope for an
  embedded client: **serving** as a relay (`net/udprelay.Server`, `feature/relayserver`) and
  *requesting* an allocation of our own. Two riders from this revision's sweep, both **not
  applicable**: `badd0c4f9` added the VNI to Go's relay handshake-work key
  (`handshakeWorkByServerDiscoVNI`), which `ts_magicsock/src/relay.rs` already keys on and
  `sock.rs` is deliberately stricter than — it additionally requires the handshake to name the peer
  it belongs to; and `94381a191` fixed the slice *capacity* arithmetic in
  `disco.UDPRelayEndpoint.decode`, an allocation-sizing bug with no observable behaviour, which has
  no analogue in a Rust decoder over a DST slice. Worth recording alongside: #335 gave the declared
  capability version a **floor** because of this row. A post-merge audit of the port that lowered the
  declaration from 130 to 125 objected that 125 still asserts 120 and 121 — the two peer-relay
  versions — and proposed dropping to 119. That was rejected on upstream evidence: a Go peer decides
  whether to offer us a relay path with `magicsock.capVerIsRelayCapable(version)`, which is exactly
  `version >= 121`, so declaring 119 would have silently disabled the client half that is ported and
  working. The declaration is now bracketed from below as well as above — floor 121, ceiling under
  126 — with a ported predicate and a test behind the floor.

- **c2n endpoints behind the declared capability version** — capver 127 (`/debug/netmap`), 128
  (`/debug/health`) and row 138 (`/debug/tka/log`) share one responder
  (`ts_control/src/tokio/ping.rs`), which serves `/echo`, `GET /vip-services` and the
  `/remoteapi/localapi/*` prefix of row 142. The three debug endpoints are **resolved by holding
  `CapabilityVersion::CURRENT`** below them. Porting them was rejected on evidence, not preference:
  each needs a subsystem this tree does not have. `handleC2NDebugNetMap` marshals a whole
  `netmap.NetworkMap` (there is no netmap aggregate here — the netmap arrives as `StateUpdate` deltas
  accumulated by the runtime's peer tracker, which the responder cannot see, and control unmarshals
  the body back into Go's struct, so any field we could not fill would read as a zero value rather
  than as "unknown"); `handleC2NDebugHealth` marshals `health.Tracker.CurrentState()` and this fork
  has no health subsystem; and `handleC2NDebugTKALog` serves the AUM chain, which lives in
  `ts_runtime` because `ts_control` deliberately does not depend on `ts_tka`. All three take Go's own
  `400`/`unknown c2n path` fallthrough (`handleC2N`, `ipn/ipnlocal/c2n.go`), asserted by test. The
  declaration is **125**, not 126: capver 126 (seamless key renewal) is not implemented here either —
  this tree's expiry recovery is a node-key rotation plus a full re-register
  (`ts_control::Config::reauth_on_expiry`), which is upstream's *non*-seamless path. 125 is also the
  capability version Tailscale `v1.88.0` declares, so it pairs with a real release for the
  `IPNVersion` in `ts_control::hostinfo`. **The declaration is what gates row 142.** A capability
  version is a contiguous claim, not a set: to declare 142 a node must implement everything from 126
  up, so the c2n LocalAPI proxy sits behind 126, 127, 128, 130
  (`key.HardwareAttestationPublic` / `…KeySignature` in `MapRequest`, no counterpart here) and 138.
  Control will not send `/remoteapi/localapi/*` to a node declaring 125, so that handler is correct,
  tested and dormant, and will stay dormant until that whole run is closed. (129 — a sleep/wake
  deadlock fix in Go's own peer-relay code — is a bug fix in an implementation this tree does not
  share, so it costs nothing.) #335 added the other bracket: the declaration may not be *lowered*
  below 121 either, because that is what a Go peer tests before offering this node a relay path. See
  the peer-relay row above.

- **Services model extension** (`tailcfg`: `1cd8bcc82`, `6cd185bf3`, `fc9b18f50`) — upstream added
  client application *actions* (with attributes and `ServiceActionType` constants) to the VIP
  services model. **Needs port**, unchanged: `ts_control_serde/src/service_vip.rs` models
  `VipService` and the c2n response and still carries no action types, so the consume side cannot
  stay current with what control may send.

- **`Node.IsRouter` / `PeerStatus.IsRouter`** (`8d830599b`) — **already covered**, and refined since
  the previous revision. Upstream added no wire field: `tailcfg.Node.IsRouter` and
  `ipnstate.PeerStatus.IsRouter` are *derived predicates* — "does this node route addresses besides
  its own" — spelled as methods so IPN-bus watchers can classify routers out of the netmap they
  already hold. Mirrored here as `ts_control::Node::is_router` (over `accepted_routes` vs
  `addresses`) and `ts_runtime::status::StatusNode::is_router` (over `allowed_routes` vs
  `ipv4`/`ipv6`), cross-checked against each other the way upstream's `TestNodeIsRouter`
  cross-checks its two definitions. #337 corrected the Rust side after the previous revision: the
  predicate tested each accepted route against the *identity* projection (`tailnet_address`, the
  first prefix of each family) rather than against control's whole `Node.Addresses` list, so a node
  control assigned two prefixes of one family read its own second prefix as a routed one and was
  reported as a router where Go says it is not. Control does not assign that shape today, which is
  why the divergence had cost nothing. #340 then fixed two test fixtures added alongside #337 that
  put the `tailnet_address` placeholders (`0.0.0.0/32`, `::/128`) into `addresses`, describing nodes
  control could never have handed us.

- **DERP `ClientInfo.AppName`** (`246c82a65`, `75519889f`) — clients may advertise an opaque app
  name (≤32 bytes printable ASCII) which servers relay to watchers and can ban on. **Not
  applicable** — the field is `omitempty` and optional, and `ts_derp`'s `ClientInfoPayload` omits it,
  which is what a Go client without the option does. The related `FramePeerPresent` extension (flags
  byte + app-name suffix) is mesh-only: `ts_derp` classifies `PeerPresent` as privileged and a leaf
  client never subscribes, so the fixed-size parser is not an interop risk.

- **`NodeAttrClientSideReachabilityRouteCheck` + `net/routecheck`** (`2fbd30824`) — client-side
  route reachability checking. **Not applicable** — no counterpart subsystem; the attribute is
  ignored, which is the correct behaviour for a client that does not implement it.

- **Upstream's `encoding/json/v2` compatibility fixes** (`82cfea90c`) — upstream adjusted JSON
  serialization for Go 1.27's finalized `encoding/json/v2`. **Needs an audit, not a port**, and the
  audit is still not done: `ts_control_serde` hand-mirrors Go's PascalCase/`omitempty`/`omitzero`
  choices field by field, so any tag semantics upstream changed must be re-checked against the wire.
  Nothing observed to have broken. Note `b3c719581` at this pin bumps upstream's toolchain to Go
  1.27.1, so the v2 encoder is now what upstream actually ships rather than what it was preparing
  for — which raises, not lowers, the value of doing the audit.

#### Not applicable, from the commits new at this pin

Recorded so the next re-derivation does not re-cut them.

- **`net/netcheck`: a received STUN response marks its address family sendable** (`92ec10267`) —
  **not applicable**. Upstream's `runProbe` recorded `IPv4CanSend`/`IPv6CanSend` only after
  `SendPacket` returned, so a fast STUN response could be folded into a cloned report that said "UDP
  works, mapping valid, CanSend false", which magicsock read as a send failure and answered with an
  unnecessary rebind. There is no target here: this fork's `ts_netcheck` measures **DERP-region
  latency only** (`RegionResult`, `measure_derp_map`), `ts_runtime::status::NetcheckReport`
  deliberately carries just the preferred region and the per-region latencies and says so in its doc
  comment ("do not fabricate"), and no rebind is driven by any such field —
  `MagicSock::rebind` is called on link change and on the manual `Device::rebind`. The module comment
  in `ts_netcheck/src/lib.rs` records why there is no STUN prober there at all (it would need a
  second bound socket and an IPv6 bind, both against this fork's anti-leak invariants).
- **`wgengine/router/osrouter`: FreeBSD routing, PF anchors and SNAT** (`1293b4f67`, `827c6fe50`,
  `4c5862376`, `4e80553a9`, `16dacb0c5`, with `58f28a192` and `d80f3f7e6` alongside) — five of the
  twenty-five new commits are one FreeBSD/PF work item. **Not applicable**: `ts_host_net` has Linux
  and macOS backends only, programs routes and DNS through `ip`/`resolvectl` and `route`/`scutil`,
  and installs no firewall rules of any kind — no PF anchors to reference-count, no SNAT rule to
  point at an egress address, no tun to destroy from `Close`.
- **`cmd/tailscale`: IPv6 localhost serve targets** (`57c3357fd`) — **not applicable**. The change is
  in the CLI's serve-target parsing, letting `[::1]:port` be accepted where only `127.0.0.1:port`
  was. This library has no CLI, and `ts_runtime::serve` takes typed targets from the embedder rather
  than parsing a user string.
- **`tstest/natlab/vmtest`: multi-flow FreeBSD SNAT test** (`b25459ab1`) — **not applicable**; a test
  for the FreeBSD work above. `tstest` is swept because it is a mapped package (`ts_test_util`), and
  this is the shape of thing that sweep will keep surfacing.

#### Not applicable, from older commits read for the first time at this revision

- **`net/packet`: ICMP Destination Unreachable generation** (`8df4816be`) — **not applicable**.
  `GenerateICMPHostUnreachable` was added for the conn25 app connector, which returns an ICMP
  unreachable when it has no IP mapping for a client (`da51072b9`). This tree has no app connector of
  either generation, so nothing would call it; `ts_packet` has no ICMP *generation* surface at all,
  only decode.
- **`tka`: constant-time comparison of the disablement secret** (`34477cf3e`) — **not applicable
  today, but it names a constraint on work that is already planned.** Upstream's
  `State.checkDisablement` moved from `bytes.Equal` to `subtle.ConstantTimeCompare`. There is nothing
  here to convert: `ts_tka` implements `disablement_value` (the Argon2i KDF, pinned byte-for-byte
  against Go's golden vectors) but no `checkDisablement`, because disablement-secret *verification*
  is not implemented — [`docs/PARITY_ROADMAP.md`](docs/PARITY_ROADMAP.md) carries it as a deferred
  item. Recorded here so that when it is implemented it is implemented constant-time, rather than
  ported from a pre-`34477cf3e` reading of upstream.
- **`net/dns/resolver`: reach netstack-only upstreams over UDP** (`e1e5325c2`, `8bebdca90`) —
  **already covered, by a stronger rule.** Upstream's `sendUDP` opened a host-stack socket and
  ignored `UseNetstackForIP`, so in userspace-networking mode a split-DNS query aimed at a *tailnet*
  resolver blackholed until the TCP fallback answered; it now dispatches through the netstack dialer.
  This fork never had the host-socket path: `ts_runtime::magic_dns`'s forwarder sends every upstream
  query over the overlay netstack `Channel`, and says why in its own doc comment — it is an anti-leak
  invariant here, not a mode.
- **`ipn/ipnlocal`, `net/dns/resolver`: no bare-name resolution when MagicDNS is disabled**
  (`1ec348784`) — **not applicable**. Upstream's `nodeByFQDNLocked` now refuses a short name when
  `nm.DNS.Proxied` is false, because `nodeByName` intentionally holds both FQDNs and short names for
  other callers. This tree is stricter and structurally so: `magic_dns::decide` returns `REFUSED` for
  *every* query when `cfg.magic_dns` is false or the node does not accept the tailnet DNS config, and
  that one read site covers the netstack responder, the peerAPI DoH server and the TUN query path.
  There is no name of any shape that resolves through MagicDNS while it is disabled.
- **`wgengine/magicsock`: only send `callMeMaybe` when disco pings were actually sent**
  (`9be21088f`, then `2690d58e4`) — **deliberate divergence, recorded rather than ported.**
  Upstream briefly let a node on a cached netmap send a `CallMeMaybe` with no peer endpoints known,
  then reverted to gating on `sentAny`. This tree's `ts_runtime::direct::run_call_me_maybe` is a
  different shape entirely: a periodic sweep over peers with no confirmed `best_addr`, gated on *our*
  side having a STUN-discovered reflexive candidate to advertise, not on having pinged the peer.
  That gate is documented in place and is the safe direction — we never relay a `CallMeMaybe` that
  carries nothing a remote peer could act on, which is what upstream's `sentAny` gate is really
  protecting against. The deliberate part on the *peer* side is the opposite of upstream's: a peer
  whose netmap carried no DERP region is still prompted, via an inferred relay region, because
  without that the WireGuard floor came up over DERP and the direct upgrade was never attempted at
  all (the fork's own issue #24). Left as-is; named so it is not re-cut as a defect.
- **`wgengine/magicsock`: invalidate the endpoint on trust timeout** (`d3ba1480f`) — **already
  covered by construction.** Upstream cleared `bestAddr` on `trustBestAddrUntil` expiry only for
  udprelay paths, so a direct UDP path could stay selected-but-untrusted and blackhole; it now clears
  for both, and `handlePongConnLocked` switches to a working alternative when the held best is
  untrusted even if `betterAddr` would not have preferred it. Here `PeerPaths::best_addr` returns
  `None` the moment `trust_until` passes, so an untrusted best is never *used* in the first place,
  and the hysteresis in `select_best` applies only while the current best is still trusted. The
  failure mode the commit fixes cannot arise. (This is a different question from the disco-key
  invalidation row above, which is about a path that is still inside its trust window but was
  confirmed under a key the peer has since replaced.)

#### Carried unchanged from the previous revisions

The rows below were re-checked against this pin and against this tree and did not move. They are
kept in full because a row whose evidence is elided is a row the next re-derivation has to redo.

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
  through onto `SshAccept::accept_env` — and then deliberately never applied. That is a scope
  decision in the safe direction, named here so it is not re-cut as a defect.
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
  reversed.
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
  parsed attributes, and `token_exchange_body` takes that stripped id.
- **SOCKS5 proxy credentials compared in constant time** (`net/socks5`: `60576f8bd`) — **still needs
  port**, and it is the oldest open row here. Upstream's SOCKS5 server checked the client-supplied
  username and password with plain string equality, which returns on the first differing byte, and
  replaced both with `subtle.ConstantTimeCompare`, evaluating both halves so the username result does
  not gate whether the password is examined. The same asymmetry exists here: `src/loopback.rs`'s
  `negotiate` does
  `uname.as_slice() == PROXY_USERNAME.as_bytes() && passwd.as_slice() == cred.as_bytes()` — two
  data-dependent comparisons, the second short-circuited by the first. The threat model transfers
  unchanged: `gen_cred` mints a 16-byte random credential that gates every dial into the tailnet, the
  listener is on `127.0.0.1`, and any local process may retry without limit, so a reject that is
  timeable leaks the credential a byte at a time. No new dependency is needed —
  `src/tsnet.rs`'s `localapi::cred_ok` is already a constant-time comparison, so the SOCKS5 path is
  the one place on the loopback that does not use it. Host-facing, not wire-facing.
- **`tsnet.Server.HTTPClient` carries `http.DefaultTransport`'s settings** (`tsnet`: `49e148c4a`,
  then `d9cc55e33`) — **still needs a port** (narrow, host-facing), unchanged at this pin.
  `49e148c4a` stopped returning `&http.Client{Transport: &http.Transport{DialContext: s.Dial}}` and
  *cloned* `http.DefaultTransport`; `d9cc55e33` undid the clone a day later, because an application
  is permitted to replace or mutate the package-level `http.DefaultTransport` and cloning it made
  `HTTPClient` inherit whatever an embedder had done to a global. Upstream now spells the transport
  out as a literal and pins the settings by hand: `ForceAttemptHTTP2: true`, `MaxIdleConns: 100`,
  `IdleConnTimeout: 90s`, `TLSHandshakeTimeout: 10s`, `ExpectContinueTimeout: 1s`,
  `DialContext: s.Dial`, and no `Proxy` — with a comment telling the next reader to keep it in sync
  with `http.DefaultTransport` by hand.
  So the port is a fixed list — five settings, plus the tailnet dialer this tree already installs —
  to decide about one at a time. The hazard upstream backed out of (a mutable process-global leaking
  into a tailnet client) is one this tree never had, because `hyper_util`'s builder has no such
  global; the divergence is only that `Server::http_client` (`src/tsnet.rs`) takes the builder's own
  defaults rather than Go's chosen ones. The `Proxy = nil` half stays structurally true:
  `TailnetConnector` dials the overlay directly and has no environment-proxy path to disable.
  Upstream's `TestHTTPClientDefaultTransport` fails on any unrecognised future field and asserts that
  `TLSClientConfig`, `TLSNextProto` and `HTTP2` are *nil*; that test shape is the one worth copying,
  because it forces a decision instead of drifting.
- **`Dialer.Close` no longer touches the peerapi transport when omitted** (`net/tsdial`:
  `72780705e`) — **not applicable**. The bug is that Go's `Dialer.Close` called `PeerAPITransport()`
  unconditionally, which panics in a binary built with the `ts_omit_peerapiclient` build tag. There
  are no build tags here and no equivalent unconditional accessor; the peerapi client is ordinary
  Rust state whose absence is an `Option`, not a panic.
- **`Sys.ExtraRootCAs` plumbed through the TLS dial paths** (`net/tlsdial`: `a182b864a`) —
  **already covered**, and by an older mechanism than upstream's. `ts_tls_util` builds its
  `RootCertStore` from `webpki_roots::TLS_SERVER_ROOTS` and additively loads extra trust anchors from
  the PEM file named by `TS_RS_EXTRA_CA_PEM`, which is the same capability reached by configuration
  rather than by a `tsd.Sys` field. Failure to load is logged and non-fatal, so a bad path cannot
  silently weaken trust — it surfaces as a handshake error.
- **LetsEncrypt Generation Y roots (`YE`, `YR`)** (`net/bakedroots`: `f65372c9b`) — **not
  applicable as a port**, but it names a real maintenance obligation. Go bakes a hand-curated root
  list into the binary because a Go client cannot rely on the OS trust store everywhere; this tree
  has no such list to append to, because `webpki-roots` *is* the compiled-in bundle and tracks
  Mozilla's set on the crate's own release cadence. The obligation upstream discharges by editing
  `bakedroots.go` is discharged here by keeping that dependency current, which is a `cargo update` in
  its own PR (see [`CONTRIBUTING.md`](CONTRIBUTING.md#dependencies)), not a code change. A stale
  `webpki-roots` is the failure mode this row exists to name: it looks like nothing until a CA
  rotates and control or DERP stops verifying.
- **`UserDial` happy eyeballs, and `UserDialPlan` for non-Tailscale addresses** (`net/tsdial`:
  `f3a117e81`, `0e10a3f58`) — **not applicable as the tree stands**. Both are about `tailscaled`
  dialling *on behalf of a local user process*: racing A and AAAA candidates with a 300 ms delay when
  userspace networking sits behind an exit node, and letting the LocalAPI `/dial` handler tell a
  client to dial a non-Tailscale address itself. Neither has a target here. This fork's overlay is
  IPv4-only by default and its MagicDNS resolver returns a single `Option<Ipv4Addr>`
  (`loopback::Resolver`), so there is no second address family to race; and the one-route LocalAPI
  serves no `/dial`. The first would become live if IPv6 MagicDNS lands — it pairs with row 133 and
  `Config::enable_ipv6`, and is noted here so that port is not written IPv4-shaped a second time.

Deliberately **not** listed: upstream refactors with no observable behaviour (the
`tailcfg/{nodecap,selfcap}` package split, `DERPRegionID` typing, `NodeMutationAdd` →
`NodeMutationUpsert`, the `feature/` build-tag reorganization, removal of `LazyWG` and the engine
watchdog, `types/netmap` field removals), and upstream-internal locking/allocation fixes in
`control/controlclient`, `derp/derpserver` and `ipn/ipnlocal` (including `886d1b2e6`, `5be05f2c0`,
`d64aaffc0` and `e32b9bde1`, all of which are Go concurrency shape rather than wire behaviour). From
the packages the previous revisions added to the sweep: the tree-wide renames and modernizers that touched `net/socks5`
(`bd2a2d53d`, `2810f0c6f`, `3ec5be3f5`, `c2e474e72`) and the `net/tsdial` commits that only follow
upstream's own refactors of `types/netmap`, `netmon` and `syncs`. `wgengine/router`'s Linux
netfilter, `ip rule` and connmark work (`ts_host_net` installs no firewall rules),
`wgengine/wgcfg`'s removal of `Peers` from its config struct and the `wireguard-go` bumps that go
with it, `ssh/tailssh`'s exit-status framing and incubator test fixes, `feature/acme`'s per-domain
locking, and `ipn/ipnlocal`'s locking and delta-path rework. New at this pin and equally out:
`91d10d38a` (`net/portmapper`, a package with no counterpart here — *roadmap*), `99f1ee74b`
(`feature/conn25`, likewise), the `fuzz:` and `go.toolchain.rev` housekeeping, and `9ea7cba44`
itself, which is a licence-notice regeneration and is the pin only because it is what HEAD was.
`tsnet` has over a hundred commits in the window and is **not** re-derived here: that facade has its
own line-by-line parity matrix in [`docs/TSNET_PARITY.md`](docs/TSNET_PARITY.md), and duplicating it
into this ledger would create two records that disagree. Only `tsnet` changes that alter behaviour a
mapped crate already implements are pulled in, as `49e148c4a` and `d9cc55e33` were above.

### Re-deriving this ledger

```sh
# The capability-version window (§A): everything above CapabilityVersion::CURRENT here.
git -C <tailscale-go> grep -n 'CurrentCapabilityVersion CapabilityVersion' 9ea7cba44 -- tailcfg/tailcfg.go
git -C <tailscale-go> grep -nE '^//[[:space:]]*-[[:space:]]*1[3-9][0-9]:' 9ea7cba44 -- tailcfg/tailcfg.go

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
git -C <tailscale-go> log --oneline 9ea7cba44..<new-pin>

# And the mirror image of that, which the revision at 9ea7cba44 needed and the two before it did
# not: what moved *here* since the tree revision the header table names. Three §B rows closed at
# that revision for this reason alone, with upstream perfectly still.
git log --oneline 610c596..HEAD
```

The capability-history pattern is deliberately whitespace-tolerant: upstream writes those entries as
`//   - 133: …`, but the exact indentation is a comment convention, not something `gofmt` enforces,
and a pattern that pins it would go silently empty the day it changes. Check the row count rather
than trusting the exit status — at the pinned commit the second command returns **16 lines**, 130
through 145, i.e. the fifteen-version window of §A plus the 130 row that anchors it. An empty or
short result means the pattern broke, not that upstream added nothing.

**The sweep list is part of the ledger, and it has been wrong twice.** The revision before last
added `net/socks5`, `net/tsdial`, `net/tlsdial`, `net/bakedroots`, `ipn/localapi`,
`feature/remoteconfig` and `tsnet`, and wrote down the rule that produced them: when
[Package mapping](#package-mapping) gains an upstream package — a table row or a *partial* entry
alike — add it here too, or the mapping is a claim the sweep never checks. The previous revision
applied that rule literally, found the list still short by sixteen mapped packages, and rebuilt the
loop from the mapping rather than extending it by hand: `net/netmon`, `net/art`,
`control/controlhttp`, `types/persist`, `feature/identityfederation`, `feature/taildrop`,
`feature/ssh`, `feature/acme`, `ssh/tailssh`, `util/clientmetric`, `tstime`, `tstest`, `tool/`,
`tsd`, and — the consequential ones — the parent paths `wgengine` and `ipn`. The list was checked
again at this revision against the mapping and is complete; `sessionrecording` joined the mapping
here and needs no loop entry of its own, because the client half lives behind `ssh/tailssh`'s
calling code, which is swept.

`wgengine` was the lesson for the sweep list. **The lesson at this revision is a different one, and
it is worth writing down as plainly:** a package being *in* the loop does not mean its commits have
been *read*. Four of this revision's new rows — `0eb38dc2e`, `0bbe6394d`, `f6fa29463`, `9175fe267` —
are commits from `control/controlclient`, `net/dns/resolver`, `tka` and `net/tstun`, four packages
that have been in the loop since the ledger existed. They opened rows now because this revision read
the sweep output line by line against the tree instead of skimming for unfamiliar package names. The
quad-100 row at the previous revision was the same failure in its first form. Budget for the reading,
not just for the `git log`.

Two entries are noisy by nature and should be read with that in mind: `ipn` (which subsumes
`ipn/localapi` and `ipn/ipnlocal`) catches every multi-package commit that also touched
`cmd/tailscale`, most of which is the daemon CLI this library deliberately does not have, and
`tsnet` is swept but not itemised row-by-row in §B — see the note at the end of §B for why. One
mapping row has no upstream path to sweep at all: `golang.zx2c4.com/wireguard`'s device, which
`ts_tunnel` re-implements, is an upstream *dependency* rather than a package in this repository —
track it through upstream's `go.mod` bumps, not through this loop.

When the pin is advanced, bump the header table, re-run the above, and rewrite §A and §B. A row
whose assessment changes should say *why* it changed — and note that "why" has three sources, not
one, and that all three have now actually happened. Upstream can move (as `e1d17a6b9` and
`f53c28101` moved the disco-key rows at this revision, and as `d9cc55e33` moved the
`tsnet.Server.HTTPClient` row at the previous one). This tree can move, with upstream perfectly
still (as it did at the revision before last, when three capability-version rows flipped, and again
at this one, when #339, #342/#343/#345 and #347 closed three §B rows). Or the **sweep itself** can
widen, or simply be read more carefully, and surface something that was true all along.

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
