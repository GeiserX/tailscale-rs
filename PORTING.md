# Porting ledger: upstream Go `tailscale` → this repository

| | |
| --- | --- |
| **Upstream source** | `https://github.com/tailscale/tailscale` (Go) |
| **Upstream commit this ledger was written against** | `023255e8a27ec9f6a21d24e3eda21c052ff72af3` (2026-09-09, `net/dnscache, feature/dnsresolvecache: only persist DNS resolutions after TLS verification`) |
| **Upstream `tailcfg.CurrentCapabilityVersion` at that commit** | **146** (2026-09-02) — **unchanged**, the first hold since it moved at the previous pin; see §A |
| **This repository at ledger time** | `dcd2c13` — workspace version `0.52.3` |
| **`ts_capabilityversion::CapabilityVersion::CURRENT` here** | **125** (2025-08-11) — held below 126; see §B, *c2n endpoints behind the declared capability version* |
| **Gap window this ledger covers** | capability version **131 → 146**, i.e. upstream commits from 2025-10-06 to 2026-09-09 (the window is anchored to when capver 130 landed upstream; the declaration here being 125 rather than 130 does not change what upstream added) |
| **Previous pin** | `3945b82f8a9550b54c33e61d4ed2227862d53e8a` (2026-09-08). Fourteen upstream commits separate the two, nine of them in mapped packages — three in `net/socks5` alone, two in `tstest`. **This tree is where the movement was, for the fourth revision running**: seventeen commits landed here since `4e8578d`, closing **all six** of the rows the previous revision opened, in the order it wrote them down. See §B, *What changed at this revision*. The five rows that replace them came from nowhere near the new delta — see the sweep-list note under [Re-deriving this ledger](#re-deriving-this-ledger), which gained a package at this revision for the third time |

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
| `net/routemanager` (split out of `wgengine/wgcfg`, `a5102d3fc`) | [`ts_overlay_router`](ts_overlay_router/src/lib.rs) + the route/IP indexes in [`ts_runtime::peer_tracker`](ts_runtime/src/peer_tracker/peer_db.rs) — **new to this mapping at this revision**; it is where upstream now keeps the per-peer data-plane attributes (`PeerRoute.Jailed`, `MasqAddr4`/`MasqAddr6`) that `net/tstun` reads, and two §B rows come out of it |
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
| `sessionrecording` (client half only) | [`src/ssh/recording.rs`](src/ssh/recording.rs) — moved out of the no-counterpart list three revisions ago; a rule carrying `recorders` now streams the session to them and applies Go's `onRecordingFailure`, instead of refusing the session |
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
- `feature/androiddns`, `feature/androidbin` — Android support for *raw* binaries: DNS through
  Android's system `dnsproxyd` cache (`86b3cd5aa`), and a `net/netmon` interface-getter fallback plus
  an Android CA-root path for binaries that have no `/etc/resolv.conf`, no bionic libc and no
  `NETLINK_ROUTE` (`60d9c54b6`). `ts_host_net` has Linux and macOS backends only, and
  `ts_netmon` has no OS backend at all yet, so neither has a target here.
- `net/connreject`, `feature/connreject` — the opt-in, LRU-bounded aggregator of recent
  connection-rejection events (TSMP rejects received and sent, and pendopen timeouts) behind
  `nodecap.ConnReject` and the `GET /debug/rejects` c2n endpoint, added at `85c1efb46` — the commit
  that raised `CurrentCapabilityVersion` to 146. The *diagnostics* are out of scope for an embedded
  node (§A row 146). The TSMP rejected-connection messages they count were a §B row of their own at
  the previous revision and are now implemented in both directions (#421); the aggregator on top of
  them stays out.
- `net/dnscache`, `net/dnsfallback`, `feature/dnsresolvecache` — the resolution cache in front of Go's
  *control-plane and DERP* dials, its DERP-based bootstrap-DNS fallback, and the on-disk persistence
  of last-known-good answers for those hostnames (`aa2681ac5`, tightened at this pin by `023255e8a`
  so an answer is persisted only once it has passed TLS verification). No counterpart: this
  fork dials control through control's own `DialPlan` (`ts_control::dial_plan`, which carries literal
  addresses) and falls back to the system resolver, so there is no client-side answer cache to persist.
  Upstream links the new feature into `tailscaled` and deliberately **not** into `tsnet`.
- `portlist`, `posture`, `feature/posture` — port-list and device-posture reporting to control.
- `net/tshttpproxy` — HTTP proxy support for *outbound control/DERP* dials. (The fork's
  `ProxyExitDialer` is the opposite direction — exit-node egress — and is not a port of this.)
- `tsconsensus`, `prober`, `safeweb`, `tsweb`, `wf`, `util/syspolicy`,
  `clientupdate`, `feature/wakeonlan`, `feature/tap`, `feature/tpm`, `feature/bird`,
  `feature/linkspeed`, `feature/tundevstats`, `feature/routecheck`,
  `feature/favorites`, `feature/serviceclientprefs`, `k8s-operator`, `kube` — platform, operator
  and product surfaces outside the embedded-node scope.
- `feature/remoteconfig` — **partial**, and moved out of the list above two revisions ago: its
  `c2nPrefix`, `localAPIStrip` and `handleC2NRemoteAPI` (the c2n → LocalAPI proxy of capver 142) are
  ported into `ts_control/src/tokio/ping.rs`; the rest of the package — the remote-config prefs
  surface and its CLI — is not.
- `ts_ffi`, `ts_python`, `ts_elixir` have no upstream counterpart in `tailscale/tailscale` at all —
  Go's C bindings live in the separate `tailscale/libtailscale` repository.

## Gap list

Every row was checked against the pinned upstream commit **and** against this tree; the evidence
is named inline so a reviewer can re-check a single row without re-deriving the whole ledger.
Assessments are one of **needs port**, **not applicable**, **already covered**.

### A. Capability versions 131 → 146

This is the sharpest available axis: `tailcfg.CurrentCapabilityVersion` is upstream's own record of
every client behaviour change that control can observe. The window is anchored to capver 130, the
last version this port tracked before the ledger existed; the declaration here is **125**, held
below 126, see §B. Upstream is at **146** at the new pin — `tailcfg/tailcfg.go:198` — so the window
is sixteen versions, unchanged from the previous revision. Descriptions are upstream's own
(`tailcfg/tailcfg.go`, `tailcfg/nodecap`).

**No row is new at this revision.** `tailcfg/tailcfg.go:198` still reads
`CurrentCapabilityVersion CapabilityVersion = 146` at the new pin, and the capability-history
comment still returns exactly **17** lines, 130 through 146 — the same window the previous revision
derived. Upstream added one version at the previous pin after four pins of stillness and has added
none since, so the window is the same sixteen versions.
**No row changed assessment either**, for the sixth revision running, but the reason is a
*different* one this time and it is worth naming, because the previous five revisions all said "the
tree moved somewhere else". Seventeen commits landed in this tree since `4e8578d`, and eight of them
are ports — but every one of them closes a §B row, not a capability-version row. The one
capability-version row that could have moved is **133**, and it did not: nothing in those seventeen
commits touches which addresses MagicDNS is served or registered on. The tree evidence is re-stated
under the table below. The rows the previous revisions flipped (135, 142, 144) still say why they
flipped, because that history is what makes the row re-checkable.

| Ver | Date | Upstream change | Assessment |
| --- | --- | --- | --- |
| 131 | 2025-11-25 | Client respects `NodeAttrDefaultAutoUpdate` | **not applicable** — self-updating a client binary; this is an embedded library with no updatable binary (`Hostinfo.allows_update` is modelled and false by default) |
| 132 | 2026-02-13 | Client respects `NodeAttrDisableHostsFileUpdates` | **not applicable** — nothing here writes a hosts file; upstream notes the attr is Windows-only as of 2026-02, and there is no Windows `ts_host_net` backend |
| 133 | 2026-02-17 | `NodeAttrForceRegisterMagicDNSIPv4Only`; MagicDNS IPv6 registered with the OS by default | **needs port** — upstream `net/dns/config.go` `serviceIPs` registers **both** `100.100.100.100` and the IPv6 service IP with the OS resolver *by default*, and falls back to IPv4-only when control sets the attr. This tree registers IPv4 only *unconditionally* — which is upstream's attr-set branch, not its default — so the behaviours are not equivalent. Wider than a type signature: the IPv6 MagicDNS service IP is not served here at all (`ts_runtime::magic_dns` binds `100.100.100.100:53` only; `ts_host_net::HostDns::nameservers` is `Vec<Ipv4Addr>` for both the Linux and macOS backends), so registering it before serving it would point the host resolver at a dead address. The port is: serve MagicDNS on the IPv6 service IP, register both by default, honour the attr to drop back to IPv4-only. Host-OS-facing, not wire-facing — no peer or control plane observes it directly — and it pairs with `Config::enable_ipv6` |
| 134 | 2026-03-09 | Client understands `NodeAttrDisableAndroidBindToActiveNetwork` | **not applicable** — Android-only socket binding |
| 135 | 2026-03-30 | Client understands `NodeAttrCacheNetworkMaps` (and `DisableCacheNetworkMaps`, #19947) | **already covered** — *changed from "needs port (optional)"*: the cache landed here in #320, two revisions before this one. `ts_control/src/tokio/netmap_cache.rs` persists the raw decompressed `MapResponse` to `<Config::netmap_cache_dir>/netmap.json` (0600 under a 0700 directory, temp-file rename), `ts_runtime/src/control_runner.rs:1472` loads it before the control client exists, and *both* attributes are honoured — `disable-cache-network-maps` takes precedence and discards an existing cache, as upstream documents. Inert unless the embedder configures storage **and** control grants the attribute |
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
| 146 | 2026-09-02 | Client understands `NodeAttrConnReject` (`debug-conn-reject`); can handle c2n `GET /debug/rejects` | **not applicable (declaration held below it)** — *new at the previous revision* (`85c1efb46`). The attribute turns on an in-memory, LRU-bounded aggregator of recent connection-rejection events (TSMP rejects received, TSMP rejects sent on ACL-blocked inbound flows, pendopen timeouts) keyed by direction/proto/peer/reason, and exposes it over a LocalAPI route and a c2n `GET /debug/rejects`. Both surfaces are out of scope here for reasons already recorded: the c2n route joins 127, 128 and 138 behind the held declaration and takes Go's own `400`/`unknown c2n path` fallthrough, and this fork's LocalAPI serves one route. The attribute is off by default at the control plane, so ignoring it is what a Go client without the feature does. The §B row this version opened at the previous revision — the TSMP rejected-connection messages the aggregator *counts* — is **closed** at this one: both halves landed here in #421. The aggregator on top of them stays out of scope for the reasons above, so this row does not move |

Net: of the sixteen versions upstream added, **one still needs a port** — 133, host-OS-facing —
**four are already covered** (135, 137, 142, 144), and the remaining eleven are not applicable to an
embedded userspace node (138 and 146 among them, once the declaration was held below the versions
that promise them). Identical to the previous revision's count, because neither axis moved: upstream
added no version and this tree's ports all landed in §B. Row 133 was re-checked against the tree at
this pin and is still open: `ts_host_net::HostDns::nameservers`
([`ts_host_net/src/lib.rs`](ts_host_net/src/lib.rs)) is still a `Vec<Ipv4Addr>`, its doc comment
still says "IPv4 nameservers only", and `ts_runtime::tun_actor` still fills it with the single IPv4
service IP, so there is still no IPv6 MagicDNS address to register. Nothing in this revision's
seventeen tree commits touched it — they are MagicDNS *subdomain* resolution (#415), exit-node latency
history (#417), filter reply admission (#418, #419, #430), TSMP rejects (#421, #428) and the
peerAPI DNS gate (#423, #425), none of which changes which addresses the MagicDNS responder is
reachable on. In particular #415 is the near miss to name: it widened *which names* MagicDNS answers
for, not *which addresses* it answers on. The row is still *not* closed by #347 (the quad-100
absorption fix in §B) either: that made the TUN transport absorb every quad-100 packet whatever its
port and protocol, which is about traffic already addressed to `100.100.100.100` — it neither serves
nor registers the IPv6 service IP, which is what 133 asks for.

### B. Behaviour upstream changed in the window that is not capver-gated

Derived from `git log --since=2025-10-06` over the packages that map to crates here, with
docs/typo/refactor commits filtered out. **The sweep list gained a package at this revision** —
`net/routemanager`, upstream's incremental route manager (`a5102d3fc`, 2026-07-09), which now holds
the per-peer data-plane attributes `net/tstun` reads. It had been sitting outside both the mapping
and the loop since July; two of this revision's five new rows are its fields. That is the third time
the sweep list has been short, and the third time the fix was to re-read
[Package mapping](#package-mapping) rather than to trust the loop. Upstream added no other package
in the interval.

#### What changed at this revision

Read this first: it is the shortest honest summary of the diff between this ledger revision and the
last one.

- **All six rows the previous revision opened are closed, because this tree moved.** MagicDNS
  subdomain resolution (#415), the exit-node suggestion's latency history (#417), the UDP/SCTP
  reverse-flow cache (#418), the stateless TCP-non-SYN and ICMP-response carve-outs (#419), TSMP
  rejected-connection messages in both directions (#421, with #428 for the log level a peer can
  drive) and the peerAPI DNS source gate (#423, with #425 for the dropped-filter case) are all
  **already covered** now. Each row below says what closed it and names the code, because a closed
  row still has to be re-checkable — and can reopen.
- **Upstream added no capability version.** 146 is still the ceiling, so §A is unchanged but for row
  146's cross-reference, which now points at a closed row instead of an open one.
- **Five rows opened, and not one of them because upstream moved in this interval.** Fourteen
  upstream commits separate `3945b82f8` from `023255e8a`; nine land in mapped packages and every one
  of the nine is assessed *not applicable* below. The five new rows all come out of reading code
  that has been sitting in swept packages for months or years: `filtertype.Match.SrcCaps` (declared
  at capver 109, 2024-11), `Node.IsJailed` (capver 81), per-peer masquerade (capver 87), the TSMP
  ping responder, and the packet-level peerAPI carve-out. **This is the fifth revision running that
  the sweep's own back-catalogue, not the new delta, was where the rows came from** — see the
  closing note under [Re-deriving this ledger](#re-deriving-this-ledger).
- **Three of the five are the same shape, and it is a shape worth naming: a wire field this tree
  decodes and then ignores.** `Node.IsJailed`, `Node.SelfNodeV4MasqAddrForThisPeer` and its v6
  sibling are all modelled in `ts_control_serde` and all stop there — nothing carries them into
  `ts_control::Node`, and nothing in the data plane reads them. Each is behind a capability version
  *below* the 125 this node declares, so control is entitled to configure all three and to expect
  them honoured. A decoded-and-dropped field is the failure mode a `git grep` for the field name
  cannot distinguish from a ported one; the technique that found all three was reading upstream's
  consumer (`net/tstun/wrap.go`'s `peerConfigTable`) and asking what feeds it here.
- **One of the five is not a missing feature but a `TODO` under an implemented one.**
  `ts_packetfilter` implements `cap:`-prefixed ACL sources end to end — `SrcIp::NodeCap`, the rule
  match, the `CapIter` plumbing — and both call sites hand it an empty capability set
  (`// TODO(npry): wire in nodecaps`). The declared 125 promises capver 109's `SrcCaps` support. It
  is the cheapest of the five to close and the easiest to have missed, because every layer but the
  caller is already right.
- **No row changed because of a divergence decision being revisited.** The four deliberate
  divergences recorded at the previous revisions (DNS-after-router-failure, SSH `acceptEnv`, the
  `callMeMaybe` gate, and the peerAPI DoH server's authoritative-answer widening) were re-checked
  and stand.

#### Rows

- **ACL rules whose source is a capability (`cap:…`) never match**
  (`wgengine/filter/filtertype/filtertype.go`: `Match.SrcCaps`; `wgengine/filter/filter.go`:
  `f.srcIPHasCap`; `ipn/ipnlocal/local.go`: `srcIPHasCapForFilter`; capability versions 100 and 109)
  — **needs port**, and it is the cheapest of the five new rows to close because every layer but the
  caller is already right.
  Upstream lets a policy name its source by *capability* instead of by prefix. `tailcfg.FilterRule`
  carries such a source as the string `cap:<name>`; `MatchesFromFilterRules` splits it out into
  `Match.SrcCaps`; and `runIn4`/`runIn6` pass `f.srcIPHasCap` into every `matches4.match` and
  `matchIPsOnly` call so a packet whose source peer holds the named capability is accepted even
  though no `Srcs` prefix covers it. The test function is `LocalBackend.srcIPHasCapForFilter`, and
  note the refusal it carries: `return !n.UnsignedPeerAPIOnly() && n.HasCap(cap)` — an unsigned peer
  is denied every capability, which is the same rule as the *Peer capabilities are not withheld from
  `UnsignedPeerAPIOnly` peers* row below and must travel with this port rather than after it.
  Upstream dates this precisely: capver 100 (2024-06-18) is "initial support", capver **109**
  (2024-11-18) is "client supports `filtertype.Match.SrcCaps`", and this node declares **125**. So
  control is entitled to compile a `cap:`-sourced rule for us and to expect it honoured.
  Everything here is ported except the last step. `ts_packetfilter_serde`'s `SrcIp` parses the
  `cap:` form into `SrcIp::NodeCap` (its own doc says "the type name is a misnomer: the source may
  not be an IP at all"); `ts_packetfilter::rule` matches a rule's capability sources against a
  supplied set; and the `Filter` trait threads a `CapIter` through `match_for`/`matches`/`can_access`
  from top to bottom. Then both call sites hand it nothing.
  `ts_dataplane::inbound_filter_verdict` reads `// TODO(npry): wire in nodecaps` and then
  `let caps = [];`, and `ts_runtime::peerapi_doh::dns_source_allowed` — the ACL arm of the peerAPI
  DNS gate #423 landed — does the same and says why in place. So a `cap:`-sourced rule is decoded,
  compiled, and can never match: this node drops a packet a Go client accepts, and refuses a peerAPI
  DNS query a Go client answers. It fails closed, which is why it has cost nothing visible; it is
  still a divergence a control plane can trigger at will.
  The port is the capability test itself: resolve the source address to a peer
  (`PeerTracker::peer_by_tailnet_ip`, which the DoH gate already calls) and pass that peer's node
  capabilities into `can_access` at both sites. The cases to pin are the ones that keep it from
  widening the ACL: a source that resolves to no peer supplies no capabilities and is still judged
  on prefixes alone; an `UnsignedPeerAPIOnly` peer supplies none either, per Go's own line; the
  empty capability name matches nothing (Go guards `cap == ""` explicitly); and a rule with *both*
  `Srcs` and `SrcCaps` still accepts on the prefix when the capability is absent. Both call sites
  move together or the two answers disagree — the dataplane would admit a packet the DoH gate
  refuses, from the same peer, under the same policy.

- **A jailed peer gets the ordinary ACL instead of the shields-up filter**
  (`net/routemanager/routemanager.go`: `PeerRoute.Jailed`; `net/tstun/wrap.go`:
  `inboundPacketIsJailed`/`outboundPacketIsJailed`; `ipn/ipnlocal/local.go`: `SetJailedFilter`;
  capability version 81) — **needs port**, and it is the one new row where the missing behaviour
  removes a restriction rather than adding one.
  Control marks a peer `IsJailed` when that peer "should not be allowed to initiate connections" to
  us — upstream's canonical case is a Mullvad-style exit node, a peer this node dials out through
  and which has no business dialling back in. Upstream implements it as a *second, separate filter*.
  `LocalBackend.updateFilterLocked` builds it unconditionally, on every netmap, as
  `filter.NewShieldsUpFilter(localNets, logNets, oldJailedFilter, b.logf)` — a filter with no rules
  at all, sharing flow state with its predecessor — and installs it with `e.SetJailedFilter`. Then
  `tstun.Wrapper` *chooses* between the two per packet: `filterPacketInboundFromWireGuard` uses the
  jailed filter when `pc.inboundPacketIsJailed(p)`, and `filterPacketOutboundToWireGuard` uses it
  when `pc.outboundPacketIsJailed(p)`. Because a shields-up filter has no rules, nothing a jailed
  peer *initiates* is admitted, while the reply-admission carve-outs (TCP non-SYN, ICMP responses,
  the UDP/SCTP reverse-flow cache) still run against the jailed filter's own state — so a connection
  *we* opened to that peer keeps working in both directions. That is the whole point: one-way, not
  no-way. Capver 81 (2024-05-06) declares the client understands `Node.IsJailed`, and this node
  declares 125.
  Here, `is_jailed` is decoded and dropped. `ts_control_serde::Node::is_jailed` exists with Go's own
  doc comment on it; the string appears nowhere else in the tree; `ts_control::Node` does not carry
  it; and `ts_dataplane::filter_inbound_from_peer` takes exactly one `filter` for every peer in the
  batch. So a jailed exit node can open a TCP connection to any port this node's ACL happens to
  leave open — which, for a node that has *selected* that peer as its exit node, is precisely the
  peer with the most reach and the least reason to have it.
  The mechanism is already here, which is what makes the port tractable: `ts_packetfilter`'s
  `ShieldsUpFilter` (`ts_runtime::packetfilter`) is this fork's `NewShieldsUpFilter`, built today
  from the *local* `Env::block_incoming` knob rather than per peer. The port is to build the second
  filter alongside the first and select between them per source peer, the way Go selects per packet,
  plus carrying `is_jailed` onto `ts_control::Node`. The negative cases are what make it safe:
  a reply to a flow *this* node opened to the jailed peer must still be admitted (or selecting a
  jailed exit node breaks the exit node), an unjailed peer must be unaffected, and a peer that
  becomes unjailed in a later netmap must stop being filtered — the jailed flag is per netmap, not
  sticky. Worth reading alongside the shields-up reason on the TSMP reject path, which already
  distinguishes a shields-up deny from an ACL deny; a jailed peer's refusal should carry the same
  reason a Go node's does.

- **Per-peer masquerade addresses are decoded and never applied**
  (`net/routemanager/routemanager.go`: `PeerRoute.MasqAddr4`/`MasqAddr6`; `net/tstun/wrap.go`:
  `peerConfigTable.snat`/`dnat`/`selectSrcIP`/`mapDstIP`; `ipn/ipnlocal/peerapi.go`:
  `isAddressValid`, `5186c3f41` at this pin; capability versions 64 and 87) — **needs port**, and it
  is the row whose failure mode is hardest to diagnose from this side.
  When two tailnets are shared, control can tell this node "peer P knows you as address M" by
  setting `SelfNodeV4MasqAddrForThisPeer` (or the v6 field) on P in our netmap. Upstream honours it
  as symmetric NAT in the data plane: `selectSrcIP` rewrites the source of a packet *we* originate
  to `M` when the destination is P's prefix (and refuses to do so when the source is not our own
  native address, so a subnet-routed packet is left alone), and `mapDstIP` rewrites the destination
  of a packet *from* P back from `M` to our native address. Both go through `checksum.UpdateSrcAddr`
  / `UpdateDstAddr`, and both are documented as never changing packet length or address family.
  L7 follows the same rule: `peerAPIHandler.isAddressValid` accepts a `Host` naming `M`. That last
  function is the only part of this upstream touched in the new interval — `5186c3f41` fixed it to
  require a masquerade match only for the *family* the masquerade applies to, because a v6-only
  masquerade pair still leaves the peer dialling our native v4 peerAPI URL and every fresh
  connection was getting a 403.
  Nothing here applies any of it. `ts_control_serde::Node` models both fields, with Go's own comment;
  neither reaches `ts_control::Node`; and there is no SNAT or DNAT anywhere in `ts_dataplane` — the
  outbound path runs the capture tee, the host-injected-TSMP drop, the flow-state record and the
  routing, and never touches an address. `ts_runtime::peerapi`'s `is_self_address` records the
  consequence honestly and reaches the wrong conclusion from it: its doc says masquerade "is not
  implemented at all and there is no current divergence". The divergence is real, because the
  behaviour is *control-driven and peer-side*. Capver 64 (2023-03-16) and 87 (2024-08-03, "…now
  works") both sit below the 125 this node declares, so control may configure a masquerade for a
  shared peer on the strength of that declaration alone. When it does, the peer sends to `M`, we
  receive a packet addressed to an IP we do not own and the netstack drops it; we reply from our
  native address, which is outside the peer's allowed IPs for us, and the peer drops that. The node
  is simply unreachable from that peer, with nothing in either log naming a cause.
  Two ways to close it, and the choice is the row's real content. **Implement it**: carry both
  fields onto `ts_control::Node`, add the two rewrites to `ts_dataplane`'s inbound and outbound
  paths with incremental checksum updates, and teach `is_self_address` the masquerade address
  per family (Go's shape *after* `5186c3f41`, not before — the pre-fix shape 403s a mixed-family
  peer). **Or refuse it**: hold the declared capability version below 64, which this tree cannot do,
  because #335 established a *floor* of 121 for the peer-relay client half. That leaves implementing
  it, or accepting a knowingly false declaration — which is the kind of thing this ledger exists to
  stop happening silently. Test the refusals with the port: a subnet-routed packet is not SNATed
  (Go returns early when the source is not our native address), a family with no masquerade
  configured is untouched, and the checksum is updated rather than recomputed from scratch.

- **A TSMP ping gets no pong**
  (`net/tstun/wrap.go`: `filterPacketInboundFromWireGuard`'s `p.AsTSMPPing()` arm and
  `injectOutboundPong`; `net/packet/tsmp.go`: `TSMPPingRequest`, `TSMPPongReply`;
  `wgengine/userspace.go`: `OnTSMPPongReceived`) — **needs port**, and it is the new row a real Go
  peer can see without any help from control.
  Upstream answers a TSMP ping in the wrapper, before any filtering: `AsTSMPPing` matches, the node
  notes activity, `injectOutboundPong` builds a `TSMPPongReply` carrying the request's 8-byte
  opaque data and this node's peerAPI port, reverses the IP header with `ToResponse` and injects it
  outbound, and the ping itself returns `filter.DropSilently` so it never reaches the local stack.
  The other direction is symmetric: an arriving pong is handed to `OnTSMPPongReceived`, which
  `userspaceEngine` dispatches through a `pongCallback` map keyed on those same 8 bytes, and that is
  how `tailscale ping` reports an end-to-end round trip that a disco ping cannot measure — disco
  ping proves a *path*, TSMP ping proves the *node* is alive and processing packets.
  This tree names the two type bytes and stops: `ts_packet::tsmp`'s `TSMP_TYPE_PING` and
  `TSMP_TYPE_PONG` each carry the doc comment "Not parsed here". `ts_dataplane`'s inbound TSMP arm
  consumes the disco advertisement and (since #421) the rejected-connection header, and lets every
  other TSMP body through to the ACL step, which accepts it and hands it to `smoltcp` — which has no
  handler for IP protocol 99. So a Go peer running `tailscale ping --tsmp` against this node waits
  out its timeout while the node sits there working perfectly. It is the same class of silence #421
  removed from the ACL-drop path, one message type over.
  The send half is the port worth doing first and it is small: `ts_packet::tsmp` already marshals two
  TSMP bodies against Go's own layout, so a third is the same shape, and `ts_dataplane` already has
  a route for injecting a TSMP message back to a peer — `harvest.rejects_to_send`, built for the
  reject. The pong's `PeerAPIPort` field should be filled from the same `RejectConfig::peerapi_port`
  the reject path already carries, since that is exactly Go's `t.PeerAPIPort` and it is already
  plumbed. The receive half (matching a pong against an outstanding request) needs a caller here to
  be worth anything — `Device` has no `ping` surface today — so it can be a separate decision; say
  which way you went. Refusals to bring with it: a ping whose body is short is not a ping (Go's
  `AsTSMPPing` length check), a ping is dropped rather than delivered even when a pong could not be
  built, and a pong is never generated for a non-IPv4/IPv6 header (Go's `default: return`).

- **The peerAPI has no packet-level carve-out, so it is reachable only through the ACL**
  (`net/tstun/wrap.go`: "Let peerapi through the filter; its ACLs are handled at L7, not at the
  packet level") — **needs a decision more than a port**, and it is the other half of the design
  #423 ported one half of.
  Upstream pairs a deliberate hole in the packet filter with an L7 check inside each handler. The
  hole: after `RunIn` returns a non-`Accept` outcome, `filterPacketInboundFromWireGuard` flips it
  back to `Accept` when the packet is a TCP SYN whose destination port is this node's peerAPI port.
  The check: every peerAPI handler that needs an access decision makes it itself — Taildrop against
  the file-sharing capability, the DNS proxy against `isPeerAPIDNSAllowed`. The two are one design,
  and upstream's reason for it is that a tailnet ACL is written about *ports and services*, not
  about the daemon's own ephemeral peerAPI port, so requiring the ACL to name that port would make
  Taildrop depend on a rule nobody writes.
  This tree now has the L7 half and not the packet half. #423 landed the DNS source gate, and
  `ts_runtime::peerapi`'s `gate_taildrop` is the file-sharing check; but `ts_dataplane` admits a
  peerAPI SYN only if some ordinary rule covers it. `tsmp_reject_for_drop` documents the seam
  exactly — it suppresses the TSMP reject for a peerAPI-port SYN "by suppressing the message here
  rather than by admitting the packet", so a peer whose ACL does not cover our peerAPI port is
  dropped *and* told nothing, where Go would have admitted it and then made an L7 decision.
  Which way to go is a genuine choice and it should be made deliberately rather than by omission.
  Adding the carve-out is parity, and it is what makes Taildrop from a Go peer work under an
  ordinary ACL; it also widens what reaches the peerAPI to every peer, which is safe only because
  the L7 gates are now in place — and they were not, before #423. Leaving it out is stricter, and
  the fork has been running that way; the cost is that Taildrop *to* this node silently fails on a
  tailnet where it works for every Go client, and the failure looks like a network problem. The
  reading this ledger recommends is to add it, now that both L7 gates exist, and to gate it exactly
  as Go does — TCP, SYN only, destination port equal to the peerAPI port, and only when a peerAPI is
  actually running — so the hole is no wider than upstream's. Whichever way it goes, the decision
  belongs in the code as a comment, because the current state reads as an oversight and is not.

- **TSMP rejected-connection messages are neither sent nor understood**
  (`net/tstun/wrap.go`, `wgengine/pendopen.go`, `net/packet/tsmp.go`) — **already covered**,
  *changed from "needs port"*: #421 landed both halves after the previous revision was written, and
  #428 corrected the receive half's log level.
  Upstream's send half injects a `packet.TailscaleRejectedHeader` (TSMP type `!`) back to the peer
  when `filterPacketInboundFromWireGuard` drops an IPv4 TCP SYN on the ACL, carrying the four-tuple
  and a reason — `RejectedDueToACLs`, or `RejectedDueToShieldsUp` when the filter has shields up;
  its receive half parses one in `trackOpenPreFilterIn`, matches it against the pending-open flow
  table, and drops it silently rather than delivering it.
  `ts_packet::tsmp` now carries `TailscaleRejectedHeader` with both a marshaller and a parser, and
  `RejectReason` spells out all four of Go's reasons plus the zero. `ts_dataplane`'s
  `tsmp_reject_for_drop` is the send decision, and it ports Go's guards refusal for refusal:
  nothing for a non-IPv4 drop, nothing for a non-SYN, nothing when `disableTSMPRejected` is set, and
  nothing for a peerAPI-port SYN — that last one reaching Go's outcome by suppressing the message
  rather than by admitting the packet, which is the seam the new peerAPI carve-out row above is
  about. The reason is `SHIELDS_UP` or `ACLS` off `filter.shields_up()`, and `maybe_broken` stays
  false because neither reason is one of Go's non-terminal ones. The receive half consumes an
  inbound reject instead of delivering it to `smoltcp` and records it on
  `InboundHarvest::rejected_flows` for the embedder. #428 is worth keeping in view because it is a
  fork-local consequence rather than a Go one: this tree has no pending-open flow table to match a
  reject against, so Go's `open-conn-track: flow … rejected due to …` line had nothing to filter it
  and any authenticated peer could drive an operator's default-level log at link speed. It now logs
  at `debug!`, in step with the sibling TSMP branches, and the embedder — the layer that *can* do
  Go's match — is the layer that decides a rejection is worth an `info!`.
  The capver-146 aggregator that counts these events is separately out of scope — see §A and the
  *no counterpart here* list.

- **The peerAPI DNS proxy answers any peer that can reach it**
  (`ipn/ipnlocal/peerapi.go`: `isPeerAPIDNSAllowed`, `a4c790224`) — **already covered**, *changed
  from "needs port"*: #423, with #425 for a case the first pass got wrong.
  Upstream gates `handleDNSQuery` before it resolves anything and answers `403 DNS access denied`
  when the gate fails: a peer that is untagged and owned by the same user is allowed outright,
  otherwise the node must be `OfferingExitNode() || OfferingAppConnector()` **and** the peer must
  pass `filter.CheckTCP(remoteIP, 0.0.0.0-or-2000::, 53) == Accept`.
  `ts_runtime::peerapi_doh::dns_source_allowed` is now that gate, evaluated once per connection
  ahead of any resolution. It resolves the connection's source to a known tailnet peer, refuses when
  it is not one, and then asks the live packet filter whether a TCP SYN from that source to an
  off-tailnet address on port 53 would be accepted — `internet_probe_dst` picking the family the way
  Go picks between `0.0.0.0` and `2000::`. Go's self arm is deliberately not ported and the function
  says why: this fork carries no owner notion on the peerAPI path, and the arm only ever *widens*
  upstream's answer, so skipping it is the strictly safer of the two readings. #425 is the
  correction worth recording: a filter that has not been compiled yet is Go's `f == nil` refusal,
  but the first pass reached the same `false` through a path that also refused *after* a filter was
  dropped and rebuilt, which left the gate refusing every peer until the next netmap. The refusal
  now distinguishes "no filter yet" from "filter says no", and both are tested. The one thing the
  gate deliberately does **not** touch is the divergence already recorded in `peerapi_doh`'s module
  docs — this server answers some names authoritatively where Go forwards. That is about *which
  names*; this row was about *which peers*. Note also what the gate still cannot express: it hands
  `can_access` an empty capability set, so a policy that grants internet access by `cap:` rather
  than by prefix refuses here. That is the new `SrcCaps` row above, and closing it closes this
  residue with it.

- **The inbound ACL admits no replies: TCP non-SYN and ICMP responses are dropped**
  (`wgengine/filter/filter.go`: `runIn4`/`runIn6`) — **already covered**, *changed from "needs
  port"*: #419, with #430 for a fragment case it exposed.
  Go accepts an inbound TCP segment that is not a SYN unconditionally ("we want to allow return
  packets on those connections … a new incoming session can't be initiated without first sending a
  SYN") and an ICMP echo response or ICMP error unconditionally ("ICMP responses are allowed"),
  both ahead of any rule match.
  `ts_dataplane::inbound_filter_verdict` now runs both carve-outs in Go's order, between the
  reverse-flow cache and `can_access`, each quoting the upstream comment it ports.
  `ts_packetfilter::PacketInfo` gained an `l4` member carrying the decoded TCP flags and ICMP type,
  which is what made the non-SYN case representable at all — and `PacketInfo::is_tcp_non_syn`
  demands a *decoded* flags byte rather than treating "no flags available" as "not a SYN", so the
  carve-out cannot be reached by a packet whose L4 header was not parsed. The negative case that
  gives the change its value is asserted: an inbound TCP **SYN** with no matching rule is still
  dropped. The third class — ICMP that is neither a response nor an error still matching IPs-only —
  was already right in `ts_packetfilter::rule` and was left alone.
  #430 is the fork-local consequence, and it is the kind this ledger exists to record: making the
  verdict depend on a decoded L4 header meant the *head fragment* of a fragmented reply, which
  carries the L4 header, was being classified before reassembly and dropped. The fragment
  classification and the reply carve-outs now compose in the right order, with the pre-existing
  RFC 1858-style fragment refusals unchanged.

- **Outbound UDP flows are not tracked, so their replies need an explicit rule**
  (`wgengine/filter/filter.go`, `net/tstun/wrap.go`: `e0677ccc7`) — **already covered**, *changed
  from "needs port"*: #418.
  Go's `Filter` carries a 512-entry `flowtrack` LRU that `RunOut`'s `UpdateOutboundFlowState` fills
  with the *reversed* tuple for UDP and SCTP, consulted first by `runIn4`/`runIn6` for those
  protocols and returning `Accept, "cached"` on a hit; `e0677ccc7` extended the fill to netstack's
  injected path, which is the only path this fork has.
  `ts_dataplane::flowtrack` is now that cache, bounded at Go's own 512 rather than at an invented
  number, filled by `process_outbound` for every outbound UDP and SCTP packet and consulted at the
  top of `inbound_filter_verdict` — ahead of the stateless carve-outs, in Go's order, with the
  upstream code quoted beside it. The comment that matters for the next reader is on the miss path:
  "the cache only ever admits, it never denies", so a miss falls straight through to the rule match
  rather than short-circuiting to a drop. The negative cases are asserted: an inbound datagram with
  no tracked flow and no rule is still dropped, an entry does not admit a datagram from a different
  source address or port, and the cache is bounded so a peer cannot grow it without limit.

- **Exit-node suggestion ranks on the latest report, not on recent per-region latency**
  (`ipn/ipnlocal/local.go`, `net/netcheck/netcheck.go`: `f442cda99`, `e9e209673`) — **already
  covered**, *changed from "needs port"*: #417.
  Upstream's `suggestExitNodeUsingDERP` takes `preferredDERP` plus a `regionLatency` map from
  `netcheck.Client.RecentRegionLatency()` — the lowest latency seen per region across a retained
  history whose window is tied to the full-report interval — rather than the single most recent
  report, because an incremental report made a distant exit node fall back to a random pick.
  `ts_runtime::exit_node_suggest::suggest_exit_node` now takes `(preferred_region,
  region_latency)`, and `ControlRunner::recent_region_latency` is this fork's
  `RecentRegionLatency()`: a per-region best-latency history kept beside the measurer, with its
  retention window tied to the re-measure cadence the way upstream ties its to
  `fullReportInterval`. `min_latency_derp_region` is unchanged as a port of `minLatencyDERPRegion`
  and now reads the history instead of one report, and the two injected selectors — ports of Go's
  `selectRegionFunc`/`selectNodeFunc` — are kept, because they are what makes the algorithm
  testable without a DERP map. The reason this mattered more here than upstream is unchanged and
  worth keeping written down: `ts_netcheck::Config` defaults to `complete_threshold: 3`, so a report
  against a real DERP map names a handful of regions *every* time, not merely on incremental runs.

- **MagicDNS does not resolve subdomains for peers carrying `dns-subdomain-resolve`**
  (`net/dns/resolver/tsdns.go`, `tailcfg/nodecap/nodecap.go`: `f48cd4666`) — **already covered**,
  *changed from "needs port"*: #415.
  Upstream's resolver keeps a `SubdomainHosts` set beside its `Hosts` map and, on a miss, walks the
  queried name's parents looking for one that names a subdomain host, so for a node named `machine`
  both `my.machine` and `be.my.machine` resolve to it at any depth.
  `ts_runtime::magic_dns` now carries the attribute onto the DNS view and does the parent walk, and
  the cases that keep it from becoming a wildcard are pinned: a node *without*
  `dns-subdomain-resolve` still answers `NXDOMAIN` for its subdomains, an exact name still beats a
  parent match, the walk stops at the tailnet zone rather than climbing out of it, and the
  multi-label case resolves. The peerAPI DoH server shares `decide`, so the widening reaches that
  path too — `peerapi_doh`'s module docs now say so explicitly rather than leaving it to be
  discovered, which is the right treatment for a behaviour that widens what a *peer* can ask this
  node about.

- **TSMP disco-key advertisement** (`net/packet`, `net/tstun`, `wgengine/magicsock`,
  `control/controlclient`: `c54d24369`, `c870d3811`, `bf467727f`, `82a381e54`, `014d5bd9e`,
  `3799eaf26`, `fb27d87e0`) —
  peers advertise their disco key in a TSMP message around the WireGuard handshake, and learn a
  peer's disco key from it without restarting WireGuard. It is the one item here a real Go peer will
  *send us* unprompted. **Both halves remain covered.** Receive: `ts_packet::tsmp` decodes the
  advertisement (Go `Parsed.AsTSMPDiscoAdvertisement`), `ts_dataplane::filter_inbound_from_peer`
  consumes it ahead of the ACL and drops it rather than delivering it to the local stack (Go
  `tstun.filterPacketInboundFromWireGuard` returning `filter.DropSilently`), a zero advertised key
  is ignored (Go's `!discoKeyAdvert.Key.IsZero()` guard, `82a381e54`), and
  `PeerTracker::learn_disco_key` applies it to the peer. Send: `ts_packet::tsmp` marshals it against
  Go's own `TestTSMPDiscoKeyAdvertisementMarshal` vectors, `ts_tunnel` reports the two moments
  `wireguard-go` calls `SendPriorityMessage` (`device/receive.go`) and carries its refusals (empty or
  oversize is dropped, not truncated; a peer with no live keypair sends nothing), and
  `ts_dataplane::DiscoAdvertisementState::advertisement_for` decides the content, refusal for
  refusal against Go `magicsock.Conn.PriorityMessageForPeer` — including the one a wireguard-only
  peer depends on (`ep.isWireguardOnly` ⇒ send nothing), which matters because that peer is a plain
  `wireguard-go` or kernel endpoint that would receive an IP-proto-99 packet it has no idea what to
  do with. Row 144 above is the capability-version view of the same work.
  **The three rows an earlier revision opened off the back of this one have all closed**; they are
  the next three bullets, and each records what closed it.

- **A peer's *inactive* known disco key is accepted on ingress, and becomes the active key**
  (`wgengine/magicsock/endpoint.go`, `wgengine/magicsock/magicsock.go`: `da1fc4fc8`, `e1d17a6b9`) —
  **already covered**, *changed from "needs port"*: #372 landed it after an earlier revision was
  written.
  Upstream resolves every inbound disco comparison in `Conn.handleDiscoMessage` and
  `unambiguousNodeKeyOfPingLocked` through `endpoint.checkAndUpdateDiscoKey`, which returns true for
  **either** slot's key and, when the key seen is the currently-inactive one, compare-and-swaps
  `tsmpActive` so that key becomes the active one and calls `changedActiveDiscoLocked`.
  Here `PeerDb` now carries a second index — `inactive_disco_idx`, the peer's other known key — and
  `PeerDb::peer_by_known_disco_key` resolves an inbound frame's sender against both, so a peer
  mid-rotation that is still sending under the key control gave us is understood instead of dropped.
  `EndpointDisco::check_and_update` is the switch itself, cited to
  `endpoint.checkAndUpdateDiscoKey` by name, and it keeps the refusal that carries the security
  value: a key belonging to **neither** slot is refused even though the frame that carried it
  opened correctly, so a peer cannot move itself onto a key nobody told us about. The switch and the
  path invalidation it triggers travel together, on the one `peer_watch` snapshot every other
  disco-key transition already used.

- **A control disco-key update does not preempt an active TSMP-learned key** (`wgengine/magicsock`,
  `control/controlclient`, `ipn/ipnlocal`: `f53c28101`) — **already covered**, *changed from "needs
  port"*: #370.
  Upstream's `endpoint.updateDiscoKey` sets `epDisco.tsmpActive = old.tsmpActive || key.IsZero()`:
  control's new key is still *recorded*, but a TSMP-learned key that is already active stays active,
  and the switch back to control's key happens only when disco is actually received under it.
  `EndpointDisco::update_from_control` is now that line — `self.tsmp_active = self.tsmp_active ||
  key.is_none()` — and the doc comment this ledger called "the single most misleading line in the
  tree on this subject" at an earlier revision has been rewritten to say what the code now does.
  The ordering hazard an earlier revision flagged was respected: #372 landed the ingress half
  first, so a peer whose key control has legitimately rotated is not stranded by the stickiness.
  The `ScheduleHandshakeOnUserSend` half of `f53c28101` still has no target here — `ts_tunnel` is
  this fork's own WireGuard implementation and has no such callback — but the behaviour it replaced
  (tear down and re-establish on every disco-key change) is not what this tree does either, so
  nothing regresses by leaving it.

- **The trusted direct path is invalidated when a peer's disco key changes**
  (`wgengine/magicsock/endpoint.go`: `65d222674`, `e1d17a6b9`'s `changedActiveDiscoLocked`) —
  **already covered**, *changed from "needs port"*: #369.
  Upstream sets `trustBestAddrUntil = 0` and calls `invalidateDiscoPathLocked()` on *every* disco-key
  transition, keeping `bestAddr` so data keeps flowing while a fresh path is confirmed.
  An earlier revision found the right primitive here with no caller on this path — it had
  `MagicSock::rebind` and nothing else. #369 added the missing one, and gave it its own method rather
  than reusing the rebind case, because the two are not the same invalidation:
  `ts_magicsock::path::PeerPaths::invalidate_disco_path` clears the trust window, the in-flight
  probes (their tx ids went to the old key, so a matching pong must not re-confirm across the
  rotation) and every candidate's measurement and ping timestamps — so the next pinger tick is a full
  immediate sweep — while **keeping** `best` and the candidate set, which is exactly Go's "keep
  bestAddr so that we can still send data while we find a new path". `invalidate_best`, the rebind
  case, still clears the best address outright, because there the *local* NAT mapping changed and the
  address is stale as an address.
  The path in is `ts_runtime::direct::disco_key_rotations`, which diffs consecutive peer snapshots
  and calls `MagicSock::changed_active_disco` — this fork's `changedActiveDiscoLocked` — so a
  control-side change, a TSMP advertisement and an active-slot switch on receive all reach the same
  invalidation, which is what stops the node coasting for a full `TRUST_DURATION` (6.5 s) on a path
  confirmed by a pong signed under a key the peer has since replaced. One fork-local limit is worth
  recording rather than leaving to be rediscovered: `PeerPaths::best_addr` gates on trust, so this
  node does not keep *sending* to the retained best the way Go's `addrForSendLocked` dual-sends to an
  untrusted `bestAddr`. The retained address is what the immediate re-probe targets, and traffic
  rides DERP for the one round trip it takes to re-confirm.

- **Peer capabilities are not withheld from `UnsignedPeerAPIOnly` peers**
  (`ipn/ipnlocal/node_backend.go`, `wgengine/magicsock/magicsock.go`, `control/controlclient/map.go`:
  `0eb38dc2e`) — **half covered, half still needs port**, *changed from "needs port"*.
  Upstream refuses such peers three things, all unconditionally and none of them dependent on
  tailnet lock being enabled, because the point is that an unsigned peer is by definition outside
  the lock's coverage: `upgradeNode` clamps their `AllowedIPs` back to their own `Addresses`;
  `nodeBackend.peerCapsLocked` / `PeerCapsForIP` / `PeerCapsForService` return nil for them; and
  `magicsock.nodeHasCap` refuses them the relay-allocation and relay-target capabilities.
  The route clamp landed here at #365: `ts_control::Node` now carries `unsigned_peer_api_only`, and
  the `From<ts_control_serde::Node>` impl clamps `accepted_routes` back to the node's own addresses
  whenever it is set, with a regression test that gives an unsigned and a signed peer the *same*
  advertised route so it cannot pass by dropping routes generally. That closes the case where
  control could hand an unsigned peer `0.0.0.0/0` and have this node route to it.
  The capability half is untouched. There is still no per-peer capability map anywhere in the domain
  model — `ts_control::Node` carries only the node-attribute `cap_map`, and
  `ts_runtime/src/peerapi.rs` still records threading `PeerCapMap` in as an open limitation — and
  `ts_magicsock`'s relay module still accepts a `CallMeMaybeVia` with no capability gate on the peer
  at all. Admission under an *active* lock remains the separate, deliberate divergence
  [`docs/PARITY_ROADMAP.md`](docs/PARITY_ROADMAP.md) records: this tree drops unsigned peers
  outright there, which is stricter than Go.

- **MagicDNS negative answers carry an SOA, and positive answers expire in 5 seconds**
  (`net/dns/resolver/tsdns.go`: `0bbe6394d`) — **already covered**, *changed from "needs port"*:
  #367. Upstream attaches the zone's SOA to the authority section of every NXDOMAIN and NODATA
  response it is authoritative for, advertising a 10-second negative-caching TTL (RFC 2308), and
  dropped the positive-answer TTL from 600 seconds to 5; the motivating bug is a macOS
  `mDNSResponder` that caches an SOA-less negative answer on its own schedule, so a name queried
  shortly *before* a node was renamed to it does not start resolving until something flushes the
  cache. `ts_dns_wire`'s `ANSWER_TTL` is now `5`, `NEGATIVE_TTL` is `10`, and `encode_response`
  emits an authority section carrying a single SOA whose MNAME and RNAME both repeat the zone name
  and whose REFRESH/RETRY/EXPIRE/MINIMUM all repeat the negative TTL — the same placeholder shape as
  Go's `marshalSOA`, for the same reason: nothing consumes those fields, only the TTLs mean
  anything. The interaction an earlier revision warned about was handled rather than dodged: an
  authority record makes a previously-fitting negative answer larger, and the truncation path is
  tested with the SOA present.

- **Host-injected TSMP is dropped on the TUN-to-WireGuard path** (`net/tstun/wrap.go`:
  `9175fe267`) — **already covered**, *changed from "needs port"*: #360.
  Upstream's `filterPacketOutboundToWireGuard` drops any packet the host writes into the TUN whose
  `IPProto` is TSMP, counting `tstun_out_to_wg_drop_tsmp`, on the rule that "TSMP traffic should only
  originate from tailscaled, not from the host itself". `ts_dataplane::process_outbound` now makes
  that check at the top of the outbound path, before routing. The negative case that gives the fix
  its value is asserted: this node's *own* advertisements are injected below that point via the
  priority-message path, so they still go out — without that test the fix would silently disable
  capability version 144.

- **A TKA `SyncOffer` offers every checkpoint ancestor** (`tka/sync.go`, `tka/limits.go`:
  `f6fa29463`) — **already covered**, *changed from "needs port"*: #363.
  Upstream replaced the exponential ancestor sampling (`ancestorsSkipStart = 4`,
  `ancestorsSkipShift = 2`) with "offer every ancestor whose `MessageKind` is `AUMCheckpoint`", and
  raised `maxSyncHeadIntersectionIter` from 400 to 1000, because nodes compact aggressively and an
  exponentially sampled offer can be *disjoint* from what the node kept — leaving it unable to find
  a common ancestor and stuck in a poll-and-fail loop with a permanently stale view of the tailnet.
  `ts_tka::Authority::sync_offer` now walks parents and pushes checkpoints, with the cap at 1000.
  The trap an earlier revision named was checked: `missing_aums` consumes the same offer, and both
  arms of `intersection` were re-tested against the checkpoints-only ancestor shape.

- **A peer removal evicts index entries another peer has since claimed**
  (`ipn/ipnlocal/node_backend.go`: `2ae2808b6`) — **already covered**, *changed from "needs port"*:
  #412 landed it after the revision that opened the row was written.
  Upstream's `nodeBackend` used to evict its index entries (`nodeByAddr`, `nodeByKey`,
  `nodeByWGString`, `nodeByStableID`, `nodeByName`) from a node's last-known value without checking
  that the entry still pointed at that node, and made every eviction conditional through a
  `deleteIfOwned` helper. The exposure was never theoretical here and was worse than the ordering
  upstream had to defend against: `PeerTracker::apply_peer_update` applies a `Delta`'s upserts first
  and its removals second, so the intra-batch ordering that broke Go is the ordering this tree always
  uses, and a peer inheriting a departing peer's tailnet IP was installed in `ip_idx` and then evicted
  by the departing peer's removal.
  `ts_runtime/src/peer_tracker/peer_db.rs` now carries `delete_if_owned` and `delete_ip_if_owned`, and
  every retraction in `IndexState::remove` goes through one of them — `nk_idx`, `stableid_idx`,
  `control_idx`, both `ip_idx` entries, **both** halves of `name_idx` (the fqdn half was unguarded too,
  which an earlier revision's write-up missed) and `disco_idx`. The IP helper matches on the exact
  prefix (`lookup_prefix_exact`), never a longest-prefix match, because a peer owns the row for its own
  address and not for whatever covering route answers a lookup. The five hand-rolled guards already on
  the upsert path call the same helper, so there is one definition of the rule rather than six
  spellings of it — which is how the removal path came to be missing it. `route_idx` is deliberately
  still unguarded: it is a multimap keyed by route holding a vec of peer ids, so a successor's claim
  does not displace the departing peer's row and the removal already filters by id. The orderings that
  actually differ are tested, and so is the positive case, so the fix cannot pass by never evicting
  anything.

- **Expired peers are neither flagged nor re-evaluated when their keys expire**
  (`ipn/ipnlocal/expiry.go`, `ipn/ipnlocal/local.go`: `0640312e5`, and the `expiryManager` the commit
  repairs) — **already covered**, *changed from "needs port"*: #408, with #410 for two follow-ups.
  Upstream's `expiryManager` does three things this tree did none of: `flagExpiredPeers` marks a peer
  whose `KeyExpiry` has passed, clears its `Endpoints` and `HomeDERP` and breaks its node key with
  `key.NodePublicWithBadOldPrefix`; `nextPeerExpiry` finds the soonest future expiry across peers and
  self so a timer can re-evaluate on time rather than on netmap arrival; and `onControlTime` corrects
  every expiry comparison for the local-to-control clock delta, ignoring a delta-adjusted "now" before
  a hardcoded epoch so a control server sending a wildly past `ControlTime` cannot expire the tailnet.
  `ts_control::ExpiryManager` ([`ts_control/src/expiry.rs`](ts_control/src/expiry.rs)) is all three,
  function for function, and `ts_runtime::status::StatusNode` now carries the flag for a watcher to
  read. The peer is **flagged, not dropped** — that is the point: it keeps its identity, so `whois`,
  `status` and a refused peerAPI dial can each say *why* it is unreachable rather than "no such peer",
  which is what Go's "peer's node key has expired" refusal reads as.
  Two fork-local consequences were found and fixed in #410 rather than left to be rediscovered, and
  both are worth keeping in view because they are consequences of this tree's shape, not Go's. Upstream
  re-derives its netmap from `controlclient`'s pristine peer store on every pass, so a peer whose key
  control later extends comes back with its endpoints and DERP home restated; **here the peer db *is*
  the store**, so flagging destroyed the only copy and a recovered peer came back unroutable. The memo
  this fork already kept for the pristine node key (`previously_expired`, Go's `previouslyExpired` set)
  now keeps the endpoints and DERP region alongside it, and the restore is non-clobbering, so an update
  that extends the expiry *and* restates endpoints keeps control's word. Separately, `Device::send_file`
  read `expired` and `peerapi_addr` off a caller-supplied `NodeInfo` snapshot that could be arbitrarily
  old; it now re-reads the live record at the decision point.

- **A REFUSED or SERVFAIL from the first upstream ends the forward**
  (`net/dns/resolver/forwarder.go`: `0b4c0f208`) — **already covered**, *changed from "needs port"*:
  #406. Upstream treats both response codes as *soft* while a query is outstanding against more than
  one upstream — a broken resolver answering REFUSED quickly must not beat a healthy resolver that is
  still working — and returns an upstream's own SERVFAIL bytes verbatim rather than a locally
  synthesized packet, because the upstream's answer may carry RFC 8914 extended DNS error information.
  `ts_runtime::magic_dns` no longer ends the walk on either code: the first such response is
  remembered, the walk goes on, and it is relayed only once the upstream list is exhausted — verbatim,
  and in preference to the caller's synthesized SERVFAIL, so an extended error survives. Every other
  RCODE, NXDOMAIN included, is a real answer and still ends the walk where it is found. The anti-
  poisoning check an earlier revision insisted on is unchanged and still runs first: a datagram from
  an address we did not query, or one that does not echo our transaction id and question, is discarded
  before it can be relayed *or* remembered as the soft error, so an off-path injector cannot plant the
  response a fully-refused forward ends up returning. The socket work (`ask_upstream`) and the decision
  of which response the client gets (`forward_walk`) are now separate functions, which is what makes
  the walk testable without a network.

- **`UserProfile.Groups` is not modelled** (`tailcfg`: `6a19995f1`) — **already covered**, *changed
  from "needs port"*: #404. Upstream reintroduced `UserProfile.Groups`, "a subset of SCIM groups (e.g.
  `engineering@example.com`) or group names in the tailnet policy document (e.g. `group:eng`) that
  contain this user and that the coordination server was configured to report to this node", carried in
  `MapResponse.UserProfiles` and surfaced through `WhoIs`. It is now modelled the whole way:
  `ts_control_serde::UserProfile` gains `groups: Vec<Cow<'a, str>>` (`Cow`, not `&str`, because Go
  HTML-escapes `&` on marshal and a borrowed slice would fail the decode of the whole profile on a group
  named `R&D`), `ts_control::UserProfile` carries it into the domain, and
  `ts_runtime::status::WhoIs` now holds `user_profile: Option<UserProfile>` instead of a flattened
  label — `WhoIs::user()` gives back exactly the old string and `WhoIs::user_groups()` the groups. The
  decision an earlier revision left open (widen `WhoIs` or add a narrow accessor) went the way it
  recommended: widen, because that is the shape that absorbs the next `UserProfile` field without
  another decision. The absent case is asserted as well as the present one — an omitted key, an
  explicit `[]` and a wire `null` all decode to an empty list and none of them fails the profile.

- **IPv6 fragment extension-header handling in the filter** (`net/packet`, `wgengine/filter`:
  `4c4ec3d46`, `26b2ed0a6`) — **already covered**, unchanged at this revision and re-checked. #342 gave
  `ts_dataplane` the IPv6 half of the RFC 1858-style classification it had only for IPv4, #343
  extended it to a Fragment header hidden behind a chained extension header, and #345 rewrote the
  tests so each extension header has its own control and its drop cannot pass vacuously. #398 added
  one more pin at an earlier revision (the pre-rule drop of a proto-0 first IPv6 fragment), and #390
  stopped a prepended IPv6 header choosing which rule matches.

- **Quad-100 traffic is absorbed locally regardless of port and protocol** (`wgengine/netstack`:
  `1b4091161`) — **already covered**, unchanged at this revision. `ts_runtime::tun_actor::classify_service_ip`
  returns `ServiceIpPacket::Absorbed` for **every** packet destined to `100.100.100.100` that is not
  the UDP/53 query it serves, and an unserved quad-100 TCP port is answered with a RST built by
  `build_tcp_reset` (RFC 9293 §3.10.7 CLOSED-state rules) rather than dropped into a retransmit
  loop — upstream's `hittingServiceIP` case in `acceptTCP`.

- **The DNS forwarder sets TC against the *client's* size limit** (`net/dns/resolver`:
  `8cac8b117`) — **already covered**, and refined four times more at an earlier revision. #339 added
  `set_tc_if_over_client_limit`; #395 then corrected *which* answers it applies to, so this node
  sets TC on the same answers a Go node does and not on others; #380 stopped a 4096-byte answer Go
  marks truncated being relayed as though it fit; #387 answered the TCP retry a truncated answer
  forces; and #397 stopped an oversized delegated DoH answer killing the TCP client. The
  pre-existing `MAX_UPSTREAM_RESPONSE` (4096) relay cap stays the separate bound it always was.

- **Peer relay** (`disco` 0x04–0x09, `net/udprelay`, `feature/relayserver`; capver 120/121, i.e.
  *behind* the declared 125) — **ported (client half)**, unchanged in scope at this revision. All
  nine disco message types have a codec (`ts_disco_protocol`'s relay module, checked against Go's own
  `disco_test.go` vectors), and `ts_magicsock` runs the client side end to end: an inbound
  `CallMeMaybeVia` starts the 3-way bind handshake with the named relay server, and a relayed
  ping/pong confirms a Geneve-framed path that carries WireGuard data instead of falling back to
  DERP. Direct paths still take priority over relay ones. #400 hardened it here at an earlier revision: a
  relay server that *refuses* the handshake no longer fails silently. Not ported, and out of scope
  for an embedded client: **serving** as a relay (`net/udprelay.Server`, `feature/relayserver`) and
  *requesting* an allocation of our own. Worth recording alongside: #335 gave the declared capability
  version a **floor** because of this row — a Go peer decides whether to offer us a relay path with
  `magicsock.capVerIsRelayCapable(version)`, which is exactly `version >= 121`, so declaring less
  would silently disable the client half that is ported and working. The declaration is bracketed
  from below as well as above — floor 121, ceiling under 126 — with a ported predicate and a test
  behind the floor.

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
  share, so it costs nothing.)

- **Services model extension** (`tailcfg`: `1cd8bcc82`, `6cd185bf3`, `fc9b18f50`) — upstream added
  client application *actions* (with attributes and `ServiceActionType` constants) to the VIP
  services model. **Needs port**, unchanged: `ts_control_serde/src/service_vip.rs` models
  `VipService` and the c2n response and still carries no action types, so the consume side cannot
  stay current with what control may send.

- **`Node.IsRouter` / `PeerStatus.IsRouter`** (`8d830599b`) — **already covered**, and corrected
  again at an earlier revision. Upstream added no wire field: both are *derived predicates* — "does this
  node route addresses besides its own" — spelled as methods so IPN-bus watchers can classify
  routers out of the netmap they already hold. Mirrored here as `ts_control::Node::is_router` (over
  `accepted_routes` vs `addresses`) and `ts_runtime::status::StatusNode::is_router` (over
  `allowed_routes` vs `ipv4`/`ipv6`), cross-checked against each other the way upstream's
  `TestNodeIsRouter` cross-checks its two definitions. #337 fixed the domain predicate (it tested each
  accepted route against the *identity* projection — the first prefix of each family — rather than
  against control's whole `Node.Addresses` list), #340 fixed two test fixtures added alongside it,
  and **#402 fixed the same narrowing where it had survived**: the status
  projection. `StatusNode::is_router` was still asking its question of the `ipv4`/`ipv6`
  first-of-family pair, so a peer control assigned two single-IP prefixes of one family, advertising
  both, was reported as a router to embedders while Go's `PeerStatus.IsRouter` — which tests each
  `AllowedIPs` prefix against the whole `TailscaleIPs` slice — says it is not. `StatusNode` now
  carries `tailscale_ips` beside the identity pair, because the predicate cannot recover addresses
  the projection dropped. Control does not assign that shape today, which is why the divergence had
  cost nothing; the surface it was wrong on is the one embedders actually read.

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
  Nothing observed to have broken. `b3c719581` bumped upstream's toolchain to Go 1.27.1 before the
  previous pin, so the v2 encoder is what upstream actually ships rather than what it was preparing
  for — which raises, not lowers, the value of doing the audit. The `UserProfile.Groups` row above is
  a reminder of the cheaper half of the same job: a field-by-field re-read of `tailcfg` against
  `ts_control_serde` finds omissions that no amount of tag-semantics reasoning will.

#### Not applicable, or already covered, from the commits new at this pin

Recorded so the next re-derivation does not re-read them. Fourteen upstream commits landed between
`3945b82f8` and `023255e8a`, nine of them in mapped packages. **None opened a row** — the first time
that has been true of a whole interval, and the reason the five new rows above all come from the
back-catalogue instead.

- **`net/socks5`: nil `Server.Logf`, and a data race on the UDP client address** (`de01da564`,
  `0301c7493`, with `f48358288` for the test) — **not applicable**, both, and for the same
  structural reason. The first is a nil-func hazard: `Serve` copied `Server.Logf` into each `Conn`,
  so the UDP error paths called a nil `func` instead of falling back to `log.Printf`. The second is
  a data race: `handleUDPRequest` wrote `Conn.udpClientAddr` on the reader goroutine while
  `handleUDPResponse` read it from one goroutine per target, now guarded by `syncs.MutexValue`.
  Neither has a target here on two counts. `src/loopback.rs` is a SOCKS5 **CONNECT-only** server —
  it implements no `UDP ASSOCIATE`, so there is no UDP client address to race over — and Rust has
  neither a nil function value nor an unsynchronized shared field that compiles. Worth re-reading
  only if UDP association is ever added; the field the race was on is exactly the state such an
  implementation would need.
- **`net/tstun`: handle a zero-value `stack.GSO.MSS`** (`5208e6d7f`) — **not applicable.** A guard
  for `stack.GSO.Type != stack.GSONone` with an MSS of zero. Same ground as capability version 140:
  there is no GRO/GSO offload on this datapath (`ts_transport_tun` is single-queue), so there is no
  GSO descriptor to carry a zero MSS.
- **`wgengine/netstack`: split outbound traffic into destination queues** (`2c30be2a4`) — **not
  applicable.** gVisor's writes are routed into dedicated WireGuard, host and loopback queues, each
  drained by its own goroutine, "preparing the outbound path for batching and multiqueue WireGuard
  delivery". It is internal concurrency shape with no observable behaviour change, and it is shape
  this fork does not share: `ts_netstack_smoltcp` hands outbound packets to the runtime through a
  `Channel` rather than through a gVisor link endpoint. Recorded rather than skipped because it is
  the first move in a batching series, and a later commit in that series may well change what goes
  on the wire.
- **`wgengine/wgcfg`: size crypto and per-peer queues by CPU factor** (`960cb5046`) — **not
  applicable as a port, but it names a live constraint here.** Upstream replaced fixed queue depths
  with CPU-proportional ones "to better balance throughput vs backlogged packet memory
  consumption", cutting peak RSS by 46–77% in its own benchmarks with throughput flat or up. There
  is no `wireguard-go` queue here to size — `ts_tunnel` is this fork's own implementation — so
  there is nothing to port. It lands next to a memory constraint this fork *does* have and
  documents elsewhere: `Config::tcp_buffer_size` is allocated eagerly per socket, so a forwarder
  carrying many concurrent flows pins memory in proportion to flow count with no auto-tuning. Both
  are the same trade read from two sides; upstream's answer (scale the bound to the host) is the one
  this fork has not taken.
- **`ipn/ipnlocal`: require a peerapi masquerade `Host` match only per address family**
  (`5186c3f41`) — **not applicable as a standalone fix, and folded into the masquerade row above.**
  `isAddressValid` rejected every non-masquerade destination whenever *any* masquerade address was
  set for the peer, so a v6-only masquerade pair 403'd the peer's dials to the native v4 peerAPI
  URL. There is nothing to fix here because there is nothing to be wrong: masquerade is decoded and
  never applied. It is written up above instead, because it is the shape the port must take if
  masquerade is implemented — the pre-fix reading of `isAddressValid` is a bug this fork would
  otherwise reproduce from scratch.
- **`net/dns`: export `OSConfigurationReadWarnable`** (`970cc199f`) — **not applicable.** The
  mapped-package hunk of an otherwise `tstest/natlab` commit: a health `Warnable` is exported so a
  VM test can take the warning's wording from it. There is no health tracker here (see the *no
  counterpart here* list) and `ts_host_net` has no `openresolv` backend, which is what the test
  covers.
- **`net/dnscache`, `feature/dnsresolvecache`: only persist resolutions after TLS verification**
  (`023255e8a`) — **not applicable**, and it is the new pin only because it was HEAD when this
  revision was derived. It tightens `aa2681ac5` (assessed at the previous revision) so a resolution
  is written to the on-disk cache only once it has passed TLS certificate validation, weeding out a
  lying resolver such as a captive portal's. The two reasons the parent commit had no target here
  are unchanged: this fork resolves control through control's own `DialPlan` and the system resolver
  with no answer cache in between, and upstream links the feature into `tailscaled` and deliberately
  **not** into `tsnet`.
- **`tstest/integration`: wait for the daemon to exit after killing it** (`7dfc149c8`) — **not
  applicable.** Upstream's own integration harness, and a daemon this library does not have.
- **Dependency and toolchain bumps** (`b658bd558` x/crypto + x/mod + x/tools, `7b0d5155c`
  wireguard-go, `3d3261b66` `go.toolchain.rev`, `653a95434` go-tool-cache) — **not applicable.**
  The `wireguard-go` bump is the one to keep half an eye on, per the Package mapping note: it is an
  upstream *dependency* that `ts_tunnel` re-implements, so it is tracked through `go.mod` rather
  than through the sweep. Nothing in this bump changes the handshake or the timers.

Carried from the previous revision and re-checked at this pin, because a reader of the TSMP rows
will otherwise go looking for them:

- **The gates on upstream's *periodic* TSMP disco advertiser no longer exist** (`ee76a7d3f` "do not
  send TSMP disco when connected", `92ab4866d` raising `discoKeyAdvertisementInterval` to two minutes,
  `be2f554dd` disabling the advert when netmap caching is off, `54005752a` suppressing it when
  `bestAddr` is a peer relay, over `c76113ac7`/`2d21dd46c`/`151644f64`) — **not applicable, and the
  reason is that upstream deleted the mechanism.** `3799eaf26` moved the send onto `wireguard-go`'s
  `SetPriorityMessageOnEstablishmentFunc`, and at this pin `PriorityMessageForPeer` is the whole send
  side: a zero disco key, an unknown endpoint, an invalid self node, an `isWireguardOnly` peer, no
  self address in the destination's family, or a marshal failure each return nil, and there is no
  timer and no knob left. That is exactly the set `ts_dataplane::DiscoAdvertisementState::advertisement_for`
  ports, which is why the "refusal for refusal" claim in the TSMP row still holds — re-checked against
  `wgengine/magicsock/magicsock.go` at `023255e8a`, not carried forward on trust.
- **`net/netcheck`: mark address family sendable on STUN response** (`92ec10267`) — **not applicable.**
  A race between `runProbe` recording `IPv4CanSend`/`IPv6CanSend` after `SendPacket` returns and a fast
  STUN response being processed first, which produced a report with a valid mapping but `CanSend`
  false and made magicsock rebind. `ts_netcheck` has no `Report` type and no `CanSend` fields — it
  measures DERP-region latency over HTTPS and deliberately runs no STUN prober of its own (see the
  note in `ts_netcheck/src/lib.rs`); production reflexive discovery is the disco pong harvest on
  magicsock's one bound socket. There is no second writer to race.
- **`disco`: `UDPRelayEndpoint.AddrPorts` slice cap math** (`94381a191`) — **not applicable.** An
  operator-precedence slip in the `make(...)` *capacity* argument of the decoder. `append` corrects an
  undersized capacity by reallocating, so no decoded value and no encoded byte changes; `ts_disco_protocol`'s
  relay codec allocates from the same length arithmetic done correctly.
- **`feature/acme`: trailing dot trimmed before cert lookup, one async renewal at a time**
  (`1a14668a3`, `2d98e7524`) — **not applicable.** Both act on state this fork does not keep. There is
  no cert *store* here to key by domain — `ts_control::cert::get_certificate` is fail-closed
  `Unimplemented` and `ts_control::acme::issue_certificate` is one-shot — so there is no lookup a
  trailing dot could miss (and `is_tailnet_name` trims one anyway), and no background renewal to
  de-duplicate. Re-read them if a cert cache is ever added; the trailing-dot rule is an SNI fact
  (RFC 6066 §3) that will apply the moment there is a keyed store.
- **`net/netmon`: skip `RTM_MISS` route messages on darwin** (`2767100bc`) — **not applicable**, for
  the same structural reason as `5927c1864` in the older list: `ts_netmon` ships `ManualLinkMonitor`
  and `NoopLinkMonitor` and no OS backend, so there is no PF_ROUTE reader to filter messages in.

#### Not applicable, from older commits read at previous revisions

Re-checked against this pin and against this tree; none moved.

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
  port**, and it is now by a wide margin the oldest open row here: it has survived four revisions of
  this ledger unchanged. Upstream's SOCKS5 server checked the client-supplied
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
the packages earlier revisions added to the sweep: the tree-wide renames and modernizers that touched `net/socks5`
(`bd2a2d53d`, `2810f0c6f`, `3ec5be3f5`, `c2e474e72`) and the `net/tsdial` commits that only follow
upstream's own refactors of `types/netmap`, `netmon` and `syncs`. `wgengine/router`'s Linux
netfilter, `ip rule` and connmark work (`ts_host_net` installs no firewall rules),
`wgengine/wgcfg`'s removal of `Peers` from its config struct and the `wireguard-go` bumps that go
with it, `ssh/tailssh`'s exit-status framing and incubator test fixes, `feature/acme`'s per-domain
locking, and `ipn/ipnlocal`'s locking and delta-path rework. Also out, from earlier
pins: `91d10d38a` (`net/portmapper`, a package with no counterpart here — *roadmap*), `99f1ee74b`
(`feature/conn25`, likewise), the `fuzz:` and `go.toolchain.rev` housekeeping, `9ea7cba44` (a
licence-notice regeneration), `a8b023c06` (a `cmd/k8s-operator` change) and `3945b82f8` (`paths`, the
daemon's default socket path on Android), the three previous pins. The new pin `023255e8a` is
likewise only what HEAD was when this revision was derived — it tightens an on-disk DNS cache this
fork does not keep, and is written up with the other new commits above.
`tsnet` has over a hundred commits in the window and is **not** re-derived here: that facade has its
own line-by-line parity matrix in [`docs/TSNET_PARITY.md`](docs/TSNET_PARITY.md), and duplicating it
into this ledger would create two records that disagree. Only `tsnet` changes that alter behaviour a
mapped crate already implements are pulled in, as `49e148c4a` and `d9cc55e33` were above.

### Re-deriving this ledger

```sh
# The capability-version window (§A): everything above CapabilityVersion::CURRENT here.
git -C <tailscale-go> grep -n 'CurrentCapabilityVersion CapabilityVersion' 023255e8a -- tailcfg/tailcfg.go
git -C <tailscale-go> grep -nE '^//[[:space:]]*-[[:space:]]*1[3-9][0-9]:' 023255e8a -- tailcfg/tailcfg.go

# What upstream touched per mapped package since capver 130 landed (§B). Every upstream package
# named in "Package mapping" is in this list; parent paths (wgengine, ipn) are used where the
# mapping names several children, so a subdirectory upstream adds later cannot fall outside it.
for p in tailcfg disco derp net/packet net/tstun net/netcheck net/stun net/dns \
         net/udprelay net/socks5 net/tsdial net/tlsdial net/bakedroots net/netmon net/art \
         net/routemanager \
         control/controlclient control/controlbase control/controlhttp \
         wgengine ipn tsd tka types/key types/persist tsnet \
         feature/remoteconfig feature/identityfederation feature/taildrop feature/ssh \
         feature/acme ssh/tailssh util/clientmetric tstime tstest tool/; do
  echo "== $p"; git -C <tailscale-go> log --since=2025-10-06 --oneline -- "$p"
done

# Only what moved since the pin this ledger currently carries — the fast path on a re-derivation
# that follows soon after the last one. Read it *in addition to* the full sweep, never instead of
# it: a row's assessment can change because this tree moved, with upstream perfectly still, and the
# sweep list itself can be wrong (it has been, three times).
git -C <tailscale-go> log --oneline 023255e8a..<new-pin>

# And the mirror image of that, which has now been the larger half of the diff four times running:
# what moved *here* since the tree revision the header table names. Every row the previous revision
# opened closed at this one for this reason alone, with upstream contributing nothing at all.
git log --oneline dcd2c13..HEAD
```

The capability-history pattern is deliberately whitespace-tolerant: upstream writes those entries as
`//   - 133: …`, but the exact indentation is a comment convention, not something `gofmt` enforces,
and a pattern that pins it would go silently empty the day it changes. Check the row count rather
than trusting the exit status — at the pinned commit the second command returns **17 lines**, 130
through 146, i.e. the sixteen-version window of §A plus the 130 row that anchors it. That is the
same count the previous revision derived, and the check earned its keep for the first time here:
17 lines with no new version at the end is what "upstream added nothing" looks like, and it is
indistinguishable from a broken pattern unless you count. An empty or short result means the pattern
broke, not that upstream added nothing.

**The sweep list is part of the ledger, and it has now been wrong three times.** The rule that
governs it has not changed since it was written down: when [Package mapping](#package-mapping)
gains an upstream package — a table row or a *partial* entry alike — add it here too, or the mapping
is a claim the sweep never checks. Three revisions ago the list gained `net/socks5`, `net/tsdial`,
`net/tlsdial`, `net/bakedroots`, `ipn/localapi`, `feature/remoteconfig` and `tsnet`; the revision
after that found it short by sixteen more and rebuilt the loop from the mapping rather than
extending it by hand (`net/netmon`, `net/art`, `control/controlhttp`, `types/persist`,
`feature/identityfederation`, `feature/taildrop`, `feature/ssh`, `feature/acme`, `ssh/tailssh`,
`util/clientmetric`, `tstime`, `tstest`, `tool/`, `tsd`, and — the consequential ones — the parent
paths `wgengine` and `ipn`).

**This revision found the third miss, and it is the most instructive of the three, because the rule
as written would not have caught it.** `net/routemanager` (`a5102d3fc`, 2026-07-09) is upstream's
incremental route manager: it took over the per-peer data-plane attributes that used to be derived
inside `wgengine/wgcfg`, and `net/tstun`'s `peerConfigTable` now reads `PeerRoute.Jailed`,
`PeerRoute.MasqAddr4` and `PeerRoute.MasqAddr6` out of it. The mapping had no row for it, so the
loop had no entry for it, so four commits' worth of behaviour sat outside the sweep for two months —
and two of this revision's five rows are its fields. The generalisation worth carrying forward: the
rule "add a package to the loop when the mapping gains one" only fires when someone *notices* the
mapping should gain one. **Upstream splitting an existing package is the case that slips**, because
nothing about the mapping looks stale — `wgengine` was already in the loop, and the behaviour simply
walked out of it. The check that would have caught this is cheap and is now part of the recipe:
`git -C <tailscale-go> log --diff-filter=A --oneline <old-pin>..<new-pin> -- '*/*.go'` for new
top-level packages, and for each one, ask not "does it have a counterpart here" but "does anything
*already swept* now read from it". `net/connreject` at the previous revision was the same question
answered the other way round — out of scope itself, but the messages it aggregates are sent and
consumed in swept packages.
Upstream added no *new* package in this interval, so the four recorded at the previous revision
stand: `net/connreject` and `feature/connreject` (`85c1efb46`), `feature/androidbin` (`60d9c54b6`)
and `feature/dnsresolvecache` (`aa2681ac5`), joining `feature/androiddns` (`86b3cd5aa`). All five
are documented under Package mapping as having no counterpart and are deliberately *not* swept,
because the sweep exists to catch behaviour a mapped crate already implements.
`sessionrecording` likewise needs no loop entry of its own, because the client half lives behind
`ssh/tailssh`'s calling code, which is swept.

`wgengine` was the lesson for the sweep list. **The lesson the previous three revisions drew — that
a package being *in* the loop does not mean its commits have been *read* — held for a fourth time,
and this time with nothing left over.** Upstream moved fourteen commits in the interval, nine of
them in mapped packages, and **not one of the fourteen opened a row**. The ledger still gained five
rows. Every one came out of reading code that had been sitting in swept packages for months or
years: `filtertype.Match.SrcCaps` has been declared since capver 109 in 2024-11, `Node.IsJailed`
since capver 81, per-peer masquerade since capver 64, and Go's TSMP ping responder and peerAPI
carve-out are older than this ledger. **When the upstream delta is small, that is not a signal to do
less reading — it is the revision where the reading is the whole job.** Budget for it, not just for
the `git log`.

Two techniques paid at this revision and are worth repeating verbatim, because between them they
produced all five rows:

1. **Take a wire field this tree decodes and follow it forward.** Three of the five rows are the
   same shape — a field modelled in `ts_control_serde` that reaches nothing. A `git grep` for the
   field name finds it and looks like evidence of a port. The question that separates the two is
   "what *reads* this", and the fastest way to ask it is to open upstream's consumer first: reading
   `net/tstun/wrap.go`'s `peerConfigTable` gave `Jailed` and both masquerade fields in one pass.
2. **Take a function this ledger already claims parity for and read it top to bottom at the pin.**
   That is how the previous revision found the reply-admission rows in `runIn4`, and it is how the
   `SrcCaps` row was found here: `ts_packetfilter` implements capability sources completely, so
   everything about it reads as ported until you reach the two callers that pass an empty set. A
   `TODO` under a finished-looking feature is the hardest kind of gap to see from a diff, and the
   only way to see it is to read the call site.

Two entries are noisy by nature and should be read with that in mind: `ipn` (which subsumes
`ipn/localapi` and `ipn/ipnlocal`) catches every multi-package commit that also touched
`cmd/tailscale`, most of which is the daemon CLI this library deliberately does not have, and
`tsnet` is swept but not itemised row-by-row in §B — see the note at the end of §B for why. One
mapping row has no upstream path to sweep at all: `golang.zx2c4.com/wireguard`'s device, which
`ts_tunnel` re-implements, is an upstream *dependency* rather than a package in this repository —
track it through upstream's `go.mod` bumps, not through this loop.

When the pin is advanced, bump the header table, re-run the above, and rewrite §A and §B. A row
whose assessment changes should say *why* it changed — and note that "why" has three sources, not
one, and that all three have now happened more than once. Upstream can move (`85c1efb46` added
capability version 146 at the previous revision, `2ae2808b6` moved the index-eviction row before
that, `e1d17a6b9` and `f53c28101` moved the disco-key rows before that, and `d9cc55e33` moved the
`tsnet.Server.HTTPClient` row before that) — though it contributed *nothing* at this revision, which
is a first. This tree can move, with upstream still, and that is now overwhelmingly the dominant
source: six §B rows closed at this revision on tree movement alone (#415, #417, #418, #419, #421, #423),
four at the previous one (#404, #406, #408/#410, #412), six before that (#360, #363, #367, #369, #370
and #372), three before that (#339, #342/#343/#345, #347), and three
capability-version rows at the one before. Or the **sweep itself** can widen, or simply be read more
carefully, and surface something that was true all along — which is where **all five** of this
revision's new rows came from, the first revision at which that source accounted for the whole
intake.

One consequence worth stating for whoever advances the pin next: **a row this ledger closes is not a
row that stops needing evidence.** Every "already covered" bullet above names the tree code that
covers it, because the next revision has to be able to re-check the claim without re-deriving the
whole document — and because a closed row can reopen if the code it names is refactored away.

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
