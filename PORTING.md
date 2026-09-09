# Porting ledger: upstream Go `tailscale` → this repository

| | |
| --- | --- |
| **Upstream source** | `https://github.com/tailscale/tailscale` (Go) |
| **Upstream commit this ledger was written against** | `3945b82f8a9550b54c33e61d4ed2227862d53e8a` (2026-09-08, `paths: return an absolute default socket path on Android`) |
| **Upstream `tailcfg.CurrentCapabilityVersion` at that commit** | **146** (2026-09-02) — **moved for the first time in five pins**, from 145; see §A row 146 |
| **This repository at ledger time** | `4e8578d` — workspace version `0.50.1` |
| **`ts_capabilityversion::CapabilityVersion::CURRENT` here** | **125** (2025-08-11) — held below 126; see §B, *c2n endpoints behind the declared capability version* |
| **Gap window this ledger covers** | capability version **131 → 146**, i.e. upstream commits from 2025-10-06 to 2026-09-08 (the window is anchored to when capver 130 landed upstream; the declaration here being 125 rather than 130 does not change what upstream added) |
| **Previous pin** | `a8b023c063b608fcead5446f3d885c4fc847c944` (2026-09-08). Seven upstream commits separate the two, four of them in mapped packages — smaller again than the previous revision's eleven, and the second-smallest delta this ledger has covered. **This tree is where the movement was, for the third revision running**: nine commits landed here since `478ab69`, closing **all four** of the rows the previous revision opened, in the order it wrote them down. See §B, *What changed at this revision* |

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
| `sessionrecording` (client half only) | [`src/ssh/recording.rs`](src/ssh/recording.rs) — moved out of the no-counterpart list two revisions ago; a rule carrying `recorders` now streams the session to them and applies Go's `onRecordingFailure`, instead of refusing the session |
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
  `NETLINK_ROUTE` (`60d9c54b6`, new at this pin). `ts_host_net` has Linux and macOS backends only, and
  `ts_netmon` has no OS backend at all yet, so neither has a target here.
- `net/connreject`, `feature/connreject` — the opt-in, LRU-bounded aggregator of recent
  connection-rejection events (TSMP rejects received and sent, and pendopen timeouts) behind
  `nodecap.ConnReject` and the `GET /debug/rejects` c2n endpoint, added at `85c1efb46` — the commit
  that raised `CurrentCapabilityVersion` to 146. The *diagnostics* are out of scope for an embedded
  node (§A row 146), but the TSMP rejected-connection messages they count are **not** implemented
  here at all, in either direction — that is a §B row of its own.
- `net/dnscache`, `net/dnsfallback`, `feature/dnsresolvecache` — the resolution cache in front of Go's
  *control-plane and DERP* dials, its DERP-based bootstrap-DNS fallback, and (`aa2681ac5`, new at this
  pin) the on-disk persistence of last-known-good answers for those hostnames. No counterpart: this
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

### A. Capability versions 131 → 146

This is the sharpest available axis: `tailcfg.CurrentCapabilityVersion` is upstream's own record of
every client behaviour change that control can observe. The window is anchored to capver 130, the
last version this port tracked before the ledger existed; the declaration here is **125**, held
below 126, see §B. Upstream is at **146** at the new pin — `tailcfg/tailcfg.go:198` — so the window
is sixteen versions, one wider than the fifteen the previous four revisions covered. Descriptions
are upstream's own (`tailcfg/tailcfg.go`, `tailcfg/nodecap`).

**One row is new at this revision, and it is the first capability version upstream has added since
this ledger began.** `85c1efb46` raised `CurrentCapabilityVersion` to **146** and added
`nodecap.ConnReject` plus the `GET /debug/rejects` c2n endpoint. Its assessment is *not applicable*,
in the same class as 127, 128 and 138 — the endpoint is a c2n debug route this responder does not
serve and the declaration is held below it — but the reading it forced was not wasted: the TSMP
rejected-connection messages upstream's new aggregator *counts* turn out to be absent here in both
directions, which is a §B row and the sharpest new one at this pin.
**No other row changed assessment**, for the fifth revision running, and for the same one-sided
reason as before: nothing in this tree's nine commits touched a capability-version row. The work that
landed here was on the *non*-capver axis, and §B is where it shows up. The one row that could have
moved is 133, and the tree evidence for it is re-stated under the table below. The rows the previous
revisions flipped (135, 142, 144) still say why they flipped, because that history is what makes the
row re-checkable.

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
| 146 | 2026-09-02 | Client understands `NodeAttrConnReject` (`debug-conn-reject`); can handle c2n `GET /debug/rejects` | **not applicable (declaration held below it)** — *new at this revision* (`85c1efb46`). The attribute turns on an in-memory, LRU-bounded aggregator of recent connection-rejection events (TSMP rejects received, TSMP rejects sent on ACL-blocked inbound flows, pendopen timeouts) keyed by direction/proto/peer/reason, and exposes it over a LocalAPI route and a c2n `GET /debug/rejects`. Both surfaces are out of scope here for reasons already recorded: the c2n route joins 127, 128 and 138 behind the held declaration and takes Go's own `400`/`unknown c2n path` fallthrough, and this fork's LocalAPI serves one route. The attribute is off by default at the control plane, so ignoring it is what a Go client without the feature does. **But read the §B row it opened**: the events the aggregator counts are TSMP rejected-connection messages (`packet.TailscaleRejectedHeader`), and this tree neither sends nor understands them — see *TSMP rejected-connection messages are neither sent nor understood* |

Net: of the sixteen versions upstream added, **one still needs a port** — 133, host-OS-facing —
**four are already covered** (135, 137, 142, 144), and the remaining eleven are not applicable to an
embedded userspace node (138 and the new 146 among them, once the declaration was held below the
versions that promise them). That is the previous three revisions' count plus the one version
upstream added. Row 133 was re-checked against the tree at this pin and is still open:
`ts_host_net::HostDns::nameservers` ([`ts_host_net/src/lib.rs`](ts_host_net/src/lib.rs)) is still a
`Vec<Ipv4Addr>`, its doc comment still says "IPv4 nameservers only", and `ts_runtime::tun_actor`
still fills it with the single IPv4 service IP, so there is still no IPv6 MagicDNS address to
register. Nothing in this revision's nine tree commits touched it — they are peer-index, peer-expiry,
DNS-forwarder and user-profile work (#404, #406, #408, #410, #412), none of which changes which
addresses the MagicDNS responder is reachable on. The row is still *not* closed by #347 (the quad-100
absorption fix in §B): that made the TUN transport absorb every quad-100 packet whatever its port and
protocol, which is about traffic already addressed to `100.100.100.100` — it neither serves nor
registers the IPv6 service IP, which is what 133 asks for.

### B. Behaviour upstream changed in the window that is not capver-gated

Derived from `git log --since=2025-10-06` over the packages that map to crates here, with
docs/typo/refactor commits filtered out. The sweep list is unchanged at this revision: it was
rebuilt from [Package mapping](#package-mapping) three revisions ago and checked against the mapping
again here. Upstream added four packages in the interval (`net/connreject`, `feature/connreject`,
`feature/androidbin`, `feature/dnsresolvecache`); none has a counterpart, so all four are recorded in
the *no counterpart here* list rather than swept, the same treatment `feature/androiddns` got at the
previous revision.

#### What changed at this revision

Read this first: it is the shortest honest summary of the diff between this ledger revision and the
last one.

- **All four rows the previous revision opened are closed, because this tree moved.** The
  conditional index eviction (#412), the peer-expiry subsystem (#408, with #410 for the recovery and
  stale-send follow-ups), the multi-upstream DNS forward that a single REFUSED used to end (#406),
  and `UserProfile.Groups` (#404) are all **already covered** now. Each row below says what closed it
  and names the code, because a closed row still has to be re-checkable — and can reopen.
- **Upstream added a capability version for the first time since this ledger existed.** 146
  (`85c1efb46`), the connection-rejection diagnostics. §A carries it as *not applicable*; the reading
  it forced is what opened the TSMP-reject row below.
- **Six rows opened, and only one of them because upstream moved in this interval.** Seven upstream
  commits separate `a8b023c06` from `3945b82f8`. Two of them made a reader look somewhere they had not
  looked (`85c1efb46` at the TSMP reject path, `a4c790224` at the peerAPI DNS gate) and found gaps
  that were already years old. The other four new rows come from commits that have been sitting in
  swept packages the whole time: `wgengine/filter`'s reply admission (two rows), the exit-node
  suggestion's latency source (`f442cda99`, `e9e209673`), and the MagicDNS subdomain node attribute
  (`f48cd4666`). **This is the fourth revision running that the sweep's own back-catalogue, not the
  new delta, was where the rows came from** — see the closing note under
  [Re-deriving this ledger](#re-deriving-this-ledger).
- **Two of the new rows are the widest-reaching this ledger has carried.** `wgengine/filter`'s
  `runIn4`/`runIn6` admit *replies to flows this node started* without an ACL rule — TCP non-SYN
  unconditionally, ICMP responses and errors unconditionally, and UDP/SCTP through a reverse-flow
  conntrack LRU that `RunOut` (and, since `e0677ccc7`, netstack's injected path) fills. This fork's
  inbound filter is match-or-drop with none of the three. Under a permissive tailnet ACL nothing shows;
  under a restrictive one this node drops the answers to its own outbound connections.
- **One claim this ledger has made for two revisions was re-checked and stands.** The TSMP disco
  advertisement send half is cited here as matching Go "refusal for refusal". Upstream's *periodic*
  advertiser — and with it the four gates that guarded it (`ee76a7d3f`, `92ab4866d`, `be2f554dd`,
  `54005752a`) — no longer exists at this pin: `3799eaf26` moved the send onto `wireguard-go`'s
  establishment hook, which is exactly the shape this tree ports. Recorded under *Not applicable* so
  the next re-derivation does not re-open it.
- **No row changed because of a divergence decision being revisited.** The three deliberate
  divergences recorded at the previous revisions (DNS-after-router-failure, SSH `acceptEnv`, the
  `callMeMaybe` gate) were re-checked and stand.

#### Rows

- **TSMP rejected-connection messages are neither sent nor understood**
  (`net/tstun/wrap.go`, `wgengine/pendopen.go`, `net/packet/tsmp.go`; the diagnostics on top of them
  at `85c1efb46`, capver 146) — **needs port**, and it is the sharpest new row at this pin.
  Upstream has two halves, both old, and this tree has neither.
  *Send.* When `tstun.Wrapper.filterPacketInboundFromWireGuard` drops an inbound packet on the ACL, and
  the packet is an IPv4 TCP SYN, Go injects a `packet.TailscaleRejectedHeader` (TSMP type `!`) back to
  the peer carrying the four-tuple and a reason — `RejectedDueToACLs`, or `RejectedDueToShieldsUp` when
  the filter has shields up. The comment above it says why: "Their host networking stack can translate
  this into ICMP or whatnot as required. But notably, their GUI or tailscale CLI can show them a
  rejection history with reasons." Note the ordering: the peerAPI carve-out ("Let peerapi through the
  filter; its ACLs are handled at L7, not at the packet level") flips the outcome back to `Accept`
  *before* this, so a peerAPI SYN never produces a reject.
  *Receive.* `userspaceEngine.trackOpenPreFilterIn` parses an inbound reject, matches it against the
  pending-open flow table, logs `open-conn-track: flow … rejected due to …`, removes the flow — or, if
  the header's `MaybeBroken` bit is set, only *marks* the flow as problematic — and then **drops the
  packet silently** rather than delivering it, for every reason except the app-connector transit-IP one.
  Here, `ts_packet::tsmp` decodes the disco advertisement and nothing else: `TSMP_TYPE_REJECTED_CONN`
  is a named constant whose own doc says "Not parsed here". `ts_dataplane::filter_inbound_from_peer`
  consumes the disco advertisement and leaves every other TSMP message to the ACL step, which accepts
  it (`"accepting TSMP inbound (bypasses ACL, Go parity)"`) and hands it to the local stack — so a Go
  peer's reject is delivered to `smoltcp` as an IP-proto-99 datagram it has no handler for, instead of
  being consumed. And nothing on the drop path emits one: `inbound_filter_verdict` returning `false`
  drops the packet with a `trace!` and no reply.
  Both halves matter to a client that is always the dialer. Without the receive half, dialling a peer
  whose ACL refuses us waits out a TCP timeout with no reason available to the embedder, where a Go
  client fails immediately and says why. Without the send half, a Go or GUI peer dialling *us* into an
  ACL drop gets the same silence — this is the one direction where the missing behaviour is visible to
  the peer rather than to us. The port is small and self-contained on both sides: marshal/parse
  `TailscaleRejectedHeader` against Go's own layout in `net/packet/tsmp.go`, emit one on an IPv4 TCP-SYN
  ACL drop with the shields-up reason distinguished, and consume an inbound one instead of delivering
  it. The error paths are the interesting part and must come with it: a fragmented TSMP is already
  refused before the ACL here, a reject must not be generated for a *non*-SYN or a non-IPv4 drop (Go
  guards both), and the received one must be dropped rather than passed up. The capver-146 aggregator
  that counts these events is separately out of scope — see §A and the *no counterpart here* list.

- **The peerAPI DNS proxy answers any peer that can reach it**
  (`ipn/ipnlocal/peerapi.go`: `a4c790224` at this pin, over the older `replyToDNSQueries`) —
  **needs port**, and it is the row with the widest gap between what the code does and what an operator
  would assume.
  Go gates `handleDNSQuery` on `isPeerAPIDNSAllowed` before it resolves anything, and returns
  `403 DNS access denied` when it fails. The gate has two arms. A peer that is **untagged and owned by
  the same user** (`IsSelfUntagged()` — tightened from a plain `isSelf` at this pin, so a *tagged* node
  no longer gets the shortcut) is allowed outright. Otherwise the node must be
  `OfferingExitNode() || OfferingAppConnector()` **and** the peer must pass
  `filter.CheckTCP(remoteIP, 0.0.0.0-or-2000::, 53) == Accept` — i.e. control's ACL must actually grant
  that peer internet access through us. Upstream needs this check inside the handler because peerAPI
  deliberately bypasses the ACL filter (`shouldProcessInbound` admits the peerAPI port ahead of it), so
  the handler is the only place the ACL can be consulted.
  This fork has no equivalent. `ts_runtime::peerapi`'s `route_conn` runs `validate_peerapi_request` —
  Go's `validatePeerAPIRequest`, the anti-DNS-rebinding Host/Origin check — and then hands anything that
  is not Taildrop or ingress straight to `peerapi_doh::handle_conn`, which applies exactly two rules:
  control's `ExitNodeFilteredSet` (`REFUSED`) and the fork's `forward_exit_egress` opt-in, which gates
  *recursion* but not the peer. So on a node that has opted into exit egress, **any** peer whose packets
  reach the peerAPI port gets recursive resolution through this node's resolvers, whether or not control
  grants it internet access here; and on any node at all, any such peer gets authoritative MagicDNS
  answers. The exposure differs from upstream's in both directions, and the difference is
  worth stating exactly, because it is one design read two ways. Go pairs a **packet-level carve-out**
  with an **L7 check**: `filterPacketInboundFromWireGuard` flips an ACL-refused inbound SYN back to
  `Accept` when its destination is the peerAPI port — "its ACLs are handled at L7, not at the packet
  level" — and every peerAPI handler that needs an access decision then makes it itself. This tree has
  neither half. There is no carve-out, so a peer must at least be ACL-permitted to reach the peerAPI
  port at all (stricter than Go, and worth its own look for Taildrop, which upstream expects to work
  under an ACL that never names that port); and there is no L7 check, so a peer that is past the port
  is asked nothing further by the DNS proxy. The common tailnet ACL is permissive about ports while
  being specific about *internet* access — exactly the condition Go's `CheckTCP(…, 53)` tests and the
  one this fork never tests.
  The port is a source gate in `peerapi_doh` — the fork already computes everything it needs: the
  packet filter is in `ts_runtime::packetfilter`, and the peer behind a connection is resolvable through
  `PeerTracker::peer_by_tailnet_ip`. The decision to make is what to do with Go's self arm, since this
  fork has no `isSelf` notion on the peerAPI path; the safe reading is to implement only the ACL arm and
  keep serving nothing when the ACL says no. Note the interaction with the deliberate divergence already
  recorded in `peerapi_doh`'s module docs: this server answers some names authoritatively where Go
  forwards. That divergence is about *which names*; this row is about *which peers*, and adding the
  source gate does not disturb it.

- **The inbound ACL admits no replies: TCP non-SYN and ICMP responses are dropped**
  (`wgengine/filter/filter.go`: `runIn4`/`runIn6`) — **needs port**, and it is the first of two rows on
  the same function.
  Go's inbound filter accepts three classes of packet *before* consulting any rule, all of them replies
  to something this node started. An inbound TCP segment that is not a SYN is accepted unconditionally
  ("For TCP, we want to allow *outgoing* connections, which means we want to allow return packets on
  those connections … a new incoming session can't be initiated without first sending a SYN"). An ICMP
  echo *response* or ICMP *error* is accepted unconditionally ("ICMP responses are allowed"). And ICMP
  that is neither still matches IPs-only, ignoring ports.
  This fork ports the third and neither of the first two. `ts_dataplane::inbound_filter_verdict` runs
  Go's `pre()` fragment and unknown-proto drops, accepts TSMP, and then goes straight to
  `filter.can_access` with a `ts_packetfilter::PacketInfo` that carries `{src, dst, ip_proto, port}` —
  **no TCP flags at all**, so the non-SYN carve-out is not merely missing, it is unrepresentable in the
  type the filter matches on. (`ts_packetfilter::rule` does implement Go's `matchIPsOnly` for ICMP and
  portless protocols, so the third class is covered; that is the part to leave alone.)
  What this costs depends entirely on the tailnet's ACL, which is why it has hidden for so long. Under a
  permissive `accept: *:*` policy every reply matches a rule anyway and nothing is visible. Under a
  policy that grants this node *outbound* access to a peer without granting the peer inbound access
  back, the SYN-ACK for this node's own connection arrives at a destination port that is ephemeral, no
  rule matches, and the connection hangs — the failure looks like a network problem and not like a
  filter decision. The same policy silently drops the echo reply to a `tailscale ping`-shaped probe.
  The port is: carry the TCP flags (and the ICMP type) into `PacketInfo`, accept a non-SYN TCP segment
  and an ICMP echo-response/error ahead of the rule match, and test the negative case that gives the
  change its value — an inbound TCP **SYN** with no matching rule must still be dropped, or the carve-out
  becomes an open door. `ts_packet` already decodes what is needed.

- **Outbound UDP flows are not tracked, so their replies need an explicit rule**
  (`wgengine/filter/filter.go`, `net/tstun/wrap.go`: `e0677ccc7`) — **needs port**, the stateful half of
  the row above, and the half this fork's own architecture makes sharper.
  Go's `Filter` carries a 512-entry `flowtrack` LRU. `RunOut` calls `UpdateOutboundFlowState`, which for
  UDP and SCTP inserts the *reversed* tuple; `runIn4`/`runIn6` consult it first for those protocols and
  return `Accept, "cached"` on a hit. `e0677ccc7` is the part that names this fork's exact situation:
  packets produced by **netstack** — "used by tailscaled with `--tun userspace-networking`, by tsnet, and
  by the SOCKS5/HTTP proxies" — enter the wrapper through `InjectOutbound` and bypass `RunOut`, so their
  reverse tuple was never recorded and "a netstack-side dial of UDP would send fine but the reply would be
  dropped as `no matching rule`". Upstream fixed it by exporting `UpdateOutboundFlowState` and calling it
  on the injected path.
  Here there is no conntrack of any kind to fix: `ts_packetfilter`'s own docs say so ("this fork's filter
  is **stateless** — it has no TCP-flow tracking"), and `ts_packetfilter_state` is about *ruleset* state
  from a `MapResponse`, not flows. `ts_dataplane::process_outbound` runs the capture tee, the
  host-injected-TSMP drop and the routing, and records nothing. And the path upstream had to special-case
  is not an edge case here — it is the *only* path this fork has, because every outbound packet in this
  engine comes from the netstack.
  The port is a small reverse-flow LRU consulted by `inbound_filter_verdict` for UDP/SCTP and filled by
  `process_outbound`, with the bound taken from Go (`lruMax = 512`) rather than invented. The negative
  cases are what make it safe and must be asserted: an inbound UDP datagram with no matching outbound
  flow and no rule is still dropped, an entry does not match a datagram from a different source, and the
  cache is bounded so a peer cannot grow it without limit. Read it together with the row above — they are
  two halves of Go's reply admission, but they are separate changes (one stateless and cheap, one stateful)
  and belong in separate PRs.

- **Exit-node suggestion ranks on the latest report, not on recent per-region latency**
  (`ipn/ipnlocal/local.go`, `net/netcheck/netcheck.go`: `f442cda99`, `e9e209673`) — **needs port**,
  embedder-facing.
  Upstream used to rank exit-node candidates by their home region's latency in the *most recent* netcheck
  report, and changed it because netcheck alternates full reports (every region) with incremental ones
  (home plus a handful of the fastest): "When the most recent report is incremental, the suggestion fell
  back to a random for exit nodes that are far away." `suggestExitNodeUsingDERP` now takes
  `preferredDERP` plus a `regionLatency` map from `netcheck.Client.RecentRegionLatency()` — the lowest
  latency seen per region across a retained history — and `e9e209673` tied the retention window to the
  full-report interval (`maxAge = fullReportInterval + ReportTimeout`) so that history is guaranteed to
  contain one full report, with a test that asserts exactly that.
  This tree ports the pre-change shape and says so: `ts_runtime::exit_node_suggest::suggest_exit_node`
  takes a single `&NetcheckReport`, and `min_latency_derp_region` — a faithful port of Go's
  `minLatencyDERPRegion`, down to treating a missing region as `Duration::MAX` — returns `None` when the
  winning region has no measurement, at which point the caller falls back to `select_region`, a uniform
  random pick. There is no history to fall back on: `ts_runtime::derp_latency` measures and publishes,
  keeping nothing.
  The reason this bites harder here than it did upstream is the measurer's own contract.
  `ts_netcheck::Config` defaults to `complete_threshold: 3` — the measurement ends as soon as **three**
  regions have answered (and in any case at `report_timeout`, 5 s) — so a report on a real DERP map names
  a handful of regions, not all of them, *every time*. A candidate exit node homed anywhere else is
  ranked against nothing, and the suggestion is random among the candidate regions rather than nearest.
  The port is a per-region best-latency history in the latency measurer or its actor, with the retention
  window tied to the re-measure cadence the way upstream ties it to `fullReportInterval`, and
  `suggest_exit_node` taking `(preferred_region, region_latency)` instead of the report. The test worth
  copying is upstream's: run many measurements, most of them partial, and assert every region still has a
  latency to rank on. Keep the two random selectors injected — that is what makes the algorithm testable
  here and it is a port of Go's own `selectRegionFunc`/`selectNodeFunc`.

- **MagicDNS does not resolve subdomains for peers carrying `dns-subdomain-resolve`**
  (`net/dns/resolver/tsdns.go`, `tailcfg/nodecap/nodecap.go`: `f48cd4666`) — **needs port**, narrow and
  self-contained.
  Upstream added the `DNSSubdomainResolve` node capability (`"dns-subdomain-resolve"`): when control sets
  it on a node, "all of that host's subdomains should resolve to the same IP address". The resolver
  carries a `SubdomainHosts` set beside its `Hosts` map, and on a miss walks the queried name's parents
  (`dnsname.Parent`) looking for one that names a subdomain host — so for a node named `machine`, both
  `my.machine` and `be.my.machine` resolve to it, any depth of label. It is a control-driven behaviour: a
  node without the attribute is unaffected, which is why upstream could add it without a capability
  version.
  Nothing here implements it. The string `dns-subdomain-resolve` appears nowhere in this tree, and
  `ts_runtime::magic_dns`'s `decide` resolves peer names by exact match against the view's name index.
  A tailnet that has turned the attribute on for a node gets working subdomain resolution from every Go
  client and `NXDOMAIN` from this one — a difference an embedder cannot diagnose from this side.
  The port is the parent walk plus the attribute plumbed onto the DNS view, and the cases to pin are the
  ones that keep it from becoming a wildcard: a node *without* the attribute must still answer `NXDOMAIN`
  for its subdomains, the walk must stop at the tailnet zone rather than climbing out of it, and an exact
  name must still beat a parent match.

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
  **The three rows the previous revision opened off the back of this one have all closed**; they are
  the next three bullets, and each records what closed it.

- **A peer's *inactive* known disco key is accepted on ingress, and becomes the active key**
  (`wgengine/magicsock/endpoint.go`, `wgengine/magicsock/magicsock.go`: `da1fc4fc8`, `e1d17a6b9`) —
  **already covered**, *changed from "needs port"*: #372 landed it after the previous revision was
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
  tree on this subject" at the previous revision has been rewritten to say what the code now does.
  The ordering hazard the previous revision flagged was respected: #372 landed the ingress half
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
  The previous revision found the right primitive here with no caller on this path — it had
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
  anything. The interaction the previous revision warned about was handled rather than dodged: an
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
  The trap the previous revision named was checked: `missing_aums` consumes the same offer, and both
  arms of `intersection` were re-tested against the checkpoints-only ancestor shape.

- **A peer removal evicts index entries another peer has since claimed**
  (`ipn/ipnlocal/node_backend.go`: `2ae2808b6`) — **already covered**, *changed from "needs port"*:
  #412 landed it after the previous revision was written.
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
  which the previous revision's write-up missed) and `disco_idx`. The IP helper matches on the exact
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
  poisoning check the previous revision insisted on is unchanged and still runs first: a datagram from
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
  decision the previous revision left open (widen `WhoIs` or add a narrow accessor) went the way it
  recommended: widen, because that is the shape that absorbs the next `UserProfile` field without
  another decision. The absent case is asserted as well as the present one — an omitted key, an
  explicit `[]` and a wire `null` all decode to an empty list and none of them fails the profile.

- **IPv6 fragment extension-header handling in the filter** (`net/packet`, `wgengine/filter`:
  `4c4ec3d46`, `26b2ed0a6`) — **already covered**, unchanged at this revision and re-checked. #342 gave
  `ts_dataplane` the IPv6 half of the RFC 1858-style classification it had only for IPv4, #343
  extended it to a Fragment header hidden behind a chained extension header, and #345 rewrote the
  tests so each extension header has its own control and its drop cannot pass vacuously. #398 added
  one more pin at the previous revision (the pre-rule drop of a proto-0 first IPv6 fragment), and #390
  stopped a prepended IPv6 header choosing which rule matches.

- **Quad-100 traffic is absorbed locally regardless of port and protocol** (`wgengine/netstack`:
  `1b4091161`) — **already covered**, unchanged at this revision. `ts_runtime::tun_actor::classify_service_ip`
  returns `ServiceIpPacket::Absorbed` for **every** packet destined to `100.100.100.100` that is not
  the UDP/53 query it serves, and an unserved quad-100 TCP port is answered with a RST built by
  `build_tcp_reset` (RFC 9293 §3.10.7 CLOSED-state rules) rather than dropped into a retransmit
  loop — upstream's `hittingServiceIP` case in `acceptTCP`.

- **The DNS forwarder sets TC against the *client's* size limit** (`net/dns/resolver`:
  `8cac8b117`) — **already covered**, and refined four times more at the previous revision. #339 added
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
  DERP. Direct paths still take priority over relay ones. #400 hardened it here at the previous revision: a
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
  again at the previous revision. Upstream added no wire field: both are *derived predicates* — "does this
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

Recorded so the next re-derivation does not re-read them. Seven upstream commits landed between
`a8b023c06` and `3945b82f8`. Four touched mapped packages; `85c1efb46` and `a4c790224` are the two
that opened rows (written up above, and in §A for `85c1efb46`'s capability version), and the rest are
here.

- **`derp/derpserver`: serve hijacked connections on their own goroutine** (`8e1fbc474`) — **not
  applicable.** The DERP **server** half is out of scope, and the change is a Go memory-lifetime fix:
  handing a hijacked connection to a fresh goroutine so the HTTP/1 `conn.serve` frame, its 4 KiB
  bufio pair and the upgrade request can be collected. It touches `types/key` too, but only to soften
  two `Deprecated:` markers on `UntypedHexString` to warnings — the untyped hex format *is* the DERP
  wire protocol's key encoding, so those call sites are permanent. `ts_derp`'s client half encodes the
  same bytes and has no deprecation surface to follow.
- **`feature/androidbin`: netmon and TLS in raw Android binaries** (`60d9c54b6`) — **not applicable.**
  The `net/netmon` hunk is a fallback hook consulted only when no interface getter is registered *and*
  `net.Interfaces` failed; the rest is a new feature package. There is no Android backend in
  `ts_host_net` and no OS backend in `ts_netmon` at all, so there is nothing here for the hook to hang
  off. Recorded in the *no counterpart here* list with `feature/androiddns`.
- **`net/dnscache`, `feature/dnsresolvecache`: persist DNS resolutions to disk** (`aa2681ac5`) —
  **not applicable.** It records every successful resolution from `net/dnscache` as a JSON file per
  hostname under `$statedir/dns-cache/`, so a later boot with broken DNS can still reach the control
  plane, and consults it ahead of the DERP-based bootstrap DNS. Two independent reasons it has no
  target: this fork resolves control through control's own `DialPlan` and the system resolver with no
  answer cache in between, and upstream links the feature into `tailscaled` and deliberately **not**
  into `tsnet`. Worth re-reading if the DERP-based bootstrap path is ever removed upstream, since that
  is the stated direction.
- **`metrics`: Linux 6.2+ stat fast path for `CurrentFDs`** (`1e95ec8ad`) — **not applicable.** The
  `metrics` package is the *server-side* expvar surface, not `util/clientmetric`, which is what
  `ts_metrics` mirrors; and the change is an `fstat` fast path for a metric that counts open file
  descriptors on hosts like `derper`.
- **`paths`: absolute default socket path on Android** (`3945b82f8`) — **not applicable.** Where the
  daemon puts `tailscaled.sock`. There is no daemon here. It is the new pin only because it was HEAD
  when this revision was derived.
- **`feature/conn25`, `ipn/ipnlocal`: restrict conn25 DNS by peercap** (`a4c790224`) — the conn25 half
  is **not applicable** (no app connector of either generation), but reading it is what opened the
  peerAPI DNS-proxy row above: the same commit rewrote `replyToDNSQueries` into `isPeerAPIDNSAllowed`
  and, in passing, tightened the same-user shortcut from `isSelf` to `IsSelfUntagged()`, so a *tagged*
  node no longer skips the ACL check. See *The peerAPI DNS proxy answers any peer that can reach it*.

Also re-checked at this revision, and recorded because a reader of the TSMP rows will otherwise go
looking for them:

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
  `wgengine/magicsock/magicsock.go` at `3945b82f8`, not carried forward on trust.
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
the packages the previous revisions added to the sweep: the tree-wide renames and modernizers that touched `net/socks5`
(`bd2a2d53d`, `2810f0c6f`, `3ec5be3f5`, `c2e474e72`) and the `net/tsdial` commits that only follow
upstream's own refactors of `types/netmap`, `netmon` and `syncs`. `wgengine/router`'s Linux
netfilter, `ip rule` and connmark work (`ts_host_net` installs no firewall rules),
`wgengine/wgcfg`'s removal of `Peers` from its config struct and the `wireguard-go` bumps that go
with it, `ssh/tailssh`'s exit-status framing and incubator test fixes, `feature/acme`'s per-domain
locking, and `ipn/ipnlocal`'s locking and delta-path rework. Also out, from earlier
pins: `91d10d38a` (`net/portmapper`, a package with no counterpart here — *roadmap*), `99f1ee74b`
(`feature/conn25`, likewise), the `fuzz:` and `go.toolchain.rev` housekeeping, `9ea7cba44` (a
licence-notice regeneration) and `a8b023c06` (a `cmd/k8s-operator` change), the two previous pins. The
new pin `3945b82f8` is likewise only what HEAD was when this revision was derived — it moves the
daemon's default socket path on Android and touches nothing mapped.
`tsnet` has over a hundred commits in the window and is **not** re-derived here: that facade has its
own line-by-line parity matrix in [`docs/TSNET_PARITY.md`](docs/TSNET_PARITY.md), and duplicating it
into this ledger would create two records that disagree. Only `tsnet` changes that alter behaviour a
mapped crate already implements are pulled in, as `49e148c4a` and `d9cc55e33` were above.

### Re-deriving this ledger

```sh
# The capability-version window (§A): everything above CapabilityVersion::CURRENT here.
git -C <tailscale-go> grep -n 'CurrentCapabilityVersion CapabilityVersion' 3945b82f8 -- tailcfg/tailcfg.go
git -C <tailscale-go> grep -nE '^//[[:space:]]*-[[:space:]]*1[3-9][0-9]:' 3945b82f8 -- tailcfg/tailcfg.go

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
git -C <tailscale-go> log --oneline 3945b82f8..<new-pin>

# And the mirror image of that, which has now been the larger half of the diff three times running:
# what moved *here* since the tree revision the header table names. Every row the previous revision
# opened closed at this one for this reason alone, with upstream nearly still.
git log --oneline 4e8578d..HEAD
```

The capability-history pattern is deliberately whitespace-tolerant: upstream writes those entries as
`//   - 133: …`, but the exact indentation is a comment convention, not something `gofmt` enforces,
and a pattern that pins it would go silently empty the day it changes. Check the row count rather
than trusting the exit status — at the pinned commit the second command returns **17 lines**, 130
through 146, i.e. the sixteen-version window of §A plus the 130 row that anchors it. An empty or
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
again at this revision against the mapping and is complete. Upstream added four packages in the
interval — `net/connreject` and `feature/connreject` (`85c1efb46`), `feature/androidbin`
(`60d9c54b6`) and `feature/dnsresolvecache` (`aa2681ac5`) — joining `feature/androiddns`
(`86b3cd5aa`) from the previous interval. All five are documented under Package mapping as having no
counterpart and are deliberately *not* swept, because the sweep exists to catch behaviour a mapped
crate already implements. Note the one thing that rule does **not** buy you: `net/connreject` itself
is out of scope, but the TSMP messages it aggregates are sent and consumed in `net/tstun` and
`wgengine`, which *are* swept — the row came from following the new package back into the mapped ones,
not from sweeping it.
`sessionrecording` likewise needs no loop entry of its own, because the client half lives behind
`ssh/tailssh`'s calling code, which is swept.

`wgengine` was the lesson for the sweep list. **The lesson the previous two revisions drew — that a
package being *in* the loop does not mean its commits have been *read* — held for a third time, and
by the widest margin yet.** Upstream moved seven commits in the interval; the ledger gained six rows,
and four of them came out of commits that had been sitting in swept packages the whole time
(`wgengine/filter`'s `runIn4`/`runIn6` reply admission, which is not even a commit but the shape of a
function that has been there all along; `f442cda99` and `e9e209673` in `ipn` and `net/netcheck`; and
`f48cd4666` in `net/dns`). The two that *did* come from the new delta came from it indirectly: reading
`85c1efb46` and `a4c790224` sent a reader to code paths whose gaps predate both commits by years.
**When the upstream delta is small, that is not a signal to do less reading — it is the revision where
the reading is the whole job.** Budget for it, not just for the `git log`. The concrete technique that
paid at this revision, and is worth repeating: take a function this ledger already claims parity for,
open it at the pin, and read it top to bottom against the port — the reply-admission rows came out of
reading all of `runIn4`, not out of any commit touching it.

Two entries are noisy by nature and should be read with that in mind: `ipn` (which subsumes
`ipn/localapi` and `ipn/ipnlocal`) catches every multi-package commit that also touched
`cmd/tailscale`, most of which is the daemon CLI this library deliberately does not have, and
`tsnet` is swept but not itemised row-by-row in §B — see the note at the end of §B for why. One
mapping row has no upstream path to sweep at all: `golang.zx2c4.com/wireguard`'s device, which
`ts_tunnel` re-implements, is an upstream *dependency* rather than a package in this repository —
track it through upstream's `go.mod` bumps, not through this loop.

When the pin is advanced, bump the header table, re-run the above, and rewrite §A and §B. A row
whose assessment changes should say *why* it changed — and note that "why" has three sources, not
one, and that all three have now happened more than once. Upstream can move (as `85c1efb46` added
capability version 146 at this revision, `2ae2808b6` moved the index-eviction row at the previous one,
`e1d17a6b9` and `f53c28101` moved the disco-key rows before that, and `d9cc55e33` moved the
`tsnet.Server.HTTPClient` row before that). This tree can move, with upstream nearly still — still the
dominant source: four §B rows closed at this revision on tree movement alone (#404, #406, #408/#410,
#412), six at the previous one (#360, #363, #367, #369, #370, #372), three before that
(#339, #342/#343/#345, #347), and three capability-version rows at the one before. Or the **sweep
itself** can widen, or simply be read more carefully, and surface something that was true all along —
which is where four of this revision's six new rows came from.

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
