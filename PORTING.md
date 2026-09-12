# Porting ledger: upstream Go `tailscale` → this repository

| | |
| --- | --- |
| **Upstream source** | `https://github.com/tailscale/tailscale` (Go) |
| **Upstream commit this ledger was written against** | `e2ed432399c9b0fda7aa14e9eb27784d2d893c55` (2026-09-12, `go.toolchain.rev: bump for stack debugging API`) — **held at this revision**: `git ls-remote https://github.com/tailscale/tailscale HEAD` still returned it as upstream's default-branch HEAD on 2026-09-13 |
| **Upstream `tailcfg.CurrentCapabilityVersion` at that commit** | **147** (2026-09-09) — unchanged; see §A |
| **This repository at ledger time** | `01244f8` — workspace version `0.56.0` |
| **`ts_capabilityversion::CapabilityVersion::CURRENT` here** | **125** (2025-08-11) — held below 126; see §B, *c2n endpoints behind the declared capability version* |
| **Gap window this ledger covers** | capability version **131 → 147**, i.e. upstream commits from 2025-10-06 to 2026-09-12 (the window is anchored to when capver 130 landed upstream; the declaration here being 125 rather than 130 does not change what upstream added) |
| **Previous pin** | `e2ed432399c9b0fda7aa14e9eb27784d2d893c55`, with this tree at `608144d` — **neither side moved.** `e2ed43239..` upstream HEAD is empty, and `608144d..HEAD` here is one commit, #460, the previous revision of this document, which touched no code. So everything that changed at this revision came from reading, and all of it from one read: the previous revision closed four rows on ports that [`PARITY_AUDIT.json`](PARITY_AUDIT.json) never audited (#440, #443, #445, #448). Read against the Go they cite, together with #456 and #459, five hold and **one is narrower than upstream** — #440 ports Go's truncation retry but not the UDP/TCP race it sits inside. That is the one new row, in §B |

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
| `control/controlknobs` | **no single counterpart** — each control-driven toggle is read where it applies, as a bare node-attribute string at its consumer ([`ts_nodecapability`](ts_nodecapability/src/lib.rs) supplies only the map type, not a list of names; the map itself reaches the tree as [`ts_control::Node::cap_map`](ts_control/src/node.rs) and is queried with `has_node_attr`). Added to this mapping at the **previous** revision, which read its fifteen commits in the window, found them all already assessed, and concluded it paid nothing. Reading the *struct* instead of its commits opened **eight** rows at this revision: of the twenty-seven knobs it carries, this tree honours one (`cache-network-maps`, with `disable-cache-network-maps`), and five have a live target here and are ignored. See §B |

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
| `net/routemanager` (split out of `wgengine/wgcfg`, `a5102d3fc`) | [`ts_overlay_router`](ts_overlay_router/src/lib.rs) + the route/IP indexes in [`ts_runtime::peer_tracker`](ts_runtime/src/peer_tracker/peer_db.rs) — new to this mapping at the **previous** revision; it is where upstream now keeps the per-peer data-plane attributes (`PeerRoute.Jailed`, `MasqAddr4`/`MasqAddr6`) that `net/tstun` reads, and two §B rows come out of it |
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
| `sessionrecording` (client half only) | [`src/ssh/recording.rs`](src/ssh/recording.rs) — moved out of the no-counterpart list four revisions ago; a rule carrying `recorders` now streams the session to them and applies Go's `onRecordingFailure`, instead of refusing the session. **Added to the sweep list at this revision**, three revisions late: it is its own top-level upstream package with its own commits, and the standing argument that `ssh/tailssh` covers it is false — see §B |
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

### A. Capability versions 131 → 147

This is the sharpest available axis: `tailcfg.CurrentCapabilityVersion` is upstream's own record of
every client behaviour change that control can observe. The window is anchored to capver 130, the
last version this port tracked before the ledger existed; the declaration here is **125**, held
below 126, see §B. Upstream is at **147** at the pin — `tailcfg/tailcfg.go:199` — so the window is
**seventeen** versions, as at the previous revision. Descriptions are upstream's own
(`tailcfg/tailcfg.go`, `tailcfg/nodecap`).

**No row is new at this revision.** The pin did not move, and the two §A commands were re-run against
it anyway: `tailcfg/tailcfg.go:199` still reads `CurrentCapabilityVersion CapabilityVersion = 147`, and
the capability-history comment returns exactly **18** lines, 130 through 147 — the count the previous
revision derived when the pin *did* move. An unmoved pin is when that count earns its keep: "upstream
added nothing", "I re-ran it against the same tree" and "the pattern broke" all feel the same, and
only the count tells them apart. An empty or short result still means the pattern broke.

**No row changed assessment.** Rows **133** and **147** are still the two open capability-version
rows, and both were re-checked against this tree rather than carried on trust: nothing in
`ts_host_net`, `ts_runtime::magic_dns` or `ts_control`'s register and map paths changed in the
interval, whose only commit here is #460, the previous revision of this document. Row **137** keeps
its *already covered* verdict and the caveat the previous revision gave it — upstream's register path
now tests `isRateLimitedResponse(res)`, which also accepts a `503` carrying a `Retry-After` — and that
widening is still row 147's business rather than 137's. The rows earlier revisions flipped (135, 142,
144) still say why they flipped, because that history is what makes the row re-checkable.

One cross-check is the cheapest confirmation this section has, and re-run at this revision it returned
the same **65** unhandled attributes as at the previous one: the node-attribute walk described under
[Re-deriving this ledger](#re-deriving-this-ledger) reports,
independently of this table, which attribute strings appear nowhere in this workspace. Every
attribute named by a row below still comes back **unhandled** — `default-auto-update` (131),
`disable-hosts-file-updates` (132), `force-register-magicdns-ipv4-only` (133),
`disable-android-bind-to-active-network` (134), `disable-linux-cgnat-drop-rule` (136),
`emit-runtime-metrics` (139), the four GRO/GSO names (140), `never-gso-equal-tail` (141),
`scope-quad100-macos` (145) and `debug-conn-reject` (146) — and the two attributes of the one row
marked *already covered* on an attribute, 135, come back **handled**. That is the table agreeing
with the tree by a route that does not read the table. It also says something the table does not:
for every row above assessed *not applicable*, the attribute is not merely unimplemented but
unnamed, so a future reader grepping for it finds nothing and must come back here. Row 147 is the
exception that proves the walk's limit — it is gated on no attribute at all, so the walk cannot see
it, and it had to come from the delta.


| Ver | Date | Upstream change | Assessment |
| --- | --- | --- | --- |
| 131 | 2025-11-25 | Client respects `NodeAttrDefaultAutoUpdate` | **not applicable** — self-updating a client binary; this is an embedded library with no updatable binary (`Hostinfo.allows_update` is modelled and false by default) |
| 132 | 2026-02-13 | Client respects `NodeAttrDisableHostsFileUpdates` | **not applicable** — nothing here writes a hosts file; upstream notes the attr is Windows-only as of 2026-02, and there is no Windows `ts_host_net` backend |
| 133 | 2026-02-17 | `NodeAttrForceRegisterMagicDNSIPv4Only`; MagicDNS IPv6 registered with the OS by default | **needs port** — upstream `net/dns/config.go` `serviceIPs` registers **both** `100.100.100.100` and the IPv6 service IP with the OS resolver *by default*, and falls back to IPv4-only when control sets the attr. This tree registers IPv4 only *unconditionally* — which is upstream's attr-set branch, not its default — so the behaviours are not equivalent. Wider than a type signature: the IPv6 MagicDNS service IP is not served here at all (`ts_runtime::magic_dns` binds `100.100.100.100:53` only; `ts_host_net::HostDns::nameservers` is `Vec<Ipv4Addr>` for both the Linux and macOS backends), so registering it before serving it would point the host resolver at a dead address. The port is: serve MagicDNS on the IPv6 service IP, register both by default, honour the attr to drop back to IPv4-only. Host-OS-facing, not wire-facing — no peer or control plane observes it directly — and it pairs with `Config::enable_ipv6` |
| 134 | 2026-03-09 | Client understands `NodeAttrDisableAndroidBindToActiveNetwork` | **not applicable** — Android-only socket binding |
| 135 | 2026-03-30 | Client understands `NodeAttrCacheNetworkMaps` (and `DisableCacheNetworkMaps`, #19947) | **already covered** — *changed from "needs port (optional)"*: the cache landed here in #320, two revisions before this one. `ts_control/src/tokio/netmap_cache.rs` persists the raw decompressed `MapResponse` to `<Config::netmap_cache_dir>/netmap.json` (0600 under a 0700 directory, temp-file rename), `ts_runtime/src/control_runner.rs:1472` loads it before the control client exists, and *both* attributes are honoured — `disable-cache-network-maps` takes precedence and discards an existing cache, as upstream documents. Inert unless the embedder configures storage **and** control grants the attribute |
| 136 | 2026-04-09 | Client understands `NodeAttrDisableLinuxCGNATDropRule` | **not applicable** — `ts_host_net` programs routes and DNS only; it never installs firewall rules, so there is no CGNAT DROP rule to disable |
| 137 | 2026-04-15 | Client handles 429 responses to `/machine/register` | **already covered** — `ts_control/src/tokio/register.rs:261` parses the 429 plus its retry delay into a typed rate-limit error instead of an opaque HTTP error. *Caveat new at the previous revision:* `29cfb0b4c` replaced upstream's literal `res.StatusCode == 429` at this same call site (`control/controlclient/direct.go:828`) with `isRateLimitedResponse(res)`, which also accepts a `503` carrying a `Retry-After`. This row's own claim is still met — a 429 to `/machine/register` is handled — but the call site it names is now wider upstream than here. See row 147 |
| 138 | 2026-03-31 | Can handle c2n `/debug/tka` (`/debug/tka/log`) | **not applicable (declaration held below it)** — the c2n responder (`ts_control/src/tokio/ping.rs`) serves `/echo`, `GET /vip-services` and the `/remoteapi/localapi/*` prefix; `/debug/tka/log` is not among them and takes Go's own `400`/`unknown c2n path` fallthrough, which is asserted by test. The declared capability version is held below the versions that promise it, so control never asks. Resolved together with 127 and 128; see §B |
| 139 | 2026-05-22 | Client understands `NodeAttrEmitRuntimeMetrics` (emit Go `runtime/metrics` as clientmetrics) | **not applicable** — the attr exports the *Go runtime's* metrics; there is no Rust equivalent. `ts_metrics` already mirrors `util/clientmetric` itself |
| 140 | 2026-05-27 | Client understands `NodeAttrDisableUDPGRO` / `DisableUDPGSO` / `DisableTUNUDPGRO` / `DisableTUNTCPGRO` | **not applicable** — no GRO/GSO offload on this datapath (`ts_transport_tun` is single-queue, no offload), so there is nothing for control to disable |
| 141 | 2026-05-28 | Client understands `NodeAttrNeverGSOEqualTail` | **not applicable** — same: the attr is a workaround for kernel GSO batching this port does not do |
| 142 | 2026-07-06 | Client understands c2n `/remoteapi/localapi/*` proxy (`feature/remoteconfig`) | **already covered** — *changed from "needs port (narrow)"*: #317 gave the responder the prefix route it lacked. `ts_control/src/tokio/ping.rs` now walks Go's own dispatch order (exact method+path, exact path, then prefixes, then the 400), strips `/remoteapi`, and carries all four of `handleC2NRemoteAPI`'s refusals. Caveat worth keeping in view: control gates this request on the *declared* capability version, so with 125 declared the handler is implemented but unreachable. A capability version is a contiguous claim, so it becomes live only once 126 through 141 are all implementable — see §B for the full list standing in the way |
| 143 | 2026-07-22 | Client correctly ignores conn25 node attributes when not enabled by environment variable | **not applicable** — no app connector of either generation here, so conn25 attributes are already ignored |
| 144 | 2026-07-31 | Client sends `packet.TSMPDiscoKeyAdvertisement` around WireGuard handshakes | **already covered** — *changed from "needs port"*: the send half landed in #314 and #318, so both halves are now here. `ts_packet::tsmp` marshals against Go's own `TestTSMPDiscoKeyAdvertisementMarshal` vectors, `ts_tunnel` reports the two moments `wireguard-go` calls `SendPriorityMessage`, and `ts_dataplane` chooses the content (Go `magicsock.Conn.PriorityMessageForPeer`). Unlike 142 this is peer-observable regardless of the declared version — the client sends it unprompted — so it is the one changed row a real Go peer can see |
| 145 | 2026-08-04 | Client understands `NodeAttrScopeQuad100OnMacOS` | **not applicable** — the attr changes resolver ordering for the *sandboxed* macOS app; `ts_host_net::macos` installs a service-scoped `scutil` DNS dictionary and has no default-resolver behaviour to scope |
| 146 | 2026-09-02 | Client understands `NodeAttrConnReject` (`debug-conn-reject`); can handle c2n `GET /debug/rejects` | **not applicable (declaration held below it)** — *new two revisions ago* (`85c1efb46`). The attribute turns on an in-memory, LRU-bounded aggregator of recent connection-rejection events (TSMP rejects received, TSMP rejects sent on ACL-blocked inbound flows, pendopen timeouts) keyed by direction/proto/peer/reason, and exposes it over a LocalAPI route and a c2n `GET /debug/rejects`. Both surfaces are out of scope here for reasons already recorded: the c2n route joins 127, 128 and 138 behind the held declaration and takes Go's own `400`/`unknown c2n path` fallthrough, and this fork's LocalAPI serves one route. The attribute is off by default at the control plane, so ignoring it is what a Go client without the feature does. The §B row this version opened when it was new — the TSMP rejected-connection messages the aggregator *counts* — closed at the previous revision: both halves landed here in #421. The aggregator on top of them stays out of scope for the reasons above, so this row does not move |
| 147 | 2026-09-09 | Client handles 429/503 responses with `Retry-After` headers to `/machine/` endpoints | **needs port** — *new at the previous revision* (`29cfb0b4c`, the one delta commit that moved the capability version). Three separable behaviours, and this tree has the first only in part. (1) **Which responses count.** `control/controlclient/direct.go:621` `isRateLimitedResponse` returns true for `429` always, and for `503` **only when a `Retry-After` header is present** — a bare `503` stays a generic failure subject to backoff. That asymmetry is the refusal to port, not decoration. Here, `ts_control/src/tokio/register.rs:261` tests `status.as_u16() == 429` and nothing else. (2) **Where it is checked.** Upstream now also checks it in `sendMapRequest` (`direct.go:1196`): a non-200 **map** response that is rate-limited becomes a typed `rateLimitError` instead of the generic `initial fetch failed %d: %.200s`. Here, `ts_control/src/tokio/map_stream.rs:543` collapses every non-success map status into an opaque `MapStreamError::Http`, reading no header — so `ts_control::Error::RateLimited` is constructed in exactly one place in this tree (`register.rs:274`) and the map poll can never produce one. The rate-limit arm that already exists in `ts_control/src/tokio/client.rs:659` is therefore reachable only for the *re-register* inside the poll loop, which is what its own log message at `:671` says. (3) **How long to wait.** `control/controlclient/auto.go:655` `waitRetryAfter` caps the server-requested delay at `maxRetryWindow = 5 * time.Minute`, and in `mapRoutine` (`auto.go:631`) a rate-limited poll **skips `bo.BackOff` entirely** rather than backing off as well. This tree clamps at `MAX_RETRY_AFTER = 1 hour` (`register.rs:303`, mirroring Go's older `parseRateLimitError` bound, which upstream kept) and has no second, tighter cap at the wait site. Control-observable: a rate-limited node here reconnects on local backoff and ignores the cooldown control asked for |

Net: of the seventeen versions upstream added, **two need a port** — 133, host-OS-facing, and 147,
control-observable — **four are already covered** (135, 137, 142, 144), and the remaining eleven are
not applicable to an embedded userspace node (138 and 146 among them, once the declaration was held
below the versions that promise them). The count is unchanged from the previous revision: nothing that
was open closed, and nothing that was closed reopened.

Row 133 was re-checked against the tree at this revision and is still open:
`ts_host_net::HostDns::nameservers` ([`ts_host_net/src/lib.rs:44`](ts_host_net/src/lib.rs)) is still
a `Vec<Ipv4Addr>`, its doc comment still says "IPv4 nameservers", the Linux backend still fills
it with the single literal `100.100.100.100`, `ts_runtime::magic_dns` still binds
`100.100.100.100:53` only, and `force-register-magicdns-ipv4-only` still appears nowhere in the tree
— so there is still no IPv6 MagicDNS address either to serve or to register, and no attr to drop back
from if there were. One commit landed in this tree in the interval — #460, the previous revision of
this document — and it touched no code; the row is still *not* closed by #347 (the quad-100 absorption fix in §B), which made the TUN
transport absorb every quad-100 packet whatever its port and protocol — that is about traffic already
addressed to `100.100.100.100`, and it neither serves nor registers the IPv6 service IP, which is
what 133 asks for.

Row 133 sits at the centre of **two** rows rather than three since the previous revision, when the
third closed. A reader who finds one wants both, so they are named here once:

- 133 itself — which *addresses of this node's resolver* the host OS is pointed at (register both
  service IPs by default; honour `force-register-magicdns-ipv4-only` to drop back to IPv4).
- the `magicdns-aaaa` row in §B — which *addresses of peers* that resolver hands out.

The third, the *host route set* row — which *peer prefixes* the host FIB carries, and Go's
`one-cgnat` knob over it — was ported in #438 and is closed. It did not leave the group cleanly: the
audit of that port (§B) found the tri-state inverted and upstream's platform gate missing, so two
**new** rows stand where the old one did. Both are still host-OS-facing, which is what put the group
together in the first place.

All of these are host-OS-facing rather than wire-facing, and all are decided in this tree by local
`Config` rather than by what control asked for. Grouping them is not a claim that they are one job.
Row 147, by contrast, is control-facing and belongs to none of this group.


### B. Behaviour upstream changed in the window that is not capver-gated

Derived from `git log --since=2025-10-06` over the packages that map to crates here, with
docs/typo/refactor commits filtered out. **The sweep list is unchanged at this revision and was
re-run in full** — thirty-eight entries, 857 distinct commits across them at the pin — and, as at the
previous revision, nothing the list itself got wrong: every package in
[Package mapping](#package-mapping) that has an upstream path has a loop entry, and
`git log --diff-filter=A --oneline e2ed43239..<new-pin> -- '*/*.go'` is empty by construction,
because the new pin is the old one. The five times the list *was* short are written up under
[Re-deriving this ledger](#re-deriving-this-ledger) and those lessons stand unchanged.

**What is different at this revision is that nothing moved and a row still opened.** Neither upstream
nor this tree changed code in the interval, so the sweep, the node-attribute walk and the wire-type
checks all returned what they returned last time — and they would have returned it whatever state the
ports underneath were in. The one new row comes from the fourth source of change named under
[Re-deriving this ledger](#re-deriving-this-ledger): a port that landed here and is narrower than the
upstream behaviour it copied. The previous revision closed six rows; four of those closures had never
been read against upstream. They have now, and one of them was incomplete.

A note on wording: rows carried from before the previous revision keep the revision-relative phrasing
they were written with ("new at this revision", "unchanged at this pin"), and that phrasing refers to
the revision that wrote the row. Text written at *this* revision is the header table, §A's opening
paragraphs and its *Net* paragraph, this section's opening, [What changed at this
revision](#what-changed-at-this-revision), the first row under [Rows](#rows), and [Audited at this
revision](#audited-at-this-revision).

#### What changed at this revision

Read this first: it is the shortest honest summary of the diff between this ledger revision and the
last one.

- **Neither side moved.** `git ls-remote https://github.com/tailscale/tailscale HEAD` returned
  `e2ed432399c9b0fda7aa14e9eb27784d2d893c55`, the pin, so `git log --oneline e2ed43239..<new-pin>` is
  empty. `git log --oneline 608144d..HEAD` is one commit, `01244f8` (#460), the previous revision of
  this document. Every command under [Re-deriving this ledger](#re-deriving-this-ledger) was re-run
  anyway, and each returned what the previous revision recorded: **18** capability-history lines;
  **38** sweep entries; **85** node-attribute constants, **65** unhandled and **20** matched — the same
  sixteen genuine reads and four known false positives; the renamed half of the outbound wire check
  empty, and the un-renamed half returning `NetInfo.HairPinning` and nothing else real (see the note
  on case under that recipe).
- **One row opened, from an audit rather than from any command.** #440 closed the upstream-resolver
  TCP-retry row at the previous revision. Read against `net/dns/resolver/forwarder.go` at the commit
  it cites, it ports Go's truncation arm and not the race that arm sits inside: Go also falls back to
  TCP when the UDP hop is slow or fails, starts TCP at once for a TCP client, and does *not* retry a
  UDP client's truncated answer. See the first row below. It does not reopen the closed row — what
  #440 shipped is correct as far as it goes — it narrows it, as the previous revision's audit narrowed
  #438 and #442.
- **Five other merged ports were audited and hold.** #443, #445, #448, #456 and #459 were each read
  against the Go they cite; the evidence is under [Audited at this
  revision](#audited-at-this-revision). None opened a row. #448's second upstream meaning was
  already a row (`disable-relay-client`) and still is.
- **No row closed, and no carried row changed assessment.** The five open §B rows of the previous
  revision are carried — `disable-relay-client`, the two `one-cgnat` rows and the two
  `disable-delta-updates` rows — and each was re-checked against this tree, which has not changed
  underneath them. So were the four deliberate divergences recorded at earlier revisions
  (DNS-after-router-failure, SSH `acceptEnv`, the `callMeMaybe` gate, and the peerAPI DoH server's
  authoritative-answer widening).
- **One recipe note added; no command changed.** The un-renamed outbound wire-name check has to look
  names up case-insensitively: the PascalCase of `derp_map` is `DerpMap` and Go spells it `DERPMap`,
  so a case-sensitive lookup reports sixty "phantoms" that are not. Case-insensitive, over `tailcfg`
  and `tka`, it reports three: `HairPinning`, the known row, and two false positives — `action_type`,
  which serializes as `Type` through a rename a one-line extractor misses, and `Endpoint::ty`, which
  never reaches the wire under its own name because `MapRequest.endpoints` is serialized through a
  custom module into Go's parallel `Endpoints`/`EndpointTypes` arrays
  (`ts_control_serde/src/netmap.rs:206`–`:222`).

#### Rows

- **The upstream DNS hop falls back to TCP only on truncation, where Go races TCP against a slow or
  failed UDP hop** (`net/dns/resolver/forwarder.go:627` `send`, `:676`–`:744`, `:108`
  `udpRaceTimeout`; `util/race/race.go:58` `Start`) — **needs port**, and *new at this revision from
  auditing #440*, not from upstream: `forwarder.go` and `util/race` are byte-identical between
  `023255e8a`, the commit #440 cites, and the pin. Go's `send` does not ask over UDP and then decide.
  It hands two closures to `race.New(timeout, firstUDP, thenTCP)` (`:744`), and `Race.Start` runs
  `firstUDP` at once and `thenTCP` on whichever comes first of `timeout` elapsing (`race.go:70`) or
  `firstUDP` returning an error (`race.go:102` closes `startFallback`); the first non-error answer
  wins. Three behaviours fall out of that, and this tree has one of them, run sequentially:

  1. **A slow or failed UDP hop falls back to TCP.** For a UDP client `timeout` is `udpRaceTimeout`,
     two seconds (`:738`); for a TCP client it is zero (`:740`), so TCP starts alongside UDP. A
     resolver whose UDP path drops or stalls but whose TCP path answers is answered in about two
     seconds. Here `ask_with_tcp_retry` (`ts_runtime/src/magic_dns.rs:1248`) awaits the UDP hop to
     completion — bounded only by `UPSTREAM_TIMEOUT`, five seconds (`:93`) — and a UDP hop that errors
     or times out returns `None` before TCP is considered, so the walk moves to the next resolver or
     ends in `SERVFAIL`. Upstream's own `TestForwarderNetstackUpstream` bounds elapsed time by
     `udpRaceTimeout` because this fallback can hide a broken UDP path behind correct bytes arriving
     two seconds late; that is the test shape to copy.
  2. **A truncated answer is retried over TCP, to the same resolver** (`firstUDP` maps it to
     `truncatedResponseError`, `:722`). This is what #440 ported, and its bounds are right: the same
     resolver and never the next, a failed retry relays the truncated answer, an answer that fit is
     never retried, and both hops ride the overlay `Channel`, never a host socket.
  3. **A UDP client's truncated answer is *not* retried** (`:707`): Go returns it as it came, because
     the client can retry over TCP itself. Here `forward_query` (`magic_dns.rs:1158`) gives the
     client transport to the walk but not to `ask_upstream`, so a truncated answer is re-asked over
     TCP for a UDP client too — a TCP connection to the resolver that a Go node on the same tailnet
     does not open.

  `skipTCP` (`:677`) gates all of it, not only the truncation arm: under
  `dns-forwarder-disable-tcp-retries`, `thenTCP` waits on the context and never dials, so a ported race
  arm must honour `TcpRetry::Disabled` as well. The doc comment on `ask_upstream`
  (`magic_dns.rs:1203`) says Go's forwarder "does exactly this"; that sentence is the claim this row
  corrects. Resolver-observable and client-observable — a name resolves or does not on a UDP-hostile
  path — and not peer-observable. The decision to make is whether to port all three, or to port the
  fallback and record the UDP-client skip as a deliberate divergence with its reason.

- **`disable-relay-client` is ignored, so this node keeps using peer-relay paths control switched
  off** (`wgengine/magicsock/magicsock.go:3000`–`:3002`, `:2331`, `:2858`, `:3050`;
  `tailcfg/nodecap/nodecap.go`: `DisableRelayClient`) — **needs port**, and **the one row of the
  previous revision's seven that did not close.** Upstream computes
  `relayClientEnabled := self.Valid() && !self.HasCap(nodecap.DisableRelayClient) &&
  !self.HasCap(nodecap.OnlyTCP443)` once per netmap and then gates three things on it: an inbound
  `CallMeMaybeVia` from a peer is **dropped** (`:2331`, logging `ignoring %s from %v;
  disable-relay-client node attr is set`) — silently as far as the peer is concerned; the relay
  server set is **cleared** rather than recomputed (`:3050` calls
  `relayManager.handleRelayServersSet(nil)`); and `SetFilter` **returns early** (`:2858`) instead of
  re-deriving the relay server set from the new filter. `nodecap.go` documents the attribute as
  dynamically settable: adding it to a running node stops new allocations and new paths at its next
  network map, and deliberately does **not** tear down paths already in use.

  This tree has the relay client half and no gate on it. `ts_magicsock`'s relay module implements the
  `CallMeMaybeVia` → 3-way bind handshake → relayed ping/pong path
  ([`ts_magicsock/src/relay.rs`](ts_magicsock/src/relay.rs)), and the ingress arms at
  [`ts_magicsock/src/sock.rs:1384`](ts_magicsock/src/sock.rs), `:1398` and `:2379` admit a
  `CallMeMaybeVia` on `call_me_maybe_sender_allowed` (`:2026`) alone — a peer-identity check with no
  node-attribute check beside it. `disable-relay-client` appears nowhere in the workspace.

  **Re-verified at this revision, and unchanged:** `disable-relay-client` still appears nowhere in the
  workspace. **At the previous revision one thing about it changed:** its sibling did. The predicate
  upstream writes reads *both* attributes, and `only-tcp-443` is now honoured here — #448 added
  `ts_control::Node::NODE_ATTR_ONLY_TCP_443` (`ts_control/src/node.rs:800`) and the UDP-send gate
  above it. So the shared predicate this row asked the *first* of the two ports to introduce was not
  introduced: #448 ported `only-tcp-443` for its UDP-send meaning only, and its relay-client meaning
  is still unread. Whoever takes this row should write Go's predicate whole, with both attributes in
  it, and route #448's existing attribute read through it rather than adding a second, divergent one.
  `call_me_maybe_sender_allowed` is already the right chokepoint and already carries the metric for
  the refusal (`disco_call_me_maybe_via_recv_rejected`). Carry Go's two bounds exactly, because they
  are the behaviour rather than decoration: the drop is **silent** to the peer (no disco reply of any
  kind, just a log), and an existing relayed path is **not** torn down when the attribute appears —
  only new ones are refused, so a test must assert that an already-established relay path keeps
  carrying traffic.

- **`one-cgnat?v=false` disables the CGNAT collapse outright where upstream keeps the 10000 ceiling**
  (`net/routemanager/routemanager.go:148` `cgnatThreshold`, `:887`–`:891`, `:959`) — **needs port**,
  and *new at the previous revision from the audit of #438*, not from upstream. Upstream carries the decision
  into the route manager as `TailnetConfig.OneCGNAT`, a plain `bool`, and `RouteManager.cgnatThreshold()`
  returns `1` when it is set and the `cgnatThreshold` constant (`10_000`) otherwise. So the
  *disabling* attribute only declines the **forced** collapse; the ceiling still applies, and
  `wantCoarse := len(rm.cgnatPfxs) > rm.cgnatThreshold()` still installs the single `100.64.0.0/10`
  once more than 10000 distinct CGNAT peer routes exist. The merged `cgnat_threshold` maps
  `Some(false)` to `usize::MAX` — commented "unreachable so the fold never fires" — so with
  `one-cgnat?v=false` set the collapse can never happen at any peer count: a tailnet above the
  threshold programs one `/32` per peer here where a Go client programs a single `/10`. The merged
  test `host_routes_collapse_above_the_threshold_unless_control_forbids_it` pins the divergent half,
  and #438's commit body states the inverted rule as fact. This is the unbounded host route table
  #438 set out to bound, still reachable on control's say-so. Host-OS-facing. The fix is one
  expression: `Some(false)` must yield `CGNAT_THRESHOLD`, not `usize::MAX`, and the merged test must
  be re-pinned to upstream's rule rather than to the one it currently asserts.

- **The no-attribute `one-cgnat` case skips upstream's platform and CGNAT-interface gate**
  (`ipn/ipnlocal/local.go:6202`–`:6235` `shouldUseOneCGNATRoute`, `:6131`) — **needs port**, and
  *new at the previous revision from the audit of #438*. With neither `one-cgnat` attribute present, upstream
  does **not** fall through to the 10000 threshold. `shouldUseOneCGNATRoute` consults the knob first
  (an explicit `true` or `false` is terminal), then returns true for `versionOS == "plan9"`, then for
  `versionOS == "macOS"` or `"android"` probes `netmon.HasCGNATInterface()` and returns true when no
  *other* interface uses the CGNAT range — returning **false** if that probe errors — and only
  otherwise false. A true result becomes `TailnetConfig.OneCGNAT`, i.e. a threshold of 1, so the
  `/10` replaces the per-peer `/32`s from the second CGNAT route onward. The merged `Node::one_cgnat()`
  returns `None` whenever the attribute is absent and `cgnat_threshold(None)` is unconditionally
  `CGNAT_THRESHOLD`, with no platform or interface input anywhere on the path. On **macOS** — a
  platform this workspace builds and tests on — this tree therefore keeps one `/32` per peer at every
  peer count below 10000 where a Go client installs the single `/10`. Port the error direction too:
  a failed interface probe means *false*, not *true*. Read this row with the one above it; they are
  two halves of the same tri-state and are cheapest to port together, but they are independently
  testable and neither blocks the other.

- **The `disable-delta-updates` escape hatch diverts only `PeersChangedPatch`, so control still
  cannot take this node off the delta path** (`control/controlclient/map.go:278`
  `tryHandleIncrementally`, and `handleNonKeepAliveMapResponse` below it) — **needs port**, and *new
  at the previous revision from the audit of #442*. Upstream's gate is the **first statement** of
  `tryHandleIncrementally`, and a `false` return there is **not scoped to patches**:
  `handleNonKeepAliveMapResponse` falls through to `ms.netmap()` and `netmapUpdater.UpdateFullNetmap(nm)`
  for the entire response, whatever it carried — which is what the attribute's own documentation asks
  for ("treat all netmap changes as 'full' ones as tailscaled did in 1.48.x and earlier"). In the
  merged tree the check lives in `PeerTracker::apply_peer_patch_set`, which the netmap handler reaches
  only from inside `if !msg.peer_patches.is_empty()`. `PeerTracker::apply_peer_update` — which applies
  `PeerUpdate::Delta`, built in `ts_control::tokio::map_stream` from `MapResponse.PeersChanged` and
  `PeersRemoved`, this tree's **other** delta mechanism — runs unconditionally just above it and is
  untouched by the attribute. So a response carrying only `PeersChanged`/`PeersRemoved` never takes
  the full arm even with the attribute set, and one carrying both applies the delta incrementally
  *before* the patches are rebuilt as a full update. The escape hatch exists precisely for the case
  where control has decided this client's incremental path cannot be trusted; covering one of its two
  delta mechanisms does not achieve that. The gate belongs above both, at the one point the map
  response is dispatched, not inside either applier.

- **The `disable-delta-updates` full arm omits the tailnet-lock re-filter upstream runs**
  (`ipn/ipnlocal/local.go`: `tkaFilterNetmapLocked` immediately before `setNetMapLocked`;
  `tkaFilterDeltaMutsLocked`) — **needs port**, narrow, and *new at the previous revision from the audit of
  #442*. Upstream reaches the full netmap path through `tkaFilterNetmapLocked(st.NetMap)` (guarded
  only by `envknob.TKASkipSignatureCheck`), so declining the delta path also re-verifies **every**
  peer's node-key signature against the lock; the delta path gets the narrower
  `tkaFilterDeltaMutsLocked` instead, and upstream's comment says that exists precisely to match "the
  full-netmap behavior of `tkaFilterNetmapLocked`". `rebuild_netmap_with_patches` re-installs every
  retained peer through `upsert_from_control` without re-running the lock gate, so the only trust
  check on this arm is the per-patched-node one inside `apply_peer_patches`. A peer that was admitted
  earlier and whose signature has since stopped verifying is evicted by upstream on this path and
  retained here. #442's `DECISIONS` section discloses the omission and gives a defensible reason —
  this tree rewrites an expiry-flagged peer's node key via
  `ts_keys::node_public_with_bad_old_prefix`, so a whole-database re-filter would evict it and lose
  the diagnostic — which is why the audit filed this **minor** rather than as a security regression.
  It is still a divergence on the arm #442 introduced, and the disclosed reason argues for a
  *narrower* gate (exempt the expiry-flagged rewrite) rather than for no gate.

#### Audited at this revision

The previous revision closed six rows, and [`PARITY_AUDIT.json`](PARITY_AUDIT.json) audits three merged
ports (#436, #438, #442). Four of those six closures, and two later ports, had never been read against
the Go they cite. Each is read here at the pin, and each verdict names the Go and the tree code it
rests on, so a later revision can re-check it rather than trust it.

- **#440, the upstream-resolver TCP retry** — **gap: narrower than upstream.** See the first row
  above.
- **#443, the periodic STUN idle stop and `debug-always-stun`** — **faithful** on the arms it ports.
  Go's `shouldDoPeriodicReSTUNLocked` (`wgengine/magicsock/magicsock.go:3603`) stops on network-down
  or homeless, then on no peers or a zero private key, then on `idleFor > sessionActiveTimeout` unless
  `ForceBackgroundSTUN` is set. `should_do_periodic_restun` (`ts_runtime/src/direct.rs:779`) checks
  no-peers first and idle-with-override after it, in Go's order, so a peerless node stays quiet under
  the override exactly as in Go. Its doc comment records the arms it does not port and why (a zero
  key cannot occur while the prober runs; network-down and homeless wait on a `ts_netmon` OS
  backend), which is where the previous revision's closure already left them.
- **#445, `silent-disco`** — **faithful.** Go's attribute sets `heartbeatDisabled`
  (`wgengine/magicsock/endpoint.go:1701`), which keeps the heartbeat timer from starting (`:1016`),
  returns early from `heartbeat` (`:879`), and — the compensating arm — re-extends
  `trustBestAddrUntil` when data arrives on the best address (`:591`). All three are here:
  `PeerPaths::set_heartbeat_disabled` (`ts_magicsock/src/path.rs:276`), the inbound re-trust
  (`path.rs:303`), and the heartbeat exemption that drops out under it (`path.rs:526`).
- **#448, `only-tcp-443`** — **faithful** for the meaning it claims. Go reads the attribute inside
  magicsock in three places that matter here: `sendUDPStd` returns without sending
  (`wgengine/magicsock/magicsock.go:1622`), `sendUDPNetcheck` refuses with `ErrUnsupported`
  (`:1606`), and netcheck is told `OnlyTCP443` (`:1038`), which skips the STUN probe plan and the ICMP
  probes and keeps the HTTPS latency arm (`net/netcheck/netcheck.go:940`, `:1008`). Here `send_udp`
  returns without sending (`ts_magicsock/src/sock.rs:372`), `send_stun_request` refuses with
  `Error::OnlyTcp443` (`sock.rs:2148`), and the STUN sweep skips its round (`ts_runtime/src/direct.rs:853`);
  `ts_netcheck` has only an HTTPS arm, so its report is already Go's `OnlyTCP443` report. Two more Go
  reads have no target in this tree — the port mapper (`magicsock.go:686`) and the skip of the
  rebind-on-send-error path (`:921`). The last, inside `relayClientEnabled` (`:3002`), is the
  `disable-relay-client` row above, unchanged.
- **#456, method-aware c2n dispatch** — **faithful, with a scoping decision it records.** Go's
  `handleC2N` (`ipn/ipnlocal/c2n.go:133`) tries method and path, then path alone, then the prefix
  handlers, and refuses with `405 bad method` for a path it serves under another method and
  `400 unknown c2n path` otherwise. #456 ports that order, and scopes the `405` set to *this node's*
  routes: `POST /update` answers `400` here, where a Go build carrying `feature/clientupdate` answers
  `405`. That is what a Go build without the feature answers too, and a `405` would claim a feature
  this node lacks. Recorded, not opened.
- **#459, VIP-service client actions** — **faithful** on the decode half, which is all it claims;
  the *Services model extension* entry below records why having no consumer here is correct.

#### Closed at the previous revision

None closed at this revision. Six rows the revision before the previous one opened were ported before
the previous revision was written. Each names the tree code that now
covers it, because a closed row still needs evidence: the next revision must be able to re-check the
claim without re-deriving the document, and a closed row reopens if the code it names is refactored
away. Two of the six closed *incompletely* and have successor rows above; that is recorded here too,
because "closed" and "closed cleanly" are not the same claim.

- **`only-tcp-443`** — **closed by #448** (`743aea8`, "stop sending UDP when control sets
  only-tcp-443"). `ts_control::Node::NODE_ATTR_ONLY_TCP_443` (`ts_control/src/node.rs:800`) reads the
  attribute off the self node, and `ts_runtime::direct` gates the UDP send path on it
  (`ts_runtime/src/direct.rs:2257`, `:2272`, `:2293` exercise both directions, including clearing the
  attribute without a restart). **Not closed cleanly:** the attribute's *other* upstream meaning —
  it is half of Go's `relayClientEnabled` predicate — is still unread here. See the
  `disable-relay-client` row above.
- **`silent-disco`** — **closed by #445** (`ee7c674`, "stop pinging peers control set silent-disco
  for"). `ts_control::Node::NODE_ATTR_SILENT_DISCO` (`node.rs:770`) plus the suppression and its
  compensating arm in `ts_runtime::peer_tracker` (`peer_tracker/mod.rs:3363`). The compensating half
  — extending best-path trust on inbound data when the heartbeat is suppressed — was the part this
  row warned was not optional, and it landed with it.
- **The periodic STUN sweep's idle stop condition, and `debug-always-stun`** — **closed by #443**
  (`1632f07`, "stop the periodic STUN sweep when the datapath goes idle").
  `ts_control::Node::NODE_ATTR_DEBUG_FORCE_BACKGROUND_STUN` (`node.rs:674`) is the override, and
  `ts_runtime/src/direct.rs:2296`/`:2462` exercise the idle arm against it. The two arms this row
  explicitly excluded — network-down and homeless — remain out of scope pending a `ts_netmon` OS
  backend, and are to be cut as their own row when that backend lands.
- **`disable-delta-updates`** — **closed by #442** (`cb2b2c0`, "let control switch this node off the
  delta netmap path"). `ts_control::Node::NODE_ATTR_DISABLE_DELTA_UPDATES` (`node.rs:744`) and the
  gate in `ts_runtime::peer_tracker` (`peer_tracker/mod.rs:3138`). **Not closed cleanly:** two
  successor rows above — the gate covers only one of this tree's two delta mechanisms, and the full
  arm omits the tailnet-lock re-filter.
- **The upstream-resolver TCP retry, and `dns-forwarder-disable-tcp-retries`** — **closed by #440**
  (`1e3687a`, "resolve names whose answer does not fit a UDP datagram").
  `ts_control::Node`'s attribute constant (`node.rs:651`) is the off switch, and the retry itself is
  in `ts_runtime::magic_dns` (`magic_dns.rs:3724` exercises it). The anti-leak coupling this row
  insisted on — the TCP hop rides the same overlay netstack channel as the UDP hop, never a host
  socket — was kept.
- **The host route set, and `one-cgnat`** — **closed by #438** (`c133b98`, "bound the host route
  table by collapsing CGNAT peer routes"). `ts_control::Node::NODE_ATTR_ONE_CGNAT_ENABLE` /
  `_DISABLE` (`node.rs:698`) and the collapse in `ts_runtime::tun_actor` (`tun_actor.rs:1915`). The
  collapse mechanics are right: `10000` as the constant, a strict `>` comparison, single-IP-in-CGNAT
  as the collapsible class, the `/10` replacing the `/32`s it covers, and the self and MagicDNS
  `/32`s kept distinct. **Not closed cleanly:** two successor rows above — the `?v=false` arm is
  inverted and the no-attribute arm skips upstream's platform gate.

#### Not applicable, from the commits in `023255e8a..e2ed43239`

No commit is new at this pin, so this list is the previous revision's, carried unchanged and
re-checked: the seven commits in `023255e8a..e2ed43239`. One of them is §A row 147; the rest are here so the next
revision does not re-derive them.

- **`ipn/ipnlocal`: exceptions to the 4via6 target filter** (`f31cfaec3`) — **not applicable.**
  Upstream added `TS_4VIA6_ALLOW_LOCAL`, an envknob of IPv4 ranges/prefixes/addresses that
  `viaTargetAllowed` consults *before* its loopback / multicast / unspecified / broadcast / CGNAT /
  link-local refusals, so a deployer can deliberately expose host-scoped addresses through a 4via6
  subnet router. This tree has no 4via6 data path to guard: 4via6 appears only in doc comments
  (`ts_control/src/map_request_builder.rs:223`, `ts_control/src/config.rs:468`, `src/config.rs:302`)
  recording that the app-connector data path — control-pushed domain routes, the 4via6 domain→route
  mapping, the per-domain DNS — is deliberately out of scope, which is the same reason §A row 143 is
  not applicable. There is no `viaTargetAllowed` here to add exceptions to. **If 4via6 is ever
  ported, port `viaTargetAllowed` with it and this envknob after it** — the guard is the sole check
  on the embedded IPv4 target, because the packet filter only ever sees the outer via address.
- **`control/controlclient`: `mapSession` no longer runs in its own goroutine** (`4b60ec876`) —
  **not applicable**, and worth one sentence of *why* because it touches a swept core package. The
  commit reverts plumbing added so that disco keys could flow into `mapSession` for TSMP-learned-key
  filtering; upstream moved that learning into the userspace engine and introduced two active disco
  keys per endpoint, so the extra goroutine and its separate entry path are no longer needed. It
  changes Go's internal concurrency structure and nothing a peer or control plane observes. This
  tree never had the structure being reverted — `ts_control`'s map poll is a stream consumed by an
  actor — and the disco-key behaviour the revert refers to is already carried by the TSMP disco-key
  rows below. Its only effect on this ledger is line numbers: it moved the `DisableDeltaUpdates`
  gate in `map.go` from `:349` to `:278`.
- **`ipn/localapi`: require local admin for `dev-set-state-store`** (`c9f5d175b`) — **not
  applicable.** A privilege check on a LocalAPI debug handler that could otherwise write state keys
  (for example `_serve/<profile-id>`) while bypassing the per-handler admin check `serve-config`
  performs. This fork's LocalAPI serves one route and has no `dev-set-state-store` handler, so there
  is no bypass to close. Recorded rather than skipped because it is a security fix in a swept
  package: if a LocalAPI debug surface is ever added here, it inherits this requirement.
- **`go.mod`: bump `wireguard-go` for a small-packet buffer pool** (`8054aa257`) — **not
  applicable**, and it is the mapping row that has no upstream path to sweep.
  `golang.zx2c4.com/wireguard`'s device is an upstream *dependency* that `ts_tunnel` re-implements,
  so this is tracked through `go.mod` bumps rather than through the loop — which is exactly how it
  surfaced. The change reduces packet slab memory retained in per-peer staged queues. `ts_tunnel`
  does not stage per-peer packet queues in the shape being fixed, so there is no equivalent
  retention here. Adjacent but distinct from this repository's own memory trade-off, which is
  `Config::tcp_buffer_size` in the netstacks — see [`AGENTS.md`](AGENTS.md); do not conflate them.
- **`cmd/cigocacher`: stop logging the default cache dir** (`91bd4f99d`) and **`go.toolchain.rev`
  bump** (`e2ed43239`) — **not applicable.** Upstream CI tooling and toolchain pinning; neither is a
  client behaviour and `cmd/` is out of scope.

#### Not applicable, from packages first swept at the previous revision

- **`sessionrecording`'s seven commits in the window** — **not applicable**, all seven, and recorded
  here so the next revision does not re-derive them. The package entered the loop at the **previous**
  revision, the fifth and most embarrassing time the sweep list was found short (see
  [Re-deriving this ledger](#re-deriving-this-ledger) for why it was missing). Re-run at this pin the
  loop returns the same seven — upstream touched the package none of the seven times in the interval
  — so these assessments carry unchanged. `08eae9aff`
  (2025-10-10) adds `Event.Destination` and the `Destination` struct to `sessionrecording/event.go`:
  that is the **Kubernetes API-server proxy's** audit-event stream, not the SSH cast stream, and this
  fork has no API-server proxy. `cd2a3425c` (2025-10-08) introduced that same event surface and is
  out for the same reason. `899625464` (2025-10-29) fixes a Go-internal transport slip —
  `DialTLSContext` where `DialContext` was meant, so the passed-in dialer was being ignored in favour
  of `net.Dialer`; this fork dials the recorder over the tailnet explicitly and has no
  `http.Transport` to mis-wire. `53ef7f92c` (2026-06-19) calls `hc.CloseIdleConnections()` after the
  upload and sets a 30 s `IdleConnTimeout` on both recorder clients, to stop the SSH server
  exhausting ports by pooling idle connections to the recorder; this fork's recorder client
  ([`src/ssh/recording.rs`](src/ssh/recording.rs)) holds no connection pool to leak — the upload owns
  its connection and closes it — so there is no idle connection to reap. The remaining three
  (`7f3bbc986`, `5ef3713c9`, `3ec5be3f5`) are a `net/netutil` helper, a `cmd/vet` analyzer and the
  `AUTHORS` file removal, and touch this package only incidentally.
  The one thing worth re-checking at every future revision is **not** in those commits: `CastHeader`
  in `sessionrecording/header.go` is the wire format this fork writes to a real tsrecorder, it is
  unchanged in the window, and it is the reason the package needs to be in the loop at all. A field
  added to it is a field a recorder will expect.

- **A wrapped (tailnet-lock) auth key is sent to control verbatim, and no node-key signature is ever
  sent** (`tka/sig.go`: `DecodeWrappedAuthkey`, `SignByCredential`; `control/controlclient/direct.go`:
  the `authKey, isWrapped, wrappedSig, wrappedKey := tka.DecodeWrappedAuthkey(c.authKey, c.logf)`
  line in `doLogin`, and `RegisterRequest.NodeKeySignature`) — **needs port**, and it is the row with
  the sharpest failure of the eight: on a tailnet whose lock is on, there is no way for this node to
  arrive signed.
  Upstream's pre-auth keys come in two forms. A plain key is `tskey-auth-…`. A key issued for a
  tailnet whose lock is on is *wrapped*: the same key, then the literal separator `--TL`, then a
  base64 (raw-std, unpadded) `SigCredential` node-key signature, a `-`, and a base64 ed25519 private
  key whose signing authority that credential delegates. `DecodeWrappedAuthkey` cuts the string at
  `--TL` and returns the two halves; every decode failure inside it returns the *whole* string with
  `isWrapped` false, so a malformed suffix degrades to "this is a plain key" rather than to an error.
  `doLogin` then does two things with the result that this tree does neither of: it registers with
  the **stripped** key — the part before `--TL`, which is what control is expecting to see — and,
  when the key was wrapped, it calls `tka.SignByCredential(wrappedKey, wrappedSig, tryingNewKey.Public())`
  to build a `SigRotation` whose `Nested` is the credential and whose signature is made by the
  delegated private key, and attaches it as `RegisterRequest.NodeKeySignature`. That signature is
  what makes the new node key trusted under the lock from its first contact, with no human running
  `tailscale lock sign`.
  Here, the auth key reaches the wire untouched: `ts_control::tokio::register` takes
  `auth_key: Option<&str>` and sets `auth: auth_key.map(RegisterAuth::from)`, and `RegisterAuth`
  ([`ts_control_serde/src/register.rs`](ts_control_serde/src/register.rs)) is a one-field borrow of
  that same `&str`. The literal `--TL` appears nowhere in the tree. `RegisterRequest.node_key_signature`
  is modelled — with Go's own comment on it — and is never set by any caller. So two things go wrong
  at once for an embedder handed a wrapped key: the auth key sent to control is not the auth key
  control issued, and even if control tolerated the suffix the node would register unsigned, which on
  a locked tailnet is a node its peers will refuse. The peer-side half of the lock is fully
  implemented here — `ts_tka`'s `verify_signature` accepts `Credential`-rooted chains and skips the
  `pubkey == node_key` bind for a `Credential` leaf, because `SigCredential` leaves `Pubkey` unused
  and binding it rejects legitimate credential-provisioned peers — so what is missing is specifically
  the *self*-signing half, and `ts_tka` already has the pieces:
  `NodeKeySignature::sign_rotation` builds a rotation wrap, and `ts_runtime`'s `tka_sign` already
  signs and submits a `Direct` signature over a live Noise channel. What is absent is the decode of
  the `--TL` suffix and a rotation wrap whose nested signature is a *supplied* credential rather than
  an inner `Direct` this tree constructs.
  Bring Go's refusals with it, because they are the whole safety of the feature: a key with no `--TL`
  is a plain key; a suffix with no `-` delimiter, a suffix half that is not valid unpadded raw-std
  base64, or a signature blob that does not deserialize all degrade to "plain key" and register
  unwrapped rather than failing; and `SignByCredential` refuses outright when the wrapped signature is
  not of kind `SigCredential` (`wrapped signature must be a credential, got %v`), which is the usage
  refusal to port rather than to infer.

- **The register response's two instructions — re-sign this node key, and regenerate the expired one
  — are both ignored** (`control/controlclient/direct.go`: `doLoginOrRegen`, the
  `if len(resp.NodeKeySignature) > 0` and `if resp.NodeKeyExpired` arms of `doLogin`, and the
  `tka.ResignNKS(persist.NetworkLockKey, tryingNewKey.Public(), opt.OldNodeKeySignature)` call;
  `tka/sig.go`: `ResignNKS`, `maybeTrimRotationSignatureChain`) — **needs port**, and it is the row
  most likely to present as a node that simply stops working one day rather than as a node that never
  worked.
  Upstream's registration is a two-shot loop, and the shape is `doLoginOrRegen`: call `doLogin`; if it
  comes back with `mustRegen`, set `opt.Regen` and `opt.OldNodeKeySignature` from what the first call
  returned and call it exactly once more. Two things in the response set `mustRegen`. **`NodeKeySignature`
  non-empty** means "here is the signature your *old* node key had; re-sign it for the new one" —
  `doLogin` returns it, and on the second pass `tka.ResignNKS` unserializes it, returns it verbatim if
  it already covers the key being registered, otherwise wraps it in a fresh `SigRotation` signed by
  this node's network-lock private key, and the result goes out as `RegisterRequest.NodeKeySignature`.
  `maybeTrimRotationSignatureChain` is the bound that makes the wrap safe to repeat: a rotation chain
  may name at most 15 previous node keys, because CBOR nesting is capped at 16, and past that the
  chain is rebuilt from the original `Direct` leaf forward. **`NodeKeyExpired`** means the key just
  offered is expired; Go logs it without PII and returns `mustRegen` so the second pass generates a
  fresh node key (moving the current one to `OldPrivateNodeKey`), and it treats `regen=true` *with*
  `NodeKeyExpired` as a contradiction and errors — `weird: regen=true but server says NodeKeyExpired`.
  Here, `classify_register_response` ([`ts_control/src/tokio/register.rs`](ts_control/src/tokio/register.rs))
  reads exactly three things: `machine_authorized`, `auth_url` and `error`. `node_key_signature` and
  `node_key_expired` are both modelled on `RegisterResponse` and are read by nothing in the tree, so
  each of control's two instructions lands as an unauthorized registration with no auth URL —
  `MachineNotAuthorized(None)` — and the caller retries the same key with the same missing signature.
  The node-key rotation machinery it would need is already here: `ts_keys::NodeState` carries
  `old_node_key` and the register path already logs `re-registering with OldNodeKey set`, and
  `network_lock_keys` is persisted and its public half already goes out as `RegisterRequest.nl_key` —
  which is precisely the declaration on the strength of which control sends the signature back.
  The port is the loop, not the crypto: classify the two fields into the existing typed error set,
  re-sign or regenerate, and retry **once**. Go's single retry is the behaviour to copy, not an
  unbounded loop. The refusals to carry: the signature is used verbatim when it already covers the
  key being registered rather than being needlessly re-wrapped; a chain at the 15-key limit is
  trimmed rather than extended; a re-sign failure is logged and registration proceeds *without* a
  signature (Go's `ResignNKS` error path does not abort the register); and `regen` together with
  `NodeKeyExpired` is an error, not a third attempt.

- **MagicDNS `AAAA` answers are gated on a local flag, not on the `magicdns-aaaa` node capability**
  (`ipn/ipnlocal/node_backend.go`: `magicDNSAddrs`, `magicDNSHostAddrs`, and the
  `nm.AllCaps.Contains(nodecap.MagicDNSPeerAAAA)` test in `dnsConfigForNetmap`;
  `tailcfg/nodecap/nodecap.go`: `MagicDNSPeerAAAA`; capability version 116) — **needs port**, and it
  is the one row of the eight that diverges in *both* directions: this node can answer `AAAA` where Go
  would not, and refuse it where Go would answer.
  Upstream decides a peer's MagicDNS addresses in one function, `magicDNSAddrs`, from the peer's
  addresses plus two flags. The default rule is deliberately conservative and is commented as such:
  if the peer has an IPv4 address at all, its IPv6 addresses are dropped from the answer, "as we
  don't guarantee that the peer node actually can speak IPv6 correctly". Two things lift it.
  `selfV6Only` — *this* node has v6 addresses and no v4 — returns only the peer's v6, because there
  is nothing else this node could reach. And `wantAAAA`, set when the **self node** holds the
  `magicdns-aaaa` capability, keeps the peer's v6 alongside its v4. Capability version 116
  (2025-05-05, "Client serves MagicDNS `AAAA` if `NodeAttrMagicDNSPeerAAAA` set on self node") is the
  declaration that the client will do this, and it sits well below the 125 this node declares, so
  control may set the attribute and expect `AAAA` to start being served.
  Here the whole decision is one embedder-set boolean. `ts_runtime::magic_dns` answers an `AAAA`
  question for a tailnet name from `DnsView::enable_ipv6`, which is `ts_control::Config::enable_ipv6`
  carried through `ts_runtime::env`: with it off (the default) a known peer's `AAAA` returns `NoError`
  with an empty answer, and with it on the peer's overlay v6 address is returned. Control's
  capability map is not consulted; the string `magicdns-aaaa` appears nowhere in the tree. The two
  divergences fall straight out. With `enable_ipv6` on and the attribute *unset*, this node hands out
  a peer's `AAAA` beside its `A` — which is what Go does only when control asked for it, and Go's
  comment says why it otherwise does not. With `enable_ipv6` off and the attribute *set*, control has
  asked for `AAAA` and gets `NODATA`.
  The port is to make the answer the conjunction Go makes it: keep the local gate, because it is this
  fork's own anti-leak decision and is load-bearing (with IPv6 off the node opens no IPv6 socket, so
  an `AAAA` it hands out is an address it cannot then reach), and add the capability as the second
  condition, with Go's default suppression — drop a peer's v6 when that peer also has a v4 — applying
  when the capability is absent. The self-v6-only case can be assessed and recorded rather than
  implemented: a node with only v6 addresses is not a configuration this fork produces today. Assert
  the negatives: a peer with only a v6 address is answered under the *current* rules already and must
  not regress; an `AAAA` for a tailnet name that resolves to nothing is still `NXDOMAIN` and is never
  forwarded upstream (the existing anti-leak test); and the capability is read from the **self** node,
  not from the peer being resolved.

- **The DERP home region is chosen without control's per-region scores**
  (`net/netcheck/netcheck.go`: `addReportHistoryAndSetPreferredDERP`; `tailcfg/derpmap.go`:
  `DERPHomeParams.RegionScore`) — **needs port**, and it is narrow, cheap, and the clearest example in
  this ledger of a gap that only a top-to-bottom read of an already-ported function can find.
  Upstream's home-DERP choice is latency plus history plus stickiness, and this tree ports all three
  faithfully — `ts_runtime::control_runner::select_home_region` reproduces Go's asymmetric comparison
  (the candidate by smoothed latency, the incumbent by this cycle's raw latency), its 10 ms absolute
  threshold, and even its integer `oldRegionCurLatency/3*2` in preference to the float form, with the
  divergence at the exact two-thirds boundary written out in the comment. What it does not do is the
  step Go takes *first*. Before any comparison, Go fetches `dm.HomeParams().RegionScore()` and scales
  every region's latency by its score — both the smoothed `bestRecent` map and, separately, each
  region's latency in the current report, because the reports themselves are deliberately not mutated
  in case the scores change. A score in `(0, 1)` makes a region proportionally more preferred, a score
  above 1 penalises it, an absent region is 1.0, and a zero or negative score is ignored — Go's
  `if score := scores.Get(regionID); score > 0`. A nil map means "no change from the previous value";
  an empty non-nil map resets every score to 1.0.
  Here, `DerpMap::home_params` and `HomeParams::region_score`
  ([`ts_control_serde/src/derp_map.rs`](ts_control_serde/src/derp_map.rs)) are modelled and are read
  by nothing: `ts_netcheck::RegionResult` carries an id, a latency, a latency-map key and the
  connected remote, and `select_home_region` sees only that. So control's only lever for steering a
  client off a region it is deliberately draining does nothing to this node, which keeps choosing on
  raw latency and reporting the result in `NetInfo.PreferredDERP` — the field control reads back to
  find out where to route the node's traffic.
  The port is to scale inside the existing pure function so it stays unit-testable: pass the score map
  in, apply it to both the smoothed and the raw sides exactly where Go applies it, and leave the
  hysteresis arithmetic untouched. The cases to pin are Go's guards, not the happy path: a score of 0
  or below is ignored rather than treated as "infinitely preferred", a region absent from the map is
  unscaled, an empty map is a reset and a nil map is not, and a score high enough to move the choice
  must still pass the same stickiness thresholds — scoring changes the inputs to the comparison, never
  the comparison.

- **Only `c2n` ping requests are answered, and a repeated one is answered again**
  (`control/controlclient/direct.go`: `answerPing`, `answerHeadPing`, `doPingerPing`,
  `isUniquePingRequest`, and the `if pr := resp.PingRequest; pr != nil && c.isUniquePingRequest(pr)`
  guard in the map-response loop; `tailcfg`: `PingRequest.URLIsNoise`, capability version 38) —
  **needs port**, and the cheap half of it is the half worth doing first.
  Upstream's `PingRequest` is control asking the node to do something and report back by hitting
  `pr.URL`, and `answerPing` has four arms. `Types == ""` is a plain **HEAD ping**: `answerHeadPing`
  issues an HTTP `HEAD` to `pr.URL` under a 15-second timeout and logs the round-trip; it is how
  control measures that a node is awake and can reach a URL. `Types == "c2n"` is the control-to-node
  HTTP request this tree implements. Anything else is a comma-separated list of `PingType`s —
  `disco`, `TSMP`, `ICMP`, `peerapi` — each dispatched to `doPingerPing`, with an explicit
  `unsupported ping request type: %q` for a name outside that set. Two rules sit around the switch.
  `useNoise := pr.URLIsNoise || pr.Types == "c2n"` chooses the transport, and a `c2n` request that
  did *not* come out as Noise is **refused** rather than answered — `refusing to answer c2n ping
  without noise` — unless a debug envknob says otherwise. And the request is only dispatched at all
  when `isUniquePingRequest` says its `URL` differs from the last one seen: a `PingRequest` with an
  empty URL is bogus and dropped, and a repeat of the previous URL is dropped too, so a re-sent or
  replayed map response does not produce a second answer.
  `ts_control::handle_ping` ([`ts_control/src/tokio/ping.rs`](ts_control/src/tokio/ping.rs)) walks
  `ping_request.types` and `continue`s past everything that is not `PingType::C2N` with
  `ignoring unsupported ping type`. An empty `types` — Go's HEAD ping — is not an unsupported type but
  an empty loop, so it is dropped with no log at all, which is the least debuggable of the two
  outcomes. There is no dedup: every map response carrying a `PingRequest` is answered, however many
  times control sends the same one. `url_is_noise` is modelled on the request and read by nothing,
  which is harmless *today* only because the one arm implemented is the one Go forces onto Noise
  regardless. And the response is posted to `control_url.join(ping_request.url.path())` — the path
  only, rebased onto the control URL — where Go posts to `pr.URL` as given; that is a deliberate-looking
  narrowing this fork should keep, but it currently keeps it by accident and drops the query string
  with it, so it belongs in a comment either way.
  The port splits cleanly. The HEAD arm and the dedup are small, self-contained and need no new
  subsystem. The `doPingerPing` arms need a pinger this `Device` does not expose — and the `TSMP` one
  is the send half of the *A TSMP ping gets no pong* row below, which is the reason to read the two
  rows together and to decide them in that order. Carry the refusals: an empty `pr.URL` is bogus and
  answered with nothing, a repeated URL is dropped, an unknown type name is logged and skipped rather
  than failing the whole request, and a `c2n` request is answered only over Noise.

- **The map request never carries `TKAHead`, so control is told this node has no lock state**
  (`control/controlclient/direct.go`: `SetTKAHead` and the `TKAHead: tkaHead` field of the built
  `MapRequest`; `control/controlclient/auto.go`: `Auto.SetTKAHead`) — **needs port**, narrow, and
  recorded with its own bound: nothing in this tree's own tailnet-lock sync depends on it.
  Upstream keeps the head hash of the local tailnet-lock authority on the `Direct` client and stamps
  it into **every** map request. `SetTKAHead` reports whether the value actually changed, and `Auto`
  uses that to force a fresh map request when it does, so control learns of a local head advance
  promptly rather than on the next unrelated update. It is the mirror of `MapResponse`'s `TKAInfo`:
  control says where it thinks the chain is, the client says where it actually is.
  Here, `MapRequest::tka_head` ([`ts_control_serde/src/netmap.rs`](ts_control_serde/src/netmap.rs))
  is modelled as `&'a str` with Go's own description, and `MapRequestBuilder`
  ([`ts_control/src/map_request_builder.rs`](ts_control/src/map_request_builder.rs)) has no setter for
  it, so it takes its `Default` and every map request this node has ever sent carries an empty head.
  The bound worth stating, so the row is not read as worse than it is: this tree's sync is driven
  entirely from the *response* side — `ts_runtime::control_runner::maybe_sync_tka` compares control's
  `TKAInfo.Head` with the local `Authority`'s head and syncs when they differ, which is Go's
  `tkaSyncIfNeeded` — so an empty request-side head costs correctness nothing here. What it costs is
  honesty on the wire: a control plane that reads `TKAHead` to decide what to send, or to notice a
  node whose chain has forked or fallen behind, sees a node that is permanently at genesis, which is
  exactly the "no peer or control plane can distinguish this from a Go client" line this repository
  is measured against. The port is a setter on the builder fed from the synced authority's head in
  its base32 form (`Authority::head` → `AumHash::to_base32`, both already used by the sync path),
  plus Go's changed-or-not return so a head advance triggers a map request instead of waiting for one.
  The negative cases: no synced authority means the empty string, not a zero-hash; and an unchanged
  head must not force a request, or a node with a lock sends map requests in a loop.

- **ACL rules whose source is a capability (`cap:…`) never match**
  (`wgengine/filter/filtertype/filtertype.go`: `Match.SrcCaps`; `wgengine/filter/filter.go`:
  `f.srcIPHasCap`; `ipn/ipnlocal/local.go`: `srcIPHasCapForFilter`; capability versions 100 and 109)
  — **needs port**, and it is the cheapest of the previous revision's five rows to close, because
  every layer but the caller is already right.
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
  capability version 81) — **needs port**, and it is the one of the previous revision's rows where
  the missing behaviour
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
  `wgengine/userspace.go`: `OnTSMPPongReceived`) — **needs port**, and it is the carried row a real Go
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
  rotation) and every candidate's measurement and ping timestamps, while **keeping** `best` and the
  candidate set, which is exactly Go's "keep bestAddr so that we can still send data while we find a
  new path". `invalidate_best`, the rebind case, still clears the best address outright, because
  there the *local* NAT mapping changed and the address is stale as an address.

  **Narrowed twice at this revision, and the row's own wording was part of what was wrong.** #369
  left the re-probe to the periodic sweep, so this row (and the function's doc) claimed traffic rode
  DERP "for the one round trip it takes to re-confirm" when nothing had asked for that round trip —
  it was up to a full `PING_INTERVAL` (2 s) short of true. #451 (`588ea36`) pings inside the netmap
  handler instead, and #453 (`4060be0`) fixed the arm of `changed_active_disco` that answered "no
  re-probe needed" for the case that needs it most: where path state already exists under the peer's
  *new* disco key, which is normally an unconfirmed entry built from an inbound disco ping rather
  than a confirmed one. Both are closer to upstream without reaching it: Go's `addrForSendLocked`
  returns the retained-but-untrusted `bestAddr` **and** the DERP address, so a packet rides both
  while the path is re-confirmed, and this dataplane routes each peer through exactly one underlay.
  That residual difference is a deliberate divergence of the overlay-router design, not an open row.
  Recorded here because the row read as settled for two revisions while its central timing claim was
  not checked against the code.
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

- **Services model extension** (`tailcfg`: `1cd8bcc82`, `6cd185bf3`, `fc9b18f50`) — **already
  covered**, *changed from "needs port" at this revision*: #459 (`2194f0d`) ported the consuming half.
  `ts_control_serde::service_vip` now carries `ServiceDetails` (decoded from the `services/<id>` cap
  values under `NODE_ATTR_PREFIX_SERVICES`), `ServiceAction`, `ServiceActionType` with the thirteen
  well-known slugs and the three action-attribute keys, and `ts_control::Node::visible_services()`
  surfaces them off the domain node's cap map. The forward-compatibility shape is the part worth
  re-checking rather than the field list: `ServiceActionType` is a transparent `&str` newtype rather
  than an enum, and action attribute values stay raw JSON, because Go's contract is that a client
  **ignores an action type it does not recognise** rather than failing the netmap — an enum would
  turn a newer control plane into a decode failure that takes the whole map response with it.
  Unparseable values are skipped per value, not per node. This closes the decode side only, which is
  the whole of what a headless library owes here: upstream's *consumers* of these actions are the
  desktop and mobile GUIs, which choose an application to launch per port, and this fork has no such
  surface — so `visible_services()` having no caller in this tree is correct rather than a follow-on
  gap. The `services/` string is one of the sixteen genuine node-attribute reads counted above.

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

- **`NetInfo.HairPinning` was deleted upstream and is still modelled here** (`tailcfg`:
  `de733c595`, 2025-11-09, "tailcfg: kill off rest of HairPinning symbols") — **needs port**, where
  the port is a deletion, and it is the only row at this revision that comes from a commit inside the
  window — a commit a plain reading of the sweep should have produced at one of the previous six
  revisions.
  Upstream stopped populating `NetInfo.HairPinning` in May 2024 (`9eb72bb51`, #12205) and removed the
  last symbols at `de733c595`: the struct field, its `Clone`, its view accessor and its tests. At the
  pin the string `HairPinning` does not appear anywhere in `tailscale/tailscale`. It is gone from the
  wire type, so a Go client neither sends the key nor expects it.
  `ts_control_serde::NetInfo::hair_pinning` ([`ts_control_serde/src/net_info.rs`](ts_control_serde/src/net_info.rs))
  is still declared, with the old Go doc comment on it, as `Option<bool>` under
  `skip_serializing_if = "Option::is_none"`. **There is no divergence on the wire today** and the row
  says so plainly: nothing in this tree sets the field, so it is always `None`, so it is always
  absent — which is a field-by-field match with a Go client that no longer has it. What the row is
  about is the trap and the audit. The trap is that the only thing standing between this tree and an
  identifiable not-a-Go-client tell is that nobody has written to a `pub` field; a `NetInfo` carrying
  `"HairPinning"` is a key no Go client has sent since 2024. The audit is the more useful half: this
  was found by taking every `pub` field in `ts_control_serde` and checking its wire name against every
  identifier in upstream's Go, which is the mechanical form of the "field-by-field re-read of
  `tailcfg` against `ts_control_serde`" the `encoding/json/v2` row below has been asking for. Run in
  both directions at this revision, that check returns exactly this one phantom field outbound, and
  inbound returns `Node.ComputedName`/`ComputedNameWithHost` (the row below), `Hostinfo.RemoteConfig`
  (the unported half of `feature/remoteconfig`, already recorded) and `DNSConfig.TempCorpIssue13969`
  (upstream's own named-for-deletion field). That is a cheap check with a short answer, and it is now
  part of the recipe.

- **Peer display names are the FQDN, where Go computes three names and shows the short one**
  (`tailcfg`: `Node.InitDisplayNames`, `Node.DisplayName`, `Node.ComputedName`,
  `Node.ComputedNameWithHost`; `control/controlclient/map.go` and `direct.go`, which call
  `InitDisplayNames(magicDNSSuffix)` on the self node and on every changed peer) — **needs port**,
  narrow, and **status-surface only**: no peer and no control plane observes it, so a reader
  triaging this list should rank it accordingly.
  Upstream computes the display names on the *client*, not in control — the comment on the fields says
  so ("populated from controlclient (not from control)") — and the rule in `InitDisplayNames` is
  four steps. Trim the tailnet's MagicDNS suffix off `Node.Name`, giving the base name for an ordinary
  node and the whole FQDN for a shared-in node whose name is under a different tailnet. Take
  `dnsname.SanitizeHostname(Hostinfo.Hostname)` as the host name, and discard it when it matches the
  base name case-insensitively. If the base name came out empty, promote the host name into it, or
  fall back to the node key's string form when there is no host name either. Finally build
  `ComputedNameWithHost` as `"name (host)"` when a differing host name survived, and as the bare name
  otherwise. `DisplayName(forOwner)` then picks between the two — the owner of a node sees the form
  that disambiguates it, everyone else sees the short one.
  Here, `ts_runtime::status::StatusNode::from_node` ([`ts_runtime/src/status.rs`](ts_runtime/src/status.rs))
  sets one field by one rule: `node.fqdn_opt(false).unwrap_or_else(|| node.hostname.clone())` — the
  FQDN if a tailnet component is known, else the bare hostname — and its test asserts exactly that.
  So where `tailscale status` shows `laptop`, this fork's `StatusNode::display_name` shows
  `laptop.tailnet-name.ts.net`, and where Go disambiguates two nodes as `laptop` and
  `laptop (laptop-2)` this fork shows two FQDNs. `Node.ComputedName` and `Node.ComputedNameWithHost`
  are the two `tailcfg` fields with no counterpart in `ts_control_serde`, which is the other half of
  the same fact — and note they are `json`-tagged, so control *may* send them, but Go overwrites
  whatever arrives by calling `InitDisplayNames` itself.
  The port is `InitDisplayNames` as a function over the domain `Node`, called where the netmap is
  ingested rather than at each status read, plus the owner/not-owner choice on the way out. Carry the
  refusals, because they are the whole of the function: a host name equal to the base name
  case-insensitively is dropped rather than shown in parentheses, an empty base name promotes the host
  name instead of rendering as empty, and a node with neither falls back to the node key rather than
  to an empty string.

#### Not applicable, from code read at previous revisions and re-checked here

These are what earlier revisions' reading turned up that did **not** open a needs-port row; they are
written down for the same reason a closed row is, so the next revision can re-check the judgement
instead of re-deriving it. The first is the residue of the `controlknobs` read that produced seven
rows at the previous revision, and its tally **moved at this one**, because six of those seven
rows were ported in the interval.

- **The other twenty-one `controlknobs` knobs, and the node attributes outside that struct**
  (`control/controlknobs/controlknobs.go`; `tailcfg/nodecap/nodecap.go`) — **not applicable**, each
  for a reason this fork has already settled. Reading `Knobs` top to bottom against this tree gives
  twenty-seven knobs in three groups, and the first two groups changed size at this revision. **Six
  are now honoured**, up from one: `CacheNetworkMaps` with `DisableCacheNetworkMaps` taking
  precedence (§A row 135), plus `SilentDisco` (#445), `ForceBackgroundSTUN` (#443),
  `DisableDeltaUpdates` (#442), `DisableDNSForwarderTCPRetries` (#440) and `OneCGNAT` (#438) — the
  last two of those with the caveats recorded in the rows above, which is why "honoured" here means
  "read and acted on", not "ported cleanly". **None of the twenty-seven now has a live target and
  is ignored**, which is the first time that has been true. The one switch still in that category is
  not in `Knobs` at all: `disable-relay-client`, which upstream reads directly in `magicsock`
  alongside `only-tcp-443` (the latter now read here, via #448). The remaining
  twenty-one have **no target here**:
  - already §A rows, assessed there and not repeated: `DisableHostsFileUpdates` (132),
    `ForceRegisterMagicDNSIPv4Only` (133, the one open §A row), `EmitRuntimeMetrics` (139), the four
    GRO/GSO knobs (140), `NeverGSOEqualTail` (141), `ScopeQuad100OnMacOS` (145).
  - no subsystem to switch: `DisableUPnP` and `ProbeUDPLifetime` (no portmapper, no UDP-lifetime
    probing — *roadmap*), `PeerMTUEnable` (no path-MTU discovery on this datapath),
    `LinuxForceIPTables` / `LinuxForceNfTables` (`ts_host_net` installs no firewall rules),
    `AppCStoreRoutes` (no app connector — *roadmap*), `DisableCaptivePortalDetection` (no
    captive-portal detection), `DisableSplitDNSWhenNoCustomResolvers` (an iOS battery optimisation
    with no macOS/Linux arm), `DisableLocalDNSOverrideViaNRPT` (Windows NRPT; no Windows backend).
  - Go-internal shape rather than behaviour: `DisableSkipStatusQueue` gates whether queued
    `netmap.NetworkMap` values may be skipped between `controlclient` and `LocalBackend`, which is
    a Go channel discipline this actor-per-concern runtime does not reproduce.
  - `UserDialUseRoutes` — already a row of its own below (`UserDial` happy eyeballs), *not
    applicable* for the same reason: there is no `UserDial` here to route.
  - `RandomizeClientPort` is the one that needs a sentence rather than a line, because it looks
    applicable and is not. Upstream's knob makes magicsock bind `:0` *instead of a configured fixed
    port* (`wgengine/userspace.go:836`). This fork has no configured fixed port: `rebind_socket`
    binds ephemeral and only *prefers* the previous port across a re-bind, so that an advertised
    endpoint survives ([`ts_magicsock/src/sock.rs:97`](ts_magicsock/src/sock.rs)). There is nothing
    for the attribute to override. If a fixed-port option is ever added to `Config`, this knob
    becomes live in the same commit and should be ported with it.

  Outside `Knobs`, the attributes with no counterpart here are the ones the §A table and the *no
  counterpart* list already cover: the daemon/GUI surfaces (`disable-web-client`,
  `suggest-exit-node-ui`, `tailnet-display-name`, `auto-exit-node`, `native-ipv4`), the SSH incubator
  knobs (`ssh-behavior-v1`, `ssh-behavior-v2`, `ssh-aggregator`, `ssh-env-vars` — this fork's SSH
  server runs no incubator and accepts no `SendEnv`), `log-exit-flows` (*roadmap*, netlog),
  `store-appc-routes`, `disable-relay-server` (this node never serves as a relay), the Darwin
  socket-binding caps, and the debug caps `debug-no-wg-trim` (no lazy WireGuard config here) and
  `debug-disable-subnets-if-pac` (no WPAD detection).

- **`NetInfo` is reported with four of the twelve facets Go fills**
  (`wgengine/magicsock/magicsock.go`: `updateNetInfo`) — **not applicable**, on grounds this fork has
  already settled elsewhere. (The thirteenth field this tree models is `HairPinning`, and that one is
  a row of its own above.) Go builds a whole `tailcfg.NetInfo`
  out of each netcheck report: `MappingVariesByDestIP`, `UPnP`, `PMP`, `PCP`, `HavePortMap`, the
  `DERPLatency` map keyed `"<rid>-v4"`/`"-v6"`, `WorkingIPv6`, `OSHasIPv6`, `WorkingUDP`,
  `WorkingICMPv4`, `PreferredDERP` and `FirewallMode`, and hands it to a callback that ships it on the
  next map request — de-duplicated by `BasicallyEqual`, so an unchanged report is not re-uploaded.
  `ts_control::tokio::client`'s `CarriedNetInfo` carries four of those — `preferred_derp`,
  `derp_latency`, `working_udp`, `mapping_varies_by_dest_ip` — and applies the whole of it to every
  map request, which is Go's `hi.NetInfo = c.netinfo.Clone()` invariant and is already tested here.
  The eight it does not carry each have an answer already recorded in the *no counterpart here* list
  or in this fork's design: `UPnP`, `PMP`, `PCP` and `HavePortMap` need `net/portmapper`, which is
  roadmap; `FirewallMode` describes an iptables-vs-nftables choice `ts_host_net` never makes because
  it installs no firewall rules (the same reason capability version 136 is not applicable);
  `WorkingIPv6` and `OSHasIPv6` come from a netcheck that probes v6, and this fork's `ts_netcheck` is
  HTTPS-over-IPv4 only by deliberate anti-leak design — the note at the top of
  [`ts_netcheck/src/lib.rs`](ts_netcheck/src/lib.rs) records that a STUN prober binding a second
  socket was removed rather than left dormant; and `WorkingICMPv4` needs an ICMP socket this node does
  not open. `LinkType` is the one to *not* go looking for: upstream declares it and fills it nowhere,
  so leaving it absent is parity, not a gap. The thirteenth field this tree models, `HairPinning`, is
  a different case entirely and **is** a row — upstream deleted it, and the row is above.

- **Traffic-steering exit-node suggestion** (`ipn/ipnlocal/local.go`: `suggestExitNode`,
  `suggestExitNodeUsingTrafficSteering`; `net/traffic`; `tailcfg/nodecap`: `TrafficSteering`) —
  **not applicable**, and it is the tidier twin of the `net/routecheck` row below it. Upstream's
  `suggestExitNode` is a `switch` with two arms: when the self node holds the `traffic-steering`
  capability it ranks candidates by the priority scores in `net/traffic` (an FNV-based rendezvous
  hash over peers, memoised per netmap), and its `default` arm is `suggestExitNodeUsingDERP`, the
  latency-and-region algorithm this tree ports and which the previous revision's #417 finished by
  adding the per-region latency history. The capability is not implemented here and `net/traffic` has
  no counterpart, so this node takes Go's own default arm — which is the correct behaviour for a
  client that does not advertise the capability, exactly as with `client-side-reachability` and
  `net/routecheck`. Recorded because `net/traffic` is a package upstream added inside the window and
  a reader doing the new-package check will land on it: it is read by `ipn/ipnlocal`, which *is*
  mapped, so the check's question ("does anything already swept now read from it?") answers yes and
  the follow-up question ("and does that reading change a behaviour this tree implements?") answers
  no, because it is gated behind a capability this node never claims.

#### Not applicable, or already covered, from the commits new at the previous pin

Recorded so the next re-derivation does not re-read them. **No commit is new at this revision**: the
pin did not move, so this list is the previous revision's, carried unchanged and re-checked. It
covers the fourteen upstream commits that landed between `3945b82f8` and `023255e8a`, nine of them in
mapped packages, **none of which opened a row** — the first time that was true of a whole interval,
and now the second, for the stronger reason that there was no interval.

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

The rows below were re-checked against this pin and against this tree and did not move — and at this
revision that is every row this document already carried, because nothing landed against any of them.
They are kept in full because a row whose evidence is elided is a row the next re-derivation has to
redo.

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
daemon's default socket path on Android), the four previous pins. `023255e8a` — the pin for three
revisions and now the *previous* pin — was likewise only what HEAD was when it was first derived: it
tightens an on-disk DNS cache this fork does not keep, and is written up with the other commits
above. `e2ed43239`, the pin at this revision, is the same kind of commit: a `go.toolchain.rev` bump,
out of scope in itself, and the pin only because it was HEAD when the window was re-derived. Also
out, from the package the sweep list gained at the previous revision: `sessionrecording`'s
`7f3bbc986` (a `net/netutil` helper), `5ef3713c9` (a `cmd/vet` analyzer) and `3ec5be3f5` (the
`AUTHORS` removal), all three tree-wide commits that touch that package only incidentally; its four
substantive commits are assessed above.
`tsnet` has over a hundred commits in the window and is **not** re-derived here: that facade has its
own line-by-line parity matrix in [`docs/TSNET_PARITY.md`](docs/TSNET_PARITY.md), and duplicating it
into this ledger would create two records that disagree. Only `tsnet` changes that alter behaviour a
mapped crate already implements are pulled in, as `49e148c4a` and `d9cc55e33` were above.

### Re-deriving this ledger

```sh
# The capability-version window (§A): everything above CapabilityVersion::CURRENT here.
git -C <tailscale-go> grep -n 'CurrentCapabilityVersion CapabilityVersion' e2ed43239 -- tailcfg/tailcfg.go
git -C <tailscale-go> grep -nE '^//[[:space:]]*-[[:space:]]*1[3-9][0-9]:' e2ed43239 -- tailcfg/tailcfg.go

# What upstream touched per mapped package since capver 130 landed (§B). Every upstream package
# named in "Package mapping" is in this list; parent paths (wgengine, ipn) are used where the
# mapping names several children, so a subdirectory upstream adds later cannot fall outside it.
for p in tailcfg disco derp net/packet net/tstun net/netcheck net/stun net/dns \
         net/udprelay net/socks5 net/tsdial net/tlsdial net/bakedroots net/netmon net/art \
         net/routemanager \
         control/controlclient control/controlbase control/controlhttp control/controlknobs \
         wgengine ipn tsd tka types/key types/persist tsnet \
         feature/remoteconfig feature/identityfederation feature/taildrop feature/ssh \
         feature/acme ssh/tailssh sessionrecording util/clientmetric tstime tstest tool/; do
  echo "== $p"; git -C <tailscale-go> log --since=2025-10-06 --oneline -- "$p"
done

# Only what moved since the pin this ledger currently carries — the fast path on a re-derivation
# that follows soon after the last one. Read it *in addition to* the full sweep, never instead of
# it: a row's assessment can change because this tree moved, with upstream perfectly still, the
# sweep list itself can be wrong (it has been, five times), and this range can be EMPTY (it was, at
# two revisions running before the previous one, and is again at this one) without the ledger being
# finished. At the previous revision it was seven commits and supplied one of five new rows; at THIS
# revision it was empty, and the one new row came from re-reading merged ports here against upstream.
# A non-empty delta is not a licence to skip the reading either.
git ls-remote https://github.com/tailscale/tailscale HEAD   # <new-pin>; may already equal the pin
git -C <tailscale-go> log --oneline e2ed43239..<new-pin>

# And the mirror image of that: what moved *here* since the tree revision the header table names.
# At the previous revision it was TWENTY-THREE commits, six of which closed rows; at THIS revision it
# is ONE, the previous rewrite of this document. Read it against the open rows first -- that is the
# cheapest way to find a row that closed -- and then check that every port in it has been read
# against upstream, in PARITY_AUDIT.json or under "Audited at this revision" in §B. A port that
# closed a row and was never audited is where a row that closed INCOMPLETELY hides: this revision's
# one new row came from auditing four of those.
git log --oneline 01244f8..HEAD

# Wire types, both directions. Cheap, mechanical, and it found two rows two revisions ago after six
# revisions of not being run. Re-run at this pin it returns the one known phantom and nothing new.
#
# Outbound: resolve every `pub` field in ts_control_serde to the wire name it actually serializes
# under -- its #[serde(rename = "...")] if it has one, else the PascalCase of the field name -- and
# look that name up in upstream's Go. A name upstream no longer has is a field this tree models
# alone (NetInfo.HairPinning was found this way).
grep -rhoE '#\[serde\((.*)rename = "[^"]+"' ts_control_serde/src | grep -oE '"[^"]+"$' | tr -d '"' \
  | sort -u | while read -r n; do
      git -C <tailscale-go> grep -qw "$n" e2ed43239 -- '*.go' || echo "phantom: $n"
    done
# The un-renamed half is the one that matters and it is NOT optional: the renamed-field pass above
# returns nothing at this pin, and the one phantom this tree has -- NetInfo.HairPinning -- is an
# un-renamed field whose wire name is the PascalCase of its Rust name. Do that derivation explicitly
# (hair_pinning -> HairPinning), and when you automate it, do not "skip fields with a rename" by
# grepping a few lines of context for the word `rename`: net_info.rs has that word in a *comment*
# six lines above the field, which is enough to make a naive filter skip the only true positive.
# The cheap manual form, per module:
#   grep -nE '^\s*pub [a-z_]+\s*:' ts_control_serde/src/<mod>.rs
# Look the derived name up CASE-INSENSITIVELY (git grep -qiw ... -- 'tailcfg/*.go' 'tka/*.go'). Go
# spells acronyms in capitals -- DERPMap, AllowedIPs, NodeID -- so a case-sensitive lookup of the
# PascalCase derivation reports about sixty phantoms that are not. Case-insensitive, at this pin, it
# reports HairPinning (the known row) and two false positives: action_type, renamed to "Type", and
# Endpoint::ty, which reaches the wire only as MapRequest's parallel Endpoints/EndpointTypes arrays.

# Inbound: the reverse -- every json-tagged field of tailcfg's structs checked against those same
# wire names. A name this tree lacks is a field control may send that nothing here reads.
git -C <tailscale-go> show e2ed43239:tailcfg/tailcfg.go   # plus derpmap.go, tka.go, c2ntypes.go

# And the coarser version of the same question, which is where five of this revision's rows started:
# a `pub` field in ts_control_serde whose name appears nowhere else in this workspace is a field this
# node decodes and drops.

# Node attributes, the same question for control's switches rather than for its fields. Every
# constant in tailcfg/nodecap is a string control can set on this node; one that appears nowhere in
# this workspace is a switch this node ignores. Most misses are correct -- check each against the
# capability-version table and the *no counterpart here* list before opening a row. (This found
# magicdns-aaaa at this pin.)
# NOTE the character class: the first version of this command used '"[a-z0-9-]+"', which silently
# skipped every attribute whose key contains ?, =, :, . or an uppercase letter -- one-cgnat?v=true,
# one-cgnat?v=false, linux-netfilter?v=iptables, linux-netfilter?v=nftables, drive:share,
# drive:access, tailnet.maxKeyDuration and every URL-form cap. one-cgnat is a real row and six
# revisions of this walk never reported it. Widen the class; do not narrow it back.
git -C <tailscale-go> show e2ed43239:tailcfg/nodecap/nodecap.go | grep -oE '"[A-Za-z0-9?=:./_-]+"' \
  | tr -d '"' | sort -u | while read -r cap; do
      grep -rqI --include='*.rs' -- "\"$cap\"" . || echo "unhandled node attribute: $cap"
    done
# And read the HANDLED side with the same suspicion, because a bare string match is not a handler:
# at this pin "https", "full" and "foo.com" all come back handled and none of them is an attribute
# this node acts on. Only six attributes are genuinely read here: cache-network-maps,
# disable-cache-network-maps, dns-subdomain-resolve, funnel, service-host, suggest-exit-node.
```

The capability-history pattern is deliberately whitespace-tolerant: upstream writes those entries as
`//   - 133: …`, but the exact indentation is a comment convention, not something `gofmt` enforces,
and a pattern that pins it would go silently empty the day it changes. Check the row count rather
than trusting the exit status — at the pinned commit the second command returns **18 lines**, 130
through 147, i.e. the seventeen-version window of §A plus the 130 row that anchors it. Three
revisions derived **17** against a pin that never moved; the previous revision derived **18** when the
pin moved by one version; this revision derived **18** again against the same pin. That is why counting is the whole of the check rather than a formality:
when the pin does not move, "upstream added nothing", "I re-ran it against the same tree" and "the
pattern broke" all produce the same *feeling*, and only the count tells them apart. An empty or short
result means the pattern broke, not that upstream added nothing.

**Two of the commands above were wrong, and both were rewritten at the previous revision.** They are
called out here rather than only in the comments, because a command that returns a plausible short
answer is worse than one that fails: nobody re-checks it. Both behaved as intended when re-run at
this pin, and the first of them is why this revision could see six rows close at all — the six
attributes those ports added include two `one-cgnat?v=…` keys that the narrow class could not match.

1. **The node-attribute walk's character class was too narrow.** `'"[a-z0-9-]+"'` matches only
   attributes whose key is lowercase letters, digits and hyphens, and upstream has fourteen that are
   not: the four query-string forms (`one-cgnat?v=true`, `one-cgnat?v=false`,
   `linux-netfilter?v=iptables`, `linux-netfilter?v=nftables`), the two `drive:` forms,
   `tailnet.maxKeyDuration`, and the URL-form caps. The walk was added one revision ago and reported
   forty-seven unhandled attributes both times it was run; it never reported `one-cgnat`, which is a
   row in §B at this revision. The lesson generalises past this one command: **a filter written to
   match the examples in front of you is a filter that will not report the thing it was written to
   find.** Derive the class from the type's documented grammar, not from the values you happened to
   read.
2. **The outbound wire-name check only ever ran on half its input.** As written it walks fields with
   an explicit `#[serde(rename = …)]`, and at this pin that half returns *nothing*. The one phantom
   this tree actually has — `NetInfo.HairPinning`, opened as a row one revision ago — is an
   un-renamed field, found by the un-renamed half that the recipe mentioned in a parenthesis and did
   not spell out. Worse, the obvious way to automate the un-renamed half (skip a field if the lines
   above it mention `rename`) skips `hair_pinning` specifically, because the word appears in a
   comment six lines above it. The recipe now spells the derivation out.

**The sweep list is part of the ledger, and it has now been wrong five times.** The rule that
governs it has not changed since it was written down: when [Package mapping](#package-mapping)
gains an upstream package — a table row or a *partial* entry alike — add it here too, or the mapping
is a claim the sweep never checks. Four revisions ago the list gained `net/socks5`, `net/tsdial`,
`net/tlsdial`, `net/bakedroots`, `ipn/localapi`, `feature/remoteconfig` and `tsnet`; the revision
after that found it short by sixteen more and rebuilt the loop from the mapping rather than
extending it by hand (`net/netmon`, `net/art`, `control/controlhttp`, `types/persist`,
`feature/identityfederation`, `feature/taildrop`, `feature/ssh`, `feature/acme`, `ssh/tailssh`,
`util/clientmetric`, `tstime`, `tstest`, `tool/`, `tsd`, and — the consequential ones — the parent
paths `wgengine` and `ipn`).

**The third miss was the most instructive of the first three, because the rule as written would not
have caught it.** `net/routemanager` (`a5102d3fc`, 2026-07-09) is upstream's incremental route
manager: it took over the per-peer data-plane attributes that used to be derived inside
`wgengine/wgcfg`, and `net/tstun`'s `peerConfigTable` now reads `PeerRoute.Jailed`,
`PeerRoute.MasqAddr4` and `PeerRoute.MasqAddr6` out of it. The mapping had no row for it, so the
loop had no entry for it, so four commits' worth of behaviour sat outside the sweep for two months.
The generalisation worth carrying forward: the rule "add a package to the loop when the mapping gains
one" only fires when someone *notices* the mapping should gain one. **Upstream splitting an existing
package is the case that slips**, because nothing about the mapping looks stale — `wgengine` was
already in the loop, and the behaviour simply walked out of it. The check that would have caught this
is cheap and is part of the recipe: `git -C <tailscale-go> log --diff-filter=A --oneline
<old-pin>..<new-pin> -- '*/*.go'` for new top-level packages, and for each one, ask not "does it have
a counterpart here" but "does anything *already swept* now read from it".

**The fourth miss looked like it did not pay, and the fifth revision found that it had.**
`control/controlknobs` is upstream's single struct of the client behaviours control can switch on and
off. The previous revision added it by the rule, read its fifteen commits in the window, found every
one already assessed, and concluded that "a mapping row that is honest is worth adding even when
adding it pays nothing." Reading the **struct** instead of its **commits** opened eight rows at this
revision. Both halves of that are worth keeping. The conclusion was wrong, and the reason it was
wrong is a distinction this document had not drawn before: sweeping a package asks *what changed in
it*, and for a package whose whole content is a list of switches, nothing changing is not the same as
nothing being owed. **When a package's purpose is to enumerate something, read the enumeration, not
its history.** `controlknobs` is one such package; `tailcfg/nodecap` is the other, and `tailcfg`'s
capability-version comment is a third.

**The fifth miss is the one to be embarrassed by, because the entry had been considered and written
out.** `sessionrecording` has had a [Package mapping](#package-mapping) row since it moved out of the
*no counterpart* list four revisions ago, and the previous revision recorded, in §B, that it "needs no
loop entry of its own, because the client half lives behind `ssh/tailssh`'s calling code, which is
swept." One command falsifies that: `git log --since=2025-10-06 --oneline -- sessionrecording`
returns seven commits, and not one of them appears in `ssh/tailssh`'s log for the same window. Being
*called from* a swept package does not put a package's commits in a swept package's log — nothing
about Go's import graph makes that true, and the sentence reads as though it should be. All seven
assess *not applicable* (they are written up in §B), so the cost this time was zero and the rule the
episode establishes is not: **the only admissible reason to leave a mapped package out of the loop is
that it has no upstream path to sweep.** `golang.zx2c4.com/wireguard` qualifies — it is a dependency,
not a directory in this repository. Nothing else does. If a package is in the mapping and has a path,
put the path in the loop and let the assessments come out *not applicable*; that costs one line of
output per revision and it is re-checkable, which an argument is not.

New-package runs, for completeness. With the pin unchanged the `--diff-filter=A` check over
`<old-pin>..<new-pin>` is empty by construction, so the whole-window form (`--since=2025-10-06`) from
the previous revision stands unchanged and is not re-derived here: it returned about two hundred
directories, roughly a hundred genuinely new packages, almost all of them `cmd/`, `k8s-operator`,
`gokrazy`, `tstest` and `feature/` surfaces already recorded as out of scope. The three worth the
question "does anything already swept now read from it" were `feature/captiveportal`,
`net/routecheck` and `net/traffic`, all three already carried as rows or as *no counterpart*
entries, and `net/porttrack` is a test helper nothing imports. The five packages recorded as new and
deliberately unswept stand: `net/connreject` and `feature/connreject` (`85c1efb46`),
`feature/androidbin` (`60d9c54b6`), `feature/dnsresolvecache` (`aa2681ac5`) and `feature/androiddns`
(`86b3cd5aa`). All five are documented under Package mapping as having no counterpart, and — per the
rule the fifth miss establishes — they stay out of the loop because the sweep exists to catch
behaviour a mapped crate already implements, not because anything else covers them.

`wgengine` was the lesson for the sweep list. **The lesson the previous revisions drew — that a
package being *in* the loop does not mean its commits have been *read* — stopped being a warning two
revisions ago and became rows; at this revision it acquired a sharper form.** The previous revision
found two rows from commits inside the window and inside a swept package that six revisions had read
past (`de733c595` removing `tailcfg.NetInfo.HairPinning`; `Node.InitDisplayNames`, which never
changed at all). This revision found seven from a package that was swept, whose commits were all
correctly assessed, and whose *contents* nobody had opened. **A swept package is not a read package,
and a read commit log is not a read package either.**

**And when the upstream delta is empty, that is not a signal to do less reading — it is the revision
where the reading is the whole job.** Budget for it, not just for the `git log`. Two revisions
running the pin has not moved at all, and the ledger gained eight rows and then nine.

Five techniques have paid. None of them produced this revision's one row, which came from auditing a
merged port against the Go it cites — the fourth source of change, below — and none of them could
have:

1. **Take a wire field this tree decodes and follow it forward.** A field modelled in
   `ts_control_serde` that reaches nothing. A `git grep` for the field name finds it and looks like
   evidence of a port. The question that separates the two is "what *reads* this", and it has a
   mechanical form: take every `pub` field in `ts_control_serde` and grep the workspace, excluding
   that crate, for its name. Seventy-two come back with no reader at this revision; most are
   `Hostinfo`/`NetInfo` reporting facets with nothing to report, and the residue is where the rows
   are. Re-run at this revision it produced no *new* row, which is itself worth recording: the vein
   was worked out by the previous two revisions.
2. **Take a function this ledger already claims parity for and read it top to bottom at the pin.**
   That is how earlier revisions found the reply-admission rows in `runIn4`, the `SrcCaps` callers,
   `select_home_region` and `handle_ping`; at this revision it produced the periodic-STUN row, where
   `stun_probe_should_run` ports one of Go's four stop conditions and documents that it ports one of
   four. **The best place to look is a divergence the code already admits to in a doc comment**, on
   the theory that if the author noticed it, it is real, and if it never reached this ledger, nobody
   has decided about it.
3. **Walk `tailcfg/nodecap` against this workspace** — and then ask the second question. The first
   question ("is this string in the tree?") is a grep and produced one row when it was added. The
   second ("does the behaviour it switches exist here to be switched?") is a judgement, cannot be
   automated, has to be asked once per miss, and produced seven. Forty of the misses are correct.
   The walk tells you where to ask; it does not answer.
4. **Check the wire types in both directions, mechanically** — outbound, each `ts_control_serde`
   field resolved to the wire name it serializes under and looked up in Go; inbound, the reverse over
   `tailcfg`'s json-tagged fields. It found `NetInfo.HairPinning` and `Node.ComputedName*` one
   revision ago. Re-run at this revision it returns exactly the one known phantom and nothing new;
   the command itself needed fixing first (above).
5. **Read the enumerations, not their history.** New at this revision and the highest-yield of the
   five so far: `controlknobs.Knobs` is twenty-seven fields, each a switch control can throw on this
   client, and `UpdateFromNodeAttributes` is the one function that fills them. Reading that file
   against this tree took minutes and opened eight rows. The generalisation is in the fourth-miss
   note above: a package whose purpose is to enumerate something owes you a read of the enumeration,
   and its commit log will never tell you that.

Two entries are noisy by nature and should be read with that in mind: `ipn` (which subsumes
`ipn/localapi` and `ipn/ipnlocal`) catches every multi-package commit that also touched
`cmd/tailscale`, most of which is the daemon CLI this library deliberately does not have, and
`tsnet` is swept but not itemised row-by-row in §B — see the note at the end of §B for why. One
mapping row has no upstream path to sweep at all: `golang.zx2c4.com/wireguard`'s device, which
`ts_tunnel` re-implements, is an upstream *dependency* rather than a package in this repository —
track it through upstream's `go.mod` bumps, not through this loop. It is the only admissible
exception; see the fifth miss above.

When the pin is advanced, bump the header table, re-run the above, and rewrite §A and §B. **And when
it cannot be advanced, because upstream's default branch is already what the header pins, re-run
everything anyway and rewrite §A and §B from what came back** — that happened at two revisions
running before the previous one and again at this one, and it is not a special case to be handled once: a pin catches up with upstream
whenever a re-derivation follows soon after the last one, and the value of the document at that
moment is entirely in the reading.

A row whose assessment changes should say *why* it changed — and note that "why" has **four**
sources, not three. The fourth was added at the previous revision, and at this one it is the only
source that produced anything.

1. **Upstream can move.** `29cfb0b4c` added capability version 147 at the previous revision; `85c1efb46`
   added 146 four revisions ago, `2ae2808b6` moved the index-eviction row before that, `e1d17a6b9`
   and `f53c28101` moved the disco-key rows before that, and `d9cc55e33` moved the
   `tsnet.Server.HTTPClient` row before that. It contributed nothing at three consecutive revisions,
   one row at the previous revision and nothing at this one, which is about its long-run rate.
2. **This tree can move, with upstream still**, and that is the dominant source by a wide margin.
   **Six §B rows closed at the previous revision** on tree movement alone (#438, #440, #442, #443, #445,
   #448) — the largest single-revision close in this ledger's history, and the first close of any
   kind in three revisions; none closed at this revision, where the tree moved by one documentation
   commit. Six closed two revisions before that (#415, #417, #418, #419, #421,
   #423), four before that (#404, #406, #408/#410, #412), six before that (#360, #363, #367, #369,
   #370, #372), three before that (#339, #342/#343/#345, #347), and three capability-version rows at
   the one before.
3. **The sweep itself can widen, or simply be read more carefully**, and surface something that was
   true all along. That is where all seventeen changes across the two previous revisions came from,
   and it remains the technique of last resort when the delta is thin.
4. **A port that landed here can turn out to be narrower than the upstream behaviour it copied.**
   Added at the previous revision, when **four of its five new rows** came from re-reading three merged
   ports against the Go tree they cited, which is what [`PARITY_AUDIT.json`](PARITY_AUDIT.json)
   records; at this revision it produced the **one** new row, from ports that record does not cover
   (see *Audited at this revision* in §B). None of the four is visible to the sweep, to the
   node-attribute walk, or to the wire-type checks — every one of those reports the attribute as
   *handled* and the behaviour as *present*, because it is. What is wrong is the decision logic
   underneath, and only reading the merged diff against upstream finds it. **So a revision that
   closes rows owes the next revision an audit of what it closed**, and closing six rows without one
   would have shipped a ledger claiming six clean ports where two were incomplete. The previous
   revision paid that debt for two of its six closures and not for the other four; this revision paid
   the rest, and one of those four was incomplete too.

One consequence worth stating for whoever advances the pin next: **a row this ledger closes is not a
row that stops needing evidence.** Every "already covered" and "closed at this revision" bullet above
names the tree code that covers it, because the next revision has to be able to re-check the claim
without re-deriving the whole document — and because a closed row can reopen if the code it names is
refactored away. The fourth source above sharpens that into something stronger than a filing
convention: a closed row can be *wrong on the day it closes*, and naming the code is what makes that
discoverable.

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
