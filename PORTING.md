# Porting ledger: upstream Go `tailscale` → this repository

| | |
| --- | --- |
| **Upstream source** | `https://github.com/tailscale/tailscale` (Go) |
| **Upstream commit this ledger was written against** | `a8b023c063b608fcead5446f3d885c4fc847c944` (2026-09-08, `cmd/k8s-operator,k8s-operator: make PeerRelay port and endpoints configurable`) |
| **Upstream `tailcfg.CurrentCapabilityVersion` at that commit** | **145** (2026-08-04) — unchanged from the previous four pins |
| **This repository at ledger time** | `27c9a87` — workspace version `0.48.0` |
| **`ts_capabilityversion::CapabilityVersion::CURRENT` here** | **125** (2025-08-11) — held below 126; see §B, *c2n endpoints behind the declared capability version* |
| **Gap window this ledger covers** | capability version **131 → 145**, i.e. upstream commits from 2025-10-06 to 2026-09-08 (the window is anchored to when capver 130 landed upstream; the declaration here being 125 rather than 130 does not change what upstream added) |
| **Previous pin** | `9ea7cba44591e0cd840c6c94d23274dd222059bf` (2026-08-31). Eleven upstream commits separate the two, six of them in mapped packages — the smallest upstream delta any revision of this ledger has covered. **This tree is again where the movement was**, and by a wider margin than last time: thirty-nine commits landed here since `610c596`, closing six §B rows outright and half of a seventh. See §B, *What changed at this revision* |

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
- `feature/androiddns` — DNS through Android's system `dnsproxyd` cache, for binaries with no
  `/etc/resolv.conf` and no bionic libc. Added upstream at `86b3cd5aa`, after the previous pin.
  `ts_host_net` has Linux and macOS backends only.
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
window is the same fifteen versions the previous three revisions covered. Descriptions are
upstream's own (`tailcfg/tailcfg.go`, `tailcfg/nodecap`).

**No row changed assessment at this revision, for the fourth revision running, and for the same
one-sided reason as last time.** Upstream added no capability version between `9ea7cba44` and
`a8b023c06`; the sixteen-row comment block in `tailcfg/tailcfg.go` is byte-identical, and with only
eleven upstream commits in the interval that is unsurprising. This tree, by contrast, moved further
than at any previous revision: thirty-nine commits since `610c596`, six of which closed §B rows
outright. None of them touched a capability-version row — the work that landed here was on the
*non*-capver axis, and §B is where it shows up. The one row that could have moved is 133, and the
tree evidence for it is re-stated under the table below.
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
promises it). That is the same count the previous three revisions reached. Row 133 was re-checked
against the tree at this pin and is still open: `ts_host_net::HostDns::nameservers`
([`ts_host_net/src/lib.rs`](ts_host_net/src/lib.rs)) is still a `Vec<Ipv4Addr>`, its doc comment
still says "IPv4 nameservers only", and `ts_runtime::tun_actor` still fills it with the single IPv4
service IP, so there is still no IPv6 MagicDNS address to register. Nothing in this revision's
thirty-nine tree commits touched it: the DNS work that landed (#367, #380, #387, #395, #397) is all
about what an answer *contains* and how big it may be, not about which addresses the responder is
reachable on. Note too that the row is *not* closed by #347 (the quad-100 absorption fix in §B):
that made the TUN transport absorb every quad-100 packet whatever its port and protocol, which is
about traffic already addressed to `100.100.100.100` — it neither serves nor registers the IPv6
service IP, which is what 133 asks for.

### B. Behaviour upstream changed in the window that is not capver-gated

Derived from `git log --since=2025-10-06` over the packages that map to crates here, with
docs/typo/refactor commits filtered out. The sweep list is unchanged at this revision: it was
rebuilt from [Package mapping](#package-mapping) two revisions ago, checked against the mapping
again here, and the one package upstream added in the interval (`feature/androiddns`) has no
counterpart and is recorded in the *no counterpart here* list rather than swept.

#### What changed at this revision

Read this first: it is the shortest honest summary of the diff between this ledger revision and the
last one.

- **Six rows closed outright, and half of a seventh, because this tree moved.** The three disco-key
  rows the previous revision opened are all **already covered** now — ingress under a peer's other
  known key (#372), an active TSMP key surviving control changing its mind (#370), and the trusted
  direct path being invalidated on a key change (#369). So are the SOA on negative MagicDNS answers
  (#367), the drop of host-injected TSMP (#360), and the checkpoint-based TKA sync offer (#363).
  The `UnsignedPeerAPIOnly` row is the half: #365 landed the route clamp, and the capability half is
  still open. Each row says so inline below.
- **One row opened because upstream moved.** Eleven commits separate `9ea7cba44` from
  `a8b023c06` — the smallest interval this ledger has covered — and six of them touched mapped
  packages. Exactly one of the six opens a row: `2ae2808b6`, the conditional index eviction, which
  this tree needs in the half of the code that does not have it. Of the other five, two are already
  covered here (one by a *stronger* rule than upstream's, one by construction) and three are not
  applicable. All five are itemised under *Not applicable, or already covered, from the commits new
  at this pin* so the next re-derivation does not re-read them.
- **Three rows opened because the sweep was read more carefully.** `0b4c0f208` and `6a19995f1`
  landed upstream well before the previous pin, in `net/dns/resolver` and `tailcfg` — two packages
  that have been in the loop since the ledger existed. The peer-expiry row is the same shape from
  the other direction: `0640312e5` *is* new at this pin and is itself not applicable, but reading it
  meant reading `ipn/ipnlocal/expiry.go`, and that whole subsystem turns out to have no counterpart
  here. This is the failure mode the previous revision named and the one before that hit first: a
  package being swept is not the same as its commits being read. Each of the three is named below
  with the tree evidence that shows the gap is real.
- **No row changed because of a divergence decision being revisited.** The three deliberate
  divergences recorded at the previous revisions (DNS-after-router-failure, SSH `acceptEnv`, the
  `callMeMaybe` gate) were re-checked and stand.

#### Rows

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
  (`ipn/ipnlocal/node_backend.go`: `2ae2808b6`) — **needs port**, and it is the sharpest new row at
  this pin.
  Upstream's `nodeBackend` used to evict its index entries (`nodeByAddr`, `nodeByKey`,
  `nodeByWGString`, `nodeByStableID`, `nodeByName`) from a node's last-known value without checking
  that the entry still pointed at that node. Control can reassign a churning ephemeral peer's
  Tailscale IP or MagicDNS name to a newer peer and deliver the new peer's upsert *before* the old
  peer's removal — in an earlier `MapResponse`, or reordered within one batch by the NodeID sort in
  `netmap.MutationsFromMapResponse` — and the removal then wiped the new owner's entry. The peer map
  itself stayed correct in every ordering, so WireGuard kept the peer and handshakes succeeded, but
  `WhoIs` by IP failed until the next full netmap; on app connectors that surfaced as
  "peerapi: unknown peer" with a full restart as the only recovery. The fix makes every eviction
  conditional through a `deleteIfOwned` helper.
  Half of this tree already does that and says so. `PeerDb::upsert` guards its retractions from
  `disco_idx`, `name_idx`, `ip_idx` and `route_idx` — "only retract a mapping that is still ours;
  never clobber another peer's" — because an unguarded version used to `assert!` and panic the actor
  under concurrent joins. **`IndexState::remove`, the *removal* path, does not.** It calls
  `nk_idx.remove`, `stableid_idx.remove`, `control_idx.remove`, `ip_idx.remove` for both tailnet
  addresses, and `disco_idx.remove` unconditionally; only the hostname half of `name_idx` and the
  inactive disco key are guarded, and the comment on the guarded one — "for the same reason as every
  other index above" — describes indexes that are not in fact guarded. The exposure is not
  theoretical: `PeerTracker::apply_peer_update` applies a `Delta`'s **upserts first and its removals
  second**, unconditionally, so the intra-batch ordering upstream had to defend against is the
  ordering this tree always uses. A peer that inherits a departing peer's tailnet IP is installed in
  `ip_idx`, and the departing peer's removal then evicts it — after which
  `PeerTracker::peer_by_tailnet_ip`, the `whois` built on it, and every peerAPI source check that
  resolves through it fail for a peer that is present and handshaking. The disco index has the same shape, and there `disco_idx` losing an entry costs the
  new peer its direct path.

- **Expired peers are neither flagged nor re-evaluated when their keys expire**
  (`ipn/ipnlocal/expiry.go`, `ipn/ipnlocal/local.go`: `0640312e5`, and the `expiryManager` the
  commit repairs) — **needs port**, and it is wider than the commit that surfaced it.
  Upstream keeps an `expiryManager` that does three things this tree does none of. It marks peers
  expired: `flagExpiredPeers` walks the netmap, sets `Expired` on every peer whose `KeyExpiry` has
  passed, clears their `Endpoints` and `HomeDERP`, and *breaks their node key* with
  `key.NodePublicWithBadOldPrefix` as defence in depth against control handing us a live-looking
  expired node. It re-evaluates on time rather than only on netmap arrival: `nextPeerExpiry` finds
  the soonest future expiry across peers and self, and `setControlClientStatusLocked` arms a timer
  for it — which is the timer `0640312e5` fixes, by refreshing the captured netmap from live peer
  state before reinstalling it so a delta that arrived meanwhile is not rolled back. And it corrects
  for clock skew: `onControlTime` stores the delta between local time and `MapResponse.ControlTime`,
  every expiry comparison is made against the adjusted time, and a delta-adjusted "now" before a
  hardcoded epoch is ignored outright, so a control server (or a Headscale) sending a wildly past
  `ControlTime` cannot expire the whole tailnet.
  Here, expiry is modelled and then never enforced for peers. `ts_control::Node::key_expired` and
  `key_expired_at_unix` exist and are correct, but the only caller is the **self**-node path in
  `ts_runtime::control_runner` (the reauth decision) and `Device::self_key_expired`. No peer is ever
  flagged, `ts_runtime::status::StatusNode` has no `expired` field for a watcher to read, nothing
  re-examines expiry between netmaps, and `ts_control_serde::MapResponse::control_time` is parsed
  off the wire and has no consumer at all — so there is no clock-delta correction either. The
  visible consequences are ordinary: this node keeps a fully-configured WireGuard peer for a node
  whose key control has expired, keeps its endpoints and DERP home, keeps dialling it, and keeps
  accepting its peerAPI connections, where Go refuses with "peer's node key has expired". The
  smallest useful slice is the flagging plus the status field; the timer and the clock delta are
  what make it correct rather than approximate.

- **A REFUSED or SERVFAIL from the first upstream ends the forward**
  (`net/dns/resolver/forwarder.go`: `0b4c0f208`) — **needs port**, host-facing.
  Upstream treats both response codes as *soft* errors while a query is outstanding against more
  than one upstream: a broken resolver answering REFUSED quickly must not beat a healthy resolver
  that is still working, so the race continues, and only if every resolver refuses is the first
  REFUSED returned to the client. SERVFAIL had always been soft; the same commit additionally
  returns an upstream's *own* SERVFAIL bytes verbatim rather than replacing them with a locally
  synthesized packet, because the upstream's answer may carry RFC 8914 extended DNS error
  information that a synthesized one throws away.
  `ts_runtime::magic_dns::forward_query` tries its upstreams **in order** and returns
  `cap_response(...)` on the first datagram that comes from the address it queried and matches the
  query's transaction id — whatever RCODE it carries. So a first upstream that refuses ends the
  forward, the remaining upstreams are never tried, and the stub resolver is handed the refusal.
  This bites hardest exactly where a split-DNS route or a fallback list names more than one
  resolver, which is the common configuration control pushes. The port is small and self-contained —
  keep going on REFUSED and SERVFAIL, remember the first such response, and return it only when the
  list is exhausted — and the negative cases worth pinning are that a lone refusing upstream still
  gets its answer relayed (not converted to the synthesized SERVFAIL fallback), and that the
  anti-poisoning source/txid check still refuses a mismatched datagram before any of this.

- **`UserProfile.Groups` is not modelled** (`tailcfg`: `6a19995f1`) — **needs port**, narrow.
  Upstream reintroduced `UserProfile.Groups`, "a subset of SCIM groups (e.g.
  `engineering@example.com`) or group names in the tailnet policy document (e.g. `group:eng`) that
  contain this user and that the coordination server was configured to report to this node", carried
  in `MapResponse.UserProfiles` and surfaced through `WhoIs`. `ts_control_serde::UserProfile` models
  `ID`, `LoginName`, `DisplayName` and `ProfilePicURL` and stops there, so the field is discarded at
  the wire boundary and `ts_runtime::status::WhoIs` — whose `user` is a single display label joined
  out of the accumulated profile table — cannot offer it. That matters for an *embedded* node more
  than for the daemon: an embedder authorising an inbound tailnet connection from `Runtime::whois`
  has no way to ask which groups the caller belongs to, and has to re-derive it out of band. The
  decision to make is how far up to carry it: the wire field and `ts_control::UserProfile` are
  mechanical, but `WhoIs` currently flattens a profile to one string, so exposing groups means
  widening that type.

- **IPv6 fragment extension-header handling in the filter** (`net/packet`, `wgengine/filter`:
  `4c4ec3d46`, `26b2ed0a6`) — **already covered**, unchanged at this revision. #342 gave
  `ts_dataplane` the IPv6 half of the RFC 1858-style classification it had only for IPv4, #343
  extended it to a Fragment header hidden behind a chained extension header, and #345 rewrote the
  tests so each extension header has its own control and its drop cannot pass vacuously. #398 added
  one more pin at this revision (the pre-rule drop of a proto-0 first IPv6 fragment), and #390
  stopped a prepended IPv6 header choosing which rule matches.

- **Quad-100 traffic is absorbed locally regardless of port and protocol** (`wgengine/netstack`:
  `1b4091161`) — **already covered**, unchanged at this revision. `ts_runtime::tun_actor::classify_service_ip`
  returns `ServiceIpPacket::Absorbed` for **every** packet destined to `100.100.100.100` that is not
  the UDP/53 query it serves, and an unserved quad-100 TCP port is answered with a RST built by
  `build_tcp_reset` (RFC 9293 §3.10.7 CLOSED-state rules) rather than dropped into a retransmit
  loop — upstream's `hittingServiceIP` case in `acceptTCP`.

- **The DNS forwarder sets TC against the *client's* size limit** (`net/dns/resolver`:
  `8cac8b117`) — **already covered**, and refined four times more at this revision. #339 added
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
  DERP. Direct paths still take priority over relay ones. #400 hardened it here at this revision: a
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
  again at this revision. Upstream added no wire field: both are *derived predicates* — "does this
  node route addresses besides its own" — spelled as methods so IPN-bus watchers can classify
  routers out of the netmap they already hold. Mirrored here as `ts_control::Node::is_router` (over
  `accepted_routes` vs `addresses`) and `ts_runtime::status::StatusNode::is_router` (over
  `allowed_routes` vs `ipv4`/`ipv6`), cross-checked against each other the way upstream's
  `TestNodeIsRouter` cross-checks its two definitions. #337 fixed the domain predicate (it tested each
  accepted route against the *identity* projection — the first prefix of each family — rather than
  against control's whole `Node.Addresses` list), #340 fixed two test fixtures added alongside it,
  and **#402 at this revision fixed the same narrowing where it had survived**: the status
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

Recorded so the next re-derivation does not re-read them. Eleven upstream commits landed between
`9ea7cba44` and `a8b023c06`. Six touched mapped packages; `2ae2808b6` is the one that opens a row
and is written up above, and these are the other five.

- **`control/controlclient`: replay user profiles on delta peer upserts** (`5201273ae`) — **already
  covered, by a stronger rule.** Upstream's bug needs two things to be true: a full netmap carries
  only the profiles of users with a currently visible peer, and `nodeBackend` replaces its live
  profile set *wholesale* on every full netmap install. A user whose peers are all invisible at that
  moment therefore loses their profile downstream, and control (mapver 5+) does not resend unchanged
  profiles when a peer of theirs later returns as a delta upsert — so `WhoIs` fails one step after
  the peer is admitted. The fix replays the profiles of upserted peers' users and sharers from
  `mapSession.lastUserProfile`. Neither precondition exists here. `PeerTracker`'s `user_profiles` map
  **accumulates and is never replaced or pruned** — the field's own doc comment says why ("a peer
  upserted in one response may reference a profile delivered in an earlier one") — and the
  accumulation happens ahead of the no-peer-update early return, so a response carrying profiles and
  no peer delta still lands them. There is no netmap install that could drop a profile, so there is
  nothing to replay.
- **`wgengine/magicsock`: fix logging for changing disco keys** (`33cc45a32`) — **already covered by
  construction.** Two halves. The log-label half (a control-sourced update was logged as coming from
  TSMP) has no analogue: nothing here decides anything from a log string, and the invalidation this
  tree performs is driven by diffing the *effective* key across peer snapshots. The behavioural half
  is an early return when there is no existing disco state and the incoming key is zero, which
  otherwise allocated a new empty state, compare-and-swapped it in and reported "changed" — a
  spurious key-change transition for a peer that has never had a disco key.
  `PeerTracker::upsert_from_control` cannot reach that state: it writes through
  `EndpointDisco::update_from_control` **only when control's key actually differs from what control
  last said**, and an entry left with no key material in either slot is dropped
  (`EndpointDisco::is_empty`), exactly as Go nils the endpoint's `disco` pointer.
- **`wgengine`: per-peer WireGuard PSKs** (`31d8badb3`) — **not applicable.** The commit replaces the
  allowed-IPs-only peer callback result with a `wgcfg.PeerConfig` carrying allowed IPs *and* an
  optional pre-shared key, and bumps `wireguard-go` for the new peer PSK APIs. It is plumbing for an
  out-of-tree consumer: at this pin the only construction site in `tailscale.com` is
  `LocalBackend.peerConfig`, which sets `AllowedIPs` and leaves `PresharedKey` at its zero value,
  and nothing in `tailcfg` carries a PSK. So no Go peer this node meets negotiates a non-zero PSK,
  and there is no wire behaviour to match. Worth re-reading if control ever gains a PSK field.
- **`all`: ~128 KiB packet buffers for batched I/O** (`8fc6dca15`) — **not applicable.** A
  memory-model change following `wireguard-go`'s new `tun.Device.Read` and `conn.ReceiveFunc`
  interfaces, touching `net/batching`, `net/tstun`, `wgengine/magicsock` and `wgengine/netstack`. It
  changes throughput and peak RSS, not what a peer observes; the `net/tstun/wrap.go` hunks are buffer
  plumbing with no filter-verdict change. This datapath has no batched I/O to convert — but note the
  fork's own memory story is in [`AGENTS.md`](AGENTS.md) under `tcp_buffer_size`, and it is a
  different lever from this one.
- **`ipn/ipnlocal`: preserve peer deltas on expiry** (`0640312e5`) — the commit itself is **not
  applicable**: it refreshes the netmap captured when the expiry timer was armed from live peer
  state before reinstalling it, so a delta that arrived meanwhile is not rolled back. There is no
  captured-netmap reinstall here to roll anything back. Reading it is what opened the peer-expiry
  row above, because the machinery it repairs is machinery this tree does not have at all. See
  *Expired peers are neither flagged nor re-evaluated when their keys expire*.

Of the remaining five, one is a package upstream added in the interval:

- **`feature/androiddns`: DNS via Android's `dnsproxyd`** (`86b3cd5aa`) — **not applicable.** It
  resolves names through Android's system DNS cache for binaries that have no `/etc/resolv.conf` and
  no bionic libc. There is no Android backend in `ts_host_net`; the package is recorded in the *no
  counterpart here* list rather than added to the sweep, because the sweep exists to catch
  behaviour a mapped crate already implements.

The last four are outside the mapped set and are not itemised: `a8b023c06` and `63d1eedf2`
(`cmd/k8s-operator`, the operator surface this library is not), `b82b06c8a` (`cmd/tsconnect`), and
`b62350fbe` (a CI workflow note).

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
(`feature/conn25`, likewise), the `fuzz:` and `go.toolchain.rev` housekeeping, and `9ea7cba44`, the
previous pin, which is a licence-notice regeneration. The new pin `a8b023c06` is likewise only what
HEAD was when this revision was derived — it is a `cmd/k8s-operator` change and touches nothing
mapped.
`tsnet` has over a hundred commits in the window and is **not** re-derived here: that facade has its
own line-by-line parity matrix in [`docs/TSNET_PARITY.md`](docs/TSNET_PARITY.md), and duplicating it
into this ledger would create two records that disagree. Only `tsnet` changes that alter behaviour a
mapped crate already implements are pulled in, as `49e148c4a` and `d9cc55e33` were above.

### Re-deriving this ledger

```sh
# The capability-version window (§A): everything above CapabilityVersion::CURRENT here.
git -C <tailscale-go> grep -n 'CurrentCapabilityVersion CapabilityVersion' a8b023c06 -- tailcfg/tailcfg.go
git -C <tailscale-go> grep -nE '^//[[:space:]]*-[[:space:]]*1[3-9][0-9]:' a8b023c06 -- tailcfg/tailcfg.go

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
git -C <tailscale-go> log --oneline a8b023c06..<new-pin>

# And the mirror image of that, which has now been the larger half of the diff twice running: what
# moved *here* since the tree revision the header table names. Six §B rows closed at this revision
# for this reason alone, with upstream almost perfectly still.
git log --oneline 27c9a87..HEAD
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
again at this revision against the mapping and is complete. Upstream added one package in the
interval, `feature/androiddns` (`86b3cd5aa`); it is documented under Package mapping as having no
counterpart and is deliberately *not* swept, because the sweep exists to catch behaviour a mapped
crate already implements and there is no Android backend in `ts_host_net` for it to diverge from.
`sessionrecording` likewise needs no loop entry of its own, because the client half lives behind
`ssh/tailssh`'s calling code, which is swept.

`wgengine` was the lesson for the sweep list. **The lesson the previous revision drew — that a
package being *in* the loop does not mean its commits have been *read* — held again here, and this
revision is the clearest case yet.** Upstream moved eleven commits in the interval; the ledger still
gained four rows, and three of them came out of commits that had been sitting in swept packages the
whole time (`0b4c0f208` in `net/dns/resolver`, `6a19995f1` in `tailcfg`, and `ipn/ipnlocal/expiry.go`
as a subsystem rather than a commit). The previous revision found four the same way, and the
quad-100 row before that was the same failure in its first form. **When the upstream delta is small,
that is not a signal to do less reading — it is the revision where the reading is the whole job.**
Budget for it, not just for the `git log`.

Two entries are noisy by nature and should be read with that in mind: `ipn` (which subsumes
`ipn/localapi` and `ipn/ipnlocal`) catches every multi-package commit that also touched
`cmd/tailscale`, most of which is the daemon CLI this library deliberately does not have, and
`tsnet` is swept but not itemised row-by-row in §B — see the note at the end of §B for why. One
mapping row has no upstream path to sweep at all: `golang.zx2c4.com/wireguard`'s device, which
`ts_tunnel` re-implements, is an upstream *dependency* rather than a package in this repository —
track it through upstream's `go.mod` bumps, not through this loop.

When the pin is advanced, bump the header table, re-run the above, and rewrite §A and §B. A row
whose assessment changes should say *why* it changed — and note that "why" has three sources, not
one, and that all three have now happened more than once. Upstream can move (as `2ae2808b6` moved
the index-eviction row at this revision, `e1d17a6b9` and `f53c28101` moved the disco-key rows at the
previous one, and `d9cc55e33` moved the `tsnet.Server.HTTPClient` row before that). This tree can
move, with upstream nearly still — which is now the dominant source: six §B rows closed at this
revision on tree movement alone (#360, #363, #367, #369, #370, #372), three at the previous one
(#339, #342/#343/#345, #347), and three capability-version rows at the one before. Or the **sweep
itself** can widen, or simply be read more carefully, and surface something that was true all along.

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
