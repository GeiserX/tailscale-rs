# tsnet Parity Roadmap

> **Goal:** a complete pure-Rust port of Go `tsnet`. This document is the durable plan; live
> status is tracked in beads (`bd list`, prefix `tsr`).

## Gap audit and open backlog at wind-down (2026-10-14)

The automated factory that opened most pull requests in this repository stopped on 2026-10-14. This
section is the one place that says what is still missing against Go, which older parity claims were
wrong, where the open work is, and how to pick it up again. The rest of this document is history. Where
an older sentence in this repository's docs contradicted the tree, it was corrected in place in the same
change that added this section.

**What was compared.** This repository at `f311bba` against Go `tailscale` v1.102.4 (`bbcd7d1f`). Rust
paths are relative to this repository, Go paths to the Go tree at that tag. The comparison was read-only:
nothing was built or run, so a row marked "not run" is read from the code, not observed.

**Severity words used below.**

- **blocks-parity**: a peer, a control plane or an embedder sees behaviour that differs from Go in a way
  that breaks a real use.
- **minor**: an observable difference that does not break the common path.
- **product-decision**: a deliberate or arguable divergence that needs a decision, not a port.

Rows keep the number they were given in their area (C for control, M for the underlay, N for the data
plane, R for the runtime facade), so a bead or a commit can cite one.

### Area verdicts

- **Control plane.** Complete for the path a plain node walks on an unlocked tailnet. Every
  `RegisterRequest` and `RegisterResponse` field exists (`ts_control_serde/src/register.rs:64-170`). The
  Noise handshake, the 4096-byte frame limit, zstd map polling, map-session resumption, the 120 s read
  watchdog, logout, interactive login and node-key rotation are ported
  (`ts_control_noise/src/handshake.rs:127`, `ts_control_noise/src/codec.rs:11`,
  `ts_control/src/tokio/map_stream.rs:228`). Tailnet Lock verification enforces, including the rotation
  tracker (`ts_runtime/src/peer_tracker/mod.rs:421-453`, `:510`). The biggest gap is the node's own
  signature on a locked tailnet. The node never sends `NodeKeySignature` when it registers, cannot use a
  pre-signed auth key, and does not re-sign after a key rotation (rows C1 to C3). On a locked tailnet
  that blocks joining and drops the node at every rotation. On an unlocked tailnet nothing here blocks
  real use. The declared capability version stays at 125 against Go's 142, on purpose
  (`ts_capabilityversion/src/lib.rs:320-384`).
- **Underlay (magicsock, disco, DERP, netcheck, netmon).** The core works and is mostly faithful: disco
  ping, pong and CallMeMaybe, trust windows, active STUN, the hard-NAT port guess, home-DERP hysteresis,
  the 60 s idle-out for non-home DERP, silent disco and the DERP-borne ping answer. The biggest gap is
  cadence. The node probes every peer in the netmap forever and sends CallMeMaybe over DERP every 5 s to
  every peer without a direct path, where Go probes only while traffic flows and stops 45 s after the
  last send (rows M1, M2). The second is DERP liveness. The DERP client has no read deadline and the home
  connection is never idled out, so a silently dead home DERP is never noticed (row M3). Link-change
  recovery is absent in the default build: the monitor is off by default (`src/config.rs:719`) and, when
  on, runs a backend that never emits an event (`ts_runtime/src/lib.rs:426-433`). None of this breaks a
  small tailnet with public-IP peers. M3 and the missing link monitor do threaten long-lived nodes that
  roam or sit behind a NAT that rebinds.
- **Data plane (netstack, forwarder, packet filter).** The packet filter is close to complete: pre-rule
  drops, IPv4 and IPv6 fragments, the flow cache for TCP non-SYN, ICMP responses and UDP, portless
  matching and shields-up (`ts_dataplane/src/lib.rs:35`, `:122-215`, `:608`, `:641`, `:665`;
  `ts_dataplane/src/flowtrack.rs:35`). The netstack and forwarder are the weaker half. A forwarded TCP
  connection to a dead backend looks accepted and then closes, where Go answers with a reset (row N1).
  smoltcp ran with no congestion control, where Go runs Reno (row N2, now fixed). In TUN mode with an exit node,
  nothing stops the node routing its own WireGuard and DERP traffic into the tunnel (row N3, not run).
  Netstack mode is the default and is not affected by N3. Go's Linux router features (SNAT, netfilter
  chains, IP forwarding) do not apply: forwarding here is in user space (`ts_forwarder/src/lib.rs:1-7`).
- **Runtime facade and node services.** The facade is more complete than the older docs said. The
  `tsnet::Server` facade (`src/tsnet.rs:576`) has a pluggable state store, a second loopback credential,
  an in-process LocalAPI client and a netmap cache. Per-peer online state and WhoIs user profiles are
  kept. Status, WhoIs, Taildrop, the Funnel client leg, capture and exit-node suggestion all work. The
  biggest gap blocks real use: every TLS listener holds the one certificate it got at start and nothing
  renews it, so a long-running service serves an expired certificate after about 90 days (row R1). Next
  come three gaps that hurt anyone hosting HTTP behind Serve or Services. The Serve proxy neither sets
  nor strips Go's `Tailscale-User-*` headers (R2). WhoIs cannot map a proxied loopback connection back to
  the tailnet caller (R3). `listen_service` does not advertise the service at runtime (R4).

### Control plane gaps

| Row | Go v1.102.4 behaviour (file:line) | Rust at f311bba (file:line, or "not found" and the grep) | Severity | Note |
|---|---|---|---|---|
| C1 | Decodes a wrapped pre-signed auth key (`tskey-…--TL<sig>-<priv>`), strips the suffix and signs the new node key with it (`control/controlclient/direct.go:672`, `:768-772`; `tka/sig.go:442`, `:467`) | Not found: `grep -rn -i 'wrapped\|--TL\|sign_by_credential' ts_control ts_runtime ts_tka ts_keys src` has no hit in the auth path. The whole string is sent as `AuthKey` (`ts_control/src/tokio/register.rs:221`) | blocks-parity | Locked tailnets only. The suffix reaches control as part of the key. No bead. |
| C2 | On re-register after rotation, re-signs the new node key with the network-lock key and sends it as `NodeKeySignature` (`direct.go:764-767`, `:797`; `tka/sig.go:360`) | Not found: `node_key_signature` is never set in the request builder (`register.rs:176-226`). `ts_tka` only verifies rotation chains (`ts_tka/src/lib.rs:309`) | blocks-parity | Locked tailnets only. After a reauth rotation (`ts_control/src/tokio/client.rs:621-622`) the node stays unsigned until a signer re-signs it. No bead. |
| C3 | A `NodeKeySignature` in the register response triggers a retry carrying it as `OldNodeKeySignature` (`direct.go:576-582`, `:886-888`) | Not found: `grep -rn '\.node_key_signature' ts_control ts_runtime src`, excluding `ts_control_serde`, is empty. `classify_register_response` reads only `machine_authorized`, `auth_url` and `error` (`register.rs:131-145`) | blocks-parity | Same lock-only scope as C1 and C2. No bead. |
| C6 | Lock disable fetches the bootstrap, checks `ValidDisablement(secret)` and stays locked when the secret is wrong (`ipn/ipnlocal/tailnet-lock.go:380-405`, `:509-519`) | Disable clears enforcement as soon as control reports it, with no bootstrap fetch (`ts_runtime/src/control_runner.rs:461-485`). `ts_tka` has the KDF (`ts_tka/src/lib.rs:107`) but no check: `grep -n 'fn [a-z_]*disablement' ts_tka/src/lib.rs` finds only `disablement_value` | blocks-parity | Already listed as deferred below. Listed here because it is the control-trust hole in the lock. |
| C4 | `NodeKeyExpired` in the register response regenerates the key and retries (`direct.go:890-897`) | Not found: the same grep for `node_key_expired` is empty | minor | Rotation happens only from the netmap self-expiry path (`client.rs:621-622`). A register-time expiry falls through to `MachineNotAuthorized(None)` (`register.rs:144`). |
| C5 | Sends the current lock head in every MapRequest (`TKAHead`, `direct.go:1139`; set from `local.go:1990`) | Not found: `tka_head` appears only in the serde struct (`ts_control_serde/src/netmap.rs:114`) | minor | Control cannot see which lock head the node holds. |
| C7 | `UnsignedPeerAPIOnly` peers are admitted unsigned under a lock (`tailnet-lock.go:194`) and limited to peerAPI in the filter (`local.go:3495-3504`) | The field is ingested and routes are clamped (`ts_control/src/node.rs:253`, `:1134-1146`). The lock check still drops every unsigned peer (`ts_runtime/src/peer_tracker/mod.rs:389-394`) | minor | Documented. Now a live gap, because the node model carries the field. |
| C9 | `Debug` in MapResponse is acted on: `Exit`, `DisableLogTail`, `SleepSeconds` (`control/controlclient/map.go:241`; `direct.go:1429-1442`) | Parsed (`ts_control_serde/src/debug.rs:20-29`; `netmap.rs:473`), never read: `grep -rn 'sleep_seconds\|disable_log_tail\|map_response\.debug' ts_control/src ts_runtime/src src` is empty | minor | `SleepSeconds` is control's backpressure lever. Exit and log-tail are product decisions. |
| C10 | `Health` and `DisplayMessages` are kept, with `"*": null` meaning clear-all, and published on the netmap (`map.go:757-771`, `:1270-1297`) | Parsed (`netmap.rs:428`, `:444`), never read: the same grep for `display_messages\|\.health\b` finds only an unrelated status key (`src/tsnet.rs:1383`) | minor | Warnings pushed by control never reach the embedder. The only health warning raised is the packet-filter one (`ts_runtime/src/packetfilter.rs:69`). |
| C12 | Duplicate `PingRequest` URLs are dropped (`isUniquePingRequest`, `direct.go:1330`, `:1599-1611`) | Not found: `grep -rn -i 'last_ping\|unique_ping' ts_control/src ts_runtime/src` is empty. Each frame's ping is answered (`map_stream.rs:459`; `ping.rs:314`) | minor | The Rust doc comment says it should dedupe (`ts_control_serde/src/ping.rs:46`). The code does not. |
| C13 | Empty `Types` means a HEAD ping to the URL. `disco`, `TSMP`, `ICMP` and `peerapi` run a pinger and report back (`direct.go:1633-1656`) | Only `c2n` is answered. Every other type is logged and skipped, and an empty `Types` gives an empty list, so nothing is done (`ping.rs:319-323`; `util.rs:40-41`) | minor | Control's liveness and peer-ping probes go unanswered. |
| C14 | An unknown ping type string is logged and ignored (`direct.go:1654-1655`) | `PingType` is a closed serde enum with no `#[serde(other)]` (`ts_control_serde/src/ping.rs:11-30`), so an unknown type fails the whole `MapResponse` decode, and a failed decode ends the stream (`ts_control/src/tokio/map_stream.rs:364`, `:384-391`) | minor | Read from the serde shape, not observed. One new type from control would make the poll loop reconnect. |
| C15 | The C2N reply is POSTed to `pr.URL` as given (`feature/c2n/c2n.go:54`) | POSTs to `control_url.join(url.path())`, which drops any query string (`ping.rs:342`) | minor | Read only. Whether control ever puts a query on this URL was not checked. |
| C16 | controlknobs reads 27 node attributes (`control/controlknobs/controlknobs.go:147-199`) | These have no Rust consumer: `randomize-client-port`, `probe-udp-lifetime`, `disable-split-dns-when-no-custom-resolvers`, `peer-mtu-enable`, `user-dial-routes`, `disable-captive-portal-detection`, `force-register-magicdns-ipv4-only`, `disable-skip-status-queue`, `emit-runtime-metrics`. Each was grepped as a quoted string over `ts_*` and `src` with zero hits | minor | The other unconsumed knobs are host-OS ones (`disable-*-gro/gso`, NRPT, hosts file, iptables/nftables, `debug-disable-upnp`, `store-appc-routes`), a product decision for a user-space node. |
| C17 | Legacy self-node `Capabilities` are folded into `CapMap` (`map.go:302`, `:634`) | `capabilities` is parsed (`ts_control_serde/src/node.rs:195`) but the domain node builds from `cap_map` only (`ts_control/src/node.rs:1079`) | minor | Matters only for a control plane that still sends the old list. |
| C18 | Hostinfo carries `ExitNodeID` from the selected exit node (`local.go:6715`, `:7219-7220`). This is capability version 122, which a declaration of 125 asserts | Not found: `grep -rn 'exit_node_id:' ts_control/src ts_runtime/src src` is empty. `MapRequestBuilder` has no exit-node setter (`map_request_builder.rs:53-247`) | minor | A real overclaim of capability version 122. `set_exit_node` exists, so the data is there. |
| C19 | Hostinfo `SSH_HostKeys` is filled when the SSH server runs, and `RemoteConfig`, `ShieldsUp`, `NoLogsNoSupport`, `BackendLogID` and `FrontendLogID` are sent (`tailcfg/tailcfg.go:868`, `:897`, `:907`) | `ssh_host_keys` is only ever `vec![]` (`src/lib.rs:2205`). `RemoteConfig` is absent from the serde struct (`ts_control_serde/src/host_info.rs`). The others are never set | minor | SSH host keys matter: this node serves SSH, so peers' `tailscale ssh` known-hosts get nothing from control. The others are product decisions. |
| C22 | Dials plaintext port 80 first and races 443 after a delay (`controlhttp/client.go:290-303`). Honours an HTTP proxy from the environment (`client.go:80-84`) | One dial on the URL's scheme port (`ts_control/src/control_dialer.rs:207-221`). No proxy: `ts_http_util` connects "straight to the origin server" (`ts_http_util/src/client.rs:17`) | minor | Works against controlplane.tailscale.com. Fails behind an egress HTTP proxy and differs on networks that interfere with TLS. |
| C23 | ACE (CONNECT-proxy) dial-plan candidates are dialed (`controlhttp/client.go:123-131`, `:397`, `:427`) | Parsed (`ts_control/src/dial_plan.rs:90-94`), then skipped (`control_dialer.rs:97-101`, `:165`) | minor | Recorded in code only until now. |
| C24 | Seamless key renewal (capability version 126), plus C2N `/debug/netmap`, `/debug/health` and `/debug/tka/log` (127, 128, 138) (`tailcfg/tailcfg.go:175-188`) | Absent. The declaration is held at 125 for this reason (`ts_capabilityversion/src/lib.rs:320-340`) | minor | Renewal is not seamless, so connections break across a key renewal. |
| C26 | Network-lock public keys parse in the CLI `tlpub:` form as well as `nlpub:` (`types/key/nl.go:29`, `:131-132`) | Not found: `grep -rn 'tlpub' ts_keys/src` is empty. `ts_keys` knows `nlpub` only (`ts_keys/src/lib.rs:76`) | minor | Matters once `tka_add` and `tka_remove` take keys pasted from `tailscale lock status`. |
| C8 | Lock verbs `Modify` (add and remove), `ForceLocalDisable`, `AffectedSigs`, `Generate/Cosign/SubmitRecoveryAUM`, `WrapPreauthKey`, `VerifySigningDeeplink` (`tailnet-lock.go:970`, `:830`, `:1112`, `:1150-1214`, `:1253`, `:1270`) | Only `tka_status`, `tka_log`, `tka_sign`, `tka_disable` and `tka_init` exist (`src/lib.rs:1308-1403`). `grep -rn 'affected.sigs' ts_* src` finds nothing | product-decision | The docs listed only add/remove and local-disable. Recovery AUMs, affected-sigs and wrap-preauth-key were listed nowhere. |
| C11 | `ClientVersion`, `DefaultAutoUpdate` and `CollectServices` are published or stored (`direct.go:1343-1344`, `:1039-1042`; `map.go:748-749`) | Parsed (`netmap.rs:376`, `:486`, `:492`), never read: a grep for each name is empty | product-decision | There is no updater. Without `CollectServices`, nothing gates `Hostinfo.Services`. |
| C20 | Requests `Tailnet` from policy in register (`direct.go:783-798`) | Not found: `tailnet` is never set in `register.rs:176-226` | product-decision | Used for MDM tailnet pinning. |
| C21 | Signs RegisterRequest with a device certificate (`SignatureType`, `Timestamp`, `DeviceCert`, `Signature`; `direct.go:813`, `sign_supported.go:138`) | The fields exist (`ts_control_serde/src/register.rs:105-113`) but are never set | product-decision | Windows certstore only in Go. |
| C25 | Go-only control endpoints: `/machine/set-device-attr` (`direct.go:1874`), `/machine/audit-log` (`tailcfg.go:3655`), `/machine/feature/query` (`localapi.go:1609`), `/machine/webclient/*` (`web_client.go:183-185`), `SetExpirySooner` (`direct.go:589`) | Not found: `grep -rn 'set_expiry_sooner\|audit.log\|feature/query\|set-device-attr\|machine/webclient' ts_* src` hits only an unrelated audit-log-ID field | product-decision | No tsnet embedder surface needs these today. |

Still open from earlier docs and beads: `tsr-84mh` (ServicesHash still hashes `serde_json::to_vec` with no
trailing newline, `ts_control/src/config.rs:787-791`), `tsr-cbw4` (register sets no `net_info`,
`register.rs:176-226`), `tsr-ajyc` (`GoArchVar` and `Cloud` unset, `register.rs:180-205`,
`map_request_builder.rs:152`), the self-locked-out health warning (now a log line at
`ts_runtime/src/control_runner.rs:923-937`, still not a health warning), the `tka_add`, `tka_remove` and
`tka_local_disable` engine asks, and multi-node `tka/init` enrollment (a non-empty `NeedSignatures` is
refused, `control_runner.rs:1430`).

### Underlay gaps (magicsock, disco, DERP, netcheck, netmon)

| Row | Go v1.102.4 behaviour (file:line) | Rust at f311bba (file:line, or "not found" and the grep) | Severity | Note |
|---|---|---|---|---|
| M1 | Discovery pings only from a send or an active heartbeat. The heartbeat ends 45 s after the last send (`wgengine/magicsock/endpoint.go:820-860`, `:1067`; `magicsock.go:4024`) | `run_pinger` ticks every 2 s (`ts_runtime/src/direct.rs:115`, `:676`). `send_pings` pings every path that `needs_refresh` (`ts_magicsock/src/sock.rs:1086-1100`, `path.rs:679-687`). There is no per-peer activity gate | blocks-parity | Idle peers are pinged for the life of the process. The comment at `sock.rs:1091-1093` claims the stock-client ping rate, but only the per-candidate floors are ported. Bead `tsr-7s3`. |
| M2 | CallMeMaybe is queued only when a send-triggered discovery sweep sent a ping (`endpoint.go:1394-1401`) | `run_call_me_maybe` sends one over DERP every 5 s to every peer with a disco key and no trusted best path (`ts_runtime/src/direct.rs:145`, `:975-1050`). It ignores traffic | blocks-parity | DERP load grows with the number of peers without a direct path, and the wire pattern differs from any stock client. No bead. |
| M3 | DERP `Recv` has a 120 s read deadline. A dead connection errors out and is redialed (`derp/derp_client.go:495-511`) | No read timeout. KeepAlive frames are logged with a TODO (`ts_derp/src/client.rs:229-234`). Home DERP is exempt from the inactivity timer (`ts_runtime/src/multiderp.rs:490`, `:541-542`). A grep for `timeout\|keepalive\|from_secs(120)` over `ts_derp/src` returns nothing | blocks-parity | A home DERP TCP connection dropped by a NAT stays "up" until a write fails. An idle node is unreachable meanwhile. No bead. |
| M18 | The peer-relay client discovers relay servers and sends `AllocateUDPRelayEndpointRequest` itself (`endpoint.go:896`, `:905`; `relaymanager.go:1027`, `:1094`) | No sender. Inbound Allocate messages are dropped (`sock.rs:2748-2754`). Rust only answers a `CallMeMaybeVia` a peer allocated (`relay.rs:1-20`) | blocks-parity (for relays) | Two nodes from this repository behind hard NAT can never use a peer relay. Bead `tsr-a9x4`. |
| M4 | On rebind, closes DERP connections whose local IP is gone (`wgengine/magicsock/derp.go:907`) | Rebind leaves DERP alone on purpose (`ts_magicsock/src/sock.rs:484`, `:489`). A grep for `close_derps_on_rebind\|maybeCloseDERPsOnRebind` finds nothing | minor | Makes M3 worse after a network switch. |
| M5 | With no netcheck preferred region, a deterministic fallback home is chosen (`derp.go:114`, `:200-201`) | An empty measurement set returns with no home (`ts_runtime/src/control_runner.rs:1944-1947`). A grep for `fallback` in `multiderp.rs` and `control_runner.rs` finds only the per-peer region fallback (`multiderp.rs:243`) | minor | A node whose latency probes all fail never picks a home DERP. |
| M6 | The home DERP is not changed while disconnected from control (`derp.go:186-190`) | `select_home_region` runs on every measurement with no control-connectivity gate (`control_runner.rs:1961-1966`, `:2073`) | minor | |
| M7 | `HomeParams.RegionScore` scales each region's latency before home selection (`net/netcheck/netcheck.go:1403-1410`) | Parsed (`ts_control_serde/src/derp_map.rs:243`, `:338`) but not used. `select_home_region` takes no scores (`control_runner.rs:2073-2076`). A grep for `region_score\|home_params` in `ts_runtime/src` finds nothing | minor | Control cannot steer the home region. |
| M8 | The deprecated `Avoid` region is skipped unless it is already preferred (`netcheck.go:389`) | Parsed (`derp_map.rs:302`) and dropped by `region_info` (`ts_control/src/derp.rs:40-45`) | minor | `NoMeasureNoHome` is honoured (`ts_netcheck/src/derp_latency.rs:89`). |
| M9 | `NotePreferred` is sent to every connected DERP on a home change (`derp.go:292`; `derp/derphttp/derphttp_client.go:423`) | Frame codec only (`ts_derp/src/frame/body/note_preferred.rs:8`). Never sent: a grep for `NotePreferred` in `ts_derp/src/client.rs` and `ts_runtime/src/multiderp.rs` finds nothing | minor | Server-side preference and metrics differ. |
| M11 | WireGuard data from an unknown source address goes to wireguard-go through `lazyEndpoint`, so a roamed peer is re-learned (`magicsock.go:4402`, `:1838`) | Dropped: "dropping data from unknown source address" (`ts_magicsock/src/sock.rs:1397-1405`) | minor | A peer whose NAT port changed loses direct traffic until its trust lapses to DERP. |
| M12 | A send error to the best address clears it at once with `noteBadEndpoint` (`endpoint.go:1655`) | Not found. A grep for `bad_endpoint\|noteBadEndpoint` finds nothing | minor | Rust waits for trust to expire. |
| M13 | Each disco ping is sent on its own, so one failure does not stop the others (`endpoint.go:1299`, `:1367-1392`) | `emit_disco_pings` returns on the first `send_udp` error with `?` (`sock.rs:1165`), which skips the rest of the sweep and the relay pings | minor | Present at `f311bba`. Fixed on main by #606 (`ec5dc27`), merged later on 2026-10-14. |
| M14 | Rebind plus ReSTUN on socket errors such as EPERM or a down network, at most once per 5 s (`magicsock.go:1605-1619`; `magicsock_notplan9.go:17`) | Not found. A grep for `should_rebind\|maybe_rebind_on_error\|EPERM` over the underlay crates finds nothing | minor | |
| M15 | With an unspecified bind, every interface address is advertised with the bound port. Loopback is used only if nothing else exists (`magicsock.go:1411-1430`) | IPv4 advertises the literal bound `0.0.0.0:port` as `Local` (`sock.rs:643-649`), unfiltered up to control (`direct.rs:942-951`, `control_runner.rs:2123-2135`, `ts_control/src/tokio/client.rs:218-228`). IPv6 interfaces are listed only when `enable_ipv6` is set (`sock.rs:675-700`) | minor | Peers receive a useless `0.0.0.0` candidate. |
| M17 | `betterAddr` points: latency percentage, +10 for IPv6, and a margin above 1 point (`endpoint.go:1856-1946`) | Latency only, with a 1% hysteresis. IPv6 only breaks exact ties (`path.rs:61`, `:706-718`) | minor | PR #604 closed unmerged. Still present at `f311bba`. |
| M20 | Wall-clock jump poll every 15 s to catch sleep and wake (`net/netmon/netmon.go:33`, `:704-714`) | Not found in `ts_netmon/src/lib.rs` or `ts_runtime/src/netmon.rs`. A grep for `wall\|time.jump` finds only the debouncer's own cap (`ts_netmon/src/lib.rs:19`) | minor | Not covered by `tsr-7wrn` or `tsr-cnlh`. |
| M21 | `SetNetworkUp` pauses STUN and endpoint work while offline (`magicsock.go:2717`) | Not found. A grep for `network_up\|set_network_up` finds nothing | minor | Depends on a real link monitor. |
| M22 | Peer path MTU discovery (`peermtu.go:38`, `:86`) | Not found. A grep for `pmtud\|wire_mtu\|peer_mtu` finds nothing | minor | Go gates it behind a knob. |
| M23 | UDP-lifetime probing, a control knob (`endpoint.go:697`; `magicsock.go:2866`) | Not found. A grep for `probe_udp_lifetime` finds nothing | minor | |
| M24 | The endpoint tracker keeps recently seen endpoints advertised so they do not flap (`endpoint_tracker.go:117`; `magicsock.go:1405`) | Not found. A grep for `endpoint_tracker` finds nothing. The reflexive set is a bounded set cleared on rebind (`sock.rs:509`, `:2453`) | minor | |
| M26 | Linux raw-socket disco listener, for when a host firewall drops disco UDP (`magicsock_linux.go:171`) | Not found. A grep for `raw_disco\|AF_PACKET` finds nothing | minor | |
| M27 | Homeless mode (`magicsock.go:4004`) and `RotateDiscoKey` (`magicsock.go:1263`) | Not found. Grep for `homeless`, `rotate_disco` | minor | `RotateDiscoKey` is debug-only in Go (`ipn/ipnlocal/local.go:7941`). |
| M10 | The DERP dial honours the HTTP(S) proxy from the environment (`derphttp_client.go:746-750`) | Not found. A grep for `https_proxy\|proxy_from_env\|derp.*proxy` finds nothing | product-decision | Probably deliberate under the anti-leak posture, and documented nowhere until now. |
| M16 | Private, link-local and loopback candidates are pinged and preferred, with +20, +30 and +50 points (`endpoint.go:1892-1906`) | Private, loopback and link-local candidates are rejected outright (`sock.rs:567-575`) | product-decision | Peers on the same LAN never go direct. This matches the public-VPS topology stance (`path.rs:7`, `:58`) but was not in the parity docs. |
| M19 | No WireGuard persistent keepalive anywhere. A grep for `PersistentKeepalive` over the whole Go tree finds 0 hits, and `wgengine/wgcfg/nmcfg` does not exist | A 25 s keepalive is on by default for every peer (`ts_control/src/config.rs:102-114`, `:837`) | product-decision | The idle-wedge fix. A deliberate divergence that the code comment called Go parity. Bead `tsr-0hd2` (blocked). |
| M25 | Static endpoints from config (`magicsock.go:1002`, `:1407`) and cloud-metadata public IPs (`magicsock.go:1373`) | Not found. A grep for `static_endpoints\|GetPublicIPs\|cloud_info` finds nothing | product-decision | A metadata query is an extra egress. |

Still open from earlier docs and beads: the portmapper's UPnP-IGD half (`tsr-x4yg`; NAT-PMP and
PCP are in `ts_portmapper`), the netmon OS backends (`tsr-7wrn`, `tsr-cnlh`; only
`ManualLinkMonitor` and `NoopLinkMonitor` exist, `ts_netmon/src/lib.rs:260`, `:297`), a full netcheck
report (`tsr-dsjq`; `ts_netcheck/src` holds only `derp_latency.rs` and `https.rs`), the NoPath demand
ping (`tsr-qc3o`, `sock.rs:2832-2836`), `disable-relay-client` (`tsr-re0d2b5d`), Mullvad and
WireGuard-only peers (the flag is carried at `ts_runtime/src/dataplane.rs:395-410`, with no send path),
an own DERP server (`ts_derp` is client-only), and the symmetric-NAT port spray, still skipped on
purpose.

### Data plane gaps (netstack, forwarder, packet filter)

| Row | Go v1.102.4 behaviour (file:line) | Rust at f311bba (file:line, or "not found" and the grep) | Severity | Note |
|---|---|---|---|---|
| N1 | Forwarded TCP dials the backend before completing the client handshake, then completes it (`wgengine/netstack/netstack.go:1782-1786`, then `r.Complete(false)` at `:1601`). A failed dial gets a RST (`:1732-1733`). The dial is cancelled when the client gives up (`:1750-1768`) | The smoltcp listener completes the handshake at accept (`ts_forwarder/src/tcp.rs:55`) and only then dials (`tcp.rs:113-127`). On a failed or timed-out dial the overlay stream is dropped, and drop sends `Close` (`ts_netstack_smoltcp_socket/src/tcp/stream.rs:345-353`), which is smoltcp `close()`, a FIN (`ts_netstack_smoltcp_core/src/socket_impl/tcp/stream.rs:122`). The dial has a fixed 10 s cap (`tcp.rs:14`) | blocks-parity | A client behind a subnet router or exit node sees connect succeed and then EOF instead of connection refused, and every forwarded port looks open to a scan. No bead. |
| N2 | gVisor TCP runs Reno congestion control (`netstack.go:375-376`), with SACK on (`:356`) and RACK off (`:365`) | No congestion control. `ts_netstack_smoltcp_core/Cargo.toml:26-43` enables neither `socket-tcp-reno` nor `socket-tcp-cubic`: `grep -rn "socket-tcp-reno\|socket-tcp-cubic" --include=Cargo.toml .` returns nothing. smoltcp then falls back to `NoControl`: https://github.com/smoltcp-rs/smoltcp/blob/v0.13.1/src/socket/tcp/congestion.rs | blocks-parity | Present at `f311bba`. Reno fixed on main by #627: the `socket-tcp-reno` feature is on and `new_tcp_socket` sets every socket to Reno (`ts_netstack_smoltcp_core/src/socket_impl/tcp/mod.rs`). A 500 kB transfer through an 8-slot dropping ingress queue now takes tens of milliseconds, where it timed out at 60 s before. Sender-side SACK recovery is still missing: smoltcp 0.14.0 negotiates SACK and sends SACK blocks as a receiver, but its sender never reads them. |
| N3 | The underlay sockets bypass the tunnel's routes. Linux uses SO_MARK (`net/netns/netns_linux.go:48`, `:113`) with policy rules (`wgengine/router/osrouter/router_linux.go:1505`). macOS uses IP_BOUND_IF (`net/netns/netns_darwin.go:295-298`) | Not found: `grep -rn -i "bind_device\|IP_BOUND_IF\|SO_MARK\|set_mark\|fwmark\|netns" --include='*.rs' .` returns nothing. TUN mode installs an exit node's `/0` as `0.0.0.0/1` plus `128.0.0.0/1` (`ts_host_net/src/lib.rs:159-176`), and on macOS installs `/0` directly (`ts_runtime/src/tun_actor.rs:369-370`) | blocks-parity | TUN mode only. With an exit node selected, the host route table sends the magicsock UDP and DERP TCP toward the peer into the tunnel too. Not run, so the loop is unverified. No bead. |
| N4 | An ICMP echo to a subnet-route or 4via6 destination is answered by a relayed system ping (`netstack.go:1458-1507`; `userPing` at `:1359`) | Not found: `grep -rln -i "user_ping\|userping\|system ping\|/sbin/ping" --include='*.rs' .` returns nothing, and `ts_forwarder/src` has no ICMP path (`grep -n -i "icmp\|ping" ts_forwarder/src/*.rs` hits only test byte strings in `dialer.rs`) | blocks-parity | Separate from the own-IP echo in `tsr-rsu`. Pinging a host behind a subnet router from this repository gets no answer. No bead. |
| N5 | The UDP forwarder accepts every datagram and never sends ICMP port unreachable (`acceptUDPNoICMP`, `netstack.go:646`, `:1945-1948`) | Not suppressed. smoltcp 0.13.1 answers an unmatched datagram with PortUnreachable unless a raw socket took it (`src/iface/interface/udp.rs` upstream). `grep -rn "PortUnreachable" --include='*.rs' .` returns nothing here. With an explicit port list, a datagram to an unlisted port on a forwarded destination gets an unreachable spoofed from that destination | minor | Follows from the explicit-port design (`src/config.rs:119-128`). The raw UDP observer in all-port mode (`ts_forwarder/src/all_port.rs:184`) is the exception. |
| N6 | Forwarded UDP idles out after 2 min, or 30 s for port 53 (`netstack.go:2123-2131`) | 30 s for every port (`ts_forwarder/src/udp.rs:19`), reaped every 15 s (`udp.rs:23`) | minor | Long-quiet UDP flows such as VoIP or WireGuard inside WireGuard lose their mapping four times sooner. |
| N7 | In-flight TCP forward attempts are capped globally: 8192 on Linux, 2048 elsewhere (`netstack.go:84-98`). Each client is capped at 2/3 of that (`netstack.go:110-119`, `:553-571`) | The caps are per port (`tcp.rs:23`, 512), plus the listener backlog (`ts_netstack_smoltcp_core/src/config.rs:101`, `:128`) and a global cap in all-port mode (`all_port.rs:74`, 2048). There is no per-client cap: `grep -rn -i "per_client\|per-client\|connsInFlightByClient" --include='*.rs' ts_forwarder ts_netstack_smoltcp_core ts_runtime/src` returns nothing | minor | One peer can fill a port's 512 slots and starve the other peers on that port. |
| N9 | gVisor auto-tunes the TCP receive buffer up to 8 MiB RX and 6 MiB TX (`wgengine/netstack/netstack_tcpbuf_default.go`; `netstack.go:303-325`). Keepalive is on per forwarded connection, with an idle of about 2 h by default (`netstack.go:124-132`, `:1630`) | A fixed 256 KiB per direction (`config.rs:97`) with no auto-tuning (`config.rs:27`). Keepalive probes at 60 s and aborts after 120 s (`config.rs:99-100`), on every socket (`ts_netstack_smoltcp_core/src/socket_impl/tcp/mod.rs:38-46`) | minor | Throughput is capped by the bandwidth-delay product. The keepalive timing difference was documented nowhere until now. |
| N8 | Extension hooks can widen the link-local exemption and ingress acceptance (`IngressAllowHooks`, `LinkLocalAllowHooks`; `wgengine/filter/filter.go:71-94`, `:674-684`; wired at `ipn/ipnlocal/local.go:3481-3482`) | Hard-coded. Only 169.254.169.254 is exempt (`ts_dataplane/src/lib.rs:20`), and there is no hook mechanism | product-decision | Upstream uses these for extensions this repository does not ship. |

Still open from earlier docs and beads: capability-sourced (`cap:`) ACL rules never match
(`ts_dataplane/src/lib.rs:674-675`, also `ts_runtime/src/peerapi_doh.rs:444`), a jailed peer gets the
ordinary ACL (`is_jailed` is decoded at `ts_control_serde/src/node.rs:267` and used nowhere), per-peer
masquerade addresses are never applied (`ts_runtime/src/peerapi.rs:349-351`), a TSMP ping gets no pong
(`ts_dataplane/src/lib.rs:805-815`, where Go accepts TSMP outright at `wgengine/filter/filter.go:551-552`),
the egress queue is still unbounded (`ts_runtime/src/dataplane.rs:115`, `:141`), the node does not answer
pings to its own IP (`tsr-rsu`), netstack sharding (`tsr-4pp`), 4via6 (`tsr-o7m8`) and a fixed
`MAX_UDP_FLOWS` (`tsr-iyv`, `ts_forwarder/src/udp.rs:39`). The first four are in
[PORTING.md](../PORTING.md) at lines 1263, 1300, 1338 and 1378.

#### smoltcp sender patches

The exit-node performance work in #598 was built on a branch that vendored smoltcp 0.13.1 and patched
its TCP sender. The first patch was the fast-retransmit RTO backoff fix. Thirteen more followed: the
congestion window enforced over bytes in flight, NewReno partial-ACK repair without go-back-N,
ACK-clocked Reno growth with a slow-start restart after a retransmission timeout, Cubic slow-start and
growth fixes, a bounded SACK scoreboard for selective recovery, RTT-based pacing, and a per-socket
minimum computed RTO used for a 200 ms floor.

None of them reached main. The backoff fix shipped upstream in smoltcp 0.14.0, which #616 took from
crates.io. When the branch took main to land #598, the vendored copy and the other patches were
dropped: they cannot build against crates.io smoltcp, and a `[patch.crates-io]` entry never reaches
users of the published crates. #598 merged without them.

They remain in the history of the `exit-node-perf` branch of
https://github.com/kasper0406/geiserx-tailscale-rs, before commit `a158b68`, which dropped them. Their
home is upstream smoltcp. Nothing in this repository carries them. The Reno controller this repository
runs since row N2 was fixed is smoltcp 0.14.0's own, without these patches.

### Runtime facade and node service gaps

| Row | Go v1.102.4 behaviour (file:line) | Rust at f311bba (file:line, or "not found" and the grep) | Severity | Note |
|---|---|---|---|---|
| R1 | TLS listeners resolve the certificate per handshake via `getCert` and then `LocalClient.GetCertificate` (`tsnet/tsnet.go:1418-1424`, used by `ListenTLS` at `:1371` and `ListenFunnel` at `:1507`). The certificate is cached and renewed | The acceptor wraps one fixed certificate, `SingleCert` (`ts_control/src/serve.rs:202-207`, `:216-220`). It is built once in `listen_tls` (`src/lib.rs:1848-1850`) and `listen_funnel` (`src/lib.rs:2004`). No renewal loop: `grep -rni renew src ts_runtime/src ts_control/src` finds only doc comments | blocks-parity | A service running past the certificate lifetime serves an expired certificate. The crate doc at `ts_control/src/cert.rs:25` claims "renewing at ~2/3 of lifetime", which is true of no listener. Bead `tsr-pyc9` covers only the missing cache. |
| R2 | The Serve reverse proxy deletes incoming `Tailscale-User-Login`, `-Name`, `-Profile-Pic` and `-Headers-Info`, then sets them from WhoIs. It also sets `X-Forwarded-For`, `-Host`, `-Proto` and `Tailscale-App-Capabilities` (`ipn/ipnlocal/serve.go:980-982`, `:1078-1106`, `:1124`) | Not found: `grep -rln 'Tailscale-User-Login\|X-Forwarded-For\|Tailscale-App-Capabilities' --include='*.rs' .` returns nothing. The proxy is a byte splice (`ts_runtime/src/serve.rs:332-346`) | blocks-parity | A backend written for Go Serve trusts these headers. Here it receives whatever the caller sent, so a tailnet peer can spoof `Tailscale-User-Login`. No bead. |
| R3 | WhoIs on a loopback `ip:port` resolves the real tailnet source through the ProxyMapper. Go registers those mappings for Serve TCP forwards (`ipn/ipnlocal/local.go:1698`, `:1730`) | Not found: `grep -rni 'proxymap\|ProxyMapper\|whois_ip_port' --include='*.rs' .` returns nothing. `whois` uses only the IP (`src/lib.rs:1478`, `ts_runtime/src/status.rs:285`) | blocks-parity | With R2, a Serve or TCP-forward backend has no way to learn who called. No bead. |
| R4 | `ListenService` advertises the service by editing the `AdvertiseServices` prefs, and withdraws it by refcount on close (`tsnet/tsnet.go:1756-1780`, `:1783`, `:1866`) | `listen_service` only resolves a VIP the netmap already granted, then binds it (`src/lib.rs:2051-2063`). Advertising exists only as the static `Config::advertise_services`, set before construction (`src/config.rs:293`). There is no runtime setter: `grep -rn 'fn set_advertise_services' src ts_runtime/src` returns nothing | blocks-parity | Go code that calls ListenService without pre-configuring the name gets no VIP here. Closing the listener never withdraws the service. No bead. |
| R5 | `ServiceModeHTTP{HTTPS, AcceptAppCaps, PROXYProtocol}` installs serve config with TLS termination and per-path app caps. `ServiceModeTCP{TerminateTLS, PROXYProtocolVersion}` does the same for TCP (`tsnet/tsnet.go:1588-1646`, `:1918-1933`) | `ServiceMode::{Tcp, Http}` carries a port only. Http is "identical to Tcp", with TLS left to the embedder (`ts_control/src/service.rs:29-44`) | blocks-parity | An HTTPS VIP service needs the embedder to fetch a certificate and terminate TLS itself, which then also hits R1. No bead. |
| R6 | The Server reads `TS_AUTHKEY` then `TS_AUTH_KEY`, plus `TS_CONTROL_URL`, `TS_CLIENT_SECRET`, `TS_CLIENT_ID`, `TS_ID_TOKEN` and `TS_AUDIENCE`, when fields are empty (`tsnet/tsnet.go:722-765`) | The facade builds from `Config::default()` (`src/tsnet.rs:682`) and reads no environment variable: `grep -n env src/tsnet.rs` finds only a test temp dir at `:2090`. Only `Config::default_from_env` reads the environment (`src/config.rs:517-531`), and it uses `TS_AUTH_KEY` only (`src/config.rs:13`). `TS_AUTHKEY` is not found: `grep -rn '"TS_AUTHKEY"' --include='*.rs' .` | minor | A Go-style deploy that sets `TS_AUTHKEY` never registers. The rustdoc at `src/tsnet.rs:581-582` says "Falls back to TS_AUTH_KEY", which is false. |
| R7 | `TSNET_FORCE_LOGIN` forces interactive login (`tsnet/tsnet.go:962`) | Not found: `grep -rn TSNET_FORCE_LOGIN --include='*.rs' .` | minor | |
| R8 | An empty `Dir` defaults to `UserConfigDir/tsnet-<prog>`, so state persists by default. A memory store is refused unless the node is ephemeral (`tsnet/tsnet.go:800-814`) | With no `dir` and no `store`, the identity is "fresh every run" (`src/tsnet.rs:612-618`), while `ephemeral` defaults to false (`src/tsnet.rs:690`). Nothing performs Go's memory-store check | minor | Every restart of a default `Server` registers a new non-ephemeral node, so stale nodes pile up in the admin console. |
| R9 | An empty `Hostname` defaults to the program name (`tsnet/tsnet.go:794-798`) | It defaults to the OS hostname (`ts_control/src/config.rs:815`) | minor | Two tsnet programs on one machine collide on the MagicDNS name. |
| R10 | `ListenFunnel` without `FunnelOnly` listens on the tailnet and Funnel together (`listenOnBoth`, `tsnet/tsnet.go:1491`, `:1500-1501`) | The listener carries only relay-delivered public ingress. `funnel_only` is accepted and ignored (`src/lib.rs:2006-2009`) | minor | Tailnet peers cannot reach a Funnel port through the same listener. |
| R11 | The LocalAPI serves the full handler table (`ipn/localapi/localapi.go:71`) in `ipnstate.Status` JSON (`Self`, `Peer`, `BackendState` and so on) | The facade's LocalAPI routes only `GET /localapi/v0/status` and returns 404 otherwise (`src/tsnet.rs:1577-1590`). It emits a custom snake_case object (`self`, `peers`, `active_exit_node`) (`src/tsnet.rs:1376-1384`). Control's c2n `/remoteapi/localapi/` proxy reaches the same table (`ts_control/src/tokio/ping.rs:27`) | minor | Go tooling and the remote-config path cannot parse the status body. |
| R12 | `ipnstate.Status` carries `BackendState`, `AuthURL`, `CurrentTailnet`, `CertDomains`, the `User` map and `ClientVersion`. `PeerStatus` carries `OS`, `HostName`, `UserID`, `Tags`, `PrimaryRoutes`, `RxBytes`, `TxBytes`, `LastWrite`, `LastHandshake`, `Active`, `ExitNodeOption`, `PeerAPIURL` and `TaildropTarget` (`ipn/ipnstate/ipnstate.go:31-89`, `:233-293`) | `Status` has self, peers, active exit, suffix and health (`ts_runtime/src/status.rs:37-58`). `StatusNode` has id, name, IPs, online, last_seen, routes, exit flag, cur_addr, relay, SSH keys and expired (`ts_runtime/src/status.rs:65-128`) | minor | Traffic counters, handshake age and tags are not observable. |
| R13 | `WhoIsNodeKey` and `WhoIsProto` (`client/local/local.go:384`, `:401`) | Only `whois(addr)` (`src/lib.rs:1478`). `grep -rn 'fn whois_' --include='*.rs' src ts_runtime/src` finds only internal helpers | minor | `WhoIsForIP` and `WhoIsForService` were already documented as missing. |
| R14 | `ipn.Notify` carries `FilesWaiting`, `IncomingFiles`, `OutgoingFiles`, `Health`, `Prefs`, `LoginFinished`, `ErrMessage`, `Engine` and `SuggestedExitNode` (`ipn/backend.go:312-471`). `AwaitWaitingFiles` long-polls on it (`client/local/local.go:813`) | `Notify` has only `state`, `net_map` and `browse_to_url` (`ts_runtime/src/ipn_bus.rs:113-128`). `grep -rn 'watch_incoming_files\|incoming_files\|await_waiting' --include='*.rs' .` returns nothing | minor | A Taildrop receiver must poll `taildrop_waiting_files`. |
| R15 | PeerAPI also serves `/v0/goroutines`, `/v0/env`, `/v0/metrics`, `/v0/magicsock`, `/v0/dnsfwd`, `/v0/interfaces` and `/v0/sockstats` (`ipn/ipnlocal/peerapi.go:387-405`), plus `/v0/doctor` (`feature/doctor/doctor.go:26`) and `/v0/wol` (`feature/wakeonlan/wakeonlan.go:29`) | Routes are only `/v0/put/`, `/v0/ingress` and DoH (`ts_runtime/src/peerapi.rs:292-309`) | minor | These are debug or optional features, and Go gates them on peer capabilities. |
| R16 | The DNS forwarder answers Bonjour browse names (`b/db/r/dr/lb._dns-sd._udp.*`) with a local NXDOMAIN instead of forwarding them (`net/dns/resolver/forwarder.go:1179`; `net/dns/resolver/tsdns.go:1417`) | Not found: `grep -rni 'dns-sd\|bonjour' --include='*.rs' ts_runtime/src` | minor | LAN-discovery queries leave the node toward the upstream resolver. |
| R17 | Capture records disco frames as `PathDisco` = 254 (`wgengine/magicsock/magicsock.go:2276`) and synthesized packets (`net/tstun/wrap.go:1340`, `:1476`) | `CapturePath` has no Disco variant (`ts_dataplane/src/lib.rs:1518`). Only `FromLocal` and `FromPeer` are ever emitted (`ts_dataplane/src/lib.rs:1638`, `:1726`) | minor | A pcap file shows no disco traffic. |
| R18 | Usermetrics `tailscaled_*` with labels (`wgengine/magicsock/magicsock.go:768`, `health/usermetrics.go:35`, `ipn/ipnlocal/local.go:572`) exposed by `UserMetrics` (`client/local/local.go:425`), plus about 350 clientmetric registrations | Unlabelled counters and gauges only (`ts_metrics/src/lib.rs:76-81`). There are 24 registrations in the tree. `Device::metrics` (`src/lib.rs:1465`) has no `tailscaled_*` series | minor | Dashboards built for Go find nothing to scrape. |
| R19 | `Server.ListenSSH`, `RegisterFallbackTCPHandler` and `CapturePcap` sit on the Server (`tsnet/tsnet.go:1292`, `:1403`, `:2223`) | The facade has none of the three. They are reachable only through `Server::device()` (`src/tsnet.rs:764`) | minor | |
| R20 | Not applicable (bindings exist only here) | `ts_ffi` exports 59 functions against 77 public `Device` methods. `set_exit_node`, `logout`, `watch_ipn_bus`, `suggest_exit_node`, `set_serve_config` and `listen_ssh` appear in no binding. `listen_funnel` exists only in Python and Elixir | minor | The older "~90%" figure, which claimed every `Device` method had a binding, was corrected in place. |

Still open from earlier docs and beads: the refusals the Go-shape Serve config still makes on purpose
(TerminateTLS, ProxyProtocol, AcceptAppCaps, plain-HTTP ports, Path handlers, non-root Proxy mounts and
Services, listed at `ts_control/src/serve/ipn.rs:386-394`), the loopback HTTP-proxy half and SOCKS5 UDP
ASSOCIATE and BIND (`tsr-ask7`), the facade's missing `Logf`, `UserLogf`, `GetRootPath`, `Sys()` and
`LogtailWriter`, plus `RunWebClient` carried but never sent (`tsr-reh3`, `ts_control/src/config.rs:539`),
the missing certificate cache (`tsr-pyc9`, `src/lib.rs:1815-1817`), `FunnelTLSConfig` ignored
(`src/tsnet.rs:318-325`), the Funnel public relay leg (`tsr-am9.11`, external), `WhoIsForIP` and
`WhoIsForService`, SSH login-shell only and check mode (`tsr-v5gw`, `tsr-0h2`), 4via6 MagicDNS and app
connectors (`tsr-o7m8`), exit-node DoH answering MagicDNS (`tsr-i2w`), encrypted upstream resolvers
(`tsr-3l78`), PeerAPI resume, headers and capability scope (`tsr-cvh`, `tsr-dlzn`), the
`AllowedSuggestedExitNodes` policy (`ts_runtime/src/exit_node_suggest.rs:6-8`, `:95-97`, `:195-196`) and
IPv6 reverse DNS, which is NXDOMAIN on purpose (`ts_runtime/src/magic_dns.rs:466`, `:494`).

### Code comments that are wrong

This change touches docs only, so these comments stay as they are. Fix each with the code it describes.

| File:line | What it says | What is true at f311bba |
|---|---|---|
| `ts_control/src/cert.rs:25` | The node serves the certificate "renewing at ~2/3 of lifetime (with ARI)". | No listener renews. Each holds one fixed certificate (row R1). |
| `src/tsnet.rs:581-582` | `auth_key` "Falls back to `TS_AUTH_KEY`". | The facade reads no environment variable (row R6). |
| `src/lib.rs:1295` | Per-peer `online`, user and capabilities are "honestly `None`/empty". | They are kept and reported (`ts_runtime/src/status.rs:7-23`). |
| `src/config.rs:124-125` | "The underlying netstack has no all-port accept mode." | `forward_all_ports` exists (`src/config.rs:143`, `ts_forwarder/src/all_port.rs`). |
| `ts_control/src/tka.rs:10` | "AUM-sync RPC deferred." | The sync RPC is implemented (`ts_runtime/src/tka_sync.rs`; `control_runner.rs:461-560`). |
| `ts_magicsock/src/sock.rs:1091-1093` | The cadence gates make "the on-wire ping rate match a stock client". | There is no activity gate, so it does not (row M1). |
| `ts_control/src/config.rs:104-106` | The 25 s keepalive "Matches Tailscale, which sets `PersistentKeepalive = 25`". | Go v1.102.4 sets no WireGuard keepalive and has no `nmcfg` package (row M19). |
| `ts_control_serde/src/ping.rs:46` | Repeated `PingRequest` URLs "should be ignored". | Nothing dedupes them (row C12). |

### Open backlog

The tracker held 75 unresolved beads when the factory stopped: 72 open, 2 in progress and 1 blocked.
The beads, not this table, are the backlog's source of truth. This table is a copy of the export taken
on 2026-10-14.

Look at these first:

- **P0 `tsr-am9`**, the tsnet full-parity epic. It is done when the gaps above are closed or decided.
- **P1 `tsr-0hd2`** (blocked): the 25 s WireGuard keepalive that Go never sends (row M19). It waits on a
  live idle-then-dial test with the keepalive off.
- **In progress `tsr-7s3`**: ping cadence and path selection (rows M1 and M17, whose PR #604 closed unmerged).
- **In progress `tsr-doz6`**: link-change detection. Slice a shipped. The Linux and macOS backends are
  `tsr-7wrn` and `tsr-cnlh`.

Some open beads are already closed by the tree. Close them when the tracker is next pulled:

- `tsr-x72n`: per-peer online, last seen and the WhoIs user are kept (`ts_runtime/src/status.rs:20-23`,
  `:93`, `:96`, `:223`; `ts_runtime/src/peer_tracker/mod.rs:1905`, `:1968`).
- `tsr-ohp`: the flow cache is ported (`ts_dataplane/src/flowtrack.rs:31-35`, commits `bebe07f` and
  `3da1d5c`).
- `tsr-4obf`: IPv6 fragments are handled (`ts_dataplane/src/lib.rs:122-215`, commit `e7e4759`).
- `tsr-re6d8674`: the CallMeMaybe refusals are in (`ts_magicsock/src/sock.rs:2721`, `:2316`, `:2352`).
  The three entries in [restock-beads.json](restock-beads.json) are closed by the same code and
  `ts_magicsock/src/relay.rs:133-176`.
- `tsr-u5x`: routes and the DNS responder gate are re-read on every apply
  (`ts_runtime/src/tun_actor.rs:372-374`, `:744-747`). Whether the OS resolver config is re-applied was
  not traced, so check that before closing.
- `tsr-ask7` is partly closed: the second credential and a status-only LocalAPI ship
  (`src/tsnet.rs:469`, `:1577-1590`). The HTTP-proxy half and SOCKS5 UDP ASSOCIATE and BIND remain.
- `tsr-a9x4`'s title says peer relays are absent. The receiving side is there; only the client side that
  allocates a relay is missing (row M18).

Most blocks-parity rows have no bead: C1, C2, C3, C6, M2, M3, N1, N3, N4, R2, R3, R4 and R5. File one
for each before picking them up.

Pull requests #597 to #606 carried real fixes for rows in the tables above: exit-node support, the
lost FIN, the smoltcp retransmit fix, session revocation, Hostinfo, exit-flow confinement, `betterAddr`
scoring, the key-file mode and probing after a failed send. All of them merged after the `f311bba` pin
except two: #616 replaced #600 by taking the fix from smoltcp 0.14.0, and #604 closed unmerged.

| Bead | Priority | Type | Status | Title |
|---|---|---|---|---|
| `tsr-am9` | P0 | epic | open | tsnet full-parity: rewrite Go tsnet completely into Rust |
| `tsr-0hd2` | P1 | bug | blocked | magicsock: fork sets WG PersistentKeepalive=25s on every peer; Go v1.100.0 leaves it 0 (disabled) |
| `tsr-7s3` | P2 | bug | in progress | magicsock: ping cadence + path-selection diverge from Go (no goodEnoughLatency/sessionActiveTimeout/upgradeUDPDirect/betterAddr-bonuses; 2s vs 5s ping floor) |
| `tsr-doz6` | P2 | bug | in progress | runtime: no netmon/link-change detection, rebind is embedder-driven; node degrades to DERP on net change (highest-leverage) |
| `tsr-4pp` | P2 | task | open | Shard the netstack per ~50-100 sessions in k8s |
| `tsr-7wrn` | P2 | bug | open | tsr-doz6 slice b: Linux netlink LinkMonitor backend |
| `tsr-cnlh` | P2 | bug | open | tsr-doz6 slice c: macOS PF_ROUTE LinkMonitor backend |
| `tsr-re0d2b5d` | P2 | bug | open | Honour disable-relay-client instead of opening relay paths control switched off |
| `tsr-x4yg` | P2 | bug | open | magicsock portmapper (EPIC): NAT-PMP and PCP done (`ts_portmapper`, `ts_runtime::portmap`); UPnP-IGD (phase 2) open, so UPnP-only routers stay on DERP |
| `tsr-0h2` | P3 | feature | open | Daemon ask: SSH check-mode (HoldAndDelegate) round-trip |
| `tsr-1rs` | P3 | task | open | harden flaky udp_forwarder_splices test (real-UDP round-trip on loaded CI) |
| `tsr-3l78` | P3 | bug | open | magic-dns: DoH/DoT/HttpWireguard upstream resolvers parsed-then-dropped, encrypted-upstream split-DNS silently ignored |
| `tsr-4obf` | P3 | bug | open | packetfilter: IPv6 fragment-extension-header handling (decode6 parity; moot while IPv4-only) |
| `tsr-51o6` | P3 | bug | open | ts_magicsock counters_call_me_maybe_accept_vs_reject flakes under full-workspace parallel test |
| `tsr-84mh` | P3 | bug | open | control: ServicesHash not byte-equal to Go vipServiceHash (missing trailing newline + Ports null-vs-[*]) |
| `tsr-a9x4` | P3 | bug | open | magicsock/disco: peer relays (CallMeMaybeVia + Geneve data path) absent, double-hard-NAT pairs stay on DERP (EPIC) |
| `tsr-ajyc` | P3 | bug | open | hostinfo: fill best-effort Distro/DistroVersion/DistroCodeName + Cloud + Container/Env to fully match Go hostinfo.New |
| `tsr-am9.11` | P3 | task | open | Funnel public ingress relay leg (DERP TCPHandlerForIngress) |
| `tsr-ask7` | P3 | bug | open | loopback: SOCKS5-CONNECT-only, missing HTTP-proxy half, SOCKS5 UDP ASSOCIATE, LocalAPI-over-HTTP; fixed cred |
| `tsr-aud436` | P3 | bug | open | Parity audit of #436: Rejected packet filter raises no health warning (invalid-packet-filter Warnable not ported) |
| `tsr-aud466` | P3 | bug | open | Parity audit of #466: Backlog entry endorses relaying the first REFUSED when a later resolver hard-fails; Go sends SERVFAIL |
| `tsr-cbw4` | P3 | bug | open | control: register/doLogin path carries no NetInfo (Go's hostInfoLocked attaches it to doLogin too) |
| `tsr-cvh` | P3 | bug | open | peerapi: GET /v0/put/ resume hash-exchange missing + taildrop response Content-Type + ingress Src-header/cap gaps |
| `tsr-dlzn` | P3 | bug | open | peerapi: capability enforcement is membership-only, not FILE_SHARING_SEND/ingress-cap-scoped (broader trust than Go) |
| `tsr-dsjq` | P3 | bug | open | netcheck: not a full Go netcheck.Report (no UDP/NAT-hardness/MappingVaries/hairpin at cold start) |
| `tsr-i2w` | P3 | bug | open | exit-node DoH answers MagicDNS authoritatively vs Go forward-only HandlePeerDNSQuery |
| `tsr-iyv` | P3 | task | open | forwarder: make MAX_UDP_FLOWS configurable for high-fan-out DNS exits (LOW) |
| `tsr-j5z4` | P3 | bug | open | docs(readme): reconcile README/SECURITY.md/rustdoc, TKA+exit-DNS understated, default-build TLS overstated, portmapper unlisted |
| `tsr-o7m8` | P3 | bug | open | app-connector + 4via6 domain-based routing absent (advanced/optional, long-tail) |
| `tsr-ohp` | P3 | task | open | packetfilter: stateless filter has no runIn conntrack (non-SYN-accept / ICMP-resp / UDP-LRU), design decision |
| `tsr-pyc9` | P3 | bug | open | acme: no cert cache, every listen_tls/get_certificate re-issues from Let's Encrypt (rate-limit risk) |
| `tsr-qc3o` | P3 | bug | open | magicsock disco: send-path NoPath should kick a wantFullPing-gated demand ping (Go endpoint.send) |
| `tsr-qn2` | P3 | task | open | tunnel: make transport padding MTU-aware to match wireguard-go at non-16-aligned MTUs + recv-pad invariant doc |
| `tsr-re6d8674` | P3 | bug | open | Port Go's CallMeMaybe admission refusals: DERP only, bound to the DERP sender, Via only from relay-capable peers |
| `tsr-reh3` | P3 | bug | open | tsnet-api: small surface gaps, no Logf injection, no Port-pin, no RunWebClient, no Sys(); confirm ListenPacket/GetRootPath/OAuth-key |
| `tsr-rsu` | P3 | bug | open | netstack: enable auto-icmp-echo-reply (node doesn't answer pings to its own IP vs Go gVisor) |
| `tsr-u5x` | P3 | task | open | tunnel/TUN: re-steer host FIB + host DNS on runtime set_accept_routes/set_exit_node/set_accept_dns toggle |
| `tsr-v5gw` | P3 | bug | open | ssh: login-shell-only, no exec/SFTP/port-forward; userLogin principals never match (silent ACL divergence) |
| `tsr-x72n` | P3 | bug | open | status/whois: per-peer online/last_seen + WhoIs.user not retained (reported None), wire delivers them |

The factory lane is closed and its beads are retired: the rows that tracked its pull requests, review
rounds, conflicts and Dependabot updates are gone from this table, and every pull request they named is
merged or closed.

### How to resume

1. Pull the tracker before anything else. It syncs only from the private remote named by `sync.remote`
   in `.beads/config.yaml` (see "Where the tracker syncs" in
   [AGENTS.md](../AGENTS.md#where-the-tracker-syncs)). Then run `bd list --status open` and
   `bd show <id>`. The beads are the source of truth. The table above is a copy that will drift.
2. The tracker export frozen at the stop, and the runbook for winding the factory down and starting it
   again, are kept privately with the factory, not in this repository.
3. Check the rows above against main first. Several pull requests merged after the `f311bba` pin, so
   some rows may already be closed.
4. Close the beads the tree already closed (listed above) and file a bead for each blocks-parity row
   that has none.
5. Re-check a row against the code before porting it. The line numbers above are anchors at
   `f311bba` and Go v1.102.4, not guarantees. If upstream has moved, re-pin both trees and re-read the
   rows that touch what moved. The full per-commit ledger against upstream is
   [PORTING.md](../PORTING.md).

## Recently closed (v0.6.4–v0.6.5)

The consumer-facing tsnet gaps the embedders actually hit are now closed and live-verified against
`controlplane.tailscale.com`:

- **Runtime exit-node switch** — `Device::set_exit_node` (Go `EditPrefs(ExitNodeID/IP)`). v0.6.4.
- **Logout / deregister** — `Device::logout` (Go `LocalClient.Logout`): re-register with a past
  expiry. v0.6.5.
- **Typed registration outcome** — `Device::wait_until_running(timeout) -> Result<(), RegistrationError>`
  + `Device::watch_state()` (`DeviceState` stream). Replaces poll-`ipv4_addr` loops; distinguishes
  permanent (`AuthRejected`/`KeyExpired`) from recoverable (`NeedsLogin` — keeps retrying) and
  transient (`NetworkUnreachable`). v0.6.5.
- **Active exit node** — `Device::active_exit_node()` / `Status.active_exit_node` (Go
  `Status.ExitNodeStatus.ID`): the resolved, fail-closed engaged exit, not the configured selector.
  v0.6.5.
- **WhoIs user + capabilities** — `WhoIs.capabilities` from the node `CapMap`; `WhoIs.user` from the
  netmap `UserProfiles` join. v0.6.5. *(Per-node `online`/`last_seen` were not retained at v0.6.5. They
  are now: `ts_runtime/src/status.rs:20-23`, `:93`, `:96`.)*
- **`russh` 0.61.2 security bump** (GHSA-wwx6-x28x-8259), ssh-feature-only; ring-only invariant
  preserved. v0.6.5.

Recently landed (tracked): **live Tailnet-Lock (TKA) enforcement** — per-peer key-signature
verification is now **active and fail-closed** at the peer-trust chokepoint, matching Go's
`tkaFilterNetmapLocked`. Once a verified `Authority` has been synced from control (over the internal
watch channel, only after `VerifiedAumChain::verify`), peers with a missing or unauthorized signature
are dropped; with no lock synced every peer is admitted, and a disabled lock clears enforcement. The
cross-peer rotation filter (Go's `rotationTracker`) also drops peers presenting a rotated-away key.
The remaining TKA parity items are narrower: disablement-secret verification, the `UnsignedPeerAPIOnly`
under-enforcement gap, and surfacing a self-locked-out health warning — see the deferred list below
and issue #7.

## Where we are (v0.8.1 — near-complete tsnet parity)

> Per-lane percentages below were last measured at v0.5.39; the numbered roadmap was reconciled
> against the tree at v0.8.1 (see "Roadmap" — 16/21 shipped, 1 genuinely open). Treat the lane
> percentages as a floor, not a ceiling.

Crucially, the fork is **more mature than its own stale README suggests**:

- **Direct-path P2P is real** — disco Ping/Pong/CallMeMaybe, RTT-based best-addr selection, trust
  windows, DERP-as-fallback. It is **not** DERP-relay-only. IPv6 direct paths negotiate when
  `enable_ipv6` is set (v0.5.37).
- **No `panic=abort`** — kameo actors isolate per-flow panics; crash isolation is intact.
- **Anti-leak is type-encoded** — `DirectDialer` structurally refuses exit egress; egress
  fail-closes when no `/0` route matches; no host-socket fallback exists in `Device::tcp_connect`.
- **musl static + ring-only** — CI musl lane + `aws-lc-rs`-absence guard; aws-lc confined to the
  optional `ssh` feature.

Per-lane parity estimate (updated v0.5.39): A (Status/WhoIs) ~85%, B (MagicDNS) ~85% (full netstack
`100.100.100.100:53` server; host-resolver redirect only missing in TUN mode), C (forwarding) ~85%,
D (Ping/direct) ~90% (IPv6 direct paths land; only symmetric-NAT spray skipped),
E (TLS/Serve/ACME) ~80% (client-side ACME DNS-01 issuance shipped behind `acme`; `listen_tls` issues
real certs against a `set-dns`-capable control plane; only the stored Serve-state runtime + the
external Funnel relay leg remain), FFI/Python/Elixir bindings cover most public `Device` methods but not
all of them: at `f311bba` `ts_ffi` exports 59 functions against 77 public `Device` methods, and
`set_exit_node`, `logout`, `watch_ipn_bus`, `suggest_exit_node`, `set_serve_config` and `listen_ssh`
have no binding (2026-10-14 row R20).

### Shipped since v0.4.0 (the parity push)
Taildrop send/recv, CapturePcap, TKA Ed25519 fix, node-key rotation, WIF/OAuth bootstrap, loopback
SOCKS5 (v0.5.27–v0.5.32); a multi-reviewer hardening pass (v0.5.33); then the parity sweep:
**FFI/Python/Elixir lane propagation** (v0.5.34), **turnkey `listen_ssh` login-shell** (v0.5.35),
**disco/STUN observability counters** (v0.5.36), **IPv6 local disco candidates** (v0.5.37),
**client-side ACME (RFC 8555 DNS-01) + `set-dns` RPC** (v0.5.38), **`listen_tls`→ACME wiring**
(v0.5.39). Tier 1 (direct-path glue, disco↔node-key binding, musl lane) and Tier 2 (tags, ephemeral,
upstream-proxy dialer, netmap resumption) were verified already-complete in-tree.

Most recent wave:
- **Serve `Path` / `Redirect` handlers** — HTTP path-prefix mux and HTTP 3xx redirect targets added
  to `ServeTarget`, validated and dispatched on the TLS-terminated stream, fail-closed (unmatched
  path → 404, backend dial failure → drop). Hand-rolled HTTP head parsing; no axum/hyper added.
- **Recursive MagicDNS in TUN mode** — the TUN-mode `100.100.100.100:53` resolver now forwards
  non-tailnet names recursively (previously inert in TUN mode), reusing the forwarder netstack's
  overlay-backed `Channel` and the same `decide`/`recursive_plan` path as netstack mode, so the
  IPv4-only egress filter and fail-closed NXDOMAIN default are inherited.
- **Tailnet Lock peer-key enforcement (active)** — per-peer node-key signature verification is
  threaded through the domain `Node` and **enforcing** at the `ts_runtime` peer-trust chokepoint,
  matching Go's `tkaFilterNetmapLocked`. A verified `ts_tka::Authority` is delivered from the control
  runner over an internal watch channel — only after `VerifiedAumChain::verify` — and the chokepoint
  then fails closed on missing/unauthorized signatures (self is structurally never filtered). With no
  lock synced, behavior is unchanged (admit-all); a disabled lock clears enforcement. A whole-netmap
  rotation filter (Go's `rotationTracker`) additionally drops a peer presenting a node key that a
  newer rotation chain has superseded (clone/replay defense). The narrower remaining items
  (disablement-secret verification, the `UnsignedPeerAPIOnly` under-enforcement gap, self-locked-out
  health warning) are in the deferred list below and [SECURITY.md](../SECURITY.md).

### Deferred (in-scope eventually, not blocked externally — with reasons)
- **TKA disablement-secret verification** — the cryptographic proof that a given lock *disable* is
  authorized is not yet checked, so a disable is currently taken at face value. Control is already
  trusted for the enable/disable toggle (it cannot forge-admit a peer either way — admission still
  requires a key in the verified chain), so this is a hardening item, not an open admit-all hole (see
  [SECURITY.md](../SECURITY.md)).
- **Self-locked-out health warning** — Go surfaces a health warning when the node's own key is not
  authorized under an active lock. Self is structurally never filtered here (the self node never
  enters the peer db), so there is no lockout risk. The lockout is now logged at warn on every sync
  (`ts_runtime/src/control_runner.rs:923-937`), but it is still not raised as a health warning.
- ~~**`ts_tka` CTAP2-CBOR cross-validation against Go test vectors**~~: landed. Go golden vectors are
  committed under `tests/vectors/` (`tka_cbor_sighash_golden.json`, `tka_aum_hash_golden.json`,
  `tka_disablement_golden.json`) and checked by `tka_cbor_matches_go_golden`,
  `aum_serialize_matches_go_test_serialization_vectors` and `disablement_value_matches_go_golden`
  (`ts_tka/src/lib.rs:3605`, `:3778`, `:4672`).
- **`UnsignedPeerAPIOnly`** — the peerAPI-only network-access carve-out for unsigned peers under
  tailnet lock; Go admits such peers unsigned, whereas an active lock here rejects unsigned peers
  outright (*more* restrictive — a connectivity gap in the safe direction). The node model now ingests
  the field (`ts_control/src/node.rs:253`, `:1134-1146`), so this gap is live (2026-10-14 row C7).
- **DERP mesh / private DERP server** — running our own DERP relay mesh (consuming public relays as
  a fallback path is implemented).
- **TKA signing**: initiating a lock, signing and disabling now ship (`tka_init`, `tka_sign`,
  `tka_disable`, `src/lib.rs:1347-1403`). Still missing: add and remove keys, local disable, recovery
  AUMs, affected-sigs and wrap-preauth-key (2026-10-14 row C8), and the node's own `NodeKeySignature`
  on register (rows C1 to C3).
- **UPnP-IGD port mapping** — NAT-PMP and PCP are done ([`ts_portmapper`](../ts_portmapper/src/lib.rs));
  UPnP-IGD (SSDP discovery, SOAP mapping) is phase 2.
- **App connector** — `4via6`-style application connectors.
- **`4via6`** subnet-route encoding.
- ~~**Serve get/set_serve_config + accept-loop runtime**~~: shipped. `Device::set_serve_config`
  (`src/lib.rs:1897`) stores the config in Go's `ipn.ServeConfig` shape since `50611ab`
  (`ts_control/src/serve/ipn.rs:1-15`). The refusals it still makes on purpose are listed at
  `ts_control/src/serve/ipn.rs:386-394`.
- **Service advertise-to-control** — consume-side done; advertise-side is low value (ACL-preassigned
  VIPs work) and needs a wire-field decision.
- **Symmetric-NAT birthday-paradox port spray** — deliberately skipped (low value for the
  DERP-acceptable userspace-netstack deployment; the single-port guess already covers easy cases).
- **Netstack sharding** (`tsr-4pp`) — benchmark-gated; needs a real exit-egress measurement
  first.
- `Sys()` internals — satisfied via typed accessors (`self_node`/`status`/`watch_netmap`/`whois`).

### Blocked by external dependency
These cannot be built against a self-hosted control plane and depend on Tailscale-operated infra or
out-of-band setup:
- **Funnel public ingress relay** — depends on the Tailscale-operated public relay leg; un-buildable
  against a self-hosted control plane. `listen_funnel` correctly fail-closed.
- **ACME on a self-hosted control plane** — a self-hosted control plane may return `501` for the
  ACME-over-control cert RPC; client-side ACME (DNS-01) is implemented but the control-plane leg is
  not available there.
- **OIDC / SSO** — identity-provider integration is a control-plane/deployment concern.
- **Network flow logs** — depends on the control-plane log-collection pipeline.
- **Taildrop relay** — the relayed (non-direct) Taildrop path depends on Tailscale infra (direct
  send/recv is implemented).
- **Node sharing** — cross-tailnet sharing is a control-plane feature.

## Upstream tracking

Upstream [`tailscale/tailscale-rs`](https://github.com/tailscale/tailscale-rs) is now active. Going
forward this fork tracks upstream and aims to upstream or re-base fork-specific work where it makes
sense, while keeping the anti-leak/egress posture (see `AGENTS.md`).

## Consumers and the seams they need

- **Userspace egress client** — holds a `Device` handle and obtains per-flow `AsyncRead+AsyncWrite`
  streams from `Device::tcp_connect`, gated by `Config::exit_node`. This **is** the dialer; do not
  reach for `ts_forwarder::RealDialer` (that is the *inbound* exit-node-server chokepoint, the wrong
  direction). Fail-closed composes because there is no host-socket fallback in the egress path.
- **Per-pod userspace client** — pure userspace netstack (no TUN/root), ephemeral auth-key join to
  the control plane, exit-node selection, graceful teardown. Most of this exists; gaps are tags,
  ephemeral config, and the upstream residential-proxy hop.

## Roadmap (ranked by leverage)

> **Status reconciled at v0.8.1** (2026-06-10) against the actual tree. The original Tier-1..5
> numbered list (authored ~v0.5.39) is **badly stale**: of its 21 items, **16 shipped, 4 are partial
> by design / external-blocked, and only 1 is genuinely unbuilt**. The closed items are preserved
> below (struck, with the proof) so the history is legible; the live work is the short
> "**Actually remaining**" list. Don't re-investigate a struck item as if open — that mis-step is
> exactly what the closed `~~item~~` lines exist to prevent (it cost a misdiagnosis on #24).

### Actually remaining (the real backlog)

- **Netstack sharding** (was Tier-3 #9; bead `tsr-4pp`) — the one fully-unbuilt numbered item. One
  shared smoltcp poll loop serves all flows; shard per ~50–100 sessions. smoltcp has no sender-side SACK
  recovery and no buffer auto-tuning, and runs Reno since row N2 was fixed, so **benchmark over a real exit
  before committing the dataplane** (deliberately gated, not neglected).
- **Tailnet-Lock (TKA) enforcement hardening** (part of old #20; issue #7) — core enforcement now
  **ships active and fail-closed**, matching Go's `tkaFilterNetmapLocked`: a verified `Authority`
  reaches the `peer_tracker` over an internal watch channel (only after `VerifiedAumChain::verify`)
  and drops peers with a missing/unauthorized signature, and a whole-netmap rotation filter (Go's
  `rotationTracker`) drops peers presenting a rotated-away key. What remains is narrower:
  disablement-secret verification, the `UnsignedPeerAPIOnly` carve-out, and a self-locked-out health
  warning (see the deferred list and "Invariants").
- **Own/private DERP server** (part of old #20) — `ts_derp` is client + mesh-frame types only (no
  server accept loop). Consuming public relays as fallback already works; running our own mesh is the
  open piece. Low priority for the egress use case.
- **DERP connectivity floor for no-region peers** — ✅ **shipped v0.8.1** (#24): a peer with no netmap
  home region was denied any underlay route; now the relay region is inferred (observed-route à la Go
  `c.derpRoute`, then home-region last resort). Listed here only as the most recent close.

A handful of **partial-by-design** items are NOT backlog (they are as-complete-as-they-can-be for our
deployment): client-side ACME is shipped but a self-hosted control plane 501s on `set-dns` (external,
old #10); TUN mode is shipped but userspace-only seams (`tcp_connect`/loopback) are `UnsupportedInTunMode`
by design (old #14); `listen_funnel` client leg is shipped but the public relay leg is Tailscale-operated
and external-blocked (old #16). These are environment limits, not engine work.

### Closed (shipped — verified in-tree at v0.8.1)

Tier 1 — ~~direct-path orchestration glue~~ (`direct.rs` `run_pinger`/`run_stun_prober`/`run_call_me_maybe`),
~~disco↔node-key binding~~ (`sock.rs` `BindingVerifier`, fail-closed; the `TODO(parity)` is gone),
~~musl static build + CI lane~~ (`ci.yml` `musl_static`, aws-lc-absence guard).
Tier 2 — ~~`config.tags`→`HostInfo.request_tags`~~ (`client.rs:298`, `register.rs`),
~~config-driven `ephemeral`~~ (`Config::ephemeral`), ~~upstream proxy dialer for the exit hop~~
(`ProxyExitDialer`, `ExitProxyConfig`), ~~netmap stream resumption~~ (`MapSession`/`advance_session`).
Tier 3 — ~~`tcp_buffer_size` knob~~ (default already 256 KiB; per-deployment `Config::tcp_buffer_size`).
Tier 4 — ~~Serve config + `RegisterFallbackTCPHandler`~~ (`ts_runtime/src/serve.rs` `ServeManager`),
~~bindings lane propagation~~ (FFI/Python/Elixir cover most `Device` methods, not the stale "~30%";
2026-10-14 row R20 lists what has no binding).
Tier 5 — ~~IPv6 on the tailnet (flag-gated)~~ (`Config::enable_ipv6`), ~~full MagicDNS server~~
(`magic_dns.rs`, `100.100.100.100:53` + exit-node DoH), ~~`ListenSSH`~~ (`src/ssh/`, feature-gated),
~~`ListenService`/VIP + ServiceMode~~ (consume only: runtime advertise and Go's ServiceMode TLS and
app-cap options are open, 2026-10-14 rows R4 and R5), ~~symmetric-NAT traversal~~ (Go has no
256-port spray; the hard-NAT `Stun4LocalPort` guess **is** implemented — at parity), ~~Taildrop~~,
~~key rotation~~, ~~metrics/observability~~, ~~WIF fields + `Sys()` accessors~~.

> Reclassified, not "done by us": old #10 (ACME) — real Tailscale has no `cert/<domain>` RPC; the node
> is the ACME client, which is shipped. Old #19 (birthday-paradox spray) — a real spray was rejected as
> a Go divergence + SSRF risk; matching Go's actual `Stun4LocalPort` tactic is the parity bar and is met.

## Cross-cutting doc-hygiene
- ~~Reconcile README DERP-vs-direct~~ — **done.** The README now states direct NAT traversal is
  real and DERP is the fallback used only when no direct path is available.
- ~~Clarify `fallback_resolvers`~~ — **done.** The README states fail-closed NXDOMAIN is the
  *default* and that configuring a resolver opts in to forwarding query names upstream.
- Security posture is now documented in full in [SECURITY.md](../SECURITY.md) (unaudited crypto, the
  active TKA enforcement and its remaining gaps, peerAPI capability gap, at-rest key handling,
  anti-leak posture).

## Invariants that must never regress
- Real origin IP must never leak; no silent direct-dial fallback (fail-closed is sacred).
- IPv4-only on the tailnet by default (bind `0.0.0.0`, never `::`); any IPv6 work is opt-in and must
  not weaken the deployment posture.
- Stay on `ring` for the tailnet/TLS path; confine `aws-lc-rs` to the optional `ssh` feature.
- Keep `panic=unwind` (actor model isolates per-flow panics; `panic=abort` would weaken isolation).
- Unaudited crypto is acceptable *only* because the deployer owns both ends (their control plane +
  their exits) and pins the capability version.
