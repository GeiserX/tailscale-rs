# Changelog

Record breaking or significant changes here. All dates are UTC.

## [0.36.0](https://github.com/GeiserX/tailscale-rs/compare/v0.35.8...v0.36.0) (2026-06-14)


### Features

* **runtime:** warn when self is locked out of the active network lock ([#210](https://github.com/GeiserX/tailscale-rs/issues/210)) ([df5c685](https://github.com/GeiserX/tailscale-rs/commit/df5c685f7e6d7652d0389fd20c3f1fe922ab1d62))


### Bug Fixes

* **derp:** document the intentional 64KiB inbound frame cap, drop dead const ([#208](https://github.com/GeiserX/tailscale-rs/issues/208)) ([7cbdb6e](https://github.com/GeiserX/tailscale-rs/commit/7cbdb6e1717863f5023e2cc032a28466cfe9dac3))

## [0.35.8](https://github.com/GeiserX/tailscale-rs/compare/v0.35.7...v0.35.8) (2026-06-14)


### Bug Fixes

* **taildrop:** serialize same-name transfers and refuse symlinked store paths ([#206](https://github.com/GeiserX/tailscale-rs/issues/206)) ([4064854](https://github.com/GeiserX/tailscale-rs/commit/4064854dad644720b4d66e1202154d0b2031836d))

## [0.35.7](https://github.com/GeiserX/tailscale-rs/compare/v0.35.6...v0.35.7) (2026-06-14)


### Bug Fixes

* **disco:** parse a pre-1.16 node-key-less Ping, drop it fail-closed ([#204](https://github.com/GeiserX/tailscale-rs/issues/204)) ([615757f](https://github.com/GeiserX/tailscale-rs/commit/615757f1abe4823cd7c4cdec757b770053b18d7a))

## [0.35.6](https://github.com/GeiserX/tailscale-rs/compare/v0.35.5...v0.35.6) (2026-06-14)


### Bug Fixes

* **dataplane:** always accept inbound TSMP, bypassing the ACL ([#200](https://github.com/GeiserX/tailscale-rs/issues/200)) ([353e56e](https://github.com/GeiserX/tailscale-rs/commit/353e56ecc9cfe444d2a8f7c98193322b810f961f))
* **derp:** send ClientInfo with Go's exact JSON wire keys ([#203](https://github.com/GeiserX/tailscale-rs/issues/203)) ([14244a5](https://github.com/GeiserX/tailscale-rs/commit/14244a544eda8646159ee4ee466a664642f2f906))
* **magicsock:** accept the alternate 0x8020 XOR-MAPPED-ADDRESS in STUN responses ([#202](https://github.com/GeiserX/tailscale-rs/issues/202)) ([d8df398](https://github.com/GeiserX/tailscale-rs/commit/d8df398809ab81ffe0cafa80fa4efff76c979834))

## [0.35.5](https://github.com/GeiserX/tailscale-rs/compare/v0.35.4...v0.35.5) (2026-06-14)


### Bug Fixes

* **dataplane:** drop multicast and link-local destinations before the ACL ([#198](https://github.com/GeiserX/tailscale-rs/issues/198)) ([6e257c8](https://github.com/GeiserX/tailscale-rs/commit/6e257c870eb0d3ab6dde14b81ae924ddcc0be451))

## [0.35.4](https://github.com/GeiserX/tailscale-rs/compare/v0.35.3...v0.35.4) (2026-06-13)


### Bug Fixes

* **netcheck:** apply preferred-DERP selection hysteresis to stop home-relay flapping ([#196](https://github.com/GeiserX/tailscale-rs/issues/196)) ([8cc6b4f](https://github.com/GeiserX/tailscale-rs/commit/8cc6b4f51d217bbed4412a3dbef8f2ccacf5553b))

## [0.35.3](https://github.com/GeiserX/tailscale-rs/compare/v0.35.2...v0.35.3) (2026-06-13)


### Bug Fixes

* **derp:** skip unknown frame types instead of tearing down the connection ([#194](https://github.com/GeiserX/tailscale-rs/issues/194)) ([22e4cc0](https://github.com/GeiserX/tailscale-rs/commit/22e4cc0eb3c333cb4f113a531aec71ccf96c6d45))

## [0.35.2](https://github.com/GeiserX/tailscale-rs/compare/v0.35.1...v0.35.2) (2026-06-13)


### Bug Fixes

* **tunnel:** do not arm the reactive keepalive on a received keepalive ([#190](https://github.com/GeiserX/tailscale-rs/issues/190)) ([6dbe36b](https://github.com/GeiserX/tailscale-rs/commit/6dbe36bf8cec715916db45c6933eadba8edd667c))

## [0.35.1](https://github.com/GeiserX/tailscale-rs/compare/v0.35.0...v0.35.1) (2026-06-13)


### Bug Fixes

* **runtime:** give the control runner an unbounded mailbox ([#188](https://github.com/GeiserX/tailscale-rs/issues/188)) ([c16da70](https://github.com/GeiserX/tailscale-rs/commit/c16da701131b677acd2a52db0c0b1bf7b8209a98))

## [0.35.0](https://github.com/GeiserX/tailscale-rs/compare/v0.34.2...v0.35.0) (2026-06-13)


### Features

* **tka:** cross-peer rotation-obsolete peer dropping ([#186](https://github.com/GeiserX/tailscale-rs/issues/186)) ([c145ddf](https://github.com/GeiserX/tailscale-rs/commit/c145ddf55c00c045c6a4119a0dce197f4554e784))
* **tka:** RotationDetails extraction for rotation-obsolete peer dropping ([#184](https://github.com/GeiserX/tailscale-rs/issues/184)) ([7c7f4ed](https://github.com/GeiserX/tailscale-rs/commit/7c7f4ed3a43f431744080ddcfd4b36ae81461574))

## [0.34.2](https://github.com/GeiserX/tailscale-rs/compare/v0.34.1...v0.34.2) (2026-06-13)


### Bug Fixes

* **taildrop:** verify full length before finalize; bound and truncate resume ([#182](https://github.com/GeiserX/tailscale-rs/issues/182)) ([440bb57](https://github.com/GeiserX/tailscale-rs/commit/440bb57f9d8c820aea20e2592055487f67b244df))

## [0.34.1](https://github.com/GeiserX/tailscale-rs/compare/v0.34.0...v0.34.1) (2026-06-13)


### Bug Fixes

* re-trigger release for the control-plane liveness and Cap parity fixes ([#180](https://github.com/GeiserX/tailscale-rs/issues/180)) ([18da4b8](https://github.com/GeiserX/tailscale-rs/commit/18da4b8f1dc9d99a36cfea06738352d9c7e36870))

## [0.34.0](https://github.com/GeiserX/tailscale-rs/compare/v0.33.0...v0.34.0) (2026-06-13)


### Features

* **tka:** enforce Tailnet Lock at the peer-trust chokepoint ([#176](https://github.com/GeiserX/tailscale-rs/issues/176)) ([2e581ac](https://github.com/GeiserX/tailscale-rs/commit/2e581ace187a27cde2f2d230d86a3b231d94499f))

## [0.33.0](https://github.com/GeiserX/tailscale-rs/compare/v0.32.0...v0.33.0) (2026-06-13)


### Features

* **tka:** genesis-checkpoint builder + Argon2i disablement_value (tsr-cfw) ([#173](https://github.com/GeiserX/tailscale-rs/issues/173)) ([e27a85c](https://github.com/GeiserX/tailscale-rs/commit/e27a85cad6e5d4e50c1577caa67b286911e20b9a))
* **tsnet:** Device::tka_init — initialize Tailnet Lock (tsr-cfw, epic complete) ([#175](https://github.com/GeiserX/tailscale-rs/issues/175)) ([6c31d8b](https://github.com/GeiserX/tailscale-rs/commit/6c31d8b48e564a05b1a981bb3551973a90157e6d))

## [0.32.0](https://github.com/GeiserX/tailscale-rs/compare/v0.31.0...v0.32.0) (2026-06-13)


### Features

* **control:** TKA mutation RPC client methods (tsr-cfw) ([#168](https://github.com/GeiserX/tailscale-rs/issues/168)) ([79bb19a](https://github.com/GeiserX/tailscale-rs/commit/79bb19a880f41fb44ad5fd35d00f8b8a63d571f2))
* **tka:** NodeKeySignature::sign_direct + TKA mutation RPC wire types (tsr-cfw) ([#167](https://github.com/GeiserX/tailscale-rs/issues/167)) ([29fcc27](https://github.com/GeiserX/tailscale-rs/commit/29fcc27a7ec1a7b341586d65d137694fb2b02cae))
* **tsnet:** add Device::http_connector for HTTP over the tailnet (tsr-6fw) ([#165](https://github.com/GeiserX/tailscale-rs/issues/165)) ([91b6184](https://github.com/GeiserX/tailscale-rs/commit/91b618413c19ec898f4587d3255f57f509f87869))
* **tsnet:** Device::tka_disable — submit the disablement secret (tsr-cfw) ([#170](https://github.com/GeiserX/tailscale-rs/issues/170)) ([40cc81d](https://github.com/GeiserX/tailscale-rs/commit/40cc81d4084b3c3036e5b2b31cbd985c1ed5e74a))
* **tsnet:** Device::tka_sign + NodeKeySignature::serialize (tsr-cfw) ([#169](https://github.com/GeiserX/tailscale-rs/issues/169)) ([d3e99cd](https://github.com/GeiserX/tailscale-rs/commit/d3e99cd1d8ee263c8735c7878351da688a22dbac))


### Bug Fixes

* **deps:** bump pyo3 0.28 -&gt; 0.29 to clear RUSTSEC-2026-0176/0177 (tsr-s0y) ([#171](https://github.com/GeiserX/tailscale-rs/issues/171)) ([8c10302](https://github.com/GeiserX/tailscale-rs/commit/8c103022202afdc6f94b45edb13bab0c3980b581))

## [0.31.0](https://github.com/GeiserX/tailscale-rs/compare/v0.30.1...v0.31.0) (2026-06-13)


### ⚠ BREAKING CHANGES

* **ts_tunnel:** zeroize WireGuard symmetric key material on drop (tsr-9nu) ([#164](https://github.com/GeiserX/tailscale-rs/issues/164))

### Features

* **tka:** add Aum::sign + pin the sign-&gt;verify round-trip KAT (tsr-cfw) ([#163](https://github.com/GeiserX/tailscale-rs/issues/163)) ([5ea65e1](https://github.com/GeiserX/tailscale-rs/commit/5ea65e194a694c308237f75a651be33e1bdaaf39))
* **ts_tunnel:** zeroize WireGuard symmetric key material on drop (tsr-9nu) ([#164](https://github.com/GeiserX/tailscale-rs/issues/164)) ([93f804d](https://github.com/GeiserX/tailscale-rs/commit/93f804d13735a17e2972e78380ac4779fecb727d))


### Bug Fixes

* **docs:** repair broken intra-doc links across the workspace; add exit-DNS antileak test ([#158](https://github.com/GeiserX/tailscale-rs/issues/158)) ([f43c51a](https://github.com/GeiserX/tailscale-rs/commit/f43c51ab8253fa4b95fdad0df78c52a63c5a9aef))
* **magicsock:** confirm the pinged path on any pong source (match Go; tsr-ugm) ([#160](https://github.com/GeiserX/tailscale-rs/issues/160)) ([3adbe4c](https://github.com/GeiserX/tailscale-rs/commit/3adbe4c2826e39483c2cc6a03b91171b297368d4))

## [0.30.1](https://github.com/GeiserX/tailscale-rs/compare/v0.30.0...v0.30.1) (2026-06-13)


### Bug Fixes

* **ffi:** null-check the parse entry points, fix IPv6 scope_id + recursion landmine ([#155](https://github.com/GeiserX/tailscale-rs/issues/155)) ([193e522](https://github.com/GeiserX/tailscale-rs/commit/193e5227cce97de8894802a0e28e1db71b546e26))
* **ffi:** null-safe slice conversion in tcp/udp send/recv ([#157](https://github.com/GeiserX/tailscale-rs/issues/157)) ([5545c2a](https://github.com/GeiserX/tailscale-rs/commit/5545c2a81e1f15b54caf57618b626b5991fd77e7))

## [0.30.0](https://github.com/GeiserX/tailscale-rs/compare/v0.29.3...v0.30.0) (2026-06-13)


### Features

* **runtime:** add Device::query_dns through the live MagicDNS forwarder ([#152](https://github.com/GeiserX/tailscale-rs/issues/152)) ([d737e08](https://github.com/GeiserX/tailscale-rs/commit/d737e08301d9af8a2964544cb9608b886c2f2daf))


### Bug Fixes

* **control:** bound control-plane response body reads against OOM ([#149](https://github.com/GeiserX/tailscale-rs/issues/149)) ([a4eed0d](https://github.com/GeiserX/tailscale-rs/commit/a4eed0d95cb9579d112e4cb69b6e9b61fb873a0a))
* **magicdns:** bound concurrent in-flight forwarded queries ([#148](https://github.com/GeiserX/tailscale-rs/issues/148)) ([190b08f](https://github.com/GeiserX/tailscale-rs/commit/190b08f0e3080e650b4cc83c52044f7a6167db2f))
* **tun:** read into an MTU-sized buffer so inbound packets aren't dropped ([#151](https://github.com/GeiserX/tailscale-rs/issues/151)) ([ef14d15](https://github.com/GeiserX/tailscale-rs/commit/ef14d153fc4c9d440c9a8a04a72d2720d4de24c4))

## [0.29.3](https://github.com/GeiserX/tailscale-rs/compare/v0.29.2...v0.29.3) (2026-06-12)


### Bug Fixes

* **bart:** correct lookup_prefix_lpm leaf match (was a self-comparison) ([#147](https://github.com/GeiserX/tailscale-rs/issues/147)) ([a397cf6](https://github.com/GeiserX/tailscale-rs/commit/a397cf68cbdec05eaf4f07fed447d47ef052ddc2))
* **control-noise:** bound the handshake-response read; exact record cap ([#145](https://github.com/GeiserX/tailscale-rs/issues/145)) ([0fb48c1](https://github.com/GeiserX/tailscale-rs/commit/0fb48c1520e25343c9f85bb1fdd89074b76ba374))
* **derp:** drop short PeerGone/RecvPacket frames instead of panicking ([#143](https://github.com/GeiserX/tailscale-rs/issues/143)) ([09f747d](https://github.com/GeiserX/tailscale-rs/commit/09f747d65d8cae3e24966a7e007982ea37099d1b))
* **disco:** per-type version handling instead of whole-packet reject ([#144](https://github.com/GeiserX/tailscale-rs/issues/144)) ([5728c82](https://github.com/GeiserX/tailscale-rs/commit/5728c828fa3750c45f735ae1fa3e54a8f7ec2af1))
* **forwarder:** add global cross-port concurrent-flow cap (all-port mode) ([#140](https://github.com/GeiserX/tailscale-rs/issues/140)) ([7deaf87](https://github.com/GeiserX/tailscale-rs/commit/7deaf870ffb87f755fe92921624df8a49fedbea3))
* **netcheck:** map dropped STUN transaction to TimedOut instead of panic ([#146](https://github.com/GeiserX/tailscale-rs/issues/146)) ([fdfc199](https://github.com/GeiserX/tailscale-rs/commit/fdfc1996b36cc59752e47201ccac997aab37d902))
* **netstack:** guard handle recycling (ABA) on blocked-command replay ([#138](https://github.com/GeiserX/tailscale-rs/issues/138)) ([a617deb](https://github.com/GeiserX/tailscale-rs/commit/a617deb5b7a45e11fb255b7c9a3aa2d0da502e1e))
* **netstack:** make drain_tcp_closes dedup-safe (no panic on a repeated handle) ([#142](https://github.com/GeiserX/tailscale-rs/issues/142)) ([e9d0e09](https://github.com/GeiserX/tailscale-rs/commit/e9d0e09d0bf38e81fb1eb916c2414fe5e09b0324))
* **netstack:** reclaim autonomously-Closed accepted sockets (tsr-9ue) ([#141](https://github.com/GeiserX/tailscale-rs/issues/141)) ([5eeb11a](https://github.com/GeiserX/tailscale-rs/commit/5eeb11ae5a7f3adc16369d4782648c509aa878aa))

## [0.29.2](https://github.com/GeiserX/tailscale-rs/compare/v0.29.1...v0.29.2) (2026-06-12)


### Bug Fixes

* **magicdns:** forward non-A/AAAA/PTR qtypes + non-IN class instead of REFUSED ([#136](https://github.com/GeiserX/tailscale-rs/issues/136)) ([b08ef4a](https://github.com/GeiserX/tailscale-rs/commit/b08ef4aecb2f6a5f72827fd445e3500c465bbdf2))

## [0.29.1](https://github.com/GeiserX/tailscale-rs/compare/v0.29.0...v0.29.1) (2026-06-12)


### Bug Fixes

* **control-serde:** decode Go-faithful EnvType, TpmInfo, MapResponse health/messages ([#131](https://github.com/GeiserX/tailscale-rs/issues/131)) ([0d9654b](https://github.com/GeiserX/tailscale-rs/commit/0d9654b22ec4580a1cf9ec45b37378fbe46a2772))
* **control-serde:** use Cow for escape-prone text fields so JSON escapes decode ([#132](https://github.com/GeiserX/tailscale-rs/issues/132)) ([3c0f47d](https://github.com/GeiserX/tailscale-rs/commit/3c0f47def8565abb9ad912a4ba1864da28517f96))
* **control:** surface mid-session re-auth URL instead of dropping it ([#134](https://github.com/GeiserX/tailscale-rs/issues/134)) ([a2a34d1](https://github.com/GeiserX/tailscale-rs/commit/a2a34d1f40b815f221ca6b2209be953b926b6999))
* **magicsock:** add best-addr hysteresis to stop direct-path flapping ([#135](https://github.com/GeiserX/tailscale-rs/issues/135)) ([6866f3c](https://github.com/GeiserX/tailscale-rs/commit/6866f3c217494cd06a3d89d008b87870840f8f73))

## [0.29.0](https://github.com/GeiserX/tailscale-rs/compare/v0.28.3...v0.29.0) (2026-06-12)


### Features

* **runtime:** add accept_dns client preference gating the MagicDNS responder ([#124](https://github.com/GeiserX/tailscale-rs/issues/124)) ([427d5e0](https://github.com/GeiserX/tailscale-rs/commit/427d5e06d3b3cfdc1f755484cc330c5559b5a214))
* **runtime:** add Device::cert_pair — export the ACME leaf+chain + key as PEM ([#129](https://github.com/GeiserX/tailscale-rs/issues/129)) ([b66eb5a](https://github.com/GeiserX/tailscale-rs/commit/b66eb5a01fdbe6ac91225b8a6a02fa1ae0c5af98))
* **tunnel:** zero-pad transport payloads to a 16-byte boundary before sealing ([#122](https://github.com/GeiserX/tailscale-rs/issues/122)) ([db0a1fa](https://github.com/GeiserX/tailscale-rs/commit/db0a1fa4701514395de7fc200407d7ce327468cd))


### Bug Fixes

* **forwarder:** complete the exit SSRF guard (multicast/class-E) and cap concurrent UDP flows ([#117](https://github.com/GeiserX/tailscale-rs/issues/117)) ([a6c1f22](https://github.com/GeiserX/tailscale-rs/commit/a6c1f22b98021a65e7d4eb69698951a434ad679d))
* **netstack:** propagate TCP half-close via a ShutdownWrite command ([#120](https://github.com/GeiserX/tailscale-rs/issues/120)) ([ba306d9](https://github.com/GeiserX/tailscale-rs/commit/ba306d9c90494f112242170126301b3a27c96d76))
* **runtime:** route the union of peer AllowedIPs into the TUN host FIB ([#127](https://github.com/GeiserX/tailscale-rs/issues/127)) ([1ed5303](https://github.com/GeiserX/tailscale-rs/commit/1ed53036594c130e691c7a2dd7bbf43d38552b71))
* **tunnel:** jitter handshake-initiation retransmits like wireguard-go ([#123](https://github.com/GeiserX/tailscale-rs/issues/123)) ([c7d27b4](https://github.com/GeiserX/tailscale-rs/commit/c7d27b45e431208bc9220cf7b28561d8c1fccd38))
* **tunnel:** match wireguard-go anti-replay window and message-count ceilings ([#121](https://github.com/GeiserX/tailscale-rs/issues/121)) ([9b5a858](https://github.com/GeiserX/tailscale-rs/commit/9b5a8588698b7fa92b16c5e890044b13e9d2aad4))

## [0.28.3](https://github.com/GeiserX/tailscale-rs/compare/v0.28.2...v0.28.3) (2026-06-12)


### Bug Fixes

* **disco:** parse over-length Pong and non-multiple CallMeMaybe laxly for Go interop ([#115](https://github.com/GeiserX/tailscale-rs/issues/115)) ([98dd6ea](https://github.com/GeiserX/tailscale-rs/commit/98dd6ea2f1d2dfa4b0a17b1e96cf5e01e452f46f))
* **packetfilter:** match ICMP and other portless protocols IPs-only like Go ([#113](https://github.com/GeiserX/tailscale-rs/issues/113)) ([fa7fac4](https://github.com/GeiserX/tailscale-rs/commit/fa7fac4952cb59b76eadbd6760b5411c2de38515))
* **tka:** resolve forks against the real replayed weight, not an empty state ([#116](https://github.com/GeiserX/tailscale-rs/issues/116)) ([8ff99fd](https://github.com/GeiserX/tailscale-rs/commit/8ff99fd20ec504a0148b0d6431b8487f00c410b5))

## [0.28.2](https://github.com/GeiserX/tailscale-rs/compare/v0.28.1...v0.28.2) (2026-06-12)


### Bug Fixes

* **control:** back off map-poll reconnects and watchdog the long-poll read ([#109](https://github.com/GeiserX/tailscale-rs/issues/109)) ([96f9d9f](https://github.com/GeiserX/tailscale-rs/commit/96f9d9f4c192ffee91d31847d60a31f830e8a2ea))
* **netcheck:** bound the derp-map measurement with a report deadline and per-probe timeout ([#112](https://github.com/GeiserX/tailscale-rs/issues/112)) ([9cb2bce](https://github.com/GeiserX/tailscale-rs/commit/9cb2bceaa2809772f3eb969f3527930b65313649))
* **netstack:** reap idle/half-open TCP sockets and bound the accept backlog ([#111](https://github.com/GeiserX/tailscale-rs/issues/111)) ([555ee11](https://github.com/GeiserX/tailscale-rs/commit/555ee11ec7e4baab6b79d9745616acdfb400cd20))

## [0.28.1](https://github.com/GeiserX/tailscale-rs/compare/v0.28.0...v0.28.1) (2026-06-11)


### Bug Fixes

* **magicsock:** bound addr_to_disco attribution map in lockstep with the learned cap (anti-amplification) ([#105](https://github.com/GeiserX/tailscale-rs/issues/105)) ([57083ba](https://github.com/GeiserX/tailscale-rs/commit/57083bae3989c96f1be192195f0c64f8fa7d29b6))
* **tunnel:** bound handshake retransmits at REKEY_ATTEMPT_TIME (give up after MAX_TIMER_HANDSHAKES) ([#107](https://github.com/GeiserX/tailscale-rs/issues/107)) ([a534944](https://github.com/GeiserX/tailscale-rs/commit/a534944652d42779d204401aac172799812eb12e))

## [0.28.0](https://github.com/GeiserX/tailscale-rs/compare/v0.27.0...v0.28.0) (2026-06-11)


### Features

* **device:** add Device::set_accept_routes() — runtime accept-routes toggle (tsnet parity) ([#101](https://github.com/GeiserX/tailscale-rs/issues/101)) ([abd32ee](https://github.com/GeiserX/tailscale-rs/commit/abd32ee97a372f80fa0cb096f1497c4f4366bd53))


### Bug Fixes

* **derp:** handle Health/Restarting frames as non-fatal + jittered reconnect backoff (tsnet parity) ([#103](https://github.com/GeiserX/tailscale-rs/issues/103)) ([5bb6a3d](https://github.com/GeiserX/tailscale-rs/commit/5bb6a3db9df362ef45da501bd84a4a2edfe308d1))
* **magicsock:** cap inbound CallMeMaybe endpoints (anti-amplification) ([#104](https://github.com/GeiserX/tailscale-rs/issues/104)) ([43e501d](https://github.com/GeiserX/tailscale-rs/commit/43e501d4bb391918f6d24aa897ef40d6635ef1ca))

## [0.27.0](https://github.com/GeiserX/tailscale-rs/compare/v0.26.0...v0.27.0) (2026-06-11)


### Features

* **device:** add Device::set_hostname() — runtime hostname change (tsnet parity) ([#97](https://github.com/GeiserX/tailscale-rs/issues/97)) ([8a1522a](https://github.com/GeiserX/tailscale-rs/commit/8a1522a139f745c279893d697d1256b55bf89f7d))
* **device:** add Device::watch_ipn_bus() — unified IPN notification stream (tsnet parity) ([#99](https://github.com/GeiserX/tailscale-rs/issues/99)) ([dbf4c66](https://github.com/GeiserX/tailscale-rs/commit/dbf4c661a24b8be4e04b42e3546dfa7a5f9b4ac5))
* **ipn-bus:** surface running-node PopBrowserURL + de-thrash the consent-URL cell (tsnet parity) ([#100](https://github.com/GeiserX/tailscale-rs/issues/100)) ([09244c0](https://github.com/GeiserX/tailscale-rs/commit/09244c04a148db356179df98058696e1fc94d57b))

## [0.26.0](https://github.com/GeiserX/tailscale-rs/compare/v0.25.0...v0.26.0) (2026-06-11)


### Features

* **whois:** match cap-grants with a node-capability source (SrcIp::NodeCap) ([#95](https://github.com/GeiserX/tailscale-rs/issues/95)) ([69ec39a](https://github.com/GeiserX/tailscale-rs/commit/69ec39af2659afacbc78f7168c55530ade3d0466))

## [0.25.0](https://github.com/GeiserX/tailscale-rs/compare/v0.24.0...v0.25.0) (2026-06-11)


### Features

* **device:** add Device::set_advertise_exit_node() — runtime /0 exit advertisement ([#93](https://github.com/GeiserX/tailscale-rs/issues/93)) ([4441dd2](https://github.com/GeiserX/tailscale-rs/commit/4441dd2e9f27ec20b9cbb544b91dd33f1598cdf1))

## [0.24.0](https://github.com/GeiserX/tailscale-rs/compare/v0.23.0...v0.24.0) (2026-06-11)


### Features

* **whois:** flow-scoped peer-capability grants (CapMap) — retain cap-grants end to end ([#91](https://github.com/GeiserX/tailscale-rs/issues/91)) ([8c0bbac](https://github.com/GeiserX/tailscale-rs/commit/8c0bbacb5f03ff7c0bb899680e8899d48fa60cea))

## [0.23.0](https://github.com/GeiserX/tailscale-rs/compare/v0.22.1...v0.23.0) (2026-06-11)


### Features

* **status:** populate PeerStatus.Relay — the DERP region code (completes direct-vs-relay) ([#89](https://github.com/GeiserX/tailscale-rs/issues/89)) ([1bb1d50](https://github.com/GeiserX/tailscale-rs/commit/1bb1d5022802fe553e606bf12076599434de9647))

## [0.22.1](https://github.com/GeiserX/tailscale-rs/compare/v0.22.0...v0.22.1) (2026-06-11)


### Bug Fixes

* **tunnel:** enforce REJECT_AFTER_MESSAGES — volume-aware rotation, non-panicking nonce ceiling ([#87](https://github.com/GeiserX/tailscale-rs/issues/87)) ([7ccc366](https://github.com/GeiserX/tailscale-rs/commit/7ccc3665e4aff872b38533304b74a21da97b62c9))

## [0.22.0](https://github.com/GeiserX/tailscale-rs/compare/v0.21.2...v0.22.0) (2026-06-11)


### Features

* **device:** add Device::ping_disco() — true on-demand disco ping with fresh RTT ([#85](https://github.com/GeiserX/tailscale-rs/issues/85)) ([f6b465d](https://github.com/GeiserX/tailscale-rs/commit/f6b465d7f93698bfeeccf1fa7de7d7e16caf4ad9))

## [0.21.2](https://github.com/GeiserX/tailscale-rs/compare/v0.21.1...v0.21.2) (2026-06-11)


### Bug Fixes

* **tka:** match Go's rotation/credential verify — recurse wrapping key, drop synthetic pubkey bind ([#83](https://github.com/GeiserX/tailscale-rs/issues/83)) ([1f91f03](https://github.com/GeiserX/tailscale-rs/commit/1f91f03ab66cdfe4fbadd69013b11d8c786cacc2))

## [0.21.1](https://github.com/GeiserX/tailscale-rs/compare/v0.21.0...v0.21.1) (2026-06-11)


### Bug Fixes

* **keys,http:** stop panicking on malformed control wire input (parse errors, not unwinds) ([#81](https://github.com/GeiserX/tailscale-rs/issues/81)) ([0a4970f](https://github.com/GeiserX/tailscale-rs/commit/0a4970f069fbe977436a801c69e763c743e7eb0f))

## [0.21.0](https://github.com/GeiserX/tailscale-rs/compare/v0.20.0...v0.21.0) (2026-06-11)


### Features

* **device:** add Device::direct_path() — underlay direct path + RTT (tsnet parity) ([#79](https://github.com/GeiserX/tailscale-rs/issues/79)) ([a187d00](https://github.com/GeiserX/tailscale-rs/commit/a187d0064130d4ce37196a1e992103e2024db565))

## [0.20.0](https://github.com/GeiserX/tailscale-rs/compare/v0.19.0...v0.20.0) (2026-06-11)


### Features

* **status:** surface per-peer current direct endpoint (CurAddr) in Status ([#77](https://github.com/GeiserX/tailscale-rs/issues/77)) ([6dc0d30](https://github.com/GeiserX/tailscale-rs/commit/6dc0d30d83fc7c523fd16d38937f4d3a224a4c9d))

## [0.19.0](https://github.com/GeiserX/tailscale-rs/compare/v0.18.2...v0.19.0) (2026-06-11)


### Features

* **device:** add Device::set_advertise_routes() runtime EditPrefs (tsnet parity) ([#75](https://github.com/GeiserX/tailscale-rs/issues/75)) ([def7e46](https://github.com/GeiserX/tailscale-rs/commit/def7e46981e98e68bb6dd2d87da7354822f77edb))

## [0.18.2](https://github.com/GeiserX/tailscale-rs/compare/v0.18.1...v0.18.2) (2026-06-11)


### Bug Fixes

* **control:** apply peers_changed_patch alongside a co-occurring full/delta peer set ([#72](https://github.com/GeiserX/tailscale-rs/issues/72)) ([587e2ae](https://github.com/GeiserX/tailscale-rs/commit/587e2ae315a0102731ac09890e64ea6cfd03b3c1))

## [0.18.1](https://github.com/GeiserX/tailscale-rs/compare/v0.18.0...v0.18.1) (2026-06-11)


### Bug Fixes

* **derp:** keep home region sticky on same-region re-measure; stop connect() panicking on transient failures ([#69](https://github.com/GeiserX/tailscale-rs/issues/69)) ([2a15b18](https://github.com/GeiserX/tailscale-rs/commit/2a15b18143e17f9da619d80b6c7a5014126f30e5))
* **magicsock:** re-ping direct paths before trust lapses; bound the in-flight ping map ([#71](https://github.com/GeiserX/tailscale-rs/issues/71)) ([e7afad9](https://github.com/GeiserX/tailscale-rs/commit/e7afad93997708148746224c05031cc0ddf126e1))

## [0.18.0](https://github.com/GeiserX/tailscale-rs/compare/v0.17.0...v0.18.0) (2026-06-11)


### Features

* **device:** add set_dns, dial_udp, and pop_browser_url accessors (tsnet parity) ([#68](https://github.com/GeiserX/tailscale-rs/issues/68)) ([5f8e5d1](https://github.com/GeiserX/tailscale-rs/commit/5f8e5d103ee7cbe0dd0fd3888733bd9854887abe))


### Bug Fixes

* **tunnel,control:** bound netmap/control frames, reject equal-timestamp handshake replay ([#66](https://github.com/GeiserX/tailscale-rs/issues/66)) ([4aaac31](https://github.com/GeiserX/tailscale-rs/commit/4aaac31f65430cc1e4d7356b981b7dc2c942753e))

## [0.17.0](https://github.com/GeiserX/tailscale-rs/compare/v0.16.0...v0.17.0) (2026-06-11)


### Features

* **tsnet:** shields-up (block_incoming) — refuse inbound peer connections ([#63](https://github.com/GeiserX/tailscale-rs/issues/63)) ([b4fdb9e](https://github.com/GeiserX/tailscale-rs/commit/b4fdb9e23a5be818a3ab2494e2d960b4ce387b73))

## [0.16.0](https://github.com/GeiserX/tailscale-rs/compare/v0.15.0...v0.16.0) (2026-06-11)


### Features

* **ts_runtime:** TKA verify-and-log seam in peer_tracker ([#136](https://github.com/GeiserX/tailscale-rs/issues/136), observe-only) ([#62](https://github.com/GeiserX/tailscale-rs/issues/62)) ([acc70ee](https://github.com/GeiserX/tailscale-rs/commit/acc70eea3ba39516faf5f0927e324aa83bf98a61))
* **tsnet:** Device::netcheck() net-report accessor (Go netcheck.Report / tnet netcheck) ([#60](https://github.com/GeiserX/tailscale-rs/issues/60)) ([e30a4be](https://github.com/GeiserX/tailscale-rs/commit/e30a4be26a1cc795f3414858eeb6cc344cee40e5))

## [0.15.0](https://github.com/GeiserX/tailscale-rs/compare/v0.14.0...v0.15.0) (2026-06-10)


### Features

* **tsnet:** Device::dns_config() accessor (Go nm.DNS / tnet dns status) ([#59](https://github.com/GeiserX/tailscale-rs/issues/59)) ([7a4ff31](https://github.com/GeiserX/tailscale-rs/commit/7a4ff3144cd5e156ad7dc0c1a97c435abd018c53))


### Bug Fixes

* **release:** bump inter-crate pins to 0.14.0 + auto-bump them in future releases ([#57](https://github.com/GeiserX/tailscale-rs/issues/57)) ([a33e5bc](https://github.com/GeiserX/tailscale-rs/commit/a33e5bcbce036773bf684e16f0532899f49d0e86))

## [0.14.0](https://github.com/GeiserX/tailscale-rs/compare/v0.13.0...v0.14.0) (2026-06-10)


### Features

* **ts_control:** /machine/tka/bootstrap Noise RPC (genesis AUM fetch) ([#55](https://github.com/GeiserX/tailscale-rs/issues/55)) ([2e51d5e](https://github.com/GeiserX/tailscale-rs/commit/2e51d5e6cfe61cd7ed3d4b73554e7f47fc9b4806))
* **ts_runtime:** wire TKA bootstrap+sync into ControlRunner (observe-only) ([#56](https://github.com/GeiserX/tailscale-rs/issues/56)) ([5f42811](https://github.com/GeiserX/tailscale-rs/commit/5f42811ae08e459de67ff716f6418542e76289ea))

## [0.13.0](https://github.com/GeiserX/tailscale-rs/compare/v0.12.0...v0.13.0) (2026-06-10)


### ⚠ BREAKING CHANGES

* **ts_keys:** zeroize private keys on drop, drop Copy (tsr-9nu) ([#39](https://github.com/GeiserX/tailscale-rs/issues/39))

### Features

* **runtime:** add Device::file_targets() Taildrop send-target enumeration ([#47](https://github.com/GeiserX/tailscale-rs/issues/47)) ([b0bcb13](https://github.com/GeiserX/tailscale-rs/commit/b0bcb13ea8d667001f1e8aad8ca1e7fb1d89fae1))
* **status:** retain per-peer online/last_seen (Go PeerStatus.Online) ([#45](https://github.com/GeiserX/tailscale-rs/issues/45)) ([651d091](https://github.com/GeiserX/tailscale-rs/commit/651d09193f1a01efbc06b5ec9253b8a8b5fd3145))
* **ts_control:** /machine/tka/sync Noise RPC client (offer + send) ([#50](https://github.com/GeiserX/tailscale-rs/issues/50)) ([08b22e1](https://github.com/GeiserX/tailscale-rs/commit/08b22e14e9463b97bb77a90439d16d60010c6c71))
* **ts_keys:** zeroize private keys on drop, drop Copy (tsr-9nu) ([#39](https://github.com/GeiserX/tailscale-rs/issues/39)) ([bf429a0](https://github.com/GeiserX/tailscale-rs/commit/bf429a09b44b8df952727aaf03c44b7f2d90a36b))
* **ts_tka:** AUM-chain sync — store + SyncOffer + MissingAUMs ([#49](https://github.com/GeiserX/tailscale-rs/issues/49)) ([1666319](https://github.com/GeiserX/tailscale-rs/commit/1666319e18924db1f88f7e4f8aa3727fa392a3a7))
* **ts_tka:** decode AUMs from CBOR (Aum::from_cbor) ([#48](https://github.com/GeiserX/tailscale-rs/issues/48)) ([e753e05](https://github.com/GeiserX/tailscale-rs/commit/e753e054db0148f3584cbc8758c7fc61da2b17de))
* **ts_tka:** port Go StaticValidate cluster + last-key guard (consensus parity) ([#41](https://github.com/GeiserX/tailscale-rs/issues/41)) ([25e604c](https://github.com/GeiserX/tailscale-rs/commit/25e604c33e6b465f7e3388056982098b9d1db932))
* **ts_tka:** type-enforce AUM signature verification (VerifiedAumChain, [#7](https://github.com/GeiserX/tailscale-rs/issues/7) MUST-1) ([#40](https://github.com/GeiserX/tailscale-rs/issues/40)) ([5c6747f](https://github.com/GeiserX/tailscale-rs/commit/5c6747f61b45c877ef47946a184959a54c0bfa99))
* **tsnet:** Device::dial/dial_tcp/listen_packet string-address entry points ([#42](https://github.com/GeiserX/tailscale-rs/issues/42)) ([6e7a3d9](https://github.com/GeiserX/tailscale-rs/commit/6e7a3d9276a6f00f7ddd97eeb8c2ac63de4a5073))
* **tsnet:** TailscaleIPs/CertDomains/MagicDNSSuffix self-identity accessors ([#44](https://github.com/GeiserX/tailscale-rs/issues/44)) ([2f065cd](https://github.com/GeiserX/tailscale-rs/commit/2f065cd7d20aff45d57246c87c7fd6cc1baeb490))


### Bug Fixes

* **tsnet:** bind UDP local socket on the remote's address family (dial/listen_packet) ([#46](https://github.com/GeiserX/tailscale-rs/issues/46)) ([719d18b](https://github.com/GeiserX/tailscale-rs/commit/719d18b1b83e87a953e094a11b28127d0bd868bb))

## [0.13.0](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.13.0) - 2026-06-10

### Security
- **Private keys now zeroize on drop and are no longer `Copy` (tsr-9nu).** The private-key newtypes
  (`NodePrivateKey`, `MachinePrivateKey`, `DiscoPrivateKey`, `NetworkLockPrivateKey` — and the
  keypairs that embed them) now derive `zeroize::ZeroizeOnDrop`, so their 32-byte secret is wiped
  from memory when the last owner drops, and they **drop `Copy`** so the secret can no longer be
  silently bit-copied to scattered stack/heap locations the zeroizer can never reach. This makes
  the `NodeState`/`PersistState` doc promise ("the dedicated key types are zeroized in memory on
  drop") actually true — previously the types had no `Drop` at all. Public keys are unchanged: they
  keep `Copy` and the full `zerocopy` (`FromBytes`/`IntoBytes`) wire surface, because they are not
  secret. Mirrors Go's `key` package, where private-key material is held in non-copied value types
  and a private key's `Public()` derivation takes a pointer receiver.
  - **Breaking (minor, source-level):** `*PrivateKey: Copy` is removed and `PrivateKey::public_key()`
    now takes `&self` instead of `self`. Existing `key.public_key()` calls are unaffected (the
    receiver widened). Code that *relied* on implicit copies of a private key must now `.clone()`
    explicitly. Private keys are also no longer `zerocopy::FromBytes`/`IntoBytes`; construct them
    from a `[u8; 32]` via `From<[u8; 32]>` (or `FromStr`) rather than `read_from_bytes`.
  - No new dependency (zeroize was already a dep for the ACME key; only its `derive` feature is
    added). Adds a behavioral regression test that `Zeroize::zeroize` wipes the secret to zero.

## [0.12.0](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.12.0) - 2026-06-10

### Added
- **`Device::rebind()`** — re-bind the underlay UDP socket after a network/link change (Wi-Fi
  switch, sleep/wake), the Rust analog of Go magicsock's `Conn.Rebind()` + `resetEndpointStates`
  (daemon ask #4 / tsr-9cs). The embedder owns *when* to call it (it watches the OS for link
  changes — there is no built-in monitor); the engine re-binds the socket (same-port-preferred →
  ephemeral fallback, IPv4-only invariant preserved) and invalidates the stale local NAT mapping:
  learned reflexive (STUN) addresses and every peer's *confirmed* direct path are cleared while
  candidate endpoints are kept, so peers re-probe over the new socket and relay over DERP (never a
  direct host dial) until a path re-confirms. Peers, control, the netmap, disco keys, and DERP are
  untouched; WireGuard sessions survive. No-op when the underlay is inert (DERP-only). Internally
  `MagicSock`'s socket moved behind a `Mutex<Arc<UdpSocket>>` (the `RebindingUDPConn` pattern) so the
  swap is atomic; no new dependency. New public API → minor bump.

## [0.11.0](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.11.0) - 2026-06-10

### Fixed
- **Receive-triggered rekey (#26), and the receive expiry tightened 240→180s.** The fork previously
  rekeyed only on outbound `Peer::send`, so a mostly-inbound, send-idle session had nothing to
  refresh its keys — which forced a lenient 240s receive expiry (`REJECT_AFTER_TIME_RECV`) instead of
  the spec 180s. Added receive-triggered rekey mirroring Go wireguard-go's `keepKeyFreshReceiving`:
  on a successfully-decrypted inbound packet, if **we were the initiator** of the current keypair and
  it is older than 165s (`RejectAfterTime − KeepaliveTimeout − RekeyTimeout`), enqueue a fresh
  handshake — **initiator-only** (the responder must not, or both ends initiate at once), one-shot
  per keypair. With this in place an inbound session rehandshakes ~15s before its keys hard-expire, so
  `REJECT_AFTER_TIME_RECV` is now the spec `REJECT_AFTER_TIME` (180s). The Go handshake KAT stays
  byte-exact.
- **Tailnet-Lock `AumState` nil-vs-empty CBOR (Go interop).** A checkpoint with a nil
  `DisablementValues`/`Keys` must encode as CBOR null `0xf6` (Go), not an empty array `0x80`; the
  divergence changed the checkpoint `Hash`/chain head vs Go on the replay path (the shipped verify
  path was never affected). Found by a crypto audit cross-validating AUM `Hash`/`SigHash`/`Serialize`
  against a real Go run.

### Changed (source-breaking → minor bump)
- **`tka::AumState.{disablement_values,keys}` are now `Option<Vec<…>>`** (were `Vec<…>`), so a nil
  slice (Go's zero value) is representable and encodes as CBOR null — fixing the interop bug above.
  `None` = Go nil = `0xf6`; `Some(vec)` = array.

### Added / internal
- ts_tka crypto audit: a Go-produced `AUM.Hash`/`SigHash`/`Serialize` golden + the
  `aum_hash_sighash_matches_go_golden` KAT (closes the prior "no Go `AUM.Hash()` pinned" gap);
  `CRYPTO_VERIFICATION_STATUS.md`/`CRYPTOGRAPHY.md` axis B updated.
- Two review-code! passes' fixes (observed-route learning extracted + tested; doc/comment
  clarifications) and a clearer exit-node "not full-tunnel" warning + `Config::exit_node` doc note
  distinguishing full-tunnel egress from reaching a peer's port.

## [0.10.0](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.10.0) - 2026-06-10

### Fixed
- **Handshake no longer rejected for a non-zero `mac2` (cookie MAC) (#23).** `MACReceiver::verify_macs`
  rejected any inbound handshake carrying a non-zero `mac2`. Per WireGuard, a peer sends a non-zero
  `mac2` when replying to a `CookieReply` the receiver issued under load — so this deterministically
  failed the handshake for a correct peer that sends `mac2`, a real interop bug that can surface as
  `handshake failed to complete`. This fork's responder never issues `CookieReply`s (it holds only a
  `mac1_key`, no cookie secret/state), so it has nothing to verify `mac2` against: the WireGuard-correct
  behavior is `mac1` is the authenticator, `mac2` is ignored — matching wireguard-go (checks `mac2`
  only when `UnderLoad`) and boringtun (only while a cookie is active). `mac1` verification is
  unchanged. The Go handshake KAT still passes byte-for-byte.

### Added
- **`tka::Authority::from_chain` / `from_forked_chain` — the AUM-chain replayer (#7).** Derives a
  trusted-key `State`/`Authority` by replaying a chain of `Aum`s (chunk 1A, v0.9.0, added the `Aum`
  type + byte-exact CBOR). `apply_verified_aum` folds each AUM (Go `State.applyVerifiedAUM`:
  parent-hash chain check, genesis-kind guard, per-kind key mutation, checkpoint StateID match);
  `pick_next_aum` resolves a fork by Go `tka.pickNextAUM`'s rules (signature weight → `RemoveKey`
  preference → lowest hash) — a total, deterministic comparator so all nodes select the same active
  branch; `weight` sums distinct trusted signers' votes. The consensus logic was reviewed
  rule-by-rule against Go v1.100.0. No production caller yet (the verify-and-log seam + the
  `/machine/tka/sync` RPC are the remaining #7 chunks); the client verify path is unchanged. Minor
  bump (additive public API).

## [0.9.0](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.9.0) - 2026-06-10

### Added
- **`tka::Aum` + `AumKey`/`AumState`/`AumSignature`** — the acquisition-side AUM (Authority Update
  Message) type and its canonical CBOR serialization, mirroring Go `tka.AUM`/`tka.Key`/`tka.State`/
  `tkatype.Signature`. `Aum::serialize`/`hash`/`sig_hash` match Go `AUM.Serialize`/`Hash`/`SigHash`
  byte-for-byte (BLAKE2s-256 over CTAP2 CBOR; `sig_hash` omits the signatures field). This is the
  first chunk of Tailnet-Lock verify-and-log (#7) — the prerequisite for the chain replayer that
  will derive a trusted-key `Authority` from a control-synced chain. The client verify path
  (`Authority::node_key_authorized`) is unchanged.
- Byte-exactness is **proven, not assumed**: new tests reproduce the literal `[]byte` vectors from Go
  `tka/aum_test.go` `TestSerialization` and assert identical canonical bytes. (This caught a real
  encoding subtlety — a non-`omitempty` nil `[]byte` field encodes as CBOR null `0xf6`, not an empty
  byte string.) Both the `NodeKeySignature` and `Aum` CBOR paths are now cross-validated against Go.

### Changed (source-breaking → minor bump)
- **`tka::cbor::Value` gains `Null` and `TextMap` variants.** The enum is public and not
  `#[non_exhaustive]`, so an external exhaustive `match` on it must add arms — hence a minor bump.
  `Null` encodes CBOR null (`0xf6`) for nil non-`omitempty` fields; `TextMap` encodes
  `map[string]string` with CTAP2 bytewise-lexical key ordering.

## [0.8.1](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.8.1) - 2026-06-10

### Fixed
- **Peers with no netmap DERP home region are now reachable over DERP (#24).** A peer whose netmap
  entry carried no home region (`derp_region == None`) was given **no underlay route at all** — the
  route updater skipped it, so the outbound router dropped every WireGuard packet to it, handshake
  included. The failure was symmetric (the dataplane's only egress is the underlay route table, so we
  could neither initiate to nor respond to such a peer) and presented as a 30s dial timeout. This is
  the live blocker for routing through a NAT'd peer on a self-hosted control plane (e.g. Headscale)
  that doesn't echo `preferred_derp`. DERP is the connectivity floor in Tailscale; this restores it.
  When the netmap supplies no region, the relay region is now inferred — mirroring Go magicsock's
  `c.derpRoute`: an **observed route** (a region we have actually received a DERP frame from the peer
  on — it is demonstrably listening there), else our **own current home region** as a bounded,
  interop-safe last resort (it rendezvouses a co-regional peer even when control never echoes the
  peer's region; if the peer is not on that region the DERP server simply drops the relayed frame —
  no host dial, no leak). The inference is gated on the region having a live transport task and is
  consulted both for the WireGuard underlay route and for the `CallMeMaybe` direct-path prompt, so a
  no-region peer also gets its direct-path upgrade attempted instead of being silently skipped.
  Anti-leak posture preserved: the inferred region only ever resolves to a DERP transport (never the
  direct host-dial path). Observed routes are pruned to the live netmap. Patch bump (internal
  route-layer change; no public API change).

## [0.8.0](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.8.0) - 2026-06-10

### Added
- **`Device::new_with_secret(&Config, Option<secrecy::SecretString>)`** — a back-compat secret-typed
  constructor for embedders that hold the registration auth key as a `secrecy::SecretString` (e.g. a
  daemon that keeps the key zeroized end-to-end). The caller no longer has to expose the secret into
  a plain `String` at the engine boundary. `Device::new(Option<String>)` is unchanged. The engine
  still resolves the key to a `String` internally for registration (so this closes the *caller's*
  plaintext window, not the engine's internal handling — engine-side key zeroization is tracked
  separately). Adds a `secrecy` dependency (pure-Rust, no aws-lc/openssl/ring — the ring-only egress
  invariant is preserved) and re-exports `tailscale::SecretString`. Minor bump (additive public API).
- **`docs/LIVE_SETTABLE_PREFS.md`** — documents which `Device` prefs are mutable on a running device
  (`set_exit_node`, `set_serve_config`, `logout`) vs which require a `Device::new` rebuild.

## [0.7.3](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.7.3) - 2026-06-10

### Fixed (security)
- **SSH session-recording policy is now enforced (closed a silent bypass).** The SSH server
  (`ssh` feature) parsed an `SSHAction`'s `recorders` / `on_recording_failure` / `hold_and_delegate`
  off the wire but dropped them in the domain conversion, so a control policy demanding *"record this
  session or refuse it"* was silently downgraded to a plain accept. Those fields are now carried into
  the domain action, and the server applies a **fail-closed gate**: when a matched rule requires
  recording (non-empty `recorders`) but no recorder transport is available, the session is **refused**
  (with the policy's `reject_session_with_message` if set). This matches Go `tailssh`'s posture when
  reject-on-failure is configured — a turnkey server with no recorder can only honor a record-required
  policy by refusing. A rule carrying `hold_and_delegate` (check-mode) is likewise not silently
  accepted. The common no-recording path (empty `recorders`) is unchanged. *Deferred to a follow-up:*
  the recorder transport itself (dial recorders + asciinema/CastV2 PTY stream), after which the
  interim fail-closed relaxes to Go's fail-open-unless-reject-on-failure default; and the
  `hold_and_delegate` delegate round-trip.

## [0.7.2](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.7.2) - 2026-06-10

### Fixed
- **Session-lifetime correctness (internal; no public API change).** Four fixes surfaced during the
  #20/#21 handshake-race review:
  - **`confirm()` now bounds the tentative responder session** — it takes the current time and
    rejects (returns `None`, slot intact, no id leak) when the not-yet-confirmed responder session
    is past its receive expiry, so a delayed or replayed (but still AEAD-valid) transport packet can
    no longer activate a stale responder session arbitrarily later. Mirrors WireGuard bounding a
    not-yet-confirmed keypair by the reject-after time on the receive path.
  - **`get_recv` previous-session expiry fix** — the `recv_prev` branch checked the *current*
    session's expiry instead of the previous one's, so it could return an expired previous session
    (or drop a still-valid one).
  - **Receive-session id leak fixed** — when a transmit session expired and the session state reset,
    the receive sessions were dropped without freeing their ids from the id map (an unreclaimable
    leak that accumulates on long-lived hosts). The reset now routes through the id-freeing path.
  - **WireGuard timer constants** — the inline `120`/`240`-second magic numbers are now named
    `REKEY_AFTER_TIME` (120s) and `REJECT_AFTER_TIME` (180s, the spec value), applied to the
    transmit side (self-correcting: an outbound send past this age triggers a fresh handshake). The
    receive bound is deliberately kept at a more lenient `REJECT_AFTER_TIME_RECV` (240s): this fork
    triggers rekey only on outbound traffic (no receive-triggered rekey yet), so a strict 180s
    receive bound would silently drop inbound traffic on a send-idle, mostly-inbound session.
    Tightening the receive bound to 180s is gated on adding a receive-triggered rekey.

## [0.7.1](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.7.1) - 2026-06-10

### Fixed
- **Simultaneous-initiation handshake race no longer wedges relay-only peers (closes #20).** Two
  peers reachable only via a DERP relay (no direct path) that initiated at the same cadence
  deterministically failed to ever complete a handshake: `Handshake::respond` unconditionally
  overwrote an in-flight `Initiated` with `Responded`, so the peer's later `HandshakeResponse` failed
  `finish()`'s state guard → `handshake failed to complete` + `session not found` looped every ~5.5s
  forever. A direct path's timing jitter masks this; a relay-only idle path removes the jitter and the
  race becomes the steady state. Fixed by mirroring canonical WireGuard (wireguard-go / boringtun /
  kernel — none of which use a deterministic public-key tie-break, which would be interop-unsafe):
  the per-peer handshake now retains **both** an in-flight initiator slot **and** a responder slot at
  once, so an inbound initiation no longer destroys our pending one. Both handshakes complete; the
  responder session stays provisional (send-disabled) until a confirming transport packet; the
  existing receive-session rotation converges them. We always respond to a peer's `msg1`, so interop
  with real wireguard-go/Tailscale/kernel peers is unchanged (the Go transport-key KAT still passes
  byte-for-byte). Internal change only — no public API change.

## [0.7.0](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.7.0) - 2026-06-09

### Added
- **Persistent-keepalive (per-peer, default 25s, opt-in) + a periodic dataplane tick, so an idle
  DERP-relayed session no longer wedges.** A purely event-driven WG endpoint advances its timers
  only on packet send/recv, so an idle tunnel went silent ~10s after the last packet and the
  dataplane then blocked forever on I/O with no timer wakeup; the NAT/relay mapping went cold and
  the next dial could never re-handshake (504 until process restart). Two parts, both required:
  (1) a per-peer persistent keepalive that re-arms **unconditionally** (not gated on inbound
  traffic) and, after a full interval of *outbound* silence, emits one empty authenticated data
  packet to hold the path/NAT/relay mapping warm — it fires at or before the interval (no upward
  jitter) to stay under the ~30s UDP NAT floor, and does **not** advance the data-sent timers; and
  (2) a clock-driven periodic tick that services the endpoint even with zero traffic, so the
  keepalive timer actually fires on a truly idle tunnel. Opt-in via the new
  **`PeerConfig::persistent_keepalive_interval: Option<Duration>`** (mirroring Tailscale's per-peer
  `KeepAlive=true` → 25s for relayed/exit peers); `None` preserves the prior purely-reactive
  behavior. **API note:** this **adds a public field to `PeerConfig`** (and threads through
  `Config`) — a source-visible, non-breaking API addition, hence the **minor** version bump
  (0.6.10 → 0.7.0). Scope: this fixes the idle→dial case; it does **not** make rekey timer-driven, so
  a tunnel kept alive *solely* by keepalives with zero application traffic past `REKEY_AFTER_TIME`
  is a separate, not-yet-addressed case (see `docs/IDLE-WEDGE-RESEARCH.md`).

### Verification / hardening (no runtime behavior change)
- **Cryptographic-verification tooling.** Added a direct **BLAKE2s-256 known-answer test** (the one
  primitive previously lacking a direct KAT — 8 unkeyed + 7 keyed vectors incl. the 16-byte
  `Blake2sMac<U16>` cookie-MAC short-key path), a **dudect constant-time leakage-detection bench**
  over the AEAD tag-verify path (informational, not CI-gated), a **`cargo-fuzz` target for the
  Tailnet-Lock CBOR decoder** plus a stable-CI smoke test asserting the panic-free / fail-closed
  invariant and a Go `fxamacker/cbor` differential oracle, and **`docs/CRYPTO_VERIFICATION_STATUS.md`**
  (a four-axis framing: artifact authenticity / implementation correctness / protocol security /
  side-channel). Reconciled `docs/CRYPTOGRAPHY.md` §6 with the lockfile (the data plane rides
  `x25519-dalek 3.0.0-rc.0` → `curve25519-dalek 5.0.0-rc.0`, not the previously-documented 4.1.3).

## [0.6.10](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.6.10) - 2026-06-09

### Fixed
- **Incremental peer patches (`MapResponse.peers_changed_patch`) are now applied instead of
  dropped.** The map-stream decoder logged and discarded these patches, so the per-peer updates
  control sends mid-session — chiefly a peer's UDP endpoints and home DERP region when an idle peer
  re-establishes connectivity — never reached the netmap. magicsock kept stale endpoints and could
  not re-handshake the moved peer, wedging idle sessions. Patches now surface as a new
  `PeerUpdate::Patch` and are merged in the peer tracker: each patch is looked up by node id (an
  unknown id is ignored — a patch never creates a node), only the fields it carries are merged onto
  the existing node, and the tailnet-lock gate is re-run before upsert so a key-rotation patch
  cannot bypass TKA (a patch whose new signature fails verification evicts the peer, fail-closed). A
  full/delta resync in the same response still takes precedence.
- **macOS TUN bring-up no longer fails with "No such file or directory (os error 2)".** The host
  networking layer invoked `route(8)` at `/usr/sbin/route`, which is the Linux/iproute2 location and
  does not exist on macOS (macOS ships `route(8)` in `/sbin`). The missing binary made every route
  installation fail with `ENOENT`, which the TUN actor treats as fatal and fail-closes — so the TUN
  interface never came up. Corrected to `/sbin/route`. (`scutil(8)` was already correct.)

## [0.6.9](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.6.9) - 2026-06-09

### Fixed
- **Netmap decode now tolerates `null` for every sequence/map field (Go `omitempty` ↔ Rust).** Go
  marshals empty slices/maps as JSON `null`, so a control plane (notably an IPv6-off Headscale)
  sends `null` for array fields the client modeled as required sequences — failing the netmap decode
  with `invalid type: null, expected a sequence`/`expected a map` and looping the map-poll stream
  forever. v0.6.8 fixed only `Node.addresses`; this is the systematic pass. Rather than annotate
  each field (the per-field approach is what let the gap recur), `null` tolerance is now applied at
  the **struct level** via `#[serde_with::apply]` on every type on the deserialized netmap path —
  `Node`, `MapResponse`, `DNSConfig`/`Resolver`, `DerpMap`/`Region`/`HomeParams`, `SSHPolicy` and
  its nested rules, `ControlDialPlan`, and the `ts_packetfilter_serde` filter/cap-grant types — so
  any `Vec`/map field added later is covered automatically. `null`, `[]`/`{}`, and a populated
  container are accepted interchangeably; `Option<…>` fields (whose `null`/absence means *unchanged
  from the prior poll*, e.g. `peers`, `packet_filter` singular) are deliberately left untouched.
  Regression tests decode a full `MapResponse` + peer `Node` + `DNSConfig`, a DERP map, an SSH
  policy, a packet filter, and a dial plan with `null` everywhere a sequence/map is expected.

## [0.6.8](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.6.8) - 2026-06-09

### Fixed
- **Netmap deserialization against IPv4-only control planes.** `Node.Addresses` was modeled as a
  fixed 2-tuple `(Ipv4Net, Ipv6Net)`, but the wire field (Go `tailcfg.Node.Addresses`) is a
  variable-length `[]Prefix`. A node on an **IPv6-off** tailnet (e.g. a self-hosted Headscale with
  IPv6 disabled) is assigned only an IPv4 prefix, so the netmap stream failed to parse with
  `invalid length 1, expected a tuple of size 2`, looping forever and never bringing the device up.
  `addresses` is now a `Vec<ipnet::IpNet>`; the domain `Node` derives its v4 identity from the first
  IPv4 prefix and an optional v6 from the first IPv6 prefix (a synthesized `::/128` placeholder when
  the tailnet is IPv4-only — never read in that mode). Dual-stack tailnets are unaffected. Regression
  tests cover v4-only, dual-stack, and the raw single-address JSON decode.

## [0.6.7](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.6.7) - 2026-06-09

### Added
- **Re-export `TransportMode` and `TunConfig` from the crate facade**, and a chainable
  **`Config::use_tun(name, mtu)`** builder. `Config::transport_mode` was already public, but the
  `TransportMode`/`TunConfig` types were only reachable via `ts_control::`, forcing a downstream
  crate that uses only the `tailscale` facade to add a direct `ts_control` dependency just to select
  TUN mode. Now `tailscale::TransportMode` / `tailscale::TunConfig` are exported, and
  `Config::default().use_tun(Some("tailscale0".into()), None)` sets `transport_mode` to
  `Tun(TunConfig { name, mtu })` in one call. Additive and backward-compatible; TUN mode still
  requires root/`CAP_NET_ADMIN` and the engine `tun` feature.

## [0.6.6](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.6.6) - 2026-06-08

### Added
- **`Config::allow_http_key_fetch`** (default `false`) — opt into fetching the control server's
  machine public key (`GET /key`) over plain **http** when the control URL is `http://`. The `/key`
  bootstrap was previously always upgraded to `https`, so a node could not register against a
  control plane that only serves plain http (e.g. a self-hosted Headscale on an `http://host:port`
  LAN endpoint / NodePort with no TLS) even though the rest of the control connection already honors
  the `http` scheme — registration failed at the key fetch with a `ConnectToControlServer` network
  error. Set this `true` for such a deployment (safe only over a trusted network path; no effect on
  `https://` control URLs). Replaces the build-time-only `insecure-keyfetch` feature with a runtime
  per-deployment knob; the feature still works as an unconditional build override.

### Changed
- **Crate package names renamed to a `geiserx_` namespace for crates.io publication.** The bare
  `ts_*` package names collide with unrelated crates already on crates.io (names are global +
  permanent there), so every publishable workspace crate is renamed: the facade `tailscale-rs` →
  `geiserx_tailscale`, and each `ts_*` → `geiserx_ts_*` (e.g. `ts_control` → `geiserx_ts_control`).
  **Library (import) names are unchanged** — each crate keeps `[lib] name = "ts_control"` etc., so
  `use tailscale::…` / `use ts_control::…` and all source code are unaffected; only the published
  package names and the `package = "…"` keys in `[workspace.dependencies]` change. The four internal
  `publish = false` crates (`checks`, `ts_cli_util`, `ts_devtools`, `ts_test_util`) are untouched.

## [0.6.5](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.6.5) - 2026-06-08

### Added
- **`Device::logout()` — deregister this node from the control plane** (the equivalent of Go
  `tsnet`'s `LocalClient.Logout`). Re-`POST`s `/machine/register` with the node's current node key
  and a backdated `expiry`, which control honors by expiring the node now: it drops out of every
  peer's netmap and must re-register to rejoin. This matters for **non-ephemeral** nodes, which
  otherwise linger in the tailnet (visible to peers, counting against the machine limit) for ~24h
  after the process exits. It is a control-plane state change only — the local datapath is untouched
  (tear down via `Device::shutdown`), the on-disk node key is not deleted (re-registering with it is
  the re-login path), and it is idempotent (logging out an already-expired node still returns `Ok`).
  New `ts_control::logout` RPC (fresh Noise channel, 30s-bounded) + `Runtime::logout`. The logout
  request mirrors the normal registration request shape (node key, NL key, host identity) — control
  rejects a skeleton request — and only adds the past expiry. Verified live against
  `controlplane.tailscale.com` (campaign scenario `s8`).
- **`Device::wait_until_running(timeout)` + `Device::watch_state()` — typed registration outcome /
  connection-state stream.** `wait_until_running` resolves `Ok(())` once the node is registered and
  running, or returns a typed `RegistrationError` distinguishing a **permanent** failure
  (`AuthRejected` — bad/expired/unknown auth key; `KeyExpired`; `NeedsLogin` — interactive auth) from
  a **transient** one (`NetworkUnreachable`), or `Timeout`. `watch_state()` exposes a
  `watch::Receiver<DeviceState>` (`Connecting` → `Running` / `NeedsLogin` / `Expired` / `Failed`) so
  an embedder reacts to control-connection transitions push-style instead of polling. This replaces
  the consumer workaround of polling `ipv4_addr()` until a deadline and reporting a generic timeout.
  The control runner publishes transitions into a `watch` cell created in `Runtime::spawn` (so a
  hard registration failure surfaces its reason even though it stops the actor). Verified live
  (campaign scenario `s9`). *(Per-reconnect `Connecting` dips are not yet emitted — control
  reconnects transparently below this layer; the state reflects registration outcome + key expiry.)*
- **`Device::active_exit_node()` + `Status.active_exit_node` — the exit node actually engaged.** The
  route updater (the single authoritative resolver of the exit-node selector against the live peer
  set) publishes the resolved, **fail-closed** stable id; `Status`/`active_exit_node` report it. This
  differs from the configured `exit_node()` selector — it is `None` when the selector matches no
  peer or the matched peer no longer advertises a default route (egress is then dropped). Mirrors Go
  `tsnet`'s `Status.ExitNodeStatus.ID`.
- **`WhoIs` now surfaces node capabilities and the owning user.** `WhoIs.capabilities` is populated
  from the node's control-pushed `CapMap`, and `WhoIs.user` resolves the owning user's login/display
  name by joining the node's user id against the netmap's `UserProfiles` table (accumulated across
  delta updates by the peer tracker). Previously both were always empty. (Per-node `online` state
  remains a gap — the domain `Node` still does not retain the wire `online`/`last_seen` fields.)

### Changed
- **CI now runs on a self-hosted Linux/X64 runner** instead of paid GitHub-hosted minutes. A new
  idempotent `provision-self-hosted` composite action self-heals the bare-Ubuntu runner's build
  prerequisites (rustup, `lld`, `libpython3.12-dev`) so a freshly (re)created runner Just Works, and
  the `musl_static` `cross` lanes get the toolchain identity-mount they need under docker-in-docker.
  The self-hosted lanes are gated to **never run code from fork PRs** (the runner has Docker-socket
  access) and check out with `persist-credentials: false`. No effect on consumers — build/test parity
  is unchanged.
### Security
- **`russh` 0.60.3 → 0.61.2**, clearing GHSA-wwx6-x28x-8259 (a negotiated-compression "ZIP bomb"
  that bypassed the max-packet-size check → OOM/DoS). russh `0.61.1` itself does not build (its
  `p256` rc pin resolves against an incompatible `primefield` rc — upstream russh#720); `0.61.2`
  bumps the whole RustCrypto subtree to the coherent rc generation and compiles. This required moving
  the workspace's `x25519-dalek` pin `3.0.0-pre.6 → 3.0.0-rc.0` (russh 0.61.2 hard-pins
  `curve25519-dalek = 5.0.0-rc.0`, and the two release in lockstep) — a forward step on the same
  pre-release line the core WireGuard handshake already used, not a new pre-release dependency. The
  ring-only egress invariant is preserved (aws-lc-rs remains absent from the default graph; `cargo
  deny --no-default-features` passes), and the WireGuard handshake + Wycheproof x25519 vectors
  (`ts_keys`/`ts_tunnel`) pass unchanged on the new pin. `russh` remains optional / off-by-default
  (`ssh` feature only).

## [0.6.4](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.6.4) - 2026-06-08

### Added
- **`Device::set_exit_node(Option<ExitNodeSelector>)` — change the exit node at runtime** without
  recreating the device (the equivalent of Go `tsnet`'s `LocalClient.EditPrefs(ExitNodeID/ExitNodeIP)`).
  The selector (stable ID / tailnet IP / MagicDNS name) is the same type as `Config::exit_node`, is
  re-resolved against the live peer set, and the outbound route + inbound source filter recompute
  immediately; `None` clears the exit (fail-closed). Internally, `Env::exit_node` became a live
  `watch` cell that both the route updater and source filter read each recompute, and the peer
  tracker re-broadcasts its snapshot on a switch. Verified live (campaign scenario `s7`).

## [0.6.3](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.6.3) - 2026-06-07

Open-source-readiness polish ahead of the public move to `github.com/GeiserX/tailscale-rs`
(in-repo phase; the repo transfer + self-hosted CI move follow separately).

### Changed
- **Published crate renamed `tailscale` → `tailscale-rs`** (the crate `tailscale` is already taken
  on crates.io). The **library name stays `tailscale`** via `[lib] name = "tailscale"`, so
  `use tailscale::…` is unchanged for all consumers; downstream `Cargo.toml` uses
  `tailscale = { package = "tailscale-rs", … }`.
- `repository` now points at `github.com/GeiserX/tailscale-rs`; all in-repo repository references
  (CHANGELOG release links, VENDOR origin, SECURITY advisory URL, README issue tracker) repointed.
- `LICENSE` retains the upstream Tailscale BSD-3-Clause copyright and adds a fork-modifications
  copyright line (license unchanged — BSD-3, matching upstream).

### Added
- Professional README: SVG banner, status/license/MSRV/edition/fork badges, corrected install
  snippet, and a Mermaid overview.
- `release-binaries` workflow: builds the C FFI library (`libtailscalers.{a,so,dylib}` +
  `tailscale.h`) for Linux and macOS on each `v*` tag and attaches them to the GitHub Release
  (the Rust crate itself remains the tsnet-equivalent, published to crates.io separately).
- Standard OSS infra: `.github/FUNDING.yml`, `dependabot.yml` (cargo + github-actions),
  `stale.yml`, `.coderabbit.yaml`.

## [0.6.2](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.6.2) - 2026-06-07

Three panics surfaced by the v0.6.1 live e2e campaign against real Tailscale, all fixed and
re-verified live (the full 6-scenario campaign now passes; it was 4/6).

### Fixed
- **`PeerDb` no longer panics under concurrent/churning netmaps (tsr-gxq).** `PeerDb::upsert` had
  four `assert!(removed_index_entry == id)` checks (disco-key, fqdn, tailnet-IP v4/v6, and the
  generic node-key/stable-id/control index helper) that fired when a peer's indexed value was
  transiently reassigned across peers — killing the `PeerTracker` actor and freezing the netmap.
  They now use a guarded remove (retract only our own mapping, tolerate an absent/different one),
  matching the idiom the hostname index already used. Joining many nodes concurrently is now safe.
- **Overlay `ping` (and any raw/UDP socket op) no longer panics the netstack on a stale handle
  (tsr-02e).** A blocked `Recv`/`Send` whose socket was closed before it re-ran called smoltcp's
  `SocketSet::get_mut` on a freed handle, which panics — taking down the whole netstack actor (every
  later op then failed with `InternalChannelClosed`). A new `get_socket_mut!` checks the handle is
  live first and returns a clean "socket closed" error otherwise; the `Close` path is guarded too.
  `Device::ping` to real peers now works.
- **Registration failures are diagnosable (tsr-kqj).** Control's `RegisterResponse.Error` message
  (e.g. `"invalid key: API key does not exist"`) was discarded, leaving a bad auth key to surface as
  an opaque `Internal(Actor)`. The reason is now carried through a new `Error::Registration(String)`
  and logged at the failure point. (Surfacing it as a typed error out of `Device::new` rather than a
  later call remains a documented follow-up.)

## [0.6.1](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.6.1) - 2026-06-07

### Added
- **Extensive live-tailnet e2e campaign** (`tests/tailnet_e2e_campaign.rs`): a gated, CI-safe test
  binary with six independent scenarios against real Tailscale — concurrent multi-node join,
  overlay ICMP ping to real peers, deep MagicDNS resolution, ephemeral re-join churn, overlay TCP
  connect, and an IPv4-only config permutation. Skips cleanly unless `TS_RS_TEST_NET=1` +
  `TS_RS_TEST_AUTHKEY` are set.

A run against a live tailnet validated registration, CGNAT addressing, MagicDNS (self + 24/24
peers), ephemeral churn, and overlay TCP to real peers — and surfaced two pre-existing panics now
tracked as bugs: a `PeerDb::upsert` disco-key index assertion under concurrent/churning netmaps,
and an overlay-`ping` netstack panic on a stale raw-socket handle.

Minor-version bump marking the open-source-readiness milestone: a session of crypto-interop
proofs, an `unsafe` audit, a whole-codebase review, and now an FFI panic boundary leave the fork
substantially hardened. No breaking API changes, but the safety posture is materially stronger.

### Added
- **Panic boundary across the entire C FFI (tsr-vmy).** A Rust panic unwinding across an
  `extern "C"` frame is undefined behavior; previously a malformed-packet panic in the datapath
  could corrupt the host (Go/C) process silently. All ~41 `extern "C"` entry points now run inside
  a `ffi_guard` that catches any unwind at the boundary and returns the type's documented failure
  sentinel (negative `c_int`, `NULL`, `None`, or an `AF_UNSPEC` `sockaddr`), logging the panic via
  `tracing`. Implemented with `catch_unwind` (not `panic = "abort"`) so the crate stays an
  embeddable `staticlib`/`cdylib`.
- **Behavioral test for the SSH privilege-drop ordering (tsr-h45).** The sacred
  supplementary-groups → setgid → setuid-last sequence is extracted into a pure `priv_drop_plan`
  function (the post-fork closure just executes the plan), with unit tests asserting uid-is-last
  and the Apple/Linux step difference — so a reordering can no longer ship undetected.

### Fixed
- **Mutex-poisoning hazard on the WireGuard nonce path** (`ts_tunnel`): the per-session nonce lock
  now recovers a poisoned guard instead of propagating the panic, so one transient panic can't
  permanently brick a session's encrypt path (and can't escalate to FFI UB).
- **Flaky taildrop tests** (`ts_runtime`): the test temp-dir helper now uses an atomic counter, not
  a coarse timestamp, so concurrent tests no longer collide on a shared directory.

## [0.5.63](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.63) - 2026-06-07

Whole-codebase health review + fixes (open-source readiness). A multi-perspective audit
(architecture, security, complexity, dead-code, error-handling, test-health, consistency, docs,
CI/deps) found the core paths sound; this release lands the polish.

- **`cargo doc --workspace` is green again.** 61 broken/`private`-target intra-doc-link errors
  across `ts_magicsock`, `ts_control`, `ts_runtime`, `ts_ffi`, `ts_dns_wire`, `ts_tka`, and the root
  crate were fixed (resolved to the real item or de-linked to code spans). These had accumulated
  undetected because the `cargo doc` CI lane is upstream-owner-gated and never ran on the fork — the
  gate will pass the moment docs are built.
- **Dependency advisory cleared:** `russh` bumped `0.60` → `0.60.3`, clearing RUSTSEC-2026-0153 /
  -0154 (pre-auth allocation DoS). Still confined to the off-by-default `ssh` feature; `aws-lc-rs`
  stays off the default graph.
- **Consistency:** `ts_tka`'s `TkaError` now derives `thiserror::Error` like the other fork-own
  crypto crates (messages byte-identical); added `# Errors` rustdoc where missing.
- **Complexity:** the TUN uplink datapath (`ts_runtime` `tun_actor`) is extracted from an ~80-line
  inline nested closure into a named `up_pump` async fn — same behavior, now readable/testable.
- **Docs/metadata:** fixed stale upstream references (issue-tracker, release-tag links, README
  badges), closed the `docs/CRYPTOGRAPHY.md` §9 numbering gap, switched `SECURITY.md` disclosure to
  GitHub private advisories, and set `rust-version` to the CI-verified `1.94.1` (was an untested
  `1.91.0` claim). Removed a dead `MPL-2.0` allowance from `deny.toml`.

## [0.5.62](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.62) - 2026-06-07

`unsafe` audit + minimization (tsr-5fu) — open-source readiness. Every `unsafe` block was reviewed
for whether it is actually needed, whether a safe alternative exists (even if it means rewriting),
and whether the irreducible remainder is minimal and justified. Net result: the avoidable `unsafe`
is gone, three more crates are now statically `unsafe`-free, and a latent bug was fixed.

- **Two hand-written `unsafe` marker impls eliminated via safe idioms.** `TcpStream`'s
  `unsafe impl Sync` is replaced by adding `+ Sync` to its boxed-future type alias, so `Sync`
  now **auto-derives** (compiler-enforced — the futures only capture `Sync` data). `ChannelServer`'s
  `unsafe impl Send for PhantomSend<H>` becomes the safe `PhantomData<fn() -> H>` idiom (the same
  covariant variance, unconditionally `Send`/`Sync`, no `unsafe`).
- **Two misused-`unsafe` APIs de-`unsafe`d.** `ts_disco_protocol`'s `from_bytes_unchecked[_mut]`
  (whose bodies were already safe validating zerocopy calls — `unsafe` was flagging a *semantic*
  footgun, not a memory-safety contract) are renamed to `from_bytes_unvalidated[_mut]` and made
  safe. A test-only hand-rolled `Waker` (`ts_http_util`) is replaced by stable `Waker::noop()`.
- **Bug fix:** `ts_ffi`'s `ts_sockaddr_set_port` read the `sockaddr` union field *by value* and wrote
  the port to the discarded temporary — so the port was never stored. It now writes through the
  union place.
- **`#![deny(unsafe_code)]` added** to `ts_disco_protocol`, `ts_http_util`, and
  `ts_netstack_smoltcp_socket` (now 9 workspace crates forbid/deny `unsafe`).
- **Irreducible `unsafe` documented, not removed:** `ts_packet`'s `BufMut` impl (`bytes::BufMut` is
  an `unsafe trait`, so `unsafe impl` is mandatory), the SSH `pre_exec` privilege-drop, edition-2024
  `env::set_var` in tests, the inherited perf-critical `ts_bart` IP-octet cast, and the `ts_ffi` C
  boundary all carry `// SAFETY:` justifications. `ts_ffi/README.md` gains a reader-facing note
  explaining why the FFI layer concentrates the workspace's `unsafe`.

## [0.5.61](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.61) - 2026-06-07

Adversarial primitive test vectors (tsr-46h, follow-up to tsr-19k). Where tsr-19k proved
byte-for-byte **wire interop** with Go, this proves the underlying **primitive crates** survive
Google's Project Wycheproof adversarial battery (malleability, low-order points, non-canonical
encodings, forged tags). Sourced from the `wycheproof` crate v0.6.0 — **ring-clean** (serde /
serde_json / data-encoding only; no aws-lc/openssl/ring), so the ring-only invariant holds.

- **ChaCha20Poly1305** (`chacha20poly1305` v0.10.1, WireGuard transport AEAD): 316 of the
  96-bit-nonce vectors — Valid ciphertext+tag must match and round-trip, Invalid must fail to
  decrypt. The 9 non-96-bit-nonce groups are skipped (XChaCha API this fork does not use).
- **X25519** (`x25519-dalek` v3.0.0-pre.6, WireGuard/Noise DH): all 518 vectors (265 Valid + 253
  Acceptable adversarial), computed shared secret matches Wycheproof's expected bytes — confirms
  dalek's RFC 7748 non-contributory behavior on low-order/non-canonical/twist/zero inputs.
- **Ed25519 standard verify** (`ed25519-dalek` v2.2.0, TKA rotation-wrap sig): all 150 vectors
  (88 Valid + 62 Invalid) — Valid verify, Invalid rejected, zero exceptions. The ZIP-215
  (`ed25519-zebra`) verifier is intentionally out of scope (Wycheproof assumes standard
  verification; the cofactored verifier is covered by the speccheck dual-verifier KAT).
- **HKDF-SHA256 deliberately excluded**: this fork's HKDF is over BLAKE2s, never SHA-256, so the
  `hkdf_sha256` Wycheproof set does not apply. Documented in
  [`tests/vectors/VENDOR.md`](tests/vectors/VENDOR.md) and [`docs/CRYPTOGRAPHY.md`](docs/CRYPTOGRAPHY.md) §8b.

## [0.5.60](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.60) - 2026-06-07

Cross-implementation interop proofs from the crypto audit (tsr-19k). The hand-rolled crypto was
previously validated only by self-consistent round-trips, which cannot catch a wire-incompatibility
with Go Tailscale. This release pins **Go-sourced known-answer vectors** over every hand-rolled
surface; a divergence fails closed (denied auth / failed handshake / consensus split) but still
breaks real interop, so these are the silent-wire-incompatibility guard.

- **Control-plane big-endian-nonce AEAD KAT** (`ts_control_noise`): the `ChaCha20Poly1305BigEndian`
  fork now has a byte-for-byte KAT against Go `golang.org/x/crypto/chacha20poly1305`, including a
  high counter that exercises the full `to_be_bytes` width — proving the 4-character endianness edit
  matches Go's `binary.BigEndian.PutUint64`.
- **WireGuard transport + handshake KATs** (`ts_tunnel`): a little-endian transport-nonce KAT vs Go
  ciphertexts, plus a fixed-ephemeral `Noise_IKpsk2` handshake transcript whose derived send/recv
  transport keys match an independent Go reimplementation of wireguard-go's construction
  byte-for-byte.
- **Key-confirmation conformance** (`ts_tunnel`): a test pins the Dowling–Paterson (IACR 2018/080,
  Thm 1) property — the responder stays **provisional** after `ResponderHello` and is promoted to
  live **only** after the first AEAD-verifying inbound transport packet, never on handshake
  completion alone.
- **TKA CBOR / SigHash golden + dual-verifier cross-bind** (`ts_tka`): the `NodeKeySignature`
  CTAP2-CBOR encoding and `BLAKE2s-256` SigHash now byte-match the **real `tailscale.com/tka`
  v1.100.0** package for Direct / Credential / Rotation kinds, and the Ed25519 dual-verifier
  accept/reject matrix is cross-bound to Go `crypto/ed25519` + `ed25519consensus` verdicts on the
  12 `ed25519-speccheck` vectors.
- **Vectors are committed** under [`tests/vectors/`](tests/vectors/) with the Go generators in
  `tests/vectors/gen/` and full provenance (toolchain + module versions + regen commands) in
  [`tests/vectors/VENDOR.md`](tests/vectors/VENDOR.md). Documented in
  [`docs/CRYPTOGRAPHY.md`](docs/CRYPTOGRAPHY.md) §8a.

## [0.5.59](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.59) - 2026-06-07

Crypto-hardening from the audit beads (tsr-9nu, tsr-quk):

- **Private keys no longer leak via `Debug`** (was: `Debug` forwarded to `Display`, printing the
  full secret hex — a log-leak risk). All private-key newtypes (`Machine`/`Node`/`Disco`/
  `NetworkLock`) and their keypairs now render `<Type>(<redacted>)`; public keys still show
  `prefix:hex`. Regression tests added (`ts_keys` `debug_redaction_tests`). The raw bytes remain
  reachable only via the explicit `to_bytes()`/`Display`/serde paths.
- **Tailnet Lock Ed25519 verifiers proven correct** against the `ed25519-speccheck` adversarial
  vectors: a new KAT pins the accept/reject matrix of both verifiers (`verify_ed25519_std` /
  `verify_ed25519_zip215`), hard-asserts that the standard verifier **rejects `S ≥ L` malleability
  signatures**, and demonstrates the cofactored-vs-cofactorless **disagreement** (ZIP-215 accepts,
  standard rejects the same triple) — confirming the dual-verifier split is intentional, not
  accidental. `ed25519-zebra` is documented as MUST-stay ≥ 2.x (1.x is pre-ZIP-215 and would split
  consensus with Go).
- **CBOR canonicalization correctness**: corrected the `ts_tka` CTAP2 key-ordering doc-comment
  (fxamacker `SortCTAP2` is bytewise-lexicographic, not length-first; coincides with numeric order
  for TKA's uint-only keys) and added a duplicate-key `debug_assert` guard to the `IntMap` encoder.
- **Doc fix**: the DERP `Nonce` doc-comment named the wrong cipher (was "ChaCha20Poly1305"; it is
  NaCl `SalsaBox` / XSalsa20-Poly1305).

Deferred (documented in the beads): key-material zeroization is blocked by the `Copy` + `zerocopy`
design of the key newtypes — tracked in tsr-9nu with a recommended posture; interop cross-vectors
vs Go and the key-confirmation conformance test remain in tsr-19k.

## [0.5.58](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.58) - 2026-06-07

Fixes from a whole-codebase health audit:

- **Fix (exit-node SSRF guard gap).** `ts_forwarder`'s `exit_dst_is_forbidden` now also rejects
  CGNAT/shared `100.64.0.0/10` (the Tailscale range itself — closing a path where a peer could
  drive an exit CONNECT at another tailnet node via the residential proxy), broadcast
  `255.255.255.255`, and `0.0.0.0/8`.
- **Fix (CI phantom-runner spam).** The `python` and `elixir` workflows' self-hosted-runner jobs
  are now gated `if: github.repository_owner == 'tailscale'` (mirroring the `rust` workflow), so
  they no longer queue for hours and auto-cancel on every push to the fork.
- **Hardening (at-rest key hygiene).** The persisted ACME account-key buffer is wrapped in
  `Zeroizing` so it is wiped on drop (on-wire JSON unchanged). At-rest protection of the state
  file remains the embedding application's responsibility (documented).
- **Robustness.** `dataplane` peer-upsert no longer `unwrap()`s on a maintained invariant (logs +
  skips instead of panicking the whole update); `multiderp` degrades a single DERP region on a
  transient actor send error instead of aborting setup; exit-node DoH delegation failures are
  logged at `warn` (were `debug`, hiding broken recursive DNS from operators).
- **Tests (crypto known-answer / regression vectors).** Added the first tests for the TS2021
  big-endian ChaCha20Poly1305 AEAD (round-trip, tamper-rejection, a big-endianness assertion that
  catches a nonce-order revert, and a frozen self-vector); a frozen CTAP2-CBOR vector for
  `ts_tka` (catches canonical-CBOR/digest drift that would break wire-compat with Go); and offline
  unit coverage of the ACME directory/nonce/error-path helpers. No crypto defect was found.
- **Docs/consistency.** Added module docs to four previously doc-less modules; documented the
  `ssh`-feature advisory scope; corrected the README install-version example (`0.3`→`0.5`) and the
  `SECURITY.md` vulnerability-reporting contact.

## [0.5.57](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.57) - 2026-06-07

Fixes from a multi-perspective review of the v0.5.56 wave:

- **Fix (Serve `Path` → `Proxy` dropped the client's first request).** `serve_path` reads the HTTP
  request head to pick a path prefix, then proxied the stream onward — but the already-consumed
  head bytes were never replayed to the backend, so the backend saw a request with its request
  line + headers missing. The consumed head is now replayed before the bidirectional splice
  (`proxy_to_backend_with_prefix`); the direct (non-`Path`) `Proxy` path is unchanged.
- **Fix (recursive MagicDNS in TUN head-of-line blocking).** A `Decision::Forward` was awaited
  inline in the TUN uplink pump, so one slow/hung upstream DNS query stalled *all* TUN traffic for
  up to the 5 s timeout. Forwards now run on a bounded `JoinSet` (≤256 in flight) like the netstack
  resolver loop; the synchronous fast paths stay inline. IPv4-only egress + NXDOMAIN fail-closed
  fallback preserved.
- **Fix (Serve `Redirect` header injection).** The redirect `Location` target is now rejected at
  validation time if it contains CR/LF, closing an HTTP response-splitting vector.
- **Fix (Tailnet Lock revocation on re-sync).** A `Full` netmap re-sync now evicts a
  previously-admitted peer whose signature is no longer authorized under an active TKA `Authority`
  (the retain set is filtered through the gate); the no-authority path is unchanged.
- **Tests.** First unit tests for `ts_http_util` (`origin_form_target` incl. an
  is-never-absolute-form regression guard for the Let's-Encrypt bug fixed in 0.5.52, `host_header`
  port handling, default User-Agent); Serve dispatch byte-emission + oversized/malformed-head +
  end-to-end `Path` routing; TKA enforcement driven through the real `PeerUpdate::Full`/`Delta`
  handlers (handler refactored to a single shared `apply_peer_update` so tests exercise the real
  path).
- **Cleanups.** Deduplicated `find_header_end` onto the shared helper; made the `MAX_HTTP_HEAD`
  bound exact; documented the `ssh`-graph advisory scope in `deny.toml`; refreshed a stale comment
  in the Pebble test script.

## [0.5.56](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.56) - 2026-06-07

Hardening + feature wave (security gaps + buildable parity gaps from a feature-surface audit):

- **Tailnet Lock (TKA) peer-key enforcement, wired (partial).** The per-peer node-key signature
  (`tailcfg.Node.KeySignature`) is now threaded through the domain `Node` instead of being dropped
  in wire→domain conversion, and a fail-closed authorization gate is wired at the peer-trust
  chokepoint (`ts_runtime` peer tracker): when a TKA `Authority` is present, peers whose node key
  isn't signed by a trusted key — or that present no signature — are refused (not added to the peer
  DB). Four unit tests cover active/inactive/unsigned/bad-signature/authorized cases.
  **Status:** enforcement is currently inert because the `/machine/tka/sync/*` RPC + AUM-chain
  replayer that supply the trusted-key `Authority` are deferred — so do not yet rely on Tailnet
  Lock for control-plane-compromise protection. See `SECURITY.md`.
- **Supply-chain CI gate.** `cargo deny` now runs on every push in the GitHub-hosted `hosted_test`
  lane against the ring-only runtime graph (`--no-default-features --exclude-dev check all`), with
  an explicit `aws-lc-rs`/`aws-lc-sys` ban in `deny.toml`, machine-enforcing the ring-only /
  musl-clean invariant (previously only in the upstream-gated job that never runs on this fork).
- **Tailscale Serve `Path` and `Redirect` handlers.** `ServeTarget` gains a `Path` (HTTP
  path-prefix mux, longest-prefix wins) and `Redirect` (configurable 3xx + `Location`) variant,
  with hand-rolled HTTP request-head parsing on the TLS-terminated stream (no axum/hyper),
  fail-closed on unmatched paths / backend failures.
- **Recursive MagicDNS in TUN mode.** TUN-mode `Decision::Forward` no longer dead-ends at NXDOMAIN:
  it now forwards over the forwarder netstack's overlay channel (UDP or exit-node DoH), reusing the
  existing resolver path and preserving the IPv4-only egress filter.
- **`SECURITY.md`** added: unaudited-crypto disclaimer, TKA-enforcement status, peerAPI
  capability-gap note, at-rest-key-handling note, anti-leak posture, vulnerability-reporting
  contact, and a not-affiliated-with-Tailscale-Inc. notice. README + parity roadmap updated; the
  project now tracks the (active) upstream `tailscale/tailscale-rs`.

Deferred (documented in `docs/PARITY_ROADMAP.md`): TKA AUM-sync RPC + live `Authority`, DERP mesh
server, TKA signing, UPnP/PCP/PMP portmapper, app-connector, 4via6; and the BLOCKED-by-external
set (Funnel public relay, ACME/set-dns on a self-hosted control plane, OIDC/SSO, network flow logs, Taildrop relay,
node sharing).

## [0.5.55](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.55) - 2026-06-06

**Fix the aarch64 `musl_static` `GLIBC_2.XX not found` failure (isolate the CI target cache per
lane).** The shared `setup-rust` action keys its `target/` cache on `builder-triple`
(`x86_64-unknown-linux-gnu` for both musl matrix entries) + `Cargo.lock` only — not on the cross
target — so both musl jobs and `hosted_test` restored one shared cache. `cross` runs each target
in its own container image (different glibc); a build-script binary (e.g. `libc`'s) compiled for
one image and restored into another fails with `GLIBC_2.XX not found`, because cargo does not
invalidate build-script fingerprints across targets (cross-rs FAQ "Glibc Version Error"). Each
GitHub-hosted lane now passes a distinct `cache-key` (`hosted-test`,
`musl-<target-triple>`), keeping the cache fully (no per-run loss, no extra runner cost) while
preventing the cross-container artifact collision. `x86_64` musl and `hosted_test` were already
green; this fixes the remaining `aarch64` musl lane.

## [0.5.54](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.54) - 2026-06-06

**Give the `musl_static` lane disk headroom.** It started failing with `ENOSPC`: the `cross`
docker images plus build artifacts overflow the hosted runner's ~14 GB free disk. Added the same
hand-rolled `Free disk space` step the `hosted_test` lane already uses (remove unused
preinstalled SDKs + prune docker images) so both GitHub-hosted lanes have room to build.

## [0.5.53](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.53) - 2026-06-06

**Stop the perpetually-queued CI jobs (notification spam).** The inherited `build_test` matrix,
`arch_independent`, and `publish` jobs target self-hosted runner labels (and a crates.io publish)
that only exist in the upstream `tailscale` org; on this fork they queued forever and never
reported, spamming the Actions tab. They are now gated `if: github.repository_owner ==
'tailscale'` so they skip cleanly off-upstream, leaving only the two GitHub-hosted lanes that
actually run here (`hosted_test` + `musl_static`). The four sibling workflows that can never run
on the fork (`c`, `elixir`, `nix`, `python`) were disabled at the Actions level.

## [0.5.52](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.52) - 2026-06-06

**Fix three RFC-compliance bugs in the shared HTTP client (`ts_http_util`), surfaced by a new
live-CA ACME integration test.** None were visible at compile time, and all three were
production-DOA for the `acme` feature against Let's Encrypt (real Tailscale's control plane is
lenient and runs on the default port, so they did not affect the tailnet path):

1. **Absolute-form request target.** `ClientExt::{get,post}` sent the request line in absolute
   form (`POST https://host/path HTTP/1.1`) instead of RFC 7230 §5.3.1 origin-form
   (`POST /path HTTP/1.1`); these clients dial the origin directly, never a forward proxy. A
   compliant ACME server compares the JWS `url` against `scheme + Host + request-target`, so the
   absolute-form target doubled the URL and every signed POST was rejected.
2. **Missing `User-Agent`.** RFC 8555 §6.1 requires one; Boulder/Let's Encrypt and Pebble ≥ 2.10
   reject requests without it. A default `tailscale-rs/<version>` UA is now sent.
3. **`host_header` dropped the non-default port.** Servers that reconstruct their own absolute
   URLs from the `Host` header (e.g. an ACME directory's `newNonce`/`newAccount` endpoints) were
   handed `localhost` instead of `localhost:14000` and advertised unreachable `:443` URLs. The
   port is now included whenever the URL carries a non-default one.

**Validation harnesses added (all gated, no-op in CI without their env):**
- `ts_control/tests/acme_pebble.rs` (`acme` feature + `TS_RS_TEST_PEBBLE`) — drives the full
  RFC 8555 DNS-01 flow against a real [Pebble](https://github.com/letsencrypt/pebble) CA via
  `scripts/pebble-up.sh`/`pebble-down.sh` (native Go, no Docker) and asserts a real issued chain.
- `ts_forwarder/tests/antileak_runtime.rs` — runtime proof of the fail-closed anti-leak
  invariant: `DirectDialer` structurally refuses exit egress, `ProxyExitDialer` fails closed on a
  dead proxy with no direct fallback, the SSRF guard rejects loopback/metadata/private/IPv6, and
  proxy UDP egress is refused. Complements the static `checks` firewall with actual dialer
  behavior.
- `tests/tailnet_live.rs` (`TS_RS_TEST_NET` + `TS_RS_TEST_AUTHKEY`) — joins a real Tailscale
  tailnet end-to-end (registration, CGNAT IP assignment, peer/netmap read, MagicDNS resolve),
  proving the pure-Rust fork interoperates with `controlplane.tailscale.com`.

## [0.5.51](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.51) - 2026-06-06

**Harden the `hosted_test` CI lane** (from a multi-perspective review of v0.5.47–0.5.50): add a
workflow-level `concurrency` group so rapid pushes to the same ref collapse, with
`cancel-in-progress` gated OFF for tag refs so an in-flight `publish` run is never cancelled
mid-release; add `timeout-minutes: 60` so a hung `cargo` step can't burn the 6h GitHub-hosted
default; and skip the lane on tag pushes (`if: !startsWith(github.ref, 'refs/tags/')`) since it
verifies code and `publish` deliberately does not depend on it, so re-running it on every release
tag gates nothing.

## [0.5.50](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.50) - 2026-06-06

**Give the `hosted_test` lane enough disk to build.** With both clippy steps green, the
`ubuntu-latest` runner died with `ENOSPC` during `cargo build --all-targets`: this ~45-crate
workspace's clippy + build + test artifacts overflow the hosted runner's ~14 GB free disk. Added
a `Free disk space` step that removes the unused preinstalled SDKs (dotnet, Android, GHC, CodeQL,
boost, the agent toolcache) and prunes Docker images — hand-rolled, no third-party action, to
keep the OSS supply chain minimal — and set `CARGO_INCREMENTAL=0` to roughly halve `target/`.

## [0.5.49](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.49) - 2026-06-06

**Fix a Linux-only clippy lint the new `hosted_test` lane exposed.** `ts_host_net/src/linux.rs`
is `#[cfg(target_os = "linux")]`, so it never compiled under local macOS clippy — the
`ubuntu-latest` lane is the first thing to lint it. Collapsed a nested `if let Some(..) { if let
Err(..) }` into a single let-chain to satisfy `clippy::collapsible_if`. Verified the only two
crates carrying Linux-gated code (`ts_host_net`, `ts_netstack_smoltcp`) are clippy-clean for the
`aarch64-unknown-linux-musl` target.

## [0.5.48](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.48) - 2026-06-06

**Fix the `hosted_test` lane added in 0.5.47.** The shared `setup-rust` composite action bakes
the `components` input into an `actions/cache` key, and cache keys reject commas — so passing
`components: clippy,rustfmt` failed key validation in the `Setup rust` step before any
verification ran. Pass `components: ""` (as `musl_static` does) and install clippy + rustfmt in a
dedicated `rustup component add` step after the toolchain override is set.

## [0.5.47](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.47) - 2026-06-06

**CI now has a real green signal.** The inherited upstream workflow matrix targets self-hosted
runner labels (`linux-x86_64-16cpu`, `linux-arm64-16cpu`, `macos-26`, …) that do not exist on
this fork, so every `rust`-workflow job queued forever and never reported. Added a `hosted_test`
job that runs on GitHub-hosted `ubuntu-latest` and executes the same core verification (fmt,
clippy `-D warnings` for lib + other targets, `build --all-targets`, `test`, and the `checks`
anti-leak firewall) with default features (ring-only; no `ssh`/`acme`/`tun`). This is the only
lane in the `rust` workflow that actually executes; `musl_static` already covered the musl path.

Fixed three latent clippy lints that only surface under the full `--workspace --bins --tests`
pass the new lane runs (per-crate checks had missed them): a doc-list overindent in
`checks/src/ipv4_only_host_net.rs`, a `field_reassign_with_default` in a `ts_keys` test, and two
`let-underscore-drop`s in a `ts_host_net` test (now bound and asserted on).

## [0.5.46](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.46) - 2026-06-06

**Client-side Funnel ingress** (roadmap `tsr-am9.11`): `Device::listen_funnel` now returns a
**working** ingress listener — the final tsnet-parity item. Investigation corrected the model:
Funnel ingress is **not** a DERP-layer feature. Tailscale's ingress relay is a tailnet *peer* that
**POSTs to the node's peerAPI `/v0/ingress`** and the node HTTP-hijacks the connection — so the
node side is a peerAPI route, fully buildable. (The public DNS + the relay itself remain
Tailscale-operated infrastructure: this works against real Tailscale SaaS with a Funnel-enabled ACL;
a self-hosted control plane provides no relay, documented in `MISSING_FUNNEL_RELAY`.)

- New peerAPI `POST /v0/ingress` route (`ts_runtime::peerapi`): fail-closed netmap-membership gate
  (a non-member ingress POST is rejected `403`; the stricter relay-specific cap is a documented
  follow-up, same posture as Taildrop), parses `Tailscale-Ingress-Target`/`-Src`, replies
  `HTTP/1.1 101 Switching Protocols` to hijack the connection into a raw bidi stream, and hands it
  to the funnel manager. No active funnel listener ⇒ `404` (never hijack what won't be served).
- New `FunnelManager` (`ts_runtime::funnel`, mirrors the Serve runtime): TLS-terminates each hijacked
  stream with the node's `*.ts.net` cert (the ACME-issued DNS-01 cert matches the Funnel hostname —
  no TLS-ALPN-01 needed) and yields `FunnelAccepted { target, src, stream }` over a
  `FunnelAcceptedReceiver`.
- **API change**: `Device::listen_funnel` now returns `FunnelAcceptedReceiver` (was `TlsAcceptor`) —
  the working hand-back shape. The `funnel_access` (NodeCanFunnel + CheckFunnelPort) and cert gates
  stay fail-closed. While a funnel listener is active the node advertises `HostInfo.IngressEnabled`
  (new `MapRequestBuilder::ingress_enabled`) so control routes Funnel traffic to it.
- **Anti-leak**: ingress arrives on the overlay peerAPI listener and is TLS-terminated on the
  overlay — never a host socket, never routed through `ts_forwarder`; no plaintext/self-signed
  fallback. The Python/Elixir `listen_funnel` bindings were updated for the new return type.

## [0.5.45](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.45) - 2026-06-06

**VIP-service advertise side** (roadmap `tsr-am9.9`): a node can now tell control it hosts a
`svc:<name>` VIP service, completing Tailscale Services (the consume side — binding a control-assigned
VIP — already shipped). Mirrors Go's `Hostinfo.ServicesHash` + c2n `GET /vip-services` mechanism (not
an inline `Hostinfo.Services` entry — that struct can't carry a `svc:` name).

- New `Config::advertise_services: Vec<String>` (the `svc:<dns-label>` names this node hosts;
  validated with `validate_service_name`, invalid names dropped fail-closed). Threaded root →
  `ts_control::Config` like `requested_tags`.
- `ts_control::services_hash(...)` computes Go's `vipServiceHash`: the sorted `VIPService` list
  serialized to canonical JSON, SHA-256'd (via **ring** — the same provider the rest of the TLS
  stack uses, now an unconditional `ts_control` dep; **no aws-lc-rs / openssl**, confirmed absent
  from the default *and* `acme` graphs), hex-encoded; `""` when empty. It's set as
  `Hostinfo.ServicesHash` on both the register and every map request via a new
  `MapRequestBuilder::services_hash` setter.
- The existing inbound c2n dispatcher (`ping.rs`, previously only `/echo`) gains a `GET /vip-services`
  arm returning `C2NVIPServicesResponse { VIPServices, ServicesHash }` (new serde types;
  `VipService`/`ProtoPortRange`/`ServiceName` gained `Serialize`). Control fetches the full list on a
  hash change, validates the node may host it (ACL), and returns the VIP via the existing
  `service-host` capability the consume side already reads.
- Empty `advertise_services` ⇒ hash `""` ⇒ the wire field is omitted ⇒ behavior unchanged. The
  consume side (`service.rs` / `node.rs`) is untouched.

## [0.5.44](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.44) - 2026-06-06

**TUN-mode MagicDNS** (roadmap `tsr-am9.7`): TUN-transport nodes now get MagicDNS, closing the gap
where their host DNS was inert (`nameservers: vec![]`). Mirrors Go's model — an in-process packet
intercept, not a host socket.

- The TUN packet pump now intercepts outbound UDP queries to `100.100.100.100:53`, answers them
  in-process via the **same** `decide()` MagicDNS responder the netstack path uses (no second
  resolver), and writes the reply back into the TUN (parsed/rebuilt with `etherparse`, checksums
  recomputed). Non-matching packets pass through to the overlay unchanged.
- `host_dns_from_dns_config` now programs the host resolver with `nameservers = [100.100.100.100]`
  (when MagicDNS is enabled) via `ts_host_net::apply_dns` (macOS `scutil` / Linux `resolvectl`), and
  `host_routes_from_node` adds the `100.100.100.100/32` route so the host's queries actually enter
  the TUN. The `TunActor` builds its own `DnsView` from the control state (peers + DNS config),
  mirroring the netstack `MagicDnsActor`.
- **Fail-safe**: a `Decision::Forward` (recursive / exit-node DNS) answers NXDOMAIN in TUN mode — a
  tailnet name is answered authoritatively, a public name gets NXDOMAIN rather than hanging or
  leaking to a host resolver. Recursive/exit-node DoH forwarding in TUN mode is a documented
  follow-up (it needs an overlay `Channel` threaded into the TUN actor). The netstack-mode MagicDNS
  path is byte-identical. New `etherparse` dep is gated to the off-by-default `tun` feature.

## [0.5.43](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.43) - 2026-06-06

**Docs: correct the symmetric-NAT caveat** (`tsr-am9.10`). The crate-root README claimed
"symmetric-NAT birthday-paradox hole-punching is not yet implemented." Investigation against
`tailscale/tailscale` @ main **and** v1.30.0 found that **upstream Go has no 256-port spray** — the
"birthday-paradox spray" is a common misconception. Go's actual hard/symmetric-NAT tactic is a
**single `EndpointSTUN4LocalPort` candidate** (the reflexive IPv4 paired with the node's fixed local
port, gated on `MappingVariesByDestIP && port != 0`), which this fork already emits in
`self_endpoints` and advertises in every `CallMeMaybe`. So symmetric-NAT handling is at **parity with
Go**; the README is corrected to say so. Building an actual 256-port spray was rejected: it would
diverge from Go, be an SSRF-style host-sourced-UDP-spray (which `ts_magicsock` explicitly guards
against), and leak unbounded in-flight ping state. No behavior change.

## [0.5.42](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.42) - 2026-06-06

**Stored Serve config + accept-loop runtime** (roadmap `tsr-am9.8`): `Device::set_serve_config` /
`get_serve_config`, completing Go `tsnet`'s `Get/SetServeConfig` + serving runtime. Now that ACME
issuance landed (v0.5.38–39), serve ports terminate TLS with a real Let's Encrypt cert.

- New `ServeState { name, ports: BTreeMap<u16, ServeTarget> }` (multi-port, mirroring upstream
  `ipn.ServeConfig`'s per-port `TCP` map). `ServeTarget` gains, alongside `Accept`/`Proxy{to}`:
  `Text{body}` (Go `HTTPHandler.Text`) and `TcpForward{to}` (Go `TCPPortHandler.TCPForward`, raw
  passthrough, no TLS); the enum is now `#[non_exhaustive]`.
- `Device::set_serve_config(state)` validates, builds each TLS-terminating port's `TlsAcceptor`
  up-front via the ACME cert path (any cert failure fails the whole call **closed** — no port is
  bound, no plaintext downgrade), then binds one overlay accept loop per port and reconciles on
  re-set (full-replace, Go semantics). It returns a `ServeAcceptedReceiver` — the in-process Rust
  stand-in for `ListenTLS`'s `net.Listener` — over which `Accept`-target streams arrive.
- Per-connection dispatch: `Accept` → TLS-terminated stream handed to the receiver; `Proxy{to}` →
  TLS-terminate then `copy_bidirectional` to a local host backend; `Text{body}` → write + close;
  `TcpForward{to}` → raw overlay stream spliced to a local host backend (no TLS).
- **Anti-leak**: serve listeners bind the **overlay** netstack only; the Proxy/TcpForward backend
  dial is a local host socket to the embedder's own backend (like the loopback proxy / Go's
  reverse-proxy to `127.0.0.1`), never routed through the `ts_forwarder` egress path. Per-port
  concurrent-connection cap (256). The legacy single-port `ServeConfig` + `Device::listen_tls`
  /`listen_funnel` are unchanged.

## [0.5.41](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.41) - 2026-06-06

Hardening + coverage from a multi-reviewer audit of the v0.5.33–v0.5.40 parity sweep. No happy-path
behavior change.

- **Security (HIGH)**: stop logging private key bytes. `ts_ffi`'s key-state load logged the full
  `persisted_key_state` (node/machine/network-lock private keys) at INFO via a derived `Debug`. The
  log line now records only the file path, and the FFI `key` / `persisted_key_state` types get
  manual **redacting `Debug`** impls so a stray `{:?}` can never leak key bytes.
- **ACME robustness**: every Let's Encrypt HTTP request is now bounded by a 30s
  `ACME_HTTP_TIMEOUT` (a stalled CA connection previously hung issuance forever, defeating the
  bounded poll loop), and responses are capped at 256 KiB (`ACME_MAX_RESPONSE`) against an unbounded
  body. Added a doc note that finalize is issued once the last authz is `valid` without polling the
  order to `ready` (accepted by LE/Pebble; a future hardening for strict CAs).
- **SSH lifecycle**: `serve_ssh` now bounds concurrent connections with a 64-permit semaphore
  (defense-in-depth beside the per-connection 16-channel cap) and owns its per-connection sessions
  in a `JoinSet`, so dropping the `serve_ssh` future aborts in-flight sessions instead of leaking
  them. A signal-killed shell now reports `128 + signal` instead of a bogus `exit-status 0`.
- **Tests**: an RFC-7638-style **known-answer** JWK-thumbprint test + a `public_jwk` header
  member-order guard (catch silent ACME wire drift against Let's Encrypt); an inclusive SSH
  channel-cap boundary test (15→allow / 16→refuse); and a symmetric isolation guard on the
  bad-binding disco-ping path (a rejected ping delivers no pong / doesn't bump the accepted counter).
- **Docs**: the FFI `ts_taildrop_save_file` / `ts_capture_pcap` `dst_path` is documented as a
  trusted-embedder host path (sanitize untrusted input); the permissive IPv6 pingable-candidate
  predicate is documented as intentional (no stable `is_global`; worst case a dead candidate → DERP).

## [0.5.40](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.40) - 2026-06-06

**Docs**: refresh `docs/PARITY_ROADMAP.md` to reflect near-complete tsnet parity as of v0.5.39.
Updates the per-lane parity estimates (A ~85%, B ~85%, C ~85%, D ~90%, E ~80%, bindings ~90%),
records the v0.5.27–v0.5.39 parity push, and enumerates the remaining deferred/external items
(TUN-mode MagicDNS, Serve accept-loop runtime, Service advertise-to-control, symmetric-NAT spray,
the external Funnel relay leg, netstack sharding) with their bead IDs. No code change.

## [0.5.39](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.39) - 2026-06-06

**Route `Device::listen_tls` through the ACME-aware issuance path** (follow-up to v0.5.38). With the
`acme` feature, `Device::get_certificate` issues a real cert, but `Device::listen_tls` was still
delegating to `ts_control::listen_tls`, which only knows the non-`acme` fail-closed stub — so a
`--features acme` build still failed closed on `listen_tls`. `Device::listen_tls` now validates the
serve config, obtains the certificate via `Device::get_certificate` (the `acme`-routed path), and
assembles the acceptor with `ts_control::tls_acceptor`. Without `acme` the behavior is unchanged
(same fail-closed `CertError`); with `acme` (and a `set-dns`-capable control plane) `listen_tls` now
returns a working acceptor. `listen_funnel` remains fail-closed on `MISSING_FUNNEL_RELAY` — public
Funnel additionally requires a Tailscale-operated ingress relay that a self-hosted control plane
cannot provide.

## [0.5.38](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.38) - 2026-06-06

**Client-side ACME (Let's Encrypt) certificate issuance + `set-dns` RPC** (roadmap Tier 4 item 10 /
Tier 5 item 16 keystone): `Device::get_certificate` can now mint a *real* publicly-trusted
certificate for a node's `*.ts.net` MagicDNS name, completing the long-stubbed Lane E. Behind the
new off-by-default `acme` feature.

This is faithful to how Go `tsnet` does it — **the node is the ACME client talking directly to
Let's Encrypt**; control's only role is publishing the DNS-01 challenge TXT:

- **Hand-rolled ACME (RFC 8555) DNS-01 engine** (`ts_control::acme`): full new-account → new-order →
  authz → finalize → download flow over the existing **ring-based** `ts_http_util` HTTPS stack, with
  ES256 JWS signing via `ring`, the RFC 7638 JWK thumbprint + RFC 8555 §8.1/§8.4 key-authorization /
  TXT-value computation (unit-tested byte-exact), and a `rcgen` (ring) CSR. Deliberately **not**
  `instant-acme` — that bundles a second hyper/aws-lc-rs TLS stack; hand-rolling keeps the
  **ring-only invariant structural** (confirmed: `aws-lc-rs` absent from the `--features acme`
  graph). No second TLS stack, no `instant-acme`, no `openssl`.
- **`POST /machine/set-dns` Noise RPC** (`ts_control::tokio::set_dns` + `ts_control_serde::SetDnsRequest`):
  publishes the `_acme-challenge.<name>` TXT, mirroring the existing id-token RPC. A `SetDnsPublisher`
  bridges it to the engine's `PublishTxt` seam.
- **Wiring**: `Device::get_certificate` → `Runtime::get_certificate` → a ControlRunner message (holds
  the control URL + node keys) → `issue_certificate_via_setdns`. The ACME **account key** is
  persisted in the node key state (`PersistState::acme_account_key`, `#[serde(default)]` so existing
  key files load as `None`) to keep one Let's Encrypt account across renewals; absent, an ephemeral
  per-call account key is generated.
- **Off by default + fail-closed**: WITHOUT the `acme` feature, `Device::get_certificate` is
  byte-identical to before (`CertError::Unimplemented`, no self-signed/plaintext fallback). The
  issuance path is **SaaS-only / DOA against a self-hosted control plane**, which returns HTTP 501 for `set-dns`
  (built for full tsnet parity, like the WIF subsystem) — it works against real Let's Encrypt + a
  control plane that implements `set-dns`. When functional, it transparently unblocks
  `Device::listen_tls` and `listen_funnel`.

## [0.5.37](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.37) - 2026-06-06

**IPv6 direct-path candidates** (roadmap Tier 5, item 13): close the last gap to negotiating a direct
IPv6 underlay path when `Config::enable_ipv6` is set. The disco machinery was already v6-capable
(reflexive set, peer-candidate accept/ping, IPv6-wins best-addr tiebreak, the dual-stack `[::]:0`
underlay bind), but `self_endpoints` only ever advertised the bound socket address — which for a
dual-stack bind is the undialable unspecified `[::]`, so no usable local v6 candidate was offered
and a direct v6 path never formed.

- `MagicSock::self_endpoints` now enumerates the host's IPv6 interface addresses (via `if-addrs`,
  which pulls only `libc` — no TLS) and emits each **global-unicast** address as a `Local` candidate
  paired with the bound port, **only when `enable_ipv6` is set**. The candidates are filtered through
  the same `is_pingable_candidate` the peer-accept side uses (single source of truth — rejects `::`,
  `::1`, link-local `fe80::/10`, ULA `fc00::/7`, multicast), so what we advertise exactly matches
  what we'd accept.
- **Default unchanged**: with `enable_ipv6 = false` (the proxy / k8s deployment default) zero v6
  candidates are emitted and the path is byte-identical to before. STUN stays IPv4-only (v6 reflexive
  arrives only via peer pongs, by design).
- **Anti-leak intact**: this is the overlay underlay disco path, not the forwarder egress — the
  `ts_forwarder` IPv4-only egress is untouched and the `ipv4_only_forwarder` guard stays green.

## [0.5.36](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.36) - 2026-06-06

**Disco + STUN observability counters** (roadmap Tier 5, item 20): extend the client-metric registry
with the NAT-traversal counters that surface the operationally-critical direct-vs-DERP-relay signal.
Previously only 5 UDP-datapath counters were wired; the disco path had none.

New `magicsock_*` counters (exported via `Device::metrics()` Prometheus text):
`disco_ping_recv` / `disco_ping_recv_rejected` (passed vs. failed the disco↔node-key binding check),
`disco_pong_sent`, `disco_pong_recv` / `disco_pong_recv_solicited`,
`disco_call_me_maybe_recv` / `disco_call_me_maybe_recv_rejected` (membership-gate accept vs. drop),
`disco_ping_sent`, `disco_call_me_maybe_sealed`, `stun_recv`, and `reflexive_learned` (only on a new
reflexive address, deduped). Each is incremented at the precise disco/STUN handler site; the
binding/gating behavior is byte-identical (pure observation). 5 delta-based tests assert the
counters fire (and the rejected paths do NOT increment the accepted counters). No new dependencies;
counters are relaxed atomics off the hot-path locks.

## [0.5.35](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.35) - 2026-06-06

**Turnkey Tailscale SSH login-shell server** (roadmap Tier 5, item 17): `Device::listen_ssh` now
runs a complete SSH server on the tailnet that grants authorized connections an interactive login
shell as their policy-mapped local user, mirroring Go `tailssh`'s incubator shell path. Behind the
off-by-default, non-musl `ssh` feature.

Previously the fork had the authorization half (`authorize_ssh`, fail-closed, enforced in
`ChannelServer::auth_none`) and a generic `serve_ssh::<H>` accept loop, but the only `ChannelHandler`
was the TUI demo — an embedder had to hand-write a shell handler. This adds the missing piece.

- **`Device::listen_ssh(config, listen_addr)`** = `serve_ssh::<ChannelServer<ShellHandler>>`.
- **`ShellHandler`** (`src/ssh/shell.rs`): resolves the **policy-mapped** local user (from the single
  `auth_none` accept decision — never re-evaluated, never defaulted) against the local passwd db via
  `nix`, spawns the user's login shell (`<shell> -l`) in a PTY (`pty-process`), and pumps the PTY
  master ↔ the SSH channel; window-change sets `TIOCSWINSZ`; child exit reports `exit-status`.
- **Privilege drop** in the child `pre_exec`, in the exact order **initgroups → setgid → setuid**
  (uid last — the order is load-bearing), so the shell runs as the mapped user, never as the
  (root) daemon. **Fail-closed everywhere**: an unresolved user, a failed privilege-drop step, or a
  daemon lacking the privilege to setuid aborts the session rather than running a shell with the
  wrong/elevated identity.
- **Clean environment**: the shell gets only `HOME/USER/LOGNAME/SHELL/PATH/TERM` (env cleared first),
  so the daemon's environment (auth keys, proxy credentials) never leaks into a user shell.
- **Resource bound**: a per-connection cap of 16 concurrent channels prevents an
  authorized-but-hostile peer from fork-bombing the host with session handlers.
- The authorized `local_user` is threaded from the single `auth_none` policy decision through to the
  handler (the `ChannelHandler::new` signature gains the accept identity); the SSH `exec` request
  form is not yet surfaced (interactive login shell only).

New dependencies (`pty-process`, `nix`) are strictly under the `ssh` feature; the default
musl/ring-only egress graph is unchanged (confirmed `aws-lc-rs` absent without `ssh`).

## [0.5.34](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.34) - 2026-06-06

**Language-binding parity** (roadmap Tier 4, item 12): propagate the newer `Device` surface into all
three bindings (`ts_ffi` C ABI, `ts_python` pyo3, `ts_elixir` rustler), bringing them from ~lanes-A–E
coverage up to the full device API.

Each binding now exposes (mirroring its native idiom): `fetch_id_token`, `metrics` (Prometheus
text), `self_key_expiry_unix` / `self_key_expired`, Taildrop receive (`waiting_files`,
`delete_file`, `save_file`-to-path) + Taildrop **send** (`send_file` resolves the peer by name and
streams a local file over the overlay), `capture_pcap`-to-path + `stop_capture`, `loopback` (returns
the bound addr + proxy credential + a stop-on-drop handle), and `tka_status`.

- **C FFI** (`ts_ffi`): new `ts_fetch_id_token`, `ts_metrics`, `ts_self_key_expiry_unix`,
  `ts_self_key_expired`, `ts_tka_status`, `ts_send_file`, `ts_taildrop_{waiting_files,file_size,
  save_file,delete_file}`, `ts_capture_pcap`/`ts_stop_capture`, `ts_loopback`/`ts_loopback_stop`,
  `ts_listen_service` (+ `ts_service_mode`), and `ts_string_free` for library-allocated strings; the
  `tailscale.h` header is regenerated. `listen_funnel` is omitted from the C ABI (its
  `FunnelOptions` type would require a `ts_control` dependency the C crate deliberately avoids; Funnel
  is fail-closed regardless).
- **Python** (`ts_python`): the above as `Device` async methods plus `listen_funnel` /
  `listen_service`, and a `LoopbackHandle` pyclass whose `stop()`/`__del__` tears down the proxy.
- **Elixir** (`ts_elixir`): the above as NIFs plus `listen_funnel`/`listen_service` and a
  `rotate_node_key` on the `Keystate` struct; a `LoopbackHandleResource` is registered for teardown.

`register_fallback_tcp_handler` is intentionally not bridged into Python/Elixir (it takes a native
Rust closure with no clean cross-language callback seam). No new TLS/crypto dependencies — the
ring-only invariant is preserved; the two non-C bindings take an internal `ts_control` dependency for
`FunnelOptions` only.

## [0.5.33](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.33) - 2026-06-06

Hardening + coverage from a multi-reviewer audit of the v0.5.27–v0.5.32 safe-bucket features. No
happy-path behavior change.

- **Capture hot-path fix** (`ts_runtime::capture`): `PcapSink` no longer flushes per record — a
  per-packet `flush()` syscall on the single dataplane thread collapsed throughput under capture.
  Buffered records now flush when the writer is dropped (on `stop_capture`); a new
  `PcapSink::flush()` lets a caller flush periodically for live tailing. The doc comment, which
  wrongly claimed "periodic flush", is corrected. Byte-layout unchanged.
- **WIF blocking I/O fix** (`ts_control::wif`): the AWS web-identity token read now uses
  `tokio::fs::read_to_string` instead of the blocking `std::fs` call inside the async resolver.
- **Loopback connection cap** (`Device::loopback`): the SOCKS5 accept loop now bounds concurrent
  connections with a semaphore (256), so a local client cannot open unbounded overlay sockets
  (each pins ~512 KiB of netstack buffers); the accept loop back-pressures at the cap.
- **Regression tests added**: `RegisterRequest.OldNodeKey` wire (de)serialization (present-when-set,
  omitted-when-`None`); the dataplane capture tee actually firing with `FromLocal` on
  `process_outbound`; and the Taildrop SSRF guard composition (`is_tailscale_ip ∘ peerapi_addr`
  rejects a non-CGNAT peer address).
- **Docs**: `LoopbackHandle` now documents that it is not tied to `Device` shutdown (hold/drop it for
  the proxy's lifetime); the WIF `?baseURL=` is documented as intentionally inert on the `client_id`
  path; the `CapturePath::SynthesizedTo{Local,Peer}` variants are documented as retained for Go
  wire-parity and not yet emitted.

## [0.5.32](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.32) - 2026-06-05

**Loopback SOCKS5 proxy** (`tsr-am9.6`): `Device::loopback()`, porting the SOCKS5 half of Go
`tsnet.Server.Loopback`. Binds a host-loopback TCP listener and proxies SOCKS5 `CONNECT`s into the
tailnet, so a non-Rust host process can reach tailnet peers through the proxy.

- `Device::loopback() -> (SocketAddr, proxy_cred, LoopbackHandle)`: binds `127.0.0.1:0` (**host
  loopback only** — never an external interface), serves SOCKS5 (RFC 1928) with required
  username/password auth (RFC 1929): username `tsnet`, password = a fresh 128-bit random hex
  `proxy_cred`. Each `CONNECT` is dialed **into the overlay** (`ATYP=IPv4` → `tcp_connect`,
  `ATYP=DOMAINNAME` → in-process MagicDNS resolve → overlay dial) and spliced to the accepted
  socket. `ATYP=IPv6` is refused (the fork is IPv4-only on the tailnet); non-`CONNECT` commands are
  refused. The returned `LoopbackHandle` stops the accept loop on drop (`#[must_use]`).
- **Anti-leak**: every connection egresses over the overlay netstack — never a host socket to the
  destination — so the host's real origin IP is never used to reach the target; there is no
  direct-dial fallback. The listener is loopback-only, and name resolution uses the in-process
  netmap (never the host resolver, which would leak intent). The SOCKS5 negotiation is bounded by a
  30s timeout (a stalled local client can't park a task forever); the splice itself is unbounded
  (proxied connections are long-lived).
- The LocalAPI HTTP surface Go also serves on the loopback is intentionally **not** ported: the fork
  exposes status/whois/id-token natively on `Device`, and Go itself recommends the in-process client
  over the loopback LocalAPI — so there is no SOCKS-vs-HTTP demux, just SOCKS5.

## [0.5.31](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.31) - 2026-06-05

**Workload-identity federation (WIF) + OAuth-client auth-key bootstrap** (`tsr-am9.5`), behind the
new off-by-default `identity-federation` cargo feature. Ports Go Tailscale's `feature/oauthkey` +
`feature/identityfederation`: resolve a Tailscale auth key from OAuth-client credentials or an
ambient IdP OIDC token *before* registration.

- New `Config` fields mirroring Go `tsnet.Server`: `auth_key`, `client_id`, `client_secret`,
  `id_token`, `audience` (env fallbacks `TS_AUTH_KEY` / `TS_CLIENT_ID` / `TS_CLIENT_SECRET` /
  `TS_ID_TOKEN` / `TS_AUDIENCE`). `Device::new` resolves the effective key with Go's precedence
  (explicit arg → `config.auth_key` → OAuth/WIF exchange).
- `ts_control::wif` (feature-gated) implements the exact Go wire contract: OAuth client-credentials
  (`POST /api/v2/oauth/token`), the bespoke WIF token-exchange (`POST /api/v2/oauth/token-exchange`
  with `client_id`+`jwt`), and CreateKey (`POST /api/v2/tailnet/-/keys`), plus ambient OIDC-token
  fetch for GitHub Actions / GCP metadata / AWS web-identity-token-file. Validation matches Go
  (client_id requires exactly one of id_token/audience; each requires client_id).
- **SaaS-only** and off by default: a self-hosted control plane does not implement
  these admin-API endpoints (they are not part of the self-hosted control-plane API), mirroring Go's optional
  `feature/` blank-import gating. With the feature off, auth-key resolution is a pure pass-through
  and the config fields are inert — zero behavior change, zero new dependency.
- **Anti-leak preserved**: all calls reuse the existing ring-based `ts_http_util`/`ts_tls_util` stack
  (no new TLS/HTTP/AWS-SDK deps, cert validation intact); credentials/tokens are never logged or
  embedded in error strings; any failure is **fail-closed** (registration aborts — no silent keyless
  fallback). The id-token *issuance* side (`Device::fetch_id_token`) was already shipped earlier;
  this adds the *consumption*/bootstrap half.

The OAuth secret may carry a `?baseURL=` that redirects the exchange host, so the `client_secret` /
`auth_key` value must be treated as fully operator-trusted input (documented on the fields).

## [0.5.30](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.30) - 2026-06-05

**Node-key rotation: wire `RegisterRequest.OldNodeKey` + add the rotation primitive** (`tsr-am9.4`).
Fixes a real bug and completes the embedder-driven rotation path.

The bug: `register()` always sent `OldNodeKey = None`, so the fork's documented "re-create the
Device with a fresh node key + prior `old_node_key`" rotation silently broke key continuity — control
saw each rotation as a brand-new node. There was also no seam to supply the prior key.

- `register()` now sends `RegisterRequest.OldNodeKey` from the key state (omitted, as before, on a
  normal first registration — no behavior change for the common path).
- `PersistState` / `NodeState` carry a new `old_node_key: Option<NodePublicKey>`
  (`#[serde(default)]`, so existing on-disk key files load unchanged → `None`).
- New `PersistState::rotate_node_key()` and `Config::rotate_node_key()` mirror Go's `regen` flow:
  record the current node public key as the old key, generate a fresh node key. Re-create the
  `Device` from the rotated config to perform the rotation.

**This is deliberately NOT a background pre-expiry auto-rotator.** Research confirmed Go tsnet does
**not** auto-rotate the node key before expiry — node-key expiry is an intentional periodic
human/IdP re-authentication control, and the supported posture for unattended servers is to *disable
key expiry* (or use an auth-key / tag), not to silently rotate. Re-registration still requires a
valid auth credential. The fork matches Go: it surfaces expiry (`Device::self_key_expired` /
`self_key_expiry_unix`) and exposes the rotation primitive for the embedder to trigger; it never
silently re-registers on a timer.

Known follow-up: on a tailnet-lock (TKA) enabled tailnet, a rotation must also re-sign the node key
with the network-lock key (`RegisterRequest.NodeKeySignature`); this release covers the non-TKA path
(marked with a `TODO(TKA)`).

## [0.5.29](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.29) - 2026-06-05

**Fix: Tailnet-Lock (TKA) node key is now Ed25519, not X25519** (`tsr-am9.3`). The node-side
network-lock key (`NetworkLockPublicKey`/`NetworkLockPrivateKey`/`NetworkLockKeyPair`) was being
generated as an **X25519** key, but Go Tailscale's `key.NLPrivate`/`NLPublic` are **Ed25519**
(RFC 8032). The X25519 public key sent in `RegisterRequest.NLKey` would never have matched what a
TKA authority expects. Now fixed to standards-conformant Ed25519.

- New `create_ed25519_keypair_types!` macro in `ts_keys`, reusing the existing crypto-agnostic
  byte/Display/FromStr/serde/zerocopy machinery; only the key derivation differs — the public is
  derived via the RFC 8032 seed→public path (`ed25519-dalek`), matching Go's
  `ed25519.PrivateKey.Public()`.
- The `nlpub:`+lowercase-hex wire encoding of the 32-byte Ed25519 public is **byte-identical** to
  Go's `key.NLPublic.MarshalText` (proven by an RFC 8032 §7.1 Test-1 known-answer test through the
  fork's own `NetworkLockPrivateKey`).
- Seed entropy is sourced from `getrandom` (32 uniformly-random bytes) — deliberately **not** from
  x25519's bit-clamped `StaticSecret`, which would reduce seed entropy.
- The persisted node-state key stays 32 bytes with the same `nlpriv:`/`nlpub:` serde form, so the
  change needs **no migration** (matches Go, which was always Ed25519): a pre-fix persisted key
  simply loads as a valid Ed25519 seed and the node re-registers its corrected public on next
  connect. The X25519 key path is unchanged for Disco/Machine/Node keys (those genuinely are
  X25519).

## [0.5.28](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.28) - 2026-06-05

**Debug packet capture / `CapturePcap`** (`tsr-am9.2`): tee a pcap of every packet crossing the
dataplane to a writer, for `tcpdump`/Wireshark debugging — the fork's equivalent of Go Tailscale's
`tsnet.Server.CapturePcap` (`tstun.Wrapper.InstallCaptureHook` + `feature/capture`).

- **`Device::capture_pcap(writer)` / `Device::stop_capture()`** (root crate): install a capture hook
  that streams a pcap to any `std::io::Write`, and clear it. The 24-byte global header is written on
  start; capture is **opt-in** (off by default) and writes **only** to the caller-supplied sink —
  never to the network.
- **Byte-faithful classic-pcap framer** (`ts_runtime::capture::PcapSink`): magic `0xA1B2C3D4`, v2.4,
  snaplen 65535, **`LINKTYPE_USER0` (147)**, with Tailscale's 4-byte per-record path preamble
  (`[path:u16 LE][snat_len=0][dnat_len=0]` — this fork never does SNAT/DNAT) before each raw IP
  packet. A produced file opens in Wireshark; with Tailscale's `ts-dissector.lua` the direction/path
  of each packet decodes. Each record is flushed so a reader tailing the stream sees packets promptly.
- **Read-only dataplane tee** (`ts_dataplane`): a `CapturePath` (`FromLocal`/`FromPeer`/
  `SynthesizedTo{Local,Peer}`, on-wire codes 0–3, matching Go) + an `Option<CaptureHook>` on the
  sync `DataPlane`. Packets are tee'd at two points — outbound pre-encrypt (`FromLocal`) and inbound
  post-decrypt, pre-filter (`FromPeer`) — strictly read-only (no drop/reorder/mutate). When no
  capture is installed the datapath is byte- and performance-identical to before (a single `Option`
  check). The hook is installed/cleared at runtime via the dataplane actor, mirroring the existing
  packet-filter hot-swap.

## [0.5.27](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.27) - 2026-06-05

**Taildrop file sender** (`tsr-am9.1`): the sending half of Tailscale's peer-to-peer file transfer,
mirroring Go's wire sender. The fork already implemented the *receiver* (peerAPI `PUT /v0/put/<name>`
server + path-safe store); this adds the *client* that pushes a local file to a tailnet peer.

- **`Device::send_file(peer, name, content_length, reader)`** (root crate): push `content_length`
  bytes from any `AsyncRead` to a peer as `PUT /v0/put/<name>`. The body streams from offset 0 (the
  Range/resume GET Go uses as an optimization is deliberately omitted — a fresh full PUT is always
  correct).
- **Anti-leak**: the transfer dials **exclusively** over the overlay netstack (`channel.tcp_connect`,
  bound to this node's tailnet IPv4) — never a host socket — reusing the same discipline as the
  peerAPI DoH client (`ts_runtime::peerapi_doh`).
- **SSRF-safe by construction**: the destination is derived **only** from the peer's own node record
  via the new `Node::peerapi_addr()` (`tailnet-ipv4 : peerapi4-port`, mirroring Go
  `peerAPIBase`/`peerAPIPorts`). The caller passes a `&NodeInfo` obtained from `peer_by_name` /
  `peer_by_tailnet_ip` (a current netmap peer), not a raw address; as defense in depth the resolved
  address is additionally asserted to be a Tailscale CGNAT IP before dialing.
- **Request-smuggling-safe**: the file name is validated by the receiver's `validate_base_name`
  (rejects `/`, `\`, NUL, control chars, `..`) **and** percent-escaped with a strict whitelist encoder
  (`path_escape`, the Go `url.PathEscape` counterpart to the receiver's `percent_decode`), so CRLF /
  header injection / path traversal are structurally impossible.
- **Bounded against a hostile peer**: 10s dial timeout, 60s per-write idle timeout (caps a stalled
  `write_all` if a peer accepts the connection but never drains its window), 30s response-head read
  bounded to 8 KiB. Every non-2xx status (`403`→denied, `409`→conflict, other) returns an error — no
  failure is ever masked as success.

## [0.5.26](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.26) - 2026-06-05

Hardening + coverage from a multi-reviewer audit of v0.5.22–v0.5.25. No happy-path behavior change.

- **Security: gate the disco Pong reflexive-harvest** (`ts_magicsock`). `note_reflexive(src)` on an
  inbound Pong is now performed only when the pong is **both** (1) from a current netmap member
  (verifier checked, same as CallMeMaybe) and (2) **solicited** — it matched an outstanding ping we
  actually sent for that `(tx_id, from)`. Previously any party knowing our control-advertised disco
  pubkey could seal a pong with an arbitrary `src` and pollute our reflexive set (advertised to
  control + in CallMeMaybe, and amplified into the new `Stun4LocalPort` guess). The legitimate
  NAT-traversal path is unchanged.
- **`is_symmetric_nat` predicate extracted** (`ts_magicsock`): symmetric-NAT detection is now a
  named, documented method separate from endpoint assembly; the `reflexive` lock no longer spans the
  candidate-build loop.
- **`IdTokenError` owns its error vocabulary** (`ts_control`): a private `IdTokenInternalErrorKind`
  replaces the cross-module reuse of registration's error kind. `parse_token_response` and
  `flatten_send_err` were extracted and a **30s timeout** now bounds the id-token RPC.
- **Coverage**: added the previously-missing tests for the id-token RPC error mapping + response
  parsing (15), the kameo send-error flatten (3), `peer_relay` wire (de)serialization (3), the
  chrono-free key-expiry variants + `expiry==now` boundary + `is_peer_relay` (4), symmetric-NAT edge
  cases (local-port-skip / dedup / IPv6-ignored / non-member + unsolicited pong, 5), and a byte-exact
  Geneve reference vector (2) closing the self-roundtrip-only blind spot.

## [0.5.25](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.25) - 2026-06-05

**Symmetric-NAT traversal: hard-NAT local-port candidate** (`tsr-bs7`): improve direct-connect
success behind symmetric (endpoint-dependent-mapping) NATs, mirroring **current** Go Tailscale.

- magicsock now detects a symmetric NAT when the one bound socket is observed at **two or more
  distinct reflexive IPv4 `addr:port`s** (endpoint-dependent mapping — exactly Go's
  `MappingVariesByDestIP` determination from multi-STUN-server observations), or when set explicitly
  via `MagicSock::set_symmetric_nat` (e.g. from control's `NetInfo`).
- When symmetric NAT is detected, `self_endpoints()` advertises an extra hard-NAT candidate pairing
  a reflexive IPv4 with the node's **local** bound port (`SelfEndpointType::Stun4LocalPort` →
  control `EndpointType::Stun4LocalPort`), mirroring Go's `EndpointSTUN4LocalPort`: if the router
  has a static port-mapping to the fixed local port, this `(reflexive_ip, local_port)` may be
  reachable where the per-destination reflexive port is not. It rides the existing
  Pong→`bestAddr` path-selection with no special handling.

**Scope note:** the classic *birthday-paradox port-spray* this bead was named for **no longer exists
in mainline Tailscale** — it was removed in favor of this single static-port-mapping guess + DERP
fallback. Porting the spray would reimplement dead upstream code, so this release matches what Go
actually does today; behind a hard NAT with no static mapping, a flow still falls back to DERP (as
in upstream).

## [0.5.24](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.24) - 2026-06-05

**Peer-relay awareness** (`tsr-77q-d`): make the fork wire-aware of Tailscale's peer-relay feature
(relaying traffic through a peer's UDP relay server, Geneve-encapsulated). This is the bounded,
client-aware slice; the **active relay data path is intentionally deferred** (see below).

- **Geneve codec** (`ts_packet::geneve`, re-exported as `tailscale::geneve`): parse/encode the
  RFC 8926 fixed Geneve header Tailscale uses for relayed disco + WireGuard frames (the C bit,
  protocol type `0x7A11`/`0x7A12`, 24-bit VNI). Rejects non-zero version / variable options so a
  foreign Geneve packet isn't mis-decoded.
- **`Hostinfo.PeerRelay`** is parsed into `ts_control::Node::peer_relay` with an
  `is_peer_relay()` accessor, so a relay-capable peer can be recognized. (The fork is a relay
  *client* only and never advertises itself as a relay server.)

**Deferred:** actually traversing a relay path — the `relayManager` allocation/handshake state
machine + magicsock Geneve data path — is a large subsystem (Go ~1700-2000 LOC of stateful client
code) and is **not implemented**. This release makes the fork recognize the framing and peer
capability without choking; the disco demux already gracefully ignores relayed control frames it
can't act on. (The private/custom **DERP map** half of this bead was already satisfied — the fork
honors control-pushed DERP maps.)

## [0.5.23](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.23) - 2026-06-05

**Node-key expiry handling** (`tsr-77q-e`): surface this node's key-expiry state so an embedder can
react (re-authenticate / rotate), mirroring Go's **reactive** model.

- `ts_control::Node::key_expired(now)` / `key_expiry()` (and `chrono`-free `key_expired_at_unix` /
  `key_expiry_unix`): compute expiry from the self-node's `KeyExpiry` exactly as Go does
  (`!KeyExpiry.IsZero() && KeyExpiry.Before(now)`; a key with no expiry never expires).
- `Device::self_key_expiry_unix()` / `Device::self_key_expired()`: expose the current node's expiry
  instant and expired flag.

Per Go, the fork does **not** auto-rotate the node key in the background — Go transitions to
`NeedsLogin` on expiry and re-registers via a stored auth-key or interactive login. The registration
wire path already carries `RegisterRequest::old_node_key` + `expiry` for rotation (set a fresh
`node_key` + the prior `old_node_key` to rotate, or the same key to refresh); this release adds the
client-side *detection* half.

## [0.5.22](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.22) - 2026-06-05

**OIDC ID-token issuance / workload-identity federation** (`tsr-cdv`): a node can now ask control
to mint a short-lived OIDC ID token (JWT) it can present to a third-party relying party (e.g.
AWS/GCP workload-identity federation), mirroring Go `tailscale`'s `id-token` LocalAPI.

- **Wire types** (`ts_control_serde`): `TokenRequest` (`{CapVersion, NodeKey, Audience}`) and
  `TokenResponse` (`{id_token}`), mirroring `tailcfg.TokenRequest`/`TokenResponse`.
- **Noise RPC** (`ts_control::fetch_id_token`): `POST /machine/id-token` over the ts2021 transport,
  returning the signed JWT whose `aud` claim is the requested audience. Requires control capability
  version ≥ 30.
- **API**: `Device::fetch_id_token(audience)` (via a `ControlRunner` delegated-reply message + a
  `Runtime` wrapper). The node is the token *subject*, not the authenticator — this is token
  issuance, not a registration/login path; `RegisterRequest` is unchanged.

(Note: Go has no `ClientID` field and no separate federated-registration wire path — the bead's
"ClientID/Audience" framing maps to this issuance flow, where `Audience` is a per-call runtime input
and there is no `ClientID`. `tsnet.Sys()` is an unrelated generic subsystem accessor and is not
modelled.)

## [0.5.21](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.21) - 2026-06-05

Hardening from a multi-reviewer audit of the v0.5.15–v0.5.20 parity features. No behavior change to
the happy paths; tightens fail-closed posture, removes DoS levers, and adds coverage.

- **TKA: bound recursion on untrusted input** (`ts_tka`). A peer-supplied `NodeKeySignature` CBOR
  blob is now depth-capped (`MAX_SIG_NESTING_DEPTH = 16`) at **decode** time — both the
  signature-chain walk and generic CBOR container nesting — so a deeply-nested blob can no longer
  overflow the stack (DoS). The CBOR decoder also now rejects duplicate map keys (CTAP2/Go parity).
- **TKA: bind nested-credential pubkey** (`ts_tka`). A `SigKind::Credential` reached via a rotation
  wrap must now have its `pubkey` equal the rotation pivot, closing a latent soundness gap vs Go.
- **TKA tests**: added the previously-missing rotation-chain end-to-end test, the nested-credential
  bind test, and the depth-cap rejection test; documented the ZIP-215-vs-standard verifier split in
  `Cargo.toml`. Removed dead `text_string_map`/`Value::TextMap` encoder surface.
- **Taildrop: move blocking fsync off the async runtime** (`ts_runtime::taildrop`). The terminal
  `flush`+`sync_all`+atomic `rename` now run in `tokio::task::spawn_blocking`, so up to 512
  concurrent transfers no longer starve the tokio worker pool. Fail-closed preserved (a finalize
  failure leaves the partial in place, never publishes).
- **peerAPI/Taildrop tests**: added request→response coverage driving the production `BodyReader` +
  `put_file` over real async streams (200/403/400/405, the DoH-route regression guard, and the
  Content-Length cap), plus the previously-untested offset-resume path.
- **Device error fidelity**: `taildrop_*` errors now map to distinct `InternalErrorKind`
  (`BadRequest` / `AlreadyExists` / `NotFound` / `Io`) instead of collapsing every failure into the
  generic `Actor` kind, so callers can act on the actual cause.

## [0.5.20](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.20) - 2026-06-05

**Tailnet Lock (TKA) verification** (`tsr-77q-c`): the client-side signature-chain verification path
of Tailscale's Tailnet Lock, mirroring Go's `tka` package. Fail-closed.

- **`ts_tka` crate**: a dependency-light reimplementation of the TKA verification primitives —
  a CTAP2-canonical CBOR encoder (so a value's signing digest is byte-identical to Go's
  `fxamacker/cbor` CTAP2 output), `AumHash` (BLAKE2s-256 + RFC4648 base32-nopad, the type
  `TkaInfo.head` carries), the `Aum`/`Key`/`NodeKeySignature` wire vocabulary, and an `Authority`
  exposing `node_key_authorized` — the check that a peer's node key is signed by a key trusted under
  the current tailnet-lock state. Signature verification uses ZIP-215 (cofactored) Ed25519 for
  direct/credential signatures (matching Go `ed25519consensus`) and standard Ed25519 for the
  rotation wrap.
- **Netmap threading**: control's `TKAInfo` (head + disablement) is parsed into a domain `TkaStatus`,
  threaded `MapResponse` → `StateUpdate` → `ControlRunner`, and exposed via `Device::tka_status()`.
  The `tailscale::tka` module re-exports the verification engine for embedders.
- **Fail-closed**: any decode/shape/signature failure denies authorization; a credential-only
  signature can never authorize a node; an untrusted authorizing key denies.

**Validation caveat:** the CTAP2-CBOR byte-exactness is asserted by construction and exercised by an
end-to-end Ed25519 sign→verify roundtrip, but has **not** been cross-validated against Go-produced
TKA test vectors. A *failed* verification is always safe to act on (deny); treat a *successful* one
as advisory until vectors land. The node's own NL-key signing (admin side) is out of scope — the
fork's `NetworkLockPublicKey` is modelled as X25519 while Go TKA keys are Ed25519; only client-side
verification (against peers' Ed25519 keys in the authority state) is implemented here.

## [0.5.19](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.19) - 2026-06-05

**Client metrics / observability** (`tsr-77q-b`): a `clientmetric`-style in-process metric registry
plus a `Device::metrics()` Prometheus-text export. (Go `tsnet` exposes no metrics method of its own,
so this is the fork's clean public surface.)

- **`ts_metrics` crate**: a small, dependency-free reimplementation of Go's `util/clientmetric` — a
  process-global registry of named counters/gauges (`Metric::new_counter` / `new_gauge`, `add` /
  `inc` / `set`, single relaxed-atomic increments on hot paths) with a `write_prometheus` exporter
  emitting `# TYPE <name> <kind>\n<name> <value>\n` per metric, name-sorted. Metric names are
  validated to `[A-Za-z0-9_]` (Go `isIllegalMetricRune`).
- **magicsock counters**: the direct-UDP datapath now increments canonical `magicsock_*` counters
  (`magicsock_send_udp`, `magicsock_send_udp_bytes`, `magicsock_send_udp_error`,
  `magicsock_recv_data_udp`, `magicsock_recv_data_bytes_udp`), matching the Go naming convention.
- **`Device::metrics() -> String`** returns the full Prometheus text exposition for the embedder to
  scrape or forward.

## [0.5.18](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.18) - 2026-06-05

**Taildrop file transfer (receive side)** (`tsr-77q-a`): this node can now receive files from
tailnet peers over the peerAPI, mirroring Go Tailscale's Taildrop. Fail-closed and IPv4-only.

- **Path-safe file store** (`ts_runtime::taildrop`): a `TaildropStore` that writes each incoming
  transfer to a `<name>.partial` file and **atomically renames** it to the final name on success
  (non-clobbering ` (n)` suffix on conflict, Go `nextFilename`). `validate_base_name` is the
  security boundary — it rejects path separators, `..`, NUL/control chars, and the reserved
  `.partial`/`.deleted` suffixes before any path is constructed, so a malicious file name can never
  escape the store directory. Supports offset-resume.
- **peerAPI route + router** (`ts_runtime::peerapi`): the peerAPI listener is now a single
  path-routing server (mirroring Go's one-server-many-routes model). `PUT /v0/put/<name>` lands a
  Taildrop file (`200 OK` + `{}\n`; `400` invalid name, `409` in-progress conflict, `405` wrong
  method); `/dns-query` continues to the existing exit-node DoH handler byte-for-byte.
- **Fail-closed access gate**: a `PUT` is accepted only when a Taildrop directory is configured
  (`Config::taildrop_dir`, default `None` = disabled) **and** this node holds the
  `https://tailscale.com/cap/file-sharing` node capability **and** the source IP resolves to a known
  tailnet node. (The per-peer `file-send` peer-capability check is deferred until the packet-filter
  peer-cap map is threaded into the runtime node model — documented in `peerapi.rs`; the surface
  stays fail-closed without it.)
- **Embedder API** (`Device`): `taildrop_waiting_files()`, `taildrop_open_file(name)`, and
  `taildrop_delete_file(name)` let the host application consume received files. `WaitingFile` is
  re-exported from the crate root.

The sender side (`tailscale file cp` / push) and the LocalAPI long-poll are out of scope for this
slice; this is the receive half a peer pushes to.

## [0.5.17](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.17) - 2026-06-05

**Tailscale VIP services / `ListenService`** (`tsr-6b5`): a node can now host a Tailscale **VIP
service** (`svc:<label>`) by binding an overlay listener on the virtual IP address control assigned
that service, mirroring Go `tsnet.Server.ListenService`. Fail-closed throughout.

- **Wire types** (`ts_control_serde`): `ServiceName` (`svc:<label>`), `VipService`,
  `ProtoPortRange`, and `ServiceIpMappings` (the value of the `service-host` node-capability —
  `NODE_ATTR_SERVICE_HOST`), mirroring `tailcfg`. These are the control-assigned service→VIP
  mappings a host learns from its netmap.
- **Domain model** (`ts_control::Node`): a new `service_vips` map (svc-name → VIP IPs) parsed from
  the `service-host` cap, with `service_addresses()` (flattened set) / `service_addresses_for(name)`
  (per-service) accessors and an `is_service_host()` gate. A `validate_service_name` enforces the
  `svc:<dns-label>` shape.
- **Listen gate** (`ts_control::resolve_service_listen` + `Device::listen_service`): binds a
  listener on the service's control-assigned VIP only when the name is valid, the host is **tagged**
  (Go `ErrUntaggedServiceHost`), and control assigned that specific service a VIP — otherwise a
  typed `ServiceError` and the node serves nothing (never a host socket, never an unbound listen).
  Per-service VIP selection ensures a multi-service co-host binds the correct address for each
  service.
- **Netstack acceptance**: control-assigned VIPs are added to the application netstack's
  accepted-address set (the same mechanism as the MagicDNS `100.100.100.100` service IP) so a
  hosted-service listener is reachable by tailnet peers. IPv6 VIPs are dropped when IPv6 is disabled
  on the overlay (the default), consistently in both the accept-set and the listen resolver — the
  fork stays IPv4-only by default.

The advertise→`c2n`-fetch leg (`Hostinfo.ServicesHash` + control's `GET /vip-services`) and the
L3/`Tun` service mode (a TODO in upstream tsnet) are out of scope for this slice; VIP hosting works
from the control-assigned `service-host` mapping a node already receives.

## [0.5.16](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.16) - 2026-06-05

**Tailscale SSH server authorization** (`tsr-l24`): the in-process SSH server now enforces the
control-pushed `SSHPolicy`, brought to Go `tailssh` parity and made **fail-closed**. Previously the
SSH `ChannelServer` accepted *any* known tailnet peer with no policy evaluation; that gap is closed.

- **Wire types** (`ts_control_serde`): `SSHPolicy` / `SSHRule` / `SSHPrincipal` / `SSHAction` /
  `SSHRecorderFailureAction`, mirroring `tailcfg` field-for-field (verbatim lowerCamel JSON tags:
  `ruleExpires`, `sshUsers`, `nodeIP`, `userLogin`, `sessionDuration` (nanoseconds), `notifyURL`,
  …). `MapResponse.SSHPolicy` is now deserialized off the netmap.
- **Policy evaluator** (`ts_control::SshPolicy`): an owned domain model + `evaluate` that reproduces
  Go `evalSSHPolicy` / `matchRule` / `mapLocalUser` — **first-match-wins, default-deny**, with the
  exact `SSHUsers` map semantics (`"*"` wildcard key, `"="` identity map, empty-string value =
  rule does not apply). Principal matching by stable node id / node IP / `any`. Rule-expiry is
  honored and **fails closed**: an unreadable host clock makes time-limited rules look expired
  (deny) rather than perpetually live.
- **Server enforcement** (`Device::authorize_ssh`, `ssh` feature): resolves the connection's source
  IP to a known tailnet peer (unknown ⇒ deny), fetches the current policy (**absent ⇒ deny-all**),
  and evaluates it; `auth_none` rejects on any deny *or* any lookup error. The policy is threaded
  netmap → `StateUpdate` → `ControlRunner` (watch channel) → `Device`.
- **musl-clean isolation guard** (`checks::ssh_isolation`): a new build-gate asserting the `ssh`
  feature (which pulls `russh` → `aws-lc-rs`) stays OFF by default, `dep:russh`-gated, and that
  `aws-lc-rs` is never a direct dependency — so the core tailnet/egress path remains `ring`-only and
  cross-compiles cleanly to musl. The SSH server is meant to run isolated in a separate non-musl
  binary.

Advanced SSH features (session recording / `OnRecordingFailure`, the interactive `holdAndDelegate`
control round-trip) are intentionally out of scope for this basic `ListenSSH` parity slice.

## [0.5.15](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.15) - 2026-06-05

**`ListenFunnel`** (`tsr-jir`): the Tailscale Funnel public-ingress entry point, brought to the same
fail-closed posture as `ListenTLS`. `Device::listen_funnel` validates that the self node may funnel
before doing anything, then attempts to terminate TLS on the overlay netstack — never on a host
socket, never with a self-signed cert, never with a plaintext downgrade.

- **Capability gating mirrors Go `tsnet` exactly** (`ts_control::Node`): `NodeCanFunnel` requires
  BOTH `CapabilityHTTPS` (`"https"`) AND `NodeAttrFunnel` (`"funnel"`) in the node's CapMap, and
  `CheckFunnelPort` reads the allowed ports from the `funnel-ports` cap **key's** `?ports=` query —
  comma-separated single ports (string equality) plus `first-last` inclusive `uint16` ranges. An
  empty / unparseable / missing / wrong-URL ports query denies. The node carries an owned
  `NodeCapMap` populated from the netmap.
- **`FunnelError`** (`NotAllowed` / `PortNotAllowed` / `Cert` / `Unsupported`) and
  `FunnelOptions { funnel_only }` in `ts_control::serve`. `listen_funnel` runs the access check →
  `cert::get_certificate` (which is itself `Unimplemented` in this fork) → and, since a self-hosted
  control plane provides no Tailscale-operated public ingress relay, surfaces
  `FunnelError::Unsupported` rather than bringing a non-functional listener up. Fail-closed.
- **capver-113 ingress signalling**: a new default-`false` `wire_ingress` config knob threads
  through `tailscale::Config` → `ts_control::Config` → the registration and streaming map-request
  `HostInfo`. When set, it advertises `HostInfo.WireIngress` ("would like to be wired up for
  Funnel") to control. `HostInfo.IngressEnabled` is intentionally left `false` — no Funnel endpoint
  ever goes live in this fork, mirroring how Go suppresses `WireIngress` only once ingress is
  actually enabled.
- **`funnel_fail_closed` leak-firewall** (`checks` crate): a new build-gate that scans the
  production (non-test) portion of both `ts_control/src/serve.rs` and `ts_control/src/cert.rs` for
  self-signed cert-minting tokens (`rcgen` / `generate_simple_self_signed` / `self_signed`), so a
  self-signed fallback can never silently regress into the public-TLS termination path. The
  `#[cfg(test)]` cutoff is matched only at column 0 and the file must contain exactly one such
  boundary, closing an evasion vector.

## [0.5.14](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.14) - 2026-06-05

**TUN-mode host integration** (`tsr-248.1`): a new `ts_host_net` crate programs the host routing
table and system resolver so a TUN-mode node's traffic is actually steered into the kernel TUN
interface. Without it the TUN device exists but the OS has no FIB entries pointing tailnet / subnet
/ exit prefixes at it. This is the host-side analogue of `ts_forwarder`'s `RealDialer` anti-leak
chokepoint, and is **off the default (netstack) path** — it only runs in TUN transport mode.

- **`ts_host_net` crate**: a `HostNet` trait (`apply_routes` / `apply_dns` / `teardown`) with
  per-OS implementations — macOS (`route(8)` + `scutil(8)`), Linux (`ip(8)` + `resolvectl(1)`),
  and a typed `Unsupported` error on every other platform (never a silent no-op). Zero new heavy
  dependencies (`ipnet` / `thiserror` / `tracing` only), keeping the musl-clean posture intact.
- **IPv4-only by construction**: `HostRoutes` / `HostDns` carry only `Ipv4Net` / `Ipv4Addr`, so a
  v6 route can never be emitted. A new `ipv4_only_host_net` `checks`-crate grep gate enforces it.
- **Fail-closed**: a partial `apply_*` rolls back its own state before returning `Err`; `teardown`
  reverses exactly what was installed. The TUN actor never pumps packets on an unrouted interface
  and never silently falls back to the netstack.
- **`/0` split-default**: a literal `0.0.0.0/0` exit route is expanded to the reversible
  `0.0.0.0/1` + `128.0.0.0/1` pair (longest-prefix-match wins without clobbering the host default;
  avoids `EEXIST` from `route add default` on macOS). Shared between both platform impls so they
  cannot drift.
- **Host-route gating**: subnet routes are steered into the TUN only when `--accept-routes` is set,
  and the host `/0` only when an exit node is configured (`HostRouteGating`).
- **Anti-injection input guards**: control-supplied DNS match-domains and the (embedder-influenced)
  TUN interface name are validated as strict DNS / interface names before reaching a privileged
  argv or `scutil` stdin script — a domain containing a newline can no longer inject a `scutil`
  verb. DNS programming is inert this slice (empty nameservers ⇒ no-op) until a TUN-mode MagicDNS
  responder exists; pointing the resolver at a dead `100.100.100.100` would black-hole.

## [0.5.13](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.13) - 2026-06-05

Cleanup of two known compromises from the v0.5.12 TUN-mode work; no behavior change to the data or
egress paths.

- **Dedicated error variant** (root `tailscale`): added `InternalErrorKind::UnsupportedInTunMode`.
  Netstack-only `Device` APIs (and the internal `channel()` accessor) now surface this in TUN mode
  instead of overloading the generic `InternalErrorKind::Actor` "internal component unavailable"
  sentinel, so callers can distinguish "wrong transport mode" from a genuine actor failure. The
  `ts_runtime` `UnsupportedInTunMode` / `TunUnavailable` kinds map to it.
- **`ts_transport_tun` serde feature fixed**: the `serde` feature now also enables `ipnet/serde`, so
  the `Config` struct (which holds an `ipnet::IpNet`) actually derives working
  `Serialize`/`Deserialize`. Added a gated `config_serde_round_trip` test.

## [0.5.12](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.12) - 2026-06-05

**TUN-mode transport**, gated behind a new default-off `tun` Cargo feature. A node can now run its
application data path over a real kernel TUN interface (`utun` on macOS, `/dev/net/tun` on Linux)
instead of the userspace smoltcp netstack, selected via a new `Config::transport_mode`
(`TransportMode::Netstack` — the default — or `TransportMode::Tun(TunConfig { name, mtu })`). This
brings the fork toward Go `tsnet`'s TUN/`Up`-style data path while leaving the default userspace
posture byte-for-byte unchanged.

**The forwarder / exit-node egress path is UNCHANGED and stays hardcoded IPv4 in both modes** —
TUN mode swaps only the *application* data path, never the forwarder. The real-origin-IP isolation
invariant and its `checks`-crate grep gate are untouched.

- **Feature gate** (`ts_runtime`, root `tailscale`): the `tun` feature is **off by default**. With
  it off, no TUN code compiles and the default dependency graph is unchanged (`ts_transport_tun`
  does not enter it). `tun-rs` is off the `ring`-only egress path, so the musl-clean egress
  invariant holds.
- **Transport selection** (`ts_runtime::Runtime::spawn`): branches on `Config::transport_mode`.
  Netstack mode spawns the application netstack + MagicDNS responder + fallback-TCP registry as
  before; TUN mode spawns a `TunActor` on the same overlay seam instead. **Fail-closed, no silent
  fallback:** requesting `Tun` in a build without the `tun` feature is a hard error
  (`ErrorKind::TunUnavailable`), never a silent downgrade to netstack.
- **`TunActor`** (`ts_runtime::tun_actor`): creates the device lazily on the first netmap update
  (the tailnet `/32` prefix is assigned by control at runtime), then runs a two-task pump moving
  packets between the kernel interface and the dataplane. Device-creation failure (e.g. missing
  root / `CAP_NET_ADMIN`) logs a single error and leaves the actor idle — **no packets flow, no
  leak** — rather than falling back.
- **Crate hardening** (`ts_transport_tun`): `AsyncTunTransport::new` now maps a
  `PermissionDenied` device-open to the typed `Error::RootUserRequired` (previously a dead
  variant), dead code removed.
- **In TUN mode there is no application netstack**: netstack-only `Device` APIs (`udp_bind`,
  `tcp_listen`, `tcp_connect`, `register_fallback_tcp_handler`, …) return an error
  (`ErrorKind::UnsupportedInTunMode`); control-plane and peer-lookup APIs are unaffected.
  `register_fallback_tcp_handler` is now fallible (returns `Result`) to reflect this.

Note: true Go-`tsnet` TUN parity also requires host **route and DNS programming** (Go's
`router`/`dns` engines) so the OS actually sends overlay traffic to the interface; that is tracked
as a follow-up and is out of scope for this data-path seam.

## [0.5.11](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.11) - 2026-06-05

IPv6 **on the tailnet overlay**, gated and default-off. A new runtime flag `Config::enable_ipv6`
(`false` by default — the node stays IPv4-only) opts a node into native IPv6 overlay addressing,
disco candidates, and MagicDNS AAAA. This brings overlay IPv6 to parity with Go `tsnet`'s
`--ipv6`-style posture while keeping the fork's IPv4-only default intact.

**The flag governs only the overlay. It has no effect on the exit-node / forwarder egress path,
which stays hardcoded IPv4 regardless** — the real-origin-IP isolation invariant. This is now
enforced two ways: a public-API guard test (`ts_forwarder/tests/ipv4_only_guard.rs`) asserts every
dialer errors on an IPv6 destination, and a CI grep gate (`ipv4_only_forwarder` in the `checks`
crate, run by `cargo run -p checks`) fails the build if any IPv6 bind/connect/gate token appears in
`ts_forwarder/src/`.

- **Underlay bind** (`ts_runtime::direct`): with the gate on, binds dual-stack `[::]:0` (single
  socket serving native v6 and v4-mapped v4); with the gate off, binds `0.0.0.0:0` as before. The v6
  bind **fails inert** — if the host has IPv6 disabled at the kernel, it warns and falls back to
  IPv4-only rather than failing to come up.
- **Disco candidates** (`ts_magicsock`): with the gate on, IPv6 endpoints that are valid global
  unicast (not loopback / link-local / ULA / multicast / unspecified) become ping candidates; with
  the gate off, all IPv6 candidates are rejected. STUN stays IPv4-only.
- **Netstack addressing** (`ts_runtime::netstack_actor`): with the gate on, the node's IPv6 /128
  overlay address is assigned alongside the IPv4 /32. The `ts_netstack_smoltcp_core` interface
  address capacity was raised (`iface-max-addr-count-5`) so the v4 + v6 + MagicDNS + dual loopback
  address set no longer silently overflows.
- **MagicDNS** (`ts_runtime::magic_dns`): with the gate on, AAAA queries for tailnet names answer the
  peer's overlay IPv6; with the gate off, AAAA returns NODATA (`NOERROR` + empty answer) and tailnet
  AAAA is never forwarded upstream.

## [0.5.10](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.10) - 2026-06-04

Foreign-language binding parity: the C FFI (`ts_ffi`), Python (`ts_python`, PyO3), and Elixir
(`ts_elixir`, Rustler NIF) bindings now expose the same five capability lanes the native `tailscale`
crate already had, bringing each binding to feature parity with Go `tsnet`'s surface. Pure binding
plumbing — no change to the native API or its semantics.

- Lane 1 (Status/WhoIs): `status`, `whois`, and a one-shot `netmap` snapshot in all three bindings.
  Status/StatusNode/WhoIs are marshaled idiomatically (visitor-callback structs in C; `IntoPyObject`
  in Python; `NifStruct` in Elixir). `online` maps to tri-state (1/0/-1, None/bool, `true/false/nil`);
  `allowed_routes` to CIDR strings; `capabilities` to `(name, [values])` pairs.
- Lane 2 (MagicDNS): `resolve(name) -> Option<ipv4>` and `connect_by_name(name, port)` returning the
  binding's existing TCP-stream handle type.
- Lane 3 (Forwarding config): the 8 forwarding fields (`accept_routes`, `exit_node`,
  `advertise_routes`, `advertise_exit_node`, `forward_tcp_ports`, `forward_udp_ports`,
  `forward_all_ports`, `forward_exit_egress`) are accepted from each binding's config constructor and
  threaded into `tailscale::Config`.
- Lane 4 (Ping): `ping(addr, timeout_ms)` returning RTT in milliseconds.
- Lane 5 (TLS/Serve): full `ServeConfig`/`ServeTarget` marshaling plus `get_certificate` and
  `listen_tls`. **Fail-closed (sacred):** issuance is `Unimplemented` in this fork, so both surfaces
  always propagate the native `CertError` (negative return / raised exception / `{:error, reason}`)
  and never self-sign or fabricate success.
- C FFI exposes the new types without a doubled prefix (`status_node` → `ts_status_node` via
  cbindgen); `tailscale.h` is regenerated at build time (gitignored).

## [0.5.9](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.9) - 2026-06-04

Full exit-node DNS proxy (peerAPI DoH) parity with Go `tsnet`. When this node is selected as a
peer's exit node, it now answers that peer's recursive DNS over the overlay; and when this node has
selected an exit node, its own recursive lookups are delegated to that exit node's DoH endpoint
instead of leaking to a local resolver.

- Feat (server): a peerAPI DoH server (`/dns-query`, RFC 8484 over HTTP/1.1 on the encrypted overlay)
  shares the same `decide` path as the local MagicDNS responder, so authoritative MagicDNS records
  (peer names, control-pushed `ExtraRecords`, PTR) are answered identically. Binds the overlay IPv4
  at `Config::peerapi_port`. Supports `POST` (body is the raw DNS message) and
  `GET ?dns=<base64url>`.
- Feat (client): when an exit node is active, the MagicDNS responder delegates catch-all **recursive**
  forwards to the exit node's peerAPI DoH endpoint over the overlay (`forward_doh`). Deliberately
  configured split-DNS routes always stay on their configured upstreams (never delegated). Resolvers
  marked `use_with_exit_node` are kept local, mirroring Go's `UseWithExitNode`.
- Feat (control): `Node::peerapi_doh_url` / `peerapi_doh_addr` expose a peer's DoH endpoint
  (IPv4-only), gated on `peerapi_dns_proxy || cap >= PEER_CAN_PROXY_DNS` (CapabilityVersion 26) and a
  non-WireGuard-only peer. `route_updater` publishes the active exit node so the responder can
  resolve its DoH address once.
- Anti-leak / fail-closed (sacred): server recursion is gated behind `forward_exit_egress` — a node
  that hasn't opted into exit egress answers a recursive query `REFUSED`, never resolving a peer's
  public name through its own host resolver (the cloud host's real IP can't leak). Names in control's
  `ExitNodeFilteredSet` are `REFUSED`. Client delegation is fail-closed: any DoH connect/HTTP/timeout
  failure resolves to NXDOMAIN — **never a silent fallback to a local resolver**. All sockets are on
  the overlay netstack (`0.0.0.0:0`), never a host socket; IPv4-only. Requests and responses are
  size-capped; concurrent in-flight requests are bounded.

## [0.5.8](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.8) - 2026-06-04

`tsnet.Server.RegisterFallbackTCPHandler` parity: an embedder can now register a callback consulted
for every **inbound TCP flow that matches no explicit `Device::tcp_listen` listener**, mirroring Go
`tsnet`'s fallback-handler contract.

- Feat: `Device::register_fallback_tcp_handler(cb)` returns a `#[must_use]` `FallbackTcpHandle` that
  deregisters on drop (mirrors the `unregister func()` Go returns). The callback receives the
  `(src, dst)` `SocketAddr` pair and returns a `FallbackDecision` — `(None, false)` declines (the
  next handler is tried), `(Some(handler), true)` claims the flow, and `(None, true)` claims and
  rejects it. Multiple handlers dispatch in registration order; the first to intercept wins.
- Feat: read-only `BoundPorts` query on the netstack listener registry
  (`CreateSocket::bound_tcp_ports`) so the fallback manager never binds a competing any-IP listener
  on a port the embedder already serves with an explicit `tcp_listen`.
- How it works: a raw `(Ipv4, Tcp)` observer socket suppresses smoltcp's unmatched-SYN RST and
  reveals each SYN's destination port; the manager lazily materializes a per-port any-IP listener
  and dispatches accepted flows to the registered handlers. The observer runs **only while at least
  one handler is registered** — started on the first registration, torn down on the last
  deregistration — so the netstack's default **fail-closed RST** behavior stays pristine when no
  handler is installed.
- Anti-leak / DoS bounds: flows no handler claims are **closed (fail-closed), never direct-dialed**;
  the observer never creates a host socket. Per-port listeners are capped (`MAX_PORTS = 1024`),
  idle-reaped (120 s), and per-port in-flight flows are bounded (`MAX_INFLIGHT = 512`). IPv4-only.

## [0.5.7](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.7) - 2026-06-04

Documentation correction (no code change): the TLS-certificate seam (`ts_control::cert`) described
a control protocol that **does not exist** in real Tailscale, which would have led a future
implementer to build the wrong thing.

- Docs: corrected `ts_control/src/cert.rs` (and the matching `serve.rs` / `src/lib.rs` doc
  references) to describe the **actual** tsnet certificate protocol. There is **no**
  `POST /machine/<machineKey>/cert/<domain>` "ACME-over-control" endpoint — the node itself is the
  ACME client and talks **directly to Let's Encrypt**; control's only role is to publish the
  **DNS-01** challenge TXT (`_acme-challenge.<name>`) via `POST /machine/set-dns` over the Noise
  (ts2021) channel, with `NodeKey` carried in the request body (`SetDNSRequest`) and an empty
  `SetDNSResponse{}` on 200. (DNS-01 is for `*.ts.net`; TLS-ALPN-01 is for Funnel/BYO; HTTP-01 is
  unused.) Updated `MISSING_CERT_RPC` and the `CertError::Unimplemented` detail to name the real
  missing pieces: a client-side ACME engine plus a `set-dns` Noise RPC.
- Docs: recorded the **deployment caveat** explaining why issuance stays a fail-closed stub rather
  than being built now — the fork's control target is **a self-hosted control plane**, which returns **HTTP 501
  NotImplemented** for `/machine/set-dns`, so a client-side ACME engine could not complete a DNS-01
  challenge against a self-hosted control plane regardless. The fail-closed contract is unchanged:
  `get_certificate` / `listen_tls` still return `CertError::Unimplemented` after the tailnet-name
  check, never self-signing and never downgrading to plaintext.

## [0.5.6](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.6) - 2026-06-04

Documentation hygiene (no code change): the README's "Unsupported" list contradicted its own
"Implemented" section and the actual code.

- Docs: removed **Split DNS** and **upstream/recursive DNS forwarding** from the README's
  "Unsupported features" list — both are implemented and wired end-to-end (`ts_control::dns`
  longest-suffix `routes` + `fallback_resolvers`/`resolvers` recursive forwarding, decided in
  `ts_runtime::magic_dns`). The stale entry claimed "non-tailnet queries are not forwarded ...
  fail-closed by design", directly contradicting the "Implemented" MagicDNS entry, which correctly
  states that configuring `fallback_resolvers` opts in to forwarding. Added an explicit Split-DNS
  bullet to the "Implemented" list (longest-suffix route match; empty route list = negative route =
  NXDOMAIN; recursive forwarding applies only when no route matches). Fail-closed remains the
  default (NXDOMAIN, never forwarded) when no route and no resolver is configured.

## [0.5.5](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.5) - 2026-06-04

Review-driven test hardening of the v0.5.4 STUN cleanup (no behavior change; tests and one
signature/doc tidy).

- Tests: close the two coverage gaps a review found in the active-STUN receive path. A
  matched-transaction-id Binding Success whose body is hostile — wrong message type, wrong magic
  cookie, or a lying XOR-MAPPED-ADDRESS attribute length — is now asserted to be consumed (we did
  send that txid) yet learn no reflexive address, pinning that a matched-but-malformed frame can
  never inject a forged endpoint. A second test pins the v0.5.4 contract that the 96-bit
  transaction id is the *sole* anti-spoof match: a valid Binding Success for an in-flight txid is
  accepted even when its UDP source differs from the probed server (legitimate under NAT/hairpin),
  proving the server address is deliberately neither stored nor matched.
- Cleanup: `probe_stun_servers_once` now takes `&MagicSock` instead of `&Arc<MagicSock>` (the Arc
  was never cloned), and a redundant opening clause in the `tcp_buffer_size` memory-at-scale doc
  was tightened.

## [0.5.4](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.4) - 2026-06-04

Review-driven hardening of the v0.5.3 active-STUN + `tcp_buffer_size` work (no behavior change to
the shipped feature; tests, docs, and an internal cleanup).

- Cleanup: the STUN in-flight map (`MagicSock`) no longer stores the per-request server address —
  it was never read for response matching, and storing it falsely implied source-address pinning.
  The 96-bit transaction id is and remains the sole anti-spoof match (a STUN reply may legitimately
  arrive from a different source under NAT/hairpin); the map is now keyed `txid → sent-Instant` for
  TTL pruning only, and the field/TTL docs are corrected to say so.
- Tests: added coverage for the previously-untested seams — the `stun_servers_v4` anti-DNS-leak
  filter (FixedAddr-v4-with-port kept; `UseDns`/`Disable`/no-`stun_port` skipped), the per-tick STUN
  prober fan-out (emits a well-formed 20-byte Binding Request to a v4 server; empty server list is a
  no-op falling back to pong-harvest), and the `tcp_buffer_size` runtime seam (`None` ⇒ netstack
  default, `Some(n)` ⇒ override reaching both netstacks). Consolidated the duplicate STUN wire-format
  test encoders into one canonical `crate::stun::test_support` helper.
- Docs: documented the `tcp_buffer_size` memory cost at scale — buffers are allocated eagerly per
  socket (~512 KiB/socket at the 256 KiB default), so ~1,000 concurrent forwarded flows pin ~512 MB,
  a real fraction of a 4 GB exit node. Operators forwarding many concurrent flows on small boxes
  should lower the knob (see the new exit-node section of `AGENTS.md` and the
  `ts_netstack_smoltcp_core` config doc). The `stun_servers_from_regions` helper carries a loud
  "do not loosen to `UseDns`" anti-leak note.

## [0.5.3](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.3) - 2026-06-04

Direct-path NAT-traversal completion plus a netstack throughput knob (`docs/PARITY_ROADMAP.md`).

- Added: **leak-safe active STUN** for reflexive-endpoint discovery. A periodic prober sends
  RFC 5389 Binding Requests over the *single existing bound IPv4 MagicSock socket* (no second
  socket, no IPv6, no DNS egress) and harvests the reflexive (public) endpoint from the response,
  feeding the same `note_reflexive` chokepoint as the disco pong-harvest path. The STUN codec is
  hand-rolled with zero new dependencies, fully bounds-checked, and fail-closed: only `FixedAddr`
  IPv4 STUN servers from the derp map are probed (`UseDns` servers are skipped to avoid a DNS-leak
  path), the 96-bit transaction id is the authoritative anti-spoof match, the in-flight set is
  bounded (16 entries, 5 s TTL), and an unknown/stale/malformed response learns nothing. This
  completes the direct-path orchestration so a node can discover its public endpoint without
  relying solely on DERP pong-harvest.
- Added: `Config::tcp_buffer_size`, a per-deployment knob for the userspace netstack's per-socket
  TCP send/receive window, threaded `tailscale::Config` → `ts_control::Config` (transport-only) →
  the runtime's netstack configuration (applies to both the application and forwarder netstacks).
  The default per-direction buffer is raised from 16 KiB to **256 KiB**: smoltcp has no TCP window
  auto-tuning, so the old 16 KiB window capped a single flow to ~1.6 Mbps at an 80 ms RTT, visibly
  throttling large model-API responses. `None` uses the netstack default; lower it on
  memory-constrained deployments running many concurrent sockets.
- Docs: corrected the README and crate-level docs that claimed all communication relies on DERP
  relays — direct peer-to-peer NAT traversal (STUN-discovered endpoints + disco, with `CallMeMaybe`
  hole-punching over DERP) is implemented, with DERP as the fallback when no direct path exists.
  Also clarified that MagicDNS only fails closed (NXDOMAIN, never forwarded upstream) *by default*;
  configuring `fallback_resolvers` opts in to forwarding non-tailnet names upstream.

## [0.5.2](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.2) - 2026-06-04

Tier 2 of the tsnet full-parity roadmap (`docs/PARITY_ROADMAP.md`).

- Added: control `MapRequest` now carries requested tags (`HostInfo.RequestTags`), wired from
  `Config::tags` through the map-request builder on both initial connect and reconnect, so a
  tag-keyed control ACL (e.g. a a self-hosted control plane route auto-approver) can match this node.
- Added: ephemeral registration is now config-driven (`Config::ephemeral`, default `true`)
  instead of hardcoded. A persistent exit node or subnet router can set it to `false` so
  control will not GC it out of the tailnet during a brief disconnect.
- Added: netmap stream resumption on reconnect. The client now tracks the control-issued map
  session handle and per-response sequence number, and offers the last `(handle, seq)` on
  reconnect so control can resume the netmap stream after a drop instead of always restarting
  a full netmap (both resume and full-restart paths are handled safely).
- Added (product capability, beyond strict tsnet parity): upstream **proxy egress** for exit
  nodes. `ProxyExitDialer` (a `RealDialer`) egresses exit-node flows via a SOCKS5
  (RFC 1928/1929) or HTTP `CONNECT` upstream — hand-rolled with zero new dependencies — so a
  cloud exit node can route the traffic it egresses through a residential proxy
  and never expose its own origin IP. It is now fully wired
  through the config chain: `Config::exit_proxy` (`ExitProxyConfig` / `ExitProxyScheme`) →
  `ts_control::Config` (transport-only) → `ForwarderConfig` → the forwarder's dialer selection.
  Strictly opt-in and **fail-closed**: only consulted when `forward_exit_egress` is set, and any
  proxy connect/handshake failure drops the flow rather than dialing direct (UDP fails closed
  with `ProxyUdpUnsupported`, handshake failures with `ProxyHandshake`), so the real origin IP
  never leaks. Without an `exit_proxy`, exit egress uses `HostExitDialer`; with neither, the
  default `DirectDialer` structurally refuses exit egress. See the proxy-egress section of
  `AGENTS.md`.
- Fixed: `HostInfo.App` / `HostInfo.IPNVersion` (the client build string the tailnet admin sees)
  were silently dropped on connect because the map-request builder rebuilt the request without
  them; they are now threaded through via a `client_info` builder setter.
- Hardened: the resumed map-session handle is bounded (≤256 bytes) and sanitized
  (ASCII-graphic) before being stored or logged, and `seq` resets to `0` on a handle change —
  closing a log-injection / unbounded-memory vector on a hostile control response.
- Security: the proxy dialer rejects forbidden exit destinations (loopback / link-local /
  unspecified) via an SSRF guard, and `ProxyConfig`'s `Debug` redacts proxy credentials.

## [0.5.1](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.1) - 2026-06-04

Hardening pass over the Tier 1 direct-path code (review-driven fixes).

- Security: `CallMeMaybe` over DERP is now gated on a netmap-membership check before its
  endpoints are learned; relayed Ping fails closed instead of being honored. The
  `BindingVerifier` signature is now `Fn(&DiscoPublicKey, Option<&NodePublicKey>) -> bool`:
  `Some(claimed)` demands an exact node-key match (Ping), `None` is membership-only
  (CallMeMaybe). An absent verifier fails closed (frame dropped), and the absence is warned
  once.
- Security: disco `Pong` is now rejected when its UDP source address differs from the address
  that was pinged, closing a path-confirmation spoofing vector; the learned reflexive-address
  set is capped (`MAX_REFLEXIVE_ADDRS`).
- Reliability: shared `RwLock`s recover from poisoning instead of cascading a single task
  panic into every other flow (kameo actors still isolate per-flow panics); periodic disco
  intervals use `MissedTickBehavior::Delay`.
- Tests: added coverage for fail-closed Ping with no verifier, membership-gated CallMeMaybe,
  relayed-Ping drop, source-address Pong rejection, and forbidden-endpoint filtering.

## [0.5.0](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.5.0) - 2026-06-04

Tier 1 of the tsnet full-parity roadmap (`docs/PARITY_ROADMAP.md`).

- Security: enforce the disco↔node-key binding in the netmap-owning layer. Inbound disco
  pings now cross-check `claimed_node_key` against the control netmap and fail closed on
  mismatch or unknown disco key (no pong, no learned path). Resolves the `TODO(parity)`.
- Added: inbound disco-over-DERP demux. DERP-relayed `CallMeMaybe` frames are now decoded
  and their endpoints learned (through the existing `is_pingable_candidate` sanitizer);
  relayed Ping/Pong are dropped and non-disco frames still reach the dataplane.
- Added (CI/build): static musl build lanes (`aarch64`/`x86_64-unknown-linux-musl`) with the
  `ssh`/`aws-lc-rs` feature off, keeping the ring-only egress path musl-clean; a guard fails
  the build if `aws-lc-rs` enters the graph.

## [0.4.0](https://github.com/GeiserX/tailscale-rs/releases/tag/v0.4.0) - 2026-06-03

Initial tailscale-rs parity release (fork of tailscale/tailscale-rs).

- Added (Rust API): Experimental support for user-defined tailnet SSH servers using
  [`russh`](https://docs.rs/russh/latest/russh/) and (optionally)
  [`ratatui`](https://docs.rs/ratatui/latest/ratatui/).
  [#178](https://github.com/tailscale/tailscale-rs/pull/178).
- Hardened the tsnet-parity dataplane (anti-leak, bounds, panic-safety).

## [0.3.3](https://github.com/tailscale/tailscale-rs/releases/tag/v0.3.3) - 2026-05-20

- Fixed: don't generate `tailscale.h` on publish.
  [#196](https://github.com/tailscale/tailscale-rs/pull/196).
- Fixed: Elixir CI/CD publishing infrastructure.
  [#197](https://github.com/tailscale/tailscale-rs/pull/197).

## [0.3.2](https://github.com/tailscale/tailscale-rs/releases/tag/v0.3.2) - 2026-05-20

Partial release; this version is tagged and published to PyPI, but was not published to crates.io or hex.pm.

- Fixed: removed `std` dependency from `ts_netstack_smoltcp_core`.
  [#194](https://github.com/tailscale/tailscale-rs/pull/194).

## [0.3.1](https://github.com/tailscale/tailscale-rs/releases/tag/v0.3.1) - 2026-05-20

Partial release; this version is tagged and published to PyPI, but was not published to crates.io or hex.pm.

- Fixed: Python CI/CD publishing infrastructure.
  [#191](https://github.com/tailscale/tailscale-rs/pull/191).
- Fixed: Rust CI/CD publishing infrastructure.
  [#193](https://github.com/tailscale/tailscale-rs/pull/193).

## [0.3.0](https://github.com/tailscale/tailscale-rs/releases/tag/v0.3.0) - 2026-05-19

Internal release; this version is tagged, but was not published to any package repositories.

- **Breaking** (Rust API): exports `config`, `netstack`, and `keys` modules and moves some functionality
  from the crate root to these modules. Replaces `load_key_file` with `Config::default_with_key_file`.
  Exports a few more types so fewer users will have to depend on internal crates.
  [#105](https://github.com/tailscale/tailscale-rs/pull/105).
- **Breaking** (Rust API, ts_netstack_smoltcp, ts_control): errors have been refactored, some minor
  changes to APIs around errors.
  [#154](https://github.com/tailscale/tailscale-rs/pull/154).
- Added (Rust API): load configuration options from environment variables. Adds `config::auth_key_from_env`
  and `config::Config::default_from_env`.
  [#97](https://github.com/tailscale/tailscale-rs/pull/97).
- Added (Rust API, Python, Elixir): `Device::self_node`.
  [#147](https://github.com/tailscale/tailscale-rs/pull/147).
- Added (Python and Elixir bindings): optional configuration parameters.
  [#140](https://github.com/tailscale/tailscale-rs/pull/140) and [#148](https://github.com/tailscale/tailscale-rs/pull/148).
- Fixed (ts_netstack_smoltcp): big improvement to TCP accept performance.
  [#141](https://github.com/tailscale/tailscale-rs/pull/141).
- Updated MSRV to 1.94.1.
  [#181](https://github.com/tailscale/tailscale-rs/pull/181).

## [0.2.0](https://github.com/tailscale/tailscale-rs/releases/tag/v0.2.0) - 2026-04-15

Initial public release.

## 0.1.0

Hello, world!
