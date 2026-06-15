#![doc = include_str!("../README.md")]

mod derp_latency;
pub mod https;
// `stun` is test-only: `StunProber` binds its own `0.0.0.0:0` AND `[::]:0` sockets (a second egress
// and an IPv6 bind), which violates this fork's IPv4-only / single-bound-socket anti-leak invariant.
// It is never constructed on any live path — production STUN/reflexive discovery is the disco
// pong-harvest on magicsock's one bound socket (see `ts_runtime::direct::run_advertiser`), and DERP
// latency uses HTTPS (`measure_derp_map`), not STUN. Gating the whole module behind `cfg(test)` keeps
// it (and its `[::]:0` bind, and the `stun_rs` dependency it pulls) out of the production binary, so a
// future caller can't accidentally wire a second-egress/IPv6-leaking prober into the datapath.
#[cfg(test)]
mod stun;

pub use derp_latency::{Config, RegionResult, measure_derp_map};
#[doc(inline)]
pub use https::measure_https_latency;
