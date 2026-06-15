#![doc = include_str!("../README.md")]

mod derp_latency;
pub mod https;
// NOTE: there is deliberately no `stun` module here. An earlier `StunProber` bound its own
// `0.0.0.0:0` AND `[::]:0` sockets (a second egress + an IPv6 bind), which violates this fork's
// IPv4-only / single-bound-socket anti-leak invariant. It was never constructed on any live path and
// was removed entirely (recoverable from git history) rather than left as dormant, leak-prone code a
// future caller could wire into the datapath. Production reflexive discovery is the disco
// pong-harvest on magicsock's one bound socket (`ts_runtime::direct::run_advertiser`) plus the
// hand-rolled single-socket STUN codec in `ts_magicsock`; DERP latency uses HTTPS (`measure_derp_map`).

pub use derp_latency::{Config, RegionResult, measure_derp_map};
#[doc(inline)]
pub use https::measure_https_latency;
