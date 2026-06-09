#![doc = include_str!("../README.md")]
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(test)]
extern crate std;

mod cap_grant;
mod dst_port;
mod filter_rule;
mod ip_proto;
mod ip_range;
mod srcip;

pub use cap_grant::CapGrant;
pub use dst_port::DstPort;
pub use filter_rule::{AppRule, FilterRule, NetworkRule};
pub use ip_proto::IpProto;
pub use ip_range::IpRange;
pub use srcip::SrcIp;

/// A set of packet filtering rules that is named by a specific key.
pub type Ruleset<'a> = alloc::vec::Vec<FilterRule<'a>>;

/// A map of named rulesets, typically transmitted in a `MapResponse`.
pub type Map<'a> = alloc::collections::BTreeMap<&'a str, Option<Ruleset<'a>>>;

/// Deserialize a field as `T`, treating a wire `null` as `T::default()`.
///
/// Go marshals empty slices/maps as JSON `null` (not `[]`/`{}`) for `omitempty`-tagged fields, so a
/// control plane (notably an IPv6-off Headscale) sends `null` for `SrcIPs`/`Dsts` — fields modeled
/// here as required sequences. A plain `#[serde(default)]` covers an *omitted* field but NOT an
/// explicit `null`. This mirrors `ts_control_serde::util::null_to_default`, duplicated locally so
/// this crate keeps its minimal dependency set (no `ts_control_serde` / `serde_with`).
pub(crate) fn null_to_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de> + Default,
{
    use serde::Deserialize as _;
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}
