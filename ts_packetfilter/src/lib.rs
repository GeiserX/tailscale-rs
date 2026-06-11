#![doc = include_str!("../README.md")]
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(any(feature = "std", test))]
extern crate std;

use alloc::{collections::BTreeMap, string::String};
use core::net::IpAddr;

#[cfg(feature = "checking-filter")]
mod checking_filter;
pub mod filter;
mod ip_proto;
mod rule;
mod state;

#[cfg(feature = "checking-filter")]
pub use checking_filter::CheckingFilter;
#[doc(inline)]
pub use filter::{Filter, FilterAndStorage, FilterExt, FilterStorage, FilterStorageExt};
#[doc(inline)]
pub use ip_proto::IpProto;
#[doc(inline)]
pub use rule::{DstMatch, Rule, Ruleset, SrcMatch};
#[doc(inline)]
pub use state::apply_update;

use crate::filter::CapIter;

/// The name of the default ruleset, i.e. the key the filter in
/// `MapResponse::packet_filter` should use.
pub const DEFAULT_RULESET_NAME: &str = "base";

/// The special ruleset name that clears the packet filter state if it's present
/// with a `null` value.
pub const CLEAR_MAP_KEY: &str = "*";

/// Metadata about an IP packet.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct PacketInfo {
    /// The address of the sender of the packet.
    pub src: IpAddr,
    /// The address of the receiver of the packet.
    pub dst: IpAddr,
    /// The IP protocol number.
    pub ip_proto: IpProto,
    /// The port number.
    pub port: u16,
}

/// Trivial filter that drops all traffic.
///
/// Can be used as an initial filter before the actual filter has been downloaded from
/// control.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct DropAllFilter;

impl Filter for DropAllFilter {
    fn match_for(&self, info: &PacketInfo, caps: CapIter) -> Option<&str> {
        tracing::trace!(?info, caps = ?caps.into_iter().collect::<alloc::vec::Vec<_>>(), "drop all: drop!");

        None
    }
}

/// A [`Filter`] wrapper that enforces **shields-up** (Go `ipn` `ShieldsUp` / `block_incoming`): drop
/// every inbound packet destined to **one of this node's own addresses**, while delegating all other
/// packets to the wrapped `inner` filter.
///
/// Scoping the deny to `self_addrs` (rather than dropping everything) is deliberate, because this
/// fork's filter is **stateless** — it has no TCP-flow tracking, so it cannot tell a new inbound
/// connection from a reply to one we initiated. Dropping only packets aimed at our own host
/// addresses means:
/// - new inbound connections *terminating on this node* are refused (the shields-up intent), but
/// - **forwarded transit** (subnet-route / exit-node traffic, whose `dst` is some other route, never
///   a self address) is unaffected, and
/// - reply admission for our own outbound flows continues to be governed by the wrapped ACL filter
///   exactly as before (we don't blanket-drop it here).
///
/// This is the honest stateless-filter approximation of Go's stateful ShieldsUp: it blocks inbound
/// *to self* and leaves everything else to the real filter. Mirrors `DropAllFilter`'s "deny by
/// returning `None`" pattern, scoped by destination.
#[derive(Debug, Clone)]
pub struct ShieldsUpFilter<F> {
    /// The underlying (control-derived) filter consulted for any packet not denied by shields-up.
    pub inner: F,
    /// This node's own addresses; an inbound packet whose `dst` is in this set is dropped.
    pub self_addrs: alloc::vec::Vec<IpAddr>,
}

impl<F: Filter> Filter for ShieldsUpFilter<F> {
    fn match_for(&self, info: &PacketInfo, caps: CapIter) -> Option<&str> {
        if self.self_addrs.contains(&info.dst) {
            tracing::trace!(
                ?info,
                "shields-up: dropping inbound packet to a self address"
            );
            return None;
        }
        self.inner.match_for(info, caps)
    }
}

/// Alias representing a BTreeMap-based filter.
pub type BTreeFilter = BTreeMap<String, Ruleset>;

/// Alias representing a [`hashbrown::HashMap`]-based filter.
pub type HashbrownFilter = hashbrown::HashMap<String, Ruleset>;

/// Alias representing a [`HashMap`][std::collections::HashMap]-based filter.
#[cfg(feature = "std")]
pub type HashMapFilter = std::collections::HashMap<String, Ruleset>;

static_assertions::assert_impl_all!(BTreeFilter: Filter, FilterStorage);
static_assertions::assert_impl_all!(HashbrownFilter: Filter, FilterStorage);
#[cfg(feature = "std")]
static_assertions::assert_impl_all!(HashMapFilter: Filter, FilterStorage);

#[cfg(test)]
mod shields_tests {
    use super::*;

    /// A trivial inner filter that accepts everything — so the wrapper's deny is the only thing that
    /// can drop a packet (isolates `ShieldsUpFilter`'s behavior from any ruleset).
    struct AllowAll;
    impl Filter for AllowAll {
        fn match_for(&self, _info: &PacketInfo, _caps: CapIter) -> Option<&str> {
            Some("allow-all")
        }
    }

    fn pkt(dst: &str) -> PacketInfo {
        PacketInfo {
            src: "100.64.0.9".parse().unwrap(),
            dst: dst.parse().unwrap(),
            ip_proto: IpProto::TCP,
            port: 22,
        }
    }

    #[test]
    fn shields_up_drops_inbound_to_self_address() {
        let f = ShieldsUpFilter {
            inner: AllowAll,
            self_addrs: alloc::vec!["100.64.0.1".parse().unwrap()],
        };
        // Destined to our own address → dropped, even though the inner filter would allow it.
        assert!(
            f.match_for(&pkt("100.64.0.1"), &mut core::iter::empty())
                .is_none()
        );
    }

    #[test]
    fn shields_up_passes_non_self_dst_to_inner() {
        let f = ShieldsUpFilter {
            inner: AllowAll,
            self_addrs: alloc::vec!["100.64.0.1".parse().unwrap()],
        };
        // A forwarded/subnet dst (not one of our addresses) → delegated to the inner filter, which
        // accepts. This is why shields-up doesn't break subnet/exit transit.
        assert_eq!(
            f.match_for(&pkt("10.0.0.5"), &mut core::iter::empty()),
            Some("allow-all")
        );
    }

    #[test]
    fn shields_up_empty_self_addrs_is_transparent() {
        // Before the first netmap (no self addresses known yet), the wrapper denies nothing — it is
        // a pass-through to the inner filter, never a blanket drop.
        let f = ShieldsUpFilter {
            inner: AllowAll,
            self_addrs: alloc::vec![],
        };
        assert_eq!(
            f.match_for(&pkt("100.64.0.1"), &mut core::iter::empty()),
            Some("allow-all")
        );
    }
}
