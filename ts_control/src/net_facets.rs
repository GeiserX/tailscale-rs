//! Transport-neutral NetInfo facts the runtime hands to control alongside its endpoints.
//!
//! Control never sees how they were learned: [`StunFacts`] come from the magicsock's reflexive
//! (STUN) set, [`PortMapFacets`] from the port mapper. Both are defined here so `ts_control` needs
//! no dependency on either crate.

use alloc::{collections::BTreeSet, string::String};
use core::net::SocketAddr;

/// What the reflexive (STUN) addresses say about UDP, computed from the reflexive set **before**
/// endpoint de-duplication, so a reflexive address that equals the port-mapped one still counts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StunFacts {
    /// Go `NetInfo.WorkingUDP`: a reflexive address was learned, so UDP reaches the internet.
    pub working_udp: bool,
    /// Go `NetInfo.MappingVariesByDestIP`: at least two distinct IPv4 reflexive addresses (a
    /// symmetric NAT). IPv4-only, matching magicsock's `is_symmetric_nat`.
    pub mapping_varies: bool,
}

impl StunFacts {
    /// The facts for this reflexive set.
    pub fn from_reflexive(reflexive: &[SocketAddr]) -> Self {
        let distinct_v4: BTreeSet<&SocketAddr> = reflexive.iter().filter(|a| a.is_ipv4()).collect();
        Self {
            working_udp: !reflexive.is_empty(),
            mapping_varies: distinct_v4.len() >= 2,
        }
    }
}

/// Port-mapping facets for NetInfo. `None` means "not checked" and is never sent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PortMapFacets {
    /// Go `NetInfo.UPnP` (never probed yet, so `None`).
    pub upnp: Option<bool>,
    /// Go `NetInfo.PMP`.
    pub pmp: Option<bool>,
    /// Go `NetInfo.PCP`.
    pub pcp: Option<bool>,
    /// Go `NetInfo.HavePortMap`. Here it means an **advertised** mapping, so control never sees
    /// `HavePortMap` without a port-mapped endpoint.
    pub have_port_map: bool,
}

impl PortMapFacets {
    /// Go's NetInfo `portmap=` summary (`tailcfg.NetInfo.portMapSummary`): `?` when there is no
    /// mapping and nothing was checked, otherwise one letter per protocol (`U`, `M`, `C`) that is
    /// present, nothing for one that is absent, and `_` for one not checked (`conciseOptBool`). A
    /// mapping prefixes `active-`; here that means an advertised mapping, where Go's means any
    /// held mapping.
    pub fn summary(&self) -> String {
        if !self.have_port_map && self.upnp.is_none() && self.pmp.is_none() && self.pcp.is_none() {
            return "?".into();
        }
        let mut s = String::new();
        if self.have_port_map {
            s.push_str("active-");
        }
        for (v, c) in [(self.upnp, 'U'), (self.pmp, 'M'), (self.pcp, 'C')] {
            match v {
                None => s.push('_'),
                Some(true) => s.push(c),
                Some(false) => {}
            }
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    fn addrs(list: &[&str]) -> Vec<SocketAddr> {
        list.iter().map(|a| a.parse().unwrap()).collect()
    }

    #[test]
    fn stun_facts() {
        assert_eq!(StunFacts::from_reflexive(&[]), StunFacts::default());
        let one = StunFacts::from_reflexive(&addrs(&["203.0.113.7:41641"]));
        assert!(one.working_udp && !one.mapping_varies);
        let two = StunFacts::from_reflexive(&addrs(&["203.0.113.7:41641", "198.51.100.9:51000"]));
        assert!(two.working_udp && two.mapping_varies);
        let dup = StunFacts::from_reflexive(&addrs(&["203.0.113.7:41641", "203.0.113.7:41641"]));
        assert!(!dup.mapping_varies);
        let v6 = StunFacts::from_reflexive(&addrs(&["[2001:db8::1]:1", "[2001:db8::2]:1"]));
        assert!(v6.working_udp && !v6.mapping_varies);
    }

    /// Port of netcheck `TestReportString`'s portmap cases, plus the `active-` prefix of Go's
    /// `NetInfo.portMapSummary`.
    #[test]
    fn summary_matches_go() {
        let f = |upnp, pmp, pcp, have| PortMapFacets {
            upnp,
            pmp,
            pcp,
            have_port_map: have,
        };
        assert_eq!(f(None, None, None, false).summary(), "?");
        assert_eq!(
            f(Some(true), Some(true), Some(true), false).summary(),
            "UMC"
        );
        assert_eq!(
            f(Some(true), Some(false), Some(true), false).summary(),
            "UC"
        );
        assert_eq!(
            f(None, Some(true), Some(true), true).summary(),
            "active-_MC"
        );
        assert_eq!(f(None, Some(false), Some(false), false).summary(), "_");
        // A mapping with nothing checked: Go prints `active-___`, not `active-?`.
        assert_eq!(f(None, None, None, true).summary(), "active-___");
    }
}
