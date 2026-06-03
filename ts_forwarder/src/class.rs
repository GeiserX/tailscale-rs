//! Flow classification against the set of advertised routes.

use std::net::IpAddr;

use ipnet::IpNet;

/// How an inbound overlay flow's destination relates to our advertised routes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowClass {
    /// The destination is covered by a narrower advertised prefix (a real subnet route).
    Subnet,
    /// The destination matched only a default route (`0.0.0.0/0`): exit-node egress.
    ExitNode,
}

/// The set of prefixes this node forwards inbound traffic for.
///
/// Owned by the forwarder. A `0.0.0.0/0` entry means this node advertises itself as an exit
/// node; any narrower prefix is a subnet route. Destinations matching no prefix are not
/// forwarded (fail-closed).
#[derive(Clone, Default, Debug)]
pub struct RouteTable {
    /// Advertised prefixes, sorted longest-prefix-first so [`classify`](Self::classify) can
    /// return the most specific match.
    prefixes: Vec<IpNet>,
}

impl RouteTable {
    /// Build a route table from a set of advertised prefixes.
    pub fn new(prefixes: impl IntoIterator<Item = IpNet>) -> Self {
        let mut prefixes: Vec<IpNet> = prefixes.into_iter().collect();
        // Longest-prefix-first: a narrower subnet route wins over a 0.0.0.0/0 exit route.
        prefixes.sort_by_key(|net| core::cmp::Reverse(net.prefix_len()));
        Self { prefixes }
    }

    /// Classify a destination IP.
    ///
    /// Returns `None` when the destination matches no advertised prefix; such flows MUST NOT
    /// be forwarded.
    pub fn classify(&self, dst: IpAddr) -> Option<FlowClass> {
        for net in &self.prefixes {
            if net.contains(&dst) {
                return Some(if net.prefix_len() == 0 {
                    FlowClass::ExitNode
                } else {
                    FlowClass::Subnet
                });
            }
        }
        None
    }

    /// Whether any routes are advertised at all.
    pub fn is_empty(&self) -> bool {
        self.prefixes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn empty_table_classifies_nothing() {
        let t = RouteTable::default();
        assert!(t.is_empty());
        assert_eq!(t.classify(ip("10.0.0.1")), None);
    }

    #[test]
    fn subnet_prefix_classifies_as_subnet() {
        let t = RouteTable::new([net("10.0.0.0/8")]);
        assert_eq!(t.classify(ip("10.1.2.3")), Some(FlowClass::Subnet));
        assert_eq!(t.classify(ip("11.0.0.1")), None);
    }

    #[test]
    fn default_route_classifies_as_exit_node() {
        let t = RouteTable::new([net("0.0.0.0/0")]);
        assert_eq!(t.classify(ip("1.2.3.4")), Some(FlowClass::ExitNode));
    }

    #[test]
    fn narrower_subnet_wins_over_default_route() {
        // Both an exit route and a subnet route are advertised; a dst inside the subnet must
        // classify as Subnet (the more specific, dialable-without-leak class), not ExitNode.
        let t = RouteTable::new([net("0.0.0.0/0"), net("192.168.0.0/16")]);
        assert_eq!(t.classify(ip("192.168.1.1")), Some(FlowClass::Subnet));
        assert_eq!(t.classify(ip("8.8.8.8")), Some(FlowClass::ExitNode));
    }
}
