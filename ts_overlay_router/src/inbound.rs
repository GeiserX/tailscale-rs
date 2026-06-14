//! Inbound overlay routing, for packets originating from remote peers.

use std::collections::HashMap;

use itertools::Itertools;
use ts_bart::{RoutingTable, Table};
use ts_packet::PacketMut;
use ts_transport::OverlayTransportId;

/// An inbound routing action.
#[derive(Debug, Clone)]
pub enum RouteAction {
    /// Drop the packet. This is semantically equivalent to having no route, and can be used
    /// to notch out a set of addresses from a larger route.
    Drop,
    /// Deliver the packet to the given overlay transport.
    ToOverlay(OverlayTransportId),
}

/// Routes packets that originate from remote peers.
#[derive(Default)]
pub struct Router {
    table: Table<RouteAction>,
}

/// The result of routing a batch of packets.
pub type Result = HashMap<OverlayTransportId, Vec<PacketMut>>;

impl Router {
    /// Assigns a batch of packets to their next hop.
    ///
    /// Packets that don't match any routes are dropped.
    pub fn route(&self, packets: impl IntoIterator<Item = PacketMut>) -> Result {
        packets
            .into_iter()
            .filter_map(|packet| {
                let addr = packet.get_dst_addr()?;
                let _span =
                    tracing::trace_span!("route_inbound", len = packet.len(), %addr).entered();

                match self.table.lookup(addr) {
                    Some(&RouteAction::ToOverlay(key)) => Some((key, packet)),
                    Some(RouteAction::Drop) => {
                        tracing::trace!("explicit drop");
                        None
                    }
                    None => {
                        tracing::trace!("no route");

                        None
                    }
                }
            })
            .into_group_map()
    }

    /// Replaces the router's current routes with the provided ones.
    ///
    /// Returns the previous set of routes.
    pub fn swap(&mut self, routes: Table<RouteAction>) -> Table<RouteAction> {
        std::mem::replace(&mut self.table, routes)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    /// Build a minimal IPv4 packet with the given destination.
    fn v4_packet(dst: Ipv4Addr, payload: &[u8]) -> PacketMut {
        let mut packet = PacketMut::new(20);
        packet[0] = 0x45;
        packet[16..20].copy_from_slice(dst.octets().as_ref());
        packet.extend_from_slice(payload);
        packet
    }

    #[test]
    fn test_inbound_overlay() {
        let mut routes = Table::default();
        routes.insert(
            "1.2.3.4/32".parse().unwrap(),
            RouteAction::ToOverlay(1.into()),
        );
        routes.insert(
            "2.3.4.0/24".parse().unwrap(),
            RouteAction::ToOverlay(2.into()),
        );
        routes.insert("2.3.4.5/32".parse().unwrap(), RouteAction::Drop);

        let mut router = Router::default();
        let prev = router.swap(routes);
        assert_eq!(prev.size4(), 0);
        assert_eq!(prev.size6(), 0);

        let pkts = vec![
            v4_packet("1.2.3.4".parse().unwrap(), b"for transport 1"),
            v4_packet("2.3.4.1".parse().unwrap(), b"for transport 2"),
            v4_packet("2.3.4.5".parse().unwrap(), b"drop"),
            v4_packet("2.3.4.10".parse().unwrap(), b"for transport 2"),
        ];
        let mut got = router.route(pkts.clone());
        let mut want = HashMap::from([
            (1.into(), vec![pkts[0].clone()]),
            (2.into(), vec![pkts[1].clone(), pkts[3].clone()]),
        ]);

        // Hashmap traversal is non-deterministic, so packets from different peers may be reordered.
        // For the test, sort everything.
        for pkts in got.values_mut() {
            pkts.sort();
        }
        for pkts in want.values_mut() {
            pkts.sort();
        }

        assert_eq!(got, want);
    }

    /// A packet whose destination matches NO route is dropped (the `None => None` arm). This is the
    /// structural analogue of Go filter's `local4`/`local6` destination-local precondition: only a
    /// packet whose dst has a local overlay route is delivered. It is what bounds the dataplane's
    /// unconditional inbound TSMP accept to local destinations — a TSMP packet to an unrouted dst
    /// still gets dropped here, after the filter admitted it, exactly as Go's `local4` gate runs
    /// before the `case TSMP: Accept`. (AND is order-independent, so accept-then-route-drop matches
    /// Go's gate-then-accept.)
    #[test]
    fn unrouted_dst_is_dropped() {
        let mut routes = Table::default();
        routes.insert(
            "100.64.0.1/32".parse().unwrap(),
            RouteAction::ToOverlay(1.into()),
        );
        let mut router = Router::default();
        router.swap(routes);

        // A local dst (has a route) is delivered; an unrouted dst (no route at all) is dropped.
        let local = v4_packet("100.64.0.1".parse().unwrap(), b"local");
        let unrouted = v4_packet("8.8.8.8".parse().unwrap(), b"no route");
        let got = router.route(vec![local.clone(), unrouted]);

        assert_eq!(
            got,
            HashMap::from([(1.into(), vec![local])]),
            "only the routed-local dst is delivered; the unrouted dst is dropped"
        );
    }
}
