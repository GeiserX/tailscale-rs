//! Connection tracking for outbound UDP and SCTP flows, so their replies are admitted without an
//! explicit ACL rule.
//!
//! This is the port of the state Go's packet filter carries in `Filter.state`
//! (`wgengine/filter/filter.go`): a bounded LRU of [`Tuple`]s, keyed the way Go's
//! `net/flowtrack.Tuple` is keyed — protocol plus a full source and destination `ip:port` on each
//! side. Go fills it in `Filter.UpdateOutboundFlowState`, which inserts the **reversed** tuple of
//! every outbound UDP/SCTP packet, and reads it at the top of `runIn4`/`runIn6`'s UDP/SCTP arm,
//! returning `Accept, "cached"` on a hit *before* any rule is matched.
//!
//! Why this fork needs it at all — and needs it more than upstream does. Go's `RunOut` sits on the
//! TUN read path, and upstream `e0677ccc7` had to add a second call site because packets produced
//! by **netstack** ("used by tailscaled with `--tun userspace-networking`, by tsnet, and by the
//! SOCKS5/HTTP proxies") reach the wrapper through `InjectOutbound` and never pass `RunOut`, so
//! "a netstack-side dial of UDP would send fine but the reply would be dropped as `no matching
//! rule`". In this engine that injected path is not a special case, it is the only path there is:
//! every outbound packet comes from the netstack through [`crate::DataPlane::process_outbound`].
//! Without this cache an embedder that sends a UDP datagram to a peer gets the reply dropped
//! unless control's ACL happens to name the ephemeral source port back — which it cannot.
//!
//! Only UDP and SCTP are tracked, exactly as Go's switch is. TCP needs no state (Go admits any
//! non-SYN segment) and ICMP needs none either (Go admits responses and errors outright).

use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
};

use ts_packetfilter::IpProto;

/// The maximum number of tracked flows — Go `wgengine/filter.lruMax`, the `MaxEntries` of the
/// `lru.Cache` in `Filter.state`. Taken from upstream rather than invented: it is what bounds the
/// memory a stream of outbound datagrams to distinct destinations can pin, and it is the reason a
/// peer cannot grow this table without limit.
pub(crate) const LRU_MAX: usize = 512;

/// One tracked flow, the port of Go `net/flowtrack.Tuple`: the protocol and a full `ip:port` on
/// each side. Both ports are part of the key, which is what makes an entry admit the reply to
/// *this* datagram and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Tuple {
    /// Go `Tuple.proto`. Only [`IpProto::UDP`] and [`IpProto::SCTP`] are ever stored.
    pub(crate) proto: IpProto,
    /// Go `Tuple.src`.
    pub(crate) src: SocketAddr,
    /// Go `Tuple.dst`.
    pub(crate) dst: SocketAddr,
}

/// Whether Go's `UpdateOutboundFlowState` / `runIn4` switch tracks this protocol at all: its two
/// arms are `case ipproto.UDP, ipproto.SCTP`. Everything else — TCP, ICMP, TSMP, anything
/// portless — is decided without state.
fn is_tracked(proto: IpProto) -> bool {
    matches!(proto, IpProto::UDP | IpProto::SCTP)
}

/// A bounded, least-recently-used set of [`Tuple`]s — Go's `lru.Cache[flowtrack.Tuple, struct{}]`
/// with `MaxEntries: lruMax`. The values Go stores are empty structs, so this is a set, not a map.
///
/// Recency is tracked with a monotonic stamp per entry and an ordered index over those stamps, so
/// both `add` and a hit are `O(log n)` and eviction always drops the genuinely oldest entry. Go's
/// `lru.Cache` moves an entry to the front on `Get` as well as on `Add`; so does this.
///
/// No lock: Go guards its cache with `filterState.mu` because `RunIn`/`RunOut` are called from many
/// goroutines, while this fork's dataplane step is single-threaded and takes `&mut self`.
#[derive(Debug, Default)]
pub(crate) struct FlowCache {
    /// The tracked flows, each mapped to the recency stamp it currently holds.
    by_tuple: HashMap<Tuple, u64>,
    /// The same flows indexed by that stamp, so the least-recently-used one is the first entry.
    by_recency: BTreeMap<u64, Tuple>,
    /// The next recency stamp to hand out. Monotonic; one increment per insert or hit.
    next_stamp: u64,
}

impl FlowCache {
    /// Record an outbound packet's flow, so the reply to it is admitted — Go
    /// `Filter.UpdateOutboundFlowState`, which `RunOut` calls on every outbound packet and which
    /// upstream `e0677ccc7` exported so `net/tstun`'s injected (netstack) path could call it too.
    ///
    /// `src`/`dst` are the outbound packet's own, and the stored tuple is the **reverse** of them
    /// (Go's `flowtrack.MakeTuple(q.IPProto, q.Dst, q.Src)`, commented "src/dst reversed"): what
    /// is being remembered is the shape the *reply* will have.
    ///
    /// A protocol Go does not track is silently ignored, which is Go's switch falling through.
    pub(crate) fn record_outbound(&mut self, proto: IpProto, src: SocketAddr, dst: SocketAddr) {
        if !is_tracked(proto) {
            return;
        }
        self.add(Tuple {
            proto,
            src: dst,
            dst: src,
        });
    }

    /// Whether an inbound packet is the reply to a flow this node started — Go `runIn4`/`runIn6`:
    ///
    /// ```text
    /// case ipproto.UDP, ipproto.SCTP:
    ///     t := flowtrack.MakeTuple(q.IPProto, q.Src, q.Dst)
    ///     if _, ok := f.state.lru.Get(t); ok {
    ///         return Accept, "cached"
    ///     }
    /// ```
    ///
    /// `false` for every protocol Go does not track and for every tuple that was never recorded,
    /// in which case the caller falls through to the rule match exactly as Go does. A hit refreshes
    /// the entry's recency, mirroring `lru.Cache.Get`.
    pub(crate) fn admits_inbound(
        &mut self,
        proto: IpProto,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> bool {
        if !is_tracked(proto) {
            return false;
        }
        self.get(&Tuple { proto, src, dst })
    }

    /// How many flows are currently tracked. Never exceeds [`LRU_MAX`].
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.by_tuple.len()
    }

    /// The next recency stamp.
    fn bump(&mut self) -> u64 {
        let stamp = self.next_stamp;
        self.next_stamp += 1;
        stamp
    }

    /// Go `lru.Cache.Add`: insert (or refresh) `tuple`, then evict from the back until the cache is
    /// within `MaxEntries`.
    fn add(&mut self, tuple: Tuple) {
        let stamp = self.bump();
        if let Some(previous) = self.by_tuple.insert(tuple, stamp) {
            self.by_recency.remove(&previous);
        }
        self.by_recency.insert(stamp, tuple);

        // The bound is the whole point: a peer that provokes — or an embedder that sends —
        // datagrams to endlessly many distinct destinations must not be able to grow this table.
        while self.by_tuple.len() > LRU_MAX {
            let Some((_, evicted)) = self.by_recency.pop_first() else {
                break;
            };
            self.by_tuple.remove(&evicted);
        }
    }

    /// Go `lru.Cache.Get`: report whether `tuple` is present, moving it to the front if it is.
    fn get(&mut self, tuple: &Tuple) -> bool {
        let Some(&previous) = self.by_tuple.get(tuple) else {
            return false;
        };
        let stamp = self.bump();
        self.by_tuple.insert(*tuple, stamp);
        self.by_recency.remove(&previous);
        self.by_recency.insert(stamp, *tuple);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `a.b.c.d:port`.
    fn sa(s: &str) -> SocketAddr {
        s.parse().expect("socket address")
    }

    /// The core of the port: an outbound datagram records the reverse tuple, so the datagram coming
    /// back the other way is a hit — and nothing else is.
    #[test]
    fn outbound_datagram_admits_only_its_own_reply() {
        let mut flows = FlowCache::default();
        let src = sa("100.64.0.1:41234");
        let dst = sa("192.0.2.7:53");

        flows.record_outbound(IpProto::UDP, src, dst);

        assert!(
            flows.admits_inbound(IpProto::UDP, dst, src),
            "the reply to the recorded flow is admitted (Go's Accept, \"cached\")"
        );

        // The refusals. Each of these is one field of Go's tuple differing, and each must miss.
        assert!(
            !flows.admits_inbound(IpProto::UDP, src, dst),
            "the outbound direction itself is not a recorded reply"
        );
        assert!(
            !flows.admits_inbound(IpProto::UDP, sa("198.51.100.7:53"), src),
            "a different source ADDRESS does not ride the entry"
        );
        assert!(
            !flows.admits_inbound(IpProto::UDP, sa("192.0.2.7:5353"), src),
            "a different source PORT does not ride the entry"
        );
        assert!(
            !flows.admits_inbound(IpProto::UDP, dst, sa("100.64.0.1:41235")),
            "a different destination port does not ride the entry"
        );
        assert!(
            !flows.admits_inbound(IpProto::UDP, dst, sa("100.64.0.2:41234")),
            "a different destination address does not ride the entry"
        );
        assert!(
            !flows.admits_inbound(IpProto::SCTP, dst, src),
            "the protocol is part of Go's tuple: SCTP does not ride a UDP entry"
        );
    }

    /// Go's switch has exactly two arms. A protocol outside them records nothing, so nothing it
    /// could later match exists — TCP and ICMP replies are Go's *stateless* carve-outs, not this
    /// cache's business.
    #[test]
    fn only_udp_and_sctp_are_tracked() {
        let mut flows = FlowCache::default();
        let src = sa("100.64.0.1:41234");
        let dst = sa("192.0.2.7:443");

        flows.record_outbound(IpProto::SCTP, src, dst);
        assert!(
            flows.admits_inbound(IpProto::SCTP, dst, src),
            "SCTP is tracked, same as UDP (Go `case ipproto.UDP, ipproto.SCTP`)"
        );

        for proto in [
            IpProto::TCP,
            IpProto::ICMP,
            IpProto::ICMPV6,
            IpProto::TSMP,
            IpProto::new(0),
        ] {
            let before = flows.len();
            flows.record_outbound(proto, src, dst);
            assert_eq!(before, flows.len(), "{proto:?} must not be recorded");
            assert!(
                !flows.admits_inbound(proto, dst, src),
                "{proto:?} is never admitted from the flow cache"
            );
        }
    }

    /// The bound, taken from Go's `lruMax`. A stream of outbound datagrams from distinct ephemeral
    /// ports pins at most [`LRU_MAX`] entries, and the oldest flow is the one that goes.
    #[test]
    fn the_cache_is_bounded_at_gos_lru_max() {
        let mut flows = FlowCache::default();
        // One flow per ephemeral source port, which is the shape a busy embedder actually produces.
        let me = |port: u16| SocketAddr::from((std::net::Ipv4Addr::new(100, 64, 0, 1), port));
        let dst = sa("192.0.2.7:53");
        let port = |i: usize| u16::try_from(1024 + i).expect("port fits");

        // The first flow, whose eviction is asserted below.
        flows.record_outbound(IpProto::UDP, me(port(0)), dst);

        // Ten times the bound's worth of distinct flows.
        for i in 1..(LRU_MAX * 10) {
            flows.record_outbound(IpProto::UDP, me(port(i)), dst);
            assert!(
                flows.len() <= LRU_MAX,
                "the cache never exceeds Go's lruMax ({LRU_MAX})"
            );
        }
        assert_eq!(flows.len(), LRU_MAX, "and it fills to exactly that bound");

        assert!(
            !flows.admits_inbound(IpProto::UDP, dst, me(port(0))),
            "the oldest flow was evicted, so its reply is back to needing a rule"
        );
        assert!(
            flows.admits_inbound(IpProto::UDP, dst, me(port(LRU_MAX * 10 - 1))),
            "the newest flow is still tracked"
        );
    }

    /// Both `Add` and `Get` move an entry to the front (Go `lru.Cache`), so a flow that keeps
    /// receiving replies outlives newer, idle ones.
    #[test]
    fn a_hit_refreshes_recency_so_a_busy_flow_survives_eviction() {
        let mut flows = FlowCache::default();
        let me = |port: u16| SocketAddr::from((std::net::Ipv4Addr::new(100, 64, 0, 1), port));
        let dst = sa("192.0.2.7:53");
        let port = |i: usize| u16::try_from(1024 + i).expect("port fits");

        // Fill the cache exactly, oldest first.
        for i in 0..LRU_MAX {
            flows.record_outbound(IpProto::UDP, me(port(i)), dst);
        }
        // Touch the oldest with a reply, which moves it to the front.
        assert!(flows.admits_inbound(IpProto::UDP, dst, me(port(0))));

        // One more flow evicts exactly one entry — and it must be flow 1, not the refreshed flow 0.
        flows.record_outbound(IpProto::UDP, me(port(LRU_MAX)), dst);
        assert_eq!(flows.len(), LRU_MAX);
        assert!(
            flows.admits_inbound(IpProto::UDP, dst, me(port(0))),
            "the refreshed flow survived"
        );
        assert!(
            !flows.admits_inbound(IpProto::UDP, dst, me(port(1))),
            "the next-oldest flow was evicted instead"
        );
    }
}
