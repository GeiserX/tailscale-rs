#![doc = include_str!("../README.md")]
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};

use ts_bart::{RoutingTable, RoutingTableExt};
use ts_bitset::{BitsetDyn, BitsetStatic};
use ts_dynbitset::DynBitset;
use ts_packetfilter::{Filter, FilterStorage, IpProto, PacketInfo, Rule, Ruleset, filter::CapIter};

mod cap_lookup;
mod dst_port;
mod port_trie;

use cap_lookup::CapLookup;
use dst_port::DstMatchLookup;
#[doc(inline)]
pub use port_trie::PortTrie;

type RuleId = usize;
type RuleBitset = DynBitset;

/// A filter that stores each of its rule components (src ip, src cap, dst ip/port, and ip
/// proto) independently in data structures which can be queried for all matching rules
/// as bitset results.
///
/// The set of rules matching a packet can be computed by querying all the component
/// structures and taking the bitwise intersection of their results: the surviving bits
/// are the rule ids that matched. The ruleset name is resolved via a reverse index from
/// the rule id.
#[derive(Debug, Clone, Default)]
pub struct BartFilter {
    caps: CapLookup,
    srcs: ts_bart::Table<RuleBitset>,
    dsts: DstMatchLookup,
    ip_protos: BTreeMap<IpProto, RuleBitset>,

    /// Lookup rule id -> ruleset name.
    rules_to_rulesets: Vec<Option<String>>,

    /// Unallocated rule IDs that should be claimed by new rules.
    rule_freelist: RuleBitset,

    /// Lookup for ruleset info by name.
    rulesets: BTreeMap<String, RulesetEntry>,
}

fn pop_freelist(b: &mut DynBitset) -> Option<usize> {
    // Want to pop the _first_ id to promote compactness near the beginning of id ranges
    // so it's more likely that our id bitsets will stay small. Ids at the end of the id range
    // will tend to be cleaned up and made implicitly available by compacting operations.
    if let Some(first) = b.first_set() {
        b.clear(first);
        return Some(first);
    }

    None
}

#[derive(Debug, Clone)]
struct RulesetEntry {
    /// The original rule records need to be retained in order to avoid a linear walk of
    /// all the child data structures on ruleset removal. E.g. because we have the
    /// [`DstMatch`] entries, [`DstMatchLookup`] can directly resolve the ids to remove.
    /// Likewise for [`CapLookup`], `srcs`, and `ip_protos`.
    ///
    /// For small filters, it would likely be a favorable tradeoff to just drop this field
    /// and do the linear lookup, as it will be fast enough, and the field can use a
    /// substantial amount of memory. But for large filters that are updated with any
    /// frequency, the linear walk would likely cause substantial pauses in packet
    /// processing.
    ///
    /// This comes at the cost of significant weight of this field.
    ruleset: Ruleset,
    rule_ids: RuleBitset,
}

impl RulesetEntry {
    fn rules_and_ids(&self) -> impl Iterator<Item = (RuleId, &Rule)> {
        self.rule_ids.bits().zip(&self.ruleset)
    }
}

impl BartFilter {
    /// Insert a ruleset under the given name. If it already exists, its state
    /// is cleared before updating.
    fn insert(&mut self, name: &str, ruleset: Ruleset) {
        self.remove(name);

        let mut ent = RulesetEntry {
            ruleset,
            rule_ids: Default::default(),
        };

        for rule in &ent.ruleset {
            let rule_id = if let Some(idx) = pop_freelist(&mut self.rule_freelist) {
                idx
            } else {
                let idx = self.rules_to_rulesets.len();
                self.rules_to_rulesets.push(None);
                idx
            };

            ent.rule_ids.set(rule_id);
            self.rules_to_rulesets[rule_id] = Some(name.to_string());

            for proto in &rule.protos {
                self.ip_protos.entry(*proto).or_default().set(rule_id);
            }

            for cap in &rule.src.caps {
                self.caps.insert(cap, rule_id);
            }

            for &pfx in &rule.src.pfxs {
                self.srcs.modify(pfx, |val| {
                    if let Some(val) = val {
                        val.set(rule_id);
                        ts_bart::RouteModification::Noop
                    } else {
                        ts_bart::RouteModification::Insert(DynBitset::empty().with_bit(rule_id))
                    }
                });
            }

            for dstport in &rule.dst {
                self.dsts.insert(rule_id, dstport.clone());
            }
        }

        self.rulesets.insert(name.to_string(), ent);
        self.compact();
    }

    fn remove(&mut self, ruleset_name: &str) {
        let Some(entry) = self.rulesets.remove(ruleset_name) else {
            return;
        };

        self.rule_freelist.union_inplace(&entry.rule_ids);

        for rule_id in entry.rule_ids.bits() {
            self.rules_to_rulesets[rule_id] = None;
        }

        for (rule_id, rule) in entry.rules_and_ids() {
            for proto in &rule.protos {
                let remove = if let Some(rules) = self.ip_protos.get_mut(proto) {
                    rules.clear(rule_id);
                    rules.is_empty()
                } else {
                    false
                };

                if remove {
                    self.ip_protos.remove(proto);
                }
            }

            for dst in &rule.dst {
                self.dsts.remove(rule_id, dst);
            }

            for cap in &rule.src.caps {
                self.caps.remove(rule_id, cap);
            }

            for &pfx in &rule.src.pfxs {
                self.srcs.modify(pfx, |val| {
                    if let Some(val) = val {
                        val.clear(rule_id);

                        if val.is_empty() {
                            return ts_bart::RouteModification::Remove;
                        }
                    }

                    ts_bart::RouteModification::Noop
                });
            }
        }

        self.compact();
    }

    fn lookup(&self, info: &PacketInfo, caps: CapIter) -> DynBitset {
        let mut src_matches = self.caps.lookup(caps);

        // src cap OR src ip
        if let Some(ip_matches) = self.srcs.lookup(info.src) {
            src_matches.union_inplace(ip_matches);
        }

        // must match src AND ipproto AND dest
        let mut all_matches = src_matches;
        if all_matches.is_empty() {
            return all_matches;
        }

        if let Some(proto_matches) = self.ip_protos.get(&info.ip_proto) {
            all_matches.intersect_inplace(proto_matches);
        } else {
            all_matches.clear_all();
        }

        if all_matches.is_empty() {
            return all_matches;
        }

        // Destination match, with the port test applied per-protocol exactly as the reference
        // `Rule::matches`/`DstMatch::matches` path does (Go `runIn4`/`runIn6`): TCP/UDP/SCTP check
        // the port; ICMP/ICMPv6 match IPs only; any other portless protocol matches IPs only but
        // only against all-ports `DstMatch`es. Keeping this in lockstep with the map filter is
        // required — `CheckingFilter` runs both and flags any divergence.
        let dst_matches = if info.ip_proto.is_port_ful() {
            self.dsts.lookup(&info.dst, info.port)
        } else if info.ip_proto == IpProto::ICMP || info.ip_proto == IpProto::ICMPV6 {
            self.dsts.lookup_ips_only(&info.dst)
        } else {
            self.dsts.lookup_all_ports_ips(&info.dst)
        };
        all_matches.intersect_inplace(&dst_matches);

        all_matches
    }

    fn compact(&mut self) {
        while let Some(None) = self.rules_to_rulesets.last() {
            self.rules_to_rulesets.pop();
        }

        // The freelist only needs to actually hold ids within the rule to ruleset mapping -- ids
        // outside that range are implicitly free.
        self.rule_freelist.zero_from(self.rules_to_rulesets.len());
    }
}

impl FilterStorage for BartFilter {
    fn insert_dyn(&mut self, name: &str, ruleset: &mut dyn Iterator<Item = Rule>) {
        self.insert(name, ruleset.collect());
    }

    fn remove(&mut self, name: &str) {
        self.remove(name);
    }

    fn clear(&mut self) {
        self.caps.clear();
        self.srcs.clear();
        self.dsts.clear();
        self.ip_protos.clear();
        self.rule_freelist.clear_all();
        self.rules_to_rulesets.clear();
        self.rulesets.clear();
    }
}

impl Filter for BartFilter {
    fn match_for(&self, info: &PacketInfo, caps: CapIter) -> Option<&str> {
        let all_matches = self.lookup(info, caps);

        // Grab the first match
        all_matches
            .first_set()
            .map(|rule_id| self.rules_to_rulesets[rule_id].as_ref().unwrap().as_str())
    }

    fn matches(&self, info: &PacketInfo, caps: CapIter) -> bool {
        let all_matches = self.lookup(info, caps);

        !all_matches.is_empty()
    }
}

#[cfg(test)]
mod test {
    use alloc::vec;

    use pf::FilterExt;
    use proptest::prelude::*;
    use ts_array256::ArrayStorageSliceExt;
    use ts_packetfilter as pf;

    use super::*;
    use crate::dst_port::test::bart_bitset;

    #[test]
    fn basic() {
        let mut filter = BartFilter::default();
        filter.verify_integrity();

        filter.insert(
            "abc",
            vec![Rule {
                src: pf::SrcMatch {
                    pfxs: vec!["0.0.0.0/0".parse().unwrap()],
                    caps: vec![String::new()],
                },
                // TCP (a port-ful proto) so the `0..=0` rule matches the port-0 probe below: a
                // bare `IpProto::new(0)` is now treated as an "other" protocol that only matches an
                // all-ports rule (Go `matchProtoAndIPsOnlyIfAllPorts`), so it would not match here.
                protos: vec![IpProto::TCP],
                dst: vec![pf::DstMatch {
                    ips: vec!["0.0.0.0/0".parse().unwrap()],
                    ports: 0..=0,
                }],
            }],
        );
        filter.verify_integrity();

        assert!(filter.can_access(
            &PacketInfo {
                src: "1.2.3.4".parse().unwrap(),
                dst: "5.6.7.8".parse().unwrap(),
                port: 0,
                ip_proto: IpProto::TCP,
            },
            []
        ));

        filter.remove("abc");
        filter.verify_integrity();
    }

    #[test]
    fn repeated_dst() {
        let mut filter = BartFilter::default();

        let rule = Rule {
            src: pf::SrcMatch {
                pfxs: vec!["0.0.0.0/0".parse().unwrap()],
                caps: vec![String::new()],
            },
            protos: vec![IpProto::new(0)],
            dst: vec![
                pf::DstMatch {
                    ports: 0..=0,
                    ips: vec!["128.0.0.0/1".parse().unwrap()],
                },
                pf::DstMatch {
                    ports: 0..=0,
                    ips: vec!["0.0.0.0/0".parse().unwrap()],
                },
            ],
        };

        filter.insert("", vec![rule]);
        filter.verify_integrity();

        filter.remove("");
        filter.verify_integrity();
    }

    #[test]
    fn rules_in_same_ruleset_distinct() {
        let mut filter = BartFilter::default();

        filter.insert(
            "a",
            vec![
                Rule {
                    src: pf::SrcMatch {
                        pfxs: vec!["128.0.0.0/1".parse().unwrap()],
                        ..Default::default()
                    },
                    protos: vec![IpProto::TCP, IpProto::UDP],
                    dst: vec![pf::DstMatch {
                        ports: 80..=80,
                        ips: vec!["0.0.0.0/0".parse().unwrap()],
                    }],
                },
                Rule {
                    src: pf::SrcMatch {
                        caps: vec!["mycap".to_string()],
                        ..Default::default()
                    },
                    protos: vec![IpProto::TCP, IpProto::UDP],
                    dst: vec![pf::DstMatch {
                        ports: 123..=124,
                        ips: vec!["0.0.0.0/0".parse().unwrap()],
                    }],
                },
            ],
        );

        assert!(!filter.can_access(
            &PacketInfo {
                src: "128.1.1.1".parse().unwrap(), // only first
                dst: "1.1.1.1".parse().unwrap(),   // both
                ip_proto: IpProto::UDP,            // both
                port: 123,                         // second
            },
            []
        ));

        assert!(!filter.can_access(
            &PacketInfo {
                src: "0.1.1.1".parse().unwrap(), // neither
                dst: "1.1.1.1".parse().unwrap(), // both
                ip_proto: IpProto::UDP,          // both
                port: 80,                        // first
            },
            ["mycap"] // second
        ));
    }

    #[test]
    fn compaction() {
        let mut filter = BartFilter::default();

        filter.insert("abc", vec![Rule::default()]);
        filter.insert("def", vec![Rule::default()]);
        filter.insert("ghi", vec![Rule::default()]);

        filter.remove("abc");

        assert_eq!(filter.rule_freelist.count_ones(), 1);
        assert_eq!(filter.rules_to_rulesets.len(), 3);
        assert_eq!(filter.rulesets.len(), 2);

        // compaction should trigger here
        filter.remove("ghi");

        assert_eq!(filter.rule_freelist.count_ones(), 1);
        assert_eq!(filter.rules_to_rulesets.len(), 2);
        assert_eq!(filter.rulesets.len(), 1);

        filter.remove("def");

        assert!(filter.rule_freelist.is_empty());
        assert!(filter.rules_to_rulesets.is_empty());
        assert!(filter.rulesets.is_empty());
    }

    impl BartFilter {
        fn verify_integrity(&self) {
            self.dsts.verify_integrity();
            self.caps.verify_integrity();

            let ruleset_stored_rule_ids =
                self.rulesets
                    .values()
                    .fold(DynBitset::default(), |mut acc, x| {
                        acc.union_inplace(&x.rule_ids);
                        acc
                    });

            let ipv4_matches = bart_bitset(self.srcs.root(true));
            let ipv6_matches = bart_bitset(self.srcs.root(false));

            let src_matches = ipv4_matches | ipv6_matches;

            let ipproto_matches =
                self.ip_protos
                    .values()
                    .fold(DynBitset::default(), |mut acc, x| {
                        acc.union_inplace(x);
                        acc
                    });

            let cap_matches = self.caps.dump_rule_ids();
            let dst_matches = self.dsts.dump_rule_ids();

            // PRE: all rules applied actually have a src match defined
            assert_eq!(src_matches, ipproto_matches, "src <-> ipproto");
            assert_eq!(src_matches, dst_matches, "src <-> dst");
            assert_eq!(src_matches, cap_matches, "src <-> cap");
            assert_eq!(src_matches, ruleset_stored_rule_ids, "src <-> ruleset");

            assert!(!self.rule_freelist.intersects(&src_matches));
        }
    }

    /// A rule that grants the source `0.0.0.0/0` access to `dst_ip` on the given protos + port
    /// range — the shape of a typical `tailscale up` ACL ("these peers may reach me on tcp/22").
    fn rule(protos: &[IpProto], dst_ip: &str, ports: core::ops::RangeInclusive<u16>) -> Rule {
        Rule {
            src: pf::SrcMatch {
                pfxs: vec!["0.0.0.0/0".parse().unwrap()],
                // An (empty-string) cap entry so every rule registers in BOTH the src-ip and cap
                // bookkeeping — `BartFilter::verify_integrity` asserts `src <-> cap` parity, matching
                // the convention of the other tests in this module.
                caps: vec![String::new()],
            },
            protos: protos.to_vec(),
            dst: vec![pf::DstMatch {
                ports,
                ips: vec![dst_ip.parse().unwrap()],
            }],
        }
    }

    fn info(proto: IpProto, dst: &str, port: u16) -> PacketInfo {
        PacketInfo {
            src: "1.2.3.4".parse().unwrap(),
            dst: dst.parse().unwrap(),
            ip_proto: proto,
            port,
        }
    }

    /// The iter44 fix: a rule that opens a narrow TCP port to an IP also allows ICMP to that IP
    /// (Go `runIn4`/`runIn6` route ICMP through an IPs-only match — "if any port is open to an IP,
    /// allow ICMP to it"). Before the fix, ICMP (port 0) failed the `22..=22` port test and was
    /// dropped, silently breaking ping to a peer that only opens tcp/22 under a restrictive ACL.
    #[test]
    fn icmp_allowed_by_a_port_scoped_tcp_rule_to_the_same_ip() {
        let mut filter = BartFilter::default();
        // The default protos a portless ACL compiles to include ICMP + TCP (control sends them).
        filter.insert(
            "acl",
            vec![rule(
                &[IpProto::ICMP, IpProto::ICMPV6, IpProto::TCP, IpProto::UDP],
                "5.6.7.8/32",
                22..=22,
            )],
        );
        filter.verify_integrity();

        // ICMP to the granted IP: allowed (IPs-only — the 22..=22 range is ignored for ICMP).
        assert!(
            filter.can_access(&info(IpProto::ICMP, "5.6.7.8", 0), []),
            "ICMP to a granted IP must be allowed regardless of the rule's port range"
        );
        // ICMP to a DIFFERENT IP: still denied (IPs-only does not mean all-IPs).
        assert!(
            !filter.can_access(&info(IpProto::ICMP, "9.9.9.9", 0), []),
            "ICMP to a non-granted IP stays denied"
        );
        // TCP is still port-gated: 22 allowed, 443 denied.
        assert!(filter.can_access(&info(IpProto::TCP, "5.6.7.8", 22), []));
        assert!(
            !filter.can_access(&info(IpProto::TCP, "5.6.7.8", 443), []),
            "TCP must still honor the rule's port range"
        );
    }

    /// A non-ICMP "portless" protocol matches IPs-only ONLY when the rule opens all ports (Go
    /// `matchProtoAndIPsOnlyIfAllPorts`); a narrow port range never opens such a protocol.
    #[test]
    fn other_portless_proto_matches_only_under_an_all_ports_rule() {
        let gre = IpProto::new(47); // GRE: portless, not ICMP.

        // Narrow-port rule: GRE is NOT allowed (the rule doesn't open all ports).
        let mut narrow = BartFilter::default();
        narrow.insert("acl", vec![rule(&[gre], "5.6.7.8/32", 22..=22)]);
        assert!(
            !narrow.can_access(&info(gre, "5.6.7.8", 0), []),
            "a portless non-ICMP proto is not opened by a narrow-port rule"
        );

        // A range that CONTAINS port 0 but is NOT all-ports must also NOT open GRE — guards against a
        // naive `ports.start() == 0` or single-`lookup(0)` regression (the discriminating case for
        // "contains 0 isn't enough; the range must be exactly 0..=65535").
        let mut contains_zero = BartFilter::default();
        contains_zero.insert("acl", vec![rule(&[gre], "5.6.7.8/32", 0..=1024)]);
        assert!(
            !contains_zero.can_access(&info(gre, "5.6.7.8", 0), []),
            "a range containing port 0 but not all ports must not open a portless proto"
        );

        // All-ports rule: GRE IS allowed (IPs-only under all-ports).
        let mut all_ports = BartFilter::default();
        all_ports.insert("acl", vec![rule(&[gre], "5.6.7.8/32", 0..=u16::MAX)]);
        assert!(
            all_ports.can_access(&info(gre, "5.6.7.8", 0), []),
            "an all-ports rule opens a portless non-ICMP proto to the granted IP"
        );
    }

    /// The load-bearing invariant behind the bart `lookup_all_ports_ips` trick (`lookup(0) ∩
    /// lookup(65535)`): two PARTIAL-range `DstMatch`es of the SAME rule that together cover both port
    /// extremes — but where no single `DstMatch` is all-ports — must NOT be treated as all-ports.
    /// The intersection runs at the `DstMatchId` level before resolving to rule ids, so the two
    /// distinct DstMatchIds (`0..=0` in `lookup(0)`, `60000..=65535` in `lookup(65535)`) never
    /// collapse into a false all-ports match. Without this, a portless proto (GRE) would be wrongly
    /// ALLOWED — a silent ACL bypass — so this test guards both the bart trick and the map path's
    /// exact `ports == ALL_PORTS` check, and confirms the two agree.
    #[test]
    fn split_range_dstmatches_do_not_count_as_all_ports() {
        use pf::FilterExt;
        let gre = IpProto::new(47);
        let rules = vec![Rule {
            src: pf::SrcMatch {
                pfxs: vec!["0.0.0.0/0".parse().unwrap()],
                caps: vec![String::new()],
            },
            protos: vec![gre],
            // Two partial ranges covering port 0 and port 65535 separately — neither is all-ports.
            dst: vec![
                pf::DstMatch {
                    ports: 0..=0,
                    ips: vec!["5.6.7.8/32".parse().unwrap()],
                },
                pf::DstMatch {
                    ports: 60000..=u16::MAX,
                    ips: vec!["5.6.7.8/32".parse().unwrap()],
                },
            ],
        }];

        let mut bart = BartFilter::default();
        bart.insert("acl", rules.clone());
        bart.verify_integrity();
        let mut map = pf::HashbrownFilter::default();
        map.insert("acl".to_string(), rules);

        let probe = info(gre, "5.6.7.8", 0);
        assert!(
            !bart.can_access(&probe, []),
            "split partial ranges must not be treated as all-ports (bart)"
        );
        assert!(
            !map.can_access(&probe, []),
            "split partial ranges must not be treated as all-ports (map)"
        );
        assert_eq!(
            bart.can_access(&probe, []),
            map.can_access(&probe, []),
            "bart and map must agree on the split-range non-all-ports verdict"
        );
    }

    /// ICMPv6 takes the same IPs-only path as ICMP and must be exercised distinctly over an IPv6
    /// address (it carries Neighbor Discovery — a regression here breaks v6 connectivity). A port-80
    /// rule over a v6 prefix allows ICMPv6 to a covered address (IPs-only) and denies it elsewhere.
    #[test]
    fn icmpv6_matches_ips_only_over_a_v6_prefix() {
        use pf::FilterExt;
        let rules = vec![rule(
            &[IpProto::ICMPV6, IpProto::TCP],
            "2001:db8::/32",
            80..=80,
        )];

        let mut bart = BartFilter::default();
        bart.insert("acl", rules.clone());
        let mut map = pf::HashbrownFilter::default();
        map.insert("acl".to_string(), rules);

        for probe in [
            info(IpProto::ICMPV6, "2001:db8::1", 0), // granted v6 prefix -> allow (IPs-only)
            info(IpProto::ICMPV6, "2001:dead::1", 0), // other v6 prefix  -> deny
            info(IpProto::TCP, "2001:db8::1", 80),   // TCP in range      -> allow
            info(IpProto::TCP, "2001:db8::1", 443),  // TCP out of range  -> deny
        ] {
            assert_eq!(
                bart.can_access(&probe, []),
                map.can_access(&probe, []),
                "bart and map must agree on the ICMPv6/v6 verdict for {probe:?}"
            );
        }
        assert!(bart.can_access(&info(IpProto::ICMPV6, "2001:db8::1", 0), []));
        assert!(!bart.can_access(&info(IpProto::ICMPV6, "2001:dead::1", 0), []));
    }

    /// The production `BartFilter` and the reference map `Rule::matches` path must agree for every
    /// protocol/port combination — `CheckingFilter` runs both and flags divergence, so the iter44
    /// fix had to land in lockstep. This drives a shared rule set through both and asserts identical
    /// verdicts across ICMP, TCP (in/out of range), and a portless non-ICMP proto.
    #[test]
    fn bart_and_map_agree_on_icmp_and_port_modes() {
        use pf::FilterExt;
        let rules = vec![rule(
            &[IpProto::ICMP, IpProto::TCP, IpProto::UDP],
            "5.6.7.8/32",
            22..=22,
        )];

        let mut bart = BartFilter::default();
        bart.insert("acl", rules.clone());
        let mut map = pf::HashbrownFilter::default();
        map.insert("acl".to_string(), rules);

        for probe in [
            info(IpProto::ICMP, "5.6.7.8", 0),  // ICMP granted IP -> both allow
            info(IpProto::ICMP, "9.9.9.9", 0),  // ICMP other IP   -> both deny
            info(IpProto::TCP, "5.6.7.8", 22),  // TCP in range    -> both allow
            info(IpProto::TCP, "5.6.7.8", 443), // TCP out of range-> both deny
            info(IpProto::UDP, "5.6.7.8", 22),  // UDP in range    -> both allow
            info(IpProto::new(47), "5.6.7.8", 0), // GRE narrow port -> both deny
        ] {
            assert_eq!(
                bart.can_access(&probe, []),
                map.can_access(&probe, []),
                "bart and map filters must agree for {probe:?}"
            );
        }
    }

    prop_compose! {
        fn any_rule()(
            protos in proptest::collection::vec(any::<i64>(), 1..25),
            caps in proptest::collection::vec(any::<String>(), 1..25),
            dstmatches in proptest::collection::vec(dst_port::test::any_dstmatch(), 1..25),
            srcs in proptest::collection::vec(dst_port::test::any_ipnet(), 1..25),
        ) -> Rule {
            Rule {
                dst: dstmatches,
                protos: protos.into_iter().map(IpProto::new).collect(),
                src: pf::SrcMatch {
                    pfxs: srcs,
                    caps,
                }
            }
        }
    }

    proptest::proptest! {
        #[test]
        fn prop_basic(name: String, rule in any_rule()) {
            // Add TCP (a port-ful proto) to the rule's proto set so the self-match probe below can
            // use the port-ful match path: a packet at the rule's port-range start self-matches. A
            // random `any::<i64>()` proto from `any_rule` is usually an "other" protocol, which now
            // matches IPs-only and only under an all-ports rule (Go `matchProtoAndIPsOnlyIfAllPorts`),
            // so probing with the raw generated proto would no longer self-match a narrow-port rule.
            // TCP exercises the same dst/src/proto bookkeeping while keeping the self-match valid.
            let mut rule = rule;
            rule.protos.push(IpProto::TCP);

            let mut filter = BartFilter::default();
            filter.insert(&name, vec![rule.clone()]);
            filter.verify_integrity();

            if let Some(dst) = rule.dst.first() &&
            let Some(dst_pfx) = dst.ips.first() &&
            let Some(src_pfx) = rule.src.pfxs.first()
            {
                let packet_info = PacketInfo {
                    dst: dst_pfx.addr(),
                    port: *dst.ports.start(),
                    src: src_pfx.addr(),
                    ip_proto: IpProto::TCP,
                };
                let cap = rule.src.caps.iter().map(|cap| cap.as_str()).take(1).collect::<Vec<_>>();

                let rules = filter.lookup(&packet_info, &mut cap.iter().copied());
                prop_assert!(!rules.is_empty());
                prop_assert!(filter.can_access(&packet_info, cap));
            }

            filter.remove(&name);
            filter.verify_integrity();

            assert!(filter.rules_to_rulesets.is_empty());
            assert!(filter.rule_freelist.is_empty());
            assert!(filter.rulesets.is_empty());
            assert_eq!(filter.srcs.size(), 0);
        }
    }
}
