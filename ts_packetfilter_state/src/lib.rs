#![doc = include_str!("../README.md")]
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::borrow::Borrow;

use ts_packetfilter as pf;
#[doc(inline)]
pub use ts_packetfilter::apply_update as apply_update_dyn;
use ts_packetfilter_serde as pf_serde;

/// Convert the given `MapResponse`-deserialized rule into [`pf`] format.
///
/// Returns `None` if the rule is not a network rule.
pub fn rule_to_pf(rule: &pf_serde::FilterRule) -> Option<pf::Rule> {
    let rule = rule.as_network()?;

    let mut caps = vec![];
    let mut src_pfxs = vec![];

    for src in &rule.src_ips {
        match src {
            pf_serde::SrcIp::IpRange(r) => src_pfxs.extend(r.iter_prefixes()),
            pf_serde::SrcIp::NodeCap(cap) => caps.push(cap.to_string()),
        }
    }

    let protos = rule
        .ip_proto
        .iter()
        .copied()
        .map(|proto| {
            let proto: isize = proto.into();
            pf::IpProto::from(proto as i64)
        })
        .collect::<Vec<_>>();

    let dsts = rule
        .dst_ports
        .iter()
        .map(|port| pf::DstMatch {
            ips: port.ip.iter_prefixes().collect(),
            ports: port.ports.clone(),
        })
        .collect();

    Some(pf::Rule {
        src: pf::SrcMatch {
            pfxs: src_pfxs,
            caps,
        },
        protos,
        dst: dsts,
    })
}

/// Convert the given `MapResponse`-deserialized rules into [`pf`] format.
#[inline]
pub fn rules_to_pf<'r, 'f>(
    rules: impl IntoIterator<Item = &'f pf_serde::FilterRule<'r>>,
) -> impl Iterator<Item = pf::Rule>
where
    'r: 'f,
{
    rules.into_iter().filter_map(rule_to_pf)
}

/// An owned peer-capability grant retained from a `MapResponse`'s application
/// ([`FilterRule::Application`][pf_serde::FilterRule]) rules — the data the network-rule compile path
/// ([`rule_to_pf`]) discards. Owns its strings (the wire form borrows from the transient netmap
/// buffer). Backs flow-scoped WhoIs (Go `apitype.WhoIsResponse.CapMap` / `Filter.CapsWithValues`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CapGrant {
    /// Source IP prefixes the grant applies to (the flow's source must fall in one).
    pub src_pfxs: Vec<ipnet::IpNet>,
    /// Source **node-capability** names the grant applies to (`SrcIp::NodeCap`, e.g.
    /// `tailscale.com/cap/...`): the grant matches a flow whose SOURCE node holds one of these caps,
    /// in addition to (a union with) the IP-prefix `src_pfxs`. For a `Runtime::whois` query the
    /// source is this node, so these are matched against our own node cap map.
    pub src_node_caps: Vec<String>,
    /// Destination IP prefixes the grant covers (the flow's destination must fall in one).
    pub dst_pfxs: Vec<ipnet::IpNet>,
    /// The granted capabilities: name -> list of raw-JSON values (Go `tailcfg.PeerCapMap`).
    pub caps: BTreeMap<String, Vec<String>>,
}

/// Retain the peer-capability grants from a set of `MapResponse` filter rules — the application-rule
/// counterpart to [`rules_to_pf`], which keeps exactly what that drops. Network rules are skipped.
/// Both `SrcIp::IpRange` (→ [`CapGrant::src_pfxs`]) and `SrcIp::NodeCap` (→
/// [`CapGrant::src_node_caps`]) sources are captured.
pub fn retain_cap_grants<'r, 'f>(
    rules: impl IntoIterator<Item = &'f pf_serde::FilterRule<'r>>,
) -> Vec<CapGrant>
where
    'r: 'f,
{
    let mut out = Vec::new();
    for rule in rules {
        let Some(app) = rule.as_app() else {
            continue;
        };
        let mut src_pfxs = Vec::new();
        let mut src_node_caps = Vec::new();
        for src in &app.src_ips {
            match src {
                pf_serde::SrcIp::IpRange(r) => src_pfxs.extend(r.iter_prefixes()),
                pf_serde::SrcIp::NodeCap(cap) => src_node_caps.push(cap.to_string()),
            }
        }
        for grant in &app.cap_grant {
            let caps = grant
                .peer_caps
                .iter()
                .map(|(name, vals)| {
                    (
                        name.as_ref().to_string(),
                        vals.iter().map(|v| v.to_string()).collect::<Vec<String>>(),
                    )
                })
                .collect::<BTreeMap<String, Vec<String>>>();
            out.push(CapGrant {
                src_pfxs: src_pfxs.clone(),
                src_node_caps: src_node_caps.clone(),
                dst_pfxs: grant.dsts.clone(),
                caps,
            });
        }
    }
    out
}

/// The flow-scoped peer-capability map for a `src -> dst` flow (Go `Filter.CapsWithValues`): union
/// the `caps` of every retained grant whose source matches `src` AND whose `dst_pfxs` contains `dst`,
/// accumulating values per capability name. A grant's source matches when `src` falls in one of its
/// `src_pfxs` **or** the source node holds one of its `src_node_caps` (`src_node_caps` checked via
/// `src_holds_cap`). Empty when no grant matches.
pub fn caps_for(
    grants: &[CapGrant],
    src: core::net::IpAddr,
    dst: core::net::IpAddr,
    src_holds_cap: impl Fn(&str) -> bool,
) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for grant in grants {
        let src_ok = grant.src_pfxs.iter().any(|p| p.contains(&src))
            || grant.src_node_caps.iter().any(|c| src_holds_cap(c));
        let dst_ok = grant.dst_pfxs.iter().any(|p| p.contains(&dst));
        if src_ok && dst_ok {
            for (name, vals) in &grant.caps {
                out.entry(name.clone()).or_default().extend(vals.clone());
            }
        }
    }
    out
}

/// Report whether the special key indicating that the filter state should be
/// cleared is present and has a `null` value.
#[inline]
pub fn should_clear_storage<K, V>(packet_filters: &BTreeMap<K, Option<V>>) -> bool
where
    K: Borrow<str> + Ord,
{
    matches!(packet_filters.get(pf::CLEAR_MAP_KEY), Some(&None))
}

/// Update `storage` on the basis of a `MapResponse` update.
///
/// `packet_filter` is the old-style `packet_filter` field, and `update_map` is the
/// `packet_filters` field.
pub fn convert_and_apply_update<'r>(
    mut storage: impl pf::FilterStorage,
    packet_filter: Option<&pf_serde::Ruleset<'r>>,
    update_map: &pf_serde::Map<'r>,
) {
    let should_clear = should_clear_storage(update_map);

    let packet_filter = packet_filter.map(|f| rules_to_pf(f).collect());
    let mut map_iter = update_map
        .iter()
        .map(|(s, r)| (*s, r.as_ref().map(|r| rules_to_pf(r).collect())));

    apply_update_dyn(&mut storage, packet_filter, should_clear, &mut map_iter)
}

/// Update `storage` on the basis of a `MapResponse` update converted to `pf` format.
///
/// `packet_filter` is the old-style `packet_filter` field, and `update_map` is the
/// `packet_filters` field.
pub fn apply_update(
    mut storage: impl pf::FilterStorage,
    packet_filter: Option<pf::Ruleset>,
    update_map: &BTreeMap<String, Option<pf::Ruleset>>,
) {
    let should_clear = should_clear_storage(update_map);

    apply_update_dyn(
        &mut storage,
        packet_filter,
        should_clear,
        &mut update_map.iter().map(|(k, v)| (k.as_str(), v.clone())),
    )
}

#[cfg(test)]
mod test {
    use alloc::{collections::BTreeMap, vec};
    use core::net::IpAddr;
    use std::net::Ipv4Addr;

    use pf::FilterExt;
    use pf_serde::{DstPort, IpProto, NetworkRule, SrcIp};

    use super::*;

    const PROTO: pf::IpProto = pf::IpProto::TCP;
    const PORT: u16 = 80;

    const SRC: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    const DST: IpAddr = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));

    /// `retain_cap_grants` keeps application-rule grants (which `rule_to_pf` drops), and `caps_for`
    /// unions the caps of every grant matching the `src -> dst` flow — Go `Filter.CapsWithValues`.
    #[test]
    fn cap_grants_retained_and_matched_for_flow() {
        use pf_serde::{AppRule, CapGrant as SerdeCapGrant, FilterRule};
        use ts_peercapability::Name;

        let src_net: ipnet::IpNet = "100.64.0.0/10".parse().unwrap();
        let dst_net: ipnet::IpNet = "100.99.0.0/16".parse().unwrap();

        // An application rule granting `cap/web` (value `["read"]`) for the dst prefix, plus a plain
        // network rule that must be ignored by the cap-grant retention.
        let app = FilterRule::Application(AppRule {
            src_ips: vec![SrcIp::from(src_net)],
            cap_grant: vec![SerdeCapGrant {
                dsts: vec![dst_net],
                peer_caps: [(Name("tailscale.com/cap/web"), vec!["\"read\""])]
                    .into_iter()
                    .collect(),
            }],
        });
        let net = FilterRule::Network(NetworkRule {
            src_ips: vec![SrcIp::from(SRC)],
            ip_proto: IpProto::NULL_DEFAULTS.to_vec(),
            dst_ports: vec![DstPort {
                ports: PORT..=PORT,
                ip: DST.into(),
            }],
        });

        let grants = retain_cap_grants([&app, &net]);
        assert_eq!(grants.len(), 1, "only the application rule yields a grant");

        // A flow from inside src_net to inside dst_net gets the cap (IP-prefix source match; this
        // grant has no node-cap source, so the cap check is never consulted — `|_| false`).
        let in_src = IpAddr::V4(Ipv4Addr::new(100, 64, 1, 1));
        let in_dst = IpAddr::V4(Ipv4Addr::new(100, 99, 5, 5));
        let caps = caps_for(&grants, in_src, in_dst, |_| false);
        assert_eq!(
            caps.get("tailscale.com/cap/web").map(Vec::as_slice),
            Some(&["\"read\"".to_string()][..]),
            "the matching flow gets the granted cap value"
        );

        // A flow to a dst outside the grant's prefixes gets nothing.
        let out_dst = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(
            caps_for(&grants, in_src, out_dst, |_| false).is_empty(),
            "a dst outside the grant prefix yields no caps"
        );
    }

    /// A cap-grant whose SOURCE is a node-capability (`SrcIp::NodeCap`, not an IP prefix) matches a
    /// flow whose source node HOLDS that cap — Go `SrcIp` node-cap semantics. The source IP is
    /// irrelevant for such a grant; the `src_holds_cap` predicate decides.
    #[test]
    fn cap_grant_node_cap_source_matches_when_source_holds_cap() {
        use pf_serde::{AppRule, CapGrant as SerdeCapGrant, FilterRule, SrcIp};
        use ts_peercapability::Name;

        let dst_net: ipnet::IpNet = "100.99.0.0/16".parse().unwrap();

        // Source is the node-cap `cap:tailscale.com/cap/is-admin` (no IP prefix).
        let app = FilterRule::Application(AppRule {
            src_ips: vec![SrcIp::from_cap("tailscale.com/cap/is-admin")],
            cap_grant: vec![SerdeCapGrant {
                dsts: vec![dst_net],
                peer_caps: [(Name("tailscale.com/cap/admin-ui"), vec!["true"])]
                    .into_iter()
                    .collect(),
            }],
        });

        let grants = retain_cap_grants([&app]);
        assert_eq!(grants.len(), 1);
        assert!(
            grants[0].src_pfxs.is_empty(),
            "a node-cap source has no IP prefix"
        );
        assert_eq!(grants[0].src_node_caps, vec!["tailscale.com/cap/is-admin"]);

        let src = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)); // src IP is irrelevant for this grant
        let dst = IpAddr::V4(Ipv4Addr::new(100, 99, 5, 5));

        // Source holds the required node-cap → the grant matches.
        let held = caps_for(&grants, src, dst, |c| c == "tailscale.com/cap/is-admin");
        assert_eq!(
            held.get("tailscale.com/cap/admin-ui").map(Vec::as_slice),
            Some(&["true".to_string()][..]),
            "a node-cap-sourced grant applies when the source holds the cap"
        );

        // Source does NOT hold the cap → no match (even though the dst is in range).
        assert!(
            caps_for(&grants, src, dst, |_| false).is_empty(),
            "no node-cap held ⇒ a node-cap-sourced grant does not apply"
        );
    }

    #[test]
    fn basic() {
        let mut filters = BTreeMap::new();

        convert_and_apply_update(
            &mut filters,
            None,
            &pf_serde::Map::from_iter([(pf::CLEAR_MAP_KEY, None)]),
        );
        assert_eq!(filters.len(), 0);

        convert_and_apply_update(
            &mut filters,
            None,
            &pf_serde::Map::from_iter([(pf::DEFAULT_RULESET_NAME, Some(vec![]))]),
        );
        assert_eq!(filters.len(), 0);

        convert_and_apply_update(
            &mut filters,
            None,
            &pf_serde::Map::from_iter([(
                pf::DEFAULT_RULESET_NAME,
                Some(vec![
                    NetworkRule {
                        src_ips: vec![SrcIp::from(SRC)],
                        ip_proto: IpProto::NULL_DEFAULTS.to_vec(),
                        dst_ports: vec![DstPort {
                            ports: PORT..=PORT,
                            ip: DST.into(),
                        }],
                    }
                    .into(),
                ]),
            )]),
        );
        assert_eq!(filters.len(), 1);
        assert!(filters.can_access(
            &pf::PacketInfo {
                dst: DST,
                ip_proto: PROTO,
                src: SRC,
                port: PORT,
            },
            []
        ));

        convert_and_apply_update(
            &mut filters,
            None,
            &pf_serde::Map::from_iter([(pf::CLEAR_MAP_KEY, None)]),
        );
        assert_eq!(filters.len(), 0);
    }
}
