use alloc::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::derp_map::RegionId;

/// Map of stringified DERP region IDs and address families to their average latency in
/// milliseconds.
pub type DerpLatencyMap<'a> = BTreeMap<&'a str, f64>;

/// Indicates the type of physical link (layer 2) connecting a Tailscale node to the network.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkType<'a> {
    /// A wired connection, such as 802.3 Ethernet or 802.4 Token Bus.
    Wired,
    /// A wireless 802.11 connection.
    Wifi,
    /// A wireless cellular data connection, such as 3G/4G/5G or the fabled EDGE.
    Mobile,
    /// A network link type that doesn't fall under the other categories.
    #[serde(untagged, borrow)]
    Other(&'a str),
}

/// Information about a Tailscale node's host networking state.
#[serde_with::apply(
    &str => #[serde(borrow)] #[serde(skip_serializing_if = "str::is_empty")],
    Option => #[serde(skip_serializing_if = "Option::is_none")],
     _ => #[serde(default)],
)]
#[derive(Clone, Debug, PartialEq, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct NetInfo<'a> {
    // NOTE: Go `tailcfg.NetInfo` fields use empty-name `json:",omitzero"` tags → each marshals as the
    // Go field name VERBATIM, preserving acronyms (`WorkingUDP`, `WorkingIPv6`, `UPnP`, `PreferredDERP`,
    // …). The struct's `rename_all = "PascalCase"` would lowercase those acronyms (`WorkingUdp`,
    // `Upnp`, `PreferredDerp`), keys a strict Go decoder drops — so every acronym field carries an
    // explicit `#[serde(rename)]` to Go's exact key. Non-acronym fields (HairPinning, HavePortMap,
    // LinkType, FirewallMode) keep the PascalCase default.
    /// Indicates whether the host's NAT mappings vary based on the destination IP address. Wire key
    /// `MappingVariesByDestIP`, not `MappingVariesByDestIp`.
    #[serde(rename = "MappingVariesByDestIP")]
    pub mapping_varies_by_dest_ip: Option<bool>,
    /// Indicates if the router between the Tailscale node and the internet does hairpinning. This
    /// value will be `true` even when there's no NAT involved.
    pub hair_pinning: Option<bool>,
    /// Indicates whether the Tailscale node's host has IPv6 internet connectivity. Wire key
    /// `WorkingIPv6`, not `WorkingIpv6`.
    #[serde(rename = "WorkingIPv6")]
    pub working_ipv6: Option<bool>,
    /// Indicates whether the Tailscale node's host operating system supports IPv6 at all,
    /// regardless of whether IPv6 internet connectivity is available. Wire key `OSHasIPv6`, not
    /// `OsHasIpv6`.
    #[serde(rename = "OSHasIPv6")]
    pub os_has_ipv6: Option<bool>,
    /// Indicates whether the Tailscale node's host has UDP internet connectivity. Wire key
    /// `WorkingUDP`, not `WorkingUdp`.
    #[serde(rename = "WorkingUDP")]
    pub working_udp: Option<bool>,
    /// Indicates whether the Tailscale node's host has working ICMPv4. `None` indicates this wasn't
    /// checked, and is unknown. Wire key `WorkingICMPv4`, not `WorkingIcmpv4`.
    #[serde(rename = "WorkingICMPv4")]
    pub working_icmpv4: Option<bool>,
    /// Indicates whether the Tailscale node has an existing open port mapping, regardless of the
    /// mapping mechanism (e.g. UPnP, NAT-PMP, PCP, etc.).
    pub have_port_map: Option<bool>,
    /// Indicates whether UPnP is present on the Tailscale node's LAN. `None` indicates this wasn't
    /// checked, and is unknown. Wire key `UPnP` (Go's exact casing), not the `PascalCase` `Upnp`.
    #[serde(rename = "UPnP")]
    pub upnp: Option<bool>,
    /// Indicates whether NAT-PMP is present on the Tailscale node's LAN. `None` indicates this
    /// wasn't checked, and is unknown. Wire key `PMP`, not `Pmp`.
    #[serde(rename = "PMP")]
    pub pmp: Option<bool>,
    /// Indicates whether PCP is present on the Tailscale node's LAN. `None` indicates this wasn't
    /// checked, and is unknown. Wire key `PCP`, not `Pcp`.
    #[serde(rename = "PCP")]
    pub pcp: Option<bool>,
    /// The Tailscale node's preferred (home) DERP region ID. This is where the node expects to be
    /// contacted to begin a peer-to-peer connection.
    ///
    /// A Tailscale node might be temporarily connected to multiple DERP servers (to speak to
    /// Tailscale nodes located in different DERP regions); this field is the region ID that this
    /// node subscribes to traffic at. Zero means disconnected or unknown.
    ///
    /// Wire key `PreferredDERP` (Go's `DERP` acronym), not the `PascalCase` default `PreferredDerp`.
    #[serde(rename = "PreferredDERP")]
    #[serde(deserialize_with = "crate::util::derp_region_id")]
    pub preferred_derp: Option<RegionId>,
    /// The current type of physical link connecting the Tailscale node to the network; `None`
    /// indicates unknown.
    #[serde(borrow)]
    pub link_type: Option<LinkType<'a>>,
    /// The fastest recent time to reach various DERP STUN servers, in seconds. The map key is the
    /// "regionID-v4" or "-v6"; it was previously the DERP server's STUN host:port.
    ///
    /// This should only be updated rarely, or when there's a material change, as any change here
    /// also gets uploaded to the control plane.
    ///
    /// Wire key `DERPLatency` (Go's `DERP` acronym), not the `PascalCase` default `DerpLatency`.
    #[serde(rename = "DERPLatency")]
    pub derp_latency: Option<DerpLatencyMap<'a>>,
    /// Encodes both which firewall mode was selected and why, to help debug iptables-vs-nftables
    /// issues. The string is of the form "{nft,ift}-REASON", like "nft-forced" or "ipt-default".
    ///
    /// As of 2023-08-19, this field is Linux-specific. Empty means either this Tailscale node is
    /// not running on Linux, or indicates a configuration in which the host firewall rules are
    /// not managed by Tailscale.
    pub firewall_mode: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NetInfo acronym fields must serialize under Go `tailcfg.NetInfo`'s verbatim wire keys
    /// (`WorkingUDP`, `WorkingIPv6`, `OSHasIPv6`, `WorkingICMPv4`, `MappingVariesByDestIP`, `UPnP`,
    /// `PMP`, `PCP`, `PreferredDERP`, `DERPLatency`), NOT the `rename_all = "PascalCase"` default which
    /// lowercases the acronyms (`WorkingUdp`, `Upnp`, `PreferredDerp`, …) — keys a strict Go decoder
    /// drops. Regression guard for the per-field `#[serde(rename)]` overrides.
    #[test]
    fn netinfo_acronym_fields_use_go_wire_keys() {
        let ni = NetInfo {
            mapping_varies_by_dest_ip: Some(true),
            working_ipv6: Some(false),
            os_has_ipv6: Some(true),
            working_udp: Some(true),
            working_icmpv4: Some(false),
            upnp: Some(false),
            pmp: Some(false),
            pcp: Some(true),
            preferred_derp: Some(RegionId::from(core::num::NonZeroU32::new(1).unwrap())),
            ..Default::default()
        };
        let v = serde_json::to_value(&ni).unwrap();
        for key in [
            "MappingVariesByDestIP",
            "WorkingIPv6",
            "OSHasIPv6",
            "WorkingUDP",
            "WorkingICMPv4",
            "UPnP",
            "PMP",
            "PCP",
            "PreferredDERP",
        ] {
            assert!(v.get(key).is_some(), "missing Go wire key {key}");
        }
        // The PascalCase-mangled forms must be ABSENT (a regression would re-introduce them).
        for bad in [
            "MappingVariesByDestIp",
            "WorkingIpv6",
            "OsHasIpv6",
            "WorkingUdp",
            "WorkingIcmpv4",
            "Upnp",
            "Pmp",
            "Pcp",
            "PreferredDerp",
        ] {
            assert!(v.get(bad).is_none(), "mangled key {bad} must not appear");
        }

        // Decode side: control SENDS Go's keys, so we must read them back (rename governs both).
        let json =
            r#"{"WorkingUDP":true,"UPnP":false,"PreferredDERP":3,"MappingVariesByDestIP":true}"#;
        let back: NetInfo = serde_json::from_str(json).unwrap();
        assert_eq!(back.working_udp, Some(true));
        assert_eq!(back.upnp, Some(false));
        assert_eq!(back.mapping_varies_by_dest_ip, Some(true));
        assert_eq!(
            back.preferred_derp,
            Some(RegionId::from(core::num::NonZeroU32::new(3).unwrap()))
        );
    }
}
