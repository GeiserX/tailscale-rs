//! Wire types for Tailscale **VIP services** (`svc:` services with control-assigned virtual IPs).
//!
//! Distinct from [`Service`][crate::Service] (the legacy `HostInfo.Services` peerAPI advertisement).
//! A VIP service is named `svc:<dns-label>` and is assigned one or more virtual IPs by control; the
//! node that *hosts* the service learns those IPs from the `service-host`
//! ([`NODE_ATTR_SERVICE_HOST`]) node-capability value, which carries a [`ServiceIpMappings`] map.
//! These same VIP IPs are also injected into the node's `AllowedIPs`.
//!
//! Mirrors `tailcfg`'s `ServiceName`, `VIPService`, `ProtoPortRange`, and `ServiceIPMappings`.

use alloc::{collections::BTreeMap, vec::Vec};
use core::net::IpAddr;

use serde::Deserialize;

/// The node-capability key by which control tells a node which VIP service IPs it hosts
/// (`tailcfg.NodeAttrServiceHost`). Possession of this cap (with a non-empty mapping) is the grant
/// to host VIP services. The cap's value deserializes as [`ServiceIpMappings`].
pub const NODE_ATTR_SERVICE_HOST: &str = "service-host";

/// The `svc:` prefix every [`ServiceName`] carries (`tailcfg` `serviceNamePrefix`).
pub const SERVICE_NAME_PREFIX: &str = "svc:";

/// A Tailscale VIP service name of the form `svc:<dns-label>` (`tailcfg.ServiceName`).
///
/// Stored verbatim as it appears on the wire (including the `svc:` prefix). Validation of the
/// `svc:`-prefix + DNS-label shape is performed by the consumer (see the domain layer), not here —
/// this is a transparent wire newtype.
#[derive(Default, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
pub struct ServiceName<'a>(#[serde(borrow)] pub &'a str);

/// A protocol + inclusive port range (`tailcfg.ProtoPortRange`). `proto == 0` means "all protocols"
/// in Go (`int(0)`); otherwise it is an IP protocol number (6 = TCP, 17 = UDP). A `first..=last`
/// span of `0..=65535` means "all ports".
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ProtoPortRange {
    /// IP protocol number (`Proto` in Go). `0` = all protocols.
    #[serde(default)]
    pub proto: u8,
    /// Inclusive first port (`Ports.First`).
    #[serde(default)]
    pub first: u16,
    /// Inclusive last port (`Ports.Last`).
    #[serde(default)]
    pub last: u16,
}

/// A Tailscale VIP service definition as fetched from control (`tailcfg.VIPService`).
///
/// This is the *definition* of a service (name, advertised port ranges, active flag); the
/// host-assigned VIP IPs come separately via [`ServiceIpMappings`].
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct VipService<'a> {
    /// The `svc:`-prefixed service name.
    #[serde(borrow)]
    pub name: ServiceName<'a>,
    /// The protocol/port ranges this service is advertised on.
    #[serde(default)]
    pub ports: Vec<ProtoPortRange>,
    /// Whether the service is currently active.
    #[serde(default)]
    pub active: bool,
}

/// The value of the `service-host` ([`NODE_ATTR_SERVICE_HOST`]) node-capability: a map from VIP
/// [`ServiceName`] to the virtual IP addresses control has assigned that service on this host
/// (`tailcfg.ServiceIPMappings`). The host binds/answers for these IPs.
///
/// Example wire value (a single JSON object inside the cap's value array):
/// ```json
/// { "svc:samba": ["100.65.32.1", "fd7a:115c:a1e0::1234"] }
/// ```
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ServiceIpMappings<'a>(#[serde(borrow)] pub BTreeMap<&'a str, Vec<IpAddr>>);

impl<'a> ServiceIpMappings<'a> {
    /// All VIP IPs assigned to `service` (matched verbatim incl. the `svc:` prefix), or an empty
    /// slice if the service is not present.
    pub fn addrs_for(&self, service: &str) -> &[IpAddr] {
        self.0.get(service).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Every VIP IP across all hosted services (deduplication is the caller's concern).
    pub fn all_addrs(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.0.values().flatten().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_ip_mappings_parse_and_lookup() {
        let wire = r#"{
            "svc:samba": ["100.65.32.1", "fd7a:115c:a1e0::1234"],
            "svc:web": ["100.65.32.2"]
        }"#;
        let m: ServiceIpMappings = serde_json::from_str(wire).unwrap();

        assert_eq!(
            m.addrs_for("svc:samba"),
            &[
                "100.65.32.1".parse::<IpAddr>().unwrap(),
                "fd7a:115c:a1e0::1234".parse::<IpAddr>().unwrap()
            ]
        );
        assert_eq!(
            m.addrs_for("svc:web"),
            &["100.65.32.2".parse::<IpAddr>().unwrap()]
        );
        assert!(m.addrs_for("svc:absent").is_empty());
        assert_eq!(m.all_addrs().count(), 3);
    }

    #[test]
    fn vip_service_parses() {
        let wire = r#"{
            "Name": "svc:samba",
            "Ports": [{ "Proto": 6, "First": 445, "Last": 445 }],
            "Active": true
        }"#;
        let svc: VipService = serde_json::from_str(wire).unwrap();
        assert_eq!(svc.name, ServiceName("svc:samba"));
        assert_eq!(svc.ports.len(), 1);
        assert_eq!(svc.ports[0].proto, 6);
        assert_eq!(svc.ports[0].first, 445);
        assert_eq!(svc.ports[0].last, 445);
        assert!(svc.active);
    }

    #[test]
    fn empty_mappings_parse() {
        let m: ServiceIpMappings = serde_json::from_str("{}").unwrap();
        assert_eq!(m.all_addrs().count(), 0);
    }
}
