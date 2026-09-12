//! Wire types for Tailscale **VIP services** (`svc:` services with control-assigned virtual IPs).
//!
//! Distinct from [`Service`][crate::Service] (the legacy `HostInfo.Services` peerAPI advertisement).
//! A VIP service is named `svc:<dns-label>` and is assigned one or more virtual IPs by control; the
//! node that *hosts* the service learns those IPs from the `service-host`
//! ([`NODE_ATTR_SERVICE_HOST`]) node-capability value, which carries a [`ServiceIpMappings`] map.
//! These same VIP IPs are also injected into the node's `AllowedIPs`.
//!
//! Mirrors `tailcfg`'s `ServiceName`, `VIPService`, `ProtoPortRange`, `ServiceIPMappings`,
//! `ServiceDetails`, `ServiceAction` and `ServiceActionType`.

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::net::IpAddr;

use serde::{Deserialize, Serialize};

/// The node-capability key by which control tells a node which VIP service IPs it hosts
/// (`tailcfg.NodeAttrServiceHost`). Possession of this cap (with a non-empty mapping) is the grant
/// to host VIP services. The cap's value deserializes as [`ServiceIpMappings`].
pub const NODE_ATTR_SERVICE_HOST: &str = "service-host";

/// The node-capability key marking a peer as eligible to be *suggested* as an exit node
/// (`tailcfg.NodeAttrSuggestExitNode`). Control sets it on the exit-node candidates a client may
/// auto-pick from; the exit-node suggestion algorithm (`Device::suggest_exit_node`) requires this
/// cap in a peer's `CapMap` for the peer to be a candidate. The cap's value is empty (the key's
/// presence is the whole signal), so unlike [`NODE_ATTR_SERVICE_HOST`] it carries no payload to
/// deserialize — consumers check key presence via `Node::has_node_attr`.
pub const NODE_ATTR_SUGGEST_EXIT_NODE: &str = "suggest-exit-node";

/// The `svc:` prefix every [`ServiceName`] carries (`tailcfg` `serviceNamePrefix`).
pub const SERVICE_NAME_PREFIX: &str = "svc:";

/// A Tailscale VIP service name of the form `svc:<dns-label>` (`tailcfg.ServiceName`).
///
/// Stored verbatim as it appears on the wire (including the `svc:` prefix). Validation of the
/// `svc:`-prefix + DNS-label shape is performed by the consumer (see the domain layer), not here —
/// this is a transparent wire newtype.
#[derive(Default, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct ServiceName<'a>(#[serde(borrow)] pub &'a str);

/// A protocol + inclusive port range (`tailcfg.ProtoPortRange`). `proto == 0` means "all protocols"
/// in Go (`int(0)`); otherwise it is an IP protocol number (6 = TCP, 17 = UDP). A `first..=last`
/// span of `0..=65535` means "all ports".
///
/// **Wire form is a STRING, not a JSON object.** Go's `tailcfg.ProtoPortRange` implements
/// `encoding.TextMarshaler`/`TextUnmarshaler` (`tailcfg/proto_port_range.go`), so it serializes as
/// `"[<proto>:]<ports>"` (e.g. `"tcp:443"`, `"udp:1-100"`, `"443"`, `"*"`), NOT
/// `{"Proto":6,"First":443,"Last":443}`. We hand-roll the same text codec below so a real
/// `tailscale serve`/VIP-service `ServiceConfig` round-trips; emitting the object form was
/// wire-incompatible with a genuine control plane. The `<proto>` token uses Go `ipproto`'s
/// `preferredNames` (tcp/udp/icmp/igmp/sctp/dccp/gre/ah/esp/egp/igp/ipv4/ipv6-icmp) or a decimal
/// number; `<ports>` is `first` when `first == last`, `*` for the full `0..=65535` span, else
/// `first-last`.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct ProtoPortRange {
    /// IP protocol number (`Proto` in Go). `0` = all protocols.
    pub proto: u8,
    /// Inclusive first port (`Ports.First`).
    pub first: u16,
    /// Inclusive last port (`Ports.Last`).
    pub last: u16,
}

/// Go `ipproto.preferredNames` — the protocol-number → name table `ipproto.Proto.MarshalText` uses
/// (and `UnmarshalText` accepts, case-insensitively). Mirrored exactly so our `<proto>` token matches
/// Go's wire bytes. Numbers not in this table marshal as their decimal value.
const PROTO_NAMES: &[(u8, &str)] = &[
    (51, "ah"),
    (33, "dccp"),
    (8, "egp"),
    (50, "esp"),
    (47, "gre"),
    (1, "icmp"),
    (2, "igmp"),
    (9, "igp"),
    (4, "ipv4"),
    (58, "ipv6-icmp"),
    (132, "sctp"),
    (6, "tcp"),
    (17, "udp"),
];

impl ProtoPortRange {
    /// The full `0..=65535` "all ports" span (Go `PortRangeAny`).
    fn ports_is_any(&self) -> bool {
        self.first == 0 && self.last == 65535
    }
}

impl core::fmt::Display for ProtoPortRange {
    /// Mirrors Go `ProtoPortRange.String()`: `"*"` for all-protocols+all-ports; otherwise
    /// `[<proto>:]<ports>` where the proto token is present only when `proto != 0`.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.proto == 0 && self.ports_is_any() {
            return f.write_str("*");
        }
        if self.proto != 0 {
            match PROTO_NAMES.iter().find(|(n, _)| *n == self.proto) {
                Some((_, name)) => write!(f, "{name}:")?,
                None => write!(f, "{}:", self.proto)?,
            }
        }
        // Ports (Go `PortRange.String`): single port, `*` for the any span, else `first-last`.
        if self.ports_is_any() {
            f.write_str("*")
        } else if self.first == self.last {
            write!(f, "{}", self.first)
        } else {
            write!(f, "{}-{}", self.first, self.last)
        }
    }
}

impl core::str::FromStr for ProtoPortRange {
    type Err = alloc::string::String;

    /// Parse Go's text form `[<proto>:]<ports>` (the inverse of the [`Display`](core::fmt::Display)
    /// impl). `<proto>` is a `preferredNames` name (case-insensitive) or a decimal `u8`; absent means
    /// proto 0. `<ports>` is `*` (the any span), a single port, or `low-high`.
    ///
    /// Proto names are resolved against `PROTO_NAMES` (Go's `ipproto.preferredNames`, the *marshal*
    /// set). Go's `ipproto.UnmarshalText` accepts a slightly larger `acceptedNames` alias set
    /// (`icmpv4`, `icmpv6`, `ip-in-ip`, `tsmp`) that we deliberately do NOT — a real control plane
    /// only ever *emits* the `preferredNames` form (`icmp`/`ipv6-icmp`/`ipv4`/the decimal), so the
    /// aliases appear only in hand-authored configs, never on control traffic. Decimal numbers and
    /// `*` are accepted exactly as Go does.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(String::from("empty ProtoPortRange"));
        }
        // Bare "*" = all protocols + all ports.
        if s == "*" {
            return Ok(ProtoPortRange {
                proto: 0,
                first: 0,
                last: 65535,
            });
        }
        let (proto, ports) = match s.split_once(':') {
            Some((p, ports)) => {
                let lower = p.to_ascii_lowercase();
                let proto = match PROTO_NAMES.iter().find(|(_, name)| *name == lower) {
                    Some((num, _)) => *num,
                    None => p
                        .parse::<u8>()
                        .map_err(|_| alloc::format!("invalid protocol {p:?}"))?,
                };
                (proto, ports)
            }
            None => (0, s),
        };
        let (first, last) = if ports == "*" {
            (0u16, 65535u16)
        } else if let Some((lo, hi)) = ports.split_once('-') {
            (
                lo.parse::<u16>()
                    .map_err(|_| alloc::format!("invalid first port {lo:?}"))?,
                hi.parse::<u16>()
                    .map_err(|_| alloc::format!("invalid last port {hi:?}"))?,
            )
        } else {
            let p = ports
                .parse::<u16>()
                .map_err(|_| alloc::format!("invalid port {ports:?}"))?;
            (p, p)
        };
        Ok(ProtoPortRange { proto, first, last })
    }
}

impl Serialize for ProtoPortRange {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // `collect_str` formats via `Display` without an intermediate `String` allocation.
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ProtoPortRange {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <&str>::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// A Tailscale VIP service definition as fetched from control (`tailcfg.VIPService`).
///
/// This is the *definition* of a service (name, advertised port ranges, active flag); the
/// host-assigned VIP IPs come separately via [`ServiceIpMappings`].
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
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

/// An **owned** VIP service definition, used when *advertising* the services this node hosts back
/// to control (the borrowed [`VipService`] is for the inbound control→node direction). Field-for-
/// field the same wire shape as [`VipService`] (`tailcfg.VIPService`), but owning its `name` so it
/// can be built from a [`crate`]-external `String` config without lifetime entanglement.
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct VipServiceOwned {
    /// The `svc:`-prefixed service name (owned).
    pub name: String,
    /// The protocol/port ranges this service is advertised on.
    #[serde(default)]
    pub ports: Vec<ProtoPortRange>,
    /// Whether the service is currently active.
    #[serde(default)]
    pub active: bool,
}

/// The body a node returns to control's c2n `GET /vip-services` request, listing the VIP services
/// this node currently hosts plus the hash that triggered the fetch (`tailcfg.C2NVIPServicesResponse`).
///
/// Control fetches this whenever the node's advertised `HostInfo.ServicesHash` changes; the
/// `services_hash` here echoes the same value (see the services-hash helper in `ts_control`).
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct C2NVIPServicesResponse {
    /// The VIP services this node hosts (`VIPServices` on the wire).
    #[serde(rename = "VIPServices", default)]
    pub vip_services: Vec<VipServiceOwned>,
    /// The opaque hash of the advertised service list (`ServicesHash` on the wire), matching the
    /// `HostInfo.ServicesHash` the node last sent.
    #[serde(rename = "ServicesHash", default)]
    pub services_hash: String,
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

/// The node-capability key **prefix** under which control describes the VIP services that are
/// *visible* (reachable) to this node (`tailcfg.NodeAttrPrefixServices`). Each `CapMap` key of the
/// form `services/<opaque-id>` carries one [`ServiceDetails`] value.
///
/// The suffix after the prefix is an opaque, server-chosen identifier: consumers must take the
/// canonical service name from [`ServiceDetails::name`] rather than parsing it out of the map key.
/// This is the *consume* counterpart to [`NODE_ATTR_SERVICE_HOST`], which tells a node which VIP
/// services it *hosts*.
pub const NODE_ATTR_PREFIX_SERVICES: &str = "services/";

/// The type of a [`ServiceAction`] (`tailcfg.ServiceActionType`): which protocol or application a
/// client should use when it invokes the action.
///
/// Well-known Tailscale types are plain slugs with no URL prefix (`"ssh"`, `"http"`, …) and are
/// listed in [`SERVICE_ACTION_TYPES`]. Where a type names an application-layer protocol with a
/// well-known port the slug generally follows the IANA service-name registry, except where the
/// commonly used protocol name differs (Go keeps `"rdp"` over IANA's `ms-wbt-server`, `"vnc"` over
/// `rfb`, `"mssql"` over `ms-sql-s`). Third-party types, if upstream ever adds any, must use URL
/// form (`"example.com/my-custom-type"`) so they cannot collide with the first-party slugs.
///
/// Deliberately a transparent string newtype rather than an enum: control may send a type this
/// build has never heard of, and Go's rule is that *clients should ignore actions with types they
/// do not recognize* — not that the netmap is malformed. Any slug therefore decodes; ask
/// [`ServiceActionType::is_known`] whether this build recognizes it.
#[derive(
    Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize,
)]
pub struct ServiceActionType<'a>(#[serde(borrow)] pub &'a str);

/// `tailcfg.ServiceActionTypeAWSS3`: the port is an AWS S3-compatible endpoint, so an AWS
/// configuration may be pointed at it and S3 clients used.
pub const SERVICE_ACTION_TYPE_AWS_S3: ServiceActionType<'static> = ServiceActionType("aws-s3");
/// `tailcfg.ServiceActionTypeCockroachDB`: the port is a CockroachDB server.
pub const SERVICE_ACTION_TYPE_COCKROACH_DB: ServiceActionType<'static> =
    ServiceActionType("cockroach");
/// `tailcfg.ServiceActionTypeElasticSearch`: the port is an Elasticsearch server.
pub const SERVICE_ACTION_TYPE_ELASTIC_SEARCH: ServiceActionType<'static> =
    ServiceActionType("elasticsearch");
/// `tailcfg.ServiceActionTypeHTTP`: the port is an HTTP server.
pub const SERVICE_ACTION_TYPE_HTTP: ServiceActionType<'static> = ServiceActionType("http");
/// `tailcfg.ServiceActionTypeKubernetes`: the port is a Kubernetes API server, so a Kubernetes
/// context may be pointed at the service and Kubernetes clients used.
pub const SERVICE_ACTION_TYPE_KUBERNETES: ServiceActionType<'static> =
    ServiceActionType("kubernetes");
/// `tailcfg.ServiceActionTypeMongoDB`: the port is a MongoDB server.
pub const SERVICE_ACTION_TYPE_MONGO_DB: ServiceActionType<'static> = ServiceActionType("mongodb");
/// `tailcfg.ServiceActionTypeMSSQL`: the port is a Microsoft SQL Server.
pub const SERVICE_ACTION_TYPE_MSSQL: ServiceActionType<'static> = ServiceActionType("mssql");
/// `tailcfg.ServiceActionTypeMySQL`: the port is a MySQL server.
pub const SERVICE_ACTION_TYPE_MYSQL: ServiceActionType<'static> = ServiceActionType("mysql");
/// `tailcfg.ServiceActionTypePostgreSQL`: the port is a PostgreSQL server.
pub const SERVICE_ACTION_TYPE_POSTGRESQL: ServiceActionType<'static> =
    ServiceActionType("postgresql");
/// `tailcfg.ServiceActionTypeRDP`: the port is an RDP server.
pub const SERVICE_ACTION_TYPE_RDP: ServiceActionType<'static> = ServiceActionType("rdp");
/// `tailcfg.ServiceActionTypeVNC`: the port is a VNC server.
pub const SERVICE_ACTION_TYPE_VNC: ServiceActionType<'static> = ServiceActionType("vnc");
/// `tailcfg.ServiceActionTypeSSH`: the port is an SSH server.
pub const SERVICE_ACTION_TYPE_SSH: ServiceActionType<'static> = ServiceActionType("ssh");
/// `tailcfg.ServiceActionTypeTCP`: the port is a generic TCP server.
pub const SERVICE_ACTION_TYPE_TCP: ServiceActionType<'static> = ServiceActionType("tcp");

/// Every [`ServiceActionType`] this build recognizes, in the order Go's
/// `ServiceActionType.Valid()` switch lists them. Backs [`ServiceActionType::is_known`] and is
/// public so a consumer can enumerate what it may be asked to handle.
pub const SERVICE_ACTION_TYPES: &[ServiceActionType<'static>] = &[
    SERVICE_ACTION_TYPE_AWS_S3,
    SERVICE_ACTION_TYPE_COCKROACH_DB,
    SERVICE_ACTION_TYPE_ELASTIC_SEARCH,
    SERVICE_ACTION_TYPE_HTTP,
    SERVICE_ACTION_TYPE_KUBERNETES,
    SERVICE_ACTION_TYPE_MONGO_DB,
    SERVICE_ACTION_TYPE_MSSQL,
    SERVICE_ACTION_TYPE_MYSQL,
    SERVICE_ACTION_TYPE_POSTGRESQL,
    SERVICE_ACTION_TYPE_RDP,
    SERVICE_ACTION_TYPE_VNC,
    SERVICE_ACTION_TYPE_SSH,
    SERVICE_ACTION_TYPE_TCP,
];

impl ServiceActionType<'_> {
    /// Whether this is one of the [`SERVICE_ACTION_TYPES`] slugs (Go `ServiceActionType.Valid`).
    ///
    /// A `false` here is *not* a decode error — it is the signal to ignore this one action and
    /// keep the rest of the service (and the netmap) intact.
    pub fn is_known(&self) -> bool {
        SERVICE_ACTION_TYPES.iter().any(|known| known.0 == self.0)
    }
}

/// `tailcfg.ServiceActionAttributeWebClientURL`: a browser-based client for the action is available
/// at this URL. The value is a JSON string holding an `http(s)` URL.
pub const SERVICE_ACTION_ATTRIBUTE_WEB_CLIENT_URL: &str = "tailscale.com/cap/web-client-url";
/// `tailcfg.ServiceActionAttributeResourceName`: the named resource should be selected when the
/// client opens the application for this action — a database name, for PostgreSQL. The value is a
/// JSON string.
pub const SERVICE_ACTION_ATTRIBUTE_RESOURCE_NAME: &str = "tailscale.com/cap/resource-name";
/// `tailcfg.ServiceActionAttributeSkipUsername`: no username is required, typically because an
/// application-layer proxy injects credentials on the user's behalf, so a username prompt should be
/// skipped. The value is a JSON boolean.
pub const SERVICE_ACTION_ATTRIBUTE_SKIP_USERNAME: &str = "tailscale.com/cap/skip-username";

/// An action a Tailscale client can invoke against a [`ServiceDetails`] (`tailcfg.ServiceAction`).
///
/// Decode-only: this fork *consumes* what control publishes about services it can reach and never
/// advertises actions of its own, so there is no `Serialize` impl to emit a shape upstream would
/// have to accept.
#[derive(Default, Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ServiceAction<'a> {
    /// The action's type slug (`Type` on the wire). Renamed because `type` is a Rust keyword.
    /// May be a slug this build does not know — see [`ServiceActionType`].
    #[serde(rename = "Type", borrow, default)]
    pub action_type: ServiceActionType<'a>,
    /// The target TCP port. Control guarantees it matches one of the concrete (non-range) TCP
    /// ports in the enclosing [`ServiceDetails::ports`]; nothing here re-checks that, because a
    /// mismatch is control's bug and dropping the action would lose information the consumer may
    /// want to log.
    #[serde(default)]
    pub port: u16,
    /// An optional human-readable label, shown when a client offers several actions to pick from.
    /// Empty means "infer one from [`ServiceAction::action_type`]".
    #[serde(borrow, default)]
    pub display_name: &'a str,
    /// Optional extra metadata, keyed by attribute name (the
    /// `SERVICE_ACTION_ATTRIBUTE_*` constants). Which attributes apply depends on
    /// [`ServiceAction::action_type`].
    ///
    /// Values stay as raw JSON (Go's `tailcfg.RawMessage`) because each attribute has its own
    /// schema — a string for a URL, a boolean for skip-username — and an unrecognized attribute
    /// must be ignorable rather than fatal.
    #[serde(borrow, default)]
    pub attributes: BTreeMap<&'a str, &'a serde_json::value::RawValue>,
}

/// A VIP service that is *visible* to this node, as published by control under a
/// [`NODE_ATTR_PREFIX_SERVICES`] capability key (`tailcfg.ServiceDetails`).
///
/// Distinct from [`VipService`], which is the *hosting* side of the model (what a node offers, and
/// what it sends back on c2n `GET /vip-services`). `ServiceDetails` is the consuming side: name,
/// label, the VIPs to dial, the ports the service accepts, and the client application actions
/// available on those ports.
///
/// Decode-only, for the same reason as [`ServiceAction`].
#[derive(Default, Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ServiceDetails<'a> {
    /// The `svc:`-prefixed service name. This, not the capability-map key, is the canonical name.
    #[serde(borrow)]
    pub name: ServiceName<'a>,
    /// An optional human-readable label. Empty means clients fall back to
    /// [`ServiceDetails::name`].
    #[serde(borrow, default)]
    pub display_name: &'a str,
    /// The IPv4 and IPv6 addresses assigned to this service — the addresses a client dials.
    #[serde(default)]
    pub addrs: Vec<IpAddr>,
    /// The protocol/port combinations the service accepts.
    #[serde(default)]
    pub ports: Vec<ProtoPortRange>,
    /// How a client may interact with the service. Several actions may name the same port, and not
    /// every port needs one; when this is empty a client may infer default interactions from
    /// [`ServiceDetails::ports`].
    #[serde(borrow, default)]
    pub actions: Vec<ServiceAction<'a>>,
}

impl<'a> ServiceDetails<'a> {
    /// The actions whose type this build recognizes, in wire order.
    ///
    /// The upstream contract is that a client ignores actions it does not understand, so this is
    /// the accessor a consumer that is about to *act* should use; iterate
    /// [`ServiceDetails::actions`] directly to see everything control sent, unknown slugs included.
    pub fn known_actions(&self) -> impl Iterator<Item = &ServiceAction<'a>> {
        self.actions.iter().filter(|a| a.action_type.is_known())
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
        // Ports are Go TextMarshaler STRINGS ("tcp:445"), not objects.
        let wire = r#"{
            "Name": "svc:samba",
            "Ports": ["tcp:445"],
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

    #[test]
    fn c2n_vip_services_response_serializes_pascalcase() {
        use alloc::string::ToString;

        let resp = C2NVIPServicesResponse {
            vip_services: alloc::vec![VipServiceOwned {
                name: "svc:samba".to_string(),
                ports: alloc::vec![ProtoPortRange {
                    proto: 6,
                    first: 445,
                    last: 445,
                }],
                active: true,
            }],
            services_hash: "abc123".to_string(),
        };

        let value: serde_json::Value = serde_json::to_value(&resp).unwrap();
        // PascalCase wire names, including the all-caps `VIPServices`.
        let svc = &value["VIPServices"][0];
        assert_eq!(svc["Name"], "svc:samba");
        // Ports serialize as Go TextMarshaler STRINGS ("tcp:445"), not objects.
        assert_eq!(svc["Ports"][0], "tcp:445");
        assert_eq!(svc["Active"], true);
        assert_eq!(value["ServicesHash"], "abc123");
    }

    #[test]
    fn vip_service_round_trips_serialize() {
        let svc = VipService {
            name: ServiceName("svc:web"),
            ports: alloc::vec![ProtoPortRange {
                proto: 0,
                first: 0,
                last: 65535,
            }],
            active: true,
        };
        let json = serde_json::to_string(&svc).unwrap();
        let back: VipService = serde_json::from_str(&json).unwrap();
        assert_eq!(svc, back);
    }

    /// ProtoPortRange serializes to Go's exact TextMarshaler form, and parses it back. Each KAT is the
    /// string a real Go `tailcfg.ProtoPortRange` emits for the given (proto, first, last).
    #[test]
    fn proto_port_range_text_form_matches_go() {
        use core::str::FromStr;
        let cases: &[(ProtoPortRange, &str)] = &[
            // all protocols + all ports => "*"
            (ppr(0, 0, 65535), "*"),
            // tcp single port
            (ppr(6, 443, 443), "tcp:443"),
            // udp range
            (ppr(17, 1, 100), "udp:1-100"),
            // proto 0 (any) with a single port => bare port
            (ppr(0, 53, 53), "53"),
            // proto 0 with a range
            (ppr(0, 80, 90), "80-90"),
            // a named proto with the all-ports span => "<proto>:*"
            (ppr(6, 0, 65535), "tcp:*"),
            // a proto number with NO preferred name => decimal
            (ppr(99, 1, 1), "99:1"),
            // icmp / sctp names
            (ppr(1, 8, 8), "icmp:8"),
            (ppr(132, 9, 9), "sctp:9"),
        ];
        for (range, text) in cases {
            // Serialize: the JSON value is exactly the text string.
            let v = serde_json::to_value(range).unwrap();
            assert_eq!(
                v,
                serde_json::Value::String((*text).into()),
                "serialize {range:?}"
            );
            // Display matches too.
            assert_eq!(alloc::format!("{range}"), *text);
            // Parse round-trips back to the same struct.
            assert_eq!(
                ProtoPortRange::from_str(text).unwrap(),
                *range,
                "parse {text:?}"
            );
            // Full serde round-trip.
            let json = serde_json::to_string(range).unwrap();
            let back: ProtoPortRange = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, range);
        }
    }

    /// Case-insensitive proto names + the `*` wildcard parse (Go `UnmarshalText` accepts these).
    #[test]
    fn proto_port_range_parse_accepts_case_and_wildcards() {
        use core::str::FromStr;
        assert_eq!(
            ProtoPortRange::from_str("TCP:443").unwrap(),
            ppr(6, 443, 443)
        );
        assert_eq!(
            ProtoPortRange::from_str("Udp:*").unwrap(),
            ppr(17, 0, 65535)
        );
        assert_eq!(ProtoPortRange::from_str("*").unwrap(), ppr(0, 0, 65535));
        // A bare proto-number prefix.
        assert_eq!(ProtoPortRange::from_str("6:443").unwrap(), ppr(6, 443, 443));
        // Malformed inputs are rejected, not panicked.
        assert!(ProtoPortRange::from_str("").is_err());
        assert!(ProtoPortRange::from_str("tcp:nope").is_err());
        assert!(ProtoPortRange::from_str("999999:1").is_err()); // proto > u8
    }

    /// The exact JSON a Go `tailcfg.ServiceDetails` marshals to, decoded field for field.
    /// `DisplayName`/`Actions` are `json:",omitzero"` and `Addrs`/`Ports` are `json:",omitempty"`
    /// upstream, so every one of them is optional on the wire and defaulted here.
    #[test]
    fn service_details_parses_go_shape() {
        let wire = r#"{
            "Name": "svc:postgres",
            "DisplayName": "Analytics DB",
            "Addrs": ["100.65.32.7", "fd7a:115c:a1e0::7"],
            "Ports": ["tcp:5432", "tcp:22"],
            "Actions": [
                {
                    "Type": "postgresql",
                    "Port": 5432,
                    "DisplayName": "Open in psql",
                    "Attributes": {
                        "tailscale.com/cap/resource-name": "metrics",
                        "tailscale.com/cap/skip-username": true,
                        "tailscale.com/cap/web-client-url": "https://pg.example.com/"
                    }
                },
                { "Type": "ssh", "Port": 22 }
            ]
        }"#;
        let details: ServiceDetails = serde_json::from_str(wire).unwrap();

        assert_eq!(details.name, ServiceName("svc:postgres"));
        assert_eq!(details.display_name, "Analytics DB");
        assert_eq!(
            details.addrs,
            alloc::vec![
                "100.65.32.7".parse::<IpAddr>().unwrap(),
                "fd7a:115c:a1e0::7".parse::<IpAddr>().unwrap()
            ]
        );
        assert_eq!(
            details.ports,
            alloc::vec![ppr(6, 5432, 5432), ppr(6, 22, 22)]
        );

        assert_eq!(details.actions.len(), 2);
        let pg = &details.actions[0];
        assert_eq!(pg.action_type, SERVICE_ACTION_TYPE_POSTGRESQL);
        assert_eq!(pg.port, 5432);
        assert_eq!(pg.display_name, "Open in psql");
        // Attribute values stay raw JSON, so each attribute's own schema decodes separately.
        assert_eq!(
            pg.attributes[SERVICE_ACTION_ATTRIBUTE_RESOURCE_NAME].get(),
            r#""metrics""#
        );
        assert_eq!(
            pg.attributes[SERVICE_ACTION_ATTRIBUTE_SKIP_USERNAME].get(),
            "true"
        );
        assert_eq!(
            serde_json::from_str::<&str>(
                pg.attributes[SERVICE_ACTION_ATTRIBUTE_WEB_CLIENT_URL].get()
            )
            .unwrap(),
            "https://pg.example.com/"
        );

        let ssh = &details.actions[1];
        assert_eq!(ssh.action_type, SERVICE_ACTION_TYPE_SSH);
        assert_eq!(ssh.port, 22);
        // `omitzero` fields absent on the wire default rather than fail.
        assert_eq!(ssh.display_name, "");
        assert!(ssh.attributes.is_empty());
    }

    /// The whole point of the consume side: control may publish an action type (or an attribute)
    /// this build has never heard of, and Go's contract is that clients ignore those — not that the
    /// service, and with it the netmap carrying it, fails to decode.
    #[test]
    fn unknown_action_type_and_attribute_are_tolerated() {
        let wire = r#"{
            "Name": "svc:mixed",
            "Ports": ["tcp:9000", "tcp:22"],
            "Actions": [
                { "Type": "ftp", "Port": 9000, "DisplayName": "Some future thing" },
                {
                    "Type": "ssh",
                    "Port": 22,
                    "Attributes": { "example.com/cap/not-yet-invented": {"a": 1} }
                }
            ],
            "SomeFieldFromALaterControlPlane": 3
        }"#;
        let details: ServiceDetails = serde_json::from_str(wire).unwrap();

        // Both actions decoded; the unrecognized one is present but flagged.
        assert_eq!(details.actions.len(), 2);
        assert_eq!(details.actions[0].action_type, ServiceActionType("ftp"));
        assert!(!details.actions[0].action_type.is_known());
        assert_eq!(details.actions[0].display_name, "Some future thing");
        assert!(details.actions[1].action_type.is_known());

        // An unknown attribute rides along as raw JSON instead of failing the action.
        assert_eq!(
            details.actions[1].attributes["example.com/cap/not-yet-invented"].get(),
            r#"{"a": 1}"#
        );

        // `known_actions` is what a consumer that is about to act should walk.
        let known: Vec<_> = details.known_actions().collect();
        assert_eq!(known.len(), 1);
        assert_eq!(known[0].action_type, SERVICE_ACTION_TYPE_SSH);
    }

    /// Mirrors Go's `TestServiceActionTypeValid`, including its two negative cases.
    #[test]
    fn service_action_type_known_set_matches_go() {
        let known: Vec<&str> = SERVICE_ACTION_TYPES.iter().map(|t| t.0).collect();
        assert_eq!(
            known,
            alloc::vec![
                "aws-s3",
                "cockroach",
                "elasticsearch",
                "http",
                "kubernetes",
                "mongodb",
                "mssql",
                "mysql",
                "postgresql",
                "rdp",
                "vnc",
                "ssh",
                "tcp",
            ]
        );
        for t in SERVICE_ACTION_TYPES {
            assert!(t.is_known(), "{t:?}");
        }
        assert!(!ServiceActionType("ftp").is_known());
        assert!(!ServiceActionType("").is_known());
        // Slugs are exact: no case folding, no URL prefix.
        assert!(!ServiceActionType("SSH").is_known());
        assert!(!ServiceActionType("tailscale.com/cap/ssh").is_known());
    }

    /// A service with no actions at all is the pre-actions shape a current control plane still
    /// sends, and it must keep decoding.
    #[test]
    fn service_details_without_actions_parses() {
        let details: ServiceDetails =
            serde_json::from_str(r#"{"Name":"svc:samba","Addrs":["100.65.32.1"]}"#).unwrap();
        assert_eq!(details.name, ServiceName("svc:samba"));
        assert!(details.actions.is_empty());
        assert!(details.ports.is_empty());
        assert_eq!(details.display_name, "");
        assert_eq!(details.known_actions().count(), 0);
    }

    fn ppr(proto: u8, first: u16, last: u16) -> ProtoPortRange {
        ProtoPortRange { proto, first, last }
    }
}
