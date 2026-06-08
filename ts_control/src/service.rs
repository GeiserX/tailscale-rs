//! Tailscale VIP-service hosting (`tsnet`'s `ListenService`).
//!
//! A node hosts a **VIP service** (`svc:<label>`) by binding a listener on the virtual IP
//! address(es) control assigned that service. This module provides the fail-closed gating that
//! decides *whether* and *on which address* a node may listen for a service, mirroring Go's
//! `tsnet.Server.ListenService` preconditions:
//!
//! 1. the service name must be a valid `svc:<dns-label>` ([`crate::validate_service_name`]);
//! 2. the host must be **tagged** (Go `ErrUntaggedServiceHost`) — an untagged node cannot host
//!    services;
//! 3. control must have assigned the service a VIP address on this node (delivered via the
//!    `service-host` node-capability, parsed into [`Node::service_addresses`]).
//!
//! When all hold, [`resolve_service_listen`] returns the [`core::net::SocketAddr`] the embedder
//! should bind via `Device::tcp_listen` on the overlay netstack. Otherwise it returns a typed
//! [`ServiceError`] and the node serves nothing — never a host socket, never an unbound listen.
//!
//! The L3/`Tun` service mode (Go `ServiceConfig.Tun`) is intentionally unsupported: it is a TODO in
//! upstream tsnet and the fork's default data path is the userspace netstack.

use crate::node::Node;

/// How a VIP service terminates incoming connections (a scoped mirror of tsnet's `ServiceMode`).
///
/// Both modes bind a TCP listener on the service VIP; the distinction is what terminates the
/// stream. L3/`Tun` forwarding (Go `ServiceConfig.Tun`) is deliberately omitted — see the module
/// docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceMode {
    /// Raw TCP on `port`: the embedder is handed the accepted overlay stream (like tsnet's
    /// `ServiceModeTCP`).
    Tcp {
        /// The service port to listen on.
        port: u16,
    },
    /// HTTP(S) on `port`: the embedder serves an HTTP handler over the accepted stream (like
    /// tsnet's `ServiceModeHTTP`). The fork treats this identically to [`ServiceMode::Tcp`] at the
    /// listen layer — it binds the same VIP:port and hands back the stream; TLS termination /
    /// HTTP handling is the embedder's concern.
    Http {
        /// The service port to listen on.
        port: u16,
    },
}

impl ServiceMode {
    /// The TCP port this mode listens on.
    pub fn port(&self) -> u16 {
        match self {
            ServiceMode::Tcp { port } | ServiceMode::Http { port } => *port,
        }
    }
}

/// Why a VIP-service listen request was refused. Fail-closed by construction: there is no variant
/// that yields a usable listen address without a genuine control-assigned VIP on a tagged host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceError {
    /// The service name is not a valid `svc:<dns-label>` (Go `ServiceName.Validate`).
    InvalidName(String),
    /// The node is not tagged, so it cannot host VIP services (Go `ErrUntaggedServiceHost`).
    UntaggedHost,
    /// Control has not assigned this node a VIP address for the service (no `service-host` cap
    /// entry, or none covering this service). The node serves nothing rather than binding an
    /// arbitrary address — fail-closed.
    NoAssignedVip(String),
    /// Binding the overlay listener on the resolved VIP failed (e.g. the netstack is unavailable,
    /// as in TUN transport mode, or the address is already in use). Carries a human-readable detail.
    Listen(String),
}

impl core::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ServiceError::InvalidName(name) => {
                write!(
                    f,
                    "invalid VIP service name {name:?} (expected svc:<dns-label>)"
                )
            }
            ServiceError::UntaggedHost => write!(
                f,
                "this node is untagged and cannot host a Tailscale service (it must be tagged)"
            ),
            ServiceError::NoAssignedVip(name) => write!(
                f,
                "control has not assigned a VIP address for service {name:?} on this node"
            ),
            ServiceError::Listen(detail) => {
                write!(f, "failed to bind the VIP service listener: {detail}")
            }
        }
    }
}

impl std::error::Error for ServiceError {}

/// Resolve the overlay [`core::net::SocketAddr`] a node should bind to host VIP service `name` in
/// `mode`, enforcing the three fail-closed preconditions (valid name, tagged host, control-assigned
/// VIP). See the module docs.
///
/// Picks the first hosted VIP whose IP family the netstack can serve: an IPv6 VIP is only chosen
/// when `enable_ipv6` is set (the fork is IPv4-only by default), preferring an IPv4 VIP otherwise.
pub fn resolve_service_listen(
    node: &Node,
    name: &str,
    mode: ServiceMode,
    enable_ipv6: bool,
) -> Result<core::net::SocketAddr, ServiceError> {
    if crate::validate_service_name(name).is_none() {
        return Err(ServiceError::InvalidName(name.to_string()));
    }

    // Go refuses to host a service from an untagged node (ErrUntaggedServiceHost).
    if node.tags.is_empty() {
        return Err(ServiceError::UntaggedHost);
    }

    // Pick a VIP assigned to *this specific service* that the netstack can actually serve. Prefer
    // IPv4; only use an IPv6 VIP when IPv6 is enabled on the overlay (matching the netstack's
    // accepted-address set). Using the per-service mapping (not the flattened host set) ensures a
    // multi-service co-host binds the correct VIP for `name`.
    let vips = node.service_addresses_for(name);
    let vip = vips
        .iter()
        .find(|ip| ip.is_ipv4())
        .or_else(|| vips.iter().find(|ip| enable_ipv6 && ip.is_ipv6()))
        .ok_or_else(|| ServiceError::NoAssignedVip(name.to_string()))?;

    Ok(core::net::SocketAddr::new(*vip, mode.port()))
}

#[cfg(test)]
mod tests {
    use alloc::{collections::BTreeMap, string::ToString, vec, vec::Vec};
    use core::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::node::{NodeCapMap, StableId, TailnetAddress};

    /// Build a node hosting `service` on `vips` (when both are non-empty), tagged with `tags`.
    fn node(tags: &[&str], service: &str, vips: Vec<IpAddr>) -> Node {
        node_multi(tags, &[(service, vips)])
    }

    /// Build a node hosting several `(service, vips)` mappings.
    fn node_multi(tags: &[&str], services: &[(&str, Vec<IpAddr>)]) -> Node {
        let mut cap_map = NodeCapMap::new();
        let mut service_vips: BTreeMap<String, Vec<IpAddr>> = BTreeMap::new();
        for (service, vips) in services {
            if !service.is_empty() && !vips.is_empty() {
                service_vips.insert((*service).to_string(), vips.clone());
            }
        }
        if !service_vips.is_empty() {
            cap_map.insert(ts_control_serde::NODE_ATTR_SERVICE_HOST.to_string(), vec![]);
        }
        Node {
            id: 1,
            stable_id: StableId("n1".to_string()),
            hostname: "host".to_string(),
            user_id: 0,
            tailnet: Some("tail1.ts.net".to_string()),
            tags: tags.iter().map(|t| t.to_string()).collect(),
            tailnet_address: TailnetAddress {
                ipv4: "100.64.0.1/32".parse().unwrap(),
                ipv6: "fd7a::1/128".parse().unwrap(),
            },
            node_key: [0u8; 32].into(),
            node_key_expiry: None,
            key_signature: vec![],
            machine_key: None,
            disco_key: None,
            accepted_routes: vec![],
            underlay_addresses: vec![],
            derp_region: None,
            cap: Default::default(),
            cap_map,
            peerapi_port: None,
            peerapi_dns_proxy: false,
            is_wireguard_only: false,
            exit_node_dns_resolvers: vec![],
            peer_relay: false,
            service_vips,
        }
    }

    fn vip4() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(100, 65, 32, 1))
    }

    #[test]
    fn tagged_host_with_vip_resolves_listen_addr() {
        let n = node(&["tag:samba"], "svc:samba", vec![vip4()]);
        let addr = resolve_service_listen(&n, "svc:samba", ServiceMode::Tcp { port: 445 }, false)
            .expect("a tagged host with an assigned VIP must resolve");
        assert_eq!(addr, core::net::SocketAddr::new(vip4(), 445));
    }

    #[test]
    fn http_mode_binds_same_vip_and_port() {
        let n = node(&["tag:web"], "svc:web", vec![vip4()]);
        let addr =
            resolve_service_listen(&n, "svc:web", ServiceMode::Http { port: 8080 }, false).unwrap();
        assert_eq!(addr, core::net::SocketAddr::new(vip4(), 8080));
    }

    #[test]
    fn invalid_name_is_rejected() {
        let n = node(&["tag:x"], "svc:x", vec![vip4()]);
        // Missing svc: prefix.
        let err =
            resolve_service_listen(&n, "samba", ServiceMode::Tcp { port: 1 }, false).unwrap_err();
        assert!(matches!(err, ServiceError::InvalidName(_)));
        // Bad label.
        let err = resolve_service_listen(&n, "svc:-bad", ServiceMode::Tcp { port: 1 }, false)
            .unwrap_err();
        assert!(matches!(err, ServiceError::InvalidName(_)));
    }

    #[test]
    fn untagged_host_is_rejected() {
        let n = node(&[], "svc:samba", vec![vip4()]);
        let err = resolve_service_listen(&n, "svc:samba", ServiceMode::Tcp { port: 445 }, false)
            .unwrap_err();
        assert_eq!(err, ServiceError::UntaggedHost);
    }

    #[test]
    fn no_assigned_vip_is_rejected() {
        let n = node(&["tag:samba"], "", vec![]);
        let err = resolve_service_listen(&n, "svc:samba", ServiceMode::Tcp { port: 445 }, false)
            .unwrap_err();
        assert!(matches!(err, ServiceError::NoAssignedVip(_)));
    }

    #[test]
    fn ipv6_vip_only_chosen_when_ipv6_enabled() {
        let vip6: IpAddr = "fd7a:115c:a1e0::1234".parse().unwrap();
        let n = node(&["tag:samba"], "svc:samba", vec![vip6]);

        // IPv6 disabled: no servable VIP -> fail closed.
        let err = resolve_service_listen(&n, "svc:samba", ServiceMode::Tcp { port: 445 }, false)
            .unwrap_err();
        assert!(matches!(err, ServiceError::NoAssignedVip(_)));

        // IPv6 enabled: the v6 VIP is used.
        let addr =
            resolve_service_listen(&n, "svc:samba", ServiceMode::Tcp { port: 445 }, true).unwrap();
        assert_eq!(addr, core::net::SocketAddr::new(vip6, 445));
    }

    #[test]
    fn ipv4_vip_preferred_over_ipv6() {
        let vip6: IpAddr = "fd7a:115c:a1e0::1234".parse().unwrap();
        let n = node(&["tag:samba"], "svc:samba", vec![vip6, vip4()]);
        let addr =
            resolve_service_listen(&n, "svc:samba", ServiceMode::Tcp { port: 445 }, true).unwrap();
        assert_eq!(addr, core::net::SocketAddr::new(vip4(), 445));
    }

    #[test]
    fn co_hosted_services_bind_their_own_vip() {
        // Two services on distinct VIPs: each resolves to its OWN VIP, not the other's (the fix for
        // the flattened-set wrong-bind).
        let vip_a = IpAddr::V4(Ipv4Addr::new(100, 65, 32, 1));
        let vip_b = IpAddr::V4(Ipv4Addr::new(100, 65, 32, 2));
        let n = node_multi(
            &["tag:multi"],
            &[("svc:a", vec![vip_a]), ("svc:b", vec![vip_b])],
        );

        let a = resolve_service_listen(&n, "svc:a", ServiceMode::Tcp { port: 1 }, false).unwrap();
        let b = resolve_service_listen(&n, "svc:b", ServiceMode::Tcp { port: 2 }, false).unwrap();
        assert_eq!(a, core::net::SocketAddr::new(vip_a, 1));
        assert_eq!(b, core::net::SocketAddr::new(vip_b, 2));

        // A service this host does not have is denied even though the host has OTHER VIPs.
        let err = resolve_service_listen(&n, "svc:absent", ServiceMode::Tcp { port: 3 }, false)
            .unwrap_err();
        assert!(matches!(err, ServiceError::NoAssignedVip(_)));
    }
}
