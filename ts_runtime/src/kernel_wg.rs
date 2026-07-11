//! Kernel-WireGuard backend for the hybrid data plane (KERNEL_WG_DESIGN.md, seam #1).
//!
//! Mirrors the tailnet peer set assembled at the dataplane `PeerState` seam into a kernel
//! WireGuard interface via `defguard_wireguard_rs`. Hybrid rule: only peers with a direct underlay
//! endpoint are placed on the kernel path (kernel does crypto + sends UDP direct, far cheaper on
//! 32-bit MIPS); relay-only / not-yet-direct peers stay on the userspace `ts_tunnel` + DERP path.
//!
//! Off by default; built only with the `kernel-wg` cargo feature. The actual netlink ops require
//! root + `kmod-wireguard` and are validated on-device, not in CI.
use std::net::SocketAddr;

use defguard_wireguard_rs::{
    InterfaceConfiguration, Kernel, WGApi, WireguardInterfaceApi, host::Peer, key::Key,
    net::IpAddrMask,
};

/// One tailnet peer projected from a control `Node` at the dataplane seam.
pub struct KernelPeer {
    /// The peer's WireGuard public key (`Node.node_key`).
    pub public_key: [u8; 32],
    /// The peer's tailnet addresses + accepted routes (`Node.tailnet_address` / `accepted_routes`).
    pub allowed_ips: Vec<IpAddrMask>,
    /// Direct underlay endpoint (`Node.underlay_addresses`); `None` => relay-only, excluded.
    pub endpoint: Option<SocketAddr>,
}

/// Pick the kernel-path endpoint for a peer: prefer the disco-verified direct address (`best_addr`,
/// seam #2 — the live, NAT-traversed path) when present, else fall back to a control-distributed
/// candidate from `Node.underlay_addresses` (seam #1). `None` => no direct path => relay-only =>
/// the peer is excluded from the kernel path and stays on userspace `ts_tunnel` + DERP.
pub fn select_endpoint(
    best_addr: Option<SocketAddr>,
    underlay_addresses: &[SocketAddr],
) -> Option<SocketAddr> {
    best_addr.or_else(|| underlay_addresses.first().copied())
}

/// Build the defguard interface config, applying the hybrid rule (direct-endpoint peers only).
pub fn build_config(
    ifname: &str,
    private_key: [u8; 32],
    listen_port: u32,
    peers: &[KernelPeer],
) -> InterfaceConfiguration {
    let kernel_peers: Vec<Peer> = peers
        .iter()
        .filter(|p| p.endpoint.is_some())
        .map(|p| {
            let mut peer = Peer::new(Key::new(p.public_key));
            peer.endpoint = p.endpoint;
            peer.allowed_ips = p.allowed_ips.clone();
            peer
        })
        .collect();

    InterfaceConfiguration {
        name: ifname.to_string(),
        prvkey: Key::new(private_key).to_string(),
        addresses: vec![],
        port: listen_port,
        peers: kernel_peers,
        mtu: None,
    }
}

/// Create (if needed) and configure the kernel wg interface for the given peer set. Real netlink —
/// needs root + `kmod-wireguard` on the device.
pub fn sync(
    ifname: &str,
    private_key: [u8; 32],
    listen_port: u32,
    peers: &[KernelPeer],
) -> Result<(), defguard_wireguard_rs::error::WireguardInterfaceError> {
    let cfg = build_config(ifname, private_key, listen_port, peers);
    let wgapi = WGApi::<Kernel>::new(ifname.to_string())?;
    // The interface may already exist (created by uci/`ip link`); an error here is non-fatal — we
    // still attempt to configure it below.
    if let Err(e) = wgapi.create_interface() {
        tracing::debug!(error = %e, ifname, "kernel-wg: create_interface failed (may already exist)");
    }
    wgapi.configure_interface(&cfg)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn cidr(a: [u8; 4], c: u8) -> IpAddrMask {
        IpAddrMask::new(Ipv4Addr::from(a).into(), c)
    }

    #[test]
    fn select_endpoint_prefers_disco_best_addr_then_falls_back() {
        let underlay = ["198.51.100.7:41641".parse().unwrap()];
        let best: SocketAddr = "203.0.113.9:41641".parse().unwrap();
        // disco best_addr wins when present (seam #2: the live, verified direct path)
        assert_eq!(select_endpoint(Some(best), &underlay), Some(best));
        // else fall back to the control-distributed candidate (seam #1)
        assert_eq!(select_endpoint(None, &underlay), Some(underlay[0]));
        // relay-only peer: no endpoint at all => excluded from the kernel path
        assert_eq!(select_endpoint(None, &[]), None);
    }

    #[test]
    fn only_direct_endpoint_peers_reach_the_kernel() {
        let peers = vec![
            KernelPeer {
                public_key: [1; 32],
                allowed_ips: vec![cidr([100, 64, 0, 1], 32)],
                endpoint: None,
            },
            KernelPeer {
                public_key: [2; 32],
                allowed_ips: vec![cidr([100, 64, 0, 2], 32)],
                endpoint: Some("203.0.113.5:41641".parse().unwrap()),
            },
        ];
        let cfg = build_config("wg-ts", [7; 32], 51820, &peers);
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(cfg.peers[0].public_key, Key::new([2; 32]));
        assert_eq!(
            cfg.peers[0].endpoint,
            Some("203.0.113.5:41641".parse().unwrap())
        );
    }
}
