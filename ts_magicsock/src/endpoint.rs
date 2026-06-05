//! Our own candidate endpoints, surfaced for advertisement to control and `CallMeMaybe`.
//!
//! These are the addresses we believe a peer could reach us on. They come from two sources,
//! both observed on the single bound underlay socket (never a second socket — see the crate
//! anti-leak note):
//! - the locally bound address ([`SelfEndpointType::Local`]), known the instant we bind, and
//! - reflexive addresses learned from disco pong `src` echoes ([`SelfEndpointType::Stun`]),
//!   which are the STUN-equivalent mappings a peer observed our traffic arriving from.

use core::net::SocketAddr;

/// How a [`SelfEndpoint`] was discovered. Maps 1:1 onto the control protocol's endpoint type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SelfEndpointType {
    /// The locally bound address (LAN / host address).
    Local,
    /// A reflexive address learned from a disco pong's echoed source (STUN-equivalent).
    Stun,
    /// Hard-NAT guess: a reflexive (STUN) IPv4 paired with our **local** bound port. Under a
    /// symmetric (endpoint-dependent-mapping) NAT the public port varies per-destination, so the
    /// reflexive `ip:port` a peer learns is useless to a third peer; but if the router happens to
    /// have a static port-mapping to our fixed local port, `(reflexive_ip, local_port)` may be
    /// reachable. Mirrors Go's `EndpointSTUN4LocalPort`. A best-effort candidate, only emitted when
    /// symmetric NAT is detected.
    Stun4LocalPort,
}

/// One candidate address we believe we are reachable on, tagged with how we learned it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SelfEndpoint {
    /// The address itself.
    pub addr: SocketAddr,
    /// How this address was discovered.
    pub ty: SelfEndpointType,
}
