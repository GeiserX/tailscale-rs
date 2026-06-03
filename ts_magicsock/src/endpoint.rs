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
}

/// One candidate address we believe we are reachable on, tagged with how we learned it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SelfEndpoint {
    /// The address itself.
    pub addr: SocketAddr,
    /// How this address was discovered.
    pub ty: SelfEndpointType,
}
