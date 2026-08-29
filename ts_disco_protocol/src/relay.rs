//! Peer-relay disco messages: the bind handshake, `CallMeMaybeVia`, and relay allocation.
//!
//! These are disco message types `0x04`–`0x09` (Go `disco/disco.go`,
//! `TypeBindUDPRelayEndpoint` … `TypeAllocateUDPRelayEndpointResponse`). They carry the
//! peer-relay ("UDP relay") path: a node asks a relay server to allocate an endpoint, tells its
//! peer about it with a [`CallMeMaybeVia`], and both peers then run a 3-way bind handshake with
//! the relay server before either may send data through it.
//!
//! Every one of these bodies is a fixed field layout with (for the relay-endpoint carrying ones)
//! a trailing array of 18-byte [`Endpoint`]s, so they are modelled the same way the rest of this
//! crate models disco: `zerocopy` structs read in place out of the decrypted packet body.
//!
//! Wire layouts, mirroring Go byte-for-byte:
//!
//! ```text
//! BindUDPRelayEndpointCommon (72 bytes), shared by 0x04 / 0x05 / 0x06:
//!   vni         u32 big-endian      4
//!   generation  u32 big-endian      4
//!   remote_key  disco public key   32
//!   challenge   opaque             32
//!
//! UDPRelayEndpoint (124 bytes + 18 per addr:port), carried by 0x07 and (after a
//! 4-byte generation) 0x09:
//!   server_disco             disco public key      32
//!   client_disco             2 disco public keys   64
//!   lamport_id               u64 big-endian         8
//!   vni                      u32 big-endian         4
//!   bind_lifetime            u64 big-endian ns      8
//!   steady_state_lifetime    u64 big-endian ns      8
//!   addr_ports               [Endpoint]            18 each, at least one
//!
//! AllocateUDPRelayEndpointRequest (68 bytes), 0x08:
//!   client_disco  2 disco public keys   64
//!   generation    u32 big-endian         4
//! ```

use core::{
    fmt::{Debug, Formatter},
    hash::{Hash, Hasher},
    time::Duration,
};

use ts_keys::DiscoPublicKey;
use zerocopy::{NetworkEndian, U32, U64};

use crate::{Endpoint, Message, MessageType};

/// Length in bytes of the `Challenge` field carried in a
/// [`BindUdpRelayEndpointChallenge`] / [`BindUdpRelayEndpointAnswer`] message.
///
/// Go `disco.BindUDPRelayChallengeLen`.
pub const BIND_UDP_RELAY_CHALLENGE_LEN: usize = 32;

/// The fields common to all three bind-handshake messages (Go
/// `disco.BindUDPRelayEndpointCommon`).
///
/// All four values stay constant for the lifetime of one handshake except `challenge`, which is
/// meaningless in a [`BindUdpRelayEndpoint`] — there it is pure padding, so that all three
/// handshake messages are the same size on the wire and a passive observer cannot tell them
/// apart by length.
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    Hash,
    zerocopy::Immutable,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Unaligned,
    zerocopy::KnownLayout,
)]
#[repr(C, packed)]
pub struct BindUdpRelayEndpointCommon {
    /// The Geneve header Virtual Network Identifier this handshake is for.
    ///
    /// It must equal the VNI in the *cleartext* Geneve header the message arrived under; a
    /// mismatch means the cleartext header was tampered with or mangled in transit, and the
    /// message must be dropped.
    pub vni: U32<NetworkEndian>,
    /// The handshake generation. A client picks a new, non-zero value at the start of every
    /// handshake so late replies from a previous attempt can be told apart.
    pub generation: U32<NetworkEndian>,
    /// The disco key of the *remote peer* participating over this relay endpoint (not the relay
    /// server's, and not ours).
    pub remote_key: DiscoPublicKey,
    /// Set by the server in a [`BindUdpRelayEndpointChallenge`] and echoed by the client in a
    /// [`BindUdpRelayEndpointAnswer`]. Padding in a [`BindUdpRelayEndpoint`].
    pub challenge: [u8; BIND_UDP_RELAY_CHALLENGE_LEN],
}

impl BindUdpRelayEndpointCommon {
    /// The size of a marshalled `BindUDPRelayEndpointCommon`, without the message header
    /// (Go `bindUDPRelayEndpointCommonLen`).
    pub const fn size() -> usize {
        size_of::<Self>()
    }
}

/// Generate one of the three bind-handshake message types.
///
/// They are byte-identical on the wire apart from the message-type byte, so upstream models them
/// as three distinct Go types embedding the same struct; we do the same rather than collapsing
/// them, because the type byte is what says who is talking to whom (client→server bind,
/// server→client challenge, client→server answer) and a handler that confused them would accept
/// a challenge it should have sent.
macro_rules! bind_handshake_message {
    ($(#[$attr:meta])* $name:ident, $ty:expr) => {
        $(#[$attr])*
        #[derive(
            Debug,
            Copy,
            Clone,
            PartialEq,
            Eq,
            Hash,
            zerocopy::Immutable,
            zerocopy::FromBytes,
            zerocopy::IntoBytes,
            zerocopy::Unaligned,
            zerocopy::KnownLayout,
        )]
        #[repr(C, packed)]
        pub struct $name {
            /// The handshake fields; see [`BindUdpRelayEndpointCommon`].
            pub common: BindUdpRelayEndpointCommon,
        }

        impl Message for $name {
            const TYPE: MessageType = $ty;
        }

        impl $name {
            /// The size of this message's body, without the message header.
            pub const fn size() -> usize {
                size_of::<Self>()
            }
        }

        impl From<BindUdpRelayEndpointCommon> for $name {
            fn from(common: BindUdpRelayEndpointCommon) -> Self {
                Self { common }
            }
        }
    };
}

bind_handshake_message!(
    /// First message of the 3-way bind handshake, client → relay server (disco `0x04`).
    BindUdpRelayEndpoint,
    MessageType::BindUdpRelayEndpoint
);
bind_handshake_message!(
    /// Second message of the bind handshake, relay server → client (disco `0x05`). Carries the
    /// challenge the client must echo.
    BindUdpRelayEndpointChallenge,
    MessageType::BindUdpRelayEndpointChallenge
);
bind_handshake_message!(
    /// Third message of the bind handshake, client → relay server (disco `0x06`), echoing the
    /// server's challenge.
    BindUdpRelayEndpointAnswer,
    MessageType::BindUdpRelayEndpointAnswer
);

/// A relay endpoint a UDP relay server has allocated (Go `disco.UDPRelayEndpoint`, itself a
/// mirror of `net/udprelay/endpoint.ServerEndpoint`).
///
/// Carried by both [`CallMeMaybeVia`] and [`AllocateUdpRelayEndpointsResponse`]. Dynamically
/// sized: the fixed fields are followed by one or more candidate `addr:port`s of the relay
/// server.
#[derive(
    zerocopy::Immutable,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Unaligned,
    zerocopy::KnownLayout,
)]
#[repr(C, packed)]
pub struct UdpRelayEndpoint {
    /// The relay server's disco public key. The bind-handshake messages are sealed to *this*
    /// key, not to the peer's.
    pub server_disco: DiscoPublicKey,
    /// The disco keys of the two clients permitted to handshake with this endpoint.
    pub client_disco: [DiscoPublicKey; 2],
    /// The server's Lamport clock value for this allocation, used to order competing
    /// allocations for the same peer pair.
    pub lamport_id: U64<NetworkEndian>,
    /// The Geneve Virtual Network Identifier that selects this endpoint on the relay server.
    pub vni: U32<NetworkEndian>,
    /// How long the endpoint stays allocated while the bind handshake is still in progress,
    /// in nanoseconds (Go marshals `time.Duration`, which is an `int64` of nanoseconds).
    pub bind_lifetime_nanos: U64<NetworkEndian>,
    /// How long the endpoint stays allocated once bound and idle, in nanoseconds.
    pub steady_state_lifetime_nanos: U64<NetworkEndian>,
    /// The relay server's candidate `addr:port`s. Go's decoder requires at least one.
    pub addr_ports: [Endpoint],
}

impl UdpRelayEndpoint {
    /// Size of the fixed portion, i.e. everything before `addr_ports`
    /// (Go `udpRelayEndpointLenMinusAddrPorts`).
    pub const LEN_MINUS_ADDR_PORTS: usize = size_of::<DiscoPublicKey>() * 3
        + size_of::<u64>()
        + size_of::<u32>()
        + size_of::<u64>()
        + size_of::<u64>();

    /// The size of a `UDPRelayEndpoint` carrying the given number of `addr:port`s.
    pub const fn size_for_addr_port_count(addr_port_count: usize) -> usize {
        Self::LEN_MINUS_ADDR_PORTS + size_of::<Endpoint>() * addr_port_count
    }

    /// The Lamport clock value for this allocation.
    pub fn lamport_id(&self) -> u64 {
        self.lamport_id.get()
    }

    /// The Geneve Virtual Network Identifier for this endpoint.
    pub fn vni(&self) -> u32 {
        self.vni.get()
    }

    /// How long the endpoint stays allocated while binding.
    pub fn bind_lifetime(&self) -> Duration {
        Duration::from_nanos(self.bind_lifetime_nanos.get())
    }

    /// How long the endpoint stays allocated once bound and idle.
    pub fn steady_state_lifetime(&self) -> Duration {
        Duration::from_nanos(self.steady_state_lifetime_nanos.get())
    }
}

impl Debug for &UdpRelayEndpoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UdpRelayEndpoint")
            .field("server_disco", &self.server_disco)
            .field("client_disco", &self.client_disco)
            .field("lamport_id", &self.lamport_id())
            .field("vni", &self.vni())
            .field("bind_lifetime", &self.bind_lifetime())
            .field("steady_state_lifetime", &self.steady_state_lifetime())
            .field("addr_ports", &&self.addr_ports)
            .finish()
    }
}

impl PartialEq for &UdpRelayEndpoint {
    fn eq(&self, other: &Self) -> bool {
        self.server_disco == other.server_disco
            && self.client_disco == other.client_disco
            && self.lamport_id() == other.lamport_id()
            && self.vni() == other.vni()
            && self.bind_lifetime_nanos.get() == other.bind_lifetime_nanos.get()
            && self.steady_state_lifetime_nanos.get() == other.steady_state_lifetime_nanos.get()
            && self.addr_ports == other.addr_ports
    }
}

impl Eq for &UdpRelayEndpoint {}

impl Hash for &UdpRelayEndpoint {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.server_disco.hash(state);
        self.client_disco.hash(state);
        self.lamport_id().hash(state);
        self.vni().hash(state);
        self.bind_lifetime_nanos.get().hash(state);
        self.steady_state_lifetime_nanos.get().hash(state);
        self.addr_ports.hash(state);
    }
}

/// A `CallMeMaybe` whose candidate paths run *through a relay* (disco `0x07`, Go
/// `disco.CallMeMaybeVia`).
///
/// Like [`CallMeMaybe`][crate::CallMeMaybe] this is sent only over DERP, and asks the recipient
/// to open a path back. The "Via" is the difference: the candidate addresses belong to a UDP
/// relay server, and using them requires first completing the 3-way bind handshake
/// ([`BindUdpRelayEndpoint`] → [`BindUdpRelayEndpointChallenge`] → [`BindUdpRelayEndpointAnswer`])
/// with that server. Upstream is explicit that a direct path, signalled by a plain `CallMeMaybe`,
/// takes priority over a `CallMeMaybeVia` path.
#[derive(
    zerocopy::Immutable,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Unaligned,
    zerocopy::KnownLayout,
)]
#[repr(C, packed)]
pub struct CallMeMaybeVia {
    /// The relay endpoint to handshake with and then send through.
    pub endpoint: UdpRelayEndpoint,
}

impl Message for CallMeMaybeVia {
    const TYPE: MessageType = MessageType::CallMeMaybeVia;
}

impl CallMeMaybeVia {
    /// The size of a `CallMeMaybeVia` carrying the given number of relay `addr:port`s.
    pub const fn size_for_addr_port_count(addr_port_count: usize) -> usize {
        UdpRelayEndpoint::size_for_addr_port_count(addr_port_count)
    }
}

impl Debug for &CallMeMaybeVia {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CallMeMaybeVia")
            .field("endpoint", &&self.endpoint)
            .finish()
    }
}

impl PartialEq for &CallMeMaybeVia {
    fn eq(&self, other: &Self) -> bool {
        &self.endpoint == &other.endpoint
    }
}

impl Eq for &CallMeMaybeVia {}

/// A request to a relay server to allocate an endpoint for a pair of clients (disco `0x08`, Go
/// `disco.AllocateUDPRelayEndpointRequest`). Sent only over DERP.
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    Hash,
    zerocopy::Immutable,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Unaligned,
    zerocopy::KnownLayout,
)]
#[repr(C, packed)]
pub struct AllocateUdpRelayEndpointsRequest {
    /// The disco keys of the two clients that may handshake with the allocated endpoint.
    pub client_disco: [DiscoPublicKey; 2],
    /// The allocation-request generation, echoed back in the response so a client can line a
    /// response up with the request that caused it.
    pub generation: U32<NetworkEndian>,
}

impl Message for AllocateUdpRelayEndpointsRequest {
    const TYPE: MessageType = MessageType::AllocateUdpRelayEndpointsRequest;
}

impl AllocateUdpRelayEndpointsRequest {
    /// The size of this message's body, without the message header
    /// (Go `allocateUDPRelayEndpointRequestLen`).
    pub const fn size() -> usize {
        size_of::<Self>()
    }
}

/// A relay server's response to an [`AllocateUdpRelayEndpointsRequest`] (disco `0x09`, Go
/// `disco.AllocateUDPRelayEndpointResponse`). Sent only over DERP.
#[derive(
    zerocopy::Immutable,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Unaligned,
    zerocopy::KnownLayout,
)]
#[repr(C, packed)]
pub struct AllocateUdpRelayEndpointsResponse {
    /// The generation from the request this answers.
    pub generation: U32<NetworkEndian>,
    /// The endpoint that was allocated.
    pub endpoint: UdpRelayEndpoint,
}

impl Message for AllocateUdpRelayEndpointsResponse {
    const TYPE: MessageType = MessageType::AllocateUdpRelayEndpointsResponse;
}

impl AllocateUdpRelayEndpointsResponse {
    /// The size of a response carrying the given number of relay `addr:port`s.
    pub const fn size_for_addr_port_count(addr_port_count: usize) -> usize {
        size_of::<u32>() + UdpRelayEndpoint::size_for_addr_port_count(addr_port_count)
    }

    /// The generation from the request this answers.
    pub fn generation(&self) -> u32 {
        self.generation.get()
    }
}

impl Debug for &AllocateUdpRelayEndpointsResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AllocateUdpRelayEndpointsResponse")
            .field("generation", &self.generation())
            .field("endpoint", &&self.endpoint)
            .finish()
    }
}

impl PartialEq for &AllocateUdpRelayEndpointsResponse {
    fn eq(&self, other: &Self) -> bool {
        self.generation() == other.generation() && &self.endpoint == &other.endpoint
    }
}

impl Eq for &AllocateUdpRelayEndpointsResponse {}

/// A message whose body ends in a [`UdpRelayEndpoint`], and therefore inherits Go's
/// `UDPRelayEndpoint.decode` minimum: the fixed part plus **one** whole `addr:port`.
///
/// Crate-internal: it exists only so [`Packet`][crate::Packet]'s two relay-endpoint parsers can
/// share one length check instead of repeating it per message type.
pub(crate) trait RelayEndpointMessage {
    /// The shortest body Go's decoder accepts for this message.
    const MIN_LEN: usize;
}

impl RelayEndpointMessage for CallMeMaybeVia {
    const MIN_LEN: usize = Self::size_for_addr_port_count(1);
}

impl RelayEndpointMessage for AllocateUdpRelayEndpointsResponse {
    const MIN_LEN: usize = Self::size_for_addr_port_count(1);
}
