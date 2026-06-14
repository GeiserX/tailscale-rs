use core::fmt;

use ts_keys::NodePublicKey;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::frame;

/// Indication from the server that a previous sender has disconnected.
///
/// The wire body is a 32-byte peer key optionally followed by a 1-byte reason code. The reason byte
/// is a later addition (Go `derp`: "Backward compatibility for the older peerGone without reason
/// byte"), so a 32-byte (reason-less) body is valid and defaults the reason to
/// [`PeerGoneReason::Disconnected`]. This fixed struct models only the 33-byte form; the recv loop
/// parses the key and the optional reason directly from the frame body so it accepts both lengths
/// (see `client.rs`).
#[derive(
    Debug, Copy, Clone, PartialEq, KnownLayout, Immutable, IntoBytes, FromBytes, Unaligned,
)]
#[repr(C, packed)]
pub struct PeerGone {
    /// The server that disconnected.
    pub key: NodePublicKey,
    /// The reason code for the peer disconnection.
    pub raw_reason: u8,
}

impl PeerGone {
    /// Interpret the raw reason field as a [`PeerGoneReason`].
    pub fn reason(&self) -> PeerGoneReason {
        PeerGoneReason::from(self.raw_reason)
    }
}

impl frame::Body for PeerGone {
    const FRAME_TYPE: frame::FrameType = frame::FrameType::PeerGone;
}

/// Code indicating why a DERP server can't find a path to a particular peer.
///
/// Parsing is **total**: any unrecognized byte maps to [`PeerGoneReason::Other`] rather than an
/// error, mirroring Go's `derp_client`, which casts the byte with no validation
/// (`reason = PeerGoneReasonType(b[KeyLen])`). A future or unknown reason code must NOT tear down the
/// DERP connection — it is logged and the peer is still treated as gone.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PeerGoneReason {
    /// The peer was connected to this DERP server, but has disconnected (Go `0x00`).
    Disconnected,
    /// The DERP server doesn't know about this peer, meaning the peer has not connected to this
    /// DERP server for a long time, or has never connected to this DERP server. This is
    /// unexpected in normal ops (Go `0x01`).
    NotHere,
    /// A meshed-connection break (Go `PeerGoneReasonMeshConnBroke = 0xf0`). Go invents this
    /// client-side on a watch-connection disconnect; it is not normally sent on the wire to a leaf
    /// client, but is recognized for completeness.
    MeshConnBroke,
    /// Any other reason byte the server sent that this client does not specifically recognize. Go
    /// accepts (and forwards) an arbitrary reason byte, so we do too rather than failing.
    Other(u8),
}

impl PeerGoneReason {
    /// The wire byte for this reason.
    pub fn as_byte(self) -> u8 {
        match self {
            PeerGoneReason::Disconnected => 0x00,
            PeerGoneReason::NotHere => 0x01,
            PeerGoneReason::MeshConnBroke => 0xf0,
            PeerGoneReason::Other(v) => v,
        }
    }
}

impl fmt::Display for PeerGoneReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<u8> for PeerGoneReason {
    fn from(v: u8) -> Self {
        match v {
            0x00 => PeerGoneReason::Disconnected,
            0x01 => PeerGoneReason::NotHere,
            0xf0 => PeerGoneReason::MeshConnBroke,
            other => PeerGoneReason::Other(other),
        }
    }
}

impl From<PeerGoneReason> for u8 {
    fn from(v: PeerGoneReason) -> Self {
        v.as_byte()
    }
}
