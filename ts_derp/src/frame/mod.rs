//! Derp framing implementation.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

mod body;
mod codec;
mod error;
mod frame_type;
mod header;
mod magic;
mod raw;

#[allow(deprecated)]
pub use body::KeepAlive;
pub use body::{
    Body, ClientInfo, ClientInfoPayload, ClosePeer, ForwardPacket, Health, NotePreferred, PeerGone,
    PeerGoneReason, PeerPresent, Ping, Pong, RecvPacket, Restarting, SendPacket, ServerInfo,
    ServerInfoPayload, ServerKey, WatchConns,
};
pub use codec::Codec;
pub use error::Error;
pub use frame_type::FrameType;
pub use header::{Header, RawHeader};
pub use magic::Magic;
pub use raw::RawFrame;

/// Maximum size (in bytes) of a packet sent via DERP, not including any on-wire framing overhead.
/// Equivalent to the max payload size of a [SendPacket], [ForwardPacket], or [RecvPacket] frame
/// (Go `derp.MaxPacketSize = 64 << 10`).
///
/// # Intentional divergence from Go on the bound for a *known inbound* frame
///
/// Go applies this 64 KiB bound only on the **send** side (`send`/`ForwardPacket`: "packet too
/// big"); on the **receive** side every frame — including `RecvPacket` and `ServerInfo` — is bounded
/// only by the wider [`MAX_RECV_FRAME_SIZE`] (`1 << 20`, Go `recvTimeout`), with `ServerInfo`
/// additionally validated post-parse against Go's `NonceLen + MaxInfoLen`. This fork deliberately
/// holds **every known frame** to this tighter 64 KiB cap at decode (`Header::new` /
/// `Header::try_from`) as well, which is *stricter* than Go on the inbound path. This is the safe
/// direction: it bounds a single inbound frame's allocation to 64 KiB rather than 1 MiB (16× tighter
/// anti-DoS), and it drops no real traffic — a real DERP server relays WireGuard/disco datagrams
/// whose payload (plus a `RecvPacket`/`ForwardPacket` frame's 32-byte source-key prefix) stays well
/// under `MAX_PACKET_SIZE`; Tailscale's tunnel MTU is ~1280 B, so the 64 KiB–1 MiB *frame-body* band
/// is never legitimately used (a production `ServerInfo` is likewise a few hundred bytes). An unknown
/// (forward-extension) frame is still read and skipped up to [`MAX_RECV_FRAME_SIZE`] so a newer
/// server is never disconnected.
pub const MAX_PACKET_SIZE: usize = 64 << 10;

/// Upper bound (in bytes) on any frame body the receive codec will read off the wire before
/// rejecting it as malformed. Matches Go `derp.go` `recvTimeout`'s `1<<20` cap — a generous safety
/// bound that is **larger** than [`MAX_PACKET_SIZE`] so the codec can read (and, for an unknown
/// type, skip) a large frame a forward-extended server might emit, rather than tearing the
/// connection down. Known frames are still bounded to [`MAX_PACKET_SIZE`] at `Header` build time
/// (see the divergence note there); this is only the read/skip ceiling for unknown frames.
pub const MAX_RECV_FRAME_SIZE: usize = 1 << 20;

/// Minimum frequency (in seconds) at which the DERP server sends [`KeepAlive`] frames to each DERP
/// client. The server adds some jitter, so this timing is not exact, but 2x this value can be
/// considered a missed keep-alive.
pub const KEEP_ALIVE: usize = 60;

/// Current version of the DERP protocol; must be bumped whenever there's a wire-incompatible
/// change.
/// - Version 1 (zero on wire): consistent box headers, in use by employee dev nodes a bit
/// - Version 2: received packets have src addrs in [RecvPacket] frames at beginning
pub const PROTOCOL_VERSION: usize = 2;

/// IP address.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, KnownLayout, Immutable, IntoBytes, FromBytes)]
pub struct Ip([u8; 16]);
