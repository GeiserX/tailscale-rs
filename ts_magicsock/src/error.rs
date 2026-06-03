//! Error types for the direct (disco) UDP underlay.

/// Errors that can occur while building or parsing disco messages.
#[derive(Debug, thiserror::Error)]
pub enum DiscoError {
    /// The underlying disco codec rejected the buffer (bad magic, wrong size, failed seal).
    #[error("disco codec error: {0}")]
    Codec(#[from] ts_disco_protocol::Error),

    /// The datagram opened but its body did not match its declared message type.
    #[error("disco message was malformed")]
    Malformed,

    /// The datagram carried a disco message type this transport does not handle.
    #[error("unknown or unhandled disco message type")]
    UnknownMessageType,
}

/// Errors produced by the direct UDP underlay transport.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An I/O error on the underlay socket.
    #[error("magicsock io error: {0}")]
    Io(#[from] std::io::Error),

    /// A disco protocol error.
    #[error(transparent)]
    Disco(#[from] DiscoError),

    /// No direct path is currently known for the destination peer.
    ///
    /// This is **not** a silent failure: the caller (route layer) must keep the peer on
    /// DERP rather than dialing the host network directly. Surfacing it as an error keeps
    /// the anti-leak posture fail-closed.
    #[error("no direct path known for peer")]
    NoPath,
}
