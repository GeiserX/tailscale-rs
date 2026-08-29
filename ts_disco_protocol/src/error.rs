/// Errors that may be encountered during disco message processing.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, thiserror::Error)]
pub enum Error {
    /// Encryption or decryption failed.
    #[error("crypto operation failed")]
    CryptoFailed,

    /// Message had the wrong magic bytes.
    #[error("wrong magic bytes sequence")]
    WrongMagic,

    /// The version number of a decrypted message was one this message type does not understand.
    ///
    /// Never a packet-wide verdict: the disco version byte is a per-message-type advisory (matching
    /// Go's `disco.Parse`), so Ping/Pong ignore it, the bind-handshake messages ignore it, and
    /// CallMeMaybe soft-empties on a non-zero version. See
    /// [`Packet::validate`][crate::Packet::validate].
    ///
    /// It *is* produced by the three version-gated peer-relay accessors —
    /// [`call_me_maybe_via`][crate::Packet::call_me_maybe_via],
    /// [`allocate_udp_relay_endpoints_request`][crate::Packet::allocate_udp_relay_endpoints_request]
    /// and
    /// [`allocate_udp_relay_endpoints_response`][crate::Packet::allocate_udp_relay_endpoints_response]
    /// — where Go returns an *empty* message instead of an error. An empty relay message carries no
    /// candidate `addr:port`, so Go's relay manager acts on nothing; surfacing the typed error the
    /// caller drops reaches the same observable outcome without reading a future version's body
    /// under this version's field layout.
    #[error("disco version other than 0")]
    UnknownVersion,

    /// The message was too short to decode.
    #[error("message was too short")]
    TooShort,

    /// Alignment issue while decoding.
    #[error("misaligned body while decoding")]
    Alignment,

    /// Validity issue while decoding.
    #[error("invalid value")]
    Validity,
}

impl<A, S, V> From<zerocopy::ConvertError<A, S, V>> for Error {
    fn from(value: zerocopy::ConvertError<A, S, V>) -> Self {
        match value {
            zerocopy::ConvertError::Size(..) => Error::TooShort,
            zerocopy::ConvertError::Alignment(..) => Error::Alignment,
            zerocopy::ConvertError::Validity(..) => Error::Validity,
        }
    }
}
