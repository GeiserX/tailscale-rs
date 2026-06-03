use ts_keys::DiscoPublicKey;
use zerocopy::TryFromBytes;

use crate::Error;

/// A disco message header.
///
/// This is the outer message header that isn't part of the encrypted payload.
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    Hash,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Unaligned,
)]
#[repr(C, packed)]
pub struct Header {
    pub(crate) magic: [u8; Header::MAGIC.len()],
    pub(crate) sender_pub: DiscoPublicKey,
    pub(crate) nonce: [u8; Header::NONCE_LEN],
}

impl Header {
    /// Magic bytes indicating that this is a disco message.
    /// "TS" followed by UTF-8 speech bubble.
    pub const MAGIC: [u8; 6] = *b"TS\xf0\x9f\x92\xac";

    /// Length in bytes of the nonce field.
    pub const NONCE_LEN: usize = 24;

    /// Construct a new [`Header`] with the given pubkey and nonce.
    pub const fn new(sender_pub: DiscoPublicKey, nonce: [u8; 24]) -> Self {
        Self {
            magic: Self::MAGIC,
            sender_pub,
            nonce,
        }
    }

    /// Parse header from buffer, validating that message has the correct magic bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<(&Self, &[u8]), Error> {
        let (slf, rest) = Self::try_ref_from_prefix(buf)?;
        slf.validate()?;

        Ok((slf, rest))
    }

    /// The disco public key of the node that sent this message.
    ///
    /// Incoming disco packets carry the sender's disco key in cleartext (it is needed to
    /// open the [`crypto_box`][crypto_box] seal), so this identifies the peer that a
    /// received [`Ping`][crate::Ping]/[`Pong`][crate::Pong] came from.
    pub const fn sender_pub(&self) -> DiscoPublicKey {
        self.sender_pub
    }

    /// The nonce used to seal this message.
    pub const fn nonce(&self) -> [u8; Header::NONCE_LEN] {
        self.nonce
    }

    /// Report whether this is a valid disco header.
    ///
    /// This requires the magic bytes to match.
    pub const fn is_valid(&self) -> bool {
        matches!(self.magic, Self::MAGIC)
    }

    /// Validate that this header has the right magic number, and throw an error if not.
    pub const fn validate(&self) -> Result<(), Error> {
        if !self.is_valid() {
            return Err(Error::WrongMagic);
        }

        Ok(())
    }
}
