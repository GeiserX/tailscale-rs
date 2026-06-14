use core::marker::PhantomData;

use aead::{AeadInPlace, generic_array::GenericArray};
use crypto_box::Tag;
use ts_keys::{DiscoPrivateKey, DiscoPublicKey, NodePublicKey};
use zerocopy::{FromBytes, IntoBytes, KnownLayout, TryFromBytes};

use crate::{Error, Header, Message, message_type::MessageType};

/// The transaction-id length at the head of a Ping body (Go `disco.Ping.TxID` is `[12]byte`).
const PING_TX_ID_LEN: usize = 12;

/// Marker type indicating that a [`Packet`] is in an encrypted state.
pub enum Encrypted {}

/// Payload of a plaintext [`Packet`].
#[derive(
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Unaligned,
)]
#[repr(C, packed)]
pub struct Plaintext {
    ty: u8,
    version: u8,
    message: [u8],
}

impl Plaintext {
    pub const VERSION: u8 = 0;

    pub fn ty(&self) -> Option<MessageType> {
        self.ty.try_into().ok()
    }

    pub const fn size_for_message(payload_size: usize) -> usize {
        2 + payload_size
    }
}

#[derive(
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Unaligned,
)]
#[repr(C, packed)]
pub struct AeadTaggedPayload {
    tag: [u8; 16],
    payload: [u8],
}

impl AeadTaggedPayload {
    pub const fn size_for_payload(payload_size: usize) -> usize {
        16 + payload_size
    }
}

/// A disco packet that may hold an encrypted or plaintext payload.
#[derive(
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Unaligned,
)]
#[repr(C, packed)]
pub struct Packet<CryptState: ?Sized> {
    phantom: PhantomData<CryptState>,
    header: Header,
    payload: AeadTaggedPayload,
}

impl<CryptState> Packet<CryptState>
where
    CryptState: ?Sized,
{
    /// Get a ref to the header contained in the packet.
    pub fn header(&self) -> &Header {
        &self.header
    }
}

impl Packet<Plaintext> {
    /// Initialize a plaintext packet in the given byte slice `b`. The `init_msg` closure
    /// is used to set the message data.
    ///
    /// The byte slice must be sized exactly: use [`Packet::size_for_message`] to calculate
    /// this.
    ///
    /// This does not set the header nonce or sender key: these are set at encryption time
    /// (in [`Packet::encrypt_in_place`]).
    pub fn init_from_bytes<Msg>(
        b: &mut [u8],
        init_msg: impl FnOnce(&mut Msg),
    ) -> Result<&mut Self, Error>
    where
        Msg: ?Sized + Message + zerocopy::Immutable + TryFromBytes + IntoBytes + KnownLayout,
    {
        let s = Self::try_mut_from_bytes(b)?;

        let pt = Plaintext::mut_from_bytes(&mut s.payload.payload)?;
        pt.ty = Msg::TYPE as _;
        pt.version = 0;

        let msg = Msg::try_mut_from_bytes(&mut pt.message)?;
        init_msg(msg);

        s.validate()?;

        Ok(s)
    }

    /// Initialize a packet with a raw, untyped message body of whatever length `b` was sized for
    /// (use [`Packet::size_for_message`] with the desired body length). Sets the given message
    /// `ty` + version 0 and hands the message bytes to `init_msg` to fill.
    ///
    /// Unlike [`init_from_bytes`](Self::init_from_bytes), this does not constrain the body to a
    /// typed message's exact layout — it is for constructing bodies that a strict typed parse would
    /// reject (e.g. an over-length fixed message, or a non-multiple variable message) to exercise
    /// the lax inbound parsers.
    ///
    /// **Unstable test/fuzz seam** — `#[doc(hidden)]`, no semver guarantee. It must be `pub` only
    /// because its sole consumer is a `#[cfg(test)]` helper in a *different* crate (cfg(test) does
    /// not cross crate boundaries); it is not part of the supported public surface. `init_msg` must
    /// not index beyond the provided slice (its length is whatever `b` was sized for).
    #[doc(hidden)]
    pub fn init_raw_message(
        b: &mut [u8],
        ty: MessageType,
        init_msg: impl FnOnce(&mut [u8]),
    ) -> Result<&mut Self, Error> {
        Self::init_raw_message_versioned(b, ty, Plaintext::VERSION, init_msg)
    }

    /// Like [`init_raw_message`](Self::init_raw_message) but with an explicit `version` byte, to
    /// exercise the per-type version laxity (Go's `disco.Parse` ignores the version for Ping/Pong
    /// and soft-empties CallMeMaybe when it isn't 0). A future-version message must still parse
    /// (Ping/Pong) or soft-empty (CallMeMaybe), never be rejected wholesale.
    ///
    /// **Unstable test/fuzz seam** — `#[doc(hidden)]`, no semver guarantee; `pub` only because its
    /// consumer is a `#[cfg(test)]` helper in a different crate.
    #[doc(hidden)]
    pub fn init_raw_message_versioned(
        b: &mut [u8],
        ty: MessageType,
        version: u8,
        init_msg: impl FnOnce(&mut [u8]),
    ) -> Result<&mut Self, Error> {
        let s = Self::try_mut_from_bytes(b)?;

        let pt = Plaintext::mut_from_bytes(&mut s.payload.payload)?;
        pt.ty = ty as _;
        pt.version = version;
        init_msg(&mut pt.message);

        s.validate()?;

        Ok(s)
    }

    /// Cast the slice to a plaintext packet.
    ///
    /// # Note
    ///
    /// This is memory-safe, but may be semantically unsound: the type and version fields are not
    /// set and may disagree with the payload.
    pub fn from_bytes_unvalidated(b: &[u8]) -> Result<&Self, Error> {
        Self::try_ref_from_bytes(b).map_err(From::from)
    }

    /// Cast the slice to a mutable plaintext packet.
    ///
    /// # Note
    ///
    /// Like [`Packet::from_bytes_unvalidated`], this is memory-safe but may be semantically unsound.
    pub fn from_bytes_unvalidated_mut(b: &mut [u8]) -> Result<&mut Self, Error> {
        Self::try_mut_from_bytes(b).map_err(From::from)
    }

    /// Encrypt this packet, converting it to a [`Packet<Encrypted>`].
    pub fn encrypt_in_place(
        &mut self,
        secret: &DiscoPrivateKey,
        receiver: &DiscoPublicKey,
        nonce: [u8; Header::NONCE_LEN],
    ) -> Result<&mut Packet<Encrypted>, Error> {
        let bx = crypto_box::SalsaBox::new(&receiver.into(), &secret.into());

        self.header.magic = Header::MAGIC;
        self.header.sender_pub = secret.public_key();
        self.header.nonce = nonce;

        let tag = bx
            .encrypt_in_place_detached(&GenericArray::from(nonce), &[], &mut self.payload.payload)
            .map_err(|_e| Error::CryptoFailed)?;

        self.payload.tag.copy_from_slice(tag.as_ref());

        let bs = self.as_mut_bytes();
        let ret = Packet::mut_from_bytes(bs)?;

        Ok(ret)
    }

    /// Report the type of the message stored in this packet, if it is recognized.
    pub fn ty(&self) -> Option<MessageType> {
        self.plaintext()?.ty()
    }

    /// Return the type byte for this packet, if the plaintext body is parseable.
    pub fn ty_raw(&self) -> Option<u8> {
        Some(self.plaintext()?.ty)
    }

    /// Return the version byte for this packet, if the body was parseable.
    pub fn version(&self) -> Option<u8> {
        Some(self.plaintext()?.version)
    }

    /// Convert the payload of this packet to the given message type.
    ///
    /// Fails if the body could not be parsed or the type field doesn't match.
    pub fn as_msg<T>(&self) -> Option<&T>
    where
        T: ?Sized + Message + zerocopy::Immutable + zerocopy::KnownLayout + zerocopy::FromBytes,
    {
        let pt = self.plaintext()?;

        if pt.ty() != Some(T::TYPE) {
            return None;
        }

        T::ref_from_bytes(&pt.message).ok()
    }

    /// Convert the payload to a **sized** message type, parsing only its fixed prefix and ignoring
    /// any trailing bytes — Go's disco parser is "deliberately lax on longer-than-expected messages,
    /// for future compatibility" (`disco.Parse`). The strict [`as_msg`](Self::as_msg) requires the
    /// body to be *exactly* the message size, so a forward-compatible peer that appends bytes to a
    /// (e.g.) `Pong` would have its message dropped; this accepts it by taking the prefix.
    ///
    /// Only valid for fixed-size `T` (it uses `ref_from_prefix`); a dynamically-sized message like
    /// `CallMeMaybe` must be parsed with its own length-aware logic, not this.
    pub fn as_msg_lax<T>(&self) -> Option<&T>
    where
        T: Message + Sized + zerocopy::Immutable + zerocopy::KnownLayout + zerocopy::FromBytes,
    {
        let pt = self.plaintext()?;

        if pt.ty() != Some(T::TYPE) {
            return None;
        }

        // `ref_from_prefix` parses the first `size_of::<T>()` bytes and returns the rest; we ignore
        // the rest (forward-compat trailing bytes), mirroring Go's lax fixed-message parse.
        T::ref_from_prefix(&pt.message).ok().map(|(msg, _rest)| msg)
    }

    /// Parse a Ping payload laxly, mirroring Go's `disco.parsePing` exactly: a body of at least 12
    /// bytes yields the transaction id, and the sender's node key is read **only if** at least
    /// `NodePublicKey::KEY_LEN_BYTES` (32) bytes remain after the tx id. Old clients (~1.16.0 and
    /// earlier) send a 12-byte Ping with no node key, so the node key is `Option`al; any bytes beyond
    /// `tx_id + node_key` are padding and ignored ("deliberately lax on longer-than-expected messages,
    /// for future compatibility"). Returns `None` only when the type byte isn't `Ping` or the body is
    /// shorter than the 12-byte tx id (Go's `errShort`).
    ///
    /// The strict [`as_msg::<Ping>`](Self::as_msg) requires the full fixed layout (12 + 32 + padding),
    /// so it drops a node-key-less pre-1.16 Ping entirely; this accessor matches Go's parse. (Whether
    /// such a node-key-less Ping is then *acted on* is a separate consumer-side binding decision.)
    pub fn ping_lax(&self) -> Option<([u8; PING_TX_ID_LEN], Option<NodePublicKey>)> {
        let pt = self.plaintext()?;
        if pt.ty() != Some(MessageType::Ping) {
            return None;
        }
        let body = &pt.message;
        // Go: `if len(p) < 12 { return nil, errShort }`.
        let tx_id: [u8; PING_TX_ID_LEN] = body.get(..PING_TX_ID_LEN)?.try_into().ok()?;
        // Go: `if len(p) >= key.NodePublicRawLen` (evaluated AFTER consuming the 12-byte tx id) read
        // the node key; otherwise leave it unset. Any trailing bytes are padding.
        let node_key = body
            .get(PING_TX_ID_LEN..)
            .and_then(|rest| NodePublicKey::read_from_prefix(rest).ok())
            .map(|(k, _rest)| k);
        Some((tx_id, node_key))
    }

    /// Parse a `CallMeMaybe` payload into its whole endpoints, **ignoring a trailing partial
    /// endpoint** — Go's `parseCallMeMaybe` is lax: a body that is not an exact multiple of the
    /// 18-byte endpoint size yields the whole leading endpoints, never an error. A short body
    /// (`< 18` bytes, including empty) therefore yields **no** endpoints rather than an error — note
    /// this is the *opposite* of the fixed messages' floor (e.g. [`as_msg_lax::<Pong>`](Self::as_msg_lax)
    /// rejects a too-short Pong), and matches Go's "soft-empty" CallMeMaybe behavior. The strict
    /// [`as_msg::<CallMeMaybe>`](Self::as_msg) instead requires an exact multiple, so it would drop
    /// the *entire* message on any trailing/extension bytes a forward-compatible peer might append.
    /// Returns `None` only if the message type doesn't match. A `version != 0` `CallMeMaybe` yields
    /// **no** endpoints (an empty iterator), matching Go's `parseCallMeMaybe`, which returns an empty
    /// message when `ver != 0` (it only parses endpoints for the version it understands) rather than
    /// erroring — so a future-version CallMeMaybe is tolerated, just carries no endpoints here.
    pub fn call_me_maybe_endpoints(&self) -> Option<impl Iterator<Item = &crate::Endpoint>> {
        let pt = self.plaintext()?;
        if pt.ty() != Some(crate::CallMeMaybe::TYPE) {
            return None;
        }
        // Go `parseCallMeMaybe`: `if len(p)%epLength != 0 || ver != 0 || len(p) == 0 { return m, nil }`
        // — a non-zero version produces an empty (not errored) message. Match that by parsing no
        // endpoints when the version isn't the one we understand.
        let message: &[u8] = if pt.version == Plaintext::VERSION {
            &pt.message
        } else {
            &[]
        };
        let ep_size = core::mem::size_of::<crate::Endpoint>();
        Some(
            message
                .chunks_exact(ep_size)
                .filter_map(|chunk| crate::Endpoint::ref_from_bytes(chunk).ok()),
        )
    }

    /// Convert the payload of this packet to a mutable reference to the given message type.
    ///
    /// Fails if the body could not be parsed or the type field doesn't match.
    pub fn as_msg_mut<T>(&mut self) -> Option<&mut T>
    where
        T: ?Sized
            + Message
            + zerocopy::Immutable
            + zerocopy::KnownLayout
            + zerocopy::FromBytes
            + zerocopy::IntoBytes,
    {
        let pt = self.plaintext_mut()?;

        if pt.ty() != Some(T::TYPE) {
            return None;
        }

        T::mut_from_bytes(&mut pt.message).ok()
    }

    /// Calculate the size of the buffer required to store a packet with a message payload
    /// of the given size.
    pub const fn size_for_message(message_size: usize) -> usize {
        size_of::<Header>()
            + AeadTaggedPayload::size_for_payload(Plaintext::size_for_message(message_size))
    }

    /// Allocate a [`Vec`][alloc::vec::Vec] to store a packet of the given size.
    #[cfg(feature = "alloc")]
    pub fn vec_for_message(message_size: usize) -> alloc::vec::Vec<u8> {
        alloc::vec![0; Self::size_for_message(message_size)]
    }

    /// Allocate a [`Box`][alloc::boxed::Box]ed slice to store a packet of the given size.
    #[cfg(feature = "alloc")]
    pub fn box_for_message(message_size: usize) -> alloc::boxed::Box<[u8]> {
        Self::vec_for_message(message_size).into_boxed_slice()
    }

    /// Check that this is a valid packet: the inner plaintext is well-formed (parses to at least
    /// the fixed header — version byte + message-type byte).
    ///
    /// The version byte is deliberately NOT rejected here. Go's `disco.Parse` (`disco/disco.go`)
    /// treats the version as a per-message-type advisory, not a packet-wide gate: `parsePing` /
    /// `parsePong` ignore it entirely (accept any version), and `parseCallMeMaybe` soft-empties when
    /// `version != 0`. So a future disco protocol bump that stays wire-compatible for Ping/Pong keeps
    /// working. Rejecting the whole datagram on a non-zero version (the old behavior) would drop a
    /// real Go peer's Ping/Pong after such a bump, silently forcing that peer permanently onto DERP.
    /// Per-type version handling lives in the typed accessors / the consumer instead. Unknown message
    /// types likewise do not fail here.
    pub fn validate(&self) -> Result<(), Error> {
        // Still require the plaintext to be at least the fixed header (version + type) so the typed
        // accessors can read the type byte; `ref_from_bytes` enforces that minimum size.
        Plaintext::ref_from_bytes(&self.payload.payload)?;

        Ok(())
    }

    fn plaintext(&self) -> Option<&Plaintext> {
        Plaintext::ref_from_bytes(&self.payload.payload).ok()
    }

    fn plaintext_mut(&mut self) -> Option<&mut Plaintext> {
        Plaintext::mut_from_bytes(&mut self.payload.payload).ok()
    }
}

impl Packet<Encrypted> {
    /// Try to cast the given bytes to an encrypted packet.
    ///
    /// Fails if the format is invalid or the header magic bytes were incorrect.
    pub fn from_encrypted_bytes(b: &[u8]) -> Result<&Self, Error> {
        let slf = Self::try_ref_from_bytes(b)?;
        slf.header.validate()?;

        Ok(slf)
    }

    /// Try to cast the given bytes to a mutable encrypted packet.
    ///
    /// Fails if the format is invalid or the header magic bytes were incorrect.
    pub fn from_encrypted_bytes_mut(b: &mut [u8]) -> Result<&mut Self, Error> {
        let slf = Self::try_mut_from_bytes(b)?;
        slf.header.validate()?;

        Ok(slf)
    }

    /// Get a reference to the payload bytes.
    pub const fn payload_bytes(&self) -> &[u8] {
        &self.payload.payload
    }

    /// Decrypt this packet, turning it into a [`Packet<Plaintext>`].
    pub fn decrypt_in_place(
        &mut self,
        secret: &DiscoPrivateKey,
    ) -> Result<&mut Packet<Plaintext>, Error> {
        crypto_box::SalsaBox::new(&self.header.sender_pub.into(), &secret.into())
            .decrypt_in_place_detached(
                &self.header.nonce.into(),
                &[],
                &mut self.payload.payload,
                Tag::from_slice(&self.payload.tag),
            )
            .map_err(|_e| Error::CryptoFailed)?;

        let bs = self.as_mut_bytes();
        let ret = Packet::mut_from_bytes(bs)?;
        ret.validate()?;

        Ok(ret)
    }
}
