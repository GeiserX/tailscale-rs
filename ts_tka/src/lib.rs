#![doc = include_str!("../README.md")]

//! # Overview
//!
//! This crate implements the **client-side verification** path of Tailscale's Tailnet Lock (TKA),
//! mirroring Go's `tka` package. The pieces:
//!
//! - [`cbor`]: a CTAP2-canonical CBOR encoder, so a value's signing digest is byte-identical to
//!   Go's `fxamacker/cbor` (CTAP2 mode) output.
//! - [`AumHash`]: a BLAKE2s-256 hash with RFC4648 base32 (no padding) text encoding — the type
//!   `TkaInfo.head` carries on the wire.
//! - [`Aum`] / [`AumKind`] / [`Key`] / [`NodeKeySignature`]: the wire types, with canonical
//!   serialization + signing-digest helpers.
//! - [`Authority`]: holds the current trusted-key [`State`] and exposes
//!   [`Authority::node_key_authorized`], the check that a peer's node key is signed by a key trusted
//!   under the current tailnet-lock state.
//!
//! ## Fail-closed + validation gap
//!
//! Verification is fail-closed: any decode/shape/signature problem denies authorization. **Caveat:**
//! the CTAP2-CBOR byte-exactness has not been cross-validated against Go-produced test vectors in
//! this fork, so byte-for-byte wire compatibility with a live Tailscale TKA is asserted by
//! construction, not proven. Treat a *successful* verification as advisory until vectors land;
//! a *failed* verification is always safe to act on (deny).

extern crate alloc;

use alloc::{string::String, vec::Vec};

use blake2::{Blake2s256, Digest};

pub mod cbor;

use cbor::Value;

/// Length in bytes of an [`AumHash`] (BLAKE2s-256 output).
pub const AUM_HASH_LEN: usize = 32;

/// Maximum nesting depth allowed when decoding/verifying a [`NodeKeySignature`] and its CBOR.
///
/// A peer-supplied signature CBOR is attacker-controlled and cheap to nest arbitrarily deep (a few
/// bytes per level). Without a bound, the recursive decoder/verifier overflows the stack and aborts
/// the process (DoS). Go bounds this. Real TKA rotation chains are short (a handful of links), so a
/// cap of 16 sits comfortably above any legitimate chain while staying far below stack-overflow.
/// Enforced at DECODE time (before any crypto), and also bounds generic CBOR container nesting.
const MAX_SIG_NESTING_DEPTH: usize = 16;

/// A BLAKE2s-256 hash of an AUM's canonical serialization. Identifies an AUM and links the chain
/// (`PrevAUMHash`). Text form is RFC4648 standard base32, no padding (Go `AUMHash.MarshalText`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AumHash(pub [u8; AUM_HASH_LEN]);

impl AumHash {
    /// Decode an `AumHash` from its base32 (no-pad, RFC4648 standard alphabet) text form, as found
    /// in `TkaInfo.head`. Returns `None` if the text is not exactly 32 decoded bytes.
    pub fn from_base32(text: &str) -> Option<AumHash> {
        let decoded = base32_decode_nopad(text)?;
        if decoded.len() != AUM_HASH_LEN {
            return None;
        }
        let mut h = [0u8; AUM_HASH_LEN];
        h.copy_from_slice(&decoded);
        Some(AumHash(h))
    }

    /// Encode this hash as base32 (no-pad, standard alphabet) — the wire/text form.
    pub fn to_base32(&self) -> String {
        base32_encode_nopad(&self.0)
    }
}

/// The kind of an [`Aum`] (Go `AUMKind`; integer values are wire-stable, do not reorder).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AumKind {
    /// Invalid / unset (0).
    Invalid = 0,
    /// Add a trusted key (1).
    AddKey = 1,
    /// Remove a trusted key (2).
    RemoveKey = 2,
    /// No-op (3).
    NoOp = 3,
    /// Update an existing key's votes/metadata (4).
    UpdateKey = 4,
    /// Checkpoint: a full state snapshot (5).
    Checkpoint = 5,
}

impl AumKind {
    /// Decode an [`AumKind`] from its wire integer, or `None` for an unknown kind. Provided for a
    /// future AUM-chain replayer (the admin-side authority-derivation half), which is out of scope
    /// for the current client-verify path.
    pub fn from_u8(n: u8) -> Option<AumKind> {
        Some(match n {
            0 => AumKind::Invalid,
            1 => AumKind::AddKey,
            2 => AumKind::RemoveKey,
            3 => AumKind::NoOp,
            4 => AumKind::UpdateKey,
            5 => AumKind::Checkpoint,
            _ => return None,
        })
    }
}

/// The kind of a TKA [`Key`] (Go `KeyKind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// Ed25519 trusted key (Go `Key25519` = 1).
    Ed25519,
}

/// A trusted TKA key (Go `tka.Key`). Its [`Key::id`] (the 32-byte public key for Ed25519) is what an
/// [`Aum`] / [`NodeKeySignature`] references via `KeyID`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    /// Key algorithm.
    pub kind: KeyKind,
    /// Voting weight (Go `Votes`, valid range 1..=4096).
    pub votes: u32,
    /// The raw public key bytes (32 for Ed25519).
    pub public: Vec<u8>,
}

impl Key {
    /// The key id: for Ed25519 this is the public key verbatim (Go `Key.ID`).
    pub fn id(&self) -> &[u8] {
        &self.public
    }
}

/// The kind of a [`NodeKeySignature`] (Go `SigKind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SigKind {
    /// Invalid (0).
    Invalid = 0,
    /// Directly signs a node key with a trusted key (1).
    Direct = 1,
    /// Signs a rotated node key, nesting the prior signature (2).
    Rotation = 2,
    /// A credential signature; cannot authorize a node on its own (3).
    Credential = 3,
}

impl SigKind {
    fn from_u8(n: u8) -> Option<SigKind> {
        Some(match n {
            0 => SigKind::Invalid,
            1 => SigKind::Direct,
            2 => SigKind::Rotation,
            3 => SigKind::Credential,
            _ => return None,
        })
    }
}

/// A node-key signature (Go `tka.NodeKeySignature`): proof that a node's key is authorized under the
/// tailnet-lock authority. Decoded from the CBOR blob a peer presents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeKeySignature {
    /// Signature kind.
    pub sig_kind: SigKind,
    /// The node public key this signature authorizes (Go `Pubkey`).
    pub pubkey: Vec<u8>,
    /// The id of the trusted [`Key`] that signed this (Go `KeyID`).
    pub key_id: Vec<u8>,
    /// The Ed25519 signature bytes.
    pub signature: Vec<u8>,
    /// For [`SigKind::Rotation`], the nested (prior) signature.
    pub nested: Option<alloc::boxed::Box<NodeKeySignature>>,
    /// For rotation, the wrapping public key the nested signature authorized.
    pub wrapping_pubkey: Vec<u8>,
}

/// Errors from TKA verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TkaError {
    /// The CBOR blob could not be decoded into the expected shape.
    Decode(&'static str),
    /// A signature failed to verify cryptographically.
    BadSignature,
    /// The authorizing key is not trusted in the current authority state.
    UntrustedKey,
    /// A credential signature was presented where a node-authorizing signature was required.
    CredentialCannotAuthorize,
    /// The presented signature does not cover the given node key.
    NodeKeyMismatch,
}

impl core::fmt::Display for TkaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TkaError::Decode(s) => write!(f, "TKA decode error: {s}"),
            TkaError::BadSignature => write!(f, "TKA signature verification failed"),
            TkaError::UntrustedKey => write!(f, "TKA authorizing key is not trusted"),
            TkaError::CredentialCannotAuthorize => {
                write!(f, "a credential signature cannot authorize a node")
            }
            TkaError::NodeKeyMismatch => write!(f, "signature does not cover this node key"),
        }
    }
}

impl core::error::Error for TkaError {}

impl NodeKeySignature {
    /// The canonical CBOR serialization of this signature with the `Signature` field nil'd, used as
    /// the signing-digest preimage (Go `NodeKeySignature.SigHash` zeroes `Signature` then
    /// serializes).
    fn sig_hash(&self) -> [u8; AUM_HASH_LEN] {
        let v = self.to_cbor(/* include_signature = */ false);
        blake2s_256(&v.to_vec())
    }

    /// Build the CBOR value for this signature. When `include_signature` is false, the signature
    /// field (key 4) is omitted (the SigHash preimage).
    fn to_cbor(&self, include_signature: bool) -> Value {
        cbor::int_map([
            (1, Some(Value::Uint(self.sig_kind as u8 as u64))),
            (2, nonempty_bytes(&self.pubkey)),
            (3, nonempty_bytes(&self.key_id)),
            (
                4,
                if include_signature {
                    nonempty_bytes(&self.signature)
                } else {
                    None
                },
            ),
            (5, self.nested.as_ref().map(|n| n.to_cbor(true))),
            (6, nonempty_bytes(&self.wrapping_pubkey)),
        ])
    }

    /// The key id that ultimately roots this signature in a trusted key (Go `authorizingKeyID`):
    /// for a rotation, recurse into the nested signature; otherwise this signature's `key_id`.
    fn authorizing_key_id(&self) -> Result<&[u8], TkaError> {
        match self.sig_kind {
            SigKind::Rotation => self
                .nested
                .as_ref()
                .ok_or(TkaError::Decode("rotation signature missing nested"))?
                .authorizing_key_id(),
            SigKind::Direct | SigKind::Credential => Ok(&self.key_id),
            SigKind::Invalid => Err(TkaError::Decode("invalid signature kind")),
        }
    }

    /// Verify this signature authorizes `node_key`, rooted in the trusted `verification_key` (Go
    /// `NodeKeySignature.verifySignature`).
    fn verify_signature(&self, node_key: &[u8], verification_key: &Key) -> Result<(), TkaError> {
        // For non-credential signatures the signed pubkey must equal the node key being authorized.
        if self.sig_kind != SigKind::Credential && self.pubkey != node_key {
            return Err(TkaError::NodeKeyMismatch);
        }

        let sig_hash = self.sig_hash();

        match self.sig_kind {
            SigKind::Rotation => {
                let nested = self
                    .nested
                    .as_ref()
                    .ok_or(TkaError::Decode("rotation signature missing nested"))?;
                // The outer rotation signature is verified with STANDARD ed25519 against the nested
                // signature's wrapping public key.
                let verify_pub = &nested.wrapping_pubkey;
                if verify_pub.len() != 32 {
                    return Err(TkaError::Decode("wrapping pubkey wrong length"));
                }
                verify_ed25519_std(verify_pub, &sig_hash, &self.signature)?;
                // The nested signature must cover the rotation pivot (`verify_pub`). For a nested
                // Direct this is enforced inside its own `verify_signature` (the non-credential
                // `pubkey != node_key` check). A nested Credential SKIPS that check, so bind it
                // here: the credential must cover exactly the wrapping pubkey it is rotating, or an
                // attacker could splice an unrelated valid credential into the chain.
                if nested.sig_kind == SigKind::Credential && nested.pubkey != *verify_pub {
                    return Err(TkaError::NodeKeyMismatch);
                }
                // Then the nested signature must itself be valid, rooting in the trusted key.
                nested.verify_signature(verify_pub, verification_key)
            }
            SigKind::Direct | SigKind::Credential => {
                if self.nested.is_some() {
                    return Err(TkaError::Decode("direct/credential signature has nested"));
                }
                if verification_key.kind != KeyKind::Ed25519 || verification_key.public.len() != 32
                {
                    return Err(TkaError::Decode("verification key not ed25519"));
                }
                // Direct/credential signatures verify with ZIP-215 (cofactored) ed25519, matching
                // Go's `ed25519consensus.Verify`.
                verify_ed25519_zip215(&verification_key.public, &sig_hash, &self.signature)
            }
            SigKind::Invalid => Err(TkaError::Decode("invalid signature kind")),
        }
    }
}

/// The current authority state (Go `tka.State`): the set of trusted keys at a given chain head.
/// This is the minimal slice a client needs for [`Authority::node_key_authorized`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct State {
    /// The trusted keys.
    pub keys: Vec<Key>,
}

impl State {
    /// Find a trusted key by its id (Go `State.GetKey`).
    pub fn get_key(&self, key_id: &[u8]) -> Option<&Key> {
        self.keys.iter().find(|k| k.id() == key_id)
    }
}

/// A tailnet-lock authority as a client tracks it: the current trusted-key [`State`] and the chain
/// `head`. Built by replaying the AUM chain (or from a control-provided checkpoint); the client
/// then uses [`Authority::node_key_authorized`] to decide whether a peer is trusted.
#[derive(Debug, Clone)]
pub struct Authority {
    head: AumHash,
    state: State,
}

impl Authority {
    /// Construct an authority directly from a known `head` and trusted-key `state` (e.g. a
    /// control-provided checkpoint the client already trusts).
    pub fn from_state(head: AumHash, state: State) -> Authority {
        Authority { head, state }
    }

    /// The current chain head hash (Go `Authority.Head`).
    pub fn head(&self) -> AumHash {
        self.head
    }

    /// The trusted-key state.
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Whether `head` (e.g. decoded from `TkaInfo.head`) matches this authority's head. A client
    /// that finds a mismatch must resync before trusting verifications.
    pub fn head_matches(&self, head: &AumHash) -> bool {
        &self.head == head
    }

    /// Verify that `node_key` is authorized under the current authority state by the given
    /// node-key-signature CBOR blob (Go `Authority.NodeKeyAuthorized`).
    ///
    /// Fail-closed: a credential-only signature, an untrusted authorizing key, a malformed blob, or
    /// a bad signature all return `Err`.
    pub fn node_key_authorized(
        &self,
        node_key: &[u8],
        signature_cbor: &[u8],
    ) -> Result<(), TkaError> {
        let sig = decode_node_key_signature(signature_cbor)?;
        // A credential signature can never authorize a node on its own.
        if sig.sig_kind == SigKind::Credential {
            return Err(TkaError::CredentialCannotAuthorize);
        }
        let key_id = sig.authorizing_key_id()?;
        let key = self.state.get_key(key_id).ok_or(TkaError::UntrustedKey)?;
        sig.verify_signature(node_key, key)
    }
}

/// Compute the [`AumHash`] of an AUM given its canonical CBOR serialization. Exposed so a chain
/// replayer can link AUMs (`PrevAUMHash`) without re-deriving the hash function.
pub fn aum_hash(canonical_cbor: &[u8]) -> AumHash {
    AumHash(blake2s_256(canonical_cbor))
}

fn blake2s_256(data: &[u8]) -> [u8; AUM_HASH_LEN] {
    let mut hasher = Blake2s256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut h = [0u8; AUM_HASH_LEN];
    h.copy_from_slice(&out);
    h
}

/// `Some(Bytes)` when `b` is non-empty, else `None` — the `omitempty` rule for byte fields.
fn nonempty_bytes(b: &[u8]) -> Option<Value> {
    if b.is_empty() {
        None
    } else {
        Some(Value::Bytes(b.to_vec()))
    }
}

/// Verify a standard (RFC 8032, non-cofactored) Ed25519 signature.
fn verify_ed25519_std(public: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), TkaError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let pk: [u8; 32] = public
        .try_into()
        .map_err(|_| TkaError::Decode("bad pubkey len"))?;
    let vk = VerifyingKey::from_bytes(&pk).map_err(|_| TkaError::Decode("bad ed25519 pubkey"))?;
    let sig: [u8; 64] = sig
        .try_into()
        .map_err(|_| TkaError::Decode("bad sig len"))?;
    vk.verify(msg, &Signature::from_bytes(&sig))
        .map_err(|_| TkaError::BadSignature)
}

/// Verify a ZIP-215 (cofactored) Ed25519 signature, matching Go `ed25519consensus.Verify`.
fn verify_ed25519_zip215(public: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), TkaError> {
    let pk: [u8; 32] = public
        .try_into()
        .map_err(|_| TkaError::Decode("bad pubkey len"))?;
    let vk = ed25519_zebra::VerificationKey::try_from(pk)
        .map_err(|_| TkaError::Decode("bad ed25519 pubkey"))?;
    let sig_bytes: [u8; 64] = sig
        .try_into()
        .map_err(|_| TkaError::Decode("bad sig len"))?;
    let sig = ed25519_zebra::Signature::from(sig_bytes);
    vk.verify(&sig, msg).map_err(|_| TkaError::BadSignature)
}

/// Decode a [`NodeKeySignature`] from canonical CBOR. This is a minimal decoder for the exact map
/// shape Go emits (integer keys 1..=6); anything else is rejected (fail-closed).
fn decode_node_key_signature(buf: &[u8]) -> Result<NodeKeySignature, TkaError> {
    let (val, rest) = decode_value(buf, 0)?;
    if !rest.is_empty() {
        return Err(TkaError::Decode("trailing bytes after signature"));
    }
    node_key_signature_from_value(val, 0)
}

fn node_key_signature_from_value(val: Value, depth: usize) -> Result<NodeKeySignature, TkaError> {
    if depth > MAX_SIG_NESTING_DEPTH {
        return Err(TkaError::Decode("nested signature too deep"));
    }
    let Value::IntMap(entries) = val else {
        return Err(TkaError::Decode("signature is not an int-keyed map"));
    };
    let mut sig_kind = None;
    let mut pubkey = Vec::new();
    let mut key_id = Vec::new();
    let mut signature = Vec::new();
    let mut nested = None;
    let mut wrapping_pubkey = Vec::new();

    for (k, v) in entries {
        match k {
            1 => {
                let Value::Uint(n) = v else {
                    return Err(TkaError::Decode("sig kind not uint"));
                };
                sig_kind = Some(
                    SigKind::from_u8(
                        u8::try_from(n).map_err(|_| TkaError::Decode("sig kind range"))?,
                    )
                    .ok_or(TkaError::Decode("unknown sig kind"))?,
                );
            }
            2 => pubkey = expect_bytes(v)?,
            3 => key_id = expect_bytes(v)?,
            4 => signature = expect_bytes(v)?,
            5 => {
                nested = Some(alloc::boxed::Box::new(node_key_signature_from_value(
                    v,
                    depth + 1,
                )?))
            }
            6 => wrapping_pubkey = expect_bytes(v)?,
            _ => return Err(TkaError::Decode("unknown signature field")),
        }
    }

    Ok(NodeKeySignature {
        sig_kind: sig_kind.ok_or(TkaError::Decode("signature missing kind"))?,
        pubkey,
        key_id,
        signature,
        nested,
        wrapping_pubkey,
    })
}

fn expect_bytes(v: Value) -> Result<Vec<u8>, TkaError> {
    match v {
        Value::Bytes(b) => Ok(b),
        _ => Err(TkaError::Decode("expected byte string")),
    }
}

/// Decode one CBOR value (the subset the encoder produces) from `buf`, returning the value and the
/// remaining bytes. Minimal — only the major types TKA uses.
fn decode_value(buf: &[u8], depth: usize) -> Result<(Value, &[u8]), TkaError> {
    // Bound generic CBOR container nesting so a deeply-nested array/map (even a non-signature one)
    // cannot overflow the recursive decoder before signature-shape validation runs.
    if depth > MAX_SIG_NESTING_DEPTH {
        return Err(TkaError::Decode("nested signature too deep"));
    }
    let (major, arg, rest) = decode_head(buf)?;
    match major {
        0 => Ok((Value::Uint(arg), rest)),
        2 => {
            let len = arg as usize;
            if rest.len() < len {
                return Err(TkaError::Decode("byte string truncated"));
            }
            Ok((Value::Bytes(rest[..len].to_vec()), &rest[len..]))
        }
        3 => {
            let len = arg as usize;
            if rest.len() < len {
                return Err(TkaError::Decode("text string truncated"));
            }
            Ok((Value::Text(rest[..len].to_vec()), &rest[len..]))
        }
        4 => {
            let mut items = Vec::new();
            let mut cur = rest;
            for _ in 0..arg {
                let (v, next) = decode_value(cur, depth + 1)?;
                items.push(v);
                cur = next;
            }
            Ok((Value::Array(items), cur))
        }
        5 => {
            let mut entries: Vec<(u64, Value)> = Vec::new();
            let mut cur = rest;
            for _ in 0..arg {
                let (k, next) = decode_head(cur).and_then(|(m, a, r)| {
                    if m == 0 {
                        Ok((a, r))
                    } else {
                        Err(TkaError::Decode("map key not uint"))
                    }
                })?;
                // CTAP2/Go reject duplicate map keys; do the same (fail-closed) rather than
                // silently last-wins.
                if entries.iter().any(|(existing, _)| *existing == k) {
                    return Err(TkaError::Decode("duplicate map key"));
                }
                let (v, next2) = decode_value(next, depth + 1)?;
                entries.push((k, v));
                cur = next2;
            }
            Ok((Value::IntMap(entries), cur))
        }
        _ => Err(TkaError::Decode("unsupported CBOR major type")),
    }
}

/// Decode a CBOR head: returns `(major, argument, rest)`.
fn decode_head(buf: &[u8]) -> Result<(u8, u64, &[u8]), TkaError> {
    let first = *buf.first().ok_or(TkaError::Decode("empty CBOR"))?;
    let major = first >> 5;
    let info = first & 0x1f;
    let rest = &buf[1..];
    let (arg, rest) = match info {
        n @ 0..=23 => (n as u64, rest),
        24 => {
            let b = *rest.first().ok_or(TkaError::Decode("truncated u8"))?;
            (b as u64, &rest[1..])
        }
        25 => {
            if rest.len() < 2 {
                return Err(TkaError::Decode("truncated u16"));
            }
            (u16::from_be_bytes([rest[0], rest[1]]) as u64, &rest[2..])
        }
        26 => {
            if rest.len() < 4 {
                return Err(TkaError::Decode("truncated u32"));
            }
            (
                u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as u64,
                &rest[4..],
            )
        }
        27 => {
            if rest.len() < 8 {
                return Err(TkaError::Decode("truncated u64"));
            }
            let mut b = [0u8; 8];
            b.copy_from_slice(&rest[..8]);
            (u64::from_be_bytes(b), &rest[8..])
        }
        _ => return Err(TkaError::Decode("indefinite/reserved CBOR length")),
    };
    Ok((major, arg, rest))
}

// ----- RFC 4648 base32 (standard alphabet, no padding) -----

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn base32_encode_nopad(data: &[u8]) -> String {
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        buffer = (buffer << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            out.push(BASE32_ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(BASE32_ALPHABET[idx] as char);
    }
    out
}

fn base32_decode_nopad(text: &str) -> Option<Vec<u8>> {
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    for c in text.chars() {
        let val = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            '2'..='7' => c as u32 - '2' as u32 + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_roundtrip_32_bytes() {
        let h = AumHash([0xABu8; 32]);
        let text = h.to_base32();
        let back = AumHash::from_base32(&text).unwrap();
        assert_eq!(h, back);
    }

    #[test]
    fn base32_rejects_wrong_length() {
        // "AAAA" decodes to fewer than 32 bytes.
        assert!(AumHash::from_base32("AAAA").is_none());
        // Lowercase / invalid alphabet rejected.
        assert!(AumHash::from_base32("aaaa").is_none());
    }

    #[test]
    fn base32_matches_known_vector() {
        // RFC 4648 base32 of "foobar" is "MZXW6YTBOI" (with padding "======"); no-pad drops the pad.
        assert_eq!(base32_encode_nopad(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32_decode_nopad("MZXW6YTBOI").unwrap(), b"foobar");
    }

    #[test]
    fn credential_signature_cannot_authorize() {
        let auth = Authority::from_state(AumHash([0; 32]), State::default());
        let sig = NodeKeySignature {
            sig_kind: SigKind::Credential,
            pubkey: alloc::vec![1, 2, 3],
            key_id: alloc::vec![4, 5, 6],
            signature: alloc::vec![0; 64],
            nested: None,
            wrapping_pubkey: Vec::new(),
        };
        let cbor = sig.to_cbor(true).to_vec();
        let err = auth.node_key_authorized(&[1, 2, 3], &cbor).unwrap_err();
        assert_eq!(err, TkaError::CredentialCannotAuthorize);
    }

    #[test]
    fn untrusted_key_denied() {
        // A direct signature whose key id is not in the (empty) trusted state.
        let auth = Authority::from_state(AumHash([0; 32]), State::default());
        let sig = NodeKeySignature {
            sig_kind: SigKind::Direct,
            pubkey: alloc::vec![9; 32],
            key_id: alloc::vec![7; 32],
            signature: alloc::vec![0; 64],
            nested: None,
            wrapping_pubkey: Vec::new(),
        };
        let cbor = sig.to_cbor(true).to_vec();
        let err = auth.node_key_authorized(&[9; 32], &cbor).unwrap_err();
        assert_eq!(err, TkaError::UntrustedKey);
    }

    #[test]
    fn direct_signature_verifies_end_to_end() {
        use ed25519_dalek::{Signer, SigningKey};

        // A trusted Ed25519 key signs a node key directly.
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let trusted_pub = signing.verifying_key().to_bytes().to_vec();
        let node_key = alloc::vec![7u8; 32];

        let trusted = Key {
            kind: KeyKind::Ed25519,
            votes: 1,
            public: trusted_pub.clone(),
        };
        let auth = Authority::from_state(
            AumHash([0; 32]),
            State {
                keys: alloc::vec![trusted],
            },
        );

        // Build the signature, compute its sig-hash preimage, sign, then fill in the signature.
        let mut sig = NodeKeySignature {
            sig_kind: SigKind::Direct,
            pubkey: node_key.clone(),
            key_id: trusted_pub.clone(),
            signature: Vec::new(),
            nested: None,
            wrapping_pubkey: Vec::new(),
        };
        let sig_hash = sig.sig_hash();
        // NOTE: Go verifies Direct with ZIP-215; a standard ed25519-dalek signature is accepted by
        // ZIP-215 verification (ZIP-215 is a superset), so signing with dalek here is valid.
        sig.signature = signing.sign(&sig_hash).to_bytes().to_vec();

        let cbor = sig.to_cbor(true).to_vec();
        assert!(auth.node_key_authorized(&node_key, &cbor).is_ok());

        // A different node key must NOT be authorized by this signature.
        let other = alloc::vec![8u8; 32];
        assert_eq!(
            auth.node_key_authorized(&other, &cbor).unwrap_err(),
            TkaError::NodeKeyMismatch
        );
    }

    #[test]
    fn tampered_signature_denied() {
        use ed25519_dalek::{Signer, SigningKey};

        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let trusted_pub = signing.verifying_key().to_bytes().to_vec();
        let node_key = alloc::vec![7u8; 32];
        let auth = Authority::from_state(
            AumHash([0; 32]),
            State {
                keys: alloc::vec![Key {
                    kind: KeyKind::Ed25519,
                    votes: 1,
                    public: trusted_pub.clone(),
                }],
            },
        );
        let mut sig = NodeKeySignature {
            sig_kind: SigKind::Direct,
            pubkey: node_key.clone(),
            key_id: trusted_pub,
            signature: Vec::new(),
            nested: None,
            wrapping_pubkey: Vec::new(),
        };
        let sig_hash = sig.sig_hash();
        let mut sigbytes = signing.sign(&sig_hash).to_bytes();
        sigbytes[0] ^= 0xff; // tamper
        sig.signature = sigbytes.to_vec();

        let cbor = sig.to_cbor(true).to_vec();
        assert_eq!(
            auth.node_key_authorized(&node_key, &cbor).unwrap_err(),
            TkaError::BadSignature
        );
    }

    #[test]
    fn head_matches_check() {
        let h = AumHash([5u8; 32]);
        let auth = Authority::from_state(h, State::default());
        assert!(auth.head_matches(&h));
        assert!(!auth.head_matches(&AumHash([6u8; 32])));
    }

    // ----- Fix 1: depth cap on attacker-controlled nesting -----

    #[test]
    fn deeply_nested_signature_rejected_without_overflow() {
        // Wrap a NodeKeySignature inside `nested` far past MAX_SIG_NESTING_DEPTH. This is cheap to
        // construct (a few bytes per level) and would overflow an unbounded recursive decoder. The
        // decoder must reject it as a Decode error — never panic / stack-overflow.
        let mut sig = NodeKeySignature {
            sig_kind: SigKind::Direct,
            pubkey: alloc::vec![1u8; 32],
            key_id: alloc::vec![2u8; 32],
            signature: alloc::vec![3u8; 64],
            nested: None,
            wrapping_pubkey: Vec::new(),
        };
        for _ in 0..(MAX_SIG_NESTING_DEPTH + 8) {
            sig = NodeKeySignature {
                sig_kind: SigKind::Rotation,
                pubkey: alloc::vec![1u8; 32],
                key_id: Vec::new(),
                signature: alloc::vec![3u8; 64],
                nested: Some(alloc::boxed::Box::new(sig)),
                wrapping_pubkey: alloc::vec![1u8; 32],
            };
        }
        let cbor = sig.to_cbor(true).to_vec();
        let err = decode_node_key_signature(&cbor).unwrap_err();
        assert_eq!(err, TkaError::Decode("nested signature too deep"));
    }

    // ----- Fix 5: duplicate CBOR map keys rejected -----

    #[test]
    fn duplicate_map_key_rejected() {
        // Hand-craft a CBOR map with key 1 repeated: map(2) { 1:0, 1:1 } => 0xa2 01 00 01 01.
        let blob = [0xa2u8, 0x01, 0x00, 0x01, 0x01];
        let err = decode_node_key_signature(&blob).unwrap_err();
        assert_eq!(err, TkaError::Decode("duplicate map key"));
    }

    // ----- Fix 3: rotation-chain happy path + ZIP-215/std split -----

    // ZIP-215 vs standard ed25519 in TKA, and why this crate carries BOTH verifiers:
    //
    //   * Direct/Credential signatures are verified with `verify_ed25519_zip215` (ed25519-zebra),
    //     matching Go `ed25519consensus.Verify` — the *cofactored* ZIP-215 rule the TKA leaf
    //     signatures are produced under. ZIP-215 is a strict superset of RFC 8032: any standard
    //     (dalek) signature is accepted by it, which is why the tests below can sign leaves with
    //     dalek and still verify under zebra.
    //   * The outer rotation WRAP signature is verified with `verify_ed25519_std` (ed25519-dalek),
    //     matching Go's plain `ed25519.Verify` for the rotation wrap. Collapsing these two
    //     verifiers into one would silently diverge from Go on the wire — hence both deps are kept
    //     (see Cargo.toml comment).
    #[test]
    fn rotation_chain_verifies_end_to_end() {
        use ed25519_dalek::{Signer, SigningKey};

        // Trusted key signs the inner Direct over the wrapping (pivot) pubkey.
        let trusted = SigningKey::from_bytes(&[7u8; 32]);
        let trusted_pub = trusted.verifying_key().to_bytes().to_vec();

        // The rotation pivot: a fresh keypair whose public key the inner Direct authorizes and
        // whose private key signs the outer rotation wrap.
        let wrapping = SigningKey::from_bytes(&[9u8; 32]);
        let wrapping_pub = wrapping.verifying_key().to_bytes().to_vec();

        let node_key = alloc::vec![5u8; 32];

        let auth = Authority::from_state(
            AumHash([0; 32]),
            State {
                keys: alloc::vec![Key {
                    kind: KeyKind::Ed25519,
                    votes: 1,
                    public: trusted_pub.clone(),
                }],
            },
        );

        // Inner Direct: trusted key authorizes the wrapping pubkey. Verified ZIP-215, so a dalek
        // signature is accepted.
        let mut inner = NodeKeySignature {
            sig_kind: SigKind::Direct,
            pubkey: wrapping_pub.clone(),
            key_id: trusted_pub.clone(),
            signature: Vec::new(),
            nested: None,
            wrapping_pubkey: wrapping_pub.clone(),
        };
        let inner_hash = inner.sig_hash();
        inner.signature = trusted.sign(&inner_hash).to_bytes().to_vec();

        // Outer Rotation: signs the node key with the wrapping key (verified STANDARD ed25519).
        let mut outer = NodeKeySignature {
            sig_kind: SigKind::Rotation,
            pubkey: node_key.clone(),
            key_id: Vec::new(),
            signature: Vec::new(),
            nested: Some(alloc::boxed::Box::new(inner)),
            wrapping_pubkey: Vec::new(),
        };
        let outer_hash = outer.sig_hash();
        outer.signature = wrapping.sign(&outer_hash).to_bytes().to_vec();

        let cbor = outer.to_cbor(true).to_vec();
        assert!(auth.node_key_authorized(&node_key, &cbor).is_ok());

        // A tampered rotation-wrap signature must be rejected by the STANDARD ed25519 verifier.
        let mut tampered = outer.clone();
        let mut sb = tampered.signature.clone();
        sb[0] ^= 0xff;
        tampered.signature = sb;
        let cbor_bad = tampered.to_cbor(true).to_vec();
        assert_eq!(
            auth.node_key_authorized(&node_key, &cbor_bad).unwrap_err(),
            TkaError::BadSignature
        );
    }

    // ----- Fix 2: nested-Credential pubkey must bind to the rotation pivot -----

    #[test]
    fn rotation_nested_credential_pubkey_bind() {
        use ed25519_dalek::{Signer, SigningKey};

        let trusted = SigningKey::from_bytes(&[11u8; 32]);
        let trusted_pub = trusted.verifying_key().to_bytes().to_vec();
        let wrapping = SigningKey::from_bytes(&[13u8; 32]);
        let wrapping_pub = wrapping.verifying_key().to_bytes().to_vec();
        let node_key = alloc::vec![6u8; 32];

        let auth = Authority::from_state(
            AumHash([0; 32]),
            State {
                keys: alloc::vec![Key {
                    kind: KeyKind::Ed25519,
                    votes: 1,
                    public: trusted_pub.clone(),
                }],
            },
        );

        // Helper: build a rotation wrapping a nested Credential whose `pubkey` is `cred_pubkey`.
        let build = |cred_pubkey: Vec<u8>| -> Vec<u8> {
            let mut inner = NodeKeySignature {
                sig_kind: SigKind::Credential,
                pubkey: cred_pubkey,
                key_id: trusted_pub.clone(),
                signature: Vec::new(),
                nested: None,
                wrapping_pubkey: wrapping_pub.clone(),
            };
            let inner_hash = inner.sig_hash();
            inner.signature = trusted.sign(&inner_hash).to_bytes().to_vec();

            let mut outer = NodeKeySignature {
                sig_kind: SigKind::Rotation,
                pubkey: node_key.clone(),
                key_id: Vec::new(),
                signature: Vec::new(),
                nested: Some(alloc::boxed::Box::new(inner)),
                wrapping_pubkey: Vec::new(),
            };
            let outer_hash = outer.sig_hash();
            outer.signature = wrapping.sign(&outer_hash).to_bytes().to_vec();
            outer.to_cbor(true).to_vec()
        };

        // Matching: credential covers exactly the wrapping pivot pubkey -> accepted.
        let cbor_ok = build(wrapping_pub.clone());
        assert!(auth.node_key_authorized(&node_key, &cbor_ok).is_ok());

        // Mismatch: credential covers an unrelated pubkey -> rejected (NodeKeyMismatch), even though
        // the credential is otherwise signed by the trusted key.
        let cbor_bad = build(alloc::vec![0xaau8; 32]);
        assert_eq!(
            auth.node_key_authorized(&node_key, &cbor_bad).unwrap_err(),
            TkaError::NodeKeyMismatch
        );
    }
}
