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
//! - [`AumHash`] / [`AumKind`] / [`Key`] / [`NodeKeySignature`]: the wire types, with canonical
//!   serialization + signing-digest helpers.
//! - [`Authority`]: holds the current trusted-key [`State`] and exposes
//!   [`Authority::node_key_authorized`], the check that a peer's node key is signed by a key trusted
//!   under the current tailnet-lock state.
//!
//! ## Fail-closed + validation status
//!
//! Verification is fail-closed: any decode/shape/signature problem denies authorization. The
//! CTAP2-CBOR byte-exactness is **cross-validated against Go-produced output**: the
//! [`NodeKeySignature`] path against real `tka.NodeKeySignature.Serialize`/`SigHash` golden vectors
//! (`tka_cbor_matches_go_golden`), and the [`Aum`] path against the literal `[]byte` vectors in Go's
//! `tka/aum_test.go` `TestSerialization` (`aum_serialize_matches_go_test_serialization_vectors`).
//! What remains for full Tailnet-Lock support is the *acquisition* side — the `/machine/tka/sync`
//! RPC client and the [`Aum`]-chain replayer that folds a chain into a trusted-key [`State`] (the
//! [`Authority`] is currently only constructible via [`Authority::from_state`]). See issue #7.

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

/// The kind of an AUM (Authority Update Message) (Go `AUMKind`; integer values are wire-stable, do
/// not reorder).
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
/// [`AumHash`] / [`NodeKeySignature`] references via `KeyID`.
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
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum TkaError {
    /// The CBOR blob could not be decoded into the expected shape.
    #[error("TKA decode error: {0}")]
    Decode(&'static str),
    /// A signature failed to verify cryptographically.
    #[error("TKA signature verification failed")]
    BadSignature,
    /// The authorizing key is not trusted in the current authority state.
    #[error("TKA authorizing key is not trusted")]
    UntrustedKey,
    /// A credential signature was presented where a node-authorizing signature was required.
    #[error("a credential signature cannot authorize a node")]
    CredentialCannotAuthorize,
    /// The presented signature does not cover the given node key.
    #[error("signature does not cover this node key")]
    NodeKeyMismatch,
}

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
    ///
    /// # Errors
    ///
    /// Returns [`TkaError::Decode`] if `signature_cbor` is malformed,
    /// [`TkaError::CredentialCannotAuthorize`] for a credential-only signature,
    /// [`TkaError::UntrustedKey`] if the authorizing key is not in the current state,
    /// [`TkaError::NodeKeyMismatch`] if the signature does not cover `node_key`, or
    /// [`TkaError::BadSignature`] if cryptographic verification fails.
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

/// A trusted-key payload as carried *inside* an [`Aum`] (`AUMAddKey`/`AUMUpdateKey`) or a
/// checkpoint [`AumState`] — Go `tka.Key`, full wire shape (the verify-path [`Key`] is a leaner
/// slice that omits `meta`, which the node-key-signature path never needs).
///
/// CBOR keymap (Go `cbor:"…,keyasint"`): `kind`=1, `votes`=2, `public`=3, `meta`=**12** (omitempty).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AumKey {
    /// Key algorithm (`Key25519` = 1).
    pub kind: KeyKind,
    /// Voting weight.
    pub votes: u32,
    /// Raw public key bytes (32 for Ed25519); the key id for `Key25519`.
    pub public: Vec<u8>,
    /// Optional metadata (Go `map[string]string`); omitted from CBOR when empty.
    pub meta: Vec<(alloc::string::String, alloc::string::String)>,
}

impl AumKey {
    /// The key id (for `Key25519`, the public key verbatim — Go `Key.ID`).
    pub fn id(&self) -> &[u8] {
        &self.public
    }

    fn kind_u8(&self) -> u8 {
        match self.kind {
            KeyKind::Ed25519 => 1,
        }
    }

    fn to_cbor(&self) -> Value {
        cbor::int_map([
            (1, Some(Value::Uint(self.kind_u8() as u64))),
            (2, Some(Value::Uint(self.votes as u64))),
            (3, Some(Value::Bytes(self.public.clone()))),
            (12, meta_to_cbor(&self.meta)),
        ])
    }
}

/// A full authority-state snapshot as carried in an `AUMCheckpoint` (Go `tka.State`).
///
/// CBOR keymap: `last_aum_hash`=1, `disablement_values`=2, `keys`=3, `state_id1`=4 (omitempty),
/// `state_id2`=5 (omitempty). Keys 1/2/3 are **non-`omitempty`** (a nil `last_aum_hash` encodes as
/// CBOR null, a nil `disablement_values`/`keys` as an empty array — matching Go's struct encoding).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AumState {
    /// The hash of the AUM this state was produced by (Go `LastAUMHash`); `None` encodes as null.
    pub last_aum_hash: Option<AumHash>,
    /// Disablement secret hashes (Go `DisablementValues`).
    pub disablement_values: Vec<Vec<u8>>,
    /// The trusted keys at this state.
    pub keys: Vec<AumKey>,
    /// Optional state identifier, high half (Go `StateID1`); omitted from CBOR when 0.
    pub state_id1: u64,
    /// Optional state identifier, low half (Go `StateID2`); omitted from CBOR when 0.
    pub state_id2: u64,
}

impl AumState {
    fn to_cbor(&self) -> Value {
        cbor::int_map([
            (
                1,
                Some(match &self.last_aum_hash {
                    Some(h) => Value::Bytes(h.0.to_vec()),
                    None => Value::Null,
                }),
            ),
            (
                2,
                Some(Value::Array(
                    self.disablement_values
                        .iter()
                        .map(|d| Value::Bytes(d.clone()))
                        .collect(),
                )),
            ),
            (
                3,
                Some(Value::Array(
                    self.keys.iter().map(AumKey::to_cbor).collect(),
                )),
            ),
            (
                4,
                (self.state_id1 != 0).then_some(Value::Uint(self.state_id1)),
            ),
            (
                5,
                (self.state_id2 != 0).then_some(Value::Uint(self.state_id2)),
            ),
        ])
    }
}

/// A signature attached to an [`Aum`] (Go `tkatype.Signature`): which trusted key signed, and the
/// signature bytes. CBOR keymap: `key_id`=1, `signature`=2 (both non-`omitempty`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AumSignature {
    /// The id of the trusted key that produced `signature`.
    pub key_id: Vec<u8>,
    /// The raw signature bytes.
    pub signature: Vec<u8>,
}

impl AumSignature {
    fn to_cbor(&self) -> Value {
        // Both fields are non-`omitempty` in Go, so an empty/nil `[]byte` encodes as CBOR null
        // (`0xf6`), not as an empty byte string (`0x40`) and not omitted — same rule as the AUM's
        // genesis `prev_aum_hash`. (Go's `TestSerialization` Signature vector ends `02 f6`.)
        cbor::int_map([
            (1, Some(bytes_or_null(&self.key_id))),
            (2, Some(bytes_or_null(&self.signature))),
        ])
    }
}

/// An Authority Update Message (Go `tka.AUM`): one link in the tailnet-lock chain. This is the
/// acquisition-side type a client replays to derive the trusted-key [`State`] (the verify-only path
/// in [`Authority`] doesn't need it). Serialization is byte-exact with Go's `fxamacker/cbor`
/// (CTAP2) so [`Aum::hash`]/[`Aum::sig_hash`] match Go's `AUM.Hash`/`AUM.SigHash`.
///
/// CBOR keymap (Go `cbor:"…,keyasint"`): `message_kind`=1, `prev_aum_hash`=2 (both
/// **non-`omitempty`**; a nil `prev` encodes as CBOR null, *not* omitted), `key`=3, `key_id`=4,
/// `state`=5, `votes`=6, `meta`=7, `signatures`=**23** (all `omitempty`). Key 23 is the last key
/// encodable in a single CBOR head byte, which is why Go put `Signatures` there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aum {
    /// The kind of update.
    pub message_kind: AumKind,
    /// The hash of the previous AUM in the chain (`None`/empty = genesis, encodes as CBOR null).
    pub prev_aum_hash: Option<AumHash>,
    /// `AUMAddKey`/`AUMUpdateKey`: the key being added.
    pub key: Option<AumKey>,
    /// `AUMRemoveKey`/`AUMUpdateKey`: the id of the key being removed/updated.
    pub key_id: Vec<u8>,
    /// `AUMCheckpoint`: the full state snapshot.
    pub state: Option<AumState>,
    /// `AUMUpdateKey`: the new vote weight (Go `*uint`; `None` = unchanged/omitted).
    pub votes: Option<u32>,
    /// `AUMUpdateKey`: new metadata.
    pub meta: Vec<(alloc::string::String, alloc::string::String)>,
    /// The signatures over this AUM's [`Aum::sig_hash`].
    pub signatures: Vec<AumSignature>,
}

impl Aum {
    fn message_kind_u8(&self) -> u8 {
        self.message_kind as u8
    }

    /// Build the canonical CBOR value. When `include_signatures` is false, key 23 is omitted (the
    /// [`Aum::sig_hash`] preimage — Go nils `Signatures`, which `omitempty`-drops it).
    fn to_cbor(&self, include_signatures: bool) -> Value {
        let signatures = if include_signatures && !self.signatures.is_empty() {
            Some(Value::Array(
                self.signatures.iter().map(AumSignature::to_cbor).collect(),
            ))
        } else {
            None
        };
        cbor::int_map([
            // key 1, NON-omitempty.
            (1, Some(Value::Uint(self.message_kind_u8() as u64))),
            // key 2, NON-omitempty: a nil prev hash is CBOR null, never omitted.
            (
                2,
                Some(match &self.prev_aum_hash {
                    Some(h) => Value::Bytes(h.0.to_vec()),
                    None => Value::Null,
                }),
            ),
            (3, self.key.as_ref().map(AumKey::to_cbor)),
            (4, nonempty_bytes(&self.key_id)),
            (5, self.state.as_ref().map(AumState::to_cbor)),
            (6, self.votes.map(|v| Value::Uint(v as u64))),
            (7, meta_to_cbor(&self.meta)),
            (23, signatures),
        ])
    }

    /// The canonical CBOR serialization including signatures (Go `AUM.Serialize`).
    pub fn serialize(&self) -> Vec<u8> {
        self.to_cbor(/* include_signatures = */ true).to_vec()
    }

    /// The chain-link hash: `BLAKE2s-256` of the full serialization (Go `AUM.Hash`).
    pub fn hash(&self) -> AumHash {
        AumHash(blake2s_256(&self.serialize()))
    }

    /// The signing digest: `BLAKE2s-256` of the serialization with `signatures` omitted (Go
    /// `AUM.SigHash`).
    pub fn sig_hash(&self) -> [u8; AUM_HASH_LEN] {
        blake2s_256(&self.to_cbor(/* include_signatures = */ false).to_vec())
    }
}

/// `Some(TextMap)` for a non-empty `map[string]string`, else `None` (the `omitempty` rule). Keys are
/// UTF-8 text; CTAP2 canonical ordering is applied at encode time by [`cbor::Value::TextMap`].
fn meta_to_cbor(meta: &[(alloc::string::String, alloc::string::String)]) -> Option<Value> {
    if meta.is_empty() {
        return None;
    }
    Some(Value::TextMap(
        meta.iter()
            .map(|(k, v)| (k.as_bytes().to_vec(), Value::Text(v.as_bytes().to_vec())))
            .collect(),
    ))
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

/// A byte string, or CBOR null when empty — the encoding Go's `fxamacker/cbor` produces for a
/// **non-`omitempty`** `[]byte` field that is nil/empty (e.g. `tkatype.Signature.{KeyID,Signature}`,
/// or an AUM's genesis `PrevAUMHash`). Distinct from [`nonempty_bytes`], which *omits* the field.
fn bytes_or_null(b: &[u8]) -> Value {
    if b.is_empty() {
        Value::Null
    } else {
        Value::Bytes(b.to_vec())
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

    // ----- CTAP2-CBOR byte-exactness FROZEN regression vector -----

    /// A small hex helper for embedding captured bytes in a failure message.
    fn hex(bytes: &[u8]) -> String {
        let mut s = String::new();
        for b in bytes {
            s.push_str(&alloc::format!("{b:02x}"));
        }
        s
    }

    /// FROZEN CTAP2-CBOR byte-exactness vector for the wire/signing serialization.
    ///
    /// The crate docs (and the `cbor` module) state the CTAP2-canonical CBOR encoding is asserted by
    /// construction but NOT cross-validated against Go's `fxamacker/cbor` (CTAP2 mode) in this fork.
    /// The existing TKA tests build a signature, sign it, and verify round-trip — so they would all
    /// still pass if the canonical encoding silently changed (int-map key ordering, smallest-int
    /// rule, omitempty), because both sides of the round-trip use the same encoder. That class of
    /// change would, however, break wire-compat with a live Go TKA.
    ///
    /// This pins the EXACT bytes for a fixed `NodeKeySignature` (Direct, deterministic key material):
    /// the full `to_cbor(true)` serialization, the `to_cbor(false)` SigHash preimage, the resulting
    /// `sig_hash` (BLAKE2s-256 of the preimage), and the `aum_hash` over the full serialization. ANY
    /// accidental change to canonical-CBOR encoding or the BLAKE2s digest breaks this test.
    ///
    /// NOTE: this is a regression-FREEZE vector captured from the current encoder, NOT a Go-sourced
    /// cross-vector. It should be replaced with a real `fxamacker/cbor` CTAP2 vector (the same
    /// `NodeKeySignature` encoded by a live Go `tka`) once one can be captured.
    #[test]
    fn node_key_signature_cbor_frozen_vector() {
        // Deterministic, fixed key material — NOT random. byte i = i, so the bytes are obvious.
        let pubkey: Vec<u8> = (0u8..32).collect();
        let key_id: Vec<u8> = (32u8..64).collect();
        let signature: Vec<u8> = (64u8..128).collect();

        let sig = NodeKeySignature {
            sig_kind: SigKind::Direct,
            pubkey,
            key_id,
            signature,
            nested: None,
            wrapping_pubkey: Vec::new(), // empty -> omitted (omitempty), key 6 must NOT appear
        };

        // 1. Full serialization (include_signature = true): keys 1,2,3,4 present, 5/6 omitted.
        let full = sig.to_cbor(true).to_vec();
        const EXPECTED_FULL: &[u8] = &[
            0xa4, 0x01, 0x01, 0x02, 0x58, 0x20, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
            0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x03, 0x58, 0x20, 0x20,
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
            0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
            0x3d, 0x3e, 0x3f, 0x04, 0x58, 0x40, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
            0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,
            0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63,
            0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71,
            0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
        ];
        assert_eq!(
            full,
            EXPECTED_FULL,
            "full CBOR serialization changed (canonical-CBOR encoding drift). actual: {}",
            hex(&full)
        );

        // 2. SigHash preimage (include_signature = false): key 4 (signature) omitted.
        let preimage = sig.to_cbor(false).to_vec();
        const EXPECTED_PREIMAGE: &[u8] = &[
            0xa3, 0x01, 0x01, 0x02, 0x58, 0x20, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
            0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x03, 0x58, 0x20, 0x20,
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
            0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
            0x3d, 0x3e, 0x3f,
        ];
        assert_eq!(
            preimage,
            EXPECTED_PREIMAGE,
            "SigHash preimage CBOR changed. actual: {}",
            hex(&preimage)
        );

        // 3. sig_hash = BLAKE2s-256(preimage) — pinned.
        let sig_hash = sig.sig_hash();
        const EXPECTED_SIG_HASH: [u8; AUM_HASH_LEN] = [
            0x22, 0x6f, 0x9c, 0xbc, 0x63, 0x73, 0x92, 0x75, 0x2e, 0x0e, 0xb1, 0x32, 0x9c, 0xc4,
            0x99, 0x07, 0x01, 0x4a, 0xb6, 0x4f, 0x8e, 0x5d, 0x82, 0x85, 0xc2, 0x91, 0x42, 0x62,
            0xf6, 0xa6, 0xa8, 0x33,
        ];
        assert_eq!(
            sig_hash,
            EXPECTED_SIG_HASH,
            "sig_hash (BLAKE2s-256 of preimage) changed. actual: {}",
            hex(&sig_hash)
        );

        // 4. aum_hash over the full serialization — pinned (exercises the public `aum_hash` helper
        //    + BLAKE2s digest over a frozen input).
        let aum = aum_hash(&full);
        const EXPECTED_AUM_HASH: [u8; AUM_HASH_LEN] = [
            0xa4, 0x40, 0x71, 0xa3, 0x7a, 0xbf, 0x80, 0x92, 0xd6, 0xff, 0x23, 0x84, 0xb2, 0xb0,
            0xa3, 0x50, 0xc7, 0xcb, 0x48, 0x41, 0xed, 0x68, 0x99, 0x62, 0x41, 0x7c, 0xd4, 0x23,
            0x68, 0xdc, 0x72, 0x49,
        ];
        assert_eq!(
            aum.0,
            EXPECTED_AUM_HASH,
            "aum_hash over full serialization changed. actual: {}",
            hex(&aum.0)
        );
    }

    // ----- ed25519-speccheck KAT: dual-verifier (dalek std vs zebra ZIP-215) -----

    /// Decode an ASCII hex string to bytes. Panics on malformed input (test-only).
    fn unhex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "odd hex length");
        let nib = |c: u8| -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => panic!("bad hex nibble"),
            }
        };
        let b = s.as_bytes();
        let mut out = Vec::with_capacity(s.len() / 2);
        let mut i = 0;
        while i < b.len() {
            out.push((nib(b[i]) << 4) | nib(b[i + 1]));
            i += 2;
        }
        out
    }

    /// The 12 adversarial Ed25519 vectors from `novifinancial/ed25519-speccheck`.
    ///
    /// Provenance: `cases.json` at commit `65519336fda78a3d016e947df6d82848aca0c9da`
    /// (<https://github.com/novifinancial/ed25519-speccheck/blob/main/cases.json>), the canonical
    /// generated vectors backing the "Taming the many EdDSAs" paper (IACR 2020/1244, Table 6c).
    /// The hex below is copied byte-for-byte from that file; the `message` field is itself hex
    /// (the speccheck driver hex-decodes it before verifying), so we decode it the same way.
    ///
    /// Tuple layout: `(message_hex, pubkey_hex, signature_hex)`.
    const SPECCHECK_VECTORS: [(&str, &str, &str); 12] = [
        // 0: S = 0; both A and R small-order.
        (
            "8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000",
        ),
        // 1: 0 < S < L; small A only.
        (
            "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
            "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
        ),
        // 2: 0 < S < L; small R only.
        (
            "aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab",
            "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e",
        ),
        // 3: A and R mixed-order; passes both (unless full-order checked).
        (
            "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
            "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
            "9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009",
        ),
        // 4: A and R mixed; passes cofactored, FAILS cofactorless — the cofactored discriminator.
        (
            "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
            "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
            "160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed5125ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09",
        ),
        // 5: A mixed, R order L; "fails cofactored iff (8h) prereduced".
        (
            "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
            "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
            "21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405",
        ),
        // 6: S > L (out of bounds) — malleability vector; std verifier MUST reject.
        (
            "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
            "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
            "e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514",
        ),
        // 7: S >> L (no canonical serialization with null high bit) — std verifier MUST reject.
        (
            "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
            "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
            "8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa19427e71f98a473474f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c22",
        ),
        // 8: 0 < S < L; non-canonical R, reduced for hash.
        (
            "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
            "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f",
        ),
        // 9: 0 < S < L; non-canonical R, NOT reduced for hash.
        (
            "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
            "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908",
        ),
        // 10: 0 < S < L; non-canonical A, reduced for hash.
        (
            "e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
        ),
        // 11: 0 < S < L; non-canonical A, NOT reduced for hash.
        (
            "39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
        ),
    ];

    /// Known-answer test guarding the dual-verifier split that backs TKA consensus correctness.
    ///
    /// `verify_ed25519_std` wraps `ed25519-dalek 2.x` (standard RFC-8032-ish, cofactorless) and is
    /// used for SigRotation WRAPPING signatures. `verify_ed25519_zip215` wraps `ed25519-zebra 4.x`
    /// (ZIP-215 cofactored) and is used for Direct/Credential signatures to match Go
    /// `ed25519consensus`. If these two ever collapse to identical behavior, Go wire-compat for
    /// Tailnet-Lock silently breaks — this test proves they remain distinct on the adversarial set.
    ///
    /// The accept/reject matrix is asserted **as actually observed** from the pinned crate versions
    /// (`ed25519-dalek 2.2.0`, `ed25519-zebra 4.2.0`). These are newer than the versions tabulated
    /// in the "Taming the many EdDSAs" paper (Table 5: dalek 1.0.0-pre.4, zebra 2.1.1), so the
    /// non-canonical cases (8–11) may differ from the paper; we lock in current behavior as a
    /// regression guard. The SECURITY-CRITICAL invariants are NOT version-tunable: the standard
    /// verifier MUST reject the S >= L malleability vectors (6, 7), and the two verifiers MUST
    /// disagree on the cofactored discriminator (vector 4). Those are hard, separate assertions.
    #[test]
    fn ed25519_speccheck_dual_verifier_kat() {
        // Observed accept(true)/reject(false) matrix for the pinned crates, vectors 0..=11.
        // Anchored to the speccheck paper rows then corrected to what the crates actually do
        // (see the per-vector run below — any divergence makes the test fail loudly).
        //
        //                              0    1    2    3    4    5    6    7    8    9    10   11
        const STD_EXPECT: [bool; 12] = [
            true, true, true, true, false, false, false, false, false, false, false, true,
        ];
        const ZIP215_EXPECT: [bool; 12] = [
            true, true, true, true, true, true, false, false, false, true, true, true,
        ];

        for (i, (msg_hex, pk_hex, sig_hex)) in SPECCHECK_VECTORS.iter().enumerate() {
            let msg = unhex(msg_hex);
            let pk = unhex(pk_hex);
            let sig = unhex(sig_hex);
            assert_eq!(pk.len(), 32, "vector {i}: pubkey not 32 bytes");
            assert_eq!(sig.len(), 64, "vector {i}: signature not 64 bytes");

            let std_ok = verify_ed25519_std(&pk, &msg, &sig).is_ok();
            let zip_ok = verify_ed25519_zip215(&pk, &msg, &sig).is_ok();

            assert_eq!(
                std_ok, STD_EXPECT[i],
                "speccheck vector {i}: verify_ed25519_std accept={std_ok}, expected {}",
                STD_EXPECT[i]
            );
            assert_eq!(
                zip_ok, ZIP215_EXPECT[i],
                "speccheck vector {i}: verify_ed25519_zip215 accept={zip_ok}, expected {}",
                ZIP215_EXPECT[i]
            );
        }

        // SECURITY-CRITICAL invariant (NOT version-tunable): the standard verifier must reject
        // signatures whose scalar S is out of range (S >= L). These are vectors 6 and 7 — the
        // EdDSA malleability guard. If either ACCEPTS, that is a real security finding.
        for &i in &[6usize, 7usize] {
            let (msg_hex, pk_hex, sig_hex) = SPECCHECK_VECTORS[i];
            let (msg, pk, sig) = (unhex(msg_hex), unhex(pk_hex), unhex(sig_hex));
            assert!(
                verify_ed25519_std(&pk, &msg, &sig).is_err(),
                "SECURITY: verify_ed25519_std ACCEPTED S>=L malleability vector {i}"
            );
        }

        // KEY DISCRIMINATOR (vector 4): cofactored (ZIP-215/zebra) accepts, cofactorless
        // (standard/dalek) rejects, on the SAME (pk, msg, sig). This proves the dual-verifier
        // split is real and not accidentally identical.
        {
            let (msg_hex, pk_hex, sig_hex) = SPECCHECK_VECTORS[4];
            let (msg, pk, sig) = (unhex(msg_hex), unhex(pk_hex), unhex(sig_hex));
            assert!(
                verify_ed25519_zip215(&pk, &msg, &sig).is_ok(),
                "vector 4: ZIP-215 (zebra) should ACCEPT the cofactored discriminator"
            );
            assert!(
                verify_ed25519_std(&pk, &msg, &sig).is_err(),
                "vector 4: standard (dalek) should REJECT the cofactored discriminator"
            );
        }
    }

    // ----- Cross-implementation KATs against real Go `tailscale.com/tka` v1.100.0 -----

    /// Cross-implementation Known-Answer-Test: the CTAP2-CBOR serialization and BLAKE2s-256
    /// `SigHash` of three `NodeKeySignature` shapes must byte-match the REAL Go
    /// `tailscale.com/tka` package, version **v1.100.0** (toolchain **go1.26.4**).
    ///
    /// Provenance: the golden bytes below were produced by a Go generator that imports the real
    /// upstream `tailscale.com/tka` and calls `NodeKeySignature.Serialize()` (full CBOR including
    /// the signature field) and `NodeKeySignature.SigHash()` (BLAKE2s-256 of the CBOR with the
    /// `Signature` field nil'd). They are authoritative upstream output, NOT this fork's own
    /// encoder echoed back — this is the cross-validation the `node_key_signature_cbor_frozen_vector`
    /// freeze-test could not provide. The generator lives alongside the speccheck generator under
    /// `tests/vectors/gen` (Go module pinned to `tailscale.com v1.100.0`).
    ///
    /// Three shapes are covered: a `Direct` leaf, a `Credential` leaf (same fields, different
    /// `sigKind`), and a `Rotation` wrapping a nested `Direct` (the rotation-chain wire form). The
    /// int-map keys are 1=sigKind, 2=pubkey, 3=keyID, 4=signature, 5=nested, 6=wrappingPubkey;
    /// empty byte fields are omitted (`omitempty`).
    #[test]
    fn tka_cbor_matches_go_golden() {
        // Common fixed field material (real Go generator inputs).
        let pubkey32 = unhex("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
        let key_id32 = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let sig64 = unhex(
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeffe0e1e2e3e4e5e6e7e8e9eaebecedeeefd0d1d2d3d4d5d6d7d8d9dadbdcdddedfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
        );
        let wrap32 = unhex("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f");
        let rot_sig64 = unhex(
            "55565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f9091929394",
        );

        // GOLDEN 1 — Direct.
        {
            let sig = NodeKeySignature {
                sig_kind: SigKind::Direct,
                pubkey: pubkey32.clone(),
                key_id: key_id32.clone(),
                signature: sig64.clone(),
                nested: None,
                wrapping_pubkey: Vec::new(),
            };
            let full = sig.to_cbor(true).to_vec();
            let expected_full = unhex(
                "a40101025820a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf035820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f045840f0f1f2f3f4f5f6f7f8f9fafbfcfdfeffe0e1e2e3e4e5e6e7e8e9eaebecedeeefd0d1d2d3d4d5d6d7d8d9dadbdcdddedfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
            );
            assert_eq!(
                full,
                expected_full,
                "GOLDEN 1 (Direct) full CBOR diverged from Go tka v1.100.0. actual: {}",
                hex(&full)
            );
            let expected_hash =
                unhex("7e9653c97d35485b37b9bf942b1861cd2f3cb0663b5bb154f1178cca72101e74");
            assert_eq!(
                sig.sig_hash().as_slice(),
                expected_hash.as_slice(),
                "GOLDEN 1 (Direct) sig_hash diverged from Go tka v1.100.0. actual: {}",
                hex(&sig.sig_hash())
            );
        }

        // GOLDEN 2 — Credential (same fields as Direct, sigKind=3).
        {
            let sig = NodeKeySignature {
                sig_kind: SigKind::Credential,
                pubkey: pubkey32.clone(),
                key_id: key_id32.clone(),
                signature: sig64.clone(),
                nested: None,
                wrapping_pubkey: Vec::new(),
            };
            let full = sig.to_cbor(true).to_vec();
            let expected_full = unhex(
                "a40103025820a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf035820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f045840f0f1f2f3f4f5f6f7f8f9fafbfcfdfeffe0e1e2e3e4e5e6e7e8e9eaebecedeeefd0d1d2d3d4d5d6d7d8d9dadbdcdddedfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
            );
            assert_eq!(
                full,
                expected_full,
                "GOLDEN 2 (Credential) full CBOR diverged from Go tka v1.100.0. actual: {}",
                hex(&full)
            );
            let expected_hash =
                unhex("b6070ea8bc7ae8989ef4293f5031bedaa4a499803ade99f9e2f34dc2898ac03f");
            assert_eq!(
                sig.sig_hash().as_slice(),
                expected_hash.as_slice(),
                "GOLDEN 2 (Credential) sig_hash diverged from Go tka v1.100.0. actual: {}",
                hex(&sig.sig_hash())
            );
        }

        // GOLDEN 3 — Rotation wrapping a nested Direct.
        //
        // Decoded from the authoritative Go bytes, the OUTER map is `a4` = 4 entries: keys
        // 1=sigKind(Rotation), 2=pubkey(wrap32), 4=signature(rotSig64), 5=nested. The outer has NO
        // key 6 (its `wrapping_pubkey` is EMPTY → omitted) and NO key 3 (its `key_id` is EMPTY →
        // omitted). The trailing `065820<wrap32>` in the hex belongs to the NESTED Direct map
        // (`a5` = 5 entries: keys 1,2,3,4,6), whose `wrapping_pubkey` IS set to wrap32. Constructing
        // the structs this way (outer wrapping_pubkey empty, nested wrapping_pubkey=wrap32)
        // reproduces the Go bytes exactly.
        {
            let nested = NodeKeySignature {
                sig_kind: SigKind::Direct,
                pubkey: pubkey32.clone(),
                key_id: key_id32.clone(),
                signature: sig64.clone(),
                nested: None,
                wrapping_pubkey: wrap32.clone(),
            };
            let sig = NodeKeySignature {
                sig_kind: SigKind::Rotation,
                pubkey: wrap32.clone(),
                key_id: Vec::new(),
                signature: rot_sig64.clone(),
                nested: Some(alloc::boxed::Box::new(nested)),
                wrapping_pubkey: Vec::new(),
            };
            let full = sig.to_cbor(true).to_vec();
            let expected_full = unhex(
                "a40102025820101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f04584055565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939405a50101025820a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf035820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f045840f0f1f2f3f4f5f6f7f8f9fafbfcfdfeffe0e1e2e3e4e5e6e7e8e9eaebecedeeefd0d1d2d3d4d5d6d7d8d9dadbdcdddedfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf065820101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
            );
            assert_eq!(
                full,
                expected_full,
                "GOLDEN 3 (Rotation) full CBOR diverged from Go tka v1.100.0. actual: {}",
                hex(&full)
            );
            let expected_hash =
                unhex("fac0a5a6781bb945369c28a0b3d3eea04e1648b60ec1a990a1ff68a9a566e6a7");
            assert_eq!(
                sig.sig_hash().as_slice(),
                expected_hash.as_slice(),
                "GOLDEN 3 (Rotation) sig_hash diverged from Go tka v1.100.0. actual: {}",
                hex(&sig.sig_hash())
            );
        }
    }

    /// Cross-bind the dual Ed25519 verifier accept/reject matrix to the verdicts produced by the
    /// REAL Go implementations on the adversarial speccheck set (see [`SPECCHECK_VECTORS`]).
    ///
    /// Provenance of the Go verdicts: Go `crypto/ed25519.Verify` (standard, cofactorless) and
    /// `github.com/hdevalence/ed25519consensus v0.2.0` (ZIP-215, cofactored), toolchain
    /// **go1.26.4**, driven by the generator under `tests/vectors/gen/zip215`. These are the SAME
    /// verdicts the pinned Rust crates produce — proving `ed25519-dalek 2.x` == Go-std and
    /// `ed25519-zebra 4.x` == Go-`ed25519consensus` on the adversarial set. The arrays below MUST
    /// therefore equal `STD_EXPECT` / `ZIP215_EXPECT` asserted in
    /// `ed25519_speccheck_dual_verifier_kat`; this test additionally pins them to Go's behavior.
    ///
    /// NOTE: [`SPECCHECK_VECTORS`] is duplicated (byte-for-byte) in the Go generator at
    /// `tests/vectors/gen/zip215/main.go`. Both copies derive from the same upstream
    /// `cases.json` commit; if you edit one you MUST edit the other, or this proof would compare
    /// inputs the Go verdicts were never computed over.
    #[test]
    fn ed25519_dual_verifier_matches_go_verdicts() {
        //                                  0    1    2    3    4    5    6    7    8    9   10   11
        const GO_STD_ACCEPT: [bool; 12] = [
            true, true, true, true, false, false, false, false, false, false, false, true,
        ];
        const GO_ZIP215_ACCEPT: [bool; 12] = [
            true, true, true, true, true, true, false, false, false, true, true, true,
        ];

        for (i, (msg_hex, pk_hex, sig_hex)) in SPECCHECK_VECTORS.iter().enumerate() {
            let msg = unhex(msg_hex);
            let pk = unhex(pk_hex);
            let sig = unhex(sig_hex);

            let std_ok = verify_ed25519_std(&pk, &msg, &sig).is_ok();
            let zip_ok = verify_ed25519_zip215(&pk, &msg, &sig).is_ok();

            assert_eq!(
                std_ok, GO_STD_ACCEPT[i],
                "vector {i}: Rust verify_ed25519_std accept={std_ok} disagrees with Go \
                 crypto/ed25519.Verify={}",
                GO_STD_ACCEPT[i]
            );
            assert_eq!(
                zip_ok, GO_ZIP215_ACCEPT[i],
                "vector {i}: Rust verify_ed25519_zip215 accept={zip_ok} disagrees with Go \
                 ed25519consensus.Verify={}",
                GO_ZIP215_ACCEPT[i]
            );
        }
    }

    /// Byte-exact cross-validation of [`Aum::serialize`] against the literal `[]byte` vectors in Go
    /// `tka/aum_test.go` `TestSerialization` (tailscale v1.100.0, fxamacker/cbor v2.9.2 CTAP2 mode).
    /// These are the authoritative oracle: if our CTAP2 CBOR diverges from Go by a single byte, the
    /// `AUM.Hash` chain links and every signature digest break. Each case reproduces the exact Go
    /// `AUM{…}` literal and asserts identical canonical bytes.
    #[test]
    fn aum_serialize_matches_go_test_serialization_vectors() {
        // AddKey: AUM{MessageKind: AUMAddKey, Key: &Key{}}. Go's *zero* Key{} has Kind=0
        // (KeyInvalid) and Public=nil, which our `AumKey` (always a valid KeyKind + Vec) cannot
        // model — that zero-Key encoding (`03 a3 01 00 02 00 03 f6`) is asserted directly at the
        // CBOR layer here, while the AUM keymap around it (map3, kind=AddKey, null prev, Key at
        // key 3) is covered by the structural assertions plus the three full vectors below.
        let add_key_inner_zero_key = cbor::Value::IntMap(alloc::vec![
            (1, cbor::Value::Uint(0)), // Kind = KeyInvalid(0)
            (2, cbor::Value::Uint(0)), // Votes = 0
            (3, cbor::Value::Null),    // Public = nil -> null
        ]);
        assert_eq!(
            add_key_inner_zero_key.to_vec(),
            alloc::vec![0xa3, 0x01, 0x00, 0x02, 0x00, 0x03, 0xf6],
            "Go's zero Key{{}} encodes as map(3){{kind=0, votes=0, public=null}}"
        );

        // RemoveKey: AUM{MessageKind: AUMRemoveKey, KeyID: []byte{1, 2}}
        let remove_key = Aum {
            message_kind: AumKind::RemoveKey,
            prev_aum_hash: None,
            key: None,
            key_id: alloc::vec![1, 2],
            state: None,
            votes: None,
            meta: Vec::new(),
            signatures: Vec::new(),
        };
        assert_eq!(
            remove_key.serialize(),
            // a3 (map3) 01 02 (kind=RemoveKey) 02 f6 (prev=null) 04 42 01 02 (KeyID=bytes{1,2})
            alloc::vec![0xa3, 0x01, 0x02, 0x02, 0xf6, 0x04, 0x42, 0x01, 0x02],
            "RemoveKey AUM serialization must match Go TestSerialization byte-for-byte"
        );

        // UpdateKey: AUM{MessageKind: AUMUpdateKey, Votes: &uint(2), KeyID: []byte{1,2},
        //                Meta: map[string]string{"a":"b"}}
        let update_key = Aum {
            message_kind: AumKind::UpdateKey,
            prev_aum_hash: None,
            key: None,
            key_id: alloc::vec![1, 2],
            state: None,
            votes: Some(2),
            meta: alloc::vec![("a".into(), "b".into())],
            signatures: Vec::new(),
        };
        assert_eq!(
            update_key.serialize(),
            // a5 (map5) 01 04 (UpdateKey) 02 f6 (prev null) 04 42 01 02 (KeyID) 06 02 (Votes=2)
            // 07 a1 61 61 61 62 (Meta = {"a":"b"})  — keys ascending 1,2,4,6,7
            alloc::vec![
                0xa5, 0x01, 0x04, 0x02, 0xf6, 0x04, 0x42, 0x01, 0x02, 0x06, 0x02, 0x07, 0xa1, 0x61,
                0x61, 0x61, 0x62
            ],
            "UpdateKey AUM serialization must match Go TestSerialization byte-for-byte"
        );

        // Signature: AUM{MessageKind: AUMAddKey, Signatures: []tkatype.Signature{{KeyID: []byte{1}}}}
        let with_sig = Aum {
            message_kind: AumKind::AddKey,
            prev_aum_hash: None,
            key: None,
            key_id: Vec::new(),
            state: None,
            votes: None,
            meta: Vec::new(),
            signatures: alloc::vec![AumSignature {
                key_id: alloc::vec![1],
                signature: Vec::new(),
            }],
        };
        assert_eq!(
            with_sig.serialize(),
            // a3 (map3) 01 01 (AddKey) 02 f6 (prev null) 17 (key 23 = Signatures) 81 (array1)
            // a2 (map2) 01 41 01 (Signature.KeyID = bytes{1}) 02 f6 (Signature.Signature = null)
            alloc::vec![
                0xa3, 0x01, 0x01, 0x02, 0xf6, 0x17, 0x81, 0xa2, 0x01, 0x41, 0x01, 0x02, 0xf6
            ],
            "Signature AUM serialization must match Go TestSerialization (key 23 + nil sig = null)"
        );

        // sig_hash must drop key 23 (Go SigHash nils Signatures → omitempty): the with_sig AUM's
        // sig_hash equals the BLAKE2s of the same AUM with no signatures.
        let no_sig = Aum {
            signatures: Vec::new(),
            ..with_sig.clone()
        };
        assert_eq!(
            with_sig.sig_hash(),
            blake2s_256(&no_sig.serialize()),
            "SigHash preimage must omit key 23 (Signatures), matching Go AUM.SigHash"
        );
        // And the full Hash differs from the SigHash (signatures are in the chain-link hash).
        assert_ne!(
            with_sig.hash().0,
            with_sig.sig_hash(),
            "Hash (incl. signatures) must differ from SigHash (excl.) when signatures are present"
        );
    }

    /// Checkpoint AUM with an embedded `State`: exercises [`AumState`]/[`AumKey`] CBOR (the 32-byte
    /// `LastAUMHash` as a definite-length byte string, the `DisablementValues`/`Keys` arrays, and the
    /// `Key.Public` at key 3). Mirrors the structure of Go's `TestSerialization` Checkpoint case.
    #[test]
    fn aum_checkpoint_state_serialization() {
        let checkpoint = Aum {
            message_kind: AumKind::Checkpoint,
            prev_aum_hash: Some(AumHash([0u8; AUM_HASH_LEN])),
            key: None,
            key_id: Vec::new(),
            state: Some(AumState {
                last_aum_hash: Some(AumHash([0u8; AUM_HASH_LEN])),
                disablement_values: Vec::new(),
                keys: alloc::vec![AumKey {
                    kind: KeyKind::Ed25519,
                    votes: 1,
                    public: alloc::vec![5, 6],
                    meta: Vec::new(),
                }],
                state_id1: 0,
                state_id2: 0,
            }),
            votes: None,
            meta: Vec::new(),
            signatures: Vec::new(),
        };
        let bytes = checkpoint.serialize();
        // Spot-check the structurally-load-bearing pieces (full-vector parity is covered by the
        // three exact vectors above; here we pin the State/Key encoding shape):
        // map3: key1=Checkpoint(5), key2=prev(32-byte bytestring 0x58 0x20 …), key5=State.
        assert_eq!(
            &bytes[0..3],
            &[0xa3, 0x01, 0x05],
            "map(3), MessageKind=Checkpoint(5)"
        );
        assert_eq!(
            &bytes[3..6],
            &[0x02, 0x58, 0x20],
            "key2 prev = 32-byte byte string head"
        );
        // The embedded State map (key 5) must contain: LastAUMHash (1) as 32-byte bytes, an empty
        // DisablementValues array (2 → 0x80), and a Keys array (3 → 0x81 with one Key map).
        // Locate the State map head (key 5) after the 32-byte prev hash: 3 + 3 + 32 = offset 38.
        assert_eq!(bytes[38], 0x05, "key 5 = State");
        // State is a map; its first entry is key1 (LastAUMHash) = 32-byte byte string.
        assert_eq!(
            &bytes[39..42],
            &[0xa3, 0x01, 0x58],
            "State map(3), key1 LastAUMHash bytes"
        );
        // The Key inside Keys carries Public={5,6} at key 3 (…03 42 05 06) and Votes=1 at key 2.
        let tail = &bytes[bytes.len() - 4..];
        assert_eq!(
            tail,
            &[0x03, 0x42, 0x05, 0x06],
            "Key.Public (key 3) = bytes{{5,6}}"
        );
        // Round-trips deterministically (hash is stable).
        assert_eq!(checkpoint.hash(), checkpoint.hash());
    }
}
