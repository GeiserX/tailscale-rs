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

// ---------------------------------------------------------------------------------------------
// Static-validation limits — mirror Go `tka/limits.go` (v1.100.0) byte-for-byte. These bound the
// accept/reject boundary so a Rust node and a Go node agree on which AUMs/keys/checkpoints are
// well-formed; a mismatch here is a tailnet-lock CONSENSUS SPLIT (the two derive different trusted
// states), not merely a robustness nicety. Do not change without changing Go.
// ---------------------------------------------------------------------------------------------

/// Max trusted keys in a checkpoint state (Go `maxKeys`).
const MAX_KEYS: usize = 512;
/// Max disablement values in a checkpoint state (Go `maxDisablementValues`).
const MAX_DISABLEMENT_VALUES: usize = 32;
/// Required byte length of each disablement value — a BLAKE2s-256 digest (Go `disablementLength`).
const DISABLEMENT_LENGTH: usize = 32;
/// Max total bytes of a key's metadata map, summed over keys+values (Go `maxMetaBytes`).
const MAX_META_BYTES: usize = 512;
/// Max key voting weight (Go `Key.StaticValidate`: `Votes > 4096` is "excessive key weight").
const MAX_KEY_VOTES: u32 = 4096;

/// A BLAKE2s-256 hash of an AUM's canonical serialization. Identifies an AUM and links the chain
/// (`PrevAUMHash`). Text form is RFC4648 standard base32, no padding (Go `AUMHash.MarshalText`).
///
/// `Ord`/`PartialOrd` order by the raw 32 bytes — used to key the sync store (a `BTreeMap`, since the
/// crate is `no_std`) and already relied on by [`pick_next_aum`]'s lowest-hash fork tiebreak.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
    /// An AUM's `PrevAUMHash` does not match the hash of the state it was applied to (Go
    /// "parent AUMHash mismatch") — the chain link is broken.
    #[error("AUM parent hash does not match the current chain head")]
    BadParent,
    /// An `AUMAddKey` named a key id that is already trusted, or an `AUMRemoveKey`/`AUMUpdateKey`
    /// named a key id that is not (Go "key already exists" / `ErrNoSuchKey`).
    #[error("AUM key-state update is invalid (key already exists, or no such key)")]
    BadKeyState,
    /// An AUM chain was empty, did not begin at a genesis (`AUMCheckpoint`/`AUMAddKey` with no
    /// parent), or otherwise could not be replayed into a state.
    #[error("AUM chain is empty or has no valid genesis")]
    BadChain,
    /// An AUM carried no signatures (Go `aumVerify` "unsigned AUM"). Every AUM — including the
    /// genesis — must be signed by at least one trusted key before it can advance the chain.
    #[error("AUM is unsigned")]
    UnsignedAum,
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

    /// The rotation pubkey this signature wraps (Go `NodeKeySignature.wrappingPublic`). If this
    /// signature carries a `wrapping_pubkey`, that is it; otherwise — for a rotation — recurse into
    /// the nested signature (intermediate rotation layers may omit their own wrapping pubkey, in
    /// which case the inner one applies). `None` for a non-rotation with no wrapping pubkey.
    fn wrapping_public(&self) -> Option<&[u8]> {
        if !self.wrapping_pubkey.is_empty() {
            return Some(&self.wrapping_pubkey);
        }
        match self.sig_kind {
            SigKind::Rotation => self.nested.as_ref()?.wrapping_public(),
            _ => None,
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
                // The outer rotation signature is verified with STANDARD ed25519 against the rotation
                // pubkey. Go resolves this via `s.Nested.wrappingPublic()`, which RECURSES: an
                // intermediate rotation layer may omit its own `WrappingPubkey`, in which case the
                // next-inner one applies. (Reading `nested.wrapping_pubkey` directly broke multi-level
                // rotation chains — the deny-direction consensus split this fixes.)
                let verify_pub = nested
                    .wrapping_public()
                    .ok_or(TkaError::Decode("missing rotation key"))?;
                if verify_pub.len() != 32 {
                    return Err(TkaError::Decode("wrapping pubkey wrong length"));
                }
                verify_ed25519_std(verify_pub, &sig_hash, &self.signature)?;
                // Recurse to verify the nested signature, rooting in the trusted key. The nested node
                // key Go passes is the nested signature's own `Pubkey` — EXCEPT for a nested
                // Credential, which "certifies an indirection key rather than a node key, so there's
                // no need to check the node key" (Go passes an empty node key, and the nested
                // `verify_signature` skips its `pubkey != node_key` check for `Credential`). We must
                // NOT add an extra `nested.pubkey == verify_pub` bind here — Go has none, and a
                // SigCredential leaves `Pubkey` unused, so that bind wrongly rejected legitimate
                // credential-provisioned peers.
                let nested_node_key: &[u8] = if nested.sig_kind == SigKind::Credential {
                    &[]
                } else {
                    &nested.pubkey
                };
                nested.verify_signature(nested_node_key, verification_key)
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

    /// Validate this key's well-formedness, mirroring Go `Key.StaticValidate` (`tka/key.go`,
    /// v1.100.0). A trusted key folded into the state with an out-of-range `votes` would contribute
    /// the wrong weight to [`pick_next_aum`] fork resolution, so a node that accepts it diverges from
    /// one that rejects it — a consensus split. Checked at decode/fold time.
    ///
    /// Rules (exact Go parity): `votes` must be `1..=4096` (`0` → "key votes must be non-zero",
    /// `>4096` → "excessive key weight"); the metadata byte total (Σ key+value lengths) must be
    /// `≤ MAX_META_BYTES`; the kind must be a recognized key kind (`Key25519`).
    pub fn static_validate(&self) -> Result<(), TkaError> {
        if self.votes > MAX_KEY_VOTES {
            return Err(TkaError::BadKeyState);
        }
        if self.votes == 0 {
            return Err(TkaError::BadKeyState);
        }
        let meta_bytes: usize = self.meta.iter().map(|(k, v)| k.len() + v.len()).sum();
        if meta_bytes > MAX_META_BYTES {
            return Err(TkaError::BadKeyState);
        }
        // `kind` is the `KeyKind` enum (only `Ed25519`), so an unrecognized kind is unrepresentable
        // here — Go's `default → "unrecognized key kind"` arm can't be hit by a decoded `AumKey`.
        match self.kind {
            KeyKind::Ed25519 => {}
        }
        Ok(())
    }

    /// The leaner verify-path [`Key`] view of this key (drops `meta`, which the node-key-signature
    /// verification path never reads). Used by the replayer to populate the trusted-key [`State`].
    pub fn to_key(&self) -> Key {
        Key {
            kind: self.kind,
            votes: self.votes,
            public: self.public.clone(),
        }
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
/// `state_id2`=5 (omitempty). Keys 1/2/3 are **non-`omitempty`**, and Go's `fxamacker/cbor`
/// distinguishes a **nil** slice/pointer from an **empty-but-present** one: a nil field encodes as
/// CBOR **null** (`0xf6`), an empty-non-nil slice as an empty **array** (`0x80`). `last_aum_hash`,
/// `disablement_values`, and `keys` are therefore `Option`: `None` ⇒ Go nil ⇒ `0xf6`; `Some(vec)`
/// (incl. `Some(empty)`) ⇒ array. Getting this wrong changes the checkpoint's `Hash` — and thus the
/// chain head — versus Go, so it is consensus-relevant (this was a recorded interop bug; fixed here).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AumState {
    /// The hash of the AUM this state was produced by (Go `LastAUMHash`); `None` (Go nil) ⇒ null.
    pub last_aum_hash: Option<AumHash>,
    /// Disablement secret hashes (Go `DisablementValues`). `None` (Go nil) ⇒ CBOR null `0xf6`;
    /// `Some(vec)` ⇒ array (empty array `0x80` when `Some(vec![])`).
    pub disablement_values: Option<Vec<Vec<u8>>>,
    /// The trusted keys at this state (Go `Keys`). `None` (Go nil) ⇒ CBOR null `0xf6`; `Some(vec)` ⇒
    /// array.
    pub keys: Option<Vec<AumKey>>,
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
                Some(match &self.disablement_values {
                    // Go nil ⇒ CBOR null; Some(vec) ⇒ array (empty array for Some(vec![])).
                    None => Value::Null,
                    Some(vals) => {
                        Value::Array(vals.iter().map(|d| Value::Bytes(d.clone())).collect())
                    }
                }),
            ),
            (
                3,
                Some(match &self.keys {
                    None => Value::Null,
                    Some(keys) => Value::Array(keys.iter().map(AumKey::to_cbor).collect()),
                }),
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

    /// Validate this state for inclusion in a `Checkpoint` AUM, mirroring Go
    /// `State.staticValidateCheckpoint` (`tka/state.go`, v1.100.0). A checkpoint replaces the entire
    /// trusted-key set, so a malformed one a Rust node accepts but a Go node rejects (or vice versa)
    /// is a consensus split; a zero-key checkpoint would silently disable the authority.
    ///
    /// Rules (exact Go parity):
    /// - `last_aum_hash` must be `None` ("cannot specify a parent AUM" — a checkpoint roots a state).
    /// - disablement values: **≥1**, **≤ MAX_DISABLEMENT_VALUES**, each exactly `DISABLEMENT_LENGTH`
    ///   bytes, **no duplicates**.
    /// - keys: **≥1**, **≤ MAX_KEYS**, each [`AumKey::static_validate`]s, **no duplicate key ids**.
    ///
    /// Treats `None` (Go nil) the same as an empty slice for the count checks (a nil `keys`/
    /// `disablement_values` fails the "≥1" requirement, exactly as Go's `len(nil) == 0`).
    pub fn static_validate_checkpoint(&self) -> Result<(), TkaError> {
        if self.last_aum_hash.is_some() {
            return Err(TkaError::BadKeyState);
        }

        let disablements = self.disablement_values.as_deref().unwrap_or(&[]);
        if disablements.is_empty() || disablements.len() > MAX_DISABLEMENT_VALUES {
            return Err(TkaError::BadKeyState);
        }
        for (i, ds) in disablements.iter().enumerate() {
            if ds.len() != DISABLEMENT_LENGTH {
                return Err(TkaError::BadKeyState);
            }
            // O(n²) dedup — bounded by MAX_DISABLEMENT_VALUES (32), so trivially small. Mirrors Go's
            // nested-loop `bytes.Equal` check.
            if disablements[..i].iter().any(|other| other == ds) {
                return Err(TkaError::BadKeyState);
            }
        }

        let keys = self.keys.as_deref().unwrap_or(&[]);
        if keys.is_empty() || keys.len() > MAX_KEYS {
            return Err(TkaError::BadKeyState);
        }
        for (i, k) in keys.iter().enumerate() {
            k.static_validate()?;
            // Duplicate key-id check (Go compares `Key.ID()` pairwise). Bounded by MAX_KEYS (512).
            if keys[..i].iter().any(|other| other.id() == k.id()) {
                return Err(TkaError::BadKeyState);
            }
        }
        Ok(())
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

    /// Validate this AUM's structural well-formedness, mirroring Go `AUM.StaticValidate`
    /// (`tka/aum.go`, v1.100.0). Run **before** folding (and at decode time). Because the chain-link
    /// [`Aum::hash`] covers *every present field*, an AUM carrying fields foreign to its kind hashes
    /// differently than the canonical/stripped form — so if one node folds it (no static-validate)
    /// while another rejects it, they derive different heads = a consensus split. This is the gate
    /// that keeps both sides byte-identical on what counts as a well-formed AUM.
    ///
    /// Rules (exact Go parity):
    /// - if `key` is present, it must [`AumKey::static_validate`];
    /// - every signature must have `key_id` of length 32 **and** `signature` of length 64;
    /// - if `state` is present, it must [`AumState::static_validate_checkpoint`];
    /// - per-kind field allow-lists:
    ///   - `AddKey`: must have `key`; must NOT set `key_id`/`state`/`votes`/`meta`;
    ///   - `RemoveKey`: must have `key_id`; must NOT set `key`/`state`/`votes`/`meta`;
    ///   - `UpdateKey`: must have `key_id` **and** (`votes` or `meta`); must NOT set `key`/`state`;
    ///   - `Checkpoint`: must have `state`; must NOT set `key_id`/`key`/`votes`/`meta`;
    ///   - `NoOp`/`Invalid`/unknown: no field constraints (Go's forward-compat `default`).
    ///
    /// # `key_id`/`meta` nil-vs-empty (a decoder invariant, not a divergence today)
    /// Go's allow-list tests are asymmetric: the *required*-field checks use `len(KeyID)==0`, but the
    /// *forbidden*-field checks use `KeyID != nil` / `Meta != nil` — so in Go an empty-but-**non-nil**
    /// `[]byte{}`/`map{}` counts as "present". This fork models `key_id` as `Vec<u8>` and `meta` as a
    /// `Vec` (no nil-vs-empty distinction), so "present" == non-empty here. This is **not** an
    /// accept/reject divergence in practice: Go's encoder `omitempty`-drops an empty `key_id`/`meta`,
    /// so a well-formed AUM never carries an empty-non-nil one, and on the wire an absent field
    /// decodes to the nil/empty representation either way. The invariant the future AUM wire decoder
    /// (chunk 2) MUST uphold to stay consensus-identical with Go: decode an **absent OR empty** key 4
    /// / key 7 to the empty `Vec` (i.e. collapse Go's empty-non-nil into "absent"), never surfacing a
    /// distinct empty-but-present state that would flip one of these checks.
    ///
    /// The same invariant covers **`prev_aum_hash` (key 2)**: Go `AUM.StaticValidate` rejects a
    /// present-but-zero-length `PrevAUMHash` ("absent parent must be a nil slice"), but this fork's
    /// `Option<AumHash>` (`AumHash` wraps a fixed `[u8; 32]`) can only be `None` (nil) or a full
    /// 32-byte hash — Go's rejected empty-non-nil state is structurally unrepresentable, so the check
    /// is unnecessary here. The decoder MUST likewise map an absent OR empty key-2 byte string to
    /// `None`, never an empty-present hash, or a future widening of the representation could
    /// reintroduce that divergence.
    pub fn static_validate(&self) -> Result<(), TkaError> {
        if let Some(key) = &self.key {
            key.static_validate()?;
        }
        for sig in &self.signatures {
            if sig.key_id.len() != 32 || sig.signature.len() != 64 {
                return Err(TkaError::Decode(
                    "AUM signature has missing keyID or malformed signature",
                ));
            }
        }
        if let Some(state) = &self.state {
            state.static_validate_checkpoint()?;
        }

        // Field-presence shorthands for the per-kind allow-lists.
        let has_key = self.key.is_some();
        let has_key_id = !self.key_id.is_empty();
        let has_state = self.state.is_some();
        let has_votes = self.votes.is_some();
        let has_meta = !self.meta.is_empty();

        match self.message_kind {
            AumKind::AddKey => {
                if !has_key {
                    return Err(TkaError::Decode("AddKey AUMs must contain a key"));
                }
                if has_key_id || has_state || has_votes || has_meta {
                    return Err(TkaError::Decode("AddKey AUMs may only specify a Key"));
                }
            }
            AumKind::RemoveKey => {
                if !has_key_id {
                    return Err(TkaError::Decode("RemoveKey AUMs must specify a key ID"));
                }
                if has_key || has_state || has_votes || has_meta {
                    return Err(TkaError::Decode("RemoveKey AUMs may only specify a KeyID"));
                }
            }
            AumKind::UpdateKey => {
                if !has_key_id {
                    return Err(TkaError::Decode("UpdateKey AUMs must specify a key ID"));
                }
                if !has_votes && !has_meta {
                    return Err(TkaError::Decode(
                        "UpdateKey AUMs must contain an update to votes or key metadata",
                    ));
                }
                if has_key || has_state {
                    return Err(TkaError::Decode(
                        "UpdateKey AUMs may only specify KeyID, Votes, and Meta",
                    ));
                }
            }
            AumKind::Checkpoint => {
                if !has_state {
                    return Err(TkaError::Decode("Checkpoint AUMs must specify the state"));
                }
                if has_key_id || has_key || has_votes || has_meta {
                    return Err(TkaError::Decode("Checkpoint AUMs may only specify State"));
                }
            }
            // NoOp + Invalid (and, once an AUM decoder exists, any unknown forward-compat kind):
            // no field constraints, matching Go's `AUMNoOp` empty case + tolerant `default`.
            AumKind::NoOp | AumKind::Invalid => {}
        }
        Ok(())
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

// ===========================================================================================
// AUM-chain replay (issue #7, chunk 1B) — the acquisition-side derivation of a trusted-key
// `State`/`Authority` from a chain of `Aum`s, mirroring Go `tka/state.go` + `tka/tka.go`.
// ===========================================================================================

/// The mutable trusted-key state a replay folds AUMs into. Carries the keys plus the hash of the
/// last AUM applied (Go `State.LastAUMHash`), which the next AUM's `prev_aum_hash` must match.
/// Distinct from the public [`State`] (which is the verify-only snapshot the [`Authority`] exposes);
/// this one tracks the chain cursor needed during replay.
#[derive(Debug, Clone, Default)]
struct ReplayState {
    keys: Vec<AumKey>,
    last_aum_hash: Option<AumHash>,
    /// The `(StateID1, StateID2)` seeded by the genesis checkpoint, if any. A *subsequent*
    /// checkpoint must carry the same pair (Go state.go: "checkpointed state has an incorrect
    /// stateID"); `None` until a checkpoint is applied.
    state_id: Option<(u64, u64)>,
}

impl ReplayState {
    fn get_key(&self, key_id: &[u8]) -> Option<&AumKey> {
        self.keys.iter().find(|k| k.id() == key_id)
    }

    fn find_key_index(&self, key_id: &[u8]) -> Option<usize> {
        self.keys.iter().position(|k| k.id() == key_id)
    }

    /// The total signing weight of `aum` under this state (Go `AUM.Weight`): the sum of `votes` over
    /// the **distinct** keys (deduped by key id) that both signed the AUM *and* are trusted here.
    /// An unknown signing key contributes 0; a key that signed twice counts once.
    fn weight(&self, aum: &Aum) -> u64 {
        let mut seen: Vec<&[u8]> = Vec::new();
        let mut weight: u64 = 0;
        for sig in &aum.signatures {
            let id = sig.key_id.as_slice();
            if seen.contains(&id) {
                continue;
            }
            if let Some(key) = self.get_key(id) {
                weight += key.votes as u64;
                seen.push(id);
            }
        }
        weight
    }

    /// Fold one already-signature-verified AUM into the state (Go `State.applyVerifiedAUM`).
    ///
    /// Checks the parent-hash chain link first (a brand-new state with no `last_aum_hash` matches any
    /// parent — the genesis case), then applies the per-kind mutation. Advances `last_aum_hash` to
    /// the applied AUM's own hash so the next link can be verified.
    ///
    /// When this is the genesis (the state has no `last_aum_hash` yet), Go restricts the kind to
    /// `NoOp`/`AddKey`/`Checkpoint` (Go `computeStateAt` rejects anything else as
    /// "invalid genesis update") and a genesis AUM must carry no parent — both are enforced here so a
    /// non-genesis-rooted slice can't be silently accepted as if it were a genesis.
    fn apply_verified_aum(&mut self, aum: &Aum) -> Result<(), TkaError> {
        match &self.last_aum_hash {
            // Once the chain is rolling, the AUM must name the current head as its parent.
            Some(head) => match &aum.prev_aum_hash {
                Some(prev) if prev == head => {}
                _ => return Err(TkaError::BadParent),
            },
            // Genesis: must have no parent, and only certain kinds may start a chain.
            None => {
                if aum.prev_aum_hash.is_some() {
                    return Err(TkaError::BadParent);
                }
                if !matches!(
                    aum.message_kind,
                    AumKind::NoOp | AumKind::AddKey | AumKind::Checkpoint
                ) {
                    return Err(TkaError::BadChain);
                }
            }
        }

        match aum.message_kind {
            AumKind::NoOp | AumKind::Invalid => {
                // No state change (unknown/forward-compat kinds are tolerated as no-ops, matching
                // Go's `default` arm). The chain cursor still advances (below).
            }
            AumKind::Checkpoint => {
                // A checkpoint replaces the whole key set with its embedded snapshot. A genesis
                // checkpoint seeds the authority's StateID; a later checkpoint must match it (Go
                // rejects "checkpointed state has an incorrect stateID") — otherwise it belongs to a
                // different authority and replaying it would silently fork the trusted-key set.
                let state = aum
                    .state
                    .as_ref()
                    .ok_or(TkaError::Decode("checkpoint AUM missing state"))?;
                let incoming = (state.state_id1, state.state_id2);
                match self.state_id {
                    Some(existing) if existing != incoming => {
                        return Err(TkaError::BadKeyState);
                    }
                    _ => self.state_id = Some(incoming),
                }
                // A checkpoint replaces the key set with its snapshot; a nil `keys` (Go nil) means
                // "no trusted keys", i.e. the empty set.
                self.keys = state.keys.clone().unwrap_or_default();
            }
            AumKind::AddKey => {
                let key = aum
                    .key
                    .as_ref()
                    .ok_or(TkaError::Decode("AddKey AUM missing key"))?;
                if self.get_key(key.id()).is_some() {
                    return Err(TkaError::BadKeyState);
                }
                self.keys.push(key.clone());
            }
            AumKind::UpdateKey => {
                let idx = self
                    .find_key_index(&aum.key_id)
                    .ok_or(TkaError::BadKeyState)?;
                // Mirror Go `applyVerifiedAUM` (AUMUpdateKey): each field is applied only when the
                // update carries it — `if update.Votes != nil` / `if update.Meta != nil`. `votes`
                // maps cleanly to `Option<u32>`. `meta` is a `Vec`, which cannot distinguish Go's
                // nil map (leave unchanged) from an empty-but-present map (clear) — we treat empty
                // as "not carried / leave unchanged", matching the nil case. The empty-but-present
                // "clear meta" case is both unrepresentable here and verify-irrelevant (the
                // verify-path `Key` drops `meta` entirely via `to_key`, so it never reaches a
                // `node_key_authorized` decision); document the limitation rather than assign
                // unconditionally, which would wrongly wipe `meta` on a votes-only update.
                if let Some(votes) = aum.votes {
                    self.keys[idx].votes = votes;
                }
                if !aum.meta.is_empty() {
                    self.keys[idx].meta = aum.meta.clone();
                }
                // Go `applyVerifiedAUM` re-runs `k.StaticValidate()` after the mutation and errors
                // "updated key fails validation" if the *result* is invalid (e.g. votes set to 0 or
                // > 4096). Without this, an out-of-range UpdateKey one node accepts and another
                // rejects flips fork weight → consensus split.
                self.keys[idx].static_validate()?;
            }
            AumKind::RemoveKey => {
                // Last-key guard (Go `aumVerify`): refuse to remove the final trusted key — that
                // would leave the authority with an empty key set and effectively disable tailnet
                // lock. Checked against the key id, before the removal.
                if self.keys.len() == 1 && self.keys[0].id() == aum.key_id.as_slice() {
                    return Err(TkaError::BadKeyState);
                }
                let idx = self
                    .find_key_index(&aum.key_id)
                    .ok_or(TkaError::BadKeyState)?;
                self.keys.remove(idx);
            }
        }

        self.last_aum_hash = Some(aum.hash());
        Ok(())
    }

    /// The verify-path [`State`] snapshot (just the trusted keys).
    fn to_state(&self) -> State {
        State {
            keys: self.keys.iter().map(AumKey::to_key).collect(),
        }
    }

    /// Verify an AUM's signatures against the trusted keys in **this** state — the authenticity
    /// gate Go runs in `aumVerify` (`tka/tka.go`) before `applyVerifiedAUM`. This is MUST-1: a
    /// control-supplied chain must not advance the trusted-key state on an AUM that isn't signed by
    /// keys already trusted at its parent.
    ///
    /// Mirrors Go exactly (verified against `tailscale/tailscale` v1.100.0):
    /// - **`len(signatures) == 0` ⇒ "unsigned AUM"** ([`TkaError::UnsignedAum`]). Every AUM,
    ///   including the genesis, must be signed.
    /// - For **every** signature (not "at least one"): its `key_id` must resolve to a key trusted in
    ///   this state ([`TkaError::UntrustedKey`] otherwise), and the signature must verify
    ///   cryptographically over [`Aum::sig_hash`] with that key — cofactored Ed25519
    ///   (`ed25519consensus.Verify` / ZIP-215), the same primitive the node-key-signature Direct
    ///   path uses. Any failure rejects the whole AUM ([`TkaError::BadSignature`]).
    /// - **No weight/threshold gate here.** Go's `aumVerify` does *not* compare `Weight` against any
    ///   quorum; weight is used only by [`pick_next_aum`] for fork resolution. "Authentic" means
    ///   all signatures valid against trusted keys.
    /// - `is_genesis` only documents intent; unlike Go it changes nothing in *this* function (Go's
    ///   `isGenesisAUM` flag gates `checkParent`, which the replayer performs separately in
    ///   [`ReplayState::apply_verified_aum`]). The signature checks run identically for genesis and
    ///   non-genesis AUMs.
    fn verify_aum_signatures(&self, aum: &Aum, _is_genesis: bool) -> Result<(), TkaError> {
        if aum.signatures.is_empty() {
            return Err(TkaError::UnsignedAum);
        }
        let sig_hash = aum.sig_hash();
        for sig in &aum.signatures {
            let key = self.get_key(&sig.key_id).ok_or(TkaError::UntrustedKey)?;
            if key.kind != KeyKind::Ed25519 || key.public.len() != 32 {
                return Err(TkaError::Decode("AUM signing key is not ed25519"));
            }
            // AUM `tkatype.Signature` verifies cofactored (ZIP-215), matching Go's
            // `signatureVerify` → `ed25519consensus.Verify`.
            verify_ed25519_zip215(&key.public, &sig_hash, &sig.signature)?;
        }
        Ok(())
    }
}

/// A chain of AUMs whose signatures have been verified as it was folded from genesis to head — the
/// only input [`Authority::from_verified_chain`] accepts. This is MUST-1 made un-skippable in the
/// type system: a `VerifiedAumChain` can be obtained **only** via [`VerifiedAumChain::verify`],
/// which runs Go's `aumVerify` on every AUM against the trusted-key state as it stood at that AUM's
/// parent. A control-supplied `&[Aum]` therefore cannot reach a live `Authority`'s trusted-key set
/// without each link being signed by keys already trusted at the point it is applied.
///
/// Mirrors Go `tka.Authority.Inform` (`InformIdempotent` → `aumVerify(update, state, false)` →
/// `CommitVerifiedAUMs`), which verifies as it folds rather than trusting a precomputed chain.
#[derive(Debug, Clone)]
pub struct VerifiedAumChain {
    /// The replayed trusted-key state at the head (already folded + verified).
    state: ReplayState,
    /// The head AUM hash (the chain link the resulting authority advertises).
    head: AumHash,
}

impl VerifiedAumChain {
    /// Verify and replay a **linear** chain of AUMs from genesis to head, checking each AUM's
    /// signatures against the trusted-key state at its parent (MUST-1). On success the returned
    /// value witnesses that every link is authentic and the chain folds cleanly.
    ///
    /// `aums` must be ordered parent→child (the first is the genesis). The genesis is verified
    /// against the trusted-key set it establishes: a genesis **`Checkpoint`** self-certifies (its
    /// signatures must verify against the keys it embeds, exactly Go's
    /// `aumVerify(bootstrap, *bootstrap.State, true)`); a genesis `AddKey`/`NoOp` is verified
    /// against the keys present *after* it seeds them, so a bootstrapping `AddKey` must be
    /// self-signed by the key it introduces. Each subsequent AUM is verified against the state at
    /// its parent, then folded.
    ///
    /// # Errors
    /// [`TkaError::UnsignedAum`] for an AUM with no signatures; [`TkaError::UntrustedKey`] if a
    /// signature names a key not trusted at that point; [`TkaError::BadSignature`] on a failed
    /// cryptographic check; plus every structural error of [`ReplayState::apply_verified_aum`]
    /// ([`TkaError::BadChain`]/[`BadParent`](TkaError::BadParent)/[`BadKeyState`](TkaError::BadKeyState)/[`Decode`](TkaError::Decode)).
    pub fn verify(aums: &[Aum]) -> Result<VerifiedAumChain, TkaError> {
        let last = aums.last().ok_or(TkaError::BadChain)?;
        let head = last.hash();
        let mut state = ReplayState::default();
        for (i, aum) in aums.iter().enumerate() {
            let is_genesis = i == 0;
            // Go `aumVerify` runs `aum.StaticValidate()` FIRST (before parent/signature checks). It
            // is state-independent (per-kind field allow-lists, per-sig 32/64-byte lengths, embedded
            // Key/Checkpoint validity), so it gates every AUM the same way regardless of position.
            aum.static_validate()?;
            // Then the structural fold + signature verify. Apply the fold FIRST for the genesis so a
            // genesis `Checkpoint`/`AddKey` seeds the trusted keys, then verify signatures against
            // the resulting state — this is what lets a genesis self-certify (Go verifies a bootstrap
            // Checkpoint against its own embedded `*State`). For a non-genesis AUM,
            // `apply_verified_aum` only mutates *after* its parent-link check passes; we verify
            // signatures against the state-at-parent by checking BEFORE the fold.
            if is_genesis {
                state.apply_verified_aum(aum)?;
                state.verify_aum_signatures(aum, true)?;
            } else {
                state.verify_aum_signatures(aum, false)?;
                state.apply_verified_aum(aum)?;
            }
        }
        Ok(VerifiedAumChain { state, head })
    }
}

/// Choose the next AUM to apply when more than one child extends the current head (Go
/// `tka.pickNextAUM`). The three rules, in order:
///
/// 1. **Highest signature weight** wins (computed against `state`).
/// 2. If tied, prefer the **`RemoveKey`** AUM (a revocation should not be out-voted by a no-op fork).
/// 3. If still tied, the **lowest `AUM.Hash()`** (bytewise) wins — a deterministic, content-derived
///    tiebreak both peers compute identically.
///
/// `candidates` must be non-empty. The comparison is total and deterministic, so every node
/// replaying the same chain selects the same active branch (the property tailnet-lock relies on).
fn pick_next_aum<'a>(state: &ReplayState, candidates: &'a [Aum]) -> &'a Aum {
    debug_assert!(!candidates.is_empty(), "pick_next_aum needs candidates");
    let mut best = &candidates[0];
    let mut best_weight = state.weight(best);
    let mut best_hash = best.hash();
    for cand in &candidates[1..] {
        let w = state.weight(cand);
        let h = cand.hash();
        // Rule 1: strictly higher weight wins.
        let better = if w != best_weight {
            w > best_weight
        } else if (cand.message_kind == AumKind::RemoveKey)
            != (best.message_kind == AumKind::RemoveKey)
        {
            // Rule 2: exactly one is a RemoveKey → that one wins.
            cand.message_kind == AumKind::RemoveKey
        } else {
            // Rule 3: lowest hash wins.
            h.0 < best_hash.0
        };
        if better {
            best = cand;
            best_weight = w;
            best_hash = h;
        }
    }
    best
}

impl Authority {
    /// Build an [`Authority`] from a [`VerifiedAumChain`] — the **trust-boundary** constructor.
    ///
    /// Because a `VerifiedAumChain` can only be produced by [`VerifiedAumChain::verify`] (which runs
    /// Go's `aumVerify` on every link), this is the constructor a live client must use when the chain
    /// originates from an untrusted source (the control plane / `/machine/tka/*` sync RPC). The type
    /// system makes the signature check un-skippable: there is no way to reach this function with an
    /// unverified chain. Mirrors Go `tka.Open`, which folds only AUMs already verified by `Inform`.
    pub fn from_verified_chain(chain: VerifiedAumChain) -> Authority {
        Authority {
            head: chain.head,
            state: chain.state.to_state(),
        }
    }

    /// Build an [`Authority`] by replaying a **linear** chain of AUMs from genesis to head (Go
    /// `tka.Authority.Head` after `computeActiveChain` on a single confirmed branch), checking only
    /// the chain's **structure** (genesis kind, parent links, key-state transitions, checkpoint
    /// StateID) — **NOT** AUM signatures.
    ///
    /// # This is NOT a trust boundary
    /// `from_chain` does not verify that each AUM is signed by keys trusted at its parent. It is safe
    /// only for chains whose authenticity is already established by other means — the existing unit
    /// tests, and a chain the caller has *itself* fed through [`VerifiedAumChain::verify`]. For any
    /// chain that comes from an untrusted source (the control plane), use
    /// [`VerifiedAumChain::verify`] + [`Authority::from_verified_chain`], which the type system makes
    /// impossible to bypass. (A malicious control plane could otherwise forge an `AddKey`/`RemoveKey`
    /// here and silently defeat tailnet lock — the exact threat TKA exists to stop.)
    ///
    /// `aums` must be ordered parent→child: the first is the genesis — a `NoOp`, `AddKey`, or
    /// `Checkpoint` with **no** parent (Go `computeStateAt` rejects any other kind as an invalid
    /// genesis) — and each subsequent AUM's `prev_aum_hash` must equal the prior AUM's [`Aum::hash`].
    /// A slice that is actually a *suffix* of a chain (its first AUM names a parent not in the slice)
    /// is rejected rather than mis-rooted.
    ///
    /// For the **forked** case (competing children of one parent), use [`Authority::from_forked_chain`].
    ///
    /// # Errors
    /// [`TkaError::BadChain`] if `aums` is empty or its genesis is an invalid kind;
    /// [`TkaError::BadParent`] if a link doesn't chain (incl. a genesis that carries a parent);
    /// [`TkaError::BadKeyState`] for an invalid add/remove/update or a mismatched checkpoint StateID;
    /// [`TkaError::Decode`] for a malformed checkpoint/add.
    pub fn from_chain(aums: &[Aum]) -> Result<Authority, TkaError> {
        let last = aums.last().ok_or(TkaError::BadChain)?;
        let head = last.hash();
        let mut state = ReplayState::default();
        for aum in aums {
            state.apply_verified_aum(aum)?;
        }
        Ok(Authority {
            head,
            state: state.to_state(),
        })
    }

    /// Resolve a **single fork point**: a shared linear `prefix` (genesis→fork point, parent-ordered)
    /// followed by `branches`, the competing children of the fork point. The active child is chosen by
    /// [`pick_next_aum`]'s deterministic rules (weight → `RemoveKey` preference → lowest hash),
    /// evaluated against the state at the fork point, and applied. This is the consensus-critical
    /// selection every node must make identically; the linear [`Authority::from_chain`] is the common
    /// (no-fork) case.
    ///
    /// **Each branch must be exactly one AUM.** In this single-AUM-per-branch shape the choice is
    /// provably identical to Go's `pickNextAUM` over the fork point's children. A *multi-step* branch
    /// is **rejected** ([`TkaError::BadChain`]) rather than mis-resolved: Go re-runs `pickNextAUM` at
    /// *every* link (`advanceByPrimary`), re-evaluating weight against the evolving state, so judging a
    /// whole multi-AUM branch by its first AUM alone could pick a different active head than Go and
    /// silently fork the trusted-key set. Implementing the per-step loop (and a general multi-fork DAG
    /// walk) is deferred to when the sync layer can actually surface such a chain; until then this
    /// guard keeps the model honest. (The common re-bootstrap case — competing single-AUM heads — is
    /// fully covered.)
    ///
    /// # Errors
    /// As [`Authority::from_chain`], plus [`TkaError::BadChain`] if `branches` is empty, or any branch
    /// is not exactly one AUM.
    pub fn from_forked_chain(prefix: &[Aum], branches: &[&[Aum]]) -> Result<Authority, TkaError> {
        // Each branch must be exactly one AUM — see the doc: a multi-step branch judged by its first
        // AUM could diverge from Go's per-step resolution. Reject rather than silently mis-resolve.
        if branches.is_empty() || branches.iter().any(|b| b.len() != 1) {
            return Err(TkaError::BadChain);
        }
        let mut state = ReplayState::default();
        for aum in prefix {
            state.apply_verified_aum(aum)?;
        }
        // Choose the winning child, judged against the state at the fork point — exactly Go's
        // `pickNextAUM` over the children.
        let heads: Vec<Aum> = branches.iter().map(|b| b[0].clone()).collect();
        let winner_head = pick_next_aum(&state, &heads).hash();
        let winner = branches
            .iter()
            .find(|b| b[0].hash() == winner_head)
            .ok_or(TkaError::BadChain)?;
        state.apply_verified_aum(&winner[0])?;
        Ok(Authority {
            head: winner[0].hash(),
            state: state.to_state(),
        })
    }
}

// ===========================================================================================
// AUM-chain sync (issue #7, chunk 2 — `tsr-5po`): the acquisition-side machinery a client uses
// to catch its local chain up to the control server's, mirroring Go `tka/sync.go` + the
// `computeStateAt`/`fastForward` chain walkers in `tka/tka.go` (v1.100.0). This is the storage +
// offer/missing layer the `/machine/tka/sync` RPC (a later chunk) drives; it does NOT itself talk
// to the network.
//
// Verification posture: the walkers fold AUMs with `ReplayState::apply_verified_aum`
// (structural-only, exactly Go's `applyVerifiedAUM`), NOT `verify_aum_signatures`. Authenticity is
// enforced separately when a synced chain is turned into an `Authority` (via
// `VerifiedAumChain::verify` + `from_verified_chain`, the un-bypassable trust boundary). The store
// itself is untrusted scratch space — putting unverified AUMs in it is fine because nothing trusts
// them until that boundary runs.
// ===========================================================================================

/// The starting number of AUMs to skip between ancestors in a [`SyncOffer`] (Go
/// `ancestorsSkipStart`). The gap grows exponentially (`<< ancestorsSkipShift` each step).
const ANCESTORS_SKIP_START: u64 = 4;
/// How many bits to advance the ancestor skip count each step (Go `ancestorsSkipShift`): `4 << 2 =
/// 16`, so after skipping 4 it skips 16, then 64…
const ANCESTORS_SKIP_SHIFT: u64 = 2;
/// Iteration cap for the backward head-intersection walk + offer ancestor walk (Go
/// `maxSyncHeadIntersectionIter`, `tka/limits.go`).
const MAX_SYNC_HEAD_INTERSECTION_ITER: u64 = 400;
/// Iteration cap for forward fast-forward / `computeStateAt` walks (Go `maxSyncIter` /
/// `maxScanIterations`, `tka/limits.go`).
const MAX_SYNC_ITER: usize = 2000;

/// A read-only store of AUMs keyed by hash, plus the parent→children index the forward walk needs
/// (Go's `tka.Chonk`, reduced to the methods the sync/offer path actually calls). The client builds
/// one of these from the AUMs it has on hand; the sync RPC populates it with what control sends.
///
/// "Not found" is signalled by `None` from [`aum`](AumStore::aum) (Go's `os.ErrNotExist` sentinel),
/// which the walkers treat as a loop terminator, not an error.
pub trait AumStore {
    /// Fetch the AUM with this hash, or `None` if the store does not hold it.
    fn aum(&self, hash: &AumHash) -> Option<Aum>;
    /// The AUMs whose `prev_aum_hash` is `hash` — the forward links out of `hash` (Go
    /// `Chonk.ChildAUMs`). Order is unspecified; the caller resolves forks deterministically.
    fn child_aums(&self, hash: &AumHash) -> Vec<Aum>;
}

/// An in-memory [`AumStore`]: a hash→AUM map plus a parent-hash→child-hashes index, both built as
/// AUMs are inserted. `no_std`-friendly (`BTreeMap`, not `HashMap`). This is the store a client uses
/// to stage the AUMs it knows about while computing a [`SyncOffer`] / the AUMs a peer is missing.
#[derive(Debug, Clone, Default)]
pub struct MemAumStore {
    by_hash: alloc::collections::BTreeMap<AumHash, Aum>,
    /// parent hash → child hashes (the forward index). A genesis AUM (no parent) contributes no
    /// entry here; it is found only via `by_hash`.
    children: alloc::collections::BTreeMap<AumHash, Vec<AumHash>>,
}

impl MemAumStore {
    /// A new, empty store.
    pub fn new() -> MemAumStore {
        MemAumStore::default()
    }

    /// Insert an AUM, indexing it by its own hash and (if it has a parent) under its parent's child
    /// list. Idempotent: re-inserting the same AUM hash replaces it and does not duplicate the child
    /// edge. Returns the inserted AUM's hash.
    pub fn insert(&mut self, aum: Aum) -> AumHash {
        let hash = aum.hash();
        if let Some(parent) = aum.prev_aum_hash {
            let kids = self.children.entry(parent).or_default();
            if !kids.contains(&hash) {
                kids.push(hash);
            }
        }
        self.by_hash.insert(hash, aum);
        hash
    }

    /// Build a store from an iterator of AUMs (e.g. a chain or a sync batch).
    pub fn from_aums(aums: impl IntoIterator<Item = Aum>) -> MemAumStore {
        let mut store = MemAumStore::new();
        for aum in aums {
            store.insert(aum);
        }
        store
    }

    /// Number of AUMs held.
    pub fn len(&self) -> usize {
        self.by_hash.len()
    }

    /// Whether the store holds no AUMs.
    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }

    /// Walk the chain from `oldest` (the genesis) forward to the head, returning the AUMs in
    /// parent→child order — the linear form [`VerifiedAumChain::verify`] / [`Authority::from_chain`]
    /// expect. At a fork (a parent with more than one child) the deterministic [`pick_next_aum`] rule
    /// chooses the branch, so the result is the active chain (matching how the chain is replayed).
    ///
    /// Used by the runtime sync driver to turn the AUMs accumulated in the store (genesis +
    /// sync-received) into the ordered chain it re-verifies into an [`Authority`]. Bounded by
    /// [`MAX_SYNC_ITER`] so a malformed/cyclic store cannot loop forever.
    ///
    /// # Errors
    /// [`TkaError::BadChain`] if `oldest` is not in the store, or the walk exceeds the iteration cap
    /// (a cycle or an over-long chain). Signature/structure are NOT checked here — that is `verify`'s
    /// job; this only orders the AUMs.
    pub fn linear_chain_from(&self, oldest: AumHash) -> Result<Vec<Aum>, TkaError> {
        let mut out = Vec::new();
        let Some(mut curs) = self.aum(&oldest) else {
            return Err(TkaError::BadChain);
        };
        for _ in 0..MAX_SYNC_ITER {
            out.push(curs.clone());
            let children = self.child_aums(&curs.hash());
            if children.is_empty() {
                return Ok(out);
            }
            // Deterministic branch choice at a fork (weight → RemoveKey → lowest-hash). For a linear
            // chain there is exactly one child; `pick_next_aum` returns it. We don't have a replayed
            // `ReplayState` here, so use a default (empty-key) state — at a genuine fork that means
            // the weight term is 0 for both and the tiebreak falls through to the lowest-hash rule,
            // which is still deterministic and matches what a fresh verifier would pick before any
            // keys are trusted. (Sync stores are linear in practice; forks are the rare case.)
            let next = pick_next_aum(&ReplayState::default(), &children).clone();
            curs = next;
        }
        Err(TkaError::BadChain) // iteration cap: cycle or over-long chain
    }
}

impl AumStore for MemAumStore {
    fn aum(&self, hash: &AumHash) -> Option<Aum> {
        self.by_hash.get(hash).cloned()
    }

    fn child_aums(&self, hash: &AumHash) -> Vec<Aum> {
        self.children
            .get(hash)
            .map(|kids| {
                kids.iter()
                    .filter_map(|h| self.by_hash.get(h).cloned())
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// A node's view of where its chain is, offered to a peer so the peer can work out what to send (Go
/// `tka.SyncOffer`): the current `head` plus a sparse, exponentially-spaced sample of `ancestors`
/// back to the oldest AUM the node holds. The last entry is always the oldest-known AUM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncOffer {
    /// The node's current chain head.
    pub head: AumHash,
    /// A subset of the chain's ancestors, newest-first, ending with the oldest-known AUM. Used by a
    /// peer to find a "tail intersection" when it doesn't recognise the head.
    pub ancestors: Vec<AumHash>,
}

/// The result of comparing two [`SyncOffer`]s (Go `tka.intersection`): where (if anywhere) the two
/// chains meet, which tells [`missing_aums`](sync_missing_aums) where to start gathering.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Intersection {
    /// Both heads are equal — nothing to exchange.
    up_to_date: bool,
    /// The newest common AUM that is the *remote's* head and an ancestor of ours (we have updates
    /// building on it to send).
    head_intersection: Option<AumHash>,
    /// The oldest common AUM, where the chains diverge — a starting point to send from when we don't
    /// recognise the remote's head.
    tail_intersection: Option<AumHash>,
}

/// Compute the state at `want_hash` by walking back to a checkpoint or genesis, then forward along
/// the taken path (Go `computeStateAt`, `tka/tka.go`). Structural fold only (no signature check) —
/// the verify boundary is elsewhere. Returns `None` (not an error) if `want_hash` is not in the
/// store, mirroring the `os.ErrNotExist` sentinel Go callers special-case.
fn compute_state_at(
    storage: &dyn AumStore,
    max_iter: usize,
    want_hash: AumHash,
) -> Result<Option<ReplayState>, TkaError> {
    let Some(top) = storage.aum(&want_hash) else {
        return Ok(None);
    };

    // Walk backwards to a starting point: a checkpoint AUM (which carries full state) or a genesis
    // AUM (no parent — valid only for NoOp/AddKey/Checkpoint). `path` records every hash on the way
    // so the forward pass can follow exactly this branch (which, for a non-primary fork, may differ
    // from standard fork resolution).
    let mut curs = top;
    let mut state = ReplayState::default();
    let mut path: alloc::collections::BTreeSet<AumHash> = alloc::collections::BTreeSet::new();
    let mut started = false;
    for i in 0..=max_iter {
        if i == max_iter {
            return Err(TkaError::BadChain); // iteration limit exceeded
        }
        path.insert(curs.hash());

        if curs.message_kind == AumKind::Checkpoint {
            // A checkpoint encapsulates the state at that point: fold it into an empty state.
            let mut s = ReplayState::default();
            s.apply_verified_aum(&curs)?;
            state = s;
            started = true;
            break;
        }
        match curs.prev_aum_hash {
            None => {
                // Genesis: applies to the empty state. Only NoOp/AddKey reach here (Checkpoint broke
                // above); anything else is an invalid genesis. `apply_verified_aum` enforces the
                // same kind restriction, so just fold and let it reject a bad genesis.
                let mut s = ReplayState::default();
                s.apply_verified_aum(&curs)?;
                state = s;
                started = true;
                break;
            }
            Some(parent) => {
                let Some(p) = storage.aum(&parent) else {
                    return Err(TkaError::BadParent); // dangling parent link
                };
                curs = p;
            }
        }
    }
    debug_assert!(
        started,
        "compute_state_at must find a checkpoint or genesis"
    );

    // Fast-forward from the starting point, following only AUMs on `path` (the custom advancer),
    // until we reach `want_hash`. No gather side-effect here — we only want the final state.
    let (_, end_state) = fast_forward(
        storage,
        max_iter,
        state,
        &mut |_: &Aum, _: &mut ReplayState| Ok(false),
        Some(&path),
        Some(want_hash),
    )?;
    Ok(Some(end_state))
}

/// Fast-forward from `start_state` along the chain (Go `fastForwardWithAdvancer` +
/// `advanceByPrimary`). At each step it takes the children of the current AUM and advances by:
/// - the child on `path` when `path` is `Some` (the `computeStateAt` custom advancer), or
/// - [`pick_next_aum`]'s deterministic fork resolution otherwise (the primary advancer).
///
/// Stops when `stop_at` (when set) is reached — returning that AUM + the state *before* applying it
/// for a gather caller, matching Go's `done(curs, state)` check at the top of the loop — or when
/// there are no more children. `gather` is invoked for each visited AUM (Go's `done` callback side
/// effect) and its boolean return additionally stops the walk when true.
///
/// Returns the final AUM reached and the folded state at it. Structural fold only.
fn fast_forward(
    storage: &dyn AumStore,
    max_iter: usize,
    start_state: ReplayState,
    gather: &mut dyn FnMut(&Aum, &mut ReplayState) -> Result<bool, TkaError>,
    path: Option<&alloc::collections::BTreeSet<AumHash>>,
    stop_at: Option<AumHash>,
) -> Result<(Aum, ReplayState), TkaError> {
    let start_hash = start_state
        .last_aum_hash
        .ok_or(TkaError::Decode("fast_forward from a state with no head"))?;
    let mut curs = storage.aum(&start_hash).ok_or(TkaError::BadParent)?;
    let mut state = start_state;

    for _ in 0..max_iter {
        // Done check runs BEFORE advancing (Go checks `done(curs, state)` at loop top): for a
        // `stop_at` caller this returns the stop AUM with the state *before* applying it.
        if Some(curs.hash()) == stop_at {
            return Ok((curs, state));
        }
        // Side-effect callback (the gather closure for `missing_aums`); a `true` return also stops.
        if gather(&curs, &mut state)? {
            return Ok((curs, state));
        }

        let children = storage.child_aums(&curs.hash());
        let next = match path {
            // `computeStateAt` advancer: follow the unique child that is on the recorded path.
            Some(p) => children.into_iter().find(|c| p.contains(&c.hash())),
            // Primary advancer: deterministic fork resolution.
            None => {
                if children.is_empty() {
                    None
                } else {
                    Some(pick_next_aum(&state, &children).clone())
                }
            }
        };
        match next {
            None => return Ok((curs, state)), // no more children: we are at head
            Some(n) => {
                state.apply_verified_aum(&n)?;
                curs = n;
            }
        }
    }
    Err(TkaError::BadChain) // iteration limit exceeded
}

impl Authority {
    /// Build the [`SyncOffer`] this authority would send a peer (Go `Authority.SyncOffer`): its
    /// `head` plus an exponentially-spaced sample of ancestors back to `oldest`, ending with
    /// `oldest`. `oldest` is the oldest AUM the caller holds (Go `a.oldestAncestor.Hash()`); our
    /// verify-only [`Authority`] does not track it, so it is passed in — typically the genesis hash
    /// of the chain the caller staged in `storage`.
    ///
    /// `storage` must contain the chain from `head` back to `oldest`; a gap simply truncates the
    /// ancestor list early (the walk breaks on the first missing parent, exactly like Go).
    pub fn sync_offer(
        &self,
        storage: &dyn AumStore,
        oldest: AumHash,
    ) -> Result<SyncOffer, TkaError> {
        let mut out = SyncOffer {
            head: self.head,
            ancestors: Vec::with_capacity(6),
        };
        let mut skip_amount = ANCESTORS_SKIP_START;
        let mut curs = self.head;
        for i in 0..MAX_SYNC_HEAD_INTERSECTION_ITER {
            if i > 0 && skip_amount != 0 && i % skip_amount == 0 {
                out.ancestors.push(curs);
                skip_amount <<= ANCESTORS_SKIP_SHIFT;
            }
            let Some(parent) = storage.aum(&curs) else {
                break; // os.ErrNotExist: stop, don't error
            };
            // We append `oldest` after the loop, so don't duplicate it.
            if parent.hash() == oldest {
                break;
            }
            match parent.prev_aum_hash {
                Some(prev) => curs = prev,
                None => break, // reached a genesis that isn't `oldest`; nothing earlier to walk
            }
        }
        out.ancestors.push(oldest);
        Ok(out)
    }

    /// Given a peer's [`SyncOffer`], compute the AUMs **they** are missing — the ones to send them so
    /// their chain catches up to ours (Go `Authority.MissingAUMs`). `storage` must hold our chain.
    /// Returns an empty `Vec` when the peer is already up to date.
    ///
    /// Mirrors Go: compute our own offer, find the intersection of the two chains, then gather every
    /// AUM from the intersection forward to our head (excluding the intersection AUM itself).
    pub fn missing_aums(
        &self,
        storage: &dyn AumStore,
        remote_offer: &SyncOffer,
        oldest: AumHash,
    ) -> Result<Vec<Aum>, TkaError> {
        let local_offer = self.sync_offer(storage, oldest)?;
        let isect = compute_sync_intersection(storage, &local_offer, remote_offer)?;
        if isect.up_to_date {
            return Ok(Vec::new());
        }
        let from = isect
            .head_intersection
            .or(isect.tail_intersection)
            .ok_or(TkaError::BadChain)?; // Go panics "unreachable"; we fail closed instead.

        let Some(state) = compute_state_at(storage, MAX_SYNC_ITER, from)? else {
            return Err(TkaError::BadParent);
        };
        let mut out: Vec<Aum> = Vec::with_capacity(12);
        fast_forward(
            storage,
            MAX_SYNC_ITER,
            state,
            &mut |curs: &Aum, _: &mut ReplayState| -> Result<bool, TkaError> {
                // Gather every AUM from the intersection forward, excluding the intersection itself.
                if curs.hash() != from {
                    out.push(curs.clone());
                }
                Ok(false) // never stop early; walk to head (no more children)
            },
            None,
            None,
        )?;
        Ok(out)
    }
}

/// Find where two chains meet (Go `computeSyncIntersection`). See [`Intersection`].
fn compute_sync_intersection(
    storage: &dyn AumStore,
    local_offer: &SyncOffer,
    remote_offer: &SyncOffer,
) -> Result<Intersection, TkaError> {
    // Simple case: identical heads → up to date.
    if remote_offer.head == local_offer.head {
        return Ok(Intersection {
            up_to_date: true,
            head_intersection: Some(local_offer.head),
            tail_intersection: None,
        });
    }

    // Head intersection: if we hold the remote's head, walk back from our head looking for it. If
    // found, their head is an ancestor of ours and we have the AUMs that build on it.
    if storage.aum(&remote_offer.head).is_some() {
        let mut curs = local_offer.head;
        for _ in 0..MAX_SYNC_HEAD_INTERSECTION_ITER {
            let Some(parent) = storage.aum(&curs) else {
                break; // os.ErrNotExist
            };
            if parent.hash() == remote_offer.head {
                return Ok(Intersection {
                    up_to_date: false,
                    head_intersection: Some(parent.hash()),
                    tail_intersection: None,
                });
            }
            match parent.prev_aum_hash {
                Some(prev) => curs = prev,
                None => break,
            }
        }
    }

    // Tail intersection: we don't recognise their head, but if one of the ancestors they offered is
    // on our chain, that's a starting point. Iterate in their order (newest-first) so we pick the
    // most-recent shared ancestor and send the fewest AUMs.
    for ancestor in &remote_offer.ancestors {
        let state = match compute_state_at(storage, MAX_SYNC_ITER, *ancestor)? {
            Some(s) => s,
            None => continue, // os.ErrNotExist: we don't have this ancestor; try the next
        };
        let (end, _) = fast_forward(
            storage,
            MAX_SYNC_ITER,
            state,
            &mut |_: &Aum, _: &mut ReplayState| Ok(false),
            None,
            Some(local_offer.head),
        )?;
        // fast_forward can stop early (no more children) before reaching the target, so re-check.
        if end.hash() == local_offer.head {
            return Ok(Intersection {
                up_to_date: false,
                head_intersection: None,
                tail_intersection: Some(*ancestor),
            });
        }
    }

    Err(TkaError::BadChain) // ErrNoIntersection
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

/// A byte string, or an empty `Vec` for CBOR `null` — the decode inverse of [`bytes_or_null`]. Go's
/// `fxamacker/cbor` encodes a nil *non*-`omitempty` `[]byte` field as CBOR null (`0xf6`); on decode
/// that round-trips back to an empty `Vec` (the field's zero value). Any other CBOR type is rejected.
fn expect_bytes_or_null(v: Value) -> Result<Vec<u8>, TkaError> {
    match v {
        Value::Bytes(b) => Ok(b),
        Value::Null => Ok(Vec::new()),
        _ => Err(TkaError::Decode("expected byte string or null")),
    }
}

fn expect_uint(v: Value) -> Result<u64, TkaError> {
    match v {
        Value::Uint(n) => Ok(n),
        _ => Err(TkaError::Decode("expected unsigned integer")),
    }
}

/// Decode a `map[string]string` (`Meta`) from a [`Value::TextMap`]. Values must be text strings.
fn meta_from_value(
    v: Value,
) -> Result<Vec<(alloc::string::String, alloc::string::String)>, TkaError> {
    let Value::TextMap(entries) = v else {
        return Err(TkaError::Decode("meta is not a text-keyed map"));
    };
    let mut out = Vec::with_capacity(entries.len());
    for (k, val) in entries {
        let Value::Text(vbytes) = val else {
            return Err(TkaError::Decode("meta value not text"));
        };
        let key = alloc::string::String::from_utf8(k)
            .map_err(|_| TkaError::Decode("meta key not utf-8"))?;
        let value = alloc::string::String::from_utf8(vbytes)
            .map_err(|_| TkaError::Decode("meta value not utf-8"))?;
        out.push((key, value));
    }
    Ok(out)
}

/// Decode a 32-byte [`AumHash`] from a CBOR byte string of exactly 32 bytes.
fn aum_hash_from_bytes(b: Vec<u8>) -> Result<AumHash, TkaError> {
    let arr: [u8; AUM_HASH_LEN] = b
        .try_into()
        .map_err(|_| TkaError::Decode("AUM hash not 32 bytes"))?;
    Ok(AumHash(arr))
}

impl AumKey {
    /// Decode an [`AumKey`] from its CBOR value (Go `tka.Key`; keymap `kind`=1, `votes`=2,
    /// `public`=3, `meta`=12). The inverse of [`AumKey::to_cbor`]. Only `Key25519` (kind `1`) is
    /// supported (the sole [`KeyKind`] this fork models); any other kind is rejected (fail-closed).
    fn from_value(v: Value) -> Result<AumKey, TkaError> {
        let Value::IntMap(entries) = v else {
            return Err(TkaError::Decode("key is not an int-keyed map"));
        };
        let mut kind = None;
        let mut votes = None;
        let mut public = None;
        let mut meta = Vec::new();
        for (k, val) in entries {
            match k {
                1 => {
                    kind = Some(match expect_uint(val)? {
                        1 => KeyKind::Ed25519,
                        _ => return Err(TkaError::Decode("unsupported key kind")),
                    })
                }
                2 => {
                    votes = Some(
                        u32::try_from(expect_uint(val)?)
                            .map_err(|_| TkaError::Decode("key votes out of range"))?,
                    )
                }
                3 => public = Some(expect_bytes_or_null(val)?),
                12 => meta = meta_from_value(val)?,
                _ => return Err(TkaError::Decode("unknown key field")),
            }
        }
        Ok(AumKey {
            kind: kind.ok_or(TkaError::Decode("key missing kind"))?,
            votes: votes.ok_or(TkaError::Decode("key missing votes"))?,
            public: public.ok_or(TkaError::Decode("key missing public"))?,
            meta,
        })
    }
}

impl AumState {
    /// Decode an [`AumState`] from its CBOR value (Go `tka.State`; keymap `last_aum_hash`=1,
    /// `disablement_values`=2, `keys`=3, `state_id1`=4, `state_id2`=5). The inverse of
    /// [`AumState::to_cbor`]: keys 1/2/3 are non-`omitempty`, so a nil one arrives as CBOR null
    /// (`None`); a present array arrives as `Some(vec)` (possibly empty). Keys 4/5 are `omitempty`,
    /// defaulting to 0 when absent.
    fn from_value(v: Value) -> Result<AumState, TkaError> {
        let Value::IntMap(entries) = v else {
            return Err(TkaError::Decode("state is not an int-keyed map"));
        };
        let mut state = AumState::default();
        for (k, val) in entries {
            match k {
                1 => {
                    state.last_aum_hash = match val {
                        Value::Null => None,
                        Value::Bytes(b) => Some(aum_hash_from_bytes(b)?),
                        _ => return Err(TkaError::Decode("last_aum_hash not bytes or null")),
                    }
                }
                2 => {
                    state.disablement_values = match val {
                        Value::Null => None,
                        Value::Array(items) => Some(
                            items
                                .into_iter()
                                .map(expect_bytes)
                                .collect::<Result<Vec<_>, _>>()?,
                        ),
                        _ => return Err(TkaError::Decode("disablement_values not array or null")),
                    }
                }
                3 => {
                    state.keys = match val {
                        Value::Null => None,
                        Value::Array(items) => Some(
                            items
                                .into_iter()
                                .map(AumKey::from_value)
                                .collect::<Result<Vec<_>, _>>()?,
                        ),
                        _ => return Err(TkaError::Decode("state keys not array or null")),
                    }
                }
                4 => state.state_id1 = expect_uint(val)?,
                5 => state.state_id2 = expect_uint(val)?,
                _ => return Err(TkaError::Decode("unknown state field")),
            }
        }
        Ok(state)
    }
}

impl AumSignature {
    /// Decode an [`AumSignature`] from its CBOR value (Go `tkatype.Signature`; keymap `key_id`=1,
    /// `signature`=2, both non-`omitempty` → a nil one is CBOR null → empty `Vec`).
    fn from_value(v: Value) -> Result<AumSignature, TkaError> {
        let Value::IntMap(entries) = v else {
            return Err(TkaError::Decode("signature is not an int-keyed map"));
        };
        let mut key_id = None;
        let mut signature = None;
        for (k, val) in entries {
            match k {
                1 => key_id = Some(expect_bytes_or_null(val)?),
                2 => signature = Some(expect_bytes_or_null(val)?),
                _ => return Err(TkaError::Decode("unknown AUM signature field")),
            }
        }
        Ok(AumSignature {
            key_id: key_id.ok_or(TkaError::Decode("AUM signature missing key_id"))?,
            signature: signature.ok_or(TkaError::Decode("AUM signature missing signature"))?,
        })
    }
}

impl Aum {
    /// Decode an [`Aum`] from its canonical CBOR serialization (the inverse of [`Aum::serialize`] /
    /// [`Aum::to_cbor`]). This is the acquisition primitive a sync/bootstrap path uses to turn the
    /// raw `MarshaledAUM` bytes control sends into an [`Aum`] before it is verified and replayed
    /// (Go `tka.AUM` CBOR unmarshal).
    ///
    /// The keymap (Go `cbor:"…,keyasint"`): `message_kind`=1 and `prev_aum_hash`=2 are
    /// non-`omitempty` (a nil prev arrives as CBOR null → `None`); `key`=3, `key_id`=4, `state`=5,
    /// `votes`=6, `meta`=7, `signatures`=23 are `omitempty` (absent ⇒ the field's zero value).
    ///
    /// Fail-closed: a trailing byte after the AUM, an unknown field key, a wrong value type, an
    /// unknown `message_kind`, or any malformed CBOR head all return [`TkaError::Decode`]. The
    /// decoder does NOT re-canonicalize or validate chain structure — that is the verifier's job; it
    /// only reconstructs the struct the bytes describe.
    ///
    /// # Errors
    ///
    /// Returns [`TkaError::Decode`] if `buf` is not exactly one canonical-shaped AUM CBOR map.
    pub fn from_cbor(buf: &[u8]) -> Result<Aum, TkaError> {
        let (val, rest) = decode_value(buf, 0)?;
        if !rest.is_empty() {
            return Err(TkaError::Decode("trailing bytes after AUM"));
        }
        let Value::IntMap(entries) = val else {
            return Err(TkaError::Decode("AUM is not an int-keyed map"));
        };
        let mut message_kind = None;
        let mut prev_aum_hash = None;
        let mut have_prev = false;
        let mut key = None;
        let mut key_id = Vec::new();
        let mut state = None;
        let mut votes = None;
        let mut meta = Vec::new();
        let mut signatures = Vec::new();
        for (k, v) in entries {
            match k {
                1 => {
                    message_kind = Some(
                        AumKind::from_u8(
                            u8::try_from(expect_uint(v)?)
                                .map_err(|_| TkaError::Decode("message kind out of range"))?,
                        )
                        .ok_or(TkaError::Decode("unknown AUM message kind"))?,
                    )
                }
                2 => {
                    have_prev = true;
                    prev_aum_hash = match v {
                        Value::Null => None,
                        Value::Bytes(b) => Some(aum_hash_from_bytes(b)?),
                        _ => return Err(TkaError::Decode("prev_aum_hash not bytes or null")),
                    }
                }
                3 => key = Some(AumKey::from_value(v)?),
                4 => key_id = expect_bytes_or_null(v)?,
                5 => state = Some(AumState::from_value(v)?),
                6 => {
                    votes = Some(
                        u32::try_from(expect_uint(v)?)
                            .map_err(|_| TkaError::Decode("votes out of range"))?,
                    )
                }
                7 => meta = meta_from_value(v)?,
                23 => {
                    let Value::Array(items) = v else {
                        return Err(TkaError::Decode("signatures not an array"));
                    };
                    signatures = items
                        .into_iter()
                        .map(AumSignature::from_value)
                        .collect::<Result<Vec<_>, _>>()?;
                }
                _ => return Err(TkaError::Decode("unknown AUM field")),
            }
        }
        // `message_kind` (1) and `prev_aum_hash` (2) are non-`omitempty`: both keys must be present
        // on the wire (the prev *value* may be null, but the key itself is always emitted).
        if !have_prev {
            return Err(TkaError::Decode("AUM missing prev_aum_hash"));
        }
        Ok(Aum {
            message_kind: message_kind.ok_or(TkaError::Decode("AUM missing message kind"))?,
            prev_aum_hash,
            key,
            key_id,
            state,
            votes,
            meta,
            signatures,
        })
    }
}

/// Decode one CBOR value (the subset the encoder produces) from `buf`, returning the value and the
/// remaining bytes. Minimal — only the major types TKA uses.
fn decode_value(buf: &[u8], depth: usize) -> Result<(Value, &[u8]), TkaError> {
    // Bound generic CBOR container nesting so a deeply-nested array/map (even a non-signature one,
    // e.g. an AUM with nested arrays) cannot overflow the recursive decoder before shape validation
    // runs. Shared by the AUM and node-key-signature paths, so the message is kept neutral (the
    // signature-specific depth guard with its own message lives in `node_key_signature_from_value`).
    if depth > MAX_SIG_NESTING_DEPTH {
        return Err(TkaError::Decode("CBOR nesting too deep"));
    }
    let (major, arg, rest) = decode_head(buf)?;
    match major {
        0 => Ok((Value::Uint(arg), rest)),
        2 => {
            // `usize::try_from` rather than `as usize`: on a 32-bit target a `u64` length above
            // `usize::MAX` must fail closed, not silently truncate to a smaller in-bounds length.
            let len = usize::try_from(arg).map_err(|_| TkaError::Decode("byte string too long"))?;
            if rest.len() < len {
                return Err(TkaError::Decode("byte string truncated"));
            }
            Ok((Value::Bytes(rest[..len].to_vec()), &rest[len..]))
        }
        3 => {
            let len = usize::try_from(arg).map_err(|_| TkaError::Decode("text string too long"))?;
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
            // A CBOR map decodes to either an `IntMap` (unsigned-integer keys — the `keyasint`
            // structs: AUM, Key, State, signatures) or a `TextMap` (text-string keys — Go
            // `map[string]string` `Meta` fields). The variant is chosen by the FIRST key's major
            // type and every key must match it: TKA never emits a mixed-key map, so a key whose
            // type differs from the first is rejected (fail-closed). An empty map decodes to an
            // empty `IntMap` (matching the prior behavior; an empty `map[string]string` is
            // `omitempty`-dropped by Go, so an empty map on the wire is always a struct).
            decode_map(rest, arg, depth)
        }
        // Major type 7: only the `null` simple value (`0xf6`, argument 22) is accepted. Go's
        // `fxamacker/cbor` emits CBOR null for a nil *non*-`omitempty` byte/slice/pointer field —
        // an AUM's genesis `prev_aum_hash`, `AumSignature.{key_id,signature}`, and an `AumState`'s
        // `last_aum_hash`/`disablement_values`/`keys` (see the encoder's `Value::Null` arm). Any
        // other major-7 simple value or float (booleans, undefined, `f16`/`f32`/`f64`) is rejected:
        // TKA never emits them, so accepting them would only widen the attack surface. The
        // `NodeKeySignature` path is unaffected — its `expect_bytes` rejects `Value::Null`, so a
        // null where bytes are required still fails closed there.
        7 if arg == 22 => Ok((Value::Null, rest)),
        // Major types 1 (negative int) and 6 (tag), and any other major-7 value, are unsupported.
        _ => Err(TkaError::Decode("unsupported CBOR major type")),
    }
}

/// Decode the `count` key/value pairs of a CBOR map (major type 5) from `buf`, producing either a
/// [`Value::IntMap`] (unsigned-integer keys) or a [`Value::TextMap`] (text-string keys). The key
/// type is fixed by the first pair; every subsequent key must use the same major type (TKA emits no
/// mixed-key maps). An empty map decodes to an empty `IntMap`. Duplicate keys are rejected
/// (fail-closed), matching the CTAP2 / Go "no duplicate map keys" rule. Map *key ordering is not
/// enforced* on decode: the verify path re-serializes canonically before hashing, so a non-canonical
/// input simply produces a different (still self-consistent) struct, never a hash that silently
/// matches Go's for different bytes.
fn decode_map(buf: &[u8], count: u64, depth: usize) -> Result<(Value, &[u8]), TkaError> {
    if count == 0 {
        return Ok((Value::IntMap(Vec::new()), buf));
    }
    // Peek the first key's major type to pick the map variant.
    let (first_major, ..) = decode_head(buf)?;
    match first_major {
        0 => {
            let mut entries: Vec<(u64, Value)> = Vec::new();
            let mut cur = buf;
            for _ in 0..count {
                let (k, next) = decode_head(cur).and_then(|(m, a, r)| {
                    if m == 0 {
                        Ok((a, r))
                    } else {
                        Err(TkaError::Decode("mixed map key types"))
                    }
                })?;
                let (v, next2) = decode_value(next, depth + 1)?;
                entries.push((k, v));
                cur = next2;
            }
            reject_duplicate_keys(entries.iter().map(|(k, _)| *k))?;
            Ok((Value::IntMap(entries), cur))
        }
        3 => {
            let mut entries: Vec<(Vec<u8>, Value)> = Vec::new();
            let mut cur = buf;
            for _ in 0..count {
                // Decode the text-string key via the shared value decoder so its length/truncation
                // checks apply uniformly, then require it to be `Value::Text`.
                let (key_val, next) = decode_value(cur, depth + 1)?;
                let Value::Text(k) = key_val else {
                    return Err(TkaError::Decode("mixed map key types"));
                };
                let (v, next2) = decode_value(next, depth + 1)?;
                entries.push((k, v));
                cur = next2;
            }
            reject_duplicate_keys(entries.iter().map(|(k, _)| k.clone()))?;
            Ok((Value::TextMap(entries), cur))
        }
        _ => Err(TkaError::Decode("map key not uint or text string")),
    }
}

/// Reject a CBOR map with duplicate keys (CTAP2 / Go forbid them) in `O(n log n)` via a sort, rather
/// than the `O(n²)` per-insert linear scan a naive decoder uses. The map element count is
/// attacker-controlled (a CBOR head can claim a large count), so the quadratic form is a latent
/// super-linear CPU-DoS on a hostile control-plane blob; the sort keeps it linear-ish. Insertion
/// order of the map itself is preserved by the caller (the verify path re-serializes canonically
/// before hashing, so wire order never reaches a hash).
fn reject_duplicate_keys<K: Ord>(keys: impl Iterator<Item = K>) -> Result<(), TkaError> {
    let mut ks: Vec<K> = keys.collect();
    ks.sort_unstable();
    if ks.windows(2).any(|w| w[0] == w[1]) {
        return Err(TkaError::Decode("duplicate map key"));
    }
    Ok(())
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
        // The shared generic-container depth guard in `decode_value` trips first (the CBOR is
        // nested past the cap before the signature-shape walk runs), so the neutral message.
        assert_eq!(err, TkaError::Decode("CBOR nesting too deep"));
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

    // ----- tsr-358: nested-Credential `pubkey` is UNUSED (Go parity) -----

    /// A rotation wrapping a nested **Credential** must verify regardless of the credential's
    /// `pubkey` field — Go's `SigCredential` "certifies an indirection key rather than a node key,
    /// so there's no need to check the node key", and `verifySignature` adds NO `nested.pubkey ==
    /// wrappingPublic` bind. The pre-fix code rejected the real Go shape (empty credential `pubkey`)
    /// and only accepted a fork-invented `pubkey == wrapping_pub` construction — a deny-direction
    /// consensus split (legitimate credential-provisioned peers wrongly denied under enforce). This
    /// pins the Go behavior: empty `pubkey` accepted, and an arbitrary (ignored) `pubkey` also
    /// accepted; security comes purely from the two signatures verifying, not from the field.
    #[test]
    fn rotation_nested_credential_pubkey_is_unused() {
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

        // Build a rotation wrapping a nested Credential whose `pubkey` is `cred_pubkey`. The
        // credential is signed by the trusted key over its own sig-hash; the credential's
        // `wrapping_pubkey` is the rotation pivot the outer signature is verified against.
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

        // The real Go shape: a SigCredential leaves `Pubkey` EMPTY. Must be accepted.
        let cbor_empty = build(Vec::new());
        assert!(
            auth.node_key_authorized(&node_key, &cbor_empty).is_ok(),
            "a credential with empty pubkey (the Go shape) must verify"
        );

        // An arbitrary credential `pubkey` is IGNORED (Go never checks it) — also accepted.
        let cbor_arbitrary = build(alloc::vec![0xaau8; 32]);
        assert!(
            auth.node_key_authorized(&node_key, &cbor_arbitrary).is_ok(),
            "a credential's pubkey is unused; an arbitrary value must not change the verdict"
        );

        // Sanity: tampering the OUTER rotation signature is still rejected (the real security gate).
        let mut outer_bad_cbor = {
            let mut inner = NodeKeySignature {
                sig_kind: SigKind::Credential,
                pubkey: Vec::new(),
                key_id: trusted_pub.clone(),
                signature: Vec::new(),
                nested: None,
                wrapping_pubkey: wrapping_pub.clone(),
            };
            let ih = inner.sig_hash();
            inner.signature = trusted.sign(&ih).to_bytes().to_vec();
            let mut outer = NodeKeySignature {
                sig_kind: SigKind::Rotation,
                pubkey: node_key.clone(),
                key_id: Vec::new(),
                signature: Vec::new(),
                nested: Some(alloc::boxed::Box::new(inner)),
                wrapping_pubkey: Vec::new(),
            };
            let oh = outer.sig_hash();
            let mut sig = wrapping.sign(&oh).to_bytes().to_vec();
            sig[0] ^= 0xff;
            outer.signature = sig;
            outer.to_cbor(true).to_vec()
        };
        assert_eq!(
            auth.node_key_authorized(&node_key, &outer_bad_cbor)
                .unwrap_err(),
            TkaError::BadSignature,
            "a tampered rotation-wrap signature must still be rejected"
        );
        outer_bad_cbor.clear();
    }

    /// Multi-level rotation: an intermediate rotation layer omits its own `wrapping_pubkey`, so the
    /// outer signature's verify key must be resolved by RECURSING (`wrapping_public`) into the
    /// inner-most layer that defines one — Go `NodeKeySignature.wrappingPublic`. The pre-fix code
    /// read `nested.wrapping_pubkey` directly and rejected this with "wrapping pubkey wrong length"
    /// (the second deny-direction consensus split).
    #[test]
    fn multi_level_rotation_resolves_wrapping_key_by_recursion() {
        use ed25519_dalek::{Signer, SigningKey};

        let trusted = SigningKey::from_bytes(&[21u8; 32]);
        let trusted_pub = trusted.verifying_key().to_bytes().to_vec();
        // The single rotation pivot key, carried only on the INNERMOST signature.
        let pivot = SigningKey::from_bytes(&[23u8; 32]);
        let pivot_pub = pivot.verifying_key().to_bytes().to_vec();
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

        // Innermost: a Direct signature by the trusted key, carrying the pivot as its wrapping key.
        let mut inner = NodeKeySignature {
            sig_kind: SigKind::Direct,
            pubkey: pivot_pub.clone(),
            key_id: trusted_pub.clone(),
            signature: Vec::new(),
            nested: None,
            wrapping_pubkey: pivot_pub.clone(),
        };
        let inner_hash = inner.sig_hash();
        inner.signature = trusted.sign(&inner_hash).to_bytes().to_vec();

        // Middle rotation: OMITS its own wrapping_pubkey (empty) — wrapping_public must recurse to
        // `inner`'s pivot. Its outer-of-inner signature is verified under the pivot key.
        let mut middle = NodeKeySignature {
            sig_kind: SigKind::Rotation,
            pubkey: pivot_pub.clone(),
            key_id: Vec::new(),
            signature: Vec::new(),
            nested: Some(alloc::boxed::Box::new(inner)),
            wrapping_pubkey: Vec::new(),
        };
        let middle_hash = middle.sig_hash();
        middle.signature = pivot.sign(&middle_hash).to_bytes().to_vec();

        // Outer rotation over `middle`: also resolves its verify key by recursing to the pivot.
        let mut outer = NodeKeySignature {
            sig_kind: SigKind::Rotation,
            pubkey: node_key.clone(),
            key_id: Vec::new(),
            signature: Vec::new(),
            nested: Some(alloc::boxed::Box::new(middle)),
            wrapping_pubkey: Vec::new(),
        };
        let outer_hash = outer.sig_hash();
        outer.signature = pivot.sign(&outer_hash).to_bytes().to_vec();

        let cbor = outer.to_cbor(true).to_vec();
        assert!(
            auth.node_key_authorized(&node_key, &cbor).is_ok(),
            "a multi-level rotation with an intermediate omitting wrapping_pubkey must verify via recursion"
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
                disablement_values: Some(Vec::new()),
                keys: Some(alloc::vec![AumKey {
                    kind: KeyKind::Ed25519,
                    votes: 1,
                    public: alloc::vec![5, 6],
                    meta: Vec::new(),
                }]),
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

    // ---- AUM-chain replay (chunk 1B) -----------------------------------------------------------

    /// A test trusted key from a seed byte (deterministic public key + given votes).
    fn test_aum_key(seed: u8, votes: u32) -> AumKey {
        use ed25519_dalek::SigningKey;
        let pubk = SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
            .to_vec();
        AumKey {
            kind: KeyKind::Ed25519,
            votes,
            public: pubk,
            meta: Vec::new(),
        }
    }

    /// A genesis `AUMAddKey` (no parent) adding `key`.
    fn genesis_add(key: AumKey) -> Aum {
        Aum {
            message_kind: AumKind::AddKey,
            prev_aum_hash: None,
            key: Some(key),
            key_id: Vec::new(),
            state: None,
            votes: None,
            meta: Vec::new(),
            signatures: Vec::new(),
        }
    }

    /// A child AUM of `parent` of the given kind, optionally carrying a key / key_id.
    fn child(parent: &Aum, kind: AumKind, key: Option<AumKey>, key_id: Vec<u8>) -> Aum {
        Aum {
            message_kind: kind,
            prev_aum_hash: Some(parent.hash()),
            key,
            key_id,
            state: None,
            votes: None,
            meta: Vec::new(),
            signatures: Vec::new(),
        }
    }

    /// Linear replay applies each kind: genesis AddKey(k0), AddKey(k1), UpdateKey(k1 votes), then
    /// RemoveKey(k0). The final state has only k1 with its updated votes, and head = last AUM hash.
    #[test]
    fn replay_linear_chain_folds_all_kinds() {
        let k0 = test_aum_key(1, 1);
        let k1 = test_aum_key(2, 1);

        let a0 = genesis_add(k0.clone());
        let a1 = child(&a0, AumKind::AddKey, Some(k1.clone()), Vec::new());
        let mut a2 = child(&a1, AumKind::UpdateKey, None, k1.public.clone());
        a2.votes = Some(5);
        let a3 = child(&a2, AumKind::RemoveKey, None, k0.public.clone());

        let auth = Authority::from_chain(&[a0, a1, a2, a3.clone()]).unwrap();

        // Only k1 remains, with the updated vote weight.
        assert_eq!(auth.state().keys.len(), 1, "k0 removed, k1 remains");
        let remaining = &auth.state().keys[0];
        assert_eq!(remaining.public, k1.public, "k1 is the surviving key");
        assert_eq!(remaining.votes, 5, "UpdateKey raised k1's votes to 5");
        // Head is the hash of the last applied AUM.
        assert_eq!(auth.head(), a3.hash(), "head = last AUM hash");
    }

    /// A broken chain link (wrong `prev_aum_hash`) is rejected with `BadParent`.
    #[test]
    fn replay_rejects_broken_parent_link() {
        let k0 = test_aum_key(1, 1);
        let k1 = test_aum_key(2, 1);
        let a0 = genesis_add(k0);
        // a1 claims a bogus parent, not a0's hash.
        let mut a1 = child(&a0, AumKind::AddKey, Some(k1), Vec::new());
        a1.prev_aum_hash = Some(AumHash([0xab; 32]));
        assert_eq!(
            Authority::from_chain(&[a0, a1]).unwrap_err(),
            TkaError::BadParent
        );
    }

    /// AddKey of an already-trusted key, and Remove/Update of an absent key, are rejected.
    #[test]
    fn replay_rejects_bad_key_state() {
        let k0 = test_aum_key(1, 1);
        let a0 = genesis_add(k0.clone());
        // Duplicate add of k0.
        let dup = child(&a0, AumKind::AddKey, Some(k0.clone()), Vec::new());
        assert_eq!(
            Authority::from_chain(&[a0.clone(), dup]).unwrap_err(),
            TkaError::BadKeyState
        );
        // Remove of a key that was never added.
        let absent = test_aum_key(9, 1);
        let rm = child(&a0, AumKind::RemoveKey, None, absent.public.clone());
        assert_eq!(
            Authority::from_chain(&[a0, rm]).unwrap_err(),
            TkaError::BadKeyState
        );
    }

    /// An empty chain is rejected.
    #[test]
    fn replay_empty_chain_is_bad_chain() {
        assert_eq!(Authority::from_chain(&[]).unwrap_err(), TkaError::BadChain);
    }

    /// `weight` sums the votes of distinct trusted signing keys: an unknown signer contributes 0, and
    /// a key that signs twice counts once (Go `TestAUMWeight` "Double use" → its votes, not double).
    #[test]
    fn replay_weight_dedups_and_ignores_unknown() {
        let k0 = test_aum_key(1, 2);
        let k1 = test_aum_key(2, 3);
        let state = ReplayState {
            keys: alloc::vec![k0.clone(), k1.clone()],
            last_aum_hash: None,
            state_id: None,
        };

        // Empty signatures → 0.
        let mut aum = genesis_add(test_aum_key(5, 1));
        assert_eq!(state.weight(&aum), 0);

        // One known signer (k0, votes 2).
        aum.signatures = alloc::vec![AumSignature {
            key_id: k0.public.clone(),
            signature: Vec::new()
        }];
        assert_eq!(state.weight(&aum), 2);

        // Two distinct known signers → 2 + 3 = 5.
        aum.signatures = alloc::vec![
            AumSignature {
                key_id: k0.public.clone(),
                signature: Vec::new()
            },
            AumSignature {
                key_id: k1.public.clone(),
                signature: Vec::new()
            },
        ];
        assert_eq!(state.weight(&aum), 5);

        // Double-use of k0 → counted once (2), not 4.
        aum.signatures = alloc::vec![
            AumSignature {
                key_id: k0.public.clone(),
                signature: Vec::new()
            },
            AumSignature {
                key_id: k0.public.clone(),
                signature: Vec::new()
            },
        ];
        assert_eq!(state.weight(&aum), 2, "a key signing twice counts once");

        // Unknown signer → 0.
        aum.signatures = alloc::vec![AumSignature {
            key_id: alloc::vec![0xff; 32],
            signature: Vec::new()
        }];
        assert_eq!(
            state.weight(&aum),
            0,
            "an untrusted signing key contributes no weight"
        );
    }

    /// `pick_next_aum` rule 3 (the deterministic tiebreak): with equal weight (0, no signatures) and
    /// neither a RemoveKey, the candidate with the lexicographically-lowest `Hash()` wins —
    /// regardless of input order, so two nodes select the same branch.
    #[test]
    fn pick_next_aum_lowest_hash_tiebreak_is_order_independent() {
        let k = test_aum_key(1, 1);
        let a0 = genesis_add(k);
        // Two distinct NoOp children of a0 (differ by key_id so their hashes differ).
        let c1 = child(&a0, AumKind::NoOp, None, alloc::vec![1]);
        let c2 = child(&a0, AumKind::NoOp, None, alloc::vec![2]);
        let state = ReplayState::default();

        let lower = if c1.hash().0 < c2.hash().0 {
            c1.hash()
        } else {
            c2.hash()
        };
        let ab = [c1.clone(), c2.clone()];
        let ba = [c2, c1];
        let pick_ab = pick_next_aum(&state, &ab).hash();
        let pick_ba = pick_next_aum(&state, &ba).hash();
        assert_eq!(pick_ab, lower, "lowest hash wins");
        assert_eq!(
            pick_ab, pick_ba,
            "selection is independent of candidate order"
        );
    }

    /// `pick_next_aum` rule 1 (weight) dominates rule 3 (hash): a signed child with real weight beats
    /// an unsigned child even if the unsigned one has a lower hash.
    #[test]
    fn pick_next_aum_weight_beats_hash() {
        use ed25519_dalek::SigningKey;
        let signer_seed = 3u8;
        let signer_pub = SigningKey::from_bytes(&[signer_seed; 32])
            .verifying_key()
            .to_bytes()
            .to_vec();
        let state = ReplayState {
            keys: alloc::vec![AumKey {
                kind: KeyKind::Ed25519,
                votes: 4,
                public: signer_pub.clone(),
                meta: Vec::new(),
            }],
            last_aum_hash: None,
            state_id: None,
        };

        let a0 = genesis_add(test_aum_key(1, 1));
        let unsigned = child(&a0, AumKind::NoOp, None, alloc::vec![1]);
        let mut signed = child(&a0, AumKind::NoOp, None, alloc::vec![2]);
        signed.signatures = alloc::vec![AumSignature {
            key_id: signer_pub,
            signature: Vec::new(),
        }];

        // The signed child wins on weight (4 > 0) no matter the hash order.
        let candidates = [unsigned.clone(), signed.clone()];
        let winner = pick_next_aum(&state, &candidates);
        assert_eq!(
            winner.hash(),
            signed.hash(),
            "higher weight wins over lower hash"
        );
    }

    /// `from_forked_chain`: a shared genesis, then two competing RemoveKey vs NoOp branches at equal
    /// weight — rule 2 prefers the RemoveKey branch. The resulting state reflects the chosen branch.
    #[test]
    fn forked_chain_prefers_removekey_branch() {
        let k0 = test_aum_key(1, 1);
        let k1 = test_aum_key(2, 1);
        // Genesis adds both keys (two AUMs).
        let a0 = genesis_add(k0.clone());
        let a1 = child(&a0, AumKind::AddKey, Some(k1.clone()), Vec::new());
        // Fork at a1: branch A removes k0; branch B is a NoOp. Equal weight (0 sigs).
        let branch_remove = child(&a1, AumKind::RemoveKey, None, k0.public.clone());
        let branch_noop = child(&a1, AumKind::NoOp, None, alloc::vec![9]);

        let noop_branch = [branch_noop.clone()];
        let remove_branch = [branch_remove.clone()];
        let auth = Authority::from_forked_chain(&[a0, a1], &[&noop_branch[..], &remove_branch[..]])
            .unwrap();

        // RemoveKey branch wins → k0 gone, only k1 remains; head = the RemoveKey AUM.
        assert_eq!(auth.state().keys.len(), 1);
        assert_eq!(auth.state().keys[0].public, k1.public);
        assert_eq!(
            auth.head(),
            branch_remove.hash(),
            "active head = RemoveKey branch"
        );
    }

    /// End-to-end: replay a chain to an `Authority`, then verify it authorizes a node key signed by a
    /// trusted key — proving the replayed state drives `node_key_authorized` identically to
    /// `from_state`. A key removed by the chain no longer authorizes.
    #[test]
    fn replayed_authority_authorizes_node_end_to_end() {
        use ed25519_dalek::{Signer, SigningKey};

        let signing = SigningKey::from_bytes(&[77u8; 32]);
        let trusted_pub = signing.verifying_key().to_bytes().to_vec();
        let trusted = AumKey {
            kind: KeyKind::Ed25519,
            votes: 1,
            public: trusted_pub.clone(),
            meta: Vec::new(),
        };
        // A second key we'll add then remove, to show a removed key can't authorize.
        let revoked_signing = SigningKey::from_bytes(&[88u8; 32]);
        let revoked_pub = revoked_signing.verifying_key().to_bytes().to_vec();
        let revoked = AumKey {
            kind: KeyKind::Ed25519,
            votes: 1,
            public: revoked_pub.clone(),
            meta: Vec::new(),
        };

        let a0 = genesis_add(trusted);
        let a1 = child(&a0, AumKind::AddKey, Some(revoked), Vec::new());
        let a2 = child(&a1, AumKind::RemoveKey, None, revoked_pub.clone());
        let auth = Authority::from_chain(&[a0, a1, a2]).unwrap();

        let node_key = alloc::vec![7u8; 32];
        // Signature from the still-trusted key authorizes.
        let mut sig = NodeKeySignature {
            sig_kind: SigKind::Direct,
            pubkey: node_key.clone(),
            key_id: trusted_pub.clone(),
            signature: Vec::new(),
            nested: None,
            wrapping_pubkey: Vec::new(),
        };
        sig.signature = signing.sign(&sig.sig_hash()).to_bytes().to_vec();
        assert!(
            auth.node_key_authorized(&node_key, &sig.to_cbor(true).to_vec())
                .is_ok(),
            "the replayed authority must authorize a node signed by a still-trusted key"
        );

        // The same node key signed by the REVOKED key must be rejected (key no longer in state).
        let mut bad = NodeKeySignature {
            sig_kind: SigKind::Direct,
            pubkey: node_key.clone(),
            key_id: revoked_pub.clone(),
            signature: Vec::new(),
            nested: None,
            wrapping_pubkey: Vec::new(),
        };
        bad.signature = revoked_signing.sign(&bad.sig_hash()).to_bytes().to_vec();
        assert_eq!(
            auth.node_key_authorized(&node_key, &bad.to_cbor(true).to_vec())
                .unwrap_err(),
            TkaError::UntrustedKey,
            "a key the chain removed must not authorize"
        );
    }

    /// Genesis-kind guard (Go `computeStateAt` "invalid genesis update"): a chain whose first AUM is
    /// a `RemoveKey`/`UpdateKey` is rejected. (A genesis `NoOp`/`AddKey`/`Checkpoint` is allowed.)
    #[test]
    fn replay_rejects_invalid_genesis_kind() {
        // A bare RemoveKey as genesis: no key to remove → today this is BadKeyState, but the genesis
        // guard catches an UpdateKey before the key lookup. Use UpdateKey to exercise the guard arm.
        let mut g = genesis_add(test_aum_key(1, 1));
        g.message_kind = AumKind::UpdateKey;
        g.key = None;
        g.key_id = test_aum_key(1, 1).public.clone();
        assert_eq!(
            Authority::from_chain(&[g]).unwrap_err(),
            TkaError::BadChain,
            "an UpdateKey cannot be a genesis AUM"
        );
    }

    /// Genesis must carry no parent: a first AUM with a non-None `prev_aum_hash` (i.e. a chain
    /// *suffix* mis-supplied as a whole chain) is rejected as `BadParent`, not silently re-rooted.
    #[test]
    fn replay_rejects_genesis_with_parent() {
        let mut g = genesis_add(test_aum_key(1, 1));
        g.prev_aum_hash = Some(AumHash([0x11; 32])); // names a parent not in the slice
        assert_eq!(
            Authority::from_chain(&[g]).unwrap_err(),
            TkaError::BadParent,
            "a genesis AUM that names a parent must be rejected (not treated as genesis)"
        );
    }

    /// Checkpoint StateID guard (Go "checkpointed state has an incorrect stateID"): a genesis
    /// checkpoint seeds the StateID; a later checkpoint with a different StateID is rejected.
    #[test]
    fn replay_rejects_checkpoint_stateid_mismatch() {
        let k = test_aum_key(1, 1);
        // Genesis checkpoint seeds StateID (7, 0).
        let genesis = Aum {
            message_kind: AumKind::Checkpoint,
            prev_aum_hash: None,
            key: None,
            key_id: Vec::new(),
            state: Some(AumState {
                last_aum_hash: None,
                disablement_values: Some(Vec::new()),
                keys: Some(alloc::vec![k.clone()]),
                state_id1: 7,
                state_id2: 0,
            }),
            votes: None,
            meta: Vec::new(),
            signatures: Vec::new(),
        };
        // A second checkpoint, correctly chained, but with a FOREIGN StateID (8, 0).
        let bad = Aum {
            message_kind: AumKind::Checkpoint,
            prev_aum_hash: Some(genesis.hash()),
            key: None,
            key_id: Vec::new(),
            state: Some(AumState {
                last_aum_hash: Some(genesis.hash()),
                disablement_values: Some(Vec::new()),
                keys: Some(alloc::vec![k.clone()]),
                state_id1: 8, // ← mismatch
                state_id2: 0,
            }),
            votes: None,
            meta: Vec::new(),
            signatures: Vec::new(),
        };
        assert_eq!(
            Authority::from_chain(&[genesis.clone(), bad]).unwrap_err(),
            TkaError::BadKeyState,
            "a checkpoint with a foreign StateID belongs to another authority and must be rejected"
        );
        // A matching-StateID second checkpoint is accepted.
        let ok = Aum {
            message_kind: AumKind::Checkpoint,
            prev_aum_hash: Some(genesis.hash()),
            key: None,
            key_id: Vec::new(),
            state: Some(AumState {
                last_aum_hash: Some(genesis.hash()),
                disablement_values: Some(Vec::new()),
                keys: Some(alloc::vec![k]),
                state_id1: 7,
                state_id2: 0,
            }),
            votes: None,
            meta: Vec::new(),
            signatures: Vec::new(),
        };
        assert!(Authority::from_chain(&[genesis, ok]).is_ok());
    }

    /// `from_forked_chain` rejects a multi-step branch rather than mis-resolving it (Go re-runs
    /// pickNextAUM per link; judging a whole branch by its first AUM could diverge).
    #[test]
    fn forked_chain_rejects_multistep_branch() {
        let k0 = test_aum_key(1, 1);
        let a0 = genesis_add(k0.clone());
        let b1 = child(&a0, AumKind::NoOp, None, alloc::vec![1]);
        // A two-AUM branch (b1 → b2): must be rejected as BadChain.
        let b2 = child(&b1, AumKind::NoOp, None, alloc::vec![2]);
        let single = [child(&a0, AumKind::NoOp, None, alloc::vec![3])];
        let multi = [b1, b2];
        assert_eq!(
            Authority::from_forked_chain(&[a0], &[&single[..], &multi[..]]).unwrap_err(),
            TkaError::BadChain,
            "a multi-step branch must be rejected, not judged by its first AUM"
        );
    }

    /// Cross-implementation Known-Answer-Test for the **AUM** type: [`Aum::serialize`],
    /// [`Aum::hash`] (Go `AUM.Hash`), and [`Aum::sig_hash`] (Go `AUM.SigHash`) must byte-match the
    /// REAL `tailscale.com/tka` package, version **v1.100.0** (toolchain **go1.26.3+**).
    ///
    /// Provenance: every golden below is authoritative upstream output produced by the Go generator
    /// at `tests/vectors/gen/tka/main.go` (which imports the real `tailscale.com/tka`, builds one
    /// `tka.AUM` per `MessageKind`, and dumps `AUM.Serialize()`/`AUM.Hash()`/`AUM.SigHash()` hex).
    /// The same values are committed for provenance at `tests/vectors/tka_aum_hash_golden.json`.
    /// This is the missing half of axis-B for AUM: the sibling
    /// [`aum_serialize_matches_go_test_serialization_vectors`] test pins Go's *Serialize()* literals
    /// from `tka/aum_test.go`, but no Go-produced *AUM.Hash()* digest was pinned until now — so an
    /// error in the BLAKE2s-over-canonical-CBOR digest (the value that links the whole chain and is
    /// signed) would have gone undetected. Here `hash`/`sig_hash` are pinned to Go directly.
    ///
    /// Covered kinds: AddKey (genesis, with a real Key25519 + meta), RemoveKey, UpdateKey
    /// (votes+meta), a signed AddKey (Signatures at CBOR key 23), and a Checkpoint with a populated
    /// `State`. The signed AUM additionally proves `hash() != sig_hash()` — i.e. `Hash()` covers the
    /// signatures and `SigHash()` excludes them, exactly as Go's `AUM.SigHash` nils `Signatures`
    /// before serializing.
    #[test]
    fn aum_hash_sighash_matches_go_golden() {
        // Deterministic field material — identical to the Go generator's inputs.
        let prev = AumHash({
            let mut a = [0u8; AUM_HASH_LEN];
            let mut i = 0;
            while i < AUM_HASH_LEN {
                a[i] = 0x20u8.wrapping_add(i as u8);
                i += 1;
            }
            a
        });
        let key_pub: Vec<u8> = (0..32u16).map(|i| 0x40u8.wrapping_add(i as u8)).collect();
        let key_pub2: Vec<u8> = (0..32u16).map(|i| 0x60u8.wrapping_add(i as u8)).collect();
        let sig_bytes: Vec<u8> = (0..64u16).map(|i| 0x80u8.wrapping_add(i as u8)).collect();

        // Assert one AUM's serialize/hash/sig_hash against the authoritative Go hex.
        let check = |label: &str, aum: &Aum, ser_hex: &str, hash_hex: &str, sig_hash_hex: &str| {
            assert_eq!(
                hex(&aum.serialize()),
                ser_hex,
                "{label}: Aum::serialize diverged from Go tka v1.100.0"
            );
            assert_eq!(
                hex(&aum.hash().0),
                hash_hex,
                "{label}: Aum::hash (Go AUM.Hash) diverged from Go tka v1.100.0"
            );
            assert_eq!(
                hex(&aum.sig_hash()),
                sig_hash_hex,
                "{label}: Aum::sig_hash (Go AUM.SigHash) diverged from Go tka v1.100.0"
            );
        };

        // (a) AddKey genesis (nil prev) with a real Key25519 + meta {"name":"alpha"}.
        let add_key = Aum {
            message_kind: AumKind::AddKey,
            prev_aum_hash: None,
            key: Some(AumKey {
                kind: KeyKind::Ed25519,
                votes: 7,
                public: key_pub.clone(),
                meta: alloc::vec![("name".into(), "alpha".into())],
            }),
            key_id: Vec::new(),
            state: None,
            votes: None,
            meta: Vec::new(),
            signatures: Vec::new(),
        };
        check(
            "AddKey",
            &add_key,
            "a3010102f603a401010207035820404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f0ca1646e616d6565616c706861",
            "921ca301077ae2b892ca8c40b3315e5f2a9ccc9ac99eec784e93b323577e1e14",
            "921ca301077ae2b892ca8c40b3315e5f2a9ccc9ac99eec784e93b323577e1e14",
        );

        // (b) RemoveKey with a non-nil prev.
        let remove_key = Aum {
            message_kind: AumKind::RemoveKey,
            prev_aum_hash: Some(prev),
            key: None,
            key_id: key_pub.clone(),
            state: None,
            votes: None,
            meta: Vec::new(),
            signatures: Vec::new(),
        };
        check(
            "RemoveKey",
            &remove_key,
            "a30102025820202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f045820404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            "46be17c398760d2e649147b06a68e8576ee37c59cf0558046182f48ba20aa912",
            "46be17c398760d2e649147b06a68e8576ee37c59cf0558046182f48ba20aa912",
        );

        // (c) UpdateKey with votes=2 + meta {"role":"ci"}.
        let update_key = Aum {
            message_kind: AumKind::UpdateKey,
            prev_aum_hash: Some(prev),
            key: None,
            key_id: key_pub.clone(),
            state: None,
            votes: Some(2),
            meta: alloc::vec![("role".into(), "ci".into())],
            signatures: Vec::new(),
        };
        check(
            "UpdateKey",
            &update_key,
            "a50104025820202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f045820404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f060207a164726f6c65626369",
            "42d160d81a0922511b4ce60050dba76569f79423b6e721c5040faf414c250e43",
            "42d160d81a0922511b4ce60050dba76569f79423b6e721c5040faf414c250e43",
        );

        // (e) AddKey carrying one Signature (CBOR key 23). hash (incl sigs) MUST differ from
        // sig_hash (excl sigs) — the property the whole signing scheme depends on.
        let signed = Aum {
            message_kind: AumKind::AddKey,
            prev_aum_hash: Some(prev),
            key: Some(AumKey {
                kind: KeyKind::Ed25519,
                votes: 1,
                public: key_pub.clone(),
                meta: Vec::new(),
            }),
            key_id: Vec::new(),
            state: None,
            votes: None,
            meta: Vec::new(),
            signatures: alloc::vec![AumSignature {
                key_id: key_pub2.clone(),
                signature: sig_bytes.clone(),
            }],
        };
        check(
            "AddKey+Signature",
            &signed,
            "a40101025820202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f03a301010201035820404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f1781a2015820606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f025840808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
            "e70332d9a03b205577204f1896bb8dcb7c8f8894cc87a5b5c4d5dabcdf6ef135",
            "0a7a0ecdf854ad99e8728a1de89ac23c1f08457132a537a3add9594749a7f536",
        );
        assert_ne!(
            hex(&signed.hash().0),
            hex(&signed.sig_hash()),
            "Hash() must cover Signatures while SigHash() excludes them (Go AUM.SigHash nils them)"
        );

        // (f) Checkpoint carrying a State with a POPULATED DisablementValues [{0xaa,0xbb}] + 1 key.
        // This is the common real shape and matches Go byte-for-byte (the array encoding is correct).
        let checkpoint = Aum {
            message_kind: AumKind::Checkpoint,
            prev_aum_hash: Some(prev),
            key: None,
            key_id: Vec::new(),
            state: Some(AumState {
                last_aum_hash: Some(prev),
                disablement_values: Some(alloc::vec![alloc::vec![0xaa, 0xbb]]),
                keys: Some(alloc::vec![AumKey {
                    kind: KeyKind::Ed25519,
                    votes: 1,
                    public: key_pub.clone(),
                    meta: Vec::new(),
                }]),
                state_id1: 0,
                state_id2: 0,
            }),
            votes: None,
            meta: Vec::new(),
            signatures: Vec::new(),
        };
        check(
            "Checkpoint(populated DisablementValues)",
            &checkpoint,
            "a30105025820202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f05a3015820202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f028142aabb0381a301010201035820404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            "38c35c51580dcb75212d79c07695c8ec8b399b59ba552ea93f080b126fdaa0ae",
            "38c35c51580dcb75212d79c07695c8ec8b399b59ba552ea93f080b126fdaa0ae",
        );
    }

    /// Go-match golden for the nil-`DisablementValues` checkpoint — the case that was a recorded
    /// interop bug (Rust forced an empty array `0x80` where Go emits CBOR null `0xf6`) and is now
    /// FIXED by making `AumState.{disablement_values,keys}` `Option` (None = Go nil = `0xf6`).
    ///
    /// When an `AUMCheckpoint`'s embedded `State` has a **nil** `DisablementValues` (Go's zero value,
    /// the overwhelmingly common case), Go's `fxamacker/cbor` CTAP2 encoder emits the field as
    /// **CBOR null `0xf6`**; a populated slice encodes as an array (proven by the populated case in
    /// [`aum_hash_sighash_matches_go_golden`]). This test pins the Go bytes + Hash for the nil case
    /// and asserts the Rust output now byte-matches — guarding the fix against regression.
    #[test]
    fn aum_checkpoint_nil_disablement_matches_go() {
        let prev = AumHash({
            let mut a = [0u8; AUM_HASH_LEN];
            let mut i = 0;
            while i < AUM_HASH_LEN {
                a[i] = 0x20u8.wrapping_add(i as u8);
                i += 1;
            }
            a
        });
        let key_pub: Vec<u8> = (0..32u16).map(|i| 0x40u8.wrapping_add(i as u8)).collect();
        let key_pub2: Vec<u8> = (0..32u16).map(|i| 0x60u8.wrapping_add(i as u8)).collect();

        // Checkpoint with a State whose DisablementValues is EMPTY (== Go nil zero value), 2 keys.
        let checkpoint = Aum {
            message_kind: AumKind::Checkpoint,
            prev_aum_hash: Some(prev),
            key: None,
            key_id: Vec::new(),
            state: Some(AumState {
                last_aum_hash: Some(prev),
                disablement_values: Some(Vec::new()),
                keys: Some(alloc::vec![
                    AumKey {
                        kind: KeyKind::Ed25519,
                        votes: 1,
                        public: key_pub.clone(),
                        meta: Vec::new(),
                    },
                    AumKey {
                        kind: KeyKind::Ed25519,
                        votes: 3,
                        public: key_pub2.clone(),
                        meta: alloc::vec![("k".into(), "v".into())],
                    },
                ]),
                state_id1: 0,
                state_id2: 0,
            }),
            votes: None,
            meta: Vec::new(),
            signatures: Vec::new(),
        };

        // Authoritative Go bytes (generator case "checkpoint: State w/ nil DisablementValues"):
        // the State map is `…02 f6 03 82 …` — a NIL DisablementValues encodes as CBOR null (0xf6).
        // FIXED: `AumState.disablement_values` is now `Option`, so the nil case (`None`) is
        // representable and encodes as null, byte-matching Go. (Was a recorded interop bug where the
        // `Vec` type forced an empty array `0x80` and diverged the checkpoint Hash from Go.)
        const GO_SERIALIZE: &str = "a30105025820202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f05a3015820202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f02f60382a301010201035820404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5fa401010203035820606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f0ca1616b6176";
        const GO_HASH: &str = "cae17cc938c5a954cd4389d83c6afe4d3487edac38b94824bec3312b82f35710";

        // Re-point the checkpoint's State to a genuinely-nil DisablementValues (`None`), which is the
        // case the Go golden above was generated from.
        let checkpoint = {
            let mut c = checkpoint;
            if let Some(state) = c.state.as_mut() {
                state.disablement_values = None;
            }
            c
        };

        assert_eq!(
            hex(&checkpoint.serialize()),
            GO_SERIALIZE,
            "nil DisablementValues must encode as CBOR null (0xf6), byte-matching Go"
        );
        assert_eq!(
            hex(&checkpoint.hash().0),
            GO_HASH,
            "with the nil-vs-empty fix, the checkpoint chain-link Hash matches Go"
        );
    }

    // =======================================================================================
    // MUST-1: AUM signature verification (`VerifiedAumChain` / Go `aumVerify`). The trust
    // boundary for a control-supplied chain — an AUM may advance the trusted-key state only if
    // every signature on it verifies against a key already trusted at its parent.
    // =======================================================================================

    /// The signing key whose public key `test_aum_key(seed, _)` derives — so a key trusted via
    /// `test_aum_key(seed, v)` can be made to actually sign an AUM.
    fn signer_for(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    /// Sign `aum` with each `(seed)` signer, appending a real `AumSignature` over `aum.sig_hash()`.
    /// The signer's public key is `test_aum_key(seed, _).public`, so signing with `seed` produces a
    /// signature that a state trusting `test_aum_key(seed, _)` will accept.
    fn sign_aum(aum: &mut Aum, seeds: &[u8]) {
        use ed25519_dalek::Signer;
        let sig_hash = aum.sig_hash();
        for &seed in seeds {
            let signer = signer_for(seed);
            aum.signatures.push(AumSignature {
                key_id: signer.verifying_key().to_bytes().to_vec(),
                signature: signer.sign(&sig_hash).to_bytes().to_vec(),
            });
        }
    }

    /// A genesis `AddKey` that adds `test_aum_key(seed, votes)` and is self-signed by that very key
    /// — the bootstrapping shape (Go verifies a genesis against the keys it itself establishes).
    fn signed_genesis_add(seed: u8, votes: u32) -> Aum {
        let mut g = genesis_add(test_aum_key(seed, votes));
        sign_aum(&mut g, &[seed]);
        g
    }

    /// Happy path: a self-signed genesis followed by a child signed by the trusted genesis key
    /// verifies, and `from_verified_chain` yields the same state as the structural `from_chain`.
    #[test]
    fn verified_chain_accepts_properly_signed_chain() {
        let g = signed_genesis_add(1, 1);
        // Child adds a second key, signed by the trusted key from the genesis (seed 1).
        let mut a1 = child(&g, AumKind::AddKey, Some(test_aum_key(2, 1)), Vec::new());
        sign_aum(&mut a1, &[1]);

        let chain = [g.clone(), a1.clone()];
        let verified = VerifiedAumChain::verify(&chain).expect("a properly signed chain verifies");
        let auth = Authority::from_verified_chain(verified);

        assert_eq!(auth.head(), a1.hash(), "head = last AUM");
        assert_eq!(auth.state().keys.len(), 2, "both keys trusted");
        // The verified-path state must equal the structural-path state for an authentic chain.
        let structural = Authority::from_chain(&chain).unwrap();
        assert_eq!(auth.state(), structural.state());
        assert_eq!(auth.head(), structural.head());
    }

    /// An unsigned AUM (no signatures at all) is rejected — Go `aumVerify` "unsigned AUM". This
    /// holds even for the genesis.
    #[test]
    fn verified_chain_rejects_unsigned_aum() {
        // Unsigned genesis.
        let g = genesis_add(test_aum_key(1, 1));
        assert_eq!(
            VerifiedAumChain::verify(core::slice::from_ref(&g)).unwrap_err(),
            TkaError::UnsignedAum,
            "an unsigned genesis must be rejected"
        );

        // Signed genesis, but an unsigned child.
        let sg = signed_genesis_add(1, 1);
        let a1 = child(&sg, AumKind::AddKey, Some(test_aum_key(2, 1)), Vec::new());
        assert_eq!(
            VerifiedAumChain::verify(&[sg, a1]).unwrap_err(),
            TkaError::UnsignedAum,
            "an unsigned non-genesis AUM must be rejected"
        );
    }

    /// THE headline security property: a malicious control plane inserts an `AddKey` that adds the
    /// attacker's own key, signed by the attacker (a key NOT trusted in the current state). MUST-1
    /// rejects it as `UntrustedKey` — so the forged key never reaches a live `Authority`. Without
    /// the signature gate, `from_chain` would happily fold it (demonstrated) — which is exactly the
    /// tailnet-lock-defeating forgery the type-enforced `VerifiedAumChain` prevents.
    #[test]
    fn verified_chain_rejects_forged_addkey_from_untrusted_signer() {
        let g = signed_genesis_add(1, 1); // only key seed=1 is trusted
        // Attacker forges an AddKey inserting their own key (seed 9), signed by seed 9 (untrusted).
        let mut forged = child(&g, AumKind::AddKey, Some(test_aum_key(9, 99)), Vec::new());
        sign_aum(&mut forged, &[9]);

        assert_eq!(
            VerifiedAumChain::verify(&[g.clone(), forged.clone()]).unwrap_err(),
            TkaError::UntrustedKey,
            "an AddKey signed only by an untrusted key must be rejected"
        );
        // Contrast: the structural-only `from_chain` (NOT a trust boundary) DOES fold the forgery,
        // proving why the type-enforced verified path is necessary.
        let structural = Authority::from_chain(&[g, forged]).unwrap();
        assert_eq!(
            structural.state().keys.len(),
            2,
            "structural from_chain folds the forged key — exactly why it is not a trust boundary"
        );
    }

    /// A signature whose `key_id` IS trusted but whose bytes were produced over different content
    /// (here: signed by the wrong private key but labelled with the trusted key's id) fails the
    /// cryptographic check → `BadSignature`.
    #[test]
    fn verified_chain_rejects_tampered_signature() {
        let g = signed_genesis_add(1, 1);
        let mut a1 = child(&g, AumKind::AddKey, Some(test_aum_key(2, 1)), Vec::new());
        // Label the signature with the trusted key's id (seed 1) but sign with the WRONG key.
        use ed25519_dalek::Signer;
        let wrong = signer_for(42);
        a1.signatures.push(AumSignature {
            key_id: signer_for(1).verifying_key().to_bytes().to_vec(),
            signature: wrong.sign(&a1.sig_hash()).to_bytes().to_vec(),
        });
        assert_eq!(
            VerifiedAumChain::verify(&[g, a1]).unwrap_err(),
            TkaError::BadSignature,
            "a signature that doesn't verify under the named trusted key is rejected"
        );
    }

    /// Every signature must verify (Go loops over all, failing on the first bad one): a child with
    /// one valid trusted signature AND one bad/untrusted signature is still rejected.
    #[test]
    fn verified_chain_requires_all_signatures_valid() {
        let g = signed_genesis_add(1, 1);
        let mut a1 = child(&g, AumKind::AddKey, Some(test_aum_key(2, 1)), Vec::new());
        // First a valid signature by the trusted key, then a second by an untrusted key.
        sign_aum(&mut a1, &[1]); // valid (seed 1 trusted)
        sign_aum(&mut a1, &[7]); // untrusted (seed 7 not in state)
        assert_eq!(
            VerifiedAumChain::verify(&[g, a1]).unwrap_err(),
            TkaError::UntrustedKey,
            "a single untrusted signature rejects the AUM even alongside a valid one"
        );
    }

    /// A genesis `Checkpoint` self-certifies against the keys it embeds (Go
    /// `aumVerify(bootstrap, *bootstrap.State, true)`): the checkpoint's signature must verify
    /// against a key inside its own `State`. The embedded `State` must itself be Go-valid (≥1
    /// disablement value of 32 bytes, ≥1 key) — `static_validate_checkpoint` enforces that.
    #[test]
    fn verified_chain_genesis_checkpoint_self_certifies() {
        let trusted = test_aum_key(1, 1);
        let mut g = Aum {
            message_kind: AumKind::Checkpoint,
            prev_aum_hash: None,
            key: None,
            key_id: Vec::new(),
            state: Some(AumState {
                last_aum_hash: None,
                // A valid checkpoint needs ≥1 disablement value, each exactly 32 bytes.
                disablement_values: Some(alloc::vec![alloc::vec![0xD5u8; DISABLEMENT_LENGTH]]),
                keys: Some(alloc::vec![trusted.clone()]),
                state_id1: 0,
                state_id2: 0,
            }),
            votes: None,
            meta: Vec::new(),
            signatures: Vec::new(),
        };
        // Unsigned → rejected.
        assert_eq!(
            VerifiedAumChain::verify(&[g.clone()]).unwrap_err(),
            TkaError::UnsignedAum
        );
        // Signed by the key embedded in its own State → accepted.
        sign_aum(&mut g, &[1]);
        let verified = VerifiedAumChain::verify(&[g.clone()])
            .expect("a checkpoint signed by an embedded key self-certifies");
        let auth = Authority::from_verified_chain(verified);
        assert_eq!(auth.state().keys.len(), 1);
        assert_eq!(auth.head(), g.hash());
    }

    /// A genesis `Checkpoint` whose embedded `State` is malformed is rejected by
    /// `static_validate_checkpoint` (Go `staticValidateCheckpoint`), before any signature check.
    #[test]
    fn verified_chain_rejects_malformed_checkpoint_state() {
        let trusted = test_aum_key(1, 1);
        let mk = |state: AumState| {
            let mut g = Aum {
                message_kind: AumKind::Checkpoint,
                prev_aum_hash: None,
                key: None,
                key_id: Vec::new(),
                state: Some(state),
                votes: None,
                meta: Vec::new(),
                signatures: Vec::new(),
            };
            sign_aum(&mut g, &[1]);
            g
        };
        let base = AumState {
            last_aum_hash: None,
            disablement_values: Some(alloc::vec![alloc::vec![0xD5u8; DISABLEMENT_LENGTH]]),
            keys: Some(alloc::vec![trusted.clone()]),
            state_id1: 0,
            state_id2: 0,
        };

        // No disablement values → rejected.
        let no_disable = AumState {
            disablement_values: None,
            ..base.clone()
        };
        assert_eq!(
            VerifiedAumChain::verify(&[mk(no_disable)]).unwrap_err(),
            TkaError::BadKeyState,
            "a checkpoint with no disablement value is rejected"
        );

        // Disablement value of the wrong length → rejected.
        let bad_len = AumState {
            disablement_values: Some(alloc::vec![alloc::vec![0u8; 16]]),
            ..base.clone()
        };
        assert_eq!(
            VerifiedAumChain::verify(&[mk(bad_len)]).unwrap_err(),
            TkaError::BadKeyState,
            "a disablement value of the wrong length is rejected"
        );

        // No keys → rejected.
        let no_keys = AumState {
            keys: Some(Vec::new()),
            ..base.clone()
        };
        assert_eq!(
            VerifiedAumChain::verify(&[mk(no_keys)]).unwrap_err(),
            TkaError::BadKeyState,
            "a checkpoint with no keys is rejected"
        );

        // Duplicate keys → rejected.
        let dup_keys = AumState {
            keys: Some(alloc::vec![trusted.clone(), trusted.clone()]),
            ..base.clone()
        };
        assert_eq!(
            VerifiedAumChain::verify(&[mk(dup_keys)]).unwrap_err(),
            TkaError::BadKeyState,
            "a checkpoint with duplicate key ids is rejected"
        );

        // F5: a NON-adjacent duplicate ([a, b, a]) is also caught (the prefix-scan dedup checks all
        // earlier elements, not just the neighbor).
        let nonadjacent_dup = AumState {
            keys: Some(alloc::vec![
                test_aum_key(1, 1),
                test_aum_key(2, 1),
                test_aum_key(1, 1)
            ]),
            ..base.clone()
        };
        assert_eq!(
            VerifiedAumChain::verify(&[mk(nonadjacent_dup)]).unwrap_err(),
            TkaError::BadKeyState,
            "a non-adjacent duplicate key id is rejected"
        );

        // F4: more than MAX_KEYS (512) keys → rejected. Use distinct 32-byte public keys (index-
        // encoded) so there are no duplicate ids — only the `> MAX_KEYS` cap can be the failure.
        let distinct_over_cap: alloc::vec::Vec<AumKey> = (0u32..=(MAX_KEYS as u32))
            .map(|i| AumKey {
                kind: KeyKind::Ed25519,
                votes: 1,
                // Distinct 32-byte public keys by encoding the index — no dup, so only the >512 cap trips.
                public: {
                    let mut p = alloc::vec![0u8; 32];
                    p[0..4].copy_from_slice(&i.to_le_bytes());
                    p
                },
                meta: Vec::new(),
            })
            .collect();
        assert_eq!(distinct_over_cap.len(), MAX_KEYS + 1);
        let over_keys = AumState {
            keys: Some(distinct_over_cap),
            ..base.clone()
        };
        assert_eq!(
            VerifiedAumChain::verify(&[mk(over_keys)]).unwrap_err(),
            TkaError::BadKeyState,
            "a checkpoint with > MAX_KEYS keys is rejected"
        );

        // F4: more than MAX_DISABLEMENT_VALUES (32) disablement values → rejected (each distinct).
        let over_disablements = AumState {
            disablement_values: Some(
                (0u8..=(MAX_DISABLEMENT_VALUES as u8))
                    .map(|i| {
                        let mut d = alloc::vec![0u8; DISABLEMENT_LENGTH];
                        d[0] = i;
                        d
                    })
                    .collect(),
            ),
            ..base
        };
        assert_eq!(
            VerifiedAumChain::verify(&[mk(over_disablements)]).unwrap_err(),
            TkaError::BadKeyState,
            "a checkpoint with > MAX_DISABLEMENT_VALUES disablement values is rejected"
        );
    }

    /// A broken parent link is still caught on the verified path (the structural fold runs after the
    /// signature check for non-genesis AUMs).
    #[test]
    fn verified_chain_rejects_broken_parent_link() {
        let g = signed_genesis_add(1, 1);
        let mut orphan = child(&g, AumKind::NoOp, None, alloc::vec![9]);
        orphan.prev_aum_hash = Some(AumHash([0xAB; 32])); // wrong parent
        sign_aum(&mut orphan, &[1]); // validly signed, but mis-linked
        assert_eq!(
            VerifiedAumChain::verify(&[g, orphan]).unwrap_err(),
            TkaError::BadParent,
            "a validly-signed but mis-linked AUM is still rejected"
        );
    }

    // ===== Aum::from_cbor — the decode inverse of Aum::serialize (issue #7 chunk 2, tsr-2dr) =====

    /// `Aum::from_cbor(aum.serialize())` reconstructs the exact `Aum` for every message kind and
    /// optional-field combination. This is the core round-trip contract the sync/bootstrap path
    /// relies on: bytes control sends → `Aum` → verify/replay.
    #[test]
    fn aum_from_cbor_roundtrips_every_shape() {
        let cases: alloc::vec::Vec<(&str, Aum)> = alloc::vec![
            (
                "RemoveKey, genesis (null prev), key_id",
                Aum {
                    message_kind: AumKind::RemoveKey,
                    prev_aum_hash: None,
                    key: None,
                    key_id: alloc::vec![1, 2],
                    state: None,
                    votes: None,
                    meta: Vec::new(),
                    signatures: Vec::new(),
                },
            ),
            (
                "UpdateKey with votes + meta (text-keyed map)",
                Aum {
                    message_kind: AumKind::UpdateKey,
                    prev_aum_hash: None,
                    key: None,
                    key_id: alloc::vec![1, 2],
                    state: None,
                    votes: Some(2),
                    meta: alloc::vec![("a".into(), "b".into())],
                    signatures: Vec::new(),
                },
            ),
            (
                "AddKey with an embedded Key + non-null prev + signatures",
                Aum {
                    message_kind: AumKind::AddKey,
                    prev_aum_hash: Some(AumHash([0x11; AUM_HASH_LEN])),
                    key: Some(AumKey {
                        kind: KeyKind::Ed25519,
                        votes: 3,
                        public: alloc::vec![9, 8, 7],
                        meta: alloc::vec![("k".into(), "v".into())],
                    }),
                    key_id: Vec::new(),
                    state: None,
                    votes: None,
                    meta: Vec::new(),
                    signatures: alloc::vec![
                        AumSignature {
                            key_id: alloc::vec![1],
                            signature: Vec::new(), // nil → null on the wire
                        },
                        AumSignature {
                            key_id: alloc::vec![2, 3],
                            signature: alloc::vec![4, 5, 6],
                        },
                    ],
                },
            ),
            (
                "Checkpoint with full State (null + empty-array + populated arms)",
                Aum {
                    message_kind: AumKind::Checkpoint,
                    prev_aum_hash: Some(AumHash([0u8; AUM_HASH_LEN])),
                    key: None,
                    key_id: Vec::new(),
                    state: Some(AumState {
                        last_aum_hash: Some(AumHash([0xAB; AUM_HASH_LEN])),
                        disablement_values: Some(alloc::vec![alloc::vec![1, 2], alloc::vec![3]]),
                        keys: Some(alloc::vec![AumKey {
                            kind: KeyKind::Ed25519,
                            votes: 1,
                            public: alloc::vec![5, 6],
                            meta: Vec::new(),
                        }]),
                        state_id1: 7,
                        state_id2: 0, // omitted (omitempty)
                    }),
                    votes: None,
                    meta: Vec::new(),
                    signatures: Vec::new(),
                },
            ),
            (
                "Checkpoint with nil State arms (null) and empty disablement array",
                Aum {
                    message_kind: AumKind::Checkpoint,
                    prev_aum_hash: Some(AumHash([0u8; AUM_HASH_LEN])),
                    key: None,
                    key_id: Vec::new(),
                    state: Some(AumState {
                        last_aum_hash: None,                  // null
                        disablement_values: Some(Vec::new()), // empty array 0x80
                        keys: None,                           // null
                        state_id1: 0,
                        state_id2: 9,
                    }),
                    votes: None,
                    meta: Vec::new(),
                    signatures: Vec::new(),
                },
            ),
            (
                "NoOp, non-null prev, nothing else",
                Aum {
                    message_kind: AumKind::NoOp,
                    prev_aum_hash: Some(AumHash([0x42; AUM_HASH_LEN])),
                    key: None,
                    key_id: Vec::new(),
                    state: None,
                    votes: None,
                    meta: Vec::new(),
                    signatures: Vec::new(),
                },
            ),
        ];

        for (label, aum) in cases {
            let bytes = aum.serialize();
            let decoded = Aum::from_cbor(&bytes)
                .unwrap_or_else(|e| panic!("from_cbor failed for {label:?}: {e}"));
            assert_eq!(decoded, aum, "round-trip mismatch for {label:?}");
            // And the decoded AUM re-serializes to the identical bytes (canonical-form preserved →
            // hash/sig_hash are stable across a decode/encode cycle, which the chain replayer needs).
            assert_eq!(
                decoded.serialize(),
                bytes,
                "re-serialize must be byte-identical for {label:?}"
            );
            assert_eq!(
                decoded.hash(),
                aum.hash(),
                "hash must survive round-trip for {label:?}"
            );
        }
    }

    /// Decode the exact frozen Go `TestSerialization` byte vectors (the same literals asserted on the
    /// encode side) straight into `Aum`s — proving the decoder consumes real Go-produced bytes, not
    /// just our own encoder's output.
    #[test]
    fn aum_from_cbor_decodes_frozen_go_vectors() {
        // RemoveKey: a3 01 02 02 f6 04 42 01 02
        let remove_key = Aum::from_cbor(&[0xa3, 0x01, 0x02, 0x02, 0xf6, 0x04, 0x42, 0x01, 0x02])
            .expect("decode RemoveKey vector");
        assert_eq!(remove_key.message_kind, AumKind::RemoveKey);
        assert_eq!(remove_key.prev_aum_hash, None);
        assert_eq!(remove_key.key_id, alloc::vec![1, 2]);

        // UpdateKey: a5 01 04 02 f6 04 42 01 02 06 02 07 a1 61 61 61 62
        let update_key = Aum::from_cbor(&[
            0xa5, 0x01, 0x04, 0x02, 0xf6, 0x04, 0x42, 0x01, 0x02, 0x06, 0x02, 0x07, 0xa1, 0x61,
            0x61, 0x61, 0x62,
        ])
        .expect("decode UpdateKey vector");
        assert_eq!(update_key.message_kind, AumKind::UpdateKey);
        assert_eq!(update_key.votes, Some(2));
        assert_eq!(
            update_key.meta,
            alloc::vec![(
                alloc::string::String::from("a"),
                alloc::string::String::from("b")
            )],
            "the text-keyed Meta map must decode to {{\"a\":\"b\"}}"
        );

        // Signature: a3 01 01 02 f6 17 81 a2 01 41 01 02 f6
        let with_sig = Aum::from_cbor(&[
            0xa3, 0x01, 0x01, 0x02, 0xf6, 0x17, 0x81, 0xa2, 0x01, 0x41, 0x01, 0x02, 0xf6,
        ])
        .expect("decode Signature vector");
        assert_eq!(with_sig.message_kind, AumKind::AddKey);
        assert_eq!(with_sig.signatures.len(), 1);
        assert_eq!(with_sig.signatures[0].key_id, alloc::vec![1]);
        assert_eq!(
            with_sig.signatures[0].signature,
            Vec::<u8>::new(),
            "the nil Signature (CBOR null) must decode to an empty Vec"
        );
        // Byte-exact re-encode of every frozen vector.
        assert_eq!(
            with_sig.serialize(),
            alloc::vec![
                0xa3, 0x01, 0x01, 0x02, 0xf6, 0x17, 0x81, 0xa2, 0x01, 0x41, 0x01, 0x02, 0xf6
            ]
        );
    }

    /// The `null` (0xf6) major-7 arm is accepted ONLY for null; other major-7 simple/float values
    /// are still rejected (fail-closed), and the `NodeKeySignature` path is unaffected because its
    /// `expect_bytes` rejects null where bytes are required.
    #[test]
    fn decode_value_accepts_only_null_in_major7() {
        // Bare null decodes.
        assert_eq!(decode_value(&[0xf6], 0).unwrap().0, Value::Null);
        // true (0xf5), false (0xf4), undefined (0xf7), a float64 (0xfb …) → rejected.
        for bad in [
            alloc::vec![0xf5u8],
            alloc::vec![0xf4],
            alloc::vec![0xf7],
            alloc::vec![0xfb, 0x40, 0x09, 0x21, 0xfb, 0x54, 0x44, 0x2d, 0x18],
        ] {
            assert!(
                decode_value(&bad, 0).is_err(),
                "major-7 value {bad:02x?} other than null must be rejected"
            );
        }
    }

    /// `Aum::from_cbor` fails closed on malformed / adversarial input — never panics, never `Ok` on
    /// garbage. Complements the `cbor_decode_smoke` integration test (which targets the signature
    /// path) for the AUM path.
    #[test]
    fn aum_from_cbor_fails_closed() {
        // Empty input.
        assert!(Aum::from_cbor(&[]).is_err());
        // Not a map (a bare uint).
        assert!(Aum::from_cbor(&[0x00]).is_err());
        // Map missing the non-omitempty prev_aum_hash (only message_kind present): a1 01 03.
        assert!(
            Aum::from_cbor(&[0xa1, 0x01, 0x03]).is_err(),
            "an AUM without key 2 (prev_aum_hash) must be rejected (non-omitempty)"
        );
        // Unknown field key (99): a2 01 03 18 63 00.
        assert!(
            Aum::from_cbor(&[0xa2, 0x01, 0x03, 0x18, 0x63, 0x00]).is_err(),
            "an unknown AUM field key must be rejected"
        );
        // Unknown message kind (9): a2 01 09 02 f6.
        assert!(
            Aum::from_cbor(&[0xa2, 0x01, 0x09, 0x02, 0xf6]).is_err(),
            "an unknown message_kind must be rejected"
        );
        // Trailing byte after a complete AUM: (a2 01 03 02 f6) + 00.
        assert!(
            Aum::from_cbor(&[0xa2, 0x01, 0x03, 0x02, 0xf6, 0x00]).is_err(),
            "trailing bytes after the AUM must be rejected"
        );
        // prev_aum_hash present but wrong length (31 bytes) → rejected.
        let mut short_prev = alloc::vec![0xa2u8, 0x01, 0x03, 0x02, 0x58, 0x1f];
        short_prev.extend(core::iter::repeat_n(0u8, 31));
        assert!(
            Aum::from_cbor(&short_prev).is_err(),
            "a prev_aum_hash that is not 32 bytes must be rejected"
        );
    }

    /// A text-keyed map (`Meta`) and an int-keyed map are distinguished on decode, and a mixed-key
    /// map is rejected (TKA emits no mixed-key maps).
    #[test]
    fn decode_map_rejects_mixed_key_types() {
        // map(2){ 1: 0, "a": "b" } — int key then text key. a2 01 00 61 61 61 62
        assert!(
            decode_value(&[0xa2, 0x01, 0x00, 0x61, 0x61, 0x61, 0x62], 0).is_err(),
            "a map mixing uint and text keys must be rejected"
        );
        // A pure text map decodes to TextMap.
        let (v, rest) = decode_value(&[0xa1, 0x61, 0x61, 0x61, 0x62], 0).unwrap();
        assert!(rest.is_empty());
        assert_eq!(
            v,
            Value::TextMap(alloc::vec![(b"a".to_vec(), Value::Text(b"b".to_vec()))])
        );
    }

    // ===== Review follow-ups (PR #48 review): close decode coverage gaps =====

    /// Gap 2 (highest value): decode the authoritative frozen **Go checkpoint** bytes — the most
    /// complex AUM shape (null `disablement_values` arm, two nested keys, the second carrying a
    /// `Meta`, 32-byte hashes). The encode side asserts these exact bytes
    /// (`aum_checkpoint_nil_disablement_matches_go`); here we prove the *decoder* consumes them and
    /// round-trips byte-identically (so `hash()` is stable), exercising `AumState::from_value` +
    /// nested `AumKey::from_value` against real Go output rather than our own encoder.
    #[test]
    fn aum_from_cbor_decodes_frozen_go_checkpoint() {
        const GO_SERIALIZE: &str = "a30105025820202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f05a3015820202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f02f60382a301010201035820404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5fa401010203035820606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f0ca1616b6176";
        const GO_HASH: &str = "cae17cc938c5a954cd4389d83c6afe4d3487edac38b94824bec3312b82f35710";
        let bytes = unhex(GO_SERIALIZE);

        let aum = Aum::from_cbor(&bytes).expect("decode the frozen Go checkpoint");
        assert_eq!(aum.message_kind, AumKind::Checkpoint);
        let st = aum.state.as_ref().expect("checkpoint carries a State");
        assert_eq!(
            st.disablement_values, None,
            "nil DisablementValues → the null arm → None"
        );
        let keys = st.keys.as_ref().expect("State has keys");
        assert_eq!(keys.len(), 2, "two nested keys");
        assert_eq!(keys[0].votes, 1);
        assert_eq!(keys[1].votes, 3);
        assert_eq!(
            keys[1].meta,
            alloc::vec![(
                alloc::string::String::from("k"),
                alloc::string::String::from("v")
            )],
            "the second nested key carries Meta {{\"k\":\"v\"}}"
        );
        // Byte-exact re-encode → the chain-link Hash matches Go's golden hash.
        assert_eq!(
            aum.serialize(),
            bytes,
            "re-serialize must be byte-identical to the Go bytes"
        );
        assert_eq!(
            hex(&aum.hash().0),
            GO_HASH,
            "decoded checkpoint's Hash matches Go golden"
        );
    }

    /// Gap 1: round-trip the field combinations the original cases missed — multi-entry `Meta`
    /// (canonical-ordering), both `state_id`s non-zero (key-4/key-5 routing), `votes` at the u32
    /// boundary, a both-empty (`null`/`null`) `AumSignature`, and `key`+`key_id`+`signatures`
    /// coexisting (key 3/4/23 cross-talk).
    #[test]
    fn aum_from_cbor_roundtrips_review_gap_shapes() {
        let cases: alloc::vec::Vec<(&str, Aum)> = alloc::vec![
            (
                "multi-entry meta, pre-sorted (serialize() canonicalises key order)",
                Aum {
                    message_kind: AumKind::UpdateKey,
                    prev_aum_hash: None,
                    key: None,
                    key_id: alloc::vec![1],
                    state: None,
                    votes: Some(1),
                    // Pre-sorted: `serialize()` emits TextMap keys in CTAP2 order, so the decoded
                    // meta is sorted; supplying sorted input keeps the `==` round-trip exact.
                    meta: alloc::vec![
                        ("a".into(), "2".into()),
                        ("mid".into(), "3".into()),
                        ("zebra".into(), "1".into()),
                    ],
                    signatures: Vec::new(),
                },
            ),
            (
                "both state_ids non-zero (key 4 and key 5 must not be swapped)",
                Aum {
                    message_kind: AumKind::Checkpoint,
                    prev_aum_hash: Some(AumHash([0u8; AUM_HASH_LEN])),
                    key: None,
                    key_id: Vec::new(),
                    state: Some(AumState {
                        last_aum_hash: None,
                        disablement_values: None,
                        keys: Some(Vec::new()),
                        state_id1: 7,
                        state_id2: 9,
                    }),
                    votes: None,
                    meta: Vec::new(),
                    signatures: Vec::new(),
                },
            ),
            (
                "votes at u32::MAX + AddKey with key.votes at u32::MAX and multi-meta",
                Aum {
                    message_kind: AumKind::AddKey,
                    prev_aum_hash: Some(AumHash([0x33; AUM_HASH_LEN])),
                    key: Some(AumKey {
                        kind: KeyKind::Ed25519,
                        votes: u32::MAX,
                        public: alloc::vec![1, 2, 3],
                        meta: alloc::vec![("a".into(), "x".into()), ("b".into(), "y".into())],
                    }),
                    key_id: Vec::new(),
                    state: None,
                    votes: None,
                    meta: Vec::new(),
                    signatures: Vec::new(),
                },
            ),
            (
                "both-empty AumSignature (key_id null AND signature null)",
                Aum {
                    message_kind: AumKind::AddKey,
                    prev_aum_hash: None,
                    key: None,
                    key_id: Vec::new(),
                    state: None,
                    votes: None,
                    meta: Vec::new(),
                    signatures: alloc::vec![AumSignature {
                        key_id: Vec::new(),
                        signature: Vec::new(),
                    }],
                },
            ),
            (
                "key + key_id + signatures coexisting (keys 3, 4, 23)",
                Aum {
                    message_kind: AumKind::AddKey,
                    prev_aum_hash: Some(AumHash([0x55; AUM_HASH_LEN])),
                    key: Some(AumKey {
                        kind: KeyKind::Ed25519,
                        votes: 2,
                        public: alloc::vec![7, 7, 7],
                        meta: Vec::new(),
                    }),
                    key_id: alloc::vec![9, 9],
                    state: None,
                    votes: None,
                    meta: Vec::new(),
                    signatures: alloc::vec![AumSignature {
                        key_id: alloc::vec![1],
                        signature: alloc::vec![2, 3, 4],
                    }],
                },
            ),
            (
                "votes = 0 (boundary; Some(0) must survive, distinct from None)",
                Aum {
                    message_kind: AumKind::UpdateKey,
                    prev_aum_hash: None,
                    key: None,
                    key_id: alloc::vec![1],
                    state: None,
                    votes: Some(0),
                    meta: Vec::new(),
                    signatures: Vec::new(),
                },
            ),
        ];
        for (label, aum) in cases {
            let bytes = aum.serialize();
            let decoded = Aum::from_cbor(&bytes)
                .unwrap_or_else(|e| panic!("from_cbor failed for {label:?}: {e}"));
            assert_eq!(decoded, aum, "round-trip mismatch for {label:?}");
            assert_eq!(
                decoded.serialize(),
                bytes,
                "re-serialize differs for {label:?}"
            );
        }
    }

    /// Gap 3: additional fail-closed guards on the AUM entry point — truncated map (count > entries),
    /// a duplicate key at the AUM level, votes > u32::MAX, an unsupported key kind, and a malformed
    /// (non-map) `state` value. Each must `Err`, never panic, never `Ok`.
    #[test]
    fn aum_from_cbor_fails_closed_review_gaps() {
        // Truncated map: header claims 3 pairs, only 2 present then EOF.
        assert!(
            Aum::from_cbor(&[0xa3, 0x01, 0x03, 0x02, 0xf6]).is_err(),
            "a map claiming more pairs than present must be rejected"
        );
        // Duplicate key at the AUM level: key 1 appears twice (a3 01 03 02 f6 01 04).
        assert!(
            Aum::from_cbor(&[0xa3, 0x01, 0x03, 0x02, 0xf6, 0x01, 0x04]).is_err(),
            "a duplicate AUM map key must be rejected"
        );
        // votes > u32::MAX: 06 1b 0000_0001_0000_0000 (= 2^32).
        assert!(
            Aum::from_cbor(&[
                0xa3, 0x01, 0x04, 0x02, 0xf6, 0x06, 0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                0x00,
            ])
            .is_err(),
            "votes above u32::MAX must be rejected (fail-closed narrowing)"
        );
        // Unsupported key kind: AddKey embedding a key with kind=2. a3 01 01 02 f6 03 a3 01 02 02 01 03 41 09
        assert!(
            Aum::from_cbor(&[
                0xa3, 0x01, 0x01, 0x02, 0xf6, 0x03, 0xa3, 0x01, 0x02, 0x02, 0x01, 0x03, 0x41, 0x09,
            ])
            .is_err(),
            "an unsupported key kind must be rejected (not silently treated as Ed25519)"
        );
        // Malformed state: key 5 is a uint, not a map. a2 01 05 05 00 — but prev (key 2) missing too;
        // use a3 with prev null: a3 01 05 02 f6 05 00.
        assert!(
            Aum::from_cbor(&[0xa3, 0x01, 0x05, 0x02, 0xf6, 0x05, 0x00]).is_err(),
            "a non-map `state` value must be rejected"
        );
        // A deeply-nested array inside an AUM field must error (shared depth cap), not overflow.
        let mut nested = alloc::vec![0xa2u8, 0x01, 0x03, 0x02]; // map(2){1:3, 2: <nested>}
        nested.extend(core::iter::repeat_n(0x81u8, MAX_SIG_NESTING_DEPTH + 8)); // array(1) per level
        nested.push(0x00); // innermost uint
        assert!(
            Aum::from_cbor(&nested).is_err(),
            "an AUM field nested past the depth cap must be rejected, not overflow the stack"
        );
    }

    /// Gap 5 + Finding L2: a NON-canonical encoding decodes to the SAME `Aum` (and thus the same
    /// `hash()`) as its canonical form — pinning the property that makes the lenient decode benign
    /// (the verify path re-serializes canonically, so wire-form variation can never forge a hash).
    #[test]
    fn aum_from_cbor_noncanonical_decodes_to_same_hash() {
        // Canonical NoOp with null prev: a2 01 03 02 f6.
        let canonical = [0xa2u8, 0x01, 0x03, 0x02, 0xf6];
        // Non-canonical variants that must decode to the SAME struct:
        //  (a) message_kind via a non-minimal 2-byte int head (0x18 0x03 instead of 0x03):
        let noncanon_int = [0xa2u8, 0x01, 0x18, 0x03, 0x02, 0xf6];
        //  (b) prev=null via the 2-byte simple-value form (0xf8 0x16 instead of 0xf6):
        let noncanon_null = [0xa2u8, 0x01, 0x03, 0x02, 0xf8, 0x16];
        //  (c) map keys in DESCENDING order (2 before 1):
        let noncanon_order = [0xa2u8, 0x02, 0xf6, 0x01, 0x03];

        let base = Aum::from_cbor(&canonical).expect("canonical decodes");
        for (label, bytes) in [
            ("non-minimal int head", &noncanon_int[..]),
            ("2-byte null simple value", &noncanon_null[..]),
            ("descending key order", &noncanon_order[..]),
        ] {
            let got = Aum::from_cbor(bytes)
                .unwrap_or_else(|e| panic!("non-canonical ({label}) should still decode: {e}"));
            assert_eq!(
                got, base,
                "non-canonical ({label}) must decode to the same Aum"
            );
            assert_eq!(
                got.hash(),
                base.hash(),
                "non-canonical ({label}) must hash identically (re-serialized canonically)"
            );
            // And it normalises: re-serialize equals the canonical bytes.
            assert_eq!(
                got.serialize(),
                canonical,
                "non-canonical ({label}) must re-serialize to the canonical form"
            );
        }
    }
    // ---- StaticValidate cluster (tsr-uvg): Go `AUM/Key/State.StaticValidate` parity ----

    /// `Key::static_validate` — votes must be 1..=4096 (Go `Key.StaticValidate`).
    #[test]
    fn key_static_validate_votes_range() {
        let mut k = test_aum_key(1, 1);
        assert!(k.static_validate().is_ok(), "votes=1 ok");
        k.votes = 4096;
        assert!(k.static_validate().is_ok(), "votes=4096 ok (boundary)");
        k.votes = 0;
        assert_eq!(
            k.static_validate().unwrap_err(),
            TkaError::BadKeyState,
            "votes=0 rejected"
        );
        k.votes = 4097;
        assert_eq!(
            k.static_validate().unwrap_err(),
            TkaError::BadKeyState,
            "votes>4096 rejected"
        );
    }

    /// `Key::static_validate` — metadata byte total must be ≤ MAX_META_BYTES.
    #[test]
    fn key_static_validate_meta_size() {
        let mut k = test_aum_key(2, 1);
        // 256-byte key + 256-byte value = 512 total = exactly MAX_META_BYTES → ok.
        k.meta = alloc::vec![(
            String::from_utf8(alloc::vec![b'k'; 256]).unwrap(),
            String::from_utf8(alloc::vec![b'v'; 256]).unwrap(),
        )];
        assert!(k.static_validate().is_ok(), "512 meta bytes ok (boundary)");
        // One more byte → rejected.
        k.meta[0].1.push('x');
        assert_eq!(
            k.static_validate().unwrap_err(),
            TkaError::BadKeyState,
            "meta>512 rejected"
        );
    }

    /// `Aum::static_validate` — per-kind field allow-lists (Go `AUM.StaticValidate`).
    #[test]
    fn aum_static_validate_per_kind_field_allow_lists() {
        // AddKey must have a key and nothing else.
        let mut a = genesis_add(test_aum_key(1, 1));
        assert!(a.static_validate().is_ok());
        a.key_id = alloc::vec![1, 2, 3]; // foreign field
        assert!(
            a.static_validate().is_err(),
            "AddKey with a stray KeyID rejected"
        );

        // RemoveKey must have a key_id and nothing else.
        let g = signed_genesis_add(1, 1);
        let mut rm = child(
            &g,
            AumKind::RemoveKey,
            None,
            test_aum_key(2, 1).public.clone(),
        );
        assert!(rm.static_validate().is_ok());
        rm.votes = Some(3); // foreign field
        assert!(
            rm.static_validate().is_err(),
            "RemoveKey with stray Votes rejected"
        );

        // UpdateKey must have key_id AND (votes or meta).
        let mut up = child(
            &g,
            AumKind::UpdateKey,
            None,
            test_aum_key(2, 1).public.clone(),
        );
        assert!(
            up.static_validate().is_err(),
            "UpdateKey with neither votes nor meta rejected"
        );
        up.votes = Some(2);
        assert!(up.static_validate().is_ok(), "UpdateKey with votes ok");
        up.key = Some(test_aum_key(3, 1)); // foreign field
        assert!(
            up.static_validate().is_err(),
            "UpdateKey with a stray Key rejected"
        );

        // Checkpoint must have state and nothing else.
        let mut cp = child(&g, AumKind::Checkpoint, None, Vec::new());
        cp.state = Some(AumState {
            last_aum_hash: None,
            disablement_values: Some(alloc::vec![alloc::vec![0xD5u8; DISABLEMENT_LENGTH]]),
            keys: Some(alloc::vec![test_aum_key(1, 1)]),
            state_id1: 0,
            state_id2: 0,
        });
        assert!(cp.static_validate().is_ok());
        cp.votes = Some(1); // foreign field
        assert!(
            cp.static_validate().is_err(),
            "Checkpoint with stray Votes rejected"
        );
    }

    /// `Aum::static_validate` — every signature must have a 32-byte key_id and 64-byte signature.
    #[test]
    fn aum_static_validate_signature_lengths() {
        let mut a = genesis_add(test_aum_key(1, 1));
        a.signatures = alloc::vec![AumSignature {
            key_id: alloc::vec![0u8; 31], // wrong length (should be 32)
            signature: alloc::vec![0u8; 64],
        }];
        assert!(a.static_validate().is_err(), "31-byte keyID rejected");
        a.signatures[0].key_id = alloc::vec![0u8; 32];
        a.signatures[0].signature = alloc::vec![0u8; 63]; // wrong length (should be 64)
        assert!(a.static_validate().is_err(), "63-byte signature rejected");
    }

    /// The last-key guard (Go `aumVerify`): a `RemoveKey` removing the only remaining trusted key is
    /// rejected — otherwise the authority would be left with an empty key set (lock disabled).
    #[test]
    fn verified_chain_rejects_removing_last_key() {
        let g = signed_genesis_add(1, 1); // exactly one trusted key (seed 1)
        let mut rm = child(
            &g,
            AumKind::RemoveKey,
            None,
            test_aum_key(1, 1).public.clone(),
        );
        sign_aum(&mut rm, &[1]); // validly signed by the trusted key
        assert_eq!(
            VerifiedAumChain::verify(&[g, rm]).unwrap_err(),
            TkaError::BadKeyState,
            "removing the last trusted key must be refused"
        );
    }

    /// Removing a non-last key is fine: with two trusted keys, one can be removed.
    #[test]
    fn verified_chain_allows_removing_non_last_key() {
        let g = signed_genesis_add(1, 1);
        let mut add = child(&g, AumKind::AddKey, Some(test_aum_key(2, 1)), Vec::new());
        sign_aum(&mut add, &[1]);
        let mut rm = child(
            &add,
            AumKind::RemoveKey,
            None,
            test_aum_key(2, 1).public.clone(),
        );
        sign_aum(&mut rm, &[1]);
        let verified = VerifiedAumChain::verify(&[g, add, rm]).expect("removing a non-last key ok");
        let auth = Authority::from_verified_chain(verified);
        assert_eq!(
            auth.state().keys.len(),
            1,
            "back to one key after the remove"
        );
    }

    /// `UpdateKey` is re-validated after mutation (Go re-runs `Key.StaticValidate`): an update that
    /// sets votes out of range is rejected.
    #[test]
    fn verified_chain_rejects_updatekey_to_invalid_votes() {
        let g = signed_genesis_add(1, 1);
        let mut up = child(
            &g,
            AumKind::UpdateKey,
            None,
            test_aum_key(1, 1).public.clone(),
        );
        up.votes = Some(5000); // > 4096 → invalid after mutation
        sign_aum(&mut up, &[1]);
        assert_eq!(
            VerifiedAumChain::verify(&[g, up]).unwrap_err(),
            TkaError::BadKeyState,
            "an UpdateKey that sets votes > 4096 is rejected (post-mutation re-validate)"
        );
    }

    // ===== AUM-chain sync: store + SyncOffer + MissingAUMs (issue #7 chunk 2, tsr-5po) =====

    /// Build a simple linear chain `genesis(AddKey) -> NoOp -> NoOp -> ...` of `len` AUMs, returning
    /// the AUMs in parent→child order. The genesis adds `test_aum_key(1, 1)`.
    fn linear_chain(len: usize) -> Vec<Aum> {
        assert!(len >= 1);
        let mut chain = alloc::vec![genesis_add(test_aum_key(1, 1))];
        for _ in 1..len {
            let parent = chain.last().unwrap();
            chain.push(child(parent, AumKind::NoOp, None, Vec::new()));
        }
        chain
    }

    /// An [`Authority`] whose head is the last AUM of `chain` (via the structural `from_chain`; the
    /// sync layer is signature-agnostic, so unsigned test chains are fine here).
    fn authority_at_head(chain: &[Aum]) -> Authority {
        Authority::from_chain(chain).expect("linear test chain replays")
    }

    #[test]
    fn mem_store_indexes_by_hash_and_children() {
        let chain = linear_chain(3);
        let store = MemAumStore::from_aums(chain.clone());
        assert_eq!(store.len(), 3);
        // by-hash lookup
        assert_eq!(store.aum(&chain[1].hash()).as_ref(), Some(&chain[1]));
        assert!(store.aum(&AumHash([0xFF; AUM_HASH_LEN])).is_none());
        // child index: genesis has one child (chain[1]); the tail has none.
        let kids = store.child_aums(&chain[0].hash());
        assert_eq!(kids.len(), 1);
        assert_eq!(kids[0], chain[1]);
        assert!(store.child_aums(&chain[2].hash()).is_empty());
        // insert is idempotent on hash + child edge.
        let mut s2 = store.clone();
        s2.insert(chain[1].clone());
        assert_eq!(s2.len(), 3, "re-insert must not grow the store");
        assert_eq!(
            s2.child_aums(&chain[0].hash()).len(),
            1,
            "child edge not duplicated"
        );
    }

    #[test]
    fn sync_offer_head_and_oldest_bookend() {
        let chain = linear_chain(5);
        let store = MemAumStore::from_aums(chain.clone());
        let auth = authority_at_head(&chain);
        let oldest = chain[0].hash();

        let offer = auth.sync_offer(&store, oldest).expect("offer");
        assert_eq!(offer.head, chain[4].hash(), "offer head is the chain head");
        assert_eq!(
            *offer.ancestors.last().unwrap(),
            oldest,
            "the last ancestor is always the oldest AUM"
        );
        // Every ancestor is a real hash in the chain.
        for a in &offer.ancestors {
            assert!(
                store.aum(a).is_some(),
                "ancestor {a:?} must be in the store"
            );
        }
    }

    #[test]
    fn sync_offer_truncates_on_a_gap() {
        // A store missing an interior AUM: the backward walk breaks early, but `oldest` is still
        // appended (matching Go's break-then-append). Drop chain[1] so walking back from head hits
        // a gap.
        let chain = linear_chain(4);
        let store = MemAumStore::from_aums(
            chain
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != 1)
                .map(|(_, a)| a.clone()),
        );
        let auth = authority_at_head(&chain);
        let offer = auth
            .sync_offer(&store, chain[0].hash())
            .expect("offer despite gap");
        assert_eq!(*offer.ancestors.last().unwrap(), chain[0].hash());
    }

    #[test]
    fn missing_aums_empty_when_up_to_date() {
        let chain = linear_chain(4);
        let store = MemAumStore::from_aums(chain.clone());
        let auth = authority_at_head(&chain);
        let oldest = chain[0].hash();
        // Peer offers the SAME head → nothing missing.
        let peer_offer = auth.sync_offer(&store, oldest).expect("offer");
        let missing = auth
            .missing_aums(&store, &peer_offer, oldest)
            .expect("missing");
        assert!(missing.is_empty(), "an up-to-date peer is missing nothing");
    }

    #[test]
    fn missing_aums_head_intersection_sends_the_tail() {
        // We are at head chain[4]; the peer is behind at chain[2] (their head is an ancestor of
        // ours). We must send them chain[3] and chain[4] (everything after the intersection).
        let chain = linear_chain(5);
        let store = MemAumStore::from_aums(chain.clone());
        let oldest = chain[0].hash();
        let us = authority_at_head(&chain); // head = chain[4]

        // The peer's offer: head = chain[2], ancestors back to oldest. Build it from a peer authority
        // whose head is chain[2] over a store holding the prefix [0..=2].
        let peer_prefix: Vec<Aum> = chain[0..=2].to_vec();
        let peer_store = MemAumStore::from_aums(peer_prefix.clone());
        let peer = authority_at_head(&peer_prefix); // head = chain[2]
        let peer_offer = peer.sync_offer(&peer_store, oldest).expect("peer offer");

        let missing = us
            .missing_aums(&store, &peer_offer, oldest)
            .expect("missing");
        let missing_hashes: Vec<AumHash> = missing.iter().map(Aum::hash).collect();
        assert_eq!(
            missing_hashes,
            alloc::vec![chain[3].hash(), chain[4].hash()],
            "must send exactly the AUMs after the peer's head, in order"
        );
    }

    #[test]
    fn missing_aums_excludes_the_intersection_itself() {
        // The intersection AUM (the peer's head) must NOT be in the sent set — they already have it.
        let chain = linear_chain(4);
        let store = MemAumStore::from_aums(chain.clone());
        let oldest = chain[0].hash();
        let us = authority_at_head(&chain);

        let peer_prefix: Vec<Aum> = chain[0..=1].to_vec();
        let peer = authority_at_head(&peer_prefix);
        let peer_offer = peer
            .sync_offer(&MemAumStore::from_aums(peer_prefix.clone()), oldest)
            .expect("peer offer");

        let missing = us
            .missing_aums(&store, &peer_offer, oldest)
            .expect("missing");
        assert!(
            !missing.iter().any(|a| a.hash() == chain[1].hash()),
            "the intersection AUM (peer's head) must be excluded"
        );
        assert_eq!(missing.len(), 2, "only chain[2] and chain[3] are missing");
    }

    #[test]
    fn missing_aums_no_intersection_errors() {
        // Two totally unrelated chains (different genesis keys → different hashes everywhere): no
        // intersection, so `missing_aums` fails closed rather than mis-rooting.
        let ours = linear_chain(3);
        let store = MemAumStore::from_aums(ours.clone());
        let us = authority_at_head(&ours);

        // A foreign chain the peer offers; we hold none of it.
        let theirs = {
            let mut c = alloc::vec![genesis_add(test_aum_key(9, 1))];
            c.push(child(&c[0], AumKind::NoOp, None, Vec::new()));
            c
        };
        let foreign_offer = SyncOffer {
            head: theirs[1].hash(),
            ancestors: alloc::vec![theirs[1].hash(), theirs[0].hash()],
        };
        assert!(
            us.missing_aums(&store, &foreign_offer, ours[0].hash())
                .is_err(),
            "no intersection must fail closed, not mis-root"
        );
    }

    #[test]
    fn compute_state_at_matches_replay_at_each_point() {
        // The state computed at an interior AUM via the store walk must equal a direct linear replay
        // of the prefix up to that AUM (the verify-only Authority's state).
        let chain = linear_chain(4);
        let store = MemAumStore::from_aums(chain.clone());
        for i in 0..chain.len() {
            let want = chain[i].hash();
            let via_store = compute_state_at(&store, MAX_SYNC_ITER, want)
                .expect("compute_state_at ok")
                .expect("hash present");
            let via_replay = Authority::from_chain(&chain[0..=i]).expect("prefix replays");
            assert_eq!(
                via_store.to_state(),
                *via_replay.state(),
                "computed state at chain[{i}] must match a direct prefix replay"
            );
        }
    }

    #[test]
    fn sync_offer_ancestors_are_exponentially_spaced() {
        // With a long chain the ancestor sampling thins out (skip 4, then 16, ...), so the count is
        // far below the chain length — the whole point of the offer.
        let chain = linear_chain(60);
        let store = MemAumStore::from_aums(chain.clone());
        let auth = authority_at_head(&chain);
        let offer = auth.sync_offer(&store, chain[0].hash()).expect("offer");
        assert!(
            offer.ancestors.len() < 12,
            "exponential spacing keeps the ancestor list small (got {})",
            offer.ancestors.len()
        );
        // First sampled ancestor is 4 back from head (i=4 is the first i%4==0 with i>0): chain[56].
        assert_eq!(offer.ancestors[0], chain[60 - 1 - 4].hash());
        assert_eq!(*offer.ancestors.last().unwrap(), chain[0].hash());
    }

    #[test]
    fn linear_chain_from_returns_ordered_chain() {
        // A store built from a linear chain returns it genesis→head in order, regardless of insert
        // order, so it round-trips through `VerifiedAumChain`/`from_chain`.
        let chain = linear_chain(5);
        // Insert in reverse to prove ordering is by chain links, not insert order.
        let mut store = MemAumStore::new();
        for aum in chain.iter().rev() {
            store.insert(aum.clone());
        }
        let ordered = store.linear_chain_from(chain[0].hash()).expect("walk");
        let got: Vec<AumHash> = ordered.iter().map(Aum::hash).collect();
        let want: Vec<AumHash> = chain.iter().map(Aum::hash).collect();
        assert_eq!(got, want, "linear_chain_from must yield genesis→head order");
        // And it replays into the same head a direct from_chain produces.
        assert_eq!(
            Authority::from_chain(&ordered).unwrap().head(),
            chain[4].hash()
        );
    }

    #[test]
    fn linear_chain_from_missing_genesis_errors() {
        let chain = linear_chain(3);
        let store = MemAumStore::from_aums(chain.clone());
        // A genesis hash not in the store is BadChain, not a panic.
        assert_eq!(
            store
                .linear_chain_from(AumHash([0xEE; AUM_HASH_LEN]))
                .unwrap_err(),
            TkaError::BadChain
        );
    }

    #[test]
    fn linear_chain_from_single_genesis() {
        // A store with only the genesis returns just it (the bootstrap case before any sync).
        let g = genesis_add(test_aum_key(1, 1));
        let store = MemAumStore::from_aums([g.clone()]);
        let ordered = store.linear_chain_from(g.hash()).expect("walk");
        assert_eq!(ordered.len(), 1);
        assert_eq!(ordered[0].hash(), g.hash());
    }
}
