use core::fmt::{Debug, Display, Formatter};

use crate::{
    DiscoKeyPair, MachineKeyPair, MachinePrivateKey, NetworkLockKeyPair, NetworkLockPrivateKey,
    NodeKeyPair, NodePrivateKey, NodePublicKey,
};

/// The portion of the key state that should be retained between runs of the same device.
///
/// Disco keys are ephemeral and should be generated anew each time a device runs, so are
/// excluded from this state.
///
/// # At-rest protection is the embedder's responsibility
///
/// The secret-bearing fields here are zeroized in memory on drop (the dedicated key types and the
/// [`Zeroizing`](zeroize::Zeroizing)-wrapped ACME account key), but that is an in-process hygiene
/// measure only. Protecting this state **at rest** — restrictive file permissions (e.g. `0o600`),
/// full-disk or filesystem encryption, secure-enclave/keyring storage — is entirely the
/// responsibility of the embedding application that serializes and writes it to durable storage.
/// This crate neither reads nor writes files and makes no at-rest guarantee (see `SECURITY.md`).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PersistState {
    /// The [`MachinePrivateKey`] for the hardware this Tailnet peer runs on.
    pub machine_key: MachinePrivateKey,

    /// The [`NetworkLockPrivateKey`] for this Tailnet peer, for use with Tailnet Lock.
    pub network_lock_key: NetworkLockPrivateKey,

    /// The [`NodePrivateKey`] for this Tailnet peer.
    pub node_key: NodePrivateKey,

    /// The node's PREVIOUS node public key, recorded during a node-key rotation so the next
    /// registration sends it as `RegisterRequest.OldNodeKey` for key continuity (Go's `regen` flow).
    /// `None` outside a rotation (the default). Reactive / embedder-driven — matching Go, this fork
    /// does NOT auto-rotate the node key before expiry (Go deliberately doesn't either; key expiry is
    /// a human-re-auth control). See [`PersistState::rotate_node_key`].
    #[cfg_attr(feature = "serde", serde(default))]
    pub old_node_key: Option<NodePublicKey>,

    /// The persisted ACME account key (PKCS#8 DER of an ECDSA P-256 key), or `None` if no ACME
    /// account has been provisioned for this node. The `acme` cert-issuance path loads this to keep
    /// the same Let's Encrypt account identity across renewals; absent, the runtime generates an
    /// ephemeral per-call key (a new ACME account each issuance). `#[serde(default)]` so key files
    /// written before this field load as `None` (mirrors [`old_node_key`](PersistState::old_node_key)).
    ///
    /// Wrapped in [`Zeroizing`](zeroize::Zeroizing) so the DER private-key bytes are wiped from
    /// memory on drop. `Zeroizing<Vec<u8>>` serializes transparently via its inner `Vec`, so the
    /// persisted JSON shape is identical to a bare `Vec<u8>` (a byte array).
    #[cfg_attr(feature = "serde", serde(default))]
    pub acme_account_key: Option<zeroize::Zeroizing<alloc::vec::Vec<u8>>>,
}

impl PersistState {
    /// Rotate the node key for re-registration, mirroring Go's `regen` flow: record the current
    /// node public key as [`old_node_key`](PersistState::old_node_key) and replace the node key with
    /// a freshly-generated one. The next registration that uses this state will send the prior key
    /// as `RegisterRequest.OldNodeKey`, so control links the new node key to the node's existing
    /// identity instead of treating it as a brand-new node.
    ///
    /// This is the embedder-driven rotation primitive (re-create the device with the returned state).
    /// It is reactive, NOT a pre-expiry auto-rotator: Go has no such timer, because node-key expiry
    /// is a deliberate periodic human/IdP re-attestation control. Re-registration still requires a
    /// valid auth credential, exactly as a fresh registration does.
    ///
    // TODO(TKA): on a tailnet-lock-enabled tailnet, a node-key rotation must also re-sign the node
    // key with the network-lock key and send the new `RegisterRequest.NodeKeySignature`. This
    // primitive covers the non-TKA path; TKA re-sign is a separate follow-up.
    pub fn rotate_node_key(&mut self) {
        self.old_node_key = Some(self.node_key.public_key());
        self.node_key = NodePrivateKey::random();
    }
}

impl From<&NodeState> for PersistState {
    fn from(value: &NodeState) -> Self {
        Self {
            // `.clone()` (not a bare field read): the private keys are no longer `Copy`, so copying
            // them out of a `&NodeState` is now an explicit clone. The original keys stay owned by
            // `value` and zeroize on their own drop.
            node_key: value.node_keys.private.clone(),
            machine_key: value.machine_keys.private.clone(),
            network_lock_key: value.network_lock_keys.private.clone(),
            old_node_key: value.old_node_key,
            acme_account_key: value.acme_account_key.clone(),
        }
    }
}

impl From<NodeState> for PersistState {
    fn from(value: NodeState) -> Self {
        Self::from(&value)
    }
}

impl Default for PersistState {
    fn default() -> Self {
        Self {
            machine_key: MachinePrivateKey::random(),
            network_lock_key: NetworkLockPrivateKey::random(),
            node_key: NodePrivateKey::random(),
            old_node_key: None,
            acme_account_key: None,
        }
    }
}

/// The complete runtime key state for a Tailscale node.
#[derive(Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize))]
pub struct NodeState {
    /// The [`DiscoKeyPair`] this Tailnet peer uses for the Disco protocol.
    ///
    /// These should be randomly generated for each run of a Tailscale device.
    pub disco_keys: DiscoKeyPair,

    /// The [`MachineKeyPair`] for the hardware this Tailnet peer runs on.
    pub machine_keys: MachineKeyPair,

    /// The [`NetworkLockKeyPair`] for this Tailnet peer, for use with Tailnet Lock.
    pub network_lock_keys: NetworkLockKeyPair,

    /// The [`NodeKeyPair`] for this Tailnet peer.
    pub node_keys: NodeKeyPair,

    /// The node's previous node public key during a rotation (see
    /// [`PersistState::old_node_key`]). Threaded to registration as `RegisterRequest.OldNodeKey`.
    #[cfg_attr(feature = "serde", serde(default))]
    pub old_node_key: Option<NodePublicKey>,

    /// The persisted ACME account key (PKCS#8 DER), threaded from
    /// [`PersistState::acme_account_key`]. The `acme` cert-issuance path reads this to reuse the
    /// same Let's Encrypt account across renewals. `None` when no ACME account is provisioned.
    ///
    /// Wrapped in [`Zeroizing`](zeroize::Zeroizing) so the DER private-key bytes are wiped from
    /// memory on drop; serializes transparently via the inner `Vec` (unchanged JSON shape).
    #[cfg_attr(feature = "serde", serde(default))]
    pub acme_account_key: Option<zeroize::Zeroizing<alloc::vec::Vec<u8>>>,
}

impl Debug for NodeState {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("NodeState")
            .field(&self.machine_keys.public)
            .field(&self.node_keys.public)
            .field(&self.disco_keys.public)
            .field(&self.network_lock_keys.public)
            .finish()
    }
}

impl Display for NodeState {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(self, f)
    }
}

impl NodeState {
    /// Generate a new [`NodeState`]. All keys get random values.
    pub fn generate() -> Self {
        Default::default()
    }

    /// Rotate the node key for re-registration, the runtime twin of
    /// [`PersistState::rotate_node_key`]: record the current node public key as
    /// [`old_node_key`](NodeState::old_node_key) and replace the [`node_keys`](NodeState::node_keys)
    /// pair with a freshly-generated one. The next registration built from this state sends the prior
    /// key as `RegisterRequest.OldNodeKey`, so control links the new node key to the node's existing
    /// identity instead of treating it as a brand-new node (Go's `regen`/`doLogin` flow).
    ///
    /// Only the **node key** rotates. The disco and machine keys are deliberately left untouched: the
    /// data plane (magicsock/WireGuard sessions, disco) keys on those and on per-peer keys, never on
    /// the self node key, so a node-key rotation does not re-key or flap an established tunnel. The
    /// node key is a control-plane identity. (The disco ping packet does carry the self node key as a
    /// claimed-sender identity — a caller that rotates at runtime should refresh magicsock's copy so
    /// outbound pings advertise the new key, but that is a magicsock concern, not a key-state one.)
    ///
    // TODO(TKA): on a tailnet-lock-enabled tailnet, a node-key rotation must also re-sign the new node
    // key with the network-lock key and send the new `RegisterRequest.NodeKeySignature`. This
    // primitive covers the non-TKA path; the TKA re-sign is a separate follow-up, so an auto-reauth
    // caller must gate rotation OFF while lock enforcement is active (else the node locks itself out
    // of locked peers with an unsigned key).
    pub fn rotate_node_key(&mut self) {
        self.old_node_key = Some(self.node_keys.public);
        self.node_keys = NodeKeyPair::new();
    }
}

impl From<&PersistState> for NodeState {
    fn from(value: &PersistState) -> Self {
        Self {
            disco_keys: Default::default(),
            // `.clone().into()`: building each keypair consumes a private key, which can no longer
            // be `Copy`-d out of the `&PersistState`. Clone the stored key, then derive the pair
            // (the pair's public half is computed from a borrow inside `From<$private>`).
            node_keys: value.node_key.clone().into(),
            machine_keys: value.machine_key.clone().into(),
            network_lock_keys: value.network_lock_key.clone().into(),
            old_node_key: value.old_node_key,
            acme_account_key: value.acme_account_key.clone(),
        }
    }
}

impl From<PersistState> for NodeState {
    fn from(value: PersistState) -> Self {
        Self::from(&value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotate_node_key_sets_old_and_fresh() {
        let mut state = PersistState::default();
        let before_pub = state.node_key.public_key();

        state.rotate_node_key();

        assert_eq!(state.old_node_key, Some(before_pub));
        assert_ne!(state.node_key.public_key(), before_pub);
    }

    #[test]
    fn node_state_rotate_node_key_sets_old_and_fresh() {
        let mut state = NodeState::generate();
        let before_pub = state.node_keys.public;
        // The other key roles must be preserved across a node-key rotation (only the node key
        // rotates — disco/machine/network-lock are unchanged, which is what keeps tunnels from
        // flapping and keeps a locked-tailnet re-sign possible).
        let disco_before = state.disco_keys.public;
        let machine_before = state.machine_keys.public;
        let lock_before = state.network_lock_keys.public;

        state.rotate_node_key();

        // Old key recorded, node key replaced with a fresh one.
        assert_eq!(state.old_node_key, Some(before_pub));
        assert_ne!(state.node_keys.public, before_pub);
        // The fresh keypair's public matches its private (it's a real, consistent pair).
        assert_eq!(
            state.node_keys.public,
            NodePublicKey::from(&state.node_keys.private)
        );
        // Every other key role is untouched.
        assert_eq!(state.disco_keys.public, disco_before);
        assert_eq!(state.machine_keys.public, machine_before);
        assert_eq!(state.network_lock_keys.public, lock_before);
    }

    #[test]
    fn node_state_rotate_threads_to_persist_old_node_key() {
        // After a runtime rotation, converting back to a PersistState carries the prior public key as
        // old_node_key (so an embedder persisting the rotated state keeps the OldNodeKey linkage).
        let mut state = NodeState::generate();
        let before_pub = state.node_keys.public;
        state.rotate_node_key();
        let persist = PersistState::from(&state);
        assert_eq!(persist.old_node_key, Some(before_pub));
        assert_eq!(persist.node_key.public_key(), state.node_keys.public);
    }

    #[test]
    fn node_state_threads_old_node_key() {
        let mut persist = PersistState::default();
        let some_pub = NodePrivateKey::random().public_key();
        persist.old_node_key = Some(some_pub);

        let node_state = NodeState::from(&persist);
        assert_eq!(node_state.old_node_key, Some(some_pub));

        let round_trip = PersistState::from(&node_state);
        assert_eq!(round_trip.old_node_key, Some(some_pub));
    }

    #[test]
    fn default_persist_state_has_no_old_key() {
        assert!(PersistState::default().old_node_key.is_none());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn persist_state_old_node_key_serde_default() {
        // A default PersistState round-trips with no old key.
        let json = serde_json::to_string(&PersistState::default()).unwrap();
        let parsed: PersistState = serde_json::from_str(&json).unwrap();
        assert!(parsed.old_node_key.is_none());

        // A serialized form that OMITS `old_node_key` still deserializes (serde(default) →
        // backward-compat with pre-rotation persisted state).
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("old_node_key")
            .expect("default serializes the field");
        let parsed: PersistState =
            serde_json::from_value(value).expect("missing old_node_key deserializes via default");
        assert!(parsed.old_node_key.is_none());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn persist_state_acme_account_key_serde_default_and_round_trip() {
        use alloc::vec;

        // An old key file that OMITS `acme_account_key` still deserializes (serde(default) → None).
        let json = serde_json::to_string(&PersistState::default()).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("acme_account_key")
            .expect("default serializes the field");
        let parsed: PersistState = serde_json::from_value(value)
            .expect("missing acme_account_key deserializes via default");
        assert!(parsed.acme_account_key.is_none());

        // A `Some(der)` value round-trips through serde and across the NodeState conversions.
        // The `Zeroizing` wrapper must NOT change the on-wire JSON: it serializes as the inner
        // byte `Vec`, so the rendered JSON is identical to a bare `Vec<u8>`.
        let state = PersistState {
            acme_account_key: Some(zeroize::Zeroizing::new(vec![1u8, 2, 3, 4])),
            ..Default::default()
        };
        let json = serde_json::to_string(&state).unwrap();
        assert!(
            json.contains("\"acme_account_key\":[1,2,3,4]"),
            "Zeroizing must serialize as the bare byte array (unchanged JSON shape): {json}"
        );
        let parsed: PersistState = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.acme_account_key.as_deref().map(|v| v.as_slice()),
            Some(&[1u8, 2, 3, 4][..])
        );

        let node_state = NodeState::from(&state);
        assert_eq!(
            node_state.acme_account_key.as_deref().map(|v| v.as_slice()),
            Some(&[1u8, 2, 3, 4][..])
        );
        let round_trip = PersistState::from(&node_state);
        assert_eq!(
            round_trip.acme_account_key.as_deref().map(|v| v.as_slice()),
            Some(&[1u8, 2, 3, 4][..])
        );
    }
}
