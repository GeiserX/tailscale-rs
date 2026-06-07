use std::time::Instant;

use aead::AeadInPlace;
use blake2::{Blake2s256, Digest};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use hkdf::SimpleHkdf;
use ts_keys::{NodeKeyPair, NodePrivateKey, NodePublicKey};
use ts_packet::PacketMut;
use ts_time::Handle;
use zerocopy::{FromZeros, IntoBytes};

use crate::{
    config::Psk,
    endpoint::Event,
    macs::{MACReceiver, MACSender, Mac},
    messages::*,
    session::{ReceiveSession, TransmitSession},
    time::TAI64N,
};

/// The symmetric session keys produced by a WireGuard handshake.
struct SessionKeys {
    initiator_to_responder: chacha20poly1305::Key,
    responder_to_initiator: chacha20poly1305::Key,
}

/// The state of a partially processed handshake.
///
/// Has to be cloneable because we may have to attempt finalization of the handshake
/// as the initiator multiple times, if rogue invalid responses are received. It's
/// deliberately not Copy, because cloning and allowing potential reuse of the cipher
/// state is risky and needs to be a deliberate act.
#[derive(Clone)]
struct HandshakeState {
    hash: [u8; 32],
    chaining_key: [u8; 32],
    cipher: Option<ChaCha20Poly1305>,
}

/// Initialize a ChaCha20Poly1305 cipher with the given key.
///
/// # Panics
/// Panics if the key isn't exactly 32 bytes.
fn must_cipher(key: &[u8]) -> ChaCha20Poly1305 {
    assert_eq!(key.len(), 32);
    ChaCha20Poly1305::new_from_slice(key).unwrap()
}

/// Use HKDF to derive two 32-byte values.
fn must_hkdf2(chaining_key: &[u8; 32], key: &[u8]) -> ([u8; 32], [u8; 32]) {
    let kdf = SimpleHkdf::<Blake2s256>::new(Some(chaining_key), key);
    let mut expanded = [0; 64];
    // Expansion only fails if you request more bytes than the KDF can provide. This KDF can always
    // provide 64 bytes.
    kdf.expand(&[], &mut expanded).unwrap();
    (
        expanded[..32].try_into().unwrap(),
        expanded[32..].try_into().unwrap(),
    )
}

/// Use HKDF to derive three 32-byte values.
fn must_hkdf3(chaining_key: &[u8; 32], key: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let kdf = SimpleHkdf::<Blake2s256>::new(Some(chaining_key), key);
    let mut expanded = [0; 96];
    // Expansion only fails if you request more bytes than the KDF can provide. This KDF can always
    // provide 96 bytes.
    kdf.expand(&[], &mut expanded).unwrap();
    (
        expanded[..32].try_into().unwrap(),
        expanded[32..64].try_into().unwrap(),
        expanded[64..].try_into().unwrap(),
    )
}

impl HandshakeState {
    fn new(responder_static: NodePublicKey) -> HandshakeState {
        // TODO: precompute initial hash and chaining key, unless the compiler
        // is clever enough to figure it out by itself?
        let init = Blake2s256::digest("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s");
        HandshakeState {
            hash: init.into(),
            chaining_key: init.into(),
            cipher: None,
        }
        .mix_hash(b"WireGuard v1 zx2c4 Jason@zx2c4.com")
        .mix_hash(responder_static.as_bytes())
    }

    /// Mix data into the handshake state.
    ///
    /// This is the MixHash() operation in the Noise spec.
    fn mix_hash(mut self, data: &[u8]) -> Self {
        let mut h = Blake2s256::new_with_prefix(self.hash);
        h.update(data);
        h.finalize_into(self.hash.as_mut_bytes().into());
        self
    }

    /// Mix a symmetric key into the handshake state, producing a single-use AEAD
    /// cipher able to encrypt/decrypt the next portion of the handshake.
    ///
    /// This is the MixKey() operation in the Noise spec.
    fn mix_key(self, key: &[u8; 32]) -> HandshakeState {
        let (ck, k) = must_hkdf2(&self.chaining_key, key);
        HandshakeState {
            hash: self.hash,
            chaining_key: ck,
            cipher: Some(must_cipher(&k)),
        }
    }

    /// Derive a one-time AEAD from the pre-shared symmetric key.
    ///
    /// This is the `psk` handshake step.
    fn mix_psk(self, psk: &Psk) -> HandshakeState {
        let (ck, h, k) = must_hkdf3(&self.chaining_key, psk.as_ref());
        HandshakeState {
            hash: self.hash,
            chaining_key: ck,
            cipher: Some(must_cipher(&k)),
        }
        .mix_hash(&h)
    }

    /// Finalize the handshake and return a pair of symmetric session keys.
    ///
    /// This is the Split() operation in the Noise spec.
    fn finish(self) -> SessionKeys {
        let (k1, k2) = must_hkdf2(&self.chaining_key, &[]);
        SessionKeys {
            initiator_to_responder: chacha20poly1305::Key::from(k1),
            responder_to_initiator: chacha20poly1305::Key::from(k2),
        }
    }

    /// Encrypt cleartext into dst.
    ///
    /// dst must be 16 bytes longer than cleartext, and is overwritten.
    ///
    /// This is the EncryptAndHash() operation in the Noise spec.
    ///
    /// # Panics
    /// Panics if dst is not exactly 16 bytes longer than cleartext, or if called at an
    /// incorrect stage of the handshake where encryption is forbidden.
    fn encrypt(mut self, cleartext: &[u8], dst: &mut [u8]) -> HandshakeState {
        assert_eq!(
            dst.len(),
            cleartext.len() + 16,
            "output slice provided to encrypt must be 16 bytes longer than the input"
        );
        let cipher = self.cipher.take().unwrap();
        // The cipher API here is awkward: we can either encrypt into a fresh Vec (causing an alloc), or we
        // can encrypt in place. The operation we want, encrypting into a provided slice of the right size,
        // isn't available.
        //
        // So, we do a little dance of copying the cleartext to the destination slice, then encrypt in place
        // and add the authentication tag to the end. This is unwieldy, but being able to pass in a destination
        // slice plays much nicer with zerocopy's transmutations.
        cleartext.write_to_prefix(dst).unwrap(); // destination size verified by assert above
        let nonce = [0; 12];
        // ChaCha20Poly1305 only fails if you try to encrypt more than ~274GiB in a single call.
        // If you're from the future with 300GiB MTUs and debugging a panic here: hello!
        let tag = cipher
            .encrypt_in_place_detached(&nonce.into(), &self.hash, &mut dst[..cleartext.len()])
            .unwrap();
        tag.write_to_suffix(dst).unwrap(); // destination size verified by assert above
        self.mix_hash(dst)
    }

    /// Decrypt ciphertext and return the cleartext.
    ///
    /// This is the DecryptAndHash() operation in the Noise spec.
    ///
    /// # Panics
    /// Panics if ciphertext is not exactly 16 bytes longer than dst, or if called at an
    /// incorrect stage of the handshake where decryption is forbidden.
    fn decrypt(mut self, ciphertext: &[u8], dst: &mut [u8]) -> Option<HandshakeState> {
        assert_eq!(
            dst.len(),
            ciphertext.len() - 16,
            "output slice provided to decrypt must be 16 bytes shorter than the input"
        );
        let cipher = self.cipher.take().unwrap();
        // Awkward API, see the longer comment in encrypt() for details.
        ciphertext[..dst.len()].write_to(dst).unwrap(); // destination size verified by assert above
        let nonce = [0; 12];
        cipher
            .decrypt_in_place_detached(
                &nonce.into(),
                &self.hash,
                dst,
                ciphertext[dst.len()..].into(),
            )
            .inspect_err(|e| {
                tracing::warn!(error = %e, "decryption failed");
            })
            .ok()?;
        Some(self.mix_hash(ciphertext))
    }
}

/// A partially completed incoming handshake.
pub struct ReceivedHandshake {
    send_id: SessionId,

    // Info decrypted from the HandshakeInitiation
    peer_ephemeral: x25519_dalek::PublicKey,
    peer_static: NodePublicKey,
    pub timestamp: TAI64N,

    // State needed to complete the handshake
    handshake: HandshakeState,
}

impl ReceivedHandshake {
    /// Process a peer's handshake initiation message.
    pub fn new(
        pkt: &HandshakeInitiation,
        my_static: &NodeKeyPair,
        macs: &MACReceiver,
    ) -> Option<ReceivedHandshake> {
        if !macs.verify_macs(pkt.as_bytes()) {
            return None;
        };

        // TODO: cookie DoS protection. Deferring implementation until more of the surrounding code is in place,
        // because the right place to do cookie enforcement might be outside of the core Noise handshake logic.
        let peer_ephemeral = x25519_dalek::PublicKey::from(pkt.ephemeral_pub);
        let my_static_dalek = x25519_dalek::StaticSecret::from(my_static.private);
        let mut peer_static_bytes = [0; 32];
        let mut timestamp = TAI64N::new_zeroed();
        let handshake = HandshakeState::new(my_static.public)
            .mix_hash(&pkt.ephemeral_pub) // e
            .mix_key(&pkt.ephemeral_pub) // e (extra mixing required by psk variant)
            .mix_key(my_static_dalek.diffie_hellman(&peer_ephemeral).as_bytes()) // es (reversed because this is the responder)
            .decrypt(&pkt.static_pub_sealed, &mut peer_static_bytes)? // s
            .mix_key(
                my_static_dalek
                    .diffie_hellman(&x25519_dalek::PublicKey::from(peer_static_bytes))
                    .as_bytes(),
            ) // ss
            .decrypt(&pkt.timestamp_sealed, timestamp.as_mut_bytes())?; // payload

        Some(ReceivedHandshake {
            handshake,
            timestamp,
            peer_static: NodePublicKey::from(peer_static_bytes),
            peer_ephemeral: x25519_dalek::PublicKey::from(pkt.ephemeral_pub),
            send_id: pkt.sender_id,
        })
    }

    /// Finalize the handshake, producing a HandshakeResponse.
    pub fn respond(
        self,
        session_id: SessionId,
        psk: &Psk,
        macs: &MACSender,
        now: Instant,
    ) -> (SessionPair, PacketMut) {
        let my_ephemeral = x25519_dalek::ReusableSecret::random();
        let my_ephemeral_pub = x25519_dalek::PublicKey::from(&my_ephemeral);
        let mut response = HandshakeResponse {
            sender_id: session_id,
            receiver_id: self.send_id,
            ephemeral_pub: my_ephemeral_pub.to_bytes(),
            ..Default::default()
        };

        let session_keys = self
            .handshake
            .mix_hash(&my_ephemeral_pub.to_bytes()) // e
            .mix_key(&my_ephemeral_pub.to_bytes()) // e (extra mixing required by psk variant)
            .mix_key(my_ephemeral.diffie_hellman(&self.peer_ephemeral).as_bytes()) // ee
            .mix_key(
                my_ephemeral
                    .diffie_hellman(&self.peer_static.into())
                    .as_bytes(),
            ) // se (reversed because this is the responder)
            .mix_psk(psk) // psk
            .encrypt(&[], &mut response.auth_tag) // payload (empty, but must encrypt to generate an auth tag)
            .finish();

        let send = TransmitSession::new(session_keys.responder_to_initiator, self.send_id, now);
        let recv = ReceiveSession::new(session_keys.initiator_to_responder, session_id, now);
        let mut pkt = PacketMut::new(size_of::<HandshakeResponse>());
        // Packet is allocated above with the correct size.
        response.write_to(pkt.as_mut()).unwrap();
        macs.write_macs(pkt.as_mut());
        (SessionPair { send, recv }, pkt)
    }

    pub fn peer_static(&self) -> NodePublicKey {
        self.peer_static
    }
}

/// Generate a handshake initiation message for a peer.
pub fn initiate_handshake(
    endpoint_static: NodePrivateKey,
    peer_static: NodePublicKey,
    session_id: SessionId,
    timestamp: TAI64N,
) -> (SentHandshake, HandshakeInitiation) {
    let ephemeral = x25519_dalek::ReusableSecret::random();
    let ephemeral_pub = x25519_dalek::PublicKey::from(&ephemeral);
    let endpoint_static_pub = NodePublicKey::from(endpoint_static);

    let mut pkt = HandshakeInitiation {
        sender_id: session_id,
        ephemeral_pub: ephemeral_pub.to_bytes(),
        ..Default::default()
    };

    let handshake = HandshakeState::new(peer_static)
        .mix_hash(ephemeral_pub.as_bytes()) // e
        .mix_key(ephemeral_pub.as_bytes()) // e (extra mixing required by psk variant)
        .mix_key(ephemeral.diffie_hellman(&peer_static.into()).as_bytes()) // es
        .encrypt(endpoint_static_pub.as_bytes(), &mut pkt.static_pub_sealed) // s
        .mix_key(
            x25519_dalek::StaticSecret::from(endpoint_static)
                .diffie_hellman(&peer_static.into())
                .as_bytes(),
        ) // ss
        .encrypt(timestamp.as_bytes(), &mut pkt.timestamp_sealed); // payload

    let ret = SentHandshake {
        id: session_id,
        my_ephemeral: ephemeral,
        my_static: endpoint_static,
        handshake,
    };

    (ret, pkt)
}

/// A partially completed sent handshake.
pub struct SentHandshake {
    pub id: SessionId,
    my_ephemeral: x25519_dalek::ReusableSecret,
    my_static: NodePrivateKey,
    handshake: HandshakeState,
}

pub struct SessionPair {
    pub send: TransmitSession,
    pub recv: ReceiveSession,
}

/// A handshake with a peer.
pub(crate) enum Handshake {
    /// No handshake in progress.
    None,
    /// We are the initiator, awaiting a response.
    ///
    /// Second field is the timeout for the handshake.
    Initiated(SentHandshake, Handle<Event>, Mac),
    /// We are the responder, awaiting an initial transport
    /// message to confirm the new session.
    Responded(Box<SessionPair>),
}

impl Handshake {
    pub(crate) fn is_active(&self) -> bool {
        !matches!(self, Handshake::None)
    }

    /// Return the session id of the handshake, if any.
    pub(crate) fn session_id(&self) -> Option<SessionId> {
        match self {
            Handshake::Initiated(handshake, ..) => Some(handshake.id),
            Handshake::Responded(tentative) => Some(tentative.recv.id()),
            Handshake::None => None,
        }
    }

    /// Respond to a peer's handshake initiation, and switch to the responder state to await
    /// session confirmation.
    ///
    /// Responding replaces any other handshake state unconditionally.
    pub(crate) fn respond(
        &mut self,
        session_id: SessionId,
        handshake: ReceivedHandshake,
        psk: &Psk,
        cookie_sender: &MACSender,
        now: Instant,
    ) -> PacketMut {
        // TODO: tie-breaker for simultaneous initiation.
        // When both peers initiate simultaneously, it's possible to get into a sticky situation
        // where each peer completes their own initiation based on the other's response, and in
        // so doing end up on completely different session keys that will never be confirmed.
        // We need to resolve the conflict one way or another to avoid this race.
        //
        // However, in practice the race is vanishingly rare unless you somehow externally
        // synchronize the peers to start handshaking at exactly the same time. So, the code is
        // usable without this race avoidance logic.
        //
        // We may also be able to resolve this race with a 4th handshake state wherein we are
        // simultaneously initiator and responder, and temporarily exist in quantum superposition
        // until confirmation packets collapse the state again.
        let (session, packet) = handshake.respond(session_id, psk, cookie_sender, now);
        *self = Handshake::Responded(Box::new(session));
        packet
    }

    /// Finish a handshake as the initiator, returning the newly established sessions.
    ///
    /// The handshake state is unchanged if the handshake cannot complete, either because
    /// it's not in an appropriate state or because the handshake response isn't a valid
    /// completion of the handshake.
    pub(crate) fn finish(
        &mut self,
        packet: &HandshakeResponse,
        psk: &Psk,
        cookies: &MACReceiver,
        now: Instant,
    ) -> Option<SessionPair> {
        let Handshake::Initiated(sent_handshake, ..) = self else {
            return None;
        };

        if !cookies.verify_macs(packet.as_bytes()) {
            return None;
        };

        let peer_ephemeral = x25519_dalek::PublicKey::from(packet.ephemeral_pub);
        let handshake = sent_handshake.handshake.clone();
        let session_keys = handshake
            .mix_hash(&packet.ephemeral_pub) // e
            .mix_key(&packet.ephemeral_pub) // e (extra mixing required by psk variant)
            .mix_key(
                sent_handshake
                    .my_ephemeral
                    .diffie_hellman(&peer_ephemeral)
                    .as_bytes(),
            ) // ee
            .mix_key(
                x25519_dalek::StaticSecret::from(sent_handshake.my_static)
                    .diffie_hellman(&peer_ephemeral)
                    .as_bytes(),
            ) // se
            .mix_psk(psk) // psk
            .decrypt(&packet.auth_tag, &mut Vec::new()) // payload (empty, but must decrypt to verify auth tag)
            .map(|handshake| handshake.finish())?;

        let send = TransmitSession::new(session_keys.initiator_to_responder, packet.sender_id, now);
        let recv = ReceiveSession::new(session_keys.responder_to_initiator, sent_handshake.id, now);

        let Handshake::Initiated(_, timeout, _) = std::mem::replace(self, Handshake::None) else {
            unreachable!();
        };
        timeout.cancel();

        Some(SessionPair { send, recv })
    }

    /// Confirm a handshake as responder, using the provided ciphertext packets.
    ///
    /// A tentative session becomes confirmed when it successfully decrypts its first packet.
    ///
    /// The handshake state is unchanged if the handshake cannot be confirmed, either because it's
    /// not in an appropriate state or because no packet successfully decrypted.
    ///
    /// Upon successful confirmation, returns the newly established sessions as well as the one
    /// or more packets that decrypted successfully
    pub(crate) fn confirm(
        &mut self,
        session_id: SessionId,
        mut packets: Vec<PacketMut>,
    ) -> Option<(SessionPair, Vec<PacketMut>)> {
        let Handshake::Responded(tentative) = self else {
            return None;
        };

        if tentative.recv.id() != session_id {
            return None;
        };

        packets = tentative.recv.decrypt(packets);
        if packets.is_empty() {
            return None;
        }

        let Handshake::Responded(tentative) = std::mem::replace(self, Handshake::None) else {
            unreachable!();
        };

        Some((*tentative, packets))
    }
}

#[cfg(test)]
mod tests {
    use ts_keys::{NodeKeyPair, NodePrivateKey};
    use ts_time::Scheduler;
    use zerocopy::TryFromBytes;

    use super::*;

    fn fixed_static(b: u8) -> x25519_dalek::StaticSecret {
        x25519_dalek::StaticSecret::from([b; 32])
    }

    /// Cross-implementation KAT for the WireGuard `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`
    /// handshake. We drive the real private [`HandshakeState`] mix sequence — the exact calls
    /// that production [`initiate_handshake`] and [`ReceivedHandshake::respond`] make — but with
    /// FIXED ephemeral and static keys, so the derived transport (split) keys are deterministic.
    /// The reference keys are produced by an independent Go reimplementation of wireguard-go's
    /// `device/noise-protocol.go` construction over `golang.org/x/crypto` v0.52.0 (go1.26.4);
    /// generator `tests/vectors/gen/wg`. Two independent implementations of the same KDF/AEAD/DH
    /// schedule agreeing byte-for-byte on the final transport keys proves our Noise handshake is
    /// wire-compatible with Go Tailscale / wireguard-go. A divergence fails closed (the responder
    /// can never decrypt the initiator's first transport frame) but breaks real interop.
    ///
    /// Fixed inputs (little-endian 32-byte fill): init static = 0x01, resp static = 0x02,
    /// init ephemeral = 0x03, resp ephemeral = 0x04, psk = 0x05, timestamp payload = 0x07×12.
    #[test]
    fn handshake_transport_keys_match_go_kat() {
        fn unhex32(s: &str) -> [u8; 32] {
            let mut out = [0u8; 32];
            for (i, byte) in out.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("valid hex");
            }
            out
        }

        // Fixed keypairs.
        let init_static_priv = NodePrivateKey::from([0x01; 32]);
        let init_static = NodeKeyPair::from(init_static_priv);
        let resp_static = NodeKeyPair::from(NodePrivateKey::from([0x02; 32]));
        let init_ephem = fixed_static(0x03);
        let resp_ephem = fixed_static(0x04);
        let init_ephem_pub = x25519_dalek::PublicKey::from(&init_ephem);
        let resp_ephem_pub = x25519_dalek::PublicKey::from(&resp_ephem);
        let psk = Psk::from([0x05; 32]);
        let timestamp = [0x07u8; 12];

        let init_static_dalek = x25519_dalek::StaticSecret::from(init_static.private);
        let resp_static_pub_dalek = x25519_dalek::PublicKey::from(resp_static.public);

        // Confirm our clamped public keys match Go's curve25519 output (a guard that the fixed
        // inputs really are what the Go vectors were generated from).
        assert_eq!(
            init_ephem_pub.to_bytes(),
            unhex32("5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22"),
            "init ephemeral public mismatch — fixed inputs diverged from the Go vector"
        );
        assert_eq!(
            resp_ephem_pub.to_bytes(),
            unhex32("ac01b2209e86354fb853237b5de0f4fab13c7fcbf433a61c019369617fecf10b"),
            "resp ephemeral public mismatch"
        );
        assert_eq!(
            NodePublicKey::from(init_static.private).to_bytes(),
            unhex32("a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209"),
            "init static public mismatch"
        );
        assert_eq!(
            resp_static_pub_dalek.to_bytes(),
            unhex32("ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59"),
            "resp static public mismatch"
        );

        // --- Initiator builds the initiation (mirrors `initiate_handshake`). ---
        let mut static_sealed = [0u8; 32 + 16];
        let mut ts_sealed = [0u8; 12 + 16];
        let handshake = HandshakeState::new(resp_static.public)
            .mix_hash(init_ephem_pub.as_bytes()) // e
            .mix_key(init_ephem_pub.as_bytes()) // e (psk double-mix)
            .mix_key(init_ephem.diffie_hellman(&resp_static_pub_dalek).as_bytes()) // es
            .encrypt(
                NodePublicKey::from(init_static.private).as_bytes(),
                &mut static_sealed,
            ); // s
        let handshake = handshake
            .mix_key(
                init_static_dalek
                    .diffie_hellman(&resp_static_pub_dalek)
                    .as_bytes(),
            ) // ss
            .encrypt(&timestamp, &mut ts_sealed); // payload

        // --- Responder continues from the same running state (mirrors `respond`). The decrypt
        // side on the real responder reconstructs an identical hash/chaining-key, so continuing
        // the initiator's state here is equivalent to the two-party transcript. ---
        let mut auth_tag = [0u8; 16];
        let init_static_pub_dalek = x25519_dalek::PublicKey::from(init_static.public);
        let session_keys = handshake
            .mix_hash(resp_ephem_pub.as_bytes()) // e
            .mix_key(resp_ephem_pub.as_bytes()) // e (psk double-mix)
            .mix_key(resp_ephem.diffie_hellman(&init_ephem_pub).as_bytes()) // ee
            .mix_key(resp_ephem.diffie_hellman(&init_static_pub_dalek).as_bytes()) // se (responder)
            .mix_psk(&psk) // psk
            .encrypt(&[], &mut auth_tag) // empty payload → auth tag
            .finish();

        // Go split: kdf2(ck, empty) → (send_key_i2r, recv_key_r2i), matching `finish()`'s
        // (initiator_to_responder, responder_to_initiator).
        let i2r: [u8; 32] = session_keys.initiator_to_responder.into();
        let r2i: [u8; 32] = session_keys.responder_to_initiator.into();
        assert_eq!(
            i2r,
            unhex32("a18cc809fd05b6b5f99644cf506f89dce368c2f54a9dbeb9a384f36c274317ef"),
            "initiator→responder transport key diverges from Go reference"
        );
        assert_eq!(
            r2i,
            unhex32("b1aa1b797d3a45da97552b8084ade493aa767f15af95854bc86557f6dacd851d"),
            "responder→initiator transport key diverges from Go reference"
        );
    }

    /// Key-confirmation conformance (Dowling–Paterson, IACR 2018/080, Theorem 1, eCK-PFS-PSK).
    ///
    /// Their proof shows WireGuard's bare handshake provides NO key confirmation: after sending
    /// its ResponderHello, the responder has not yet seen any evidence the initiator derived the
    /// same keys. Deployed WireGuard (and wireguard-go) therefore treat the responder session as
    /// PROVISIONAL until the first inbound transport message decrypts — only an AEAD-verifying
    /// packet under the new keys confirms the peer.
    ///
    /// This test pins that property in `ts_tunnel`: after `respond()`, the handshake is
    /// `Responded` (tentative) and `confirm()` returns `None` for a packet that fails to decrypt
    /// (here, a bogus transport frame). The session is promoted to live (`Handshake::None` +
    /// returned `SessionPair`) ONLY when `confirm()` is handed a packet that the tentative receive
    /// session actually decrypts. If this ever regresses — e.g. the responder marking itself live
    /// at `respond()` time — an unconfirmed/forged peer could be treated as authenticated.
    #[test]
    fn responder_stays_provisional_until_first_transport_packet() {
        let (a_static, b_static) = (NodeKeyPair::new(), NodeKeyPair::new());
        let psk: Psk = rand::random();

        // A initiates.
        let a_mac_send = MACSender::new(&b_static.public);
        let a_session = SessionId::random();
        let (a_handshake, init_pkt) =
            initiate_handshake(a_static.private, b_static.public, a_session, TAI64N::now());
        let mut init_pkt = PacketMut::from(init_pkt.as_bytes());
        let handshake_mac = a_mac_send.write_macs(init_pkt.as_mut());

        let mut scheduler = Scheduler::default();
        let timeout = scheduler.add(
            ts_time::TimeRange::new_around(Instant::now(), std::time::Duration::from_secs(1000)),
            crate::Event::HandshakeTimeout(crate::config::PeerId(0)),
        );
        let mut a_handshake = Handshake::Initiated(a_handshake, timeout, handshake_mac);

        // B responds, entering the tentative `Responded` state.
        let init_ref = HandshakeInitiation::try_ref_from_bytes(init_pkt.as_ref()).unwrap();
        let b_mac_send = MACSender::new(&a_static.public);
        let b_mac_recv = MACReceiver::new(&b_static.public);
        let b_received = ReceivedHandshake::new(init_ref, &b_static, &b_mac_recv).unwrap();
        let b_session = SessionId::random();
        let mut b_handshake = Handshake::None;
        let response_pkt =
            b_handshake.respond(b_session, b_received, &psk, &b_mac_send, Instant::now());

        // ASSERT: the responder is provisional, NOT live.
        assert!(
            matches!(b_handshake, Handshake::Responded(_)),
            "responder must be tentative (Responded) after respond(), not live"
        );
        assert_eq!(b_handshake.session_id(), Some(b_session));

        // A finishes and gets live sessions (the initiator DOES confirm at finish() — it has the
        // responder's authenticated empty payload). This is the initiator side; the responder is
        // still waiting.
        let a_mac_recv = MACReceiver::new(&a_static.public);
        let response_ref = HandshakeResponse::try_ref_from_bytes(response_pkt.as_ref()).unwrap();
        let mut a_sessions = a_handshake
            .finish(response_ref, &psk, &a_mac_recv, Instant::now())
            .expect("initiator finishes");

        // A bogus packet for B's session id must NOT confirm (fails AEAD): responder stays tentative.
        let mut bogus = PacketMut::new(size_of::<TransportDataHeader>() + 5 + 16);
        let bogus_hdr = TransportDataHeader {
            receiver_id: b_session,
            ..Default::default()
        };
        bogus_hdr.write_to_prefix(bogus.as_mut()).unwrap();
        assert!(
            b_handshake.confirm(b_session, vec![bogus]).is_none(),
            "a packet that fails to decrypt must NOT confirm the responder session"
        );
        assert!(
            matches!(b_handshake, Handshake::Responded(_)),
            "responder must remain provisional after a non-decrypting packet"
        );

        // A real first transport packet from A under the new keys: NOW the responder confirms.
        let plaintext = vec![PacketMut::from("confirm-me".as_bytes())];
        let mut first = plaintext.clone();
        a_sessions.send.encrypt(first.iter_mut());
        let (b_sessions, decrypted) = b_handshake
            .confirm(b_session, first)
            .expect("first AEAD-verifying transport packet confirms the responder");
        assert_eq!(
            decrypted, plaintext,
            "confirmed packet must decrypt to plaintext"
        );

        // ASSERT: confirmation consumed the tentative state — the handshake is now idle/live.
        assert!(
            matches!(b_handshake, Handshake::None),
            "confirm() must consume the tentative state once the session is live"
        );

        // And the now-live responder session round-trips in both directions.
        let reply = vec![PacketMut::from("ack".as_bytes())];
        let mut reply_pkt = reply.clone();
        b_sessions.send.encrypt(&mut reply_pkt);
        assert_eq!(a_sessions.recv.decrypt(reply_pkt), reply);
    }

    #[test]
    fn test_handshake() {
        let (a_static, b_static) = (NodeKeyPair::new(), NodeKeyPair::new());
        let psk = rand::random();

        // Peer A sends a handshake initiation...
        let a_mac_send = MACSender::new(&b_static.public);
        let a_mac_recv = MACReceiver::new(&a_static.public);
        let a_session = SessionId::random(); // A wants to receive at this ID
        let a_init_time = TAI64N::now();
        let (a_handshake, init_pkt) =
            initiate_handshake(a_static.private, b_static.public, a_session, a_init_time);

        let mut init_pkt = PacketMut::from(init_pkt.as_bytes());
        let handshake_mac = a_mac_send.write_macs(init_pkt.as_mut());

        let mut scheduler = Scheduler::default();
        let timeout = scheduler.add(
            ts_time::TimeRange::new_around(Instant::now(), std::time::Duration::from_secs(1000)),
            crate::Event::HandshakeTimeout(crate::config::PeerId(0)),
        );
        let mut a_handshake = Handshake::Initiated(a_handshake, timeout, handshake_mac);

        // Peer B receives it and responds
        let init_pkt = HandshakeInitiation::try_ref_from_bytes(init_pkt.as_ref())
            .expect("init_pkt should be a valid handshake initiation message");
        let b_mac_send = MACSender::new(&a_static.public);
        let b_mac_recv = MACReceiver::new(&b_static.public);
        let b_handshake = ReceivedHandshake::new(init_pkt, &b_static, &b_mac_recv)
            .expect("peer B should successfully process A's handshake initiation");
        assert_eq!(b_handshake.peer_static, a_static.public);
        assert_eq!(b_handshake.timestamp, a_init_time);
        let b_session = SessionId::random(); // B wants to receive at this ID
        let (mut b_session, response_pkt) =
            b_handshake.respond(b_session, &psk, &b_mac_send, Instant::now());

        // Peer A receives response
        let response_pkt = HandshakeResponse::try_ref_from_bytes(response_pkt.as_ref())
            .expect("response_pkt should be a valid handshake response message");
        let Some(mut a_session) =
            a_handshake.finish(response_pkt, &psk, &a_mac_recv, Instant::now())
        else {
            panic!("failed to process handshake response from peer B");
        };

        // They can now communicate
        let a_plaintext = vec![PacketMut::from("xyzzy".as_bytes())];
        let mut packets = a_plaintext.clone();
        a_session.send.encrypt(packets.iter_mut());
        let b_received = b_session.recv.decrypt(packets);
        assert_eq!(b_received, a_plaintext);

        let b_plaintext = vec![PacketMut::from("plover".as_bytes())];
        packets = b_plaintext.clone();
        b_session.send.encrypt(&mut packets);
        let a_received = a_session.recv.decrypt(packets);
        assert_eq!(a_received, b_plaintext);
    }
}
