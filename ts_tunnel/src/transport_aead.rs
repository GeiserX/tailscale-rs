//! Transport-data AEAD only; handshake/cookie constructions remain RustCrypto.
//!
//! Nonce allocation and replay protection belong to `session`. Neither backend's packet operations
//! copy the packet body or allocate here (appending the tag may grow PacketMut,
//! exactly as RustCrypto's existing AeadInPlace implementation did).

#[cfg(not(feature = "ring-aead"))]
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::AeadInPlace};
#[cfg(feature = "ring-aead")]
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use ts_packet::PacketMut;
#[cfg(feature = "ring-aead")]
use zeroize::Zeroize;
use zeroize::Zeroizing;

pub(crate) struct TransportCipher {
    #[cfg(feature = "ring-aead")]
    // ring's algorithm-erased key reserves space for AES schedules too. Box it
    // once at session creation to keep the peer state small; never per packet.
    cipher: Box<LessSafeKey>,
    #[cfg(not(feature = "ring-aead"))]
    cipher: ChaCha20Poly1305,
}

impl TransportCipher {
    pub(crate) fn new(key: chacha20poly1305::Key) -> Self {
        // Keep the construction input wiped even if key setup ever panics. Do
        // not retain another raw key alongside ring's opaque internal key.
        let raw = Zeroizing::new(key);
        #[cfg(feature = "ring-aead")]
        let cipher = Box::new(LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, raw.as_ref())
                .expect("fixed-size ChaCha20-Poly1305 key"),
        ));
        #[cfg(not(feature = "ring-aead"))]
        let cipher = ChaCha20Poly1305::new_from_slice(raw.as_ref())
            .expect("fixed-size ChaCha20-Poly1305 key");
        Self { cipher }
    }

    pub(crate) fn seal(&self, nonce: [u8; 12], packet: &mut PacketMut) -> aead::Result<()> {
        #[cfg(feature = "ring-aead")]
        {
            // The session atomically reserves counters before encrypting. This
            // API supplies that explicit nonce without adding mutable key state.
            let tag = self
                .cipher
                .seal_in_place_separate_tag(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::empty(),
                    packet.as_mut(),
                )
                .map_err(|_| aead::Error)?;
            packet.extend_from_slice(tag.as_ref());
            Ok(())
        }
        #[cfg(not(feature = "ring-aead"))]
        self.cipher.encrypt_in_place((&nonce).into(), &[], packet)
    }

    pub(crate) fn open(&self, nonce: [u8; 12], packet: &mut PacketMut) -> aead::Result<()> {
        #[cfg(feature = "ring-aead")]
        {
            // WireGuard already stores ciphertext||tag contiguously. Borrow it
            // directly; truncate only after authenticated plaintext is returned.
            let len = self
                .cipher
                .open_in_place(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::empty(),
                    packet.as_mut(),
                )
                .map(|plaintext| plaintext.len())
                .map_err(|_| aead::Error);
            match len {
                Ok(len) => {
                    packet.truncate(len);
                    Ok(())
                }
                Err(e) => {
                    // ring normally wipes candidate plaintext on tag failure.
                    // Cover every error path explicitly, including short input.
                    packet.as_mut().zeroize();
                    Err(e)
                }
            }
        }
        #[cfg(not(feature = "ring-aead"))]
        self.cipher.decrypt_in_place((&nonce).into(), &[], packet)
    }
}
