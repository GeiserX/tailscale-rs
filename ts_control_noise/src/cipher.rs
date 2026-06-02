use noise_protocol::Cipher;
use noise_rust_crypto::sensitive::Sensitive;

// TODO (dylan): replace this impl with our own WireGuard-based NoiseIK impl, remove noise-protocol
// and noise-rust-crypto crates
/// Temporary forked implementation of [`noise_rust_crypto::ChaCha20Poly1305`] to handle the big-
/// endian nonces used in the TS2021 control protocol. Will be replaced with the same crypto
/// used for our WireGuard implementation once we create a NoiseIK handshake using its primitives.
pub enum ChaCha20Poly1305BigEndian {}

/// NOTE: This is a copy/paste of the [`Cipher`] impl in [`noise_rust_crypto::ChaCha20Poly1305`],
/// with 4 chars changed; the four instances of `nonce.to_le_bytes()` in the original impl were
/// replaced with `nonce.to_be_bytes()` below. That's it.
impl Cipher for ChaCha20Poly1305BigEndian {
    fn name() -> &'static str {
        "ChaChaPoly"
    }

    type Key = Sensitive<[u8; 32]>;

    fn encrypt(k: &Self::Key, nonce: u64, ad: &[u8], plaintext: &[u8], out: &mut [u8]) {
        assert!(plaintext.len().checked_add(16) == Some(out.len()));

        let mut full_nonce = [0u8; 12];
        full_nonce[4..].copy_from_slice(&nonce.to_be_bytes());

        let (in_out, tag_out) = out.split_at_mut(plaintext.len());
        in_out.copy_from_slice(plaintext);

        use chacha20poly1305::{AeadInPlace, KeyInit};
        let tag = chacha20poly1305::ChaCha20Poly1305::new(&(**k).into())
            .encrypt_in_place_detached(&full_nonce.into(), ad, in_out)
            .unwrap();

        tag_out.copy_from_slice(tag.as_ref())
    }

    #[allow(clippy::unnecessary_map_or)]
    fn encrypt_in_place(
        k: &Self::Key,
        nonce: u64,
        ad: &[u8],
        in_out: &mut [u8],
        plaintext_len: usize,
    ) -> usize {
        assert!(
            plaintext_len
                .checked_add(16)
                .map_or(false, |l| l <= in_out.len())
        );

        let mut full_nonce = [0u8; 12];
        full_nonce[4..].copy_from_slice(&nonce.to_be_bytes());

        let (in_out, tag_out) = in_out[..plaintext_len + 16].split_at_mut(plaintext_len);

        use chacha20poly1305::{AeadInPlace, KeyInit};
        let tag = chacha20poly1305::ChaCha20Poly1305::new(&(**k).into())
            .encrypt_in_place_detached(&full_nonce.into(), ad, in_out)
            .unwrap();
        tag_out.copy_from_slice(tag.as_ref());

        plaintext_len + 16
    }

    fn decrypt(
        k: &Self::Key,
        nonce: u64,
        ad: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<(), ()> {
        assert!(ciphertext.len().checked_sub(16) == Some(out.len()));

        let mut full_nonce = [0u8; 12];
        full_nonce[4..].copy_from_slice(&nonce.to_be_bytes());

        out.copy_from_slice(&ciphertext[..out.len()]);
        let tag = &ciphertext[out.len()..];

        use chacha20poly1305::{AeadInPlace, KeyInit};
        chacha20poly1305::ChaCha20Poly1305::new(&(**k).into())
            .decrypt_in_place_detached(&full_nonce.into(), ad, out, tag.into())
            .map_err(|_| ())
    }

    fn decrypt_in_place(
        k: &Self::Key,
        nonce: u64,
        ad: &[u8],
        in_out: &mut [u8],
        ciphertext_len: usize,
    ) -> Result<usize, ()> {
        assert!(ciphertext_len <= in_out.len());
        assert!(ciphertext_len >= 16);

        let mut full_nonce = [0u8; 12];
        full_nonce[4..].copy_from_slice(&nonce.to_be_bytes());

        let (in_out, tag) = in_out[..ciphertext_len].split_at_mut(ciphertext_len - 16);

        use chacha20poly1305::{AeadInPlace, KeyInit};
        chacha20poly1305::ChaCha20Poly1305::new(&(**k).into())
            .decrypt_in_place_detached(&full_nonce.into(), ad, in_out, tag.as_ref().into())
            .map_err(|_| ())?;

        Ok(in_out.len())
    }
}
