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

#[cfg(test)]
mod tests {
    use noise_protocol::Cipher;
    use noise_rust_crypto::sensitive::Sensitive;

    use super::ChaCha20Poly1305BigEndian;

    type C = ChaCha20Poly1305BigEndian;

    fn key(bytes: [u8; 32]) -> Sensitive<[u8; 32]> {
        Sensitive::from(bytes.into())
    }

    /// encrypt → decrypt round-trips to the original plaintext, with associated data preserved.
    #[test]
    fn encrypt_decrypt_round_trip() {
        let k = key([0x42u8; 32]);
        let nonce = 7u64;
        let ad = b"associated-data";
        let plaintext = b"the quick brown fox jumps over the lazy dog";

        let mut ct = alloc_zeroed(plaintext.len() + 16);
        C::encrypt(&k, nonce, ad, plaintext, &mut ct);

        let mut pt = alloc_zeroed(plaintext.len());
        C::decrypt(&key([0x42u8; 32]), nonce, ad, &ct, &mut pt).expect("decrypt must succeed");
        assert_eq!(&pt, plaintext);
    }

    /// A tampered ciphertext body fails authentication (the AEAD tag no longer matches).
    #[test]
    fn tampered_ciphertext_fails_auth() {
        let k = key([0x11u8; 32]);
        let nonce = 3u64;
        let ad = b"ad";
        let plaintext = b"secret payload";

        let mut ct = alloc_zeroed(plaintext.len() + 16);
        C::encrypt(&k, nonce, ad, plaintext, &mut ct);
        ct[0] ^= 0xff; // flip a ciphertext byte

        let mut pt = alloc_zeroed(plaintext.len());
        assert!(
            C::decrypt(&key([0x11u8; 32]), nonce, ad, &ct, &mut pt).is_err(),
            "tampered ciphertext must not authenticate"
        );
    }

    /// A tampered Poly1305 tag fails authentication.
    #[test]
    fn tampered_tag_fails_auth() {
        let k = key([0x22u8; 32]);
        let nonce = 9u64;
        let ad = b"ad";
        let plaintext = b"secret payload";

        let mut ct = alloc_zeroed(plaintext.len() + 16);
        C::encrypt(&k, nonce, ad, plaintext, &mut ct);
        let last = ct.len() - 1;
        ct[last] ^= 0x01; // flip a tag byte

        let mut pt = alloc_zeroed(plaintext.len());
        assert!(
            C::decrypt(&key([0x22u8; 32]), nonce, ad, &ct, &mut pt).is_err(),
            "tampered tag must not authenticate"
        );
    }

    /// Tampered associated data fails authentication (the AD is authenticated, not encrypted).
    #[test]
    fn tampered_ad_fails_auth() {
        let k = key([0x33u8; 32]);
        let nonce = 1u64;
        let plaintext = b"secret payload";

        let mut ct = alloc_zeroed(plaintext.len() + 16);
        C::encrypt(&k, nonce, b"original-ad", plaintext, &mut ct);

        let mut pt = alloc_zeroed(plaintext.len());
        assert!(
            C::decrypt(&key([0x33u8; 32]), nonce, b"tampered-ad", &ct, &mut pt).is_err(),
            "decrypt with different AD must not authenticate"
        );
    }

    /// `encrypt_in_place` / `decrypt_in_place` round-trip and agree with the detached API.
    #[test]
    fn in_place_round_trip_matches_detached() {
        let k = key([0x55u8; 32]);
        let nonce = 0xdead_beefu64;
        let ad = b"some-ad";
        let plaintext = b"hello in-place world";

        // Detached encryption for the reference ciphertext+tag.
        let mut reference = alloc_zeroed(plaintext.len() + 16);
        C::encrypt(&k, nonce, ad, plaintext, &mut reference);

        // In-place encryption into a buffer with room for the 16-byte tag.
        let mut buf = alloc_zeroed(plaintext.len() + 16);
        buf[..plaintext.len()].copy_from_slice(plaintext);
        let written = C::encrypt_in_place(&key([0x55u8; 32]), nonce, ad, &mut buf, plaintext.len());
        assert_eq!(written, plaintext.len() + 16);
        assert_eq!(
            buf, reference,
            "in-place must equal detached ciphertext+tag"
        );

        // In-place decryption recovers the plaintext.
        let n = C::decrypt_in_place(&key([0x55u8; 32]), nonce, ad, &mut buf, written)
            .expect("decrypt_in_place must succeed");
        assert_eq!(n, plaintext.len());
        assert_eq!(&buf[..n], plaintext);
    }

    /// The nonce is BIG-endian: the 12-byte AEAD nonce a `u64` counter produces is
    /// `[0,0,0,0] || counter.to_be_bytes()`. We prove this WITHOUT reaching into the private
    /// nonce-construction: encrypt under counter=1 (big-endian), then decrypt the same ciphertext
    /// against the stock RustCrypto `ChaCha20Poly1305` using a hand-built BIG-endian nonce. If the
    /// fork ever reverts to little-endian (`to_le_bytes`), the nonce would be
    /// `[0,0,0,0] || 0x0100000000000000`, this decryption would FAIL, and the test would catch the
    /// regression.
    #[test]
    fn nonce_is_big_endian() {
        use chacha20poly1305::{AeadInPlace, KeyInit};

        let key_bytes = [0x77u8; 32];
        let counter = 1u64;
        let ad = b"endianness-ad";
        let plaintext = b"prove the nonce byte order";

        // Ciphertext produced by the fork under test (big-endian nonce).
        let mut ct = alloc_zeroed(plaintext.len() + 16);
        C::encrypt(&key(key_bytes), counter, ad, plaintext, &mut ct);

        // Independently rebuild the expected BIG-endian 12-byte nonce: 4 zero bytes then be(counter).
        let mut be_nonce = [0u8; 12];
        be_nonce[4..].copy_from_slice(&counter.to_be_bytes());
        assert_eq!(
            be_nonce,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            "counter=1 big-endian nonce must end in 0x01"
        );

        // Decrypt the fork's ciphertext with the stock cipher driven by the BIG-endian nonce.
        let (body, tag) = ct.split_at(plaintext.len());
        let mut decrypted = body.to_vec();
        chacha20poly1305::ChaCha20Poly1305::new(&key_bytes.into())
            .decrypt_in_place_detached(&be_nonce.into(), ad, &mut decrypted, tag.into())
            .expect("stock cipher with big-endian nonce must decrypt the fork's output");
        assert_eq!(&decrypted, plaintext);

        // Sanity: the WRONG (little-endian) nonce must NOT decrypt it — this is exactly what a
        // `to_be_bytes` -> `to_le_bytes` revert would produce, and it must fail.
        let mut le_nonce = [0u8; 12];
        le_nonce[4..].copy_from_slice(&counter.to_le_bytes());
        let mut decrypted_le = body.to_vec();
        assert!(
            chacha20poly1305::ChaCha20Poly1305::new(&key_bytes.into())
                .decrypt_in_place_detached(&le_nonce.into(), ad, &mut decrypted_le, tag.into())
                .is_err(),
            "little-endian nonce must NOT decrypt a big-endian-encrypted message"
        );
    }

    /// FROZEN regression vector (endianness / nonce-construction / dependency freeze).
    ///
    /// The RFC 8439 §2.8.2 known-answer test is NOT directly applicable here: its 96-bit nonce is
    /// `07 00 00 00 40 41 42 43 44 45 46 47`, whose leading bytes are non-zero, but this big-endian
    /// variant constructs the 12-byte nonce as `[0,0,0,0] || u64::to_be_bytes(counter)` — the first
    /// four bytes are ALWAYS zero, so no `u64` counter can reproduce the RFC nonce. We therefore
    /// freeze a fixed (key, counter, ad, plaintext) -> (ciphertext, tag) self-vector captured from
    /// the CURRENT implementation. ANY future change to the byte order, the nonce construction, or
    /// the underlying `chacha20poly1305` dependency that alters the wire output will break this.
    ///
    /// NOTE: this is a regression-FREEZE vector, not a cross-implementation KAT. It should be
    /// replaced with a real Go-`tsnet`-captured cross-vector (same key/nonce/ad/plaintext encrypted
    /// by Go's TS2021 control AEAD) once one can be sourced from a live Go process.
    #[test]
    fn frozen_self_vector() {
        let key_bytes = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let counter = 0x0102_0304_0506_0708u64;
        let ad: &[u8] = b"ts2021";
        let plaintext: &[u8] = b"frozen vector plaintext";

        // Expected ciphertext+tag, captured once from this implementation and pinned. If this
        // assertion ever fails, the wire format changed — investigate before updating the constant.
        const EXPECTED: &[u8] = &[
            0x89, 0x94, 0xca, 0x82, 0xc0, 0xe2, 0x88, 0xea, 0x75, 0xdc, 0x9c, 0xb9, 0xf8, 0xcc,
            0x57, 0x32, 0xf4, 0xe5, 0x0a, 0x25, 0x79, 0x35, 0x5c, 0x1d, 0x60, 0xe2, 0x34, 0x28,
            0x2e, 0xd6, 0x0c, 0xf3, 0x3f, 0x15, 0x63, 0xad, 0xeb, 0x85, 0xe1,
        ];

        let mut ct = alloc_zeroed(plaintext.len() + 16);
        C::encrypt(&key(key_bytes), counter, ad, plaintext, &mut ct);
        assert_eq!(
            ct.len(),
            EXPECTED.len(),
            "captured vector length must match plaintext+16"
        );
        assert_eq!(
            ct,
            EXPECTED,
            "frozen self-vector mismatch: the AEAD wire output changed (endianness / nonce \
             construction / chacha20poly1305 dep). hex of actual output: {}",
            hex(&ct)
        );

        // And it round-trips back.
        let mut pt = alloc_zeroed(plaintext.len());
        C::decrypt(&key(key_bytes), counter, ad, &ct, &mut pt).expect("frozen vector must decrypt");
        assert_eq!(&pt, plaintext);
    }

    /// Cross-implementation Known-Answer-Test against real Go ciphertext.
    ///
    /// Vectors generated with Go `golang.org/x/crypto/chacha20poly1305` v0.52.0, go1.26.4;
    /// generator `tests/vectors/gen/aead`. Proves the big-endian transport nonce matches Go
    /// `control/controlbase` (which does `binary.BigEndian.PutUint64(nonce[4:], counter)`).
    #[test]
    fn be_aead_matches_go_kat() {
        fn unhex(s: &str) -> Vec<u8> {
            assert!(
                s.len().is_multiple_of(2),
                "hex string must have even length"
            );
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
                .collect()
        }

        struct Vector {
            key: &'static str,
            counter: u64,
            ad: &'static str,
            pt: &'static str,
            ct: &'static str,
        }

        let vectors = [
            Vector {
                key: "4242424242424242424242424242424242424242424242424242424242424242",
                counter: 7,
                ad: "0102030405060708",
                pt: "68656c6c6f20776972654b4154",
                ct: "7b0294364fe1db3a5103032cdafb17a16a78348e953af8d63604bc1c13",
            },
            Vector {
                key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                counter: 0,
                ad: "",
                pt: "",
                ct: "10324f800a160bd9a1794255be7ec29d",
            },
            Vector {
                key: "ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00",
                counter: 0xdead_beef_cafe_1234,
                ad: "74732d636f6e74726f6c",
                pt: "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e",
                ct: "e900e29d1fef158b66dd67d574e1d2a33f6b4fa944df63796cf805a59773b5f460000021305cf53b6c18ab89f504bb83b8843a277346639e9e6c51ef",
            },
        ];

        for (i, v) in vectors.iter().enumerate() {
            let key_bytes: [u8; 32] = unhex(v.key).try_into().expect("32-byte key");
            let ad = unhex(v.ad);
            let pt = unhex(v.pt);
            let expected_ct = unhex(v.ct);

            // Byte-exact Go-interop assertion: our ciphertext+tag must equal Go's bytes.
            let mut out = alloc_zeroed(pt.len() + 16);
            C::encrypt(&key(key_bytes), v.counter, &ad, &pt, &mut out);
            assert_eq!(
                out,
                expected_ct,
                "vector {i}: ciphertext must match Go output. actual: {}",
                hex(&out)
            );

            // Round-trip: decrypt Go's ciphertext back to the plaintext.
            let mut recovered = alloc_zeroed(pt.len());
            C::decrypt(
                &key(key_bytes),
                v.counter,
                &ad,
                &expected_ct,
                &mut recovered,
            )
            .expect("Go ciphertext must decrypt");
            assert_eq!(recovered, pt, "vector {i}: round-trip plaintext mismatch");
        }
    }

    fn alloc_zeroed(len: usize) -> Vec<u8> {
        vec![0u8; len]
    }

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::new();
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}
