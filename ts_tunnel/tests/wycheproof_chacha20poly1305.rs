//! Project Wycheproof (github.com/C2SP/wycheproof) adversarial KAT for
//! ChaCha20Poly1305, via the wycheproof crate v0.6.0. Validates the
//! chacha20poly1305 v0.10.1 primitive ts_tunnel uses for WireGuard transport
//! AEAD. Only the 96-bit-nonce groups are exercised (RustCrypto's
//! ChaCha20Poly1305 is fixed-12-byte-nonce); other nonce widths belong to the
//! XChaCha API we don't use.

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{AeadInPlace, Nonce, Tag},
};
use wycheproof::{
    TestResult,
    aead::{TestName, TestSet},
};

#[test]
fn wycheproof_chacha20poly1305_adversarial_kat() {
    let set = TestSet::load(TestName::ChaCha20Poly1305).expect("load Wycheproof ChaCha20Poly1305");

    let mut ran = 0usize;
    let mut skipped_groups = 0usize;
    let mut acceptable_skipped = 0usize;

    for group in &set.test_groups {
        // RustCrypto ChaCha20Poly1305 is a fixed 96-bit nonce, 256-bit key,
        // 128-bit tag construction. Every other nonce width belongs to the
        // XChaCha/variable-nonce API ts_tunnel does not use.
        if group.nonce_size != 96 {
            skipped_groups += group.tests.len();
            continue;
        }

        assert_eq!(
            group.key_size, 256,
            "96-bit-nonce group must use a 256-bit key"
        );
        assert_eq!(
            group.tag_size, 128,
            "96-bit-nonce group must use a 128-bit tag"
        );

        let cipher = |key: &[u8]| {
            ChaCha20Poly1305::new_from_slice(key).expect("ChaCha20Poly1305 key (32 bytes)")
        };

        for t in &group.tests {
            let nonce = Nonce::<ChaCha20Poly1305>::from_slice(&t.nonce);
            let aead = cipher(&t.key);

            // --- Encryption check (seal pt, compare against expected ct||tag). ---
            // Skip sealing on Invalid vectors: those carry a forged/tampered
            // ct/tag/nonce, so the produced output is not expected to match.
            match t.result {
                TestResult::Valid => {
                    let mut buffer = t.pt.to_vec();
                    let produced_tag = aead
                        .encrypt_in_place_detached(nonce, &t.aad, &mut buffer)
                        .unwrap_or_else(|e| {
                            panic!("tc {} {:?}: encrypt failed: {e}", t.tc_id, t.flags)
                        });
                    assert_eq!(
                        buffer.as_slice(),
                        t.ct.as_slice(),
                        "tc {} {:?}: ciphertext mismatch",
                        t.tc_id,
                        t.flags
                    );
                    assert_eq!(
                        produced_tag.as_slice(),
                        t.tag.as_slice(),
                        "tc {} {:?}: tag mismatch",
                        t.tc_id,
                        t.flags
                    );
                }
                TestResult::Acceptable => {
                    // No Acceptable cases are expected for ChaCha20Poly1305. If
                    // one appears, surface it by counting rather than risking a
                    // flaky strict/lenient assertion.
                    acceptable_skipped += 1;
                }
                TestResult::Invalid => {}
            }

            // --- Decryption / verification check. ---
            let mut ct_buf = t.ct.to_vec();
            let tag = Tag::<ChaCha20Poly1305>::from_slice(&t.tag);
            let opened = aead.decrypt_in_place_detached(nonce, &t.aad, &mut ct_buf, tag);

            match t.result {
                TestResult::Valid => {
                    opened.unwrap_or_else(|e| {
                        panic!(
                            "tc {} {:?}: valid vector failed to open: {e}",
                            t.tc_id, t.flags
                        )
                    });
                    assert_eq!(
                        ct_buf.as_slice(),
                        t.pt.as_slice(),
                        "tc {} {:?}: decrypted plaintext mismatch",
                        t.tc_id,
                        t.flags
                    );
                }
                TestResult::Invalid => {
                    assert!(
                        opened.is_err(),
                        "tc {} {:?}: CRITICAL auth-bypass — invalid vector decrypted successfully",
                        t.tc_id,
                        t.flags
                    );
                }
                TestResult::Acceptable => {}
            }

            ran += 1;
        }
    }

    println!(
        "wycheproof ChaCha20Poly1305: ran {ran} test(s) across 96-bit-nonce groups, \
         skipped {skipped_groups} test(s) in non-96-bit-nonce groups, \
         {acceptable_skipped} Acceptable result(s) counted (encryption not asserted)"
    );

    // Guard against a future API change that silently skips everything: the
    // 96-bit-nonce group carries ~316 vectors.
    assert!(
        ran >= 300,
        "expected to run >=300 ChaCha20Poly1305 vectors, only ran {ran} — \
         did the 96-bit-nonce group disappear or get skipped?"
    );
}
