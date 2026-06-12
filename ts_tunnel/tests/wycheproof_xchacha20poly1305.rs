//! Project Wycheproof (github.com/C2SP/wycheproof) adversarial KAT for
//! XChaCha20Poly1305, via the wycheproof crate v0.6.0. Validates the
//! `chacha20poly1305::XChaCha20Poly1305` (192-bit nonce) primitive `ts_tunnel`
//! uses in exactly one place: the WireGuard cookie-reply decrypt
//! (`MACSender::receive_cookie`, `src/macs.rs` — `XChaCha20Poly1305::new(mac2_key)`
//! then `decrypt(nonce_24, Payload { msg: cookie_sealed, aad: handshake_mac })`).
//!
//! The sibling `wycheproof_chacha20poly1305.rs` covers ONLY the 96-bit-nonce
//! (transport-AEAD) construction and explicitly skips every other nonce width as
//! "the XChaCha API we don't use" — but the cookie path DOES use XChaCha
//! (24-byte nonce), so that construction was un-cross-validated. This KAT closes
//! that gap: the cookie-reply decrypt is receive-only (this node never issues
//! cookies), so a divergence would break handshakes specifically against an
//! under-load Go responder that sends a `CookieReply`. The adversarial-Invalid
//! groups also guard the auth path: a tampered cookie envelope MUST fail to open
//! (a "decrypt that ignores the tag" would be a silent auth-bypass on the cookie).
//!
//! Only the 192-bit-nonce groups are exercised (XChaCha20Poly1305 is fixed-24-byte
//! nonce, 256-bit key, 128-bit tag) — any other width would belong to a different
//! construction. Mirrors the ChaCha20Poly1305 KAT structure exactly.

use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, Tag},
};
use wycheproof::{
    TestResult,
    aead::{TestName, TestSet},
};

#[test]
fn wycheproof_xchacha20poly1305_adversarial_kat() {
    let set =
        TestSet::load(TestName::XChaCha20Poly1305).expect("load Wycheproof XChaCha20Poly1305");

    let mut ran = 0usize;
    let mut skipped_groups = 0usize;
    let mut acceptable_skipped = 0usize;

    for group in &set.test_groups {
        // XChaCha20Poly1305 is a fixed 192-bit nonce, 256-bit key, 128-bit tag
        // construction (the cookie-reply path). Skip any other nonce width.
        if group.nonce_size != 192 {
            skipped_groups += group.tests.len();
            continue;
        }

        assert_eq!(
            group.key_size, 256,
            "192-bit-nonce group must use a 256-bit key"
        );
        assert_eq!(
            group.tag_size, 128,
            "192-bit-nonce group must use a 128-bit tag"
        );

        let cipher = |key: &[u8]| {
            XChaCha20Poly1305::new_from_slice(key).expect("XChaCha20Poly1305 key (32 bytes)")
        };

        for t in &group.tests {
            let nonce = XNonce::from_slice(&t.nonce);
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
                    // No Acceptable cases are expected for XChaCha20Poly1305. If
                    // one appears, surface it by counting rather than risking a
                    // flaky strict/lenient assertion.
                    acceptable_skipped += 1;
                }
                TestResult::Invalid => {}
            }

            // --- Decryption / verification check. ---
            let mut ct_buf = t.ct.to_vec();
            let tag = Tag::<XChaCha20Poly1305>::from_slice(&t.tag);
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
        "wycheproof XChaCha20Poly1305: ran {ran} test(s) across 192-bit-nonce groups, \
         skipped {skipped_groups} test(s) in other-nonce-width groups, \
         {acceptable_skipped} Acceptable result(s) counted (encryption not asserted)"
    );

    // Guard against a future API change that silently skips everything: the
    // XChaCha20Poly1305 set carries well over 100 vectors.
    assert!(
        ran >= 100,
        "expected to run >=100 XChaCha20Poly1305 vectors, only ran {ran} — \
         did the 192-bit-nonce group disappear or get skipped?"
    );
}
