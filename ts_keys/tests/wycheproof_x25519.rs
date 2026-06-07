//! Project Wycheproof (github.com/C2SP/wycheproof) adversarial KAT for X25519 ECDH, via the
//! wycheproof crate v0.6.0. Validates the x25519-dalek v3.0.0-pre.6 primitive used for
//! WireGuard/Noise DH. X25519 has no Invalid vectors; the Acceptable set is the adversarial
//! low-order/non-canonical/twist battery — dalek is non-contributory (RFC 7748) and computes
//! (rather than rejects) these, so we assert the computed shared secret matches Wycheproof's
//! expected bytes.

use wycheproof::{
    TestResult,
    xdh::{TestName, TestSet},
};
use x25519_dalek::x25519;

/// Coerce a Wycheproof `Vec<u8>` field (always 32 bytes for X25519) into a fixed `[u8; 32]`.
fn arr32(v: &[u8], tc_id: usize, field: &str) -> [u8; 32] {
    v.try_into()
        .unwrap_or_else(|_| panic!("tc {tc_id}: {field} not 32 bytes (got {})", v.len()))
}

#[test]
fn wycheproof_x25519_full_set() {
    let set = TestSet::load(TestName::X25519).expect("load Wycheproof X25519 set");

    let mut valid = 0usize;
    let mut acceptable = 0usize;
    let mut total = 0usize;
    // Acceptable adversarial vectors where dalek's computed secret diverges from Wycheproof's
    // listed bytes. Expected to be empty for the non-contributory dalek primitive.
    let mut mismatches: Vec<String> = Vec::new();

    for group in &set.test_groups {
        for t in &group.tests {
            total += 1;
            let priv_k = arr32(&t.private_key, t.tc_id, "private_key");
            let pub_k = arr32(&t.public_key, t.tc_id, "public_key");
            let want = arr32(&t.shared_secret, t.tc_id, "shared_secret");

            // dalek's free x25519() clamps the scalar internally and always returns a value
            // (it never errors), matching the RFC 7748 non-contributory contract.
            let got = x25519(priv_k, pub_k);

            match t.result {
                // Core correctness: a Valid vector MUST reproduce the listed shared secret.
                TestResult::Valid => {
                    valid += 1;
                    assert_eq!(
                        got, want,
                        "tc {} (flags {:?}): Valid shared-secret mismatch\n  got:  {:02x?}\n  want: {:02x?}",
                        t.tc_id, t.flags, got, want
                    );
                }
                // Adversarial edge cases (low-order/non-canonical/twist/zero-shared). dalek is
                // non-contributory and computes these; assert against the expected bytes, but
                // collect any divergence so the reviewer sees exactly which cases differ.
                TestResult::Acceptable => {
                    acceptable += 1;
                    if got != want {
                        mismatches.push(format!(
                            "tc {} (flags {:?}): got {:02x?} want {:02x?}",
                            t.tc_id, t.flags, got, want
                        ));
                    }
                }
                // X25519 has no Invalid vectors; guard against a future schema change.
                TestResult::Invalid => panic!(
                    "tc {} (flags {:?}): unexpected Invalid result in X25519 set",
                    t.tc_id, t.flags
                ),
            }
        }
    }

    if !mismatches.is_empty() {
        for m in &mismatches {
            eprintln!("ACCEPTABLE MISMATCH: {m}");
        }
        panic!(
            "{} Acceptable adversarial vector(s) diverged from Wycheproof's expected bytes \
             (see ACCEPTABLE MISMATCH lines above); dalek pre.6 should match all of them",
            mismatches.len()
        );
    }

    println!(
        "Wycheproof X25519: ran {total} tests ({valid} Valid, {acceptable} Acceptable), \
         0 mismatches"
    );

    // No silent skips: every test in the set was handled by one of the match arms above.
    assert_eq!(
        valid + acceptable,
        total,
        "every test must be Valid or Acceptable; counts diverged"
    );
    assert!(
        total > 500,
        "expected the full X25519 battery (>500 vectors), only ran {total}"
    );
}
