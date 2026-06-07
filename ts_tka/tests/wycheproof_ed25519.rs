//! Project Wycheproof adversarial KAT for Ed25519 signature verification.
//!
//! SCOPE: this test targets ONLY the STANDARD Ed25519 verifier that `ts_tka`
//! ships as `verify_ed25519_std` — `ed25519-dalek` v2.x, RFC 8032 cofactorless
//! verification, the verifier used for the outer rotation-wrap signature.
//!
//! Project Wycheproof's Ed25519 test set assumes STANDARD RFC-8032 verification,
//! so this is the only verifier it is meaningful to validate against it.
//!
//! The OTHER verifier in `ts_tka`, `verify_ed25519_zip215` (`ed25519-zebra`,
//! ZIP-215 COFACTORED — used for Direct/Credential sigs to match Go
//! `ed25519consensus`), is INTENTIONALLY out of scope here: ZIP-215 is
//! deliberately more lax on cofactored / non-canonical edge cases, so feeding it
//! Wycheproof's standard-verification verdicts would produce false mismatches.
//! That verifier is already covered by `ts_tka`'s
//! `ed25519_speccheck_dual_verifier_kat`.
//!
//! `verify_ed25519_std` is a PRIVATE fn in `ts_tka/src/lib.rs`; an integration
//! test cannot reach it, so we replicate its exact logic below with the same
//! `ed25519-dalek` API. As of this writing `verify_ed25519_std` does:
//!     VerifyingKey::from_bytes(&pk).verify(msg, &Signature::from_bytes(&sig))
//! i.e. plain (non-strict) `verify`. We mirror that EXACTLY — the whole point is
//! to validate the verifier `ts_tka` actually ships. If `verify_ed25519_std` is
//! ever changed to `verify_strict`, change `verify_std` below to match.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use wycheproof::{
    TestResult,
    eddsa::{TestName, TestSet},
};

/// Local replica of `ts_tka`'s private `verify_ed25519_std`. Mirrors it exactly:
/// `VerifyingKey::from_bytes` + plain (non-strict) `verify`.
fn verify_std(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(pk32): Result<[u8; 32], _> = pk.try_into() else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk32) else {
        return false;
    };
    let Ok(sig64): Result<[u8; 64], _> = sig.try_into() else {
        return false;
    };
    let sig = Signature::from_bytes(&sig64);
    vk.verify(msg, &sig).is_ok()
}

#[test]
fn wycheproof_ed25519_standard_verifier_kat() {
    let set = TestSet::load(TestName::Ed25519).expect("load Wycheproof Ed25519 test set");

    let mut valid_count = 0usize;
    let mut invalid_count = 0usize;
    let mut acceptable_count = 0usize;
    let mut total = 0usize;

    for (gi, group) in set.test_groups.iter().enumerate() {
        // `group.key` is an `EddsaPublic`; `group.key.pk` is a `ByteString`
        // which `Deref`s to `Vec<u8>` — the raw 32 public-key bytes.
        let pk: &[u8] = &group.key.pk;

        for t in &group.tests {
            total += 1;
            let accepted = verify_std(pk, &t.msg, &t.sig);

            match t.result {
                TestResult::Valid => {
                    valid_count += 1;
                    assert!(
                        accepted,
                        "Wycheproof Valid vector REJECTED by standard verifier: \
                         group={gi} tc_id={} flags={:?}",
                        t.tc_id, t.flags
                    );
                }
                TestResult::Invalid => {
                    invalid_count += 1;
                    assert!(
                        !accepted,
                        "SECURITY: Wycheproof INVALID vector ACCEPTED by standard verifier \
                         (signature malleability / forgery acceptance): \
                         group={gi} tc_id={} flags={:?}",
                        t.tc_id, t.flags
                    );
                }
                TestResult::Acceptable => {
                    // Ed25519 has no Acceptable vectors; count defensively.
                    acceptable_count += 1;
                }
            }
        }
    }

    println!(
        "Wycheproof Ed25519 (standard verifier, ed25519-dalek v2): \
         total={total} valid={valid_count} invalid={invalid_count} acceptable={acceptable_count}"
    );

    assert_eq!(
        acceptable_count, 0,
        "unexpected Acceptable vectors in Ed25519 set"
    );
    assert!(
        total > 100,
        "ran too few Wycheproof vectors ({total}) — silent skip?"
    );
    assert_eq!(
        total,
        valid_count + invalid_count,
        "vector accounting mismatch"
    );
}
