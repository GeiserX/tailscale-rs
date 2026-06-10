#![no_main]
//! Fuzz target for [`ts_tka::Aum::from_cbor`] — the AUM CBOR decoder (the acquisition-side inverse
//! of `Aum::serialize`).
//!
//! # Why this is its own target
//!
//! The sibling `cbor_decode` target reaches only the *node-key-signature* decode path (via
//! `Authority::node_key_authorized` → `decode_node_key_signature`). `Aum::from_cbor` is a SECOND
//! hand-written CBOR entry point — it drives `decode_value`/`decode_map` plus the
//! `Aum`/`AumKey`/`AumState`/`AumSignature` `from_value` walkers, including the `null` (major-7) and
//! text-keyed-map (`Meta`) arms the signature path never exercises. Those bytes come from the
//! control plane on the Tailnet-Lock sync/bootstrap path — attacker-influenced input — so the decode
//! surface deserves its own randomized coverage.
//!
//! # Invariant under test: panic-free + DoS-safe
//!
//! Decoding arbitrary bytes must NEVER panic, abort, or stack-overflow — it must always return
//! either `Ok(Aum)` (a well-formed AUM; verification happens later and is out of scope here) or
//! `Err(TkaError::Decode(..))`. Concretely:
//!   * No slice-index/overflow panic on malformed heads, truncated strings, or oversized length
//!     prefixes.
//!   * No stack overflow from adversarial nesting: `decode_value` bounds container depth at
//!     `MAX_SIG_NESTING_DEPTH`, shared with the signature path.
//!   * No unbounded allocation: container arms never pre-allocate from an attacker-claimed count.
//!
//! Unlike `cbor_decode` (which asserts `is_err` on an empty-key authority), `Ok` IS a valid outcome
//! here — `from_cbor` is decode-only and reaches no trust decision — so we only assert the absence
//! of a panic. As a cheap extra check, when decoding succeeds we re-serialize and re-decode and
//! require the result to be stable (the canonical-form idempotence the chain replayer relies on).

use libfuzzer_sys::fuzz_target;
use ts_tka::Aum;

fuzz_target!(|data: &[u8]| {
    // Property 1: decoding arbitrary CBOR must never panic / stack-overflow. Both Ok and Err are
    // acceptable (this entry point makes no trust decision).
    if let Ok(aum) = Aum::from_cbor(data) {
        // Property 2 (idempotence): a decoded AUM re-serializes to canonical bytes that decode back
        // to the identical AUM. The chain replayer hashes the re-serialization, so this stability is
        // what makes lenient (non-canonical) decode safe.
        let reser = aum.serialize();
        let again = Aum::from_cbor(&reser)
            .expect("a decoded AUM must re-decode from its own canonical serialization");
        assert!(
            again == aum,
            "decode→serialize→decode must be stable (canonical-form idempotence)"
        );
    }
});
