//! Constant-time leakage *detection* for the WireGuard transport AEAD path.
//!
//! This is a [dudect](https://eprint.iacr.org/2016/1123) t-test harness (Reparaz, Balasch &
//! Verbauwhede, 2016). The statistics live in the in-tree `dudect` module
//! (`benches/dudect/mod.rs`), vendored from the `dudect-bencher` crate — that module records why.
//! dudect is a *leakage detector*, not a prover:
//! it times an operation across two input distributions (`Class::Left` / `Class::Right`) and runs
//! Welch's t-test on the timing samples. A large `max_t` is statistical evidence that the two
//! distributions take measurably different time — i.e. a likely timing side-channel. The
//! conventional threshold used in this repo is **`|max_t| > 5` ⇒ likely leak** (the sign only says
//! which class was slower, so the test is on the magnitude). Crucially, a *small*
//! `max_t` does **not** prove the code is constant-time — dudect can DETECT a leak but can never
//! PROVE its absence. See `docs/CRYPTOGRAPHY.md` §7 ("Constant-time and side-channels").
//!
//! Run (release mode is mandatory — the constant-time properties only hold in optimized builds, and
//! debug-build timing noise swamps the signal):
//!
//! ```text
//! cargo bench -p geiserx_ts_tunnel --bench constant_time
//! ```
//!
//! Each run draws a fresh seed and prints it; set `DUDECT_SEED=0x…` to replay an interesting one.
//!
//! Every run opens with a self-check that feeds the detector two synthetic distributions, one clean
//! and one carrying a deliberate 20ns leak, and aborts if it cannot tell them apart.
//!
//! This bench is **informational only**. It is NOT wired into the default CI/test gate: a flaky
//! `max_t` on a noisy shared runner must never fail the build. Run it on demand on a quiet machine
//! when auditing the AEAD-verify path.
//!
//! # Operations benched
//!
//! - **`aead_decrypt_tag_verify`** — the ChaCha20Poly1305 AEAD tag verification that backs
//!   [`ts_tunnel`]'s `ReceiveSession::decrypt` / `decrypt_one` (`src/session.rs`). The session
//!   ultimately calls `ChaCha20Poly1305::decrypt_in_place`, which authenticates the Poly1305 tag
//!   before returning. We bench that primitive directly via `decrypt_in_place_detached` rather than
//!   driving a full `ReceiveSession`: constructing a `ReceiveSession` and feeding it a frame would
//!   also exercise the framed-header parse, the per-session receiver-id check, and the replay
//!   window — none of which are the crypto we want to scope, and the replay window mutates across
//!   iterations. A bare `ChaCha20Poly1305` built from a fixed key with the *same* AEAD call
//!   isolates exactly the tag-verification primitive the session relies on (RustCrypto's AEAD
//!   compares the Poly1305 tag in constant time). `Class::Left` verifies a frame with a VALID tag
//!   (auth succeeds); `Class::Right` verifies a frame whose tag is corrupted in the first byte
//!   (auth fails). A constant-time verifier rejects the bad tag in the same time it accepts the
//!   good one, so we expect a small `max_t`.
//!
//!   **Why the payload is empty.** The bench uses a zero-length message on purpose. The security
//!   property under test is the *tag comparison* — that an attacker cannot forge the Poly1305 tag a
//!   byte at a time by observing how long verification takes. ChaCha20Poly1305 first computes the
//!   Poly1305 MAC and compares it to the supplied tag in constant time, and *only on success* runs
//!   the ChaCha20 keystream to decrypt the body. With a non-empty payload, `Class::Left` (valid
//!   tag) would therefore additionally run the keystream over the whole buffer while `Class::Right`
//!   (invalid tag) would short-circuit before it — a large, *legitimate* timing difference that
//!   reveals only accept-vs-reject, which the caller already learns from the boolean result and
//!   which leaks nothing extra about the key or tag. An empty message removes that confound so the
//!   measurement isolates the constant-time tag compare itself, which is the part that must not
//!   leak. (Set `PT_LEN` > 0 to observe the legitimate accept/reject keystream gap instead.)
//!
//! ## Note on the cert-pinning constant-time compare
//!
//! `ts_tls_util/src/pinned.rs:99` performs the SHA-256 cert-pin compare with
//! `subtle::ConstantTimeEq` (`a.ct_eq(&b)`). That `subtle` compare deserves its own dudect bench,
//! but `subtle` is only a *transitive* dependency of `ts_tunnel` (pulled in under
//! `chacha20poly1305`/`aes-gcm`) and is not directly nameable here without adding it to
//! `ts_tunnel`'s `Cargo.toml` — which is intentionally out of scope for this file. The cert-pin
//! constant-time bench therefore belongs alongside `ts_tls_util`, where `subtle` is a direct
//! dependency. This file scopes the AEAD-verify path only.

use std::cell::RefCell;

use aead::{AeadCore, AeadInPlace, KeyInit, generic_array::typenum::Unsigned};
use chacha20poly1305::ChaCha20Poly1305;
use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};

mod dudect;

use dudect::{Class, CtRunner};

/// RNG handed to the bench function.
type BenchRng = StdRng;

/// Environment variable that pins the [`BenchRng`] seed, e.g. `DUDECT_SEED=0xdeadbeef`.
const SEED_VAR: &str = "DUDECT_SEED";

/// Number of timed samples drawn per bench invocation. dudect's t-statistic stabilizes with sample
/// count; 100k keeps a single `cargo bench` run to a few seconds while giving the test enough data
/// to flag a real leak.
const SAMPLES: usize = 100_000;

/// Plaintext (message) size for the AEAD frame, in bytes. **Zero on purpose** — see the
/// module-level "Why the payload is empty" note: an empty message strips the post-verify ChaCha20
/// keystream (which only runs on a valid tag) so the bench isolates the constant-time Poly1305 tag
/// *comparison*, not the legitimate accept/reject decrypt gap. Raise it to measure that gap instead.
const PT_LEN: usize = 0;

/// One pre-built AEAD decrypt input: ciphertext buffer + 12-byte nonce + 16-byte detached tag.
///
/// Built entirely OUTSIDE the timed closure so that `run_one` measures only the
/// `decrypt_in_place_detached` call (key schedule, nonce setup, and tag corruption are all
/// excluded from the timing).
struct DecryptInput {
    ciphertext: Vec<u8>,
    nonce: chacha20poly1305::Nonce,
    tag: chacha20poly1305::Tag,
}

/// Prepare a valid (`Class::Left`) or tag-corrupted (`Class::Right`) AEAD decrypt input.
///
/// The message is first encrypted under the fixed `cipher` to produce a genuine ciphertext+tag,
/// then for the `Right` class the first tag byte is flipped so verification must fail. Both classes
/// share an identical (here zero-length) buffer and a random nonce; only the tag differs, so any
/// timing gap is attributable to the verify outcome rather than to differing work.
fn make_input(cipher: &ChaCha20Poly1305, rng: &mut BenchRng, class: Class) -> DecryptInput {
    let mut nonce = chacha20poly1305::Nonce::default();
    rng.fill_bytes(nonce.as_mut_slice());

    let mut ciphertext = vec![0u8; PT_LEN];
    rng.fill_bytes(&mut ciphertext);

    // Encrypt in place to get a buffer + tag that authenticates. Empty AAD matches the transport
    // frame path in `session.rs` (`decrypt_in_place(nonce, &[], pkt)`).
    let mut tag = cipher
        .encrypt_in_place_detached(&nonce, &[], &mut ciphertext)
        .expect("encrypt_in_place_detached must not fail for a fixed-size buffer");

    if let Class::Right = class {
        // Corrupt the tag so AEAD verification fails. Flip the low bit of the first byte.
        tag[0] ^= 0x01;
    }

    DecryptInput {
        ciphertext,
        nonce,
        tag,
    }
}

/// dudect bench: ChaCha20Poly1305 AEAD decrypt-and-verify, valid vs. corrupted tag.
fn aead_decrypt_tag_verify(runner: &mut CtRunner, rng: &mut BenchRng) {
    // Fixed key for the whole run: we are isolating the tag-verify primitive, not key handling.
    // A real `ReceiveSession` derives this from the handshake; here it is a constant.
    let key = chacha20poly1305::Key::from_slice(&[0x42u8; 32]).to_owned();
    let cipher = ChaCha20Poly1305::new(&key);

    debug_assert_eq!(
        <ChaCha20Poly1305 as AeadCore>::TagSize::USIZE,
        16,
        "Poly1305 tag is 16 bytes"
    );

    // Pre-build every input (and its class) up front, outside the timing loop.
    let inputs: Vec<(Class, DecryptInput)> = (0..SAMPLES)
        .map(|_| {
            // Randomly assign each sample to a distribution, as dudect expects (interleaved
            // classes keep the t-test statistically meaningful against slow environmental drift).
            let class = if rng.random::<bool>() {
                Class::Left
            } else {
                Class::Right
            };
            let input = make_input(&cipher, rng, class);
            (class, input)
        })
        .collect();

    // `run_one` takes an `Fn` closure, but `decrypt_in_place_detached` needs a `&mut [u8]`
    // scratch buffer. Allocating that buffer inside the closure (e.g. `ciphertext.clone()`) would
    // fold per-iteration heap-allocator timing into the measurement and swamp the AEAD signal. So
    // we allocate ONE scratch buffer up front and reuse it across all iterations via a `RefCell`
    // for the interior mutability the `Fn` bound demands. Each timed call refills the scratch from
    // the pre-built ciphertext with a fixed-cost `copy_from_slice` (a constant-length memcpy,
    // identical for both classes) and then runs the verify+decrypt — so the only deliberate
    // difference between Left and Right is the tag validity.
    let scratch = RefCell::new(vec![0u8; PT_LEN]);

    for (class, input) in inputs {
        let DecryptInput {
            ciphertext,
            nonce,
            tag,
        } = input;
        runner.run_one(class, || {
            let mut buf = scratch.borrow_mut();
            buf.copy_from_slice(&ciphertext);
            // The operation under test: authenticate the tag and decrypt in place. For the Right
            // class this returns Err (tag mismatch); a constant-time verifier takes the same time
            // either way. We deliberately ignore the Result — only the timing matters here.
            let _ = cipher.decrypt_in_place_detached(&nonce, &[], &mut buf, &tag);
        });
    }
}

/// Reads the [`SEED_VAR`] override, or draws a fresh seed from the OS.
///
/// A fresh seed per run is deliberate: a fixed one would reproduce a seed-specific artifact on
/// every run forever. The seed is printed so an interesting run can be replayed exactly.
///
/// # Panics
///
/// Panics if [`SEED_VAR`] is set to something that is not a `u64` (decimal, or `0x`-prefixed hex).
fn seed() -> u64 {
    match std::env::var(SEED_VAR) {
        Err(_) => rand::rng().next_u64(),
        Ok(raw) => {
            let trimmed = raw.trim();
            let parsed = match trimmed
                .strip_prefix("0x")
                .or_else(|| trimmed.strip_prefix("0X"))
            {
                Some(hex) => u64::from_str_radix(hex, 16),
                None => trimmed.parse(),
            };
            parsed.unwrap_or_else(|e| panic!("{SEED_VAR}={raw:?} is not a u64: {e}"))
        }
    }
}

fn main() {
    dudect::self_check();

    let seed = seed();
    let mut rng = BenchRng::seed_from_u64(seed);
    let mut runner = CtRunner::default();
    aead_decrypt_tag_verify(&mut runner, &mut rng);

    let summary = runner.summarize();
    println!("bench aead_decrypt_tag_verify (seed 0x{seed:016x}) ... {summary}");

    let verdict = if summary.max_t.abs() > 5f64 {
        "|max t| is above the 5 threshold — investigate"
    } else {
        "|max t| is below the 5 threshold — no leak detected, which is not proof of constant-timeness"
    };
    println!("\nmax t = {:+.5}: {verdict}", summary.max_t);
}
