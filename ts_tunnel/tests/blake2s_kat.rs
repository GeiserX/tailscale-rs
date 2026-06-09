//! Reference known-answer test (KAT) for BLAKE2s, the one crypto primitive
//! in `ts_tunnel` with no direct KAT elsewhere. `ts_tunnel` uses BLAKE2s in two
//! distinct widths/forms:
//!   * **32-byte output** (`blake2::Blake2s256`): the WireGuard `Noise_IKpsk2`
//!     transcript hash, the HKDF chaining-key expansion, and the mac1/mac2
//!     MAC-key derivations (`src/handshake.rs`, `src/macs.rs`); `ts_tka` also
//!     uses it for the `NodeKeySignature` SigHash.
//!   * **16-byte output keyed MAC** (`type CookieMac = Blake2sMac<U16>`,
//!     `src/macs.rs:18`): the actual mac1/mac2 cookie MAC written to a packet's
//!     trailer. It is keyed via `new_from_slice` (`src/macs.rs:91`), the
//!     short-key path that pads keys shorter than 32 bytes (the live cookie key
//!     is 16 bytes).
//!
//! Both flavors are covered here, and both code paths the keyed forms use are
//! exercised:
//!   * [`blake2s256_reference_kat`] covers the 32-byte hash/transcript path —
//!     the *unkeyed* `Blake2s256` AND the *keyed* `Blake2sMac256` (32-byte key
//!     via `KeyInit`).
//!   * [`blake2s_mac16_kat`] covers the 16-byte `Blake2sMac<U16>` cookie-MAC
//!     path, INCLUDING short (<32-byte) keys that exercise the `new_from_slice`
//!     padding the cookie MAC actually relies on (`src/macs.rs:91`).
//!
//! So the unkeyed hash, the 32-byte keyed MAC, and the 16-byte keyed cookie MAC
//! (full-length and short/padded key) are all tested. The Wycheproof project ships no BLAKE2 set
//! (`wycheproof_chacha20poly1305.rs` covers only the AEAD), so this validates
//! the BLAKE2s primitive against the canonical BLAKE2 reference vectors.
//!
//! Provenance: the canonical BLAKE2 reference KAT, from the official
//! `github.com/BLAKE2/BLAKE2` repository, file `testvectors/blake2-kat.json`.
//! That file's BLAKE2s entries are unkeyed and keyed BLAKE2s-256 over the
//! standard incrementing-byte inputs: an input of length `n` is the bytes
//! `00 01 02 ... (n-1)`, and keyed vectors use the fixed 32-byte key
//! `00 01 02 ... 1f`. Two well-known anchors are present and asserted exactly,
//! binding this test to the published values (`unkeyed BLAKE2s-256("")` =
//! `69217a30...1ed0eef9`; `unkeyed BLAKE2s-256("abc")` = `508c5e8c...86675982`,
//! input `0x616263`).
//!
//! Every 32-byte output below was produced by RustCrypto's `blake2` crate (the
//! proven dependency `ts_tunnel` ships) over the canonical inputs and
//! independently cross-checked against `testvectors/blake2-kat.json` (and
//! against an unrelated implementation, Python `hashlib.blake2s`). The 16-byte
//! `Blake2sMac<U16>` outputs are not in the canonical 32-byte-only KAT file, so
//! they were produced by the same `blake2` crate (the reference implementation
//! `ts_tunnel` actually ships and uses for the cookie MAC) and independently
//! cross-checked against Python `hashlib.blake2s(digest_size=16, key=..)`, which
//! matched byte-for-byte. The 32-byte vectors are also committed as JSON
//! provenance at `tests/vectors/blake2s_kat.json`; all vectors are embedded
//! here as arrays so this test needs no JSON-parsing dev-dependency.
//!
//! The keyed path is a MAC construction parameterized by the key
//! (`blake2::Blake2sMac256` / `Blake2sMac<U16>` via `KeyInit` / `new_from_slice`),
//! *not* a hash with a prefixed key.

use blake2::digest::consts::U16;
use blake2::digest::{FixedOutput, KeyInit, Mac, Update};
use blake2::{Blake2s256, Blake2sMac, Blake2sMac256, Digest};

/// The 32-byte canonical keyed-vector key, `00 01 02 ... 1f`.
const KEY32: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/// `(input_hex, key_hex, expected_out_hex)`. `key_hex` empty => unkeyed.
/// Inputs follow the canonical BLAKE2 KAT convention (bytes 00 01 02 ...);
/// keyed vectors use the 32-byte key `00 01 02 ... 1f` (`KEY32`).
const VECTORS: &[(&str, &str, &str)] = &[
    // --- unkeyed BLAKE2s-256 (key = "") ---
    // empty input — canonical anchor
    (
        "",
        "",
        "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
    ),
    // "abc" (0x616263) — canonical anchor
    (
        "616263",
        "",
        "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
    ),
    // 00 (1 byte)
    (
        "00",
        "",
        "e34d74dbaf4ff4c6abd871cc220451d2ea2648846c7757fbaac82fe51ad64bea",
    ),
    // 00 01 (2 bytes)
    (
        "0001",
        "",
        "ddad9ab15dac4549ba42f49d262496bef6c0bae1dd342a8808f8ea267c6e210c",
    ),
    // 00 01 02 (3 bytes)
    (
        "000102",
        "",
        "e8f91c6ef232a041452ab0e149070cdd7dd1769e75b3a5921be37876c45c9900",
    ),
    // 00..0f (16 bytes)
    (
        "000102030405060708090a0b0c0d0e0f",
        "",
        "efc04cdc391c7e9119bd38668a534e65fe31036d6a62112e44ebeb11f9c57080",
    ),
    // 00..1f (32 bytes, one full BLAKE2s block)
    (
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "",
        "05825607d7fdf2d82ef4c3c8c2aea961ad98d60edff7d018983e21204c0d93d1",
    ),
    // 00..3f (64 bytes, two blocks)
    (
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        "",
        "56f34e8b96557e90c1f24b52d0c89d51086acf1b00f634cf1dde9233b8eaaa3e",
    ),
    // --- keyed BLAKE2s-256 (key = 00 01 02 ... 1f = KEY32) ---
    // empty input, keyed — canonical first keyed BLAKE2s vector
    (
        "",
        KEY32,
        "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49",
    ),
    // 00 (1 byte), keyed
    (
        "00",
        KEY32,
        "40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1",
    ),
    // 00 01 (2 bytes), keyed
    (
        "0001",
        KEY32,
        "6bb71300644cd3991b26ccd4d274acd1adeab8b1d7914546c1198bbe9fc9d803",
    ),
    // 00 01 02 (3 bytes), keyed
    (
        "000102",
        KEY32,
        "1d220dbe2ee134661fdf6d9e74b41704710556f2f6e5a091b227697445dbea6b",
    ),
    // 00..0f (16 bytes), keyed
    (
        "000102030405060708090a0b0c0d0e0f",
        KEY32,
        "19ba234f0a4f38637d1839f9d9f76ad91c8522307143c97d5f93f69274cec9a7",
    ),
    // 00..1f (32 bytes), keyed
    (
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        KEY32,
        "c03bc642b20959cbe133a0303e0c1abff3e31ec8e1a328ec8565c36decff5265",
    ),
    // 00..3f (64 bytes), keyed
    (
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        KEY32,
        "8975b0577fd35566d750b362b0897a26c399136df07bababbde6203ff2954ed4",
    ),
];

/// A 16-byte (short, <32) key, `00 01 02 ... 0f`. Keying `Blake2sMac<U16>` with
/// this exercises the `new_from_slice` short-key padding path — exactly what the
/// live cookie MAC uses (`src/macs.rs:91`, where the 16-byte cookie key is keyed
/// via `new_from_slice`, NOT `new`).
const KEY16: &str = "000102030405060708090a0b0c0d0e0f";

/// `(input_hex, key_hex, expected_out_hex)` for the **16-byte-output** keyed MAC
/// `Blake2sMac<U16>` (the `CookieMac` of `src/macs.rs:18`). Distinct from
/// [`VECTORS`] because the output width differs (16 vs 32 bytes). Includes both
/// a full-length 32-byte key (`KEY32`) and a SHORT 16-byte key (`KEY16`); the
/// short-key rows drive the `new_from_slice` padding the cookie MAC relies on.
///
/// Outputs were produced by RustCrypto's `blake2` crate (the dep `ts_tunnel`
/// ships, keyed via `new_from_slice` + `finalize_fixed`, mirroring `macs.rs`)
/// and independently cross-checked against Python
/// `hashlib.blake2s(digest_size=16, key=..)`, which matched byte-for-byte.
const MAC16_VECTORS: &[(&str, &str, &str)] = &[
    // --- 32-byte key (KEY32) ---
    // empty input, full-length key
    ("", KEY32, "9536f9b267655743dee97b8a670f9f53"),
    // "abc" (0x616263), full-length key
    ("616263", KEY32, "61ba5f165c194692e09d12520cc4c74a"),
    // 00..3f (64 bytes), full-length key
    (
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        KEY32,
        "f1efa90d2547036841ecd3627fafbc36",
    ),
    // --- SHORT 16-byte key (KEY16) — exercises new_from_slice padding ---
    // empty input, short key (the cookie-MAC short-key padding path)
    ("", KEY16, "af4e5d3bb230e9ff9096ca6f7c501f76"),
    // "abc" (0x616263), short key
    ("616263", KEY16, "75296c2d2c0f51210b383f386bc8b1ff"),
    // 00..1f (32 bytes, one full block), short key
    (
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        KEY16,
        "6b363e9519590c23cda5d0e30b29e1f1",
    ),
];

/// Decode an even-length hex string into bytes. Empty string -> empty vec.
fn unhex(s: &str) -> Vec<u8> {
    assert!(
        s.len().is_multiple_of(2),
        "hex string must have even length: {s:?}"
    );
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex byte"))
        .collect()
}

/// Compute BLAKE2s-256: unkeyed via `Blake2s256`, keyed via `Blake2sMac256`.
fn blake2s256(input: &[u8], key: &[u8]) -> [u8; 32] {
    if key.is_empty() {
        let mut h = Blake2s256::new();
        Digest::update(&mut h, input);
        h.finalize().into()
    } else {
        // Keyed BLAKE2s is a MAC construction *parameterized by the key*, NOT a
        // plain hash over key||input. `Blake2sMac256` keys via `KeyInit`.
        // Disambiguate `new_from_slice` (both `KeyInit` and `Mac` provide it; the
        // latter is in scope for the U16 cookie-MAC helper below).
        let mut m =
            <Blake2sMac256 as KeyInit>::new_from_slice(key).expect("BLAKE2s key (<=32 bytes)");
        Update::update(&mut m, input);
        m.finalize_fixed().into()
    }
}

/// Compute the 16-byte-output keyed MAC `Blake2sMac<U16>` — the `CookieMac` of
/// `src/macs.rs:18`. Keyed via `new_from_slice` + `finalize_fixed` to mirror the
/// cookie-MAC code path exactly (`src/macs.rs:91`), which uses `new_from_slice`
/// precisely so keys shorter than 32 bytes are padded correctly.
fn blake2s_mac16(input: &[u8], key: &[u8]) -> [u8; 16] {
    let mut m: Blake2sMac<U16> =
        Mac::new_from_slice(key).expect("BLAKE2s cookie-MAC key (<=32 bytes)");
    Mac::update(&mut m, input);
    m.finalize_fixed().into()
}

#[test]
fn blake2s256_reference_kat() {
    let mut ran = 0usize;
    let mut keyed = 0usize;

    for (in_hex, key_hex, out_hex) in VECTORS {
        let input = unhex(in_hex);
        let key = unhex(key_hex);
        let expected = unhex(out_hex);
        assert_eq!(expected.len(), 32, "BLAKE2s-256 output must be 32 bytes");

        let got = blake2s256(&input, &key);
        assert_eq!(
            got.as_slice(),
            expected.as_slice(),
            "BLAKE2s-256 mismatch: in={in_hex} key={key_hex}\n  got      {}\n  expected {out_hex}",
            hex::encode(got),
        );

        if !key.is_empty() {
            keyed += 1;
        }
        ran += 1;
    }

    println!(
        "BLAKE2s-256 reference KAT: ran {ran} vector(s) ({keyed} keyed, {} unkeyed)",
        ran - keyed
    );

    // Guard against a future edit that silently empties the vector table.
    assert!(
        ran >= 8,
        "expected to run >=8 BLAKE2s-256 vectors, only ran {ran}"
    );
    assert!(keyed >= 1, "expected at least one keyed BLAKE2s-256 vector");
}

/// KAT for the 16-byte-output keyed MAC `Blake2sMac<U16>` — the `CookieMac` the
/// mac1/mac2 cookie MAC actually uses (`src/macs.rs:18`). The 32-byte
/// `blake2s256_reference_kat` above does NOT cover this width or the short-key
/// `new_from_slice` padding the live cookie key (16 bytes) depends on
/// (`src/macs.rs:91`), so this is its own test.
#[test]
fn blake2s_mac16_kat() {
    let mut ran = 0usize;
    let mut short_key = 0usize;

    for (in_hex, key_hex, out_hex) in MAC16_VECTORS {
        let input = unhex(in_hex);
        let key = unhex(key_hex);
        let expected = unhex(out_hex);
        assert_eq!(
            expected.len(),
            16,
            "Blake2sMac<U16> output must be 16 bytes"
        );
        assert!(
            !key.is_empty() && key.len() <= 32,
            "cookie-MAC key must be 1..=32 bytes: key={key_hex}"
        );

        let got = blake2s_mac16(&input, &key);
        assert_eq!(
            got.as_slice(),
            expected.as_slice(),
            "Blake2sMac<U16> mismatch: in={in_hex} key={key_hex}\n  got      {}\n  expected {out_hex}",
            hex::encode(got),
        );

        // A key shorter than the 32-byte block exercises the `new_from_slice`
        // short-key padding path that the cookie MAC relies on.
        if key.len() < 32 {
            short_key += 1;
        }
        ran += 1;
    }

    println!("Blake2sMac<U16> cookie-MAC KAT: ran {ran} vector(s) ({short_key} short-key)");

    // Guard against a future edit silently gutting coverage: keep >=2 vectors,
    // and ensure the short-key (new_from_slice padding) path stays covered.
    assert!(
        ran >= 2,
        "expected to run >=2 Blake2sMac<U16> vectors, only ran {ran}"
    );
    assert!(
        short_key >= 1,
        "expected at least one SHORT-key (<32 byte) Blake2sMac<U16> vector to exercise \
         the new_from_slice padding the cookie MAC uses"
    );
}
