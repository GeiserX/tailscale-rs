//! Stable-CI smoke complement to the nightly `cbor_decode` fuzz target.
//!
//! # Why this exists
//!
//! The highest-value TKA fuzz target lives at `ts_tka/fuzz/fuzz_targets/cbor_decode.rs`: it feeds
//! arbitrary bytes to [`ts_tka::Authority::node_key_authorized`] (the public entry a hostile peer's
//! node-key-signature CBOR blob reaches) and asserts the decode is panic-free and fail-closed
//! (always `Err`, never `Ok`, never a panic / stack-overflow). But that fuzzer needs a nightly
//! toolchain + `cargo-fuzz` and is its OWN cargo workspace (`ts_tka/fuzz/Cargo.toml`), so a normal
//! `cargo test` NEVER runs it — the panic-free / fail-closed invariant gets ZERO coverage in stable
//! CI.
//!
//! This test closes that gap: it drives the SAME public entry the fuzzer uses
//! (`Authority::from_state(AumHash([0u8;32]), State::default())` then
//! `auth.node_key_authorized(&[0u8;32], blob)`) with a curated set of HAND-CRAFTED malformed /
//! adversarial CBOR blobs, and asserts each returns `Err` (never panics, never `Ok`). On an
//! empty-trusted-key authority no input can legitimately authorize, so `Ok` would itself be a
//! finding (a forged authorization) — exactly the property the fuzzer checks. This is the
//! deterministic, always-on stable-CI complement to the (broader, randomized) nightly fuzzer.
//!
//! Cases mirror the documented fuzz concerns: empty input, a truncated CBOR head, adversarial
//! nesting past `MAX_SIG_NESTING_DEPTH` (= 16, `ts_tka/src/lib.rs:39`), a bad/unsupported major
//! type, an oversized length prefix (claims a huge byte-string length with no payload), and a few
//! arbitrary random byte strings.

use ts_tka::{AumHash, Authority, State};

/// Build the same empty-trusted-key authority the fuzz target uses. The goal is to reach the
/// decoder with attacker bytes; the trusted-key set is empty, so nothing can ever authorize.
fn empty_authority() -> Authority {
    Authority::from_state(AumHash([0u8; 32]), State::default())
}

/// Run one blob through the public entry and assert it fails closed (Err, no panic, no Ok).
///
/// `label` names the case so a regression points at the exact blob.
fn assert_rejected(label: &str, blob: &[u8]) {
    let auth = empty_authority();
    let node_key = [0u8; 32];
    let result = auth.node_key_authorized(&node_key, blob);
    assert!(
        result.is_err(),
        "node_key_authorized returned Ok on an empty-trusted-key authority for case {label:?} \
         (blob = {blob:02x?}) — every malformed/adversarial input MUST fail closed",
    );
}

#[test]
fn empty_input_rejected() {
    // No bytes at all: the decoder's first byte read must fail, not panic.
    assert_rejected("empty", &[]);
}

#[test]
fn truncated_cbor_head_rejected() {
    // Major type 0 (uint) with additional-info 24 ("one length byte follows") but NO following
    // byte: the head is truncated mid-argument.
    assert_rejected("uint head info=24, no arg byte", &[0x18]);
    // Additional-info 25 ("u16 follows") with only one of the two bytes present.
    assert_rejected("uint head info=25, 1 of 2 arg bytes", &[0x19, 0x00]);
    // Additional-info 27 ("u64 follows") with no argument bytes at all.
    assert_rejected("uint head info=27, no arg bytes", &[0x1b]);
}

#[test]
fn deeply_nested_array_rejected() {
    // A CBOR array-of-one nested far past MAX_SIG_NESTING_DEPTH (16). Each `0x81` is "array, 1
    // item" and costs one byte per level; the recursive `decode_value` must bound depth and reject
    // (never blow the stack). Terminal innermost item is a uint 0 (`0x00`).
    let depth = 16 /* MAX_SIG_NESTING_DEPTH */ + 8;
    let mut blob = vec![0x81u8; depth];
    blob.push(0x00);
    assert_rejected("array nested past MAX depth", &blob);

    // Same idea with nested MAPS (major 5): `0xa1 0x00` = "map(1) { key 0 => <value> }". Nest the
    // value far past the cap. Each level is `a1 00` (2 bytes) wrapping the next.
    let mut map_blob = Vec::new();
    for _ in 0..depth {
        map_blob.push(0xa1); // map, 1 pair
        map_blob.push(0x00); // key: uint 0
    }
    map_blob.push(0x00); // innermost value: uint 0
    assert_rejected("map nested past MAX depth", &map_blob);
}

#[test]
fn bad_major_type_rejected() {
    // Major type 7 (0b111 << 5 = 0xe0): floats / simple values — unsupported by this decoder.
    assert_rejected("major type 7 (simple/float)", &[0xe0]);
    // Major type 1 (0b001 << 5 = 0x20): negative integer — also unsupported (TKA never emits it).
    assert_rejected("major type 1 (negative int)", &[0x20]);
    // Major type 6 (0b110 << 5 = 0xc0): tagged value — unsupported.
    assert_rejected("major type 6 (tag)", &[0xc0]);
}

#[test]
fn oversized_length_prefix_rejected() {
    // Byte string (major 2) whose length prefix is a u64 = 0xffff_ffff_ffff_ffff but with NO
    // payload following. The decoder must detect the truncation rather than allocate/over-read.
    // 0x5b = major 2, additional-info 27 (u64 length follows).
    let blob = [0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    assert_rejected("byte string u64-length, no payload", &blob);

    // Byte string with a u32 length = 0xffff_ffff and no payload. 0x5a = major 2, info 26 (u32).
    let blob32 = [0x5a, 0xff, 0xff, 0xff, 0xff];
    assert_rejected("byte string u32-length, no payload", &blob32);

    // Text string (major 3) with a large u16 length (0xffff) and no payload. 0x79 = major 3,
    // info 25 (u16). Also an array (major 4) claiming a huge element count with no elements.
    assert_rejected("text string u16-length, no payload", &[0x79, 0xff, 0xff]);
    assert_rejected(
        "array huge count, no elements",
        &[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    );
}

#[test]
fn random_byte_strings_rejected() {
    // A handful of arbitrary blobs. None can authorize on an empty-trusted-key authority; the point
    // is that each fails closed (Err) without panicking, whatever shape it happens to decode to.
    let randoms: &[&[u8]] = &[
        &[0xff],
        &[0x00, 0x11, 0x22, 0x33],
        &[0xde, 0xad, 0xbe, 0xef],
        &[0xa1, 0x07, 0x42, 0xab, 0xcd], // map(1){ 7: h'abcd' } — unknown signature field (key 7)
        &[0x42, 0x13, 0x37],             // bstr(2) h'1337' — decodes fine but is not an int-map
        &[0x80],                         // array(0) — empty array, not a signature map
        &[0xa0],                         // map(0) — empty int-map: no kind => "missing kind"
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        &[0x9f, 0xff], // indefinite-length array start (reserved/unsupported here)
        &[0xfb, 0x40, 0x09, 0x21, 0xfb, 0x54, 0x44, 0x2d, 0x18], // a float64 (major 7)
    ];
    for (i, blob) in randoms.iter().enumerate() {
        assert_rejected(&alloc_label(i), blob);
    }
}

/// Tiny helper so each random case reports a distinct label without pulling in `format!` repeatedly
/// at the call site.
fn alloc_label(i: usize) -> String {
    format!("random #{i}")
}
