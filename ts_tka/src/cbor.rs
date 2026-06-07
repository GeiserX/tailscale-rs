//! A minimal **CTAP2 canonical** CBOR encoder, sufficient for serializing TKA's AUMs, keys, and
//! node-key signatures byte-for-byte the way Go's `fxamacker/cbor` (CTAP2 mode) does.
//!
//! Byte-exactness matters: the signing digest is `BLAKE2s-256(canonical_cbor(value))`, so any
//! deviation from Go's canonical form makes every signature fail to verify. We therefore implement
//! exactly the CTAP2 rules the TKA types exercise — no more:
//!
//! - **Definite lengths only** (no indefinite-length items).
//! - **Smallest-integer encoding**: a value is encoded in the shortest of the 1/2/4/8-byte forms.
//! - **Maps keyed by unsigned integers** (`keyasint`), with keys sorted by the **CTAP2 canonical
//!   key ordering**. NOTE: `fxamacker/cbor`'s `SortCTAP2` is **bytewise-lexicographic on the encoded
//!   key** (the same comparator as RFC 8949 §4.2.1 deterministic encoding), *not* the
//!   "shorter-key-first / length-then-lexical" rule (that is `SortCanonical` / RFC 7049 §3.9). The
//!   two rules diverge only for keys whose encoded forms differ in length; for the small integer
//!   keys TKA uses (all ≤ 23, single-byte heads) bytewise == numeric == length-first, so ascending
//!   numeric order is byte-equivalent. If `IntMap` ever carries keys ≥ 24 (multi-byte heads),
//!   revisit this to ensure pure-bytewise ordering on the encoded key.
//! - **No duplicate map keys** (CTAP2 forbids them; a duplicate would be a malformed map).
//! - **`omitempty`**: a field whose value is absent/empty is not emitted at all.
//!
//! The encoder is a tiny value model ([`Value`]) plus [`Value::encode`]. It is deliberately not a
//! general-purpose CBOR library.

use alloc::vec::Vec;

/// A CBOR value, limited to the shapes TKA serialization needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Unsigned integer (CBOR major type 0).
    Uint(u64),
    /// Byte string (CBOR major type 2).
    Bytes(Vec<u8>),
    /// Text string (CBOR major type 3).
    Text(Vec<u8>),
    /// Array (CBOR major type 4).
    Array(Vec<Value>),
    /// Map with unsigned-integer keys (CBOR major type 5, `keyasint`). Encoded in CTAP2 canonical
    /// key order regardless of insertion order.
    IntMap(Vec<(u64, Value)>),
}

impl Value {
    /// Encode this value as canonical CTAP2 CBOR into `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Value::Uint(n) => encode_head(out, 0, *n),
            Value::Bytes(b) => {
                encode_head(out, 2, b.len() as u64);
                out.extend_from_slice(b);
            }
            Value::Text(t) => {
                encode_head(out, 3, t.len() as u64);
                out.extend_from_slice(t);
            }
            Value::Array(items) => {
                encode_head(out, 4, items.len() as u64);
                for it in items {
                    it.encode(out);
                }
            }
            Value::IntMap(entries) => {
                // CTAP2 canonical key order. fxamacker `SortCTAP2` = bytewise-lexicographic on the
                // encoded key; for TKA's uint-only keys (all <= 23, single-byte heads) that is
                // byte-equivalent to ascending numeric order. (See the module doc for the caveat if
                // keys >= 24 are ever introduced.)
                let mut sorted: Vec<&(u64, Value)> = entries.iter().collect();
                sorted.sort_by_key(|(k, _)| *k);
                // CTAP2 forbids duplicate map keys: a duplicate would emit a malformed map and,
                // worse, change the signing digest in a way that diverges from Go. Catch it in
                // debug builds (callers build IntMaps from fixed `keyasint` field sets, so a
                // duplicate is a construction bug, not attacker input).
                debug_assert!(
                    sorted.windows(2).all(|w| w[0].0 != w[1].0),
                    "IntMap has duplicate keys; CTAP2 canonical CBOR forbids duplicate map keys"
                );
                encode_head(out, 5, sorted.len() as u64);
                for (k, v) in sorted {
                    encode_head(out, 0, *k); // key: unsigned int
                    v.encode(out);
                }
            }
        }
    }

    /// Convenience: encode to a fresh `Vec`.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out);
        out
    }
}

/// Build an `IntMap` from `(key, Option<Value>)` pairs, dropping `None` entries (the `omitempty`
/// rule). Order of `pairs` is irrelevant — encoding re-sorts canonically.
pub fn int_map(pairs: impl IntoIterator<Item = (u64, Option<Value>)>) -> Value {
    Value::IntMap(
        pairs
            .into_iter()
            .filter_map(|(k, v)| v.map(|v| (k, v)))
            .collect(),
    )
}

/// Encode a CBOR head: major type `major` (0..7) in the top 3 bits, with the argument `n` in the
/// **smallest** of the inline / 1 / 2 / 4 / 8-byte forms (canonical minimal-integer rule).
fn encode_head(out: &mut Vec<u8>, major: u8, n: u64) {
    let mt = major << 5;
    if n < 24 {
        out.push(mt | (n as u8));
    } else if n <= u8::MAX as u64 {
        out.push(mt | 24);
        out.push(n as u8);
    } else if n <= u16::MAX as u64 {
        out.push(mt | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= u32::MAX as u64 {
        out.push(mt | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(mt | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uint_minimal_encoding() {
        assert_eq!(Value::Uint(0).to_vec(), vec![0x00]);
        assert_eq!(Value::Uint(23).to_vec(), vec![0x17]);
        assert_eq!(Value::Uint(24).to_vec(), vec![0x18, 24]);
        assert_eq!(Value::Uint(255).to_vec(), vec![0x18, 0xff]);
        assert_eq!(Value::Uint(256).to_vec(), vec![0x19, 0x01, 0x00]);
        assert_eq!(
            Value::Uint(65536).to_vec(),
            vec![0x1a, 0x00, 0x01, 0x00, 0x00]
        );
    }

    #[test]
    fn bytes_encoding() {
        assert_eq!(Value::Bytes(vec![1, 2, 3]).to_vec(), vec![0x43, 1, 2, 3]);
        assert_eq!(Value::Bytes(vec![]).to_vec(), vec![0x40]);
    }

    #[test]
    fn int_map_sorts_keys_ascending() {
        // Insert out of order; encoding must sort keys 1,2,3.
        let m = Value::IntMap(vec![
            (3, Value::Uint(30)),
            (1, Value::Uint(10)),
            (2, Value::Uint(20)),
        ]);
        assert_eq!(
            m.to_vec(),
            // map(3) { 1:10, 2:20, 3:30 }
            vec![0xa3, 0x01, 0x0a, 0x02, 0x14, 0x03, 0x18, 30]
        );
    }

    #[test]
    fn int_map_omitempty_drops_none() {
        let m = int_map([
            (1, Some(Value::Uint(1))),
            (2, None),
            (3, Some(Value::Uint(3))),
        ]);
        // Only keys 1 and 3 present.
        assert_eq!(m.to_vec(), vec![0xa2, 0x01, 0x01, 0x03, 0x03]);
    }
}
