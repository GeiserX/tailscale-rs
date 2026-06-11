#![doc = include_str!("../README.md")]
#![no_std]

extern crate alloc;

mod keystate;
mod macros;

#[doc(inline)]
pub use keystate::{NodeState, PersistState};
use macros::{
    _create_x25519_base_key_type, create_ed25519_keypair_types, create_ed25519_private_key_type,
    create_ed25519_public_key_type, create_x25519_keypair_types, create_x25519_private_key_type,
    create_x25519_public_key_type,
};

/// Errors that may occur when parsing a string into a key type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// Key string was formatted incorrectly.
    #[error("key string was formatted incorrectly")]
    InvalidFormat,

    /// Key was the wrong length.
    #[error("key was the wrong length")]
    WrongLength,

    /// Parsed prefix did not match the key type.
    #[error("parsed prefix did not match the key type")]
    BadPrefix,
}

// The client never handles challenge private keys, so we only create a public key type rather than
// public/private/keypair types.
create_x25519_public_key_type!(
    /// The X25519 public key of a challenge issued by control to a Tailnet node during registration.
    ChallengePublicKey,
    "chalpub"
);

// The client never handles DERP server private keys, so we only create a public key type rather
// than public/private/keypair types.
create_x25519_public_key_type!(
    /// The X25519 public key of a DERP server.
    DerpServerPublicKey,
    "derp"
);
create_x25519_keypair_types!(
    /// The X25519 public key a Tailscale node uses for the Disco protocol.
    DiscoPublicKey,
    "discokey",
    /// The X25519 private key a Tailscale node uses for the Disco protocol.
    DiscoPrivateKey,
    "privkey",
    /// The X25519 public/private key pair a Tailscale node uses for the Disco protocol.
    DiscoKeyPair
);

create_x25519_keypair_types!(
    /// The X25519 public key of a unique piece of hardware running one or more Tailscale nodes.
    /// Also the key type sent from a control server to a Tailscale node during the initial control
    /// handshake.
    MachinePublicKey,
    "mkey",
    /// The X25519 private key of a unique piece of hardware running one or more Tailscale nodes.
    MachinePrivateKey,
    "privkey",
    /// The X25519 public/private key pair of a unique piece of hardware running one or more
    /// Tailscale nodes.
    MachineKeyPair
);

create_ed25519_keypair_types!(
    /// The Ed25519 public key of a Tailscale node for use with Tailnet Lock.
    NetworkLockPublicKey,
    "nlpub",
    /// The Ed25519 private key of a Tailscale node for use with Tailnet Lock.
    NetworkLockPrivateKey,
    "nlpriv",
    /// The Ed25519 public/private key pair of a Tailscale node for use with Tailnet Lock.
    NetworkLockKeyPair
);

create_x25519_keypair_types!(
    /// The X25519 public key of a Tailscale node.
    NodePublicKey,
    "nodekey",
    /// The X25519 private key of a Tailscale node.
    NodePrivateKey,
    "privkey",
    /// The X25519 public/private key pair of a Tailscale node.
    NodeKeyPair
);

#[cfg(test)]
mod debug_redaction_tests {
    use alloc::format;

    use super::{
        DiscoPrivateKey, MachinePrivateKey, NetworkLockPrivateKey, NodePrivateKey, NodePublicKey,
    };

    /// A private key's `Debug` MUST NOT contain the secret bytes (regression guard for the
    /// log-leak fixed in tsr-9nu). We use an all-`0xAB` key so the hex `"ab"` is unmistakable.
    #[test]
    fn private_key_debug_is_redacted() {
        let secret = [0xABu8; 32];

        let m = MachinePrivateKey::from(secret);
        let n = NodePrivateKey::from(secret);
        let d = DiscoPrivateKey::from(secret);
        let nl = NetworkLockPrivateKey::from(secret);

        for (label, dbg) in [
            ("MachinePrivateKey", format!("{m:?}")),
            ("NodePrivateKey", format!("{n:?}")),
            ("DiscoPrivateKey", format!("{d:?}")),
            ("NetworkLockPrivateKey", format!("{nl:?}")),
        ] {
            assert!(
                dbg.contains("<redacted>"),
                "{label} Debug should be redacted, got {dbg:?}"
            );
            assert!(
                !dbg.contains("abab"),
                "{label} Debug leaked secret bytes: {dbg:?}"
            );
            // The secret is also reachable via Display/to_bytes — confirm those still expose it,
            // so the redaction is Debug-only and didn't break the explicit serialization paths.
            assert!(
                format!("{m}").contains("abab"),
                "Display must still expose the key bytes"
            );
        }
    }

    /// A public key's `Debug` SHOULD still print the full `prefix:hex` (public keys are not secret).
    #[test]
    fn public_key_debug_shows_hex() {
        let pubk = NodePublicKey::from([0xABu8; 32]);
        let dbg = format!("{pubk:?}");
        assert!(
            dbg.contains("abab"),
            "public key Debug should show hex: {dbg:?}"
        );
        assert_eq!(dbg, format!("{pubk}"), "public Debug == Display");
    }

    /// Private keys wipe their secret bytes on drop (`ZeroizeOnDrop`, tsr-9nu). We can't observe a
    /// value after it drops in safe Rust, so this drives `Zeroize::zeroize` explicitly (the same
    /// code the drop glue runs) and confirms the buffer is zeroed — a behavioral guard that the
    /// derive is wired up, not merely that it compiles.
    #[test]
    fn private_key_zeroize_wipes_bytes() {
        use zeroize::Zeroize;

        let mut k = NodePrivateKey::from([0xABu8; 32]);
        assert_eq!(
            k.to_bytes(),
            [0xABu8; 32],
            "precondition: key holds its bytes"
        );
        k.zeroize();
        assert_eq!(
            k.to_bytes(),
            [0u8; 32],
            "zeroize must wipe the secret bytes to zero"
        );
    }

    /// `public_key()` borrows (`&self`) — deriving the public key must not consume the private key,
    /// so it stays usable afterwards. This is the API shape that lets callers hold a private key
    /// without it being moved/dropped on every derivation (mirrors Go's `key.NodePrivate.Public()`).
    #[test]
    fn public_key_derivation_borrows_private() {
        let k = NodePrivateKey::from([0x11u8; 32]);
        let p1 = k.public_key();
        // `k` is still alive here precisely because `public_key` took `&self`.
        let p2 = k.public_key();
        assert_eq!(p1, p2, "repeated derivation from the same key agrees");
        // And a clone derives the same public key (clone copies the secret faithfully).
        assert_eq!(k.clone().public_key(), p1);
    }

    /// A key string of the right length+prefix but containing non-hex (or a non-ASCII char that
    /// splits a 2-byte window) must parse to `Err`, NOT panic. Regression: the hex loop used
    /// `.unwrap()` on `get(i..i+2)` and `from_str_radix`, so a malformed key in a control response
    /// would unwind and kill the netmap decoder. Go's key parse returns an error here.
    #[test]
    fn malformed_hex_key_errors_not_panics() {
        use core::str::FromStr;

        // 64 non-hex ASCII chars: length + prefix pass, `from_str_radix("zz",16)` must error.
        let non_hex = alloc::format!("nodekey:{}", "z".repeat(64));
        assert!(
            NodePublicKey::from_str(&non_hex).is_err(),
            "non-hex key body must be a parse error, not a panic"
        );

        // A multi-byte UTF-8 char makes the byte length 64 while `get(i..i+2)` can land on a char
        // boundary and return None — must also be an error, not a panic. "é" is 2 UTF-8 bytes.
        let multibyte = alloc::format!("nodekey:{}", "é".repeat(32));
        assert_eq!(multibyte.len() - "nodekey:".len(), 64, "body is 64 bytes");
        assert!(
            NodePublicKey::from_str(&multibyte).is_err(),
            "a non-ASCII body must be a parse error, not a panic"
        );
    }
}

#[cfg(all(test, feature = "serde"))]
mod nl_tests {
    use core::str::FromStr;

    use super::{NetworkLockKeyPair, NetworkLockPrivateKey, NetworkLockPublicKey};

    /// A `NetworkLockKeyPair` round-trips through its `nlpriv:`/`nlpub:` string forms.
    #[test]
    fn nl_key_roundtrip_serde() {
        let kp = NetworkLockKeyPair::new();

        let priv_str = alloc::format!("{}", kp.private);
        let pub_str = alloc::format!("{}", kp.public);
        assert!(priv_str.starts_with("nlpriv:"));
        assert!(pub_str.starts_with("nlpub:"));

        let parsed_priv = NetworkLockPrivateKey::from_str(&priv_str).unwrap();
        let parsed_pub = NetworkLockPublicKey::from_str(&pub_str).unwrap();
        assert_eq!(parsed_priv, kp.private);
        assert_eq!(parsed_pub, kp.public);
    }

    /// Public-key derivation is deterministic and matches the audited ed25519-dalek RFC 8032
    /// seed->public derivation (proving we are NOT using X25519 scalar multiplication).
    #[test]
    fn nl_public_derivation_is_deterministic() {
        let seed = [7u8; 32];
        let sk = NetworkLockPrivateKey::from(seed);
        let p1 = sk.public_key();
        let p2 = sk.public_key();
        assert_eq!(p1, p2);

        let dalek = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        assert_eq!(p1.to_bytes(), dalek);
    }

    /// RFC 8032 §7.1 TEST 1 known-answer vector, exercised through the fork's own
    /// `NetworkLockPrivateKey`: the canonical Ed25519 secret seed must derive the canonical public
    /// key. This pins the fork's NL key to standards-conformant Ed25519 (RFC 8032) — a stronger proof
    /// than the dalek cross-check, since it would catch a byte-swap, a wrong seed interpretation, or a
    /// future dependency that derived a different curve. Vector verified against rfc-editor.org/rfc/rfc8032.txt.
    #[test]
    fn nl_public_matches_rfc8032_test1() {
        fn unhex(s: &str) -> [u8; 32] {
            let b = s.as_bytes();
            let mut out = [0u8; 32];
            let mut i = 0;
            while i < 32 {
                let hi = (b[2 * i] as char).to_digit(16).unwrap() as u8;
                let lo = (b[2 * i + 1] as char).to_digit(16).unwrap() as u8;
                out[i] = (hi << 4) | lo;
                i += 1;
            }
            out
        }
        let seed = unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let public = unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let derived = NetworkLockPrivateKey::from(seed).public_key();
        assert_eq!(derived.to_bytes(), public);

        // Also lock in the full `nlpub:`+lowercase-hex emission (prefix + hex jointly), which is the
        // exact text form Go sends as `RegisterRequest.NLKey` (`key.NLPublic.MarshalText`).
        assert_eq!(
            alloc::format!("{derived}"),
            "nlpub:d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
    }

    /// `KeyPair::new`, `From<private>`, and the standalone `private.public_key()` all agree on the
    /// derived public — there is one derivation, regardless of how the pair is constructed.
    #[test]
    fn nl_keypair_derivation_is_consistent() {
        let kp = NetworkLockKeyPair::new();
        assert_eq!(kp.public, kp.private.public_key());
        // `.clone()`: `From<private>` consumes the key (no longer `Copy`); keep `kp.private` for
        // the equality check below.
        let from_priv = NetworkLockKeyPair::from(kp.private.clone());
        assert_eq!(from_priv.public, kp.public);
        assert_eq!(from_priv.private, kp.private);
    }

    /// Regression guard: the Ed25519 derivation must NOT match the old (buggy) X25519 derivation
    /// for the same 32-byte seed.
    #[test]
    fn nl_key_is_not_x25519() {
        let seed = [7u8; 32];
        let ed = NetworkLockPrivateKey::from(seed).public_key().to_bytes();
        let x = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(seed)).to_bytes();
        assert_ne!(ed, x);
    }
}
