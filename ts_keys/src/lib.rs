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
        let from_priv = NetworkLockKeyPair::from(kp.private);
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
