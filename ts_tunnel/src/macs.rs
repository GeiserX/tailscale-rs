use std::{
    ops::Add,
    time::{Duration, Instant},
};

use aead::{Aead, Payload, consts::U16};
use blake2::{Blake2s256, Blake2sMac, Digest, digest::FixedOutput};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use ts_keys::NodePublicKey;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned};

use crate::messages::CookieReply;

const MAC1_LABEL: &[u8] = b"mac1----";
const MAC2_LABEL: &[u8] = b"cookie--";
const COOKIE_ROTATION_TIME: Duration = Duration::from_secs(120);

type CookieMac = Blake2sMac<U16>;

pub type Mac = [u8; 16];

#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
struct Mac1Trailer {
    mac1: Mac,
    mac2: Mac,
}

#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
struct Mac2Trailer {
    mac2: Mac,
}

fn mac1_key(key: &NodePublicKey) -> [u8; 32] {
    let mut h = Blake2s256::new_with_prefix(MAC1_LABEL);
    h.update(key.to_bytes());
    h.finalize().into()
}

fn mac2_key(key: &NodePublicKey) -> [u8; 32] {
    let mut h = Blake2s256::new_with_prefix(MAC2_LABEL);
    h.update(key.to_bytes());
    h.finalize().into()
}

#[derive(Debug)]
struct Mac2Cookie {
    key: [u8; 16],
    expiry: Instant,
}

/// Computes MACs on outbound packets.
pub struct MACSender {
    mac1_key: [u8; 32],
    mac2_key: [u8; 32],
    cookie: Option<Mac2Cookie>,
}

impl MACSender {
    /// Create a MAC sender for the given peer.
    pub fn new(peer_key: &NodePublicKey) -> Self {
        Self {
            mac1_key: mac1_key(peer_key),
            mac2_key: mac2_key(peer_key),
            cookie: None,
        }
    }

    /// Write packet MACs to the final 32 bytes of pkt.
    ///
    /// Returns the computed mac1 value.
    ///
    /// # Panics
    ///
    /// If pkt is smaller than 32 bytes.
    pub fn write_macs(&self, pkt: &mut [u8]) -> Mac {
        let (data, trailer) = Mac1Trailer::try_mut_from_suffix(pkt).unwrap();
        let mut m: CookieMac = blake2::digest::Mac::new(&self.mac1_key.into());
        blake2::digest::Mac::update(&mut m, data);
        m.finalize_into(trailer.mac1.as_mut_bytes().into());
        let ret = trailer.mac1;

        if let Some(mac2) = &self.cookie
            && mac2.expiry > Instant::now()
        {
            let (data, trailer) = Mac2Trailer::try_mut_from_suffix(pkt).unwrap();
            // Have to use new_from_slice, because new only accepts keys exactly 32 bytes long,
            // whereas new_from_slice accepts keys <32 bytes and pads them in the correct way
            // internally.
            let mut m: CookieMac = blake2::digest::Mac::new_from_slice(&mac2.key).unwrap();
            blake2::digest::Mac::update(&mut m, data);
            m.finalize_into(trailer.mac2.as_mut_bytes().into());
        } else {
            trailer.mac2 = Default::default();
        }

        ret
    }

    /// Process a received cookie reply message.
    pub fn receive_cookie(&mut self, cookie: &CookieReply, handshake_mac: &Mac) {
        let cipher = XChaCha20Poly1305::new(&self.mac2_key.into());
        let msg = Payload {
            msg: &cookie.cookie_sealed,
            aad: handshake_mac,
        };
        let Ok(cookie) = cipher.decrypt(&cookie.nonce.into(), msg) else {
            return;
        };
        self.cookie = Some(Mac2Cookie {
            // CookieReply has fixed sized fields of the correct size, so the conversion
            // from Vec cannot fail.
            key: cookie.try_into().unwrap(),
            expiry: Instant::now().add(COOKIE_ROTATION_TIME),
        });
    }
}

/// Verifies MACs on inbound packets.
pub struct MACReceiver {
    mac1_key: [u8; 32],
}

impl MACReceiver {
    /// Creates a MAC receiver.
    pub fn new(my_key: &NodePublicKey) -> Self {
        Self {
            mac1_key: mac1_key(my_key),
        }
    }

    /// Verifies packet MACs in the final 32 bytes of pkt.
    #[must_use]
    pub fn verify_macs(&self, pkt: &[u8]) -> bool {
        let Ok((data, trailer)) = Mac1Trailer::try_ref_from_suffix(pkt) else {
            return false;
        };
        let mut m: CookieMac = blake2::digest::Mac::new(&self.mac1_key.into());
        blake2::digest::Mac::update(&mut m, data);
        if blake2::digest::Mac::verify(m, &trailer.mac1.into()).is_err() {
            return false;
        }

        // mac1 (verified above) is the authenticator. mac2 is the cookie MAC: a peer sets it to a
        // non-zero value only when replying to a CookieReply we issued under load (the WireGuard
        // DoS mitigation). This implementation never issues CookieReplies as the responder — it
        // holds no cookie secret and has no under-load/rate-limit path — so there is nothing to
        // verify mac2 against, and a correct peer's non-zero mac2 must NOT be rejected. We
        // therefore intentionally ignore mac2, matching wireguard-go (which only checks mac2 when
        // `UnderLoad`, i.e. after issuing cookies) and boringtun (which only enforces mac2 while a
        // cookie is active). Net effect: a packet is accepted iff mac1 verifies.
        true
    }
}

#[cfg(test)]
mod tests {
    use ts_keys::NodeKeyPair;

    use super::*;

    /// Build a packet whose final 32 bytes hold a valid mac1 for `receiver_key`, plus the given
    /// `mac2` bytes. `write_macs` (sender side) computes mac1 over the data preceding the trailer
    /// and writes a zero mac2 (no cookie); we then overwrite mac2 to model a peer that received a
    /// CookieReply and now carries a non-zero cookie MAC.
    fn packet_with_mac1(receiver_key: &NodeKeyPair, mac2: Mac) -> Vec<u8> {
        let sender = MACSender::new(&receiver_key.public);
        // 16 bytes of payload + 32-byte (mac1 || mac2) trailer.
        let mut pkt = vec![0u8; 16 + 32];
        sender.write_macs(&mut pkt);
        let (_data, trailer) = Mac1Trailer::try_mut_from_suffix(&mut pkt).unwrap();
        trailer.mac2 = mac2;
        pkt
    }

    #[test]
    fn verify_macs_accepts_valid_mac1_with_zero_mac2() {
        let receiver = NodeKeyPair::new();
        let recv = MACReceiver::new(&receiver.public);
        let pkt = packet_with_mac1(&receiver, Mac::default());
        assert!(recv.verify_macs(&pkt), "valid mac1 + zero mac2 must verify");
    }

    /// Regression: a peer replying to a CookieReply sends a NON-ZERO mac2. Previously
    /// `verify_macs` rejected any non-zero mac2 (the `// TODO` reject), so such handshakes failed
    /// deterministically. Since this implementation never issues cookies, mac2 must be ignored.
    #[test]
    fn verify_macs_accepts_valid_mac1_with_nonzero_mac2() {
        let receiver = NodeKeyPair::new();
        let recv = MACReceiver::new(&receiver.public);
        let pkt = packet_with_mac1(&receiver, [0xAB; 16]);
        assert!(
            recv.verify_macs(&pkt),
            "valid mac1 with a non-zero (cookie) mac2 must still verify"
        );
    }

    #[test]
    fn verify_macs_rejects_bad_mac1() {
        // Compute a valid mac1 for one key, but verify against a different key.
        let signer = NodeKeyPair::new();
        let other = NodeKeyPair::new();
        let recv = MACReceiver::new(&other.public);
        let pkt = packet_with_mac1(&signer, Mac::default());
        assert!(
            !recv.verify_macs(&pkt),
            "a mac1 computed under a different key must be rejected"
        );
    }

    #[test]
    fn verify_macs_rejects_bad_mac1_even_with_nonzero_mac2() {
        // A forged mac1 must stay rejected regardless of mac2 (ignoring mac2 must not weaken mac1).
        let signer = NodeKeyPair::new();
        let other = NodeKeyPair::new();
        let recv = MACReceiver::new(&other.public);
        let pkt = packet_with_mac1(&signer, [0xCD; 16]);
        assert!(
            !recv.verify_macs(&pkt),
            "bad mac1 must be rejected even with a non-zero mac2"
        );
    }
}
