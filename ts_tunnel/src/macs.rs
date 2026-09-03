use std::{
    ops::Add,
    time::{Duration, Instant},
};

use aead::{Aead, Payload, consts::U16};
use blake2::{Blake2s256, Blake2sMac, Digest, digest::FixedOutput};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use ts_keys::NodePublicKey;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned};
use zeroize::Zeroizing;

use crate::messages::{CookieReply, SessionId};

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

/// Compute a cookie: `MAC(secret, binding)`, keyed Blake2s-128 exactly as wireguard-go's
/// `CookieChecker` does (`device/cookie.go`, both `CreateReply` and `CheckMAC2`).
fn cookie_mac(secret: &[u8; 32], binding: &[u8]) -> Mac {
    let mut m: CookieMac = blake2::digest::Mac::new(secret.into());
    blake2::digest::Mac::update(&mut m, binding);
    let mut cookie = Mac::default();
    m.finalize_into(cookie.as_mut_bytes().into());
    cookie
}

/// The rotating responder-side cookie secret and the instant it was drawn.
struct CookieSecret {
    value: Zeroizing<[u8; 32]>,
    set_at: Instant,
}

/// The responder half of the WireGuard cookie mechanism (whitepaper §5.4.7; wireguard-go
/// `CookieChecker` in `device/cookie.go`), the under-load denial-of-service mitigation.
///
/// A responder that is under load answers a handshake initiation carrying no valid `mac2` with a
/// [`CookieReply`] *instead of* doing the initiation's X25519 work, and only proceeds once the
/// initiator retransmits with a `mac2` derived from that cookie. The cookie is
/// `MAC(rotating secret, binding)` sealed under `HASH("cookie--" || our public key)` with the
/// received message's `mac1` as associated data, so only a party that genuinely *receives* our
/// reply can produce the `mac2` the retransmit must carry. That is the whole mitigation: a flood
/// with a forged source cannot answer the challenge, so it never reaches the expensive path.
///
/// `binding` is the return-routability material — whatever identifies where the initiation came
/// from, so that a cookie issued for one origin is worthless to another. wireguard-go binds to the
/// datagram's source address; this engine binds to the underlay peer the datagram was attributed
/// to (see [`crate::Endpoint::recv_from`]).
///
/// The secret rotates every [`COOKIE_ROTATION_TIME`] (Go `CookieRefreshTime`), which bounds how
/// long an issued cookie stays usable — the same two minutes the initiator side keeps a received
/// cookie for in [`MACSender::receive_cookie`].
pub struct CookieGenerator {
    /// `HASH("cookie--" || our public key)`: the XChaCha20-Poly1305 key the cookie is sealed
    /// under. It is derived from a *public* key and so is not itself secret — an initiator must be
    /// able to open the reply. Unforgeability comes from `secret` plus the reply only ever being
    /// sent to the attributed origin.
    encryption_key: [u8; 32],
    /// The current cookie secret. `None` until the first reply is issued, which is why
    /// [`CookieGenerator::check_mac2`] refuses every `mac2` until we have actually issued a cookie
    /// (Go's `secretSet` zero value has the same effect).
    secret: Option<CookieSecret>,
}

impl CookieGenerator {
    /// Create a cookie generator for our own node key (Go `CookieChecker.Init`).
    pub fn new(my_key: &NodePublicKey) -> Self {
        Self {
            encryption_key: mac2_key(my_key),
            secret: None,
        }
    }

    /// The cookie for `binding`, rotating the secret first if it is unset or older than
    /// [`COOKIE_ROTATION_TIME`] (the refresh step at the top of Go's `CreateReply`).
    fn cookie(&mut self, binding: &[u8], now: Instant) -> Mac {
        let fresh = self
            .secret
            .as_ref()
            .is_some_and(|s| now.saturating_duration_since(s.set_at) <= COOKIE_ROTATION_TIME);
        if !fresh {
            self.secret = Some(CookieSecret {
                value: Zeroizing::new(rand::random()),
                set_at: now,
            });
        }
        // Set immediately above when it was missing or stale, so the secret is present here.
        let secret = self.secret.as_ref().expect("cookie secret was just set");
        cookie_mac(&secret.value, binding)
    }

    /// Build the cookie reply that answers `msg` — a handshake message whose final 32 bytes are
    /// `mac1 || mac2` — for an initiator whose sender id is `receiver_id` (Go `CreateReply`).
    ///
    /// Returns `None` only if `msg` is too short to carry the MAC trailer; the caller has already
    /// verified `mac1` over that same trailer, so in practice this always yields a reply.
    pub fn create_reply(
        &mut self,
        msg: &[u8],
        receiver_id: SessionId,
        binding: &[u8],
        now: Instant,
    ) -> Option<CookieReply> {
        let (_, trailer) = Mac1Trailer::try_ref_from_suffix(msg).ok()?;
        // Copy out of the packed struct before taking any reference to it.
        let mac1 = trailer.mac1;
        let cookie = self.cookie(binding, now);

        let nonce: [u8; 24] = rand::random();
        let cipher = XChaCha20Poly1305::new(&self.encryption_key.into());
        let sealed = cipher
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: &cookie,
                    aad: &mac1,
                },
            )
            .ok()?;

        Some(CookieReply {
            receiver_id,
            nonce,
            // A 16-byte cookie sealed with a 16-byte tag is exactly the 32 bytes the field holds.
            cookie_sealed: sealed.try_into().ok()?,
            ..Default::default()
        })
    }

    /// Verify the `mac2` in the final 16 bytes of `msg` against the cookie we would have issued for
    /// `binding` (Go `CheckMAC2`).
    ///
    /// Refuses while no cookie secret is set or the secret has aged past
    /// [`COOKIE_ROTATION_TIME`]: a responder that has issued nothing recently has nothing to check
    /// against, so this is only ever consulted while under load — see [`crate::Endpoint::recv_from`].
    #[must_use]
    pub fn check_mac2(&self, msg: &[u8], binding: &[u8], now: Instant) -> bool {
        let Some(secret) = &self.secret else {
            return false;
        };
        if now.saturating_duration_since(secret.set_at) > COOKIE_ROTATION_TIME {
            return false;
        }
        let Ok((data, trailer)) = Mac2Trailer::try_ref_from_suffix(msg) else {
            return false;
        };
        let cookie = cookie_mac(&secret.value, binding);
        // `new_from_slice` for the same reason as the sender side: the cookie is a 16-byte key.
        let mut m: CookieMac = blake2::digest::Mac::new_from_slice(&cookie).unwrap();
        blake2::digest::Mac::update(&mut m, data);
        blake2::digest::Mac::verify(m, &trailer.mac2.into()).is_ok()
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

        // mac1 (verified above) is the authenticator, and it is the only thing checked here. mac2
        // is the cookie MAC: a peer sets it to a non-zero value only when answering a CookieReply
        // we issued under load, so it is meaningful only while we are under load and have a cookie
        // secret to check it against. That check lives one layer up, in
        // [`CookieGenerator::check_mac2`], where the endpoint knows both the load state and which
        // origin the packet was attributed to — matching wireguard-go, which likewise runs
        // `CheckMAC1` unconditionally and `CheckMAC2` only when `IsUnderLoad` (`device/receive.go`).
        // Net effect here: a packet is accepted iff mac1 verifies, and a correct peer's non-zero
        // mac2 is never grounds for rejection on its own.
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

    /// A message MAC'd for `responder` by a fresh initiator, plus that initiator's `MACSender` (so
    /// the caller can feed it a cookie reply) and the mac1 it must authenticate the reply with.
    fn initiation_for(responder: &NodeKeyPair) -> (MACSender, Vec<u8>, Mac) {
        let sender = MACSender::new(&responder.public);
        // 16 bytes of payload + the 32-byte (mac1 || mac2) trailer.
        let mut pkt = vec![0u8; 16 + 32];
        let mac1 = sender.write_macs(&mut pkt);
        (sender, pkt, mac1)
    }

    /// The whole cookie exchange, both halves through the production code: an under-load responder
    /// issues a cookie reply for a message that carries no `mac2`, the initiator opens it with
    /// `receive_cookie` and re-MACs its retransmit, and the responder's `check_mac2` accepts that
    /// retransmit. This is what makes the mitigation usable rather than a permanent refusal.
    #[test]
    fn cookie_reply_lets_the_initiator_answer_the_challenge() {
        let responder = NodeKeyPair::new();
        let now = Instant::now();
        let binding = b"peer-1";

        let (mut sender, pkt, mac1) = initiation_for(&responder);
        let mut generator = CookieGenerator::new(&responder.public);

        // No cookie has been issued yet: the initiator's mac2 is zero and must not verify.
        assert!(
            !generator.check_mac2(&pkt, binding, now),
            "a zero mac2 must never verify, and nothing verifies before a cookie is issued"
        );

        let reply = generator
            .create_reply(&pkt, SessionId::from(7), binding, now)
            .expect("a MAC-trailered message must yield a cookie reply");
        assert_eq!(
            reply.receiver_id,
            SessionId::from(7),
            "the reply must be addressed to the initiation's sender id"
        );

        // The initiator opens the cookie and retransmits; the retransmit now carries a mac2.
        sender.receive_cookie(&reply, &mac1);
        let mut retransmit = vec![0u8; 16 + 32];
        sender.write_macs(&mut retransmit);
        assert_ne!(
            retransmit[32..],
            [0u8; 16][..],
            "after a cookie reply the initiator must write a non-zero mac2"
        );
        assert!(
            generator.check_mac2(&retransmit, binding, now),
            "the responder must accept the mac2 derived from the cookie it just issued"
        );
    }

    /// A cookie is bound to the origin it was issued for: replaying its `mac2` from a different
    /// origin must fail, or the challenge would prove nothing about where the packet came from.
    #[test]
    fn check_mac2_rejects_a_cookie_issued_for_another_binding() {
        let responder = NodeKeyPair::new();
        let now = Instant::now();

        let (mut sender, pkt, mac1) = initiation_for(&responder);
        let mut generator = CookieGenerator::new(&responder.public);
        let reply = generator
            .create_reply(&pkt, SessionId::from(1), b"peer-1", now)
            .expect("cookie reply");
        sender.receive_cookie(&reply, &mac1);
        let mut retransmit = vec![0u8; 16 + 32];
        sender.write_macs(&mut retransmit);

        assert!(
            generator.check_mac2(&retransmit, b"peer-1", now),
            "the cookie must verify for the binding it was issued for"
        );
        assert!(
            !generator.check_mac2(&retransmit, b"peer-2", now),
            "a cookie issued for one origin must not verify for another"
        );
    }

    /// The cookie secret rotates every `COOKIE_ROTATION_TIME`, so a cookie an initiator is still
    /// holding stops being accepted once it ages out — the bound on how long one challenge is worth.
    #[test]
    fn check_mac2_rejects_a_cookie_after_the_secret_rotates() {
        let responder = NodeKeyPair::new();
        let now = Instant::now();
        let binding = b"peer-1";

        let (mut sender, pkt, mac1) = initiation_for(&responder);
        let mut generator = CookieGenerator::new(&responder.public);
        let reply = generator
            .create_reply(&pkt, SessionId::from(1), binding, now)
            .expect("cookie reply");
        sender.receive_cookie(&reply, &mac1);
        let mut retransmit = vec![0u8; 16 + 32];
        sender.write_macs(&mut retransmit);

        assert!(generator.check_mac2(&retransmit, binding, now));
        assert!(
            !generator.check_mac2(
                &retransmit,
                binding,
                now + COOKIE_ROTATION_TIME + Duration::from_secs(1)
            ),
            "a cookie must not outlive the secret it was derived from"
        );
    }

    /// The reply is sealed with the answered message's mac1 as associated data, so it only opens
    /// for the initiator that actually sent that message. An initiator holding a different
    /// in-flight mac1 learns nothing and keeps sending a zero mac2.
    #[test]
    fn cookie_reply_only_opens_for_the_initiation_it_answers() {
        let responder = NodeKeyPair::new();
        let now = Instant::now();
        let binding = b"peer-1";

        let (mut sender, pkt, _mac1) = initiation_for(&responder);
        let mut generator = CookieGenerator::new(&responder.public);
        let reply = generator
            .create_reply(&pkt, SessionId::from(1), binding, now)
            .expect("cookie reply");

        // Same reply, but authenticated against a mac1 from some other handshake.
        sender.receive_cookie(&reply, &[0x11; 16]);
        let mut retransmit = vec![0u8; 16 + 32];
        sender.write_macs(&mut retransmit);
        assert_eq!(
            retransmit[32..],
            [0u8; 16][..],
            "a cookie reply that does not authenticate must leave the mac2 zero"
        );
        assert!(
            !generator.check_mac2(&retransmit, binding, now),
            "an initiator that could not open the cookie cannot answer the challenge"
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
