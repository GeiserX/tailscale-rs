use core::fmt::{Debug, Formatter};
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

use aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use ts_packet::PacketMut;
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned,
    little_endian::{U32, U64},
};

use crate::{
    messages::{SessionId, TransportDataHeader},
    replay::ReplayWindow,
};

type SessionKey = chacha20poly1305::Key;

/// Session age past which the transmit side is considered stale and a key rotation
/// (rehandshake) should be initiated. This is `REKEY-AFTER-TIME` from the WireGuard
/// whitepaper §6.1 ("Transport Message Limits"), 120 seconds.
pub(crate) const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);

/// Session age past which a session must no longer be used to send any transport data. This is
/// `REJECT-AFTER-TIME` from the WireGuard whitepaper §6.1, 180 seconds. Applied to the **transmit**
/// side, where it is self-correcting: a `Peer::send` past this age finds the send session expired
/// and triggers a fresh handshake, so an actively-sending peer rekeys well before it (rekey is
/// driven at `REKEY_AFTER_TIME` = 120s).
pub(crate) const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);

/// Keypair age past which the **receive** path triggers a rekey, mirroring Go wireguard-go's
/// `keepKeyFreshReceiving` threshold `RejectAfterTime - KeepaliveTimeout - RekeyTimeout`
/// = 180 − 10 − 5 = **165s**. When an authenticated transport packet is received on a keypair this
/// old *and we were its initiator*, a fresh handshake is enqueued — so a mostly-*inbound*,
/// send-idle session rekeys ~15s before its receive keys would hard-expire at [`REJECT_AFTER_TIME`],
/// keeping live inbound traffic flowing. Initiator-only (the responder must not rekey, per WireGuard,
/// or both sides initiate at once).
pub(crate) const REKEY_AFTER_TIME_RECEIVING: Duration = Duration::from_secs(165);

/// Age past which a **receive** session is dropped — now the canonical `REJECT_AFTER_TIME` (180s),
/// matching the transmit side and the WireGuard spec. This was held at a lenient 240s while the fork
/// lacked a receive-triggered rekey (a send-idle, mostly-inbound session had nothing to refresh its
/// keys, so a strict 180s bound would silently drop inbound traffic). With receive-triggered rekey
/// now in place ([`REKEY_AFTER_TIME_RECEIVING`] = 165s, initiator-side), a live inbound session
/// rehandshakes before the 180s ceiling, so the spec bound is safe. Kept as a named alias of
/// `REJECT_AFTER_TIME` (rather than folded into it) to document that the receive teardown is a
/// distinct decision that only became spec-tight once receive-rekey landed.
pub(crate) const REJECT_AFTER_TIME_RECV: Duration = REJECT_AFTER_TIME;

/// Hard message-count ceiling for a keypair: no transport message may be sent with a nonce at or
/// beyond this. Matches wireguard-go `device/constants.go` `RejectAfterMessages = MaxUint64 - 2^13 - 1`
/// (the whitepaper's "2^60" is a looser conceptual bound; this is the value Go/boringtun actually
/// enforce, so we match it byte-for-byte for parity). Time-based rekey/expiry (120s/180s) makes this
/// physically unreachable on any real link, but enforcing it removes the only `panic!` on the send
/// path and makes rotation volume-aware exactly like Go.
pub(crate) const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13) - 1;

/// Message count past which a key rotation (rehandshake) should be initiated — the volume analog of
/// [`REKEY_AFTER_TIME`]. Matches wireguard-go `RekeyAfterMessages = MaxUint64 - 2^16 - 1`: an
/// actively-sending peer rekeys on whichever of time-or-volume it reaches first, so the nonce never
/// approaches [`REJECT_AFTER_MESSAGES`].
pub(crate) const REKEY_AFTER_MESSAGES: u64 = u64::MAX - (1 << 16) - 1;

/// A generator of monotonically increasing 64-bit nonces.
#[derive(Default)]
struct NonceGenerator {
    nonce: Mutex<u64>,
}

impl NonceGenerator {
    /// Reserve a batch of consecutive nonces.
    ///
    /// The reserved range is fully consumed even if the returned NonceIter isn't.
    fn batch(&self, num: usize) -> NonceIter {
        // Recover from poisoning rather than propagating the panic: the guarded value is a single u64
        // counter with no cross-field invariant, so a poisoned lock only means a prior holder panicked
        // (e.g. the unreachable exhaustion guard) — the counter itself is always valid to read/advance.
        // Propagating the poison would permanently brick this session's nonce path (and a panic here can
        // become UB across the FFI boundary).
        let mut nonce = self
            .nonce
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Clamp at the u64 ceiling rather than panic. This is doubly unreachable in practice — a
        // session is torn down at REJECT_AFTER_TIME (180s) and `expired()` now also fires at
        // REJECT_AFTER_MESSAGES well before the counter could reach u64::MAX — but a `panic!` on the
        // data/send path can become UB across the FFI boundary, so clamp-and-stop instead: the
        // returned iter yields no more nonces past the ceiling (the caller's packet is dropped, and
        // `expired()` has already forced a rekey). To exhaust a u64 in 180s at 1500-byte packets you
        // would have to push ~230 exabytes/sec; this branch exists only as a non-panicking backstop.
        let end = nonce.checked_add(num as u64).unwrap_or(u64::MAX);
        let ret = NonceIter { cur: *nonce, end };
        *nonce = end;
        ret
    }

    /// The next nonce that would be issued — i.e. the count of nonces already consumed. Used to
    /// drive volume-based rotation ([`REKEY_AFTER_MESSAGES`]) and the hard ceiling
    /// ([`REJECT_AFTER_MESSAGES`]) without consuming a nonce.
    fn count(&self) -> u64 {
        *self
            .nonce
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Test-only: seed the counter directly so volume-threshold logic (which is otherwise reachable
    /// only after ~2^64 packets) can be exercised without exhausting the generator.
    #[cfg(test)]
    fn set_count(&self, value: u64) {
        *self
            .nonce
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = value;
    }
}
struct NonceIter {
    cur: u64,
    end: u64,
}

impl Iterator for NonceIter {
    type Item = Nonce;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cur == self.end {
            None
        } else {
            let ret = self.cur;
            self.cur += 1;
            Some(Nonce::from(ret))
        }
    }
}

/// A cryptographic nonce for use with ChaCha20Poly1305.
#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
struct Nonce {
    _zero: U32,
    counter: U64,
}

impl From<U64> for Nonce {
    fn from(v: U64) -> Self {
        Nonce {
            counter: v,
            _zero: Default::default(),
        }
    }
}

impl From<u64> for Nonce {
    fn from(v: u64) -> Self {
        Self::from(U64::from(v))
    }
}

impl AsRef<chacha20poly1305::Nonce> for Nonce {
    fn as_ref(&self) -> &chacha20poly1305::Nonce {
        let array: &[u8] = self.as_bytes();
        array.into()
    }
}

/// Established session that can only send.
pub struct TransmitSession {
    cipher: ChaCha20Poly1305,
    nonce: NonceGenerator,
    id: SessionId,
    created: Instant,
}

impl TransmitSession {
    pub fn new(key: SessionKey, id: SessionId, now: Instant) -> Self {
        TransmitSession {
            cipher: ChaCha20Poly1305::new(&key),
            nonce: Default::default(),
            id,
            created: now,
        }
    }

    /// Encrypt a batch of packets.
    pub fn encrypt<'a, Into, Iter>(&self, packets: Into)
    where
        Iter: ExactSizeIterator<Item = &'a mut PacketMut>,
        Into: IntoIterator<Item = &'a mut PacketMut, IntoIter = Iter>,
    {
        let packets = packets.into_iter();
        let nonce = self.nonce.batch(packets.len());
        for (packet, nonce) in packets.zip(nonce) {
            // Session encryption only fails if the provided packet can't grow, which ours can.
            self.cipher
                .encrypt_in_place(nonce.as_ref(), &[], packet)
                .unwrap();
            let header = TransportDataHeader {
                receiver_id: self.id,
                nonce: nonce.counter,
                ..Default::default()
            };
            packet.grow_front(size_of::<TransportDataHeader>());
            // Write only fails if the packet is too small, and we just extended it to have
            // enough space.
            header.write_to_prefix(packet.as_mut()).unwrap();
        }
    }

    /// Whether a key rotation should be initiated — on whichever of TIME or VOLUME is reached first,
    /// matching wireguard-go (`REKEY_AFTER_TIME` 120s OR `REKEY_AFTER_MESSAGES`). The volume term
    /// makes rotation message-aware so the nonce never approaches the hard ceiling.
    pub fn stale(&self, now: Instant) -> bool {
        now.duration_since(self.created) > REKEY_AFTER_TIME
            || self.nonce.count() >= REKEY_AFTER_MESSAGES
    }

    /// Whether this session must no longer send — TIME past [`REJECT_AFTER_TIME`] (180s) OR the
    /// message count at/over the hard [`REJECT_AFTER_MESSAGES`] ceiling (wireguard-go parity). Past
    /// this the caller drops the send session and triggers a fresh handshake.
    pub fn expired(&self, now: Instant) -> bool {
        now.duration_since(self.created) > REJECT_AFTER_TIME
            || self.nonce.count() >= REJECT_AFTER_MESSAGES
    }

    /// Whether this keypair is old enough to warrant a receive-path rekey
    /// ([`REKEY_AFTER_TIME_RECEIVING`] = 165s; Go `keepKeyFreshReceiving`). The send and receive
    /// sessions of a pair share a `created` instant, so the transmit session's age is the keypair
    /// age the receive-rekey decision needs. The caller additionally gates on being the initiator
    /// and a once-per-keypair guard.
    pub fn needs_receive_rekey(&self, now: Instant) -> bool {
        now.duration_since(self.created) > REKEY_AFTER_TIME_RECEIVING
    }
}

/// Established session that can only receive.
pub struct ReceiveSession {
    cipher: ChaCha20Poly1305,
    id: SessionId,
    created: Instant,
    window: ReplayWindow,
}

impl Debug for ReceiveSession {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceiveSession")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl ReceiveSession {
    pub fn new(key: SessionKey, id: SessionId, now: Instant) -> Self {
        ReceiveSession {
            cipher: ChaCha20Poly1305::new(&key),
            id,
            created: now,
            window: ReplayWindow::default(),
        }
    }

    /// Decrypt wireguard transport data messages in place.
    ///
    /// Returns the packets which successfully decrypted.
    pub fn decrypt(&mut self, mut packets: Vec<PacketMut>) -> Vec<PacketMut> {
        packets.retain_mut(|packet| self.decrypt_one(packet));
        packets
    }

    /// Decrypt a wireguard transport data message in place.
    #[tracing::instrument(skip_all, fields(session_id = ?self.id))]
    #[must_use]
    fn decrypt_one(&mut self, pkt: &mut PacketMut) -> bool {
        let Ok((header, _)) = TransportDataHeader::try_ref_from_prefix(pkt.as_ref()) else {
            tracing::warn!("decode as transport packet failed");
            return false;
        };

        let _guard = tracing::trace_span!("header_parsed", ?header).entered();

        if header.receiver_id != self.id {
            // Technically an unnecessary check, because a bespoke session is created for each
            // session ID, with different AEAD keys. So, if the caller mistakenly hands the wrong
            // packet to a session, it'll always fail to decrypt below. But, comparing one u32
            // is cheaper than getting partway through AEAD decryption before finding that the
            // authenticator is wrong, so might as well take the shortcut.
            //
            // Passing the wrong packet to a session is also a programmer error, so scream a bit
            // more loudly in debug builds.
            tracing::error!(message_session_id = ?header.receiver_id, "wrong receiver id");

            debug_assert!(
                false,
                "decrypt_in_place given packet with wrong receiver ID"
            );

            return false;
        }

        let counter = header.nonce.into();
        if !self.window.check(counter) {
            tracing::trace!("reject old/replayed packet");
            return false;
        }

        let nonce = Nonce::from(header.nonce);
        pkt.truncate_front(size_of::<TransportDataHeader>());

        match self.cipher.decrypt_in_place(nonce.as_ref(), &[], pkt) {
            Ok(_) => {
                self.window.set(counter);
                true
            }
            Err(e) => {
                tracing::error!(err = %e, "decryption failed");
                false
            }
        }
    }

    pub fn id(&self) -> SessionId {
        self.id
    }

    /// Whether this receive session is too old to accept inbound transport data. Uses
    /// [`REJECT_AFTER_TIME_RECV`], which now equals `REJECT_AFTER_TIME` (180s) — matching the
    /// transmit side and the WireGuard spec, once the receive-triggered rekey (#26) made the
    /// previously-lenient 240s bound unnecessary. See [`REJECT_AFTER_TIME_RECV`].
    pub fn expired(&self, now: Instant) -> bool {
        now.duration_since(self.created) > REJECT_AFTER_TIME_RECV
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::Message;

    fn unhex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "odd hex length");
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("valid hex"))
            .collect()
    }

    /// Cross-implementation KAT: the WireGuard transport-data frame uses ChaCha20Poly1305 with a
    /// 12-byte nonce of `[0,0,0,0] || counter.to_le_bytes()` (LITTLE-endian — the counterpart of
    /// the control-plane BIG-endian nonce) and empty AAD. These reference ciphertexts come from
    /// Go `golang.org/x/crypto/chacha20poly1305` v0.52.0 (go1.26.4); generator
    /// `tests/vectors/gen/wg`. Proves our zerocopy `Nonce {_zero: U32, counter: U64(LE)}` packing
    /// is byte-identical to wireguard-go's transport nonce, so a peer running Go can decrypt our
    /// transport frames (and vice-versa). A divergence here fails closed (AEAD auth failure) but
    /// silently breaks data-plane interop.
    #[test]
    fn transport_nonce_matches_go_kat() {
        // (key_hex, counter, pt_hex, expected ciphertext||tag hex), empty AAD.
        const VECTORS: &[(&str, u64, &str, &str)] = &[
            (
                "1111111111111111111111111111111111111111111111111111111111111111",
                0,
                "78797a7a79",
                "ddc5edec00deab2e13b1c722647aba8e9bd1d6574e",
            ),
            (
                "1111111111111111111111111111111111111111111111111111111111111111",
                1,
                "706c6f766572",
                "a148eec08017563c51a807ab84fa67a6071a0aaf8a91",
            ),
            (
                "1111111111111111111111111111111111111111111111111111111111111111",
                0x0102030405060708,
                "deadbeef",
                "6adef61326b21fac9641232622ec6e35c845e0e2",
            ),
        ];

        for (i, (key_hex, counter, pt_hex, ct_hex)) in VECTORS.iter().enumerate() {
            let key_bytes: [u8; 32] = unhex(key_hex).try_into().expect("32-byte key");
            let pt = unhex(pt_hex);
            let expected = unhex(ct_hex);

            // Build a TransmitSession whose first emitted nonce equals `counter` by pre-advancing
            // the generator. `batch(n)` consumes n consecutive nonces starting at the current
            // value, so reserving `counter` of them leaves the next packet on `counter`.
            let session =
                TransmitSession::new(key_bytes.into(), SessionId::from(0), Instant::now());
            let _ = session.nonce.batch(*counter as usize);

            let mut pkt = [PacketMut::from(pt.as_slice())];
            session.encrypt(&mut pkt);

            // After encrypt: packet = TransportDataHeader(16) || ciphertext || tag(16).
            let hdr_len = size_of::<TransportDataHeader>();
            let (header, body) = pkt[0].as_ref().split_at(hdr_len);

            // Sanity: the header carries the LE counter we expect.
            let parsed = TransportDataHeader::try_ref_from_prefix(header).unwrap().0;
            assert_eq!(
                u64::from(parsed.nonce),
                *counter,
                "vector {i}: header nonce mismatch"
            );

            assert_eq!(
                body, expected,
                "vector {i}: ciphertext||tag diverges from Go reference"
            );
        }
    }

    #[test]
    fn test_session() {
        let k: [u8; 32] = rand::random();
        let session = SessionId::random();
        let now = Instant::now();
        let send = TransmitSession::new(k.into(), session, now);
        let mut recv = ReceiveSession::new(k.into(), session, now);

        const CLEARTEXT: &[u8] = b"foobar";
        let mut pkt = [PacketMut::from(CLEARTEXT)];

        send.encrypt(&mut pkt);
        assert_eq!(pkt[0].len(), 38);
        let Ok(Message::TransportDataHeader(msg)) = Message::try_from(pkt[0].as_ref()) else {
            panic!("packet is not a valid TransportData message");
        };
        assert_eq!(msg.receiver_id, session);
        assert_eq!(u64::from(msg.nonce), 0);

        assert!(recv.decrypt_one(&mut pkt[0]));
        assert_eq!(pkt[0].as_ref(), CLEARTEXT);

        send.encrypt(&mut pkt);
        assert_eq!(pkt[0].len(), 38);
        let Ok(Message::TransportDataHeader(msg)) = Message::try_from(pkt[0].as_ref()) else {
            panic!("packet is not a valid TransportData message");
        };
        assert_eq!(msg.receiver_id, session);
        assert_eq!(u64::from(msg.nonce), 1);

        assert!(recv.decrypt_one(&mut pkt[0]));
        assert_eq!(pkt[0].as_ref(), CLEARTEXT);
    }

    #[test]
    fn session_timers() {
        let k: [u8; 32] = rand::random();
        let session = SessionId::random();
        let now = Instant::now();
        let send = TransmitSession::new(k.into(), session, now);
        let recv = ReceiveSession::new(k.into(), session, now);

        // stale() is keyed on REKEY_AFTER_TIME (120s): not stale before, stale after.
        assert!(!send.stale(now));
        assert!(!send.stale(now + Duration::from_secs(100)));
        assert!(send.stale(now + Duration::from_secs(130)));
        assert!(send.stale(now + Duration::from_secs(250)));

        // expired() is keyed on REJECT_AFTER_TIME (180s): not expired well below the line,
        // expired well above it. 130s sits below 180s (so still live — rekey, driven by
        // stale() at 120s, has fired by now but the session is not yet dead); 250s is above.
        assert!(!send.expired(now));
        assert!(!send.expired(now + Duration::from_secs(100)));
        assert!(!send.expired(now + Duration::from_secs(130)));
        assert!(send.expired(now + Duration::from_secs(250)));

        // ReceiveSession::expired() now uses REJECT_AFTER_TIME_RECV == REJECT_AFTER_TIME (180s),
        // matching the transmit side and the WireGuard spec. (It was a lenient 240s only while the
        // fork lacked a receive-triggered rekey; now that receive-rekey fires at 165s — see below —
        // a live inbound session rehandshakes before the 180s ceiling, so the spec bound is safe.)
        // The recv and send bounds now agree: both live at 130s, both expired at 200s.
        assert!(!recv.expired(now));
        assert!(!recv.expired(now + Duration::from_secs(100)));
        assert!(!recv.expired(now + Duration::from_secs(130)));
        assert!(send.expired(now + Duration::from_secs(200)));
        assert!(recv.expired(now + Duration::from_secs(200)));
        assert!(recv.expired(now + Duration::from_secs(250)));

        // needs_receive_rekey() is keyed on REKEY_AFTER_TIME_RECEIVING (165s = 180 − 10 − 5, Go's
        // keepKeyFreshReceiving threshold): not yet at 130s (still well inside the keypair's life),
        // true at 170s — ~10s before the 180s receive ceiling, so an initiator-side, mostly-inbound
        // session enqueues a fresh handshake before its receive keys hard-expire.
        assert!(!send.needs_receive_rekey(now + Duration::from_secs(130)));
        assert!(!send.needs_receive_rekey(now + Duration::from_secs(160)));
        assert!(send.needs_receive_rekey(now + Duration::from_secs(170)));
    }

    /// Rotation/expiry are VOLUME-aware, not only time-aware (wireguard-go parity): a session that
    /// has sent past `REKEY_AFTER_MESSAGES` is `stale()` (rekey) even when young, and one past
    /// `REJECT_AFTER_MESSAGES` is `expired()` even at t=0 — so the nonce can never reach the u64
    /// ceiling. Seeded directly because the thresholds are otherwise ~2^64 packets away.
    #[test]
    fn rotation_and_expiry_are_volume_aware() {
        let k: [u8; 32] = rand::random();
        let now = Instant::now();

        // Just below the rekey-volume threshold: a fresh session is neither stale nor expired.
        let send = TransmitSession::new(k.into(), SessionId::random(), now);
        send.nonce.set_count(REKEY_AFTER_MESSAGES - 1);
        assert!(
            !send.stale(now),
            "below the volume threshold and young: not stale"
        );
        assert!(!send.expired(now));

        // At/over the rekey-volume threshold (but below reject): stale → rekey, not yet expired.
        let send = TransmitSession::new(k.into(), SessionId::random(), now);
        send.nonce.set_count(REKEY_AFTER_MESSAGES);
        assert!(
            send.stale(now),
            "at REKEY_AFTER_MESSAGES: must rotate even when young"
        );
        assert!(
            !send.expired(now),
            "rekey volume is below the reject ceiling"
        );

        // At the hard reject ceiling: expired even at t=0 (the send session must stop).
        let send = TransmitSession::new(k.into(), SessionId::random(), now);
        send.nonce.set_count(REJECT_AFTER_MESSAGES);
        assert!(
            send.expired(now),
            "at REJECT_AFTER_MESSAGES: must stop sending"
        );
    }

    /// The Go-parity ordering invariant: rekey volume is below reject volume, so a session rotates
    /// before it can hit the hard ceiling. A compile-time check (the values are consts).
    const _: () = assert!(REKEY_AFTER_MESSAGES < REJECT_AFTER_MESSAGES);

    /// The nonce generator clamps at the u64 ceiling instead of panicking (defense-in-depth on the
    /// send path — a panic there can become UB across the FFI boundary). Past the ceiling the batch
    /// yields no further nonces, so the caller drops the packet rather than crashing.
    #[test]
    fn nonce_generator_clamps_at_ceiling_without_panic() {
        let ng = NonceGenerator::default();
        ng.set_count(u64::MAX - 2);
        // Reserve more than remain: must not panic; the count clamps to u64::MAX.
        let mut iter = ng.batch(10);
        // Only the two nonces below the ceiling are yielded (u64::MAX-2, u64::MAX-1).
        assert_eq!(
            iter.next().map(|n| u64::from(n.counter)),
            Some(u64::MAX - 2)
        );
        assert_eq!(
            iter.next().map(|n| u64::from(n.counter)),
            Some(u64::MAX - 1)
        );
        assert_eq!(iter.next().map(|n| u64::from(n.counter)), None);
        assert_eq!(ng.count(), u64::MAX, "the counter clamps at the ceiling");
    }

    /// A persistent keepalive is an *empty* authenticated packet. Emitting one must NOT push the
    /// session's rotation/expiry clock forward — those track session age from the handshake
    /// (`created`), not the time of the last send (the boringtun `if !src.is_empty()` invariant).
    /// If a keepalive reset the clock it would mask a genuinely dead peer and starve rekey. The
    /// session's staleness/expiry is keyed on `created`, which encryption never touches, so any
    /// number of keepalive sends leaves the `stale`/`expired` schedule byte-for-byte unchanged.
    #[test]
    fn keepalive_does_not_advance_rotation_timers() {
        let k: [u8; 32] = rand::random();
        let session = SessionId::random();
        let now = Instant::now();
        let send = TransmitSession::new(k.into(), session, now);

        // Emit several empty keepalives (the `encapsulate(&[])` path the endpoint uses).
        for _ in 0..5 {
            let mut keepalive = [PacketMut::new(0)];
            send.encrypt(&mut keepalive);
            // It really is an (encrypted) empty payload: header(16) + tag(16), no plaintext body.
            assert_eq!(keepalive[0].len(), size_of::<TransportDataHeader>() + 16);
        }

        // Rotation/expiry are still measured from `created`, exactly as in `session_timers`.
        assert!(!send.stale(now));
        assert!(!send.stale(now + Duration::from_secs(100)));
        assert!(send.stale(now + Duration::from_secs(130)));
        assert!(!send.expired(now + Duration::from_secs(130)));
        assert!(send.expired(now + Duration::from_secs(250)));
    }
}
