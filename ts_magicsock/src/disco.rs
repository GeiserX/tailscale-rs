//! Building and parsing disco messages on the wire.
//!
//! This layer sits directly on top of the [`ts_disco_protocol`] codec (which already
//! implements the [`crypto_box`][crypto_box]/SalsaBox sealing and the zerocopy message
//! framing). It adds the small amount of glue needed to drive disco over a UDP socket:
//! constructing sealed [`Ping`]/[`Pong`] datagrams and demultiplexing inbound datagrams
//! into typed messages plus the sender's disco key.
//!
//! [crypto_box]: https://docs.rs/crypto_box

use core::net::SocketAddr;

use rand::Rng;
use ts_disco_protocol::{
    CallMeMaybe, Endpoint, Header, MessageType, Packet, Ping, Pong, is_disco_message,
};
use ts_keys::{DiscoPrivateKey, DiscoPublicKey, NodePublicKey};
use zerocopy::IntoBytes;

use crate::error::DiscoError;

/// A per-ping transaction id (12 bytes, matching the wire format).
pub type TxId = [u8; 12];

/// Generate a fresh random transaction id for a ping.
pub fn random_tx_id() -> TxId {
    let mut id = [0u8; 12];
    rand::rng().fill_bytes(&mut id);
    id
}

/// Report whether `buf` is a disco datagram (as opposed to a WireGuard one).
///
/// This is the demux predicate shared by every reader of the underlay socket: the disco
/// magic prefix never collides with a WireGuard message type byte, so an exact prefix
/// match cleanly separates control-of-path traffic from data-plane traffic.
pub fn looks_like_disco(buf: &[u8]) -> bool {
    is_disco_message(buf)
}

/// Serialize and seal a disco [`Ping`] addressed to `receiver`.
///
/// The returned bytes are ready to be written to the socket. `our_node_key` is embedded so
/// the receiver can bind our disco key to our node key 1:1 (see [`Ping::node_key`]).
pub fn seal_ping(
    our_disco: &DiscoPrivateKey,
    our_node_key: NodePublicKey,
    receiver: &DiscoPublicKey,
    tx_id: TxId,
) -> Result<Vec<u8>, DiscoError> {
    let mut buf = vec![0u8; Packet::size_for_message(Ping::size_with_padding(0))];

    let pkt = Packet::init_from_bytes::<Ping>(&mut buf, |ping| {
        ping.tx_id = tx_id;
        ping.node_key = our_node_key;
    })?;

    pkt.encrypt_in_place(our_disco, receiver, random_nonce())?;

    Ok(buf)
}

/// Serialize and seal a disco [`Pong`] addressed to `receiver`.
///
/// `src` is the address we observed the corresponding ping arriving from; echoing it back
/// is how the pinger learns its own reflexive (STUN-equivalent) address on this path.
pub fn seal_pong(
    our_disco: &DiscoPrivateKey,
    receiver: &DiscoPublicKey,
    tx_id: TxId,
    src: SocketAddr,
) -> Result<Vec<u8>, DiscoError> {
    let mut buf = vec![0u8; Packet::size_for_message(Pong::size())];

    let pkt = Packet::init_from_bytes::<Pong>(&mut buf, |pong| {
        pong.tx_id = tx_id;
        pong.src = Endpoint::from(src);
    })?;

    pkt.encrypt_in_place(our_disco, receiver, random_nonce())?;

    Ok(buf)
}

/// Serialize and seal a disco [`CallMeMaybe`] addressed to `receiver`.
///
/// `endpoints` are the candidate addresses we believe we're reachable on; the peer will
/// disco-ping them to try to open a direct path. This message is normally sent over DERP to
/// bootstrap hole-punching.
pub fn seal_call_me_maybe(
    our_disco: &DiscoPrivateKey,
    receiver: &DiscoPublicKey,
    endpoints: &[SocketAddr],
) -> Result<Vec<u8>, DiscoError> {
    let mut buf =
        vec![0u8; Packet::size_for_message(CallMeMaybe::size_for_endpoint_count(endpoints.len()))];

    let pkt = Packet::init_from_bytes::<CallMeMaybe>(&mut buf, |cmm| {
        for (i, ep) in endpoints.iter().enumerate() {
            cmm.endpoints[i] = Endpoint::from(*ep);
        }
    })?;

    pkt.encrypt_in_place(our_disco, receiver, random_nonce())?;

    Ok(buf)
}

/// A disco message decoded from the wire, together with the disco key that sent it.
#[derive(Debug)]
pub enum Inbound {
    /// A ping: the peer wants us to confirm this path. We should reply with a pong.
    Ping {
        /// The disco key that sealed the ping.
        sender: DiscoPublicKey,
        /// The node key the sender claims (to be cross-checked against the netmap).
        claimed_node_key: NodePublicKey,
        /// The ping's transaction id, to be echoed in the pong.
        tx_id: TxId,
    },
    /// A pong: the peer confirmed a path we pinged.
    Pong {
        /// The disco key that sealed the pong.
        sender: DiscoPublicKey,
        /// The transaction id of the ping this answers.
        tx_id: TxId,
        /// The address the peer saw our ping arrive from (our reflexive address).
        src: SocketAddr,
    },
    /// A call-me-maybe: the peer is asking us to open a path to its listed endpoints.
    CallMeMaybe {
        /// The disco key that sealed the message.
        sender: DiscoPublicKey,
        /// The endpoints the peer believes it is reachable on.
        endpoints: Vec<SocketAddr>,
    },
}

/// Parse and open an inbound disco datagram.
///
/// `buf` must be a mutable copy of the received bytes (decryption happens in place). Returns
/// an error if the datagram is not a valid disco message or cannot be opened with our key.
pub fn open(our_disco: &DiscoPrivateKey, buf: &mut [u8]) -> Result<Inbound, DiscoError> {
    let pkt = Packet::from_encrypted_bytes_mut(buf)?;
    let sender = pkt.header().sender_pub();

    let plain = pkt.decrypt_in_place(our_disco)?;

    match plain.ty() {
        Some(MessageType::Ping) => {
            let ping = plain.as_msg::<Ping>().ok_or(DiscoError::Malformed)?;
            Ok(Inbound::Ping {
                sender,
                claimed_node_key: ping.node_key,
                tx_id: ping.tx_id,
            })
        }
        Some(MessageType::Pong) => {
            let pong = plain.as_msg::<Pong>().ok_or(DiscoError::Malformed)?;
            Ok(Inbound::Pong {
                sender,
                tx_id: pong.tx_id,
                src: pong.src.socket_addr(),
            })
        }
        Some(MessageType::CallMeMaybe) => {
            let cmm = plain.as_msg::<CallMeMaybe>().ok_or(DiscoError::Malformed)?;
            let endpoints = cmm.endpoints.iter().map(|e| e.socket_addr()).collect();
            Ok(Inbound::CallMeMaybe { sender, endpoints })
        }
        _ => Err(DiscoError::UnknownMessageType),
    }
}

fn random_nonce() -> [u8; Header::NONCE_LEN] {
    let mut nonce = [0u8; Header::NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

/// Test helper: assert the disco magic prefix is what every demux site keys on. Kept here
/// so a wire-format change is caught by this crate's own tests, not only the protocol crate.
#[allow(dead_code)]
pub(crate) fn magic_prefix() -> &'static [u8] {
    Header::MAGIC.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (DiscoPrivateKey, DiscoPublicKey) {
        let sk = DiscoPrivateKey::random();
        let pk = sk.public_key();
        (sk, pk)
    }

    #[test]
    fn ping_roundtrips_and_demuxes_as_disco() {
        let (a_sk, _a_pk) = keypair();
        let (b_sk, b_pk) = keypair();
        let node_key = ts_keys::NodePrivateKey::random().public_key();
        let tx = random_tx_id();

        let wire = seal_ping(&a_sk, node_key, &b_pk, tx).unwrap();
        assert!(looks_like_disco(&wire), "ping must demux as disco");

        let mut buf = wire.clone();
        match open(&b_sk, &mut buf).unwrap() {
            Inbound::Ping {
                sender,
                claimed_node_key,
                tx_id,
            } => {
                assert_eq!(sender, a_sk.public_key());
                assert_eq!(claimed_node_key, node_key);
                assert_eq!(tx_id, tx);
            }
            other => panic!("expected ping, got {other:?}"),
        }
    }

    #[test]
    fn pong_roundtrips_and_echoes_src() {
        let (a_sk, _a_pk) = keypair();
        let (b_sk, b_pk) = keypair();
        let tx = random_tx_id();
        let src: SocketAddr = "203.0.113.7:41641".parse().unwrap();

        let wire = seal_pong(&a_sk, &b_pk, tx, src).unwrap();
        let mut buf = wire;
        match open(&b_sk, &mut buf).unwrap() {
            Inbound::Pong {
                sender,
                tx_id,
                src: got,
            } => {
                assert_eq!(sender, a_sk.public_key());
                assert_eq!(tx_id, tx);
                assert_eq!(got, src);
            }
            other => panic!("expected pong, got {other:?}"),
        }
    }

    #[test]
    fn call_me_maybe_roundtrips() {
        let (a_sk, _a_pk) = keypair();
        let (b_sk, b_pk) = keypair();
        let eps: Vec<SocketAddr> = vec![
            "203.0.113.7:41641".parse().unwrap(),
            "198.51.100.2:3478".parse().unwrap(),
        ];

        let wire = seal_call_me_maybe(&a_sk, &b_pk, &eps).unwrap();
        assert!(looks_like_disco(&wire), "call-me-maybe must demux as disco");

        let mut buf = wire;
        match open(&b_sk, &mut buf).unwrap() {
            Inbound::CallMeMaybe { sender, endpoints } => {
                assert_eq!(sender, a_sk.public_key());
                assert_eq!(endpoints, eps);
            }
            other => panic!("expected call-me-maybe, got {other:?}"),
        }
    }

    #[test]
    fn wrong_key_fails_to_open() {
        let (a_sk, _a_pk) = keypair();
        let (_b_sk, b_pk) = keypair();
        let (c_sk, _c_pk) = keypair();
        let node_key = ts_keys::NodePrivateKey::random().public_key();

        let wire = seal_ping(&a_sk, node_key, &b_pk, random_tx_id()).unwrap();
        let mut buf = wire;
        // c is not the intended receiver: opening must fail (authenticated encryption).
        assert!(open(&c_sk, &mut buf).is_err());
    }

    #[test]
    fn non_disco_bytes_are_not_disco() {
        // A WireGuard data packet starts with type byte 0x04, never the disco magic.
        let wg = [0x04u8, 0, 0, 0, 1, 2, 3, 4];
        assert!(!looks_like_disco(&wg));
    }
}
