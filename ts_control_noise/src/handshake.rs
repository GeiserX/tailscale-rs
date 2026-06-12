use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::BytesMut;
use noise_protocol::{HandshakeState, HandshakeStateBuilder, patterns::noise_ik};
use noise_rust_crypto::{Blake2s, X25519, sensitive::Sensitive};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio_util::codec::Framed;
use ts_hexdump::{AsHexExt, Case};
use ts_keys::{MachinePrivateKey, MachinePublicKey};
use zerocopy::{IntoBytes, TryFromBytes};
use zeroize::Zeroizing;

use crate::{
    ChaCha20Poly1305BigEndian, Error,
    codec::BiCodec,
    framed_io::FramedIo,
    messages::{Header, Initiation, MessageType, RESPONSE_PAYLOAD_LEN},
};

type Cipher = ChaCha20Poly1305BigEndian;
type Codec = BiCodec<Cipher, Cipher>;
type NoiseFramed<T> = Framed<T, Codec>;
type WrappedIo<T> = FramedIo<NoiseFramed<T>, BytesMut>;

/// Noise handshake state.
pub struct Handshake {
    state: HandshakeState<X25519, Cipher, Blake2s>,
}

impl Handshake {
    /// Create a new handshake with the given `prologue` and using the specified keys.
    ///
    /// `capability_version` is used to indicate our capabilities to the control server.
    ///
    /// The second returned value is a base64-encoded payload that should be transmitted
    /// to the control server in order to start the handshake.
    pub fn initialize(
        prologue: &str,
        node_machine_private_key: &MachinePrivateKey,
        control_public_key: &MachinePublicKey,
        capability_version: ts_capabilityversion::CapabilityVersion,
    ) -> (Self, String) {
        let key = Sensitive::from(Zeroizing::from(node_machine_private_key.to_bytes()));

        let mut builder = HandshakeStateBuilder::new();
        builder.set_pattern(noise_ik());
        builder.set_is_initiator(true);
        builder.set_rs(control_public_key.to_bytes());
        builder.set_prologue(prologue.as_bytes());
        builder.set_s(key);

        let mut state = builder.build_handshake_state();

        let overhead = state.get_next_message_overhead();
        let mut ciphertext = [0u8; Initiation::PAYLOAD_LEN];
        state
            .write_message(&[], &mut ciphertext)
            .expect("initiation payload size too small");
        let init_msg = Initiation::new(capability_version.into(), overhead as u16, ciphertext);

        (Self { state }, STANDARD.encode(init_msg.as_bytes()))
    }

    /// Complete the handshake by reading the control server's response.
    pub async fn complete<T: AsyncRead + Unpin>(
        &mut self,
        mut conn: T,
    ) -> Result<WrappedIo<T>, Error> {
        let mut hdr_bytes = [0u8; 3];
        conn.read_exact(&mut hdr_bytes[..]).await?;

        let hdr = Header::try_ref_from_bytes(&hdr_bytes)?;

        // Validate the header BEFORE allocating on its length. `hdr.len` is an attacker-controlled
        // `u16` straight off the wire; a malicious/buggy control server could otherwise force a
        // 64 KiB zeroed allocation per handshake attempt. Go reads the response into a fixed
        // 51-byte `responseMessage` and rejects a wrong type/length before trusting it; match that —
        // the Noise IK response (message 2) body is exactly `RESPONSE_PAYLOAD_LEN` (48) bytes, so
        // anything else is malformed. The record layer already caps its reads (codec.rs); this
        // brings the handshake read to the same fail-closed discipline.
        if hdr.typ != MessageType::Response {
            return Err(Error::BadFormat);
        }
        if hdr.len.get() as usize != RESPONSE_PAYLOAD_LEN {
            return Err(Error::BadFormat);
        }

        let mut packet = BytesMut::zeroed(hdr.len.get() as _);
        conn.read_exact(&mut packet).await?;

        tracing::trace!(
            ?hdr,
            "response body from control:\n{}",
            packet
                .iter()
                .hexdump(Case::Lower)
                .flatten()
                .collect::<String>()
        );

        let data = self.state.read_message_vec(&packet)?;
        if !data.is_empty() || !self.state.completed() {
            return Err(Error::HandshakeFailed);
        }

        let (tx, rx) = self.state.get_ciphers();

        Ok(FramedIo::new(Framed::new(
            conn,
            BiCodec {
                tx: tx.into(),
                rx: rx.into(),
            },
        )))
    }
}

#[cfg(test)]
mod tests {
    use ts_keys::MachinePrivateKey;

    use super::*;

    fn test_handshake() -> Handshake {
        let node_sk = MachinePrivateKey::random();
        let control_sk = MachinePrivateKey::random();
        let (hs, _init) = Handshake::initialize(
            "Tailscale Control Protocol v1",
            &node_sk,
            &control_sk.public_key(),
            ts_capabilityversion::CapabilityVersion::CURRENT,
        );
        hs
    }

    /// A handshake response whose `Header::len` is oversized (here 0xFFFF) must be rejected as
    /// `BadFormat` WITHOUT allocating on the attacker-controlled length. The header is validated
    /// (type == Response, len == RESPONSE_PAYLOAD_LEN) before the `BytesMut::zeroed` read, so a
    /// malicious/buggy control server can't make the client allocate ~64 KiB per handshake attempt.
    #[tokio::test]
    async fn oversized_response_len_is_rejected_before_alloc() {
        let mut hs = test_handshake();
        // 3-byte header: type=Response(0x2), len=0xFFFF (big-endian). No body follows — if the code
        // tried to read `len` bytes it would block/EOF; rejecting on the header means it never does.
        let header = [MessageType::Response as u8, 0xFF, 0xFF];
        match hs.complete(&header[..]).await {
            Err(Error::BadFormat) => {}
            Err(e) => panic!("expected BadFormat, got {e:?}"),
            Ok(_) => panic!("an oversized response length must be rejected"),
        }
    }

    /// A response with the correct length but the WRONG type (here Record) is rejected as
    /// `BadFormat`, before any body read.
    #[tokio::test]
    async fn wrong_response_type_is_rejected() {
        let mut hs = test_handshake();
        let header = [
            MessageType::Record as u8,
            0x00,
            RESPONSE_PAYLOAD_LEN as u8, // a plausible length, but the type is wrong
        ];
        match hs.complete(&header[..]).await {
            Err(Error::BadFormat) => {}
            Err(e) => panic!("expected BadFormat, got {e:?}"),
            Ok(_) => panic!("a non-Response handshake reply must be rejected"),
        }
    }
}
