use std::io::ErrorKind;

use bytes::{Buf, BufMut, BytesMut};
use noise_protocol::{Cipher, CipherState};
use tokio_util::codec::{Decoder, Encoder};
use zerocopy::{IntoBytes, TryCastError, TryFromBytes, U16};

use crate::messages::{Header, MessageType};

/// The maximum wire size of a message to control over noise.
pub const MAX_MESSAGE_SIZE: usize = 4096;

/// Control noise codec that uses a different cipher state for the up and down directions.
///
/// Just a wrapper containing two [`Codec`]s, one of which provides [`Encoder`] and the
/// other [`Decoder`].
pub struct BiCodec<Tx, Rx>
where
    Tx: Cipher,
    Rx: Cipher,
{
    /// The transmit codec, used for encoding messages to control.
    pub tx: Codec<Tx>,
    /// The receive codec, used for decoding messages from control.
    pub rx: Codec<Rx>,
}

impl<B, Tx, Rx> Encoder<B> for BiCodec<Tx, Rx>
where
    B: AsRef<[u8]>,
    Tx: Cipher,
    Rx: Cipher,
{
    type Error = <Codec<Tx> as Encoder<B>>::Error;

    fn encode(&mut self, item: B, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.tx.encode(item, dst)
    }
}

impl<Tx, Rx> Decoder for BiCodec<Tx, Rx>
where
    Tx: Cipher,
    Rx: Cipher,
{
    type Item = <Codec<Rx> as Decoder>::Item;
    type Error = <Codec<Rx> as Decoder>::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.rx.decode(src)
    }
}

/// Codec supporting encrypting and decrypting data according to the control noise protocol
/// using the specified cipher state.
pub struct Codec<C>
where
    C: Cipher,
{
    /// The cipher state to use to encode and decode message payloads.
    pub cipher_state: CipherState<C>,
}

impl<C> From<CipherState<C>> for Codec<C>
where
    C: Cipher,
{
    fn from(value: CipherState<C>) -> Self {
        Codec {
            cipher_state: value,
        }
    }
}

impl<B, C> Encoder<B> for Codec<C>
where
    C: Cipher,
    B: AsRef<[u8]>,
{
    type Error = std::io::Error;

    fn encode(&mut self, b: B, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let b = b.as_ref();
        let max_data_chunk = MAX_MESSAGE_SIZE - (size_of::<Header>() + C::tag_len());

        for chunk in b.chunks(max_data_chunk) {
            let hdr = Header {
                typ: MessageType::Record,
                len: U16::new(chunk.len() as u16 + C::tag_len() as u16),
            };

            dst.put(hdr.as_bytes());

            let data_start = dst.len();

            dst.put(chunk);
            dst.put_bytes(0, C::tag_len());

            self.cipher_state
                .encrypt_in_place(&mut dst[data_start..], chunk.len());
        }

        Ok(())
    }
}

impl<C> Decoder for Codec<C>
where
    C: Cipher,
{
    type Error = std::io::Error;
    type Item = BytesMut;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let (header, rest_len) = match Header::try_ref_from_prefix(src) {
            Ok((hdr, rest)) => (*hdr, rest.len()),
            Err(TryCastError::Size(_)) => return Ok(None),
            Err(e) => {
                tracing::error!(error = %e, "parsing control message header");
                return Err(ErrorKind::InvalidData.into());
            }
        };
        let len = header.len.get() as usize;

        // A frame's declared body length must fit one Noise message. Go `controlbase` rejects
        // `headerLen + length > maxMessageSize` (i.e. body `> maxMessageSize - 3 = maxCiphertextSize
        // = 4093`), since its cap counts the 3-byte header. Match that exactly: the body alone must
        // be `<= MAX_MESSAGE_SIZE - size_of::<Header>()`. The encoder never emits a chunk larger than
        // this (`max_data_chunk` above subtracts the header + tag), so a bigger `len` is a
        // malformed/hostile frame — reject it rather than `split_to` a large body.
        const MAX_BODY_LEN: usize = MAX_MESSAGE_SIZE - size_of::<Header>();
        if len > MAX_BODY_LEN {
            tracing::error!(len, max = MAX_BODY_LEN, "control message frame too large");
            return Err(ErrorKind::InvalidData.into());
        }

        if rest_len < len {
            return Ok(None);
        }

        src.advance(size_of::<Header>());
        let mut body = src.split_to(len);

        match header.typ {
            MessageType::Record => {
                // A `Record` body is ciphertext + a `tag_len()`-byte AEAD tag, so a well-formed frame
                // is always at least `tag_len()` bytes (the encoder enforces this). Reject a shorter
                // body here: `decrypt_in_place` asserts `ciphertext_len >= tag_len()` and would
                // otherwise PANIC on a control-supplied short `Record` frame (e.g. a 3-byte header
                // declaring `len = 0`). Go `controlbase` surfaces a decode error (the AEAD `Open`
                // fails) rather than crashing; mirror that — turn the hostile/buggy short frame into a
                // clean `InvalidData` error, the same path the over-max and decrypt-failure cases take.
                if len < C::tag_len() {
                    tracing::error!(
                        len,
                        tag_len = C::tag_len(),
                        "control Record frame shorter than the AEAD tag"
                    );
                    return Err(ErrorKind::InvalidData.into());
                }
                match self.cipher_state.decrypt_in_place(&mut body, len) {
                    Ok(n) => body.truncate(n),
                    Err(()) => {
                        tracing::error!("decryption failed");
                        return Err(ErrorKind::InvalidData.into());
                    }
                }

                Ok(Some(body))
            }
            MessageType::Error => {
                let error_message =
                    core::str::from_utf8(&body).unwrap_or("<invalid utf-8 in error body>");

                tracing::error!(
                    error_message,
                    error_body_len = body.len(),
                    "error received from control"
                );
                Ok(None)
            }
            typ => {
                tracing::error!(message_type = ?typ, "unexpected message type from control");
                Err(ErrorKind::InvalidData.into())
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::sync::LazyLock;

    use noise_protocol::Cipher as _;
    use proptest::{collection::vec, prelude::*};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::codec::Framed;

    use super::*;

    type Cipher = crate::ChaCha20Poly1305BigEndian;

    fn init_codec_pair(key: [u8; 32], nonce: u64) -> (Codec<Cipher>, Codec<Cipher>) {
        let encrypt_state = CipherState::<Cipher>::new(&key, nonce);
        let decrypt_state = encrypt_state.clone();

        (
            Codec {
                cipher_state: encrypt_state,
            },
            Codec {
                cipher_state: decrypt_state,
            },
        )
    }

    fn rand_codec_pair() -> (Codec<Cipher>, Codec<Cipher>) {
        init_codec_pair(rand::random(), rand::random())
    }

    const TEST_PAYLOAD: &[u8] = b"hello";

    #[test]
    fn roundtrip() {
        let (mut encrypt_codec, mut decrypt_codec) = rand_codec_pair();
        let mut buf = BytesMut::new();

        encrypt_codec.encode(TEST_PAYLOAD, &mut buf).unwrap();
        assert_ne!(buf.as_ref(), TEST_PAYLOAD);
        assert_eq!(
            buf.len(),
            TEST_PAYLOAD.len() + Cipher::tag_len() + size_of::<Header>()
        );

        let decoded = decrypt_codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.as_ref(), TEST_PAYLOAD);
    }

    #[test]
    fn roundtrip_partial() {
        let (mut encrypt_codec, mut decrypt_codec) = rand_codec_pair();
        let mut buf = BytesMut::new();

        encrypt_codec.encode(TEST_PAYLOAD, &mut buf).unwrap();
        assert_ne!(buf.as_ref(), TEST_PAYLOAD);
        assert_eq!(
            buf.len(),
            TEST_PAYLOAD.len() + Cipher::tag_len() + size_of::<Header>()
        );

        for i in 0..TEST_PAYLOAD.len() - 1 {
            let mut test_payload = buf.clone().split_to(i);
            assert_eq!(
                decrypt_codec.decode(&mut test_payload).unwrap(),
                None,
                "i={i}"
            );
            assert_eq!(test_payload.len(), i);
        }

        let decoded = decrypt_codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.as_ref(), TEST_PAYLOAD);
    }

    /// A `Record` frame whose declared body length is below the AEAD tag length must be rejected as
    /// an `InvalidData` decode error, NOT panic. Before the tag-length floor, such a frame reached
    /// `decrypt_in_place`'s `assert!(ciphertext_len >= tag_len())` and crashed the control task — a
    /// malicious/buggy control server could panic the client with a 3-byte header (e.g. `len = 0`).
    #[test]
    fn short_record_frame_is_rejected_not_panic() {
        for len in 0..Cipher::tag_len() as u16 {
            let (_enc, mut dec) = rand_codec_pair();
            // Hand-build a `Record` header (typ=0x04) declaring `len` body bytes, then `len` bytes of
            // body — a complete-but-undersized frame the decoder must reject (not return `None` for
            // "need more bytes", and not panic).
            let mut buf = BytesMut::new();
            buf.put_u8(MessageType::Record as u8);
            buf.put_u16(len); // network-endian U16, matching the Header layout
            buf.put_bytes(0, len as usize);

            let got = dec.decode(&mut buf);
            assert!(
                matches!(&got, Err(e) if e.kind() == ErrorKind::InvalidData),
                "a Record frame with len={len} (< tag_len) must be InvalidData, got {got:?}"
            );
        }
    }

    /// The lower boundary of the tag-length floor: a record with `len == tag_len()` (an empty
    /// plaintext plus the AEAD tag) is legitimate and must decode to an empty payload, NOT be
    /// rejected. Pins the floor at `< tag_len` (not `<= tag_len`), so a future off-by-one tightening
    /// the guard to `<=` would be caught. The `encode` loop skips empty input (`[].chunks(_)` yields
    /// nothing), so the frame is hand-built the way the encoder builds a chunk (a header, a
    /// tag-sized zeroed body, then `encrypt_in_place(.., 0)`).
    #[test]
    fn empty_record_at_tag_len_boundary_roundtrips() {
        let (mut encrypt_codec, mut decrypt_codec) = rand_codec_pair();

        let mut buf = BytesMut::new();
        let hdr = Header {
            typ: MessageType::Record,
            len: U16::new(Cipher::tag_len() as u16), // 0 plaintext + tag
        };
        buf.put(hdr.as_bytes());
        let body_start = buf.len();
        buf.put_bytes(0, Cipher::tag_len()); // tag-sized body, 0 plaintext
        encrypt_codec
            .cipher_state
            .encrypt_in_place(&mut buf[body_start..], 0);
        assert_eq!(buf.len(), Cipher::tag_len() + size_of::<Header>());

        let decoded = decrypt_codec.decode(&mut buf).unwrap().unwrap();
        assert!(
            decoded.is_empty(),
            "an empty record (len == tag_len) must decode to an empty payload, not be rejected"
        );
    }

    static RUNTIME: LazyLock<tokio::runtime::Runtime> =
        LazyLock::new(|| tokio::runtime::Runtime::new().unwrap());

    #[test]
    fn read_write() {
        let (encrypt_codec, decrypt_codec) = rand_codec_pair();

        let (rx, tx) = tokio::io::simplex(32);

        let mut framed_encrypt =
            crate::framed_io::FramedIo::<_, BytesMut>::new(Framed::new(tx, encrypt_codec));
        let mut framed_decrypt =
            crate::framed_io::FramedIo::<_, BytesMut>::new(Framed::new(rx, decrypt_codec));

        let (_, read_payload) = RUNTIME.block_on(async move {
            tokio::try_join![
                async move {
                    framed_encrypt.write_all(TEST_PAYLOAD).await?;
                    framed_encrypt.flush().await
                },
                async move {
                    let mut read_payload = BytesMut::zeroed(TEST_PAYLOAD.len());
                    framed_decrypt.read_exact(&mut read_payload).await?;
                    Ok(read_payload)
                }
            ]
            .unwrap()
        });

        assert_eq!(read_payload, TEST_PAYLOAD);
    }

    proptest::proptest! {
        #[test]
        fn roundtrip_prop(payload in vec(any::<u8>(), 1..=MAX_MESSAGE_SIZE - size_of::<Header>() - Cipher::tag_len()), key: [u8; 32], nonce: u64) {
            let (mut encrypt_codec, mut decrypt_codec) = init_codec_pair(key, nonce);

            let mut buf = BytesMut::new();
            encrypt_codec.encode(&payload, &mut buf).unwrap();
            let decoded = decrypt_codec.decode(&mut buf).unwrap().unwrap();
            assert_eq!(decoded.as_ref(), payload.as_slice());
        }

        #[test]
        fn read_write_prop(payload in vec(any::<u8>(), 1..=MAX_MESSAGE_SIZE * 4), key: [u8; 32], nonce: u64) {
            let (encrypt_codec, decrypt_codec) = init_codec_pair(key, nonce);

            let (rx, tx) = tokio::io::simplex(32);

            let mut framed_encrypt = crate::framed_io::FramedIo::<_, BytesMut>::new(Framed::new(tx, encrypt_codec));
            let mut framed_decrypt = crate::framed_io::FramedIo::<_, BytesMut>::new(Framed::new(rx, decrypt_codec));

            let write_payload = payload.clone();
            let mut read_payload = BytesMut::zeroed(payload.len());

            let (_, read_payload) = RUNTIME.block_on(async move {
                tokio::try_join![
                    async move {
                        framed_encrypt.write_all(&write_payload).await?;
                        framed_encrypt.flush().await
                    },
                    async move {
                        framed_decrypt.read_exact(&mut read_payload).await?;
                        Ok(read_payload)
                    }
                ]
                .unwrap()
            });

            assert_eq!(read_payload, payload);
        }
    }
}
