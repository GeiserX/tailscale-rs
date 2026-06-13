use bytes::{Buf, BufMut, BytesMut};
use ts_hexdump::{AsHexExt, Case};
use zerocopy::{FromBytes, IntoBytes};

use crate::frame::{Header, RawFrame, RawHeader};

/// Implements [`tokio_util::codec::Encoder`] and [`tokio_util::codec::Decoder`] for
/// the derp protocol.
pub struct Codec;

impl<'a, 'b> tokio_util::codec::Encoder<(RawFrame<'a>, &'b [u8])> for Codec {
    type Error = std::io::Error;

    #[tracing::instrument(skip_all, fields(frame_hdr = ?frame.header, frame_body_len = frame.raw_body.len(), extra_payload_len = extra_payload.len()), err, level = "trace")]
    fn encode(
        &mut self,
        (frame, extra_payload): (RawFrame<'a>, &'b [u8]),
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        let header: RawHeader = frame.header.into();

        debug_assert_eq!(header.len(), { frame.raw_body.len() + extra_payload.len() });

        tracing::trace!(raw_header = ?header);

        dst.put_slice(header.as_bytes());
        dst.put_slice(frame.raw_body);
        dst.put_slice(extra_payload);

        tracing::trace!(
            len = dst.len(),
            "dst:\n{}",
            dst.iter().hexdump_string(Case::Lower)
        );

        Ok(())
    }
}

impl<'a> tokio_util::codec::Encoder<RawFrame<'a>> for Codec {
    type Error = std::io::Error;

    #[tracing::instrument(skip_all, fields(frame_hdr = ?frame.header, frame_body_len = frame.raw_body.len()), err, level = "trace")]
    fn encode(&mut self, frame: RawFrame<'a>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        <Self as tokio_util::codec::Encoder<(RawFrame<'a>, &'static [u8])>>::encode(
            self,
            (frame, &[]),
            dst,
        )
    }
}

impl tokio_util::codec::Decoder for Codec {
    type Item = yoke::Yoke<RawFrame<'static>, Vec<u8>>;
    type Error = std::io::Error;

    #[tracing::instrument(skip_all, fields(src_len = src.len(), src_cap = src.capacity()), err, level = "trace")]
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Loop so an UNKNOWN frame type is skipped (Go `derp_client.go` `recvTimeout` `default:
        // continue`) and the next frame is then attempted in the same call, rather than tearing down
        // the connection. DERP is forward-extensible — a newer server may emit frame types this enum
        // does not list — so a client must tolerate (skip) them. A genuinely malformed header (bad
        // length) is still a hard error.
        loop {
            if src.len() < Header::LEN_BYTES {
                return Ok(None);
            }

            // Parse the raw TLV header first. Its `len` is always readable regardless of whether the
            // type byte is a known `FrameType`, which is what lets us measure (and skip) an unknown
            // frame. `RawHeader::len()` enforces nothing on its own; the `MAX_PACKET_SIZE` bound is
            // applied below for both the known and unknown paths.
            let (raw_header, post_header_len) = {
                let (raw_header, rest) = RawHeader::ref_from_prefix(src).map_err(|e| {
                    tracing::error!(err = %e);
                    std::io::Error::other("invalid raw header")
                })?;
                (*raw_header, rest.len())
            };

            let header_len = src.len() - post_header_len;
            let body_len = raw_header.len();

            // Bound the body length BEFORE trusting it to compute the full packet length — applied
            // even for an unknown type so a bogus length can never drive an oversized skip. The read
            // ceiling is Go `recvTimeout`'s `1<<20` (`MAX_RECV_FRAME_SIZE`), NOT the tighter
            // `MAX_PACKET_SIZE`: a forward-extended server may emit a large unknown frame up to 1 MiB,
            // and Go skips it rather than disconnecting, so we must read it to skip it. Known frames
            // are still held to `MAX_PACKET_SIZE` below — `Header::new` re-applies that tighter bound
            // when the type is recognized, so this wider ceiling only ever permits SKIPPING a large
            // unknown frame, never ACCEPTING an over-`MAX_PACKET_SIZE` known one.
            if body_len > crate::frame::MAX_RECV_FRAME_SIZE {
                return Err(std::io::Error::other(
                    crate::frame::Error::InvalidPacketLength(body_len),
                ));
            }

            let full_packet_len = header_len + body_len;

            if full_packet_len > src.len() {
                tracing::trace!("incomplete packet, bail out");
                return Ok(None);
            }

            // Resolve the frame type. An unknown type is skipped (advance past the whole frame and
            // try the next one); any other conversion error is fatal.
            let header: Header = match raw_header.typ() {
                Ok(typ) => Header::new(typ, body_len as u32).map_err(std::io::Error::other)?,
                Err(crate::frame::Error::InvalidFrameType(t)) => {
                    tracing::debug!(frame_type = t, body_len, "skipping unknown DERP frame type");
                    src.advance(full_packet_len);
                    continue;
                }
                Err(e) => return Err(std::io::Error::other(e)),
            };

            tracing::trace!(header_len, post_header_len, full_packet_len, ?header);

            src.advance(header_len);
            let payload = src.split_to(body_len);

            let ret = yoke::Yoke::attach_to_cart(payload.to_vec(), move |raw_body| RawFrame {
                header,
                raw_body,
            });

            return Ok(Some(ret));
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::{BufMut, BytesMut};
    use tokio_util::codec::Decoder;

    use super::Codec;
    use crate::frame::FrameType;

    /// Append a raw DERP TLV frame (type:1, len:4 BE, body) to `buf`.
    fn put_frame(buf: &mut BytesMut, typ: u8, body: &[u8]) {
        buf.put_u8(typ);
        buf.put_u32(body.len() as u32);
        buf.put_slice(body);
    }

    /// An unknown frame type is SKIPPED (Go `default: continue`), not fatal, and a following known
    /// frame in the same buffer is still decoded — the forward-compat contract.
    #[test]
    fn decode_skips_unknown_frame_type_and_decodes_the_next() {
        let mut buf = BytesMut::new();
        // A frame type this enum does not list (0x7f), with a non-empty body, followed by a real Ping.
        put_frame(&mut buf, 0x7f, &[0xaa; 12]);
        put_frame(&mut buf, FrameType::Ping as u8, &[0x01; 8]);

        let mut codec = Codec;
        let frame = codec
            .decode(&mut buf)
            .expect("decode must not error on an unknown frame type")
            .expect("the known Ping after the skipped unknown frame must decode");
        let f = frame.get();
        assert_eq!(
            f.header.typ,
            FrameType::Ping,
            "skipped unknown, returned the Ping"
        );
        assert_eq!(f.raw_body, &[0x01; 8], "the Ping body is intact");
        // The unknown frame and the Ping were both consumed.
        assert!(buf.is_empty(), "both frames consumed from the buffer");
    }

    /// A trailing unknown frame (nothing after it) is skipped and yields `None` (need more data),
    /// not an error — a clean idle state, exactly as Go treats an unknown trailing frame.
    #[test]
    fn decode_trailing_unknown_frame_is_skipped_to_none() {
        let mut buf = BytesMut::new();
        put_frame(&mut buf, 0x7e, &[0xbb; 4]);

        let mut codec = Codec;
        let out = codec
            .decode(&mut buf)
            .expect("a lone unknown frame must be skipped, not error");
        assert!(
            out.is_none(),
            "no known frame follows, so decode yields None"
        );
        assert!(buf.is_empty(), "the unknown frame was consumed");
    }

    /// A bad length (beyond `MAX_PACKET_SIZE`) is still a hard error even for an unknown type — a
    /// bogus length beyond the receive ceiling (Go `recvTimeout`'s `1<<20`) must never drive an
    /// oversized skip — it is a hard error even for an unknown type.
    #[test]
    fn decode_rejects_oversized_length_even_for_unknown_type() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x7f); // unknown type
        buf.put_u32((crate::frame::MAX_RECV_FRAME_SIZE + 1) as u32); // length over the read ceiling
        // (no body bytes needed — the length check fires before completeness)

        let mut codec = Codec;
        let err = codec
            .decode(&mut buf)
            .expect_err("over-ceiling length must be a hard error");
        // Assert it is specifically the length rejection, not some incidental parse failure.
        let inner = err
            .into_inner()
            .and_then(|e| e.downcast::<crate::frame::Error>().ok());
        assert!(
            matches!(
                inner.as_deref(),
                Some(crate::frame::Error::InvalidPacketLength(_))
            ),
            "must reject via the length bound, got {inner:?}"
        );
    }

    /// An unknown frame between `MAX_PACKET_SIZE` and the `MAX_RECV_FRAME_SIZE` read ceiling is
    /// SKIPPED (Go reads up to `1<<20` and skips unknown types), not errored — the parity fix. Here
    /// the (large) body is fully present, so the skip lands and the following Ping decodes.
    #[test]
    fn decode_skips_large_unknown_frame_within_recv_ceiling() {
        let big = crate::frame::MAX_PACKET_SIZE + 1024; // > MAX_PACKET_SIZE, < MAX_RECV_FRAME_SIZE
        let mut buf = BytesMut::new();
        put_frame(&mut buf, 0x7f, &vec![0u8; big]);
        put_frame(&mut buf, FrameType::Ping as u8, &[0x02; 8]);

        let mut codec = Codec;
        let frame = codec
            .decode(&mut buf)
            .expect("a large unknown frame within the read ceiling must skip, not error")
            .expect("the Ping after the skipped large unknown frame must decode");
        assert_eq!(frame.get().header.typ, FrameType::Ping);
        assert!(buf.is_empty(), "both frames consumed");
    }

    /// A KNOWN frame whose body exceeds `MAX_PACKET_SIZE` (but is within the read ceiling) is still
    /// rejected — the wider read ceiling only ever permits SKIPPING a large unknown frame, never
    /// ACCEPTING an over-`MAX_PACKET_SIZE` known one (`Header::new` re-applies the tighter bound).
    #[test]
    fn decode_rejects_known_frame_over_max_packet_size() {
        let over = crate::frame::MAX_PACKET_SIZE + 1;
        let mut buf = BytesMut::new();
        buf.put_u8(FrameType::SendPacket as u8);
        buf.put_u32(over as u32);
        // Provide the full body so the completeness check passes and the bound is what fires.
        buf.put_slice(&vec![0u8; over]);

        let mut codec = Codec;
        assert!(
            codec.decode(&mut buf).is_err(),
            "a known frame over MAX_PACKET_SIZE must be rejected, not accepted via the read ceiling"
        );
    }

    /// An incomplete unknown-frame body (header declares N, fewer than N bytes present) yields
    /// `Ok(None)` (need more data) and does NOT consume/skip — a partial unknown frame must wait,
    /// not be discarded with a wrong length.
    #[test]
    fn decode_incomplete_unknown_frame_body_yields_none_without_consuming() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x7f); // unknown type
        buf.put_u32(16); // claims a 16-byte body
        buf.put_slice(&[0xaa; 4]); // only 4 present

        let mut codec = Codec;
        assert!(
            codec
                .decode(&mut buf)
                .expect("a partial unknown frame must not error")
                .is_none(),
            "an incomplete unknown frame yields None (need more data)"
        );
        assert_eq!(
            buf.len(),
            9,
            "the partial unknown frame is retained, not skipped"
        );
    }
}
