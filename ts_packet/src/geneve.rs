//! Geneve (RFC 8926) fixed-header codec for Tailscale **peer-relay** framing.
//!
//! Tailscale's peer-relay data path encapsulates both relayed disco (the bind handshake) and
//! relayed WireGuard data in a Geneve header carrying a 24-bit VNI (virtual network identifier).
//! This module parses/encodes just the 8-byte fixed Geneve header Tailscale uses — the relay data
//! path itself (the `relayManager` handshake + magicsock integration) is not yet implemented in this
//! fork, but recognizing the framing keeps the fork wire-aware (e.g. so relayed frames can be
//! classified rather than treated as opaque/undecodable).
//!
//! Header layout (RFC 8926 §3.4, fixed 8 bytes; Tailscale uses no variable options):
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |        Virtual Network Identifier (VNI)        |    Reserved   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

/// The fixed Geneve header length in bytes (Tailscale uses no variable options, so `Opt Len` is 0).
pub const GENEVE_FIXED_HEADER_LEN: usize = 8;

/// Geneve "Protocol Type" for relayed **disco** frames (Tailscale `GeneveProtocolDisco`).
pub const GENEVE_PROTOCOL_DISCO: u16 = 0x7A11;
/// Geneve "Protocol Type" for relayed **WireGuard** frames (Tailscale `GeneveProtocolWireGuard`).
pub const GENEVE_PROTOCOL_WIREGUARD: u16 = 0x7A12;

/// A parsed Tailscale Geneve fixed header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeneveHeader {
    /// The "Control" (C) bit: set when the payload is a control message (the relay bind handshake)
    /// rather than tunneled data.
    pub control: bool,
    /// The inner protocol type (`GENEVE_PROTOCOL_DISCO` / `GENEVE_PROTOCOL_WIREGUARD`).
    pub protocol: u16,
    /// The 24-bit Virtual Network Identifier.
    pub vni: u32,
}

/// Errors decoding a Geneve header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneveError {
    /// The buffer is shorter than the 8-byte fixed header.
    TooShort,
    /// The version field is not 0 (the only version Tailscale emits).
    BadVersion,
    /// A non-zero `Opt Len` was present (Tailscale uses no variable options; we don't parse them).
    UnexpectedOptions,
}

impl GeneveHeader {
    /// Parse a Geneve fixed header from the front of `buf`. Returns the header and the offset of the
    /// inner payload (always [`GENEVE_FIXED_HEADER_LEN`]). Rejects a non-zero version or option
    /// length (Tailscale emits neither) so a malformed/foreign Geneve packet is not mis-decoded.
    pub fn parse(buf: &[u8]) -> Result<(GeneveHeader, usize), GeneveError> {
        if buf.len() < GENEVE_FIXED_HEADER_LEN {
            return Err(GeneveError::TooShort);
        }
        // Byte 0: Ver (2 bits) | Opt Len (6 bits, in 4-byte words).
        let version = buf[0] >> 6;
        if version != 0 {
            return Err(GeneveError::BadVersion);
        }
        let opt_len_words = buf[0] & 0x3f;
        if opt_len_words != 0 {
            return Err(GeneveError::UnexpectedOptions);
        }
        // Byte 1: O (bit 7) | C (bit 6) | reserved.
        let control = (buf[1] & 0x40) != 0;
        // Bytes 2..4: Protocol Type (big-endian u16).
        let protocol = u16::from_be_bytes([buf[2], buf[3]]);
        // Bytes 4..7: 24-bit VNI (big-endian); byte 7 is reserved.
        let vni = (u32::from(buf[4]) << 16) | (u32::from(buf[5]) << 8) | u32::from(buf[6]);

        Ok((
            GeneveHeader {
                control,
                protocol,
                vni,
            },
            GENEVE_FIXED_HEADER_LEN,
        ))
    }

    /// Encode this header into an 8-byte fixed Geneve header (no variable options).
    pub fn encode(&self) -> [u8; GENEVE_FIXED_HEADER_LEN] {
        let mut out = [0u8; GENEVE_FIXED_HEADER_LEN];
        // Ver = 0, Opt Len = 0 => byte 0 is 0.
        out[0] = 0;
        // O bit unused (0); set C bit when control.
        out[1] = if self.control { 0x40 } else { 0x00 };
        out[2..4].copy_from_slice(&self.protocol.to_be_bytes());
        out[4] = (self.vni >> 16) as u8;
        out[5] = (self.vni >> 8) as u8;
        out[6] = self.vni as u8;
        // out[7] reserved = 0.
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_disco_data() {
        let h = GeneveHeader {
            control: true,
            protocol: GENEVE_PROTOCOL_DISCO,
            vni: 0x0A_BC_DE,
        };
        let bytes = h.encode();
        let (parsed, off) = GeneveHeader::parse(&bytes).unwrap();
        assert_eq!(off, GENEVE_FIXED_HEADER_LEN);
        assert_eq!(parsed, h);
    }

    #[test]
    fn roundtrip_wireguard_no_control() {
        let h = GeneveHeader {
            control: false,
            protocol: GENEVE_PROTOCOL_WIREGUARD,
            vni: 1,
        };
        let bytes = h.encode();
        assert_eq!(bytes[1] & 0x40, 0, "control bit must be clear");
        let (parsed, _) = GeneveHeader::parse(&bytes).unwrap();
        assert_eq!(parsed, h);
    }

    #[test]
    fn vni_is_24_bits() {
        let h = GeneveHeader {
            control: false,
            protocol: GENEVE_PROTOCOL_DISCO,
            vni: 0xFF_FF_FF,
        };
        let bytes = h.encode();
        // Byte 7 (reserved) must stay zero even at max VNI.
        assert_eq!(bytes[7], 0);
        let (parsed, _) = GeneveHeader::parse(&bytes).unwrap();
        assert_eq!(parsed.vni, 0xFF_FF_FF);
    }

    #[test]
    fn rejects_short_buffer() {
        assert_eq!(GeneveHeader::parse(&[0u8; 7]), Err(GeneveError::TooShort));
    }

    #[test]
    fn rejects_bad_version() {
        let mut bytes = GeneveHeader {
            control: false,
            protocol: GENEVE_PROTOCOL_DISCO,
            vni: 0,
        }
        .encode();
        bytes[0] = 0x40; // version = 1
        assert_eq!(GeneveHeader::parse(&bytes), Err(GeneveError::BadVersion));
    }

    #[test]
    fn rejects_variable_options() {
        let mut bytes = GeneveHeader {
            control: false,
            protocol: GENEVE_PROTOCOL_DISCO,
            vni: 0,
        }
        .encode();
        bytes[0] = 0x02; // opt len = 2 words
        assert_eq!(
            GeneveHeader::parse(&bytes),
            Err(GeneveError::UnexpectedOptions)
        );
    }

    #[test]
    fn encode_matches_spec_byte_layout() {
        // Byte-exact reference vector hand-derived from RFC 8926 §3.4 + Tailscale's usage,
        // NOT computed by round-tripping through this fork's own encoder (that would be
        // circular and would mask any byte-order / bit-position bug). The 6 round-trip tests
        // above only prove encode/parse are mutually consistent, not that either matches the
        // wire format.
        //
        // For GeneveHeader { control: true, protocol: GENEVE_PROTOCOL_DISCO (0x7A11),
        //                    vni: 0x0ABCDE }:
        //   byte 0: Ver(2b)=00 | Opt Len(6b)=000000                     => 0x00
        //   byte 1: O(bit7)=0 | C(bit6)=1 | Rsvd(6b)=0  (0b0100_0000)   => 0x40
        //   byte 2: Protocol Type high byte (0x7A11 big-endian)          => 0x7A
        //   byte 3: Protocol Type low  byte                              => 0x11
        //   byte 4: VNI[23:16] of 0x0ABCDE                               => 0x0A
        //   byte 5: VNI[15:8]                                            => 0xBC
        //   byte 6: VNI[7:0]                                             => 0xDE
        //   byte 7: Reserved                                             => 0x00
        //
        // Residual gap: this is a SPEC-derived vector, not one captured from a live Go
        // `tailscaled` peer-relay packet. Full Go cross-validation would require a captured
        // on-wire Geneve frame from tailscaled and is left as the remaining verification step.
        let h = GeneveHeader {
            control: true,
            protocol: GENEVE_PROTOCOL_DISCO,
            vni: 0x0A_BC_DE,
        };
        assert_eq!(h.encode(), [0x00, 0x40, 0x7A, 0x11, 0x0A, 0xBC, 0xDE, 0x00]);
    }

    #[test]
    fn parse_known_wire_bytes() {
        // Hand-built wire bytes (NOT produced by this fork's encoder), decoded field-by-field
        // per RFC 8926 §3.4:
        //   byte 0 = 0x00: Ver=00 (ok), Opt Len=000000 (no options)
        //   byte 1 = 0x00: O=0, C(bit6)=0  => control = false
        //   bytes 2..4 = 0x7A,0x12: Protocol Type big-endian 0x7A12 = GENEVE_PROTOCOL_WIREGUARD
        //   bytes 4..7 = 0x00,0x00,0x01: 24-bit VNI big-endian = 0x000001 = 1
        //   byte 7 = 0x00: Reserved
        // Inner payload therefore begins at offset GENEVE_FIXED_HEADER_LEN (8).
        //
        // Residual gap: spec-derived, not captured from Go `tailscaled`; a real captured
        // peer-relay frame would be needed for full cross-implementation validation.
        let wire = [0x00, 0x00, 0x7A, 0x12, 0x00, 0x00, 0x01, 0x00];
        let (parsed, off) = GeneveHeader::parse(&wire).unwrap();
        assert_eq!(
            parsed,
            GeneveHeader {
                control: false,
                protocol: GENEVE_PROTOCOL_WIREGUARD,
                vni: 1,
            }
        );
        assert_eq!(off, GENEVE_FIXED_HEADER_LEN);
    }

    #[test]
    fn parse_returns_payload_offset() {
        let mut buf = GeneveHeader {
            control: false,
            protocol: GENEVE_PROTOCOL_WIREGUARD,
            vni: 7,
        }
        .encode()
        .to_vec();
        buf.extend_from_slice(b"payload");
        let (_, off) = GeneveHeader::parse(&buf).unwrap();
        assert_eq!(&buf[off..], b"payload");
    }
}
