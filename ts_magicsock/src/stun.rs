//! A minimal, hand-rolled STUN codec for leak-safe active reflexive-address discovery.
//!
//! This is **not** a general STUN implementation. It encodes exactly the one
//! Binding Request we send, and decodes exactly the one Binding Success Response we expect,
//! on the single bound underlay UDP socket. We deliberately do **not** pull in a STUN crate
//! (e.g. `stun-rs`) or [`ts_netcheck::StunProber`]: that prober binds its own sockets
//! (including an IPv6 `[::]:0` egress) which would be a second egress and an IPv6 leak. By
//! sending the request *from* the one [`crate::MagicSock`] socket and demuxing the response
//! *on* that same socket, the reflexive address we learn is the mapping of the only egress
//! path — no second socket, no IPv6, no DNS.
//!
//! # Anti-leak / fail-closed posture
//!
//! Every parse path fails closed: a response is accepted *only* when the message type, magic
//! cookie, and the 12-byte transaction id all match what we sent, and it carries a well-formed
//! IPv4 XOR-MAPPED-ADDRESS. An IPv6 mapped address, a truncated or malformed attribute, a wrong
//! cookie, or an unrecognized transaction id all yield `None`, so a spoofed or stray datagram
//! can never inject an address into the reflexive set.

use core::net::{Ipv4Addr, SocketAddrV4};

/// The STUN magic cookie (RFC 5389), in host byte order. On the wire it is the big-endian
/// bytes `bytes[4..8]` of every STUN message.
pub(crate) const MAGIC_COOKIE: u32 = 0x2112_A442;

/// STUN message type for a Binding Request (the only request we send).
pub(crate) const BINDING_REQUEST: u16 = 0x0001;

/// STUN message type for a Binding Success Response (the only response we accept).
pub(crate) const BINDING_SUCCESS: u16 = 0x0101;

/// The XOR-MAPPED-ADDRESS attribute type (RFC 5389 §15.2); the reflexive address lives here.
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// The non-standard "alternate" XOR-MAPPED-ADDRESS attribute type (`0x8020`). Not in RFC 5389:
/// some servers emit the address under this type instead — `0x8020` is the comprehension-optional
/// shift of `0x0020` (bit 15 set), an easy mistake for a server to make. Go `stun.ParseResponse`
/// (`attrXorMappedAddressAlt`) accepts it identically to `0x0020`; we alias it the same way so a
/// peer behind such a buggy STUN server can still learn its reflexive address.
const ATTR_XOR_MAPPED_ADDRESS_ALT: u16 = 0x8020;

/// Address family byte for IPv4 inside an XOR-MAPPED-ADDRESS attribute.
const FAMILY_IPV4: u8 = 0x01;

/// Address family byte for IPv6 inside an XOR-MAPPED-ADDRESS attribute (never accepted).
const FAMILY_IPV6: u8 = 0x02;

/// The fixed 20-byte STUN message header length.
const HEADER_LEN: usize = 20;

/// SOFTWARE attribute type (RFC 5389 §15.10). Go sends it on every Binding Request; a real Tailscale
/// STUN server (the DERP-embedded one we probe) REQUIRES it — `stun.ParseBindingRequest` rejects a
/// request without `SOFTWARE == "tailnode"` as `ErrWrongSoftware` and drops it (no response). So a
/// bare header gets no reflexive address back from Tailscale infrastructure.
const ATTR_SOFTWARE: u16 = 0x8022;

/// FINGERPRINT attribute type (RFC 5389 §15.5). Go appends it last; the Tailscale STUN server also
/// requires it (`ErrNoFingerprint`/`ErrWrongFingerprint`).
const ATTR_FINGERPRINT: u16 = 0x8028;

/// The SOFTWARE attribute value Go's STUN client sends (`net/stun/stun.go` `software`). Exactly 8
/// bytes, so it needs no RFC-5389 4-byte padding. This is the genuine Tailscale software string every
/// real client sends — matching it is parity, not a tell; the *absence* is the tell.
const SOFTWARE: &[u8] = b"tailnode";

/// FINGERPRINT XOR constant (RFC 5389 §15.5: the attribute value is `crc32(message) XOR 0x5354554e`).
const FINGERPRINT_XOR: u32 = 0x5354_554E;

/// A 12-byte STUN transaction id, matching the on-wire layout (`bytes[8..20]`).
pub(crate) type StunTxId = [u8; 12];

/// CRC-32 (IEEE 802.3, the `crc32.ChecksumIEEE` Go uses for the FINGERPRINT attribute), computed
/// bit-by-bit so no lookup table or dependency is pulled onto this leak-safe path. Reflected input/
/// output, init `0xFFFFFFFF`, final XOR `0xFFFFFFFF`, polynomial `0xEDB88320` (the reflected
/// `0x04C11DB7`) — the standard parameters `ChecksumIEEE` uses.
fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Encode a STUN Binding Request carrying `tx_id`, byte-faithful to Go `net/stun.Request`.
///
/// Layout (40 bytes): the 20-byte header (type [`BINDING_REQUEST`] `0x0001`, message length `0x0014`
/// = the 20 trailing attribute bytes, magic cookie [`MAGIC_COOKIE`] big-endian at `bytes[4..8]`,
/// transaction id at `bytes[8..20]`), then a SOFTWARE attribute (`0x8022`, len 8, [`SOFTWARE`]) and a
/// FINGERPRINT attribute (`0x8028`, len 4, `crc32_ieee(message_so_far) XOR 0x5354554e`), fingerprint
/// LAST per RFC 5389. A bare 20-byte header is rejected by the Tailscale DERP STUN server we probe
/// (`ErrWrongSoftware`), so the SOFTWARE+FINGERPRINT trailer is required for the request to be
/// answered at all — and its absence is a non-Tailscale fingerprint.
pub(crate) fn encode_binding_request(tx_id: StunTxId) -> Vec<u8> {
    // 2-byte type + 2-byte length per attribute; SOFTWARE value is 8 bytes (no padding), FINGERPRINT
    // value is 4 bytes → trailing attribute bytes = (4 + 8) + (4 + 4) = 20.
    const TRAILER_LEN: u16 = (4 + 8) + (4 + 4);
    let mut buf = Vec::with_capacity(HEADER_LEN + TRAILER_LEN as usize);
    buf.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    buf.extend_from_slice(&TRAILER_LEN.to_be_bytes());
    buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    buf.extend_from_slice(&tx_id);

    // SOFTWARE attribute.
    buf.extend_from_slice(&ATTR_SOFTWARE.to_be_bytes());
    buf.extend_from_slice(&(SOFTWARE.len() as u16).to_be_bytes());
    buf.extend_from_slice(SOFTWARE);

    // FINGERPRINT attribute, computed over everything written so far (RFC 5389: the CRC covers the
    // message up to but not including the FINGERPRINT TLV, with the length field already counting it).
    let fp = crc32_ieee(&buf) ^ FINGERPRINT_XOR;
    buf.extend_from_slice(&ATTR_FINGERPRINT.to_be_bytes());
    buf.extend_from_slice(&4u16.to_be_bytes());
    buf.extend_from_slice(&fp.to_be_bytes());
    buf
}

/// Cheap predicate: does `buf` look like a STUN Binding Success Response we might have asked for?
///
/// Only checks the fixed header bytes (type and cookie); it does **not** validate the
/// transaction id or attributes. Used in the recv loop to decide whether to attempt the full,
/// transaction-matched [`parse_binding_response`] before falling through to the disco demux.
pub(crate) fn looks_like_stun_success(buf: &[u8]) -> bool {
    buf.len() >= HEADER_LEN
        && buf[0..2] == BINDING_SUCCESS.to_be_bytes()
        && buf[4..8] == MAGIC_COOKIE.to_be_bytes()
}

/// Parse a STUN Binding Success Response and return the IPv4 reflexive address it reports.
///
/// Returns `Some(addr)` **only if** all of the following hold:
/// - the message type (`bytes[0..2]`) is [`BINDING_SUCCESS`] (`0x0101`);
/// - the magic cookie (`bytes[4..8]`) is [`MAGIC_COOKIE`];
/// - the transaction id (`bytes[8..20]`) equals `expected`;
/// - the message carries a well-formed XOR-MAPPED-ADDRESS (`0x0020`, or the non-standard alternate
///   `0x8020` that some buggy servers emit) attribute with IPv4 family (`0x01`).
///
/// Returns `None` on any mismatch, on an IPv6 family (`0x02`) mapped address, on truncation, or
/// on a malformed TLV / bad attribute length. Attributes are walked with full bounds checks; a
/// single malformed attribute aborts the walk (fail closed) rather than guessing.
///
/// The walk returns on the first XOR-MAPPED-ADDRESS *type* it finds (`0x0020` or `0x8020`),
/// decoding its value or yielding `None`. Go `stun.ParseResponse` instead walks all attributes and
/// lets the last XOR-mapped attribute win. This differs only for a pathological response carrying
/// *both* types: a real server sends one or the other (`0x8020` is its misplacement of the same
/// attribute), never both, so first-match is equivalent in practice and consistent with this
/// parser's minimal fail-closed posture. A malformed first xor-mapped attribute fails the whole
/// parse closed (we do not keep walking to a later valid one); Go likewise aborts `ParseResponse`
/// on a malformed `xorMappedAddress`, so the result — learn nothing — is the same.
pub(crate) fn parse_binding_response(buf: &[u8], expected: StunTxId) -> Option<SocketAddrV4> {
    if buf.len() < HEADER_LEN {
        return None;
    }
    if buf[0..2] != BINDING_SUCCESS.to_be_bytes() {
        return None;
    }
    if buf[4..8] != MAGIC_COOKIE.to_be_bytes() {
        return None;
    }
    if buf[8..20] != expected {
        return None;
    }

    // The declared attributes length lives at bytes[2..4]; clamp it to what's actually present so
    // a lying length cannot read past the datagram.
    let declared_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let attrs_end = HEADER_LEN.checked_add(declared_len)?;
    if attrs_end > buf.len() {
        return None;
    }
    let attrs = &buf[HEADER_LEN..attrs_end];

    // Walk the TLV attributes: each is (u16 type, u16 length, value), value padded to a 4-byte
    // boundary. Bounds-check every step; a malformed entry fails closed.
    let mut off = 0usize;
    while off + 4 <= attrs.len() {
        let attr_type = u16::from_be_bytes([attrs[off], attrs[off + 1]]);
        let attr_len = u16::from_be_bytes([attrs[off + 2], attrs[off + 3]]) as usize;
        let value_start = off + 4;
        let value_end = value_start.checked_add(attr_len)?;
        if value_end > attrs.len() {
            // Attribute claims more bytes than remain: malformed, fail closed.
            return None;
        }

        if attr_type == ATTR_XOR_MAPPED_ADDRESS || attr_type == ATTR_XOR_MAPPED_ADDRESS_ALT {
            return parse_xor_mapped_address(&attrs[value_start..value_end]);
        }

        // Advance past this attribute's value, padded up to a 4-byte boundary.
        let padded = attr_len.checked_add(3)? & !3usize;
        off = value_start.checked_add(padded)?;
    }

    // No XOR-MAPPED-ADDRESS attribute present.
    None
}

/// Decode the value of an XOR-MAPPED-ADDRESS attribute into an IPv4 [`SocketAddrV4`].
///
/// Value layout (RFC 5389 §15.2): 1 reserved byte, 1 family byte, 2 XOR-port bytes, then the
/// XOR-address bytes (4 for IPv4). Only IPv4 (`family == 0x01`) is accepted; IPv6 (`0x02`) and
/// any other family yield `None`. The XOR keys are the cookie's top 16 bits for the port and
/// the full cookie for the address.
///
/// The transaction id is deliberately not a parameter: per RFC 5389 §15.2 the txid only
/// participates in the XOR for IPv6 addresses (the high 96 bits), and we reject IPv6 outright, so
/// the IPv4 decode is keyed entirely on the 32-bit magic cookie.
fn parse_xor_mapped_address(value: &[u8]) -> Option<SocketAddrV4> {
    // reserved(1) + family(1) + port(2) + ipv4(4) = 8 bytes minimum.
    if value.len() < 8 {
        return None;
    }
    let family = value[1];
    if family == FAMILY_IPV6 {
        // IPv6 mapped address: the underlay is IPv4-only; never enter the reflexive set.
        return None;
    }
    if family != FAMILY_IPV4 {
        return None;
    }

    // XOR-decode the port with the top 16 bits of the magic cookie (0x2112).
    let xor_port = u16::from_be_bytes([value[2], value[3]]);
    let port = xor_port ^ ((MAGIC_COOKIE >> 16) as u16);

    // XOR-decode the IPv4 address with the full magic cookie.
    let xor_ip = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
    let ip = Ipv4Addr::from(xor_ip ^ MAGIC_COOKIE);

    Some(SocketAddrV4::new(ip, port))
}

/// Test-only wire-format encoders, shared with the [`crate::sock`] STUN tests so there is a single
/// canonical Binding-Success encoder (the decoder under test never round-trips against its own
/// private copy).
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// Build a Binding Success Response carrying an IPv4 XOR-MAPPED-ADDRESS for `addr` and the
    /// given transaction id, matching the wire format we parse.
    pub(crate) fn encode_success_ipv4(tx_id: StunTxId, addr: SocketAddrV4) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        // attributes length: one XOR-MAPPED-ADDRESS attr (4 header + 8 value = 12 bytes).
        buf.extend_from_slice(&12u16.to_be_bytes());
        buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(&tx_id);

        // Attribute header.
        buf.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        buf.extend_from_slice(&8u16.to_be_bytes());
        // Value: reserved, family, xor-port, xor-ip.
        buf.push(0x00);
        buf.push(FAMILY_IPV4);
        let xor_port = addr.port() ^ ((MAGIC_COOKIE >> 16) as u16);
        buf.extend_from_slice(&xor_port.to_be_bytes());
        let xor_ip = u32::from(*addr.ip()) ^ MAGIC_COOKIE;
        buf.extend_from_slice(&xor_ip.to_be_bytes());

        buf
    }

    /// Build a Binding Success Response carrying an IPv6-family XOR-MAPPED-ADDRESS (which must
    /// never be accepted).
    pub(crate) fn encode_success_ipv6(tx_id: StunTxId) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        // 4 header + 20 value (reserved + family + port + 16-byte v6 addr) = 24 bytes.
        buf.extend_from_slice(&24u16.to_be_bytes());
        buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(&tx_id);

        buf.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        buf.extend_from_slice(&20u16.to_be_bytes());
        buf.push(0x00);
        buf.push(FAMILY_IPV6);
        buf.extend_from_slice(&0u16.to_be_bytes()); // xor-port
        buf.extend_from_slice(&[0u8; 16]); // xor-ipv6
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::{
        test_support::{encode_success_ipv4, encode_success_ipv6},
        *,
    };

    #[test]
    fn encode_binding_request_layout() {
        let tx_id: StunTxId = [9u8; 12];
        let req = encode_binding_request(tx_id);
        // 40 bytes: 20-byte header + SOFTWARE(4+8) + FINGERPRINT(4+4), matching Go net/stun.Request.
        assert_eq!(req.len(), 40);
        assert_eq!(req[0..2], BINDING_REQUEST.to_be_bytes());
        assert_eq!(
            req[2..4],
            0x0014u16.to_be_bytes(),
            "length = 20 trailing attr bytes"
        );
        assert_eq!(req[4..8], MAGIC_COOKIE.to_be_bytes());
        assert_eq!(req[8..20], tx_id);
        // SOFTWARE attribute: type 0x8022, len 8, value "tailnode".
        assert_eq!(req[20..22], ATTR_SOFTWARE.to_be_bytes());
        assert_eq!(req[22..24], 8u16.to_be_bytes());
        assert_eq!(&req[24..32], SOFTWARE);
        // FINGERPRINT attribute: type 0x8028, len 4, value crc32_ieee(prefix) ^ 0x5354554e, LAST.
        assert_eq!(req[32..34], ATTR_FINGERPRINT.to_be_bytes());
        assert_eq!(req[34..36], 4u16.to_be_bytes());
        let want_fp = crc32_ieee(&req[..32]) ^ FINGERPRINT_XOR;
        assert_eq!(req[36..40], want_fp.to_be_bytes());
    }

    /// CRC-32/IEEE known-answer test: `crc32("123456789") == 0xCBF43926` (the canonical check value
    /// for this CRC variant). Pins our hand-rolled `crc32_ieee` against the algorithm Go's
    /// `crc32.ChecksumIEEE` implements, so the FINGERPRINT a real Tailscale STUN server validates is
    /// correct.
    #[test]
    fn crc32_ieee_canonical_check_value() {
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32_ieee(b""), 0x0000_0000);
    }

    #[test]
    fn round_trip_matching_txid_returns_addr() {
        let tx_id: StunTxId = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let expected = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 41641);
        let buf = encode_success_ipv4(tx_id, expected);
        assert_eq!(parse_binding_response(&buf, tx_id), Some(expected));
    }

    #[test]
    fn mismatched_txid_returns_none() {
        let tx_id: StunTxId = [1u8; 12];
        let other: StunTxId = [2u8; 12];
        let addr = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 2), 3478);
        let buf = encode_success_ipv4(tx_id, addr);
        assert_eq!(parse_binding_response(&buf, other), None);
    }

    #[test]
    fn ipv6_family_returns_none() {
        let tx_id: StunTxId = [7u8; 12];
        let buf = encode_success_ipv6(tx_id);
        assert_eq!(
            parse_binding_response(&buf, tx_id),
            None,
            "an IPv6 mapped address must never be parsed into a v4 reflexive addr"
        );
    }

    #[test]
    fn truncated_header_returns_none() {
        // A buffer shorter than the 20-byte header.
        let buf = [0u8; 12];
        assert_eq!(parse_binding_response(&buf, [0u8; 12]), None);
    }

    #[test]
    fn wrong_cookie_returns_none() {
        let tx_id: StunTxId = [3u8; 12];
        let addr = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 1), 1234);
        let mut buf = encode_success_ipv4(tx_id, addr);
        // Corrupt the magic cookie.
        buf[4] ^= 0xff;
        assert_eq!(parse_binding_response(&buf, tx_id), None);
    }

    #[test]
    fn bad_attr_length_returns_none() {
        let tx_id: StunTxId = [4u8; 12];
        let addr = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 2), 5555);
        let mut buf = encode_success_ipv4(tx_id, addr);
        // The attribute header starts at offset 20: type(2) at [20..22], length(2) at [22..24].
        // Inflate the declared attribute length so its value runs past the buffer end.
        buf[22] = 0xff;
        buf[23] = 0xff;
        assert_eq!(
            parse_binding_response(&buf, tx_id),
            None,
            "an attribute claiming more bytes than present must fail closed"
        );
    }

    #[test]
    fn wrong_message_type_returns_none() {
        let tx_id: StunTxId = [5u8; 12];
        let addr = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 3), 9999);
        let mut buf = encode_success_ipv4(tx_id, addr);
        // Turn the success response into a request type.
        buf[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
        assert_eq!(parse_binding_response(&buf, tx_id), None);
    }

    /// Decode a hand-built wire vector that does NOT come from our own `encode_success_ipv4`,
    /// pinning the XOR decode against an independently-derived known-good answer.
    ///
    /// This is the critical complement to the round-trip tests: a round trip through our own
    /// encoder would still pass even if the encoder *and* decoder shared a bug (e.g. wrong cookie
    /// endianness, swapped XOR keys). Here the input bytes and the expected `192.0.2.1:32853`
    /// answer are written out by hand from the RFC 5769 §2.1 sample-response convention
    /// (X-Port `0xa147` ^ `0x2112` = 32853; X-Address `0xe112a643` ^ `0x2112a442` = 192.0.2.1),
    /// so any drift in the magic cookie, the XOR keying, or the byte order is caught.
    #[test]
    fn known_good_external_vector_decodes() {
        // The RFC 5769 §2.1 sample transaction id.
        let tx_id: StunTxId = [
            0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
        ];
        let mut buf = Vec::new();
        // Header: Binding Success, attrs length = 12 (one XOR-MAPPED-ADDRESS attr), cookie, txid.
        buf.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        buf.extend_from_slice(&12u16.to_be_bytes());
        buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(&tx_id);
        // XOR-MAPPED-ADDRESS attribute, value length 8.
        buf.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        buf.extend_from_slice(&8u16.to_be_bytes());
        buf.push(0x00); // reserved
        buf.push(FAMILY_IPV4); // family
        buf.extend_from_slice(&[0xa1, 0x47]); // X-Port (hand-derived, not via our encoder)
        buf.extend_from_slice(&[0xe1, 0x12, 0xa6, 0x43]); // X-Address (hand-derived)

        assert_eq!(
            parse_binding_response(&buf, tx_id),
            Some(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 32853)),
            "the known-good external vector must decode to 192.0.2.1:32853"
        );
    }

    /// An unknown comprehension-optional attribute appearing *before* XOR-MAPPED-ADDRESS must be
    /// skipped (TLV walk advances past type+len+value, padded to a 4-byte boundary) and the walk
    /// must continue to find the real address. A bug in the `(len + 3) & !3` padding advance would
    /// pass every single-attribute round-trip test but desync the offset here and miss the address.
    #[test]
    fn unknown_attribute_is_skipped_and_walk_continues() {
        let tx_id: StunTxId = [8u8; 12];
        let expected = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 41641);

        // A SOFTWARE-like unknown attribute (type 0x8022) with a 5-byte value => padded to 8.
        const UNKNOWN_ATTR: u16 = 0x8022;
        let unknown_value: &[u8] = b"hello"; // 5 bytes => 3 bytes of padding to reach 8.

        let xmapped_len = 4 + 8; // attr header + value
        let unknown_len = 4 + 8; // attr header + padded value
        let attrs_len = (xmapped_len + unknown_len) as u16;

        let mut buf = Vec::new();
        buf.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        buf.extend_from_slice(&attrs_len.to_be_bytes());
        buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(&tx_id);

        // Unknown attribute first (must be skipped including its 3 padding bytes).
        buf.extend_from_slice(&UNKNOWN_ATTR.to_be_bytes());
        buf.extend_from_slice(&(unknown_value.len() as u16).to_be_bytes());
        buf.extend_from_slice(unknown_value);
        buf.extend_from_slice(&[0u8; 3]); // padding to 4-byte boundary

        // Then the real XOR-MAPPED-ADDRESS.
        buf.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        buf.extend_from_slice(&8u16.to_be_bytes());
        buf.push(0x00);
        buf.push(FAMILY_IPV4);
        let xor_port = expected.port() ^ ((MAGIC_COOKIE >> 16) as u16);
        buf.extend_from_slice(&xor_port.to_be_bytes());
        let xor_ip = u32::from(*expected.ip()) ^ MAGIC_COOKIE;
        buf.extend_from_slice(&xor_ip.to_be_bytes());

        assert_eq!(
            parse_binding_response(&buf, tx_id),
            Some(expected),
            "an unknown leading attribute must be skipped and the walk must find XOR-MAPPED-ADDRESS"
        );
    }

    /// A response carrying no XOR-MAPPED-ADDRESS attribute at all (only an unknown attribute) must
    /// return `None` (learns nothing) rather than mis-decoding the unknown attribute's bytes.
    #[test]
    fn no_xor_mapped_address_returns_none() {
        let tx_id: StunTxId = [11u8; 12];
        const UNKNOWN_ATTR: u16 = 0x8022;
        let value: &[u8] = b"softwarexx"; // 10 bytes => padded to 12

        let attrs_len: u16 = 4 + 12; // attr header + value padded 10 -> 12
        let mut buf = Vec::new();
        buf.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        buf.extend_from_slice(&attrs_len.to_be_bytes());
        buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(&tx_id);
        buf.extend_from_slice(&UNKNOWN_ATTR.to_be_bytes());
        buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
        buf.extend_from_slice(value);
        buf.extend_from_slice(&[0u8; 2]); // pad 10 -> 12

        assert_eq!(
            parse_binding_response(&buf, tx_id),
            None,
            "a response with no XOR-MAPPED-ADDRESS attribute must learn nothing"
        );
    }

    /// A server that (incorrectly) reports the reflexive address under the non-standard alternate
    /// XOR-MAPPED-ADDRESS type `0x8020` is still parsed, matching Go `attrXorMappedAddressAlt`. The
    /// value bytes are identical to the standard attribute; only the type word differs.
    #[test]
    fn alt_xor_mapped_address_type_decodes() {
        let tx_id: StunTxId = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let expected = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 41641);

        // Start from a standard 0x0020 response, then flip the attribute type word to 0x8020. The
        // attribute header begins at offset 20 (just after the 20-byte message header); its type is
        // the first two bytes there.
        let mut buf = encode_success_ipv4(tx_id, expected);
        buf[HEADER_LEN..HEADER_LEN + 2].copy_from_slice(&ATTR_XOR_MAPPED_ADDRESS_ALT.to_be_bytes());

        assert_eq!(
            parse_binding_response(&buf, tx_id),
            Some(expected),
            "the address must decode when carried under the alternate 0x8020 type (Go parity)"
        );
    }

    /// The alternate `0x8020` type goes through the same fail-closed value decode: an IPv6-family
    /// address under `0x8020` must still be rejected (the underlay is IPv4-only).
    #[test]
    fn alt_xor_mapped_address_ipv6_still_rejected() {
        let tx_id: StunTxId = [7u8; 12];
        let mut buf = encode_success_ipv6(tx_id);
        buf[HEADER_LEN..HEADER_LEN + 2].copy_from_slice(&ATTR_XOR_MAPPED_ADDRESS_ALT.to_be_bytes());
        assert_eq!(
            parse_binding_response(&buf, tx_id),
            None,
            "an IPv6 mapped address under the alternate type must still be rejected"
        );
    }

    /// Pins the documented first-match-on-type contract: a (pathological) response carrying BOTH a
    /// `0x0020` and a `0x8020` XOR-MAPPED-ADDRESS with different addresses returns the FIRST one in
    /// wire order. Go would return the last; this divergence is harmless (a real server never sends
    /// both, and only an on-path attacker who already knows our txid could craft it, in which case
    /// they control the whole response anyway). This test exists so a future switch to last-wins
    /// can't silently change the behavior the doc justifies.
    #[test]
    fn both_xor_mapped_types_return_first_in_wire_order() {
        let tx_id: StunTxId = [2u8; 12];
        let first = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 1), 1111);
        let second = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 2), 2222);

        // Hand-build a response with two XOR-MAPPED-ADDRESS attrs: 0x0020(first) then 0x8020(second).
        let mut buf = Vec::new();
        buf.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        buf.extend_from_slice(&(2u16 * 12).to_be_bytes()); // two 12-byte attrs (4 header + 8 value)
        buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(&tx_id);
        for (attr_type, addr) in [
            (ATTR_XOR_MAPPED_ADDRESS, first),
            (ATTR_XOR_MAPPED_ADDRESS_ALT, second),
        ] {
            buf.extend_from_slice(&attr_type.to_be_bytes());
            buf.extend_from_slice(&8u16.to_be_bytes());
            buf.push(0x00);
            buf.push(FAMILY_IPV4);
            buf.extend_from_slice(&(addr.port() ^ ((MAGIC_COOKIE >> 16) as u16)).to_be_bytes());
            buf.extend_from_slice(&(u32::from(*addr.ip()) ^ MAGIC_COOKIE).to_be_bytes());
        }

        assert_eq!(
            parse_binding_response(&buf, tx_id),
            Some(first),
            "the first XOR-MAPPED-ADDRESS in wire order wins (first-match-on-type contract)"
        );
    }

    /// A truncated value (< 8 bytes) under the alternate `0x8020` type fails closed, exactly as it
    /// does under `0x0020`: the alt type shares the same fail-closed value decode.
    #[test]
    fn alt_xor_mapped_address_short_value_returns_none() {
        let tx_id: StunTxId = [9u8; 12];
        let mut buf = Vec::new();
        buf.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        buf.extend_from_slice(&(4u16 + 4).to_be_bytes()); // 4-byte header + 4-byte (too-short) value
        buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(&tx_id);
        buf.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS_ALT.to_be_bytes());
        buf.extend_from_slice(&4u16.to_be_bytes()); // value length 4 < the 8-byte minimum
        buf.extend_from_slice(&[0x00, FAMILY_IPV4, 0x00, 0x00]);

        assert_eq!(
            parse_binding_response(&buf, tx_id),
            None,
            "a short value under 0x8020 must fail closed like 0x0020"
        );
    }

    #[test]
    fn looks_like_stun_success_true_and_false() {
        let tx_id: StunTxId = [6u8; 12];
        let addr = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 4), 7777);
        let good = encode_success_ipv4(tx_id, addr);
        assert!(looks_like_stun_success(&good));

        // Too short.
        assert!(!looks_like_stun_success(&good[..10]));

        // Right length, wrong type.
        let mut wrong_type = good.clone();
        wrong_type[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
        assert!(!looks_like_stun_success(&wrong_type));

        // Right length and type, wrong cookie.
        let mut wrong_cookie = good.clone();
        wrong_cookie[4] ^= 0xff;
        assert!(!looks_like_stun_success(&wrong_cookie));
    }
}
