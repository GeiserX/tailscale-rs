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
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

/// STUN message type for a Binding Request (the only request we send).
pub const BINDING_REQUEST: u16 = 0x0001;

/// STUN message type for a Binding Success Response (the only response we accept).
pub const BINDING_SUCCESS: u16 = 0x0101;

/// The XOR-MAPPED-ADDRESS attribute type (RFC 5389 §15.2); the reflexive address lives here.
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// Address family byte for IPv4 inside an XOR-MAPPED-ADDRESS attribute.
const FAMILY_IPV4: u8 = 0x01;

/// Address family byte for IPv6 inside an XOR-MAPPED-ADDRESS attribute (never accepted).
const FAMILY_IPV6: u8 = 0x02;

/// The fixed 20-byte STUN message header length.
const HEADER_LEN: usize = 20;

/// A 12-byte STUN transaction id, matching the on-wire layout (`bytes[8..20]`).
pub type StunTxId = [u8; 12];

/// Encode a 20-byte STUN Binding Request carrying `tx_id`.
///
/// Layout: type = [`BINDING_REQUEST`] (`0x0001`), message length = `0x0000` (no attributes),
/// magic cookie = [`MAGIC_COOKIE`] big-endian at `bytes[4..8]`, transaction id at
/// `bytes[8..20]`.
pub fn encode_binding_request(tx_id: StunTxId) -> [u8; HEADER_LEN] {
    let mut buf = [0u8; HEADER_LEN];
    buf[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    // length stays 0x0000 (no attributes).
    buf[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    buf[8..20].copy_from_slice(&tx_id);
    buf
}

/// Cheap predicate: does `buf` look like a STUN Binding Success Response we might have asked for?
///
/// Only checks the fixed header bytes (type and cookie); it does **not** validate the
/// transaction id or attributes. Used in the recv loop to decide whether to attempt the full,
/// transaction-matched [`parse_binding_response`] before falling through to the disco demux.
pub fn looks_like_stun_success(buf: &[u8]) -> bool {
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
/// - the message carries a well-formed XOR-MAPPED-ADDRESS (`0x0020`) attribute with IPv4
///   family (`0x01`).
///
/// Returns `None` on any mismatch, on an IPv6 family (`0x02`) mapped address, on truncation, or
/// on a malformed TLV / bad attribute length. Attributes are walked with full bounds checks; a
/// single malformed attribute aborts the walk (fail closed) rather than guessing.
pub fn parse_binding_response(buf: &[u8], expected: StunTxId) -> Option<SocketAddrV4> {
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

        if attr_type == ATTR_XOR_MAPPED_ADDRESS {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a Binding Success Response carrying an IPv4 XOR-MAPPED-ADDRESS for `addr` and the
    /// given transaction id, matching the wire format we parse.
    fn encode_success_ipv4(tx_id: StunTxId, addr: SocketAddrV4) -> Vec<u8> {
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
    fn encode_success_ipv6(tx_id: StunTxId) -> Vec<u8> {
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

    #[test]
    fn encode_binding_request_layout() {
        let tx_id: StunTxId = [9u8; 12];
        let req = encode_binding_request(tx_id);
        assert_eq!(req[0..2], BINDING_REQUEST.to_be_bytes());
        assert_eq!(req[2..4], [0, 0], "no attributes => length 0");
        assert_eq!(req[4..8], MAGIC_COOKIE.to_be_bytes());
        assert_eq!(req[8..20], tx_id);
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
