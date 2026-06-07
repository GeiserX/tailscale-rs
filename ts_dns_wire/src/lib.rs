//! Minimal RFC 1035 DNS wire-format codec for a MagicDNS responder.
//!
//! This crate provides just enough of the DNS wire format to:
//!
//! - decode an incoming UDP DNS query (the first question only), via
//!   [`decode_query`], and
//! - encode a corresponding response (echoing the question, appending
//!   answer records), via [`encode_response`].
//!
//! It is `#![no_std]` and depends only on `alloc`. It performs no I/O and
//! does no networking; it is pure wire-format codec. None of the parsing
//! functions panic on malformed input.

#![no_std]

extern crate alloc;

use alloc::{string::String, vec::Vec};

/// Fixed DNS header length in bytes (RFC 1035 §4.1.1).
const HEADER_LEN: usize = 12;

/// Maximum length of a single DNS label (RFC 1035 §2.3.4).
const MAX_LABEL_LEN: usize = 63;

/// Maximum total length of a DNS name (RFC 1035 §2.3.4).
const MAX_NAME_LEN: usize = 255;

/// TTL (seconds) applied to every answer record we emit.
const ANSWER_TTL: u32 = 600;

/// Maximum size of a DNS message over UDP without EDNS (RFC 1035 §4.2.1).
///
/// This fork does not implement EDNS(0), so authoritative responses this node
/// builds must fit within the classic 512-byte limit. Answers that would
/// overflow are dropped and the TC (truncation) bit is set instead.
const MAX_UDP_MSG_LEN: usize = 512;

/// The query/answer type field of a DNS question or resource record.
///
/// Only the record types relevant to MagicDNS are named; anything else is
/// preserved verbatim as [`QType::Other`].
pub enum QType {
    /// IPv4 host address record (TYPE 1).
    A,
    /// IPv6 host address record (TYPE 28).
    Aaaa,
    /// Pointer / reverse-lookup record (TYPE 12).
    Ptr,
    /// Any other TYPE value, preserved verbatim.
    Other(u16),
}

/// A single DNS question.
pub struct Question {
    /// The queried name.
    pub name: Name,
    /// The query type.
    pub qtype: QType,
    /// The query class, echoed back unchanged in the response.
    pub qclass: u16,
}

/// A DNS name as a sequence of lowercased labels with no trailing dot.
#[derive(Clone)]
pub struct Name(
    /// The labels, each lowercased ASCII, in order, with no trailing root label.
    pub Vec<String>,
);

impl Name {
    /// Render the name in canonical form: lowercased labels joined by `.`
    /// with no trailing dot.
    ///
    /// This matches the `peer_db` canonicalization (lowercase, no trailing
    /// dot).
    pub fn to_canon(&self) -> String {
        self.0.join(".")
    }

    /// If this name is an `in-addr.arpa` reverse-lookup name with four
    /// leading numeric labels, return the corresponding IPv4 address.
    ///
    /// The labels are stored in reverse octet order (least-significant
    /// octet first), so they are reversed when building the address. Returns
    /// [`None`] if the name does not end in `in-addr.arpa`, does not have at
    /// least six labels, or whose leading labels are not valid `u8` decimal
    /// values.
    pub fn ptr_to_ipv4(&self) -> Option<[u8; 4]> {
        let labels = &self.0;
        if labels.len() < 6 {
            return None;
        }
        let n = labels.len();
        if labels[n - 2] != "in-addr" || labels[n - 1] != "arpa" {
            return None;
        }
        let mut octets = [0u8; 4];
        // labels[0..4] are the reversed octets (least significant first).
        for i in 0..4 {
            let label = labels.get(i)?;
            let val: u8 = label.parse().ok()?;
            octets[3 - i] = val;
        }
        Some(octets)
    }
}

/// Resource-record data for an answer record.
pub enum RData {
    /// An IPv4 address (A record).
    A([u8; 4]),
    /// An IPv6 address (AAAA record).
    Aaaa([u8; 16]),
    /// A pointer to another name (PTR record).
    Ptr(Name),
}

/// A decoded DNS query (the first question only).
pub struct Query {
    /// The transaction id, echoed back in the response.
    pub id: u16,
    /// The first (and only decoded) question.
    pub question: Question,
}

/// Reasons a query buffer could not be decoded.
#[derive(Debug, PartialEq)]
pub enum DecodeError {
    /// The buffer ended before a required field could be read.
    Truncated,
    /// The message is a response (QR bit set), not a query.
    NotQuery,
    /// The message declares no questions (`QDCOUNT == 0`).
    NoQuestion,
    /// The question name was malformed (compression pointer, oversized
    /// label, or oversized name).
    BadName,
}

/// Response codes (RCODE) as defined by RFC 1035 §4.1.1.
pub enum Rcode {
    /// No error condition (RCODE 0).
    NoError,
    /// Format error (RCODE 1).
    FormErr,
    /// Name does not exist (RCODE 3).
    NxDomain,
    /// Query refused (RCODE 5).
    Refused,
    /// Not implemented (RCODE 4).
    NotImpl,
}

impl Rcode {
    /// The numeric RCODE value placed in the low 4 bits of the flags field.
    fn value(&self) -> u8 {
        match self {
            Rcode::NoError => 0,
            Rcode::FormErr => 1,
            Rcode::NxDomain => 3,
            Rcode::NotImpl => 4,
            Rcode::Refused => 5,
        }
    }
}

/// Read a big-endian `u16` at `off`, returning [`DecodeError::Truncated`] if
/// the buffer is too short. Advances `off` past the read on success.
fn read_u16(buf: &[u8], off: &mut usize) -> Result<u16, DecodeError> {
    let hi = *buf.get(*off).ok_or(DecodeError::Truncated)?;
    let lo = *buf.get(*off + 1).ok_or(DecodeError::Truncated)?;
    *off += 2;
    Ok(u16::from_be_bytes([hi, lo]))
}

/// Decode the first question of a DNS query message.
///
/// Returns an error (and never panics) for any malformed or non-query input.
/// Compression pointers in the question name are rejected with
/// [`DecodeError::BadName`]; queries never need them.
pub fn decode_query(buf: &[u8]) -> Result<Query, DecodeError> {
    if buf.len() < HEADER_LEN {
        return Err(DecodeError::Truncated);
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    // QR is the top bit of the flags word. It must be 0 for a query.
    if flags & 0x8000 != 0 {
        return Err(DecodeError::NotQuery);
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount == 0 {
        return Err(DecodeError::NoQuestion);
    }

    let mut off = HEADER_LEN;
    let name = decode_name(buf, &mut off)?;
    let qtype_raw = read_u16(buf, &mut off)?;
    let qclass = read_u16(buf, &mut off)?;

    let qtype = match qtype_raw {
        1 => QType::A,
        28 => QType::Aaaa,
        12 => QType::Ptr,
        n => QType::Other(n),
    };

    Ok(Query {
        id,
        question: Question {
            name: Name(name),
            qtype,
            qclass,
        },
    })
}

/// Decode a length-prefixed QNAME starting at `off`, advancing `off` past the
/// terminating zero label. Rejects compression pointers and enforces the RFC
/// 1035 label/name length limits.
fn decode_name(buf: &[u8], off: &mut usize) -> Result<Vec<String>, DecodeError> {
    let mut labels: Vec<String> = Vec::new();
    // Total wire length consumed by the name, including length bytes and the
    // terminating zero, capped per RFC 1035.
    let mut total_len: usize = 0;

    loop {
        let len_byte = *buf.get(*off).ok_or(DecodeError::Truncated)?;
        // Reject compression pointers (top two bits set): queries never need
        // them and we do not follow them.
        if len_byte & 0xC0 == 0xC0 {
            return Err(DecodeError::BadName);
        }
        // Any other use of the high bits is reserved/invalid.
        if len_byte & 0xC0 != 0 {
            return Err(DecodeError::BadName);
        }
        let len = len_byte as usize;
        *off += 1;
        total_len += 1;
        if len == 0 {
            // Root label terminates the name.
            break;
        }
        if len > MAX_LABEL_LEN {
            return Err(DecodeError::BadName);
        }
        total_len += len;
        if total_len > MAX_NAME_LEN {
            return Err(DecodeError::BadName);
        }
        let end = *off + len;
        let label_bytes = buf.get(*off..end).ok_or(DecodeError::Truncated)?;
        let mut label = String::with_capacity(len);
        for &b in label_bytes {
            // Reject non-ASCII label octets (0x80-0xFF). DNS hostnames, and
            // IDN punycode (`xn--`), are entirely ASCII, so a non-ASCII byte
            // is not valid hostname material. Rejecting fail-closed (rather
            // than lossily transcoding Latin-1 -> multi-byte UTF-8) keeps the
            // stored label ASCII, which guarantees a byte-for-byte round trip
            // (`encode_name(decode_name(x)) == x`) and correct name
            // comparison.
            if !b.is_ascii() {
                return Err(DecodeError::BadName);
            }
            label.push((b as char).to_ascii_lowercase());
        }
        labels.push(label);
        *off = end;
    }

    Ok(labels)
}

/// Numeric TYPE value for a [`QType`] (inverse of the decode mapping).
fn qtype_value(qtype: &QType) -> u16 {
    match qtype {
        QType::A => 1,
        QType::Aaaa => 28,
        QType::Ptr => 12,
        QType::Other(n) => *n,
    }
}

/// Numeric TYPE value for the [`RData`] kind.
fn rdata_type(rdata: &RData) -> u16 {
    match rdata {
        RData::A(_) => 1,
        RData::Aaaa(_) => 28,
        RData::Ptr(_) => 12,
    }
}

/// Encode a name as length-prefixed labels followed by a zero terminator.
fn encode_name(out: &mut Vec<u8>, name: &Name) {
    for label in &name.0 {
        let bytes = label.as_bytes();
        // Labels longer than 63 bytes are clamped to stay wire-legal; names
        // produced by this crate's decoder never exceed the limit.
        let len = bytes.len().min(MAX_LABEL_LEN);
        out.push(len as u8);
        out.extend_from_slice(&bytes[..len]);
    }
    out.push(0);
}

/// Encode a single answer resource record onto `out`.
///
/// The NAME is a compression pointer (`0xC0 0x0C`) back to the question name
/// at offset 12. Records use class IN and a TTL of [`ANSWER_TTL`] seconds.
fn encode_answer(out: &mut Vec<u8>, ans: &RData) {
    // NAME: compression pointer to the question name at offset 12.
    out.push(0xC0);
    out.push(0x0C);
    // TYPE.
    out.extend_from_slice(&rdata_type(ans).to_be_bytes());
    // CLASS = IN.
    out.extend_from_slice(&1u16.to_be_bytes());
    // TTL.
    out.extend_from_slice(&ANSWER_TTL.to_be_bytes());
    // RDLENGTH + RDATA.
    match ans {
        RData::A(addr) => {
            out.extend_from_slice(&4u16.to_be_bytes());
            out.extend_from_slice(addr);
        }
        RData::Aaaa(addr) => {
            out.extend_from_slice(&16u16.to_be_bytes());
            out.extend_from_slice(addr);
        }
        RData::Ptr(name) => {
            // Encode the name into a scratch buffer to know its length.
            let mut rdata: Vec<u8> = Vec::new();
            encode_name(&mut rdata, name);
            out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            out.extend_from_slice(&rdata);
        }
    }
}

/// Encode a DNS response.
///
/// The header echoes `id`, sets QR=1 (response) and AA=1 (authoritative),
/// clears RD/RA/Z and the opcode, and places `rcode` in the low 4 bits.
/// `QDCOUNT` is 1, `ANCOUNT` is the number of answers actually included, and
/// `NSCOUNT`/`ARCOUNT` are 0. The question `q` is echoed in the question
/// section, and each answer is appended using a compression pointer
/// (`0xC0 0x0C`) back to the question name. Answer records use class IN and a
/// TTL of 600 seconds.
///
/// The encoded datagram is capped at the classic 512-byte UDP limit
/// (`MAX_UDP_MSG_LEN`); this fork does not implement EDNS(0). If the full
/// answer set would overflow that limit, the overflowing answers are dropped
/// and the TC (truncation) bit is set in the header, so the result is always
/// `<= 512` bytes and never an oversized datagram.
pub fn encode_response(id: u16, q: &Question, rcode: Rcode, answers: &[RData]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();

    // Header. The flags word is finalized after the answer loop so we can set
    // the TC bit if any answers were dropped.
    out.extend_from_slice(&id.to_be_bytes());
    // Placeholder for the flags word (bytes 2..4); rewritten below.
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    // Placeholder for ANCOUNT (bytes 6..8); rewritten below once we know how
    // many answers actually fit.
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Question section: echo the name, qtype, qclass. We decode and answer
    // only a single question (QDCOUNT is always 1 in our responses), matching
    // the decoder which reads only the first question.
    encode_name(&mut out, &q.name);
    out.extend_from_slice(&qtype_value(&q.qtype).to_be_bytes());
    out.extend_from_slice(&q.qclass.to_be_bytes());

    // Answer section. Append answers only while they fit within the 512-byte
    // UDP limit. If any answer would overflow, stop and set TC.
    let mut ancount: u16 = 0;
    let mut truncated = false;
    for ans in answers {
        let mut rr: Vec<u8> = Vec::new();
        encode_answer(&mut rr, ans);
        if out.len() + rr.len() > MAX_UDP_MSG_LEN {
            // This answer (and any after it) does not fit. Drop the rest and
            // mark the response truncated.
            truncated = true;
            break;
        }
        out.extend_from_slice(&rr);
        ancount += 1;
    }

    // Finalize the flags word: QR=1 (bit15), AA=1 (bit10), TC (bit9) if any
    // answers were dropped, and the low 4 RCODE bits.
    let mut flags: u16 = 0x8000 | 0x0400 | (rcode.value() as u16);
    if truncated {
        flags |= 0x0200; // TC
    }
    out[2..4].copy_from_slice(&flags.to_be_bytes());
    out[6..8].copy_from_slice(&ancount.to_be_bytes());

    out
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    /// Build a raw DNS query for `labels` with the given id, qtype, qclass.
    fn build_query(id: u16, labels: &[&str], qtype: u16, qclass: u16) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes()); // flags: QR=0
        buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        for label in labels {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0); // root
        buf.extend_from_slice(&qtype.to_be_bytes());
        buf.extend_from_slice(&qclass.to_be_bytes());
        buf
    }

    #[test]
    fn decode_a_query() {
        let buf = build_query(0x1234, &["host", "user", "ts", "net"], 1, 1);
        let q = decode_query(&buf).expect("decodes");
        assert_eq!(q.id, 0x1234);
        assert_eq!(q.question.name.to_canon(), "host.user.ts.net");
        assert!(matches!(q.question.qtype, QType::A));
        assert_eq!(q.question.qclass, 1);
    }

    #[test]
    fn decode_lowercases_labels() {
        let buf = build_query(0x1, &["HOST", "User", "TS", "NET"], 1, 1);
        let q = decode_query(&buf).expect("decodes");
        assert_eq!(q.question.name.to_canon(), "host.user.ts.net");
    }

    #[test]
    fn round_trip_a_response() {
        let buf = build_query(0x1234, &["host", "user", "ts", "net"], 1, 1);
        let q = decode_query(&buf).expect("decodes");
        let out = encode_response(
            0x1234,
            &q.question,
            Rcode::NoError,
            &[RData::A([100, 64, 0, 1])],
        );

        // Re-parse the header.
        assert!(out.len() >= HEADER_LEN);
        let id = u16::from_be_bytes([out[0], out[1]]);
        let flags = u16::from_be_bytes([out[2], out[3]]);
        let ancount = u16::from_be_bytes([out[6], out[7]]);
        assert_eq!(id, 0x1234);
        assert_eq!(flags & 0x8000, 0x8000, "QR=1");
        assert_eq!(flags & 0x0400, 0x0400, "AA=1");
        assert_eq!(flags & 0x000F, 0, "rcode=0");
        assert_eq!(ancount, 1);

        // The A record should appear: compression pointer, type=1, class=1,
        // ttl=600, rdlen=4, addr.
        let expected_rr: [u8; 16] = [
            0xC0, 0x0C, // NAME pointer
            0x00, 0x01, // TYPE = A
            0x00, 0x01, // CLASS = IN
            0x00, 0x00, 0x02, 0x58, // TTL = 600
            0x00, 0x04, // RDLENGTH = 4
            100, 64, 0, 1, // RDATA
        ];
        let tail = &out[out.len() - expected_rr.len()..];
        assert_eq!(tail, expected_rr);
    }

    #[test]
    fn truncated_header_only_is_err_no_panic() {
        // Header declares one question but the buffer has no question body.
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&0x1u16.to_be_bytes()); // id
        buf.extend_from_slice(&0u16.to_be_bytes()); // flags QR=0
        buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
        buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        let res = decode_query(&buf);
        assert!(res.is_err());
        assert!(matches!(res, Err(DecodeError::Truncated)));
    }

    #[test]
    fn compression_pointer_in_qname_is_bad_name() {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&0x1u16.to_be_bytes()); // id
        buf.extend_from_slice(&0u16.to_be_bytes()); // flags QR=0
        buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
        buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        // QNAME: a normal label then a compression pointer.
        buf.push(4);
        buf.extend_from_slice(b"host");
        buf.push(0xC0);
        buf.push(0x0C);
        buf.extend_from_slice(&1u16.to_be_bytes()); // qtype
        buf.extend_from_slice(&1u16.to_be_bytes()); // qclass
        let res = decode_query(&buf);
        assert!(matches!(res, Err(DecodeError::BadName)));
    }

    #[test]
    fn decode_aaaa_query() {
        let buf = build_query(0x9, &["host", "ts", "net"], 28, 1);
        let q = decode_query(&buf).expect("decodes");
        assert!(matches!(q.question.qtype, QType::Aaaa));
    }

    #[test]
    fn non_ascii_label_byte_is_rejected() {
        // A label containing a non-ASCII octet (0x80-0xFF) is not valid DNS
        // hostname material and must be rejected fail-closed rather than
        // lossily transcoded as Latin-1.
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&0x1u16.to_be_bytes()); // id
        buf.extend_from_slice(&0u16.to_be_bytes()); // flags QR=0
        buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
        buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        // QNAME: a single 4-byte label with a high-bit-set octet.
        buf.push(4);
        buf.extend_from_slice(&[b'h', 0xC3, b's', b't']);
        buf.push(0); // root
        buf.extend_from_slice(&1u16.to_be_bytes()); // qtype
        buf.extend_from_slice(&1u16.to_be_bytes()); // qclass
        let res = decode_query(&buf);
        assert!(matches!(res, Err(DecodeError::BadName)));
    }

    #[test]
    fn ascii_label_round_trips_byte_for_byte() {
        // For any all-ASCII (already lowercased) QNAME, encoding the decoded
        // name reproduces the original wire bytes exactly.
        let labels: &[&str] = &["host", "user", "ts", "net"];
        let buf = build_query(0x1234, labels, 1, 1);
        let q = decode_query(&buf).expect("decodes");

        // Reconstruct the on-wire QNAME (labels + root) from the original.
        let mut original_qname: Vec<u8> = Vec::new();
        for label in labels {
            original_qname.push(label.len() as u8);
            original_qname.extend_from_slice(label.as_bytes());
        }
        original_qname.push(0);

        let mut encoded_qname: Vec<u8> = Vec::new();
        encode_name(&mut encoded_qname, &q.question.name);
        assert_eq!(encoded_qname, original_qname);
    }

    #[test]
    fn oversized_answer_set_sets_tc_and_caps_512() {
        // AAAA records are 28 bytes each on the wire (2 ptr + 2 type +
        // 2 class + 4 ttl + 2 rdlen + 16 rdata). With a short question this
        // overflows 512 bytes well before 64 answers.
        let buf = build_query(0xABCD, &["host", "ts", "net"], 28, 1);
        let q = decode_query(&buf).expect("decodes");

        let answers: Vec<RData> = (0..64u8).map(|i| RData::Aaaa([i; 16])).collect();
        let out = encode_response(0xABCD, &q.question, Rcode::NoError, &answers);

        assert!(
            out.len() <= MAX_UDP_MSG_LEN,
            "response must be capped at 512 bytes, got {}",
            out.len()
        );
        let flags = u16::from_be_bytes([out[2], out[3]]);
        assert_eq!(flags & 0x0200, 0x0200, "TC bit must be set");
        let ancount = u16::from_be_bytes([out[6], out[7]]);
        assert!(
            (ancount as usize) < answers.len(),
            "some answers must have been dropped"
        );
    }

    #[test]
    fn answer_set_within_512_does_not_set_tc() {
        let buf = build_query(0xABCD, &["host", "ts", "net"], 1, 1);
        let q = decode_query(&buf).expect("decodes");
        let out = encode_response(
            0xABCD,
            &q.question,
            Rcode::NoError,
            &[RData::A([100, 64, 0, 1])],
        );
        assert!(out.len() <= MAX_UDP_MSG_LEN);
        let flags = u16::from_be_bytes([out[2], out[3]]);
        assert_eq!(flags & 0x0200, 0, "TC bit must be clear");
        let ancount = u16::from_be_bytes([out[6], out[7]]);
        assert_eq!(ancount, 1);
    }

    #[test]
    fn ptr_to_ipv4_reverses_octets() {
        let name = Name(vec![
            String::from("1"),
            String::from("0"),
            String::from("168"),
            String::from("192"),
            String::from("in-addr"),
            String::from("arpa"),
        ]);
        assert_eq!(name.ptr_to_ipv4(), Some([192, 168, 0, 1]));
    }
}
