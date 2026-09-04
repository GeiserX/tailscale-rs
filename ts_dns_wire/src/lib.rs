//! Minimal RFC 1035 DNS wire-format codec for a MagicDNS responder.
//!
//! This crate provides just enough of the DNS wire format to:
//!
//! - decode an incoming UDP DNS query (the first question only), via
//!   [`decode_query`], and
//! - encode a corresponding response (echoing the question, appending answer
//!   records and, for an authoritative negative answer, the zone's SOA in the
//!   authority section), via [`encode_response`].
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

/// TTL (seconds) applied to every positive answer record we emit.
///
/// Deliberately short. The source of truth for a MagicDNS answer is the local, in-memory netmap,
/// so a re-query costs nothing, while anything that caches downstream (notably macOS
/// `mDNSResponder`) holds the stale answer for the full TTL and delays clients noticing a node
/// rename by that long. Go `net/dns/resolver/tsdns.go` `defaultTTL`.
const ANSWER_TTL: u32 = 5;

/// TTL (seconds) advertised for negative caching by the SOA record attached to the authority
/// section of a negative answer we are authoritative for (RFC 2308).
///
/// It is the record's own TTL and its MINIMUM field: a resolver bounds how long it caches the
/// nonexistence of the name (or of records of the queried type) by the smaller of the two, so both
/// carry the same value. Go `net/dns/resolver/tsdns.go` `negativeTTL`.
const NEGATIVE_TTL: u32 = 10;

/// The RR TYPE of a start-of-authority record (RFC 1035 §3.3.13).
const SOA_TYPE: u16 = 6;

/// The `IN` (internet) RR CLASS (RFC 1035 §3.2.4).
const CLASS_IN: u16 = 1;

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

/// The zone an authoritative *negative* answer advertises in its authority section.
///
/// [`encode_response`] turns this into a single SOA record whose only purpose is telling a caching
/// resolver how long it may remember the answer's negativeness (`NEGATIVE_TTL`, RFC 2308). Every
/// field except the TTLs is a placeholder — nothing consumes them here (no secondaries, no zone
/// transfers) — so the record's NAME, MNAME and RNAME are all just `zone`, mirroring Go
/// `net/dns/resolver/tsdns.go` `marshalSOA`.
///
/// Set it only on a response that is negative *and* authoritative: an NXDOMAIN for a name inside a
/// zone this node serves, or a NODATA (empty NOERROR) for such a name. Attaching it to a positive
/// answer, a SERVFAIL, or a name we merely forward for would be a claim of authority we do not have.
#[derive(Clone)]
pub struct SoaZone {
    /// The zone we are authoritative for that contains the question's name — for MagicDNS, the
    /// matching tailnet search domain, negative split-DNS route, or CGNAT reverse zone.
    pub zone: Name,
    /// The SOA SERIAL field. A serial should only change when the zone data does, but nothing
    /// consumes ours, so the caller passes the response time in unix seconds: monotonic, cheap, and
    /// it fits in a `u32` until 2106.
    pub serial: u32,
}

/// A decoded DNS query (the first question only).
pub struct Query {
    /// The transaction id, echoed back in the response.
    pub id: u16,
    /// The first (and only decoded) question.
    pub question: Question,
    /// The query's Recursion-Desired (RD) bit. A response must echo RD and, when it is set, also set
    /// Recursion-Available (RA) — Go derives the response header from the parsed query header
    /// (`net/dns/resolver` `marshalResponse`), so a real MagicDNS reply to a stub resolver (which
    /// always sets RD=1) has RD=1+RA=1. Captured here so [`encode_response`] can mirror it instead of
    /// clearing both (which is a 2-bit fingerprint on every response).
    pub recursion_desired: bool,
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
    /// Server failure — the server could not process the query (RCODE 2).
    ServFail,
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
            Rcode::ServFail => 2,
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
        // RD is bit 8 (0x0100) of the flags word.
        recursion_desired: flags & 0x0100 != 0,
    })
}

/// Encode a single-question DNS query (the inverse of [`decode_query`]).
///
/// Produces a standard recursion-desired query: a 12-byte header (`id`; flags `RD=1` with QR/opcode/
/// AA/TC/RA/Z/RCODE all clear; `QDCOUNT=1`; `ANCOUNT`/`NSCOUNT`/`ARCOUNT=0`) followed by the question
/// section (QNAME as length-prefixed labels + terminating zero, then `qtype` and `qclass`, both
/// big-endian). No EDNS(0) OPT record is added, matching the rest of this fork's UDP-only,
/// classic-512 DNS path. The result round-trips through [`decode_query`].
pub fn encode_query(id: u16, name: &Name, qtype: &QType, qclass: u16) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();

    // Header. RD (recursion desired) is the only set flag bit (byte 2, 0x01); QR stays 0 (query).
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD=1
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Question: QNAME + QTYPE + QCLASS.
    encode_name(&mut out, name);
    out.extend_from_slice(&qtype_value(qtype).to_be_bytes());
    out.extend_from_slice(&qclass.to_be_bytes());

    out
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
        // Skip empty labels: a zero-length label encodes as a lone `0x00`, which is identical to the
        // QNAME root terminator — it would truncate the name mid-encode and corrupt whatever follows
        // (QTYPE/QCLASS in a query, the next record in a response). Callers normalize names, but skip
        // here too so a stray empty label (e.g. from a trailing/doubled dot) can never desync the wire
        // form. The decoder never produces empty labels, so a decode→encode round trip is unaffected.
        if bytes.is_empty() {
            continue;
        }
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
/// The NAME is either a compression pointer (`0xC0 0x0C`) back to the question name at offset 12
/// (when `compress` is set — i.e. there is more than one answer) or the full uncompressed label
/// sequence of `qname` (the single-answer case). Go only enables compression for `len(IPs) > 1`, so a
/// single-answer reply carries the full name; always emitting a pointer is a fingerprint. Records use
/// class IN and a TTL of [`ANSWER_TTL`] seconds.
fn encode_answer(out: &mut Vec<u8>, ans: &RData, compress: bool, qname: &Name) {
    // NAME: a pointer to the question name (offset 12) when compressing; otherwise the full name.
    if compress {
        out.push(0xC0);
        out.push(0x0C);
    } else {
        encode_name(out, qname);
    }
    // TYPE.
    out.extend_from_slice(&rdata_type(ans).to_be_bytes());
    // CLASS = IN.
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
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

/// Encode `soa` as a single SOA resource record for the authority section of a negative answer.
///
/// The NAME is written uncompressed: the zone is not the question name (it is a suffix of it), so
/// the `0xC0 0x0C` pointer the answer section uses does not apply, and this crate emits no other
/// compression targets.
///
/// Only the TTLs carry meaning. REFRESH/RETRY/EXPIRE/MINIMUM all repeat [`NEGATIVE_TTL`] and MNAME/
/// RNAME both repeat the zone name, exactly as Go's `marshalSOA` does: the record exists solely to
/// bound a downstream resolver's negative caching (RFC 2308), and this node has no secondaries to
/// serve the other fields to.
fn encode_soa(out: &mut Vec<u8>, soa: &SoaZone) {
    encode_name(out, &soa.zone);
    out.extend_from_slice(&SOA_TYPE.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out.extend_from_slice(&NEGATIVE_TTL.to_be_bytes());

    // RDATA into a scratch buffer so RDLENGTH can be written ahead of it.
    let mut rdata: Vec<u8> = Vec::new();
    encode_name(&mut rdata, &soa.zone); // MNAME (placeholder)
    encode_name(&mut rdata, &soa.zone); // RNAME (placeholder)
    rdata.extend_from_slice(&soa.serial.to_be_bytes()); // SERIAL
    rdata.extend_from_slice(&NEGATIVE_TTL.to_be_bytes()); // REFRESH
    rdata.extend_from_slice(&NEGATIVE_TTL.to_be_bytes()); // RETRY
    rdata.extend_from_slice(&NEGATIVE_TTL.to_be_bytes()); // EXPIRE
    rdata.extend_from_slice(&NEGATIVE_TTL.to_be_bytes()); // MINIMUM
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(&rdata);
}

/// Encode a DNS response.
///
/// The header echoes `id`, sets QR=1 (response) and AA=1 (authoritative), echoes the query's
/// Recursion-Desired bit (`recursion_desired`) and — when RD is set — also sets Recursion-Available
/// (RA), matching Go `net/dns/resolver` `marshalResponse`, which derives the response header from the
/// parsed query header (so a reply to a stub resolver, which always sets RD=1, has RD=1+RA=1). It
/// places `rcode` in the low 4 bits; Z and the opcode stay clear (MagicDNS answers standard opcode-0
/// queries). `QDCOUNT` is 1, `ANCOUNT` is the number of answers actually included, `NSCOUNT` is 1
/// when an `soa` was given and fitted, and `ARCOUNT` is 0. The question `q` is echoed in the
/// question section. A single answer's NAME is written uncompressed (full label sequence);
/// compression pointers (`0xC0 0x0C` back to the question name) are used only when there is more
/// than one answer — matching Go, which calls `EnableCompression` only for `len(IPs) > 1`. Answer
/// records use class IN and a TTL of `ANSWER_TTL` (5) seconds.
///
/// `soa` attaches the zone's SOA record to the authority section, advertising a `NEGATIVE_TTL`
/// (10-second) negative-caching bound to downstream resolvers (RFC 2308). Pass it only on an authoritative
/// negative answer — see [`SoaZone`].
///
/// The encoded datagram is capped at the classic 512-byte UDP limit
/// (`MAX_UDP_MSG_LEN`); this fork does not implement EDNS(0). If the full
/// answer set would overflow that limit, the overflowing answers are dropped
/// and the TC (truncation) bit is set in the header, so the result is always
/// `<= 512` bytes and never an oversized datagram. Note a single answer's size now includes the FULL
/// uncompressed question name (compression only kicks in for >1 answer), so the 512 cap is reached by
/// a shorter answer set than when every answer was a 2-byte pointer — only material for a near-maximal
/// (~240+ wire-byte) name, where even one answer is then dropped + TC set (valid DNS; this fork is
/// UDP-only).
///
/// The SOA is appended last and only if it still fits under that cap; if it does not, it is
/// **dropped** (`NSCOUNT` stays 0) and TC is *not* set on its account. The record is advisory — it
/// only shortens how long a resolver may cache a negative answer that is already complete without
/// it — so it must never displace an answer, and setting TC would tell a stub to retry over TCP,
/// which this UDP-only fork cannot serve. That keeps the "an authoritative reply always fits 512"
/// invariant the forwarded-path truncation check relies on.
pub fn encode_response(
    id: u16,
    q: &Question,
    recursion_desired: bool,
    rcode: Rcode,
    answers: &[RData],
    soa: Option<&SoaZone>,
) -> Vec<u8> {
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
    //
    // Compression: only when there is more than one answer (Go calls `EnableCompression` solely for
    // `len(IPs) > 1`). A single answer's NAME is written in full (uncompressed) label form; with >1,
    // each answer NAME is a `0xC0 0x0C` pointer back to the question name. This matches Go's answer-
    // section byte layout instead of always emitting a pointer (a fingerprint on every reply).
    let compress = answers.len() > 1;
    let mut ancount: u16 = 0;
    let mut truncated = false;
    for ans in answers {
        let mut rr: Vec<u8> = Vec::new();
        encode_answer(&mut rr, ans, compress, &q.name);
        if out.len() + rr.len() > MAX_UDP_MSG_LEN {
            // This answer (and any after it) does not fit. Drop the rest and
            // mark the response truncated.
            truncated = true;
            break;
        }
        out.extend_from_slice(&rr);
        ancount += 1;
    }

    // Authority section: the zone's SOA, when this is an authoritative negative answer. Appended
    // only if it fits within what is left of the 512-byte budget; see the note above on why an
    // SOA that does not fit is dropped rather than truncating the message or setting TC.
    let mut nscount: u16 = 0;
    if let Some(soa) = soa {
        let mut rr: Vec<u8> = Vec::new();
        encode_soa(&mut rr, soa);
        if out.len() + rr.len() <= MAX_UDP_MSG_LEN {
            out.extend_from_slice(&rr);
            nscount = 1;
        }
    }

    // Finalize the flags word: QR=1 (bit15), AA=1 (bit10); echo RD (bit8) from the query and set RA
    // (bit7) when RD is set (Go derives the response header from the query header — a stub resolver's
    // RD=1 query gets RD=1+RA=1 back); TC (bit9) if any answers were dropped; low 4 RCODE bits.
    let mut flags: u16 = 0x8000 | 0x0400 | (rcode.value() as u16);
    if recursion_desired {
        flags |= 0x0100; // RD (echoed from the query)
        flags |= 0x0080; // RA (we set it whenever RD was requested, matching Go)
    }
    if truncated {
        flags |= 0x0200; // TC
    }
    out[2..4].copy_from_slice(&flags.to_be_bytes());
    out[6..8].copy_from_slice(&ancount.to_be_bytes());
    out[8..10].copy_from_slice(&nscount.to_be_bytes());

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
        // flags: QR=0, RD=1 — every real stub resolver sets RD, so the test fixtures match it (and
        // exercise the RD-echo / RA path in `encode_response`).
        buf.extend_from_slice(&0x0100u16.to_be_bytes());
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
    fn encode_query_round_trips_through_decode() {
        // An arbitrary (non-A/AAAA/PTR) qtype must be preserved verbatim — query_dns issues these.
        let name = Name(vec![String::from("example"), String::from("com")]);
        let buf = encode_query(0xBEEF, &name, &QType::Other(16 /* TXT */), 1);

        // Header: RD=1, QR=0 (a query), QDCOUNT=1, ANCOUNT=0.
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        assert_eq!(flags & 0x8000, 0, "QR=0 (this is a query)");
        assert_eq!(flags & 0x0100, 0x0100, "RD=1 (recursion desired)");
        assert_eq!(u16::from_be_bytes([buf[4], buf[5]]), 1, "QDCOUNT=1");
        assert_eq!(u16::from_be_bytes([buf[6], buf[7]]), 0, "ANCOUNT=0");

        // The query decodes back to the same id, name, qtype, and class.
        let q = decode_query(&buf).expect("encode_query output is a valid query");
        assert_eq!(q.id, 0xBEEF);
        assert_eq!(q.question.name.to_canon(), "example.com");
        assert!(matches!(q.question.qtype, QType::Other(16)));
        assert_eq!(q.question.qclass, 1);
    }

    #[test]
    fn encode_query_skips_empty_labels_no_premature_terminator() {
        // A stray empty label (from a trailing/doubled dot in the source name) must NOT emit a lone
        // 0x00 that truncates the QNAME before its QTYPE/QCLASS. encode_name skips empties, so the
        // query still decodes to the non-empty labels with the correct qtype/class.
        let name = Name(vec![
            String::from("foo"),
            String::new(), // would be a premature root terminator if not skipped
            String::from("com"),
        ]);
        let buf = encode_query(0x1, &name, &QType::Other(16), 1);
        let q = decode_query(&buf).expect("decodes despite the empty label");
        assert_eq!(q.question.name.to_canon(), "foo.com");
        assert!(matches!(q.question.qtype, QType::Other(16)));
        assert_eq!(q.question.qclass, 1);
    }

    #[test]
    fn encode_query_preserves_named_qtypes() {
        for (qt, raw) in [(QType::A, 1u16), (QType::Aaaa, 28), (QType::Ptr, 12)] {
            let name = Name(vec![
                String::from("host"),
                String::from("ts"),
                String::from("net"),
            ]);
            let buf = encode_query(0x1, &name, &qt, 1);
            let q = decode_query(&buf).expect("decodes");
            assert_eq!(
                qtype_value(&q.question.qtype),
                raw,
                "qtype {raw} round-trips"
            );
        }
    }

    #[test]
    fn round_trip_a_response() {
        let buf = build_query(0x1234, &["host", "user", "ts", "net"], 1, 1);
        let q = decode_query(&buf).expect("decodes");
        assert!(q.recursion_desired, "build_query sets RD=1");
        let out = encode_response(
            0x1234,
            &q.question,
            q.recursion_desired,
            Rcode::NoError,
            &[RData::A([100, 64, 0, 1])],
            None,
        );

        // Re-parse the header.
        assert!(out.len() >= HEADER_LEN);
        let id = u16::from_be_bytes([out[0], out[1]]);
        let flags = u16::from_be_bytes([out[2], out[3]]);
        let ancount = u16::from_be_bytes([out[6], out[7]]);
        assert_eq!(id, 0x1234);
        assert_eq!(flags & 0x8000, 0x8000, "QR=1");
        assert_eq!(flags & 0x0400, 0x0400, "AA=1");
        assert_eq!(flags & 0x0100, 0x0100, "RD echoed from the query");
        assert_eq!(flags & 0x0080, 0x0080, "RA set because RD was requested");
        assert_eq!(flags & 0x000F, 0, "rcode=0");
        assert_eq!(ancount, 1);

        // A single answer's NAME is the FULL uncompressed label sequence (Go compresses only for
        // >1 answer), then type=1, class=1, ttl=5, rdlen=4, addr.
        let expected_rr: &[u8] = &[
            // NAME: "host.user.ts.net." uncompressed (labels + root 0).
            4, b'h', b'o', b's', b't', 4, b'u', b's', b'e', b'r', 2, b't', b's', 3, b'n', b'e',
            b't', 0, //
            0x00, 0x01, // TYPE = A
            0x00, 0x01, // CLASS = IN
            0x00, 0x00, 0x00, 0x05, // TTL = 5 (ANSWER_TTL)
            0x00, 0x04, // RDLENGTH = 4
            100, 64, 0, 1, // RDATA = 100.64.0.1
        ];
        let tail = &out[out.len() - expected_rr.len()..];
        assert_eq!(tail, expected_rr);
        // And no compression pointer anywhere in a single-answer response.
        assert!(
            !out[HEADER_LEN..].windows(2).any(|w| w[0] == 0xC0),
            "single-answer response must not use a compression pointer"
        );
    }

    /// A response with MORE than one answer DOES use a `0xC0 0x0C` pointer for each answer NAME (Go
    /// `EnableCompression` for `len(IPs) > 1`).
    #[test]
    fn multi_answer_response_uses_compression_pointers() {
        let buf = build_query(0x5555, &["h", "ts", "net"], 1, 1);
        let q = decode_query(&buf).expect("decodes");
        let out = encode_response(
            0x5555,
            &q.question,
            q.recursion_desired,
            Rcode::NoError,
            &[RData::A([100, 64, 0, 1]), RData::A([100, 64, 0, 2])],
            None,
        );
        let ancount = u16::from_be_bytes([out[6], out[7]]);
        assert_eq!(ancount, 2);
        // Each answer NAME is a pointer 0xC0 0x0C; the answer section begins right after the question.
        // The first answer RR starts with the pointer.
        let q_end = HEADER_LEN
            + // question name "h.ts.net." = 1+1 +2+1 +3+1 +1 = 10 bytes, +4 (qtype+qclass)
            (1 + 1 + 2 + 1 + 3 + 1 + 1)
            + 4;
        assert_eq!(
            &out[q_end..q_end + 2],
            &[0xC0, 0x0C],
            "multi-answer uses a pointer"
        );
    }

    /// A query with RD=0 (e.g. a non-recursive client) must get RD=0 AND RA=0 back — we ECHO the
    /// query's RD, never force it. Pins the "echo, don't set unconditionally" semantics against a
    /// regression that always sets RA.
    #[test]
    fn rd_clear_query_yields_rd_ra_clear_response() {
        // build_query sets RD=1; build a raw RD=0 query by hand (flags word all-zero).
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&0x4242u16.to_be_bytes()); // id
        buf.extend_from_slice(&0u16.to_be_bytes()); // flags: QR=0, RD=0
        buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        buf.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR count
        for label in ["h", "ts", "net"] {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
        buf.extend_from_slice(&1u16.to_be_bytes()); // qtype A
        buf.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
        let q = decode_query(&buf).expect("decodes");
        assert!(!q.recursion_desired, "RD=0 query");
        let out = encode_response(
            0x4242,
            &q.question,
            q.recursion_desired,
            Rcode::NoError,
            &[RData::A([100, 64, 0, 1])],
            None,
        );
        let flags = u16::from_be_bytes([out[2], out[3]]);
        assert_eq!(
            flags & 0x0100,
            0,
            "RD must stay clear (echoed from the RD=0 query)"
        );
        assert_eq!(
            flags & 0x0080,
            0,
            "RA must stay clear when RD was not requested"
        );
        assert_eq!(flags & 0x8000, 0x8000, "QR=1 still set");
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
        let out = encode_response(
            0xABCD,
            &q.question,
            q.recursion_desired,
            Rcode::NoError,
            &answers,
            None,
        );

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
            q.recursion_desired,
            Rcode::NoError,
            &[RData::A([100, 64, 0, 1])],
            None,
        );
        assert!(out.len() <= MAX_UDP_MSG_LEN);
        let flags = u16::from_be_bytes([out[2], out[3]]);
        assert_eq!(flags & 0x0200, 0, "TC bit must be clear");
        let ancount = u16::from_be_bytes([out[6], out[7]]);
        assert_eq!(ancount, 1);
    }

    /// Build an [`SoaZone`] for a dotted zone name.
    fn soa(zone: &str, serial: u32) -> SoaZone {
        SoaZone {
            zone: Name(zone.split('.').map(String::from).collect()),
            serial,
        }
    }

    /// A negative answer carrying an SOA puts exactly one record in the authority section, with
    /// the zone name, TYPE=SOA, CLASS=IN, TTL=NEGATIVE_TTL and an RDATA of MNAME/RNAME (both the
    /// zone) + SERIAL + REFRESH/RETRY/EXPIRE/MINIMUM (all NEGATIVE_TTL).
    #[test]
    fn nxdomain_with_soa_emits_one_authority_record() {
        let buf = build_query(0x0F0F, &["nope", "user", "ts", "net"], 1, 1);
        let q = decode_query(&buf).expect("decodes");
        let out = encode_response(
            0x0F0F,
            &q.question,
            q.recursion_desired,
            Rcode::NxDomain,
            &[],
            Some(&soa("user.ts.net", 0x0102_0304)),
        );

        let flags = u16::from_be_bytes([out[2], out[3]]);
        assert_eq!(flags & 0x000F, 3, "NXDOMAIN");
        assert_eq!(flags & 0x0400, 0x0400, "AA still set");
        assert_eq!(u16::from_be_bytes([out[6], out[7]]), 0, "ANCOUNT=0");
        assert_eq!(u16::from_be_bytes([out[8], out[9]]), 1, "NSCOUNT=1");
        assert_eq!(u16::from_be_bytes([out[10], out[11]]), 0, "ARCOUNT=0");
        assert_eq!(flags & 0x0200, 0, "TC must stay clear");

        // The whole authority record, byte for byte. "user.ts.net." is 14 wire bytes.
        let zone: &[u8] = &[
            4, b'u', b's', b'e', b'r', 2, b't', b's', 3, b'n', b'e', b't', 0,
        ];
        let mut expected: Vec<u8> = Vec::new();
        expected.extend_from_slice(zone);
        expected.extend_from_slice(&[0x00, 0x06]); // TYPE = SOA
        expected.extend_from_slice(&[0x00, 0x01]); // CLASS = IN
        expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x0A]); // TTL = 10
        // RDLENGTH = MNAME + RNAME + 5 * u32.
        let rdlen = (zone.len() * 2 + 20) as u16;
        expected.extend_from_slice(&rdlen.to_be_bytes());
        expected.extend_from_slice(zone); // MNAME
        expected.extend_from_slice(zone); // RNAME
        expected.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // SERIAL
        for _ in 0..4 {
            // REFRESH, RETRY, EXPIRE, MINIMUM
            expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x0A]);
        }
        assert_eq!(&out[out.len() - expected.len()..], expected.as_slice());
        // The SOA NAME is written in full: the zone is a suffix of the question name, not the
        // question name itself, so the answer section's 0xC0 0x0C pointer does not apply.
        assert!(
            !out[HEADER_LEN..].contains(&0xC0),
            "no compression pointer in a negative answer"
        );
    }

    /// Passing no `soa` leaves the authority section empty — an SOA-less negative answer is still
    /// what a non-authoritative rcode (SERVFAIL, REFUSED) must produce.
    #[test]
    fn negative_answer_without_soa_has_empty_authority_section() {
        let buf = build_query(0x0F0F, &["nope", "example", "com"], 1, 1);
        let q = decode_query(&buf).expect("decodes");
        let out = encode_response(
            0x0F0F,
            &q.question,
            q.recursion_desired,
            Rcode::ServFail,
            &[],
            None,
        );
        assert_eq!(u16::from_be_bytes([out[8], out[9]]), 0, "NSCOUNT=0");
        // Header + question only.
        assert_eq!(out.len(), HEADER_LEN + (1 + 4 + 1 + 7 + 1 + 3 + 1) + 4);
    }

    /// A NODATA (empty NOERROR) answer takes the SOA too: "the name exists, but holds no record of
    /// the queried type" is a negative answer a resolver caches, so it needs the same TTL bound.
    #[test]
    fn nodata_answer_carries_the_soa() {
        let buf = build_query(0x2222, &["host", "user", "ts", "net"], 28, 1);
        let q = decode_query(&buf).expect("decodes");
        let out = encode_response(
            0x2222,
            &q.question,
            q.recursion_desired,
            Rcode::NoError,
            &[],
            Some(&soa("user.ts.net", 7)),
        );
        assert_eq!(flags_of(&out) & 0x000F, 0, "NOERROR");
        assert_eq!(u16::from_be_bytes([out[6], out[7]]), 0, "ANCOUNT=0");
        assert_eq!(u16::from_be_bytes([out[8], out[9]]), 1, "NSCOUNT=1");
    }

    /// The flags word of a response.
    fn flags_of(out: &[u8]) -> u16 {
        u16::from_be_bytes([out[2], out[3]])
    }

    /// The SOA is advisory: when it does not fit under the 512-byte cap it is dropped, NSCOUNT
    /// stays 0, TC is NOT set, and the message stays within the cap. Setting TC here would tell a
    /// stub to retry over TCP, which this UDP-only fork cannot serve — for an answer that was
    /// already complete without the SOA.
    #[test]
    fn soa_that_does_not_fit_is_dropped_without_setting_tc() {
        // A near-maximal question name: 3 labels of 63 bytes = 193 wire bytes.
        let long = "a".repeat(MAX_LABEL_LEN);
        let labels = [long.as_str(), long.as_str(), long.as_str()];
        let buf = build_query(0x3333, &labels, 1, 1);
        let q = decode_query(&buf).expect("decodes");

        // The zone is the question's last two labels (129 wire bytes). Its RR is the zone name
        // three times over (NAME, MNAME, RNAME) plus 30 bytes of fixed fields = 417 bytes, and
        // only 512 - 12 - 193 - 4 = 303 are left after the header and question.
        let zone = Name(vec![long.clone(), long.clone()]);
        let out = encode_response(
            0x3333,
            &q.question,
            q.recursion_desired,
            Rcode::NxDomain,
            &[],
            Some(&SoaZone { zone, serial: 1 }),
        );

        assert!(
            out.len() <= MAX_UDP_MSG_LEN,
            "response must stay within 512 bytes, got {}",
            out.len()
        );
        assert_eq!(
            u16::from_be_bytes([out[8], out[9]]),
            0,
            "the SOA must be dropped, not truncated in"
        );
        assert_eq!(
            flags_of(&out) & 0x0200,
            0,
            "TC must NOT be set for a dropped SOA"
        );
        assert_eq!(flags_of(&out) & 0x000F, 3, "still NXDOMAIN");
    }

    /// The SOA never displaces an answer: with an answer set that already overflows 512 bytes the
    /// answers still fill the datagram, TC is set for the *answers* that were dropped, and the
    /// authority section is simply left out.
    #[test]
    fn soa_never_displaces_answers_in_a_truncated_response() {
        let buf = build_query(0x4444, &["host", "ts", "net"], 28, 1);
        let q = decode_query(&buf).expect("decodes");
        let answers: Vec<RData> = (0..64u8).map(|i| RData::Aaaa([i; 16])).collect();

        let without = encode_response(
            0x4444,
            &q.question,
            q.recursion_desired,
            Rcode::NoError,
            &answers,
            None,
        );
        let with = encode_response(
            0x4444,
            &q.question,
            q.recursion_desired,
            Rcode::NoError,
            &answers,
            Some(&soa("ts.net", 1)),
        );

        assert!(with.len() <= MAX_UDP_MSG_LEN);
        assert_eq!(
            u16::from_be_bytes([with[6], with[7]]),
            u16::from_be_bytes([without[6], without[7]]),
            "the same answers fit with an SOA requested as without one"
        );
        assert_eq!(u16::from_be_bytes([with[8], with[9]]), 0, "SOA dropped");
        assert_eq!(
            flags_of(&with) & 0x0200,
            0x0200,
            "TC set for the dropped answers"
        );
        assert_eq!(with, without, "a dropped SOA changes nothing on the wire");
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
