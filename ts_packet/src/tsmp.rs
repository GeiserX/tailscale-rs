//! TSMP — the "Tailscale Message Protocol", Go [`net/packet/tsmp.go`].
//!
//! TSMP is Tailscale's ICMP-like in-band signalling protocol between nodes. It rides IP protocol
//! **99** ("any private encryption scheme") *inside* the WireGuard tunnel, so a TSMP message is
//! only ever seen after decryption and never touches the host network stack.
//!
//! This module carries the **receive** side of the disco-key advertisement
//! (Go `packet.TSMPDiscoKeyAdvertisement`, upstream capability version 144): a peer announces its
//! current disco public key immediately after an eligible WireGuard session is established, which
//! lets the receiver learn (or re-learn) that key without waiting for a netmap update or restarting
//! WireGuard. A real Go peer sends this to us **unprompted**, so parsing it is interop-visible even
//! though this node does not yet send one.
//!
//! [`net/packet/tsmp.go`]: https://github.com/tailscale/tailscale/blob/main/net/packet/tsmp.go

use core::net::IpAddr;

/// The IP protocol number TSMP rides on (Go `ipproto.TSMP`). Not IANA-assigned: 99 is "any private
/// encryption scheme", which Tailscale reuses for inter-node messages.
pub const IP_PROTO_TSMP: u8 = 99;

/// Type byte of a [`TailscaleRejectedHeader`]-style rejected-connection message
/// (Go `packet.TSMPTypeRejectedConn`). Not parsed here.
///
/// [`TailscaleRejectedHeader`]: https://github.com/tailscale/tailscale/blob/main/net/packet/tsmp.go
pub const TSMP_TYPE_REJECTED_CONN: u8 = b'!';

/// Type byte of a TSMP ping request (Go `packet.TSMPTypePing`). Not parsed here.
pub const TSMP_TYPE_PING: u8 = b'p';

/// Type byte of a TSMP pong reply (Go `packet.TSMPTypePong`). Not parsed here.
pub const TSMP_TYPE_PONG: u8 = b'o';

/// Type byte of a disco-key advertisement (Go `packet.TSMPTypeDiscoAdvertisement`).
pub const TSMP_TYPE_DISCO_ADVERTISEMENT: u8 = b'a';

/// The shortest body Go accepts as TSMP at all (Go `packet.minTSMPSize`, the 7-byte rejected-header
/// body). A TSMP packet whose body is shorter is demoted to "unknown" by Go's decoder and never
/// reaches a TSMP consumer.
const MIN_TSMP_SIZE: usize = 7;

/// Length of a disco public key on the wire, in bytes (Go `key.DiscoPublicRawLen`).
pub const DISCO_KEY_LEN: usize = 32;

/// Wire length of a disco-key advertisement body: the type byte plus the raw key
/// (Go asserts exactly this in `TSMPDiscoKeyAdvertisement.Marshal`).
pub const DISCO_ADVERTISEMENT_LEN: usize = 1 + DISCO_KEY_LEN;

/// Length of an IPv4 base header, in bytes (Go `packet.ip4HeaderLength`).
const IP4_HEADER_LEN: usize = 20;

/// Length of an IPv6 base header, in bytes (Go `packet.ip6HeaderLength`).
const IP6_HEADER_LEN: usize = 40;

/// A peer's disco public key, advertised over TSMP inside the WireGuard tunnel.
///
/// Go [`packet.TSMPDiscoKeyAdvertisement`]. On the wire, after the IP header, the body is exactly
/// [`DISCO_ADVERTISEMENT_LEN`] (33) bytes:
///
/// ```text
/// 'a' (TSMP_TYPE_DISCO_ADVERTISEMENT) | 32 disco key bytes
/// ```
///
/// `src`/`dst` are lifted from the enclosing IP header, exactly as Go's
/// `Parsed.AsTSMPDiscoAdvertisement` does.
///
/// The key is kept as raw bytes rather than a typed key so this crate stays dependency-free and
/// `no_std`; the consumer converts it (`ts_keys::DiscoPublicKey: From<[u8; 32]>`) at the point it
/// is applied to a peer.
///
/// [`packet.TSMPDiscoKeyAdvertisement`]: https://github.com/tailscale/tailscale/blob/main/net/packet/tsmp.go
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiscoKeyAdvertisement {
    /// Source address of the enclosing IP header — the peer that advertised the key.
    pub src: IpAddr,
    /// Destination address of the enclosing IP header (one of this node's tailnet addresses).
    pub dst: IpAddr,
    /// The advertised disco public key, raw.
    pub key: [u8; DISCO_KEY_LEN],
}

impl DiscoKeyAdvertisement {
    /// Whether the advertised key is the all-zero key (Go `key.DiscoPublic.IsZero`).
    ///
    /// A zero key parses fine but must never be *learned*: Go's `tstun` publishes the
    /// advertisement only `if !discoKeyAdvert.Key.IsZero()`, and `magicsock`'s
    /// `HandleDiscoKeyAdvertisement` rejects it a second time. It still means the packet was a
    /// well-formed advertisement, so it is dropped rather than delivered to the local stack.
    pub fn key_is_zero(&self) -> bool {
        self.key == [0u8; DISCO_KEY_LEN]
    }

    /// Parse a complete IP packet (IPv4 or IPv6, as handed up by WireGuard decryption) as a TSMP
    /// disco-key advertisement, or `None` if it is not one.
    ///
    /// Go `Parsed.AsTSMPDiscoAdvertisement` applied to a `Parsed` that `Parsed.Decode` filled in —
    /// i.e. this folds Go's decode step (which is what rejects a truncated, fragmented or
    /// non-TSMP packet before the type byte is ever looked at) into the same call.
    ///
    /// Returns `None` — never a partially-filled value — for anything that is not a complete
    /// advertisement: a non-TSMP protocol, a truncated packet, a fragment, a body shorter than
    /// [`DISCO_ADVERTISEMENT_LEN`], or a TSMP body carrying some other type byte (a ping, a pong,
    /// a rejected-connection header, or a type this client does not know).
    pub fn parse(ip_packet: &[u8]) -> Option<Self> {
        let (src, dst, body) = tsmp_body(ip_packet)?;

        // Go: `if len(p) < 33 || p[0] != byte(TSMPTypeDiscoAdvertisement) { return }`. Note the
        // length test is `<`, not `==`: a longer body with the right prefix is still a valid
        // advertisement, so a future upstream extension that appends fields stays parseable.
        if body.len() < DISCO_ADVERTISEMENT_LEN || body[0] != TSMP_TYPE_DISCO_ADVERTISEMENT {
            return None;
        }

        let key: [u8; DISCO_KEY_LEN] = body[1..DISCO_ADVERTISEMENT_LEN].try_into().ok()?;

        Some(Self { src, dst, key })
    }
}

/// The TSMP body of an IP packet, plus the source and destination from its IP header, or `None` if
/// the packet is not a well-formed, unfragmented TSMP packet.
///
/// This is the TSMP arm of Go's `Parsed.decode4` / `Parsed.decode6` plus `Parsed.Payload()`:
/// everything those do before a TSMP consumer gets to look at the first body byte. In particular
/// the returned body is bounded by the IP header's own length field (Go's `q.length`), not by the
/// buffer, so trailing bytes past the IP length are never treated as message content.
pub fn tsmp_body(b: &[u8]) -> Option<(IpAddr, IpAddr, &[u8])> {
    match b.first()? >> 4 {
        4 => tsmp_body4(b),
        6 => tsmp_body6(b),
        _ => None,
    }
}

/// IPv4 half of [`tsmp_body`] (Go `Parsed.decode4`, `case ipproto.TSMP`).
fn tsmp_body4(b: &[u8]) -> Option<(IpAddr, IpAddr, &[u8])> {
    if b.len() < IP4_HEADER_LEN {
        return None;
    }
    if b[9] != IP_PROTO_TSMP {
        return None;
    }

    // Go `q.length`: the header's own Total Length field. A buffer shorter than it means the packet
    // was cut off, which Go demotes to "unknown".
    let length = usize::from(u16::from_be_bytes([b[2], b[3]]));
    if b.len() < length {
        return None;
    }

    // Go `q.subofs = int((b[0] & 0x0F) << 2)` — the IHL, in 4-byte words.
    let subofs = usize::from(b[0] & 0x0f) * 4;
    if subofs > length {
        // Next-proto starts beyond the end of the packet.
        return None;
    }

    // Go strictly disallows a *fragmented* TSMP: a first fragment with More-Fragments set is
    // demoted to "unknown", and any later fragment is classified as `ipproto.Fragment` rather than
    // TSMP, so neither ever reaches a TSMP consumer. Without the whole message in hand it cannot be
    // a valid inter-node control packet.
    let frag_flags = u16::from_be_bytes([b[6], b[7]]);
    if frag_flags & 0x2000 != 0 || frag_flags & 0x1fff != 0 {
        return None;
    }

    // Go measures the sub-header against the rest of the *buffer* (`sub := b[q.subofs:]`) but slices
    // the payload against the IP length (`Payload()` is `b[dataofs:length]`); keep both.
    if b.len() - subofs < MIN_TSMP_SIZE {
        return None;
    }

    let src = IpAddr::from([b[12], b[13], b[14], b[15]]);
    let dst = IpAddr::from([b[16], b[17], b[18], b[19]]);

    Some((src, dst, &b[subofs..length]))
}

/// IPv6 half of [`tsmp_body`] (Go `Parsed.decode6`, `case ipproto.TSMP`).
///
/// **Narrower than Go by design:** TSMP must be the base header's immediate Next Header. Go's
/// `decode6` additionally steps over a Fragment extension header, which would let a *first* IPv6
/// fragment carry TSMP (`decode6` has no more-fragments guard, unlike `decode4`). A disco-key
/// advertisement is 33 bytes and is never fragmented by any sender, and this tree does not yet
/// implement IPv6 fragment extension-header classification anywhere else either, so refusing to
/// parse one is the fail-closed choice rather than a half-implemented one.
fn tsmp_body6(b: &[u8]) -> Option<(IpAddr, IpAddr, &[u8])> {
    if b.len() < IP6_HEADER_LEN {
        return None;
    }
    if b[6] != IP_PROTO_TSMP {
        return None;
    }

    // Go `q.length`: the Payload Length field plus the fixed base header.
    let length = usize::from(u16::from_be_bytes([b[4], b[5]])) + IP6_HEADER_LEN;
    if b.len() < length {
        return None;
    }

    if b.len() - IP6_HEADER_LEN < MIN_TSMP_SIZE {
        return None;
    }

    let src: [u8; 16] = b[8..24].try_into().ok()?;
    let dst: [u8; 16] = b[24..40].try_into().ok()?;

    Some((
        IpAddr::from(src),
        IpAddr::from(dst),
        &b[IP6_HEADER_LEN..length],
    ))
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    /// A disco key that is obviously not the zero key, and asymmetric so a reversed or
    /// off-by-one slice would be visible.
    const KEY: [u8; DISCO_KEY_LEN] = [
        0x9c, 0x5f, 0x3a, 0x01, 0x7d, 0xe2, 0x44, 0xb8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a,
        0x69, 0x78,
    ];

    /// Go `packet.ip4Checksum` (RFC 1071), so the test vectors below are byte-identical to what
    /// Go's `IP4Header.Marshal` emits rather than merely parseable by our own decoder.
    fn ip4_checksum(b: &[u8]) -> u16 {
        let mut ac: u32 = 0;
        for pair in b.chunks(2) {
            ac += match pair {
                [hi, lo] => u32::from(u16::from_be_bytes([*hi, *lo])),
                [hi] => u32::from(*hi) << 8,
                _ => 0,
            };
        }
        while (ac >> 16) > 0 {
            ac = (ac >> 16) + (ac & 0xffff);
        }
        !(ac as u16)
    }

    /// Go `packet.Generate(IP4Header{...}, payload)`: an IPv4 header with no options, TTL 64, a
    /// correct header checksum, and `payload` appended.
    fn generate4(proto: u8, src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut buf = alloc::vec![0u8; IP4_HEADER_LEN + payload.len()];
        buf[IP4_HEADER_LEN..].copy_from_slice(payload);

        buf[0] = 0x40 | (IP4_HEADER_LEN >> 2) as u8;
        buf[1] = 0x00;
        let total_len = buf.len() as u16;
        buf[2..4].copy_from_slice(&total_len.to_be_bytes());
        buf[4..6].copy_from_slice(&0u16.to_be_bytes());
        buf[6..8].copy_from_slice(&0u16.to_be_bytes());
        buf[8] = 64;
        buf[9] = proto;
        buf[10..12].copy_from_slice(&0u16.to_be_bytes());
        buf[12..16].copy_from_slice(&src);
        buf[16..20].copy_from_slice(&dst);

        let sum = ip4_checksum(&buf[0..IP4_HEADER_LEN]);
        buf[10..12].copy_from_slice(&sum.to_be_bytes());

        buf
    }

    /// Go `packet.Generate(IP6Header{...}, payload)`.
    fn generate6(next_header: u8, src: [u8; 16], dst: [u8; 16], payload: &[u8]) -> Vec<u8> {
        let mut buf = alloc::vec![0u8; IP6_HEADER_LEN + payload.len()];
        buf[IP6_HEADER_LEN..].copy_from_slice(payload);

        buf[0] = 0x60;
        buf[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        buf[6] = next_header;
        buf[7] = 64;
        buf[8..24].copy_from_slice(&src);
        buf[24..40].copy_from_slice(&dst);

        buf
    }

    /// Go `TSMPDiscoKeyAdvertisement.Marshal`'s payload: the type byte then the raw key.
    fn advertisement_body(key: &[u8; DISCO_KEY_LEN]) -> Vec<u8> {
        let mut body = alloc::vec![TSMP_TYPE_DISCO_ADVERTISEMENT];
        body.extend_from_slice(key);
        assert_eq!(
            body.len(),
            DISCO_ADVERTISEMENT_LEN,
            "Go asserts this exact length in Marshal"
        );
        body
    }

    /// The happy path: a real advertisement, marshalled exactly as Go's
    /// `TSMPDiscoKeyAdvertisement.Marshal` would emit it, decodes to the advertised key.
    #[test]
    fn decodes_a_real_ipv4_advertisement() {
        let pkt = generate4(
            IP_PROTO_TSMP,
            [100, 64, 0, 2],
            [100, 64, 0, 1],
            &advertisement_body(&KEY),
        );

        // The full 53-byte packet, pinned so a future refactor of the generator cannot quietly
        // change what is being parsed: 20-byte IPv4 header, then 'a' (0x61), then the key.
        assert_eq!(pkt.len(), IP4_HEADER_LEN + DISCO_ADVERTISEMENT_LEN);
        assert_eq!(pkt[0], 0x45, "IPv4, IHL 5");
        assert_eq!(&pkt[2..4], &[0x00, 0x35], "total length 53");
        assert_eq!(pkt[9], 99, "IP proto TSMP");
        assert_eq!(pkt[20], b'a', "TSMP disco-advertisement type byte");

        let advert = DiscoKeyAdvertisement::parse(&pkt).expect("advertisement must decode");
        assert_eq!(advert.key, KEY, "the advertised disco key is learned");
        assert_eq!(advert.src, IpAddr::from([100, 64, 0, 2]));
        assert_eq!(advert.dst, IpAddr::from([100, 64, 0, 1]));
        assert!(!advert.key_is_zero());
    }

    /// The same over IPv6 (Go's `Marshal` picks the header family from `Src`).
    #[test]
    fn decodes_a_real_ipv6_advertisement() {
        let src = [
            0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        ];
        let dst = [
            0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ];
        let pkt = generate6(IP_PROTO_TSMP, src, dst, &advertisement_body(&KEY));

        let advert = DiscoKeyAdvertisement::parse(&pkt).expect("advertisement must decode");
        assert_eq!(advert.key, KEY);
        assert_eq!(advert.src, IpAddr::from(src));
        assert_eq!(advert.dst, IpAddr::from(dst));
    }

    /// A zero key is a well-formed advertisement on the wire, but it must never be learned: Go
    /// publishes only `if !discoKeyAdvert.Key.IsZero()`.
    #[test]
    fn zero_key_parses_but_is_flagged() {
        let pkt = generate4(
            IP_PROTO_TSMP,
            [100, 64, 0, 2],
            [100, 64, 0, 1],
            &advertisement_body(&[0u8; DISCO_KEY_LEN]),
        );

        let advert = DiscoKeyAdvertisement::parse(&pkt).expect("a zero-key advertisement parses");
        assert!(
            advert.key_is_zero(),
            "the zero key must be recognizable so it is never learned"
        );
    }

    /// The negative cases: every one of these is a TSMP packet (or nearly one) that must NOT be
    /// mistaken for an advertisement. `parse` returns `None` in each — never a half-filled value.
    #[test]
    fn non_advertisements_do_not_parse() {
        let src = [100, 64, 0, 2];
        let dst = [100, 64, 0, 1];
        let tsmp = |body: &[u8]| generate4(IP_PROTO_TSMP, src, dst, body);

        // Other TSMP message types this client does not (yet) consume. Each is a legitimate
        // message a real Go peer can send us; none is an advertisement.
        let mut ping = alloc::vec![TSMP_TYPE_PING];
        ping.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let mut pong = alloc::vec![TSMP_TYPE_PONG];
        pong.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0]);
        let rejected = alloc::vec![TSMP_TYPE_REJECTED_CONN, 6, b'A', 0x1f, 0x90, 0x00, 0x50];
        for (name, body) in [
            ("ping", ping),
            ("pong", pong),
            ("rejected-conn", rejected),
            // A 33-byte body of the right length but an unknown type byte.
            ("unknown type byte", {
                let mut b = advertisement_body(&KEY);
                b[0] = b'Z';
                b
            }),
        ] {
            assert!(
                DiscoKeyAdvertisement::parse(&tsmp(&body)).is_none(),
                "a {name} TSMP body must not parse as a disco-key advertisement"
            );
        }

        // A truncated advertisement: the right type byte but only 31 of the 32 key bytes. Go's
        // `len(p) < 33` guard rejects it; a decoder that zero-padded would "learn" a wrong key.
        let mut short = advertisement_body(&KEY);
        short.truncate(DISCO_ADVERTISEMENT_LEN - 1);
        assert!(
            DiscoKeyAdvertisement::parse(&tsmp(&short)).is_none(),
            "a truncated advertisement must not be half-parsed"
        );

        // The bare type byte, with no key at all — also below Go's 7-byte `minTSMPSize` floor.
        assert!(
            DiscoKeyAdvertisement::parse(&tsmp(&[TSMP_TYPE_DISCO_ADVERTISEMENT])).is_none(),
            "a bodyless advertisement must not parse"
        );

        // Right body, wrong IP protocol: TSMP is proto 99, and nothing else is TSMP.
        assert!(
            DiscoKeyAdvertisement::parse(&generate4(6, src, dst, &advertisement_body(&KEY)))
                .is_none(),
            "a TCP packet whose payload happens to look like an advertisement must not parse"
        );

        // Not an IP packet at all: a bare body, and empty input.
        assert!(DiscoKeyAdvertisement::parse(&advertisement_body(&KEY)).is_none());
        assert!(DiscoKeyAdvertisement::parse(&[]).is_none());
    }

    /// Fragmentation: Go strictly disallows a fragmented TSMP — a first fragment with
    /// More-Fragments set is demoted to "unknown", and any later fragment is classified as
    /// `ipproto.Fragment`, so neither reaches a TSMP consumer.
    #[test]
    fn fragmented_tsmp_does_not_parse() {
        let base = generate4(
            IP_PROTO_TSMP,
            [100, 64, 0, 2],
            [100, 64, 0, 1],
            &advertisement_body(&KEY),
        );
        assert!(
            DiscoKeyAdvertisement::parse(&base).is_some(),
            "control: the unfragmented packet parses"
        );

        // First fragment (offset 0) with More-Fragments set.
        let mut more_frags = base.clone();
        more_frags[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        assert!(
            DiscoKeyAdvertisement::parse(&more_frags).is_none(),
            "a first TSMP fragment with MF set must not parse"
        );

        // A later fragment (non-zero offset) carries no message start at all.
        let mut later = base.clone();
        later[6..8].copy_from_slice(&0x000au16.to_be_bytes());
        assert!(
            DiscoKeyAdvertisement::parse(&later).is_none(),
            "a later TSMP fragment must not parse"
        );
    }

    /// The body is bounded by the IP header's own length field, not by the buffer: a header that
    /// claims fewer bytes than are present must not have the trailing bytes read as message
    /// content, and one that claims more than are present is a truncated packet.
    #[test]
    fn body_is_bounded_by_the_ip_length_field() {
        let src = [100, 64, 0, 2];
        let dst = [100, 64, 0, 1];

        // Total length says 52 (a 32-byte body) while 53 bytes are present: the last key byte is
        // past the IP length, so this is a 32-byte body and not an advertisement.
        let mut short_len = generate4(IP_PROTO_TSMP, src, dst, &advertisement_body(&KEY));
        let declared = (short_len.len() - 1) as u16;
        short_len[2..4].copy_from_slice(&declared.to_be_bytes());
        assert!(
            DiscoKeyAdvertisement::parse(&short_len).is_none(),
            "bytes past the IP total-length field must not be read as message content"
        );

        // Total length says 54 while only 53 bytes are present: cut off, Go demotes to "unknown".
        let mut long_len = generate4(IP_PROTO_TSMP, src, dst, &advertisement_body(&KEY));
        let declared = (long_len.len() + 1) as u16;
        long_len[2..4].copy_from_slice(&declared.to_be_bytes());
        assert!(
            DiscoKeyAdvertisement::parse(&long_len).is_none(),
            "a packet cut off before its declared IP length must not parse"
        );

        // Trailing bytes *inside* a correctly-declared packet are fine: a longer body that still
        // starts with the type byte and 32 key bytes is a valid advertisement (Go tests `<`, not
        // `==`), so a future upstream field append stays parseable.
        let mut extended = advertisement_body(&KEY);
        extended.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let pkt = generate4(IP_PROTO_TSMP, src, dst, &extended);
        assert_eq!(
            DiscoKeyAdvertisement::parse(&pkt).map(|a| a.key),
            Some(KEY),
            "a longer body that still carries the type byte and key parses"
        );
    }
}
