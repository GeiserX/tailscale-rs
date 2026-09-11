//! TSMP — the "Tailscale Message Protocol", Go [`net/packet/tsmp.go`].
//!
//! TSMP is Tailscale's ICMP-like in-band signalling protocol between nodes. It rides IP protocol
//! **99** ("any private encryption scheme") *inside* the WireGuard tunnel, so a TSMP message is
//! only ever seen after decryption and never touches the host network stack.
//!
//! This module carries two of TSMP's messages, both in both directions.
//!
//! The **rejected-connection** message (Go `packet.TailscaleRejectedHeader`, TSMP type `'!'`) is
//! how a node tells a dialer that it dropped the connection and why. A node that drops an inbound
//! IPv4 TCP SYN on its ACL sends one back carrying the four-tuple and a reason; the dialer that
//! receives one learns immediately that the connection is refused, instead of waiting out a TCP
//! timeout with nothing to show for it. See [`TailscaleRejectedHeader::marshal`](crate::tsmp::TailscaleRejectedHeader::marshal) and
//! [`TailscaleRejectedHeader::parse`](crate::tsmp::TailscaleRejectedHeader::parse).
//!
//! The **disco-key advertisement**
//! (Go `packet.TSMPDiscoKeyAdvertisement`, upstream capability version 144) announces this node's
//! current disco public key immediately after an eligible WireGuard session is established, which
//! lets the far side learn (or re-learn) that key without waiting for a netmap update or restarting
//! WireGuard. A real Go peer sends this to us **unprompted**, and from capability version 144 we
//! send our own the same way — see
//! [`DiscoKeyAdvertisement::parse`](crate::tsmp::DiscoKeyAdvertisement::parse) and
//! [`DiscoKeyAdvertisement::marshal`](crate::tsmp::DiscoKeyAdvertisement::marshal).
//!
//! [`net/packet/tsmp.go`]: https://github.com/tailscale/tailscale/blob/main/net/packet/tsmp.go

use alloc::vec::Vec;
use core::{
    fmt,
    net::{IpAddr, SocketAddr},
};

/// The IP protocol number TSMP rides on (Go `ipproto.TSMP`). Not IANA-assigned: 99 is "any private
/// encryption scheme", which Tailscale reuses for inter-node messages.
pub const IP_PROTO_TSMP: u8 = 99;

/// Type byte of a [`TailscaleRejectedHeader`] rejected-connection message
/// (Go `packet.TSMPTypeRejectedConn`).
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

    /// Marshal this advertisement into a complete IP packet, ready to be handed to WireGuard as
    /// the plaintext of a transport-data message.
    ///
    /// Go [`TSMPDiscoKeyAdvertisement.Marshal`]: an IPv4 or IPv6 base header (chosen by the address
    /// family, `packet.Generate` over `IP4Header`/`IP6Header`) carrying IP protocol
    /// [`IP_PROTO_TSMP`], followed by the [`DISCO_ADVERTISEMENT_LEN`]-byte body — the type byte
    /// `'a'` and the raw 32-byte disco key. Field for field this is Go's `IP4Header.Marshal` /
    /// `IP6Header.Marshal`: TTL/hop-limit 64, IP ID 0, no options, no fragmentation, and (v4 only)
    /// an RFC 1071 header checksum.
    ///
    /// # Errors
    ///
    /// [`MarshalError::MixedAddressFamilies`] when `src` and `dst` are not in the same address
    /// family. Go picks the header family from `Src` alone and then *discards* the
    /// `errWrongFamily` its `IP4Header.Marshal` returns for a v6 `Dst` (`packet.Generate` ignores
    /// the error), emitting a packet with an all-zero header. Refusing is the fail-closed reading
    /// of the same check, and the divergence is unobservable: Go's only caller,
    /// `magicsock.Conn.PriorityMessageForPeer`, picks `src` with `selfIPMatchingFamily(self, dst)`,
    /// so the families always match by construction — as they do here.
    ///
    /// [`TSMPDiscoKeyAdvertisement.Marshal`]: https://github.com/tailscale/tailscale/blob/main/net/packet/tsmp.go
    pub fn marshal(&self) -> Result<Vec<u8>, MarshalError> {
        // Go: `payload = append([]byte{byte(TSMPTypeDiscoAdvertisement)}, ka.Key.AppendTo(...)...)`,
        // then a belt-and-braces `len(payload) != 33` check. That check cannot fail here: the body
        // is a type byte plus a fixed-size `[u8; DISCO_KEY_LEN]`, so the length is a compile-time
        // constant.
        let mut body = [0u8; DISCO_ADVERTISEMENT_LEN];
        body[0] = TSMP_TYPE_DISCO_ADVERTISEMENT;
        body[1..].copy_from_slice(&self.key);

        match (self.src, self.dst) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => Ok(generate4(src.octets(), dst.octets(), &body)),
            (IpAddr::V6(src), IpAddr::V6(dst)) => Ok(generate6(src.octets(), dst.octets(), &body)),
            _ => Err(MarshalError::MixedAddressFamilies),
        }
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

/// Why a [`DiscoKeyAdvertisement`] could not be marshalled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarshalError {
    /// `src` and `dst` are in different address families, so neither an IPv4 nor an IPv6 header
    /// can carry both. See [`DiscoKeyAdvertisement::marshal`] and
    /// [`TailscaleRejectedHeader::marshal`].
    MixedAddressFamilies,
    /// A [`TailscaleRejectedHeader`] carries no reason (Go's "TailscaleRejectedHeader has no
    /// reason"). See [`TailscaleRejectedHeader::marshal`].
    MissingRejectReason,
}

impl fmt::Display for MarshalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MixedAddressFamilies => f.write_str("wrong address family for src/dst IP"),
            Self::MissingRejectReason => f.write_str("TailscaleRejectedHeader has no reason"),
        }
    }
}

impl core::error::Error for MarshalError {}

/// Bit the `MaybeBroken` flag occupies in a rejected-connection message's flags byte
/// (Go `packet.rejectFlagBitMaybeBroken`).
const REJECT_FLAG_BIT_MAYBE_BROKEN: u8 = 0x1;

/// Wire length of the rejected-connection body this node marshals: the type byte, the protocol
/// byte, the reason byte, the two ports and the flags byte. Go `TailscaleRejectedHeader.Len` is
/// this plus its IP header.
pub const REJECTED_CONN_LEN: usize = 8;

/// Shortest rejected-connection body Go will parse (`AsTailscaleRejectedHeader`'s `len(p) < 7`).
/// The flags byte was appended to the message after it first shipped, so a sender that predates it
/// emits only seven bytes and its `MaybeBroken` reads as `false` — which is why parsing must accept
/// seven and marshalling must still emit eight.
pub const REJECTED_CONN_MIN_LEN: usize = 7;

/// Why a peer refused a connection, as carried in a [`TailscaleRejectedHeader`]
/// (Go `packet.TailscaleRejectReason`).
///
/// A single opaque byte, not an enum, because that is what it is on the wire: Go's type is
/// `type TailscaleRejectReason byte` and its `String` falls back to `0x%02x` for a value it does
/// not know. Modelling it as a closed set here would silently rewrite a future upstream reason into
/// "unknown" and lose the byte a log line should print.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RejectReason(pub u8);

impl RejectReason {
    /// The zero value: no rejection (Go `TailscaleRejectReasonNone`). A header carrying it cannot
    /// be marshalled — see [`TailscaleRejectedHeader::marshal`].
    pub const NONE: Self = Self(0);
    /// The ACLs refused the connection (Go `RejectedDueToACLs`).
    pub const ACLS: Self = Self(b'A');
    /// The node has shields up (Go `RejectedDueToShieldsUp`).
    pub const SHIELDS_UP: Self = Self(b'S');
    /// A relay node's IP forwarding is disabled (Go `RejectedDueToIPForwarding`).
    pub const IP_FORWARDING: Self = Self(b'F');
    /// The target host's own firewall blocked the traffic (Go `RejectedDueToHostFirewall`).
    pub const HOST_FIREWALL: Self = Self(b'W');
    /// An app connector has no real-IP mapping for the transit IP the client used, so it has no
    /// destination to forward the connection to (Go
    /// `RejectedDueToUnknownAppConnectorTransitIP`).
    ///
    /// Unlike every other reason, this one is **not** terminal and not purely informational: it
    /// asks the client to re-establish the transit-IP ↔ real-IP binding, so upstream's receive
    /// hook deliberately lets the message through to the local stack instead of consuming it. See
    /// `ts_dataplane`'s inbound filter for that rule.
    pub const UNKNOWN_APP_CONNECTOR_TRANSIT_IP: Self = Self(b'T');

    /// Whether this is the zero value (Go `TailscaleRejectReason.IsZero`).
    pub const fn is_zero(self) -> bool {
        self.0 == Self::NONE.0
    }
}

impl fmt::Display for RejectReason {
    /// Go `TailscaleRejectReason.String`, including its `0x%02x` fallback for a reason this client
    /// does not know.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::ACLS => f.write_str("acl"),
            Self::SHIELDS_UP => f.write_str("shields"),
            Self::IP_FORWARDING => f.write_str("host-ip-forwarding-disabled"),
            Self::HOST_FIREWALL => f.write_str("host-firewall"),
            Self::UNKNOWN_APP_CONNECTOR_TRANSIT_IP => {
                f.write_str("app-connector-transit-ip-unknown")
            }
            Self(other) => write!(f, "0x{other:02x}"),
        }
    }
}

/// A peer telling us it refused a connection, or us telling a peer the same (Go
/// [`packet.TailscaleRejectedHeader`], TSMP type `'!'`).
///
/// On the wire, after the IP header, the body is [`REJECTED_CONN_LEN`] (8) bytes:
///
/// ```text
/// '!' | proto | reason | src port (BE) | dst port (BE) | flags
///  0     1        2          3..5             5..7         7
/// ```
///
/// **The four-tuple is written from the *rejecter's* point of view and read back from the
/// *dialer's*, and the two agree.** The rejecter fills `ip_src`/`ip_dst` with the *reversed* IP
/// pair of the packet it dropped (its own address first) while leaving `src`/`dst` as the rejected
/// connection's own direction — the dialer's address and port first. [`Self::parse`] rebuilds
/// `src` from the receiving packet's IP *destination* and `dst` from its IP *source*, which is
/// exactly the same pair again, so a marshalled header parses back field-for-field identical on the
/// far side. That is Go's `AsTailscaleRejectedHeader` and it is what lets a dialer match the
/// message against the flow it opened.
///
/// `proto` is the raw IP protocol number (Go's `ipproto.Proto`, a byte) rather than a typed
/// protocol, so this crate stays dependency-free and `no_std`.
///
/// [`packet.TailscaleRejectedHeader`]: https://github.com/tailscale/tailscale/blob/main/net/packet/tsmp.go
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TailscaleRejectedHeader {
    /// Source address of the enclosing IP header — the node doing the rejecting.
    pub ip_src: IpAddr,
    /// Destination address of the enclosing IP header — the node whose connection was rejected.
    pub ip_dst: IpAddr,
    /// The rejected connection's source (the dialer's address and port).
    pub src: SocketAddr,
    /// The rejected connection's destination (the rejecter's address and port).
    pub dst: SocketAddr,
    /// The rejected connection's IP protocol number (Go `ipproto.Proto`; in practice TCP).
    pub proto: u8,
    /// Why it was rejected.
    pub reason: RejectReason,
    /// Whether the rejection is *non-terminal* (Go `MaybeBroken`): the dialer should treat the flow
    /// as problematic rather than dead, because the reason may be transient or a misconfiguration
    /// on the far side.
    pub maybe_broken: bool,
}

impl TailscaleRejectedHeader {
    /// Marshal this header into a complete IP packet, ready to be handed to WireGuard as the
    /// plaintext of a transport-data message.
    ///
    /// Go `packet.Generate(TailscaleRejectedHeader{…}, nil)`: an IPv4 or IPv6 base header (chosen by
    /// the address family) carrying IP protocol [`IP_PROTO_TSMP`], then the
    /// [`REJECTED_CONN_LEN`]-byte body. The IP header is the same `IP4Header.Marshal` /
    /// `IP6Header.Marshal` a disco-key advertisement uses — TTL/hop-limit 64, IP ID 0, no options,
    /// no fragmentation, and (v4 only) an RFC 1071 header checksum.
    ///
    /// # Errors
    ///
    /// - [`MarshalError::MissingRejectReason`] when `reason` is [`RejectReason::NONE`]. Go's own
    ///   refusal: `if h.Reason == 0 { return errors.New("TailscaleRejectedHeader has no reason") }`.
    ///   A reasonless reject tells the far side nothing it can act on or display.
    /// - [`MarshalError::MixedAddressFamilies`] when `ip_src` and `ip_dst` are in different
    ///   families. Go picks the header family from `IPSrc` alone and then discards the
    ///   `errWrongFamily` its `IP4Header.Marshal` returns for a mismatched `Dst`, emitting a packet
    ///   with an all-zero header; refusing is the fail-closed reading of the same check. Go's
    ///   caller takes both addresses from one dropped packet, as this fork's does, so the families
    ///   match by construction and the divergence is unobservable.
    pub fn marshal(&self) -> Result<Vec<u8>, MarshalError> {
        // Go: `if h.Reason == 0 { return errors.New("TailscaleRejectedHeader has no reason") }`.
        if self.reason.is_zero() {
            return Err(MarshalError::MissingRejectReason);
        }

        let mut body = [0u8; REJECTED_CONN_LEN];
        body[0] = TSMP_TYPE_REJECTED_CONN;
        body[1] = self.proto;
        body[2] = self.reason.0;
        body[3..5].copy_from_slice(&self.src.port().to_be_bytes());
        body[5..7].copy_from_slice(&self.dst.port().to_be_bytes());
        // Go builds the flags byte one bit at a time; `MaybeBroken` is the only bit defined.
        body[7] = if self.maybe_broken {
            REJECT_FLAG_BIT_MAYBE_BROKEN
        } else {
            0
        };

        match (self.ip_src, self.ip_dst) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => Ok(generate4(src.octets(), dst.octets(), &body)),
            (IpAddr::V6(src), IpAddr::V6(dst)) => Ok(generate6(src.octets(), dst.octets(), &body)),
            _ => Err(MarshalError::MixedAddressFamilies),
        }
    }

    /// Parse a complete IP packet (IPv4 or IPv6, as handed up by WireGuard decryption) as a TSMP
    /// rejected-connection message, or `None` if it is not one.
    ///
    /// Go `Parsed.AsTailscaleRejectedHeader` applied to a `Parsed` that `Parsed.Decode` filled in —
    /// i.e. this folds Go's decode step (which is what rejects a truncated, fragmented or non-TSMP
    /// packet before the type byte is ever looked at) into the same call, exactly as
    /// [`DiscoKeyAdvertisement::parse`] does.
    ///
    /// Returns `None` — never a partially-filled value — for anything that is not a
    /// rejected-connection message: a non-TSMP protocol, a truncated packet, a fragment, a body
    /// shorter than [`REJECTED_CONN_MIN_LEN`], or a TSMP body carrying some other type byte.
    ///
    /// A [`RejectReason::NONE`] on the wire still parses: Go does not screen the reason here, and a
    /// reason byte this client does not know is deliberately preserved rather than flattened, so a
    /// log line can print it.
    pub fn parse(ip_packet: &[u8]) -> Option<Self> {
        let (ip_src, ip_dst, body) = tsmp_body(ip_packet)?;

        // Go: `if len(p) < 7 || p[0] != byte(TSMPTypeRejectedConn) { return }`.
        if body.len() < REJECTED_CONN_MIN_LEN || body[0] != TSMP_TYPE_REJECTED_CONN {
            return None;
        }

        // Go reads the flags byte only `if len(p) > 7`, so a seven-byte body from a sender that
        // predates the flags byte parses with `MaybeBroken` false rather than failing.
        let maybe_broken = body
            .get(7)
            .is_some_and(|flags| flags & REJECT_FLAG_BIT_MAYBE_BROKEN != 0);

        Some(Self {
            ip_src,
            ip_dst,
            // Go: `Src: netip.AddrPortFrom(pp.Dst.Addr(), …)` / `Dst: …(pp.Src.Addr(), …)`. The IPs
            // are swapped relative to the packet carrying them because the *connection* ran the
            // other way round; see the type's own doc.
            src: SocketAddr::new(ip_dst, u16::from_be_bytes([body[3], body[4]])),
            dst: SocketAddr::new(ip_src, u16::from_be_bytes([body[5], body[6]])),
            proto: body[1],
            reason: RejectReason(body[2]),
            maybe_broken,
        })
    }
}

/// Build a complete IPv4 packet carrying `payload` as IP protocol [`IP_PROTO_TSMP`]
/// (Go `packet.Generate(IP4Header{IPProto: ipproto.TSMP, Src, Dst}, payload)`).
///
/// Byte for byte Go's `IP4Header.Marshal`: version 4 with IHL 5 (no options), DSCP/ECN 0, the Total
/// Length field, IP ID 0, no flags and no fragment offset, TTL 64, the protocol byte, an RFC 1071
/// header checksum, then the addresses.
fn generate4(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut buf = alloc::vec![0u8; IP4_HEADER_LEN + payload.len()];
    buf[IP4_HEADER_LEN..].copy_from_slice(payload);

    buf[0] = 0x40 | (IP4_HEADER_LEN >> 2) as u8;
    buf[1] = 0x00;
    // `as u16` cannot truncate in practice: the only caller marshals a 53-byte advertisement, and
    // the IP total-length field is a u16 by definition.
    let total_len = buf.len() as u16;
    buf[2..4].copy_from_slice(&total_len.to_be_bytes());
    // IP ID 0, then flags + fragment offset 0: Go's `IP4Header` for an advertisement carries no
    // `IPID`, and TSMP is never fragmented.
    buf[4..6].copy_from_slice(&0u16.to_be_bytes());
    buf[6..8].copy_from_slice(&0u16.to_be_bytes());
    buf[8] = 64;
    buf[9] = IP_PROTO_TSMP;
    // The checksum field must be zero while the checksum is computed over these same bytes.
    buf[10..12].copy_from_slice(&0u16.to_be_bytes());
    buf[12..16].copy_from_slice(&src);
    buf[16..20].copy_from_slice(&dst);

    let checksum = ip4_checksum(&buf[..IP4_HEADER_LEN]);
    buf[10..12].copy_from_slice(&checksum.to_be_bytes());

    buf
}

/// Build a complete IPv6 packet carrying `payload` as next header [`IP_PROTO_TSMP`]
/// (Go `packet.Generate(IP6Header{IPProto: ipproto.TSMP, Src, Dst}, payload)`).
///
/// Byte for byte Go's `IP6Header.Marshal`: version 6 with traffic class and flow label 0 (Go writes
/// `IPID & 0x000FFFFF`, which is 0 for an advertisement, then stamps `0x60` over the top nibble),
/// the Payload Length field, the next-header byte, hop limit 64, then the addresses. IPv6 headers
/// carry no checksum.
fn generate6(src: [u8; 16], dst: [u8; 16], payload: &[u8]) -> Vec<u8> {
    let mut buf = alloc::vec![0u8; IP6_HEADER_LEN + payload.len()];
    buf[IP6_HEADER_LEN..].copy_from_slice(payload);

    buf[0] = 0x60;
    buf[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    buf[6] = IP_PROTO_TSMP;
    buf[7] = 64;
    buf[8..24].copy_from_slice(&src);
    buf[24..40].copy_from_slice(&dst);

    buf
}

/// The IPv4 header checksum (RFC 1071), Go `packet.ip4Checksum`: the one's-complement of the
/// one's-complement sum of the header's 16-bit big-endian words, with a trailing odd byte taken as
/// the high half of a final word. The caller must zero the checksum field first.
fn ip4_checksum(b: &[u8]) -> u16 {
    let mut ac: u32 = 0;
    let mut chunks = b.chunks_exact(2);
    for pair in &mut chunks {
        ac += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    if let [last] = chunks.remainder() {
        ac += u32::from(*last) << 8;
    }
    while (ac >> 16) > 0 {
        ac = (ac >> 16) + (ac & 0xffff);
    }
    !(ac as u16)
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
    ///
    /// Deliberately a second, independent implementation of the production [`ip4_checksum`]: the
    /// parse tests below build their inputs with it, so a bug in the marshal path cannot make both
    /// sides of a parse test agree with each other.
    fn ref_ip4_checksum(b: &[u8]) -> u16 {
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
    /// correct header checksum, and `payload` appended. Independent of the production
    /// [`generate4`], and takes the protocol byte so the negative cases can build a non-TSMP packet.
    fn ref_generate4(proto: u8, src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
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

        let sum = ref_ip4_checksum(&buf[0..IP4_HEADER_LEN]);
        buf[10..12].copy_from_slice(&sum.to_be_bytes());

        buf
    }

    /// Go `packet.Generate(IP6Header{...}, payload)`. Independent of the production [`generate6`].
    fn ref_generate6(next_header: u8, src: [u8; 16], dst: [u8; 16], payload: &[u8]) -> Vec<u8> {
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

    /// Decode a hex string into bytes, so the pinned Go vectors below can be written the way Go's
    /// own test writes them.
    fn unhex(s: &str) -> Vec<u8> {
        assert!(
            s.len().is_multiple_of(2),
            "hex string must have even length"
        );
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    /// The **send** side, against pinned bytes: [`DiscoKeyAdvertisement::marshal`] must emit exactly
    /// what Go's `TSMPDiscoKeyAdvertisement.Marshal` emits.
    ///
    /// The expected packets are pinned as literal bytes, not rebuilt by the test, and the header
    /// prefixes are the ones Go's own `TestTSMPDiscoKeyAdvertisementMarshal`
    /// (`net/packet/tsmp_test.go`) pins:
    ///
    /// - IPv4 `45 00 0035 0000 0000 40 63 <cksum>` — version 4 / IHL 5, DSCP+ECN 0, total length
    ///   53, IP ID 0, no flags or fragment offset, TTL 64, proto 99, RFC 1071 checksum. Go's own
    ///   vector uses different addresses (and so a different checksum); the header is otherwise
    ///   byte-identical, and `ref_ip4_checksum` — the independent RFC 1071 implementation this test
    ///   module carries — reproduces Go's published checksum for Go's own addresses.
    /// - IPv6 `6000000000216340` — Go's vector verbatim: version 6, traffic class and flow label 0,
    ///   payload length 33, next header 99, hop limit 64.
    #[test]
    fn marshals_the_bytes_go_marshals() {
        // Go's test key is 32 repeats of `'a'`; keep that so the on-wire body is 33 bytes of `'a'`
        // and a transposed type byte would be invisible — hence the separate `KEY` case below.
        let go_test_key = [b'a'; DISCO_KEY_LEN];

        let src4 = [100u8, 64, 0, 2];
        let dst4 = [100u8, 64, 0, 1];
        let mut want4 = unhex("45000035000000004063b1e3");
        want4.extend_from_slice(&src4);
        want4.extend_from_slice(&dst4);
        want4.push(b'a');
        want4.extend_from_slice(&go_test_key);

        let advert = DiscoKeyAdvertisement {
            src: IpAddr::from(src4),
            dst: IpAddr::from(dst4),
            key: go_test_key,
        };
        let got = advert
            .marshal()
            .expect("a same-family advertisement marshals");
        assert_eq!(
            got, want4,
            "IPv4 advertisement must be byte-identical to Go's"
        );
        assert_eq!(
            got.len(),
            IP4_HEADER_LEN + DISCO_ADVERTISEMENT_LEN,
            "53 bytes"
        );
        assert_eq!(
            ref_ip4_checksum(&got[..IP4_HEADER_LEN]),
            0,
            "a correct IPv4 header checksums to zero over the whole header"
        );

        // `2001:db8::1`/`::2`, the documentation prefix Go's own vector uses.
        let src6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let mut want6 = unhex("6000000000216340");
        want6.extend_from_slice(&src6);
        want6.extend_from_slice(&dst6);
        want6.push(b'a');
        want6.extend_from_slice(&go_test_key);

        let advert = DiscoKeyAdvertisement {
            src: IpAddr::from(src6),
            dst: IpAddr::from(dst6),
            key: go_test_key,
        };
        let got = advert
            .marshal()
            .expect("a same-family advertisement marshals");
        assert_eq!(
            got, want6,
            "IPv6 advertisement must be byte-identical to Go's"
        );
        assert_eq!(
            got.len(),
            IP6_HEADER_LEN + DISCO_ADVERTISEMENT_LEN,
            "73 bytes"
        );
    }

    /// What we marshal is what we parse: a marshalled advertisement decodes back to the same
    /// addresses and key, over both families. This is the round trip Go's `Parsed.Decode` +
    /// `AsTSMPDiscoAdvertisement` does to a `Marshal`ed packet, and it is what makes the send side
    /// interop-checkable against our own receive side.
    #[test]
    fn marshal_round_trips_through_parse() {
        for (src, dst) in [
            (IpAddr::from([100, 64, 0, 2]), IpAddr::from([100, 64, 0, 1])),
            (
                IpAddr::from([
                    0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
                ]),
                IpAddr::from([
                    0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                ]),
            ),
        ] {
            let advert = DiscoKeyAdvertisement { src, dst, key: KEY };
            let bytes = advert
                .marshal()
                .expect("same-family advertisement marshals");

            assert_eq!(
                DiscoKeyAdvertisement::parse(&bytes),
                Some(advert),
                "a marshalled advertisement must parse back identically ({src} -> {dst})"
            );
        }
    }

    /// The marshal refusal: `src` and `dst` in different address families have no header that can
    /// carry both. Go reaches for `Src`'s family and then throws away the `errWrongFamily` its
    /// `IP4Header.Marshal` returns, emitting an all-zero header; we refuse instead. Nothing on the
    /// wire diverges — Go's only caller picks `src` to match `dst`'s family — but a garbage packet
    /// is never handed to WireGuard.
    #[test]
    fn mixed_address_families_do_not_marshal() {
        let v4 = IpAddr::from([100, 64, 0, 1]);
        let v6 = IpAddr::from([
            0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]);

        for (src, dst) in [(v4, v6), (v6, v4)] {
            assert_eq!(
                DiscoKeyAdvertisement { src, dst, key: KEY }.marshal(),
                Err(MarshalError::MixedAddressFamilies),
                "a mixed-family advertisement must not marshal ({src} -> {dst})"
            );
        }
    }

    /// The happy path: a real advertisement, marshalled exactly as Go's
    /// `TSMPDiscoKeyAdvertisement.Marshal` would emit it, decodes to the advertised key.
    #[test]
    fn decodes_a_real_ipv4_advertisement() {
        let pkt = ref_generate4(
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
        let pkt = ref_generate6(IP_PROTO_TSMP, src, dst, &advertisement_body(&KEY));

        let advert = DiscoKeyAdvertisement::parse(&pkt).expect("advertisement must decode");
        assert_eq!(advert.key, KEY);
        assert_eq!(advert.src, IpAddr::from(src));
        assert_eq!(advert.dst, IpAddr::from(dst));
    }

    /// A zero key is a well-formed advertisement on the wire, but it must never be learned: Go
    /// publishes only `if !discoKeyAdvert.Key.IsZero()`.
    #[test]
    fn zero_key_parses_but_is_flagged() {
        let pkt = ref_generate4(
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
        let tsmp = |body: &[u8]| ref_generate4(IP_PROTO_TSMP, src, dst, body);

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
            DiscoKeyAdvertisement::parse(&ref_generate4(6, src, dst, &advertisement_body(&KEY)))
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
        let base = ref_generate4(
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
        let mut short_len = ref_generate4(IP_PROTO_TSMP, src, dst, &advertisement_body(&KEY));
        let declared = (short_len.len() - 1) as u16;
        short_len[2..4].copy_from_slice(&declared.to_be_bytes());
        assert!(
            DiscoKeyAdvertisement::parse(&short_len).is_none(),
            "bytes past the IP total-length field must not be read as message content"
        );

        // Total length says 54 while only 53 bytes are present: cut off, Go demotes to "unknown".
        let mut long_len = ref_generate4(IP_PROTO_TSMP, src, dst, &advertisement_body(&KEY));
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
        let pkt = ref_generate4(IP_PROTO_TSMP, src, dst, &extended);
        assert_eq!(
            DiscoKeyAdvertisement::parse(&pkt).map(|a| a.key),
            Some(KEY),
            "a longer body that still carries the type byte and key parses"
        );
    }

    /// Go `TailscaleRejectedHeader.Marshal`'s body: the type byte, proto, reason, both ports and
    /// the flags byte. Independent of the production `marshal`, so the parse tests below cannot
    /// agree with a bug in it.
    fn rejected_body(proto: u8, reason: u8, src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
        let mut body = alloc::vec![TSMP_TYPE_REJECTED_CONN, proto, reason];
        body.extend_from_slice(&src_port.to_be_bytes());
        body.extend_from_slice(&dst_port.to_be_bytes());
        body.push(flags);
        assert_eq!(
            body.len(),
            REJECTED_CONN_LEN,
            "Go's TailscaleRejectedHeader.Len minus the IP header"
        );
        body
    }

    /// The reject a node sends when its ACL refuses an inbound SYN from `100.64.0.9:41234` to its
    /// own `100.64.0.1:22` — the shape `ts_dataplane` builds.
    fn acl_reject() -> TailscaleRejectedHeader {
        TailscaleRejectedHeader {
            ip_src: "100.64.0.1".parse().unwrap(),
            ip_dst: "100.64.0.9".parse().unwrap(),
            src: "100.64.0.9:41234".parse().unwrap(),
            dst: "100.64.0.1:22".parse().unwrap(),
            proto: 6,
            reason: RejectReason::ACLS,
            maybe_broken: false,
        }
    }

    /// The **send** side, against pinned bytes: [`TailscaleRejectedHeader::marshal`] must emit
    /// exactly what Go's `packet.Generate(TailscaleRejectedHeader{…}, nil)` emits.
    ///
    /// The IPv4 prefix `45 00 001c 0000 0000 40 63 <cksum>` is version 4 / IHL 5, DSCP+ECN 0, total
    /// length 28 (20-byte header + 8-byte body), IP ID 0, no flags or fragment offset, TTL 64,
    /// proto 99 and the RFC 1071 checksum. The body that follows is Go's `Marshal` field for
    /// field: `'!'`, the proto byte, the reason byte, both ports big-endian, then the flags byte.
    #[test]
    fn marshals_the_reject_bytes_go_marshals() {
        let packet = acl_reject()
            .marshal()
            .expect("a v4 reject with a reason marshals");

        let mut want = unhex("4500001c000000004063");
        // Checksum from the independent RFC 1071 implementation this module carries, taken over
        // the same header with a zeroed checksum field.
        let sum = ref_ip4_checksum(&unhex("4500001c00000000406300006440000164400009"));
        want.extend_from_slice(&sum.to_be_bytes());
        want.extend_from_slice(&[100, 64, 0, 1]);
        want.extend_from_slice(&[100, 64, 0, 9]);
        want.extend_from_slice(&rejected_body(6, b'A', 41234, 22, 0x00));

        assert_eq!(packet, want, "marshalled reject must be Go's bytes");
        assert_eq!(packet.len(), IP4_HEADER_LEN + REJECTED_CONN_LEN);
        assert_eq!(packet[9], IP_PROTO_TSMP, "rides IP protocol 99");
    }

    /// The `MaybeBroken` bit is the flags byte's low bit, and it is the only bit set.
    #[test]
    fn marshals_the_maybe_broken_flag_bit() {
        let packet = TailscaleRejectedHeader {
            reason: RejectReason::IP_FORWARDING,
            maybe_broken: true,
            ..acl_reject()
        }
        .marshal()
        .expect("marshals");

        assert_eq!(
            packet[IP4_HEADER_LEN + 7],
            0x01,
            "flags byte carries MaybeBroken"
        );
        assert_eq!(packet[IP4_HEADER_LEN + 2], b'F', "reason byte");
    }

    /// IPv6 marshals against Go's `IP6Header`: version 6, zero traffic class and flow label,
    /// payload length 8, next header 99, hop limit 64 — `600000000008 63 40`.
    #[test]
    fn marshals_an_ipv6_reject() {
        let packet = TailscaleRejectedHeader {
            ip_src: "fd7a:115c:a1e0::1".parse().unwrap(),
            ip_dst: "fd7a:115c:a1e0::9".parse().unwrap(),
            src: "[fd7a:115c:a1e0::9]:41234".parse().unwrap(),
            dst: "[fd7a:115c:a1e0::1]:22".parse().unwrap(),
            ..acl_reject()
        }
        .marshal()
        .expect("marshals");

        assert_eq!(&packet[..8], &unhex("6000000000086340")[..]);
        assert_eq!(packet.len(), IP6_HEADER_LEN + REJECTED_CONN_LEN);
    }

    /// Go's own usage refusals, both of them. A header with no reason is refused
    /// (`"TailscaleRejectedHeader has no reason"`), and so is one whose IP addresses are in
    /// different families — neither header can carry both.
    #[test]
    fn refuses_to_marshal_a_reasonless_or_mixed_family_reject() {
        assert_eq!(
            TailscaleRejectedHeader {
                reason: RejectReason::NONE,
                ..acl_reject()
            }
            .marshal(),
            Err(MarshalError::MissingRejectReason),
        );

        assert_eq!(
            TailscaleRejectedHeader {
                ip_dst: "fd7a:115c:a1e0::9".parse().unwrap(),
                ..acl_reject()
            }
            .marshal(),
            Err(MarshalError::MixedAddressFamilies),
        );
    }

    /// The **receive** side against the **send** side, both production functions: what the rejecter
    /// marshals is what the dialer parses, field for field. This is the property the whole message
    /// rests on — the rejecter writes the tuple from its own side of the wire and the dialer must
    /// read back the flow *it* opened.
    #[test]
    fn a_marshalled_reject_parses_back_identically() {
        let sent = acl_reject();
        let wire = sent.marshal().expect("marshals");

        let got = TailscaleRejectedHeader::parse(&wire).expect("parses");

        assert_eq!(got, sent);
        // Spelled out, because this is the part a reader has to trust: the dialer's own address
        // and ephemeral port come back as `src`, and the peer it dialled as `dst`.
        assert_eq!(got.src, "100.64.0.9:41234".parse().unwrap());
        assert_eq!(got.dst, "100.64.0.1:22".parse().unwrap());
        assert_eq!(got.reason, RejectReason::ACLS);
        assert!(!got.maybe_broken);
    }

    /// The app-connector reason is `'T'` on the wire, and reaches the caller as the named constant
    /// rather than as an unrecognised byte.
    ///
    /// It is the one reason whose *identity* changes what a receiver does with the packet — see
    /// `ts_dataplane`'s inbound filter, which lets this one through to the local stack and consumes
    /// every other — so a reader that flattened it into "unknown" would silently restore the drop.
    #[test]
    fn the_app_connector_transit_ip_reason_is_the_wire_byte_t() {
        assert_eq!(
            RejectReason::UNKNOWN_APP_CONNECTOR_TRANSIT_IP,
            RejectReason(b'T')
        );

        let body = rejected_body(6, b'T', 41234, 22, 0x00);
        let pkt = ref_generate4(IP_PROTO_TSMP, [100, 64, 0, 1], [100, 64, 0, 9], &body);

        assert_eq!(
            TailscaleRejectedHeader::parse(&pkt).expect("parses").reason,
            RejectReason::UNKNOWN_APP_CONNECTOR_TRANSIT_IP,
        );

        // And back out again: a node relaying or re-emitting one must not rewrite the byte.
        let sent = TailscaleRejectedHeader {
            reason: RejectReason::UNKNOWN_APP_CONNECTOR_TRANSIT_IP,
            ..acl_reject()
        };
        assert_eq!(
            sent.marshal().expect("marshals")[IP4_HEADER_LEN + 2],
            b'T',
            "reason byte"
        );
    }

    /// A seven-byte body — a sender that predates the flags byte — parses, with `MaybeBroken`
    /// false. Go reads the flags byte only `if len(p) > 7`.
    #[test]
    fn parses_a_seven_byte_reject_without_a_flags_byte() {
        let mut body = rejected_body(6, b'S', 41234, 22, 0x00);
        body.truncate(REJECTED_CONN_MIN_LEN);

        let pkt = ref_generate4(IP_PROTO_TSMP, [100, 64, 0, 1], [100, 64, 0, 9], &body);
        let got = TailscaleRejectedHeader::parse(&pkt).expect("a 7-byte reject parses");

        assert_eq!(got.reason, RejectReason::SHIELDS_UP);
        assert!(!got.maybe_broken, "no flags byte means not maybe-broken");

        // Six bytes is below Go's `len(p) < 7` floor.
        body.truncate(REJECTED_CONN_MIN_LEN - 1);
        let short = ref_generate4(IP_PROTO_TSMP, [100, 64, 0, 1], [100, 64, 0, 9], &body);
        assert!(
            TailscaleRejectedHeader::parse(&short).is_none(),
            "a body shorter than 7 bytes is not a reject"
        );
    }

    /// The flags byte's other seven bits are reserved: an unknown bit must not be read as
    /// `MaybeBroken`, and must not stop the message parsing.
    #[test]
    fn parses_reserved_flag_bits_without_setting_maybe_broken() {
        let pkt = ref_generate4(
            IP_PROTO_TSMP,
            [100, 64, 0, 1],
            [100, 64, 0, 9],
            &rejected_body(6, b'A', 41234, 22, 0xfe),
        );
        let got = TailscaleRejectedHeader::parse(&pkt).expect("parses");
        assert!(!got.maybe_broken);

        let pkt = ref_generate4(
            IP_PROTO_TSMP,
            [100, 64, 0, 1],
            [100, 64, 0, 9],
            &rejected_body(6, b'A', 41234, 22, 0xff),
        );
        assert!(
            TailscaleRejectedHeader::parse(&pkt)
                .expect("parses")
                .maybe_broken,
            "bit 0 set alongside the reserved bits is still MaybeBroken"
        );
    }

    /// The two message types must not be confused for one another, in either direction: a
    /// disco-key advertisement is not a reject and a reject is not an advertisement, even though
    /// both are TSMP on the same protocol number.
    #[test]
    fn the_two_tsmp_message_types_do_not_parse_as_each_other() {
        let reject = acl_reject().marshal().expect("marshals");
        assert!(
            DiscoKeyAdvertisement::parse(&reject).is_none(),
            "a reject is not a disco-key advertisement"
        );

        let advert = DiscoKeyAdvertisement {
            src: "100.64.0.1".parse().unwrap(),
            dst: "100.64.0.9".parse().unwrap(),
            key: KEY,
        }
        .marshal()
        .expect("marshals");
        assert!(
            TailscaleRejectedHeader::parse(&advert).is_none(),
            "a disco-key advertisement is not a reject"
        );
    }

    /// Everything `tsmp_body` refuses before a type byte is looked at refuses a reject too: a
    /// non-TSMP protocol, a truncated packet and a fragment. Same decode gate as the
    /// advertisement, asserted on this message so a future decode change cannot loosen one half
    /// without the other going red.
    #[test]
    fn a_non_tsmp_truncated_or_fragmented_packet_is_not_a_reject() {
        let body = rejected_body(6, b'A', 41234, 22, 0x00);
        let src = [100, 64, 0, 1];
        let dst = [100, 64, 0, 9];

        let base = ref_generate4(IP_PROTO_TSMP, src, dst, &body);
        assert!(
            TailscaleRejectedHeader::parse(&base).is_some(),
            "control: the unfragmented TSMP packet parses"
        );

        // Protocol 6 (TCP), not 99.
        let tcp = ref_generate4(6, src, dst, &body);
        assert!(
            TailscaleRejectedHeader::parse(&tcp).is_none(),
            "a non-TSMP protocol is not a reject"
        );

        // Cut off before the declared IP total length.
        let mut truncated = base.clone();
        truncated.pop();
        assert!(
            TailscaleRejectedHeader::parse(&truncated).is_none(),
            "a packet cut off before its declared IP length is not a reject"
        );

        // A first fragment with More-Fragments set, and a later fragment.
        let mut more_frags = base.clone();
        more_frags[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        assert!(
            TailscaleRejectedHeader::parse(&more_frags).is_none(),
            "a fragmented reject must not parse"
        );

        let mut later = base.clone();
        later[6..8].copy_from_slice(&0x000au16.to_be_bytes());
        assert!(
            TailscaleRejectedHeader::parse(&later).is_none(),
            "a later TSMP fragment must not parse"
        );
    }

    /// Go `TailscaleRejectReason.String`, including the `0x%02x` fallback that keeps an unknown
    /// reason byte printable rather than flattening it.
    #[test]
    fn reject_reasons_render_as_go_renders_them() {
        use alloc::string::ToString;

        assert_eq!(RejectReason::ACLS.to_string(), "acl");
        assert_eq!(RejectReason::SHIELDS_UP.to_string(), "shields");
        assert_eq!(
            RejectReason::IP_FORWARDING.to_string(),
            "host-ip-forwarding-disabled"
        );
        assert_eq!(RejectReason::HOST_FIREWALL.to_string(), "host-firewall");
        assert_eq!(
            RejectReason::UNKNOWN_APP_CONNECTOR_TRANSIT_IP.to_string(),
            "app-connector-transit-ip-unknown"
        );
        assert_eq!(RejectReason(0x7a).to_string(), "0x7a");
        assert_eq!(RejectReason::NONE.to_string(), "0x00");
        assert!(RejectReason::NONE.is_zero());
        assert!(!RejectReason::ACLS.is_zero());
    }

    /// An unknown reason byte survives the round trip rather than being rewritten, which is what
    /// lets a log line print a reason this client's build does not know about yet.
    #[test]
    fn an_unknown_reason_byte_round_trips() {
        let sent = TailscaleRejectedHeader {
            reason: RejectReason(b'Z'),
            ..acl_reject()
        };
        let wire = sent.marshal().expect("marshals");
        assert_eq!(wire[IP4_HEADER_LEN + 2], b'Z');
        assert_eq!(
            TailscaleRejectedHeader::parse(&wire)
                .expect("parses")
                .reason,
            RejectReason(b'Z'),
        );
    }
}
