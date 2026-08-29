//! Byte-for-byte encode/decode vectors for the peer-relay disco messages (`0x04`–`0x09`),
//! taken from upstream Go's own test table.
//!
//! Source: `disco/disco_test.go`, `TestMarshalAndParse` in
//! <https://github.com/tailscale/tailscale> — the `want` hex string of each of the six
//! peer-relay cases, produced by `Message.AppendMarshal` and re-parsed by `disco.Parse`. The
//! Go types under test are `disco.BindUDPRelayEndpoint`, `disco.BindUDPRelayEndpointChallenge`,
//! `disco.BindUDPRelayEndpointAnswer`, `disco.CallMeMaybeVia`,
//! `disco.AllocateUDPRelayEndpointRequest` and `disco.AllocateUDPRelayEndpointResponse`
//! (`disco/disco.go`), whose field documentation lives on
//! `net/udprelay/endpoint.ServerEndpoint`.
//!
//! **One deliberate difference from Go's table.** Go's `call_me_maybe_via` and
//! `allocate_udp_relay_endpoint_response` vectors carry the literal `1.2.3.4:567` as their first
//! relay `addr:port`. This repository may not publish routable IPv4 literals outside the RFC 5737
//! documentation ranges, so those four address bytes — and only those four, at one known offset
//! inside an 18-byte v4-mapped endpoint — are `c0 00 02 04` (`192.0.2.4`) here instead of
//! `01 02 03 04`. The port, the v4-mapped `::ffff:` prefix, every other endpoint and every other
//! field are Go's bytes unaltered. The four bind/allocate-request vectors contain no IP address at
//! all and are byte-for-byte Go.
//!
//! Every case is checked in both directions: this crate's encoder must produce Go's bytes, and
//! this crate's parser must read Go's bytes back into the same field values. A round-trip test
//! alone would only prove the encoder and parser agree with each other.

use core::{
    net::{SocketAddr, SocketAddrV6},
    time::Duration,
};

use ts_disco_protocol::{
    AllocateUdpRelayEndpointsRequest, AllocateUdpRelayEndpointsResponse, BindUdpRelayEndpoint,
    BindUdpRelayEndpointAnswer, BindUdpRelayEndpointChallenge, BindUdpRelayEndpointCommon,
    CallMeMaybeVia, Endpoint, Error, Message, MessageType, Packet, UdpRelayEndpoint,
};
use ts_keys::DiscoPublicKey;
use zerocopy::IntoBytes;

/// Decode a compile-time hex literal. Panics on malformed input — this is test data.
fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}

/// Build a 32-byte key with only the listed `(index, value)` pairs set, matching Go's
/// `key.DiscoPublicFromRaw32(mem.B([]byte{1: 1, 2: 2, ...}))` sparse array literals.
fn disco_key(set: &[(usize, u8)]) -> DiscoPublicKey {
    let mut raw = [0u8; 32];
    for &(i, v) in set {
        raw[i] = v;
    }
    DiscoPublicKey::from(raw)
}

/// Go `relayHandshakeCommon` from `TestMarshalAndParse`.
fn relay_handshake_common() -> BindUdpRelayEndpointCommon {
    let mut challenge = [0u8; 32];
    for (i, b) in challenge.iter_mut().enumerate() {
        *b = i as u8;
    }
    BindUdpRelayEndpointCommon {
        vni: 1.into(),
        generation: 2.into(),
        remote_key: disco_key(&[(1, 1), (2, 2), (30, 30), (31, 31)]),
        challenge,
    }
}

/// Go `udpRelayEndpoint` from `TestMarshalAndParse`, with the IPv4 relay address moved into the
/// RFC 5737 documentation range (see the module docs).
fn udp_relay_endpoint_fields() -> (DiscoPublicKey, [DiscoPublicKey; 2], [SocketAddr; 2]) {
    let server_disco = disco_key(&[(1, 1), (2, 2), (30, 30), (31, 31)]);
    let client_disco = [
        disco_key(&[(1, 1), (2, 2), (3, 3), (30, 30), (31, 31)]),
        disco_key(&[(1, 1), (2, 2), (4, 4), (30, 30), (31, 31)]),
    ];
    let addr_ports = [
        "192.0.2.4:567".parse().unwrap(),
        SocketAddr::V6("[2001::3456]:789".parse::<SocketAddrV6>().unwrap()),
    ];
    (server_disco, client_disco, addr_ports)
}

/// Fill a [`UdpRelayEndpoint`] with Go's `udpRelayEndpoint` values.
fn init_udp_relay_endpoint(ep: &mut UdpRelayEndpoint) {
    let (server_disco, client_disco, addr_ports) = udp_relay_endpoint_fields();
    ep.server_disco = server_disco;
    ep.client_disco = client_disco;
    ep.lamport_id = 123.into();
    ep.vni = 456.into();
    // Go's `time.Duration` marshals as an int64 count of nanoseconds: 1s and 1min.
    ep.bind_lifetime_nanos = 1_000_000_000u64.into();
    ep.steady_state_lifetime_nanos = 60_000_000_000u64.into();
    for (slot, addr) in ep.addr_ports.iter_mut().zip(addr_ports) {
        *slot = Endpoint::from(addr);
    }
}

/// Assert Go's `udpRelayEndpoint` field values came back out of a parsed message.
fn assert_udp_relay_endpoint(ep: &UdpRelayEndpoint) {
    let (server_disco, client_disco, addr_ports) = udp_relay_endpoint_fields();
    assert_eq!(ep.server_disco, server_disco);
    assert_eq!(ep.client_disco, client_disco);
    assert_eq!(ep.lamport_id(), 123);
    assert_eq!(ep.vni(), 456);
    assert_eq!(ep.bind_lifetime(), Duration::from_secs(1));
    assert_eq!(ep.steady_state_lifetime(), Duration::from_secs(60));
    let got: Vec<SocketAddr> = ep.addr_ports.iter().map(|e| e.socket_addr()).collect();
    assert_eq!(got, addr_ports.to_vec());
}

/// Build a plaintext packet holding `Msg` and return just the disco *message* bytes — the type
/// byte, the version byte and the body — which is exactly what Go's `AppendMarshal` produces and
/// what `disco.Parse` consumes.
fn marshal<Msg>(body_len: usize, init: impl FnOnce(&mut Msg)) -> Vec<u8>
where
    Msg: ?Sized
        + Message
        + zerocopy::Immutable
        + zerocopy::TryFromBytes
        + zerocopy::IntoBytes
        + zerocopy::KnownLayout,
{
    let mut buf = vec![0u8; Packet::size_for_message(body_len)];
    let pkt = Packet::init_from_bytes::<Msg>(&mut buf, init).expect("init packet");
    let bytes = pkt.as_bytes();
    // The plaintext (ty + version + body) is the tail of the packet, after the disco header and
    // the AEAD tag; slicing from the end avoids hard-coding either offset.
    bytes[bytes.len() - (2 + body_len)..].to_vec()
}

/// Wrap raw disco *message* bytes (Go's `AppendMarshal` output) in a plaintext packet so the
/// typed parsers can be pointed at them. The header and tag bytes are irrelevant here: nothing on
/// the parse path reads them.
fn packet_for(message: &[u8]) -> Vec<u8> {
    let body_len = message.len().saturating_sub(2);
    let mut buf = vec![0u8; Packet::size_for_message(body_len)];
    let at = buf.len() - message.len();
    buf[at..].copy_from_slice(message);
    buf
}

/// Parse raw disco message bytes and run `$body` with `$pkt` bound to the plaintext packet.
///
/// A macro rather than a function because the plaintext packet borrows the buffer it was parsed
/// out of, and `Packet`'s plaintext state marker is not a nameable public type.
macro_rules! with_parsed {
    ($message:expr, | $pkt:ident | $body:block) => {{
        let buf = packet_for($message);
        let $pkt = Packet::from_bytes_unvalidated(&buf).expect("plaintext packet");
        $body
    }};
}

// ---------------------------------------------------------------------------------------------
// The three bind-handshake messages (0x04 / 0x05 / 0x06).
//
// Go: `parseBindUDPRelayEndpoint*` ignores the version byte entirely and decodes the first 72
// bytes, erroring only when fewer than 72 are present. `Packet::as_msg_lax` is exactly that
// parse: fixed-size prefix, trailing bytes ignored, version not consulted.
// ---------------------------------------------------------------------------------------------

const BIND_VECTOR: &str = concat!(
    "0400000000010000000200010200000000000000000000000000000000000000",
    "00000000000000001e1f000102030405060708090a0b0c0d0e0f101112131415",
    "161718191a1b1c1d1e1f",
);

const CHALLENGE_VECTOR: &str = concat!(
    "0500000000010000000200010200000000000000000000000000000000000000",
    "00000000000000001e1f000102030405060708090a0b0c0d0e0f101112131415",
    "161718191a1b1c1d1e1f",
);

const ANSWER_VECTOR: &str = concat!(
    "0600000000010000000200010200000000000000000000000000000000000000",
    "00000000000000001e1f000102030405060708090a0b0c0d0e0f101112131415",
    "161718191a1b1c1d1e1f",
);

#[test]
fn bind_udp_relay_endpoint_matches_go_bytes() {
    let want = hex(BIND_VECTOR);
    let got = marshal::<BindUdpRelayEndpoint>(BindUdpRelayEndpoint::size(), |m| {
        m.common = relay_handshake_common();
    });
    assert_eq!(got, want);

    with_parsed!(&want, |pkt| {
        assert_eq!(pkt.ty(), Some(MessageType::BindUdpRelayEndpoint));
        let msg = pkt
            .as_msg_lax::<BindUdpRelayEndpoint>()
            .expect("parse bind");
        assert_eq!(msg.common, relay_handshake_common());
    });
}

#[test]
fn bind_udp_relay_endpoint_challenge_matches_go_bytes() {
    let want = hex(CHALLENGE_VECTOR);
    let got =
        marshal::<BindUdpRelayEndpointChallenge>(BindUdpRelayEndpointChallenge::size(), |m| {
            m.common = relay_handshake_common();
        });
    assert_eq!(got, want);

    with_parsed!(&want, |pkt| {
        let msg = pkt
            .as_msg_lax::<BindUdpRelayEndpointChallenge>()
            .expect("parse challenge");
        assert_eq!(msg.common, relay_handshake_common());
    });
}

#[test]
fn bind_udp_relay_endpoint_answer_matches_go_bytes() {
    let want = hex(ANSWER_VECTOR);
    let got = marshal::<BindUdpRelayEndpointAnswer>(BindUdpRelayEndpointAnswer::size(), |m| {
        m.common = relay_handshake_common();
    });
    assert_eq!(got, want);

    with_parsed!(&want, |pkt| {
        let msg = pkt
            .as_msg_lax::<BindUdpRelayEndpointAnswer>()
            .expect("parse answer");
        assert_eq!(msg.common, relay_handshake_common());
    });
}

/// The three handshake messages are the same length on the wire, differing only in their type
/// byte. Go relies on that (the challenge field is pure padding in a `BindUDPRelayEndpoint`), and
/// a handler that keyed on length instead of type would be wrong.
#[test]
fn the_three_handshake_messages_differ_only_in_their_type_byte() {
    let bind = hex(BIND_VECTOR);
    let challenge = hex(CHALLENGE_VECTOR);
    let answer = hex(ANSWER_VECTOR);

    assert_eq!(bind.len(), challenge.len());
    assert_eq!(bind.len(), answer.len());
    assert_eq!(bind[1..], challenge[1..]);
    assert_eq!(bind[1..], answer[1..]);
    assert_eq!(
        (bind[0], challenge[0], answer[0]),
        (0x04, 0x05, 0x06),
        "the peer-relay handshake type bytes are disco 0x04/0x05/0x06"
    );
    assert_eq!(BindUdpRelayEndpointCommon::size(), 72);
}

/// Go's `parseBindUDPRelayEndpoint*` never looks at the version byte, so a future disco version
/// that keeps this layout must still parse rather than being dropped onto DERP.
#[test]
fn bind_handshake_ignores_the_version_byte() {
    let mut wire = hex(BIND_VECTOR);
    wire[1] = 7;
    with_parsed!(&wire, |pkt| {
        let msg = pkt
            .as_msg_lax::<BindUdpRelayEndpoint>()
            .expect("a non-zero version must still parse");
        assert_eq!(msg.common, relay_handshake_common());
    });
}

/// Go is "deliberately lax on longer-than-expected messages": trailing bytes past the 72-byte
/// common block are ignored, not a parse failure.
#[test]
fn bind_handshake_tolerates_trailing_bytes() {
    let mut wire = hex(BIND_VECTOR);
    wire.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    with_parsed!(&wire, |pkt| {
        let msg = pkt
            .as_msg_lax::<BindUdpRelayEndpoint>()
            .expect("trailing bytes must be ignored");
        assert_eq!(msg.common, relay_handshake_common());
    });
}

/// One byte short of the 72-byte common block is Go's `errShort`.
#[test]
fn bind_handshake_rejects_a_short_body() {
    let mut wire = hex(BIND_VECTOR);
    wire.pop();
    with_parsed!(&wire, |pkt| {
        assert!(
            pkt.as_msg_lax::<BindUdpRelayEndpoint>().is_none(),
            "a 71-byte common block must not parse"
        );
    });
}

// ---------------------------------------------------------------------------------------------
// CallMeMaybeVia (0x07).
// ---------------------------------------------------------------------------------------------

const CALL_ME_MAYBE_VIA_VECTOR: &str = concat!(
    "0700000102000000000000000000000000000000000000000000000000000000",
    "1e1f000102030000000000000000000000000000000000000000000000000000",
    "1e1f000102000400000000000000000000000000000000000000000000000000",
    "1e1f000000000000007b000001c8000000003b9aca000000000df84758000000",
    "0000000000000000ffffc0000204023720010000000000000000000000003456",
    "0315",
);

#[test]
fn call_me_maybe_via_matches_go_bytes() {
    let want = hex(CALL_ME_MAYBE_VIA_VECTOR);
    let got = marshal::<CallMeMaybeVia>(CallMeMaybeVia::size_for_addr_port_count(2), |m| {
        init_udp_relay_endpoint(&mut m.endpoint);
    });
    assert_eq!(got, want);

    with_parsed!(&want, |pkt| {
        assert_eq!(pkt.ty(), Some(MessageType::CallMeMaybeVia));
        let msg = pkt
            .call_me_maybe_via()
            .expect("type byte is CallMeMaybeVia")
            .expect("body parses");
        assert_udp_relay_endpoint(&msg.endpoint);
    });
}

/// Go's `parseCallMeMaybeVia` short-circuits on a non-zero version and returns an *empty*
/// message, which carries no relay `addr:port` and so causes no bind attempt. We surface that as
/// a typed error the caller drops — the same "nothing happens" outcome, without ever reading a
/// future version's body with this version's layout.
#[test]
fn call_me_maybe_via_rejects_a_future_version() {
    let mut wire = hex(CALL_ME_MAYBE_VIA_VECTOR);
    wire[1] = 1;
    with_parsed!(&wire, |pkt| {
        assert_eq!(pkt.call_me_maybe_via(), Some(Err(Error::UnknownVersion)));
    });
}

/// Go's `UDPRelayEndpoint.decode` requires the fixed part **plus at least one whole
/// `addr:port`**. A message with none is `errShort`, not an empty candidate list — unlike the
/// plain `CallMeMaybe`, which soft-empties.
#[test]
fn call_me_maybe_via_requires_at_least_one_addr_port() {
    let wire = hex(CALL_ME_MAYBE_VIA_VECTOR);
    let truncated = &wire[..2 + UdpRelayEndpoint::LEN_MINUS_ADDR_PORTS];
    with_parsed!(truncated, |pkt| {
        assert_eq!(pkt.call_me_maybe_via(), Some(Err(Error::TooShort)));
    });
}

/// A ragged `addr:port` tail (not a whole multiple of the 18-byte endpoint size) is also Go's
/// `errShort`.
#[test]
fn call_me_maybe_via_rejects_a_partial_addr_port() {
    let mut wire = hex(CALL_ME_MAYBE_VIA_VECTOR);
    wire.pop();
    with_parsed!(&wire, |pkt| {
        assert_eq!(pkt.call_me_maybe_via(), Some(Err(Error::TooShort)));
    });
}

/// The accessor is type-gated: pointed at some other disco message it reports "not mine" rather
/// than misreading the body.
#[test]
fn call_me_maybe_via_accessor_is_type_gated() {
    let wire = hex(BIND_VECTOR);
    with_parsed!(&wire, |pkt| {
        assert!(pkt.call_me_maybe_via().is_none());
    });
}

// ---------------------------------------------------------------------------------------------
// AllocateUdpRelayEndpointsRequest (0x08) and AllocateUdpRelayEndpointsResponse (0x09).
// ---------------------------------------------------------------------------------------------

const ALLOCATE_REQUEST_VECTOR: &str = concat!(
    "0800000102030000000000000000000000000000000000000000000000000000",
    "1e1f000102000400000000000000000000000000000000000000000000000000",
    "1e1f00000001",
);

const ALLOCATE_RESPONSE_VECTOR: &str = concat!(
    "0900000000010001020000000000000000000000000000000000000000000000",
    "000000001e1f0001020300000000000000000000000000000000000000000000",
    "000000001e1f0001020004000000000000000000000000000000000000000000",
    "000000001e1f000000000000007b000001c8000000003b9aca000000000df847",
    "580000000000000000000000ffffc00002040237200100000000000000000000",
    "000034560315",
);

#[test]
fn allocate_request_matches_go_bytes() {
    let want = hex(ALLOCATE_REQUEST_VECTOR);
    let (_, client_disco, _) = udp_relay_endpoint_fields();
    let got = marshal::<AllocateUdpRelayEndpointsRequest>(
        AllocateUdpRelayEndpointsRequest::size(),
        |m| {
            m.client_disco = client_disco;
            m.generation = 1.into();
        },
    );
    assert_eq!(got, want);

    with_parsed!(&want, |pkt| {
        assert_eq!(
            pkt.ty(),
            Some(MessageType::AllocateUdpRelayEndpointsRequest)
        );
        let msg = pkt
            .allocate_udp_relay_endpoints_request()
            .expect("type byte matches")
            .expect("body parses");
        assert_eq!(msg.client_disco, client_disco);
        assert_eq!(msg.generation.get(), 1);
    });
}

/// Go parses the request from its 68-byte prefix and ignores anything after it.
#[test]
fn allocate_request_tolerates_trailing_bytes() {
    let mut wire = hex(ALLOCATE_REQUEST_VECTOR);
    wire.extend_from_slice(&[0xff; 3]);
    with_parsed!(&wire, |pkt| {
        let msg = pkt
            .allocate_udp_relay_endpoints_request()
            .expect("type byte matches")
            .expect("trailing bytes must be ignored");
        assert_eq!(msg.generation.get(), 1);
    });
}

#[test]
fn allocate_request_rejects_a_short_body() {
    let mut wire = hex(ALLOCATE_REQUEST_VECTOR);
    wire.pop();
    with_parsed!(&wire, |pkt| {
        assert_eq!(
            pkt.allocate_udp_relay_endpoints_request(),
            Some(Err(Error::TooShort))
        );
    });
}

#[test]
fn allocate_response_matches_go_bytes() {
    let want = hex(ALLOCATE_RESPONSE_VECTOR);
    let got = marshal::<AllocateUdpRelayEndpointsResponse>(
        AllocateUdpRelayEndpointsResponse::size_for_addr_port_count(2),
        |m| {
            m.generation = 1.into();
            init_udp_relay_endpoint(&mut m.endpoint);
        },
    );
    assert_eq!(got, want);

    with_parsed!(&want, |pkt| {
        assert_eq!(
            pkt.ty(),
            Some(MessageType::AllocateUdpRelayEndpointsResponse)
        );
        let msg = pkt
            .allocate_udp_relay_endpoints_response()
            .expect("type byte matches")
            .expect("body parses");
        assert_eq!(msg.generation(), 1);
        assert_udp_relay_endpoint(&msg.endpoint);
    });
}

#[test]
fn allocate_response_rejects_a_future_version() {
    let mut wire = hex(ALLOCATE_RESPONSE_VECTOR);
    wire[1] = 9;
    with_parsed!(&wire, |pkt| {
        assert_eq!(
            pkt.allocate_udp_relay_endpoints_response(),
            Some(Err(Error::UnknownVersion))
        );
    });
}

#[test]
fn allocate_response_rejects_a_body_without_the_generation() {
    let wire = hex(ALLOCATE_RESPONSE_VECTOR);
    with_parsed!(&wire[..4], |pkt| {
        assert_eq!(
            pkt.allocate_udp_relay_endpoints_response(),
            Some(Err(Error::TooShort))
        );
    });
}

/// Every peer-relay type byte upstream defines is recognized by [`MessageType`], and each maps to
/// the message this crate can now actually decode. Before this codec existed the type bytes were
/// enumerated but unparseable, so a `CallMeMaybeVia` was dropped and the peer silently stayed on
/// DERP.
#[test]
fn every_peer_relay_type_byte_round_trips() {
    for (byte, want) in [
        (0x04u8, MessageType::BindUdpRelayEndpoint),
        (0x05, MessageType::BindUdpRelayEndpointChallenge),
        (0x06, MessageType::BindUdpRelayEndpointAnswer),
        (0x07, MessageType::CallMeMaybeVia),
        (0x08, MessageType::AllocateUdpRelayEndpointsRequest),
        (0x09, MessageType::AllocateUdpRelayEndpointsResponse),
    ] {
        assert_eq!(MessageType::try_from(byte), Ok(want));
        assert_eq!(want as u8, byte);
    }

    assert_eq!(BindUdpRelayEndpoint::TYPE as u8, 0x04);
    assert_eq!(BindUdpRelayEndpointChallenge::TYPE as u8, 0x05);
    assert_eq!(BindUdpRelayEndpointAnswer::TYPE as u8, 0x06);
    assert_eq!(CallMeMaybeVia::TYPE as u8, 0x07);
    assert_eq!(AllocateUdpRelayEndpointsRequest::TYPE as u8, 0x08);
    assert_eq!(AllocateUdpRelayEndpointsResponse::TYPE as u8, 0x09);
}
