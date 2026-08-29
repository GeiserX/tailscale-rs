//! Building and parsing disco messages on the wire.
//!
//! This layer sits directly on top of the [`ts_disco_protocol`] codec (which already
//! implements the [`crypto_box`][crypto_box]/SalsaBox sealing and the zerocopy message
//! framing). It adds the small amount of glue needed to drive disco over a UDP socket:
//! constructing sealed [`Ping`]/[`Pong`] datagrams and demultiplexing inbound datagrams
//! into typed messages plus the sender's disco key.
//!
//! [crypto_box]: https://docs.rs/crypto_box

use core::{net::SocketAddr, time::Duration};

use rand::Rng;
use ts_disco_protocol::{
    BIND_UDP_RELAY_CHALLENGE_LEN, BindUdpRelayEndpoint, BindUdpRelayEndpointAnswer,
    BindUdpRelayEndpointChallenge, BindUdpRelayEndpointCommon, CallMeMaybe, CallMeMaybeVia,
    Endpoint, Header, Message, MessageType, Packet, Ping, Pong, is_disco_message,
};
use ts_keys::{DiscoPrivateKey, DiscoPublicKey, NodePublicKey};
use ts_packet::geneve::{
    GENEVE_FIXED_HEADER_LEN, GENEVE_PROTOCOL_DISCO, GENEVE_PROTOCOL_WIREGUARD, GeneveHeader,
};
// `IntoBytes` is only needed by the test-only `magic_prefix` wire-format guard.
#[cfg(test)]
use zerocopy::IntoBytes;

use crate::{error::DiscoError, relay::RelayServerEndpoint};

/// Maximum number of endpoints accepted from a single inbound `CallMeMaybe`.
///
/// Anti-amplification cap. A `CallMeMaybe` carries a peer's candidate endpoints, each of which we
/// disco-ping from the real host socket to try to open a direct path. The wire message is only
/// bounded by the transport frame size (~64 KiB over DERP ≈ 3,600 endpoints at 18 bytes each), so
/// without a cap an authenticated-but-malicious tailnet peer could make this node emit thousands of
/// host-sourced UDP probes per ping interval at attacker-chosen public IPs — an SSRF-style scanner /
/// amplifier sourced from this node's real IP. We keep only the first N (the order the peer
/// serialized them, freshest-first by convention) and drop the rest.
///
/// Upstream Go v1.100.0 has **no** per-message cap here (its `handleCallMeMaybe` ingests and pings
/// every endpoint, and its soft >100 candidate prune explicitly exempts CallMeMaybe-sourced entries),
/// so this is deliberately *stricter* than Go. Kept separate from `MAX_REFLEXIVE_ADDRS` (the
/// send-side self-endpoint cap) so the receive and send limits can diverge.
pub const MAX_INBOUND_CALLMEMAYBE_ENDPOINTS: usize = 16;

/// A per-ping transaction id (12 bytes, matching the wire format).
pub type TxId = [u8; 12];

/// Generate a fresh random transaction id for a ping.
pub fn random_tx_id() -> TxId {
    let mut id = [0u8; 12];
    rand::rng().fill_bytes(&mut id);
    id
}

/// Report whether `buf` is a disco datagram (as opposed to a WireGuard one).
///
/// This is the demux predicate shared by every reader of the underlay socket: the disco
/// magic prefix never collides with a WireGuard message type byte, so an exact prefix
/// match cleanly separates control-of-path traffic from data-plane traffic.
pub fn looks_like_disco(buf: &[u8]) -> bool {
    is_disco_message(buf)
}

/// Serialize and seal a disco [`Ping`] addressed to `receiver`.
///
/// The returned bytes are ready to be written to the socket. `our_node_key` is embedded so
/// the receiver can bind our disco key to our node key 1:1 (see [`Ping::node_key`]).
pub fn seal_ping(
    our_disco: &DiscoPrivateKey,
    our_node_key: NodePublicKey,
    receiver: &DiscoPublicKey,
    tx_id: TxId,
) -> Result<Vec<u8>, DiscoError> {
    let mut buf = vec![0u8; Packet::size_for_message(Ping::size_with_padding(0))];

    let pkt = Packet::init_from_bytes::<Ping>(&mut buf, |ping| {
        ping.tx_id = tx_id;
        ping.node_key = our_node_key;
    })?;

    pkt.encrypt_in_place(our_disco, receiver, random_nonce())?;

    Ok(buf)
}

/// Serialize and seal a disco [`Pong`] addressed to `receiver`.
///
/// `src` is the address we observed the corresponding ping arriving from; echoing it back
/// is how the pinger learns its own reflexive (STUN-equivalent) address on this path.
pub fn seal_pong(
    our_disco: &DiscoPrivateKey,
    receiver: &DiscoPublicKey,
    tx_id: TxId,
    src: SocketAddr,
) -> Result<Vec<u8>, DiscoError> {
    let mut buf = vec![0u8; Packet::size_for_message(Pong::size())];

    let pkt = Packet::init_from_bytes::<Pong>(&mut buf, |pong| {
        pong.tx_id = tx_id;
        pong.src = Endpoint::from(src);
    })?;

    pkt.encrypt_in_place(our_disco, receiver, random_nonce())?;

    Ok(buf)
}

/// Serialize and seal a disco [`CallMeMaybe`] addressed to `receiver`.
///
/// `endpoints` are the candidate addresses we believe we're reachable on; the peer will
/// disco-ping them to try to open a direct path. This message is normally sent over DERP to
/// bootstrap hole-punching.
pub fn seal_call_me_maybe(
    our_disco: &DiscoPrivateKey,
    receiver: &DiscoPublicKey,
    endpoints: &[SocketAddr],
) -> Result<Vec<u8>, DiscoError> {
    let mut buf =
        vec![0u8; Packet::size_for_message(CallMeMaybe::size_for_endpoint_count(endpoints.len()))];

    let pkt = Packet::init_from_bytes::<CallMeMaybe>(&mut buf, |cmm| {
        for (i, ep) in endpoints.iter().enumerate() {
            cmm.endpoints[i] = Endpoint::from(*ep);
        }
    })?;

    pkt.encrypt_in_place(our_disco, receiver, random_nonce())?;

    Ok(buf)
}

/// Seal one of the three bind-handshake messages, addressed to the **relay server**.
///
/// The handshake is between us and the relay server, not between us and the peer, so `server` is
/// the relay's disco key (upstream `sendDiscoMessage(..., work.se.ServerDisco, bind, ...)`). The
/// returned bytes are the naked disco frame; wrap them with [`geneve_encap`] before sending.
fn seal_bind_message<M>(
    our_disco: &DiscoPrivateKey,
    receiver: &DiscoPublicKey,
    common: RelayHandshakeCommon,
) -> Result<Vec<u8>, DiscoError>
where
    M: Message
        + Sized
        + From<BindUdpRelayEndpointCommon>
        + zerocopy::Immutable
        + zerocopy::TryFromBytes
        + zerocopy::IntoBytes
        + zerocopy::KnownLayout,
{
    let mut buf = vec![0u8; Packet::size_for_message(size_of::<M>())];
    let pkt = Packet::init_from_bytes::<M>(&mut buf, |msg| {
        *msg = M::from(common.to_wire());
    })?;
    pkt.encrypt_in_place(our_disco, receiver, random_nonce())?;
    Ok(buf)
}

/// Seal a [`BindUdpRelayEndpoint`] (disco `0x04`) — the first message of the bind handshake,
/// addressed to the relay server.
pub fn seal_relay_bind(
    our_disco: &DiscoPrivateKey,
    server: &DiscoPublicKey,
    common: RelayHandshakeCommon,
) -> Result<Vec<u8>, DiscoError> {
    seal_bind_message::<BindUdpRelayEndpoint>(our_disco, server, common)
}

/// Seal a [`BindUdpRelayEndpointChallenge`] (disco `0x05`) — the second message of the bind
/// handshake, which a relay *server* sends to a client.
///
/// This fork is a relay client, so nothing in it sends this message on a production path. It is
/// provided so the codec is complete in both directions and so the peer-relay tests can stand in
/// for a relay server; `receiver` is the client's disco key.
pub fn seal_relay_bind_challenge(
    server_disco: &DiscoPrivateKey,
    receiver: &DiscoPublicKey,
    common: RelayHandshakeCommon,
) -> Result<Vec<u8>, DiscoError> {
    seal_bind_message::<BindUdpRelayEndpointChallenge>(server_disco, receiver, common)
}

/// Seal a [`BindUdpRelayEndpointAnswer`] (disco `0x06`) — the third message of the bind
/// handshake, echoing the server's challenge back to it.
pub fn seal_relay_bind_answer(
    our_disco: &DiscoPrivateKey,
    server: &DiscoPublicKey,
    common: RelayHandshakeCommon,
) -> Result<Vec<u8>, DiscoError> {
    seal_bind_message::<BindUdpRelayEndpointAnswer>(our_disco, server, common)
}

/// Seal a [`CallMeMaybeVia`] (disco `0x07`) advertising `endpoint` to `receiver`.
///
/// Provided for completeness of the codec and exercised by the round-trip tests: this fork does
/// not run a relay server and so never allocates an endpoint to advertise. Sent over DERP.
///
/// `endpoint` must carry at least one `addr:port`: Go's `UDPRelayEndpoint.decode` treats a message
/// with none as short and errors, so a zero-address message would be unparseable at the far end.
pub fn seal_call_me_maybe_via(
    our_disco: &DiscoPrivateKey,
    receiver: &DiscoPublicKey,
    endpoint: &RelayServerEndpoint,
) -> Result<Vec<u8>, DiscoError> {
    let mut buf = vec![
        0u8;
        Packet::size_for_message(CallMeMaybeVia::size_for_addr_port_count(
            endpoint.addr_ports.len()
        ))
    ];
    let pkt = Packet::init_from_bytes::<CallMeMaybeVia>(&mut buf, |m| {
        m.endpoint.server_disco = endpoint.server_disco;
        m.endpoint.client_disco = endpoint.client_disco;
        m.endpoint.lamport_id = endpoint.lamport_id.into();
        m.endpoint.vni = endpoint.vni.into();
        // Go marshals `time.Duration`, an int64 nanosecond count. Saturate rather than wrap: a
        // lifetime past ~584 years is nonsense, and a wrapped one would read as a tiny lifetime.
        m.endpoint.bind_lifetime_nanos = duration_nanos(endpoint.bind_lifetime).into();
        m.endpoint.steady_state_lifetime_nanos =
            duration_nanos(endpoint.steady_state_lifetime).into();
        for (slot, addr) in m.endpoint.addr_ports.iter_mut().zip(&endpoint.addr_ports) {
            *slot = Endpoint::from(*addr);
        }
    })?;
    pkt.encrypt_in_place(our_disco, receiver, random_nonce())?;
    Ok(buf)
}

/// A `Duration` as the u64 nanosecond count Go's `time.Duration` marshals to, saturating instead
/// of wrapping.
fn duration_nanos(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

/// Prefix a frame with the Geneve header the peer-relay leg uses.
///
/// `control` must be set for the three bind-handshake messages and clear for everything else
/// (relayed ping/pong and relayed WireGuard data) — that bit is how a relay server tells a
/// message addressed *to it* from one it should forward. See
/// [`ts_packet::geneve::GeneveHeader::control`].
pub fn geneve_encap(vni: u32, protocol: u16, control: bool, frame: &[u8]) -> Vec<u8> {
    let header = GeneveHeader {
        control,
        protocol,
        vni,
    }
    .encode();
    let mut out = Vec::with_capacity(header.len() + frame.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(frame);
    out
}

/// Wrap a frame as relayed **disco**: Geneve protocol `0x7A11`.
pub fn geneve_encap_disco(vni: u32, control: bool, frame: &[u8]) -> Vec<u8> {
    geneve_encap(vni, GENEVE_PROTOCOL_DISCO, control, frame)
}

/// Wrap a frame as relayed **WireGuard** data: Geneve protocol `0x7A12`, never control.
pub fn geneve_encap_wireguard(vni: u32, frame: &[u8]) -> Vec<u8> {
    geneve_encap(vni, GENEVE_PROTOCOL_WIREGUARD, false, frame)
}

/// What a Geneve-encapsulated datagram turned out to carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneveKind {
    /// A relayed disco frame. `control` distinguishes a bind-handshake message (terminating on
    /// the relay server, or originating from it) from a relayed ping/pong.
    Disco {
        /// The Geneve control bit.
        control: bool,
    },
    /// Relayed WireGuard data.
    WireGuard,
}

/// Classify a datagram that may be Geneve-encapsulated, returning the VNI, what it carries, and
/// the offset of the inner frame.
///
/// This mirrors Go's `packetLooksLike` (`wgengine/magicsock/magicsock.go`) rather than simply
/// decoding a header: a naked WireGuard datagram must never be mistaken for a Geneve one. Go's
/// argument for why the two cannot collide is the byte pattern — this fork's port of that check is
/// the version/reserved-bit gate below plus the protocol-field match, and, for a disco protocol
/// value, the requirement that the inner frame actually carry the disco magic. When the Geneve
/// header is well-formed but says "disco" over something that is not disco, Go deliberately falls
/// back to treating the datagram as naked WireGuard rather than dropping it; so do we, by
/// returning `None`.
pub fn geneve_prefix(buf: &[u8]) -> Option<(u32, GeneveKind, usize)> {
    if buf.len() < GENEVE_FIXED_HEADER_LEN {
        return None;
    }
    // Go: version bits, the reserved bits of byte 1 and the reserved byte 7 are all values
    // Tailscale always transmits as zero, and are what separate a Geneve header from a naked
    // WireGuard message type or a STUN binding.
    if buf[0] & 0xC0 != 0 || buf[1] & 0x3F != 0 || buf[7] != 0 {
        return None;
    }
    let (header, offset) = GeneveHeader::parse(buf).ok()?;
    match header.protocol {
        GENEVE_PROTOCOL_DISCO => {
            // A Geneve header claiming disco over a non-disco payload: Go keeps pre-Geneve
            // behaviour and treats the datagram as naked WireGuard.
            is_disco_message(buf.get(offset..)?).then_some((
                header.vni,
                GeneveKind::Disco {
                    control: header.control,
                },
                offset,
            ))
        }
        GENEVE_PROTOCOL_WIREGUARD => Some((header.vni, GeneveKind::WireGuard, offset)),
        // A well-formed Geneve header with a protocol we do not know: Go falls through to the
        // naked-disco / naked-WireGuard checks, because the bytes examined so far do not
        // distinguish it from either.
        _ => None,
    }
}

/// A disco message decoded from the wire, together with the disco key that sent it.
#[derive(Debug)]
pub enum Inbound {
    /// A ping: the peer wants us to confirm this path. We should reply with a pong.
    Ping {
        /// The disco key that sealed the ping.
        sender: DiscoPublicKey,
        /// The node key the sender claims for its disco key.
        ///
        /// Disco intends this to be bound to the disco key via the control netmap (i.e. verify
        /// control really advertised this node key for this disco key). This codec/socket layer
        /// has no netmap, so the cross-check is performed by the magicsock consumer
        /// (`handle_disco`) via the optional [`crate::BindingVerifier`] the netmap-owning route
        /// layer installs: a ping whose `claimed_node_key` is not bound to its disco key is
        /// dropped fail-closed.
        ///
        /// `None` for a pre-1.16.0 peer that sent a node-key-less Ping (12-byte body; Go `parsePing`
        /// accepts it, reading the node key only when >=32 bytes follow the tx id). The fork is the
        /// dialing client against modern (>=1.16) peers, which always embed the key, so `handle_disco`
        /// drops a `None`-keyed Ping fail-closed — it cannot satisfy the exact disco<->node-key
        /// binding. This keeps the fork at least as strict as Go (which would still pong it on disco
        /// membership), never looser.
        claimed_node_key: Option<NodePublicKey>,
        /// The ping's transaction id, to be echoed in the pong.
        tx_id: TxId,
    },
    /// A pong: the peer confirmed a path we pinged.
    Pong {
        /// The disco key that sealed the pong.
        sender: DiscoPublicKey,
        /// The transaction id of the ping this answers.
        tx_id: TxId,
        /// The address the peer saw our ping arrive from (our reflexive address).
        src: SocketAddr,
    },
    /// A call-me-maybe: the peer is asking us to open a path to its listed endpoints.
    CallMeMaybe {
        /// The disco key that sealed the message.
        sender: DiscoPublicKey,
        /// The endpoints the peer believes it is reachable on.
        endpoints: Vec<SocketAddr>,
    },
    /// A call-me-maybe-via: the peer is asking us to open a path *through a UDP relay server*
    /// it has already had an endpoint allocated on.
    ///
    /// Arrives over DERP, exactly like [`Inbound::CallMeMaybe`]. Acting on it means running the
    /// 3-way bind handshake against the named relay server before anything can flow.
    CallMeMaybeVia {
        /// The disco key that sealed the message: the peer, not the relay server.
        sender: DiscoPublicKey,
        /// The relay endpoint to handshake with.
        endpoint: RelayServerEndpoint,
    },
    /// The first bind-handshake message, sent by a relay *client* to a relay *server*.
    ///
    /// This fork is a relay client only, never a relay server (upstream's server half lives in
    /// `net/udprelay` / `feature/relayserver`, which this repository does not implement), so
    /// receiving one means a peer took us for a relay server. Decoded so the message is
    /// recognized rather than mistaken for something else, then dropped.
    BindUdpRelayEndpoint {
        /// The disco key that sealed the message.
        sender: DiscoPublicKey,
        /// The handshake fields.
        common: RelayHandshakeCommon,
    },
    /// A relay server's challenge, the second bind-handshake message. This is the one message of
    /// the three a relay *client* acts on.
    BindUdpRelayEndpointChallenge {
        /// The disco key that sealed the message: the relay server's.
        sender: DiscoPublicKey,
        /// The handshake fields, including the challenge to echo back.
        common: RelayHandshakeCommon,
    },
    /// The third bind-handshake message, client → server. Server-bound like
    /// [`Inbound::BindUdpRelayEndpoint`]: decoded, then dropped.
    BindUdpRelayEndpointAnswer {
        /// The disco key that sealed the message.
        sender: DiscoPublicKey,
        /// The handshake fields, echoing the server's challenge.
        common: RelayHandshakeCommon,
    },
    /// A request to allocate a relay endpoint, addressed to a relay server. Server-bound:
    /// decoded, then dropped.
    AllocateUdpRelayEndpointsRequest {
        /// The disco key that sealed the message.
        sender: DiscoPublicKey,
        /// The two client disco keys the endpoint should serve.
        client_disco: [DiscoPublicKey; 2],
        /// The request generation, to be echoed in the response.
        generation: u32,
    },
    /// A relay server's response to an allocation request.
    ///
    /// This fork does not *request* allocations (it has no relay-allocation client; peers that
    /// run a relay allocate on our behalf and tell us with a `CallMeMaybeVia`), so an unsolicited
    /// response is decoded and dropped rather than acted on.
    AllocateUdpRelayEndpointsResponse {
        /// The disco key that sealed the message: the relay server's.
        sender: DiscoPublicKey,
        /// The generation echoed from the request.
        generation: u32,
        /// The endpoint that was allocated.
        endpoint: RelayServerEndpoint,
    },
}

/// The fields shared by all three bind-handshake messages, in owned host-order form
/// (upstream `disco.BindUDPRelayEndpointCommon`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayHandshakeCommon {
    /// The relay endpoint's Geneve Virtual Network Identifier.
    ///
    /// Upstream requires this sealed copy to equal the VNI in the *cleartext* Geneve header the
    /// message arrived under. They can only differ if the cleartext header was tampered with or
    /// mangled, so a mismatch drops the message.
    pub vni: u32,
    /// The handshake generation the client chose. Non-zero.
    pub generation: u32,
    /// The disco key of the remote *peer* on this relay endpoint — not the relay server's, and
    /// not ours.
    pub remote_key: DiscoPublicKey,
    /// The server's challenge, echoed by the client in its answer. Meaningless padding in the
    /// first (bind) message.
    pub challenge: [u8; BIND_UDP_RELAY_CHALLENGE_LEN],
}

impl RelayHandshakeCommon {
    /// Read the wire form into owned host order.
    fn from_wire(wire: &BindUdpRelayEndpointCommon) -> Self {
        Self {
            vni: wire.vni.get(),
            generation: wire.generation.get(),
            remote_key: wire.remote_key,
            challenge: wire.challenge,
        }
    }

    /// Write owned host order back to the wire form.
    fn to_wire(self) -> BindUdpRelayEndpointCommon {
        BindUdpRelayEndpointCommon {
            vni: self.vni.into(),
            generation: self.generation.into(),
            remote_key: self.remote_key,
            challenge: self.challenge,
        }
    }
}

/// Parse and open an inbound disco datagram.
///
/// `buf` must be a mutable copy of the received bytes (decryption happens in place). Returns
/// an error if the datagram is not a valid disco message or cannot be opened with our key.
pub fn open(our_disco: &DiscoPrivateKey, buf: &mut [u8]) -> Result<Inbound, DiscoError> {
    let pkt = Packet::from_encrypted_bytes_mut(buf)?;
    let sender = pkt.header().sender_pub();

    let plain = pkt.decrypt_in_place(our_disco)?;

    match plain.ty() {
        Some(MessageType::Ping) => {
            // Lax parse (Go `parsePing`): a 12-byte body (tx id only, no node key) from a pre-1.16
            // peer is accepted, with the node key read only when >=32 bytes follow; trailing bytes
            // are padding. The strict `as_msg::<Ping>` would drop a node-key-less Ping (its layout
            // mandates the 32-byte key). `claimed_node_key` is therefore `Option`al here.
            let (tx_id, claimed_node_key) = plain.ping_lax().ok_or(DiscoError::Malformed)?;
            Ok(Inbound::Ping {
                sender,
                claimed_node_key,
                tx_id,
            })
        }
        Some(MessageType::Pong) => {
            // Lax parse (Go `parsePong` is "deliberately lax on longer-than-expected messages"):
            // take the fixed Pong prefix and ignore any trailing forward-compat bytes, so a future
            // peer that appends to a Pong still gets its path confirmed instead of falling back to
            // DERP. The strict exact-size parse would drop such a Pong entirely.
            let pong = plain.as_msg_lax::<Pong>().ok_or(DiscoError::Malformed)?;
            Ok(Inbound::Pong {
                sender,
                tx_id: pong.tx_id,
                src: pong.src.socket_addr(),
            })
        }
        Some(MessageType::CallMeMaybe) => {
            // Lax parse (Go `parseCallMeMaybe`): take the whole 18-byte endpoints and ignore a
            // trailing partial/extension tail, rather than dropping the entire message when the body
            // isn't an exact multiple of the endpoint size. Still capped per message
            // (anti-amplification — [`MAX_INBOUND_CALLMEMAYBE_ENDPOINTS`]); keep the first N listed.
            let endpoints = plain
                .call_me_maybe_endpoints()
                .ok_or(DiscoError::Malformed)?
                .take(MAX_INBOUND_CALLMEMAYBE_ENDPOINTS)
                .map(|e| e.socket_addr())
                .collect();
            Ok(Inbound::CallMeMaybe { sender, endpoints })
        }
        // The peer-relay handshake messages (0x04/0x05/0x06). Go's parsers ignore the version
        // byte for all three and read the fixed 72-byte common block from the body prefix, which
        // is exactly `as_msg_lax`.
        Some(MessageType::BindUdpRelayEndpoint) => {
            let msg = plain
                .as_msg_lax::<BindUdpRelayEndpoint>()
                .ok_or(DiscoError::Malformed)?;
            Ok(Inbound::BindUdpRelayEndpoint {
                sender,
                common: RelayHandshakeCommon::from_wire(&msg.common),
            })
        }
        Some(MessageType::BindUdpRelayEndpointChallenge) => {
            let msg = plain
                .as_msg_lax::<BindUdpRelayEndpointChallenge>()
                .ok_or(DiscoError::Malformed)?;
            Ok(Inbound::BindUdpRelayEndpointChallenge {
                sender,
                common: RelayHandshakeCommon::from_wire(&msg.common),
            })
        }
        Some(MessageType::BindUdpRelayEndpointAnswer) => {
            let msg = plain
                .as_msg_lax::<BindUdpRelayEndpointAnswer>()
                .ok_or(DiscoError::Malformed)?;
            Ok(Inbound::BindUdpRelayEndpointAnswer {
                sender,
                common: RelayHandshakeCommon::from_wire(&msg.common),
            })
        }
        Some(MessageType::CallMeMaybeVia) => {
            let msg = plain
                .call_me_maybe_via()
                .ok_or(DiscoError::Malformed)?
                .map_err(|_| DiscoError::Malformed)?;
            Ok(Inbound::CallMeMaybeVia {
                sender,
                endpoint: RelayServerEndpoint::from_wire(&msg.endpoint),
            })
        }
        Some(MessageType::AllocateUdpRelayEndpointsRequest) => {
            let msg = plain
                .allocate_udp_relay_endpoints_request()
                .ok_or(DiscoError::Malformed)?
                .map_err(|_| DiscoError::Malformed)?;
            Ok(Inbound::AllocateUdpRelayEndpointsRequest {
                sender,
                client_disco: msg.client_disco,
                generation: msg.generation.get(),
            })
        }
        Some(MessageType::AllocateUdpRelayEndpointsResponse) => {
            let msg = plain
                .allocate_udp_relay_endpoints_response()
                .ok_or(DiscoError::Malformed)?
                .map_err(|_| DiscoError::Malformed)?;
            Ok(Inbound::AllocateUdpRelayEndpointsResponse {
                sender,
                generation: msg.generation(),
                endpoint: RelayServerEndpoint::from_wire(&msg.endpoint),
            })
        }
        // A type byte outside the nine upstream defines. Go's `disco.Parse` errors here too.
        None => Err(DiscoError::UnknownMessageType),
    }
}

fn random_nonce() -> [u8; Header::NONCE_LEN] {
    let mut nonce = [0u8; Header::NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

/// The disco magic prefix that every demux site keys on (see [`looks_like_disco`]). Kept here
/// so a wire-format change is caught by this crate's own tests, not only the protocol crate.
///
/// Test-only: this is a wire-format guard exercised by `magic_prefix_is_the_demux_key`; it has
/// no runtime caller, so it is compiled only under `cfg(test)` rather than carrying an
/// `#[allow(dead_code)]`.
#[cfg(test)]
pub(crate) fn magic_prefix() -> &'static [u8] {
    Header::MAGIC.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (DiscoPrivateKey, DiscoPublicKey) {
        let sk = DiscoPrivateKey::random();
        let pk = sk.public_key();
        (sk, pk)
    }

    #[test]
    fn ping_roundtrips_and_demuxes_as_disco() {
        let (a_sk, _a_pk) = keypair();
        let (b_sk, b_pk) = keypair();
        let node_key = ts_keys::NodePrivateKey::random().public_key();
        let tx = random_tx_id();

        let wire = seal_ping(&a_sk, node_key, &b_pk, tx).unwrap();
        assert!(looks_like_disco(&wire), "ping must demux as disco");

        let mut buf = wire.clone();
        match open(&b_sk, &mut buf).unwrap() {
            Inbound::Ping {
                sender,
                claimed_node_key,
                tx_id,
            } => {
                assert_eq!(sender, a_sk.public_key());
                assert_eq!(claimed_node_key, Some(node_key));
                assert_eq!(tx_id, tx);
            }
            other => panic!("expected ping, got {other:?}"),
        }
    }

    #[test]
    fn pong_roundtrips_and_echoes_src() {
        let (a_sk, _a_pk) = keypair();
        let (b_sk, b_pk) = keypair();
        let tx = random_tx_id();
        let src: SocketAddr = "203.0.113.7:41641".parse().unwrap();

        let wire = seal_pong(&a_sk, &b_pk, tx, src).unwrap();
        let mut buf = wire;
        match open(&b_sk, &mut buf).unwrap() {
            Inbound::Pong {
                sender,
                tx_id,
                src: got,
            } => {
                assert_eq!(sender, a_sk.public_key());
                assert_eq!(tx_id, tx);
                assert_eq!(got, src);
            }
            other => panic!("expected pong, got {other:?}"),
        }
    }

    #[test]
    fn call_me_maybe_roundtrips() {
        let (a_sk, _a_pk) = keypair();
        let (b_sk, b_pk) = keypair();
        let eps: Vec<SocketAddr> = vec![
            "203.0.113.7:41641".parse().unwrap(),
            "198.51.100.2:3478".parse().unwrap(),
        ];

        let wire = seal_call_me_maybe(&a_sk, &b_pk, &eps).unwrap();
        assert!(looks_like_disco(&wire), "call-me-maybe must demux as disco");

        let mut buf = wire;
        match open(&b_sk, &mut buf).unwrap() {
            Inbound::CallMeMaybe { sender, endpoints } => {
                assert_eq!(sender, a_sk.public_key());
                assert_eq!(endpoints, eps);
            }
            other => panic!("expected call-me-maybe, got {other:?}"),
        }
    }

    /// Anti-amplification: a `CallMeMaybe` advertising far more than
    /// [`MAX_INBOUND_CALLMEMAYBE_ENDPOINTS`] is accepted but only its first N endpoints are kept,
    /// so a malicious peer can't make us disco-ping thousands of attacker-chosen addresses from one
    /// datagram.
    #[test]
    fn call_me_maybe_endpoints_capped_to_first_n() {
        let (a_sk, _a_pk) = keypair();
        let (b_sk, b_pk) = keypair();

        // Build a list well over the cap with distinct, order-revealing addresses.
        let over = MAX_INBOUND_CALLMEMAYBE_ENDPOINTS + 50;
        let eps: Vec<SocketAddr> = (0..over)
            .map(|i| format!("203.0.113.7:{}", 40000 + i as u16).parse().unwrap())
            .collect();

        let wire = seal_call_me_maybe(&a_sk, &b_pk, &eps).unwrap();
        let mut buf = wire;
        match open(&b_sk, &mut buf).unwrap() {
            Inbound::CallMeMaybe { endpoints, .. } => {
                assert_eq!(
                    endpoints.len(),
                    MAX_INBOUND_CALLMEMAYBE_ENDPOINTS,
                    "endpoints must be capped at MAX_INBOUND_CALLMEMAYBE_ENDPOINTS"
                );
                // The kept ones are the FIRST N, in order.
                assert_eq!(
                    endpoints,
                    eps[..MAX_INBOUND_CALLMEMAYBE_ENDPOINTS].to_vec(),
                    "the kept endpoints must be the first N the peer listed"
                );
            }
            other => panic!("expected call-me-maybe, got {other:?}"),
        }
    }

    /// Exact N→N+1 boundary: one endpoint over the cap drops precisely the last (overflow) one and
    /// keeps the first N — pinning the `>= cap` / `take(N)` operators against an off-by-one.
    #[test]
    fn call_me_maybe_drops_exactly_the_overflow_endpoint() {
        let (a_sk, _a_pk) = keypair();
        let (b_sk, b_pk) = keypair();
        let eps: Vec<SocketAddr> = (0..MAX_INBOUND_CALLMEMAYBE_ENDPOINTS + 1)
            .map(|i| format!("203.0.113.7:{}", 40000 + i as u16).parse().unwrap())
            .collect();

        let wire = seal_call_me_maybe(&a_sk, &b_pk, &eps).unwrap();
        let mut buf = wire;
        match open(&b_sk, &mut buf).unwrap() {
            Inbound::CallMeMaybe { endpoints, .. } => {
                assert_eq!(endpoints, eps[..MAX_INBOUND_CALLMEMAYBE_ENDPOINTS].to_vec());
                assert!(
                    !endpoints.contains(eps.last().unwrap()),
                    "the single overflow endpoint must be the one dropped"
                );
            }
            other => panic!("expected call-me-maybe, got {other:?}"),
        }
    }

    /// A `CallMeMaybe` at or under the cap is unaffected (no truncation of a legitimate list).
    #[test]
    fn call_me_maybe_at_cap_is_unchanged() {
        let (a_sk, _a_pk) = keypair();
        let (b_sk, b_pk) = keypair();
        let eps: Vec<SocketAddr> = (0..MAX_INBOUND_CALLMEMAYBE_ENDPOINTS)
            .map(|i| format!("198.51.100.2:{}", 3478 + i as u16).parse().unwrap())
            .collect();

        let wire = seal_call_me_maybe(&a_sk, &b_pk, &eps).unwrap();
        let mut buf = wire;
        match open(&b_sk, &mut buf).unwrap() {
            Inbound::CallMeMaybe { endpoints, .. } => assert_eq!(endpoints, eps),
            other => panic!("expected call-me-maybe, got {other:?}"),
        }
    }

    /// Interop (Go `parsePong` is "deliberately lax on longer-than-expected messages"): an
    /// over-length Pong — a forward-compatible peer appending trailing bytes after the 30-byte body
    /// — must still parse (its `tx_id`/`src` taken from the prefix, the tail ignored), so the path
    /// gets confirmed instead of falling back to DERP. The pre-fix exact-size parse dropped it.
    #[test]
    fn over_length_pong_is_accepted_lax() {
        let (a_sk, _a_pk) = keypair();
        let (b_sk, b_pk) = keypair();
        let tx = random_tx_id();
        let src: SocketAddr = "203.0.113.7:41641".parse().unwrap();

        // Seal a normal pong, then re-seal the same plaintext with 7 trailing bytes appended to the
        // message body (simulating a future peer's extension).
        let mut wire = seal_pong_with_trailing(&a_sk, &b_pk, tx, src, 7);

        match open(&b_sk, &mut wire).unwrap() {
            Inbound::Pong {
                sender,
                tx_id,
                src: got,
            } => {
                assert_eq!(sender, a_sk.public_key());
                assert_eq!(tx_id, tx, "tx_id taken from the prefix");
                assert_eq!(
                    got, src,
                    "src taken from the prefix; trailing bytes ignored"
                );
            }
            other => panic!("expected pong, got {other:?}"),
        }
    }

    /// Interop (Go `parseCallMeMaybe`): a `CallMeMaybe` whose body is NOT an exact multiple of the
    /// 18-byte endpoint size must yield its whole leading endpoints (the trailing partial/extension
    /// bytes ignored), not be dropped entirely. The pre-fix exact-multiple parse dropped the whole
    /// message on any trailing bytes.
    #[test]
    fn call_me_maybe_with_trailing_partial_endpoint_keeps_whole_ones() {
        let (a_sk, _a_pk) = keypair();
        let (b_sk, b_pk) = keypair();
        let eps: Vec<SocketAddr> = vec![
            "203.0.113.7:41641".parse().unwrap(),
            "198.51.100.2:3478".parse().unwrap(),
        ];

        // Two whole 18-byte endpoints + 5 trailing bytes (a partial third endpoint / extension).
        let mut wire = seal_call_me_maybe_with_trailing(&a_sk, &b_pk, &eps, 5);

        match open(&b_sk, &mut wire).unwrap() {
            Inbound::CallMeMaybe { sender, endpoints } => {
                assert_eq!(sender, a_sk.public_key());
                assert_eq!(
                    endpoints, eps,
                    "the two whole endpoints are parsed; the trailing partial is ignored"
                );
            }
            other => panic!("expected call-me-maybe, got {other:?}"),
        }
    }

    /// Floor guard (the inverse of the lax-tail tests): lax must mean "ignore EXTRA", NEVER "accept
    /// LESS". A Pong whose body is shorter than the canonical 30 bytes must still be rejected —
    /// `as_msg_lax::<Pong>` requires the full fixed prefix, so a truncated Pong is `Malformed`, not
    /// silently read with uninitialized/attacker-truncated `src`/`tx_id`.
    #[test]
    fn truncated_pong_is_rejected_not_read_short() {
        let (a_sk, _a_pk) = keypair();
        let (b_sk, b_pk) = keypair();
        let tx = random_tx_id();

        // 29-byte body (one short of Pong's 30): just the tx_id (12) + a partial Endpoint (17).
        let mut body = Vec::new();
        body.extend_from_slice(&tx);
        body.extend_from_slice(&[0u8; 17]);
        assert_eq!(body.len(), 29);
        let mut wire = seal_raw(&a_sk, &b_pk, MessageType::Pong, &body, 0);

        assert!(
            matches!(open(&b_sk, &mut wire), Err(DiscoError::Malformed)),
            "a Pong shorter than its fixed size must be rejected, not read short"
        );
    }

    /// A `CallMeMaybe` body shorter than one 18-byte endpoint (here 5 bytes, and the empty case)
    /// yields NO endpoints rather than an error — Go's "soft-empty" CallMeMaybe parity, and the
    /// deliberate opposite of Pong's reject-on-short floor. Pinning the asymmetry so a future change
    /// can't silently flip either floor.
    #[test]
    fn short_call_me_maybe_yields_empty_not_error() {
        let (a_sk, _a_pk) = keypair();
        let (b_sk, b_pk) = keypair();

        for body_len in [0usize, 5, 17] {
            let mut wire = seal_raw(
                &a_sk,
                &b_pk,
                MessageType::CallMeMaybe,
                &vec![0u8; body_len],
                0,
            );
            match open(&b_sk, &mut wire) {
                Ok(Inbound::CallMeMaybe { endpoints, .. }) => assert!(
                    endpoints.is_empty(),
                    "a sub-endpoint-length CallMeMaybe ({body_len}B) must yield no endpoints"
                ),
                other => panic!("expected empty call-me-maybe for {body_len}B, got {other:?}"),
            }
        }
    }

    /// The cross-type guard is load-bearing: lax parsing must not let a packet of one type be read
    /// as another. A `CallMeMaybe`-typed packet must NOT parse as a `Pong` via the lax path (and
    /// vice-versa) — the `pt.ty()` check in each parser is what prevents a wrong-typed body being
    /// misread. `open()` dispatches on the type, so we assert it returns the matching `Inbound`.
    #[test]
    fn lax_parsers_keep_the_type_guard() {
        let (a_sk, _a_pk) = keypair();
        let (b_sk, b_pk) = keypair();

        // A CallMeMaybe must open as CallMeMaybe (never as a Pong), even though its body length
        // could be mistaken for a padded Pong.
        let eps: Vec<SocketAddr> = vec!["203.0.113.7:41641".parse().unwrap()];
        let mut cmm = seal_call_me_maybe(&a_sk, &b_pk, &eps).unwrap();
        assert!(
            matches!(open(&b_sk, &mut cmm).unwrap(), Inbound::CallMeMaybe { .. }),
            "a CallMeMaybe-typed packet must open as CallMeMaybe, not be misread as a Pong"
        );

        // A Pong must open as Pong (never as CallMeMaybe).
        let mut pong = seal_pong(
            &a_sk,
            &b_pk,
            random_tx_id(),
            "198.51.100.2:3478".parse().unwrap(),
        )
        .unwrap();
        assert!(
            matches!(open(&b_sk, &mut pong).unwrap(), Inbound::Pong { .. }),
            "a Pong-typed packet must open as Pong, not be misread as a CallMeMaybe"
        );
    }

    /// Seal a disco message of `ty` from `message` bytes with `trailing` extra **non-zero** bytes
    /// appended to the body (so the on-wire message is longer than the canonical size). The trailing
    /// fill is `0xAB`, not zero, so an over-length test strictly proves the tail is *ignored* rather
    /// than coincidentally tolerated because it was zero. Builds the plaintext buffer directly
    /// because the typed `seal_*` helpers produce exact-size bodies.
    fn seal_raw(
        our_disco: &DiscoPrivateKey,
        receiver: &DiscoPublicKey,
        ty: MessageType,
        message: &[u8],
        trailing: usize,
    ) -> Vec<u8> {
        use ts_disco_protocol::Packet;
        let body_len = message.len() + trailing;
        let mut buf = vec![0u8; Packet::size_for_message(body_len)];
        // Plaintext layout inside the packet payload is `ty:u8, version:u8, message:[u8]`; write it
        // via the raw-message initializer so we control the exact (over-long) body.
        let pkt = Packet::init_raw_message(&mut buf, ty, |msg| {
            msg[..message.len()].copy_from_slice(message);
            // Trailing bytes are a recognizable non-zero pattern, so the lax parsers must actively
            // ignore them (a zero fill could pass even if the tail were wrongly read).
            msg[message.len()..].fill(0xAB);
        })
        .expect("init raw disco message");
        pkt.encrypt_in_place(our_disco, receiver, random_nonce())
            .expect("encrypt");
        buf
    }

    fn seal_pong_with_trailing(
        our_disco: &DiscoPrivateKey,
        receiver: &DiscoPublicKey,
        tx_id: TxId,
        src: SocketAddr,
        trailing: usize,
    ) -> Vec<u8> {
        // Canonical 30-byte Pong body: tx_id(12) + Endpoint(18).
        let mut body = Vec::new();
        body.extend_from_slice(&tx_id);
        body.extend_from_slice(Endpoint::from(src).as_bytes());
        seal_raw(our_disco, receiver, MessageType::Pong, &body, trailing)
    }

    fn seal_call_me_maybe_with_trailing(
        our_disco: &DiscoPrivateKey,
        receiver: &DiscoPublicKey,
        endpoints: &[SocketAddr],
        trailing: usize,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        for ep in endpoints {
            body.extend_from_slice(Endpoint::from(*ep).as_bytes());
        }
        seal_raw(
            our_disco,
            receiver,
            MessageType::CallMeMaybe,
            &body,
            trailing,
        )
    }

    #[test]
    fn wrong_key_fails_to_open() {
        let (a_sk, _a_pk) = keypair();
        let (_b_sk, b_pk) = keypair();
        let (c_sk, _c_pk) = keypair();
        let node_key = ts_keys::NodePrivateKey::random().public_key();

        let wire = seal_ping(&a_sk, node_key, &b_pk, random_tx_id()).unwrap();
        let mut buf = wire;
        // c is not the intended receiver: opening must fail (authenticated encryption).
        assert!(open(&c_sk, &mut buf).is_err());
    }

    #[test]
    fn non_disco_bytes_are_not_disco() {
        // A WireGuard data packet starts with type byte 0x04, never the disco magic.
        let wg = [0x04u8, 0, 0, 0, 1, 2, 3, 4];
        assert!(!looks_like_disco(&wg));
    }

    #[test]
    fn magic_prefix_is_the_demux_key() {
        // The magic prefix is load-bearing: it is exactly what `looks_like_disco`/the codec
        // keys on to separate disco from WireGuard. Guard the wire format from this crate.
        let prefix = magic_prefix();
        assert_eq!(prefix, b"TS\xf0\x9f\x92\xac", "disco magic prefix changed");

        // A real sealed disco datagram must begin with exactly this prefix, and that is what
        // makes `looks_like_disco` accept it. This ties the helper to the predicate every
        // reader of the underlay socket uses.
        let (a_sk, _a_pk) = keypair();
        let (_b_sk, b_pk) = keypair();
        let node_key = ts_keys::NodePrivateKey::random().public_key();
        let mut wire = seal_ping(&a_sk, node_key, &b_pk, random_tx_id()).unwrap();

        assert!(
            wire.starts_with(prefix),
            "sealed disco must carry the magic prefix"
        );
        assert!(looks_like_disco(&wire), "magic prefix must demux as disco");

        // Flipping a prefix byte must break the demux — proving the prefix is the key.
        wire[0] ^= 0xff;
        assert!(
            !looks_like_disco(&wire),
            "a corrupted prefix must not demux as disco"
        );
    }

    /// Seal a disco message with an explicit version byte (vs the `seal_*` helpers which use 0), so
    /// the per-type version laxity can be exercised end-to-end through `open()`.
    fn seal_versioned(
        our_disco: &DiscoPrivateKey,
        receiver: &DiscoPublicKey,
        ty: MessageType,
        version: u8,
        message: &[u8],
    ) -> Vec<u8> {
        use ts_disco_protocol::Packet;
        let mut buf = vec![0u8; Packet::size_for_message(message.len())];
        let pkt = Packet::init_raw_message_versioned(&mut buf, ty, version, |msg| {
            msg.copy_from_slice(message);
        })
        .expect("init versioned disco message");
        pkt.encrypt_in_place(our_disco, receiver, random_nonce())
            .expect("encrypt");
        buf
    }

    /// A `Ping` with a future (non-zero) version byte must still parse — Go's `parsePing` ignores
    /// the version. The old whole-packet version gate dropped it, which would silently force a
    /// real Go peer onto DERP after a disco protocol bump. (tsr-ibc)
    #[test]
    fn future_version_ping_still_parses() {
        let (a_sk, _a_pk) = keypair();
        let (b_sk, b_pk) = keypair();
        let node_key = ts_keys::NodePrivateKey::random().public_key();
        let tx = random_tx_id();

        // Canonical Ping body: tx_id(12) + node_key(32).
        let mut body = Vec::new();
        body.extend_from_slice(&tx);
        body.extend_from_slice(&node_key.to_bytes());
        let mut wire = seal_versioned(&a_sk, &b_pk, MessageType::Ping, 1, &body);

        match open(&b_sk, &mut wire).expect("a future-version ping must still open") {
            Inbound::Ping {
                claimed_node_key,
                tx_id,
                ..
            } => {
                assert_eq!(claimed_node_key, Some(node_key));
                assert_eq!(tx_id, tx);
            }
            other => panic!("expected ping, got {other:?}"),
        }
    }

    /// A pre-1.16.0 peer's node-key-less Ping (a 12-byte body: tx id only, no node key) must still
    /// parse, surfacing `claimed_node_key: None` — Go `parsePing` reads the node key only when >=32
    /// bytes follow the tx id. The strict `as_msg::<Ping>` would drop it (its layout mandates the
    /// 32-byte key); the lax `ping_lax` accepts it. (The consumer then drops a `None`-keyed ping
    /// fail-closed, but that is `handle_disco`'s decision, tested in `sock.rs`.)
    #[test]
    fn pre_116_node_keyless_ping_parses_with_none_node_key() {
        let (a_sk, _a_pk) = keypair();
        let (b_sk, b_pk) = keypair();
        let tx = random_tx_id();

        // A 12-byte Ping body: tx id only, no node key, no padding.
        let mut wire = seal_raw(&a_sk, &b_pk, MessageType::Ping, &tx, 0);
        match open(&b_sk, &mut wire).expect("a node-key-less ping must still open") {
            Inbound::Ping {
                sender,
                claimed_node_key,
                tx_id,
            } => {
                assert_eq!(sender, a_sk.public_key());
                assert_eq!(
                    claimed_node_key, None,
                    "a 12-byte ping carries no node key (Go parsePing parity)"
                );
                assert_eq!(tx_id, tx);
            }
            other => panic!("expected ping, got {other:?}"),
        }
    }

    /// Boundary: the node key is read only when **at least 32 bytes follow the 12-byte tx id** (Go
    /// `parsePing`'s `len(p) >= NodePublicRawLen` evaluated after consuming the tx id). A 43-byte body
    /// (31 bytes after the tx id) is one short, so `claimed_node_key` is `None` — those 31 bytes are
    /// padding, NOT a truncated key. This pins the gate against a `total >= 44` off-by-one (which would
    /// agree with the 12- and 44-byte cases but diverge exactly here).
    #[test]
    fn ping_one_byte_short_of_node_key_parses_as_none() {
        let (a_sk, _a_pk) = keypair();
        let (b_sk, b_pk) = keypair();
        let tx = random_tx_id();

        // 43-byte body: 12-byte tx id + 31 bytes (one short of a 32-byte node key).
        let mut body = Vec::new();
        body.extend_from_slice(&tx);
        body.extend_from_slice(&[0xAB; 31]);
        assert_eq!(body.len(), 43);
        let mut wire = seal_raw(&a_sk, &b_pk, MessageType::Ping, &body, 0);
        match open(&b_sk, &mut wire).expect("a 43-byte ping must still open") {
            Inbound::Ping {
                claimed_node_key,
                tx_id,
                ..
            } => {
                assert_eq!(
                    claimed_node_key, None,
                    "31 bytes after the tx id is < 32, so no node key is read (remaining-length gate)"
                );
                assert_eq!(tx_id, tx);
            }
            other => panic!("expected ping, got {other:?}"),
        }
    }

    /// A Ping with a node key AND trailing padding (body > 44 bytes) parses to `Some(node_key)` with
    /// the trailing bytes ignored — Go `parsePing` is "deliberately lax on longer-than-expected
    /// messages". The trailing fill is a recognizable non-zero pattern so the parser must actively
    /// ignore it (a zero fill could pass even if the tail were wrongly folded into the key).
    #[test]
    fn ping_with_node_key_and_trailing_padding_parses_as_some() {
        let (a_sk, _a_pk) = keypair();
        let (b_sk, b_pk) = keypair();
        let tx = random_tx_id();
        let node_key = ts_keys::NodePrivateKey::random().public_key();

        // 12 tx id + 32 node key + 7 trailing padding bytes = 51-byte body.
        let mut body = Vec::new();
        body.extend_from_slice(&tx);
        body.extend_from_slice(&node_key.to_bytes());
        body.extend_from_slice(&[0xAB; 7]);
        let mut wire = seal_raw(&a_sk, &b_pk, MessageType::Ping, &body, 0);
        match open(&b_sk, &mut wire).expect("an over-length ping must still open") {
            Inbound::Ping {
                claimed_node_key,
                tx_id,
                ..
            } => {
                assert_eq!(
                    claimed_node_key,
                    Some(node_key),
                    "the 32-byte node key is read; the 7 trailing padding bytes are ignored"
                );
                assert_eq!(tx_id, tx);
            }
            other => panic!("expected ping, got {other:?}"),
        }
    }

    /// A `Pong` with a future version byte must still parse (Go's `parsePong` ignores version),
    /// so a forward-version peer's pong still confirms the path instead of being dropped.
    #[test]
    fn future_version_pong_still_parses() {
        let (a_sk, _a_pk) = keypair();
        let (b_sk, b_pk) = keypair();
        let tx = random_tx_id();
        let src: SocketAddr = "203.0.113.9:41641".parse().unwrap();

        let mut body = Vec::new();
        body.extend_from_slice(&tx);
        body.extend_from_slice(Endpoint::from(src).as_bytes());
        let mut wire = seal_versioned(&a_sk, &b_pk, MessageType::Pong, 2, &body);

        match open(&b_sk, &mut wire).expect("a future-version pong must still open") {
            Inbound::Pong {
                tx_id, src: got, ..
            } => {
                assert_eq!(tx_id, tx);
                assert_eq!(got, src);
            }
            other => panic!("expected pong, got {other:?}"),
        }
    }

    /// A `CallMeMaybe` with a future version byte must open with NO endpoints (Go's
    /// `parseCallMeMaybe` soft-empties when `ver != 0`), rather than being rejected wholesale.
    #[test]
    fn future_version_call_me_maybe_opens_empty() {
        let (a_sk, _a_pk) = keypair();
        let (b_sk, b_pk) = keypair();
        let ep: SocketAddr = "203.0.113.10:3478".parse().unwrap();

        let body = Endpoint::from(ep).as_bytes().to_vec();
        let mut wire = seal_versioned(&a_sk, &b_pk, MessageType::CallMeMaybe, 1, &body);

        match open(&b_sk, &mut wire).expect("a future-version call-me-maybe must still open") {
            Inbound::CallMeMaybe { endpoints, .. } => {
                assert!(
                    endpoints.is_empty(),
                    "a non-zero-version CallMeMaybe yields no endpoints (Go soft-empty), got {endpoints:?}"
                );
            }
            other => panic!("expected call-me-maybe, got {other:?}"),
        }
    }

    /// The version-0 path is unchanged: a normal CallMeMaybe still yields its endpoints.
    #[test]
    fn version_zero_call_me_maybe_still_yields_endpoints() {
        let (a_sk, _a_pk) = keypair();
        let (b_sk, b_pk) = keypair();
        let ep: SocketAddr = "203.0.113.11:3478".parse().unwrap();

        let mut wire = seal_call_me_maybe(&a_sk, &b_pk, &[ep]).unwrap();
        match open(&b_sk, &mut wire).expect("v0 call-me-maybe opens") {
            Inbound::CallMeMaybe { endpoints, .. } => {
                assert_eq!(endpoints, vec![ep], "v0 endpoints must still be delivered");
            }
            other => panic!("expected call-me-maybe, got {other:?}"),
        }
    }
}
