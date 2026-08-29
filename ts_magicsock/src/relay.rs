//! Peer-relay client state: the `CallMeMaybeVia` → bind-handshake → relayed ping/pong path.
//!
//! A peer that cannot be reached directly may still be reachable through a **UDP relay server**
//! (upstream `net/udprelay`, driven client-side by `wgengine/magicsock/relaymanager.go`). The peer
//! asks a relay to allocate an endpoint for the two of us, then tells us about it over DERP with a
//! [`CallMeMaybeVia`][ts_disco_protocol::CallMeMaybeVia]. Before either side may push data through
//! that endpoint it must complete a 3-way bind handshake with the relay server:
//!
//! ```text
//!   us ──BindUDPRelayEndpoint (0x04, Geneve control)──────────▶ relay server
//!   us ◀─BindUDPRelayEndpointChallenge (0x05, Geneve control)── relay server
//!   us ──BindUDPRelayEndpointAnswer (0x06, Geneve control)────▶ relay server
//!   us ──disco Ping (Geneve, sealed to the PEER)─────────────▶ relay ──▶ peer
//!   us ◀─disco Pong (Geneve, sealed by the PEER)────────────── relay ◀── peer
//! ```
//!
//! Only after that pong does the relay `addr:port` become a usable path. Everything on the relay
//! leg is wrapped in a Geneve header ([`ts_packet::geneve`]) carrying the endpoint's VNI: the
//! three handshake messages with the control bit set (that is how the relay server knows to
//! terminate them rather than forward them), the relayed ping/pong and the WireGuard data without
//! it.
//!
//! Two framings, two trust levels — deliberately kept out of [`PeerPaths`][crate::PeerPaths]:
//! a relay `addr:port` is the *relay server's* address, not the peer's, so it must never become a
//! naked disco-ping target or a naked WireGuard destination. Mixing it into the direct candidate
//! set would do exactly that.

use core::{net::SocketAddr, time::Duration};
use std::{collections::HashMap, time::Instant};

use ts_keys::DiscoPublicKey;

use crate::{disco::TxId, path::TRUST_DURATION};

/// Maximum number of relay `addr:port`s accepted from one `CallMeMaybeVia`.
///
/// Anti-amplification, the relay-path analogue of
/// [`MAX_INBOUND_CALLMEMAYBE_ENDPOINTS`][crate::disco::MAX_INBOUND_CALLMEMAYBE_ENDPOINTS]: every
/// accepted address gets a bind message emitted from the real host socket, so an authenticated
/// peer that stuffed a `CallMeMaybeVia` with thousands of addresses could otherwise turn this node
/// into a host-sourced scanner. A real relay server advertises a handful of addresses (one per
/// address family per interface). Upstream applies no cap here, so this is deliberately stricter
/// than Go; the addresses beyond the cap are dropped, which at worst costs a relay path we would
/// have had.
pub(crate) const MAX_RELAY_ADDR_PORTS: usize = 8;

/// Maximum relayed disco pings outstanding on one relay endpoint at a time.
///
/// Mirrors Go's `limitPings` in `relayManager.handshakeServerEndpoint`: an inbound relayed ping
/// makes us send one back, so without a cap two peers could ping-amplify each other through the
/// relay. Go's comment — "inbound pings trigger outbound pings, so we want to be a little
/// defensive" — is the whole reason.
const MAX_RELAY_PINGS_IN_FLIGHT: usize = 10;

/// A relayed ping with no pong after this long is presumed lost and its record pruned, so the
/// in-flight map cannot grow for an endpoint that never answers. Matches the direct path's
/// equivalent bound.
const RELAY_PING_TIMEOUT: Duration = Duration::from_secs(5);

/// A relay endpoint a peer told us about (upstream `disco.UDPRelayEndpoint`, itself a mirror of
/// `net/udprelay/endpoint.ServerEndpoint`), in owned host-order form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayServerEndpoint {
    /// The relay server's disco key. The three bind-handshake messages are sealed to *this* key;
    /// the ping/pong that ride the same Geneve framing are sealed to the peer's.
    pub server_disco: DiscoPublicKey,
    /// The two client disco keys the relay server will accept on this endpoint. For a
    /// `CallMeMaybeVia` we act on, these must be exactly {our disco key, the sender's}.
    pub client_disco: [DiscoPublicKey; 2],
    /// The relay server's Lamport clock for this allocation. A later allocation for the same peer
    /// supersedes an earlier one; an equal-or-older one is ignored.
    pub lamport_id: u64,
    /// The Geneve Virtual Network Identifier that selects this endpoint on the relay server.
    pub vni: u32,
    /// How long the server keeps the endpoint while the handshake is still in progress.
    pub bind_lifetime: Duration,
    /// How long the server keeps the endpoint once bound and idle.
    pub steady_state_lifetime: Duration,
    /// The relay server's candidate addresses, already capped at `MAX_RELAY_ADDR_PORTS`.
    pub addr_ports: Vec<SocketAddr>,
}

impl RelayServerEndpoint {
    /// Read a wire [`UdpRelayEndpoint`][ts_disco_protocol::UdpRelayEndpoint] into owned form,
    /// keeping at most [`MAX_RELAY_ADDR_PORTS`] addresses.
    pub(crate) fn from_wire(wire: &ts_disco_protocol::UdpRelayEndpoint) -> Self {
        Self {
            server_disco: wire.server_disco,
            client_disco: wire.client_disco,
            lamport_id: wire.lamport_id(),
            vni: wire.vni(),
            bind_lifetime: wire.bind_lifetime(),
            steady_state_lifetime: wire.steady_state_lifetime(),
            addr_ports: wire
                .addr_ports
                .iter()
                .take(MAX_RELAY_ADDR_PORTS)
                .map(|e| e.socket_addr())
                .collect(),
        }
    }

    /// Whether this endpoint was allocated for exactly the pair (`us`, `peer`).
    ///
    /// Fail-closed identity check on an otherwise peer-supplied message: the relay server will
    /// only carry traffic for the two keys it was told about, so a `CallMeMaybeVia` naming any
    /// other pair is either a mistake or an attempt to make us handshake against an endpoint that
    /// is not ours. Order is not significant — the server does not assign the slots by role.
    pub(crate) fn is_for_pair(&self, us: &DiscoPublicKey, peer: &DiscoPublicKey) -> bool {
        let [a, b] = &self.client_disco;
        (a == us && b == peer) || (a == peer && b == us)
    }
}

/// How far through the 3-way bind handshake one relay endpoint has got.
///
/// Only the client-side states of Go's `disco.BindUDPRelayHandshakeState`; the server-side ones
/// (`ChallengeSent`, `AnswerReceived`) belong to a relay server, which this fork is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum HandshakeState {
    /// We sent [`BindUdpRelayEndpoint`][ts_disco_protocol::BindUdpRelayEndpoint] to every
    /// candidate address and are waiting for a challenge.
    BindSent,
    /// We answered a challenge and pinged the peer through the relay; waiting for the pong that
    /// makes the path usable.
    AnswerSent,
}

/// A relay `addr:port` a relayed pong has confirmed.
#[derive(Debug, Clone, Copy)]
struct ConfirmedRelay {
    addr: SocketAddr,
    latency: Duration,
    trust_until: Instant,
}

/// One peer's relay endpoint and the handshake/liveness state for it.
#[derive(Debug)]
pub(crate) struct RelayPath {
    /// The endpoint the peer advertised.
    pub(crate) endpoint: RelayServerEndpoint,
    /// The handshake generation we put in our bind message. Non-zero, per upstream ("clients must
    /// set a new, nonzero value at the start of every handshake").
    pub(crate) generation: u32,
    /// How far the handshake has got.
    pub(crate) state: HandshakeState,
    /// Relayed pings awaiting a pong: transaction id → (address sent to, when).
    in_flight: HashMap<TxId, (SocketAddr, Instant)>,
    /// The confirmed relay address, if a pong has come back and its trust has not lapsed.
    confirmed: Option<ConfirmedRelay>,
    /// The relay address we answered a challenge from, if we have. This is where a retry ping goes
    /// while the endpoint is handshook-but-unconfirmed: an endpoint may advertise several
    /// addresses, and only the one that challenged us is known to be live.
    answered_addr: Option<SocketAddr>,
}

impl RelayPath {
    /// Start tracking a freshly-advertised endpoint, in the `BindSent` state.
    pub(crate) fn new(endpoint: RelayServerEndpoint, generation: u32) -> Self {
        Self {
            endpoint,
            generation,
            state: HandshakeState::BindSent,
            in_flight: HashMap::new(),
            confirmed: None,
            answered_addr: None,
        }
    }

    /// Record that we answered a challenge from `addr` and are now waiting on the peer.
    pub(crate) fn note_answered(&mut self, addr: SocketAddr) {
        self.state = HandshakeState::AnswerSent;
        self.answered_addr = Some(addr);
    }

    /// Record a relayed ping we just sent, so its pong is recognized as solicited.
    ///
    /// Returns `false` (and records nothing) when [`MAX_RELAY_PINGS_IN_FLIGHT`] pings are already
    /// outstanding after pruning the timed-out ones — the caller must then not send. Dropping the
    /// *new* ping rather than evicting an old one is the fail-safe choice: it keeps a ping-storm
    /// bounded without invalidating a probe that may still be answered.
    pub(crate) fn note_ping_sent(&mut self, tx_id: TxId, to: SocketAddr, now: Instant) -> bool {
        self.in_flight
            .retain(|_, (_, sent)| now.duration_since(*sent) < RELAY_PING_TIMEOUT);
        if self.in_flight.len() >= MAX_RELAY_PINGS_IN_FLIGHT {
            return false;
        }
        self.in_flight.insert(tx_id, (to, now));
        true
    }

    /// Consume a relayed pong. Returns the round-trip latency when `tx_id` matched a ping we sent
    /// through this endpoint, and marks the relay address confirmed and trusted.
    ///
    /// The transaction id is single-use (removed on match), so a replayed pong confirms nothing.
    /// `from` — the relay server address the pong arrived from — is what gets confirmed, because
    /// that is the address we must send through; the peer's own address never appears here.
    pub(crate) fn note_pong(&mut self, tx_id: TxId, now: Instant) -> Option<Duration> {
        let (to, sent) = self.in_flight.remove(&tx_id)?;
        let latency = now.saturating_duration_since(sent);
        match self.confirmed {
            // A pong from a *different*, no-faster address of the same endpoint is a rival: it
            // neither takes over nor refreshes the address currently in use. (The direct path
            // holds the same rule — a rival pong must not extend the trust of the held best, or a
            // dead best would be kept alive by a live rival.)
            Some(c) if c.addr != to && latency >= c.latency => {}
            // Otherwise this address becomes (or stays) the one in use: the first to answer, a
            // faster rival, or the same address re-confirming and refreshing its trust.
            _ => {
                self.confirmed = Some(ConfirmedRelay {
                    addr: to,
                    latency,
                    trust_until: now + TRUST_DURATION,
                });
            }
        }
        Some(latency)
    }

    /// The confirmed relay address and VNI, if one is confirmed and still trusted.
    ///
    /// `None` once trust lapses, exactly like the direct path: the caller then keeps the peer on
    /// DERP rather than pushing data at a relay that may have dropped the binding.
    pub(crate) fn usable(&self, now: Instant) -> Option<(SocketAddr, u32)> {
        let c = self.confirmed?;
        (c.trust_until > now).then_some((c.addr, self.endpoint.vni))
    }

    /// The last measured relayed round-trip latency, if the path is confirmed.
    pub(crate) fn latency(&self) -> Option<Duration> {
        Some(self.confirmed?.latency)
    }

    /// Whether the path should be re-pinged now to keep (or regain) its trust.
    ///
    /// Unconfirmed-but-answered endpoints are re-pinged so a lost ping or pong does not strand the
    /// handshake; a confirmed one is re-pinged once it is within `refresh_lead` of expiry, on the
    /// same schedule as a direct best path.
    pub(crate) fn wants_ping(&self, now: Instant, refresh_lead: Duration) -> bool {
        match self.confirmed {
            Some(c) => c.trust_until.saturating_duration_since(now) <= refresh_lead,
            None => self.state == HandshakeState::AnswerSent,
        }
    }
}

/// Every peer's relay path, plus the reverse lookup the data path needs.
#[derive(Debug, Default)]
pub(crate) struct RelayPaths {
    by_peer: HashMap<DiscoPublicKey, RelayPath>,
    /// `(relay addr, VNI)` → peer, so an inbound Geneve-wrapped WireGuard datagram can be
    /// attributed without opening anything. Kept in lockstep with `by_peer`.
    by_addr_vni: HashMap<(SocketAddr, u32), DiscoPublicKey>,
}

impl RelayPaths {
    /// Install (or replace) a peer's relay path.
    ///
    /// Returns `false` without changing anything when `endpoint` does not supersede what we
    /// already have: upstream orders competing allocations for a peer pair by the relay server's
    /// Lamport id, and an older or equal id is a stale or duplicated announcement.
    pub(crate) fn insert(
        &mut self,
        peer: DiscoPublicKey,
        endpoint: RelayServerEndpoint,
        generation: u32,
    ) -> bool {
        if let Some(existing) = self.by_peer.get(&peer)
            && endpoint.lamport_id <= existing.endpoint.lamport_id
        {
            return false;
        }
        self.forget_addrs(&peer);
        self.by_peer
            .insert(peer, RelayPath::new(endpoint, generation));
        true
    }

    /// The peer whose relay handshake is with `server_disco` on `vni`, if any.
    ///
    /// A relay server's challenge names neither the peer nor us, so this pairing — the sender's
    /// disco key plus the cleartext Geneve VNI — is the only thing that binds a challenge to the
    /// handshake it belongs to. Matches Go's `handshakeWorkByServerDiscoVNI`.
    pub(crate) fn peer_for_server(
        &self,
        server_disco: &DiscoPublicKey,
        vni: u32,
    ) -> Option<DiscoPublicKey> {
        self.by_peer
            .iter()
            .find(|(_, path)| {
                path.endpoint.server_disco == *server_disco && path.endpoint.vni == vni
            })
            .map(|(peer, _)| *peer)
    }

    /// The peer a Geneve-wrapped datagram from `addr` on `vni` belongs to.
    pub(crate) fn peer_for_addr(&self, addr: SocketAddr, vni: u32) -> Option<DiscoPublicKey> {
        self.by_addr_vni.get(&(addr, vni)).copied()
    }

    /// Mutable access to a peer's relay path.
    pub(crate) fn get_mut(&mut self, peer: &DiscoPublicKey) -> Option<&mut RelayPath> {
        self.by_peer.get_mut(peer)
    }

    /// Read-only access to a peer's relay path.
    pub(crate) fn get(&self, peer: &DiscoPublicKey) -> Option<&RelayPath> {
        self.by_peer.get(peer)
    }

    /// Record that `addr`/`vni` now carries traffic for `peer`, so inbound datagrams from it can
    /// be attributed. Called once a relayed pong confirms the address.
    pub(crate) fn note_confirmed_addr(&mut self, peer: DiscoPublicKey, addr: SocketAddr, vni: u32) {
        self.by_addr_vni.insert((addr, vni), peer);
    }

    /// Drop a peer's relay path entirely (it left the netmap, or its endpoint was superseded).
    pub(crate) fn remove(&mut self, peer: &DiscoPublicKey) {
        self.forget_addrs(peer);
        self.by_peer.remove(peer);
    }

    /// Every peer that currently wants a relayed ping, with the address and VNI to ping through.
    pub(crate) fn wanting_ping(
        &self,
        now: Instant,
        refresh_lead: Duration,
    ) -> Vec<(DiscoPublicKey, SocketAddr, u32)> {
        self.by_peer
            .iter()
            .filter(|(_, path)| path.wants_ping(now, refresh_lead))
            .filter_map(|(peer, path)| {
                // Re-ping the confirmed address when there is one, else the address whose
                // challenge we answered — never a candidate we have heard nothing from.
                let addr = path.confirmed.map(|c| c.addr).or(path.answered_addr)?;
                Some((*peer, addr, path.endpoint.vni))
            })
            .collect()
    }

    /// Remove every `(addr, vni)` attribution belonging to `peer`.
    fn forget_addrs(&mut self, peer: &DiscoPublicKey) {
        self.by_addr_vni.retain(|_, owner| owner != peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> DiscoPublicKey {
        DiscoPublicKey::from([b; 32])
    }

    fn endpoint(lamport_id: u64, vni: u32, addr: &str) -> RelayServerEndpoint {
        RelayServerEndpoint {
            server_disco: key(9),
            client_disco: [key(1), key(2)],
            lamport_id,
            vni,
            bind_lifetime: Duration::from_secs(30),
            steady_state_lifetime: Duration::from_secs(300),
            addr_ports: vec![addr.parse().unwrap()],
        }
    }

    #[test]
    fn pair_check_accepts_either_slot_order_and_rejects_a_third_party() {
        let ep = endpoint(1, 7, "192.0.2.10:41641");
        assert!(ep.is_for_pair(&key(1), &key(2)));
        assert!(ep.is_for_pair(&key(2), &key(1)));
        assert!(
            !ep.is_for_pair(&key(1), &key(3)),
            "an endpoint allocated for someone else must be refused"
        );
    }

    #[test]
    fn a_newer_lamport_id_supersedes_and_an_older_one_is_ignored() {
        let mut paths = RelayPaths::default();
        assert!(paths.insert(key(2), endpoint(5, 7, "192.0.2.10:41641"), 1));
        assert!(
            !paths.insert(key(2), endpoint(5, 8, "192.0.2.11:41641"), 2),
            "an equal Lamport id does not supersede"
        );
        assert!(
            !paths.insert(key(2), endpoint(4, 9, "192.0.2.12:41641"), 3),
            "an older Lamport id does not supersede"
        );
        assert_eq!(paths.get(&key(2)).unwrap().endpoint.vni, 7);
        assert!(paths.insert(key(2), endpoint(6, 11, "192.0.2.13:41641"), 4));
        assert_eq!(paths.get(&key(2)).unwrap().endpoint.vni, 11);
    }

    #[test]
    fn a_pong_confirms_the_relay_address_and_trust_expires() {
        let now = Instant::now();
        let mut path = RelayPath::new(endpoint(1, 7, "192.0.2.10:41641"), 1);
        let relay: SocketAddr = "192.0.2.10:41641".parse().unwrap();
        assert_eq!(path.usable(now), None);

        assert!(path.note_ping_sent([1u8; 12], relay, now));
        assert!(
            path.note_pong([1u8; 12], now + Duration::from_millis(20))
                .is_some()
        );
        assert_eq!(
            path.usable(now + Duration::from_millis(20)),
            Some((relay, 7))
        );
        assert_eq!(
            path.usable(now + TRUST_DURATION + Duration::from_secs(1)),
            None,
            "an unrefreshed relay path must lapse back to DERP"
        );
    }

    #[test]
    fn a_faster_rival_takes_over_and_a_slower_one_does_not_refresh_the_incumbent() {
        let now = Instant::now();
        let mut path = RelayPath::new(endpoint(1, 7, "192.0.2.10:41641"), 1);
        let a: SocketAddr = "192.0.2.10:41641".parse().unwrap();
        let b: SocketAddr = "192.0.2.11:41641".parse().unwrap();

        // `a` confirms with a 100ms round trip.
        assert!(path.note_ping_sent([1u8; 12], a, now));
        path.note_pong([1u8; 12], now + Duration::from_millis(100));
        assert_eq!(path.usable(now + Duration::from_millis(100)), Some((a, 7)));

        // A slower rival neither takes over nor extends `a`'s trust window.
        let held = now + Duration::from_millis(100) + TRUST_DURATION;
        assert!(path.note_ping_sent([2u8; 12], b, now));
        path.note_pong([2u8; 12], now + Duration::from_millis(300));
        assert_eq!(path.usable(now + Duration::from_millis(300)), Some((a, 7)));
        assert_eq!(
            path.usable(held + Duration::from_millis(1)),
            None,
            "a rival pong must not keep the incumbent alive past its own trust"
        );

        // A faster rival does take over.
        let later = held + Duration::from_secs(1);
        assert!(path.note_ping_sent([3u8; 12], a, later));
        path.note_pong([3u8; 12], later + Duration::from_millis(100));
        assert!(path.note_ping_sent([4u8; 12], b, later));
        path.note_pong([4u8; 12], later + Duration::from_millis(10));
        assert_eq!(path.usable(later + Duration::from_millis(10)), Some((b, 7)));
    }

    #[test]
    fn an_unsolicited_pong_confirms_nothing() {
        let now = Instant::now();
        let mut path = RelayPath::new(endpoint(1, 7, "192.0.2.10:41641"), 1);
        assert!(path.note_pong([9u8; 12], now).is_none());
        assert_eq!(path.usable(now), None);
    }

    #[test]
    fn a_transaction_id_is_single_use() {
        let now = Instant::now();
        let mut path = RelayPath::new(endpoint(1, 7, "192.0.2.10:41641"), 1);
        let relay: SocketAddr = "192.0.2.10:41641".parse().unwrap();
        assert!(path.note_ping_sent([3u8; 12], relay, now));
        assert!(path.note_pong([3u8; 12], now).is_some());
        assert!(
            path.note_pong([3u8; 12], now).is_none(),
            "a replayed pong must not re-confirm"
        );
    }

    #[test]
    fn in_flight_pings_are_capped_and_pruned() {
        let now = Instant::now();
        let mut path = RelayPath::new(endpoint(1, 7, "192.0.2.10:41641"), 1);
        let relay: SocketAddr = "192.0.2.10:41641".parse().unwrap();
        for i in 0..MAX_RELAY_PINGS_IN_FLIGHT {
            assert!(path.note_ping_sent([i as u8; 12], relay, now));
        }
        assert!(
            !path.note_ping_sent([200u8; 12], relay, now),
            "the cap must refuse the next ping"
        );
        // Once the outstanding ones time out they are pruned and room reappears.
        let later = now + RELAY_PING_TIMEOUT + Duration::from_secs(1);
        assert!(path.note_ping_sent([201u8; 12], relay, later));
    }

    #[test]
    fn attribution_follows_the_peer_and_is_dropped_with_it() {
        let mut paths = RelayPaths::default();
        let relay: SocketAddr = "192.0.2.10:41641".parse().unwrap();
        paths.insert(key(2), endpoint(1, 7, "192.0.2.10:41641"), 1);
        paths.note_confirmed_addr(key(2), relay, 7);
        assert_eq!(paths.peer_for_addr(relay, 7), Some(key(2)));
        assert_eq!(
            paths.peer_for_addr(relay, 8),
            None,
            "the VNI is part of the key"
        );
        paths.remove(&key(2));
        assert_eq!(paths.peer_for_addr(relay, 7), None);
    }

    #[test]
    fn a_challenge_is_matched_by_server_key_and_vni() {
        let mut paths = RelayPaths::default();
        paths.insert(key(2), endpoint(1, 7, "192.0.2.10:41641"), 1);
        assert_eq!(paths.peer_for_server(&key(9), 7), Some(key(2)));
        assert_eq!(paths.peer_for_server(&key(9), 8), None);
        assert_eq!(paths.peer_for_server(&key(8), 7), None);
    }
}
