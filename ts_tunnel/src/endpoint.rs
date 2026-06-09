use core::time::Duration;
use std::{
    cmp::min,
    collections::{HashMap, VecDeque, vec_deque},
    time::Instant,
};

use itertools::Itertools;
use ts_keys::{NodeKeyPair, NodePublicKey};
use ts_packet::PacketMut;
use ts_time::{Handle, Scheduler, TimeRange};
use zerocopy::IntoBytes;

use crate::{
    config::{PeerConfig, PeerId},
    handshake::{Handshake, ReceivedHandshake, SessionPair, initiate_handshake},
    macs::{MACReceiver, MACSender},
    messages::{CookieReply, HandshakeResponse, Message, SessionId},
    session::{ReceiveSession, TransmitSession},
    time::{TAI64N, TAI64NClock},
};

const MAX_QUEUED_PER_PEER: usize = 32;

/// If an endpoint hasn't sent any packets to a peer for `KEEPALIVE_TIMEOUT` after receiving a
/// packet from that peer, it must send an empty keepalive message so that the peer can distinguish
/// lack of activity from loss of session.
/// See: WireGuard spec, section 6.5
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// A bounded packet queue that drops oldest packets when full.
#[derive(Default)]
struct Queue(VecDeque<PacketMut>);

impl Queue {
    /// Shorthand for Queue::default then Queue::append.
    fn new_with(packets: Vec<PacketMut>) -> Self {
        let mut queue = Self::default();
        queue.append(packets);
        queue
    }

    fn append(&mut self, packets: Vec<PacketMut>) {
        let new_packets = min(packets.len(), MAX_QUEUED_PER_PEER);
        let drop_incoming = packets.len() - new_packets;
        let keep_queued = MAX_QUEUED_PER_PEER - new_packets;
        let drop_queued = self.0.len().saturating_sub(keep_queued);
        self.0.drain(..drop_queued);
        packets
            .into_iter()
            .skip(drop_incoming)
            .for_each(|packet| self.0.push_back(packet));
    }
}

impl From<Queue> for Vec<PacketMut> {
    fn from(queue: Queue) -> Self {
        queue.0.into()
    }
}

impl IntoIterator for Queue {
    type Item = PacketMut;
    type IntoIter = vec_deque::IntoIter<PacketMut>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// State of a peer's session.
enum SessionState {
    /// No active session, packets may be queued for future transmission.
    None(Queue),
    /// Active session available.
    Active {
        recv: Box<ReceiveSession>,
        recv_prev: Option<Box<ReceiveSession>>,
        send: TransmitSession,
    },
}

impl SessionState {
    /// Take the session state, leaving SessionState::None in its place.
    fn take(&mut self) -> SessionState {
        std::mem::replace(self, SessionState::None(Queue::default()))
    }

    /// Activate the session using the provided send/receive sessions.
    ///
    /// Existing sessions are rotated appropriately. Returns encrypted packets to send to the
    /// peer, if any were queued.
    fn activate(&mut self, endpoint: &mut EndpointState, next: SessionPair) -> Vec<PacketMut> {
        tracing::trace!(recv_id = ?next.recv.id(), "activating new session");

        match self.take() {
            SessionState::None(queue) => {
                let mut ret = queue.into();
                next.send.encrypt(&mut ret);
                *self = SessionState::Active {
                    send: next.send,
                    recv: Box::new(next.recv),
                    recv_prev: None,
                };
                ret
            }
            SessionState::Active {
                recv,
                mut recv_prev,
                ..
            } => {
                recv_prev
                    .take()
                    .inspect(|recv_prev| endpoint.ids.remove_session(recv_prev.id()));
                *self = SessionState::Active {
                    send: next.send,
                    recv: Box::new(next.recv),
                    recv_prev: Some(recv),
                };
                vec![]
            }
        }
    }

    /// Deactivate the session, releasing any active session IDs.
    fn deactivate(&mut self, endpoint: &mut EndpointState) {
        if let SessionState::Active {
            recv,
            mut recv_prev,
            ..
        } = self.take()
        {
            endpoint.ids.remove_session(recv.id());
            recv_prev
                .as_mut()
                .inspect(|recv_prev| endpoint.ids.remove_session(recv_prev.id()));
        }
    }

    /// Encrypt a keepalive packet for transmission.
    ///
    /// Returns None if the session cannot currently transmit.
    fn encrypt_keepalive(&mut self) -> Option<PacketMut> {
        if let SessionState::Active { send, .. } = self
            && !send.expired(Instant::now())
        {
            let mut packet = vec![PacketMut::new(0)];
            send.encrypt(&mut packet);
            packet.pop()
        } else {
            None
        }
    }

    /// Encrypt packets for transmission.
    ///
    /// Returns the encrypted packets if a session is available, otherwise queues the packets and
    /// returns None to signal that the caller needs to establish a session.
    fn encrypt_or_queue(&mut self, mut packets: Vec<PacketMut>) -> Option<Vec<PacketMut>> {
        match self {
            SessionState::None(queue) => {
                queue.append(packets);
                None
            }
            SessionState::Active { send, .. } => {
                if send.expired(Instant::now()) {
                    // Note, this also deletes both receive sessions. This is okay: due to the
                    // semantics of session rotation, if the transmit session has expired, all
                    // receive sessions have also expired.
                    *self = SessionState::None(Queue::new_with(packets));
                    return None;
                }
                send.encrypt(&mut packets);
                Some(packets)
            }
        }
    }

    /// Get the receive session matching the given ID, if any.
    fn get_recv(&mut self, id: SessionId) -> Option<&mut ReceiveSession> {
        match self {
            SessionState::None(_) => None,
            SessionState::Active {
                recv, recv_prev, ..
            } => {
                if recv.id() == id && !recv.expired(Instant::now()) {
                    Some(recv)
                } else if let Some(recv_prev) = recv_prev.as_mut()
                    && recv_prev.id() == id
                    && !recv.expired(Instant::now())
                {
                    Some(recv_prev)
                } else {
                    None
                }
            }
        }
    }

    /// Report whether the transmit side of the session is stale and in need of key rotation.
    ///
    /// Returns true if no session exists.
    fn needs_rotation(&self) -> bool {
        match self {
            SessionState::None(_) => true,
            SessionState::Active { send, .. } => send.stale(Instant::now()),
        }
    }
}

/// Tracks and allocates session IDs for peer sessions.
#[derive(Default)]
struct IdMap {
    sessions: HashMap<SessionId, PeerId>,
    // TODO: track recently abandoned session IDs, avoid reusing them for
    // one or two session lifetimes to avoid confusion with reordered packets.
    node_keys: HashMap<NodePublicKey, PeerId>,
}

impl IdMap {
    /// Return the peer handle for a node public key, if any.
    fn get_by_nodekey(&self, key: &NodePublicKey) -> Option<PeerId> {
        self.node_keys.get(key).copied()
    }

    /// Return the peer handle for a session, if any.
    fn get_by_session_id(&self, key: &SessionId) -> Option<&PeerId> {
        self.sessions.get(key)
    }

    /// Add a peer handle for communicating with the given peer pubkey.
    ///
    /// Returns `false` if a peer already exists for the key.
    fn add_peer(&mut self, id: PeerId, key: &NodePublicKey) -> bool {
        if self.node_keys.contains_key(key) {
            return false;
        }

        self.node_keys.insert(*key, id);
        true
    }

    /// Allocate a new session ID for communication with the given peer.
    ///
    /// Note that due to key rotation, a peer can have multiple session IDs in use at once.
    fn allocate_session(&mut self, peer: PeerId) -> SessionId {
        loop {
            let ret = SessionId::random();
            if let std::collections::hash_map::Entry::Vacant(e) = self.sessions.entry(ret) {
                e.insert(peer);
                return ret;
            }
        }
    }

    /// Abandon the given session ID.
    ///
    /// Panics if the session ID isn't currently in use.
    fn remove_session(&mut self, id: SessionId) {
        self.sessions.remove(&id).unwrap();
    }

    fn remove_handshake_session(&mut self, handshake: &Handshake) {
        if let Some(id) = handshake.session_id() {
            self.remove_session(id);
        }
    }

    /// Delete the peer handle for the given key.
    ///
    /// Panics if there is no peer currently using that key.
    fn remove_peer(&mut self, key: &NodePublicKey) {
        self.node_keys.remove(key).unwrap();
    }
}

struct Peer {
    id: PeerId,
    config: PeerConfig,
    session: SessionState,
    handshake: Handshake,
    last_seen_timestamp: Option<TAI64N>,
    cookie_sender: MACSender,
    keepalive: Option<Handle<Event>>,
    send_another_keepalive: bool,
    /// Pending persistent-keepalive timer, if a persistent keepalive is configured and a session is
    /// (or was) active. Distinct from `keepalive` (the reactive WireGuard §6.5 keepalive): this one
    /// re-arms unconditionally and fires on a totally idle tunnel. See
    /// [`PeerConfig::persistent_keepalive_interval`].
    persistent_keepalive: Option<Handle<Event>>,
}

impl Peer {
    fn new(id: PeerId, config: PeerConfig) -> Self {
        let macs = MACSender::new(&config.key);
        Self {
            id,
            config,
            session: SessionState::None(Queue::default()),
            handshake: Handshake::None,
            last_seen_timestamp: None,
            cookie_sender: macs,
            keepalive: None,
            send_another_keepalive: false,
            persistent_keepalive: None,
        }
    }

    fn schedule_keepalive(&mut self, scheduler: &mut Scheduler<Event>) {
        if self.keepalive.is_some() {
            self.send_another_keepalive = true;
            return;
        }
        let tr = TimeRange::new_around(Instant::now() + KEEPALIVE_TIMEOUT, Duration::from_secs(1));
        self.keepalive = Some(scheduler.add(tr, Event::MaybeSendKeepalive(self.id)));
    }

    /// (Re)arm the persistent-keepalive timer for this peer's configured interval, cancelling any
    /// previously-scheduled persistent keepalive.
    ///
    /// Called both when a session becomes active and after every *outgoing authenticated* packet, so
    /// the timer always measures the time since the last outbound traffic — a persistent keepalive
    /// only fires once the tunnel has been silent (outbound) for a full interval. No-op when the peer
    /// has no persistent keepalive configured. Note this is independent of the reactive `keepalive`
    /// timer (WireGuard §6.5), which is armed only by *inbound* traffic.
    fn arm_persistent_keepalive(&mut self, scheduler: &mut Scheduler<Event>) {
        // `effective_persistent_keepalive` normalizes a `Some(ZERO)` / sub-minimum interval to
        // `None` (WireGuard treats `PersistentKeepalive = 0` as "off"; a near-zero interval would
        // otherwise re-arm every tick — a send-flood). Reading it here is the single chokepoint that
        // arms the timer, so the guard applies everywhere the keepalive is (re)armed.
        let Some(interval) = self.config.effective_persistent_keepalive() else {
            return;
        };
        // Fire *at* the interval, never after it. The scheduler dispatches at the END of a
        // `TimeRange`, so the window must end at `now + interval`; we give it a small lead so a
        // batched dispatch can coalesce nearby peers' keepalives without ever pushing a keepalive
        // *past* the interval. Pushing it later would risk the NAT/relay mapping (≈30s UDP timeout,
        // which the 25s default sits under) expiring before the refresh — so, unlike the one-shot
        // reactive keepalive (WireGuard §6.5, which jitters ±1s around its deadline), a recurring
        // persistent keepalive must not jitter upward. Each peer's timer is anchored to its own
        // last-send instant, so peers are naturally desynchronized without added jitter.
        let now = Instant::now();
        let deadline = now + interval;
        // Lead = min(1s, interval/4), clamped so the window start never precedes `now`.
        let lead = Duration::from_secs(1).min(interval / 4);
        let tr = TimeRange::new(deadline.checked_sub(lead).unwrap_or(now).max(now), deadline);
        let handle = scheduler.add(tr, Event::PersistentKeepalive(self.id));
        if let Some(prev) = self.persistent_keepalive.replace(handle) {
            prev.cancel();
        }
    }

    // TODO: consider replacing outparam with plain SendResult that supports merging.
    fn send(
        &mut self,
        endpoint: &mut EndpointState,
        packets: Vec<PacketMut>,
        out: &mut SendResult,
    ) {
        if let Some(mut packets) = self.session.encrypt_or_queue(packets) {
            tracing::trace!("enqueueing packets to peer");
            // Outgoing authenticated traffic resets the persistent-keepalive timer: we only need to
            // emit a persistent keepalive once the tunnel has gone silent for a full interval.
            if !packets.is_empty() {
                self.arm_persistent_keepalive(&mut endpoint.scheduler);
            }
            out.queue_to_peer(self.id).append(&mut packets);
            // Fall through to check if the session is in need of rotation.
        }

        if self.handshake.is_active() {
            tracing::trace!("handshake is already in-flight, bail");
            return;
        }

        if !self.session.needs_rotation() {
            tracing::trace!("session does not need rotation");
            return;
        }

        self.start_handshake(endpoint, out);
    }

    #[tracing::instrument(skip_all, fields(?session_id, n_packets = packets.len()))]
    fn recv(
        &mut self,
        endpoint: &mut EndpointState,
        session_id: SessionId,
        mut packets: Vec<PacketMut>,
        out: &mut RecvResult,
    ) {
        let pre_len = packets.len();

        packets.retain_mut(|packet| match Message::try_from(packet.as_ref()) {
            Err(()) => {
                tracing::trace!("dropping invalid packet");
                false
            }
            Ok(Message::TransportDataHeader(_)) => true,
            Ok(Message::HandshakeResponse(resp)) => {
                self.recv_handshake_response(endpoint, resp, out);
                false
            }
            Ok(Message::CookieReply(resp)) => {
                self.recv_cookie_reply(resp);
                false
            }
            Ok(Message::HandshakeInitiation(_)) => {
                debug_assert!(
                    false,
                    "handshake initiations should have been filtered out prior to calling recv"
                );
                tracing::warn!("unexpected handshake init in recv");
                false
            }
        });

        let post_len = packets.len();
        if post_len != pre_len {
            tracing::trace!(n_dropped = pre_len - post_len, "dropped packets");
        }

        self.recv_transport_data(endpoint, session_id, packets, out);
    }

    fn recv_cookie_reply(&mut self, packet: &CookieReply) {
        let Handshake::Initiated(_, _, handshake_mac1) = &mut self.handshake else {
            tracing::trace!("dropping cookie reply received outside of handshake");
            return;
        };
        self.cookie_sender.receive_cookie(packet, handshake_mac1);
    }

    fn recv_handshake_response(
        &mut self,
        endpoint: &mut EndpointState,
        packet: &HandshakeResponse,
        out: &mut RecvResult,
    ) {
        let Some(session) = self.handshake.finish(
            packet,
            &self.config.psk,
            &endpoint.my_cookie,
            Instant::now(),
        ) else {
            tracing::error!("handshake failed to complete");
            return;
        };

        let mut packets = self.session.activate(endpoint, session);
        if packets.is_empty() {
            // Upon completing a handshake, the initiator must send at least one packet to confirm
            // the session. Usually that can be a queued packet, but if we happen to complete a
            // handshake with no queued packets available, we have to send an empty packet explicitly.
            packets.push(PacketMut::new(0));
            // Session was just activated, therefore it can encrypt.
            packets = self.session.encrypt_or_queue(packets).unwrap();
        }
        // A fresh send session is live: start the persistent-keepalive clock so an idle tunnel keeps
        // the path warm. The confirmation packet just emitted counts as the most recent outbound
        // traffic, so the first persistent keepalive is a full interval away.
        self.arm_persistent_keepalive(&mut endpoint.scheduler);
        out.queue_to_peer(self.id).append(&mut packets);
    }

    fn recv_transport_data(
        &mut self,
        endpoint: &mut EndpointState,
        session_id: SessionId,
        mut packets: Vec<PacketMut>,
        out: &mut RecvResult,
    ) {
        if let Some(session) = self.session.get_recv(session_id) {
            packets = session.decrypt(packets);
            if !packets.is_empty() {
                out.queue_to_local(self.id).append(&mut packets);
                self.schedule_keepalive(&mut endpoint.scheduler);
            }
            return;
        }

        let Some((session, mut packets)) = self.handshake.confirm(session_id, packets) else {
            // TODO: log
            return;
        };

        out.queue_to_local(self.id).append(&mut packets);
        self.schedule_keepalive(&mut endpoint.scheduler);

        let mut packets_for_peer = self.session.activate(endpoint, session);
        // A fresh send session is live (responder side): start the persistent-keepalive clock.
        self.arm_persistent_keepalive(&mut endpoint.scheduler);
        if !packets_for_peer.is_empty() {
            out.queue_to_peer(self.id).append(&mut packets_for_peer);
        }
    }

    fn respond_to_handshake(
        &mut self,
        endpoint: &mut EndpointState,
        handshake: ReceivedHandshake,
        out: &mut RecvResult,
    ) {
        if let Some(timestamp) = self.last_seen_timestamp
            && handshake.timestamp < timestamp
        {
            // Replayed handshake initiation
            // TODO: because we buffer the raw initiation packet on the sender side, we need to accept
            // initiations with an equal timestamp to the last one received. Check against reference
            // implementations and see if we should instead regenerate a fresh handshake with new timestamp
            // on retransmit.
            tracing::warn!("handshake replay detected, bailing out");
            return;
        }
        self.last_seen_timestamp = Some(handshake.timestamp);

        let session_id = endpoint.ids.allocate_session(self.id);

        let packet = self.handshake.respond(
            session_id,
            handshake,
            &self.config.psk,
            &self.cookie_sender,
            Instant::now(),
        );
        out.queue_to_peer(self.id).push(packet);
    }

    fn handshake_timeout(&mut self, endpoint: &mut EndpointState, out: &mut EventResult) {
        if !self.handshake.is_active() {
            // Handshake completed prior to timeout firing.
            return;
        }

        endpoint.ids.remove_handshake_session(&self.handshake);
        self.handshake = Handshake::None;

        self.start_handshake(endpoint, out);
    }

    fn send_keepalive(&mut self, scheduler: &mut Scheduler<Event>, out: &mut EventResult) {
        let Some(packet) = self.session.encrypt_keepalive() else {
            tracing::trace!("send keepalive: session expired, skipping");
            return;
        };
        out.queue_to_peer(self.id).push(packet);

        self.keepalive = None;

        if self.send_another_keepalive {
            self.schedule_keepalive(scheduler);
            self.send_another_keepalive = false;
        }
    }

    /// Fire a *persistent* keepalive: emit one empty authenticated packet and unconditionally re-arm
    /// the timer for the next interval.
    ///
    /// This is the load-bearing difference from [`send_keepalive`](Self::send_keepalive) (the
    /// reactive WireGuard §6.5 keepalive, which only re-arms when more inbound traffic arrived): a
    /// persistent keepalive keeps firing on a fully idle tunnel, so the NAT/relay path stays warm and
    /// the session timers keep ticking.
    ///
    /// The emitted packet is empty, so it does **not** advance the send session's rotation/expiry
    /// timers (those are keyed on session age from the handshake) — a genuinely dead peer is still
    /// detected and rekey still fires. If the session has expired or gone away, we do **not** re-arm:
    /// `encrypt_keepalive` returns `None`, the timer lapses, and the peer falls back to handshake on
    /// the next outbound packet (rather than busy-looping keepalives on a dead session).
    fn send_persistent_keepalive(
        &mut self,
        scheduler: &mut Scheduler<Event>,
        out: &mut EventResult,
    ) {
        // This timer has fired; drop the stale handle before deciding whether to re-arm.
        self.persistent_keepalive = None;

        let Some(packet) = self.session.encrypt_keepalive() else {
            tracing::trace!("persistent keepalive: no usable session, not re-arming");
            return;
        };
        out.queue_to_peer(self.id).push(packet);

        // Re-arm unconditionally for the next interval — this is what keeps an idle tunnel alive.
        self.arm_persistent_keepalive(scheduler);
    }

    fn shutdown(&mut self, endpoint: &mut EndpointState) {
        self.session.deactivate(endpoint);

        endpoint.ids.remove_handshake_session(&self.handshake);
        self.handshake = Handshake::None;

        // Stop keeping a removed peer's path warm.
        if let Some(handle) = self.persistent_keepalive.take() {
            handle.cancel();
        }
    }

    /// (Soft) precondition: `self.handshake == HandshakeState::None` (previous handshake is lost, but
    /// that shouldn't cause anything terrible to happen).
    fn start_handshake(&mut self, endpoint: &mut EndpointState, out: &mut impl QueueToPeer) {
        // TODO most of this logic might be better in the `handshake` module.
        let session_id = endpoint.ids.allocate_session(self.id);
        let (handshake, packet) = initiate_handshake(
            endpoint.my_key.private,
            self.config.key,
            session_id,
            endpoint.timestamps.now(),
        );

        let mut packet = PacketMut::from(packet.as_bytes());
        let mac = self.cookie_sender.write_macs(packet.as_mut());

        tracing::debug!(peer_id = ?self.id, ?session_id, "enqueue handshake start");

        out.queue_to_peer(self.id).push(packet);
        let tr = TimeRange::new_around(
            Instant::now() + HANDSHAKE_TIMEOUT,
            Duration::from_millis(500),
        );

        let timeout = endpoint.scheduler.add(tr, Event::HandshakeTimeout(self.id));
        self.handshake = Handshake::Initiated(handshake, timeout, mac);
    }
}

/// A WireGuard endpoint capable of communicating with multiple remote peers.
pub struct Endpoint {
    state: EndpointState,
    peers: HashMap<PeerId, Peer>,
}

struct EndpointState {
    my_key: NodeKeyPair,

    my_cookie: MACReceiver,
    ids: IdMap,
    timestamps: TAI64NClock,
    scheduler: Scheduler<Event>,
}

impl Endpoint {
    /// Construct a new endpoint with the given keypair.
    pub fn new(my_key: NodeKeyPair) -> Self {
        Self {
            state: EndpointState {
                my_key,
                my_cookie: MACReceiver::new(&my_key.public),
                ids: Default::default(),
                timestamps: Default::default(),
                scheduler: Default::default(),
            },
            peers: HashMap::new(),
        }
    }

    /// Insert a peer if it doesn't exist, otherwise update the peer with the given `id`
    /// with the given config.
    ///
    /// Returns the old [`PeerConfig`] if there was one.
    ///
    /// # Panics
    ///
    /// If the [`NodePublicKey`] in the new [`PeerConfig`] collides with an existing key
    /// for a different [`PeerId`].
    pub fn upsert_peer(&mut self, id: PeerId, mut cfg: PeerConfig) -> Option<PeerConfig> {
        match self.peers.get_mut(&id) {
            Some(peer) => {
                if peer.config.key != cfg.key {
                    self.state.ids.remove_peer(&peer.config.key);
                    self.state.ids.add_peer(id, &cfg.key);
                }

                // Capture the OLD effective interval BEFORE swapping in the new config.
                let prev_interval = peer.config.effective_persistent_keepalive();
                core::mem::swap(&mut peer.config, &mut cfg);

                // Reconcile the persistent-keepalive timer if the *effective* interval changed (so a
                // `None` ↔ `Some(ZERO)` flip is correctly a no-op — both normalize to "off" — and a
                // zero/sub-minimum value cancels rather than arms). Only (re)arm when a session is
                // actually live; otherwise the timer is armed at the next session activation.
                let new_interval = peer.config.effective_persistent_keepalive();
                if new_interval != prev_interval {
                    match new_interval {
                        Some(_) if !matches!(peer.session, SessionState::None(_)) => {
                            peer.arm_persistent_keepalive(&mut self.state.scheduler);
                        }
                        _ => {
                            if let Some(handle) = peer.persistent_keepalive.take() {
                                handle.cancel();
                            }
                        }
                    }
                }

                Some(cfg)
            }
            None => {
                if !self.state.ids.add_peer(id, &cfg.key) {
                    panic!("nodekey collision");
                }

                self.peers.insert(id, Peer::new(id, cfg));
                None
            }
        }
    }

    /// Remove the given peer.
    ///
    /// Returns whether the peer in question existed.
    pub fn remove_peer(&mut self, peer: PeerId) -> bool {
        match self.peers.remove(&peer) {
            None => false,
            Some(mut peer) => {
                peer.shutdown(&mut self.state);
                self.state.ids.remove_peer(&peer.config.key);
                true
            }
        }
    }

    /// Send packets to peers.
    pub fn send(
        &mut self,
        packets: impl IntoIterator<Item = (PeerId, Vec<PacketMut>)>,
    ) -> SendResult {
        let mut ret = SendResult::default();
        for (peer_id, packets) in packets {
            let Some(peer) = self.peers.get_mut(&peer_id) else {
                tracing::warn!(?peer_id, "no peer stored for id");
                continue;
            };

            tracing::debug!(
                ?peer_id,
                n_packets = packets.len(),
                "processing send packets"
            );

            peer.send(&mut self.state, packets, &mut ret);
        }
        ret
    }

    /// Receive packets from peers.
    pub fn recv(&mut self, packets: impl IntoIterator<Item = PacketMut>) -> RecvResult {
        let mut ret = RecvResult::default();

        let mut packets = packets.into_iter().into_group_map_by(|packet| {
            u32::from(
                Message::try_from(packet.as_ref())
                    .ok()
                    .and_then(|message| message.receiver_id())
                    .unwrap_or_default(),
            )
        });

        let handshakes = packets.remove(&0).unwrap_or_default();
        if !handshakes.is_empty() {
            tracing::trace!(n = handshakes.len(), "processing handshakes");
        }

        for packet in handshakes {
            self.process_one_handshake(packet, &mut ret);
        }

        tracing::trace!(n = packets.len(), "processing packets");

        for (session_id, packets) in packets {
            let session_id = session_id.into();

            let Some(peer_id) = self.state.ids.get_by_session_id(&session_id) else {
                tracing::warn!(?session_id, "session not found");
                continue;
            };
            let Some(peer) = self.peers.get_mut(peer_id) else {
                tracing::warn!(?peer_id, "no peer found");
                continue;
            };

            peer.recv(&mut self.state, session_id, packets, &mut ret);
        }

        ret
    }

    fn process_one_handshake(&mut self, packet: PacketMut, out: &mut RecvResult) {
        let Ok(Message::HandshakeInitiation(init)) = Message::try_from(packet.as_ref()) else {
            tracing::error!("message parsing failed");
            return;
        };
        let Some(handshake) =
            ReceivedHandshake::new(init, &self.state.my_key, &self.state.my_cookie)
        else {
            tracing::error!("parsing received handshake failed");
            return;
        };

        let Some(peer_id) = self.state.ids.get_by_nodekey(&handshake.peer_static()) else {
            tracing::error!(peer_key = %handshake.peer_static(), "no peer id stored for peer's key");
            return;
        };
        let Some(peer) = self.peers.get_mut(&peer_id) else {
            tracing::error!(?peer_id, "no peer entry for peer id");
            return;
        };

        peer.respond_to_handshake(&mut self.state, handshake, out)
    }

    /// Dispatch time-based events that are due to occur at or before the given instant.
    ///
    /// Use [`Endpoint::next_event`] to know when to call dispatch_events. It is inefficient but
    /// harmless to call it more frequently than specified by [`Endpoint::next_event`].
    pub fn dispatch_events(&mut self, now: Instant) -> EventResult {
        let mut out = EventResult::default();
        for event in self.state.scheduler.dispatch(now) {
            match event {
                Event::HandshakeTimeout(peer_id) => {
                    let Some(peer) = self.peers.get_mut(&peer_id) else {
                        continue;
                    };
                    peer.handshake_timeout(&mut self.state, &mut out);
                }
                Event::MaybeSendKeepalive(peer_id) => {
                    let Some(peer) = self.peers.get_mut(&peer_id) else {
                        continue;
                    };
                    peer.send_keepalive(&mut self.state.scheduler, &mut out);
                }
                Event::PersistentKeepalive(peer_id) => {
                    let Some(peer) = self.peers.get_mut(&peer_id) else {
                        continue;
                    };
                    peer.send_persistent_keepalive(&mut self.state.scheduler, &mut out);
                }
            }
        }
        out
    }

    /// Returns the next time range in which [`Endpoint::dispatch_events`] should next be called to
    /// dispatch events.
    ///
    /// [`Endpoint::dispatch_events`] should be called at some point in the returned [`TimeRange`]
    /// to keep the wireguard state machine functioning correctly.
    ///
    /// See [`Scheduler::next_dispatch_range`] for additional details.
    pub fn next_event(&self) -> Option<TimeRange> {
        self.state.scheduler.next_dispatch_range()
    }

    /// Return the node key for the selected peer.
    pub fn peer_key(&self, id: PeerId) -> Option<NodePublicKey> {
        let peer = self.peers.get(&id)?;
        Some(peer.config.key)
    }

    /// Return the peer id that has the selected node key.
    pub fn peer_id(&self, key: NodePublicKey) -> Option<PeerId> {
        self.state.ids.get_by_nodekey(&key)
    }
}

trait QueueToPeer {
    fn queue_to_peer(&mut self, peer: PeerId) -> &mut Vec<PacketMut>;
}

/// The outcome of attempting to send packets to peers.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct SendResult {
    /// Packets to be sent to remote peers.
    pub to_peers: HashMap<PeerId, Vec<PacketMut>>,
}

impl QueueToPeer for SendResult {
    fn queue_to_peer(&mut self, peer: PeerId) -> &mut Vec<PacketMut> {
        self.to_peers.entry(peer).or_default()
    }
}

/// The outcome of processing received packets.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct RecvResult {
    /// Valid packets from peers to be delivered locally.
    pub to_local: HashMap<PeerId, Vec<PacketMut>>,
    /// Packets to be sent to remote peers.
    pub to_peers: HashMap<PeerId, Vec<PacketMut>>,
}

impl RecvResult {
    fn queue_to_local(&mut self, peer: PeerId) -> &mut Vec<PacketMut> {
        self.to_local.entry(peer).or_default()
    }
}

impl QueueToPeer for RecvResult {
    fn queue_to_peer(&mut self, peer: PeerId) -> &mut Vec<PacketMut> {
        self.to_peers.entry(peer).or_default()
    }
}

/// The outcome of processing an Event.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct EventResult {
    /// Packets to be sent to remote peers.
    pub to_peers: HashMap<PeerId, Vec<PacketMut>>,
}

impl QueueToPeer for EventResult {
    fn queue_to_peer(&mut self, peer: PeerId) -> &mut Vec<PacketMut> {
        self.to_peers.entry(peer).or_default()
    }
}

/// An event that Endpoint needs to know about.
#[derive(Debug, Eq, PartialEq, PartialOrd, Ord, Copy, Clone)]
pub enum Event {
    /// Didn't receive a response to a handshake initiation.
    HandshakeTimeout(PeerId),
    /// Send a keepalive packet, if there was no recent outgoing traffic.
    MaybeSendKeepalive(PeerId),
    /// Send a *persistent* keepalive and unconditionally re-arm: keeps a fully-idle tunnel's
    /// NAT/relay path warm (WireGuard `PersistentKeepalive`).
    PersistentKeepalive(PeerId),
}

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PeerConfig;

    #[test]
    fn test_one_peer() {
        let (a_static, b_static) = (NodeKeyPair::new(), NodeKeyPair::new());
        let psk = rand::random();

        let (mut a_ep, mut b_ep) = (Endpoint::new(a_static), Endpoint::new(b_static));

        let a_peer = PeerId(1);
        let b_peer = PeerId(1);

        assert!(
            a_ep.upsert_peer(
                a_peer,
                PeerConfig {
                    key: b_static.public,
                    psk,
                    persistent_keepalive_interval: None,
                },
            )
            .is_none()
        );

        assert!(
            b_ep.upsert_peer(
                b_peer,
                PeerConfig {
                    key: a_static.public,
                    psk,
                    persistent_keepalive_interval: None,
                },
            )
            .is_none()
        );

        let a_to_b_packets = [
            PacketMut::from(vec![1, 2, 3, 4]),
            PacketMut::from(vec![5, 6, 7, 8]),
        ];

        // A sends to B. Results in a handshake initiation being transmitted, not the
        // requested packet (which gets buffered internally by the endpoint).
        let to_send = HashMap::from([(a_peer, Vec::from([a_to_b_packets[0].clone()]))]);
        let a_acts = a_ep.send(to_send);
        assert_eq!(
            a_acts.to_peers.len(),
            1,
            "communicating with unexpected number of peers"
        );
        let packets = a_acts
            .to_peers
            .get(&a_peer)
            .expect("should have packets for A's peer");
        assert_eq!(packets.len(), 1, "unexpected number of packets for peer");

        // A sends another packet. No further activity, but pkt2 gets queued as well.
        let to_send = HashMap::from([(a_peer, Vec::from([a_to_b_packets[1].clone()]))]);
        let a_acts2 = a_ep.send(to_send);
        assert_eq!(a_acts2, SendResult::default());

        // B processes the handshake and responds. No packets delivered to B.
        let b_acts = b_ep.recv(packets.clone());
        assert_eq!(b_acts.to_local.len(), 0, "unexpected received message");
        assert_eq!(
            b_acts.to_peers.len(),
            1,
            "unexpected number of sent messages"
        );
        let packets = b_acts
            .to_peers
            .get(&b_peer)
            .expect("should have packets for B's peer");
        assert_eq!(packets.len(), 1, "unexpected packet count for B's peer");

        // A processes the response, and sends the two queued packets.
        let a_acts3 = a_ep.recv(packets.clone());
        assert_eq!(a_acts3.to_local.len(), 0, "unexpected received message");
        assert_eq!(
            a_acts3.to_peers.len(),
            1,
            "unexpected number of sent messages"
        );
        let packets = a_acts3
            .to_peers
            .get(&a_peer)
            .expect("should have packets for A's peer");
        assert_eq!(packets.len(), 2, "wrong number of packets for A's peer");

        // B receives transport messages.
        let b_acts = b_ep.recv(packets.clone());
        assert_eq!(b_acts.to_local.len(), 1, "didn't receive message");
        let packets = b_acts
            .to_local
            .get(&b_peer)
            .expect("should have packets from B's peer");
        assert_eq!(packets, &a_to_b_packets, "wrong packets received from A",);
        assert_eq!(b_acts.to_peers.len(), 0, "unexpected sent message");

        // B sends transport message
        let b_to_a_packet = PacketMut::from(vec![9, 10, 11, 12]);
        let to_send = HashMap::from([(b_peer, vec![b_to_a_packet.clone()])]);
        let b_acts = b_ep.send(to_send);
        assert_eq!(
            b_acts.to_peers.len(),
            1,
            "unexpected number of sent messages"
        );
        let packets = b_acts
            .to_peers
            .get(&b_peer)
            .expect("should have packets for B's peer");
        assert_eq!(packets.len(), 1, "unexpected packet count for B's peer");

        // A receives
        let a_acts = a_ep.recv(packets.clone());
        assert_eq!(a_acts.to_local.len(), 1, "didn't receive message");
        let packets = a_acts
            .to_local
            .get(&a_peer)
            .expect("should have packets from A's peer");
        assert_eq!(
            packets,
            &[b_to_a_packet],
            "wrong packets received from A's peer"
        );
        assert_eq!(a_acts.to_peers.len(), 0, "unexpected sent message");
    }

    /// Establish a live session A→B by driving a full handshake, returning the two endpoints with A
    /// holding an active send session. `a_keepalive` is the persistent-keepalive interval configured
    /// on A's peer (B's is always `None`). A single data packet (`payload`) is sent through to prime
    /// the session. On return, A's persistent-keepalive timer (if configured) has just been armed.
    fn establish_session(
        a_keepalive: Option<Duration>,
        payload: &[u8],
    ) -> (Endpoint, Endpoint, PeerId, PeerId) {
        let (a_static, b_static) = (NodeKeyPair::new(), NodeKeyPair::new());
        let psk = rand::random();
        let (mut a_ep, mut b_ep) = (Endpoint::new(a_static), Endpoint::new(b_static));
        let (a_peer, b_peer) = (PeerId(1), PeerId(1));

        a_ep.upsert_peer(
            a_peer,
            PeerConfig {
                key: b_static.public,
                psk,
                persistent_keepalive_interval: a_keepalive,
            },
        );
        b_ep.upsert_peer(
            b_peer,
            PeerConfig {
                key: a_static.public,
                psk,
                persistent_keepalive_interval: None,
            },
        );

        // A sends -> handshake init.
        let init = a_ep.send(HashMap::from([(a_peer, vec![PacketMut::from(payload)])]));
        let init = init.to_peers.get(&a_peer).expect("handshake init").clone();
        // B responds.
        let resp = b_ep.recv(init);
        let resp = resp.to_peers.get(&b_peer).expect("handshake resp").clone();
        // A completes the handshake (this arms A's persistent keepalive) and sends the queued data.
        let data = a_ep.recv(resp);
        let data = data.to_peers.get(&a_peer).expect("data to peer").clone();
        // B confirms by receiving the first transport packet (delivers `payload` locally).
        let delivered = b_ep.recv(data);
        assert_eq!(
            delivered.to_local.get(&b_peer).map(|p| p.as_slice()),
            Some([PacketMut::from(payload)].as_slice()),
            "payload should be delivered to B after handshake"
        );

        (a_ep, b_ep, a_peer, b_peer)
    }

    /// The persistent keepalive fires on a fully idle tunnel and **re-arms unconditionally** — the
    /// load-bearing fix. After the configured interval of outbound silence, an idle endpoint emits
    /// exactly one empty keepalive to the peer; after another interval it emits another, with no
    /// inbound traffic in between (contrast the reactive §6.5 keepalive, which only re-arms on
    /// inbound traffic). This is what holds an idle DERP-relayed path warm.
    #[test]
    fn persistent_keepalive_fires_on_idle_and_rearms() {
        let interval = Duration::from_millis(100);
        let (mut a_ep, _b_ep, a_peer, _b_peer) = establish_session(Some(interval), b"hello");

        // A timer is now scheduled (the dataplane would wake on it instead of blocking forever).
        assert!(
            a_ep.next_event().is_some(),
            "an idle endpoint with persistent keepalive must schedule a wakeup"
        );

        // The persistent keepalive has no *upward* jitter: it fires within [deadline-lead, deadline]
        // (lead = min(1s, interval/4)), i.e. at or before `arm+interval`, never after — staying under
        // the NAT/relay floor. So the deadline is within [arm+3/4i, arm+i]. Dispatching at arm+2i is
        // safely past the window; use `now` captured here (>= arm time).
        let now = Instant::now();
        let out = a_ep.dispatch_events(now + interval * 2);
        let pkts = out
            .to_peers
            .get(&a_peer)
            .expect("idle endpoint must emit a persistent keepalive");
        assert_eq!(pkts.len(), 1, "exactly one keepalive per interval");
        // It's an empty (encrypted) data packet: header(16) + tag(16), no plaintext body.
        assert_eq!(
            pkts[0].len(),
            16 + 16,
            "keepalive must be an empty data packet"
        );

        // Re-armed unconditionally: a second interval elapses with zero inbound traffic, and another
        // keepalive fires. (Without unconditional re-arm — the original bug — this would be empty.)
        assert!(
            a_ep.next_event().is_some(),
            "persistent keepalive must re-arm after firing"
        );
        let now = Instant::now();
        let out = a_ep.dispatch_events(now + interval * 2);
        assert_eq!(
            out.to_peers.get(&a_peer).map(|p| p.len()),
            Some(1),
            "persistent keepalive must keep firing on a still-idle tunnel"
        );
    }

    /// Outgoing authenticated traffic resets the persistent-keepalive timer: a keepalive only fires
    /// after a full interval of *outbound silence*, so a tunnel with steady outbound traffic never
    /// emits a redundant keepalive.
    #[test]
    fn outgoing_data_resets_persistent_keepalive() {
        let interval = Duration::from_millis(200);
        let (mut a_ep, _b_ep, a_peer, _b_peer) = establish_session(Some(interval), b"hello");

        // Send outbound data partway through the interval — this re-arms the keepalive timer.
        let sent = a_ep.send(HashMap::from([(
            a_peer,
            vec![PacketMut::from(&b"more"[..])],
        )]));
        assert_eq!(
            sent.to_peers.get(&a_peer).map(|p| p.len()),
            Some(1),
            "data should be encrypted and sent to the peer"
        );

        // Just before a full interval *after the data send*: the timer was reset, so no keepalive yet.
        let now = Instant::now();
        let early = a_ep.dispatch_events(now + interval / 2);
        assert!(
            early.to_peers.get(&a_peer).is_none_or(|p| p.is_empty()),
            "keepalive must not fire before a full idle interval after outgoing data"
        );

        // After a full idle interval past the data send, the keepalive fires.
        let now = Instant::now();
        let late = a_ep.dispatch_events(now + interval * 2);
        assert_eq!(
            late.to_peers.get(&a_peer).map(|p| p.len()),
            Some(1),
            "keepalive must fire once the tunnel has been idle for the interval"
        );
    }

    /// With no persistent keepalive configured (`None`), the historical behavior is preserved: once
    /// the reactive §6.5 keepalive lapses, an idle endpoint schedules nothing and emits nothing — no
    /// persistent keepalive is ever sent.
    #[test]
    fn no_persistent_keepalive_when_unconfigured() {
        let (mut a_ep, _b_ep, a_peer, _b_peer) = establish_session(None, b"hello");

        // Dispatch far into the future: with no persistent keepalive and no inbound traffic to arm
        // the reactive one, nothing should be emitted to the peer.
        let now = Instant::now();
        let out = a_ep.dispatch_events(now + Duration::from_secs(60));
        assert!(
            out.to_peers.get(&a_peer).is_none_or(|p| p.is_empty()),
            "no keepalive should fire when persistent keepalive is disabled"
        );
    }

    /// An empty (encrypted) persistent keepalive on the wire: header(16) + auth tag(16), no body.
    const KEEPALIVE_LEN: usize = 16 + 16;

    /// Stand up one local endpoint `A` peered with two *independent* remotes (`B` and `C`), driving a
    /// full handshake with each so `A` holds a live, distinct send session per peer. Each peer can be
    /// given its own persistent-keepalive interval. Returns `A` plus the local [`PeerId`] of each peer
    /// (both timers, if configured, are armed on return).
    ///
    /// Distinct from [`establish_session`] (single peer): this exists specifically to prove the
    /// keepalive timers are *per-peer*, not a single global one.
    fn establish_two_peers(
        b_keepalive: Option<Duration>,
        c_keepalive: Option<Duration>,
    ) -> (Endpoint, PeerId, PeerId) {
        let a_static = NodeKeyPair::new();
        let mut a_ep = Endpoint::new(a_static);
        // A's two peers carry distinct PeerIds *and* distinct node keys (the id map rejects a key
        // collision), so their sessions and timers can never alias.
        let (a_b_peer, a_c_peer) = (PeerId(1), PeerId(2));

        // Drive a full handshake between A and one fresh remote, priming a live A->peer session and
        // arming A's persistent keepalive for that peer (if configured). `payload` distinguishes the
        // two peers' delivered data.
        let bring_up = |a_ep: &mut Endpoint, a_peer: PeerId, keepalive, payload: &[u8]| {
            let remote_static = NodeKeyPair::new();
            let mut remote = Endpoint::new(remote_static);
            let remote_peer = PeerId(1);
            let psk = rand::random();

            a_ep.upsert_peer(
                a_peer,
                PeerConfig {
                    key: remote_static.public,
                    psk,
                    persistent_keepalive_interval: keepalive,
                },
            );
            remote.upsert_peer(
                remote_peer,
                PeerConfig {
                    key: a_static.public,
                    psk,
                    persistent_keepalive_interval: None,
                },
            );

            let init = a_ep.send(HashMap::from([(a_peer, vec![PacketMut::from(payload)])]));
            let init = init.to_peers.get(&a_peer).expect("handshake init").clone();
            let resp = remote.recv(init);
            let resp = resp
                .to_peers
                .get(&remote_peer)
                .expect("handshake resp")
                .clone();
            let data = a_ep.recv(resp);
            let data = data.to_peers.get(&a_peer).expect("data to peer").clone();
            let delivered = remote.recv(data);
            assert_eq!(
                delivered.to_local.get(&remote_peer).map(|p| p.as_slice()),
                Some([PacketMut::from(payload)].as_slice()),
                "payload should be delivered after handshake"
            );
        };

        bring_up(&mut a_ep, a_b_peer, b_keepalive, b"to-b");
        bring_up(&mut a_ep, a_c_peer, c_keepalive, b"to-c");

        (a_ep, a_b_peer, a_c_peer)
    }

    /// Persistent-keepalive timers are **per-peer**, not a single global timer: each peer fires on its
    /// own configured cadence, and traffic on (or a firing of) one peer never resets or suppresses
    /// another peer's timer.
    ///
    /// Two peers are deliberately given *different* intervals (B short, C long) so the independence is
    /// observable with a wide, deterministic margin. The timers are armed against the real monotonic
    /// clock (`Instant::now()` inside `arm_persistent_keepalive`) and dispatched by passing a synthetic
    /// future instant to `dispatch_events`; equal intervals would put both deadlines within microseconds
    /// of each other, leaving no robust window to distinguish them. With B=100ms and C=10s we can
    /// dispatch in `[B's deadline, C's deadline)` and see B alone fire while C stays silent — a single
    /// global timer (or a per-peer timer that B's activity wrongly reset) could not produce this.
    #[test]
    fn persistent_keepalive_is_per_peer_independent() {
        let b_interval = Duration::from_millis(100);
        let c_interval = Duration::from_secs(10);
        let (mut a_ep, b_peer, c_peer) = establish_two_peers(Some(b_interval), Some(c_interval));

        // Dispatch past B's interval but far short of C's: only B's keepalive may fire.
        let now = Instant::now();
        let out = a_ep.dispatch_events(now + b_interval * 2);
        assert_eq!(
            out.to_peers.get(&b_peer).map(|p| p.len()),
            Some(1),
            "B (short interval) must fire its own keepalive"
        );
        assert!(
            out.to_peers.get(&c_peer).is_none_or(|p| p.is_empty()),
            "C (long interval) must NOT fire — its timer is independent of B's"
        );

        // Send real data to B only (re-arming *B's* timer). C must be wholly unaffected: it neither
        // fires early nor has its long timer reset by anything happening on B.
        let sent = a_ep.send(HashMap::from([(b_peer, vec![PacketMut::from(&b"x"[..])])]));
        assert_eq!(
            sent.to_peers.get(&b_peer).map(|p| p.len()),
            Some(1),
            "data to B should encrypt and send on B's live session"
        );
        let now = Instant::now();
        let out = a_ep.dispatch_events(now + b_interval * 2);
        assert_eq!(
            out.to_peers.get(&b_peer).map(|p| p.len()),
            Some(1),
            "B fires again on its re-armed timer"
        );
        assert!(
            out.to_peers.get(&c_peer).is_none_or(|p| p.is_empty()),
            "C still silent: repeated activity on B never touched C's timer"
        );

        // Finally advance past C's own interval: C fires on its own schedule, proving its timer was
        // armed and tracked independently the whole time (never reset or starved by B).
        let now = Instant::now();
        let out = a_ep.dispatch_events(now + c_interval * 2);
        assert_eq!(
            out.to_peers.get(&c_peer).map(|p| p.len()),
            Some(1),
            "C must fire on its own long interval, independent of B"
        );
    }

    /// `upsert_peer` reconciles the persistent-keepalive timer on a *live* session when the configured
    /// interval changes: `Some(..) -> None` cancels the timer (no further keepalives), and
    /// `None -> Some(..)` (re)arms it (keepalives resume). This is the runtime reconfiguration path
    /// (e.g. control toggling a peer's `KeepAlive`), and getting it wrong either leaks a stale timer or
    /// lets an idle relayed path go cold.
    #[test]
    fn upsert_peer_reconciles_persistent_keepalive() {
        let interval = Duration::from_millis(100);
        // Start with a live session that has a persistent keepalive armed.
        let (mut a_ep, _b_ep, a_peer, _b_peer) = establish_session(Some(interval), b"hello");
        let peer_key = a_ep.peer_key(a_peer).expect("peer key");
        let psk = rand::random();

        // Some -> None on the live peer must CANCEL the timer.
        a_ep.upsert_peer(
            a_peer,
            PeerConfig {
                key: peer_key,
                psk,
                persistent_keepalive_interval: None,
            },
        );
        let now = Instant::now();
        let out = a_ep.dispatch_events(now + interval * 2);
        assert!(
            out.to_peers.get(&a_peer).is_none_or(|p| p.is_empty()),
            "disabling the interval (Some->None) must cancel the keepalive timer"
        );
        // No timer should remain scheduled for this otherwise-idle endpoint.
        assert!(
            a_ep.next_event().is_none(),
            "no persistent keepalive should remain scheduled after Some->None"
        );

        // None -> Some on the (still live) peer must ARM the timer again.
        a_ep.upsert_peer(
            a_peer,
            PeerConfig {
                key: peer_key,
                psk,
                persistent_keepalive_interval: Some(interval),
            },
        );
        assert!(
            a_ep.next_event().is_some(),
            "re-enabling the interval (None->Some) on a live session must arm a timer"
        );
        let now = Instant::now();
        let out = a_ep.dispatch_events(now + interval * 2);
        assert_eq!(
            out.to_peers.get(&a_peer).map(|p| p.len()),
            Some(1),
            "re-arming (None->Some) must make keepalives fire again"
        );
    }

    /// Safety boundary (the load-bearing direction): persistent keepalives must keep a live session
    /// *usable* without masking it — emitting keepalives must neither tear the session down nor stop
    /// real data from flowing on that same session. After several idle keepalives fire, a real
    /// outbound packet must still encrypt and send as a full (non-empty) data frame on the unchanged
    /// session.
    ///
    /// Note on scope: the complementary "session aged past `REKEY_AFTER_TIME` triggers a rehandshake"
    /// assertion cannot be driven deterministically from the `Endpoint` API, because session staleness
    /// is evaluated against the real monotonic clock read *internally* (`send`/`encrypt_or_queue` call
    /// `Instant::now()`; there is no injectable `now`), so forcing a >120s-old session would require a
    /// real ~120s sleep (flaky/slow). That age-based rotation is owned and unit-tested at the
    /// `TransmitSession::stale`/`expired` level (see `session.rs`: `session_timers` and
    /// `keepalive_does_not_advance_rotation_timers`, which together prove the rotation clock is keyed on
    /// `created` and is untouched by keepalive sends). This test covers the part that *is*
    /// deterministic here: keepalives don't disturb the live session.
    #[test]
    fn keepalives_do_not_mask_a_live_session() {
        let interval = Duration::from_millis(100);
        let (mut a_ep, _b_ep, a_peer, _b_peer) = establish_session(Some(interval), b"hello");

        // Let several idle keepalives fire on the live session.
        for _ in 0..3 {
            let now = Instant::now();
            let out = a_ep.dispatch_events(now + interval * 2);
            assert_eq!(
                out.to_peers.get(&a_peer).map(|p| p.len()),
                Some(1),
                "an idle keepalive must fire each interval"
            );
            assert_eq!(
                out.to_peers.get(&a_peer).map(|p| p[0].len()),
                Some(KEEPALIVE_LEN),
                "each keepalive must be an empty data frame"
            );
        }

        // The session is still fully usable: real data encrypts and sends as a *non-empty* frame on
        // the same session (it was not torn down, expired, or wedged by the keepalives), and no
        // handshake is forced (a fresh handshake would be a handshake-message packet, not data).
        let payload = b"real-data-after-keepalives";
        let sent = a_ep.send(HashMap::from([(
            a_peer,
            vec![PacketMut::from(&payload[..])],
        )]));
        let pkts = sent
            .to_peers
            .get(&a_peer)
            .expect("real data must still be sent on the live session");
        assert_eq!(pkts.len(), 1, "exactly one data frame for the one packet");
        assert!(
            pkts[0].len() > KEEPALIVE_LEN,
            "real data must be a full (non-empty) data frame, not an empty keepalive — \
             proving keepalives didn't tear down or rotate the live session"
        );
    }
}
