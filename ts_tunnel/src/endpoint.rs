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
        /// Whether *we* were the initiator of the handshake that produced this keypair. Only the
        /// original initiator may trigger a receive-path rekey (Go `keepKeyFreshReceiving` checks
        /// `keypair.isInitiator`); the responder must not, or both sides would initiate
        /// simultaneously (the hazard #20 fixed). Send-path rekey (`needs_rotation`) is unaffected
        /// by this — either side rekeys when *it* sends on a stale keypair.
        is_initiator: bool,
        /// One-shot guard for the receive-path "last minute" rekey, mirroring Go's
        /// `sentLastMinuteHandshake`: set once `keep_key_fresh_receiving` fires for this keypair so a
        /// stream of inbound packets enqueues exactly one handshake, not one per packet. Reset on the
        /// next `activate` (a new keypair).
        last_minute_handshake_sent: bool,
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
    fn activate(
        &mut self,
        endpoint: &mut EndpointState,
        next: SessionPair,
        is_initiator: bool,
    ) -> Vec<PacketMut> {
        tracing::trace!(recv_id = ?next.recv.id(), is_initiator, "activating new session");

        match self.take() {
            SessionState::None(queue) => {
                let mut ret = queue.into();
                next.send.encrypt(&mut ret);
                *self = SessionState::Active {
                    send: next.send,
                    recv: Box::new(next.recv),
                    recv_prev: None,
                    is_initiator,
                    last_minute_handshake_sent: false,
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
                    is_initiator,
                    last_minute_handshake_sent: false,
                };
                vec![]
            }
        }
    }

    /// Whether a receive-path rekey should fire now (Go `keepKeyFreshReceiving`): we were the
    /// handshake **initiator** for this keypair, the keypair is older than the receive rekey
    /// threshold, and we haven't already fired for it. Returns false for a non-initiator (the
    /// responder must never initiate a rekey) or when there is no active session. On a `true`
    /// return it also arms the one-shot guard, so the caller enqueues exactly one handshake.
    fn keep_key_fresh_receiving(&mut self, now: Instant) -> bool {
        if let SessionState::Active {
            send,
            is_initiator: true,
            last_minute_handshake_sent: fired @ false,
            ..
        } = self
            && send.needs_receive_rekey(now)
        {
            *fired = true;
            return true;
        }
        false
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
    fn encrypt_or_queue(
        &mut self,
        endpoint: &mut EndpointState,
        mut packets: Vec<PacketMut>,
    ) -> Option<Vec<PacketMut>> {
        match self {
            SessionState::None(queue) => {
                queue.append(packets);
                None
            }
            SessionState::Active { send, .. } => {
                if send.expired(Instant::now()) {
                    // The transmit session has expired. Due to the semantics of session rotation,
                    // if the transmit session has expired, both receive sessions have also expired,
                    // so this tears the whole session down. Route the teardown through
                    // `deactivate()` so the receive session ids are freed from the id map — a plain
                    // `*self = None(..)` would drop the `ReceiveSession`s without reclaiming their
                    // ids, leaking them for the lifetime of the endpoint.
                    self.deactivate(endpoint);
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
                    && !recv_prev.expired(Instant::now())
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

    /// Free both session ids a handshake may own: the in-flight initiator's allocated recv id and
    /// the tentative responder's recv id. A handshake can hold either, both (simultaneous
    /// initiation), or neither, so each slot is freed independently.
    fn remove_handshake_session(&mut self, handshake: &Handshake) {
        if let Some(id) = handshake.initiated_session_id() {
            self.remove_session(id);
        }
        if let Some(id) = handshake.responded_session_id() {
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
    /// Consecutive failed handshake-initiation retransmits for the current attempt (Go wireguard-go
    /// `peer.timers.handshakeAttempts`). Incremented each time `REKEY_TIMEOUT` fires with no
    /// response; reset to 0 when a *fresh* (non-retry) handshake is started or a handshake completes.
    /// Once it exceeds [`MAX_TIMER_HANDSHAKES`] the peer gives up retransmitting (see
    /// [`Peer::handshake_timeout`]) rather than re-initiating every `REKEY_TIMEOUT` forever.
    handshake_attempts: u32,
}

impl Peer {
    fn new(id: PeerId, config: PeerConfig) -> Self {
        let macs = MACSender::new(&config.key);
        Self {
            id,
            config,
            session: SessionState::None(Queue::default()),
            handshake: Handshake::none(),
            last_seen_timestamp: None,
            cookie_sender: macs,
            keepalive: None,
            send_another_keepalive: false,
            persistent_keepalive: None,
            handshake_attempts: 0,
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
        if let Some(mut packets) = self.session.encrypt_or_queue(endpoint, packets) {
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

        // Outbound-traffic-triggered: a fresh handshake (resets the give-up counter).
        self.start_handshake(endpoint, out, false);
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
        let Some(handshake_mac1) = self.handshake.mac1() else {
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

        // Handshake completed: reset the give-up retransmit counter (Go wireguard-go
        // `timersHandshakeComplete` → `handshakeAttempts.Store(0)`), so a future rekey starts a fresh
        // give-up window. (Only the initiator role runs the retransmit timer/counter; the responder
        // `confirm` path never started one.)
        self.handshake_attempts = 0;

        // We sent the initiation and finished on the response: we are the INITIATOR of this keypair.
        let mut packets = self
            .session
            .activate(endpoint, session, /* is_initiator = */ true);
        if packets.is_empty() {
            // Upon completing a handshake, the initiator must send at least one packet to confirm
            // the session. Usually that can be a queued packet, but if we happen to complete a
            // handshake with no queued packets available, we have to send an empty packet explicitly.
            packets.push(PacketMut::new(0));
            // Session was just activated, therefore it can encrypt.
            packets = self.session.encrypt_or_queue(endpoint, packets).unwrap();
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
                // A keepalive decrypts to an empty payload but is still retained here (AEAD verified,
                // header+tag stripped). Distinguish *data* packets from keepalives: only a real data
                // packet arms the reactive keepalive, mirroring wireguard-go's `dataPacketReceived`
                // gate (`device/receive.go` skips a `len==0` packet via `continue` before
                // `timersDataReceived`, which is what arms `sendKeepalive`). Without this, a received
                // keepalive would arm a keepalive in reply, and two peers settle into a perpetual
                // ~1-packet-per-`KEEPALIVE_TIMEOUT` idle ping-pong that real WireGuard lets go silent.
                let data_received = packets.iter().any(|p| !p.as_ref().is_empty());

                out.queue_to_local(self.id).append(&mut packets);

                if data_received {
                    self.schedule_keepalive(&mut endpoint.scheduler);
                }

                // Receive-triggered rekey (Go `keepKeyFreshReceiving`): a packet authenticated on
                // this keypair — a keepalive counts, since it proves the peer is live on this keypair
                // — so this is gated on any authenticated packet, NOT on `data_received`. If we
                // initiated the session and it is past the receive rekey threshold, enqueue a fresh
                // handshake so the keys refresh before they hard-expire at REJECT_AFTER_TIME, keeping
                // a mostly-inbound, send-idle session alive. One-shot per keypair (the guard lives in
                // `keep_key_fresh_receiving`); initiator-only.
                if self.session.keep_key_fresh_receiving(Instant::now()) {
                    // Receive-triggered rekey is a fresh handshake (resets the give-up counter).
                    self.start_handshake(endpoint, out, false);
                }
            }
            return;
        }

        let Some((session, mut packets)) =
            self.handshake.confirm(session_id, packets, Instant::now())
        else {
            // TODO: log
            return;
        };

        out.queue_to_local(self.id).append(&mut packets);
        self.schedule_keepalive(&mut endpoint.scheduler);

        // The peer initiated and we responded; this transport packet confirms the tentative
        // responder session: we are the RESPONDER of this keypair (must not receive-rekey it).
        let mut packets_for_peer = self
            .session
            .activate(endpoint, session, /* is_initiator = */ false);
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
            && handshake.timestamp <= timestamp
        {
            // Replayed handshake initiation. Mirror wireguard-go `consumeMessageInitiation`, which
            // accepts only `timestamp.After(lastTimestamp)` (strictly greater) — an initiation whose
            // TAI64N timestamp is **equal to or below** the last accepted one is a replay and is
            // dropped. (Earlier this used `<`, which re-processed an equal-timestamp msg1: allocating
            // a fresh session id, emitting a response, and resetting the responder session — a
            // bounded churn/DoS on a captured-and-duplicated initiation.) A *correct* peer re-stamps
            // its initiation on every retransmit (the local TAI64N clock is strictly increasing), so
            // a legitimate retransmit always carries a strictly-greater timestamp and is accepted;
            // only a byte-replayed initiation collides at `==` and is now correctly rejected.
            tracing::warn!("handshake replay detected, bailing out");
            return;
        }
        self.last_seen_timestamp = Some(handshake.timestamp);

        let session_id = endpoint.ids.allocate_session(self.id);

        let (packet, displaced) = self.handshake.respond(
            session_id,
            handshake,
            &self.config.psk,
            &self.cookie_sender,
            Instant::now(),
        );
        // A previous tentative responder session was replaced (e.g. the peer retransmitted its
        // initiation, or rekeyed): free its now-orphaned receive id so it doesn't leak.
        if let Some(old_id) = displaced {
            endpoint.ids.remove_session(old_id);
        }
        out.queue_to_peer(self.id).push(packet);
    }

    fn handshake_timeout(&mut self, endpoint: &mut EndpointState, out: &mut EventResult) {
        if !self.handshake.is_active() {
            // Handshake completed prior to timeout firing.
            return;
        }

        // The in-flight initiation went unanswered. Free its session id and clear the initiator slot
        // regardless of whether we retry or give up.
        endpoint.ids.remove_handshake_session(&self.handshake);
        self.handshake = Handshake::none();

        // Give-up bound (Go wireguard-go `expiredRetransmitHandshake`): after
        // `MAX_TIMER_HANDSHAKES` consecutive failed retransmits stop retransmitting rather than
        // re-initiating every `REKEY_TIMEOUT` forever to an unreachable peer. On give-up, tear
        // the session down: `deactivate` frees the recv ids of any live keypair AND drops the staged
        // outbound queue (a peer with no reachable path shouldn't accumulate a queue indefinitely) —
        // Go's `FlushStagedPackets`. We do NOT re-arm: the next outbound packet re-triggers a fresh
        // handshake via `Peer::send` (`needs_rotation()` is true once the session is torn down),
        // which resets the counter.
        //
        // The session may be `Active` here, not just `None`: a *receive-triggered rekey*
        // (`keep_key_fresh_receiving`) arms a fresh handshake while the converged keypair is still
        // live, so an unanswered rekey can reach give-up with the old keypair still `Active`. Using
        // `deactivate` (not a bare `take`, which would drop the keypair WITHOUT freeing its recv ids
        // — a leak) frees those ids in that case and is a clean no-op for the `None` initial-handshake
        // case.
        if self.handshake_attempts >= MAX_TIMER_HANDSHAKES {
            tracing::debug!(
                peer_id = ?self.id,
                attempts = self.handshake_attempts,
                "handshake did not complete after max attempts; giving up (next outbound packet retries)"
            );
            self.session.deactivate(endpoint);
            self.handshake_attempts = 0;
            return;
        }

        self.handshake_attempts += 1;
        self.start_handshake(endpoint, out, true);
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
        self.handshake = Handshake::none();

        // Stop keeping a removed peer's path warm.
        if let Some(handle) = self.persistent_keepalive.take() {
            handle.cancel();
        }
    }

    /// (Soft) precondition: `self.handshake == HandshakeState::None` (previous handshake is lost, but
    /// that shouldn't cause anything terrible to happen).
    ///
    /// `is_retry` distinguishes a fresh handshake (a new outbound packet or receive-triggered rekey)
    /// from a retransmit of the current one (driven by [`handshake_timeout`](Self::handshake_timeout)).
    /// A fresh handshake resets the [`handshake_attempts`](Self::handshake_attempts) give-up counter
    /// to 0 — mirroring Go wireguard-go's `SendHandshakeInitiation(isRetry)`, where only `isRetry ==
    /// false` zeroes the counter. The retransmit path increments the counter itself before calling
    /// this, so it must pass `true` to avoid resetting its own progress.
    fn start_handshake(
        &mut self,
        endpoint: &mut EndpointState,
        out: &mut impl QueueToPeer,
        is_retry: bool,
    ) {
        if !is_retry {
            self.handshake_attempts = 0;
        }
        // TODO most of this logic might be better in the `handshake` module.
        let session_id = endpoint.ids.allocate_session(self.id);
        let (handshake, packet) = initiate_handshake(
            // `.clone()`: `initiate_handshake` takes the private key by value (it stores it in the
            // returned `SentHandshake`), and the key is no longer `Copy`. The endpoint keeps its
            // own long-lived copy in `endpoint.my_key.private`; this clones it for the new session.
            endpoint.my_key.private.clone(),
            self.config.key,
            session_id,
            endpoint.timestamps.now(),
        );

        let mut packet = PacketMut::from(packet.as_bytes());
        let mac = self.cookie_sender.write_macs(packet.as_mut());

        tracing::debug!(peer_id = ?self.id, ?session_id, "enqueue handshake start");

        out.queue_to_peer(self.id).push(packet);
        // Arm the retransmit timer at REKEY_TIMEOUT + upward jitter (wireguard-go
        // `timersHandshakeInitiated`). The range is anchored at the jittered target and only extends
        // *forward* (a small coalescing tail), so the timer never fires before Go's 5s floor — a
        // symmetric `new_around` window would let it fire early and erase the jitter's desync/anti-
        // fingerprint effect.
        let target = Instant::now() + rekey_retransmit_delay();
        let tr = TimeRange::new(target, target + HANDSHAKE_RETRANSMIT_COALESCE);

        let timeout = endpoint.scheduler.add(tr, Event::HandshakeTimeout(self.id));
        // Set (not replace) the initiator slot: a tentative responder session from a simultaneous
        // initiation may coexist and must be preserved (it owns an allocated id).
        self.handshake.set_initiated(handshake, timeout, mac);
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
        // Derive the cookie receiver from the public key BEFORE moving `my_key` into the state:
        // `NodeKeyPair` is no longer `Copy` (it holds a zeroize-on-drop private key), so the
        // field move would otherwise invalidate the `&my_key.public` borrow. The public key IS
        // `Copy`, so this just copies the 32 public bytes out.
        let my_cookie = MACReceiver::new(&my_key.public);
        Self {
            state: EndpointState {
                my_key,
                my_cookie,
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

    /// Number of session ids currently allocated in the id map. Used by tests to assert there are
    /// no leaked or double-counted session ids after a handshake settles or a peer is torn down.
    #[cfg(test)]
    fn session_id_count(&self) -> usize {
        self.state.ids.sessions.len()
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

/// Base interval between handshake-initiation retransmits, `REKEY_TIMEOUT` from wireguard-go
/// `device/constants.go` (`RekeyTimeout = 5s`). The actual scheduled delay adds upward jitter — see
/// [`rekey_retransmit_delay`].
const REKEY_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum random jitter added to each handshake-retransmit interval, in milliseconds —
/// wireguard-go `device/constants.go` `RekeyTimeoutJitterMaxMs = 334`. Go arms the retransmit timer
/// at `RekeyTimeout + fastrandn(RekeyTimeoutJitterMaxMs) ms` (`device/timers.go`
/// `timersHandshakeInitiated`): the jitter is **upward-only** (never fires before `REKEY_TIMEOUT`)
/// and bounds the delay to `[5.000s, 5.334s)`. The jitter desynchronizes peers that lost
/// connectivity simultaneously (so they don't re-initiate in a 5s-periodic thundering herd) and
/// removes the perfectly-periodic 5.000s retransmit cadence that would otherwise fingerprint us
/// against real WireGuard.
const REKEY_TIMEOUT_JITTER_MAX_MS: u64 = 334;

/// The delay until the next handshake-initiation retransmit: `REKEY_TIMEOUT` plus uniform random
/// jitter in `[0, REKEY_TIMEOUT_JITTER_MAX_MS)` milliseconds, matching wireguard-go
/// `timersHandshakeInitiated` (`RekeyTimeout + fastrandn(RekeyTimeoutJitterMaxMs)`). Upward-only:
/// the result is always `>= REKEY_TIMEOUT`, so we never retransmit before Go's 5s floor.
///
/// The `% REKEY_TIMEOUT_JITTER_MAX_MS` introduces modulo bias of at most
/// `REKEY_TIMEOUT_JITTER_MAX_MS / 2^64 ≈ 1.8e-17` — sub-femtosecond skew over a 334 ms span,
/// physically irrelevant for a desync/anti-fingerprint timer. Go's `fastrandn` is itself a biased
/// multiply-shift, so a perfectly-uniform sample here would diverge from the parity target rather
/// than match it; the simple modulo is both faithful and sufficient.
fn rekey_retransmit_delay() -> Duration {
    let jitter_ms = rand::random::<u64>() % REKEY_TIMEOUT_JITTER_MAX_MS;
    REKEY_TIMEOUT + Duration::from_millis(jitter_ms)
}

/// Forward-only coalescing tail for the handshake-retransmit timer: the scheduler may fire the
/// event anywhere in `[target, target + this]` so it can batch nearby wakeups, but never *before*
/// `target` (which already carries Go's upward jitter). Kept small so the effective retransmit
/// window stays within a few tens of ms of Go's `[5.000s, 5.334s)`.
const HANDSHAKE_RETRANSMIT_COALESCE: Duration = Duration::from_millis(50);

/// Max consecutive handshake-initiation retransmits before giving up (Go wireguard-go
/// `MaxTimerHandshakes = RekeyAttemptTime / RekeyTimeout = 90s / 5s = 18`). After this many failed
/// retransmits, [`Peer::handshake_timeout`] stops retransmitting and tears the session down rather
/// than re-initiating forever; the next outbound packet re-triggers a fresh handshake. Count-based
/// (not a wall clock) to avoid drift from the per-retransmit jitter.
///
/// Total initiations before give-up = 1 (initial) + 18 retransmits = 19, ≈95s of trying. This is
/// one retransmit (~5s) shy of wireguard-go, which gives up on `attempts > 18` (20 initiations,
/// ≈100s); the gate here is `attempts >= 18` after the post-increment. The difference is immaterial
/// — both are within `REKEY_ATTEMPT_TIME`'s intent and the give-up→retry-on-next-packet behavior is
/// identical — but noting it so the count isn't mistaken for byte-exact Go parity.
const MAX_TIMER_HANDSHAKES: u32 = 18;

#[cfg(test)]
mod tests {
    use std::time::Duration as StdDuration;

    use zerocopy::TryFromBytes;

    use super::*;
    use crate::{config::PeerConfig, session::ReceiveSession};

    /// The transport send path zero-pads each payload up to a 16-byte boundary before sealing
    /// (wireguard-go parity — see `session::PADDING_MULTIPLE`), and the receiver delivers the
    /// decrypted payload with that padding intact (the real packet length is recovered downstream
    /// from the inner IP header). So a payload sent through a full handshake+transport roundtrip is
    /// delivered as `payload || zeros` up to the next multiple of 16. Test helper to build that
    /// expected delivered form.
    fn pad16(payload: &[u8]) -> PacketMut {
        let mut v = payload.to_vec();
        let padded_len = payload.len().next_multiple_of(16);
        v.resize(padded_len, 0);
        PacketMut::from(v.as_slice())
    }

    /// The handshake-retransmit delay is `REKEY_TIMEOUT` plus upward-only jitter in
    /// `[0, REKEY_TIMEOUT_JITTER_MAX_MS)` ms, matching wireguard-go `timersHandshakeInitiated`. It is
    /// never below the 5s floor (Go never retransmits early) and never reaches `5s + 334ms`. Sampled
    /// many times to exercise the random range; also asserts the jitter is not degenerate (we do see
    /// more than one distinct value), so a future change that drops the randomness would be caught.
    #[test]
    fn rekey_retransmit_delay_is_jittered_upward_within_go_bounds() {
        let lo = REKEY_TIMEOUT;
        let hi = REKEY_TIMEOUT + Duration::from_millis(REKEY_TIMEOUT_JITTER_MAX_MS);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            let d = rekey_retransmit_delay();
            assert!(
                d >= lo,
                "retransmit delay {d:?} must be >= the 5s floor {lo:?}"
            );
            assert!(
                d < hi,
                "retransmit delay {d:?} must be < 5s + {REKEY_TIMEOUT_JITTER_MAX_MS}ms ({hi:?})"
            );
            seen.insert(d.as_millis());
        }
        assert!(
            seen.len() > 1,
            "the delay must actually be jittered, not a constant"
        );
    }

    /// A bare [`EndpointState`] with an empty [`IdMap`] for unit-testing the session-state helpers
    /// (`get_recv`, `encrypt_or_queue`) directly, without standing up a full handshake.
    fn bare_endpoint_state() -> EndpointState {
        let my_key = NodeKeyPair::new();
        EndpointState {
            my_cookie: MACReceiver::new(&my_key.public),
            my_key,
            ids: IdMap::default(),
            timestamps: Default::default(),
            scheduler: Default::default(),
        }
    }

    /// A random ChaCha20Poly1305 session key for building bare send/recv sessions in tests.
    fn random_session_key() -> chacha20poly1305::Key {
        rand::random::<[u8; 32]>().into()
    }

    /// An instant safely older than `REJECT_AFTER_TIME` (so `expired()` is true), with a saturating
    /// fallback for platforms whose monotonic clock starts near zero.
    fn expired_instant(now: Instant) -> Instant {
        now.checked_sub(StdDuration::from_secs(300)).unwrap_or(now)
    }

    /// FIX #3: `get_recv` must validate the EXPIRY of the session it is about to return. The
    /// `recv_prev` arm previously checked the *current* `recv`'s expiry (a copy-paste bug), so an
    /// expired `recv_prev` could be returned (and a fresh `recv_prev` wrongly rejected whenever the
    /// current `recv` happened to be expired). This pins the corrected behavior on all four
    /// combinations.
    #[test]
    fn get_recv_validates_the_returned_sessions_own_expiry() {
        let now = Instant::now();
        let old = expired_instant(now);
        let recv_id = SessionId::from(0xAAAA);
        let prev_id = SessionId::from(0xBBBB);

        // Case A: fresh recv + EXPIRED recv_prev. The fresh recv is returnable by its id; the
        // expired recv_prev must be rejected (the bug returned it because it checked recv's expiry).
        let mut state = SessionState::Active {
            send: TransmitSession::new(random_session_key(), recv_id, now),
            recv: Box::new(ReceiveSession::new(random_session_key(), recv_id, now)),
            recv_prev: Some(Box::new(ReceiveSession::new(
                random_session_key(),
                prev_id,
                old,
            ))),
            is_initiator: false,
            last_minute_handshake_sent: false,
        };
        assert!(
            state.get_recv(recv_id).is_some(),
            "fresh current recv must be returnable by its id"
        );
        assert!(
            state.get_recv(prev_id).is_none(),
            "an EXPIRED recv_prev must be rejected (regression: the arm checked recv's expiry)"
        );

        // Case B: EXPIRED recv + FRESH recv_prev. The fresh recv_prev must be returnable — the bug
        // wrongly rejected it because the *current* recv (which it checked) was expired.
        let mut state = SessionState::Active {
            send: TransmitSession::new(random_session_key(), recv_id, now),
            recv: Box::new(ReceiveSession::new(random_session_key(), recv_id, old)),
            recv_prev: Some(Box::new(ReceiveSession::new(
                random_session_key(),
                prev_id,
                now,
            ))),
            is_initiator: false,
            last_minute_handshake_sent: false,
        };
        assert!(
            state.get_recv(recv_id).is_none(),
            "an expired current recv must be rejected"
        );
        assert!(
            state.get_recv(prev_id).is_some(),
            "a FRESH recv_prev must be returnable even when the current recv is expired \
             (this is the case the bug broke)"
        );
    }

    /// Receive-triggered rekey decision (`keep_key_fresh_receiving`, Go `keepKeyFreshReceiving`):
    /// fires only when WE were the initiator, only past REKEY_AFTER_TIME_RECEIVING (165s), and only
    /// ONCE per keypair. A responder-side session must NEVER fire (else both ends rekey at once).
    #[test]
    fn keep_key_fresh_receiving_is_initiator_only_aged_and_one_shot() {
        let now = Instant::now();
        let id = SessionId::from(0xCAFE);
        let aged = now + Duration::from_secs(170); // past 165s
        let fresh = now + Duration::from_secs(100); // well within the keypair life

        let make = |is_initiator: bool| SessionState::Active {
            send: TransmitSession::new(random_session_key(), id, now),
            recv: Box::new(ReceiveSession::new(random_session_key(), id, now)),
            recv_prev: None,
            is_initiator,
            last_minute_handshake_sent: false,
        };

        // Responder: never fires, no matter the age.
        let mut responder = make(false);
        assert!(
            !responder.keep_key_fresh_receiving(aged),
            "the responder must not trigger a receive-path rekey (avoids simultaneous initiation)"
        );

        // Initiator, but keypair still young: not yet.
        let mut initiator = make(true);
        assert!(
            !initiator.keep_key_fresh_receiving(fresh),
            "an initiator session younger than 165s must not rekey yet"
        );

        // Initiator past 165s: fires exactly once, then the one-shot guard suppresses repeats.
        assert!(
            initiator.keep_key_fresh_receiving(aged),
            "an initiator session past 165s must trigger a receive-path rekey"
        );
        assert!(
            !initiator.keep_key_fresh_receiving(aged),
            "the trigger is one-shot per keypair — a stream of inbound packets enqueues one handshake"
        );

        // A `None` (no active session) never fires.
        let mut none = SessionState::None(Queue::default());
        assert!(!none.keep_key_fresh_receiving(aged));
    }

    /// FIX #4: when a session's transmit side has expired, `encrypt_or_queue` tears the session
    /// down — but it must FREE the receive session ids from the id map, not just drop the
    /// `ReceiveSession`s. Dropping them without freeing the ids leaks them for the endpoint's whole
    /// lifetime (a real concern for a long-lived NVC tunnel that rekeys repeatedly). This asserts
    /// the id-map session count returns to its baseline after the expiry-driven reset.
    #[test]
    fn encrypt_or_queue_frees_recv_ids_when_send_expired() {
        let mut endpoint = bare_endpoint_state();
        let now = Instant::now();
        let old = expired_instant(now);
        let peer = PeerId(1);

        // Allocate two ids in the id map, exactly as a rotated active session would own (recv +
        // recv_prev). Baseline is two live ids.
        let recv_id = endpoint.ids.allocate_session(peer);
        let prev_id = endpoint.ids.allocate_session(peer);
        assert_eq!(endpoint.ids.sessions.len(), 2, "two ids allocated");

        // An active session whose SEND side is expired (created `old`), holding both receive
        // sessions under the allocated ids.
        let mut state = SessionState::Active {
            send: TransmitSession::new(random_session_key(), recv_id, old),
            recv: Box::new(ReceiveSession::new(random_session_key(), recv_id, old)),
            recv_prev: Some(Box::new(ReceiveSession::new(
                random_session_key(),
                prev_id,
                old,
            ))),
            is_initiator: false,
            last_minute_handshake_sent: false,
        };

        // encrypt_or_queue on the expired send must queue the packet (returns None) AND reclaim
        // both receive ids — not leak them.
        let queued = state.encrypt_or_queue(&mut endpoint, vec![PacketMut::from(&b"data"[..])]);
        assert!(
            queued.is_none(),
            "an expired send session must queue (not encrypt) and signal a rehandshake is needed"
        );
        assert!(
            matches!(state, SessionState::None(_)),
            "the expired session must be reset to None (packets queued)"
        );
        assert_eq!(
            endpoint.ids.sessions.len(),
            0,
            "both receive ids must be freed on the expiry-driven teardown — no leak"
        );
    }

    #[test]
    fn test_one_peer() {
        let (a_static, b_static) = (NodeKeyPair::new(), NodeKeyPair::new());
        let psk = rand::random::<crate::config::Psk>();

        let (mut a_ep, mut b_ep) = (
            Endpoint::new(a_static.clone()),
            Endpoint::new(b_static.clone()),
        );

        let a_peer = PeerId(1);
        let b_peer = PeerId(1);

        assert!(
            a_ep.upsert_peer(
                a_peer,
                PeerConfig {
                    key: b_static.public,
                    psk: psk.clone(),
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
                    psk: psk.clone(),
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
        // Each payload is zero-padded to a 16-byte boundary on the send path (wireguard-go parity).
        assert_eq!(
            packets,
            &[pad16(&[1, 2, 3, 4]), pad16(&[5, 6, 7, 8])],
            "wrong packets received from A",
        );
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
            &[pad16(&[9, 10, 11, 12])],
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
        let psk = rand::random::<crate::config::Psk>();
        let (mut a_ep, mut b_ep) = (
            Endpoint::new(a_static.clone()),
            Endpoint::new(b_static.clone()),
        );
        let (a_peer, b_peer) = (PeerId(1), PeerId(1));

        a_ep.upsert_peer(
            a_peer,
            PeerConfig {
                key: b_static.public,
                psk: psk.clone(),
                persistent_keepalive_interval: a_keepalive,
            },
        );
        b_ep.upsert_peer(
            b_peer,
            PeerConfig {
                key: a_static.public,
                psk: psk.clone(),
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
            Some([pad16(payload)].as_slice()),
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

    /// Reactive (§6.5) keepalive is armed by inbound DATA, never by an inbound keepalive — mirroring
    /// wireguard-go's `dataPacketReceived` gate. Receiving an empty keepalive must NOT cause this
    /// endpoint to schedule a keepalive in reply; receiving a data packet must. Without the gate, two
    /// peers settle into a perpetual idle keepalive ping-pong real WireGuard lets go silent.
    #[test]
    fn received_keepalive_does_not_arm_reactive_keepalive() {
        // A has no persistent keepalive, so the ONLY thing that could schedule an outbound keepalive
        // on A is the reactive §6.5 arming on inbound traffic.
        let (mut a_ep, mut b_ep, a_peer, b_peer) = establish_session(None, b"hello");

        // Get a genuine keepalive FROM B: send data A->B (which arms B's reactive keepalive), then
        // dispatch B's timer past KEEPALIVE_TIMEOUT so B emits exactly one empty keepalive.
        let a_data = a_ep.send(HashMap::from([(
            a_peer,
            vec![PacketMut::from(&b"ping"[..])],
        )]));
        let to_b = a_data.to_peers.get(&a_peer).expect("data to B").clone();
        drop(b_ep.recv(to_b)); // B receives data -> arms B's reactive keepalive
        let now = Instant::now();
        let b_out = b_ep.dispatch_events(now + KEEPALIVE_TIMEOUT + Duration::from_secs(2));
        let ka = b_out
            .to_peers
            .get(&b_peer)
            .expect("B emits a reactive keepalive after receiving data")
            .clone();
        assert_eq!(ka.len(), 1);
        assert_eq!(
            ka[0].len(),
            KEEPALIVE_LEN,
            "B's packet is an empty keepalive"
        );

        // Drain any reactive keepalive A may have armed from the earlier handshake/data so the
        // assertion below isolates the effect of receiving B's keepalive. (A received only handshake
        // traffic so far, no data, so it should have nothing armed — but dispatch to be certain.)
        let now = Instant::now();
        drop(a_ep.dispatch_events(now + Duration::from_secs(60)));

        let recv = a_ep.recv(ka);
        // A keepalive carries no usable payload — any packet surfaced to local is empty (the
        // dataplane's IP src-filter drops it; the endpoint layer does not special-case it).
        assert!(
            recv.to_local
                .get(&a_peer)
                .is_none_or(|pkts| pkts.iter().all(|p| p.as_ref().is_empty())),
            "a keepalive delivers no usable (non-empty) local payload"
        );
        // ...and must NOT have armed a reactive keepalive: dispatched far forward, A emits nothing.
        let now = Instant::now();
        let after_ka = a_ep.dispatch_events(now + Duration::from_secs(60));
        assert!(
            after_ka.to_peers.get(&a_peer).is_none_or(|p| p.is_empty()),
            "receiving a keepalive must NOT arm a reactive keepalive (no idle ping-pong)"
        );

        // Contrast: a DATA packet from B DOES arm A's reactive keepalive, which then fires once.
        let b_data = b_ep.send(HashMap::from([(
            b_peer,
            vec![PacketMut::from(&b"data"[..])],
        )]));
        let data = b_data
            .to_peers
            .get(&b_peer)
            .expect("B emits a data packet")
            .clone();
        let recv = a_ep.recv(data);
        assert_eq!(
            recv.to_local.get(&a_peer).map(|p| p.as_slice()),
            Some([pad16(b"data")].as_slice()),
            "the data payload is delivered to A"
        );
        let now = Instant::now();
        let after_data = a_ep.dispatch_events(now + KEEPALIVE_TIMEOUT + Duration::from_secs(2));
        assert_eq!(
            after_data.to_peers.get(&a_peer).map(|p| p.len()),
            Some(1),
            "inbound DATA must arm the reactive keepalive, which then fires exactly once"
        );
        assert_eq!(
            after_data.to_peers.get(&a_peer).unwrap()[0].len(),
            KEEPALIVE_LEN,
            "the reactive keepalive is an empty data packet"
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
        let mut a_ep = Endpoint::new(a_static.clone());
        // A's two peers carry distinct PeerIds *and* distinct node keys (the id map rejects a key
        // collision), so their sessions and timers can never alias.
        let (a_b_peer, a_c_peer) = (PeerId(1), PeerId(2));

        // Drive a full handshake between A and one fresh remote, priming a live A->peer session and
        // arming A's persistent keepalive for that peer (if configured). `payload` distinguishes the
        // two peers' delivered data.
        let bring_up = |a_ep: &mut Endpoint, a_peer: PeerId, keepalive, payload: &[u8]| {
            let remote_static = NodeKeyPair::new();
            let mut remote = Endpoint::new(remote_static.clone());
            let remote_peer = PeerId(1);
            let psk = rand::random::<crate::config::Psk>();

            a_ep.upsert_peer(
                a_peer,
                PeerConfig {
                    key: remote_static.public,
                    psk: psk.clone(),
                    persistent_keepalive_interval: keepalive,
                },
            );
            remote.upsert_peer(
                remote_peer,
                PeerConfig {
                    key: a_static.public,
                    psk: psk.clone(),
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
                Some([pad16(payload)].as_slice()),
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
        let psk = rand::random::<crate::config::Psk>();

        // Some -> None on the live peer must CANCEL the timer.
        a_ep.upsert_peer(
            a_peer,
            PeerConfig {
                key: peer_key,
                psk: psk.clone(),
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
                psk: psk.clone(),
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

    /// Pull the (single peer's) packets out of a result's `to_peers`, asserting exactly one peer
    /// was addressed. Keeps the simultaneous-initiation test below readable.
    fn only_to_peer(
        map: &HashMap<PeerId, Vec<PacketMut>>,
        peer: PeerId,
        what: &str,
    ) -> Vec<PacketMut> {
        assert_eq!(
            map.len(),
            1,
            "expected packets for exactly one peer ({what})"
        );
        map.get(&peer).expect(what).clone()
    }

    /// Regression test for issue #20: WireGuard *simultaneous initiation*.
    ///
    /// Both peers initiate a handshake before either has seen the other's initiation. With the old
    /// single-slot `Handshake`, each peer's `respond()` clobbered its own in-flight `Initiated`
    /// state, so its later `finish()` failed ("handshake failed to complete") and every transport
    /// packet thereafter hit "session not found" — a permanent wedge. The two-slot `Handshake`
    /// retains BOTH roles (initiator + responder) simultaneously; both handshakes complete and the
    /// `SessionState` rotation converges them. This drives two real `Endpoint`s through that race
    /// and asserts: (a) data flows BOTH ways afterwards, (b) no wedge, and (c) no session ids leak
    /// (the id map returns to its baseline after both peers are torn down).
    #[test]
    fn simultaneous_initiation_converges_without_wedge() {
        let (a_static, b_static) = (NodeKeyPair::new(), NodeKeyPair::new());
        let psk = rand::random::<crate::config::Psk>();
        let (mut a_ep, mut b_ep) = (
            Endpoint::new(a_static.clone()),
            Endpoint::new(b_static.clone()),
        );
        let (a_peer, b_peer) = (PeerId(1), PeerId(1));

        a_ep.upsert_peer(
            a_peer,
            PeerConfig {
                key: b_static.public,
                psk: psk.clone(),
                persistent_keepalive_interval: None,
            },
        );
        b_ep.upsert_peer(
            b_peer,
            PeerConfig {
                key: a_static.public,
                psk: psk.clone(),
                persistent_keepalive_interval: None,
            },
        );

        // Baseline: no sessions allocated on either endpoint before any handshake.
        assert_eq!(a_ep.session_id_count(), 0);
        assert_eq!(b_ep.session_id_count(), 0);

        // (1) BOTH peers send first — each produces its own initiation while still ignorant of the
        // other's. Each endpoint now holds an in-flight initiator (and one allocated session id).
        let init_a = a_ep.send(HashMap::from([(
            a_peer,
            vec![PacketMut::from(&b"a-first"[..])],
        )]));
        let init_a = only_to_peer(&init_a.to_peers, a_peer, "A's handshake init");
        let init_b = b_ep.send(HashMap::from([(
            b_peer,
            vec![PacketMut::from(&b"b-first"[..])],
        )]));
        let init_b = only_to_peer(&init_b.to_peers, b_peer, "B's handshake init");
        assert_eq!(a_ep.session_id_count(), 1, "A allocated its initiator id");
        assert_eq!(b_ep.session_id_count(), 1, "B allocated its initiator id");

        // (2) Each initiation is delivered to the OPPOSITE endpoint. Each peer responds to the
        // peer's msg1 (the interop-mandatory behavior) WITHOUT discarding its own in-flight
        // initiation: it now holds both roles, and a second (responder) session id.
        let resp_to_a = b_ep.recv(init_a);
        assert!(resp_to_a.to_local.is_empty(), "no payload delivered yet");
        let resp_to_a = only_to_peer(&resp_to_a.to_peers, b_peer, "B's response to A");
        let resp_to_b = a_ep.recv(init_b);
        assert!(resp_to_b.to_local.is_empty(), "no payload delivered yet");
        let resp_to_b = only_to_peer(&resp_to_b.to_peers, a_peer, "A's response to B");
        assert_eq!(
            a_ep.session_id_count(),
            2,
            "A holds both an initiator and a responder session id"
        );
        assert_eq!(
            b_ep.session_id_count(),
            2,
            "B holds both an initiator and a responder session id"
        );

        // (3) Each peer receives the response to ITS OWN initiation. Under the old code this
        // `finish()` would fail (the initiation was clobbered by step 2); here it completes,
        // activates the initiator session, and flushes the queued first-packet to confirm.
        let data_from_a = a_ep.recv(resp_to_a);
        let data_from_a = only_to_peer(&data_from_a.to_peers, a_peer, "A's first transport packet");
        let data_from_b = b_ep.recv(resp_to_b);
        let data_from_b = only_to_peer(&data_from_b.to_peers, b_peer, "B's first transport packet");

        // (4) The confirming transport packets cross. Each side decrypts the peer's first packet,
        // delivering the primed payload locally — proving the session converged (no wedge).
        let delivered_to_b = b_ep.recv(data_from_a);
        assert_eq!(
            delivered_to_b.to_local.get(&b_peer).map(|p| p.as_slice()),
            Some([pad16(b"a-first")].as_slice()),
            "A's primed payload must reach B (no 'session not found' wedge)"
        );
        let delivered_to_a = a_ep.recv(data_from_b);
        assert_eq!(
            delivered_to_a.to_local.get(&a_peer).map(|p| p.as_slice()),
            Some([pad16(b"b-first")].as_slice()),
            "B's primed payload must reach A (no 'session not found' wedge)"
        );

        // (5) The tunnel is fully bidirectional on fresh data, not just the handshake-priming
        // packets: send new data each way and confirm it decrypts on the other end.
        let a_payload = b"a->b-after-converge";
        let to_b = a_ep.send(HashMap::from([(
            a_peer,
            vec![PacketMut::from(&a_payload[..])],
        )]));
        let to_b = only_to_peer(&to_b.to_peers, a_peer, "A's post-converge data");
        let got_b = b_ep.recv(to_b);
        assert_eq!(
            got_b.to_local.get(&b_peer).map(|p| p.as_slice()),
            Some([pad16(a_payload)].as_slice()),
            "fresh A->B data must flow on the converged session"
        );

        let b_payload = b"b->a-after-converge";
        let to_a = b_ep.send(HashMap::from([(
            b_peer,
            vec![PacketMut::from(&b_payload[..])],
        )]));
        let to_a = only_to_peer(&to_a.to_peers, b_peer, "B's post-converge data");
        let got_a = a_ep.recv(to_a);
        assert_eq!(
            got_a.to_local.get(&a_peer).map(|p| p.as_slice()),
            Some([pad16(b_payload)].as_slice()),
            "fresh B->A data must flow on the converged session"
        );

        // (6) No leaked session ids: tearing each peer down must free everything it holds (both the
        // active recv and the rotated recv_prev that the second completion produced). A leak or a
        // double-free (the id map `remove_session` unwraps) would surface right here.
        assert!(a_ep.remove_peer(a_peer), "A's peer should exist");
        assert!(b_ep.remove_peer(b_peer), "B's peer should exist");
        assert_eq!(
            a_ep.session_id_count(),
            0,
            "A must free every session id on teardown — no leak"
        );
        assert_eq!(
            b_ep.session_id_count(),
            0,
            "B must free every session id on teardown — no leak"
        );
    }

    /// Build a raw, MAC'd [`HandshakeInitiation`] as if sent by `from` to `to`, using `session_id`
    /// as the sender's receive id and `timestamp` as the (replay-guarding) handshake timestamp.
    /// Returns a synthetic-peer [`Handshake`] in the initiator role (so it can later `finish()` the
    /// responder's reply and converge) alongside the wire packet to feed into the responder's
    /// `recv`. Each call uses a *fresh random ephemeral* (it's a distinct handshake), so two calls
    /// produce two genuinely different initiations. `scheduler` owns the (unused-in-this-path)
    /// `REKEY_TIMEOUT` handle, mirroring the existing handshake-module unit tests.
    fn build_initiation(
        from: &NodeKeyPair,
        to: &NodeKeyPair,
        session_id: SessionId,
        timestamp: TAI64N,
        scheduler: &mut Scheduler<Event>,
    ) -> (Handshake, PacketMut) {
        let (sent, init) =
            initiate_handshake(from.private.clone(), to.public, session_id, timestamp);
        let mut pkt = PacketMut::from(init.as_bytes());
        // The initiation's mac1 must verify against the *recipient's* key (responder); the returned
        // mac1 is what an initiator keeps to authenticate a cookie reply.
        let mac1 = MACSender::new(&to.public).write_macs(pkt.as_mut());
        let target = Instant::now() + rekey_retransmit_delay();
        let timeout = scheduler.add(
            TimeRange::new(target, target + HANDSHAKE_RETRANSMIT_COALESCE),
            Event::HandshakeTimeout(PeerId(0)),
        );
        let mut handshake = Handshake::none();
        handshake.set_initiated(sent, timeout, mac1);
        (handshake, pkt)
    }

    /// Two TAI64N timestamps with a guaranteed strict ordering (`earlier < later`), built from fixed
    /// offsets past the Unix epoch so the ordering is independent of the wall clock — the second
    /// initiation must out-rank the first to pass the responder's replay guard deterministically.
    fn ordered_timestamps() -> (TAI64N, TAI64N) {
        use std::time::{Duration, UNIX_EPOCH};
        let earlier = TAI64N::from(UNIX_EPOCH + Duration::from_secs(1_000_000));
        let later = TAI64N::from(UNIX_EPOCH + Duration::from_secs(1_000_100));
        assert!(later > earlier, "fixed timestamps must be strictly ordered");
        (earlier, later)
    }

    /// Regression test for issue #20 (displaced-responder id free path — reviewer R2).
    ///
    /// This pins the EXACT line that fixes the old id leak: when a responder already holds a
    /// tentative `responded` session and a *fresh* initiation arrives from the same peer (newer
    /// timestamp, so it passes the replay guard), `Handshake::respond` replaces the old
    /// `SessionPair` and returns `Some(old_recv_id)`, which `respond_to_handshake` frees from the
    /// `IdMap` (`endpoint.rs`'s `remove_session(old_id)`). Before the fix the displaced id leaked;
    /// a naive fix that freed the wrong id (or double-freed) would panic in `remove_session`'s
    /// `unwrap`.
    ///
    /// `A` is the responder. A synthetic peer `C` sends two initiations. We assert:
    /// (a) the old responder recv-id is freed — A's `session_id_count` is UNCHANGED across the
    ///     replacement (one id in, one id out), proving no leak and no accumulation;
    /// (b) NO panic — the displaced id was the right one and was still present (no double-free);
    /// (c) A still converges afterward — C finishes A's reply to the *second* initiation, sends a
    ///     confirming transport packet, and A delivers C's payload locally.
    ///
    /// Deterministic: pure message passing plus fixed-offset timestamps (no real sleeps, no
    /// wall-clock-dependent ordering).
    #[test]
    fn fresh_initiation_frees_displaced_responder_id() {
        let (a_static, c_static) = (NodeKeyPair::new(), NodeKeyPair::new());
        let psk = rand::random::<crate::config::Psk>();
        let mut a_ep = Endpoint::new(a_static.clone());
        let a_peer = PeerId(1);

        // A knows C as a peer (so A will respond to C's initiations rather than dropping them).
        a_ep.upsert_peer(
            a_peer,
            PeerConfig {
                key: c_static.public,
                psk: psk.clone(),
                persistent_keepalive_interval: None,
            },
        );
        assert_eq!(a_ep.session_id_count(), 0, "no ids before any handshake");

        let (t_first, t_second) = ordered_timestamps();
        let mut c_scheduler = Scheduler::<Event>::default();

        // (1) C's FIRST initiation. A responds and stores a tentative responder session, allocating
        // exactly one receive id. Nothing is displaced on the first respond().
        let (_c_first, init_first) = build_initiation(
            &c_static,
            &a_static,
            SessionId::from(0x1111),
            t_first,
            &mut c_scheduler,
        );
        let resp_first = a_ep.recv([init_first]);
        assert!(
            resp_first.to_local.is_empty(),
            "a bare initiation delivers no local payload"
        );
        only_to_peer(
            &resp_first.to_peers,
            a_peer,
            "A's response to C's first init",
        );
        assert_eq!(
            a_ep.session_id_count(),
            1,
            "A allocated one responder receive id for the first initiation"
        );

        // (2) C's SECOND, fresh initiation (new ephemeral, strictly-newer timestamp → passes the
        // replay guard). A's respond() replaces the tentative SessionPair, returns the old recv-id,
        // and respond_to_handshake frees it. If this path were buggy (freed the wrong id, or the
        // id was already gone) the IdMap unwrap would PANIC here — reaching the assert proves it did
        // not (assertion b).
        let (mut c_second, init_second) = build_initiation(
            &c_static,
            &a_static,
            SessionId::from(0x2222),
            t_second,
            &mut c_scheduler,
        );
        let resp_second = a_ep.recv([init_second]);
        let resp_second = only_to_peer(
            &resp_second.to_peers,
            a_peer,
            "A's response to C's second init",
        );

        // (a) The displaced id was freed: the count is UNCHANGED across the replacement (one fresh
        // id allocated, one stale id removed) — no leak, no accumulation.
        assert_eq!(
            a_ep.session_id_count(),
            1,
            "displacing the tentative responder must free the old id (count unchanged, not 2)"
        );

        // (c) A still converges on the SECOND handshake: C finishes A's reply, sends a confirming
        // transport packet under the new keys, and A confirms its (replacement) responder session
        // and delivers C's payload locally — the tunnel works after the displacement.
        let response_ref = HandshakeResponse::try_ref_from_bytes(
            resp_second.first().expect("a response packet").as_ref(),
        )
        .expect("valid handshake response");
        let c_mac_recv = MACReceiver::new(&c_static.public);
        let c_session = c_second
            .finish(response_ref, &psk, &c_mac_recv, Instant::now())
            .expect("C finishes A's reply to the second initiation");

        let payload = b"c-confirms-after-displacement";
        let mut confirm = vec![PacketMut::from(&payload[..])];
        c_session.send.encrypt(confirm.iter_mut());
        let delivered = a_ep.recv(confirm);
        assert_eq!(
            delivered.to_local.get(&a_peer).map(|p| p.as_slice()),
            Some([pad16(payload)].as_slice()),
            "A must converge on the replacement responder session and deliver C's payload"
        );

        // Teardown frees the converged id — back to baseline, no residual leak.
        assert!(a_ep.remove_peer(a_peer), "A's peer should exist");
        assert_eq!(
            a_ep.session_id_count(),
            0,
            "every id is freed on teardown — no leak from the displacement path"
        );
    }

    /// Count the handshake-initiation packets in a per-peer emission map (a fired retransmit or a
    /// fresh initiation both emit exactly one msg1 to the peer).
    fn count_initiations(map: &HashMap<PeerId, Vec<PacketMut>>, peer: PeerId) -> usize {
        map.get(&peer)
            .map(|pkts| {
                pkts.iter()
                    .filter(|p| {
                        matches!(
                            Message::try_from(p.as_ref()),
                            Ok(Message::HandshakeInitiation(_))
                        )
                    })
                    .count()
            })
            .unwrap_or(0)
    }

    /// Regression for the WG handshake give-up bound (Go wireguard-go `expiredRetransmitHandshake` /
    /// `MaxTimerHandshakes`): the initiator must stop retransmitting after [`MAX_TIMER_HANDSHAKES`]
    /// failed attempts instead of re-initiating every `REKEY_TIMEOUT` forever to an unreachable
    /// peer, and the next outbound packet must re-trigger exactly one fresh handshake.
    ///
    /// A is the initiator; its peer B never answers (no `recv` is fed back). We `send` once to kick
    /// off the first initiation, then fire `HandshakeTimeout` past the cap and assert: (i) once at
    /// the cap a fired timeout emits NO further initiation (give-up), (ii) the give-up freed the
    /// in-flight id (no leak / no accumulation), and (iii) a subsequent `send` re-triggers exactly
    /// one fresh initiation. Deterministic: pure event dispatch, no real sleeps.
    #[test]
    fn handshake_retransmit_gives_up_after_max_attempts_then_retriggers() {
        let (a_static, b_static) = (NodeKeyPair::new(), NodeKeyPair::new());
        let mut a_ep = Endpoint::new(a_static);
        let b_peer = PeerId(1);
        a_ep.upsert_peer(
            b_peer,
            PeerConfig {
                key: b_static.public,
                psk: rand::random(),
                persistent_keepalive_interval: None,
            },
        );

        // Kick off the first handshake by sending an outbound packet (no live session → initiation).
        let first = a_ep.send([(b_peer, vec![PacketMut::new(32)])]);
        let mut total_initiations = count_initiations(&first.to_peers, b_peer);
        assert_eq!(
            total_initiations, 1,
            "the first outbound packet triggers exactly one handshake initiation"
        );
        assert_eq!(a_ep.session_id_count(), 1, "one in-flight handshake id");

        // Fire HandshakeTimeout well past the cap. Each fire below the cap re-initiates (one new
        // msg1); once attempts reach the cap the give-up fires and NO further initiation is emitted.
        // Sum every initiation so the EXACT give-up count is pinned (catches an off-by-one in either
        // direction — a regression that gave up too early or too late would change this total).
        let mut now = Instant::now();
        for _ in 0..(MAX_TIMER_HANDSHAKES + 5) {
            now += REKEY_TIMEOUT * 2; // well past the (jittered) timeout window
            total_initiations += count_initiations(&a_ep.dispatch_events(now).to_peers, b_peer);
        }
        assert_eq!(
            total_initiations,
            (MAX_TIMER_HANDSHAKES + 1) as usize,
            "exactly the initial initiation + MAX_TIMER_HANDSHAKES retransmits, then give-up (no more)"
        );
        assert_eq!(
            a_ep.session_id_count(),
            0,
            "give-up frees the in-flight handshake id (no leak / no accumulation)"
        );

        // A subsequent outbound packet re-triggers exactly one fresh handshake (the counter reset).
        let again = a_ep.send([(b_peer, vec![PacketMut::new(32)])]);
        assert_eq!(
            count_initiations(&again.to_peers, b_peer),
            1,
            "a new outbound packet after give-up re-triggers exactly one fresh initiation"
        );
        assert_eq!(
            a_ep.session_id_count(),
            1,
            "exactly one fresh in-flight id after re-trigger"
        );
    }

    /// Regression: giving up on a rekey while the previous keypair is still **Active** must FREE that
    /// keypair's receive ids, not leak them. A receive-triggered rekey (`keep_key_fresh_receiving`)
    /// arms a fresh handshake while the converged session stays live; if that rekey goes unanswered
    /// and hits the give-up bound, the teardown must go through `deactivate` (frees recv ids), not a
    /// bare `take` (drops the keypair WITHOUT freeing its ids — a permanent leak). We establish a
    /// real session (A is initiator, so it owns the keypair's recv id), then simulate the rekey by
    /// arming a fresh handshake on A's peer and driving `HandshakeTimeout` past the cap with B
    /// unreachable. A's id count must return to the post-handshake baseline.
    #[test]
    fn giveup_on_rekey_of_active_session_frees_recv_ids() {
        let (mut a_ep, _b_ep, a_peer, _b_peer) = establish_session(None, b"hello");
        let baseline = a_ep.session_id_count();
        assert_eq!(
            baseline, 1,
            "A holds exactly its established keypair's recv id"
        );

        // Simulate the receive-triggered rekey: arm a fresh handshake on A's peer WHILE the keypair
        // is still Active (this is exactly what `keep_key_fresh_receiving` does). `is_retry=false`
        // resets the give-up counter, mirroring the live path. This allocates the rekey's id.
        let peer = a_ep.peers.get_mut(&a_peer).expect("A's peer");
        peer.start_handshake(&mut a_ep.state, &mut EventResult::default(), false);
        assert_eq!(
            a_ep.session_id_count(),
            baseline + 1,
            "rekey-while-active allocates a second (handshake) id atop the live keypair"
        );

        // B is unreachable: drive the rekey's HandshakeTimeout past the cap so it gives up.
        let mut now = Instant::now();
        for _ in 0..(MAX_TIMER_HANDSHAKES + 5) {
            now += REKEY_TIMEOUT * 2;
            a_ep.dispatch_events(now);
        }

        // The give-up must have torn the Active keypair down via `deactivate`, freeing BOTH the live
        // keypair's recv id and the abandoned rekey id — back to zero. The old `take()` would have
        // leaked the keypair's recv id here (count stuck at 1).
        assert_eq!(
            a_ep.session_id_count(),
            0,
            "give-up on an Active session frees the keypair's recv ids (no leak)"
        );
    }

    /// Regression for the handshake-timestamp replay guard (`tsr-k5j`): an initiation whose TAI64N
    /// timestamp is **equal** to the last accepted one must be rejected as a replay, mirroring
    /// wireguard-go `consumeMessageInitiation` (`timestamp.After(lastTimestamp)`, strictly greater).
    ///
    /// The guard in `respond_to_handshake` used `<` (strict less-than), so an equal-timestamp msg1
    /// slipped through: A re-processed it, allocating a *fresh* receive id and emitting a *second*
    /// response. The fix is `<=` (reject equal). A correct peer re-stamps every retransmit (its
    /// local TAI64N clock is strictly increasing), so a byte-identical-timestamp initiation only
    /// arises from a captured-and-duplicated packet.
    ///
    /// `A` is the responder. Synthetic peer `C` sends two initiations carrying the **same**
    /// timestamp (distinct ephemerals/session-ids — a genuine byte-replay re-sends identical bytes,
    /// but using a fresh ephemeral here is strictly *more* permissive and still must be rejected on
    /// the timestamp alone). We assert the second produces **no response packet** and allocates **no
    /// new id** — proving the equal-timestamp initiation was dropped before `respond()`.
    ///
    /// Deterministic: pure message passing plus a single fixed-offset timestamp (no real sleeps).
    #[test]
    fn equal_timestamp_initiation_is_rejected_as_replay() {
        let (a_static, c_static) = (NodeKeyPair::new(), NodeKeyPair::new());
        let psk = rand::random::<crate::config::Psk>();
        let mut a_ep = Endpoint::new(a_static.clone());
        let a_peer = PeerId(1);

        a_ep.upsert_peer(
            a_peer,
            PeerConfig {
                key: c_static.public,
                psk: psk.clone(),
                persistent_keepalive_interval: None,
            },
        );

        // Both initiations carry the SAME timestamp — only the first may be accepted.
        let (t_replay, _t_unused) = ordered_timestamps();
        let mut c_scheduler = Scheduler::<Event>::default();

        // (1) C's first initiation. A accepts it, allocates one responder receive id, and responds.
        let (_c_first, init_first) = build_initiation(
            &c_static,
            &a_static,
            SessionId::from(0x1111),
            t_replay,
            &mut c_scheduler,
        );
        let resp_first = a_ep.recv([init_first]);
        only_to_peer(
            &resp_first.to_peers,
            a_peer,
            "A's response to C's first init",
        );
        assert_eq!(
            a_ep.session_id_count(),
            1,
            "A allocated one responder receive id for the first initiation"
        );

        // (2) C's second initiation with the SAME timestamp. The replay guard (`<=`) must drop it
        // BEFORE `respond()`: no response packet, and the id count is unchanged (no fresh id). Under
        // the old `<` guard this re-processed the initiation — emitting a second response and
        // allocating/displacing an id.
        let (_c_second, init_second) = build_initiation(
            &c_static,
            &a_static,
            SessionId::from(0x2222),
            t_replay,
            &mut c_scheduler,
        );
        let resp_second = a_ep.recv([init_second]);
        assert!(
            resp_second.to_peers.is_empty(),
            "an equal-timestamp initiation is a replay and must produce no response"
        );
        assert!(
            resp_second.to_local.is_empty(),
            "a replayed initiation delivers no local payload"
        );
        assert_eq!(
            a_ep.session_id_count(),
            1,
            "a replayed initiation must not allocate a new receive id (still exactly one)"
        );
    }

    /// Regression test for issue #20 (asymmetric convergence / orphaned-responder path — reviewer
    /// R1).
    ///
    /// A simultaneous initiation can resolve *asymmetrically*: one peer's INITIATOR side completes
    /// and carries the live session, while that same peer's tentative RESPONDER session (created
    /// because it still had to answer the other peer's msg1) never receives a confirming transport
    /// packet — the peer's own initiator session won the race instead. That tentative responder is
    /// orphaned. This test reproduces exactly that, deterministically, by driving the simultaneous
    /// race and then *withholding* A's handshake response to B (so B's initiator never finishes and
    /// A's responder session is never confirmed). We assert:
    /// (a) the tunnel still works — data flows BOTH ways on the converged (A-initiator ↔
    ///     B-responder) pair, i.e. no wedge despite A's orphaned responder;
    /// (b) the orphan is BOUNDED — A holds exactly two ids (one live + one orphan) and that count
    ///     does NOT grow as more data flows (the `responded` slot is a single `Option`, so a later
    ///     initiation/confirm/teardown can only ever *replace* the one orphan, never accumulate);
    /// (c) on teardown A's `session_id_count` returns to baseline — the orphaned responder id is
    ///     reclaimed (`shutdown` → `remove_handshake_session` frees the lingering `responded` id),
    ///     so the orphan is not a leak.
    ///
    /// What is covered vs manual: the orphan being *reclaimed on teardown* (c) and *bounded to one*
    /// (b) are fully exercised here. The other reclaim triggers the bound relies on — a later
    /// `respond` displacing the orphan (the displaced-id free path) and a `handshake_timeout` firing
    /// `remove_handshake_session` — are exercised by `fresh_initiation_frees_displaced_responder_id`
    /// and the existing timeout handling respectively; this test deliberately holds the orphan
    /// *static* to prove it neither grows nor wedges the live session.
    ///
    /// Deterministic: pure message passing, no timers dispatched, no real sleeps.
    #[test]
    fn asymmetric_simultaneous_initiation_orphans_responder_without_wedge() {
        let (a_static, b_static) = (NodeKeyPair::new(), NodeKeyPair::new());
        let psk = rand::random::<crate::config::Psk>();
        let (mut a_ep, mut b_ep) = (
            Endpoint::new(a_static.clone()),
            Endpoint::new(b_static.clone()),
        );
        let (a_peer, b_peer) = (PeerId(1), PeerId(1));

        a_ep.upsert_peer(
            a_peer,
            PeerConfig {
                key: b_static.public,
                psk: psk.clone(),
                persistent_keepalive_interval: None,
            },
        );
        b_ep.upsert_peer(
            b_peer,
            PeerConfig {
                key: a_static.public,
                psk: psk.clone(),
                persistent_keepalive_interval: None,
            },
        );

        // (1) Simultaneous initiation: both peers send before seeing the other's msg1.
        let init_a = a_ep.send(HashMap::from([(
            a_peer,
            vec![PacketMut::from(&b"a-first"[..])],
        )]));
        let init_a = only_to_peer(&init_a.to_peers, a_peer, "A's handshake init");
        let init_b = b_ep.send(HashMap::from([(
            b_peer,
            vec![PacketMut::from(&b"b-first"[..])],
        )]));
        let init_b = only_to_peer(&init_b.to_peers, b_peer, "B's handshake init");

        // (2) Each delivers its initiation to the other. Both now hold BOTH roles (initiator +
        // responder) and two ids each. We keep B's response to A but DROP A's response to B.
        let resp_to_a = b_ep.recv(init_a);
        let resp_to_a = only_to_peer(&resp_to_a.to_peers, b_peer, "B's response to A");
        let resp_to_b = a_ep.recv(init_b);
        only_to_peer(&resp_to_b.to_peers, a_peer, "A's response to B");
        // ^ Deliberately NOT delivered to B: this is what orphans A's responder session.
        assert_eq!(
            a_ep.session_id_count(),
            2,
            "A holds an initiator id and a (soon-to-be-orphaned) responder id"
        );

        // (3) Only A's initiator completes (A receives B's response). A activates its initiator
        // session and flushes its primed first packet. A's responder session stays tentative — it
        // is now the orphan, since B will never confirm it.
        let data_from_a = a_ep.recv(resp_to_a);
        let data_from_a = only_to_peer(&data_from_a.to_peers, a_peer, "A's first transport packet");

        // (4) B confirms its RESPONDER session with A's first transport packet → the (A-initiator ↔
        // B-responder) session converges and A's primed payload reaches B.
        let delivered_to_b = b_ep.recv(data_from_a);
        assert_eq!(
            delivered_to_b.to_local.get(&b_peer).map(|p| p.as_slice()),
            Some([pad16(b"a-first")].as_slice()),
            "A's primed payload must reach B on the converged session"
        );

        // (a) The tunnel works BOTH ways on the converged pair, despite A's orphaned responder.
        let a_payload = b"a->b-live";
        let to_b = a_ep.send(HashMap::from([(
            a_peer,
            vec![PacketMut::from(&a_payload[..])],
        )]));
        let to_b = only_to_peer(&to_b.to_peers, a_peer, "A->B live data");
        assert_eq!(
            b_ep.recv(to_b).to_local.get(&b_peer).map(|p| p.as_slice()),
            Some([pad16(a_payload)].as_slice()),
            "fresh A->B data must flow even though A holds an orphaned responder session"
        );
        let b_payload = b"b->a-live";
        let to_a = b_ep.send(HashMap::from([(
            b_peer,
            vec![PacketMut::from(&b_payload[..])],
        )]));
        let to_a = only_to_peer(&to_a.to_peers, b_peer, "B->A live data");
        assert_eq!(
            a_ep.recv(to_a).to_local.get(&a_peer).map(|p| p.as_slice()),
            Some([pad16(b_payload)].as_slice()),
            "fresh B->A data must flow on the converged session (no wedge)"
        );

        // (b) The orphan is BOUNDED: A still holds exactly two ids (one live recv + one orphaned
        // responder) — and crucially it did NOT grow while real data flowed above. A single
        // `Option` responder slot means an orphan can only ever be replaced, never accumulated.
        assert_eq!(
            a_ep.session_id_count(),
            2,
            "A's orphaned responder id must be bounded (one live + one orphan), not accumulating"
        );

        // (c) Teardown reclaims everything, including the orphaned responder id — no leak. (A
        // double-free of the orphan would panic in the id map's `remove_session` unwrap right here.)
        assert!(a_ep.remove_peer(a_peer), "A's peer should exist");
        assert_eq!(
            a_ep.session_id_count(),
            0,
            "teardown must reclaim A's orphaned responder id — back to baseline, no leak"
        );
        // B, whose own initiator is still in flight (its response was dropped), likewise reclaims
        // both its converged responder id and its in-flight initiator id on teardown.
        assert!(b_ep.remove_peer(b_peer), "B's peer should exist");
        assert_eq!(
            b_ep.session_id_count(),
            0,
            "teardown must reclaim B's live and in-flight ids — no leak"
        );
    }
}
