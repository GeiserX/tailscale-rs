//! The UDP socket engine: one socket carrying disco + WireGuard, demuxed by magic prefix.

use core::net::{IpAddr, SocketAddr};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Instant,
};

use tokio::{net::UdpSocket, sync::mpsc};
use ts_keys::{DiscoPrivateKey, DiscoPublicKey, NodePublicKey};
use ts_packet::PacketMut;
use ts_transport::{BatchRecvIter, BatchSendIter, UnderlayTransport};

use crate::{
    disco::{self, Inbound},
    endpoint::{SelfEndpoint, SelfEndpointType},
    error::Error,
    path::PeerPaths,
};

/// Maximum UDP datagram we will read. Tailscale uses 1280-byte WireGuard MTU; round up for
/// disco and headers.
const RECV_BUF: usize = 1600;

/// A WireGuard datagram received from a peer over a confirmed direct path, tagged with the
/// disco key of the peer it came from (resolved to a [`NodePublicKey`] by the caller).
#[derive(Debug)]
pub struct ReceivedData {
    /// The disco key of the sender (the magicsock identity; the route layer maps this to a
    /// node/peer id).
    pub from_disco: DiscoPublicKey,
    /// The source address the datagram arrived from.
    pub from_addr: SocketAddr,
    /// The WireGuard datagram payload.
    pub data: PacketMut,
}

/// Shared, per-peer path state keyed by the peer's disco key.
type Paths = Arc<Mutex<HashMap<DiscoPublicKey, PeerPaths>>>;

/// Whether a peer-supplied candidate endpoint is safe to probe with a disco ping.
///
/// Disco datagrams are emitted from the node's single real host socket, so a candidate
/// address advertised by a remote peer (in a `CallMeMaybe`, or as a ping/data source) is an
/// attacker-controllable target: an authenticated-but-malicious tailnet peer could otherwise
/// make this node spray host-sourced UDP probes at arbitrary hosts (an SSRF-style internal
/// scan, or a reachability oracle via pong timing). This filter is the choke point that drops
/// addresses that must never be probed, fail-closed (drop on any doubt).
///
/// Rejected:
/// - any IPv6 address — the underlay is IPv4-only in this deployment (IPv6 is disabled), so an
///   IPv6 candidate can only be noise or an attempt to reach a forbidden surface;
/// - unspecified (`0.0.0.0`);
/// - loopback (`127.0.0.0/8`) — would let a peer probe this host's own services;
/// - link-local (`169.254.0.0/16`);
/// - multicast and broadcast (`255.255.255.255`);
/// - RFC1918 private ranges (`10/8`, `172.16/12`, `192.168/16`). This fork's topology is
///   known-public-VPS (see `path.rs`); there is no supported direct-LAN connectivity path, so
///   private candidates are dropped rather than letting a peer steer host-sourced probes onto
///   the local network. If LAN connectivity ever becomes a supported path, relax *only* this
///   clause and keep every other rejection.
///
/// Accepted: any other (public, routable) IPv4 address.
fn is_pingable_candidate(addr: &SocketAddr) -> bool {
    let ip = match addr.ip() {
        IpAddr::V4(ip) => ip,
        // IPv6 underlay is disabled; never probe an IPv6 candidate.
        IpAddr::V6(_) => return false,
    };

    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_private()
    {
        return false;
    }

    true
}

/// A direct UDP transport over a single shared socket.
///
/// Construct with [`MagicSock::bind`], then:
/// - register peers with [`MagicSock::add_peer_endpoints`] as the netmap provides them,
/// - drive discovery with [`MagicSock::send_pings`] (periodically),
/// - pump inbound traffic by calling [`MagicSock::recv_data`] in a loop (it handles disco
///   internally and only yields WireGuard data),
/// - send WireGuard data with [`MagicSock::send_wireguard`].
pub struct MagicSock {
    sock: Arc<UdpSocket>,
    our_disco: DiscoPrivateKey,
    our_node_key: NodePublicKey,
    paths: Paths,
    /// Maps an observed source address back to the disco key that owns it, so inbound
    /// WireGuard data (which has no disco header) can be attributed to a peer.
    ///
    /// Locking discipline: `paths`, `addr_to_disco`, and `reflexive` are always locked
    /// *disjointly* — every method releases one before taking another, never nesting them. Keep
    /// it that way; do not hold two at once, or the inconsistent acquisition order across methods
    /// becomes a deadlock.
    addr_to_disco: Arc<Mutex<HashMap<SocketAddr, DiscoPublicKey>>>,
    /// Reflexive (STUN-equivalent) addresses peers have observed our traffic arriving from,
    /// learned from the `src` echoed in disco pongs. These are advertised to control and offered
    /// in `CallMeMaybe` so peers behind NAT can reach us. Learned only on this one socket — never
    /// a second egress.
    reflexive: Arc<Mutex<HashSet<SocketAddr>>>,
}

impl MagicSock {
    /// Bind the underlay UDP socket.
    ///
    /// Per the anti-leak rules this socket is the only egress path; bind it to the address
    /// the deployment wants traffic to originate from. IPv4 only in our deployment (IPv6 is
    /// disabled), but any bindable [`SocketAddr`] is accepted.
    pub async fn bind(
        bind_addr: SocketAddr,
        our_disco: DiscoPrivateKey,
        our_node_key: NodePublicKey,
    ) -> Result<Self, Error> {
        let sock = UdpSocket::bind(bind_addr).await?;
        Ok(Self {
            sock: Arc::new(sock),
            our_disco,
            our_node_key,
            paths: Default::default(),
            addr_to_disco: Default::default(),
            reflexive: Default::default(),
        })
    }

    /// The local address the underlay socket is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        Ok(self.sock.local_addr()?)
    }

    /// Our candidate self-endpoints: the bound local address plus every reflexive address peers
    /// have observed our traffic arriving from.
    ///
    /// Returned for advertisement to control and for `CallMeMaybe`. All addresses were observed on
    /// the single bound underlay socket — there is no second egress. The local address is always
    /// present (available from bind); reflexive addresses accrue as pongs arrive, so before any
    /// direct path is confirmed this returns just the local address.
    pub fn self_endpoints(&self) -> Vec<SelfEndpoint> {
        let mut eps = Vec::new();

        if let Ok(local) = self.local_addr() {
            eps.push(SelfEndpoint {
                addr: local,
                ty: SelfEndpointType::Local,
            });
        }

        let reflexive = self.reflexive.lock().unwrap();
        for addr in reflexive.iter() {
            eps.push(SelfEndpoint {
                addr: *addr,
                ty: SelfEndpointType::Stun,
            });
        }

        eps
    }

    /// Seal a disco `CallMeMaybe` addressed to `receiver`, carrying our candidate endpoints so the
    /// peer will disco-ping us and open a direct path. Sent over DERP by the caller.
    ///
    /// The endpoint set is exactly [`MagicSock::self_endpoints`] — the same addresses already
    /// advertised to control — and every one of them was observed on this single bound socket. No
    /// host-identifying address beyond what control already receives is disclosed, preserving the
    /// anti-leak posture.
    pub fn seal_call_me_maybe(&self, receiver: &DiscoPublicKey) -> Result<Vec<u8>, Error> {
        let endpoints: Vec<SocketAddr> =
            self.self_endpoints().into_iter().map(|e| e.addr).collect();
        Ok(disco::seal_call_me_maybe(
            &self.our_disco,
            receiver,
            &endpoints,
        )?)
    }

    /// Register (or extend) the candidate endpoints for a peer learned from authenticated disco
    /// traffic (an inbound ping's source address, or a CallMeMaybe). These are preserved across
    /// netmap reconciliation; only [`MagicSock::set_netmap_endpoints`] prunes control-advertised
    /// paths.
    pub fn add_peer_endpoints(
        &self,
        peer: DiscoPublicKey,
        endpoints: impl IntoIterator<Item = SocketAddr>,
    ) {
        // These addresses are peer-supplied (a CallMeMaybe's endpoint list, or an inbound
        // ping's source). Sanitize them before they can become disco-ping targets emitted from
        // the real host socket: drop anything that must never be probed (loopback, link-local,
        // private, multicast, IPv6, etc). Fail-closed — a dropped candidate just means the peer
        // stays on DERP, which is the safe default. See [`is_pingable_candidate`].
        let eps: Vec<SocketAddr> = endpoints
            .into_iter()
            .filter(|ep| {
                let ok = is_pingable_candidate(ep);
                if !ok {
                    tracing::debug!(%ep, "dropping non-pingable peer candidate endpoint");
                }
                ok
            })
            .collect();

        if eps.is_empty() {
            return;
        }

        {
            let mut a2d = self.addr_to_disco.lock().unwrap();
            for ep in &eps {
                a2d.insert(*ep, peer);
            }
        }

        let mut paths = self.paths.lock().unwrap();
        paths.entry(peer).or_default().add_learned_candidates(eps);
    }

    /// Test-only: register candidate endpoints *without* the [`is_pingable_candidate`] filter.
    ///
    /// The end-to-end tests run two magicsocks over loopback, but loopback is (correctly)
    /// rejected by the production filter. This seam lets those tests exercise the real
    /// ping/pong/data path over loopback without weakening the filter that guards the live
    /// entry point [`MagicSock::add_peer_endpoints`].
    #[cfg(test)]
    fn add_peer_endpoints_unfiltered(
        &self,
        peer: DiscoPublicKey,
        endpoints: impl IntoIterator<Item = SocketAddr>,
    ) {
        let eps: Vec<SocketAddr> = endpoints.into_iter().collect();
        {
            let mut a2d = self.addr_to_disco.lock().unwrap();
            for ep in &eps {
                a2d.insert(*ep, peer);
            }
        }
        let mut paths = self.paths.lock().unwrap();
        paths.entry(peer).or_default().add_learned_candidates(eps);
    }

    /// Reconcile a peer's control-advertised endpoints to exactly `endpoints`.
    ///
    /// This is the authoritative netmap path: endpoints control no longer advertises are pruned
    /// (and their `addr -> disco` attribution dropped), so a revoked or reassigned address can no
    /// longer be re-confirmed as a direct path. If pruning removes the peer's current best path,
    /// the path is cleared and the peer fails closed to DERP until a surviving endpoint
    /// re-confirms. Learned (disco) candidates are left intact.
    pub fn set_netmap_endpoints(
        &self,
        peer: DiscoPublicKey,
        endpoints: impl IntoIterator<Item = SocketAddr>,
    ) {
        let eps: Vec<SocketAddr> = endpoints.into_iter().collect();

        let removed = {
            let mut paths = self.paths.lock().unwrap();
            paths
                .entry(peer)
                .or_default()
                .reconcile_netmap_candidates(eps.iter().copied())
        };

        let mut a2d = self.addr_to_disco.lock().unwrap();
        for ep in &eps {
            a2d.insert(*ep, peer);
        }
        // Only drop a reverse mapping if it still points at this peer (a learned candidate or a
        // later netmap update may have re-claimed the address).
        for addr in removed {
            if a2d.get(&addr) == Some(&peer) {
                a2d.remove(&addr);
            }
        }
    }

    /// Drop all path state for peers absent from `live`.
    ///
    /// Called after a netmap update so peers removed from the tailnet stop being ping targets and
    /// release their `addr -> disco` attributions, bounding the growth of both maps.
    pub fn retain_peers(&self, live: &std::collections::HashSet<DiscoPublicKey>) {
        let mut paths = self.paths.lock().unwrap();
        paths.retain(|peer, _| live.contains(peer));
        drop(paths);

        let mut a2d = self.addr_to_disco.lock().unwrap();
        a2d.retain(|_, peer| live.contains(peer));
    }

    /// Send a disco ping to every candidate endpoint of every known peer whose path needs
    /// (re)confirmation. Returns the number of pings sent.
    ///
    /// Call this periodically and on path-trust expiry to keep direct paths alive.
    pub async fn send_pings(&self) -> Result<usize, Error> {
        let now = Instant::now();

        // Snapshot the work to do without holding the lock across awaits.
        let mut to_ping: Vec<(DiscoPublicKey, SocketAddr, disco::TxId)> = Vec::new();
        {
            let mut paths = self.paths.lock().unwrap();
            for (peer, pp) in paths.iter_mut() {
                if !pp.needs_refresh(now) {
                    continue;
                }
                for addr in pp.candidate_addrs() {
                    let tx_id = disco::random_tx_id();
                    pp.note_ping_sent(tx_id, addr, now);
                    to_ping.push((*peer, addr, tx_id));
                }
            }
        }

        let mut sent = 0;
        for (peer, addr, tx_id) in to_ping {
            let wire = disco::seal_ping(&self.our_disco, self.our_node_key, &peer, tx_id)?;
            self.sock.send_to(&wire, addr).await?;
            sent += 1;
        }

        Ok(sent)
    }

    /// The current best confirmed direct address for a peer, or `None` if there is no
    /// trusted direct path (caller must use DERP — never the host network).
    pub fn best_addr(&self, peer: &DiscoPublicKey) -> Option<SocketAddr> {
        let paths = self.paths.lock().unwrap();
        paths.get(peer)?.best_addr(Instant::now())
    }

    /// Send a WireGuard datagram to a peer over its confirmed direct path.
    ///
    /// Fails with [`Error::NoPath`] if no trusted direct path exists. This is deliberately a
    /// hard error: the caller keeps the peer on DERP rather than leaking via a host dial.
    pub async fn send_wireguard(&self, peer: &DiscoPublicKey, data: &[u8]) -> Result<(), Error> {
        let addr = self.best_addr(peer).ok_or(Error::NoPath)?;
        self.sock.send_to(data, addr).await?;
        Ok(())
    }

    /// Receive the next WireGuard datagram, handling any disco traffic inline.
    ///
    /// This loops internally: disco pings are answered with pongs, disco pongs update path
    /// state, and the first non-disco (WireGuard) datagram is returned. Returns `Ok(None)`
    /// only if the socket is closed.
    pub async fn recv_data(&self) -> Result<Option<ReceivedData>, Error> {
        let mut buf = vec![0u8; RECV_BUF];

        loop {
            let (n, from) = self.sock.recv_from(&mut buf).await?;
            let datagram = &mut buf[..n];

            if !disco::looks_like_disco(datagram) {
                // WireGuard data: attribute it to the peer that owns this source address.
                let from_disco = {
                    let a2d = self.addr_to_disco.lock().unwrap();
                    a2d.get(&from).copied()
                };

                let Some(from_disco) = from_disco else {
                    tracing::trace!(%from, "dropping data from unknown source address");
                    continue;
                };

                return Ok(Some(ReceivedData {
                    from_disco,
                    from_addr: from,
                    data: PacketMut::from(&*datagram),
                }));
            }

            // Disco control traffic: handle it and keep looping for data.
            match disco::open(&self.our_disco, datagram) {
                Ok(msg) => self.handle_disco(msg, from).await?,
                Err(e) => tracing::trace!(error = %e, %from, "ignoring undecodable disco datagram"),
            }
        }
    }

    async fn handle_disco(&self, msg: Inbound, from: SocketAddr) -> Result<(), Error> {
        match msg {
            Inbound::Ping {
                sender,
                tx_id,
                claimed_node_key: _,
            } => {
                // The ping carries a `claimed_node_key`, which disco intends to be cross-checked
                // against the control netmap (does this disco key really belong to this node
                // key?). That binding cannot be enforced at this layer: `MagicSock` has no netmap
                // / disco-key->node-key map (see the struct fields above), only path state keyed
                // by disco key. The check therefore lives in the route layer that owns the
                // netmap. We deliberately do not fabricate a half-check here. The ping is still
                // authenticated (it opened under our disco key), so learning the source and
                // ponging is sound; it just is not yet bound to a control-advertised node key.
                // TODO(parity): enforce the disco<->node-key binding in the netmap-owning layer.
                //
                // Learn this source as a candidate path for the sender and answer the ping.
                self.add_peer_endpoints(sender, [from]);
                let pong = disco::seal_pong(&self.our_disco, &sender, tx_id, from)?;
                self.sock.send_to(&pong, from).await?;
            }
            Inbound::Pong { sender, tx_id, src } => {
                {
                    let mut paths = self.paths.lock().unwrap();
                    if let Some(pp) = paths.get_mut(&sender) {
                        pp.note_pong(tx_id, Instant::now());
                    }
                }
                // The peer echoed the address it saw our ping arrive from: that is our reflexive
                // (STUN-equivalent) endpoint on this path. Retain it for advertisement. Locked
                // disjointly from `paths` above (never nested).
                self.reflexive.lock().unwrap().insert(src);
            }
            Inbound::CallMeMaybe { sender, endpoints } => {
                self.add_peer_endpoints(sender, endpoints);
            }
        }
        Ok(())
    }
}

impl AsRef<MagicSock> for MagicSock {
    fn as_ref(&self) -> &MagicSock {
        self
    }
}

/// A [`MagicSock`]-backed [`UnderlayTransport`] whose peer key is the peer's disco key.
///
/// `send` dispatches each datagram over the peer's confirmed direct path (or drops it with a
/// trace if there is no path — the data plane will retransmit, and the route layer keeps the
/// peer on DERP). `recv` yields one batch of WireGuard datagrams.
pub struct DirectTransport {
    inner: Arc<MagicSock>,
    /// Buffers data received via the background pump so `recv` can hand it to the runtime.
    inbox: tokio::sync::Mutex<mpsc::UnboundedReceiver<ReceivedData>>,
    _pump: tokio::task::JoinHandle<()>,
}

impl DirectTransport {
    /// Wrap a [`MagicSock`] and spawn the receive pump that feeds [`UnderlayTransport::recv`].
    pub fn new(inner: Arc<MagicSock>) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let pump_sock = inner.clone();
        let pump = tokio::spawn(async move {
            loop {
                match pump_sock.recv_data().await {
                    Ok(Some(data)) => {
                        if tx.send(data).is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        tracing::warn!(error = %e, "magicsock recv pump error");
                        break;
                    }
                }
            }
        });

        Self {
            inner,
            inbox: tokio::sync::Mutex::new(rx),
            _pump: pump,
        }
    }

    /// Access the underlying socket (to register endpoints, send pings, etc).
    pub fn sock(&self) -> &Arc<MagicSock> {
        &self.inner
    }
}

impl Drop for DirectTransport {
    fn drop(&mut self) {
        self._pump.abort();
    }
}

impl UnderlayTransport for DirectTransport {
    type PeerKey = DiscoPublicKey;
    type Error = Error;

    async fn send(
        &self,
        packet_batch: impl BatchSendIter<Self::PeerKey>,
    ) -> Result<(), Self::Error> {
        for (peer, pkts) in packet_batch.batch_iter() {
            for pkt in pkts {
                match self.inner.send_wireguard(&peer, pkt.as_ref()).await {
                    Ok(()) => {}
                    Err(Error::NoPath) => {
                        // No direct path: drop here, fail-closed. The route layer keeps this
                        // peer on DERP; we never dial the host network directly.
                        tracing::trace!(%peer, "no direct path, dropping (peer stays on DERP)");
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(())
    }

    async fn recv(&self) -> impl BatchRecvIter<Self::PeerKey, Error = Self::Error> {
        let received = {
            let mut inbox = self.inbox.lock().await;
            inbox.recv().await
        };

        match received {
            Some(data) => vec![Ok((data.from_disco, [data.data]))],
            None => vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn localhost() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    #[test]
    fn is_pingable_candidate_rejects_forbidden_classes() {
        // Each must be dropped before it can become a host-sourced ping target.
        let forbidden: &[&str] = &[
            "0.0.0.0:41641",         // unspecified
            "127.0.0.1:41641",       // loopback
            "127.5.6.7:41641",       // loopback (whole /8)
            "169.254.1.1:41641",     // link-local
            "224.0.0.1:41641",       // multicast
            "255.255.255.255:41641", // broadcast
            "10.0.0.5:41641",        // RFC1918 (10/8)
            "172.16.3.4:41641",      // RFC1918 (172.16/12)
            "192.168.1.1:41641",     // RFC1918 (192.168/16)
            "[::1]:41641",           // IPv6 loopback (underlay is IPv4-only)
            "[2001:db8::1]:41641",   // IPv6 public (still dropped: no IPv6 underlay)
        ];
        for s in forbidden {
            let addr: SocketAddr = s.parse().unwrap();
            assert!(
                !is_pingable_candidate(&addr),
                "{s} must be rejected as a ping candidate"
            );
        }
    }

    #[test]
    fn is_pingable_candidate_accepts_public_ipv4() {
        // Documentation/test ranges (RFC5737) are public/routable from the filter's view.
        for s in ["203.0.113.7:41641", "198.51.100.2:3478"] {
            let addr: SocketAddr = s.parse().unwrap();
            assert!(
                is_pingable_candidate(&addr),
                "{s} should be accepted as a ping candidate"
            );
        }
    }

    /// A peer-supplied candidate that is a forbidden target (e.g. a loopback or private
    /// address) must never be learned as a path, so `send_pings` cannot emit a host-sourced
    /// probe to it. A public candidate offered alongside it is still accepted.
    #[tokio::test]
    async fn add_peer_endpoints_drops_forbidden_candidates() {
        let a = MagicSock::bind(
            localhost(),
            DiscoPrivateKey::random(),
            ts_keys::NodePrivateKey::random().public_key(),
        )
        .await
        .unwrap();

        let peer = DiscoPrivateKey::random().public_key();
        let loopback: SocketAddr = "127.0.0.1:41641".parse().unwrap();
        let private: SocketAddr = "192.168.1.50:41641".parse().unwrap();
        let public: SocketAddr = "203.0.113.9:41641".parse().unwrap();

        a.add_peer_endpoints(peer, [loopback, private, public]);

        let candidates = {
            let paths = a.paths.lock().unwrap();
            paths.get(&peer).unwrap().candidate_addrs()
        };
        assert_eq!(
            candidates,
            vec![public],
            "only the public candidate should be retained: {candidates:?}"
        );

        // And the reverse attribution map must not have learned the forbidden addresses.
        let a2d = a.addr_to_disco.lock().unwrap();
        assert!(a2d.contains_key(&public), "public addr is attributed");
        assert!(!a2d.contains_key(&loopback), "loopback must not be learned");
        assert!(!a2d.contains_key(&private), "private must not be learned");
    }

    /// If every offered candidate is forbidden, the peer is not even created as a paths entry
    /// (nothing to ping), and no attribution is learned.
    #[tokio::test]
    async fn add_peer_endpoints_all_forbidden_is_noop() {
        let a = MagicSock::bind(
            localhost(),
            DiscoPrivateKey::random(),
            ts_keys::NodePrivateKey::random().public_key(),
        )
        .await
        .unwrap();

        let peer = DiscoPrivateKey::random().public_key();
        a.add_peer_endpoints(
            peer,
            [
                "127.0.0.1:1".parse().unwrap(),
                "10.0.0.1:2".parse().unwrap(),
            ],
        );

        assert!(
            a.paths.lock().unwrap().get(&peer).is_none(),
            "no path entry should be created for an all-forbidden candidate set"
        );
        assert!(
            a.addr_to_disco.lock().unwrap().is_empty(),
            "no attribution should be learned"
        );
    }

    /// Two magicsocks on loopback: A pings B's endpoint, B pongs, A confirms a direct path,
    /// then A sends WireGuard data that B receives. This is the npts.4 MVP end-to-end with
    /// no control server or DERP.
    #[tokio::test]
    async fn direct_path_confirms_and_carries_data() {
        let a_disco = DiscoPrivateKey::random();
        let b_disco = DiscoPrivateKey::random();
        let a_node = ts_keys::NodePrivateKey::random().public_key();
        let b_node = ts_keys::NodePrivateKey::random().public_key();

        let a = Arc::new(MagicSock::bind(localhost(), a_disco, a_node).await.unwrap());
        let b = Arc::new(MagicSock::bind(localhost(), b_disco, b_node).await.unwrap());

        let a_addr = a.local_addr().unwrap();
        let b_addr = b.local_addr().unwrap();

        // The production candidate filter (correctly) rejects loopback, so seed both directions
        // through the test-only unfiltered seam to exercise the real ping/pong/data path here.
        b.add_peer_endpoints_unfiltered(a_disco.public_key(), [a_addr]);

        // Run B's receive loop in the background; it answers pings and yields data.
        let b_for_pump = b.clone();
        let (data_tx, mut data_rx) = mpsc::unbounded_channel();
        let pump = tokio::spawn(async move {
            while let Ok(Some(d)) = b_for_pump.recv_data().await {
                drop(data_tx.send(d));
            }
        });

        // Run A's receive loop too: it never yields here (only pongs arrive), but it must
        // run so the pong is processed and the path confirmed as a side effect of looping.
        let a_for_pump = a.clone();
        let a_pump =
            tokio::spawn(async move { while let Ok(Some(_)) = a_for_pump.recv_data().await {} });

        // A learns B's endpoint and pings it.
        a.add_peer_endpoints_unfiltered(b_disco.public_key(), [b_addr]);
        let sent = a.send_pings().await.unwrap();
        assert_eq!(sent, 1, "should ping B's one endpoint");

        // Wait for A to confirm a direct path to B (driven by the background pong handling).
        let confirm = async {
            loop {
                if a.best_addr(&b_disco.public_key()).is_some() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(2), confirm)
            .await
            .expect("timed out waiting for path confirmation");

        let best = a.best_addr(&b_disco.public_key());
        assert_eq!(
            best,
            Some(b_addr),
            "A should have confirmed a direct path to B"
        );

        // Now A sends WireGuard data to B over the direct path.
        a.send_wireguard(&b_disco.public_key(), b"hello-wireguard")
            .await
            .unwrap();

        let got = tokio::time::timeout(std::time::Duration::from_secs(2), data_rx.recv())
            .await
            .expect("timed out waiting for data")
            .expect("data channel closed");

        assert_eq!(got.data.as_ref(), b"hello-wireguard");
        assert_eq!(got.from_disco, a_disco.public_key());

        pump.abort();
        a_pump.abort();
    }

    /// Before any pong, `self_endpoints` reports only the bound local address (no reflexive addr
    /// is known yet). After A pings B and B pongs, A has learned its reflexive address from the
    /// echoed `src` and reports it as a `Stun` endpoint — all on the one bound socket.
    #[tokio::test]
    async fn self_endpoints_learns_reflexive_from_pong() {
        let a_disco = DiscoPrivateKey::random();
        let b_disco = DiscoPrivateKey::random();
        let a_node = ts_keys::NodePrivateKey::random().public_key();
        let b_node = ts_keys::NodePrivateKey::random().public_key();

        let a = Arc::new(MagicSock::bind(localhost(), a_disco, a_node).await.unwrap());
        let b = Arc::new(MagicSock::bind(localhost(), b_disco, b_node).await.unwrap());
        let a_addr = a.local_addr().unwrap();
        let b_addr = b.local_addr().unwrap();

        // Before any disco exchange: only the local endpoint, no reflexive.
        let before = a.self_endpoints();
        assert_eq!(before.len(), 1, "only local before any pong: {before:?}");
        assert_eq!(before[0].ty, SelfEndpointType::Local);
        assert_eq!(before[0].addr, a_addr);

        // Run both receive loops so pings get ponged and pongs get processed.
        let b_for_pump = b.clone();
        let b_pump =
            tokio::spawn(async move { while let Ok(Some(_)) = b_for_pump.recv_data().await {} });
        let a_for_pump = a.clone();
        let a_pump =
            tokio::spawn(async move { while let Ok(Some(_)) = a_for_pump.recv_data().await {} });

        // Loopback is rejected by the production filter; use the test-only unfiltered seam.
        a.add_peer_endpoints_unfiltered(b_disco.public_key(), [b_addr]);
        a.send_pings().await.unwrap();

        // Wait until A has learned a reflexive endpoint (driven by B's pong echoing A's src).
        let learned = async {
            loop {
                if a.self_endpoints()
                    .iter()
                    .any(|e| e.ty == SelfEndpointType::Stun)
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(2), learned)
            .await
            .expect("timed out waiting to learn a reflexive endpoint");

        let eps = a.self_endpoints();
        let stun: Vec<_> = eps
            .iter()
            .filter(|e| e.ty == SelfEndpointType::Stun)
            .collect();
        assert_eq!(stun.len(), 1, "exactly one reflexive endpoint: {eps:?}");
        // On loopback the reflexive address B observed is A's own bound address.
        assert_eq!(stun[0].addr, a_addr, "reflexive addr is A's loopback src");
        assert!(
            eps.iter().any(|e| e.ty == SelfEndpointType::Local),
            "local endpoint still present"
        );

        a_pump.abort();
        b_pump.abort();
    }

    #[tokio::test]
    async fn seal_call_me_maybe_carries_self_endpoints() {
        let a_disco = DiscoPrivateKey::random();
        let b_disco = DiscoPrivateKey::random();
        let a_node = ts_keys::NodePrivateKey::random().public_key();

        let a = MagicSock::bind(localhost(), a_disco, a_node).await.unwrap();
        let a_addr = a.local_addr().unwrap();

        // Seal a CallMeMaybe addressed to B and confirm B can open it and sees A's local endpoint.
        let mut frame = a.seal_call_me_maybe(&b_disco.public_key()).unwrap();
        assert!(
            disco::looks_like_disco(&frame),
            "sealed call-me-maybe must demux as disco"
        );

        match disco::open(&b_disco, &mut frame).unwrap() {
            Inbound::CallMeMaybe { sender, endpoints } => {
                assert_eq!(sender, a_disco.public_key(), "sender is A's disco key");
                assert!(
                    endpoints.contains(&a_addr),
                    "call-me-maybe carries A's local endpoint: {endpoints:?}"
                );
            }
            other => panic!("expected CallMeMaybe, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_without_path_is_no_path_error() {
        let a = MagicSock::bind(
            localhost(),
            DiscoPrivateKey::random(),
            ts_keys::NodePrivateKey::random().public_key(),
        )
        .await
        .unwrap();

        let unknown = DiscoPrivateKey::random().public_key();
        let err = a.send_wireguard(&unknown, b"x").await.unwrap_err();
        assert!(matches!(err, Error::NoPath), "got {err:?}");
    }

    /// Drive the full `UnderlayTransport` surface: A confirms a direct path to B (via the
    /// `DirectTransport` recv pump answering pings), then `send` carries WireGuard data that
    /// B's `recv` yields, keyed by A's disco key.
    #[tokio::test]
    async fn direct_transport_send_recv_roundtrip() {
        use ts_transport::{BatchRecvIter, UnderlayTransport};

        let a_disco = DiscoPrivateKey::random();
        let b_disco = DiscoPrivateKey::random();
        let a_node = ts_keys::NodePrivateKey::random().public_key();
        let b_node = ts_keys::NodePrivateKey::random().public_key();

        let a_sock = Arc::new(MagicSock::bind(localhost(), a_disco, a_node).await.unwrap());
        let b_sock = Arc::new(MagicSock::bind(localhost(), b_disco, b_node).await.unwrap());
        let a_addr = a_sock.local_addr().unwrap();
        let b_addr = b_sock.local_addr().unwrap();

        // Loopback is rejected by the production filter; seed both directions via the test-only
        // unfiltered seam so the real ping/pong/data path is exercised over loopback.
        b_sock.add_peer_endpoints_unfiltered(a_disco.public_key(), [a_addr]);

        // Wrap both in DirectTransport: each spawns a recv pump that answers pings/pongs.
        let a_xport = DirectTransport::new(a_sock.clone());
        let b_xport = DirectTransport::new(b_sock);

        // A learns B's endpoint and pings it; the pumps confirm the path.
        a_sock.add_peer_endpoints_unfiltered(b_disco.public_key(), [b_addr]);
        a_sock.send_pings().await.unwrap();

        let confirm = async {
            loop {
                if a_sock.best_addr(&b_disco.public_key()).is_some() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(2), confirm)
            .await
            .expect("timed out waiting for path confirmation");

        // Send WireGuard data through the transport, keyed by B's disco key.
        let pkt = PacketMut::from(&b"hello-transport"[..]);
        a_xport
            .send([(b_disco.public_key(), vec![pkt])])
            .await
            .unwrap();

        // B's transport recv yields the datagram, attributed to A's disco key.
        let batch = tokio::time::timeout(std::time::Duration::from_secs(2), b_xport.recv())
            .await
            .expect("timed out waiting for transport recv");

        let mut got = batch.batch_iter();
        let (from, pkts) = got.next().expect("expected one batch entry").unwrap();
        assert_eq!(from, a_disco.public_key());
        let data: Vec<_> = pkts.into_iter().collect();
        assert_eq!(data.len(), 1);
        assert_eq!(data[0].as_ref(), b"hello-transport");
    }
}
