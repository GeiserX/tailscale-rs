//! DERP relay fan-out: one underlay-transport task per DERP region from the control derp map.
//!
//! [`Multiderp`] spawns a connection task per region, keeps the home region always-on, and lets the
//! others idle out after a grace period. It also demuxes disco frames (e.g. `CallMeMaybe`) relayed
//! over DERP into the magicsock so a relay-only peer can still open a direct path.
//!
//! Anti-leak: STUN server collection ([`stun_servers_from_regions`]) emits only `FixedAddr` v4
//! servers — never `UseDns` — so probing never triggers a second DNS-resolution egress path.

use core::net::{SocketAddr, SocketAddrV4};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use kameo::{
    actor::ActorRef,
    error::SendError,
    message::{Context, Message},
};
use tokio::{
    sync::{mpsc, watch},
    task::JoinSet,
};
use ts_control::DerpRegion;
use ts_derp::RegionId;
use ts_keys::{NodeKeyPair, NodePublicKey};
use ts_magicsock::MagicSock;
use ts_transport::{
    BatchRecvIter, PeerId, UnderlayTransport, UnderlayTransportExt, UnderlayTransportId,
};

use crate::{
    Env, Error,
    dataplane::{DataplaneActor, NewUnderlayTransport, UnderlayFromDataplane, UnderlayToDataplane},
    derp_latency::DerpLatencyMeasurement,
    peer_tracker::{PeerDb, PeerState},
};

/// Consumes derp map updates and spawns a task per region that runs an underlay transport.
/// Also consumes home derp indications (for this node) to notify the relevant task that it
/// should keep the transport awake even if there is no traffic.
///
/// Other than the home task (which is always kept alive to receive packets), the transport
/// tasks keep the connection alive as long as there is traffic sent or received, and for a
/// short grace period afterward. Connections are otherwise closed not in use.
pub struct Multiderp {
    env: Env,
    dataplane: ActorRef<DataplaneActor>,
    derps: HashMap<RegionId, RegionEntry>,
    /// Cached region info from the last derp map, so a `send_disco` to a not-yet-connected
    /// region can re-enter [`Multiderp::ensure_region`] with the region's servers.
    regions: HashMap<RegionId, DerpRegion>,
    current_home_derp: Option<RegionId>,
    peer_db: Arc<RwLock<Option<Arc<PeerDb>>>>,
    /// The direct underlay socket, installed by [`crate::direct::DirectManager`] once it binds.
    ///
    /// A live handle (shared `RwLock`) so a disco frame (e.g. a `CallMeMaybe`) relayed to us over
    /// DERP can be demuxed and routed into the magicsock — letting it learn a peer's candidate
    /// endpoints and open a direct path even when the peer can only reach us over the relay. `None`
    /// until the direct manager binds (or permanently if its bind failed, in which case relayed
    /// disco frames are simply forwarded to the dataplane as before — they decode as junk there
    /// and are dropped). Region tasks read it live, so regions spawned before the sock is set pick
    /// it up once available.
    direct_sock: Arc<RwLock<Option<Arc<MagicSock>>>>,
    tasks: JoinSet<()>,
}

struct RegionEntry {
    transport_id: UnderlayTransportId,
    home_derp: watch::Sender<bool>,
    /// Sender for raw sealed disco frames (e.g. CallMeMaybe) to relay through this region's
    /// DERP client, keyed by the destination peer's node public key. Bounded; a dropped frame
    /// is retried on the next CallMeMaybe cadence.
    disco_tx: mpsc::Sender<(NodePublicKey, Vec<u8>)>,
}

impl Multiderp {
    #[tracing::instrument(skip_all, fields(region_id = %id))]
    async fn ensure_region(
        &mut self,
        id: RegionId,
        region: &DerpRegion,
        mut shutdown: watch::Receiver<bool>,
    ) {
        // TODO(npry): update if region info changes

        if self.derps.contains_key(&id) {
            tracing::trace!("region already existed");
            return;
        }

        let region = region.clone();
        let keys = self.env.keys.node_keys;

        let (transport_id, mut up, down) = match self.dataplane.ask(NewUnderlayTransport).await {
            Ok(val) => val,
            Err(SendError::ActorNotRunning(..) | SendError::ActorStopped) => {
                if !*shutdown.borrow() {
                    panic!("dataplane has stopped but we're not shutting down");
                }

                return;
            }
            // A transient mailbox-full / timeout (or handler) error must degrade a single region
            // rather than abort DERP setup for the whole node. Skip this region; it is re-attempted
            // on the next derp-map update or send_disco.
            Err(e) => {
                tracing::error!(error = %e, "multiderp: failed to set up DERP region; skipping");
                return;
            }
        };
        let (home_derp_tx, mut home_derp_rx) = watch::channel(false);
        let (disco_tx, mut disco_rx) = mpsc::channel::<(NodePublicKey, Vec<u8>)>(8);

        let peer_db = self.peer_db.clone();
        let direct_sock = self.direct_sock.clone();

        self.tasks.spawn(async move {
            while !*shutdown.borrow() {
                tokio::select! {
                    _ = shutdown.changed() => {
                        break;
                    },
                    ret = run_derp_once(
                        id,
                        &region,
                        keys,
                        &down,
                        &mut up,
                        &mut home_derp_rx,
                        &mut disco_rx,
                        &peer_db,
                        &direct_sock,
                    ) => if let Err(e) = ret {
                        tracing::error!(error = %e, region_id = %id, "running derp client");
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    },
                }

                if up.is_closed() {
                    tracing::warn!(region_id = %id, "underlay up channel closed!");
                    break;
                }

                if down.is_closed() {
                    tracing::warn!(region_id = %id, "underlay down channel closed!");
                    break;
                }
            }
        });

        self.derps.insert(
            id,
            RegionEntry {
                transport_id,
                home_derp: home_derp_tx,
                disco_tx,
            },
        );
    }
}

#[kameo::messages]
impl Multiderp {
    #[message]
    pub fn transport_id_for_region(&self, id: RegionId) -> Option<UnderlayTransportId> {
        Some(self.derps.get(&id)?.transport_id)
    }

    /// v4 STUN server addresses from the current derp map, for leak-safe single-socket STUN.
    /// Only FixedAddr v4 STUN nodes are returned; UseDns nodes are skipped (resolving them
    /// would be a second egress / DNS-leak path). May be empty (then we fall back to pong-harvest).
    #[message]
    pub fn stun_servers_v4(&self) -> (Vec<SocketAddr>,) {
        (stun_servers_from_regions(self.regions.values()),)
    }

    /// Install the direct underlay socket so disco frames (e.g. a `CallMeMaybe`) relayed to us
    /// over DERP can be demuxed into the magicsock (see [`Multiderp::direct_sock`]).
    ///
    /// Sent once by [`crate::direct::DirectManager`] after it binds. Region tasks read the handle
    /// live, so this takes effect on regions already running as well as ones spawned later.
    #[message]
    pub fn set_direct_sock(&mut self, sock: Arc<MagicSock>) {
        *poisoned_write(&self.direct_sock) = Some(sock);
    }

    /// Relay a raw sealed disco frame (e.g. a CallMeMaybe) to `peer` through DERP region `region`.
    ///
    /// Wakes the region's connection if it is not currently established (the queued frame counts
    /// as activity). If the region is unknown (not in the last derp map) the frame is dropped with
    /// a warning. A full per-region queue also drops the frame; it is retried on the next cadence.
    #[message]
    pub async fn send_disco(&mut self, peer: NodePublicKey, region: RegionId, frame: Vec<u8>) {
        let Some(region_info) = self.regions.get(&region).cloned() else {
            tracing::warn!(region_id = %region, "no derp region info, dropping disco frame");
            return;
        };

        self.ensure_region(region, &region_info, self.env.shutdown.clone())
            .await;

        let Some(entry) = self.derps.get(&region) else {
            tracing::warn!(region_id = %region, "region not established, dropping disco frame");
            return;
        };

        if let Err(e) = entry.disco_tx.try_send((peer, frame)) {
            tracing::trace!(error = %e, region_id = %region, "disco relay queue full or closed, dropping frame");
        }
    }
}

/// Collect the v4 STUN server addresses from a set of derp regions, for leak-safe single-socket
/// STUN.
///
/// **Anti-leak gate — do not loosen.** Only [`ts_derp::IpUsage::FixedAddr`] v4 servers with a
/// `stun_port` are emitted. `UseDns` (and `Disable`) servers are deliberately skipped: resolving a
/// STUN server hostname would be a DNS query and a second egress path, defeating the whole point of
/// probing from the one bound underlay socket. A future reader must not "fix" this to include
/// `UseDns` servers — that would reintroduce the DNS-leak path. Extracted as a free function so the
/// filtering can be unit-tested directly against `ServerConnInfo` fixtures.
fn stun_servers_from_regions<'a>(
    regions: impl IntoIterator<Item = &'a DerpRegion>,
) -> Vec<SocketAddr> {
    let mut servers = Vec::new();
    for region in regions {
        for srv in &region.servers {
            let Some(stun_port) = srv.stun_port else {
                continue;
            };
            if let ts_derp::IpUsage::FixedAddr(v4) = srv.ipv4 {
                servers.push(SocketAddr::V4(SocketAddrV4::new(v4, stun_port)));
            }
        }
    }
    servers
}

/// Read a [`RwLock`], recovering from poisoning rather than propagating the panic.
///
/// These locks guard a wholesale-replaced snapshot (the peer db, or the direct socket handle) with
/// no cross-field invariant a mid-write panic could leave half-applied. Recovering (rather than
/// `.unwrap()`) keeps a single panicking task from poisoning the lock and cascade-killing every
/// region runner that reads it — that would collapse all DERP relaying instead of failing closed.
fn poisoned_read<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Write-lock counterpart of [`poisoned_read`]; same poison-recovery rationale.
fn poisoned_write<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct PeerDbLookup<'a>(&'a RwLock<Option<Arc<PeerDb>>>);

impl ts_transport::PeerLookup<PeerId, NodePublicKey> for PeerDbLookup<'_> {
    fn lookup_key(&self, id: PeerId) -> Option<NodePublicKey> {
        let db = poisoned_read(self.0);
        let db = db.as_ref()?;

        let (_, node) = db.get(&id)?;
        Some(node.node_key)
    }
}

impl ts_transport::PeerLookup<NodePublicKey, PeerId> for PeerDbLookup<'_> {
    fn lookup_key(&self, key: NodePublicKey) -> Option<PeerId> {
        let db = poisoned_read(self.0);
        let db = db.as_ref()?;

        let (id, _) = db.get(&key)?;

        Some(id)
    }
}

#[tracing::instrument(skip_all, fields(region_id = %id), name = "derp runner")]
async fn run_derp_once(
    id: RegionId,
    region: &DerpRegion,
    keys: NodeKeyPair,
    to_dataplane: &UnderlayToDataplane,
    from_dataplane: &mut UnderlayFromDataplane,
    home_derp_rx: &mut watch::Receiver<bool>,
    disco_rx: &mut mpsc::Receiver<(NodePublicKey, Vec<u8>)>,
    peer_db: &RwLock<Option<Arc<PeerDb>>>,
    direct_sock: &RwLock<Option<Arc<MagicSock>>>,
) -> Result<(), ts_derp::Error> {
    const INACTIVITY_TIMEOUT: Duration = Duration::from_secs(10);

    loop {
        let mut pending = None;
        let mut pending_disco = None;

        tracing::trace!("waiting for packet activity or for this to become home derp");

        while !*home_derp_rx.borrow_and_update() {
            tokio::select! {
                _ = home_derp_rx.changed() => {
                    tracing::trace!(is_home_derp = *home_derp_rx.borrow());
                },

                from_net = from_dataplane.recv() => {
                    tracing::trace!("received packet to send");
                    pending = from_net;
                    break;
                }

                disco = disco_rx.recv() => {
                    tracing::trace!("received disco frame to relay, waking connection");
                    pending_disco = disco;
                    break;
                }
            }
        }

        tracing::trace!("establishing derp connection");

        // Hold the client in an `Arc` so we can both wrap a clone with the PeerId<->NodeKey
        // lookup (for dataplane traffic) and keep a raw handle for `send_one` (disco frames
        // addressed directly by node public key, bypassing the PeerId mapping).
        let client = Arc::new(ts_derp::DefaultClient::connect(&region.servers, &keys).await?);
        let transport = client.clone().with_key_lookup(PeerDbLookup(peer_db));

        if let Some(pending) = pending {
            tracing::trace!("sending queued packet");
            transport.send([pending]).await?;
        }

        if let Some((node_key, frame)) = pending_disco {
            tracing::trace!("relaying queued disco frame");
            client.send_one(node_key, &frame).await?;
        }

        let mut last_activity = Instant::now();

        loop {
            let span = tracing::trace_span!("derp_loop");

            let inactivity_timeout =
                (!*home_derp_rx.borrow()).then(|| last_activity + INACTIVITY_TIMEOUT);

            tokio::select! {
                from_derp = transport.recv() => {
                    last_activity = Instant::now();

                    // Inbound disco-over-DERP demux (npts-C2). A peer that can only reach us over
                    // the relay (e.g. symmetric NAT on both sides) sends its CallMeMaybe over DERP;
                    // it arrives here interleaved with WireGuard data. Route disco frames into the
                    // magicsock so it can learn the peer's candidate endpoints and open a direct
                    // path; everything else goes to the dataplane unchanged.
                    //
                    // Anti-leak: only CallMeMaybe is acted on (see
                    // `MagicSock::handle_relayed_call_me_maybe`). A relayed frame has no real UDP
                    // source, so we must never feed a relayed Ping/Pong into a path that would pong
                    // to a bogus address — that entry point drops them. If the direct socket isn't
                    // bound yet (or its bind failed), disco frames fall through to the dataplane as
                    // before, where they decode as junk and are dropped. That startup window
                    // self-heals: the peer re-sends CallMeMaybe on its own advertise cadence, so a
                    // dropped frame here is recovered on the next round, not a lost hole-punch.
                    // Snapshot the direct-sock handle once for the whole batch (it changes at most
                    // once, when the direct manager installs it). See `demux_relayed_disco` for the
                    // CallMeMaybe-only filtering this feeds.
                    let sock = poisoned_read(direct_sock).clone();
                    for ret in from_derp.batch_iter() {
                        let (peer_id, pkts) = ret?;

                        let data = demux_relayed_disco(pkts, sock.as_deref());
                        if data.is_empty() {
                            continue;
                        }

                        tracing::trace!(parent: &span, %peer_id, len = data.len(), "packet from derp server");

                        let Ok(()) = to_dataplane.send((peer_id, data)) else {
                            tracing::error!(parent: &span, "underlay receive channel closed");
                            break;
                        };
                    }
                },

                disco = disco_rx.recv() => {
                    last_activity = Instant::now();

                    let Some((node_key, frame)) = disco else {
                        tracing::warn!(parent: &span, "disco relay queue closed");
                        break;
                    };

                    tracing::trace!(parent: &span, "relaying disco frame over derp");
                    client.send_one(node_key, &frame).await?;
                },

                from_net = from_dataplane.recv() => {
                    last_activity = Instant::now();

                    let Some(from_net) = from_net else {
                        tracing::warn!(parent: &span, "transport queue closed");
                        break;
                    };

                    tracing::trace!(parent: &span, peer = %from_net.0, packets = from_net.1.len(), "packets to derp server");

                    transport.send([from_net]).await?;
                },

                _ = option_timeout(inactivity_timeout) => {
                    if !*home_derp_rx.borrow_and_update() {
                        tracing::trace!(parent: &span, "timed out and not home derp, closing derp conn");
                        break;
                    }
                },

                _ = home_derp_rx.changed() => {
                    tracing::trace!(is_home_derp = *home_derp_rx.borrow());
                },
            }
        }
    }
}

/// Demux a batch of frames received from a DERP server, routing relayed disco frames into the
/// direct socket and returning the remaining (WireGuard data) frames to forward to the dataplane.
///
/// A peer reachable only over the relay (e.g. symmetric NAT on both ends) sends its `CallMeMaybe`
/// over DERP; it is interleaved with WireGuard data on this path. Each frame that
/// [`ts_magicsock::looks_like_disco`] and is consumed by
/// [`MagicSock::handle_relayed_call_me_maybe`] is dropped from the data stream (the magicsock
/// learns the peer's candidate endpoints from it). Everything else — and *all* frames when no
/// direct socket is installed — is returned unchanged for the dataplane.
///
/// Anti-leak: a relayed frame has no real UDP source, so only `CallMeMaybe` is acted on; relayed
/// Pings/Pongs are dropped by `handle_relayed_call_me_maybe` rather than producing a pong to a
/// bogus address.
fn demux_relayed_disco(
    pkts: impl IntoIterator<Item = ts_packet::PacketMut>,
    sock: Option<&MagicSock>,
) -> Vec<ts_packet::PacketMut> {
    let mut data = Vec::new();
    for mut pkt in pkts {
        if ts_magicsock::looks_like_disco(pkt.as_ref())
            && let Some(sock) = sock
            && sock.handle_relayed_call_me_maybe(pkt.as_mut())
        {
            // Consumed as a relayed disco frame; keep it off the dataplane.
            continue;
        }
        data.push(pkt);
    }
    data
}

async fn option_timeout(duration: Option<Instant>) {
    match duration {
        Some(dur) => tokio::time::sleep_until(dur.into()).await,
        None => core::future::pending().await,
    }
}

impl kameo::Actor for Multiderp {
    type Args = (Env, ActorRef<DataplaneActor>);
    type Error = Error;

    async fn on_start(
        (env, dataplane): Self::Args,
        slf: ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        env.subscribe::<Arc<ts_control::StateUpdate>>(&slf).await?;
        env.subscribe::<Arc<PeerState>>(&slf).await?;
        env.subscribe::<DerpLatencyMeasurement>(&slf).await?;

        Ok(Self {
            env,
            dataplane,
            peer_db: Default::default(),
            direct_sock: Default::default(),
            derps: Default::default(),
            regions: Default::default(),
            tasks: JoinSet::new(),
            current_home_derp: None,
        })
    }
}

impl Message<Arc<ts_control::StateUpdate>> for Multiderp {
    type Reply = ();

    #[tracing::instrument(skip_all, name = "multiderp map update")]
    async fn handle(
        &mut self,
        msg: Arc<ts_control::StateUpdate>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        let Some(derp_map) = &msg.derp else {
            return;
        };

        for (id, region) in derp_map {
            self.regions.insert(*id, region.clone());
            self.ensure_region(*id, region, self.env.shutdown.clone())
                .await;

            // If this is the home region and it was just started, it needs to be notified that it's
            // the home region.
            if let Some(home_derp) = self.current_home_derp
                && *id == home_derp
            {
                self.derps
                    .get_mut(&home_derp)
                    .unwrap()
                    .home_derp
                    .send_replace(true);
            }
        }
    }
}

impl Message<Arc<PeerState>> for Multiderp {
    type Reply = ();

    async fn handle(&mut self, msg: Arc<PeerState>, _ctx: &mut Context<Self, Self::Reply>) {
        let mut db = poisoned_write(&self.peer_db);
        *db = Some(msg.peers.clone());
    }
}

impl Message<DerpLatencyMeasurement> for Multiderp {
    type Reply = ();

    async fn handle(&mut self, msg: DerpLatencyMeasurement, _ctx: &mut Context<Self, Self::Reply>) {
        let Some(result) = msg.measurement.as_ref().first() else {
            tracing::trace!("received home derp measurement message but none was set");
            return;
        };

        if let Some(home_derp) = self.current_home_derp {
            self.derps
                .get_mut(&home_derp)
                .unwrap()
                .home_derp
                .send_replace(false);
        }

        if self.current_home_derp.is_none_or(|id| id != result.id) {
            self.current_home_derp = Some(result.id);
            if let Some(derp) = self.derps.get_mut(&result.id) {
                derp.home_derp.send_replace(true);
            }

            tracing::info!(
                region_id = %result.id,
                latency_ms = result.latency.as_secs_f32() * 1000.,
                "new home derp region selected"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use ts_keys::DiscoPrivateKey;
    use ts_packet::PacketMut;

    use super::*;

    fn localhost() -> std::net::SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    /// A binding verifier accepting every disco frame. The demux tests are not exercising the
    /// netmap-membership check (covered in `direct::tests` and `ts_magicsock`), so they install
    /// this to keep the now-fail-closed relayed-CallMeMaybe handler learning endpoints.
    fn allow_all() -> ts_magicsock::BindingVerifier {
        Arc::new(|_: &ts_keys::DiscoPublicKey, _: Option<&NodePublicKey>| true)
    }

    /// A `CallMeMaybe` relayed to us over DERP is routed into the magicsock (its endpoints are
    /// learned via `add_peer_endpoints`) and is *not* returned for the dataplane, while an
    /// interleaved WireGuard data frame still reaches the dataplane unchanged. This is the
    /// npts-C2 inbound disco-over-DERP demux.
    #[tokio::test]
    async fn relayed_call_me_maybe_is_demuxed_not_forwarded() {
        // Our direct socket; the relayed CallMeMaybe is sealed *to* its disco key.
        let our_disco = DiscoPrivateKey::random();
        let our_node = ts_keys::NodePrivateKey::random().public_key();
        let sock = MagicSock::bind(localhost(), our_disco, our_node)
            .await
            .unwrap()
            .with_binding_verifier(allow_all());

        // A remote peer's CallMeMaybe carrying a public (pingable) candidate endpoint.
        let peer_disco = DiscoPrivateKey::random();
        let peer_ep: std::net::SocketAddr = "203.0.113.7:41641".parse().unwrap();
        let cmm =
            ts_magicsock::seal_call_me_maybe(&peer_disco, &our_disco.public_key(), &[peer_ep])
                .unwrap();

        // A normal WireGuard data frame (type byte 0x04, never the disco magic prefix).
        let wg = PacketMut::from(&[0x04u8, 0, 0, 0, 1, 2, 3, 4][..]);

        let batch = vec![PacketMut::from(&cmm[..]), wg];
        let to_dataplane = demux_relayed_disco(batch, Some(&sock));

        // The CallMeMaybe was consumed; only the data frame is forwarded.
        assert_eq!(
            to_dataplane.len(),
            1,
            "only the data frame reaches the dataplane"
        );
        assert_eq!(to_dataplane[0].as_ref(), &[0x04u8, 0, 0, 0, 1, 2, 3, 4]);

        // The peer's candidate endpoint was learned by the magicsock.
        assert_eq!(
            sock.candidate_addrs(&peer_disco.public_key()),
            vec![peer_ep],
            "the relayed CallMeMaybe's endpoint should be learned"
        );
    }

    /// With no direct socket installed (bind failed, or before the direct manager binds), every
    /// frame — disco or not — is forwarded to the dataplane unchanged (the prior behavior).
    #[tokio::test]
    async fn without_direct_sock_all_frames_forwarded() {
        let our_disco = DiscoPrivateKey::random();
        let peer_disco = DiscoPrivateKey::random();
        let cmm = ts_magicsock::seal_call_me_maybe(
            &peer_disco,
            &our_disco.public_key(),
            &["203.0.113.7:41641".parse().unwrap()],
        )
        .unwrap();
        let wg = PacketMut::from(&[0x04u8, 9, 9][..]);

        let batch = vec![PacketMut::from(&cmm[..]), wg];
        let out = demux_relayed_disco(batch, None);

        assert_eq!(
            out.len(),
            2,
            "no demux without a direct socket; all frames pass through"
        );
    }

    /// A disco *Ping* relayed over DERP must be dropped, never ponged: a relayed frame has no real
    /// UDP source to answer. It is consumed (kept off the dataplane) but learns no candidate path,
    /// even with an allow-all verifier installed — proving the drop is structural (CallMeMaybe-only
    /// at the relay), not a verifier rejection.
    #[tokio::test]
    async fn relayed_ping_is_dropped_not_ponged() {
        let our_disco = DiscoPrivateKey::random();
        let our_node = ts_keys::NodePrivateKey::random().public_key();
        let sock = MagicSock::bind(localhost(), our_disco, our_node)
            .await
            .unwrap()
            .with_binding_verifier(allow_all());

        let peer_disco = DiscoPrivateKey::random();
        let peer_node = ts_keys::NodePrivateKey::random().public_key();
        let tx = ts_magicsock::random_tx_id();
        let ping =
            ts_magicsock::seal_ping(&peer_disco, peer_node, &our_disco.public_key(), tx).unwrap();

        let out = demux_relayed_disco(vec![PacketMut::from(&ping[..])], Some(&sock));

        assert!(
            out.is_empty(),
            "a relayed disco Ping is consumed (kept off the dataplane)"
        );
        assert!(
            sock.candidate_addrs(&peer_disco.public_key()).is_empty(),
            "a relayed Ping must not learn a candidate path"
        );
    }

    /// A relayed `CallMeMaybe` advertising a forbidden candidate (loopback/private/IPv6) has that
    /// endpoint filtered by `is_pingable_candidate` before it can become a host-sourced ping
    /// target; only the public candidate offered alongside it is learned.
    #[tokio::test]
    async fn relayed_call_me_maybe_forbidden_endpoints_filtered() {
        let our_disco = DiscoPrivateKey::random();
        let our_node = ts_keys::NodePrivateKey::random().public_key();
        let sock = MagicSock::bind(localhost(), our_disco, our_node)
            .await
            .unwrap()
            .with_binding_verifier(allow_all());

        let peer_disco = DiscoPrivateKey::random();
        let loopback: std::net::SocketAddr = "127.0.0.1:41641".parse().unwrap();
        let private: std::net::SocketAddr = "10.1.2.3:41641".parse().unwrap();
        let public: std::net::SocketAddr = "203.0.113.50:41641".parse().unwrap();
        let cmm = ts_magicsock::seal_call_me_maybe(
            &peer_disco,
            &our_disco.public_key(),
            &[loopback, private, public],
        )
        .unwrap();

        let out = demux_relayed_disco(vec![PacketMut::from(&cmm[..])], Some(&sock));
        assert!(out.is_empty(), "the CallMeMaybe is consumed, not forwarded");

        assert_eq!(
            sock.candidate_addrs(&peer_disco.public_key()),
            vec![public],
            "only the public candidate survives the pingable-candidate filter"
        );
    }

    /// Build a [`ServerConnInfo`] fixture with the given v4 usage and STUN port; other fields are
    /// fixed placeholders the STUN filter never reads.
    fn server(
        ipv4: ts_derp::IpUsage<core::net::Ipv4Addr>,
        stun_port: Option<u16>,
    ) -> ts_derp::ServerConnInfo {
        ts_derp::ServerConnInfo {
            hostname: "derp.example".to_string(),
            ipv4,
            ipv6: ts_derp::IpUsage::Disable,
            tls_validation_config: ts_derp::TlsValidationConfig::CommonName {
                common_name: "derp.example".to_string(),
            },
            https_port: 443,
            stun_port,
            stun_only: false,
            supports_port_80: false,
        }
    }

    fn region(servers: Vec<ts_derp::ServerConnInfo>) -> DerpRegion {
        DerpRegion {
            info: ts_derp::RegionInfo {
                name: "r".to_string(),
                code: "r".to_string(),
                no_measure_no_home: false,
            },
            servers,
        }
    }

    /// The anti-DNS-leak gate: only FixedAddr-v4 servers with a STUN port are returned. A `UseDns`
    /// server (would require a DNS lookup = second egress) is skipped, a `Disable` server is
    /// skipped, and a FixedAddr server with no `stun_port` is skipped. A future change that lets
    /// `UseDns` through would reintroduce the DNS-leak path this test guards.
    #[test]
    fn stun_servers_from_regions_returns_only_fixed_v4_with_port() {
        let fixed = core::net::Ipv4Addr::new(203, 0, 113, 5);
        let r = region(vec![
            // Kept: FixedAddr v4 with a STUN port.
            server(ts_derp::IpUsage::FixedAddr(fixed), Some(3478)),
            // Skipped: UseDns (resolving it would be a DNS leak / second egress).
            server(ts_derp::IpUsage::UseDns, Some(3478)),
            // Skipped: explicitly disabled v4.
            server(ts_derp::IpUsage::Disable, Some(3478)),
            // Skipped: FixedAddr but STUN disabled (no stun_port).
            server(
                ts_derp::IpUsage::FixedAddr(core::net::Ipv4Addr::new(198, 51, 100, 9)),
                None,
            ),
        ]);

        let got = stun_servers_from_regions([&r]);
        assert_eq!(
            got,
            vec![SocketAddr::V4(SocketAddrV4::new(fixed, 3478))],
            "only the FixedAddr-v4-with-port server must be probed (UseDns/Disable/no-port skipped)"
        );
    }

    /// A derp map with no FixedAddr-v4 STUN servers yields an empty list (the prober then falls back
    /// to pong-harvest) rather than panicking or fabricating an address.
    #[test]
    fn stun_servers_from_regions_empty_when_no_fixed_v4() {
        let r = region(vec![
            server(ts_derp::IpUsage::UseDns, Some(3478)),
            server(ts_derp::IpUsage::Disable, None),
        ]);
        assert!(
            stun_servers_from_regions([&r]).is_empty(),
            "no FixedAddr-v4 STUN server => empty probe list"
        );
    }
}
