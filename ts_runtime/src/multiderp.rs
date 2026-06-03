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
            Err(e) => unreachable!("{}", e),
        };
        let (home_derp_tx, mut home_derp_rx) = watch::channel(false);
        let (disco_tx, mut disco_rx) = mpsc::channel::<(NodePublicKey, Vec<u8>)>(8);

        let peer_db = self.peer_db.clone();

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

struct PeerDbLookup<'a>(&'a RwLock<Option<Arc<PeerDb>>>);

impl ts_transport::PeerLookup<PeerId, NodePublicKey> for PeerDbLookup<'_> {
    fn lookup_key(&self, id: PeerId) -> Option<NodePublicKey> {
        let db = self.0.read().unwrap();
        let db = db.as_ref()?;

        let (_, node) = db.get(&id)?;
        Some(node.node_key)
    }
}

impl ts_transport::PeerLookup<NodePublicKey, PeerId> for PeerDbLookup<'_> {
    fn lookup_key(&self, key: NodePublicKey) -> Option<PeerId> {
        let db = self.0.read().unwrap();
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

                    // TODO(npts-C2): inbound disco-over-DERP demux. A peer's CallMeMaybe (or any
                    // disco frame) relayed to us arrives here and is forwarded to the dataplane as
                    // if it were WireGuard data. Until we demux disco on this path, hole punching
                    // relies on the peer pinging our direct socket (where `handle_disco` answers).
                    // This is sufficient for the common NAT case; symmetric-NAT-both-sides still
                    // stays on DERP until this seam exists.
                    for ret in from_derp.batch_iter() {
                        let (peer_id, pkts) = ret?;
                        let pkts = pkts.into_iter().collect::<Vec<_>>();

                        tracing::trace!(parent: &span, %peer_id, len = pkts.len(), "packet from derp server");

                        let Ok(()) = to_dataplane.send((peer_id, pkts)) else {
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
        let mut db = self.peer_db.write().unwrap();
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
