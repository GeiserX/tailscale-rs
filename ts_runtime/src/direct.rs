//! Direct (disco) UDP underlay manager.
//!
//! This actor owns the single [`MagicSock`] that carries WireGuard datagrams directly over
//! UDP to peers' reachable endpoints, discovering and confirming paths with the disco
//! protocol. It mirrors [`crate::multiderp::Multiderp`] but for the direct underlay: it
//! registers one [`DirectTransport`] with the dataplane and bridges packets between that
//! transport and the dataplane's underlay channels.
//!
//! # Anti-leak posture
//!
//! A peer is reported as having a direct path *only* when [`MagicSock::best_addr`] returns
//! `Some` (i.e. a disco pong confirmed the path and its trust has not expired). The route
//! layer upgrades such peers from DERP to direct and auto-downgrades them back to DERP when
//! trust lapses. There is never a silent host-network dial, so the real origin IP cannot leak
//! when direct connectivity is unavailable.

use core::{net::SocketAddr, time::Duration};
use std::{
    collections::HashSet,
    sync::{Arc, RwLock},
};

use kameo::{
    actor::ActorRef,
    message::{Context, Message},
};
use tokio::task::JoinSet;
use ts_keys::DiscoPublicKey;
use ts_magicsock::{DirectTransport, MagicSock, SelfEndpoint};
use ts_transport::{
    BatchRecvIter, PeerId, PeerLookup, UnderlayTransport, UnderlayTransportExt, UnderlayTransportId,
};

use crate::{
    Env, Error,
    dataplane::{DataplaneActor, NewUnderlayTransport, UnderlayFromDataplane, UnderlayToDataplane},
    multiderp::{self, Multiderp},
    peer_tracker::{PeerDb, PeerState},
};

/// How often to (re)ping candidate endpoints. [`MagicSock::send_pings`] only pings paths that
/// need (re)confirmation, so this interval just bounds how quickly an expired path
/// (`TRUST_DURATION`) is re-confirmed.
const PING_INTERVAL: Duration = Duration::from_secs(2);

/// How often to re-evaluate our own candidate endpoints and (if changed) advertise them to
/// control. Reflexive addresses accrue asynchronously as disco pongs arrive, so we poll and
/// only publish when the set actually differs from what we last advertised.
const ADVERTISE_INTERVAL: Duration = Duration::from_secs(5);

/// Our magicsock candidate endpoints, published for [`crate::control_runner::ControlRunner`] to
/// forward to the control server so peers can learn where to attempt direct connections.
///
/// All addresses originate from the single bound underlay socket — there is no second egress.
#[derive(Clone)]
pub struct EndpointAdvertisement {
    pub endpoints: Arc<Vec<SelfEndpoint>>,
}

/// The bind address for the direct underlay socket.
///
/// IPv4-only and ephemeral-port: per the anti-leak rules this socket is the only egress path
/// for the direct underlay, and IPv6 is disabled in our deployment.
const BIND_ADDR: &str = "0.0.0.0:0";

/// Owns the direct (disco) UDP underlay and bridges it to the dataplane.
///
/// `sock`/`transport_id` are `Option`: if the underlay UDP socket fails to bind at startup the
/// manager stays **inert** (both `None`) rather than panicking, and the runtime continues
/// DERP-only. DERP-only is the anti-leak-safe fallback — there is simply no direct path to offer,
/// so no peer is ever upgraded off DERP and the real origin IP cannot leak.
pub struct DirectManager {
    sock: Option<Arc<MagicSock>>,
    transport_id: Option<UnderlayTransportId>,
    peer_db: Arc<RwLock<Option<Arc<PeerDb>>>>,
    #[allow(dead_code)]
    tasks: JoinSet<()>,
}

#[kameo::messages]
impl DirectManager {
    /// The id of the single direct underlay transport registered with the dataplane.
    ///
    /// `Some` once the actor has started and the underlay socket bound; `None` if the bind failed
    /// at startup, in which case the route updater stays DERP-only (fail-closed). The `Option`
    /// also satisfies kameo's `Reply` bound (a bare newtype is not a reply).
    #[message]
    pub fn direct_transport_id(&self) -> Option<UnderlayTransportId> {
        self.transport_id
    }

    /// Of the given peers, return those that currently have a trusted direct path.
    ///
    /// A peer is included only if its disco key is known and [`MagicSock::best_addr`] returns
    /// `Some` for it right now (live query — never cached — so trust expiry downgrades
    /// immediately).
    #[message]
    pub fn peers_with_direct_path(&self, ids: Vec<PeerId>) -> HashSet<PeerId> {
        let mut ready = HashSet::new();

        // No bound underlay socket (bind failed => inert, DERP-only): no peer has a direct path.
        let Some(sock) = self.sock.as_ref() else {
            return ready;
        };

        let db = self.peer_db.read().unwrap();
        let Some(db) = db.as_ref() else {
            return ready;
        };

        for id in ids {
            let Some((_, node)) = db.get(&id) else {
                continue;
            };
            let Some(disco) = node.disco_key else {
                continue;
            };
            if sock.best_addr(&disco).is_some() {
                ready.insert(id);
            }
        }

        ready
    }
}

/// Bidirectional [`PeerId`] <-> [`DiscoPublicKey`] lookup backed by a snapshot of the peer db.
///
/// Uses the owned (`Arc<RwLock<...>>`) form rather than a borrow, because the direct socket
/// lives for the whole runtime and the lookup must outlive any single call.
struct DiscoPeerLookup(Arc<RwLock<Option<Arc<PeerDb>>>>);

impl PeerLookup<PeerId, DiscoPublicKey> for DiscoPeerLookup {
    fn lookup_key(&self, id: PeerId) -> Option<DiscoPublicKey> {
        let db = self.0.read().unwrap();
        let db = db.as_ref()?;
        let (_, node) = db.get(&id)?;
        node.disco_key
    }
}

impl PeerLookup<DiscoPublicKey, PeerId> for DiscoPeerLookup {
    fn lookup_key(&self, key: DiscoPublicKey) -> Option<PeerId> {
        let db = self.0.read().unwrap();
        let db = db.as_ref()?;
        let (id, _) = db.get(&key)?;
        Some(id)
    }
}

/// Bridge packets between the direct transport and the dataplane underlay channels.
///
/// A simplified [`crate::multiderp::run_derp_once`]: no reconnect or home-derp logic, because
/// the single UDP socket is always bound and never needs re-establishment.
async fn run_direct(
    transport: impl UnderlayTransport<PeerKey = PeerId, Error = ts_magicsock::Error>,
    mut from_dataplane: UnderlayFromDataplane,
    to_dataplane: UnderlayToDataplane,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    while !*shutdown.borrow() {
        tokio::select! {
            _ = shutdown.changed() => break,

            from_direct = transport.recv() => {
                for ret in from_direct.batch_iter() {
                    match ret {
                        Ok((peer_id, pkts)) => {
                            let pkts = pkts.into_iter().collect::<Vec<_>>();
                            if to_dataplane.send((peer_id, pkts)).is_err() {
                                tracing::error!("underlay receive channel closed");
                                return;
                            }
                        }
                        Err(e) => {
                            tracing::trace!(error = %e, "ignoring undecodable direct packet");
                        }
                    }
                }
            }

            from_net = from_dataplane.recv() => {
                let Some(from_net) = from_net else {
                    tracing::warn!("direct underlay queue closed");
                    break;
                };

                if let Err(e) = transport.send([from_net]).await {
                    tracing::trace!(error = %e, "sending direct packet");
                }
            }
        }
    }
}

/// Periodically (re)ping candidate endpoints to confirm and keep direct paths alive.
async fn run_pinger(sock: Arc<MagicSock>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(PING_INTERVAL);

    while !*shutdown.borrow() {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = interval.tick() => {
                if let Err(e) = sock.send_pings().await {
                    tracing::trace!(error = %e, "sending disco pings");
                }
            }
        }
    }
}

/// Periodically re-evaluate our own candidate endpoints and publish them on the bus when they
/// change, so control can be told where peers may reach us directly. Only republishes on a real
/// change to avoid spamming control with redundant side-band map requests.
async fn run_advertiser(
    sock: Arc<MagicSock>,
    env: Env,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(ADVERTISE_INTERVAL);
    let mut last: Vec<SelfEndpoint> = Vec::new();

    while !*shutdown.borrow() {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = interval.tick() => {
                let mut eps = sock.self_endpoints();
                eps.sort_by_key(|e| (e.addr, e.ty as u8));
                if eps == last {
                    continue;
                }
                last = eps.clone();

                if let Err(e) = env
                    .publish(EndpointAdvertisement {
                        endpoints: Arc::new(eps),
                    })
                    .await
                {
                    tracing::error!(error = %e, "publishing endpoint advertisement");
                }
            }
        }
    }
}

/// Periodically send a `CallMeMaybe` over DERP to each peer that has no confirmed direct path
/// yet, prompting it to disco-ping our candidate endpoints so a direct path can open. Gated on
/// [`MagicSock::best_addr`] being `None`: once a path is confirmed we stop relaying to that peer,
/// so this never spams DERP for peers that are already direct.
///
/// We only target peers that have a disco key and a known home DERP region (we relay to that
/// region). The frame carries our [`MagicSock::self_endpoints`] — the same set advertised to
/// control — so no host-identifying address beyond that is disclosed.
async fn run_call_me_maybe(
    sock: Arc<MagicSock>,
    peer_db: Arc<RwLock<Option<Arc<PeerDb>>>>,
    multiderp: ActorRef<Multiderp>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(ADVERTISE_INTERVAL);

    while !*shutdown.borrow() {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = interval.tick() => {
                // A CallMeMaybe is only actionable to a remote peer if we have a reflexive
                // (STUN-discovered) candidate it can actually reach across the internet; a purely
                // local LAN address is useless to relay over DERP. Skip the whole cadence until we
                // have one, so peers that can never go direct don't incur perpetual relay load.
                if !sock
                    .self_endpoints()
                    .iter()
                    .any(|e| e.ty == ts_magicsock::SelfEndpointType::Stun)
                {
                    continue;
                }

                // Snapshot the targets under the read lock, then release it before any await.
                let targets: Vec<(ts_keys::NodePublicKey, DiscoPublicKey, ts_derp::RegionId)> = {
                    let db = peer_db.read().unwrap();
                    let Some(db) = db.as_ref() else { continue; };

                    db.peers()
                        .values()
                        .filter_map(|node| {
                            let disco = node.disco_key?;
                            let region = node.derp_region?;
                            // Only prompt peers that don't already have a confirmed direct path.
                            if sock.best_addr(&disco).is_some() {
                                return None;
                            }
                            Some((node.node_key, disco, region))
                        })
                        .collect()
                };

                for (node_key, disco, region) in targets {
                    let frame = match sock.seal_call_me_maybe(&disco) {
                        Ok(frame) => frame,
                        Err(e) => {
                            tracing::trace!(error = %e, "sealing call-me-maybe");
                            continue;
                        }
                    };

                    if let Err(e) = multiderp
                        .tell(multiderp::SendDisco {
                            peer: node_key,
                            region,
                            frame,
                        })
                        .await
                    {
                        tracing::trace!(error = %e, "relaying call-me-maybe to multiderp");
                    }
                }
            }
        }
    }
}

impl kameo::Actor for DirectManager {
    type Args = (Env, ActorRef<DataplaneActor>, ActorRef<Multiderp>);
    type Error = Error;

    async fn on_start(
        (env, dataplane, multiderp): Self::Args,
        slf: ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        env.subscribe::<Arc<PeerState>>(&slf).await?;

        let peer_db: Arc<RwLock<Option<Arc<PeerDb>>>> = Default::default();
        let mut tasks = JoinSet::new();

        // The bind address is a hardcoded, infallible constant; only the parse can't fail.
        let bind_addr: SocketAddr = BIND_ADDR.parse().expect("valid bind address");

        // Bind the direct underlay UDP socket. A bind failure is transient/environmental (e.g. no
        // ephemeral ports available); rather than panicking the actor we degrade to **DERP-only**
        // and stay inert. DERP-only is the anti-leak-safe fallback (no direct path is ever offered,
        // so the real origin IP can't leak), mirroring the MagicDNS responder's bind-failure
        // posture. The route updater treats a `None` transport id as "stay on DERP" (fail-closed).
        let sock = match MagicSock::bind(
            bind_addr,
            env.keys.disco_keys.private,
            env.keys.node_keys.public,
        )
        .await
        {
            Ok(sock) => Arc::new(sock),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    %bind_addr,
                    "direct underlay udp bind failed; direct manager inert, staying DERP-only",
                );
                return Ok(Self {
                    sock: None,
                    transport_id: None,
                    peer_db,
                    tasks,
                });
            }
        };

        let (transport_id, from_dataplane, to_dataplane) =
            dataplane.ask(NewUnderlayTransport).await?;

        let transport =
            DirectTransport::new(sock.clone()).with_key_lookup(DiscoPeerLookup(peer_db.clone()));

        tasks.spawn(run_direct(
            transport,
            from_dataplane,
            to_dataplane,
            env.shutdown.clone(),
        ));
        tasks.spawn(run_pinger(sock.clone(), env.shutdown.clone()));
        tasks.spawn(run_advertiser(
            sock.clone(),
            env.clone(),
            env.shutdown.clone(),
        ));
        tasks.spawn(run_call_me_maybe(
            sock.clone(),
            peer_db.clone(),
            multiderp,
            env.shutdown.clone(),
        ));

        Ok(Self {
            sock: Some(sock),
            transport_id: Some(transport_id),
            peer_db,
            tasks,
        })
    }
}

impl Message<Arc<PeerState>> for DirectManager {
    type Reply = ();

    async fn handle(&mut self, msg: Arc<PeerState>, _ctx: &mut Context<Self, Self::Reply>) {
        // Reconcile, don't just add: control is authoritative for each peer's underlay endpoints,
        // so an address it stops advertising must be pruned (otherwise a revoked/reassigned addr
        // stays a ping candidate forever and could be re-confirmed as a direct path). Peers that
        // leave the netmap entirely are dropped so both path and attribution maps stay bounded.
        //
        // When the underlay bind failed at startup (`sock == None`) we're inert/DERP-only: there is
        // no socket to reconcile endpoints against, so skip it. We still keep `peer_db` current for
        // any other consumers and so the manager recovers no worse than the route-updater's
        // DERP-only path.
        if let Some(sock) = self.sock.as_ref() {
            let mut live = HashSet::new();
            for node in msg.peers.peers().values() {
                let Some(disco) = node.disco_key else {
                    continue;
                };
                live.insert(disco);
                sock.set_netmap_endpoints(disco, node.underlay_addresses.iter().copied());
            }
            sock.retain_peers(&live);
        }

        let mut db = self.peer_db.write().unwrap();
        *db = Some(msg.peers.clone());
    }
}
