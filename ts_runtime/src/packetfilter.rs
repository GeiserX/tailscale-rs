use std::sync::Arc;

use kameo::{
    actor::ActorRef,
    message::{Context, Message},
};
use tokio::sync::watch;

use crate::{Error, env::Env};

/// The latest peer-capability grants retained from control's packet-filter application rules, shared
/// from the [`PacketfilterUpdater`] to [`Runtime::whois`](crate::Runtime::whois) for flow-scoped cap
/// resolution. `Arc`-wrapped so a `watch` clone is cheap.
pub type CapGrants = Arc<Vec<ts_packetfilter_state::CapGrant>>;

pub struct PacketfilterUpdater {
    env: Env,
    pf_state: ts_packetfilter::CheckingFilter<
        ts_packetfilter::HashbrownFilter,
        ts_bart_packetfilter::BartFilter,
    >,
    /// This node's own host addresses (tailnet IPv4/IPv6 + MagicDNS + VIP-service addresses), from
    /// the latest netmap self node — the destinations shields-up ([`Env::block_incoming`]) denies.
    /// Empty until the first netmap carrying a self node.
    self_addrs: Vec<std::net::IpAddr>,
    /// Sender for the latest retained cap-grants. The control runner publishes the compiled filter
    /// on the bus (no replay), but `Runtime::whois` needs the *current* grants on demand, so they
    /// ride a `watch` cell whose receiver `Runtime` holds — mirroring `active_exit_rx`/`state_rx`.
    cap_grants_tx: watch::Sender<CapGrants>,
    /// Sender for the live compiled filter the peerAPI DoH source gate reads on demand
    /// ([`LiveFilterRx`]). Written here, at the point of compilation, rather than by a bus
    /// subscriber downstream: the bus is lossy (see [`LiveFilterRx`]), so this cell is what the
    /// gate reads instead of a `PacketFilterState` subscription of its own.
    live_filter_tx: LiveFilterTx,
    /// The allowed-IP prefixes of every peer control marked `UnsignedPeerAPIOnly`, keyed by node
    /// id so a delta netmap can drop one. Such a peer carries no tailnet-lock signature, so nothing
    /// control says about it is covered by the lock — including any ACL that names it. Kept here,
    /// rather than read from the peer db, because this actor is where the filter is compiled and
    /// the two have to be judged against each other at the same instant. Mirrors the `nb.peers`
    /// walk in Go's `nodeBackend.unlockedNodesPermitted`.
    unlocked_allowed_ips: std::collections::BTreeMap<ts_control::NodeId, Vec<ipnet::IpNet>>,
    /// Whether the compiled filter currently in [`pf_state`](Self::pf_state) grants one of those
    /// peers network access. While set, the published filter is a deny-all instead of the compiled
    /// one — Go's `packetFilter = nil`. Re-derived on every netmap that moves either side.
    unlocked_nodes_permitted: bool,
}

#[derive(Clone)]
pub struct PacketFilterState(pub Arc<dyn ts_packetfilter::Filter + Send + Sync>);

/// The live inbound packet filter, as an L7 peerAPI gate reads it on demand.
///
/// The peerAPI DoH gate ([`peerapi_doh::dns_source_allowed`](crate::peerapi_doh::dns_source_allowed))
/// has to consult the *current* filter when a peer's query arrives, so it rides a `watch` cell
/// alongside the shared `DnsView` — the same shape [`CapGrants`] uses for `Runtime::whois`.
///
/// **The cell is written by [`PacketfilterUpdater`] itself, never by a bus subscriber.** The bus
/// loses messages in two ways that a fail-closed gate cannot absorb, because the loss is permanent
/// until control happens to send another filter:
///
/// 1. It has no replay, so a filter published before a subscriber's `Register` reaches the bus
///    actor is not delivered to it at all. Registration is not ordered against `Runtime::spawn`'s
///    spawn order — an actor registers from its own `on_start`, on its own task.
/// 2. It delivers **best-effort** (`kameo_actors::DeliveryStrategy::BestEffort`, the default the
///    `Env` bus is spawned with): a publish `try_send`s and *skips* any recipient whose bounded
///    mailbox is full. A subscriber that parks in a handler — [`MagicDnsActor`](crate::magic_dns)
///    awaits a DNS forward for up to five seconds in its `Query` handler — silently misses the
///    filter published while it was busy.
///
/// A `watch` written by the compiler of the filter has neither problem *on this hop*:
/// last-write-wins, no mailbox, and a receiver created at any later time reads the current value.
/// So nothing can be lost between the compiler of the filter and the gate, and the gate is
/// insulated from its own start-up order.
///
/// The hop *into* [`PacketfilterUpdater`] is a different matter and is **unchanged**: control's
/// `Arc<ts_control::StateUpdate>` reaches it over this same bus, with both failure modes above
/// still live (the updater even parks in its own handler, awaiting `Env::publish`). A netmap lost
/// there leaves this cell holding a stale value — or `None` — and the gate refusing. Closing that
/// hop is deliberately out of scope here: it needs the updater to stop awaiting `Env::publish` on
/// the hot path (or to be given a wider mailbox), which is a change to the control path rather
/// than to this gate.
///
/// `None` means no filter has been compiled yet (no netmap since start). That is a **deny** for the
/// gate, not an "allow until control speaks": Go's `isPeerAPIDNSAllowed` returns false outright when
/// `b.filterAtomic.Load()` is nil.
pub(crate) type LiveFilterRx = watch::Receiver<Option<PacketFilterState>>;

/// The writing half of [`LiveFilterRx`], held by [`PacketfilterUpdater`]. Created by
/// `Runtime::spawn` before either end's actor spawns, so neither end depends on start-up order.
pub(crate) type LiveFilterTx = watch::Sender<Option<PacketFilterState>>;

impl kameo::Actor for PacketfilterUpdater {
    type Args = (Env, watch::Sender<CapGrants>, LiveFilterTx);
    type Error = Error;

    async fn on_start(
        (env, cap_grants_tx, live_filter_tx): Self::Args,
        slf: ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        env.subscribe::<Arc<ts_control::StateUpdate>>(&slf).await?;

        Ok(Self {
            env,
            pf_state: Default::default(),
            self_addrs: Vec::new(),
            cap_grants_tx,
            live_filter_tx,
            unlocked_allowed_ips: Default::default(),
            unlocked_nodes_permitted: false,
        })
    }
}

impl PacketfilterUpdater {
    /// The filter to hand the dataplane: the live control-derived one, unless control has been
    /// caught granting an unlocked peer network access, in which case none of it is installed.
    fn published_filter(&self) -> PacketFilterState {
        if self.unlocked_nodes_permitted {
            // Control handed us an ACL that grants network access to a peer outside tailnet lock's
            // coverage, so the whole filter is untrustworthy and none of it is installed. Deny-all,
            // not allow-all: Go replaces the match list with `nil` and builds the filter from that,
            // which admits nothing. The shields-up wrapper still goes on when it is enabled, so a
            // dropped packet is still reported to the peer as a shields-up drop rather than an ACL
            // one.
            self.wrap_for_publication(ts_packetfilter::HashbrownFilter::default())
        } else {
            self.wrap_for_publication(self.pf_state.clone())
        }
    }

    /// Apply shields-up to whichever filter is being published, when [`Env::block_incoming`] is
    /// set: inbound packets destined to one of this node's own addresses are dropped (refuse
    /// inbound peer connections terminating on us), while forwarded transit and replies handled by
    /// the underlying ACL pass through. A no-op wrapper when shields-up is off, so the non-shielded
    /// path is byte-for-byte the prior behavior.
    fn wrap_for_publication(
        &self,
        inner: impl ts_packetfilter::Filter + Send + Sync + 'static,
    ) -> PacketFilterState {
        if self.env.block_incoming {
            PacketFilterState(Arc::new(ts_packetfilter::ShieldsUpFilter {
                inner,
                self_addrs: self.self_addrs.clone(),
            }))
        } else {
            PacketFilterState(Arc::new(inner))
        }
    }

    /// Re-track the unlocked (`UnsignedPeerAPIOnly`) peers this netmap carries, reporting whether
    /// the tracked set changed. A full peer set replaces; a delta upserts and removes. Field-level
    /// `PeerChange` patches are deliberately not consulted: the wire form carries neither
    /// `UnsignedPeerAPIOnly` nor `AllowedIPs`, so a patch can never move either side of this.
    fn track_unlocked_peers(&mut self, state_update: &ts_control::StateUpdate) -> bool {
        let Some(peer_update) = state_update.peer_update.as_ref() else {
            return false;
        };

        let before = self.unlocked_allowed_ips.clone();
        match peer_update {
            ts_control::PeerUpdate::Full(peers) => {
                self.unlocked_allowed_ips = peers
                    .iter()
                    .filter(|peer| peer.unsigned_peer_api_only)
                    .map(|peer| (peer.id, peer.accepted_routes.clone()))
                    .collect();
            }
            ts_control::PeerUpdate::Delta { upsert, remove } => {
                for peer in upsert {
                    if peer.unsigned_peer_api_only {
                        self.unlocked_allowed_ips
                            .insert(peer.id, peer.accepted_routes.clone());
                    } else {
                        // A peer that control has since signed is no longer unlocked.
                        self.unlocked_allowed_ips.remove(&peer.id);
                    }
                }
                for id in remove {
                    self.unlocked_allowed_ips.remove(id);
                }
            }
        }
        self.unlocked_allowed_ips != before
    }

    /// Re-run Go's `unlockedNodesPermitted` over the compiled filter and the tracked unlocked
    /// peers, returning whether the verdict changed. Logged on every transition, in both
    /// directions, because "the ACL this node is enforcing is not the one control sent" is not
    /// something an operator should have to infer from dropped traffic.
    fn reassess_unlocked_nodes(&mut self) -> bool {
        let allowed: Vec<ipnet::IpNet> = self
            .unlocked_allowed_ips
            .values()
            .flatten()
            .copied()
            .collect();
        let permitted = self
            .pf_state
            .0
            .values()
            .any(|ruleset| ts_packetfilter::permits_unlocked_nodes(ruleset, &allowed));

        if permitted == self.unlocked_nodes_permitted {
            return false;
        }
        if permitted {
            tracing::warn!(
                unlocked_peers = self.unlocked_allowed_ips.len(),
                "control's packet filter grants network access to a peer outside tailnet lock \
                 (UnsignedPeerAPIOnly); ignoring the whole filter"
            );
        } else {
            tracing::info!("control's packet filter no longer grants an unlocked peer access");
        }
        self.unlocked_nodes_permitted = permitted;
        true
    }
}

impl Message<Arc<ts_control::StateUpdate>> for PacketfilterUpdater {
    type Reply = ();

    async fn handle(
        &mut self,
        state_update: Arc<ts_control::StateUpdate>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        // Track this node's own addresses (for the shields-up deny set) whenever the netmap carries a
        // self node — independent of the packet-filter ruleset, which may update on a different
        // response. Mirror the self-address set the netstack accepts on.
        if self.env.block_incoming
            && let Some(self_node) = state_update.node.as_ref()
        {
            self.self_addrs = self_node_addresses(self_node, self.env.enable_ipv6);
        }

        // Surface the retained cap-grants for flow-scoped WhoIs. They ride the same response as the
        // compiled filter (`Some` exactly when `packetfilter` is `Some`), so update the cell here —
        // `send_replace` keeps the latest current even with no active receiver.
        if let Some(grants) = &state_update.cap_grants {
            self.cap_grants_tx.send_replace(Arc::new(grants.clone()));
        }

        // Track the unlocked peers *before* judging the filter: a single response carries both, and
        // a filter compiled against last response's peer set is exactly the gap this check closes.
        let peers_changed = self.track_unlocked_peers(&state_update);

        let filter_changed = match &state_update.packetfilter {
            Some((pf_ruleset, pf_map)) => {
                ts_packetfilter_state::apply_update(&mut self.pf_state, pf_ruleset.clone(), pf_map);
                tracing::trace!(updated_packet_filter = ?self.pf_state.0);
                true
            }
            None => false,
        };

        if !filter_changed && !peers_changed {
            return;
        }

        // Go re-runs this whenever either side moves, so a netmap that only *adds* an unlocked peer
        // invalidates a filter that was fine when it was compiled.
        let verdict_changed = self.reassess_unlocked_nodes();

        if !filter_changed && !verdict_changed {
            return;
        }

        let filter = self.published_filter();

        // The L7 gate's copy first, and by assignment rather than by publication: the cell can
        // neither drop it nor deliver it out of order, so the peerAPI DoH gate can never be left
        // refusing peers against a filter older than the one the dataplane is enforcing. See
        // [`LiveFilterRx`] for why the bus alone is not enough for this consumer.
        self.live_filter_tx.send_replace(Some(filter.clone()));

        if let Err(e) = self.env.publish(filter).await {
            tracing::error!(error = %e, "publishing packet filter state");
        }
    }
}

/// This node's own host addresses for the shields-up deny set: tailnet IPv4 (and IPv6 when enabled),
/// the MagicDNS service IP, and control-assigned VIP-service addresses — the same self-destined set
/// the application netstack accepts packets for. Mirrors `netstack_actor::overlay_addresses`.
fn self_node_addresses(self_node: &ts_control::Node, enable_ipv6: bool) -> Vec<std::net::IpAddr> {
    let tailnet_address = &self_node.tailnet_address;
    let mut addrs: Vec<std::net::IpAddr> = vec![tailnet_address.ipv4.addr().into()];
    if enable_ipv6 {
        addrs.push(tailnet_address.ipv6.addr().into());
    }
    addrs.push(core::net::Ipv4Addr::new(100, 100, 100, 100).into());
    for vip in self_node.service_addresses() {
        if vip.is_ipv6() && !enable_ipv6 {
            continue;
        }
        if !addrs.contains(&vip) {
            addrs.push(vip);
        }
    }
    addrs
}

#[cfg(test)]
mod unlocked_node_tests {
    //! Go refuses to install a packet filter that grants network access to a peer control marked
    //! `UnsignedPeerAPIOnly` — `packetFilterPermitsUnlockedNodes` in `ipn/ipnlocal/local.go`,
    //! reached from `nodeBackend.unlockedNodesPermitted`, at
    //! `023255e8a27ec9f6a21d24e3eda21c052ff72af3`. Such a peer carries no tailnet-lock signature,
    //! so the lock covers nothing control says about it; the route clamp closes `AllowedIPs`, and
    //! this closes the other door, where control writes the peer's own address into the ACL
    //! instead.
    //!
    //! These drive the production `PacketfilterUpdater` over real netmaps and read the filter it
    //! publishes, so they fail if the check is removed anywhere along that path.

    use std::sync::Arc;

    use kameo::actor::Spawn;
    use tokio::sync::watch;
    use ts_control::{Node, StableNodeId, TailnetAddress};
    use ts_packetfilter::FilterExt;

    use super::*;

    fn forwarder_cfg() -> crate::env::ForwarderConfig {
        crate::env::ForwarderConfig {
            accept_routes: false,
            accept_dns: true,
            exit_node: None,
            forward_routes: vec![],
            forward_tcp_ports: vec![],
            forward_udp_ports: vec![],
            forward_all_ports: false,
            forward_exit_egress: false,
            block_incoming: false,
            exit_proxy: None,
            peerapi_port: None,
            taildrop_dir: None,
            enable_ipv6: false,
            wireguard_listen_port: None,
            network_monitor: false,
            persistent_keepalive_interval: None,
            ingress_active: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Stand up the production updater, returning it with the live-filter cell it writes.
    fn updater() -> (ActorRef<PacketfilterUpdater>, LiveFilterRx) {
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let env =
            crate::env::Env::new(ts_keys::NodeState::generate(), shutdown_rx, forwarder_cfg());
        let (cap_grants_tx, _cap_grants_rx) = watch::channel(Default::default());
        let (filter_tx, filter_rx) = watch::channel(None);
        let updater = PacketfilterUpdater::spawn((env, cap_grants_tx, filter_tx));
        (updater, filter_rx)
    }

    /// A peer at `100.64.0.<id>`, `unsigned_peer_api_only` as given. `accepted_routes` mirrors what
    /// `From<ts_control_serde::Node>` produces: its own address, since the #365 clamp has already
    /// run by the time a `Node` exists.
    fn peer(id: i64, unsigned: bool) -> Node {
        let v4: ipnet::IpNet = format!("100.64.0.{id}/32").parse().unwrap();
        Node {
            id,
            stable_id: StableNodeId(format!("n{id}")),
            hostname: format!("peer{id}"),
            user_id: 0,
            tailnet: None,
            tags: vec![],
            addresses: vec![v4],
            tailnet_address: TailnetAddress {
                ipv4: v4.to_string().parse().unwrap(),
                ipv6: "fd7a::1/128".parse().unwrap(),
            },
            node_key: [0u8; 32].into(),
            node_key_expiry: None,
            expired: false,
            online: None,
            last_seen: None,
            key_signature: vec![],
            machine_key: None,
            disco_key: None,
            accepted_routes: vec![v4],
            underlay_addresses: vec![],
            derp_region: None,
            cap: Default::default(),
            cap_map: Default::default(),
            peerapi_port: None,
            peerapi_dns_proxy: false,
            is_wireguard_only: false,
            exit_node_dns_resolvers: vec![],
            peer_relay: false,
            ssh_host_keys: vec![],
            service_vips: Default::default(),
            unsigned_peer_api_only: unsigned,
        }
    }

    /// A rule letting `src` reach this node on every TCP port.
    fn tcp_rule(src: &str) -> ts_packetfilter::Rule {
        ts_packetfilter::Rule {
            src: ts_packetfilter::SrcMatch {
                pfxs: vec![src.parse().unwrap()],
                caps: vec![],
            },
            protos: vec![ts_packetfilter::IpProto::TCP],
            dst: vec![ts_packetfilter::DstMatch {
                ports: 0..=u16::MAX,
                ips: vec!["100.64.0.1/32".parse().unwrap()],
            }],
        }
    }

    /// A netmap update carrying whichever of the peer set and the packet filter is given.
    fn netmap(
        peer_update: Option<ts_control::PeerUpdate>,
        rules: Option<Vec<ts_packetfilter::Rule>>,
    ) -> Arc<ts_control::StateUpdate> {
        Arc::new(ts_control::StateUpdate {
            session_handle: None,
            seq: 0,
            keep_alive: false,
            derp: None,
            node: None,
            peer_update,
            peer_patches: Vec::new(),
            user_profiles: Vec::new(),
            ping: None,
            packetfilter: rules.map(|r| (Some(r), Default::default())),
            cap_grants: None,
            pop_browser_url: None,
            dial_plan: None,
            dns_config: None,
            ssh_policy: None,
            tka: None,
            online_change: Default::default(),
            peer_seen_change: Default::default(),
            control_time: None,
        })
    }

    /// Ask the published filter whether `src` may open TCP 22 on this node — the same question the
    /// inbound dataplane asks.
    fn admits(filter_rx: &LiveFilterRx, src: &str) -> bool {
        let filter = filter_rx.borrow().clone().expect("a filter was published");
        filter.0.can_access(
            &ts_packetfilter::PacketInfo {
                src: src.parse().unwrap(),
                dst: "100.64.0.1".parse().unwrap(),
                ip_proto: ts_packetfilter::IpProto::TCP,
                port: 22,
                l4: ts_packetfilter::L4Header::Unknown,
            },
            core::iter::empty(),
        )
    }

    /// Deliver a netmap and wait for the updater to republish. Every netmap in these tests moves
    /// either the filter or the verdict, so each one is followed by exactly one write to the cell.
    async fn deliver(
        updater: &ActorRef<PacketfilterUpdater>,
        filter_rx: &mut LiveFilterRx,
        update: Arc<ts_control::StateUpdate>,
    ) {
        filter_rx.mark_unchanged();
        updater.tell(update).await.expect("netmap delivered");
        tokio::time::timeout(std::time::Duration::from_secs(5), filter_rx.changed())
            .await
            .expect("the updater republished within five seconds")
            .expect("the live-filter cell is still open");
    }

    /// The whole filter goes, not just the unlocked peer's rule. Upstream drops the match list
    /// wholesale on the reasoning that a control server writing this ACL is broken or malicious, so
    /// nothing else it sent in the same filter is trustworthy either.
    #[tokio::test]
    async fn an_acl_granting_an_unlocked_peer_access_is_ignored_wholesale() {
        let (updater, mut filter_rx) = updater();

        deliver(
            &updater,
            &mut filter_rx,
            netmap(
                Some(ts_control::PeerUpdate::Full(vec![
                    peer(9, true),
                    peer(10, false),
                ])),
                Some(vec![tcp_rule("100.64.0.9/32"), tcp_rule("100.64.0.10/32")]),
            ),
        )
        .await;

        assert!(
            !admits(&filter_rx, "100.64.0.9"),
            "an ACL naming a peer outside tailnet lock must not be installed"
        );
        assert!(
            !admits(&filter_rx, "100.64.0.10"),
            "the rest of that filter must go with it, not be kept as a partial ACL"
        );
    }

    /// The negative direction, without which the test above would pass against a filter that simply
    /// never installs anything: the identical ACL, with the peer signed, is installed as sent.
    #[tokio::test]
    async fn the_same_acl_is_installed_when_no_peer_is_unlocked() {
        let (updater, mut filter_rx) = updater();

        deliver(
            &updater,
            &mut filter_rx,
            netmap(
                Some(ts_control::PeerUpdate::Full(vec![
                    peer(9, false),
                    peer(10, false),
                ])),
                Some(vec![tcp_rule("100.64.0.9/32"), tcp_rule("100.64.0.10/32")]),
            ),
        )
        .await;

        assert!(admits(&filter_rx, "100.64.0.9"));
        assert!(admits(&filter_rx, "100.64.0.10"));
    }

    /// Either side can move first. A filter that was valid when it was compiled becomes invalid the
    /// moment control adds an unlocked peer the ACL already covers — and that netmap carries no
    /// packet filter at all, so a check wired only to the filter update would miss it.
    #[tokio::test]
    async fn an_unlocked_peer_arriving_later_invalidates_the_installed_filter() {
        let (updater, mut filter_rx) = updater();

        deliver(
            &updater,
            &mut filter_rx,
            netmap(
                Some(ts_control::PeerUpdate::Full(vec![peer(9, false)])),
                Some(vec![tcp_rule("100.64.0.0/24")]),
            ),
        )
        .await;
        assert!(
            admits(&filter_rx, "100.64.0.9"),
            "a filter with no unlocked peer in the netmap is installed"
        );

        // Peers only: control marks the same peer unsigned, and sends no new ACL.
        deliver(
            &updater,
            &mut filter_rx,
            netmap(
                Some(ts_control::PeerUpdate::Delta {
                    upsert: vec![peer(9, true)],
                    remove: vec![],
                }),
                None,
            ),
        )
        .await;
        assert!(
            !admits(&filter_rx, "100.64.0.9"),
            "an unlocked peer appearing under an existing ACL must invalidate that ACL"
        );
    }

    /// And back again: the filter is set aside, not destroyed, so once the unlocked peer leaves the
    /// netmap the ACL control sent is enforced again without control having to resend it.
    #[tokio::test]
    async fn removing_the_unlocked_peer_restores_the_filter() {
        let (updater, mut filter_rx) = updater();

        deliver(
            &updater,
            &mut filter_rx,
            netmap(
                Some(ts_control::PeerUpdate::Full(vec![peer(9, true)])),
                Some(vec![tcp_rule("100.64.0.0/24")]),
            ),
        )
        .await;
        assert!(!admits(&filter_rx, "100.64.0.9"));

        deliver(
            &updater,
            &mut filter_rx,
            netmap(
                Some(ts_control::PeerUpdate::Delta {
                    upsert: vec![],
                    remove: vec![9],
                }),
                None,
            ),
        )
        .await;
        assert!(
            admits(&filter_rx, "100.64.0.9"),
            "the compiled filter is set aside while an unlocked peer is present, not dropped"
        );
    }
}
