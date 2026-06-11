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
}

#[derive(Clone)]
pub struct PacketFilterState(pub Arc<dyn ts_packetfilter::Filter + Send + Sync>);

impl kameo::Actor for PacketfilterUpdater {
    type Args = (Env, watch::Sender<CapGrants>);
    type Error = Error;

    async fn on_start(
        (env, cap_grants_tx): Self::Args,
        slf: ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        env.subscribe::<Arc<ts_control::StateUpdate>>(&slf).await?;

        Ok(Self {
            env,
            pf_state: Default::default(),
            self_addrs: Vec::new(),
            cap_grants_tx,
        })
    }
}

impl PacketfilterUpdater {
    /// Wrap the live control-derived filter for publication, applying shields-up when
    /// [`Env::block_incoming`] is set: inbound packets destined to one of this node's own addresses
    /// are dropped (refuse inbound peer connections terminating on us), while forwarded transit and
    /// replies handled by the underlying ACL pass through. A no-op wrapper when shields-up is off, so
    /// the non-shielded path is byte-for-byte the prior behavior.
    fn published_filter(&self) -> PacketFilterState {
        let inner = self.pf_state.clone();
        if self.env.block_incoming {
            PacketFilterState(Arc::new(ts_packetfilter::ShieldsUpFilter {
                inner,
                self_addrs: self.self_addrs.clone(),
            }))
        } else {
            PacketFilterState(Arc::new(inner))
        }
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

        let Some((pf_ruleset, pf_map)) = &state_update.packetfilter else {
            return;
        };

        ts_packetfilter_state::apply_update(&mut self.pf_state, pf_ruleset.clone(), pf_map);

        tracing::trace!(updated_packet_filter = ?self.pf_state.0);

        if let Err(e) = self.env.publish(self.published_filter()).await {
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
