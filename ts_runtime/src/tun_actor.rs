//! TUN transport-mode actor: rides the same dataplane overlay seam as [`NetstackActor`], but
//! moves application packets between the dataplane and a real kernel TUN interface instead of a
//! userspace smoltcp netstack.
//!
//! In TUN mode there is no userspace application netstack and no MagicDNS responder: packets flow
//! `OS-TUN <-> dataplane <-> overlay`. Netstack-only public APIs surface
//! [`ErrorKind::UnsupportedInTunMode`](crate::ErrorKind::UnsupportedInTunMode).

use core::num::NonZeroU16;
use std::sync::Arc;

use kameo::{
    actor::ActorRef,
    message::{Context, Message},
};
use tokio::task::JoinSet;
use ts_transport::OverlayTransport;
use ts_transport_tun::{AsyncTunTransport, Config as TunDeviceConfig};

use crate::{
    Error,
    dataplane::{OverlayFromDataplane, OverlayToDataplane},
    env::Env,
};

/// The TUN transport-mode actor.
///
/// Lazily creates the TUN device on the first [`ts_control::StateUpdate`] that carries a self-node
/// (the device prefix is the runtime-assigned tailnet `/32`, unknown before then). Once created,
/// two pump tasks held in the [`JoinSet`] move packets up to and down from the dataplane; they die
/// with the actor.
pub struct TunActor {
    /// Tasks pumping packets between the device and the dataplane. Dropped with the actor, which
    /// aborts them — the device handle they hold is then dropped, tearing down the interface.
    _joinset: JoinSet<()>,

    /// The control-supplied TUN knobs (name/MTU), used to build the device on the first
    /// StateUpdate. The tailnet prefix is supplied at that point from the self-node.
    tun_config: ts_control::TunConfig,

    /// `Some` until the device is created on the first StateUpdate; `.take()`n into the up-pump
    /// task at that point so the device is built exactly once.
    overlay_to_dataplane: Option<OverlayToDataplane>,

    /// `Some` until the device is created on the first StateUpdate; `.take()`n into the down-pump
    /// task at that point so the device is built exactly once.
    overlay_from_dataplane: Option<OverlayFromDataplane>,
}

/// Build the device config from the control-supplied [`ts_control::TunConfig`] plus the
/// runtime-assigned tailnet `/32` prefix. Mirrors [`env::exit_proxy_to_forwarder`](crate::env)
/// (conversion at the `ts_runtime` boundary).
///
/// Defaults: name `"tailscale0"`, MTU `1280` (Tailscale's overlay MTU). `mtu` is `Option<u16>`;
/// `0` is invalid so `and_then(NonZeroU16::new)` rejects a stray `0` and falls back to `1280`.
pub(crate) fn tun_config_from_control(
    cfg: &ts_control::TunConfig,
    prefix: ipnet::Ipv4Net,
) -> TunDeviceConfig {
    TunDeviceConfig {
        name: cfg.name.clone().unwrap_or_else(|| "tailscale0".to_owned()),
        mtu: cfg
            .mtu
            .and_then(NonZeroU16::new)
            .unwrap_or(NonZeroU16::new(1280).unwrap()),
        prefix: ipnet::IpNet::V4(prefix),
    }
}

impl kameo::Actor for TunActor {
    type Args = (
        Env,
        ts_control::TunConfig,
        OverlayToDataplane,
        OverlayFromDataplane,
    );
    type Error = Error;

    async fn on_start(
        (env, tun_config, overlay_to_dataplane, overlay_from_dataplane): Self::Args,
        slf: ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        // We need the tailnet /32 prefix to build the device, which control only assigns at
        // runtime. Subscribe and build the device lazily on the first StateUpdate carrying a node.
        env.subscribe::<Arc<ts_control::StateUpdate>>(&slf).await?;

        Ok(Self {
            _joinset: JoinSet::new(),
            tun_config,
            overlay_to_dataplane: Some(overlay_to_dataplane),
            overlay_from_dataplane: Some(overlay_from_dataplane),
        })
    }
}

impl Message<Arc<ts_control::StateUpdate>> for TunActor {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: Arc<ts_control::StateUpdate>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        let Some(self_node) = &msg.node else {
            return;
        };

        // Build the device exactly once: the first StateUpdate with a node `.take()`s the overlay
        // halves; subsequent updates find them gone and short-circuit.
        let (Some(up), Some(down)) = (
            self.overlay_to_dataplane.take(),
            self.overlay_from_dataplane.take(),
        ) else {
            return;
        };

        let device_config =
            tun_config_from_control(&self.tun_config, self_node.tailnet_address.ipv4);

        // FAIL-CLOSED, no silent fallback: a message handler cannot return `Result` to propagate a
        // device-creation failure back to `Runtime::spawn`, and the device cannot be created
        // eagerly at spawn time (the tailnet prefix is unknown until this first StateUpdate). So on
        // failure we log a single clear error line and leave the actor up but idle — no packets
        // flow (no leak), and we never fall back to a netstack or a direct dial.
        let device = match AsyncTunTransport::new(&device_config) {
            Ok(d) => Arc::new(d),
            Err(e) => {
                tracing::error!(error = %e, "TUN device creation failed; no overlay data path (fail-closed)");
                return;
            }
        };

        // UP: device -> dataplane.
        let dev_up = device.clone();
        self._joinset.spawn(async move {
            loop {
                for pkt in dev_up.recv().await {
                    match pkt {
                        Ok(p) => {
                            if up.send(vec![p]).is_err() {
                                return;
                            }
                        }
                        Err(e) => tracing::warn!(error = %e, "tun recv error"),
                    }
                }
            }
        });

        // DOWN: dataplane -> device.
        let dev_down = device.clone();
        let mut down = down;
        self._joinset.spawn(async move {
            while let Some(bufs) = down.recv().await {
                if let Err(e) = dev_down.send(bufs).await {
                    tracing::warn!(error = %e, "tun send error");
                }
            }

            tracing::warn!("tun downlink shut down!");
        });

        tracing::debug!(prefix = ?self_node.tailnet_address.ipv4, "TUN device created");
    }
}

#[cfg(test)]
mod tests {
    use core::net::Ipv4Addr;

    use ipnet::Ipv4Net;
    use ts_control::TunConfig;

    use super::tun_config_from_control;

    fn prefix() -> Ipv4Net {
        Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 1), 32).unwrap()
    }

    /// Defaults must apply when control supplies no knobs: name `tailscale0`, MTU `1280`, and the
    /// device prefix must be exactly the runtime-assigned `/32` passed in.
    #[test]
    fn defaults_and_prefix() {
        let cfg = TunConfig {
            name: None,
            mtu: None,
        };
        let dev = tun_config_from_control(&cfg, prefix());

        assert_eq!(dev.name, "tailscale0");
        assert_eq!(dev.mtu.get(), 1280);
        assert_eq!(dev.prefix, ipnet::IpNet::V4(prefix()));
    }

    /// `mtu = Some(0)` is invalid (NonZeroU16 rejects it) and must fall back to the 1280 default,
    /// while a real MTU is honored. A custom name is honored verbatim.
    #[test]
    fn mtu_zero_falls_back_and_overrides_honored() {
        let zero = TunConfig {
            name: Some("tun9".to_owned()),
            mtu: Some(0),
        };
        let dev_zero = tun_config_from_control(&zero, prefix());
        assert_eq!(dev_zero.name, "tun9");
        assert_eq!(
            dev_zero.mtu.get(),
            1280,
            "mtu=Some(0) must fall back to 1280"
        );

        let big = TunConfig {
            name: None,
            mtu: Some(9000),
        };
        let dev_big = tun_config_from_control(&big, prefix());
        assert_eq!(dev_big.mtu.get(), 9000, "a valid mtu must be honored");
    }
}
