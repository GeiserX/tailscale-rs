#![doc = include_str!("../README.md")]

use std::{collections::HashMap, sync::Arc, time::Instant};

use ts_bart::RoutingTable;
use ts_overlay_router as or;
use ts_packet::PacketMut;
use ts_packetfilter::{FilterExt, IpProto};
use ts_time::{Handle, Scheduler};
use ts_transport::{OverlayTransportId, PeerId, UnderlayTransportId};
use ts_tunnel::{Endpoint, NodeKeyPair};
use ts_underlay_router as ur;

pub mod async_tokio;

/// The single link-local destination Go's filter `pre()` exempts from the link-local drop: the
/// cloud-metadata address `169.254.169.254` (Go `isAllowedLinkLocal`).
const ALLOWED_LINK_LOCAL_V4: std::net::Ipv4Addr = std::net::Ipv4Addr::new(169, 254, 169, 254);

/// Whether an inbound packet to destination `dst` must be dropped BEFORE consulting the ACL rules,
/// mirroring Go's filter `pre()`: drop multicast destinations (`ReasonMulticast`) and link-local
/// unicast destinations that are not the allowlisted cloud-metadata address (`ReasonLinkLocalUnicast`).
/// Returning `true` means drop. This runs ahead of `can_access` so a permissive ACL cannot admit the
/// multicast / link-local traffic Go rejects unconditionally.
///
/// Go's `isAllowedLinkLocal` is `dst == gcpDNSAddr || any(LinkLocalAllowHooks)`; only the static
/// `gcpDNSAddr` arm is modeled here. The dynamic `LinkLocalAllowHooks` slice is empty in a plain
/// engine/tsnet embedding (its only upstream producer is the GCP metadata path), so the omission is
/// behaviorally equivalent for this fork; a feature that needs a dynamic link-local allowlist would
/// have to extend this. Like Go's `netip.Addr` predicates, an IPv4-mapped-IPv6 destination (e.g.
/// `::ffff:224.0.0.1`) matches NEITHER arm and falls through to the ACL — we deliberately do not
/// canonicalize/unmap, to stay byte-faithful to Go (see the mapped-v6 test cases).
fn drop_before_rules(dst: std::net::IpAddr) -> bool {
    if dst.is_multicast() {
        return true;
    }
    match dst {
        // IPv4 link-local is 169.254.0.0/16; allow only the cloud-metadata address (Go parity).
        std::net::IpAddr::V4(v4) => v4.is_link_local() && v4 != ALLOWED_LINK_LOCAL_V4,
        // IPv6 unicast link-local is fe80::/10. (`Ipv6Addr::is_unicast_link_local` is unstable, so
        // test the prefix directly.) This fork is IPv4-only by default, but match Go for any v6.
        std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// A data plane subsystem that can be the subject of timer events.
pub enum Subsystem {
    /// The wireguard component.
    Wireguard,
}

/// The direction/path of a captured packet, mirroring Go Tailscale's `capture.Path`. The numeric
/// values are the on-wire path codes written into each pcap record's Tailscale preamble.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapturePath {
    /// A packet from the local device, heading out to a peer (pre-encrypt).
    FromLocal = 0,
    /// A packet received from a peer, decrypted, heading to the local device.
    FromPeer = 1,
    /// A packet synthesized by us toward the local device. Retained for Go `capture.Path` on-wire
    /// code parity (so captured pcap path codes match Go's, and a future synthesized-packet tee
    /// point can emit it); not currently emitted — the tee only produces `FromLocal`/`FromPeer`.
    SynthesizedToLocal = 2,
    /// A packet synthesized by us toward a peer. Retained for Go `capture.Path` on-wire code parity
    /// (see [`Self::SynthesizedToLocal`]); not currently emitted.
    SynthesizedToPeer = 3,
}

impl CapturePath {
    /// The on-wire path code (the `uint16` written into the pcap record preamble).
    pub fn code(self) -> u16 {
        self as u16
    }
}

/// A debug packet-capture hook. When installed on a [`DataPlane`], it is invoked with the path and
/// the raw IP packet bytes for every plaintext packet crossing the datapath. It must be cheap and
/// non-blocking — it runs inline on the single-threaded dataplane step, so a slow hook backs up the
/// datapath. Wrapped in `Arc` so it is cheap to clone and `Send + Sync` for the actor that installs
/// it.
pub type CaptureHook = std::sync::Arc<dyn Fn(CapturePath, &[u8]) + Send + Sync>;

/// Transforms packets to make tailscale happen.
pub struct DataPlane {
    /// Wireguard encryption/decryption.
    pub wireguard: Endpoint,

    /// Outbound overlay router.
    pub or_out: or::outbound::Router,
    /// Outbound underlay router.
    pub ur_out: ur::outbound::Router,

    /// Inbound source filter.
    pub src_filter_in: Arc<ts_bart::Table<PeerId>>,
    /// Inbound overlay router.
    pub or_in: or::inbound::Router,

    /// The packet filter.
    pub packet_filter: Arc<dyn ts_packetfilter::Filter + Send + Sync>,

    /// Events queued for future processing.
    pub events: Scheduler<Subsystem>,

    /// Next event for the wireguard subsystem.
    pub wg_next: Option<Handle<Subsystem>>,

    /// Optional debug packet-capture hook (Go `tstun.Wrapper` capture hook). `None` (the default)
    /// means no capture and zero datapath overhead. Installed/cleared at runtime by the dataplane
    /// actor; see [`DataPlane::process_outbound`]/[`DataPlane::process_inbound`] for the tee points.
    pub capture: Option<CaptureHook>,
}

impl DataPlane {
    /// Creates a new data plane for a wireguard node key.
    pub fn new(my_key: NodeKeyPair) -> Self {
        DataPlane {
            wireguard: Endpoint::new(my_key),
            or_out: Default::default(),
            ur_out: Default::default(),
            src_filter_in: Default::default(),
            or_in: Default::default(),
            events: Default::default(),
            packet_filter: Arc::new(ts_packetfilter::DropAllFilter),
            wg_next: None,
            capture: None,
        }
    }

    /// Processes packets originating from the local device.
    #[tracing::instrument(skip_all, fields(n_packets = packets.len()))]
    pub fn process_outbound(&mut self, packets: Vec<PacketMut>) -> OutboundResult {
        if let Some(hook) = &self.capture {
            for p in &packets {
                hook(CapturePath::FromLocal, p.as_ref());
            }
        }

        let or::outbound::Result {
            to_wireguard,
            loopback,
        } = self.or_out.route(packets);

        let to_wireguard = to_wireguard
            .into_iter()
            .map(|(k, v)| (ts_tunnel::PeerId(k.0), v))
            .collect::<Vec<_>>();

        let ts_tunnel::SendResult {
            to_peers: encrypted,
        } = self.wireguard.send(to_wireguard);

        let to_peers = self
            .ur_out
            .route(encrypted.into_iter().map(|(k, v)| (PeerId(k.0), v)));

        if let Some(next) = self.wireguard.next_event()
            && let Some(prev) = self
                .wg_next
                .replace(self.events.add(next, Subsystem::Wireguard))
        {
            prev.cancel();
        }

        OutboundResult { to_peers, loopback }
    }

    /// Processes packets received from elsewhere.
    pub fn process_inbound(
        &mut self,
        packets: impl IntoIterator<Item = PacketMut>,
    ) -> InboundResult {
        let ts_tunnel::RecvResult { to_local, to_peers } = self.wireguard.recv(packets);

        if let Some(hook) = &self.capture {
            for packets in to_local.values() {
                for p in packets {
                    hook(CapturePath::FromPeer, p.as_ref());
                }
            }
        }

        let to_local = to_local
            .into_iter()
            .map(|(peer_id, mut packets)| -> Vec<PacketMut> {
                let _span = tracing::trace_span!(
                    "src_filter_inbound",
                    peer_id = ?peer_id,
                    n_packet = packets.len(),
                )
                .entered();

                packets.retain(|packet| {
                    let Some(src) = packet.get_src_addr() else {
                        tracing::trace!("does not look like ip packet");
                        return false;
                    };
                    let verdict = if let Some(allowed_peer) = self.src_filter_in.lookup(src) {
                        *allowed_peer == PeerId(peer_id.0)
                    } else {
                        tracing::trace!(remote_ip = %src, "unknown peer address");
                        false
                    };
                    tracing::trace!(?src, verdict);
                    verdict
                });

                packets
            })
            .map(|mut v| {
                let _span =
                    tracing::trace_span!("packet_filter_inbound", n_packet = v.len()).entered();

                v.retain(|pkt| {
                    let Ok(pkt) = etherparse::SlicedPacket::from_ip(pkt.as_ref()) else {
                        tracing::trace!("does not look like ip packet");
                        return false;
                    };

                    let (proto, src, dst) = match pkt.net {
                        Some(etherparse::NetSlice::Ipv4(ipv4)) => (
                            IpProto::new(ipv4.payload().ip_number.0 as _),
                            ipv4.header().source_addr().into(),
                            ipv4.header().destination_addr().into(),
                        ),
                        Some(etherparse::NetSlice::Ipv6(ipv6)) => (
                            IpProto::new(ipv6.payload().ip_number.0 as _),
                            ipv6.header().source_addr().into(),
                            ipv6.header().destination_addr().into(),
                        ),
                        _ => {
                            // A packet that parsed as IP but is neither IPv4 nor IPv6 (e.g. a
                            // future/odd `NetSlice` shape). These bytes are attacker-controlled
                            // post-decrypt, so fail closed — drop it — rather than `unreachable!`,
                            // which would panic the single-threaded dataplane on a crafted packet.
                            // Go's filter `pre()` likewise returns Drop/"not-ip" here, never panics.
                            tracing::trace!("parsed packet is neither IPv4 nor IPv6; dropping");
                            return false;
                        }
                    };

                    // Pre-rule destination screen, mirroring Go filter `pre()`'s unconditional drops
                    // that run BEFORE any ACL rule: a packet to a multicast or (non-allowlisted)
                    // link-local-unicast destination is dropped regardless of the rules. Without this,
                    // a permissive ACL (dst `*` / `0.0.0.0/0`) would ACCEPT inbound multicast /
                    // link-local that Go drops pre-rules — the one ACCEPT-where-Go-DROPS gap. Bounded
                    // already by the source-attribution filter above (only attributable tailnet peers
                    // reach here), but matched to Go for correctness.
                    if drop_before_rules(dst) {
                        tracing::trace!(?dst, "dropping multicast/link-local dst (pre-rule)");
                        return false;
                    }

                    let (_src_port, dst_port) = match pkt.transport {
                        Some(etherparse::TransportSlice::Udp(udp)) => {
                            (udp.source_port(), udp.destination_port())
                        }
                        Some(etherparse::TransportSlice::Tcp(tcp)) => {
                            (tcp.source_port(), tcp.destination_port())
                        }
                        _ => (0, 0),
                    };

                    let info = ts_packetfilter::PacketInfo {
                        ip_proto: proto,
                        port: dst_port,
                        src,
                        dst,
                    };

                    // TODO(npry): wire in nodecaps
                    let caps = [];
                    let verdict = self.packet_filter.can_access(&info, caps);

                    tracing::trace!(?info, ?caps, verdict);

                    verdict
                });

                v
            });

        let to_peers = to_peers
            .into_iter()
            .map(|(k, v)| (ts_transport::PeerId(k.0), v));

        let to_local = self.or_in.route(to_local.flatten());
        let to_peers = self.ur_out.route(to_peers);

        if let Some(next) = self.wireguard.next_event()
            && let Some(prev) = self
                .wg_next
                .replace(self.events.add(next, Subsystem::Wireguard))
        {
            prev.cancel();
        }

        InboundResult { to_local, to_peers }
    }

    /// Return the next time at which [`DataPlane::process_events`] must be called.
    ///
    /// [`DataPlane::process_outbound`], [`DataPlane::process_inbound`] and
    /// [`DataPlane::process_events`] may all update the next event time. Callers should prefer
    /// calling `next_event` as needed to get a correct result, rather than store the returned
    /// value.
    pub fn next_event(&self) -> Option<Instant> {
        self.events.next_dispatch()
    }

    /// Process all queued events that are due for processing.
    ///
    /// Must be called at least as often as dictated by [`DataPlane::next_event`] for the
    /// data plane to function correctly. It is harmless to call it more frequently.
    pub fn process_events(&mut self) -> EventResult {
        let mut to_peers = HashMap::new();
        let now = Instant::now();
        for event in self.events.dispatch(now) {
            match event {
                Subsystem::Wireguard => {
                    let res = self.wireguard.dispatch_events(now);
                    to_peers.extend(
                        res.to_peers
                            .into_iter()
                            .map(|(id, pkts)| (ts_transport::PeerId(id.0), pkts)),
                    );
                }
            }
        }
        let to_peers = self.ur_out.route(to_peers);

        if let Some(next) = self.wireguard.next_event()
            && let Some(prev) = self
                .wg_next
                .replace(self.events.add(next, Subsystem::Wireguard))
        {
            prev.cancel();
        }

        EventResult { to_peers }
    }
}

/// The result of processing outbound packets.
pub struct OutboundResult {
    /// Packets to be sent into underlay transports for transmission.
    pub to_peers: HashMap<(UnderlayTransportId, PeerId), Vec<PacketMut>>,
    /// Packets to be looped back and delivered to overlay transports.
    pub loopback: HashMap<OverlayTransportId, Vec<PacketMut>>,
}

/// The result of processing inbound packets.
pub struct InboundResult {
    /// Decrypted packets to be delivered to overlay transports.
    pub to_local: HashMap<OverlayTransportId, Vec<PacketMut>>,
    /// Encrypted packets to be sent to wireguard peers by the underlay.
    pub to_peers: HashMap<(UnderlayTransportId, PeerId), Vec<PacketMut>>,
}

/// The result of processing an event.
#[derive(Default)]
pub struct EventResult {
    /// Encrypted packets to be sent to wireguard peers by the underlay.
    pub to_peers: HashMap<(UnderlayTransportId, PeerId), Vec<PacketMut>>,
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// Records `(path, bytes)` for each capture-hook invocation in a test.
    type CaptureLog = Arc<Mutex<Vec<(CapturePath, Vec<u8>)>>>;

    #[test]
    fn capture_path_codes() {
        assert_eq!(CapturePath::FromLocal.code(), 0);
        assert_eq!(CapturePath::FromPeer.code(), 1);
        assert_eq!(CapturePath::SynthesizedToLocal.code(), 2);
        assert_eq!(CapturePath::SynthesizedToPeer.code(), 3);
    }

    /// The pre-rule destination screen (Go filter `pre()`): multicast and non-allowlisted link-local
    /// destinations are dropped before the ACL; ordinary unicast and the cloud-metadata link-local
    /// exception pass through to the rules.
    #[test]
    fn pre_rule_drop_matches_go() {
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        // Dropped pre-rules:
        assert!(drop_before_rules(ip("224.0.0.1")), "IPv4 multicast dropped");
        assert!(
            drop_before_rules(ip("239.255.255.250")),
            "IPv4 multicast (SSDP) dropped"
        );
        assert!(
            drop_before_rules(ip("169.254.1.1")),
            "IPv4 link-local dropped"
        );
        assert!(drop_before_rules(ip("ff02::1")), "IPv6 multicast dropped");
        assert!(drop_before_rules(ip("fe80::1")), "IPv6 link-local dropped");
        assert!(
            drop_before_rules(ip("febf:ffff::1")),
            "top of fe80::/10 dropped (locks the 0xffc0/0xfe80 mask)"
        );
        // Passed through to the rules:
        assert!(
            !drop_before_rules(ip("fec0::1")),
            "just past fe80::/10 passes (locks the 0xffc0/0xfe80 mask)"
        );
        // IPv4-mapped-IPv6 destinations match NEITHER arm and fall through to the ACL, exactly as
        // Go's `netip.Addr` predicates do (no unmap/canonicalize). Pinning this guards against a
        // future "canonicalize to be safe" refactor silently diverging from Go.
        assert!(
            !drop_before_rules(ip("::ffff:224.0.0.1")),
            "4in6-mapped multicast falls through to the ACL, matching Go"
        );
        assert!(
            !drop_before_rules(ip("::ffff:169.254.1.1")),
            "4in6-mapped link-local falls through to the ACL, matching Go"
        );
        assert!(
            !drop_before_rules(ip("100.64.0.5")),
            "ordinary tailnet unicast passes"
        );
        assert!(
            !drop_before_rules(ip("8.8.8.8")),
            "ordinary public unicast passes"
        );
        assert!(
            !drop_before_rules(ip("169.254.169.254")),
            "the cloud-metadata link-local address is the Go-allowlisted exception"
        );
        assert!(
            !drop_before_rules(ip("fd7a:115c:a1e0::1")),
            "IPv6 ULA (tailnet) passes"
        );
    }

    /// Behavioral guard: an installed capture hook MUST be invoked with `CapturePath::FromLocal`
    /// and the exact packet bytes for every outbound packet. The tee sits at the top of
    /// `process_outbound`, before `or_out.route` consumes the packets, so it fires regardless of
    /// whether a wireguard peer exists (an empty router just drops the routed packets afterward).
    /// This is the only end-to-end guard that the dataplane capture tee actually fires; a refactor
    /// that drops the tee would leave every byte-layout test green.
    #[test]
    fn capture_hook_fires_on_outbound() {
        let mut dp = DataPlane::new(NodeKeyPair::new());

        let recorded: CaptureLog = Arc::new(Mutex::new(Vec::new()));
        let sink = recorded.clone();
        dp.capture = Some(Arc::new(move |path: CapturePath, bytes: &[u8]| {
            sink.lock().unwrap().push((path, bytes.to_vec()));
        }));

        // The outbound tee passes `p.as_ref()` as-given; the bytes need not be a valid IP packet.
        let payload: Vec<u8> = vec![0xde, 0xad, 0xbe, 0xef];
        let packet = PacketMut::from(payload.clone());

        drop(dp.process_outbound(vec![packet]));

        let captured = recorded.lock().unwrap();
        assert_eq!(captured.len(), 1, "hook must fire exactly once per packet");
        assert_eq!(captured[0].0, CapturePath::FromLocal);
        assert_eq!(captured[0].1, payload);
    }
}
