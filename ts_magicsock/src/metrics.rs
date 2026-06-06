//! magicsock client-metric counters, mirroring Go Tailscale's `magicsock_*` `clientmetric`s.
//!
//! These are process-global counters incremented on the direct (UDP) datapath hot loop. They are
//! exported (alongside every other registered metric) in Prometheus text format via
//! [`ts_metrics::write_prometheus`], surfaced to embedders through `Device::metrics()`. Naming
//! follows the Go convention `magicsock_<verb>_<transport>[_detail]`.

use std::sync::OnceLock;

use ts_metrics::Metric;

/// The set of magicsock counters, lazily registered once into the global metric registry.
pub(crate) struct MagicsockMetrics {
    /// Direct-path (UDP) WireGuard datagrams sent (`magicsock_send_udp`).
    pub send_udp: &'static Metric,
    /// Bytes sent over the direct UDP path (`magicsock_send_udp_bytes`).
    pub send_udp_bytes: &'static Metric,
    /// Errors attempting a direct UDP send (`magicsock_send_udp_error`).
    pub send_udp_error: &'static Metric,
    /// WireGuard datagrams received on the direct UDP path (`magicsock_recv_data_udp`).
    pub recv_data_udp: &'static Metric,
    /// Bytes received on the direct UDP path (`magicsock_recv_data_bytes_udp`).
    pub recv_data_bytes_udp: &'static Metric,

    /// Inbound disco Pings that PASSED the disco<->node-key binding check and were acted on
    /// (source learned as a candidate, pong sent). Counts authenticated direct-path open attempts
    /// from peers (`magicsock_disco_ping_recv`).
    pub disco_ping_recv: &'static Metric,
    /// Inbound disco Pings DROPPED fail-closed by the binding check — either the claimed node key
    /// was not bound to the sender's disco key in the netmap, or no binding verifier was installed.
    /// A nonzero value means peers are attempting direct paths we refuse to authenticate
    /// (`magicsock_disco_ping_recv_rejected`).
    pub disco_ping_recv_rejected: &'static Metric,
    /// Disco Pongs we sealed and sent over the UDP socket in reply to a ping that passed the
    /// binding check (`magicsock_disco_pong_sent`).
    pub disco_pong_sent: &'static Metric,
    /// All inbound disco Pongs received on the UDP socket, whether or not they matched an
    /// outstanding ping (`magicsock_disco_pong_recv`).
    pub disco_pong_recv: &'static Metric,
    /// Inbound disco Pongs that matched an outstanding ping we sent for this `(tx_id, src addr)`
    /// pair (`solicited`), confirming a direct path. The direct-vs-DERP ratio is derived from this
    /// versus DERP-relay counters (`magicsock_disco_pong_recv_solicited`).
    pub disco_pong_recv_solicited: &'static Metric,
    /// Inbound disco CallMeMaybe frames ACCEPTED after passing the netmap-membership gate, whose
    /// advertised endpoints we learned (`magicsock_disco_call_me_maybe_recv`).
    pub disco_call_me_maybe_recv: &'static Metric,
    /// Inbound disco CallMeMaybe frames DROPPED by the netmap-membership gate (sender disco key is
    /// not a current netmap member, or no verifier installed) (`magicsock_disco_call_me_maybe_recv_rejected`).
    pub disco_call_me_maybe_recv_rejected: &'static Metric,
    /// Disco Pings sent by [`crate::sock::MagicSock::send_pings`], counted per ping actually
    /// emitted over the UDP socket (`magicsock_disco_ping_sent`).
    pub disco_ping_sent: &'static Metric,
    /// Disco CallMeMaybe frames SEALED by [`crate::sock::MagicSock::seal_call_me_maybe`]. Named for
    /// what magicsock actually does — the DERP SEND happens in `ts_runtime` (multiderp), not here,
    /// so this counts seals (the closest magicsock-owned signal), not confirmed transmissions
    /// (`magicsock_disco_call_me_maybe_sealed`).
    pub disco_call_me_maybe_sealed: &'static Metric,
    /// STUN Binding Success Responses matched to an outstanding transaction id and processed
    /// (`handle_stun_response` returned `true`, including responses consumed but unusable such as
    /// IPv6-mapped or malformed) (`magicsock_stun_recv`).
    pub stun_recv: &'static Metric,
    /// Reflexive (STUN-equivalent) addresses actually recorded as NEW by `note_reflexive` — counts
    /// only fresh inserts, not duplicates of an address already learned (`magicsock_reflexive_learned`).
    pub reflexive_learned: &'static Metric,
}

/// Access the global magicsock counter set, registering it on first use.
pub(crate) fn metrics() -> &'static MagicsockMetrics {
    static M: OnceLock<MagicsockMetrics> = OnceLock::new();
    M.get_or_init(|| MagicsockMetrics {
        send_udp: Metric::new_counter("magicsock_send_udp"),
        send_udp_bytes: Metric::new_counter("magicsock_send_udp_bytes"),
        send_udp_error: Metric::new_counter("magicsock_send_udp_error"),
        recv_data_udp: Metric::new_counter("magicsock_recv_data_udp"),
        recv_data_bytes_udp: Metric::new_counter("magicsock_recv_data_bytes_udp"),
        disco_ping_recv: Metric::new_counter("magicsock_disco_ping_recv"),
        disco_ping_recv_rejected: Metric::new_counter("magicsock_disco_ping_recv_rejected"),
        disco_pong_sent: Metric::new_counter("magicsock_disco_pong_sent"),
        disco_pong_recv: Metric::new_counter("magicsock_disco_pong_recv"),
        disco_pong_recv_solicited: Metric::new_counter("magicsock_disco_pong_recv_solicited"),
        disco_call_me_maybe_recv: Metric::new_counter("magicsock_disco_call_me_maybe_recv"),
        disco_call_me_maybe_recv_rejected: Metric::new_counter(
            "magicsock_disco_call_me_maybe_recv_rejected",
        ),
        disco_ping_sent: Metric::new_counter("magicsock_disco_ping_sent"),
        disco_call_me_maybe_sealed: Metric::new_counter("magicsock_disco_call_me_maybe_sealed"),
        stun_recv: Metric::new_counter("magicsock_stun_recv"),
        reflexive_learned: Metric::new_counter("magicsock_reflexive_learned"),
    })
}
