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
    })
}
