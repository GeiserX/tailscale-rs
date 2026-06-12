use core::time::Duration;

/// Netstack configuration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Config {
    /// Capacity of the command channel.
    ///
    /// If `None`, the channel is unbounded.
    pub command_channel_capacity: Option<usize>,

    /// Maximum transmission unit of the underlying net device.
    pub mtu: usize,

    /// Assign the IPv4 and IPv6 loopback addresses to the interface.
    pub loopback: bool,

    /// The default size of buffer allocated for each UDP socket created.
    pub udp_buffer_size: usize,
    /// The default number of pending messages supported for each UDP socket created.
    pub udp_message_count: usize,

    /// The default size of buffer allocated (for both the rx and tx half) of each TCP socket
    /// created.
    ///
    /// This sizes the smoltcp send/receive window *per direction* — each socket allocates one
    /// buffer of this size for rx and another for tx, so a socket consumes roughly `2 ×
    /// tcp_buffer_size`. smoltcp has no window auto-tuning, so this value caps the bandwidth-delay
    /// product of a single flow: a 16 KiB window throttles a flow to roughly 1.6 Mbps at an 80 ms
    /// RTT, which visibly throttles large model-API responses even at 1x. The default is therefore
    /// 256 KiB per direction (~512 KiB per socket); lower it only on memory-constrained deployments
    /// with many concurrent sockets.
    ///
    /// **Memory at scale (exit-node / subnet-router operators).** Because the per-socket buffers
    /// above are eager, concurrent-flow count multiplies them directly: at the 256 KiB default a
    /// host holding 1,000 simultaneous forwarded TCP flows pins ~512 MB just in TCP buffers, which
    /// is a real fraction of a 4 GB exit node. This matters most on the *forwarder* netstack (it
    /// fans out one socket per forwarded exit/subnet flow); the application netstack only carries
    /// the local tsnet app's own sockets. If you forward many concurrent flows on a small box,
    /// set this knob lower (e.g. 64 KiB) and accept the per-flow throughput cap as the trade.
    pub tcp_buffer_size: usize,

    /// TCP keep-alive probe interval applied to every TCP socket. When set, smoltcp sends a
    /// keep-alive probe after this much idle time, which (together with [`tcp_timeout`]) lets an
    /// idle or silently-dead connection be reaped instead of pinned forever.
    ///
    /// `None` disables keep-alive (smoltcp's default), which — combined with no timeout — means a
    /// peer that completes a handshake then goes silent holds its socket (and its ~`2 ×
    /// tcp_buffer_size` buffers) indefinitely. Defaults to 60s, comparable to Go's TCP keep-alive.
    ///
    /// [`tcp_timeout`]: Self::tcp_timeout
    pub tcp_keep_alive_interval: Option<Duration>,

    /// TCP timeout applied to every TCP socket — the socket aborts the connection if the remote
    /// fails to respond within this duration to a connect, to in-flight transmit data, or to a
    /// keep-alive probe (see smoltcp `Socket::set_timeout`). This is the backstop that actually
    /// reclaims a half-open or idle-but-dead connection: without it, smoltcp's `timed_out()` is
    /// always false and the socket lingers until the peer happens to send something.
    ///
    /// `None` disables the timeout (smoltcp's default — the leak described above). Defaults to
    /// 120s, comparable to a TCP user-timeout. Should be larger than [`tcp_keep_alive_interval`] so
    /// a probe has time to be answered before the timeout fires.
    ///
    /// [`tcp_keep_alive_interval`]: Self::tcp_keep_alive_interval
    pub tcp_timeout: Option<Duration>,

    /// Maximum number of not-yet-accepted connections per TCP listener — the sum of half-open
    /// (`SYN-RECEIVED`) and established-but-unaccepted sockets. When a listener is at this bound and
    /// a new connection arrives, the oldest **half-open** socket is aborted (RST) to make room;
    /// once no half-open remain, the oldest **established-but-unaccepted** socket is shed instead.
    /// This stops a SYN/handshake flood growing the per-listener queues (and the global socket set)
    /// without limit. Mirrors the accept-backlog bound a kernel / gVisor `tcpip` enforces.
    ///
    /// Defaults to 128. A value of `0` is treated as `1` (the backlog cannot be disabled — an
    /// unbounded accept queue is the exhaustion this knob exists to prevent); raise it for a
    /// high-fan-in listener, but note each queued half-open still holds a full `2 ×
    /// tcp_buffer_size` allocation, so a large backlog × the buffer size is the worst-case pin.
    pub tcp_listen_backlog: usize,

    /// The default size of buffer allocated for each raw socket.
    pub raw_buffer_size: usize,
    /// The default number of pending messages supported for each raw socket.
    pub raw_message_count: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            command_channel_capacity: Some(32),

            mtu: 1500,

            loopback: false,

            udp_buffer_size: 1024 * 4,
            udp_message_count: 32,

            tcp_buffer_size: 1024 * 256,

            tcp_keep_alive_interval: Some(Duration::from_secs(60)),
            tcp_timeout: Some(Duration::from_secs(120)),
            tcp_listen_backlog: 128,

            raw_buffer_size: 1024 * 4,
            raw_message_count: 32,
        }
    }
}
