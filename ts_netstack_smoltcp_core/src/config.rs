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
    pub tcp_buffer_size: usize,

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

            raw_buffer_size: 1024 * 4,
            raw_message_count: 32,
        }
    }
}
