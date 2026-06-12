use alloc::vec;

use smoltcp::socket::tcp;

use crate::Netstack;

mod listener;
mod stream;

pub use listener::{ListenerHandle, TcpListenerState};

impl Netstack {
    fn tcp_buffer(&self) -> tcp::SocketBuffer<'static> {
        tcp::SocketBuffer::new(vec![0; self.config.tcp_buffer_size])
    }

    /// Build a TCP socket with the configured rx/tx buffers and the idle/dead-connection reaping
    /// policy applied. This is the single chokepoint for socket creation so the keep-alive +
    /// timeout (which together let smoltcp abort a silently-dead or idle connection instead of
    /// pinning it forever) can never be forgotten on a code path: every listener, accepted, and
    /// dialed socket goes through here.
    ///
    /// Scope of the timeout: it tears down the *wire* connection (smoltcp moves the socket to
    /// `Closed` and emits a RST) and the state change wakes any blocked reader, so an
    /// actively-polling consumer learns the socket died and drops its [`TcpStream`], whose `Drop`
    /// routes through `drain_tcp_closes` to free the `socket_set` slot. For a netstack-owned socket
    /// (a listener / half-open / accept-queue entry) the backlog path frees it directly. The one
    /// case the timeout does *not* immediately reclaim is an accepted socket whose consumer is idle
    /// (not polling) — the wire is torn down but the in-memory socket lingers until the consumer
    /// next touches it; reclaiming that without the consumer is unsafe (the handle is consumer-owned)
    /// and is tracked separately.
    ///
    /// [`TcpStream`]: ::ts_netstack_smoltcp_socket::tcp::stream::TcpStream
    fn new_tcp_socket(&self) -> tcp::Socket<'static> {
        let mut sock = tcp::Socket::new(self.tcp_buffer(), self.tcp_buffer());
        // `core::time::Duration` → smoltcp's own `Duration` (millisecond granularity is plenty for
        // a 60s/120s policy). Skip either knob when `None` (smoltcp's no-reaping default).
        if let Some(interval) = self.config.tcp_keep_alive_interval {
            sock.set_keep_alive(Some(smoltcp::time::Duration::from_millis(
                interval.as_millis() as u64,
            )));
        }
        if let Some(timeout) = self.config.tcp_timeout {
            sock.set_timeout(Some(smoltcp::time::Duration::from_millis(
                timeout.as_millis() as u64,
            )));
        }
        sock
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use smoltcp::time::Instant;

    use crate::{Config, Netstack};

    /// Every socket `new_tcp_socket` builds carries the configured keep-alive interval and timeout,
    /// so smoltcp's `timed_out()` can actually fire and reap a silently-dead/idle connection. Before
    /// this, `set_keep_alive`/`set_timeout` were never called and a socket lingered forever.
    #[test]
    fn new_tcp_socket_applies_keepalive_and_timeout_from_config() {
        let stack = Netstack::new(
            Config {
                tcp_keep_alive_interval: Some(Duration::from_secs(60)),
                tcp_timeout: Some(Duration::from_secs(120)),
                ..Default::default()
            },
            Instant::ZERO,
        );

        let sock = stack.new_tcp_socket();
        assert_eq!(
            sock.keep_alive(),
            Some(smoltcp::time::Duration::from_secs(60)),
            "keep-alive interval must be applied"
        );
        assert_eq!(
            sock.timeout(),
            Some(smoltcp::time::Duration::from_secs(120)),
            "timeout must be applied"
        );
    }

    /// `None` knobs leave smoltcp at its no-reaping default — preserved so a deployment can opt out
    /// explicitly (and so the test pins that `None` really means "don't set it", not "set to 0").
    #[test]
    fn new_tcp_socket_honors_disabled_reaping() {
        let stack = Netstack::new(
            Config {
                tcp_keep_alive_interval: None,
                tcp_timeout: None,
                ..Default::default()
            },
            Instant::ZERO,
        );

        let sock = stack.new_tcp_socket();
        assert_eq!(sock.keep_alive(), None);
        assert_eq!(sock.timeout(), None);
    }
}
