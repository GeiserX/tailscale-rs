//! Connected UDP sockets per busy direct path (Apple platforms, opt-in).
//!
//! The underlay normally sends every datagram with `send_to` on one shared, unconnected socket.
//! On macOS that costs a route/PCB lookup per packet and, for IPv4, a random IP ID; under load
//! it is also where Macs get stuck at a low packet rate (tailscale/tailscale#21602). Once a
//! remote address has carried [`CONNECT_AFTER_BYTES`], this opens a second socket on the **same
//! local port** (`SO_REUSEPORT` on both), `connect`s it to that address and sends through it.
//! The kernel then delivers that remote's datagrams to the connected socket (the most specific
//! match), so each one gets a receive pump feeding the same demux as the shared socket. Nothing
//! the peer sees changes: same source address and port.
//!
//! Optionally sets `IP_DONTFRAG` (DF) on the connected sockets: macOS then skips the per-packet
//! random IP ID. WireGuard datagrams for the 1280-byte overlay are ~1360 bytes, under any
//! ordinary path MTU.
//!
//! Off by default; `TS_DEBUG_MAGICSOCK_CONNECTED_SOCKETS=1` / `TS_DEBUG_DONT_FRAGMENT=1` turn it
//! on (the knob names of the Go reference implementation). Any failure to open a connected socket
//! leaves that address on the shared socket for good.

use core::net::SocketAddr;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::{net::UdpSocket, sync::mpsc};

/// Bytes sent to one address before it gets a connected socket (Go uses the same 1 MiB).
pub(crate) const CONNECT_AFTER_BYTES: u64 = 1 << 20;

/// Max connected sockets at once (Go: 256).
pub(crate) const MAX_CONNECTED: usize = 256;

/// A connected socket unused for this long may be replaced when the table is full.
const IDLE_EVICT: Duration = Duration::from_secs(120);

/// Largest datagram a receive pump reads.
const PUMP_BUF: usize = 65_535;

/// A datagram received on a connected socket, handed to the shared demux.
pub(crate) type Received = (Vec<u8>, SocketAddr);

/// Settings read from the environment once, at bind.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Settings {
    pub(crate) connected_sockets: bool,
    pub(crate) dont_fragment: bool,
    /// Send batches on connected sockets with `sendmsg_x` (`batch.rs`).
    pub(crate) batched_io: bool,
}

impl Settings {
    pub(crate) fn from_env() -> Self {
        let on = |k: &str| std::env::var(k).is_ok_and(|v| v == "1" || v == "true");
        let wanted = Self {
            connected_sockets: on("TS_DEBUG_MAGICSOCK_CONNECTED_SOCKETS"),
            dont_fragment: on("TS_DEBUG_DONT_FRAGMENT"),
            batched_io: on("TS_DEBUG_MAGICSOCK_BATCHED_IO"),
        };
        if cfg!(target_vendor = "apple") {
            wanted
        } else {
            if wanted != Self::default() {
                // Delivery to the connected socket first isn't guaranteed on every kernel (Linux
                // before 5.4 delivers to the first bound socket), so this stays Apple-only.
                tracing::warn!("magicsock connected sockets / DF are Apple-only; ignoring");
            }
            Self::default()
        }
    }
}

enum Entry {
    /// Still on the shared socket; bytes sent so far.
    Counting(u64),
    Ready {
        sock: Arc<UdpSocket>,
        pump: tokio::task::AbortHandle,
        last_used: Instant,
    },
    /// Opening failed; stay on the shared socket.
    Failed,
}

/// The connected sockets of one [`MagicSock`](crate::MagicSock).
pub(crate) struct ConnectedSockets {
    settings: Settings,
    entries: HashMap<SocketAddr, Entry>,
    ready: usize,
    to_demux: mpsc::UnboundedSender<Received>,
}

impl ConnectedSockets {
    pub(crate) fn new(settings: Settings) -> (Self, mpsc::UnboundedReceiver<Received>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            Self {
                settings,
                entries: HashMap::new(),
                ready: 0,
                to_demux: tx,
            },
            rx,
        )
    }

    pub(crate) fn enabled(&self) -> bool {
        self.settings.connected_sockets
    }

    /// Whether sends on connected sockets may be batched (`sendmsg_x`).
    pub(crate) fn batched_io(&self) -> bool {
        self.settings.connected_sockets && self.settings.batched_io && crate::batch::usable()
    }

    /// The socket to send `len` bytes to `addr` on, or `None` for the `shared` socket. Counts
    /// the bytes, and opens a connected socket on `shared`'s local address once `addr` has crossed
    /// the threshold. Must be called from within a Tokio runtime.
    pub(crate) fn socket_for(
        &mut self,
        addr: SocketAddr,
        len: usize,
        shared: &UdpSocket,
    ) -> Option<Arc<UdpSocket>> {
        if !self.settings.connected_sockets {
            return None;
        }
        let entry = self.entries.entry(addr).or_insert(Entry::Counting(0));
        let sent = match entry {
            Entry::Ready {
                sock, last_used, ..
            } => {
                *last_used = Instant::now();
                return Some(sock.clone());
            }
            Entry::Failed => return None,
            Entry::Counting(sent) => {
                *sent += len as u64;
                *sent
            }
        };
        if sent < CONNECT_AFTER_BYTES || !self.make_room() {
            return None;
        }
        let opened = shared
            .local_addr()
            .and_then(|local| open(local, addr, self.settings.dont_fragment).map(|s| (s, local)));
        match opened {
            Ok((sock, local)) => {
                let sock = Arc::new(sock);
                let pump = spawn_pump(sock.clone(), addr, self.to_demux.clone());
                self.entries.insert(
                    addr,
                    Entry::Ready {
                        sock: sock.clone(),
                        pump,
                        last_used: Instant::now(),
                    },
                );
                self.ready += 1;
                tracing::debug!(%addr, %local, connected = self.ready, "magicsock: connected socket opened");
                Some(sock)
            }
            Err(e) => {
                tracing::debug!(%addr, error = %e, "magicsock: connected socket failed; staying on shared socket");
                self.entries.insert(addr, Entry::Failed);
                None
            }
        }
    }

    /// Whether another connected socket fits, evicting the longest-idle one past
    /// [`IDLE_EVICT`] if the table is full.
    fn make_room(&mut self) -> bool {
        if self.ready < MAX_CONNECTED {
            return true;
        }
        let victim = self
            .entries
            .iter()
            .filter_map(|(a, e)| match e {
                Entry::Ready { last_used, .. } if last_used.elapsed() >= IDLE_EVICT => {
                    Some((*a, *last_used))
                }
                _ => None,
            })
            .min_by_key(|(_, t)| *t);
        match victim {
            Some((a, _)) => {
                self.remove(a);
                true
            }
            None => false,
        }
    }

    /// Drop the connected socket for `addr` (if any) and start counting it again.
    pub(crate) fn remove(&mut self, addr: SocketAddr) {
        if let Some(Entry::Ready { pump, .. }) = self.entries.remove(&addr) {
            pump.abort();
            self.ready -= 1;
        }
    }

    /// Drop every connected socket (the shared socket was rebound; they're on the old port).
    pub(crate) fn clear(&mut self) {
        for (_, e) in self.entries.drain() {
            if let Entry::Ready { pump, .. } = e {
                pump.abort();
            }
        }
        self.ready = 0;
    }

    #[cfg(test)]
    pub(crate) fn ready_count(&self) -> usize {
        self.ready
    }
}

impl Drop for ConnectedSockets {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Bind a reuse-port socket to the shared socket's `local` address and connect it to `remote`.
fn open(local: SocketAddr, remote: SocketAddr, dont_fragment: bool) -> std::io::Result<UdpSocket> {
    let s = reuse_port_socket(local)?;
    s.connect(&remote.into())?;
    if dont_fragment && remote.is_ipv4() {
        set_dont_fragment(&s)?;
    }
    let sock = UdpSocket::from_std(s.into())?;
    crate::sock::tune_socket_buffers(&sock);
    Ok(sock)
}

/// A nonblocking UDP socket with `SO_REUSEADDR` + `SO_REUSEPORT`, bound to `addr`. The shared
/// socket must be created this way too, or the connected sockets can't share its port.
pub(crate) fn reuse_port_socket(addr: SocketAddr) -> std::io::Result<socket2::Socket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    if addr.is_ipv6() {
        // Match `UdpSocket::bind`'s dual-stack default on `[::]`.
        s.set_only_v6(false)?;
    }
    s.set_reuse_address(true)?;
    s.set_reuse_port(true)?;
    s.set_nonblocking(true)?;
    s.bind(&addr.into())?;
    Ok(s)
}

#[cfg(target_vendor = "apple")]
fn set_dont_fragment(s: &socket2::Socket) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    // netinet/in.h on Darwin; not exported by the libc crate.
    const IP_DONTFRAG: libc::c_int = 28;
    let one: libc::c_int = 1;
    // SAFETY: `s` is an open socket for the duration of the call; the option value points at a
    // live `c_int` and its exact size is passed.
    let r = unsafe {
        libc::setsockopt(
            s.as_raw_fd(),
            libc::IPPROTO_IP,
            IP_DONTFRAG,
            (&raw const one).cast(),
            core::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(target_vendor = "apple"))]
fn set_dont_fragment(_: &socket2::Socket) -> std::io::Result<()> {
    Ok(())
}

/// Receive on a connected socket and forward each datagram to the shared demux. Errors such as
/// `ECONNREFUSED` (an ICMP port-unreachable reported on a connected socket) are per-datagram,
/// not fatal, so the pump keeps going; it ends when the demux side goes away or it is aborted.
fn spawn_pump(
    sock: Arc<UdpSocket>,
    remote: SocketAddr,
    to_demux: mpsc::UnboundedSender<Received>,
) -> tokio::task::AbortHandle {
    tokio::spawn(async move {
        let mut buf = vec![0u8; PUMP_BUF];
        loop {
            match sock.recv(&mut buf).await {
                Ok(n) => {
                    if to_demux.send((buf[..n].to_vec(), remote)).is_err() {
                        return;
                    }
                }
                Err(e) => {
                    tracing::trace!(%remote, error = %e, "magicsock: connected socket recv error");
                    // Don't spin if the error repeats.
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    })
    .abort_handle()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn on() -> Settings {
        Settings {
            connected_sockets: true,
            dont_fragment: true,
            batched_io: true,
        }
    }

    /// After the byte threshold, sends to `remote` go out of a socket connected to it that shares
    /// the shared socket's port, and replies from `remote` arrive through the demux channel, not
    /// the shared socket.
    #[cfg(target_vendor = "apple")]
    #[tokio::test]
    async fn connects_after_threshold_and_delivers_replies_to_demux() {
        let shared: UdpSocket = UdpSocket::from_std(
            reuse_port_socket("127.0.0.1:0".parse().unwrap())
                .unwrap()
                .into(),
        )
        .unwrap();
        let local = shared.local_addr().unwrap();
        let remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote_addr = remote.local_addr().unwrap();
        let (mut c, mut demux) = ConnectedSockets::new(on());

        let chunk = 1200;
        let mut sends = 0;
        let sock = loop {
            sends += 1;
            if let Some(s) = c.socket_for(remote_addr, chunk, &shared) {
                break s;
            }
            assert!(sends as u64 * (chunk as u64) <= CONNECT_AFTER_BYTES + chunk as u64);
        };
        assert_eq!(c.ready_count(), 1);

        sock.send(b"via connected").await.unwrap();
        let mut b = [0u8; 64];
        let (n, from) = remote.recv_from(&mut b).await.unwrap();
        assert_eq!(&b[..n], b"via connected");
        assert_eq!(
            from, local,
            "connected socket must send from the shared port"
        );

        remote.send_to(b"reply", local).await.unwrap();
        let (data, from) = tokio::time::timeout(Duration::from_secs(5), demux.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!((data.as_slice(), from), (&b"reply"[..], remote_addr));

        // Subsequent sends reuse it; clearing drops it.
        assert!(c.socket_for(remote_addr, 10, &shared).is_some());
        c.clear();
        assert_eq!(c.ready_count(), 0);
    }

    #[tokio::test]
    async fn disabled_never_connects() {
        let (mut c, _rx) = ConnectedSockets::new(Settings::default());
        let shared = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote = "127.0.0.1:2".parse().unwrap();
        for _ in 0..2000 {
            assert!(c.socket_for(remote, 1500, &shared).is_none());
        }
    }

    /// Opening fails (the shared port isn't a reuse-port socket bound here), so the address
    /// stays on the shared socket for good instead of retrying every send.
    #[tokio::test]
    async fn failed_open_stays_on_shared_socket() {
        let plain = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote = "127.0.0.1:9".parse().unwrap();
        let (mut c, _rx) = ConnectedSockets::new(on());
        for _ in 0..1000 {
            assert!(c.socket_for(remote, 1500, &plain).is_none());
        }
        assert_eq!(c.ready_count(), 0);
        assert!(matches!(c.entries.get(&remote), Some(Entry::Failed)));
    }
}
