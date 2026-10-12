//! Bounded, nonblocking UDP receive batches. Buffers belong to the pump across awaits;
//! no syscall can consume data and then return Pending before handing it to the caller.
use std::{io, net::SocketAddr};

use tokio::{io::Interest, net::UdpSocket};

pub(crate) const MAX_BATCH: usize = 16;
const BUFFER_LEN: usize = 1600;
pub(crate) type Datagram = (Vec<u8>, SocketAddr);

use std::sync::{
    OnceLock,
    atomic::{AtomicU64, Ordering},
};
static METRICS: OnceLock<bool> = OnceLock::new();
static BATCHES: [AtomicU64; 17] = [const { AtomicU64::new(0) }; 17];
static FALLBACKS: AtomicU64 = AtomicU64::new(0);
static TRUNCATED: AtomicU64 = AtomicU64::new(0);
fn metrics_enabled() -> bool {
    *METRICS.get_or_init(|| std::env::var("TS_DEBUG_PIPELINE_METRICS").as_deref() == Ok("1"))
}
/// Cumulative receive counters, enabled by TS_DEBUG_PIPELINE_METRICS.
#[derive(Debug, Clone)]
pub struct Snapshot {
    /// Successful kernel batches by exact datagram count, 0..16; excludes ordinary fallback.
    pub kernel_batches: [u64; 17],
    /// Receiver instances that disabled the kernel batch syscall after an unsupported error.
    pub fallbacks: u64,
    /// Truncated datagrams reported by the kernel batch syscall.
    pub truncated: u64,
}
/// Read counters without socket or actor locks.
pub fn snapshot() -> Snapshot {
    Snapshot {
        kernel_batches: core::array::from_fn(|i| BATCHES[i].load(Ordering::Relaxed)),
        fallbacks: FALLBACKS.load(Ordering::Relaxed),
        truncated: TRUNCATED.load(Ordering::Relaxed),
    }
}

pub(crate) fn enabled() -> bool {
    std::env::var("TS_EXPERIMENT_RX_BATCH").as_deref() == Ok("1")
}

pub(crate) struct Receiver {
    buffers: [Vec<u8>; MAX_BATCH],
    kernel: bool,
}
impl Receiver {
    pub(crate) fn new() -> Self {
        Self {
            buffers: core::array::from_fn(|_| vec![0; BUFFER_LEN]),
            kernel: true,
        }
    }

    pub(crate) async fn recv(
        &mut self,
        socket: &UdpSocket,
        remote: Option<SocketAddr>,
    ) -> io::Result<Vec<Datagram>> {
        #[cfg(any(target_vendor = "apple", target_os = "linux"))]
        {
            socket
                .async_io(Interest::READABLE, || self.try_recv(socket, remote))
                .await
        }
        #[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
        {
            let (n, from) = socket.recv_from(&mut self.buffers[0]).await?;
            Ok(vec![(
                self.buffers[0][..n].to_vec(),
                remote.unwrap_or(from),
            )])
        }
    }

    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    fn try_recv(
        &mut self,
        socket: &UdpSocket,
        remote: Option<SocketAddr>,
    ) -> io::Result<Vec<Datagram>> {
        self.try_recv_with(socket, remote, sys::batch)
    }

    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    fn try_recv_with(
        &mut self,
        socket: &UdpSocket,
        remote: Option<SocketAddr>,
        kernel: impl FnOnce(
            &UdpSocket,
            &mut [Vec<u8>; MAX_BATCH],
            Option<SocketAddr>,
        ) -> io::Result<Vec<Datagram>>,
    ) -> io::Result<Vec<Datagram>> {
        if self.kernel {
            match kernel(socket, &mut self.buffers, remote) {
                Err(e)
                    if matches!(
                        e.raw_os_error(),
                        Some(libc::ENOSYS | libc::EINVAL | libc::EOPNOTSUPP)
                    ) =>
                {
                    self.kernel = false;
                    if metrics_enabled() {
                        FALLBACKS.fetch_add(1, Ordering::Relaxed);
                    }
                    tracing::debug!(error = %e, "magicsock: receive batching unavailable; using recvfrom");
                }
                result => return result,
            }
        }
        sys::single(socket, &mut self.buffers[0], remote)
    }
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
mod sys {
    use std::os::fd::AsRawFd;

    use super::*;

    fn address(storage: libc::sockaddr_storage, len: libc::socklen_t) -> io::Result<SocketAddr> {
        if len as usize > core::mem::size_of::<libc::sockaddr_storage>() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "oversized UDP source address",
            ));
        }
        // SAFETY: storage is initialized and its kernel-reported length was bounded above.
        let mut wrapped = socket2::SockAddrStorage::zeroed();
        // SAFETY: libc sockaddr_storage is this platform's sockaddr type, as required by view_as.
        unsafe {
            *wrapped.view_as::<libc::sockaddr_storage>() = storage;
        }
        // SAFETY: wrapped contains initialized kernel output with a checked length.
        let address = unsafe { socket2::SockAddr::new(wrapped, len) };
        address
            .as_socket()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "non-IP UDP source address"))
    }

    pub(super) fn single(
        socket: &UdpSocket,
        buffer: &mut [u8],
        remote: Option<SocketAddr>,
    ) -> io::Result<Vec<Datagram>> {
        // SAFETY: all-zero storage is valid uninitialized-output storage for recvfrom.
        let mut from: libc::sockaddr_storage = unsafe { core::mem::zeroed() };
        let mut len = core::mem::size_of_val(&from) as libc::socklen_t;
        // SAFETY: both output buffers and the length pointer are writable for their declared sizes.
        let n = unsafe {
            libc::recvfrom(
                socket.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_DONTWAIT,
                (&raw mut from).cast(),
                &mut len,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(vec![(
            buffer[..(n as usize).min(buffer.len())].to_vec(),
            match remote {
                Some(r) => r,
                None => address(from, len)?,
            },
        )])
    }

    #[cfg(target_vendor = "apple")]
    #[repr(C)]
    struct Header {
        name: *mut libc::c_void,
        namelen: libc::socklen_t,
        iov: *mut libc::iovec,
        iovlen: libc::c_int,
        control: *mut libc::c_void,
        controllen: libc::socklen_t,
        flags: libc::c_int,
        datalen: libc::size_t,
    }
    #[cfg(target_vendor = "apple")]
    unsafe extern "C" {
        fn recvmsg_x(
            fd: libc::c_int,
            messages: *mut Header,
            count: libc::c_uint,
            flags: libc::c_int,
        ) -> isize;
    }

    pub(super) fn batch(
        socket: &UdpSocket,
        buffers: &mut [Vec<u8>; MAX_BATCH],
        remote: Option<SocketAddr>,
    ) -> io::Result<Vec<Datagram>> {
        // SAFETY: all-zero sockaddr_storage is valid output storage; the syscall fills each source.
        let mut addresses: [libc::sockaddr_storage; MAX_BATCH] = unsafe { core::mem::zeroed() };
        let mut iovs: [libc::iovec; MAX_BATCH] = core::array::from_fn(|i| libc::iovec {
            iov_base: buffers[i].as_mut_ptr().cast(),
            iov_len: buffers[i].len(),
        });
        #[cfg(target_vendor = "apple")]
        let mut headers: [Header; MAX_BATCH] = core::array::from_fn(|i| Header {
            name: (&raw mut addresses[i]).cast(),
            namelen: core::mem::size_of::<libc::sockaddr_storage>() as _,
            iov: &raw mut iovs[i],
            iovlen: 1,
            control: core::ptr::null_mut(),
            controllen: 0,
            flags: 0,
            datalen: 0,
        });
        #[cfg(target_os = "linux")]
        let mut headers: [libc::mmsghdr; MAX_BATCH] = core::array::from_fn(|i| {
            // SAFETY: zeroed msghdr has null pointers and zero lengths; the data/name fields are set below.
            let mut h: libc::mmsghdr = unsafe { core::mem::zeroed() };
            h.msg_hdr.msg_name = (&raw mut addresses[i]).cast();
            h.msg_hdr.msg_namelen = core::mem::size_of::<libc::sockaddr_storage>() as _;
            h.msg_hdr.msg_iov = &raw mut iovs[i];
            h.msg_hdr.msg_iovlen = 1;
            h
        });
        // SAFETY: headers, iovecs, addresses and separate writable packet buffers all outlive
        // this synchronous nonblocking call. There are exactly MAX_BATCH initialized entries.
        #[cfg(target_vendor = "apple")]
        let n = unsafe {
            recvmsg_x(
                socket.as_raw_fd(),
                headers.as_mut_ptr(),
                MAX_BATCH as _,
                libc::MSG_DONTWAIT,
            )
        };
        #[cfg(target_os = "linux")]
        let n = unsafe {
            libc::recvmmsg(
                socket.as_raw_fd(),
                headers.as_mut_ptr(),
                MAX_BATCH as _,
                libc::MSG_DONTWAIT as _,
                core::ptr::null_mut(),
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let metrics = metrics_enabled();
        if metrics {
            BATCHES[(n as usize).min(MAX_BATCH)].fetch_add(1, Ordering::Relaxed);
        }
        let mut result = Vec::with_capacity(n as usize);
        for i in 0..(n as usize).min(MAX_BATCH) {
            #[cfg(target_vendor = "apple")]
            let (len, namelen) = (headers[i].datalen, headers[i].namelen);
            #[cfg(target_os = "linux")]
            let (len, namelen) = (headers[i].msg_len as usize, headers[i].msg_hdr.msg_namelen);
            #[cfg(target_vendor = "apple")]
            let flags = headers[i].flags;
            #[cfg(target_os = "linux")]
            let flags = headers[i].msg_hdr.msg_flags;
            if metrics && flags & libc::MSG_TRUNC != 0 {
                TRUNCATED.fetch_add(1, Ordering::Relaxed);
            }
            // Match ordinary recv_from: a truncated datagram yields only its prefix, never
            // a slice beyond the buffer or bytes from the following datagram.
            let len = len.min(buffers[i].len());
            let from = match remote {
                Some(r) => r,
                None => address(addresses[i], namelen)?,
            };
            result.push((buffers[i][..len].to_vec(), from));
        }
        Ok(result)
    }
}

#[cfg(all(test, any(target_vendor = "apple", target_os = "linux")))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mixed_sources_boundaries_and_truncation() {
        let rx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dst = rx.local_addr().unwrap();
        for i in 0..33u8 {
            let tx = if i % 2 == 0 { &a } else { &b };
            tx.send_to(&vec![i; if i == 17 { 2000 } else { i as usize }], dst)
                .await
                .unwrap();
        }
        let mut receiver = Receiver::new();
        let mut got = Vec::new();
        while got.len() < 33 {
            let batch =
                tokio::time::timeout(std::time::Duration::from_secs(2), receiver.recv(&rx, None))
                    .await
                    .unwrap()
                    .unwrap();
            assert!(!batch.is_empty() && batch.len() <= MAX_BATCH);
            got.extend(batch);
        }
        assert!(receiver.kernel, "the test must exercise the native syscall");
        for (i, (data, from)) in got.iter().enumerate() {
            assert_eq!(
                *from,
                if i % 2 == 0 {
                    a.local_addr().unwrap()
                } else {
                    b.local_addr().unwrap()
                }
            );
            assert_eq!(data.len(), if i == 17 { BUFFER_LEN } else { i });
            assert!(data.iter().all(|v| *v == i as u8));
        }
    }

    #[tokio::test]
    async fn unavailable_syscall_falls_back_without_losing_datagrams() {
        for errno in [libc::ENOSYS, libc::EINVAL, libc::EOPNOTSUPP] {
            let rx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let tx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            tx.send_to(b"first", rx.local_addr().unwrap())
                .await
                .unwrap();
            tx.send_to(b"second", rx.local_addr().unwrap())
                .await
                .unwrap();
            let mut receiver = Receiver::new();
            let got = rx
                .async_io(Interest::READABLE, || {
                    receiver.try_recv_with(&rx, None, |_, _, _| {
                        Err(io::Error::from_raw_os_error(errno))
                    })
                })
                .await
                .unwrap();
            assert_eq!(got, vec![(b"first".to_vec(), tx.local_addr().unwrap())]);
            assert!(!receiver.kernel);
            let got = rx
                .async_io(Interest::READABLE, || {
                    receiver.try_recv_with(&rx, None, |_, _, _| panic!("disabled kernel retried"))
                })
                .await
                .unwrap();
            assert_eq!(got, vec![(b"second".to_vec(), tx.local_addr().unwrap())]);
        }
    }

    #[tokio::test]
    async fn cancelled_empty_receive_and_connected_attribution() {
        let rx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        rx.connect(tx.local_addr().unwrap()).await.unwrap();
        let mut receiver = Receiver::new();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(10),
                receiver.recv(&rx, Some(tx.local_addr().unwrap()))
            )
            .await
            .is_err()
        );
        for i in 0..4u8 {
            tx.send_to(&[i], rx.local_addr().unwrap()).await.unwrap();
        }
        let mut got = Vec::new();
        while got.len() < 4 {
            got.extend(
                tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    receiver.recv(&rx, Some(tx.local_addr().unwrap())),
                )
                .await
                .unwrap()
                .unwrap(),
            );
        }
        assert_eq!(
            got,
            (0..4u8)
                .map(|i| (vec![i], tx.local_addr().unwrap()))
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn would_block_does_not_disable_batching() {
        let rx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut receiver = Receiver::new();
        let error = receiver
            .try_recv_with(&rx, None, |_, _, _| Err(io::ErrorKind::WouldBlock.into()))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert!(receiver.kernel);
    }
}
