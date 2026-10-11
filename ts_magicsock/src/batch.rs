//! Batched sends on a connected UDP socket with Darwin's `sendmsg_x` (opt-in, Apple only).
//!
//! One `sendmsg_x` call hands the kernel up to [`MAX_BATCH`] datagrams, instead of one `send` per
//! datagram. It is a private but long-stable libSystem call (present since macOS 10.11; Go's
//! reference implementation for darwin uses it too). It is only used on *connected* sockets, so
//! every message has the same destination and needs no address. A runtime failure that suggests
//! the call is unusable (`ENOSYS`, `EOPNOTSUPP`, `EINVAL`) disables it for the process and the
//! caller falls back to per-datagram sends.

use std::sync::atomic::{AtomicBool, Ordering};

use tokio::{io::Interest, net::UdpSocket};

/// Most datagrams per `sendmsg_x` call.
pub(crate) const MAX_BATCH: usize = 64;

/// Cleared if `sendmsg_x` turns out to be unusable at runtime.
static USABLE: AtomicBool = AtomicBool::new(true);

/// Whether batched sends may be attempted.
pub(crate) fn usable() -> bool {
    cfg!(target_vendor = "apple") && USABLE.load(Ordering::Relaxed)
}

/// Send every datagram in `pkts` on the connected socket `sock`, in batches of up to
/// [`MAX_BATCH`]. Returns how many were sent before an error that the caller should handle by
/// sending the rest one at a time; `Ok(pkts.len())` when all went out.
pub(crate) async fn send<P: AsRef<[u8]>>(sock: &UdpSocket, pkts: &[P]) -> usize {
    let mut sent = 0;
    while sent < pkts.len() {
        let chunk = &pkts[sent..pkts.len().min(sent + MAX_BATCH)];
        match sock
            .async_io(Interest::WRITABLE, || sys::send_batch(sock, chunk))
            .await
        {
            // The kernel may take fewer than offered; continue with the rest.
            Ok(n) if n > 0 => sent += n,
            Ok(_) => return sent,
            Err(e) => {
                if matches!(
                    e.raw_os_error(),
                    Some(sys::ENOSYS | sys::EOPNOTSUPP | sys::EINVAL)
                ) {
                    tracing::warn!(error = %e, "magicsock: sendmsg_x unusable; batching disabled");
                    USABLE.store(false, Ordering::Relaxed);
                } else {
                    tracing::trace!(error = %e, "magicsock: batched send failed");
                }
                return sent;
            }
        }
    }
    sent
}

#[cfg(target_vendor = "apple")]
mod sys {
    use std::os::fd::AsRawFd;

    pub(super) use libc::{EINVAL, ENOSYS, EOPNOTSUPP};
    use tokio::net::UdpSocket;

    use super::MAX_BATCH;

    /// `struct msghdr_x` from xnu `bsd/sys/socket_private.h`.
    #[repr(C)]
    struct MsghdrX {
        msg_name: *mut libc::c_void,
        msg_namelen: libc::socklen_t,
        msg_iov: *mut libc::iovec,
        msg_iovlen: libc::c_int,
        msg_control: *mut libc::c_void,
        msg_controllen: libc::socklen_t,
        msg_flags: libc::c_int,
        msg_datalen: libc::size_t,
    }

    unsafe extern "C" {
        fn sendmsg_x(
            s: libc::c_int,
            msgp: *const MsghdrX,
            cnt: libc::c_uint,
            flags: libc::c_int,
        ) -> isize;
    }

    /// One non-blocking `sendmsg_x` of up to [`MAX_BATCH`] datagrams; `WouldBlock` when the
    /// socket buffer is full.
    pub(super) fn send_batch<P: AsRef<[u8]>>(
        sock: &UdpSocket,
        pkts: &[P],
    ) -> std::io::Result<usize> {
        let n = pkts.len().min(MAX_BATCH);
        let mut iovs: [libc::iovec; MAX_BATCH] = [libc::iovec {
            iov_base: core::ptr::null_mut(),
            iov_len: 0,
        }; MAX_BATCH];
        for (iov, p) in iovs.iter_mut().zip(&pkts[..n]) {
            let p = p.as_ref();
            iov.iov_base = p.as_ptr().cast_mut().cast();
            iov.iov_len = p.len();
        }
        let hdrs: [MsghdrX; MAX_BATCH] = core::array::from_fn(|i| MsghdrX {
            msg_name: core::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: (&raw const iovs[i]).cast_mut(),
            msg_iovlen: 1,
            msg_control: core::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
            msg_datalen: 0,
        });
        // SAFETY: `hdrs[..n]` point at `iovs[..n]`, which point at the `n` borrowed packet buffers;
        // all outlive the call, which only reads them. The socket is connected, so no address is
        // passed. `n <= MAX_BATCH` fits a c_uint.
        let r = unsafe {
            sendmsg_x(
                sock.as_raw_fd(),
                hdrs.as_ptr(),
                n as libc::c_uint,
                libc::MSG_DONTWAIT,
            )
        };
        if r < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(r as usize)
        }
    }
}

#[cfg(not(target_vendor = "apple"))]
mod sys {
    pub(super) const ENOSYS: i32 = 38;
    pub(super) const EOPNOTSUPP: i32 = 95;
    pub(super) const EINVAL: i32 = 22;

    pub(super) fn send_batch<P: AsRef<[u8]>>(
        _: &tokio::net::UdpSocket,
        _: &[P],
    ) -> std::io::Result<usize> {
        Err(std::io::Error::from_raw_os_error(ENOSYS))
    }
}

#[cfg(all(test, target_vendor = "apple"))]
mod tests {
    use super::*;

    /// A batch larger than one call goes out in order, every datagram intact.
    #[tokio::test]
    async fn sends_batches_in_order() {
        let rx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        tx.connect(rx.local_addr().unwrap()).await.unwrap();
        crate::sock::tune_socket_buffers(&rx);
        crate::sock::tune_socket_buffers(&tx);
        let pkts: Vec<Vec<u8>> = (0..150u32).map(|i| i.to_le_bytes().repeat(300)).collect();
        assert_eq!(send(&tx, &pkts).await, pkts.len());
        let mut buf = [0u8; 2048];
        for want in &pkts {
            let n = rx.recv(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], &want[..]);
        }
    }
}
