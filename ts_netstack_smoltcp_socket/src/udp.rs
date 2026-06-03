use core::{
    fmt::{Debug, Formatter},
    net::SocketAddr,
    num::NonZeroUsize,
};

use bytes::Bytes;
use netcore::{HasChannel, Response, smoltcp::iface::SocketHandle};

use crate::netcore::{DisplayExt, udp};

/// A UDP socket.
pub struct UdpSocket {
    pub(crate) sender: netcore::Channel,
    pub(crate) handle: SocketHandle,

    pub(crate) local: SocketAddr,
}

impl Debug for UdpSocket {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UdpSocket")
            .field("handle", &self.handle.as_display_debug())
            .field("local_endpoint", &self.local)
            .finish()
    }
}

impl UdpSocket {
    /// Send a packet to the given endpoint with the provided data.
    pub fn send_to_blocking(
        &self,
        endpoint: SocketAddr,
        data: &[u8],
    ) -> Result<(), netcore::Error> {
        self.request_blocking(udp::Command::Send {
            endpoint,
            local: None,
            buf: Bytes::copy_from_slice(data),
        })?
        .to_ok()
    }

    /// Send a packet to the given endpoint with the provided data.
    pub async fn send_to(&self, endpoint: SocketAddr, data: &[u8]) -> Result<(), netcore::Error> {
        self.request(udp::Command::Send {
            endpoint,
            local: None,
            buf: Bytes::copy_from_slice(data),
        })
        .await?
        .to_ok()
    }

    /// Send a packet to `endpoint`, spoofing the source address as `local`.
    ///
    /// Used by a forwarder so reply datagrams appear to originate from the original
    /// destination the peer expected.
    pub fn send_to_from_blocking(
        &self,
        endpoint: SocketAddr,
        local: core::net::IpAddr,
        data: &[u8],
    ) -> Result<(), netcore::Error> {
        self.request_blocking(udp::Command::Send {
            endpoint,
            local: Some(local),
            buf: Bytes::copy_from_slice(data),
        })?
        .to_ok()
    }

    /// Send a packet to `endpoint`, spoofing the source address as `local`.
    ///
    /// Used by a forwarder so reply datagrams appear to originate from the original
    /// destination the peer expected.
    pub async fn send_to_from(
        &self,
        endpoint: SocketAddr,
        local: core::net::IpAddr,
        data: &[u8],
    ) -> Result<(), netcore::Error> {
        self.request(udp::Command::Send {
            endpoint,
            local: Some(local),
            buf: Bytes::copy_from_slice(data),
        })
        .await?
        .to_ok()
    }

    /// Receive a packet into the given buffer.
    pub fn recv_from_blocking(
        &self,
        buf: &mut [u8],
    ) -> Result<(SocketAddr, usize), netcore::Error> {
        let len = NonZeroUsize::new(buf.len()).ok_or(netcore::Error::zero_buffer())?;

        let resp = self.request_blocking(udp::Command::Recv { max_len: Some(len) })?;

        self._udp_recv(resp, buf)
    }

    /// Receive a packet bytes buffer.
    pub fn recv_from_bytes_blocking(&self) -> Result<(SocketAddr, Bytes), netcore::Error> {
        let resp = self.request_blocking(udp::Command::Recv { max_len: None })?;
        self._udp_recv_bytes(resp)
    }

    /// Receive a packet into the given buffer.
    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(SocketAddr, usize), netcore::Error> {
        let len = NonZeroUsize::new(buf.len()).ok_or(netcore::Error::zero_buffer())?;

        let resp = self
            .request(udp::Command::Recv { max_len: Some(len) })
            .await?;

        self._udp_recv(resp, buf)
    }

    /// Asynchronously receive a packet bytes buffer.
    pub async fn recv_from_bytes(&self) -> Result<(SocketAddr, Bytes), netcore::Error> {
        let resp = self.request(udp::Command::Recv { max_len: None }).await?;

        self._udp_recv_bytes(resp)
    }

    /// Receive a packet, also reporting the local (destination) address it was sent to.
    ///
    /// Under any-IP acceptance the local address is the original packet destination -- a
    /// forwarder needs it to know which real socket to relay through. Returns
    /// `(remote, local, payload)`.
    pub fn recv_from_with_dst_bytes_blocking(
        &self,
    ) -> Result<(SocketAddr, SocketAddr, Bytes), netcore::Error> {
        let resp = self.request_blocking(udp::Command::Recv { max_len: None })?;
        self._udp_recv_with_dst_bytes(resp)
    }

    /// Receive a packet, also reporting the local (destination) address it was sent to.
    ///
    /// Under any-IP acceptance the local address is the original packet destination -- a
    /// forwarder needs it to know which real socket to relay through. Returns
    /// `(remote, local, payload)`.
    pub async fn recv_from_with_dst_bytes(
        &self,
    ) -> Result<(SocketAddr, SocketAddr, Bytes), netcore::Error> {
        let resp = self.request(udp::Command::Recv { max_len: None }).await?;
        self._udp_recv_with_dst_bytes(resp)
    }

    fn _udp_recv(
        &self,
        resp: Response,
        buf: &mut [u8],
    ) -> Result<(SocketAddr, usize), netcore::Error> {
        let (remote, ret) = self._udp_recv_bytes(resp)?;

        debug_assert!(ret.len() <= buf.len());
        let n_copied = ret.len().min(buf.len());

        buf[..n_copied].copy_from_slice(&ret[..n_copied]);

        Ok((remote, n_copied))
    }

    fn _udp_recv_bytes(&self, resp: Response) -> Result<(SocketAddr, Bytes), netcore::Error> {
        let (remote, _local, ret) = self._udp_recv_with_dst_bytes(resp)?;
        Ok((remote, ret))
    }

    fn _udp_recv_with_dst_bytes(
        &self,
        resp: Response,
    ) -> Result<(SocketAddr, SocketAddr, Bytes), netcore::Error> {
        netcore::try_response_as!(
            resp,
            udp::Response::RecvFrom {
                remote,
                local,
                buf: ret,
                truncated,
            }
        );

        if let Some(truncated) = truncated {
            tracing::warn!(truncated, "udp recv truncated");
        }

        Ok((remote, local, ret))
    }

    /// Report the local endpoint to which this socket is bound.
    pub const fn local_addr(&self) -> SocketAddr {
        self.local
    }

    socket_requestor_impl!();
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        if let Err(e) = self
            .sender
            .request_nonblocking(Some(self.handle), udp::Command::Close)
        {
            tracing::warn!(err = %e, "possible socket leak");
        }
    }
}
