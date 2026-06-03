//! Commands for UDP sockets.

use core::{
    fmt::{Debug, Formatter},
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
};

use bytes::Bytes;
use smoltcp::iface::SocketHandle;

use crate::command;

/// Commands driving UDP sockets.
pub enum Command {
    /// Bind a new socket to the given endpoint.
    Bind {
        /// The endpoint to bind to.
        ///
        /// The port on this endpoint may not be unspecified.
        endpoint: SocketAddr,
    },

    /// Send a message to the given endpoint.
    Send {
        /// The endpoint to send the message to.
        endpoint: SocketAddr,
        /// The source address to send from.
        ///
        /// If `None`, smoltcp selects a source address (RFC 6724 / heuristic). A forwarder
        /// sets this to spoof the source as the original destination the peer expected, so
        /// reply datagrams appear to come from the right address.
        local: Option<IpAddr>,
        /// The message payload.
        buf: Bytes,
    },

    /// Receive a packet incoming on the socket.
    Recv {
        /// If `Some`, limit the length of the received packet to at most the contained
        /// value.
        ///
        /// If the actual received length of the packet was longer, this may lead to
        /// payload truncation, indicated by the presence of the
        /// [`Response::RecvFrom::truncated`] field.
        ///
        /// For use in emulating an API like `recv_from(&mut [u8])`, where the caller
        /// supplies the buffer.
        max_len: Option<NonZeroUsize>,
    },

    /// Close the socket.
    Close,
}

impl Debug for Command {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Bind { endpoint } => f.debug_struct("Bind").field("endpoint", endpoint).finish(),
            Self::Send {
                endpoint,
                local,
                buf,
            } => f
                .debug_struct("Send")
                .field("endpoint", endpoint)
                .field("local", local)
                .field("buf_len", &buf.len())
                .finish(),
            Self::Recv { max_len } => f.debug_struct("Recv").field("max_len", max_len).finish(),
            Self::Close => f.debug_struct("Close").finish(),
        }
    }
}

impl From<Command> for command::Command {
    fn from(value: Command) -> Self {
        command::Command::Udp(value)
    }
}

/// UDP response messages.
pub enum Response {
    /// Socket was bound successfully.
    Bound {
        /// The bound socket's handle.
        handle: SocketHandle,
        /// The local endpoint to which the socket was bound.
        local: SocketAddr,
    },
    /// A packet was received.
    RecvFrom {
        /// The remote address that sent the packet.
        remote: SocketAddr,

        /// The local (destination) address the packet was sent to.
        ///
        /// Under any-IP acceptance this is the original packet destination, which may be an
        /// address the netstack does not own. A forwarder uses this to know which real socket
        /// to relay through and which source to spoof on replies.
        local: SocketAddr,

        /// The packet payload.
        buf: Bytes,

        /// If present, indicates that the packet held more data than is in the `buf` field,
        /// which was truncated because [`Command::Recv::max_len`] was set.
        ///
        /// The contained value is the original length of the packet before truncation.
        truncated: Option<usize>,
    },
}

impl From<Response> for command::Response {
    fn from(value: Response) -> Self {
        Self::Udp(value)
    }
}

impl Debug for Response {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Bound { handle, local } => f
                .debug_struct("Bound")
                .field("handle", handle)
                .field("local", local)
                .finish(),
            Self::RecvFrom {
                remote,
                local,
                buf,
                truncated,
            } => f
                .debug_struct("RecvFrom")
                .field("remote", remote)
                .field("local", local)
                .field("buf_len", &buf.len())
                .field("truncated", truncated)
                .finish(),
        }
    }
}
