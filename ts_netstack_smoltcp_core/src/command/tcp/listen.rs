//! TCP listener commands.

use core::net::SocketAddr;

use smoltcp::iface::SocketHandle;

use crate::{command, socket_impl::tcp::ListenerHandle};

/// Commands to control TCP listeners.
#[derive(Debug)]
pub enum Command {
    /// Begin listening on the given endpoint.
    Listen {
        /// The endpoint to begin listening on.
        local_endpoint: SocketAddr,
    },

    /// Accept an incoming connection on the given listener.
    ///
    /// Response channel blocks until a connection is made.
    Accept {
        /// The handle of the listener to accept on.
        handle: ListenerHandle,
    },

    /// Close the given listener.
    ///
    /// Happy-path response: [`Response::Ok`][command::Response::Ok].
    Close {
        /// The handle of hte listener to close.
        handle: ListenerHandle,
    },

    /// Query the set of local ports that currently have an explicit listener.
    ///
    /// Read-only: answered purely from the listener registry without touching the packet
    /// ingress / accept path. Used by the fallback-TCP-handler manager to learn which ports are
    /// already owned by an explicit `Listen`er, so it never binds a competing any-IP listener on
    /// a port the embedder is already serving.
    ///
    /// Response: [`Response::BoundPorts`].
    BoundPorts,
}

impl From<Command> for command::Command {
    fn from(value: Command) -> Self {
        command::Command::TcpListen(value)
    }
}

/// Responses to TCP listener [`Command`]s.
#[derive(Debug)]
pub enum Response {
    /// Successfully listening on the requested endpoint.
    Listening {
        /// Handle of the new listener.
        handle: ListenerHandle,
    },
    /// Successfully accepted an incoming TCP connection.
    Accepted {
        /// Address of the remote that initiated the connection.
        remote: SocketAddr,
        /// The local (destination) address the remote connected to.
        ///
        /// Under any-IP acceptance this is the original packet destination, which may be an
        /// address the netstack does not own. A forwarder uses this to know where to dial.
        local: SocketAddr,
        /// Handle of the new TCP connection.
        handle: SocketHandle,
    },
    /// The set of local ports that currently have an explicit listener.
    ///
    /// Answers [`Command::BoundPorts`]. Read-only snapshot of the listener registry.
    BoundPorts {
        /// Local ports with an active explicit listener (may contain duplicates if multiple
        /// listeners share a port; callers that need a set should dedup).
        ports: alloc::vec::Vec<u16>,
    },
}

impl From<Response> for command::Response {
    fn from(value: Response) -> Self {
        Self::TcpListen(value)
    }
}
