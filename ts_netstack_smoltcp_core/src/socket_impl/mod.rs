//! Socket command handler implementations for [`Netstack`][crate::Netstack].

/// Unwrap an optional handle or log an error and return
/// [`Error::BadRequest`][crate::command::Error::BadRequest].
macro_rules! unwrap_handle {
    ($handle:expr) => {{
        let handle = $handle;

        match handle {
            Some(handle) => handle,
            None => {
                tracing::error!(?handle, "no socket handle");

                return $crate::command::Error::missing_socket().into();
            }
        }
    }};
}

/// Get a mutable socket of type `$ty` for the optional `$handle`, or early-return a clean
/// [`Error::missing_socket`][crate::command::Error::missing_socket] [`Response`][crate::Response]
/// if the handle no longer refers to a live socket.
///
/// smoltcp 0.13's [`SocketSet::get_mut`][smoltcp::iface::SocketSet::get_mut] **panics** on a stale
/// or wrong-type handle, and it exposes no fallible getter — the only safe existence check is to
/// scan [`SocketSet::iter`][smoltcp::iface::SocketSet::iter]. A blocked command (a `Recv`/`Send`
/// that returned [`Response::WouldBlock`][crate::Response::WouldBlock]) can outlive its socket: a
/// `Close` (or a dropped owning future) removes the handle while the queued command still
/// references it, and `pump_blocked_commands` then re-runs the command against a dead handle
/// (tsr-02e — ping's raw ICMP socket). We must check existence first and never panic the netstack
/// actor (a panic kills the actor, after which every op fails with `InternalChannelClosed`).
macro_rules! get_socket_mut {
    ($self:expr, $ty:ty, $handle:expr) => {{
        let handle = unwrap_handle!($handle);

        // `iter()` borrows `self.socket_set` immutably; resolve the bool before the mutable
        // `get_mut` borrow below so the two borrows never overlap.
        let exists = $self.socket_set.iter().any(|(h, _)| h == handle);

        if !exists {
            tracing::debug!(
                ?handle,
                "socket gone (closed before blocked command re-ran); dropping command"
            );

            return $crate::command::Error::missing_socket().into();
        }

        $self.socket_set.get_mut::<$ty>(handle)
    }};
}

pub mod raw;
pub mod tcp;
pub mod udp;
