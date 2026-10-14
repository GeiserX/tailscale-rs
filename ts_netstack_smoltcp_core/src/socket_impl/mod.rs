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
/// or wrong-type handle, and it exposes no fallible getter. The generation/kind registry
/// maintained by `add_socket`/`remove_socket` validates indexed access in O(log n).
/// A blocked command can outlive its socket (tsr-02e), so always validate first and never panic the netstack
/// actor (a panic kills the actor, after which every op fails with `InternalChannelClosed`).
macro_rules! get_socket_mut {
    ($self:expr, $ty:ty, $handle:expr) => {{
        let handle = unwrap_handle!($handle);

        let matches_type = $self.socket_matches::<$ty>(handle);

        if !matches_type {
            tracing::debug!(
                ?handle,
                "socket gone or slot reused by another type; dropping command"
            );

            return $crate::command::Error::missing_socket().into();
        }

        $self.socket_set.get_mut::<$ty>(handle)
    }};
}

pub mod raw;
pub mod tcp;
pub mod udp;
