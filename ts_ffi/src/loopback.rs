//! Loopback SOCKS5 proxy marshaling for the C FFI.
//!
//! This mirrors `tailscale::Device::loopback`: it binds a host-loopback-only SOCKS5 proxy whose
//! every connection egresses over the overlay (never a host socket), and returns the bound address,
//! the required proxy credential, and an opaque handle whose drop stops the proxy.

use std::ffi::{self, c_char};

use crate::{TOKIO_RUNTIME, device, ffi_guard, into_c_string, net_types::sockaddr};

/// An opaque handle to a running loopback SOCKS5 proxy.
///
/// Hold it for exactly as long as the proxy should run; free it with [`ts_loopback_stop`] (which
/// stops the proxy) when done. Do not let it outlive the device it proxies into.
//
// The wrapped handle is never read: its sole purpose is to keep the proxy alive until this struct
// is dropped (the native `LoopbackHandle`'s `Drop` aborts the accept loop).
#[allow(dead_code)]
pub struct loopback_handle(tailscale::LoopbackHandle);

/// Start the loopback SOCKS5 proxy for this device (like the SOCKS5 leg of `tsnet`'s `Loopback`).
///
/// On success returns 0, writes the bound `127.0.0.1` address (host loopback only) to `*out_addr`,
/// writes a newly-allocated proxy credential string to `*out_cred` (the SOCKS5 password for
/// username `tsnet`; the caller frees it with [`ts_string_free`](crate::ts_string_free)), and writes
/// an owned handle to `*out_handle` (free it with [`ts_loopback_stop`]). Returns a negative number
/// on error (e.g. TUN transport mode, or a bind failure — logged via `tracing`); in that case
/// nothing is written.
///
/// # Safety
///
/// `out_addr`, `out_cred`, and `out_handle` must each be valid, writable pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_loopback(
    dev: &device,
    out_addr: &mut sockaddr,
    out_cred: *mut *mut c_char,
    out_handle: *mut *mut loopback_handle,
) -> ffi::c_int {
    ffi_guard(move || {
        match TOKIO_RUNTIME.block_on(dev.0.loopback()) {
            Ok((addr, cred, handle)) => {
                let cred_ptr = into_c_string(cred);
                if cred_ptr.is_null() {
                    return -1;
                }
                *out_addr = addr.into();
                // SAFETY: `out_cred` and `out_handle` are valid writable pointers by precondition.
                unsafe {
                    *out_cred = cred_ptr;
                    *out_handle = Box::into_raw(Box::new(loopback_handle(handle)));
                }
                0
            }
            Err(e) => {
                tracing::error!(err = %e, "loopback");
                -1
            }
        }
    })
}

/// Stop the loopback SOCKS5 proxy and free its handle (the counterpart to the handle returned by
/// [`ts_loopback`]).
///
/// Dropping the handle stops the accept loop and releases the bound `127.0.0.1` port. Passing
/// `NULL` is a no-op.
#[unsafe(no_mangle)]
pub extern "C" fn ts_loopback_stop(handle: Option<Box<loopback_handle>>) {
    ffi_guard(move || drop(handle))
}
