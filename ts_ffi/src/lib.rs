#![allow(non_camel_case_types)]

//! C FFI for tailscale-rs.
//!
//! # Safety
//!
//! All resources created by this library must be treated in accordance with the Rust
//! borrowing and ownership rules. Keep in mind that this _requires_ all memory to be
//! initialized before handing it into Rust-land.
//!
//! Null-checking is the responsibility of the caller, both on function call and return. We
//! don't check for parameter nullity: all params are assumed non-null unless noted
//! otherwise. Null return values are used for error signaling and must be inspected.
//!
//! Handles provided by this library are threadsafe -- operations will be implicitly
//! synchronized and serialized by the runtime. The only caveat is that you cannot `deinit`
//! or `close` a handle concurrently with other operations: this requires external
//! synchronization.

use std::{
    ffi::{self, CStr, CString, c_char},
    net::SocketAddr,
    sync::{LazyLock, Once},
    time::Duration,
};

use tracing::level_filters::LevelFilter;

mod capture;
mod config;
mod keys;
mod loopback;
mod net_types;
mod status;
mod taildrop;
mod tcp;
mod tls;
mod udp;
mod util;

pub use capture::{ts_capture_pcap, ts_stop_capture};
pub use loopback::{loopback_handle, ts_loopback, ts_loopback_stop};
pub use net_types::{
    AF_INET, AF_INET6, in_addr_t, in6_addr_t, sa_family_t, sockaddr, sockaddr_data, sockaddr_in,
    sockaddr_in6,
};
pub use status::{status_node, status_visitor, ts_status, ts_whois};
pub use taildrop::{
    ts_taildrop_delete_file, ts_taildrop_file_size, ts_taildrop_save_file,
    ts_taildrop_waiting_files,
};
pub use tcp::{
    tcp_listener, tcp_stream, ts_connect_by_name, ts_tcp_close, ts_tcp_close_listener,
    ts_tcp_connect, ts_tcp_listen, ts_tcp_listener_local_addr, ts_tcp_local_addr, ts_tcp_recv,
    ts_tcp_remote_addr, ts_tcp_send,
};
pub use tls::{
    serve_config, serve_target, service_mode, ts_get_certificate, ts_listen_service, ts_listen_tls,
};
pub use udp::{ts_udp_bind, ts_udp_close, ts_udp_recvfrom, ts_udp_sendto, udp_socket};

static TOKIO_RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    tracing::info!("started tokio runtime");

    rt
});

/// A Tailscale device, also variously called a "node" or "peer".
///
/// A device is the unit of identity in a tailnet; it has a tailnet IP and can send and
/// receive IP datagrams to other peers.
pub struct device(tailscale::Device);

static TRACING_ONCE: Once = Once::new();

/// Initialize the Rust tailscale tracing subsystem.
///
/// This is automatically called during `ts_init`, but you may want to call this first to log any
/// errors if initialization needs to be done before `ts_init`.
#[unsafe(no_mangle)]
pub extern "C" fn ts_init_tracing() {
    TRACING_ONCE.call_once(|| {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::builder()
                    .with_default_directive(LevelFilter::INFO.into())
                    .from_env_lossy(),
            )
            .init();
    });
}

/// Initialize a new Tailscale device.
///
/// `config` is the configuration with which to initialize the device. You may pass `NULL`, and a
/// default ephemeral configuration will be used.
///
/// `auth_token` is an optional auth token (you may pass `NULL`) that is used to authenticate the
/// device if required. If you pass `NULL`, the credentials in `config_path` must already be
/// authorized to make a successful connection.
///
/// # Safety
///
/// `auth_token`  must be able to be read according to [`CStr`] rules, i.e.
/// it must be NUL-terminated and valid for reading up to and including the NUL.
/// The string fields of `config` may be `NULL`, but if they are not, they must
/// obey the same invariants.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_init(
    config: Option<&config::config>,
    auth_token: *const c_char,
) -> Option<Box<device>> {
    ts_init_tracing();

    let config = match config {
        Some(cfg) => unsafe { cfg.to_ts_config() },
        None => Default::default(),
    };

    let auth_token = if auth_token.is_null() {
        None
    } else {
        unsafe { util::str(auth_token).map(ToOwned::to_owned) }
    };

    match TOKIO_RUNTIME.block_on(tailscale::Device::new(&config, auth_token)) {
        Ok(dev) => Some(Box::new(device(dev))),
        Err(e) => {
            tracing::error!(err = %e, "ts_init failed");
            None
        }
    }
}

/// Initialize a new Tailscale device with a default configuration using the given key file for the
/// key state. The file is created with new keys if it doesn't exist.
///
/// `auth_token` is an optional auth token (you may pass `NULL`) that is used to authenticate the
/// device if required. If you pass `NULL`, the credentials in `key_file` must already be
/// authorized to make a successful connection.
///
/// # Safety
///
/// `auth_token` and `key_file` must be able to be read according to [`CStr`] rules, i.e.
/// they must be NUL-terminated and valid for reading up to and including the NUL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_init_from_key_file(
    key_file: *const c_char,
    auth_token: *const c_char,
) -> Option<Box<device>> {
    let mut state = keys::persisted_key_state::default();

    // SAFETY: CStr invariants maintained by function precondition
    if unsafe { keys::ts_load_key_file(key_file, false, &mut state) } < 0 {
        return None;
    }

    let config = config::config {
        key_state: Some(&mut state),
        ..Default::default()
    };

    // SAFETY: `auth_token` meets the CStr invariants by this function precondition. `config` is
    // safely default-initialized, except for key state, which has no safety requirements.
    unsafe { ts_init(Some(&config), auth_token) }
}

/// Deinitialize and shut down a Tailscale device.
#[unsafe(no_mangle)]
pub extern "C" fn ts_deinit(dev: Box<device>) {
    drop(dev)
}

/// Get the IPv4 address of the Tailscale node, blocking until it's available.
///
/// Returns a negative number on error.
#[unsafe(no_mangle)]
pub extern "C" fn ts_ipv4_addr(dev: &device, dst: &mut in_addr_t) -> ffi::c_int {
    let addr = match TOKIO_RUNTIME.block_on(dev.0.ipv4_addr()) {
        Ok(addr) => addr,
        Err(e) => {
            tracing::error!(error = %e, "getting ipv4");
            return -1;
        }
    };

    dst.0 = addr.octets();

    0
}

/// Get the IPv6 address of the Tailscale node, blocking until it's available.
///
/// Returns a negative number on error.
#[unsafe(no_mangle)]
pub extern "C" fn ts_ipv6_addr(dev: &device, dst: &mut in6_addr_t) -> ffi::c_int {
    let addr = match TOKIO_RUNTIME.block_on(dev.0.ipv6_addr()) {
        Ok(addr) => addr,
        Err(e) => {
            tracing::error!(error = %e, "getting ipv6");
            return -1;
        }
    };

    dst.0 = addr.segments();

    0
}

/// Get the IPv4 address of a specified peer by name.
///
/// `peer_name` can be a fully-qualified name (`$HOST.tail1234.ts.net`) or an unqualified
/// hostname (`$HOST`). The first match is returned: shared-in nodes may cause ambiguity
/// when unqualified hostnames are used.
///
/// Returns a negative number if there was an error, zero if no match was found, and a
/// positive number if `addr` has been populated with the address for the requested peer.
///
/// # Safety
///
/// `peer_name` must be able to be read according to [`CStr`] rules, i.e.
/// it must be NUL-terminated and valid for reading up to and including the NUL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_peer_ipv4_addr(
    dev: &device,
    peer_name: *const c_char,
    addr: &mut in_addr_t,
) -> ffi::c_int {
    // SAFETY: ensured by function precondition
    unsafe {
        _peer_by_addr(dev, peer_name, |n| {
            *addr = n.tailnet_address.ipv4.addr().into();
        })
    }
}

/// Get the IPv6 address of a specified peer by name.
///
/// `peer_name` can be a fully-qualified name (`$HOST.tail1234.ts.net`) or an unqualified
/// hostname (`$HOST`). The first match is returned: shared-in nodes may cause ambiguity
/// when unqualified hostnames are used.
///
/// Returns a negative number if there was an error, zero if no match was found, and a
/// positive number if `addr` has been populated with the address for the requested peer.
///
/// # Safety
///
/// `peer_name` must be able to be read according to [`CStr`] rules, i.e.
/// it must be NUL-terminated and valid for reading up to and including the NUL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_peer_ipv6_addr(
    dev: &device,
    peer_name: *const c_char,
    addr: &mut in6_addr_t,
) -> ffi::c_int {
    // SAFETY: ensured by function precondition
    unsafe {
        _peer_by_addr(dev, peer_name, |n| {
            *addr = n.tailnet_address.ipv6.addr().into();
        })
    }
}

/// # Safety
///
/// `peer_name` must be able to be read according to [`CStr`] rules, i.e.
/// it must be NUL-terminated and valid for reading up to and including the NUL.
unsafe fn _peer_by_addr(
    dev: &device,
    peer_name: *const c_char,
    on_node_info: impl FnOnce(&tailscale::NodeInfo),
) -> ffi::c_int {
    // SAFETY: ensured by function precondition
    let name = unsafe { CStr::from_ptr(peer_name) };

    let Ok(name) = name.to_str() else {
        tracing::error!("peer name: invalid utf-8");
        return -1;
    };

    match TOKIO_RUNTIME.block_on(dev.0.peer_by_name(name)) {
        Ok(Some(node)) => {
            on_node_info(&node);
            1
        }

        Ok(None) => 0,

        Err(e) => {
            tracing::error!(error = %e, "looking up peer");
            -1
        }
    }
}

/// Resolve a tailnet peer (or this node) by MagicDNS `name` to its tailnet IPv4 address.
///
/// This is an in-process netmap lookup (no DNS server); only MagicDNS names are resolved. IPv6 is
/// never resolved (this fork is IPv4-only on the tailnet).
///
/// Returns a negative number on error, zero if no tailnet node has that name, and a positive
/// number if `addr` has been populated with the resolved IPv4 address.
///
/// # Safety
///
/// `name` must be able to be read according to [`CStr`] rules, i.e. it must be NUL-terminated and
/// valid for reading up to and including the NUL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_resolve(
    dev: &device,
    name: *const c_char,
    addr: &mut in_addr_t,
) -> ffi::c_int {
    // SAFETY: ensured by function precondition
    let Some(name) = (unsafe { util::str(name) }) else {
        tracing::error!("resolve: name is null or invalid utf-8");
        return -1;
    };

    match TOKIO_RUNTIME.block_on(dev.0.resolve(name)) {
        Ok(Some(ipv4)) => {
            *addr = ipv4.into();
            1
        }
        Ok(None) => 0,
        Err(e) => {
            tracing::error!(error = %e, "resolve");
            -1
        }
    }
}

/// Ping a tailnet peer over the overlay with an ICMPv4 echo, returning the round-trip time.
///
/// `dst` is the destination address (only its IP is used; the port is ignored). `timeout_ms` is
/// the timeout in milliseconds. On success the round-trip time in milliseconds is written to `rtt_ms`.
///
/// Returns 0 on success, a negative number on error (timeout, IPv6 destination — unsupported in
/// this IPv4-only fork — or a netstack error). `rtt_ms` is only written on success.
///
/// # Safety
///
/// `dst` must be a valid [`sockaddr`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_ping(
    dev: &device,
    dst: &sockaddr,
    timeout_ms: u64,
    rtt_ms: &mut u64,
) -> ffi::c_int {
    let Ok(dst): Result<SocketAddr, _> = dst.try_into() else {
        tracing::error!("ping: invalid sockaddr");
        return -1;
    };

    match TOKIO_RUNTIME.block_on(dev.0.ping(dst.ip(), Duration::from_millis(timeout_ms))) {
        Ok(rtt) => {
            *rtt_ms = rtt.as_millis() as u64;
            0
        }
        Err(e) => {
            tracing::error!(err = %e, "ping");
            -1
        }
    }
}

/// Free a C string previously allocated and returned by this library (e.g. by [`ts_metrics`],
/// [`ts_fetch_id_token`], [`ts_tka_status`], or `ts_taildrop_waiting_files`).
///
/// Passing `NULL` is a no-op. Each returned string must be freed at most once, and only with this
/// function — do not call the C library `free` on it.
///
/// # Safety
///
/// `s` must be either `NULL` or a pointer obtained from one of this library's string-returning
/// functions and not yet freed. It must not be used after this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_string_free(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    // SAFETY: by precondition, `s` came from `CString::into_raw` in this library and has not been
    // freed, so reconstituting the `CString` (which frees on drop) is sound.
    drop(unsafe { CString::from_raw(s) });
}

/// Helper: allocate a C string from a Rust `String`, returning a pointer that the caller must free
/// with [`ts_string_free`]. Returns null if the string contains an interior NUL.
pub(crate) fn into_c_string(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(e) => {
            tracing::error!(err = %e, "string contains interior NUL");
            std::ptr::null_mut()
        }
    }
}

/// Request an OIDC **ID token** from control for this node, scoped to `audience` (like `tailscale`'s
/// `id-token` LocalAPI).
///
/// On success, writes a newly-allocated, NUL-terminated JWT string to `*out` and returns 0; the
/// caller must free it with [`ts_string_free`]. On error, writes `NULL` to `*out` and returns a
/// negative number (the underlying [`IdTokenError`](tailscale::IdTokenError) is logged via
/// `tracing`).
///
/// # Safety
///
/// `audience` must be readable per [`CStr`] rules (NUL-terminated, valid up to and including the
/// NUL). `out` must be a valid, writable pointer to a `char *`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_fetch_id_token(
    dev: &device,
    audience: *const c_char,
    out: *mut *mut c_char,
) -> ffi::c_int {
    // SAFETY: ensured by function precondition
    let Some(audience) = (unsafe { util::str(audience) }) else {
        tracing::error!("fetch_id_token: audience is null or invalid utf-8");
        return -1;
    };

    match TOKIO_RUNTIME.block_on(dev.0.fetch_id_token(audience)) {
        Ok(jwt) => {
            let ptr = into_c_string(jwt);
            if ptr.is_null() {
                return -1;
            }
            // SAFETY: `out` is a valid writable pointer by precondition.
            unsafe { *out = ptr };
            0
        }
        Err(e) => {
            tracing::error!(err = %e, "fetch_id_token");
            // SAFETY: `out` is a valid writable pointer by precondition.
            unsafe { *out = std::ptr::null_mut() };
            -1
        }
    }
}

/// Snapshot this node's client metrics in Prometheus text exposition format (like Go Tailscale's
/// `clientmetric` registry).
///
/// Returns a newly-allocated, NUL-terminated string the caller must free with [`ts_string_free`].
/// Returns `NULL` only if the rendered metrics contain an interior NUL (never expected). The
/// registry is process-global, so the output covers every device in the process.
#[unsafe(no_mangle)]
pub extern "C" fn ts_metrics(dev: &device) -> *mut c_char {
    into_c_string(dev.0.metrics())
}

/// This node's key-expiry instant as Unix seconds (`Node.KeyExpiry` in Go).
///
/// On success returns 0 and sets `*out_has` to 1 with `*out_unix` populated if the key has an
/// expiry, or `*out_has` to 0 (and leaves `*out_unix` untouched) if the key never expires. Returns
/// a negative number on error (and writes nothing).
///
/// # Safety
///
/// `out_unix` and `out_has` must be valid, writable pointers.
#[unsafe(no_mangle)]
pub extern "C" fn ts_self_key_expiry_unix(
    dev: &device,
    out_unix: &mut i64,
    out_has: &mut ffi::c_int,
) -> ffi::c_int {
    match TOKIO_RUNTIME.block_on(dev.0.self_key_expiry_unix()) {
        Ok(Some(unix)) => {
            *out_unix = unix;
            *out_has = 1;
            0
        }
        Ok(None) => {
            *out_has = 0;
            0
        }
        Err(e) => {
            tracing::error!(err = %e, "self_key_expiry_unix");
            -1
        }
    }
}

/// Whether this node's key has expired as of now (`!KeyExpiry.IsZero() && KeyExpiry.Before(now)` in
/// Go). A key with no expiry is never expired.
///
/// On success returns 0 and sets `*out` to 1 if expired, 0 otherwise. Returns a negative number on
/// error.
///
/// # Safety
///
/// `out` must be a valid, writable pointer.
#[unsafe(no_mangle)]
pub extern "C" fn ts_self_key_expired(dev: &device, out: &mut ffi::c_int) -> ffi::c_int {
    match TOKIO_RUNTIME.block_on(dev.0.self_key_expired()) {
        Ok(expired) => {
            *out = expired as ffi::c_int;
            0
        }
        Err(e) => {
            tracing::error!(err = %e, "self_key_expired");
            -1
        }
    }
}

/// Fetch the current Tailnet Lock (TKA) status pushed by control, if any.
///
/// On success returns 0 and writes a newly-allocated JSON object to `*out` of the form
/// `{"enabled":<bool>,"disabled":<bool>,"head":"<base32>"}` (the caller frees it with
/// [`ts_string_free`]). When control has sent no TKA status, returns 0 and writes the JSON
/// `null`. Returns a negative number on error (and writes `NULL` to `*out`).
///
/// # Safety
///
/// `out` must be a valid, writable pointer to a `char *`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_tka_status(dev: &device, out: *mut *mut c_char) -> ffi::c_int {
    match TOKIO_RUNTIME.block_on(dev.0.tka_status()) {
        Ok(status) => {
            let json = match status {
                Some(s) => format!(
                    "{{\"enabled\":{},\"disabled\":{},\"head\":{:?}}}",
                    s.is_enabled(),
                    s.disabled,
                    s.head
                ),
                None => "null".to_owned(),
            };
            let ptr = into_c_string(json);
            if ptr.is_null() {
                return -1;
            }
            // SAFETY: `out` is a valid writable pointer by precondition.
            unsafe { *out = ptr };
            0
        }
        Err(e) => {
            tracing::error!(err = %e, "tka_status");
            // SAFETY: `out` is a valid writable pointer by precondition.
            unsafe { *out = std::ptr::null_mut() };
            -1
        }
    }
}

/// Send a local file to a tailnet peer via Taildrop (Go `PushFile` / `tailscale file cp`).
///
/// Looks up `peer_name` (a MagicDNS name) in the netmap, opens `src_path` as a local file, and
/// streams its full contents to the peer's peerAPI as `file_name` over the encrypted overlay (never
/// a host socket). The destination is derived solely from the resolved peer's own node record.
///
/// Returns 0 on success, a positive number (1) if no peer matched `peer_name`, and a negative
/// number on error (invalid input, file open failure, or transfer failure — logged via `tracing`).
///
/// # Safety
///
/// `peer_name`, `file_name`, and `src_path` must each be readable per [`CStr`] rules (NUL-
/// terminated, valid up to and including the NUL).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_send_file(
    dev: &device,
    peer_name: *const c_char,
    file_name: *const c_char,
    src_path: *const c_char,
) -> ffi::c_int {
    // SAFETY: ensured by function precondition
    let (Some(peer_name), Some(file_name), Some(src_path)) = (unsafe {
        (
            util::str(peer_name),
            util::str(file_name),
            util::str(src_path),
        )
    }) else {
        tracing::error!("send_file: a string argument is null or invalid utf-8");
        return -1;
    };

    let peer = match TOKIO_RUNTIME.block_on(dev.0.peer_by_name(peer_name)) {
        Ok(Some(peer)) => peer,
        Ok(None) => return 1,
        Err(e) => {
            tracing::error!(err = %e, "send_file: peer lookup");
            return -1;
        }
    };

    TOKIO_RUNTIME.block_on(async {
        let file = match tokio::fs::File::open(src_path).await {
            Ok(f) => f,
            Err(e) => {
                tracing::error!(err = %e, "send_file: open source");
                return -1;
            }
        };
        let len = match file.metadata().await {
            Ok(m) => m.len(),
            Err(e) => {
                tracing::error!(err = %e, "send_file: stat source");
                return -1;
            }
        };
        match dev.0.send_file(&peer, file_name, len, file).await {
            Ok(()) => 0,
            Err(e) => {
                tracing::error!(err = %e, "send_file");
                -1
            }
        }
    })
}
