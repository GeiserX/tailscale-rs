//! tsnet `Server` facade marshaling for the C FFI.
//!
//! Wraps [`tailscale::tsnet::Server`] — the Go `tsnet.Server`-shaped facade over `Device` — to
//! surface the two things the plain `Device` FFI (`ts_init` + `ts_loopback`) does not:
//!
//! * the **dual-credential loopback** (Go `Loopback() (addr, proxyCred, localAPICred, err)`): a
//!   SOCKS5 proxy *and* an in-process LocalAPI HTTP server, each on its own `127.0.0.1` listener
//!   with its own credential; and
//! * the **LocalClient** handle (Go `LocalClient()`): an authenticated client for that LocalAPI
//!   HTTP server.
//!
//! Thin: every call forwards to the facade over the shared `TOKIO_RUNTIME`. The server is
//! constructed lazily — the wrapped `Device` is not built until the first [`ts_server_loopback`] /
//! [`ts_server_local_client`] call (Go's "fields may be set until the first method call"). Fork
//! config supersets beyond Go `tsnet.Server` (exit nodes, forwarding) stay on the [`crate::device`]
//! surface (`ts_init`); this exposes the Go-parity `Server` fields.

use std::ffi::{self, CString, c_char};
use std::path::PathBuf;

use tailscale::tsnet;

use crate::{TOKIO_RUNTIME, ffi_guard, into_c_string, net_types::sockaddr, util};

/// An opaque, lazily-started tsnet server (Go `tsnet.Server`).
///
/// Create one with [`ts_server_new`], drive it with [`ts_server_loopback`] /
/// [`ts_server_local_client`], and free it with [`ts_server_free`] (whose drop tears the loopback
/// listeners down and shuts the wrapped device down).
pub struct server(tsnet::Server);

/// An opaque handle to the in-process LocalAPI HTTP client (Go `tsnet.Server.LocalClient()`).
///
/// Obtain one with [`ts_server_local_client`]; query it with [`ts_local_client_status`] /
/// [`ts_local_client_get`]; free it with [`ts_local_client_free`]. Freeing this handle does *not*
/// stop the LocalAPI server (that lives for the [`server`]'s lifetime) — it only releases the
/// handle.
pub struct local_client(tsnet::LocalClient);

/// Create a new tsnet server (Go `&tsnet.Server{Hostname, AuthKey, ControlURL, Dir, Ephemeral,
/// AdvertiseTags}`).
///
/// Every string argument may be `NULL` to leave that field unset (engine default). `dir`, when
/// non-`NULL`, is the state directory that persists this node's identity keys across runs (Go
/// `Server.Dir`); `NULL` gives a fresh ephemeral in-memory identity. `tags` (Go `AdvertiseTags`) is
/// a `tags_len`-long array of C strings — the ACL tags to advertise — or `NULL` (with `tags_len` 0)
/// for none. No network I/O happens here — the wrapped device is built on the first
/// [`ts_server_loopback`]/[`ts_server_local_client`] call.
///
/// Returns an owned handle (free with [`ts_server_free`]), or `NULL` only if the call panicked.
///
/// # Safety
///
/// Each non-`NULL` string argument must be readable per [`std::ffi::CStr`] rules (NUL-terminated,
/// valid up to and including the NUL). When `tags` is non-`NULL` it must point to `tags_len`
/// readable, properly-aligned `*const c_char` elements, each element itself `NULL` or such a C
/// string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_server_new(
    hostname: *const c_char,
    auth_key: *const c_char,
    control_url: *const c_char,
    dir: *const c_char,
    ephemeral: bool,
    tags: *const *const c_char,
    tags_len: usize,
) -> Option<Box<server>> {
    ffi_guard(move || {
        // A server may be the first entry point a caller touches, before any `ts_init`.
        crate::ts_init_tracing();
        // SAFETY: each pointer is `NULL` or a valid C string per the safety precondition.
        let owned = |p| unsafe { util::str(p) }.map(ToOwned::to_owned);
        let mut s = tsnet::Server::new();
        s.hostname = owned(hostname);
        s.auth_key = owned(auth_key);
        s.control_url = owned(control_url);
        s.ephemeral = ephemeral;
        // SAFETY: `dir` is `NULL` or a valid C string per the safety precondition.
        s.dir = unsafe { util::str(dir) }.map(PathBuf::from);
        // ACL tags (Go `AdvertiseTags`): read the `tags_len`-long pointer array, keeping each valid
        // UTF-8 C string (a `NULL` or non-UTF-8 element is skipped). A `NULL` array leaves it empty.
        if !tags.is_null() {
            // SAFETY: non-`NULL` `tags` is valid for `tags_len` `*const c_char` reads per the
            // precondition; each element pointer is dereferenced null-safely by `util::str`.
            s.advertise_tags = unsafe { std::slice::from_raw_parts(tags, tags_len) }
                .iter()
                .filter_map(|&p| unsafe { util::str(p) }.map(ToOwned::to_owned))
                .collect();
        }
        Some(Box::new(server(s)))
    })
}

/// Start (once) the loopback surface and return its addresses + both credentials (Go
/// `Loopback() (addr, proxyCred, localAPICred, err)`).
///
/// On success returns 0 and writes: the SOCKS5 proxy's bound `127.0.0.1` address to
/// `*out_socks_addr` and its credential (SOCKS5 password for username `tsnet`) to `*out_proxy_cred`;
/// the in-process LocalAPI HTTP server's bound `127.0.0.1` address to `*out_localapi_addr` and its
/// credential (HTTP Basic-auth password) to `*out_localapi_cred`. Both credential strings are
/// newly-allocated and must be freed with [`ts_string_free`](crate::ts_string_free).
///
/// Idempotent: repeated calls return the same addresses and credentials (the listeners live for the
/// [`server`]'s lifetime). Returns a negative number on error (e.g. TUN transport mode, or a bind
/// failure — logged via `tracing`); in that case nothing is written.
///
/// # Safety
///
/// `out_socks_addr`, `out_proxy_cred`, `out_localapi_addr`, and `out_localapi_cred` must each be
/// valid, writable pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_server_loopback(
    srv: &server,
    out_socks_addr: &mut sockaddr,
    out_proxy_cred: *mut *mut c_char,
    out_localapi_addr: &mut sockaddr,
    out_localapi_cred: *mut *mut c_char,
) -> ffi::c_int {
    ffi_guard(move || {
        let lb = match TOKIO_RUNTIME.block_on(srv.0.loopback()) {
            Ok(lb) => lb,
            Err(e) => {
                tracing::error!(err = %e, "server loopback");
                return -1;
            }
        };
        // Build both C strings before writing any output, so a NUL in one credential (never happens
        // for a base64/hex credential) cannot leak the other.
        let (proxy, localapi) = match (CString::new(lb.proxy_cred), CString::new(lb.local_api_cred)) {
            (Ok(p), Ok(l)) => (p, l),
            _ => {
                tracing::error!("loopback credential contains interior NUL");
                return -1;
            }
        };
        *out_socks_addr = lb.address.into();
        *out_localapi_addr = lb.local_api_address.into();
        // SAFETY: `out_proxy_cred`/`out_localapi_cred` are valid writable pointers by precondition.
        unsafe {
            *out_proxy_cred = proxy.into_raw();
            *out_localapi_cred = localapi.into_raw();
        }
        0
    })
}

/// Obtain a [`local_client`] for this node's in-process LocalAPI HTTP server (Go
/// `tsnet.Server.LocalClient()`), starting the loopback surface if needed.
///
/// On success returns 0 and writes an owned handle to `*out_handle` (free it with
/// [`ts_local_client_free`]). Returns a negative number on error (logged via `tracing`); nothing is
/// written.
///
/// # Safety
///
/// `out_handle` must be a valid, writable pointer to a `local_client *`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_server_local_client(
    srv: &server,
    out_handle: *mut *mut local_client,
) -> ffi::c_int {
    ffi_guard(move || match TOKIO_RUNTIME.block_on(srv.0.local_client()) {
        Ok(lc) => {
            // SAFETY: `out_handle` is a valid writable pointer by precondition.
            unsafe { *out_handle = Box::into_raw(Box::new(local_client(lc))) };
            0
        }
        Err(e) => {
            tracing::error!(err = %e, "server local_client");
            -1
        }
    })
}

/// `GET /localapi/v0/status` over the loopback (Go `LocalClient().Status`): the node + peer status
/// as raw JSON.
///
/// On success returns 0 and writes a newly-allocated, NUL-terminated JSON string to `*out_json`
/// (free it with [`ts_string_free`](crate::ts_string_free)). Returns a negative number if the
/// server answered non-`200` or the request failed (logged via `tracing`); nothing is written.
///
/// # Safety
///
/// `out_json` must be a valid, writable pointer to a `char *`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_local_client_status(
    lc: &local_client,
    out_json: *mut *mut c_char,
) -> ffi::c_int {
    ffi_guard(move || match TOKIO_RUNTIME.block_on(lc.0.status()) {
        Ok(body) => {
            let json = into_c_string(String::from_utf8_lossy(&body).into_owned());
            if json.is_null() {
                return -1;
            }
            // SAFETY: `out_json` is a valid writable pointer by precondition.
            unsafe { *out_json = json };
            0
        }
        Err(e) => {
            tracing::error!(err = %e, "local_client status");
            -1
        }
    })
}

/// Perform an authenticated `GET` against an arbitrary LocalAPI `path` (e.g.
/// `"/localapi/v0/status"`), returning the HTTP status code and body.
///
/// On success returns 0, writes the HTTP status code to `*out_code`, and writes a newly-allocated,
/// NUL-terminated body string to `*out_body` (free it with
/// [`ts_string_free`](crate::ts_string_free)). Returns a negative number if the request could not be
/// performed (logged via `tracing`); in that case nothing is written. Note a non-`200` code is a
/// *success* here (0 is returned, `*out_code` carries the code) — only transport failures are errors.
///
/// # Safety
///
/// `path` must be readable per [`std::ffi::CStr`] rules. `out_code` and `out_body` must each be
/// valid, writable pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_local_client_get(
    lc: &local_client,
    path: *const c_char,
    out_code: *mut u16,
    out_body: *mut *mut c_char,
) -> ffi::c_int {
    ffi_guard(move || {
        // SAFETY: `path` is a valid C string per the safety precondition.
        let Some(path) = (unsafe { util::str(path) }) else {
            tracing::error!("local_client get: path is NULL or not UTF-8");
            return -1;
        };
        match TOKIO_RUNTIME.block_on(lc.0.get(path)) {
            Ok((code, body)) => {
                let body = into_c_string(String::from_utf8_lossy(&body).into_owned());
                if body.is_null() {
                    return -1;
                }
                // SAFETY: `out_code`/`out_body` are valid writable pointers by precondition.
                unsafe {
                    *out_code = code;
                    *out_body = body;
                }
                0
            }
            Err(e) => {
                tracing::error!(err = %e, "local_client get");
                -1
            }
        }
    })
}

/// The `127.0.0.1` address of the LocalAPI HTTP server this client talks to (Go
/// `LocalClient().address`). Returns an `AF_UNSPEC` [`sockaddr`] only on panic.
#[unsafe(no_mangle)]
pub extern "C" fn ts_local_client_address(lc: &local_client) -> sockaddr {
    ffi_guard(move || lc.0.address().into())
}

/// The LocalAPI credential (HTTP Basic-auth password) this client sends (Go `LocalClient()`'s cred),
/// matching the Python/Elixir `credential` accessors.
///
/// Returns a newly-allocated, NUL-terminated string the caller must free with
/// [`ts_string_free`](crate::ts_string_free). Returns `NULL` only on panic (the hex credential never
/// contains an interior NUL).
#[unsafe(no_mangle)]
pub extern "C" fn ts_local_client_credential(lc: &local_client) -> *mut c_char {
    ffi_guard(move || into_c_string(lc.0.credential().to_owned()))
}

/// Free the server, tearing down the loopback SOCKS5 proxy + LocalAPI HTTP server and shutting the
/// wrapped device down (the `Server`'s drop stops the accept loops and releases the bound ports).
/// Passing `NULL` is a no-op.
///
/// Any [`local_client`] handles obtained from this server are inert afterward; free them separately
/// with [`ts_local_client_free`].
#[unsafe(no_mangle)]
pub extern "C" fn ts_server_free(srv: Option<Box<server>>) {
    ffi_guard(move || drop(srv))
}

/// Free a [`local_client`] handle. Does not stop the LocalAPI server (that lives for the
/// [`server`]'s lifetime). Passing `NULL` is a no-op.
#[unsafe(no_mangle)]
pub extern "C" fn ts_local_client_free(lc: Option<Box<local_client>>) {
    ffi_guard(move || drop(lc))
}
