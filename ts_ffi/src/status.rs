//! Status and WhoIs marshaling for the C FFI.
//!
//! These mirror `tailscale::Device::status` and `tailscale::Device::whois`.
//!
//! ## The visitor idiom
//!
//! A [`tailscale::Status`] holds a self node plus a `Vec` of peers, each carrying owned `String`s
//! and a `Vec` of routes. Rather than transfer ownership of that nested, heap-allocated data across
//! the C boundary (which raises thorny free-who/free-when questions), we use a **visitor
//! callback**: the caller passes a function pointer and an opaque `void *user` cookie, and we
//! invoke it once per node with a borrowed [`status_node`].
//!
//! **Lifetime:** every pointer inside the [`status_node`] (the strings and the
//! `allowed_routes` array) is valid **only for the duration of that one callback invocation**. The
//! callback must copy out anything it needs to retain. After the callback returns, the backing
//! buffers are freed.

use std::{
    ffi::{self, CString, c_char, c_void},
    net::SocketAddr,
};

use crate::{TOKIO_RUNTIME, device, ffi_guard, net_types::sockaddr};

/// A single node in a [`ts_status`] / [`ts_whois`] result.
///
/// All pointer fields are valid only for the duration of the callback invocation that received
/// this struct (see the module docs). Copy anything you need to keep.
#[repr(C)]
pub struct status_node {
    /// The node's stable id (stable across re-registration). NUL-terminated.
    pub stable_id: *const c_char,
    /// The node's display name (fqdn if known, else bare hostname). NUL-terminated.
    pub display_name: *const c_char,
    /// The node's tailnet IPv4/IPv6 addresses, with port zeroed.
    pub ipv4: sockaddr,
    /// The node's tailnet IPv6 address, with port zeroed.
    pub ipv6: sockaddr,
    /// Whether the node is online: 1 = online, 0 = offline, -1 = unknown (always -1 in this fork).
    pub online: ffi::c_int,
    /// The routes this node accepts traffic for, as a `NULL`-terminated array of CIDR strings.
    pub allowed_routes: *const *const c_char,
    /// Number of entries in [`allowed_routes`](Self::allowed_routes) (excluding the `NULL`).
    pub allowed_routes_len: usize,
    /// Whether this node advertises a default route (is an exit-node candidate): 1 = yes, 0 = no.
    pub is_exit_node: ffi::c_int,
}

/// A per-node visitor callback. Invoked once per node with a borrowed [`status_node`] and the
/// opaque `user` cookie passed to the enumerating function.
pub type status_visitor = Option<unsafe extern "C" fn(node: *const status_node, user: *mut c_void)>;

/// Build the owned C-string backing buffers for one status node and invoke `visit`.
///
/// The buffers live on this stack frame and are dropped after `visit` returns, enforcing the
/// callback-only lifetime documented at the module level.
fn visit_node(
    stable_id: &str,
    display_name: &str,
    ipv4: std::net::IpAddr,
    ipv6: std::net::IpAddr,
    online: Option<bool>,
    routes: &[String],
    is_exit_node: bool,
    visit: unsafe extern "C" fn(*const status_node, *mut c_void),
    user: *mut c_void,
) {
    let stable_id = CString::new(stable_id).unwrap_or_default();
    let display_name = CString::new(display_name).unwrap_or_default();
    let routes: Vec<CString> = routes
        .iter()
        .filter_map(|r| CString::new(r.as_str()).ok())
        .collect();
    let mut route_ptrs: Vec<*const c_char> = routes.iter().map(|c| c.as_ptr()).collect();
    route_ptrs.push(std::ptr::null());

    let node = status_node {
        stable_id: stable_id.as_ptr(),
        display_name: display_name.as_ptr(),
        ipv4: SocketAddr::from((ipv4, 0)).into(),
        ipv6: SocketAddr::from((ipv6, 0)).into(),
        online: match online {
            Some(true) => 1,
            Some(false) => 0,
            None => -1,
        },
        allowed_routes: route_ptrs.as_ptr(),
        allowed_routes_len: routes.len(),
        is_exit_node: is_exit_node as ffi::c_int,
    };

    // SAFETY: `visit` is a caller-provided C function pointer; `node`'s pointers are valid for this
    // call. `user` is passed back verbatim per the visitor contract.
    unsafe { visit(&node, user) };
}

/// Enumerate this device and its tailnet peers (like `tailscale status`).
///
/// Invokes `visit` once for this node (if a netmap has been received) and once per peer. The
/// per-node [`status_node`] and all pointers inside it are valid **only** for the duration of
/// each callback (see the module docs) — copy out what you need.
///
/// Returns a negative number on error, otherwise the number of nodes visited (>= 0).
///
/// # Safety
///
/// `visit` must be a valid function pointer for the lifetime of this call (or `NULL`, in which case
/// nothing is visited and 0 is returned). `user` is passed back to `visit` unchanged.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_status(
    dev: &device,
    visit: status_visitor,
    user: *mut c_void,
) -> ffi::c_int {
    ffi_guard(move || {
        let Some(visit) = visit else {
            return 0;
        };

        let status = match TOKIO_RUNTIME.block_on(dev.0.status()) {
            Ok(status) => status,
            Err(e) => {
                tracing::error!(err = %e, "status");
                return -1;
            }
        };

        let mut count = 0;

        if let Some(n) = &status.self_node {
            let routes: Vec<String> = n.allowed_routes.iter().map(ToString::to_string).collect();
            visit_node(
                &n.stable_id.0,
                &n.display_name,
                n.ipv4,
                n.ipv6,
                n.online,
                &routes,
                n.is_exit_node,
                visit,
                user,
            );
            count += 1;
        }

        for n in &status.peers {
            let routes: Vec<String> = n.allowed_routes.iter().map(ToString::to_string).collect();
            visit_node(
                &n.stable_id.0,
                &n.display_name,
                n.ipv4,
                n.ipv6,
                n.online,
                &routes,
                n.is_exit_node,
                visit,
                user,
            );
            count += 1;
        }

        count
    })
}

/// Look up the tailnet node that owns the IP of `addr` (like `tsnet`'s `WhoIs`).
///
/// On a match, invokes `visit` exactly once with a borrowed [`status_node`] for the owning node
/// (same callback-only lifetime as [`ts_status`]). The port of `addr` is ignored.
///
/// Returns a negative number on error, zero if no node owns that address (and `visit` is not
/// called), and a positive number if a node was found and visited.
///
/// # Safety
///
/// `addr` must be a valid [`sockaddr`]. `visit` must be a valid function pointer for the lifetime
/// of this call (or `NULL`, in which case a match is reported but not visited). `user` is passed
/// back to `visit` unchanged.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_whois(
    dev: &device,
    addr: &sockaddr,
    visit: status_visitor,
    user: *mut c_void,
) -> ffi::c_int {
    ffi_guard(move || {
        let Ok(addr): Result<SocketAddr, _> = addr.try_into() else {
            tracing::error!("whois: invalid sockaddr");
            return -1;
        };

        match TOKIO_RUNTIME.block_on(dev.0.whois(addr)) {
            Ok(Some(whois)) => {
                if let Some(visit) = visit {
                    let node = tailscale::StatusNode::from_node(&whois.node);
                    let routes = node
                        .allowed_routes
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>();
                    visit_node(
                        &node.stable_id.0,
                        &node.display_name,
                        node.ipv4,
                        node.ipv6,
                        node.online,
                        &routes,
                        node.is_exit_node,
                        visit,
                        user,
                    );
                }
                1
            }
            Ok(None) => 0,
            Err(e) => {
                tracing::error!(err = %e, "whois");
                -1
            }
        }
    })
}
