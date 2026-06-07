//! TLS / Serve marshaling for the C FFI (Lane 5).
//!
//! ## Fail-closed by design
//!
//! This fork has no client-side ACME engine and no `set-dns` RPC to publish the DNS-01 challenge,
//! so [`ts_get_certificate`] and [`ts_listen_tls`] **always fail** today (with
//! `CertError::Unimplemented`/`NotTailnetName`). They never self-sign and never return a
//! placeholder. The error is logged via `tracing`; the function returns a negative status.
//!
//! We marshal the full [`serve_config`] now so callers can wire up against the final shape. When
//! issuance lands, [`ts_get_certificate`] will gain an out-param for the resulting key material and
//! [`ts_listen_tls`] will start returning a usable acceptor handle — without a C signature change
//! for the inputs.

use std::ffi::{self, c_char};

use crate::{TOKIO_RUNTIME, device, tcp::tcp_listener, util};

/// What a [`serve_config`] does with each decrypted stream.
#[repr(C)]
pub enum serve_target {
    /// Hand the accepted, decrypted stream back to the embedder.
    Accept = 0,
    /// Reverse-proxy the decrypted stream to the local address in [`serve_config::to`].
    Proxy = 1,
}

/// Configuration for terminating TLS on one tailnet port for one MagicDNS name.
///
/// Safe to zero-initialize: a zeroed struct has `kind == Accept`, `port == 0`, and null strings
/// (which fail validation, consistent with the fail-closed posture).
#[repr(C)]
pub struct serve_config {
    /// The MagicDNS name the certificate is for (e.g. `host.tailnet.ts.net`). Must be non-null.
    pub name: *const c_char,
    /// The tailnet (overlay) port to terminate TLS on.
    pub port: u16,
    /// What to do with each decrypted stream.
    pub kind: serve_target,
    /// For [`serve_target::Proxy`], the `host:port` to dial for the proxied backend. Ignored (and
    /// may be `NULL`) for [`serve_target::Accept`].
    pub to: *const c_char,
}

/// Obtain a TLS certificate for a node's MagicDNS `name` (like `tsnet`'s `GetCertificate`).
///
/// **Fail-closed.** This fork cannot mint a certificate, so this always returns a negative number
/// (after a tailnet-name check), logging the underlying [`CertError`](tailscale::CertError) via
/// `tracing`. It never self-signs.
///
/// Returns 0 on success (unreachable today) or a negative number on error. When issuance lands,
/// this will gain an out-param for the resulting key material.
///
/// # Safety
///
/// `name` must be able to be read according to [`std::ffi::CStr`] rules, i.e. it must be
/// NUL-terminated and valid for reading up to and including the NUL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_get_certificate(dev: &device, name: *const c_char) -> ffi::c_int {
    // SAFETY: ensured by function precondition
    let Some(name) = (unsafe { util::str(name) }) else {
        tracing::error!("get_certificate: name is null or invalid utf-8");
        return -1;
    };

    match TOKIO_RUNTIME.block_on(dev.0.get_certificate(name)) {
        Ok(_key) => 0,
        Err(e) => {
            tracing::error!(err = %e, "get_certificate (fail-closed in this fork)");
            -1
        }
    }
}

/// Build a TLS acceptor terminating TLS for `cfg.name` on the overlay (like `tsnet`'s `ListenTLS`).
///
/// **Fail-closed.** Because no real certificate can be issued in this fork, this always returns a
/// negative number rather than serving a self-signed cert or downgrading to plaintext. The
/// underlying [`CertError`](tailscale::CertError) is logged via `tracing`.
///
/// Returns 0 on success (unreachable today) or a negative number on error.
///
/// # Safety
///
/// `cfg.name` (and `cfg.to`, when `cfg.kind == Proxy`) must be able to be read according to
/// [`std::ffi::CStr`] rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_listen_tls(dev: &device, cfg: &serve_config) -> ffi::c_int {
    // SAFETY: ensured by function precondition
    let Some(name) = (unsafe { util::str(cfg.name) }) else {
        tracing::error!("listen_tls: name is null or invalid utf-8");
        return -1;
    };

    let target = match cfg.kind {
        serve_target::Accept => tailscale::ServeTarget::Accept,
        serve_target::Proxy => {
            // SAFETY: ensured by function precondition
            let Some(to) = (unsafe { util::str(cfg.to) }) else {
                tracing::error!("listen_tls: proxy target is null or invalid utf-8");
                return -1;
            };
            tailscale::ServeTarget::Proxy { to: to.to_owned() }
        }
    };

    let serve_cfg = tailscale::ServeConfig {
        name: name.to_owned(),
        port: cfg.port,
        target,
    };

    match TOKIO_RUNTIME.block_on(dev.0.listen_tls(&serve_cfg)) {
        Ok(_acceptor) => 0,
        Err(e) => {
            tracing::error!(err = %e, "listen_tls (fail-closed in this fork)");
            -1
        }
    }
}

/// How a [`ts_listen_service`] binds the service VIP port.
///
/// Both modes bind the same VIP:port at the listen layer (TLS termination / HTTP handling is the
/// embedder's concern); they differ only in the Go `ServiceMode` they map to.
#[repr(C)]
pub enum service_mode {
    /// Raw TCP on the service port (`tsnet`'s `ServiceModeTCP`).
    Tcp = 0,
    /// HTTP(S) on the service port (`tsnet`'s `ServiceModeHTTP`).
    Http = 1,
}

/// Host a Tailscale **VIP service** (`svc:<label>`) by binding an overlay listener on the
/// service's control-assigned virtual IP (like `tsnet`'s `ListenService`).
///
/// **Fail-closed.** Mirrors Go `tsnet.Server.ListenService`'s preconditions, enforced from this
/// node's own netmap state: the `name` must be a valid `svc:<dns-label>`, this node must be tagged,
/// and control must have assigned the service a VIP on this node. Any unmet precondition returns a
/// negative number (the typed [`ServiceError`](tailscale::ServiceError) is logged via `tracing`)
/// rather than binding anything.
///
/// On success returns a [`tcp_listener`] handle bound on the service VIP and `port` over the overlay
/// netstack (never a host socket); accept connections with
/// `ts_tcp_accept` and free it with
/// [`ts_tcp_close_listener`](crate::ts_tcp_close_listener). Returns null on error.
///
/// # Safety
///
/// `name` must be readable per [`std::ffi::CStr`] rules (NUL-terminated, valid up to and including
/// the NUL).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_listen_service(
    dev: &device,
    name: *const c_char,
    mode: service_mode,
    port: u16,
) -> Option<Box<tcp_listener>> {
    // SAFETY: ensured by function precondition
    let Some(name) = (unsafe { util::str(name) }) else {
        tracing::error!("listen_service: name is null or invalid utf-8");
        return None;
    };

    let svc_mode = match mode {
        service_mode::Tcp => tailscale::ServiceMode::Tcp { port },
        service_mode::Http => tailscale::ServiceMode::Http { port },
    };

    match TOKIO_RUNTIME.block_on(dev.0.listen_service(name, svc_mode)) {
        Ok(listener) => Some(Box::new(tcp_listener::new(listener))),
        Err(e) => {
            tracing::error!(err = %e, "listen_service (fail-closed in this fork)");
            None
        }
    }
}
