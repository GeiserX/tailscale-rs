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

use crate::{TOKIO_RUNTIME, device, util};

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
