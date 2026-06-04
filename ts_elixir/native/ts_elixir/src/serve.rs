//! Lane 5: TLS / Serve marshaling (`get_certificate`, `listen_tls`).
//!
//! Both NIFs are **fail-closed**: this fork has no client-side ACME engine and no `set-dns`
//! RPC, so `tailscale::Device::get_certificate` / `listen_tls` always return
//! [`tailscale::CertError::Unimplemented`] today. We faithfully surface that as
//! `{:error, reason}` carrying the `CertError` Display string — we never self-sign, never
//! downgrade to plaintext, and never report success. When ACME issuance lands natively, these
//! start succeeding with no Elixir-side change.

use rustler::{Encoder, ResourceArc, Term};

use crate::{Device, TOKIO_RUNTIME, atoms};

mod atoms_serve {
    rustler::atoms! {
        accept,
        proxy,
    }
}

/// Decode an Elixir serve-config term into a native [`tailscale::ServeConfig`].
///
/// The term is a `{name, port, target}` tuple where `target` is either the atom `:accept` or a
/// `{:proxy, "host:port"}` tuple.
fn serve_config_from_erl(term: Term) -> Option<tailscale::ServeConfig> {
    let tuple = rustler::types::tuple::get_tuple(term).ok()?;
    if tuple.len() != 3 {
        return None;
    }

    let name: String = tuple[0].decode().ok()?;
    let port: u16 = tuple[1].decode().ok()?;
    let target = serve_target_from_erl(tuple[2])?;

    Some(tailscale::ServeConfig { name, port, target })
}

fn serve_target_from_erl(term: Term) -> Option<tailscale::ServeTarget> {
    if let Ok(atom) = term.decode::<rustler::Atom>()
        && atom == atoms_serve::accept()
    {
        return Some(tailscale::ServeTarget::Accept);
    }

    if let Ok(tuple) = rustler::types::tuple::get_tuple(term)
        && tuple.len() == 2
        && tuple[0].decode::<rustler::Atom>().ok()? == atoms_serve::proxy()
    {
        let to: String = tuple[1].decode().ok()?;
        return Some(tailscale::ServeTarget::Proxy { to });
    }

    None
}

#[rustler::nif(schedule = "DirtyIo")]
fn get_certificate(env: rustler::Env<'_>, dev: ResourceArc<Device>, name: &str) -> impl Encoder {
    let dev = dev.inner.clone();
    let name = name.to_owned();

    // Fail-closed: always `{:error, reason}` until ACME issuance lands (CertError::Unimplemented).
    match TOKIO_RUNTIME.block_on(async move { dev.get_certificate(&name).await }) {
        Ok(_cert) => (atoms::ok(), atoms::ok()).encode(env),
        Err(e) => (atoms::error(), e.to_string()).encode(env),
    }
}

#[rustler::nif(schedule = "DirtyIo")]
fn listen_tls(env: rustler::Env<'_>, dev: ResourceArc<Device>, config: Term) -> impl Encoder {
    let dev = dev.inner.clone();
    let Some(cfg) = serve_config_from_erl(config) else {
        return env.error_tuple("invalid serve config");
    };

    // Fail-closed: always `{:error, reason}` until ACME issuance lands (CertError::Unimplemented).
    match TOKIO_RUNTIME.block_on(async move { dev.listen_tls(&cfg).await }) {
        Ok(_acceptor) => (atoms::ok(), atoms::ok()).encode(env),
        Err(e) => (atoms::error(), e.to_string()).encode(env),
    }
}
