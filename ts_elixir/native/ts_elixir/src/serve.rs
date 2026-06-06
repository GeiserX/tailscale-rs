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

        tcp,
        http,
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

/// Expose a tailnet TLS service to the public internet via Tailscale Funnel (mirrors `listen_tls`).
///
/// `funnel_only` maps to [`tailscale::FunnelOptions::funnel_only`]. Like [`listen_tls`], this is
/// **fail-closed**: the node-attribute/port gate is enforced first, then the node's `*.ts.net` cert
/// is obtained via the ACME-aware path (`Cert` error if unavailable — never a self-signed cert or
/// plaintext downgrade). On success the funnel ingress listener is registered and its
/// `FunnelAcceptedReceiver` is dropped here (the BEAM has no idiomatic place to hold it), so this NIF
/// surfaces only the gate/cert outcome; the public ingress relay that feeds it is Tailscale
/// infrastructure, present only against real Tailscale SaaS.
#[rustler::nif(schedule = "DirtyIo")]
fn listen_funnel(
    env: rustler::Env<'_>,
    dev: ResourceArc<Device>,
    config: Term,
    funnel_only: bool,
) -> impl Encoder {
    let dev = dev.inner.clone();
    let Some(cfg) = serve_config_from_erl(config) else {
        return env.error_tuple("invalid serve config");
    };
    let opts = ts_control::FunnelOptions { funnel_only };

    // On success `listen_funnel` returns a `FunnelAcceptedReceiver` delivering TLS-terminated public
    // connections; the BEAM has no idiomatic place to hold a Rust receiver (like the other Serve
    // NIFs), so we drop it and surface only the gate/cert outcome.
    match TOKIO_RUNTIME.block_on(async move { dev.listen_funnel(&cfg, opts).await }) {
        Ok(_receiver) => (atoms::ok(), atoms::ok()).encode(env),
        Err(e) => (atoms::error(), e.to_string()).encode(env),
    }
}

/// Host a Tailscale VIP service (`svc:<label>`) on its control-assigned VIP (mirrors `listen_tls`).
///
/// `mode` is a `{:tcp, port}` or `{:http, port}` tuple. **Fail-closed**: an invalid name, an
/// untagged host, or a missing control-assigned VIP all return a typed
/// [`tailscale::ServiceError`] before any listener is bound. On success the bound overlay listener
/// is created and immediately dropped — like the other Serve NIFs, the BEAM has no idiomatic place
/// to hold a Rust listener, so we surface the precondition outcome only.
#[rustler::nif(schedule = "DirtyIo")]
fn listen_service(
    env: rustler::Env<'_>,
    dev: ResourceArc<Device>,
    name: &str,
    mode: Term,
) -> impl Encoder {
    let dev = dev.inner.clone();
    let name = name.to_owned();
    let Some(mode) = service_mode_from_erl(mode) else {
        return env.error_tuple("invalid service mode");
    };

    match TOKIO_RUNTIME.block_on(async move { dev.listen_service(&name, mode).await }) {
        Ok(_listener) => (atoms::ok(), atoms::ok()).encode(env),
        Err(e) => (atoms::error(), e.to_string()).encode(env),
    }
}

/// Decode a `{:tcp, port}` / `{:http, port}` tuple into a [`tailscale::ServiceMode`].
fn service_mode_from_erl(term: Term) -> Option<tailscale::ServiceMode> {
    let tuple = rustler::types::tuple::get_tuple(term).ok()?;
    if tuple.len() != 2 {
        return None;
    }
    let tag = tuple[0].decode::<rustler::Atom>().ok()?;
    let port: u16 = tuple[1].decode().ok()?;

    if tag == atoms_serve::tcp() {
        Some(tailscale::ServiceMode::Tcp { port })
    } else if tag == atoms_serve::http() {
        Some(tailscale::ServiceMode::Http { port })
    } else {
        None
    }
}
