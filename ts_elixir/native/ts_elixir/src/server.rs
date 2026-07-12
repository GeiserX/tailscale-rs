//! tsnet `Server` facade NIFs: the two surfaces the plain [`crate::Device`] NIFs do not expose —
//! the **dual-credential loopback** (Go `Loopback() (addr, proxyCred, localAPICred, err)`) and the
//! **LocalClient** handle (Go `LocalClient()`).
//!
//! Each NIF follows the crate-level idiom: a [`ResourceArc`] is driven via [`TOKIO_RUNTIME`]
//! `.block_on`, and the result is encoded as an `{:ok, _}` / `{:error, reason}` tuple. The wrapped
//! [`tailscale::tsnet::Server`] builds its node lazily on the first `server_loopback` /
//! `server_local_client` call, so `server_new` does no I/O and is not `DirtyIo`.
//!
//! Fork config supersets beyond Go `tsnet` parity (exit nodes, forwarding) stay on the `Device`
//! surface (`connect`); these NIFs expose the Go-parity `Server` fields.

use std::collections::HashMap;
use std::path::PathBuf;

use rustler::{Atom, Encoder, ResourceArc, Term};
use tailscale::tsnet;

use crate::TOKIO_RUNTIME;

mod atoms {
    rustler::atoms! {
        hostname,
        auth_key,
        control_url,
        ephemeral,
        dir,
        tags,
    }
}

/// Resource wrapping a lazily-started tsnet server (Go `tsnet.Server`). Dropping it (via GC) tears
/// down the loopback listeners and shuts the wrapped node down.
pub(crate) struct ServerResource {
    inner: tsnet::Server,
}

#[rustler::resource_impl]
impl rustler::Resource for ServerResource {}

/// Resource wrapping a LocalAPI HTTP client (Go `tsnet.Server.LocalClient()`).
pub(crate) struct LocalClientResource {
    inner: tsnet::LocalClient,
}

#[rustler::resource_impl]
impl rustler::Resource for LocalClientResource {}

/// Build a new tsnet server from a Go-`tsnet.Server`-parity option map (all keys optional):
/// `hostname`, `auth_key`, `control_url`, `ephemeral` (default `false`), `dir` (state directory
/// persisting identity keys across runs), and `tags`. No network I/O — the node is built on first
/// use. Returns `{:ok, server}`, or `{:error, reason}` if an option value has the wrong type.
#[rustler::nif]
fn server_new(env: rustler::Env<'_>, opts: HashMap<Atom, Term<'_>>) -> impl Encoder {
    match build_server(&opts) {
        Ok(s) => (
            crate::atoms::ok(),
            ResourceArc::new(ServerResource { inner: s }),
        )
            .encode(env),
        Err(reason) => (crate::atoms::error(), reason).encode(env),
    }
}

/// Map a Go-`tsnet.Server`-parity option map onto a [`tsnet::Server`]. A wrong-typed value yields a
/// human-readable reason string rather than a raised NIF error, matching the crate's `{:error, _}`
/// convention.
fn build_server(opts: &HashMap<Atom, Term<'_>>) -> Result<tsnet::Server, &'static str> {
    let mut s = tsnet::Server::new();

    if let Some(v) = opts.get(&atoms::hostname()) {
        s.hostname = Some(
            v.decode::<String>()
                .map_err(|_| "hostname must be a string")?,
        );
    }
    if let Some(v) = opts.get(&atoms::auth_key()) {
        s.auth_key = Some(
            v.decode::<String>()
                .map_err(|_| "auth_key must be a string")?,
        );
    }
    if let Some(v) = opts.get(&atoms::control_url()) {
        s.control_url = Some(
            v.decode::<String>()
                .map_err(|_| "control_url must be a string")?,
        );
    }
    if let Some(v) = opts.get(&atoms::ephemeral()) {
        s.ephemeral = v
            .decode::<bool>()
            .map_err(|_| "ephemeral must be a boolean")?;
    }
    if let Some(v) = opts.get(&atoms::dir()) {
        s.dir = Some(PathBuf::from(
            v.decode::<String>().map_err(|_| "dir must be a string")?,
        ));
    }
    if let Some(v) = opts.get(&atoms::tags()) {
        s.advertise_tags = v
            .decode::<Vec<String>>()
            .map_err(|_| "tags must be a list of strings")?;
    }

    Ok(s)
}

/// Start (once) the loopback surface, returning `{:ok, {socks_addr, proxy_cred, localapi_addr,
/// localapi_cred}}` (Go `Loopback() (addr, proxyCred, localAPICred, err)`), where each `*_addr` is
/// an `{ip, port}` tuple. Idempotent: the two `127.0.0.1` listeners live for the server's lifetime.
#[rustler::nif(schedule = "DirtyIo")]
fn server_loopback(env: rustler::Env<'_>, srv: ResourceArc<ServerResource>) -> impl Encoder {
    match TOKIO_RUNTIME.block_on(srv.inner.loopback()) {
        Ok(lb) => (
            crate::atoms::ok(),
            (
                crate::sockaddr_to_erl(env, lb.address),
                lb.proxy_cred,
                crate::sockaddr_to_erl(env, lb.local_api_address),
                lb.local_api_cred,
            ),
        )
            .encode(env),
        Err(e) => (crate::atoms::error(), e.to_string()).encode(env),
    }
}

/// Obtain a LocalClient for this node's in-process LocalAPI HTTP server (Go
/// `tsnet.Server.LocalClient()`), starting the loopback surface if needed. Returns `{:ok, client}`.
#[rustler::nif(schedule = "DirtyIo")]
fn server_local_client(env: rustler::Env<'_>, srv: ResourceArc<ServerResource>) -> impl Encoder {
    match TOKIO_RUNTIME.block_on(srv.inner.local_client()) {
        Ok(lc) => (
            crate::atoms::ok(),
            ResourceArc::new(LocalClientResource { inner: lc }),
        )
            .encode(env),
        Err(e) => (crate::atoms::error(), e.to_string()).encode(env),
    }
}

/// `GET /localapi/v0/status` over the loopback (Go `LocalClient().Status`): the node + peer status
/// as a JSON string. `{:error, _}` if the server answered non-`200`.
#[rustler::nif(schedule = "DirtyIo")]
fn local_client_status(
    env: rustler::Env<'_>,
    lc: ResourceArc<LocalClientResource>,
) -> impl Encoder {
    match TOKIO_RUNTIME.block_on(lc.inner.status()) {
        Ok(body) => (
            crate::atoms::ok(),
            String::from_utf8_lossy(&body).into_owned(),
        )
            .encode(env),
        Err(e) => (crate::atoms::error(), e.to_string()).encode(env),
    }
}

/// Perform an authenticated `GET` against an arbitrary LocalAPI `path`, returning `{:ok, {code,
/// body}}` where `body` is the response decoded as a UTF-8 string.
#[rustler::nif(schedule = "DirtyIo")]
fn local_client_get(
    env: rustler::Env<'_>,
    lc: ResourceArc<LocalClientResource>,
    path: &str,
) -> impl Encoder {
    match TOKIO_RUNTIME.block_on(lc.inner.get(path)) {
        Ok((code, body)) => (
            crate::atoms::ok(),
            (code, String::from_utf8_lossy(&body).into_owned()),
        )
            .encode(env),
        Err(e) => (crate::atoms::error(), e.to_string()).encode(env),
    }
}

/// The LocalAPI HTTP server address (`{ip, port}`) this client talks to.
#[rustler::nif]
fn local_client_address(
    env: rustler::Env<'_>,
    lc: ResourceArc<LocalClientResource>,
) -> impl Encoder {
    crate::sockaddr_to_erl(env, lc.inner.address())
}

/// The LocalAPI credential (HTTP Basic-auth password) this client sends.
#[rustler::nif]
fn local_client_credential(lc: ResourceArc<LocalClientResource>) -> String {
    lc.inner.credential().to_owned()
}
