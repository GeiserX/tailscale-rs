//! Newer `Device` surface for tsnet parity: identity tokens, metrics, key-expiry, Taildrop
//! (waiting/delete/save/send), debug pcap capture, the SOCKS5 loopback proxy, and the Tailnet
//! Lock (TKA) status.
//!
//! Each NIF mirrors the crate-level idiom in [`crate`]: a [`ResourceArc<Device>`] is cloned, the
//! async `Device` method is driven via [`TOKIO_RUNTIME`]`.block_on`, and the result is encoded as
//! an `{:ok, _}` / `{:error, reason}` tuple. NIFs that touch the filesystem or the network run on
//! the `DirtyIo` scheduler.
//!
//! Two surfaces could not be handed back to the BEAM directly and are adapted:
//! - Taildrop *save* takes a destination path and copies the received file there, because a NIF
//!   cannot hand a `std::fs::File` back to Elixir.
//! - Taildrop *send* opens a local `src_path` as a tokio file and streams it; the peer is resolved
//!   via [`tailscale::Device::peer_by_name`].
//! - `capture_pcap` opens `dst_path` as a `std::fs::File` and writes the pcap there.

use std::sync::Mutex;

use rustler::{Encoder, ResourceArc};

use crate::{Device, TOKIO_RUNTIME, atoms};

/// Resource wrapping the SOCKS5 loopback proxy handle. Dropping the inner [`tailscale::LoopbackHandle`]
/// stops the proxy listener, so [`loopback_stop`] takes the handle out of the `Mutex` and drops it.
pub(crate) struct LoopbackHandleResource {
    inner: Mutex<Option<tailscale::LoopbackHandle>>,
}

#[rustler::resource_impl]
impl rustler::Resource for LoopbackHandleResource {}

/// A waiting (fully-received) Taildrop file, surfaced as `%Tailscale.WaitingFile{name, size}`.
#[derive(rustler::NifStruct)]
#[module = "Tailscale.WaitingFile"]
struct WaitingFile {
    name: String,
    size: u64,
}

impl From<tailscale::WaitingFile> for WaitingFile {
    fn from(value: tailscale::WaitingFile) -> Self {
        Self {
            name: value.name,
            size: value.size,
        }
    }
}

/// The control-pushed Tailnet Lock status, surfaced as `%Tailscale.TkaStatus{head, disabled}`.
#[derive(rustler::NifStruct)]
#[module = "Tailscale.TkaStatus"]
struct TkaStatus {
    head: String,
    disabled: bool,
}

/// Fetch an OIDC ID token (a signed JWT) for this node scoped to `audience`.
#[rustler::nif(schedule = "DirtyIo")]
fn fetch_id_token(env: rustler::Env<'_>, dev: ResourceArc<Device>, audience: &str) -> impl Encoder {
    let dev = dev.inner.clone();
    let audience = audience.to_owned();

    match TOKIO_RUNTIME.block_on(async move { dev.fetch_id_token(&audience).await }) {
        Ok(token) => (atoms::ok(), token).encode(env),
        Err(e) => (atoms::error(), e.to_string()).encode(env),
    }
}

/// Snapshot this process's client metrics in Prometheus text exposition format. The registry is
/// process-global, so this is synchronous and infallible.
#[rustler::nif]
fn metrics(dev: ResourceArc<Device>) -> String {
    dev.inner.metrics()
}

/// This node's key-expiry instant as Unix seconds, or `{:ok, nil}` if the key never expires.
#[rustler::nif(schedule = "DirtyIo")]
fn self_key_expiry_unix(env: rustler::Env<'_>, dev: ResourceArc<Device>) -> impl Encoder {
    let dev = dev.inner.clone();

    match TOKIO_RUNTIME.block_on(async move { dev.self_key_expiry_unix().await }) {
        Ok(expiry) => (atoms::ok(), expiry).encode(env),
        Err(e) => (atoms::error(), e.to_string()).encode(env),
    }
}

/// Whether this node's key has expired as of now.
#[rustler::nif(schedule = "DirtyIo")]
fn self_key_expired(env: rustler::Env<'_>, dev: ResourceArc<Device>) -> impl Encoder {
    let dev = dev.inner.clone();

    match TOKIO_RUNTIME.block_on(async move { dev.self_key_expired().await }) {
        Ok(expired) => (atoms::ok(), expired).encode(env),
        Err(e) => (atoms::error(), e.to_string()).encode(env),
    }
}

/// List the Taildrop files this device has fully received and not yet consumed.
#[rustler::nif(schedule = "DirtyIo")]
fn taildrop_waiting_files(env: rustler::Env<'_>, dev: ResourceArc<Device>) -> impl Encoder {
    match dev.inner.taildrop_waiting_files() {
        Ok(files) => (
            atoms::ok(),
            files.into_iter().map(WaitingFile::from).collect::<Vec<_>>(),
        )
            .encode(env),
        Err(e) => (atoms::error(), e.to_string()).encode(env),
    }
}

/// Delete a received Taildrop file by name.
#[rustler::nif(schedule = "DirtyIo")]
fn taildrop_delete_file(
    env: rustler::Env<'_>,
    dev: ResourceArc<Device>,
    name: &str,
) -> impl Encoder {
    match dev.inner.taildrop_delete_file(name) {
        Ok(()) => (atoms::ok(), atoms::ok()).encode(env),
        Err(e) => (atoms::error(), e.to_string()).encode(env),
    }
}

/// Save a received Taildrop file to `dst_path` by copying it there (a NIF can't hand a
/// `std::fs::File` back to Elixir). Returns the number of bytes copied.
#[rustler::nif(schedule = "DirtyIo")]
fn taildrop_save_file(
    env: rustler::Env<'_>,
    dev: ResourceArc<Device>,
    name: &str,
    dst_path: &str,
) -> impl Encoder {
    let result = (|| {
        let (mut src, _size) = dev
            .inner
            .taildrop_open_file(name)
            .map_err(|e| e.to_string())?;
        let mut dst = std::fs::File::create(dst_path).map_err(|e| e.to_string())?;
        std::io::copy(&mut src, &mut dst).map_err(|e| e.to_string())
    })();

    match result {
        Ok(n) => (atoms::ok(), n).encode(env),
        Err(e) => (atoms::error(), e).encode(env),
    }
}

/// Send a local file at `src_path` to `peer_name` via Taildrop. The peer is resolved with
/// [`tailscale::Device::peer_by_name`]; the file is opened as a tokio file and streamed.
#[rustler::nif(schedule = "DirtyIo")]
fn taildrop_send_file(
    env: rustler::Env<'_>,
    dev: ResourceArc<Device>,
    peer_name: &str,
    file_name: &str,
    src_path: &str,
) -> impl Encoder {
    let dev = dev.inner.clone();
    let peer_name = peer_name.to_owned();
    let file_name = file_name.to_owned();
    let src_path = src_path.to_owned();

    let result = TOKIO_RUNTIME.block_on(async move {
        let peer = dev
            .peer_by_name(&peer_name)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "no such peer".to_string())?;
        let file = tokio::fs::File::open(&src_path)
            .await
            .map_err(|e| e.to_string())?;
        let len = file.metadata().await.map_err(|e| e.to_string())?.len();
        dev.send_file(&peer, &file_name, len, file)
            .await
            .map_err(|e| e.to_string())
    });

    match result {
        Ok(()) => (atoms::ok(), atoms::ok()).encode(env),
        Err(e) => (atoms::error(), e).encode(env),
    }
}

/// Begin a debug packet capture, writing a pcap of every dataplane packet to `dst_path`.
#[rustler::nif(schedule = "DirtyIo")]
fn capture_pcap(env: rustler::Env<'_>, dev: ResourceArc<Device>, dst_path: &str) -> impl Encoder {
    let dev = dev.inner.clone();
    let dst_path = dst_path.to_owned();

    let result = TOKIO_RUNTIME.block_on(async move {
        let file = std::fs::File::create(&dst_path).map_err(|e| e.to_string())?;
        dev.capture_pcap(file).await.map_err(|e| e.to_string())
    });

    match result {
        Ok(()) => (atoms::ok(), atoms::ok()).encode(env),
        Err(e) => (atoms::error(), e).encode(env),
    }
}

/// Stop a debug packet capture started by [`capture_pcap`]. Idempotent.
#[rustler::nif(schedule = "DirtyIo")]
fn stop_capture(env: rustler::Env<'_>, dev: ResourceArc<Device>) -> impl Encoder {
    let dev = dev.inner.clone();

    match TOKIO_RUNTIME.block_on(async move { dev.stop_capture().await }) {
        Ok(()) => (atoms::ok(), atoms::ok()).encode(env),
        Err(e) => (atoms::error(), e.to_string()).encode(env),
    }
}

/// Start the SOCKS5 loopback proxy, returning `{:ok, {addr, cred, handle}}` where `addr` is a
/// `{ip, port}` tuple, `cred` is the proxy password, and `handle` is a [`LoopbackHandleResource`]
/// whose drop (via [`loopback_stop`] or GC) stops the listener.
#[rustler::nif(schedule = "DirtyIo")]
fn loopback(env: rustler::Env<'_>, dev: ResourceArc<Device>) -> impl Encoder {
    let dev = dev.inner.clone();

    match TOKIO_RUNTIME.block_on(async move { dev.loopback().await }) {
        Ok((addr, cred, handle)) => {
            let handle = ResourceArc::new(LoopbackHandleResource {
                inner: Mutex::new(Some(handle)),
            });
            (
                atoms::ok(),
                (crate::sockaddr_to_erl(env, addr), cred, handle),
            )
                .encode(env)
        }
        Err(e) => (atoms::error(), e.to_string()).encode(env),
    }
}

/// Stop a loopback proxy by taking its handle out of the resource and dropping it. Idempotent: a
/// second call (or a call after GC) is a no-op.
#[rustler::nif]
fn loopback_stop(
    env: rustler::Env<'_>,
    handle: ResourceArc<LoopbackHandleResource>,
) -> impl Encoder {
    if let Ok(mut guard) = handle.inner.lock() {
        guard.take();
    }
    atoms::ok().encode(env)
}

/// Fetch the current Tailnet Lock (TKA) status, or `{:ok, nil}` if control has sent none.
#[rustler::nif(schedule = "DirtyIo")]
fn tka_status(env: rustler::Env<'_>, dev: ResourceArc<Device>) -> impl Encoder {
    let dev = dev.inner.clone();

    match TOKIO_RUNTIME.block_on(async move { dev.tka_status().await }) {
        Ok(None) => (atoms::ok(), Option::<()>::None).encode(env),
        Ok(Some(status)) => (
            atoms::ok(),
            TkaStatus {
                head: status.head,
                disabled: status.disabled,
            },
        )
            .encode(env),
        Err(e) => (atoms::error(), e.to_string()).encode(env),
    }
}
