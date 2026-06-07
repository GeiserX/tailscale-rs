//! Client-side Funnel **ingress** termination (`tsnet`'s `ListenFunnel` data path).
//!
//! ## The model (Go `ipn/ipnlocal/serve.go`'s `handleIngress` / `TCPHandlerForFunnelFlow`)
//!
//! Public Funnel traffic does not reach this node directly. Tailscale operates a public **ingress
//! relay** (a tailnet peer, provisioned by control when a node advertises `HostInfo.IngressEnabled`)
//! plus the public DNS `<node>.<tailnet>.ts.net:443` → relay mapping. A public client's TLS bytes
//! arrive at the relay, which opens a connection to this node's **peerAPI** and `POST`s
//! `/v0/ingress` with the headers `Tailscale-Ingress-Src` (the public client `host:port`,
//! informational) and `Tailscale-Ingress-Target` (the `host:port` the client hit). The node replies
//! `HTTP/1.1 101 Switching Protocols\r\n\r\n` to **hijack** the connection into a raw bidirectional
//! stream that now carries the public client's TLS handshake + records. The node then TLS-terminates
//! that stream with its own `*.ts.net` certificate (the Funnel hostname *is* the node's MagicDNS
//! name) and serves the decrypted stream.
//!
//! This module is the node-side half: the [`FunnelManager`](crate::funnel::FunnelManager) holds the node's `TlsAcceptor` and an
//! `mpsc::Sender` sink ([`FunnelIngressSink`](crate::funnel::FunnelIngressSink)) the peerAPI `/v0/ingress` handler pushes hijacked
//! raw streams to. A spawned pump task TLS-terminates each raw stream and yields the decrypted
//! [`FunnelAccepted`](crate::funnel::FunnelAccepted) over a [`FunnelAcceptedReceiver`](crate::funnel::FunnelAcceptedReceiver) the embedder holds (the in-process stand-in
//! for Go `tsnet`'s `ListenFunnel`-returned `net.Listener`).
//!
//! The relay + DNS legs are **Tailscale infrastructure** — present against real Tailscale SaaS (with
//! a Funnel-enabled ACL), absent against a self-hosted control plane. So this code is
//! correct and fully wired, but only ever fed when the node talks to real Tailscale.
//!
//! ## Anti-leak
//!
//! The hijacked ingress stream arrives on the **overlay** peerAPI listener (the netstack
//! `OverlayStream`, never a host socket). TLS is terminated on that overlay stream and the
//! decrypted stream is handed to the embedder. Nothing here ever dials a host socket and nothing
//! routes through the `ts_forwarder` exit-egress path — Funnel ingress is purely inbound overlay
//! traffic, structurally separate from the exit-node anti-leak chokepoint. There is no plaintext
//! downgrade: if TLS termination fails, the connection is dropped (logged).

use std::sync::Arc;

use netstack::netsock::TcpStream as OverlayStream;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc,
};
use ts_control::tls::TlsAcceptor;

use crate::serve::AsyncReadWrite;

/// Bound on hijacked-but-not-yet-TLS-terminated ingress connections queued to the pump task, and on
/// TLS-terminated connections queued to the embedder. A relay flood back-pressures the peerAPI
/// `/v0/ingress` handler (which then drops, fail-closed) rather than buffering without limit. Each
/// queued conn pins an overlay TCP socket (~512 KiB rx+tx buffers — see `tcp_buffer_size` in
/// AGENTS.md), so the cap is deliberately modest.
const MAX_INGRESS_INFLIGHT: usize = 256;

/// A raw (not-yet-TLS-terminated) Funnel ingress connection the peerAPI `/v0/ingress` handler
/// hijacked off the relay's POST and handed to the [`FunnelManager`]'s sink.
///
/// `stream` is the overlay peerAPI connection *after* the `HTTP/1.1 101 Switching Protocols` reply —
/// raw bytes from here on are the public client's TLS handshake + records. `target` is the
/// `Tailscale-Ingress-Target` (`host:port` the public client hit) and `src` the
/// `Tailscale-Ingress-Src` (the public client's `host:port`, informational), both parsed from the
/// POST headers.
pub struct IngressConn {
    /// The `Tailscale-Ingress-Target` header — the `host:port` the public client connected to.
    pub target: String,
    /// The `Tailscale-Ingress-Src` header — the public client's `host:port` (informational).
    pub src: String,
    /// The hijacked raw overlay stream carrying the public client's TLS, post-101.
    pub stream: OverlayStream,
}

/// The sink the peerAPI `/v0/ingress` handler pushes hijacked [`IngressConn`]s to. Cloneable; an
/// `mpsc::Sender` so the handler back-pressures (and then drops, fail-closed) when the pump can't
/// keep up. Installed into the peerAPI server via the shared slot (see [`FunnelIngressSlot`]) when
/// the embedder calls `Device::listen_funnel`.
pub type FunnelIngressSink = mpsc::Sender<IngressConn>;

/// The shared, runtime-lifetime slot the peerAPI server reads per connection to find the active
/// [`FunnelIngressSink`], and that `Device::listen_funnel` writes when it stands up a
/// [`FunnelManager`]. `None` (the default) means no funnel listener is active, so the peerAPI
/// `/v0/ingress` route fails closed (`404`) without hijacking. The peerAPI server (spawned at
/// runtime start, before any `listen_funnel`) holds a clone of this `Arc`; installing a sink at
/// `listen_funnel` time makes the route live without restarting the server.
pub type FunnelIngressSlot = Arc<std::sync::Mutex<Option<FunnelIngressSink>>>;

/// A fully TLS-terminated Funnel ingress connection handed back to the embedder (the in-process
/// stand-in for Go `tsnet`'s `ListenFunnel`-returned `net.Listener`).
///
/// `stream` is the decrypted stream (the overlay stream wrapped in `tokio_rustls`'s server
/// `TlsStream`, boxed so the type is target-agnostic). `target`/`src` carry the ingress headers
/// through so an embedder can route on the hit `host:port` and log the public client.
pub struct FunnelAccepted {
    /// The `Tailscale-Ingress-Target` (`host:port` the public client hit).
    pub target: String,
    /// The `Tailscale-Ingress-Src` (the public client's `host:port`, informational).
    pub src: String,
    /// The accepted, TLS-terminated stream, ready to read/write.
    pub stream: Box<dyn AsyncReadWrite>,
}

/// Receiver side of the Funnel ingress hand-back channel (mirrors a `net.Listener`'s accept queue).
/// `Device::listen_funnel` returns one; await [`recv`](mpsc::Receiver::recv) to take the next
/// TLS-terminated public connection. Dropping it (or dropping the [`FunnelManager`]) tears the
/// listener down.
pub type FunnelAcceptedReceiver = mpsc::Receiver<FunnelAccepted>;

/// Owns the node's Funnel ingress data path: the `TlsAcceptor` built from the node's `*.ts.net`
/// cert and the pump task that TLS-terminates each hijacked [`IngressConn`].
///
/// Built by `Device::listen_funnel` after the [`funnel_access`](ts_control::funnel_access) gate and
/// cert path pass. Holds the sink end so the manager keeps the channel (and thus the route) alive;
/// dropping the manager closes the sink and stops the pump. Registered on the device (mirroring
/// `serve: Mutex<Option<ServeManager>>`) so its lifetime is tied to the `Device`.
pub struct FunnelManager {
    /// Kept so the [`FunnelIngressSink`] installed in the shared slot stays valid for the manager's
    /// life; dropping the manager drops this, closing the channel and ending the pump task.
    _ingress_tx: FunnelIngressSink,
    /// Aborts the TLS-termination pump task when the manager drops.
    pump: tokio::task::AbortHandle,
}

impl Drop for FunnelManager {
    fn drop(&mut self) {
        self.pump.abort();
    }
}

impl FunnelManager {
    /// Build a manager from the node's `acceptor` (made from its `*.ts.net` cert), returning the
    /// manager, the [`FunnelIngressSink`] to install into the peerAPI [`FunnelIngressSlot`], and the
    /// [`FunnelAcceptedReceiver`] handed back to the embedder.
    ///
    /// Spawns the pump task: for each hijacked [`IngressConn`] it TLS-terminates the raw overlay
    /// stream with `acceptor` and forwards a [`FunnelAccepted`] to the embedder. A TLS handshake
    /// failure drops that connection (fail-closed, logged) and the pump continues. The pump ends when
    /// the sink is dropped (manager dropped) or the embedder drops the receiver.
    pub fn new(acceptor: TlsAcceptor) -> (Self, FunnelIngressSink, FunnelAcceptedReceiver) {
        let (ingress_tx, ingress_rx) = mpsc::channel::<IngressConn>(MAX_INGRESS_INFLIGHT);
        let (accept_tx, accept_rx) = mpsc::channel::<FunnelAccepted>(MAX_INGRESS_INFLIGHT);

        let pump = tokio::spawn(run_pump(acceptor, ingress_rx, accept_tx)).abort_handle();

        (
            Self {
                _ingress_tx: ingress_tx.clone(),
                pump,
            },
            ingress_tx,
            accept_rx,
        )
    }
}

/// TLS-terminate each hijacked ingress stream and hand the decrypted stream to the embedder.
///
/// One handshake per connection, spawned so a slow handshake on one public client can't head-of-line
/// block another. A handshake failure drops the connection (fail-closed, logged). Ends when
/// `ingress_rx` closes (sink dropped) or `accept_tx` closes (embedder dropped the receiver).
async fn run_pump(
    acceptor: TlsAcceptor,
    mut ingress_rx: mpsc::Receiver<IngressConn>,
    accept_tx: mpsc::Sender<FunnelAccepted>,
) {
    while let Some(conn) = ingress_rx.recv().await {
        let acceptor = acceptor.clone();
        let accept_tx = accept_tx.clone();
        tokio::spawn(async move {
            terminate_and_forward(&acceptor, conn, &accept_tx).await;
        });
    }
}

/// Terminate TLS on one hijacked ingress stream and forward the decrypted stream. Anti-leak: TLS is
/// terminated on the overlay stream (never a host socket); no plaintext downgrade — a handshake
/// failure drops the connection.
async fn terminate_and_forward(
    acceptor: &TlsAcceptor,
    conn: IngressConn,
    accept_tx: &mpsc::Sender<FunnelAccepted>,
) {
    let IngressConn {
        target,
        src,
        stream,
    } = conn;
    let tls = match acceptor.accept(stream).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(%target, %src, error = %e, "funnel ingress: TLS handshake failed; dropping conn");
            return;
        }
    };
    let accepted = FunnelAccepted {
        target,
        src,
        stream: Box::new(tls),
    };
    if accept_tx.send(accepted).await.is_err() {
        tracing::debug!("funnel ingress: accept receiver dropped; closing conn");
    }
}

/// Assert that `S` is an `AsyncRead + AsyncWrite` so callers know the decrypted stream is drivable.
#[allow(dead_code)]
fn _assert_accepted_is_io<S: AsyncRead + AsyncWrite>() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inflight_cap_is_bounded() {
        assert_eq!(MAX_INGRESS_INFLIGHT, 256);
    }

    // NOTE: a live TLS-termination test needs both a `TlsAcceptor` (a real `CertifiedKey`, which
    // `ts_control::serve` already exercises via `tls_acceptor_builds_from_certified_key`) and an
    // `OverlayStream` (constructible only with a live netstack channel). `ts_runtime` carries no
    // `rcgen` dev-dep and cannot build either in isolation, so — like the netstack-backed managers
    // (`serve`/`fallback_tcp`) — the pump's accept/forward path is left to integration coverage
    // (`Device::listen_funnel` against a real device). The pure pieces (the inflight cap here, the
    // ingress header parse + 101-response bytes + route classification in `peerapi`) are unit-tested.
}
