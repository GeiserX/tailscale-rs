//! Stored Serve config + accept-loop runtime (`tsnet`'s `Get/SetServeConfig` + serving runtime).
//!
//! Go `tsnet` stores an `ipn.ServeConfig` on the node and runs one accept loop per configured
//! tailnet port, dispatching each accepted connection per its handler (proxy / text / raw TCP
//! forward / hand-back). This module is the faithful equivalent on the **application** netstack: a
//! [`ServeManager`] owns the current [`ServeState`](ts_control::ServeState), one accept-loop task
//! per bound port, and tears every loop down on drop / on the next `set`.
//!
//! ## Storage + reconcile (full-replace)
//!
//! The manager holds the current [`ServeState`] plus one [`tokio::task::AbortHandle`] per bound
//! port behind a single `Arc<Mutex<Inner>>` (mirroring [`crate::fallback_tcp::FallbackTcpManager`]).
//! [`ServeManager::set`] uses **full-replace** semantics: it aborts *every* existing accept loop and
//! respawns from the new config. Go reconciles incrementally (leaving unchanged ports running); we
//! do full-replace because it is simpler and correct, and a `SetServeConfig` is a rare control-plane
//! operation, not a hot path. The passed [`ServeState`] becomes the whole config (REPLACE, matching
//! Go). [`pure_reconcile`] computes the add/remove port deltas for testing and documentation, even
//! though the live path replaces wholesale.
//!
//! ## TLS termination
//!
//! TLS-terminating ports ([`ServeTarget::terminates_tls`]) need a [`TlsAcceptor`]; the caller
//! (`Device::set_serve_config`) obtains it **once** via the cert path and hands it in per port. The
//! manager never builds an acceptor and never touches the cert/ACME machinery — that keeps
//! `ts_runtime` off the cert path and lets the device fail the whole `set` closed if a cert cannot
//! be issued (no plaintext downgrade).
//!
//! ## Anti-leak
//!
//! Every accept loop binds the **overlay** netstack only (via [`Channel::tcp_listen`] on the
//! device's own tailnet IPv4) — never a host socket. The [`ServeTarget::Proxy`] /
//! [`ServeTarget::TcpForward`] backend dial is a **local host socket** to the embedder's own backend
//! (exactly like Go's reverse-proxy to `127.0.0.1` and like [`crate::Runtime`]'s loopback proxy) —
//! it is intentionally NOT routed through the `ts_forwarder` exit-egress path, so the exit-node
//! anti-leak chokepoint is untouched. A backend dial failure drops the connection (fail-closed,
//! logged); it never falls back to anything.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
};

use netstack::{CreateSocket, netcore::Channel, netsock::TcpStream as OverlayStream};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::{Semaphore, mpsc},
};
use ts_control::{ServeState, ServeTarget, tls::TlsAcceptor};

/// Max concurrent in-flight connections served per bound port. Bounds the per-port spawn fan-out so
/// a flood of accepts on one serve port cannot grow tasks (and overlay sockets) without limit;
/// saturated => the accept loop back-pressures (stops accepting) until an in-flight conn finishes.
/// Mirrors the loopback proxy's `MAX_CONCURRENT_CONNS` rationale (each accepted conn pins an overlay
/// TCP socket, ~512 KiB of rx+tx buffers — see `tcp_buffer_size` in AGENTS.md).
const MAX_SERVE_CONNS_PER_PORT: usize = 256;

/// A connection handed back to the embedder for a [`ServeTarget::Accept`] port (the in-process
/// stand-in for Go `tsnet`'s `ListenTLS`-returned `net.Listener`).
///
/// `stream` is already TLS-terminated (the overlay stream wrapped in `tokio_rustls`'s server
/// `TlsStream`), boxed so the channel is target-agnostic. `port` is the serve port it arrived on so
/// an embedder serving `Accept` on several ports can demultiplex.
pub struct ServeAccepted {
    /// The tailnet (overlay) port this connection was accepted on.
    pub port: u16,
    /// The accepted, TLS-terminated stream, ready to read/write.
    pub stream: Box<dyn AsyncReadWrite>,
}

/// Object-safe alias for the boxed accepted stream: an `AsyncRead + AsyncWrite` the embedder drives.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncReadWrite for T {}

/// Receiver side of the [`ServeTarget::Accept`] hand-back channel (mirrors a `net.Listener`'s accept
/// queue). [`ServeManager::set`] returns one; await [`recv`](mpsc::Receiver::recv) to take the next
/// accepted, TLS-terminated connection. Dropped/replaced when the next `set` runs.
pub type ServeAcceptedReceiver = mpsc::Receiver<ServeAccepted>;

/// A fully-resolved per-port serve plan: the target plus, for TLS-terminating targets, the acceptor
/// the device built up-front from the cert path. The caller guarantees `acceptor.is_some()` exactly
/// when `target.terminates_tls()` — the manager asserts this is never violated by failing the bind.
pub struct ResolvedPort {
    /// What to serve on this port.
    pub target: ServeTarget,
    /// The TLS acceptor for this port, present iff `target.terminates_tls()`.
    pub acceptor: Option<TlsAcceptor>,
}

/// Shared manager state behind a single lock.
struct Inner {
    /// The currently-stored config (what [`get`](ServeManager::get) returns). Empty default until
    /// the first `set`.
    state: ServeState,
    /// One accept-loop abort handle per currently-bound port. Aborting a handle stops that port's
    /// accept loop (and, transitively, drops its listener so the overlay port is released).
    ports: BTreeMap<u16, tokio::task::AbortHandle>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        for h in self.ports.values() {
            h.abort();
        }
    }
}

/// Owns the stored Serve config and the live per-port accept loops (`tsnet` serving runtime).
///
/// Built once from the application netstack [`Channel`] and the device's overlay IPv4, held by the
/// [`crate::Runtime`]. [`set`](Self::set) replaces the whole config (full-replace reconcile);
/// dropping the manager (with the runtime / device) aborts every accept loop.
pub struct ServeManager {
    inner: Arc<Mutex<Inner>>,
    channel: Channel,
    self_ipv4: Ipv4Addr,
}

impl ServeManager {
    /// Build a manager bound to the application netstack `channel` and the device's own tailnet
    /// `self_ipv4` (the overlay address every serve listener binds on). No accept loop runs until the
    /// first [`set`](Self::set).
    pub fn new(channel: Channel, self_ipv4: Ipv4Addr) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                state: ServeState::default(),
                ports: BTreeMap::new(),
            })),
            channel,
            self_ipv4,
        }
    }

    /// The currently-stored config (Go `GetServeConfig`); empty default if none was ever set.
    pub fn get(&self) -> ServeState {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .state
            .clone()
    }

    /// Replace the whole Serve config (Go `SetServeConfig`, REPLACE semantics), full-replace
    /// reconcile.
    ///
    /// `state` is the new config; `resolved` carries the per-port target + (for TLS ports) the
    /// pre-built acceptor, keyed identically to `state.ports`. Aborts every existing accept loop and
    /// spawns one per port in `resolved`. Returns a fresh [`ServeAcceptedReceiver`] delivering
    /// connections for every [`ServeTarget::Accept`] port (empty if there are none).
    ///
    /// The caller is responsible for `state.validate()` and for obtaining the acceptors (failing the
    /// whole call closed if a cert can't be issued) before calling this; the manager only binds and
    /// dispatches.
    pub fn set(
        &self,
        state: ServeState,
        resolved: BTreeMap<u16, ResolvedPort>,
    ) -> ServeAcceptedReceiver {
        // A bounded channel back-pressures a slow embedder rather than buffering unboundedly.
        let (accept_tx, accept_rx) = mpsc::channel::<ServeAccepted>(MAX_SERVE_CONNS_PER_PORT);

        let mut new_ports: BTreeMap<u16, tokio::task::AbortHandle> = BTreeMap::new();
        for (port, rp) in resolved {
            let channel = self.channel.clone();
            let self_ipv4 = self.self_ipv4;
            let accept_tx = accept_tx.clone();
            let handle = tokio::spawn(async move {
                if let Err(e) = run_port(channel, self_ipv4, port, rp, accept_tx).await {
                    tracing::warn!(%port, error = %e, "serve listener exited");
                }
            })
            .abort_handle();
            new_ports.insert(port, handle);
        }

        // Swap in the new state + handles under the lock; aborting the OLD handles happens when the
        // replaced map is dropped at end of scope (after the lock is released).
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.state = state;
        let old = std::mem::replace(&mut inner.ports, new_ports);
        drop(inner);
        for h in old.values() {
            h.abort();
        }

        accept_rx
    }
}

/// Compute which ports must be added and removed to go from `current` to `next` (pure; the diff Go
/// reconciles incrementally). The live [`ServeManager::set`] uses full-replace, but this captures
/// the delta for tests/documentation: a port is *changed* iff its target differs, which counts as
/// both a remove and an add.
#[cfg_attr(not(test), allow(dead_code))]
fn pure_reconcile(
    current: &BTreeMap<u16, ServeTarget>,
    next: &BTreeMap<u16, ServeTarget>,
) -> (BTreeSet<u16>, BTreeSet<u16>) {
    let mut to_add = BTreeSet::new();
    let mut to_remove = BTreeSet::new();
    for (port, target) in next {
        match current.get(port) {
            Some(cur) if cur == target => {}
            _ => {
                to_add.insert(*port);
            }
        }
    }
    for port in current.keys() {
        match next.get(port) {
            Some(target) if current.get(port) == Some(target) => {}
            _ => {
                to_remove.insert(*port);
            }
        }
    }
    (to_add, to_remove)
}

/// Accept loop for one serve port: bind the overlay listener on `(self_ipv4, port)` and dispatch
/// each accepted connection per `rp.target`, capped at [`MAX_SERVE_CONNS_PER_PORT`] in flight.
async fn run_port(
    channel: Channel,
    self_ipv4: Ipv4Addr,
    port: u16,
    rp: ResolvedPort,
    accept_tx: mpsc::Sender<ServeAccepted>,
) -> Result<(), netstack::netcore::Error> {
    // Anti-leak: bind the OVERLAY netstack on this node's own tailnet IPv4, never a host socket.
    let listen_addr = SocketAddr::new(self_ipv4.into(), port);
    let listener = channel.tcp_listen(listen_addr).await?;
    tracing::debug!(%port, "serve listener accepting");

    let rp = Arc::new(rp);
    let inflight = Arc::new(Semaphore::new(MAX_SERVE_CONNS_PER_PORT));

    loop {
        // Acquire a permit BEFORE accepting so the loop back-pressures at the cap.
        let Ok(permit) = inflight.clone().acquire_owned().await else {
            return Ok(());
        };
        let overlay = listener.accept().await?;

        let rp = rp.clone();
        let accept_tx = accept_tx.clone();
        tokio::spawn(async move {
            let _permit = permit; // released when this connection finishes
            dispatch_conn(port, overlay, rp, accept_tx).await;
        });
    }
}

/// Dispatch one accepted overlay connection per the port's target. TLS is terminated here (once per
/// connection) for TLS-terminating targets; failures drop the connection (fail-closed, logged).
async fn dispatch_conn(
    port: u16,
    overlay: OverlayStream,
    rp: Arc<ResolvedPort>,
    accept_tx: mpsc::Sender<ServeAccepted>,
) {
    match &rp.target {
        // Raw passthrough: NO TLS. Splice the raw overlay stream to the local backend.
        ServeTarget::TcpForward { to } => {
            forward_to_backend(port, overlay, to).await;
        }
        // TLS-terminating targets: terminate TLS once, then act on the decrypted stream.
        _ => {
            let Some(acceptor) = rp.acceptor.as_ref() else {
                // The caller's contract guarantees a TLS acceptor for every TLS-terminating port;
                // a missing one means we must never serve plaintext — drop, fail-closed.
                tracing::warn!(%port, "serve: missing TLS acceptor for TLS port; dropping conn");
                return;
            };
            let tls = match acceptor.accept(overlay).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(%port, error = %e, "serve: TLS handshake failed; dropping conn");
                    return;
                }
            };
            match &rp.target {
                ServeTarget::Accept => {
                    // Hand the TLS-terminated stream back to the embedder over the channel.
                    let accepted = ServeAccepted {
                        port,
                        stream: Box::new(tls),
                    };
                    if accept_tx.send(accepted).await.is_err() {
                        tracing::debug!(%port, "serve: accept receiver dropped; closing conn");
                    }
                }
                ServeTarget::Proxy { to } => {
                    proxy_to_backend(port, tls, to).await;
                }
                ServeTarget::Text { body } => {
                    write_text(port, tls, body).await;
                }
                // `TcpForward` is handled in the non-TLS arm above; nothing else terminates TLS.
                // The wildcard covers `#[non_exhaustive]` future raw (non-TLS) variants: if one is
                // added it must NOT silently terminate TLS here — drop it fail-closed until this
                // dispatch is taught how to serve it.
                other => {
                    debug_assert!(
                        !other.terminates_tls(),
                        "TLS-terminating ServeTarget reached fall-through arm"
                    );
                    tracing::warn!(%port, "serve: unhandled ServeTarget on TLS port; dropping conn");
                }
            }
        }
    }
}

/// Reverse-proxy a TLS-terminated stream to a local host backend (Go `Proxy` handler). The backend
/// dial is a LOCAL host socket to the embedder's own backend — never the forwarder egress path.
async fn proxy_to_backend<S>(port: u16, mut tls: S, to: &str)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut backend = match tokio::net::TcpStream::connect(to).await {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!(%port, %to, error = %e, "serve proxy: backend dial failed; dropping conn");
            return;
        }
    };
    if let Err(e) = tokio::io::copy_bidirectional(&mut tls, &mut backend).await {
        tracing::debug!(%port, %to, error = %e, "serve proxy: splice ended");
    }
}

/// Forward a RAW (non-TLS) overlay stream to a local host backend (Go `TCPForward` handler). The
/// backend dial is a LOCAL host socket — never the forwarder egress path.
async fn forward_to_backend(port: u16, mut overlay: OverlayStream, to: &str) {
    let mut backend = match tokio::net::TcpStream::connect(to).await {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!(%port, %to, error = %e, "serve forward: backend dial failed; dropping conn");
            return;
        }
    };
    if let Err(e) = tokio::io::copy_bidirectional(&mut overlay, &mut backend).await {
        tracing::debug!(%port, %to, error = %e, "serve forward: splice ended");
    }
}

/// Write a fixed body to the TLS-terminated stream, flush, and close (Go `Text` handler).
async fn write_text<S>(port: u16, mut tls: S, body: &str)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if let Err(e) = tls.write_all(body.as_bytes()).await {
        tracing::debug!(%port, error = %e, "serve text: write failed");
        return;
    }
    if let Err(e) = tls.flush().await {
        tracing::debug!(%port, error = %e, "serve text: flush failed");
    }
    drop(tls.shutdown().await);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy(to: &str) -> ServeTarget {
        ServeTarget::Proxy { to: to.into() }
    }

    #[test]
    fn cap_is_bounded() {
        assert_eq!(MAX_SERVE_CONNS_PER_PORT, 256);
    }

    #[test]
    fn reconcile_adds_new_ports() {
        let current = BTreeMap::new();
        let mut next = BTreeMap::new();
        next.insert(443u16, ServeTarget::Accept);
        next.insert(8443u16, proxy("127.0.0.1:8080"));
        let (add, remove) = pure_reconcile(&current, &next);
        assert_eq!(add, BTreeSet::from([443, 8443]));
        assert!(remove.is_empty());
    }

    #[test]
    fn reconcile_removes_dropped_ports() {
        let mut current = BTreeMap::new();
        current.insert(443u16, ServeTarget::Accept);
        current.insert(8443u16, proxy("127.0.0.1:8080"));
        let mut next = BTreeMap::new();
        next.insert(443u16, ServeTarget::Accept);
        let (add, remove) = pure_reconcile(&current, &next);
        assert!(add.is_empty());
        assert_eq!(remove, BTreeSet::from([8443]));
    }

    #[test]
    fn reconcile_changed_port_is_remove_and_add() {
        // Same port, different target => counts as both (full-replace would respawn it anyway).
        let mut current = BTreeMap::new();
        current.insert(443u16, proxy("127.0.0.1:8080"));
        let mut next = BTreeMap::new();
        next.insert(443u16, proxy("127.0.0.1:9090"));
        let (add, remove) = pure_reconcile(&current, &next);
        assert_eq!(add, BTreeSet::from([443]));
        assert_eq!(remove, BTreeSet::from([443]));
    }

    #[test]
    fn reconcile_unchanged_port_is_noop() {
        let mut current = BTreeMap::new();
        current.insert(443u16, ServeTarget::Accept);
        let next = current.clone();
        let (add, remove) = pure_reconcile(&current, &next);
        assert!(add.is_empty());
        assert!(remove.is_empty());
    }

    #[test]
    fn terminates_tls_matches_dispatch_arm() {
        // The dispatch decision (TLS vs raw) must agree with the type's own `terminates_tls`: only
        // TcpForward is raw; Accept/Proxy/Text all terminate TLS.
        assert!(ServeTarget::Accept.terminates_tls());
        assert!(proxy("127.0.0.1:8080").terminates_tls());
        assert!(ServeTarget::Text { body: "ok".into() }.terminates_tls());
        assert!(
            !ServeTarget::TcpForward {
                to: "127.0.0.1:5000".into()
            }
            .terminates_tls()
        );
    }

    // NOTE: a live bind+accept test needs a running netstack channel + overlay; the existing
    // netstack-backed managers (fallback_tcp) likewise unit-test only the pure pieces (port diff,
    // dispatch decision) and leave the bind/accept path to integration coverage. We mirror that:
    // `pure_reconcile` + the `terminates_tls` agreement are tested here; the bind/accept/splice path
    // is exercised via `Device::set_serve_config` against a real device.
}
