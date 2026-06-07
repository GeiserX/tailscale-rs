//! Stored Serve config + accept-loop runtime (`tsnet`'s `Get/SetServeConfig` + serving runtime).
//!
//! Go `tsnet` stores an `ipn.ServeConfig` on the node and runs one accept loop per configured
//! tailnet port, dispatching each accepted connection per its handler (proxy / text / raw TCP
//! forward / hand-back). This module is the faithful equivalent on the **application** netstack: a
//! [`ServeManager`](crate::serve::ServeManager) owns the current [`ServeState`](ts_control::ServeState), one accept-loop task
//! per bound port, and tears every loop down on drop / on the next `set`.
//!
//! ## Storage + reconcile (full-replace)
//!
//! The manager holds the current [`ServeState`](ts_control::ServeState) plus one [`tokio::task::AbortHandle`] per bound
//! port behind a single `Arc<Mutex<Inner>>` (mirroring [`crate::fallback_tcp::FallbackTcpManager`]).
//! [`ServeManager::set`](crate::serve::ServeManager::set) uses **full-replace** semantics: it aborts *every* existing accept loop and
//! respawns from the new config. Go reconciles incrementally (leaving unchanged ports running); we
//! do full-replace because it is simpler and correct, and a `SetServeConfig` is a rare control-plane
//! operation, not a hot path. The passed [`ServeState`](ts_control::ServeState) becomes the whole config (REPLACE, matching
//! Go). `pure_reconcile` computes the add/remove port deltas for testing and documentation, even
//! though the live path replaces wholesale.
//!
//! ## TLS termination
//!
//! TLS-terminating ports (`ServeTarget::terminates_tls`) need a `TlsAcceptor`; the caller
//! (`Device::set_serve_config`) obtains it **once** via the cert path and hands it in per port. The
//! manager never builds an acceptor and never touches the cert/ACME machinery — that keeps
//! `ts_runtime` off the cert path and lets the device fail the whole `set` closed if a cert cannot
//! be issued (no plaintext downgrade).
//!
//! ## Anti-leak
//!
//! Every accept loop binds the **overlay** netstack only (via `Channel::tcp_listen` on the
//! device's own tailnet IPv4) — never a host socket. The `ServeTarget::Proxy` /
//! `ServeTarget::TcpForward` backend dial is a **local host socket** to the embedder's own backend
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
                // Reached DIRECTLY (no request head consumed off `tls`): a plain splice with no
                // prefix replay — the backend sees the client's bytes verbatim.
                ServeTarget::Proxy { to } => {
                    proxy_to_backend(port, tls, to).await;
                }
                ServeTarget::Text { body } => {
                    write_text(port, tls, body).await;
                }
                ServeTarget::Redirect { to, status } => {
                    serve_redirect(port, tls, to, *status).await;
                }
                ServeTarget::Path { handlers } => {
                    serve_path(port, tls, handlers).await;
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
///
/// Reached DIRECTLY from [`dispatch_conn`] (no request head has been consumed off `tls`), so no
/// prefix replay is needed — the backend sees the client's bytes verbatim via the bidirectional
/// splice. The `Path`-nested case (where a head WAS consumed) uses [`proxy_to_backend_with_prefix`]
/// instead.
async fn proxy_to_backend<S>(port: u16, tls: S, to: &str)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    proxy_to_backend_with_prefix(port, tls, to, &[]).await;
}

/// Reverse-proxy a TLS-terminated stream to a local host backend, writing `prefix` to the backend
/// FIRST (before the bidirectional splice). This replays an HTTP request head already consumed off
/// `tls` (e.g. by [`serve_path`]'s [`read_http_head`]) so the backend sees the complete request: the
/// consumed request line + headers, then the rest of the body/stream via the splice. An empty
/// `prefix` is equivalent to a plain splice ([`proxy_to_backend`]). The backend dial is a LOCAL host
/// socket — never the forwarder egress path; any failure (dial or prefix write) drops the conn
/// fail-closed.
async fn proxy_to_backend_with_prefix<S>(port: u16, mut tls: S, to: &str, prefix: &[u8])
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
    if !prefix.is_empty()
        && let Err(e) = backend.write_all(prefix).await
    {
        tracing::debug!(%port, %to, error = %e, "serve proxy: prefix replay failed; dropping conn");
        return;
    }
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

/// Max bytes of an HTTP request head (request line + headers) we will buffer before giving up. A
/// peer that never sends `\r\n\r\n` within this exact bound is dropped fail-closed (no unbounded
/// read); the buffer is bound-checked AFTER each read, so it never exceeds this cap.
const MAX_HTTP_HEAD: usize = 8 * 1024;

/// Read the HTTP request head (up to and including `\r\n\r\n`) from a TLS-terminated stream into a
/// buffer. Returns `(buf, header_end)` where `header_end` is the offset just past the terminator, or
/// `None` if the peer closed early or the head exceeded [`MAX_HTTP_HEAD`]. Hand-rolled (no
/// axum/hyper); mirrors the peerAPI router's head-read style.
async fn read_http_head<S>(stream: &mut S) -> Option<(Vec<u8>, usize)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    loop {
        if let Some(end) = crate::peerapi_doh::find_header_end(&buf) {
            return Some((buf, end));
        }
        match stream.read(&mut tmp).await {
            Ok(0) => return None,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                // Bound-check AFTER extending so the buffer never exceeds MAX_HTTP_HEAD. The
                // terminator is re-checked at the top of the loop, so a head whose terminator lands
                // exactly at the bound still succeeds; only a head with no terminator within
                // MAX_HTTP_HEAD is dropped fail-closed.
                if crate::peerapi_doh::find_header_end(&buf).is_none() && buf.len() >= MAX_HTTP_HEAD
                {
                    return None;
                }
            }
            Err(_) => return None,
        }
    }
}

/// Parse the request-line path from an HTTP head. Returns the path component (without the query
/// string), or `None` if the head is malformed. Hand-rolled; no HTTP library framing assumptions
/// beyond the request line.
fn request_path(buf: &[u8]) -> Option<String> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(buf) {
        Ok(_) => {}
        Err(_) => return None,
    }
    let path = req.path?;
    let raw = path.split_once('?').map(|(p, _)| p).unwrap_or(path);
    Some(raw.to_string())
}

/// Reason phrase for a redirect status (best-effort; falls back to "Redirect").
fn redirect_reason(status: u16) -> &'static str {
    match status {
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        _ => "Redirect",
    }
}

/// Write a bodyless HTTP redirect (Go `HTTPHandler` redirect) on a TLS-terminated stream, then close.
/// Fail-closed: any write error drops the conn. No request parsing is needed — every request on a
/// `Redirect` target gets the same response.
async fn serve_redirect<S>(port: u16, mut tls: S, to: &str, status: u16)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nLocation: {to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        reason = redirect_reason(status),
    );
    if let Err(e) = tls.write_all(head.as_bytes()).await {
        tracing::debug!(%port, error = %e, "serve redirect: write failed");
        return;
    }
    if let Err(e) = tls.flush().await {
        tracing::debug!(%port, error = %e, "serve redirect: flush failed");
    }
    drop(tls.shutdown().await);
}

/// Write a bodyless HTTP status response (e.g. `404 Not Found`) on a TLS-terminated stream, then
/// close. Local mirror of `peerapi_doh::write_status` (which takes the concrete peerAPI stream type).
async fn write_http_status<S>(port: u16, mut tls: S, status: &str)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let head = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    if let Err(e) = tls.write_all(head.as_bytes()).await {
        tracing::debug!(%port, error = %e, "serve path: status write failed");
        return;
    }
    drop(tls.flush().await);
    drop(tls.shutdown().await);
}

/// Serve a [`ServeTarget::Path`] mux on a TLS-terminated stream: read the request head, pick the
/// longest-matching path prefix in `handlers`, and dispatch the matched nested target on the
/// already-decrypted stream. Fail-closed: a malformed head, no matching prefix, or an
/// un-dispatchable nested target ⇒ 404/drop. For a matched nested `Proxy`, the request head consumed
/// here is replayed to the backend first (via [`proxy_to_backend_with_prefix`]) so the backend sees
/// the complete request. Backend dial failures inside a nested `Proxy` drop the conn. Nested `Path`
/// is rejected by `ServeState::validate`, so it is not expected here; it is dropped fail-closed if it
/// ever reaches dispatch.
async fn serve_path<S>(port: u16, mut tls: S, handlers: &BTreeMap<String, ServeTarget>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some((buf, _end)) = read_http_head(&mut tls).await else {
        tracing::debug!(%port, "serve path: incomplete/oversized request head; dropping conn");
        return;
    };
    let Some(path) = request_path(&buf) else {
        write_http_status(port, tls, "400 Bad Request").await;
        return;
    };

    // Longest-matching prefix wins.
    let matched = handlers
        .iter()
        .filter(|(prefix, _)| path.starts_with(prefix.as_str()))
        .max_by_key(|(prefix, _)| prefix.len())
        .map(|(_, target)| target);

    let Some(target) = matched else {
        write_http_status(port, tls, "404 Not Found").await;
        return;
    };

    match target {
        // The request head was already consumed off `tls` by `read_http_head`; replay it (`buf`) to
        // the backend FIRST so the backend sees the complete request (head + remaining body/stream),
        // not a request with its first request-line+headers missing.
        ServeTarget::Proxy { to } => proxy_to_backend_with_prefix(port, tls, to, &buf).await,
        ServeTarget::Text { body } => write_text(port, tls, body).await,
        ServeTarget::Redirect { to, status } => serve_redirect(port, tls, to, *status).await,
        // Accept (no hand-back channel here), TcpForward (raw, not on a TLS path), nested Path
        // (rejected by validate), and any future `#[non_exhaustive]` variant are not servable as a
        // Path leaf: drop fail-closed rather than guess.
        _ => {
            tracing::warn!(%port, "serve path: unsupported nested target; dropping conn");
            write_http_status(port, tls, "404 Not Found").await;
        }
    }
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
        // TcpForward is raw; Accept/Proxy/Text/Path/Redirect all terminate TLS.
        assert!(ServeTarget::Accept.terminates_tls());
        assert!(proxy("127.0.0.1:8080").terminates_tls());
        assert!(ServeTarget::Text { body: "ok".into() }.terminates_tls());
        assert!(
            ServeTarget::Redirect {
                to: "/elsewhere".into(),
                status: 302,
            }
            .terminates_tls()
        );
        let mut handlers = BTreeMap::new();
        handlers.insert("/".to_string(), proxy("127.0.0.1:8080"));
        assert!(ServeTarget::Path { handlers }.terminates_tls());
        assert!(
            !ServeTarget::TcpForward {
                to: "127.0.0.1:5000".into()
            }
            .terminates_tls()
        );
    }

    #[test]
    fn find_header_end_shared_with_peerapi_doh() {
        // The local mirror was removed; serve dispatch now uses the shared peerAPI helper. Keep one
        // assertion that the shared fn behaves as serve dispatch relies on (peerapi_doh owns the
        // exhaustive coverage).
        assert_eq!(
            crate::peerapi_doh::find_header_end(b"GET / HTTP/1.1\r\n\r\n"),
            Some(18)
        );
        assert_eq!(
            crate::peerapi_doh::find_header_end(b"GET / HTTP/1.1\r\n"),
            None
        );
    }

    #[test]
    fn request_path_strips_query() {
        assert_eq!(
            request_path(b"GET /api/v1?x=1 HTTP/1.1\r\nHost: h\r\n\r\n").as_deref(),
            Some("/api/v1")
        );
        assert_eq!(
            request_path(b"GET / HTTP/1.1\r\n\r\n").as_deref(),
            Some("/")
        );
        assert_eq!(request_path(b"not a request").as_deref(), None);
    }

    #[test]
    fn request_path_none_on_malformed_request_line() {
        // No method/version framing at all => httparse rejects => None.
        assert_eq!(request_path(b"GARBAGE\r\n\r\n").as_deref(), None);
        // Empty buffer => incomplete => None.
        assert_eq!(request_path(b"").as_deref(), None);
    }

    #[test]
    fn longest_prefix_wins() {
        // Mirror the selection serve_path performs: longest matching prefix wins.
        let mut handlers: BTreeMap<String, ServeTarget> = BTreeMap::new();
        handlers.insert("/".to_string(), proxy("127.0.0.1:1"));
        handlers.insert("/api".to_string(), proxy("127.0.0.1:2"));
        handlers.insert("/api/v2".to_string(), proxy("127.0.0.1:3"));

        let pick = |path: &str| -> Option<&ServeTarget> {
            handlers
                .iter()
                .filter(|(prefix, _)| path.starts_with(prefix.as_str()))
                .max_by_key(|(prefix, _)| prefix.len())
                .map(|(_, target)| target)
        };

        assert_eq!(pick("/api/v2/x"), Some(&proxy("127.0.0.1:3")));
        assert_eq!(pick("/api/v1"), Some(&proxy("127.0.0.1:2")));
        assert_eq!(pick("/other"), Some(&proxy("127.0.0.1:1")));
    }

    #[test]
    fn redirect_reason_known_statuses() {
        assert_eq!(redirect_reason(301), "Moved Permanently");
        assert_eq!(redirect_reason(308), "Permanent Redirect");
        assert_eq!(redirect_reason(399), "Redirect");
    }

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Read everything the server side wrote to the `client` half of a duplex until the server task
    /// closes its end (drop/shutdown), returning it as a `String`.
    async fn drain_to_string(mut client: tokio::io::DuplexStream) -> String {
        let mut out = Vec::new();
        drop(client.read_to_end(&mut out).await);
        String::from_utf8(out).expect("server emitted valid utf8")
    }

    #[tokio::test]
    async fn serve_redirect_emits_exact_response() {
        let (client, server) = tokio::io::duplex(4096);
        let t = tokio::spawn(async move {
            serve_redirect(443, server, "/elsewhere", 302).await;
        });
        let got = drain_to_string(client).await;
        t.await.unwrap();
        assert_eq!(
            got,
            "HTTP/1.1 302 Found\r\nLocation: /elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn write_http_status_emits_status_line() {
        let (client, server) = tokio::io::duplex(4096);
        let t = tokio::spawn(async move {
            write_http_status(443, server, "404 Not Found").await;
        });
        let got = drain_to_string(client).await;
        t.await.unwrap();
        assert_eq!(
            got,
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );

        let (client, server) = tokio::io::duplex(4096);
        let t = tokio::spawn(async move {
            write_http_status(443, server, "400 Bad Request").await;
        });
        let got = drain_to_string(client).await;
        t.await.unwrap();
        assert_eq!(
            got,
            "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn read_http_head_reads_terminated_head() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        client
            .write_all(b"GET /api HTTP/1.1\r\nHost: h\r\n\r\nBODY")
            .await
            .unwrap();
        drop(client);
        let (buf, end) = read_http_head(&mut server).await.expect("complete head");
        // `end` points just past the terminator; the head + trailing body are both buffered.
        assert_eq!(&buf[..end], b"GET /api HTTP/1.1\r\nHost: h\r\n\r\n");
        assert_eq!(&buf[end..], b"BODY");
    }

    #[tokio::test]
    async fn read_http_head_none_on_early_eof() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        client.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        drop(client); // EOF before the terminator
        assert!(read_http_head(&mut server).await.is_none());
    }

    #[tokio::test]
    async fn read_http_head_none_on_oversized_head() {
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        // A head that never terminates and exceeds MAX_HTTP_HEAD must be dropped fail-closed.
        let oversized = vec![b'a'; MAX_HTTP_HEAD + 1024];
        client.write_all(&oversized).await.unwrap();
        drop(client);
        assert!(read_http_head(&mut server).await.is_none());
    }

    #[tokio::test]
    async fn read_http_head_never_exceeds_max_head() {
        // A terminator landing exactly at the bound still succeeds (the buffer never overshoots).
        let (mut client, mut server) = tokio::io::duplex(MAX_HTTP_HEAD + 16);
        let mut head = vec![b'a'; MAX_HTTP_HEAD - 4];
        head.extend_from_slice(b"\r\n\r\n");
        assert_eq!(head.len(), MAX_HTTP_HEAD);
        client.write_all(&head).await.unwrap();
        drop(client);
        let (buf, end) = read_http_head(&mut server).await.expect("head at bound");
        assert_eq!(end, MAX_HTTP_HEAD);
        assert!(buf.len() <= MAX_HTTP_HEAD);
    }

    #[tokio::test]
    async fn proxy_with_prefix_writes_prefix_before_bidi_copy() {
        // Fix 1 regression guard: the consumed request head MUST hit the backend FIRST, before the
        // bidirectional splice forwards the rest of the client stream. The backend is a real
        // loopback TcpListener (the helper dials `to` via tokio TcpStream).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = listener.local_addr().unwrap();

        let prefix = b"GET /api HTTP/1.1\r\nHost: h\r\n\r\n";
        let body = b"trailing-body-bytes";
        let backend = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut head = vec![0u8; prefix.len()];
            sock.read_exact(&mut head).await.unwrap();
            let mut rest = vec![0u8; body.len()];
            sock.read_exact(&mut rest).await.unwrap();
            (head, rest)
        });

        // Client side of the duplex stands in for the TLS-terminated stream the helper splices.
        let (mut client, server) = tokio::io::duplex(4096);
        let to = backend_addr.to_string();
        let proxy_task = tokio::spawn(async move {
            proxy_to_backend_with_prefix(443, server, &to, prefix).await;
        });

        // Feed the rest of the request body through the splice, then close.
        client.write_all(body).await.unwrap();
        drop(client);

        let (head, rest) = backend.await.unwrap();
        proxy_task.await.unwrap();
        assert_eq!(
            head, prefix,
            "prefix (consumed head) replayed to backend first"
        );
        assert_eq!(rest, body, "remaining stream spliced after the prefix");
    }

    #[tokio::test]
    async fn serve_path_proxy_replays_consumed_head_to_backend() {
        // End-to-end longest-prefix selection routing to a nested Proxy: the head consumed by
        // `read_http_head` must reach the backend, proving the request is not dropped (the bug).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = listener.local_addr().unwrap();
        let request = b"GET /api/v2/x HTTP/1.1\r\nHost: h\r\n\r\n";
        let backend = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut head = vec![0u8; request.len()];
            sock.read_exact(&mut head).await.unwrap();
            head
        });

        let mut handlers: BTreeMap<String, ServeTarget> = BTreeMap::new();
        handlers.insert("/".to_string(), proxy("127.0.0.1:1")); // shorter prefix (not selected)
        handlers.insert("/api/v2".to_string(), proxy(&backend_addr.to_string())); // longest match

        let (mut client, server) = tokio::io::duplex(4096);
        let path_task = tokio::spawn(async move {
            serve_path(443, server, &handlers).await;
        });
        client.write_all(request).await.unwrap();
        drop(client);

        let head = backend.await.unwrap();
        path_task.await.unwrap();
        assert_eq!(
            head, request,
            "serve_path routed to the longest-prefix Proxy and replayed the consumed head"
        );
    }

    #[tokio::test]
    async fn serve_path_text_target_emits_body() {
        // Longest-prefix selection routing to a nested Text target: the body is emitted verbatim.
        let mut handlers: BTreeMap<String, ServeTarget> = BTreeMap::new();
        handlers.insert(
            "/".to_string(),
            ServeTarget::Text {
                body: "root".into(),
            },
        );
        handlers.insert(
            "/hello".to_string(),
            ServeTarget::Text {
                body: "hello-body".into(),
            },
        );

        let (mut client, server) = tokio::io::duplex(4096);
        let t = tokio::spawn(async move {
            serve_path(443, server, &handlers).await;
        });
        client
            .write_all(b"GET /hello/world HTTP/1.1\r\nHost: h\r\n\r\n")
            .await
            .unwrap();
        // Keep the client half open: `read_http_head` already saw the full head, and the Text target
        // neither reads further nor needs EOF. Drain the body the server writes + shuts down.
        let got = drain_to_string(client).await;
        t.await.unwrap();
        assert_eq!(got, "hello-body");
    }

    // NOTE: a live bind+accept test needs a running netstack channel + overlay; the existing
    // netstack-backed managers (fallback_tcp) likewise unit-test only the pure pieces (port diff,
    // dispatch decision) and leave the bind/accept path to integration coverage. The byte-emission
    // helpers above are exercised directly over `tokio::io::duplex` + loopback `TcpStream` backends;
    // the bind/accept/splice path is exercised via `Device::set_serve_config` against a real device.
}
