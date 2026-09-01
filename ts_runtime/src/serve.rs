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
///
/// The target is returned **raw**, exactly as the client wrote it: normalizing it is
/// [`match_path_handler`]'s job, because Go's `getServeHandler` looks the raw target up first and
/// only then cleans it. A malformed target (`*`, an authority-form `host:port`) comes back here as
/// itself and is refused there, not here.
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

/// Go's `path.Clean` (Go stdlib `path/path.go`), transliterated. This is the lexical cleaning
/// `getServeHandler` (`ipn/ipnlocal/serve.go` @ `49e148c4a30b4f8098f69468fd27a7021d85ea02`) applies
/// to the request path *before* it walks the mounts, so it must be the same cleaning here: dot and
/// dot-dot segments are resolved, repeated and trailing separators collapse, and a leading dot-dot
/// on a rooted path is dropped (`/api/../secret` ⇒ `/secret`, `/../x` ⇒ `/x`, `//a//b/` ⇒ `/a/b`).
///
/// Purely lexical, exactly like Go's: it never touches a filesystem and never decodes percent
/// escapes. Non-rooted inputs keep Go's answers too — `""` and `"."` clean to `"."`, and `"*"`
/// cleans to `"*"` — which is what makes the "not absolute" refusal in [`match_path_handler`]
/// catch the malformed request targets.
fn clean_path(path: &str) -> String {
    let s = path.as_bytes();
    if s.is_empty() {
        return ".".to_string();
    }
    let n = s.len();
    let rooted = s[0] == b'/';

    // `out` is Go's `lazybuf`: the cleaned bytes written so far. `dotdot` is the index past which
    // a `..` may still eat an element (1 on a rooted path, so `..` can never eat the leading `/`).
    let mut out: Vec<u8> = Vec::with_capacity(n);
    let mut r = 0usize;
    let mut dotdot = 0usize;
    if rooted {
        out.push(b'/');
        r = 1;
        dotdot = 1;
    }

    while r < n {
        if s[r] == b'/' {
            // Empty path element: drop it (this is what collapses `//` and a trailing `/`).
            r += 1;
        } else if s[r] == b'.' && (r + 1 == n || s[r + 1] == b'/') {
            // `.` element: drop it.
            r += 1;
        } else if s[r] == b'.' && r + 1 < n && s[r + 1] == b'.' && (r + 2 == n || s[r + 2] == b'/')
        {
            // `..` element: back up over the previously written element, if there is one.
            r += 2;
            if out.len() > dotdot {
                let mut w = out.len() - 1;
                while w > dotdot && out[w] != b'/' {
                    w -= 1;
                }
                out.truncate(w);
            } else if !rooted {
                // Nothing to back up over and no leading `/` to anchor to: the `..` is kept, as
                // Go keeps it (`../..` cleans to itself). A rooted path drops it instead, which is
                // why `/../secret` is `/secret` and can never escape above the root.
                if !out.is_empty() {
                    out.push(b'/');
                }
                out.extend_from_slice(b"..");
                dotdot = out.len();
            }
        } else {
            // A real path element: add the separator if one is needed, then copy the element.
            if (rooted && out.len() != 1) || (!rooted && !out.is_empty()) {
                out.push(b'/');
            }
            while r < n && s[r] != b'/' {
                out.push(s[r]);
                r += 1;
            }
        }
    }

    if out.is_empty() {
        return ".".to_string();
    }
    // Every byte written is copied verbatim from `path` (valid UTF-8) and the buffer is only ever
    // truncated at an ASCII `/`, so this cannot split a multi-byte character.
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// Whether a mount point in a [`ServeTarget::Path`] map claims `path`.
///
/// A mount at `P` claims exactly `P` itself and the paths **below** it — i.e. `path == P`, or `path`
/// begins with `P` followed by `/`. It does **not** claim arbitrary strings that merely start with
/// the same bytes: a `/api` mount does not claim `/apifoo`, `/apibar` or `/api-internal`, which fall
/// through to whatever shorter mount (typically `/`) does claim them.
///
/// A mount written with a trailing slash means the same thing as one without: `/api/` is normalized
/// to `/api`, so it claims `/api/v2` without needing the request to be `/api//v2`, and it also
/// claims the bare `/api`. The root mount `/` normalizes to the empty prefix and therefore claims
/// every path.
///
/// ## Go behaviour this mirrors
///
/// Go's `getServeHandler` (`ipn/ipnlocal/serve.go`) never does a raw byte-prefix test. It first
/// looks the cleaned request path up in the handler map exactly, and only then walks *backwards*
/// over the path's `/` separators, retrying the lookup on each successively shorter truncation of
/// the path. Because every candidate it ever tries is the path cut at a `/`, a handler can only ever
/// be reached at a path-segment boundary — `/apifoo` never reaches the `/api` handler there, and it
/// must not here either.
fn mount_claims_path(mount: &str, path: &str) -> bool {
    // "/api/" and "/api" are the same mount; "/" becomes the empty prefix, which claims everything.
    let base = mount.strip_suffix('/').unwrap_or(mount);
    if base.is_empty() {
        return true;
    }
    match path.strip_prefix(base) {
        // Exactly the mount itself, or a path below it. Anything else (`/apifoo` for `/api`) is a
        // different path that merely shares a byte prefix.
        Some(rest) => rest.is_empty() || rest.starts_with('/'),
        None => false,
    }
}

/// Pick the [`ServeTarget`] a request `path` dispatches to in a [`ServeTarget::Path`] mux, given the
/// raw request target from the request line.
///
/// Pure and total over `(handlers, path)` — the whole routing decision, with no I/O — so it is
/// testable directly instead of only through a TLS-terminated socket. [`serve_path`] calls this; it
/// is the single definition of the rule, and a test that re-implemented it would be testing its own
/// copy rather than what dispatch does.
///
/// ## Go behaviour this mirrors
///
/// `getServeHandler` (`ipn/ipnlocal/serve.go` @ `49e148c4a30b4f8098f69468fd27a7021d85ea02`) resolves
/// a request in three steps, and so does this:
///
/// 1. **Exact lookup of the raw target.** A mount spelled exactly as the request target wins
///    verbatim, before any normalization (Go: `wsc.Handlers().GetOk(r.URL.Path)`).
/// 2. **Clean, then match.** Otherwise the target is [`clean_path`]ed — Go's `path.Clean` — and only
///    the *cleaned* path is offered to the mounts. Dot-dot is therefore resolved **before** any
///    mount is consulted: with mounts at `/` and `/api`, `/api/../secret` is `/secret` and is served
///    by `/`; it must never reach the `/api` backend, which was never mounted for it.
/// 3. **Refuse a target that is not an absolute path.** A cleaned path not starting with `/` matches
///    nothing. Go needs this guard because the malformed request targets — `*` (`GET *`) and the
///    empty authority-form target — clean to `*` and `.`, which are `path.Dir` fixed points that
///    would spin its backwards walk forever. Here the walk cannot spin, but the guard still carries
///    Go's *routing* answer: those targets match no mount. Without it a root mount claims them,
///    because `/` normalizes to the empty prefix that claims every string.
///
/// Longest match wins among the mounts that claim the cleaned path (see [`mount_claims_path`]): the
/// one with the most path bytes is chosen, so `/api/v2` beats `/api` beats `/`. This is the same
/// answer as Go's backwards walk, which tries the path cut at each `/` from longest to shortest.
/// Ties (only reachable between the same mount spelled with and without a trailing slash, e.g.
/// `/api` and `/api/`) resolve to the last in `BTreeMap` order, deterministically. `None` means no
/// mount claims the path, which dispatch turns into a fail-closed 404.
fn match_path_handler<'h>(
    handlers: &'h BTreeMap<String, ServeTarget>,
    path: &str,
) -> Option<&'h ServeTarget> {
    // (1) The raw target, looked up exactly.
    if let Some(target) = handlers.get(path) {
        return Some(target);
    }
    // (2) Everything else routes on the cleaned path, never the raw one.
    let cleaned = clean_path(path);
    // (3) Not an absolute path => no mount claims it.
    if !cleaned.starts_with('/') {
        return None;
    }
    handlers
        .iter()
        .filter(|(mount, _)| mount_claims_path(mount, &cleaned))
        .max_by_key(|(mount, _)| mount.strip_suffix('/').unwrap_or(mount).len())
        .map(|(_, target)| target)
}

/// Serve a [`ServeTarget::Path`] mux on a TLS-terminated stream: read the request head, pick the
/// longest-matching mount in `handlers` (via [`match_path_handler`]), and dispatch the matched
/// nested target on the already-decrypted stream. Fail-closed: a malformed head, no matching mount,
/// or an un-dispatchable nested target ⇒ 404/drop. For a matched nested `Proxy`, the request head consumed
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

    let Some(target) = match_path_handler(handlers, &path) else {
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

    /// The mux `serve_path` dispatch tests below route against: root, `/api`, `/api/v2`, each with a
    /// distinguishable backend so a test can assert which one a path did *not* reach.
    fn mux() -> BTreeMap<String, ServeTarget> {
        let mut handlers: BTreeMap<String, ServeTarget> = BTreeMap::new();
        handlers.insert("/".to_string(), proxy("127.0.0.1:1"));
        handlers.insert("/api".to_string(), proxy("127.0.0.1:2"));
        handlers.insert("/api/v2".to_string(), proxy("127.0.0.1:3"));
        handlers
    }

    #[test]
    fn longest_matching_mount_wins() {
        // Calls the production selection (`serve_path` calls the same fn) — not a copy of it.
        let handlers = mux();
        assert_eq!(
            match_path_handler(&handlers, "/api/v2/x"),
            Some(&proxy("127.0.0.1:3")),
            "the longest mount claiming the path must win"
        );
        assert_eq!(
            match_path_handler(&handlers, "/api/v1"),
            Some(&proxy("127.0.0.1:2"))
        );
        assert_eq!(
            match_path_handler(&handlers, "/api"),
            Some(&proxy("127.0.0.1:2"))
        );
        assert_eq!(
            match_path_handler(&handlers, "/other"),
            Some(&proxy("127.0.0.1:1"))
        );
    }

    #[test]
    fn mount_does_not_claim_a_longer_first_segment() {
        // The negative case, and the whole point: a `/api` mount must NOT swallow `/apifoo`. A raw
        // byte-prefix test routes these to the `/api` backend; Go's segment-boundary lookup does
        // not, and neither may we. Assert where they must *not* go, not only where they must.
        let handlers = mux();
        let api = proxy("127.0.0.1:2");
        let root = proxy("127.0.0.1:1");
        for path in ["/apifoo", "/apibar", "/api-internal", "/api_v2", "/apis/x"] {
            let picked = match_path_handler(&handlers, path);
            assert_ne!(picked, Some(&api), "{path} must not reach the /api backend");
            assert_eq!(
                picked,
                Some(&root),
                "{path} must fall through to the / mount"
            );
        }
        // Same shape one level down: `/api/v2` must not claim `/api/v20`.
        let picked = match_path_handler(&handlers, "/api/v20");
        assert_ne!(
            picked,
            Some(&proxy("127.0.0.1:3")),
            "/api/v20 must not reach the /api/v2 backend"
        );
        assert_eq!(picked, Some(&api));
    }

    #[test]
    fn mount_claims_itself_and_paths_below_it() {
        assert!(mount_claims_path("/api", "/api"));
        assert!(mount_claims_path("/api", "/api/"));
        assert!(mount_claims_path("/api", "/api/v2/x"));
        assert!(!mount_claims_path("/api", "/apifoo"));
        assert!(!mount_claims_path("/api", "/ap"));
        assert!(!mount_claims_path("/api", "/"));
        // The root mount claims everything.
        assert!(mount_claims_path("/", "/"));
        assert!(mount_claims_path("/", "/anything/at/all"));
    }

    #[test]
    fn trailing_slash_mount_needs_no_doubled_slash() {
        // `/api/` is the same mount as `/api`: it claims `/api/v2`, not only `/api//v2`.
        assert!(mount_claims_path("/api/", "/api/v2"));
        assert!(mount_claims_path("/api/", "/api/"));
        assert!(mount_claims_path("/api/", "/api"));
        assert!(!mount_claims_path("/api/", "/apifoo"));

        let mut handlers: BTreeMap<String, ServeTarget> = BTreeMap::new();
        handlers.insert("/".to_string(), proxy("127.0.0.1:1"));
        handlers.insert("/api/".to_string(), proxy("127.0.0.1:2"));
        assert_eq!(
            match_path_handler(&handlers, "/api/v2"),
            Some(&proxy("127.0.0.1:2"))
        );
        assert_eq!(
            match_path_handler(&handlers, "/apifoo"),
            Some(&proxy("127.0.0.1:1")),
            "/apifoo must fall through to / even when the mount is spelled /api/"
        );
    }

    #[test]
    fn clean_path_matches_go_path_clean() {
        // The table is Go's own `path.Clean` test table (Go stdlib `path/path_test.go`), which is
        // the cleaning `getServeHandler` applies before it consults the mounts.
        for (input, want) in [
            ("", "."),
            ("abc", "abc"),
            ("abc/def", "abc/def"),
            ("a/b/c", "a/b/c"),
            (".", "."),
            ("..", ".."),
            ("../..", "../.."),
            ("/abc", "/abc"),
            ("/", "/"),
            ("abc/", "abc"),
            ("abc/def/", "abc/def"),
            ("a/b/c/", "a/b/c"),
            ("./", "."),
            ("../", ".."),
            ("../../", "../.."),
            ("/abc/", "/abc"),
            ("abc//def//ghi", "abc/def/ghi"),
            ("//abc", "/abc"),
            ("///abc", "/abc"),
            ("//abc//", "/abc"),
            ("abc//", "abc"),
            ("abc/./def", "abc/def"),
            ("/./abc/def", "/abc/def"),
            ("abc/..", "."),
            ("abc/def/..", "abc"),
            ("abc/def/../ghi", "abc/ghi"),
            ("abc/def/../../ghi", "ghi"),
            ("abc/def/../../..", ".."),
            ("/abc/def/../../..", "/"),
            ("abc/./../def", "def"),
            ("abc//./../def", "def"),
            ("abc/../../././../def", "../../def"),
            // A rooted path can never climb above the root: the leading `..` is dropped.
            ("/../abc", "/abc"),
            ("/api/../secret", "/secret"),
            // The malformed request targets. Neither becomes absolute, which is what the
            // "not absolute" refusal keys off.
            ("*", "*"),
            ("host:443", "host:443"),
        ] {
            assert_eq!(clean_path(input), want, "clean_path({input:?})");
        }
    }

    #[test]
    fn dot_dot_segment_is_cleaned_before_the_mounts_are_consulted() {
        // The bug: matching the RAW target means `/api/../secret` starts with `/api/`, so the `/api`
        // mount claims it and the request reaches a backend it was never mounted for. Go cleans
        // first — the path is `/secret`, which only the `/` mount claims.
        let handlers = mux();
        let root = proxy("127.0.0.1:1");
        let api = proxy("127.0.0.1:2");
        let api_v2 = proxy("127.0.0.1:3");

        for path in [
            "/api/../secret",
            "/api/v2/../../secret",
            "/api/./../secret",
            "/api/..//secret",
            // Climbing above the root is dropped, not an escape: still `/secret`.
            "/../api/../secret",
        ] {
            let picked = match_path_handler(&handlers, path);
            assert_ne!(picked, Some(&api), "{path} must not reach the /api backend");
            assert_ne!(
                picked,
                Some(&api_v2),
                "{path} must not reach the /api/v2 backend"
            );
            assert_eq!(
                picked,
                Some(&root),
                "{path} cleans to /secret, which only / claims"
            );
        }

        // Cleaning cuts both ways: a dot-dot that lands back inside a mount still routes there.
        assert_eq!(
            match_path_handler(&handlers, "/api/v2/../v2/x"),
            Some(&api_v2),
            "/api/v2/../v2/x cleans to /api/v2/x"
        );
        assert_eq!(
            match_path_handler(&handlers, "/api/v2/.."),
            Some(&api),
            "/api/v2/.. cleans to /api"
        );
        // Redundant separators and dot segments normalize away too.
        assert_eq!(match_path_handler(&handlers, "//api//v2//x"), Some(&api_v2));
        assert_eq!(match_path_handler(&handlers, "/api/./v2"), Some(&api_v2));
    }

    #[test]
    fn malformed_request_target_matches_no_mount() {
        // `GET * HTTP/1.1` yields the target `*`, and an authority-form target has no path at all.
        // Go refuses both (they do not clean to an absolute path). A root mount normalizes to the
        // empty prefix that claims every string, so without the refusal `*` would be served by `/`.
        let handlers = mux();
        for target in ["*", "host:443", "example.com:443", "", ".", "..", "api/v2"] {
            assert_eq!(
                match_path_handler(&handlers, target),
                None,
                "{target:?} is not an absolute path and must match no mount, not even /"
            );
        }
        // A mount spelled exactly as the raw target still wins: that is Go's first lookup, which
        // happens before the cleaning and the absolute-path refusal.
        let mut odd: BTreeMap<String, ServeTarget> = BTreeMap::new();
        odd.insert("*".to_string(), proxy("127.0.0.1:9"));
        assert_eq!(match_path_handler(&odd, "*"), Some(&proxy("127.0.0.1:9")));
    }

    #[test]
    fn unmatched_path_selects_nothing() {
        // No root mount => a path no mount claims is `None`, which dispatch turns into a 404.
        let mut handlers: BTreeMap<String, ServeTarget> = BTreeMap::new();
        handlers.insert("/api".to_string(), proxy("127.0.0.1:2"));
        assert_eq!(match_path_handler(&handlers, "/apifoo"), None);
        assert_eq!(match_path_handler(&handlers, "/other"), None);
        assert_eq!(
            match_path_handler(&handlers, "/api/v2"),
            Some(&proxy("127.0.0.1:2"))
        );
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

    #[tokio::test]
    async fn serve_path_does_not_route_a_longer_first_segment_to_the_shorter_mount() {
        // End to end through the real dispatch: with `/` and `/hello` mounted, `/hellofoo` is a
        // different path, not a path below `/hello`, so it must be served by the `/` mount.
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
            .write_all(b"GET /hellofoo HTTP/1.1\r\nHost: h\r\n\r\n")
            .await
            .unwrap();
        let got = drain_to_string(client).await;
        t.await.unwrap();
        assert_ne!(
            got, "hello-body",
            "/hellofoo must not reach the /hello mount"
        );
        assert_eq!(got, "root");
    }

    /// Text mux used by the dispatch tests below: `/` and `/api` with distinguishable bodies, so a
    /// test can assert which backend a request did *not* reach.
    fn text_mux() -> BTreeMap<String, ServeTarget> {
        let mut handlers: BTreeMap<String, ServeTarget> = BTreeMap::new();
        handlers.insert(
            "/".to_string(),
            ServeTarget::Text {
                body: "root".into(),
            },
        );
        handlers.insert(
            "/api".to_string(),
            ServeTarget::Text {
                body: "api-body".into(),
            },
        );
        handlers
    }

    /// Run one raw request line through the real dispatch and return everything the server wrote.
    async fn serve_path_response(
        request: &[u8],
        handlers: BTreeMap<String, ServeTarget>,
    ) -> String {
        let (mut client, server) = tokio::io::duplex(4096);
        let t = tokio::spawn(async move {
            serve_path(443, server, &handlers).await;
        });
        client.write_all(request).await.unwrap();
        let got = drain_to_string(client).await;
        t.await.unwrap();
        got
    }

    #[tokio::test]
    async fn serve_path_does_not_route_a_dot_dot_target_to_the_mount_it_climbed_out_of() {
        // End to end through the real dispatch: the request target names `/api`, but it climbs out
        // of it. Go cleans to `/secret` and serves it from `/`; the `/api` backend must never see
        // it — it was never mounted for `/secret`.
        let got = serve_path_response(
            b"GET /api/../secret HTTP/1.1\r\nHost: h\r\n\r\n",
            text_mux(),
        )
        .await;
        assert_ne!(
            got, "api-body",
            "/api/../secret must not reach the /api mount"
        );
        assert_eq!(got, "root", "/api/../secret cleans to /secret, served by /");

        // The query string is stripped before cleaning, exactly as Go cleans `r.URL.Path`.
        let got = serve_path_response(
            b"GET /api/../secret?x=1 HTTP/1.1\r\nHost: h\r\n\r\n",
            text_mux(),
        )
        .await;
        assert_eq!(got, "root");

        // And a target that stays inside the mount after cleaning still reaches it.
        let got =
            serve_path_response(b"GET /api/v2/../v2 HTTP/1.1\r\nHost: h\r\n\r\n", text_mux()).await;
        assert_eq!(got, "api-body");
    }

    #[tokio::test]
    async fn serve_path_404s_a_malformed_request_target() {
        // `GET *` parses fine as a request line but is not an absolute path. Go matches no handler
        // for it; here the root mount would otherwise claim it, since `/` normalizes to the empty
        // prefix. Fail closed with a 404 instead of serving the root backend.
        let got = serve_path_response(b"GET * HTTP/1.1\r\nHost: h\r\n\r\n", text_mux()).await;
        assert_ne!(got, "root", "`GET *` must not be served by the / mount");
        assert!(
            got.starts_with("HTTP/1.1 404 Not Found\r\n"),
            "expected a 404, got {got:?}"
        );

        // Authority-form (`CONNECT host:443`) likewise has no path to route on.
        let got =
            serve_path_response(b"CONNECT host:443 HTTP/1.1\r\nHost: h\r\n\r\n", text_mux()).await;
        assert!(
            got.starts_with("HTTP/1.1 404 Not Found\r\n"),
            "expected a 404, got {got:?}"
        );
    }

    // NOTE: a live bind+accept test needs a running netstack channel + overlay; the existing
    // netstack-backed managers (fallback_tcp) likewise unit-test only the pure pieces (port diff,
    // dispatch decision) and leave the bind/accept path to integration coverage. The byte-emission
    // helpers above are exercised directly over `tokio::io::duplex` + loopback `TcpStream` backends;
    // the bind/accept/splice path is exercised via `Device::set_serve_config` against a real device.
}
