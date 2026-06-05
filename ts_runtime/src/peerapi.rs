//! peerAPI listener + request router.
//!
//! Go tsnet runs **one** peerAPI HTTP server per node that multiplexes many routes (`/dns-query`,
//! `/v0/put/<name>`, …). This module is the Rust equivalent: it owns the single TCP listener on the
//! node's overlay IPv4 at [`Config::peerapi_port`][ts_control::Config::peerapi_port], reads each
//! request's headers, and dispatches by path:
//!
//! - `/dns-query` → the exit-node DoH handler ([`crate::peerapi_doh`]), unchanged byte-for-byte.
//! - `/v0/put/<name>` → the Taildrop receive handler ([`handle_taildrop_put`]), writing the file
//!   into the configured [`TaildropStore`](crate::taildrop::TaildropStore).
//! - anything else → `404`.
//!
//! ## Anti-leak / IPv4-only
//!
//! The listener binds the overlay IPv4 only (`0.0.0.0:port` on the netstack — never a host socket),
//! exactly as the old DoH-only server did. Requests are size-capped; a saturated server drops the
//! flow (fail-closed, [`MAX_INFLIGHT`]); a slow request is timed out ([`REQUEST_TIMEOUT`]).
//!
//! ## Taildrop access gate (fail-closed)
//!
//! A `PUT /v0/put/<name>` is only accepted when **both** hold:
//!
//! 1. A Taildrop store is configured (`taildrop_dir` set; no store ⇒ `403`).
//! 2. This node holds the node-level capability `https://tailscale.com/cap/file-sharing`
//!    ([`FILE_SHARING_NODE_CAP`]), checked against the self node's cap map
//!    ([`Node::has_node_attr`][ts_control::Node::has_node_attr]).
//!
//! **Documented limitation (peer-cap):** Go additionally requires the *sending peer* to hold the
//! `FILE_SHARING_SEND` peer-capability (`https://tailscale.com/cap/file-send`). That datum lives in
//! the packet-filter peer-capability map, which this fork does **not** thread into the runtime's
//! domain [`Node`][ts_control::Node] (only the node-attribute `cap_map` is). So we cannot yet check
//! the per-peer send grant. As a partial substitute we *do* require the source IP to resolve to a
//! known tailnet peer (or this node) — a `PUT` from an unknown source IP is refused (`403`). The
//! transfer still cannot happen unless the node operator opted in by configuring a Taildrop
//! directory AND this node holds the `file-sharing` node cap, so the surface stays fail-closed.
//! See `tracking: thread PeerCapMap into ts_control::Node` to remove this limitation.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use netstack::{netcore::Channel, netsock::TcpStream};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Semaphore, watch},
    time::timeout,
};

use crate::{
    magic_dns::DnsView,
    peerapi_doh::{find_header_end, write_status},
    taildrop::{TaildropError, TaildropStore},
};

/// The node-level capability that authorizes this node to participate in Taildrop file sharing
/// (Go `tailcfg.CapabilityFileSharing`). Checked against the self node's cap map.
pub(crate) const FILE_SHARING_NODE_CAP: &str = "https://tailscale.com/cap/file-sharing";

/// Max concurrent in-flight peerAPI requests served at once. Bounds per-flow spawn fan-out so a
/// flood can't grow tasks without limit; saturated => drop the flow (fail-closed). Mirrors the
/// `fallback_tcp` / forwarder cap (and the old DoH-only server's cap).
const MAX_INFLIGHT: usize = 512;

/// How long one peerAPI connection may take to be fully serviced before we give up (fail-closed: a
/// slow-loris peer can't pin a server task indefinitely). A Taildrop body can be large, so this is
/// generous relative to the small DoH request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

/// Largest header block we will read before the `\r\n\r\n` terminator. The body is read separately
/// (DoH bounds its own; Taildrop streams the body straight to disk by `Content-Length`). Anything
/// past this with no header terminator is `400` and the connection closed.
const MAX_HEADERS: usize = 16 * 1024;

/// Run the single peerAPI server on `channel`, accepting on `0.0.0.0:port` of the overlay netstack
/// and dispatching each request by path. Returns on bind/accept failure — fail-closed: no server
/// means peers can't use this node's peerAPI at all.
///
/// Binding the unspecified overlay address (rather than this node's specific tailnet IPv4) avoids a
/// startup dependency on the self IP, which isn't known until the first netmap; the interface owns
/// the node's tailnet address, so a peer dialing `<our-tailnet-ipv4>:port` is accepted here. IPv4-only.
///
/// `view_rx` is the live [`DnsView`] shared with the MagicDNS responder (same control/peer state);
/// the DoH handler resolves queries against it and the Taildrop handler reads the self-node cap and
/// peer set from it for the access gate. `forward_exit_egress` gates DoH recursive resolution.
/// `taildrop` is the configured file store, or `None` when Taildrop is disabled (a `PUT` then `403`s).
pub(crate) async fn serve(
    channel: Channel,
    port: u16,
    view_rx: watch::Receiver<Arc<DnsView>>,
    forward_exit_egress: bool,
    taildrop: Option<Arc<TaildropStore>>,
) {
    use std::net::Ipv4Addr;

    use netstack::CreateSocket;

    let addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port);
    let listener = match channel.tcp_listen(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, %addr, "peerapi: tcp listen failed; server inert");
            return;
        }
    };
    tracing::debug!(%addr, taildrop = taildrop.is_some(), "peerapi server accepting");

    let inflight = Arc::new(Semaphore::new(MAX_INFLIGHT));

    loop {
        let stream = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "peerapi: accept failed, stopping server");
                return;
            }
        };

        let Ok(permit) = inflight.clone().try_acquire_owned() else {
            tracing::warn!(
                peer = %stream.remote_addr(),
                "peerapi drop: at max in-flight requests ({MAX_INFLIGHT})"
            );
            // Dropping `stream` closes the flow; fail-closed.
            continue;
        };

        let channel = channel.clone();
        let view_rx = view_rx.clone();
        let taildrop = taildrop.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = timeout(
                REQUEST_TIMEOUT,
                route_conn(stream, &channel, &view_rx, forward_exit_egress, taildrop),
            )
            .await
            {
                tracing::debug!(error = %e, "peerapi: connection timed out");
            }
        });
    }
}

/// Read one request's headers off `stream`, classify the route, and dispatch. Reads only up to the
/// `\r\n\r\n` terminator here; each handler consumes its own body from the already-read `seed` plus
/// the remaining stream.
async fn route_conn(
    mut stream: TcpStream,
    channel: &Channel,
    view_rx: &watch::Receiver<Arc<DnsView>>,
    forward_exit_egress: bool,
    taildrop: Option<Arc<TaildropStore>>,
) -> std::io::Result<()> {
    let (seed, header_end) = match read_headers(&mut stream).await? {
        Some(v) => v,
        None => return Ok(()), // peer closed before sending anything
    };

    // Parse just the request line + headers to learn the method and path.
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(&seed) {
        Ok(httparse::Status::Complete(_)) => {}
        // We already located \r\n\r\n, so Partial/Err here means malformed headers.
        Ok(httparse::Status::Partial) | Err(_) => {
            return write_status(&mut stream, "400 Bad Request").await;
        }
    }

    let method = req.method.unwrap_or("");
    let full_path = req.path.unwrap_or("");

    match classify_route(method, full_path) {
        Route::TaildropPut { name } => {
            // Extract everything we need from the borrowed `req` into owned values *before* moving
            // `seed` into the handler (the parsed `req` borrows `seed`). `content_length` is `None`
            // when absent/unparseable → the handler answers `400`.
            let offset = parse_range_offset(&req);
            let content_length =
                header_value(&req, "content-length").and_then(|v| v.trim().parse::<u64>().ok());
            let src = stream.remote_addr();
            // `req` (which borrows `seed`) is not used past here, so NLL ends the borrow and `seed`
            // can be moved into the handler below.
            handle_taildrop_put(
                stream,
                seed,
                header_end,
                name,
                offset,
                content_length,
                src,
                view_rx,
                taildrop,
            )
            .await
        }
        Route::TaildropMethodNotAllowed => {
            write_status(&mut stream, "405 Method Not Allowed").await
        }
        // Everything else is handed to the DoH handler (which itself returns 404 for a path that
        // is not `/dns-query`).
        Route::DohOrOther => {
            crate::peerapi_doh::handle_conn(
                stream,
                seed,
                header_end,
                channel,
                view_rx,
                forward_exit_egress,
            )
            .await
        }
    }
}

/// The route a peerAPI request maps to, derived purely from its method and path.
#[derive(Debug, PartialEq, Eq)]
enum Route {
    /// `PUT /v0/put/<name>` — a Taildrop file upload; `name` is the percent-decoded base name.
    TaildropPut { name: String },
    /// A `/v0/put/` path with a non-`PUT` method → `405`.
    TaildropMethodNotAllowed,
    /// Anything else; handed to the DoH handler (`/dns-query`, else `404`).
    DohOrOther,
}

/// Classify a request by `method` and `full_path` (which may carry a `?query`). Mirrors Go's
/// `strings.CutPrefix(path, "/v0/put/")` for the Taildrop route, percent-decoding the name. Pure so
/// the routing decision is unit-testable without a live stream.
fn classify_route(method: &str, full_path: &str) -> Route {
    let raw_path = full_path.split('?').next().unwrap_or(full_path);
    if let Some(encoded_name) = raw_path.strip_prefix("/v0/put/") {
        if method != "PUT" {
            return Route::TaildropMethodNotAllowed;
        }
        return Route::TaildropPut {
            name: percent_decode(encoded_name),
        };
    }
    Route::DohOrOther
}

/// Read from `stream` until the `\r\n\r\n` header terminator, returning the buffered bytes (which
/// may include the start of the body) and the offset just past the terminator. `Ok(None)` if the
/// peer closed before sending any bytes. Caps the header block at [`MAX_HEADERS`].
async fn read_headers(stream: &mut TcpStream) -> std::io::Result<Option<(Vec<u8>, usize)>> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    loop {
        if let Some(pos) = find_header_end(&buf) {
            return Ok(Some((buf, pos)));
        }
        if buf.len() > MAX_HEADERS {
            // No terminator within the cap: treat as a malformed/abusive request. Returning the
            // oversized buffer with header_end past the end lets the caller emit 400 deterministically
            // — but simpler to signal here by returning an empty header_end sentinel is fragile, so
            // we just return what we have and let httparse fail (Partial) → 400.
            return Ok(Some((buf, 0)));
        }
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Ok(if buf.is_empty() { None } else { Some((buf, 0)) });
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// Look up a request header value case-insensitively.
fn header_value<'a>(req: &'a httparse::Request<'_, '_>, name: &str) -> Option<&'a str> {
    req.headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .and_then(|h| std::str::from_utf8(h.value).ok())
}

/// The outcome of the Taildrop access gate.
#[derive(Debug, PartialEq, Eq)]
enum GateDecision {
    /// Accept the transfer.
    Allow,
    /// Reject with `403 Forbidden` (fail-closed): no store, missing node cap, or unknown source.
    Deny,
}

/// Decide whether a `PUT /v0/put/` from `src` is authorized, given the live `view`. Fail-closed:
///
/// - No store configured ⇒ `Deny` (handled by the caller before this, but modeled here for tests).
/// - Self node missing the [`FILE_SHARING_NODE_CAP`] node cap ⇒ `Deny`.
/// - Source IP does not resolve to a known tailnet peer or this node ⇒ `Deny`.
///
/// See the module-level "Documented limitation (peer-cap)" note: the per-peer `FILE_SHARING_SEND`
/// grant is not checkable from runtime state, so the known-source check is the partial substitute.
/// Pure (no I/O) so it is unit-testable without a live stream.
fn gate_taildrop(view: &DnsView, src: SocketAddr, store_configured: bool) -> GateDecision {
    if !store_configured {
        return GateDecision::Deny;
    }

    // Node-level opt-in: this node must hold the file-sharing capability.
    let node_ok = view
        .self_node
        .as_ref()
        .is_some_and(|n| n.has_node_attr(FILE_SHARING_NODE_CAP));
    if !node_ok {
        return GateDecision::Deny;
    }

    // Partial peer check: the source must be a known tailnet node (peer or self). The full
    // FILE_SHARING_SEND peer-cap check is not yet possible (see module docs). Resolve against the
    // shared view's peer DB / self node directly (DnsView's fields are crate-visible).
    if !source_is_known_node(view, src.ip()) {
        return GateDecision::Deny;
    }

    GateDecision::Allow
}

/// Whether `ip` belongs to a known tailnet peer or this node, per the shared view.
fn source_is_known_node(view: &DnsView, ip: std::net::IpAddr) -> bool {
    if view.peers.as_ref().and_then(|p| p.get(&ip)).is_some() {
        return true;
    }
    view.self_node.as_ref().is_some_and(|n| {
        std::net::IpAddr::from(n.tailnet_address.ipv4.addr()) == ip
            || std::net::IpAddr::from(n.tailnet_address.ipv6.addr()) == ip
    })
}

/// Parse the optional resume `Range: bytes=<start>-` header into a starting offset. Mirrors Go's
/// single-range support: a malformed or absent range yields offset `0` (transfer from the start).
fn parse_range_offset(req: &httparse::Request<'_, '_>) -> u64 {
    let Some(val) = header_value(req, "range") else {
        return 0;
    };
    let val = val.trim();
    let Some(rest) = val.strip_prefix("bytes=") else {
        return 0;
    };
    // Only a single range is supported; `<start>-` (open-ended) is what a resumed Taildrop sends.
    let Some((start, _end)) = rest.split_once('-') else {
        return 0;
    };
    start.trim().parse::<u64>().unwrap_or(0)
}

/// Minimal percent-decode of a URL path segment (`%XX` → byte). Invalid escapes are left verbatim,
/// matching a permissive decoder; the result is handed to [`TaildropStore::put_file`], which
/// validates the name and rejects anything unsafe (so a decode that produces a `/` or `..` is still
/// caught downstream with a `400`). Hand-rolled to avoid pulling a new dependency into this crate.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Handle one `PUT /v0/put/<name>` Taildrop transfer.
///
/// On success writes `200 OK` with body `"{}\n"` (Go's `taildropResp`). The access gate
/// ([`gate_taildrop`]) is enforced first (fail-closed `403`). The file name is percent-decoded then
/// handed to [`TaildropStore::put_file`], whose [`validate_base_name`][crate::taildrop::validate_base_name]
/// is the security boundary. Error mapping mirrors Go: `InvalidFileName` → `400`, `FileExists` →
/// `409 Conflict`, `Io` → `500`.
#[allow(clippy::too_many_arguments)]
async fn handle_taildrop_put(
    mut stream: TcpStream,
    seed: Vec<u8>,
    header_end: usize,
    name: String,
    offset: u64,
    content_length: Option<u64>,
    src: SocketAddr,
    view_rx: &watch::Receiver<Arc<DnsView>>,
    taildrop: Option<Arc<TaildropStore>>,
) -> std::io::Result<()> {
    // Access gate first — before any name decode or filesystem path is built.
    let Some(store) = taildrop else {
        return write_status(&mut stream, "403 Forbidden").await;
    };
    {
        let view = view_rx.borrow().clone();
        if gate_taildrop(&view, src, true) == GateDecision::Deny {
            return write_status(&mut stream, "403 Forbidden").await;
        }
    }

    // Content-Length bounds the body. A missing length is a 400 (we don't support chunked uploads).
    let Some(content_length) = content_length else {
        return write_status(&mut stream, "400 Bad Request").await;
    };

    // Stream the body to the store: feed the already-read seed body bytes first, then the rest of
    // the stream, capped at exactly `content_length`. `put_file` reads to EOF, so wrap the source in
    // a reader that yields precisely the declared body length.
    let body_seed = seed[header_end..].to_vec();
    let reader = BodyReader::new(body_seed, &mut stream, content_length);

    match store.put_file(&name, reader, offset).await {
        Ok(_total) => write_taildrop_ok(&mut stream).await,
        Err(TaildropError::InvalidFileName) => write_status(&mut stream, "400 Bad Request").await,
        Err(TaildropError::FileExists) => write_status(&mut stream, "409 Conflict").await,
        Err(TaildropError::Io(e)) => {
            tracing::warn!(error = %e, %src, "taildrop put: I/O error");
            write_status(&mut stream, "500 Internal Server Error").await
        }
    }
}

/// The full Taildrop success response bytes: `200 OK` with body exactly `"{}\n"` and
/// `Content-Length: 3` (Go `taildropResp`). Pure so the exact wire bytes are unit-testable.
fn taildrop_ok_response() -> Vec<u8> {
    const BODY: &[u8] = b"{}\n";
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        BODY.len()
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(BODY);
    out
}

/// Write the Taildrop success response (see [`taildrop_ok_response`]).
async fn write_taildrop_ok(stream: &mut TcpStream) -> std::io::Result<()> {
    stream.write_all(&taildrop_ok_response()).await?;
    stream.flush().await
}

/// An [`AsyncRead`] over a request body that yields exactly `remaining` bytes: first the bytes
/// already buffered while reading headers (`seed`), then bytes pulled from the underlying stream,
/// stopping at the declared `Content-Length`. This gives [`TaildropStore::put_file`] a reader that
/// hits EOF at the body boundary so it never blocks waiting for bytes past the body or over-reads
/// into a (non-existent here) next request.
/// Generic over the underlying byte source so the production `&mut TcpStream` (the netstack stream)
/// works by inference while tests can drive it over any `AsyncRead`, e.g. a `tokio::io::duplex`
/// half — the netstack `TcpStream` is a concrete, privately-constructed type that can't be built in
/// a test, so this is the only way to exercise the cap against a real async stream.
struct BodyReader<S> {
    seed: std::io::Cursor<Vec<u8>>,
    stream: S,
    remaining: u64,
}

impl<S> BodyReader<S> {
    fn new(seed: Vec<u8>, stream: S, content_length: u64) -> Self {
        // The seed may hold more than the body in pathological pipelined cases; cap it.
        let seed = if seed.len() as u64 > content_length {
            seed[..content_length as usize].to_vec()
        } else {
            seed
        };
        let remaining = content_length.saturating_sub(seed.len() as u64);
        Self {
            seed: std::io::Cursor::new(seed),
            stream,
            remaining,
        }
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for BodyReader<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Drain the seed first (synchronous, in-memory).
        if (self.seed.position() as usize) < self.seed.get_ref().len() {
            let dst = buf.initialize_unfilled();
            let n = std::io::Read::read(&mut self.seed, dst)?;
            buf.advance(n);
            return std::task::Poll::Ready(Ok(()));
        }

        if self.remaining == 0 {
            // Body fully delivered: report EOF so `put_file`'s copy loop terminates.
            return std::task::Poll::Ready(Ok(()));
        }

        // Read from the stream, but never past the remaining body length. `limited` is a sub-view
        // over `buf`'s unfilled region; read into it in a scope so its mutable borrow of `buf` ends
        // before we advance `buf` by however many bytes landed.
        let want = self.remaining.min(buf.remaining() as u64) as usize;
        let poll = {
            let mut limited = buf.take(want);
            let stream = std::pin::Pin::new(&mut self.stream);
            match tokio::io::AsyncRead::poll_read(stream, cx, &mut limited) {
                std::task::Poll::Ready(Ok(())) => {
                    std::task::Poll::Ready(Ok(limited.filled().len()))
                }
                std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => std::task::Poll::Pending,
            }
        };
        match poll {
            std::task::Poll::Ready(Ok(n)) => {
                buf.advance(n);
                self.remaining -= n as u64;
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn req_with<'a>(
        buf: &'a [u8],
        headers: &'a mut [httparse::Header<'a>],
    ) -> httparse::Request<'a, 'a> {
        let mut req = httparse::Request::new(headers);
        let _ = req.parse(buf);
        req
    }

    #[test]
    fn percent_decode_decodes_escapes() {
        assert_eq!(percent_decode("photo.jpg"), "photo.jpg");
        assert_eq!(percent_decode("my%20file.txt"), "my file.txt");
        assert_eq!(percent_decode("a%2Fb"), "a/b"); // decodes to a slash; put_file rejects it
        // Invalid escape left verbatim.
        assert_eq!(percent_decode("100%done"), "100%done");
    }

    #[test]
    fn parse_range_offset_reads_resume_start() {
        let buf = b"PUT /v0/put/x HTTP/1.1\r\nRange: bytes=1024-\r\n\r\n";
        let mut headers = [httparse::EMPTY_HEADER; 8];
        let req = req_with(buf, &mut headers);
        assert_eq!(parse_range_offset(&req), 1024);
    }

    #[test]
    fn parse_range_offset_defaults_zero() {
        let buf = b"PUT /v0/put/x HTTP/1.1\r\nContent-Length: 3\r\n\r\n";
        let mut headers = [httparse::EMPTY_HEADER; 8];
        let req = req_with(buf, &mut headers);
        assert_eq!(parse_range_offset(&req), 0);

        let buf2 = b"PUT /v0/put/x HTTP/1.1\r\nRange: items=1-2\r\n\r\n";
        let mut headers2 = [httparse::EMPTY_HEADER; 8];
        let req2 = req_with(buf2, &mut headers2);
        assert_eq!(parse_range_offset(&req2), 0);
    }

    /// Build a minimal tailnet `Node` at `ipv4` with the given stable id.
    fn node_at(stable: &str, ipv4: &str) -> ts_control::Node {
        use ts_control::{Node, NodeCapMap, StableNodeId, TailnetAddress};
        Node {
            id: 1,
            stable_id: StableNodeId(stable.to_string()),
            hostname: stable.to_string(),
            tailnet: Some("user.ts.net".to_string()),
            tags: vec![],
            tailnet_address: TailnetAddress {
                ipv4: format!("{ipv4}/32").parse().unwrap(),
                ipv6: "fd7a::1/128".parse().unwrap(),
            },
            node_key: [0u8; 32].into(),
            node_key_expiry: None,
            machine_key: None,
            disco_key: None,
            accepted_routes: vec![],
            underlay_addresses: vec![],
            derp_region: None,
            cap: Default::default(),
            cap_map: NodeCapMap::new(),
            peerapi_port: None,
            peerapi_dns_proxy: false,
            is_wireguard_only: false,
            exit_node_dns_resolvers: vec![],
            service_vips: Default::default(),
        }
    }

    /// A `DnsView` whose self node holds (or not) the file-sharing node cap, and a peer DB with the
    /// given peer IPs present.
    fn view_with(node_has_cap: bool, peer_ips: &[Ipv4Addr]) -> DnsView {
        use crate::peer_tracker::PeerDb;

        let mut self_node = node_at("self", "100.64.0.1");
        if node_has_cap {
            self_node
                .cap_map
                .insert(FILE_SHARING_NODE_CAP.to_string(), Vec::new());
        }

        let mut db = PeerDb::default();
        for (i, ip) in peer_ips.iter().enumerate() {
            db.upsert(&node_at(&format!("peer{i}"), &ip.to_string()));
        }

        DnsView {
            self_node: Some(self_node),
            peers: Some(Arc::new(db)),
            ..Default::default()
        }
    }

    fn src(ip: &str) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(ip.parse().unwrap()), 41234)
    }

    #[test]
    fn gate_denies_without_store() {
        let v = view_with(true, &["100.64.0.9".parse().unwrap()]);
        assert_eq!(
            gate_taildrop(&v, src("100.64.0.9"), false),
            GateDecision::Deny
        );
    }

    #[test]
    fn gate_denies_when_node_lacks_file_sharing_cap() {
        // Store configured + known peer source, but the node does NOT hold the file-sharing cap.
        let v = view_with(false, &["100.64.0.9".parse().unwrap()]);
        assert_eq!(
            gate_taildrop(&v, src("100.64.0.9"), true),
            GateDecision::Deny
        );
    }

    #[test]
    fn gate_denies_unknown_source_ip() {
        let v = view_with(true, &["100.64.0.9".parse().unwrap()]);
        // A source IP that is neither a known peer nor this node.
        assert_eq!(
            gate_taildrop(&v, src("198.51.100.7"), true),
            GateDecision::Deny
        );
    }

    #[test]
    fn gate_allows_known_peer_with_node_cap_and_store() {
        let v = view_with(true, &["100.64.0.9".parse().unwrap()]);
        assert_eq!(
            gate_taildrop(&v, src("100.64.0.9"), true),
            GateDecision::Allow
        );
    }

    #[test]
    fn classify_route_maps_put_to_taildrop() {
        assert_eq!(
            classify_route("PUT", "/v0/put/photo.jpg"),
            Route::TaildropPut {
                name: "photo.jpg".to_string()
            }
        );
        // Percent-decoding applies to the name.
        assert_eq!(
            classify_route("PUT", "/v0/put/my%20file.txt"),
            Route::TaildropPut {
                name: "my file.txt".to_string()
            }
        );
        // A query string after the path is ignored when extracting the route.
        assert_eq!(
            classify_route("PUT", "/v0/put/a.bin?x=1"),
            Route::TaildropPut {
                name: "a.bin".to_string()
            }
        );
    }

    #[test]
    fn classify_route_non_put_on_taildrop_is_405() {
        assert_eq!(
            classify_route("GET", "/v0/put/photo.jpg"),
            Route::TaildropMethodNotAllowed
        );
        assert_eq!(
            classify_route("POST", "/v0/put/photo.jpg"),
            Route::TaildropMethodNotAllowed
        );
    }

    #[test]
    fn classify_route_dns_query_falls_through_to_doh() {
        // The DoH path (and anything else) is handed to the DoH handler — the router does not steal
        // `/dns-query`, preserving the existing exit-node DoH behavior.
        assert_eq!(classify_route("POST", "/dns-query"), Route::DohOrOther);
        assert_eq!(
            classify_route("GET", "/dns-query?dns=abc"),
            Route::DohOrOther
        );
        assert_eq!(classify_route("GET", "/something-else"), Route::DohOrOther);
    }

    #[test]
    fn taildrop_ok_response_is_exact() {
        // Success is HTTP 200 with body exactly `{}\n` and Content-Length 3 (Go `taildropResp`).
        let resp = taildrop_ok_response();
        let text = String::from_utf8(resp).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Content-Length: 3\r\n"));
        assert!(text.ends_with("\r\n\r\n{}\n"));
    }

    // ---------------------------------------------------------------------------------------------
    // Request → response path coverage.
    //
    // The netstack `netsock::TcpStream` is a concrete struct with a `pub(crate)` constructor that
    // needs a live `netcore::Channel` + `SocketHandle`; it cannot be built from a
    // `tokio::io::duplex` half. `route_conn` / `handle_taildrop_put` are hard-typed to it, so a
    // single end-to-end duplex drive of those two functions is infeasible without changing their
    // production signatures (which we will not do gratuitously). Instead we exercise the request →
    // response path at the seams the types allow:
    //
    //  * `taildrop_request_path` below reproduces exactly the decision sequence that
    //    `route_conn` + `handle_taildrop_put` walk (classify → gate → content-length → name
    //    validation via `put_file`), driving the body over a real `tokio::io::duplex` async stream
    //    through the production `BodyReader` and the production `TaildropStore::put_file`, and
    //    emitting the production response bytes. This covers 200/403/400/405 and the file landing in
    //    the store.
    //  * `body_reader_caps_at_content_length` drives the production `BodyReader` (now generic) over
    //    a `tokio::io::duplex` half whose source is LARGER than the declared length, asserting only
    //    `content_length` bytes are delivered.
    //  * `dns_query_post_is_not_taildrop_405_or_404` asserts the DoH POST still reaches the DoH path
    //    (a `DohOrOther` route, never `405`/Taildrop), the regression guard requested for the
    //    refactor.

    use crate::taildrop::TaildropStore;

    fn tmp_store() -> (std::path::PathBuf, Arc<TaildropStore>) {
        let mut root = std::env::temp_dir();
        root.push(format!(
            "peerapi-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = Arc::new(TaildropStore::new(&root).unwrap());
        (root, store)
    }

    /// Drive the exact decision sequence of `route_conn` → `handle_taildrop_put` against a real
    /// async body stream, returning the production response status line (first line) plus body. This
    /// mirrors the production control flow seam-for-seam: classify the route, run the gate, require a
    /// Content-Length, then stream the `BodyReader` into `TaildropStore::put_file` and map the result
    /// through the same status codes.
    async fn taildrop_request_path(
        method: &str,
        full_path: &str,
        content_length: Option<u64>,
        body: &[u8],
        store: Option<Arc<TaildropStore>>,
        view: &DnsView,
        src: SocketAddr,
    ) -> (String, Vec<u8>) {
        // Status helper mirroring `peerapi_doh::write_status`'s wire shape closely enough for the
        // assertions (status line is what we check).
        fn status(code: &str) -> (String, Vec<u8>) {
            (format!("HTTP/1.1 {code}"), Vec::new())
        }

        match classify_route(method, full_path) {
            Route::TaildropMethodNotAllowed => status("405 Method Not Allowed"),
            Route::DohOrOther => status("DOH"), // would be handed to the DoH handler
            Route::TaildropPut { name } => {
                // Gate (fail-closed): no store → 403; gate Deny → 403.
                let Some(store) = store else {
                    return status("403 Forbidden");
                };
                if gate_taildrop(view, src, true) == GateDecision::Deny {
                    return status("403 Forbidden");
                }
                let Some(content_length) = content_length else {
                    return status("400 Bad Request");
                };

                // Real async stream carrying the body, fed through the production BodyReader.
                let (mut client, server) = tokio::io::duplex(64 * 1024);
                let body = body.to_vec();
                tokio::spawn(async move {
                    client.write_all(&body).await.ok();
                    client.shutdown().await.ok();
                });
                let reader = BodyReader::new(Vec::new(), server, content_length);

                match store.put_file(&name, reader, 0).await {
                    Ok(_) => {
                        let resp = taildrop_ok_response();
                        // Split off the status line + body for the assertions.
                        let text = String::from_utf8_lossy(&resp).into_owned();
                        let line = text.lines().next().unwrap_or("").to_string();
                        (line, b"{}\n".to_vec())
                    }
                    Err(TaildropError::InvalidFileName) => status("400 Bad Request"),
                    Err(TaildropError::FileExists) => status("409 Conflict"),
                    Err(TaildropError::Io(_)) => status("500 Internal Server Error"),
                }
            }
        }
    }

    #[tokio::test]
    async fn put_request_allowed_writes_file_and_200() {
        let (root, store) = tmp_store();
        let view = view_with(true, &["100.64.0.9".parse().unwrap()]);
        let body = b"hello over the wire";

        let (line, resp_body) = taildrop_request_path(
            "PUT",
            "/v0/put/wire.txt",
            Some(body.len() as u64),
            body,
            Some(store.clone()),
            &view,
            src("100.64.0.9"),
        )
        .await;

        assert_eq!(line, "HTTP/1.1 200 OK");
        assert_eq!(resp_body, b"{}\n");
        // The file landed in the store with the exact body.
        assert_eq!(std::fs::read(root.join("wire.txt")).unwrap(), body);

        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn put_request_denied_by_gate_is_403() {
        let view = view_with(true, &["100.64.0.9".parse().unwrap()]);

        // No store configured → 403.
        let (line, _) = taildrop_request_path(
            "PUT",
            "/v0/put/x.txt",
            Some(1),
            b"x",
            None,
            &view,
            src("100.64.0.9"),
        )
        .await;
        assert_eq!(line, "HTTP/1.1 403 Forbidden");

        // Store present but node lacks the file-sharing cap → gate Deny → 403.
        let (root, store) = tmp_store();
        let no_cap = view_with(false, &["100.64.0.9".parse().unwrap()]);
        let (line, _) = taildrop_request_path(
            "PUT",
            "/v0/put/x.txt",
            Some(1),
            b"x",
            Some(store),
            &no_cap,
            src("100.64.0.9"),
        )
        .await;
        assert_eq!(line, "HTTP/1.1 403 Forbidden");
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn put_request_with_bad_name_is_400() {
        let (root, store) = tmp_store();
        let view = view_with(true, &["100.64.0.9".parse().unwrap()]);

        // `../escape` percent-encoded as `%2E%2E%2Fescape`; classify percent-decodes it to
        // `../escape`, which `put_file` rejects → InvalidFileName → 400.
        let (line, _) = taildrop_request_path(
            "PUT",
            "/v0/put/%2E%2E%2Fescape",
            Some(1),
            b"x",
            Some(store),
            &view,
            src("100.64.0.9"),
        )
        .await;
        assert_eq!(line, "HTTP/1.1 400 Bad Request");
        // Nothing escaped the store root.
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn get_on_taildrop_path_is_405() {
        let view = view_with(true, &["100.64.0.9".parse().unwrap()]);
        let (root, store) = tmp_store();
        let (line, _) = taildrop_request_path(
            "GET",
            "/v0/put/x.txt",
            Some(1),
            b"x",
            Some(store),
            &view,
            src("100.64.0.9"),
        )
        .await;
        assert_eq!(line, "HTTP/1.1 405 Method Not Allowed");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn dns_query_post_is_not_taildrop_405_or_404() {
        // Regression guard for the refactor: a DoH POST must not be stolen by the Taildrop router; it
        // classifies as `DohOrOther` and is handed to the DoH handler (it never short-circuits to
        // 405 or a Taildrop response in `route_conn`).
        assert_eq!(classify_route("POST", "/dns-query"), Route::DohOrOther);
        assert_eq!(classify_route("POST", "/dns-query?x=1"), Route::DohOrOther);
    }

    #[tokio::test]
    async fn body_reader_caps_at_content_length() {
        // Feed a source LARGER than the declared length over a real async duplex stream and assert
        // the production `BodyReader` delivers exactly `content_length` bytes (the cap holds, so a
        // peer can't smuggle bytes past the declared body into `put_file`).
        let declared: u64 = 8;
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            // 20 bytes available, only 8 should be read.
            client.write_all(b"01234567OVERFLOW1234").await.ok();
            client.shutdown().await.ok();
        });

        let mut reader = BodyReader::new(Vec::new(), server, declared);
        let mut out = Vec::new();
        let mut chunk = [0u8; 4];
        loop {
            let n = tokio::io::AsyncReadExt::read(&mut reader, &mut chunk)
                .await
                .unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&chunk[..n]);
        }
        assert_eq!(out, b"01234567");
        assert_eq!(out.len() as u64, declared);
    }

    #[tokio::test]
    async fn body_reader_includes_seed_then_caps() {
        // The seed bytes (already read while parsing headers) count toward the cap: seed=3, declared
        // total=6, stream supplies more but is capped so total delivered == 6 (seed first, then 3
        // stream bytes). Drive it with the same fixed-buffer read loop `put_file` uses (production's
        // actual read pattern) rather than `read_to_end`.
        let declared: u64 = 6;
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            client.write_all(b"XXXXXXXXXX").await.ok(); // plenty, will be capped
            client.shutdown().await.ok();
        });
        let mut reader = BodyReader::new(b"abc".to_vec(), server, declared);
        let mut out = Vec::new();
        let mut chunk = [0u8; 4];
        loop {
            let n = tokio::io::AsyncReadExt::read(&mut reader, &mut chunk)
                .await
                .unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&chunk[..n]);
        }
        assert_eq!(out.len() as u64, declared);
        assert_eq!(out, b"abcXXX");
    }
}
