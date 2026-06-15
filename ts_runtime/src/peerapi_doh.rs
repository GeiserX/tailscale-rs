//! peerAPI DoH server (`/dns-query`) — the exit-node DNS-proxy half of Go tsnet's peerAPI.
//!
//! When this node is selected as another peer's exit node, that peer routes its non-MagicDNS
//! lookups to us over the overlay as RFC 8484 DNS-over-HTTPS (here plain HTTP/1.1 over the
//! encrypted WireGuard overlay — exactly what Go does: `http://<peer-ip>:<peerapi>/dns-query`). We
//! bind a TCP listener on this node's overlay IPv4 at [`Config::peerapi_port`][ts_control::Config::peerapi_port]
//! and answer those queries.
//!
//! ## What we answer
//!
//! The request DNS bytes are fed through the **same** [`decide`] used by the local MagicDNS
//! responder, so authoritative MagicDNS records (peer names, control-pushed `ExtraRecords`, PTR)
//! are answered locally here.
//!
//! ### Deliberate divergence from Go (and why blanket forward-only would be unsafe)
//!
//! Go's exit-node DNS proxy (`HandlePeerDNSQuery` in `net/dns/resolver/tsdns.go`) is a **pure
//! recursive forwarder**: after the filtered-set check it forwards every allowed name to the OS
//! stub resolver and never answers a name authoritatively from MagicDNS. This fork instead reuses
//! the shared `decide`, so for a routed peer it *does* answer the exit node's own peer
//! names / `ExtraRecords` / PTR locally. The only observable consequence is that a routed client
//! asking this exit node's DoH for one of the **exit node's own** tailnet peer names gets a positive
//! answer where Go would forward it to upstream — a narrow MagicDNS-namespace bleed across the exit
//! boundary (no leak: the answer comes from local netmap data and never touches a host socket).
//!
//! Matching Go by making this path blanket forward-only would be a **regression in the unsafe
//! direction**: `decide`'s authoritative replies include this fork's anti-leak guards — a PTR for a
//! tailnet CGNAT IP (`100.64.0.0/10`) that misses the peer set, and any `ip6.arpa` reverse, are
//! answered `NXDOMAIN` precisely so a probed tailnet address is never relayed to an upstream
//! resolver. A forward-only rewrite that simply dropped the authoritative step would forward those
//! tailnet-reverse queries upstream and leak the probed IP. A faithful narrowing must therefore
//! forward only the *peer-name / ExtraRecord* authoritative cases while keeping the CGNAT/`ip6.arpa`
//! NXDOMAIN guards — tracked as a follow-up, not the blanket change. (Go's OS-stub-resolver forward
//! target is also unavailable here; this path forwards to the tailnet's configured resolvers.)
//!
//! Two server-side rules layer on top:
//!
//! - **Exit-node filtered set** ([`DnsConfig::exit_node_filters`]): a name in control's
//!   `ExitNodeFilteredSet` is `REFUSED` before anything else (Go `dnsConfigForNetmap`'s filter).
//! - **Recursive egress is gated** ([`Env::forward_exit_egress`]): a query that `decide` would
//!   forward to a real upstream resolver only proceeds when this node has explicitly opted into
//!   exit egress. Otherwise it is `REFUSED` — **fail-closed**. This is the same anti-leak opt-in
//!   that governs the TCP exit path: a cloud exit node (default `forward_exit_egress == false`)
//!   never resolves a peer's public name through its real host resolver, so the cloud host's real
//!   IP can't leak. A residential node that sets `forward_exit_egress = true` opts into serving
//!   recursion, and that recursion goes out over the **overlay** netstack (same as MagicDNS), never
//!   a bare host socket.
//!
//! ## Two paths for a forwarded client's DNS (tsr-c39)
//!
//! Exit-node DNS for a routed client is **client-side** in Go, and there are exactly two paths — we
//! implement both, neither requiring exit-side DNS interception:
//! 1. **DoH delegation (this server).** A modern client redirects its catch-all resolver to this
//!    node's `/dns-query` (Go `dnsConfigForNetmap`/`exitNodeCanProxyDNS`); we answer here.
//! 2. **Raw UDP:53 forwarding.** If the client instead emits a plain DNS datagram to a public
//!    resolver, it is just part of the `0.0.0.0/0` traffic the [`crate::forwarder`] forwards — the
//!    forwarder does **not** special-case port 53, so it egresses via the same dialer (host IP, or a
//!    residential proxy) as all other forwarded traffic, fail-closed under `DirectDialer`. So a
//!    forwarded client's DNS always shares the forwarded-traffic egress; there is no separate DNS
//!    egress that could leak the origin IP (asserted by `ts_forwarder`'s antileak_runtime tests).
//!
//! ## Anti-leak / IPv6-off
//!
//! The listener binds the overlay IPv4 only. Recursive forwarding reuses [`forward_query`], which
//! binds `0.0.0.0:0` on the overlay netstack — never a host socket. A saturated server drops the
//! flow (fail-closed). Requests are size-capped; one request is answered per connection then it is
//! closed.

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use base64::Engine;
use netstack::{CreateSocket, netcore::Channel, netsock::TcpStream};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::watch,
    time::timeout,
};
use ts_dns_wire::{Rcode, decode_query, encode_response};

use crate::magic_dns::{Decision, DnsView, decide, forward_query};

/// Largest HTTP request (headers + body) we will read for one DoH query. A DNS message is at most
/// 64 KiB, but a peerAPI DoH query is a single small question; cap well below that to bound memory
/// and reject abuse. Anything larger is answered `413` and the connection closed.
const MAX_REQUEST: usize = 8 * 1024;

/// How long the DoH *client* waits for the exit node to answer a delegated query before giving up
/// and returning the fallback NXDOMAIN. Matches the local UDP upstream timeout.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);

/// Cap on a DoH response body we read into memory from the exit node. A delegated answer is one DNS
/// message; cap it at the DNS-over-TCP max (64 KiB) so a misbehaving/hostile exit node can't make us
/// allocate without bound. Anything past this is treated as a failure (NXDOMAIN).
const MAX_CLIENT_RESPONSE: usize = 64 * 1024;

/// Delegate a recursive DNS `query` to an exit node's peerAPI DoH endpoint at `doh_addr`, over the
/// overlay netstack `channel`. Returns the exit node's DNS answer bytes, or the caller-supplied
/// `fallback` buffer on any failure (connect, write, malformed HTTP, timeout) — **fail-closed,
/// never a fallback to a local resolver**: when an exit node is selected, recursive DNS must egress
/// from the exit node, so a failure here resolves to the `fallback` rather than silently leaking the
/// query (and this host's real IP) to a local upstream. The caller supplies the rcode: the client
/// recursive path passes a SERVFAIL (a forward failure is soft, not a cacheable non-existence).
///
/// Anti-leak: the connection is made over the overlay (`channel.tcp_connect(0.0.0.0:0, doh_addr)`),
/// so it rides the encrypted WireGuard tunnel to the peer — never a host socket. IPv4-only:
/// `doh_addr` is always the peer's tailnet IPv4 (see [`Node::peerapi_doh_addr`]).
pub(crate) async fn forward_doh(
    channel: &Channel,
    doh_addr: SocketAddr,
    query: &[u8],
    fallback: Vec<u8>,
) -> Vec<u8> {
    match timeout(CLIENT_TIMEOUT, doh_round_trip(channel, doh_addr, query)).await {
        Ok(Ok(resp)) if !resp.is_empty() => resp,
        Ok(Ok(_)) => {
            // A broken exit-node recursive resolver silently fails every delegated query, so
            // surface delegation failures at warn (default level) — the operator needs the signal.
            tracing::warn!(%doh_addr, "peerapi doh client: empty response from exit node");
            fallback
        }
        Ok(Err(e)) => {
            tracing::warn!(error = %e, %doh_addr, "peerapi doh client: delegation failed");
            fallback
        }
        Err(_) => {
            tracing::warn!(%doh_addr, "peerapi doh client: delegation timed out");
            fallback
        }
    }
}

/// Perform one DoH `POST /dns-query` round trip to `doh_addr` over the overlay and return the
/// response body (the DNS answer). Errors on connect/write/read failure or a malformed HTTP reply.
async fn doh_round_trip(
    channel: &Channel,
    doh_addr: SocketAddr,
    query: &[u8],
) -> std::io::Result<Vec<u8>> {
    let local = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0);
    let mut stream = channel
        .tcp_connect(local, doh_addr)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    let request = format!(
        "POST /dns-query HTTP/1.1\r\nHost: {doh_addr}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        query.len()
    );
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(query).await?;
    stream.flush().await?;

    read_doh_response(&mut stream).await
}

/// Read an HTTP/1.1 DoH response from `stream` and return its body (the DNS answer). Requires a
/// `200` status; any other status, a missing/oversized body, or a malformed response is an error
/// (the caller maps that to NXDOMAIN — fail-closed). Reads the body by `Content-Length`.
async fn read_doh_response(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];

    let header_end = loop {
        if let Some(pos) = find_header_end(&buf) {
            break pos;
        }
        if buf.len() > MAX_CLIENT_RESPONSE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "doh response headers too large",
            ));
        }
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "eof before doh response headers",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    };

    let content_length = parse_response_head(&buf)?;

    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "eof before doh response body complete",
            ));
        }
        body.extend_from_slice(&tmp[..n]);
        if body.len() > MAX_CLIENT_RESPONSE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "doh response body too large",
            ));
        }
    }
    body.truncate(content_length);
    Ok(body)
}

/// Parse an HTTP/1.1 DoH response head from `buf` (which must contain the full headers) and return
/// its declared `Content-Length`. Requires a `200` status and a parseable `Content-Length` within
/// [`MAX_CLIENT_RESPONSE`]; any other status, a missing/unparseable length, or an oversized body is
/// an error (the caller maps that to NXDOMAIN — fail-closed). Pure so it is unit-testable without a
/// live `TcpStream`.
fn parse_response_head(buf: &[u8]) -> std::io::Result<usize> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers);
    match resp.parse(buf) {
        Ok(httparse::Status::Complete(_)) => {}
        Ok(httparse::Status::Partial) | Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "malformed doh response headers",
            ));
        }
    }

    if resp.code != Some(200) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("doh response status {:?}", resp.code),
        ));
    }

    let content_length = resp
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-length"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .and_then(|v| v.trim().parse::<usize>().ok())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "doh response missing length",
            )
        })?;

    if content_length > MAX_CLIENT_RESPONSE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "doh response body too large",
        ));
    }

    Ok(content_length)
}

/// Service one DoH connection: read the HTTP request, resolve the DNS query, write the response.
/// Closes the connection afterward (one request per connection).
///
/// `seed` carries the header bytes the shared peerAPI router ([`crate::peerapi`]) already read off
/// the stream while it determined the route, and `header_end` is the offset just past the
/// `\r\n\r\n` header terminator within `seed`. The DoH parser resumes from there, so no bytes are
/// lost when the router hands the connection over.
pub(crate) async fn handle_conn(
    mut stream: TcpStream,
    seed: Vec<u8>,
    header_end: usize,
    channel: &Channel,
    view_rx: &watch::Receiver<Arc<DnsView>>,
    forward_exit_egress: bool,
) -> std::io::Result<()> {
    let request = match read_request(&mut stream, seed, header_end).await? {
        Some(r) => r,
        None => return Ok(()),
    };

    let query = match request {
        DohRequest::TooLarge => {
            return write_status(&mut stream, "413 Payload Too Large").await;
        }
        DohRequest::BadRequest => {
            return write_status(&mut stream, "400 Bad Request").await;
        }
        DohRequest::NotFound => {
            return write_status(&mut stream, "404 Not Found").await;
        }
        DohRequest::Query(bytes) => bytes,
    };

    let view = view_rx.borrow().clone();
    let response = resolve(&view, &query, channel, forward_exit_egress).await;
    write_dns_response(&mut stream, &response).await
}

/// Resolve a DoH DNS query against `view`, applying the exit-node filtered set and the recursive
/// egress gate. Returns the DNS wire response bytes.
///
/// - Malformed query => `FORMERR` (we still answer something parseable to the peer, never hang).
/// - Filtered name => `REFUSED` (Go `ExitNodeFilteredSet`).
/// - Authoritative answer => returned as-is from [`decide`].
/// - Recursive forward when `forward_exit_egress` is false => `REFUSED` (fail-closed, no leak).
/// - Recursive forward when enabled => forwarded over the overlay via [`forward_query`].
async fn resolve(
    view: &DnsView,
    query: &[u8],
    channel: &Channel,
    forward_exit_egress: bool,
) -> Vec<u8> {
    match server_decide(view, query, forward_exit_egress) {
        ServerDecision::Reply(resp) => resp,
        ServerDecision::Forward {
            upstreams,
            query,
            servfail,
        } => forward_query(channel, &upstreams, &query, servfail).await,
    }
}

/// The server-side decision for a DoH query: either a complete response (authoritative answer,
/// `REFUSED`, or `FORMERR`) or a request to forward over the overlay.
///
/// Unlike [`decide`], this also applies the two exit-node-server rules: the
/// [`ExitNodeFilteredSet`][DnsConfig::exit_node_filters] (`REFUSED`) and the recursive-egress gate
/// (`REFUSED` unless `forward_exit_egress`). Pure (no I/O) so both rules are unit-testable.
enum ServerDecision {
    Reply(Vec<u8>),
    Forward {
        upstreams: Vec<SocketAddr>,
        query: Vec<u8>,
        /// Fallback response if every upstream fails — a SERVFAIL, carried over from the shared
        /// [`Decision::Forward`]: an off-tailnet name the exit-node DoH server couldn't forward is a
        /// soft failure, not a cacheable non-existence.
        servfail: Vec<u8>,
    },
}

fn server_decide(view: &DnsView, query: &[u8], forward_exit_egress: bool) -> ServerDecision {
    let Ok(decoded) = decode_query(query) else {
        // We can't parse it; answer FORMERR with a best-effort echo of the id if present.
        let id = if query.len() >= 2 {
            u16::from_be_bytes([query[0], query[1]])
        } else {
            0
        };
        return ServerDecision::Reply(encode_formerr(id));
    };

    let canon = decoded.question.name.to_canon();

    // Server-side: a name in control's ExitNodeFilteredSet must never be answered by an exit-node
    // DNS proxy.
    if view.cfg.exit_node_filters(&canon) {
        return ServerDecision::Reply(encode_response(
            decoded.id,
            &decoded.question,
            decoded.recursion_desired,
            Rcode::Refused,
            &[],
        ));
    }

    match decide(view, query) {
        // Malformed (already handled above) — decide drops it; answer FORMERR defensively.
        None => ServerDecision::Reply(encode_formerr(decoded.id)),
        Some(Decision::Reply(resp)) => ServerDecision::Reply(resp),
        Some(Decision::Forward {
            upstreams,
            query,
            servfail,
            // The exit-node DNS proxy resolves recursively itself; it never re-delegates to its own
            // exit node, so the client-side recursive flag is irrelevant here.
            recursive: _,
        }) => {
            // Recursive resolution to a real upstream. Gated behind the same anti-leak opt-in as
            // the TCP exit path: a node that hasn't opted into exit egress must NOT resolve a
            // peer's public name through its own resolver (would expose its real IP). Fail-closed.
            if !forward_exit_egress {
                return ServerDecision::Reply(encode_response(
                    decoded.id,
                    &decoded.question,
                    decoded.recursion_desired,
                    Rcode::Refused,
                    &[],
                ));
            }
            ServerDecision::Forward {
                upstreams,
                query,
                servfail,
            }
        }
    }
}

/// A `FORMERR` (format error, RCODE 1) response carrying only the transaction id. Used when the
/// request body isn't a decodable DNS query, so the peer gets a definite (non-hanging) answer.
fn encode_formerr(id: u16) -> Vec<u8> {
    // 12-byte header: id, flags (QR=1, RCODE=1=FORMERR), zeroed counts.
    let mut msg = vec![0u8; 12];
    msg[0..2].copy_from_slice(&id.to_be_bytes());
    msg[2] = 0x80; // QR=1 (response)
    msg[3] = 0x01; // RCODE = FORMERR
    msg
}

/// The parsed outcome of reading one DoH HTTP request.
enum DohRequest {
    /// A valid DNS query body to resolve.
    Query(Vec<u8>),
    /// The request exceeded [`MAX_REQUEST`].
    TooLarge,
    /// The request was malformed, used an unsupported method, or had a bad `dns` parameter.
    BadRequest,
    /// The path was not `/dns-query`.
    NotFound,
}

/// Parse one DoH HTTP/1.1 request, given the header bytes already read by the shared peerAPI router
/// in `buf` (with `header_end` the offset just past `\r\n\r\n`). Supports `POST /dns-query` (body is
/// the raw DNS message, `Content-Type: application/dns-message`) and `GET /dns-query?dns=<base64url>`
/// (RFC 8484). Reads any remaining body bytes from `stream`. Returns `Ok(None)` if the peer closed
/// before sending a full request.
async fn read_request(
    stream: &mut TcpStream,
    buf: Vec<u8>,
    header_end: usize,
) -> std::io::Result<Option<DohRequest>> {
    let mut tmp = [0u8; 1024];

    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);
    let parsed = match req.parse(&buf) {
        Ok(httparse::Status::Complete(n)) => n,
        // We already located \r\n\r\n, so a Partial here means malformed headers.
        Ok(httparse::Status::Partial) => return Ok(Some(DohRequest::BadRequest)),
        Err(_) => return Ok(Some(DohRequest::BadRequest)),
    };
    debug_assert_eq!(parsed, header_end);

    let method = req.method.unwrap_or("");
    let path = req.path.unwrap_or("");

    // Split path and query string.
    let (raw_path, query_str) = match path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path, None),
    };
    if raw_path != "/dns-query" {
        return Ok(Some(DohRequest::NotFound));
    }

    match method {
        "GET" => Ok(Some(parse_get(query_str))),
        "POST" => {
            let content_length =
                header_value(&req, "content-length").and_then(|v| v.trim().parse::<usize>().ok());
            let Some(len) = content_length else {
                return Ok(Some(DohRequest::BadRequest));
            };
            if len > MAX_REQUEST {
                return Ok(Some(DohRequest::TooLarge));
            }
            // The body must be application/dns-message.
            if !header_value(&req, "content-type")
                .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/dns-message"))
            {
                return Ok(Some(DohRequest::BadRequest));
            }

            let mut body = buf[header_end..].to_vec();
            while body.len() < len {
                if buf.len() + tmp.len() > MAX_REQUEST + 1024 {
                    return Ok(Some(DohRequest::TooLarge));
                }
                let n = stream.read(&mut tmp).await?;
                if n == 0 {
                    return Ok(Some(DohRequest::BadRequest));
                }
                body.extend_from_slice(&tmp[..n]);
            }
            body.truncate(len);
            Ok(Some(DohRequest::Query(body)))
        }
        _ => Ok(Some(DohRequest::BadRequest)),
    }
}

/// Parse the `dns` query parameter of a `GET /dns-query` request (RFC 8484: base64url, no padding).
fn parse_get(query_str: Option<&str>) -> DohRequest {
    let Some(qs) = query_str else {
        return DohRequest::BadRequest;
    };
    let Some(dns_param) = qs.split('&').find_map(|kv| kv.strip_prefix("dns=")) else {
        return DohRequest::BadRequest;
    };
    match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(dns_param) {
        Ok(bytes) if bytes.len() <= MAX_REQUEST => DohRequest::Query(bytes),
        Ok(_) => DohRequest::TooLarge,
        Err(_) => DohRequest::BadRequest,
    }
}

/// Look up a request header value case-insensitively.
fn header_value<'a>(req: &'a httparse::Request<'_, '_>, name: &str) -> Option<&'a str> {
    req.headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .and_then(|h| std::str::from_utf8(h.value).ok())
}

/// Find the byte offset just past the `\r\n\r\n` header terminator, if present. Shared with the
/// peerAPI router ([`crate::peerapi`]).
pub(crate) fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Write a `200 OK` DoH response carrying `dns_msg` as `application/dns-message`.
async fn write_dns_response(stream: &mut TcpStream, dns_msg: &[u8]) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        dns_msg.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(dns_msg).await?;
    stream.flush().await
}

/// Write a bodyless HTTP error response with the given status line (e.g. `"400 Bad Request"`).
/// Shared with the peerAPI router ([`crate::peerapi`]).
pub(crate) async fn write_status(stream: &mut TcpStream, status: &str) -> std::io::Result<()> {
    let head = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    stream.write_all(head.as_bytes()).await?;
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_header_end_locates_terminator() {
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\n\r\n"), Some(18));
        assert_eq!(
            find_header_end(b"GET / HTTP/1.1\r\nX: 1\r\n\r\nBODY"),
            Some(24)
        );
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\n"), None);
    }

    #[test]
    fn parse_get_decodes_base64url_dns_param() {
        // base64url of a 4-byte placeholder query.
        let raw = [0xab, 0xcd, 0x01, 0x00];
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        match parse_get(Some(&format!("dns={encoded}"))) {
            DohRequest::Query(b) => assert_eq!(b, raw),
            _ => panic!("expected Query"),
        }
    }

    #[test]
    fn parse_get_rejects_missing_or_bad_param() {
        assert!(matches!(parse_get(None), DohRequest::BadRequest));
        assert!(matches!(parse_get(Some("foo=bar")), DohRequest::BadRequest));
        assert!(matches!(
            parse_get(Some("dns=!!!notbase64!!!")),
            DohRequest::BadRequest
        ));
    }

    #[test]
    fn parse_response_head_returns_content_length_on_200() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 42\r\nConnection: close\r\n\r\n";
        assert_eq!(parse_response_head(head).unwrap(), 42);
    }

    #[test]
    fn parse_response_head_rejects_non_200() {
        let head = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        assert!(parse_response_head(head).is_err());
    }

    #[test]
    fn parse_response_head_rejects_missing_length() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n\r\n";
        assert!(parse_response_head(head).is_err());
    }

    #[test]
    fn parse_response_head_rejects_oversized_body() {
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_CLIENT_RESPONSE + 1
        );
        assert!(parse_response_head(head.as_bytes()).is_err());
    }

    #[test]
    fn encode_formerr_sets_response_and_rcode() {
        let msg = encode_formerr(0x1234);
        assert_eq!(&msg[0..2], &[0x12, 0x34]);
        assert_eq!(msg[2] & 0x80, 0x80, "QR response bit set");
        assert_eq!(msg[3] & 0x0F, 0x01, "FORMERR rcode");
    }

    use ts_control::DnsConfig;

    /// Build a raw DNS query buffer for `labels` (A/IN).
    fn query_for(id: u16, labels: &[&str]) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes()); // flags: QR=0 (query)
        buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        for label in labels {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0); // root
        buf.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
        buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
        buf
    }

    fn rcode(resp: &[u8]) -> u8 {
        resp[3] & 0x0F
    }

    /// A view with MagicDNS on, one upstream resolver, and the given filtered set.
    fn view(filtered: &[&str]) -> DnsView {
        DnsView {
            cfg: DnsConfig {
                magic_dns: true,
                search_domains: vec!["user.ts.net".to_string()],
                fallback_resolvers: vec![ts_control::DnsResolver {
                    transport: ts_control::ResolverTransport::Udp("9.9.9.9:53".parse().unwrap()),
                    use_with_exit_node: false,
                }],
                exit_node_filtered_set: filtered.iter().map(|s| s.to_string()).collect(),
                ..Default::default()
            },
            // The accept-dns gate defaults to `false` (Default); set it true so these DoH tests
            // exercise the serving/forwarding path, not the gated-off REFUSED path.
            accept_dns: true,
            ..Default::default()
        }
    }

    #[test]
    fn filtered_name_is_refused() {
        let v = view(&["blocked.example.com"]);
        let q = query_for(0x1, &["blocked", "example", "com"]);
        match server_decide(&v, &q, true) {
            ServerDecision::Reply(resp) => assert_eq!(rcode(&resp), 5, "REFUSED"),
            ServerDecision::Forward { .. } => panic!("filtered name must not forward"),
        }
    }

    #[test]
    fn recursive_query_refused_when_egress_disabled() {
        // A public name that would otherwise forward must be REFUSED when this node hasn't opted
        // into exit egress — fail-closed, no leak of the real host IP.
        let v = view(&[]);
        let q = query_for(0x2, &["example", "com"]);
        match server_decide(&v, &q, false) {
            ServerDecision::Reply(resp) => assert_eq!(rcode(&resp), 5, "REFUSED"),
            ServerDecision::Forward { .. } => panic!("must not forward when egress disabled"),
        }
    }

    #[test]
    fn recursive_query_forwards_when_egress_enabled() {
        let v = view(&[]);
        let q = query_for(0x3, &["example", "com"]);
        match server_decide(&v, &q, true) {
            ServerDecision::Forward { upstreams, .. } => {
                assert_eq!(upstreams, vec!["9.9.9.9:53".parse().unwrap()]);
            }
            ServerDecision::Reply(_) => panic!("expected forward when egress enabled"),
        }
    }

    #[test]
    fn authoritative_answer_is_not_gated() {
        // A tailnet name under a search domain is authoritative (NXDOMAIN here since no peer), and
        // is answered regardless of the egress gate — it never forwards.
        let v = view(&[]);
        let q = query_for(0x4, &["host", "user", "ts", "net"]);
        match server_decide(&v, &q, false) {
            ServerDecision::Reply(resp) => assert_eq!(rcode(&resp), 3, "NXDOMAIN, not REFUSED"),
            ServerDecision::Forward { .. } => panic!("tailnet name must not forward"),
        }
    }

    #[test]
    fn unparseable_body_is_formerr() {
        match server_decide(&view(&[]), &[0xAB, 0xCD, 0xFF], true) {
            ServerDecision::Reply(resp) => {
                assert_eq!(&resp[0..2], &[0xAB, 0xCD]);
                assert_eq!(rcode(&resp), 1, "FORMERR");
            }
            ServerDecision::Forward { .. } => panic!("garbage must not forward"),
        }
    }
}
