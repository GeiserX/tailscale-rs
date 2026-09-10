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
//! A peer control has marked with the `dns-subdomain-resolve` node attribute widens that same bleed
//! by the names *under* its own name and nothing else, from the same netmap data (the walk in
//! `DnsView::subdomain_host_for`).
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
//! ## Which peers we answer at all
//!
//! Before any of that: a peerAPI DNS query is refused `403` unless the querying peer would be
//! accepted by the live packet filter for TCP port 53 to an off-tailnet destination — Go's
//! `isPeerAPIDNSAllowed` (`ipn/ipnlocal/peerapi.go`), evaluated once per connection in
//! [`dns_source_allowed`]. It is a gate on *which peers*, orthogonal to the divergence above about
//! *which names*: control's ACL has to actually grant that peer internet access through this node
//! before we resolve anything for it, recursive or authoritative.
//!
//! Two more server-side rules, on the *names* rather than the peer, layer on top:
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
use ts_packetfilter::FilterExt;

use crate::{
    magic_dns::{
        ClientTransport, Decision, DnsView, check_response_size_and_set_tc, decide, forward_query,
    },
    packetfilter::LiveFilterRx,
};

/// Largest HTTP request (headers + body) we will read for one DoH query. A DNS message is at most
/// 65,535 bytes, but a peerAPI DoH query is a single small question; cap well below that to bound
/// memory and reject abuse. Anything larger is answered `413` and the connection closed.
const MAX_REQUEST: usize = 8 * 1024;

/// How long the DoH *client* waits for the exit node to answer a delegated query before giving up
/// and returning the fallback NXDOMAIN. Matches the local UDP upstream timeout.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);

/// The transport family this node answers a peer's DoH query as — Go's `family` argument, threaded
/// into `checkResponseSizeAndSetTC`. `Resolver.HandlePeerDNSQuery` forwards a peer's query with
/// `packet{q, "tcp", from}`, so the size check is a no-op for everything the DoH *server* returns.
///
/// It is not a claim that HTTP is TCP. It is a claim about *whose* datagram budget is at stake: the
/// peer that POSTed the query holds it, and runs its own `checkResponseSizeAndSetTC` over our answer
/// against its own client's family before relaying it onward. Marking the answer here as well would
/// set `TC` on a reply the peer's client can receive perfectly well, sending it off to a TCP retry
/// it has no reason to make.
const PEER_CLIENT_TRANSPORT: ClientTransport = ClientTransport::Tcp;

/// Cap on a DoH response body we read into memory from the exit node. A delegated answer is one DNS
/// message, and a DNS message is at most 65,535 bytes — that is all a DNS-over-TCP two-byte length
/// prefix (RFC 1035 §4.2.2) can frame. Capping here bounds the allocation a misbehaving/hostile exit
/// node can force *and* keeps every delegated answer relayable: a 65,536-byte body is not a DNS
/// message we could ever put back on the wire to a TCP stub resolver, so it is rejected at the read
/// rather than carried to [`crate::dns_over_tcp`] where the framing would fail and take the client's
/// connection down with it. Anything past this is treated as a failure (the caller's `fallback`).
const MAX_CLIENT_RESPONSE: usize = u16::MAX as usize;

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
///
/// When the delegated answer is relayed back to a **UDP** stub resolver it is marked truncated if
/// it exceeds the buffer size `query` advertised (see [`check_response_size_and_set_tc`]), exactly
/// as on the plain UDP forward. The DoH transport itself has no such limit; the limit belongs to the
/// client we answer, not to the hop we fetched over — which is why `client` selects it, and why a
/// [`ClientTransport::Tcp`] client (RFC 7766 §8: no message-size bound) is never marked. Upstream
/// does the same: Go's `forwarder.send` calls `checkResponseSizeAndSetTC(res, fq.packet, fq.family)`
/// on the `http://` (peerAPI DoH) branch, and `fq.family` is the *requesting client's* transport,
/// not HTTP.
pub(crate) async fn forward_doh(
    channel: &Channel,
    doh_addr: SocketAddr,
    query: &[u8],
    fallback: Vec<u8>,
    client: ClientTransport,
) -> Vec<u8> {
    match timeout(CLIENT_TIMEOUT, doh_round_trip(channel, doh_addr, query)).await {
        Ok(Ok(resp)) if !resp.is_empty() => check_response_size_and_set_tc(query, resp, client),
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
///
/// The querying peer is gated once, here, before any resolution: see [`dns_source_allowed`], which
/// answers `403` for a peer control's ACL does not grant internet access through this node.
pub(crate) async fn handle_conn(
    mut stream: TcpStream,
    seed: Vec<u8>,
    header_end: usize,
    channel: &Channel,
    view_rx: &watch::Receiver<Arc<DnsView>>,
    filter_rx: &LiveFilterRx,
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
    // Both `borrow()` guards are dropped at the end of their own `let` — a `watch::Ref` is not
    // `Send`, and this task is spawned.
    let filter = filter_rx.borrow().clone();

    // The source gate, run once for this connection *before* anything is resolved — Go's
    // `handleDNSQuery` answering `403` when `isPeerAPIDNSAllowed` says no.
    let src = stream.remote_addr().ip();
    if !dns_source_allowed(&view, filter.as_ref().map(|f| &*f.0), src) {
        tracing::debug!(
            %src,
            "peerapi doh: 403, the ACL does not grant this peer internet access through us"
        );
        return write_status(&mut stream, "403 Forbidden").await;
    }

    let response = resolve(&view, &query, channel, forward_exit_egress).await;
    write_dns_response(&mut stream, &response).await
}

/// Go `packet.TCPSyn`: the SYN bit of a TCP flags byte. `CheckTCP` builds its probe packet with
/// exactly this flag set, so the probe is a connection *opening* — the one segment an inbound ACL
/// has any say over.
const TCP_SYN_FLAG: u8 = 0x02;

/// The destination a `CheckTCP` probe for a `src` of this family names — Go's
/// `isPeerAPIDNSAllowed`: `0.0.0.0` for an IPv4 peer, `2000::` for an IPv6 one. Both are
/// off-tailnet (outside `100.64.0.0/10` / `fd7a:115c:a1e0::/48`) and outside any private range, so
/// a rule matches them only if it grants this peer the *internet* through us — which is exactly the
/// question being asked. `2000::` is the base of the IANA global-unicast block, chosen upstream for
/// that reason.
fn internet_probe_dst(src: std::net::IpAddr) -> std::net::IpAddr {
    match src {
        std::net::IpAddr::V4(_) => std::net::Ipv4Addr::UNSPECIFIED.into(),
        std::net::IpAddr::V6(_) => std::net::Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0).into(),
    }
}

/// Whether the peer at `src` may have its DNS queries answered by this node's peerAPI DoH server at
/// all — the port of Go's `isPeerAPIDNSAllowed` (`ipn/ipnlocal/peerapi.go`), which `handleDNSQuery`
/// runs ahead of any resolution and answers `403 DNS access denied` when it refuses.
///
/// Upstream needs this check *inside* the handler because peerAPI deliberately bypasses the packet
/// filter: `net/tstun/wrap.go` flips an ACL-refused inbound SYN back to `Accept` when its
/// destination is the peerAPI port ("Let peerapi through the filter; its ACLs are handled at L7, not
/// at the packet level"). This fork has no such packet-level carve-out — a peer only reaches this
/// port if the ACL already admits it there — but the common tailnet policy is permissive about
/// *ports* and specific about *internet access*, and it is internet access that a DNS proxy hands
/// out. So the L7 check is still the only thing that asks the right question, and without it any
/// peer that can open a TCP connection to the peerAPI port gets recursive resolution through this
/// node's resolvers (on an exit-egress node) and authoritative MagicDNS answers for this node's
/// tailnet names (on any node).
///
/// Two conditions, both fail-closed:
///
/// 1. `src` must resolve to a node in the current netmap — Go's peerAPI listener resolves the
///    connection's source to a peer (`WhoIs`) before a handler ever runs and drops the connection
///    when it cannot. Same lookup the Taildrop and ingress gates use
///    ([`PeerDb::get`][crate::peer_tracker::PeerDb::get] by tailnet IP, i.e.
///    `PeerTracker::peer_by_tailnet_ip`), so an unknown source is refused before the ACL is asked.
///    This node's *own* address is not special-cased the way the Taildrop and ingress gates do it:
///    nothing dials our own peerAPI DoH (the MagicDNS client delegates to the active exit node,
///    which is a peer), so admitting it would only widen the surface.
/// 2. The live packet filter must accept a TCP SYN from `src` to
///    [`internet_probe_dst`]`:53` — Go's `filter.CheckTCP(remoteIP, 0.0.0.0-or-2000::, 53) ==
///    Accept`. No filter yet (no netmap since start) is a refusal, as it is upstream (`f == nil`).
///
/// **Go's self arm is deliberately not ported.** Upstream short-circuits to allow when the peer is
/// untagged and owned by the same user as this node (`IsSelfUntagged`, tightened from a plain
/// `isSelf` by commit `a4c790224` so a *tagged* node no longer gets the shortcut). This fork carries
/// no self/owner notion on the peerAPI path — `Node::user_id` is present but nothing here
/// establishes "the same user" the way Go's profile state does — so a same-user peer is admitted by
/// the ACL like any other. That is the strictly safer reading of the two: the arm we skip only ever
/// *widens* upstream's answer.
///
/// Pure (no I/O) so both directions are unit-testable.
pub(crate) fn dns_source_allowed(
    view: &DnsView,
    filter: Option<&(dyn ts_packetfilter::Filter + Send + Sync)>,
    src: std::net::IpAddr,
) -> bool {
    if view.peers.as_ref().and_then(|p| p.get(&src)).is_none() {
        tracing::debug!(%src, "peerapi doh: source is not a known tailnet peer");
        return false;
    }

    // Go: `f := b.filterAtomic.Load(); if f == nil { return false }`.
    let Some(filter) = filter else {
        tracing::debug!(%src, "peerapi doh: no packet filter compiled yet; refusing");
        return false;
    };

    let info = ts_packetfilter::PacketInfo {
        src,
        dst: internet_probe_dst(src),
        ip_proto: ts_packetfilter::IpProto::TCP,
        port: 53,
        l4: ts_packetfilter::L4Header::Tcp {
            flags: TCP_SYN_FLAG,
        },
    };

    // Node capabilities are not threaded into the ACL match anywhere in this fork yet (the
    // dataplane's rule match passes an empty set too, `ts_dataplane::inbound_filter_verdict`), so a
    // policy that grants internet access by capability rather than by source prefix will refuse
    // here. Fail-closed, and it moves in step with the dataplane when caps are wired in.
    let caps = [];
    filter.can_access(&info, caps)
}

/// Resolve a DoH DNS query against `view`, applying the exit-node filtered set and the recursive
/// egress gate. Returns the DNS wire response bytes.
///
/// - Malformed query => `FORMERR` (we still answer something parseable to the peer, never hang).
/// - Filtered name => `REFUSED` (Go `ExitNodeFilteredSet`).
/// - Authoritative answer => returned as-is from [`decide`].
/// - Recursive forward when `forward_exit_egress` is false => `REFUSED` (fail-closed, no leak).
/// - Recursive forward when enabled => forwarded over the overlay via [`forward_query`].
///
/// A forwarded answer is **never** marked `TC` for size on this path. We are the DoH *server*, and
/// the peer that POSTed the query is the one holding the datagram budget: it runs its own
/// `checkResponseSizeAndSetTC` over our answer, against its own client's family, before relaying it
/// onward. Upstream draws the line the same way — `Resolver.HandlePeerDNSQuery` forwards with
/// `packet{q, "tcp", from}`, and the family guard at the top of `checkResponseSizeAndSetTC` makes
/// the check a no-op for it. Marking it here would set `TC` on an answer the peer's own client can
/// receive, telling it to retry over a transport it has no reason to reach for.
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
        } => forward_query(channel, &upstreams, &query, servfail, PEER_CLIENT_TRANSPORT).await,
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
            // No SOA: REFUSED asserts nothing about the name, so there is nothing to bound the
            // caching of, and we are not authoritative for a name we are declining to answer.
            None,
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
                    None,
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

    /// A DNS message is at most 65,535 bytes, because that is all a DNS-over-TCP length prefix can
    /// frame. A 65,536-byte delegated body is therefore not a DNS message at all: accept it and
    /// `dns_over_tcp::serve_conn` cannot put a `u16` prefix on it and drops the client's connection
    /// instead of answering. Reject it here, where the failure is a `fallback` the client still
    /// gets.
    #[test]
    fn parse_response_head_rejects_body_too_large_to_frame_over_tcp() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 65536\r\n\r\n";
        assert!(
            parse_response_head(head).is_err(),
            "a 65,536-byte body exceeds the DNS-over-TCP framing limit"
        );

        // ...and one byte less is the largest DNS message there is: still accepted, and it frames.
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 65535\r\n\r\n";
        let len = parse_response_head(head).expect("65,535 bytes is a legal DNS message");
        assert_eq!(len, 65_535);
        assert!(
            u16::try_from(len).is_ok(),
            "every accepted body must fit a two-byte length prefix"
        );
    }

    #[test]
    fn encode_formerr_sets_response_and_rcode() {
        let msg = encode_formerr(0x1234);
        assert_eq!(&msg[0..2], &[0x12, 0x34]);
        assert_eq!(msg[2] & 0x80, 0x80, "QR response bit set");
        assert_eq!(msg[3] & 0x0F, 0x01, "FORMERR rcode");
    }

    /// A peer [`Node`][ts_control::Node] named `<hostname>.user.ts.net` at the given tailnet
    /// prefixes, for the peer db the view resolves sources and names against.
    fn peer_node(hostname: &str, v4: &str, v6: &str) -> ts_control::Node {
        use ts_control::{Node, NodeCapMap, StableNodeId, TailnetAddress};
        Node {
            id: 1,
            stable_id: StableNodeId("n1".to_string()),
            hostname: hostname.to_string(),
            user_id: 0,
            tailnet: Some("user.ts.net".to_string()),
            tags: vec![],
            addresses: vec![v4.parse().unwrap(), v6.parse().unwrap()],
            tailnet_address: TailnetAddress {
                ipv4: v4.parse().unwrap(),
                ipv6: v6.parse().unwrap(),
            },
            node_key: [0u8; 32].into(),
            node_key_expiry: None,
            expired: false,
            online: None,
            last_seen: None,
            key_signature: vec![],
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
            peer_relay: false,
            ssh_host_keys: vec![],
            service_vips: Default::default(),
            unsigned_peer_api_only: false,
        }
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
    fn a_subdomain_host_answers_here_like_any_other_peer_name() {
        // The DoH server shares `decide`, so the `dns-subdomain-resolve` walk reaches this path
        // too: a subdomain of one of *this* node's peers is answered locally, from netmap data,
        // exactly as that peer's own name already is (the documented MagicDNS-namespace bleed at
        // the top of this module — it is the same bleed, one name wider, and it still never
        // touches a host socket). It is authoritative, so the egress gate does not apply.
        use std::sync::Arc;

        use crate::peer_tracker::PeerDb;

        let mut node = peer_node("host", "100.64.0.1/32", "fd7a::1/128");
        node.cap_map
            .insert("dns-subdomain-resolve".to_string(), vec![]);

        let mut db = PeerDb::default();
        db.upsert(&node);
        let mut v = view(&[]);
        v.peers = Some(Arc::new(db));

        let q = query_for(0x9, &["my", "host", "user", "ts", "net"]);
        match server_decide(&v, &q, false) {
            ServerDecision::Reply(resp) => {
                assert_eq!(rcode(&resp), 0, "NoError from the subdomain host");
                assert_eq!(
                    u16::from_be_bytes([resp[6], resp[7]]),
                    1,
                    "one A record, the peer's own address"
                );
                assert_eq!(&resp[resp.len() - 4..], &[100, 64, 0, 1]);
            }
            ServerDecision::Forward { .. } => {
                panic!("an authoritative subdomain answer must not forward")
            }
        }
    }

    /// The DoH *server* never marks a peer's answer truncated for size. Upstream's
    /// `HandlePeerDNSQuery` forwards with family `"tcp"` and the guard at the top of
    /// `checkResponseSizeAndSetTC` drops the check entirely; the peer that asked us runs the same
    /// check itself, against its own client's transport, before relaying our answer onward. Setting
    /// `TC` here would tell that peer's client to retry over a transport it never needed.
    #[test]
    fn a_peers_doh_answer_is_never_marked_truncated_for_size() {
        let query = query_for(0x5, &["example", "com"]);
        let mut answer = query.clone();
        answer[2] |= 0x80; // QR=1
        answer.resize(900, 0xAB); // over the 512 bytes a query with no OPT record advertises

        let out = check_response_size_and_set_tc(&query, answer.clone(), PEER_CLIENT_TRANSPORT);
        assert_eq!(
            out, answer,
            "the DoH server relays the peer's answer byte-for-byte"
        );
        assert_eq!(
            out[2] & 0x02,
            0,
            "TC is the requesting peer's call to make, not ours"
        );
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

    // ---------------------------------------------------------------------------------------------
    // The source gate (Go `isPeerAPIDNSAllowed`).
    //
    // Both directions are tested on purpose: a gate that never refuses and a gate that always
    // refuses look identical from one side. Every refusal below is asserted with
    // `forward_exit_egress = true` and against a query the server *would* have resolved, so what is
    // being measured is the gate and not the egress opt-in.

    /// A ruleset granting `src_pfx` TCP access to `dst_pfx` on `ports`, as control compiles one.
    fn tcp_rule(
        src_pfx: &str,
        dst_pfx: &str,
        ports: std::ops::RangeInclusive<u16>,
    ) -> ts_packetfilter::Rule {
        ts_packetfilter::Rule {
            src: ts_packetfilter::SrcMatch {
                pfxs: vec![src_pfx.parse().unwrap()],
                caps: vec![],
            },
            protos: vec![ts_packetfilter::IpProto::TCP],
            dst: vec![ts_packetfilter::DstMatch {
                ports,
                ips: vec![dst_pfx.parse().unwrap()],
            }],
        }
    }

    /// A live filter carrying `rules`, in the shape the packet-filter updater publishes.
    fn filter_of(
        rules: Vec<ts_packetfilter::Rule>,
    ) -> Arc<dyn ts_packetfilter::Filter + Send + Sync> {
        let mut f = ts_packetfilter::HashbrownFilter::new();
        f.insert("acl".to_string(), rules);
        Arc::new(f)
    }

    /// A view holding one peer at `100.64.0.1`/`fd7a::1` plus one upstream resolver, so a public
    /// name is a genuine `Forward` and a refusal can only have come from the gate.
    fn view_with_peer() -> DnsView {
        let mut db = crate::peer_tracker::PeerDb::default();
        db.upsert(&peer_node("host", "100.64.0.1/32", "fd7a::1/128"));
        let mut v = view(&[]);
        v.peers = Some(Arc::new(db));
        v
    }

    /// What this server does with one `/dns-query` POST. Mirrors `handle_conn`'s sequence at the
    /// seams the types allow — the netstack `TcpStream` cannot be constructed in a unit test (the
    /// same limitation `crate::peerapi`'s tests record) — by calling the two production functions
    /// `handle_conn` calls, in its order: gate first, resolve only if the gate allowed.
    enum Served {
        /// The gate refused: `403`, and `server_decide` was never reached.
        Forbidden,
        /// The gate allowed, and this is what the server decided about the name.
        Dns(ServerDecision),
    }

    fn doh_request_path(
        view: &DnsView,
        filter: Option<&(dyn ts_packetfilter::Filter + Send + Sync)>,
        src: std::net::IpAddr,
        query: &[u8],
        forward_exit_egress: bool,
    ) -> Served {
        if !dns_source_allowed(view, filter, src) {
            return Served::Forbidden;
        }
        Served::Dns(server_decide(view, query, forward_exit_egress))
    }

    #[test]
    fn probe_destination_is_off_tailnet_per_family() {
        // Go: `netip.AddrFrom4([4]byte{})` for a v4 peer, `2000::` for a v6 one.
        assert_eq!(
            internet_probe_dst("100.64.0.1".parse().unwrap()),
            "0.0.0.0".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(
            internet_probe_dst("fd7a::1".parse().unwrap()),
            "2000::".parse::<std::net::IpAddr>().unwrap()
        );
    }

    #[test]
    fn a_peer_the_acl_grants_internet_is_answered() {
        // Control grants this peer the internet through us on port 53 — Go's
        // `CheckTCP(peer, 0.0.0.0, 53) == Accept`. The query is resolved as before.
        let v = view_with_peer();
        let filter = filter_of(vec![tcp_rule("100.64.0.1/32", "0.0.0.0/0", 53..=53)]);
        let src: std::net::IpAddr = "100.64.0.1".parse().unwrap();

        assert!(dns_source_allowed(&v, Some(&*filter), src));

        let q = query_for(0x10, &["example", "com"]);
        match doh_request_path(&v, Some(&*filter), src, &q, true) {
            Served::Dns(ServerDecision::Forward { .. }) => {}
            Served::Dns(ServerDecision::Reply(_)) => panic!("expected the forward it always got"),
            Served::Forbidden => panic!("an ACL-granted peer must still get its answer"),
        }
    }

    #[test]
    fn a_peer_the_acl_denies_gets_403_and_no_resolution() {
        // The common tailnet policy: this peer may reach every port of every tailnet node — which
        // is how it reached the peerAPI port at all — but control grants it no internet access
        // through us. Go refuses its DNS with `403`, and so do we.
        let v = view_with_peer();
        let filter = filter_of(vec![tcp_rule(
            "100.64.0.1/32",
            "100.64.0.0/10",
            0..=u16::MAX,
        )]);
        let src: std::net::IpAddr = "100.64.0.1".parse().unwrap();

        assert!(!dns_source_allowed(&v, Some(&*filter), src));

        // Exit egress is ON, so the refusal below is the source gate's and not the egress opt-in's:
        // ungated, this exact query forwards.
        let q = query_for(0x11, &["example", "com"]);
        assert!(
            matches!(server_decide(&v, &q, true), ServerDecision::Forward { .. }),
            "the name itself is one this node would have resolved"
        );
        assert!(matches!(
            doh_request_path(&v, Some(&*filter), src, &q, true),
            Served::Forbidden
        ));

        // And the authoritative half is refused too: the gate is about which peer asked, not which
        // name it asked for, so this peer does not get MagicDNS answers for our tailnet either.
        let tailnet_q = query_for(0x12, &["host", "user", "ts", "net"]);
        assert!(matches!(
            doh_request_path(&v, Some(&*filter), src, &tailnet_q, true),
            Served::Forbidden
        ));
    }

    #[test]
    fn a_source_that_is_no_known_peer_is_refused() {
        // Go's peerAPI resolves the connection's source to a peer before any handler runs and drops
        // the connection when it cannot. An allow-everything ACL does not rescue an unknown source.
        let v = view_with_peer();
        let filter = filter_of(vec![tcp_rule("0.0.0.0/0", "0.0.0.0/0", 0..=u16::MAX)]);

        assert!(!dns_source_allowed(
            &v,
            Some(&*filter),
            "198.51.100.7".parse().unwrap()
        ));
    }

    #[test]
    fn no_compiled_filter_yet_refuses() {
        // Go: `f := b.filterAtomic.Load(); if f == nil { return false }`. Before the first netmap
        // there is nothing to check the peer against, so it is a refusal — never an allow.
        let v = view_with_peer();
        assert!(!dns_source_allowed(&v, None, "100.64.0.1".parse().unwrap()));
    }

    #[test]
    fn an_ipv6_peer_is_checked_against_the_global_unicast_probe() {
        // Same two directions for the v6 arm, where Go probes `2000::` instead of `0.0.0.0`: a rule
        // covering global unicast admits, a tailnet-only rule does not.
        let v = view_with_peer();
        let src: std::net::IpAddr = "fd7a::1".parse().unwrap();

        let internet = filter_of(vec![tcp_rule("fd7a::1/128", "2000::/3", 53..=53)]);
        assert!(dns_source_allowed(&v, Some(&*internet), src));

        let tailnet_only = filter_of(vec![tcp_rule("fd7a::1/128", "fd7a::/48", 0..=u16::MAX)]);
        assert!(!dns_source_allowed(&v, Some(&*tailnet_only), src));
    }

    #[test]
    fn a_rule_on_another_port_does_not_open_dns() {
        // The gate asks about port 53 specifically (Go's `CheckTCP(..., 53)`): a peer granted the
        // internet on 443 alone is not granted this node's resolver.
        let v = view_with_peer();
        let filter = filter_of(vec![tcp_rule("100.64.0.1/32", "0.0.0.0/0", 443..=443)]);

        assert!(!dns_source_allowed(
            &v,
            Some(&*filter),
            "100.64.0.1".parse().unwrap()
        ));
    }

    // ---------------------------------------------------------------------------------------------
    // How the filter gets here.
    //
    // The gate above is only as good as its input: it refuses when it has no filter, so a filter
    // that goes missing on the way is not a silent no-op, it is this node refusing peers control's
    // ACL admits, until control happens to send another one. These exercise the delivery path from
    // the production `PacketfilterUpdater` to the value `handle_conn` passes to `dns_source_allowed`.

    use kameo::actor::Spawn;

    /// A minimal `ForwarderConfig` for standing up an `Env` (mirrors the sibling actor tests;
    /// nothing here reads the forwarding fields).
    fn forwarder_cfg() -> crate::env::ForwarderConfig {
        crate::env::ForwarderConfig {
            accept_routes: false,
            accept_dns: true,
            exit_node: None,
            forward_routes: vec![],
            forward_tcp_ports: vec![],
            forward_udp_ports: vec![],
            forward_all_ports: false,
            forward_exit_egress: false,
            block_incoming: false,
            exit_proxy: None,
            peerapi_port: None,
            taildrop_dir: None,
            enable_ipv6: false,
            wireguard_listen_port: None,
            network_monitor: false,
            persistent_keepalive_interval: None,
            ingress_active: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// A netmap update carrying `rules` as control's packet filter, and nothing else.
    fn netmap_with(rules: Vec<ts_packetfilter::Rule>) -> Arc<ts_control::StateUpdate> {
        Arc::new(ts_control::StateUpdate {
            session_handle: None,
            seq: 0,
            keep_alive: false,
            derp: None,
            node: None,
            peer_update: None,
            peer_patches: Vec::new(),
            user_profiles: Vec::new(),
            ping: None,
            packetfilter: Some((Some(rules), Default::default())),
            cap_grants: None,
            pop_browser_url: None,
            dial_plan: None,
            dns_config: None,
            ssh_policy: None,
            tka: None,
            online_change: Default::default(),
            peer_seen_change: Default::default(),
            control_time: None,
        })
    }

    /// Stand up the production packet-filter updater over a fresh `Env`, returning it with the live
    /// filter cell the peerAPI DoH gate reads.
    fn updater_with_cell() -> (
        kameo::actor::ActorRef<crate::packetfilter::PacketfilterUpdater>,
        crate::packetfilter::LiveFilterRx,
        watch::Sender<Option<crate::packetfilter::PacketFilterState>>,
        crate::env::Env,
    ) {
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        // The shutdown sender is dropped here on purpose: nothing in these tests reads it, and the
        // `Env` only ever borrows the receiver.
        let env =
            crate::env::Env::new(ts_keys::NodeState::generate(), shutdown_rx, forwarder_cfg());
        let (cap_grants_tx, _cap_grants_rx) = watch::channel(Default::default());
        let (filter_tx, filter_rx) = watch::channel(None);
        let updater = crate::packetfilter::PacketfilterUpdater::spawn((
            env.clone(),
            cap_grants_tx,
            filter_tx.clone(),
        ));
        (updater, filter_rx, filter_tx, env)
    }

    /// Run the gate against whatever the cell currently holds, exactly as `handle_conn` does
    /// (`filter_rx.borrow().clone()`, then `dns_source_allowed`).
    fn gate_says_yes(
        view: &DnsView,
        filter_rx: &crate::packetfilter::LiveFilterRx,
        src: &str,
    ) -> bool {
        let filter = filter_rx.borrow().clone();
        dns_source_allowed(view, filter.as_ref().map(|f| &*f.0), src.parse().unwrap())
    }

    /// Every filter control compiles reaches the gate, including one compiled before the gate
    /// existed. The peerAPI server task is spawned by `MagicDnsActor::on_start`, which runs on its
    /// own task and can therefore attach at any point relative to the first netmap; a cell written
    /// by the updater is readable whenever the reader shows up, so "the gate started late" cannot
    /// turn into "the gate refuses everyone".
    #[tokio::test]
    async fn a_gate_that_attaches_after_the_first_netmap_still_reads_the_filter() {
        let (updater, filter_rx, filter_tx, _env) = updater_with_cell();
        let v = view_with_peer();

        // Before any netmap: no filter, so the gate refuses (Go's `f == nil`).
        assert!(
            !gate_says_yes(&v, &filter_rx, "100.64.0.1"),
            "no compiled filter yet must refuse"
        );

        // Control grants this peer the internet through us on 53.
        updater
            .tell(netmap_with(vec![tcp_rule(
                "100.64.0.1/32",
                "0.0.0.0/0",
                53..=53,
            )]))
            .await
            .expect("netmap delivered to the packet-filter updater");
        wait_for_filter(&filter_rx).await;

        // A receiver created *now* — a peerAPI server task that started after that netmap — reads
        // the filter that was compiled before it existed.
        let late_rx = filter_tx.subscribe();
        assert!(
            gate_says_yes(&v, &late_rx, "100.64.0.1"),
            "a gate attaching after the compile must still see the filter"
        );
    }

    /// The gate tracks policy: a later netmap that takes the grant away reaches it too, and the
    /// same peer is refused. Without this direction the test above would pass against a cell that
    /// is written once and then goes stale.
    #[tokio::test]
    async fn a_revoked_grant_reaches_the_gate_too() {
        let (updater, mut filter_rx, _filter_tx, _env) = updater_with_cell();
        let v = view_with_peer();

        updater
            .tell(netmap_with(vec![tcp_rule(
                "100.64.0.1/32",
                "0.0.0.0/0",
                53..=53,
            )]))
            .await
            .expect("first netmap delivered");
        wait_for_filter(&filter_rx).await;
        assert!(gate_says_yes(&v, &filter_rx, "100.64.0.1"));

        // Control re-issues the policy with the peer's internet access removed; it keeps tailnet
        // access, which is how it reaches the peerAPI port at all.
        filter_rx.mark_unchanged();
        updater
            .tell(netmap_with(vec![tcp_rule(
                "100.64.0.1/32",
                "100.64.0.0/10",
                0..=u16::MAX,
            )]))
            .await
            .expect("second netmap delivered");
        filter_rx
            .changed()
            .await
            .expect("the revocation reaches the cell");

        assert!(
            !gate_says_yes(&v, &filter_rx, "100.64.0.1"),
            "a revoked grant must reach the gate, not leave it admitting on a stale filter"
        );
    }

    /// Why the cell, and not a bus subscription feeding one.
    ///
    /// The `Env` bus delivers best-effort (`kameo_actors::DeliveryStrategy::BestEffort`, the default
    /// it is spawned with): publishing `try_send`s and *skips* any subscriber whose bounded mailbox
    /// is full. `MagicDnsActor` parks in handlers — its `Query` handler awaits a DNS forward for up
    /// to five seconds — so it is exactly the kind of subscriber that gets skipped, and nothing
    /// redelivers afterwards. Here a subscriber parked in its handler misses filters the updater
    /// published while it was busy, and the gate reading the updater's own cell is unaffected.
    #[tokio::test]
    async fn a_parked_bus_subscriber_misses_filters_the_cell_still_carries() {
        let (updater, mut filter_rx, _filter_tx, env) = updater_with_cell();
        let v = view_with_peer();

        // A subscriber that parks in its first handler, with the smallest mailbox there is so the
        // publishes behind it have nowhere to queue.
        let seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let last_seen: TapState = Arc::new(std::sync::Mutex::new(None));
        let (release_tx, release_rx) = watch::channel(false);
        let tap = ParkedFilterTap::spawn_with_mailbox(
            (seen.clone(), last_seen.clone(), release_rx),
            kameo::mailbox::bounded(1),
        );
        env.subscribe::<crate::packetfilter::PacketFilterState>(&tap)
            .await
            .expect("tap subscribed to the filter bus");

        // Three policies in a row. Only the last one grants this peer DNS.
        for rules in [
            vec![tcp_rule("100.64.0.1/32", "100.64.0.0/10", 0..=u16::MAX)],
            vec![tcp_rule("100.64.0.1/32", "0.0.0.0/0", 443..=443)],
            vec![tcp_rule("100.64.0.1/32", "0.0.0.0/0", 53..=53)],
        ] {
            filter_rx.mark_unchanged();
            updater
                .tell(netmap_with(rules))
                .await
                .expect("netmap delivered");
            filter_rx
                .changed()
                .await
                .expect("each compiled filter reaches the cell");
        }

        // The tap is registered before any of the three, so the first one reaches it and it parks
        // there; waiting for that is what makes the count below a measurement of dropped filters
        // rather than of a subscription that never worked.
        wait_for_count(&seen, 1).await;
        let delivered = seen.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            delivered < 3,
            "the bus dropped nothing ({delivered}/3 delivered to a parked subscriber); \
             this test only means something if it does"
        );
        assert!(
            gate_says_yes(&v, &filter_rx, "100.64.0.1"),
            "the gate answers from the newest compiled filter, not from what the bus managed to deliver"
        );

        // And the same gate, asked against the newest filter that subscriber actually received —
        // the answer the peerAPI DoH gate gave while it was fed from a bus subscription — refuses
        // the peer control has granted. The two answers differ, which is the whole defect.
        let stale = last_seen.lock().unwrap().clone();
        assert!(
            !dns_source_allowed(
                &v,
                stale.as_ref().map(|f| &*f.0),
                "100.64.0.1".parse().unwrap()
            ),
            "the parked subscriber is supposed to be stuck on an older policy here"
        );

        release_tx.send_replace(true);
    }

    /// Wait for `counter` to reach `want`, failing the test rather than hanging.
    async fn wait_for_count(counter: &std::sync::atomic::AtomicUsize, want: usize) {
        for _ in 0..200 {
            if counter.load(std::sync::atomic::Ordering::SeqCst) >= want {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!(
            "timed out waiting for the bus tap to receive {want}: got {}",
            counter.load(std::sync::atomic::Ordering::SeqCst)
        );
    }

    /// Wait for the cell to hold a compiled filter, failing the test rather than hanging.
    async fn wait_for_filter(filter_rx: &crate::packetfilter::LiveFilterRx) {
        for _ in 0..200 {
            if filter_rx.borrow().is_some() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for the packet-filter updater to write the live filter cell");
    }

    /// The newest filter a bus subscriber actually received — the value a cell fed from a bus
    /// subscription would be holding.
    type TapState = Arc<std::sync::Mutex<Option<crate::packetfilter::PacketFilterState>>>;

    /// A bus subscriber that parks in its handler, the way `MagicDnsActor` parks while a DNS
    /// forward is in flight. Records what it actually received.
    struct ParkedFilterTap {
        seen: Arc<std::sync::atomic::AtomicUsize>,
        last_seen: TapState,
        release: watch::Receiver<bool>,
    }

    impl kameo::Actor for ParkedFilterTap {
        type Args = (
            Arc<std::sync::atomic::AtomicUsize>,
            TapState,
            watch::Receiver<bool>,
        );
        type Error = crate::Error;

        async fn on_start(
            (seen, last_seen, release): Self::Args,
            _slf: kameo::actor::ActorRef<Self>,
        ) -> Result<Self, Self::Error> {
            Ok(Self {
                seen,
                last_seen,
                release,
            })
        }
    }

    impl kameo::message::Message<crate::packetfilter::PacketFilterState> for ParkedFilterTap {
        type Reply = ();

        async fn handle(
            &mut self,
            msg: crate::packetfilter::PacketFilterState,
            _ctx: &mut kameo::message::Context<Self, Self::Reply>,
        ) {
            // Scoped: the guard must not be held across the park below.
            {
                *self.last_seen.lock().unwrap() = Some(msg);
            }
            self.seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            loop {
                let released = *self.release.borrow_and_update();
                if released || self.release.changed().await.is_err() {
                    return;
                }
            }
        }
    }
}
