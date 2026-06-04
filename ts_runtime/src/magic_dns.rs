//! MagicDNS responder with a split-DNS / recursive forwarder.
//!
//! An in-netstack DNS server bound to `100.100.100.100:53`. It is authoritative for in-tailnet
//! peer names and control-pushed [`ExtraRecord`][ts_control::ExtraRecord]s, answering `A`/`AAAA`/
//! `PTR` for those directly. For names it is *not* authoritative for, it brings tsnet-style
//! split-DNS and recursive resolution:
//!
//! - **Split DNS** ([`DnsConfig::routes`]): the longest matching suffix route forwards the query
//!   to one of that route's upstream resolvers. A route with an **empty** upstream list is a
//!   negative route — names under it are `NXDOMAIN` (Go keeps them on the built-in resolver; for
//!   us that means fail-closed unless an overlay/extra record matched first).
//! - **Recursive** ([`DnsConfig::fallback_resolvers`] / [`DnsConfig::resolvers`]): names matching
//!   no route are forwarded to the fallback resolvers, else the global resolvers.
//! - **Fail closed**: if no route and no resolver is configured, an unknown name is `NXDOMAIN`.
//!
//! Anti-leak / IPv6-off posture: upstream forwarding binds `0.0.0.0:0` (UDP, IPv4 only) and never
//! opens an IPv6 socket. AAAA is answered from overlay data but never sourced over a v6 socket.
//!
//! - MagicDNS disabled (`dns_config == None` or `magic_dns == false`) => `REFUSED` for every query.
//! - Unsupported qtype => `REFUSED` (never forwarded).
//! - Malformed query => dropped (no response).

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use kameo::{
    actor::ActorRef,
    message::{Context, Message},
};
use netstack::{CreateSocket, netcore::Channel};
use tokio::{sync::watch, task::JoinSet, time::timeout};
use ts_control::{DnsConfig, DnsResolver, Node};
use ts_dns_wire::{Name, QType, RData, Rcode, decode_query, encode_response};

use crate::{
    Error,
    env::Env,
    peer_tracker::{PeerDb, PeerState},
};

/// How long to wait for an upstream resolver to answer a forwarded query before giving up.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);
/// Cap on a forwarded upstream response we read into memory (a single UDP datagram).
const MAX_UPSTREAM_RESPONSE: usize = 1232;

/// The MagicDNS service IP. The netstack interface owns this address, so a `udp_bind` here
/// receives the tailnet's DNS traffic.
const MAGIC_DNS_IP: Ipv4Addr = Ipv4Addr::new(100, 100, 100, 100);
/// The DNS service port.
const MAGIC_DNS_PORT: u16 = 53;

/// The latest view the answer loop resolves queries against.
///
/// Updated by the actor's message handlers (from control `StateUpdate` and peer `PeerState`
/// updates) and read fresh by the answer loop for every packet.
#[derive(Clone, Default)]
pub(crate) struct DnsView {
    /// The DNS configuration. `magic_dns == false` (the default) means serve nothing.
    pub(crate) cfg: DnsConfig,
    /// The current peer database, if we've seen a peer update.
    pub(crate) peers: Option<Arc<PeerDb>>,
    /// This node, if we've seen a self-node update.
    pub(crate) self_node: Option<Node>,
    /// The peerAPI DoH socket address of the currently-selected exit node, if one is active and can
    /// proxy DNS ([`Node::peerapi_doh_addr`]). When set, the MagicDNS *client* serve loop delegates
    /// recursive resolution to this address over the overlay instead of forwarding to the locally
    /// configured upstream resolvers — so recursive DNS egresses from the exit node, not this host.
    ///
    /// Only consumed by the local MagicDNS responder's serve loop (the client side). The peerAPI
    /// DoH *server* shares this same view but ignores this field: an exit-node DNS proxy resolves
    /// recursively itself (gated by `forward_exit_egress`), it never re-delegates to its own exit
    /// node. `None` means no active exit node / no DoH delegation — recursion stays local.
    pub(crate) exit_doh: Option<SocketAddr>,
}

impl DnsView {
    /// Find the node (peer or self) that answers to `name`, case/dot-insensitively.
    fn node_by_name(&self, name: &str) -> Option<Node> {
        if let Some(node) = self
            .peers
            .as_ref()
            .and_then(|p| p.get(&name).map(|(_, n)| n.clone()))
        {
            return Some(node);
        }

        self.self_node
            .as_ref()
            .filter(|n| n.matches_name(name))
            .cloned()
    }

    /// Resolve `canon` to an answer address of the requested family. A tailnet peer/self match
    /// wins first — tried as written and then qualified by each tailnet search domain (so a
    /// short/partially-qualified name like `host` or `host.user` still resolves to
    /// `host.user.ts.net`). Failing that, a control-pushed [`ExtraRecord`] of the matching family
    /// answers, matched as a fully-qualified name only (no search-domain expansion — like Go tsnet,
    /// ExtraRecords are authoritative FQDN entries, not subject to client search-list qualification).
    /// Still fail-closed: only ever resolves to a known tailnet peer/self or an explicitly
    /// control-pushed static record — never anything else.
    fn resolve_addr(&self, canon: &str, want_v4: bool) -> Option<IpAddr> {
        let addr_of = |node: Node| -> IpAddr {
            if want_v4 {
                IpAddr::from(node.tailnet_address.ipv4.addr())
            } else {
                IpAddr::from(node.tailnet_address.ipv6.addr())
            }
        };

        if let Some(node) = self.node_by_name(canon) {
            return Some(addr_of(node));
        }
        for suffix in &self.cfg.search_domains {
            if let Some(node) = self.node_by_name(&format!("{canon}.{suffix}")) {
                return Some(addr_of(node));
            }
        }

        // Control-pushed static records match the fully-qualified query name only.
        self.cfg.extra_records.iter().find_map(|rec| {
            let family_ok = matches!(
                (rec.addr, want_v4),
                (IpAddr::V4(_), true) | (IpAddr::V6(_), false)
            );
            (rec.name == canon && family_ok).then_some(rec.addr)
        })
    }

    /// Find the node (peer or self) that owns the tailnet IP `ip`.
    fn node_by_ip(&self, ip: IpAddr) -> Option<Node> {
        if let Some(node) = self
            .peers
            .as_ref()
            .and_then(|p| p.get(&ip).map(|(_, n)| n.clone()))
        {
            return Some(node);
        }

        self.self_node
            .as_ref()
            .filter(|n| {
                IpAddr::from(n.tailnet_address.ipv4.addr()) == ip
                    || IpAddr::from(n.tailnet_address.ipv6.addr()) == ip
            })
            .cloned()
    }

    /// Decide how to resolve a non-overlay `name` against the split-DNS routes and recursive
    /// resolvers, returning the upstreams to forward to.
    ///
    /// Longest-suffix wins among [`DnsConfig::routes`]: a route's suffix matches `name` if `name`
    /// equals it or ends with `.suffix`. A matched route with a non-empty upstream list forwards
    /// there; a matched route with an **empty** list is a negative route ([`Upstreams::Block`] =>
    /// NXDOMAIN). With no route match, [`DnsConfig::fallback_resolvers`] (preferred) or
    /// [`DnsConfig::resolvers`] resolve recursively; if neither is configured we stay fail-closed
    /// ([`Upstreams::None`] => NXDOMAIN).
    fn route_for(&self, name: &str) -> Upstreams<'_> {
        let mut best: Option<(&str, &Vec<DnsResolver>)> = None;
        for (suffix, upstreams) in &self.cfg.routes {
            if suffix_matches(name, suffix) && best.is_none_or(|(b, _)| suffix.len() > b.len()) {
                best = Some((suffix.as_str(), upstreams));
            }
        }

        if let Some((_, upstreams)) = best {
            return if upstreams.is_empty() {
                Upstreams::Block
            } else {
                // A deliberately-configured split-DNS route: not eligible for exit-node DoH
                // delegation — these upstreams (e.g. an internal resolver reachable over a subnet
                // route) must keep receiving the query directly.
                Upstreams::Route(upstreams)
            };
        }

        if !self.cfg.fallback_resolvers.is_empty() {
            return Upstreams::Recursive(&self.cfg.fallback_resolvers);
        }
        if !self.cfg.resolvers.is_empty() {
            return Upstreams::Recursive(&self.cfg.resolvers);
        }
        Upstreams::None
    }
}

/// The upstreams a non-overlay query should be forwarded to (or why it should not be forwarded).
enum Upstreams<'a> {
    /// A split-DNS route matched: forward to these route-specific upstreams (never DoH-delegated).
    Route(&'a [DnsResolver]),
    /// No route matched: forward to these recursive (fallback/global) resolvers. Eligible for
    /// exit-node DoH delegation in the client serve loop.
    Recursive(&'a [DnsResolver]),
    /// A negative split-DNS route matched: do not resolve (NXDOMAIN).
    Block,
    /// No route and no resolver configured: fail closed (NXDOMAIN).
    None,
}

/// What the (sync) decision step concluded for a query: either a complete response to send back,
/// or a request to forward the original query to an upstream resolver.
pub(crate) enum Decision {
    /// A fully-formed response is ready to send.
    Reply(Vec<u8>),
    /// Forward the original query datagram to one of these upstream UDP resolvers; on success
    /// relay the upstream answer, on failure/timeout answer NXDOMAIN with the given id+question.
    Forward {
        /// UDP upstreams to try, in order.
        upstreams: Vec<SocketAddr>,
        /// The original query bytes to forward verbatim.
        query: Vec<u8>,
        /// Fallback NXDOMAIN response if every upstream fails.
        nxdomain: Vec<u8>,
        /// Whether this is a *recursive* (catch-all fallback/global resolver) forward, as opposed
        /// to a deliberately-configured split-DNS route. Only recursive forwards are eligible for
        /// exit-node DoH delegation in the client serve loop (see [`DnsView::exit_doh`]); split-DNS
        /// routes always stay on their configured upstreams (typically subnet-reachable internal
        /// resolvers). The peerAPI DoH *server* ignores this flag entirely.
        recursive: bool,
    },
}

/// Whether `name` is `suffix` or sits under it at a label boundary: `"a.corp"` matches `"corp"`,
/// `"acorp"` does not. An **empty** suffix never matches (defense-in-depth: an empty suffix would
/// otherwise make `ends_with("")` match every name and either over-route or treat everything as a
/// tailnet name — both leak-prone).
fn suffix_matches(name: &str, suffix: &str) -> bool {
    if suffix.is_empty() {
        return false;
    }
    name == suffix
        || (name.len() > suffix.len()
            && name.ends_with(suffix)
            && name.as_bytes()[name.len() - suffix.len() - 1] == b'.')
}

/// Returns `true` if `name` falls under one of the tailnet search domains. Such names are
/// authoritative MagicDNS names and are NEVER forwarded to an upstream resolver — anti-leak: a
/// tailnet name (and the fact that it was queried) must not escape to a third-party resolver.
fn is_tailnet_name(view: &DnsView, name: &str) -> bool {
    view.cfg
        .search_domains
        .iter()
        .any(|suffix| suffix_matches(name, suffix))
}

/// Whether `name` is an IPv6 reverse-DNS (`PTR`) name (ends in `ip6.arpa`). This fork is IPv4-only
/// on the tailnet; an IPv6 reverse lookup must NEVER be forwarded to a third-party resolver
/// (anti-leak: it would reveal that a tailnet v6 address — e.g. a ULA `fd7a:…` — was probed). All
/// such queries fail closed to NXDOMAIN.
fn is_ip6_arpa(name: &str) -> bool {
    suffix_matches(name, "ip6.arpa")
}

/// Whether `ip` is in the Tailscale CGNAT range `100.64.0.0/10` (RFC 6598, the tailnet IPv4 space).
/// Reverse (`PTR`) queries for these addresses are authoritative to MagicDNS: if no peer owns the
/// IP we fail closed to NXDOMAIN rather than forwarding the probe to a third-party resolver.
fn is_tailnet_cgnat(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (64..=127).contains(&o[1])
}

/// Decide what to do with a single DNS query against `view`: either a complete response is ready
/// ([`Decision::Reply`]), the query should be forwarded to upstream resolvers
/// ([`Decision::Forward`]), or the packet should be dropped without answering (`None`).
///
/// Pure (no I/O), factored out of the socket loop so it can be unit-tested without a netstack. It
/// never panics and fails closed: an unknown, unroutable, or tailnet-suffix name resolves to
/// NXDOMAIN rather than leaking to an upstream resolver.
pub(crate) fn decide(view: &DnsView, buf: &[u8]) -> Option<Decision> {
    // Malformed / non-query input is dropped: we never answer something we can't parse.
    let query = decode_query(buf).ok()?;
    let q = &query.question;
    let id = query.id;

    let reply = |rcode, answers: &[RData]| Decision::Reply(encode_response(id, q, rcode, answers));

    // Fail closed: MagicDNS off => serve nothing.
    if !view.cfg.magic_dns {
        return Some(reply(Rcode::Refused, &[]));
    }

    // We only serve the internet (IN) class. Anything else (CHAOS, HESIOD, ...) is refused.
    const CLASS_IN: u16 = 1;
    if q.qclass != CLASS_IN {
        return Some(reply(Rcode::Refused, &[]));
    }

    let canon = q.name.to_canon();

    Some(match &q.qtype {
        QType::A => match view.resolve_addr(&canon, true) {
            Some(IpAddr::V4(v4)) => reply(Rcode::NoError, &[RData::A(v4.octets())]),
            // No overlay/extra-record answer: try split-DNS / recursive upstreams.
            _ => forward_or_nxdomain(view, &canon, buf, id, q),
        },
        QType::Aaaa => match view.resolve_addr(&canon, false) {
            Some(IpAddr::V6(v6)) => reply(Rcode::NoError, &[RData::Aaaa(v6.octets())]),
            _ => forward_or_nxdomain(view, &canon, buf, id, q),
        },
        QType::Ptr => match q.name.ptr_to_ipv4() {
            Some(octets) => {
                let v4: Ipv4Addr = octets.into();
                let ip = IpAddr::V4(v4);
                match view.node_by_ip(ip) {
                    Some(node) => {
                        let fqdn = node.fqdn(false);
                        let labels: Vec<String> = fqdn.split('.').map(str::to_owned).collect();
                        reply(Rcode::NoError, &[RData::Ptr(Name(labels))])
                    }
                    // Anti-leak: a reverse query for an IP in the tailnet CGNAT range
                    // (100.64.0.0/10) that misses the peer set is authoritative-but-unknown; fail
                    // closed to NXDOMAIN rather than leaking the probed tailnet IP upstream. Only
                    // genuinely off-tailnet reverse queries are forwarded.
                    None if is_tailnet_cgnat(v4) => reply(Rcode::NxDomain, &[]),
                    None => forward_or_nxdomain(view, &canon, buf, id, q),
                }
            }
            // Anti-leak / IPv4-only-tailnet: an IPv6 reverse (`ip6.arpa`) PTR must never be
            // forwarded — relaying it would reveal that a tailnet v6 address (e.g. a ULA `fd7a:…`)
            // was probed. Fail closed to NXDOMAIN, exactly like the IPv4 CGNAT guard above.
            None if is_ip6_arpa(&canon) => reply(Rcode::NxDomain, &[]),
            None => forward_or_nxdomain(view, &canon, buf, id, q),
        },
        // Anything else (TXT, SRV, ...) is refused: we only serve MagicDNS host records and
        // forward A/AAAA/PTR. We never forward arbitrary qtypes.
        QType::Other(_) => reply(Rcode::Refused, &[]),
    })
}

/// For a name with no overlay answer, consult the split-DNS routes + recursive resolvers and
/// either forward (to UDP upstreams) or fail closed with NXDOMAIN.
///
/// Anti-leak: a name under a tailnet search domain is authoritative and is never forwarded — it
/// fails closed to NXDOMAIN so neither the name nor the query leaks to a third-party resolver.
fn forward_or_nxdomain(
    view: &DnsView,
    canon: &str,
    buf: &[u8],
    id: u16,
    q: &ts_dns_wire::Question,
) -> Decision {
    let nxdomain = encode_response(id, q, Rcode::NxDomain, &[]);

    if is_tailnet_name(view, canon) {
        return Decision::Reply(nxdomain);
    }

    let (resolvers, recursive) = match view.route_for(canon) {
        Upstreams::Route(resolvers) => (resolvers, false),
        Upstreams::Recursive(resolvers) => (resolvers, true),
        // Negative route or nothing configured: fail closed.
        Upstreams::Block | Upstreams::None => return Decision::Reply(nxdomain),
    };

    let upstreams: Vec<SocketAddr> = resolvers
        .iter()
        .map(DnsResolver::udp_addr)
        // Anti-leak / IPv6-off: only forward over IPv4 upstreams; never open a v6 socket.
        .filter(SocketAddr::is_ipv4)
        .collect();
    if upstreams.is_empty() {
        Decision::Reply(nxdomain)
    } else {
        Decision::Forward {
            upstreams,
            query: buf.to_vec(),
            nxdomain,
            recursive,
        }
    }
}

/// Client-side plan for a *recursive* forward: keep resolving over local UDP upstreams, or delegate
/// the query to the active exit node's peerAPI DoH endpoint over the overlay.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RecursivePlan {
    /// Forward over UDP to these upstreams. Used when no exit node is active, or when the config
    /// has `use_with_exit_node` resolvers (kept local even with an exit node selected).
    Udp(Vec<SocketAddr>),
    /// Delegate the query to the exit node's peerAPI DoH server at this overlay address.
    Doh(SocketAddr),
}

/// Decide whether a recursive forward should stay on local UDP upstreams or be delegated to the
/// active exit node's DoH endpoint. Pure (no I/O) so the delegation rule is unit-testable.
///
/// - No active exit node ([`DnsView::exit_doh`] is `None`) => keep `default_upstreams` (UDP).
/// - Exit node active, but the config has [`use_with_exit_node`][ts_control::DnsResolver::use_with_exit_node]
///   resolvers => those resolvers stay local (Go keeps `UseWithExitNode` resolvers when an exit node
///   is selected); forward to them over UDP, do NOT delegate.
/// - Exit node active, no kept-local resolvers => delegate to the exit node's DoH. Recursive DNS
///   then egresses from the exit node, not this host (the whole point of routing through an exit
///   node: this node's real IP is never used to resolve the peer's public names).
pub(crate) fn recursive_plan(view: &DnsView, default_upstreams: Vec<SocketAddr>) -> RecursivePlan {
    let Some(doh) = view.exit_doh else {
        return RecursivePlan::Udp(default_upstreams);
    };
    let kept: Vec<SocketAddr> = view
        .cfg
        .resolvers_with_exit_node()
        .map(DnsResolver::udp_addr)
        // Anti-leak / IPv6-off: only ever resolve over IPv4 upstreams; never open a v6 socket.
        .filter(SocketAddr::is_ipv4)
        .collect();
    if kept.is_empty() {
        RecursivePlan::Doh(doh)
    } else {
        RecursivePlan::Udp(kept)
    }
}

/// Cap a forwarded upstream response to a single UDP datagram ([`MAX_UPSTREAM_RESPONSE`]). When the
/// response is too large it is truncated mid-message, so we set the `TC` (truncation) flag in the
/// DNS header (byte 2, bit `0x02`) telling the stub resolver to retry over TCP — relaying a chopped
/// answer without `TC` would surface a malformed-but-"complete" message. The flag is only set when
/// truncation actually occurs.
fn cap_response(mut resp: Vec<u8>) -> Vec<u8> {
    if resp.len() > MAX_UPSTREAM_RESPONSE {
        resp.truncate(MAX_UPSTREAM_RESPONSE);
        // The header is 12 bytes; the TC bit lives in the second flags byte (header byte 2). A
        // capped datagram is always >= the header length, but guard anyway to never panic.
        if let Some(flags_hi) = resp.get_mut(2) {
            *flags_hi |= 0x02;
        }
    }
    resp
}

/// The byte length of a fixed DNS header.
const DNS_HEADER_LEN: usize = 12;

/// Return the byte range of the first question section (QNAME + QTYPE + QCLASS) within `msg`,
/// starting just after the 12-byte header. Returns [`None`] if the name is malformed, uses a
/// compression pointer (illegal in a question), or runs past the buffer. Used to byte-compare a
/// forwarded query's question against the upstream response's question.
fn question_range(msg: &[u8]) -> Option<std::ops::Range<usize>> {
    let mut off = DNS_HEADER_LEN;
    // Walk the QNAME label sequence to the terminating root label (0x00).
    loop {
        let len = *msg.get(off)? as usize;
        // A compression pointer (top two bits set) is not valid in a question section.
        if len & 0xC0 != 0 {
            return None;
        }
        off += 1;
        if len == 0 {
            break; // root label: QNAME complete.
        }
        off = off.checked_add(len)?;
        if off > msg.len() {
            return None;
        }
    }
    // QTYPE (2) + QCLASS (2) follow the name.
    let end = off.checked_add(4)?;
    if end > msg.len() {
        return None;
    }
    Some(DNS_HEADER_LEN..end)
}

/// Whether `resp` is a plausible DNS response to `query`: same 16-bit transaction id, the QR
/// (response) bit set, and a byte-identical question section (QNAME + QTYPE + QCLASS). Both buffers
/// carry the DNS header in the first 12 bytes (id at [0..2], flags at [2..4], QR is the high bit of
/// byte 2). Used to reject off-path/forged datagrams before relaying them back to the stub resolver
/// as authoritative: matching only the id + QR lets an injector that guesses the id swap in an
/// answer for a different question, so we also require the echoed question to match.
fn response_matches_query(query: &[u8], resp: &[u8]) -> bool {
    if query.len() < DNS_HEADER_LEN || resp.len() < DNS_HEADER_LEN {
        return false;
    }
    let id_matches = query[0..2] == resp[0..2];
    let is_response = resp[2] & 0x80 != 0;
    if !id_matches || !is_response {
        return false;
    }
    // The response must echo the exact question we asked. Parse both question sections and compare
    // their bytes; a parse failure on either side is treated as a non-match (fail closed).
    match (question_range(query), question_range(resp)) {
        (Some(q), Some(r)) => query[q] == resp[r],
        _ => false,
    }
}

/// Forward `query` to each upstream in order over the **overlay** netstack, returning the first
/// well-formed response, or `nxdomain` if every upstream times out or errors.
///
/// Anti-leak: forwarding goes through the overlay netstack `channel` (a fresh `0.0.0.0:0` overlay
/// UDP socket per query), NEVER a host socket — so the real origin IP can't leak to the resolver,
/// and split-DNS upstreams reachable only over the tailnet/subnet-router work. Each upstream is
/// bounded by [`UPSTREAM_TIMEOUT`]; responses are capped at [`MAX_UPSTREAM_RESPONSE`].
pub(crate) async fn forward_query(
    channel: &Channel,
    upstreams: &[SocketAddr],
    query: &[u8],
    nxdomain: Vec<u8>,
) -> Vec<u8> {
    for upstream in upstreams {
        let socket = match channel
            .udp_bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
            .await
        {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, %upstream, "magic dns upstream bind failed");
                continue;
            }
        };

        if let Err(e) = socket.send_to(*upstream, query).await {
            tracing::warn!(error = %e, %upstream, "magic dns upstream send failed");
            continue;
        }

        match timeout(UPSTREAM_TIMEOUT, socket.recv_from_bytes()).await {
            Ok(Ok((from, resp))) if !resp.is_empty() => {
                // Anti-poisoning: only accept a datagram that came from the upstream we queried
                // and whose DNS header matches this query (same transaction id, QR=response bit
                // set). An off-path injector racing the real answer is otherwise relayed straight
                // back to the stub resolver as authoritative.
                if from.ip() != upstream.ip() || !response_matches_query(query, &resp) {
                    tracing::debug!(%upstream, %from, "magic dns dropping unsolicited/mismatched response");
                    continue;
                }
                return cap_response(resp.to_vec());
            }
            Ok(Ok(_)) => continue,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, %upstream, "magic dns upstream recv failed");
                continue;
            }
            Err(_) => {
                tracing::debug!(%upstream, "magic dns upstream timed out");
                continue;
            }
        }
    }
    nxdomain
}

/// Run the receive/answer loop for the bound socket until it (or the netstack) goes away.
///
/// Authoritative answers are sent inline. Forwarded queries are handled on spawned tasks (each
/// cloning the overlay `channel`) so a slow upstream never blocks other queries.
async fn serve(
    socket: netstack::netsock::UdpSocket,
    rx: watch::Receiver<Arc<DnsView>>,
    channel: Channel,
) {
    let socket = Arc::new(socket);
    let mut forwards = JoinSet::new();
    loop {
        let (src, buf) = match socket.recv_from_bytes().await {
            Ok(pkt) => pkt,
            Err(e) => {
                tracing::warn!(error = %e, "magic dns socket recv failed, stopping responder");
                return;
            }
        };

        // Read the freshest view per packet.
        let view = rx.borrow().clone();

        match decide(&view, &buf) {
            // Malformed query: drop silently.
            None => continue,
            Some(Decision::Reply(resp)) => {
                if let Err(e) = socket.send_to(src, &resp).await {
                    tracing::warn!(error = %e, %src, "magic dns response send failed");
                }
            }
            Some(Decision::Forward {
                upstreams,
                query,
                nxdomain,
                recursive,
            }) => {
                // A recursive forward is eligible for exit-node DoH delegation; a split-DNS route
                // always stays on its configured upstreams. Decide the plan against the current
                // view so a query routed while an exit node is active egresses from that exit node.
                let plan = if recursive {
                    recursive_plan(&view, upstreams)
                } else {
                    RecursivePlan::Udp(upstreams)
                };
                let socket = socket.clone();
                let channel = channel.clone();
                forwards.spawn(async move {
                    let resp = match plan {
                        RecursivePlan::Udp(upstreams) => {
                            forward_query(&channel, &upstreams, &query, nxdomain).await
                        }
                        RecursivePlan::Doh(doh_addr) => {
                            crate::peerapi_doh::forward_doh(&channel, doh_addr, &query, nxdomain)
                                .await
                        }
                    };
                    if let Err(e) = socket.send_to(src, &resp).await {
                        tracing::warn!(error = %e, %src, "magic dns forwarded response send failed");
                    }
                });
            }
        }

        // Reap finished forward tasks without blocking.
        while forwards.try_join_next().is_some() {}
    }
}

/// The MagicDNS responder actor.
///
/// Subscribes to control state (for the DNS config + self node) and peer state (for the peer
/// database), keeping a [`DnsView`] that the spawned answer loop reads for every query.
pub struct MagicDnsActor {
    /// Keeps the socket-serving task alive for the lifetime of the actor.
    _joinset: JoinSet<()>,
    /// The latest view, shared with the answer loop.
    view_tx: watch::Sender<Arc<DnsView>>,
}

impl kameo::Actor for MagicDnsActor {
    type Args = (Env, Channel);
    type Error = Error;

    async fn on_start(
        (env, channel): Self::Args,
        slf: ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        env.subscribe::<Arc<ts_control::StateUpdate>>(&slf).await?;
        env.subscribe::<Arc<PeerState>>(&slf).await?;
        env.subscribe::<crate::route_updater::ActiveExitNode>(&slf)
            .await?;

        let (view_tx, view_rx) = watch::channel(Arc::new(DnsView::default()));

        let mut joinset = JoinSet::new();

        // Bind the MagicDNS socket. If the bind fails we still start (fail closed: the actor just
        // never answers anything) so a transient bind error doesn't take down the runtime.
        let addr = SocketAddr::from((MAGIC_DNS_IP, MAGIC_DNS_PORT));
        match channel.udp_bind(addr).await {
            Ok(socket) => {
                tracing::debug!(%addr, "magic dns responder bound");
                joinset.spawn(serve(socket, view_rx.clone(), channel.clone()));
            }
            Err(e) => {
                tracing::error!(error = %e, %addr, "magic dns udp bind failed; responder inert");
            }
        }

        // When this node advertises a peerAPI port, also run the exit-node DoH server on the same
        // shared view. It answers `/dns-query` for peers that select us as their exit node; its
        // recursive resolution is gated behind `forward_exit_egress` (see `peerapi_doh`).
        if let Some(port) = env.peerapi_port {
            let channel = channel.clone();
            let view_rx = view_rx.clone();
            let forward_exit_egress = env.forward_exit_egress;
            joinset.spawn(crate::peerapi_doh::serve(
                channel,
                port,
                view_rx,
                forward_exit_egress,
            ));
        }

        Ok(Self {
            _joinset: joinset,
            view_tx,
        })
    }
}

impl Message<Arc<ts_control::StateUpdate>> for MagicDnsActor {
    type Reply = ();

    async fn handle(
        &mut self,
        update: Arc<ts_control::StateUpdate>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        self.view_tx.send_modify(|view| {
            let mut next = (**view).clone();
            next.cfg = update.dns_config.clone().unwrap_or_default();
            next.self_node = update.node.clone();
            *view = Arc::new(next);
        });
    }
}

impl Message<Arc<PeerState>> for MagicDnsActor {
    type Reply = ();

    async fn handle(&mut self, state: Arc<PeerState>, _ctx: &mut Context<Self, Self::Reply>) {
        self.view_tx.send_modify(|view| {
            let mut next = (**view).clone();
            next.peers = Some(state.peers.clone());
            *view = Arc::new(next);
        });
    }
}

impl Message<crate::route_updater::ActiveExitNode> for MagicDnsActor {
    type Reply = ();

    async fn handle(
        &mut self,
        active: crate::route_updater::ActiveExitNode,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        // Cache the active exit node's DoH endpoint so the serve loop delegates recursive queries
        // to it. `None` (no exit node, or one that can't proxy DNS) keeps recursion local. Resolving
        // the address here — once, from the route updater's authoritative selection — means the
        // serve loop never re-resolves the selector.
        let exit_doh = active.node.as_ref().and_then(|n| n.peerapi_doh_addr());
        self.view_tx.send_modify(|view| {
            let mut next = (**view).clone();
            next.exit_doh = exit_doh;
            *view = Arc::new(next);
        });
    }
}

#[cfg(test)]
mod tests {
    use ts_control::{StableNodeId, TailnetAddress};

    use super::*;

    /// Test wrapper: run [`decide`] and extract the reply bytes. These tests configure no
    /// upstream resolvers, so an unresolved name fails closed to a `Reply` (NXDOMAIN), never a
    /// `Forward`; a `Forward` here is a bug and panics.
    fn answer(view: &DnsView, buf: &[u8]) -> Option<Vec<u8>> {
        match decide(view, buf)? {
            Decision::Reply(resp) => Some(resp),
            Decision::Forward { .. } => panic!("unexpected forward in authoritative-only test"),
        }
    }

    /// Build a `Node` named `host.user.ts.net` with a known v4/v6 tailnet address.
    fn test_node() -> Node {
        Node {
            id: 1,
            stable_id: StableNodeId("n1".to_string()),
            hostname: "host".to_string(),
            tailnet: Some("user.ts.net".to_string()),
            tags: vec![],
            tailnet_address: TailnetAddress {
                ipv4: "100.64.0.1/32".parse().unwrap(),
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
            peerapi_port: None,
            peerapi_dns_proxy: false,
            is_wireguard_only: false,
            exit_node_dns_resolvers: vec![],
        }
    }

    /// A view with MagicDNS on and a single peer in the db.
    fn view_with_peer() -> DnsView {
        let mut db = PeerDb::default();
        db.upsert(&test_node());

        DnsView {
            cfg: DnsConfig {
                magic_dns: true,
                search_domains: vec!["user.ts.net".to_string()],
                ..Default::default()
            },
            peers: Some(Arc::new(db)),
            self_node: None,
            exit_doh: None,
        }
    }

    /// Build a raw DNS query buffer for `labels` with the given id, qtype, qclass.
    fn build_query(id: u16, labels: &[&str], qtype: u16, qclass: u16) -> Vec<u8> {
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
        buf.push(0); // root label
        buf.extend_from_slice(&qtype.to_be_bytes());
        buf.extend_from_slice(&qclass.to_be_bytes());
        buf
    }

    /// Parse a response header: returns `(id, rcode, ancount)`.
    fn parse_header(resp: &[u8]) -> (u16, u8, u16) {
        let id = u16::from_be_bytes([resp[0], resp[1]]);
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        let ancount = u16::from_be_bytes([resp[6], resp[7]]);
        (id, (flags & 0x000F) as u8, ancount)
    }

    #[test]
    fn a_query_for_known_peer_answers_v4() {
        let view = view_with_peer();
        let buf = build_query(0x1234, &["host", "user", "ts", "net"], 1, 1);

        let resp = answer(&view, &buf).expect("answers");
        let (id, rcode, ancount) = parse_header(&resp);
        assert_eq!(id, 0x1234);
        assert_eq!(rcode, 0, "NoError");
        assert_eq!(ancount, 1);

        // The trailing RDATA of the single A record is the peer's tailnet v4 octets.
        let tail = &resp[resp.len() - 4..];
        assert_eq!(tail, &[100, 64, 0, 1]);
    }

    #[test]
    fn aaaa_query_for_known_peer_answers_v6() {
        let view = view_with_peer();
        let buf = build_query(0x5, &["host", "user", "ts", "net"], 28, 1);

        let resp = answer(&view, &buf).expect("answers");
        let (_, rcode, ancount) = parse_header(&resp);
        assert_eq!(rcode, 0, "NoError");
        assert_eq!(ancount, 1);

        let expected = "fd7a::1".parse::<std::net::Ipv6Addr>().unwrap().octets();
        let tail = &resp[resp.len() - 16..];
        assert_eq!(tail, expected);
    }

    #[test]
    fn bare_hostname_resolves() {
        // The name index also stores the bare hostname.
        let view = view_with_peer();
        let buf = build_query(0x7, &["host"], 1, 1);

        let resp = answer(&view, &buf).expect("answers");
        let (_, rcode, ancount) = parse_header(&resp);
        assert_eq!(rcode, 0);
        assert_eq!(ancount, 1);
    }

    #[test]
    fn unknown_name_is_nxdomain() {
        let view = view_with_peer();
        let buf = build_query(0x9, &["nope", "example", "com"], 1, 1);

        let resp = answer(&view, &buf).expect("answers");
        let (_, rcode, ancount) = parse_header(&resp);
        assert_eq!(rcode, 3, "NxDomain");
        assert_eq!(ancount, 0);
    }

    #[test]
    fn magic_dns_off_is_refused() {
        // Fail closed: with MagicDNS disabled, even a known name is refused.
        let mut view = view_with_peer();
        view.cfg.magic_dns = false;
        let buf = build_query(0xAB, &["host", "user", "ts", "net"], 1, 1);

        let resp = answer(&view, &buf).expect("answers");
        let (_, rcode, ancount) = parse_header(&resp);
        assert_eq!(rcode, 5, "Refused");
        assert_eq!(ancount, 0);
    }

    #[test]
    fn default_view_serves_nothing() {
        // The default (no dns_config seen) has magic_dns == false: fail closed.
        let view = DnsView::default();
        let buf = build_query(0x1, &["host", "user", "ts", "net"], 1, 1);

        let resp = answer(&view, &buf).expect("answers");
        let (_, rcode, _) = parse_header(&resp);
        assert_eq!(rcode, 5, "Refused");
    }

    #[test]
    fn unsupported_qtype_is_refused() {
        let view = view_with_peer();
        // TXT (type 16) is unsupported.
        let buf = build_query(0x1, &["host", "user", "ts", "net"], 16, 1);

        let resp = answer(&view, &buf).expect("answers");
        let (_, rcode, _) = parse_header(&resp);
        assert_eq!(rcode, 5, "Refused");
    }

    #[test]
    fn malformed_query_is_dropped() {
        // A response (QR bit set) is not a query; we drop it (no answer).
        let mut buf = build_query(0x1, &["host"], 1, 1);
        buf[2] = 0x80; // set QR bit
        assert!(answer(&view_with_peer(), &buf).is_none());
    }

    #[test]
    fn ptr_for_known_ip_answers_fqdn() {
        let view = view_with_peer();
        // Reverse name for 100.64.0.1 => 1.0.64.100.in-addr.arpa
        let buf = build_query(0x33, &["1", "0", "64", "100", "in-addr", "arpa"], 12, 1);

        let resp = answer(&view, &buf).expect("answers");
        let (_, rcode, ancount) = parse_header(&resp);
        assert_eq!(rcode, 0, "NoError");
        assert_eq!(ancount, 1);

        // The PTR rdata encodes the peer's fqdn "host.user.ts.net" as length-prefixed labels.
        let expected = {
            let mut out = Vec::new();
            for label in ["host", "user", "ts", "net"] {
                out.push(label.len() as u8);
                out.extend_from_slice(label.as_bytes());
            }
            out.push(0);
            out
        };
        let tail = &resp[resp.len() - expected.len()..];
        assert_eq!(tail, expected.as_slice());
    }

    #[test]
    fn ptr_for_unknown_ip_is_nxdomain() {
        let view = view_with_peer();
        // 9.9.9.9 is not a known tailnet IP.
        let buf = build_query(0x34, &["9", "9", "9", "9", "in-addr", "arpa"], 12, 1);

        let resp = answer(&view, &buf).expect("answers");
        let (_, rcode, _) = parse_header(&resp);
        assert_eq!(rcode, 3, "NxDomain");
    }

    #[test]
    fn ptr_for_unknown_tailnet_ip_is_nxdomain_not_forwarded() {
        // A view WITH an upstream resolver: an off-tailnet reverse query would forward, but a
        // reverse query for an unmatched IP in the CGNAT range (100.64.0.0/10) must fail closed to
        // NXDOMAIN — the probed tailnet IP must never leak upstream.
        let mut db = PeerDb::default();
        db.upsert(&test_node());
        let view = DnsView {
            cfg: DnsConfig {
                magic_dns: true,
                search_domains: vec!["user.ts.net".to_string()],
                fallback_resolvers: vec![DnsResolver {
                    transport: ts_control::ResolverTransport::Udp("9.9.9.9:53".parse().unwrap()),
                    use_with_exit_node: false,
                }],
                ..Default::default()
            },
            peers: Some(Arc::new(db)),
            self_node: None,
            exit_doh: None,
        };

        // 100.64.0.9 is in CGNAT range but owned by no peer => NXDOMAIN, never a Forward.
        let buf = build_query(0x35, &["9", "0", "64", "100", "in-addr", "arpa"], 12, 1);
        match decide(&view, &buf).expect("decides") {
            Decision::Reply(resp) => {
                let (_, rcode, _) = parse_header(&resp);
                assert_eq!(rcode, 3, "NxDomain");
            }
            Decision::Forward { .. } => {
                panic!("tailnet CGNAT PTR must never be forwarded upstream")
            }
        }
    }

    #[test]
    fn is_tailnet_cgnat_classifies_range() {
        assert!(is_tailnet_cgnat("100.64.0.0".parse().unwrap()));
        assert!(is_tailnet_cgnat("100.64.0.1".parse().unwrap()));
        assert!(is_tailnet_cgnat("100.127.255.255".parse().unwrap()));
        // Outside the /10:
        assert!(!is_tailnet_cgnat("100.63.255.255".parse().unwrap()));
        assert!(!is_tailnet_cgnat("100.128.0.0".parse().unwrap()));
        assert!(!is_tailnet_cgnat("9.9.9.9".parse().unwrap()));
        // The MagicDNS resolver IP 100.100.100.100 is itself inside the /10.
        assert!(is_tailnet_cgnat("100.100.100.100".parse().unwrap()));
    }

    #[test]
    fn response_matches_query_validates_id_and_qr() {
        // query id 0x1234, QR=0
        let query = build_query(0x1234, &["a", "com"], 1, 1);

        // A well-formed response: same id, QR=1.
        let mut good = query.clone();
        good[2] |= 0x80;
        assert!(response_matches_query(&query, &good));

        // Same id but QR still 0 (not a response): rejected.
        assert!(!response_matches_query(&query, &query));

        // QR=1 but a different transaction id: rejected (off-path forgery).
        let mut wrong_id = good.clone();
        wrong_id[0] ^= 0xFF;
        assert!(!response_matches_query(&query, &wrong_id));

        // Too-short buffers: rejected.
        assert!(!response_matches_query(&query, &[0u8; 2]));
        assert!(!response_matches_query(&[0u8; 3], &good));
    }

    #[test]
    fn self_node_resolves_when_no_peer_match() {
        // With the peer db empty but a self node set, the self node answers for its own name.
        let view = DnsView {
            cfg: DnsConfig {
                magic_dns: true,
                search_domains: vec![],
                ..Default::default()
            },
            peers: None,
            self_node: Some(test_node()),
            exit_doh: None,
        };
        let buf = build_query(0x44, &["host", "user", "ts", "net"], 1, 1);

        let resp = answer(&view, &buf).expect("answers");
        let (_, rcode, ancount) = parse_header(&resp);
        assert_eq!(rcode, 0);
        assert_eq!(ancount, 1);
        let tail = &resp[resp.len() - 4..];
        assert_eq!(tail, &[100, 64, 0, 1]);
    }

    #[test]
    fn partially_qualified_name_resolves_via_search_domain() {
        // "host.user" is not indexed directly, but the "user.ts.net" search domain qualifies it
        // to "host.user.user.ts.net"... which does NOT match. The realistic case is "host" (bare,
        // already indexed) and "host.user.ts.net" (fqdn). Verify a name needing suffix expansion:
        // with search domain "ts.net" the partially-qualified "host.user" => "host.user.ts.net".
        let mut view = view_with_peer();
        view.cfg.search_domains = vec!["ts.net".to_string()];
        let buf = build_query(0x55, &["host", "user"], 1, 1);

        let resp = answer(&view, &buf).expect("answers");
        let (_, rcode, ancount) = parse_header(&resp);
        assert_eq!(rcode, 0, "NoError via search-domain expansion");
        assert_eq!(ancount, 1);
        let tail = &resp[resp.len() - 4..];
        assert_eq!(tail, &[100, 64, 0, 1]);
    }

    #[test]
    fn extra_record_a_answers_when_no_peer_match() {
        // A control-pushed static A record answers for a non-peer name, fail-closed otherwise.
        let mut view = view_with_peer();
        view.cfg.extra_records = vec![ts_control::ExtraRecord {
            name: "static.user.ts.net".to_string(),
            addr: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9)),
        }];
        let buf = build_query(0x77, &["static", "user", "ts", "net"], 1, 1);

        let resp = answer(&view, &buf).expect("answers");
        let (_, rcode, ancount) = parse_header(&resp);
        assert_eq!(rcode, 0, "NoError from extra record");
        assert_eq!(ancount, 1);
        let tail = &resp[resp.len() - 4..];
        assert_eq!(tail, &[100, 64, 0, 9]);
    }

    #[test]
    fn extra_record_matches_query_case_insensitively() {
        // The query name is canonicalized (lowercased) at decode time, so a mixed-case query
        // matches a lowercase extra record.
        let mut view = view_with_peer();
        view.cfg.extra_records = vec![ts_control::ExtraRecord {
            name: "static.user.ts.net".to_string(),
            addr: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9)),
        }];
        let buf = build_query(0x7A, &["Static", "User", "TS", "net"], 1, 1);

        let resp = answer(&view, &buf).expect("answers");
        let (_, rcode, ancount) = parse_header(&resp);
        assert_eq!(rcode, 0, "NoError: case-insensitive match");
        assert_eq!(ancount, 1);
        let tail = &resp[resp.len() - 4..];
        assert_eq!(tail, &[100, 64, 0, 9]);
    }

    #[test]
    fn extra_record_not_expanded_by_search_domain() {
        // Unlike peer names, an extra record is matched as an FQDN only: a bare query that would
        // need search-domain expansion to reach the record name must NOT resolve.
        let mut view = view_with_peer();
        view.cfg.extra_records = vec![ts_control::ExtraRecord {
            name: "static.user.ts.net".to_string(),
            addr: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9)),
        }];
        // "static" would only reach "static.user.ts.net" via the "user.ts.net" search domain.
        let buf = build_query(0x7B, &["static"], 1, 1);

        let resp = answer(&view, &buf).expect("answers");
        let (_, rcode, _) = parse_header(&resp);
        assert_eq!(rcode, 3, "NxDomain: extra records are not search-expanded");
    }

    #[test]
    fn extra_record_aaaa_family_is_isolated() {
        // An A-only extra record must NOT answer an AAAA query for the same name (NxDomain).
        let mut view = view_with_peer();
        view.cfg.extra_records = vec![ts_control::ExtraRecord {
            name: "v4only.user.ts.net".to_string(),
            addr: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9)),
        }];
        let buf = build_query(0x78, &["v4only", "user", "ts", "net"], 28, 1);

        let resp = answer(&view, &buf).expect("answers");
        let (_, rcode, _) = parse_header(&resp);
        assert_eq!(rcode, 3, "NxDomain: A record does not satisfy AAAA");
    }

    #[test]
    fn extra_record_ignored_when_magic_dns_off() {
        // Fail closed: extra records are never served while MagicDNS is disabled.
        let mut view = view_with_peer();
        view.cfg.magic_dns = false;
        view.cfg.extra_records = vec![ts_control::ExtraRecord {
            name: "static.user.ts.net".to_string(),
            addr: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9)),
        }];
        let buf = build_query(0x79, &["static", "user", "ts", "net"], 1, 1);

        let resp = answer(&view, &buf).expect("answers");
        let (_, rcode, _) = parse_header(&resp);
        assert_eq!(rcode, 5, "Refused");
    }

    #[test]
    fn non_in_class_is_refused() {
        // A CHAOS-class (3) query for a known name must be refused, not answered as IN.
        let view = view_with_peer();
        let buf = build_query(0x66, &["host", "user", "ts", "net"], 1, 3);

        let resp = answer(&view, &buf).expect("answers");
        let (_, rcode, ancount) = parse_header(&resp);
        assert_eq!(rcode, 5, "Refused");
        assert_eq!(ancount, 0);
    }

    /// A view with MagicDNS on, the `user.ts.net` search domain, and the given split-DNS routes
    /// + global resolvers.
    fn view_with_routes(
        routes: std::collections::BTreeMap<String, Vec<DnsResolver>>,
        resolvers: Vec<DnsResolver>,
        fallback: Vec<DnsResolver>,
    ) -> DnsView {
        DnsView {
            cfg: DnsConfig {
                magic_dns: true,
                search_domains: vec!["user.ts.net".to_string()],
                routes,
                resolvers,
                fallback_resolvers: fallback,
                ..Default::default()
            },
            peers: None,
            self_node: None,
            exit_doh: None,
        }
    }

    fn udp(addr: &str) -> DnsResolver {
        DnsResolver {
            transport: ts_control::ResolverTransport::Udp(addr.parse().unwrap()),
            use_with_exit_node: false,
        }
    }

    #[test]
    fn split_dns_route_forwards_to_matching_upstream() {
        let mut routes = std::collections::BTreeMap::new();
        routes.insert("corp.example".to_string(), vec![udp("10.0.0.53:53")]);
        let view = view_with_routes(routes, vec![], vec![]);
        let buf = build_query(0x100, &["api", "corp", "example"], 1, 1);

        match decide(&view, &buf).expect("decides") {
            Decision::Forward { upstreams, .. } => {
                assert_eq!(upstreams, vec!["10.0.0.53:53".parse().unwrap()]);
            }
            Decision::Reply(_) => panic!("expected forward to the split-DNS upstream"),
        }
    }

    #[test]
    fn longest_suffix_route_wins() {
        let mut routes = std::collections::BTreeMap::new();
        routes.insert("example".to_string(), vec![udp("10.0.0.1:53")]);
        routes.insert("corp.example".to_string(), vec![udp("10.0.0.2:53")]);
        let view = view_with_routes(routes, vec![], vec![]);
        let buf = build_query(0x101, &["api", "corp", "example"], 1, 1);

        match decide(&view, &buf).expect("decides") {
            Decision::Forward { upstreams, .. } => {
                assert_eq!(
                    upstreams,
                    vec!["10.0.0.2:53".parse().unwrap()],
                    "longer suffix wins"
                );
            }
            Decision::Reply(_) => panic!("expected forward"),
        }
    }

    #[test]
    fn negative_route_is_nxdomain_not_forwarded() {
        // An empty upstream list is a negative route: fail closed, never forward.
        let mut routes = std::collections::BTreeMap::new();
        routes.insert("blocked.example".to_string(), vec![]);
        let view = view_with_routes(routes, vec![udp("8.8.8.8:53")], vec![]);
        let buf = build_query(0x102, &["x", "blocked", "example"], 1, 1);

        match decide(&view, &buf).expect("decides") {
            Decision::Reply(resp) => {
                let (_, rcode, _) = parse_header(&resp);
                assert_eq!(rcode, 3, "NxDomain: negative route is not forwarded");
            }
            Decision::Forward { .. } => panic!("negative route must not forward"),
        }
    }

    #[test]
    fn unrouted_name_forwards_to_fallback_then_global() {
        // No route matches: fallback resolvers are preferred over global resolvers.
        let view = view_with_routes(
            std::collections::BTreeMap::new(),
            vec![udp("8.8.8.8:53")],
            vec![udp("1.1.1.1:53")],
        );
        let buf = build_query(0x103, &["example", "com"], 1, 1);

        match decide(&view, &buf).expect("decides") {
            Decision::Forward { upstreams, .. } => {
                assert_eq!(
                    upstreams,
                    vec!["1.1.1.1:53".parse().unwrap()],
                    "fallback preferred"
                );
            }
            Decision::Reply(_) => panic!("expected forward to fallback"),
        }
    }

    #[test]
    fn unrouted_name_forwards_to_global_when_no_fallback() {
        let view = view_with_routes(
            std::collections::BTreeMap::new(),
            vec![udp("8.8.8.8:53")],
            vec![],
        );
        let buf = build_query(0x104, &["example", "com"], 1, 1);

        match decide(&view, &buf).expect("decides") {
            Decision::Forward { upstreams, .. } => {
                assert_eq!(upstreams, vec!["8.8.8.8:53".parse().unwrap()]);
            }
            Decision::Reply(_) => panic!("expected forward to global resolver"),
        }
    }

    #[test]
    fn tailnet_name_is_never_forwarded() {
        // Anti-leak: a name under a tailnet search domain that has no overlay match must fail
        // closed to NXDOMAIN, never leak to an upstream resolver, even with resolvers configured.
        let view = view_with_routes(
            std::collections::BTreeMap::new(),
            vec![udp("8.8.8.8:53")],
            vec![udp("1.1.1.1:53")],
        );
        // "ghost.user.ts.net" is under the tailnet suffix but matches no peer.
        let buf = build_query(0x105, &["ghost", "user", "ts", "net"], 1, 1);

        match decide(&view, &buf).expect("decides") {
            Decision::Reply(resp) => {
                let (_, rcode, _) = parse_header(&resp);
                assert_eq!(rcode, 3, "NxDomain: tailnet name not leaked upstream");
            }
            Decision::Forward { .. } => panic!("tailnet name must never be forwarded"),
        }
    }

    #[test]
    fn no_resolvers_fails_closed() {
        // No route, no resolvers: an unknown name is NXDOMAIN, not forwarded.
        let view = view_with_routes(std::collections::BTreeMap::new(), vec![], vec![]);
        let buf = build_query(0x106, &["example", "com"], 1, 1);

        match decide(&view, &buf).expect("decides") {
            Decision::Reply(resp) => {
                let (_, rcode, _) = parse_header(&resp);
                assert_eq!(rcode, 3, "NxDomain");
            }
            Decision::Forward { .. } => panic!("must not forward with no resolvers"),
        }
    }

    #[test]
    fn overlay_match_wins_over_forwarding() {
        // A known peer name resolves authoritatively even when upstream resolvers are configured.
        let mut db = PeerDb::default();
        db.upsert(&test_node());
        let view = DnsView {
            cfg: DnsConfig {
                magic_dns: true,
                search_domains: vec!["user.ts.net".to_string()],
                resolvers: vec![udp("8.8.8.8:53")],
                ..Default::default()
            },
            peers: Some(Arc::new(db)),
            self_node: None,
            exit_doh: None,
        };
        let buf = build_query(0x107, &["host", "user", "ts", "net"], 1, 1);

        match decide(&view, &buf).expect("decides") {
            Decision::Reply(resp) => {
                let (_, rcode, ancount) = parse_header(&resp);
                assert_eq!(rcode, 0, "authoritative answer wins");
                assert_eq!(ancount, 1);
            }
            Decision::Forward { .. } => panic!("overlay match must not forward"),
        }
    }

    #[test]
    fn ipv6_reverse_ptr_is_nxdomain_not_forwarded() {
        // Anti-leak: an `ip6.arpa` reverse PTR for a tailnet ULA (fd7a:…) must fail closed to
        // NXDOMAIN, never be forwarded — even with an upstream resolver configured. This fork is
        // IPv4-only on the tailnet; forwarding would reveal that a v6 address was probed.
        let view = view_with_routes(
            std::collections::BTreeMap::new(),
            vec![udp("8.8.8.8:53")],
            vec![udp("1.1.1.1:53")],
        );
        // Reverse name for fd7a::1 (nibble-reversed) under ip6.arpa. The exact nibble labels don't
        // matter to the guard — any name ending in ip6.arpa must fail closed.
        let labels = vec![
            "1", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "a", "7", "d", "f", "ip6",
            "arpa",
        ];
        let buf = build_query(0x200, &labels, 12, 1);

        match decide(&view, &buf).expect("decides") {
            Decision::Reply(resp) => {
                let (_, rcode, _) = parse_header(&resp);
                assert_eq!(
                    rcode, 3,
                    "NxDomain: ip6.arpa reverse must not leak upstream"
                );
            }
            Decision::Forward { .. } => panic!("ip6.arpa PTR must never be forwarded"),
        }
    }

    #[test]
    fn cap_response_sets_tc_when_truncated() {
        // An oversize upstream answer is capped to a single datagram AND marked truncated (TC bit)
        // so the stub resolver retries over TCP rather than trusting a chopped message.
        let mut big = build_query(0x300, &["example", "com"], 1, 1);
        big[2] |= 0x80; // make it a response (QR=1)
        big.resize(MAX_UPSTREAM_RESPONSE + 500, 0xAB);

        let out = cap_response(big);
        assert_eq!(out.len(), MAX_UPSTREAM_RESPONSE, "capped to one datagram");
        assert_ne!(out[2] & 0x02, 0, "TC bit set on truncation");
    }

    #[test]
    fn cap_response_leaves_small_response_untouched() {
        // A response that fits is returned verbatim with no TC bit forced on.
        let mut small = build_query(0x301, &["example", "com"], 1, 1);
        small[2] |= 0x80;
        let before = small.clone();

        let out = cap_response(small);
        assert_eq!(out, before, "small response unchanged");
        assert_eq!(out[2] & 0x02, 0, "TC bit not set when no truncation");
    }

    #[test]
    fn response_matches_query_rejects_mismatched_question() {
        // id + QR match but the echoed question differs (different QNAME) => rejected. This guards
        // against an off-path injector that guesses the id but answers a different question.
        let query = build_query(0x1234, &["a", "com"], 1, 1);

        let mut wrong_question = build_query(0x1234, &["b", "com"], 1, 1);
        wrong_question[2] |= 0x80; // QR=1, same id
        assert!(
            !response_matches_query(&query, &wrong_question),
            "different QNAME must be rejected"
        );

        // A different QTYPE with the same name is also rejected.
        let mut wrong_qtype = build_query(0x1234, &["a", "com"], 28, 1);
        wrong_qtype[2] |= 0x80;
        assert!(
            !response_matches_query(&query, &wrong_qtype),
            "different QTYPE must be rejected"
        );

        // The exact echoed question with QR=1 is accepted.
        let mut good = query.clone();
        good[2] |= 0x80;
        assert!(
            response_matches_query(&query, &good),
            "matching question accepted"
        );
    }

    #[test]
    fn suffix_matches_handles_boundaries_and_empty() {
        // Exact and label-boundary matches.
        assert!(suffix_matches("corp", "corp"));
        assert!(suffix_matches("a.corp", "corp"));
        assert!(suffix_matches("a.b.corp", "corp"));
        // Not a label boundary.
        assert!(!suffix_matches("acorp", "corp"));
        // Empty suffix never matches (defense-in-depth against `ends_with("")`).
        assert!(!suffix_matches("anything.example", ""));
        assert!(!suffix_matches("", ""));
    }

    #[test]
    fn empty_search_domain_does_not_capture_everything() {
        // Defense-in-depth: an empty search domain must NOT make every name look like a tailnet
        // name (which would fail-close legitimate recursive queries / mis-route). With an empty
        // suffix present alongside a real resolver, an off-tailnet name still forwards.
        let mut view = view_with_routes(
            std::collections::BTreeMap::new(),
            vec![udp("8.8.8.8:53")],
            vec![],
        );
        view.cfg.search_domains = vec![String::new()];
        let buf = build_query(0x400, &["example", "com"], 1, 1);

        match decide(&view, &buf).expect("decides") {
            Decision::Forward { upstreams, .. } => {
                assert_eq!(upstreams, vec!["8.8.8.8:53".parse().unwrap()]);
            }
            Decision::Reply(_) => {
                panic!("empty search domain must not treat every name as tailnet")
            }
        }
    }

    #[test]
    fn empty_route_suffix_does_not_capture_everything() {
        // Defense-in-depth: an empty route suffix must not match every name (which would route all
        // queries to that route's upstreams). With an empty-suffix route present, an unrelated name
        // still falls through to the global resolver.
        let mut routes = std::collections::BTreeMap::new();
        routes.insert(String::new(), vec![udp("10.9.9.9:53")]);
        let view = view_with_routes(routes, vec![udp("8.8.8.8:53")], vec![]);
        let buf = build_query(0x401, &["example", "com"], 1, 1);

        match decide(&view, &buf).expect("decides") {
            Decision::Forward { upstreams, .. } => {
                assert_eq!(
                    upstreams,
                    vec!["8.8.8.8:53".parse().unwrap()],
                    "empty route suffix must not capture; falls through to global"
                );
            }
            Decision::Reply(_) => panic!("expected forward to global resolver"),
        }
    }

    fn udp_exit(addr: &str) -> DnsResolver {
        DnsResolver {
            transport: ts_control::ResolverTransport::Udp(addr.parse().unwrap()),
            use_with_exit_node: true,
        }
    }

    #[test]
    fn recursive_forward_is_flagged_route_forward_is_not() {
        // A recursive (global/fallback) forward sets `recursive = true` (eligible for DoH
        // delegation); a deliberately-configured split-DNS route sets `recursive = false`.
        let mut routes = std::collections::BTreeMap::new();
        routes.insert("corp.example".to_string(), vec![udp("10.0.0.53:53")]);
        let view = view_with_routes(routes, vec![udp("8.8.8.8:53")], vec![]);

        let routed = build_query(0x500, &["api", "corp", "example"], 1, 1);
        match decide(&view, &routed).expect("decides") {
            Decision::Forward { recursive, .. } => {
                assert!(!recursive, "split-DNS route is not a recursive forward")
            }
            Decision::Reply(_) => panic!("expected route forward"),
        }

        let global = build_query(0x501, &["example", "com"], 1, 1);
        match decide(&view, &global).expect("decides") {
            Decision::Forward { recursive, .. } => {
                assert!(recursive, "unrouted name is a recursive forward")
            }
            Decision::Reply(_) => panic!("expected recursive forward"),
        }
    }

    #[test]
    fn recursive_plan_keeps_udp_without_exit_node() {
        // No active exit node: a recursive forward stays on its default UDP upstreams.
        let view = view_with_routes(std::collections::BTreeMap::new(), vec![udp("8.8.8.8:53")], vec![]);
        let default = vec!["8.8.8.8:53".parse().unwrap()];
        assert_eq!(
            recursive_plan(&view, default.clone()),
            RecursivePlan::Udp(default)
        );
    }

    #[test]
    fn recursive_plan_delegates_to_doh_with_exit_node() {
        // Exit node active, no kept-local resolvers: recursive queries delegate to the exit node's
        // DoH endpoint so resolution egresses from the exit node, not this host.
        let mut view =
            view_with_routes(std::collections::BTreeMap::new(), vec![udp("8.8.8.8:53")], vec![]);
        let doh: SocketAddr = "100.64.0.5:8080".parse().unwrap();
        view.exit_doh = Some(doh);
        assert_eq!(
            recursive_plan(&view, vec!["8.8.8.8:53".parse().unwrap()]),
            RecursivePlan::Doh(doh)
        );
    }

    #[test]
    fn recursive_plan_keeps_use_with_exit_node_resolvers_local() {
        // Even with an exit node active, resolvers flagged `use_with_exit_node` stay local (Go keeps
        // UseWithExitNode resolvers). The plan forwards to those over UDP, never delegating to DoH.
        let mut view = view_with_routes(
            std::collections::BTreeMap::new(),
            vec![udp_exit("10.0.0.53:53"), udp("8.8.8.8:53")],
            vec![],
        );
        view.exit_doh = Some("100.64.0.5:8080".parse().unwrap());
        // The default upstreams the caller computed are irrelevant when kept-local resolvers exist;
        // the plan must use the kept-local ones.
        assert_eq!(
            recursive_plan(&view, vec!["8.8.8.8:53".parse().unwrap()]),
            RecursivePlan::Udp(vec!["10.0.0.53:53".parse().unwrap()])
        );
    }
}
