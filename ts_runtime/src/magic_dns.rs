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
//! opens an IPv6 socket. AAAA handling is gated on [`DnsView::enable_ipv6`] (default off): with the
//! gate OFF an AAAA query for a tailnet/overlay/self name returns NoError with an empty answer
//! (NODATA) rather than the overlay v6 address — answering a v6 the IPv4-only client can't route
//! would only create dead connections and a fingerprint. With the gate ON, AAAA is answered from
//! overlay data (the v6 overlay addr), as historically. AAAA for tailnet names is never forwarded
//! to a recursive upstream regardless of the gate.
//!
//! - MagicDNS disabled (`dns_config == None` or `magic_dns == false`), OR the node does not accept
//!   the tailnet DNS config ([`DnsView::accept_dns`] is `false`, i.e. `--accept-dns` / `CorpDNS`
//!   off) => `REFUSED` for every query (the responder serves nothing, mirroring Go applying an empty
//!   `dns.Config` when `CorpDNS` is off).
//! - A qtype/class we don't serve authoritatively (anything but IN-class A/AAAA/PTR — TXT, SRV, MX,
//!   HTTPS/SVCB, a CHAOS-class query, …) => NODATA (empty NOERROR) for a tailnet-authoritative name,
//!   forwarded verbatim to upstream for an off-tailnet name — exactly like Go's resolver, NOT
//!   `REFUSED` (a stub reads REFUSED as "won't serve me" and abandons the resolver). Tailnet reverse
//!   zones (CGNAT `in-addr.arpa` / any `ip6.arpa`) still fail closed to NXDOMAIN for every qtype
//!   (never forwarded — anti-leak).
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
use tokio::{
    sync::{Semaphore, watch},
    task::JoinSet,
    time::timeout,
};
use ts_control::{DnsConfig, DnsResolver, Node};
use ts_dns_wire::{Name, QType, RData, Rcode, decode_query, encode_response};

use crate::{
    Error,
    env::Env,
    peer_tracker::{PeerDb, PeerState},
};

/// How long to wait for an upstream resolver to answer a forwarded query before giving up.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);
/// Cap on concurrent in-flight forwarded queries on the local `100.100.100.100:53` responder.
///
/// Each forward is spawned onto a task that holds an overlay UDP socket until the upstream answers
/// or [`UPSTREAM_TIMEOUT`] elapses. Without a cap, a local/tailnet client spraying distinct
/// forwardable names opens unbounded concurrent overlay sockets + tasks (a resource-exhaustion DoS
/// on a slow/black-holed upstream, since each lingers for the full timeout). Bound it the same way
/// the peerAPI DoH server bounds its request handlers ([`crate::peerapi`]'s `MAX_INFLIGHT`): acquire
/// a permit before spawning and drop the query fail-closed when saturated. A dropped DNS query is a
/// benign outcome — the stub resolver simply retries or times out — and Go's resolver likewise
/// bounds outstanding forwards rather than spawning without limit.
const MAX_INFLIGHT_FORWARDS: usize = 512;
/// Cap on a forwarded upstream response we read into memory (a single UDP datagram).
///
/// Matches Go's forwarder read buffer (`maxResponseBytes`, ~4 KiB). The client's query is forwarded
/// verbatim, so a client advertising a large EDNS UDP size can elicit a legitimately large
/// (1300–4096 byte) UDP answer (big TXT sets, DNSSEC, many-record round-robins). Capping at the old
/// 1232 truncated those and set TC, forcing a TCP retry this fork's UDP-only forwarder can't serve —
/// so the large answer became unreachable. 4096 relays them intact.
const MAX_UPSTREAM_RESPONSE: usize = 4096;

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
    /// Whether IPv6 is enabled on the tailnet overlay (from [`Env::enable_ipv6`], default `false`).
    ///
    /// Governs the AAAA answer path only: with the gate OFF (default) an AAAA query for a
    /// tailnet/overlay/self name is answered NoError-with-empty-answer (NODATA) instead of the
    /// overlay v6 address; with it ON, AAAA is answered from overlay data as historically. Set once
    /// from the runtime `Env` when the actor starts; never changes for the life of the runtime.
    pub(crate) enable_ipv6: bool,
    /// Whether the tailnet's DNS configuration is accepted (`--accept-dns` / `CorpDNS`, from
    /// [`Env::accept_dns`]). When `false`, [`decide`] refuses every query (the responder serves
    /// nothing), mirroring Go applying an empty `dns.Config` when `CorpDNS` is off — so a node can
    /// join for connectivity without taking over DNS.
    ///
    /// Unlike [`enable_ipv6`](DnsView::enable_ipv6) (snapshotted once at actor spawn), this is
    /// runtime-settable via `Device::set_accept_dns`, so it is re-read from the live
    /// [`Env::accept_dns`] cell on **every** view rebuild (the `StateUpdate` and `PeerState`
    /// handlers), not just at spawn — otherwise a runtime toggle would never reach the served view.
    pub(crate) accept_dns: bool,
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

    // Fail closed: MagicDNS off, or the node doesn't accept the tailnet's DNS config
    // (`--accept-dns` / `CorpDNS` is false) => serve nothing. The `accept_dns` gate mirrors Go
    // applying an empty `dns.Config` when `CorpDNS` is off: the node ignores the control-pushed DNS
    // config and refuses every query. This one read site covers the netstack responder, the peerAPI
    // DoH server that shares the view, and (via `tun_actor::plan_intercept`) the TUN query path.
    if !view.cfg.magic_dns || !view.accept_dns {
        return Some(reply(Rcode::Refused, &[]));
    }

    let canon = q.name.to_canon();

    // We only serve the internet (IN) class authoritatively. A non-IN class (CHAOS, HESIOD, the
    // ANY/255 class, ...) is NOT refused outright: Go's local resolver does no class check and
    // forwards such a query like any other name. Treat it as an unsupported authoritative type —
    // NODATA for a tailnet name, forward for an off-tailnet name — so a `CH TXT version.bind`
    // diagnostic or a `qclass=ANY` probe reaches upstream instead of getting REFUSED.
    const CLASS_IN: u16 = 1;
    if q.qclass != CLASS_IN {
        return Some(forward_or_nodata(view, &canon, buf, id, q));
    }

    Some(match &q.qtype {
        QType::A => match view.resolve_addr(&canon, true) {
            Some(IpAddr::V4(v4)) => reply(Rcode::NoError, &[RData::A(v4.octets())]),
            // No overlay/extra-record answer: try split-DNS / recursive upstreams.
            _ => forward_or_nxdomain(view, &canon, buf, id, q),
        },
        QType::Aaaa => match view.resolve_addr(&canon, false) {
            // A tailnet/overlay/self (or extra-record) AAAA match. Gate on IPv6: with IPv6 OFF
            // (default) the client is IPv4-only, so answering with the overlay v6 address would
            // only hand out an unroutable address — dead connections plus a fingerprint. Return
            // NoError with an empty answer (NODATA) instead. With the gate ON, answer from overlay
            // data as historically. We never forward this name to a recursive upstream either way:
            // a positive overlay match is authoritative.
            Some(IpAddr::V6(v6)) if view.enable_ipv6 => {
                reply(Rcode::NoError, &[RData::Aaaa(v6.octets())])
            }
            Some(IpAddr::V6(_)) => reply(Rcode::NoError, &[]),
            // No overlay/extra-record answer: split-DNS / recursive upstreams (off-tailnet names);
            // tailnet names fail closed to NXDOMAIN inside `forward_or_nxdomain`.
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
        // Anything else (TXT, SRV, MX, HTTPS/SVCB, CNAME, ...): we hold no authoritative record of
        // that type, so — like Go's resolver — forward it to upstream for an off-tailnet name and
        // return NODATA (empty NOERROR) for a tailnet-authoritative name. NOT REFUSED: a stub reads
        // REFUSED as "this server won't serve me" and abandons the resolver, which would break
        // ordinary client lookups (notably HTTPS/SVCB type 65, issued routinely by browsers for
        // HTTP/3 + ECH) for the same off-tailnet names whose A/AAAA already forward.
        QType::Other(_) => forward_or_nodata(view, &canon, buf, id, q),
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

/// For a query whose *qtype/qclass* we don't serve authoritatively (anything other than an IN-class
/// A/AAAA/PTR — e.g. TXT, SRV, MX, HTTPS/SVCB, or a CHAOS-class query): forward it to upstream like
/// any other name, but for a tailnet-authoritative name return an empty NOERROR (NODATA) instead of
/// NXDOMAIN.
///
/// This mirrors Go's resolver: an authoritative name with no record of the requested type returns
/// `RCodeSuccess` with no answers ("the name exists, but no records of that type"), NOT NXDOMAIN and
/// NOT REFUSED; a non-authoritative name is forwarded verbatim regardless of qtype. The fork
/// previously REFUSED every non-A/AAAA/PTR qtype (and every non-IN class) for *all* names, which a
/// stub resolver reads as "this server won't serve me" — so it would abandon the resolver, breaking
/// ordinary client lookups (HTTPS/SVCB type 65 issued routinely by browsers for HTTP/3 + ECH, plus
/// MX/TXT/SRV) for off-tailnet names that A/AAAA queries already forward. Refusing these was never an
/// anti-leak measure (the same name's A/AAAA already egresses); it was just broken interop.
///
/// Anti-leak is preserved: a tailnet-suffix name still never leaves this node (NODATA, not forward),
/// exactly as the A/AAAA path keeps a positive overlay match authoritative.
fn forward_or_nodata(
    view: &DnsView,
    canon: &str,
    buf: &[u8],
    id: u16,
    q: &ts_dns_wire::Question,
) -> Decision {
    // Authoritative tailnet name: NODATA (empty NOERROR), not NXDOMAIN — the name exists.
    if is_tailnet_name(view, canon) {
        return Decision::Reply(encode_response(id, q, Rcode::NoError, &[]));
    }
    // Anti-leak parity with the `QType::Ptr` arm: a reverse query for a tailnet CGNAT IPv4
    // (100.64.0.0/10) or ANY `ip6.arpa` name must NEVER egress to an upstream resolver, regardless
    // of qtype/class — forwarding it would reveal that a specific tailnet IP was probed. The PTR arm
    // enforces this (NXDOMAIN) but its guards live only inside that arm; without re-checking here, an
    // exotic-qtype (TXT/ANY/…) or non-IN-class query for a tailnet reverse name would slip through to
    // the forward path below. Fail closed to NXDOMAIN, matching the PTR arm's disposition.
    if is_ip6_arpa(canon) {
        return Decision::Reply(encode_response(id, q, Rcode::NxDomain, &[]));
    }
    if let Some(octets) = q.name.ptr_to_ipv4()
        && is_tailnet_cgnat(octets.into())
    {
        return Decision::Reply(encode_response(id, q, Rcode::NxDomain, &[]));
    }
    // Off-tailnet, non-reverse-zone: forward verbatim. `forward_or_nxdomain` already forwards
    // non-tailnet names and fails closed (NXDOMAIN) when no upstream is configured/routable; reuse it
    // (the tailnet branch above is already handled, so its tailnet→NXDOMAIN path is unreachable here).
    forward_or_nxdomain(view, canon, buf, id, q)
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
    // Bounds concurrent in-flight forwards (see `MAX_INFLIGHT_FORWARDS`); a permit is held for the
    // lifetime of each spawned forward task and released on completion.
    let inflight = Arc::new(Semaphore::new(MAX_INFLIGHT_FORWARDS));
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
                // Fail closed at the in-flight cap: drop the query (the stub resolver retries or
                // times out) rather than spawn an unbounded task that pins an overlay socket for up
                // to UPSTREAM_TIMEOUT. The permit is moved into the task as a named `_permit` binding
                // (NOT `let _ =`, which would drop it immediately) so it is released only when the
                // task body completes.
                let Ok(permit) = inflight.clone().try_acquire_owned() else {
                    tracing::warn!(
                        %src,
                        max = MAX_INFLIGHT_FORWARDS,
                        "magic dns drop: at max in-flight forwarded queries"
                    );
                    continue;
                };
                let socket = socket.clone();
                let channel = channel.clone();
                forwards.spawn(async move {
                    let _permit = permit;
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

        // Reap finished forward tasks without blocking. The unreaped completed-handle backlog is
        // bounded by MAX_INFLIGHT_FORWARDS (a task spawns only after acquiring a permit, and there
        // are at most that many), so this bounds JoinSet memory too — not just the reap cadence.
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
    /// The runtime [`Env`], retained so each view rebuild (the `StateUpdate` / `PeerState` handlers)
    /// can re-read the live [`Env::accept_dns`] cell. Unlike `enable_ipv6` (snapshotted once at
    /// spawn), `accept_dns` is runtime-settable via `Device::set_accept_dns`, so it must be read at
    /// rebuild time — not captured once — for a toggle to reach the served view.
    env: Env,
    /// The overlay channel, retained so the [`Query`] handler can run a query through the same
    /// forward path the serve loop uses ([`forward_query`] / [`forward_doh`], both binding
    /// `0.0.0.0:0` on this channel — never a host socket).
    channel: Channel,
}

/// A programmatic DNS query routed through the live MagicDNS responder (the `100.100.100.100` path),
/// for [`Device::query_dns`](crate::Device::query_dns). The handler synthesizes a query packet and
/// drives it through the exact same [`decide`]/forward logic as an on-the-wire query, so the result
/// (and its anti-leak posture) matches what a tailnet client would observe.
pub struct Query {
    /// The canonical name to resolve (e.g. `example.com`, no trailing dot).
    pub name: String,
    /// The DNS query type (`1`=A, `28`=AAAA, `12`=PTR, or any other RFC 1035 TYPE).
    pub qtype: u16,
}

/// The outcome of a `Query`: the raw DNS response bytes, the RCODE, and which upstream resolvers
/// (if any) were consulted. The response is returned as raw bytes (matching Go `LocalClient.QueryDNS`)
/// rather than parsed records — this fork's wire codec has no answer-record decoder.
///
/// (`Query` is the crate-internal actor message; not linked here as it is a private item — a
/// `pub` doc cannot intra-doc-link to it without erroring under the doc-lint gate.)
#[derive(Debug, Clone, kameo::Reply)]
pub struct DnsQueryResult {
    /// The raw DNS response datagram (header + question + any answer records).
    pub response: Vec<u8>,
    /// The RCODE from the response header's low 4 bits (`0`=NoError, `2`=SERVFAIL, `3`=NXDOMAIN,
    /// `5`=Refused, …).
    pub rcode: u8,
    /// The upstream resolver(s) the query was forwarded to. For a UDP forward this is the candidate
    /// list tried in order (the forwarder returns on the first that answers); for an exit-node DoH
    /// forward it is the single DoH endpoint. Empty for a locally-answered query (an authoritative
    /// tailnet name, a NODATA, or a fail-closed NXDOMAIN — nothing egressed).
    pub resolvers_consulted: Vec<SocketAddr>,
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

        // Seed the view with the runtime's IPv6 gate (default off) and the current accept-dns value.
        // Subsequent control/peer updates clone-and-modify this view: `enable_ipv6` (set once here)
        // is preserved, while `accept_dns` is re-read live from `Env` on every rebuild (it is
        // runtime-settable). The seed value is moot — no query is served before the first
        // StateUpdate — but seeding it keeps the pre-update view internally consistent.
        let (view_tx, view_rx) = watch::channel(Arc::new(DnsView {
            enable_ipv6: env.enable_ipv6,
            accept_dns: env.accept_dns(),
            ..DnsView::default()
        }));

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

        // When this node advertises a peerAPI port, run the single peerAPI server on the same shared
        // view. It routes `/dns-query` to the exit-node DoH handler (recursive resolution gated by
        // `forward_exit_egress`, see `peerapi_doh`) and `/v0/put/<name>` to the Taildrop receive
        // handler when a store is configured (access-gated, fail-closed, see `peerapi`).
        if let Some(port) = env.peerapi_port {
            let channel = channel.clone();
            let view_rx = view_rx.clone();
            let forward_exit_egress = env.forward_exit_egress;
            let taildrop = env.taildrop_store.clone();
            let funnel_ingress = env.funnel_ingress.clone();
            joinset.spawn(crate::peerapi::serve(
                channel,
                port,
                view_rx,
                forward_exit_egress,
                taildrop,
                funnel_ingress,
            ));
        }

        Ok(Self {
            _joinset: joinset,
            view_tx,
            env,
            channel,
        })
    }
}

/// A bare SERVFAIL response header for a [`Query`] whose name could not be encoded into a
/// well-formed query (a non-ASCII label or an over-255-byte name). A 12-byte header with QR=1 (this
/// is a response) and RCODE=2 (server failure); no question or answer section (we never produced a
/// parseable question). Lets `query_dns` return a definite, honest RCODE instead of an empty buffer
/// that would read back as a fabricated NoError.
fn servfail_response() -> Vec<u8> {
    let mut resp = vec![0u8; 12];
    // Flags: QR=1 (byte 2, 0x80) + RCODE=2 (low nibble of byte 3). All other bits clear.
    resp[2] = 0x80;
    resp[3] = 0x02;
    resp
}

impl Message<Query> for MagicDnsActor {
    type Reply = DnsQueryResult;

    async fn handle(&mut self, query: Query, _ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        // Synthesize a query packet and drive it through the SAME decide/forward path the serve loop
        // uses, against the freshest view — so the result and its anti-leak posture exactly match an
        // on-the-wire query. The id is fixed (0): a programmatic query has no concurrent-demux need,
        // and `response_matches_query` validates the echoed id against this same buffer.
        //
        // Normalize the name into labels: strip a single trailing dot (an FQDN's root marker — Go's
        // `dnsname.ToFQDN` does the same) and drop empty labels. An empty label would otherwise encode
        // as a lone `0x00`, identical to the QNAME root terminator, truncating the wire query and
        // corrupting the QTYPE/QCLASS that follow.
        let trimmed = query.name.strip_suffix('.').unwrap_or(&query.name);
        let labels: Vec<String> = trimmed
            .split('.')
            .filter(|label| !label.is_empty())
            .map(str::to_owned)
            .collect();
        let qtype = match query.qtype {
            1 => ts_dns_wire::QType::A,
            28 => ts_dns_wire::QType::Aaaa,
            12 => ts_dns_wire::QType::Ptr,
            other => ts_dns_wire::QType::Other(other),
        };
        // Class IN (1) — the only class the responder serves authoritatively (a non-IN class still
        // forwards via `forward_or_nodata`, matching the on-the-wire path).
        let buf = ts_dns_wire::encode_query(0, &ts_dns_wire::Name(labels), &qtype, 1);

        let view = self.view_tx.borrow().clone();

        let (response, resolvers_consulted) = match decide(&view, &buf) {
            // `decide` returns `None` only when `decode_query` rejects the buffer we just built. With
            // the name normalized above that can still happen for a name `encode_query` accepts but
            // `decode_query` rejects — a non-ASCII/IDN label (the caller must pass punycode) or a name
            // whose wire form exceeds 255 bytes. Surface a SERVFAIL (RCODE 2: "could not process")
            // rather than an empty buffer that would read back as a fabricated NoError. The serve loop
            // silently drops here (the on-wire client times out); a programmatic caller gets a
            // definite, honest error instead.
            None => (servfail_response(), Vec::new()),
            Some(Decision::Reply(resp)) => (resp, Vec::new()),
            Some(Decision::Forward {
                upstreams,
                query,
                nxdomain,
                recursive,
            }) => {
                let plan = if recursive {
                    recursive_plan(&view, upstreams)
                } else {
                    RecursivePlan::Udp(upstreams)
                };
                match plan {
                    RecursivePlan::Udp(upstreams) => {
                        let resp = forward_query(&self.channel, &upstreams, &query, nxdomain).await;
                        (resp, upstreams)
                    }
                    RecursivePlan::Doh(doh_addr) => {
                        let resp = crate::peerapi_doh::forward_doh(
                            &self.channel,
                            doh_addr,
                            &query,
                            nxdomain,
                        )
                        .await;
                        // The query egressed via the exit node's DoH endpoint, not a local UDP
                        // upstream — report the DoH address as the resolver consulted.
                        (resp, vec![doh_addr])
                    }
                }
            }
        };

        // RCODE is the low 4 bits of the second flags byte (header byte 3).
        let rcode = response.get(3).map(|b| b & 0x0F).unwrap_or(0);

        DnsQueryResult {
            response,
            rcode,
            resolvers_consulted,
        }
    }
}

impl Message<Arc<ts_control::StateUpdate>> for MagicDnsActor {
    type Reply = ();

    async fn handle(
        &mut self,
        update: Arc<ts_control::StateUpdate>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        // Re-read the live accept-dns cell on every rebuild (it is runtime-settable via
        // `Device::set_accept_dns`); `enable_ipv6` is preserved from the seed (set once at spawn).
        let accept_dns = self.env.accept_dns();
        self.view_tx.send_modify(|view| {
            let mut next = (**view).clone();
            next.cfg = update.dns_config.clone().unwrap_or_default();
            next.self_node = update.node.clone();
            next.accept_dns = accept_dns;
            *view = Arc::new(next);
        });
    }
}

impl Message<Arc<PeerState>> for MagicDnsActor {
    type Reply = ();

    async fn handle(&mut self, state: Arc<PeerState>, _ctx: &mut Context<Self, Self::Reply>) {
        // Re-read the live accept-dns cell on every rebuild: `Device::set_accept_dns` triggers a
        // `RepublishState` that lands here, so this is the path that re-applies the gate after a
        // runtime toggle (covers the netstack responder AND the peerAPI DoH server sharing the view).
        let accept_dns = self.env.accept_dns();
        self.view_tx.send_modify(|view| {
            let mut next = (**view).clone();
            next.peers = Some(state.peers.clone());
            next.accept_dns = accept_dns;
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
            user_id: 0,
            tailnet: Some("user.ts.net".to_string()),
            tags: vec![],
            tailnet_address: TailnetAddress {
                ipv4: "100.64.0.1/32".parse().unwrap(),
                ipv6: "fd7a::1/128".parse().unwrap(),
            },
            node_key: [0u8; 32].into(),
            node_key_expiry: None,
            online: None,
            last_seen: None,
            key_signature: vec![],
            machine_key: None,
            disco_key: None,
            accepted_routes: vec![],
            underlay_addresses: vec![],
            derp_region: None,
            cap: Default::default(),
            cap_map: Default::default(),
            peerapi_port: None,
            peerapi_dns_proxy: false,
            is_wireguard_only: false,
            exit_node_dns_resolvers: vec![],
            peer_relay: false,
            service_vips: Default::default(),
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
            enable_ipv6: false,
            accept_dns: true,
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
    fn aaaa_query_for_known_peer_is_nodata_when_ipv6_off() {
        // Gate OFF (default): an AAAA query for a known overlay peer must return NoError with an
        // empty answer (NODATA) — NOT the overlay v6 address, which the IPv4-only client can't
        // route. This is the anti-fingerprint / no-dead-connections posture.
        let view = view_with_peer();
        assert!(!view.enable_ipv6, "default gate is off");
        let buf = build_query(0x5, &["host", "user", "ts", "net"], 28, 1);

        let resp = answer(&view, &buf).expect("answers");
        let (_, rcode, ancount) = parse_header(&resp);
        assert_eq!(rcode, 0, "NoError (NODATA)");
        assert_eq!(ancount, 0, "empty answer: no AAAA handed out with IPv6 off");
    }

    #[test]
    fn a_query_still_resolves_when_ipv6_off() {
        // Gate OFF must not touch the A (v4) path: the v4 answer is byte-for-byte unchanged.
        let view = view_with_peer();
        let buf = build_query(0x6, &["host", "user", "ts", "net"], 1, 1);

        let resp = answer(&view, &buf).expect("answers");
        let (_, rcode, ancount) = parse_header(&resp);
        assert_eq!(rcode, 0, "NoError");
        assert_eq!(ancount, 1);
        let tail = &resp[resp.len() - 4..];
        assert_eq!(tail, &[100, 64, 0, 1]);
    }

    #[test]
    fn aaaa_query_for_known_peer_answers_v6_when_ipv6_on() {
        // Gate ON: historical behavior — answer AAAA from the overlay v6 address.
        let mut view = view_with_peer();
        view.enable_ipv6 = true;
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
    fn aaaa_for_unknown_tailnet_name_is_nxdomain_not_forwarded_with_ipv6_off() {
        // Anti-leak, unchanged by the gate: an AAAA for a name under the tailnet suffix that has no
        // overlay match still fails closed to NXDOMAIN — never forwarded to a recursive upstream,
        // even with resolvers configured. (Gate OFF only changes the *positive* overlay match into
        // NODATA; a non-match still routes through `forward_or_nxdomain`.)
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
            enable_ipv6: false,
            accept_dns: true,
        };
        let buf = build_query(0x5A, &["ghost", "user", "ts", "net"], 28, 1);

        match decide(&view, &buf).expect("decides") {
            Decision::Reply(resp) => {
                let (_, rcode, _) = parse_header(&resp);
                assert_eq!(rcode, 3, "NxDomain: tailnet AAAA not leaked upstream");
            }
            Decision::Forward { .. } => panic!("tailnet AAAA must never be forwarded"),
        }
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
    fn accept_dns_false_refuses_otherwise_answerable_query() {
        // The accept-dns gate (Go `CorpDNS`): with `accept_dns == false` the node ignores the
        // tailnet DNS config, so even a known peer name that would normally answer authoritatively is
        // REFUSED (the responder serves nothing) — mirroring Go applying an empty `dns.Config`.
        let mut view = view_with_peer();
        assert!(view.cfg.magic_dns, "MagicDNS itself is on");
        view.accept_dns = false;
        let buf = build_query(0xDD, &["host", "user", "ts", "net"], 1, 1);

        let resp = answer(&view, &buf).expect("answers");
        let (_, rcode, ancount) = parse_header(&resp);
        assert_eq!(rcode, 5, "Refused: accept_dns off ⇒ serve nothing");
        assert_eq!(ancount, 0);

        // Flip accept_dns back ON (the config was never destroyed, only gated): the same query now
        // answers authoritatively — proving the OFF→ON restore is automatic.
        view.accept_dns = true;
        let resp = answer(&view, &buf).expect("answers");
        let (_, rcode, ancount) = parse_header(&resp);
        assert_eq!(rcode, 0, "NoError: accept_dns on ⇒ the known peer answers");
        assert_eq!(ancount, 1);
        let tail = &resp[resp.len() - 4..];
        assert_eq!(tail, &[100, 64, 0, 1], "the peer's tailnet v4 is served");
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
    fn unsupported_qtype_on_tailnet_name_is_nodata_not_refused() {
        // TXT (type 16) for a tailnet-authoritative name: the name exists but we hold no TXT, so —
        // like Go — return NODATA (empty NOERROR), NOT REFUSED (which would make a stub abandon the
        // resolver) and NOT NXDOMAIN (the name exists). The name is never forwarded (anti-leak).
        let view = view_with_peer();
        let buf = build_query(0x1, &["host", "user", "ts", "net"], 16, 1);

        let resp = answer(&view, &buf).expect("answers");
        let (_, rcode, ancount) = parse_header(&resp);
        assert_eq!(rcode, 0, "NoError (NODATA), not Refused");
        assert_eq!(ancount, 0, "no answer records (NODATA)");
    }

    #[test]
    fn unsupported_qtype_off_tailnet_forwards_or_nxdomains() {
        // A non-A/AAAA/PTR qtype for an OFF-tailnet name must be forwardable like A/AAAA — never
        // REFUSED. With no upstream configured in this view it fails closed to NXDOMAIN (the same
        // disposition an off-tailnet A query gets here), proving the qtype no longer short-circuits
        // to REFUSED. HTTPS/SVCB is type 65 (the browser HTTP/3 + ECH case the old REFUSED broke).
        let view = view_with_peer();
        let buf = build_query(0x1, &["example", "com"], 65, 1);

        let resp = answer(&view, &buf).expect("answers");
        let (_, rcode, _) = parse_header(&resp);
        assert_eq!(
            rcode, 3,
            "off-tailnet, no upstream -> NXDOMAIN (forwardable, not Refused)"
        );
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
            enable_ipv6: false,
            accept_dns: true,
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

    /// Anti-leak regression for the exotic-qtype forward path: a NON-PTR query (TXT, type 16) for a
    /// tailnet CGNAT reverse name, with an upstream configured, must STILL fail closed to NXDOMAIN —
    /// never forward. The PTR arm guards this, but the `QType::Other` path routes through
    /// `forward_or_nodata`, which must re-apply the reverse-zone guard or the tailnet IP leaks.
    #[test]
    fn exotic_qtype_for_tailnet_cgnat_reverse_is_nxdomain_not_forwarded() {
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
            enable_ipv6: false,
            accept_dns: true,
        };

        // TXT (16) for a CGNAT reverse name => NXDOMAIN, never a Forward (no tailnet-IP leak).
        let buf = build_query(0x36, &["9", "0", "64", "100", "in-addr", "arpa"], 16, 1);
        match decide(&view, &buf).expect("decides") {
            Decision::Reply(resp) => {
                let (_, rcode, _) = parse_header(&resp);
                assert_eq!(rcode, 3, "NxDomain");
            }
            Decision::Forward { .. } => {
                panic!("a non-PTR query for a tailnet CGNAT reverse name must never forward")
            }
        }
    }

    /// Same anti-leak guard for an `ip6.arpa` reverse name under an exotic qtype: must NXDOMAIN, not
    /// forward (revealing a tailnet ULA was probed).
    #[test]
    fn exotic_qtype_for_ip6_arpa_is_nxdomain_not_forwarded() {
        let view = view_with_routes(
            std::collections::BTreeMap::new(),
            vec![udp("9.9.9.9:53")],
            vec![],
        );
        // An ip6.arpa reverse name with a TXT (16) qtype must fail closed.
        let buf = build_query(
            0x37,
            &[
                "1", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
                "a", "7", "d", "f", "ip6", "arpa",
            ],
            16,
            1,
        );
        match decide(&view, &buf).expect("decides") {
            Decision::Reply(resp) => {
                let (_, rcode, _) = parse_header(&resp);
                assert_eq!(rcode, 3, "NxDomain");
            }
            Decision::Forward { .. } => panic!("an ip6.arpa exotic-qtype query must never forward"),
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
            enable_ipv6: false,
            accept_dns: true,
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
    fn non_in_class_on_tailnet_name_is_nodata_not_answered_as_in() {
        // A CHAOS-class (3) query for a tailnet name must NOT be answered as IN (no overlay A), and
        // must NOT be REFUSED (Go does no class check on the local path). It's an unsupported
        // authoritative class -> NODATA (empty NOERROR), and never forwarded (tailnet name).
        let view = view_with_peer();
        let buf = build_query(0x66, &["host", "user", "ts", "net"], 1, 3);

        let resp = answer(&view, &buf).expect("answers");
        let (_, rcode, ancount) = parse_header(&resp);
        assert_eq!(
            rcode, 0,
            "NoError (NODATA), not Refused and not an IN answer"
        );
        assert_eq!(
            ancount, 0,
            "must not hand out the overlay A for a non-IN class"
        );
    }

    #[test]
    fn non_in_class_off_tailnet_forwards_or_nxdomains() {
        // A non-IN class for an OFF-tailnet name is forwardable (Go forwards it), never REFUSED.
        // No upstream here -> NXDOMAIN, proving the class gate no longer short-circuits to Refused.
        let view = view_with_peer();
        let buf = build_query(0x66, &["example", "com"], 1, 3);

        let resp = answer(&view, &buf).expect("answers");
        let (_, rcode, _) = parse_header(&resp);
        assert_eq!(
            rcode, 3,
            "off-tailnet non-IN class, no upstream -> NXDOMAIN, not Refused"
        );
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
            enable_ipv6: false,
            accept_dns: true,
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
    fn exotic_qtype_off_tailnet_forwards_to_upstream() {
        // The core of the fix: an HTTPS/SVCB (type 65) query for an off-tailnet name with a matching
        // route must FORWARD to the upstream (verbatim), exactly like an A query would — not REFUSE
        // and not NXDOMAIN. This is the browser HTTP/3 + ECH case the old blanket-REFUSE broke.
        let mut routes = std::collections::BTreeMap::new();
        routes.insert("corp.example".to_string(), vec![udp("10.0.0.53:53")]);
        let view = view_with_routes(routes, vec![], vec![]);
        let buf = build_query(0x102, &["api", "corp", "example"], 65, 1);

        match decide(&view, &buf).expect("decides") {
            Decision::Forward {
                upstreams, query, ..
            } => {
                assert_eq!(upstreams, vec!["10.0.0.53:53".parse().unwrap()]);
                assert_eq!(query, buf, "the exotic-qtype query is forwarded verbatim");
            }
            Decision::Reply(_) => {
                panic!("an off-tailnet HTTPS-record query must forward, not reply")
            }
        }
    }

    #[test]
    fn non_in_class_off_tailnet_forwards_to_upstream() {
        // A non-IN class for an off-tailnet routed name forwards too (Go does no class check on the
        // local path). Proves the class gate no longer short-circuits to REFUSED before routing.
        let mut routes = std::collections::BTreeMap::new();
        routes.insert("corp.example".to_string(), vec![udp("10.0.0.53:53")]);
        let view = view_with_routes(routes, vec![], vec![]);
        let buf = build_query(0x103, &["api", "corp", "example"], 1, 3);

        match decide(&view, &buf).expect("decides") {
            Decision::Forward { upstreams, .. } => {
                assert_eq!(upstreams, vec!["10.0.0.53:53".parse().unwrap()]);
            }
            Decision::Reply(_) => {
                panic!("an off-tailnet non-IN-class query must forward, not reply")
            }
        }
    }

    /// The local responder bounds concurrent in-flight forwards: `serve` acquires one
    /// `MAX_INFLIGHT_FORWARDS` permit per spawned forward task and drops the query fail-closed when
    /// the pool is exhausted (a client spraying forwardable names can't open unbounded overlay
    /// sockets). This pins the gating semantics `serve` relies on — drained pool refuses a new
    /// permit; releasing one restores capacity — and the cap constant itself. (The async `serve`
    /// loop has no netstack-free test seam, so the semaphore behavior is exercised directly here, the
    /// same `Arc<Semaphore>::try_acquire_owned` the loop uses.)
    #[test]
    fn forward_inflight_cap_fails_closed_when_saturated() {
        use std::sync::Arc;

        use tokio::sync::Semaphore;

        let inflight = Arc::new(Semaphore::new(MAX_INFLIGHT_FORWARDS));

        // Drain every permit (one per concurrently in-flight forward).
        let mut held = Vec::with_capacity(MAX_INFLIGHT_FORWARDS);
        for _ in 0..MAX_INFLIGHT_FORWARDS {
            held.push(
                inflight
                    .clone()
                    .try_acquire_owned()
                    .expect("permits available below the cap"),
            );
        }

        // At the cap, the next forward is refused — `serve` would drop the query, not spawn.
        assert!(
            inflight.clone().try_acquire_owned().is_err(),
            "a saturated forward pool must refuse a new permit (fail closed)"
        );

        // Completing an in-flight forward releases its permit and restores capacity.
        drop(held.pop());
        assert!(
            inflight.clone().try_acquire_owned().is_ok(),
            "releasing a permit must let the next forward proceed"
        );
    }

    /// A permit moved into a spawned forward task (the `let _permit = permit;` shape `serve` uses)
    /// must stay held for the *whole* task body — across the `.await` on the upstream — and release
    /// only when the task completes. This guards the regression the saturation test above can't see:
    /// "tidying" `let _permit = permit;` to `let _ = permit;` would drop the permit immediately,
    /// re-opening unbounded concurrency while leaving the synchronous drain/restore test green. Here a
    /// 1-permit pool is consumed by a task that holds it across a yield; the pool must read empty
    /// while the task runs and refill once it finishes.
    #[tokio::test]
    async fn forward_permit_is_held_for_the_task_lifetime_not_dropped_early() {
        use std::sync::Arc;

        use tokio::sync::Semaphore;

        let inflight = Arc::new(Semaphore::new(1));
        let permit = inflight
            .clone()
            .try_acquire_owned()
            .expect("the sole permit is available");

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            // Same shape as `serve`'s spawned forward: the permit is a named binding moved into the
            // task, so it lives until the body ends — not dropped at the `let`.
            let _permit = permit;
            started_tx.send(()).unwrap();
            // Stand in for the `.await` on the upstream forward.
            release_rx.await.unwrap();
        });

        started_rx.await.unwrap();
        // While the task runs, the permit it moved in is still held — the pool is empty.
        assert!(
            inflight.clone().try_acquire_owned().is_err(),
            "a permit moved into a running task must stay held across its await"
        );

        // Let the task finish; its permit drops with the body and capacity returns.
        release_tx.send(()).unwrap();
        task.await.unwrap();
        assert!(
            inflight.clone().try_acquire_owned().is_ok(),
            "the permit must be released once the task body completes"
        );
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
            enable_ipv6: false,
            accept_dns: true,
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
        let view = view_with_routes(
            std::collections::BTreeMap::new(),
            vec![udp("8.8.8.8:53")],
            vec![],
        );
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
        let mut view = view_with_routes(
            std::collections::BTreeMap::new(),
            vec![udp("8.8.8.8:53")],
            vec![],
        );
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
