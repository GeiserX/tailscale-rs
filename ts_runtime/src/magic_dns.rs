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
//! - **A refusing upstream does not end a forward**: a `REFUSED` or `SERVFAIL` from one upstream is
//!   a *soft* error — the next upstream on the route (or in the fallback list) is tried, and the
//!   refusal is relayed to the client only when no upstream did better (see [`forward_query`]).
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
//! - A **negative** answer this node is authoritative for — an NXDOMAIN for a name inside a zone we
//!   serve (a tailnet search domain, a negative split-DNS route, or the CGNAT reverse zone), or a
//!   NODATA for such a name — carries that zone's `SOA` in the authority section, advertising a
//!   10-second negative-caching bound (RFC 2308). Without one, macOS `mDNSResponder` keeps an
//!   SOA-less negative answer on its own schedule, so a name queried shortly *before* a node was
//!   renamed to it stays unresolvable until something flushes the cache. Positive answers carry a
//!   5-second TTL for the same reason in the other direction. `SERVFAIL`, `REFUSED` and the blanket
//!   `ip6.arpa` refusal claim no zone and carry no SOA.
//! - Malformed query => dropped (no response).
//! - A reply larger than the UDP payload size the query advertised — its EDNS(0) OPT record, or 512
//!   bytes when it carried none or carried one this node will not act on (RFC 1035) — comes back
//!   with the `TC` (truncated) bit set and its body intact, so the stub resolver knows to retry over
//!   TCP ([`check_response_size_and_set_tc`]). This applies to forwarded replies, where the query is
//!   relayed verbatim and so this is what catches an upstream that ignores the size its requestor
//!   asked for, and equally to answers this node composes itself. The retry that bit asks for is served
//!   by the `dns_over_tcp` server (TUN mode), which reaches the same [`decide`] through
//!   the same view — and which is never handed a `TC` bit for size, since a TCP client has no
//!   datagram to overflow (see [`ClientTransport`]).

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
use ts_dns_wire::{Name, QType, RData, Rcode, SoaZone, decode_query, encode_response};

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
/// Cap on how much of a forwarded upstream response we relay back to the stub resolver (a single
/// UDP datagram).
///
/// This is Go's `maxResponseBytes` — `const maxResponseBytes = 4095`, defined in
/// net/dns/resolver/tsdns.go @ 9ea7cba44591e0cd840c6c94d23274dd222059bf and used by the forwarder.
/// The odd-looking 4095 is deliberate upstream: `sendUDP` reads into a `maxResponseBytes+1` buffer
/// precisely so that a 4096-byte read is *detectable* as "the answer did not fit", and then cuts the
/// reply back to 4095 and sets `TC`. A 4096-byte answer is a truncated answer everywhere else in a
/// tailnet, so it has to be one here too: relaying it whole with `TC` clear is a message a Go peer
/// would have handed its stub resolver as truncated.
///
/// *Where the bound applies differs from Go*: here it is not a read bound and it does not bound
/// memory. [`forward_query`] reads with `recv_from_bytes`, which issues `Recv { max_len: None }`, so
/// the netstack has already copied the whole queued datagram out before [`cap_response`] sees it.
/// What bounds the read is the netstack UDP socket's receive ring —
/// `netcore::Config::udp_buffer_size`, 4 KiB by default and not overridden by `ts_runtime` — and
/// smoltcp drops a datagram larger than that ring at enqueue rather than delivering a chopped one.
/// That ring is 4096 and this cap is 4095, so the ring plays exactly the part Go's `+1` byte plays:
/// the one datagram size it can deliver and this cap cannot pass is the full-ring 4096-byte answer,
/// which [`cap_response`] then chops to 4095 and marks `TC` (pinned by
/// `full_ring_datagram_is_chopped_and_marked_truncated`).
///
/// The client's query is forwarded verbatim, so a client advertising a large EDNS UDP size can
/// elicit a legitimately large (1300–4095 byte) UDP answer (big TXT sets, DNSSEC, many-record
/// round-robins). Capping at the old 1232 truncated those and set TC, forcing a TCP retry — which
/// nothing served at the time, so the large answer became unreachable. 4095 relays them intact.
/// (The retry now has a server in TUN mode, `dns_over_tcp`, but the hop to the *upstream* resolver
/// is still UDP, so this cap is what bounds the answer either way.)
const MAX_UPSTREAM_RESPONSE: usize = 4095;

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
    /// A negative split-DNS route matched: do not resolve (NXDOMAIN). The route's suffix is a zone
    /// this node is authoritative for — Go's `localDomains` is exactly the set of routes configured
    /// with no resolvers — so [`authoritative_zone_for`] finds it again when naming the negative
    /// answer's SOA zone.
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
    /// relay the upstream answer, on failure/timeout answer with the prebuilt `servfail` buffer
    /// (an off-tailnet name we failed to forward is a soft failure, not a cacheable non-existence —
    /// Go forwarder.go:1297-1307).
    Forward {
        /// UDP upstreams to try, in order.
        upstreams: Vec<SocketAddr>,
        /// The original query bytes to forward verbatim.
        query: Vec<u8>,
        /// Fallback SERVFAIL response if every upstream fails or times out.
        servfail: Vec<u8>,
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

/// The zone this node is authoritative for that contains `canon`, or `None` when it is not
/// authoritative for the name.
///
/// Mirrors Go `net/dns/resolver/tsdns.go` `authoritativeZoneFor`, which scans `Resolver.localDomains`.
/// Go's `localDomains` is exactly the set of control-pushed routes with **no** resolvers
/// (`net/dns/manager.go` `compileConfig`), so the equivalent set here is the union of:
///
/// - the tailnet search domains — what [`is_tailnet_name`] tests, and the zone a tailnet-suffix
///   NXDOMAIN belongs to;
/// - the negative split-DNS routes (a route with an empty upstream list), the literal shape of
///   Go's `localDomains`;
/// - the CGNAT reverse zone `<b>.100.in-addr.arpa` covering a `100.64.0.0/10` reverse name.
///   Synthesized rather than read from the routes: this fork's reverse guard is structural
///   ([`is_tailnet_cgnat`]) and holds whether or not control pushed the matching route, and the
///   zone it names is the same per-/16 chunk real tailscaled advertises.
///
/// `ip6.arpa` is deliberately absent. This fork NXDOMAINs *every* `ip6.arpa` name as an anti-leak
/// measure ([`is_ip6_arpa`]) rather than because it serves that zone, and an SOA naming `ip6.arpa`
/// would claim authority over the whole IPv6 reverse tree — a claim we do not have and one that
/// would have a client negative-cache far more than this node answers for.
///
/// The longest match wins. Go returns the first match from an unordered slice; longest gives the
/// same answer whenever the zones nest (the usual case) and is a defensible tie-break when they
/// do not.
fn authoritative_zone_for(view: &DnsView, name: &Name, canon: &str) -> Option<String> {
    if let Some(octets) = name.ptr_to_ipv4() {
        let v4: Ipv4Addr = octets.into();
        if is_tailnet_cgnat(v4) {
            return Some(format!("{}.100.in-addr.arpa", v4.octets()[1]));
        }
    }

    view.cfg
        .search_domains
        .iter()
        .map(String::as_str)
        .chain(
            view.cfg
                .routes
                .iter()
                .filter(|(_, upstreams)| upstreams.is_empty())
                .map(|(suffix, _)| suffix.as_str()),
        )
        .filter(|zone| suffix_matches(canon, zone))
        .max_by_key(|zone| zone.len())
        .map(str::to_owned)
}

/// The SOA record to attach to an authoritative **negative** answer (NXDOMAIN, or NODATA for a
/// name we serve), or `None` when this node is not authoritative for a zone containing the name.
///
/// Without it, a downstream cache decides for itself how long to remember the nonexistence: macOS
/// `mDNSResponder` holds an SOA-less negative answer for a long time, so a name queried shortly
/// *before* a node was renamed to it keeps failing until something flushes the cache. The SOA
/// bounds that at 10 seconds (RFC 2308), which is what Go's resolver advertises.
fn soa_for(view: &DnsView, name: &Name, canon: &str) -> Option<SoaZone> {
    let zone = authoritative_zone_for(view, name, canon)?;
    Some(SoaZone {
        zone: Name(zone.split('.').map(str::to_owned).collect()),
        serial: soa_serial(),
    })
}

/// The SOA SERIAL to publish: the response time in unix seconds.
///
/// A serial is meant to change only when the zone data does, but nothing consumes ours — this node
/// has no secondaries and serves no zone transfers — so Go uses the current time and so do we. It
/// is monotonic, cheap, and fits in a `u32` until 2106. A clock before the epoch yields 0 rather
/// than panicking; the value carries no meaning either way.
fn soa_serial() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs() as u32)
}

/// Decide what to do with a single DNS query against `view`: either a complete response is ready
/// ([`Decision::Reply`]), the query should be forwarded to upstream resolvers
/// ([`Decision::Forward`]), or the packet should be dropped without answering (`None`).
///
/// Factored out of the socket loop so it can be unit-tested without a netstack: it does no I/O and
/// reads no state but `view` and the wall clock (the SOA SERIAL of a negative answer, which nothing
/// consumes — see [`soa_serial`]). It never panics and fails closed: an unknown, unroutable, or
/// tailnet-suffix name resolves to NXDOMAIN rather than leaking to an upstream resolver.
pub(crate) fn decide(view: &DnsView, buf: &[u8]) -> Option<Decision> {
    // Malformed / non-query input is dropped: we never answer something we can't parse.
    let query = decode_query(buf).ok()?;
    let q = &query.question;
    let id = query.id;
    // Echo the query's RD bit (and set RA when set) on the response — Go derives the response header
    // from the query header.
    let rd = query.recursion_desired;

    let reply = |rcode, answers: &[RData]| {
        Decision::Reply(encode_response(id, q, rd, rcode, answers, None))
    };
    // A negative answer (NXDOMAIN, or NODATA) for a name inside a zone we serve carries that zone's
    // SOA in the authority section, which bounds how long a downstream resolver may cache the
    // nonexistence (RFC 2308). `soa_for` returns `None` when we are not authoritative for the name,
    // in which case this is exactly `reply`.
    let reply_negative = |rcode, canon: &str| {
        Decision::Reply(encode_response(
            id,
            q,
            rd,
            rcode,
            &[],
            soa_for(view, &q.name, canon).as_ref(),
        ))
    };

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
        return Some(forward_or_nodata(view, &canon, buf, id, q, rd));
    }

    Some(match &q.qtype {
        QType::A => match view.resolve_addr(&canon, true) {
            Some(IpAddr::V4(v4)) => reply(Rcode::NoError, &[RData::A(v4.octets())]),
            // No overlay/extra-record answer: try split-DNS / recursive upstreams.
            _ => forward_or_nxdomain(view, &canon, buf, id, q, rd),
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
            // NODATA: the name exists but we hold no address of the queried family for it, so it
            // takes the SOA — Go sets `SOAZone` on exactly this case (`rcode == RCodeSuccess &&
            // !ip.IsValid()` for an A/AAAA/ALL question).
            Some(IpAddr::V6(_)) => reply_negative(Rcode::NoError, &canon),
            // No overlay/extra-record answer: split-DNS / recursive upstreams (off-tailnet names);
            // tailnet names fail closed to NXDOMAIN inside `forward_or_nxdomain`.
            _ => forward_or_nxdomain(view, &canon, buf, id, q, rd),
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
                    None if is_tailnet_cgnat(v4) => reply_negative(Rcode::NxDomain, &canon),
                    None => forward_or_nxdomain(view, &canon, buf, id, q, rd),
                }
            }
            // Anti-leak / IPv4-only-tailnet: an IPv6 reverse (`ip6.arpa`) PTR must never be
            // forwarded — relaying it would reveal that a tailnet v6 address (e.g. a ULA `fd7a:…`)
            // was probed. Fail closed to NXDOMAIN, exactly like the IPv4 CGNAT guard above. No SOA:
            // this blanket refusal is anti-leak, not a claim to serve `ip6.arpa` (see
            // [`authoritative_zone_for`]).
            None if is_ip6_arpa(&canon) => reply(Rcode::NxDomain, &[]),
            None => forward_or_nxdomain(view, &canon, buf, id, q, rd),
        },
        // Anything else (TXT, SRV, MX, HTTPS/SVCB, CNAME, ...): we hold no authoritative record of
        // that type, so — like Go's resolver — forward it to upstream for an off-tailnet name and
        // return NODATA (empty NOERROR) for a tailnet-authoritative name. NOT REFUSED: a stub reads
        // REFUSED as "this server won't serve me" and abandons the resolver, which would break
        // ordinary client lookups (notably HTTPS/SVCB type 65, issued routinely by browsers for
        // HTTP/3 + ECH) for the same off-tailnet names whose A/AAAA already forward.
        QType::Other(_) => forward_or_nodata(view, &canon, buf, id, q, rd),
    })
}

/// For a name with no overlay answer, consult the split-DNS routes + recursive resolvers and
/// either forward (to UDP upstreams), answer authoritatively absent (NXDOMAIN), or fail soft
/// (SERVFAIL) when an off-tailnet name simply can't be forwarded.
///
/// Rcode parity with Go's resolver (`net/dns/resolver/tsdns.go` resolution order + `forwarder.go`):
/// - A **tailnet-authoritative** name (search-domain suffix) or a **negative split-DNS route**
///   (`Upstreams::Block` — a route configured with no resolvers, which Go answers authoritatively
///   from Hosts, so an unmatched name under it is authoritatively absent) → **NXDOMAIN**.
/// - An **off-tailnet** name we cannot forward — no route and no resolver configured
///   (`Upstreams::None`), or a route whose resolvers are all filtered out (IPv6-only under the
///   IPv4-only egress) → **SERVFAIL**, matching Go forwarder.go:1207 ("no upstream resolvers set,
///   returning SERVFAIL"). A cacheable NXDOMAIN on a transient/structural inability to forward would
///   make a downstream stub cache the *non-existence* of a real name; SERVFAIL is a soft failure the
///   stub retries.
///
/// Anti-leak: a tailnet-suffix name is authoritative and is never forwarded — neither the name nor
/// the query leaks to a third-party resolver. (The CGNAT `in-addr.arpa` / `ip6.arpa` reverse-zone
/// NXDOMAIN guards live in the PTR arm of [`decide`] and are likewise unaffected.)
fn forward_or_nxdomain(
    view: &DnsView,
    canon: &str,
    buf: &[u8],
    id: u16,
    q: &ts_dns_wire::Question,
    rd: bool,
) -> Decision {
    // NXDOMAIN for authoritative-absent names; SERVFAIL for an off-tailnet name we can't forward.
    // An authoritative NXDOMAIN carries the zone's SOA so a downstream cache bounds how long it
    // remembers the nonexistence (RFC 2308); a SERVFAIL never does — it asserts nothing to cache,
    // and we are not authoritative for the name we failed to forward.
    let nxdomain = |canon: &str| {
        encode_response(
            id,
            q,
            rd,
            Rcode::NxDomain,
            &[],
            soa_for(view, &q.name, canon).as_ref(),
        )
    };
    let servfail = encode_response(id, q, rd, Rcode::ServFail, &[], None);

    if is_tailnet_name(view, canon) {
        return Decision::Reply(nxdomain(canon));
    }

    let (resolvers, recursive) = match view.route_for(canon) {
        Upstreams::Route(resolvers) => (resolvers, false),
        Upstreams::Recursive(resolvers) => (resolvers, true),
        // A negative split-DNS route is authoritative-absent (Go answers it from Hosts): NXDOMAIN.
        // Go's `localDomains` *is* this route set, so the route's own suffix names the zone.
        Upstreams::Block => return Decision::Reply(nxdomain(canon)),
        // No route and no resolver: an off-tailnet name we have nowhere to forward — SERVFAIL, not
        // a cacheable non-existence (Go forwarder.go:1207).
        Upstreams::None => return Decision::Reply(servfail),
    };

    let upstreams: Vec<SocketAddr> = resolvers
        .iter()
        .map(DnsResolver::udp_addr)
        // Anti-leak / IPv6-off: only forward over IPv4 upstreams; never open a v6 socket.
        .filter(SocketAddr::is_ipv4)
        .collect();
    if upstreams.is_empty() {
        // We had a route but every resolver was filtered out (IPv6-only): we cannot forward this
        // off-tailnet name, so soft-fail rather than assert non-existence.
        Decision::Reply(servfail)
    } else {
        Decision::Forward {
            upstreams,
            query: buf.to_vec(),
            // All upstreams failing at runtime is also an inability to forward, not a non-existence
            // (Go forwarder.go:1297-1307): hand the forwarder a SERVFAIL fallback, not NXDOMAIN.
            servfail,
            recursive,
        }
    }
}

/// The DNS query types Go's resolver explicitly leaves unimplemented for a tailnet-authoritative
/// name, answering `RCodeNotImplemented` (NOTIMP) rather than NODATA (`net/dns/resolver/tsdns.go`
/// `resolveLocal`: `case dns.TypeNS, dns.TypeSOA, dns.TypeAXFR, dns.TypeHINFO`). The numeric type
/// codes: NS=2, SOA=6, HINFO=13, AXFR=252.
fn is_unimplemented_tailnet_qtype(qtype: &ts_dns_wire::QType) -> bool {
    matches!(qtype, ts_dns_wire::QType::Other(2 | 6 | 13 | 252))
}

/// For a query whose *qtype/qclass* we don't serve authoritatively (anything other than an IN-class
/// A/AAAA/PTR — e.g. TXT, SRV, MX, HTTPS/SVCB, or a CHAOS-class query): forward it to upstream like
/// any other name, but for a tailnet-authoritative name return an empty NOERROR (NODATA) instead of
/// NXDOMAIN — except the NS/SOA/HINFO/AXFR types Go answers NOTIMP for
/// ([`is_unimplemented_tailnet_qtype`]).
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
    rd: bool,
) -> Decision {
    // Authoritative tailnet name. For most unsupported types we answer NODATA (empty NOERROR) — the
    // name exists, we just hold no record of that type. But a small set of types Go's resolver
    // *explicitly* leaves unimplemented (`net/dns/resolver/tsdns.go` `resolveLocal`:
    // `case dns.TypeNS, dns.TypeSOA, dns.TypeAXFR, dns.TypeHINFO: return RCodeNotImplemented`) must
    // answer NOTIMP, not NODATA — a `dig NS`/`SOA`/`HINFO` against the tailnet zone is otherwise a
    // clean fingerprint distinguishing this fork from real tailscaled. Off-tailnet names are
    // unaffected (they forward below regardless of type); this NOTIMP applies only to a name we are
    // authoritative for.
    if is_tailnet_name(view, canon) {
        let rcode = if is_unimplemented_tailnet_qtype(&q.qtype) {
            Rcode::NotImpl
        } else {
            Rcode::NoError
        };
        // No SOA. Go sets `SOAZone` on a no-data answer only for an A/AAAA/ALL question; a TXT or
        // SRV miss on a name we serve — and the NOTIMP types — go back bare, as they do upstream.
        return Decision::Reply(encode_response(id, q, rd, rcode, &[], None));
    }
    // Anti-leak parity with the `QType::Ptr` arm: a reverse query for a tailnet CGNAT IPv4
    // (100.64.0.0/10) or ANY `ip6.arpa` name must NEVER egress to an upstream resolver, regardless
    // of qtype/class — forwarding it would reveal that a specific tailnet IP was probed. The PTR arm
    // enforces this (NXDOMAIN) but its guards live only inside that arm; without re-checking here, an
    // exotic-qtype (TXT/ANY/…) or non-IN-class query for a tailnet reverse name would slip through to
    // the forward path below. Fail closed to NXDOMAIN, matching the PTR arm's disposition.
    if is_ip6_arpa(canon) {
        // No SOA: see the matching guard in [`decide`]'s PTR arm.
        return Decision::Reply(encode_response(id, q, rd, Rcode::NxDomain, &[], None));
    }
    if let Some(octets) = q.name.ptr_to_ipv4()
        && is_tailnet_cgnat(octets.into())
    {
        // Authoritative for the CGNAT reverse zone, so this NXDOMAIN carries its SOA — same
        // disposition as the PTR arm, whatever the qtype or class that got us here.
        return Decision::Reply(encode_response(
            id,
            q,
            rd,
            Rcode::NxDomain,
            &[],
            soa_for(view, &q.name, canon).as_ref(),
        ));
    }
    // Off-tailnet, non-reverse-zone: forward verbatim. `forward_or_nxdomain` already forwards
    // non-tailnet names and soft-fails (SERVFAIL) when no upstream is configured/routable; reuse it
    // (the tailnet branch above is already handled, so its tailnet→NXDOMAIN and negative-route paths
    // are unreachable here — this only exercises its off-tailnet forward / SERVFAIL dispositions).
    forward_or_nxdomain(view, canon, buf, id, q, rd)
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

/// Which transport the *client* we are answering reached us over.
///
/// The only thing it changes is whether an answer may be marked `TC` for exceeding the
/// UDP payload size the query advertised. That limit describes the **datagram** we would answer in
/// (RFC 1035 §4.2.1, RFC 6891 §6.2.3); a client that reached us over TCP has no such bound
/// (RFC 7766 §8), and marking its answer truncated sends a stub resolver that already retried over
/// TCP — the retry `TC` asked it to make — straight back into another retry. Go draws the same line:
/// `checkResponseSizeAndSetTC` is applied on the UDP answer path, while the TCP DNS handler
/// installed by `acceptTCP`'s `hittingDNS` case writes the answer under a 2-byte length prefix with
/// no size check (wgengine/netstack/netstack.go, net/dns/resolver/tsdns.go @
/// 9ea7cba44591e0cd840c6c94d23274dd222059bf).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClientTransport {
    /// A UDP client: the EDNS(0)-advertised (or 512-byte) datagram limit applies.
    Udp,
    /// A TCP client: no datagram limit applies, so no `TC` bit is added for size.
    ///
    /// Two things reach for it: `dns_over_tcp` (compiled with the `tun` feature — the application
    /// netstack has no TCP listener on `100.100.100.100:53` yet), and the peerAPI DoH *server*,
    /// which answers as `"tcp"` because the datagram budget belongs to the peer that asked, not to
    /// us (Go `Resolver.HandlePeerDNSQuery`, see `peerapi_doh::PEER_CLIENT_TRANSPORT`).
    Tcp,
}

/// Turn a [`Decision::Forward`] into the plan that will carry it: a recursive forward consults
/// [`recursive_plan`] (which may delegate to the active exit node's DoH endpoint), a split-DNS
/// forward always goes to its route's own upstreams over UDP.
///
/// One line of logic, but it is the point where "recursive" becomes "may egress from the exit node
/// instead of this host", so every caller — the UDP serve loop, the `query_dns` handler, the TUN
/// datapath's `plan_intercept` and the DNS-over-TCP connection loop — reads it from here rather than
/// spelling the branch out again.
pub(crate) fn forward_plan(
    view: &DnsView,
    upstreams: Vec<SocketAddr>,
    recursive: bool,
) -> RecursivePlan {
    if recursive {
        recursive_plan(view, upstreams)
    } else {
        RecursivePlan::Udp(upstreams)
    }
}

/// Cap a forwarded upstream response to a single UDP datagram ([`MAX_UPSTREAM_RESPONSE`]) before
/// relaying it, then — for a [`ClientTransport::Udp`] client only — mark it truncated if it is
/// bigger than what `query`'s sender said it can receive ([`check_response_size_and_set_tc`]).
///
/// The two checks **compose**; they are not alternatives. The [`MAX_UPSTREAM_RESPONSE`] cap is this
/// forwarder's own relay bound: when the response is too large it is truncated mid-message, so we
/// set the `TC` (truncation) flag in the DNS header (byte 2, bit `0x02`) telling the stub resolver
/// to retry over TCP — relaying a chopped answer without `TC` would surface a
/// malformed-but-"complete" message. That flag is only set when truncation actually occurs. The
/// second check is the *client's* bound, and never chops the body.
///
/// The cap runs *after* the whole datagram has been read (see [`MAX_UPSTREAM_RESPONSE`]), so it
/// bounds what we relay, not what we allocate. The netstack's UDP receive ring (4096) is one byte
/// wider than the cap (4095), so the truncating branch is reachable by exactly one deliverable
/// datagram size — the full-ring 4096-byte answer — which is the same size Go's `maxResponseBytes+1`
/// read buffer exists to catch.
///
/// The [`MAX_UPSTREAM_RESPONSE`] chop applies on **both** transports and keeps setting `TC` when it
/// fires: we really did cut the message, and saying otherwise would hand the client a
/// malformed-but-"complete" answer. It is only the *client's advertised datagram size* that a TCP
/// client does not have (see [`ClientTransport`]).
fn cap_response(query: &[u8], mut resp: Vec<u8>, client: ClientTransport) -> Vec<u8> {
    if resp.len() > MAX_UPSTREAM_RESPONSE {
        resp.truncate(MAX_UPSTREAM_RESPONSE);
        // The header is 12 bytes; the TC bit lives in the second flags byte (header byte 2). A
        // capped datagram is always >= the header length, but guard anyway to never panic.
        if let Some(flags_hi) = resp.get_mut(2) {
            *flags_hi |= 0x02;
        }
    }
    check_response_size_and_set_tc(query, resp, client)
}

/// The RFC 1035 §4.2.1 maximum size of a DNS message carried over UDP by a requestor that did not
/// advertise an EDNS(0) buffer size. Go's `defaultUDPSize` in `checkResponseSizeAndSetTC`
/// (net/dns/resolver/forwarder.go @ 9ea7cba44591e0cd840c6c94d23274dd222059bf).
///
/// It is **not** a floor under an advertised size. RFC 6891 §6.2.3 says a value below 512 "MUST be
/// treated as equal to 512", but Go takes the advertised number verbatim (`maxSize = int(ednsSize)`)
/// and only reaches for this constant when the request carries no usable OPT record at all. A stub
/// that advertises 200 is told a 300-byte answer is truncated, and a Rust node on the same tailnet
/// has to say the same thing.
const NO_EDNS_UDP_LIMIT: usize = 512;

/// The RR TYPE of an EDNS(0) OPT pseudo-record (RFC 6891 §6.1.2). In an OPT record the CLASS field
/// is repurposed to carry the requestor's UDP payload size.
const OPT_RR_TYPE: u16 = 41;

/// Wire size of an EDNS(0) OPT record carrying **no** options: NAME (1 byte, the root label) +
/// TYPE (2) + CLASS (2) + TTL (4) + RDLEN (2). Go's `optFixedBytes`.
const OPT_FIXED_BYTES: usize = 11;

/// Set the `TC` (truncated) bit on `resp` when it is larger than the UDP payload size the client's
/// `query` advertised — the size in its EDNS(0) OPT record, or 512 bytes when it carries none
/// (RFC 1035). The body is left **intact**: `TC` tells the stub resolver the answer may not fit the
/// datagram it asked for, so it should retry over TCP; it is not a claim that we chopped anything.
///
/// This is Go's `checkResponseSizeAndSetTC` (net/dns/resolver/forwarder.go @
/// 9ea7cba44591e0cd840c6c94d23274dd222059bf), including its first statement — `if family != "udp"
/// { return response }`. `client` is that `family`: it names the transport the client **we answer**
/// used, never the hop we fetched the answer over. A [`ClientTransport::Tcp`] client has no
/// datagram to overflow (RFC 7766 §8) and setting `TC` for it would only send its resolver into
/// another retry of a transport that already has no size bound.
///
/// It runs on every path that returns an answer to a client, exactly as upstream does: the UDP and
/// DoH forwards (via [`cap_response`] / `forward_doh`, Go's `forwarder.send`) **and** the answers
/// this node builds itself (Go calls it in `Resolver.Query` right after `respond` succeeds). The
/// local path is not exempt: `ts_dns_wire` caps an authoritative response at 512 bytes, which only
/// bounds it below a *default* client limit — a client that advertised less than that can still be
/// overflowed by an answer we composed.
pub(crate) fn check_response_size_and_set_tc(
    query: &[u8],
    mut resp: Vec<u8>,
    client: ClientTransport,
) -> Vec<u8> {
    if client == ClientTransport::Tcp {
        return resp;
    }
    // The header is 12 bytes and the TC bit lives in the second flags byte (header byte 2); a
    // response shorter than that is not something we can (or need to) mark. Re-setting a bit that
    // is already set is a no-op, so upstream's `truncatedFlagSet` early return needs no analogue.
    if resp.len() > client_udp_limit(query)
        && let Some(flags_hi) = resp.get_mut(2)
    {
        *flags_hi |= 0x02;
    }
    resp
}

/// The largest UDP DNS response `query`'s sender is willing to receive: the EDNS(0) advertised size
/// verbatim, or [`NO_EDNS_UDP_LIMIT`] when the query carries no valid OPT record. Go's
/// `getEDNSBufferSize` plus the `hasEDNS` branch of `checkResponseSizeAndSetTC`.
fn client_udp_limit(query: &[u8]) -> usize {
    find_opt_record(query).map_or(NO_EDNS_UDP_LIMIT, usize::from)
}

/// Return the requestor's UDP payload size from `query`'s EDNS(0) OPT record, or [`None`] when the
/// message carries no OPT record this node will act on.
///
/// A direct port of Go's `findOPTRecord` (net/dns/resolver/forwarder.go @
/// 9ea7cba44591e0cd840c6c94d23274dd222059bf), and deliberately as narrow as it is: the OPT record
/// must occupy the **final 11 bytes** of the message, and it must have a root NAME, TYPE `OPT`,
/// EDNS version 0 and `RDLEN == 0`. Upstream states the restriction outright — "Only OPT records at
/// the very end of the message with no option codes are addressed" — and everything else is
/// `(0, nil)`, i.e. *no EDNS*, i.e. the 512-byte RFC 1035 limit.
///
/// That matters far more often than "malformed query" suggests. A query carrying **any** EDNS
/// option — a DNS cookie (RFC 7873) or EDNS Client Subnet, both of which real stub resolvers send
/// routinely — has `RDLEN != 0`, so upstream ignores the 4096 it advertises and caps the answer at
/// 512. Walking the additional section properly and honouring that 4096 would leave `TC` clear on a
/// 900-byte reply that every Go node on the tailnet marks truncated, and the two nodes would hand
/// the same stub resolver different answers to the same question. Being generous here is the bug.
fn find_opt_record(packet: &[u8]) -> Option<u16> {
    /// The only EDNS version defined (RFC 6891 §6.1.3). Go: "Be conservative and don't touch
    /// unknown versions."
    const EDNS0_VERSION: u8 = 0;

    if packet.len() < DNS_HEADER_LEN + OPT_FIXED_BYTES {
        return None;
    }
    // OPT lives in the additional section, so no additional records means no OPT.
    if u16::from_be_bytes([packet[10], packet[11]]) == 0 {
        return None;
    }

    let opt = &packet[packet.len() - OPT_FIXED_BYTES..];
    if opt[0] != 0 {
        return None; // NAME must be the root domain (a single zero byte).
    }
    if u16::from_be_bytes([opt[1], opt[2]]) != OPT_RR_TYPE {
        return None;
    }
    // CLASS is repurposed as the requestor's UDP payload size (RFC 6891 §6.1.2).
    let requested_size = u16::from_be_bytes([opt[3], opt[4]]);
    // opt[5] is the extended RCODE: ignored, as upstream ignores it.
    if opt[6] != EDNS0_VERSION {
        return None;
    }
    // opt[7..9] are the EDNS flags (DO bit and friends): ignored.
    if u16::from_be_bytes([opt[9], opt[10]]) != 0 {
        return None; // RDLEN must be 0 — the record carries no options.
    }
    Some(requested_size)
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

/// SERVFAIL (RCODE 2): the upstream could not process the query. A *soft* error to a forwarder — the
/// name may still resolve through another resolver.
const RCODE_SERVFAIL: u8 = 2;
/// REFUSED (RCODE 5): the upstream will not answer this query (policy, an ACL, a view it has no
/// data for). Soft for the same reason: another resolver may well serve it.
const RCODE_REFUSED: u8 = 5;

/// The RCODE `msg` carries: the low 4 bits of header byte 3 (RFC 1035 §4.1.1), or `None` when `msg`
/// is too short to have a header. The EDNS(0) *extended* RCODE bits an OPT record can add are
/// ignored, as they are in [`find_opt_record`] and in Go's forwarder, which reads the 4-bit
/// `dnsmessage.Header.RCode`.
fn response_rcode(msg: &[u8]) -> Option<u8> {
    msg.get(3).map(|b| b & 0x0F)
}

/// Whether `msg` carries an RCODE a forwarder must treat as a **soft** error — one that means "this
/// resolver could not answer", not "here is the answer": [`RCODE_SERVFAIL`] or [`RCODE_REFUSED`].
/// See [`forward_query`] for what that changes.
fn is_soft_error(msg: &[u8]) -> bool {
    matches!(response_rcode(msg), Some(RCODE_SERVFAIL | RCODE_REFUSED))
}

/// Forward `query` to each upstream in order over the **overlay** netstack, returning the first
/// well-formed response that is not a *soft* error, or the prebuilt `fallback` buffer if no
/// upstream answered at all.
///
/// Anti-leak: forwarding goes through the overlay netstack `channel` (a fresh `0.0.0.0:0` overlay
/// UDP socket per query), NEVER a host socket — so the real origin IP can't leak to the resolver,
/// and split-DNS upstreams reachable only over the tailnet/subnet-router work. Each upstream is
/// bounded by [`UPSTREAM_TIMEOUT`]. `client` names the transport the *client* we answer used, not
/// the one we fetched over: the hop upstream is UDP either way.
///
/// The socket work is all this function does; which response is relayed to the client is
/// [`forward_walk`]'s decision.
pub(crate) async fn forward_query(
    channel: &Channel,
    upstreams: &[SocketAddr],
    query: &[u8],
    fallback: Vec<u8>,
    client: ClientTransport,
) -> Vec<u8> {
    forward_walk(upstreams, query, fallback, client, |upstream| {
        ask_upstream(channel, upstream, query)
    })
    .await
}

/// Ask one `upstream` for `query` over the overlay and return the first datagram that came back as
/// `(source address, bytes)`, or `None` when nothing usable arrived (bind, send or receive error,
/// [`UPSTREAM_TIMEOUT`], or an empty datagram).
///
/// This is the whole of [`forward_query`]'s I/O, split out from the walk so the policy above it —
/// anti-poisoning, the soft-error rules, which response is relayed — is decided (and tested) on
/// bytes rather than on sockets. It vouches for nothing about the datagram it returns: the source
/// address comes back unfiltered precisely so [`forward_walk`] can check it.
async fn ask_upstream(
    channel: &Channel,
    upstream: SocketAddr,
    query: &[u8],
) -> Option<(SocketAddr, Vec<u8>)> {
    let socket = match channel
        .udp_bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, %upstream, "magic dns upstream bind failed");
            return None;
        }
    };

    if let Err(e) = socket.send_to(upstream, query).await {
        tracing::warn!(error = %e, %upstream, "magic dns upstream send failed");
        return None;
    }

    match timeout(UPSTREAM_TIMEOUT, socket.recv_from_bytes()).await {
        Ok(Ok((from, resp))) if !resp.is_empty() => Some((from, resp.to_vec())),
        Ok(Ok(_)) => None,
        Ok(Err(e)) => {
            tracing::warn!(error = %e, %upstream, "magic dns upstream recv failed");
            None
        }
        Err(_) => {
            tracing::debug!(%upstream, "magic dns upstream timed out");
            None
        }
    }
}

/// Walk `upstreams` in order, asking `ask` for each one's answer, and decide which response the
/// client gets. [`forward_query`] is the only caller; `ask` is its overlay socket exchange
/// ([`ask_upstream`]).
///
/// **REFUSED and SERVFAIL are soft errors, not answers** ([`is_soft_error`]). An upstream that
/// answers `REFUSED` (RCODE 5) or `SERVFAIL` (RCODE 2) does not end the forward: the walk continues
/// to the next upstream, and the first such response is remembered and returned only once the list
/// is exhausted with nothing better. Otherwise a broken or misconfigured resolver that refuses
/// instantly beats a healthy one still doing the work, and the stub resolver is handed the refusal
/// as though it were the answer — complete DNS failure exactly where a split-DNS route or a
/// fallback list names more than one resolver, which is the shape control commonly pushes. Go's
/// forwarder treats both codes as soft while a query is outstanding against more than one resolver
/// and returns the first REFUSED only when every resolver refused (net/dns/resolver/forwarder.go @
/// a8b023c063b608fcead5446f3d885c4fc847c944). Every other RCODE — including NXDOMAIN, which is a
/// real answer — ends the walk on the spot.
///
/// The caller supplies `fallback` (a SERVFAIL response for a forwarded off-tailnet name — an
/// all-upstream failure is a soft "couldn't resolve", not a cacheable non-existence, matching Go
/// forwarder.go:1297-1307). Keeping it caller-supplied means this fn is rcode-agnostic. A
/// remembered soft-error response takes **precedence** over it and is relayed verbatim: the
/// upstream's own bytes can carry an RFC 8914 extended DNS error saying *why* it failed (blocked by
/// policy, DNSSEC bogus, no reachable authority), which a locally synthesized SERVFAIL throws away.
/// `fallback` is what a client gets when nothing answered — every upstream timed out, errored, or
/// only ever sent datagrams the anti-poisoning check discarded.
///
/// Every relayed response goes through [`cap_response`], which caps it at [`MAX_UPSTREAM_RESPONSE`]
/// and — for a [`ClientTransport::Udp`] client — marks it truncated when it exceeds what `query`
/// advertised it can receive.
async fn forward_walk<F, Fut>(
    upstreams: &[SocketAddr],
    query: &[u8],
    fallback: Vec<u8>,
    client: ClientTransport,
    mut ask: F,
) -> Vec<u8>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = Option<(SocketAddr, Vec<u8>)>>,
{
    // The first REFUSED/SERVFAIL an upstream answered with, held while the walk continues.
    let mut first_soft_error: Option<Vec<u8>> = None;

    for upstream in upstreams {
        let Some((from, resp)) = ask(*upstream).await else {
            continue;
        };

        // Anti-poisoning: only accept a datagram that came from the upstream we queried and whose
        // DNS header matches this query (same transaction id, QR=response bit set). An off-path
        // injector racing the real answer is otherwise relayed straight back to the stub resolver
        // as authoritative — and this check runs FIRST, so an injected refusal is not even eligible
        // to become the soft error a fully-refused forward ends up relaying.
        if from.ip() != upstream.ip() || !response_matches_query(query, &resp) {
            tracing::debug!(%upstream, %from, "magic dns dropping unsolicited/mismatched response");
            continue;
        }

        // A soft error (REFUSED/SERVFAIL) is not an answer: hold on to the first one and give the
        // remaining upstreams their turn.
        if is_soft_error(&resp) {
            tracing::debug!(
                %upstream,
                rcode = response_rcode(&resp),
                "magic dns upstream soft error, trying the next upstream"
            );
            first_soft_error.get_or_insert(resp);
            continue;
        }

        return cap_response(query, resp, client);
    }

    // Nothing better arrived. An upstream that refused or soft-failed still said something the
    // client can act on, so relay its own bytes (extended DNS error and all) ahead of the
    // synthesized `fallback`; `fallback` is only for "nobody answered".
    match first_soft_error {
        Some(resp) => cap_response(query, resp, client),
        None => fallback,
    }
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
                // Upstream runs the same size check on a locally-composed answer as on a forwarded
                // one (Go `Resolver.Query` calls `checkResponseSizeAndSetTC` right after `respond`).
                // An authoritative answer is capped at 512 bytes, but a client that advertised less
                // than that is still owed the `TC` bit.
                let resp = check_response_size_and_set_tc(&buf, resp, ClientTransport::Udp);
                if let Err(e) = socket.send_to(src, &resp).await {
                    tracing::warn!(error = %e, %src, "magic dns response send failed");
                }
            }
            Some(Decision::Forward {
                upstreams,
                query,
                servfail,
                recursive,
            }) => {
                // A recursive forward is eligible for exit-node DoH delegation; a split-DNS route
                // always stays on its configured upstreams. Decide the plan against the current
                // view so a query routed while an exit node is active egresses from that exit node.
                let plan = forward_plan(&view, upstreams, recursive);
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
                            forward_query(
                                &channel,
                                &upstreams,
                                &query,
                                servfail,
                                ClientTransport::Udp,
                            )
                            .await
                        }
                        RecursivePlan::Doh(doh_addr) => {
                            crate::peerapi_doh::forward_doh(
                                &channel,
                                doh_addr,
                                &query,
                                servfail,
                                ClientTransport::Udp,
                            )
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
            Some(Decision::Reply(resp)) => (
                check_response_size_and_set_tc(&buf, resp, ClientTransport::Udp),
                Vec::new(),
            ),
            Some(Decision::Forward {
                upstreams,
                query,
                servfail,
                recursive,
            }) => {
                let plan = forward_plan(&view, upstreams, recursive);
                match plan {
                    RecursivePlan::Udp(upstreams) => {
                        let resp = forward_query(
                            &self.channel,
                            &upstreams,
                            &query,
                            servfail,
                            ClientTransport::Udp,
                        )
                        .await;
                        (resp, upstreams)
                    }
                    RecursivePlan::Doh(doh_addr) => {
                        let resp = crate::peerapi_doh::forward_doh(
                            &self.channel,
                            doh_addr,
                            &query,
                            servfail,
                            ClientTransport::Udp,
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
        let rcode = response_rcode(&response).unwrap_or(0);

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
            addresses: vec![
                "100.64.0.1/32".parse().unwrap(),
                "fd7a::1/128".parse().unwrap(),
            ],
            tailnet_address: TailnetAddress {
                ipv4: "100.64.0.1/32".parse().unwrap(),
                ipv6: "fd7a::1/128".parse().unwrap(),
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
            cap_map: Default::default(),
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

    /// `build_query` plus an EDNS(0) OPT record in the additional section advertising `udp_size` as
    /// the requestor's UDP payload size (RFC 6891: root NAME, TYPE 41, CLASS = the size), in the
    /// only shape Go's `findOPTRecord` accepts: last record in the message, version 0, `RDLEN` 0.
    fn build_edns_query(
        id: u16,
        labels: &[&str],
        qtype: u16,
        qclass: u16,
        udp_size: u16,
    ) -> Vec<u8> {
        let mut buf = build_query(id, labels, qtype, qclass);
        buf[11] = 1; // ARCOUNT = 1
        buf.push(0); // NAME: root
        buf.extend_from_slice(&41u16.to_be_bytes()); // TYPE: OPT
        buf.extend_from_slice(&udp_size.to_be_bytes()); // CLASS: requestor's UDP payload size
        buf.extend_from_slice(&0u32.to_be_bytes()); // TTL: extended rcode + flags
        buf.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH: no options
        buf
    }

    /// Like [`build_edns_query`] but with one EDNS option in the OPT record's RDATA, so `RDLEN` is
    /// non-zero — the shape a stub resolver sending a DNS cookie (option code 10) produces.
    fn build_edns_query_with_option(
        id: u16,
        labels: &[&str],
        qtype: u16,
        qclass: u16,
        udp_size: u16,
        option_code: u16,
        option_data: &[u8],
    ) -> Vec<u8> {
        let mut buf = build_edns_query(id, labels, qtype, qclass, udp_size);
        let rdata_len = 4 + option_data.len();
        let rdlength_at = buf.len() - 2;
        buf[rdlength_at..].copy_from_slice(&(rdata_len as u16).to_be_bytes());
        buf.extend_from_slice(&option_code.to_be_bytes());
        buf.extend_from_slice(&(option_data.len() as u16).to_be_bytes());
        buf.extend_from_slice(option_data);
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
    fn unknown_off_tailnet_name_with_no_upstream_is_servfail() {
        // An off-tailnet name with no resolver configured cannot be forwarded. Go answers SERVFAIL
        // (a soft "couldn't resolve"), not NXDOMAIN — asserting non-existence of a real name we
        // simply have no upstream for would poison a downstream stub's negative cache. (A *tailnet*
        // name with no overlay match stays NXDOMAIN — see `tailnet_name_is_never_forwarded` — and a
        // negative split-DNS route stays NXDOMAIN — see `negative_route_is_nxdomain_not_forwarded`.)
        let view = view_with_peer();
        let buf = build_query(0x9, &["nope", "example", "com"], 1, 1);

        let resp = answer(&view, &buf).expect("answers");
        let (_, rcode, ancount) = parse_header(&resp);
        assert_eq!(
            rcode, 2,
            "ServFail: off-tailnet name, nothing to forward to"
        );
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
    fn unsupported_qtype_off_tailnet_forwards_or_servfails() {
        // A non-A/AAAA/PTR qtype for an OFF-tailnet name must be forwardable like A/AAAA — never
        // REFUSED. With no upstream configured in this view it soft-fails to SERVFAIL (the same
        // disposition an off-tailnet A query gets here), proving the qtype no longer short-circuits
        // to REFUSED. HTTPS/SVCB is type 65 (the browser HTTP/3 + ECH case the old REFUSED broke).
        let view = view_with_peer();
        let buf = build_query(0x1, &["example", "com"], 65, 1);

        let resp = answer(&view, &buf).expect("answers");
        let (_, rcode, _) = parse_header(&resp);
        assert_eq!(
            rcode, 2,
            "off-tailnet, no upstream -> SERVFAIL (forwardable, not Refused)"
        );
    }

    #[test]
    fn unimplemented_qtype_on_tailnet_name_is_notimp() {
        // NS (2), SOA (6), HINFO (13), AXFR (252) for a tailnet-authoritative name must answer NOTIMP
        // (rcode 4), matching Go `resolveLocal`'s `case dns.TypeNS, dns.TypeSOA, dns.TypeAXFR,
        // dns.TypeHINFO: return RCodeNotImplemented`. Returning NODATA (rcode 0) here was a clean
        // fingerprint (a `dig SOA user.ts.net` answer differs from real tailscaled). The name is
        // still never forwarded (anti-leak).
        let view = view_with_peer();
        for qtype in [2u16, 6, 13, 252] {
            let buf = build_query(0x1, &["host", "user", "ts", "net"], qtype, 1);
            let resp = answer(&view, &buf).expect("answers");
            let (_, rcode, ancount) = parse_header(&resp);
            assert_eq!(rcode, 4, "qtype {qtype} on a tailnet name must be NOTIMP");
            assert_eq!(ancount, 0, "NOTIMP carries no answer records");
        }
    }

    #[test]
    fn unimplemented_qtype_off_tailnet_still_forwards_not_notimp() {
        // The NOTIMP disposition is ONLY for a name we are authoritative for. An NS query for an
        // off-tailnet name must still forward (here: SERVFAIL, no upstream) — NOT NOTIMP — exactly
        // like the off-tailnet HTTPS/SVCB case above. Guards the NOTIMP change against over-reach.
        let view = view_with_peer();
        let buf = build_query(0x1, &["example", "com"], 2, 1); // NS, off-tailnet
        let resp = answer(&view, &buf).expect("answers");
        let (_, rcode, _) = parse_header(&resp);
        assert_eq!(
            rcode, 2,
            "off-tailnet NS -> SERVFAIL (forwardable), not NOTIMP"
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
    fn ptr_for_unknown_public_ip_off_tailnet_is_servfail() {
        let view = view_with_peer();
        // 9.9.9.9 is a public IP, not a known tailnet IP and not in the CGNAT reverse zone — so its
        // reverse query is an ordinary off-tailnet name. With no upstream to forward it to, that is
        // SERVFAIL (soft), not NXDOMAIN. (A CGNAT/ip6.arpa reverse for an unmatched tailnet IP still
        // fails closed to NXDOMAIN as an anti-leak guard — see `ptr_for_unknown_tailnet_ip_*`.)
        let buf = build_query(0x34, &["9", "9", "9", "9", "in-addr", "arpa"], 12, 1);

        let resp = answer(&view, &buf).expect("answers");
        let (_, rcode, _) = parse_header(&resp);
        assert_eq!(
            rcode, 2,
            "ServFail: off-tailnet public-IP reverse, no upstream"
        );
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
        // Not search-expanded → treated as the bare off-tailnet name "static", which has no upstream
        // here, so SERVFAIL (soft). The point of the test — that the extra record is NOT reachable
        // via search expansion — holds regardless of the failure rcode.
        assert_eq!(
            rcode, 2,
            "ServFail: bare 'static' is not search-expanded to the extra record"
        );
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
    fn non_in_class_off_tailnet_forwards_or_servfails() {
        // A non-IN class for an OFF-tailnet name is forwardable (Go forwards it), never REFUSED.
        // No upstream here -> SERVFAIL, proving the class gate no longer short-circuits to Refused.
        let view = view_with_peer();
        let buf = build_query(0x66, &["example", "com"], 1, 3);

        let resp = answer(&view, &buf).expect("answers");
        let (_, rcode, _) = parse_header(&resp);
        assert_eq!(
            rcode, 2,
            "off-tailnet non-IN class, no upstream -> SERVFAIL, not Refused"
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

    /// The address of the `n`th fake upstream resolver (RFC 5737 documentation range).
    fn upstream_addr(n: u8) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::new(198, 51, 100, n), 53))
    }

    /// Turn `query` into an upstream response: echo the header and question back with `QR` set and
    /// `rcode` in the header's low nibble, then append `tail` verbatim, counted as `ancount` answer
    /// records. The forwarder relays bytes and never parses past the question, so an opaque tail is
    /// what tells two upstreams' responses apart — and stands in for the RFC 8914 extended DNS error
    /// a real resolver puts in its own SERVFAIL/REFUSED.
    fn upstream_response(query: &[u8], rcode: u8, ancount: u16, tail: &[u8]) -> Vec<u8> {
        let mut resp = query.to_vec();
        resp[2] |= 0x80; // QR = 1 (this is a response)
        resp[3] = (resp[3] & 0xF0) | rcode;
        resp[6..8].copy_from_slice(&ancount.to_be_bytes());
        resp.extend_from_slice(tail);
        resp
    }

    /// One scripted upstream for [`run_forward_walk`]: the upstream's address, and the
    /// `(source address, datagram)` it hands back — `None` when nothing came back at all.
    type ScriptedUpstream = (SocketAddr, Option<(SocketAddr, Vec<u8>)>);

    /// Run the real [`forward_walk`] over a scripted set of upstreams: each entry is
    /// `(upstream, answer)`, where `answer` is the `(source address, datagram)` that upstream hands
    /// back (`None` = nothing came back — a timeout, a bind/send/recv failure). Returns the bytes
    /// the client would get **and** the upstreams the walk actually asked, so a test can tell "the
    /// second upstream answered" apart from "the walk stopped at the first".
    ///
    /// The script stands in for [`ask_upstream`]'s overlay socket exchange only; every decision
    /// under test — the source/transaction-id check, the REFUSED/SERVFAIL soft-error rules, which
    /// response is relayed — is made by the production code being called.
    async fn run_forward_walk(
        script: &[ScriptedUpstream],
        query: &[u8],
        fallback: Vec<u8>,
    ) -> (Vec<u8>, Vec<SocketAddr>) {
        let upstreams: Vec<SocketAddr> = script.iter().map(|(upstream, _)| *upstream).collect();
        let asked = std::cell::RefCell::new(Vec::new());

        let response = forward_walk(
            &upstreams,
            query,
            fallback,
            ClientTransport::Udp,
            |upstream| {
                asked.borrow_mut().push(upstream);
                let answer = script
                    .iter()
                    .find(|(scripted, _)| *scripted == upstream)
                    .and_then(|(_, answer)| answer.clone());
                std::future::ready(answer)
            },
        )
        .await;

        (response, asked.into_inner())
    }

    /// A first upstream answering REFUSED must NOT end the forward. A broken or misconfigured
    /// resolver refuses instantly and would otherwise beat a healthy one that is still working,
    /// handing the stub resolver a refusal as though it were the answer — complete DNS failure
    /// wherever a split-DNS route or a fallback list names more than one resolver.
    #[tokio::test]
    async fn refused_first_upstream_does_not_end_the_walk() {
        let query = build_query(0x201, &["api", "example", "com"], 1, 1);
        let (first, second) = (upstream_addr(1), upstream_addr(2));
        let refusal = upstream_response(&query, RCODE_REFUSED, 0, b"refused");
        let answer = upstream_response(&query, 0, 1, b"the real answer");
        let fallback = upstream_response(&query, RCODE_SERVFAIL, 0, b"synthesized");

        let (got, asked) = run_forward_walk(
            &[
                (first, Some((first, refusal))),
                (second, Some((second, answer.clone()))),
            ],
            &query,
            fallback,
        )
        .await;

        assert_eq!(
            asked,
            vec![first, second],
            "a REFUSED from the first upstream must not stop the walk"
        );
        assert_eq!(
            got, answer,
            "the healthy second upstream's answer is what reaches the client"
        );
    }

    /// SERVFAIL is soft in the same way: the walk goes on and the healthy upstream's answer wins.
    #[tokio::test]
    async fn servfail_first_upstream_does_not_end_the_walk() {
        let query = build_query(0x202, &["api", "example", "com"], 1, 1);
        let (first, second) = (upstream_addr(1), upstream_addr(2));
        let soft_fail = upstream_response(&query, RCODE_SERVFAIL, 0, b"servfail");
        let answer = upstream_response(&query, 0, 1, b"the real answer");
        let fallback = upstream_response(&query, RCODE_SERVFAIL, 0, b"synthesized");

        let (got, asked) = run_forward_walk(
            &[
                (first, Some((first, soft_fail))),
                (second, Some((second, answer.clone()))),
            ],
            &query,
            fallback,
        )
        .await;

        assert_eq!(asked, vec![first, second], "SERVFAIL is a soft error too");
        assert_eq!(
            got, answer,
            "the second upstream's answer reaches the client"
        );
    }

    /// An RCODE that is *not* soft is an answer: NXDOMAIN ends the walk where it is found, and the
    /// upstreams after it are never asked. (Making everything soft would turn a legitimate
    /// "no such name" into a needless extra round trip — and, with a second refusing upstream, into
    /// a different answer entirely.)
    #[tokio::test]
    async fn nxdomain_ends_the_walk_at_the_first_upstream() {
        let query = build_query(0x203, &["nope", "example", "com"], 1, 1);
        let (first, second) = (upstream_addr(1), upstream_addr(2));
        let nxdomain = upstream_response(&query, 3, 0, b"no such name");
        let fallback = upstream_response(&query, RCODE_SERVFAIL, 0, b"synthesized");

        let (got, asked) = run_forward_walk(
            &[
                (first, Some((first, nxdomain.clone()))),
                (
                    second,
                    Some((second, upstream_response(&query, 0, 1, b"late"))),
                ),
            ],
            &query,
            fallback,
        )
        .await;

        assert_eq!(asked, vec![first], "NXDOMAIN is an answer: stop asking");
        assert_eq!(got, nxdomain, "and it is what the client gets");
    }

    /// When every upstream refuses, the client gets the FIRST refusal, byte for byte — not the
    /// caller's synthesized SERVFAIL. The upstream's own bytes can carry an RFC 8914 extended DNS
    /// error explaining the refusal; a locally built packet throws that away.
    #[tokio::test]
    async fn every_upstream_refusing_returns_the_first_refusal_verbatim() {
        let query = build_query(0x204, &["api", "example", "com"], 1, 1);
        let (first, second) = (upstream_addr(1), upstream_addr(2));
        let first_refusal =
            upstream_response(&query, RCODE_REFUSED, 0, b"first refusal + extended error");
        let second_refusal = upstream_response(&query, RCODE_REFUSED, 0, b"second refusal");
        let fallback = upstream_response(&query, RCODE_SERVFAIL, 0, b"synthesized");

        let (got, asked) = run_forward_walk(
            &[
                (first, Some((first, first_refusal.clone()))),
                (second, Some((second, second_refusal.clone()))),
            ],
            &query,
            fallback.clone(),
        )
        .await;

        assert_eq!(
            asked,
            vec![first, second],
            "every upstream is given its turn"
        );
        assert_eq!(
            got, first_refusal,
            "an all-refused forward relays the first upstream's own REFUSED bytes"
        );
        assert_ne!(
            got, fallback,
            "the synthesized SERVFAIL must not replace an upstream's own response"
        );
        assert_ne!(got, second_refusal, "the FIRST refusal is the one kept");
    }

    /// The first *soft* response is the one kept whichever code it carried: a SERVFAIL followed by a
    /// REFUSED relays the upstream's own SERVFAIL, extended error and all, rather than the
    /// synthesized one the caller supplied.
    #[tokio::test]
    async fn every_upstream_soft_failing_returns_the_upstream_servfail_not_the_fallback() {
        let query = build_query(0x205, &["api", "example", "com"], 1, 1);
        let (first, second) = (upstream_addr(1), upstream_addr(2));
        let upstream_servfail = upstream_response(
            &query,
            RCODE_SERVFAIL,
            0,
            b"upstream servfail + extended error",
        );
        let refusal = upstream_response(&query, RCODE_REFUSED, 0, b"second refusal");
        let fallback = upstream_response(&query, RCODE_SERVFAIL, 0, b"synthesized");

        let (got, _asked) = run_forward_walk(
            &[
                (first, Some((first, upstream_servfail.clone()))),
                (second, Some((second, refusal))),
            ],
            &query,
            fallback.clone(),
        )
        .await;

        assert_eq!(
            got, upstream_servfail,
            "the upstream's own SERVFAIL is relayed verbatim, keeping any extended DNS error"
        );
        assert_ne!(got, fallback, "not the locally synthesized SERVFAIL");
    }

    /// A lone upstream that refuses still has its refusal relayed: with nothing else to wait for,
    /// treating REFUSED as soft changes nothing about what the client is told.
    #[tokio::test]
    async fn lone_refusing_upstream_still_has_its_refusal_relayed() {
        let query = build_query(0x206, &["api", "example", "com"], 1, 1);
        let only = upstream_addr(1);
        let refusal = upstream_response(&query, RCODE_REFUSED, 0, b"refused");
        let fallback = upstream_response(&query, RCODE_SERVFAIL, 0, b"synthesized");

        let (got, asked) =
            run_forward_walk(&[(only, Some((only, refusal.clone())))], &query, fallback).await;

        assert_eq!(asked, vec![only]);
        assert_eq!(
            got, refusal,
            "a single upstream's REFUSED is the client's answer"
        );
    }

    /// The anti-poisoning check still runs BEFORE any of the soft-error handling: a datagram whose
    /// transaction id is not the one we asked with is discarded outright and never remembered as
    /// "the first REFUSED", so an off-path injector cannot plant the response an all-refused forward
    /// ends up relaying.
    #[tokio::test]
    async fn wrong_transaction_id_response_is_discarded_not_remembered_as_a_soft_error() {
        let query = build_query(0x207, &["api", "example", "com"], 1, 1);
        let only = upstream_addr(1);
        let mut poisoned = upstream_response(&query, RCODE_REFUSED, 0, b"injected");
        poisoned[0] ^= 0xFF; // a transaction id we never asked with
        let fallback = upstream_response(&query, RCODE_SERVFAIL, 0, b"synthesized");

        let (got, _asked) = run_forward_walk(
            &[(only, Some((only, poisoned.clone())))],
            &query,
            fallback.clone(),
        )
        .await;

        assert_ne!(
            got, poisoned,
            "a mismatched transaction id must never be relayed"
        );
        assert_eq!(
            got, fallback,
            "with the datagram discarded nothing answered, so the synthesized fallback stands"
        );
    }

    /// The same for the source check: a well-formed REFUSED that echoes the question and the
    /// transaction id but arrives from an address we did not query is discarded before it can become
    /// the forward's remembered soft error.
    #[tokio::test]
    async fn off_path_source_response_is_discarded_not_remembered_as_a_soft_error() {
        let query = build_query(0x208, &["api", "example", "com"], 1, 1);
        let (only, off_path) = (upstream_addr(1), upstream_addr(9));
        let poisoned = upstream_response(&query, RCODE_REFUSED, 0, b"injected");
        let fallback = upstream_response(&query, RCODE_SERVFAIL, 0, b"synthesized");

        let (got, _asked) = run_forward_walk(
            &[(only, Some((off_path, poisoned.clone())))],
            &query,
            fallback.clone(),
        )
        .await;

        assert_ne!(
            got, poisoned,
            "a datagram from an unqueried source must never be relayed"
        );
        assert_eq!(
            got, fallback,
            "with the datagram discarded nothing answered, so the synthesized fallback stands"
        );
    }

    /// An upstream that says nothing at all (timeout, bind/send/recv failure) is simply skipped, and
    /// the next upstream's answer is what the client gets.
    #[tokio::test]
    async fn silent_upstream_is_skipped_for_the_next_one() {
        let query = build_query(0x209, &["api", "example", "com"], 1, 1);
        let (first, second) = (upstream_addr(1), upstream_addr(2));
        let answer = upstream_response(&query, 0, 1, b"the real answer");
        let fallback = upstream_response(&query, RCODE_SERVFAIL, 0, b"synthesized");

        let (got, asked) = run_forward_walk(
            &[(first, None), (second, Some((second, answer.clone())))],
            &query,
            fallback,
        )
        .await;

        assert_eq!(asked, vec![first, second]);
        assert_eq!(got, answer);
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
    fn no_resolvers_off_tailnet_is_servfail_not_nxdomain() {
        // No route, no resolvers: an OFF-tailnet name cannot be forwarded. Go answers SERVFAIL
        // (forwarder.go:1207 "no upstream resolvers set, returning SERVFAIL"), NOT NXDOMAIN — a
        // cacheable non-existence for a real name we merely couldn't forward would poison downstream
        // stub caches. We still never forward (the name does not leak); we just soft-fail.
        let view = view_with_routes(std::collections::BTreeMap::new(), vec![], vec![]);
        let buf = build_query(0x106, &["example", "com"], 1, 1);

        match decide(&view, &buf).expect("decides") {
            Decision::Reply(resp) => {
                let (_, rcode, _) = parse_header(&resp);
                assert_eq!(
                    rcode, 2,
                    "ServFail: off-tailnet name with no upstream to forward to"
                );
            }
            Decision::Forward { .. } => panic!("must not forward with no resolvers"),
        }
    }

    #[test]
    fn route_with_only_ipv6_upstreams_off_tailnet_is_servfail() {
        // A split-DNS route exists but every resolver is IPv6 (filtered out under the IPv4-only
        // egress): we have a route yet nowhere to forward. That is an inability to forward an
        // off-tailnet name, so SERVFAIL (soft), not a fabricated NXDOMAIN.
        let mut routes = std::collections::BTreeMap::new();
        routes.insert("corp.example".to_string(), vec![udp("[2001:db8::53]:53")]);
        let view = view_with_routes(routes, vec![], vec![]);
        let buf = build_query(0x108, &["host", "corp", "example"], 1, 1);

        match decide(&view, &buf).expect("decides") {
            Decision::Reply(resp) => {
                let (_, rcode, _) = parse_header(&resp);
                assert_eq!(
                    rcode, 2,
                    "ServFail: route's resolvers all filtered out (IPv6-only), cannot forward"
                );
            }
            Decision::Forward { .. } => panic!("must not forward when all upstreams are filtered"),
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

    /// The `TC` bit a truncated UDP answer sets is what sends a stub resolver to TCP (RFC 1035
    /// §4.2.1). Setting it *again* on the TCP answer sends that resolver straight back into another
    /// retry, so the client's advertised UDP payload size — a property of the datagram it would
    /// have been answered in, and one RFC 7766 §8 gives a TCP client no equivalent of — is applied
    /// only to a [`ClientTransport::Udp`] client. Same query, same answer, two transports.
    #[test]
    fn client_udp_limit_is_not_applied_to_a_tcp_client() {
        // No EDNS OPT record, so the client's limit is the classic 512 bytes.
        let query = build_query(0x310, &["example", "com"], 1, 1);
        let mut answer = query.clone();
        answer[2] |= 0x80; // make it a response (QR=1)
        answer.resize(900, 0xAB); // over 512, under MAX_UPSTREAM_RESPONSE: only the client limit bites

        let udp = cap_response(&query, answer.clone(), ClientTransport::Udp);
        assert_ne!(
            udp[2] & 0x02,
            0,
            "a UDP client that advertised 512 bytes is told the 900-byte answer is truncated"
        );
        assert_eq!(udp.len(), 900, "and the body is left intact either way");

        let tcp = cap_response(&query, answer, ClientTransport::Tcp);
        assert_eq!(
            tcp[2] & 0x02,
            0,
            "the same answer over TCP is NOT marked: the client already did the TCP retry"
        );
        assert_eq!(tcp.len(), 900, "and is relayed whole");
    }

    /// The relay cap is a different claim from the client's datagram size, and it holds on both
    /// transports: when [`MAX_UPSTREAM_RESPONSE`] really did cut the message, `TC` says so. Handing
    /// a TCP client a chopped body with `TC` clear would be a malformed-but-"complete" answer.
    #[test]
    fn a_chopped_answer_is_marked_truncated_on_both_transports() {
        let query = build_edns_query(0x311, &["example", "com"], 1, 1, 4096);
        let mut big = query.clone();
        big[2] |= 0x80;
        big.resize(MAX_UPSTREAM_RESPONSE + 500, 0xAB);

        let out = cap_response(&query, big, ClientTransport::Tcp);
        assert_eq!(out.len(), MAX_UPSTREAM_RESPONSE, "capped to one datagram");
        assert_ne!(
            out[2] & 0x02,
            0,
            "we really did chop the body, so TC is set for a TCP client too"
        );
    }

    #[test]
    fn cap_response_sets_tc_when_truncated() {
        // An oversize upstream answer is capped to a single datagram AND marked truncated (TC bit)
        // so the stub resolver retries over TCP rather than trusting a chopped message. The query
        // advertises a big EDNS buffer so only the relay cap can be what fires here.
        let query = build_edns_query(0x300, &["example", "com"], 1, 1, 4096);
        let mut big = query.clone();
        big[2] |= 0x80; // make it a response (QR=1)
        big.resize(MAX_UPSTREAM_RESPONSE + 500, 0xAB);

        let out = cap_response(&query, big, ClientTransport::Udp);
        assert_eq!(out.len(), MAX_UPSTREAM_RESPONSE, "capped to one datagram");
        assert_ne!(out[2] & 0x02, 0, "TC bit set on truncation");
    }

    #[test]
    fn cap_response_leaves_small_response_untouched() {
        // A response that fits both bounds is returned verbatim with no TC bit forced on.
        let query = build_query(0x301, &["example", "com"], 1, 1);
        let mut small = query.clone();
        small[2] |= 0x80;
        let before = small.clone();

        let out = cap_response(&query, small, ClientTransport::Udp);
        assert_eq!(out, before, "small response unchanged");
        assert_eq!(out[2] & 0x02, 0, "TC bit not set when no truncation");
    }

    #[test]
    fn cap_is_a_relay_bound_not_the_read_bound() {
        // `forward_query` reads with `recv_from_bytes`, which issues `Recv { max_len: None }`, so
        // the netstack has already copied the whole datagram out before `cap_response` runs: the
        // cap bounds what we relay, not what we read or allocate. What bounds the read is the
        // netstack UDP socket's receive ring (`udp_buffer_size`, which `ts_runtime` leaves at the
        // `netcore` default) -- smoltcp drops a datagram larger than that ring at enqueue instead
        // of delivering it, and hands us everything up to and including the ring whole. The ring
        // being *wider* than the cap is what shows the two are different bounds: the read can put
        // more bytes in front of `cap_response` than the cap will relay.
        let ring = netstack::netcore::Config::default().udp_buffer_size;
        assert!(
            ring > MAX_UPSTREAM_RESPONSE,
            "the netstack udp receive ring ({ring}) no longer exceeds the relay cap \
             ({MAX_UPSTREAM_RESPONSE}): the cap would then be unreachable through this socket, and \
             the doc describing it as a relay bound the read can overrun is wrong"
        );

        // The largest answer the cap passes is relayed byte-for-byte. Ask with an EDNS buffer that
        // covers the whole datagram, so the client-limit check (the other half of `cap_response`)
        // is not what we are measuring.
        let query = build_edns_query(0x302, &["example", "com"], 1, 1, 4096);
        let mut largest = query.clone();
        largest[2] |= 0x80; // QR=1
        largest.resize(MAX_UPSTREAM_RESPONSE, 0xAB);
        let before = largest.clone();

        let out = cap_response(&query, largest, ClientTransport::Udp);
        assert_eq!(out, before, "an answer at the cap must be relayed verbatim");
        assert_eq!(
            out[2] & 0x02,
            0,
            "TC must not be set on a datagram that was never chopped"
        );
    }

    #[test]
    fn full_ring_datagram_is_chopped_and_marked_truncated() {
        // Upstream's bound is `const maxResponseBytes = 4095` (net/dns/resolver/tsdns.go @
        // 9ea7cba44591e0cd840c6c94d23274dd222059bf). `sendUDP` reads into `maxResponseBytes+1`
        // bytes exactly so a 4096-byte answer is detectable as "did not fit", then cuts it to 4095
        // and sets TC. Here the netstack's 4096-byte receive ring plays the part of Go's `+1`: a
        // full-ring datagram is the one deliverable size the cap does not pass, and it must come
        // back with the same shape a Go forwarder would have produced. With the cap at 4096 this
        // datagram was relayed whole with TC clear, while a Go client on the same tailnet answering
        // the same query returned 4095 bytes marked truncated.
        let ring = netstack::netcore::Config::default().udp_buffer_size;
        let query = build_edns_query(0x303, &["example", "com"], 1, 1, 4096);
        let mut full_ring = query.clone();
        full_ring[2] |= 0x80; // QR=1
        full_ring.resize(ring, 0xAB);

        let out = cap_response(&query, full_ring, ClientTransport::Udp);
        assert_eq!(
            out.len(),
            4095,
            "a full-ring answer must be cut to upstream's maxResponseBytes"
        );
        assert_ne!(out[2] & 0x02, 0, "TC bit set on the chopped answer");
    }

    #[test]
    fn forwarded_reply_over_512_sets_tc_for_a_plain_query() {
        // A query with no EDNS OPT record is limited to 512 bytes (RFC 1035), so a 900-byte
        // forwarded reply -- well under the 4095 relay cap, and therefore relayed with TC clear
        // before this check existed -- must come back marked truncated, body intact.
        let query = build_query(0x400, &["example", "com"], 1, 1);
        let mut reply = query.clone();
        reply[2] |= 0x80; // QR=1
        reply.resize(900, 0xAB);

        let out = cap_response(&query, reply.clone(), ClientTransport::Udp);

        assert_ne!(
            out[2] & 0x02,
            0,
            "a 900-byte reply to a non-EDNS query must have TC set"
        );
        assert_eq!(out.len(), 900, "the body is left intact, not chopped");
        assert_eq!(
            out[3..],
            reply[3..],
            "only the flags byte carrying TC may differ"
        );
    }

    #[test]
    fn forwarded_reply_under_advertised_edns_size_leaves_tc_clear() {
        // The same 900-byte reply, but the client advertised a 4096-byte EDNS buffer: it fits, so
        // TC must stay clear and the datagram must be relayed byte-for-byte.
        let query = build_edns_query(0x401, &["example", "com"], 1, 1, 4096);
        let mut reply = query.clone();
        reply[2] |= 0x80; // QR=1
        reply.resize(900, 0xAB);
        let before = reply.clone();

        let out = cap_response(&query, reply, ClientTransport::Udp);

        assert_eq!(
            out, before,
            "a reply within the advertised buffer is verbatim"
        );
        assert_eq!(out[2] & 0x02, 0, "TC must stay clear");
    }

    /// Go's `findOPTRecord` accepts an OPT record only in the final 11 bytes of the message, with a
    /// root NAME, EDNS version 0 and `RDLEN == 0`; anything else is "no EDNS", i.e. the 512-byte
    /// RFC 1035 limit. Every rejection below is a case where a laxer reader would honour a large
    /// advertised buffer and leave `TC` clear on an answer a Go node marks truncated.
    #[test]
    fn client_udp_limit_reads_the_opt_record() {
        // No OPT record => the RFC 1035 512-byte limit.
        let plain = build_query(0x402, &["example", "com"], 1, 1);
        assert_eq!(client_udp_limit(&plain), NO_EDNS_UDP_LIMIT);

        // An OPT record's CLASS field carries the advertised size.
        let edns = build_edns_query(0x403, &["example", "com"], 1, 1, 1232);
        assert_eq!(client_udp_limit(&edns), 1232);

        // A value below 512 is taken verbatim. RFC 6891 6.2.3 would floor it at 512, but Go does
        // not (`maxSize = int(ednsSize)`), so a Rust node that did would leave `TC` clear where a
        // Go node on the same tailnet sets it.
        let tiny = build_edns_query(0x404, &["example", "com"], 1, 1, 64);
        assert_eq!(client_udp_limit(&tiny), 64);

        // An OPT record that is not the last record in the message is not read at all: upstream
        // only ever looks at the final 11 bytes.
        let mut trailing_rr = build_edns_query(0x405, &["example", "com"], 1, 1, 2048);
        // A 1-byte-RDATA TXT (type 16) record for the root name, appended after the OPT.
        trailing_rr.extend_from_slice(&[0, 0, 16, 0, 1, 0, 0, 0, 0, 0, 1, 0]);
        trailing_rr[11] = 2; // ARCOUNT = 2
        assert_eq!(client_udp_limit(&trailing_rr), NO_EDNS_UDP_LIMIT);

        // An OPT record carrying options — a DNS cookie, EDNS Client Subnet — has RDLEN != 0 and is
        // rejected. This is the common case, not a corner: stub resolvers send cookies routinely.
        let cookie =
            build_edns_query_with_option(0x406, &["example", "com"], 1, 1, 4096, 10, &[0; 8]);
        assert_eq!(client_udp_limit(&cookie), NO_EDNS_UDP_LIMIT);

        // An unknown EDNS version is left alone rather than guessed at.
        let mut future_version = build_edns_query(0x407, &["example", "com"], 1, 1, 4096);
        let ttl_at = future_version.len() - 6; // TTL = extended RCODE (1) | VERSION (1) | flags (2)
        future_version[ttl_at + 1] = 1; // EDNS version 1
        assert_eq!(client_udp_limit(&future_version), NO_EDNS_UDP_LIMIT);

        // A non-root OPT NAME is rejected.
        let mut named = build_edns_query(0x408, &["example", "com"], 1, 1, 4096);
        let name_at = named.len() - 11;
        named[name_at] = 0xC0; // a compression pointer where the root label must be
        assert_eq!(client_udp_limit(&named), NO_EDNS_UDP_LIMIT);

        // ARCOUNT == 0 means there is no additional section to hold an OPT, whatever the trailing
        // bytes happen to look like.
        let mut no_ar = build_edns_query(0x409, &["example", "com"], 1, 1, 4096);
        no_ar[11] = 0;
        assert_eq!(client_udp_limit(&no_ar), NO_EDNS_UDP_LIMIT);

        // A truncated message falls back to the conservative limit, never a larger one.
        let mut chopped = build_edns_query(0x40A, &["example", "com"], 1, 1, 4096);
        chopped.truncate(chopped.len() - 8);
        assert_eq!(client_udp_limit(&chopped), NO_EDNS_UDP_LIMIT);
    }

    /// The whole point of the narrow OPT reader, end to end: a stub resolver that advertises 4096
    /// **and** sends a DNS cookie is capped at 512, so the 900-byte forwarded reply comes back with
    /// `TC` set. A reader that walked the additional section properly would honour the 4096 and
    /// leave `TC` clear — which is the answer no Go node on the tailnet would have produced.
    #[test]
    fn an_opt_record_carrying_options_is_not_honoured() {
        let query =
            build_edns_query_with_option(0x40B, &["example", "com"], 1, 1, 4096, 10, &[0; 8]);
        let mut reply = query.clone();
        reply[2] |= 0x80; // QR=1
        reply.resize(900, 0xAB);

        let out = cap_response(&query, reply, ClientTransport::Udp);
        assert_ne!(
            out[2] & 0x02,
            0,
            "an OPT record with options is no EDNS at all upstream: the 512-byte limit applies"
        );
        assert_eq!(out.len(), 900, "the body is left intact, not chopped");
    }

    /// An advertised size below 512 is honoured as-is. Go floors nothing: `maxSize = int(ednsSize)`
    /// whenever an OPT record is present, and only a request with no OPT record falls back to 512.
    #[test]
    fn an_advertised_size_below_512_is_not_floored() {
        let query = build_edns_query(0x40C, &["example", "com"], 1, 1, 200);
        let mut reply = query.clone();
        reply[2] |= 0x80; // QR=1
        reply.resize(300, 0xAB);

        let out = cap_response(&query, reply, ClientTransport::Udp);
        assert_ne!(
            out[2] & 0x02,
            0,
            "300 bytes overflows the 200 the client asked for, so TC is set"
        );
        assert_eq!(out.len(), 300, "the body is left intact, not chopped");
    }

    /// Upstream runs the size check on answers the resolver builds itself, not only on forwarded
    /// ones (`Resolver.Query` calls `checkResponseSizeAndSetTC` right after `respond` succeeds). An
    /// authoritative answer is capped at 512 bytes, which says nothing about a client that
    /// advertised less than that.
    #[test]
    fn an_authoritative_answer_over_the_advertised_size_is_marked() {
        let view = view_with_peer();
        let buf = build_edns_query(0x40D, &["host", "user", "ts", "net"], 1, 1, 20);

        let resp = answer(&view, &buf).expect("answers");
        assert!(
            resp.len() > 20,
            "the fixture only works if the answer overflows the advertised 20 bytes"
        );

        let marked = check_response_size_and_set_tc(&buf, resp.clone(), ClientTransport::Udp);
        assert_ne!(
            marked[2] & 0x02,
            0,
            "an answer we composed ourselves can still overflow a small advertised buffer"
        );
        assert_eq!(marked.len(), resp.len(), "the body is left intact");
        assert_eq!(
            marked[3..],
            resp[3..],
            "only the flags byte carrying TC may differ"
        );
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

    // --- SOA on authoritative negative answers (RFC 2308) -----------------------------------

    /// Read an uncompressed name at `off`, returning it dotted and the offset just past it.
    fn read_name(resp: &[u8], mut off: usize) -> (String, usize) {
        let mut labels: Vec<String> = Vec::new();
        loop {
            let len = resp[off] as usize;
            assert_eq!(len & 0xC0, 0, "no compression pointer expected here");
            off += 1;
            if len == 0 {
                break;
            }
            labels.push(String::from_utf8(resp[off..off + len].to_vec()).expect("ascii label"));
            off += len;
        }
        (labels.join("."), off)
    }

    /// The number of records in a response's authority section (NSCOUNT).
    fn nscount(resp: &[u8]) -> u16 {
        u16::from_be_bytes([resp[8], resp[9]])
    }

    /// Walk an answer-less response to its authority section and read the SOA there, returning
    /// `(zone, record TTL, SERIAL, MINIMUM)`. `None` when the authority section is empty.
    ///
    /// Also asserts the record's shape as it goes: TYPE=SOA, CLASS=IN, and MNAME/RNAME both equal
    /// the owner name (the placeholders Go writes).
    fn parse_soa(resp: &[u8]) -> Option<(String, u32, u32, u32)> {
        let (.., ancount) = parse_header(resp);
        assert_eq!(ancount, 0, "parse_soa only walks answer-less responses");
        if nscount(resp) == 0 {
            return None;
        }
        assert_eq!(nscount(resp), 1, "at most one SOA");

        // Question: QNAME then QTYPE + QCLASS.
        let (_, off) = read_name(resp, 12);
        // Authority record: NAME, TYPE, CLASS, TTL, RDLENGTH, RDATA.
        let (zone, off) = read_name(resp, off + 4);
        let u16_at = |at: usize| u16::from_be_bytes([resp[at], resp[at + 1]]);
        let u32_at = |at: usize| u32::from_be_bytes(resp[at..at + 4].try_into().unwrap());
        assert_eq!(u16_at(off), 6, "TYPE = SOA");
        assert_eq!(u16_at(off + 2), 1, "CLASS = IN");
        let ttl = u32_at(off + 4);
        let rdlength = u16_at(off + 8) as usize;

        // RDATA: MNAME, RNAME, SERIAL, REFRESH, RETRY, EXPIRE, MINIMUM.
        let rdata_start = off + 10;
        let (mname, off) = read_name(resp, rdata_start);
        let (rname, off) = read_name(resp, off);
        assert_eq!(mname, zone, "MNAME is the zone (placeholder)");
        assert_eq!(rname, zone, "RNAME is the zone (placeholder)");
        let serial = u32_at(off);
        let minimum = u32_at(off + 16);
        assert_eq!(
            off + 20 - rdata_start,
            rdlength,
            "RDLENGTH covers exactly the SOA fields"
        );
        assert_eq!(resp.len(), off + 20, "the SOA is the last record");
        Some((zone, ttl, serial, minimum))
    }

    /// Roughly-now, for asserting the SOA SERIAL is a unix timestamp rather than a constant.
    fn now_unix() -> u32 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after the epoch")
            .as_secs() as u32
    }

    /// An NXDOMAIN for a name under a tailnet search domain is authoritative, so it carries that
    /// search domain's SOA with the 10-second negative TTL. Without it a downstream cache picks its
    /// own (much longer) negative lifetime and a node renamed to that name stays unresolvable.
    #[test]
    fn nxdomain_for_tailnet_name_carries_the_search_domain_soa() {
        let view = view_with_peer();
        let buf = build_query(0x1111, &["nope", "user", "ts", "net"], 1, 1);

        let resp = answer(&view, &buf).expect("answers");
        let (_, rcode, ancount) = parse_header(&resp);
        assert_eq!(rcode, 3, "NXDOMAIN");
        assert_eq!(ancount, 0);

        let (zone, ttl, serial, minimum) =
            parse_soa(&resp).expect("an SOA in the authority section");
        assert_eq!(zone, "user.ts.net", "the search domain containing the name");
        assert_eq!(ttl, 10, "negative TTL");
        assert_eq!(minimum, 10, "MINIMUM also bounds negative caching");
        // The serial is the response time in unix seconds, not a fixed placeholder.
        assert!(
            serial.abs_diff(now_unix()) < 60,
            "SERIAL should be about now, got {serial}"
        );
    }

    /// A NODATA — the name exists but we hold no address of the queried family, which is what an
    /// AAAA query for a peer becomes with the IPv6 gate off — is negative too, and takes the SOA.
    #[test]
    fn nodata_aaaa_for_known_peer_carries_the_soa() {
        let view = view_with_peer();
        assert!(!view.enable_ipv6, "default gate is off");
        let buf = build_query(0x2222, &["host", "user", "ts", "net"], 28, 1);

        let resp = answer(&view, &buf).expect("answers");
        let (_, rcode, ancount) = parse_header(&resp);
        assert_eq!(rcode, 0, "NoError (NODATA)");
        assert_eq!(ancount, 0);
        let (zone, ttl, _, minimum) = parse_soa(&resp).expect("an SOA in the authority section");
        assert_eq!(zone, "user.ts.net");
        assert_eq!((ttl, minimum), (10, 10));
    }

    /// A reverse query for an unmatched IP in the tailnet CGNAT range is authoritatively absent, so
    /// it carries the SOA of the reverse zone that covers it — the same per-/16 `in-addr.arpa`
    /// chunk real tailscaled advertises, not the search domain.
    #[test]
    fn cgnat_reverse_miss_carries_the_reverse_zone_soa() {
        let view = view_with_peer();
        // Reverse name for an unclaimed 100.64.0.0/10 address, least-significant octet first.
        let buf = build_query(0x3333, &["9", "0", "64", "100", "in-addr", "arpa"], 12, 1);

        let resp = answer(&view, &buf).expect("answers");
        let (_, rcode, ancount) = parse_header(&resp);
        assert_eq!(rcode, 3, "NXDOMAIN");
        assert_eq!(ancount, 0);
        let (zone, ttl, _, minimum) = parse_soa(&resp).expect("an SOA in the authority section");
        assert_eq!(zone, "64.100.in-addr.arpa", "the CGNAT reverse zone");
        assert_eq!((ttl, minimum), (10, 10));
    }

    /// The exotic-qtype path re-applies the CGNAT reverse guard, and its NXDOMAIN is just as
    /// authoritative — so it carries the same reverse-zone SOA the PTR arm does.
    #[test]
    fn exotic_qtype_cgnat_reverse_nxdomain_carries_the_soa() {
        let view = view_with_peer();
        // TXT (16) for a CGNAT reverse name.
        let buf = build_query(0x4444, &["9", "0", "64", "100", "in-addr", "arpa"], 16, 1);

        let resp = answer(&view, &buf).expect("answers");
        assert_eq!(parse_header(&resp).1, 3, "NXDOMAIN");
        let (zone, ..) = parse_soa(&resp).expect("an SOA in the authority section");
        assert_eq!(zone, "64.100.in-addr.arpa");
    }

    /// A negative split-DNS route (a route with no resolvers) is Go's `localDomains` verbatim: the
    /// NXDOMAIN it produces is authoritative and names the route's own suffix as its zone.
    #[test]
    fn negative_route_nxdomain_carries_the_route_zone_soa() {
        let mut routes = std::collections::BTreeMap::new();
        routes.insert("corp.example".to_string(), vec![]);
        let view = view_with_routes(routes, vec![], vec![]);
        let buf = build_query(0x5555, &["intranet", "corp", "example"], 1, 1);

        let resp = answer(&view, &buf).expect("answers");
        assert_eq!(parse_header(&resp).1, 3, "NXDOMAIN");
        let (zone, ttl, _, minimum) = parse_soa(&resp).expect("an SOA in the authority section");
        assert_eq!(zone, "corp.example");
        assert_eq!((ttl, minimum), (10, 10));
    }

    /// Answers we are NOT authoritative for carry no SOA: a SERVFAIL is a soft failure with nothing
    /// to cache, and an `ip6.arpa` NXDOMAIN is this fork's blanket anti-leak refusal, not a claim to
    /// serve the IPv6 reverse tree.
    #[test]
    fn non_authoritative_negative_answers_carry_no_soa() {
        let view = view_with_peer();

        // Off-tailnet name, no upstream configured => SERVFAIL.
        let servfail =
            answer(&view, &build_query(0x6, &["example", "com"], 1, 1)).expect("answers");
        assert_eq!(parse_header(&servfail).1, 2, "ServFail");
        assert_eq!(nscount(&servfail), 0, "SERVFAIL carries no SOA");

        // An ip6.arpa reverse name. The exact nibble labels do not matter to the guard.
        let mut labels: Vec<&str> = vec!["1"; 32];
        labels.push("ip6");
        labels.push("arpa");
        let ip6 = answer(&view, &build_query(0x7, &labels, 12, 1)).expect("answers");
        assert_eq!(parse_header(&ip6).1, 3, "NXDOMAIN");
        assert_eq!(nscount(&ip6), 0, "ip6.arpa NXDOMAIN carries no SOA");

        // MagicDNS off => REFUSED, which asserts nothing about the name.
        let mut off = view_with_peer();
        off.cfg.magic_dns = false;
        let refused = answer(
            &off,
            &build_query(0x8, &["host", "user", "ts", "net"], 1, 1),
        )
        .expect("answers");
        assert_eq!(parse_header(&refused).1, 5, "Refused");
        assert_eq!(nscount(&refused), 0, "REFUSED carries no SOA");
    }

    /// A NODATA for a type we simply do not serve on a name we do (TXT on a tailnet name) carries
    /// no SOA: Go sets `SOAZone` on a no-data answer only for an A/AAAA/ALL question.
    #[test]
    fn nodata_for_an_unserved_qtype_carries_no_soa() {
        let view = view_with_peer();
        let resp = answer(
            &view,
            &build_query(0x9, &["host", "user", "ts", "net"], 16, 1),
        )
        .expect("answers");
        let (_, rcode, ancount) = parse_header(&resp);
        assert_eq!((rcode, ancount), (0, 0), "NODATA");
        assert_eq!(nscount(&resp), 0);
    }

    /// A positive answer has an empty authority section and a 5-second TTL. The short TTL is the
    /// positive half of the same argument: the netmap is local and in-memory, so a re-query is
    /// nearly free, while a downstream cache would otherwise hide a node rename for the full TTL.
    #[test]
    fn positive_answer_has_ttl_5_and_no_authority_section() {
        let view = view_with_peer();
        let resp = answer(
            &view,
            &build_query(0xA, &["host", "user", "ts", "net"], 1, 1),
        )
        .expect("answers");
        let (_, rcode, ancount) = parse_header(&resp);
        assert_eq!((rcode, ancount), (0, 1), "one A record");
        assert_eq!(nscount(&resp), 0, "a positive answer claims no zone");
        // The single A record's tail is TTL, RDLENGTH, RDATA.
        let ttl_at = resp.len() - 10;
        let ttl = u32::from_be_bytes(resp[ttl_at..ttl_at + 4].try_into().unwrap());
        assert_eq!(ttl, 5, "positive TTL");
    }

    /// An authoritative negative answer with its SOA attached must still fit the classic 512-byte
    /// UDP limit, so the client-limit check leaves TC clear on it for a client that advertised no
    /// EDNS buffer. (A client that advertises *less* than 512 is a different case and is marked —
    /// see `an_authoritative_answer_over_the_advertised_size_is_marked`.)
    #[test]
    fn nxdomain_with_soa_stays_within_the_client_udp_limit() {
        let view = view_with_peer();
        let long = "a".repeat(63);
        let buf = build_query(0xB, &[&long, "user", "ts", "net"], 1, 1);

        let resp = answer(&view, &buf).expect("answers");
        assert_eq!(nscount(&resp), 1, "the SOA fits beside this question");
        assert!(resp.len() <= 512, "still one classic UDP datagram");

        let marked = check_response_size_and_set_tc(&buf, resp.clone(), ClientTransport::Udp);
        assert_eq!(marked, resp, "nothing to mark: an authoritative reply fits");
        assert_eq!(
            u16::from_be_bytes([marked[2], marked[3]]) & 0x0200,
            0,
            "TC must stay clear"
        );
    }

    /// When the zone is so long that its SOA no longer fits under the 512-byte cap, the SOA is
    /// dropped rather than the answer being truncated: the NXDOMAIN goes back complete, with an
    /// empty authority section, TC clear, and still within a client's UDP limit. Losing the SOA
    /// only means a resolver falls back to its own negative-cache policy.
    #[test]
    fn an_soa_that_will_not_fit_is_dropped_and_the_nxdomain_still_answers() {
        let long = "a".repeat(63);
        let zone = [long.as_str(), long.as_str(), long.as_str()].join(".");
        let mut view = view_with_peer();
        view.cfg.search_domains = vec![zone.clone()];

        let buf = build_query(0xC, &["x", &long, &long, &long], 1, 1);
        let resp = answer(&view, &buf).expect("answers");

        assert_eq!(parse_header(&resp).1, 3, "NXDOMAIN");
        assert_eq!(nscount(&resp), 0, "the SOA did not fit and was dropped");
        assert!(resp.len() <= 512, "response stays within the UDP limit");
        let marked = check_response_size_and_set_tc(&buf, resp.clone(), ClientTransport::Udp);
        assert_eq!(
            u16::from_be_bytes([marked[2], marked[3]]) & 0x0200,
            0,
            "a dropped SOA must not set TC: the fork cannot serve the TCP retry it would ask for"
        );
    }

    /// The zone is the *longest* authoritative suffix containing the name, so a name under a
    /// sub-zone gets the sub-zone's SOA rather than the shorter search domain's.
    #[test]
    fn the_longest_authoritative_zone_wins() {
        let mut routes = std::collections::BTreeMap::new();
        routes.insert("sub.user.ts.net".to_string(), vec![]);
        let mut view = view_with_routes(routes, vec![], vec![]);
        view.cfg.search_domains = vec!["user.ts.net".to_string()];

        let buf = build_query(0xD, &["nope", "sub", "user", "ts", "net"], 1, 1);
        let resp = answer(&view, &buf).expect("answers");
        assert_eq!(parse_header(&resp).1, 3, "NXDOMAIN");
        let (zone, ..) = parse_soa(&resp).expect("an SOA in the authority section");
        assert_eq!(zone, "sub.user.ts.net");
    }

    /// A name we resolved only by search-domain qualification (a short name like `host`) is not
    /// itself inside a zone we serve, so its negative answer names no zone — matching Go, whose
    /// `authoritativeZoneFor` is given the query name as asked.
    #[test]
    fn a_short_name_outside_every_zone_gets_no_soa() {
        let mut view = view_with_peer();
        view.enable_ipv6 = false;
        // `host` resolves to the peer via search-domain qualification, and with IPv6 off the AAAA
        // is a NODATA — but `host` sits under no zone we serve.
        let resp = answer(&view, &build_query(0xE, &["host"], 28, 1)).expect("answers");
        let (_, rcode, ancount) = parse_header(&resp);
        assert_eq!((rcode, ancount), (0, 0), "NODATA");
        assert_eq!(nscount(&resp), 0, "no zone contains a single-label name");
    }
}
