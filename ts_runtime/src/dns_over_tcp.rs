//! DNS over TCP for the MagicDNS service IP (`100.100.100.100:53`).
//!
//! A stub resolver that receives a UDP answer with the `TC` (truncated) bit set is required to
//! retry the query over TCP (RFC 1035 §4.2.1, RFC 7766 §5). Upstream Go serves that retry: in
//! `wgengine/netstack`'s `acceptTCP`, `hittingDNS := hittingServiceIP && reqDetails.LocalPort == 53`
//! selects the DNS handler for a quad-100 TCP connection, and only a quad-100 port with **no**
//! handler falls through to `r.Complete(true)` — the RST (wgengine/netstack/netstack.go @
//! `9ea7cba44591e0cd840c6c94d23274dd222059bf`). Without this module the retry is answered with a
//! RST, so a query whose answer does not fit a datagram has no path at all.
//!
//! What is served: the same [`decide`](crate::magic_dns::decide) responder the UDP path uses,
//! reached through [`answer_query`], so an authoritative answer, a split-DNS forward and a
//! recursive forward all behave identically on both transports. The one deliberate difference is
//! the `TC` bit — see [`ClientTransport`].
//!
//! Scope of that `TC` difference, stated exactly: it is applied to **forwarded** answers only.
//! An authoritative answer still comes out of `ts_dns_wire::encode_response`, which builds to the
//! classic 512-byte datagram budget and sets `TC` if it has to drop an answer — a bound a TCP
//! client does not have. That is left as is rather than re-plumbed, because overflowing 512 needs a
//! ~240+ wire-byte question name and a name that long matches no peer, so the branch that would set
//! `TC` on an authoritative answer is not reachable: every authoritative answer this serves
//! provably fits. A forwarded answer, which really can be large, is the case the transport
//! distinction exists for.
//!
//! One limit that stays: a forwarded answer above `MAX_UPSTREAM_RESPONSE` (4095 bytes) is chopped
//! and marked `TC` on both transports, because the hop to the upstream resolver is UDP either way —
//! so a TCP client is told "truncated" with no further transport to retry on. Closing that means
//! forwarding upstream over TCP, which this does not do.
//!
//! Framing is RFC 1035 §4.2.2: each message, in both directions, is preceded by a two-byte
//! big-endian length. Queries on one connection are answered **in order**: RFC 7766 §6.2.1 permits
//! a server to answer out of order but does not require it, and in-order keeps a connection to a
//! single task with no reply-matching state. The connection is reused until the client closes it or
//! [`IDLE_TIMEOUT`] elapses with no new query.
//!
//! Anti-leak: forwarding rides the overlay netstack channel handed to [`serve`], never a host
//! socket — the same channel, and so the same property, as the UDP responder.

use std::sync::Arc;

use netstack::{netcore::Channel, netsock::TcpListener};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{Semaphore, watch},
    time::{Duration, timeout},
};

use crate::magic_dns::{
    ClientTransport, Decision, DnsView, RecursivePlan, decide, forward_plan, forward_query,
};

/// Resolve one client query end to end and return the wire response, or `None` when the query is
/// malformed (nothing parseable to answer with — the caller drops it).
///
/// This is [`decide`] plus, for a [`Decision::Forward`], the overlay round trip that
/// [`forward_plan`] selected. Unlike the UDP serve loop — which hands the slow forward back to be
/// spawned so one hung upstream cannot head-of-line-block the single datagram socket every client
/// shares — this awaits inline, because a TCP client already has a task and a socket of its own.
///
/// Anti-leak: every forward rides `channel` (the overlay netstack), never a host socket.
async fn answer_query(view: &DnsView, channel: &Channel, query: &[u8]) -> Option<Vec<u8>> {
    match decide(view, query)? {
        Decision::Reply(response) => Some(response),
        Decision::Forward {
            upstreams,
            query,
            servfail,
            recursive,
        } => Some(match forward_plan(view, upstreams, recursive) {
            RecursivePlan::Udp(upstreams) => {
                forward_query(channel, &upstreams, &query, servfail, ClientTransport::Tcp).await
            }
            RecursivePlan::Doh(doh_addr) => {
                crate::peerapi_doh::forward_doh(
                    channel,
                    doh_addr,
                    &query,
                    servfail,
                    ClientTransport::Tcp,
                )
                .await
            }
        }),
    }
}

/// How long a connection may sit with no new query before we close it.
///
/// RFC 7766 §6.2.3 leaves the value to the implementation but requires *some* bound: a stub
/// resolver that opens a connection, asks one question and then goes quiet otherwise pins a task
/// and a netstack socket (with its eagerly-allocated send/receive buffers) indefinitely. Long
/// enough that a resolver reusing its connection for a burst of queries does not pay a fresh
/// handshake for each, short enough that an abandoned connection is reclaimed promptly.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long to wait for the rest of a message once its length prefix has arrived.
///
/// Separate from [`IDLE_TIMEOUT`] because the two failures are different: idling between queries is
/// normal client behaviour, whereas announcing a length and then stalling mid-message is either a
/// broken client or a cheap way to hold a connection open forever, and deserves the shorter leash.
const MESSAGE_TIMEOUT: Duration = Duration::from_secs(5);

/// Cap on concurrently served DNS-over-TCP connections.
///
/// Each accepted connection holds a task plus a netstack TCP socket. Bound them the same way
/// [`crate::peerapi`] bounds its request handlers: take a permit before spawning and drop the
/// connection fail-closed when saturated. Dropping a DNS connection is benign — the stub resolver
/// retries — and the alternative is letting a local client open sockets without limit.
const MAX_INFLIGHT_CONNS: usize = 64;

/// Accept and serve DNS-over-TCP connections on `listener` until it goes away.
///
/// `listener` belongs to the netstack that owns the service IP (the service netstack, in TUN mode),
/// while `forward_channel` is the **overlay** netstack a forwarded query egresses over. They are
/// different stacks on purpose: the client reaches us over the host's TUN, but an off-tailnet name
/// must be resolved through the tunnel, never from a host socket.
///
/// The caller binds the listener so that it exists before any packet is pumped in; if binding fails
/// this server is simply never started, and the caller stops classifying quad-100 TCP/53 as ours —
/// so it behaves exactly as every other unserved quad-100 port does and is answered with a RST
/// (`tun_actor::classify_service_ip` with `serve_dns_tcp` clear). The failure is never a silent
/// drop: an unanswered SYN is worse than a refused one.
pub(crate) async fn serve(
    listener: TcpListener,
    view_rx: watch::Receiver<Arc<DnsView>>,
    forward_channel: Channel,
) {
    tracing::debug!(addr = %listener.local_addr(), "magic dns tcp accepting");

    let inflight = Arc::new(Semaphore::new(MAX_INFLIGHT_CONNS));

    loop {
        let stream = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "magic dns tcp accept failed, stopping server");
                return;
            }
        };

        let Ok(permit) = inflight.clone().try_acquire_owned() else {
            tracing::warn!(
                client = %stream.remote_addr(),
                "magic dns tcp drop: at max in-flight connections ({MAX_INFLIGHT_CONNS})"
            );
            // Dropping `stream` closes the connection; the stub resolver retries.
            continue;
        };

        let view_rx = view_rx.clone();
        let forward_channel = forward_channel.clone();
        tokio::spawn(async move {
            let _permit = permit;
            serve_conn(stream, view_rx, forward_channel).await;
        });
    }
}

/// Serve length-prefixed DNS queries on one connection until the client closes it, a timeout
/// fires, or the framing goes wrong.
///
/// Generic over the stream so the loop that actually ships — framing, ordering, the malformed-query
/// disposition — is the one exercised by tests, without standing up a netstack.
///
/// Every exit is a plain close, never a reply: a client that sent something we cannot frame or
/// cannot parse gets nothing, matching the UDP responder's "malformed query => dropped" rule. There
/// is no shared datagram socket to protect here, so [`answer_query`] is awaited inline — a slow
/// upstream stalls only the connection that asked.
async fn serve_conn<S>(mut stream: S, view_rx: watch::Receiver<Arc<DnsView>>, channel: Channel)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        // The two-byte big-endian message length (RFC 1035 §4.2.2). A read error here is the
        // ordinary end of a connection: the client sent its FIN.
        let mut len_buf = [0u8; 2];
        match timeout(IDLE_TIMEOUT, stream.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => return,
            Err(_) => {
                tracing::debug!("magic dns tcp: idle connection closed");
                return;
            }
        }

        let len = usize::from(u16::from_be_bytes(len_buf));
        if len == 0 {
            // A zero-length message cannot hold even a DNS header. Nothing to answer, and the
            // stream is no longer trustworthy: close.
            tracing::debug!("magic dns tcp: zero-length message; closing");
            return;
        }
        // Bounded by construction: the length is a `u16`, so this allocates at most 64 KiB.
        let mut query = vec![0u8; len];
        match timeout(MESSAGE_TIMEOUT, stream.read_exact(&mut query)).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => return,
            Err(_) => {
                tracing::debug!(len, "magic dns tcp: message body stalled; closing");
                return;
            }
        }

        // Read the view fresh per query, exactly as the UDP responder does, and clone the `Arc` out
        // of the watch so no borrow guard is held across the forward's `await`.
        let view = view_rx.borrow().clone();
        let Some(response) = answer_query(&view, &channel, &query).await else {
            tracing::debug!("magic dns tcp: malformed query; closing");
            return;
        };

        // A response that cannot carry a length prefix cannot be sent at all. `decide` builds
        // authoritative answers well under this and a forwarded one is capped far below it, so this
        // is unreachable in practice — but truncating the *prefix* would frame the stream wrong for
        // every later query, so close instead.
        let Ok(response_len) = u16::try_from(response.len()) else {
            tracing::warn!(
                len = response.len(),
                "magic dns tcp: response too long to frame"
            );
            return;
        };
        // One write for the prefix and the message together, not two: RFC 7766 §8 asks for exactly
        // this, so the length does not go out as its own two-byte segment ahead of the body.
        let mut framed = Vec::with_capacity(2 + response.len());
        framed.extend_from_slice(&response_len.to_be_bytes());
        framed.extend_from_slice(&response);
        if stream.write_all(&framed).await.is_err() || stream.flush().await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use netstack::HasChannel;
    use ts_control::{DnsConfig, Node, StableNodeId, TailnetAddress};

    use super::*;
    use crate::peer_tracker::PeerDb;

    /// A peer named `host.user.ts.net` at `100.64.0.1`, so an `A` query for that name resolves
    /// authoritatively — no upstream, no forward.
    fn peer_node() -> Node {
        Node {
            id: 1,
            user_id: 0,
            stable_id: StableNodeId("n1".to_string()),
            hostname: "host".to_string(),
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
            node_key: [1u8; 32].into(),
            node_key_expiry: None,
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
            online: None,
            last_seen: None,
        }
    }

    /// A MagicDNS view that answers `host.user.ts.net` authoritatively and has **no** upstream
    /// resolvers, so nothing these tests ask can reach a forward.
    fn forwardless_view() -> DnsView {
        let mut db = PeerDb::default();
        db.upsert(&peer_node());

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

    /// A raw `IN A` query for `name` with the given transaction id.
    fn a_query(id: u16, name: &str) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes()); // flags: QR=0 (query)
        buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        for label in name.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0); // root label
        buf.extend_from_slice(&1u16.to_be_bytes()); // QTYPE: A
        buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS: IN
        buf
    }

    /// The RCODE of a response (the low nibble of the second flags byte).
    fn response_rcode(resp: &[u8]) -> u8 {
        resp[3] & 0x0F
    }

    /// Frame a DNS message the way a stub resolver does: two-byte big-endian length, then the
    /// message (RFC 1035 §4.2.2).
    fn framed(msg: &[u8]) -> Vec<u8> {
        let len = u16::try_from(msg.len()).expect("test message fits a length prefix");
        let mut out = len.to_be_bytes().to_vec();
        out.extend_from_slice(msg);
        out
    }

    /// Drive [`serve_conn`] over an in-memory duplex, feeding it `queries` (already framed by the
    /// caller) and returning the framed messages it wrote back.
    ///
    /// The netstack `Channel` comes from a piped netstack that is never run: [`forwardless_view`]
    /// configures no upstreams, so every query these tests send resolves authoritatively and the
    /// channel is never touched.
    async fn framed_exchange(view: DnsView, queries: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let (netstack, _pipe) = netstack::piped(netstack::netcore::Config::default());
        let channel = netstack.command_channel();
        let (_view_tx, view_rx) = watch::channel(Arc::new(view));

        let (client, server) = tokio::io::duplex(64 * 1024);
        let served = tokio::spawn(serve_conn(server, view_rx, channel));

        let (mut read_half, mut write_half) = tokio::io::split(client);
        for q in queries {
            write_half.write_all(q).await.expect("write query");
        }
        write_half.shutdown().await.expect("half-close");

        // Read framed responses until the server closes its side.
        let mut out = Vec::new();
        loop {
            let mut len = [0u8; 2];
            if read_half.read_exact(&mut len).await.is_err() {
                break;
            }
            let mut body = vec![0u8; usize::from(u16::from_be_bytes(len))];
            if read_half.read_exact(&mut body).await.is_err() {
                break;
            }
            out.push(body);
        }
        served.await.expect("serve_conn must not panic");
        out
    }

    /// The retry a truncated UDP answer demands must be *answered*, not reset: a length-prefixed
    /// query for a tailnet name gets a length-prefixed NOERROR answer carrying the peer's address.
    #[tokio::test]
    async fn length_prefixed_query_is_answered() {
        let query = a_query(0x1234, "host.user.ts.net");
        let replies = framed_exchange(forwardless_view(), &[framed(&query)]).await;

        assert_eq!(replies.len(), 1, "exactly one framed answer");
        let reply = &replies[0];
        assert_eq!(
            reply[0..2],
            query[0..2],
            "the answer echoes the query's transaction id"
        );
        assert_eq!(
            response_rcode(reply),
            0,
            "an in-tailnet name resolves NOERROR over TCP just as it does over UDP"
        );
        assert_eq!(
            reply[2] & 0x02,
            0,
            "a TCP answer is never marked truncated: the client already did the TCP retry"
        );
        assert_eq!(
            u16::from_be_bytes([reply[6], reply[7]]),
            1,
            "the answer section carries the peer's address"
        );
        assert_eq!(
            &reply[reply.len() - 4..],
            &[100, 64, 0, 1],
            "and it is the peer's tailnet IPv4"
        );
    }

    /// The connection is reused: two queries pipelined into one stream get two answers, in order.
    #[tokio::test]
    async fn connection_serves_more_than_one_query() {
        let first = a_query(0x0001, "host.user.ts.net");
        let second = a_query(0x0002, "host.user.ts.net");
        let replies = framed_exchange(forwardless_view(), &[framed(&first), framed(&second)]).await;

        assert_eq!(replies.len(), 2, "both queries answered on one connection");
        assert_eq!(replies[0][0..2], first[0..2], "first answer, first");
        assert_eq!(replies[1][0..2], second[0..2], "second answer, second");
    }

    /// A message that announces a length and then holds bytes that are not a DNS query is dropped
    /// and the connection closed — the same disposition the UDP responder gives a malformed query,
    /// never a synthesized reply.
    #[tokio::test]
    async fn malformed_query_closes_without_answering() {
        let replies = framed_exchange(forwardless_view(), &[framed(&[0u8; 3])]).await;
        assert!(
            replies.is_empty(),
            "a malformed query is answered with nothing at all"
        );
    }

    /// A zero-length message is not a DNS message; it closes the connection instead of being
    /// treated as an empty query, and nothing after it on that stream is served.
    #[tokio::test]
    async fn zero_length_message_closes_the_connection() {
        let good = a_query(0x0003, "host.user.ts.net");
        let replies = framed_exchange(forwardless_view(), &[vec![0, 0], framed(&good)]).await;
        assert!(
            replies.is_empty(),
            "the zero-length prefix ends the connection before the following query is read"
        );
    }

    /// `--accept-dns` off is a refusal, not a hole: the TCP path runs the same `decide` gate the
    /// UDP path does, so the client gets a REFUSED answer rather than an unanswered connection.
    #[tokio::test]
    async fn accept_dns_off_refuses_over_tcp_too() {
        let mut view = forwardless_view();
        view.accept_dns = false;
        let replies = framed_exchange(view, &[framed(&a_query(0x0004, "host.user.ts.net"))]).await;

        assert_eq!(replies.len(), 1, "the refusal is still an answer");
        assert_eq!(response_rcode(&replies[0]), 5, "REFUSED");
    }
}
