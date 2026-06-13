//! Host-loopback SOCKS5 proxy that dials INTO the tailnet overlay (Go `tsnet.Server.Loopback`,
//! SOCKS5 half).
//!
//! This serves a SOCKS5 (RFC 1928) proxy with required username/password auth (RFC 1929) on a
//! `127.0.0.1` host-loopback address, so a non-Rust host process can reach tailnet peers through the
//! proxy. Every accepted `CONNECT` is dialed INTO the overlay via the device's netstack — never out a
//! host socket to the destination — so the host's real origin IP is never used to reach the target.
//!
//! The LocalAPI HTTP surface that Go also serves on the loopback is intentionally NOT provided here:
//! this fork exposes status/whois/id-token natively on [`crate::Device`], and Go itself recommends
//! the in-process client over the loopback LocalAPI. The listener therefore serves SOCKS5 directly,
//! with no SOCKS-vs-HTTP first-byte demux.

use std::{
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::AbortHandle,
};
use ts_netstack_smoltcp::{CreateSocket, netcore::Channel};

use crate::{Error, InternalErrorKind};

/// A cloneable, dep-free MagicDNS resolver: maps a name to a tailnet IPv4, or `None` if unresolved.
///
/// The concrete closure (built in [`crate::Device::loopback`]) captures clones of the device's
/// control + peer-tracker actor refs and replicates [`crate::Device::resolve`]. Boxing it here keeps
/// the kameo actor types out of this module so the `tailscale` crate needs no new dependency.
pub(crate) type Resolver = Arc<
    dyn Fn(String) -> Pin<Box<dyn Future<Output = Result<Option<Ipv4Addr>, Error>> + Send>>
        + Send
        + Sync,
>;

/// SOCKS protocol version (`0x05`).
const SOCKS5_VER: u8 = 0x05;
/// SOCKS5 auth method: username/password (RFC 1929).
const METHOD_USER_PASS: u8 = 0x02;
/// SOCKS5 "no acceptable methods" selector.
const METHOD_NONE: u8 = 0xFF;
/// RFC 1929 username/password sub-negotiation version.
const AUTH_VER: u8 = 0x01;
/// SOCKS5 CONNECT command.
const CMD_CONNECT: u8 = 0x01;
/// SOCKS5 address type: IPv4.
const ATYP_IPV4: u8 = 0x01;
/// SOCKS5 address type: domain name.
const ATYP_DOMAIN: u8 = 0x03;
/// SOCKS5 address type: IPv6.
const ATYP_IPV6: u8 = 0x04;
/// SOCKS5 reply: command not supported.
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
/// SOCKS5 reply: address type not supported.
const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;
/// Upper bound on the SOCKS5 negotiation (greeting + auth + request + overlay dial). A local client
/// that connects but stalls mid-handshake is dropped rather than parking a task forever. The splice
/// that follows has no deadline — a proxied connection is legitimately long-lived.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// The fixed SOCKS5 username this proxy requires (Go uses `tsnet`).
const PROXY_USERNAME: &str = "tsnet";

/// The dial target parsed out of a SOCKS5 CONNECT request, before any I/O is performed.
///
/// Either an explicit IPv4 overlay address (`ATYP=0x01`) or a MagicDNS name (`ATYP=0x03`) plus a
/// destination port. The pure [`parse_request`] helper produces this from a request byte buffer so
/// the ATYP/CMD branching is unit-testable without a socket.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    /// Dial an explicit overlay IPv4 address and port via `tcp_connect`.
    Ipv4(Ipv4Addr, u16),
    /// Resolve a MagicDNS name and port, then dial via `connect_by_name`.
    Domain(String, u16),
}

/// Parse a SOCKS5 request body `[VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT]` into a [`Target`].
///
/// On any unsupported command or address type, returns `Err(rep)` with the SOCKS5 reply code the
/// caller should send back before closing (`0x07` command-not-supported, `0x08`
/// address-type-not-supported). A malformed/short buffer or a non-`0x05` version also maps to a
/// reply code so the caller can respond rather than hang. IPv6 (`ATYP=0x04`) is refused — this fork
/// is IPv4-only on the tailnet.
fn parse_request(buf: &[u8]) -> Result<Target, u8> {
    // Need at least VER, CMD, RSV, ATYP.
    if buf.len() < 4 || buf[0] != SOCKS5_VER {
        return Err(REP_CMD_NOT_SUPPORTED);
    }
    if buf[1] != CMD_CONNECT {
        // BIND / UDP ASSOCIATE are not supported (TCP + IPv4 overlay only).
        return Err(REP_CMD_NOT_SUPPORTED);
    }
    let atyp = buf[3];
    match atyp {
        ATYP_IPV4 => {
            // 4 octets + 2-byte port.
            if buf.len() < 4 + 4 + 2 {
                return Err(REP_CMD_NOT_SUPPORTED);
            }
            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            Ok(Target::Ipv4(ip, port))
        }
        ATYP_DOMAIN => {
            // 1-byte length, that many name bytes, then a 2-byte port.
            if buf.len() < 5 {
                return Err(REP_CMD_NOT_SUPPORTED);
            }
            let len = buf[4] as usize;
            if buf.len() < 5 + len + 2 {
                return Err(REP_CMD_NOT_SUPPORTED);
            }
            let host = match std::str::from_utf8(&buf[5..5 + len]) {
                Ok(h) => h.to_owned(),
                Err(_) => return Err(REP_CMD_NOT_SUPPORTED),
            };
            let port = u16::from_be_bytes([buf[5 + len], buf[6 + len]]);
            Ok(Target::Domain(host, port))
        }
        ATYP_IPV6 => Err(REP_ATYP_NOT_SUPPORTED),
        _ => Err(REP_ATYP_NOT_SUPPORTED),
    }
}

/// Owned, cloneable dialer captured by the accept loop so it never holds `&Device`.
///
/// Holds only `Clone`/`Arc` pieces of the [`crate::Device`]: a clone of the netstack command
/// [`Channel`], the device's own overlay IPv4 (fetched once before spawning), and a boxed
/// [`Resolver`] closure. It replicates the small `Device::tcp_connect` logic so each spliced
/// connection egresses over the overlay only — no `&Device` ever escapes.
#[derive(Clone)]
pub(crate) struct OverlayDialer {
    channel: Channel,
    self_ipv4: Ipv4Addr,
    resolve: Resolver,
}

impl OverlayDialer {
    /// Dial an explicit overlay IPv4 address (the SOCKS5 `ATYP=IPv4` path).
    ///
    /// Mirrors [`crate::Device::tcp_connect`]: binds an ephemeral overlay source port on this
    /// device's own tailnet IPv4 and connects to `(addr, port)` over the netstack.
    async fn dial_ipv4(
        &self,
        addr: Ipv4Addr,
        port: u16,
    ) -> Result<crate::netstack::TcpStream, Error> {
        // TODO(npry): collision checking (matches Device::tcp_connect).
        let ephemeral_port = rand::random_range(49152..=u16::MAX);
        self.channel
            .tcp_connect((self.self_ipv4, ephemeral_port).into(), (addr, port).into())
            .await
            .map_err(Into::into)
    }

    /// Resolve a MagicDNS `name` to a tailnet IPv4 and dial it (the SOCKS5 `ATYP=DOMAINNAME` path).
    ///
    /// Mirrors [`crate::Device::connect_by_name`]: an in-process netmap lookup via the captured
    /// [`Resolver`], then a `tcp_connect` into the overlay. Returns
    /// [`InternalErrorKind::BadRequest`] if the name does not resolve.
    async fn dial_name(&self, name: &str, port: u16) -> Result<crate::netstack::TcpStream, Error> {
        let addr = (self.resolve)(name.to_string())
            .await?
            .ok_or(Error::Internal(InternalErrorKind::BadRequest))?;
        self.dial_ipv4(addr, port).await
    }

    /// Dial the parsed [`Target`] into the overlay.
    async fn dial(&self, target: &Target) -> Result<crate::netstack::TcpStream, Error> {
        match target {
            Target::Ipv4(addr, port) => self.dial_ipv4(*addr, *port).await,
            Target::Domain(host, port) => self.dial_name(host, *port).await,
        }
    }

    /// Dial a `host`/`port` into the overlay, where `host` is either an IPv4 literal or a MagicDNS
    /// name. The crate-visible entry point used by the `hyper` HTTP connector (which parses the
    /// request `Uri` into host + port); an IPv4 literal skips the resolver, a name goes through it.
    #[cfg(feature = "hyper")]
    pub(crate) async fn dial_host_port(
        &self,
        host: &str,
        port: u16,
    ) -> Result<crate::netstack::TcpStream, Error> {
        match host.parse::<Ipv4Addr>() {
            Ok(addr) => self.dial_ipv4(addr, port).await,
            Err(_) => self.dial_name(host, port).await,
        }
    }
}

/// RAII handle for a running loopback SOCKS5 proxy (mirrors `tsnet`'s loopback teardown).
///
/// Dropping the handle aborts the **accept loop** so no new connections are accepted; in-flight
/// spliced connections continue until they close on their own, which is acceptable (the proxy is
/// loopback-only and each connection already egresses over the overlay). Call [`Self::shutdown`] to
/// stop it explicitly, or just drop it.
///
/// Lifecycle: this handle is **not** tied to [`crate::Device`] shutdown. If the caller drops the
/// `Device` but keeps (or leaks) this handle, the accept loop and the bound `127.0.0.1` port stay
/// alive until the handle drops. Hold the handle for exactly as long as you want the proxy and drop
/// it (or call [`Self::shutdown`]) when done; do not let it outlive the `Device` it proxies into
/// (dialing into a shut-down device's overlay just fails).
#[must_use = "dropping the handle stops the loopback SOCKS5 proxy"]
pub struct LoopbackHandle {
    accept_task: AbortHandle,
}

impl LoopbackHandle {
    /// Explicitly stop the loopback SOCKS5 proxy now. Equivalent to dropping the handle.
    pub fn shutdown(self) {
        // Drop runs the abort.
    }
}

impl Drop for LoopbackHandle {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

impl OverlayDialer {
    /// Build the dialer from the cloneable pieces of a [`crate::Device`]: a clone of the netstack
    /// command [`Channel`], the device's own overlay IPv4, and a boxed [`Resolver`]. No `&Device` is
    /// retained.
    pub(crate) fn new(channel: Channel, self_ipv4: Ipv4Addr, resolve: Resolver) -> Self {
        Self {
            channel,
            self_ipv4,
            resolve,
        }
    }
}

/// Start the loopback SOCKS5 proxy. Called by [`crate::Device::loopback`].
///
/// Binds a TCP listener on `127.0.0.1:0` (host loopback only), generates a 32-char hex credential,
/// and spawns the accept loop. Returns the bound address, the credential, and the [`LoopbackHandle`].
pub(crate) async fn start(
    dialer: OverlayDialer,
) -> Result<(SocketAddr, String, LoopbackHandle), Error> {
    // Bind ONLY host loopback (127.0.0.1) — never 0.0.0.0 or any external interface. The proxy is
    // reachable solely from the local host, and every connection egresses over the overlay.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|_| Error::Internal(InternalErrorKind::Io))?;
    let local_addr = listener
        .local_addr()
        .map_err(|_| Error::Internal(InternalErrorKind::Io))?;

    let cred = gen_cred();
    let accept_cred = cred.clone();
    let task = tokio::spawn(async move {
        accept_loop(listener, dialer, accept_cred).await;
    });

    Ok((
        local_addr,
        cred,
        LoopbackHandle {
            accept_task: task.abort_handle(),
        },
    ))
}

/// Generate a 16-byte random credential rendered as 32 lowercase-hex chars (no new dependency).
fn gen_cred() -> String {
    let b: [u8; 16] = rand::random();
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Cap on simultaneous loopback SOCKS5 connections. This is a `127.0.0.1`-only debug/proxy
/// listener, but each accepted connection dials INTO the overlay and so pins one netstack TCP socket
/// (~512 KiB of rx+tx buffers, see `tcp_buffer_size` in AGENTS.md). 256 ≈ a 128 MB ceiling — enough
/// for any realistic local client, while preventing a misbehaving local process from opening
/// unbounded overlay sockets and exhausting memory. At the cap the accept loop back-pressures
/// (stops accepting) until an in-flight connection finishes, which is the desired behavior here.
const MAX_CONCURRENT_CONNS: usize = 256;

/// Accept loop: one task per connection, capped at [`MAX_CONCURRENT_CONNS`] in flight. Aborting this
/// task (via [`LoopbackHandle`]) stops accepting new connections; already-spawned connection tasks
/// keep running until they finish.
async fn accept_loop(listener: TcpListener, dialer: OverlayDialer, cred: String) {
    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNS));
    loop {
        // Acquire a permit BEFORE accepting so that at the cap the loop stops pulling new
        // connections off the listener until an in-flight one finishes (back-pressure).
        let permit = match sem.clone().acquire_owned().await {
            Ok(permit) => permit,
            // The semaphore is never closed in this loop; if it somehow is, stop accepting.
            Err(_) => return,
        };
        let (sock, _peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(error = %e, "loopback SOCKS5 accept failed; stopping accept loop");
                return;
            }
        };
        let dialer = dialer.clone();
        let cred = cred.clone();
        tokio::spawn(async move {
            // Hold the permit for the lifetime of the connection; dropping it on task end frees
            // the slot for the next accept.
            let _permit = permit;
            if let Err(e) = handle_conn(sock, dialer, cred).await {
                tracing::debug!(error = %e, "loopback SOCKS5 connection ended");
            }
        });
    }
}

/// Serve one SOCKS5 connection: negotiate (greeting, auth, CONNECT, overlay dial) under a bounded
/// timeout, then splice without a deadline.
///
/// The negotiation phase is wrapped in [`HANDSHAKE_TIMEOUT`] so a local client that connects but
/// never sends (or stalls mid-handshake) cannot park a task forever. The splice that follows has no
/// timeout on purpose — a proxied connection is legitimately long-lived.
async fn handle_conn(sock: TcpStream, dialer: OverlayDialer, cred: String) -> std::io::Result<()> {
    let negotiated =
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, negotiate(sock, dialer, cred)).await {
            Ok(res) => res?,
            Err(_elapsed) => {
                tracing::debug!("loopback SOCKS5 handshake timed out");
                return Ok(());
            }
        };
    // `None` means the handshake completed but the connection was rejected/closed (bad method, auth
    // failure, unsupported request, or dial failure) — nothing left to splice.
    let Some((mut sock, mut overlay)) = negotiated else {
        return Ok(());
    };

    // Splice host socket <-> overlay stream (no deadline — proxied connections are long-lived).
    match tokio::io::copy_bidirectional(&mut sock, &mut overlay).await {
        Ok((to_overlay, to_host)) => {
            tracing::debug!(to_overlay, to_host, "loopback SOCKS5 splice finished");
        }
        Err(e) => {
            tracing::debug!(error = %e, "loopback SOCKS5 splice ended");
        }
    }
    Ok(())
}

/// Negotiate one SOCKS5 connection up to (and including) the overlay dial. Returns
/// `Ok(Some((client_socket, overlay_stream)))` ready to splice on success, or `Ok(None)` when the
/// connection was cleanly rejected/closed during negotiation (bad version/method, auth failure,
/// unsupported command/address type, or a dial failure — each already replied to the client).
async fn negotiate(
    mut sock: TcpStream,
    dialer: OverlayDialer,
    cred: String,
) -> std::io::Result<Option<(TcpStream, crate::netstack::TcpStream)>> {
    // 1) Greeting: [VER, NMETHODS, METHODS...].
    let mut head = [0u8; 2];
    sock.read_exact(&mut head).await?;
    if head[0] != SOCKS5_VER {
        return Ok(None);
    }
    let nmethods = head[1] as usize;
    let mut methods = vec![0u8; nmethods];
    sock.read_exact(&mut methods).await?;
    if !methods.contains(&METHOD_USER_PASS) {
        // No acceptable methods — we require username/password.
        sock.write_all(&[SOCKS5_VER, METHOD_NONE]).await?;
        return Ok(None);
    }
    sock.write_all(&[SOCKS5_VER, METHOD_USER_PASS]).await?;

    // 2) RFC 1929 auth: [VER=0x01, ULEN, UNAME, PLEN, PASSWD].
    let mut avh = [0u8; 2];
    sock.read_exact(&mut avh).await?;
    if avh[0] != AUTH_VER {
        return Ok(None);
    }
    let ulen = avh[1] as usize;
    let mut uname = vec![0u8; ulen];
    sock.read_exact(&mut uname).await?;
    let mut plh = [0u8; 1];
    sock.read_exact(&mut plh).await?;
    let plen = plh[0] as usize;
    let mut passwd = vec![0u8; plen];
    sock.read_exact(&mut passwd).await?;

    let ok = uname.as_slice() == PROXY_USERNAME.as_bytes() && passwd.as_slice() == cred.as_bytes();
    if !ok {
        sock.write_all(&[AUTH_VER, 0x01]).await?; // auth failure
        return Ok(None);
    }
    sock.write_all(&[AUTH_VER, 0x00]).await?; // auth success

    // 3) Request: [VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT].
    let mut rh = [0u8; 4];
    sock.read_exact(&mut rh).await?;
    // Read the variable address + port into a single buffer so `parse_request` sees the full body.
    let mut req = rh.to_vec();
    match rh[3] {
        ATYP_IPV4 => {
            let mut rest = [0u8; 4 + 2];
            sock.read_exact(&mut rest).await?;
            req.extend_from_slice(&rest);
        }
        ATYP_DOMAIN => {
            let mut lb = [0u8; 1];
            sock.read_exact(&mut lb).await?;
            let len = lb[0] as usize;
            let mut rest = vec![0u8; len + 2];
            sock.read_exact(&mut rest).await?;
            req.push(lb[0]);
            req.extend_from_slice(&rest);
        }
        ATYP_IPV6 => {
            // Drain the 16-byte address + port so the peer isn't left mid-write, then refuse.
            let mut rest = [0u8; 16 + 2];
            drop(sock.read_exact(&mut rest).await);
            reply_failure(&mut sock, REP_ATYP_NOT_SUPPORTED).await?;
            return Ok(None);
        }
        _ => {
            reply_failure(&mut sock, REP_ATYP_NOT_SUPPORTED).await?;
            return Ok(None);
        }
    }

    let target = match parse_request(&req) {
        Ok(t) => t,
        Err(rep) => {
            reply_failure(&mut sock, rep).await?;
            return Ok(None);
        }
    };

    // 4) Dial INTO the overlay (never a host socket to the destination).
    let overlay = match dialer.dial(&target).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(?target, error = ?e, "loopback SOCKS5 overlay dial failed");
            reply_failure(&mut sock, 0x05).await?; // connection refused
            return Ok(None);
        }
    };

    // Success reply: REP=0x00, ATYP=IPv4, bound addr 0.0.0.0:0 (conventional placeholder).
    sock.write_all(&[SOCKS5_VER, 0x00, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await?;

    Ok(Some((sock, overlay)))
}

/// Send a SOCKS5 failure reply with code `rep` (ATYP=IPv4, bound addr 0.0.0.0:0) and return.
async fn reply_failure(sock: &mut TcpStream, rep: u8) -> std::io::Result<()> {
    sock.write_all(&[SOCKS5_VER, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_request_ipv4() {
        // CONNECT to 100.64.0.5:8080 (0x1f90).
        let buf = [0x05, 0x01, 0x00, 0x01, 100, 64, 0, 5, 0x1f, 0x90];
        let t = parse_request(&buf).expect("ipv4 target");
        assert_eq!(t, Target::Ipv4(Ipv4Addr::new(100, 64, 0, 5), 8080));
    }

    #[test]
    fn parse_request_domain() {
        // 9-byte name "peer.host", port 443 (0x01bb).
        let mut buf = vec![0x05, 0x01, 0x00, 0x03, 0x09];
        buf.extend_from_slice(b"peer.host");
        buf.extend_from_slice(&443u16.to_be_bytes());
        let t = parse_request(&buf).expect("domain target");
        assert_eq!(t, Target::Domain("peer.host".to_string(), 443));
    }

    #[test]
    fn parse_request_ipv6_refused() {
        // ATYP=0x04 (IPv6) -> address type not supported.
        let mut buf = vec![0x05, 0x01, 0x00, 0x04];
        buf.extend_from_slice(&[0u8; 16]); // address
        buf.extend_from_slice(&443u16.to_be_bytes());
        let rep = parse_request(&buf).expect_err("ipv6 refused");
        assert_eq!(rep, REP_ATYP_NOT_SUPPORTED);
    }

    #[test]
    fn parse_request_bad_cmd() {
        // CMD=0x03 (UDP ASSOCIATE) -> command not supported.
        let buf = [0x05, 0x03, 0x00, 0x01, 100, 64, 0, 5, 0x1f, 0x90];
        let rep = parse_request(&buf).expect_err("bad cmd refused");
        assert_eq!(rep, REP_CMD_NOT_SUPPORTED);
    }

    #[test]
    fn hex_cred_len() {
        let cred = gen_cred();
        assert_eq!(cred.len(), 32);
        assert!(
            cred.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    // NOTE: a full end-to-end test (real SOCKS5 client through the proxy into a tailnet peer) needs
    // a live overlay/netstack to dial; stubbing `OverlayDialer` would require generalizing the dial
    // path over a trait purely for the test. We rely instead on the pure `parse_request` tests above
    // plus the byte-layout reasoning in `handle_conn`.
}
