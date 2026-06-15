//! The single anti-leak chokepoint: where overlay flows become real OS sockets.

use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use crate::class::FlowClass;

/// Wall-clock cap on a single proxy handshake (connect + SOCKS5/HTTP-CONNECT round-trips).
///
/// Defense-in-depth: the forwarder's dial call site already wraps `dial_tcp` in its own timeout,
/// but this dialer is the anti-leak chokepoint and must be self-protecting regardless of caller —
/// a slow/malicious proxy that trickles bytes (slowloris) must not hang the dial indefinitely. On
/// elapse we fail closed ([`DialError::ProxyHandshake`]); we never fall back to a direct dial.
const PROXY_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Errors from dialing a real OS socket for an inbound overlay flow.
#[derive(Debug, thiserror::Error)]
pub enum DialError {
    /// Exit-node egress was requested but this dialer refuses it (anti-leak).
    ///
    /// Egressing a peer's traffic via our real IP is only allowed through an explicit exit
    /// dialer wired in deliberately; the default [`DirectDialer`] refuses it structurally.
    #[error("exit-node egress refused: no exit dialer configured (anti-leak)")]
    ExitEgressRefused,

    /// The destination was not covered by any advertised route.
    #[error("destination not advertised")]
    NotAdvertised,

    /// UDP egress was requested through an upstream proxy that cannot tunnel UDP (anti-leak).
    ///
    /// HTTP CONNECT cannot carry UDP at all, and SOCKS5 UDP-ASSOCIATE is not implemented here.
    /// We refuse rather than fall back to a direct host-IP UDP dial: a direct dial would leak
    /// this node's real origin IP, which is exactly what routing through the proxy exists to
    /// prevent. Fail closed.
    #[error("UDP egress unsupported through upstream proxy (anti-leak): no direct fallback")]
    ProxyUdpUnsupported,

    /// The upstream proxy rejected or mishandled the handshake (anti-leak).
    ///
    /// Any failure to establish the tunnel to `dst` is surfaced here; we never fall back to a
    /// direct host-IP dial, because that would leak the real origin IP.
    #[error("upstream proxy handshake failed: {0} (anti-leak: no direct fallback)")]
    ProxyHandshake(String),

    /// Underlying OS socket error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// A real-OS UDP socket connected to the flow's destination, plus the source address that
/// reply datagrams must be spoofed from.
pub struct DialedUdp {
    /// A real UDP socket, bound to `0.0.0.0:0` and connected to the destination.
    pub sock: tokio::net::UdpSocket,
    /// The source address to spoof on replies: the original overlay destination the peer
    /// expected to talk to.
    pub spoof_src: IpAddr,
}

/// Turns an inbound overlay flow into a real OS socket.
///
/// This trait is THE anti-leak chokepoint: every overlay flow becomes a real socket here and
/// only here, so the policy about which flows are allowed to egress (and via what source IP)
/// lives in exactly one place.
pub trait RealDialer: Send + Sync + 'static {
    /// Dial a real TCP socket to `dst` (the original overlay destination).
    fn dial_tcp(
        &self,
        class: FlowClass,
        dst: SocketAddr,
    ) -> impl Future<Output = Result<tokio::net::TcpStream, DialError>> + Send;

    /// Dial a real UDP socket connected to `dst` (the original overlay destination).
    fn dial_udp(
        &self,
        class: FlowClass,
        dst: SocketAddr,
    ) -> impl Future<Output = Result<DialedUdp, DialError>> + Send;
}

/// Dials real OS sockets bound to `0.0.0.0:0` for subnet routes; refuses exit-node egress.
///
/// The exit-node refusal is structural, not a runtime flag: there is no field, constructor
/// argument, or setter that can enable exit egress here. Egressing a peer's traffic via our
/// real IP requires substituting a *different* [`RealDialer`] implementation (e.g. a proxy
/// dialer), which is an explicit, auditable act. This makes "no silent direct-dial of exit
/// traffic via our real IP" a type-level fact.
#[derive(Clone, Copy, Debug, Default)]
pub struct DirectDialer;

impl RealDialer for DirectDialer {
    async fn dial_tcp(
        &self,
        class: FlowClass,
        dst: SocketAddr,
    ) -> Result<tokio::net::TcpStream, DialError> {
        match class {
            FlowClass::Subnet => {
                // Explicit IPv4 bind to 0.0.0.0:0 (never ::, IPv6 is disabled everywhere).
                let sock = tokio::net::TcpSocket::new_v4()?;
                sock.bind(unspecified_v4())?;
                Ok(sock.connect(dst).await?)
            }
            FlowClass::ExitNode => Err(DialError::ExitEgressRefused),
        }
    }

    async fn dial_udp(&self, class: FlowClass, dst: SocketAddr) -> Result<DialedUdp, DialError> {
        match class {
            FlowClass::Subnet => {
                let sock = tokio::net::UdpSocket::bind(unspecified_v4()).await?;
                sock.connect(dst).await?;
                Ok(DialedUdp {
                    sock,
                    spoof_src: dst.ip(),
                })
            }
            FlowClass::ExitNode => Err(DialError::ExitEgressRefused),
        }
    }
}

/// Dials real OS sockets bound to `0.0.0.0:0` for **both** subnet routes and exit-node egress.
///
/// # Leak surface — read before using
///
/// Unlike [`DirectDialer`], this dialer egresses exit-node (`0.0.0.0/0`) flows: a peer's
/// internet-bound traffic leaves through **this host's real origin IP**. That is the entire point
/// of being an exit node, and it is exactly the behavior the anti-leak posture forbids by default.
/// Using this type is therefore an explicit, auditable opt-in: only wire it on a node whose real IP
/// *is* the intended egress (e.g. a residential exit), never on a node whose host IP must stay
/// hidden (e.g. a cloud VPS). It does not route through any proxy; egress follows the host's own
/// routing table. Proxy/residential egress via a separate source is a different [`RealDialer`]
/// implementation, layered on top, out of scope here.
///
/// Subnet routes are dialed identically to [`DirectDialer`].
#[derive(Clone, Copy, Debug, Default)]
pub struct HostExitDialer;

impl RealDialer for HostExitDialer {
    async fn dial_tcp(
        &self,
        _class: FlowClass,
        dst: SocketAddr,
    ) -> Result<tokio::net::TcpStream, DialError> {
        // Both Subnet and ExitNode egress via the host's IPv4 socket. The class is irrelevant to
        // the mechanism here; the *decision* to permit exit egress was made by choosing this dialer.
        let sock = tokio::net::TcpSocket::new_v4()?;
        sock.bind(unspecified_v4())?;
        Ok(sock.connect(dst).await?)
    }

    async fn dial_udp(&self, _class: FlowClass, dst: SocketAddr) -> Result<DialedUdp, DialError> {
        let sock = tokio::net::UdpSocket::bind(unspecified_v4()).await?;
        sock.connect(dst).await?;
        Ok(DialedUdp {
            sock,
            spoof_src: dst.ip(),
        })
    }
}

/// Which upstream proxy wire protocol to speak during the handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyScheme {
    /// SOCKS5 (RFC 1928), with optional username/password auth (RFC 1929).
    Socks5,
    /// HTTP `CONNECT` tunnelling, with optional `Proxy-Authorization: Basic` auth.
    HttpConnect,
}

/// Configuration for an upstream proxy the [`ProxyExitDialer`] tunnels through.
#[derive(Clone)]
pub struct ProxyConfig {
    /// Address of the upstream proxy to connect to (e.g. a residential proxy endpoint).
    pub addr: SocketAddr,
    /// Wire protocol to speak to the proxy.
    pub scheme: ProxyScheme,
    /// Optional `(username, password)` credentials for proxy auth.
    pub auth: Option<(String, String)>,
}

// Manual Debug that NEVER prints the proxy credentials. `ProxyConfig` is `pub` (re-exported from
// the crate root), so a stray `tracing!(?cfg)`, `{:?}`, panic message, or test assertion must not
// be able to leak the residential-proxy username/password into logs or traces. The derived
// Debug would print `auth: Some(("user", "pass"))` verbatim; this elides it to `<redacted>`.
impl core::fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("addr", &self.addr)
            .field("scheme", &self.scheme)
            .field("auth", &self.auth.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Dials destinations **through an upstream proxy**, so egress leaves via the proxy's IP rather
/// than this host's real origin IP.
///
/// # Why this exists
///
/// On a cloud exit node whose own IP must stay hidden, [`HostExitDialer`] would leak the host's
/// real IP. This dialer instead opens a TCP connection to the configured upstream proxy and
/// performs a SOCKS5 or HTTP `CONNECT` handshake to `dst`; the returned [`tokio::net::TcpStream`]
/// is the established tunnel, carrying raw bytes to `dst` exactly like a direct stream.
///
/// # Anti-leak posture (sacred)
///
/// On *any* proxy connect or handshake failure, this dialer returns `Err` — it never falls back
/// to a direct host-IP dial, because that would leak the real origin IP. UDP is refused for the
/// same reason ([`DialError::ProxyUdpUnsupported`]): HTTP CONNECT cannot carry UDP and SOCKS5
/// UDP-ASSOCIATE is not implemented, and we will not silently direct-dial UDP.
///
/// The handshake to the proxy is plaintext and needs no TLS, so this type adds no native-TLS
/// dependency.
#[derive(Clone, Debug)]
pub struct ProxyExitDialer {
    config: ProxyConfig,
}

impl ProxyExitDialer {
    /// Build a proxy dialer from an upstream proxy configuration.
    pub fn new(config: ProxyConfig) -> Self {
        Self { config }
    }

    /// Connect to the upstream proxy and tunnel to `dst`, returning the established stream.
    ///
    /// The whole handshake is bounded by [`PROXY_HANDSHAKE_TIMEOUT`] so a slow/malicious proxy
    /// cannot hang the dial; on timeout we fail closed rather than dial direct.
    async fn connect_through_proxy(
        &self,
        dst: SocketAddr,
    ) -> Result<tokio::net::TcpStream, DialError> {
        let handshake = async {
            // Connect to the proxy from an explicit IPv4 socket (never ::, IPv6 is disabled).
            let proxy_sock = tokio::net::TcpSocket::new_v4()?;
            proxy_sock.bind(unspecified_v4())?;
            let mut stream = proxy_sock.connect(self.config.addr).await?;

            match self.config.scheme {
                ProxyScheme::Socks5 => {
                    socks5_handshake(&mut stream, dst, &self.config.auth).await?
                }
                ProxyScheme::HttpConnect => {
                    http_connect_handshake(&mut stream, dst, &self.config.auth).await?
                }
            }
            Ok(stream)
        };

        match tokio::time::timeout(PROXY_HANDSHAKE_TIMEOUT, handshake).await {
            Ok(result) => result,
            Err(_elapsed) => Err(DialError::ProxyHandshake(format!(
                "proxy handshake timed out after {PROXY_HANDSHAKE_TIMEOUT:?}"
            ))),
        }
    }
}

/// Reject destinations that must never be reached through an exit-node egress: a peer could
/// otherwise drive this node to CONNECT the upstream proxy to loopback, link-local (incl. cloud
/// metadata `169.254.169.254`), or RFC1918 hosts on the proxy's side. Subnet routes legitimately
/// target private ranges (that *is* the subnet being routed), so this guard applies only to
/// exit-node flows. IPv6 is rejected wholesale elsewhere (IPv6-off posture).
///
/// In addition to loopback/private/link-local/unspecified, this also rejects:
/// - **CGNAT / shared `100.64.0.0/10` (RFC 6598)** — this is the Tailscale address range itself.
///   Without this, a malicious peer could aim an exit CONNECT at another tailnet node's `100.x`
///   address and reach internal tailnet hosts via the residential proxy.
/// - **Broadcast `255.255.255.255`** — never a legitimate egress target.
/// - **"This network" `0.0.0.0/8` (RFC 791)** — covers `0.0.0.0/8`, of which `0.0.0.0` (the
///   unspecified address) is one; the explicit `is_unspecified` check above is kept for clarity.
fn exit_dst_is_forbidden(dst: SocketAddr) -> bool {
    match dst.ip() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            // CGNAT / shared 100.64.0.0/10 (RFC 6598): the Tailscale range itself.
            let is_cgnat = o[0] == 100 && (o[1] & 0xc0) == 0x40;
            // "This network" 0.0.0.0/8 (RFC 791); includes the unspecified address.
            let is_this_network = o[0] == 0;
            // Class-E reserved 240.0.0.0/4 (RFC 1112). `Ipv4Addr::is_reserved` is nightly-only, so
            // check the octet; the all-ones broadcast 255.255.255.255 is already caught above.
            let is_class_e = o[0] >= 240;
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                // Multicast 224.0.0.0/4 (RFC 5771) — incl. link-local multicast and SSDP
                // 239.255.255.250; never a valid unicast exit destination.
                || v4.is_multicast()
                || is_cgnat
                || is_this_network
                || is_class_e
        }
        // Exit egress is IPv4-only; any v6 dst is forbidden (and refused again in the handshake).
        IpAddr::V6(_) => true,
    }
}

impl RealDialer for ProxyExitDialer {
    async fn dial_tcp(
        &self,
        class: FlowClass,
        dst: SocketAddr,
    ) -> Result<tokio::net::TcpStream, DialError> {
        // Both Subnet and ExitNode flows tunnel through the upstream proxy; choosing this dialer
        // is the explicit decision to route all egress via the proxy's IP. SSRF guard: an
        // exit-node flow must not be aimed at the proxy's own private/loopback/metadata network.
        if class == FlowClass::ExitNode && exit_dst_is_forbidden(dst) {
            tracing::warn!(%dst, "proxy exit dial refused: forbidden exit destination (SSRF guard)");
            return Err(DialError::ProxyHandshake(
                "exit destination forbidden (loopback/private/link-local)".to_owned(),
            ));
        }

        match self.connect_through_proxy(dst).await {
            Ok(stream) => {
                // No auth/credentials in the log line — only the scheme and destination.
                tracing::debug!(%dst, scheme = ?self.config.scheme, "proxy tunnel established");
                Ok(stream)
            }
            Err(e) => {
                tracing::warn!(%dst, scheme = ?self.config.scheme, error = %e, "proxy dial failed (fail-closed, no direct fallback)");
                Err(e)
            }
        }
    }

    async fn dial_udp(&self, _class: FlowClass, dst: SocketAddr) -> Result<DialedUdp, DialError> {
        // Fail closed: no UDP tunnelling is implemented, and a direct UDP dial would leak the
        // real origin IP. See [`DialError::ProxyUdpUnsupported`].
        tracing::debug!(%dst, "proxy UDP dial refused (anti-leak): no UDP tunnel, no direct fallback");
        Err(DialError::ProxyUdpUnsupported)
    }
}

/// Perform a SOCKS5 (RFC 1928) handshake over `stream`, requesting a CONNECT tunnel to `dst`.
///
/// Sends the method greeting (optionally offering username/password per RFC 1929), runs the
/// auth sub-negotiation if the proxy selects it, then issues the CONNECT command and validates
/// the reply. Returns `Err(ProxyHandshake)` on any protocol violation or non-success reply.
async fn socks5_handshake(
    stream: &mut tokio::net::TcpStream,
    dst: SocketAddr,
    auth: &Option<(String, String)>,
) -> Result<(), DialError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const VER: u8 = 0x05;
    const NO_AUTH: u8 = 0x00;
    const USER_PASS: u8 = 0x02;

    // Greeting: offer no-auth, plus user/pass when credentials are configured.
    if auth.is_some() {
        stream.write_all(&[VER, 2, NO_AUTH, USER_PASS]).await?;
    } else {
        stream.write_all(&[VER, 1, NO_AUTH]).await?;
    }

    let mut sel = [0u8; 2];
    stream.read_exact(&mut sel).await?;
    if sel[0] != VER {
        return Err(DialError::ProxyHandshake(format!(
            "socks5: bad version byte 0x{:02x} in method reply",
            sel[0]
        )));
    }
    match sel[1] {
        NO_AUTH => {}
        USER_PASS => {
            let (user, pass) = auth.as_ref().ok_or_else(|| {
                DialError::ProxyHandshake(
                    "socks5: proxy demanded user/pass auth but none configured".to_owned(),
                )
            })?;
            socks5_userpass_auth(stream, user, pass).await?;
        }
        other => {
            return Err(DialError::ProxyHandshake(format!(
                "socks5: proxy selected unsupported auth method 0x{other:02x}"
            )));
        }
    }

    // CONNECT request. dst is always IPv4 here (IPv6 is disabled everywhere).
    let ip = match dst.ip() {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => {
            return Err(DialError::ProxyHandshake(
                "socks5: IPv6 destination refused (IPv6 disabled)".to_owned(),
            ));
        }
    };
    let port = dst.port();
    let mut req = Vec::with_capacity(10);
    req.extend_from_slice(&[VER, 0x01, 0x00, 0x01]); // CONNECT, reserved, ATYP=IPv4
    req.extend_from_slice(&ip.octets());
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).await?;

    // Reply header: VER REP RSV ATYP, then a bound address we discard.
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != VER {
        return Err(DialError::ProxyHandshake(format!(
            "socks5: bad version byte 0x{:02x} in connect reply",
            head[0]
        )));
    }
    if head[1] != 0x00 {
        return Err(DialError::ProxyHandshake(format!(
            "socks5: connect rejected with reply code 0x{:02x}",
            head[1]
        )));
    }
    // We only ever CONNECT to IPv4 destinations (IPv6-off), so the only bound-address type we
    // expect back is IPv4. Reject anything else as a protocol violation rather than carrying dead
    // IPv6/domain parsing branches that this egress path can never legitimately produce.
    if head[3] != 0x01 {
        return Err(DialError::ProxyHandshake(format!(
            "socks5: unexpected bound-address type 0x{:02x} in reply (IPv4-only egress)",
            head[3]
        )));
    }
    let mut discard = [0u8; 4 + 2]; // IPv4 address + 2-byte port
    stream.read_exact(&mut discard).await?;
    Ok(())
}

/// RFC 1929 username/password sub-negotiation.
async fn socks5_userpass_auth(
    stream: &mut tokio::net::TcpStream,
    user: &str,
    pass: &str,
) -> Result<(), DialError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    if user.len() > 255 || pass.len() > 255 {
        return Err(DialError::ProxyHandshake(
            "socks5: username or password exceeds 255 bytes".to_owned(),
        ));
    }
    let mut msg = Vec::with_capacity(3 + user.len() + pass.len());
    msg.push(0x01); // auth sub-negotiation version
    msg.push(user.len() as u8);
    msg.extend_from_slice(user.as_bytes());
    msg.push(pass.len() as u8);
    msg.extend_from_slice(pass.as_bytes());
    stream.write_all(&msg).await?;

    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply[1] != 0x00 {
        return Err(DialError::ProxyHandshake(format!(
            "socks5: user/pass auth rejected with status 0x{:02x}",
            reply[1]
        )));
    }
    Ok(())
}

/// Perform an HTTP `CONNECT` handshake over `stream`, tunnelling to `dst`.
///
/// Sends `CONNECT host:port HTTP/1.1` with a `Host` header (and optional `Proxy-Authorization:
/// Basic`), then reads the response head up to `\r\n\r\n` and requires a `200` status. Returns
/// `Err(ProxyHandshake)` on any non-2xx status or malformed response.
async fn http_connect_handshake(
    stream: &mut tokio::net::TcpStream,
    dst: SocketAddr,
    auth: &Option<(String, String)>,
) -> Result<(), DialError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let target = dst.to_string();
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some((user, pass)) = auth {
        let creds = base64_encode(format!("{user}:{pass}").as_bytes());
        req.push_str(&format!("Proxy-Authorization: Basic {creds}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;

    // Read the response headers until the terminating CRLF CRLF. Cap to avoid unbounded reads.
    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(DialError::ProxyHandshake(
                "http connect: proxy closed connection before response".to_owned(),
            ));
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8192 {
            return Err(DialError::ProxyHandshake(
                "http connect: response headers exceeded 8 KiB".to_owned(),
            ));
        }
    }

    // Status line: "HTTP/1.1 2xx ...". RFC 7231 §4.3.6 allows any 2xx for a successful CONNECT.
    let head = String::from_utf8_lossy(&buf);
    let status_line = head.lines().next().unwrap_or_default();
    let code = status_line.split_whitespace().nth(1).unwrap_or_default();
    let is_2xx =
        code.len() == 3 && code.starts_with('2') && code.bytes().all(|b| b.is_ascii_digit());
    if !is_2xx {
        return Err(DialError::ProxyHandshake(format!(
            "http connect: proxy returned status line {status_line:?}"
        )));
    }
    Ok(())
}

/// Standard base64 encoding (RFC 4648) for the `Proxy-Authorization: Basic` credential.
///
/// Hand-rolled to avoid adding a dependency; the input is only small credential strings.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        // `chunks(3)` never yields an empty slice, but index symmetrically with b1/b2 so a future
        // refactor of the chunk size can't turn this into a panic.
        let b0 = *chunk.first().unwrap_or(&0) as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(n >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

/// `0.0.0.0:0` — the IPv4 wildcard bind address. Never `::`, IPv6 is disabled everywhere.
fn unspecified_v4() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn direct_dialer_refuses_exit_node_tcp() {
        let dst = "1.2.3.4:80".parse().unwrap();
        let err = DirectDialer.dial_tcp(FlowClass::ExitNode, dst).await;
        assert!(matches!(err, Err(DialError::ExitEgressRefused)));
    }

    #[tokio::test]
    async fn direct_dialer_refuses_exit_node_udp() {
        let dst = "1.2.3.4:53".parse().unwrap();
        let err = DirectDialer.dial_udp(FlowClass::ExitNode, dst).await;
        assert!(matches!(err, Err(DialError::ExitEgressRefused)));
    }

    /// The opt-in exit dialer must accept an exit-node TCP flow where [`DirectDialer`] structurally
    /// refuses it. We dial a real loopback listener so the connect actually completes — proving the
    /// egress is performed, not refused.
    #[tokio::test]
    async fn host_exit_dialer_egresses_exit_node_tcp() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dst = listener.local_addr().unwrap();

        let stream = HostExitDialer
            .dial_tcp(FlowClass::ExitNode, dst)
            .await
            .expect("host exit dialer should egress exit-node TCP");
        assert_eq!(stream.peer_addr().unwrap(), dst);
    }

    /// The opt-in exit dialer also egresses subnet flows, identically to [`DirectDialer`].
    #[tokio::test]
    async fn host_exit_dialer_egresses_subnet_tcp() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dst = listener.local_addr().unwrap();

        let stream = HostExitDialer
            .dial_tcp(FlowClass::Subnet, dst)
            .await
            .expect("host exit dialer should egress subnet TCP");
        assert_eq!(stream.peer_addr().unwrap(), dst);
    }

    /// The opt-in exit dialer egresses exit-node UDP, spoofing replies from the dialed destination.
    #[tokio::test]
    async fn host_exit_dialer_egresses_exit_node_udp() {
        let dst = "127.0.0.1:53".parse().unwrap();
        let dialed = HostExitDialer
            .dial_udp(FlowClass::ExitNode, dst)
            .await
            .expect("host exit dialer should egress exit-node UDP");
        assert_eq!(dialed.spoof_src, dst.ip());
    }

    // ---- ProxyExitDialer ----

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    /// A loopback echo server: reads one chunk and writes it straight back. Acts as `dst`.
    async fn spawn_echo() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(&buf[..n]).await.unwrap();
        });
        addr
    }

    /// Pipe bytes both directions between two streams until either side closes.
    async fn splice(a: TcpStream, b: TcpStream) {
        let (mut ar, mut aw) = a.into_split();
        let (mut br, mut bw) = b.into_split();
        let f = tokio::io::copy(&mut ar, &mut bw);
        let g = tokio::io::copy(&mut br, &mut aw);
        let _outcome = tokio::join!(f, g);
    }

    /// Minimal in-process SOCKS5 proxy: no-auth greeting, IPv4 CONNECT, then splice to dst.
    async fn spawn_fake_socks5(expect_dst: SocketAddr) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut c, _) = listener.accept().await.unwrap();
            // Greeting: VER NMETHODS METHODS...
            let mut g = [0u8; 2];
            c.read_exact(&mut g).await.unwrap();
            let mut methods = vec![0u8; g[1] as usize];
            c.read_exact(&mut methods).await.unwrap();
            c.write_all(&[0x05, 0x00]).await.unwrap(); // select no-auth
            // CONNECT request: VER CMD RSV ATYP DST.ADDR(4) DST.PORT(2)
            let mut req = [0u8; 10];
            c.read_exact(&mut req).await.unwrap();
            assert_eq!(req[0], 0x05);
            assert_eq!(req[1], 0x01); // CONNECT
            assert_eq!(req[3], 0x01); // IPv4
            let dst_ip = std::net::Ipv4Addr::new(req[4], req[5], req[6], req[7]);
            let dst_port = u16::from_be_bytes([req[8], req[9]]);
            assert_eq!(SocketAddr::from((dst_ip, dst_port)), expect_dst);
            let upstream = TcpStream::connect(expect_dst).await.unwrap();
            // Reply: VER REP RSV ATYP BND.ADDR(4) BND.PORT(2)
            c.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            splice(c, upstream).await;
        });
        addr
    }

    /// Minimal in-process HTTP CONNECT proxy: read request head, reply 200, then splice to dst.
    async fn spawn_fake_http_connect(expect_dst: SocketAddr) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut c, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                c.read_exact(&mut byte).await.unwrap();
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&head);
            assert!(text.starts_with(&format!("CONNECT {expect_dst} HTTP/1.1")));
            c.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            let upstream = TcpStream::connect(expect_dst).await.unwrap();
            splice(c, upstream).await;
        });
        addr
    }

    async fn assert_tunnel_carries_bytes(dialer: &ProxyExitDialer, dst: SocketAddr) {
        // These tests exercise the tunnelling mechanism against a loopback echo/CONNECT target, so
        // they use `Subnet` (which legitimately targets private/loopback ranges). The exit-node
        // SSRF guard against forbidden destinations has its own test
        // (`proxy_dialer_refuses_forbidden_exit_destinations`).
        let mut stream = dialer
            .dial_tcp(FlowClass::Subnet, dst)
            .await
            .expect("proxy dialer should establish tunnel");
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn proxy_dialer_socks5_tunnels_end_to_end() {
        let dst = spawn_echo().await;
        let proxy = spawn_fake_socks5(dst).await;
        let dialer = ProxyExitDialer::new(ProxyConfig {
            addr: proxy,
            scheme: ProxyScheme::Socks5,
            auth: None,
        });
        assert_tunnel_carries_bytes(&dialer, dst).await;
    }

    #[tokio::test]
    async fn proxy_dialer_http_connect_tunnels_end_to_end() {
        let dst = spawn_echo().await;
        let proxy = spawn_fake_http_connect(dst).await;
        let dialer = ProxyExitDialer::new(ProxyConfig {
            addr: proxy,
            scheme: ProxyScheme::HttpConnect,
            auth: Some(("user".to_owned(), "pass".to_owned())),
        });
        assert_tunnel_carries_bytes(&dialer, dst).await;
    }

    /// A proxy that immediately refuses the handshake must yield `Err`, never a direct fallback.
    #[tokio::test]
    async fn proxy_dialer_fails_closed_on_handshake_refusal() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut c, _) = listener.accept().await.unwrap();
            // Eat the greeting, then send a bogus version byte to reject.
            let mut g = [0u8; 2];
            let _read = c.read_exact(&mut g).await;
            let _written = c.write_all(&[0xff, 0xff]).await;
        });
        let dialer = ProxyExitDialer::new(ProxyConfig {
            addr: proxy,
            scheme: ProxyScheme::Socks5,
            auth: None,
        });
        let dst = "1.2.3.4:443".parse().unwrap();
        let err = dialer.dial_tcp(FlowClass::ExitNode, dst).await;
        assert!(matches!(err, Err(DialError::ProxyHandshake(_))));
    }

    /// A hostile SOCKS5 reply with a non-IPv4 bound-address type (here `ATYP=0x03` domain, plus an
    /// attacker-chosen huge length byte) must be REJECTED at the ATYP check, *before* any
    /// variable-length read — so a malicious proxy can't drive an unbounded/oversized read off the
    /// length field. The connect reply code is success (`0x00`), so the only thing standing between
    /// the proxy and a length-driven read is the `head[3] != 0x01` IPv4-only guard. We assert it
    /// fails closed with `ProxyHandshake` (no tunnel) rather than attempting to consume the
    /// advertised domain length. The fake proxy deliberately sends ONLY the 4-byte reply header and
    /// then nothing more: if the dialer tried to read the (non-existent) 255-byte domain it would
    /// block until `PROXY_HANDSHAKE_TIMEOUT` and surface a timeout `ProxyHandshake` instead — either
    /// way it fails closed, but the fast reject (no further read) is what this locks in.
    #[tokio::test]
    async fn proxy_dialer_socks5_rejects_non_ipv4_reply_atyp_before_unbounded_read() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut c, _) = listener.accept().await.unwrap();
            // Complete the greeting + method selection.
            let mut g = [0u8; 2];
            c.read_exact(&mut g).await.unwrap();
            let mut methods = vec![0u8; g[1] as usize];
            c.read_exact(&mut methods).await.unwrap();
            c.write_all(&[0x05, 0x00]).await.unwrap(); // no-auth
            // Consume the CONNECT request (VER CMD RSV ATYP DST.ADDR(4) DST.PORT(2)).
            let mut req = [0u8; 10];
            c.read_exact(&mut req).await.unwrap();
            // Hostile reply: VER=5, REP=0x00 (success), RSV=0, ATYP=0x03 (DOMAINNAME), then a length
            // byte of 0xFF claiming a 255-byte hostname — but send NOTHING after the header. A parser
            // that trusted ATYP/length would try to read 1 + 255 + 2 bytes that never arrive.
            let _written = c.write_all(&[0x05, 0x00, 0x00, 0x03, 0xff]).await;
            // Hold the connection open briefly so a (wrongly) reading dialer would block, not EOF.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });
        let dialer = ProxyExitDialer::new(ProxyConfig {
            addr: proxy,
            scheme: ProxyScheme::Socks5,
            auth: None,
        });
        let dst = "1.2.3.4:443".parse().unwrap();
        // Bound the call well under the proxy's 200ms hold: the ATYP guard rejects synchronously
        // after the 4-byte header read, so this returns near-instantly. If a regression instead
        // tried to read the (never-sent) 255-byte domain, it would block until the proxy drops the
        // socket (~200ms → EOF) or the handshake timeout — this 100ms bound makes "reject *before*
        // the read" independent of the error-type discrimination below (belt-and-suspenders).
        let err = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            dialer.dial_tcp(FlowClass::ExitNode, dst),
        )
        .await
        .expect("the ATYP guard must reject synchronously, not block on a variable-length read");
        assert!(
            matches!(err, Err(DialError::ProxyHandshake(_))),
            "a non-IPv4 reply ATYP must fail closed at the guard, got {err:?}"
        );
    }

    /// Connecting to a dead proxy address surfaces an error — no direct fallback.
    #[tokio::test]
    async fn proxy_dialer_fails_closed_when_proxy_unreachable() {
        // Reserve a port then drop the listener so the connect is refused.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        drop(listener);
        let dialer = ProxyExitDialer::new(ProxyConfig {
            addr: proxy,
            scheme: ProxyScheme::HttpConnect,
            auth: None,
        });
        let dst = "1.2.3.4:443".parse().unwrap();
        let err = dialer.dial_tcp(FlowClass::ExitNode, dst).await;
        assert!(err.is_err(), "unreachable proxy must fail, not fall back");
    }

    /// UDP egress through the proxy must fail closed (no UDP tunnelling, no direct-IP leak).
    #[tokio::test]
    async fn proxy_dialer_udp_fails_closed() {
        let dialer = ProxyExitDialer::new(ProxyConfig {
            addr: "127.0.0.1:1080".parse().unwrap(),
            scheme: ProxyScheme::Socks5,
            auth: None,
        });
        let dst = "1.2.3.4:53".parse().unwrap();
        let err = dialer.dial_udp(FlowClass::ExitNode, dst).await;
        assert!(matches!(err, Err(DialError::ProxyUdpUnsupported)));
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"user:pass"), "dXNlcjpwYXNz");
    }

    /// SOCKS5 proxy that demands user/pass (RFC 1929), verifies the credentials, then CONNECTs.
    async fn spawn_fake_socks5_userpass(
        expect_dst: SocketAddr,
        expect_user: &'static str,
        expect_pass: &'static str,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut c, _) = listener.accept().await.unwrap();
            // Greeting: VER NMETHODS METHODS...
            let mut g = [0u8; 2];
            c.read_exact(&mut g).await.unwrap();
            let mut methods = vec![0u8; g[1] as usize];
            c.read_exact(&mut methods).await.unwrap();
            assert!(methods.contains(&0x02), "client must offer user/pass");
            c.write_all(&[0x05, 0x02]).await.unwrap(); // select user/pass
            // Auth sub-negotiation: VER ULEN USER PLEN PASS
            let mut hdr = [0u8; 2];
            c.read_exact(&mut hdr).await.unwrap();
            assert_eq!(hdr[0], 0x01);
            let mut user = vec![0u8; hdr[1] as usize];
            c.read_exact(&mut user).await.unwrap();
            let mut plen = [0u8; 1];
            c.read_exact(&mut plen).await.unwrap();
            let mut pass = vec![0u8; plen[0] as usize];
            c.read_exact(&mut pass).await.unwrap();
            assert_eq!(user, expect_user.as_bytes());
            assert_eq!(pass, expect_pass.as_bytes());
            c.write_all(&[0x01, 0x00]).await.unwrap(); // auth success
            // CONNECT request.
            let mut req = [0u8; 10];
            c.read_exact(&mut req).await.unwrap();
            let dst_ip = std::net::Ipv4Addr::new(req[4], req[5], req[6], req[7]);
            let dst_port = u16::from_be_bytes([req[8], req[9]]);
            assert_eq!(SocketAddr::from((dst_ip, dst_port)), expect_dst);
            let upstream = TcpStream::connect(expect_dst).await.unwrap();
            c.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            splice(c, upstream).await;
        });
        addr
    }

    #[tokio::test]
    async fn proxy_dialer_socks5_userpass_auth_tunnels() {
        let dst = spawn_echo().await;
        let proxy = spawn_fake_socks5_userpass(dst, "alice", "s3cret").await;
        let dialer = ProxyExitDialer::new(ProxyConfig {
            addr: proxy,
            scheme: ProxyScheme::Socks5,
            auth: Some(("alice".to_owned(), "s3cret".to_owned())),
        });
        assert_tunnel_carries_bytes(&dialer, dst).await;
    }

    /// A SOCKS5 proxy that rejects the user/pass auth must fail closed.
    #[tokio::test]
    async fn proxy_dialer_socks5_auth_rejected_fails_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut c, _) = listener.accept().await.unwrap();
            let mut g = [0u8; 2];
            c.read_exact(&mut g).await.unwrap();
            let mut methods = vec![0u8; g[1] as usize];
            c.read_exact(&mut methods).await.unwrap();
            c.write_all(&[0x05, 0x02]).await.unwrap(); // select user/pass
            // Drain the auth message, then reject with a non-zero status.
            let mut hdr = [0u8; 2];
            let _n = c.read_exact(&mut hdr).await;
            let mut user = vec![0u8; hdr[1] as usize];
            let _n = c.read_exact(&mut user).await;
            let mut plen = [0u8; 1];
            let _n = c.read_exact(&mut plen).await;
            let mut pass = vec![0u8; plen[0] as usize];
            let _n = c.read_exact(&mut pass).await;
            let _n = c.write_all(&[0x01, 0x01]).await; // auth failure
        });
        let dialer = ProxyExitDialer::new(ProxyConfig {
            addr: proxy,
            scheme: ProxyScheme::Socks5,
            auth: Some(("alice".to_owned(), "wrong".to_owned())),
        });
        let dst = "1.2.3.4:443".parse().unwrap();
        let err = dialer.dial_tcp(FlowClass::ExitNode, dst).await;
        assert!(matches!(err, Err(DialError::ProxyHandshake(_))));
    }

    /// HTTP CONNECT proxies may answer with any 2xx (not only `200`); the tunnel must establish.
    #[tokio::test]
    async fn proxy_dialer_http_connect_accepts_2xx() {
        let dst = spawn_echo().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let expect_dst = dst;
        tokio::spawn(async move {
            let (mut c, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                c.read_exact(&mut byte).await.unwrap();
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            c.write_all(b"HTTP/1.1 201 Tunnel\r\n\r\n").await.unwrap();
            let upstream = TcpStream::connect(expect_dst).await.unwrap();
            splice(c, upstream).await;
        });
        let dialer = ProxyExitDialer::new(ProxyConfig {
            addr: proxy,
            scheme: ProxyScheme::HttpConnect,
            auth: None,
        });
        assert_tunnel_carries_bytes(&dialer, dst).await;
    }

    /// SSRF guard: an exit-node flow aimed at a loopback/private/link-local/metadata destination is
    /// refused before any proxy connection is attempted.
    #[tokio::test]
    async fn proxy_dialer_refuses_forbidden_exit_destinations() {
        let dialer = ProxyExitDialer::new(ProxyConfig {
            addr: "127.0.0.1:1080".parse().unwrap(),
            scheme: ProxyScheme::Socks5,
            auth: None,
        });
        for forbidden in [
            "127.0.0.1:80",
            "10.0.0.5:443",
            "192.168.1.1:443",
            "169.254.169.254:80", // cloud metadata
            "0.0.0.0:80",
        ] {
            let dst: SocketAddr = forbidden.parse().unwrap();
            let err = dialer.dial_tcp(FlowClass::ExitNode, dst).await;
            assert!(
                matches!(err, Err(DialError::ProxyHandshake(_))),
                "exit dial to {forbidden} must be refused"
            );
        }
    }

    /// SSRF guard ranges: CGNAT/shared `100.64.0.0/10` (the Tailscale range itself), broadcast
    /// `255.255.255.255`, and "this network" `0.0.0.0/8` must all be forbidden for an exit-node
    /// flow, while a normal public IP and a CGNAT-adjacent-but-outside address stay allowed.
    /// Tests the `exit_dst_is_forbidden` predicate directly (the dialer-level refusal is covered by
    /// `proxy_dialer_refuses_forbidden_exit_destinations`).
    #[test]
    fn exit_ssrf_guard_rejects_cgnat_broadcast_and_this_network() {
        // 100.64.0.0/10 (RFC 6598) — the Tailscale address range itself.
        for forbidden in [
            "100.64.0.1:443",       // bottom of 100.64/10
            "100.127.255.255:80",   // top of 100.64/10
            "255.255.255.255:80",   // broadcast
            "0.0.0.1:80",           // 0.0.0.0/8 "this network"
            "224.0.0.1:80",         // bottom of multicast 224.0.0.0/4 (all-systems)
            "239.255.255.250:1900", // SSDP multicast, top-ish of 224/4
            "240.0.0.1:80",         // bottom of class-E reserved 240.0.0.0/4
            "254.255.255.255:80",   // top of class-E (below the 255.255.255.255 broadcast)
        ] {
            let dst: SocketAddr = forbidden.parse().unwrap();
            assert!(
                exit_dst_is_forbidden(dst),
                "exit dst {forbidden} must be forbidden (SSRF guard)"
            );
        }

        // A normal public IP is still ALLOWED.
        let public: SocketAddr = "1.1.1.1:443".parse().unwrap();
        assert!(
            !exit_dst_is_forbidden(public),
            "public IP 1.1.1.1 must remain an allowed exit destination"
        );

        // 100.128.0.1 is OUTSIDE 100.64.0.0/10 (the /10 only covers 100.64–100.127), so it is a
        // normal public address and must NOT be caught by the CGNAT guard.
        let cgnat_adjacent: SocketAddr = "100.128.0.1:443".parse().unwrap();
        assert!(
            !exit_dst_is_forbidden(cgnat_adjacent),
            "100.128.0.1 is outside 100.64/10 and must remain allowed"
        );

        // 223.255.255.255 is the last unicast address BELOW multicast (224/4); it must remain
        // allowed — proving the multicast guard starts exactly at 224, not earlier.
        let below_multicast: SocketAddr = "223.255.255.255:443".parse().unwrap();
        assert!(
            !exit_dst_is_forbidden(below_multicast),
            "223.255.255.255 is below the 224/4 multicast block and must remain allowed"
        );
    }

    /// The SSRF guard applies only to exit-node flows: a subnet route legitimately targets a
    /// private range (that *is* the routed subnet), so a private dst is allowed for `Subnet`.
    #[tokio::test]
    async fn proxy_dialer_allows_private_subnet_destinations() {
        let dst = spawn_echo().await; // 127.0.0.1 — private/loopback
        let proxy = spawn_fake_socks5(dst).await;
        let dialer = ProxyExitDialer::new(ProxyConfig {
            addr: proxy,
            scheme: ProxyScheme::Socks5,
            auth: None,
        });
        // Subnet class is NOT subject to the exit SSRF guard.
        let mut stream = dialer
            .dial_tcp(FlowClass::Subnet, dst)
            .await
            .expect("subnet dial to private dst should be allowed");
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    /// The redacting `Debug` impl must never print the proxy credentials.
    #[test]
    fn proxy_config_debug_redacts_credentials() {
        let cfg = ProxyConfig {
            addr: "203.0.113.1:1080".parse().unwrap(),
            scheme: ProxyScheme::Socks5,
            auth: Some(("user-secret".to_owned(), "p@ssw0rd".to_owned())),
        };
        let rendered = format!("{cfg:?}");
        assert!(rendered.contains("<redacted>"), "auth must be redacted");
        assert!(!rendered.contains("user-secret"), "username must not leak");
        assert!(!rendered.contains("p@ssw0rd"), "password must not leak");
    }
}
