//! String-address dialing — the Go `tsnet.Server.Dial` / `ListenPacket` / `HTTPClient` consumer
//! entry points.
//!
//! Go `tsnet` lets an embedder write `srv.Dial(ctx, "tcp", "myhost:443")` and
//! `srv.ListenPacket("udp", "0.0.0.0:0")` — a `network` string plus a `host:port` string, where
//! `host` may be a MagicDNS name or an IP literal. This module provides the parsing + dispatch that
//! [`crate::Device::dial`], [`crate::Device::dial_tcp`], and [`crate::Device::listen_packet`] build
//! on, mirroring Go `tsnet.go`'s `resolveListenAddr` (the `host:port` parser) and the `listen`
//! network-validation set.
//!
//! The actual transport is the existing netstack: TCP reuses [`crate::Device::tcp_connect`]; UDP
//! reuses [`crate::Device::udp_bind`] wrapped by [`ConnectedUdpSocket`], which remembers a fixed
//! peer so it presents the connected-`net.Conn` shape Go's `Dial("udp", …)` returns.

use core::net::{IpAddr, SocketAddr};

use crate::{Error, InternalErrorKind, netstack};

/// The transport selected by a `network` string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Transport {
    Tcp,
    Udp,
}

/// The address family forced by a `network` string suffix (`tcp4`/`udp6`/…), or `Any` for the
/// unsuffixed `tcp`/`udp` (family then follows the resolved/parsed address).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Family {
    Any,
    V4,
    V6,
}

/// A parsed `network` string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Network {
    pub transport: Transport,
    pub family: Family,
}

/// Parse a Go-style `network` string into a [`Network`], mirroring the accepted set in Go
/// `tsnet.go`'s `listen` switch (`"tcp"`, `"tcp4"`, `"tcp6"`, `"udp"`, `"udp4"`, `"udp6"`). Anything
/// else is [`InternalErrorKind::BadRequest`] ("unsupported network type").
///
/// Unlike Go's `listen`, the empty string `""` is **not** accepted here: a bare dial/connect with no
/// transport is meaningless (Go's `Dial` would route `""` through `tsdial`, which defaults it, but
/// the typed Rust surface is clearer requiring an explicit transport).
pub(crate) fn parse_network(network: &str) -> Result<Network, Error> {
    let n = match network {
        "tcp" => Network {
            transport: Transport::Tcp,
            family: Family::Any,
        },
        "tcp4" => Network {
            transport: Transport::Tcp,
            family: Family::V4,
        },
        "tcp6" => Network {
            transport: Transport::Tcp,
            family: Family::V6,
        },
        "udp" => Network {
            transport: Transport::Udp,
            family: Family::Any,
        },
        "udp4" => Network {
            transport: Transport::Udp,
            family: Family::V4,
        },
        "udp6" => Network {
            transport: Transport::Udp,
            family: Family::V6,
        },
        _ => return Err(Error::Internal(InternalErrorKind::BadRequest)),
    };
    Ok(n)
}

/// Split a `host:port` string into its host and numeric port, mirroring Go's
/// `net.SplitHostPort` + `net.LookupPort` as used by `tsnet`'s `resolveListenAddr`.
///
/// - The host may be a MagicDNS name, an IPv4 literal, or a **bracketed** IPv6 literal
///   (`[2001:db8::1]:443`) — brackets are required for v6 exactly as Go/`SplitHostPort` requires.
/// - The port must be **numeric** in `0..=65535`. Go's `LookupPort` also resolves named ports
///   (`"http"`→80) via the OS services database; this fork deliberately does **not** pull a
///   services-file dependency, so named ports are unsupported (a small, documented divergence).
/// - A missing `:port` is rejected (Go's `SplitHostPort` errors), as is a host with no port.
///
/// Returns the host slice (brackets stripped for v6) and the parsed port.
pub(crate) fn split_host_port(addr: &str) -> Result<(&str, u16), Error> {
    let bad = || Error::Internal(InternalErrorKind::BadRequest);

    // Bracketed IPv6: "[<v6>]:port". The colon that separates host from port is the one *after*
    // the closing bracket, so a v6 literal's own colons don't confuse the split.
    let (host, port_str) = if let Some(rest) = addr.strip_prefix('[') {
        let close = rest.find(']').ok_or_else(bad)?;
        let host = &rest[..close];
        let after = &rest[close + 1..];
        let port_str = after.strip_prefix(':').ok_or_else(bad)?;
        (host, port_str)
    } else {
        // Unbracketed: split on the LAST colon. A bare IPv6 literal (multiple colons, no brackets)
        // is therefore rejected — matching Go, which requires brackets for a v6 host:port.
        let idx = addr.rfind(':').ok_or_else(bad)?;
        let host = &addr[..idx];
        let port_str = &addr[idx + 1..];
        if host.contains(':') {
            // More than one colon and not bracketed → a bare v6 literal; Go rejects this form.
            return Err(bad());
        }
        (host, port_str)
    };

    if port_str.is_empty() {
        return Err(bad());
    }
    let port: u16 = port_str.parse().map_err(|_| bad())?;
    Ok((host, port))
}

/// A UDP socket bound to a fixed remote peer — the connected-`net.Conn` shape Go's
/// `Dial(ctx, "udp", …)` returns (a `*gonet.UDPConn` with a fixed destination).
///
/// The fork's netstack [`netstack::UdpSocket`] is unconnected (`send_to`/`recv_from` carry the peer
/// per datagram, the `net.PacketConn` shape). This wrapper stores the peer so [`send`](Self::send)
/// targets it implicitly and [`recv`](Self::recv) **filters to datagrams from that peer**, dropping
/// any from other sources — exactly what a kernel `connect(2)` on a UDP socket does. UDP stays
/// message-oriented (one `send`/`recv` = one datagram), as it is for Go's UDP `net.Conn`.
pub struct ConnectedUdpSocket {
    sock: netstack::UdpSocket,
    peer: SocketAddr,
}

impl ConnectedUdpSocket {
    pub(crate) fn new(sock: netstack::UdpSocket, peer: SocketAddr) -> Self {
        Self { sock, peer }
    }

    /// The connected peer this socket sends to / receives from.
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// The local address the underlying socket is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.sock.local_addr()
    }

    /// Send one datagram to the connected peer (Go UDP `net.Conn::Write`).
    pub async fn send(&self, data: &[u8]) -> Result<(), Error> {
        self.sock.send_to(self.peer, data).await.map_err(Into::into)
    }

    /// Receive one datagram from the connected peer into `buf`, returning the byte count (Go UDP
    /// `net.Conn::Read`). Datagrams from any other source are discarded (connected-UDP semantics),
    /// so this loops until a datagram from the connected peer arrives or the socket errors.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize, Error> {
        loop {
            let (from, n) = self.sock.recv_from(buf).await?;
            if from == self.peer {
                return Ok(n);
            }
            // Not from our connected peer — drop it and keep waiting (mirrors connect(2) filtering).
        }
    }
}

/// The result of a [`crate::Device::dial`]: a connected stream whose transport matches the dialed
/// `network`. Rust has no `net.Conn` trait object, so this is an explicit enum; the TCP arm is an
/// async byte stream (`AsyncRead`+`AsyncWrite`), the UDP arm is the message-oriented connected
/// socket. Use [`crate::Device::dial_tcp`] when you know it's TCP and want the stream directly.
pub enum DialConn {
    /// A connected TCP stream (Go `Dial("tcp", …)`).
    Tcp(netstack::TcpStream),
    /// A connected UDP socket bound to the dialed peer (Go `Dial("udp", …)`).
    Udp(ConnectedUdpSocket),
}

/// Validate a resolved/parsed destination IP against the family forced by the `network` suffix
/// (`tcp4` with a v6 address → error, and vice versa), mirroring `resolveListenAddr`'s
/// `…4`/`…6` checks.
pub(crate) fn check_family(family: Family, ip: IpAddr) -> Result<(), Error> {
    let ok = match family {
        Family::Any => true,
        Family::V4 => ip.is_ipv4(),
        Family::V6 => ip.is_ipv6(),
    };
    if ok {
        Ok(())
    } else {
        Err(Error::Internal(InternalErrorKind::BadRequest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_network_accepts_the_tsnet_set() {
        assert_eq!(parse_network("tcp").unwrap().transport, Transport::Tcp);
        assert_eq!(parse_network("tcp4").unwrap().family, Family::V4);
        assert_eq!(parse_network("tcp6").unwrap().family, Family::V6);
        assert_eq!(parse_network("udp").unwrap().transport, Transport::Udp);
        assert_eq!(parse_network("udp4").unwrap().family, Family::V4);
        assert_eq!(parse_network("udp6").unwrap().family, Family::V6);
    }

    #[test]
    fn parse_network_rejects_unsupported() {
        for n in ["", "sctp", "ip", "tcp5", "unix", "TCP"] {
            assert!(parse_network(n).is_err(), "{n:?} must be rejected");
        }
    }

    #[test]
    fn split_host_port_ipv4() {
        assert_eq!(split_host_port("1.2.3.4:80").unwrap(), ("1.2.3.4", 80));
    }

    #[test]
    fn split_host_port_ipv6_bracketed() {
        assert_eq!(
            split_host_port("[2001:db8::1]:443").unwrap(),
            ("2001:db8::1", 443)
        );
    }

    #[test]
    fn split_host_port_name() {
        assert_eq!(split_host_port("myhost:22").unwrap(), ("myhost", 22));
        assert_eq!(
            split_host_port("host.tail.ts.net:8080").unwrap(),
            ("host.tail.ts.net", 8080)
        );
    }

    #[test]
    fn split_host_port_rejects_missing_port() {
        assert!(split_host_port("myhost").is_err());
        assert!(split_host_port("1.2.3.4").is_err());
        assert!(split_host_port("host:").is_err());
    }

    #[test]
    fn split_host_port_rejects_bare_ipv6() {
        // Unbracketed v6 (multiple colons) is rejected — Go requires brackets.
        assert!(split_host_port("2001:db8::1:443").is_err());
    }

    #[test]
    fn split_host_port_rejects_bad_port() {
        assert!(split_host_port("host:99999").is_err()); // > u16::MAX
        assert!(split_host_port("host:http").is_err()); // named port unsupported (numeric only)
        assert!(split_host_port("host:-1").is_err());
    }

    #[test]
    fn check_family_matches() {
        let v4: IpAddr = "1.2.3.4".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(check_family(Family::Any, v4).is_ok());
        assert!(check_family(Family::V4, v4).is_ok());
        assert!(check_family(Family::V6, v6).is_ok());
        assert!(check_family(Family::V4, v6).is_err());
        assert!(check_family(Family::V6, v4).is_err());
    }
}
