//! The single anti-leak chokepoint: where overlay flows become real OS sockets.

use std::net::{IpAddr, SocketAddr};

use crate::class::FlowClass;

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
}
