//! Integration tests for the inbound forwarder.
//!
//! These use a pair of in-memory-piped netstacks: one plays the remote peer dialing over the
//! overlay, the other is the forwarder's dedicated any-IP netstack. No external networking is
//! used beyond a loopback echo server that stands in for a "real OS socket" destination.

use core::net::{Ipv4Addr, SocketAddr};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use ts_forwarder::{
    DialError, DialedUdp, DirectDialer, FlowClass, Forwarder, HostExitDialer, PortSpec, RealDialer,
    RouteTable,
};
use ts_netstack_smoltcp::{
    CreateSocket, Netstack, WakingPipe, WakingPipeDev,
    netcore::{self, Channel, HasChannel, NetstackControl, smoltcp},
    netsock::{TcpStream as OverlayTcpStream, UdpSocket as OverlayUdpSocket},
};

const PEER_IP: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
const PEER_PORT: u16 = 1000;

/// Spawn a loopback TCP echo server, returning its address. Stands in for a "real OS socket"
/// destination that the forwarder dials.
async fn spawn_echo() -> SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = echo.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    echo_addr
}

/// Spawn a loopback TCP server that, on each connection, reads the request, writes a fixed reply,
/// then **half-closes its write side** (`shutdown(SHUT_WR)`) and holds the read side open. Models a
/// real backend that finishes responding and signals "I'm done sending" with a FIN while still
/// willing to read — the pattern that exposes whether the forwarder propagates a backend EOF to the
/// overlay peer (the iter48 / tsr-syf half-close fix). Before that fix the peer never saw this FIN.
async fn spawn_respond_then_half_close(reply: &'static [u8]) -> SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                // Read the request (one read is enough for the small test payload).
                let _n = sock.read(&mut buf).await;
                // Respond, then half-close the write side: the peer must observe EOF after `reply`.
                if sock.write_all(reply).await.is_err() {
                    return;
                }
                let _shut = sock.shutdown().await; // shutdown(SHUT_WR): FIN, read side stays open
                // Hold the connection open (read side) so teardown is driven by the half-close
                // propagating to the peer, not by us dropping the socket.
                let mut drain = [0u8; 64];
                loop {
                    match sock.read(&mut drain).await {
                        Ok(0) | Err(_) => return, // peer eventually closed its side
                        Ok(_) => {}
                    }
                }
            });
        }
    });
    addr
}

/// Spawn a loopback TCP server that counts accepted connections (then drains them), returning
/// `(addr, accept_count)`. Used by the fail-closed drop tests to assert deterministically that the
/// forwarder dialed the real socket **zero** times — distinguishing "correctly refused at dial
/// time" from "the test runtime was merely slow" (a wall-clock timeout alone can't tell them
/// apart).
async fn spawn_counting_sink() -> (SocketAddr, Arc<AtomicUsize>) {
    use tokio::io::AsyncReadExt;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let count_for_task = count.clone();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            count_for_task.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 {
                        return;
                    }
                }
            });
        }
    });
    (addr, count)
}

/// Spawn a loopback UDP echo server, returning its address. The UDP analogue of [`spawn_echo`]:
/// stands in for a "real OS socket" destination that the forwarder dials, echoing every datagram
/// back to its sender so a reply can be observed over the overlay.
async fn spawn_udp_echo() -> SocketAddr {
    let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            match echo.recv_from(&mut buf).await {
                Ok((n, from)) => {
                    if echo.send_to(&buf[..n], from).await.is_err() {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    });
    echo_addr
}

/// Spawn a loopback UDP socket that counts received datagrams, returning `(addr, recv_count)`. The
/// UDP analogue of [`spawn_counting_sink`]: the anti-leak drop tests assert deterministically that
/// the forwarder relayed **zero** datagrams to the real socket — distinguishing "correctly refused
/// at dial time" from "the test runtime was merely slow" (a wall-clock timeout alone can't tell
/// them apart).
async fn spawn_udp_counting_sink() -> (SocketAddr, Arc<AtomicUsize>) {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let count_for_task = count.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            match sock.recv_from(&mut buf).await {
                Ok(_) => {
                    count_for_task.fetch_add(1, Ordering::SeqCst);
                }
                Err(_) => return,
            }
        }
    });
    (addr, count)
}

/// Connect to `dst` over the overlay with bounded retries, returning the established stream.
///
/// The forwarder registers its per-port listen socket asynchronously after `run()` is spawned;
/// until that socket exists smoltcp RSTs an inbound SYN. Rather than guess a fixed sleep (racy
/// under CI load — too short spuriously RSTs, too long wastes time), we retry the connect until the
/// listener is live. Bounded so a genuinely-never-registered listener still fails the test.
async fn connect_with_retry(
    peer_ch: &Channel,
    local: SocketAddr,
    dst: SocketAddr,
) -> OverlayTcpStream {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut attempt = 0u32;
    loop {
        match peer_ch.tcp_connect(local, dst).await {
            Ok(stream) => return stream,
            Err(e) => {
                if tokio::time::Instant::now() >= deadline {
                    panic!(
                        "overlay connect to {dst} never succeeded after {attempt} attempts: {e}"
                    );
                }
                attempt += 1;
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }
    }
}

// Standalone integration stacks use the same opt-in settings as the runtime constructors.
fn batch_experiments(stack: &mut Netstack<WakingPipeDev>) {
    if ts_netstack_smoltcp::netcore::experiment::enabled(
        ts_netstack_smoltcp::netcore::experiment::RX_BATCH,
    ) {
        stack.set_ingress_budget(Some(128));
    }
}

/// Spawn a piped pair: `(peer_channel, forwarder_channel)`. The forwarder stack has any-IP
/// acceptance enabled; the peer stack owns `PEER_IP`.
async fn spawn_pair() -> (Channel, Channel) {
    let config = netcore::Config::default();
    let (p1, p2) = WakingPipe::new(None);

    let dev1 = WakingPipeDev {
        pipe: p1,
        mtu: 1500,
        medium: smoltcp::phy::Medium::Ip,
    };
    let dev2 = WakingPipeDev {
        pipe: p2,
        mtu: 1500,
        medium: smoltcp::phy::Medium::Ip,
    };

    let mut peer = Netstack::new(dev1, config.clone());
    let mut fwd = Netstack::new(dev2, config);
    batch_experiments(&mut peer);
    batch_experiments(&mut fwd);

    let peer_ch = peer.command_channel();
    let fwd_ch = fwd.command_channel();

    tokio::spawn(async move { peer.run_tokio().await });
    tokio::spawn(async move { fwd.run_tokio().await });

    peer_ch.set_ips([PEER_IP.into()]).await.unwrap();
    // The forwarder netstack uses any-IP acceptance so it captures flows to destinations it
    // does not own. This is the dedicated forwarder stack -- never the application stack.
    fwd_ch.set_any_ip(true).await.unwrap();

    (peer_ch, fwd_ch)
}

/// A wildcard listener on the any-IP forwarder stack must accept a flow to an arbitrary
/// destination IP and report that original destination as the accepted stream's local_addr.
#[tokio::test]
async fn accept_preserves_original_dst() {
    let (peer_ch, fwd_ch) = spawn_pair().await;

    let foreign_dst: SocketAddr = "192.0.2.7:80".parse().unwrap();

    let listener = fwd_ch
        .tcp_listen(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 80))
        .await
        .unwrap();

    let accept = tokio::spawn(async move { listener.accept().await.unwrap() });

    let peer_local = SocketAddr::new(PEER_IP.into(), PEER_PORT);
    let _client = peer_ch.tcp_connect(peer_local, foreign_dst).await.unwrap();

    let accepted = tokio::time::timeout(Duration::from_secs(5), accept)
        .await
        .expect("accept timed out")
        .unwrap();

    // The captured original destination, not the wildcard listen address.
    assert_eq!(accepted.local_addr(), foreign_dst);
    assert_eq!(accepted.remote_addr(), peer_local);
}

/// End-to-end: peer dials a subnet-route destination over the overlay; the forwarder accepts,
/// classifies it as a subnet route, dials the real OS socket via `DirectDialer`, and splices.
///
/// Requirement (2): a subnet forward reaches the intended destination.
#[tokio::test]
async fn forwarder_splices_subnet_route_to_real_socket() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let echo_addr = spawn_echo().await;
    let (peer_ch, fwd_ch) = spawn_pair().await;

    // 127.0.0.0/8 is a (narrow) subnet route -> DirectDialer will dial it.
    let routes = RouteTable::new(["127.0.0.0/8".parse().unwrap()]);
    let forwarder = Forwarder::new(fwd_ch, routes, DirectDialer, vec![echo_addr.port()], vec![]);
    tokio::spawn(async move {
        let _ = forwarder.run().await;
    });

    // Peer dials the echo server's address *over the overlay*. The forwarder captures it
    // (any-IP), classifies 127.0.0.1 as Subnet, and DirectDialer connects to the real echo. The
    // forwarder registers its per-port listen socket asynchronously, so retry the connect until
    // the listener is live (a fixed sleep is racy under CI load).
    let peer_local = SocketAddr::new(PEER_IP.into(), PEER_PORT);
    let mut client = connect_with_retry(&peer_ch, peer_local, echo_addr).await;

    client.write_all(b"hello forwarder").await.unwrap();

    // Generous read deadline (real-socket round-trip): the shared CI runner is often overloaded, so
    // a tight 5s window spuriously timed out under load. 60s absorbs scheduler jitter; the bound is
    // still finite, so a forwarder that never splices still fails — this removes false negatives
    // without weakening the regression guard. Do NOT shrink it back.
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(60), client.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();

    assert_eq!(&buf[..n], b"hello forwarder");
}

/// Large tails cross the coalescing buffer and TCP window; FIN must follow every byte and the
/// opposite direction must stay usable after EOF. Small reads exercise retained Recv remainders.
#[tokio::test]
async fn large_splice_preserves_tail_and_reply_after_peer_fin() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    tokio::time::timeout(Duration::from_secs(30), async {
        let payload: Vec<_> = (0..(512 * 1024 + 37)).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let backend = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut got = Vec::new();
            let mut buf = [0; 997];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            assert_eq!(got, expected);
            stream.write_all(&got).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let (peer_ch, fwd_ch) = spawn_pair().await;
        let forwarder = Forwarder::new(
            fwd_ch,
            RouteTable::new(["127.0.0.0/8".parse().unwrap()]),
            DirectDialer,
            vec![addr.port()],
            vec![],
        );
        let forwarding = tokio::spawn(async move { forwarder.run().await });
        let mut client =
            connect_with_retry(&peer_ch, SocketAddr::new(PEER_IP.into(), PEER_PORT), addr).await;
        client.write_all(&payload).await.unwrap();
        client.shutdown().await.unwrap();
        let mut reply = Vec::new();
        let mut buf = [0; 333];
        loop {
            let n = client.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            reply.extend_from_slice(&buf[..n]);
        }
        assert_eq!(reply, payload);
        backend.await.unwrap();
        forwarding.abort();
    })
    .await
    .unwrap();
}

/// Regression for tsr-syf (half-close): when the real backend finishes responding and half-closes
/// its write side (`shutdown(SHUT_WR)` -> FIN), that EOF must propagate back through the forwarder
/// splice to the overlay peer — the peer's `read` must return `Ok(0)`. Before the fix the overlay
/// `poll_shutdown`/`poll_close` were no-ops, so `copy_bidirectional`'s shutdown of the overlay
/// direction sent no FIN and the peer hung on this final read until the idle reaper. The finite read
/// deadline turns that hang into a failure, so this is a real regression guard.
#[tokio::test]
async fn forwarder_propagates_backend_half_close_eof_to_peer() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let backend_addr = spawn_respond_then_half_close(b"resp-then-fin").await;
    let (peer_ch, fwd_ch) = spawn_pair().await;

    let routes = RouteTable::new(["127.0.0.0/8".parse().unwrap()]);
    let forwarder = Forwarder::new(
        fwd_ch,
        routes,
        DirectDialer,
        vec![backend_addr.port()],
        vec![],
    );
    tokio::spawn(async move {
        let _ = forwarder.run().await;
    });

    let peer_local = SocketAddr::new(PEER_IP.into(), PEER_PORT);
    let mut client = connect_with_retry(&peer_ch, peer_local, backend_addr).await;

    client.write_all(b"req").await.unwrap();

    // Read the reply, then keep reading until EOF. The SECOND read (after the reply) must return
    // Ok(0) — the backend's FIN propagated through the splice. Without the half-close fix this read
    // never completes and the timeout fires (test failure).
    let mut got = Vec::new();
    let deadline = Duration::from_secs(60);
    loop {
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(deadline, client.read(&mut buf))
            .await
            .expect("read timed out waiting for backend half-close EOF to propagate")
            .unwrap();
        if n == 0 {
            break; // EOF — the backend's FIN reached the peer through the splice.
        }
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(
        got, b"resp-then-fin",
        "the reply must arrive before the propagated EOF"
    );
}

/// Requirement (1): a node may advertise a route yet forward nothing. With no forward ports
/// configured the forwarder spawns no listeners, so an inbound flow to the advertised
/// destination is never accepted/spliced — no data is forwarded.
#[tokio::test]
async fn advertised_but_no_ports_forwards_nothing() {
    use tokio::io::AsyncWriteExt;

    let (sink_addr, dial_count) = spawn_counting_sink().await;
    let (peer_ch, fwd_ch) = spawn_pair().await;

    // Route IS advertised (127.0.0.0/8) but forward ports are empty: forwarding is off.
    let routes = RouteTable::new(["127.0.0.0/8".parse().unwrap()]);
    let forwarder = Forwarder::new(fwd_ch, routes, DirectDialer, vec![], vec![]);
    tokio::spawn(async move {
        let _ = forwarder.run().await;
    });

    // NOTE: fixed sleep retained on purpose — not convertible to a deadline-poll. The assertion is
    // a *negative* (the sink saw zero connections), and with zero ports configured the forwarder
    // exposes no positive readiness signal to poll for (no listener ever registers — that absence
    // IS the behavior under test). A too-short sleep cannot cause a spurious failure here (the count
    // can only stay 0 or rise), so this is a settle, not a race to win.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let peer_local = SocketAddr::new(PEER_IP.into(), PEER_PORT);
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        if let Ok(mut client) = peer_ch.tcp_connect(peer_local, sink_addr).await {
            client.write_all(b"hello forwarder").await.ok();
        }
    })
    .await;

    // Deterministic proof of "forwarded nothing": the real sink saw zero connections. This
    // distinguishes a genuine no-op from a merely-slow splice.
    assert_eq!(
        dial_count.load(Ordering::SeqCst),
        0,
        "forwarder with no ports must never dial the real destination"
    );
}

/// Requirement (3), fail-closed half: with the default `DirectDialer`, an exit-node
/// (`0.0.0.0/0`) flow is **structurally refused** at dial time. The flow is dropped, never
/// egressed via the raw host IP — so nothing is echoed back to the peer.
#[tokio::test]
async fn exit_node_flow_is_dropped_under_direct_dialer() {
    use tokio::io::AsyncWriteExt;

    let (sink_addr, dial_count) = spawn_counting_sink().await;
    let (peer_ch, fwd_ch) = spawn_pair().await;

    // Only a default route is advertised, so the sink IP (127.0.0.1) classifies as ExitNode.
    // DirectDialer refuses exit egress at dial time -> the flow is dropped after accept, the real
    // socket is never opened. A per-port listener DOES exist, so this proves the refusal happens
    // at the dialer, not merely from a missing listener.
    let routes = RouteTable::new(["0.0.0.0/0".parse().unwrap()]);
    let forwarder = Forwarder::new(fwd_ch, routes, DirectDialer, vec![sink_addr.port()], vec![]);
    tokio::spawn(async move {
        let _ = forwarder.run().await;
    });

    // Retry the connect until the per-port listener is live, so the overlay flow is actually
    // accepted (reaching classify → dial). This proves the drop comes from the dialer refusing
    // exit egress, not from the SYN racing a not-yet-registered listener.
    let peer_local = SocketAddr::new(PEER_IP.into(), PEER_PORT);
    let mut client = connect_with_retry(&peer_ch, peer_local, sink_addr).await;
    client.write_all(b"leak attempt").await.ok();

    // NOTE: fixed sleep retained on purpose — not convertible to a deadline-poll. `connect_with_retry`
    // already proves the per-port listener accepted the flow (so classify → dial was reached); the
    // remaining wait is a settle for a *negative* assertion (a leaky dial would land *after* accept).
    // There is no positive "flow dropped" signal to poll, and a too-short sleep cannot spuriously
    // fail (the count can only stay 0 or rise). So this is a settle, not a race.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Deterministic anti-leak proof: the real destination saw zero connections, so the host IP
    // never egressed the exit-node flow.
    assert_eq!(
        dial_count.load(Ordering::SeqCst),
        0,
        "DirectDialer must never egress an exit-node flow (anti-leak)"
    );
}

/// Stands in for the internet in tests: classifies every flow as `Subnet` before handing it to
/// [`HostExitDialer`], so the loopback test server is reachable while the socket path is unchanged.
/// (`HostExitDialer` itself refuses loopback for exit-node flows.)
struct LoopbackInternetDialer;

impl RealDialer for LoopbackInternetDialer {
    async fn dial_tcp(
        &self,
        _class: FlowClass,
        dst: SocketAddr,
    ) -> Result<tokio::net::TcpStream, DialError> {
        HostExitDialer.dial_tcp(FlowClass::Subnet, dst).await
    }

    async fn dial_udp(&self, _class: FlowClass, dst: SocketAddr) -> Result<DialedUdp, DialError> {
        HostExitDialer.dial_udp(FlowClass::Subnet, dst).await
    }
}

/// Requirement (3), opt-in half: an exit-node (`0.0.0.0/0`) flow is accepted, dialed and spliced
/// to the intended destination; the destination echoes back.
#[tokio::test]
async fn exit_node_flow_egresses_under_exit_dialer() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let echo_addr = spawn_echo().await;
    let (peer_ch, fwd_ch) = spawn_pair().await;

    let routes = RouteTable::new(["0.0.0.0/0".parse().unwrap()]);
    let forwarder = Forwarder::new(
        fwd_ch,
        routes,
        LoopbackInternetDialer,
        vec![echo_addr.port()],
        vec![],
    );
    tokio::spawn(async move {
        let _ = forwarder.run().await;
    });

    let peer_local = SocketAddr::new(PEER_IP.into(), PEER_PORT);
    let mut client = connect_with_retry(&peer_ch, peer_local, echo_addr).await;
    client.write_all(b"exit egress").await.unwrap();

    // Generous read deadline (real-socket round-trip): the shared CI runner is often overloaded, so
    // a tight 5s window spuriously timed out under load. 60s absorbs scheduler jitter; the bound is
    // still finite, so a forwarder that never egresses still fails — this removes false negatives
    // without weakening the regression guard. Do NOT shrink it back.
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(60), client.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();

    assert_eq!(&buf[..n], b"exit egress");
}

/// An exit-node user must not reach this host's loopback services through `HostExitDialer`: the
/// default route covers 127.0.0.1, the listener accepts, but the dial is refused and the local
/// service never sees a connection.
#[tokio::test]
async fn exit_node_flow_to_loopback_is_refused_under_host_exit_dialer() {
    use tokio::io::AsyncWriteExt;

    let (sink_addr, dial_count) = spawn_counting_sink().await;
    let (peer_ch, fwd_ch) = spawn_pair().await;

    let routes = RouteTable::new(["0.0.0.0/0".parse().unwrap()]);
    let forwarder = Forwarder::new(
        fwd_ch,
        routes,
        HostExitDialer,
        vec![sink_addr.port()],
        vec![],
    );
    tokio::spawn(async move {
        let _ = forwarder.run().await;
    });

    let peer_local = SocketAddr::new(PEER_IP.into(), PEER_PORT);
    let mut client = connect_with_retry(&peer_ch, peer_local, sink_addr).await;
    client.write_all(b"reach localhost").await.ok();

    // Settle for a negative assertion, as in `exit_node_flow_is_dropped_under_direct_dialer`.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        dial_count.load(Ordering::SeqCst),
        0,
        "an exit-node flow must never reach this host's loopback"
    );
}

/// All-port mode: a flow to a destination port that is **not** in any explicit forward list is
/// still forwarded for an advertised subnet route. `spawn_echo` binds an OS-assigned random
/// port; the forwarder is built with `PortSpec::All` (no explicit port list at all), proving the
/// all-port range covers it.
#[tokio::test]
async fn all_ports_forwards_unlisted_port_for_subnet_route() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let echo_addr = spawn_echo().await;
    let (peer_ch, fwd_ch) = spawn_pair().await;

    // Subnet route; all-port mode, so the random echo port is covered without being enumerated.
    let routes = RouteTable::new(["127.0.0.0/8".parse().unwrap()]);
    let forwarder = Forwarder::all_ports(fwd_ch, routes, DirectDialer);
    tokio::spawn(async move {
        let _ = forwarder.run().await;
    });

    // All-port mode lazily registers the listener for the echo port on first sight of a flow to
    // it; retry the connect until that on-demand listener is live (a fixed sleep is racy under
    // CI load).
    let peer_local = SocketAddr::new(PEER_IP.into(), PEER_PORT);
    let mut client = connect_with_retry(&peer_ch, peer_local, echo_addr).await;
    client.write_all(b"all ports hello").await.unwrap();

    // Generous read deadline (real-socket round-trip): the shared CI runner is often overloaded, so
    // a tight 10s window spuriously timed out under load. 60s absorbs scheduler jitter; the bound is
    // still finite, so a forwarder that never splices still fails — this removes false negatives
    // without weakening the regression guard. Do NOT shrink it back.
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(60), client.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();

    assert_eq!(&buf[..n], b"all ports hello");
}

/// All-port + `DirectDialer` + exit-node route: even with every port open, an exit-node
/// (`0.0.0.0/0`) flow is **still dropped** at dial time. This proves all-port mode did not open
/// an anti-leak hole: the destination IP is still classified and the dialer still gates egress.
#[tokio::test]
async fn all_ports_still_drops_exit_node_flow_under_direct_dialer() {
    use tokio::io::AsyncWriteExt;

    let (sink_addr, dial_count) = spawn_counting_sink().await;
    let (peer_ch, fwd_ch) = spawn_pair().await;

    // Only a default route is advertised -> the sink IP classifies as ExitNode. All ports are
    // open (a listener exists for the sink port), so any drop must come from the dialer, not a
    // missing listener.
    let routes = RouteTable::new(["0.0.0.0/0".parse().unwrap()]);
    let forwarder =
        Forwarder::new_with_spec(fwd_ch, routes, DirectDialer, PortSpec::All, PortSpec::All);
    tokio::spawn(async move {
        let _ = forwarder.run().await;
    });

    // Retry the connect until the on-demand listener materializes and accepts the flow, so the
    // flow definitely reaches classify → dial. This proves the drop comes from the dialer refusing
    // exit egress, not from the SYN racing the on-demand listener's creation.
    let peer_local = SocketAddr::new(PEER_IP.into(), PEER_PORT);
    let mut client = connect_with_retry(&peer_ch, peer_local, sink_addr).await;
    client.write_all(b"all-ports leak attempt").await.ok();

    // NOTE: fixed sleep retained on purpose — not convertible to a deadline-poll. `connect_with_retry`
    // already proves the on-demand listener accepted the flow (so classify → dial was reached); the
    // remaining wait is a settle for a *negative* assertion (a leaky dial would land *after* accept).
    // There is no positive "flow dropped" signal to poll, and a too-short sleep cannot spuriously
    // fail (the count can only stay 0 or rise). So this is a settle, not a race.
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert_eq!(
        dial_count.load(Ordering::SeqCst),
        0,
        "all-port mode must still refuse an exit-node flow under DirectDialer (anti-leak)"
    );
}

/// Requirement (4): IPv6 inbound is never forwarded. The route table the forwarder consults is
/// v4-only (IPv6-off posture: `Config::advertised_routes` drops every v6 prefix), so any IPv6
/// destination classifies as `None` and the per-port loop drops it before any dial. This guards
/// the forwarder's actual drop gate (`RouteTable::classify`) against an IPv6 destination.
#[tokio::test]
async fn ipv6_destination_is_never_forwarded() {
    // A realistic advertised set: a v4 subnet plus the v4 exit default route. No v6 ever reaches
    // here because advertised_routes() strips it upstream; we assert the gate drops v6 regardless.
    let routes = RouteTable::new(["10.0.0.0/8".parse().unwrap(), "0.0.0.0/0".parse().unwrap()]);

    let v6_dsts = [
        "2001:db8::1".parse().unwrap(),
        "fd7a:115c:a1e0::1".parse().unwrap(),
        "::1".parse().unwrap(),
    ];
    for dst in v6_dsts {
        assert_eq!(
            routes.classify(dst),
            None,
            "IPv6 destination {dst} must never be forwarded (IPv6-off posture)"
        );
    }

    // Sanity: a v4 destination in the same table still classifies (the table isn't simply empty).
    assert!(routes.classify("10.1.2.3".parse().unwrap()).is_some());
}

/// UDP analogue of [`forwarder_splices_subnet_route_to_real_socket`]. The forwarder runs a full
/// parallel UDP relay; this asserts that path end-to-end: a peer sends a UDP datagram over the
/// overlay to a subnet-route (`127.0.0.0/8`) destination, the forwarder classifies it as Subnet,
/// `DirectDialer` opens a real OS UDP socket, the datagram reaches the real echo, and the reply is
/// relayed back over the overlay with the source spoofed as the original destination.
#[tokio::test]
async fn udp_forwarder_splices_subnet_route_to_real_socket() {
    let echo_addr = spawn_udp_echo().await;
    let (peer_ch, fwd_ch) = spawn_pair().await;

    // 127.0.0.0/8 is a (narrow) subnet route -> DirectDialer will dial it over real UDP.
    let routes = RouteTable::new(["127.0.0.0/8".parse().unwrap()]);
    let forwarder = Forwarder::new(fwd_ch, routes, DirectDialer, vec![], vec![echo_addr.port()]);
    tokio::spawn(async move {
        let _ = forwarder.run().await;
    });

    // Peer binds a UDP socket on the overlay and sends to the echo address. UDP is connectionless,
    // so there is no connect handshake to retry against; instead we retransmit the datagram with a
    // bounded poll until the round-trip reply arrives. This both waits out the relay's async
    // `0.0.0.0:port` bind (a fixed sleep would be racy) and tolerates UDP's inherent best-effort
    // delivery, while a bounded deadline still fails a genuinely-never-forwarded regression.
    let peer_local = SocketAddr::new(PEER_IP.into(), PEER_PORT);
    let peer_sock: OverlayUdpSocket = peer_ch.udp_bind(peer_local).await.unwrap();

    let payload = b"hello udp forwarder";
    // Generous round-trip deadline: this is a real-UDP-socket round-trip, and the shared
    // self-hosted CI runner is frequently overloaded, which adds scheduler jitter to every hop
    // (overlay relay bind, real dial, echo, splice-back). A tight 10s deadline produced spurious
    // "never spliced back" failures on unrelated PRs under load; 60s absorbs that jitter. The bound
    // is still finite, so a genuinely-broken forwarder (one that never forwards) still fails here —
    // this only removes false negatives, it does not weaken the regression guard. Do NOT shrink it
    // back: the failures it prevents are load-induced, not logic bugs.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut buf = [0u8; 64];
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "udp datagram was never spliced back from the real echo"
        );

        peer_sock.send_to(echo_addr, payload).await.unwrap();

        // Per-attempt recv timeout widened in proportion to the deadline so retransmit attempts are
        // not starved on a loaded runner (a too-short per-attempt window would burn the budget on
        // spurious retransmits before a slow-but-valid reply lands).
        match tokio::time::timeout(Duration::from_millis(500), peer_sock.recv_from(&mut buf)).await
        {
            Ok(Ok((remote, n))) => {
                assert_eq!(&buf[..n], payload, "echoed payload must round-trip intact");
                // The reply is source-spoofed as the original destination the peer targeted, so
                // it appears to come straight from the echo address.
                assert_eq!(
                    remote, echo_addr,
                    "reply source must be spoofed as the original destination"
                );
                return;
            }
            // Reply not back yet (relay still binding, or datagram dropped): retransmit and poll.
            Ok(Err(_)) | Err(_) => continue,
        }
    }
}

/// UDP analogue of [`exit_node_flow_is_dropped_under_direct_dialer`] — the anti-leak proof for the
/// UDP path. With only a default route (`0.0.0.0/0`) the destination classifies as ExitNode;
/// `DirectDialer` structurally refuses exit egress, so the relay drops the datagram and never
/// opens a real OS socket. A per-port UDP relay DOES exist (the port is explicitly configured), so
/// the drop is proven to come from the dialer, not a missing relay. The counting sink asserts the
/// real socket received ZERO datagrams — a deterministic leak proof, not a wall-clock timeout.
#[tokio::test]
async fn udp_exit_node_flow_is_dropped_under_direct_dialer() {
    let (sink_addr, recv_count) = spawn_udp_counting_sink().await;
    let (peer_ch, fwd_ch) = spawn_pair().await;

    // Only a default route is advertised, so the sink IP (127.0.0.1) classifies as ExitNode.
    // DirectDialer refuses exit egress at dial time -> the relay never opens the real socket.
    let routes = RouteTable::new(["0.0.0.0/0".parse().unwrap()]);
    let forwarder = Forwarder::new(fwd_ch, routes, DirectDialer, vec![], vec![sink_addr.port()]);
    tokio::spawn(async move {
        let _ = forwarder.run().await;
    });

    // Wait for the relay's `0.0.0.0:port` bind to register, then send the datagram repeatedly so
    // the relay definitely observes it (the bind is async; a single too-early datagram could be
    // dropped before the socket exists, masking a real leak). Each datagram reaches the relay's
    // classify -> dial path, which must refuse it.
    let peer_local = SocketAddr::new(PEER_IP.into(), PEER_PORT);
    let peer_sock: OverlayUdpSocket = peer_ch.udp_bind(peer_local).await.unwrap();
    for _ in 0..20 {
        peer_sock.send_to(sink_addr, b"udp leak attempt").await.ok();
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    // NOTE: fixed sleep retained on purpose — not convertible to a deadline-poll. The 20 spaced
    // retransmits above already drive the datagram through the relay's classify → dial path; the
    // remaining wait is a settle for a *negative* assertion (a leaky egress would land *after*
    // those sends). UDP exposes no positive "datagram dropped" signal to poll, and a too-short
    // sleep cannot spuriously fail (the count can only stay 0 or rise). So this is a settle, not a
    // race.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Deterministic anti-leak proof: the real destination received zero datagrams, so the host IP
    // never egressed the exit-node UDP flow.
    assert_eq!(
        recv_count.load(Ordering::SeqCst),
        0,
        "DirectDialer must never egress an exit-node UDP flow (anti-leak)"
    );
}

/// Spawn a peer netstack and a gated all-port forwarder: every packet the peer sends is offered
/// to the forwarder's [`PortGate`] (as the runtime's ingress pump does) instead of being written to
/// the forwarder netstack directly. Returns the peer's channel.
async fn spawn_gated_forwarder<D: RealDialer>(routes: RouteTable, dialer: D) -> Channel {
    spawn_gated_forwarder_with_handle(routes, dialer).await.0
}

/// [`spawn_gated_forwarder`], also returning the forwarder's task.
async fn spawn_gated_forwarder_with_handle<D: RealDialer>(
    routes: RouteTable,
    dialer: D,
) -> (Channel, tokio::task::JoinHandle<()>) {
    let config = netcore::Config::default();
    let (peer_pipe, mut from_peer) = WakingPipe::new(None);
    let (mut to_fwd, fwd_pipe) = WakingPipe::new(None);
    let dev = |pipe| WakingPipeDev {
        pipe,
        mtu: 1500,
        medium: smoltcp::phy::Medium::Ip,
    };
    let mut peer = Netstack::new(dev(peer_pipe), config.clone());
    let mut fwd = Netstack::new(dev(fwd_pipe), config);
    batch_experiments(&mut peer);
    batch_experiments(&mut fwd);
    let peer_ch = peer.command_channel();
    let fwd_ch = fwd.command_channel();
    tokio::spawn(async move { peer.run_tokio().await });
    tokio::spawn(async move { fwd.run_tokio().await });
    peer_ch.set_ips([PEER_IP.into()]).await.unwrap();
    fwd_ch.set_any_ip(true).await.unwrap();

    let (forwarder, gate) = Forwarder::all_ports_gated(fwd_ch, routes, dialer, to_fwd.tx.clone());
    let task = tokio::spawn(async move {
        let _ = forwarder.run().await;
    });

    // Peer -> gate -> forwarder netstack.
    tokio::spawn(async move {
        let batching = ts_netstack_smoltcp::netcore::experiment::enabled(
            ts_netstack_smoltcp::netcore::experiment::RX_BATCH,
        );
        while let Some(p) = from_peer.rx.recv_async().await {
            if batching {
                gate.ingress_with(&p, |p| to_fwd.tx.try_send_deferred(p));
                for _ in 1..64 {
                    let Some(p) = from_peer.rx.try_recv() else {
                        break;
                    };
                    gate.ingress_with(&p, |p| to_fwd.tx.try_send_deferred(p));
                }
                to_fwd.tx.notify_receive();
                tokio::task::yield_now().await;
            } else {
                gate.ingress(&p);
            }
        }
    });
    // Forwarder netstack -> peer.
    let to_peer = from_peer.tx.clone();
    tokio::spawn(async move {
        while let Some(p) = to_fwd.rx.recv_async().await {
            to_peer.send_async(&p).await;
        }
    });
    (peer_ch, task)
}

/// Gated all-port mode: the very first SYN to a cold port is held until the port's listener is
/// up and then accepted, so the connection completes without waiting for a SYN retransmit
/// (smoltcp's, like most clients', is ~1 s). The raw-observer mode loses that SYN.
#[tokio::test]
async fn gated_all_ports_accepts_first_syn_to_cold_port() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let echo_addr = spawn_echo().await;
    let peer_ch = spawn_gated_forwarder(
        RouteTable::new(["127.0.0.0/8".parse().unwrap()]),
        DirectDialer,
    )
    .await;

    let peer_local = SocketAddr::new(PEER_IP.into(), PEER_PORT);
    let start = std::time::Instant::now();
    // A single connect attempt: no retry loop, so a lost first SYN shows up as latency or failure.
    let mut client = tokio::time::timeout(
        Duration::from_secs(10),
        peer_ch.tcp_connect(peer_local, echo_addr),
    )
    .await
    .expect("connect timed out")
    .expect("connect to a cold port must succeed on the first attempt");
    let connect = start.elapsed();
    assert!(
        connect < Duration::from_millis(500),
        "cold-port connect took {connect:?}: the first SYN was not held for the new listener"
    );

    client.write_all(b"gated hello").await.unwrap();
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(60), client.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"gated hello");
}

/// Gated all-port mode, UDP: the first datagram to a cold port is answered (a DNS query or QUIC
/// Initial must not be lost to listener creation).
#[tokio::test]
async fn gated_all_ports_answers_first_datagram_to_cold_port() {
    let echo_addr = spawn_udp_echo().await;
    let peer_ch = spawn_gated_forwarder(
        RouteTable::new(["127.0.0.0/8".parse().unwrap()]),
        DirectDialer,
    )
    .await;

    let peer_local = SocketAddr::new(PEER_IP.into(), PEER_PORT);
    let peer_sock: OverlayUdpSocket = peer_ch.udp_bind(peer_local).await.unwrap();
    peer_sock.send_to(echo_addr, b"first").await.unwrap();

    // Exactly one send: the reply must come back without a retransmit.
    let mut buf = [0u8; 64];
    let (remote, n) = tokio::time::timeout(Duration::from_secs(10), peer_sock.recv_from(&mut buf))
        .await
        .expect("first datagram to a cold port was lost")
        .unwrap();
    assert_eq!(&buf[..n], b"first");
    assert_eq!(remote, echo_addr);
}

/// Gating does not open an anti-leak hole: an exit-node flow under `DirectDialer` is still dropped
/// at dial time, and many parallel cold SYNs to one port open exactly one listener's worth of flows.
#[tokio::test]
async fn gated_all_ports_still_drops_exit_node_flow_under_direct_dialer() {
    use tokio::io::AsyncWriteExt;

    let (sink_addr, dial_count) = spawn_counting_sink().await;
    let peer_ch = spawn_gated_forwarder(
        RouteTable::new(["0.0.0.0/0".parse().unwrap()]),
        DirectDialer,
    )
    .await;

    let peer_local = SocketAddr::new(PEER_IP.into(), PEER_PORT);
    let mut client = connect_with_retry(&peer_ch, peer_local, sink_addr).await;
    client.write_all(b"leak attempt").await.ok();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(dial_count.load(Ordering::SeqCst), 0);
}

/// Cancelling a gated forwarder stops its on-demand listeners too: a port it had opened no
/// longer accepts new connections afterwards (review finding: listener tasks were detached).
#[tokio::test]
async fn cancelling_gated_forwarder_stops_its_listeners() {
    let echo_addr = spawn_echo().await;
    let (peer_ch, task) = spawn_gated_forwarder_with_handle(
        RouteTable::new(["127.0.0.0/8".parse().unwrap()]),
        DirectDialer,
    )
    .await;

    let first = SocketAddr::new(PEER_IP.into(), PEER_PORT);
    let _open = connect_with_retry(&peer_ch, first, echo_addr).await;

    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    // Let the aborted listener's socket close in the netstack.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let second = SocketAddr::new(PEER_IP.into(), PEER_PORT + 1);
    let res = tokio::time::timeout(
        Duration::from_secs(10),
        peer_ch.tcp_connect(second, echo_addr),
    )
    .await;
    assert!(
        !matches!(res, Ok(Ok(_))),
        "a cancelled forwarder's listener still accepted a connection"
    );
}
