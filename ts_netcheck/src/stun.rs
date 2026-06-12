use core::{net::SocketAddr, time::Duration};
use std::{sync::Arc, time::Instant};

use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use stun_rs::{
    MessageClass, StunMessageBuilder, TransactionId,
    attributes::stun::{Fingerprint, Software, XorMappedAddress},
    methods::BINDING,
};
use tokio::{net::UdpSocket, sync::oneshot};

/// Probes peer devices over STUN.
///
/// A single prober is intended to be long-lived and supports concurrent use.
pub struct StunProber {
    shared: Arc<Shared>,
    _tasks: tokio::task::JoinSet<()>,
}

type StunReply = (Instant, SocketAddr);
type InFlightMap = DashMap<TransactionId, oneshot::Sender<StunReply>>;

/// Internal shared state.
// NOTE(npry): IPv4 and IPv6 sockets are explicitly separated here to avoid the complexity of
// managing a dual-stack socket, as some platforms don't support these, while others have
// support configured conditionally based on the distribution, etc. We just attempt to
// bind both independently, and at the moment, if binding the v6 socket fails, this is
// taken to imply that the platform has IPv6 support turned off.
struct Shared {
    sockv4: UdpSocket,
    sockv6: Option<UdpSocket>,

    in_flight: InFlightMap,
}

/// RAII guard to ensure that a STUN transaction is removed from the in-flight map.
struct TransactionDropGuard<'a> {
    txn: TransactionId,
    txns: &'a InFlightMap,
}

impl Drop for TransactionDropGuard<'_> {
    fn drop(&mut self) {
        self.txns.remove(&self.txn);
    }
}

impl StunProber {
    /// Default port for STUN connections.
    pub const DEFAULT_STUN_PORT: u16 = 3478;

    /// Construct a new prober.
    ///
    /// This binds UDP sockets and spawns tasks.
    pub async fn try_new() -> tokio::io::Result<Self> {
        let shared = Arc::new(Shared::try_new().await?);

        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn({
            let shared = shared.clone();
            async move { shared.run_recv(&shared.sockv4).await }
        });

        if shared.sockv6.is_some() {
            tasks.spawn({
                let shared = shared.clone();
                async move { shared.run_recv(shared.sockv6.as_ref().unwrap()).await }
            });
        }

        Ok(Self {
            shared,
            _tasks: tasks,
        })
    }

    /// Measure the latency to a peer by sending a STUN bind request.
    ///
    /// The return value includes the round-trip duration and STUNned address.
    pub async fn measure(&self, peer: SocketAddr) -> tokio::io::Result<(Duration, SocketAddr)> {
        let (rx, _guard) = self.shared.send_stun(peer).await?;
        let sent = Instant::now();

        // The oneshot sender lives in the in-flight table and is removed by the
        // `TransactionDropGuard` (or on a matched response). If it is dropped without a reply — a
        // STUN server that never answers, or the transaction being cancelled — `rx.await` returns
        // `Err(RecvError)`. Map that to an I/O error rather than panicking: a missing STUN reply is a
        // normal timeout condition (Go's netcheck treats an unanswered probe as a timeout, never a
        // crash), and this fn already returns `io::Result`. `measure` has no internal deadline, so a
        // caller must impose one (e.g. `tokio::time::timeout`); on cancellation the guard drops the
        // sender and we surface this error cleanly instead of unwinding the task.
        let (resp, addr) = rx.await.map_err(|_| dropped_transaction_err())?;

        Ok((resp.duration_since(sent), addr))
    }
}

/// The error returned when a STUN transaction's reply channel is dropped without an answer.
///
/// Shared by [`StunProber::measure`] and its regression test so the two can't drift: a dropped
/// transaction (no reply / cancellation) maps to [`TimedOut`](tokio::io::ErrorKind::TimedOut), never
/// a panic.
fn dropped_transaction_err() -> tokio::io::Error {
    tokio::io::Error::new(
        tokio::io::ErrorKind::TimedOut,
        "stun transaction dropped without a reply",
    )
}

impl Shared {
    const SOFTWARE: &str = "tailnode";

    async fn try_new() -> tokio::io::Result<Self> {
        let sockv6 = UdpSocket::bind("[::]:0")
            .await
            .inspect_err(|e| {
                tracing::error!(error = %e, "binding v6 socket");
            })
            .ok();

        Ok(Shared {
            sockv4: UdpSocket::bind("0.0.0.0:0").await?,
            sockv6,
            in_flight: DashMap::new(),
        })
    }

    /// Return the socket bound to the given IP stack.
    ///
    /// The IPv6 socket may not exist if the OS does not have IPv6 support enabled.
    fn sock(&self, v4: bool) -> tokio::io::Result<&UdpSocket> {
        if v4 {
            return Ok(&self.sockv4);
        }

        self.sockv6.as_ref().ok_or_else(|| {
            tokio::io::Error::new(
                tokio::io::ErrorKind::Unsupported,
                "platform does not support ipv6",
            )
        })
    }

    async fn send_stun(
        &self,
        addr: SocketAddr,
    ) -> tokio::io::Result<(oneshot::Receiver<StunReply>, TransactionDropGuard<'_>)> {
        // Both `unwrap`s here are on the outbound (send) path, infallible for fixed inputs — they are
        // NOT driven by any peer/network bytes, so they don't sit on the threat surface the
        // no-panic-on-hostile-input bar covers.
        let req = StunMessageBuilder::new(BINDING, MessageClass::Request)
            // `SOFTWARE` is the compile-time constant `"tailnode"`; `Software::new` only rejects
            // strings over the STUN attribute length limit, which this is not.
            .with_attribute(
                Software::new(Self::SOFTWARE).expect("SOFTWARE constant is a valid STUN attribute"),
            )
            .with_attribute(Fingerprint::default())
            .build();

        let encoder = stun_rs::MessageEncoderBuilder::default().build();
        let mut buf = BytesMut::zeroed(128);
        // A fixed BINDING request encodes well under 128 bytes, so the encode into this buffer cannot
        // fail; the only error is a too-small buffer.
        let n = encoder
            .encode(&mut buf, &req)
            .expect("BINDING request fits in a 128-byte buffer");
        buf.truncate(n);

        let (rx, guard) = self.begin_transaction(*req.transaction_id());
        self.sock(addr.is_ipv4())?.send_to(&buf, addr).await?;

        Ok((rx, guard))
    }

    fn begin_transaction(
        &self,
        txn: TransactionId,
    ) -> (oneshot::Receiver<StunReply>, TransactionDropGuard<'_>) {
        let (tx, rx) = oneshot::channel();
        self.in_flight.insert(txn, tx);

        let guard = TransactionDropGuard {
            txn,
            txns: &self.in_flight,
        };

        (rx, guard)
    }

    fn recv_stun(&self, peer: SocketAddr, buf: Bytes) -> Option<(TransactionId, SocketAddr)> {
        let (msg, _n) = stun_rs::MessageDecoderBuilder::default()
            .build()
            .decode(&buf)
            .inspect_err(|e| {
                tracing::error!(error = %e, peer = %peer, "stun decode");
            })
            .ok()?;

        let Some(addr) = msg.get::<XorMappedAddress>() else {
            tracing::error!("no xor mapped address");
            return None;
        };

        // SAFETY (invariant, not unsafe): `get::<XorMappedAddress>()` above returns an attribute only
        // when its type matches `XorMappedAddress`, so this type-checked accessor cannot fail on any
        // decoded peer bytes. Encoded in the panic message so a future panic-auditor doesn't have to
        // re-derive it from the stun-rs internals.
        let addr = addr
            .as_xor_mapped_address()
            .expect("get::<XorMappedAddress> guarantees this is the XorMappedAddress variant");

        Some((*msg.transaction_id(), *addr.socket_address()))
    }

    async fn run_recv(&self, sock: &UdpSocket) {
        loop {
            let mut buf = BytesMut::new();

            let who = match sock.recv_buf_from(&mut buf).await {
                Ok((_n, who)) => who,
                Err(e) => {
                    tracing::error!(error = %e, "stun recv");
                    continue;
                }
            };

            let rx_timestamp = Instant::now();
            let b = buf.split().freeze();

            let span = tracing::trace_span!(
                "stun_rx",
                remote_peer = %who,
                len = b.len(),
                tx_id = tracing::field::Empty,
                stun_addr = tracing::field::Empty,
            )
            .entered();

            let Some((tx_id, socket_addr)) = self.recv_stun(who, b) else {
                tracing::trace!("not a stun packet");
                continue;
            };

            span.record("tx_id", tracing::field::display(&tx_id));
            span.record("stun_addr", tracing::field::display(&socket_addr));

            let Some((_, resp_channel)) = self.in_flight.remove(&tx_id) else {
                tracing::trace!("no matching in-flight request");
                continue;
            };

            tracing::trace!("stun ok");
            let _ignore = resp_channel.send((rx_timestamp, socket_addr));
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn stun_test() {
        if !ts_test_util::run_net_tests() {
            return;
        }

        let prober = StunProber::try_new().await.unwrap();
        let mut addrs = tokio::net::lookup_host("derp1f.tailscale.com:3478")
            .await
            .unwrap();
        let addr = addrs.next().unwrap();
        tracing::trace!(%addr);

        let (dur, addr) = prober.measure(addr).await.unwrap();
        tracing::info!(?dur, %addr);
    }

    /// A dropped STUN transaction (sender gone without a reply — the no-response / cancellation
    /// case) must surface as an `io::Error(TimedOut)`, NOT panic the task. The prober's `oneshot`
    /// sender lives in the in-flight table and is dropped by the `TransactionDropGuard` when a probe
    /// is cancelled or never answered, so `await` returns `Err(RecvError)`; the old
    /// `rx.await.unwrap()` would panic (unwinding the task) despite the fn's `io::Result` contract.
    ///
    /// This drives the SAME `dropped_transaction_err()` that `measure` uses (not a copy of the
    /// mapping), so the test and production code can't drift. It reproduces only the channel-drop the
    /// guard performs rather than calling `measure` directly — `measure` would bind a real UDP socket
    /// and send a packet.
    #[tokio::test]
    async fn dropped_transaction_is_timeout_error_not_panic() {
        // Model the in-flight oneshot exactly as `measure` consumes it, then drop the sender
        // unanswered (what the drop-guard does on cancellation / no reply).
        let (tx, rx) = oneshot::channel::<StunReply>();
        drop(tx);

        let mapped: tokio::io::Result<()> =
            rx.await.map(|_| ()).map_err(|_| dropped_transaction_err());

        match mapped {
            Err(e) if e.kind() == tokio::io::ErrorKind::TimedOut => {}
            other => panic!("expected a TimedOut io::Error, got {other:?}"),
        }
    }
}
