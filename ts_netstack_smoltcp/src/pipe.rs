use alloc::sync::Arc;
use core::{
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use futures_util::task::AtomicWaker;
use netcore::{
    Pipe, flume, smoltcp,
    smoltcp::{
        phy::{ChecksumCapabilities, DeviceCapabilities, Medium},
        time::Instant,
    },
};

/// Bidirectional pipe carrying byte buffer payloads.
///
/// This is like [`netcore::Pipe`], except that it also implements
/// [`AsyncWakeDevice`][netcore::AsyncWakeDevice], which needs a bit of fiddling to adapt.
pub struct WakingPipe {
    /// The send side of the pipe.
    pub rx: WakingPipeReceiver,
    /// The transmit side of the pipe.
    pub tx: WakingPipeSender,
}

/// A [`flume::Receiver`] wrapped to support [`AsyncWakeDevice`][netcore::AsyncWakeDevice].
///
/// It wakes the remote [`WakingPipeSender`] when a message is received.
pub struct WakingPipeReceiver {
    rx: flume::Receiver<Bytes>,
    /// [`flume::Receiver`] doesn't expose a way to poll until a value is ready without
    /// consuming it. This holds the consumed value.
    buffered_rx: Option<Bytes>,

    /// The waker that this end of the pipe polls on in `poll_rx`.
    ///
    /// It is woken by the remote (tx) end of the pipe when a packet is sent, i.e. the
    /// readiness state of `poll_rx` changes.
    self_waker: Arc<AtomicWaker>,

    /// The waker for the remote (tx) end of the pipe.
    ///
    /// We wake this when we receive a packet (i.e. make room in the pipe). That only
    /// matters if `rx` is a bounded channel.
    remote_waker: Arc<AtomicWaker>,

    /// The byte budget of this direction of the pipe, if it has one. Every packet taken out of
    /// `rx` gives its length back to it.
    budget: Option<Arc<ByteBudget>>,
}

/// A [`flume::Sender`] that wakes a remote [`WakingPipeReceiver`] when a message is sent.
#[derive(Clone)]
pub struct WakingPipeSender {
    tx: flume::Sender<Bytes>,

    /// The waker this end of the pipe polls on in `poll_tx`.
    ///
    /// It is woken by the remote (rx) end of the pipe when a packet is received, i.e. the
    /// readiness state of `poll_tx` changes.
    ///
    /// This only matters if `self.tx` is a bounded channel, otherwise in the unbounded case
    /// we're always ready to send.
    self_waker: Arc<AtomicWaker>,

    /// The waker for the remote (rx) end of the pipe.
    ///
    /// We wake this when we send a packet.
    remote_waker: Arc<AtomicWaker>,

    /// The byte budget of this direction of the pipe, if it has one. Every packet put into `tx`
    /// charges its length to it.
    budget: Option<Arc<ByteBudget>>,
}

/// A cap on the bytes queued in one direction of a [`WakingPipe`], shared by the sender and the
/// receiver of that direction.
///
/// A packet-count bound alone does not cap memory: a packet's buffer is as long as the packet, and
/// what arrives from a peer is not limited to the stack's MTU (a DERP frame carries up to 64 KiB).
#[derive(Debug)]
struct ByteBudget {
    queued: AtomicUsize,
    max: usize,
}

impl ByteBudget {
    /// Charge `len` bytes if that keeps the queue within `max`; report whether it did.
    fn try_charge(&self, len: usize) -> bool {
        self.queued
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |queued| {
                queued.checked_add(len).filter(|&n| n <= self.max)
            })
            .is_ok()
    }

    /// Charge `len` bytes whether or not that exceeds `max`, for the blocking senders, which are
    /// already bounded by the channel's packet count.
    fn charge(&self, len: usize) {
        self.queued.fetch_add(len, Ordering::AcqRel);
    }

    /// Give back `len` bytes previously charged.
    fn release(&self, len: usize) {
        self.queued.fetch_sub(len, Ordering::AcqRel);
    }
}

fn charge(budget: &Option<Arc<ByteBudget>>, len: usize) {
    if let Some(budget) = budget {
        budget.charge(len);
    }
}

fn release(budget: &Option<Arc<ByteBudget>>, len: usize) {
    if let Some(budget) = budget {
        budget.release(len);
    }
}

impl WakingPipe {
    /// Construct a new pipe with the given optional capacity `limit`.
    pub fn new(limit: Option<usize>) -> (Self, Self) {
        if let Some(limit) = limit {
            Self::bounded(limit)
        } else {
            Self::unbounded()
        }
    }

    /// Construct a new unbounded pipe.
    pub fn unbounded() -> (Self, Self) {
        let (pipe1, pipe2) = Pipe::unbounded();

        Self::_new(pipe1, pipe2)
    }

    /// Construct a new pipe that can carry at most `limit` packets.
    pub fn bounded(limit: usize) -> (Self, Self) {
        let (pipe1, pipe2) = Pipe::bounded(limit);

        Self::_new(pipe1, pipe2)
    }

    /// Construct a pipe for a netstack device whose *ingress* is bounded and whose *egress* is not.
    ///
    /// The first end is the device's, the second the caller's. The caller-to-device direction holds
    /// at most `max_packets` packets and `max_bytes` bytes, and
    /// [`try_send`](WakingPipeSender::try_send) refuses a packet that would exceed either — the
    /// shape of a NIC rx ring, which drops when full. The device-to-caller direction stays
    /// unbounded: smoltcp emits through [`TxToken::consume`](smoltcp::phy::TxToken::consume),
    /// which is synchronous and cannot wait, so a full egress queue would stall the stack's poll
    /// loop rather than shed load.
    pub fn ingress_bounded(max_packets: usize, max_bytes: usize) -> (Self, Self) {
        let (to_device, device_rx) = flume::bounded(max_packets);
        let (device_tx, from_device) = flume::unbounded();

        let budget = Arc::new(ByteBudget {
            queued: AtomicUsize::new(0),
            max: max_bytes,
        });

        let (mut device, mut caller) = Self::_new(
            Pipe {
                tx: device_tx,
                rx: device_rx,
            },
            Pipe {
                tx: to_device,
                rx: from_device,
            },
        );
        device.rx.budget = Some(budget.clone());
        caller.tx.budget = Some(budget);

        (device, caller)
    }

    fn _new(pipe1: Pipe, pipe2: Pipe) -> (Self, Self) {
        let pipe1_rx_waker = Arc::new(AtomicWaker::new());
        let pipe2_rx_waker = Arc::new(AtomicWaker::new());

        let pipe1_tx_waker = Arc::new(AtomicWaker::new());
        let pipe2_tx_waker = Arc::new(AtomicWaker::new());

        (
            Self {
                rx: WakingPipeReceiver {
                    rx: pipe1.rx,
                    buffered_rx: None,
                    self_waker: pipe1_rx_waker.clone(),
                    remote_waker: pipe2_tx_waker.clone(),
                    budget: None,
                },
                tx: WakingPipeSender {
                    tx: pipe1.tx,
                    remote_waker: pipe2_rx_waker.clone(),
                    self_waker: pipe1_tx_waker.clone(),
                    budget: None,
                },
            },
            Self {
                rx: WakingPipeReceiver {
                    rx: pipe2.rx,
                    buffered_rx: None,
                    self_waker: pipe2_rx_waker,
                    remote_waker: pipe1_tx_waker,
                    budget: None,
                },
                tx: WakingPipeSender {
                    tx: pipe2.tx,
                    remote_waker: pipe1_rx_waker,
                    self_waker: pipe2_tx_waker,
                    budget: None,
                },
            },
        )
    }
}

impl WakingPipeReceiver {
    /// Receive a packet.
    pub fn recv(&mut self) -> Option<Bytes> {
        if let Some(buf) = self.buffered_rx.take() {
            return Some(buf);
        }

        let ret = self.rx.recv().ok();
        self.taken(ret.as_ref());

        ret
    }

    /// Receive a packet asynchronously.
    pub async fn recv_async(&mut self) -> Option<Bytes> {
        if let Some(buf) = self.buffered_rx.take() {
            return Some(buf);
        }

        let ret = self.rx.recv_async().await.ok();
        self.taken(ret.as_ref());

        ret
    }

    /// Receive a packet if it's possible to do so without blocking.
    pub fn try_recv(&mut self) -> Option<Bytes> {
        if let Some(buf) = self.buffered_rx.take() {
            return Some(buf);
        }

        let ret = self.rx.recv().ok();
        self.taken(ret.as_ref());

        ret
    }

    /// Report whether there is a packet ready to be received.
    pub fn rx_ready(&self) -> bool {
        self.buffered_rx.is_some() || !self.rx.is_empty()
    }

    /// Account for a packet just taken out of the channel: give its bytes back to the budget and
    /// wake the sender, which may now have room.
    fn taken(&self, buf: Option<&Bytes>) {
        if let Some(buf) = buf {
            release(&self.budget, buf.len());
        }
        self.remote_waker.wake();
    }
}

impl WakingPipeSender {
    /// Send a packet, blocking until complete.
    pub fn send(&self, buf: &[u8]) {
        charge(&self.budget, buf.len());
        if let Err(_e) = self.tx.send(Bytes::copy_from_slice(buf)) {
            release(&self.budget, buf.len());
            tracing::warn!("send dropped: remote end of pipe is gone");
            return;
        }

        self.remote_waker.wake();
    }

    /// Send a packet asynchronously.
    pub async fn send_async(&self, buf: &[u8]) {
        charge(&self.budget, buf.len());
        if let Err(_e) = self.tx.send_async(Bytes::copy_from_slice(buf)).await {
            release(&self.budget, buf.len());
            tracing::warn!("send dropped: remote end of pipe is gone");
            return;
        }

        self.remote_waker.wake();
    }

    /// Send a packet if it's possible to do so without blocking.
    ///
    /// Returns whether the packet was actually sent. On a pipe built by
    /// [`WakingPipe::ingress_bounded`], a packet that would take the queue past its byte budget is
    /// refused the same way as one that finds the queue full.
    pub fn try_send(&self, buf: &[u8]) -> bool {
        if let Some(budget) = &self.budget
            && !budget.try_charge(buf.len())
        {
            return false;
        }

        match self.tx.try_send(Bytes::copy_from_slice(buf)) {
            Ok(()) => {
                self.remote_waker.wake();
                true
            }
            Err(flume::TrySendError::Full(..)) => {
                release(&self.budget, buf.len());
                false
            }
            Err(flume::TrySendError::Disconnected(..)) => {
                release(&self.budget, buf.len());
                tracing::warn!("send dropped: remote end of pipe is gone");

                // Semantically, that the remote end was dropped can be thought of as deciding to
                // ignore all of our messages
                true
            }
        }
    }

    /// Report whether we can currently transmit.
    pub fn tx_ready(&self) -> bool {
        !self.tx.is_full()
    }
}

impl netcore::AsyncWakeDevice for WakingPipeDev {
    #[tracing::instrument(name = "WakingPipeDev::poll_tx", skip_all, level = "trace", ret)]
    fn poll_tx<'cx>(self: Pin<&mut Self>, cx: &mut Context<'cx>) -> Poll<()> {
        self.pipe.tx.self_waker.register(cx.waker());

        if self.pipe.tx.tx_ready() {
            return Poll::Ready(());
        }

        Poll::Pending
    }

    #[tracing::instrument(name = "WakingPipeDev::poll_rx", skip_all, level = "trace", ret)]
    fn poll_rx<'cx>(mut self: Pin<&mut Self>, cx: &mut Context<'cx>) -> Poll<()> {
        self.pipe.rx.self_waker.register(cx.waker());

        if self.pipe.rx.rx_ready() {
            // Check tx readiness so that we return Poll::Ready when Device::receive is actually
            // ready, which only occurs when both TxToken and RxToken can be constructed.
            core::task::ready!(self.as_mut().poll_tx(cx));

            return Poll::Ready(());
        }

        Poll::Pending
    }
}

impl smoltcp::phy::TxToken for WakingPipeSender {
    #[tracing::instrument(
        name = "WakingPipeSender::consume",
        skip_all,
        fields(len),
        level = "trace"
    )]
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut b = BytesMut::zeroed(len);

        let ret = f(&mut b);
        charge(&self.budget, len);
        if self.tx.send(b.freeze()).is_err() {
            release(&self.budget, len);
            tracing::warn!("remote end of dropped on send");
        }

        self.remote_waker.wake();

        ret
    }
}

pub struct RxToken(Bytes);

impl smoltcp::phy::RxToken for RxToken {
    #[tracing::instrument(name = "WakingPipeRx::consume", skip_all, level = "trace")]
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

/// Wrapper around [`WakingPipe`] to implement [`smoltcp::phy::Device`].
///
/// Like [`netcore::PipeDev`] except that it implements
/// [`AsyncWakeDevice`][netcore::AsyncWakeDevice].
pub struct WakingPipeDev {
    /// End of a pipe that will be directly connected to the netstack, receiving packets
    /// to be sent and supplying packets to be received.
    pub pipe: WakingPipe,

    /// The type of network frame the pipe will carry.
    ///
    /// For our purposes, this will typically be [`Medium::Ip`].
    pub medium: Medium,
    /// The maximum packet size to be transmitted through the pipe.
    ///
    /// The implementation does not check or limit the actual size of packets flowing
    /// through it, this field is just informational for
    /// [`smoltcp::phy::Device::capabilities`].
    pub mtu: usize,
}

impl smoltcp::phy::Device for WakingPipeDev {
    type RxToken<'a>
        = RxToken
    where
        Self: 'a;

    type TxToken<'a>
        = WakingPipeSender
    where
        Self: 'a;

    #[tracing::instrument(skip(self), level = "trace")]
    fn receive(&mut self, timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let tx = self.transmit(timestamp)?;

        let b = if let Some(buf) = self.pipe.rx.buffered_rx.take() {
            buf
        } else {
            let buf = self.pipe.rx.rx.try_recv().ok()?;
            release(&self.pipe.rx.budget, buf.len());
            buf
        };

        Some((RxToken(b), tx))
    }

    #[tracing::instrument(skip(self), level = "trace")]
    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        if self.pipe.tx.tx.is_disconnected() {
            return None;
        }

        Some(self.pipe.tx.clone())
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();

        caps.max_transmission_unit = self.mtu;
        caps.medium = self.medium;
        caps.checksum = ChecksumCapabilities::ignored();

        caps
    }
}

#[cfg(test)]
mod tests {
    use netcore::smoltcp::phy::{Device, RxToken as _, TxToken as _};

    use super::*;

    fn device(pipe: WakingPipe) -> WakingPipeDev {
        WakingPipeDev {
            pipe,
            medium: Medium::Ip,
            mtu: 1280,
        }
    }

    /// Hand the device one packet and report its length, as the netstack's poll loop would.
    fn device_takes(dev: &mut WakingPipeDev) -> Option<usize> {
        let (rx, _tx) = dev.receive(Instant::from_millis(0))?;
        Some(rx.consume(|buf| buf.len()))
    }

    /// The ingress direction refuses past its packet count, and taking a packet makes room again.
    #[test]
    fn ingress_refuses_past_packet_count() {
        let (dev, caller) = WakingPipe::ingress_bounded(2, usize::MAX);
        let mut dev = device(dev);

        assert!(caller.tx.try_send(&[1]));
        assert!(caller.tx.try_send(&[2]));
        assert!(
            !caller.tx.try_send(&[3]),
            "a third packet overflows the ring"
        );

        assert_eq!(device_takes(&mut dev), Some(1));
        assert!(caller.tx.try_send(&[4]), "taking a packet frees its slot");
    }

    /// The ingress direction refuses a packet that would exceed its byte budget, even with free
    /// slots, and the device taking a packet gives its bytes back.
    #[test]
    fn ingress_refuses_past_byte_budget() {
        let (dev, caller) = WakingPipe::ingress_bounded(100, 3000);
        let mut dev = device(dev);

        assert!(caller.tx.try_send(&[0; 1000]));
        assert!(caller.tx.try_send(&[0; 1000]));
        assert!(
            !caller.tx.try_send(&[0; 1001]),
            "would be 3001 bytes queued"
        );
        assert!(caller.tx.try_send(&[0; 1000]), "exactly at the budget fits");
        assert!(!caller.tx.try_send(&[0; 1]));

        assert_eq!(device_takes(&mut dev), Some(1000));
        assert!(
            caller.tx.try_send(&[0; 1000]),
            "taking a packet frees its bytes"
        );
        assert!(!caller.tx.try_send(&[0; 1]));
    }

    /// A refused packet charges nothing: refusals on a full ring must not leak budget, or the queue
    /// would eventually refuse everything.
    #[test]
    fn refused_packet_does_not_consume_budget() {
        let (dev, caller) = WakingPipe::ingress_bounded(1, 1000);
        let mut dev = device(dev);

        assert!(caller.tx.try_send(&[0; 10]));
        for _ in 0..1000 {
            assert!(!caller.tx.try_send(&[0; 10]), "the one slot is taken");
        }

        assert_eq!(device_takes(&mut dev), Some(10));
        assert!(
            caller.tx.try_send(&[0; 1000]),
            "the whole budget is free again"
        );
    }

    /// The egress direction stays unbounded: smoltcp's `TxToken::consume` cannot wait, so a bounded
    /// egress would block the stack's poll loop. Emitting far past the ingress limits must neither
    /// block nor drop.
    #[test]
    fn egress_is_not_bounded() {
        let (dev, mut caller) = WakingPipe::ingress_bounded(2, 100);
        let mut dev = device(dev);

        for i in 0..1000u32 {
            let tx = dev
                .transmit(Instant::from_millis(0))
                .expect("egress is always ready");
            tx.consume(1280, |buf| buf[..4].copy_from_slice(&i.to_be_bytes()));
        }

        for i in 0..1000u32 {
            let buf = caller.rx.recv().expect("every emitted packet is delivered");
            assert_eq!(buf.len(), 1280);
            assert_eq!(buf[..4], i.to_be_bytes());
        }
    }
}
