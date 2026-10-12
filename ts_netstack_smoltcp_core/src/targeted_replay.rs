//! Opt-in readiness replay. One waker fans out to the FIFO for a socket generation.
use alloc::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    task::Wake,
    vec::Vec,
};
use core::{
    sync::atomic::{AtomicBool, Ordering},
    task::Waker,
};

use smoltcp::{
    iface::SocketHandle,
    socket::{tcp, udp},
    time::{Duration, Instant},
};

use crate::{Command, Error, Netstack, Request, pipeline_metrics::Metric, registry::SocketKind};

const SWEEP_INTERVAL: Duration = Duration::from_millis(50);
type Key = (SocketHandle, u64);

// The atomic bit and notification channel form a shared, deduplicated dirty set. There is no
// stack pointer in a waker: late notifications are harmless and generation-checked by the map.
struct DirtyWake {
    key: Key,
    dirty: AtomicBool,
    tx: flume::Sender<Key>,
}
impl Wake for DirtyWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        if !self.dirty.swap(true, Ordering::AcqRel) {
            let _ = self.tx.send(self.key);
        }
    }
}
struct Waiters {
    requests: VecDeque<Request>,
    signal: Arc<DirtyWake>,
    waker: Waker,
    replaying: bool,
}
pub(super) struct TargetedReplay {
    queues: BTreeMap<Key, Waiters>,
    tx: flume::Sender<Key>,
    rx: flume::Receiver<Key>,
    pub(super) next_sweep: Instant,
    pub(super) pending_queues: usize,
}
#[cfg(feature = "std")]
fn enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var("TS_EXPERIMENT_TARGETED_REPLAY").as_deref() == Ok("1"))
}
#[cfg(not(feature = "std"))]
fn enabled() -> bool {
    false
}
impl TargetedReplay {
    pub(super) fn from_env(now: Instant) -> Option<Self> {
        enabled().then(|| Self::new(now))
    }
    fn new(now: Instant) -> Self {
        let (tx, rx) = flume::unbounded();
        Self {
            pending_queues: 0,
            queues: BTreeMap::new(),
            tx,
            rx,
            next_sweep: now + SWEEP_INTERVAL,
        }
    }
}
impl Netstack {
    pub(super) fn enqueue_targeted(
        &mut self,
        req: Request,
        generation: Option<u64>,
    ) -> Result<(), Request> {
        let (Some(handle), Some(generation), Some(replay)) =
            (req.handle, generation, self.targeted_replay.as_mut())
        else {
            return Err(req);
        };
        let (rx, tx, kind) = match &req.command {
            Command::TcpStream(crate::tcp::stream::Command::Recv { .. }) => {
                (true, false, SocketKind::Tcp)
            }
            Command::TcpStream(crate::tcp::stream::Command::Send { .. }) => {
                (false, true, SocketKind::Tcp)
            }
            Command::TcpStream(crate::tcp::stream::Command::Connect { .. }) => {
                (true, true, SocketKind::Tcp)
            }
            Command::Udp(crate::udp::Command::Recv { .. }) => (true, false, SocketKind::Udp),
            Command::Udp(crate::udp::Command::Send { .. }) => (false, true, SocketKind::Udp),
            _ => return Err(req),
        };
        self.metrics.record(Metric::ValidationLookups, 1);
        if !self
            .socket_registry
            .get(&handle)
            .is_some_and(|e| e.kind == kind && e.generation == generation)
        {
            return Err(req);
        }
        let queue = replay
            .queues
            .entry((handle, generation))
            .or_insert_with(|| {
                let signal = Arc::new(DirtyWake {
                    key: (handle, generation),
                    dirty: AtomicBool::new(false),
                    tx: replay.tx.clone(),
                });
                Waiters {
                    replaying: false,
                    requests: VecDeque::new(),
                    waker: Waker::from(signal.clone()),
                    signal,
                }
            });
        if queue.requests.is_empty() && !queue.replaying {
            replay.pending_queues += 1;
        }
        // Cancellation has no socket wake. Purge on enqueue as well as on the safety sweep,
        // bounding timeout/retry growth even on a socket that never receives anything.
        if !queue.replaying {
            queue
                .requests
                .retain(|r| !(r.command.is_receive() && r.resp.is_disconnected()));
        }
        if kind == SocketKind::Tcp {
            let socket = self.socket_set.get_mut::<tcp::Socket>(handle);
            if rx {
                socket.register_recv_waker(&queue.waker);
            }
            if tx {
                socket.register_send_waker(&queue.waker);
            }
        } else {
            let socket = self.socket_set.get_mut::<udp::Socket>(handle);
            if rx {
                socket.register_recv_waker(&queue.waker);
            }
            if tx {
                socket.register_send_waker(&queue.waker);
            }
        }
        queue.requests.push_back(req);
        Ok(())
    }

    pub(super) fn remove_targeted_queue(&mut self, handle: SocketHandle) {
        if let Some(replay) = &mut self.targeted_replay {
            self.metrics.record(Metric::ValidationLookups, 1);
            let Some(generation) = self.socket_registry.get(&handle).map(|e| e.generation) else {
                return;
            };
            if let Some(queue) = replay.queues.remove(&(handle, generation)) {
                if !queue.requests.is_empty() || queue.replaying {
                    replay.pending_queues -= 1;
                }
                for req in queue.requests {
                    if !(req.command.is_receive() && req.resp.is_disconnected()) {
                        drop(req.resp.send(Error::missing_socket().into()));
                    }
                }
            }
        }
    }

    pub(super) fn pump_targeted_commands(&mut self) {
        // Snapshot notifications before execution: a replay may itself trigger another wake.
        // Leave that wake for the next pump instead of spinning on spurious readiness.
        let Some(replay) = &mut self.targeted_replay else {
            return;
        };
        let keys: Vec<_> = replay.rx.try_iter().collect();
        for key in keys {
            let Some(queue) = self.targeted_replay.as_ref().unwrap().queues.get(&key) else {
                continue;
            };
            queue.signal.dirty.store(false, Ordering::Release);
            if queue.requests.is_empty() {
                continue;
            }
            self.metrics.record(Metric::DirtyHandlesPumped, 1);
            self.replay_targeted_queue(key, false);
        }
    }

    fn replay_targeted_queue(&mut self, key: Key, safety_net: bool) {
        let count = self
            .targeted_replay
            .as_ref()
            .unwrap()
            .queues
            .get(&key)
            .map_or(0, |q| q.requests.len());
        if let Some(queue) = self.targeted_replay.as_mut().unwrap().queues.get_mut(&key) {
            queue.replaying = true;
        }
        // Take exactly the original count. Requeues append in FIFO order and rearm the same
        // cached waker, including when several commands wait on the same direction.
        for _ in 0..count {
            let req = self
                .targeted_replay
                .as_mut()
                .unwrap()
                .queues
                .get_mut(&key)
                .and_then(|q| q.requests.pop_front());
            let Some(req) = req else {
                break;
            };
            if req.command.is_receive() && req.resp.is_disconnected() {
                continue;
            }
            if self.handle_gen(key.0) != Some(key.1) {
                drop(req.resp.send(Error::missing_socket().into()));
                continue;
            }
            self.metrics.record(Metric::ReplayAttempts, 1);
            self.metrics.record(
                if safety_net {
                    Metric::SafetyNetAttempts
                } else {
                    Metric::TargetedReplayAttempts
                },
                1,
            );
            // Brief 13 reclaims rx-empty reset connects before their next global replay.
            // Readiness may arrive earlier; preserve missing_socket instead of changing the
            // public result to ConnectionReset simply because this experiment is enabled.
            let completed = if matches!(
                req.command,
                Command::TcpStream(crate::tcp::stream::Command::Connect { .. })
            ) && self.socket_matches::<tcp::Socket>(key.0)
                && {
                    let sock = self.socket_set.get::<tcp::Socket>(key.0);
                    sock.state() == tcp::State::Closed && !sock.can_recv()
                } {
                self.remove_socket(key.0);
                drop(req.resp.send(Error::missing_socket().into()));
                true
            } else {
                self.execute_cmd(req)
            };
            if completed {
                self.metrics.record(Metric::ReplayCompletions, 1);
                self.metrics.record(
                    if safety_net {
                        Metric::SafetyNetCompletions
                    } else {
                        Metric::TargetedReplayCompletions
                    },
                    1,
                );
            }
        }
        let replay = self.targeted_replay.as_mut().unwrap();
        if let Some(queue) = replay.queues.get_mut(&key) {
            queue.replaying = false;
        }
        if count > 0
            && replay
                .queues
                .get(&key)
                .is_some_and(|q| q.requests.is_empty())
        {
            replay.pending_queues -= 1;
            // Retain the empty FIFO and cached waker until socket removal, avoiding per-packet
            // Arc, map-node and deque allocations. Empty entries do not arm maintenance.
            self.metrics.record(Metric::ValidationLookups, 1);
            if self
                .socket_registry
                .get(&key.0)
                .is_none_or(|e| e.generation != key.1)
            {
                replay.queues.remove(&key);
            }
        }
    }

    pub(super) fn service_replay_deadline(&mut self, now: Instant) {
        self.pump_targeted_commands();
        let Some(replay) = &mut self.targeted_replay else {
            return;
        };
        if now < replay.next_sweep {
            return;
        }
        replay.next_sweep = now + SWEEP_INTERVAL;
        if replay.pending_queues == 0 {
            return;
        }
        self.metrics.record(Metric::SafetyNetSweeps, 1);
        let keys: Vec<_> = replay
            .queues
            .iter()
            .filter_map(|(&key, q)| (!q.requests.is_empty()).then_some(key))
            .collect();
        for key in keys {
            self.replay_targeted_queue(key, true);
        }
    }
}

#[cfg(test)]
mod tests {
    use core::net::SocketAddr;

    use bytes::Bytes;

    use super::*;
    use crate::{
        Config, Pipe, PipeDev, Response,
        tcp::{listen, stream},
    };

    pub(super) fn request(
        stack: &mut Netstack,
        handle: Option<SocketHandle>,
        command: impl Into<Command>,
    ) -> flume::Receiver<Response> {
        let (resp, rx) = flume::bounded(1);
        stack.process_one_cmd(Request {
            handle,
            command: command.into(),
            resp,
        });
        rx
    }
    pub(super) fn stack() -> Netstack {
        let mut stack = Netstack::new(
            Config {
                loopback: true,
                tcp_buffer_size: 64,
                ..Config::default()
            },
            Instant::ZERO,
        );
        stack.targeted_replay = Some(TargetedReplay::new(Instant::ZERO));
        stack
    }
    pub(super) fn dev() -> PipeDev {
        let (tx, rx) = flume::unbounded();
        PipeDev {
            pipe: Pipe { tx, rx },
            medium: smoltcp::phy::Medium::Ip,
            mtu: 1536,
        }
    }
    pub(super) fn endpoint(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }
    pub(super) fn pump(stack: &mut Netstack, dev: &mut PipeDev, now: Instant) {
        // Advancing the packet timestamp explicitly covers smoltcp's delayed ACK timer.
        for _ in 0..64 {
            stack.poll_device_io(now, dev);
            if dev.pipe.rx.is_empty() {
                break;
            }
        }
    }
    pub(super) fn pair() -> (Netstack, PipeDev, SocketHandle, SocketHandle) {
        pair_with_buffer(64)
    }

    pub(super) fn pair_with_buffer(size: usize) -> (Netstack, PipeDev, SocketHandle, SocketHandle) {
        let mut stack = stack();
        stack.config.tcp_buffer_size = size;
        let mut dev = dev();
        let listener = match request(
            &mut stack,
            None,
            listen::Command::Listen {
                local_endpoint: endpoint(80),
            },
        )
        .try_recv()
        .unwrap()
        {
            Response::TcpListen(listen::Response::Listening { handle }) => handle,
            r => panic!("{r:?}"),
        };
        // An accept remains on the always-replayed queue while connect is targeted.
        let accept = request(
            &mut stack,
            None,
            listen::Command::Accept { handle: listener },
        );
        let connect = request(
            &mut stack,
            None,
            stream::Command::Connect {
                local_endpoint: endpoint(50000),
                remote_endpoint: endpoint(80),
            },
        );
        assert_eq!(stack.targeted_replay.as_ref().unwrap().queues.len(), 1);
        pump(&mut stack, &mut dev, Instant::ZERO);
        let client = match connect.try_recv().unwrap() {
            Response::TcpStream(stream::Response::Connected { handle }) => handle,
            r => panic!("{r:?}"),
        };
        let server = match accept.try_recv().unwrap() {
            Response::TcpListen(listen::Response::Accepted { handle, .. }) => handle,
            r => panic!("{r:?}"),
        };
        assert_eq!(stack.metrics.counts().targeted_replay_completions, 1);
        assert_eq!(stack.metrics.counts().safety_net_sweeps, 0);
        (stack, dev, client, server)
    }
    pub(super) fn assert_recv(rx: &flume::Receiver<Response>, bytes: &[u8]) {
        match rx.try_recv().unwrap() {
            Response::TcpStream(stream::Response::Recv { buf }) => assert_eq!(&buf[..], bytes),
            r => panic!("{r:?}"),
        }
    }

    #[test]
    fn connect_completion_is_targeted_and_accept_stays_global() {
        pair();
    }

    #[test]
    fn data_arrival_completes_recv_and_fifo_waiters_without_sweep() {
        let (mut stack, mut dev, client, server) = pair();
        let first = request(
            &mut stack,
            Some(server),
            stream::Command::Recv { max_len: Some(1) },
        );
        let second = request(
            &mut stack,
            Some(server),
            stream::Command::Recv { max_len: Some(1) },
        );
        let third = request(
            &mut stack,
            Some(server),
            stream::Command::Recv { max_len: Some(1) },
        );
        let before = stack.metrics.counts().targeted_replay_attempts;
        for _ in 0..20 {
            stack.pump_waiters();
        }
        assert_eq!(stack.metrics.counts().targeted_replay_attempts, before);
        request(
            &mut stack,
            Some(client),
            stream::Command::Send {
                buf: Bytes::from_static(b"ab"),
            },
        )
        .try_recv()
        .unwrap();
        pump(&mut stack, &mut dev, Instant::ZERO);
        assert_recv(&first, b"a");
        assert_recv(&second, b"b");
        assert!(third.is_empty());
        // The remaining receive was rearmed after the one-shot wake.
        request(
            &mut stack,
            Some(client),
            stream::Command::Send {
                buf: Bytes::from_static(b"c"),
            },
        )
        .try_recv()
        .unwrap();
        pump(&mut stack, &mut dev, Instant::from_millis(10));
        assert_recv(&third, b"c");
        assert_eq!(stack.metrics.counts().safety_net_sweeps, 0);
        assert_eq!(stack.metrics.counts().targeted_replay_completions, 4);
    }

    #[test]
    fn ack_freeing_tx_space_completes_blocked_send() {
        let (mut stack, mut dev, client, server) = pair();
        request(
            &mut stack,
            Some(client),
            stream::Command::Send {
                buf: Bytes::from(alloc::vec![b'x'; 64]),
            },
        )
        .try_recv()
        .unwrap();
        assert!(!stack.socket_set.get::<tcp::Socket>(client).can_send());
        let blocked = request(
            &mut stack,
            Some(client),
            stream::Command::Send {
                buf: Bytes::from_static(b"y"),
            },
        );
        assert!(blocked.is_empty());
        // smoltcp delays the ACK by 10 ms; TX remains full until that wire ACK arrives.
        pump(&mut stack, &mut dev, Instant::ZERO);
        assert!(blocked.is_empty());
        pump(&mut stack, &mut dev, Instant::from_millis(10));
        assert!(matches!(
            blocked.try_recv(),
            Ok(Response::TcpStream(stream::Response::Sent { n: 1 }))
        ));
        assert_eq!(stack.metrics.counts().safety_net_completions, 0);
        assert_eq!(stack.metrics.counts().safety_net_sweeps, 0);
        assert_eq!(stack.metrics.counts().targeted_replay_completions, 2);
        assert_eq!(stack.socket_set.get::<tcp::Socket>(server).recv_queue(), 64);
    }

    #[test]
    fn remote_fin_completes_recv_with_finished() {
        let (mut stack, mut dev, client, server) = pair();
        let recv = request(
            &mut stack,
            Some(server),
            stream::Command::Recv { max_len: None },
        );
        request(&mut stack, Some(client), stream::Command::ShutdownWrite)
            .try_recv()
            .unwrap();
        pump(&mut stack, &mut dev, Instant::ZERO);
        assert!(matches!(
            recv.try_recv(),
            Ok(Response::TcpStream(stream::Response::Finished))
        ));
        assert_eq!(stack.metrics.counts().safety_net_sweeps, 0);
    }

    #[test]
    fn remote_reset_and_local_close_unblock_without_sweep() {
        let (mut stack, mut dev, client, server) = pair();
        let recv = request(
            &mut stack,
            Some(server),
            stream::Command::Recv { max_len: None },
        );
        stack.socket_set.get_mut::<tcp::Socket>(client).abort();
        pump(&mut stack, &mut dev, Instant::ZERO);
        assert!(matches!(
            recv.try_recv(),
            Ok(Response::Error(_)) | Ok(Response::TcpStream(stream::Response::Finished))
        ));
        assert_eq!(stack.metrics.counts().safety_net_sweeps, 0);

        let (mut stack, _, client, _) = pair();
        request(
            &mut stack,
            Some(client),
            stream::Command::Send {
                buf: Bytes::from(alloc::vec![0; 64]),
            },
        )
        .try_recv()
        .unwrap();
        let send = request(
            &mut stack,
            Some(client),
            stream::Command::Send {
                buf: Bytes::from_static(b"z"),
            },
        );
        let close = request(&mut stack, Some(client), stream::Command::Close);
        assert!(matches!(close.try_recv(), Ok(Response::Ok)));
        stack.pump_waiters();
        assert!(matches!(send.try_recv(), Ok(Response::Error(_))));
        assert_eq!(stack.metrics.counts().safety_net_sweeps, 0);
    }

    pub(super) fn bind(stack: &mut Netstack, port: u16) -> SocketHandle {
        match request(
            stack,
            None,
            crate::udp::Command::Bind {
                endpoint: endpoint(port),
            },
        )
        .try_recv()
        .unwrap()
        {
            Response::Udp(crate::udp::Response::Bound { handle, .. }) => handle,
            r => panic!("{r:?}"),
        }
    }
    #[test]
    fn removal_answers_missing_socket_and_late_wake_cannot_cross_generation() {
        let mut stack = stack();
        let handle = bind(&mut stack, 1000);
        let old_key = (handle, stack.handle_gen(handle).unwrap());
        let recv = request(
            &mut stack,
            Some(handle),
            crate::udp::Command::Recv { max_len: None },
        );
        let old_waker = stack.targeted_replay.as_ref().unwrap().queues[&old_key]
            .waker
            .clone();
        request(&mut stack, Some(handle), crate::udp::Command::Close)
            .try_recv()
            .unwrap();
        assert!(matches!(
            recv.try_recv(),
            Ok(Response::Error(crate::Error::Internal(
                crate::InternalErrorKind::BadSocketHandle
            )))
        ));
        assert_eq!(stack.targeted_replay.as_ref().unwrap().pending_queues, 0);
        let reused = bind(&mut stack, 1000);
        assert_eq!(handle, reused);
        let new_recv = request(
            &mut stack,
            Some(reused),
            crate::udp::Command::Recv { max_len: None },
        );
        old_waker.wake();
        stack.pump_waiters();
        assert!(new_recv.is_empty());
        assert_eq!(stack.metrics.counts().targeted_replay_attempts, 0);
    }
    #[test]
    fn generation_guard_also_rejects_a_stale_queue() {
        let mut stack = stack();
        let handle = bind(&mut stack, 1000);
        let recv = request(
            &mut stack,
            Some(handle),
            crate::udp::Command::Recv { max_len: None },
        );
        stack.socket_registry.get_mut(&handle).unwrap().generation += 1;
        stack.service_replay_deadline(Instant::from_millis(50));
        assert!(matches!(
            recv.try_recv(),
            Ok(Response::Error(crate::Error::Internal(
                crate::InternalErrorKind::BadSocketHandle
            )))
        ));
        assert_eq!(stack.metrics.counts().safety_net_attempts, 0);
    }

    #[test]
    fn canceled_receives_are_bounded_on_enqueue_and_purged_by_sweep() {
        let mut stack = stack();
        let handle = bind(&mut stack, 1000);
        for _ in 0..1000 {
            let recv = request(
                &mut stack,
                Some(handle),
                crate::udp::Command::Recv { max_len: None },
            );
            let replay = stack.targeted_replay.as_ref().unwrap();
            assert_eq!(replay.queues.values().next().unwrap().requests.len(), 1);
            drop(recv);
        }
        stack.service_replay_deadline(Instant::from_millis(50));
        assert_eq!(stack.targeted_replay.as_ref().unwrap().pending_queues, 0);
        assert_eq!(stack.metrics.counts().safety_net_attempts, 0);
    }

    #[test]
    fn suppressed_wake_is_recovered_at_50ms_in_idle_driver() {
        let (mut stack, mut dev, client, server) = pair();
        let recv = request(
            &mut stack,
            Some(server),
            stream::Command::Recv { max_len: None },
        );
        // Deliberately replace the registered waker to simulate a missed smoltcp wake path.
        stack
            .socket_set
            .get_mut::<tcp::Socket>(server)
            .register_recv_waker(Waker::noop());
        request(
            &mut stack,
            Some(client),
            stream::Command::Send {
                buf: Bytes::from_static(b"hello"),
            },
        )
        .try_recv()
        .unwrap();
        pump(&mut stack, &mut dev, Instant::ZERO);
        assert!(recv.is_empty());
        // Earlier TCP timers remain visible; the safety net must not hide the delayed ACK.
        assert_eq!(stack.poll_at(Instant::ZERO), Some(Instant::from_millis(10)));
        pump(&mut stack, &mut dev, Instant::from_millis(49));
        assert!(recv.is_empty());
        assert_eq!(
            stack.poll_at(Instant::from_millis(49)),
            Some(Instant::from_millis(50))
        );
        pump(&mut stack, &mut dev, Instant::from_millis(50));
        assert_recv(&recv, b"hello");
        assert_eq!(stack.metrics.counts().safety_net_completions, 1);
        assert_eq!(stack.metrics.counts().safety_net_attempts, 1);
    }

    #[test]
    fn udp_recv_wakes_and_udp_only_stack_has_a_safety_deadline() {
        let mut stack = stack();
        let mut dev = dev();
        let handle = bind(&mut stack, 1000);
        let recv = request(
            &mut stack,
            Some(handle),
            crate::udp::Command::Recv { max_len: None },
        );
        assert_eq!(
            stack.poll_delay(Instant::ZERO),
            Some(core::time::Duration::from_millis(50))
        );
        request(
            &mut stack,
            Some(handle),
            crate::udp::Command::Send {
                endpoint: endpoint(1000),
                local: None,
                buf: Bytes::from_static(b"udp"),
            },
        )
        .try_recv()
        .unwrap();
        pump(&mut stack, &mut dev, Instant::ZERO);
        match recv.try_recv().unwrap() {
            Response::Udp(crate::udp::Response::RecvFrom { buf, .. }) => {
                assert_eq!(&buf[..], b"udp")
            }
            r => panic!("{r:?}"),
        }
        assert_eq!(stack.metrics.counts().targeted_replay_completions, 1);
        assert_eq!(stack.metrics.counts().safety_net_sweeps, 0);
        assert_eq!(stack.targeted_replay.as_ref().unwrap().pending_queues, 0);
        assert_eq!(stack.poll_at(Instant::ZERO), None);
    }
}

#[cfg(test)]
mod driver_tests {
    use core::{
        pin::Pin,
        task::{Context, Poll},
    };

    use smoltcp::phy::Device;

    use super::{tests::*, *};
    use crate::{AsyncWakeDevice, Response};

    struct AsyncDev {
        inner: crate::PipeDev,
        capacity: bool,
    }
    impl Device for AsyncDev {
        type RxToken<'a> = <crate::PipeDev as Device>::RxToken<'a>;
        type TxToken<'a> = <crate::PipeDev as Device>::TxToken<'a>;
        fn receive(&mut self, now: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
            if self.capacity {
                self.inner.receive(now)
            } else {
                None
            }
        }
        fn transmit(&mut self, now: Instant) -> Option<Self::TxToken<'_>> {
            if self.capacity {
                self.inner.transmit(now)
            } else {
                None
            }
        }
        fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
            self.inner.capabilities()
        }
    }
    impl AsyncWakeDevice for AsyncDev {
        fn poll_rx(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
            if self.capacity && !self.inner.pipe.rx.is_empty() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }
        fn poll_tx(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
            if self.capacity {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }
    }

    #[test]
    fn async_timer_recovers_suppressed_wake_without_rx_or_tx_capacity() {
        let (mut stack, mut dev, client, server) = pair();
        let recv = request(
            &mut stack,
            Some(server),
            crate::tcp::stream::Command::Recv { max_len: None },
        );
        stack
            .socket_set
            .get_mut::<tcp::Socket>(server)
            .register_recv_waker(Waker::noop());
        request(
            &mut stack,
            Some(client),
            crate::tcp::stream::Command::Send {
                buf: bytes::Bytes::from_static(b"hello"),
            },
        )
        .try_recv()
        .unwrap();
        pump(&mut stack, &mut dev, Instant::ZERO);
        let mut dev = AsyncDev {
            inner: dev,
            capacity: false,
        };
        let mut cx = Context::from_waker(Waker::noop());
        assert!(
            Pin::new(&mut stack.wait_io_async(Instant::from_millis(49), &mut dev))
                .poll(&mut cx)
                .is_pending()
        );
        assert!(recv.is_empty());
        assert!(
            Pin::new(&mut stack.wait_io_async(Instant::from_millis(50), &mut dev))
                .poll(&mut cx)
                .is_pending()
        );
        assert_recv(&recv, b"hello");
        assert_eq!(stack.metrics.counts().safety_net_completions, 1);
        assert_eq!(stack.targeted_replay.as_ref().unwrap().pending_queues, 0);
    }

    #[test]
    fn receive_only_async_ingress_services_dirty_recv_before_returning() {
        let (mut stack, dev, client, server) = pair();
        stack.set_ingress_budget(Some(1));
        let recv = request(
            &mut stack,
            Some(server),
            crate::tcp::stream::Command::Recv { max_len: None },
        );
        request(
            &mut stack,
            Some(client),
            crate::tcp::stream::Command::Send {
                buf: bytes::Bytes::from_static(b"hello"),
            },
        )
        .try_recv()
        .unwrap();
        let mut dev = AsyncDev {
            inner: dev,
            capacity: true,
        };
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..16 {
            let _polled = Pin::new(&mut stack.wait_io_async(Instant::ZERO, &mut dev)).poll(&mut cx);
            if !recv.is_empty() {
                break;
            }
        }
        assert_recv(&recv, b"hello");
        assert_eq!(stack.metrics.counts().targeted_replay_completions, 2);
        assert_eq!(stack.metrics.counts().safety_net_sweeps, 0);
    }

    #[test]
    fn receive_only_budget_drains_single_tcp_egress_in_one_poll() {
        {
            let (mut stack, dev, client, _) = pair_with_buffer(16 * 1024);
            stack.set_ingress_budget(Some(1));
            request(
                &mut stack,
                Some(client),
                crate::tcp::stream::Command::Send {
                    buf: bytes::Bytes::from(alloc::vec![b'x'; 8000]),
                },
            )
            .try_recv()
            .unwrap();
            let mut dev = AsyncDev {
                inner: dev,
                capacity: true,
            };
            let before = stack.metrics.counts().egress_passes;
            let mut cx = Context::from_waker(Waker::noop());
            assert!(
                Pin::new(&mut stack.wait_io_async(Instant::ZERO, &mut dev))
                    .poll(&mut cx)
                    .is_ready()
            );
            let packets: alloc::vec::Vec<_> = dev.inner.pipe.rx.drain().collect();
            assert!(packets.len() > 1, "single-flow egress must keep draining");
            assert!(stack.metrics.counts().egress_passes - before > 1);
            assert!(!stack.should_yield(), "no receive bound was hit");
        }
    }

    #[test]
    fn receive_only_limit_survives_egress_and_short_drains_do_not_yield() {
        let mut stack = stack();
        stack.set_ingress_budget(Some(2));
        let mut dev = AsyncDev {
            inner: dev(),
            capacity: true,
        };
        for _ in 0..5 {
            dev.inner
                .pipe
                .tx
                .send(bytes::Bytes::from_static(&[0; 20]))
                .unwrap();
        }
        let mut cx = Context::from_waker(Waker::noop());
        for remaining in [3, 1, 0] {
            assert!(
                Pin::new(&mut stack.wait_io_async(Instant::ZERO, &mut dev))
                    .poll(&mut cx)
                    .is_ready()
            );
            assert_eq!(dev.inner.pipe.rx.len(), remaining);
            assert_eq!(stack.should_yield(), remaining != 0);
        }
        assert!(
            Pin::new(&mut stack.wait_io_async(Instant::ZERO, &mut dev))
                .poll(&mut cx)
                .is_pending()
        );
        assert!(!stack.should_yield());
        assert_eq!(stack.metrics.counts().ingress_budget_hits, 2);
    }

    #[test]
    fn reset_connect_keeps_missing_socket_result_and_clears_pending_count() {
        let mut stack = stack();
        let connect = request(
            &mut stack,
            None,
            crate::tcp::stream::Command::Connect {
                local_endpoint: endpoint(50000),
                remote_endpoint: endpoint(80),
            },
        );
        let handle = stack
            .targeted_replay
            .as_ref()
            .unwrap()
            .queues
            .keys()
            .next()
            .unwrap()
            .0;
        stack.socket_set.get_mut::<tcp::Socket>(handle).abort();
        stack.pump_waiters();
        assert!(matches!(
            connect.try_recv(),
            Ok(Response::Error(crate::Error::Internal(
                crate::InternalErrorKind::BadSocketHandle
            )))
        ));
        assert!(stack.targeted_replay.as_ref().unwrap().queues.is_empty());
        assert_eq!(stack.targeted_replay.as_ref().unwrap().pending_queues, 0);
        assert!(stack.handle_gen(handle).is_none());
        assert_eq!(stack.metrics.counts().safety_net_sweeps, 0);
    }

    #[test]
    fn suppressed_reset_wake_counts_a_safety_completion() {
        let mut stack = stack();
        let connect = request(
            &mut stack,
            None,
            crate::tcp::stream::Command::Connect {
                local_endpoint: endpoint(50000),
                remote_endpoint: endpoint(80),
            },
        );
        let handle = stack
            .targeted_replay
            .as_ref()
            .unwrap()
            .queues
            .keys()
            .next()
            .unwrap()
            .0;
        let sock = stack.socket_set.get_mut::<tcp::Socket>(handle);
        sock.register_recv_waker(Waker::noop());
        sock.register_send_waker(Waker::noop());
        sock.abort();
        stack.service_replay_deadline(Instant::from_millis(50));
        assert!(matches!(
            connect.try_recv(),
            Ok(Response::Error(crate::Error::Internal(
                crate::InternalErrorKind::BadSocketHandle
            )))
        ));
        assert_eq!(stack.metrics.counts().safety_net_attempts, 1);
        assert_eq!(stack.metrics.counts().safety_net_completions, 1);
        assert_eq!(stack.metrics.counts().replay_completions, 1);
        assert_eq!(stack.targeted_replay.as_ref().unwrap().pending_queues, 0);
    }

    #[test]
    fn environment_gate_is_cached_and_copied_to_new_stacks() {
        let stack = Netstack::new(crate::Config::default(), Instant::ZERO);
        assert_eq!(stack.targeted_replay.is_some(), enabled());
        #[cfg(feature = "std")]
        assert_eq!(
            enabled(),
            std::env::var("TS_EXPERIMENT_TARGETED_REPLAY").as_deref() == Ok("1")
        );
    }
}
