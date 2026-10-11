//! Startup barrier and fail-closed supervision for security-state consumers.
//!
//! Register acknowledgements are awaited in each actor's on_start. Complete all of these
//! starts before spawning control (including cached-map replay). Never ask the broker to
//! publish: a handler waiting for publication could deadlock its own full mailbox.

use std::sync::{Arc, Mutex};

use kameo::{Actor, actor::ActorRef};
use tokio::{sync::watch, task::JoinSet};

use crate::{Error, ErrorKind};

struct FailureState {
    shutdown: watch::Sender<bool>,
    stops: Mutex<Vec<Box<dyn Fn() + Send + Sync>>>,
}

impl FailureState {
    fn stop(&self) {
        self.shutdown.send_replace(true);
        // Only nonblocking kill/abort callbacks. No actor messaging or asynchronous locks.
        for stop in self.stops.lock().unwrap().iter() {
            stop();
        }
    }
}

pub(crate) struct SecurityGuard {
    failure: Arc<FailureState>,
    monitors: JoinSet<()>,
}

impl SecurityGuard {
    pub(crate) fn new(shutdown: watch::Sender<bool>) -> Self {
        Self {
            failure: Arc::new(FailureState {
                shutdown,
                stops: Mutex::new(Vec::new()),
            }),
            monitors: JoinSet::new(),
        }
    }

    pub(crate) fn watch<A: Actor>(&mut self, actor: &ActorRef<A>) {
        // Retain a strong ref until cancellation. With weak refs, concurrent broker shutdown
        // and monitor exit could drop the last sender before kill, stranding a blocked handler.
        let stop_actor = actor.clone();
        self.failure
            .stops
            .lock()
            .unwrap()
            .push(Box::new(move || stop_actor.kill()));
        let failure = self.failure.clone();
        let mut shutdown = failure.shutdown.subscribe();
        let actor = actor.clone();
        self.monitors.spawn(async move {
            tokio::select! {
                () = actor.wait_for_shutdown() => {
                    // Drop the watch read guard before taking its write lock in stop().
                    let stopping = *shutdown.borrow();
                    if !stopping {
                        tracing::error!(actor = std::any::type_name::<A>(),
                            "security actor stopped; stopping forwarding");
                        failure.stop();
                    }
                }
                _ = async { drop(shutdown.wait_for(|stopping| *stopping).await); } => {}
            }
        });
        // Covers actors added concurrently with an earlier actor's failure.
        let stopping = *self.failure.shutdown.borrow();
        if stopping {
            self.failure.stop();
        }
    }

    pub(crate) fn packet_pump(&mut self, abort: tokio::task::AbortHandle) {
        // Abort the forwarding pump first, even if the dataplane actor is blocked in a handler.
        self.failure
            .stops
            .lock()
            .unwrap()
            .insert(0, Box::new(move || abort.abort()));
        let stopping = *self.failure.shutdown.borrow();
        if stopping {
            self.failure.stop();
        }
    }

    pub(crate) async fn ready<A: Actor>(&self, actor: &ActorRef<A>) -> Result<(), Error> {
        let mut shutdown = self.failure.shutdown.subscribe();
        let ready = tokio::select! {
            ready = actor.wait_for_startup_with_result(|result| result.is_ok()) => ready,
            _ = async { drop(shutdown.wait_for(|stopping| *stopping).await); } => false,
        };
        let stopping = *shutdown.borrow();
        if ready && !stopping {
            Ok(())
        } else {
            self.failure.stop();
            Err(Error {
                kind: ErrorKind::ActorGone,
                target_actor: Some(actor.into()),
                message_ty: None,
            })
        }
    }
}

impl Drop for SecurityGuard {
    fn drop(&mut self) {
        // Also cleans up a partially constructed runtime when any startup step returns Err.
        self.failure.stop();
        self.monitors.abort_all();
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use kameo::{
        actor::Spawn,
        message::{Context, Message},
    };
    use tokio::sync::{Notify, mpsc};

    use super::*;
    use crate::{
        Env,
        dataplane::{DataplaneActor, NewOverlayTransport, PacketPumpAbortHandle},
        env::ForwarderConfig,
        forwarder_actor::ForwarderActor,
    };

    fn environment() -> (Env, watch::Sender<bool>) {
        let (shutdown, rx) = watch::channel(false);
        let env = Env::new(
            ts_keys::NodeState::generate(),
            rx,
            ForwarderConfig::from_control_config(&ts_control::Config::default()),
        );
        (env, shutdown)
    }

    struct Probe {
        env: Env,
        seen: mpsc::UnboundedSender<u32>,
        pause: Option<(Arc<Notify>, Arc<Notify>)>,
    }

    impl Actor for Probe {
        type Args = (
            Env,
            mpsc::UnboundedSender<u32>,
            Option<(Arc<Notify>, Arc<Notify>)>,
            Option<Arc<Notify>>,
        );
        type Error = Error;

        async fn on_start(
            (env, seen, pause, start): Self::Args,
            slf: ActorRef<Self>,
        ) -> Result<Self, Error> {
            if let Some(start) = start {
                start.notified().await;
            }
            env.subscribe::<u32>(&slf).await?;
            Ok(Self { env, seen, pause })
        }
    }

    impl Message<u32> for Probe {
        type Reply = ();
        async fn handle(&mut self, value: u32, _: &mut Context<Self, ()>) {
            if value == 0
                && let Some((entered, release)) = self.pause.take()
            {
                entered.notify_one();
                release.notified().await;
                // The mailbox is full and the broker is waiting for this actor to drain it.
                // Waiting for broker handling here (or using a bounded broker) would deadlock.
                self.env.publish(10_000_u32).await.unwrap();
            }
            self.seen.send(value).unwrap();
        }
    }

    #[tokio::test]
    async fn saturated_subscriber_can_publish_from_handler_and_keeps_order() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (env, shutdown) = environment();
            let mut guard = SecurityGuard::new(shutdown);
            guard.watch(&env.bus);
            let (seen, mut rx) = mpsc::unbounded_channel();
            let entered = Arc::new(Notify::new());
            let release = Arc::new(Notify::new());
            let actor = Probe::spawn_with_mailbox(
                (
                    env.clone(),
                    seen,
                    Some((entered.clone(), release.clone())),
                    None,
                ),
                kameo::mailbox::bounded(1),
            );
            guard.watch(&actor);
            guard.ready(&actor).await.unwrap();
            env.publish(0_u32).await.unwrap();
            entered.notified().await;
            // More than even the old default broker capacity; publishing must finish while
            // the subscriber is blocked. The one-slot subscriber necessarily fills too.
            for n in 1..=128_u32 {
                env.publish(n).await.unwrap();
            }
            while actor.mailbox_sender().capacity() != Some(0) {
                tokio::task::yield_now().await;
            }
            // A harmless broker request stays queued: the broker is actually blocked,
            // not merely scheduled behind the publisher on this single-threaded runtime.
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(20),
                    env.bus
                        .ask(kameo_actors::message_bus::Unregister::<u64>::new(
                            actor.id()
                        ))
                )
                .await
                .is_err()
            );
            release.notify_one();
            for n in 0..=128_u32 {
                assert_eq!(rx.recv().await, Some(n));
            }
            assert_eq!(rx.recv().await, Some(10_000));
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn late_registration_ack_orders_future_publications_without_replay() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (env, shutdown) = environment();
            let mut guard = SecurityGuard::new(shutdown);
            guard.watch(&env.bus);
            env.publish(7_u32).await.unwrap();
            let (seen, mut rx) = mpsc::unbounded_channel();
            let start = Arc::new(Notify::new());
            let actor = Probe::spawn((env.clone(), seen, None, Some(start.clone())));
            guard.watch(&actor);
            let ready = guard.ready(&actor);
            tokio::pin!(ready);
            assert!(
                tokio::time::timeout(Duration::from_millis(20), &mut ready)
                    .await
                    .is_err()
            );
            start.notify_one();
            ready.await.unwrap();
            // Same rule as runtime cached-map replay: publish only after the startup barrier.
            env.publish(8_u32).await.unwrap();
            assert_eq!(rx.recv().await, Some(8));
            assert!(rx.try_recv().is_err());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn subscribe_waits_for_registration_behind_a_blocked_broker() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (env, shutdown) = environment();
            let mut guard = SecurityGuard::new(shutdown);
            guard.watch(&env.bus);
            let (seen, _rx) = mpsc::unbounded_channel();
            let entered = Arc::new(Notify::new());
            let release = Arc::new(Notify::new());
            let busy = Probe::spawn_with_mailbox(
                (
                    env.clone(),
                    seen,
                    Some((entered.clone(), release.clone())),
                    None,
                ),
                kameo::mailbox::bounded(1),
            );
            guard.watch(&busy);
            guard.ready(&busy).await.unwrap();
            env.publish(0_u32).await.unwrap();
            entered.notified().await;
            env.publish(1_u32).await.unwrap();
            env.publish(2_u32).await.unwrap();
            while busy.mailbox_sender().capacity() != Some(0) {
                tokio::task::yield_now().await;
            }
            let (seen, mut rx) = mpsc::unbounded_channel();
            let late = Probe::spawn((env.clone(), seen, None, None));
            guard.watch(&late);
            // A tell-based Register would return before the broker installs it and wrongly
            // allow this actor through its startup barrier while delivery is blocked.
            assert!(
                tokio::time::timeout(Duration::from_millis(20), guard.ready(&late))
                    .await
                    .is_err()
            );
            release.notify_one();
            guard.ready(&late).await.unwrap();
            env.publish(3_u32).await.unwrap();
            assert_eq!(rx.recv().await, Some(10_000));
            assert_eq!(rx.recv().await, Some(3));
            assert!(rx.try_recv().is_err());
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn critical_subscriber_death_aborts_packet_pump_and_other_actors() {
        for kill in [false, true] {
            tokio::time::timeout(Duration::from_secs(5), async {
                let (env, shutdown) = environment();
                let mut guard = SecurityGuard::new(shutdown.clone());
                guard.watch(&env.bus);
                let dataplane = DataplaneActor::spawn(env.clone());
                guard.watch(&dataplane);
                guard.ready(&dataplane).await.unwrap();
                let pump = dataplane.ask(PacketPumpAbortHandle).await.unwrap();
                guard.packet_pump(pump.clone());
                let (_, up, down) = dataplane.ask(NewOverlayTransport).await.unwrap();
                let forwarder = ForwarderActor::spawn((env.clone(), Default::default(), up, down));
                guard.watch(&forwarder);
                guard.ready(&forwarder).await.unwrap();
                let (seen, _rx) = mpsc::unbounded_channel();
                let entered = Arc::new(Notify::new());
                let release = Arc::new(Notify::new());
                let pause = kill.then(|| (entered.clone(), release));
                let actor = Probe::spawn_with_mailbox(
                    (env.clone(), seen, pause, None),
                    kameo::mailbox::bounded(1),
                );
                guard.watch(&actor);
                guard.ready(&actor).await.unwrap();
                assert!(!pump.is_finished());
                if kill {
                    env.publish(0_u32).await.unwrap();
                    entered.notified().await;
                    for n in 1..=128_u32 {
                        env.publish(n).await.unwrap();
                    }
                    while actor.mailbox_sender().capacity() != Some(0) {
                        tokio::task::yield_now().await;
                    }
                    actor.kill();
                } else {
                    actor.stop_gracefully().await.unwrap();
                }
                forwarder.wait_for_shutdown().await;
                dataplane.wait_for_shutdown().await;
                env.bus.wait_for_shutdown().await;
                assert!(*shutdown.borrow());
                while !pump.is_finished() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
    }

    struct FailedStart;

    impl Actor for FailedStart {
        type Args = ();
        type Error = Error;
        async fn on_start(_: (), _: ActorRef<Self>) -> Result<Self, Error> {
            Err(Error {
                kind: ErrorKind::ActorGone,
                target_actor: None,
                message_ty: None,
            })
        }
    }

    #[tokio::test]
    async fn failed_startup_cannot_pass_security_barrier() {
        let (env, shutdown) = environment();
        let mut guard = SecurityGuard::new(shutdown.clone());
        guard.watch(&env.bus);
        let actor = FailedStart::spawn(());
        guard.watch(&actor);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), guard.ready(&actor))
                .await
                .unwrap()
                .unwrap_err()
                .kind,
            ErrorKind::ActorGone
        );
        env.bus.wait_for_shutdown().await;
        assert!(*shutdown.borrow());
    }
}
