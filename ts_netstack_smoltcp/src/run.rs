use core::time::Duration;

use netcore::smoltcp;
use tracing::Instrument;

/// Run the netstack in the current thread.
///
/// Expect this function to block forever.
#[tracing::instrument(level = "trace", skip_all, fields(?poll_max_delay))]
pub fn run_blocking(
    netstack: &mut netcore::Netstack,
    dev: &mut impl smoltcp::phy::Device,
    mut now: impl FnMut() -> smoltcp::time::Instant,
    poll_max_delay: Duration,
) {
    loop {
        let now = now();
        let span = tracing::trace_span!("loop", %now, delay = tracing::field::Empty).entered();

        netstack.poll_device_io(now, &mut *dev);

        let delay = netstack
            .poll_delay(now)
            .unwrap_or(Duration::MAX)
            .min(poll_max_delay);

        span.record("delay", tracing::field::debug(delay));

        tracing::trace!("wait");

        match netstack.wait_for_cmd_blocking(Some(delay)) {
            Ok(cmd) => {
                netstack.process_one_cmd(cmd);
                // process any more commands pending in the channel before polling device i/o
                netstack.process_cmds();
            }
            Err(netcore::flume::RecvTimeoutError::Timeout) => {
                // no commands received, fall through to poll for i/o
            }
            Err(netcore::flume::RecvTimeoutError::Disconnected) => {
                // this can't occur: netstack holds a sender, so the channel can't close until it
                // drops
                unreachable!("internal command channel closed")
            }
        }
    }
}

/// Run the netstack indefinitely.
#[tracing::instrument(level = "trace", skip_all)]
pub async fn run(
    netstack: &mut netcore::Netstack,
    dev: &mut (impl netcore::AsyncWakeDevice + smoltcp::phy::Device + Unpin),
    mut clock: impl FnMut() -> smoltcp::time::Instant,
    sleep: impl AsyncFn(Duration) + Clone,
) {
    use futures_util::FutureExt;

    loop {
        // Commands must get service even with a perpetually readable device.
        if netstack.ingress_budget().is_some() {
            netstack.process_cmds();
        }
        let now = clock();

        let delay = netstack.poll_delay(now);
        let span = tracing::trace_span!("loop", %now, ?delay);
        let cmd_fut = netstack.wait_for_cmd();

        tracing::trace!(parent: &span, "select");

        // IoPoller captures its timestamp. Recreate it on every future poll so a
        // device wake after Pending uses the current clock for RTTs and timers.
        let io = core::future::poll_fn(|cx| netstack.wait_io_async(clock(), dev).poll_unpin(cx));
        futures_util::select_biased![
            _ = io
                .instrument(span.clone())
                .fuse() =>
            {
                tracing::trace!(parent: &span, "device wakeup");
            },
            _ = option_timeout(sleep.clone(), delay).instrument(span.clone()).fuse() => {
                tracing::trace!(parent: &span, "timeout wakeup");
            },
            cmd = cmd_fut.instrument(span.clone()).fuse() => {
                span.in_scope(|| {
                    tracing::trace!("command wakeup");

                    if let Some(cmd) = cmd {
                        netstack.process_one_cmd(cmd);
                    } else {
                        // this can't occur: netstack holds a sender for its own channel, so the receive
                        // channel can't close until the netstack itself drops
                        unreachable!("internal command channel closed");
                    }

                    // Process any more commands pending in the channel before polling device i/o
                    netstack.process_cmds();
                });
            }
        ];
        if netstack.should_yield() {
            #[cfg(feature = "tokio")]
            tokio::task::yield_now().await;
            #[cfg(not(feature = "tokio"))]
            {
                let mut yielded = false;
                core::future::poll_fn(|cx| {
                    if yielded {
                        core::task::Poll::Ready(())
                    } else {
                        yielded = true;
                        cx.waker().wake_by_ref();
                        core::task::Poll::Pending
                    }
                })
                .await;
            }
        }
    }
}

async fn option_timeout(sleep: impl AsyncFn(Duration), dur: Option<Duration>) {
    match dur {
        Some(dur) => sleep(dur).await,
        _ => core::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use crate::{WakingPipe, WakingPipeDev};
    use core::{
        cell::{Cell, RefCell},
        future::Future,
        pin::{Pin, pin},
        task::{Context, Poll},
    };
    use netcore::{AsyncWakeDevice, smoltcp};
    use smoltcp::{
        phy::{Device, DeviceCapabilities},
        time::Instant,
    };
    use std::{rc::Rc, vec::Vec};

    struct TimedDevice {
        inner: WakingPipeDev,
        receives: Rc<RefCell<Vec<Instant>>>,
    }

    impl Device for TimedDevice {
        type RxToken<'a> = <WakingPipeDev as Device>::RxToken<'a>;
        type TxToken<'a> = <WakingPipeDev as Device>::TxToken<'a>;
        fn receive(&mut self, now: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
            let tokens = self.inner.receive(now);
            if tokens.is_some() {
                self.receives.borrow_mut().push(now);
            }
            tokens
        }
        fn transmit(&mut self, now: Instant) -> Option<Self::TxToken<'_>> {
            self.inner.transmit(now)
        }
        fn capabilities(&self) -> DeviceCapabilities {
            self.inner.capabilities()
        }
    }
    impl AsyncWakeDevice for TimedDevice {
        fn poll_rx(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            Pin::new(&mut self.get_mut().inner).poll_rx(cx)
        }
        fn poll_tx(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            Pin::new(&mut self.get_mut().inner).poll_tx(cx)
        }
    }

    #[test]
    fn receive_after_pending_uses_current_clock() {
        let (pipe, incoming) = WakingPipe::new(None);
        let receives = Rc::new(RefCell::new(Vec::new()));
        let mut dev = TimedDevice {
            inner: WakingPipeDev {
                pipe,
                mtu: 1280,
                medium: smoltcp::phy::Medium::Ip,
            },
            receives: receives.clone(),
        };
        let mut stack = netcore::Netstack::new(netcore::Config::default(), Instant::ZERO);
        let now = Cell::new(Instant::ZERO);
        let mut runner = pin!(super::run(
            &mut stack,
            &mut dev,
            || now.get(),
            |_| core::future::pending()
        ));
        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(runner.as_mut().poll(&mut cx).is_pending());
        // A real device token arrives 42 ms after the runner became Pending.
        // Its malformed IP bytes are harmless; the ingress timestamp is the assertion.
        now.set(Instant::from_millis(42));
        assert!(incoming.tx.try_send(&[0]));
        assert!(runner.as_mut().poll(&mut cx).is_pending());
        assert_eq!(&*receives.borrow(), &[Instant::from_millis(42)]);
    }
}
