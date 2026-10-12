//! A continuously readable device must not monopolise a current-thread executor.
use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use ts_netstack_smoltcp::{
    HasChannel, Netstack,
    netcore::{
        self, NetstackControl,
        smoltcp::{
            phy::{self, Device, Medium},
            time::Instant,
        },
    },
};
struct Flood(Arc<AtomicU64>, Arc<AtomicBool>);
struct Rx;
struct Tx;
impl phy::RxToken for Rx {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&[0; 20])
    }
}
impl phy::TxToken for Tx {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut vec![0; len])
    }
}
impl Device for Flood {
    type RxToken<'a>
        = Rx
    where
        Self: 'a;
    type TxToken<'a>
        = Tx
    where
        Self: 'a;
    fn receive(&mut self, _: Instant) -> Option<(Rx, Tx)> {
        if self.1.load(Ordering::Relaxed) {
            return None;
        }
        self.0.fetch_add(1, Ordering::Relaxed);
        Some((Rx, Tx))
    }
    fn transmit(&mut self, _: Instant) -> Option<Tx> {
        Some(Tx)
    }
    fn capabilities(&self) -> phy::DeviceCapabilities {
        let mut c = phy::DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = 1280;
        c
    }
}
impl netcore::AsyncWakeDevice for Flood {
    fn poll_rx(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
        if self.1.load(Ordering::Relaxed) {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    }
    fn poll_tx(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
        Poll::Ready(())
    }
}
#[tokio::test]
async fn receive_only_flood_yields_to_timer_and_socket_commands() {
    let packets = Arc::new(AtomicU64::new(0));
    let escaped = Arc::new(AtomicBool::new(false));
    let device = Flood(packets.clone(), escaped.clone());
    let (ready, started) = tokio::sync::oneshot::channel();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut stack = Netstack::new(device, Default::default());
            stack.set_ingress_budget(Some(8));
            let channel = stack.command_channel();
            tokio::spawn(async move { stack.run_tokio().await });
            let (tick, timer) = tokio::sync::oneshot::channel();
            tokio::spawn(async {
                tokio::time::sleep(Duration::from_millis(10)).await;
                tick.send(()).unwrap();
            });
            ready.send((channel, timer)).unwrap();
            drop(stopped.await);
        });
    });
    let (channel, timer) = started.await.unwrap();
    let result = tokio::time::timeout(Duration::from_millis(500), async {
        for _ in 0..64 {
            channel.set_any_ip(true).await.unwrap();
        }
        channel.set_any_ip(false).await.unwrap();
        timer.await.unwrap();
        assert!(packets.load(Ordering::Relaxed) >= 8);
    })
    .await;
    // An independent watchdog can end the device flood even if the regression blocks poll forever.
    // Thus the failing test cannot strand its executor or the test process.
    escaped.store(true, Ordering::Relaxed);
    let _ = stop.send(());
    tokio::task::spawn_blocking(move || thread.join().unwrap())
        .await
        .unwrap();
    result.unwrap();
}
