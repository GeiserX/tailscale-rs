//! Cumulative host TCP write sizes, gated by TS_DEBUG_PIPELINE_METRICS=1.
use std::{
    io,
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    task::Poll,
};

static BYTES: AtomicU64 = AtomicU64::new(0);
static WRITES: [AtomicU64; 9] = [const { AtomicU64::new(0) }; 9];
static PENDING: AtomicU64 = AtomicU64::new(0);
static PARTIAL: AtomicU64 = AtomicU64::new(0);

/// Inclusive byte upper bounds; the final bucket includes any larger write.
pub const WRITE_SIZE_BOUNDS: [u64; 9] = [
    1024,
    2048,
    4096,
    8192,
    16384,
    32768,
    65536,
    131072,
    u64::MAX,
];

pub(crate) fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var("TS_DEBUG_PIPELINE_METRICS").as_deref() == Ok("1"))
}

/// Counts successful nonzero AsyncWrite completions, not offered bytes or Pending retries.
/// For the production host Tokio TcpStream each such completion is a successful socket write.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    /// Actual bytes accepted by the host socket.
    pub host_write_bytes: u64,
    /// Successful writes in the buckets defined by WRITE_SIZE_BOUNDS.
    pub host_write_sizes: [u64; 9],
    /// Host write polls returning Pending; readiness/backpressure, not syscalls.
    pub host_write_pending: u64,
    /// Successful writes accepting fewer bytes than offered.
    pub host_write_partial: u64,
}
/// Read without messaging or formatting on the packet path. Use deltas over the transfer window.
pub fn snapshot() -> Snapshot {
    Snapshot {
        host_write_bytes: BYTES.load(Ordering::Relaxed),
        host_write_sizes: core::array::from_fn(|i| WRITES[i].load(Ordering::Relaxed)),
        host_write_pending: PENDING.load(Ordering::Relaxed),
        host_write_partial: PARTIAL.load(Ordering::Relaxed),
    }
}
fn bucket(bytes: usize) -> usize {
    WRITE_SIZE_BOUNDS
        .iter()
        .position(|bound| bytes as u64 <= *bound)
        .unwrap_or(8)
}
pub(crate) fn record(result: &Poll<io::Result<usize>>, offered: usize) {
    match result {
        Poll::Ready(Ok(n)) if *n > 0 => {
            BYTES.fetch_add(*n as u64, Ordering::Relaxed);
            WRITES[bucket(*n)].fetch_add(1, Ordering::Relaxed);
            if *n < offered {
                PARTIAL.fetch_add(1, Ordering::Relaxed);
            }
        }
        Poll::Pending => {
            PENDING.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }
}
