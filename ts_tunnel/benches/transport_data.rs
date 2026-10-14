//! Actual transport session paths, including nonce reservation, padding, framing
//! and replay checks. No handshake, endpoint grouping, network or key setup is timed.
//! Run once without defaults and once with `--features ring-aead`; samples report
//! ns per packet for a complete session seal+open. Existing header insertion moves
//! the body identically in both backends. Spare headroom prevents buffer growth.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    hint::black_box,
    sync::atomic::{AtomicUsize, Ordering},
    time::Instant,
};

struct CountingAllocator;
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

// SAFETY: forward allocation operations unchanged to System. Counting does not
// dereference or modify any pointer or layout supplied by the allocator caller.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: caller provided a valid allocation layout.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: caller provided a matching live allocation and layout.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: caller provided valid reallocation arguments.
        unsafe { System.realloc(ptr, layout, size) }
    }
}

use ts_packet::PacketMut;

// Exercise the exact private production implementation without exposing session
// keys or adding a public benchmark-only cryptographic API to the library.
#[allow(dead_code, unused_imports)]
#[path = "../src/messages.rs"]
mod messages;
#[allow(dead_code, unused_imports)]
#[path = "../src/replay.rs"]
mod replay;
#[allow(dead_code, unused_imports)]
#[path = "../src/session.rs"]
mod session;
#[allow(dead_code, unused_imports)]
#[path = "../src/transport_aead.rs"]
mod transport_aead;

fn main() {
    let n = std::env::var("BENCH_PACKETS")
        .ok()
        .map(|v| v.parse::<usize>().unwrap())
        .unwrap_or(400_000);
    let backend = if cfg!(feature = "ring-aead") {
        "ring"
    } else {
        "rustcrypto"
    };
    for size in [0, 64, 1280, 1312, 1500] {
        for sample in 0..5 {
            let cipher = transport_aead::TransportCipher::new([7u8; 32].into());
            let mut packet = PacketMut::with_capacity(size + 64);
            packet.extend_from_slice(&vec![0x42; size]);
            ALLOCATIONS.store(0, Ordering::Relaxed);
            let start = Instant::now();
            for i in 0..n {
                packet.truncate(size);
                let mut nonce = [0; 12];
                nonce[4..].copy_from_slice(&(i as u64).to_le_bytes());
                cipher
                    .seal(black_box(nonce), black_box(&mut packet))
                    .unwrap();
                cipher
                    .open(black_box(nonce), black_box(&mut packet))
                    .unwrap();
            }
            let ns = start.elapsed().as_secs_f64() * 1e9 / n as f64;
            let allocations = ALLOCATIONS.load(Ordering::Relaxed);
            assert_eq!(allocations, 0, "timed AEAD loop must not allocate");
            println!(
                "backend={backend} size={size} sample={sample} packets={n} aead_seal_open_ns={ns:.1} allocations={allocations}"
            );

            let now = Instant::now();
            let key = [7u8; 32];
            let id = messages::SessionId::from(1);
            let send = session::TransmitSession::new(key.into(), id, now);
            let mut recv = session::ReceiveSession::new(key.into(), id, now);
            // Each open advances the buffer start by the 16-byte header; reserve
            // that cumulative space before timing to avoid allocator interference.
            let mut packet = PacketMut::with_capacity(n * 16 + size + 64);
            packet.extend_from_slice(&vec![0x42; size]);
            let mut packets = vec![packet];
            // Register tracing callsites / initialize lazy thread-local state once,
            // outside timing. That existing one-time allocation is not packet work.
            send.encrypt(&mut packets);
            packets = recv.decrypt(packets);
            assert_eq!(packets.len(), 1);
            ALLOCATIONS.store(0, Ordering::Relaxed);
            let start = Instant::now();
            for _ in 0..n {
                packets[0].truncate(size);
                send.encrypt(black_box(&mut packets));
                packets = recv.decrypt(black_box(packets));
                assert_eq!(packets.len(), 1);
                black_box(&packets);
            }
            let ns = start.elapsed().as_secs_f64() * 1e9 / n as f64;
            let allocations = ALLOCATIONS.load(Ordering::Relaxed);
            assert_eq!(allocations, 0, "timed session loop must not allocate");
            println!(
                "backend={backend} size={size} sample={sample} packets={n} session_seal_open_ns={ns:.1} allocations={allocations}"
            );
        }
    }
}
