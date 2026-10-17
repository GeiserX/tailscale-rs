//! Test harness: a fake NAT-PMP/PCP router on loopback and `TestCap`, a loopback transport.
//!
//! Compiled only for this crate's tests and with the `test-harness` feature, which only
//! dev-dependencies may enable (the `portmapper_lan_only` check enforces it). Nothing here can
//! reach a real gateway: [`FakeRouter::start`] refuses a non-loopback bind address, `TestCap`
//! asserts its router is on loopback and sends only to it, and [`send_datagrams`] refuses a
//! non-loopback destination.
//!
//! The router decodes requests with its own decoder written from RFC 6886 and RFC 6887; it does
//! not reuse [`crate::pmp`] or [`crate::pcp`], so a codec bug cannot hide behind a matching
//! harness bug.

mod cap;
mod clock;
mod lifecycle;
mod router;
#[cfg(test)]
mod tests;

use std::net::{Ipv4Addr, SocketAddr};

pub use cap::TestCap;
pub use clock::LeaseClock;
pub use lifecycle::{ManualClock, PanicLookup, ScriptedLookup, TestCaps};
pub use router::{
    AssignPort, Barrier, Corruption, Counters, DecodedRequest, EpochMode, FakeRouter, MappingEntry,
    RequestKind, ResultOverride, RouterEndpoint, RouterOptions,
};

/// Send `count` datagrams of `len` bytes to `to` from a loopback socket (for the probe's hold
/// window). Returns the sender's address. A non-loopback `to` is refused with
/// [`std::io::ErrorKind::InvalidInput`].
pub async fn send_datagrams(
    to: SocketAddr,
    count: usize,
    len: usize,
) -> std::io::Result<SocketAddr> {
    if !to.ip().is_loopback() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "send_datagrams sends to loopback only",
        ));
    }
    let s = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let payload = vec![0x5a; len];
    for _ in 0..count {
        s.send_to(&payload, to).await?;
    }
    s.local_addr()
}

/// Read-only cleanup diagnostics for integration tests; no ledger mutation is exposed.
#[derive(Debug, Clone, Copy)]
pub struct CleanupSnapshot {
    /// Unacknowledged delete attempts.
    pub delete_tries: u32,
    /// Whether an operation currently reserves this entry for deletion.
    pub deleting: bool,
}
