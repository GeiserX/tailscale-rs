//! Pcap stream framer for debug packet capture (`CapturePcap`).
//!
//! This is the *format* half of Tailscale's debug packet capture: a [`PcapSink`] that frames
//! captured packets into a byte stream and writes them to any [`std::io::Write`]. A separate seam
//! tees packets into the sink; this module is only concerned with producing bytes.
//!
//! The on-the-wire format is **classic pcap** (not pcapng), little-endian, byte-faithful to Go
//! Tailscale's `feature/capture` (`capture.go`):
//!
//! - a 24-byte classic pcap global header, written once on construction, using link type
//!   [`LINKTYPE_USER0`] (147);
//! - per packet, a 16-byte classic pcap record header, followed by Tailscale's custom 4-byte path
//!   preamble (a `u16` little-endian path code, then a SNAT length byte and a DNAT length byte),
//!   followed by the raw IP packet bytes.
//!
//! Because this fork never performs SNAT/DNAT on the captured path, both NAT length bytes in the
//! preamble are **always 0** (the no-NAT common case). A file produced here is readable in
//! Wireshark; with Tailscale's `ts-dissector.lua` the per-record path/preamble decodes, and without
//! it the records are still walkable but shown as opaque USER0 data.

use std::time::{SystemTime, UNIX_EPOCH};

/// LINKTYPE_USER0 — the link-layer type Go Tailscale uses for its capture stream. Wireshark needs
/// Tailscale's `ts-dissector.lua` to decode the per-record path/preamble; without it the records are
/// still walkable but shown as opaque USER0 data.
pub const LINKTYPE_USER0: u32 = 147;

/// A pcap stream framer that writes captured packets to a writer in Go-Tailscale-faithful classic
/// pcap (USER0 link type + a 4-byte path preamble per record). Construct with [`PcapSink::new`]
/// (which emits the global header), then call [`PcapSink::log_packet`] per packet.
///
/// Records are **not** flushed per packet (that would be a syscall on every packet on the single
/// dataplane thread). For buffering, wrap `writer` in a [`std::io::BufWriter`]; buffered records are
/// flushed when the writer is dropped (on capture stop), or call [`PcapSink::flush`] periodically if
/// a reader needs to tail the stream promptly.
pub struct PcapSink<W> {
    writer: W,
}

impl<W: std::io::Write> PcapSink<W> {
    /// Create a sink and immediately write the 24-byte pcap global header.
    pub fn new(mut writer: W) -> std::io::Result<Self> {
        writer.write_all(&global_header())?;
        Ok(Self { writer })
    }

    /// Frame and write one captured packet: the 16-byte record header, the 4-byte Tailscale path
    /// preamble, then the raw IP bytes. The timestamp is taken from the system clock now.
    pub fn log_packet(&mut self, path_code: u16, pkt: &[u8]) -> std::io::Result<()> {
        let (sec, usec) = now_parts();
        self.write_record(path_code, sec, usec, pkt)
    }

    /// Pure record writer (timestamp injected), factored out so the exact byte layout is
    /// unit-testable without the system clock.
    fn write_record(
        &mut self,
        path_code: u16,
        ts_sec: u32,
        ts_usec: u32,
        pkt: &[u8],
    ) -> std::io::Result<()> {
        // caplen == orig_len == 4 (preamble) + pkt.len(). IP packets are <= 64 KiB, so this cast
        // can never overflow in practice; saturate defensively regardless.
        let incl_len: u32 = 4u32.saturating_add(pkt.len() as u32);

        // 16-byte classic pcap record header (little-endian).
        self.writer.write_all(&ts_sec.to_le_bytes())?;
        self.writer.write_all(&ts_usec.to_le_bytes())?;
        self.writer.write_all(&incl_len.to_le_bytes())?;
        self.writer.write_all(&incl_len.to_le_bytes())?;

        // 4-byte Tailscale path preamble (path u16 LE, then no-NAT zero length bytes).
        self.writer.write_all(&record_preamble(path_code))?;

        // Raw IP packet bytes.
        self.writer.write_all(pkt)?;

        // No per-record flush: flushing on every packet is a syscall per packet on the single
        // dataplane thread, which collapses throughput under capture. Buffered records are flushed
        // when the writer is dropped on capture stop (see [`PcapSink::flush`] for an explicit
        // periodic/tailing flush, and wrap `writer` in a `std::io::BufWriter` if you want buffering).
        Ok(())
    }

    /// Flush the underlying writer. Optional: callers that need a reader tailing the stream (e.g.
    /// `tcpdump -r` on a growing file, or a live pipe) to see packets promptly can call this
    /// periodically — it is *not* called per record, so the hot path stays syscall-free. Buffered
    /// records are otherwise flushed when the writer is dropped on capture stop.
    pub fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }

    /// Consume the sink and return the inner writer (test helper for byte assertions).
    #[cfg(test)]
    fn into_inner(self) -> W {
        self.writer
    }
}

/// Return the 24-byte classic pcap global header (little-endian), with USER0 link type.
fn global_header() -> [u8; 24] {
    let mut h = [0u8; 24];
    h[0..4].copy_from_slice(&0xA1B2_C3D4u32.to_le_bytes()); // magic_number
    h[4..6].copy_from_slice(&2u16.to_le_bytes()); // version_major
    h[6..8].copy_from_slice(&4u16.to_le_bytes()); // version_minor
    h[8..12].copy_from_slice(&0i32.to_le_bytes()); // thiszone
    h[12..16].copy_from_slice(&0u32.to_le_bytes()); // sigfigs
    h[16..20].copy_from_slice(&65535u32.to_le_bytes()); // snaplen
    h[20..24].copy_from_slice(&LINKTYPE_USER0.to_le_bytes()); // network (linktype)
    h
}

/// Return the 4-byte Tailscale per-record preamble: the path code as a little-endian `u16`, then a
/// zero SNAT length byte and a zero DNAT length byte (this fork never does SNAT/DNAT).
fn record_preamble(path_code: u16) -> [u8; 4] {
    let p = path_code.to_le_bytes();
    [p[0], p[1], 0, 0]
}

/// Return `(seconds, microseconds)` since the Unix epoch from the system clock. On a clock error
/// (time before the epoch) return `(0, 0)`.
fn now_parts() -> (u32, u32) {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as u32, d.subsec_micros()),
        Err(_) => (0, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_header_is_exact() {
        assert_eq!(
            global_header(),
            [
                0xD4, 0xC3, 0xB2, 0xA1, // magic 0xA1B2C3D4 LE
                0x02, 0x00, // version_major 2
                0x04, 0x00, // version_minor 4
                0x00, 0x00, 0x00, 0x00, // thiszone 0
                0x00, 0x00, 0x00, 0x00, // sigfigs 0
                0xFF, 0xFF, 0x00, 0x00, // snaplen 65535
                0x93, 0x00, 0x00, 0x00, // network 147 (LINKTYPE_USER0)
            ]
        );
    }

    #[test]
    fn record_preamble_encodes_path_le() {
        assert_eq!(record_preamble(1), [0x01, 0x00, 0x00, 0x00]);
        assert_eq!(record_preamble(0x0102), [0x02, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn write_record_layout() {
        let mut sink = PcapSink::new(Vec::<u8>::new()).expect("global header");
        sink.write_record(1, 0x1122_3344, 0x0005_5AA5, &[0xAB, 0xCD, 0xEF])
            .expect("write record");
        let buf = sink.into_inner();

        // Skip the 24-byte global header; assert the record bytes that follow.
        let rec = &buf[24..];
        assert_eq!(
            rec,
            &[
                0x44, 0x33, 0x22, 0x11, // ts_sec  0x11223344 LE
                0xA5, 0x5A, 0x05, 0x00, // ts_usec 0x00055AA5 LE
                0x07, 0x00, 0x00, 0x00, // caplen  4 + 3 = 7
                0x07, 0x00, 0x00, 0x00, // orig_len 7
                0x01, 0x00, 0x00, 0x00, // preamble: path 1, snat 0, dnat 0
                0xAB, 0xCD, 0xEF, // payload
            ]
        );
    }

    #[test]
    fn new_writes_global_header() {
        let mut buf = Vec::<u8>::new();
        let _sink = PcapSink::new(&mut buf).expect("global header");
        assert_eq!(buf, global_header());
    }
}
