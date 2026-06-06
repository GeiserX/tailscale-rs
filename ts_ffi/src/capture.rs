//! Debug packet-capture marshaling for the C FFI.
//!
//! These mirror `tailscale::Device::capture_pcap` and `tailscale::Device::stop_capture`. The native
//! `capture_pcap` takes any `W: Write + Send + 'static` writer; across C we accept a destination
//! file path and hand the opened [`std::fs::File`] (which satisfies that bound) to the runtime.

use std::ffi::{self, c_char};

use crate::{TOKIO_RUNTIME, device, util};

/// Begin a debug packet capture, writing a pcap of every packet crossing the dataplane to the file
/// at `dst_path` (like Go `tsnet.Server.CapturePcap`).
///
/// Creates (or truncates) `dst_path` and installs the capture hook; from now until
/// [`ts_stop_capture`] is called (or another capture replaces this one), every plaintext IP packet
/// on the datapath is framed and written to that file. The 24-byte pcap global header is written
/// immediately on success. The resulting file opens in Wireshark (`LINKTYPE_USER0` with a 4-byte
/// path preamble per record). Buffered bytes are flushed when capture stops and the file is dropped.
///
/// Returns 0 on success and a negative number on error (file-create failure, the dataplane actor
/// being unreachable, or the initial header write failing — logged via `tracing`).
///
/// # Safety
///
/// `dst_path` must be readable per [`std::ffi::CStr`] rules (NUL-terminated, valid up to and
/// including the NUL).
///
/// `dst_path` is written verbatim on the host filesystem; the C embedder is responsible for
/// ensuring it is a trusted, sanitized path (no path-traversal from untrusted input).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_capture_pcap(dev: &device, dst_path: *const c_char) -> ffi::c_int {
    // SAFETY: ensured by function precondition
    let Some(dst_path) = (unsafe { util::str(dst_path) }) else {
        tracing::error!("capture_pcap: dst_path is null or invalid utf-8");
        return -1;
    };

    let file = match std::fs::File::create(dst_path) {
        Ok(f) => std::io::BufWriter::new(f),
        Err(e) => {
            tracing::error!(err = %e, "capture_pcap: create destination");
            return -1;
        }
    };

    match TOKIO_RUNTIME.block_on(dev.0.capture_pcap(file)) {
        Ok(()) => 0,
        Err(e) => {
            tracing::error!(err = %e, "capture_pcap");
            -1
        }
    }
}

/// Stop a debug packet capture started by [`ts_capture_pcap`] (Go `ClearCaptureSink`).
///
/// Clears the dataplane capture hook; the writer is dropped and its remaining buffered bytes
/// flushed. Idempotent — stopping when no capture is installed is a no-op. Returns 0 on success and
/// a negative number on error (the dataplane actor being unreachable — logged via `tracing`).
#[unsafe(no_mangle)]
pub extern "C" fn ts_stop_capture(dev: &device) -> ffi::c_int {
    match TOKIO_RUNTIME.block_on(dev.0.stop_capture()) {
        Ok(()) => 0,
        Err(e) => {
            tracing::error!(err = %e, "stop_capture");
            -1
        }
    }
}
