//! Panic boundary for the C FFI.
//!
//! A Rust panic that unwinds across an `extern "C"` frame is **undefined behavior**. Every
//! `extern "C"` entry point in this crate therefore runs its body inside [`ffi_guard`], which
//! catches any unwind at the boundary and returns the type's documented failure sentinel (a
//! negative `c_int`, a `NULL` pointer, `None`, an `AF_UNSPEC` [`sockaddr`], or nothing for `()`)
//! instead of letting the unwind escape into C.
//!
//! This is the `catch_unwind` approach rather than `panic = "abort"`: the crate ships an embeddable
//! `staticlib`/`cdylib`, so aborting the host process on any internal panic would be a hostile
//! default, and the workspace's `#[should_panic]` tests rely on unwinding being available.

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
};

use crate::net_types::{in_addr_t, sa_family_t, sockaddr, sockaddr_data, sockaddr_in};

/// The value an FFI entry point returns when its body panics.
///
/// Implemented for every type an `extern "C"` function in this crate returns. The sentinel must be
/// a value C callers already interpret as failure for that return type (so a caught panic is
/// indistinguishable from an ordinary error return, never UB).
pub trait FfiSentinel {
    /// The failure value to hand back to C when the guarded body unwinds.
    fn ffi_panic_sentinel() -> Self;
}

impl FfiSentinel for () {
    fn ffi_panic_sentinel() {}
}

impl FfiSentinel for std::ffi::c_int {
    fn ffi_panic_sentinel() -> Self {
        // Every `c_int`-returning entry point documents "negative on error".
        -1
    }
}

impl<T> FfiSentinel for *mut T {
    fn ffi_panic_sentinel() -> Self {
        // NULL is the documented error/return signal for pointer-returning entry points.
        ptr::null_mut()
    }
}

impl<T> FfiSentinel for Option<Box<T>> {
    fn ffi_panic_sentinel() -> Self {
        // A handle-returning entry point uses `None` (FFI-ABI NULL) to signal failure.
        None
    }
}

impl FfiSentinel for sockaddr {
    fn ffi_panic_sentinel() -> Self {
        // A `sockaddr`-returning entry point signals failure with `AF_UNSPEC` (0); the payload is
        // zeroed so no stale union bytes are exposed.
        sockaddr {
            sa_family: sa_family_t(0),
            sa_data: sockaddr_data {
                sockaddr_in: sockaddr_in {
                    sin_port: 0,
                    sin_addr: in_addr_t([0; 4]),
                },
            },
        }
    }
}

/// Run an FFI entry-point body inside a panic boundary.
///
/// If `f` unwinds, the unwind is caught here (never crossing the `extern "C"` frame, which would be
/// UB) and the return type's [`FfiSentinel`] failure value is returned instead. The panic message
/// is logged via `tracing` so the failure is diagnosable rather than silent.
///
/// `f` is wrapped in [`AssertUnwindSafe`]: FFI bodies operate on `&`/`&mut` references and raw
/// pointers supplied by the caller, which are not `UnwindSafe`, but the boundary already returns a
/// failure sentinel on panic, so the caller cannot observe a logically-torn value through the Rust
/// side — any further use is governed by the C caller contract.
pub fn ffi_guard<R: FfiSentinel>(f: impl FnOnce() -> R) -> R {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(payload) => {
            let msg = payload
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                .unwrap_or("<non-string panic payload>");
            tracing::error!(
                panic = msg,
                "ts_ffi: caught panic at the C boundary; returning failure sentinel"
            );
            R::ffi_panic_sentinel()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_passes_through_ok() {
        assert_eq!(ffi_guard(|| 42i32), 42);
        assert!(ffi_guard(|| Some(Box::new(7u8))).is_some());
    }

    #[test]
    fn guard_returns_sentinel_on_panic() {
        let v: std::ffi::c_int = ffi_guard(|| panic!("boom"));
        assert_eq!(v, -1, "c_int panic sentinel must be -1");

        let p: *mut u8 = ffi_guard(|| panic!("boom"));
        assert!(p.is_null(), "pointer panic sentinel must be null");

        let h: Option<Box<u8>> = ffi_guard(|| panic!("boom"));
        assert!(h.is_none(), "handle panic sentinel must be None");

        let sa: sockaddr = ffi_guard(|| panic!("boom"));
        assert_eq!(
            sa.sa_family.0, 0,
            "sockaddr panic sentinel must be AF_UNSPEC"
        );

        // A String payload (vs &str) is also caught and downcast for the log.
        let v2: std::ffi::c_int = ffi_guard(|| panic!("{}", String::from("dynamic")));
        assert_eq!(v2, -1);
    }
}
