//! Taildrop receive-side marshaling for the C FFI.
//!
//! These mirror `tailscale::Device::taildrop_waiting_files`, `taildrop_open_file`, and
//! `taildrop_delete_file`. The native `taildrop_open_file` returns a `std::fs::File`, which does
//! not cross the C ABI cleanly; instead this module exposes the two C-faithful operations a caller
//! actually needs: [`ts_taildrop_file_size`] to size a received file, and [`ts_taildrop_save_file`]
//! to copy it out to a caller-chosen destination path.

use std::ffi::{self, c_char};

use crate::{device, ffi_guard, into_c_string, util};

/// List the Taildrop files this device has fully received and not yet consumed (Go LocalAPI
/// `WaitingFiles`).
///
/// On success returns the number of waiting files (>= 0) and, when that count is positive, writes a
/// newly-allocated, NUL-terminated string to `*out` containing the file names separated by `\n`
/// (one per line, no trailing newline); the caller must free it with
/// [`ts_string_free`](crate::ts_string_free). When there are no waiting files, returns 0 and writes
/// `NULL` to `*out`. Returns a negative number on error (and writes `NULL` to `*out`).
///
/// Names are sorted by the underlying store and are validated leaf base names (no path separators),
/// so `\n`-splitting the result is unambiguous.
///
/// # Safety
///
/// `out` must be a valid, writable pointer to a `char *`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_taildrop_waiting_files(
    dev: &device,
    out: *mut *mut c_char,
) -> ffi::c_int {
    ffi_guard(move || {
        let files = match dev.0.taildrop_waiting_files() {
            Ok(files) => files,
            Err(e) => {
                tracing::error!(err = %e, "taildrop_waiting_files");
                // SAFETY: `out` is a valid writable pointer by precondition.
                unsafe { *out = std::ptr::null_mut() };
                return -1;
            }
        };

        if files.is_empty() {
            // SAFETY: `out` is a valid writable pointer by precondition.
            unsafe { *out = std::ptr::null_mut() };
            return 0;
        }

        let count = files.len() as ffi::c_int;
        let joined = files
            .into_iter()
            .map(|f| f.name)
            .collect::<Vec<_>>()
            .join("\n");

        let ptr = into_c_string(joined);
        if ptr.is_null() {
            return -1;
        }
        // SAFETY: `out` is a valid writable pointer by precondition.
        unsafe { *out = ptr };
        count
    })
}

/// Get the size in bytes of a received Taildrop file by name (Go LocalAPI `OpenFile`, size only).
///
/// On success returns 0 and writes the file's size to `*out_size`. Returns a negative number on
/// error (Taildrop disabled, invalid name, or filesystem error — logged via `tracing`).
///
/// # Safety
///
/// `name` must be readable per [`std::ffi::CStr`] rules (NUL-terminated, valid up to and including
/// the NUL). `out_size` must be a valid, writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_taildrop_file_size(
    dev: &device,
    name: *const c_char,
    out_size: &mut u64,
) -> ffi::c_int {
    ffi_guard(move || {
        // SAFETY: ensured by function precondition
        let Some(name) = (unsafe { util::str(name) }) else {
            tracing::error!("taildrop_file_size: name is null or invalid utf-8");
            return -1;
        };

        match dev.0.taildrop_open_file(name) {
            Ok((_file, size)) => {
                *out_size = size;
                0
            }
            Err(e) => {
                tracing::error!(err = %e, "taildrop_file_size");
                -1
            }
        }
    })
}

/// Save a received Taildrop file by name to the caller's destination path (the C-faithful form of
/// Go LocalAPI `OpenFile` + read-out).
///
/// Opens the received file by `name` (path-traversal-validated inside the store) and copies its
/// full contents to `dst_path`, creating or truncating it. Returns 0 on success and a negative
/// number on error (Taildrop disabled, invalid name, source open failure, or copy failure — logged
/// via `tracing`). The received file is **not** deleted; call
/// [`ts_taildrop_delete_file`] afterwards to consume it.
///
/// # Safety
///
/// `name` and `dst_path` must each be readable per [`std::ffi::CStr`] rules (NUL-terminated, valid
/// up to and including the NUL).
///
/// `dst_path` is written verbatim on the host filesystem; the C embedder is responsible for
/// ensuring it is a trusted, sanitized path (no path-traversal from untrusted input).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_taildrop_save_file(
    dev: &device,
    name: *const c_char,
    dst_path: *const c_char,
) -> ffi::c_int {
    ffi_guard(move || {
        // SAFETY: ensured by function precondition
        let (Some(name), Some(dst_path)) = (unsafe { (util::str(name), util::str(dst_path)) })
        else {
            tracing::error!("taildrop_save_file: a string argument is null or invalid utf-8");
            return -1;
        };

        let (mut src, _size) = match dev.0.taildrop_open_file(name) {
            Ok(opened) => opened,
            Err(e) => {
                tracing::error!(err = %e, "taildrop_save_file: open source");
                return -1;
            }
        };

        let mut dst = match std::fs::File::create(dst_path) {
            Ok(f) => f,
            Err(e) => {
                tracing::error!(err = %e, "taildrop_save_file: create destination");
                return -1;
            }
        };

        match std::io::copy(&mut src, &mut dst) {
            Ok(_) => 0,
            Err(e) => {
                tracing::error!(err = %e, "taildrop_save_file: copy");
                -1
            }
        }
    })
}

/// Delete a received Taildrop file by name (Go LocalAPI `DeleteFile`).
///
/// Returns 0 on success and a negative number on error (Taildrop disabled, invalid name, or
/// filesystem error — logged via `tracing`). The `name` is path-traversal-validated inside the
/// store.
///
/// # Safety
///
/// `name` must be readable per [`std::ffi::CStr`] rules (NUL-terminated, valid up to and including
/// the NUL).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_taildrop_delete_file(dev: &device, name: *const c_char) -> ffi::c_int {
    ffi_guard(move || {
        // SAFETY: ensured by function precondition
        let Some(name) = (unsafe { util::str(name) }) else {
            tracing::error!("taildrop_delete_file: name is null or invalid utf-8");
            return -1;
        };

        match dev.0.taildrop_delete_file(name) {
            Ok(()) => 0,
            Err(e) => {
                tracing::error!(err = %e, "taildrop_delete_file");
                -1
            }
        }
    })
}
