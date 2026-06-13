use std::ffi::{CStr, c_char};

/// Convert `c` to a `&CStr`
///
/// Returns `None` if `c` is null.
///
/// # Safety
///
/// `c` must either null or NUL-terminated and valid for reads up to the NUL-terminator.
pub unsafe fn cstr<'a>(c: *const c_char) -> Option<&'a CStr> {
    if !c.is_null() {
        // SAFETY: ensured by function safety precondition.
        Some(unsafe { CStr::from_ptr(c) })
    } else {
        None
    }
}

/// Convert `c` to a `&str`.
///
/// Returns `None` if c is null or not valid UTF-8.
///
/// # Safety
///
/// `c` must either null or NUL-terminated and valid for reads up to the NUL-terminator.
pub unsafe fn str<'a>(c: *const c_char) -> Option<&'a str> {
    // SAFETY: ensured by function safety precondition.
    unsafe { cstr(c) }.and_then(|cstr| cstr.to_str().ok())
}

/// Convert a `(ptr, len)` pair from C into a `&[u8]`, null-safely.
///
/// `core::slice::from_raw_parts` is UB if `ptr` is null — **even when `len == 0`**. A C caller
/// passing `NULL` with `len == 0` (a natural "empty buffer" idiom) would otherwise trip that UB,
/// which `ffi_guard`'s `catch_unwind` cannot catch. This maps `NULL + len 0` to an empty slice and
/// rejects a null pointer with a non-zero length (a real caller error) as `None`.
///
/// # Safety
///
/// If `ptr` is non-null, it must be valid for reads of `len` bytes and properly aligned, per
/// [`core::slice::from_raw_parts`].
pub unsafe fn slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return (len == 0).then_some(&[]);
    }
    // SAFETY: non-null, validity/alignment ensured by the function safety precondition.
    Some(unsafe { core::slice::from_raw_parts(ptr, len) })
}

/// Mutable counterpart of [`slice`]: convert a `(ptr, len)` pair into a `&mut [u8]`, null-safely.
///
/// Same null/`len == 0` handling as [`slice`].
///
/// # Safety
///
/// If `ptr` is non-null, it must be valid for reads and writes of `len` bytes and properly aligned,
/// per [`core::slice::from_raw_parts_mut`], and not aliased for the slice's lifetime.
pub unsafe fn slice_mut<'a>(ptr: *mut u8, len: usize) -> Option<&'a mut [u8]> {
    if ptr.is_null() {
        return (len == 0).then_some(&mut []);
    }
    // SAFETY: non-null, validity/alignment/non-aliasing ensured by the function safety precondition.
    Some(unsafe { core::slice::from_raw_parts_mut(ptr, len) })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The null-safe slice helpers must map null+len0 to an empty slice (the common C empty-buffer
    /// idiom), reject null+len>0 (a caller error) as None, and pass a real buffer through — never
    /// invoking `from_raw_parts(null, ..)`, which is UB even at len 0.
    #[test]
    fn slice_helpers_handle_null_and_len_zero() {
        // null + len 0 -> empty slice (NOT a from_raw_parts(null,0) UB).
        // SAFETY: null pointer, len 0 — exactly the case the helper guards.
        assert_eq!(unsafe { slice(core::ptr::null(), 0) }, Some(&[][..]));
        // null + len > 0 -> None (caller error).
        // SAFETY: null pointer; the helper returns None without dereferencing.
        assert_eq!(unsafe { slice(core::ptr::null(), 4) }, None);
        // A real buffer round-trips.
        let data = [1u8, 2, 3, 4];
        // SAFETY: `data` is valid for reads of 4 bytes.
        assert_eq!(unsafe { slice(data.as_ptr(), 4) }, Some(&data[..]));

        // Mutable variant: same null/len0 contract.
        // SAFETY: null pointer, len 0.
        assert_eq!(
            unsafe { slice_mut(core::ptr::null_mut(), 0) },
            Some(&mut [][..])
        );
        // SAFETY: null pointer; returns None without deref.
        assert!(unsafe { slice_mut(core::ptr::null_mut(), 8) }.is_none());
        let mut buf = [0u8; 3];
        let ptr = buf.as_mut_ptr();
        // SAFETY: `buf` is valid for reads+writes of 3 bytes and not aliased here.
        let s = unsafe { slice_mut(ptr, 3) }.expect("non-null buffer");
        s[0] = 9;
        assert_eq!(buf[0], 9);
    }
}
