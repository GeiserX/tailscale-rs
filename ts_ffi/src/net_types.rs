//! Platform-independent recapitulation of `<sys/socket.h>`
//!
//! This is done to avoid platform-specific dependencies on the way `<sys/socket.h>` is
//! arranged and on availability of it on your system. Notably, Rust's `libc` crate does not
//! provide a useful `sockaddr` type or variants on Windows, and further, the functionality
//! provided by this library doesn't logically represent a dependency on libc itself. The
//! interface here attempts to be compatible to make things easy, but these types are
//! specifically for interfacing with the _tailscale_ libraries, not your system, so it's ok
//! if things diverge.

use std::{
    ffi::{self, c_char},
    fmt::{Debug, Formatter},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use crate::ffi_guard;

/// Socket address family.
#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct sa_family_t(pub u16);

impl Debug for sa_family_t {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match *self {
            AF_INET => write!(f, "AF_INET"),
            AF_INET6 => write!(f, "AF_INET6"),
            _ => write!(f, "sa_family_t({})", self.0),
        }
    }
}

/// IPv4 address family.
pub const AF_INET: sa_family_t = sa_family_t(2);
/// IPv6 address family.
pub const AF_INET6: sa_family_t = sa_family_t(23);

/// IPv4 address.
#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct in_addr_t(pub [u8; 4]);

impl From<&in_addr_t> for Ipv4Addr {
    fn from(value: &in_addr_t) -> Self {
        Ipv4Addr::from_octets(value.0)
    }
}

impl From<in_addr_t> for Ipv4Addr {
    fn from(value: in_addr_t) -> Self {
        Ipv4Addr::from_octets(value.0)
    }
}

impl From<&Ipv4Addr> for in_addr_t {
    fn from(value: &Ipv4Addr) -> Self {
        Self(value.octets())
    }
}

impl From<Ipv4Addr> for in_addr_t {
    fn from(value: Ipv4Addr) -> Self {
        Self(value.octets())
    }
}

impl Debug for in_addr_t {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Ipv4Addr::from(self).fmt(f)
    }
}

/// IPv6 address.
#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct in6_addr_t(pub [u16; 8]);

impl Debug for in6_addr_t {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Ipv6Addr::from(*self).fmt(f)
    }
}

impl From<in6_addr_t> for Ipv6Addr {
    fn from(value: in6_addr_t) -> Self {
        Ipv6Addr::from(value.0)
    }
}

impl From<&in6_addr_t> for Ipv6Addr {
    fn from(value: &in6_addr_t) -> Self {
        Ipv6Addr::from(value.0)
    }
}

impl From<Ipv6Addr> for in6_addr_t {
    fn from(value: Ipv6Addr) -> Self {
        Self(value.segments())
    }
}

impl From<&Ipv6Addr> for in6_addr_t {
    fn from(value: &Ipv6Addr) -> Self {
        Self(value.segments())
    }
}

/// Socket address.
///
/// Meant for compat between `<sys/socket.h>` `sockaddr`s and tailscale sockets. On most
/// platforms, you should be able to cast directly from the sockaddr types into this struct,
/// though this isn't guaranteed if your libc makes unusual choices.
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr {
    /// Address family.
    ///
    /// Only `AF_INET` and `AF_INET6` are supported.
    pub sa_family: sa_family_t,

    /// The address info payload for this `ts_sockaddr` type.
    pub sa_data: sockaddr_data,
}

impl Debug for sockaddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.sa_family {
            // SAFETY: ensured by sa_family = AF_INET
            AF_INET => unsafe { &self.sa_data.sockaddr_in }.fmt(f),
            // SAFETY: ensured by sa_family = AF_INET6
            AF_INET6 => unsafe { &self.sa_data.sockaddr_in6 }.fmt(f),

            unknown => f
                .debug_struct("sockaddr")
                .field("sa_family", &unknown)
                .finish_non_exhaustive(),
        }
    }
}

/// Address-family-specific payload for a [`sockaddr`].
///
/// Only `AF_INET` and `AF_INET6` are supported.
#[derive(Copy, Clone)]
#[repr(C)]
pub union sockaddr_data {
    /// IPv4 sockaddr payload.
    pub sockaddr_in: sockaddr_in,
    /// IPv6 sockaddr payload.
    pub sockaddr_in6: sockaddr_in6,
}

impl TryFrom<sockaddr> for SocketAddr {
    type Error = ();

    fn try_from(sockaddr: sockaddr) -> Result<Self, Self::Error> {
        // Delegate to the by-reference impl. `sockaddr.try_into()` here would re-select THIS
        // by-value impl (sockaddr is `Copy`), recursing forever → stack-overflow abort (which
        // `ffi_guard`/`catch_unwind` cannot catch). Borrow to dispatch to `TryFrom<&sockaddr>`.
        (&sockaddr).try_into()
    }
}

impl TryFrom<&sockaddr> for SocketAddr {
    type Error = ();

    fn try_from(sockaddr: &sockaddr) -> Result<Self, Self::Error> {
        match sockaddr.sa_family {
            AF_INET => {
                // SAFETY: ensured by sa_family = AF_INET
                let sin = unsafe { &sockaddr.sa_data.sockaddr_in };
                let addrv4: SocketAddrV4 = sin.into();

                Ok(addrv4.into())
            }
            AF_INET6 => {
                // SAFETY: ensured by sa_family = AF_INET6
                let sin6 = unsafe { &sockaddr.sa_data.sockaddr_in6 };
                let addrv6: SocketAddrV6 = sin6.into();

                Ok(addrv6.into())
            }
            invalid_af => {
                tracing::error!(?invalid_af);
                Err(())
            }
        }
    }
}

impl From<SocketAddr> for sockaddr {
    fn from(value: SocketAddr) -> Self {
        match value {
            SocketAddr::V4(addr) => sockaddr {
                sa_family: AF_INET,

                sa_data: sockaddr_data {
                    sockaddr_in: addr.into(),
                },
            },
            SocketAddr::V6(addr) => sockaddr {
                sa_family: AF_INET6,

                sa_data: sockaddr_data {
                    sockaddr_in6: addr.into(),
                },
            },
        }
    }
}

/// C-compatible IPv4 socket address.
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct sockaddr_in {
    /// Port number.
    pub sin_port: u16,
    /// IPv4 address.
    pub sin_addr: in_addr_t,
}

impl From<&SocketAddrV4> for sockaddr_in {
    fn from(addr: &SocketAddrV4) -> Self {
        sockaddr_in {
            sin_addr: addr.ip().into(),
            sin_port: addr.port(),
        }
    }
}

impl From<SocketAddrV4> for sockaddr_in {
    fn from(addr: SocketAddrV4) -> Self {
        (&addr).into()
    }
}

impl From<sockaddr_in> for SocketAddrV4 {
    fn from(value: sockaddr_in) -> Self {
        (&value).into()
    }
}

impl From<&sockaddr_in> for SocketAddrV4 {
    fn from(value: &sockaddr_in) -> Self {
        SocketAddrV4::new(value.sin_addr.into(), value.sin_port)
    }
}

/// C-compatible IPv6 socket address.
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct sockaddr_in6 {
    /// Port number.
    pub sin6_port: u16,
    /// Flow label.
    pub sin6_flowinfo: u32,
    /// IPv6 address.
    pub sin6_addr: in6_addr_t,
    /// Scope id.
    pub sin6_scope_id: u32,
}

impl From<&SocketAddrV6> for sockaddr_in6 {
    fn from(addr: &SocketAddrV6) -> Self {
        sockaddr_in6 {
            sin6_addr: addr.ip().into(),
            sin6_port: addr.port(),
            sin6_scope_id: addr.scope_id(),
            sin6_flowinfo: addr.flowinfo(),
        }
    }
}

impl From<SocketAddrV6> for sockaddr_in6 {
    fn from(addr: SocketAddrV6) -> Self {
        (&addr).into()
    }
}

impl From<&sockaddr_in6> for SocketAddrV6 {
    fn from(sin6: &sockaddr_in6) -> Self {
        // `SocketAddrV6::new(addr, port, flowinfo, scope_id)` — the 4th arg is the scope id, NOT a
        // second flowinfo. Passing `sin6_flowinfo` twice dropped `sin6_scope_id` and corrupted the
        // scope (matters for IPv6 link-local zones). The symmetric `From<&SocketAddrV6>` above maps
        // both fields correctly; mirror it.
        SocketAddrV6::new(
            sin6.sin6_addr.into(),
            sin6.sin6_port,
            sin6.sin6_flowinfo,
            sin6.sin6_scope_id,
        )
    }
}

impl From<sockaddr_in6> for SocketAddrV6 {
    fn from(sin6: sockaddr_in6) -> Self {
        (&sin6).into()
    }
}

/// Parse a [`sockaddr`] from a C string.
///
/// This helper is provided to avoid the need to use `inet_pton`, `getaddrinfo`, and the
/// like if you know you have a string in a conventional `$ADDR:$PORT` shape.
///
/// # Safety
///
/// `s` must be able to be read according to [`std::ffi::CStr`] rules, i.e.
/// it must be NUL-terminated and valid for reading up to and including the NUL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_parse_sockaddr(s: *const c_char, addr: &mut sockaddr) -> ffi::c_int {
    ffi_guard(move || {
        // Null-check via the crate `util::str` helper (returns None on null or non-UTF-8) rather than
        // a bare `CStr::from_ptr`, which is UB on a null `s` and is NOT caught by `ffi_guard` (it is
        // UB, not a panic). Matches the null-safe convention used by `ts_resolve`/`ts_connect_by_name`.
        // SAFETY: ensured by function precondition (NUL-terminated / null).
        let Some(s) = (unsafe { crate::util::str(s) }) else {
            tracing::error!("null or bad utf8 sockaddr string");
            return -1;
        };

        let parsed = match s.parse::<SocketAddr>() {
            Ok(parsed) => parsed,
            Err(e) => {
                tracing::error!(error = %e, "invalid addr");
                return -1;
            }
        };

        *addr = parsed.into();

        0
    })
}

/// Parse an IP address from a string into a [`sockaddr`], setting `sa_family` and the
/// address field. The port is zeroed, and flow info and scope id are left unchanged.
///
/// This is a convenience to allow easily constructing a `sockaddr` with a string IP,
/// but using a port from a different source.
///
/// # Safety
///
/// `s` must be able to be read according to [`std::ffi::CStr`] rules, i.e.
/// it must be NUL-terminated and valid for reading up to and including the NUL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_parse_ip(s: *const c_char, addr: &mut sockaddr) -> ffi::c_int {
    ffi_guard(move || {
        // Null-check via `util::str` (None on null/non-UTF-8) rather than a bare `CStr::from_ptr`,
        // which is UB on a null `s` and uncatchable by `ffi_guard`.
        // SAFETY: ensured by function precondition (NUL-terminated / null).
        let Some(s) = (unsafe { crate::util::str(s) }) else {
            tracing::error!("null or bad utf8 ip string");
            return -1;
        };

        let parsed = match s.parse::<IpAddr>() {
            Ok(parsed) => parsed,
            Err(e) => {
                tracing::error!(error = %e, "invalid addr");
                return -1;
            }
        };

        *addr = SocketAddr::from((parsed, 0)).into();

        0
    })
}

/// Convenience to set a port on a [`sockaddr`] regardless of its `sa_family`.
///
/// Returns a negative number if `sa_family` is invalid.
#[unsafe(no_mangle)]
pub extern "C" fn ts_sockaddr_set_port(addr: &mut sockaddr, port: u16) -> ffi::c_int {
    ffi_guard(move || {
        match addr.sa_family {
            // `sa_family == AF_INET` means the active union variant is `sockaddr_in`. The assignment
            // writes the port field in place through the union place (no `unsafe` needed: assigning to
            // a union field is safe, only reading one is unsafe), so it mutates `addr` rather than a
            // copied-out temporary.
            AF_INET => {
                addr.sa_data.sockaddr_in.sin_port = port;
                0
            }
            // `sa_family == AF_INET6` means the active union variant is `sockaddr_in6`; the port is
            // written in place through the union place.
            AF_INET6 => {
                addr.sa_data.sockaddr_in6.sin6_port = port;
                0
            }
            _ => -1,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The IPv6 sockaddr↔SocketAddrV6 conversion must preserve BOTH `flowinfo` and `scope_id` as
    /// distinct fields. The decode path previously passed `sin6_flowinfo` for both, dropping the
    /// scope id (breaks IPv6 link-local zones). Use distinct non-zero values so a duplication bug
    /// can't pass by coincidence.
    #[test]
    fn sockaddr_in6_preserves_flowinfo_and_scope_id() {
        let sin6 = sockaddr_in6 {
            sin6_port: 443,
            sin6_flowinfo: 0x0011_2233,
            sin6_addr: Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 2, 3, 4).into(),
            sin6_scope_id: 0x00AA_BBCC,
        };
        let addr: SocketAddrV6 = (&sin6).into();
        assert_eq!(addr.flowinfo(), 0x0011_2233, "flowinfo must round-trip");
        assert_eq!(
            addr.scope_id(),
            0x00AA_BBCC,
            "scope_id must round-trip (not be a 2nd flowinfo)"
        );
        assert_eq!(addr.port(), 443);

        // And back the other way preserves both too (the symmetric impl).
        let back: sockaddr_in6 = (&addr).into();
        assert_eq!(back.sin6_flowinfo, 0x0011_2233);
        assert_eq!(back.sin6_scope_id, 0x00AA_BBCC);
    }

    /// The by-value `TryFrom<sockaddr>` must dispatch to the by-reference impl, not recurse into
    /// itself (which would stack-overflow → abort, uncatchable by `ffi_guard`). Exercising it on a
    /// real AF_INET sockaddr proves it terminates and produces the right address.
    #[test]
    fn try_from_owned_sockaddr_does_not_recurse() {
        let sa: sockaddr = SocketAddr::from((Ipv4Addr::new(100, 64, 0, 1), 8080)).into();
        let parsed: SocketAddr = sa.try_into().expect("owned sockaddr converts");
        assert_eq!(
            parsed,
            SocketAddr::from((Ipv4Addr::new(100, 64, 0, 1), 8080))
        );
    }

    /// A null `*const c_char` passed to the parse entry points must be rejected with -1, NOT
    /// dereferenced (UB / segfault that `ffi_guard`'s `catch_unwind` cannot save). Pins the
    /// null-check the bare `CStr::from_ptr` lacked.
    #[test]
    fn parse_entry_points_reject_null_pointer() {
        let mut addr: sockaddr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)).into();
        // SAFETY: passing a null pointer is exactly the precondition these now guard against.
        let rc_sockaddr = unsafe { ts_parse_sockaddr(core::ptr::null(), &mut addr) };
        assert_eq!(
            rc_sockaddr, -1,
            "ts_parse_sockaddr(null) must return -1, not deref null"
        );
        // SAFETY: same — null is handled, returns -1.
        let rc_ip = unsafe { ts_parse_ip(core::ptr::null(), &mut addr) };
        assert_eq!(
            rc_ip, -1,
            "ts_parse_ip(null) must return -1, not deref null"
        );
    }
}
