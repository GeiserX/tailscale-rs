//! macOS default routes from the routing-socket dump `sysctl(CTL_NET, PF_ROUTE, 0, AF_UNSPEC,
//! NET_RT_DUMP2, 0)`.
//!
//! The parser is pure, bounds-checked and compiled on every target so it can be tested and fuzzed
//! anywhere. It never casts the byte buffer to a struct: header fields are read with
//! `from_ne_bytes` at fixed offsets (asserted against `libc::rt_msghdr2` in a macOS test), and
//! sockaddrs are walked by their own `sa_len`, never past it or the message end. The only
//! `unsafe` in this module is the two `sysctl` calls.
//!
//! The dump is requested for `AF_UNSPEC` (as Go's `route.FetchRIB` does) rather than `AF_INET`, so
//! an IPv6-only default can be reported as such instead of as "offline".

use std::net::Ipv4Addr;

use super::{DefaultRoute, DefaultRoutes, LookupError};

/// Largest dump accepted.
pub const MAX_DUMP: usize = 4 << 20;

/// `RTM_VERSION` on macOS.
const RTM_VERSION: u8 = 5;
/// `RTM_GET2`: the message type `NET_RT_DUMP2` returns.
const RTM_GET2: u8 = 0x14;
/// `sizeof(struct rt_msghdr2)`.
const HDR2_LEN: usize = 92;
/// Field offsets in `struct rt_msghdr2`.
const OFF_VERSION: usize = 2;
const OFF_TYPE: usize = 3;
const OFF_INDEX: usize = 4;
const OFF_FLAGS: usize = 8;
const OFF_ADDRS: usize = 12;

const RTF_UP: u32 = 0x1;
const RTF_GATEWAY: u32 = 0x2;
const RTF_IFSCOPE: u32 = 0x100_0000;

const RTAX_DST: usize = 0;
const RTAX_GATEWAY: usize = 1;
const RTAX_NETMASK: usize = 2;
const RTAX_IFA: usize = 5;
const RTAX_MAX: usize = 8;

const AF_INET: u8 = 2;
const AF_LINK: u8 = 18;
const AF_INET6: u8 = 30;

/// One decoded sockaddr.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sa {
    V4(Ipv4Addr),
    V6([u8; 16]),
    /// A link-layer address (`sockaddr_dl`), as used by interface routes such as utun defaults.
    Link,
    /// A netmask in any form, reduced to whether it is all zeros (`/0`).
    Mask {
        zero: bool,
    },
    Other,
}

fn parse_err(offset: usize, what: &'static str) -> LookupError {
    LookupError::Parse { offset, what }
}

fn ne_u16(b: &[u8], at: usize) -> Option<u16> {
    b.get(at..at + 2).map(|s| u16::from_ne_bytes([s[0], s[1]]))
}

fn ne_u32(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4)
        .map(|s| u32::from_ne_bytes([s[0], s[1], s[2], s[3]]))
}

/// Bytes a sockaddr of length `sa_len` occupies in a routing message (Darwin's `ROUNDUP32`).
const fn roundup(sa_len: usize) -> usize {
    if sa_len == 0 {
        4
    } else {
        1 + ((sa_len - 1) | 3)
    }
}

/// Decode the sockaddr `sa` (exactly `sa_len` bytes) found at position `rtax`.
fn decode_sa(rtax: usize, sa: &[u8]) -> Sa {
    let family = sa.get(1).copied().unwrap_or(0);
    if rtax == RTAX_NETMASK {
        // Netmasks are often compact: a short `sa_len`, family 0, trailing zero bytes omitted. Only
        // "is it /0" matters here, and that holds iff every byte after the family is zero.
        return Sa::Mask {
            zero: sa.iter().skip(2).all(|&b| b == 0),
        };
    }
    match family {
        AF_INET => match sa.get(4..8) {
            Some(a) => Sa::V4(Ipv4Addr::new(a[0], a[1], a[2], a[3])),
            None => Sa::Other,
        },
        AF_INET6 => match sa.get(8..24) {
            Some(a) => {
                let mut v = [0u8; 16];
                v.copy_from_slice(a);
                Sa::V6(v)
            }
            None => Sa::Other,
        },
        AF_LINK => Sa::Link,
        _ => Sa::Other,
    }
}

/// Parse a `NET_RT_DUMP2` dump into its usable default routes: `UP | GATEWAY`, not
/// `RTF_IFSCOPE`, destination `0.0.0.0/0` (or `::/0`) and an IP gateway.
pub fn parse_rt_dump(b: &[u8]) -> Result<DefaultRoutes, LookupError> {
    let mut out = DefaultRoutes::default();
    let mut off = 0;
    while off < b.len() {
        let msg = &b[off..];
        let msglen = usize::from(ne_u16(msg, 0).ok_or(parse_err(off, "truncated header"))?);
        if msglen < 4 || msglen > msg.len() {
            return Err(parse_err(off, "bad message length"));
        }
        let msg = &msg[..msglen];
        if msg[OFF_VERSION] != RTM_VERSION {
            return Err(parse_err(off, "unexpected rtm_version"));
        }
        if msg[OFF_TYPE] == RTM_GET2 {
            if msglen < HDR2_LEN {
                return Err(parse_err(off, "message shorter than rt_msghdr2"));
            }
            parse_route(msg, off, &mut out)?;
        }
        off += msglen;
    }
    Ok(out)
}

/// Parse one `RTM_GET2` message (`msg` is exactly `rtm_msglen` bytes, at least a header long).
fn parse_route(msg: &[u8], base: usize, out: &mut DefaultRoutes) -> Result<(), LookupError> {
    let index = ne_u16(msg, OFF_INDEX).unwrap_or(0);
    let flags = ne_u32(msg, OFF_FLAGS).unwrap_or(0);
    let present = ne_u32(msg, OFF_ADDRS).unwrap_or(0);

    let mut addrs: [Option<Sa>; RTAX_MAX] = [None; RTAX_MAX];
    let mut at = HDR2_LEN;
    for (rtax, slot) in addrs.iter_mut().enumerate() {
        if present & (1 << rtax) == 0 {
            continue;
        }
        let Some(&sa_len) = msg.get(at) else {
            return Err(parse_err(base + at, "sockaddr past message end"));
        };
        let sa_len = usize::from(sa_len);
        if sa_len > msg.len() - at {
            return Err(parse_err(base + at, "sockaddr overruns message"));
        }
        *slot = Some(decode_sa(rtax, &msg[at..at + sa_len]));
        at += roundup(sa_len).min(msg.len() - at);
    }

    let usable = flags & RTF_UP != 0 && flags & RTF_GATEWAY != 0 && flags & RTF_IFSCOPE == 0;
    if !usable || addrs[RTAX_NETMASK] != Some(Sa::Mask { zero: true }) {
        return Ok(());
    }
    match (addrs[RTAX_DST], addrs[RTAX_GATEWAY]) {
        (Some(Sa::V4(dst)), Some(Sa::V4(gw))) if dst.is_unspecified() && !gw.is_unspecified() => {
            let ifa = match addrs[RTAX_IFA] {
                Some(Sa::V4(a)) if !a.is_unspecified() => Some(a),
                _ => None,
            };
            out.v4.push(DefaultRoute {
                gw,
                if_index: Some(u32::from(index)),
                if_name: None,
                metric: 0,
                ifa,
            });
        }
        (Some(Sa::V6(dst)), Some(Sa::V6(_))) if dst == [0; 16] => out.has_v6_default = true,
        _ => {}
    }
    Ok(())
}

/// Fetch the raw `NET_RT_DUMP2` dump: size query, a buffer 1.25× that, retried on `ENOMEM` (the
/// table grew in between) up to 3 times, capped at [`MAX_DUMP`].
#[cfg(target_os = "macos")]
pub fn fetch_rt_dump() -> Result<Vec<u8>, LookupError> {
    use std::{io, ptr};

    let os_err = |e: io::Error| match e.raw_os_error() {
        Some(libc::EPERM | libc::EACCES) => LookupError::Permission(e),
        _ => LookupError::Os(e),
    };
    let mut mib = [
        libc::CTL_NET,
        libc::PF_ROUTE,
        0,
        libc::AF_UNSPEC,
        libc::NET_RT_DUMP2,
        0,
    ];
    let miblen = mib.len() as libc::c_uint;
    for _ in 0..3 {
        let mut need: libc::size_t = 0;
        // SAFETY: a size query: `mib` is valid for `miblen` ints, the old buffer is null, and
        // `need` is a valid `size_t` the kernel writes the required size to. No new value is set.
        let r = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                miblen,
                ptr::null_mut(),
                &mut need,
                ptr::null_mut(),
                0,
            )
        };
        if r != 0 {
            return Err(os_err(io::Error::last_os_error()));
        }
        if need > MAX_DUMP {
            return Err(LookupError::TooLarge);
        }
        let cap = (need + need / 4).clamp(512, MAX_DUMP);
        let mut buf = vec![0u8; cap];
        let mut got: libc::size_t = cap;
        // SAFETY: `buf` is valid for writes of `got` bytes; the kernel writes at most `got` bytes
        // and stores the length it wrote in `got`. No new value is set.
        let r = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                miblen,
                buf.as_mut_ptr().cast(),
                &mut got,
                ptr::null_mut(),
                0,
            )
        };
        if r != 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ENOMEM) {
                continue;
            }
            return Err(os_err(e));
        }
        buf.truncate(got.min(cap));
        return Ok(buf);
    }
    Err(LookupError::TooLarge)
}

/// The host's default routes.
#[cfg(target_os = "macos")]
pub(super) fn default_routes() -> Result<DefaultRoutes, LookupError> {
    parse_rt_dump(&fetch_rt_dump()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::{IfInfo, select};

    fn sin(ip: [u8; 4]) -> Vec<u8> {
        let mut s = vec![16, AF_INET, 0, 0];
        s.extend_from_slice(&ip);
        s.extend_from_slice(&[0; 8]);
        s
    }

    fn sin6(ip: [u8; 16]) -> Vec<u8> {
        let mut s = vec![28, AF_INET6, 0, 0, 0, 0, 0, 0];
        s.extend_from_slice(&ip);
        s.extend_from_slice(&[0; 4]);
        s
    }

    /// A `sockaddr_dl` with no name or address (20 bytes, as the kernel pads it).
    fn sdl(index: u16) -> Vec<u8> {
        let mut s = vec![20, AF_LINK];
        s.extend_from_slice(&index.to_ne_bytes());
        s.extend_from_slice(&[0; 16]);
        s
    }

    /// The compact `/0` netmask: `sa_len` 0, occupying 4 bytes.
    fn mask0() -> Vec<u8> {
        vec![0, 0, 0, 0]
    }

    /// A compact /24 netmask: `sa_len` 7, family 0xff, three mask bytes after the 4-byte head.
    fn mask24() -> Vec<u8> {
        vec![7, 0xff, 0, 0, 255, 255, 255, 0]
    }

    /// One `RTM_GET2` message with the given flags, interface and `(RTAX index, sockaddr)` list.
    fn msg(flags: u32, index: u16, sas: &[(usize, Vec<u8>)]) -> Vec<u8> {
        let mut m = vec![0u8; HDR2_LEN];
        m[OFF_VERSION] = RTM_VERSION;
        m[OFF_TYPE] = RTM_GET2;
        m[OFF_INDEX..OFF_INDEX + 2].copy_from_slice(&index.to_ne_bytes());
        m[OFF_FLAGS..OFF_FLAGS + 4].copy_from_slice(&flags.to_ne_bytes());
        let mut present = 0u32;
        for (rtax, sa) in sas {
            present |= 1 << rtax;
            let mut sa = sa.clone();
            sa.resize(roundup(usize::from(sa[0])), 0);
            m.extend_from_slice(&sa);
        }
        m[OFF_ADDRS..OFF_ADDRS + 4].copy_from_slice(&present.to_ne_bytes());
        let len = u16::try_from(m.len()).unwrap();
        m[0..2].copy_from_slice(&len.to_ne_bytes());
        m
    }

    const UG: u32 = RTF_UP | RTF_GATEWAY;

    fn default_v4(gw: [u8; 4], index: u16, flags: u32) -> Vec<u8> {
        msg(
            flags,
            index,
            &[
                (RTAX_DST, sin([0; 4])),
                (RTAX_GATEWAY, sin(gw)),
                (RTAX_NETMASK, mask0()),
            ],
        )
    }

    fn en(name: &str, index: u32, addr: [u8; 4]) -> IfInfo {
        IfInfo {
            name: name.to_owned(),
            index,
            up: true,
            loopback: false,
            point_to_point: false,
            v4: vec![(addr.into(), 24)],
        }
    }

    /// The macOS fixture list.
    #[test]
    fn fixtures() {
        let utun_default = msg(
            RTF_UP | RTF_IFSCOPE,
            14,
            &[
                (RTAX_DST, sin([0; 4])),
                (RTAX_GATEWAY, sdl(14)),
                (RTAX_NETMASK, mask0()),
            ],
        );
        let lan = msg(
            RTF_UP,
            4,
            &[
                (RTAX_DST, sin([192, 168, 1, 0])),
                (RTAX_GATEWAY, sdl(4)),
                (RTAX_NETMASK, mask24()),
            ],
        );
        let dump = [
            // Scoped defaults (RTF_IFSCOPE) are skipped; the unscoped one wins.
            default_v4([10, 0, 0, 1], 5, UG | RTF_IFSCOPE),
            utun_default,
            lan,
            default_v4([192, 168, 1, 1], 4, UG),
            // An IPv6 default.
            msg(
                UG,
                4,
                &[
                    (RTAX_DST, sin6([0; 16])),
                    (
                        RTAX_GATEWAY,
                        sin6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
                    ),
                    (RTAX_NETMASK, mask0()),
                ],
            ),
        ]
        .concat();
        let r = parse_rt_dump(&dump).unwrap();
        assert_eq!(
            r.v4,
            vec![DefaultRoute {
                gw: Ipv4Addr::new(192, 168, 1, 1),
                if_index: Some(4),
                if_name: None,
                metric: 0,
                ifa: None,
            }]
        );
        assert!(r.has_v6_default);
        let ifs = [
            en("en0", 4, [192, 168, 1, 20]),
            en("en5", 5, [10, 0, 0, 20]),
        ];
        let gw = select(&r, &ifs, &|_| None).unwrap().unwrap();
        assert_eq!(
            (gw.if_name.as_str(), gw.self_ip),
            ("en0", Ipv4Addr::new(192, 168, 1, 20))
        );
    }

    #[test]
    fn utun_default_without_gateway_flag_is_ignored() {
        let d = msg(
            RTF_UP,
            14,
            &[
                (RTAX_DST, sin([0; 4])),
                (RTAX_GATEWAY, sdl(14)),
                (RTAX_NETMASK, mask0()),
            ],
        );
        assert_eq!(parse_rt_dump(&d).unwrap(), DefaultRoutes::default());
    }

    /// A VPN's unscoped default via a point-to-point interface, carrying an RFC 1918 gateway.
    #[test]
    fn vpn_default_is_interface_unusable() {
        let r = parse_rt_dump(&default_v4([10, 8, 0, 1], 14, UG)).unwrap();
        let mut utun = en("utun3", 14, [10, 8, 0, 2]);
        utun.point_to_point = true;
        assert!(matches!(
            select(&r, &[utun], &|_| None),
            Err(LookupError::InterfaceUnusable)
        ));
        // The interface vanished between the dump and the interface scan.
        assert!(matches!(
            select(&r, &[], &|_| None),
            Err(LookupError::InterfaceUnusable)
        ));
    }

    #[test]
    fn ipv6_only_default() {
        let d = msg(
            UG,
            4,
            &[
                (RTAX_DST, sin6([0; 16])),
                (
                    RTAX_GATEWAY,
                    sin6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
                ),
                (RTAX_NETMASK, sin6([0; 16])),
            ],
        );
        let r = parse_rt_dump(&d).unwrap();
        assert!(r.v4.is_empty() && r.has_v6_default);
        assert!(matches!(
            select(&r, &[], &|_| None),
            Err(LookupError::GatewayIpv6)
        ));
    }

    #[test]
    fn rtax_ifa_is_the_self_hint() {
        let d = msg(
            UG,
            4,
            &[
                (RTAX_DST, sin([0; 4])),
                (RTAX_GATEWAY, sin([192, 168, 1, 1])),
                (RTAX_NETMASK, mask0()),
                (4, sdl(4)),
                (RTAX_IFA, sin([192, 168, 1, 21])),
            ],
        );
        let r = parse_rt_dump(&d).unwrap();
        assert_eq!(r.v4[0].ifa, Some(Ipv4Addr::new(192, 168, 1, 21)));
        let mut i = en("en0", 4, [192, 168, 1, 20]);
        i.v4.push((Ipv4Addr::new(192, 168, 1, 21), 24));
        let gw = select(&r, &[i], &|_| None).unwrap().unwrap();
        assert_eq!(gw.self_ip, Ipv4Addr::new(192, 168, 1, 21));
    }

    #[test]
    fn non_default_masks_are_not_defaults() {
        let d = msg(
            UG,
            4,
            &[
                (RTAX_DST, sin([0; 4])),
                (RTAX_GATEWAY, sin([192, 168, 1, 1])),
                (RTAX_NETMASK, mask24()),
            ],
        );
        assert!(parse_rt_dump(&d).unwrap().v4.is_empty());
        // No netmask at all: a host route, not a default.
        let host = msg(
            UG,
            4,
            &[
                (RTAX_DST, sin([0; 4])),
                (RTAX_GATEWAY, sin([192, 168, 1, 1])),
            ],
        );
        assert!(parse_rt_dump(&host).unwrap().v4.is_empty());
    }

    /// Truncated and garbled buffers are `Parse` errors, never a panic.
    #[test]
    fn truncated_and_garbled() {
        let good = [
            default_v4([192, 168, 1, 1], 4, UG),
            default_v4([10, 0, 0, 1], 5, UG),
        ]
        .concat();
        for cut in [1, 3, 50, HDR2_LEN + 2, good.len() - 1] {
            assert!(
                matches!(parse_rt_dump(&good[..cut]), Err(LookupError::Parse { .. })),
                "cut at {cut}"
            );
        }
        let mut bad_version = good.clone();
        bad_version[OFF_VERSION] = 4;
        assert!(matches!(
            parse_rt_dump(&bad_version),
            Err(LookupError::Parse { offset: 0, .. })
        ));
        // A sockaddr whose length runs past the message.
        let mut overrun = default_v4([192, 168, 1, 1], 4, UG);
        overrun[HDR2_LEN] = 200;
        assert!(matches!(
            parse_rt_dump(&overrun),
            Err(LookupError::Parse { .. })
        ));
        // A message length shorter than the header.
        let mut short = default_v4([192, 168, 1, 1], 4, UG);
        short[0..2].copy_from_slice(&40u16.to_ne_bytes());
        assert!(matches!(
            parse_rt_dump(&short),
            Err(LookupError::Parse { .. })
        ));
        // Messages of another type are skipped by length.
        let mut other = default_v4([192, 168, 1, 1], 4, UG);
        other[OFF_TYPE] = 0x12;
        assert_eq!(parse_rt_dump(&other).unwrap(), DefaultRoutes::default());
        assert_eq!(parse_rt_dump(&[]).unwrap(), DefaultRoutes::default());
    }

    #[test]
    fn roundup_matches_darwin() {
        assert_eq!(
            [0, 1, 4, 5, 16, 20, 28].map(roundup),
            [4, 4, 4, 8, 16, 20, 28]
        );
    }

    proptest::proptest! {
        #[test]
        fn never_panics(b in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..600)) {
            drop(parse_rt_dump(&b));
        }

        /// Garbage after a valid prefix never panics either.
        #[test]
        fn valid_prefix_then_garbage(tail in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..200)) {
            let mut b = default_v4([192, 168, 1, 1], 4, UG);
            b.extend_from_slice(&tail);
            drop(parse_rt_dump(&b));
        }
    }

    /// The header offsets and constants match the platform headers.
    #[cfg(target_os = "macos")]
    #[test]
    fn header_layout_matches_libc() {
        use core::mem::{offset_of, size_of};
        assert_eq!(size_of::<libc::rt_msghdr2>(), HDR2_LEN);
        assert_eq!(offset_of!(libc::rt_msghdr2, rtm_msglen), 0);
        assert_eq!(offset_of!(libc::rt_msghdr2, rtm_version), OFF_VERSION);
        assert_eq!(offset_of!(libc::rt_msghdr2, rtm_type), OFF_TYPE);
        assert_eq!(offset_of!(libc::rt_msghdr2, rtm_index), OFF_INDEX);
        assert_eq!(offset_of!(libc::rt_msghdr2, rtm_flags), OFF_FLAGS);
        assert_eq!(offset_of!(libc::rt_msghdr2, rtm_addrs), OFF_ADDRS);
        assert_eq!(libc::RTM_VERSION, i32::from(RTM_VERSION));
        assert_eq!(libc::RTM_GET2, i32::from(RTM_GET2));
        assert_eq!(libc::RTF_UP as u32, RTF_UP);
        assert_eq!(libc::RTF_GATEWAY as u32, RTF_GATEWAY);
        assert_eq!(libc::RTF_IFSCOPE as u32, RTF_IFSCOPE);
        assert_eq!(libc::RTAX_DST as usize, RTAX_DST);
        assert_eq!(libc::RTAX_GATEWAY as usize, RTAX_GATEWAY);
        assert_eq!(libc::RTAX_NETMASK as usize, RTAX_NETMASK);
        assert_eq!(libc::RTAX_IFA as usize, RTAX_IFA);
        assert_eq!(libc::RTAX_MAX as usize, RTAX_MAX);
        assert_eq!(libc::AF_INET as u8, AF_INET);
        assert_eq!(libc::AF_INET6 as u8, AF_INET6);
        assert_eq!(libc::AF_LINK as u8, AF_LINK);
    }

    /// Port of Go's `TestFetchRoutingTable` (tailscale/tailscale#1345): repeated fetches succeed
    /// and agree on the default routes, and the live dump parses. A local read; no packet is sent.
    #[cfg(target_os = "macos")]
    #[test]
    fn fetch_routing_table_repeatedly() {
        let first = parse_rt_dump(&fetch_rt_dump().unwrap()).unwrap();
        for _ in 0..9 {
            let again = parse_rt_dump(&fetch_rt_dump().unwrap()).unwrap();
            assert_eq!(again, first);
        }
    }

    /// Adapted from Go's `TestLikelyHomeRouterIPSyscallExec`: our best unscoped IPv4 default
    /// agrees with `netstat -rn -f inet` (exec of a local tool; no network traffic).
    #[cfg(target_os = "macos")]
    #[test]
    fn agrees_with_netstat() {
        let Ok(out) = std::process::Command::new("/usr/sbin/netstat")
            .args(["-r", "-n", "-f", "inet"])
            .output()
        else {
            return;
        };
        let text = String::from_utf8_lossy(&out.stdout);
        // Same filter as Go's `likelyHomeRouterIPDarwinExec`: "default", flags with G and without
        // I (interface-scoped), an IPv4 gateway.
        let netstat: Vec<(Ipv4Addr, String)> = text
            .lines()
            .filter_map(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                match f.as_slice() {
                    ["default", gw, flags, netif, ..]
                        if flags.contains('G') && !flags.contains('I') =>
                    {
                        Some((gw.parse().ok()?, (*netif).to_owned()))
                    }
                    _ => None,
                }
            })
            .collect();
        let ours = parse_rt_dump(&fetch_rt_dump().unwrap()).unwrap();
        let ifs = crate::gateway::interfaces().unwrap();
        let mut ours: Vec<(Ipv4Addr, String)> = ours
            .v4
            .iter()
            .map(|r| {
                let name = ifs
                    .iter()
                    .find(|i| Some(i.index) == r.if_index)
                    .map(|i| i.name.clone())
                    .unwrap_or_default();
                (r.gw, name)
            })
            .collect();
        let mut netstat = netstat;
        ours.sort();
        netstat.sort();
        assert_eq!(ours, netstat);
    }
}
