//! Linux default routes from `/proc/net/route` (IPv4) and `/proc/net/ipv6_route` (only to tell
//! "offline" from "IPv6-only").
//!
//! The parsers are pure and compiled on every target so they can be tested and fuzzed anywhere;
//! only the file reads are Linux-specific.
//!
//! Limitation: `/proc/net/route` shows the main routing table only. With policy routing (`ip rule`,
//! fwmark) the gateway may be reached through another table. Sends are safe anyway: the cap binds
//! its sockets to the interface (`SO_BINDTODEVICE`) and sets `SO_DONTROUTE`; when binding is not
//! permitted ([`crate::BindMode::SourceIp`]) the cap requires the kernel's source selection for the
//! gateway to be `self_ip`, at build time and before every send. The selection itself can still be
//! wrong under policy routing (`--portmap-gateway` covers that). A netlink backend is a later
//! improvement.

use super::{DefaultRoute, LookupError};

/// Largest routing file read; anything bigger is [`LookupError::TooLarge`].
pub const MAX_BYTES: usize = 64 * 1024;
/// Most lines accepted (header included); more is [`LookupError::TooLarge`].
pub const MAX_LINES: usize = 1000;

const RTF_UP: u32 = 0x1;
const RTF_GATEWAY: u32 = 0x2;

fn parse_err(offset: usize, what: &'static str) -> LookupError {
    LookupError::Parse { offset, what }
}

/// Split capped input into lines, enforcing the byte and line caps.
fn capped_lines(text: &[u8]) -> Result<Vec<&str>, LookupError> {
    if text.len() > MAX_BYTES {
        return Err(LookupError::TooLarge);
    }
    let text = std::str::from_utf8(text).map_err(|e| parse_err(e.valid_up_to(), "not UTF-8"))?;
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.len() > MAX_LINES {
        return Err(LookupError::TooLarge);
    }
    Ok(lines)
}

fn hex_u32(field: &str, line: usize) -> Result<u32, LookupError> {
    if field.is_empty() || field.len() > 8 {
        return Err(parse_err(line, "bad hex field"));
    }
    u32::from_str_radix(field, 16).map_err(|_| parse_err(line, "bad hex field"))
}

/// Parse `/proc/net/route` into its usable IPv4 default routes: destination and mask 0, flags
/// `UP` and `GATEWAY`, and a nonzero gateway.
///
/// Addresses are the kernel's `__be32` printed as a host-order integer, so the bytes come back
/// with `to_ne_bytes` (`0101A8C0` is 192.168.1.1 on a little-endian host).
pub fn parse_proc_net_route(text: &[u8]) -> Result<Vec<DefaultRoute>, LookupError> {
    let lines = capped_lines(text)?;
    let Some((header, rows)) = lines.split_first() else {
        return Err(parse_err(0, "empty file"));
    };
    let cols: Vec<&str> = header.split_whitespace().collect();
    let col = |name: &str| {
        cols.iter()
            .position(|c| c.eq_ignore_ascii_case(name))
            .ok_or(parse_err(0, "missing column"))
    };
    let (c_if, c_dst, c_gw, c_flags, c_metric, c_mask) = (
        col("Iface")?,
        col("Destination")?,
        col("Gateway")?,
        col("Flags")?,
        col("Metric")?,
        col("Mask")?,
    );
    let needed = [c_if, c_dst, c_gw, c_flags, c_metric, c_mask]
        .into_iter()
        .max()
        .unwrap_or(0);

    let mut out = Vec::new();
    for (i, row) in rows.iter().enumerate() {
        let line = i + 1;
        let f: Vec<&str> = row.split_whitespace().collect();
        if f.len() <= needed {
            return Err(parse_err(line, "short line"));
        }
        let dst = hex_u32(f[c_dst], line)?;
        let mask = hex_u32(f[c_mask], line)?;
        let flags = hex_u32(f[c_flags], line)?;
        let gw = hex_u32(f[c_gw], line)?;
        let metric = f[c_metric]
            .parse::<u32>()
            .map_err(|_| parse_err(line, "bad metric"))?;
        let usable = flags & RTF_UP != 0 && flags & RTF_GATEWAY != 0;
        if dst != 0 || mask != 0 || !usable || gw == 0 {
            continue;
        }
        out.push(DefaultRoute {
            gw: gw.to_ne_bytes().into(),
            if_index: None,
            if_name: Some(f[c_if].to_owned()),
            metric,
            ifa: None,
        });
    }
    Ok(out)
}

/// Whether `/proc/net/ipv6_route` has a usable default route (`::/0` with `UP` and `GATEWAY`).
pub fn parse_proc_net_ipv6_route_has_default(text: &[u8]) -> Result<bool, LookupError> {
    for (line, row) in capped_lines(text)?.into_iter().enumerate() {
        let f: Vec<&str> = row.split_whitespace().collect();
        let [dst, plen, _src, _splen, _nh, _metric, _ref, _use, flags, ..] = f.as_slice() else {
            return Err(parse_err(line, "short line"));
        };
        let flags = hex_u32(flags, line)?;
        let is_default = dst.len() == 32 && dst.bytes().all(|b| b == b'0') && *plen == "00";
        if is_default && flags & RTF_UP != 0 && flags & RTF_GATEWAY != 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Combine `/proc/net/route` (`v4`, `None` if missing) with the advisory IPv6 check.
///
/// `/proc/net/ipv6_route` only tells "offline" from "IPv6-only", so `read_v6` is called only when
/// there is no IPv4 default route, and any error reading or parsing it (for example
/// [`LookupError::TooLarge`] on a host with hundreds of veth routes) counts as "no IPv6 default"
/// rather than failing a lookup whose IPv4 answer is fine.
pub fn default_routes_from(
    v4: Option<&[u8]>,
    read_v6: impl FnOnce() -> Result<Option<Vec<u8>>, LookupError>,
) -> Result<super::DefaultRoutes, LookupError> {
    let v4 = match v4 {
        Some(b) => parse_proc_net_route(b)?,
        None => Vec::new(),
    };
    let has_v6_default = v4.is_empty()
        && matches!(
            read_v6().map(|b| b.map(|b| parse_proc_net_ipv6_route_has_default(&b))),
            Ok(Some(Ok(true)))
        );
    Ok(super::DefaultRoutes { v4, has_v6_default })
}

/// Read a routing file, at most [`MAX_BYTES`] of it. A missing file reads as empty.
#[cfg(target_os = "linux")]
fn read_capped(path: &str) -> Result<Option<Vec<u8>>, LookupError> {
    use std::io::Read;
    let f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(LookupError::Permission(e));
        }
        Err(e) => return Err(LookupError::Os(e)),
    };
    let mut buf = Vec::new();
    f.take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(LookupError::Os)?;
    if buf.len() > MAX_BYTES {
        return Err(LookupError::TooLarge);
    }
    Ok(Some(buf))
}

/// The host's default routes.
#[cfg(target_os = "linux")]
pub(super) fn default_routes() -> Result<super::DefaultRoutes, LookupError> {
    let v4 = read_capped("/proc/net/route")?;
    default_routes_from(v4.as_deref(), || read_capped("/proc/net/ipv6_route"))
}

#[cfg(test)]
mod tests {
    use std::{fmt::Write, net::Ipv4Addr};

    use super::*;
    use crate::gateway::{DefaultRoutes, IfInfo, select};

    const HEADER: &str =
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n";

    /// An address as `/proc/net/route` prints it on this host.
    fn hex(ip: &str) -> String {
        let ip: Ipv4Addr = ip.parse().unwrap();
        format!("{:08X}", u32::from_ne_bytes(ip.octets()))
    }

    fn row(iface: &str, dst: &str, gw: &str, flags: u32, metric: u32, mask: &str) -> String {
        format!(
            "{iface}\t{}\t{}\t{flags:04X}\t0\t0\t{metric}\t{}\t0\t0\t0\n",
            hex(dst),
            hex(gw),
            hex(mask)
        )
    }

    fn eth(name: &str, addr: &str) -> IfInfo {
        IfInfo {
            name: name.to_owned(),
            index: 7,
            up: true,
            loopback: false,
            point_to_point: false,
            v4: vec![(addr.parse().unwrap(), 24)],
        }
    }

    fn select_from(text: &str, ifs: &[IfInfo]) -> Result<Option<crate::Gateway>, LookupError> {
        let v4 = parse_proc_net_route(text.as_bytes())?;
        select(
            &DefaultRoutes {
                v4,
                has_v6_default: false,
            },
            ifs,
            &|_| None,
        )
    }

    /// The kernel's byte order on a little-endian host.
    #[cfg(target_endian = "little")]
    #[test]
    fn hex_byte_order_golden() {
        let text =
            format!("{HEADER}eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n");
        let r = parse_proc_net_route(text.as_bytes()).unwrap();
        assert_eq!(r[0].gw, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(r[0].if_name.as_deref(), Some("eth0"));
        assert_eq!(r[0].metric, 100);
    }

    /// Metric selection, ties, down routes and non-default routes.
    #[test]
    fn selection_fixtures() {
        let ifs = [eth("eth0", "192.168.1.20"), eth("wlan0", "10.0.0.20")];
        let text = format!(
            "{HEADER}{}{}{}{}",
            row("wlan0", "0.0.0.0", "10.0.0.1", 0x3, 600, "0.0.0.0"),
            row("eth0", "0.0.0.0", "192.168.1.1", 0x3, 100, "0.0.0.0"),
            row("eth0", "192.168.1.0", "0.0.0.0", 0x1, 100, "255.255.255.0"),
            // A down default (no RTF_UP) with a better metric is ignored.
            row("wlan0", "0.0.0.0", "10.0.0.1", 0x2, 1, "0.0.0.0"),
        );
        let got = select_from(&text, &ifs).unwrap().unwrap();
        assert_eq!(got.gw, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(got.if_name, "eth0");

        let tie = format!(
            "{HEADER}{}{}",
            row("wlan0", "0.0.0.0", "10.0.0.1", 0x3, 100, "0.0.0.0"),
            row("eth0", "0.0.0.0", "192.168.1.1", 0x3, 100, "0.0.0.0"),
        );
        assert!(matches!(
            select_from(&tie, &ifs),
            Err(LookupError::Ambiguous)
        ));

        // A public best default never falls through to the private one.
        let public = format!(
            "{HEADER}{}{}",
            row("eth0", "0.0.0.0", "203.0.113.1", 0x3, 0, "0.0.0.0"),
            row("wlan0", "0.0.0.0", "10.0.0.1", 0x3, 100, "0.0.0.0"),
        );
        assert!(matches!(
            select_from(&public, &ifs),
            Err(LookupError::NotPrivate)
        ));
    }

    /// Go's `TestAwsAppRunnerDefaultRouteInterface` fixture: the default's gateway is link-local
    /// (169.254.175.249), so there is no usable gateway.
    #[cfg(target_endian = "little")]
    #[test]
    fn aws_app_runner_fixture() {
        let text = format!(
            "{HEADER}eth0\t00000000\tF9AFFEA9\t0003\t0\t0\t0\t00000000\t0\t0\t0\n\
             *\tFEA9FEA9\t00000000\t0005\t0\t0\t0\tFFFFFFFF\t0\t0\t0\n\
             ecs-eth0\t02AAFEA9\t01ACFEA9\t0007\t0\t0\t0\tFFFFFFFF\t0\t0\t0\n\
             ecs-eth0\t00ACFEA9\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n\
             eth0\t00AFFEA9\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
        );
        let r = parse_proc_net_route(text.as_bytes()).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].gw, Ipv4Addr::new(169, 254, 175, 249));
        assert!(matches!(
            select_from(&text, &[]),
            Err(LookupError::NotPrivate)
        ));
    }

    /// Go's `TestGoogleCloudRunDefaultRouteInterface` fixture: the default has no gateway, so
    /// there is nothing to map through.
    #[test]
    fn cloud_run_fixture() {
        let text = format!(
            "{HEADER}eth0\t8008FEA9\t00000000\t0001\t0\t0\t0\t01FFFFFF\t0\t0\t0\n\
             eth1\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n"
        );
        assert!(parse_proc_net_route(text.as_bytes()).unwrap().is_empty());
    }

    /// Port of Go's `TestExtremelyLongProcNetRoute` (903 lines are fine), plus the caps.
    #[test]
    fn extremely_long_proc_net_route() {
        let mut text = HEADER.to_owned();
        for n in 0..=900 {
            writeln!(
                text,
                "eth{n}\t8008FEA9\t00000000\t0001\t0\t0\t0\t01FFFFFF\t0\t0\t0"
            )
            .unwrap();
        }
        text.push_str(&row(
            "tokenring1",
            "0.0.0.0",
            "192.168.1.1",
            0x3,
            0,
            "0.0.0.0",
        ));
        let r = parse_proc_net_route(text.as_bytes()).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].if_name.as_deref(), Some("tokenring1"));

        // Over the line cap.
        for n in 0..100 {
            writeln!(
                text,
                "eth{n}\t8008FEA9\t00000000\t0001\t0\t0\t0\t01FFFFFF\t0\t0\t0"
            )
            .unwrap();
        }
        assert!(matches!(
            parse_proc_net_route(text.as_bytes()),
            Err(LookupError::TooLarge)
        ));
        // Over the byte cap.
        let big = format!("{HEADER}{}", " ".repeat(MAX_BYTES));
        assert!(matches!(
            parse_proc_net_route(big.as_bytes()),
            Err(LookupError::TooLarge)
        ));
    }

    #[test]
    fn garbled_input_is_a_parse_error() {
        for bad in [
            "".to_owned(),
            "Iface\tGateway\n".to_owned(),
            format!("{HEADER}eth0\t00000000\n"),
            format!("{HEADER}eth0\tZZZZZZZZ\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"),
            format!("{HEADER}eth0\t00000000\t0101A8C0\t0003\t0\t0\tx\t00000000\t0\t0\t0\n"),
            format!("{HEADER}eth0\t000000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"),
        ] {
            assert!(
                matches!(
                    parse_proc_net_route(bad.as_bytes()),
                    Err(LookupError::Parse { .. })
                ),
                "{bad:?}"
            );
        }
        assert!(matches!(
            parse_proc_net_route(&[0xff, 0xfe]),
            Err(LookupError::Parse { .. })
        ));
    }

    #[test]
    fn ipv6_default_detection() {
        let zero = "0".repeat(32);
        let nh = "fe800000000000000000000000000001";
        let def = format!("{zero} 00 {zero} 00 {nh} 00000400 00000001 00000000 00000003 eth0\n");
        assert!(parse_proc_net_ipv6_route_has_default(def.as_bytes()).unwrap());
        let link = format!(
            "fe800000000000000000000000000000 40 {zero} 00 {zero} 00000100 00000001 00000000 00000001 eth0\n"
        );
        assert!(!parse_proc_net_ipv6_route_has_default(link.as_bytes()).unwrap());
        assert!(parse_proc_net_ipv6_route_has_default(b"short line\n").is_err());
        assert!(!parse_proc_net_ipv6_route_has_default(b"").unwrap());
    }

    /// The IPv6 table is advisory: a huge one (hundreds of veth `fe80::/64` routes, over the cap)
    /// never fails a lookup with a valid IPv4 default, and is not even read then.
    #[test]
    fn ipv6_route_is_advisory() {
        let zero = "0".repeat(32);
        let mut veths = String::new();
        for i in 0..450 {
            writeln!(
                veths,
                "fe800000000000000000000000000000 40 {zero} 00 {zero} 00000100 00000001 00000000 00000001 veth{i:05x}"
            )
            .unwrap();
        }
        assert!(veths.len() > MAX_BYTES);
        assert!(matches!(
            parse_proc_net_ipv6_route_has_default(veths.as_bytes()),
            Err(LookupError::TooLarge)
        ));

        let v4 = format!(
            "{HEADER}{}",
            row("eth0", "0.0.0.0", "192.168.1.1", 0x3, 100, "0.0.0.0")
        );
        let r = default_routes_from(Some(v4.as_bytes()), || {
            panic!("ipv6_route read with an IPv4 default present")
        })
        .unwrap();
        let got = select(&r, &[eth("eth0", "192.168.1.20")], &|_| None)
            .unwrap()
            .unwrap();
        assert_eq!(got.gw, Ipv4Addr::new(192, 168, 1, 1));

        // No IPv4 default: an oversize or unreadable IPv6 table means "no IPv6 default".
        let r = default_routes_from(Some(HEADER.as_bytes()), || Ok(Some(veths.into_bytes())));
        assert_eq!(r.unwrap(), DefaultRoutes::default());
        let r = default_routes_from(None, || Err(LookupError::TooLarge));
        assert_eq!(r.unwrap(), DefaultRoutes::default());
        // And a real IPv6 default is still reported.
        let nh = "fe800000000000000000000000000001";
        let def = format!("{zero} 00 {zero} 00 {nh} 00000400 00000001 00000000 00000003 eth0\n");
        let r = default_routes_from(None, || Ok(Some(def.into_bytes()))).unwrap();
        assert!(r.has_v6_default && r.v4.is_empty());
    }

    proptest::proptest! {
        #[test]
        fn never_panics(b in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512)) {
            drop(parse_proc_net_route(&b));
            drop(parse_proc_net_ipv6_route_has_default(&b));
        }
    }
}
