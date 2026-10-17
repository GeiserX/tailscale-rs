//! Linux `/proc/net/route` and `/proc/net/ipv6_route` parsers: capped, never panic, and every
//! default route has a nonzero gateway and an interface name.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ts_portmapper::gateway::linux::{
    parse_proc_net_ipv6_route_has_default, parse_proc_net_route, MAX_BYTES,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(routes) = parse_proc_net_route(data) {
        assert!(data.len() <= MAX_BYTES);
        assert!(routes
            .iter()
            .all(|r| !r.gw.is_unspecified() && r.if_name.is_some()));
    }
    let _ = parse_proc_net_ipv6_route_has_default(data);
});
