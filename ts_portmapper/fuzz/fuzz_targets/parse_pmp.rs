//! NAT-PMP reply parsers: never panic, and a success always satisfies the documented invariants.
#![no_main]

use std::num::NonZeroU16;

use libfuzzer_sys::fuzz_target;
use ts_portmapper::pmp::{self, MapKind};

fuzz_target!(|data: &[u8]| {
    let _ = pmp::reply_result(data);
    if let Ok(r) = pmp::parse_public_addr_reply(data) {
        assert_eq!(data.len(), pmp::PUBLIC_ADDR_REPLY_LEN);
        assert!(ts_portmapper::is_plausible_external(r.public_ip));
    }
    // Ask for the internal port the reply carries (when there is one) to reach the success path.
    let port = data
        .get(8..10)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .and_then(NonZeroU16::new)
        .unwrap_or(NonZeroU16::MIN);
    if let Ok(r) = pmp::parse_map_reply(data, port, MapKind::Map) {
        assert_eq!(data.len(), pmp::MAP_REPLY_LEN);
        assert_eq!(r.internal, port.get());
        assert!(r.external != 0 && r.lifetime != 0);
    }
    if let Ok(r) = pmp::parse_map_reply(data, port, MapKind::Delete) {
        assert_eq!(r.lifetime, 0);
    }
});
