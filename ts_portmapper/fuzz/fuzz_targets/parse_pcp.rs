//! PCP header and ANNOUNCE parsers (port of upstream Go's `FuzzParsePCPResponse`, on tailscale
//! main after v1.102.4, with invariants).
#![no_main]

use libfuzzer_sys::fuzz_target;
use ts_portmapper::pcp;

fuzz_target!(|data: &[u8]| {
    if let Ok(h) = pcp::parse_header(data) {
        assert!((pcp::HEADER_LEN..=pcp::MAX_LEN).contains(&data.len()));
        assert_eq!(data.len() % 4, 0);
        assert_eq!(data[0], pcp::VERSION);
        assert_ne!(data[1] & pcp::R_BIT, 0);
        assert_eq!(h.opcode, data[1] & !pcp::R_BIT);
    }
    if pcp::parse_announce_reply(data).is_ok() {
        assert_eq!(data[1] & !pcp::R_BIT, pcp::OP_ANNOUNCE);
    }
});
