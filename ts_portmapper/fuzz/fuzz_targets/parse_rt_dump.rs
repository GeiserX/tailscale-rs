//! macOS routing-socket dump parser: bounds-checked, never panics, and every default route it
//! reports has a nonzero gateway.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ts_portmapper::gateway::darwin::parse_rt_dump;

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = parse_rt_dump(data) {
        assert!(r.v4.iter().all(|d| !d.gw.is_unspecified() && d.if_index.is_some()));
    }
});
