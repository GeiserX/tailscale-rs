//! PCP MAP reply parser (port of upstream Go's `FuzzParsePCPMapResponse`, on tailscale main after
//! v1.102.4): exactly one of a mapping or an error (by construction), a MAP parser never accepts
//! another opcode, a success always satisfies the documented invariants, and only a full-length
//! response that echoes our nonce is ever a success or an authoritative router error.
#![no_main]

use std::num::NonZeroU16;

use libfuzzer_sys::fuzz_target;
use ts_portmapper::pcp::{self, MapKind, Nonce, ReplyError};

/// The nonce "we sent". Fixed and independent of the input, so a reply has to match it the way a
/// spoofer would have to (libFuzzer's comparison tracing still finds it).
const NONCE: [u8; 12] = *b"ts-pm-nonce!";

fuzz_target!(|data: &[u8]| {
    let nonce = Nonce::from_bytes(NONCE);
    // Use the internal port the reply carries, so the success path is reachable.
    let port = data
        .get(40..42)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .and_then(NonZeroU16::new)
        .unwrap_or(NonZeroU16::MIN);
    for kind in [MapKind::Map, MapKind::Delete] {
        let r = pcp::parse_map_reply(data, &nonce, port, kind);
        if data
            .get(1)
            .is_some_and(|op| op & !pcp::R_BIT != pcp::OP_MAP)
        {
            assert!(r.is_err(), "a MAP parser accepted another opcode");
        }
        if matches!(r, Ok(_) | Err(ReplyError::Router { .. })) {
            assert!(data.len() >= pcp::MAP_LEN, "authoritative without a nonce");
            assert_eq!(&data[24..36], &NONCE, "authoritative with another nonce");
        }
        if let Err(ReplyError::Unmatched { .. }) = r {
            assert!(data.len() < pcp::MAP_LEN);
        }
        if let Ok(m) = r {
            assert_eq!(m.internal, port.get());
            assert_eq!(data[36], pcp::PROTO_UDP);
            match kind {
                MapKind::Map => {
                    assert!(m.lifetime != 0 && m.external.port() != 0);
                    assert!(ts_portmapper::is_plausible_external(*m.external.ip()));
                }
                MapKind::Delete => assert_eq!(m.lifetime, 0),
            }
        }
    }
});
