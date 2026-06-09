#![no_main]
//! Fuzz target for the Tailnet-Lock (TKA) CBOR decoder.
//!
//! # Why this is the highest-value TKA fuzz target
//!
//! [`ts_tka::Authority::node_key_authorized`] is fed a peer's node-key-signature CBOR blob that
//! originates from the control plane / another node — i.e. **attacker-controlled bytes**. Internally
//! it calls the private `decode_node_key_signature` (a hand-written CBOR decoder), so driving
//! `node_key_authorized` with arbitrary `data` exercises the entire decode path the way a hostile
//! peer would.
//!
//! # Invariant under test: panic-free + DoS-safe
//!
//! Decoding arbitrary bytes must NEVER panic, abort, or stack-overflow — it must always return
//! `Err(TkaError::Decode(..))` (or, for a well-formed-but-unauthorized blob, some other `Err`). Two
//! concrete properties:
//!   * No slice-index panic, integer-overflow panic, or unwrap on malformed CBOR heads / truncated
//!     byte strings / bad major types.
//!   * No stack overflow from adversarial nesting: the decoder bounds container depth at
//!     `MAX_SIG_NESTING_DEPTH` (= 16, `ts_tka/src/lib.rs`), so a CBOR blob that nests arrays/maps a
//!     few bytes per level cannot blow the stack before shape validation runs.
//!
//! We assert `is_err()` rather than just ignoring the result: on this empty-trusted-key authority a
//! valid Ed25519-rooted signature is unreachable (no trusted key can match), so EVERY input must be
//! rejected. A future `Ok(())` here would itself be a finding (a forged authorization).
//!
//! # Differential-oracle intent
//!
//! Tailscale's Go `tka` decodes this same blob with `github.com/fxamacker/cbor`. The companion Go
//! oracle at `tests/vectors/gen/cbor_diff/` reads the SAME bytes from stdin and reports whether Go
//! accepts/rejects. The follow-on (tracked as tsr-19k) wires the two into an automated differential
//! loop: feed each fuzz input to both decoders and assert they agree on accept/reject. This target
//! is the Rust half of that loop; on its own it already proves the panic-free / DoS-safe invariant.

use libfuzzer_sys::fuzz_target;
use ts_tka::{Authority, AumHash, State};

fuzz_target!(|data: &[u8]| {
    // A minimal authority with an EMPTY trusted-key set. `from_state` takes a known chain `head`
    // and the trusted-key `State`; `State::default()` is the empty key set, which is all we need —
    // the goal is to reach the decoder with attacker bytes, not to authorize anything.
    let auth = Authority::from_state(AumHash([0u8; 32]), State::default());

    // The node key we are "checking" is irrelevant to the decode path; use a fixed all-zero key.
    let node_key = [0u8; 32];

    // Property: decoding arbitrary CBOR must never panic and must fail-closed (return Err). With an
    // empty trusted-key state no input can legitimately authorize, so the result is always Err.
    let result = auth.node_key_authorized(&node_key, data);
    assert!(
        result.is_err(),
        "node_key_authorized unexpectedly returned Ok on an empty-trusted-key authority"
    );
});
