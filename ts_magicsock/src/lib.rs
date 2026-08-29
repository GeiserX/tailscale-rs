#![doc = include_str!("../README.md")]

//! A direct (disco) UDP underlay transport for the Tailscale runtime.
//!
//! This is the second implementation of [`ts_transport::UnderlayTransport`] beside DERP. It
//! carries WireGuard datagrams directly over UDP to a peer's reachable endpoint, using the
//! [disco protocol][ts_disco_protocol] to discover and confirm which endpoint works
//! ("hole punching" / path selection). A single UDP socket carries both disco control
//! traffic and WireGuard data; the two are demultiplexed by the disco magic prefix.
//!
//! It also implements the **peer-relay client**: a peer that runs a UDP relay server offers an
//! endpoint on it in a `CallMeMaybeVia`, and once the 3-way bind handshake with that server
//! completes, WireGuard data goes through the relay — Geneve-encapsulated on the same socket —
//! instead of falling back to DERP. A direct path always wins over a relay one. This node never
//! *serves* as a relay.
//!
//! # Anti-leak posture
//!
//! The one bound UDP socket is the **only** permitted egress path for this transport, the
//! peer-relay leg included. When neither a direct path nor a confirmed relay path exists for a
//! peer (or a previously-confirmed path's trust expires), [`MagicSock`] refuses to send — it never
//! dials the host network as a silent fallback. The caller (route layer) keeps such peers on DERP.
//! This keeps the real origin IP from leaking when direct connectivity is unavailable.
//!
//! A relay server learns our public address, but so does any peer we disco-ping: relay addresses
//! are peer-supplied and pass through the same `is_pingable_candidate` sanitizer a `CallMeMaybe`
//! endpoint does, the announcing peer must be a current netmap member, and the relay endpoint must
//! have been allocated for exactly this pair of disco keys.

mod disco;
mod endpoint;
mod error;
mod metrics;
mod path;
mod relay;
mod sock;
mod stun;

pub use disco::{
    GeneveKind, Inbound, RelayHandshakeCommon, TxId, geneve_encap_disco, geneve_encap_wireguard,
    geneve_prefix, looks_like_disco, random_tx_id, seal_call_me_maybe, seal_call_me_maybe_via,
    seal_ping, seal_relay_bind, seal_relay_bind_answer, seal_relay_bind_challenge,
};
pub use endpoint::{SelfEndpoint, SelfEndpointType};
pub use error::{DiscoError, Error};
pub use path::{PeerPaths, TRUST_DURATION};
pub use relay::RelayServerEndpoint;
pub use sock::{BindingVerifier, DirectTransport, MagicSock, ReceivedData};
