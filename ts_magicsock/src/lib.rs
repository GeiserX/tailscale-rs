#![doc = include_str!("../README.md")]

//! A direct (disco) UDP underlay transport for the Tailscale runtime.
//!
//! This is the second implementation of [`ts_transport::UnderlayTransport`] beside DERP. It
//! carries WireGuard datagrams directly over UDP to a peer's reachable endpoint, using the
//! [disco protocol][ts_disco_protocol] to discover and confirm which endpoint works
//! ("hole punching" / path selection). A single UDP socket carries both disco control
//! traffic and WireGuard data; the two are demultiplexed by the disco magic prefix.
//!
//! # Anti-leak posture
//!
//! The one bound UDP socket is the **only** permitted egress path for this transport. When
//! no direct path to a peer is confirmed (or a previously-confirmed path's trust expires),
//! [`MagicSock`] surfaces that as the absence of a best address — it never dials the host
//! network as a silent fallback. The caller (route layer) keeps such peers on DERP. This
//! keeps the real origin IP from leaking when direct connectivity is unavailable.

mod disco;
mod endpoint;
mod error;
mod path;
mod sock;

pub use disco::{Inbound, TxId, looks_like_disco, random_tx_id, seal_call_me_maybe};
pub use endpoint::{SelfEndpoint, SelfEndpointType};
pub use error::{DiscoError, Error};
pub use path::{PeerPaths, TRUST_DURATION};
pub use sock::{BindingVerifier, DirectTransport, MagicSock, ReceivedData};
