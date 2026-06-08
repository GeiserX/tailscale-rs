pub use client::AsyncControlClient;
use connect::connect;
pub use connect::{
    CONTROL_PROTOCOL_VERSION, fetch_control_key, read_challenge_packet, upgrade_ts2021,
};
pub use id_token::{IdTokenError, fetch_id_token};
pub use logout::{LogoutError, LogoutInternalErrorKind, logout};
pub use map_stream::{FilterUpdate, PeerUpdate, StateUpdate};
use register::register;
// `set_dns` is a generic control RPC, but in this fork only the (feature-gated) ACME engine calls
// it; gate the `mod`/`pub use` on `acme` so the default build stays dead-code-warning-clean.
#[cfg(feature = "acme")]
pub use set_dns::{SetDnsError, set_dns};

mod client;
mod connect;
mod id_token;
mod logout;
mod map_stream;
mod ping;
mod prefixed_reader;
mod register;
#[cfg(feature = "acme")]
mod set_dns;
