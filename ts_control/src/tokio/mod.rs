pub use client::AsyncControlClient;
use connect::connect;
pub use connect::{
    CONTROL_PROTOCOL_VERSION, fetch_control_key, read_challenge_packet, upgrade_ts2021,
};
pub use id_token::{IdTokenError, fetch_id_token};
pub use logout::{LogoutError, LogoutInternalErrorKind, logout};
pub use map_stream::{FilterUpdate, PeerUpdate, StateUpdate};
use register::register;
// `set_dns` is a generic control RPC. It is exposed unconditionally because the `tailscale` facade
// surfaces it as `Device::set_dns` (Go `LocalClient.SetDNS`), independent of the `acme` feature;
// the (feature-gated) ACME DNS-01 engine is a second caller, not the only one.
pub use set_dns::{SetDnsError, SetDnsInternalErrorKind, set_dns};
pub use tka_mutation::{tka_disable, tka_init_begin, tka_init_finish, tka_submit_signature};
pub use tka_sync::{
    TkaSyncError, TkaSyncInternalErrorKind, tka_bootstrap, tka_sync_offer, tka_sync_send,
};

mod client;
mod connect;
mod id_token;
mod logout;
mod map_stream;
mod ping;
mod prefixed_reader;
mod register;
mod set_dns;
mod tka_mutation;
mod tka_sync;
