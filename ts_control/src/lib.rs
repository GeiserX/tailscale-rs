#![doc = include_str!("../README.md")]

extern crate alloc;

/// Package version of `ts_control` as reported by cargo.
// TODO(npry): this is used to populate Hostinfo.ipn_version, which requests "long format":
//  attach build info and whatever else that entails
const PKG_VERSION: &str = if let Some(version) = option_env!("CARGO_PKG_VERSION") {
    version
} else {
    ""
};

/// Client-side ACME (Let's Encrypt) DNS-01 cert issuance engine (`acme` feature, SaaS-only).
#[cfg(feature = "acme")]
pub mod acme;
#[cfg(feature = "async_tokio")]
mod cert;
mod config;
mod control_dialer;
mod derp;
mod dial_plan;
mod dns;
#[cfg_attr(not(feature = "async_tokio"), expect(dead_code))]
mod map_request_builder;
mod node;
#[cfg(feature = "async_tokio")]
mod serve;
mod service;
mod ssh_policy;
mod tka;
#[cfg(feature = "async_tokio")]
mod tokio;
#[cfg(feature = "identity-federation")]
pub mod wif;

use std::fmt;

#[cfg(feature = "async_tokio")]
pub use cert::{
    CertError, MISSING_CERT_RPC, certified_key_from_pem, get_certificate, is_tailnet_name,
};
#[cfg(feature = "acme")]
pub use cert::{PublishTxt, SetDnsPublisher, issue_certificate_via_setdns};
#[doc(inline)]
pub use config::{
    Config, DEFAULT_CONTROL_SERVER, DEFAULT_PERSISTENT_KEEPALIVE, ExitProxyConfig, ExitProxyScheme,
    TransportMode, TunConfig, services_hash,
};
pub use control_dialer::{ControlDialer, TcpDialer, complete_connection};
pub use derp::{Map as DerpMap, Region as DerpRegion, convert_derp_map};
pub use dial_plan::{DialCandidate, DialMode, DialPlan};
pub use dns::{DnsConfig, ExtraRecord, Resolver as DnsResolver, ResolverTransport};
pub use node::{
    ExitNodeSelector, Id as NodeId, Node, NodeCapMap, PeerChange, StableId as StableNodeId,
    TailnetAddress, UserProfile, is_tailscale_ip, validate_service_name,
};
#[cfg(feature = "async_tokio")]
pub use serve::{
    FunnelError, FunnelOptions, MISSING_FUNNEL_RELAY, ServeConfig, ServeState, ServeTarget,
    accept_tls, funnel_access, listen_funnel, listen_tls, tls_acceptor,
};
pub use service::{ServiceError, ServiceMode, resolve_service_listen};
pub use ssh_policy::{
    SshAccept, SshAction, SshConnIdentity, SshDecision, SshDenyReason, SshPolicy, SshPrincipal,
    SshRule,
};
pub use tka::TkaStatus;
pub use ts_control_serde::{Endpoint, EndpointType, UserId};
#[cfg(feature = "identity-federation")]
pub use wif::{WifConfig, WifError, resolve_auth_key};

/// Re-exported TLS types from the `tokio-rustls`/`ring` stack used by `cert`/`serve`, so
/// embedders can name [`get_certificate`]/[`listen_tls`] return types without taking their own
/// direct `tokio-rustls` dependency (and risking a second, mismatched crypto provider).
#[cfg(feature = "async_tokio")]
pub mod tls {
    pub use tokio_rustls::{TlsAcceptor, rustls::sign::CertifiedKey, server::TlsStream};
}

#[cfg(feature = "async_tokio")]
pub use crate::tokio::{
    AsyncControlClient, FilterUpdate, IdTokenError, LogoutError, LogoutInternalErrorKind,
    PeerUpdate, StateUpdate, TkaSyncError, TkaSyncInternalErrorKind, fetch_id_token, logout,
    tka_sync_offer, tka_sync_send,
};

/// An error which occurred while connecting to the control server or control plane.
#[derive(Debug, thiserror::Error, Clone, Eq, PartialEq)]
pub enum Error {
    /// A machine was not authorized by control to join tailnet; authorize via the supplied URL.
    #[error("machine was not authorized by control to join tailnet, authorize at {0}")]
    MachineNotAuthorized(url::Url),

    /// The user supplied an invalid URL.
    #[error("invalid URL: {0}")]
    InvalidUrl(url::Url),

    /// Control rejected registration with a specific reason (e.g. a bad/expired/unknown auth key).
    /// The string is control's verbatim `RegisterResponse.Error` message.
    #[error("control rejected registration: {0}")]
    Registration(String),

    /// Some kind of networking error.
    ///
    /// These might be addressed by retrying, or might be an unresolvable error.
    ///
    /// [`Operation`] is intended to be informational, rather then inspected during handling.
    #[error("a networking error occurred in {0}")]
    NetworkError(Operation),

    /// An internal error that users of the library are not expected to handle.
    ///
    /// [`InternalErrorKind`] and [`Operation`] are intended to be informational, rather then
    /// inspected during handling.
    #[error("{0} error in {1}")]
    Internal(InternalErrorKind, Operation),
}

impl Error {
    fn io_error(err: std::io::Error, op: Operation) -> Self {
        if crate::is_network_error(&err) {
            Error::NetworkError(op)
        } else {
            Error::Internal(InternalErrorKind::Io, op)
        }
    }
}

/// What kind of internal error has occurred.
///
/// This is intended to be useful for reporting a crash to an end user, rather than being handled.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum InternalErrorKind {
    /// An error in URL parsing.
    Url,
    /// An unsuccessful HTTP request or upgrade.
    Http,
    /// An error in serialization or deserialization.
    SerDe,
    /// An error in I/O.
    Io,
    /// An invalid message format.
    MessageFormat,
    /// An error parsing a string as UTF8.
    Utf8,
    /// Noise framework handshake.
    NoiseHandshake,
    /// Tailscale challenge packet.
    Challenge,
    /// The user's machine was not authorized to register with a Tailnet and there is no URL for
    /// the user to authorize at.
    MachineAuthorization,
}

impl fmt::Display for InternalErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InternalErrorKind::Url => write!(f, "URL parsing error"),
            InternalErrorKind::Http => write!(f, "unsuccessful HTTP request or upgrade"),
            InternalErrorKind::SerDe => write!(f, "serialization/deserialization error"),
            InternalErrorKind::Io => write!(f, "I/O error"),
            InternalErrorKind::MessageFormat => write!(f, "message format error"),
            InternalErrorKind::Utf8 => write!(f, "invalid UTF8"),
            InternalErrorKind::NoiseHandshake => write!(f, "error in Noise handshake"),
            InternalErrorKind::Challenge => write!(f, "error with Tailscale challenge packet"),
            InternalErrorKind::MachineAuthorization => {
                write!(f, "machine not authorized to register with Tailnet")
            }
        }
    }
}

/// The phase of connecting the control plane to a Tailnet in which an error occurs.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Operation {
    /// Requesting a net map.
    MapRequest,
    /// Connecting to a control server.
    ConnectToControlServer,
    /// Registering the user's device with a Tailnet.
    Registration,
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operation::MapRequest => write!(f, "net map request"),
            Operation::ConnectToControlServer => write!(f, "connection to control server"),
            Operation::Registration => write!(f, "registration"),
        }
    }
}

impl From<ts_http_util::Error> for Error {
    fn from(error: ts_http_util::Error) -> Self {
        tracing::error!(%error, "http error");

        if http_error_is_recoverable(error) {
            Error::NetworkError(Operation::ConnectToControlServer)
        } else {
            Error::Internal(InternalErrorKind::Http, Operation::ConnectToControlServer)
        }
    }
}

/// Returns true if the input io error should be classed as a network error.
fn is_network_error(err: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(
        err.kind(),
        ConnectionRefused
            | ConnectionReset
            | HostUnreachable
            | NetworkUnreachable
            | ConnectionAborted
            | NotConnected
            | TimedOut
            | AddrNotAvailable
            | Interrupted
            | NetworkDown
    )
}

/// Returns true if the error is likely to be a transient network error.
fn http_error_is_recoverable(error: ts_http_util::Error) -> bool {
    match error {
        ts_http_util::Error::Io => true,
        ts_http_util::Error::InvalidInput
        // A TCP timeout (recoverable) should get classed as an IO error, so any other kind of
        // timeout is probably not.
        | ts_http_util::Error::Timeout
        | ts_http_util::Error::InvalidResponse => false,
        // In the future, this might be recoverable with a reset.
        ts_http_util::Error::ConnectionClosed => false,
    }
}
