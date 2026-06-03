//! Logic for connecting to a derp server.

use core::net::{IpAddr, SocketAddr};
use std::io;

use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    task::JoinSet,
};
use ts_tls_util::ServerName;

use crate::{IpUsage, ServerConnInfo, TlsValidationConfig};

/// Error that may occur while dialing a derp server.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// IO error occurred.
    #[error("io error occurred")]
    Io,

    /// Bad parameter.
    #[error("invalid parameter")]
    InvalidParam,
}

impl From<io::Error> for Error {
    fn from(_: io::Error) -> Self {
        Error::Io
    }
}

/// Dial a TLS connection to the first server that can successfully establish a TCP
/// connection (they are tried serially in the order presented).
///
/// A returned error is specifically an error constructing the TLS connection.
///
/// Returns `Ok(None)` iff no server could be reached, either due to connectivity errors or
/// because they were not configured to be reachable (see the note in [`dial_region_tcp`]).
/// Self-signed server certs are supported via SHA-256 cert pinning (see
/// [`TlsValidationConfig::SelfSigned`]).
pub async fn dial_region_tls<'c>(
    servers: impl IntoIterator<Item = &'c ServerConnInfo>,
) -> Result<
    Option<(
        impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
        &'c ServerConnInfo,
        SocketAddr,
    )>,
    Error,
> {
    let Some((conn, server)) = dial_region_tcp(servers).await else {
        return Ok(None);
    };
    let remote_addr = conn.peer_addr()?;

    let tls_conn = match &server.tls_validation_config {
        TlsValidationConfig::CommonName { common_name } => {
            ts_tls_util::connect(
                ServerName::try_from(common_name.clone()).map_err(|e| {
                    tracing::error!(error = %e, "derp common name");
                    Error::InvalidParam
                })?,
                conn,
            )
            .await?
        }
        #[cfg(feature = "insecure-for-tests")]
        TlsValidationConfig::InsecureForTests => {
            tracing::warn!(%server.hostname, "using insecure TLS for tests");

            ts_tls_util::connect_insecure(
                ServerName::try_from(server.hostname.clone()).map_err(|e| {
                    tracing::error!(error = %e, "derp hostname");
                    Error::InvalidParam
                })?,
                conn,
            )
            .await?
        }
        TlsValidationConfig::SelfSigned { sha256 } => {
            // Self-hosted / self-signed DERP (e.g. a self-hosted control plane-embedded): accept
            // exactly the cert whose DER matches the configured SHA-256 pin. The
            // SNI still uses the configured hostname (typically an IP literal),
            // but trust is the pin, not the public PKI. Fail-closed: a mismatched
            // cert is a hard handshake error, never a downgrade.
            ts_tls_util::connect_pinned(
                ServerName::try_from(server.hostname.clone())
                    .map_err(|e| {
                        tracing::error!(error = %e, "derp self-signed hostname");
                        Error::InvalidParam
                    })?
                    .to_owned(),
                *sha256,
                conn,
            )
            .await?
        }
    };

    Ok(Some((tls_conn, server, remote_addr)))
}

/// Attempt to establish a TCP connection to one of the listed servers.
///
/// The servers are attempted serially; both IPv4 and IPv6 connections are concurrently
/// attempted for each server (if respectively enabled in the [`ServerConnInfo`]).
///
/// Returns `None` if no server could be dialed, whether due to encountered errors or
/// because they were not configured to be reachable (both ipv4/ipv6 disabled or stun_only).
pub async fn dial_region_tcp<'c>(
    servers: impl IntoIterator<Item = &'c ServerConnInfo>,
) -> Option<(TcpStream, &'c ServerConnInfo)> {
    for server in servers {
        if server.stun_only {
            tracing::trace!(%server.hostname, "server is stun only, skip");
            continue;
        }

        // SelfSigned is now supported via SHA-256 cert pinning in dial_region_tls.
        // InsecureForTests is allowed through -- TLS verification is skipped in dial_region_tls.

        match dial_server(server).await {
            Ok(Some(conn)) => {
                tracing::trace!(
                    remote_addr = %conn.peer_addr().unwrap_or((core::net::Ipv4Addr::UNSPECIFIED, 0).into()),
                    %server.hostname,
                    "derp tcp dial ok",
                );
                return Some((conn, server));
            }
            Ok(None) => {
                continue;
            }
            Err(e) => {
                tracing::error!(error = %e, %server.hostname, "failed tcp dialing server");
                continue;
            }
        }
    }

    None
}

/// Attempt a TCP connection to a single server.
///
/// IPv4 and IPv6 connections are raced concurrently: the first one to establish wins and is
/// used.
///
/// Returns `None` iff the server has both IPv4 and IPv6 configured as [`IpUsage::Disable`].
pub async fn dial_server(server: &ServerConnInfo) -> Result<Option<TcpStream>, Error> {
    let mut js = JoinSet::new();

    // TODO(npry): respect ipv6 preference. The go client just adds a flat 200ms sleep to
    //  the ipv4 sample in this case.

    js.spawn(dial_by_ipusage(
        server.ipv4,
        server.hostname.clone(),
        server.https_port,
    ));
    js.spawn(dial_by_ipusage(
        server.ipv6,
        server.hostname.clone(),
        server.https_port,
    ));

    let mut last_error = None;

    while let Some(task) = js.join_next().await {
        // A JoinError is either a cancellation (not the case by inspection) or a task panic.
        // Hence, this unwrap just forwards the inner panic, which is the behavior we want here.
        match task.unwrap() {
            Ok(Some(stream)) => return Ok(Some(stream)),
            Ok(None) => {
                continue;
            }
            Err(e) => {
                last_error = Some(e);
                continue;
            }
        }
    }

    if let Some(e) = last_error {
        Err(e.into())
    } else {
        Ok(None)
    }
}

#[tracing::instrument(skip_all, level = "trace")]
async fn dial_by_ipusage(
    ip: IpUsage<impl Into<IpAddr>>,
    hostname: String,
    port: u16,
) -> io::Result<Option<TcpStream>> {
    match ip {
        IpUsage::Disable => Ok(None),
        IpUsage::FixedAddr(ip) => {
            let ip = ip.into();

            TcpStream::connect((ip, port)).await.map(Some)
        }
        IpUsage::UseDns => TcpStream::connect((hostname, port)).await.map(Some),
    }
}
