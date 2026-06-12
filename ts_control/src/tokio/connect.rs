use alloc::string::String;
use core::{fmt, str::FromStr};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use ts_capabilityversion::CapabilityVersion;
use ts_http_util::{BytesBody, ClientExt, EmptyBody, HeaderName, HeaderValue, Http2, ResponseExt};
use ts_keys::{MachineKeyPair, MachinePublicKey};
use url::Url;
use zerocopy::network_endian::U32;

use crate::tokio::prefixed_reader::PrefixedReader;

const CHALLENGE_MAGIC: [u8; 5] = [0xFF, 0xFF, 0xFF, b'T', b'S'];
const HANDSHAKE_HEADER_KEY: &str = "X-Tailscale-Handshake";
const MAX_CHALLENGE_LENGTH: usize = 1024;
const UPGRADE_HEADER_VALUE: &str = "tailscale-control-protocol";

lazy_static::lazy_static! {
    /// The version of the control protocol this node will use to communicate with the control
    /// plane; corresponds to the node's capability version.
    pub static ref CONTROL_PROTOCOL_VERSION: String = format!("Tailscale Control Protocol v{}", CapabilityVersion::CURRENT);
}

#[derive(Debug, thiserror::Error, Clone, Copy, Eq, PartialEq)]
pub enum ConnectionError {
    #[error("internal error during connection: {0}")]
    Internal(InternalErrorKind),
    #[error("Network error")]
    NetworkError,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum InternalErrorKind {
    Url,
    Http,
    SerDe,
    MessageFormat,
    Io,
    ChallengeLength,
    NoiseHandshake,
}

impl fmt::Display for InternalErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InternalErrorKind::Url => write!(f, "URL parsing error"),
            InternalErrorKind::Http => write!(f, "unsuccessful HTTP request or upgrade"),
            InternalErrorKind::SerDe => write!(f, "serialization/deserialization error"),
            InternalErrorKind::MessageFormat => write!(f, "message format error"),
            InternalErrorKind::Io => write!(f, "I/O error"),
            InternalErrorKind::ChallengeLength => write!(f, "challenge too long"),
            InternalErrorKind::NoiseHandshake => write!(f, "error in Noise handshake"),
        }
    }
}

impl ConnectionError {
    fn io_error(field: &'static str, stage: &'static str, err: std::io::Error) -> Self {
        tracing::error!("could not read {field} from {stage} message: {err}");

        if crate::is_network_error(&err) {
            ConnectionError::NetworkError
        } else {
            ConnectionError::Internal(InternalErrorKind::Io)
        }
    }
}

impl From<serde_json::Error> for ConnectionError {
    fn from(error: serde_json::Error) -> Self {
        tracing::error!(%error, "deserialization error");
        ConnectionError::Internal(InternalErrorKind::SerDe)
    }
}

impl From<ts_http_util::Error> for ConnectionError {
    fn from(error: ts_http_util::Error) -> Self {
        tracing::error!(%error, "http error connecting to control server");

        if crate::http_error_is_recoverable(error) {
            ConnectionError::NetworkError
        } else {
            ConnectionError::Internal(InternalErrorKind::Http)
        }
    }
}

impl From<url::ParseError> for ConnectionError {
    fn from(error: url::ParseError) -> Self {
        tracing::error!(%error, "bad URL");
        ConnectionError::Internal(InternalErrorKind::Url)
    }
}

impl From<ts_control_noise::Error> for ConnectionError {
    fn from(error: ts_control_noise::Error) -> Self {
        match error {
            ts_control_noise::Error::BadFormat => {
                ConnectionError::Internal(InternalErrorKind::MessageFormat)
            }
            ts_control_noise::Error::HandshakeFailed => {
                ConnectionError::Internal(InternalErrorKind::NoiseHandshake)
            }
            ts_control_noise::Error::Io(error) => {
                tracing::error!(%error, "IO error in Noise communication");
                ConnectionError::Internal(InternalErrorKind::Io)
            }
        }
    }
}

impl From<ConnectionError> for crate::Error {
    fn from(e: ConnectionError) -> Self {
        match e {
            ConnectionError::Internal(k) => {
                crate::Error::Internal(k.into(), crate::Operation::ConnectToControlServer)
            }
            ConnectionError::NetworkError => {
                crate::Error::NetworkError(crate::Operation::ConnectToControlServer)
            }
        }
    }
}

impl From<InternalErrorKind> for crate::InternalErrorKind {
    fn from(e: InternalErrorKind) -> Self {
        match e {
            InternalErrorKind::Url => crate::InternalErrorKind::Url,
            InternalErrorKind::Http => crate::InternalErrorKind::Http,
            InternalErrorKind::SerDe => crate::InternalErrorKind::SerDe,
            InternalErrorKind::MessageFormat => crate::InternalErrorKind::MessageFormat,
            InternalErrorKind::Io => crate::InternalErrorKind::Io,
            InternalErrorKind::ChallengeLength => crate::InternalErrorKind::Challenge,
            InternalErrorKind::NoiseHandshake => crate::InternalErrorKind::NoiseHandshake,
        }
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ControlPublicKeys {
    legacy_public_key: MachinePublicKey,
    public_key: MachinePublicKey,
}

impl fmt::Display for ControlPublicKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.public_key)
    }
}

#[tracing::instrument(skip_all, fields(%control_url), err)]
pub async fn connect(
    control_url: &Url,
    machine_keys: &MachineKeyPair,
    allow_http_key_fetch: bool,
) -> Result<Http2<BytesBody>, ConnectionError> {
    let h1_client = connect_h1(control_url).await?;

    let control_public_key = fetch_control_key(control_url, allow_http_key_fetch).await?;

    let (handshake, init_msg) = ts_control_noise::Handshake::initialize(
        &CONTROL_PROTOCOL_VERSION,
        &machine_keys.private,
        &control_public_key,
        CapabilityVersion::CURRENT,
    );

    let conn = upgrade_ts2021(control_url, &init_msg, handshake, h1_client).await?;

    // The early payload (challenge packet) is optional. The server may send
    // the magic prefix [FF FF FF 'T' 'S'] followed by a JSON challenge, or it
    // may go straight to HTTP/2 (whose first frame starts with different bytes).
    // Read the first 9 bytes (same size as an HTTP/2 frame header) and check.
    let conn = read_challenge_packet(conn).await?;

    let h2_conn = ts_http_util::http2::connect(conn).await?;
    Ok(h2_conn)
}

/// Connect an HTTP/1.1 client to the control server, using TLS for https://
/// URLs and plain TCP for http:// URLs.
async fn connect_h1(url: &Url) -> Result<ts_http_util::Http1<EmptyBody>, ConnectionError> {
    if url.scheme() == "http" {
        Ok(ts_http_util::http1::connect_tcp(url).await?)
    } else {
        Ok(ts_http_util::http1::connect_tls(url).await?)
    }
}

/// Build the `/key` fetch URL, applying the http→https upgrade policy.
///
/// Pure (no I/O) so the scheme decision is unit-testable. By default the unauthenticated key
/// bootstrap is upgraded to `https` even for an `http://` control URL; the upgrade is skipped when
/// the caller opts into http (`allow_http_key_fetch`) or the `insecure-keyfetch` build feature is
/// on. An `https://` control URL is unaffected (already https). `set_scheme` only fails as a no-op
/// when the scheme is unchanged, so its result is intentionally ignored.
fn key_fetch_url(control_url: &Url, allow_http_key_fetch: bool) -> Result<Url, url::ParseError> {
    let mut key_url = control_url.join("/key")?;
    let force_https = !allow_http_key_fetch && !cfg!(feature = "insecure-keyfetch");
    if force_https {
        let _ = key_url.set_scheme("https");
    }
    Ok(key_url)
}

/// Fetch the control server's machine public key from `GET /key`.
///
/// The `/key` bootstrap is unauthenticated, so by default it is forced over `https` even when the
/// control URL is `http://`. Pass `allow_http_key_fetch = true` (from
/// [`Config::allow_http_key_fetch`](crate::Config::allow_http_key_fetch)) to fetch it over the same
/// `http` scheme as the control URL — required for a plain-http control plane (e.g. a self-hosted
/// Headscale on a `http://host:port` LAN endpoint), and only safe over a trusted network path. The
/// compile-time `insecure-keyfetch` feature forces http unconditionally (build-time escape hatch);
/// the runtime flag is the per-deployment knob and supersedes the need for that feature.
#[tracing::instrument(skip_all, fields(%control_url, allow_http_key_fetch), ret, err, level = "trace")]
pub async fn fetch_control_key(
    control_url: &Url,
    allow_http_key_fetch: bool,
) -> Result<MachinePublicKey, ConnectionError> {
    let mut key_url = key_fetch_url(control_url, allow_http_key_fetch)?;

    if key_url.scheme() == "http" {
        tracing::warn!("fetching control key over insecure http");
    }

    key_url
        .query_pairs_mut()
        .extend_pairs([("v", CapabilityVersion::CURRENT.to_string())]);

    let client = connect_h1(&key_url).await?;
    let response = client.get(&key_url, None).await?;
    if !response.status().is_success() {
        let status = response.status();
        tracing::error!(
            status_code = status.as_str(),
            "failed to retrieve control server machine public key"
        );

        return Err(ConnectionError::Internal(InternalErrorKind::Http));
    }

    let control_keys: ControlPublicKeys = serde_json::from_slice(
        &response
            .collect_bytes_limited(crate::MAX_CONTROL_RESPONSE)
            .await?,
    )?;
    let control_public_key = control_keys.public_key;

    Ok(control_public_key)
}

#[tracing::instrument(skip_all, fields(%control_url, %init_msg), err)]
pub async fn upgrade_ts2021(
    control_url: &Url,
    init_msg: &str,
    mut handshake: ts_control_noise::Handshake,
    h1_client: impl ts_http_util::Client<EmptyBody>,
) -> Result<impl AsyncRead + AsyncWrite + Unpin + 'static, ConnectionError> {
    let ts2021_url = control_url.join("/ts2021")?;

    tracing::trace!(
        %ts2021_url,
        "started NoiseIK handshake, upgrading to TS2021"
    );

    let resp = h1_client
        .send(ts_http_util::make_upgrade_req(
            &ts2021_url,
            UPGRADE_HEADER_VALUE,
            [(
                HeaderName::from_str(HANDSHAKE_HEADER_KEY).unwrap(),
                HeaderValue::from_str(init_msg).expect("handshake header is valid"),
            )],
        )?)
        .await?;

    let upgraded = ts_http_util::do_upgrade(resp).await.map_err(|error| {
        tracing::error!(%error, "could not upgrade control connection to TS2021 protocol");
        ConnectionError::Internal(InternalErrorKind::Http)
    })?;

    let conn = handshake.complete(upgraded).await?;

    tracing::debug!("upgraded control connection from HTTP/1.1 to TS2021");

    Ok(conn)
}

/// Read the optional early payload (challenge packet) from the server.
///
/// The server may send a challenge packet with magic prefix [FF FF FF 'T' 'S'] followed
/// by a JSON payload, or it may go straight to HTTP/2. This function checks for the magic header
/// and consumes the payload if present, otherwise chaining the bytes back for consumption by the
/// HTTP/2 parser.
#[tracing::instrument(skip_all, err, level = "trace")]
pub async fn read_challenge_packet<Conn>(
    mut conn: Conn,
) -> Result<PrefixedReader<Conn>, ConnectionError>
where
    Conn: AsyncRead + Unpin,
{
    let mut magic = [0u8; CHALLENGE_MAGIC.len()];

    conn.read_exact(&mut magic)
        .await
        .map_err(|err| ConnectionError::io_error("header", "early_payload", err))?;

    // This isn't an early challenge payload, it's the start of the HTTP/2 header -- chain it back
    if magic != CHALLENGE_MAGIC {
        return Ok(PrefixedReader::new(conn, Bytes::copy_from_slice(&magic)));
    }

    let mut challenge_len: U32 = 0.into();
    conn.read_exact(challenge_len.as_mut())
        .await
        .map_err(|err| ConnectionError::io_error("length", "challenge", err))?;

    let challenge_len = challenge_len.get() as usize;
    if challenge_len > MAX_CHALLENGE_LENGTH {
        tracing::error!(
            challenge_len,
            "invalid challenge length; must be less than {MAX_CHALLENGE_LENGTH} bytes"
        );
        return Err(ConnectionError::Internal(
            InternalErrorKind::ChallengeLength,
        ));
    }

    // Read and discard the challenge JSON.
    let mut limited = conn.take(challenge_len as _);
    tokio::io::copy(&mut limited, &mut tokio::io::sink())
        .await
        .map_err(|err| ConnectionError::io_error("body", "challenge", err))?;

    tracing::trace!(
        n_bytes = challenge_len,
        "read and discarded early challenge payload"
    );

    Ok(PrefixedReader::new(
        limited.into_inner(),
        Default::default(),
    ))
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    // The `insecure-keyfetch` build feature forces http unconditionally; these scheme-policy tests
    // assert the DEFAULT (feature-off) behavior, so skip them when it's on.
    #[cfg(not(feature = "insecure-keyfetch"))]
    mod key_fetch_scheme {
        use url::Url;

        use super::super::key_fetch_url;

        /// An `http://` control URL upgrades the key fetch to `https` by default (fail-closed).
        #[test]
        fn http_control_upgrades_to_https_by_default() {
            let u = Url::parse("http://192.168.10.11:30443/").unwrap();
            let key = key_fetch_url(&u, false).unwrap();
            assert_eq!(key.scheme(), "https");
            assert_eq!(key.path(), "/key");
        }

        /// With `allow_http_key_fetch = true`, an `http://` control URL fetches `/key` over http —
        /// the fix that lets a plain-http LAN/NodePort control plane (e.g. Headscale) register.
        #[test]
        fn http_control_stays_http_when_allowed() {
            let u = Url::parse("http://192.168.10.11:30443/").unwrap();
            let key = key_fetch_url(&u, true).unwrap();
            assert_eq!(key.scheme(), "http");
            assert_eq!(key.host_str(), Some("192.168.10.11"));
            assert_eq!(key.port(), Some(30443));
        }

        /// An `https://` control URL is unaffected by the flag — it stays https either way.
        #[test]
        fn https_control_stays_https_regardless() {
            let u = Url::parse("https://controlplane.tailscale.com/").unwrap();
            assert_eq!(key_fetch_url(&u, false).unwrap().scheme(), "https");
            assert_eq!(key_fetch_url(&u, true).unwrap().scheme(), "https");
        }
    }

    /// Build a challenge packet: magic + big-endian length + JSON body.
    fn make_challenge(json: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&CHALLENGE_MAGIC);
        buf.extend_from_slice(&(json.len() as u32).to_be_bytes());
        buf.extend_from_slice(json);
        buf
    }

    /// Test that when the server sends an early challenge packet (production control
    /// server behavior), the magic+length+JSON is consumed and subsequent HTTP/2 data
    /// is passed through unmodified.
    #[tokio::test]
    async fn challenge_present() {
        let json = b"{\"nodeKeyChallenge\":\"test\"}";
        let payload = b"HTTP/2 data after challenge";

        let mut data = make_challenge(json);
        data.extend_from_slice(payload);

        let (mut writer, reader) = duplex(1024);
        writer.write_all(&data).await.unwrap();
        drop(writer);

        let mut conn = read_challenge_packet(reader).await.unwrap();

        let mut out = Vec::new();
        conn.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, payload);
    }

    /// Test that when the server skips the early challenge and goes straight to HTTP/2
    /// (testcontrol behavior), all bytes are preserved -- the 9-byte peek that didn't
    /// match the magic is chained back so the HTTP/2 parser sees the full stream.
    #[tokio::test]
    async fn challenge_absent() {
        let payload = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

        let (mut writer, reader) = duplex(1024);
        writer.write_all(payload).await.unwrap();
        drop(writer);

        let mut conn = read_challenge_packet(reader).await.unwrap();

        let mut out = Vec::new();
        conn.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, payload);
    }
}
