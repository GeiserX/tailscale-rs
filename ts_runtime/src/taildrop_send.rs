//! Taildrop file *sender* — the client half of Tailscale's peer-to-peer file transfer.
//!
//! Where [`crate::taildrop`] + [`crate::peerapi`] implement the *receiving* half (a peer pushes a
//! file to this node and it lands in the on-disk store), this module implements the *sending* half:
//! pushing a local file to a peer over the overlay peerAPI as `PUT /v0/put/<name>`, faithfully
//! mirroring Go's wire sender.
//!
//! ## Wire contract
//!
//! We emit `PUT http://<peer>/v0/put/<url.PathEscape(name)>` with a `Content-Length: <size>` header
//! and the file bytes as the body, then expect HTTP `200` on success. The receiver returns
//! `409 Conflict` when a transfer for that name is already in progress, and `403` when the sender
//! lacks the file-send capability. We always send **from offset 0** — the Range/resume GET that Go
//! uses as an optimization to skip already-received bytes is deliberately omitted; a fresh full PUT
//! is always correct. The name is percent-escaped exactly like Go `url.PathEscape` (see
//! [`path_escape`]), the encoder counterpart to the receiver's `percent_decode`.
//!
//! ## Anti-leak
//!
//! ALL traffic rides the overlay netstack `channel` (`channel.tcp_connect`), so it travels the
//! encrypted WireGuard tunnel to the peer — **never a host socket**. IPv4-only: the local bind and
//! the destination are tailnet IPv4 addresses. This is the same discipline the DoH client
//! ([`crate::peerapi_doh`]) follows, mirrored here.

use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use netstack::{CreateSocket, netcore::Channel};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

/// How long we wait to dial the peer's peerAPI over the overlay before giving up.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long we wait for the peer's HTTP response head once the body has been sent. There is no
/// overall body-send timeout — files can be large; we rely on the connection itself for liveness.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a single write (the request head, or one body chunk) may block before we give up. This
/// bounds an otherwise-unbounded `write_all` against a hostile peer that accepts the connection then
/// never drains its receive window — without it, the post-flush [`RESPONSE_TIMEOUT`] would never be
/// reached because the body write hangs first. There is still no *total* body-send deadline (a slow
/// but live peer streaming a large file is fine); this only caps a single stalled write.
const WRITE_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Cap on the response headers we will buffer. The body is irrelevant (the receiver returns `{}`);
/// only the status line matters, so a tiny cap suffices and bounds memory against a hostile peer.
const MAX_RESP_HEADERS: usize = 8 * 1024;

/// Errors from the Taildrop file *sender* ([`send_file`]). Payload-free except
/// [`TaildropSendError::UnexpectedStatus`] so the type stays cheap to construct and compare.
#[derive(Debug)]
pub enum TaildropSendError {
    /// Dialing the peer's peerAPI over the overlay failed.
    Connect,
    /// A write to or read from the overlay stream failed.
    Io,
    /// The file name failed [`crate::taildrop::validate_base_name`] (the receiver would reject it).
    InvalidName,
    /// The receiver returned `403` — this sender lacks the file-send capability.
    Forbidden,
    /// The receiver returned `409` — a transfer for this name is already in progress.
    Conflict,
    /// The receiver returned an HTTP status we do not handle. Carries the status code.
    UnexpectedStatus(u16),
    /// The dial or the response read exceeded its timeout.
    Timeout,
}

impl core::fmt::Display for TaildropSendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TaildropSendError::Connect => write!(f, "failed to dial peer over the overlay"),
            TaildropSendError::Io => write!(f, "taildrop send I/O error"),
            TaildropSendError::InvalidName => write!(f, "invalid taildrop file name"),
            TaildropSendError::Forbidden => {
                write!(
                    f,
                    "peer rejected transfer: file-send capability denied (403)"
                )
            }
            TaildropSendError::Conflict => {
                write!(f, "a transfer for this file is already in progress (409)")
            }
            TaildropSendError::UnexpectedStatus(code) => {
                write!(f, "peer returned unexpected status {code}")
            }
            TaildropSendError::Timeout => write!(f, "taildrop send timed out"),
        }
    }
}

impl std::error::Error for TaildropSendError {}

/// Percent-escape a path segment exactly like Go `url.PathEscape`: unreserved bytes
/// (`A-Z a-z 0-9 - _ . ~`) pass through verbatim; every other byte is encoded as `%XX` with
/// uppercase hex. This is the encoder counterpart to the receiver's `percent_decode` (in
/// [`crate::peerapi`]), so `percent_decode(path_escape(x)) == x` holds. Hand-rolled, no new deps.
pub(crate) fn path_escape(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for &b in name.as_bytes() {
        let unreserved = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~');
        if unreserved {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(hex_upper(b >> 4));
            out.push(hex_upper(b & 0x0F));
        }
    }
    out
}

/// Map a 4-bit nibble (`0..=15`) to its uppercase ASCII hex digit.
fn hex_upper(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'A' + (nibble - 10)) as char,
    }
}

/// Classify an HTTP status code into a send result. Pure, so it is unit-testable without a live
/// stream: `2xx` is success; `403`/`409` map to their dedicated errors; anything else is
/// [`TaildropSendError::UnexpectedStatus`].
fn classify_status(code: u16) -> Result<(), TaildropSendError> {
    match code {
        200..=299 => Ok(()),
        403 => Err(TaildropSendError::Forbidden),
        409 => Err(TaildropSendError::Conflict),
        _ => Err(TaildropSendError::UnexpectedStatus(code)),
    }
}

/// Parse the 3-digit status code out of an HTTP/1.1 status line (`HTTP/1.1 <code> <reason>\r\n`).
/// Pure and unit-testable: returns `None` if no `HTTP/`-prefixed status line with three ASCII
/// digits after the first space can be found.
fn parse_status_line(head: &[u8]) -> Option<u16> {
    if !head.starts_with(b"HTTP/") {
        return None;
    }
    let space = head.iter().position(|&b| b == b' ')?;
    let digits = head.get(space + 1..space + 4)?;
    if !digits.iter().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let code = (digits[0] - b'0') as u16 * 100
        + (digits[1] - b'0') as u16 * 10
        + (digits[2] - b'0') as u16;
    Some(code)
}

/// Send the contents of `reader` (`content_length` bytes) to peer `dst` as a Taildrop
/// `PUT /v0/put/<name>` over the overlay netstack `channel`, binding locally to `self_ipv4`.
///
/// The name is validated up front ([`crate::taildrop::validate_base_name`]) — the receiver would
/// reject an unsafe name anyway, so we fail fast — then percent-escaped into the request path. The
/// body is streamed to EOF (we trust the caller's declared `content_length`, like Go's
/// `DeclaredSize`, and do not enforce that the read byte count matches it). Only the response status
/// line is inspected ([`classify_status`]); the body is ignored.
///
/// Anti-leak: the connection is dialed over `channel`, so it rides the encrypted overlay — never a
/// host socket.
pub async fn send_file<R>(
    channel: &Channel,
    self_ipv4: Ipv4Addr,
    dst: SocketAddr,
    name: &str,
    content_length: u64,
    mut reader: R,
) -> Result<(), TaildropSendError>
where
    R: AsyncRead + Unpin,
{
    // Fail fast on an unsafe name: the receiver validates it identically and would reject the PUT.
    crate::taildrop::validate_base_name(name).ok_or(TaildropSendError::InvalidName)?;

    let local = SocketAddr::new(self_ipv4.into(), 0);
    tracing::debug!(%dst, name, content_length, "taildrop send: dialing peer over overlay");
    let mut stream = timeout(CONNECT_TIMEOUT, channel.tcp_connect(local, dst))
        .await
        .map_err(|_| TaildropSendError::Timeout)?
        .map_err(|_| TaildropSendError::Connect)?;

    // Request head: PUT the percent-escaped name with the declared length. `Connection: close` so
    // the peer closes after answering and our response read terminates on EOF.
    let head = format!(
        "PUT /v0/put/{} HTTP/1.1\r\nHost: {dst}\r\nContent-Length: {content_length}\r\nConnection: close\r\n\r\n",
        path_escape(name),
    );
    write_all_bounded(&mut stream, head.as_bytes()).await?;

    // Stream the body to EOF.
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader
            .read(&mut buf)
            .await
            .map_err(|_| TaildropSendError::Io)?;
        if n == 0 {
            break;
        }
        write_all_bounded(&mut stream, &buf[..n]).await?;
    }
    timeout(WRITE_IDLE_TIMEOUT, stream.flush())
        .await
        .map_err(|_| TaildropSendError::Timeout)?
        .map_err(|_| TaildropSendError::Io)?;

    // Read just the response head (the body is irrelevant), bounded by both size and time.
    let code = timeout(RESPONSE_TIMEOUT, read_response_status(&mut stream))
        .await
        .map_err(|_| TaildropSendError::Timeout)??;

    match classify_status(code) {
        Ok(()) => Ok(()),
        Err(e) => {
            tracing::warn!(%dst, name, status = code, "taildrop send: peer rejected transfer");
            Err(e)
        }
    }
}

/// `write_all` one buffer to `stream`, bounded by [`WRITE_IDLE_TIMEOUT`] so a peer that accepts the
/// connection but never drains its receive window cannot block the send indefinitely. A timeout is a
/// [`TaildropSendError::Timeout`]; any other write failure is [`TaildropSendError::Io`].
async fn write_all_bounded<S>(stream: &mut S, data: &[u8]) -> Result<(), TaildropSendError>
where
    S: AsyncWriteExt + Unpin,
{
    timeout(WRITE_IDLE_TIMEOUT, stream.write_all(data))
        .await
        .map_err(|_| TaildropSendError::Timeout)?
        .map_err(|_| TaildropSendError::Io)
}

/// Read an HTTP/1.1 response head from `stream` until the `\r\n\r\n` terminator, then parse out the
/// status code. Caps the buffered headers at [`MAX_RESP_HEADERS`]; an oversized or unparseable head,
/// or an early EOF, is an [`TaildropSendError::Io`]. The `find_header_end` gate guarantees the buffer
/// passed to [`parse_status_line`] is always a fully `\r\n\r\n`-terminated head.
async fn read_response_status<S>(stream: &mut S) -> Result<u16, TaildropSendError>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    loop {
        if crate::peerapi_doh::find_header_end(&buf).is_some() {
            break;
        }
        if buf.len() > MAX_RESP_HEADERS {
            return Err(TaildropSendError::Io);
        }
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|_| TaildropSendError::Io)?;
        if n == 0 {
            return Err(TaildropSendError::Io);
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    parse_status_line(&buf).ok_or(TaildropSendError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_escape_leaves_unreserved_verbatim() {
        assert_eq!(path_escape("photo.jpg"), "photo.jpg");
        assert_eq!(
            path_escape("AZaz09-_.~"),
            "AZaz09-_.~",
            "all unreserved bytes pass through"
        );
    }

    #[test]
    fn path_escape_encodes_reserved() {
        assert_eq!(path_escape("my file.txt"), "my%20file.txt");
        assert_eq!(path_escape("a/b"), "a%2Fb");
        // Uppercase hex, non-ASCII multibyte.
        assert_eq!(path_escape("é"), "%C3%A9");
    }

    #[test]
    fn classify_status_maps_codes() {
        assert!(classify_status(200).is_ok());
        assert!(classify_status(204).is_ok());
        assert!(matches!(
            classify_status(403),
            Err(TaildropSendError::Forbidden)
        ));
        assert!(matches!(
            classify_status(409),
            Err(TaildropSendError::Conflict)
        ));
        assert!(matches!(
            classify_status(500),
            Err(TaildropSendError::UnexpectedStatus(500))
        ));
    }

    #[test]
    fn parse_status_line_extracts_code() {
        assert_eq!(
            parse_status_line(b"HTTP/1.1 200 OK\r\nX: 1\r\n\r\n"),
            Some(200)
        );
        assert_eq!(parse_status_line(b"HTTP/1.1 409 Conflict\r\n"), Some(409));
        assert_eq!(parse_status_line(b"not http at all"), None);
        assert_eq!(parse_status_line(b"HTTP/1.1 XX OK\r\n"), None);
        assert_eq!(parse_status_line(b""), None);
    }

    #[test]
    fn send_error_display_is_non_empty() {
        for e in [
            TaildropSendError::Connect,
            TaildropSendError::Io,
            TaildropSendError::InvalidName,
            TaildropSendError::Forbidden,
            TaildropSendError::Conflict,
            TaildropSendError::UnexpectedStatus(418),
            TaildropSendError::Timeout,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }
}
