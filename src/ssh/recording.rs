//! Session-recording transport for Tailscale SSH: stream a PTY session to a tsrecorder in
//! asciinema **CastV2** format.
//!
//! # What this is
//!
//! A policy rule may carry `recorders` (a list of tailnet `ip:port` recorder addresses) and an
//! `onRecordingFailure` action. Go's `tailssh` then *records the session while it runs*: it dials a
//! recorder, streams an asciinema cast over HTTP, and tees the PTY's output into that stream. This
//! module is the Rust port of that transport.
//!
//! # Upstream
//!
//! Ported from `tailscale/tailscale` at commit
//! `16dacb0c504bef3ca2bacd9478eccaa640e9780d` (`main`, 2026-09-01):
//!
//! * `sessionrecording/connect.go` — `ConnectToRecorder`, `supportsV2`, `connectV1`, `connectV2`,
//!   the `v2ResponseFrame` ack protocol, and the `perDialAttemptTimeout` / `http2ProbeTimeout` /
//!   `allDialAttemptsTimeout` / `uploadAckWindow` budgets. Unchanged since `v1.102.3`.
//! * `sessionrecording/header.go` — `CastHeader`. Unchanged since `v1.102.3`.
//! * `ssh/tailssh/tailssh.go` — `startNewRecording`, `recording`, `loggingWriter` (the fail-open /
//!   fail-closed policy around a recording that cannot start or cannot be written), and the
//!   exit-254 refusal code.
//!
//! # The two wire protocols
//!
//! A recorder is probed for the newer endpoint first, exactly as Go does:
//!
//! 1. **V2** — an HTTP/2-over-cleartext (`h2c`) `HEAD /v2/record` probe. A `200` on HTTP/2 means
//!    the recorder speaks V2, and the cast is uploaded as the body of a `POST /v2/record` whose
//!    response is a stream of `{"ack":N}` frames. If no ack arrives inside
//!    [`UPLOAD_ACK_WINDOW`] the upload is considered dead — this is what detects a recorder that
//!    has silently gone away during an idle session.
//! 2. **V1** — the legacy `POST /record` over HTTP/1.1, kept for older tsrecorder instances. The
//!    request announces `Expect: 100-continue` and the recorder's `100 Continue` is the signal
//!    that it is ready to accept the recording; only then is the session allowed to start.
//!
//! The probe is a separate `HEAD` (not an optimistic `POST`) for the reason Go documents: an
//! HTTP/2 `POST` to an HTTP/1 server hangs until the request body closes instead of answering
//! `404`, and a recording body stays open for the whole session.
//!
//! # Fail-open and fail-closed
//!
//! Go's default is **fail-open**: if recording cannot be started the session proceeds unrecorded,
//! *unless* the policy set `onRecordingFailure.rejectSessionWithMessage`, which makes it
//! fail-closed. Mid-session, a failed upload terminates the session only when
//! `onRecordingFailure.terminateSessionWithMessage` is set. Both decisions are
//! [`start_failure_action`] and [`upload_failure_action`], kept as pure functions so the policy
//! can be tested without a recorder.

use std::{
    collections::BTreeMap,
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bytes::Bytes;
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    sync::{mpsc, oneshot},
};
use ts_control::SshRecorderFailureAction;
use ts_http_util::{Client, Method, Request, ResponseExt, StatusCode};

/// asciinema cast format version written in the header (Go `CastHeader.Version = 2`).
const CAST_VERSION: u32 = 2;

/// Timeout for a single dial of one recorder address (Go `perDialAttemptTimeout`).
const PER_DIAL_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for the `HEAD /v2/record` probe (Go `http2ProbeTimeout`).
const HTTP2_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Overall budget for trying every recorder, probes and dials included (Go
/// `allDialAttemptsTimeout`).
const ALL_DIAL_ATTEMPTS_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the V2 upload waits for an ack frame before declaring the recorder gone (Go
/// `uploadAckWindow`). tsrecorder sends acks even with no new data, so this also catches a dead
/// recorder under an idle session.
pub const UPLOAD_ACK_WINDOW: Duration = Duration::from_secs(30);

/// How long the V1 connect waits for the recorder's `100 Continue` before giving up on it.
///
/// Go has no equivalent bound: `connectV1` selects on the `Got100Continue` trace against the
/// request's error channel, and a recorder that accepts the TCP connection but never answers the
/// `Expect:` header leaves `ConnectToRecorder` blocked. Bounding it here turns that hang into an
/// ordinary per-recorder failure, so the next recorder in the list is still tried and the
/// policy's `onRecordingFailure` still decides. The value matches the per-dial budget.
const EXPECT_CONTINUE_TIMEOUT: Duration = PER_DIAL_ATTEMPT_TIMEOUT;

/// Upper bound on a response head (status line plus headers) read from a recorder. A recorder is
/// a network peer, so its head is read into a bounded buffer rather than until a blank line
/// arrives — an endless header stream must not grow the client's memory.
const MAX_RESPONSE_HEAD: usize = 8 * 1024;

/// Upper bound on un-parsed V2 ack-frame bytes buffered from a recorder's response. Ack frames are
/// tens of bytes; anything past this is a recorder streaming garbage, and the upload is failed
/// rather than buffered.
const MAX_ACK_BUFFER: usize = 64 * 1024;

/// Number of cast lines that may be queued for upload before the writer blocks.
///
/// Go uses an `io.Pipe`, which blocks the session's writer until the HTTP body reader consumes the
/// bytes; a small bounded queue is the same back-pressure with one buffered batch of slack.
const CAST_QUEUE_DEPTH: usize = 64;

/// An attempt to start a recording on one recorder. Mirrors `tailcfg.SSHRecordingAttempt`; the
/// attempts are in the order the recorders were tried, and on success the last one is the recorder
/// that accepted the recording.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordingAttempt {
    /// The recorder address this attempt dialed.
    pub recorder: SocketAddr,
    /// Why the attempt failed, or empty if it succeeded.
    pub failure_message: String,
}

/// Why a recording could not be started on any configured recorder.
#[derive(Debug, thiserror::Error)]
pub enum RecorderError {
    /// The action demanded recording but carried no recorder addresses.
    #[error("recording: no recorders configured")]
    NoRecorders,
    /// Every configured recorder failed; the message enumerates each failure in order.
    #[error("{0}")]
    AllFailed(String),
    /// The overall 30-second budget for trying every recorder elapsed.
    #[error("recording: timed out connecting to recorders")]
    DialBudgetElapsed,
    /// A single recorder failed. Carries the reason.
    #[error("{0}")]
    Recorder(String),
    /// An I/O error talking to a recorder.
    #[error("recording: {0}")]
    Io(#[from] io::Error),
}

/// The header of an asciinema cast file (Go `sessionrecording.CastHeader`).
///
/// Only the fields Tailscale SSH sets are modelled; the Kubernetes-proxy fields have no counterpart
/// in this fork. Field order matches the Go struct so the emitted JSON is byte-comparable.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct CastHeader {
    /// asciinema file format version. Always 2.
    pub version: u32,
    /// Terminal width in characters; non-zero for PTY sessions.
    pub width: u16,
    /// Terminal height in characters; non-zero for PTY sessions.
    pub height: u16,
    /// Unix timestamp of when the recording started.
    pub timestamp: i64,
    /// The command that was executed. Empty for shell sessions.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub command: String,
    /// FQDN (MagicDNS name, no trailing dot) of the node originating the connection.
    #[serde(rename = "srcNode")]
    pub src_node: String,
    /// Stable node id of the node originating the connection.
    #[serde(rename = "srcNodeID")]
    pub src_node_id: String,
    /// Tags on the originating node, if it is tagged.
    #[serde(rename = "srcNodeTags", skip_serializing_if = "Vec::is_empty")]
    pub src_node_tags: Vec<String>,
    /// User id of the originating node's owner, if it is not tagged.
    #[serde(rename = "srcNodeUserID", skip_serializing_if = "is_zero")]
    pub src_node_user_id: i64,
    /// Login name of the originating node's owner, if it is not tagged.
    #[serde(rename = "srcNodeUser", skip_serializing_if = "String::is_empty")]
    pub src_node_user: String,
    /// Session environment. Go sets only `TERM`.
    pub env: BTreeMap<String, String>,
    /// The username as presented by the client.
    #[serde(rename = "sshUser")]
    pub ssh_user: String,
    /// The effective local username on the server.
    #[serde(rename = "localUser")]
    pub local_user: String,
    /// Identifier of the SSH connection this session belongs to; shared across sessions
    /// multiplexed on one connection.
    #[serde(rename = "connectionID")]
    pub connection_id: String,
}

/// `serde` predicate for Go's `omitempty` on an integer field.
fn is_zero(v: &i64) -> bool {
    *v == 0
}

impl CastHeader {
    /// A header for a session starting at `timestamp_unix`, with `TERM` set to `term`.
    ///
    /// Go refuses to write an empty `TERM` (`envValFromList` falls back to `xterm-256color`), so an
    /// empty `term` is normalized the same way here.
    pub fn new(timestamp_unix: i64, term: &str) -> Self {
        let term = if term.is_empty() {
            "xterm-256color"
        } else {
            term
        };
        Self {
            version: CAST_VERSION,
            timestamp: timestamp_unix,
            env: BTreeMap::from([("TERM".to_string(), term.to_string())]),
            ..Default::default()
        }
    }

    /// The header as the cast file's first line: its JSON encoding plus a newline.
    pub fn to_line(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut line = serde_json::to_vec(self)?;
        line.push(b'\n');
        Ok(line)
    }
}

/// One CastV2 body frame — `[elapsed_seconds, "o", data]` plus a newline (Go `loggingWriter.Write`).
///
/// `data` is the raw PTY bytes. Go stringifies them with `string(p)` and lets `encoding/json`
/// substitute U+FFFD for invalid UTF-8; [`String::from_utf8_lossy`] is the same substitution, so a
/// session emitting binary output produces the same cast on both implementations.
pub fn cast_output_line(elapsed: Duration, data: &[u8]) -> Vec<u8> {
    // `serde_json` cannot fail on (f64, &str, &str) — a non-finite f64 would be the only failure
    // mode and `Duration::as_secs_f64` is always finite — so the encoding is unwrapped into the
    // same "" a failed marshal would leave, never a panic.
    let frame = (elapsed.as_secs_f64(), "o", String::from_utf8_lossy(data));
    let mut line = serde_json::to_vec(&frame).unwrap_or_default();
    line.push(b'\n');
    line
}

/// What to do when a recording could **not be started** (Go `startNewRecording`'s error path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartFailure {
    /// Proceed with the session unrecorded. Go's default.
    FailOpen,
    /// Refuse the session, showing this message to the client
    /// (`onRecordingFailure.rejectSessionWithMessage`).
    Reject(String),
}

/// What to do when an **in-progress** recording upload fails (Go's `errChan` goroutine).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadFailure {
    /// Let the session continue unrecorded. Go's default.
    FailOpen,
    /// Terminate the session, showing this message to the client
    /// (`onRecordingFailure.terminateSessionWithMessage`).
    Terminate(String),
}

/// Go: `if onFailure != nil && onFailure.RejectSessionWithMessage != ""` → reject, else fail open.
pub fn start_failure_action(on_failure: Option<&SshRecorderFailureAction>) -> StartFailure {
    match on_failure {
        Some(f) if !f.reject_session_with_message.is_empty() => {
            StartFailure::Reject(f.reject_session_with_message.clone())
        }
        _ => StartFailure::FailOpen,
    }
}

/// Go: `if onFailure != nil && onFailure.TerminateSessionWithMessage != ""` → terminate, else fail
/// open.
pub fn upload_failure_action(on_failure: Option<&SshRecorderFailureAction>) -> UploadFailure {
    match on_failure {
        Some(f) if !f.terminate_session_with_message.is_empty() => {
            UploadFailure::Terminate(f.terminate_session_with_message.clone())
        }
        _ => UploadFailure::FailOpen,
    }
}

/// The production [`RecorderDialer`]: reaches a recorder as an ordinary tailnet peer.
///
/// Go dials recorders with the node's `UserDial`, i.e. over the tailnet and never over the host's
/// own routing table. [`Device::tcp_connect`][crate::Device::tcp_connect] is the same thing here:
/// the connection leaves through the overlay, so a recorder address is only reachable if it really
/// is a tailnet address.
pub struct TailnetDialer(std::sync::Arc<crate::Device>);

impl TailnetDialer {
    /// Dial recorders over `dev`'s tailnet.
    pub fn new(dev: std::sync::Arc<crate::Device>) -> Self {
        Self(dev)
    }
}

impl RecorderDialer for TailnetDialer {
    type Io = crate::netstack::TcpStream;

    async fn dial(&self, addr: SocketAddr) -> io::Result<Self::Io> {
        self.0.tcp_connect(addr).await.map_err(io::Error::other)
    }
}

/// How a session dials a recorder.
///
/// Production dials over the tailnet (Go uses the node's `UserDial`, so a recorder is reached as a
/// tailnet peer and never over the host's own routing table); tests supply an in-memory pipe.
pub trait RecorderDialer: Send + Sync {
    /// The connected stream this dialer produces.
    type Io: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// Dial one recorder address.
    fn dial(&self, addr: SocketAddr) -> impl Future<Output = io::Result<Self::Io>> + Send;
}

/// The streaming HTTP request body carrying the cast to the recorder.
struct CastBody {
    /// `None` for a body that is empty from the start (the `HEAD` probe).
    rx: Option<mpsc::Receiver<Bytes>>,
}

impl CastBody {
    /// A body that ends immediately.
    fn empty() -> Self {
        Self { rx: None }
    }

    /// A body fed by the session's cast lines.
    fn channel(rx: mpsc::Receiver<Bytes>) -> Self {
        Self { rx: Some(rx) }
    }
}

impl hyper::body::Body for CastBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, io::Error>>> {
        match self.get_mut().rx.as_mut() {
            None => Poll::Ready(None),
            Some(rx) => rx
                .poll_recv(cx)
                .map(|frame| frame.map(|b| Ok(hyper::body::Frame::data(b)))),
        }
    }
}

/// One ack frame of a V2 upload response (Go `v2ResponseFrame`).
#[derive(Debug, Default, serde::Deserialize)]
struct V2ResponseFrame {
    /// Bytes the recorder has received so far. Not a durability guarantee.
    #[serde(default)]
    #[allow(
        dead_code,
        reason = "the ack's arrival is the signal; its value is advisory"
    )]
    ack: i64,
    /// Set only on the last frame, when the recorder failed to store the recording.
    #[serde(default)]
    error: String,
}

/// A live upload to one recorder: where cast bytes go, and how its end is reported.
struct RecorderUpload {
    /// The recorder that accepted the recording.
    recorder: SocketAddr,
    /// Sink for cast lines.
    body: mpsc::Sender<Bytes>,
    /// Resolves once the upload ends: `Ok(())` on a clean end, `Err(msg)` on failure. Go's
    /// `errChan`.
    done: oneshot::Receiver<Result<(), String>>,
}

/// A recording that could not be started and whose policy says the session must be refused.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct RecordingRejected {
    /// The message to show the connecting client.
    pub message: String,
    /// Why recording could not start.
    #[source]
    pub cause: RecorderError,
}

/// A live session recording (Go's `recording` plus its `loggingWriter`).
#[derive(Debug)]
pub struct SessionRecording {
    /// When the recording started; cast frame timestamps are relative to it.
    start: Instant,
    /// The message to show the client if the recording breaks, or `None` when the policy fails
    /// open. Go's `recording.failOpen` is exactly "no `TerminateSessionWithMessage`", so the two
    /// are the same fact and are kept as one field.
    terminate_message: Option<String>,
    /// Sink for cast lines.
    body: mpsc::Sender<Bytes>,
    /// Set once a write failed under a fail-open policy; no further cast lines are attempted (Go
    /// `loggingWriter.recordingFailedOpen`).
    stopped: bool,
    /// Fires with the message to show the client when the upload failed and the policy says
    /// terminate. Taken by the session's output pump.
    terminate: Option<oneshot::Receiver<String>>,
    /// Held only so that dropping the recording tells the upload watcher the session is over.
    _alive: oneshot::Sender<()>,
    /// The recorder this session streams to, for logging.
    recorder: SocketAddr,
}

impl SessionRecording {
    /// Start recording this session, or decide the session may proceed without a recording.
    ///
    /// Port of Go `sshSession.startNewRecording`. The three outcomes are Go's three:
    ///
    /// * `Ok(Some(rec))` — a recorder accepted the recording and the header is written.
    /// * `Ok(None)` — recording could not start and the policy fails **open**; run the session
    ///   unrecorded (Go's `return nil, nil`).
    /// * `Err(_)` — the session must be refused (Go's `userVisibleError`, or a header that could
    ///   not be written — Go exits the session in both cases).
    pub async fn start<D: RecorderDialer>(
        recorders: &[SocketAddr],
        on_failure: Option<&SshRecorderFailureAction>,
        header: &CastHeader,
        dialer: &D,
    ) -> Result<Option<Self>, RecordingRejected> {
        let (result, attempts) = connect_to_recorder(recorders, dialer).await;

        let upload = match result {
            Ok(upload) => upload,
            Err(e) => {
                notify_unsupported(on_failure, &attempts);
                return match start_failure_action(on_failure) {
                    StartFailure::Reject(message) => {
                        tracing::warn!(error = %e, "recording: error starting recording (rejecting session)");
                        Err(RecordingRejected { message, cause: e })
                    }
                    StartFailure::FailOpen => {
                        tracing::warn!(error = %e, "recording: error starting recording (failing open)");
                        Ok(None)
                    }
                };
            }
        };

        // Go writes the header through the same writer as the body, and treats a failed header
        // write as a failed start — which refuses the session regardless of `onRecordingFailure`.
        let line = header.to_line().map_err(|e| RecordingRejected {
            message: "can't start new recording".to_string(),
            cause: RecorderError::Recorder(format!("recording: encoding cast header: {e}")),
        })?;
        if upload.body.send(Bytes::from(line)).await.is_err() {
            return Err(RecordingRejected {
                message: "can't start new recording".to_string(),
                cause: RecorderError::Recorder(
                    "recording: recorder closed the upload before the cast header".to_string(),
                ),
            });
        }

        let (terminate_tx, terminate_rx) = oneshot::channel();
        // Dropped together with the recording when the session ends, which is how the watcher
        // below tells "the recorder hung up on a live session" from "the session is simply over".
        let (alive_tx, mut alive_rx) = oneshot::channel::<()>();
        let action = upload_failure_action(on_failure);
        let terminate_message = match &action {
            UploadFailure::Terminate(message) => Some(message.clone()),
            UploadFailure::FailOpen => None,
        };
        let recorder = upload.recorder;
        let done = upload.done;
        tokio::spawn(async move {
            let err = match done.await {
                // The upload ended cleanly. Go checks the session's context here: if the session
                // is already over this is just the end of the recording, and only an upload that
                // ends *while the session runs* is a failure ("recording upload ended before the
                // SSH session") — the recorder stopped recording a session that is still going.
                Ok(Ok(())) => {
                    if matches!(
                        alive_rx.try_recv(),
                        Err(oneshot::error::TryRecvError::Closed)
                    ) {
                        tracing::debug!(%recorder, "recording: finished uploading recording");
                        return;
                    }
                    "recording upload ended before the SSH session".to_string()
                }
                Ok(Err(e)) => e,
                // The upload task went away without reporting; nothing to act on.
                Err(_) => return,
            };
            match action {
                UploadFailure::Terminate(message) => {
                    tracing::warn!(%recorder, error = %err, "recording: error uploading recording (closing session)");
                    if terminate_tx.send(message).is_err() {
                        tracing::debug!(%recorder, "recording: session ended before it could be terminated");
                    }
                }
                UploadFailure::FailOpen => {
                    tracing::warn!(%recorder, error = %err, "recording: error uploading recording (failing open)");
                }
            }
        });

        Ok(Some(Self {
            start: Instant::now(),
            terminate_message,
            body: upload.body,
            stopped: false,
            terminate: Some(terminate_rx),
            _alive: alive_tx,
            recorder,
        }))
    }

    /// The recorder this session is streamed to.
    pub fn recorder(&self) -> SocketAddr {
        self.recorder
    }

    /// Take the channel that fires with the message to show the client when the upload failed and
    /// the policy says terminate. Yields `None` after the first call.
    pub fn take_terminate(&mut self) -> Option<oneshot::Receiver<String>> {
        self.terminate.take()
    }

    /// Record one chunk of session **output**, then let the caller forward it to the client.
    ///
    /// Port of Go `loggingWriter.Write`: the cast line is written first, and a failure to write it
    /// only stops the session when the policy is fail-closed. Only output is recorded — Go
    /// deliberately does not record input, which may contain passwords.
    ///
    /// `Err` means the session must be terminated (the policy is fail-closed on a broken
    /// recording); the error is the message to show the client.
    pub async fn record_output(&mut self, data: &[u8]) -> Result<(), String> {
        if self.stopped {
            return Ok(());
        }
        let line = cast_output_line(self.start.elapsed(), data);
        if self.body.send(Bytes::from(line)).await.is_err() {
            if let Some(message) = &self.terminate_message {
                return Err(message.clone());
            }
            tracing::warn!(
                recorder = %self.recorder,
                "recording: recorder upload closed; continuing unrecorded (failing open)"
            );
            self.stopped = true;
        }
        Ok(())
    }
}

/// Log that `onRecordingFailure.notifyURL` cannot be honored.
///
/// Go posts an `SSHEventNotifyRequest` to control over Noise (`sshSession.notifyControl`). The
/// turnkey server here has no control channel of its own, so the notification is reported in the
/// log instead of silently dropped.
fn notify_unsupported(
    on_failure: Option<&SshRecorderFailureAction>,
    attempts: &[RecordingAttempt],
) {
    let Some(url) = on_failure
        .map(|f| f.notify_url.as_str())
        .filter(|u| !u.is_empty())
    else {
        return;
    };
    tracing::warn!(
        notify_url = %url,
        attempts = attempts.len(),
        "recording: onRecordingFailure.notifyURL is set but this server has no control channel to \
         notify; recording failure is reported here only"
    );
}

/// Connect to the first recorder in `recorders` that accepts a recording.
///
/// Port of Go `sessionrecording.ConnectToRecorder`. The attempts are returned in the order they
/// were made whether or not one succeeded; on success the last attempt is the connected recorder.
async fn connect_to_recorder<D: RecorderDialer>(
    recorders: &[SocketAddr],
    dialer: &D,
) -> (Result<RecorderUpload, RecorderError>, Vec<RecordingAttempt>) {
    if recorders.is_empty() {
        return (Err(RecorderError::NoRecorders), Vec::new());
    }

    // One budget for every probe and dial, so a list of black-holed recorders cannot hold the
    // session open indefinitely.
    let deadline = Instant::now() + ALL_DIAL_ATTEMPTS_TIMEOUT;

    let mut attempts = Vec::with_capacity(recorders.len());
    let mut failures = Vec::new();

    for &addr in recorders {
        let Some(budget) = deadline.checked_duration_since(Instant::now()) else {
            attempts.push(RecordingAttempt {
                recorder: addr,
                failure_message: RecorderError::DialBudgetElapsed.to_string(),
            });
            failures.push(RecorderError::DialBudgetElapsed.to_string());
            break;
        };

        match tokio::time::timeout(budget, connect_one(addr, dialer)).await {
            Ok(Ok(upload)) => {
                attempts.push(RecordingAttempt {
                    recorder: addr,
                    failure_message: String::new(),
                });
                return (Ok(upload), attempts);
            }
            Ok(Err(e)) => {
                let msg = format!("recording: error starting recording on {addr}: {e}");
                attempts.push(RecordingAttempt {
                    recorder: addr,
                    failure_message: msg.clone(),
                });
                failures.push(msg);
            }
            Err(_) => {
                let msg = format!("recording: error starting recording on {addr}: timed out");
                attempts.push(RecordingAttempt {
                    recorder: addr,
                    failure_message: msg.clone(),
                });
                failures.push(msg);
            }
        }
    }

    (Err(RecorderError::AllFailed(failures.join("; "))), attempts)
}

/// Probe one recorder for V2 and connect over whichever protocol it speaks.
///
/// Go probes with a `HEAD` on an `h2c` client and, when the probe fails, connects with a separate
/// HTTP/1 client — two clients, so two connections. The same split is made here: the probe and a
/// successful V2 upload share one connection, and the V1 fallback dials a fresh one. A **failed
/// V2 POST does not fall back**, matching Go: only the probe decides the protocol.
async fn connect_one<D: RecorderDialer>(
    addr: SocketAddr,
    dialer: &D,
) -> Result<RecorderUpload, RecorderError> {
    let io = dial(addr, dialer).await?;

    let v2 = match ts_http_util::http2::connect::<CastBody>(io).await {
        Ok(client) => supports_v2(&client, addr).await.then_some(client),
        Err(e) => {
            tracing::debug!(%addr, error = %e, "recording: h2c handshake failed; trying V1");
            None
        }
    };

    match v2 {
        Some(client) => connect_v2(client, addr).await,
        None => connect_v1(dial(addr, dialer).await?, addr).await,
    }
}

/// Dial one recorder within the per-attempt budget.
async fn dial<D: RecorderDialer>(addr: SocketAddr, dialer: &D) -> Result<D::Io, RecorderError> {
    match tokio::time::timeout(PER_DIAL_ATTEMPT_TIMEOUT, dialer.dial(addr)).await {
        Ok(io) => Ok(io?),
        Err(_) => Err(RecorderError::Recorder(format!("dialing {addr} timed out"))),
    }
}

/// Whether this recorder serves `/v2/record` (Go `supportsV2`).
///
/// A `HEAD` is used rather than the `POST` itself because an HTTP/2 `POST` to an HTTP/1 server
/// hangs until the request body is closed instead of answering `404`, and a recording body is open
/// for the whole session.
async fn supports_v2(client: &ts_http_util::Http2<CastBody>, addr: SocketAddr) -> bool {
    let req = match Request::builder()
        .method(Method::HEAD)
        .uri(format!("http://{addr}/v2/record"))
        .body(CastBody::empty())
    {
        Ok(req) => req,
        Err(e) => {
            tracing::debug!(%addr, error = %e, "recording: building V2 probe");
            return false;
        }
    };

    match tokio::time::timeout(HTTP2_PROBE_TIMEOUT, client.send(req)).await {
        Ok(Ok(resp)) => {
            resp.status() == StatusCode::OK && resp.version() >= hyper::http::Version::HTTP_2
        }
        Ok(Err(e)) => {
            tracing::debug!(%addr, error = %e, "recording: V2 probe failed; falling back to V1");
            false
        }
        Err(_) => {
            tracing::debug!(%addr, "recording: V2 probe timed out; falling back to V1");
            false
        }
    }
}

/// Upload the recording to `POST /v2/record` over `h2c` (Go `connectV2`).
async fn connect_v2(
    client: ts_http_util::Http2<CastBody>,
    addr: SocketAddr,
) -> Result<RecorderUpload, RecorderError> {
    let (body_tx, body_rx) = mpsc::channel(CAST_QUEUE_DEPTH);

    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{addr}/v2/record"))
        .body(CastBody::channel(body_rx))
        .map_err(|e| RecorderError::Recorder(format!("building V2 request: {e}")))?;

    // Over HTTP/2 this returns as soon as the response head arrives, so the ack stream can be
    // consumed while the request body is still being written.
    let resp = client
        .send(req)
        .await
        .map_err(|e| RecorderError::Recorder(format!("V2 upload: {e}")))?;

    if resp.status() != StatusCode::OK {
        return Err(RecorderError::Recorder(format!(
            "recording: unexpected status: {}",
            resp.status()
        )));
    }

    let (done_tx, done_rx) = oneshot::channel();
    let mut acks = resp.into_read();
    tokio::spawn(async move {
        // Hold the client for the upload's lifetime: dropping it tears down the h2 connection.
        let _client = client;
        if done_tx.send(read_acks(&mut acks).await).is_err() {
            tracing::debug!(%addr, "recording: session ended before the upload result was read");
        }
    });

    Ok(RecorderUpload {
        recorder: addr,
        body: body_tx,
        done: done_rx,
    })
}

/// Consume the recorder's ack stream until it ends, errors, or goes quiet.
///
/// Go runs the decode loop and the ack watchdog as two goroutines; bounding each read by
/// [`UPLOAD_ACK_WINDOW`] is the same rule — tsrecorder acks even when the session is idle, so a
/// window with no frame means the recorder is gone.
async fn read_acks<R: AsyncRead + Unpin>(acks: &mut R) -> Result<(), String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = match tokio::time::timeout(UPLOAD_ACK_WINDOW, acks.read(&mut chunk)).await {
            Ok(Ok(0)) => return Ok(()),
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(format!("recording: unexpected error receiving acks: {e}")),
            Err(_) => {
                return Err(format!(
                    "did not receive ack frames from the recorder in {}s",
                    UPLOAD_ACK_WINDOW.as_secs()
                ));
            }
        };
        buf.extend_from_slice(&chunk[..n]);
        match take_ack_frames(&mut buf) {
            Ok(frames) => {
                for frame in frames {
                    if !frame.error.is_empty() {
                        return Err(format!(
                            "recording: received error from the recorder: {:?}",
                            frame.error
                        ));
                    }
                }
            }
            Err(e) => return Err(e),
        }
        if buf.len() > MAX_ACK_BUFFER {
            return Err("recording: recorder sent an oversized ack frame".to_string());
        }
    }
}

/// Decode every complete ack frame at the front of `buf` and drain them from it.
///
/// The recorder writes frames back to back with no delimiter, exactly as Go's `json.Decoder`
/// reads them, so a partial trailing frame is left in `buf` for the next read.
fn take_ack_frames(buf: &mut Vec<u8>) -> Result<Vec<V2ResponseFrame>, String> {
    let mut frames = Vec::new();
    let consumed = {
        let mut stream = serde_json::Deserializer::from_slice(buf).into_iter::<V2ResponseFrame>();
        loop {
            match stream.next() {
                Some(Ok(frame)) => frames.push(frame),
                // An incomplete trailing frame is normal: the rest arrives on the next read.
                Some(Err(e)) if e.is_eof() => break stream.byte_offset(),
                Some(Err(e)) => {
                    return Err(format!("recording: unexpected error receiving acks: {e}"));
                }
                None => break stream.byte_offset(),
            }
        }
    };
    buf.drain(..consumed);
    Ok(frames)
}

/// Upload the recording to the legacy `POST /record` over HTTP/1.1 (Go `connectV1`).
///
/// The request is written by hand rather than through an HTTP client because the recorder's
/// `100 Continue` **is** the readiness signal: the session is only allowed to start once the
/// recorder has said it will accept the recording. Go gets that signal from an
/// `httptrace.ClientTrace`; hyper's client does not surface informational responses, so an
/// optimistic connect would report success to a recorder that is about to refuse — turning a
/// fail-closed policy into a silently unrecorded session.
async fn connect_v1<Io: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    io: Io,
    addr: SocketAddr,
) -> Result<RecorderUpload, RecorderError> {
    let (read, mut write) = tokio::io::split(io);
    let mut read = BufReader::new(read);

    write.write_all(v1_request_head(addr).as_bytes()).await?;
    write.flush().await?;

    // Wait for `100 Continue`; anything else (including a final status) means this recorder will
    // not take the recording.
    let head = match tokio::time::timeout(EXPECT_CONTINUE_TIMEOUT, read_head(&mut read)).await {
        Ok(head) => head?,
        Err(_) => {
            return Err(RecorderError::Recorder(
                "recording: recorder did not answer Expect: 100-continue".to_string(),
            ));
        }
    };
    match parse_status(&head) {
        Some(100) => {}
        Some(status) => {
            return Err(RecorderError::Recorder(format!(
                "recording: unexpected status: {status}"
            )));
        }
        None => {
            return Err(RecorderError::Recorder(
                "recording: unparseable response from recorder".to_string(),
            ));
        }
    }

    let (body_tx, mut body_rx) = mpsc::channel::<Bytes>(CAST_QUEUE_DEPTH);
    let (done_tx, done_rx) = oneshot::channel();

    tokio::spawn(async move {
        if done_tx
            .send(pump_v1(&mut body_rx, &mut read, &mut write).await)
            .is_err()
        {
            tracing::debug!(%addr, "recording: session ended before the upload result was read");
        }
    });

    Ok(RecorderUpload {
        recorder: addr,
        body: body_tx,
        done: done_rx,
    })
}

/// Stream the cast to a V1 recorder as HTTP/1.1 chunked body, then read its final status.
async fn pump_v1<R, W>(
    body: &mut mpsc::Receiver<Bytes>,
    read: &mut BufReader<R>,
    write: &mut W,
) -> Result<(), String>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    while let Some(chunk) = body.recv().await {
        if chunk.is_empty() {
            // A zero-length chunk is the chunked-encoding terminator; never send one for data.
            continue;
        }
        let framed = format!("{:x}\r\n", chunk.len());
        write
            .write_all(framed.as_bytes())
            .await
            .map_err(|e| format!("recording: upload write: {e}"))?;
        write
            .write_all(&chunk)
            .await
            .map_err(|e| format!("recording: upload write: {e}"))?;
        write
            .write_all(b"\r\n")
            .await
            .map_err(|e| format!("recording: upload write: {e}"))?;
        write
            .flush()
            .await
            .map_err(|e| format!("recording: upload flush: {e}"))?;
    }

    write
        .write_all(b"0\r\n\r\n")
        .await
        .map_err(|e| format!("recording: upload close: {e}"))?;
    write
        .flush()
        .await
        .map_err(|e| format!("recording: upload close: {e}"))?;

    let head = read_head(read)
        .await
        .map_err(|e| format!("recording: reading final response: {e}"))?;
    match parse_status(&head) {
        Some(200) => Ok(()),
        Some(status) => Err(format!("recording: unexpected status: {status}")),
        None => Err("recording: unparseable response from recorder".to_string()),
    }
}

/// The `POST /record` request head Go's `net/http` would write for `connectV1`.
fn v1_request_head(addr: SocketAddr) -> String {
    format!(
        "POST /record HTTP/1.1\r\n\
         Host: {addr}\r\n\
         User-Agent: tailscale-rs/{version}\r\n\
         Transfer-Encoding: chunked\r\n\
         Expect: 100-continue\r\n\
         \r\n",
        version = env!("CARGO_PKG_VERSION"),
    )
}

/// Read one HTTP response head (status line and headers) up to the blank line.
///
/// Bounded by [`MAX_RESPONSE_HEAD`]: the recorder is a network peer, so a head that never ends
/// must fail rather than grow the buffer.
async fn read_head<R: AsyncRead + Unpin>(read: &mut BufReader<R>) -> io::Result<String> {
    let mut head = String::new();
    loop {
        let mut line = String::new();
        let n = read.read_line(&mut line).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "recorder closed the connection before answering",
            ));
        }
        head.push_str(&line);
        if line == "\r\n" || line == "\n" {
            return Ok(head);
        }
        if head.len() > MAX_RESPONSE_HEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "recorder response head exceeds the maximum size",
            ));
        }
    }
}

/// The status code of an HTTP response head, or `None` if the status line is not one.
fn parse_status(head: &str) -> Option<u16> {
    let line = head.lines().next()?;
    let mut parts = line.split_whitespace();
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    parts.next()?.parse().ok()
}

#[cfg(all(test, feature = "ssh"))]
mod tests {
    use std::{
        collections::VecDeque,
        sync::Mutex as StdMutex,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use tokio::io::DuplexStream;

    use super::*;

    /// A recorder address in the RFC 5737 documentation range.
    fn recorder_addr() -> SocketAddr {
        "192.0.2.10:8080".parse().unwrap()
    }

    /// A dialer that hands out pre-arranged connections, in order.
    ///
    /// `connect_one` dials once for the V2 probe and, if that probe fails, a second time for the
    /// V1 fallback — so a V1 test scripts two connections and a V2 test only one.
    struct ScriptedDialer(StdMutex<VecDeque<DuplexStream>>);

    impl ScriptedDialer {
        fn new(conns: impl IntoIterator<Item = DuplexStream>) -> Self {
            Self(StdMutex::new(conns.into_iter().collect()))
        }
    }

    impl RecorderDialer for ScriptedDialer {
        type Io = DuplexStream;

        async fn dial(&self, _addr: SocketAddr) -> io::Result<Self::Io> {
            self.0
                .lock()
                .expect("scripted dialer lock")
                .pop_front()
                .ok_or_else(|| io::Error::other("scripted dialer is out of connections"))
        }
    }

    /// A dialer whose every dial fails, standing in for an unreachable recorder.
    struct DeadDialer;

    impl RecorderDialer for DeadDialer {
        type Io = DuplexStream;

        async fn dial(&self, _addr: SocketAddr) -> io::Result<Self::Io> {
            Err(io::Error::other("no route to recorder"))
        }
    }

    /// A connection whose far end is already gone, so the h2c handshake on it fails immediately
    /// and [`connect_one`] falls back to V1.
    fn dead_connection() -> DuplexStream {
        let (near, far) = tokio::io::duplex(64);
        drop(far);
        near
    }

    // ---- cast encoding ----

    /// The header is the cast file's first line, and carries Go's field names and values.
    #[test]
    fn cast_header_line_carries_the_go_field_names() {
        let mut header = CastHeader::new(1_700_000_000, "screen-256color");
        header.ssh_user = "alice".to_string();
        header.local_user = "ubuntu".to_string();
        header.src_node = "laptop.tail-scale.ts.net".to_string();
        header.src_node_id = "nodeid-abc".to_string();
        header.connection_id = "ssh-conn-20231114T221320-0011223344".to_string();
        header.src_node_user_id = 42;

        let line = header.to_line().expect("header must encode");
        assert_eq!(line.last(), Some(&b'\n'), "the header is one cast line");

        let v: serde_json::Value = serde_json::from_slice(&line).expect("header must be JSON");
        assert_eq!(v["version"], 2);
        assert_eq!(v["timestamp"], 1_700_000_000_i64);
        assert_eq!(v["env"]["TERM"], "screen-256color");
        assert_eq!(v["sshUser"], "alice");
        assert_eq!(v["localUser"], "ubuntu");
        assert_eq!(v["srcNode"], "laptop.tail-scale.ts.net");
        assert_eq!(v["srcNodeID"], "nodeid-abc");
        assert_eq!(v["srcNodeUserID"], 42);
        assert_eq!(v["connectionID"], "ssh-conn-20231114T221320-0011223344");
        // Go marks these `omitempty`, so an unset one must not appear at all.
        assert!(v.get("command").is_none(), "empty command must be omitted");
        assert!(v.get("srcNodeTags").is_none(), "no tags must be omitted");
        assert!(v.get("srcNodeUser").is_none(), "no login must be omitted");
        // Width/height are always present, zero for a session with no known PTY size.
        assert_eq!(v["width"], 0);
        assert_eq!(v["height"], 0);
    }

    /// An empty `TERM` is normalized the way Go's `envValFromList` fallback does.
    #[test]
    fn cast_header_defaults_an_empty_term() {
        let header = CastHeader::new(0, "");
        assert_eq!(
            header.env.get("TERM").map(String::as_str),
            Some("xterm-256color")
        );
    }

    /// A tagged node records its tags and no owner id, so the two are never both present.
    #[test]
    fn cast_header_tags_are_omitted_when_absent_and_present_when_set() {
        let mut header = CastHeader::new(0, "vt100");
        header.src_node_tags = vec!["tag:prod".to_string()];
        let v: serde_json::Value =
            serde_json::from_slice(&header.to_line().expect("encodes")).expect("JSON");
        assert_eq!(v["srcNodeTags"][0], "tag:prod");
        assert!(v.get("srcNodeUserID").is_none());
    }

    /// A body frame is `[elapsed, "o", data]` — output only, one line.
    #[test]
    fn cast_output_line_is_a_castv2_output_frame() {
        let line = cast_output_line(Duration::from_millis(1500), b"hi there");
        assert_eq!(line.last(), Some(&b'\n'));
        let v: serde_json::Value = serde_json::from_slice(&line).expect("frame must be JSON");
        assert_eq!(v[0], 1.5);
        assert_eq!(v[1], "o", "only output is recorded, never input");
        assert_eq!(v[2], "hi there");
    }

    /// Binary PTY output is not a JSON error: Go stringifies it and `encoding/json` substitutes
    /// U+FFFD, which is what `from_utf8_lossy` does here.
    #[test]
    fn cast_output_line_survives_invalid_utf8() {
        let line = cast_output_line(Duration::ZERO, &[0xff, 0xfe, b'!']);
        let v: serde_json::Value = serde_json::from_slice(&line).expect("frame must be JSON");
        assert_eq!(v[2], "\u{fffd}\u{fffd}!");
    }

    // ---- the failure policy ----

    /// Go rejects the session only when `RejectSessionWithMessage` is set; everything else fails
    /// open.
    #[test]
    fn start_failure_is_fail_open_unless_reject_message_is_set() {
        assert_eq!(start_failure_action(None), StartFailure::FailOpen);
        assert_eq!(
            start_failure_action(Some(&SshRecorderFailureAction::default())),
            StartFailure::FailOpen,
            "an empty action must not be read as fail-closed"
        );
        assert_eq!(
            start_failure_action(Some(&SshRecorderFailureAction {
                terminate_session_with_message: "gone".to_string(),
                ..Default::default()
            })),
            StartFailure::FailOpen,
            "terminate-on-upload-failure says nothing about starting"
        );
        assert_eq!(
            start_failure_action(Some(&SshRecorderFailureAction {
                reject_session_with_message: "no recorder, no shell".to_string(),
                ..Default::default()
            })),
            StartFailure::Reject("no recorder, no shell".to_string()),
        );
    }

    /// And terminates a running session only when `TerminateSessionWithMessage` is set.
    #[test]
    fn upload_failure_is_fail_open_unless_terminate_message_is_set() {
        assert_eq!(upload_failure_action(None), UploadFailure::FailOpen);
        assert_eq!(
            upload_failure_action(Some(&SshRecorderFailureAction {
                reject_session_with_message: "no recorder, no shell".to_string(),
                ..Default::default()
            })),
            UploadFailure::FailOpen,
            "reject-at-start says nothing about a session already running"
        );
        assert_eq!(
            upload_failure_action(Some(&SshRecorderFailureAction {
                terminate_session_with_message: "recording lost".to_string(),
                ..Default::default()
            })),
            UploadFailure::Terminate("recording lost".to_string()),
        );
    }

    /// With no recorder reachable and no explicit reject message, Go proceeds **unrecorded**.
    #[tokio::test]
    async fn unreachable_recorder_fails_open_by_default() {
        let header = CastHeader::new(0, "xterm");
        let rec = SessionRecording::start(&[recorder_addr()], None, &header, &DeadDialer)
            .await
            .expect("the default policy must not refuse the session");
        assert!(rec.is_none(), "the session runs, just without a recording");
    }

    /// With `rejectSessionWithMessage` set, the same failure refuses the session and carries that
    /// exact message back to the client.
    #[tokio::test]
    async fn unreachable_recorder_is_fail_closed_when_the_policy_says_so() {
        let on_failure = SshRecorderFailureAction {
            reject_session_with_message: "this session must be recorded".to_string(),
            ..Default::default()
        };
        let header = CastHeader::new(0, "xterm");
        let err =
            SessionRecording::start(&[recorder_addr()], Some(&on_failure), &header, &DeadDialer)
                .await
                .expect_err("a fail-closed policy must refuse the session");
        assert_eq!(err.message, "this session must be recorded");
    }

    /// Every configured recorder is tried, in order, and each failure is recorded as its own
    /// attempt (Go returns the attempts so control can be told which recorders were tried).
    #[tokio::test]
    async fn every_recorder_is_attempted_in_order() {
        let first: SocketAddr = "192.0.2.10:8080".parse().unwrap();
        let second: SocketAddr = "198.51.100.20:9000".parse().unwrap();
        let (result, attempts) = connect_to_recorder(&[first, second], &DeadDialer).await;
        assert!(result.is_err());
        assert_eq!(
            attempts.iter().map(|a| a.recorder).collect::<Vec<_>>(),
            vec![first, second],
        );
        assert!(attempts.iter().all(|a| !a.failure_message.is_empty()));
    }

    /// An action that demands recording but names no recorder cannot be honored.
    #[tokio::test]
    async fn no_recorders_is_an_error_not_a_silent_success() {
        let (result, attempts) = connect_to_recorder(&[], &DeadDialer).await;
        assert!(matches!(result, Err(RecorderError::NoRecorders)));
        assert!(attempts.is_empty());
    }

    // ---- HTTP plumbing ----

    #[test]
    fn parse_status_reads_the_status_line() {
        assert_eq!(parse_status("HTTP/1.1 100 Continue\r\n\r\n"), Some(100));
        assert_eq!(parse_status("HTTP/1.1 200 OK\r\nX: y\r\n\r\n"), Some(200));
        assert_eq!(parse_status("HTTP/1.0 404 Not Found\r\n\r\n"), Some(404));
        // Anything that is not an HTTP response head is not a status.
        assert_eq!(parse_status("hello\r\n"), None);
        assert_eq!(parse_status(""), None);
        assert_eq!(parse_status("HTTP/1.1 nope\r\n"), None);
    }

    #[test]
    fn ack_frames_are_decoded_and_partials_are_kept() {
        // Two whole frames back to back, then half of a third.
        let mut buf = br#"{"ack":1}{"ack":2}{"ac"#.to_vec();
        let frames = take_ack_frames(&mut buf).expect("two whole frames decode");
        assert_eq!(frames.len(), 2);
        assert_eq!(
            buf,
            br#"{"ac"#.to_vec(),
            "the partial frame waits for more bytes"
        );

        // The recorder's error frame is surfaced as the frame's error.
        let mut buf = br#"{"error":"disk full"}"#.to_vec();
        let frames = take_ack_frames(&mut buf).expect("an error frame is still a frame");
        assert_eq!(frames[0].error, "disk full");

        // Garbage is a protocol error, not silently skipped.
        let mut buf = b"not json at all".to_vec();
        assert!(take_ack_frames(&mut buf).is_err());
    }

    /// A recorder that never ends its response head must not grow the client's memory.
    #[tokio::test]
    async fn response_head_is_bounded() {
        let (near, mut far) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let junk = format!("X-Pad: {}\r\n", "a".repeat(1024));
            for _ in 0..32 {
                if far.write_all(junk.as_bytes()).await.is_err() {
                    return;
                }
            }
        });
        let mut read = BufReader::new(near);
        let err = read_head(&mut read)
            .await
            .expect_err("an endless head must fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// The V1 request is what Go's `net/http` would send for `connectV1`.
    #[test]
    fn v1_request_head_announces_expect_continue() {
        let head = v1_request_head(recorder_addr());
        assert!(head.starts_with("POST /record HTTP/1.1\r\n"));
        assert!(head.contains("Host: 192.0.2.10:8080\r\n"));
        assert!(head.contains("Expect: 100-continue\r\n"));
        assert!(head.contains("Transfer-Encoding: chunked\r\n"));
        assert!(head.ends_with("\r\n\r\n"));
    }

    // ---- end-to-end against an in-process recorder ----

    /// Read one HTTP head from `read`, up to and including the blank line.
    async fn read_request_head<R: AsyncRead + Unpin>(read: &mut BufReader<R>) -> String {
        let mut head = String::new();
        loop {
            let mut line = String::new();
            let n = read.read_line(&mut line).await.expect("head line");
            assert_ne!(n, 0, "connection closed mid-head");
            head.push_str(&line);
            if line == "\r\n" {
                return head;
            }
        }
    }

    /// Decode an HTTP/1.1 chunked body up to its terminating zero-length chunk.
    async fn read_chunked_body<R: AsyncRead + Unpin>(read: &mut BufReader<R>) -> Vec<u8> {
        let mut body = Vec::new();
        loop {
            let mut size_line = String::new();
            if read.read_line(&mut size_line).await.expect("chunk size") == 0 {
                return body;
            }
            let size = usize::from_str_radix(size_line.trim(), 16).expect("chunk size is hex");
            if size == 0 {
                // Trailer section: a single CRLF for a body with no trailers.
                let mut end = String::new();
                drop(read.read_line(&mut end).await);
                return body;
            }
            let mut chunk = vec![0u8; size];
            read.read_exact(&mut chunk).await.expect("chunk data");
            let mut crlf = [0u8; 2];
            read.read_exact(&mut crlf).await.expect("chunk CRLF");
            body.extend_from_slice(&chunk);
        }
    }

    /// A legacy (V1) tsrecorder: answers `Expect: 100-continue`, takes the chunked cast, and
    /// finishes with a 200. Returns the cast it received.
    async fn fake_v1_recorder(io: DuplexStream) -> Vec<u8> {
        let (read, mut write) = tokio::io::split(io);
        let mut read = BufReader::new(read);

        let head = read_request_head(&mut read).await;
        assert!(
            head.starts_with("POST /record HTTP/1.1\r\n"),
            "head was {head:?}"
        );
        assert!(
            head.contains("Expect: 100-continue\r\n"),
            "head was {head:?}"
        );

        write
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await
            .expect("100-continue");
        write.flush().await.expect("flush");

        let cast = read_chunked_body(&mut read).await;

        write
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .expect("final response");
        write.flush().await.expect("flush");
        cast
    }

    /// A recorder that speaks only HTTP/1.1 gets the whole cast: header line first, then one
    /// output frame per chunk of session output. This exercises the real path — the h2c probe
    /// fails, `connect_v1` waits for `100 Continue`, and the session's writes are chunk-framed.
    #[tokio::test]
    async fn v1_recorder_receives_the_whole_cast() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let dialer = ScriptedDialer::new([dead_connection(), client_io]);
        let recorder = tokio::spawn(fake_v1_recorder(server_io));

        let mut header = CastHeader::new(1_700_000_000, "xterm-256color");
        header.local_user = "ubuntu".to_string();

        let mut rec = SessionRecording::start(&[recorder_addr()], None, &header, &dialer)
            .await
            .expect("the recorder accepts the recording")
            .expect("recording must be live");
        assert_eq!(rec.recorder(), recorder_addr());

        rec.record_output(b"$ whoami\r\n").await.expect("recorded");
        rec.record_output(b"ubuntu\r\n").await.expect("recorded");
        // Ending the session closes the upload, which is what makes the recorder finish.
        drop(rec);

        let cast = tokio::time::timeout(Duration::from_secs(10), recorder)
            .await
            .expect("recorder must finish")
            .expect("recorder task");
        let cast = String::from_utf8(cast).expect("the cast is UTF-8 JSON lines");
        let mut lines = cast.lines();

        let head: serde_json::Value =
            serde_json::from_str(lines.next().expect("header line")).expect("header JSON");
        assert_eq!(head["version"], 2);
        assert_eq!(head["localUser"], "ubuntu");

        let first: serde_json::Value =
            serde_json::from_str(lines.next().expect("first frame")).expect("frame JSON");
        assert_eq!(first[1], "o");
        assert_eq!(first[2], "$ whoami\r\n");

        let second: serde_json::Value =
            serde_json::from_str(lines.next().expect("second frame")).expect("frame JSON");
        assert_eq!(second[2], "ubuntu\r\n");
        assert!(lines.next().is_none(), "nothing beyond what was recorded");
    }

    /// A recorder that answers the `Expect:` with a final status instead of `100 Continue` has
    /// refused the recording, and the session must not be treated as recorded.
    #[tokio::test]
    async fn v1_recorder_that_refuses_is_not_treated_as_connected() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let (read, mut write) = tokio::io::split(server_io);
            let mut read = BufReader::new(read);
            read_request_head(&mut read).await;
            drop(
                write
                    .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                    .await,
            );
            drop(write.flush().await);
        });

        let dialer = ScriptedDialer::new([dead_connection(), client_io]);
        let on_failure = SshRecorderFailureAction {
            reject_session_with_message: "this session must be recorded".to_string(),
            ..Default::default()
        };
        let header = CastHeader::new(0, "xterm");
        let err = SessionRecording::start(&[recorder_addr()], Some(&on_failure), &header, &dialer)
            .await
            .expect_err("a refusing recorder must not look like a live recording");
        assert_eq!(err.message, "this session must be recorded");
        assert!(
            err.cause.to_string().contains("403"),
            "the refusal reason must be preserved: {}",
            err.cause
        );
    }

    /// A V1 recorder that accepts the recording and then hangs up mid-session.
    fn spawn_recorder_that_hangs_up(server_io: DuplexStream) {
        tokio::spawn(async move {
            let (read, mut write) = tokio::io::split(server_io);
            let mut read = BufReader::new(read);
            read_request_head(&mut read).await;
            drop(write.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await);
            drop(write.flush().await);
            // Returning drops both halves, which is the recorder vanishing mid-session.
        });
    }

    /// Keep recording until the broken upload is noticed, and report what `record_output` said.
    async fn record_until_it_notices(rec: &mut SessionRecording) -> Result<(), String> {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                rec.record_output(b"x").await?;
                tokio::task::yield_now().await;
                if rec.stopped {
                    return Ok(());
                }
            }
        })
        .await
        .expect("the broken upload must be noticed")
    }

    /// A recorder that vanishes mid-session ends the session with the policy's message when
    /// `terminateSessionWithMessage` is set — the message the client is owed, not a generic one.
    #[tokio::test]
    async fn a_broken_upload_is_fail_closed_with_the_policy_message() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        spawn_recorder_that_hangs_up(server_io);
        let dialer = ScriptedDialer::new([dead_connection(), client_io]);

        let on_failure = SshRecorderFailureAction {
            terminate_session_with_message: "recording lost; ending session".to_string(),
            ..Default::default()
        };
        let header = CastHeader::new(0, "xterm");
        let mut rec =
            SessionRecording::start(&[recorder_addr()], Some(&on_failure), &header, &dialer)
                .await
                .expect("the recorder accepted the recording")
                .expect("recording must be live");

        assert_eq!(
            record_until_it_notices(&mut rec).await,
            Err("recording lost; ending session".to_string()),
        );
    }

    /// The same recorder vanishing under the default (fail-open) policy leaves the session
    /// running: recording stops, the shell does not.
    #[tokio::test]
    async fn a_broken_upload_is_fail_open_by_default() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        spawn_recorder_that_hangs_up(server_io);
        let dialer = ScriptedDialer::new([dead_connection(), client_io]);

        let header = CastHeader::new(0, "xterm");
        let mut rec = SessionRecording::start(&[recorder_addr()], None, &header, &dialer)
            .await
            .expect("the recorder accepted the recording")
            .expect("recording must be live");

        assert_eq!(record_until_it_notices(&mut rec).await, Ok(()));
        assert!(rec.stopped, "no further cast lines are attempted");
        // And it stays fail-open: later output is still passed through without error.
        rec.record_output(b"still alive").await.expect("fail-open");
    }

    /// Read a whole `hyper` request body.
    async fn collect_incoming(mut body: hyper::body::Incoming) -> Vec<u8> {
        use hyper::body::Body as _;
        let mut out = Vec::new();
        while let Some(frame) = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await
        {
            match frame {
                Ok(frame) => {
                    if let Some(data) = frame.data_ref() {
                        out.extend_from_slice(data);
                    }
                }
                Err(_) => break,
            }
        }
        out
    }

    /// A modern (V2) tsrecorder: answers the `HEAD /v2/record` probe, takes the cast as the body
    /// of `POST /v2/record`, and acks it. Sends the received cast on `cast_tx`.
    async fn fake_v2_recorder(io: DuplexStream, cast_tx: oneshot::Sender<Vec<u8>>) {
        let cast_tx = std::sync::Arc::new(StdMutex::new(Some(cast_tx)));
        let service = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
            let cast_tx = cast_tx.clone();
            async move {
                let response = |status: StatusCode, body: CastBody| {
                    ts_http_util::Response::builder()
                        .status(status)
                        .body(body)
                        .expect("response builds")
                };
                match (req.method().clone(), req.uri().path()) {
                    (Method::HEAD, "/v2/record") => {
                        Ok::<_, io::Error>(response(StatusCode::OK, CastBody::empty()))
                    }
                    (Method::POST, "/v2/record") => {
                        let (ack_tx, ack_rx) = mpsc::channel(4);
                        tokio::spawn(async move {
                            // tsrecorder acks continuously, including while the session is idle.
                            drop(ack_tx.send(Bytes::from_static(br#"{"ack":0}"#)).await);
                            let cast = collect_incoming(req.into_body()).await;
                            drop(
                                ack_tx
                                    .send(Bytes::from(format!(r#"{{"ack":{}}}"#, cast.len())))
                                    .await,
                            );
                            if let Some(tx) = cast_tx.lock().expect("cast lock").take() {
                                drop(tx.send(cast));
                            }
                        });
                        Ok(response(StatusCode::OK, CastBody::channel(ack_rx)))
                    }
                    _ => Ok(response(StatusCode::NOT_FOUND, CastBody::empty())),
                }
            }
        });

        drop(
            hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(hyper_util::rt::TokioIo::new(io), service)
                .await,
        );
    }

    /// A recorder that answers the `HEAD /v2/record` probe gets the cast over `h2c` on the same
    /// connection — the probe and the upload share one connection, as they do in Go.
    #[tokio::test]
    async fn v2_recorder_receives_the_whole_cast() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (cast_tx, cast_rx) = oneshot::channel();
        tokio::spawn(fake_v2_recorder(server_io, cast_tx));

        // Only one connection is scripted: a V2 recorder never falls back to V1.
        let dialer = ScriptedDialer::new([client_io]);

        let mut header = CastHeader::new(1_700_000_000, "xterm-256color");
        header.ssh_user = "alice".to_string();

        let mut rec = SessionRecording::start(&[recorder_addr()], None, &header, &dialer)
            .await
            .expect("the recorder accepts the recording")
            .expect("recording must be live");
        rec.record_output(b"hello\r\n").await.expect("recorded");
        drop(rec);

        let cast = tokio::time::timeout(Duration::from_secs(10), cast_rx)
            .await
            .expect("recorder must finish")
            .expect("recorder sends the cast");
        let cast = String::from_utf8(cast).expect("the cast is UTF-8 JSON lines");
        let mut lines = cast.lines();

        let head: serde_json::Value =
            serde_json::from_str(lines.next().expect("header line")).expect("header JSON");
        assert_eq!(head["sshUser"], "alice");

        let frame: serde_json::Value =
            serde_json::from_str(lines.next().expect("frame")).expect("frame JSON");
        assert_eq!(frame[1], "o");
        assert_eq!(frame[2], "hello\r\n");
    }

    /// The cast header's timestamp is a real Unix timestamp, so a recording is placeable in time.
    #[test]
    fn cast_header_timestamp_is_unix_seconds() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after the epoch")
            .as_secs() as i64;
        let header = CastHeader::new(now, "xterm");
        assert!(header.timestamp > 1_600_000_000, "{}", header.timestamp);
    }
}
