//! Supervise the whole map poll, including waits outside the body reader.

use tokio::{sync::watch, time::Instant};

use crate::{Error, Operation};

/// Go's `controlclient.watchdogTimeout`. Keep-alives count as responses.
pub(super) const MAP_RESPONSE_TIMEOUT: core::time::Duration = core::time::Duration::from_secs(120);

/// Fixed labels only: never put control URLs, credentials or peer data in diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PollPhase {
    Connect,
    Register,
    MapResponseHeaders,
    StartupMapRequest,
    ReadingFrame,
    C2nPing,
    SetDerpHomeRegion,
    SetEndpoints,
    SetRoutableIps,
    SetHostname,
    ProcessingResponse,
}

impl PollPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Register => "register",
            Self::MapResponseHeaders => "map_response_headers",
            Self::StartupMapRequest => "startup_map_request",
            Self::ReadingFrame => "reading_frame",
            Self::C2nPing => "c2n_ping",
            Self::SetDerpHomeRegion => "side_map_request_set_derp_home_region",
            Self::SetEndpoints => "side_map_request_set_endpoints",
            Self::SetRoutableIps => "side_map_request_set_routable_ips",
            Self::SetHostname => "side_map_request_set_hostname",
            Self::ProcessingResponse => "processing_response",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FramePart {
    Prefix,
    Body,
}

impl FramePart {
    fn as_str(self) -> &'static str {
        match self {
            Self::Prefix => "prefix",
            Self::Body => "body",
        }
    }
}

#[derive(Clone, Copy)]
struct PollState {
    phase: PollPhase,
    stream_phase: PollPhase,
    phase_started: Instant,
    attempt_started: Instant,
    // Existing watchdog deadline follows delivery to the consumer.
    last_response: Instant,
    // Diagnostics record decoded arrival before any awaited cache persistence.
    last_frame: Option<Instant>,
    frames_received: u64,
    frame_part: FramePart,
    frame_bytes_received: usize,
    frame_bytes_expected: usize,
    // Hostinfo is concurrent with the reader, not a replacement for its phase.
    startup_started: Option<Instant>,
}

/// The exact snapshot used by the warn log, also inspected by paused-clock tests.
struct TimeoutDiagnostics {
    state: PollState,
    phase_secs: u64,
    since_last_map_response_secs: u64,
    attempt_age_secs: u64,
    partial_frame: bool,
    startup_request_secs: u64,
}

/// Owned by one poll attempt; its timer runs even while a side RPC is awaiting headers.
/// HTTP/2 PING ACKs prove transport liveness, not map-poll progress.
pub(super) struct MapPollWatchdog {
    state: watch::Sender<PollState>,
    connected: watch::Sender<bool>,
}

impl MapPollWatchdog {
    pub(super) fn new(connected: watch::Sender<bool>) -> Self {
        let now = Instant::now();
        Self {
            state: watch::channel(PollState {
                phase: PollPhase::Connect,
                stream_phase: PollPhase::ReadingFrame,
                phase_started: now,
                attempt_started: now,
                last_response: now,
                last_frame: None,
                frames_received: 0,
                frame_part: FramePart::Prefix,
                frame_bytes_received: 0,
                frame_bytes_expected: 4,
                startup_started: None,
            })
            .0,
            connected,
        }
    }

    pub(super) fn set_phase(&self, phase: PollPhase) {
        self.state.send_if_modified(|state| {
            if state.phase == phase {
                return false;
            }
            state.phase = phase;
            state.phase_started = Instant::now();
            true
        });
    }

    pub(super) fn startup_request_started(&self) {
        self.state
            .send_modify(|state| state.startup_started = Some(Instant::now()));
    }

    pub(super) fn startup_request_finished(&self) {
        self.state.send_modify(|state| state.startup_started = None);
    }

    pub(super) fn reading_frame_part(&self, part: FramePart, expected: usize) {
        self.set_phase(PollPhase::ReadingFrame);
        self.state.send_modify(|state| {
            state.stream_phase = PollPhase::ReadingFrame;
            state.frame_part = part;
            state.frame_bytes_received = 0;
            state.frame_bytes_expected = expected;
        });
    }

    pub(super) fn processing_frame(&self) {
        self.state
            .send_modify(|state| state.stream_phase = PollPhase::ProcessingResponse);
        self.set_phase(PollPhase::ProcessingResponse);
    }

    // The stream's unfold future survives select cancellation. Resume its retained
    // phase after a command or startup completion, including an in-flight cache write.
    pub(super) fn resume_stream(&self) {
        let phase = self.state.borrow().stream_phase;
        self.set_phase(phase);
    }

    pub(super) fn frame_bytes_received(&self, count: usize) {
        self.state
            .send_modify(|state| state.frame_bytes_received += count);
    }

    // Count decoded frames before cache persistence, which may itself be stuck.
    pub(super) fn frame_received(&self) {
        self.state.send_modify(|state| {
            state.frames_received = state.frames_received.saturating_add(1);
            state.last_frame = Some(Instant::now());
        });
    }

    /// Called only for a decoded response, before processing it. In particular, a
    /// length prefix, a side-RPC reply, and a PING ACK do not reset the deadline.
    pub(super) fn response_received(&self) {
        self.state.send_modify(|state| {
            state.last_response = Instant::now();
        });
        self.set_phase(PollPhase::ProcessingResponse);
        self.connected.send_replace(true);
    }

    fn timeout_diagnostics(&self) -> TimeoutDiagnostics {
        let now = Instant::now();
        let state = *self.state.borrow();
        TimeoutDiagnostics {
            phase_secs: now.duration_since(state.phase_started).as_secs(),
            since_last_map_response_secs: now
                .duration_since(state.last_frame.unwrap_or(state.attempt_started))
                .as_secs(),
            attempt_age_secs: now.duration_since(state.attempt_started).as_secs(),
            partial_frame: match state.frame_part {
                FramePart::Prefix => state.frame_bytes_received > 0,
                FramePart::Body => state.frame_bytes_received < state.frame_bytes_expected,
            },
            startup_request_secs: state
                .startup_started
                .map_or(0, |at| now.duration_since(at).as_secs()),
            state,
        }
    }

    // Called by both timers so a body-read timeout winning the select race has the
    // same diagnostics as the attempt-wide watchdog. All fields are labels/counts.
    pub(super) fn log_timeout(&self) {
        let diagnostic = self.timeout_diagnostics();
        let state = diagnostic.state;
        tracing::warn!(
            watchdog_secs = MAP_RESPONSE_TIMEOUT.as_secs(),
            phase = state.phase.as_str(),
            phase_secs = diagnostic.phase_secs,
            since_last_map_response_secs = diagnostic.since_last_map_response_secs,
            frames_received = state.frames_received,
            attempt_age_secs = diagnostic.attempt_age_secs,
            partial_frame = diagnostic.partial_frame,
            frame_part = state.frame_part.as_str(),
            frame_bytes_received = state.frame_bytes_received,
            frame_bytes_expected = state.frame_bytes_expected,
            concurrent_phase = if state.startup_started.is_some() {
                PollPhase::StartupMapRequest.as_str()
            } else {
                "none"
            },
            startup_request_secs = diagnostic.startup_request_secs,
            "map response long-poll timed out! Restarting control connection"
        );
    }

    /// Dropping the attempt on timeout also drops its HTTP/2 client and pending RPCs.
    /// The caller's existing reconnect/backoff loop handles the returned network error.
    pub(super) async fn run(
        &self,
        poll: impl Future<Output = Result<(), Error>>,
    ) -> Result<(), Error> {
        let mut changes = self.state.subscribe();
        let mut poll = core::pin::pin!(poll);
        let outcome = loop {
            // Diagnostic updates wake us but never extend the response deadline.
            let deadline = changes.borrow_and_update().last_response + MAP_RESPONSE_TIMEOUT;
            tokio::select! {
                outcome = &mut poll => break outcome,
                _ = changes.changed() => {},
                () = tokio::time::sleep_until(deadline) => {
                    self.log_timeout();
                    break Err(Error::NetworkError(Operation::MapRequest));
                }
            }
        };
        // Includes EOF, read errors, setup failures and intentional reauthentication.
        // Reconnecting/registering alone cannot clear the warning: a response must arrive.
        self.connected.send_replace(false);
        outcome
    }
}

#[cfg(test)]
mod tests {
    use futures_util::StreamExt;
    use tokio::io::AsyncWriteExt;

    use super::*;
    use crate::tokio::map_stream::{map_stream, map_stream_with_watchdog};

    fn frame(body: &[u8]) -> Vec<u8> {
        let mut bytes = (body.len() as u32).to_le_bytes().to_vec();
        bytes.extend_from_slice(body);
        bytes
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_setup_is_bounded_before_a_reader_exists() {
        let (connected, status) = watch::channel(false);
        let watchdog = MapPollWatchdog::new(connected);
        let started = Instant::now();
        let result = watchdog.run(core::future::pending()).await;
        assert!(matches!(
            result,
            Err(Error::NetworkError(Operation::MapRequest))
        ));
        assert_eq!(started.elapsed(), MAP_RESPONSE_TIMEOUT);
        assert!(!*status.borrow());
    }

    #[tokio::test(start_paused = true)]
    async fn keepalives_reset_watchdog_but_silence_disconnects() {
        let (connected, status) = watch::channel(false);
        let watchdog = MapPollWatchdog::new(connected);
        let (reader, mut writer) = tokio::io::duplex(1024);
        let bytes = frame(br#"{"KeepAlive":true}"#);
        let started = Instant::now();
        let mut received = 0;
        let poll = async {
            let mut stream = core::pin::pin!(map_stream(reader, None));
            for _ in 0..4 {
                tokio::time::sleep(core::time::Duration::from_secs(60)).await;
                writer.write_all(&bytes).await.unwrap();
                let response = stream.next().await.unwrap();
                assert!(response.keep_alive);
                watchdog.frame_received();
                watchdog.response_received();
                received += 1;
                assert!(*status.borrow());
            }
            // No FIN/RST, and no body read is being polled: model a stuck side RPC.
            // The old body-only watchdog cannot fire here, even if h2 PINGs succeed.
            core::future::pending::<Result<(), Error>>().await
        };
        assert!(watchdog.run(poll).await.is_err());
        assert_eq!(received, 4);
        assert_eq!(started.elapsed(), core::time::Duration::from_secs(360));
        assert!(!*status.borrow());
    }

    #[tokio::test(start_paused = true)]
    async fn eof_and_errors_disconnect_immediately() {
        for outcome in [Ok(()), Err(Error::NetworkError(Operation::MapRequest))] {
            let (connected, status) = watch::channel(false);
            let watchdog = MapPollWatchdog::new(connected);
            watchdog.frame_received();
            watchdog.response_received();
            assert!(*status.borrow());
            let started = Instant::now();
            let _outcome = watchdog.run(async { outcome }).await;
            assert_eq!(started.elapsed(), core::time::Duration::ZERO);
            assert!(!*status.borrow());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_reports_map_headers_phase_and_ages() {
        let watchdog = MapPollWatchdog::new(watch::channel(false).0);
        let poll = async {
            tokio::time::sleep(core::time::Duration::from_secs(10)).await;
            watchdog.set_phase(PollPhase::Register);
            tokio::time::sleep(core::time::Duration::from_secs(20)).await;
            watchdog.set_phase(PollPhase::MapResponseHeaders);
            core::future::pending().await
        };
        assert!(watchdog.run(poll).await.is_err());
        let diagnostic = watchdog.timeout_diagnostics();
        assert_eq!(diagnostic.state.phase.as_str(), "map_response_headers");
        assert_eq!(diagnostic.phase_secs, 90);
        assert_eq!(diagnostic.since_last_map_response_secs, 120);
        assert_eq!(diagnostic.state.frames_received, 0);
        assert_eq!(diagnostic.attempt_age_secs, 120);
        assert!(!diagnostic.partial_frame);
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_reports_each_named_side_request() {
        for (phase, label) in [
            (
                PollPhase::SetDerpHomeRegion,
                "side_map_request_set_derp_home_region",
            ),
            (PollPhase::SetEndpoints, "side_map_request_set_endpoints"),
            (
                PollPhase::SetRoutableIps,
                "side_map_request_set_routable_ips",
            ),
            (PollPhase::SetHostname, "side_map_request_set_hostname"),
        ] {
            let watchdog = MapPollWatchdog::new(watch::channel(false).0);
            let poll = async {
                tokio::time::sleep(core::time::Duration::from_secs(5)).await;
                watchdog.frame_received();
                watchdog.response_received();
                tokio::time::sleep(core::time::Duration::from_secs(5)).await;
                watchdog.set_phase(phase);
                core::future::pending().await
            };
            assert!(watchdog.run(poll).await.is_err());
            let diagnostic = watchdog.timeout_diagnostics();
            assert_eq!(diagnostic.state.phase.as_str(), label);
            assert_eq!(diagnostic.phase_secs, 115);
            assert_eq!(diagnostic.since_last_map_response_secs, 120);
            assert_eq!(diagnostic.state.frames_received, 1);
            assert_eq!(diagnostic.attempt_age_secs, 125);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_reports_real_partial_prefix_without_extending_deadline() {
        let watchdog = MapPollWatchdog::new(watch::channel(false).0);
        let (reader, mut writer) = tokio::io::duplex(64);
        let poll = async {
            let mut stream = core::pin::pin!(map_stream_with_watchdog(reader, None, &watchdog));
            let write_prefix = async {
                tokio::time::sleep(core::time::Duration::from_secs(119)).await;
                writer.write_all(&[64, 0]).await.unwrap();
                core::future::pending::<()>().await;
            };
            tokio::select! {
                _response = stream.next() => {},
                () = write_prefix => unreachable!(),
            }
            Ok(())
        };
        // Either the reader timer or the outer timer may win; both log the same snapshot.
        let _outcome = watchdog.run(poll).await;
        let diagnostic = watchdog.timeout_diagnostics();
        assert_eq!(diagnostic.state.phase.as_str(), "reading_frame");
        assert_eq!(diagnostic.phase_secs, 120);
        assert_eq!(diagnostic.since_last_map_response_secs, 120);
        assert_eq!(diagnostic.attempt_age_secs, 120);
        assert_eq!(diagnostic.state.frames_received, 0);
        assert_eq!(diagnostic.state.frame_part, FramePart::Prefix);
        assert_eq!(diagnostic.state.frame_bytes_received, 2);
        assert_eq!(diagnostic.state.frame_bytes_expected, 4);
        assert!(diagnostic.partial_frame);
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_distinguishes_partial_body_from_silence() {
        for bytes in [Vec::new(), vec![64, 0, 0, 0, 1, 2, 3]] {
            let partial_body = !bytes.is_empty();
            let watchdog = MapPollWatchdog::new(watch::channel(false).0);
            let (reader, mut writer) = tokio::io::duplex(64);
            writer.write_all(&bytes).await.unwrap();
            let poll = async {
                let mut stream = core::pin::pin!(map_stream_with_watchdog(reader, None, &watchdog));
                let _response = stream.next().await;
                Ok(())
            };
            let _outcome = watchdog.run(poll).await;
            let diagnostic = watchdog.timeout_diagnostics();
            assert_eq!(diagnostic.state.phase.as_str(), "reading_frame");
            assert_eq!(diagnostic.phase_secs, 120);
            assert_eq!(diagnostic.partial_frame, partial_body);
            if partial_body {
                assert_eq!(diagnostic.state.frame_part, FramePart::Body);
                assert_eq!(diagnostic.state.frame_bytes_received, 3);
                assert_eq!(diagnostic.state.frame_bytes_expected, 64);
            } else {
                assert_eq!(diagnostic.state.frame_part, FramePart::Prefix);
                assert_eq!(diagnostic.state.frame_bytes_received, 0);
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_preserves_concurrent_startup_request_and_reader_age() {
        let watchdog = MapPollWatchdog::new(watch::channel(false).0);
        let poll = async {
            watchdog.set_phase(PollPhase::ReadingFrame);
            tokio::time::sleep(core::time::Duration::from_secs(10)).await;
            watchdog.startup_request_started();
            // A completed select arm re-enters the same pending frame read. This must
            // not reset phase age, nor lose the concurrently pending startup request.
            watchdog.set_phase(PollPhase::ReadingFrame);
            core::future::pending().await
        };
        assert!(watchdog.run(poll).await.is_err());
        let diagnostic = watchdog.timeout_diagnostics();
        assert_eq!(diagnostic.state.phase.as_str(), "reading_frame");
        assert_eq!(diagnostic.phase_secs, 120);
        assert_eq!(diagnostic.startup_request_secs, 110);
        assert!(diagnostic.state.startup_started.is_some());
        watchdog.startup_request_finished();
        assert!(
            watchdog
                .timeout_diagnostics()
                .state
                .startup_started
                .is_none()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_resumes_response_processing_after_concurrent_startup_finishes() {
        let watchdog = MapPollWatchdog::new(watch::channel(false).0);
        let poll = async {
            watchdog.startup_request_started();
            tokio::time::sleep(core::time::Duration::from_secs(10)).await;
            // Count arrival before cache persistence; do not change the poll's existing
            // timeout/health semantics, which wait for delivery to the consumer.
            watchdog.frame_received();
            watchdog.processing_frame();
            watchdog.startup_request_finished();
            watchdog.resume_stream();
            core::future::pending().await
        };
        assert!(watchdog.run(poll).await.is_err());
        let diagnostic = watchdog.timeout_diagnostics();
        assert_eq!(diagnostic.state.phase.as_str(), "processing_response");
        assert_eq!(diagnostic.phase_secs, 110);
        assert_eq!(diagnostic.since_last_map_response_secs, 110);
        assert_eq!(diagnostic.state.frames_received, 1);
        assert_eq!(diagnostic.attempt_age_secs, 120);
        assert!(diagnostic.state.startup_started.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn decoded_keepalive_and_netmap_are_counted_once_before_processing() {
        let watchdog = MapPollWatchdog::new(watch::channel(false).0);
        let mut bytes = frame(br#"{"KeepAlive":true}"#);
        bytes.extend_from_slice(&frame(br#"{"Seq":1}"#));
        let mut stream = core::pin::pin!(map_stream_with_watchdog(&bytes[..], None, &watchdog));
        for expected in 1..=2 {
            let _response = stream.next().await.unwrap();
            // Count is already available even before the consumer processes the response.
            assert_eq!(
                watchdog.timeout_diagnostics().state.frames_received,
                expected
            );
            watchdog.response_received();
            assert_eq!(
                watchdog.timeout_diagnostics().state.frames_received,
                expected
            );
        }
    }
}
