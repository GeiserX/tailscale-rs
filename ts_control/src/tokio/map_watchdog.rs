//! Supervise the whole map poll, including waits outside the body reader.

use tokio::{sync::watch, time::Instant};

use crate::{Error, Operation};

/// Go's `controlclient.watchdogTimeout`. Keep-alives count as responses.
pub(super) const MAP_RESPONSE_TIMEOUT: core::time::Duration = core::time::Duration::from_secs(120);

/// Owned by one poll attempt; its timer runs even while a side RPC is awaiting headers.
/// HTTP/2 PING ACKs prove transport liveness, not map-poll progress.
pub(super) struct MapPollWatchdog {
    last_response: watch::Sender<Instant>,
    connected: watch::Sender<bool>,
}

impl MapPollWatchdog {
    pub(super) fn new(connected: watch::Sender<bool>) -> Self {
        Self {
            last_response: watch::channel(Instant::now()).0,
            connected,
        }
    }

    /// Called only for a decoded response, before processing it. In particular, a
    /// length prefix, a side-RPC reply, and a PING ACK do not reset the deadline.
    pub(super) fn response_received(&self) {
        self.last_response.send_replace(Instant::now());
        self.connected.send_replace(true);
    }

    /// Dropping the attempt on timeout also drops its HTTP/2 client and pending RPCs.
    /// The caller's existing reconnect/backoff loop handles the returned network error.
    pub(super) async fn run(
        &self,
        poll: impl Future<Output = Result<(), Error>>,
    ) -> Result<(), Error> {
        let mut responses = self.last_response.subscribe();
        let mut poll = core::pin::pin!(poll);
        let outcome = loop {
            let deadline = *responses.borrow_and_update() + MAP_RESPONSE_TIMEOUT;
            tokio::select! {
                outcome = &mut poll => break outcome,
                _ = responses.changed() => {},
                () = tokio::time::sleep_until(deadline) => {
                    tracing::warn!(
                        watchdog_secs = MAP_RESPONSE_TIMEOUT.as_secs(),
                        "map response long-poll timed out! Restarting control connection"
                    );
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
    use crate::tokio::map_stream::map_stream;

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
            watchdog.response_received();
            assert!(*status.borrow());
            let started = Instant::now();
            let _outcome = watchdog.run(async { outcome }).await;
            assert_eq!(started.elapsed(), core::time::Duration::ZERO);
            assert!(!*status.borrow());
        }
    }
}
