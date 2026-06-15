//! Device connection-state tracking: a push-style view of where a [`Runtime`](crate::Runtime) is in
//! its control-plane lifecycle, plus a typed registration outcome.
//!
//! Mirrors the part of Go `tsnet`/`ipn`'s state machine an embedder actually reacts to: is the node
//! still coming up, running, waiting for interactive login, expired, or did registration hard-fail?
//! The [`ControlRunner`](crate::control_runner::ControlRunner) publishes transitions into a
//! `watch` cell so an embedder can `await` them ([`Runtime::watch_state`](crate::Runtime::watch_state))
//! instead of polling [`status`](crate::Runtime::status), and
//! [`Runtime::wait_until_running`](crate::Runtime::wait_until_running) is a one-shot convenience
//! built on the same cell.

/// The control-plane lifecycle state of a device.
///
/// Published by the control runner as it brings the node up and maintains the netmap stream. A
/// consumer watches this to drive UI ("connecting…", "needs login", "expired") and to distinguish a
/// permanent failure from a transient one without inspecting logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceState {
    /// The runtime has spawned and is registering / establishing the control session. The initial
    /// state of every device.
    Connecting,
    /// Registered and the netmap stream is live — the node is up.
    Running,
    /// Control requires interactive authentication (no usable auth key): the node is waiting for a
    /// human to authorize it at the carried URL. Transient — registration retries until authorized.
    NeedsLogin(url::Url),
    /// The node key expired and an automatic, non-interactive re-authentication is in progress: the
    /// runtime is rotating the node key and re-registering with the stored auth key (Go `doLogin`).
    /// **Transient** — treated like [`Connecting`](Self::Connecting) by the waiters
    /// ([`wait_until_running`](crate::Runtime::wait_until_running) keeps waiting, never settling on
    /// it), and the next good self-node flips the state back to [`Running`](Self::Running). No
    /// `browse_to_url` is derived from it (the recovery is non-interactive, unlike
    /// [`NeedsLogin`](Self::NeedsLogin)). Entered only when an auth key is retained, auto-reauth is
    /// enabled, and Tailnet Lock enforcement is NOT active; otherwise the runtime falls through to
    /// [`Expired`](Self::Expired). See the runtime's `expiry_action` for the decision matrix.
    Reauthenticating,
    /// The node key has expired (control reported the self-node's key expiry is in the past). The
    /// node must re-authenticate to continue. Surfaced from the netmap self-node, not registration.
    Expired,
    /// Registration hard-failed with a permanent reason (e.g. a bad/expired/unknown auth key). The
    /// control runner stops; this carries the typed reason. Not retried.
    Failed(RegistrationError),
}

/// A typed registration outcome, distinguishing a **permanent** failure (don't retry — tell the
/// user) from a **transient** one (worth retrying).
///
/// This is the error surfaced by [`Runtime::wait_until_running`](crate::Runtime::wait_until_running),
/// replacing the previous "poll `ipv4_addr` until a deadline and report a generic timeout" workaround
/// with an actionable reason.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum RegistrationError {
    /// Control rejected registration with a permanent reason — typically a bad, expired, or unknown
    /// auth key. The string is control's verbatim reason. **Permanent**: re-pairing (a new auth
    /// key) is required; retrying with the same key will not succeed.
    #[error("authentication rejected by control: {0}")]
    AuthRejected(String),

    /// The node key has expired. **Permanent** until re-authentication.
    #[error("node key expired; re-authentication required")]
    KeyExpired,

    /// Interactive authorization is required: control offered an auth URL (no usable auth key).
    /// **Actionable but not permanent** — direct the user to the URL; the runtime keeps retrying
    /// registration and will reach `Running` once the user authorizes (so this is *not*
    /// [`is_permanent`](Self::is_permanent)). A caller using an auth key should not hit this; a
    /// caller doing interactive auth should drive it via
    /// [`watch_state`](crate::Runtime::watch_state) rather than treating this as a hard failure.
    #[error("interactive login required at {0}")]
    NeedsLogin(url::Url),

    /// The control plane was unreachable (network/transport error). **Transient**: retrying later
    /// may succeed.
    #[error("control plane unreachable")]
    NetworkUnreachable,

    /// No settled state was reached before the caller's timeout elapsed. **Indeterminate**:
    /// registration may still be in flight (e.g. slow control plane); the caller may retry the wait.
    #[error("timed out waiting for the device to finish registering")]
    Timeout,
}

impl RegistrationError {
    /// Whether this outcome is **permanent** — re-pairing / new credentials are required and
    /// retrying as-is will not succeed (`AuthRejected`, `KeyExpired`). Everything else is not
    /// permanent: `NetworkUnreachable`/`Timeout` are transient (retry may succeed), and `NeedsLogin`
    /// is actionable-but-recoverable (the runtime keeps retrying and reaches `Running` once the user
    /// authorizes the offered URL — so it is *not* permanent).
    pub fn is_permanent(&self) -> bool {
        matches!(
            self,
            RegistrationError::AuthRejected(_) | RegistrationError::KeyExpired
        )
    }
}

/// Map a control-layer [`ts_control::Error`] from the registration path into a typed
/// [`RegistrationError`]. Used by the control runner when its `check_auth` loop hard-fails.
impl From<&ts_control::Error> for RegistrationError {
    fn from(e: &ts_control::Error) -> Self {
        match e {
            ts_control::Error::MachineNotAuthorized(u) => RegistrationError::NeedsLogin(u.clone()),
            ts_control::Error::Registration(reason) => {
                RegistrationError::AuthRejected(reason.clone())
            }
            ts_control::Error::NetworkError(_) => RegistrationError::NetworkUnreachable,
            // A 429 rate-limit is **transient** — control is asking us to wait, not rejecting us —
            // so it must NOT become a permanent `AuthRejected`. The control runner's `check_auth`
            // loop already intercepts `RateLimited` and sleeps the server delay before this mapping
            // is reached; classifying it as `NetworkUnreachable` here keeps any other caller of this
            // conversion on the correct (non-permanent, retry-may-succeed) branch.
            ts_control::Error::RateLimited(_) => RegistrationError::NetworkUnreachable,
            // InvalidUrl / Internal: not a transient network condition and not an auth decision —
            // treat as a (permanent-ish) auth rejection carrying the display reason so the caller
            // sees something actionable rather than an opaque "timeout".
            other => RegistrationError::AuthRejected(other.to_string()),
        }
    }
}

/// Wait on a [`DeviceState`] `watch` channel until it settles, mapping the settled state to the
/// typed [`wait_until_running`](crate::Runtime::wait_until_running) result.
///
/// Factored out of [`Runtime::wait_until_running`](crate::Runtime) so the (non-trivial) loop — the
/// see-then-await ordering, the per-state mapping, sender-drop handling, and the timeout — is
/// unit-testable against a plain `watch::channel` without standing up a runtime.
pub(crate) async fn wait_for_running(
    mut rx: tokio::sync::watch::Receiver<DeviceState>,
    timeout: Option<core::time::Duration>,
) -> Result<(), RegistrationError> {
    let wait = async {
        loop {
            // Evaluate the current value, then await a change. `borrow_and_update` marks the current
            // value seen so a transition isn't missed between this check and `changed()`.
            let settled = match &*rx.borrow_and_update() {
                DeviceState::Running => Some(Ok(())),
                DeviceState::Failed(e) => Some(Err(e.clone())),
                DeviceState::Expired => Some(Err(RegistrationError::KeyExpired)),
                DeviceState::NeedsLogin(u) => Some(Err(RegistrationError::NeedsLogin(u.clone()))),
                // Transient, like `Connecting`: an auto-reauth is in flight and the next good
                // self-node flips back to `Running`, so keep waiting rather than settling.
                DeviceState::Connecting | DeviceState::Reauthenticating => None,
            };
            if let Some(result) = settled {
                return result;
            }
            // Not settled yet — wait for the next transition. If the sender is dropped (runtime
            // tearing down), treat it as unreachable rather than hanging forever.
            if rx.changed().await.is_err() {
                return Err(RegistrationError::NetworkUnreachable);
            }
        }
    };

    match timeout {
        Some(timeout) => tokio::time::timeout(timeout, wait)
            .await
            .unwrap_or(Err(RegistrationError::Timeout)),
        None => wait.await,
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use tokio::sync::watch;

    use super::*;

    #[test]
    fn permanence_classification() {
        // Permanent: re-pairing / new credentials required.
        assert!(RegistrationError::AuthRejected("bad key".into()).is_permanent());
        assert!(RegistrationError::KeyExpired.is_permanent());
        // Not permanent: NeedsLogin recovers once the user authorizes (runtime keeps retrying);
        // network/timeout are transient.
        assert!(
            !RegistrationError::NeedsLogin("https://login.example/x".parse().unwrap())
                .is_permanent()
        );
        assert!(!RegistrationError::NetworkUnreachable.is_permanent());
        assert!(!RegistrationError::Timeout.is_permanent());
    }

    #[test]
    fn maps_control_error_variants() {
        let url: url::Url = "https://login.example/a".parse().unwrap();
        assert_eq!(
            RegistrationError::from(&ts_control::Error::MachineNotAuthorized(url.clone())),
            RegistrationError::NeedsLogin(url)
        );
        assert_eq!(
            RegistrationError::from(&ts_control::Error::Registration("bad auth key".into())),
            RegistrationError::AuthRejected("bad auth key".into())
        );
        assert_eq!(
            RegistrationError::from(&ts_control::Error::NetworkError(
                ts_control::Operation::Registration
            )),
            RegistrationError::NetworkUnreachable
        );
        // A 429 rate-limit is TRANSIENT and must map to a non-permanent state, never the
        // `AuthRejected` catch-all (which would wrongly stop the runtime). This pins the explicit
        // arm: if a refactor drops it and lets `RateLimited` fall into `other => AuthRejected`, this
        // assertion fails.
        let rl = RegistrationError::from(&ts_control::Error::RateLimited(Duration::from_secs(30)));
        assert_eq!(rl, RegistrationError::NetworkUnreachable);
        assert!(
            !rl.is_permanent(),
            "a rate-limit must be a transient (non-permanent) failure"
        );
    }

    // --- wait_for_running loop ---

    /// An already-`Running` cell resolves `Ok(())` immediately (the initial `borrow_and_update`
    /// sees it without waiting for a transition).
    #[tokio::test]
    async fn wait_resolves_when_already_running() {
        let (_tx, rx) = watch::channel(DeviceState::Running);
        assert_eq!(
            wait_for_running(rx, Some(Duration::from_secs(1))).await,
            Ok(())
        );
    }

    /// A transition `Connecting → Running` published from another task is observed (no missed
    /// wakeup) and resolves `Ok(())`.
    #[tokio::test]
    async fn wait_resolves_on_transition_to_running() {
        let (tx, rx) = watch::channel(DeviceState::Connecting);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            tx.send_replace(DeviceState::Running);
        });
        assert_eq!(
            wait_for_running(rx, Some(Duration::from_secs(1))).await,
            Ok(())
        );
    }

    /// Each settled non-running state maps to its typed error.
    #[tokio::test]
    async fn wait_maps_each_settled_failure() {
        for (state, expected) in [
            (
                DeviceState::Failed(RegistrationError::AuthRejected("bad".into())),
                RegistrationError::AuthRejected("bad".into()),
            ),
            (DeviceState::Expired, RegistrationError::KeyExpired),
            (
                DeviceState::NeedsLogin("https://login.example/x".parse().unwrap()),
                RegistrationError::NeedsLogin("https://login.example/x".parse().unwrap()),
            ),
        ] {
            let (_tx, rx) = watch::channel(state);
            assert_eq!(
                wait_for_running(rx, Some(Duration::from_secs(1))).await,
                Err(expected)
            );
        }
    }

    /// A cell stuck at `Connecting` past the timeout yields `Timeout`.
    #[tokio::test]
    async fn wait_times_out_while_connecting() {
        let (_tx, rx) = watch::channel(DeviceState::Connecting);
        assert_eq!(
            wait_for_running(rx, Some(Duration::from_millis(30))).await,
            Err(RegistrationError::Timeout)
        );
    }

    /// `Reauthenticating` is transient (the auto-reauth analogue of `is_permanent() == false`): a
    /// waiter must NOT settle on it — like `Connecting`, it times out rather than resolving to a
    /// terminal error, because the next good self-node flips the state back to `Running`. This is the
    /// behavioral guard that an in-flight auto-reauth never surfaces as a permanent failure.
    #[tokio::test]
    async fn wait_does_not_settle_on_reauthenticating() {
        let (_tx, rx) = watch::channel(DeviceState::Reauthenticating);
        assert_eq!(
            wait_for_running(rx, Some(Duration::from_millis(30))).await,
            Err(RegistrationError::Timeout),
            "Reauthenticating is transient — a waiter keeps waiting, it does not settle"
        );
    }

    /// The full auto-reauth recovery as a waiter sees it: `Reauthenticating` (in flight) → `Running`
    /// (the next good self-node) resolves `Ok(())`. Proves the transient state is observed and then
    /// recovered, never surfaced as a failure.
    #[tokio::test]
    async fn wait_resolves_on_reauthenticating_then_running() {
        let (tx, rx) = watch::channel(DeviceState::Reauthenticating);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            tx.send_replace(DeviceState::Running);
        });
        assert_eq!(
            wait_for_running(rx, Some(Duration::from_secs(1))).await,
            Ok(())
        );
    }

    /// If the sender is dropped while still `Connecting`, the wait ends as `NetworkUnreachable`
    /// rather than hanging forever.
    #[tokio::test]
    async fn wait_sender_dropped_is_network_unreachable() {
        let (tx, rx) = watch::channel(DeviceState::Connecting);
        drop(tx);
        assert_eq!(
            wait_for_running(rx, Some(Duration::from_secs(1))).await,
            Err(RegistrationError::NetworkUnreachable)
        );
    }
}
