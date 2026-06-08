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

    /// Interactive authorization is required and was not completed within the wait: control offered
    /// an auth URL (no usable auth key). **Actionable**: direct the user to the URL. The node will
    /// register once authorized.
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
    /// Whether this outcome is permanent (operator action required) rather than transient (a retry
    /// might succeed). `AuthRejected`/`KeyExpired`/`NeedsLogin` are permanent-until-action;
    /// `NetworkUnreachable`/`Timeout` are transient.
    pub fn is_permanent(&self) -> bool {
        matches!(
            self,
            RegistrationError::AuthRejected(_)
                | RegistrationError::KeyExpired
                | RegistrationError::NeedsLogin(_)
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
            // InvalidUrl / Internal: not a transient network condition and not an auth decision —
            // treat as a (permanent-ish) auth rejection carrying the display reason so the caller
            // sees something actionable rather than an opaque "timeout".
            other => RegistrationError::AuthRejected(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permanence_classification() {
        assert!(RegistrationError::AuthRejected("bad key".into()).is_permanent());
        assert!(RegistrationError::KeyExpired.is_permanent());
        assert!(
            RegistrationError::NeedsLogin("https://login.example/x".parse().unwrap())
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
    }
}
