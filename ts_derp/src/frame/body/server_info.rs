use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    Nonce,
    frame::{Body, FrameType},
};

/// Part of the initial derp handshake, providing info about the server.
///
/// The payload follows as an encrypted JSON blob in the format specified by
/// [`ServerInfoPayload`].
#[derive(
    Debug, Copy, Clone, PartialEq, KnownLayout, Immutable, IntoBytes, FromBytes, Unaligned,
)]
#[repr(C, packed)]
pub struct ServerInfo {
    /// Nonce to use for decrypting the additional payload.
    pub nonce: Nonce,
}

impl Body for ServerInfo {
    const FRAME_TYPE: FrameType = FrameType::ServerInfo;
}

/// Associated payload to [`ServerInfo`], containing runtime info for the server.
#[derive(Debug, Copy, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ServerInfoPayload {
    /// Version of the server.
    pub version: i32,
    /// Sustained refill rate of the server's token bucket.
    pub token_bucket_bytes_per_second: Option<i32>,
    /// The burst rate for the server's token bucket.
    pub token_bucket_bytes_burst: Option<i32>,
}

impl ServerInfoPayload {
    /// Get the server's sustained token bucket refill rate as a usize.
    ///
    /// A negative advertised value is clamped to `0` (via `try_from`): a byte rate is non-negative,
    /// and `0` is the "no limiter" sentinel the rate-limiter already understands. Clamping is
    /// important because a bare `as usize` would sign-extend a negative `i32` to a near-`usize::MAX`
    /// rate — an *effectively infinite* (never-throttling) limiter, the opposite of Go, where a
    /// negative `rate.Limit` refills nothing. Clamping a malformed/hostile value to `0` keeps the
    /// node from being tricked into ignoring the limit entirely.
    pub fn token_bucket_bytes_per_second(&self) -> Option<usize> {
        self.token_bucket_bytes_per_second
            .map(|v| usize::try_from(v).unwrap_or(0))
    }

    /// Get the server's token bucket burst rate as a usize. A negative value is clamped to `0` (a
    /// byte count is non-negative); see [`token_bucket_bytes_per_second`](Self::token_bucket_bytes_per_second)
    /// for why the bare `as usize` sign-extension must be avoided.
    pub fn token_bucket_bytes_burst(&self) -> Option<usize> {
        self.token_bucket_bytes_burst
            .map(|v| usize::try_from(v).unwrap_or(0))
    }

    /// Get the server's version as a usize. A negative version is clamped to `0`.
    pub fn version(&self) -> usize {
        usize::try_from(self.version).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A negative advertised token-bucket value must clamp to `0`, NOT sign-extend to a near-
    /// `usize::MAX` "infinite" rate (which would make the rate-limiter never throttle — the opposite
    /// of the intended limit, and a way a malformed/hostile server could trick the node into ignoring
    /// the directive entirely). A byte count is non-negative.
    #[test]
    fn negative_token_bucket_values_clamp_to_zero() {
        let payload = ServerInfoPayload {
            version: -5,
            token_bucket_bytes_per_second: Some(-1),
            token_bucket_bytes_burst: Some(-1000),
        };
        assert_eq!(
            payload.token_bucket_bytes_per_second(),
            Some(0),
            "a negative rate clamps to 0 (the no-limiter sentinel), not usize::MAX"
        );
        assert_eq!(
            payload.token_bucket_bytes_burst(),
            Some(0),
            "a negative burst clamps to 0"
        );
        assert_eq!(payload.version(), 0, "a negative version clamps to 0");
    }

    /// Normal non-negative values pass through unchanged.
    #[test]
    fn non_negative_token_bucket_values_pass_through() {
        let payload = ServerInfoPayload {
            version: 2,
            token_bucket_bytes_per_second: Some(1_000_000),
            token_bucket_bytes_burst: Some(2_000_000),
        };
        assert_eq!(payload.token_bucket_bytes_per_second(), Some(1_000_000));
        assert_eq!(payload.token_bucket_bytes_burst(), Some(2_000_000));
        assert_eq!(payload.version(), 2);

        let absent = ServerInfoPayload {
            version: 1,
            token_bucket_bytes_per_second: None,
            token_bucket_bytes_burst: None,
        };
        assert_eq!(
            absent.token_bucket_bytes_per_second(),
            None,
            "absent stays absent"
        );
        assert_eq!(absent.token_bucket_bytes_burst(), None);
    }
}
