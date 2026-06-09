use core::time::Duration;

use rand::{
    Rng, RngExt,
    distr::{Distribution, StandardUniform},
};
use ts_keys::NodePublicKey;

/// A handle for a wireguard peer.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct PeerId(pub u32);

/// A wireguard symmetric pre-shared key.
#[derive(Copy, Clone)]
pub struct Psk([u8; 32]);

impl From<[u8; 32]> for Psk {
    fn from(bytes: [u8; 32]) -> Self {
        Psk(bytes)
    }
}

impl AsRef<[u8]> for Psk {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Psk {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Distribution<Psk> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Psk {
        Psk(rng.random())
    }
}

/// The cryptographic configuration for a wireguard peer.
pub struct PeerConfig {
    /// The peer's public key.
    pub key: NodePublicKey,
    /// The pre-shared key to use for the peer, for post-quantum resistance.
    pub psk: Psk,
    /// How often to send an empty authenticated *persistent* keepalive to this peer when there has
    /// been no other outgoing authenticated traffic, or `None` to disable persistent keepalives for
    /// this peer.
    ///
    /// This is WireGuard's `PersistentKeepalive` (Tailscale sets it to 25s on a peer when control
    /// marks the peer `KeepAlive=true`). Unlike the reactive WireGuard §6.5 keepalive — which is
    /// armed only after *receiving* a packet and stops ~10s after the last inbound packet — the
    /// persistent keepalive re-arms unconditionally as long as the session is alive, so a tunnel
    /// that is idle in *both* directions still emits a packet every interval. That holds the
    /// NAT/relay (e.g. DERP) path mapping warm and keeps the session timers ticking on an otherwise
    /// silent tunnel; without it a relayed session ages past expiry and the path goes cold, so the
    /// next dial has to rehandshake over a dead path and wedges.
    ///
    /// The keepalive is an *empty* data packet: it deliberately does **not** advance the session's
    /// rotation/expiry timers (those track session age from the handshake, not keepalive sends), so
    /// a peer that has genuinely gone away is still detected and rekey still fires on schedule.
    ///
    /// `None` (the per-peer default constructed by [`PeerConfig`] callers that don't set it) keeps
    /// the historical behavior: reactive keepalive only, no persistent keepalive.
    ///
    /// A `Some(Duration::ZERO)` here means "off", matching WireGuard's own `PersistentKeepalive = 0`
    /// semantics — but the *raw* field is not the value consumers should arm timers from. Read
    /// [`PeerConfig::effective_persistent_keepalive`] instead, which normalizes zero/sub-minimum
    /// intervals so a misconfigured `Some(0)` can't turn into a keepalive send-flood.
    pub persistent_keepalive_interval: Option<Duration>,
}

impl PeerConfig {
    /// The persistent-keepalive interval that timers should actually be armed from, with the
    /// zero guard applied:
    ///
    /// - `None` → `None` (persistent keepalive disabled — unchanged).
    /// - `Some(d)` where `d` is zero → `None` (treated as "off", matching WireGuard's
    ///   `PersistentKeepalive = 0` semantics; arming a `now + 0` timer would fire immediately and
    ///   re-arm every tick → a send-flood). Zero is the one value that can actually busy-loop the
    ///   sender, so it is the one value normalized here.
    /// - any positive `Some(d)` → unchanged. A sub-second interval is unusual (the real-world value
    ///   is ~25s) but is the caller's legitimate choice; it is NOT silently clamped, and it cannot
    ///   busy-loop the dataplane because the driver's idle wakeup is itself floored (see
    ///   `ts_dataplane`). Tests use small intervals deliberately for fast, deterministic timing.
    ///
    /// Consumers of the interval (e.g. the endpoint's persistent-keepalive arming path) should read
    /// through this rather than the raw [`PeerConfig::persistent_keepalive_interval`] field so the
    /// zero-guard is enforced at every arming site.
    pub fn effective_persistent_keepalive(&self) -> Option<Duration> {
        match self.persistent_keepalive_interval {
            Some(d) if d.is_zero() => None,
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with(interval: Option<Duration>) -> PeerConfig {
        PeerConfig {
            key: NodePublicKey::from([0xABu8; 32]),
            psk: Psk::from([0u8; 32]),
            persistent_keepalive_interval: interval,
        }
    }

    /// `None` (persistent keepalive unconfigured) stays `None`.
    #[test]
    fn none_stays_disabled() {
        assert_eq!(config_with(None).effective_persistent_keepalive(), None);
    }

    /// `Some(0)` is the misconfiguration that would arm a `now + 0` timer firing every tick (a
    /// keepalive send-flood). It must normalize to `None` (off), matching WireGuard's
    /// `PersistentKeepalive = 0` semantics.
    #[test]
    fn zero_is_disabled_not_a_flood() {
        assert_eq!(
            config_with(Some(Duration::ZERO)).effective_persistent_keepalive(),
            None,
            "a zero interval must disable persistent keepalive, never arm a 0-delay timer"
        );
    }

    /// A small-but-nonzero interval passes through unchanged: zero is the only value that can
    /// busy-loop (a `now + 0` timer), and the dataplane's own idle-wakeup floor — not a config
    /// clamp — is what bounds wakeup cadence. Sub-second intervals are unusual but a legitimate
    /// caller choice (tests rely on them for fast, deterministic timing).
    #[test]
    fn small_nonzero_interval_is_preserved() {
        let small = Duration::from_millis(1);
        assert_eq!(
            config_with(Some(small)).effective_persistent_keepalive(),
            Some(small),
            "a positive interval must be preserved verbatim, not clamped"
        );
        let hundred_ms = Duration::from_millis(100);
        assert_eq!(
            config_with(Some(hundred_ms)).effective_persistent_keepalive(),
            Some(hundred_ms),
        );
    }

    /// A normal interval (e.g. Tailscale's 25s default) passes through unchanged.
    #[test]
    fn normal_interval_unchanged() {
        let normal = Duration::from_secs(25);
        assert_eq!(
            config_with(Some(normal)).effective_persistent_keepalive(),
            Some(normal),
        );
    }
}
