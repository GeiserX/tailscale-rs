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
    pub persistent_keepalive_interval: Option<Duration>,
}
