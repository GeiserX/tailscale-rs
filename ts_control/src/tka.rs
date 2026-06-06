//! Owned domain view of the control-pushed Tailnet Lock (TKA) status.
//!
//! Control includes a `TKAInfo` in each [`MapResponse`][ts_control_serde::MapResponse] carrying the
//! current authority head (a base32 `AUMHash`) and a disablement signal. This is the lightweight
//! per-netmap signal; the full authority (the AUM chain + trusted keys) is synced via a separate
//! RPC. The actual signature verification lives in the `ts_tka` crate; this type just carries the
//! head/disabled fields off the netmap so the runtime and embedder can react (e.g. detect a head
//! change and resync, or surface lock state).
//!
//! AUM-sync RPC deferred, see SECURITY.md.

use alloc::string::{String, ToString};

/// The control plane's view of this tailnet's Tailnet Lock state (Go `tailcfg.TKAInfo`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TkaStatus {
    /// The base32 (no-pad) `AUMHash` of the latest Authority Update Message control has applied. A
    /// node whose locally-known head differs should resync the authority. Empty when control sends
    /// no head.
    pub head: String,
    /// Whether control believes Tailnet Lock should be disabled (the node should fetch and verify a
    /// disablement secret before disabling locally).
    pub disabled: bool,
}

impl TkaStatus {
    /// Build the owned status from the borrowed serde view parsed off the netmap.
    pub fn from_serde(info: &ts_control_serde::TkaInfo<'_>) -> Self {
        TkaStatus {
            head: info.head.to_string(),
            disabled: info.disabled,
        }
    }

    /// Whether Tailnet Lock is in effect for this tailnet: a non-empty head and not disabled.
    pub fn is_enabled(&self) -> bool {
        !self.head.is_empty() && !self.disabled
    }
}
