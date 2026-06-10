//! Tailnet-Lock (TKA) chain-sync orchestration: the runtime-layer driver that ties the transport
//! RPCs (`ts_control::{tka_bootstrap, tka_sync_offer, tka_sync_send}`) to the chain logic
//! (`ts_tka::{Aum, Authority, MemAumStore, VerifiedAumChain}`), mirroring Go's `tkaSyncIfNeeded`
//! (`ipn/ipnlocal/tailnet-lock.go`, v1.100.0).
//!
//! This lives in `ts_runtime` because it is the only layer that depends on **both** the wire crate
//! (`ts_control`, which deliberately knows nothing of `ts_tka`) and the chain crate (`ts_tka`). It
//! converts between the wire forms (base32 head strings, base64'd raw-CBOR AUM bytes) and the domain
//! types, and drives the two-phase flow:
//!
//! 1. **Bootstrap** (only when we hold no chain yet): `tka_bootstrap` fetches the genesis AUM; we
//!    `Aum::from_cbor` it, build the initial [`Authority`] via the **un-bypassable trust boundary**
//!    `VerifiedAumChain::verify` → `Authority::from_verified_chain`, and seed a [`MemAumStore`].
//! 2. **Sync** (offer → send): compute our [`SyncOffer`], send it, decode the AUMs control says we're
//!    missing, `Inform`-equivalent (verify + fold into a fresh Authority over the grown store), then
//!    tell control the AUMs *it* is missing. The order matches Go exactly — we compute what to *send*
//!    from the pre-Inform store, then advance.
//!
//! **Posture (observe-only, fail-open):** every failure path returns `Ok(None)` or an `Err` that the
//! caller treats as "no Authority obtained" — it never blocks the netmap, never drops a peer. The
//! resulting [`Authority`] is published for the verify-and-log consumer (#136); enforcement is a
//! separate, later, gated decision. The chain always passes through `VerifiedAumChain::verify`, so a
//! malicious control plane cannot forge trusted keys here.

use std::sync::Arc;

use ts_control::{
    TkaSyncError, TkaSyncOfferRequest, TkaSyncSendRequest, tka_bootstrap, tka_sync_offer,
    tka_sync_send,
};
use ts_tka::{Aum, AumHash, Authority, MemAumStore, SyncOffer, VerifiedAumChain};

/// The synced TKA state a successful [`sync_tka`] produces: the verified [`Authority`] (for the
/// verify-and-log consumer) plus the [`MemAumStore`] of AUMs gathered so far (so the next sync can
/// compute offers/missing-sets without re-bootstrapping).
pub(crate) struct SyncedTka {
    pub authority: Arc<Authority>,
    pub store: MemAumStore,
    /// The genesis/oldest AUM hash, needed as the `oldest` argument to subsequent `sync_offer`s.
    pub oldest: AumHash,
}

/// Errors internal to the sync driver. All map to "no Authority obtained" at the caller — the netmap
/// is never errored and peers are never dropped on any of these.
#[derive(Debug, thiserror::Error)]
pub(crate) enum TkaSyncDriverError {
    /// A transport RPC failed (network / unsupported / HTTP). `Unsupported` means control has no TKA
    /// endpoint — treat as "inert", not a hard error.
    #[error("TKA sync RPC failed: {0}")]
    Rpc(#[from] TkaSyncError),
    /// An AUM from control failed to decode or verify. Fail-closed: we do NOT advance the Authority.
    #[error("TKA chain verification failed: {0}")]
    Chain(#[from] ts_tka::TkaError),
}

/// Decode a base64-of-CBOR AUM batch (the wire form of `MissingAUMs`) into domain [`Aum`]s.
/// Fail-closed: a single undecodable AUM rejects the whole batch (we never partially trust).
fn decode_aums(marshaled: &[Vec<u8>]) -> Result<Vec<Aum>, ts_tka::TkaError> {
    marshaled.iter().map(|b| Aum::from_cbor(b)).collect()
}

/// Re-verify a chain (existing store contents + newly-received AUMs) into a fresh [`Authority`],
/// the `Inform` analog. We replay the full known AUM set through the trust boundary rather than
/// mutating in place, so the resulting Authority is always one `VerifiedAumChain::verify` proved.
///
/// The store's AUMs in linear genesis→head order are what `verify` expects; we reconstruct that order
/// by walking from the genesis (`oldest`) forward via the store's child links.
fn rebuild_authority(store: &MemAumStore, oldest: AumHash) -> Result<Authority, ts_tka::TkaError> {
    let chain = store.linear_chain_from(oldest)?;
    let verified = VerifiedAumChain::verify(&chain)?;
    Ok(Authority::from_verified_chain(verified))
}

/// Run a TKA bootstrap+sync cycle against control.
///
/// `current` is our existing synced state (`None` on first run → bootstrap first). Returns
/// `Ok(Some(SyncedTka))` with the advanced Authority on success, `Ok(None)` when control has no lock
/// for us (inert), or `Err` on a transport/verify failure (caller stays inert).
pub(crate) async fn sync_tka(
    config: &ts_control::Config,
    keys: &ts_keys::NodeState,
    current: Option<SyncedTka>,
) -> Result<Option<SyncedTka>, TkaSyncDriverError> {
    let control_url = &config.server_url;
    let allow_http_key_fetch = config.allow_http_key_fetch;

    // Phase 1: bootstrap if we have no chain yet.
    let (mut store, oldest, mut authority) = match current {
        Some(s) => (s.store, s.oldest, (*s.authority).clone()),
        None => {
            let resp = tka_bootstrap(
                control_url,
                keys,
                String::new(), // no local head yet
                allow_http_key_fetch,
            )
            .await?;
            if resp.genesis_aum.is_empty() {
                // Control returned no genesis: TKA is not enabled for us. Stay inert (not an error).
                return Ok(None);
            }
            let genesis = Aum::from_cbor(&resp.genesis_aum)?;
            let oldest = genesis.hash();
            let mut store = MemAumStore::new();
            store.insert(genesis);
            let authority = rebuild_authority(&store, oldest)?;
            (store, oldest, authority)
        }
    };

    // Phase 2: offer → (decode + inform) → send. Mirror Go's order exactly.
    let local_offer = authority.sync_offer(&store, oldest)?;
    let offer_req = TkaSyncOfferRequest {
        version: Default::default(), // overwritten by the RPC with CURRENT
        node_key: keys.node_keys.public,
        head: local_offer.head.to_base32(),
        ancestors: local_offer
            .ancestors
            .iter()
            .map(|a| a.to_base32())
            .collect(),
    };
    let offer_resp = tka_sync_offer(control_url, keys, offer_req, allow_http_key_fetch).await?;

    // Reconstruct control's offer from the response so we can compute what *control* is missing —
    // BEFORE we Inform ourselves with control's AUMs (Go computes missing-to-send pre-Inform).
    let control_offer = parse_offer(&offer_resp.head, &offer_resp.ancestors)?;

    // Decode + insert the AUMs control sent, then rebuild (verify) the advanced Authority.
    let received = decode_aums(&offer_resp.missing_aums)?;
    for aum in &received {
        store.insert(aum.clone());
    }
    // Compute what control is missing from the store as it stands (post-insert is fine: missing_aums
    // is computed against control's offer, and the gather is from our head — inserting control's own
    // AUMs cannot make us think it lacks them).
    let to_send = authority
        .missing_aums(&store, &control_offer, oldest)
        .unwrap_or_default();
    // Advance our Authority over the grown store (the Inform analog) — through the trust boundary.
    authority = rebuild_authority(&store, oldest)?;

    // Phase 3: send control the AUMs it lacks (best-effort; a failure here doesn't undo our advance).
    let send_req = TkaSyncSendRequest {
        version: Default::default(),
        node_key: keys.node_keys.public,
        head: authority.head().to_base32(),
        missing_aums: to_send.iter().map(Aum::serialize).collect(),
        interactive: false,
    };
    if let Err(e) = tka_sync_send(control_url, keys, send_req, allow_http_key_fetch).await {
        // We already advanced locally; control not accepting our AUMs is logged, not fatal.
        tracing::warn!(error = ?e, "TKA sync/send failed (local Authority already advanced)");
    }

    Ok(Some(SyncedTka {
        authority: Arc::new(authority),
        store,
        oldest,
    }))
}

/// Parse a wire offer (base32 head + ancestors) into a domain [`SyncOffer`]. A malformed base32 hash
/// is a decode error (fail-closed).
fn parse_offer(head: &str, ancestors: &[String]) -> Result<SyncOffer, ts_tka::TkaError> {
    let head = AumHash::from_base32(head).ok_or(ts_tka::TkaError::Decode("bad base32 head"))?;
    let ancestors = ancestors
        .iter()
        .map(|a| AumHash::from_base32(a).ok_or(ts_tka::TkaError::Decode("bad base32 ancestor")))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SyncOffer { head, ancestors })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_offer_roundtrips_base32() {
        // A head + two ancestors as base32 (no-pad) of 32-byte hashes parse back to those hashes.
        let h0 = AumHash([0x11; 32]);
        let h1 = AumHash([0x22; 32]);
        let h2 = AumHash([0x33; 32]);
        let offer = parse_offer(&h0.to_base32(), &[h1.to_base32(), h2.to_base32()]).expect("parse");
        assert_eq!(offer.head, h0);
        assert_eq!(offer.ancestors, vec![h1, h2]);
    }

    #[test]
    fn parse_offer_rejects_bad_base32() {
        // A non-base32 / wrong-length head fails closed (not a panic).
        assert!(parse_offer("not valid base32!", &[]).is_err());
        // A good head but a bad ancestor also fails.
        let good = AumHash([1u8; 32]).to_base32();
        assert!(parse_offer(&good, &["@@@@".to_string()]).is_err());
    }

    #[test]
    fn decode_aums_roundtrips_and_rejects_garbage() {
        // A valid AUM serializes → decode_aums reconstructs it; a garbage blob in the batch rejects
        // the whole batch (fail-closed, never partial trust).
        let aum = Aum {
            message_kind: ts_tka::AumKind::NoOp,
            prev_aum_hash: None,
            key: None,
            key_id: Vec::new(),
            state: None,
            votes: None,
            meta: Vec::new(),
            signatures: Vec::new(),
        };
        let good = aum.serialize();
        let decoded = decode_aums(std::slice::from_ref(&good)).expect("decode");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].hash(), aum.hash());
        // One garbage blob alongside a good one → the whole batch errors.
        assert!(decode_aums(&[good, vec![0xff, 0x00, 0x13]]).is_err());
    }
}
