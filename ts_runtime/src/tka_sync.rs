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
//! **Posture (this module fails open; the published `Authority` is then ENFORCED).** This is two
//! distinct claims, kept distinct:
//!
//! - *Sync failure is fail-open here*: every failure path in **this** module (a transport error, a
//!   malformed AUM, a verify failure) returns `Ok(None)` or an `Err` that the caller treats as "no
//!   new Authority obtained this round" — a failed *sync* never blocks the netmap and leaves the
//!   prior enforcement state untouched (see `control_runner`'s apply step). It does NOT mean TKA is
//!   observe-only.
//! - *A successfully synced `Authority` is actively enforced*: once this module returns an
//!   `Authority`, the control runner publishes it to the peer tracker's enforcement cell and the
//!   peer-trust chokepoint fails **closed** — a peer presenting a missing or unauthorized
//!   `key_signature` is **dropped** at the peer-db upsert path (`peer_tracker::tka_snapshot_admits`,
//!   matching Go's `tkaFilterNetmapLocked`). With no lock synced, every peer is admitted (Go's
//!   `b.tka == nil` early return); a control-signalled *disable* clears enforcement back to admit-all.
//!
//! The chain always passes through the **un-bypassable trust boundary** `VerifiedAumChain::verify`
//! before it can reach enforcement, so a malicious control plane cannot forge a trusted key to admit
//! an unauthorized peer — it can only toggle the lock's enable/disable state. The authoritative
//! description of the enforcement posture, threat model, and the remaining deferred gaps
//! (disablement-secret verification, rotation-obsolete/clone-replay dropping) lives in `SECURITY.md`;
//! keep this doc consistent with it.
//!
//! **Do not "simplify" by removing enforcement to match an outdated "observe-only" reading** — that
//! would silently downgrade a working, fail-closed security control to verify-only.

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

/// One entry of the Tailnet-Lock update-chain log, mirroring Go `ipnstate.NetworkLockUpdate` (the
/// rows `tailscale lock log` prints). Produced by [`Device::tka_log`](crate::Runtime::tka_log) from
/// the locally-synced AUM chain — a pure local read, no control round-trip.
///
/// `aum_hash` + `change` + `raw` are the exact Go `NetworkLockUpdate` fields (`Hash`, `Change`,
/// `Raw`). `signer_key_ids` is an extra convenience this engine extracts from the decoded AUM —
/// Go's struct has no `Signatures` field and recovers the signer only by decoding `Raw`; we surface
/// the signer key ids directly so a daemon need not re-decode, while still carrying `raw` for a
/// faithful full decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TkaLogEntry {
    /// The AUM's chain-link hash (Go `NetworkLockUpdate.Hash`): `BLAKE2s-256` of its serialization.
    pub aum_hash: [u8; 32],
    /// The human-readable change kind (Go `NetworkLockUpdate.Change`), e.g. `"add-key"` /
    /// `"remove-key"` / `"checkpoint"` — [`AumKind::as_str`](ts_tka::AumKind::as_str).
    pub change: String,
    /// The id of each trusted key that signed this AUM (each
    /// [`AumSignature::key_id`](ts_tka::AumSignature::key_id), the signer's 32-byte ed25519 public
    /// key for an Ed25519 key). Convenience extraction; absent from Go's struct.
    pub signer_key_ids: Vec<Vec<u8>>,
    /// The AUM's canonical CBOR serialization (Go `NetworkLockUpdate.Raw` = `AUM.Serialize()`), so a
    /// consumer can decode the full AUM (incl. signatures) faithfully.
    pub raw: Vec<u8>,
}

/// Read up to `limit` entries of the TKA update-chain log from a synced AUM `store`, **head-first**
/// (newest → oldest), mirroring Go `NetworkLockLog` which walks `Head` back toward genesis.
///
/// The store holds the chain genesis→head; [`MemAumStore::linear_chain_from`] yields that
/// genesis→head order, which we **reverse** to match Go's head→genesis walk before truncating to
/// `limit`. A pure function over the synced state (no crypto, no mutation, no RPC) so it is unit
/// testable without standing up an actor. An unwalkable store (genesis missing / cycle) yields an
/// empty log rather than erroring — the caller's "no readable chain" is an empty history, matching
/// the no-lock-synced case.
pub(crate) fn tka_log_entries(
    store: &MemAumStore,
    oldest: AumHash,
    limit: usize,
) -> Vec<TkaLogEntry> {
    // genesis→head; an unwalkable store (missing genesis / cycle) → empty log.
    let chain = store.linear_chain_from(oldest).unwrap_or_default();
    chain
        .iter()
        .rev() // Go walks head→genesis; the store walk is genesis→head.
        .take(limit)
        .map(|aum| TkaLogEntry {
            aum_hash: aum.hash().0,
            change: aum.message_kind.as_str().to_string(),
            signer_key_ids: aum.signatures.iter().map(|s| s.key_id.clone()).collect(),
            raw: aum.serialize(),
        })
        .collect()
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

    // ---- tka_log_entries (PR-A) ----------------------------------------------------------------

    /// A test [`AumKey`](ts_tka::AumKey) from a seed byte (deterministic public key + given votes).
    fn test_aum_key(seed: u8, votes: u32) -> ts_tka::AumKey {
        use ed25519_dalek::SigningKey;
        ts_tka::AumKey {
            kind: ts_tka::KeyKind::Ed25519,
            votes,
            public: SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
            meta: Vec::new(),
        }
    }

    /// A genesis `Checkpoint` AUM trusting `key` (no parent). Mirrors the on-wire genesis a node
    /// syncs; built directly (not via `new_genesis_checkpoint`) so the test stays a pure
    /// ordering/mapping check independent of disablement-value construction.
    fn genesis_checkpoint(key: ts_tka::AumKey) -> Aum {
        Aum {
            message_kind: ts_tka::AumKind::Checkpoint,
            prev_aum_hash: None,
            key: None,
            key_id: Vec::new(),
            state: Some(ts_tka::AumState {
                last_aum_hash: None,
                disablement_values: Some(vec![vec![0x11; 32]]),
                keys: Some(vec![key]),
                state_id1: 0,
                state_id2: 0,
            }),
            votes: None,
            meta: Vec::new(),
            signatures: Vec::new(),
        }
    }

    /// An `AddKey` child of `parent` adding `key`.
    fn add_key_child(parent: &Aum, key: ts_tka::AumKey) -> Aum {
        Aum {
            message_kind: ts_tka::AumKind::AddKey,
            prev_aum_hash: Some(parent.hash()),
            key: Some(key),
            key_id: Vec::new(),
            state: None,
            votes: None,
            meta: Vec::new(),
            signatures: Vec::new(),
        }
    }

    /// `tka_log_entries` returns the chain **head-first** (Go `NetworkLockLog` walks head→genesis,
    /// the opposite of the store's genesis→head order), with the correct `change` strings, an
    /// `aum_hash` matching `Aum::hash`, and a `raw` that round-trips through the AUM decoder.
    #[test]
    fn tka_log_entries_head_first_with_fields() {
        let g = genesis_checkpoint(test_aum_key(1, 1));
        let a1 = add_key_child(&g, test_aum_key(2, 1));
        let a2 = add_key_child(&a1, test_aum_key(3, 1));
        // Insert in a scrambled order to prove ordering is by chain links, not insert order.
        let mut store = MemAumStore::new();
        store.insert(a1.clone());
        store.insert(a2.clone());
        store.insert(g.clone());

        let log = tka_log_entries(&store, g.hash(), 100);

        // (a) head-first: newest (a2) → genesis (g).
        let got_hashes: Vec<[u8; 32]> = log.iter().map(|e| e.aum_hash).collect();
        assert_eq!(
            got_hashes,
            vec![a2.hash().0, a1.hash().0, g.hash().0],
            "log must be head-first (a2, a1, genesis)"
        );
        // (b) change strings.
        let changes: Vec<&str> = log.iter().map(|e| e.change.as_str()).collect();
        assert_eq!(changes, vec!["add-key", "add-key", "checkpoint"]);
        // (c) aum_hash == Aum::hash().0 (re-checked against the genesis explicitly).
        assert_eq!(log[2].aum_hash, g.hash().0);
        // (d) raw round-trips through the AUM decoder back to the same AUM.
        for (entry, aum) in log.iter().zip([&a2, &a1, &g]) {
            let decoded = Aum::from_cbor(&entry.raw).expect("raw is canonical AUM CBOR");
            assert_eq!(&decoded, aum, "raw must decode back to the source AUM");
        }
    }

    /// `limit` truncates from the head (the most recent `limit` entries).
    #[test]
    fn tka_log_entries_limit_truncates_from_head() {
        let g = genesis_checkpoint(test_aum_key(1, 1));
        let a1 = add_key_child(&g, test_aum_key(2, 1));
        let a2 = add_key_child(&a1, test_aum_key(3, 1));
        let store = MemAumStore::from_aums([g.clone(), a1.clone(), a2.clone()]);

        let log = tka_log_entries(&store, g.hash(), 2);
        assert_eq!(log.len(), 2, "limit caps the row count");
        assert_eq!(
            log.iter().map(|e| e.aum_hash).collect::<Vec<_>>(),
            vec![a2.hash().0, a1.hash().0],
            "limit keeps the newest entries (head-first)"
        );
        // limit 0 → empty.
        assert!(tka_log_entries(&store, g.hash(), 0).is_empty());
    }

    /// `signer_key_ids` is the `key_id` of each [`AumSignature`](ts_tka::AumSignature) on the AUM,
    /// in order — what a daemon renders without re-decoding `raw`.
    #[test]
    fn tka_log_entries_extracts_signer_key_ids() {
        use ed25519_dalek::SigningKey;
        let mut g = genesis_checkpoint(test_aum_key(1, 1));
        // Sign the genesis with the key it seeds (exactly what `Aum::sign` records: key_id = the
        // signer's verifying-key bytes).
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        g.sign(&sk);
        let signer_id = sk.verifying_key().to_bytes().to_vec();
        let store = MemAumStore::from_aums([g.clone()]);

        let log = tka_log_entries(&store, g.hash(), 100);
        assert_eq!(log.len(), 1);
        assert_eq!(
            log[0].signer_key_ids,
            vec![signer_id],
            "signer_key_ids carries each signature's key_id"
        );
        // An unsigned AUM yields no signer ids.
        let unsigned = genesis_checkpoint(test_aum_key(2, 1));
        let store2 = MemAumStore::from_aums([unsigned.clone()]);
        assert!(
            tka_log_entries(&store2, unsigned.hash(), 100)[0]
                .signer_key_ids
                .is_empty()
        );
    }

    /// An empty / unwalkable store yields an empty log (mirrors the no-lock-synced case the actor
    /// short-circuits before ever calling this): a missing genesis is an empty history, never an
    /// error.
    #[test]
    fn tka_log_entries_unwalkable_store_is_empty() {
        // Empty store: any `oldest` is absent → BadChain inside, mapped to an empty Vec.
        let empty = MemAumStore::new();
        assert!(tka_log_entries(&empty, AumHash([0u8; 32]), 100).is_empty());
        // Non-empty store but `oldest` not present → still empty (not a panic / error).
        let g = genesis_checkpoint(test_aum_key(1, 1));
        let store = MemAumStore::from_aums([g]);
        assert!(tka_log_entries(&store, AumHash([0xEE; 32]), 100).is_empty());
    }
}
