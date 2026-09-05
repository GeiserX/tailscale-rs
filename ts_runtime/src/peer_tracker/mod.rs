//! Peer delta update tracking.

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::Arc,
};

use kameo::{
    actor::ActorRef,
    message::{Context, Message},
    reply::ReplySender,
};
use tokio::sync::watch;
use ts_control::{Node, UserId, UserProfile};
use ts_keys::{DiscoPublicKey, NodePublicKey};
use ts_transport::PeerId;

use crate::{
    Error, dataplane::PeerDiscoKeyAdvertisement, direct::DiscoKeyObserved, env::Env,
    status::StatusNode,
};

mod peer_db;

pub use peer_db::{DiscoKeyMatch, PeerDb};

/// Whether `key` is the all-zero disco key, which Go spells `key.DiscoPublic.IsZero()` and treats
/// everywhere as "this peer has no disco key" rather than as a usable key.
fn disco_key_is_zero(key: &DiscoPublicKey) -> bool {
    key.to_bytes() == [0u8; DiscoPublicKey::KEY_LEN_BYTES]
}

/// Normalize a disco key as it arrives from control: the all-zero key means "absent", exactly as
/// Go's `IsZero()` checks in `endpoint.updateDiscoKey` read it.
fn disco_key_from_control(key: Option<DiscoPublicKey>) -> Option<DiscoPublicKey> {
    key.filter(|k| !disco_key_is_zero(k))
}

/// The two disco keys a peer can present, and which of them is currently active — Go
/// [`magicsock.endpointDisco`] (`wgengine/magicsock/endpoint.go`).
///
/// A peer's disco key reaches us from two independent sources: **control**, in a netmap node or a
/// `PeersChangedPatch`, and the **peer itself**, in a TSMP disco-key advertisement carried inside
/// the WireGuard tunnel. Go keeps both side by side on the endpoint, and so do we, because control
/// is the slower of the two: an advertisement exists precisely to cover the window where control has
/// not caught up with the peer's current key, so collapsing the two into one field would let the
/// next map poll overwrite a freshly-learned key with control's stale one — losing the feature's own
/// motivating case.
///
/// Only one key is active for sending at a time ([`key`](Self::key)). That active key is what the
/// peer db carries in [`Node::disco_key`], which is this fork's live lookup for every direct-path
/// consumer (`direct::DiscoPeerLookup` resolves against it, and `PeerDb`'s disco index is built from
/// it) — the stand-in for Go's per-endpoint `disco` pointer.
///
/// [`magicsock.endpointDisco`]: https://github.com/tailscale/tailscale/blob/49e148c4a30b4f8098f69468fd27a7021d85ea02/wgengine/magicsock/endpoint.go
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct EndpointDisco {
    /// The key learned from control (Go `endpointDisco.controlKey`).
    control: Option<DiscoPublicKey>,
    /// The key learned from a TSMP advertisement (Go `endpointDisco.tsmpKey`).
    tsmp: Option<DiscoPublicKey>,
    /// Whether [`tsmp`](Self::tsmp) is the active key (Go `endpointDisco.tsmpActive`).
    tsmp_active: bool,
}

impl EndpointDisco {
    /// The key currently regarded as active — Go `endpointDisco.key()`.
    fn key(&self) -> Option<DiscoPublicKey> {
        if self.tsmp_active {
            self.tsmp
        } else {
            self.control
        }
    }

    /// The control-learned key, active or not — Go `endpointDisco.keyFromControl()`.
    fn key_from_control(&self) -> Option<DiscoPublicKey> {
        self.control
    }

    /// The TSMP-learned key, active or not — Go `endpointDisco.keyFromTSMP()`.
    fn key_from_tsmp(&self) -> Option<DiscoPublicKey> {
        self.tsmp
    }

    /// Replace the control-learned key, leaving any TSMP-learned key in place — Go
    /// [`endpoint.updateDiscoKey`].
    ///
    /// Control's key is always recorded in control's own slot, but it takes the *active* slot only
    /// if no TSMP-learned key already holds it: Go `epDisco.tsmpActive = old.tsmpActive ||
    /// key.IsZero()`. A key the peer told us itself is better evidence than a control server that
    /// is, by construction, the slower of the two sources — so control changing its mind no longer
    /// preempts an active TSMP key. Upstream returns to control's key when disco is actually
    /// *received* under it (`endpoint.checkAndUpdateDiscoKey`), not when control asserts it.
    ///
    /// An absent (Go: zero) control key still hands the slot to the TSMP key, if there is one. When
    /// there is neither key, the caller drops the whole entry ([`is_empty`](Self::is_empty)) — which
    /// is what stops an active TSMP slot with no TSMP key in it outliving this call, exactly as Go
    /// nils the endpoint's `disco` pointer in the same case.
    ///
    /// [`endpoint.updateDiscoKey`]: https://github.com/tailscale/tailscale/blob/9ea7cba44591e0cd840c6c94d23274dd222059bf/wgengine/magicsock/endpoint.go
    fn update_from_control(&mut self, key: Option<DiscoPublicKey>) {
        self.control = key;
        self.tsmp_active = self.tsmp_active || key.is_none();
    }

    /// Replace the TSMP-learned key, leaving the control-learned key in place — Go
    /// `endpoint.updateTSMPDiscoKey`.
    fn update_from_tsmp(&mut self, key: Option<DiscoPublicKey>) {
        self.tsmp = key;
        self.tsmp_active = key.is_some();
    }

    /// The peer's other known key: the slot that is not active, when it holds a key that differs
    /// from the active one.
    ///
    /// This is what makes ingress under the peer's *other* key resolvable
    /// ([`PeerDb::set_inactive_disco_key`]). `None` when the inactive slot is empty or holds the
    /// same key as the active one — there is no second key to accept in either case.
    fn inactive_key(&self) -> Option<DiscoPublicKey> {
        let inactive = if self.tsmp_active {
            self.control
        } else {
            self.tsmp
        };

        inactive.filter(|k| Some(*k) != self.key())
    }

    /// Accept `key` as this peer's, switching the active slot to it when it is the currently
    /// *inactive* one — Go [`endpoint.checkAndUpdateDiscoKey`].
    ///
    /// Called with the sender key of a disco frame we have opened, which proves the sender holds
    /// that key's private half. Receiving under a key is therefore demonstrative: it is what the
    /// peer is actually using, so upstream makes it the key we send to as well.
    ///
    /// Returns `None` when `key` belongs to **neither** slot — the refusal that is the whole
    /// security value of the check, and the reason this is not simply "trust whatever key opened".
    /// Otherwise `Some(changed)`, where `changed` reports whether the active key moved (and so
    /// whether the direct path built under the old one has to be invalidated).
    ///
    /// [`endpoint.checkAndUpdateDiscoKey`]: https://github.com/tailscale/tailscale/blob/9ea7cba44591e0cd840c6c94d23274dd222059bf/wgengine/magicsock/endpoint.go
    fn check_and_update(&mut self, key: DiscoPublicKey) -> Option<bool> {
        if self.key() == Some(key) {
            return Some(false);
        }

        // Not the active key. Go's compare-and-swap on `tsmpActive`: whichever slot holds it
        // becomes the active one. Control's slot is tried first only for determinism — the two
        // holding the same key is already handled by the equality check above.
        if self.control == Some(key) {
            self.tsmp_active = false;
            return Some(true);
        }
        if self.tsmp == Some(key) {
            self.tsmp_active = true;
            return Some(true);
        }

        None
    }

    /// No key material from either source — Go nils out the endpoint's `disco` pointer here.
    fn is_empty(&self) -> bool {
        self.control.is_none() && self.tsmp.is_none()
    }
}

/// Actor that tracks peer delta updates and emits new states.
pub struct PeerTracker {
    peer_db: PeerDb,
    seen_state_update: bool,
    pending_requests: Vec<Pending>,
    /// Latest peer snapshot, published on every netmap update so embedders can watch for peer
    /// changes ([`WatchNetmap`]).
    peer_watch: watch::Sender<Vec<StatusNode>>,
    /// Accumulated netmap user profiles (`MapResponse.UserProfiles`), keyed by user id, joined
    /// against a node's [`Node::user_id`](ts_control::Node::user_id) to resolve the owning user's
    /// login/display name for a [`WhoIs`](crate::status::WhoIs). Control sends these incrementally
    /// (only new/changed profiles per response), so this map **accumulates** across updates rather
    /// than being replaced — a peer upserted in one response may reference a profile delivered in an
    /// earlier one.
    user_profiles: HashMap<UserId, UserProfile>,
    /// Per-peer disco-key provenance ([`EndpointDisco`]), keyed by the peer's node key.
    ///
    /// Go keeps this on the magicsock `endpoint`, which the peer map keys by node key; here the peer
    /// db stores control's [`Node`] verbatim, so the second key (and which of the two is active)
    /// lives beside it. Keying by node key reproduces Go's lifetime exactly: the state is dropped
    /// when the peer leaves the netmap, and a peer that ROTATES its node key gets a fresh entry —
    /// Go builds it a new endpoint, so a key learned over TSMP under the old node key is never
    /// carried onto the new one. [`prune_endpoint_disco`](PeerTracker::prune_endpoint_disco) does
    /// the dropping.
    endpoint_disco: HashMap<NodePublicKey, EndpointDisco>,
    /// Tailnet-Lock (TKA) authority enforced at the peer-trust chokepoint, matching Go
    /// `tkaFilterNetmapLocked`. Read on demand from a [`watch`] cell the control runner owns: when it
    /// holds `Some` (a verified lock has been synced from control), enforcement is **active** — every
    /// upserted peer must present a `key_signature` this authority authorizes, or it is dropped
    /// (fail-closed), exactly as Go drops peers with a missing or failing signature. When it holds
    /// `None` (no lock, or the lock was disabled) enforcement is **inactive** and every peer is
    /// upserted, identical to pre-TKA behavior and to Go's `b.tka == nil` early return.
    ///
    /// A `watch::Receiver` (not the bus) is the transport on purpose: the authority is a single
    /// security-critical state cell, and `watch` is last-write-wins, never-dropped, and ordered by
    /// the control runner's own writes — so a disable (`None`) can never be reordered behind or
    /// silently dropped before a stale `Some` (which a best-effort broadcast bus could do, leaving a
    /// defunct lock enforcing forever). The control runner is the sole writer; we only ever read.
    ///
    /// The authority always passes through `VerifiedAumChain::verify` before the control runner
    /// publishes it, so enforcement only engages on a chain we have cryptographically verified.
    /// Connectivity now depends on `ts_tka` verifying genuinely-good signatures correctly (see
    /// SECURITY.md). Self is structurally never filtered here (the self node never enters `peer_db` —
    /// it is routed to the control runner's `self_node` cell), so a node cannot lock itself out of
    /// its own netmap.
    tka_authority: watch::Receiver<Option<Arc<ts_tka::Authority>>>,
    env: Env,
}

impl PeerTracker {
    fn peer_by_name_opt(&self, name: &str) -> Option<&Node> {
        // Canonicalization (case + trailing dot) is handled inside the name index lookup.
        self.peer_db.get(&name).map(|(_id, node)| node)
    }

    fn peer_by_tailnet_ip_opt(&self, ip: IpAddr) -> Option<&Node> {
        self.peer_db.get(&ip).map(|(_id, node)| node)
    }

    /// Build the peer entries for a [`Status`](crate::Status) snapshot from the current peer db.
    ///
    /// Connectivity fields (`cur_addr`/`relay`) are left at their `from_node` defaults (`None`) here:
    /// this is the live-watch/hot path and must stay magicsock-free and synchronous. The explicit
    /// [`GetStatus`] snapshot enriches them ([`status_peers_with_ids`](Self::status_peers_with_ids)).
    fn status_peers(&self) -> Vec<StatusNode> {
        self.peer_db
            .peers()
            .values()
            .map(StatusNode::from_node)
            .collect()
    }

    /// Like [`status_peers`](Self::status_peers) but pairs each entry with its [`PeerId`], so the
    /// caller can join per-peer connectivity (the direct manager's `best_addrs`, keyed by `PeerId`)
    /// onto the `StatusNode` before returning it. Order is unspecified (a `HashMap` walk).
    fn status_peers_with_ids(&self) -> Vec<(PeerId, StatusNode)> {
        self.peer_db
            .peers()
            .iter()
            .map(|(id, node)| (*id, StatusNode::from_node(node)))
            .collect()
    }

    fn whois_opt(&self, addr: std::net::SocketAddr) -> Option<crate::status::WhoIs> {
        let ip = crate::status::whois_addr(addr);
        let node = self.peer_by_tailnet_ip_opt(ip).cloned()?;
        // Join the node's owning user id against the accumulated UserProfiles table to resolve a
        // login/display name. `None` when control sent no profile for that user (e.g. tagged nodes
        // with no human owner, or a profile not yet delivered).
        let user = self.resolve_user(node.user_id);
        Some(crate::status::WhoIs::from_node_with_user(node, user))
    }

    /// Resolve a user id to its best display label from the accumulated profile table.
    fn resolve_user(&self, user_id: UserId) -> Option<String> {
        self.user_profiles
            .get(&user_id)
            .and_then(UserProfile::best_label)
    }

    /// Whether `node` may be admitted to the peer db under Tailnet Lock, matching Go
    /// `tkaFilterNetmapLocked`'s per-peer verdict (drop unsigned / failed-signature peers).
    ///
    /// This consults the live [`tka_authority`](Self::tka_authority) cell on each call (one `borrow`,
    /// held only for the duration of the verdict). For a `Full` resync — which checks every peer —
    /// prefer [`tka_authority_snapshot`](Self::tka_authority_snapshot) +
    /// [`tka_snapshot_admits`](Self::tka_snapshot_admits) to borrow once and verify each peer a single
    /// time; this method is the convenience wrapper for the single-peer (`Delta`/patch) sites.
    ///
    /// Fail-closed and gated:
    /// - No authority ⇒ no lock synced ⇒ always admit (Go's `b.tka == nil` early return; identical to
    ///   pre-TKA behavior).
    /// - **Empty trusted-key state** ⇒ always admit (logged at `error!` — see
    ///   [`tka_snapshot_admits`](Self::tka_snapshot_admits) for the full rationale).
    /// - Authority present + peer carries a `key_signature` the authority authorizes for the peer's
    ///   node key ⇒ admit.
    /// - Authority present + signature missing or unauthorized/invalid ⇒ **drop** (Go drops peers
    ///   with a missing signature or failed `NodeKeyAuthorized` under tailnet lock).
    fn tka_admits(&self, node: &Node) -> bool {
        // Single-peer sites (`Delta`/patch) only need the admit bool; the rotation details are used
        // exclusively by the cross-peer `Full` filter (rotation obsolescence is whole-netmap).
        Self::tka_snapshot_admits(self.tka_authority.borrow().as_deref(), node).admitted
    }

    /// Borrow the current TKA authority once (cloning the cheap `Arc`) for a batch verdict. Returns
    /// `None` when no lock is synced (admit-all). Used by the `Full` path so a netmap of N peers
    /// reads the cell once and runs at most one signature verify per peer (not two).
    fn tka_authority_snapshot(&self) -> Option<Arc<ts_tka::Authority>> {
        self.tka_authority.borrow().clone()
    }

    /// The per-peer Tailnet-Lock verdict against an already-borrowed `authority` snapshot. Factored
    /// out so both the single-peer [`tka_admits`](Self::tka_admits) and the `Full` batch path share
    /// one verdict implementation (no divergence) while the batch path verifies each peer exactly
    /// once.
    ///
    /// Returns whether the peer is admitted AND, for an admitted peer signed by a rotation chain, the
    /// [`RotationDetails`](ts_tka::RotationDetails) of that chain — so the `Full` path can run the
    /// cross-peer rotation filter (Go's `rotationTracker`) without a second verify per peer. A peer
    /// that is dropped, unsigned, or signed by a non-rotation chain carries `rotation == None`.
    ///
    /// Never logs key/signature bytes — only the `stable_id` and the `TkaError` Display (static
    /// descriptors). One documented parity gap remains vs Go (in PARITY_ROADMAP): no
    /// `UnsignedPeerAPIOnly` *admission* exemption — Go admits such a peer unsigned under an active
    /// lock, we drop it (stricter, the safe direction). [`Node::unsigned_peer_api_only`] is now
    /// carried, and the routes half of upstream's treatment is enforced at decode
    /// (`ts_control::Node`'s `From` impl clamps such a peer's accepted routes to its own addresses,
    /// unconditionally, whether or not a lock is active); only the admission carve-out is deferred.
    fn tka_snapshot_admits(authority: Option<&ts_tka::Authority>, node: &Node) -> TkaVerdict {
        let Some(auth) = authority else {
            return TkaVerdict::admit();
        };

        // Brick-guard: an authority with no trusted keys would drop every peer. A verified chain is
        // structurally guaranteed ≥1 key (genesis rejects an empty key set, and the last key cannot
        // be removed), so reaching here means a `ts_tka` invariant was violated — admit rather than
        // black-hole the whole netmap, and log at `error!` because it signals a real bug, not an
        // expected runtime input. This is OUR fail-safe, not a Go behavior. NOTE: it only catches the
        // empty-keyset shape; a non-empty authority that authorizes none of the offered peers still
        // (correctly) drops them — that is what a lock that revoked everyone means. The
        // "authorized-zero-peers" isolation case is surfaced separately by the caller.
        if auth.state().keys.is_empty() {
            tracing::error!(
                "TKA: authority has an empty trusted-key set (verified chains never do — likely a \
                 ts_tka bug); not enforcing (admitting all) to avoid isolating the node"
            );
            return TkaVerdict::admit();
        }

        if node.key_signature.is_empty() {
            tracing::warn!(
                stable_id = ?node.stable_id,
                "TKA: dropping unsigned peer under tailnet lock"
            );
            return TkaVerdict::drop();
        }

        match auth.node_key_authorized_with_details(&node.node_key.to_bytes(), &node.key_signature)
        {
            Ok(rotation) => {
                tracing::debug!(stable_id = ?node.stable_id, "TKA: peer node-key authorized");
                TkaVerdict {
                    admitted: true,
                    rotation,
                }
            }
            Err(e) => {
                tracing::warn!(
                    stable_id = ?node.stable_id,
                    error = %e,
                    "TKA: dropping peer with unauthorized node key"
                );
                TkaVerdict::drop()
            }
        }
    }

    /// The **keep** verdict for a whole batch of peers under `authority` — one complete Go
    /// `tkaFilterNetmapLocked` pass (`ipn/ipnlocal/tailnet-lock.go`, v1.100.0), in Go's order:
    ///
    /// 1. the per-peer signature verdict ([`tka_snapshot_admits`](Self::tka_snapshot_admits)), then
    /// 2. the cross-peer rotation filter (Go `rotationTracker`): a peer presenting a node key that a
    ///    newer rotation has superseded — or a tied clone of one — is dropped even though its own
    ///    signature verifies. That is whole-batch by nature (one peer's chain obsoletes another's
    ///    key), which is why it lives here and not in the per-peer verdict.
    ///
    /// Factored out because two call sites must agree exactly on what "admitted" means: the `Full`
    /// netmap upsert in [`apply_peer_update`](Self::apply_peer_update), and
    /// [`tka_reevaluate_peer_db`](Self::tka_reevaluate_peer_db), which re-runs the same pass over the
    /// peers already in the db when a freshly-synced authority is installed. A divergence between
    /// them would be a peer admitted by one path and dropped by the other.
    ///
    /// `authority` is borrowed once and each peer verified exactly once (the ed25519 verify is the
    /// expensive part). Returns one `bool` per input node, in input order; `None` authority ⇒ all
    /// `true` (no lock synced ⇒ admit all, Go's `b.tka == nil` early return).
    fn tka_keep_verdicts(authority: Option<&ts_tka::Authority>, nodes: &[&Node]) -> Vec<bool> {
        let verdicts = nodes
            .iter()
            .map(|node| Self::tka_snapshot_admits(authority, node))
            .collect::<Vec<_>>();

        let mut rotation = RotationTracker::default();
        for (node, verdict) in nodes.iter().zip(&verdicts) {
            if verdict.admitted
                && let Some(details) = &verdict.rotation
            {
                rotation.add(node.node_key.to_bytes().to_vec(), details);
            }
        }
        let obsolete = rotation.obsolete_keys();

        nodes
            .iter()
            .zip(&verdicts)
            .map(|(node, v)| {
                // `contains` takes `&[u8]` (HashSet<Vec<u8>> borrows as a slice) — no alloc.
                v.admitted && !obsolete.contains(&node.node_key.to_bytes()[..])
            })
            .collect()
    }
}

/// The outcome of a per-peer Tailnet-Lock check: whether the peer is admitted, plus (for an admitted
/// peer signed by a rotation chain) the chain's [`RotationDetails`](ts_tka::RotationDetails) so the
/// `Full` path can run the cross-peer rotation filter from the SAME verify pass (no second verify).
struct TkaVerdict {
    admitted: bool,
    rotation: Option<ts_tka::RotationDetails>,
}

impl TkaVerdict {
    /// Admitted, no rotation details (no lock / brick-guard / non-rotation signature).
    fn admit() -> Self {
        Self {
            admitted: true,
            rotation: None,
        }
    }
    /// Dropped.
    fn drop() -> Self {
        Self {
            admitted: false,
            rotation: None,
        }
    }
}

/// Cross-peer rotation-obsolescence tracker, mirroring Go `ipnlocal.rotationTracker`. Fed the
/// [`RotationDetails`](ts_tka::RotationDetails) of every admitted, rotation-signed peer in a `Full`
/// netmap; [`obsolete_keys`](Self::obsolete_keys) then returns the node keys to drop on top of the
/// per-peer verdict. Two rules (Go `tkaFilterNetmapLocked` + `rotationTracker.obsoleteKeys`):
///
/// 1. Every prior node key named in any rotation chain is obsolete (a newer chain rotated it away).
/// 2. Among `Direct`-rooted chains sharing one wrapping pubkey (a clone signal), only the
///    longest-chain peer survives; if the two longest are tied, ALL in that group are dropped (we
///    cannot tell which is the latest, so reject for safety). `Credential`-rooted chains are exempt
///    from rule 2 — several nodes can legitimately join under one reusable auth key (same wrapping
///    pubkey), so sharing it is not a clone signal there. (Rule 1 still applies to them.)
///
/// Node keys are tracked as raw `Vec<u8>` (the verified 32-byte node-public bytes).
#[derive(Default)]
struct RotationTracker {
    obsolete: HashSet<Vec<u8>>,
    by_wrapping_key: HashMap<Vec<u8>, Vec<SigRotation>>,
}

/// One admitted peer's rotation entry within a wrapping-key group.
struct SigRotation {
    node_key: Vec<u8>,
    num_prev_keys: usize,
}

impl RotationTracker {
    /// Record an admitted peer `node_key` and its rotation `details` (Go `addRotationDetails`).
    fn add(&mut self, node_key: Vec<u8>, details: &ts_tka::RotationDetails) {
        // Rule 1: every prior key is obsolete — applied for ALL chains (incl. credential-rooted),
        // matching Go's ungated `obsolete.AddSlice(d.PrevNodeKeys)`.
        self.obsolete.extend(details.prev_node_keys.iter().cloned());
        // Rule 2 (clone-uniqueness) is gated to Direct-rooted chains only.
        if details.initial_sig_kind != ts_tka::SigKind::Direct {
            return;
        }
        self.by_wrapping_key
            .entry(details.initial_wrapping_pubkey.clone())
            .or_default()
            .push(SigRotation {
                node_key,
                num_prev_keys: details.prev_node_keys.len(),
            });
    }

    /// Compute the full obsolete node-key set (Go `rotationTracker.obsoleteKeys`). Processes each
    /// wrapping-key group, mutating the shared `obsolete` set as it goes (so a key obsoleted by one
    /// group is seen as obsolete by later groups via the `retain` below — Go's
    /// `slices.DeleteFunc(... Contains)`). Group iteration order (a `HashMap` drain) is
    /// nondeterministic, but the result is order-INDEPENDENT: this only ever *inserts* into
    /// `obsolete` (never removes), and rule 1 already obsoleted every prior key before this loop, so
    /// the final set is a union that does not depend on which group runs first (as in Go).
    fn obsolete_keys(mut self) -> HashSet<Vec<u8>> {
        // Drain only the group map so the loop can mutate `self.obsolete` without aliasing it; the
        // shared `obsolete` set itself is NOT drained, preserving the cross-group visibility above.
        let groups: Vec<Vec<SigRotation>> = self.by_wrapping_key.drain().map(|(_k, v)| v).collect();
        for mut group in groups {
            // Drop entries already obsoleted (rotated away) by another chain.
            group.retain(|rd| !self.obsolete.contains(&rd.node_key));
            if group.is_empty() {
                continue;
            }
            // Longest chain (most prior keys) is the newest ⇒ the survivor; sort decreasing.
            // `sort_by_key` is stable (like Go's `SortStableFunc`); `Reverse` gives descending order.
            group.sort_by_key(|rd| core::cmp::Reverse(rd.num_prev_keys));
            if group.len() >= 2 && group[0].num_prev_keys == group[1].num_prev_keys {
                // Tie for longest ⇒ cannot disambiguate the latest ⇒ drop the WHOLE group.
                tracing::warn!(
                    "TKA: multiple peers share a wrapping key with equal rotation depth; dropping all (cannot determine the latest)"
                );
                for rd in &group {
                    self.obsolete.insert(rd.node_key.clone());
                }
            } else {
                // Only the longest-chain peer survives; the rest are obsolete.
                for rd in &group[1..] {
                    self.obsolete.insert(rd.node_key.clone());
                }
            }
        }
        self.obsolete
    }
}

impl kameo::Actor for PeerTracker {
    /// `(env, tka_authority)`: the bus/keys env, plus the read end of the control runner's TKA
    /// enforcement-authority cell (Go `tkaFilterNetmapLocked`). The control runner is the sole
    /// writer; it publishes the verified `Authority` after a successful `/machine/tka/sync` and
    /// `None` when the lock is disabled. A `watch` cell (not a bus message) so the latest value is
    /// always readable on demand, never dropped, and never reordered (see the control runner's
    /// `tka_authority` cell).
    type Args = (Env, watch::Receiver<Option<Arc<ts_tka::Authority>>>);
    type Error = Error;

    async fn on_start(
        (env, tka_authority): Self::Args,
        slf: ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        env.subscribe::<Arc<ts_control::StateUpdate>>(&slf).await?;
        env.subscribe::<PeerDiscoKeyAdvertisement>(&slf).await?;
        env.subscribe::<DiscoKeyObserved>(&slf).await?;

        // Re-filter the peer db whenever the enforcement authority changes. Go gets this for free:
        // `SetControlClientStatus` runs `tkaSyncIfNeeded` and `tkaFilterNetmapLocked` back to back
        // over one netmap. Here the sync is asynchronous, so the peers admitted before the authority
        // arrived need a second pass — see `tka_reevaluate_peer_db`. `changed()` resolves on every
        // write to the cell (enable, re-sync, disable); the task ends when the control runner drops
        // the sender (shutdown) or the tracker itself is gone.
        //
        // A **weak** ref on purpose: the runtime holds only a `WeakActorRef` to the peer tracker, so
        // a strong one parked in this task would keep the actor's mailbox alive past shutdown.
        let mut authority_changes = tka_authority.clone();
        let notify = slf.downgrade();
        tokio::spawn(async move {
            while authority_changes.changed().await.is_ok() {
                let Some(tracker) = notify.upgrade() else {
                    break; // the peer tracker is gone; nothing left to re-filter
                };
                if tracker.tell(TkaAuthorityChanged).await.is_err() {
                    break; // the peer tracker stopped
                }
            }
        });

        let (peer_watch, _) = watch::channel(Vec::new());

        Ok(Self {
            peer_db: PeerDb::default(),
            pending_requests: Default::default(),
            seen_state_update: false,
            peer_watch,
            user_profiles: HashMap::new(),
            endpoint_disco: HashMap::new(),
            // The cell starts `None` (no lock synced ⇒ enforcement inactive, admit all, matching
            // Go's `b.tka == nil`); the control runner flips it to `Some` on the first sync.
            tka_authority,
            env,
        })
    }
}

enum Pending {
    PeerByName(PeerByName, ReplySender<Option<Node>>),
    AcceptedRoute(PeerByAcceptedRoute, ReplySender<Vec<Node>>),
    TailnetIp(PeerByTailnetIp, ReplySender<Option<Node>>),
    Status(ReplySender<Vec<(PeerId, StatusNode)>>),
    WhoIs(Whois, ReplySender<Option<crate::status::WhoIs>>),
}

// For messages with arguments, a struct is generated with the args as fields. They aren't
// documented, and we can't apply attributes directly to the fields. Hence, wrap in a module where
// docs are turned off everywhere.
#[allow(missing_docs)]
mod msg_impl {
    use std::net::IpAddr;

    use kameo::prelude::DelegatedReply;

    use super::*;

    #[kameo::messages]
    impl PeerTracker {
        /// Lookup a peer by name.
        ///
        /// Waits until we've received at least one peer update from control.
        #[message(ctx)]
        pub async fn peer_by_name(
            &mut self,
            ctx: &mut Context<Self, DelegatedReply<Option<Node>>>,
            name: String,
        ) -> DelegatedReply<Option<Node>> {
            let (deleg, sender) = ctx.reply_sender();
            let Some(sender) = sender else { return deleg };

            if !self.seen_state_update {
                tracing::debug!(query = name, "no peer state seen yet, queueing request");

                self.pending_requests
                    .push(Pending::PeerByName(PeerByName { name }, sender));

                return deleg;
            }

            sender.send(self.peer_by_name_opt(&name).cloned());

            deleg
        }

        /// Lookup all peers that accept packets addressed to the given IP.
        ///
        /// This includes the peer's tailnet address and any subnet routes it provides. Only
        /// the peers with the most specific subnet route match that covers `ip` will be
        /// returned.
        ///
        /// E.g., suppose:
        ///
        /// - We're querying for `10.1.2.3`
        /// - `PeerA` and `PeerB` have accepted routes for `10.1.2.0/24`
        /// - `PeerC` has an accepted route for `10.1.0.0/16`
        ///
        /// Only `PeerA` and `PeerB` will be returned, since they have the most specific
        /// prefix match.
        #[message(ctx)]
        pub fn peer_by_accepted_route(
            &mut self,
            ctx: &mut Context<Self, DelegatedReply<Vec<Node>>>,
            ip: IpAddr,
        ) -> DelegatedReply<Vec<Node>> {
            let (deleg, sender) = ctx.reply_sender();
            let Some(sender) = sender else { return deleg };

            if !self.seen_state_update {
                tracing::debug!(query = %ip, "no peer state seen yet, queueing request");

                self.pending_requests
                    .push(Pending::AcceptedRoute(PeerByAcceptedRoute { ip }, sender));

                return deleg;
            }

            sender.send(
                self.peer_db
                    .get_route(ip.into())
                    .map(|(_id, node)| node.clone())
                    .collect(),
            );

            deleg
        }

        /// Lookup the peer that has the given tailnet IP address.
        #[message(ctx)]
        pub fn peer_by_tailnet_ip(
            &mut self,
            ctx: &mut Context<Self, DelegatedReply<Option<Node>>>,
            ip: IpAddr,
        ) -> DelegatedReply<Option<Node>> {
            let (deleg, sender) = ctx.reply_sender();
            let Some(sender) = sender else { return deleg };

            if !self.seen_state_update {
                tracing::debug!(query = %ip, "no peer state seen yet, queueing request");

                self.pending_requests
                    .push(Pending::TailnetIp(PeerByTailnetIp { ip }, sender));

                return deleg;
            }

            sender.send(self.peer_by_tailnet_ip_opt(ip).cloned());

            deleg
        }

        /// Build the peer entries of a [`Status`](crate::Status) snapshot, each paired with its
        /// [`PeerId`] so [`Runtime::status`](crate::Runtime::status) can join per-peer connectivity
        /// (`cur_addr`/`relay`) from the direct manager before returning. The self node is *not*
        /// included here (it lives in the control runner); `Runtime::status` combines both and drops
        /// the ids.
        ///
        /// Waits until we've received at least one peer update from control.
        #[message(ctx)]
        pub fn get_status(
            &mut self,
            ctx: &mut Context<Self, DelegatedReply<Vec<(PeerId, StatusNode)>>>,
        ) -> DelegatedReply<Vec<(PeerId, StatusNode)>> {
            let (deleg, sender) = ctx.reply_sender();
            let Some(sender) = sender else { return deleg };

            if !self.seen_state_update {
                tracing::debug!("no peer state seen yet, queueing status request");
                self.pending_requests.push(Pending::Status(sender));
                return deleg;
            }

            sender.send(self.status_peers_with_ids());

            deleg
        }

        /// Return every known peer's full domain [`Node`] (not the lossy [`StatusNode`]).
        ///
        /// Used by [`Runtime::file_targets`](crate::Runtime::file_targets), which needs the full node
        /// (peerAPI address, owning user id, cap map) to compute Taildrop send targets. The self node
        /// is not included (it lives in the control runner). Returns empty before the first netmap —
        /// the natural "not connected yet" analog (an immediate answer, no queueing needed: callers
        /// that need a populated list await `Running` first).
        #[message]
        pub fn all_peers(&self) -> Vec<Node> {
            self.peer_db.peers().values().cloned().collect()
        }

        /// Resolve which node owns a tailnet source address.
        ///
        /// Maps the source IP of `addr` to the owning node via the tailnet-IP index, returning a
        /// [`WhoIs`](crate::WhoIs). The port is ignored (a tailnet IP uniquely identifies a node).
        ///
        /// The resulting [`WhoIs`](crate::WhoIs) carries no user/login or capability data: this
        /// fork's domain [`Node`] does not retain those wire fields. See the
        /// [`status`](crate::status) module docs for the gap.
        ///
        /// Waits until we've received at least one peer update from control.
        #[message(ctx)]
        pub fn whois(
            &mut self,
            ctx: &mut Context<Self, DelegatedReply<Option<crate::status::WhoIs>>>,
            addr: std::net::SocketAddr,
        ) -> DelegatedReply<Option<crate::status::WhoIs>> {
            let (deleg, sender) = ctx.reply_sender();
            let Some(sender) = sender else { return deleg };

            if !self.seen_state_update {
                tracing::debug!(query = %addr, "no peer state seen yet, queueing whois request");
                self.pending_requests
                    .push(Pending::WhoIs(Whois { addr }, sender));
                return deleg;
            }

            sender.send(self.whois_opt(addr));

            deleg
        }

        /// Subscribe to netmap peer-change events.
        ///
        /// Returns a [`watch::Receiver`] whose value is the current set of peer
        /// [`StatusNode`]s, updated on every netmap state update from control. Embedders can await
        /// changes via [`watch::Receiver::changed`] to react to peers joining, leaving, or changing.
        ///
        /// The receiver's initial value is the peer set at subscription time (empty before the
        /// first netmap update). This is a peer-only view; combine with the self node from
        /// [`Runtime::status`](crate::Runtime::status) when a full snapshot is needed.
        #[message(derive(Clone))]
        pub fn watch_netmap(&self) -> watch::Receiver<Vec<StatusNode>> {
            self.peer_watch.subscribe()
        }
    }
}

pub use msg_impl::*;

#[derive(Debug, Clone)]
pub(crate) struct PeerState {
    #[allow(unused)]
    pub deletions: HashSet<PeerId>,
    #[allow(unused)]
    pub upserts: HashSet<PeerId>,
    pub peers: Arc<PeerDb>,
}

impl Message<Arc<ts_control::StateUpdate>> for PeerTracker {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: Arc<ts_control::StateUpdate>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        // Accumulate user profiles first — control sends them incrementally and a response may
        // carry profiles with no peer delta (or peers that reference a profile from an earlier
        // response), so this must happen before the no-peer-update early return below.
        for profile in &msg.user_profiles {
            self.user_profiles.insert(profile.id, profile.clone());
        }

        // Apply the standalone online/last-seen delta maps (channels C/D, `MapResponse.OnlineChange`
        // / `PeerSeenChange`). These arrive keyed by control node id and may ride a response that
        // carries NO `peer_update` (a bare online flip is the common case), so they must be applied
        // *before* the no-peer-update early return — otherwise online status freezes at the last
        // full-node/patch value. Each entry only ever *sets* a value (never back to unknown).
        // Wall clock for a `PeerSeenChange: true` (Go uses `clock.Now()`). chrono is built without
        // its `clock` feature in this workspace, so derive it from `SystemTime` the same way the
        // control runner / ssh-policy paths do (unix secs → `DateTime::from_timestamp`).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| chrono::DateTime::from_timestamp(d.as_secs() as i64, d.subsec_nanos()))
            .unwrap_or_default();
        let liveness_changed =
            self.apply_liveness_changes(&msg.online_change, &msg.peer_seen_change, now);

        if msg.peer_update.is_none() && msg.peer_patches.is_empty() {
            // No peer set or patch this response. If a liveness delta still mutated the netmap,
            // publish the refreshed snapshot so watchers (and `GetStatus`) see the new online state.
            if liveness_changed {
                self.service_pending_requests();
                self.peer_watch.send_replace(self.status_peers());
                if let Err(e) = self
                    .env
                    .publish(Arc::new(PeerState {
                        upserts: HashSet::default(),
                        deletions: HashSet::default(),
                        peers: Arc::new(self.peer_db.clone()),
                    }))
                    .await
                {
                    tracing::error!(error = %e, "publishing liveness-only peer state update");
                }
            }
            return;
        }

        // Apply the whole-node peer set (if any) FIRST, then the field-level patches on top —
        // mirroring Go's `controlclient` order (`Peers*` then `PeersChangedPatch`). A response may
        // carry either, both, or (with a liveness-only delta) neither. Merge the upsert/deletion sets
        // so the published `PeerState` reflects every node touched by both passes; a node both
        // upserted by the set and patched stays in `upserts` (the patch removes it from `deletions`).
        let (mut upserts, mut deletions) = msg
            .peer_update
            .as_ref()
            .map(|u| self.apply_peer_update(u))
            .unwrap_or_default();

        if !msg.peer_patches.is_empty() {
            let (patch_upserts, patch_deletions) = self.apply_peer_patches(&msg.peer_patches);
            // A patch can evict a node the set just upserted (TKA rejection after key rotation), or
            // re-admit/patch one not in the set — reconcile so each id lands in exactly one set.
            for id in &patch_upserts {
                deletions.remove(id);
            }
            for id in &patch_deletions {
                upserts.remove(id);
            }
            upserts.extend(patch_upserts);
            deletions.extend(patch_deletions);
        }

        tracing::debug!(
            n_upsert = upserts.len(),
            n_delete = deletions.len(),
            peer_count = self.peer_db.peers().len(),
            "new peer state"
        );

        self.service_pending_requests();

        // Publish the latest peer snapshot to netmap watchers. `send_replace` keeps the receiver's
        // value current even when there are no subscribers, so a late subscriber sees fresh state.
        self.peer_watch.send_replace(self.status_peers());

        if let Err(e) = self
            .env
            .publish(Arc::new(PeerState {
                upserts,
                deletions,
                peers: Arc::new(self.peer_db.clone()),
            }))
            .await
        {
            tracing::error!(error = %e, "publishing peer state update");
        }
    }
}

impl Message<PeerDiscoKeyAdvertisement> for PeerTracker {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: PeerDiscoKeyAdvertisement,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        if !self.learn_disco_key(msg.peer, msg.key) {
            return;
        }

        // The key changed, so republish: the direct-path machinery resolves a peer's disco key out
        // of the published `PeerState` snapshot (`direct::DiscoPeerLookup`), which is the whole
        // point of learning it — it is what lets disco reach this peer without waiting for a
        // netmap update. Go does the equivalent by writing the key straight into the magicsock
        // endpoint and re-keying its peer map.
        self.peer_watch.send_replace(self.status_peers());

        if let Err(e) = self
            .env
            .publish(Arc::new(PeerState {
                upserts: HashSet::from_iter([msg.peer]),
                deletions: HashSet::default(),
                peers: Arc::new(self.peer_db.clone()),
            }))
            .await
        {
            tracing::error!(error = %e, "publishing peer state after a TSMP disco-key advertisement");
        }
    }
}

impl Message<DiscoKeyObserved> for PeerTracker {
    type Reply = ();

    async fn handle(&mut self, msg: DiscoKeyObserved, _ctx: &mut Context<Self, Self::Reply>) {
        if !self.observe_disco_key(msg.peer, msg.key) {
            return;
        }

        // The active key moved, so republish. This is the *same* channel a TSMP advertisement and a
        // netmap disco-key change use, and it is what makes the direct manager invalidate the
        // trusted path built under the old key: it diffs consecutive snapshots
        // (`direct::disco_key_rotations`) and calls `MagicSock::changed_active_disco` — this fork's
        // `endpoint.changedActiveDiscoLocked`, which Go likewise reaches from
        // `checkAndUpdateDiscoKey`. Keeping the switch and the invalidation on one path is why the
        // switch is done here rather than on the packet path that spotted it.
        self.peer_watch.send_replace(self.status_peers());

        if let Err(e) = self
            .env
            .publish(Arc::new(PeerState {
                upserts: HashSet::from_iter([msg.peer]),
                deletions: HashSet::default(),
                peers: Arc::new(self.peer_db.clone()),
            }))
            .await
        {
            tracing::error!(error = %e, "publishing peer state after a disco active-key switch");
        }
    }
}

/// Internal self-message: the Tailnet-Lock enforcement-authority cell changed — the control runner
/// installed a freshly-synced [`Authority`](ts_tka::Authority) after a `/machine/tka/sync`, or
/// cleared it because the lock was disabled. Sent by the watch task
/// [`on_start`](kameo::Actor::on_start) spawns, so the peer db is re-filtered the moment enforcement
/// changes instead of at whatever later `Full` netmap happens to arrive.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TkaAuthorityChanged;

impl Message<TkaAuthorityChanged> for PeerTracker {
    type Reply = ();

    async fn handle(&mut self, _msg: TkaAuthorityChanged, _ctx: &mut Context<Self, Self::Reply>) {
        let deletions = self.tka_reevaluate_peer_db();
        if deletions.is_empty() {
            // The common case: enforcement is inactive, or every admitted peer still verifies.
            return;
        }

        // An evicted peer must lose its data path, not just its db row, so republish the snapshot
        // the `Arc<PeerState>` subscribers (route updater, source filter, dataplane) resolve
        // against — the same publish the netmap handler does after a peer set changes.
        self.peer_watch.send_replace(self.status_peers());

        if let Err(e) = self
            .env
            .publish(Arc::new(PeerState {
                upserts: HashSet::default(),
                deletions,
                peers: Arc::new(self.peer_db.clone()),
            }))
            .await
        {
            tracing::error!(error = %e, "publishing peer state after a TKA authority change");
        }
    }
}

/// Ask the peer tracker to re-broadcast its current peer snapshot on the bus, without any peer
/// change. Sent after a runtime preference change so the route updater and source filter (both
/// `Arc<PeerState>` subscribers) re-resolve against the new value immediately, rather than waiting
/// for the next netmap update: `Device::set_exit_node` (new exit-node selector) and
/// `Device::set_accept_routes` (new accept-routes flag) both send it.
#[derive(Debug, Clone, Copy)]
pub struct RepublishState;

impl Message<RepublishState> for PeerTracker {
    type Reply = ();

    async fn handle(&mut self, _msg: RepublishState, _ctx: &mut Context<Self, Self::Reply>) {
        // An empty upsert/deletion set: this is a re-broadcast of the unchanged peer set, not a
        // delta. Subscribers recompute their routes/filters against the current peers and the
        // (just-updated) runtime preferences (exit-node selector, accept-routes flag).
        if let Err(e) = self
            .env
            .publish(Arc::new(PeerState {
                upserts: HashSet::default(),
                deletions: HashSet::default(),
                peers: Arc::new(self.peer_db.clone()),
            }))
            .await
        {
            tracing::error!(error = %e, "re-publishing peer state after a runtime preference change");
        }
    }
}

impl PeerTracker {
    /// Learn a peer's disco key from a TSMP disco-key advertisement, returning whether the
    /// advertisement was applied.
    ///
    /// Go [`magicsock.Conn.HandleDiscoKeyAdvertisement`], reduced to the state this fork keeps:
    /// Go stores the learned key on the magicsock endpoint and re-keys its peer map, whereas here
    /// the peer db's `disco_key` (and its disco index) *is* the live lookup every direct-path
    /// consumer reads. The key is recorded in the peer's [`EndpointDisco`] TSMP slot — never on top
    /// of control's — and the peer db then carries whichever of the two is active, so the next
    /// netmap cannot silently undo it ([`upsert_from_control`](Self::upsert_from_control)).
    ///
    /// The three refusals are Go's, in Go's order:
    ///
    /// 1. **A zero key is never learned.** Go checks it twice — `tstun` publishes only
    ///    `if !Key.IsZero()`, and `HandleDiscoKeyAdvertisement` rejects it again. The dataplane
    ///    already dropped it here too; this is the second check, kept because the cost of getting
    ///    it wrong is a peer bound to an unusable key.
    /// 2. **An unknown peer is ignored** (Go: "endpoint not found for node"). An advertisement
    ///    never creates a peer — only control does — so one that arrives before or after the
    ///    peer's netmap entry is a no-op, exactly like a `PeersChangedPatch` for an unknown node.
    /// 3. **An unchanged key is a no-op**, so a peer re-advertising the key we already hold costs
    ///    no upsert and no republish (Go counts this as
    ///    `magicsock_tsmp_disco_key_advertisement_unchanged` and returns). "Unchanged" is measured
    ///    against the **TSMP-learned** key (Go compares `epDisco.keyFromTSMP()`), NOT against the
    ///    effective one: an advertisement that merely restates what control already told us is new
    ///    information — it is the peer itself confirming the key — so it is recorded as the active
    ///    TSMP key and survives control later dropping or contradicting it.
    ///
    /// The tailnet-lock gate is deliberately *not* re-run: unlike a `PeersChangedPatch`, an
    /// advertisement cannot touch the node key or its TKA signature — only the disco key — so the
    /// peer-trust decision that admitted this node is unchanged by definition.
    ///
    /// [`magicsock.Conn.HandleDiscoKeyAdvertisement`]: https://github.com/tailscale/tailscale/blob/49e148c4a30b4f8098f69468fd27a7021d85ea02/wgengine/magicsock/magicsock.go
    fn learn_disco_key(&mut self, peer: PeerId, key: DiscoPublicKey) -> bool {
        if disco_key_is_zero(&key) {
            tracing::debug!(?peer, "TSMP-advertised disco key is the zero key; ignoring");
            return false;
        }

        let Some((_id, existing)) = self.peer_db.get(&peer) else {
            tracing::debug!(
                ?peer,
                "TSMP disco-key advertisement for unknown peer; ignoring"
            );
            return false;
        };

        let node_key = existing.node_key;
        if self
            .endpoint_disco
            .get(&node_key)
            .and_then(EndpointDisco::key_from_tsmp)
            == Some(key)
        {
            tracing::trace!(?peer, "TSMP-advertised disco key is unchanged");
            return false;
        }

        let node = existing.clone();
        let disco = self.endpoint_disco.entry(node_key).or_default();
        disco.update_from_tsmp(Some(key));
        let disco = *disco;
        self.store_disco(&node, disco);

        tracing::info!(
            ?peer,
            stable_id = ?node.stable_id,
            %key,
            "learned peer disco key from a TSMP advertisement"
        );

        true
    }

    /// Write a peer's resolved disco state onto the peer db.
    ///
    /// The node lands carrying the **effective** key ([`EndpointDisco::key`]), which is what the
    /// disco index — and so every *send* path — resolves against, and the peer's other known key
    /// (if any) is registered as its inactive ingress key so a frame arriving under it still
    /// attributes to this peer ([`PeerDb::peer_by_known_disco_key`]).
    ///
    /// Every disco-key writer goes through here — control, a TSMP advertisement, and an
    /// active-slot switch on receive — so the two cannot drift apart on which key is which.
    fn store_disco(&mut self, node: &Node, disco: EndpointDisco) -> PeerId {
        let effective = disco.key();

        let id = if effective == node.disco_key {
            self.peer_db.upsert(node)
        } else {
            let mut node = node.clone();
            node.disco_key = effective;
            self.peer_db.upsert(&node)
        };

        self.peer_db
            .set_inactive_disco_key(id, disco.inactive_key());

        id
    }

    /// Apply the sender key of an inbound disco frame to this peer's two-slot disco state — the
    /// `ts_runtime` half of Go [`endpoint.checkAndUpdateDiscoKey`].
    ///
    /// A peer mid-rotation keeps sending disco under the key it has not yet switched away from.
    /// Upstream accepts either of the two keys it knows for the peer and, when the one received is
    /// the currently-inactive one, makes it active: receiving under a key is proof of what the peer
    /// is using, and is stronger evidence than what control last said. Without this a rotation
    /// costs the peer its direct path until control catches up or the peer re-advertises.
    ///
    /// Returns whether the active key changed, so the caller can republish — which is how the
    /// direct manager learns to invalidate the trusted path built under the old key (Go's
    /// `changedActiveDiscoLocked`, reached here through the same snapshot diff every other
    /// disco-key transition uses).
    ///
    /// The refusals, all of which leave the peer db untouched:
    ///
    /// 1. **An unknown peer**, exactly as for a TSMP advertisement.
    /// 2. **A peer with no disco key material at all** (Go: `epDisco == nil` ⇒ `false`).
    /// 3. **A key belonging to neither slot.** This is the one that carries the security value:
    ///    a peer must not be able to move itself onto a key nobody told us about, so a third key
    ///    is refused even though the frame that carried it opened correctly.
    ///
    /// [`endpoint.checkAndUpdateDiscoKey`]: https://github.com/tailscale/tailscale/blob/9ea7cba44591e0cd840c6c94d23274dd222059bf/wgengine/magicsock/endpoint.go
    fn observe_disco_key(&mut self, peer: PeerId, key: DiscoPublicKey) -> bool {
        let Some((_id, existing)) = self.peer_db.get(&peer) else {
            tracing::debug!(?peer, "disco received for an unknown peer; ignoring");
            return false;
        };

        let node = existing.clone();
        let Some(disco) = self.endpoint_disco.get_mut(&node.node_key) else {
            // Go's `epDisco == nil`: the peer has no key from either source, so there is nothing
            // this key could match and nothing to switch to.
            tracing::debug!(
                ?peer,
                "disco received for a peer with no known disco key; ignoring"
            );
            return false;
        };

        let Some(changed) = disco.check_and_update(key) else {
            tracing::debug!(
                ?peer,
                %key,
                "refusing disco under a key that is neither of the peer's known disco keys"
            );
            return false;
        };

        if !changed {
            return false;
        }

        let disco = *disco;
        self.store_disco(&node, disco);

        tracing::info!(
            ?peer,
            stable_id = ?node.stable_id,
            %key,
            "peer is sending disco under its other known key; making that key active"
        );

        true
    }

    /// Upsert a control-sourced [`Node`] into the peer db, resolving its disco key against anything
    /// this peer has told us over TSMP first.
    ///
    /// Every node built from control goes through here — `Full`, `Delta { upsert }`, and a
    /// `PeersChangedPatch` — so the three cannot diverge on which of the two keys wins. This is the
    /// disco half of Go [`endpoint.updateFromNode`]: control's key is written through
    /// [`EndpointDisco::update_from_control`] **only when it differs from what control last said**
    /// (Go's `if discoKey != n.DiscoKey()` guard, which compares `keyFromControl()`, never the
    /// effective key). So a netmap that merely restates the key control already sent leaves an
    /// active TSMP key alone — which is the entire point of the advertisement, whose motivating case
    /// is a peer whose key control has not caught up with. Control genuinely changing its mind is
    /// *recorded* in control's slot, but it does not take the active slot back from a TSMP-learned
    /// key: upstream switches back only when disco is received under control's key
    /// (`endpoint.checkAndUpdateDiscoKey`). See [`EndpointDisco::update_from_control`].
    ///
    /// The node lands in the db carrying the *effective* key ([`EndpointDisco::key`]), so the disco
    /// index and every send path resolve against the key we would actually send to; the other known
    /// key is registered for ingress attribution ([`store_disco`](Self::store_disco)).
    ///
    /// [`endpoint.updateFromNode`]: https://github.com/tailscale/tailscale/blob/49e148c4a30b4f8098f69468fd27a7021d85ea02/wgengine/magicsock/endpoint.go
    fn upsert_from_control(&mut self, node: &Node) -> PeerId {
        let node_key = node.node_key;
        let from_control = disco_key_from_control(node.disco_key);

        let disco = self.endpoint_disco.entry(node_key).or_default();
        if disco.key_from_control() != from_control {
            disco.update_from_control(from_control);
        }
        let disco = *disco;

        // No key material from either source: Go nils the endpoint's `disco` pointer, so a peer
        // that has never had a disco key costs us no entry either.
        if disco.is_empty() {
            self.endpoint_disco.remove(&node_key);
        }

        self.store_disco(node, disco)
    }

    /// The disco key control last gave us for `node_key` — Go `endpointDisco.keyFromControl()`.
    fn control_disco_key(&self, node_key: &NodePublicKey) -> Option<DiscoPublicKey> {
        self.endpoint_disco
            .get(node_key)
            .and_then(EndpointDisco::key_from_control)
    }

    /// Drop [`EndpointDisco`] state for node keys the peer db no longer holds.
    ///
    /// Go gets this for free: the two keys live on the magicsock `endpoint`, which the peer map keys
    /// by node key and deletes when the peer leaves the netmap — and a peer that rotates its node
    /// key gets a brand-new endpoint, so a TSMP-learned key is not carried across a rotation. Here
    /// the state is a side table, so every control update prunes it to get the same lifetime.
    fn prune_endpoint_disco(&mut self) {
        if self.endpoint_disco.is_empty() {
            return;
        }

        let peers = &self.peer_db;
        self.endpoint_disco
            .retain(|node_key, _| peers.has(node_key).is_some());
    }

    /// Apply a single [`PeerUpdate`](ts_control::PeerUpdate) to the peer db, enforcing the
    /// Tailnet-Lock peer-trust chokepoint ([`tka_admits`](Self::tka_admits)) at every upsert site.
    ///
    /// This is the **single source of truth** for the peer-trust enforcement loop: the actor's
    /// netmap [`handle`](Message::handle) calls it, and so do the TKA enforcement tests, so the two
    /// real upsert sites (`Full` and `Delta { upsert }`) cannot diverge from what is tested.
    ///
    /// Returns `(upserts, deletions)` — the [`PeerId`]s touched — for downstream bookkeeping.
    fn apply_peer_update(
        &mut self,
        peer_update: &ts_control::PeerUpdate,
    ) -> (HashSet<PeerId>, HashSet<PeerId>) {
        let mut upserts = HashSet::default();
        let mut deletions = HashSet::default();

        match peer_update {
            ts_control::PeerUpdate::Full(new_nodes) => {
                tracing::trace!("full peer update");

                // Borrow the authority ONCE for the whole batch and verify each peer EXACTLY once
                // (Go runs `tkaFilterNetmapLocked` once over the assembled netmap; an earlier draft
                // verified every peer twice — once for `retained_ids`, once in the upsert loop —
                // doubling the ed25519 cost on the hot resync path). `tka_keep_verdicts` is that one
                // pass — per-peer signature verdict AND the cross-peer rotation filter — and is
                // shared verbatim with `tka_reevaluate_peer_db`, so the netmap path and the
                // authority-install path cannot drift apart on what "admitted" means.
                //
                // The result is a per-NODE keep vector (not a stable_id set), which drives both the
                // `retain` (evict revoked peers, keyed by stable_id) and the upsert loop. Judging
                // each node by its own verdict means a node whose signature fails is never admitted
                // on the strength of a different node that happens to share its stable_id.
                //
                // Revocation evicts: a peer re-included with a now-invalid/missing signature under an
                // active authority fails its verdict, so it is excluded from `retained_ids` and
                // `retain` drops the stale (previously-admitted) entry. With no authority the snapshot
                // is `None`, so every node passes — byte-for-byte the pre-TKA behavior (no regression).
                let authority = self.tka_authority_snapshot();
                let node_refs = new_nodes.iter().collect::<Vec<&Node>>();
                let keep = Self::tka_keep_verdicts(authority.as_deref(), &node_refs);

                // `retained_ids` is the set of stable_ids that survive (drives `retain` to evict the
                // rest). It must agree with what the upsert loop below will leave in the db. Control
                // should never send two distinct nodes with the same `stable_id` in one `Full`, but if
                // it does, `peer_db.upsert` is last-writer-wins on `stable_id`, so the db ends holding
                // the LAST kept node for that id. Build `retained_ids` from kept nodes only — a
                // stable_id is retained iff at least one of its (possibly duplicate) nodes is kept, so
                // the upsert loop's last-kept node lands and `retain` never evicts a just-upserted id.
                let retained_ids = new_nodes
                    .iter()
                    .zip(keep.iter().copied())
                    .filter(|(_, k)| *k)
                    .map(|(node, _)| &node.stable_id)
                    .collect::<HashSet<_>>();

                // Isolation diagnostic: an ACTIVE lock that authorized none of the offered peers
                // leaves this node with no peers — surface it loudly so a self-lockout (vs an attack)
                // is diagnosable. `authority.is_some()` means a real keyed lock (the empty-keyset
                // brick-guard admits-all, so it never reaches here with zero retained).
                if authority.is_some() && !new_nodes.is_empty() && retained_ids.is_empty() {
                    tracing::error!(
                        offered = new_nodes.len(),
                        "TKA: active lock authorized ZERO of the offered peers; node is isolated \
                         (verify the lock state, or disable tailnet lock to recover)"
                    );
                }

                self.peer_db.retain(|id, peer| {
                    let retain = retained_ids.contains(&peer.stable_id);

                    if !retain {
                        deletions.insert(id);
                    }

                    retain
                });

                for (node, k) in new_nodes.iter().zip(keep.iter().copied()) {
                    if !k {
                        continue; // fail-CLOSED: rejected by tailnet lock or rotation-obsolete (above)
                    }
                    let peer_id = self.upsert_from_control(node);
                    upserts.insert(peer_id);
                }
            }

            ts_control::PeerUpdate::Delta { remove, upsert } => {
                tracing::trace!("delta peer update");

                for peer in upsert {
                    if !self.tka_admits(peer) {
                        // fail-CLOSED: do not upsert a peer rejected by tailnet lock. If the peer is
                        // ALREADY in the db (a delta re-upserting an existing peer whose signature is
                        // now invalid — e.g. revoked between syncs), evict the stale entry rather than
                        // leaving an unverified peer admitted; Go re-filters the whole netmap each map
                        // response, so a now-unsigned peer would not survive there either.
                        if let Some((id, _)) = self.peer_db.remove(&peer.stable_id) {
                            tracing::warn!(
                                stable_id = ?peer.stable_id,
                                "TKA: delta re-upsert rejected; evicting now-unauthorized peer"
                            );
                            deletions.insert(id);
                        }
                        continue;
                    }
                    let id = self.upsert_from_control(peer);

                    upserts.insert(id);
                }

                for peer in remove {
                    let Some((id, _node)) = self.peer_db.remove(peer) else {
                        // A benign, expected race: the peer may already be gone (dropped in a prior
                        // `Full`, or fail-closed by TKA — whose now-"unknown" ids commonly reappear in
                        // a trailing `peers_removed`). Go treats an unknown removal as a no-op; log at
                        // debug, not error, to avoid false-alarm noise on a healthy node (matches the
                        // unknown-node handling in `apply_peer_patches`).
                        tracing::debug!(
                            control_node_id = peer,
                            "removed peer was unknown; ignoring"
                        );
                        continue;
                    };

                    deletions.insert(id);
                }
            }
        }

        self.prune_endpoint_disco();

        (upserts, deletions)
    }

    /// Re-run the Tailnet-Lock filter over the peers **already in the peer db**, evicting the ones
    /// the current authority does not admit. Returns the evicted [`PeerId`]s (empty when nothing
    /// changed, which is the overwhelmingly common case).
    ///
    /// # Why this exists (a Go-ordering gap, not an extra feature)
    /// Go filters the very netmap that announced the lock: `SetControlClientStatus`
    /// (`ipn/ipnlocal/local.go`, v1.100.0) calls `tkaSyncIfNeeded` and then, a few lines later,
    /// `tkaFilterNetmapLocked(st.NetMap)` — synchronously, on the same `st.NetMap`, in one pass. So
    /// the peers announced alongside `TKAEnabled` are checked by the authority that sync just built.
    ///
    /// Here the sync is a spawned task (`control_runner`'s `maybe_sync_tka`), so the ordering is
    /// inverted: the netmap that carried the `TkaStatus` reaches the peer db *before* the authority
    /// exists, and is admitted with enforcement inactive. Without this pass those peers stay
    /// admitted — unauthorized ones included — until control happens to send another `Full`, which on
    /// a steady map poll may be never. That is the whole initial peer set escaping a lock the node
    /// really did sync, so this runs the moment the authority is installed ([`TkaAuthorityChanged`])
    /// and brings the db back in line.
    ///
    /// No authority (nothing synced yet, or the lock was disabled) ⇒ no eviction: enforcement is
    /// inactive and every peer is admitted, exactly Go's `b.tka == nil` early return. A peer dropped
    /// while the lock was active is **not** resurrected by a later disable — the db no longer holds
    /// it and this fork keeps no shadow copy of filtered nodes (Go's `b.tka.filtered`); it returns on
    /// the next netmap that re-includes it. That is the safe direction: more restrictive, and
    /// connectivity-only.
    fn tka_reevaluate_peer_db(&mut self) -> HashSet<PeerId> {
        let Some(authority) = self.tka_authority_snapshot() else {
            return HashSet::default();
        };

        // Verdicts first, under an immutable borrow of the db; the eviction below needs `&mut`.
        let evicted: HashSet<PeerId> = {
            let entries = self
                .peer_db
                .peers()
                .iter()
                .map(|(id, node)| (*id, node))
                .collect::<Vec<(PeerId, &Node)>>();
            let nodes = entries
                .iter()
                .map(|(_, node)| *node)
                .collect::<Vec<&Node>>();
            let keep = Self::tka_keep_verdicts(Some(&authority), &nodes);
            entries
                .iter()
                .zip(keep)
                .filter_map(|((id, _), keep)| (!keep).then_some(*id))
                .collect()
        };

        if evicted.is_empty() {
            return evicted;
        }

        tracing::warn!(
            n_evicted = evicted.len(),
            peer_count = self.peer_db.peers().len(),
            "TKA: re-filtered the peer db against the newly installed lock authority; evicted \
             already-admitted peers"
        );
        self.peer_db.retain(|id, _| !evicted.contains(&id));
        self.prune_endpoint_disco();
        evicted
    }

    /// Apply field-level peer patches (`MapResponse.PeersChangedPatch`), returning the upserted /
    /// deleted [`PeerId`]s.
    ///
    /// This is a SEPARATE channel from [`apply_peer_update`](Self::apply_peer_update): Go's
    /// `controlclient` applies the whole-node `Peers*` set first and then `PeersChangedPatch`, so a
    /// response that carries both has the peer set applied first (by the caller) and these patches
    /// applied second, on top of the freshly-synced nodes. A patch only mutates a peer already in the
    /// netmap; an unknown node id is ignored (the wire contract — a patch never creates a node).
    fn apply_peer_patches(
        &mut self,
        patches: &[ts_control::PeerChange],
    ) -> (HashSet<PeerId>, HashSet<PeerId>) {
        let mut upserts = HashSet::default();
        let mut deletions = HashSet::default();

        tracing::trace!(n = patches.len(), "peer patch update");

        for patch in patches {
            // Clone the current node, apply the present fields, and re-upsert through the same path
            // as a delta so indexes/routes stay consistent.
            let Some((_id, existing)) = self.peer_db.get(&patch.id) else {
                tracing::debug!(
                    control_node_id = patch.id,
                    "peer patch for unknown node; ignoring"
                );
                continue;
            };

            let mut node = existing.clone();
            if let Some(endpoints) = &patch.underlay_addresses {
                node.underlay_addresses = endpoints.clone();
            }
            if let Some(derp) = patch.derp_region {
                node.derp_region = Some(derp);
            }
            if let Some(cap) = patch.cap {
                node.cap = cap;
            }
            if let Some(cap_map) = &patch.cap_map {
                node.cap_map = cap_map.clone();
            }
            // The db entry carries the EFFECTIVE disco key, which may have been learned over TSMP,
            // so restate what CONTROL last said before folding the patch in. Otherwise a patch that
            // says nothing about the disco key would hand a TSMP-learned key back as if control had
            // sent it, and `upsert_from_control` would write it into control's slot — losing the key
            // control actually gave us, on a patch that never mentioned the disco key at all.
            node.disco_key = self.control_disco_key(&node.node_key);
            if let Some(disco_key) = patch.disco_key {
                node.disco_key = Some(disco_key);
            }
            if let Some(expiry) = patch.node_key_expiry {
                node.node_key_expiry = Some(expiry);
            }
            // Online/last-seen liveness deltas (`PeerChange.Online`/`LastSeen`) — the dominant
            // channel by which peer online transitions arrive mid-session. A patch only ever *sets*
            // a value (never patches back to unknown), so apply when present.
            if let Some(online) = patch.online {
                node.online = Some(online);
            }
            if let Some(last_seen) = patch.last_seen {
                node.last_seen = Some(last_seen);
            }
            // Key rotation: a patch may swap the node key (and its TKA signature). Apply both
            // together so the trust gate below verifies the new signature against the new key, never
            // a mismatched pair.
            if let Some(node_key) = patch.node_key {
                node.node_key = node_key;
            }
            if let Some(sig) = &patch.key_signature {
                node.key_signature = sig.clone();
            }

            // Re-run the tailnet-lock gate on the patched node: a patch that rotates the key must
            // satisfy the active authority, exactly like a `Delta` upsert, or it would be a
            // trust-enforcement bypass. fail-CLOSED — if the patched node is no longer admitted,
            // evict it rather than keep the stale (now-unverified) entry.
            if !self.tka_admits(&node) {
                if let Some((id, _)) = self.peer_db.remove(&patch.id) {
                    tracing::warn!(
                        control_node_id = patch.id,
                        "peer patch rejected by tailnet lock; evicting peer"
                    );
                    deletions.insert(id);
                }
                continue;
            }

            let id = self.upsert_from_control(&node);
            upserts.insert(id);
        }

        self.prune_endpoint_disco();

        (upserts, deletions)
    }

    /// Apply the standalone online/last-seen delta maps (`MapResponse.OnlineChange` /
    /// `PeerSeenChange`, channels C/D) onto the retained netmap. Returns `true` if any node was
    /// actually mutated (so the caller knows whether to re-publish).
    ///
    /// Mirrors Go `controlclient/map.go:updatePeersStateFromResponse` (the two channels are
    /// semantically DISTINCT and must not be conflated):
    /// - `OnlineChange` (channel C) is the sole driver of a peer's `online` flag (`mut.Online = v`).
    /// - `PeerSeenChange` (channel D) is the sole driver of `last_seen`: `true ⇒ LastSeen = now`,
    ///   `false ⇒ LastSeen = nil` (cleared). It NEVER touches `online` — "not seen recently" is not
    ///   the same as "offline", which only `OnlineChange` asserts.
    ///
    /// Each entry is keyed by control node id and applies to a peer already in the netmap; an unknown
    /// node id is ignored (these maps never create a node). `now` is the wall-clock timestamp for a
    /// `PeerSeenChange: true` (Go uses `clock.Now()`); the caller passes it so this stays a pure
    /// function of its inputs. Returns `true` if any node was actually mutated.
    fn apply_liveness_changes(
        &mut self,
        online_change: &std::collections::BTreeMap<ts_control::NodeId, bool>,
        peer_seen_change: &std::collections::BTreeMap<ts_control::NodeId, bool>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let mut changed = false;

        // Channel C — direct online flips (the only writer of `online`).
        for (&node_id, &online) in online_change {
            if let Some((_pid, existing)) = self.peer_db.get(&node_id)
                && existing.online != Some(online)
            {
                let mut node = existing.clone();
                node.online = Some(online);
                self.peer_db.upsert(&node);
                changed = true;
            }
        }

        // Channel D — peer-seen flips (the only writer of `last_seen`; never touches `online`).
        // `true` ⇒ last-seen is now; `false` ⇒ last-seen cleared (Go map.go:820-830).
        for (&node_id, &seen) in peer_seen_change {
            let new_last_seen = if seen { Some(now) } else { None };
            if let Some((_pid, existing)) = self.peer_db.get(&node_id)
                && existing.last_seen != new_last_seen
            {
                let mut node = existing.clone();
                node.last_seen = new_last_seen;
                self.peer_db.upsert(&node);
                changed = true;
            }
        }

        changed
    }

    /// Test-only constructor: build a [`PeerTracker`] with a chosen initial TKA authority without
    /// going through the actor `on_start` path. Returns the tracker plus the **`watch::Sender`** for
    /// its enforcement-authority cell, so a test can drive the exact enable/disable transitions the
    /// control runner drives at runtime (`tx.send_replace(Some(..))` ⇒ enforce, `tx.send_replace(None)`
    /// ⇒ clear). The initial `Some` exercises the fail-closed chokepoint
    /// ([`tka_admits`](Self::tka_admits)); `None` is the no-lock admit-all path. The returned sender
    /// must be kept alive for the tracker to read updated values.
    #[cfg(test)]
    fn for_test(
        env: Env,
        tka_authority: Option<ts_tka::Authority>,
    ) -> (Self, watch::Sender<Option<Arc<ts_tka::Authority>>>) {
        let (peer_watch, _) = watch::channel(Vec::new());
        let (tka_tx, tka_rx) = watch::channel(tka_authority.map(Arc::new));
        let tracker = Self {
            peer_db: PeerDb::default(),
            seen_state_update: false,
            pending_requests: Vec::new(),
            peer_watch,
            user_profiles: HashMap::new(),
            endpoint_disco: HashMap::new(),
            tka_authority: tka_rx,
            env,
        };
        (tracker, tka_tx)
    }

    fn service_pending_requests(&mut self) {
        if self.seen_state_update {
            return;
        }

        self.seen_state_update = true;

        if !self.pending_requests.is_empty() {
            tracing::debug!(
                n_pending = self.pending_requests.len(),
                "state update received, servicing pending requests"
            );
        }

        for req in core::mem::take(&mut self.pending_requests) {
            match req {
                Pending::PeerByName(PeerByName { name }, reply) => {
                    reply.send(self.peer_by_name_opt(&name).cloned());
                }
                Pending::TailnetIp(PeerByTailnetIp { ip }, reply) => {
                    reply.send(self.peer_by_tailnet_ip_opt(ip).cloned());
                }
                Pending::AcceptedRoute(PeerByAcceptedRoute { ip }, reply) => {
                    reply.send(
                        self.peer_db
                            .get_route(ip.into())
                            .map(|(_id, node)| node.clone())
                            .collect(),
                    );
                }
                Pending::Status(reply) => {
                    reply.send(self.status_peers_with_ids());
                }
                Pending::WhoIs(Whois { addr }, reply) => {
                    reply.send(self.whois_opt(addr));
                }
            }
        }
    }
}

#[cfg(test)]
mod tka_tests {
    //! Tailnet-Lock (TKA) enforcement tests for the peer-trust chokepoint.
    //!
    //! These exercise [`PeerTracker::tka_admits`] and the `tka_admits ⇒ upsert` loop the netmap
    //! handler runs. The test [`ts_tka::Authority`] is built with [`ts_tka::Authority::from_state`]
    //! over a known Ed25519 trusted key, and the signed node-key signature CBOR is produced through
    //! `ts_tka`'s public `cbor` encoder + `aum_hash` (the exact same canonical bytes `ts_tka`'s own
    //! `direct_signature_verifies_end_to_end` test signs, with no new crypto vectors invented and no
    //! private `ts_tka` API used).

    use ed25519_dalek::{Signer, SigningKey};
    use ts_control::{Node, StableNodeId, TailnetAddress};
    use ts_tka::{
        AumHash, Authority, Key, KeyKind, State,
        cbor::{self, Value},
    };

    use super::*;

    /// `SigKind::Direct` wire value (Go `SigKind`; `ts_tka::SigKind::Direct = 1`).
    const SIG_KIND_DIRECT: u64 = 1;

    /// The 32-byte node key used across the signed-peer fixtures.
    const NODE_KEY_BYTES: [u8; 32] = [7u8; 32];

    /// Build a real [`Env`] for the tracker. Only the bus/keys/shutdown plumbing matters here; the
    /// TKA gate reads neither, so the forwarding preferences are all benign defaults.
    pub(super) fn test_env() -> Env {
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        Env::new(
            ts_keys::NodeState::generate(),
            shutdown_rx,
            crate::env::ForwarderConfig {
                accept_routes: false,
                accept_dns: true,
                exit_node: None,
                forward_routes: Vec::new(),
                forward_tcp_ports: Vec::new(),
                forward_udp_ports: Vec::new(),
                forward_all_ports: false,
                forward_exit_egress: false,
                block_incoming: false,
                exit_proxy: None,
                peerapi_port: None,
                taildrop_dir: None,
                enable_ipv6: false,
                wireguard_listen_port: None,
                network_monitor: false,
                persistent_keepalive_interval: None,
                ingress_active: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            },
        )
    }

    /// A minimal peer [`Node`] carrying `node_key` and the given `key_signature`.
    pub(super) fn peer_node(stable_id: &str, node_key: [u8; 32], key_signature: Vec<u8>) -> Node {
        Node {
            id: 1,
            stable_id: StableNodeId(stable_id.to_string()),
            hostname: stable_id.to_string(),
            user_id: 0,
            tailnet: Some("ts.net".to_string()),
            tags: Vec::new(),
            addresses: vec![
                "100.64.0.1/32".parse().unwrap(),
                "fd7a:115c:a1e0::1/128".parse().unwrap(),
            ],
            tailnet_address: TailnetAddress {
                ipv4: "100.64.0.1/32".parse().unwrap(),
                ipv6: "fd7a:115c:a1e0::1/128".parse().unwrap(),
            },
            node_key: node_key.into(),
            node_key_expiry: None,
            online: None,
            last_seen: None,
            key_signature,
            machine_key: None,
            disco_key: None,
            accepted_routes: Vec::new(),
            underlay_addresses: Vec::new(),
            derp_region: None,
            cap: Default::default(),
            cap_map: Default::default(),
            peerapi_port: None,
            peerapi_dns_proxy: false,
            is_wireguard_only: false,
            exit_node_dns_resolvers: Vec::new(),
            peer_relay: false,
            ssh_host_keys: Vec::new(),
            service_vips: Default::default(),
            unsigned_peer_api_only: false,
        }
    }

    /// Encode a `Direct` [`ts_tka::NodeKeySignature`] CBOR exactly as `ts_tka`'s private `to_cbor`
    /// does (int-map keys: 1=kind, 2=pubkey, 3=key_id, 4=signature; empty byte fields omitted),
    /// using only the crate's *public* `cbor` encoder. `signature` of `None` produces the
    /// signing-digest preimage (the `SigHash` form).
    fn direct_sig_cbor(node_key: &[u8], key_id: &[u8], signature: Option<&[u8]>) -> Vec<u8> {
        let mut pairs = alloc_pairs(node_key, key_id);
        if let Some(sig) = signature {
            pairs.push((4, Some(Value::Bytes(sig.to_vec()))));
        }
        cbor::int_map(pairs).to_vec()
    }

    fn alloc_pairs(node_key: &[u8], key_id: &[u8]) -> Vec<(u64, Option<Value>)> {
        vec![
            (1, Some(Value::Uint(SIG_KIND_DIRECT))),
            (2, Some(Value::Bytes(node_key.to_vec()))),
            (3, Some(Value::Bytes(key_id.to_vec()))),
        ]
    }

    /// Build a TKA [`Authority`] that trusts `signing.verifying_key()`, plus a valid `Direct`
    /// node-key signature CBOR authorizing [`NODE_KEY_BYTES`] under it.
    fn authority_and_valid_sig() -> (Authority, Vec<u8>) {
        // A fixed, known Ed25519 trusted key (mirrors ts_tka's own end-to-end test seed).
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let trusted_pub = signing.verifying_key().to_bytes().to_vec();

        let authority = Authority::from_state(
            AumHash([0; 32]),
            State {
                keys: vec![Key {
                    kind: KeyKind::Ed25519,
                    votes: 1,
                    public: trusted_pub.clone(),
                }],
            },
        );

        // SigHash preimage = canonical CBOR with the signature field omitted; sign its blake2s hash.
        let preimage = direct_sig_cbor(&NODE_KEY_BYTES, &trusted_pub, None);
        let sig_hash = ts_tka::aum_hash(&preimage).0;
        let signature = signing.sign(&sig_hash).to_bytes().to_vec();

        let signed_cbor = direct_sig_cbor(&NODE_KEY_BYTES, &trusted_pub, Some(&signature));
        // Sanity: the authority accepts the signature we just built (same path the gate uses).
        assert!(
            authority
                .node_key_authorized(&NODE_KEY_BYTES, &signed_cbor)
                .is_ok()
        );

        (authority, signed_cbor)
    }

    #[tokio::test]
    async fn tka_inactive_upserts_all_peers() {
        // No authority ⇒ enforcement inactive ⇒ both a signed and an unsigned peer are admitted.
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), None);

        let signed = peer_node("signed", [1u8; 32], vec![0xde, 0xad, 0xbe, 0xef]);
        let unsigned = peer_node("unsigned", [2u8; 32], vec![]);

        assert!(tracker.tka_admits(&signed));
        assert!(tracker.tka_admits(&unsigned));

        tracker.peer_db.upsert(&signed);
        tracker.peer_db.upsert(&unsigned);
        assert_eq!(tracker.peer_db.peers().len(), 2);
    }

    #[tokio::test]
    async fn tka_active_rejects_unsigned_peer() {
        // Authority present + peer presents no signature ⇒ rejected (fail-closed), not in peer_db.
        let (authority, _sig) = authority_and_valid_sig();
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), Some(authority));

        let unsigned = peer_node("unsigned", NODE_KEY_BYTES, vec![]);
        assert!(!tracker.tka_admits(&unsigned));

        // Mirror the handler's `if !tka_admits { continue }` loop.
        if tracker.tka_admits(&unsigned) {
            tracker.peer_db.upsert(&unsigned);
        }
        assert_eq!(tracker.peer_db.peers().len(), 0);
        assert!(tracker.peer_db.get(&unsigned.node_key).is_none());
    }

    #[tokio::test]
    async fn tka_active_rejects_bad_signature() {
        // Authority present + a signature that fails to verify ⇒ rejected, not in peer_db.
        let (authority, mut sig) = authority_and_valid_sig();
        // Tamper the last byte (the trailing signature byte) so verification fails.
        let last = sig.len() - 1;
        sig[last] ^= 0xff;

        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), Some(authority));
        let bad = peer_node("bad", NODE_KEY_BYTES, sig);
        assert!(!tracker.tka_admits(&bad));

        if tracker.tka_admits(&bad) {
            tracker.peer_db.upsert(&bad);
        }
        assert_eq!(tracker.peer_db.peers().len(), 0);
    }

    #[tokio::test]
    async fn tka_active_admits_authorized_peer() {
        // Authority present + correctly-signed node key ⇒ admitted and upserted.
        let (authority, sig) = authority_and_valid_sig();
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), Some(authority));

        let good = peer_node("good", NODE_KEY_BYTES, sig);
        assert!(tracker.tka_admits(&good));

        if tracker.tka_admits(&good) {
            tracker.peer_db.upsert(&good);
        }
        assert_eq!(tracker.peer_db.peers().len(), 1);
        assert!(tracker.peer_db.get(&good.node_key).is_some());
    }

    // ---------------------------------------------------------------------------------------------
    // Tests that drive REAL `PeerUpdate`s through the shared handler body
    // ([`PeerTracker::apply_peer_update`], the single source of truth the actor's netmap `handle`
    // also calls), so the two real upsert sites (`Full` and `Delta { upsert }`) are exercised via
    // the actual enforcement path — not by hand-mirroring `if !tka_admits { continue }`.
    // ---------------------------------------------------------------------------------------------

    #[tokio::test]
    async fn tka_active_delta_upsert_rejects_unauthorized() {
        // Drive a real `Delta { upsert }` whose peer carries no signature. The Delta upsert site
        // must reject it under an active authority ⇒ not present in peer_db after the handler runs.
        let (authority, _sig) = authority_and_valid_sig();
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), Some(authority));

        let unsigned = peer_node("unsigned", NODE_KEY_BYTES, vec![]);
        let update = ts_control::PeerUpdate::Delta {
            upsert: vec![unsigned.clone()],
            remove: Vec::new(),
        };

        tracker.apply_peer_update(&update);

        assert_eq!(tracker.peer_db.peers().len(), 0);
        assert!(tracker.peer_db.get(&unsigned.node_key).is_none());
    }

    #[tokio::test]
    async fn tka_active_delta_upsert_admits_authorized() {
        // Drive a real `Delta { upsert }` with a correctly-signed peer ⇒ present in peer_db.
        let (authority, sig) = authority_and_valid_sig();
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), Some(authority));

        let good = peer_node("good", NODE_KEY_BYTES, sig);
        let update = ts_control::PeerUpdate::Delta {
            upsert: vec![good.clone()],
            remove: Vec::new(),
        };

        tracker.apply_peer_update(&update);

        assert_eq!(tracker.peer_db.peers().len(), 1);
        assert!(tracker.peer_db.get(&good.node_key).is_some());
    }

    #[tokio::test]
    async fn tka_active_full_admits_only_authorized_in_mixed_batch() {
        // Drive a real `Full` carrying a MIX of authorized + unauthorized peers. Only the
        // correctly-signed peer survives the Full upsert site; the unsigned and bad-sig peers are
        // dropped fail-closed.
        let (authority, sig) = authority_and_valid_sig();
        // A bad-sig variant of the same authorized signature (tamper the trailing byte).
        let mut bad_sig = sig.clone();
        let last = bad_sig.len() - 1;
        bad_sig[last] ^= 0xff;

        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), Some(authority));

        // Only the authorized peer carries NODE_KEY_BYTES (the key the authority signed); the
        // rejected peers use distinct node keys so the survivor is unambiguous.
        let good = peer_node("good", NODE_KEY_BYTES, sig);
        let unsigned = peer_node("unsigned", [8u8; 32], vec![]);
        let bad = peer_node("bad", [9u8; 32], bad_sig);

        let update =
            ts_control::PeerUpdate::Full(vec![good.clone(), unsigned.clone(), bad.clone()]);

        tracker.apply_peer_update(&update);

        assert_eq!(tracker.peer_db.peers().len(), 1);
        assert!(tracker.peer_db.get(&good.node_key).is_some());
        assert!(tracker.peer_db.get(&unsigned.node_key).is_none());
        assert!(tracker.peer_db.get(&bad.node_key).is_none());
    }

    /// End-to-end through the REAL enforcement-authority transport (the `watch` cell the control
    /// runner writes), not a direct field poke: writing `Some(authority)` flips enforcement on so a
    /// mixed batch drops the unsigned/bad peers, and a subsequent `None` (lock disabled) clears
    /// enforcement so a peer DROPPED while enforced is re-admitted. Exercises the exact `borrow`-based
    /// read path `tka_admits` uses — a broken receiver wiring would pass every for_test-field test but
    /// fail here.
    #[tokio::test]
    async fn tka_authority_watch_enables_then_clears_enforcement() {
        let (authority, sig) = authority_and_valid_sig();
        let mut bad_sig = sig.clone();
        let last = bad_sig.len() - 1;
        bad_sig[last] ^= 0xff;

        let (mut tracker, tka_tx) = PeerTracker::for_test(test_env(), None);

        // 1) No authority yet ⇒ admit-all (Go b.tka == nil).
        let good = peer_node("good", NODE_KEY_BYTES, sig.clone());
        let unsigned = peer_node("unsigned", [8u8; 32], vec![]);
        let bad = peer_node("bad", [9u8; 32], bad_sig);
        let batch = ts_control::PeerUpdate::Full(vec![good.clone(), unsigned.clone(), bad.clone()]);
        tracker.apply_peer_update(&batch);
        assert_eq!(tracker.peer_db.peers().len(), 3, "no lock ⇒ admit all");

        // 2) Publish the verified authority over the watch cell (exactly what the control runner does
        //    on a successful sync) ⇒ enforcement ON. A re-applied Full now drops unsigned + bad.
        tka_tx.send_replace(Some(Arc::new(authority)));
        tracker.apply_peer_update(&batch);
        assert_eq!(
            tracker.peer_db.peers().len(),
            1,
            "lock active ⇒ only the signed peer survives"
        );
        assert!(tracker.peer_db.get(&good.node_key).is_some());
        assert!(tracker.peer_db.get(&unsigned.node_key).is_none());
        assert!(tracker.peer_db.get(&bad.node_key).is_none());

        // 3) Lock disabled (None) ⇒ enforcement cleared ⇒ a peer that was DROPPED while enforced is
        //    re-admitted by a fresh netmap. Assert the specific previously-dropped key returns (not
        //    merely a count), so this proves the drop→clear→re-admit transition, not "admit-all-fresh".
        tka_tx.send_replace(None);
        tracker.apply_peer_update(&batch);
        assert_eq!(
            tracker.peer_db.peers().len(),
            3,
            "lock disabled ⇒ admit all again"
        );
        assert!(
            tracker.peer_db.get(&unsigned.node_key).is_some(),
            "the peer dropped under enforcement must come back once the lock is cleared"
        );
        assert!(tracker.peer_db.get(&bad.node_key).is_some());
    }

    /// The ordering gap this closes. A peer admitted BEFORE the lock synced must be re-checked the
    /// moment the authority is installed — not left in the db until control happens to send another
    /// `Full`. Go never has this problem: `SetControlClientStatus` runs `tkaSyncIfNeeded` and then
    /// `tkaFilterNetmapLocked(st.NetMap)` on the SAME netmap in one pass, so the netmap that
    /// announced the lock is itself filtered. Here the sync is a spawned task, so the netmap lands
    /// first and `tka_reevaluate_peer_db` is what restores Go's ordering.
    ///
    /// Note this test applies NO second netmap: the eviction must come from the authority install
    /// alone, which is exactly what was missing before.
    #[tokio::test]
    async fn tka_authority_install_reevaluates_already_admitted_peers() {
        let (authority, sig) = authority_and_valid_sig();
        let mut bad_sig = sig.clone();
        let last = bad_sig.len() - 1;
        bad_sig[last] ^= 0xff;

        let (mut tracker, tka_tx) = PeerTracker::for_test(test_env(), None);

        // 1) A netmap arrives while nothing is synced ⇒ enforcement inactive ⇒ all three admitted.
        let good = peer_node("good", NODE_KEY_BYTES, sig);
        let unsigned = peer_node("unsigned", [8u8; 32], vec![]);
        let bad = peer_node("bad", [9u8; 32], bad_sig);
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![
            good.clone(),
            unsigned.clone(),
            bad.clone(),
        ]));
        assert_eq!(tracker.peer_db.peers().len(), 3, "no lock yet ⇒ admit all");
        let unsigned_id = tracker
            .peer_db
            .get(&unsigned.node_key)
            .expect("unsigned peer admitted while no lock is synced")
            .0;
        let bad_id = tracker
            .peer_db
            .get(&bad.node_key)
            .expect("bad-sig peer admitted while no lock is synced")
            .0;

        // 2) The sync completes and the control runner installs the verified authority.
        tka_tx.send_replace(Some(Arc::new(authority)));
        let evicted = tracker.tka_reevaluate_peer_db();

        assert_eq!(
            evicted,
            HashSet::from_iter([unsigned_id, bad_id]),
            "the unsigned and bad-signature peers are the ones reported evicted"
        );
        assert_eq!(tracker.peer_db.peers().len(), 1);
        assert!(
            tracker.peer_db.get(&good.node_key).is_some(),
            "the authorized peer stays admitted"
        );
        assert!(tracker.peer_db.get(&unsigned.node_key).is_none());
        assert!(tracker.peer_db.get(&bad.node_key).is_none());

        // 3) Idempotent: a second pass over the now-clean db evicts nobody.
        assert!(tracker.tka_reevaluate_peer_db().is_empty());
    }

    /// With no authority the re-evaluation evicts nobody — enforcement is inactive and every peer is
    /// admitted, exactly Go's `b.tka == nil` early return. Covers both "never synced" and "the lock
    /// was disabled after enforcing", the two ways the cell holds `None`.
    #[tokio::test]
    async fn tka_reevaluate_without_authority_evicts_nothing() {
        let (authority, sig) = authority_and_valid_sig();
        let (mut tracker, tka_tx) = PeerTracker::for_test(test_env(), None);

        let good = peer_node("good", NODE_KEY_BYTES, sig);
        let unsigned = peer_node("unsigned", [8u8; 32], vec![]);
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![
            good.clone(),
            unsigned.clone(),
        ]));

        // Never synced.
        assert!(tracker.tka_reevaluate_peer_db().is_empty());
        assert_eq!(tracker.peer_db.peers().len(), 2);

        // Enforced, then disabled: the disable must not evict the peer the lock had authorized, and
        // must not start dropping the unsigned one either.
        tka_tx.send_replace(Some(Arc::new(authority)));
        assert_eq!(tracker.tka_reevaluate_peer_db().len(), 1);
        tka_tx.send_replace(None);
        assert!(tracker.tka_reevaluate_peer_db().is_empty());
        assert!(tracker.peer_db.get(&good.node_key).is_some());
    }

    /// The re-evaluation runs the WHOLE Go `tkaFilterNetmapLocked` pass, not just the per-peer
    /// signature check: a peer presenting a node key that a newer rotation superseded is evicted too,
    /// even though its own `Direct` signature still verifies against the authority. Both peers are
    /// already in the db when the authority lands, so the cross-peer rotation filter has to run over
    /// the db contents — which is why `tka_keep_verdicts` is shared with the `Full` path rather than
    /// re-derived here.
    #[tokio::test]
    async fn tka_reevaluate_applies_the_cross_peer_rotation_filter() {
        use ed25519_dalek::SigningKey;
        use ts_tka::NodeKeySignature;

        let trusted = SigningKey::from_bytes(&[42u8; 32]);
        let authority = Authority::from_state(
            AumHash([0; 32]),
            State {
                keys: vec![Key {
                    kind: KeyKind::Ed25519,
                    votes: 1,
                    public: trusted.verifying_key().to_bytes().to_vec(),
                }],
            },
        );
        // `stale` holds the pivot key with a valid Direct signature; `rotated` holds a key whose
        // rotation chain rotated the pivot key AWAY, which obsoletes `stale`.
        let pivot = SigningKey::from_bytes(&[9u8; 32]);
        let pivot_pub: [u8; 32] = pivot.verifying_key().to_bytes();
        let stale = peer_node(
            "stale",
            pivot_pub,
            NodeKeySignature::sign_direct(&pivot_pub, &trusted).serialize(),
        );
        let new_key = [4u8; 32];
        let rotated = peer_node(
            "rotated",
            new_key,
            NodeKeySignature::sign_rotation(&new_key, &trusted, &pivot).serialize(),
        );

        // Both admitted while nothing is synced.
        let (mut tracker, tka_tx) = PeerTracker::for_test(test_env(), None);
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![
            stale.clone(),
            rotated.clone(),
        ]));
        assert_eq!(tracker.peer_db.peers().len(), 2, "no lock yet ⇒ admit all");

        tka_tx.send_replace(Some(Arc::new(authority)));
        let evicted = tracker.tka_reevaluate_peer_db();

        assert_eq!(
            evicted.len(),
            1,
            "only the rotation-obsolete peer is evicted"
        );
        assert!(
            tracker.peer_db.get(&rotated.node_key).is_some(),
            "the freshly-rotated peer stays"
        );
        assert!(
            tracker.peer_db.get(&stale.node_key).is_none(),
            "the peer whose key a rotation superseded is evicted, though its own signature verifies"
        );
    }

    /// A `StateUpdate` carrying nothing but a `Full` peer set — the netmap shape the live-actor test
    /// publishes on the bus.
    fn netmap_with_peers(peers: Vec<Node>) -> ts_control::StateUpdate {
        ts_control::StateUpdate {
            session_handle: None,
            seq: 0,
            keep_alive: false,
            derp: None,
            node: None,
            peer_update: Some(ts_control::PeerUpdate::Full(peers)),
            peer_patches: Vec::new(),
            user_profiles: Vec::new(),
            ping: None,
            packetfilter: None,
            cap_grants: None,
            pop_browser_url: None,
            dial_plan: None,
            dns_config: None,
            ssh_policy: None,
            tka: None,
            online_change: Default::default(),
            peer_seen_change: Default::default(),
        }
    }

    /// Poll a live [`PeerTracker`] until it holds exactly `want` peers, bounded by a timeout so a
    /// broken wiring fails the test instead of hanging the suite.
    async fn await_peer_count(tracker: &ActorRef<PeerTracker>, want: usize) -> Vec<Node> {
        let settled = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let peers = tracker.ask(AllPeers).await.expect("peer tracker is alive");
                if peers.len() == want {
                    return peers;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await;
        settled.unwrap_or_else(|_| panic!("peer tracker never settled at {want} peer(s)"))
    }

    /// End-to-end through the LIVE actor, which is the only thing that proves the wiring: the peer
    /// tracker watches its own enforcement cell, so the control runner's `send_replace` re-filters
    /// the peer db with no further netmap. If the watch task were never spawned (or the message not
    /// handled) the unsigned peer would stay admitted forever — a hole every `for_test` unit test
    /// above would still pass over, because they call the re-evaluation by hand.
    #[tokio::test]
    async fn tka_authority_change_refilters_through_the_live_actor() {
        use kameo::actor::Spawn as _;

        let (authority, sig) = authority_and_valid_sig();
        let env = test_env();
        let (tka_tx, tka_rx) = watch::channel(None);
        let tracker = PeerTracker::spawn((env.clone(), tka_rx));

        // Await one reply first: the actor's `on_start` (which registers it on the bus) has then
        // completed, so the netmap published below cannot race the subscription.
        assert!(
            tracker
                .ask(AllPeers)
                .await
                .expect("peer tracker started")
                .is_empty()
        );

        let good = peer_node("good", NODE_KEY_BYTES, sig);
        let unsigned = peer_node("unsigned", [8u8; 32], vec![]);
        env.publish(Arc::new(netmap_with_peers(vec![
            good.clone(),
            unsigned.clone(),
        ])))
        .await
        .expect("publish netmap");

        // No lock synced ⇒ both peers land.
        await_peer_count(&tracker, 2).await;

        // The control runner installs the verified authority. No netmap follows.
        tka_tx.send_replace(Some(Arc::new(authority)));

        let peers = await_peer_count(&tracker, 1).await;
        assert_eq!(
            peers[0].stable_id, good.stable_id,
            "only the authorized peer survives the authority install"
        );
    }

    /// Degenerate input: two DISTINCT nodes sharing one `stable_id` in a single `Full`, one with a
    /// valid signature and one unsigned, under an active lock. Each node is judged by its OWN verdict
    /// (the per-node `admits` vector), so the unsigned node is never admitted on the strength of its
    /// signed twin. The single-verify `Full` refactor keeps this per-node semantics (a stable_id-set
    /// alone would have admitted whichever node was upserted last). Malformed control input; asserted
    /// only to lock the verdict-per-node behavior against regression.
    #[tokio::test]
    async fn tka_full_duplicate_stable_id_judges_each_node_on_its_own_signature() {
        let (authority, sig) = authority_and_valid_sig();
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), Some(authority));

        // Both carry stable_id "dup"; the signed one authorizes NODE_KEY_BYTES, the other is unsigned
        // and uses a different node key. Order them unsigned-last so a last-writer-wins stable_id set
        // would (wrongly) leave the unsigned node's key in the db.
        let signed = peer_node("dup", NODE_KEY_BYTES, sig);
        let unsigned = peer_node("dup", [8u8; 32], vec![]);
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![
            signed.clone(),
            unsigned.clone(),
        ]));

        // The unsigned node's own verdict failed, so its key must NOT be present, regardless of the
        // shared stable_id. (The signed twin retained the stable_id; the db holds the signed key.)
        assert!(
            tracker.peer_db.get(&unsigned.node_key).is_none(),
            "a node whose own signature fails must not be admitted via a stable_id twin"
        );
        assert!(tracker.peer_db.get(&signed.node_key).is_some());
    }

    /// Full-path consistency under two KEPT nodes sharing a `stable_id`: `peer_db.upsert` is
    /// last-writer-wins on `stable_id`, so the db ends holding exactly one node for that id (the last
    /// kept), and `retain` never evicts that just-upserted id (`retained_ids` contains the shared id
    /// because at least one of its nodes was kept). No lock here, so both nodes are "kept". This pins
    /// the published-state invariant the whole-surface audit flagged: `retain` and the upsert loop
    /// agree on the surviving stable_id. Malformed control input; asserted for robustness.
    #[tokio::test]
    async fn tka_full_duplicate_stable_id_both_kept_is_consistent() {
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), None);
        let first = peer_node("dup", [1u8; 32], vec![]);
        let last = peer_node("dup", [2u8; 32], vec![]);
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![
            first.clone(),
            last.clone(),
        ]));

        // Exactly one db entry for the shared stable_id, holding the LAST node (upsert is
        // last-writer-wins on stable_id); the first node's key was transparently superseded.
        assert_eq!(
            tracker.peer_db.peers().len(),
            1,
            "one entry for the shared stable_id"
        );
        assert!(
            tracker.peer_db.get(&last.node_key).is_some(),
            "the db holds the last-upserted node for the shared id"
        );
        assert!(
            tracker.peer_db.get(&first.node_key).is_none(),
            "the first node's key was superseded by the last at the shared id"
        );
    }

    /// A peer admitted in one `Full`, then in a later `Full` presenting a key that a co-resident
    /// peer's rotation chain has rotated away, is EVICTED — the cross-peer rotation filter applies on
    /// every resync, not only at first admission. Exercises the rotation filter through two
    /// sequential `Full` updates with real signing.
    #[tokio::test]
    async fn tka_full_rotation_obsolete_evicts_on_resync() {
        use ed25519_dalek::SigningKey;
        use ts_tka::NodeKeySignature;

        let trusted = SigningKey::from_bytes(&[42u8; 32]);
        let trusted_pub = trusted.verifying_key().to_bytes().to_vec();
        let authority = Authority::from_state(
            AumHash([0; 32]),
            State {
                keys: vec![Key {
                    kind: KeyKind::Ed25519,
                    votes: 1,
                    public: trusted_pub.clone(),
                }],
            },
        );
        let pivot = SigningKey::from_bytes(&[9u8; 32]);
        let pivot_pub: [u8; 32] = pivot.verifying_key().to_bytes();

        // First Full: the soon-to-be-stale peer presents the pivot key with a valid Direct sig.
        let stale_sig = NodeKeySignature::sign_direct(&pivot_pub, &trusted).serialize();
        let stale_peer = peer_node("stale", pivot_pub, stale_sig);
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), Some(authority));
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![stale_peer.clone()]));
        assert!(
            tracker.peer_db.get(&stale_peer.node_key).is_some(),
            "the stale peer is admitted while no rotation has superseded it yet"
        );

        // Second Full: a freshly-rotated peer (whose chain rotated AWAY the pivot key) joins, and the
        // stale peer is re-included. The rotation filter now obsoletes the pivot key ⇒ stale evicted.
        let new_key = [4u8; 32];
        let new_sig = NodeKeySignature::sign_rotation(&new_key, &trusted, &pivot).serialize();
        let new_peer = peer_node("rotated", new_key, new_sig);
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![
            new_peer.clone(),
            stale_peer.clone(),
        ]));
        assert!(
            tracker.peer_db.get(&new_peer.node_key).is_some(),
            "the freshly-rotated peer is admitted"
        );
        assert!(
            tracker.peer_db.get(&stale_peer.node_key).is_none(),
            "the stale peer is EVICTED on the resync once a rotation supersedes its key"
        );
    }

    /// The empty-trusted-key-state brick-guard: an authority with no keys must NOT drop the whole
    /// netmap (a `ts_tka` invariant violation / replayer edge). A verified chain always carries ≥1
    /// key, so this never weakens a genuine lock — it only prevents a black-hole. Uses ≥2 peers
    /// (one signed, one unsigned) to prove it admits **all**, not accidentally just one.
    #[tokio::test]
    async fn tka_empty_keyset_authority_admits_all() {
        use ts_tka::{AumHash, Authority, State};
        let empty_auth = Authority::from_state(AumHash([0u8; 32]), State { keys: Vec::new() });
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), Some(empty_auth));
        let signed = peer_node("signed", [7u8; 32], vec![0xde, 0xad]);
        let unsigned = peer_node("unsigned", [8u8; 32], vec![]);
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![
            signed.clone(),
            unsigned.clone(),
        ]));
        assert_eq!(
            tracker.peer_db.peers().len(),
            2,
            "an empty-keyset authority must admit ALL peers (brick-guard), not enforce"
        );
    }

    /// Signature-replay / `NodeKeyMismatch`: a structurally-valid signature that authorizes
    /// `NODE_KEY_BYTES` must NOT admit a DIFFERENT node key carrying that same signature blob. This is
    /// the highest-value bypass — if the sig↔node-key binding in `verify_signature` were dropped, this
    /// is the only test that would catch it (the other "bad" peers only flip a byte ⇒ `BadSignature`).
    #[tokio::test]
    async fn tka_active_rejects_valid_sig_for_wrong_node_key() {
        let (authority, sig) = authority_and_valid_sig();
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), Some(authority));

        // The signature authorizes NODE_KEY_BYTES; attach it to an imposter with a different key.
        let imposter = peer_node("imposter", [0x55u8; 32], sig);
        assert!(
            !tracker.tka_admits(&imposter),
            "a signature bound to one node key must not authorize a different node key"
        );
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![imposter.clone()]));
        assert!(tracker.peer_db.get(&imposter.node_key).is_none());
    }

    /// `UntrustedKey`: a signature produced by a well-formed Ed25519 key that is NOT in the
    /// authority's trusted-key state must be rejected — distinct from a tampered-byte `BadSignature`.
    #[tokio::test]
    async fn tka_active_rejects_sig_from_untrusted_key() {
        use ed25519_dalek::{Signer, SigningKey};
        let (authority, _sig) = authority_and_valid_sig();
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), Some(authority));

        // Sign a valid CBOR with a DIFFERENT key (not the one the authority trusts). The key_id in
        // the signature names this untrusted key, so `get_key` misses ⇒ UntrustedKey.
        let rogue = SigningKey::from_bytes(&[99u8; 32]);
        let rogue_pub = rogue.verifying_key().to_bytes().to_vec();
        let preimage = direct_sig_cbor(&NODE_KEY_BYTES, &rogue_pub, None);
        let sig_hash = ts_tka::aum_hash(&preimage).0;
        let signature = rogue.sign(&sig_hash).to_bytes().to_vec();
        let rogue_cbor = direct_sig_cbor(&NODE_KEY_BYTES, &rogue_pub, Some(&signature));

        let peer = peer_node("rogue-signed", NODE_KEY_BYTES, rogue_cbor);
        assert!(
            !tracker.tka_admits(&peer),
            "a signature from a key outside the trusted set must be rejected"
        );
        // Drive the real upsert path too (match the sibling replay test's depth): an untrusted-key
        // signature must keep the peer out of the db, not merely fail the verdict in isolation.
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![peer.clone()]));
        assert!(tracker.peer_db.get(&peer.node_key).is_none());
    }

    /// Bus-enable analogue for `Delta`: enforcement engaged via the watch cell must also gate a
    /// `Delta { upsert }` (not only `Full`). Closes the "authority arrived over the transport AND the
    /// next update is a Delta" combination.
    #[tokio::test]
    async fn tka_watch_enable_enforces_delta_upsert() {
        let (authority, sig) = authority_and_valid_sig();
        let (mut tracker, tka_tx) = PeerTracker::for_test(test_env(), None);
        tka_tx.send_replace(Some(Arc::new(authority)));

        let good = peer_node("good", NODE_KEY_BYTES, sig);
        let unsigned = peer_node("unsigned", [8u8; 32], vec![]);
        tracker.apply_peer_update(&ts_control::PeerUpdate::Delta {
            remove: vec![],
            upsert: vec![good.clone(), unsigned.clone()],
        });
        assert!(tracker.peer_db.get(&good.node_key).is_some());
        assert!(
            tracker.peer_db.get(&unsigned.node_key).is_none(),
            "delta upsert under an active lock must drop the unsigned peer"
        );
    }

    /// A `Delta` re-upsert of an ALREADY-ADMITTED peer whose signature is now invalid must EVICT the
    /// stale entry (revocation-via-delta), not leave it admitted. Go re-filters the whole netmap each
    /// response, so a now-unsigned peer would not survive there either.
    #[tokio::test]
    async fn tka_delta_reupsert_with_invalid_sig_evicts_existing() {
        let (authority, sig) = authority_and_valid_sig();
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), Some(authority));

        // Admit the signed peer.
        let good = peer_node("good", NODE_KEY_BYTES, sig.clone());
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![good.clone()]));
        assert!(tracker.peer_db.get(&good.node_key).is_some());

        // Re-upsert the SAME stable_id (now with no signature) via a delta ⇒ evicted, not retained.
        let revoked = peer_node("good", NODE_KEY_BYTES, vec![]);
        tracker.apply_peer_update(&ts_control::PeerUpdate::Delta {
            remove: vec![],
            upsert: vec![revoked],
        });
        assert!(
            tracker.peer_db.get(&good.node_key).is_none(),
            "a delta re-upsert that fails the lock must evict the previously-admitted peer"
        );
    }

    #[tokio::test]
    async fn tka_full_resync_revocation_behavior() {
        // Revocation-on-resync: admit a peer, then re-include the SAME stable_id in a `Full` with a
        // now-invalid signature. Per the Logic review finding, the pre-fix `retain` kept the stale
        // (previously-admitted) entry because membership was decided purely by stable_id.
        //
        // FIXED (not merely documented): the `Full` `retain` now keys on `tka_admits`-passing
        // stable_ids, so a peer whose re-included signature no longer verifies under the active
        // authority is EVICTED. This test asserts eviction. The inactive (authority=None) path is
        // provably unchanged — `tka_admits` always returns `true` there, so the retained set equals
        // the set of re-included stable_ids exactly (see `tka_inactive_full_resync_keeps_*`).
        let (authority, sig) = authority_and_valid_sig();
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), Some(authority));

        // 1) Admit the peer with a valid signature via a real `Full`.
        let good = peer_node("revoked", NODE_KEY_BYTES, sig.clone());
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![good.clone()]));
        assert_eq!(tracker.peer_db.peers().len(), 1);
        assert!(tracker.peer_db.get(&good.node_key).is_some());

        // 2) Re-sync the SAME stable_id, but with a now-invalid signature (tamper trailing byte).
        let mut bad_sig = sig;
        let last = bad_sig.len() - 1;
        bad_sig[last] ^= 0xff;
        let revoked = peer_node("revoked", NODE_KEY_BYTES, bad_sig);
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![revoked.clone()]));

        // Eviction: the stale entry is dropped because its re-included signature fails the gate.
        assert_eq!(tracker.peer_db.peers().len(), 0);
        assert!(tracker.peer_db.get(&revoked.node_key).is_none());
    }

    #[tokio::test]
    async fn tka_inactive_full_resync_keeps_reincluded_peer() {
        // Guard the inactive (authority=None) path against the revocation fix: with no authority,
        // a peer re-included in a `Full` survives regardless of its signature bytes — byte-for-byte
        // pre-TKA behavior, proving the `Full` `retain` change does not regress the always-taken
        // branch this wave.
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), None);

        let peer = peer_node("p", NODE_KEY_BYTES, vec![0xde, 0xad]);
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![peer.clone()]));
        assert_eq!(tracker.peer_db.peers().len(), 1);

        // Re-sync the same stable_id with garbage signature bytes; inactive enforcement keeps it.
        let resynced = peer_node("p", NODE_KEY_BYTES, vec![0x00]);
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![resynced.clone()]));
        assert_eq!(tracker.peer_db.peers().len(), 1);
        assert!(tracker.peer_db.get(&resynced.node_key).is_some());
    }

    /// A `Patch` for a peer already in the netmap merges only the fields it carries — here new UDP
    /// endpoints and a new home DERP — leaving the rest of the node intact. This is the fix for
    /// dropped `peers_changed_patch`: without it the netmap keeps stale endpoints and the peer can
    /// never re-handshake after it moves.
    #[tokio::test]
    async fn patch_merges_endpoints_and_derp_into_existing_peer() {
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), None);

        // Seed a peer (id == 1, per `peer_node`) with no endpoints / no DERP.
        let peer = peer_node("mover", [1u8; 32], vec![]);
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![peer.clone()]));
        let (_pid, before) = tracker.peer_db.get(&(1 as ts_control::NodeId)).unwrap();
        assert!(before.underlay_addresses.is_empty());
        assert!(before.derp_region.is_none());

        // Patch in fresh reachability (the idle-peer-reconnect case).
        let new_ep: std::net::SocketAddr = "203.0.113.7:41641".parse().unwrap();
        let patch = ts_control::PeerChange {
            id: 1,
            derp_region: Some(ts_derp::RegionId(core::num::NonZeroU32::new(5).unwrap())),
            cap: None,
            cap_map: None,
            underlay_addresses: Some(vec![new_ep]),
            node_key: None,
            key_signature: None,
            disco_key: None,
            node_key_expiry: None,
            online: None,
            last_seen: None,
        };
        let (upserts, deletions) = tracker.apply_peer_patches(std::slice::from_ref(&patch));

        assert_eq!(upserts.len(), 1);
        assert_eq!(deletions.len(), 0);
        // Same peer, now carrying the patched endpoint + DERP; node key untouched.
        assert_eq!(tracker.peer_db.peers().len(), 1);
        let (_pid, after) = tracker.peer_db.get(&(1 as ts_control::NodeId)).unwrap();
        assert_eq!(after.underlay_addresses, vec![new_ep]);
        assert_eq!(
            after.derp_region,
            Some(ts_derp::RegionId(core::num::NonZeroU32::new(5).unwrap()))
        );
        assert_eq!(after.node_key, peer.node_key);
    }

    /// Regression for `tsr-5u0`: when a whole-node set (`Delta`/`Full`) and a patch co-occur in one
    /// response, the patch is applied *on top of* the node the set just upserted — mirroring the
    /// handler's apply-order (peer set first, then `peer_patches`). Before the fix the patch shared
    /// the single `peer_update` slot and the co-occurring set silently dropped it, so a peer brought
    /// in by the delta kept stale (empty) reachability.
    #[tokio::test]
    async fn patch_applies_on_top_of_co_occurring_delta() {
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), None);

        // The whole-node delta upserts a brand-new peer (id == 1) with no reachability.
        let peer = peer_node("mover", [1u8; 32], vec![]);
        let (set_upserts, _) = tracker.apply_peer_update(&ts_control::PeerUpdate::Delta {
            upsert: vec![peer.clone()],
            remove: vec![],
        });
        assert_eq!(set_upserts.len(), 1, "delta upserts the new peer");

        // The patch from the SAME response then sets that peer's endpoints + DERP. This is exactly
        // the consumer order the handler runs (apply_peer_update then apply_peer_patches).
        let new_ep: std::net::SocketAddr = "203.0.113.7:41641".parse().unwrap();
        let patch = ts_control::PeerChange {
            id: 1,
            derp_region: Some(ts_derp::RegionId(core::num::NonZeroU32::new(7).unwrap())),
            cap: None,
            cap_map: None,
            underlay_addresses: Some(vec![new_ep]),
            node_key: None,
            key_signature: None,
            disco_key: None,
            node_key_expiry: None,
            online: None,
            last_seen: None,
        };
        let (patch_upserts, patch_deletions) =
            tracker.apply_peer_patches(std::slice::from_ref(&patch));

        assert_eq!(
            patch_upserts.len(),
            1,
            "patch re-upserts the just-added peer"
        );
        assert_eq!(patch_deletions.len(), 0);
        // The peer added by the delta now carries the patched reachability — the patch was NOT lost.
        let (_pid, after) = tracker.peer_db.get(&(1 as ts_control::NodeId)).unwrap();
        assert_eq!(after.underlay_addresses, vec![new_ep]);
        assert_eq!(
            after.derp_region,
            Some(ts_derp::RegionId(core::num::NonZeroU32::new(7).unwrap()))
        );
    }

    /// A `Patch` whose node id is not in the current netmap is ignored (the wire contract: a patch
    /// never creates a node). No upsert, no deletion, peer set unchanged.
    #[tokio::test]
    async fn patch_for_unknown_node_is_ignored() {
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), None);
        let known = peer_node("known", [1u8; 32], vec![]); // id == 1
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![known]));

        let patch = ts_control::PeerChange {
            id: 999, // not in the netmap
            derp_region: None,
            cap: None,
            cap_map: None,
            underlay_addresses: Some(vec!["198.51.100.9:1".parse().unwrap()]),
            node_key: None,
            key_signature: None,
            disco_key: None,
            node_key_expiry: None,
            online: None,
            last_seen: None,
        };
        let (upserts, deletions) = tracker.apply_peer_patches(std::slice::from_ref(&patch));

        assert_eq!(upserts.len(), 0);
        assert_eq!(deletions.len(), 0);
        assert_eq!(tracker.peer_db.peers().len(), 1);
        assert!(tracker.peer_db.get(&(999 as ts_control::NodeId)).is_none());
    }

    /// An expiry-only `Patch` updates `node_key_expiry` on the matching peer (Go
    /// `PeerChange.KeyExpiry`), rather than being silently dropped until the next full resync.
    #[tokio::test]
    async fn patch_updates_node_key_expiry() {
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), None);
        let peer = peer_node("expiring", [1u8; 32], vec![]); // id == 1, node_key_expiry: None
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![peer]));

        let expiry = "2027-01-01T00:00:00Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap();
        let patch = ts_control::PeerChange {
            id: 1,
            derp_region: None,
            cap: None,
            cap_map: None,
            underlay_addresses: None,
            node_key: None,
            key_signature: None,
            disco_key: None,
            node_key_expiry: Some(expiry),
            online: None,
            last_seen: None,
        };
        tracker.apply_peer_patches(std::slice::from_ref(&patch));

        let (_pid, after) = tracker.peer_db.get(&(1 as ts_control::NodeId)).unwrap();
        assert_eq!(after.node_key_expiry, Some(expiry));
    }

    /// Channel B: a `PeerChange.online` patch flips a peer's online state without a full node.
    #[tokio::test]
    async fn patch_updates_online() {
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), None);
        let peer = peer_node("p", [1u8; 32], vec![]); // id == 1, online: None
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![peer]));
        assert_eq!(
            tracker
                .peer_db
                .get(&(1 as ts_control::NodeId))
                .unwrap()
                .1
                .online,
            None
        );

        let mut patch = ts_control::PeerChange {
            id: 1,
            derp_region: None,
            cap: None,
            cap_map: None,
            underlay_addresses: None,
            node_key: None,
            key_signature: None,
            disco_key: None,
            node_key_expiry: None,
            online: Some(true),
            last_seen: None,
        };
        tracker.apply_peer_patches(std::slice::from_ref(&patch));
        assert_eq!(
            tracker
                .peer_db
                .get(&(1 as ts_control::NodeId))
                .unwrap()
                .1
                .online,
            Some(true),
            "PeerChange.online=Some(true) marks the peer online"
        );

        // A subsequent patch flips it offline.
        patch.online = Some(false);
        tracker.apply_peer_patches(std::slice::from_ref(&patch));
        assert_eq!(
            tracker
                .peer_db
                .get(&(1 as ts_control::NodeId))
                .unwrap()
                .1
                .online,
            Some(false)
        );
    }

    /// Channel C/D (Go `map.go:updatePeersStateFromResponse`): `online_change` is the sole driver of
    /// `online`; `peer_seen_change` is the sole driver of `last_seen` (true ⇒ now, false ⇒ cleared)
    /// and must NEVER touch `online`. Both apply to a peer already in the netmap and ignore unknown
    /// ids. This pins the fix for the prior bug where channel D wrote `online=false` (conflating
    /// "not seen recently" with "offline" — distinct signals in Go).
    #[tokio::test]
    async fn liveness_change_maps_apply_online() {
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), None);
        let peer = peer_node("p", [1u8; 32], vec![]); // id == 1
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![peer]));
        // A fixed timestamp (chrono is built without its `clock` feature, so no `Utc::now()`).
        let now = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();

        // Channel C: online_change sets online=true.
        let mut online_change = std::collections::BTreeMap::new();
        online_change.insert(1 as ts_control::NodeId, true);
        online_change.insert(999 as ts_control::NodeId, true); // unknown id — ignored
        let changed = tracker.apply_liveness_changes(&online_change, &Default::default(), now);
        assert!(changed);
        assert_eq!(
            tracker
                .peer_db
                .get(&(1 as ts_control::NodeId))
                .unwrap()
                .1
                .online,
            Some(true)
        );

        // Channel D: peer_seen_change=true sets last_seen=now and leaves online UNTOUCHED.
        let mut seen_true = std::collections::BTreeMap::new();
        seen_true.insert(1 as ts_control::NodeId, true);
        let changed = tracker.apply_liveness_changes(&Default::default(), &seen_true, now);
        assert!(changed);
        {
            let (_id, node) = tracker.peer_db.get(&(1 as ts_control::NodeId)).unwrap();
            assert_eq!(
                node.last_seen,
                Some(now),
                "peer_seen_change=true sets last_seen=now"
            );
            assert_eq!(
                node.online,
                Some(true),
                "channel D must NOT touch online (still true from channel C)"
            );
        }

        // Channel D: peer_seen_change=false clears last_seen, still leaving online untouched.
        let mut seen_false = std::collections::BTreeMap::new();
        seen_false.insert(1 as ts_control::NodeId, false);
        let changed = tracker.apply_liveness_changes(&Default::default(), &seen_false, now);
        assert!(changed);
        {
            let (_id, node) = tracker.peer_db.get(&(1 as ts_control::NodeId)).unwrap();
            assert_eq!(
                node.last_seen, None,
                "peer_seen_change=false clears last_seen"
            );
            assert_eq!(node.online, Some(true), "channel D must NOT mark offline");
        }
        assert_eq!(
            tracker.peer_db.peers().len(),
            1,
            "the node is retained, not removed"
        );

        // No-op when nothing matches / changes.
        assert!(!tracker.apply_liveness_changes(&Default::default(), &Default::default(), now));
    }

    /// Security: a `Patch` that rotates the node key must re-satisfy the tailnet-lock authority,
    /// exactly like a `Delta` upsert. A key-rotation patch whose new signature does NOT verify
    /// evicts the peer (fail-closed) rather than leaving a now-unverified entry — closing what would
    /// otherwise be a trust-enforcement bypass via the patch path.
    #[tokio::test]
    async fn patch_key_rotation_failing_tka_evicts_peer() {
        let (authority, sig) = authority_and_valid_sig();
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), Some(authority));

        // Admit a correctly-signed peer (id == 1).
        let good = peer_node("rotator", NODE_KEY_BYTES, sig.clone());
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![good.clone()]));
        assert_eq!(tracker.peer_db.peers().len(), 1);

        // Patch a new node key whose signature is garbage under the active authority.
        let patch = ts_control::PeerChange {
            id: 1,
            derp_region: None,
            cap: None,
            cap_map: None,
            underlay_addresses: None,
            node_key: Some([0x33u8; 32].into()),
            key_signature: Some(vec![0x00, 0x01, 0x02]),
            disco_key: None,
            node_key_expiry: None,
            online: None,
            last_seen: None,
        };
        let (upserts, deletions) = tracker.apply_peer_patches(std::slice::from_ref(&patch));

        assert_eq!(upserts.len(), 0);
        assert_eq!(deletions.len(), 1);
        assert_eq!(tracker.peer_db.peers().len(), 0);
    }

    /// A node's `user_id` joins against the accumulated UserProfiles table to resolve the owning
    /// user's login name in `WhoIs.user`. With no matching profile, `user` is `None` (the
    /// pre-existing behavior); once a profile arrives, the same node resolves to its login. This
    /// proves the accumulate-then-join path the netmap handler builds.
    fn profile(id: ts_control::UserId, login: &str) -> ts_control::UserProfile {
        ts_control::UserProfile {
            id,
            login_name: login.to_string(),
            display_name: None,
        }
    }

    #[tokio::test]
    async fn whois_resolves_user_from_accumulated_profiles() {
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), None);

        // A peer owned by user id 42 at 100.64.0.1 (the peer_node fixture's address).
        let mut peer = peer_node("p", NODE_KEY_BYTES, Vec::new());
        peer.user_id = 42;
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![peer]));
        let addr = "100.64.0.1:0".parse().unwrap();

        // No profile yet: the node resolves but its owner is unknown.
        let who = tracker.whois_opt(addr).expect("peer is known");
        assert_eq!(who.user, None);

        // Profile for a DIFFERENT user must not match.
        tracker
            .user_profiles
            .insert(7, profile(7, "someone-else@example.com"));
        assert_eq!(tracker.whois_opt(addr).unwrap().user, None);

        // The owning user's profile arrives (as the netmap handler would accumulate it): now the
        // login resolves.
        tracker
            .user_profiles
            .insert(42, profile(42, "alice@example.com"));
        assert_eq!(
            tracker.whois_opt(addr).unwrap().user,
            Some("alice@example.com".to_string())
        );
    }

    /// `UserProfile::best_label` prefers the login name, falling back to display name, else `None`.
    #[test]
    fn user_profile_best_label_prefers_login() {
        assert_eq!(
            profile(1, "alice@example.com").best_label(),
            Some("alice@example.com".to_string())
        );
        let display_only = ts_control::UserProfile {
            id: 2,
            login_name: String::new(),
            display_name: Some("Bob".to_string()),
        };
        assert_eq!(display_only.best_label(), Some("Bob".to_string()));
        let empty = ts_control::UserProfile {
            id: 3,
            login_name: String::new(),
            display_name: None,
        };
        assert_eq!(empty.best_label(), None);
    }

    // ----- tsr-jo1: RotationTracker (Go ipnlocal.rotationTracker.obsoleteKeys) -----

    /// A `RotationDetails` for a `Direct`-rooted chain with the given prior keys + wrapping key.
    fn rot_details(
        prev: &[&[u8]],
        wrapping: &[u8],
        kind: ts_tka::SigKind,
    ) -> ts_tka::RotationDetails {
        ts_tka::RotationDetails {
            prev_node_keys: prev.iter().map(|p| p.to_vec()).collect(),
            initial_sig_kind: kind,
            initial_wrapping_pubkey: wrapping.to_vec(),
        }
    }

    /// Rule 1: every prior node key named by any rotation chain is obsolete, regardless of the
    /// chain's root kind (Go's ungated `obsolete.AddSlice(d.PrevNodeKeys)`).
    #[test]
    fn rotation_tracker_prev_keys_always_obsolete() {
        let mut t = RotationTracker::default();
        // A Direct-rooted chain that rotated away OLD1, and a Credential-rooted one that rotated OLD2.
        t.add(
            b"newA".to_vec(),
            &rot_details(&[b"OLD1"], b"wrapA", ts_tka::SigKind::Direct),
        );
        t.add(
            b"newB".to_vec(),
            &rot_details(&[b"OLD2"], b"wrapB", ts_tka::SigKind::Credential),
        );
        let obsolete = t.obsolete_keys();
        assert!(
            obsolete.contains(b"OLD1".as_slice()),
            "Direct chain's prior key obsolete"
        );
        assert!(
            obsolete.contains(b"OLD2".as_slice()),
            "Credential chain's prior key obsolete too (rule 1 is ungated)"
        );
        // The current keys themselves are not obsolete (only one peer per wrapping key here).
        assert!(!obsolete.contains(b"newA".as_slice()));
        assert!(!obsolete.contains(b"newB".as_slice()));
    }

    /// Rule 2: among `Direct`-rooted chains sharing a wrapping key, only the longest survives; the
    /// shorter (older) clone's key is obsolete.
    #[test]
    fn rotation_tracker_unequal_chain_keeps_longest() {
        let mut t = RotationTracker::default();
        // Same wrapping key; "long" has 2 prior keys, "short" has 1 ⇒ "short" is the older clone.
        t.add(
            b"long".to_vec(),
            &rot_details(&[b"p1", b"p2"], b"wrap", ts_tka::SigKind::Direct),
        );
        t.add(
            b"short".to_vec(),
            &rot_details(&[b"q1"], b"wrap", ts_tka::SigKind::Direct),
        );
        let obsolete = t.obsolete_keys();
        assert!(
            obsolete.contains(b"short".as_slice()),
            "the shorter-chain clone is obsolete"
        );
        assert!(
            !obsolete.contains(b"long".as_slice()),
            "the longest-chain peer survives"
        );
    }

    /// Rule 2 tie: two `Direct`-rooted chains sharing a wrapping key with EQUAL chain length cannot
    /// be disambiguated ⇒ BOTH are dropped (Go's safety branch).
    #[test]
    fn rotation_tracker_equal_chain_drops_both() {
        let mut t = RotationTracker::default();
        t.add(
            b"cloneA".to_vec(),
            &rot_details(&[b"p1"], b"wrap", ts_tka::SigKind::Direct),
        );
        t.add(
            b"cloneB".to_vec(),
            &rot_details(&[b"p2"], b"wrap", ts_tka::SigKind::Direct),
        );
        let obsolete = t.obsolete_keys();
        assert!(
            obsolete.contains(b"cloneA".as_slice()),
            "tied clone A dropped"
        );
        assert!(
            obsolete.contains(b"cloneB".as_slice()),
            "tied clone B dropped"
        );
    }

    /// `Credential`-rooted chains sharing a wrapping key are EXEMPT from rule 2 (reusable-authkey
    /// carve-out): both are kept even with equal chain length.
    #[test]
    fn rotation_tracker_credential_root_clones_both_kept() {
        let mut t = RotationTracker::default();
        t.add(
            b"credA".to_vec(),
            &rot_details(&[b"p1"], b"wrap", ts_tka::SigKind::Credential),
        );
        t.add(
            b"credB".to_vec(),
            &rot_details(&[b"p2"], b"wrap", ts_tka::SigKind::Credential),
        );
        let obsolete = t.obsolete_keys();
        assert!(
            !obsolete.contains(b"credA".as_slice()),
            "credential-rooted clone A kept"
        );
        assert!(
            !obsolete.contains(b"credB".as_slice()),
            "credential-rooted clone B kept"
        );
    }

    /// A peer that another chain already rotated away does not also act as a surviving clone: it is
    /// removed from its wrapping-key group before the longest-survivor pick (Go's `DeleteFunc`).
    #[test]
    fn rotation_tracker_already_obsolete_peer_not_a_survivor() {
        let mut t = RotationTracker::default();
        // "victim" is rotated away by "rotator" (different wrapping key), AND shares wrapping key
        // "w" with "other". Because "victim" is already obsolete, only "other" is in play for "w" and
        // survives (no spurious tie-drop of "other").
        t.add(
            b"rotator".to_vec(),
            &rot_details(&[b"victim"], b"wRot", ts_tka::SigKind::Direct),
        );
        t.add(
            b"victim".to_vec(),
            &rot_details(&[b"x"], b"w", ts_tka::SigKind::Direct),
        );
        t.add(
            b"other".to_vec(),
            &rot_details(&[b"y"], b"w", ts_tka::SigKind::Direct),
        );
        let obsolete = t.obsolete_keys();
        assert!(
            obsolete.contains(b"victim".as_slice()),
            "victim rotated away by rotator"
        );
        assert!(
            !obsolete.contains(b"other".as_slice()),
            "other survives — victim was removed from the group before the tie check"
        );
    }

    /// Empty tracker (no rotation-signed peers) ⇒ no obsolete keys (the non-rotation netmap path).
    #[test]
    fn rotation_tracker_empty_is_noop() {
        let t = RotationTracker::default();
        assert!(t.obsolete_keys().is_empty());
    }

    /// End-to-end through the real `Full` path: a peer presenting a freshly-rotated key (a Rotation
    /// chain) is admitted, while a second peer still presenting the rotated-AWAY pivot key — even with
    /// that key's own still-valid Direct signature — is DROPPED by the cross-peer rotation filter.
    /// This is the gap closed here: Go `tkaFilterNetmapLocked` drops the stale clone; we used to admit
    /// it. Uses real `ts_tka` signing (`sign_direct` + `sign_rotation`) so the whole
    /// verify → details → filter pipeline runs.
    ///
    /// Construction: the trusted key signs an inner `Direct` over the PIVOT keypair's public key; the
    /// pivot key then signs an outer `Rotation` authorizing `new_key`. That chain's `prev_node_keys`
    /// names the pivot pubkey — so a peer presenting the pivot pubkey as its node key is the
    /// rotated-away key the filter must drop.
    #[tokio::test]
    async fn tka_full_drops_rotated_away_key_e2e() {
        use ed25519_dalek::SigningKey;
        use ts_tka::NodeKeySignature;

        let trusted = SigningKey::from_bytes(&[42u8; 32]);
        let trusted_pub = trusted.verifying_key().to_bytes().to_vec();
        let authority = Authority::from_state(
            AumHash([0; 32]),
            State {
                keys: vec![Key {
                    kind: KeyKind::Ed25519,
                    votes: 1,
                    public: trusted_pub.clone(),
                }],
            },
        );

        // The rotation pivot: a keypair whose public key the inner Direct authorizes and whose
        // private key signs the outer rotation wrap. This pivot pubkey IS the key being rotated away.
        let pivot = SigningKey::from_bytes(&[9u8; 32]);
        let pivot_pub: [u8; 32] = pivot.verifying_key().to_bytes();

        let new_key = [4u8; 32]; // the freshly-rotated node key

        // Fresh peer: a Rotation chain authorizing `new_key`, inner Direct over the pivot signed by
        // trusted, outer wrap signed by the pivot. Its prev_node_keys names `pivot_pub`.
        let new_sig = NodeKeySignature::sign_rotation(&new_key, &trusted, &pivot).serialize();
        let new_peer = peer_node("rotated", new_key, new_sig);

        // Stale peer: still presents the pivot pubkey (the rotated-away key) with its own valid
        // Direct signature — valid in isolation, but obsoleted by the fresh peer's rotation chain.
        let stale_sig = NodeKeySignature::sign_direct(&pivot_pub, &trusted).serialize();
        let stale_peer = peer_node("stale", pivot_pub, stale_sig);

        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), Some(authority));
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![
            new_peer.clone(),
            stale_peer.clone(),
        ]));

        assert!(
            tracker.peer_db.get(&new_peer.node_key).is_some(),
            "the freshly-rotated peer is admitted"
        );
        assert!(
            tracker.peer_db.get(&stale_peer.node_key).is_none(),
            "the peer presenting the rotated-away key is dropped (Go tkaFilterNetmapLocked)"
        );
    }
}

#[cfg(test)]
mod tsmp_disco_key_tests {
    //! Receive side of the TSMP disco-key advertisement, at the point the key is *learned*.
    //!
    //! These exercise [`PeerTracker::learn_disco_key`] — the fork's stand-in for Go
    //! `magicsock.Conn.HandleDiscoKeyAdvertisement` — which is the single place an advertisement
    //! reaches peer state. The wire decode and the "consumed, not delivered" drop are covered in
    //! `ts_packet::tsmp` and `ts_dataplane` respectively.

    use ts_keys::DiscoPublicKey;

    use super::{
        tka_tests::{peer_node, test_env},
        *,
    };

    /// The key a peer advertises, and a second one for the re-advertise case.
    const ADVERTISED: [u8; 32] = [0xa5u8; 32];
    const READVERTISED: [u8; 32] = [0x5au8; 32];
    /// The (staler) key control has for that same peer, and the one control eventually catches up
    /// to.
    const FROM_CONTROL: [u8; 32] = [0xc0u8; 32];
    const CONTROL_CAUGHT_UP: [u8; 32] = [0x0cu8; 32];

    /// The node key of the single peer these tests use.
    const PEER_NODE_KEY: [u8; 32] = [1u8; 32];

    /// A tracker holding one peer with no disco key yet, plus that peer's [`PeerId`].
    fn tracker_with_peer() -> (PeerTracker, PeerId) {
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), None);
        let node = peer_node("peer", PEER_NODE_KEY, Vec::new());
        let id = tracker.peer_db.upsert(&node);
        (tracker, id)
    }

    /// The peer as CONTROL describes it: the same node, carrying whatever disco key the netmap says
    /// it has (`None` for a peer control has no disco key for at all).
    fn node_from_control(disco_key: Option<[u8; 32]>) -> Node {
        let mut node = peer_node("peer", PEER_NODE_KEY, Vec::new());
        node.disco_key = disco_key.map(DiscoPublicKey::from);
        node
    }

    /// A netmap `Full` carrying just this peer, as control currently describes it.
    fn control_full(disco_key: Option<[u8; 32]>) -> ts_control::PeerUpdate {
        ts_control::PeerUpdate::Full(vec![node_from_control(disco_key)])
    }

    /// A tracker whose single peer arrived through the netmap carrying `disco_key`, exactly as the
    /// actor's handler applies it. Returns the peer's [`PeerId`] too.
    fn tracker_with_control_peer(disco_key: Option<[u8; 32]>) -> (PeerTracker, PeerId) {
        let (mut tracker, _tka_tx) = PeerTracker::for_test(test_env(), None);
        let node = node_from_control(disco_key);
        tracker.apply_peer_update(&control_full(disco_key));
        let id = tracker
            .peer_db
            .has(&node.node_key)
            .expect("control delivered it");
        (tracker, id)
    }

    /// The disco key the peer db currently holds for `peer` — the effective key every direct-path
    /// consumer resolves against.
    fn effective_key(tracker: &PeerTracker, peer: PeerId) -> Option<DiscoPublicKey> {
        tracker
            .peer_db
            .get(&peer)
            .expect("peer still present")
            .1
            .disco_key
    }

    /// The happy path: an advertised key is applied to the peer AND lands in the disco index, which
    /// is what the direct-path machinery (`direct::DiscoPeerLookup`) reads. Re-advertising the same
    /// key is a no-op; advertising a different one replaces it, retracting the old index entry.
    #[tokio::test]
    async fn advertisement_learns_the_peers_disco_key() {
        let (mut tracker, peer) = tracker_with_peer();
        let key = DiscoPublicKey::from(ADVERTISED);

        assert!(
            tracker.learn_disco_key(peer, key),
            "a first advertisement changes the peer db"
        );
        assert_eq!(
            tracker
                .peer_db
                .get(&peer)
                .expect("peer still present")
                .1
                .disco_key,
            Some(key),
            "the advertised disco key is learned"
        );
        assert_eq!(
            tracker.peer_db.has(&key),
            Some(peer),
            "and is reachable through the disco index the direct path resolves against"
        );

        assert!(
            !tracker.learn_disco_key(peer, key),
            "re-advertising the same key is a no-op (Go counts it 'unchanged' and returns)"
        );

        let rotated = DiscoPublicKey::from(READVERTISED);
        assert!(tracker.learn_disco_key(peer, rotated));
        assert_eq!(
            tracker
                .peer_db
                .get(&peer)
                .expect("peer still present")
                .1
                .disco_key,
            Some(rotated),
            "a later advertisement replaces the key without a netmap update"
        );
        assert_eq!(tracker.peer_db.has(&rotated), Some(peer));
        assert_eq!(
            tracker.peer_db.has(&key),
            None,
            "the superseded key no longer resolves to the peer"
        );
    }

    /// The refusals, each of which must leave the peer db untouched: the zero key is never learned,
    /// and an advertisement never creates a peer.
    #[tokio::test]
    async fn refused_advertisements_change_nothing() {
        let (mut tracker, peer) = tracker_with_peer();

        assert!(
            !tracker.learn_disco_key(peer, DiscoPublicKey::from([0u8; 32])),
            "the zero key is never learned"
        );
        assert_eq!(
            tracker
                .peer_db
                .get(&peer)
                .expect("peer still present")
                .1
                .disco_key,
            None,
            "a zero-key advertisement must not bind the peer to an unusable key"
        );

        // An advertisement for a peer control has never told us about. Go logs "endpoint not found
        // for node" and returns; it must not conjure a peer into existence.
        let unknown = PeerId(4242);
        assert_eq!(tracker.peer_db.get(&unknown), None, "precondition");
        assert!(
            !tracker.learn_disco_key(unknown, DiscoPublicKey::from(ADVERTISED)),
            "an advertisement for an unknown peer is ignored"
        );
        assert_eq!(
            tracker.peer_db.peers().len(),
            1,
            "an advertisement never creates a peer — only control does"
        );
        assert_eq!(
            tracker.peer_db.has(&DiscoPublicKey::from(ADVERTISED)),
            None,
            "and never indexes a key against a peer that does not exist"
        );
    }

    /// The feature's motivating case, end to end: the peer told us a key control has not caught up
    /// with, and then control polls again with the SAME stale key it had before. The advertisement
    /// must survive.
    ///
    /// Go keeps the two keys apart on the endpoint (`endpointDisco.controlKey` /
    /// `tsmpKey`), and `updateFromNode` only rewrites the control side when control's key actually
    /// changed — so a netmap restating the old key never touches the active TSMP key. With a single
    /// field the next map poll silently reverted the peer to control's stale key, which is precisely
    /// the state the advertisement exists to escape.
    #[tokio::test]
    async fn netmap_restating_controls_stale_key_keeps_the_tsmp_key() {
        let (mut tracker, peer) = tracker_with_control_peer(Some(FROM_CONTROL));
        let advertised = DiscoPublicKey::from(ADVERTISED);
        assert_eq!(
            effective_key(&tracker, peer),
            Some(DiscoPublicKey::from(FROM_CONTROL)),
            "precondition: the peer starts on the key control gave us"
        );

        assert!(tracker.learn_disco_key(peer, advertised));
        assert_eq!(effective_key(&tracker, peer), Some(advertised));

        // Control polls again, still behind: a `Full` resync, then a `Delta` re-upsert, both
        // carrying the key control already sent.
        tracker.apply_peer_update(&control_full(Some(FROM_CONTROL)));
        assert_eq!(
            effective_key(&tracker, peer),
            Some(advertised),
            "a Full restating control's stale key must not undo the TSMP-learned key"
        );
        tracker.apply_peer_update(&ts_control::PeerUpdate::Delta {
            upsert: vec![node_from_control(Some(FROM_CONTROL))],
            remove: vec![],
        });
        assert_eq!(
            effective_key(&tracker, peer),
            Some(advertised),
            "and neither must a Delta re-upsert of the same node"
        );
        assert_eq!(
            tracker.peer_db.has(&advertised),
            Some(peer),
            "the direct path still resolves the peer by the key it advertised"
        );
        assert_eq!(
            tracker.peer_db.has(&DiscoPublicKey::from(FROM_CONTROL)),
            None,
            "and control's superseded key does not resolve to it"
        );

        // Control finally changes its mind. The new key is recorded in control's slot, but the key
        // the peer itself told us stays active — upstream returns to control's key only when disco
        // is received under it (`endpoint.checkAndUpdateDiscoKey`).
        tracker.apply_peer_update(&control_full(Some(CONTROL_CAUGHT_UP)));
        assert_eq!(
            effective_key(&tracker, peer),
            Some(advertised),
            "a control-side key change must not preempt an active TSMP-learned key"
        );
        assert_eq!(
            tracker.control_disco_key(&PEER_NODE_KEY.into()),
            Some(DiscoPublicKey::from(CONTROL_CAUGHT_UP)),
            "but control's new key IS recorded in control's slot"
        );
    }

    /// An advertisement that merely restates the key control already gave us is still *new*
    /// information — it is the peer itself confirming the key — so Go records it as the TSMP key and
    /// makes it active. Its "unchanged" early return compares `epDisco.keyFromTSMP()`, the
    /// TSMP-learned key specifically, never the effective one.
    ///
    /// The observable consequence, asserted here: once the peer has confirmed the key, control
    /// dropping it (a netmap node with no disco key) leaves the confirmed key in place instead of
    /// blinding the direct path.
    #[tokio::test]
    async fn advertisement_restating_controls_key_is_recorded_as_the_tsmp_key() {
        let (mut tracker, peer) = tracker_with_control_peer(Some(FROM_CONTROL));
        let key = DiscoPublicKey::from(FROM_CONTROL);

        assert!(
            tracker.learn_disco_key(peer, key),
            "an advertisement of the key control already sent is recorded, not dropped"
        );
        assert_eq!(
            tracker
                .endpoint_disco
                .get(&PEER_NODE_KEY.into())
                .and_then(EndpointDisco::key_from_tsmp),
            Some(key),
            "it lands in the TSMP slot (Go epDisco.tsmpKey), not only in control's"
        );
        assert!(
            !tracker.learn_disco_key(peer, key),
            "re-advertising it now IS unchanged, and is refused"
        );

        // Control drops the peer's disco key. The key the peer itself confirmed stays active.
        tracker.apply_peer_update(&control_full(None));
        assert_eq!(
            effective_key(&tracker, peer),
            Some(key),
            "a control key going away hands the active slot to the TSMP-learned key"
        );
        assert_eq!(tracker.peer_db.has(&key), Some(peer));
    }

    /// A `PeersChangedPatch` is a control write like any other: one that says nothing about the
    /// disco key must leave an active TSMP key alone, and one that carries a new key is control
    /// catching up, so it wins.
    ///
    /// The patch path is the subtle one — it starts from the db node, which carries the *effective*
    /// key, so without re-deriving what control last said it would hand the TSMP key back as if
    /// control had sent it.
    #[tokio::test]
    async fn patch_without_a_disco_key_leaves_the_tsmp_key_active() {
        let (mut tracker, peer) = tracker_with_control_peer(Some(FROM_CONTROL));
        let advertised = DiscoPublicKey::from(ADVERTISED);
        assert!(tracker.learn_disco_key(peer, advertised));

        // A reachability-only patch (the idle-peer-reconnect case) for the same node.
        let endpoint: std::net::SocketAddr = "203.0.113.9:41641".parse().unwrap();
        let mut patch = ts_control::PeerChange {
            id: 1,
            derp_region: None,
            cap: None,
            cap_map: None,
            underlay_addresses: Some(vec![endpoint]),
            node_key: None,
            key_signature: None,
            disco_key: None,
            node_key_expiry: None,
            online: None,
            last_seen: None,
        };
        tracker.apply_peer_patches(std::slice::from_ref(&patch));
        assert_eq!(
            effective_key(&tracker, peer),
            Some(advertised),
            "a patch that never mentions the disco key must not revert it to control's"
        );
        assert_eq!(
            tracker
                .peer_db
                .get(&peer)
                .expect("peer still present")
                .1
                .underlay_addresses,
            vec![endpoint],
            "and the patch it DID carry still applied"
        );

        // Now control changes the key through the patch channel. Same rule as the netmap path: the
        // key lands in control's slot, and the active TSMP key is left alone.
        patch.disco_key = Some(DiscoPublicKey::from(CONTROL_CAUGHT_UP));
        tracker.apply_peer_patches(std::slice::from_ref(&patch));
        assert_eq!(
            effective_key(&tracker, peer),
            Some(advertised),
            "a patch carrying a new disco key does not preempt the active TSMP-learned key either"
        );
        assert_eq!(
            tracker.control_disco_key(&PEER_NODE_KEY.into()),
            Some(DiscoPublicKey::from(CONTROL_CAUGHT_UP)),
            "the patched key is still recorded as what control now says"
        );
    }

    /// The rule this whole pair of slots exists to express: once the peer has told us its key over
    /// TSMP, control changing its mind is *recorded* but does not take the active slot back — Go
    /// `endpoint.updateDiscoKey`'s `epDisco.tsmpActive = old.tsmpActive || key.IsZero()`.
    ///
    /// Control is the slower source; a key the peer sent us itself is the better evidence. Upstream
    /// hands the slot back only when disco is actually *received* under control's key
    /// (`endpoint.checkAndUpdateDiscoKey`). Here the peer re-advertising is the path back, and it is
    /// asserted at the end so the sticky rule cannot be read as "the TSMP key is now permanent".
    #[tokio::test]
    async fn a_control_key_change_does_not_preempt_an_active_tsmp_key() {
        let (mut tracker, peer) = tracker_with_control_peer(Some(FROM_CONTROL));
        let advertised = DiscoPublicKey::from(ADVERTISED);
        let caught_up = DiscoPublicKey::from(CONTROL_CAUGHT_UP);
        assert!(tracker.learn_disco_key(peer, advertised));

        tracker.apply_peer_update(&control_full(Some(CONTROL_CAUGHT_UP)));
        assert_eq!(
            effective_key(&tracker, peer),
            Some(advertised),
            "the TSMP-learned key stays active across a control-side change"
        );
        assert_eq!(
            tracker.peer_db.has(&advertised),
            Some(peer),
            "so the direct path still resolves the peer by the key it advertised"
        );
        assert_eq!(
            tracker.peer_db.has(&caught_up),
            None,
            "and control's new key is not what we send to"
        );
        assert_eq!(
            tracker.control_disco_key(&PEER_NODE_KEY.into()),
            Some(caught_up),
            "control's new key is recorded all the same — it is not discarded, just not active"
        );

        // Control changing its mind a second time, and then dropping the key entirely, changes
        // nothing about which key is active.
        tracker.apply_peer_update(&control_full(Some(FROM_CONTROL)));
        tracker.apply_peer_update(&control_full(None));
        assert_eq!(
            effective_key(&tracker, peer),
            Some(advertised),
            "neither a second control change nor control dropping the key moves the active slot"
        );

        // The peer itself is what moves it: it advertises the key control had been trying to give
        // us, and that advertisement is what we act on.
        assert!(tracker.learn_disco_key(peer, caught_up));
        assert_eq!(
            effective_key(&tracker, peer),
            Some(caught_up),
            "a peer re-advertising moves the active key, because the peer is the evidence"
        );
    }

    /// The sticky flag must not strand a peer that never had a TSMP key: control sending nothing
    /// leaves no key material at all, and the key control sends next must become the active one.
    ///
    /// This is the case Go covers by nil-ing the endpoint's `disco` pointer when both keys are
    /// zero; here [`PeerTracker::upsert_from_control`] drops the entry, so the "no control key means
    /// the TSMP slot is active" flag cannot survive to shadow a later control key with nothing.
    #[tokio::test]
    async fn a_first_control_key_is_active_even_after_control_sent_none() {
        let (mut tracker, peer) = tracker_with_control_peer(None);
        assert_eq!(effective_key(&tracker, peer), None, "precondition");
        assert!(
            tracker.endpoint_disco.is_empty(),
            "a peer with no key material from either source costs no entry"
        );

        tracker.apply_peer_update(&control_full(Some(FROM_CONTROL)));
        assert_eq!(
            effective_key(&tracker, peer),
            Some(DiscoPublicKey::from(FROM_CONTROL)),
            "control's first key is active — there is no TSMP key for it to defer to"
        );
        assert_eq!(
            tracker.peer_db.has(&DiscoPublicKey::from(FROM_CONTROL)),
            Some(peer)
        );
    }

    /// The TSMP-learned key lives exactly as long as Go's endpoint does: it is dropped when the peer
    /// leaves the netmap, and it is not carried across a node-key rotation (Go builds the rotated
    /// peer a brand-new endpoint, with a brand-new `endpointDisco`).
    #[tokio::test]
    async fn tsmp_key_does_not_outlive_the_peer_or_its_node_key() {
        let (mut tracker, peer) = tracker_with_control_peer(Some(FROM_CONTROL));
        assert!(tracker.learn_disco_key(peer, DiscoPublicKey::from(ADVERTISED)));

        // The peer leaves the netmap, then comes back on control's key.
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![]));
        assert!(tracker.peer_db.peers().is_empty());
        assert!(
            tracker.endpoint_disco.is_empty(),
            "the departed peer's disco state goes with it"
        );
        tracker.apply_peer_update(&control_full(Some(FROM_CONTROL)));
        let readded = node_from_control(Some(FROM_CONTROL));
        let peer = tracker.peer_db.has(&readded.node_key).expect("re-added");
        assert_eq!(
            effective_key(&tracker, peer),
            Some(DiscoPublicKey::from(FROM_CONTROL)),
            "a peer that left and rejoined starts from control's key again"
        );

        // Learn a key again, then rotate the node key underneath it.
        assert!(tracker.learn_disco_key(peer, DiscoPublicKey::from(READVERTISED)));
        let mut rotated = node_from_control(Some(FROM_CONTROL));
        rotated.node_key = [2u8; 32].into();
        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![rotated.clone()]));
        let peer = tracker
            .peer_db
            .has(&rotated.node_key)
            .expect("rotated peer");
        assert_eq!(
            effective_key(&tracker, peer),
            Some(DiscoPublicKey::from(FROM_CONTROL)),
            "a key learned under the old node key is not carried onto the new one"
        );
        assert_eq!(
            tracker.endpoint_disco.len(),
            1,
            "and the old node key's state is pruned"
        );
    }

    /// How the peer db resolves `key` for an inbound disco frame: the peer it belongs to and which
    /// of that peer's two slots it matched.
    fn ingress_match(
        tracker: &PeerTracker,
        key: DiscoPublicKey,
    ) -> Option<(PeerId, peer_db::DiscoKeyMatch)> {
        tracker
            .peer_db
            .peer_by_known_disco_key(&key)
            .map(|(id, _node, matched)| (id, matched))
    }

    /// The bead's case, end to end: the peer advertised K2 over TSMP so we send to K2, but it is
    /// still sending disco under the K1 control gave us. That frame must resolve to the peer, and
    /// receiving under K1 must make K1 the key we send to — because it is demonstrably what the
    /// peer uses.
    ///
    /// Go: every inbound disco comparison goes through `endpoint.checkAndUpdateDiscoKey`, which
    /// accepts either slot and compare-and-swaps `tsmpActive` when the key seen is the inactive one.
    #[tokio::test]
    async fn disco_under_the_inactive_key_is_accepted_and_makes_that_key_active() {
        let (mut tracker, peer) = tracker_with_control_peer(Some(FROM_CONTROL));
        let from_control = DiscoPublicKey::from(FROM_CONTROL);
        let advertised = DiscoPublicKey::from(ADVERTISED);

        assert!(tracker.learn_disco_key(peer, advertised));
        assert_eq!(
            effective_key(&tracker, peer),
            Some(advertised),
            "precondition: we are sending to the TSMP-learned key"
        );
        assert_eq!(
            ingress_match(&tracker, from_control),
            Some((peer, peer_db::DiscoKeyMatch::Inactive)),
            "control's key is still the peer's other known key, and still resolves on ingress"
        );

        // Disco arrives under control's key: accepted, and it becomes the active one.
        assert!(
            tracker.observe_disco_key(peer, from_control),
            "receiving under the inactive key switches the active key"
        );
        assert_eq!(
            effective_key(&tracker, peer),
            Some(from_control),
            "we now send to the key the peer is demonstrably using"
        );
        assert_eq!(
            tracker.peer_db.has(&from_control),
            Some(peer),
            "and it is the key the send-side disco index carries"
        );
        assert_eq!(
            ingress_match(&tracker, from_control),
            Some((peer, peer_db::DiscoKeyMatch::Active))
        );
        assert_eq!(
            ingress_match(&tracker, advertised),
            Some((peer, peer_db::DiscoKeyMatch::Inactive)),
            "the TSMP key is retained in the other slot, so ingress under it still resolves"
        );

        assert!(
            !tracker.observe_disco_key(peer, from_control),
            "a second frame under the now-active key changes nothing (and forces no republish)"
        );

        // And it switches back: the peer resumes sending under the key it advertised.
        assert!(tracker.observe_disco_key(peer, advertised));
        assert_eq!(effective_key(&tracker, peer), Some(advertised));
        assert_eq!(
            ingress_match(&tracker, from_control),
            Some((peer, peer_db::DiscoKeyMatch::Inactive))
        );
    }

    /// The refusal that is the whole security value of the check: a key belonging to NEITHER slot
    /// is rejected, leaving the peer on the key it was on. Plus the two other refusals Go has —
    /// an unknown peer, and a peer with no disco key material at all (`epDisco == nil`).
    #[tokio::test]
    async fn disco_under_a_key_in_neither_slot_is_refused() {
        let (mut tracker, peer) = tracker_with_control_peer(Some(FROM_CONTROL));
        let from_control = DiscoPublicKey::from(FROM_CONTROL);
        let advertised = DiscoPublicKey::from(ADVERTISED);
        let third = DiscoPublicKey::from(READVERTISED);

        assert!(tracker.learn_disco_key(peer, advertised));

        assert!(
            !tracker.observe_disco_key(peer, third),
            "a third key is refused: a peer must not move itself onto a key nobody told us about"
        );
        assert_eq!(
            effective_key(&tracker, peer),
            Some(advertised),
            "and the peer stays on the key it was on"
        );
        assert_eq!(
            ingress_match(&tracker, third),
            None,
            "the refused key never becomes resolvable"
        );
        assert_eq!(
            ingress_match(&tracker, from_control),
            Some((peer, peer_db::DiscoKeyMatch::Inactive)),
            "the two real slots are untouched"
        );

        // An unknown peer: like a TSMP advertisement, this never creates one.
        assert!(!tracker.observe_disco_key(PeerId(4242), from_control));
        assert_eq!(tracker.peer_db.peers().len(), 1);

        // A peer with no disco key from either source — Go returns false on `epDisco == nil`.
        let (mut bare, bare_peer) = tracker_with_control_peer(None);
        assert_eq!(effective_key(&bare, bare_peer), None, "precondition");
        assert!(
            !bare.observe_disco_key(bare_peer, from_control),
            "a peer with no known disco key has no slot for this key to match"
        );
        assert_eq!(effective_key(&bare, bare_peer), None);
    }

    /// A peer that has only ever had one key registers no inactive key at all, so the second index
    /// stays empty and an inbound frame under any other key is refused.
    #[tokio::test]
    async fn a_single_key_peer_has_no_second_slot() {
        let (tracker, peer) = tracker_with_control_peer(Some(FROM_CONTROL));
        let from_control = DiscoPublicKey::from(FROM_CONTROL);

        assert_eq!(
            ingress_match(&tracker, from_control),
            Some((peer, peer_db::DiscoKeyMatch::Active))
        );
        assert_eq!(
            ingress_match(&tracker, DiscoPublicKey::from(ADVERTISED)),
            None,
            "no second key was ever learned, so nothing else resolves to this peer"
        );
    }

    /// An advertisement that merely restates control's key must not leave the peer with the same
    /// key in both slots pretending to be two — `inactive_key` reports `None` when the inactive
    /// slot holds the active key, so ingress sees exactly one key.
    #[tokio::test]
    async fn the_same_key_in_both_slots_is_one_key() {
        let (mut tracker, peer) = tracker_with_control_peer(Some(FROM_CONTROL));
        let from_control = DiscoPublicKey::from(FROM_CONTROL);

        assert!(tracker.learn_disco_key(peer, from_control));
        assert_eq!(
            tracker
                .endpoint_disco
                .get(&PEER_NODE_KEY.into())
                .and_then(EndpointDisco::inactive_key),
            None,
            "both slots hold the same key, so there is no second key"
        );
        assert_eq!(
            ingress_match(&tracker, from_control),
            Some((peer, peer_db::DiscoKeyMatch::Active))
        );
        assert!(
            !tracker.observe_disco_key(peer, from_control),
            "and receiving under it is a no-op, not a switch"
        );
    }

    /// A peer that leaves the netmap takes BOTH its keys with it: the inactive-key index must not
    /// keep attributing frames to a peer that is gone.
    #[tokio::test]
    async fn a_departed_peer_stops_resolving_under_either_key() {
        let (mut tracker, peer) = tracker_with_control_peer(Some(FROM_CONTROL));
        let advertised = DiscoPublicKey::from(ADVERTISED);
        assert!(tracker.learn_disco_key(peer, advertised));
        assert!(ingress_match(&tracker, DiscoPublicKey::from(FROM_CONTROL)).is_some());

        tracker.apply_peer_update(&ts_control::PeerUpdate::Full(vec![]));
        assert_eq!(ingress_match(&tracker, advertised), None);
        assert_eq!(
            ingress_match(&tracker, DiscoPublicKey::from(FROM_CONTROL)),
            None,
            "the inactive key is retracted with the peer, not left dangling"
        );
    }
}
