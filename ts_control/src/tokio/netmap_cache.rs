//! Persistent netmap cache (`nodecap.CacheNetworkMaps`, capability version 135).
//!
//! Control can ask a node to keep the last network map it received on disk and use it on the next
//! cold start, so the node can begin re-establishing peer connectivity before control has answered
//! its first map poll. Upstream Go carries this in `ipn/ipnlocal/netmapcache` (the store) and
//! `ipn/ipnlocal/diskcache.go` + `local.go` (the policy); the two node attributes are
//! `tailcfg/nodecap/nodecap.go` `CacheNetworkMaps` / `DisableCacheNetworkMaps` (upstream
//! `72780705eda81790e839a0793a90bdea4164d3ca`).
//!
//! **Caching is off unless control asks for it.** Go's contract, verbatim from `nodecap.go`: "When
//! this attribute is absent (or removed), a node that supports netmap caching will ignore and
//! discard existing cached maps, and will not store any." `DisableCacheNetworkMaps` exists so a
//! policy document can override the grant and "takes precedence over `CacheNetworkMaps`". Both are
//! honoured here — see [`netmap_caching_enabled`].
//!
//! **What is persisted.** Go stores the assembled `netmap.NetworkMap` column by column
//! (`netmapcache.Cache.Store` writes the self node, DNS config, DERP map and packet filter whether
//! or not the map has peers). This port has no `NetworkMap` aggregate (the netmap is consumed as a
//! [`StateUpdate`] stream), so the cache keeps the *raw decompressed `MapResponse` JSON* of the last
//! **self-contained netmap frame** and replays it through the same decoder the live poll uses. A
//! frame is self-contained when it carries a self node and either control's complete peer list
//! (`MapResponse.Peers` non-empty — Go's own "if non-empty, is the complete list" signal) or no peer
//! information at all alongside a DERP map, which is control's opening netmap for a node with no
//! visible peers. See `cacheable`.
//!
//! Delta frames are never persisted, because replaying a delta on a cold start would install a
//! partial netmap, and a peerless frame never evicts a cached peer list. The cache therefore holds
//! the last self-contained netmap, not a continuously-updated one: Go's per-peer delta merge into
//! the cache (`writePeerDeltaToDiskLocked` → `netmapcache.Cache.UpdatePeers`) is **not** ported, so
//! between two full netmaps the cached peer list ages by every delta control sends, and a cold start
//! can replay a peer that has since been removed until control's first netmap lands.
//!
//! **The persisted material is sensitive.** A `MapResponse` carries the tailnet's peer list with
//! their node/disco public keys and endpoints, the DNS configuration, and the compiled packet
//! filter. The cache directory is created `0700` and the file is written `0600` (Go writes its
//! cache entries `0600` in `netmapcache.FileStore.Store`); on a platform without Unix modes the
//! file inherits the directory's ACL. Nothing is written at all unless the embedder configured
//! [`Config::netmap_cache_dir`](crate::Config::netmap_cache_dir) *and* control granted the
//! attribute.
//!
//! **A private directory is required, not assumed.** Creating a directory `0700` says nothing
//! about a directory that already existed — `DirBuilder` leaves an existing directory's mode and
//! owner exactly as they are — so both ends of the cache *check* rather than assume. The netmap is
//! written only into a directory this user owns with no group/other permission bits, and only
//! through a freshly created `0600` file; it is read back only from such a directory, through an
//! `O_NOFOLLOW` open of a regular `0600` file this user owns. Anything that fails the check is
//! refused: nothing is cached, and nothing is replayed. The alternative is handing the tailnet's
//! peer keys to every local user, or letting one of them choose the netmap this node starts from.
//! Only the cache directory itself is vetted, not its ancestors — the embedder picks the root, and
//! a state directory reachable through a world-writable parent is the embedder's to fix.
//!
//! **Peers cached while Tailnet Lock was on are replayed only if the caller vouches for them** —
//! see [`NetmapCache::load_state_update_vouched`]. The cache also carries a second, opaque entry
//! next to the netmap ([`TKA_CHAIN_CACHE_FILE`]) that the runtime uses to persist the Tailnet-Lock
//! authority the cached peers were admitted under, so a cold start can run that vouching before
//! control has answered. This module never decodes that entry — it stores and vets bytes.

use std::path::{Path, PathBuf};

use super::map_stream::{PeerUpdate, StateUpdate, state_update_from_frame};
use crate::NodeCapMap;

/// The node attribute by which control asks this node to persist network maps and use them on the
/// next start (Go `tailcfg.NodeAttrCacheNetworkMaps` / `nodecap.CacheNetworkMaps`).
pub const NODE_ATTR_CACHE_NETWORK_MAPS: &str = "cache-network-maps";

/// The node attribute that suppresses netmap persistence even when
/// [`NODE_ATTR_CACHE_NETWORK_MAPS`] is also granted (Go `nodecap.DisableCacheNetworkMaps`,
/// tailscale/tailscale#19947). It exists so a policy document can override the grant, and Go
/// documents it as taking precedence — so it is checked first and wins.
///
/// **Deliberately ahead of the shipped Go.** Upstream declares this attribute and aliases it as
/// `tailcfg.NodeAttrDisableCacheNetworkMaps`, but as of `9ea7cba44591e0cd840c6c94d23274dd222059bf`
/// no code reads it: both cache decision sites in `ipn/ipnlocal/local.go` gate on
/// `SelfHasCap(nodecap.CacheNetworkMaps)` and the `TS_USE_CACHED_NETMAP` envknob alone, so a Go node
/// granted both attributes still caches. This port implements the contract the attribute documents
/// rather than the one the current tree happens to enforce, because the attribute exists to let a
/// tailnet's policy say "do not write this node's peer keys, DNS config and packet filter to disk",
/// and a client that ignores it writes them anyway. The divergence only ever *withholds* a cache,
/// so its whole cost is cold-start latency on a node whose policy asked for exactly that.
pub const NODE_ATTR_DISABLE_CACHE_NETWORK_MAPS: &str = "disable-cache-network-maps";

/// File name of the cached netmap frame under [`NetmapCache`]'s directory.
pub const NETMAP_CACHE_FILE: &str = "netmap.json";

/// Name of the temporary file the cache writes before renaming it over [`NETMAP_CACHE_FILE`], so a
/// crash mid-write cannot leave a half-written netmap behind for the next cold start to read.
const NETMAP_CACHE_TMP_FILE: &str = "netmap.json.tmp";

/// File name, under [`NetmapCache`]'s directory, of the Tailnet-Lock chain the cached netmap's
/// peers were admitted under.
///
/// Written and read by the runtime (`ts_runtime`), which owns every TKA type; this crate deliberately
/// knows nothing of `ts_tka` and treats the entry as **opaque bytes**. It lives here so it shares the
/// netmap cache's directory vetting, its private-file write, and its lifetime: the two entries are
/// only ever useful together, and [`NetmapCache::discard`] drops both.
pub const TKA_CHAIN_CACHE_FILE: &str = "tka-chain";

/// Temporary file for [`TKA_CHAIN_CACHE_FILE`], renamed into place like the netmap's.
const TKA_CHAIN_CACHE_TMP_FILE: &str = "tka-chain.tmp";

/// Whether control's node attributes ask this node to persist network maps.
///
/// Fail-closed and disable-wins, mirroring Go: the grant
/// ([`NODE_ATTR_CACHE_NETWORK_MAPS`]) must be present, and
/// [`NODE_ATTR_DISABLE_CACHE_NETWORK_MAPS`] must not be — a node holding both does **not** cache,
/// because Go documents the disabling attribute as taking precedence over the enabling one. A node
/// holding neither does not cache either, which is the conformant default: a client that never
/// caches is a valid client, and the cost is cold-start latency only.
pub fn netmap_caching_enabled(cap_map: &NodeCapMap) -> bool {
    !cap_map.contains_key(NODE_ATTR_DISABLE_CACHE_NETWORK_MAPS)
        && cap_map.contains_key(NODE_ATTR_CACHE_NETWORK_MAPS)
}

/// An on-disk cache of the last full network map, rooted at one directory.
///
/// Constructed from [`Config::netmap_cache_dir`](crate::Config::netmap_cache_dir). Cheap to clone
/// (it is a path); all I/O errors are logged and swallowed — a cache is an optimization, and losing
/// it must never take the netmap stream or the node's start-up down with it.
#[derive(Debug, Clone)]
pub struct NetmapCache {
    dir: PathBuf,
}

impl NetmapCache {
    /// A cache rooted at `dir`. The directory is created (mode `0700` on Unix) on the first write,
    /// not here, so constructing a cache for a node control never grants the attribute to touches
    /// the filesystem exactly zero times.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The file the cached netmap frame lives in.
    pub fn path(&self) -> PathBuf {
        self.dir.join(NETMAP_CACHE_FILE)
    }

    /// The file the [Tailnet-Lock chain][TKA_CHAIN_CACHE_FILE] lives in.
    pub fn tka_chain_path(&self) -> PathBuf {
        self.dir.join(TKA_CHAIN_CACHE_FILE)
    }

    /// Apply the cache policy to one decoded netmap frame and the raw bytes it was decoded from.
    ///
    /// Mirrors the two Go call sites that maintain the cache on every installed netmap
    /// (`ipnlocal.setNetMapLocked`): persist when control grants the attribute, otherwise discard
    /// whatever is on disk. The decision is taken from the **self node carried by this frame**, so
    /// a frame that carries no self node leaves the cache exactly as it was (control sends plenty of
    /// peer-only and keep-alive frames, and none of them re-state the node's attributes).
    ///
    /// What counts as a frame worth persisting is `cacheable`'s job.
    pub async fn observe(&self, update: &StateUpdate, frame: &[u8]) {
        let Some(node) = update.node.as_ref() else {
            return;
        };

        if !netmap_caching_enabled(&node.cap_map) {
            // Go: "When this attribute is absent (or removed), a node that supports netmap caching
            // will ignore and discard existing cached maps, and will not store any."
            self.discard().await;
            return;
        }

        match cacheable(update) {
            // A delta frame, or anything else that is only a piece of the netmap. Replaying one on a
            // cold start would install a partial netmap (the peers that happened to change last, and
            // nothing else), which is worse than no cache at all.
            Cacheable::No => return,
            Cacheable::WithPeers => {}
            // A netmap with no peers in it. Go caches these — its `Store` writes the self node, DNS
            // config, DERP map and packet filter whatever the peer count — and they are the only
            // netmap a node with no visible peers ever gets, so without this such a node has no cache
            // at all. But this port classifies frames, not an assembled map, so it declines to let
            // one *replace* a cached peer list: a frame that looks peerless because control chose to
            // re-state the netmap head without repeating the peers would otherwise throw the peers
            // away. Go cannot make that mistake (it always writes back a complete aggregate), and
            // keeping the richer cache is the same answer this cache gave before peerless netmaps
            // were stored at all.
            Cacheable::WithoutPeers => {
                if self.cached_netmap_has_peers().await {
                    return;
                }
            }
        }

        if let Err(e) = self.store(frame).await {
            tracing::warn!(error = %e, path = %self.path().display(), "writing netmap cache");
        }
    }

    /// Persist `frame` (the raw decompressed `MapResponse` JSON) as the cached netmap.
    ///
    /// Written to a temporary file and renamed into place so a torn write is never observable, with
    /// the directory `0700` and the file `0600` on Unix — the frame carries peer keys, endpoints,
    /// DNS configuration and the packet filter. A directory that is not private to this user is
    /// refused ([`create_dir_private`]) and nothing is written; the caller logs and carries on
    /// without a cache, which is always a safe outcome.
    async fn store(&self, frame: &[u8]) -> std::io::Result<()> {
        self.store_entry(NETMAP_CACHE_FILE, NETMAP_CACHE_TMP_FILE, frame)
            .await
    }

    /// Persist `bytes` as the cache entry `name`, staged through `tmp_name` and renamed into place.
    ///
    /// The one write path both cache entries take, so the netmap and the Tailnet-Lock chain get the
    /// same directory vetting, the same freshly-created `0600` file, and the same torn-write-proof
    /// rename. Anything the vetting refuses is an error the caller logs and carries on without.
    async fn store_entry(&self, name: &str, tmp_name: &str, bytes: &[u8]) -> std::io::Result<()> {
        create_dir_private(&self.dir).await?;

        let tmp = self.dir.join(tmp_name);
        write_private(&tmp, bytes).await?;
        tokio::fs::rename(&tmp, self.dir.join(name)).await
    }

    /// Persist the Tailnet-Lock chain the cached netmap's peers were admitted under.
    ///
    /// `chain` is opaque here: the runtime encodes it (and is the only thing that decodes it), so
    /// this crate keeps its rule of never depending on `ts_tka`. Written exactly like the netmap —
    /// same private directory, same `0600` file — because it decides which cached peers a cold start
    /// dials, and a chain another local user could choose would decide it for us. Errors are logged
    /// and swallowed: without a chain the replay simply withholds the peers.
    pub async fn store_tka_chain(&self, chain: &[u8]) {
        if let Err(e) = self
            .store_entry(TKA_CHAIN_CACHE_FILE, TKA_CHAIN_CACHE_TMP_FILE, chain)
            .await
        {
            tracing::warn!(error = %e, path = %self.tka_chain_path().display(), "writing tailnet-lock chain cache");
        }
    }

    /// The persisted Tailnet-Lock chain, or `None` when there is none (or it could not be vouched
    /// for). Vetted exactly like the netmap; a refusal is a cold start with no chain, which withholds
    /// the cached peers.
    pub async fn load_tka_chain(&self) -> Option<Vec<u8>> {
        self.load_entry(TKA_CHAIN_CACHE_FILE).await
    }

    /// Remove the persisted Tailnet-Lock chain, if any (the lock was disabled, or the chain no longer
    /// describes the cached netmap). Leaves the cached netmap alone — its peers are then withheld.
    pub async fn discard_tka_chain(&self) {
        remove_entry(&self.tka_chain_path()).await;
    }

    /// The cached netmap frame, or `None` when nothing has been cached (or it could not be read).
    ///
    /// A refusal — an unreadable file, a directory or file that is not private to this user, a
    /// symlink where the cache file should be — is `None` here and therefore a cold start with no
    /// cache, which is exactly the behaviour of a node that never cached anything.
    async fn load(&self) -> Option<Vec<u8>> {
        self.load_entry(NETMAP_CACHE_FILE).await
    }

    /// Whether the netmap currently on disk carries a peer list, i.e. whether replacing it with a
    /// peerless frame would lose peers a cold start could otherwise dial.
    ///
    /// `false` when there is nothing cached, when what is cached fails the vetting, and when it no
    /// longer decodes — in all three cases there are no peers to protect, and the caller should go
    /// ahead and write. Only consulted for a [peerless][Cacheable::WithoutPeers] frame, which is
    /// control's opening netmap for a peerless node rather than anything mid-session, so this costs
    /// one read per map session at most.
    async fn cached_netmap_has_peers(&self) -> bool {
        let Some(frame) = self.load().await else {
            return false;
        };
        state_update_from_frame(&frame)
            .is_some_and(|cached| matches!(cached.peer_update, Some(PeerUpdate::Full(_))))
    }

    /// Read the cache entry `name`, or `None` when it is absent or fails the vetting below.
    async fn load_entry(&self, name: &str) -> Option<Vec<u8>> {
        let path = self.dir.join(name);
        match self.read_cached(&path).await {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                tracing::warn!(error = %e, path = %path.display(), "reading netmap cache");
                None
            }
        }
    }

    /// Read the cached frame, refusing anything a local attacker could have chosen.
    ///
    /// The directory is vetted before the file because the file's own mode is worth nothing inside a
    /// directory other users can write: they cannot open our `0600` file, but they can replace it,
    /// and a replayed netmap installs peers, a DERP map, a DNS configuration and a packet filter.
    /// That is the whole cold-start state of the node, so this path fails closed on anything it
    /// cannot vouch for.
    async fn read_cached(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        let dir = tokio::fs::symlink_metadata(&self.dir).await?;
        ensure_private(&self.dir, &dir, Entry::Dir)?;
        read_private(path).await
    }

    /// Remove the cached netmap **and** the Tailnet-Lock chain that vouches for its peers, if any.
    /// Errors are logged, never propagated: the cache is being thrown away, so failing to throw it
    /// away is not something a caller can act on.
    ///
    /// Both entries go together. The chain exists only to say which of the cached peers may be
    /// replayed, so keeping it after the netmap it describes is gone would leave a tailnet's key
    /// authority on disk for nothing.
    pub async fn discard(&self) {
        remove_entry(&self.path()).await;
        remove_entry(&self.tka_chain_path()).await;
    }

    /// The cached netmap, decoded into a [`StateUpdate`] ready to publish on a cold start.
    ///
    /// Decoded by the same (crate-private) frame decoder the live map poll runs every wire frame
    /// through, so a replayed netmap and a freshly-received one are built identically. Three fields
    /// of the live frame are deliberately dropped, because they describe the *session* the frame
    /// arrived on rather than the netmap it carried, and that session is long gone:
    ///
    /// * `session_handle` / `seq` — the resume cursor for a map session this process never opened.
    ///   Replaying them would offer control a cursor into someone else's stream.
    /// * `ping` — control's request to probe something, answered at the time it was asked. Firing a
    ///   stale probe at start-up is at best noise.
    ///
    /// Loading is *not* gated on the node attributes: nothing is ever written without the grant, so
    /// (as Go puts it) the presence of a cache is itself the record that the node was told to keep
    /// one. If the grant has since been withdrawn, the first netmap of this session says so and
    /// [`observe`](Self::observe) discards the cache then.
    ///
    /// **Peers cached under an active Tailnet Lock are replayed only if a caller vouches for them**
    /// — this method has no vouching caller, so it withholds them. Use
    /// [`load_state_update_vouched`](Self::load_state_update_vouched) to supply the verdict.
    pub async fn load_state_update(&self) -> Option<StateUpdate> {
        self.load_state_update_vouched(|_, _| Vec::new()).await
    }

    /// [`load_state_update`](Self::load_state_update), with `vouch` deciding which peers a netmap
    /// cached under an **active** Tailnet Lock replays.
    ///
    /// Go replays its cached map through the same `setNetMapLocked` a live one takes, so
    /// `tkaFilterNetmapLocked` (`ipn/ipnlocal/tailnet-lock.go`) runs over it and drops only the peers
    /// that fail it — an unsigned peer, one whose `NodeKeyAuthorized` check errors, or one a newer
    /// rotation obsoletes. The peers holding a valid signature survive and are dialed before control
    /// answers, which is the entire point of the cache. Go can run that filter at cold start because
    /// its TKA authority is persisted on disk and already loaded by then.
    ///
    /// This crate cannot run it: it deliberately depends on nothing TKA (`ts_tka` lives above it), so
    /// it can decode `MapResponse.TKAInfo` but cannot verify a `key_signature`. So it asks. `vouch`
    /// receives the lock the peers were cached under and the cached peers, and returns the ones to
    /// replay — the runtime answers it with the authority it persisted next to this netmap
    /// ([`TKA_CHAIN_CACHE_FILE`]), running the same filter the live netmap path runs. A caller with
    /// no authority to answer with returns nothing and the peers are withheld, which is where
    /// [`load_state_update`](Self::load_state_update) lands: safe, because the rest of the netmap
    /// (self node, DERP map, DNS, packet filter) carries no peer identity, and magicsock admits no
    /// traffic from a key the peer set does not contain.
    ///
    /// `vouch` is **not** consulted when the cached frame says the lock was off — there is nothing to
    /// enforce then and every peer replays, exactly as Go's filter returns early on `b.tka == nil`.
    /// Reading the lock state from the cached frame is sound for the frames this cache holds: only a
    /// self-contained, non-delta netmap is ever stored (see `cacheable`), and `tailcfg` documents
    /// `TKAInfo` on a non-delta `MapResponse` as authoritative in both directions — populated means
    /// control believes the lock is on for this node, absent means it believes it is off.
    ///
    /// Peer *patches* (`MapResponse.PeersChangedPatch`) are always dropped under an active lock: a
    /// patch carries no `key_signature`, so there is nothing for `vouch` to judge, and Go's filter
    /// likewise only ever sees whole peers.
    pub async fn load_state_update_vouched<F>(&self, vouch: F) -> Option<StateUpdate>
    where
        F: FnOnce(&crate::TkaStatus, Vec<crate::Node>) -> Vec<crate::Node>,
    {
        let frame = self.load().await?;
        let mut update = state_update_from_frame(&frame)?;

        update.session_handle = None;
        update.seq = 0;
        update.ping = None;

        let Some(tka) = update.tka.as_ref().filter(|t| t.is_enabled()).cloned() else {
            return Some(update);
        };

        let cached = match update.peer_update.take() {
            Some(PeerUpdate::Full(peers)) => peers,
            // Only a self-contained netmap is ever cached, and a peerless one carries no peer set to
            // vouch for, so there is nothing to replay.
            _ => Vec::new(),
        };
        let cached_count = cached.len();
        let vouched = vouch(&tka, cached);
        tracing::info!(
            cached = cached_count,
            replayed = vouched.len(),
            "cached netmap was taken under Tailnet Lock; replaying only the peers vouched for"
        );

        // An empty verdict replays no peer update at all rather than an empty *complete* peer list.
        // At cold start the two install identically (the peer db starts empty), and this keeps a
        // caller that can vouch for nothing on exactly the path a node with no cached peers takes.
        update.peer_update = (!vouched.is_empty()).then_some(PeerUpdate::Full(vouched));
        update.peer_patches.clear();

        Some(update)
    }
}

/// What one decoded frame is worth to the cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cacheable {
    /// A netmap carrying control's complete peer list. Always persisted.
    WithPeers,
    /// A netmap carrying no peer information at all. Persisted only over a cache that has no peers
    /// of its own — see [`NetmapCache::observe`].
    WithoutPeers,
    /// A piece of a netmap: a delta, a patch, an online/last-seen flip, or a self-node update with
    /// nothing else in it. Never persisted.
    No,
}

/// Classify one frame for the cache.
///
/// Go never has to do this: `ipnlocal` caches the *assembled* `netmap.NetworkMap`, so every install
/// writes a complete map back. Here the unit of storage is the frame control sent, so the frame has
/// to be complete on its own or a cold start replays a fragment.
///
/// * **[`WithPeers`](Cacheable::WithPeers)** — `MapResponse.Peers` non-empty, which `tailcfg`
///   defines as the complete peer list. This is control's opening netmap for a node with peers.
/// * **[`WithoutPeers`](Cacheable::WithoutPeers)** — no peer information of any kind (no `Peers`,
///   no `PeersChanged`/`PeersRemoved`/`PeersChangedPatch`, no `OnlineChange`/`PeerSeenChange`) plus
///   a DERP map. Control's opening netmap always carries the DERP map, and a node that sees no peers
///   gets no other kind of netmap, so this is how a peerless tailnet gets a cache — the case Go
///   covers with `netmapcache.Cache.Store` over a zero-peer `NetworkMap`. Requiring the DERP map is
///   what keeps a mid-session self-node update (a cap-map or endpoint change, which carries a self
///   node and nothing else) out of the cache.
/// * **[`No`](Cacheable::No)** — anything else.
///
/// The caller has already established that the frame carries a self node.
fn cacheable(update: &StateUpdate) -> Cacheable {
    if matches!(update.peer_update, Some(PeerUpdate::Full(_))) {
        return Cacheable::WithPeers;
    }

    let carries_peer_deltas = update.peer_update.is_some()
        || !update.peer_patches.is_empty()
        || !update.online_change.is_empty()
        || !update.peer_seen_change.is_empty();

    if !carries_peer_deltas && update.derp.is_some() {
        Cacheable::WithoutPeers
    } else {
        Cacheable::No
    }
}

/// Remove one cache entry, logging (never propagating) anything but its absence — the entry is being
/// thrown away, so failing to throw it away is not something a caller can act on.
async fn remove_entry(path: &Path) {
    match tokio::fs::remove_file(path).await {
        Ok(()) => tracing::debug!(path = %path.display(), "discarded netmap cache entry"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "discarding netmap cache entry")
        }
    }
}

/// Create `dir` (and its parents) private to this user — `0700` on Unix, the platform default
/// elsewhere — and **require** that a directory that already exists is private too.
///
/// `DirBuilder::recursive` succeeds on an existing directory and leaves its mode and owner exactly
/// as they are, so "created `0700`" says nothing about the directory the cache actually writes
/// into. A `0755` directory left by an older writer, one another user made first, or one the
/// embedder pointed at deliberately would take the netmap all the same — and the netmap is the
/// tailnet's peer keys, endpoints, DNS names and packet filter. So the directory is checked, and a
/// directory that fails the check fails the write: the cache is an optimization, and not having one
/// is always safe.
///
/// The check is re-run after a successful create because `recursive(true)` also succeeds when the
/// directory already exists — including one that appeared between the check above and the create.
async fn create_dir_private(dir: &Path) -> std::io::Result<()> {
    match tokio::fs::symlink_metadata(dir).await {
        Ok(meta) => return ensure_private(dir, &meta, Entry::Dir),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    let mut builder = tokio::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        builder.mode(0o700);
    }
    builder.create(dir).await?;

    let meta = tokio::fs::symlink_metadata(dir).await?;
    ensure_private(dir, &meta, Entry::Dir)
}

/// Write `bytes` to a file this call creates at `path`, `0600` on Unix (Go's
/// `netmapcache.FileStore` writes its cache entries with the same mode).
///
/// Exclusive creation, not truncation: `OpenOptions::mode` applies only to a file the open
/// *creates*, so opening something already at `path` would write the netmap into a file whose mode
/// somebody else chose — a stale temporary file from a write that crashed, or a symlink another
/// user planted. Unlink first and then refuse to open anything but a file we made, so the `0600` is
/// a fact about the file the netmap lands in rather than a hope.
async fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt as _;

    if let Err(e) = tokio::fs::remove_file(path).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(e);
    }

    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        opts.mode(0o600);
    }

    let mut file = opts.open(path).await?;
    file.write_all(bytes).await?;
    file.flush().await
}

/// Read `path`, refusing to read anything but a regular file private to this user.
///
/// `O_NOFOLLOW` so a symlink at the cache path is an error rather than a redirect, and the vetting
/// runs on the *open handle* (`fstat`) rather than on the path, so what is checked is exactly what
/// is then read.
async fn read_private(path: &Path) -> std::io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt as _;

    let mut opts = tokio::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        opts.custom_flags(libc::O_NOFOLLOW);
    }

    let mut file = opts.open(path).await?;
    ensure_private(path, &file.metadata().await?, Entry::File)?;

    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).await?;
    Ok(bytes)
}

/// What [`ensure_private`] was asked to vet.
#[derive(Clone, Copy)]
enum Entry {
    /// The cache directory.
    Dir,
    /// A file inside it.
    File,
}

/// Fail unless `meta` describes an entry of `kind` that no other local user can reach: the right
/// type, owned by the effective uid, and carrying no group or other permission bits.
///
/// `meta` must come from a `symlink_metadata` or from an already-open handle, never from a
/// path-following `metadata` — `is_dir`/`is_file` are then false for a symlink, so a symlink can
/// never pass. On a platform without Unix modes only the type is checked and the entry inherits the
/// directory's ACL, as the module doc says.
fn ensure_private(path: &Path, meta: &std::fs::Metadata, kind: Entry) -> std::io::Result<()> {
    let (ok, want) = match kind {
        Entry::Dir => (meta.is_dir(), "a directory"),
        Entry::File => (meta.is_file(), "a regular file"),
    };
    if !ok {
        return Err(refused(path, &alloc::format!("not {want}")));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        // SAFETY: `geteuid` cannot fail, takes no arguments and touches no memory.
        let euid = unsafe { libc::geteuid() };
        if meta.uid() != euid {
            return Err(refused(path, "owned by another user"));
        }
        if meta.mode() & 0o077 != 0 {
            return Err(refused(path, "readable or writable by other users"));
        }
    }

    Ok(())
}

/// The error a failed [`ensure_private`] returns. `PermissionDenied` because that is what it is:
/// the cache declines to use a location it cannot keep to itself.
fn refused(path: &Path, why: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        alloc::format!("refusing the netmap cache at {}: {why}", path.display()),
    )
}

#[cfg(test)]
mod tests {
    use futures_util::StreamExt as _;

    use super::{super::map_stream::map_stream, *};

    /// Frame a JSON body the way control does on a real map poll: zstd-compressed, prefixed with a
    /// little-endian `u32` length. Feeding the cache through [`map_stream`] rather than calling
    /// [`NetmapCache::observe`] directly is deliberate — the tests then exercise the same path a
    /// live netmap takes, frame bytes and all.
    fn frame(body: &str) -> Vec<u8> {
        let compressed = ruzstd::encoding::compress_to_vec(
            body.as_bytes(),
            ruzstd::encoding::CompressionLevel::Fastest,
        );
        let mut buf = (compressed.len() as u32).to_le_bytes().to_vec();
        buf.extend_from_slice(&compressed);
        buf
    }

    /// A unique, empty scratch directory. No `tempfile` dev-dependency is added for this (the crate
    /// has none, and `cargo deny`/`machete` see every one we add); a pid- and label-keyed directory
    /// under the system temp dir is enough for a test that cleans up after itself.
    fn scratch_dir(label: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ts-rs-netmap-cache-{}-{label}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        dir
    }

    /// A cache over `dir` — the cold-start shape (a fresh `NetmapCache`, nothing in memory).
    fn cache_at(dir: &Path) -> NetmapCache {
        NetmapCache::new(dir)
    }

    /// A full netmap: a self node carrying `cap_map`, one peer, and a DERP map. `cap_map` is
    /// spliced in verbatim so a test can grant, withhold, or contradict the caching attributes.
    fn full_netmap(cap_map: &str) -> String {
        full_netmap_with(cap_map, "")
    }

    /// [`full_netmap`] plus `extra_fields` — a JSON fragment spliced in ahead of the rest, each
    /// field comma-terminated — so a test can state `TKAInfo` (or anything else) on the frame
    /// without rebuilding the whole netmap.
    fn full_netmap_with(cap_map: &str, extra_fields: &str) -> String {
        full_netmap_with_peers(
            cap_map,
            extra_fields,
            r#"{
                "ID": 2,
                "StableID": "peer-2",
                "Name": "peer.example.ts.net.",
                "Addresses": ["100.64.0.2/32"],
                "Endpoints": ["192.0.2.7:41641"],
                "HomeDERP": 3
            }"#,
        )
    }

    /// [`full_netmap_with`] with the `Peers` array spelled out, so a test can cache more than one
    /// peer and check *which* of them a vouching cold start replays.
    fn full_netmap_with_peers(cap_map: &str, extra_fields: &str, peers: &str) -> String {
        format!(
            r#"{{
                {extra_fields}
                "MapSessionHandle": "sess-1",
                "Seq": 9,
                "Node": {{
                    "ID": 1,
                    "StableID": "self-1",
                    "Name": "self.example.ts.net.",
                    "Addresses": ["100.64.0.1/32"],
                    "CapMap": {cap_map}
                }},
                "Peers": [{peers}],
                "DERPMap": {{ "Regions": {{ "3": {{
                    "RegionID": 3,
                    "RegionCode": "tst",
                    "RegionName": "Test",
                    "Nodes": []
                }} }} }},
                "PingRequest": {{
                    "URL": "https://control.example/ping/abc",
                    "URLIsNoise": false,
                    "Types": "disco"
                }}
            }}"#
        )
    }

    /// Control's opening netmap for a node that sees **no peers**: a self node carrying `cap_map`, an
    /// explicitly empty peer list, a DERP map and a DNS config. This is the whole netmap such a node
    /// ever receives, and the DERP map and DNS config in it are exactly what a cold start wants.
    fn peerless_netmap(cap_map: &str) -> String {
        format!(
            r#"{{
                "MapSessionHandle": "sess-1",
                "Seq": 1,
                "Node": {{
                    "ID": 1,
                    "StableID": "self-1",
                    "Name": "self.example.ts.net.",
                    "Addresses": ["100.64.0.1/32"],
                    "CapMap": {cap_map}
                }},
                "Peers": [],
                "DERPMap": {{ "Regions": {{ "3": {{
                    "RegionID": 3,
                    "RegionCode": "tst",
                    "RegionName": "Test",
                    "Nodes": []
                }} }} }},
                "DNSConfig": {{
                    "Resolvers": [{{ "Addr": "192.0.2.53" }}],
                    "Domains": ["example.ts.net"]
                }}
            }}"#
        )
    }

    /// Run one framed netmap through the production map-poll stream with `cache` attached, exactly
    /// as the live control session does.
    async fn poll_one(body: &str, cache: &NetmapCache) {
        let buf = frame(body);
        let mut stream = core::pin::pin!(map_stream(&buf[..], Some(cache.clone())));
        stream.next().await.expect("one netmap");
    }

    /// The headline behaviour: with `cache-network-maps` granted, a full netmap is persisted, and a
    /// *fresh* cache over the same directory — the cold-start case, a new process that has not
    /// spoken to control — decodes it back into the netmap the node had.
    #[tokio::test]
    async fn cached_netmap_is_used_on_cold_start() {
        let dir = scratch_dir("cold-start");
        let cache = NetmapCache::new(&dir);

        poll_one(&full_netmap(r#"{"cache-network-maps": null}"#), &cache).await;

        // Cold start: nothing in memory, only what is on disk.
        let replayed = NetmapCache::new(&dir)
            .load_state_update()
            .await
            .expect("a cached netmap must be replayable on cold start");

        let node = replayed.node.as_ref().expect("self node");
        assert_eq!(node.stable_id.0, "self-1");
        assert!(
            netmap_caching_enabled(&node.cap_map),
            "the replayed self node must carry the attribute that made it cacheable"
        );

        let Some(PeerUpdate::Full(peers)) = replayed.peer_update.as_ref() else {
            panic!(
                "the cached netmap must replay a full peer set, got {:?}",
                replayed.peer_update
            );
        };
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].stable_id.0, "peer-2");
        assert_eq!(
            peers[0].underlay_addresses,
            vec!["192.0.2.7:41641".parse().unwrap()],
            "the peer's endpoints are the point of the cache: they are what a cold start dials"
        );
        assert!(
            replayed.derp.is_some(),
            "the DERP map must survive the round trip; without it a cold start has no relay"
        );

        // Session-scoped fields belong to the poll the frame arrived on, not to the netmap, and
        // that session is gone.
        assert_eq!(replayed.session_handle, None);
        assert_eq!(replayed.seq, 0);
        assert!(replayed.ping.is_none(), "a stale ping must not be replayed");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// `disable-cache-network-maps` takes precedence over `cache-network-maps` (Go
    /// `nodecap.DisableCacheNetworkMaps`: "When set, it takes precedence"). A node granted both
    /// must not persist anything, so a cold start finds nothing to replay.
    #[tokio::test]
    async fn disable_cache_network_maps_suppresses_the_cache() {
        let dir = scratch_dir("disable-attr");
        let cache = NetmapCache::new(&dir);

        poll_one(
            &full_netmap(r#"{"cache-network-maps": null, "disable-cache-network-maps": null}"#),
            &cache,
        )
        .await;

        assert!(
            !cache.path().exists(),
            "disable-cache-network-maps must suppress the write even when the enabling \
             attribute is also granted"
        );
        assert!(
            NetmapCache::new(&dir).load_state_update().await.is_none(),
            "a suppressed cache must leave a cold start with nothing to replay"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A netmap that withdraws the grant must delete what was cached under it — Go: "When this
    /// attribute is absent (or removed), a node that supports netmap caching will ignore and
    /// discard existing cached maps". Covers both ways to withdraw it: dropping the attribute, and
    /// overriding it with the disabling one.
    #[tokio::test]
    async fn withdrawing_the_attribute_discards_an_existing_cache() {
        for (label, cap_map) in [
            ("dropped", "{}"),
            (
                "overridden",
                r#"{"cache-network-maps": null, "disable-cache-network-maps": null}"#,
            ),
        ] {
            let dir = scratch_dir(&format!("withdraw-{label}"));
            let cache = NetmapCache::new(&dir);

            poll_one(&full_netmap(r#"{"cache-network-maps": null}"#), &cache).await;
            assert!(cache.path().exists(), "{label}: the grant must cache first");

            poll_one(&full_netmap(cap_map), &cache).await;
            assert!(
                !cache.path().exists(),
                "{label}: withdrawing the grant must discard the cached netmap"
            );

            std::fs::remove_dir_all(&dir).ok();
        }
    }

    /// A node control never granted the attribute writes nothing at all — not even the directory.
    /// A client that does not cache is conformant, and this is the default.
    #[tokio::test]
    async fn no_attribute_never_caches() {
        let dir = scratch_dir("no-attr");
        let cache = NetmapCache::new(&dir);

        poll_one(&full_netmap("{}"), &cache).await;

        assert!(
            !dir.exists(),
            "an ungranted node must not so much as create the cache directory"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Only a frame whose peer list control marked complete is cacheable. A delta frame — the
    /// common case mid-session — must leave the cached full netmap alone rather than replace it
    /// with the handful of peers that happened to change.
    #[tokio::test]
    async fn delta_frames_do_not_replace_the_cached_full_netmap() {
        let dir = scratch_dir("delta");
        let cache = NetmapCache::new(&dir);

        poll_one(&full_netmap(r#"{"cache-network-maps": null}"#), &cache).await;
        let cached = std::fs::read(cache.path()).expect("cached netmap");

        poll_one(
            r#"{
                "Seq": 10,
                "Node": { "ID": 1, "StableID": "self-1", "CapMap": {"cache-network-maps": null} },
                "PeersChanged": [{ "ID": 3, "StableID": "peer-3", "Name": "late.example.ts.net." }]
            }"#,
            &cache,
        )
        .await;

        assert_eq!(
            std::fs::read(cache.path()).expect("cached netmap"),
            cached,
            "a delta frame must not overwrite the cached full netmap"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A netmap with no peers in it is still a netmap, and Go caches it: `netmapcache.Cache.Store`
    /// writes the self node, DNS config, DERP map and packet filter whatever the peer count. A node
    /// that sees no peers — a solo tailnet, or one whose ACLs show it nobody — gets no other kind of
    /// netmap, so gating the write on a non-empty peer list left exactly that node with no cache at
    /// all and no DERP map or DNS config to start from.
    #[tokio::test]
    async fn a_peerless_netmap_is_cached() {
        let dir = scratch_dir("peerless");
        let cache = NetmapCache::new(&dir);

        poll_one(&peerless_netmap(r#"{"cache-network-maps": null}"#), &cache).await;

        let replayed = NetmapCache::new(&dir)
            .load_state_update()
            .await
            .expect("a node with no peers must still cache its netmap");

        assert_eq!(
            replayed.node.as_ref().expect("self node").stable_id.0,
            "self-1"
        );
        assert!(
            replayed.derp.is_some(),
            "the DERP map is the head start a peerless node gets from the cache"
        );
        assert!(
            replayed.dns_config.is_some(),
            "so is the DNS configuration; Go stores both for a zero-peer netmap"
        );
        assert!(
            replayed.peer_update.is_none(),
            "there were no peers to replay, and an empty peer list is not a full reset"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A peerless frame refreshes a peerless cache but never replaces a cache that has peers in it.
    ///
    /// Go writes back a complete assembled `NetworkMap` every time, so it cannot lose peers this way;
    /// this port stores the frame control sent, so a frame that re-states the netmap head without
    /// repeating the peers would throw away the peer list a cold start exists to dial. Keeping the
    /// richer cache is the conservative half of caching peerless netmaps at all.
    #[tokio::test]
    async fn a_peerless_netmap_never_evicts_cached_peers() {
        let dir = scratch_dir("peerless-keeps-peers");
        let cache = NetmapCache::new(&dir);

        poll_one(&full_netmap(r#"{"cache-network-maps": null}"#), &cache).await;
        poll_one(&peerless_netmap(r#"{"cache-network-maps": null}"#), &cache).await;

        let replayed = NetmapCache::new(&dir)
            .load_state_update()
            .await
            .expect("the cached netmap survives");
        assert!(
            matches!(replayed.peer_update, Some(PeerUpdate::Full(ref p)) if p[0].stable_id.0 == "peer-2"),
            "the peer-bearing netmap must still be the cached one, got {:?}",
            replayed.peer_update
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The narrowness that makes the above safe: a mid-session self-node update — a cap-map or
    /// endpoint change, carrying a self node and nothing else — is not a netmap and is not cached.
    /// Without the DERP map it is indistinguishable from the head of one, so the frame is refused
    /// and whatever is cached stays.
    #[tokio::test]
    async fn a_self_only_update_is_not_a_netmap() {
        let dir = scratch_dir("self-only");
        let cache = NetmapCache::new(&dir);

        poll_one(
            r#"{
                "Seq": 4,
                "Node": {
                    "ID": 1,
                    "StableID": "self-1",
                    "Name": "self.example.ts.net.",
                    "Addresses": ["100.64.0.1/32"],
                    "CapMap": {"cache-network-maps": null}
                }
            }"#,
            &cache,
        )
        .await;

        assert!(
            !cache.path().exists(),
            "a frame that carries only the self node is not a netmap a cold start can start from"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The classifier itself, over the frame shapes control actually sends.
    #[test]
    fn only_self_contained_netmap_frames_are_cacheable() {
        let classify = |body: &str| {
            cacheable(&state_update_from_frame(body.as_bytes()).expect("a decodable frame"))
        };

        assert_eq!(classify(&full_netmap("{}")), Cacheable::WithPeers);
        assert_eq!(classify(&peerless_netmap("{}")), Cacheable::WithoutPeers);
        // A peer delta, even one that also re-states the DERP map, is a piece of a netmap.
        assert_eq!(
            classify(
                r#"{"Node": {"ID": 1}, "PeersChanged": [{"ID": 3, "StableID": "peer-3"}],
                    "DERPMap": { "Regions": {} }}"#
            ),
            Cacheable::No
        );
        // So is a standalone online flip, which carries no peer body at all.
        assert_eq!(
            classify(
                r#"{"Node": {"ID": 1}, "OnlineChange": {"3": true}, "DERPMap": {"Regions": {}}}"#
            ),
            Cacheable::No
        );
        // And so is a self-node update with no DERP map behind it.
        assert_eq!(classify(r#"{"Node": {"ID": 1}}"#), Cacheable::No);
    }

    /// The cached frame is the tailnet's peer list, keys, DNS config and packet filter, so it is
    /// written private to this user (Go writes its cache entries `0600`).
    #[cfg(unix)]
    #[tokio::test]
    async fn cached_netmap_is_written_private() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = scratch_dir("perms");
        let cache = NetmapCache::new(&dir);

        poll_one(&full_netmap(r#"{"cache-network-maps": null}"#), &cache).await;

        let file = std::fs::metadata(cache.path()).expect("cached netmap");
        assert_eq!(
            file.permissions().mode() & 0o777,
            0o600,
            "the cached netmap must be readable only by this user"
        );

        let parent = std::fs::metadata(&dir).expect("cache dir");
        assert_eq!(
            parent.permissions().mode() & 0o777,
            0o700,
            "the cache directory must be private too"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// [`NetmapCache::load_state_update`] — the load with **no** voucher — replays everything of a
    /// netmap cached under an active lock **except** its peers.
    ///
    /// Go's cached replay goes through `tkaFilterNetmapLocked` against the authority it persisted on
    /// disk. A caller that brings no authority cannot run that filter, so it can vouch for nothing
    /// and the peers wait for control's first netmap — while the relay/DNS half of the head start is
    /// kept. [`NetmapCache::load_state_update_vouched`] is the load that can do better.
    #[tokio::test]
    async fn peers_cached_under_tailnet_lock_are_not_replayed() {
        let dir = scratch_dir("tka-locked");
        let cache = NetmapCache::new(&dir);

        poll_one(
            &full_netmap_with(
                r#"{"cache-network-maps": null}"#,
                r#""TKAInfo": { "Head": "s7ovkkqcbxlaqedbmdyrhqzhqu", "Disabled": false },"#,
            ),
            &cache,
        )
        .await;

        let replayed = NetmapCache::new(&dir)
            .load_state_update()
            .await
            .expect("a locked tailnet still replays the netmap");

        assert!(
            replayed.peer_update.is_none(),
            "peers cached under Tailnet Lock must not be replayed unverified, got {:?}",
            replayed.peer_update
        );
        assert!(replayed.peer_patches.is_empty());
        assert!(
            replayed.node.is_some() && replayed.derp.is_some(),
            "the rest of the netmap carries no peer identity and must still replay"
        );
    }

    /// Control saying the lock is *disabled* is not the lock being on: those peers replay. Both the
    /// "no `TKAInfo` at all" case (the fixture used by every other test) and this explicit
    /// `Disabled: true` one are the netmap of an unlocked tailnet.
    #[tokio::test]
    async fn peers_cached_with_the_lock_disabled_still_replay() {
        let dir = scratch_dir("tka-disabled");
        let cache = NetmapCache::new(&dir);

        poll_one(
            &full_netmap_with(
                r#"{"cache-network-maps": null}"#,
                r#""TKAInfo": { "Head": "s7ovkkqcbxlaqedbmdyrhqzhqu", "Disabled": true },"#,
            ),
            &cache,
        )
        .await;

        let replayed = NetmapCache::new(&dir)
            .load_state_update()
            .await
            .expect("a cached netmap");

        assert!(
            matches!(replayed.peer_update, Some(PeerUpdate::Full(ref p)) if p.len() == 1),
            "a disabled lock enforces nothing, so its peers replay: {:?}",
            replayed.peer_update
        );
    }

    /// The headline of the vouched load: a netmap cached under an active lock replays **exactly** the
    /// peers the caller vouches for — not all of them, and not none of them.
    ///
    /// This is what Go does with its cached map: it runs `tkaFilterNetmapLocked` over it and keeps
    /// the peers the authority authorizes, which is the whole point of the cache (peer connectivity
    /// before control answers). The voucher also sees the lock the peers were cached under, so it can
    /// check that the authority it holds is the one this netmap was taken with.
    #[tokio::test]
    async fn a_vouched_load_replays_exactly_the_peers_the_caller_keeps() {
        let dir = scratch_dir("tka-vouched");
        let cache = NetmapCache::new(&dir);

        poll_one(
            &full_netmap_with_peers(
                r#"{"cache-network-maps": null}"#,
                r#""TKAInfo": { "Head": "s7ovkkqcbxlaqedbmdyrhqzhqu", "Disabled": false },"#,
                r#"{
                    "ID": 2,
                    "StableID": "signed-peer",
                    "Name": "signed.example.ts.net.",
                    "Addresses": ["100.64.0.2/32"],
                    "Endpoints": ["192.0.2.7:41641"],
                    "HomeDERP": 3
                }, {
                    "ID": 3,
                    "StableID": "revoked-peer",
                    "Name": "revoked.example.ts.net.",
                    "Addresses": ["100.64.0.3/32"],
                    "Endpoints": ["192.0.2.8:41641"],
                    "HomeDERP": 3
                }"#,
            ),
            &cache,
        )
        .await;

        let mut saw_head = String::new();
        let replayed = NetmapCache::new(&dir)
            .load_state_update_vouched(|tka, peers| {
                saw_head = tka.head.clone();
                assert_eq!(peers.len(), 2, "the voucher is handed every cached peer");
                peers
                    .into_iter()
                    .filter(|p| p.stable_id.0 == "signed-peer")
                    .collect()
            })
            .await
            .expect("a locked tailnet still replays the netmap");

        assert_eq!(
            saw_head, "s7ovkkqcbxlaqedbmdyrhqzhqu",
            "the voucher must be told which lock these peers were cached under"
        );
        let Some(PeerUpdate::Full(peers)) = replayed.peer_update.as_ref() else {
            panic!(
                "the vouched peers must replay as a full peer set, got {:?}",
                replayed.peer_update
            );
        };
        assert_eq!(
            peers
                .iter()
                .map(|p| p.stable_id.0.as_str())
                .collect::<Vec<_>>(),
            vec!["signed-peer"],
            "only the vouched peer replays"
        );
        assert_eq!(
            peers[0].underlay_addresses,
            vec!["192.0.2.7:41641".parse().unwrap()],
            "with its endpoints, which are what a cold start dials"
        );
        assert!(
            replayed.node.is_some() && replayed.derp.is_some(),
            "the rest of the netmap replays as before"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A voucher that keeps nothing lands on the same replay as no voucher at all: no peer update.
    #[tokio::test]
    async fn a_voucher_that_keeps_nothing_replays_no_peers() {
        let dir = scratch_dir("tka-vouched-none");
        let cache = NetmapCache::new(&dir);

        poll_one(
            &full_netmap_with(
                r#"{"cache-network-maps": null}"#,
                r#""TKAInfo": { "Head": "s7ovkkqcbxlaqedbmdyrhqzhqu", "Disabled": false },"#,
            ),
            &cache,
        )
        .await;

        let replayed = NetmapCache::new(&dir)
            .load_state_update_vouched(|_, _| Vec::new())
            .await
            .expect("a cached netmap");

        assert!(
            replayed.peer_update.is_none(),
            "a peer nobody vouches for must not be replayed, got {:?}",
            replayed.peer_update
        );
        assert!(replayed.peer_patches.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The voucher is not consulted at all when the cached frame says the lock was off — there is
    /// nothing to enforce, so every peer replays (Go's filter returns early on `b.tka == nil`).
    #[tokio::test]
    async fn an_unlocked_netmap_never_asks_the_voucher() {
        let dir = scratch_dir("tka-vouched-unlocked");
        let cache = NetmapCache::new(&dir);

        poll_one(&full_netmap(r#"{"cache-network-maps": null}"#), &cache).await;

        let replayed = NetmapCache::new(&dir)
            .load_state_update_vouched(|_, _| panic!("the voucher must not be consulted"))
            .await
            .expect("a cached netmap");

        assert!(
            matches!(replayed.peer_update, Some(PeerUpdate::Full(ref p)) if p.len() == 1),
            "an unlocked netmap replays its peers untouched: {:?}",
            replayed.peer_update
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The Tailnet-Lock chain the runtime persists beside the netmap round-trips through the same
    /// vetted directory, and [`NetmapCache::discard`] drops it with the netmap it vouches for.
    #[tokio::test]
    async fn the_tka_chain_round_trips_and_is_discarded_with_the_netmap() {
        let dir = scratch_dir("tka-chain");
        let cache = NetmapCache::new(&dir);

        poll_one(&full_netmap(r#"{"cache-network-maps": null}"#), &cache).await;
        cache.store_tka_chain(b"an opaque chain blob").await;

        assert_eq!(
            NetmapCache::new(&dir).load_tka_chain().await.as_deref(),
            Some(&b"an opaque chain blob"[..]),
            "a cold start must read back the chain the last session persisted"
        );

        // Discarding the netmap discards the chain that only exists to vouch for its peers.
        cache.discard().await;
        assert!(NetmapCache::new(&dir).load_tka_chain().await.is_none());
        assert!(NetmapCache::new(&dir).load_state_update().await.is_none());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// `discard_tka_chain` drops the chain and **only** the chain: the netmap it described stays, and
    /// is then replayed without its peers (the no-authority case).
    #[tokio::test]
    async fn discarding_the_chain_leaves_the_cached_netmap() {
        let dir = scratch_dir("tka-chain-only");
        let cache = NetmapCache::new(&dir);

        poll_one(
            &full_netmap_with(
                r#"{"cache-network-maps": null}"#,
                r#""TKAInfo": { "Head": "s7ovkkqcbxlaqedbmdyrhqzhqu", "Disabled": false },"#,
            ),
            &cache,
        )
        .await;
        cache.store_tka_chain(b"an opaque chain blob").await;
        cache.discard_tka_chain().await;

        assert!(NetmapCache::new(&dir).load_tka_chain().await.is_none());
        let replayed = NetmapCache::new(&dir)
            .load_state_update()
            .await
            .expect("the netmap survives its chain");
        assert!(replayed.node.is_some());
        assert!(replayed.peer_update.is_none());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A cache directory that already exists and is reachable by other users takes no netmap. The
    /// frame is the tailnet's peer keys, endpoints, DNS config and packet filter; `0700` on create
    /// says nothing about a directory that was already there, so it is checked on every write.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_shared_cache_directory_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = scratch_dir("shared-dir");
        std::fs::create_dir_all(&dir).expect("scratch dir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        poll_one(
            &full_netmap(r#"{"cache-network-maps": null}"#),
            &cache_at(&dir),
        )
        .await;

        assert!(
            !cache_at(&dir).path().exists(),
            "a netmap must not be written into a directory other users can read"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The read end refuses the same way: a cached netmap sitting in a directory other users can
    /// write is a netmap any of them can replace, and a replayed netmap is the whole cold-start
    /// state of the node (peers, DERP map, DNS, packet filter). A `0600` file does not redeem it.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_cache_in_a_shared_directory_is_not_replayed() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = scratch_dir("shared-dir-load");
        std::fs::create_dir_all(&dir).expect("scratch dir");
        std::fs::write(
            dir.join(NETMAP_CACHE_FILE),
            full_netmap(r#"{"cache-network-maps": null}"#),
        )
        .expect("plant a netmap");
        std::fs::set_permissions(
            dir.join(NETMAP_CACHE_FILE),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("chmod");

        // Private directory: the planted netmap is ours, and it replays.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        assert!(
            cache_at(&dir).load_state_update().await.is_some(),
            "control: a private cache replays"
        );

        // Same file, group/other-writable directory: refused.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).expect("chmod");
        assert!(
            cache_at(&dir).load_state_update().await.is_none(),
            "a netmap another local user could have swapped must not be replayed"
        );

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).ok();
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A world-readable cache file is not replayed either, and neither is a symlink standing in for
    /// one — the read opens `O_NOFOLLOW` and vets the open handle, so the file that is checked is
    /// the file that is read.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_shared_or_symlinked_cache_file_is_not_replayed() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = scratch_dir("shared-file");
        std::fs::create_dir_all(&dir).expect("scratch dir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");

        let body = full_netmap(r#"{"cache-network-maps": null}"#);
        std::fs::write(dir.join(NETMAP_CACHE_FILE), &body).expect("plant a netmap");
        std::fs::set_permissions(
            dir.join(NETMAP_CACHE_FILE),
            std::fs::Permissions::from_mode(0o644),
        )
        .expect("chmod");

        assert!(
            cache_at(&dir).load_state_update().await.is_none(),
            "a world-readable cache file is not one this node wrote; it must not be replayed"
        );

        // A symlink where the cache file belongs, pointing at a perfectly valid netmap.
        let elsewhere = dir.join("planted.json");
        std::fs::write(&elsewhere, &body).expect("plant a netmap");
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o600))
            .expect("chmod");
        std::fs::remove_file(dir.join(NETMAP_CACHE_FILE)).expect("clear");
        std::os::unix::fs::symlink(&elsewhere, dir.join(NETMAP_CACHE_FILE)).expect("symlink");

        assert!(
            cache_at(&dir).load_state_update().await.is_none(),
            "the cache path must be a regular file, never a redirect to one"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The temporary file the write goes through is created, never reused: `mode` applies only to a
    /// file the open creates, so writing through one that was already there — a crashed write's
    /// leftovers, or something another user planted — would give the netmap somebody else's mode.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_stale_temporary_file_never_lends_the_netmap_its_mode() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = scratch_dir("stale-tmp");
        std::fs::create_dir_all(&dir).expect("scratch dir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");

        let tmp = dir.join(NETMAP_CACHE_TMP_FILE);
        std::fs::write(&tmp, b"half a netmap").expect("stale temporary file");
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o666)).expect("chmod");

        poll_one(
            &full_netmap(r#"{"cache-network-maps": null}"#),
            &cache_at(&dir),
        )
        .await;

        let cached = cache_at(&dir).path();
        assert_eq!(
            std::fs::metadata(&cached)
                .expect("cached netmap")
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "the netmap must land in a file this write created, at this write's mode"
        );
        assert!(
            cache_at(&dir).load_state_update().await.is_some(),
            "and it must still be the netmap"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The attribute test itself, both ways round and with neither attribute present.
    #[test]
    fn caching_is_granted_only_by_the_enabling_attribute_alone() {
        let cap = |caps: &[&str]| -> NodeCapMap {
            caps.iter().map(|c| ((*c).to_owned(), Vec::new())).collect()
        };

        assert!(netmap_caching_enabled(&cap(&[
            NODE_ATTR_CACHE_NETWORK_MAPS
        ])));
        assert!(!netmap_caching_enabled(&cap(&[])));
        assert!(!netmap_caching_enabled(&cap(&[
            NODE_ATTR_DISABLE_CACHE_NETWORK_MAPS
        ])));
        assert!(!netmap_caching_enabled(&cap(&[
            NODE_ATTR_CACHE_NETWORK_MAPS,
            NODE_ATTR_DISABLE_CACHE_NETWORK_MAPS
        ])));
    }
}
