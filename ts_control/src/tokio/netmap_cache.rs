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
//! **What is persisted.** Go stores the assembled `netmap.NetworkMap` column by column. This port
//! has no `NetworkMap` aggregate (the netmap is consumed as a [`StateUpdate`] stream), so the cache
//! keeps the *raw decompressed `MapResponse` JSON* of the last **full** netmap frame and replays it
//! through the same decoder the live poll uses. A frame counts as full only when control marked its
//! peer list complete (`MapResponse.Peers` non-empty — Go's own "if non-empty, is the complete
//! list" signal); delta frames are never persisted, because replaying a delta on a cold start would
//! install a partial netmap. The cache therefore holds the last complete netmap, not a
//! continuously-updated one: Go's per-peer delta merge into the cache is not ported.
//!
//! **The persisted material is sensitive.** A `MapResponse` carries the tailnet's peer list with
//! their node/disco public keys and endpoints, the DNS configuration, and the compiled packet
//! filter. The cache directory is created `0700` and the file is written `0600` (Go writes its
//! cache entries `0600` in `netmapcache.FileStore.Store`); on a platform without Unix modes the
//! file inherits the directory's ACL. Nothing is written at all unless the embedder configured
//! [`Config::netmap_cache_dir`](crate::Config::netmap_cache_dir) *and* control granted the
//! attribute.

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
pub const NODE_ATTR_DISABLE_CACHE_NETWORK_MAPS: &str = "disable-cache-network-maps";

/// File name of the cached netmap frame under [`NetmapCache`]'s directory.
pub const NETMAP_CACHE_FILE: &str = "netmap.json";

/// Name of the temporary file the cache writes before renaming it over [`NETMAP_CACHE_FILE`], so a
/// crash mid-write cannot leave a half-written netmap behind for the next cold start to read.
const NETMAP_CACHE_TMP_FILE: &str = "netmap.json.tmp";

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

    /// Apply the cache policy to one decoded netmap frame and the raw bytes it was decoded from.
    ///
    /// Mirrors the two Go call sites that maintain the cache on every installed netmap
    /// (`ipnlocal.setNetMapLocked`): persist when control grants the attribute, otherwise discard
    /// whatever is on disk. The decision is taken from the **self node carried by this frame**, so
    /// a frame that carries no self node leaves the cache exactly as it was (control sends plenty of
    /// peer-only and keep-alive frames, and none of them re-state the node's attributes).
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

        // Only a frame whose peer list control marked complete is a self-contained netmap. Replaying
        // a delta frame on a cold start would install a partial netmap (peers that happened to
        // change last, and nothing else), which is worse than no cache at all.
        if !matches!(update.peer_update, Some(PeerUpdate::Full(_))) {
            return;
        }

        if let Err(e) = self.store(frame).await {
            tracing::warn!(error = %e, path = %self.path().display(), "writing netmap cache");
        }
    }

    /// Persist `frame` (the raw decompressed `MapResponse` JSON) as the cached netmap.
    ///
    /// Written to a temporary file and renamed into place so a torn write is never observable, with
    /// the directory `0700` and the file `0600` on Unix — the frame carries peer keys, endpoints,
    /// DNS configuration and the packet filter.
    async fn store(&self, frame: &[u8]) -> std::io::Result<()> {
        create_dir_private(&self.dir).await?;

        let tmp = self.dir.join(NETMAP_CACHE_TMP_FILE);
        write_private(&tmp, frame).await?;
        tokio::fs::rename(&tmp, self.path()).await
    }

    /// The cached netmap frame, or `None` when nothing has been cached (or it could not be read).
    async fn load(&self) -> Option<Vec<u8>> {
        match tokio::fs::read(self.path()).await {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                tracing::warn!(error = %e, path = %self.path().display(), "reading netmap cache");
                None
            }
        }
    }

    /// Remove the cached netmap, if any. Errors are logged, never propagated: the cache is being
    /// thrown away, so failing to throw it away is not something a caller can act on.
    pub async fn discard(&self) {
        match tokio::fs::remove_file(self.path()).await {
            Ok(()) => tracing::debug!(path = %self.path().display(), "discarded netmap cache"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!(error = %e, path = %self.path().display(), "discarding netmap cache");
            }
        }
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
    pub async fn load_state_update(&self) -> Option<StateUpdate> {
        let frame = self.load().await?;
        let mut update = state_update_from_frame(&frame)?;

        update.session_handle = None;
        update.seq = 0;
        update.ping = None;

        Some(update)
    }
}

/// Create `dir` (and its parents) private to this user — `0700` on Unix, the platform default
/// elsewhere. An already-existing directory is left as it is, mode included.
async fn create_dir_private(dir: &Path) -> std::io::Result<()> {
    let mut builder = tokio::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        builder.mode(0o700);
    }
    builder.create(dir).await
}

/// Write `bytes` to `path`, creating it `0600` on Unix (Go's `netmapcache.FileStore` writes its
/// cache entries with the same mode). An existing file is truncated; its mode is left alone, which
/// is why the cache only ever writes through a fresh temporary file.
async fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt as _;

    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        opts.mode(0o600);
    }

    let mut file = opts.open(path).await?;
    file.write_all(bytes).await?;
    file.flush().await
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

    /// A full netmap: a self node carrying `cap_map`, one peer, and a DERP map. `cap_map` is
    /// spliced in verbatim so a test can grant, withhold, or contradict the caching attributes.
    fn full_netmap(cap_map: &str) -> String {
        format!(
            r#"{{
                "MapSessionHandle": "sess-1",
                "Seq": 9,
                "Node": {{
                    "ID": 1,
                    "StableID": "self-1",
                    "Name": "self.example.ts.net.",
                    "Addresses": ["100.64.0.1/32"],
                    "CapMap": {cap_map}
                }},
                "Peers": [{{
                    "ID": 2,
                    "StableID": "peer-2",
                    "Name": "peer.example.ts.net.",
                    "Addresses": ["100.64.0.2/32"],
                    "Endpoints": ["192.0.2.7:41641"],
                    "HomeDERP": 3
                }}],
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
