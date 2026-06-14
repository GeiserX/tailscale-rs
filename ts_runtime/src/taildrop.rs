//! Taildrop file store — the receiving half of Tailscale's peer-to-peer file transfer.
//!
//! A peer sends a file to this node via the peerAPI route `PUT /v0/put/<name>` (handled in
//! `peerapi`). This module owns the on-disk store those puts land in, faithfully mirroring
//! Go's `taildrop.manager`:
//!
//! - Incoming bytes are written to a per-transfer **partial** file (`<base>.partial`) so an
//!   interrupted transfer never exposes a truncated file under its real name, and can be resumed
//!   from an offset.
//! - On successful completion the partial is **atomically renamed** to the final base name. If the
//!   final name already exists, a non-clobbering ` (n)` suffix is chosen (Go `nextFilename`).
//! - File names are strictly validated ([`validate_base_name`](crate::taildrop::validate_base_name)) to defeat path traversal and
//!   reserved-suffix abuse before any path is constructed — this is the security boundary.
//!
//! # Anti-abuse / safety
//!
//! Every name is validated to be a single, local, non-traversing path component before it touches
//! the filesystem; a name containing `/`, `\`, `..`, a NUL, control chars, or the reserved
//! `.partial` / `.deleted` suffixes is rejected with [`TaildropError::InvalidFileName`](crate::taildrop::TaildropError::InvalidFileName). The store
//! root is fixed at construction; all I/O is confined to it by joining only validated base names.

use std::{
    collections::HashSet,
    io::{self, Seek, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use tokio::io::{AsyncRead, AsyncReadExt};

/// How long an abandoned `.partial` is kept before the reaper deletes it (Go
/// `feature/taildrop/delete.go` `deleteDelay = time.Hour`). A resume within the window keeps the
/// partial alive (its mtime advances on every write, and an in-flight transfer is skipped outright),
/// so this is the grace period for a transfer to be resumed before its leftovers are reclaimed.
pub const DELETE_DELAY: Duration = Duration::from_secs(60 * 60);

/// Suffix for in-progress transfers. A completed transfer is renamed off this suffix; a name
/// ending in it is itself never accepted as a base name (Go `partialSuffix`).
const PARTIAL_SUFFIX: &str = ".partial";
/// Suffix Go uses to tombstone files pending deletion on platforms with async close; we reject it
/// as a base name for parity so a sender can't create one (Go `deletedSuffix`).
const DELETED_SUFFIX: &str = ".deleted";
/// Maximum base-name length in bytes (Go `validateBaseName`: 255).
const MAX_BASE_NAME_LEN: usize = 255;

/// Errors from the Taildrop file store.
#[derive(Debug)]
pub enum TaildropError {
    /// The requested file name is invalid (traversal, reserved suffix, empty, too long, bad runes).
    /// Maps to peerAPI `400 Bad Request`.
    InvalidFileName,
    /// A transfer for this exact base name is already in progress. Maps to peerAPI `409 Conflict`.
    FileExists,
    /// Underlying filesystem I/O failure. Maps to peerAPI `500`.
    Io(io::Error),
}

impl core::fmt::Display for TaildropError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TaildropError::InvalidFileName => write!(f, "invalid taildrop file name"),
            TaildropError::FileExists => {
                write!(f, "a transfer for this file is already in progress")
            }
            TaildropError::Io(e) => write!(f, "taildrop I/O error: {e}"),
        }
    }
}

impl std::error::Error for TaildropError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TaildropError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for TaildropError {
    fn from(e: io::Error) -> Self {
        TaildropError::Io(e)
    }
}

/// A waiting (fully-received) Taildrop file, as reported to the embedder. Mirrors Go
/// `apitype.WaitingFile` (default field-name JSON marshalling: `Name`, `Size`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaitingFile {
    /// The file's base name.
    pub name: String,
    /// The file's size in bytes.
    pub size: u64,
}

/// Validate a Taildrop base name, mirroring Go `taildrop.validateBaseName`.
///
/// Returns the name unchanged when it is a safe, single, local path component; otherwise `None`.
/// Rejection rules (any one fails): empty or `> 255` bytes; leading/trailing ASCII space; contains
/// a path separator (`/` or `\`), a NUL, or an ASCII control char; is `.` or `..`; equals a cleaned
/// path other than itself (catches embedded `..`/`.` segments and absolute paths); or ends in the
/// reserved `.partial` / `.deleted` suffixes.
pub fn validate_base_name(name: &str) -> Option<&str> {
    if name.is_empty() || name.len() > MAX_BASE_NAME_LEN {
        return None;
    }
    if name.starts_with(' ') || name.ends_with(' ') {
        return None;
    }
    if name == "." || name == ".." {
        return None;
    }
    if name.ends_with(PARTIAL_SUFFIX) || name.ends_with(DELETED_SUFFIX) {
        return None;
    }
    // Reject any separator, NUL, or control character outright. This is the core traversal guard:
    // with no `/`, `\`, or `..` segment possible, the name can only ever be a leaf in the store dir.
    for ch in name.chars() {
        if ch == '/' || ch == '\\' || ch == '\0' || ch.is_control() {
            return None;
        }
    }
    // Defense in depth: a name that does not survive `Path` normalization as a single normal
    // component is rejected (catches `..`, absolute paths, and any platform-specific oddity).
    let p = Path::new(name);
    let mut comps = p.components();
    match (comps.next(), comps.next()) {
        (Some(std::path::Component::Normal(c)), None) if c == name => Some(name),
        _ => None,
    }
}

/// Choose a non-clobbering final name for `base` within `dir`, mirroring Go `nextFilename`:
/// `foo.txt` -> `foo (1).txt` -> `foo (2).txt` ... inserting ` (n)` before the extension. Returns
/// the first candidate (incl. `base` itself) whose path does not yet exist. Bounded to avoid an
/// unbounded loop on a pathological directory.
fn next_available_name(dir: &Path, base: &str) -> String {
    if !path_present(&dir.join(base)) {
        return base.to_string();
    }
    let (stem, ext) = match base.rsplit_once('.') {
        // Keep the dot with the extension; an empty stem (dotfile like ".bashrc") has no split.
        Some((stem, ext)) if !stem.is_empty() => (stem, format!(".{ext}")),
        _ => (base, String::new()),
    };
    for n in 1..=10_000u32 {
        let candidate = format!("{stem} ({n}){ext}");
        if !path_present(&dir.join(&candidate)) {
            return candidate;
        }
    }
    // Pathological fallback: suffix with a high counter; extremely unlikely to be reached.
    format!("{stem} (overflow){ext}")
}

/// Whether a path is present, treating a symlink (even a dangling one) as present. Unlike
/// `Path::exists()` (which follows the link and returns `false` for a dangling symlink), this uses
/// `symlink_metadata` so a planted symlink can never be mistaken for a free name in
/// [`next_available_name`] — we must not select, then rename onto, a symlink.
fn path_present(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// Reject a path that is (or whose final component is) a symlink. This is hardening **beyond**
/// upstream Go, whose taildrop (`feature/taildrop/fileops_fs.go` at v1.100.0) opens with a plain
/// `os.OpenFile(O_CREATE|O_RDWR)` / `os.Open` and refuses symlinks nowhere — it relies on name
/// validation (`joinDir`) alone. `validate_base_name` already blocks a traversing *name*,
/// but not a symlink **component already planted in the store root** by a local attacker (e.g.
/// `root/foo.txt -> /etc/cron.d/x`), which a plain `open`/`rename`/`remove` would follow. Uses
/// `symlink_metadata` (lstat — does NOT follow the final symlink); a non-existent path is fine
/// (returns `Ok(())`), only an existing symlink is refused.
///
/// This is a check-then-act guard, so it is not atomic with the open/rename/remove that follows.
/// It kills the **persistent-plant** attack (a symlink left in the store root is no longer followed
/// deterministically), and the per-name in-flight lock serializes our OWN operations on a name, but
/// on its own it does not close a sub-millisecond race where an external process swaps the path for
/// a symlink between this lstat and the syscall. The two paths that actually *open* a store file —
/// the `offset > 0` resume write-open and the read-open — additionally pass `O_NOFOLLOW`
/// ([`open_nofollow`]) so the kernel refuses a final-component symlink atomically, closing that
/// residual race; `refuse_symlink` is retained ahead of them as a
/// portable defense-in-depth check that also yields a clean typed error. The `offset == 0` put is
/// atomically protected by `create_new` (`O_EXCL`, which refuses an existing symlink), and the
/// non-opening ops (`rename`/`remove_file`/`read_dir`) act on the link itself rather than following
/// it, so the advisory check is sufficient there. The residual external-swap window therefore only
/// requires an external writer who already holds store-dir write access (the threat bound for this
/// hardening).
fn refuse_symlink(path: &Path) -> Result<(), TaildropError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(TaildropError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "taildrop path is a symlink; refusing to follow it",
        ))),
        Ok(_) => Ok(()),
        // Not present yet (the common case for a fresh partial / final name) — nothing to refuse.
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Open an existing store file with the given [`OpenOptions`](std::fs::OpenOptions), refusing a
/// final-component symlink **atomically** in the kernel via `O_NOFOLLOW` on Unix. This is the atomic
/// counterpart to the advisory [`refuse_symlink`] check: where `refuse_symlink` lstat's the path
/// first (a check-then-act guard with a sub-millisecond swap window), `O_NOFOLLOW` makes the kernel
/// fail the `open` itself (`ELOOP`) if the final path component is a symlink, so an external process
/// cannot win a race by swapping the path for a symlink after the lstat. This is fork hardening with
/// no upstream-Go equivalent (Go's taildrop opens without `O_NOFOLLOW`).
///
/// On non-Unix targets `O_NOFOLLOW` has no portable equivalent, so this is a plain `open` and the
/// preceding `refuse_symlink` advisory check is the only symlink defense there (Windows does not use
/// the Unix symlink threat model for this store).
fn open_nofollow(opts: &mut std::fs::OpenOptions, path: &Path) -> io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // `custom_flags` sets the raw `open(2)` flag set, which `open()` then ORs with the access
        // mode (`O_RDONLY`/`O_WRONLY`) derived from `.read`/`.write` — so the access mode is
        // preserved alongside `O_NOFOLLOW`. `O_NOFOLLOW` makes the kernel return `ELOOP` instead of
        // following a final-component symlink. It does not affect non-final components, but the store
        // root is fixed and names are validated to a single component, so the final component is the
        // only attacker-influenceable one.
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    opts.open(path)
}

/// A Taildrop file store rooted at a fixed directory. All operations are confined to this root by
/// joining only [`validate_base_name`]-validated names.
#[derive(Debug, Clone)]
pub struct TaildropStore {
    root: PathBuf,
    /// Base names with a transfer currently in flight. A `put_file` claims its base name here for
    /// the whole receive (both a fresh `offset == 0` transfer and a resumed `offset > 0` one), so
    /// two concurrent PUTs for the same name cannot interleave `set_len`/`seek`/`write_all` and
    /// corrupt the shared `.partial`. Shared (`Arc`) so it survives `TaildropStore::clone()` — the
    /// store is handed around as `Arc<TaildropStore>` but cloning it must not fork the guard set.
    in_flight: Arc<Mutex<HashSet<String>>>,
}

/// RAII claim on an in-flight transfer name; releasing it (on drop) frees the name for the next
/// transfer. Holds the shared guard set so the entry is removed even on an early return / error /
/// panic in `put_file`.
struct InFlightGuard {
    set: Arc<Mutex<HashSet<String>>>,
    name: String,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        // A poisoned lock still lets us recover the set and remove our entry — leaving a stale name
        // claimed would wedge all future transfers of that name behind a phantom conflict.
        let mut set = self.set.lock().unwrap_or_else(|p| p.into_inner());
        set.remove(&self.name);
    }
}

impl TaildropStore {
    /// Create a store rooted at `root`, creating the directory (and parents) if needed.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, TaildropError> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        Ok(Self {
            root,
            in_flight: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    /// Claim `base` as in-flight, returning an RAII guard that frees it on drop. Returns
    /// [`TaildropError::FileExists`] if another transfer already holds the name — this is the
    /// concurrency analog of the on-disk `.partial` conflict, and it serializes all transfers of one
    /// name so a resume (`offset > 0`) cannot race a concurrent transfer's `set_len`/`seek`/`write`.
    fn claim_in_flight(&self, base: &str) -> Result<InFlightGuard, TaildropError> {
        let name = base.to_string();
        let mut set = self.in_flight.lock().unwrap_or_else(|p| p.into_inner());
        if !set.insert(name.clone()) {
            return Err(TaildropError::FileExists);
        }
        Ok(InFlightGuard {
            set: self.in_flight.clone(),
            name,
        })
    }

    /// The partial-file path for an already-validated base name.
    fn partial_path(&self, base: &str) -> PathBuf {
        self.root.join(format!("{base}{PARTIAL_SUFFIX}"))
    }

    /// Reap abandoned `.partial` files: delete every `<base>.partial` in the store root whose last
    /// modification is older than `delete_delay` relative to `now` AND whose base name has no
    /// in-flight transfer. Returns the number deleted. Mirrors Go `feature/taildrop/delete.go`'s
    /// `fileDeleter`, which GCs a partial `deleteDelay` (1h) after it was last touched, sparing one
    /// that an active put is still writing.
    ///
    /// This fork has no per-file timer queue (the store is a passive `Arc`, not an actor); instead a
    /// periodic background sweep — see [`spawn_partial_reaper`] — calls this. The two Go cancellation
    /// signals are both honored: an **active** transfer's base name is in `in_flight` (skipped here,
    /// the analog of Go's "no active put" check), and a **resumed** transfer advances the partial's
    /// mtime on every write (so a partial resumed within the window looks recent and is spared). A
    /// permanently-abandoned partial is neither, so it ages out and is deleted, reclaiming the disk
    /// and clearing the stale-partial `409` that would otherwise block an `offset == 0` re-send of
    /// the same name forever.
    ///
    /// `now` and `delete_delay` are parameters (not read from the clock here) so the reap logic is
    /// deterministically testable. A partial whose mtime is unreadable or in the future is treated as
    /// fresh (kept) — fail-safe toward never deleting a file that might still be live.
    pub fn reap_abandoned_partials(&self, now: SystemTime, delete_delay: Duration) -> usize {
        let entries = match std::fs::read_dir(&self.root) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return 0,
            Err(e) => {
                tracing::warn!(error = %e, "taildrop reaper: cannot read store dir");
                return 0;
            }
        };
        // Snapshot the in-flight names once; an active transfer must never have its partial reaped.
        let in_flight: HashSet<String> = self
            .in_flight
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();

        let mut deleted = 0usize;
        for entry in entries.flatten() {
            // `metadata()` here is lstat-based (does not follow symlinks); a symlink is never a
            // partial we created, so `is_file()` is false for it and it is skipped — consistent with
            // the symlink refusal elsewhere in this store.
            let Ok(meta) = entry.metadata() else { continue };
            if !meta.is_file() {
                continue;
            }
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            let Some(base) = name.strip_suffix(PARTIAL_SUFFIX) else {
                continue; // not a partial
            };
            if in_flight.contains(base) {
                continue; // an active transfer owns this partial — never reap it (Go "no active put")
            }
            // Age check: keep anything modified within `delete_delay` of `now`. An unreadable or
            // future mtime is treated as fresh (kept) — fail-safe toward not deleting a live file.
            let age_ok = meta
                .modified()
                .ok()
                .and_then(|m| now.duration_since(m).ok())
                .is_some_and(|age| age >= delete_delay);
            if !age_ok {
                continue;
            }
            // Final guard against the snapshot TOCTOU: re-check in-flight membership under the lock
            // immediately before deleting, so a transfer that claimed this base AFTER the upfront
            // snapshot (the microsecond window between the snapshot and here) still spares its
            // partial. The mtime check above already makes a wrong delete unreachable in practice (a
            // live partial is < delete_delay old), but this closes the window completely and cheaply
            // (one lock per aged candidate, which is rare).
            if self
                .in_flight
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .contains(base)
            {
                continue;
            }
            match std::fs::remove_file(entry.path()) {
                Ok(()) => {
                    deleted += 1;
                    tracing::info!(partial = %name, "taildrop reaper: deleted abandoned partial");
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {} // already gone, fine
                Err(e) => {
                    tracing::warn!(error = %e, partial = %name, "taildrop reaper: delete failed")
                }
            }
        }
        deleted
    }

    /// Receive a file named `name` from `reader`, writing to `<name>.partial` then atomically
    /// renaming to a non-clobbering final name on success. Mirrors Go `manager.PutFile`.
    ///
    /// `offset` lets a resumed transfer append past already-written bytes (the partial is opened, the
    /// write starts at `offset`, and any bytes already on disk past `offset` are truncated away).
    /// `expected_len` is the declared total length of the completed file (the request's
    /// `Content-Length` plus `offset`); the transfer is finalized only if exactly that many bytes are
    /// present. Returns the total number of bytes in the completed file.
    ///
    /// Fail-closed: an invalid name is rejected before any path is built; an in-progress partial for
    /// the same name yields [`TaildropError::FileExists`]; an out-of-range resume `offset` (past the
    /// current partial length) is rejected; an I/O error mid-transfer — or a body that ends before
    /// `expected_len` (a short/interrupted stream) — leaves the `.partial` on disk and the final name
    /// is never created. This matches Go `feature/taildrop/send.go`, which errors when the copied
    /// length does not equal the declared length rather than publishing a truncated file.
    ///
    /// The retained `.partial` is resumable only by a peer that issues a ranged retry (an `offset > 0`
    /// PUT); a sender that always restarts at `offset == 0` will instead hit the in-progress-conflict
    /// path ([`TaildropError::FileExists`]) until the stale partial is cleared. A permanently-abandoned
    /// partial is reclaimed by the background reaper after [`DELETE_DELAY`] (Go's `fileDeleter`
    /// equivalent — see [`reap_abandoned_partials`](Self::reap_abandoned_partials) /
    /// [`spawn_partial_reaper`]), which also clears that `offset == 0` conflict once the stale partial
    /// ages out.
    pub async fn put_file<R>(
        &self,
        name: &str,
        mut reader: R,
        offset: u64,
        expected_len: u64,
    ) -> Result<u64, TaildropError>
    where
        R: AsyncRead + Unpin,
    {
        let base = validate_base_name(name).ok_or(TaildropError::InvalidFileName)?;
        let partial = self.partial_path(base);

        // Claim the name for the whole transfer FIRST, so two concurrent PUTs for the same base name
        // (especially two resumes, `offset > 0`, which reopen the same `.partial`) cannot interleave
        // their `set_len`/`seek`/`write_all` and corrupt the shared partial. The fresh-transfer path
        // is already protected on disk by `create_new`, but the resume path opens with plain
        // `write(true)` and needs this lock. The guard frees the name on drop (incl. early return /
        // error / panic). Held across the await — it is a cheap `HashSet` membership marker, not a
        // lock held during I/O, so it never blocks the runtime.
        let _claim = self.claim_in_flight(base)?;

        // Refuse to follow a symlink planted in the store root (fork hardening, no upstream-Go
        // equivalent): the partial must be a regular file we create/own, never a pre-existing
        // symlink to elsewhere.
        refuse_symlink(&partial)?;

        // A fresh transfer (offset 0) must not collide with another in-flight transfer of the same
        // name; a resume (offset > 0) reopens the existing partial. File handles are std (the tokio
        // `fs` feature is intentionally not enabled in this crate); the body is read async off the
        // overlay stream and written to the blocking handle in a bounded loop.
        let mut file = if offset == 0 {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&partial)
            {
                Ok(f) => f,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    return Err(TaildropError::FileExists);
                }
                Err(e) => return Err(e.into()),
            }
        } else {
            // Resume open: `O_NOFOLLOW` so a symlink swapped in for the partial after the
            // `refuse_symlink` lstat above is refused atomically by the kernel rather than followed.
            let mut f = open_nofollow(std::fs::OpenOptions::new().write(true), &partial)?;
            // Bound the resume offset to the current partial length and truncate any bytes past it,
            // matching Go `feature/taildrop/fileops_fs.go` (`OpenWriter` rejects `offset > curr` and
            // `Truncate(offset)`s). Without the bound a too-large offset would leave a zero-filled
            // sparse hole; without the truncate a shorter resumed body would leave a prior attempt's
            // stale tail past the new end. `metadata().len()` is the partial's current size.
            let current = f.metadata()?.len();
            if offset > current {
                return Err(TaildropError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "taildrop resume offset is past the end of the partial file",
                )));
            }
            f.set_len(offset)?;
            f.seek(io::SeekFrom::Start(offset))?;
            f
        };

        let mut copied: u64 = 0;
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            // Each `write_all` only pushes the chunk into the page cache (microseconds); the
            // genuinely blocking cost is the terminal `flush`/`sync_all`/`rename` below, which we
            // hand to a blocking thread so a flood of concurrent transfers can't starve the tokio
            // worker pool on fsync (see `peerapi::MAX_INFLIGHT`).
            file.write_all(&buf[..n])?;
            copied += n as u64;
        }

        // Length check (Go `send.go`: error when `copyLength != length`). A body that ended before the
        // declared length — an interrupted/short stream — must NOT be finalized as a complete file;
        // leave the `.partial` on disk (with the bytes received so far) so a Range-capable peer can
        // resume it. `checked_add` rather than a bare `+`: `offset` is an attacker-supplied header and
        // the bound above already rejects an `offset` past the (real, on-disk) partial length, so this
        // cannot overflow in practice — but treat an overflow as a length mismatch rather than a panic.
        let total = match offset.checked_add(copied) {
            Some(t) if t == expected_len => t,
            _ => {
                return Err(TaildropError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!(
                        "taildrop body ended early: got {copied} of {expected_len} expected bytes \
                         at offset {offset}; leaving partial for resume"
                    ),
                )));
            }
        };

        // Finalize off the async runtime: `sync_all` (fsync) and `rename` are the dominant blocking
        // operations, so run them on a blocking thread. The `File` and both paths are owned by the
        // closure (`Send + 'static`), and `next_available_name` (which `stat`s candidates) goes with
        // them. Fail-closed: any I/O error — or a join failure — propagates without ever publishing
        // the final name, leaving the `.partial` in place for a later resume.
        let root = self.root.clone();
        let base = base.to_string();
        tokio::task::spawn_blocking(move || -> io::Result<()> {
            file.flush()?;
            file.sync_all()?;
            drop(file);

            // Atomically publish under a non-clobbering final name. `next_available_name` probes
            // candidates with `symlink_metadata` (not `exists`, which follows symlinks), so it will
            // not treat a planted symlink as "free" and rename onto it; and we refuse to rename onto
            // an existing symlink target outright (fork hardening, beyond Go). The `_claim` guard (held
            // by the caller for the whole transfer) keeps this name serialized against other PUTs.
            let final_name = next_available_name(&root, &base);
            let final_path = root.join(&final_name);
            if let Err(e) = refuse_symlink(&final_path) {
                return Err(match e {
                    TaildropError::Io(io_err) => io_err,
                    other => io::Error::other(other.to_string()),
                });
            }
            std::fs::rename(&partial, &final_path)?;
            Ok(())
        })
        .await
        .map_err(|join_err| {
            // A panicked/cancelled finalize task: surface as I/O so the caller maps it to a 500 and
            // the partial is left untouched (never publishes the final name).
            TaildropError::Io(io::Error::other(format!(
                "taildrop finalize task failed: {join_err}"
            )))
        })??;

        Ok(total)
    }

    /// List fully-received (non-partial) files, sorted by name (Go `WaitingFiles`).
    pub fn waiting_files(&self) -> Result<Vec<WaitingFile>, TaildropError> {
        let mut out = Vec::new();
        let entries = match std::fs::read_dir(&self.root) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        for entry in entries {
            let entry = entry?;
            // `entry.metadata()` does NOT follow symlinks (it is `lstat`-based), so a planted
            // symlink has `is_file() == false` here and is skipped — a symlink in the store root is
            // never reported as a waiting file (fork hardening, beyond Go), even one pointing at a real
            // regular file elsewhere.
            let meta = entry.metadata()?;
            if meta.file_type().is_symlink() || !meta.is_file() {
                continue;
            }
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            // Skip in-progress / tombstoned files.
            if name.ends_with(PARTIAL_SUFFIX) || name.ends_with(DELETED_SUFFIX) {
                continue;
            }
            out.push(WaitingFile {
                name,
                size: meta.len(),
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Delete a fully-received file by base name (Go `DeleteFile`). The name is validated first, so a
    /// traversal attempt can never escape the store root, and a symlink at the target is refused
    /// (fork hardening, beyond Go) rather than followed — a planted `root/foo.txt -> /etc/passwd`
    /// must not let a `delete foo.txt` remove the link's target. (`remove_file` unlinks the symlink
    /// itself rather than its referent, so the advisory `refuse_symlink` is sufficient here.)
    pub fn delete_file(&self, name: &str) -> Result<(), TaildropError> {
        let base = validate_base_name(name).ok_or(TaildropError::InvalidFileName)?;
        let path = self.root.join(base);
        refuse_symlink(&path)?;
        std::fs::remove_file(path)?;
        Ok(())
    }

    /// Open a fully-received file by base name for reading, returning the handle and its size (Go
    /// `OpenFile`). The name is validated first, and a symlink at the target is refused — advisorily
    /// by `refuse_symlink` and then atomically by `O_NOFOLLOW` on the open itself (fork hardening
    /// with no upstream-Go equivalent) — so a planted (or race-swapped) symlink cannot redirect the
    /// read to an arbitrary file.
    pub fn open_file(&self, name: &str) -> Result<(std::fs::File, u64), TaildropError> {
        let base = validate_base_name(name).ok_or(TaildropError::InvalidFileName)?;
        let path = self.root.join(base);
        refuse_symlink(&path)?;
        // `O_NOFOLLOW` so a symlink swapped in after the `refuse_symlink` lstat is refused atomically
        // by the kernel rather than followed, never redirecting the read to an arbitrary file.
        let f = open_nofollow(std::fs::OpenOptions::new().read(true), &path)?;
        let size = f.metadata()?.len();
        Ok((f, size))
    }
}

/// Spawn the background reaper that periodically GCs abandoned `.partial` files (Go
/// `feature/taildrop/delete.go`'s `fileDeleter`). It sweeps every [`DELETE_DELAY`], deleting partials
/// older than `DELETE_DELAY` that have no in-flight transfer (see
/// [`TaildropStore::reap_abandoned_partials`]), and exits when `shutdown` flips to `true`.
///
/// Returns a [`JoinHandle`](tokio::task::JoinHandle) the caller should abort on drop so the task
/// never outlives the runtime (the established `reauth_bridge` / `DerpLatencyMeasurer` pattern). An
/// `Arc<TaildropStore>` is held (cheap clone), so the sweep sees live `in_flight` state.
///
/// The first sweep is deferred one full `DELETE_DELAY` (not run at startup): a partial on disk at
/// boot is by definition at least 0s old, and Go likewise only deletes after the delay elapses, so
/// waiting one interval avoids reaping a partial a just-restarted node might still resume.
pub fn spawn_partial_reaper(
    store: Arc<TaildropStore>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(DELETE_DELAY);
        // `interval` fires immediately on the first `tick()`; consume that so the first real sweep is
        // one `DELETE_DELAY` out (no startup reap — a partial must age the full delay first).
        tick.tick().await;
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    let n = store.reap_abandoned_partials(SystemTime::now(), DELETE_DELAY);
                    if n > 0 {
                        tracing::info!(deleted = n, "taildrop reaper: swept abandoned partials");
                    }
                }
                _ = shutdown.wait_for(|x| *x) => break,
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root() -> PathBuf {
        // A per-call atomic counter guarantees uniqueness across tests that run concurrently in the
        // same binary. A timestamp alone is NOT enough: `SystemTime` resolution is coarse on some
        // platforms, so two tests starting in the same tick would collide on one dir and stomp each
        // other's files (the cause of intermittent taildrop-test flakiness under parallel runs).
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!("taildrop-test-{}-{n}", std::process::id()));
        p
    }

    #[test]
    fn validate_rejects_traversal_and_reserved() {
        // Valid leaf names.
        assert_eq!(validate_base_name("photo.jpg"), Some("photo.jpg"));
        assert_eq!(
            validate_base_name("a file with spaces.txt"),
            Some("a file with spaces.txt")
        );
        assert_eq!(validate_base_name(".bashrc"), Some(".bashrc"));

        // Traversal / separators.
        assert_eq!(validate_base_name("../etc/passwd"), None);
        assert_eq!(validate_base_name("a/b"), None);
        assert_eq!(validate_base_name("a\\b"), None);
        assert_eq!(validate_base_name("/abs"), None);
        assert_eq!(validate_base_name(".."), None);
        assert_eq!(validate_base_name("."), None);

        // NUL / control.
        assert_eq!(validate_base_name("a\0b"), None);
        assert_eq!(validate_base_name("a\nb"), None);

        // Reserved suffixes.
        assert_eq!(validate_base_name("x.partial"), None);
        assert_eq!(validate_base_name("x.deleted"), None);

        // Edges.
        assert_eq!(validate_base_name(""), None);
        assert_eq!(validate_base_name(" leading"), None);
        assert_eq!(validate_base_name("trailing "), None);
        assert_eq!(validate_base_name(&"a".repeat(256)), None);
        assert_eq!(
            validate_base_name(&"a".repeat(255)).map(|s| s.len()),
            Some(255)
        );
    }

    #[tokio::test]
    async fn put_file_writes_then_atomically_renames() {
        let root = tmp_root();
        let store = TaildropStore::new(&root).unwrap();

        let data = b"hello taildrop";
        let n = store
            .put_file("greeting.txt", &data[..], 0, data.len() as u64)
            .await
            .unwrap();
        assert_eq!(n, data.len() as u64);

        // The final file exists; no .partial remains.
        let body = std::fs::read(root.join("greeting.txt")).unwrap();
        assert_eq!(body, data);
        assert!(!root.join("greeting.txt.partial").exists());

        let wf = store.waiting_files().unwrap();
        assert_eq!(wf.len(), 1);
        assert_eq!(wf[0].name, "greeting.txt");
        assert_eq!(wf[0].size, data.len() as u64);

        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn put_file_resumes_from_offset() {
        let root = tmp_root();
        let store = TaildropStore::new(&root).unwrap();

        // Pre-write a prefix into the `.partial` directly, simulating bytes already received by an
        // earlier (interrupted) transfer.
        let prefix = b"the first half ";
        let partial = root.join("resume.txt.partial");
        std::fs::write(&partial, prefix).unwrap();

        // Resume at offset == the prefix length: `put_file` opens the existing partial, seeks past
        // the prefix, and appends the rest.
        let rest = b"and the second half";
        let total = store
            .put_file(
                "resume.txt",
                &rest[..],
                prefix.len() as u64,
                (prefix.len() + rest.len()) as u64,
            )
            .await
            .unwrap();

        // The returned count is offset + freshly-copied bytes, and the final file is the prefix and
        // the resumed bytes concatenated (the seek positioned the write correctly).
        assert_eq!(total, (prefix.len() + rest.len()) as u64);
        let body = std::fs::read(root.join("resume.txt")).unwrap();
        let mut expected = prefix.to_vec();
        expected.extend_from_slice(rest);
        assert_eq!(body, expected);
        assert!(!partial.exists());

        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn put_file_short_body_leaves_partial_not_truncated_final() {
        // F2: a body that ends before the declared length must NOT be finalized as a complete (but
        // truncated) file under the real name. Go errors when copyLength != length; we leave the
        // `.partial` in place for resume.
        let root = tmp_root();
        let store = TaildropStore::new(&root).unwrap();

        // Reader yields 5 bytes but we declare 10 expected (a short/interrupted stream).
        let err = store
            .put_file("short.txt", &b"world"[..], 0, 10)
            .await
            .unwrap_err();
        assert!(
            matches!(err, TaildropError::Io(ref e) if e.kind() == io::ErrorKind::UnexpectedEof),
            "a short body must error, got {err:?}"
        );
        // The final name was NEVER created; the partial remains with the bytes received so far.
        assert!(!root.join("short.txt").exists(), "no truncated final file");
        let partial = std::fs::read(root.join("short.txt.partial")).unwrap();
        assert_eq!(
            partial, b"world",
            "partial holds the received prefix for resume"
        );
        assert!(store.waiting_files().unwrap().is_empty());

        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn put_file_resume_offset_past_end_is_rejected() {
        // F3: a resume offset beyond the current partial length must be rejected (Go errors
        // "offset out of range"), not produce a zero-filled sparse hole.
        let root = tmp_root();
        let store = TaildropStore::new(&root).unwrap();
        std::fs::write(root.join("sparse.txt.partial"), b"abc").unwrap(); // 3 bytes on disk

        let err = store
            .put_file("sparse.txt", &b"xyz"[..], 99, 102)
            .await
            .unwrap_err();
        assert!(
            matches!(err, TaildropError::Io(ref e) if e.kind() == io::ErrorKind::InvalidInput),
            "offset past end must be rejected, got {err:?}"
        );
        // The partial is untouched (still 3 bytes), no final file.
        assert_eq!(
            std::fs::read(root.join("sparse.txt.partial")).unwrap(),
            b"abc"
        );
        assert!(!root.join("sparse.txt").exists());

        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn put_file_resume_truncates_stale_tail() {
        // F3: resuming at an offset LESS than the current partial length must truncate the bytes
        // past the offset (Go `Truncate(offset)`), so a stale tail from a prior attempt cannot
        // survive past the newly-written end.
        let root = tmp_root();
        let store = TaildropStore::new(&root).unwrap();
        // A prior attempt left 20 bytes; we resume at offset 5 with a 3-byte tail ⇒ final is 8 bytes.
        std::fs::write(root.join("retry.txt.partial"), b"KEEPme-STALE-TAILxxx").unwrap();

        let total = store
            .put_file("retry.txt", &b"NEW"[..], 5, 8)
            .await
            .unwrap();
        assert_eq!(total, 8);
        let body = std::fs::read(root.join("retry.txt")).unwrap();
        assert_eq!(
            body, b"KEEPmNEW",
            "bytes past offset 5 truncated, then NEW appended"
        );

        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn put_file_conflict_picks_non_clobbering_name() {
        let root = tmp_root();
        let store = TaildropStore::new(&root).unwrap();

        store
            .put_file("dup.txt", &b"first"[..], 0, 5)
            .await
            .unwrap();
        store
            .put_file("dup.txt", &b"second"[..], 0, 6)
            .await
            .unwrap();
        store
            .put_file("dup.txt", &b"third"[..], 0, 5)
            .await
            .unwrap();

        // Original plus two non-clobbering renames.
        assert!(root.join("dup.txt").exists());
        assert!(root.join("dup (1).txt").exists());
        assert!(root.join("dup (2).txt").exists());

        let wf = store.waiting_files().unwrap();
        assert_eq!(wf.len(), 3);

        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn put_file_in_progress_partial_is_conflict() {
        let root = tmp_root();
        let store = TaildropStore::new(&root).unwrap();

        // Simulate an in-flight transfer by pre-creating the .partial file.
        std::fs::write(root.join("busy.txt.partial"), b"partial").unwrap();

        let err = store
            .put_file("busy.txt", &b"x"[..], 0, 1)
            .await
            .unwrap_err();
        assert!(matches!(err, TaildropError::FileExists));

        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn put_file_rejects_bad_name_before_any_io() {
        let root = tmp_root();
        let store = TaildropStore::new(&root).unwrap();

        let err = store
            .put_file("../escape", &b"x"[..], 0, 1)
            .await
            .unwrap_err();
        assert!(matches!(err, TaildropError::InvalidFileName));
        // Nothing was written anywhere.
        assert!(store.waiting_files().unwrap().is_empty());

        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn delete_and_open_roundtrip() {
        let root = tmp_root();
        let store = TaildropStore::new(&root).unwrap();

        store.put_file("doc.bin", &b"abc"[..], 0, 3).await.unwrap();
        let (_f, size) = store.open_file("doc.bin").unwrap();
        assert_eq!(size, 3);

        store.delete_file("doc.bin").unwrap();
        assert!(store.waiting_files().unwrap().is_empty());

        // Traversal can't reach outside the root.
        assert!(matches!(
            store.delete_file("../../etc/passwd"),
            Err(TaildropError::InvalidFileName)
        ));

        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn concurrent_resume_for_same_name_is_serialized() {
        // The in-flight name guard: while one transfer holds a base name, a second PUT for the SAME
        // name (the resume-race the lock closes) is rejected with FileExists rather than interleaving
        // writes into the shared `.partial`. We hold the first transfer open with a reader that never
        // completes until we let it, then fire the second concurrently.
        let root = tmp_root();
        let store = Arc::new(TaildropStore::new(&root).unwrap());

        // A reader that delivers a byte, then blocks until released — keeps transfer #1 in flight
        // (and thus the name claimed) while we attempt transfer #2.
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        struct BlockingReader {
            sent: bool,
            release: Option<tokio::sync::oneshot::Receiver<()>>,
        }
        impl AsyncRead for BlockingReader {
            fn poll_read(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                if !self.sent {
                    buf.put_slice(b"x");
                    self.sent = true;
                    return std::task::Poll::Ready(Ok(()));
                }
                // After the first byte, park until released, then report EOF.
                match self.release.as_mut() {
                    Some(rx) => match std::pin::Pin::new(rx).poll(cx) {
                        std::task::Poll::Ready(_) => {
                            self.release = None;
                            std::task::Poll::Ready(Ok(())) // EOF (no bytes written)
                        }
                        std::task::Poll::Pending => std::task::Poll::Pending,
                    },
                    None => std::task::Poll::Ready(Ok(())),
                }
            }
        }

        let s1 = store.clone();
        let t1 = tokio::spawn(async move {
            let reader = BlockingReader {
                sent: false,
                release: Some(release_rx),
            };
            // expected_len 1: completes once the single byte is read and the reader returns EOF.
            s1.put_file("race.bin", reader, 0, 1).await
        });

        // Wait until transfer #1 has actually claimed the name (its partial exists).
        let partial = root.join("race.bin.partial");
        for _ in 0..200 {
            if partial.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(
            partial.exists(),
            "transfer #1 should have created the partial"
        );

        // Transfer #2 for the SAME name, while #1 still holds the claim → FileExists, no interleave.
        let err = store
            .put_file("race.bin", &b"yy"[..], 1, 3)
            .await
            .unwrap_err();
        assert!(
            matches!(err, TaildropError::FileExists),
            "a concurrent transfer for an in-flight name must be rejected, got {err:?}"
        );

        // Release #1 so it finalizes cleanly, and confirm the name frees afterward.
        release_tx.send(()).unwrap();
        t1.await.unwrap().unwrap();
        // Now the name is free: a fresh transfer succeeds (the guard was released on drop).
        store.put_file("race.bin", &b"z"[..], 0, 1).await.unwrap();

        std::fs::remove_dir_all(&root).ok();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_in_store_root_is_refused_not_followed() {
        use std::os::unix::fs::symlink;

        let root = tmp_root();
        let store = TaildropStore::new(&root).unwrap();

        // An attacker-planted symlink in the store root, pointing at a sensitive file OUTSIDE it.
        let outside = tmp_root();
        std::fs::create_dir_all(&outside).unwrap();
        let secret = outside.join("secret");
        std::fs::write(&secret, b"TOP SECRET").unwrap();

        // (a) open_file must refuse a symlink target, never read through it.
        let link = root.join("link.txt");
        symlink(&secret, &link).unwrap();
        let open_err = store.open_file("link.txt").unwrap_err();
        assert!(
            matches!(open_err, TaildropError::Io(ref e) if e.kind() == io::ErrorKind::InvalidInput),
            "open_file must refuse a symlink, got {open_err:?}"
        );

        // (b) delete_file must refuse the symlink, leaving BOTH the link and its target intact.
        let del_err = store.delete_file("link.txt").unwrap_err();
        assert!(
            matches!(del_err, TaildropError::Io(ref e) if e.kind() == io::ErrorKind::InvalidInput),
            "delete_file must refuse a symlink, got {del_err:?}"
        );
        assert!(
            secret.exists(),
            "the symlink target must NOT have been deleted"
        );
        assert_eq!(std::fs::read(&secret).unwrap(), b"TOP SECRET");

        // (c) waiting_files must not report the symlink as a waiting file.
        assert!(
            store.waiting_files().unwrap().is_empty(),
            "a symlink in the store root must not be listed as a waiting file"
        );

        // (d) put_file onto a symlinked partial must refuse rather than write through the link.
        let link_partial = root.join("evil.bin.partial");
        symlink(&secret, &link_partial).unwrap();
        let put_err = store
            .put_file("evil.bin", &b"data"[..], 0, 4)
            .await
            .unwrap_err();
        assert!(
            matches!(put_err, TaildropError::Io(ref e) if e.kind() == io::ErrorKind::InvalidInput),
            "put_file must refuse a symlinked partial, got {put_err:?}"
        );
        assert_eq!(
            std::fs::read(&secret).unwrap(),
            b"TOP SECRET",
            "the symlink target must NOT have been written through"
        );

        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    /// `open_nofollow` must refuse a final-component symlink **atomically in the kernel**, not merely
    /// via the advisory `refuse_symlink` lstat. This is the property that closes the TOCTOU window an
    /// external process could otherwise win by swapping the path for a symlink after the lstat: the
    /// open itself fails (`ELOOP`) on a symlinked final component. The test deliberately bypasses
    /// `refuse_symlink` and points `open_nofollow` straight at a symlink, so it would PASS-by-reading
    /// the target if the flag were dropped — i.e. it is a real regression guard for the `O_NOFOLLOW`
    /// wiring, not just a re-test of the advisory check.
    #[cfg(unix)]
    #[test]
    fn open_nofollow_refuses_a_symlinked_target_atomically() {
        use std::os::unix::fs::symlink;

        let root = tmp_root();
        std::fs::create_dir_all(&root).unwrap();
        let outside = tmp_root();
        std::fs::create_dir_all(&outside).unwrap();
        let secret = outside.join("secret");
        std::fs::write(&secret, b"TOP SECRET").unwrap();

        let link = root.join("link.bin");
        symlink(&secret, &link).unwrap();

        // Read open through the symlink must fail at the kernel (ELOOP), never returning a handle to
        // the target. `ErrorKind::FilesystemLoop` is the mapped kind on current platforms; assert on
        // the raw `ELOOP` errno too so the guard holds even if the mapping changes.
        let read_err =
            open_nofollow(std::fs::OpenOptions::new().read(true), &link).expect_err("read open");
        assert_eq!(
            read_err.raw_os_error(),
            Some(libc::ELOOP),
            "O_NOFOLLOW read open of a symlink must fail with ELOOP, got {read_err:?}"
        );

        // Write open (the resume path) likewise refuses the symlink atomically.
        let write_err =
            open_nofollow(std::fs::OpenOptions::new().write(true), &link).expect_err("write open");
        assert_eq!(
            write_err.raw_os_error(),
            Some(libc::ELOOP),
            "O_NOFOLLOW write open of a symlink must fail with ELOOP, got {write_err:?}"
        );

        // The target was never opened/written through.
        assert_eq!(std::fs::read(&secret).unwrap(), b"TOP SECRET");

        // A real (non-symlink) file at the same final name opens fine — O_NOFOLLOW only rejects a
        // symlinked final component, so the normal store path is unaffected.
        let regular = root.join("regular.bin");
        std::fs::write(&regular, b"hello").unwrap();
        let mut f = open_nofollow(std::fs::OpenOptions::new().read(true), &regular)
            .expect("O_NOFOLLOW open of a regular file must succeed");
        let mut got = String::new();
        std::io::Read::read_to_string(&mut f, &mut got).unwrap();
        assert_eq!(got, "hello");

        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    #[test]
    fn next_available_name_inserts_before_extension() {
        let root = tmp_root();
        std::fs::create_dir_all(&root).unwrap();
        assert_eq!(next_available_name(&root, "a.txt"), "a.txt");
        std::fs::write(root.join("a.txt"), b"x").unwrap();
        assert_eq!(next_available_name(&root, "a.txt"), "a (1).txt");
        std::fs::write(root.join("a (1).txt"), b"x").unwrap();
        assert_eq!(next_available_name(&root, "a.txt"), "a (2).txt");
        // Dotfile (no real extension) appends at end.
        std::fs::write(root.join(".env"), b"x").unwrap();
        assert_eq!(next_available_name(&root, ".env"), ".env (1)");
        std::fs::remove_dir_all(&root).ok();
    }

    /// The reaper deletes a `.partial` older than `delete_delay` and keeps a fresh one. Aging is
    /// driven by the passed-in `now` (the partial's real mtime is ~now): `now + 2h` with a 1h delay
    /// makes an existing partial look 2h old (reaped); `now` with a 1h delay keeps it (~0s old).
    #[test]
    fn reaper_deletes_aged_partial_keeps_fresh_and_final() {
        let root = tmp_root();
        let store = TaildropStore::new(&root).unwrap();

        std::fs::write(root.join("abandoned.bin.partial"), b"half").unwrap();
        std::fs::write(root.join("done.bin"), b"complete").unwrap(); // a finished file, not a partial

        let now = SystemTime::now();
        let delay = Duration::from_secs(3600);

        // Fresh: nothing is older than the delay yet.
        assert_eq!(
            store.reap_abandoned_partials(now, delay),
            0,
            "nothing aged out"
        );
        assert!(root.join("abandoned.bin.partial").exists());

        // Aged: 2h in the future vs a 1h delay → the partial is reaped, the final file is untouched.
        let reaped = store.reap_abandoned_partials(now + Duration::from_secs(2 * 3600), delay);
        assert_eq!(reaped, 1, "the aged partial is reaped");
        assert!(
            !root.join("abandoned.bin.partial").exists(),
            "aged partial deleted"
        );
        assert!(
            root.join("done.bin").exists(),
            "a completed (non-partial) file must never be reaped"
        );

        std::fs::remove_dir_all(&root).ok();
    }

    /// An in-flight transfer's partial is NEVER reaped, even when aged (Go's "no active put" check):
    /// while a base name is claimed, the reaper skips its partial regardless of mtime.
    #[tokio::test]
    async fn reaper_spares_in_flight_partial() {
        let root = tmp_root();
        let store = TaildropStore::new(&root).unwrap();

        // Pre-write an (old) partial and claim its base name as in-flight.
        std::fs::write(root.join("live.bin.partial"), b"in progress").unwrap();
        let _claim = store.claim_in_flight("live.bin").expect("claim");

        // Even with a far-future `now` (well past the delay), the in-flight partial is spared.
        let reaped = store.reap_abandoned_partials(
            SystemTime::now() + Duration::from_secs(48 * 3600),
            Duration::from_secs(3600),
        );
        assert_eq!(reaped, 0, "an in-flight partial must not be reaped");
        assert!(
            root.join("live.bin.partial").exists(),
            "the in-flight partial survives the sweep"
        );

        // Once the claim drops, the same aged partial IS reaped.
        drop(_claim);
        let reaped = store.reap_abandoned_partials(
            SystemTime::now() + Duration::from_secs(48 * 3600),
            Duration::from_secs(3600),
        );
        assert_eq!(
            reaped, 1,
            "after the claim drops, the aged partial is reaped"
        );

        std::fs::remove_dir_all(&root).ok();
    }

    /// The background reaper task: (1) does NOT reap at startup, and (2) terminates when shutdown
    /// flips true. With the real DELETE_DELAY (1h) interval, the first real sweep is an hour out, so
    /// within this millisecond-scale test no sweep ever fires — which is exactly what proves both
    /// "the startup tick is skipped" (an aged partial present at start survives) and "the task is
    /// parked on the interval, woken only by shutdown". (`test-util`/paused-time is intentionally not
    /// pulled into this crate's deps, so this uses real time and the fact that 1h >> the test.)
    #[tokio::test]
    async fn reaper_task_skips_startup_then_terminates_on_shutdown() {
        let root = tmp_root();
        let store = Arc::new(TaildropStore::new(&root).unwrap());
        // A partial present at boot — it must survive (no startup reap fires within the test window).
        std::fs::write(root.join("boot.bin.partial"), b"x").unwrap();

        let (tx, rx) = tokio::sync::watch::channel(false);
        let handle = spawn_partial_reaper(store.clone(), rx);

        // Give the task a moment to reach its select!; the first real sweep is DELETE_DELAY (1h) out,
        // so nothing is reaped here.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            root.join("boot.bin.partial").exists(),
            "no reap before the first real sweep (startup tick is skipped; first sweep is 1h out)"
        );

        // Flip shutdown: the task must terminate via its select! shutdown arm, not hang on the 1h
        // interval. If the shutdown arm were broken this `timeout` would elapse (the next tick is ~1h
        // away), so the timeout firing IS the regression signal.
        tx.send_replace(true);
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("reaper must terminate on shutdown (not wait for the 1h interval)")
            .expect("reaper task must not panic");

        std::fs::remove_dir_all(&root).ok();
    }

    /// A reaper spawned when shutdown is ALREADY true terminates on its first loop iteration
    /// (`watch::Receiver::wait_for` returns immediately when the predicate already holds), rather
    /// than waiting a full DELETE_DELAY (1h) for the first tick.
    #[tokio::test]
    async fn reaper_task_terminates_when_shutdown_already_set() {
        let root = tmp_root();
        let store = Arc::new(TaildropStore::new(&root).unwrap());
        let (_tx, rx) = tokio::sync::watch::channel(true); // already shut down
        let handle = spawn_partial_reaper(store, rx);
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("a reaper spawned post-shutdown must exit promptly, not wait the 1h interval")
            .expect("reaper task must not panic");
        std::fs::remove_dir_all(&root).ok();
    }
}
