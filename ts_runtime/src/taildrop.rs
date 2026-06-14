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
};

use tokio::io::{AsyncRead, AsyncReadExt};

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

/// Reject a path that is (or whose final component is) a symlink, mirroring the intent of Go's
/// `O_NOFOLLOW` on the taildrop file ops. `validate_base_name` already blocks a traversing *name*,
/// but not a symlink **component already planted in the store root** by a local attacker (e.g.
/// `root/foo.txt -> /etc/cron.d/x`), which a plain `open`/`rename`/`remove` would follow. Uses
/// `symlink_metadata` (lstat — does NOT follow the final symlink); a non-existent path is fine
/// (returns `Ok(())`), only an existing symlink is refused. This is checked under the per-name
/// in-flight lock, so it cannot race our own operations on the same name; the residual is an
/// external process mutating the store dir concurrently, which already requires store-dir write
/// access (the threat bound for this hardening).
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
        let mut set = self.in_flight.lock().unwrap_or_else(|p| p.into_inner());
        if !set.insert(base.to_string()) {
            return Err(TaildropError::FileExists);
        }
        Ok(InFlightGuard {
            set: self.in_flight.clone(),
            name: base.to_string(),
        })
    }

    /// The partial-file path for an already-validated base name.
    fn partial_path(&self, base: &str) -> PathBuf {
        self.root.join(format!("{base}{PARTIAL_SUFFIX}"))
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
    /// path ([`TaildropError::FileExists`]) until the stale partial is cleared. There is no automatic
    /// reaper for an abandoned partial yet (Go's `fileDeleter` GCs one after ~1h); tracked separately.
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

        // Refuse to follow a symlink planted in the store root (Go's `O_NOFOLLOW` intent): the
        // partial must be a regular file we create/own, never a pre-existing symlink to elsewhere.
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
            let mut f = std::fs::OpenOptions::new().write(true).open(&partial)?;
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
            // an existing symlink target outright (Go `O_NOFOLLOW` intent). The `_claim` guard (held
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
            // never reported as a waiting file (Go `O_NOFOLLOW` intent), even one pointing at a real
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
    /// traversal attempt can never escape the store root, and a symlink at the target is refused (Go
    /// `O_NOFOLLOW` intent) rather than followed — a planted `root/foo.txt -> /etc/passwd` must not
    /// let a `delete foo.txt` remove the link's target.
    pub fn delete_file(&self, name: &str) -> Result<(), TaildropError> {
        let base = validate_base_name(name).ok_or(TaildropError::InvalidFileName)?;
        let path = self.root.join(base);
        refuse_symlink(&path)?;
        std::fs::remove_file(path)?;
        Ok(())
    }

    /// Open a fully-received file by base name for reading, returning the handle and its size (Go
    /// `OpenFile`). The name is validated first, and a symlink at the target is refused (Go
    /// `O_NOFOLLOW` intent) so a planted symlink cannot redirect the read to an arbitrary file.
    pub fn open_file(&self, name: &str) -> Result<(std::fs::File, u64), TaildropError> {
        let base = validate_base_name(name).ok_or(TaildropError::InvalidFileName)?;
        let path = self.root.join(base);
        refuse_symlink(&path)?;
        let f = std::fs::File::open(path)?;
        let size = f.metadata()?.len();
        Ok((f, size))
    }
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
}
