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
    io::{self, Seek, Write},
    path::{Path, PathBuf},
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
    if !dir.join(base).exists() {
        return base.to_string();
    }
    let (stem, ext) = match base.rsplit_once('.') {
        // Keep the dot with the extension; an empty stem (dotfile like ".bashrc") has no split.
        Some((stem, ext)) if !stem.is_empty() => (stem, format!(".{ext}")),
        _ => (base, String::new()),
    };
    for n in 1..=10_000u32 {
        let candidate = format!("{stem} ({n}){ext}");
        if !dir.join(&candidate).exists() {
            return candidate;
        }
    }
    // Pathological fallback: suffix with a high counter; extremely unlikely to be reached.
    format!("{stem} (overflow){ext}")
}

/// A Taildrop file store rooted at a fixed directory. All operations are confined to this root by
/// joining only [`validate_base_name`]-validated names.
#[derive(Debug, Clone)]
pub struct TaildropStore {
    root: PathBuf,
}

impl TaildropStore {
    /// Create a store rooted at `root`, creating the directory (and parents) if needed.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, TaildropError> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// The partial-file path for an already-validated base name.
    fn partial_path(&self, base: &str) -> PathBuf {
        self.root.join(format!("{base}{PARTIAL_SUFFIX}"))
    }

    /// Receive a file named `name` from `reader`, writing to `<name>.partial` then atomically
    /// renaming to a non-clobbering final name on success. Mirrors Go `manager.PutFile`.
    ///
    /// `offset` lets a resumed transfer append past already-written bytes (the partial is opened and
    /// the write starts at `offset`). Returns the total number of bytes in the completed file.
    ///
    /// Fail-closed: an invalid name is rejected before any path is built; an in-progress partial for
    /// the same name yields [`TaildropError::FileExists`]; an I/O error mid-transfer leaves the
    /// `.partial` in place (for resume) and the final name is never created.
    pub async fn put_file<R>(
        &self,
        name: &str,
        mut reader: R,
        offset: u64,
    ) -> Result<u64, TaildropError>
    where
        R: AsyncRead + Unpin,
    {
        let base = validate_base_name(name).ok_or(TaildropError::InvalidFileName)?;
        let partial = self.partial_path(base);

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

            // Atomically publish under a non-clobbering final name.
            let final_name = next_available_name(&root, &base);
            let final_path = root.join(&final_name);
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

        Ok(offset + copied)
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
            let meta = entry.metadata()?;
            if !meta.is_file() {
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
    /// traversal attempt can never escape the store root.
    pub fn delete_file(&self, name: &str) -> Result<(), TaildropError> {
        let base = validate_base_name(name).ok_or(TaildropError::InvalidFileName)?;
        std::fs::remove_file(self.root.join(base))?;
        Ok(())
    }

    /// Open a fully-received file by base name for reading, returning the handle and its size (Go
    /// `OpenFile`). The name is validated first.
    pub fn open_file(&self, name: &str) -> Result<(std::fs::File, u64), TaildropError> {
        let base = validate_base_name(name).ok_or(TaildropError::InvalidFileName)?;
        let f = std::fs::File::open(self.root.join(base))?;
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
        let n = store.put_file("greeting.txt", &data[..], 0).await.unwrap();
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
            .put_file("resume.txt", &rest[..], prefix.len() as u64)
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
    async fn put_file_conflict_picks_non_clobbering_name() {
        let root = tmp_root();
        let store = TaildropStore::new(&root).unwrap();

        store.put_file("dup.txt", &b"first"[..], 0).await.unwrap();
        store.put_file("dup.txt", &b"second"[..], 0).await.unwrap();
        store.put_file("dup.txt", &b"third"[..], 0).await.unwrap();

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

        let err = store.put_file("busy.txt", &b"x"[..], 0).await.unwrap_err();
        assert!(matches!(err, TaildropError::FileExists));

        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn put_file_rejects_bad_name_before_any_io() {
        let root = tmp_root();
        let store = TaildropStore::new(&root).unwrap();

        let err = store.put_file("../escape", &b"x"[..], 0).await.unwrap_err();
        assert!(matches!(err, TaildropError::InvalidFileName));
        // Nothing was written anywhere.
        assert!(store.waiting_files().unwrap().is_empty());

        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn delete_and_open_roundtrip() {
        let root = tmp_root();
        let store = TaildropStore::new(&root).unwrap();

        store.put_file("doc.bin", &b"abc"[..], 0).await.unwrap();
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
