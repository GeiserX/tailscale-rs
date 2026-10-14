//! Crash-safe, owner-only files for persisted node state: the analog of Go's
//! `atomicfile.WriteFile` and `paths.MkStateDir`.

use std::{
    io::{self, Write as _},
    path::{Path, PathBuf},
};

/// Create the state directory `dir`, and any missing parent, with mode `0700` on Unix (Go
/// `paths.MkStateDir`).
///
/// An existing directory keeps its mode, except one whose base name is `tailscale`, which is set to
/// exactly `0700`. That is Go's rule: it only takes over a directory it can tell is its own.
pub(crate) fn mk_state_dir(dir: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(dir)?;

    #[cfg(unix)]
    ensure_state_dir_perms(dir)?;

    Ok(())
}

/// Go `paths.ensureStateDirPermsUnix`.
#[cfg(unix)]
fn ensure_state_dir_perms(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    if dir.file_name().is_none_or(|name| name != "tailscale") {
        return Ok(());
    }
    let meta = std::fs::metadata(dir)?;
    if !meta.is_dir() {
        return Err(io::Error::other(format!(
            "expected {} to be a directory",
            dir.display()
        )));
    }
    if meta.permissions().mode() & 0o777 == 0o700 {
        return Ok(());
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

/// Replace the file at `path` with `data` so that a crash at any point leaves either the old file or
/// the new one, never a truncated mix (Go `atomicfile.WriteFile`).
///
/// The data goes to a temporary file in the same directory, made owner-only (`0600` on Unix) before
/// any byte is written, synced to disk, then renamed over `path`. A `path` that exists but is not a
/// regular file is refused. On failure the temporary file is removed.
pub(crate) fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    if let Ok(meta) = std::fs::metadata(path)
        && !meta.is_file()
    {
        return Err(io::Error::other(format!(
            "{} already exists and is not a regular file",
            path.display()
        )));
    }

    let (tmp, file) = create_temp(path)?;
    let result = fill_and_rename(file, &tmp, path, data);
    if result.is_err() {
        drop(std::fs::remove_file(&tmp));
    }
    result
}

fn fill_and_rename(
    mut file: std::fs::File,
    tmp: &Path,
    path: &Path,
    data: &[u8],
) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(data)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(tmp, path)
}

/// Create a new, empty temporary file next to `path`, named `<name>.tmp<random>` like Go's
/// `os.CreateTemp(dir, name+".tmp")`. Exclusive creation, so it can never open a file or symlink
/// that is already there.
fn create_temp(path: &Path) -> io::Result<(PathBuf, std::fs::File)> {
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} has no file name", path.display()),
        )
    })?;
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }

    // Go gives up after 10000 name collisions; so do we.
    for _ in 0..10_000 {
        let mut tmp_name = name.to_os_string();
        tmp_name.push(format!(".tmp{}", rand::random::<u32>()));
        let tmp = dir.join(tmp_name);
        match opts.open(&tmp) {
            Ok(file) => return Ok((tmp, file)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("no free temporary file name next to {}", path.display()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ts-state-file-{name}-{}", std::process::id()));
        drop(std::fs::remove_dir_all(&dir));
        dir
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn write_atomic_creates_and_replaces_leaving_only_the_target() {
        let dir = scratch("replace");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");

        write_atomic(&path, b"first").unwrap();
        write_atomic(&path, b"second").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        assert_eq!(
            entries(&dir),
            ["state.json"],
            "no temporary file may be left"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "got {mode:o}");
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn write_atomic_refuses_a_target_that_is_not_a_regular_file() {
        let dir = scratch("not-regular");
        let path = dir.join("state.json");
        std::fs::create_dir_all(&path).unwrap();

        write_atomic(&path, b"data").unwrap_err();
        assert_eq!(
            entries(&dir),
            ["state.json"],
            "the temporary file is not left behind"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Go's rule, exactly: new directories are `0700`, an existing directory named `tailscale` is
    /// set to `0700`, and any other existing directory is left alone.
    #[cfg(unix)]
    #[test]
    fn mk_state_dir_matches_go() {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;

        let root = scratch("mkdir");
        let nested = root.join("a").join("b");
        mk_state_dir(&nested).unwrap();
        assert_eq!(mode(&root), 0o700);
        assert_eq!(mode(&root.join("a")), 0o700);
        assert_eq!(mode(&nested), 0o700);

        let own = root.join("tailscale");
        std::fs::create_dir(&own).unwrap();
        std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o755)).unwrap();
        mk_state_dir(&own).unwrap();
        assert_eq!(mode(&own), 0o700, "an existing tailscale dir is tightened");

        let other = root.join("other");
        std::fs::create_dir(&other).unwrap();
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o755)).unwrap();
        mk_state_dir(&other).unwrap();
        assert_eq!(mode(&other), 0o755, "any other existing dir is left alone");

        std::fs::remove_dir_all(&root).unwrap();
    }
}
