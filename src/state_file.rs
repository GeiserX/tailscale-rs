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
/// exactly `0700`. That is Go's rule: it only takes over a directory it can tell is its own. On
/// Windows the same rule holds, with the name compared case-insensitively, and the directory's
/// owner and access list are reset so only the current user and the Administrators can reach it.
pub(crate) fn mk_state_dir(dir: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(dir)?;

    #[cfg(any(unix, windows))]
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

/// Go `paths.ensureStateDirPermsWindows`, in Go's order: the directory must exist and be a
/// directory, and only one named `tailscale` (any case, Go's `strings.ToLower`) is touched.
#[cfg(windows)]
fn ensure_state_dir_perms(dir: &Path) -> io::Result<()> {
    let meta = std::fs::metadata(dir)?;
    if !meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("expected {} to be a directory", dir.display()),
        ));
    }
    let named_tailscale = dir
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.to_lowercase() == "tailscale");
    if !named_tailscale {
        return Ok(());
    }
    windows_acl::restrict_to_user_and_admins(dir)
}

/// The Win32 calls behind [`ensure_state_dir_perms`] on Windows.
#[cfg(windows)]
mod windows_acl {
    use std::{io, os::windows::ffi::OsStrExt as _, path::Path, ptr};

    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, GENERIC_ALL, HANDLE, LocalFree,
            WIN32_ERROR,
        },
        Security::{
            ACL,
            Authorization::{
                EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, SET_ACCESS,
                SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_USER,
                TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_TYPE, TRUSTEE_W,
            },
            CreateWellKnownSid, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION,
            GetTokenInformation, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
            PSID, SECURITY_MAX_SID_SIZE, SUB_CONTAINERS_AND_OBJECTS_INHERIT,
            TOKEN_INFORMATION_CLASS, TOKEN_PRIMARY_GROUP, TOKEN_QUERY, TOKEN_USER,
            TokenPrimaryGroup, TokenUser, WinBuiltinAdministratorsSid,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    /// Set the owner of `dir` to the current user, its primary group to the current primary group,
    /// and its DACL to full control for the current user and the built-in Administrators, inherited
    /// by everything created inside and protected from the parent's entries (Go
    /// `ensureStateDirPermsWindows`, paths/paths_windows.go:46-97).
    pub(super) fn restrict_to_user_and_admins(dir: &Path) -> io::Result<()> {
        // Go `winutil.GetCurrentUserSIDs`: the user and primary group SIDs of the process token.
        let token = ProcessToken::open()?;
        let user_info = token.information(TokenUser)?;
        let group_info = token.information(TokenPrimaryGroup)?;
        // SAFETY: GetTokenInformation(TokenUser) filled this 8-byte-aligned buffer with a
        // TOKEN_USER whose SID points into the same buffer, which outlives every use below.
        let user_sid: PSID = unsafe { (*user_info.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        // SAFETY: as above, for TokenPrimaryGroup and TOKEN_PRIMARY_GROUP.
        let group_sid: PSID =
            unsafe { (*group_info.as_ptr().cast::<TOKEN_PRIMARY_GROUP>()).PrimaryGroup };

        // Go `windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)`.
        let mut admins = [0u32; SECURITY_MAX_SID_SIZE as usize / 4];
        let mut admins_len = SECURITY_MAX_SID_SIZE;
        let admins_sid: PSID = admins.as_mut_ptr().cast();
        // SAFETY: `admins_sid` points at SECURITY_MAX_SID_SIZE writable bytes, 4-byte aligned as a
        // SID needs, and `admins_len` says so. A builtin SID needs no domain SID.
        if unsafe {
            CreateWellKnownSid(
                WinBuiltinAdministratorsSid,
                ptr::null_mut(),
                admins_sid,
                &mut admins_len,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }

        // Go's two EXPLICIT_ACCESS entries: GENERIC_ALL, SET_ACCESS,
        // SUB_CONTAINERS_AND_OBJECTS_INHERIT, one for the user and one for Administrators.
        let entries = [
            full_control(user_sid, TRUSTEE_IS_USER),
            full_control(admins_sid, TRUSTEE_IS_WELL_KNOWN_GROUP),
        ];

        // Go `windows.ACLFromEntries(explicitAccess, nil)`: a fresh ACL, nothing merged in.
        let mut dacl: *mut ACL = ptr::null_mut();
        // SAFETY: `entries` is a live array of two initialised entries whose SIDs outlive the call;
        // `dacl` receives a LocalAlloc'd ACL that `LocalAcl` frees.
        check(unsafe { SetEntriesInAclW(2, entries.as_ptr(), ptr::null(), &mut dacl) })?;
        let dacl = LocalAcl(dacl);

        let mut wide: Vec<u16> = dir.as_os_str().encode_wide().collect();
        if wide.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} contains a NUL", dir.display()),
            ));
        }
        wide.push(0);

        // Go's flags: owner, group and DACL, protected so the parent's entries are not inherited.
        let flags = OWNER_SECURITY_INFORMATION
            | GROUP_SECURITY_INFORMATION
            | DACL_SECURITY_INFORMATION
            | PROTECTED_DACL_SECURITY_INFORMATION;
        // SAFETY: `wide` is NUL-terminated; the SIDs and the ACL are valid for the whole call.
        check(unsafe {
            SetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                flags,
                user_sid,
                group_sid,
                dacl.0,
                ptr::null(),
            )
        })
    }

    fn full_control(sid: PSID, kind: TRUSTEE_TYPE) -> EXPLICIT_ACCESS_W {
        EXPLICIT_ACCESS_W {
            grfAccessPermissions: GENERIC_ALL,
            grfAccessMode: SET_ACCESS,
            grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
            // Go `windows.TRUSTEE{nil, NO_MULTIPLE_TRUSTEE, TRUSTEE_IS_SID, kind,
            // TrusteeValueFromSID(sid)}`.
            Trustee: TRUSTEE_W {
                pMultipleTrustee: ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: kind,
                ptstrName: sid.cast(),
            },
        }
    }

    fn check(rc: WIN32_ERROR) -> io::Result<()> {
        if rc == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(rc as i32))
        }
    }

    /// An ACL allocated by `SetEntriesInAclW`, freed with `LocalFree`.
    struct LocalAcl(*mut ACL);

    impl Drop for LocalAcl {
        fn drop(&mut self) {
            // SAFETY: the pointer came from SetEntriesInAclW and is freed exactly once.
            unsafe { LocalFree(self.0.cast()) };
        }
    }

    /// The current process token, opened for query and closed on drop.
    pub(super) struct ProcessToken(HANDLE);

    impl ProcessToken {
        pub(super) fn open() -> io::Result<Self> {
            let mut handle: HANDLE = ptr::null_mut();
            // SAFETY: GetCurrentProcess returns a pseudo-handle; `handle` is a valid out pointer.
            if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self(handle))
        }

        /// One token information class, in a buffer of 8-byte words so the structure it holds,
        /// which carries pointers into the same buffer, is aligned.
        pub(super) fn information(&self, class: TOKEN_INFORMATION_CLASS) -> io::Result<Vec<u64>> {
            let mut len = 0u32;
            // SAFETY: a null buffer of length zero only asks for the size.
            if unsafe { GetTokenInformation(self.0, class, ptr::null_mut(), 0, &mut len) } == 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
                    return Err(err);
                }
            }
            let mut buf = vec![0u64; (len as usize).div_ceil(8)];
            // SAFETY: `buf` holds at least `len` writable bytes.
            if unsafe { GetTokenInformation(self.0, class, buf.as_mut_ptr().cast(), len, &mut len) }
                == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(buf)
        }
    }

    impl Drop for ProcessToken {
        fn drop(&mut self) {
            // SAFETY: the handle came from OpenProcessToken and is closed exactly once.
            unsafe { CloseHandle(self.0) };
        }
    }

    /// What the Windows test reads back from a directory's security descriptor.
    #[cfg(test)]
    pub(super) struct Descriptor {
        pub(super) owner_is_user: bool,
        pub(super) dacl_protected: bool,
        /// One entry per ACE: `Some(true)` the current user, `Some(false)` Administrators, `None`
        /// anyone else or a non-allow ACE.
        pub(super) grantees: Vec<Option<bool>>,
    }

    #[cfg(test)]
    pub(super) fn describe(dir: &Path) -> Descriptor {
        use windows_sys::Win32::Security::{
            ACCESS_ALLOWED_ACE, Authorization::GetNamedSecurityInfoW, EqualSid, GetAce,
            GetSecurityDescriptorControl, IsWellKnownSid, PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
        };

        let token = ProcessToken::open().unwrap();
        let user_info = token.information(TokenUser).unwrap();
        // SAFETY: see `restrict_to_user_and_admins`.
        let user_sid: PSID = unsafe { (*user_info.as_ptr().cast::<TOKEN_USER>()).User.Sid };

        let wide: Vec<u16> = dir.as_os_str().encode_wide().chain([0]).collect();
        let mut owner: PSID = ptr::null_mut();
        let mut dacl: *mut ACL = ptr::null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated and every out pointer is valid; `sd` owns what
        // `owner` and `dacl` point into and is freed below.
        check(unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut sd,
            )
        })
        .unwrap();

        // SAFETY: `sd`, `owner` and `dacl` are valid until the LocalFree at the end.
        unsafe {
            let mut control = 0u16;
            let mut revision = 0u32;
            assert_ne!(
                GetSecurityDescriptorControl(sd, &mut control, &mut revision),
                0
            );
            let mut grantees = Vec::new();
            for i in 0..u32::from((*dacl).AceCount) {
                let mut ace = ptr::null_mut();
                assert_ne!(GetAce(dacl, i, &mut ace), 0);
                let ace = ace.cast::<ACCESS_ALLOWED_ACE>();
                // ACCESS_ALLOWED_ACE_TYPE is 0.
                if (*ace).Header.AceType != 0 {
                    grantees.push(None);
                    continue;
                }
                let sid: PSID = ptr::addr_of_mut!((*ace).SidStart).cast();
                grantees.push(if EqualSid(sid, user_sid) != 0 {
                    Some(true)
                } else if IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0 {
                    Some(false)
                } else {
                    None
                });
            }
            let described = Descriptor {
                owner_is_user: EqualSid(owner, user_sid) != 0,
                dacl_protected: control & SE_DACL_PROTECTED != 0,
                grantees,
            };
            LocalFree(sd);
            described
        }
    }
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

    /// Go's Windows rule: a directory named `tailscale`, in any case, is owned by the current user
    /// and its DACL, protected from the parent's, grants only that user and Administrators; any
    /// other directory keeps what it inherits.
    #[cfg(windows)]
    #[test]
    fn mk_state_dir_matches_go_on_windows() {
        let root = scratch("mkdir-win");

        let own = root.join("TailScale");
        mk_state_dir(&own).unwrap();
        let d = windows_acl::describe(&own);
        assert!(d.owner_is_user, "the owner is the current user");
        assert!(d.dacl_protected, "the parent's entries are not inherited");
        assert!(
            d.grantees.iter().all(Option::is_some),
            "only the user and Administrators are granted: {:?}",
            d.grantees
        );
        assert!(d.grantees.contains(&Some(true)), "the user is granted");
        assert!(
            d.grantees.contains(&Some(false)),
            "Administrators are granted"
        );

        // Running it again on the existing directory gives the same result.
        mk_state_dir(&own).unwrap();
        assert!(windows_acl::describe(&own).dacl_protected);

        let other = root.join("other");
        mk_state_dir(&other).unwrap();
        assert!(
            !windows_acl::describe(&other).dacl_protected,
            "any other directory is left alone"
        );

        std::fs::remove_dir_all(&root).unwrap();
    }
}
