//! A turnkey login-shell [`ChannelHandler`] for Tailscale SSH.
//!
//! [`ShellHandler`] runs the policy-mapped local user's login shell inside a PTY, faithfully
//! mirroring the interactive subset of Go `tailssh`'s incubator path: a `pty-req` allocates the
//! PTY and starts the login shell (`<shell> -l`), `window-change` resizes it, and the child's exit
//! code is reported back as an `exit-status`.
//!
//! # Security
//!
//! This handler **spawns a real login shell and drops privileges** to the authorized user. Several
//! invariants keep it fail-closed:
//!
//! * The local user comes **only** from the [`SshAccept`] produced by the single fail-closed
//!   authorization decision in [`auth_none`][russh::server::Handler::auth_none]. The handler never
//!   re-evaluates policy nor falls back to a configured default user.
//! * If the user cannot be resolved against the local passwd database, [`ShellHandler::new`]
//!   returns `Err` and the channel is closed — **a shell is never spawned for an unknown user**.
//! * Privileges are dropped in the child's `pre_exec` in the exact order
//!   supplementary-groups → `setgid` → `setuid` (uid **last**, because after `setuid` the process
//!   can no longer change its gid). Any failure aborts the `exec`, so the shell never runs with the
//!   wrong or elevated identity. This requires the daemon to run as root; if it does not, the
//!   `setuid`/`setgid` calls fail and the spawn fails closed.
//! * The child environment is built from scratch (`HOME`/`USER`/`SHELL`/`PATH`/`TERM`) rather than
//!   inherited, so the daemon's environment (which may carry secrets) never leaks into the shell.

use std::{path::PathBuf, sync::Arc};

use nix::unistd::{Gid, Uid, User};
use pty_process::{OwnedWritePty, Size};
use russh::{ChannelId, Sig, server::Handle};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
};

use crate::{
    Device,
    ssh::{ChannelEvent, ChannelHandler, SshAccept},
};

/// Default shell used when a resolved user has no shell set in the passwd database.
const DEFAULT_SHELL: &str = "/bin/sh";

/// Default `PATH` for the spawned login shell. The login shell itself (`-l`) will typically
/// re-derive `PATH` from system/user profiles; this is a safe minimal baseline.
const DEFAULT_PATH: &str = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";

/// The resolved local-user facts needed to spawn and privilege-drop into a login shell.
///
/// Captured up front in [`ShellHandler::new`] so the security-critical values are fixed at
/// authorization time and not re-resolved later.
#[derive(Debug, Clone)]
struct ResolvedUser {
    /// Unix login name.
    name: String,
    /// Numeric user id to `setuid` to.
    uid: Uid,
    /// Numeric primary group id to `setgid` to.
    gid: Gid,
    /// Home directory (used as the shell's working directory and `$HOME`).
    home: PathBuf,
    /// Login shell to exec (falls back to [`DEFAULT_SHELL`] if the passwd entry is empty).
    shell: PathBuf,
}

/// Resolve `local_user` against the local passwd database.
///
/// **Fail-closed:** a missing entry ([`Ok(None)`]) or a lookup error both yield `Err`, so callers
/// never proceed to spawn a shell for an unresolved user. An empty shell field is normalized to
/// [`DEFAULT_SHELL`].
fn resolve_user(local_user: &str) -> std::io::Result<ResolvedUser> {
    match User::from_name(local_user) {
        Ok(Some(user)) => {
            let shell = if user.shell.as_os_str().is_empty() {
                PathBuf::from(DEFAULT_SHELL)
            } else {
                user.shell
            };
            Ok(ResolvedUser {
                name: user.name,
                uid: user.uid,
                gid: user.gid,
                home: user.dir,
                shell,
            })
        }
        Ok(None) => Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("ssh: local user {local_user:?} not found in passwd database"),
        )),
        Err(e) => Err(std::io::Error::other(format!(
            "ssh: resolving local user {local_user:?} failed: {e}"
        ))),
    }
}

/// Build the minimal, non-inherited environment for the login shell as `(key, value)` pairs.
///
/// Only `HOME`, `USER`, `LOGNAME`, `SHELL`, `PATH`, and `TERM` are set; nothing is inherited from
/// the daemon, so its environment (potentially holding secrets) never leaks to the shell.
fn build_env(user: &ResolvedUser) -> Vec<(String, String)> {
    vec![
        ("HOME".to_string(), user.home.to_string_lossy().into_owned()),
        ("USER".to_string(), user.name.clone()),
        ("LOGNAME".to_string(), user.name.clone()),
        (
            "SHELL".to_string(),
            user.shell.to_string_lossy().into_owned(),
        ),
        ("PATH".to_string(), DEFAULT_PATH.to_string()),
        ("TERM".to_string(), "xterm-256color".to_string()),
    ]
}

/// The login-shell flag (`-l`) passed to the user's shell to start it as a login shell, mirroring
/// Go `tailssh`'s interactive path.
const LOGIN_SHELL_ARG: &str = "-l";

/// One privilege-drop operation, in the order it must be applied.
///
/// This is a pure, comparable representation of the security-critical drop sequence so the
/// ordering invariant (uid **last**) can be unit-tested without root or a real fork. The plan is
/// built before the fork (allocates) and applied step-by-step inside the `pre_exec` closure (no
/// alloc, async-signal-safe).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrivDropStep {
    /// Set supplementary groups from the user's group membership (Linux; absent on Apple).
    /// Carries the primary `gid` because `initgroups` needs it; storing it here keeps the
    /// executor free of any pre-fork lookups.
    InitGroups(Gid),
    /// Set the real/effective/saved group id.
    SetGid(Gid),
    /// Set the real/effective/saved user id. MUST be last.
    SetUid(Uid),
}

/// Build the privilege-drop plan in the sacred order: supplementary groups, then setgid, then
/// setuid LAST (uid-last so the process cannot re-raise its gid after dropping uid). This is a
/// pure function so the ordering invariant can be unit-tested without root or a real fork.
///
/// `with_initgroups` is `false` on Apple targets (where `nix` has no `initgroups`), matching the
/// `#[cfg(not(target_vendor = "apple"))]` gating of the real call; on Apple the plan is just
/// `[SetGid, SetUid]`.
fn priv_drop_plan(uid: Uid, gid: Gid, with_initgroups: bool) -> Vec<PrivDropStep> {
    let mut plan = Vec::with_capacity(3);
    if with_initgroups {
        plan.push(PrivDropStep::InitGroups(gid));
    }
    plan.push(PrivDropStep::SetGid(gid));
    plan.push(PrivDropStep::SetUid(uid));
    plan
}

/// Apply a single privilege-drop step via the corresponding `nix`/libc wrapper.
///
/// Runs post-fork inside `pre_exec`, so it must stay async-signal-safe: it only calls the libc
/// wrappers and allocates nothing. `user_cname` is the login name needed by `initgroups`; it is
/// `Some` only on platforms where an [`PrivDropStep::InitGroups`] step is present.
fn apply_priv_drop_step(
    step: &PrivDropStep,
    user_cname: Option<&std::ffi::CStr>,
) -> std::io::Result<()> {
    match step {
        PrivDropStep::InitGroups(gid) => {
            // `initgroups` is configured out of `nix` on Apple targets, and `priv_drop_plan`
            // never emits this step there, so the call is gated to match.
            #[cfg(not(target_vendor = "apple"))]
            {
                let cname = user_cname.ok_or_else(|| {
                    std::io::Error::other("ssh: initgroups step without user name")
                })?;
                nix::unistd::initgroups(cname, *gid)
                    .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
            }
            #[cfg(target_vendor = "apple")]
            {
                let _ = (gid, user_cname);
            }
        }
        PrivDropStep::SetGid(gid) => {
            nix::unistd::setgid(*gid).map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
        }
        PrivDropStep::SetUid(uid) => {
            nix::unistd::setuid(*uid).map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
        }
    }
    Ok(())
}

/// A turnkey [`ChannelHandler`] that runs the authorized user's login shell in a PTY.
///
/// Construct one indirectly via [`Device::listen_ssh`][crate::Device::listen_ssh]; it is not meant
/// to be created by hand.
pub struct ShellHandler {
    /// The russh channel this shell is bound to.
    channel_id: ChannelId,
    /// The owned write half of the PTY master; client input is written here, and window-resize
    /// `TIOCSWINSZ` ioctls are issued through it.
    pty_write: OwnedWritePty,
    /// The spawned child shell, shared with the output-pump task so both sides can signal/kill it.
    child: Arc<Mutex<tokio::process::Child>>,
}

impl ShellHandler {
    /// Forward the numeric POSIX signal `signum` to the child shell, best-effort.
    async fn signal_child(&self, signum: i32) {
        let pid = { self.child.lock().await.id() };
        let Some(pid) = pid else {
            return;
        };
        let Ok(signal) = nix::sys::signal::Signal::try_from(signum) else {
            tracing::debug!(signum, "ssh: unmapped signal; not forwarding");
            return;
        };
        if let Err(e) =
            nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as nix::libc::pid_t), signal)
        {
            tracing::debug!(error = %e, signum, "ssh: failed forwarding signal to shell");
        }
    }

    /// Kill the child shell, best-effort. Used on channel close/EOF.
    async fn kill_child(&self) {
        let mut child = self.child.lock().await;
        if let Err(e) = child.start_kill() {
            tracing::debug!(error = %e, "ssh: failed to kill shell child");
        }
    }
}

/// Map a russh [`Sig`] to its POSIX signal number for forwarding to the child.
fn sig_to_signum(sig: &Sig) -> Option<i32> {
    Some(match sig {
        Sig::HUP => nix::libc::SIGHUP,
        Sig::INT => nix::libc::SIGINT,
        Sig::QUIT => nix::libc::SIGQUIT,
        Sig::KILL => nix::libc::SIGKILL,
        Sig::TERM => nix::libc::SIGTERM,
        _ => return None,
    })
}

impl ChannelHandler for ShellHandler {
    type Error = std::io::Error;

    fn new(
        rt: tokio::runtime::Handle,
        channel_id: ChannelId,
        session: Handle,
        _dev: Arc<Device>,
        accept: &SshAccept,
    ) -> Result<Self, Self::Error> {
        // SECURITY: the identity comes solely from the fail-closed `auth_none` decision.
        let user = resolve_user(&accept.local_user)?;
        let env = build_env(&user);

        // Allocate the PTY master/subordinate pair.
        let (pty, pts) = pty_process::open().map_err(std::io::Error::other)?;

        // Build the privilege-drop plan BEFORE the fork (this allocates a Vec). Inside the
        // `pre_exec` closure we only iterate + call the syscalls (no alloc, async-signal-safe).
        //
        // `initgroups` is unavailable on Apple targets in `nix`; it is the production (Linux)
        // path. macOS dev builds still compile and drop the primary gid + uid (no InitGroups step,
        // so `user_cname` is not needed there).
        #[cfg(not(target_vendor = "apple"))]
        let with_initgroups = true;
        #[cfg(target_vendor = "apple")]
        let with_initgroups = false;
        let plan = priv_drop_plan(user.uid, user.gid, with_initgroups);
        // The login name needed by `initgroups`; only present on the platforms that have that step.
        #[cfg(not(target_vendor = "apple"))]
        let user_cname = std::ffi::CString::new(user.name.clone())
            .map_err(|e| std::io::Error::other(format!("ssh: user name has NUL byte: {e}")))?;

        let mut cmd = pty_process::Command::new(&user.shell);
        cmd = cmd.arg(LOGIN_SHELL_ARG).current_dir(&user.home).env_clear();
        for (k, v) in env {
            cmd = cmd.env(k, v);
        }

        // SECURITY: privilege drop runs in the child between fork and exec. Order is sacred:
        // (1) supplementary groups, (2) setgid, (3) setuid LAST. setuid is last because once the
        // uid is dropped the process can no longer change its gid. Any failure aborts the exec, so
        // the shell never runs with the wrong or elevated identity. The ordered `plan` was built
        // pre-fork (see `priv_drop_plan`); here we only iterate it and apply each step in order —
        // behavior is identical to the previous inline initgroups→setgid→setuid sequence.
        //
        // Safety: the closure only calls async-signal-safe libc wrappers (initgroups/setgid/
        // setuid) via `apply_priv_drop_step` and allocates nothing; it is sound to run post-fork.
        cmd = unsafe {
            cmd.pre_exec(move || {
                #[cfg(not(target_vendor = "apple"))]
                let user_cname = Some(user_cname.as_c_str());
                #[cfg(target_vendor = "apple")]
                let user_cname: Option<&std::ffi::CStr> = None;
                for step in &plan {
                    apply_priv_drop_step(step, user_cname)?;
                }
                Ok(())
            })
        };

        let child = cmd.spawn(pts).map_err(std::io::Error::other)?;

        let (mut pty_read, pty_write) = pty.into_split();
        let child = Arc::new(Mutex::new(child));

        // Pump PTY output → SSH channel data, then report the child's exit status. Runs on the
        // shared tokio runtime so it lives independently of `handle_event` calls.
        let pump_child = child.clone();
        rt.spawn(async move {
            let mut buf = [0u8; 16 * 1024];
            loop {
                match pty_read.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if session.data(channel_id, buf[..n].to_vec()).await.is_err() {
                            tracing::debug!(%channel_id, "ssh: client gone; stopping shell pump");
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, %channel_id, "ssh: pty read error");
                        break;
                    }
                }
            }

            // Report exit status (best-effort). russh exposes `exit_status_request(id, u32)`.
            let status = { pump_child.lock().await.wait().await };
            match status {
                Ok(status) => {
                    // A signal-killed shell has `code() == None`; reporting that as `exit-status 0`
                    // would lie to the client (success). russh's `exit_signal_request` needs a `Sig`
                    // name mapped from the raw signal number — awkward — so we take the simpler,
                    // still-correct path: convey signal death as the conventional `128 + signal`
                    // non-zero status (what a POSIX shell reports), never a bogus 0.
                    use std::os::unix::process::ExitStatusExt as _;
                    let code = status
                        .code()
                        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
                        as u32;
                    if session.exit_status_request(channel_id, code).await.is_err() {
                        tracing::debug!(%channel_id, "ssh: failed sending exit-status");
                    }
                }
                Err(e) => {
                    tracing::debug!(error = %e, %channel_id, "ssh: waiting on shell child");
                }
            }
            if session.close(channel_id).await.is_err() {
                tracing::trace!(%channel_id, "ssh: channel already closed");
            }
        });

        Ok(Self {
            channel_id,
            pty_write,
            child,
        })
    }

    async fn handle_event(&mut self, event: &ChannelEvent) -> Result<(), Self::Error> {
        match event {
            ChannelEvent::Data(bytes) => {
                self.pty_write.write_all(bytes).await?;
                self.pty_write.flush().await?;
            }
            ChannelEvent::Resize { width, height } => {
                // `pty-req` initial size and later `window-change` both arrive here. Issue
                // TIOCSWINSZ via pty-process' resize (rows, cols).
                if let Err(e) = self.pty_write.resize(Size::new(*height, *width)) {
                    tracing::debug!(error = %e, channel_id = %self.channel_id, "ssh: pty resize");
                }
            }
            ChannelEvent::Signal(sig) => {
                if let Some(signum) = sig_to_signum(sig) {
                    self.signal_child(signum).await;
                } else {
                    tracing::debug!(?sig, "ssh: unhandled signal; not forwarding");
                }
            }
            ChannelEvent::Close | ChannelEvent::Eof => {
                tracing::debug!(channel_id = %self.channel_id, ?event, "ssh: closing shell");
                self.kill_child().await;
            }
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "ssh"))]
mod tests {
    use super::*;

    fn fake_user() -> ResolvedUser {
        ResolvedUser {
            name: "alice".to_string(),
            uid: Uid::from_raw(1000),
            gid: Gid::from_raw(1000),
            home: PathBuf::from("/home/alice"),
            shell: PathBuf::from("/bin/bash"),
        }
    }

    #[test]
    fn env_is_minimal_and_correct() {
        let env = build_env(&fake_user());
        let get = |k: &str| {
            env.iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.as_str())
        };

        assert_eq!(get("HOME"), Some("/home/alice"));
        assert_eq!(get("USER"), Some("alice"));
        assert_eq!(get("LOGNAME"), Some("alice"));
        assert_eq!(get("SHELL"), Some("/bin/bash"));
        assert_eq!(get("TERM"), Some("xterm-256color"));
        assert_eq!(get("PATH"), Some(DEFAULT_PATH));
        // No daemon environment leaks through: only the six known keys are present.
        assert_eq!(env.len(), 6);
    }

    #[test]
    fn resolve_unknown_user_fails_closed() {
        // A username that cannot exist in any passwd database must yield Err, never a shell.
        let err = resolve_user("definitely-not-a-real-user-xyz")
            .expect_err("bogus user must fail closed");
        assert!(matches!(
            err.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::Other
        ));
    }

    #[test]
    fn login_shell_uses_dash_l() {
        // The interactive path always starts a login shell with `-l`. The exec form
        // (`<shell> -c <cmd>`) is documented as unsupported because `ChannelEvent` carries no
        // exec request; see the module note in `Device::listen_ssh`.
        assert_eq!(LOGIN_SHELL_ARG, "-l");
    }

    #[test]
    fn priv_drop_plan_orders_uid_last() {
        let uid = Uid::from_raw(1000);
        let gid = Gid::from_raw(1000);
        // Linux production path includes the supplementary-groups step first.
        let plan = priv_drop_plan(uid, gid, true);
        assert_eq!(
            plan,
            vec![
                PrivDropStep::InitGroups(gid),
                PrivDropStep::SetGid(gid),
                PrivDropStep::SetUid(uid),
            ],
            "drop sequence must be initgroups → setgid → setuid"
        );
        // setuid MUST be last — fails loudly if anyone reorders.
        assert_eq!(plan.last(), Some(&PrivDropStep::SetUid(uid)));
    }

    #[test]
    fn priv_drop_plan_apple_skips_initgroups() {
        let uid = Uid::from_raw(1000);
        let gid = Gid::from_raw(1000);
        // Apple path: `initgroups` is unavailable, so no InitGroups step — but still uid-last.
        let plan = priv_drop_plan(uid, gid, false);
        assert_eq!(
            plan,
            vec![PrivDropStep::SetGid(gid), PrivDropStep::SetUid(uid)],
        );
        assert!(!plan.contains(&PrivDropStep::InitGroups(gid)));
        assert_eq!(plan.last(), Some(&PrivDropStep::SetUid(uid)));
    }

    #[test]
    fn priv_drop_setgid_before_setuid() {
        let uid = Uid::from_raw(1000);
        let gid = Gid::from_raw(1000);
        // The sacred invariant expressed directly: gid is dropped before uid, on every platform.
        for with_initgroups in [true, false] {
            let plan = priv_drop_plan(uid, gid, with_initgroups);
            let setgid_idx = plan
                .iter()
                .position(|s| *s == PrivDropStep::SetGid(gid))
                .expect("plan must set gid");
            let setuid_idx = plan
                .iter()
                .position(|s| *s == PrivDropStep::SetUid(uid))
                .expect("plan must set uid");
            assert!(
                setgid_idx < setuid_idx,
                "setgid must precede setuid (with_initgroups={with_initgroups})"
            );
        }
    }

    #[test]
    fn empty_shell_falls_back_to_default() {
        // Mirror resolve_user's normalization of an empty passwd shell field.
        let mut u = fake_user();
        u.shell = PathBuf::from("");
        let shell = if u.shell.as_os_str().is_empty() {
            PathBuf::from(DEFAULT_SHELL)
        } else {
            u.shell.clone()
        };
        assert_eq!(shell, PathBuf::from(DEFAULT_SHELL));
    }
}
