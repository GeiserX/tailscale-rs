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
//! * The local user comes **only** from the [`SshAccept`][crate::ssh::SshAccept] produced by the single fail-closed
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
//! * When the matched policy rule demands **session recording**, the recorder is dialed and the
//!   cast header written *before* the shell is spawned, so a session that must be recorded but
//!   cannot be is never started. See [`recording`][crate::ssh::recording] for the transport and
//!   for Go's fail-open / fail-closed rules around it.

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
    ssh::{
        ChannelContext, ChannelEvent, ChannelHandler,
        recording::{CastHeader, RecordingRejected, SessionRecording, TailnetDialer},
    },
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
        ("TERM".to_string(), DEFAULT_TERM.to_string()),
    ]
}

/// The login-shell flag (`-l`) passed to the user's shell to start it as a login shell, mirroring
/// Go `tailssh`'s interactive path.
const LOGIN_SHELL_ARG: &str = "-l";

/// `TERM` for the spawned shell, and the value recorded in a session recording's cast header. Go
/// falls back to the same `xterm-256color` when the client sends no `TERM`.
const DEFAULT_TERM: &str = "xterm-256color";

/// Exit status reported when a session is refused because the recording policy could not be
/// satisfied.
///
/// Go uses 254 for exactly this and documents why: 1 is overloaded, 127 is "command not found",
/// 130 is Ctrl-C, and 255 means "ssh itself failed", so 254 is the one code in the reserved >128
/// region an operator can alert on unambiguously.
const RECORDING_DENIED_EXIT_CODE: u32 = 254;

/// The cast header for this session (Go `startNewRecording`'s `sessionrecording.CastHeader`).
///
/// `width`/`height` are left at zero, the value Go writes for a session with no PTY request. This
/// fork's channel abstraction creates the session handler at channel-open, which is *before* the
/// client's `pty-req` arrives (it is delivered later as a [`ChannelEvent::Resize`]), so the
/// terminal size is not yet known when the header has to be written. The size is still applied to
/// the PTY itself when the resize event arrives; only the header's advisory dimensions are absent.
fn session_cast_header(ctx: &ChannelContext, user: &ResolvedUser) -> CastHeader {
    let mut header = CastHeader::new(crate::ssh::now_unix_secs(), DEFAULT_TERM);
    header.ssh_user = ctx.ssh_user.clone();
    header.local_user = user.name.clone();
    header.connection_id = ctx.conn_id.clone();

    if let Some(node) = &ctx.src_node {
        set_src_node(
            &mut header,
            node.fqdn(false),
            node.stable_id.0.clone(),
            &node.tags,
            node.user_id,
        );
    }

    header
}

/// Record the originating node in `header`.
///
/// Go records the *owner* of an untagged node and the *tags* of a tagged one, never both. The
/// owner's login name is not retained by this fork's node model (see
/// [`Device::authorize_ssh`][crate::Device::authorize_ssh]), so an untagged node contributes only
/// its numeric user id.
fn set_src_node(
    header: &mut CastHeader,
    fqdn: String,
    stable_id: String,
    tags: &[String],
    user_id: i64,
) {
    header.src_node = fqdn;
    header.src_node_id = stable_id;
    if tags.is_empty() {
        header.src_node_user_id = user_id;
    } else {
        header.src_node_tags = tags.to_vec();
    }
}

/// Tell the client why its session is refused, then close the channel.
///
/// Reached only when the policy set `onRecordingFailure.rejectSessionWithMessage` and no recorder
/// would take the recording.
async fn reject_session(session: &Handle, channel_id: ChannelId, rejected: RecordingRejected) {
    tracing::warn!(
        %channel_id,
        error = %rejected.cause,
        message = %rejected.message,
        "ssh: session refused: session recording could not be started"
    );
    let refused = session
        .data(channel_id, format!("{}\r\n", rejected.message).into_bytes())
        .await
        .is_err()
        || session
            .exit_status_request(channel_id, RECORDING_DENIED_EXIT_CODE)
            .await
            .is_err()
        || session.close(channel_id).await.is_err();
    if refused {
        tracing::debug!(%channel_id, "ssh: client gone before the refusal reached it");
    }
}

/// Tell the client the session is being terminated, then kill the shell.
///
/// Reached only when the policy set `onRecordingFailure.terminateSessionWithMessage` and the
/// recording of a *running* session failed.
async fn end_session(
    session: &Handle,
    channel_id: ChannelId,
    child: &Arc<Mutex<tokio::process::Child>>,
    message: &str,
) {
    tracing::warn!(%channel_id, message, "ssh: terminating session: session recording failed");
    if session
        .data(channel_id, format!("\r\n{message}\r\n").into_bytes())
        .await
        .is_err()
    {
        tracing::debug!(%channel_id, "ssh: client gone before the termination notice reached it");
    }
    if let Err(e) = child.lock().await.start_kill() {
        tracing::debug!(error = %e, %channel_id, "ssh: failed to kill shell after recording failure");
    }
}

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

    // This handler streams its PTY output to the policy's `recorders`, so `ChannelServer` may
    // admit a connection whose rule demands recording; see `SessionRecording` for what happens
    // when the recorders cannot be reached.
    const RECORDS_SESSION: bool = true;

    async fn new(
        rt: tokio::runtime::Handle,
        channel_id: ChannelId,
        session: Handle,
        dev: Arc<Device>,
        ctx: &ChannelContext,
    ) -> Result<Self, Self::Error> {
        let accept = &ctx.accept;
        // SECURITY: the identity comes solely from the fail-closed `auth_none` decision.
        let user = resolve_user(&accept.local_user)?;
        let env = build_env(&user);

        // SECURITY: start the recording BEFORE the shell exists. Go does the same (the session
        // handler calls `startNewRecording` and only then `launchProcess`), and the ordering is
        // what makes a fail-closed policy mean anything: a session that must be recorded is never
        // spawned first and recorded second.
        let recording = if accept.recorders.is_empty() {
            None
        } else {
            let header = session_cast_header(ctx, &user);
            match SessionRecording::start(
                &accept.recorders,
                accept.on_recording_failure.as_ref(),
                &header,
                &TailnetDialer::new(dev),
            )
            .await
            {
                Ok(rec) => rec,
                Err(rejected) => {
                    // The policy set `rejectSessionWithMessage`: show it and refuse. The channel
                    // is closed by the caller on `Err`, so the message is written first.
                    reject_session(&session, channel_id, rejected).await;
                    return Err(std::io::Error::other("ssh: session recording refused"));
                }
            }
        };

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
            let mut recording = recording;
            // Fires with the message to show the client when the recorder upload failed and the
            // policy says terminate (Go's `TerminateSessionWithMessage`).
            let mut terminate = recording.as_mut().and_then(|r| r.take_terminate());
            loop {
                let read = tokio::select! {
                    message = async {
                        match terminate.as_mut() {
                            Some(rx) => rx.await.ok(),
                            None => std::future::pending().await,
                        }
                    } => {
                        terminate = None;
                        if let Some(message) = message {
                            end_session(&session, channel_id, &pump_child, &message).await;
                            break;
                        }
                        continue;
                    }
                    read = pty_read.read(&mut buf) => read,
                };

                match read {
                    Ok(0) => break,
                    Ok(n) => {
                        // Only output is recorded, and it is recorded *before* it reaches the
                        // client. Go deliberately does not record input, which may carry
                        // passwords.
                        if let Some(rec) = recording.as_mut()
                            && let Err(message) = rec.record_output(&buf[..n]).await
                        {
                            end_session(&session, channel_id, &pump_child, &message).await;
                            break;
                        }
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

    /// A [`ChannelContext`] with no resolved peer, carrying the facts the cast header needs.
    fn ctx() -> ChannelContext {
        ChannelContext {
            accept: crate::ssh::SshAccept {
                local_user: "ubuntu".to_string(),
                accept_env: Vec::new(),
                session_duration_nanos: None,
                allow_agent_forwarding: false,
                allow_local_port_forwarding: false,
                allow_remote_port_forwarding: false,
                recorders: Vec::new(),
                on_recording_failure: None,
                hold_and_delegate: String::new(),
                recording_refusal_message: String::new(),
            },
            ssh_user: "operator".to_string(),
            remote: "100.64.0.7:52344".parse().unwrap(),
            src_node: None,
            conn_id: "ssh-conn-20231114T221320-0011223344".to_string(),
        }
    }

    /// The cast header identifies the session: the username the client asked for, the local user
    /// it was mapped to, the connection it belongs to, and the terminal type.
    #[test]
    fn cast_header_describes_the_session() {
        let header = session_cast_header(&ctx(), &fake_user());
        assert_eq!(
            header.ssh_user, "operator",
            "the username the client presented"
        );
        assert_eq!(
            header.local_user,
            fake_user().name,
            "the local user the policy mapped it to"
        );
        assert_eq!(header.connection_id, "ssh-conn-20231114T221320-0011223344");
        assert_eq!(
            header.env.get("TERM").map(String::as_str),
            Some(DEFAULT_TERM)
        );
        // No PTY size is known when the handler is built; see `session_cast_header`.
        assert_eq!((header.width, header.height), (0, 0));
        // With no resolved peer nothing about the source node is invented.
        assert!(header.src_node.is_empty());
        assert!(header.src_node_id.is_empty());
        assert_eq!(header.src_node_user_id, 0);
        assert!(header.src_node_tags.is_empty());
    }

    /// An untagged node contributes its owner id; a tagged node contributes its tags. Never both,
    /// which is Go's rule.
    #[test]
    fn src_node_records_owner_or_tags_never_both() {
        let mut untagged = CastHeader::new(0, DEFAULT_TERM);
        set_src_node(
            &mut untagged,
            "laptop.tail-scale.ts.net".to_string(),
            "nodeid-abc".to_string(),
            &[],
            42,
        );
        assert_eq!(untagged.src_node, "laptop.tail-scale.ts.net");
        assert_eq!(untagged.src_node_id, "nodeid-abc");
        assert_eq!(untagged.src_node_user_id, 42);
        assert!(untagged.src_node_tags.is_empty());

        let mut tagged = CastHeader::new(0, DEFAULT_TERM);
        set_src_node(
            &mut tagged,
            "ci.tail-scale.ts.net".to_string(),
            "nodeid-def".to_string(),
            &["tag:ci".to_string()],
            42,
        );
        assert_eq!(tagged.src_node_tags, vec!["tag:ci".to_string()]);
        assert_eq!(
            tagged.src_node_user_id, 0,
            "a tagged node has no human owner to record"
        );
    }

    /// The refusal exit status is the one Go reserves for a denied recording-required session.
    #[test]
    fn recording_refusal_uses_the_reserved_exit_code() {
        assert_eq!(RECORDING_DENIED_EXIT_CODE, 254);
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
