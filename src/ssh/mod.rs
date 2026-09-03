//! Support for tailnet-native, in-process SSH servers.
//!
//! # Overview
//!
//! This module (`tailscale::ssh`) holds helpers for running SSH servers on the tailnet
//! using [`russh`]. They delegate their functionality to the [`Handler`] trait, which is
//! `russh`'s notion of a _connection_ handler, i.e. a single incoming TCP connection gets
//! a single instance of [`Handler`].
//!
//! ## Channels
//!
//! SSH has a nested notion of channels, which are multiplexed over a single connection.
//! The terminal session you open over a normal machine-to-machine ssh connection runs in a
//! channel, and in principle, you can have multiple channels open on the same connection.
//!
//! The `channel_server` module provides a [`ChannelServer`] type that separates out the
//! per-channel handler logic from `russh`'s monolithic [`Handler`]. Channel handler logic
//! is supported here by [`ChannelHandler`], which is passed into [`ChannelServer`] and
//! processes a [`ChannelEvent`] stream for each channel that's opened.
//!
//! ## Terminal applications
//!
//! Support for building per-channel terminal application is provided by [`RatatuiTerm`],
//! which implements [`ChannelHandler`] to drive a
//! [`ratatui::Terminal`][::ratatui::Terminal]. The user provides an implementation of
//! [`RatatuiApp`] that consumes input data and supports draws to the screen, and the
//! [`RatatuiTerm`] drives it automatically.

pub extern crate russh;

use std::{fmt::Debug, net::SocketAddr, sync::Arc};

/// Upper bound on concurrent SSH connections served by [`Device::serve_ssh`]. The accept loop
/// back-pressures past this cap (defense-in-depth beside the per-connection channel cap).
const MAX_SSH_CONNECTIONS: usize = 64;

use russh::server::Handler;
use ts_control::SshConnIdentity;
pub use ts_control::{SshAccept, SshDecision, SshDenyReason, SshPolicy, SshRecorderFailureAction};

mod channel_server;
mod channel_write;
mod ratatui;
pub mod recording;
mod shell;

pub use channel_server::{ChannelContext, ChannelEvent, ChannelHandler, ChannelServer};
pub use ratatui::{RatatuiApp, RatatuiEnv, RatatuiTerm};
pub use shell::ShellHandler;

impl crate::Device {
    /// Authorize an incoming Tailscale SSH connection from `remote` requesting local user
    /// `requested_user`, against the control-pushed SSH policy.
    ///
    /// **Fail-closed.** This is the Rust analogue of Go `tailssh`'s policy evaluation. It:
    /// 1. resolves `remote`'s IP to a known tailnet peer — an unknown source is denied;
    /// 2. fetches the current [`SshPolicy`][ts_control::SshPolicy] — **no policy means deny-all**;
    /// 3. evaluates the policy (first-match-wins, default-deny) against the peer's identity.
    ///
    /// Returns the [`SshDecision`]. Callers MUST reject the connection on any
    /// [`SshDecision::Deny`]. Any lookup error is surfaced as `Err` and must also be treated as a
    /// rejection by the caller — the connection is never allowed on the error path.
    ///
    /// NOTE: `userLogin`-principal matching requires the connecting peer's owner login, which this
    /// fork's domain node model does not yet retain (it is reported as `None`); such principals
    /// therefore never match here. Node-id / node-IP / `any` principals match normally.
    pub async fn authorize_ssh(
        &self,
        remote: SocketAddr,
        requested_user: &str,
    ) -> Result<SshDecision, crate::Error> {
        use ts_control::SshDenyReason;

        let Some(peer) = self.peer_by_tailnet_ip(remote.ip()).await? else {
            tracing::warn!(remote = %remote, "ssh: source IP does not match a known tailnet peer");
            return Ok(SshDecision::Deny(SshDenyReason::NoRuleMatched));
        };

        let Some(policy) = self.ssh_policy().await? else {
            tracing::warn!(remote = %remote, "ssh: no SSH policy pushed by control; deny-all");
            return Ok(SshDecision::Deny(SshDenyReason::NoRuleMatched));
        };

        let id = SshConnIdentity {
            stable_id: peer.stable_id.0.clone(),
            src_ip: remote.ip(),
            // The domain node model does not retain the owner login; see method docs.
            user_login: None,
        };

        Ok(policy.evaluate_at_unix(&id, requested_user, now_unix_secs()))
    }
}

/// Current wall-clock time as Unix seconds, derived from [`std::time::SystemTime`].
///
/// The root crate does not depend on `chrono`, and the workspace pins it without the `clock`
/// feature anyway, so policy evaluation takes a Unix timestamp instead of a `DateTime`. An
/// unreadable clock (time before the Unix epoch) is clamped to [`i64::MAX`] so SSH-rule expiry
/// **fails closed**: a broken clock makes every time-limited rule look already-expired (deny)
/// rather than perpetually-live.
pub(crate) fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(i64::MAX)
}

/// Format `unix_secs` as ISO 8601 basic date-time in UTC (`20060102T150405`), Go
/// `tstime.BasicDateTTime`.
///
/// Hand-rolled rather than pulled from `chrono`: the root crate deliberately has no `chrono`
/// dependency (see [`now_unix_secs`]), and this is the only place it would be needed. The
/// days-to-civil-date conversion is Howard Hinnant's `civil_from_days`, the same algorithm Go's
/// `time` package uses, valid for any year in the proleptic Gregorian calendar.
pub(crate) fn basic_date_t_time(unix_secs: i64) -> String {
    let days = unix_secs.div_euclid(86_400);
    let secs_of_day = unix_secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}",
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    )
}

/// Convert days since the Unix epoch to a `(year, month, day)` civil date.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    // Shift the epoch to 0000-03-01 so leap days land at the end of the 400-year era.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// A fresh SSH connection identifier, shared by every session multiplexed on the connection.
///
/// Mirrors Go `tailssh`'s `conn.connID`
/// (`fmt.Sprintf("ssh-conn-%s-%02x", now.UTC().Format(tstime.BasicDateTTime), randBytes(5))`); it
/// is the `connectionID` recorded in every session's cast header, so an operator can group the
/// recordings of one multiplexed connection.
pub(crate) fn new_conn_id(now_unix: i64) -> String {
    let rand: [u8; 5] = rand::random();
    let hex: String = rand.iter().map(|b| format!("{b:02x}")).collect();
    format!("ssh-conn-{}-{hex}", basic_date_t_time(now_unix))
}

/// Trait to construct a new [`Handler`] from a Tailscale [`Device`][crate::Device] and
/// the address of a connecting client.
///
/// Rephrasing of [`russh::server::Server`] that includes the Tailscale device as an
/// argument and skips the support for off-tailnet IP and Unix sockets.
pub trait TailnetServer {
    /// Construct a new handler.
    fn new_client(dev: Arc<crate::Device>, addr: SocketAddr) -> Self;
}

impl crate::Device {
    /// Serve an ssh service on the given TCP address.
    ///
    /// This is a minimal helper that just wires up the relevant pieces. All the
    /// authentication and actual SSH server logic must be implemented by the caller in
    /// the `TailnetServer` (`H`) and configured by `config`.
    pub async fn serve_ssh<H>(
        self: Arc<Self>,
        config: russh::server::Config,
        listen_addr: SocketAddr,
    ) -> Result<(), crate::Error>
    where
        H: TailnetServer + Handler + Send + 'static,
        H::Error: Debug,
    {
        let config = Arc::new(config);
        let listener = self.tcp_listen(listen_addr).await?;

        tracing::info!(%listen_addr, "ssh server listening");

        // Bound concurrent connections (back-pressure: acquire a permit *before* accepting so the
        // loop stops pulling connections off the listener once at the cap). Per-connection sessions
        // are held in a `JoinSet` owned by this future rather than detached via bare `tokio::spawn`,
        // so dropping the `serve_ssh` future (the caller's cancellation model) both stops accepting
        // and aborts in-flight sessions instead of leaking them.
        let sem = Arc::new(tokio::sync::Semaphore::new(MAX_SSH_CONNECTIONS));
        let mut sessions = tokio::task::JoinSet::new();

        loop {
            // Reap finished sessions opportunistically so the `JoinSet` does not grow unbounded.
            while sessions.try_join_next().is_some() {}

            // The semaphore is never closed in this loop; if it somehow is, stop accepting.
            let Ok(permit) = sem.clone().acquire_owned().await else {
                return Ok(());
            };
            let conn = listener.accept().await?;

            let handler = H::new_client(self.clone(), conn.remote_addr());
            let config = config.clone();

            sessions.spawn(async move {
                // Hold the permit for the connection's lifetime; dropping it on task end frees the
                // slot for the next accept.
                let _permit = permit;
                let sess = match russh::server::run_stream(config, conn, handler).await {
                    Ok(sess) => sess,
                    Err(e) => {
                        tracing::error!(error = ?e, "establishing session");
                        return;
                    }
                };

                match sess.await {
                    Ok(()) => {}
                    Err(e) => {
                        tracing::error!(error = ?e, "running ssh session");
                    }
                }
            });
        }
    }

    /// Run a turnkey Tailscale SSH server on `listen_addr` (tailnet overlay) that grants authorized
    /// connections an interactive login shell as their policy-mapped local user.
    ///
    /// Authorization is the control-pushed SSH policy (see [`Device::authorize_ssh`]) — fail-closed:
    /// unknown source, no policy, no matching rule, or any error rejects. The accepted connection's
    /// `local_user` is resolved against the local passwd database and the login shell is spawned in
    /// a PTY **after dropping privileges** to that user's uid/gid (the daemon must run as root to do
    /// so; if it cannot, the session fails closed). Mirrors Go `tailssh`'s incubator shell path.
    ///
    /// Only the interactive login-shell path is implemented: `pty-req` → `<shell> -l`,
    /// `window-change` → `TIOCSWINSZ`, and an `exit-status` on shell exit. The exec form
    /// (`<shell> -c <cmd>`) is **not** supported because [`ChannelEvent`] does not surface an SSH
    /// `exec` request in this fork's channel abstraction.
    pub async fn listen_ssh(
        self: Arc<Self>,
        config: russh::server::Config,
        listen_addr: SocketAddr,
    ) -> Result<(), crate::Error> {
        self.serve_ssh::<ChannelServer<ShellHandler>>(config, listen_addr)
            .await
    }

    /// Serve an SSH TUI service on the given TCP address.
    ///
    /// Wrapper around [`serve_ssh`][crate::Device::serve_ssh] to specifically use
    /// [`ChannelServer`] around a [`RatatuiTerm`] using `App`.
    pub async fn serve_ssh_tui<App>(
        self: Arc<Self>,
        config: russh::server::Config,
        listen_addr: SocketAddr,
    ) -> Result<(), crate::Error>
    where
        App: RatatuiApp + Default + Send + 'static,
    {
        self.serve_ssh::<ChannelServer<RatatuiTerm<App>>>(config, listen_addr)
            .await
    }
}

#[cfg(all(test, feature = "ssh"))]
mod tests {
    use super::{basic_date_t_time, new_conn_id};

    /// The connection id's timestamp is ISO 8601 basic format in UTC, Go
    /// `tstime.BasicDateTTime`.
    #[test]
    fn basic_date_t_time_formats_utc() {
        // 2023-11-14T22:13:20Z, the round number 1_700_000_000.
        assert_eq!(basic_date_t_time(1_700_000_000), "20231114T221320");
        // The epoch itself, and the day before it (a negative timestamp must not wrap).
        assert_eq!(basic_date_t_time(0), "19700101T000000");
        assert_eq!(basic_date_t_time(-1), "19691231T235959");
        // A leap day, where an off-by-one in the civil-date conversion would show.
        assert_eq!(basic_date_t_time(1_709_164_800), "20240229T000000");
        // A century year that IS a leap year (2000 is divisible by 400) has a 29 February.
        assert_eq!(basic_date_t_time(951_782_400), "20000229T000000");
        // One that is NOT (1900) does not: 59 days after 1900-01-01 is 1 March, not 29 February.
        assert_eq!(basic_date_t_time(-2_203_891_200), "19000301T000000");
    }

    /// The connection id has Go's shape: the `ssh-conn-` prefix, a basic-format timestamp, and 5
    /// random bytes in hex. Two connections never share one.
    #[test]
    fn conn_id_is_prefixed_timestamped_and_unique() {
        let id = new_conn_id(1_700_000_000);
        assert!(id.starts_with("ssh-conn-20231114T221320-"), "{id}");
        let suffix = id.rsplit('-').next().expect("suffix");
        assert_eq!(suffix.len(), 10, "5 random bytes as hex: {id}");
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()), "{id}");
        assert_ne!(
            new_conn_id(1_700_000_000),
            new_conn_id(1_700_000_000),
            "each connection must be distinguishable in the recordings"
        );
    }
}
