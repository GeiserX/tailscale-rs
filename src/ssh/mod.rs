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

use russh::server::Handler;
use ts_control::SshConnIdentity;
pub use ts_control::{SshAccept, SshDecision, SshDenyReason, SshPolicy};

mod channel_server;
mod channel_write;
mod ratatui;
mod shell;

pub use channel_server::{ChannelEvent, ChannelHandler, ChannelServer};
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
fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(i64::MAX)
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

        loop {
            let conn = listener.accept().await?;

            let handler = H::new_client(self.clone(), conn.remote_addr());
            let config = config.clone();

            tokio::task::spawn(async move {
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
