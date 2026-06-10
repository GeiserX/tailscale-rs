use std::{collections::HashMap, marker::PhantomData, net::SocketAddr, sync::Arc};

use russh::{
    Channel, ChannelId, Pty, Sig,
    server::{Auth, Handle, Msg, Session},
};
use tokio::{
    sync::{mpsc, mpsc::UnboundedSender},
    task::JoinSet,
};

use crate::{
    Device,
    ssh::{SshAccept, TailnetServer},
};

type Request = (ChannelId, ChannelEvent);

/// Handler for a channel session.
pub trait ChannelHandler: Sized {
    /// Error this handler produces.
    type Error: Into<std::io::Error> + std::error::Error;

    /// Construct a new per-channel handler.
    ///
    /// `accept` is the [`SshAccept`] produced by the single fail-closed authorization decision in
    /// [`auth_none`][russh::server::Handler::auth_none]; in particular its
    /// [`local_user`][SshAccept::local_user] is the policy-mapped identity the session must run as.
    /// Handlers MUST NOT re-evaluate policy or substitute a different user — the accepted identity
    /// is the sole authorization source.
    fn new(
        handle: tokio::runtime::Handle,
        channel_id: ChannelId,
        session: Handle,
        dev: Arc<Device>,
        accept: &SshAccept,
    ) -> Result<Self, Self::Error>;

    /// Handle an event from the channel.
    fn handle_event(
        &mut self,
        event: &ChannelEvent,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// Implementation of [`russh::server::Handler`] which provides per-channel session
/// handlers using a parametric [`ChannelHandler`].
///
/// Primary motivation is to support custom console or TUI sessions over tailnet SSH
/// connections.
///
/// # Authentication and authorization
///
/// Incoming connections are gated by the control-pushed Tailscale SSH policy: [`auth_none`]
/// resolves the source IP to a known tailnet peer and evaluates the policy via
/// [`Device::authorize_ssh`][crate::Device::authorize_ssh] (fail-closed — an unknown peer, an
/// absent policy, or a non-matching policy all reject). The `ssh` policy block's accept/reject
/// rules, principal matching, and SSH-user mapping are honored. A rule that **demands** session
/// recording (non-empty `recorders`) or `holdAndDelegate` is enforced **fail-closed**: since this
/// fork has no recorder transport / delegate round-trip yet, such a session is refused rather than
/// silently accepted un-recorded (see [`auth_none`]). Building those transports is deferred.
///
/// [`auth_none`]: russh::server::Handler::auth_none
pub struct ChannelServer<H> {
    channel_state: HashMap<ChannelId, ChannelState>,
    remote: SocketAddr,
    dev: Arc<Device>,
    /// The accepted identity from the single [`auth_none`][russh::server::Handler::auth_none]
    /// authorization decision, stashed so per-channel handlers run as the policy-mapped user.
    /// `None` until a successful `auth_none`; a channel open with `None` here fails closed.
    accepted: Option<SshAccept>,
    _handler: PhantomSend<H>,
}

struct PhantomSend<H>(PhantomData<fn() -> H>);

/// Maximum number of concurrent channels a single SSH connection may open. Each channel spawns a
/// session handler (e.g. a login shell), so this caps the per-connection resource/process fan-out
/// an authorized-but-hostile peer can induce. SSH clients realistically open one (or a few)
/// sessions per connection, so this is generous for legitimate use.
const MAX_CHANNELS_PER_CONN: usize = 16;

/// Whether a connection at `open_channels` currently-open channels has reached the per-connection
/// channel cap and must refuse the next channel open. Pure boundary predicate extracted from
/// [`ChannelServer::channel_open_session`] so the fork-bomb guard's edge can be unit-tested without
/// a live russh [`Session`].
fn at_channel_cap(open_channels: usize) -> bool {
    open_channels >= MAX_CHANNELS_PER_CONN
}

/// Fallback message logged when a `recording_required` session is refused and the policy supplied
/// no message of its own.
const DEFAULT_RECORDING_REFUSAL: &str =
    "policy requires session recording but recording is not available";

/// The fail-closed recording gate (tsr-0h2), extracted as a pure predicate so it can be unit-tested
/// without a live russh [`Session`]/[`Device`] (mirrors [`at_channel_cap`]).
///
/// Returns `Some(message)` when the accepted session must be **refused** because the matched rule
/// demands a capability this fork cannot provide — session recording (non-empty `recorders`) or a
/// `holdAndDelegate` decision (both surfaced as [`SshAccept::recording_required`]) — and there is no
/// recorder/delegate transport yet. The message is the policy's
/// [`recording_refusal_message`][crate::ssh::SshAccept::recording_refusal_message] when non-empty,
/// else [`DEFAULT_RECORDING_REFUSAL`]. Returns `None` for the common case (no recorders, no
/// delegate), so those sessions accept unchanged.
///
/// TODO(tsr-0h2 follow-up): once the recorder stream transport exists (dial `recorders`, asciinema/
/// CastV2 stream, tee PTY I/O at `shell.rs`) — and a Noise control round-trip backs `holdAndDelegate`
/// — relax this to Go `tailssh`'s true default: fail-OPEN on a recorder-connect failure UNLESS
/// `on_recording_failure.reject_session_with_message` is set. Until then, refuse rather than record
/// nothing.
fn recording_refusal(accept: &SshAccept) -> Option<String> {
    if !accept.recording_required {
        return None;
    }
    if accept.recording_refusal_message.is_empty() {
        Some(DEFAULT_RECORDING_REFUSAL.to_string())
    } else {
        Some(accept.recording_refusal_message.clone())
    }
}

#[derive(thiserror::Error, Debug, Copy, Clone, PartialEq, Eq)]
#[error("no such channel")]
struct NoChannel;

/// State of a channel in [`ChannelServer`].
struct ChannelState {
    channel: ChannelId,
    tx: UnboundedSender<Request>,
    _joinset: JoinSet<()>,
}

impl ChannelState {
    fn send(&self, event: ChannelEvent) {
        if self.tx.send((self.channel, event)).is_err() {
            tracing::error!(channel = %self.channel, "failed to send event");
        }
    }
}

impl<H> ChannelServer<H> {
    fn get_channel(
        &mut self,
        id: ChannelId,
    ) -> Result<&mut ChannelState, Box<dyn std::error::Error + Send + Sync + 'static>> {
        self.channel_state.get_mut(&id).ok_or(Box::new(NoChannel))
    }
}

impl<H> TailnetServer for ChannelServer<H> {
    fn new_client(dev: Arc<Device>, addr: SocketAddr) -> Self {
        Self {
            channel_state: Default::default(),
            dev,
            remote: addr,
            accepted: None,
            _handler: PhantomSend(PhantomData),
        }
    }
}

/// An event that may be generated by a channel connected to a [`ChannelServer`].
#[derive(Debug, Clone)]
pub enum ChannelEvent {
    /// Data was received over the channel.
    Data(Vec<u8>),
    /// A resize event occurred.
    Resize {
        /// The new width of the tty.
        width: u16,
        /// The new height of the tty.
        height: u16,
    },
    /// A signal was sent over the channel.
    Signal(Sig),
    /// The channel was closed.
    Close,
    /// The channel received EOF.
    Eof,
}

impl<H> russh::server::Handler for ChannelServer<H>
where
    H: ChannelHandler + Send,
    H::Error: Send,
{
    type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

    #[tracing::instrument(skip_all, fields(user = %user, remote = ?self.remote))]
    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        // Enforce the control-pushed Tailscale SSH policy. Fail-closed: an unknown source, an
        // absent policy, a non-matching policy, or any lookup error all reject the connection.
        match self.dev.authorize_ssh(self.remote, user).await {
            Ok(crate::ssh::SshDecision::Accept(accept)) => {
                // SECURITY (tsr-0h2): a matched rule that DEMANDS session recording (non-empty
                // `recorders`) — or a `holdAndDelegate` decision — cannot be honored because this
                // fork has no recorder transport / delegate round-trip yet. Refuse the session
                // (fail-closed) rather than silently downgrade it to a plain accept. This mirrors
                // Go `tailssh`'s posture when `OnRecordingFailure.RejectSessionWithMessage` is set.
                // `Auth::reject()` (the SSH `none`-method rejection) carries no client-visible
                // message, so the policy's refusal message is surfaced in the warning log.
                if let Some(msg) = recording_refusal(&accept) {
                    tracing::warn!(
                        local_user = %accept.local_user,
                        recorders = ?accept.recorders,
                        message = %msg,
                        "ssh: session refused: policy requires session recording but recording is not available"
                    );
                    return Ok(Auth::reject());
                }
                tracing::debug!(
                    local_user = %accept.local_user,
                    "ssh: policy accepted connection"
                );
                // Stash the accepted identity so the per-channel handler runs as the
                // policy-mapped local user. This is the single fail-closed authorization point;
                // the handler never re-evaluates policy.
                self.accepted = Some(accept);
                Ok(Auth::Accept)
            }
            Ok(crate::ssh::SshDecision::Deny(reason)) => {
                tracing::warn!(?reason, "ssh: policy denied connection");
                Ok(Auth::reject())
            }
            Err(e) => {
                tracing::error!(error = %e, "ssh: authorization failed; rejecting");
                Ok(Auth::reject())
            }
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        tracing::debug!(channel = ?channel.id(), "new session");

        // Fail closed: a channel open must be preceded by a successful `auth_none` that stashed
        // the accepted identity. If it is somehow absent, refuse to open the channel rather than
        // run a handler with no authorized user.
        let Some(accept) = self.accepted.clone() else {
            tracing::error!(
                channel = ?channel.id(),
                "ssh: channel open with no accepted identity; refusing"
            );
            return Ok(false);
        };

        // Bound the number of concurrent channels (each opens a session/handler — e.g. a login
        // shell). Without this an authorized-but-hostile peer could open unbounded channels on one
        // connection and fork-bomb the host with session handlers. Past the cap, refuse new channels.
        if at_channel_cap(self.channel_state.len()) {
            tracing::warn!(
                channel = ?channel.id(),
                cap = MAX_CHANNELS_PER_CONN,
                "ssh: per-connection channel cap reached; refusing new channel"
            );
            return Ok(false);
        }

        let (tx, mut rx) = mpsc::unbounded_channel::<Request>();
        let mut joinset = JoinSet::new();

        let (channel_id, session_handle) = (channel.id(), session.handle());
        let dev = self.dev.clone();

        joinset.spawn(async move {
            let rt = tokio::runtime::Handle::current();

            let mut handler = match H::new(rt, channel_id, session_handle.clone(), dev, &accept) {
                Ok(handler) => handler,
                Err(e) => {
                    let e = e.into();
                    tracing::error!(error = %e, %channel_id, "spawning channel handler");

                    if session_handle.close(channel_id).await.is_err() {
                        tracing::error!("failed closing channel after handler init error");
                    };

                    return;
                }
            };

            while let Some((_channel, evt)) = rx.recv().await {
                let result = handler.handle_event(&evt).await;

                if let Err(e) = result {
                    let e = e.into();
                    tracing::error!(error = %e, %channel_id, ?evt, "handling event");

                    if session_handle.close(channel_id).await.is_err() {
                        tracing::error!("failed closing channel after event handler error");
                    };

                    break;
                }
            }

            tracing::debug!(?channel_id, "closed");
        });

        self.channel_state.insert(
            channel.id(),
            ChannelState {
                channel: channel.id(),
                tx,
                _joinset: joinset,
            },
        );

        session.channel_success(channel.id())?;

        Ok(true)
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        tracing::trace!(?channel, "session closed");

        self.get_channel(channel)?.send(ChannelEvent::Close);
        self.channel_state.remove(&channel);

        session.channel_success(channel)?;

        Ok(())
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.get_channel(channel)?
            .send(ChannelEvent::Signal(signal));
        session.channel_success(channel)?;

        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.get_channel(channel)?
            .send(ChannelEvent::Data(data.into()));

        session.channel_success(channel)?;

        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.get_channel(channel)?.send(ChannelEvent::Eof);
        session.channel_success(channel)?;

        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _: u32,
        _: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.get_channel(channel)?.send(ChannelEvent::Resize {
            width: col_width as _,
            height: row_height as _,
        });

        session.channel_success(channel)?;

        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _: &str,
        col_width: u32,
        row_height: u32,
        _: u32,
        _: u32,
        _: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.get_channel(channel)?.send(ChannelEvent::Resize {
            width: col_width as _,
            height: row_height as _,
        });

        session.channel_success(channel)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_RECORDING_REFUSAL, MAX_CHANNELS_PER_CONN, at_channel_cap, recording_refusal,
    };
    use crate::ssh::SshAccept;

    /// The per-connection channel cap (fork-bomb guard) refuses at and beyond `MAX_CHANNELS_PER_CONN`
    /// and allows below it. Pins the exact boundary: a `>=`→`>` flip would let `MAX_CHANNELS_PER_CONN`
    /// open channels become `MAX_CHANNELS_PER_CONN + 1`, failing the `== cap` assertion below.
    #[test]
    fn channel_cap_boundary_is_inclusive() {
        // Below the cap: still allowed.
        assert!(!at_channel_cap(MAX_CHANNELS_PER_CONN - 1));
        assert!(!at_channel_cap(15));
        // At the cap: refuse the next open (the channel that would make it 17).
        assert!(at_channel_cap(MAX_CHANNELS_PER_CONN));
        assert!(at_channel_cap(16));
        // Above the cap (defensive): still refused.
        assert!(at_channel_cap(17));
        // The const itself is the documented value.
        assert_eq!(MAX_CHANNELS_PER_CONN, 16);
    }

    fn accept(recording_required: bool, refusal_message: &str) -> SshAccept {
        SshAccept {
            local_user: "root".to_string(),
            accept_env: Vec::new(),
            session_duration_nanos: None,
            allow_agent_forwarding: false,
            allow_local_port_forwarding: false,
            allow_remote_port_forwarding: false,
            recorders: Vec::new(),
            recording_required,
            recording_refusal_message: refusal_message.to_string(),
        }
    }

    /// tsr-0h2: an accept that demands recording must be REFUSED (the bypass is closed). With a
    /// policy-supplied message, that exact message is used; without one, the default is logged.
    #[test]
    fn recording_required_accept_is_refused() {
        // Policy-supplied refusal message wins.
        assert_eq!(
            recording_refusal(&accept(true, "recording required by policy")),
            Some("recording required by policy".to_string()),
        );
        // No message → default refusal text, but still a refusal (Some).
        assert_eq!(
            recording_refusal(&accept(true, "")),
            Some(DEFAULT_RECORDING_REFUSAL.to_string()),
        );
    }

    /// Regression guard for the common path: a normal accept (no recording demanded) is NOT refused,
    /// so the gate is a no-op and the session proceeds.
    #[test]
    fn normal_accept_is_not_refused() {
        assert_eq!(recording_refusal(&accept(false, "")), None);
        // Even a stray non-empty message never forces a refusal when recording isn't required.
        assert_eq!(recording_refusal(&accept(false, "ignored")), None);
    }
}
