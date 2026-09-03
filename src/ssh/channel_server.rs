use std::{collections::HashMap, marker::PhantomData, net::SocketAddr, sync::Arc};

use russh::{
    Channel, ChannelId, ChannelOpenFailure, Pty, Sig,
    server::{Auth, ChannelOpenHandle, Handle, Msg, Session},
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

/// Everything a per-channel handler is told about the connection that opened it.
///
/// Built once per connection by the fail-closed authorization in
/// [`auth_none`][russh::server::Handler::auth_none] and handed to every channel opened on it.
#[derive(Debug, Clone)]
pub struct ChannelContext {
    /// The authorization decision. Its [`local_user`][SshAccept::local_user] is the policy-mapped
    /// identity the session must run as, and its `recorders` / `on_recording_failure` are the
    /// session-recording obligation the handler has to honor.
    pub accept: SshAccept,
    /// The username the client presented (Go's `sshUser`, before the policy's user mapping).
    pub ssh_user: String,
    /// The tailnet address the connection came from.
    pub remote: SocketAddr,
    /// The connecting tailnet peer, when the source address resolved to one.
    pub src_node: Option<crate::NodeInfo>,
    /// Identifier shared by every session multiplexed on this connection, recorded in a session
    /// recording's cast header so the recordings of one connection can be grouped.
    pub conn_id: String,
}

/// Handler for a channel session.
pub trait ChannelHandler: Sized {
    /// Error this handler produces.
    type Error: Into<std::io::Error> + std::error::Error;

    /// Whether this handler streams its session to the policy's `recorders`.
    ///
    /// **This is a fail-closed gate, not a hint.** A policy rule with a non-empty `recorders` list
    /// obliges the server to record the session; a handler that leaves this `false` is refused
    /// such a connection outright rather than silently running it un-recorded. Only set it to
    /// `true` in a handler that actually calls
    /// [`SessionRecording`][crate::ssh::recording::SessionRecording].
    const RECORDS_SESSION: bool = false;

    /// Construct a new per-channel handler.
    ///
    /// `ctx` carries the single fail-closed authorization decision made in
    /// [`auth_none`][russh::server::Handler::auth_none]. Handlers MUST NOT re-evaluate policy or
    /// substitute a different user — the accepted identity is the sole authorization source.
    ///
    /// This is `async` because a handler may have to reach the network before the session may
    /// start: a recorded session dials its recorder here, and a session that must be recorded but
    /// cannot be is refused by returning `Err` — so the shell is never spawned first and recorded
    /// second.
    fn new(
        handle: tokio::runtime::Handle,
        channel_id: ChannelId,
        session: Handle,
        dev: Arc<Device>,
        ctx: &ChannelContext,
    ) -> impl Future<Output = Result<Self, Self::Error>> + Send;

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
/// rules, principal matching, and SSH-user mapping are honored.
///
/// A rule that **demands** session recording (non-empty `recorders`) is honored by handlers that
/// declare [`ChannelHandler::RECORDS_SESSION`] — [`ShellHandler`][crate::ssh::ShellHandler] streams
/// the session to the recorders and applies `onRecordingFailure`. For any other handler, and for a
/// rule carrying `holdAndDelegate` (no delegate round-trip exists), the connection is refused
/// **fail-closed** rather than silently run without the capability the policy demanded (see
/// [`auth_none`]).
///
/// [`auth_none`]: russh::server::Handler::auth_none
pub struct ChannelServer<H> {
    channel_state: HashMap<ChannelId, ChannelState>,
    remote: SocketAddr,
    dev: Arc<Device>,
    /// The authorization decision and connection facts from the single
    /// [`auth_none`][russh::server::Handler::auth_none] decision, stashed so per-channel handlers
    /// run as the policy-mapped user. `None` until a successful `auth_none`; a channel open with
    /// `None` here fails closed.
    accepted: Option<ChannelContext>,
    /// Identifier for this connection, shared by every session multiplexed on it.
    conn_id: String,
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

/// Fallback message logged when a session is refused for an action the server cannot honor and the
/// policy supplied no message of its own.
const DEFAULT_UNSUPPORTED_REFUSAL: &str =
    "policy requires a capability this SSH server cannot provide";

/// The fail-closed gate for policy actions this server cannot honor, extracted as a pure predicate
/// so it can be unit-tested without a live russh [`Session`]/[`Device`] (mirrors
/// [`at_channel_cap`]).
///
/// Returns `Some(message)` when the accepted session must be **refused**, which is either:
///
/// * the rule carries a `holdAndDelegate` URL — there is no delegate round-trip, so the decision
///   the policy wanted deferred to control can never be made; or
/// * the rule demands session recording and `handler_records` is `false`, i.e. the configured
///   [`ChannelHandler`] does not stream its session anywhere. Running it would be exactly the
///   silent un-recorded session the policy forbade.
///
/// A rule that demands recording with a recording-capable handler returns `None`: the session is
/// admitted here and the recorder is dialed by the handler, which then applies Go's
/// `onRecordingFailure` semantics (fail-open unless `rejectSessionWithMessage` is set).
///
/// The message is the policy's
/// [`recording_refusal_message`][crate::ssh::SshAccept::recording_refusal_message] when non-empty,
/// else [`DEFAULT_UNSUPPORTED_REFUSAL`].
fn unsupported_action_refusal(accept: &SshAccept, handler_records: bool) -> Option<String> {
    let unsupported =
        !accept.hold_and_delegate.is_empty() || (!accept.recorders.is_empty() && !handler_records);
    if !unsupported {
        return None;
    }
    if accept.recording_refusal_message.is_empty() {
        Some(DEFAULT_UNSUPPORTED_REFUSAL.to_string())
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
            conn_id: crate::ssh::new_conn_id(crate::ssh::now_unix_secs()),
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
                // SECURITY: a matched rule may demand a capability the configured handler cannot
                // provide — a `holdAndDelegate` decision (no delegate round-trip exists), or
                // session recording with a handler that does not record. Refuse the session
                // (fail-closed) rather than silently downgrade it to a plain accept.
                // `Auth::reject()` (the SSH `none`-method rejection) carries no client-visible
                // message, so the policy's refusal message is surfaced in the warning log.
                if let Some(msg) = unsupported_action_refusal(&accept, H::RECORDS_SESSION) {
                    tracing::warn!(
                        local_user = %accept.local_user,
                        recorders = ?accept.recorders,
                        message = %msg,
                        "ssh: session refused: policy requires a capability this server cannot provide"
                    );
                    return Ok(Auth::reject());
                }
                tracing::debug!(
                    local_user = %accept.local_user,
                    recorders = ?accept.recorders,
                    "ssh: policy accepted connection"
                );
                // The connecting peer, for the session recording's cast header. `authorize_ssh`
                // already proved the source resolves to a known peer, so this is a re-read of the
                // same peer table, never a second authorization decision.
                let src_node = self
                    .dev
                    .peer_by_tailnet_ip(self.remote.ip())
                    .await
                    .unwrap_or_else(|e| {
                        tracing::debug!(error = %e, "ssh: re-reading the connecting peer");
                        None
                    });
                // Stash the accepted identity so the per-channel handler runs as the
                // policy-mapped local user. This is the single fail-closed authorization point;
                // the handler never re-evaluates policy.
                self.accepted = Some(ChannelContext {
                    accept,
                    ssh_user: user.to_string(),
                    remote: self.remote,
                    src_node,
                    conn_id: self.conn_id.clone(),
                });
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
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        tracing::debug!(channel = ?channel.id(), "new session");

        // Fail closed: a channel open must be preceded by a successful `auth_none` that stashed
        // the accepted identity. If it is somehow absent, refuse to open the channel rather than
        // run a handler with no authorized user.
        let Some(ctx) = self.accepted.clone() else {
            tracing::error!(
                channel = ?channel.id(),
                "ssh: channel open with no accepted identity; refusing"
            );
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
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
            reply.reject(ChannelOpenFailure::ResourceShortage).await;
            return Ok(());
        }

        let (tx, mut rx) = mpsc::unbounded_channel::<Request>();
        let mut joinset = JoinSet::new();

        let (channel_id, session_handle) = (channel.id(), session.handle());
        let dev = self.dev.clone();

        joinset.spawn(async move {
            let rt = tokio::runtime::Handle::current();

            let mut handler = match H::new(rt, channel_id, session_handle.clone(), dev, &ctx).await
            {
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

        // `accept()` is what confirms the channel. No `channel_success` here: until the accept is
        // processed the channel is still inside the pending open (held by `reply`), never in the
        // session's channel map, so a pre-accept `channel_success` is a silent no-op — and would
        // hit its `assert!(channel.confirmed)` if russh ever registered the channel earlier.
        reply.accept().await;

        Ok(())
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
        DEFAULT_UNSUPPORTED_REFUSAL, MAX_CHANNELS_PER_CONN, at_channel_cap,
        unsupported_action_refusal,
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

    /// An accept carrying `recorders`, a `holdAndDelegate` URL, and a refusal message — the three
    /// inputs the gate reads.
    fn accept(recorders: &[&str], hold_and_delegate: &str, refusal_message: &str) -> SshAccept {
        SshAccept {
            local_user: "root".to_string(),
            accept_env: Vec::new(),
            session_duration_nanos: None,
            allow_agent_forwarding: false,
            allow_local_port_forwarding: false,
            allow_remote_port_forwarding: false,
            recorders: recorders.iter().map(|r| r.parse().unwrap()).collect(),
            on_recording_failure: None,
            hold_and_delegate: hold_and_delegate.to_string(),
            recording_refusal_message: refusal_message.to_string(),
        }
    }

    /// A rule demanding recording is admitted for a handler that records (the transport then
    /// applies `onRecordingFailure`), and REFUSED for one that does not — otherwise the session
    /// would run un-recorded, which is the bypass the policy forbids.
    #[test]
    fn recording_demand_is_gated_on_handler_support() {
        let a = accept(&["192.0.2.10:8080"], "", "recording required by policy");
        assert_eq!(
            unsupported_action_refusal(&a, true),
            None,
            "a recording-capable handler must be allowed to start and record the session"
        );
        assert_eq!(
            unsupported_action_refusal(&a, false),
            Some("recording required by policy".to_string()),
            "a handler that cannot record must not run a session the policy says to record"
        );
    }

    /// `holdAndDelegate` has no transport at all, so it is refused whatever the handler can do.
    #[test]
    fn hold_and_delegate_is_refused_for_every_handler() {
        let a = accept(&[], "https://control.example/ssh/action/xyz", "");
        for handler_records in [true, false] {
            assert_eq!(
                unsupported_action_refusal(&a, handler_records),
                Some(DEFAULT_UNSUPPORTED_REFUSAL.to_string()),
                "holdAndDelegate must be refused (handler_records={handler_records})"
            );
        }
    }

    /// Regression guard for the common path: a plain accept is NOT refused, so the gate is a no-op
    /// and the session proceeds.
    #[test]
    fn normal_accept_is_not_refused() {
        assert_eq!(
            unsupported_action_refusal(&accept(&[], "", ""), false),
            None
        );
        // Even a stray non-empty message never forces a refusal when nothing is demanded.
        assert_eq!(
            unsupported_action_refusal(&accept(&[], "", "ignored"), false),
            None
        );
    }
}
