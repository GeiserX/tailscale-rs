use alloc::{collections::BTreeMap, sync::Arc};

use futures_util::{Stream, StreamExt};
use tokio::{
    sync::{broadcast, mpsc},
    task::JoinSet,
};
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use url::Url;

use crate::{
    ControlDialer, Error,
    map_request_builder::MapRequestBuilder,
    tokio::{
        map_stream::{StateUpdate, map_stream, send_map_request},
        ping::handle_ping,
    },
};

/// A client to communicate with control.
#[derive(Debug)]
pub struct AsyncControlClient {
    base_url: Url,
    state_tx: broadcast::Sender<Arc<StateUpdate>>,
    command_tx: mpsc::Sender<Command>,
    _tasks: JoinSet<()>,
}

impl AsyncControlClient {
    /// Check whether it is possible to login with the given config, node keys, and auth
    /// key.
    pub async fn check_auth(
        config: &crate::Config,
        node_keys: &ts_keys::NodeState,
        auth_key: Option<&str>,
    ) -> Result<(), Error> {
        let control_url = &config.server_url;

        let h2_client = crate::tokio::connect(
            control_url,
            &node_keys.machine_keys,
            config.allow_http_key_fetch,
        )
        .await?;

        crate::tokio::register(config, control_url, auth_key, node_keys, &h2_client).await?;

        Ok(())
    }

    /// Connects to the control plane, registers this Tailscale node, and starts handling the
    /// message stream from control.
    ///
    /// The second element of the return value is a netmap stream which started listening
    /// _before_ the client connected, i.e. it will not miss any updates from control.
    #[tracing::instrument(skip_all, fields(control_url = %config.server_url))]
    pub async fn connect(
        config: &crate::Config,
        node_keys: &ts_keys::NodeState,
        auth_key: Option<&str>,
    ) -> Result<
        (
            Self,
            impl Stream<Item = Arc<StateUpdate>> + Send + Sync + use<>,
        ),
        Error,
    > {
        let control_url = &config.server_url;
        let mut tasks = JoinSet::new();

        let h2_client = crate::tokio::connect(
            control_url,
            &node_keys.machine_keys,
            config.allow_http_key_fetch,
        )
        .await?;
        tracing::info!("connected to control, registering");

        crate::tokio::register(config, control_url, auth_key, node_keys, &h2_client).await?;

        tracing::info!("registered, starting netmap stream");

        let (state_tx, state_rx) = broadcast::channel(32);
        let (command_tx, command_rx) = mpsc::channel(32);

        tasks.spawn({
            let state_tx = state_tx.clone();
            let control_url = control_url.clone();
            let node_keys = node_keys.clone();
            let auth_key = auth_key.map(ToOwned::to_owned);
            let config = config.clone();

            async move {
                run(
                    state_tx,
                    command_rx,
                    control_url.clone(),
                    node_keys.clone(),
                    auth_key,
                    config,
                )
                .await
            }
        });

        Ok((
            Self {
                base_url: control_url.clone(),
                state_tx,
                command_tx,
                _tasks: tasks,
            },
            netmap_stream(state_rx),
        ))
    }

    /// Set the DERP home region for this node.
    #[tracing::instrument(skip_all, fields(map_url = %self.map_url(), %region_id), level = "trace")]
    pub async fn set_home_region<'c>(
        &mut self,
        region_id: ts_derp::RegionId,
        latencies: impl IntoIterator<Item = (&'c str, f64)>,
    ) {
        tracing::trace!(region = %region_id, "reporting home derp to control server");

        if let Err(e) = self
            .command_tx
            .send(Command::SetDerpHomeRegion {
                id: region_id,
                latencies: latencies
                    .into_iter()
                    .map(|(name, sample)| (name.to_owned(), sample))
                    .collect(),
            })
            .await
        {
            tracing::error!(error = %e, "setting home derp region");
        }
    }

    /// Advertise this node's magicsock UDP endpoints (ip:port candidates) to the control server
    /// so peers can learn where to attempt direct connections.
    #[tracing::instrument(skip_all, fields(map_url = %self.map_url(), n_endpoints), level = "trace")]
    pub async fn set_endpoints(&mut self, endpoints: Vec<ts_control_serde::Endpoint>) {
        tracing::Span::current().record("n_endpoints", endpoints.len());
        tracing::trace!("reporting magicsock endpoints to control server");

        if let Err(e) = self
            .command_tx
            .send(Command::SetEndpoints { endpoints })
            .await
        {
            tracing::error!(error = %e, "setting endpoints");
        }
    }

    /// Construct the URL that should be used to fetch the netmap.
    pub fn map_url(&self) -> Url {
        self.base_url
            .join("machine/map")
            .expect("map_url was parsed without issue before")
    }

    /// Get a stream of all netmap updates.
    pub fn netmap_stream(&self) -> impl Stream<Item = Arc<StateUpdate>> + Send + Sync + use<> {
        netmap_stream(self.state_tx.subscribe())
    }
}

#[derive(Debug)]
pub enum Command {
    SetDerpHomeRegion {
        id: ts_derp::RegionId,
        latencies: BTreeMap<String, f64>,
    },
    SetEndpoints {
        endpoints: Vec<ts_control_serde::Endpoint>,
    },
}

/// Identifies a map-poll session so a reconnect can resume the delta stream instead of
/// cold-restarting. Control assigns the `handle` in the first [`MapResponse`] of a session and
/// stamps each response with a monotonically increasing `seq`; on reconnect we offer the last
/// `(handle, seq)` we processed and control either resumes after `seq` or ignores it and starts a
/// fresh session with a full netmap (both are safe — see [`MapRequestBuilder::map_session`]).
#[derive(Clone, Default)]
struct MapSession {
    handle: String,
    seq: i64,
}

/// Upper bound on the control-supplied session handle we will store/echo. The handle is an opaque
/// token; anything beyond this is rejected to avoid unbounded memory growth and log injection.
const MAX_SESSION_HANDLE_LEN: usize = 256;

/// Advance the resume cursor from a freshly received [`StateUpdate`]. The handle is assigned once
/// (first response of a session); `seq` advances on substantive responses and is 0 on keep-alives.
///
/// If control issues a *new* handle (a fresh session), `seq` is reset to 0 so we never carry a
/// stale cursor from the prior session into the new one. A control-supplied handle that is empty,
/// over [`MAX_SESSION_HANDLE_LEN`], or contains non-`ascii_graphic` bytes is rejected (the cursor
/// is left unchanged) to bound memory and prevent log injection.
fn advance_session(session: &mut MapSession, update: &StateUpdate) {
    if let Some(handle) = &update.session_handle {
        let valid = !handle.is_empty()
            && handle.len() <= MAX_SESSION_HANDLE_LEN
            && handle.bytes().all(|b| b.is_ascii_graphic());
        if valid && *handle != session.handle {
            session.handle = handle.clone();
            session.seq = 0;
        } else if !valid {
            tracing::warn!(
                handle_len = handle.len(),
                "control sent an invalid map-session handle; ignoring it"
            );
        }
    }
    if update.seq != 0 {
        session.seq = update.seq;
    }
}

pub async fn run(
    state_tx: broadcast::Sender<Arc<StateUpdate>>,
    mut command_rx: mpsc::Receiver<Command>,
    control_url: Url,
    node_keys: ts_keys::NodeState,
    auth_key: Option<String>,
    config: crate::Config,
) {
    let mut dialer = ControlDialer::default();
    let mut session = MapSession::default();

    loop {
        match run_once(
            &state_tx,
            &mut command_rx,
            &control_url,
            &node_keys,
            auth_key.as_deref(),
            &config,
            &mut dialer,
            &mut session,
        )
        .await
        {
            Ok(()) => {
                tracing::warn!(
                    resume_handle = %session.handle,
                    resume_seq = session.seq,
                    "netmap stream ended without error, attempting restart"
                );
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    resume_handle = %session.handle,
                    resume_seq = session.seq,
                    "netmap stream failed, attempting restart"
                );
                tokio::time::sleep(core::time::Duration::from_millis(500)).await;
            }
        }
    }
}

async fn run_once(
    state_tx: &broadcast::Sender<Arc<StateUpdate>>,
    command_rx: &mut mpsc::Receiver<Command>,
    control_url: &Url,
    node_keys: &ts_keys::NodeState,
    auth_key: Option<&str>,
    config: &crate::Config,
    control_dialer: &mut ControlDialer,
    session: &mut MapSession,
) -> Result<(), Error> {
    let h2_client = control_dialer
        .full_connect_next(
            control_url,
            &node_keys.machine_keys,
            config.allow_http_key_fetch,
        )
        .await?;

    crate::tokio::register(config, control_url, auth_key, node_keys, &h2_client).await?;

    let client_name = config.format_client_name();
    // Advertise-side VIP services: hash the validated hosted-service set into
    // `HostInfo.ServicesHash`. Empty config -> empty hash -> wire field omitted (unchanged behavior).
    let advertised_vip_services = config.advertised_vip_services();
    let services_hash = crate::services_hash(&advertised_vip_services);
    let builder = MapRequestBuilder::new(node_keys)
        .keep_alive(true)
        .omit_peers(false)
        .stream(true)
        .routable_ips(config.advertised_routes())
        .client_info(&client_name, crate::PKG_VERSION)
        .request_tags(config.tags.iter().map(String::as_str))
        .services(config.advertised_services())
        .services_hash(&services_hash)
        .wire_ingress(config.wire_ingress)
        .ingress_enabled(
            config
                .ingress_active
                .load(core::sync::atomic::Ordering::Relaxed),
        )
        .map_session(&session.handle, session.seq);

    let request = if let Some(hostname) = &config.hostname {
        builder.hostname(hostname)
    } else {
        builder
    }
    .build();

    let map_url = control_url.join("machine/map").unwrap();

    let reader = send_map_request(request, &map_url, &h2_client).await?;

    let mut stream = core::pin::pin!(map_stream(reader));
    tracing::info!("netmap stream started");

    loop {
        tokio::select! {
            state_update = stream.next() => {
                let Some(state_update) = state_update else {
                    break;
                };

                // Track the session cursor so a reconnect can resume after the last processed
                // message instead of cold-restarting.
                advance_session(session, &state_update);

                let _ = handle_ping(&state_update, control_url, &h2_client, config).await;

                if let Some(dial_plan) = &state_update.dial_plan
                    && control_dialer.update_dial_plan(dial_plan)
                {
                    tracing::trace!(new_dial_plan = ?dial_plan);
                }

                // This errors only if there are no receivers. That's not semantically an error for
                // us, so just ignore it.
                let _ignore = state_tx.send(Arc::new(state_update));
            }

            command = command_rx.recv() => {
                match command.unwrap() {
                    Command::SetDerpHomeRegion { id, latencies } => {
                        let mut builder = MapRequestBuilder::new(node_keys)
                            .keep_alive(false)
                            .omit_peers(true)
                            .stream(false)
                            .routable_ips(config.advertised_routes())
                            .preferred_derp(id)
                            .derp_latencies(latencies.iter().map(|(k, v)| (k.as_str(), *v)));

                        if let Some(hostname) = &config.hostname {
                            builder = builder.hostname(hostname);
                        }
                        let req = builder.build();

                        drop(send_map_request(req, &map_url, &h2_client).await?);
                    },
                    Command::SetEndpoints { endpoints } => {
                        let mut builder = MapRequestBuilder::new(node_keys)
                            .keep_alive(false)
                            .omit_peers(true)
                            .stream(false)
                            .routable_ips(config.advertised_routes())
                            .endpoints(endpoints);

                        if let Some(hostname) = &config.hostname {
                            builder = builder.hostname(hostname);
                        }
                        let req = builder.build();

                        drop(send_map_request(req, &map_url, &h2_client).await?);
                    },
                }
            }
        }
    }

    Ok(())
}

fn netmap_stream(
    rx: broadcast::Receiver<Arc<StateUpdate>>,
) -> impl Stream<Item = Arc<StateUpdate>> + Send + Sync {
    tokio_stream::wrappers::BroadcastStream::new(rx).filter_map(async |x| {
        if let Err(BroadcastStreamRecvError::Lagged(n)) = &x {
            tracing::warn!(messages_missed = n, "map_stream lagged");
        }

        x.ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn update(handle: Option<&str>, seq: i64) -> StateUpdate {
        StateUpdate {
            session_handle: handle.map(ToOwned::to_owned),
            seq,
            derp: None,
            node: None,
            peer_update: None,
            user_profiles: Vec::new(),
            ping: None,
            packetfilter: None,
            pop_browser_url: None,
            dial_plan: None,
            dns_config: None,
            ssh_policy: None,
            tka: None,
            online_change: Default::default(),
            peer_seen_change: Default::default(),
        }
    }

    #[test]
    fn advance_session_captures_handle_and_seq() {
        let mut session = MapSession::default();

        advance_session(&mut session, &update(Some("sess-1"), 5));

        assert_eq!(session.handle, "sess-1");
        assert_eq!(session.seq, 5);
    }

    #[test]
    fn advance_session_keepalive_preserves_cursor() {
        let mut session = MapSession {
            handle: "sess-1".to_owned(),
            seq: 7,
        };

        // Keep-alive: no handle, seq == 0. The cursor must not regress.
        advance_session(&mut session, &update(None, 0));

        assert_eq!(session.handle, "sess-1");
        assert_eq!(session.seq, 7);
    }

    #[test]
    fn advance_session_resets_seq_on_new_handle() {
        let mut session = MapSession {
            handle: "sess-1".to_owned(),
            seq: 42,
        };

        // Control started a fresh session: a new handle must reset seq so we never carry a stale
        // cursor from the prior session.
        advance_session(&mut session, &update(Some("sess-2"), 0));

        assert_eq!(session.handle, "sess-2");
        assert_eq!(session.seq, 0);
    }

    #[test]
    fn advance_session_same_handle_keeps_seq() {
        let mut session = MapSession {
            handle: "sess-1".to_owned(),
            seq: 10,
        };

        // Re-issuing the same handle (not a new session) must not reset the cursor.
        advance_session(&mut session, &update(Some("sess-1"), 0));

        assert_eq!(session.handle, "sess-1");
        assert_eq!(session.seq, 10);
    }

    #[test]
    fn advance_session_rejects_overlong_handle() {
        let mut session = MapSession::default();
        let huge = "a".repeat(MAX_SESSION_HANDLE_LEN + 1);

        advance_session(&mut session, &update(Some(&huge), 3));

        // The handle is rejected (cursor handle stays empty); seq still advances.
        assert_eq!(session.handle, "");
        assert_eq!(session.seq, 3);
    }

    #[test]
    fn advance_session_rejects_non_graphic_handle() {
        let mut session = MapSession::default();

        // A handle with control/whitespace bytes (log-injection risk) is rejected.
        advance_session(&mut session, &update(Some("bad\nhandle"), 1));

        assert_eq!(session.handle, "");
        assert_eq!(session.seq, 1);
    }
}
