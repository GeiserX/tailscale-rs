//! GL.iNet persistent Tailscale daemon for the GL-SFT1200.
//!
//! Unlike the `peer_ping` demo this is a real service node: **non-ephemeral** (it does not vanish
//! from the tailnet when the process stops), with a **persistent key/state file** (survives reboots
//! — no re-login once approved), using the kernel-WireGuard dataplane (build `--features kernel-wg`).
//! It takes no `--peer` and does not hold a console; it stays up and publishes a small **status JSON
//! file** that the ucode `/rpc` backend (`tailscale.uc`) reads, so the GL.iNet app can show the login
//! URL, the tailnet IP, and the connection state. Login flow: on first run it publishes
//! `{"state":"NeedsLogin","login_url":…}`; the app shows the URL; on approval it reaches
//! `{"state":"Running","ipv4":…}`.

use std::{error::Error, path::PathBuf, time::Duration};

use clap::Parser;
use tailscale::{Config, Device, DeviceState};
use tracing_subscriber::filter::LevelFilter;

#[derive(clap::Parser)]
#[command(version, about)]
struct Args {
    /// Persistent node key/state file (survives reboots -> reconnect without re-login).
    #[arg(short = 'c', long, default_value = "/etc/tailscale-rs/node.json")]
    key_file: PathBuf,

    /// The hostname this node requests.
    #[arg(short = 'H', long, default_value = "sft1200")]
    hostname: Option<String>,

    /// Optional auth key (interactive login is used if absent).
    #[arg(short = 'k', long, env = "TS_AUTH_KEY")]
    auth_key: Option<String>,

    /// Status JSON file the ucode backend (`tailscale.uc`) reads.
    #[arg(short = 's', long, default_value = "/var/run/tailscale-rs/status.json")]
    status_file: PathBuf,

    /// Control server URL (defaults to the Tailscale control plane).
    #[arg(long, env = "TS_CONTROL_URL")]
    control_url: Option<url::Url>,
}

/// Atomically publish the status JSON (write to a temp file + rename) so a concurrent reader in
/// `tailscale.uc` never sees a half-written file.
fn write_status(path: &PathBuf, value: &serde_json::Value) {
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, value.to_string()).is_ok()
        && let Err(e) = std::fs::rename(&tmp, path)
    {
        tracing::warn!(error = %e, path = %path.display(), "could not publish status file");
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    // This binary *is* the early-days experimental client — self-acknowledge the runtime gate so
    // the service init script does not have to carry the env var.
    // SAFETY: single-threaded at this point (before the tokio runtime spawns worker tasks).
    unsafe { std::env::set_var("TS_RS_EXPERIMENT", "this_is_unstable_software") };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let args = Args::parse();
    if let Some(d) = args.key_file.parent() {
        std::fs::create_dir_all(d).ok();
    }
    if let Some(d) = args.status_file.parent() {
        std::fs::create_dir_all(d).ok();
    }

    let mut config = Config::default_with_key_file(&args.key_file).await?;
    config.requested_hostname = args.hostname.clone();
    config.ephemeral = false; // PERSISTENT: do not auto-remove this node when the process stops.
    if let Some(url) = args.control_url {
        config.control_server_url = url;
        if config.control_server_url.scheme() == "http" {
            config.allow_http_key_fetch = true;
        }
    }

    // Supervise loop: (re)create the Device, watch it, and on a TERMINAL state
    // (`Failed`/`Expired`) tear it down and retry with backoff. The runtime treats a transient
    // boot-time network error ("control plane unreachable" — daemon started before the uplink/DNS
    // were ready) as terminal, so without this the daemon would sit in `Failed` forever. Retrying
    // the whole Device makes it self-heal once connectivity comes up, with no external nudge.
    loop {
        let dev = match Device::new(&config, args.auth_key.clone()).await {
            Ok(d) => d,
            Err(e) => {
                write_status(
                    &args.status_file,
                    &serde_json::json!({ "state": "Failed", "error": e.to_string() }),
                );
                tracing::warn!(error = %e, "Device::new failed; retrying after backoff");
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }
        };
        let mut state_rx = dev.watch_state();

        loop {
            let state = state_rx.borrow_and_update().clone();
            let status = match &state {
                DeviceState::Connecting => serde_json::json!({ "state": "Connecting" }),
                DeviceState::NeedsLogin(url) => {
                    serde_json::json!({ "state": "NeedsLogin", "login_url": url.to_string() })
                }
                DeviceState::NeedsMachineAuth => serde_json::json!({ "state": "NeedsMachineAuth" }),
                DeviceState::Reauthenticating => serde_json::json!({ "state": "Reauthenticating" }),
                DeviceState::Expired => serde_json::json!({ "state": "Expired" }),
                DeviceState::Failed(e) => {
                    serde_json::json!({ "state": "Failed", "error": e.to_string() })
                }
                DeviceState::Running => {
                    let (v4, v6) = dev
                        .tailscale_ips()
                        .await
                        .map(|(a, b)| (a.to_string(), b.map(|x| x.to_string())))
                        .unwrap_or_default();
                    serde_json::json!({
                        "state": "Running",
                        "ipv4": v4,
                        "ipv6": v6,
                        "hostname": config.requested_hostname,
                    })
                }
                // DeviceState is #[non_exhaustive]; surface any future variant rather than failing.
                _ => serde_json::json!({ "state": format!("{state:?}") }),
            };
            write_status(&args.status_file, &status);
            tracing::info!(?state, "tailscale status published");

            // Terminal state -> drop the Device and recreate it (after the backoff below).
            if matches!(state, DeviceState::Failed(_) | DeviceState::Expired) {
                break;
            }

            // Wake on a state change, or refresh periodically (IPs/peers can change while Running).
            tokio::select! {
                _ = state_rx.changed() => {}
                _ = tokio::time::sleep(Duration::from_secs(20)) => {}
            }
        }

        drop(dev);
        tracing::warn!("device reached a terminal state; recreating after backoff");
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}
