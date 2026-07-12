//! Run a TCP echo server on the tailnet, built with the Go-idiomatic [`tsnet::Server`] facade.
//!
//! This is the [`tcp_echo`](../tcp_echo) example rewritten against the `tsnet` facade instead of the
//! native [`Config`](tailscale::Config) + [`Device`](tailscale::Device) surface. Rather than
//! *constructing* a device from a config, you **set the Go-`tsnet.Server`-parity fields** on a
//! [`Server`] and let the wrapped device start **lazily on the first method call** (Go's "fields may
//! be changed until the first method call") — the exact shape a Go `tsnet` user expects:
//!
//! ```go
//! srv := &tsnet.Server{Hostname: "tsnet_echo_example", AuthKey: key, Dir: "tsnet_echo_state"}
//! defer srv.Close()
//! ln, _ := srv.Listen("tcp", ":1234")   // Start() happens lazily here
//! ```
//!
//! Requires the `tsnet` cargo feature:
//!
//! ```sh
//! TS_RS_EXPERIMENT=this_is_unstable_software \
//!   cargo run --features tsnet --example tsnet_echo -- --auth-key $TS_AUTH_KEY
//! ```
//!
//! To see the server working, connect to it with netcat (`nc`):
//!
//!     $ nc $TAILNET_IPV4 $LISTEN_PORT
//!
//! Type a message and hit enter; the server should echo the message back to you.
//!
//! [`tsnet::Server`]: tailscale::tsnet::Server
//! [`Server`]: tailscale::tsnet::Server

use std::{error::Error, net::SocketAddr, path::PathBuf, time::Duration};

use clap::Parser;
use tailscale::tsnet::Server;
use tokio::task::spawn;
use tracing_subscriber::filter::LevelFilter;

/// Run a TCP echo server on the tailnet, built with the `tsnet::Server` facade.
///
/// To see the server working, try connecting to it with netcat (`nc`):
///
///     $ nc $TAILNET_IPV4 $LISTEN_PORT
///
/// Type a message and hit enter; the server should echo the message back to you.
#[derive(clap::Parser)]
#[command(version, about)]
struct Args {
    /// Directory to persist this node's identity in (Go `tsnet.Server.Dir`).
    ///
    /// Created if it doesn't exist. Reusing the same directory across runs keeps a stable node
    /// identity instead of re-registering every boot. Omit `--dir` (pass an empty value) for an
    /// ephemeral in-memory identity (fresh every run).
    #[arg(short = 'd', long, default_value = "tsnet_echo_state")]
    dir: PathBuf,

    /// The auth key to register with (Go `tsnet.Server.AuthKey`).
    ///
    /// Can be omitted if the state directory already holds an authenticated identity. Falls back to
    /// the `TS_AUTH_KEY` environment variable.
    #[arg(short = 'k', long, env = "TS_AUTH_KEY")]
    auth_key: Option<String>,

    /// The hostname this node will request (Go `tsnet.Server.Hostname`).
    #[arg(short = 'H', long, default_value = "tsnet_echo_example")]
    hostname: Option<String>,

    /// The URL of the control server to connect to (Go `tsnet.Server.ControlURL`).
    ///
    /// Uses the default control server if unspecified.
    #[arg(long, env = "TS_CONTROL_URL")]
    control_url: Option<url::Url>,

    /// Port to listen on (on the tailnet).
    #[clap(short, long, default_value_t = 1234)]
    listen_port: u16,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let args = Args::parse();

    // `--listen-port 0` would bind an OS-chosen ephemeral port, but this example logs and tells the
    // user to `nc` the *requested* port below — `:0` is not a connectable address. Reject it with a
    // clear error rather than print an address nobody can reach.
    if args.listen_port == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "--listen-port must be between 1 and 65535",
        )
        .into());
    }

    // Set the Go-`tsnet.Server`-parity fields, exactly where Go writes struct fields. The wrapped
    // `Device` is *not* built yet — it is constructed and started lazily on the first method call
    // below, so every field may still be changed until then.
    let mut srv = Server::new();
    srv.hostname = args.hostname;
    srv.auth_key = args.auth_key;
    srv.control_url = args.control_url.map(|u| u.to_string());
    // An empty `--dir` selects an ephemeral in-memory identity (Go: neither `Dir` nor `Store` set).
    if !args.dir.as_os_str().is_empty() {
        srv.dir = Some(args.dir);
    }

    // `up` is Go's `Up`: it triggers the lazy `Start` (build config → `Device::new`) and then waits
    // until the node reaches `Running`, so its tailnet address is assigned by the time we log it.
    // `None` would wait forever; bound it so a misconfigured run fails with a typed error instead.
    srv.up(Some(Duration::from_secs(60))).await?;

    // `tailscale_ips` is Go's `TailscaleIPs`. We only need the v4 address to tell the user where to
    // point `nc`; the v6 address is `None` on an IPv4-only tailnet.
    let (ipv4, _ipv6) = srv.tailscale_ips().await?;

    // `listen("tcp", ":<port>")` is Go's `Listen`: the bare `":<port>"` binds the tailnet wildcard,
    // and the facade hands back the engine's own `netstack::TcpListener` — so the accept/echo loop
    // below is byte-for-byte identical to the native `tcp_echo` example.
    let listener = srv.listen("tcp", &format!(":{}", args.listen_port)).await?;

    let listening_addr = SocketAddr::from((ipv4, args.listen_port));
    tracing::info!(%listening_addr, "listening on the tailnet (press Ctrl-C to shut down)");

    // Accept connections until Ctrl-C, echoing each one back to its sender.
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Ctrl-C received; shutting down");
                break;
            }
            accepted = listener.accept() => {
                let conn = accepted?;

                spawn(async move {
                    let remote_ep = conn.remote_addr();
                    tracing::info!(%remote_ep, "accepted connection");

                    let (mut reader, mut writer) = tokio::io::split(conn);
                    if let Err(e) = tokio::io::copy(&mut reader, &mut writer).await {
                        tracing::error!(%remote_ep, error = %e);
                    } else {
                        tracing::info!(%remote_ep, "remote hung up");
                    }
                });
            }
        }
    }

    // `close` is Go's `Close`: stop the node, waiting up to the timeout for a graceful shutdown, and
    // report whether it completed in time. It *consumes* the server — Rust turns Go's "don't use the
    // server after Close" convention into a compile-time move — so the listener (whose backing
    // netstack is torn down with the device) is dropped first.
    drop(listener);
    let closed_cleanly = srv.close(Some(Duration::from_secs(5))).await;
    tracing::info!(closed_cleanly, "server closed");

    Ok(())
}
