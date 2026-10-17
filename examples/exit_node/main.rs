//! Run this process as a userspace **exit node** for a tailnet.
//!
//! A minimal, purpose-built runner for experimenting with a residential exit node: it joins the
//! tailnet with a persisted identity, advertises `0.0.0.0/0` and `::/0` (official clients only offer
//! an exit node that advertises both), forwards every IPv4 TCP/UDP port through the userspace
//! netstack and egresses via this host's own sockets. IPv6 exit traffic is rejected at once, so
//! clients fall back to IPv4. It does not touch the host's routes, DNS or packet filter, and it does
//! not need root.
//!
//! The auth key is read from a file (never argv or logs) and is only needed for the first
//! registration; afterwards the identity in `--state-dir` is reused. Alternatively,
//! `--interactive` prints a login URL to approve in a browser.
//!
//! ```sh
//! TS_RS_EXPERIMENT=this_is_unstable_software \
//!   cargo run --release --example exit_node -- \
//!     --state-dir ./state/rust-exit --auth-key-file ~/.config/ts-exit/authkey
//! ```
//!
//! The advertised route still has to be approved in the admin console (or by an `autoApprovers`
//! policy) before peers can select this node.
//!
//! `--portmap-probe` runs a one-shot NAT-PMP/PCP check instead of the node, before any identity,
//! state or control connection exists: it maps a dedicated test port on the LAN gateway, each
//! protocol separately, optionally holds it open to count inbound datagrams, deletes it and exits
//! (0: every protocol mapped and deleted, 2: some, 1: none or no usable gateway). Its output may
//! contain the router's public address.
//!
//! ```sh
//! cargo run --release --example exit_node -- --portmap-probe --portmap-hold 60
//! ```

use std::{error::Error, path::PathBuf, time::Duration};

use clap::Parser;
use tailscale::{Config, Device, RegistrationError, config::BadFormatBehavior};
#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};
use tracing_subscriber::filter::LevelFilter;

#[derive(clap::Parser)]
#[command(version, about)]
struct Args {
    /// Directory holding this node's persisted identity (`keys.json`). Created if missing.
    #[arg(long, required_unless_present = "portmap_probe")]
    state_dir: Option<PathBuf>,

    /// File containing the auth key. Only read if the identity is not yet registered.
    #[arg(long)]
    auth_key_file: Option<PathBuf>,

    /// Register without an auth key: print control's login URL and wait (up to 1 h) for it to
    /// be approved in a browser, like `tailscale up` does. The node is owned by the approving
    /// user rather than tagged.
    #[arg(long, conflicts_with = "auth_key_file")]
    interactive: bool,

    /// Hostname to request.
    #[arg(long, default_value = "rust-exit")]
    hostname: String,

    /// Tags to request (must match the auth key's tags), e.g. `tag:rust-exit`.
    #[arg(long = "tag")]
    tags: Vec<String>,

    /// UDP port for WireGuard + disco. Defaults away from the official client's 41641.
    #[arg(long, default_value_t = 41642)]
    port: u16,

    /// Don't advertise the exit-node route; join the tailnet only (tunnel-only tests).
    #[arg(long)]
    no_advertise: bool,

    /// Resolver that answers exit-node users' DNS aimed at resolvers this node can't reach (their
    /// LAN/hotspot resolver). Defaults to the first `nameserver` in /etc/resolv.conf.
    #[arg(long)]
    exit_dns: Option<std::net::SocketAddr>,

    /// Don't answer such DNS at all (it is then refused like any private destination).
    #[arg(long, conflicts_with = "exit_dns")]
    no_exit_dns: bool,

    /// Tailnet port for the peerAPI, which serves exit-node DNS (DoH) to the node's users; 0 disables
    /// it. Go clients send all their DNS there when using this node as exit node.
    #[arg(long, default_value_t = 41643)]
    peerapi_port: u16,

    /// Per-direction userspace TCP buffer in bytes (netstack default: 256 KiB).
    #[arg(long)]
    tcp_buffer_size: Option<usize>,

    /// Serve a tunnel-only benchmark on this port of the node's tailnet address (0 = off). A client
    /// that sends `d` gets an endless stream of zeros; `u` has everything discarded; `e` is echoed.
    #[arg(long, default_value_t = 0)]
    sink_port: u16,

    /// Tokio worker threads. One per core (tokio's default) spends CPU on cross-thread wakeups;
    /// too few lets bulk flows starve the serial packet pipeline, whose bounded ingress queue then
    /// drops packets (1-3 s TCP stalls). Tunnel benchmark, 8 parallel flows: 4 workers had the
    /// lowest CPU per GB with no stalls; 2 stalled; 10 cost 40% more CPU.
    #[arg(long, default_value_t = 4)]
    worker_threads: usize,

    /// Seconds between status lines (peers, direct vs DERP path). 0 disables.
    #[arg(long, default_value_t = 30)]
    status_interval: u64,

    /// Run the one-shot NAT-PMP/PCP probe on a dedicated test port and exit. Needs no state
    /// directory, keys or control connection.
    #[arg(long)]
    portmap_probe: bool,

    /// Probe: which protocols to map, each separately.
    #[arg(long, value_enum, default_value_t = PortmapProto::Both, requires = "portmap_probe")]
    portmap_proto: PortmapProto,

    /// Probe: the test socket's UDP port (0 = ephemeral). Never `--port`, 41641 or 41642.
    #[arg(long, default_value_t = 0, requires = "portmap_probe")]
    portmap_test_port: u16,

    /// Probe: requested lease in seconds.
    #[arg(
        long,
        default_value_t = ts_portmapper::probe_tool::DEFAULT_LIFETIME,
        value_parser = clap::value_parser!(u32).range(1..=7200),
        requires = "portmap_probe"
    )]
    portmap_lifetime: u32,

    /// Probe: seconds to hold each mapping open, counting inbound datagrams (no payloads).
    #[arg(
        long,
        default_value_t = 0,
        value_parser = clap::value_parser!(u64).range(0..=600),
        requires = "portmap_probe"
    )]
    portmap_hold: u64,

    /// Probe: seconds to keep retrying the gateway lookup (once a second; routing-table reads
    /// only) when there is no usable default route yet, e.g. a launchd job at boot.
    #[arg(
        long,
        default_value_t = 0,
        value_parser = clap::value_parser!(u64).range(0..=120),
        requires = "portmap_probe"
    )]
    portmap_wait: u64,

    /// Use this gateway (`GW` or `GW,SELF`) instead of the default route's, for the node's port
    /// mapper and for the probe. It is validated like a discovered one (private, on-link).
    #[arg(long, value_name = "GW[,SELF]")]
    portmap_gateway: Option<ts_portmapper::gateway::GatewayOverride>,

    /// Turn the NAT port mapper (NAT-PMP/PCP) off. Equivalent to `TS_DISABLE_PORTMAPPER=1`.
    #[arg(long, conflicts_with = "portmap_probe")]
    no_portmapper: bool,

    /// Advertise a port-mapped address even when it is private or CGNAT (a double NAT), as Go
    /// does. By default this runner keeps and renews such a mapping but does not offer it to
    /// peers.
    #[arg(long, conflicts_with = "portmap_probe")]
    portmap_advertise_nonpublic: bool,

    /// Renew the port mapping only on activity, as Go does. By default this runner renews it when
    /// due even while idle, as long as it has peers, so an idle exit node stays directly
    /// reachable.
    #[arg(long, conflicts_with = "portmap_probe")]
    portmap_lazy_renew: bool,
}

impl Args {
    /// The node's port-mapper options: this runner's defaults are suppression of non-public
    /// external addresses and idle renewal with peers; the flags revert either to Go's behaviour.
    fn port_mapper_options(&self) -> tailscale::config::PortMapperOptions {
        tailscale::config::PortMapperOptions {
            gateway_override: self.portmap_gateway.map(|g| (g.gw, g.self_ip)),
            advertise_nonpublic_external: self.portmap_advertise_nonpublic,
            renew_while_idle: !self.portmap_lazy_renew,
        }
    }
}

/// `--portmap-proto` values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum PortmapProto {
    Pmp,
    Pcp,
    Both,
}

impl Args {
    /// The probe's options from the command line.
    fn probe_options(&self) -> ts_portmapper::probe_tool::ProbeOptions {
        ts_portmapper::probe_tool::ProbeOptions {
            protos: ts_portmapper::oneshot::ProtoSet {
                pmp: self.portmap_proto != PortmapProto::Pcp,
                pcp: self.portmap_proto != PortmapProto::Pmp,
            },
            test_port: self.portmap_test_port,
            lifetime: self.portmap_lifetime,
            hold: Duration::from_secs(self.portmap_hold),
            gateway_override: self.portmap_gateway,
            node_port: self.port,
            wait: Duration::from_secs(self.portmap_wait),
        }
    }
}

/// Run `--portmap-probe`: no `Device`, no identity, no control. Interrupts (Ctrl-C, SIGTERM) end
/// the gateway wait or the hold early and skip the remaining maps; the delete for anything sent
/// still runs. The handlers are installed before the probe starts, so an interrupt at any point
/// is caught rather than killing the process. Returns the process exit code.
fn run_portmap_probe(args: &Args) -> Result<i32, Box<dyn Error>> {
    // The probe's report goes to stdout; logs, if any, to stderr.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();
    let opts = args.probe_options();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        // Register the handlers now (not lazily on first poll): from here on SIGINT and SIGTERM
        // are recorded instead of killing the process mid-exchange.
        #[cfg(unix)]
        let interrupt = {
            let mut int = signal(SignalKind::interrupt())?;
            let mut term = signal(SignalKind::terminate())?;
            async move {
                tokio::select! {
                    _ = int.recv() => {}
                    _ = term.recv() => {}
                }
            }
        };
        #[cfg(not(unix))]
        let interrupt = {
            let (tx, rx) = tokio::sync::oneshot::channel::<()>();
            tokio::spawn(async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    tx.send(()).ok();
                }
            });
            async move {
                rx.await.ok();
            }
        };
        let mut stdout = std::io::stdout();
        Ok::<_, Box<dyn Error>>(ts_portmapper::probe_tool::run(&opts, interrupt, &mut stdout).await)
    })
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    if args.portmap_probe {
        let code = run_portmap_probe(&args)?;
        std::process::exit(code);
    }
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(args.worker_threads.max(1))
        .enable_all()
        .build()?
        .block_on(run(args))
}

async fn run(args: Args) -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let state_dir = args
        .state_dir
        .clone()
        .ok_or("--state-dir is required unless --portmap-probe is given")?;
    tokio::fs::create_dir_all(&state_dir).await?;
    let key_file = state_dir.join("keys.json");
    let first_run = !tokio::fs::try_exists(&key_file).await?;

    let auth_key = match (&args.auth_key_file, first_run) {
        (Some(p), _) => Some(tokio::fs::read_to_string(p).await?.trim().to_owned()),
        (None, true) if !args.interactive => {
            return Err("first run needs --auth-key-file or --interactive".into());
        }
        (None, _) => None,
    };

    let exit_dns = if args.no_exit_dns {
        None
    } else {
        args.exit_dns.or_else(system_resolver)
    };
    tracing::info!(?exit_dns, "exit-node DNS for unreachable resolvers");

    let config = Config {
        key_state: tailscale::config::load_key_file(&key_file, BadFormatBehavior::Error).await?,
        client_name: Some("ts-exit-node".to_owned()),
        requested_hostname: Some(args.hostname.clone()),
        requested_tags: args.tags.clone(),
        // A persistent exit node must survive brief disconnects without being GC'd by control.
        ephemeral: false,
        // The tailnet DNS config backs the exit-node DoH service. Userspace mode never touches the
        // host resolver either way.
        accept_dns: true,
        advertise_exit_node: !args.no_advertise,
        forward_all_ports: !args.no_advertise,
        forward_exit_egress: !args.no_advertise,
        // Egress to the exit node's LAN stays off, like Go's default for exit-node users.
        exit_node_allow_lan_access: false,
        exit_node_dns: exit_dns,
        peerapi_port: (args.peerapi_port != 0).then_some(args.peerapi_port),
        tcp_buffer_size: args.tcp_buffer_size,
        wireguard_listen_port: Some(args.port),
        netmap_cache_dir: None,
        disable_port_mapper: args.no_portmapper,
        port_mapper: args.port_mapper_options(),
        ..Config::default()
    };

    let dev = Device::new(&config, auth_key).await?;
    // Interactive login: `wait_until_running` reports `NeedsLogin(url)` right away rather than
    // waiting, so show the URL and keep waiting until it is approved (or the hour runs out).
    let deadline =
        tokio::time::Instant::now() + Duration::from_secs(if args.interactive { 3600 } else { 90 });
    let mut shown = None;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match dev.wait_until_running(Some(left)).await {
            Ok(()) => break,
            Err(RegistrationError::NeedsLogin(url)) if args.interactive && !left.is_zero() => {
                if shown.as_ref() != Some(&url) {
                    tracing::info!(%url, "open this URL to log the node in");
                    shown = Some(url);
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(e) => return Err(e.into()),
        }
    }
    let (v4, v6) = dev.tailscale_ips().await?;
    tracing::info!(
        ?v4,
        ?v6,
        advertise_exit_node = !args.no_advertise,
        "running"
    );

    if args.sink_port != 0 {
        let listener = dev
            .tcp_listen(std::net::SocketAddr::from((
                std::net::Ipv4Addr::UNSPECIFIED,
                args.sink_port,
            )))
            .await?;
        tracing::info!(port = args.sink_port, "benchmark sink listening");
        tokio::spawn(async move {
            while let Ok(conn) = listener.accept().await {
                tokio::spawn(serve_sink(conn));
            }
        });
    }

    // Service managers stop a process with SIGTERM on Unix. Windows has no SIGTERM, so there the
    // node stops on Ctrl-C alone.
    #[cfg(unix)]
    let mut sigterm = signal(SignalKind::terminate())?;
    let terminate = async {
        #[cfg(unix)]
        sigterm.recv().await;
        #[cfg(not(unix))]
        std::future::pending::<()>().await;
    };
    tokio::pin!(terminate);
    let mut ticker = (args.status_interval > 0)
        .then(|| tokio::time::interval(Duration::from_secs(args.status_interval)));

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = &mut terminate => break,
            _ = async { ticker.as_mut().unwrap().tick().await }, if ticker.is_some() => {
                log_status(&dev).await;
            }
        }
    }

    tracing::info!("shutting down");
    let clean = dev.shutdown(Some(Duration::from_secs(5))).await;
    tracing::info!(clean, "stopped");
    Ok(())
}

async fn log_status(dev: &Device) {
    // Never let a status query stall the main loop (and with it signal handling).
    let status = match tokio::time::timeout(Duration::from_secs(5), dev.status()).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "status");
            return;
        }
        Err(_) => {
            let t = Duration::from_secs(2);
            let self_node = tokio::time::timeout(t, dev.self_node()).await.is_ok();
            let peer_tracker =
                tokio::time::timeout(t, dev.peers_with_route("203.0.113.1".parse().unwrap()))
                    .await
                    .is_ok();
            tracing::warn!(self_node, peer_tracker, "status query timed out");
            return;
        }
    };
    // Go's netcheck `portmap=` summary (e.g. `active-_MC`), plus the mapping when one is held.
    let (portmap, portmap_ext) = match dev.port_map_status() {
        Some(pm) => (
            pm.summary(),
            pm.external.map(|e| {
                format!(
                    "{e}{}",
                    if pm.advertised {
                        ""
                    } else {
                        " (not advertised)"
                    }
                )
            }),
        ),
        None => ("off".to_owned(), None),
    };
    match &status.self_node {
        Some(me) => tracing::info!(
            routes = ?me.allowed_routes,
            exit_node = me.is_exit_node,
            peers = status.peers.len(),
            health = ?status.health,
            %portmap,
            ext = portmap_ext.as_deref().unwrap_or("-"),
            "self"
        ),
        None => {
            tracing::info!(peers = status.peers.len(), health = ?status.health, "self (no self node yet)")
        }
    }
    // Online state is often unknown in this engine (None), so only skip peers known offline.
    for p in status.peers.iter().filter(|p| p.online != Some(false)) {
        let path = match (&p.cur_addr, &p.relay) {
            (Some(a), _) => format!("direct {a}"),
            (None, Some(r)) => format!("derp {r}"),
            (None, None) => "idle".to_owned(),
        };
        tracing::info!(peer = %p.display_name, ip = %p.ipv4, online = ?p.online, %path, "peer");
    }
}

/// This host's resolver: the first IPv4 `nameserver` in /etc/resolv.conf (macOS keeps it current)
/// that is not Tailscale's own. A host running tailscaled lists `100.100.100.100`; sending exit
/// users' DNS there would hand it to that tailscaled, which Go's exit node avoids the same way
/// (`HandlePeerDNSQuery`, net/dns/resolver/tsdns.go). Exit egress is IPv4-only, so an IPv6
/// nameserver, `fd7a:115c:a1e0::53` included, is never picked.
fn system_resolver() -> Option<std::net::SocketAddr> {
    const TAILSCALE_SERVICE_IPS: [std::net::IpAddr; 2] = [
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(100, 100, 100, 100)),
        std::net::IpAddr::V6(std::net::Ipv6Addr::new(
            0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0x53,
        )),
    ];
    let conf = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    conf.lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .filter_map(|ip| ip.trim().parse::<std::net::IpAddr>().ok())
        .filter(|ip| ip.is_ipv4() && !TAILSCALE_SERVICE_IPS.contains(ip))
        .map(|ip| std::net::SocketAddr::new(ip, 53))
        .next()
}

/// One benchmark connection: `d` streams zeros to the client, `u` discards what it sends, `e`
/// echoes it (latency probes).
async fn serve_sink(mut conn: tailscale::netstack::TcpStream) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 64 * 1024];
    let Ok(n) = conn.read(&mut buf[..1]).await else {
        return;
    };
    match (n, buf[0]) {
        (1, b'd') => {
            buf.fill(0);
            while conn.write_all(&buf).await.is_ok() {}
        }
        (1, b'u') => while matches!(conn.read(&mut buf).await, Ok(n) if n > 0) {},
        (1, b'e') => loop {
            match conn.read(&mut buf).await {
                Ok(n) if n > 0 => {
                    if conn.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        },
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    fn parse(args: &[&str]) -> Result<Args, clap::Error> {
        Args::try_parse_from(std::iter::once("exit_node").chain(args.iter().copied()))
    }

    /// The probe needs no state directory; the node still does.
    #[test]
    fn probe_runs_without_state_dir() {
        let a = parse(&["--portmap-probe"]).unwrap();
        assert!(a.portmap_probe && a.state_dir.is_none());
        let o = a.probe_options();
        assert!(o.protos.pmp && o.protos.pcp);
        assert_eq!((o.test_port, o.lifetime, o.node_port), (0, 120, 41642));
        assert!(o.validate().is_ok());
        assert!(parse(&[]).is_err());
        assert!(parse(&["--state-dir", "/tmp/x"]).is_ok());
    }

    #[test]
    fn probe_flags_require_the_probe() {
        for flags in [
            &["--state-dir", "s", "--portmap-hold", "5"][..],
            &["--state-dir", "s", "--portmap-proto", "pmp"],
            &["--state-dir", "s", "--portmap-test-port", "5000"],
            &["--state-dir", "s", "--portmap-wait", "5"],
        ] {
            assert!(parse(flags).is_err(), "{flags:?}");
        }
    }

    #[test]
    fn probe_flag_ranges_and_reserved_ports() {
        assert!(parse(&["--portmap-probe", "--portmap-lifetime", "0"]).is_err());
        assert!(parse(&["--portmap-probe", "--portmap-lifetime", "7201"]).is_err());
        assert!(parse(&["--portmap-probe", "--portmap-hold", "601"]).is_err());
        assert!(parse(&["--portmap-probe", "--portmap-wait", "121"]).is_err());
        let a = parse(&["--portmap-probe", "--portmap-wait", "30"]).unwrap();
        assert_eq!(a.probe_options().wait, Duration::from_secs(30));
        for port in ["41641", "41642"] {
            let a = parse(&["--portmap-probe", "--portmap-test-port", port]).unwrap();
            assert!(a.probe_options().validate().is_err(), "{port}");
        }
        let a = parse(&[
            "--portmap-probe",
            "--port",
            "50000",
            "--portmap-test-port",
            "50000",
        ])
        .unwrap();
        assert!(a.probe_options().validate().is_err());
        let a = parse(&[
            "--portmap-probe",
            "--portmap-proto",
            "pcp",
            "--portmap-gateway",
            "192.168.1.1,192.168.1.20",
            "--portmap-hold",
            "60",
        ])
        .unwrap();
        let o = a.probe_options();
        assert!(!o.protos.pmp && o.protos.pcp);
        assert_eq!(o.hold, Duration::from_secs(60));
        assert_eq!(
            o.gateway_override.unwrap().self_ip,
            Some("192.168.1.20".parse().unwrap())
        );
        assert!(parse(&["--portmap-probe", "--portmap-gateway", "nope"]).is_err());
    }

    /// The runner's port-mapper defaults (suppress non-public, renew while idle) and the flags
    /// that revert each to Go's behaviour; the gateway override serves the node too.
    #[test]
    fn port_mapper_flags() {
        let a = parse(&["--state-dir", "s"]).unwrap();
        assert!(!a.no_portmapper);
        let o = a.port_mapper_options();
        assert!(!o.advertise_nonpublic_external);
        assert!(o.renew_while_idle);
        assert!(o.gateway_override.is_none());
        let a = parse(&[
            "--state-dir",
            "s",
            "--portmap-advertise-nonpublic",
            "--portmap-lazy-renew",
            "--portmap-gateway",
            "192.168.1.1,192.168.1.20",
        ])
        .unwrap();
        let o = a.port_mapper_options();
        assert!(o.advertise_nonpublic_external && !o.renew_while_idle);
        assert_eq!(
            o.gateway_override,
            Some((
                "192.168.1.1".parse().unwrap(),
                Some("192.168.1.20".parse().unwrap())
            ))
        );
        assert!(
            parse(&["--state-dir", "s", "--no-portmapper"])
                .unwrap()
                .no_portmapper
        );
        assert!(parse(&["--portmap-probe", "--no-portmapper"]).is_err());
    }
}
