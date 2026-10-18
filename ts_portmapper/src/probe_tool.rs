//! The `--portmap-probe` diagnostic: validate NAT-PMP/PCP in a deployment's real launch context
//! without touching the node.
//!
//! It binds a dedicated, receive-only test socket on the gateway's self address (never the node's
//! port, never 41641/41642), probes both protocols, then for each requested protocol in turn maps
//! the test port, optionally holds the mapping open while counting inbound datagrams (length and
//! source only, never the payload, never a reply), and deletes it. If the router grants a lease no
//! longer than the hold, the mapping is renewed every half lease during the hold. Total time is
//! bounded by the gateway wait (at most 120 s) and the hold (at most 600 s) plus a few 250 ms
//! exchanges. An interrupt is checked before each map and during the hold: it skips the remaining
//! maps, and the delete for anything sent still runs. The default lease is 120 s, so even a
//! crashed probe leaves at most a 120 s request behind.
//!
//! Output is stable `key=value` lines on the given writer. It may contain the router's public
//! address: never commit it.

use std::{
    future::Future,
    io::Write,
    net::SocketAddr,
    num::{NonZeroU16, NonZeroU32},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use crate::{
    Gateway, GatewayCap, LookupError, NetGen, PolicyHandle, PxpTransport,
    gateway::{GatewayLookup, GatewayOverride, SystemLookup},
    oneshot::{self, MapError, Mapping, Proto, ProtoSet, Rule},
};

/// Ports the test socket may never use: Go's and this runner's default node ports.
pub const RESERVED_PORTS: [u16; 2] = [41641, 41642];
/// Default requested lease, in seconds.
pub const DEFAULT_LIFETIME: u32 = 120;
/// Longest lease the probe may request, in seconds.
pub const MAX_LIFETIME: u32 = 7200;
/// Longest hold window.
pub const MAX_HOLD: Duration = Duration::from_secs(600);
/// Longest wait for a usable gateway (a launchd job started before the network is up).
pub const MAX_WAIT: Duration = Duration::from_secs(120);
/// How often the gateway lookup is retried while waiting.
const WAIT_POLL: Duration = Duration::from_secs(1);
/// At most this many per-datagram `inbound` lines are printed per hold.
const MAX_INBOUND_LINES: usize = 1000;
/// At most this many distinct sources are listed per hold.
const MAX_SOURCES: usize = 32;

/// What to probe.
#[derive(Debug, Clone)]
pub struct ProbeOptions {
    /// Protocols to map, each separately.
    pub protos: ProtoSet,
    /// The test socket's port; 0 for an ephemeral one.
    pub test_port: u16,
    /// Requested lease in seconds (1..=7200).
    pub lifetime: u32,
    /// How long to hold each mapping open (at most 600 s, shorter than the lease).
    pub hold: Duration,
    /// Use this gateway instead of discovering one (still fully validated).
    pub gateway_override: Option<GatewayOverride>,
    /// The node's own UDP port, which the test socket must not use.
    pub node_port: u16,
    /// How long to keep retrying the gateway lookup (routing-table reads only, no packets)
    /// until it finds a gateway; at most 120 s.
    pub wait: Duration,
}

impl Default for ProbeOptions {
    fn default() -> Self {
        Self {
            protos: ProtoSet::BOTH,
            test_port: 0,
            lifetime: DEFAULT_LIFETIME,
            hold: Duration::ZERO,
            gateway_override: None,
            node_port: 41642,
            wait: Duration::ZERO,
        }
    }
}

impl ProbeOptions {
    fn forbidden(&self, port: u16) -> bool {
        port != 0 && (RESERVED_PORTS.contains(&port) || port == self.node_port)
    }

    /// Check the options; the error says what is wrong.
    pub fn validate(&self) -> Result<(), String> {
        if !self.protos.pmp && !self.protos.pcp {
            return Err("no protocol selected".to_owned());
        }
        if self.forbidden(self.test_port) {
            return Err(format!(
                "test port {} is a node port (41641, 41642 and --port are reserved)",
                self.test_port
            ));
        }
        if !(1..=MAX_LIFETIME).contains(&self.lifetime) {
            return Err(format!("lifetime must be 1..={MAX_LIFETIME} seconds"));
        }
        if self.hold > MAX_HOLD {
            return Err(format!(
                "hold must be at most {} seconds",
                MAX_HOLD.as_secs()
            ));
        }
        if self.hold >= Duration::from_secs(u64::from(self.lifetime)) && !self.hold.is_zero() {
            return Err("hold must be shorter than the lifetime".to_owned());
        }
        if self.wait > MAX_WAIT {
            return Err(format!(
                "wait must be at most {} seconds",
                MAX_WAIT.as_secs()
            ));
        }
        Ok(())
    }
}

/// Quote a value if it contains anything that would break `key=value` parsing.
fn v(s: impl ToString) -> String {
    let s = s.to_string();
    if s.is_empty() {
        "-".to_owned()
    } else if s.chars().any(|c| c.is_whitespace() || c == '"' || c == '=') {
        format!("{s:?}")
    } else {
        s
    }
}

fn opt<T: ToString>(o: Option<T>) -> String {
    o.map_or_else(|| "-".to_owned(), v)
}

/// Whether `cancel` has fired, without waiting. Never call it again once it returned `true`.
async fn fired(cancel: &mut Pin<&mut impl Future<Output = ()>>) -> bool {
    tokio::select! {
        biased;
        () = cancel.as_mut() => true,
        () = std::future::ready(()) => false,
    }
}

/// Look up the gateway, retrying every second for up to `wait` while there is none (or the
/// lookup fails), e.g. a launchd job started before the network is up. Reads the routing table
/// and interface list only; sends nothing. `Err(None)` means `cancel` fired.
async fn wait_for_gateway(
    lookup: Arc<dyn GatewayLookup>,
    wait: Duration,
    cancel: &mut Pin<&mut impl Future<Output = ()>>,
    out: &mut dyn Write,
) -> Result<Gateway, Option<Result<Option<Gateway>, LookupError>>> {
    let start = tokio::time::Instant::now();
    let mut attempts = 0u32;
    let result = loop {
        attempts += 1;
        let os_lookup = lookup.clone();
        let work = crate::blocking::run(move || os_lookup.lookup());
        let r = tokio::select! {
            biased;
            () = cancel.as_mut() => return Err(None),
            r = work => r.unwrap_or(Ok(None)),
        };
        if matches!(r, Ok(Some(_))) || start.elapsed() >= wait {
            break r;
        }
        tokio::select! {
            () = tokio::time::sleep(WAIT_POLL.min(wait.saturating_sub(start.elapsed()))) => {}
            () = cancel.as_mut() => {
                writeln!(out, "gateway wait={}s attempts={attempts} interrupted=true", start.elapsed().as_secs()).ok();
                return Err(None);
            }
        }
    };
    if !wait.is_zero() {
        writeln!(
            out,
            "gateway wait={}s attempts={attempts}",
            start.elapsed().as_secs()
        )
        .ok();
    }
    match result {
        Ok(Some(g)) => Ok(g),
        other => Err(Some(other)),
    }
}

/// The process context the probe runs in (the launch context is what is being validated).
fn env_line() -> String {
    let os = os_version();
    #[cfg(unix)]
    let (uid, euid, ppid) = {
        // SAFETY: getuid and geteuid take no arguments, cannot fail and touch no memory.
        let (uid, euid) = unsafe { (libc::getuid(), libc::geteuid()) };
        (
            uid.to_string(),
            euid.to_string(),
            std::os::unix::process::parent_id().to_string(),
        )
    };
    #[cfg(not(unix))]
    let (uid, euid, ppid) = ("-".to_owned(), "-".to_owned(), "-".to_owned());
    let exe = std::env::current_exe().map_or_else(|_| "-".to_owned(), |p| v(p.display()));
    let xpc = std::env::var("XPC_SERVICE_NAME").unwrap_or_default();
    format!(
        "env os={} uid={uid} euid={euid} exe={exe} ppid={ppid} xpc_service={}",
        v(os),
        v(xpc)
    )
}

/// `<product version>/<build>` on macOS, the kernel release elsewhere.
fn os_version() -> String {
    #[cfg(target_os = "macos")]
    {
        let plist = std::fs::read_to_string("/System/Library/CoreServices/SystemVersion.plist")
            .unwrap_or_default();
        let key = |k: &str| {
            let after = plist.split(&format!("<key>{k}</key>")).nth(1)?;
            let start = after.find("<string>")? + "<string>".len();
            let end = after[start..].find("</string>")? + start;
            Some(after[start..end].to_owned())
        };
        format!(
            "macos-{}/{}",
            key("ProductVersion").unwrap_or_default(),
            key("ProductBuildVersion").unwrap_or_default()
        )
    }
    #[cfg(not(target_os = "macos"))]
    {
        let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
        format!("{}-{}", std::env::consts::OS, release.trim())
    }
}

/// Run the probe against the real gateway: lookup (or validated override), [`GatewayCap`], then
/// the steps of [`run_with`]. Returns the exit code: 0 if every requested protocol was mapped and
/// deleted, 2 if some were, 1 if none were or the lookup or capability failed.
pub async fn run(
    opts: &ProbeOptions,
    cancel: impl Future<Output = ()>,
    out: &mut dyn Write,
) -> i32 {
    if let Err(e) = opts.validate() {
        writeln!(out, "error msg={}", v(e)).ok();
        return 1;
    }
    let mut cancel = std::pin::pin!(cancel);
    let lookup: Arc<dyn GatewayLookup> = Arc::new(SystemLookup::new(opts.gateway_override));
    let source = if opts.gateway_override.is_some() {
        "override"
    } else {
        "discovered"
    };
    let gateway = match wait_for_gateway(lookup.clone(), opts.wait, &mut cancel, out).await {
        Ok(g) => g,
        Err(None) => {
            writeln!(out, "{}", env_line()).ok();
            writeln!(out, "gateway source={source} error=interrupted").ok();
            return 1;
        }
        Err(Some(Ok(Some(_)))) => unreachable!("a found gateway is returned as Ok"),
        Err(Some(Ok(None))) => {
            writeln!(out, "{}", env_line()).ok();
            writeln!(out, "gateway source={source} error=no-ipv4-default-route").ok();
            return 1;
        }
        Err(Some(Err(e))) => {
            writeln!(out, "{}", env_line()).ok();
            writeln!(out, "gateway source={source} error={}", v(e)).ok();
            return 1;
        }
    };
    let validate_gateway = gateway.clone();
    let cap = match crate::blocking::run(move || {
        GatewayCap::validate(
            validate_gateway,
            NetGen(1),
            PolicyHandle::new(true),
            Some(lookup),
        )
    })
    .await
    .unwrap_or(Err(crate::CapError::InvalidGateway(
        "validation worker failed",
    ))) {
        Ok(c) => c,
        Err(e) => {
            writeln!(out, "{}", env_line()).ok();
            writeln!(
                out,
                "gateway gw={} self={} if={}/{} source={source} error={}",
                gateway.gw,
                gateway.self_ip,
                v(&gateway.if_name),
                gateway.if_index,
                v(e)
            )
            .ok();
            return 1;
        }
    };
    run_with(opts, &*cap, source, cancel, out).await
}

/// The probe steps over any transport (the real cap, or the test transport in tests).
pub async fn run_with<T: PxpTransport>(
    opts: &ProbeOptions,
    t: &T,
    source: &str,
    cancel: impl Future<Output = ()>,
    out: &mut dyn Write,
) -> i32 {
    writeln!(out, "{}", env_line()).ok();
    if let Err(e) = opts.validate() {
        writeln!(out, "error msg={}", v(e)).ok();
        return 1;
    }
    let g = t.gateway();
    writeln!(
        out,
        "gateway gw={} self={} if={}/{} prefix=/{} source={source} bind={}",
        g.gw,
        g.self_ip,
        v(&g.if_name),
        g.if_index,
        g.prefix_len,
        t.bind_mode()
    )
    .ok();

    // The dedicated test socket. An ephemeral bind can land on a reserved port (Linux's
    // ephemeral range includes 41641/41642), so retry a few times.
    let mut listener = None;
    for _ in 0..5 {
        match t.bind_probe_listener(opts.test_port) {
            Ok(l) if opts.forbidden(l.port()) => continue,
            Ok(l) => {
                listener = Some(l);
                break;
            }
            Err(e) => {
                writeln!(out, "listen port={} error={}", opts.test_port, v(e)).ok();
                return 1;
            }
        }
    }
    let Some(mut listener) = listener else {
        writeln!(out, "listen error=only-reserved-ports").ok();
        return 1;
    };
    let Some(internal) = NonZeroU16::new(listener.port()) else {
        writeln!(out, "listen error=port-0").ok();
        return 1;
    };
    writeln!(out, "listen port={internal} self={}", g.self_ip).ok();

    match oneshot::probe(t, opts.protos).await {
        Ok(r) => {
            writeln!(
                out,
                "probe pmp={} pmp_epoch={} pmp_ext_ip={} pmp_result={} pcp={} pcp_result={} pcp_epoch={} errors={}",
                r.pmp,
                opt(r.pmp_epoch),
                opt(r.pmp_public_ip),
                opt(r.pmp_result),
                r.pcp,
                opt(r.pcp_result),
                opt(r.pcp_epoch),
                v(r.errors.join("; "))
            )
            .ok();
        }
        Err(e) => {
            writeln!(out, "probe error={}", v(e)).ok();
            return 1;
        }
    }

    let lifetime = NonZeroU32::new(opts.lifetime).unwrap_or(NonZeroU32::MIN);
    let mut cancel = std::pin::pin!(cancel);
    let mut interrupted = false;
    let mut requested = 0;
    let mut succeeded = 0;
    for proto in opts.protos.iter() {
        requested += 1;
        // An interrupt during the probe or an earlier map/delete skips the remaining maps.
        if !interrupted {
            interrupted = fired(&mut cancel).await;
        }
        if interrupted {
            writeln!(out, "map proto={proto} result=skipped err=interrupted").ok();
            continue;
        }
        let rule = match Rule::new(proto, internal) {
            Ok(r) => r,
            Err(e) => {
                writeln!(out, "map proto={proto} result=error err={}", v(e)).ok();
                continue;
            }
        };
        let mapped = oneshot::map(t, &rule, lifetime, None).await;
        let (result, err) = match &mapped {
            Ok(_) => ("ok".to_owned(), None),
            Err(MapError::Pmp { code, .. }) => (code.to_string(), None),
            Err(MapError::Pcp { code, lifetime, .. }) => (
                code.to_string(),
                Some(format!("error lifetime {lifetime} s")),
            ),
            Err(MapError::PmpAddr { code, .. }) => (
                code.to_string(),
                Some("public-address request failed; the MAP may exist".to_owned()),
            ),
            Err(MapError::PcpUnverified { code, lifetime, .. }) => (
                code.to_string(),
                Some(format!("no nonce, unverified; error lifetime {lifetime} s")),
            ),
            Err(MapError::NoServices { malformed }) => ("timeout".to_owned(), malformed.clone()),
            Err(e) => ("error".to_owned(), Some(e.to_string())),
        };
        match &mapped {
            Ok(m) => writeln!(
                out,
                "map proto={proto} internal={internal} requested_lifetime={} result=ok external={} lease={} epoch={} err=-",
                opts.lifetime, m.external, m.lifetime, m.epoch
            ),
            Err(
                MapError::Pmp { epoch, .. }
                | MapError::PmpAddr { epoch, .. }
                | MapError::Pcp { epoch, .. }
                | MapError::PcpUnverified { epoch, .. },
            ) => writeln!(
                out,
                "map proto={proto} internal={internal} requested_lifetime={} result={} external=- lease=- epoch={epoch} err={}",
                opts.lifetime,
                v(result),
                opt(err)
            ),
            Err(_) => writeln!(
                out,
                "map proto={proto} internal={internal} requested_lifetime={} result={} external=- lease=- epoch=- err={}",
                opts.lifetime,
                v(result),
                opt(err)
            ),
        }
        .ok();

        if let (Ok(m), false) = (&mapped, opts.hold.is_zero()) {
            let mut h = Hold {
                t,
                rule: &rule,
                lifetime,
                mapping: m.clone(),
                renewals: 0,
            };
            interrupted = h.run(&mut listener, opts.hold, &mut cancel, out).await;
        }

        // Delete whenever the router may hold the rule. Only a refusal tied to our MAP request
        // proves it created nothing: a NAT-PMP MAP error for our port, or a PCP error that echoes
        // our nonce. A timeout, a nonce-less PCP error, a capability error (the send may have
        // happened) or anything else may hide a committed MAP; deleting a rule that does not
        // exist is harmless.
        let may_exist = !matches!(
            (proto, &mapped),
            (Proto::Pmp, Err(MapError::Pmp { .. }))
                | (Proto::Pcp, Err(MapError::Pcp { .. }))
                | (_, Err(MapError::Nonce(_)))
        );
        if !may_exist {
            writeln!(out, "delete proto={proto} sent=skipped reply=-").ok();
            continue;
        }
        let deleted = oneshot::delete(t, &rule).await;
        let line = match &deleted {
            Ok(()) => "sent=ok reply=ok lifetime=0".to_owned(),
            Err(MapError::Cap(e)) => format!("sent=err err={} reply=-", v(e)),
            Err(MapError::NoServices { .. }) => "sent=ok reply=timeout".to_owned(),
            Err(MapError::Pmp { code, .. }) => format!("sent=ok reply={code}"),
            Err(MapError::Pcp { code, .. }) => format!("sent=ok reply={code}"),
            Err(MapError::PcpUnverified { code, .. }) => {
                format!("sent=ok reply={code} err=unverified")
            }
            Err(e) => format!("sent=err err={} reply=-", v(e)),
        };
        writeln!(out, "delete proto={proto} {line}").ok();
        if mapped.is_ok() && deleted.is_ok() {
            succeeded += 1;
        }
    }

    let code = if succeeded == requested {
        0
    } else if succeeded > 0 {
        2
    } else {
        1
    };
    writeln!(
        out,
        "done exit={code} mapped_and_deleted={succeeded}/{requested}"
    )
    .ok();
    code
}

/// A mapping held open during the hold window.
struct Hold<'a, T> {
    t: &'a T,
    rule: &'a Rule,
    lifetime: NonZeroU32,
    mapping: Mapping,
    renewals: u32,
}

impl<T: PxpTransport> Hold<'_, T> {
    /// When to renew next: every half lease, if the granted lease is no longer than the hold
    /// (the router may grant less than requested).
    fn renew_every(&self, dur: Duration) -> Option<Duration> {
        let lease = Duration::from_secs(u64::from(self.mapping.lifetime));
        (lease <= dur).then(|| (lease / 2).max(Duration::from_secs(1)))
    }

    /// Renew the mapping with the same rule and report it.
    async fn renew(&mut self, out: &mut dyn Write) {
        self.renewals += 1;
        let proto = self.rule.proto();
        let n = self.renewals;
        match oneshot::map(self.t, self.rule, self.lifetime, Some(&self.mapping)).await {
            Ok(m) => {
                writeln!(
                    out,
                    "renew proto={proto} n={n} result=ok external={} lease={} epoch={}",
                    m.external, m.lifetime, m.epoch
                )
                .ok();
                self.mapping = m;
            }
            Err(e) => {
                writeln!(out, "renew proto={proto} n={n} result=error err={}", v(e)).ok();
            }
        }
    }

    /// Keep the mapping open for `dur`, reporting each inbound datagram's length and source.
    /// Returns whether `cancel` fired.
    async fn run(
        &mut self,
        listener: &mut crate::ProbeListener,
        dur: Duration,
        cancel: &mut Pin<&mut impl Future<Output = ()>>,
        out: &mut dyn Write,
    ) -> bool {
        let proto = self.rule.proto();
        let start = tokio::time::Instant::now();
        let end = start + dur;
        let mut next_renew = self.renew_every(dur).map(|d| start + d);
        if let Some(at) = next_renew {
            writeln!(
                out,
                "lease proto={proto} warning=not-longer-than-hold lease={} renew_every={}s",
                self.mapping.lifetime,
                (at - start).as_secs()
            )
            .ok();
        }
        let mut count = 0usize;
        let mut sources: Vec<SocketAddr> = Vec::new();
        let mut interrupted = false;
        loop {
            tokio::select! {
                () = tokio::time::sleep_until(end) => break,
                () = cancel.as_mut() => {
                    interrupted = true;
                    break;
                }
                () = tokio::time::sleep_until(next_renew.unwrap_or(end)), if next_renew.is_some_and(|r| r < end) => {
                    self.renew(out).await;
                    next_renew = self
                        .renew_every(dur)
                        .map(|d| tokio::time::Instant::now() + d);
                }
                r = listener.recv() => match r {
                    Ok((len, src)) => {
                        count += 1;
                        if count <= MAX_INBOUND_LINES {
                            writeln!(out, "inbound proto={proto} n={count} src={src} len={len}").ok();
                        }
                        if sources.len() < MAX_SOURCES && !sources.contains(&src) {
                            sources.push(src);
                        }
                    }
                    Err(e) => {
                        writeln!(out, "inbound proto={proto} error={}", v(e)).ok();
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                },
            }
        }
        let list: Vec<String> = sources.iter().map(ToString::to_string).collect();
        writeln!(
            out,
            "hold proto={proto} seconds={} inbound_datagrams={count} sources={} interrupted={interrupted} renewals={}",
            dur.as_secs(),
            v(list.join(",")),
            self.renewals
        )
        .ok();
        interrupted
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::{
        Gateway,
        testing::{
            FakeRouter, RequestKind, ResultOverride, RouterOptions, TestCap, send_datagrams,
        },
    };

    fn gateway() -> Gateway {
        Gateway {
            gw: Ipv4Addr::new(192, 168, 1, 1),
            self_ip: Ipv4Addr::LOCALHOST,
            prefix_len: 24,
            if_index: 4,
            if_name: "en0".to_owned(),
        }
    }

    async fn run_probe(
        router: &FakeRouter,
        opts: &ProbeOptions,
        cancel: impl Future<Output = ()>,
    ) -> (i32, String) {
        let cap = TestCap::new(gateway(), router, PolicyHandle::new(true));
        let mut out = Vec::new();
        let code = run_with(opts, &*cap, "discovered", cancel, &mut out).await;
        (code, String::from_utf8(out).unwrap())
    }

    /// Parse `key=value` pairs of the first line starting with `tag` (and containing `filter`).
    fn kv(text: &str, tag: &str, filter: &str) -> Vec<(String, String)> {
        let line = text
            .lines()
            .find(|l| l.starts_with(&format!("{tag} ")) && l.contains(filter))
            .unwrap_or_else(|| panic!("no {tag} line with {filter:?} in:\n{text}"));
        let mut pairs = Vec::new();
        let mut rest = line[tag.len() + 1..].trim();
        while !rest.is_empty() {
            let (k, after) = rest.split_once('=').unwrap();
            let (val, next) = if let Some(q) = after.strip_prefix('"') {
                let end = q.find('"').unwrap();
                (q[..end].to_owned(), q[end + 1..].trim_start())
            } else {
                let end = after.find(' ').unwrap_or(after.len());
                (after[..end].to_owned(), after[end..].trim_start())
            };
            pairs.push((k.to_owned(), val));
            rest = next;
        }
        pairs
    }

    fn keys(pairs: &[(String, String)]) -> Vec<&str> {
        pairs.iter().map(|(k, _)| k.as_str()).collect()
    }

    fn get<'a>(pairs: &'a [(String, String)], k: &str) -> &'a str {
        &pairs.iter().find(|(key, _)| key == k).unwrap().1
    }

    /// The full probe against the harness: each protocol mapped and deleted separately, on a
    /// nonzero ephemeral test port, with the expected output keys.
    #[tokio::test]
    async fn probe_maps_and_deletes_each_protocol() {
        let router = FakeRouter::start(RouterOptions::default()).await.unwrap();
        let (code, out) =
            run_probe(&router, &ProbeOptions::default(), std::future::pending()).await;
        assert_eq!(code, 0, "{out}");

        let env = kv(&out, "env", "");
        assert_eq!(
            keys(&env),
            ["os", "uid", "euid", "exe", "ppid", "xpc_service"]
        );
        let gw = kv(&out, "gateway", "");
        assert_eq!(keys(&gw), ["gw", "self", "if", "prefix", "source", "bind"]);
        assert_eq!(get(&gw, "if"), "en0/4");
        let probe = kv(&out, "probe", "");
        for k in [
            "pmp",
            "pmp_epoch",
            "pmp_ext_ip",
            "pcp",
            "pcp_result",
            "pcp_epoch",
            "errors",
        ] {
            assert!(keys(&probe).contains(&k), "{k} missing: {out}");
        }
        assert_eq!(get(&probe, "pmp"), "true");
        assert_eq!(get(&probe, "pcp"), "true");

        let port: u16 = get(&kv(&out, "listen", ""), "port").parse().unwrap();
        assert_ne!(port, 0);
        for proto in ["pmp", "pcp"] {
            let m = kv(&out, "map", &format!("proto={proto}"));
            assert_eq!(
                keys(&m),
                [
                    "proto",
                    "internal",
                    "requested_lifetime",
                    "result",
                    "external",
                    "lease",
                    "epoch",
                    "err"
                ]
            );
            assert_eq!(get(&m, "result"), "ok");
            assert_eq!(get(&m, "internal"), port.to_string());
            assert_eq!(get(&m, "requested_lifetime"), "120");
            assert_eq!(get(&m, "lease"), "120");
            let d = kv(&out, "delete", &format!("proto={proto}"));
            assert_eq!(get(&d, "sent"), "ok");
            assert_eq!(get(&d, "reply"), "ok");
        }
        // The deletes reached the router with the right identity: our internal port, lifetime 0.
        let deletes: Vec<_> = router
            .requests()
            .into_iter()
            .filter(|r| r.lifetime == Some(0) && r.internal.is_some())
            .collect();
        assert_eq!(deletes.len(), 2);
        assert!(deletes.iter().all(|r| r.internal == Some(port)));
        assert!(router.mappings().is_empty());
        let c = router.counters();
        assert_eq!(
            (c.num_pmp_map_recv, c.num_pcp_map_recv, c.num_deletes),
            (2, 2, 2)
        );
        assert!(
            out.ends_with("done exit=0 mapped_and_deleted=2/2\n"),
            "{out}"
        );
        router.shutdown().await;
    }

    /// Hold mode reports inbound datagrams by count, source and length only.
    #[tokio::test]
    async fn hold_reports_inbound_without_payload() {
        let router = FakeRouter::start(RouterOptions::default()).await.unwrap();
        let cap = TestCap::new(gateway(), &router, PolicyHandle::new(true));
        let opts = ProbeOptions {
            protos: ProtoSet {
                pmp: true,
                pcp: false,
            },
            test_port: 0,
            hold: Duration::from_secs(1),
            ..ProbeOptions::default()
        };
        // Learn the test port from the router's MAP request, then send three datagrams to it.
        let router_ref = &router;
        let sender = async {
            loop {
                if let Some(p) = router_ref
                    .requests()
                    .iter()
                    .find(|r| r.kind == RequestKind::PmpMap)
                    .and_then(|r| r.internal)
                {
                    let to = SocketAddr::from((Ipv4Addr::LOCALHOST, p));
                    return send_datagrams(to, 3, 77).await.unwrap();
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        let mut out = Vec::new();
        let run = run_with(&opts, &*cap, "override", std::future::pending(), &mut out);
        let (code, from) = tokio::join!(run, sender);
        let out = String::from_utf8(out).unwrap();
        assert_eq!(code, 0, "{out}");
        let h = kv(&out, "hold", "proto=pmp");
        assert_eq!(get(&h, "inbound_datagrams"), "3");
        assert_eq!(get(&h, "sources"), from.to_string());
        assert_eq!(get(&h, "interrupted"), "false");
        assert_eq!(out.matches("inbound proto=pmp").count(), 3);
        assert!(out.contains(&format!("src={from} len=77")));
        assert!(!out.contains("ZZZZ") && !out.contains("5a5a"));
        assert!(router.mappings().is_empty());
        router.shutdown().await;
    }

    /// An interrupt ends the hold early, and the delete still runs.
    #[tokio::test]
    async fn interrupt_still_deletes() {
        let router = FakeRouter::start(RouterOptions::default()).await.unwrap();
        let opts = ProbeOptions {
            hold: Duration::from_secs(60),
            ..ProbeOptions::default()
        };
        let cancel = tokio::time::sleep(Duration::from_millis(200));
        let start = std::time::Instant::now();
        let (code, out) = run_probe(&router, &opts, cancel).await;
        assert!(start.elapsed() < Duration::from_secs(10));
        assert_eq!(code, 2, "{out}");
        assert_eq!(get(&kv(&out, "hold", "proto=pmp"), "interrupted"), "true");
        assert_eq!(get(&kv(&out, "delete", "proto=pmp"), "reply"), "ok");
        assert_eq!(get(&kv(&out, "map", "proto=pcp"), "result"), "skipped");
        assert!(router.mappings().is_empty());
        router.shutdown().await;
    }

    /// An interrupt during the first map (no hold) skips the second map; the first is still
    /// deleted.
    #[tokio::test]
    async fn interrupt_without_hold_skips_later_maps() {
        let router = FakeRouter::start(RouterOptions::default()).await.unwrap();
        router.set_delay(Duration::from_millis(150));
        let cancel = async {
            // Fire while the NAT-PMP map is in flight (after the probe exchange).
            while !router
                .requests()
                .iter()
                .any(|r| r.kind == RequestKind::PmpMap)
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        let (code, out) = run_probe(&router, &ProbeOptions::default(), cancel).await;
        assert_eq!(code, 2, "{out}");
        assert_eq!(get(&kv(&out, "map", "proto=pmp"), "result"), "ok");
        assert_eq!(get(&kv(&out, "delete", "proto=pmp"), "reply"), "ok");
        assert_eq!(get(&kv(&out, "map", "proto=pcp"), "result"), "skipped");
        assert_eq!(router.counters().num_pcp_map_recv, 0);
        assert!(router.mappings().is_empty());
        router.shutdown().await;
    }

    /// A lease the router grants no longer than the hold is renewed every half lease, so the
    /// rule does not expire mid-hold.
    #[tokio::test]
    async fn short_lease_is_renewed_during_the_hold() {
        let router = FakeRouter::start(RouterOptions::default()).await.unwrap();
        router.set_lifetime_override(Some(2));
        let opts = ProbeOptions {
            protos: ProtoSet {
                pmp: true,
                pcp: false,
            },
            hold: Duration::from_secs(3),
            ..ProbeOptions::default()
        };
        let (code, out) = run_probe(&router, &opts, std::future::pending()).await;
        assert_eq!(code, 0, "{out}");
        let l = kv(&out, "lease", "proto=pmp");
        assert_eq!(get(&l, "warning"), "not-longer-than-hold");
        assert_eq!(get(&l, "renew_every"), "1s");
        assert_eq!(get(&kv(&out, "renew", "n=1"), "result"), "ok");
        let renewals: u32 = get(&kv(&out, "hold", "seconds="), "renewals")
            .parse()
            .unwrap();
        assert!(renewals >= 2, "{out}");
        // Create + renewals + delete, all for the test port.
        let maps = router
            .requests()
            .iter()
            .filter(|r| r.kind == RequestKind::PmpMap)
            .count();
        assert_eq!(maps, 2 + usize::try_from(renewals).unwrap());
        assert!(router.mappings().is_empty());
        router.shutdown().await;
    }

    /// A lease longer than the hold is not renewed.
    #[tokio::test]
    async fn long_lease_is_not_renewed() {
        let router = FakeRouter::start(RouterOptions::default()).await.unwrap();
        let opts = ProbeOptions {
            protos: ProtoSet {
                pmp: true,
                pcp: false,
            },
            hold: Duration::from_secs(1),
            ..ProbeOptions::default()
        };
        let (code, out) = run_probe(&router, &opts, std::future::pending()).await;
        assert_eq!(code, 0, "{out}");
        assert!(
            !out.contains("lease proto=") && !out.contains("renew "),
            "{out}"
        );
        assert_eq!(get(&kv(&out, "hold", "seconds="), "renewals"), "0");
        router.shutdown().await;
    }

    /// A lookup that finds no gateway for its first `misses` calls.
    struct LateLookup {
        misses: std::sync::atomic::AtomicU32,
    }

    impl GatewayLookup for LateLookup {
        fn lookup(&self) -> Result<Option<Gateway>, LookupError> {
            use std::sync::atomic::Ordering;
            let left = self.misses.load(Ordering::SeqCst);
            if left == 0 {
                return Ok(Some(gateway()));
            }
            self.misses.store(left - 1, Ordering::SeqCst);
            Ok(None)
        }
    }

    /// `--portmap-wait`: the lookup is retried every second until a gateway appears or the wait
    /// ends, and the wait is reported.
    #[tokio::test]
    async fn gateway_wait_retries_until_routes_appear() {
        let late = |misses| LateLookup {
            misses: std::sync::atomic::AtomicU32::new(misses),
        };
        let mut never = std::pin::pin!(std::future::pending::<()>());
        let mut out = Vec::new();
        let g = wait_for_gateway(
            Arc::new(late(2)),
            Duration::from_secs(10),
            &mut never,
            &mut out,
        )
        .await;
        assert_eq!(g.unwrap(), gateway());
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "gateway wait=2s attempts=3\n"
        );

        let mut out = Vec::new();
        let g = wait_for_gateway(
            Arc::new(late(100)),
            Duration::from_secs(3),
            &mut never,
            &mut out,
        )
        .await;
        assert!(matches!(g, Err(Some(Ok(None)))));
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "gateway wait=3s attempts=4\n"
        );

        // No wait: one attempt, no wait line.
        let mut out = Vec::new();
        let g = wait_for_gateway(Arc::new(late(1)), Duration::ZERO, &mut never, &mut out).await;
        assert!(matches!(g, Err(Some(Ok(None)))));
        assert!(out.is_empty());

        // An interrupt ends the wait.
        let mut soon = std::pin::pin!(tokio::time::sleep(Duration::from_millis(1500)));
        let mut out = Vec::new();
        let g = wait_for_gateway(
            Arc::new(late(100)),
            Duration::from_secs(60),
            &mut soon,
            &mut out,
        )
        .await;
        assert!(matches!(g, Err(None)));
        assert!(String::from_utf8(out).unwrap().contains("interrupted=true"));
    }

    /// Partial success exits 2; a refused map skips its delete.
    #[tokio::test]
    async fn partial_and_refused() {
        let router = FakeRouter::start(RouterOptions::default()).await.unwrap();
        router.set_result(
            RequestKind::PcpMap,
            Some(ResultOverride {
                code: 2,
                lifetime: 600,
            }),
        );
        let (code, out) =
            run_probe(&router, &ProbeOptions::default(), std::future::pending()).await;
        assert_eq!(code, 2, "{out}");
        let m = kv(&out, "map", "proto=pcp");
        assert_eq!(get(&m, "result"), "not-authorized(2)");
        assert_eq!(get(&kv(&out, "delete", "proto=pcp"), "sent"), "skipped");
        router.shutdown().await;
    }

    /// A NAT-PMP error to the public-address request (the WAN is down) is not a refusal of the
    /// MAP sent alongside it: the delete runs and the committed rule is gone.
    #[tokio::test]
    async fn pmp_address_error_still_deletes() {
        let router = FakeRouter::start(RouterOptions::default()).await.unwrap();
        let opts = ProbeOptions {
            protos: ProtoSet {
                pmp: true,
                pcp: false,
            },
            ..ProbeOptions::default()
        };
        let cap = TestCap::new(gateway(), &router, PolicyHandle::new(true));
        let mut out = Vec::new();
        let b = router.barrier(RequestKind::PmpPublicAddr);
        let run = run_with(&opts, &*cap, "discovered", std::future::pending(), &mut out);
        let arm = async {
            // The probe's address request is paused; fail every later one.
            b.reached().await;
            router.set_result(
                RequestKind::PmpPublicAddr,
                Some(ResultOverride {
                    code: 3,
                    lifetime: 0,
                }),
            );
            b.release();
        };
        let (code, ()) = tokio::join!(run, arm);
        let out = String::from_utf8(out).unwrap();
        assert_eq!(code, 1, "{out}");
        assert_eq!(get(&kv(&out, "probe", ""), "pmp"), "true", "{out}");
        assert_eq!(
            get(&kv(&out, "map", "proto=pmp"), "result"),
            "network-failure(3)"
        );
        assert_eq!(get(&kv(&out, "delete", "proto=pmp"), "reply"), "ok");
        assert!(router.mappings().is_empty(), "{out}");
        router.shutdown().await;
    }

    /// A spoofed nonce-less PCP error that beats a lost real reply is not a refusal: the MAP may
    /// have committed, so the delete still runs and the rule is gone.
    #[tokio::test]
    async fn unverified_pcp_error_still_deletes() {
        let router = FakeRouter::start(RouterOptions::default()).await.unwrap();
        let mut spoof = vec![0u8; 24];
        spoof[0] = crate::pcp::VERSION;
        spoof[1] = crate::pcp::R_BIT | crate::pcp::OP_MAP;
        spoof[3] = 2;
        // Only the MAP: the probe's ANNOUNCE goes first.
        router.knobs_for(Some(RequestKind::PcpMap));
        router.spoof_before_next_reply(spoof);
        router.commit_then_drop_next(1);
        let opts = ProbeOptions {
            protos: ProtoSet {
                pmp: false,
                pcp: true,
            },
            ..ProbeOptions::default()
        };
        let (code, out) = run_probe(&router, &opts, std::future::pending()).await;
        assert_eq!(code, 1, "{out}");
        assert_eq!(
            get(&kv(&out, "map", "proto=pcp"), "result"),
            "not-authorized(2)"
        );
        assert_eq!(get(&kv(&out, "delete", "proto=pcp"), "sent"), "ok");
        assert!(router.mappings().is_empty(), "{out}");
        router.shutdown().await;
    }

    /// No responder: exit 1; the timed-out map is still followed by a delete attempt.
    #[tokio::test]
    async fn no_responder_exits_1() {
        let router = FakeRouter::start(RouterOptions {
            pmp: false,
            pcp: false,
            ..RouterOptions::default()
        })
        .await
        .unwrap();
        let (code, out) =
            run_probe(&router, &ProbeOptions::default(), std::future::pending()).await;
        assert_eq!(code, 1, "{out}");
        assert_eq!(get(&kv(&out, "probe", ""), "pmp"), "false");
        assert_eq!(get(&kv(&out, "map", "proto=pmp"), "result"), "timeout");
        assert_eq!(get(&kv(&out, "delete", "proto=pmp"), "reply"), "timeout");
        router.shutdown().await;
    }

    /// Injected EHOSTUNREACH / EPERM are printed verbatim.
    #[cfg(unix)]
    #[tokio::test]
    async fn os_errors_are_printed_verbatim() {
        for (code, name) in [(libc::EHOSTUNREACH, "EHOSTUNREACH"), (libc::EPERM, "EPERM")] {
            let router = FakeRouter::start(RouterOptions::default()).await.unwrap();
            let cap = TestCap::new(gateway(), &router, PolicyHandle::new(true));
            cap.inject_send_error(Some(code));
            let mut out = Vec::new();
            let exit = run_with(
                &ProbeOptions::default(),
                &*cap,
                "discovered",
                std::future::pending(),
                &mut out,
            )
            .await;
            let out = String::from_utf8(out).unwrap();
            assert_eq!(exit, 1);
            let err = get(&kv(&out, "probe", ""), "error").to_owned();
            assert!(err.starts_with(&format!("send: {name}: ")), "{out}");
            assert!(err.contains(&format!("os error {code}")), "{out}");
            assert_eq!(router.counters().num_total_recv, 0);
            router.shutdown().await;
        }
    }

    /// The test port never equals a node port.
    #[test]
    fn reserved_ports_are_refused() {
        for port in [41641, 41642, 50000] {
            let opts = ProbeOptions {
                test_port: port,
                node_port: 50000,
                ..ProbeOptions::default()
            };
            assert!(opts.validate().is_err(), "{port}");
        }
        assert!(
            ProbeOptions {
                test_port: 50001,
                node_port: 50000,
                ..ProbeOptions::default()
            }
            .validate()
            .is_ok()
        );
        for bad in [
            ProbeOptions {
                lifetime: 0,
                ..ProbeOptions::default()
            },
            ProbeOptions {
                lifetime: 7201,
                ..ProbeOptions::default()
            },
            ProbeOptions {
                hold: Duration::from_secs(601),
                lifetime: 7200,
                ..ProbeOptions::default()
            },
            ProbeOptions {
                hold: Duration::from_secs(120),
                ..ProbeOptions::default()
            },
            ProbeOptions {
                wait: Duration::from_secs(121),
                ..ProbeOptions::default()
            },
            ProbeOptions {
                protos: ProtoSet {
                    pmp: false,
                    pcp: false,
                },
                ..ProbeOptions::default()
            },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
    }

    /// A reserved test port is refused before any socket or packet.
    #[tokio::test]
    async fn reserved_port_refused_before_io() {
        let router = FakeRouter::start(RouterOptions::default()).await.unwrap();
        let opts = ProbeOptions {
            test_port: 41641,
            ..ProbeOptions::default()
        };
        let (code, out) = run_probe(&router, &opts, std::future::pending()).await;
        assert_eq!(code, 1);
        assert!(out.contains("error msg="), "{out}");
        assert_eq!(router.counters().num_total_recv, 0);
        router.shutdown().await;
    }

    #[test]
    fn values_are_quoted_when_needed() {
        assert_eq!(v("ok"), "ok");
        assert_eq!(v(""), "-");
        assert_eq!(v("a b"), "\"a b\"");
        assert_eq!(v("k=v"), "\"k=v\"");
        assert!(env_line().starts_with("env os="));
    }
}
