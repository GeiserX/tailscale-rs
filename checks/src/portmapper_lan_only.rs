//! Leak firewall: the NAT port mapper (`ts_portmapper`) stays a LAN-only control path.
//!
//! WHY: the port mapper sends UDP to the LAN gateway's NAT-PMP/PCP port and nothing else. The real
//! boundary is the type system and runtime tests: `GatewayCap` (in `ts_portmapper/src/cap.rs`) is
//! the only code that creates sockets, its API takes a `LanDest` rather than an address, and the
//! test transport exists only behind `cfg(test)` / the `test-harness` feature. This check guards
//! the parts of that boundary a compiler cannot:
//!
//! 1. **Dependency graph** (`cargo metadata`): `ts_portmapper`'s normal and build dependency
//!    closure contains no TLS or HTTP-client crate, and `ts_control` does not depend on
//!    `ts_portmapper` at all (control only ever sees transport-neutral facets).
//! 2. **Feature graph**: no workspace crate enables `ts_portmapper/test-harness` through a normal
//!    or build dependency or one of its own features (dev-dependencies may), and the feature is
//!    not on by default.
//! 3. **Tripwire scan**: outside `cap.rs` and `testing/`, no line of `ts_portmapper/src` may
//!    mention a socket type, a socket syscall, a send/connect/write call on a raw fd, a raw-fd
//!    wrapper, the `nix` crate, a child process, or an IPv6 wildcard. The
//!    kernel source-selection lookup in the gateway module (a `connect()`ed UDP socket that never
//!    sends) is allow-listed by function name.
//!
//! The scan is a tripwire, not a proof: it matches text, so a determined author can evade it (a
//! macro, an alias built from a re-export elsewhere). It exists to make an accidental second
//! socket path loud, with adversarial fixtures for the obvious evasions (an aliased import, a
//! qualified path) below.

use std::collections::{BTreeSet, HashMap};

use crate::{Args, BoxResult};

/// The port mapper's package name.
const PORTMAPPER: &str = "geiserx_ts_portmapper";
/// The control client's package name.
const CONTROL: &str = "geiserx_ts_control";
/// The harness feature only dev-dependencies may enable.
const HARNESS_FEATURE: &str = "test-harness";

/// Crates (or crate-name prefixes ending in `*`) that mean TLS or an HTTP client.
const FORBIDDEN_DEPS: &[&str] = &[
    "rustls*",
    "tokio-rustls",
    "webpki*",
    "native-tls",
    "openssl*",
    "aws-lc*",
    "ring",
    "hyper",
    "hyper-util",
    "h2",
    "http",
    "httparse",
    "reqwest",
    "ureq",
    "isahc",
    "curl",
    "geiserx_ts_http_util",
    "geiserx_ts_tls_util",
];

/// The tree the tripwire scans.
const SCAN_ROOT: &str = "ts_portmapper/src";

/// Paths under [`SCAN_ROOT`] that may create sockets.
const SOCKET_MODULES: &[&str] = &["cap.rs", "testing/"];

/// `(file, function)` pairs allowed to match a pattern: the kernel source-selection lookup, and
/// the macOS test that cross-checks the routing-table parser against `netstat -rn` (a local exec,
/// no network traffic).
const ALLOWED_FNS: &[(&str, &str)] = &[
    ("gateway/mod.rs", "kernel_source"),
    ("gateway/darwin.rs", "agrees_with_netstat"),
];

/// Text that means "a socket or a send" outside the capability.
const PATTERNS: &[&str] = &[
    "UdpSocket",
    "TcpStream",
    "TcpSocket",
    "TcpListener",
    "socket2",
    "tokio::net",
    "mio::",
    "libc::socket",
    "libc::sendto",
    "libc::sendmsg",
    "libc::connect",
    "send_to(",
    "sendto(",
    "connect(",
    // A raw fd written to directly, or one wrapped from elsewhere.
    "libc::send(",
    "libc::write(",
    "from_raw_fd",
    "FromRawFd",
    "nix::",
    // A child process (natpmpc, route, curl, pfctl) is another egress or a host mutation.
    "Command::new",
    "process::Command",
    "Ipv6Addr::UNSPECIFIED",
    // A string literal that starts with the IPv6 wildcard, bracketed or not.
    "\"[::]",
    "\"::",
];

pub fn run(_args: &Args) -> BoxResult<()> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let out = std::process::Command::new(cargo)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--all-features",
        ])
        .output()?;
    if !out.status.success() {
        return Err(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    let metadata: serde_json::Value = serde_json::from_slice(&out.stdout)?;

    let mut problems = graph_problems(&metadata)?;
    problems.extend(feature_problems(&metadata));

    let glob = globwalk::GlobWalkerBuilder::from_patterns(SCAN_ROOT, &["**/*.rs"]).build()?;
    for entry in glob {
        let entry = entry?;
        let path = entry.path();
        let rel = path
            .strip_prefix(SCAN_ROOT)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        let contents = std::fs::read_to_string(path)?;
        problems.extend(scan_file(&rel, &contents));
    }

    if problems.is_empty() {
        return Ok(());
    }
    eprintln!("the port mapper's LAN-only boundary is broken:");
    for p in &problems {
        eprintln!("  {p}");
    }
    eprintln!(
        "Every LAN socket and send must go through GatewayCap (ts_portmapper/src/cap.rs); the \
         port mapper must not pull in TLS/HTTP clients, ts_control must not depend on it, and \
         only dev-dependencies may enable its test harness. STOP."
    );
    Err("port mapper LAN-only invariant violated".into())
}

fn forbidden_dep(name: &str) -> bool {
    FORBIDDEN_DEPS.iter().any(|f| match f.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => name == *f,
    })
}

/// Package names by id.
type Names = HashMap<String, String>;
/// The resolve graph: `id -> [(dep id, dependency kinds)]`.
type Edges = HashMap<String, Vec<(String, Vec<String>)>>;

/// Package names by id, and the resolve graph.
fn graph(metadata: &serde_json::Value) -> BoxResult<(Names, Edges)> {
    let mut names = HashMap::new();
    for p in metadata["packages"]
        .as_array()
        .ok_or("metadata: no packages")?
    {
        if let (Some(id), Some(name)) = (p["id"].as_str(), p["name"].as_str()) {
            names.insert(id.to_owned(), name.to_owned());
        }
    }
    let mut edges = HashMap::new();
    for n in metadata["resolve"]["nodes"]
        .as_array()
        .ok_or("metadata: no resolve graph")?
    {
        let id = n["id"].as_str().unwrap_or_default().to_owned();
        let deps = n["deps"]
            .as_array()
            .map(|ds| {
                ds.iter()
                    .map(|d| {
                        let kinds = d["dep_kinds"]
                            .as_array()
                            .map(|ks| {
                                ks.iter()
                                    .map(|k| k["kind"].as_str().unwrap_or("normal").to_owned())
                                    .collect()
                            })
                            .unwrap_or_default();
                        (d["pkg"].as_str().unwrap_or_default().to_owned(), kinds)
                    })
                    .collect()
            })
            .unwrap_or_default();
        edges.insert(id, deps);
    }
    Ok((names, edges))
}

/// Every package reachable from `start` through edges of the given kinds.
fn closure(edges: &Edges, start: &str, kinds: &[&str]) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut stack = vec![start.to_owned()];
    while let Some(id) = stack.pop() {
        for (dep, dep_kinds) in edges.get(&id).into_iter().flatten() {
            if dep_kinds.iter().any(|k| kinds.contains(&k.as_str())) && seen.insert(dep.clone()) {
                stack.push(dep.clone());
            }
        }
    }
    seen
}

/// Invariant 1: the port mapper's closure has no TLS/HTTP crate, and control does not reach it.
fn graph_problems(metadata: &serde_json::Value) -> BoxResult<Vec<String>> {
    let (names, edges) = graph(metadata)?;
    let id_of = |name: &str| {
        names
            .iter()
            .find(|(_, n)| n.as_str() == name)
            .map(|(id, _)| id.clone())
    };
    let mut problems = Vec::new();
    let pm = id_of(PORTMAPPER).ok_or("metadata: no ts_portmapper package")?;
    for dep in closure(&edges, &pm, &["normal", "build"]) {
        let name = names.get(&dep).map_or(dep.as_str(), String::as_str);
        if forbidden_dep(name) {
            problems.push(format!("{PORTMAPPER} depends on {name} (TLS/HTTP)"));
        }
    }
    if let Some(control) = id_of(CONTROL) {
        // Control's own dependencies of every kind, then what those really pull in (normal and
        // build edges; a dependency's dev-dependencies are never built for control).
        let mut reach = BTreeSet::new();
        for (dep, _) in edges.get(&control).into_iter().flatten() {
            reach.insert(dep.clone());
            reach.extend(closure(&edges, dep, &["normal", "build"]));
        }
        if reach.contains(&pm) {
            problems.push(format!("{CONTROL} depends on {PORTMAPPER}"));
        }
    }
    Ok(problems)
}

/// Invariant 2: only dev-dependencies enable the harness feature.
fn feature_problems(metadata: &serde_json::Value) -> Vec<String> {
    let mut problems = Vec::new();
    let members: BTreeSet<&str> = metadata["workspace_members"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|m| m.as_str())
        .collect();
    for p in metadata["packages"].as_array().into_iter().flatten() {
        let Some(id) = p["id"].as_str() else { continue };
        if !members.contains(id) {
            continue;
        }
        let name = p["name"].as_str().unwrap_or_default();
        if name == PORTMAPPER {
            let default = &p["features"]["default"];
            if default
                .as_array()
                .is_some_and(|d| d.iter().any(|f| f.as_str() == Some(HARNESS_FEATURE)))
            {
                problems.push(format!(
                    "{PORTMAPPER}'s default features enable {HARNESS_FEATURE}"
                ));
            }
            continue;
        }
        let mut aliases = vec!["ts_portmapper".to_owned(), PORTMAPPER.to_owned()];
        for d in p["dependencies"].as_array().into_iter().flatten() {
            if d["name"].as_str() != Some(PORTMAPPER) {
                continue;
            }
            if let Some(r) = d["rename"].as_str() {
                aliases.push(r.to_owned());
            }
            let dev = d["kind"].as_str() == Some("dev");
            let harness = d["features"]
                .as_array()
                .is_some_and(|fs| fs.iter().any(|f| f.as_str() == Some(HARNESS_FEATURE)));
            if harness && !dev {
                problems.push(format!(
                    "{name} enables {PORTMAPPER}/{HARNESS_FEATURE} on a non-dev dependency"
                ));
            }
        }
        if let Some(features) = p["features"].as_object() {
            for (feature, enables) in features {
                for e in enables
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|e| e.as_str())
                {
                    let hit = aliases.iter().any(|a| {
                        e == format!("{a}/{HARNESS_FEATURE}")
                            || e == format!("{a}?/{HARNESS_FEATURE}")
                    });
                    if hit {
                        problems.push(format!(
                            "{name}'s feature `{feature}` enables {PORTMAPPER}/{HARNESS_FEATURE}"
                        ));
                    }
                }
            }
        }
    }
    problems
}

/// `line` without its `//` comment (a `//` inside a string literal is kept).
fn strip_comment(line: &str) -> &str {
    let mut in_str = false;
    let mut escaped = false;
    let bytes = line.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if in_str {
            match b {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => in_str = false,
                _ => {}
            }
        } else if b == b'"' {
            in_str = true;
        } else if b == b'/' && bytes.get(i + 1) == Some(&b'/') {
            return &line[..i];
        }
    }
    line
}

/// The function a line belongs to, tracked by the last `fn name(` seen.
fn fn_name(line: &str) -> Option<&str> {
    let after = line.split("fn ").nth(1)?;
    let end = after.find(|c: char| !(c.is_alphanumeric() || c == '_'))?;
    (end > 0).then(|| &after[..end])
}

/// Whether `code` contains `pattern` starting at a word boundary (so `nix::` does not match inside
/// `std::os::unix::process`, nor `connect(` inside `disconnect(`).
fn contains_at_boundary(code: &str, pattern: &str) -> bool {
    code.match_indices(pattern).any(|(i, _)| {
        !code[..i]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_alphanumeric() || c == '_')
    })
}

/// Invariant 3: the tripwire over one file, `rel` relative to [`SCAN_ROOT`].
fn scan_file(rel: &str, contents: &str) -> Vec<String> {
    if SOCKET_MODULES.iter().any(|m| match m.strip_suffix('/') {
        Some(dir) => rel.starts_with(&format!("{dir}/")),
        None => rel == *m,
    }) {
        return Vec::new();
    }
    let mut hits = Vec::new();
    let mut current_fn: Option<String> = None;
    for (i, raw) in contents.lines().enumerate() {
        let code = strip_comment(raw);
        if let Some(f) = fn_name(code) {
            current_fn = Some(f.to_owned());
        }
        let Some(pattern) = PATTERNS.iter().find(|p| contains_at_boundary(code, p)) else {
            continue;
        };
        let allowed = ALLOWED_FNS
            .iter()
            .any(|(file, f)| *file == rel && current_fn.as_deref() == Some(*f));
        if !allowed {
            hits.push(format!(
                "{SCAN_ROOT}/{rel}:{}: `{pattern}` outside GatewayCap: {}",
                i + 1,
                raw.trim()
            ));
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The adversarial fixtures: an aliased import and a qualified path are both caught.
    #[test]
    fn evasions_are_flagged() {
        for line in [
            "use std::net::UdpSocket as Sock;",
            "let s = ::std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;",
            "use tokio::net::{UdpSocket as U};",
            // The aliased import is the line that is caught; later uses of the alias are not.
            "use socket2 as s2;",
            "unsafe { libc::sendto(fd, p, n, 0, sa, l) };",
            "sock.send_to(&pkt, dst).await?;",
            "s.connect(dst)?;",
            "let a = Ipv6Addr::UNSPECIFIED;",
            r#"let any = "[::]:0";"#,
            r#"let any: SocketAddr = "[::]".parse()?;"#,
            r#"let any = ("::", 0);"#,
            "unsafe { libc::send(fd, p, n, 0) };",
            "unsafe { libc::write(fd, p, n) };",
            "let s = unsafe { std::net::UdpSocket::from_raw_fd(fd) };",
            "use std::os::fd::FromRawFd;",
            "use nix::sys::socket;",
            "std::process::Command::new(\"natpmpc\").arg(\"-a\").status()?;",
            "let c = Command::new(\"route\");",
            "use std::process::Command as Cmd;",
        ] {
            let src = format!("fn sneaky() {{\n    {line}\n}}\n");
            assert_eq!(
                scan_file("oneshot.rs", &src).len(),
                1,
                "not flagged: {line}"
            );
        }
    }

    #[test]
    fn comments_strings_and_allowed_places_are_not_flagged() {
        let src = "/// Sends through a `UdpSocket` in GatewayCap.\n\
                   // connect( is fine in a comment\n\
                   let url = \"http://x\"; // UdpSocket\n";
        assert!(scan_file("oneshot.rs", src).is_empty());
        let sock = "fn exchange() {\n    let s = UdpSocket::bind(a)?;\n    s.send_to(b, c)?;\n}\n";
        assert!(scan_file("cap.rs", sock).is_empty());
        assert!(scan_file("testing/router.rs", sock).is_empty());
        let ks = "fn kernel_source(dst: Ipv4Addr) {\n    let s = std::net::UdpSocket::bind(x).ok()?;\n    s.connect(y).ok()?;\n}\n";
        assert!(scan_file("gateway/mod.rs", ks).is_empty());
        // The same function name elsewhere is not allowed, nor another function in that file.
        assert_eq!(scan_file("gateway/darwin.rs", ks).len(), 2);
        let other = ks.replace("kernel_source", "helper");
        assert_eq!(scan_file("gateway/mod.rs", &other).len(), 2);
        // A file named like an allowed directory is still scanned.
        assert_eq!(scan_file("testing.rs", sock).len(), 2);
    }

    /// Patterns match at a word boundary only.
    #[test]
    fn patterns_match_at_word_boundaries() {
        for line in [
            "let ppid = std::os::unix::process::parent_id();",
            "peer.disconnect();",
            "let w = rewrite(x);",
        ] {
            let src = format!("fn fine() {{\n    {line}\n}}\n");
            assert!(
                scan_file("probe_tool.rs", &src).is_empty(),
                "flagged: {line}"
            );
        }
        for line in [
            "use ::nix::sys::socket;",
            "let x = (nix::unistd::getpid(),);",
        ] {
            let src = format!("fn sneaky() {{\n    {line}\n}}\n");
            assert_eq!(scan_file("probe_tool.rs", &src).len(), 1, "{line}");
        }
    }

    #[test]
    fn comment_stripping_respects_strings() {
        assert_eq!(
            strip_comment(r#"let a = "//"; b // c"#),
            r#"let a = "//"; b "#
        );
        assert_eq!(
            strip_comment(r#"let a = "\"//"; b"#),
            r#"let a = "\"//"; b"#
        );
        assert_eq!(strip_comment("/// doc"), "");
    }

    fn metadata(extra_pm_dep: Option<&str>, control_dep: bool, harness: &str) -> serde_json::Value {
        let mut pm_deps = vec![serde_json::json!({
            "pkg": "tokio-id", "dep_kinds": [{"kind": null}]
        })];
        if let Some(d) = extra_pm_dep {
            pm_deps
                .push(serde_json::json!({"pkg": format!("{d}-id"), "dep_kinds": [{"kind": null}]}));
        }
        let mut control_deps = vec![];
        if control_dep {
            control_deps.push(serde_json::json!({"pkg": "pm-id", "dep_kinds": [{"kind": "dev"}]}));
        }
        let mut packages = vec![
            serde_json::json!({"id": "pm-id", "name": PORTMAPPER, "features": {"test-harness": []}, "dependencies": []}),
            serde_json::json!({"id": "tokio-id", "name": "tokio", "features": {}, "dependencies": []}),
            serde_json::json!({"id": "control-id", "name": CONTROL, "features": {}, "dependencies": []}),
            serde_json::json!({
                "id": "rt-id", "name": "geiserx_ts_runtime",
                "features": {"portmapper": ["dep:ts_portmapper"], "x": [harness]},
                "dependencies": [{"name": PORTMAPPER, "rename": "ts_portmapper", "kind": null, "features": []}]
            }),
        ];
        if let Some(d) = extra_pm_dep {
            packages.push(serde_json::json!({"id": format!("{d}-id"), "name": d, "features": {}, "dependencies": []}));
        }
        serde_json::json!({
            "packages": packages,
            "workspace_members": ["pm-id", "control-id", "rt-id"],
            "resolve": {"nodes": [
                {"id": "pm-id", "deps": pm_deps},
                {"id": "control-id", "deps": control_deps},
                {"id": "rt-id", "deps": [{"pkg": "pm-id", "dep_kinds": [{"kind": null}]}]},
            ]}
        })
    }

    #[test]
    fn graph_rules() {
        assert!(
            graph_problems(&metadata(None, false, ""))
                .unwrap()
                .is_empty()
        );
        for bad in [
            "rustls",
            "hyper",
            "reqwest",
            "aws-lc-sys",
            "geiserx_ts_http_util",
        ] {
            assert_eq!(
                graph_problems(&metadata(Some(bad), false, ""))
                    .unwrap()
                    .len(),
                1,
                "{bad}"
            );
        }
        assert_eq!(graph_problems(&metadata(None, true, "")).unwrap().len(), 1);
    }

    #[test]
    fn feature_rules() {
        assert!(feature_problems(&metadata(None, false, "")).is_empty());
        assert_eq!(
            feature_problems(&metadata(None, false, "ts_portmapper/test-harness")).len(),
            1
        );
        assert_eq!(
            feature_problems(&metadata(None, false, "ts_portmapper?/test-harness")).len(),
            1
        );
        let mut m = metadata(None, false, "");
        m["packages"][3]["dependencies"][0]["features"] = serde_json::json!(["test-harness"]);
        assert_eq!(feature_problems(&m).len(), 1);
        m["packages"][3]["dependencies"][0]["kind"] = serde_json::json!("dev");
        assert!(feature_problems(&m).is_empty());
        let mut d = metadata(None, false, "");
        d["packages"][0]["features"]["default"] = serde_json::json!(["test-harness"]);
        assert_eq!(feature_problems(&d).len(), 1);
    }
}
