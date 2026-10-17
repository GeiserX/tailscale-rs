//! Test isolation for the NAT port mapper: no test may ask the real LAN gateway for a mapping.
//!
//! WHY: the port mapper is on by default (Go parity), so a test that builds a real device or runtime
//! would look up the host's default route and send NAT-PMP/PCP to the real router, creating real
//! mappings. The runtime's own unit tests are guarded in code: every `ForwarderConfig` names its
//! `port_mapper` field (the shared test configurations set `None`), and in that crate's test build
//! the production client's gateway lookup is a stub that panics (`ts_runtime/src/portmap.rs`,
//! `shared_test_config_never_builds_a_client`). This check guards what code cannot:
//!
//! 1. **Integration tests that build devices** (`tests/*.rs` calling `Device::new` or
//!    `Server::new`) must turn the mapper off with `TS_DISABLE_PORTMAPPER` (the env knob covers
//!    every device the process builds, the facade server included).
//! 2. **Runtime sources** may enable the mapper (`port_mapper: Some(`) only in the production
//!    conversion (`env.rs`) and the driver's own tests (`portmap.rs`), where a harness is injected
//!    or the stub lookup is in place.
//! 3. **The stub stays**: `portmap.rs` keeps the `cfg(test)` lookup stub.
//!
//! Like any text scan it is a tripwire, not a proof.

use crate::{Args, BoxResult};

/// What a device-building integration test must contain.
const ENV_KNOB: &str = "TS_DISABLE_PORTMAPPER";
/// Calls that build a device.
const DEVICE_BUILDERS: &[&str] = &["Device::new(", "Server::new("];
/// Runtime files allowed to enable the mapper.
const ENABLE_ALLOWED: &[&str] = &["env.rs", "portmap.rs"];

pub fn run(_args: &Args) -> BoxResult<()> {
    let mut problems = Vec::new();

    for entry in globwalk::GlobWalkerBuilder::from_patterns("tests", &["*.rs"]).build()? {
        let entry = entry?;
        let contents = std::fs::read_to_string(entry.path())?;
        problems.extend(integration_test_problems(
            &entry.path().display().to_string(),
            &contents,
        ));
    }

    for entry in
        globwalk::GlobWalkerBuilder::from_patterns("ts_runtime/src", &["**/*.rs"]).build()?
    {
        let entry = entry?;
        let path = entry.path();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let contents = std::fs::read_to_string(path)?;
        problems.extend(runtime_problems(&name, &contents));
    }

    let portmap = std::fs::read_to_string("ts_runtime/src/portmap.rs")?;
    problems.extend(stub_problems(&portmap));

    if problems.is_empty() {
        return Ok(());
    }
    eprintln!("a test could reach the real LAN gateway through the port mapper:");
    for p in &problems {
        eprintln!("  {p}");
    }
    Err("port mapper test isolation violated".into())
}

/// An integration test file that builds a device must set the env knob.
fn integration_test_problems(path: &str, contents: &str) -> Vec<String> {
    let builds = DEVICE_BUILDERS.iter().any(|b| contents.contains(b));
    if builds && !contents.contains(ENV_KNOB) {
        vec![format!(
            "{path}: builds a device but never sets {ENV_KNOB}; set it (and `disable_port_mapper`) \
             before the first device"
        )]
    } else {
        Vec::new()
    }
}

/// A runtime source file other than the allowed ones must not enable the mapper.
fn runtime_problems(name: &str, contents: &str) -> Vec<String> {
    if ENABLE_ALLOWED.contains(&name) {
        return Vec::new();
    }
    contents
        .lines()
        .enumerate()
        .filter(|(_, l)| l.replace(' ', "").contains("port_mapper:Some("))
        .map(|(i, _)| {
            format!(
                "ts_runtime/src/{name}:{}: enables the port mapper; tests must use `port_mapper: \
                 None` or inject a harness in portmap.rs",
                i + 1
            )
        })
        .collect()
}

/// The `cfg(test)` lookup stub must stay in place.
fn stub_problems(portmap: &str) -> Vec<String> {
    if portmap.contains("cfg.lookup = Arc::new(tests::NeverLookup)") && portmap.contains("panic!(")
    {
        Vec::new()
    } else {
        vec![
            "ts_runtime/src/portmap.rs: the cfg(test) gateway-lookup stub (NeverLookup) is gone"
                .to_owned(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_builders_need_the_env_knob() {
        let bad = "async fn t() { Device::new(&Config::default(), None).await; }";
        assert_eq!(integration_test_problems("tests/x.rs", bad).len(), 1);
        let bad = "let mut srv = Server::new();";
        assert_eq!(integration_test_problems("tests/x.rs", bad).len(), 1);
        let ok = "unsafe { std::env::set_var(\"TS_DISABLE_PORTMAPPER\", \"1\") }; Device::new(&c)";
        assert!(integration_test_problems("tests/x.rs", ok).is_empty());
        assert!(integration_test_problems("tests/x.rs", "fn no_device() {}").is_empty());
    }

    #[test]
    fn only_allowed_runtime_files_enable_the_mapper() {
        let src = "let f = ForwarderConfig {\n    port_mapper: Some(settings),\n};";
        assert_eq!(runtime_problems("netmon.rs", src).len(), 1);
        assert_eq!(
            runtime_problems("netmon.rs", "port_mapper :  Some( x )").len(),
            1
        );
        assert!(runtime_problems("portmap.rs", src).is_empty());
        assert!(runtime_problems("netmon.rs", "port_mapper: None,").is_empty());
    }

    #[test]
    fn the_stub_must_stay() {
        assert_eq!(stub_problems("fn system_client() {}").len(), 1);
        let ok = "cfg.lookup = Arc::new(tests::NeverLookup); panic!(\"x\")";
        assert!(stub_problems(ok).is_empty());
    }
}
