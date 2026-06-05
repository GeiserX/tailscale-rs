//! Leak firewall: the optional `ssh` feature (russh → aws-lc-rs) must stay opt-in and isolated.
//!
//! WHY: the fork's core tailnet/egress path is deliberately **musl-clean and `ring`-only** — it
//! must NEVER pull in `aws-lc-rs` (nor `openssl`/native-TLS) on the default build graph. The
//! optional `ssh` Cargo feature brings in `russh`, which itself drags in `aws-lc-rs`. That
//! feature is intentionally OFF by default and meant to be isolated in a separate, non-musl
//! binary. If `russh`/`aws-lc-rs` ever entered the default graph it would contaminate every
//! build — including the exit-node egress path whose whole point is to stay `ring`-only and
//! cross-compile cleanly to musl. This check guards that invariant so it can't silently regress.
//!
//! WHAT THIS CHECKS: it reads the root `Cargo.toml` and asserts, by line-by-line string scanning
//! (no TOML parser dependency — same spirit as the other leak-firewall checks):
//!   1. `russh` is declared `optional = true` — so it never enters the default graph implicitly.
//!   2. The `default` feature list does NOT contain `"ssh"` — enabling `ssh` by default would
//!      pull `russh`/`aws-lc-rs` into every build. (An absent/empty `default` is fine.)
//!   3. The `ssh` feature gates russh behind `dep:russh` — russh is only ever enabled via the
//!      explicit feature, never as an implicit optional-dependency feature.
//!   4. There is no standalone `aws-lc-rs`/`aws_lc_rs` dependency *declaration* in the root
//!      manifest's `[dependencies]`/`[workspace.dependencies]`. It is acceptable that the
//!      optional `russh` dependency's own `features = [...]` mentions `"aws-lc-rs"` — that is a
//!      string inside russh's feature list and only takes effect when the opt-in `ssh` feature
//!      is enabled. Only a top-level `aws-lc-rs = ...` / `aws_lc_rs = ...` key is forbidden.
//!
//! Any violation surfaces a descriptive message and fails closed — keeping the egress path
//! musl-clean and ring-only, with the `ssh` feature opt-in and isolated.

use crate::{Args, BoxResult};

/// Path (relative to repo root) of the manifest this check guards.
const MANIFEST: &str = "Cargo.toml";

pub fn run(_args: &Args) -> BoxResult<()> {
    let contents = std::fs::read_to_string(MANIFEST)?;
    let violations = check_manifest(&contents);

    if !violations.is_empty() {
        eprintln!("ssh-feature isolation violated in {MANIFEST}:");
        for v in &violations {
            eprintln!("  {v}");
        }
        eprintln!(
            "The core tailnet/egress path must stay musl-clean and ring-only: russh (which drags \
             in aws-lc-rs) must remain an OFF-by-default, dep:russh-gated `ssh` feature isolated \
             in a separate non-musl binary, and aws-lc-rs must never be a direct dependency. If \
             this is intentional, the ring-only egress invariant is being broken — STOP."
        );
        return Err("ssh feature isolation invariant violated in root Cargo.toml".into());
    }

    Ok(())
}

/// Run all manifest invariants against the given `Cargo.toml` contents, returning a list of
/// human-readable violation messages (empty if all invariants hold).
fn check_manifest(contents: &str) -> Vec<String> {
    let mut violations: Vec<String> = Vec::new();

    if let Some(msg) = check_russh_optional(contents) {
        violations.push(msg);
    }
    if let Some(msg) = check_default_excludes_ssh(contents) {
        violations.push(msg);
    }
    if let Some(msg) = check_ssh_gates_russh(contents) {
        violations.push(msg);
    }
    if let Some(msg) = check_no_standalone_aws_lc(contents) {
        violations.push(msg);
    }

    violations
}

/// Invariant 1: if a `russh = { ... }` dependency line exists, it must contain `optional = true`.
/// A non-optional russh would enter the default build graph and drag in `aws-lc-rs`.
fn check_russh_optional(contents: &str) -> Option<String> {
    let russh_line = contents
        .lines()
        .map(str::trim)
        .find(|line| is_dependency_key(line, "russh"))?;

    if russh_line.contains("optional = true") {
        None
    } else {
        Some(format!(
            "russh is declared but not `optional = true` (`{russh_line}`); a non-optional russh \
             enters the default graph and pulls in aws-lc-rs"
        ))
    }
}

/// Invariant 2: the `default = [ ... ]` feature list must not contain the `"ssh"` token. The list
/// may be single-line or span multiple lines; an absent default is fine (no violation).
fn check_default_excludes_ssh(contents: &str) -> Option<String> {
    let default = collect_feature_array(contents, "default")?;
    if default.contains("\"ssh\"") {
        Some(
            "the `default` feature list contains \"ssh\"; enabling ssh by default pulls \
             russh/aws-lc-rs into every build"
                .to_string(),
        )
    } else {
        None
    }
}

/// Invariant 3: the `ssh = [ ... ]` feature list must gate russh behind `dep:russh`, confirming
/// russh is only enabled via the explicit feature.
fn check_ssh_gates_russh(contents: &str) -> Option<String> {
    let ssh = collect_feature_array(contents, "ssh")?;
    if ssh.contains("dep:russh") {
        None
    } else {
        Some(format!(
            "the `ssh` feature does not gate russh behind `dep:russh` (`{}`); russh must only be \
             enabled via the explicit ssh feature",
            ssh.trim()
        ))
    }
}

/// Invariant 4: no standalone `aws-lc-rs`/`aws_lc_rs` dependency *declaration* may exist. A mention
/// of `"aws-lc-rs"` inside russh's own `features = [...]` is acceptable (russh is optional); only a
/// top-level `aws-lc-rs = ...` / `aws_lc_rs = ...` key is forbidden.
fn check_no_standalone_aws_lc(contents: &str) -> Option<String> {
    let hit = contents.lines().map(str::trim).find(|line| {
        is_dependency_key(line, "aws-lc-rs") || is_dependency_key(line, "aws_lc_rs")
    })?;
    Some(format!(
        "found a standalone aws-lc-rs dependency declaration (`{hit}`); aws-lc-rs must never be a \
         direct dependency — it may only appear transitively via the optional russh feature"
    ))
}

/// True if `line` (already trimmed) declares a dependency keyed exactly by `name`, i.e. it starts
/// with `name` followed (after optional whitespace) by `=`. This avoids matching the same name
/// appearing as a substring inside another dependency's `features = [...]` list.
fn is_dependency_key(line: &str, name: &str) -> bool {
    match line.strip_prefix(name) {
        Some(rest) => rest.trim_start().starts_with('='),
        None => false,
    }
}

/// Collect the contents of a `<name> = [ ... ]` feature array as a single string, handling both
/// the single-line form (`name = ["a", "b"]`) and the multi-line form (`name = [` … `]`). Returns
/// `None` if no such feature key is found. Scanning is line-based and only matches a trimmed line
/// that begins with the feature key (so it won't match the name nested inside another array).
fn collect_feature_array(contents: &str, name: &str) -> Option<String> {
    let mut lines = contents.lines();

    // Find the line that opens this feature array.
    let opening = lines
        .by_ref()
        .map(str::trim)
        .find(|line| is_dependency_key(line, name) && line.contains('['))?;

    // Take everything from the first '[' onward on the opening line.
    let after_bracket = &opening[opening.find('[').unwrap()..];

    // Single-line form: the closing ']' is on the same line.
    if let Some(end) = after_bracket.find(']') {
        return Some(after_bracket[..=end].to_string());
    }

    // Multi-line form: accumulate subsequent lines until we hit the closing ']'.
    let mut collected = String::from(after_bracket);
    for line in lines {
        collected.push('\n');
        collected.push_str(line);
        if line.contains(']') {
            break;
        }
    }
    Some(collected)
}

#[cfg(test)]
mod tests {
    use super::check_manifest;

    /// A manifest matching the real repo state: russh optional, no `default` listing ssh, the ssh
    /// feature gates `dep:russh`, and no standalone aws-lc-rs. Must pass with zero violations.
    const GOOD: &str = r#"
[dependencies]
russh = { version = "0.60", optional = true, default-features = false, features = ["flate2", "aws-lc-rs"] }
bytes = { workspace = true, optional = true }

[features]
axum = ["dep:axum"]
ssh = ["dep:russh", "dep:bytes", "dep:ratatui"]
tun = ["ts_runtime/tun"]
"#;

    #[test]
    fn good_manifest_passes() {
        let v = check_manifest(GOOD);
        assert!(v.is_empty(), "expected no violations, got: {v:?}");
    }

    #[test]
    fn good_manifest_with_explicit_default_passes() {
        let manifest = r#"
[dependencies]
russh = { version = "0.60", optional = true, features = ["aws-lc-rs"] }

[features]
default = ["tun"]
ssh = ["dep:russh"]
tun = ["ts_runtime/tun"]
"#;
        assert!(check_manifest(manifest).is_empty());
    }

    #[test]
    fn good_manifest_with_multiline_default_passes() {
        let manifest = r#"
[dependencies]
russh = { version = "0.60", optional = true, features = ["aws-lc-rs"] }

[features]
default = [
    "tun",
    "axum",
]
ssh = ["dep:russh"]
"#;
        assert!(check_manifest(manifest).is_empty());
    }

    #[test]
    fn bad_ssh_in_default_fails() {
        let manifest = r#"
[dependencies]
russh = { version = "0.60", optional = true, features = ["aws-lc-rs"] }

[features]
default = ["tun", "ssh"]
ssh = ["dep:russh"]
"#;
        let v = check_manifest(manifest);
        assert!(
            v.iter().any(|m| m.contains("default") && m.contains("ssh")),
            "expected a default-contains-ssh violation, got: {v:?}"
        );
    }

    #[test]
    fn bad_ssh_in_multiline_default_fails() {
        let manifest = r#"
[features]
default = [
    "tun",
    "ssh",
]
ssh = ["dep:russh"]
"#;
        let v = check_manifest(manifest);
        assert!(
            v.iter().any(|m| m.contains("default") && m.contains("ssh")),
            "expected a multiline default-contains-ssh violation, got: {v:?}"
        );
    }

    #[test]
    fn bad_russh_not_optional_fails() {
        let manifest = r#"
[dependencies]
russh = { version = "0.60", default-features = false, features = ["aws-lc-rs"] }

[features]
ssh = ["dep:russh"]
"#;
        let v = check_manifest(manifest);
        assert!(
            v.iter()
                .any(|m| m.contains("russh") && m.contains("optional")),
            "expected a russh-not-optional violation, got: {v:?}"
        );
    }

    #[test]
    fn bad_standalone_aws_lc_dependency_fails() {
        let manifest = r#"
[dependencies]
aws-lc-rs = "1.0"
russh = { version = "0.60", optional = true, features = ["aws-lc-rs"] }

[features]
ssh = ["dep:russh"]
"#;
        let v = check_manifest(manifest);
        assert!(
            v.iter()
                .any(|m| m.contains("aws-lc-rs") && m.contains("standalone")),
            "expected a standalone-aws-lc-rs violation, got: {v:?}"
        );
    }

    #[test]
    fn bad_standalone_aws_lc_underscore_dependency_fails() {
        let manifest = r#"
[dependencies]
aws_lc_rs = "1.0"
russh = { version = "0.60", optional = true, features = ["aws-lc-rs"] }

[features]
ssh = ["dep:russh"]
"#;
        let v = check_manifest(manifest);
        assert!(
            !v.is_empty(),
            "expected a standalone aws_lc_rs violation, got none"
        );
    }

    #[test]
    fn bad_ssh_feature_missing_dep_russh_fails() {
        let manifest = r#"
[dependencies]
russh = { version = "0.60", optional = true, features = ["aws-lc-rs"] }

[features]
ssh = ["russh", "dep:bytes"]
"#;
        let v = check_manifest(manifest);
        assert!(
            v.iter().any(|m| m.contains("dep:russh")),
            "expected a missing-dep:russh violation, got: {v:?}"
        );
    }
}
