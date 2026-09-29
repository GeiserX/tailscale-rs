//! A `#![no_std]` crate must not depend on a workspace crate that links `std`.
//!
//! WHY: `#![no_std]` on a library is a promise that it builds for targets with no standard
//! library. The attribute only covers the crate it sits on, though: if any of its dependencies
//! omits `#![no_std]`, that dependency links `std` and the promise is broken without a single
//! compiler warning on a hosted target. `ts_control_serde` shipped that way for a while, because
//! `ts_capabilityversion` never declared `#![no_std]` even though it used nothing from `std`.
//!
//! WHAT THIS CHECKS: for every workspace member whose `src/lib.rs` carries an unconditional
//! `#![no_std]` line, each workspace-local crate it lists under `[dependencies]` or
//! `[target.*.dependencies]` must carry the same line in its own `src/lib.rs`. Dev-dependencies
//! are exempt (tests may use `std`). Third-party crates are out of scope: whether they link `std`
//! depends on feature selection, which a manifest scan cannot resolve.

use std::path::{Path, PathBuf};

use crate::{Args, BoxResult};

pub fn run(_args: &Args) -> BoxResult<()> {
    let contents = std::fs::read_to_string("Cargo.toml")?;
    let root = toml::from_str::<toml::Table>(&contents)?;
    let violations = find_violations(&root, |p| std::fs::read_to_string(p).ok())?;

    if !violations.is_empty() {
        eprintln!("`#![no_std]` crates depend on workspace crates that link `std`:");
        for v in &violations {
            eprintln!("  {v}");
        }
        eprintln!(
            "Add `#![no_std]` to the dependency (with `extern crate alloc;` if it allocates), or \
             drop `#![no_std]` from the dependent crate if it cannot be honoured."
        );
        return Err("no_std crate depends on a std workspace crate".into());
    }

    Ok(())
}

/// Return one message per `#![no_std]` member that depends on a workspace crate lacking
/// `#![no_std]`. `read` returns a file's contents, or `None` if it does not exist.
fn find_violations(
    root: &toml::Table,
    read: impl Fn(&Path) -> Option<String>,
) -> BoxResult<Vec<String>> {
    let workspace = root
        .get("workspace")
        .and_then(toml::Value::as_table)
        .ok_or("root Cargo.toml has no [workspace] table")?;
    let members = workspace
        .get("members")
        .and_then(toml::Value::as_array)
        .ok_or("root Cargo.toml has no workspace.members array")?;
    let workspace_deps = workspace
        .get("dependencies")
        .and_then(toml::Value::as_table);

    let is_no_std =
        |crate_dir: &Path| read(&crate_dir.join("src/lib.rs")).map(|lib| declares_no_std(&lib));

    let mut violations = Vec::new();
    for member in members.iter().filter_map(toml::Value::as_str) {
        let member_dir = Path::new(member);
        if is_no_std(member_dir) != Some(true) {
            continue;
        }

        let Some(manifest) = read(&member_dir.join("Cargo.toml")) else {
            continue;
        };
        let manifest = toml::from_str::<toml::Table>(&manifest)?;

        for (name, spec) in normal_dependencies(&manifest) {
            let Some(dep_dir) = local_path(member_dir, name, spec, workspace_deps) else {
                continue;
            };
            // `None` means the dependency has no `src/lib.rs` to judge; skip it rather than guess.
            if is_no_std(&dep_dir) == Some(false) {
                violations.push(format!(
                    "{member} is #![no_std] but depends on {name} ({}), which is not",
                    dep_dir.display()
                ));
            }
        }
    }

    Ok(violations)
}

/// True if `lib` has an unconditional `#![no_std]` inner attribute on a line of its own.
fn declares_no_std(lib: &str) -> bool {
    lib.lines().any(|line| line.trim() == "#![no_std]")
}

/// Every `(name, spec)` pair under `[dependencies]` and `[target.<cfg>.dependencies]`.
fn normal_dependencies(manifest: &toml::Table) -> Vec<(&str, &toml::Value)> {
    let mut deps = dependencies_table(manifest);
    if let Some(targets) = manifest.get("target").and_then(toml::Value::as_table) {
        for target in targets.values().filter_map(toml::Value::as_table) {
            deps.extend(dependencies_table(target));
        }
    }
    deps
}

/// The `(name, spec)` pairs of `table`'s `dependencies` sub-table, if it has one.
fn dependencies_table(table: &toml::Table) -> Vec<(&str, &toml::Value)> {
    table
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .into_iter()
        .flatten()
        .map(|(k, v)| (k.as_str(), v))
        .collect()
}

/// Resolve a dependency to its crate directory (relative to the repo root) if it is
/// workspace-local: either `path = "..."` on the member, or `workspace = true` pointing at a
/// `[workspace.dependencies]` entry with a `path`.
fn local_path(
    member_dir: &Path,
    name: &str,
    spec: &toml::Value,
    workspace_deps: Option<&toml::Table>,
) -> Option<PathBuf> {
    let spec = spec.as_table()?;
    if let Some(path) = spec.get("path").and_then(toml::Value::as_str) {
        return Some(member_dir.join(path));
    }
    if spec.get("workspace").and_then(toml::Value::as_bool) != Some(true) {
        return None;
    }
    let path = workspace_deps?
        .get(name)?
        .as_table()?
        .get("path")?
        .as_str()?;
    Some(PathBuf::from(path))
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::Path};

    use super::find_violations;

    const ROOT: &str = r#"
        [workspace]
        members = ["serde_types", "capver", "std_only"]

        [workspace.dependencies]
        capver = { path = "capver", package = "x_capver" }
        serde = "1"
    "#;

    const SERDE_TYPES_MANIFEST: &str = r#"
        [package]
        name = "serde_types"

        [dependencies]
        capver = { workspace = true, features = ["serde"] }
        serde.workspace = true

        [dev-dependencies]
        std_only = { path = "../std_only" }
    "#;

    fn run(files: &[(&str, &str)]) -> Vec<String> {
        let files: BTreeMap<_, _> = files.iter().copied().collect();
        let root = toml::from_str::<toml::Table>(ROOT).unwrap();
        find_violations(&root, |p: &Path| {
            files.get(p.to_str().unwrap()).map(|s| (*s).to_owned())
        })
        .unwrap()
    }

    /// The shape of the original defect: a `#![no_std]` crate pulling in a workspace crate, via
    /// `workspace = true`, that does not declare `#![no_std]`.
    #[test]
    fn flags_no_std_crate_depending_on_std_workspace_crate() {
        let violations = run(&[
            ("serde_types/src/lib.rs", "#![doc = \"x\"]\n#![no_std]\n"),
            ("serde_types/Cargo.toml", SERDE_TYPES_MANIFEST),
            ("capver/src/lib.rs", "#![doc = \"x\"]\nuse core::fmt;\n"),
        ]);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].contains("serde_types"), "{violations:?}");
        assert!(violations[0].contains("capver"), "{violations:?}");
    }

    /// Once the dependency declares `#![no_std]` too, nothing is flagged — and the std-only
    /// dev-dependency and the third-party `serde` are never considered.
    #[test]
    fn passes_when_dependency_is_no_std() {
        let violations = run(&[
            ("serde_types/src/lib.rs", "#![no_std]\n"),
            ("serde_types/Cargo.toml", SERDE_TYPES_MANIFEST),
            ("capver/src/lib.rs", "#![no_std]\n"),
            ("std_only/src/lib.rs", "use std::fs;\n"),
        ]);
        assert!(violations.is_empty(), "{violations:?}");
    }

    /// A crate that does not claim `#![no_std]` may depend on anything.
    #[test]
    fn ignores_crates_that_are_not_no_std() {
        let violations = run(&[
            ("serde_types/src/lib.rs", "use std::fs;\n"),
            ("serde_types/Cargo.toml", SERDE_TYPES_MANIFEST),
            ("capver/src/lib.rs", "use std::fs;\n"),
        ]);
        assert!(violations.is_empty(), "{violations:?}");
    }

    /// Member-relative `path` dependencies and target-specific dependency tables are checked too.
    #[test]
    fn follows_path_and_target_dependencies() {
        let manifest = r#"
            [package]
            name = "serde_types"

            [target.'cfg(unix)'.dependencies]
            std_only = { path = "../std_only" }
        "#;
        let violations = run(&[
            ("serde_types/src/lib.rs", "#![no_std]\n"),
            ("serde_types/Cargo.toml", manifest),
            ("serde_types/../std_only/src/lib.rs", "use std::fs;\n"),
        ]);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].contains("std_only"), "{violations:?}");
    }

    /// A conditional `no_std` or one mentioned only in a doc comment is not an unconditional
    /// `#![no_std]`, so a dependency carrying only that is still flagged.
    #[test]
    fn only_an_unconditional_attribute_counts() {
        let violations = run(&[
            ("serde_types/src/lib.rs", "#![no_std]\n"),
            ("serde_types/Cargo.toml", SERDE_TYPES_MANIFEST),
            (
                "capver/src/lib.rs",
                "//! It is `#![no_std]`.\n#![cfg_attr(not(feature = \"std\"), no_std)]\n",
            ),
        ]);
        assert_eq!(violations.len(), 1, "{violations:?}");
    }
}
