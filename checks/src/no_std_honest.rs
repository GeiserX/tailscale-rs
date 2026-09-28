//! A crate that advertises `no-std` on crates.io must not link a std-only dependency.
//!
//! WHY: the `no-std` / `no-std::no-alloc` crates.io categories are a promise to anyone building
//! for a bare-metal or other std-less target. A `#![no_std]` attribute only governs the crate's
//! own prelude; it says nothing about the dependency graph. The netstack crates once carried the
//! `no-std` category while depending on `flume`, which has no std-less mode, so a no_std build
//! failed deep in the graph even though the crate's own code was clean.
//!
//! WHAT THIS CHECKS: it runs `cargo metadata`, takes every workspace member whose categories start
//! with `no-std`, walks its NORMAL dependency edges transitively (dev and build edges are not
//! linked into the target), and fails if the walk reaches a crate in [`STD_ONLY`]. The list holds
//! only crates that require std under every feature set, so feature unification in the resolve
//! graph cannot produce a false positive for them.

use std::collections::{BTreeMap, VecDeque};

use crate::{Args, BoxResult};

/// Crates that link std no matter which features are enabled.
const STD_ONLY: &[&str] = &["flume"];

pub fn run(_args: &Args) -> BoxResult<()> {
    let output = std::process::Command::new(std::env::var("CARGO").unwrap_or("cargo".into()))
        .args(["metadata", "--format-version", "1"])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    let metadata = serde_json::from_slice::<serde_json::Value>(&output.stdout)?;
    let violations = check_metadata(&metadata)?;

    if !violations.is_empty() {
        eprintln!("crates in the `no-std` category that link a std-only dependency:");
        for v in &violations {
            eprintln!("  {v}");
        }
        eprintln!(
            "Either drop the std-only dependency or drop `no-std` from the crate's `categories`."
        );
        return Err("no-std crates depend on std-only crates".into());
    }

    Ok(())
}

/// Return one `a -> b -> ... -> std_only_crate` chain per violating `no-std` workspace member.
pub fn check_metadata(metadata: &serde_json::Value) -> BoxResult<Vec<String>> {
    let packages = metadata["packages"]
        .as_array()
        .ok_or("metadata has no packages")?;
    let names = packages
        .iter()
        .filter_map(|p| Some((p["id"].as_str()?, p["name"].as_str()?)))
        .collect::<BTreeMap<_, _>>();

    let nodes = metadata["resolve"]["nodes"]
        .as_array()
        .ok_or("metadata has no resolve graph")?;
    let normal_deps = nodes
        .iter()
        .filter_map(|n| {
            let deps = n["deps"]
                .as_array()?
                .iter()
                .filter(|d| {
                    d["dep_kinds"]
                        .as_array()
                        .is_some_and(|ks| ks.iter().any(|k| k["kind"].is_null()))
                })
                .filter_map(|d| d["pkg"].as_str())
                .collect::<Vec<_>>();
            Some((n["id"].as_str()?, deps))
        })
        .collect::<BTreeMap<_, _>>();

    let members = metadata["workspace_members"]
        .as_array()
        .ok_or("metadata has no workspace_members")?
        .iter()
        .filter_map(|m| m.as_str())
        .collect::<Vec<_>>();

    let mut violations = Vec::new();
    for pkg in packages {
        let Some(id) = pkg["id"].as_str() else {
            continue;
        };
        let claims_no_std = pkg["categories"].as_array().is_some_and(|cs| {
            cs.iter()
                .filter_map(|c| c.as_str())
                .any(|c| c.starts_with("no-std"))
        });
        if !members.contains(&id) || !claims_no_std {
            continue;
        }

        // Breadth-first so the reported chain is a shortest one.
        let mut parent = BTreeMap::from([(id, id)]);
        let mut queue = VecDeque::from([id]);
        while let Some(cur) = queue.pop_front() {
            let name = names.get(cur).copied().unwrap_or(cur);
            if STD_ONLY.contains(&name) {
                let mut chain = vec![name];
                let mut at = cur;
                while at != id {
                    at = parent[at];
                    chain.push(names.get(at).copied().unwrap_or(at));
                }
                chain.reverse();
                violations.push(chain.join(" -> "));
                break;
            }
            for &dep in normal_deps.get(cur).into_iter().flatten() {
                if !parent.contains_key(dep) {
                    parent.insert(dep, cur);
                    queue.push_back(dep);
                }
            }
        }
    }

    Ok(violations)
}

#[cfg(test)]
mod tests {
    use super::check_metadata;

    /// Build a `cargo metadata`-shaped value: `packages` is `(id, categories)`, `edges` is
    /// `(from, to, kind)` where `kind` is `None` for a normal dependency.
    fn metadata(
        packages: &[(&str, &[&str])],
        members: &[&str],
        edges: &[(&str, &str, Option<&str>)],
    ) -> serde_json::Value {
        let nodes = packages
            .iter()
            .map(|(id, _)| {
                let deps = edges
                    .iter()
                    .filter(|(from, _, _)| from == id)
                    .map(|(_, to, kind)| {
                        serde_json::json!({ "pkg": to, "dep_kinds": [{ "kind": kind }] })
                    })
                    .collect::<Vec<_>>();
                serde_json::json!({ "id": id, "deps": deps })
            })
            .collect::<Vec<_>>();
        serde_json::json!({
            "packages": packages
                .iter()
                .map(|(id, cats)| serde_json::json!({ "id": id, "name": id, "categories": cats }))
                .collect::<Vec<_>>(),
            "workspace_members": members,
            "resolve": { "nodes": nodes },
        })
    }

    #[test]
    fn transitive_std_only_dep_is_reported_with_its_chain() {
        let m = metadata(
            &[
                ("socket", &["no-std"]),
                ("core", &["network-programming"]),
                ("flume", &[]),
            ],
            &["socket", "core"],
            &[("socket", "core", None), ("core", "flume", None)],
        );
        assert_eq!(check_metadata(&m).unwrap(), ["socket -> core -> flume"]);
    }

    #[test]
    fn no_alloc_category_counts_as_a_no_std_claim() {
        let m = metadata(
            &[("bits", &["no-std::no-alloc"]), ("flume", &[])],
            &["bits"],
            &[("bits", "flume", None)],
        );
        assert_eq!(check_metadata(&m).unwrap(), ["bits -> flume"]);
    }

    #[test]
    fn dev_and_build_edges_are_not_linked_into_the_target() {
        let m = metadata(
            &[("core", &["no-std"]), ("flume", &[])],
            &["core"],
            &[
                ("core", "flume", Some("dev")),
                ("core", "flume", Some("build")),
            ],
        );
        assert!(check_metadata(&m).unwrap().is_empty());
    }

    #[test]
    fn crate_without_no_std_category_may_use_std_only_deps() {
        let m = metadata(
            &[("core", &["network-programming"]), ("flume", &[])],
            &["core"],
            &[("core", "flume", None)],
        );
        assert!(check_metadata(&m).unwrap().is_empty());
    }

    #[test]
    fn non_member_packages_are_not_checked() {
        let m = metadata(
            &[("registry_crate", &["no-std"]), ("flume", &[])],
            &[],
            &[("registry_crate", "flume", None)],
        );
        assert!(check_metadata(&m).unwrap().is_empty());
    }
}
