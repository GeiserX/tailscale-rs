//! Ensure workspace lints are enabled on all crates.

use crate::{Args, BoxResult};

#[derive(serde::Deserialize)]
struct CargoManifest {
    package: Package,
    #[serde(default)]
    lints: Lints,
}

#[derive(serde::Deserialize)]
struct Package {
    name: String,
}

#[derive(Default, serde::Deserialize)]
struct Lints {
    workspace: bool,
}

pub fn run(_args: &Args) -> BoxResult<()> {
    let glob = globwalk::GlobWalkerBuilder::from_patterns(
        ".",
        &[
            "**/Cargo.toml",
            "!target",
            "!.git",
            "!.jj",
            "!.github",
            "!.direnv",
            "!result",
            // `ts_tka/fuzz` is its OWN isolated cargo workspace (empty `[workspace]` table, the
            // cargo-fuzz convention) so it cannot inherit this repo's `[workspace.lints]`; it is
            // nightly-only dev tooling excluded from the normal build/test graph. Skip it here
            // rather than force a redundant `[workspace.lints]` into the fuzz manifest.
            "!ts_tka/fuzz",
        ],
    )
    .build()?;

    let mut failed = false;
    for entry in glob {
        let entry = entry?;

        let contents = std::fs::read_to_string(entry.path())?;
        let manifest = toml::from_str::<CargoManifest>(&contents)?;

        let name = manifest.package.name;
        if !manifest.lints.workspace {
            println!("{name}");
            failed = true;
        }
    }

    if failed {
        return Err("workspace lints not enabled".into());
    }

    Ok(())
}
