# Releasing

Releases are automated. You do **not** hand-edit versions, hand-tag, or run a publish script.

## The pipeline

```
Conventional-commit PRs land on main
        │
        ▼
release-please.yml ── maintains a standing "release PR" that:
        │              • bumps the single workspace version
        │                ([workspace.package].version — all 43 crates inherit it
        │                 via version.workspace = true)
        │              • rewrites CHANGELOG.md
        ▼
You merge the release PR
        │
        ▼
release-please ── creates the GitHub Release + pushes tag vX.Y.Z
        │           then dispatches release.yml (a tag pushed with GITHUB_TOKEN
        │           does NOT trigger `on: push: tags` — GitHub's recursion guard —
        │           so the publish is invoked explicitly)
        ▼
release.yml ── publishes all 43 geiserx_* crates to crates.io via OIDC
                trusted publishing (no stored token), driving
                scripts/publish-crates.sh (leaf-first order, resumes past
                already-published crates, self-heals through the 429 rate limit).
                release-binaries.yml separately attaches the C-library artifacts.
```

So the entire release action is: **merge the release PR.** Everything else is automatic.

## Version policy (pre-1.0)

`release-please` derives the bump from Conventional Commit types (`release-please-config.json`,
`bump-minor-pre-major: true`):

| Commit type        | Bump (while < 1.0) |
| ------------------ | ------------------ |
| `fix:`             | patch (`0.x.PATCH`) |
| `feat:`            | minor (`0.MINOR.0`) |
| `feat!:`/`BREAKING CHANGE:` | minor while < 1.0 (not a major) |

The version lives in exactly one place — `[workspace.package].version` in the root `Cargo.toml` —
and `release-please` bumps it via a generic-TOML `extra-files` updater on
`$.workspace.package.version`. (It uses `release-type: simple`, **not** `rust`: the `rust` updater
rewrites `[package].version` with a literal, which would break the facade crate's
`version.workspace = true` inheritance and split the workspace version across the 43 crates.)

## One-time setup: crates.io trusted publishing

`release.yml` authenticates to crates.io with **OIDC trusted publishing** — no long-lived token is
stored in the repo. This requires registering this repository as a *trusted publisher* on crates.io,
**once per crate** (all 43 crates already exist on crates.io, so this is pure configuration — no
token bootstrap is needed).

For **each** `geiserx_*` crate, on its crates.io *Settings → Trusted Publishing* page, add a GitHub
publisher with:

| Field             | Value                    |
| ----------------- | ------------------------ |
| Repository owner  | `GeiserX`                |
| Repository name   | `tailscale-rs`           |
| Workflow filename | `release.yml`            |
| Environment       | *(leave empty)*          |

Until a crate has its trusted publisher configured, `release.yml`'s publish step fails *for that
crate only*; the version-bump + tag + GitHub-Release half (release-please.yml) works regardless.

### Adding a NEW `geiserx_*` crate (token bootstrap REQUIRED)

A brand-new crate cannot be created by OIDC trusted publishing — crates.io rejects it with
`403 Forbidden: Trusted Publishing tokens do not support creating new crates. Publish the crate
manually, first`. So the **first** version of any new crate needs a one-time token bootstrap, in
addition to the usual checklist. When you add a new `ts_*` crate, do ALL of:

1. Add it to the workspace `members` + `[workspace.dependencies]` (with `version = "X.Y.Z"
   # x-release-please-version`).
2. **Add it to `scripts/publish-crates.sh`'s `CRATES=(…)` array in leaf-first order**, BEFORE any
   crate that depends on it (omitting it breaks the whole publish at the first dependent — e.g.
   `ts_netmon` missing broke `ts_runtime`'s publish), and bump the `43`→`N` count strings in both
   `scripts/publish-crates.sh` and `.github/workflows/release.yml` (incl. the job name).
3. **Token bootstrap (one-time, needs a crates.io token):**
   ```sh
   export CARGO_REGISTRY_TOKEN=<a crates.io API token with "publish" scope>
   cargo publish -p geiserx_<new_crate>            # creates the crate + its first version
   ./scripts/setup-trusted-publishing.sh           # registers GeiserX/tailscale-rs as its trusted publisher (idempotent; derives the list from cargo metadata, so it picks up the new crate)
   ```
   After that, CI's OIDC trusted publishing handles the crate on every future release.
4. If a release already published the rest of the workspace but failed at the new crate, finish it:
   bootstrap the crate (step 3), then re-dispatch the `Release` workflow for the same tag
   (`gh workflow run Release --ref main`; `SKIP_PUBLISHED=1` resumes past the already-published
   versions).

> **Bulk option (recommended over 43 web forms):** `scripts/setup-trusted-publishing.sh` registers
> the trusted publisher on every publishable crate in one pass via the crates.io API. It is
> idempotent (skips crates already configured) and derives the crate list from `cargo metadata`, so
> it never drifts from what `publish-crates.sh` ships:
>
> ```sh
> export CARGO_REGISTRY_TOKEN=<a crates.io API token>   # publish-scoped is fine
> ./scripts/setup-trusted-publishing.sh --dry-run       # preview (no token needed, no writes)
> ./scripts/setup-trusted-publishing.sh                 # register all 43
> ```
>
> The manual web form (above) remains the supported baseline for a single crate.

## Manual fallback

If trusted publishing is unavailable, `scripts/publish-crates.sh` still works locally with a token:

```sh
export CARGO_REGISTRY_TOKEN=<crates.io token>
TS_RS_EXPERIMENT=this_is_unstable_software SKIP_PUBLISHED=1 ./scripts/publish-crates.sh
```

This is the same script `release.yml` runs in CI; the only difference is where `CARGO_REGISTRY_TOKEN`
comes from (a local token vs. the OIDC-minted one).
