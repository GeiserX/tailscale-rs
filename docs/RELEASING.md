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

> **Bulk option (optional):** the 43 entries can be created in one pass via the crates.io
> trusted-publishing API (`/api/v1/trusted_publishing/github_configs`) with a crates.io API token —
> see the helper noted in `scripts/` if present. The manual web form is the supported baseline.

## Manual fallback

If trusted publishing is unavailable, `scripts/publish-crates.sh` still works locally with a token:

```sh
export CARGO_REGISTRY_TOKEN=<crates.io token>
TS_RS_EXPERIMENT=this_is_unstable_software SKIP_PUBLISHED=1 ./scripts/publish-crates.sh
```

This is the same script `release.yml` runs in CI; the only difference is where `CARGO_REGISTRY_TOKEN`
comes from (a local token vs. the OIDC-minted one).
