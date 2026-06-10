#!/usr/bin/env bash
# Register the GitHub Actions Trusted Publisher on crates.io for EVERY publishable workspace crate,
# so `release.yml` can publish via OIDC (no stored token). One-time setup; idempotent (re-runnable).
#
# crates.io Trusted Publishing is configured PER CRATE. Doing 43 crates by hand in the web UI
# (crates.io → each crate → Settings → Trusted Publishing) is tedious; this scripts it via the
# crates.io REST API. See https://crates.io/docs/trusted-publishing.
#
# Usage:
#   export CARGO_REGISTRY_TOKEN=<a crates.io API token with "publish" scope>   # or: CRATES_IO_TOKEN
#   ./scripts/setup-trusted-publishing.sh            # register on all publishable crates (idempotent)
#   ./scripts/setup-trusted-publishing.sh --dry-run  # show what would be registered, change nothing
#
# The token is sent in the `Authorization` header (crates.io `api_token` scheme). A normal
# publish-scoped token works; the crate must already exist and be owned by the token's user (all the
# geiserx_* crates already exist on crates.io, so this is pure configuration — no bootstrap publish).
#
# What it registers for each crate (the values release.yml needs):
#   repository_owner = GeiserX   repository_name = tailscale-rs   workflow_filename = release.yml
#   environment = (none)
set -euo pipefail

OWNER="GeiserX"
REPO="tailscale-rs"
WORKFLOW="release.yml"
ENVIRONMENT=""            # no GitHub Actions environment gate (matches release.yml)
API="https://crates.io/api/v1/trusted_publishing/github_configs"
UA="tailscale-rs trusted-publishing setup (https://github.com/${OWNER}/${REPO})"

DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1

TOKEN="${CARGO_REGISTRY_TOKEN:-${CRATES_IO_TOKEN:-}}"
if [ "$DRY" -eq 0 ] && [ -z "$TOKEN" ]; then
  echo "ERROR: set CARGO_REGISTRY_TOKEN (or CRATES_IO_TOKEN) to a crates.io API token." >&2
  exit 1
fi

need() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: '$1' is required." >&2; exit 1; }; }
need cargo; need curl; need python3

# The publishable workspace crates — derived from `cargo metadata` so this never drifts from what
# `publish-crates.sh` actually ships (publish != false). Sorted for stable output.
mapfile -t CRATES < <(
  cargo metadata --no-deps --format-version 1 \
    | python3 -c 'import sys,json; print("\n".join(sorted(p["name"] for p in json.load(sys.stdin)["packages"] if p.get("publish") is None)))'
)
echo "Found ${#CRATES[@]} publishable workspace crates."
[ "${#CRATES[@]}" -gt 0 ] || { echo "ERROR: no publishable crates found." >&2; exit 1; }

# Does crate $1 already have a github trusted-publisher for this owner/repo/workflow?
already_configured() {
  local crate="$1" body
  body=$(curl -fsS --max-time 30 -H "User-Agent: ${UA}" -H "Authorization: ${TOKEN}" \
           "${API}?crate=${crate}" 2>/dev/null) || return 1
  CRATE="$crate" OWNER="$OWNER" REPO="$REPO" WORKFLOW="$WORKFLOW" python3 - "$body" <<'PY'
import json, os, sys
try:
    cfgs = json.loads(sys.argv[1]).get("github_configs", [])
except Exception:
    sys.exit(1)
o, r, w = os.environ["OWNER"], os.environ["REPO"], os.environ["WORKFLOW"]
sys.exit(0 if any(
    c.get("repository_owner") == o and c.get("repository_name") == r and c.get("workflow_filename") == w
    for c in cfgs
) else 1)
PY
}

register() {
  local crate="$1"
  local env_json="null"
  [ -n "$ENVIRONMENT" ] && env_json="\"${ENVIRONMENT}\""
  local payload
  payload=$(printf '{"github_config":{"crate":"%s","repository_owner":"%s","repository_name":"%s","workflow_filename":"%s","environment":%s}}' \
              "$crate" "$OWNER" "$REPO" "$WORKFLOW" "$env_json")
  curl -fsS --max-time 30 -X POST "$API" \
    -H "User-Agent: ${UA}" -H "Authorization: ${TOKEN}" -H "Content-Type: application/json" \
    -d "$payload" >/dev/null
}

ok=0 skip=0 fail=0
for crate in "${CRATES[@]}"; do
  if [ "$DRY" -eq 1 ]; then
    echo "DRY-RUN would register: ${crate}  ->  ${OWNER}/${REPO} (${WORKFLOW})"
    continue
  fi
  if already_configured "$crate"; then
    echo "= ${crate}: already configured, skipping"
    skip=$((skip + 1))
    continue
  fi
  if register "$crate"; then
    echo "+ ${crate}: trusted publisher registered"
    ok=$((ok + 1))
  else
    echo "! ${crate}: FAILED to register (re-run to retry — the script is idempotent)" >&2
    fail=$((fail + 1))
  fi
  # Be gentle with the API.
  sleep 1
done

[ "$DRY" -eq 1 ] && { echo "Dry run complete (${#CRATES[@]} crates)."; exit 0; }
echo "Done: ${ok} registered, ${skip} already configured, ${fail} failed."
[ "$fail" -eq 0 ]
