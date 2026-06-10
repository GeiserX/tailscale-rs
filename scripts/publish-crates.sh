#!/usr/bin/env bash
# Publish all 43 geiserx_* workspace crates to crates.io in leaf-first dependency order.
#
# Names on crates.io are GLOBAL and PERMANENT — once published they cannot be deleted (only
# yanked) or reused. Run this only when you are sure.
#
# Usage:
#   export CARGO_REGISTRY_TOKEN=<your crates.io token>   # or: cargo login <token>
#   TS_RS_EXPERIMENT=this_is_unstable_software ./scripts/publish-crates.sh            # real publish
#   TS_RS_EXPERIMENT=this_is_unstable_software ./scripts/publish-crates.sh --dry-run  # dry-run (leaf crates only validate)
#
# It publishes one crate at a time and waits for the crates.io index to update before the next
# (a dependent crate cannot publish until its deps are live + indexed). On any failure it stops so
# you can fix and resume (re-run; already-published crates are skipped via `cargo publish` erroring
# "already exists" — set SKIP_PUBLISHED=1 to tolerate that and continue).
set -euo pipefail

DRY=""
# `--allow-dirty` is now passed unconditionally on the publish call (lockfile churn mid-publish), so
# the dry-run flag only adds `--dry-run`.
[ "${1:-}" = "--dry-run" ] && DRY="--dry-run"

: "${TS_RS_EXPERIMENT:?set TS_RS_EXPERIMENT=this_is_unstable_software}"
if [ -z "$DRY" ] && [ -z "${CARGO_REGISTRY_TOKEN:-}" ]; then
  echo "ERROR: set CARGO_REGISTRY_TOKEN (or run 'cargo login <token>') for a real publish." >&2
  exit 1
fi

# geiserx_ts_ffi's build.rs writes the generated `tailscale.h` into the SOURCE dir as a dev
# convenience; cargo's publish-verify rejects a build script modifying anything outside OUT_DIR.
# This var turns the source-dir write off (the header still goes to OUT_DIR) so the ffi crate
# packages cleanly. Harmless for the other crates.
export TS_FFI_BUILDRS_STRICT=1

# Keep the inter-crate version pins in lockstep with the workspace version.
#
# `release-please` bumps only `[workspace.package].version` in the root Cargo.toml (its `extra-files`
# jsonpath). But each inter-crate dep in `[workspace.dependencies]` carries an explicit
# `version = "X.Y.Z"` (required so the *published* crates depend by version, not just path). If those
# pins lag the workspace version, `cargo publish` fails to resolve ("candidate versions found which
# didn't match") — exactly what broke the v0.13.0 publish. Rather than make release-please rewrite 40
# heterogeneous lines, the workspace version is the single source of truth and we sync the pins to it
# here, right before publishing. Idempotent: a no-op once they already match.
WS_VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
if [ -z "$WS_VERSION" ]; then
  echo "ERROR: could not read workspace version from Cargo.toml" >&2
  exit 1
fi
# Count inter-crate geiserx_ pins NOT already at the workspace version. Only rewrite when some lag,
# so a tree whose pins already match stays byte-identical (a `cargo publish` verify step rejects a
# dirty working tree — editing an already-synced Cargo.toml would needlessly dirty it and fail the
# publish, which is exactly what broke the first v0.13.0 attempt).
STALE=$(grep -cE 'package = "geiserx_' Cargo.toml | head -1)
MATCHED=$(grep -cE 'package = "geiserx_.*version = "'"$WS_VERSION"'"' Cargo.toml || true)
GEISER_DEPS=$(grep -cE 'package = "geiserx_.*version = "[0-9]+\.[0-9]+\.[0-9]+"' Cargo.toml || true)
if [ "$MATCHED" -eq "$GEISER_DEPS" ]; then
  echo "Inter-crate version pins already at $WS_VERSION ($MATCHED deps) — no edit needed."
else
  echo "Syncing $((GEISER_DEPS - MATCHED)) inter-crate version pins to workspace version $WS_VERSION ..."
  # Only touch lines in [workspace.dependencies] that are local geiserx_ path deps carrying a version.
  perl -i -pe 'if (/package = "geiserx_/ && /version = "[0-9]+\.[0-9]+\.[0-9]+"/) { s/version = "[0-9]+\.[0-9]+\.[0-9]+"/version = "'"$WS_VERSION"'"/ }' Cargo.toml
  echo "Inter-crate pins now at $WS_VERSION."
fi

# Leaf-first publish order (topologically sorted; facade at #40, bindings last).
CRATES=(
  geiserx_ts_bitset
  geiserx_ts_capabilityversion
  geiserx_ts_dns_wire
  geiserx_ts_hexdump
  geiserx_ts_host_net
  geiserx_ts_keys
  geiserx_ts_metrics
  geiserx_ts_netstack_smoltcp_core
  geiserx_ts_nodecapability
  geiserx_ts_packetfilter
  geiserx_ts_peercapability
  geiserx_ts_time
  geiserx_ts_tka
  geiserx_ts_tls_util
  geiserx_ts_array256
  geiserx_ts_dynbitset
  geiserx_ts_packet
  geiserx_ts_control_noise
  geiserx_ts_disco_protocol
  geiserx_ts_netstack_smoltcp_socket
  geiserx_ts_packetfilter_serde
  geiserx_ts_http_util
  geiserx_ts_bart
  geiserx_ts_transport
  geiserx_ts_tunnel
  geiserx_ts_netstack_smoltcp
  geiserx_ts_control_serde
  geiserx_ts_bart_packetfilter
  geiserx_ts_magicsock
  geiserx_ts_overlay_router
  geiserx_ts_transport_tun
  geiserx_ts_underlay_router
  geiserx_ts_forwarder
  geiserx_ts_derp
  geiserx_ts_packetfilter_state
  geiserx_ts_dataplane
  geiserx_ts_control
  geiserx_ts_netcheck
  geiserx_ts_runtime
  geiserx_tailscale
  geiserx_ts_elixir
  geiserx_ts_ffi
  geiserx_ts_python
)

total=${#CRATES[@]}
i=0
# crates.io heavily rate-limits NEW crate names (~1 new crate per 10 min after a small burst).
# On a 429 we parse its "try again after <RFC2822>" and sleep until then, so a 43-new-crate split
# publishes unattended (it just takes hours). Publishing new *versions* of existing crates is not
# limited, so a resume after the burst flies through already-published ones via SKIP_PUBLISHED.
for crate in "${CRATES[@]}"; do
  i=$((i+1))
  echo ""
  echo "==== [$i/$total] $crate ===="
  while :; do
    # Capture the single publish attempt's combined output so we can branch on the failure reason.
    # `--allow-dirty`: publishing crate N updates `Cargo.lock` (recording each just-published dep's
    # version), which dirties the working tree and would make crate N+1's publish-verify abort with
    # "files in the working directory contain changes not yet committed". CI checks out a clean tag,
    # so the only dirt is cargo's own lockfile churn mid-publish — benign and expected. (This bit the
    # first v0.13.0 attempt at the facade crate, which has the most published deps.)
    out=$(cargo publish -p "$crate" --allow-dirty $DRY 2>&1) && rc=0 || rc=$?
    printf '%s\n' "$out"
    if [ "$rc" -eq 0 ]; then
      [ -n "$DRY" ] && break
      echo "   published; settling before next crate ..."
      sleep 15
      break
    elif [ "${SKIP_PUBLISHED:-}" = "1" ] && printf '%s' "$out" | grep -qiE "already (exists|uploaded)"; then
      echo "   already on crates.io, skipping."
      break
    elif printf '%s' "$out" | grep -qiE "429 Too Many Requests|published too many"; then
      # Parse "Please try again after <Day, DD Mon YYYY HH:MM:SS GMT>" and wait until then (+30s).
      after=$(printf '%s' "$out" | grep -oE "try again after [A-Za-z]{3}, [0-9]{2} [A-Za-z]{3} [0-9]{4} [0-9:]{8} GMT" | sed 's/try again after //')
      target=$(date -j -u -f "%a, %d %b %Y %H:%M:%S GMT" "$after" "+%s" 2>/dev/null || echo "")
      now=$(date -u "+%s")
      if [ -n "$target" ] && [ "$target" -gt "$now" ]; then
        wait_s=$(( target - now + 30 ))
      else
        wait_s=610   # fallback: ~10 min + margin
      fi
      echo "   rate-limited (429). Waiting ${wait_s}s (until ${after:-~10min}) then retrying $crate ..."
      sleep "$wait_s"
      # loop retries the same crate
    else
      echo "ERROR: publishing $crate failed (rc=$rc). Stopping. Fix and re-run." >&2
      exit "$rc"
    fi
  done
done

echo ""
echo "All $total crates published."
