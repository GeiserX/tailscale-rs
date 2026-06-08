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
[ "${1:-}" = "--dry-run" ] && DRY="--dry-run --allow-dirty"

: "${TS_RS_EXPERIMENT:?set TS_RS_EXPERIMENT=this_is_unstable_software}"
if [ -z "$DRY" ] && [ -z "${CARGO_REGISTRY_TOKEN:-}" ]; then
  echo "ERROR: set CARGO_REGISTRY_TOKEN (or run 'cargo login <token>') for a real publish." >&2
  exit 1
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
for crate in "${CRATES[@]}"; do
  i=$((i+1))
  echo ""
  echo "==== [$i/$total] $crate ===="
  if cargo publish -p "$crate" $DRY; then
    [ -n "$DRY" ] && continue
    # Wait for the new version to appear in the sparse index before publishing dependents.
    echo "   waiting for crates.io to index $crate ..."
    for _ in $(seq 1 60); do
      sleep 5
      if curl -fsS "https://crates.io/api/v1/crates/$crate" >/dev/null 2>&1; then
        echo "   indexed."
        break
      fi
    done
    sleep 5
  else
    rc=$?
    if [ "${SKIP_PUBLISHED:-}" = "1" ] && cargo publish -p "$crate" $DRY 2>&1 | grep -q "already exists"; then
      echo "   already published, skipping."
      continue
    fi
    echo "ERROR: publishing $crate failed (rc=$rc). Stopping. Fix and re-run." >&2
    exit "$rc"
  fi
done

echo ""
echo "All $total crates published."
