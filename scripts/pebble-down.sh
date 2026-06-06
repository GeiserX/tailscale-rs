#!/usr/bin/env bash
#
# pebble-down.sh - stop the Pebble ACME test CA + challtestsrv started by
# scripts/pebble-up.sh, using the PIDs recorded in scripts/.pebble/pids.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="${SCRIPT_DIR}/.pebble"
PIDS_FILE="${STATE_DIR}/pids"

if [ ! -f "${PIDS_FILE}" ]; then
  echo "no PIDs file at ${PIDS_FILE}; nothing to stop" >&2
  exit 0
fi

# shellcheck source=/dev/null
. "${PIDS_FILE}"

for pid in "${PEBBLE_PID:-}" "${CHALLTESTSRV_PID:-}"; do
  if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
    echo "killing pid ${pid}" >&2
    kill "${pid}" 2>/dev/null || true
  fi
done

# Give them a moment, then hard-kill any survivors.
sleep 0.5
for pid in "${PEBBLE_PID:-}" "${CHALLTESTSRV_PID:-}"; do
  if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
    kill -9 "${pid}" 2>/dev/null || true
  fi
done

rm -f "${PIDS_FILE}"
echo "pebble stopped" >&2
