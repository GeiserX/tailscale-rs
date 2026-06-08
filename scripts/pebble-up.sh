#!/usr/bin/env bash
#
# pebble-up.sh - bring up a local Pebble ACME test CA + challtestsrv DNS server
# so the ts_control `acme` engine can be exercised end-to-end against a real
# RFC 8555 server (DNS-01). Idempotent: installs the Go binaries if absent,
# (re)launches both servers, waits for the directory, fetches the runtime CA
# root, and prints the exact environment to export for the integration test.
#
# Pairs with scripts/pebble-down.sh (kills what this started).
#
# Output is plain ASCII. PIDs are written to scripts/.pebble/pids.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="${SCRIPT_DIR}/.pebble"
PIDS_FILE="${STATE_DIR}/pids"
CONFIG_FILE="${STATE_DIR}/pebble-config.json"
CA_PEM="${STATE_DIR}/pebble-root.pem"
PEBBLE_LOG="${STATE_DIR}/pebble.log"
CHALLTESTSRV_LOG="${STATE_DIR}/challtestsrv.log"

# Endpoints (defaults baked into the config / flags below).
DIRECTORY_URL="https://localhost:14000/dir"
MGMT_URL="https://localhost:15000"
CHALLTESTSRV_MGMT_URL="http://localhost:8055"
CHALLTESTSRV_DNS="127.0.0.1:8053"

GO_BIN="${GO_BIN:-/opt/homebrew/bin/go}"
if ! command -v "${GO_BIN}" >/dev/null 2>&1; then
  GO_BIN="$(command -v go || true)"
fi
if [ -z "${GO_BIN}" ]; then
  echo "ERROR: go not found (set GO_BIN to the go binary path)" >&2
  exit 1
fi

# Pebble version is PINNED to v2.9.0.
#
# The `acme` engine now sends a User-Agent (ts_http_util), so the RFC 8555 sec 6.1
# enforcement in Pebble >= v2.10.0 is no longer a blocker. The pin remains for a
# DIFFERENT reason: the bundled challtestsrv's DNS-01 bind flag is `-dns01` in
# v2.9.0 and was renamed to `-dnsserver` in v2.10.x (see the challtestsrv launch
# below), so the flag wiring in this script is version-specific. Bumping the pin
# requires updating that flag. v2.9.0 also builds cleanly with current Go.
PEBBLE_VERSION="${PEBBLE_VERSION:-v2.9.0}"

GOPATH="$("${GO_BIN}" env GOPATH)"
GOBIN_DIR="${GOPATH}/bin"
PEBBLE="${GOBIN_DIR}/pebble"
CHALLTESTSRV="${GOBIN_DIR}/pebble-challtestsrv"

mkdir -p "${STATE_DIR}"

GOMODCACHE="$("${GO_BIN}" env GOMODCACHE)"
PEBBLE_MODULE="${GOMODCACHE}/github.com/letsencrypt/pebble/v2@${PEBBLE_VERSION}"

# --- 1. Install the PINNED binaries ----------------------------------------
# Always (re)install the pinned version: a `pebble` binary on PATH does not
# record its version, so we cannot tell a stale `@latest` build apart from the
# pinned one. `go install` is a fast no-op once cached.
echo "installing pebble ${PEBBLE_VERSION} ..." >&2
"${GO_BIN}" install "github.com/letsencrypt/pebble/v2/cmd/pebble@${PEBBLE_VERSION}"
echo "installing pebble-challtestsrv ${PEBBLE_VERSION} ..." >&2
"${GO_BIN}" install "github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@${PEBBLE_VERSION}"

# The bundled test certs live in the module cache for the pinned version. The
# install above ensures it is present; fail loudly if not.
if [ ! -d "${PEBBLE_MODULE}/test/certs" ]; then
  "${GO_BIN}" mod download "github.com/letsencrypt/pebble/v2@${PEBBLE_VERSION}" 2>/dev/null || true
fi
if [ ! -d "${PEBBLE_MODULE}/test/certs" ]; then
  echo "ERROR: Pebble module test/certs not found at ${PEBBLE_MODULE}/test/certs" >&2
  exit 1
fi
# TLS material the ACME directory listener (:14000) serves; localhost cert is
# signed by pebble.minica.pem, so trusting the minica lets the ACME client
# connect over HTTPS.
LOCALHOST_CERT="${PEBBLE_MODULE}/test/certs/localhost/cert.pem"
LOCALHOST_KEY="${PEBBLE_MODULE}/test/certs/localhost/key.pem"
MINICA_PEM="${PEBBLE_MODULE}/test/certs/pebble.minica.pem"

# --- 2. Clean up any previous run ------------------------------------------
if [ -f "${PIDS_FILE}" ]; then
  echo "stopping previous pebble run ..." >&2
  "${SCRIPT_DIR}/pebble-down.sh" >/dev/null 2>&1 || true
fi

# --- 3. Write a minimal Pebble config --------------------------------------
# httpPort/tlsPort here are the ports Pebble would use to VALIDATE http-01/
# tls-alpn-01 challenges; dns-01 does not use them, but Pebble still wants
# them present. certificate/privateKey is the TLS material the ACME directory
# listener (:14000) serves (Pebble's bundled localhost cert). We point Pebble's
# resolver at challtestsrv's DNS (:8053) so the dns-01 TXT we publish there is
# what Pebble queries.
cat > "${CONFIG_FILE}" <<EOF
{
  "pebble": {
    "listenAddress": "0.0.0.0:14000",
    "managementListenAddress": "0.0.0.0:15000",
    "certificate": "${LOCALHOST_CERT}",
    "privateKey": "${LOCALHOST_KEY}",
    "httpPort": 5002,
    "tlsPort": 5001,
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false
  }
}
EOF

# --- 4. Launch challtestsrv -------------------------------------------------
# -dns01 binds the DNS server; -management binds the mgmt HTTP API used by the
# test's ChalltestsrvPublisher to POST /set-txt. Disable the other mock
# servers (http-01/https-01/doh) so we don't fight for ports.
# NOTE: the DNS bind flag is `-dns01` in pebble v2.9.0 (it was renamed to
# `-dnsserver` in v2.10.x). We pin v2.9.0 (see PEBBLE_VERSION above), so use
# `-dns01` here. The other mock servers are disabled so we don't fight for ports.
echo "starting pebble-challtestsrv ..." >&2
"${CHALLTESTSRV}" \
  -dns01 ":8053" \
  -http01 "" \
  -https01 "" \
  -tlsalpn01 "" \
  -doh "" \
  -management ":8055" \
  >"${CHALLTESTSRV_LOG}" 2>&1 &
CHALLTESTSRV_PID=$!

# --- 5. Launch Pebble -------------------------------------------------------
# PEBBLE_VA_NOSLEEP=1 removes Pebble's random validation delay (faster test).
# -dnsserver points Pebble at challtestsrv for all DNS resolution.
echo "starting pebble ..." >&2
PEBBLE_VA_NOSLEEP=1 PEBBLE_VA_ALWAYS_VALID=0 "${PEBBLE}" \
  -config "${CONFIG_FILE}" \
  -dnsserver "${CHALLTESTSRV_DNS}" \
  >"${PEBBLE_LOG}" 2>&1 &
PEBBLE_PID=$!

# Record PIDs immediately so a failed wait can still be cleaned up.
printf 'PEBBLE_PID=%s\nCHALLTESTSRV_PID=%s\n' "${PEBBLE_PID}" "${CHALLTESTSRV_PID}" > "${PIDS_FILE}"

# --- 6. Wait for the directory to respond ----------------------------------
echo "waiting for ${DIRECTORY_URL} ..." >&2
ready=0
for _ in $(seq 1 50); do
  if curl -k -sf "${DIRECTORY_URL}" >/dev/null 2>&1; then
    ready=1
    break
  fi
  # Bail early if either process already died.
  if ! kill -0 "${PEBBLE_PID}" 2>/dev/null; then
    echo "ERROR: pebble exited early; log:" >&2
    cat "${PEBBLE_LOG}" >&2
    exit 1
  fi
  if ! kill -0 "${CHALLTESTSRV_PID}" 2>/dev/null; then
    echo "ERROR: pebble-challtestsrv exited early; log:" >&2
    cat "${CHALLTESTSRV_LOG}" >&2
    exit 1
  fi
  sleep 0.3
done

if [ "${ready}" -ne 1 ]; then
  echo "ERROR: ${DIRECTORY_URL} did not become ready" >&2
  echo "--- pebble.log ---" >&2
  cat "${PEBBLE_LOG}" >&2
  echo "--- challtestsrv.log ---" >&2
  cat "${CHALLTESTSRV_LOG}" >&2
  exit 1
fi

# --- 7. Assemble the trust bundle ------------------------------------------
# Two distinct CAs are in play:
#   * pebble.minica.pem signs the localhost cert the ACME DIRECTORY listener
#     (:14000) serves over TLS -- trusting it is what lets the ACME *client*
#     connect at all (this is the one TS_RS_EXTRA_CA_PEM strictly needs).
#   * /roots/0 (+ /intermediates/0) is the freshly-generated CA Pebble uses to
#     SIGN issued certs -- included so the bundle also covers the issued chain.
echo "assembling trust bundle (minica + ${MGMT_URL}/roots/0) ..." >&2
if [ ! -f "${MINICA_PEM}" ]; then
  echo "ERROR: pebble.minica.pem not found at ${MINICA_PEM}" >&2
  exit 1
fi
cat "${MINICA_PEM}" > "${CA_PEM}"
curl -k -sf "${MGMT_URL}/roots/0" >> "${CA_PEM}" 2>/dev/null || true
curl -k -sf "${MGMT_URL}/intermediates/0" >> "${CA_PEM}" 2>/dev/null || true

if [ ! -s "${CA_PEM}" ]; then
  echo "ERROR: assembled CA bundle is empty" >&2
  exit 1
fi

# --- 8. Report --------------------------------------------------------------
cat <<EOF

============================================================================
Pebble is UP. Export these, then run the integration test:

  export TS_RS_TEST_PEBBLE=1
  export TS_RS_ACME_DIRECTORY="${DIRECTORY_URL}"
  export TS_RS_EXTRA_CA_PEM="${CA_PEM}"
  export TS_RS_CHALLTESTSRV_URL="${CHALLTESTSRV_MGMT_URL}"

  TS_RS_EXPERIMENT=this_is_unstable_software \\
    cargo test -p geiserx_ts_control --features acme --test acme_pebble -- --nocapture

Details:
  ACME directory URL : ${DIRECTORY_URL}
  CA root PEM path   : ${CA_PEM}
  challtestsrv mgmt  : ${CHALLTESTSRV_MGMT_URL}  (DNS on ${CHALLTESTSRV_DNS})
  pebble PID         : ${PEBBLE_PID}
  challtestsrv PID   : ${CHALLTESTSRV_PID}
  PIDs file          : ${PIDS_FILE}
  logs               : ${PEBBLE_LOG}
                       ${CHALLTESTSRV_LOG}

Tear down with: ${SCRIPT_DIR}/pebble-down.sh
============================================================================
EOF
