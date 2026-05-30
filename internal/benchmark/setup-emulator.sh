#!/usr/bin/env bash
#
# setup-emulator.sh — start an Azurite blob emulator that all three benchmarked
# tools (bbb, azcopy and boostedblob/py-bbb) can talk to.
#
# py-bbb (boostedblob) hardcodes `https://{account}.blob.core.windows.net` with
# no endpoint or port override, so the emulator has to be reachable at that
# exact host over HTTPS on port 443. This script therefore:
#
#   1. generates a local CA and a server certificate for
#      `{account}.blob.core.windows.net` and installs the CA into the system
#      trust store (so Go-based bbb/azcopy and Python's ssl all trust it),
#   2. points `{account}.blob.core.windows.net` at 127.0.0.1 via /etc/hosts,
#   3. starts Azurite on port 443 with TLS and --skipApiVersionCheck.
#
# It needs root (for port 443, /etc/hosts and the trust store); when not run as
# root it re-invokes the privileged bits with sudo.
#
# Environment:
#   BENCH_ACCOUNT   Storage account name      (default: devstoreaccount1)
#   BENCH_KEY       Shared key for the account
#                   (default: the well-known Azurite key)
#   BENCH_STATE_DIR Directory for certs/data/logs/pid (default: a mktemp dir;
#                   the chosen path is printed as "BENCH_STATE_DIR=<dir>")
#   AZURITE_BIN     Azurite blob entrypoint   (default: azurite-blob, or `npx`)
#
set -euo pipefail

BENCH_ACCOUNT="${BENCH_ACCOUNT:-devstoreaccount1}"
BENCH_KEY="${BENCH_KEY:-Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==}"
BENCH_STATE_DIR="${BENCH_STATE_DIR:-$(mktemp -d)}"
HOST="${BENCH_ACCOUNT}.blob.core.windows.net"

log() { printf '>>> %s\n' "$*" >&2; }

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  SUDO="sudo"
fi

mkdir -p "${BENCH_STATE_DIR}"

# ---------------------------------------------------------------------------
# 1. Certificates.
# ---------------------------------------------------------------------------
CA_KEY="${BENCH_STATE_DIR}/ca.key"
CA_PEM="${BENCH_STATE_DIR}/ca.pem"
SRV_KEY="${BENCH_STATE_DIR}/server.key"
SRV_CRT="${BENCH_STATE_DIR}/server.crt"

log "Generating CA and server certificate for ${HOST}"
openssl genrsa -out "${CA_KEY}" 2048 >/dev/null 2>&1
# The CA needs explicit basicConstraints/keyUsage extensions; without them
# strict TLS stacks (notably Python's, used by py-bbb) reject the chain with
# "CA cert does not include key usage extension".
openssl req -x509 -new -nodes -key "${CA_KEY}" -sha256 -days 3650 \
  -subj "/CN=bbb-bench-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "${CA_PEM}" >/dev/null 2>&1

openssl genrsa -out "${SRV_KEY}" 2048 >/dev/null 2>&1
openssl req -new -key "${SRV_KEY}" -subj "/CN=${HOST}" \
  -out "${BENCH_STATE_DIR}/server.csr" >/dev/null 2>&1
cat >"${BENCH_STATE_DIR}/san.ext" <<EXT
subjectAltName=DNS:${HOST},DNS:*.blob.core.windows.net
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EXT
openssl x509 -req -in "${BENCH_STATE_DIR}/server.csr" -CA "${CA_PEM}" \
  -CAkey "${CA_KEY}" -CAcreateserial -days 3650 -sha256 \
  -extfile "${BENCH_STATE_DIR}/san.ext" -out "${SRV_CRT}" >/dev/null 2>&1

log "Trusting the CA in the system store"
${SUDO} cp "${CA_PEM}" /usr/local/share/ca-certificates/bbb-bench-ca.crt
${SUDO} update-ca-certificates >/dev/null 2>&1

# ---------------------------------------------------------------------------
# 2. /etc/hosts.
# ---------------------------------------------------------------------------
if ! getent hosts "${HOST}" | grep -q '127.0.0.1'; then
  log "Pointing ${HOST} at 127.0.0.1"
  printf '127.0.0.1 %s\n' "${HOST}" | ${SUDO} tee -a /etc/hosts >/dev/null
fi

# ---------------------------------------------------------------------------
# 3. Azurite on :443 with TLS.
# ---------------------------------------------------------------------------
AZURITE_BIN="${AZURITE_BIN:-}"

DATA_DIR="${BENCH_STATE_DIR}/data"
LOG_FILE="${BENCH_STATE_DIR}/azurite.log"
PID_FILE="${BENCH_STATE_DIR}/azurite.pid"
mkdir -p "${DATA_DIR}"

log "Starting Azurite on https://0.0.0.0:443"
# Azurite must bind privileged port 443, so launch it under the same privilege
# escalation used for the trust store. Resolve the absolute entrypoint so it
# survives the sudo PATH reset.
AZURITE_RESOLVED="${AZURITE_BIN:-$(command -v azurite-blob || true)}"
if [ -z "${AZURITE_RESOLVED}" ]; then
  log "azurite-blob not found on PATH; install it (npm install -g azurite)"
  exit 1
fi
NODE_BIN="$(command -v node)"
# azurite-blob shims are Node scripts; run them through node explicitly so the
# resolved path works regardless of the shebang and PATH under sudo.
ENTRY="$(${NODE_BIN} -e 'process.stdout.write(require("fs").realpathSync(process.argv[1]))' "${AZURITE_RESOLVED}")"
if [ -z "${ENTRY}" ]; then
  log "Could not resolve the Azurite entrypoint from ${AZURITE_RESOLVED}"
  exit 1
fi

${SUDO} bash -c "nohup '${NODE_BIN}' '${ENTRY}' \
  --blobHost 0.0.0.0 --blobPort 443 \
  --cert '${SRV_CRT}' --key '${SRV_KEY}' \
  --skipApiVersionCheck \
  --location '${DATA_DIR}' --silent \
  > '${LOG_FILE}' 2>&1 & echo \$! > '${PID_FILE}'"

# Wait for the listener.
for _ in $(seq 1 30); do
  if curl -s -o /dev/null "https://${HOST}/?comp=list" 2>/dev/null; then
    break
  fi
  sleep 1
done
if ! curl -s -o /dev/null "https://${HOST}/?comp=list" 2>/dev/null; then
  log "Azurite did not become ready; log follows:"
  cat "${LOG_FILE}" >&2 || true
  exit 1
fi

log "Azurite is ready at https://${HOST}"
printf 'BENCH_STATE_DIR=%s\n' "${BENCH_STATE_DIR}"
