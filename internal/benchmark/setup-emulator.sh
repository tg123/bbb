#!/usr/bin/env bash
#
# setup-emulator.sh — prepare the local TLS trust so all three benchmarked tools
# (bbb, azcopy and boostedblob/py-bbb) can talk to the Azurite emulator.
#
# The Azurite emulator itself runs as its own Compose service (see
# docker-compose.yaml); this script only arranges the things that must happen
# inside the benchmark container:
#
# py-bbb (boostedblob) hardcodes `https://{account}.blob.core.windows.net` with
# no endpoint or port override, so the emulator has to be reachable at that exact
# host over HTTPS on port 443. This script therefore:
#
#   1. generates a local CA and a server certificate for
#      `{account}.blob.core.windows.net` into the shared state dir (so the
#      azurite service can serve TLS with it) and installs the CA into the
#      system trust store (so Go-based bbb/azcopy and Python's ssl all trust it),
#   2. points `{account}.blob.core.windows.net` at 127.0.0.1 via /etc/hosts (the
#      benchmark container shares the azurite service's network namespace, so the
#      emulator listens on the shared loopback at :443).
#
# It needs root (for /etc/hosts and the trust store); when not run as root it
# re-invokes the privileged bits with sudo.
#
# Environment:
#   BENCH_ACCOUNT   Storage account name      (default: devstoreaccount1)
#   BENCH_STATE_DIR Directory for the certificate material, shared with the
#                   azurite service (default: a mktemp dir; the chosen path is
#                   printed as "BENCH_STATE_DIR=<dir>")
#
set -euo pipefail

BENCH_ACCOUNT="${BENCH_ACCOUNT:-devstoreaccount1}"
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

log "TLS trust ready for https://${HOST}"
printf 'BENCH_STATE_DIR=%s\n' "${BENCH_STATE_DIR}"
