#!/usr/bin/env bash
#
# run.sh — entrypoint for the benchmark Compose service.
#
# Runs entirely inside the container (see internal/benchmark/Dockerfile and
# docker-compose.yaml), so it is root and needs no host privileges. It:
#
#   1. generates the TLS material and trusts the CA (setup-emulator.sh) so the
#      production-style host https://{account}.blob.core.windows.net — mapped to
#      the azurite service's loopback by the compose extra_hosts — is served over
#      TLS with the shared certificate,
#   2. builds bbb from the mounted repo,
#   3. runs the benchmark (benchmark.sh).
#
set -euo pipefail

cd "$(dirname "$0")/../.."

# The azurite service shares this volume to pick up the TLS certificate; default
# to it so setup-emulator.sh, the benchmark and the emulator all agree.
STATE_DIR="${BENCH_STATE_DIR:-/bench-state}"

# Generate the TLS material (into STATE_DIR, shared with the azurite service)
# and trust the CA. The hardcoded host is mapped to the shared loopback by the
# azurite service's extra_hosts (inherited via network_mode).
BENCH_STATE_DIR="${STATE_DIR}" bash internal/benchmark/setup-emulator.sh

# Make every TLS client in this container (Go and Python alike) trust the CA
# that setup-emulator.sh installed into the system store. boostedblob talks to
# the emulator over HTTPS, so without this its requests fail verification.
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
export REQUESTS_CA_BUNDLE="${SSL_CERT_FILE}"
export CURL_CA_BUNDLE="${SSL_CERT_FILE}"

# Wait for the azurite service (running in the shared network namespace) to come
# up on :443 now that it has the certificate.
HOST="${BENCH_ACCOUNT:-devstoreaccount1}.blob.core.windows.net"
for _ in $(seq 1 60); do
  if curl -s -o /dev/null "https://${HOST}/?comp=list"; then
    break
  fi
  sleep 1
done
if ! curl -s -o /dev/null "https://${HOST}/?comp=list"; then
  echo "Azurite did not become ready at https://${HOST} after 60 seconds" >&2
  exit 1
fi

# py-bbb and the SAS generator live in the image's venv.
export PYBBB="/opt/venv/bin/python -m boostedblob"
export BENCH_PYTHON="/opt/venv/bin/python"

# Build bbb from the mounted repo. Disable VCS stamping: the repo is a bind
# mount owned by another user, which otherwise trips git's safe.directory check.
BBB_BIN="$(mktemp -d)/bbb"
go build -buildvcs=false -o "${BBB_BIN}" .
export BBB_BIN

# Record the repo's short commit so the report identifies the exact bbb build.
# The bind mount is owned by another user, so allow git to read it regardless.
git config --global --add safe.directory "$(pwd)" 2>/dev/null || true
BBB_VERSION="$(git rev-parse --short HEAD 2>/dev/null || true)"
export BBB_VERSION

# Start fresh so the workflow only appends this run's table to the job summary.
if [ -n "${BENCH_SUMMARY_FILE:-}" ]; then
  : >"${BENCH_SUMMARY_FILE}"
fi

bash internal/benchmark/benchmark.sh
