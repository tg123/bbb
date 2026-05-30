#!/usr/bin/env bash
#
# run.sh — entrypoint for the benchmark Compose service.
#
# Runs entirely inside the container (see internal/benchmark/Dockerfile and
# docker-compose.yaml), so it is root and needs no host privileges. It:
#
#   1. sets up the Azurite emulator behind the production-style host
#      https://{account}.blob.core.windows.net on :443 (setup-emulator.sh),
#   2. builds bbb from the mounted repo,
#   3. runs the benchmark (benchmark.sh).
#
set -euo pipefail

cd "$(dirname "$0")/../.."

STATE_DIR="$(mktemp -d)"

# Start the emulator and trust its CA. setup-emulator.sh prints
# "BENCH_STATE_DIR=<dir>"; capture it so cleanup and the benchmark agree on the
# location, though run.sh provides it up front.
BENCH_STATE_DIR="${STATE_DIR}" bash internal/benchmark/setup-emulator.sh

# Make every TLS client in this container (Go and Python alike) trust the CA
# that setup-emulator.sh installed into the system store. boostedblob talks to
# the emulator over HTTPS, so without this its requests fail verification.
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
export REQUESTS_CA_BUNDLE="${SSL_CERT_FILE}"
export CURL_CA_BUNDLE="${SSL_CERT_FILE}"

# py-bbb and the SAS generator live in the image's venv.
export PYBBB="/opt/venv/bin/python -m boostedblob"
export BENCH_PYTHON="/opt/venv/bin/python"

# Build bbb from the mounted repo. Disable VCS stamping: the repo is a bind
# mount owned by another user, which otherwise trips git's safe.directory check.
BBB_BIN="$(mktemp -d)/bbb"
go build -buildvcs=false -o "${BBB_BIN}" .
export BBB_BIN

# Start fresh so the workflow only appends this run's table to the job summary.
if [ -n "${BENCH_SUMMARY_FILE:-}" ]; then
  : >"${BENCH_SUMMARY_FILE}"
fi

bash internal/benchmark/benchmark.sh
