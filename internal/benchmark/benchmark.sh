#!/usr/bin/env bash
#
# benchmark.sh — compare bbb (this repo) upload/download throughput against
# azcopy and boostedblob (py-bbb) using a real Azure Blob Storage account.
#
# py-bbb (https://github.com/hauntsaninja/boostedblob) only talks to the real
# `*.blob.core.windows.net` endpoint, so this benchmark cannot run against the
# Azurite emulator — a real storage account is required.
#
# Required environment variables:
#   BENCH_ACCOUNT    Azure storage account name
#   BENCH_KEY        Azure storage account shared key
#   BENCH_CONTAINER  Container to use (created if missing)
#
# Optional environment variables:
#   BENCH_SIZE_MB      Test file size in MiB                (default: 1024)
#   BENCH_RUNS         Timed runs per tool/direction        (default: 3)
#   BENCH_CONCURRENCY  Concurrency passed to bbb/azcopy     (default: nproc)
#   BBB_BIN            Path to the bbb binary under test    (default: bbb on PATH)
#   PYBBB              Command to invoke py-bbb              (default: python -m boostedblob)
#   AZCOPY_BIN         Path to azcopy                       (default: azcopy on PATH)
#   BENCH_FAIL_FACTOR  If set, fail when bbb is slower than the fastest other
#                      tool by more than this factor (e.g. 1.5). Unset = report only.
#   GITHUB_STEP_SUMMARY  When set, the results table is appended to it.
#
set -euo pipefail

: "${BENCH_ACCOUNT:?BENCH_ACCOUNT is required}"
: "${BENCH_KEY:?BENCH_KEY is required}"
: "${BENCH_CONTAINER:?BENCH_CONTAINER is required}"

BENCH_SIZE_MB="${BENCH_SIZE_MB:-1024}"
BENCH_RUNS="${BENCH_RUNS:-3}"
BENCH_CONCURRENCY="${BENCH_CONCURRENCY:-$(nproc)}"
BBB_BIN="${BBB_BIN:-bbb}"
PYBBB="${PYBBB:-python -m boostedblob}"
AZCOPY_BIN="${AZCOPY_BIN:-azcopy}"

WORKDIR="$(mktemp -d)"
SRC_FILE="${WORKDIR}/testfile.bin"
trap 'rm -rf "${WORKDIR}"' EXIT

BLOB_HOST="https://${BENCH_ACCOUNT}.blob.core.windows.net"

log() { printf '>>> %s\n' "$*" >&2; }

# seconds() runs a command, discarding its output, and prints the wall-clock
# seconds it took as a floating point number.
seconds() {
  local start end
  start="$(date +%s.%N)"
  "$@" >/dev/null 2>&1
  end="$(date +%s.%N)"
  awk -v s="${start}" -v e="${end}" 'BEGIN { printf "%.3f", e - s }'
}

# best_of runs the given command BENCH_RUNS times and prints the fastest time.
best_of() {
  local best="" t
  for _ in $(seq 1 "${BENCH_RUNS}"); do
    t="$(seconds "$@")"
    if [ -z "${best}" ] || awk -v a="${t}" -v b="${best}" 'BEGIN { exit !(a < b) }'; then
      best="${t}"
    fi
  done
  printf '%s' "${best}"
}

mbps() { # seconds -> MB/s for BENCH_SIZE_MB
  awk -v mb="${BENCH_SIZE_MB}" -v s="$1" 'BEGIN { if (s <= 0) { print "n/a" } else { printf "%.1f", mb / s } }'
}

# ---------------------------------------------------------------------------
# Setup: account-key env for each tool, container, SAS token, source file.
# ---------------------------------------------------------------------------

# bbb (this repo) uses BBB_AZBLOB_ACCOUNTKEY.
export BBB_AZBLOB_ACCOUNTKEY="${BENCH_KEY}"

# py-bbb (boostedblob) uses AZURE_STORAGE_ACCOUNT(+_KEY).
export AZURE_STORAGE_ACCOUNT="${BENCH_ACCOUNT}"
export AZURE_STORAGE_ACCOUNT_KEY="${BENCH_KEY}"

log "Ensuring container ${BENCH_CONTAINER} exists"
az storage container create \
  --account-name "${BENCH_ACCOUNT}" \
  --account-key "${BENCH_KEY}" \
  --name "${BENCH_CONTAINER}" \
  --only-show-errors >/dev/null

# azcopy authenticates with a short-lived container SAS computed locally.
SAS_EXPIRY="$(date -u -d '+2 hours' '+%Y-%m-%dT%H:%MZ')"
SAS="$(az storage container generate-sas \
  --account-name "${BENCH_ACCOUNT}" \
  --account-key "${BENCH_KEY}" \
  --name "${BENCH_CONTAINER}" \
  --permissions racwdl \
  --expiry "${SAS_EXPIRY}" \
  --https-only \
  --only-show-errors \
  --output tsv)"
export AZCOPY_LOG_LEVEL=ERROR

log "Generating ${BENCH_SIZE_MB} MiB test file"
dd if=/dev/urandom of="${SRC_FILE}" bs=1M count="${BENCH_SIZE_MB}" status=none

# ---------------------------------------------------------------------------
# Per-tool transfer commands. Each tool gets its own blob name so runs do not
# clobber one another.
# ---------------------------------------------------------------------------

bbb_upload()    { "${BBB_BIN}" cp -f --concurrency "${BENCH_CONCURRENCY}" "${SRC_FILE}" "az://${BENCH_ACCOUNT}/${BENCH_CONTAINER}/bench-bbb.bin"; }
bbb_download()  { "${BBB_BIN}" cp -f --concurrency "${BENCH_CONCURRENCY}" "az://${BENCH_ACCOUNT}/${BENCH_CONTAINER}/bench-bbb.bin" "${WORKDIR}/dl-bbb.bin"; }

# ${PYBBB} is intentionally left unquoted so that multi-word commands such as
# the default "python -m boostedblob" word-split into separate arguments.
pybbb_upload()   { ${PYBBB} cp "${SRC_FILE}" "az://${BENCH_ACCOUNT}/${BENCH_CONTAINER}/bench-pybbb.bin"; }
pybbb_download() { ${PYBBB} cp "az://${BENCH_ACCOUNT}/${BENCH_CONTAINER}/bench-pybbb.bin" "${WORKDIR}/dl-pybbb.bin"; }

azcopy_upload()   { "${AZCOPY_BIN}" copy "${SRC_FILE}" "${BLOB_HOST}/${BENCH_CONTAINER}/bench-azcopy.bin?${SAS}" --overwrite=true; }
azcopy_download() { "${AZCOPY_BIN}" copy "${BLOB_HOST}/${BENCH_CONTAINER}/bench-azcopy.bin?${SAS}" "${WORKDIR}/dl-azcopy.bin" --overwrite=true; }

# Prime each upload once so the download benchmark has a blob to read, and so
# the first (often slower) connection setup is not counted in the timing.
log "Priming uploads"
bbb_upload    >/dev/null 2>&1 || { log "bbb upload failed";    exit 1; }
pybbb_upload  >/dev/null 2>&1 || { log "py-bbb upload failed"; exit 1; }
azcopy_upload >/dev/null 2>&1 || { log "azcopy upload failed"; exit 1; }

# ---------------------------------------------------------------------------
# Run the benchmark.
# ---------------------------------------------------------------------------
declare -A UP DOWN
for tool in bbb pybbb azcopy; do
  log "Benchmarking ${tool} upload (${BENCH_RUNS} runs)"
  UP[${tool}]="$(best_of "${tool}_upload")"
  log "Benchmarking ${tool} download (${BENCH_RUNS} runs)"
  DOWN[${tool}]="$(best_of "${tool}_download")"
done

# ---------------------------------------------------------------------------
# Report.
# ---------------------------------------------------------------------------
emit() { printf '%s\n' "$1"; if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then printf '%s\n' "$1" >>"${GITHUB_STEP_SUMMARY}"; fi; }

emit "### Transfer benchmark — ${BENCH_SIZE_MB} MiB, best of ${BENCH_RUNS}, concurrency ${BENCH_CONCURRENCY}"
emit ""
emit "| Tool | Upload (s) | Upload MB/s | Download (s) | Download MB/s |"
emit "|------|-----------:|------------:|-------------:|--------------:|"
emit "| bbb (this repo) | ${UP[bbb]} | $(mbps "${UP[bbb]}") | ${DOWN[bbb]} | $(mbps "${DOWN[bbb]}") |"
emit "| py-bbb (boostedblob) | ${UP[pybbb]} | $(mbps "${UP[pybbb]}") | ${DOWN[pybbb]} | $(mbps "${DOWN[pybbb]}") |"
emit "| azcopy | ${UP[azcopy]} | $(mbps "${UP[azcopy]}") | ${DOWN[azcopy]} | $(mbps "${DOWN[azcopy]}") |"

# ---------------------------------------------------------------------------
# Cleanup blobs.
# ---------------------------------------------------------------------------
log "Cleaning up benchmark blobs"
for name in bench-bbb.bin bench-pybbb.bin bench-azcopy.bin; do
  "${BBB_BIN}" rm -f "az://${BENCH_ACCOUNT}/${BENCH_CONTAINER}/${name}" >/dev/null 2>&1 || true
done

# ---------------------------------------------------------------------------
# Optional regression gate.
# ---------------------------------------------------------------------------
if [ -n "${BENCH_FAIL_FACTOR:-}" ]; then
  fail=0
  for direction in UP DOWN; do
    declare -n times="${direction}"
    others_best="$(awk -v a="${times[pybbb]}" -v b="${times[azcopy]}" 'BEGIN { print (a < b ? a : b) }')"
    if awk -v bbb="${times[bbb]}" -v other="${others_best}" -v f="${BENCH_FAIL_FACTOR}" \
        'BEGIN { exit !(bbb > other * f) }'; then
      log "REGRESSION: bbb ${direction} ${times[bbb]}s is slower than ${others_best}s * ${BENCH_FAIL_FACTOR}"
      fail=1
    fi
  done
  [ "${fail}" -eq 0 ] || exit 1
fi

log "Benchmark complete"
