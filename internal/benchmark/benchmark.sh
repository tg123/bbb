#!/usr/bin/env bash
#
# benchmark.sh — compare bbb (this repo) upload/download throughput against
# azcopy and boostedblob (py-bbb) using the Azurite emulator. Each tool's
# download is verified against the source file's MD5 so a corrupt or truncated
# transfer fails the run rather than being reported as a (fast but wrong) result.
#
# The emulator must already be running and reachable at
# `https://${BENCH_ACCOUNT}.blob.core.windows.net` (port 443). The Compose stack
# (docker-compose.yaml) runs Azurite as its own service and maps that host to it;
# setup-emulator.sh only arranges the TLS cert and trust. py-bbb (boostedblob)
# hardcodes that host, so all three tools are pointed at it for an
# apples-to-apples comparison.
#
# Environment:
#   BENCH_ACCOUNT      Storage account name             (default: devstoreaccount1)
#   BENCH_KEY          Shared key for the account
#                      (default: the well-known Azurite key)
#   BENCH_CONTAINER    Container to use, created if missing (default: bench)
#   BENCH_SIZE_MB      Test file size in MiB             (default: 1024)
#   BENCH_RUNS         Timed runs per tool/direction     (default: 3)
#   BENCH_CONCURRENCY  Concurrency passed to bbb/azcopy  (default: nproc)
#   BBB_BIN            Path to the bbb binary under test (default: bbb on PATH)
#   BBB_VERSION        Identifier shown for bbb in the report, e.g. the repo's
#                      short commit sha (default: derived via `git`, else unset)
#   PYBBB              Command to invoke py-bbb           (default: python -m boostedblob)
#   AZCOPY_BIN         Path to azcopy                    (default: azcopy on PATH)
#   BENCH_FAIL_FACTOR  If set, fail when bbb is slower than the fastest other
#                      tool by more than this factor (e.g. 1.05 = 5%; default via
#                      compose/CI is 1.05). Empty = report only.
#   BENCH_PYTHON       Python used to mint the azcopy SAS (needs
#                      azure-storage-blob)               (default: python3)
#   BENCH_SUMMARY_FILE When set, the results table is also appended to this file.
#
set -euo pipefail

BENCH_ACCOUNT="${BENCH_ACCOUNT:-devstoreaccount1}"
BENCH_KEY="${BENCH_KEY:-Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==}"
BENCH_CONTAINER="${BENCH_CONTAINER:-bench}"
BENCH_SIZE_MB="${BENCH_SIZE_MB:-1024}"
BENCH_RUNS="${BENCH_RUNS:-3}"
BENCH_CONCURRENCY="${BENCH_CONCURRENCY:-$(nproc)}"
BBB_BIN="${BBB_BIN:-bbb}"
PYBBB="${PYBBB:-python -m boostedblob}"
AZCOPY_BIN="${AZCOPY_BIN:-azcopy}"
BENCH_PYTHON="${BENCH_PYTHON:-python3}"

HOST="${BENCH_ACCOUNT}.blob.core.windows.net"
BLOB_HOST="https://${HOST}"

WORKDIR="$(mktemp -d)"
SRC_FILE="${WORKDIR}/testfile.bin"
trap 'rm -rf "${WORKDIR}"' EXIT

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

# verify_md5 checks that the file at $1 matches the source file's MD5, failing
# the whole benchmark otherwise so an upload/download that silently corrupts or
# truncates data can never be reported as a fast (but wrong) result.
verify_md5() {
  local label="$1" file="$2" got
  if [ ! -f "${file}" ]; then
    log "INTEGRITY: ${label} produced no downloaded file (${file})"
    exit 1
  fi
  got="$(md5sum "${file}" | awk '{ print $1 }')"
  if [ "${got}" != "${SRC_MD5}" ]; then
    log "INTEGRITY: ${label} MD5 mismatch — expected ${SRC_MD5}, got ${got}"
    exit 1
  fi
  log "${label} round-trip MD5 OK (${got})"
}

# ---------------------------------------------------------------------------
# Per-tool auth.
# ---------------------------------------------------------------------------

# bbb (this repo) talks to the production-style host via BBB_AZBLOB_ENDPOINT and
# authenticates with the shared key.
export BBB_AZBLOB_ENDPOINT="https://%s.blob.core.windows.net/"
export BBB_AZBLOB_ACCOUNTKEY="${BENCH_KEY}"

# py-bbb (boostedblob) uses AZURE_STORAGE_ACCOUNT(+_KEY) and the hardcoded host.
export AZURE_STORAGE_ACCOUNT="${BENCH_ACCOUNT}"
export AZURE_STORAGE_ACCOUNT_KEY="${BENCH_KEY}"

# azcopy authenticates with a container SAS minted from the account key with
# azure-storage-blob (so no host `az` CLI is required).
export AZCOPY_LOG_LEVEL=ERROR

log "Ensuring container ${BENCH_CONTAINER} exists"
"${BBB_BIN}" az mkcontainer "az://${BENCH_ACCOUNT}/${BENCH_CONTAINER}" >/dev/null 2>&1 || true

SAS="$("${BENCH_PYTHON}" - "${BENCH_ACCOUNT}" "${BENCH_CONTAINER}" "${BENCH_KEY}" <<'PY'
import sys
from datetime import datetime, timedelta, timezone

from azure.storage.blob import ContainerSasPermissions, generate_container_sas

account, container, key = sys.argv[1:4]
sys.stdout.write(
    generate_container_sas(
        account_name=account,
        container_name=container,
        account_key=key,
        permission=ContainerSasPermissions(
            read=True, add=True, create=True, write=True, delete=True, list=True
        ),
        expiry=datetime.now(timezone.utc) + timedelta(hours=2),
    )
)
PY
)"

log "Generating ${BENCH_SIZE_MB} MiB test file"
dd if=/dev/urandom of="${SRC_FILE}" bs=1M count="${BENCH_SIZE_MB}" status=none
SRC_MD5="$(md5sum "${SRC_FILE}" | awk '{ print $1 }')"
log "Test file MD5: ${SRC_MD5}"

# ---------------------------------------------------------------------------
# Per-tool transfer commands. Each tool gets its own blob name so runs do not
# clobber one another.
# ---------------------------------------------------------------------------

bbb_upload()    { "${BBB_BIN}" cp -f --concurrency "${BENCH_CONCURRENCY}" "${SRC_FILE}" "az://${BENCH_ACCOUNT}/${BENCH_CONTAINER}/bench-bbb.bin"; }
bbb_download()  { "${BBB_BIN}" cp -f --concurrency "${BENCH_CONCURRENCY}" "az://${BENCH_ACCOUNT}/${BENCH_CONTAINER}/bench-bbb.bin" "${WORKDIR}/dl-bbb.bin"; }
# S2S StageBlockFromURL has near-zero per-call client cost, but the cap
# defaults to the caller's --concurrency to respect parallel-copy budgeting.
# On low-vCPU CI runners (--concurrency = nproc = 4) that under-pipelines a
# single large copy; raise the cap to the hard ceiling for the bench so we
# measure server-side throughput rather than 4-way client serialisation.
bbb_s2s()       { BBB_AZBLOB_COPY_CONCURRENCY_MAX=256 "${BBB_BIN}" cp -f --concurrency "${BENCH_CONCURRENCY}" "az://${BENCH_ACCOUNT}/${BENCH_CONTAINER}/bench-bbb.bin" "az://${BENCH_ACCOUNT}/${BENCH_CONTAINER}/bench-bbb-s2s.bin" 2>&1 | tee -a "${WORKDIR}/bbb-s2s.log" >/dev/null; }

# ${PYBBB} is intentionally left unquoted so that multi-word commands such as
# the default "python -m boostedblob" word-split into separate arguments.
pybbb_upload()   { ${PYBBB} cp "${SRC_FILE}" "az://${BENCH_ACCOUNT}/${BENCH_CONTAINER}/bench-pybbb.bin"; }
pybbb_download() { ${PYBBB} cp "az://${BENCH_ACCOUNT}/${BENCH_CONTAINER}/bench-pybbb.bin" "${WORKDIR}/dl-pybbb.bin"; }
pybbb_s2s()      { ${PYBBB} cp "az://${BENCH_ACCOUNT}/${BENCH_CONTAINER}/bench-pybbb.bin" "az://${BENCH_ACCOUNT}/${BENCH_CONTAINER}/bench-pybbb-s2s.bin"; }

azcopy_upload()   { "${AZCOPY_BIN}" copy "${SRC_FILE}" "${BLOB_HOST}/${BENCH_CONTAINER}/bench-azcopy.bin?${SAS}" --overwrite=true; }
azcopy_download() { "${AZCOPY_BIN}" copy "${BLOB_HOST}/${BENCH_CONTAINER}/bench-azcopy.bin?${SAS}" "${WORKDIR}/dl-azcopy.bin" --overwrite=true; }
azcopy_s2s()      { "${AZCOPY_BIN}" copy "${BLOB_HOST}/${BENCH_CONTAINER}/bench-azcopy.bin?${SAS}" "${BLOB_HOST}/${BENCH_CONTAINER}/bench-azcopy-s2s.bin?${SAS}" --overwrite=true --s2s-preserve-access-tier=false; }

# Prime each upload once so the download benchmark has a blob to read, and so
# the first (often slower) connection setup is not counted in the timing.
log "Priming uploads"
bbb_upload    >/dev/null 2>&1 || { log "bbb upload failed";    exit 1; }
pybbb_upload  >/dev/null 2>&1 || { log "py-bbb upload failed"; exit 1; }
azcopy_upload >/dev/null 2>&1 || { log "azcopy upload failed"; exit 1; }

# ---------------------------------------------------------------------------
# Run the benchmark.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Run the benchmark. Upload + download first (each tool's last download is
# verified for byte-for-byte integrity below), then S2S separately — keeping
# the integrity check independent of the S2S step.
# ---------------------------------------------------------------------------
declare -A UP DOWN S2S
for tool in bbb pybbb azcopy; do
  log "Benchmarking ${tool} upload (${BENCH_RUNS} runs)"
  UP[${tool}]="$(best_of "${tool}_upload")"
  log "Benchmarking ${tool} download (${BENCH_RUNS} runs)"
  DOWN[${tool}]="$(best_of "${tool}_download")"
done

# ---------------------------------------------------------------------------
# Integrity check: every tool's last download must round-trip the test file
# byte-for-byte (verified via MD5), so a corrupt or truncated transfer fails the
# benchmark instead of being reported as a result.
# ---------------------------------------------------------------------------
log "Verifying upload/download integrity (MD5)"
verify_md5 "bbb"        "${WORKDIR}/dl-bbb.bin"
verify_md5 "py-bbb"     "${WORKDIR}/dl-pybbb.bin"
verify_md5 "azcopy"     "${WORKDIR}/dl-azcopy.bin"

for tool in bbb pybbb azcopy; do
  log "Benchmarking ${tool} s2s copy (${BENCH_RUNS} runs)"
  S2S[${tool}]="$(best_of "${tool}_s2s")"
done

if [ -s "${WORKDIR}/bbb-s2s.log" ]; then
  log "bbb s2s stderr (first lines):"
  head -20 "${WORKDIR}/bbb-s2s.log" | sed 's/^/  /' >&2
fi

# ---------------------------------------------------------------------------
# Report.
# ---------------------------------------------------------------------------
emit() { printf '%s\n' "$1"; if [ -n "${BENCH_SUMMARY_FILE:-}" ]; then printf '%s\n' "$1" >>"${BENCH_SUMMARY_FILE}"; fi; }

# ---------------------------------------------------------------------------
# Tool identity labels for the report: bbb's short commit sha, and the actual
# installed versions of boostedblob and azcopy, so the table records exactly
# what was compared. Each falls back to a bare name if its version can't be
# resolved.
# ---------------------------------------------------------------------------
BBB_VERSION="${BBB_VERSION:-}"
BBB_LABEL="bbb (this repo)"
[ -n "${BBB_VERSION}" ] && BBB_LABEL="bbb (${BBB_VERSION})"

PYBBB_VERSION="$("${BENCH_PYTHON}" -m pip show boostedblob 2>/dev/null | awk -F': ' '/^Version:/ { print $2; exit }')"
PYBBB_LABEL="boostedblob"
[ -n "${PYBBB_VERSION}" ] && PYBBB_LABEL="boostedblob (${PYBBB_VERSION})"

AZCOPY_VERSION="$("${AZCOPY_BIN}" --version 2>/dev/null | awk '{ print $NF; exit }')"
AZCOPY_LABEL="azcopy"
[ -n "${AZCOPY_VERSION}" ] && AZCOPY_LABEL="azcopy (${AZCOPY_VERSION})"

emit "### Transfer benchmark (Azurite emulator) — ${BENCH_SIZE_MB} MiB, best of ${BENCH_RUNS}, concurrency ${BENCH_CONCURRENCY}"
emit ""
emit "| Tool | Upload (s) | Upload MB/s | Download (s) | Download MB/s | S2S Copy (s) | S2S MB/s |"
emit "|------|-----------:|------------:|-------------:|--------------:|-------------:|---------:|"
emit "| ${BBB_LABEL} | ${UP[bbb]} | $(mbps "${UP[bbb]}") | ${DOWN[bbb]} | $(mbps "${DOWN[bbb]}") | ${S2S[bbb]} | $(mbps "${S2S[bbb]}") |"
emit "| ${PYBBB_LABEL} | ${UP[pybbb]} | $(mbps "${UP[pybbb]}") | ${DOWN[pybbb]} | $(mbps "${DOWN[pybbb]}") | ${S2S[pybbb]} | $(mbps "${S2S[pybbb]}") |"
emit "| ${AZCOPY_LABEL} | ${UP[azcopy]} | $(mbps "${UP[azcopy]}") | ${DOWN[azcopy]} | $(mbps "${DOWN[azcopy]}") | ${S2S[azcopy]} | $(mbps "${S2S[azcopy]}") |"
emit ""
emit "> The Azurite emulator is CPU/loopback-bound, so absolute numbers measure client-side overhead rather than real network throughput. S2S regressions are gated against azcopy only because py-bbb's async StartCopyFromURL is acked instantly on Azurite."

# ---------------------------------------------------------------------------
# Cleanup blobs.
# ---------------------------------------------------------------------------
log "Cleaning up benchmark blobs"
for name in bench-bbb.bin bench-pybbb.bin bench-azcopy.bin bench-bbb-s2s.bin bench-pybbb-s2s.bin bench-azcopy-s2s.bin; do
  "${BBB_BIN}" rm -f "az://${BENCH_ACCOUNT}/${BENCH_CONTAINER}/${name}" >/dev/null 2>&1 || true
done

# ---------------------------------------------------------------------------
# Optional regression gate.
# ---------------------------------------------------------------------------
if [ -n "${BENCH_FAIL_FACTOR:-}" ]; then
  fail=0
  # py-bbb's S2S uses async StartCopyFromURL which Azurite acknowledges
  # before bytes actually move (sub-second for 1 GiB), so for S2S we gate
  # only against azcopy. For upload/download both peers are comparable.
  for direction in UP DOWN S2S; do
    declare -n times="${direction}"
    if [ "${direction}" = "S2S" ]; then
      others_best="${times[azcopy]}"
    else
      others_best="$(awk -v a="${times[pybbb]}" -v b="${times[azcopy]}" 'BEGIN { print (a < b ? a : b) }')"
    fi
    if awk -v bbb="${times[bbb]}" -v other="${others_best}" -v f="${BENCH_FAIL_FACTOR}" \
        'BEGIN { exit !(bbb > other * f) }'; then
      log "REGRESSION: bbb ${direction} ${times[bbb]}s is slower than ${others_best}s * ${BENCH_FAIL_FACTOR}"
      fail=1
    fi
  done
  [ "${fail}" -eq 0 ] || exit 1
fi

log "Benchmark complete"
