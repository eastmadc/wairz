#!/bin/bash
# refresh-nvd-cache.sh — Rule #37 offline-trust-anchor refresh + INTEGRITY GATE
# for the pinned NVD cache. Populates the nvd_cache_data Docker volume from the
# EMBA nvd-json-data-feeds git feed, builds cpe_index.json, and writes
# MANIFEST.json. The worker + backend read the volume FULLY OFFLINE at scan
# time; this host-side script is the only path that touches the feed.
#
# The pin (backend/nvd-anchors/nvd-cache.sha256) is a CONTENT digest that is
# RE-DERIVED FROM THE VOLUME'S BYTES — not the upstream git commit. Rule #37
# requires the refresh tool to "compute SHA256, compare against the pinned
# hash, exit non-zero on drift"; a commit hash cannot do that, because a feed
# that silently REMOVES CVEs still matches its own commit while every
# downstream verdict keeps reporting `enrichment_status: complete`.
#
# Adopting a new pin is a DELIBERATE, REVIEWED act: --apply populates and
# reports the new digest but NEVER moves the pin. Only --adopt-pin writes it.
# Do NOT cron --apply: an automated adopt-whatever-upstream-published defeats
# the review step the pin exists to force (Rule #37: "the operator reviews +
# commits + rebuilds"). Cron the no-flag VERIFY instead and alert on non-zero.
#
# Usage:
#   scripts/refresh-nvd-cache.sh                    # VERIFY volume vs pin (default)
#   scripts/refresh-nvd-cache.sh --verify           # same, explicit
#   scripts/refresh-nvd-cache.sh --apply            # pull + populate + index + manifest
#   scripts/refresh-nvd-cache.sh --apply --adopt-pin  # ...and adopt the new pin
#   NVD_FEED_DIR=/path/to/clone scripts/refresh-nvd-cache.sh --apply
#   NVD_SKIP_PULL=1 ...                             # populate from the clone as-is
#
# Exit codes:
#   0  ok — the volume's re-derived content digest matches the pin
#   2  FEED drift — the feed clone's HEAD differs from the manifest's
#      feed_commit (upstream moved; coverage is stale, integrity is intact)
#   3  setup failure (missing docker/git/feed clone, container unreachable)
#   4  INTEGRITY DRIFT — the volume's content digest does NOT match the pin.
#      The volume was tampered with, truncated, or repopulated from a
#      different feed without review. THIS IS THE SECURITY-RELEVANT ONE.
#   5  NOT VERIFIABLE — no pin recorded, or the volume/manifest is absent or
#      predates content pinning. Deliberately NOT 0: "never pinned" is not
#      evidence of integrity.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANCHORS="${REPO_ROOT}/backend/nvd-anchors"
PIN_FILE="${ANCHORS}/nvd-cache.sha256"
URL_FILE="${ANCHORS}/nvd-cache.url"
FEED_DIR="${NVD_FEED_DIR:-${HOME}/nvd-json-data-feeds}"
VOLUME_PATH="/opt/wairz/nvd-cache"   # mount path inside the backend container
BACKEND_SVC="backend"

APPLY=0
ADOPT=0
for arg in "$@"; do
  case "${arg}" in
    --apply)     APPLY=1 ;;
    --verify)    APPLY=0 ;;
    --adopt-pin) ADOPT=1 ;;
    -h|--help)   sed -n '2,40p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "ERROR: unknown argument '${arg}'" >&2; exit 3 ;;
  esac
done
if [[ "${ADOPT}" -eq 1 && "${APPLY}" -eq 0 ]]; then
  echo "ERROR: --adopt-pin only makes sense with --apply" >&2
  echo "       (the pin is adopted from a volume this run populated, never from" >&2
  echo "        one it merely inspected)" >&2
  exit 3
fi

command -v docker >/dev/null 2>&1 || { echo "ERROR: docker required" >&2; exit 3; }
SRC_URL="$(tr -d '[:space:]' < "${URL_FILE}")"
PINNED="$(tr -d '[:space:]' < "${PIN_FILE}" 2>/dev/null || true)"

# ── helpers ──────────────────────────────────────────────────────────────────
# Every helper runs the command DIRECTLY (no pipeline) so "$?" / "if ! cmd"
# reflects the command's own status. `cmd | tail` would report tail's exit and
# silently launder a failure (Rule #35a).

_in_backend() {
  docker compose exec -T -w /app -e PYTHONPATH=/app "${BACKEND_SVC}" \
    /app/.venv/bin/python -c "$1"
}

# "<content_sha256> <file_count> <total_bytes>" re-derived from the volume.
# Walks ~369k files / ~2 GB — minutes, by design: this is the out-of-band gate.
_volume_digest() {
  _in_backend "
import sys
from app.services.nvd_cache_service import compute_content_digest
d = compute_content_digest('${VOLUME_PATH}')
sys.stdout.write('%s %d %d' % (d['content_sha256'], d['file_count'], d['total_bytes']))
"
}

# "<feed_commit> <content_sha256> <populated_at> <cve_count>", '-' when absent.
_volume_manifest() {
  _in_backend "
import json, sys
try:
    m = json.load(open('${VOLUME_PATH}/MANIFEST.json'))
except Exception:
    m = {}
sys.stdout.write(' '.join(str(m.get(k) or '-') for k in
                 ('feed_commit', 'content_sha256', 'populated_at', 'cve_count')))
"
}

# ── VERIFY (default) ─────────────────────────────────────────────────────────
if [[ "${APPLY}" -eq 0 ]]; then
  MANIFEST_OUT=""
  if ! MANIFEST_OUT="$(_volume_manifest)"; then
    echo "ERROR: cannot reach the '${BACKEND_SVC}' container to read the volume" >&2
    exit 3
  fi
  read -r M_FEED_COMMIT M_CONTENT_SHA M_POPULATED_AT M_CVE_COUNT <<< "${MANIFEST_OUT}"

  if [[ "${M_POPULATED_AT}" == "-" ]]; then
    echo "NOT VERIFIABLE: no MANIFEST.json on ${VOLUME_PATH} — the volume is empty." >&2
    echo "                bootstrap it: scripts/refresh-nvd-cache.sh --apply --adopt-pin" >&2
    exit 5
  fi
  if [[ -z "${PINNED}" ]]; then
    echo "NOT VERIFIABLE: ${PIN_FILE} records no pin." >&2
    echo "                An unpinned volume cannot be checked; 'never pinned' is" >&2
    echo "                not evidence of integrity. Adopt one with --apply --adopt-pin." >&2
    exit 5
  fi
  if [[ "${#PINNED}" -ne 64 ]]; then
    echo "NOT VERIFIABLE: the pin '${PINNED}' is not a 64-hex content digest." >&2
    echo "                Pre-2026-07-25 pins recorded the upstream FEED COMMIT, which" >&2
    echo "                is a provenance label, not an integrity gate. Re-derive one:" >&2
    echo "                scripts/refresh-nvd-cache.sh --apply --adopt-pin" >&2
    exit 5
  fi

  echo "[refresh-nvd] re-deriving the content digest from ${VOLUME_PATH} (minutes) ..."
  DIGEST_OUT=""
  if ! DIGEST_OUT="$(_volume_digest)"; then
    echo "ERROR: failed to compute the volume's content digest" >&2
    exit 3
  fi
  read -r VOL_DIGEST VOL_FILES VOL_BYTES <<< "${DIGEST_OUT}"

  if [[ "${VOL_DIGEST}" != "${PINNED}" ]]; then
    echo "INTEGRITY DRIFT: the volume does NOT match the pin." >&2
    echo "  pinned:  ${PINNED}" >&2
    echo "  derived: ${VOL_DIGEST}   (${VOL_FILES} CVE files, ${VOL_BYTES} bytes)" >&2
    echo "  The volume was tampered with, truncated, or repopulated from a" >&2
    echo "  different feed without review. CVE verdicts from this cache are NOT" >&2
    echo "  attributable to pin ${PINNED}. Investigate before scanning; adopt a" >&2
    echo "  new pin only deliberately: --apply --adopt-pin." >&2
    exit 4
  fi
  echo "[refresh-nvd] INTEGRITY OK: ${VOL_FILES} CVE files match pin ${PINNED}"
  echo "[refresh-nvd] populated_at=${M_POPULATED_AT} cve_count=${M_CVE_COUNT} feed_commit=${M_FEED_COMMIT}"
  if [[ "${M_CONTENT_SHA}" != "${VOL_DIGEST}" ]]; then
    echo "[refresh-nvd] NOTE: MANIFEST.json records content_sha256=${M_CONTENT_SHA};" >&2
    echo "              the volume re-derives to ${VOL_DIGEST}. The pin matches the" >&2
    echo "              volume, so scanning is safe, but the manifest is stale —" >&2
    echo "              re-run --apply to rewrite it." >&2
  fi

  # Coverage (not integrity): has upstream moved past what we populated from?
  # Only meaningful when a feed clone is present; an air-gapped host skips it.
  if [[ -d "${FEED_DIR}/.git" ]] && command -v git >/dev/null 2>&1; then
    HEAD_COMMIT="$(git -C "${FEED_DIR}" rev-parse HEAD)"
    if [[ "${M_FEED_COMMIT}" != "-" && "${M_FEED_COMMIT}" != "${HEAD_COMMIT}" ]]; then
      echo "FEED DRIFT: volume populated from ${M_FEED_COMMIT}, clone HEAD is ${HEAD_COMMIT}" >&2
      echo "            Coverage is stale (correctness is not — every scan against this" >&2
      echo "            pin stays byte-reproducible). Refresh deliberately when you want" >&2
      echo "            the newer CVEs: --apply, review the digest, then --adopt-pin." >&2
      exit 2
    fi
  fi
  exit 0
fi

# ── APPLY ────────────────────────────────────────────────────────────────────
command -v git >/dev/null 2>&1 || { echo "ERROR: git required for --apply" >&2; exit 3; }
[[ -d "${FEED_DIR}/.git" ]] || {
  echo "ERROR: ${FEED_DIR} is not a git clone of nvd-json-data-feeds" >&2
  echo "       clone it first: git clone ${SRC_URL} ${FEED_DIR}" >&2
  exit 3
}

# Best-effort pull to pick up the latest feed. Failure is NON-FATAL (this is an
# offline-first Rule #37 tool — an air-gapped host populates from the existing
# clone at its pinned commit). Set NVD_SKIP_PULL=1 to skip the network attempt.
if [[ "${NVD_SKIP_PULL:-0}" != "1" ]]; then
  echo "[refresh-nvd] git pull ${FEED_DIR} ..."
  git -C "${FEED_DIR}" pull --ff-only --quiet \
    || echo "[refresh-nvd] WARNING: git pull failed (offline?) — populating from the" \
            "current checkout $(git -C "${FEED_DIR}" rev-parse --short HEAD)" >&2
fi

HEAD_COMMIT="$(git -C "${FEED_DIR}" rev-parse HEAD)"
COUNT="$(find "${FEED_DIR}" -name 'CVE-*.json' 2>/dev/null | wc -l | tr -d ' ')"

# Sanity floor: the feed carries 300k+ CVE files; a near-empty tree is a broken
# clone. A liveness check, NOT integrity — the digest below is the integrity gate.
if [[ "${COUNT}" -lt 300000 ]]; then
  echo "ERROR: only ${COUNT} CVE files under ${FEED_DIR} (<300000 floor) — refusing to populate" >&2
  exit 3
fi

echo "[refresh-nvd] populating ${VOLUME_PATH} (${COUNT} files — a few minutes) ..."
docker compose exec -T "${BACKEND_SVC}" sh -c \
  "rm -rf ${VOLUME_PATH}/CVE-* ${VOLUME_PATH}/cpe_index.json ${VOLUME_PATH}/MANIFEST.json 2>/dev/null; mkdir -p ${VOLUME_PATH}"
tar -C "${FEED_DIR}" --exclude='./.git' -cf - . \
  | docker compose exec -T "${BACKEND_SVC}" tar -C "${VOLUME_PATH}" -xf -

echo "[refresh-nvd] building cpe_index.json (walks ${COUNT} files) ..."
_in_backend "
from app.services.nvd_cache_service import build_cpe_index
print('[index]', build_cpe_index('${VOLUME_PATH}'))
"

echo "[refresh-nvd] deriving the content digest from the VOLUME (minutes) ..."
DIGEST_OUT=""
if ! DIGEST_OUT="$(_volume_digest)"; then
  echo "ERROR: failed to compute the volume's content digest after populate" >&2
  exit 3
fi
read -r VOL_DIGEST VOL_FILES VOL_BYTES <<< "${DIGEST_OUT}"

# cve_count is measured ON THE VOLUME, not taken from the feed clone: a partial
# tar leaves fewer files than the feed declared, and a manifest that reports the
# feed's number over-states what a scan can actually reach.
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
_in_backend "
import json
json.dump({
    'sha256': '${VOL_DIGEST}',            # generation identity == content digest
    'content_sha256': '${VOL_DIGEST}',    # explicit, re-derivable from the bytes
    'digest_version': 1,
    'feed_commit': '${HEAD_COMMIT}',      # provenance label, NOT an integrity gate
    'populated_at': '${NOW}',
    'cve_count': ${VOL_FILES},
    'content_bytes': ${VOL_BYTES},
    'source_repo': '${SRC_URL}',
}, open('${VOLUME_PATH}/MANIFEST.json', 'w'))
print('[manifest] written')
"

echo "[refresh-nvd] populated + indexed: ${VOL_FILES} CVE files, ${VOL_BYTES} bytes"
echo "[refresh-nvd] content digest: ${VOL_DIGEST}"
echo "[refresh-nvd] feed commit:    ${HEAD_COMMIT}"

if [[ "${ADOPT}" -eq 1 ]]; then
  echo "${VOL_DIGEST}" > "${PIN_FILE}"
  echo "${HEAD_COMMIT}" > "${ANCHORS}/nvd-cache.commit"
  echo "[refresh-nvd] PIN ADOPTED. REVIEW + COMMIT ${PIN_FILE} and ${ANCHORS}/nvd-cache.commit."
  echo "[refresh-nvd] The worker shares the same volume (no separate step)."
  exit 0
fi

if [[ "${PINNED}" == "${VOL_DIGEST}" ]]; then
  echo "[refresh-nvd] digest matches the existing pin — nothing to adopt."
  exit 0
fi
echo "NOT ADOPTED: the pin was left at '${PINNED:-<none>}'." >&2
echo "             --apply deliberately does NOT move the pin. Review the change" >&2
echo "             (what the feed added/removed since ${PINNED:-<none>}), then adopt:" >&2
echo "               scripts/refresh-nvd-cache.sh --apply --adopt-pin" >&2
echo "             Until then the volume will FAIL verification (exit 4), which is" >&2
echo "             correct: it holds content no reviewed pin vouches for." >&2
exit 4
