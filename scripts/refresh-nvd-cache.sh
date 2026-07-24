#!/bin/bash
# refresh-nvd-cache.sh — Rule #37 offline-trust-anchor refresh for the pinned NVD
# cache. Populates the nvd_cache_data Docker volume from the EMBA
# nvd-json-data-feeds git feed, builds cpe_index.json, and writes MANIFEST.json,
# pinned by the feed's git commit (backend/nvd-anchors/nvd-cache.sha256). The
# worker + backend read the volume FULLY OFFLINE at scan time; this host-side
# script is the only path that touches the feed.
#
# Usage:
#   scripts/refresh-nvd-cache.sh              # verify feed commit == pin (exit 2 on drift)
#   scripts/refresh-nvd-cache.sh --apply      # pull feed + populate volume + build index + bump pin
#   NVD_FEED_DIR=/path/to/clone scripts/refresh-nvd-cache.sh --apply
#
# Exit codes: 0 ok; 2 drift (feed commit != pin, without --apply); 3 setup failure.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANCHORS="${REPO_ROOT}/backend/nvd-anchors"
PIN_FILE="${ANCHORS}/nvd-cache.sha256"
URL_FILE="${ANCHORS}/nvd-cache.url"
FEED_DIR="${NVD_FEED_DIR:-${HOME}/nvd-json-data-feeds}"
VOLUME_PATH="/opt/wairz/nvd-cache"   # mount path inside the backend container
BACKEND_SVC="backend"
APPLY=0
[[ "${1:-}" == "--apply" ]] && APPLY=1

command -v git >/dev/null 2>&1 || { echo "ERROR: git required" >&2; exit 3; }
command -v docker >/dev/null 2>&1 || { echo "ERROR: docker required" >&2; exit 3; }
SRC_URL="$(tr -d '[:space:]' < "${URL_FILE}")"
[[ -d "${FEED_DIR}/.git" ]] || {
  echo "ERROR: ${FEED_DIR} is not a git clone of nvd-json-data-feeds" >&2
  echo "       clone it first: git clone ${SRC_URL} ${FEED_DIR}" >&2
  exit 3
}

# Best-effort pull to pick up the latest feed. Failure is NON-FATAL (this is an
# offline-first Rule #37 tool — an air-gapped host populates from the existing
# clone at its pinned commit). Set NVD_SKIP_PULL=1 to skip the network attempt.
if [[ "${APPLY}" -eq 1 && "${NVD_SKIP_PULL:-0}" != "1" ]]; then
  echo "[refresh-nvd] git pull ${FEED_DIR} ..."
  git -C "${FEED_DIR}" pull --ff-only --quiet \
    || echo "[refresh-nvd] WARNING: git pull failed (offline?) — populating from the" \
            "current checkout $(git -C "${FEED_DIR}" rev-parse --short HEAD)" >&2
fi

HEAD_COMMIT="$(git -C "${FEED_DIR}" rev-parse HEAD)"
PINNED="$(tr -d '[:space:]' < "${PIN_FILE}" 2>/dev/null || true)"
COUNT="$(find "${FEED_DIR}" -name 'CVE-*.json' 2>/dev/null | wc -l | tr -d ' ')"

# Sanity floor: the feed carries 300k+ CVE files; a near-empty tree is a broken clone.
if [[ "${COUNT}" -lt 300000 ]]; then
  echo "ERROR: only ${COUNT} CVE files under ${FEED_DIR} (<300000 floor) — refusing to populate" >&2
  exit 3
fi

if [[ "${APPLY}" -eq 0 ]]; then
  if [[ -n "${PINNED}" && "${PINNED}" != "${HEAD_COMMIT}" ]]; then
    echo "DRIFT: pinned ${PINNED} != feed HEAD ${HEAD_COMMIT}" >&2
    echo "       (to adopt HEAD run with --apply, review the pin diff, and commit ${PIN_FILE})" >&2
    exit 2
  fi
  echo "[refresh-nvd] feed commit ${HEAD_COMMIT} (${COUNT} CVEs) matches pin — no action needed."
  exit 0
fi

# --apply: populate the named volume via a tar stream into the backend mount.
echo "[refresh-nvd] populating ${VOLUME_PATH} (${COUNT} files — a few minutes) ..."
docker compose exec -T "${BACKEND_SVC}" sh -c \
  "rm -rf ${VOLUME_PATH}/CVE-* ${VOLUME_PATH}/cpe_index.json ${VOLUME_PATH}/MANIFEST.json 2>/dev/null; mkdir -p ${VOLUME_PATH}"
tar -C "${FEED_DIR}" --exclude='./.git' -cf - . \
  | docker compose exec -T "${BACKEND_SVC}" tar -C "${VOLUME_PATH}" -xf -

echo "[refresh-nvd] building cpe_index.json (walks ${COUNT} files) ..."
docker compose exec -T -w /app -e PYTHONPATH=/app "${BACKEND_SVC}" /app/.venv/bin/python -c \
  "from app.services.nvd_cache_service import build_cpe_index; print('[index]', build_cpe_index('${VOLUME_PATH}'))"

NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
docker compose exec -T "${BACKEND_SVC}" sh -c \
  "printf '{\"sha256\": \"%s\", \"populated_at\": \"%s\", \"cve_count\": %s, \"source_repo\": \"%s\"}\n' \
    '${HEAD_COMMIT}' '${NOW}' '${COUNT}' '${SRC_URL}' > ${VOLUME_PATH}/MANIFEST.json"

echo "${HEAD_COMMIT}" > "${PIN_FILE}"
echo "[refresh-nvd] done: populated + indexed + pinned ${HEAD_COMMIT} (${COUNT} CVEs)."
echo "[refresh-nvd] REVIEW + COMMIT ${PIN_FILE}. The worker shares the same volume (no separate step)."
