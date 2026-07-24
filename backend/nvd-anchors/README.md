# NVD cache anchors (Rule #37 — offline-trust-anchor discipline)

The **pinned NVD cache** gives wairz reproducible, offline, provenance-stamped CVE
lookup (see `app/services/nvd_cache_service.py`). Unlike the other Rule #37 anchors
in `backend/ms-anchors/` (dbxupdate.bin, loldrivers.json — small, **baked into the
image**), the NVD cache is **~369k files / ~2 GB** and is therefore **NOT baked and
NOT committed**. It lives on the `nvd_cache_data` Docker volume, populated
out-of-band by `scripts/refresh-nvd-cache.sh`. Only the small **pin** is tracked:

| File | Purpose |
|------|---------|
| `nvd-cache.url` | canonical source feed (`EMBA-support-repos/nvd-json-data-feeds`) |
| `nvd-cache.sha256` | the pinned feed **git commit** — the reproducibility anchor |
| `README.md` | this file |

The worker + backend read the volume **fully offline** at scan time
(`NVD_CACHE_PATH=/opt/wairz/nvd-cache`, both services). Live NVD is an **explicit
opt-in fallback only** (`NVD_ALLOW_LIVE_FALLBACK`, default `false`) — a cache miss
with the flag off records a truthful "no CVE enrichment", never a fabricated clean
verdict.

## First-time bootstrap (required before offline scans work)

The volume ships **empty**. Populate it once:

```bash
# 1. Clone the feed (or point NVD_FEED_DIR at an existing clone):
git clone https://github.com/EMBA-support-repos/nvd-json-data-feeds ~/nvd-json-data-feeds

# 2. Populate the volume + build the cpe->cve index + write MANIFEST.json + pin:
scripts/refresh-nvd-cache.sh --apply
```

`refresh-nvd-cache.sh` (no flags) verifies the feed's git commit against the pin
and exits 2 on drift. `--apply` pulls the feed, tar-streams it into the volume,
builds `cpe_index.json` in-container, writes `MANIFEST.json` (sha256 = feed
commit), and bumps `nvd-cache.sha256` (review + commit the pin).

## Refresh cadence

NVD publishes new/modified CVEs continuously; the EMBA feed regenerates daily.
Refresh on your own schedule (e.g. weekly) — every scan against the same pin is
byte-reproducible, so a stale pin degrades *coverage*, never *correctness*.
Recommended cron (weekly, UTC Sun 04:15):

```
15 4 * * 0 [REPO]/scripts/refresh-nvd-cache.sh --apply 2>&1 | logger -t wairz-refresh-nvd
```

## Startup probe

The backend lifespan logs the cache status at boot (`app/main.py`):
`NVD cache ready: path=… manifest_sha=… populated_at=… cve_count=N`, or a
`NOT FOUND` warning pointing here. Anything other than `ready` is a cron-alert
candidate.
