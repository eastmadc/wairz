# NVD cache anchors (Rule #37 — offline-trust-anchor discipline)

The **pinned NVD cache** gives wairz reproducible, offline, provenance-stamped CVE
lookup (see `app/services/nvd_cache_service.py`). Unlike the other Rule #37 anchors
in `backend/ms-anchors/` (dbxupdate.bin, loldrivers.json — small, **baked into the
image**), the NVD cache is **~369k files / ~2.6 GB** and is therefore **NOT baked
and NOT committed**. It lives on the `nvd_cache_data` Docker volume, populated
out-of-band by `scripts/refresh-nvd-cache.sh`. Only the small **anchors** are tracked:

| File | Purpose |
|------|---------|
| `nvd-cache.url` | canonical source feed (`EMBA-support-repos/nvd-json-data-feeds`) |
| `nvd-cache.sha256` | the **content digest** of the volume — the integrity gate |
| `nvd-cache.commit` | the upstream feed **git commit** — a provenance label |
| `README.md` | this file |

The worker + backend read the volume **fully offline** at scan time
(`NVD_CACHE_PATH=/opt/wairz/nvd-cache`, both services). Live NVD is an **explicit
opt-in fallback only** (`NVD_ALLOW_LIVE_FALLBACK`, default `false`) — a cache miss
with the flag off records a truthful "no CVE enrichment", never a fabricated clean
verdict.

## The pin is a content digest, not a commit hash

`nvd-cache.sha256` holds a SHA-256 **re-derived from the bytes on the volume**:

```
outer = sha256("nvd-cache-content-digest/v1")
for relpath, file in sorted-by-relpath(CVE-*.json):     # index/manifest excluded
    outer.update(f"{relpath}\0{sha256(file bytes)}\n")
```

Sorting by relative path makes it independent of tar / filesystem walk order, so
re-extracting the same feed pins identically. Hashing the path **alongside** the
bytes makes a file landing in the wrong bucket drift — that is the shape of the
leading-zero defect that made ~8% of the cache silently unreachable.

A **git commit is not an integrity gate**. It is a label the refresh tool copies
from whatever HEAD happened to be; nothing re-derives it from what landed on the
volume. A feed that silently *removes* CVEs still matches its own commit, and
every downstream verdict then reports `enrichment_status: complete` over a cache
with holes. The commit is still recorded — in `nvd-cache.commit` and in
`MANIFEST.json`'s `feed_commit` — as provenance, which is all it can honestly be.

`MANIFEST.json` on the volume carries `content_sha256` (the same digest),
`feed_commit`, `populated_at`, and a `cve_count` **measured on the volume** (not
taken from the feed clone — a partial `tar -x` leaves fewer files than the feed
declared, and a manifest reporting the feed's number over-states what a scan can
actually reach).

## First-time bootstrap

The volume ships **empty**. Populate it once:

```bash
# 1. Clone the feed (or point NVD_FEED_DIR at an existing clone):
git clone https://github.com/EMBA-support-repos/nvd-json-data-feeds ~/nvd-json-data-feeds

# 2. Populate the volume + build the cpe->cve index + write MANIFEST.json,
#    then adopt the resulting content digest as the pin:
scripts/refresh-nvd-cache.sh --apply --adopt-pin

# 3. Review + commit backend/nvd-anchors/nvd-cache.sha256 and nvd-cache.commit.
```

## Verifying (this is the part to automate)

```bash
scripts/refresh-nvd-cache.sh            # or --verify; re-derives from the volume
```

Exit codes:

| Code | Meaning |
|-----:|---------|
| `0` | the volume's re-derived digest **matches** the pin |
| `2` | **feed drift** — the clone's HEAD moved past `MANIFEST.json`'s `feed_commit`. Coverage is stale; integrity is intact and scans stay byte-reproducible |
| `3` | setup failure (missing docker/git/feed clone, container unreachable) |
| `4` | **INTEGRITY DRIFT** — the volume does **not** match the pin: tampered, truncated, or repopulated from a different feed without review. The security-relevant one |
| `5` | **not verifiable** — no pin, or the volume/manifest is absent or predates content pinning. Deliberately not `0`: "never pinned" is not evidence of integrity |

Takes ~85 s for the full 369k-file / 2.6 GB volume (measured 2026-07-25).

## Refresh cadence — do NOT cron `--apply`

NVD publishes new/modified CVEs continuously; the EMBA feed regenerates daily.
A stale pin degrades **coverage**, never **correctness** — every scan against the
same pin is byte-reproducible.

**Adopting a new pin is a deliberate, reviewed act.** `--apply` populates the
volume and reports the new digest but **never moves the pin**; only
`--apply --adopt-pin` writes it. A cron that runs `--apply --adopt-pin` would
auto-adopt whatever upstream published, unreviewed, which is precisely the
review step the pin exists to force (Rule #37: *"Refresh is a deliberate,
out-of-band operation … the operator reviews + commits + rebuilds"*). An
attacker who can influence the feed then has an automated path to a trusted pin.

Cron the **verify** instead and alert on any non-zero exit:

```
15 4 * * 0 [REPO]/scripts/refresh-nvd-cache.sh 2>&1 | logger -t wairz-verify-nvd
```

(`logger` is a sink, not a gate — have your job runner alert on the script's exit
code. Piping to another command replaces the exit status with the *sink's*;
capture it before piping.)

When the verify reports feed drift and you want the newer CVEs, refresh by hand:

```bash
scripts/refresh-nvd-cache.sh --apply          # populate + report the new digest
#   ...review what changed, then:
scripts/refresh-nvd-cache.sh --apply --adopt-pin
```

## Startup probe

The backend lifespan logs the cache status at boot (`app/main.py`):
`NVD cache ready: path=… manifest_sha=… populated_at=… cve_count=N`, or a
`NOT FOUND` warning pointing here. `probe()` also reports `content_verifiable`
— `false` means the volume's manifest predates content pinning and
`--verify` cannot check it. Anything other than `ready` is a cron-alert candidate.
