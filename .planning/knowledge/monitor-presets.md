# Monitor Tool — Filter Presets

> Extracted: 2026-04-18
> Purpose: reusable `Monitor` command recipes for Wairz operational
>          watch tasks.  Copy / paste into the `command` field.

The backend binds `0.0.0.0:8000` and the LAN is noisy (Joomla /
VMware IDM / ServiceNow / SAAS API scanners hammering 404 paths daily).
Any filter that accepts generic `error|404|500|Failed` will flood the
agent context with garbage.  Use these scoped presets instead.

---

## Preset 1 — unpack pipeline watch (extraction events + real errors)

Use when: running a firmware upload, want to see extraction progress
and catch genuine failures without scanner noise.

```bash
docker compose logs -f --tail=0 backend worker 2>&1 \
  | stdbuf -oL grep -Ei --line-buffered \
    "Firmware classified|Extracted |Relocated |Identified |Skipped |\
Removed super|Converted .* sparse|Scatter-zip|\
Found [0-9]+ partition|Extracted [0-9]+/[0-9]+|\
Extraction complete|Hardware firmware detection|Hardware firmware graph|\
WARNING: Extraction bomb|Extraction bomb detected|\
Traceback|CancelledError|OutOfMemory|OOM|Killed|disk full|No space|\
unpack_firmware_job.*failed|unpack_firmware.*error|\
fsck\.erofs.*failed|debugfs.*failed|payload-dumper.*failed"
```

What it catches:
- Every line from the extractor (`Extracted`, `Relocated`, `Identified`)
- Post-scan summaries (`Extracted 8/8 partitions`, `Extraction complete`)
- The three fix-signal markers: `Skipped … user-data partition`,
  `Removed super.img.raw …`, `WARNING: Extraction bomb … kept`.
- Real errors: tracebacks, OOM, disk full, CancelledError.

What it does NOT catch:
- Scanner 404s (no generic `404|Failed` token)
- Uvicorn `Invalid HTTP request` noise (malformed request parser)
- Normal 2xx API traffic.

---

## Preset 2 — production error watch (no extraction context)

Use when: not actively extracting firmware, just want to know if the
backend goes sideways.

```bash
docker compose logs -f --tail=0 backend worker 2>&1 \
  | stdbuf -oL grep -Ei --line-buffered \
    "Traceback|^.*ERROR.*app\.|^.*CRITICAL|\
500 Internal Server Error|502 Bad Gateway|503 Service Unavailable|\
asyncpg\.exceptions|sqlalchemy\.exc|\
CancelledError|OutOfMemory|OOM|Killed|\
unpack_firmware.*failed|ghidra.*failed|arq.*job failed|\
DATABASE.*connection|disk full|No space"
```

What it catches:
- Python tracebacks
- Real 5xx server errors (not scanner 4xx)
- DB-layer exceptions (asyncpg + SQLAlchemy)
- Background-job failures

What it does NOT catch:
- 4xx (scanner noise)
- Routine `INFO:` log lines

---

## Preset 3 — CVE matcher progress

Use when: running the CVE match job on a large firmware, want to
know when it finishes and whether each tier succeeded.

```bash
docker compose logs -f --tail=0 backend worker 2>&1 \
  | stdbuf -oL grep -Ei --line-buffered \
    "cve_matcher|match_firmware_cves|_match_parser_detected|\
_match_curated_yaml|_match_chipset|_match_kernel|\
Persisted [0-9]+ cve match|\
Tier [0-9].*completed|tier=[a-z_]+|\
Traceback|failed to match"
```

---

## Preset 4 — hardware firmware detection watch

Use when: re-running detection after a fix that affects
`firmware_paths.get_detection_roots`, want to see root computation and
blob discovery.

```bash
docker compose logs -f --tail=0 backend worker 2>&1 \
  | stdbuf -oL grep -Ei --line-buffered \
    "Hardware firmware detector|hardware_firmware|detection_roots|\
walking [0-9]+ root|root=.*yielded [0-9]+|\
persisted [0-9]+ blob|firmware graph|\
Traceback|failed"
```

---

## Anti-preset — what NOT to use

```bash
# DON'T — catches every scanner 404, every "Invalid HTTP request",
# every INFO log containing the word "error" anywhere.
grep -Ei "error|Failed|WARNING|404|timeout"
```

This was the initial filter on 2026-04-18 that had to be stopped after
six bursts of scanner noise.  Generic tokens in a scoped grep look
reasonable in a quiet dev environment and fall apart the moment the
service is LAN- or internet-reachable.

---

## Rules of thumb

1. **Prefer path fragments (`/api/v1/`) or class names (`asyncpg`,
   `sqlalchemy`) over HTTP status codes.** Scanners will trip status-
   code filters; they rarely trip on path fragments that don't exist
   in their probe dictionary.
2. **Anchor log-level matches.** `^.*ERROR.*app\.` (python logger
   prefix) is much tighter than bare `error`.
3. **If the preset fires more than once per minute on a quiet
   system, it's too broad.** Re-scope before you drown in events.
4. **Always include `Traceback|CancelledError|OOM`** — those are the
   signals you genuinely need and they never false-fire.
5. **Persistent watches eat context fast.** Prefer a short timeout
   (`timeout_ms: 600000`) for most tasks; use `persistent: true` only
   for long-running campaigns.
