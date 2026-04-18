# Session Handoff — 2026-04-18 (session 53c9c5ff)

> Outgoing: Opus 4.7 (1M context)
> Branch: `clean-history` (many commits ahead of origin, all uncommitted)
> Next session: Citadel pickup — read `.planning/intake/seed-next-session-2026-04-19.md` first

## What shipped this session

### 1. DPCS10 extraction bomb fix (3 surgical changes, 77/77 tests)

- `unpack_android.py`: added `_is_user_data_partition()` + `_USER_DATA_PARTITION_BASES` — skip `userdata`/`cache`/`metadata`/`persist`/`misc` (+A/B variants) before sparse→raw conversion.  Saves ~3 GB per Android firmware.
- `unpack_android.py`: `_scan_super_partitions` signature changed to `tuple[int, int]`; caller deletes `super.img.raw` after successful LP2 scan (saves ~9 GB).
- `unpack.py` (4 sites): reordered bomb-check so `_analyze_filesystem` runs first; extractions with valid rootfs keep a WARNING instead of `rmtree`.
- Live verification: DPCS10 firmware `0ed279d8` retried cleanly; extraction completed with all 260 blobs.

### 2. Detection-roots container promotion (latent bug from extraction-integrity)

- `firmware_paths._compute_roots_sync`: container itself promoted as detection root when it holds raw image files at top level (post-relocation layout).
- 3 new regression tests in `test_firmware_paths.py`.
- Re-ran detection on DPCS10: 246 → 260 blobs (14 MTK blobs recovered: lk, tee, gz, preloader, scp, sspm, spmfw, md1dsp, modem, cam_vpu×3, dtbo).

### 3. HW Firmware page usability overhaul (13 items via citadel:autopilot)

- **Backend**: `/cve-aggregate` extended with severity breakdown; new `/cves` endpoint; new `/{blob_id}/download` with realpath+symlink sandbox.
- **Frontend**: StatsHeader severity breakdown + clickable cards + Kernel CVE card; PartitionTree auto-expand CVE partitions + rollup badge + sort toggle; BlobTable CVE column + search highlight; BlobDetail download button + collapsed JSON + clickable drivers; new `CvesTab.tsx`; HardwareFirmwarePage with debounced search, focus filter, controlled tabs, HBOM tooltip with counts.
- 7 new backend tests (happy path + 403 on path escape + 403 on symlink escape + 404 on missing + severity schema + empty-cves), all passing.

### 4. Knowledge base + CLAUDE.md updates

- CLAUDE.md **Security rule 1** extended: realpath on BOTH sides + symlink test reference.
- CLAUDE.md **Learned Rule 17**: canary silent CLI exits (`tsc -b` etc.).
- CLAUDE.md **Learned Rule 18**: post-relocation container as detection root.
- `.planning/knowledge/monitor-presets.md` (new): 4 scoped log-monitor presets + rules of thumb.
- Harness quality rule added: `auto-classifier-magic-offset-beyond-buffer` (was pending since 2026-04-17, now adopted — harness total 14 → 15 rules).
- 4x `/citadel:learn` re-runs with 24h-later deltas captured.

## Open threads discovered this session (not scoped yet)

1. **Legacy null-tier CVE rows** — 2,918 rows/firmware on pre-2026-04-17 uploads that predate the `match_tier` column's population.  Not a regression (matcher correctly stamps all new writes), but inflates `hw_firmware_cves` headline count on legacy firmware.  Three cleanup options documented in `.planning/knowledge/feature-hw-firmware-phase2-enrichment-patterns.md`.

2. **Phase-integration regression discipline** — The 4/17 extraction-integrity campaign's Phase 1 and Phase 2 were each unit-tested in isolation but never integration-tested end-to-end.  Cost: 24h latent bug that surfaced on my first post-merge Android upload.  Anti-pattern captured in that campaign's `-antipatterns.md` as #9.

3. **LAN scanner noise on backend** — `0.0.0.0:8000` bind lets LAN scanners (Joomla / VMware IDM / ServiceNow / Saas API) flood logs.  Benign today (all 404), but log monitors need scoped filters; Monitor preset doc now captures this.

4. **"Pending" quality-rule drift** — `/learn` historically flagged rules as "pending manual addition" when harness.json was protected.  One rule stayed pending for 24h before being rediscovered.  Hand-rolled cron candidate: grep `.planning/knowledge/*antipatterns.md` for "pending manual addition" and surface residuals.

## State of the system (verified 2026-04-18 22:06)

| Metric | Value |
|---|---|
| Backend health | healthy |
| Worker | running |
| Frontend | healthy (serving on 3000) |
| DB | 5 test firmware, 260 DPCS10 blobs detected |
| HW-firmware CVE aggregate (DPCS10) | 26 hw-firmware + 439 kernel + 1 advisory |
| Severity breakdown (DPCS10 hw-firmware) | 1 critical · 24 high · 1 medium |
| Backend tests | 77/77 affected suite passing (full suite not run end-to-end this session) |
| Frontend typecheck | clean (`tsc -b` exit 0, canaried) |
| Uncommitted changes | 27 files, +3478/-407 lines |

## Rollback safety

Nothing committed this session (all work uncommitted on `clean-history`).  Rollback is `git stash` or `git reset`.  Baseline HEAD: `f8777b1`.

## For the next session

- Read `.planning/intake/seed-next-session-2026-04-19.md` first — it contains the Ouroboros-style seed for proposed next work with three scope options (short / medium / large) the user can pick from.
- `.planning/intake/next-session-plan.md` is stale (last updated 2026-04-13, session 35) — don't treat it as current.
- Citadel entry points: `/do` for routed work, `/autopilot` for intake-item execution, `/archon` for multi-session campaigns.
