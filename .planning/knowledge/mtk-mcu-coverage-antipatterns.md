# Anti-patterns: MTK MCU Coverage

> Extracted: 2026-04-17
> Session: `626b3752` (no formal campaign — direct execution under `/do continue`)
> Commit: `9480bc7 feat(hw-firmware): MTK MCU coverage`

## Failed Patterns

### 1. Curl'ing the DB schema instead of asking it
- **What was done:** First attempt to inspect DPCS10 blob categories ran
  `SELECT ... FROM hardware_firmware_blob` (singular) — the actual table
  is `hardware_firmware_blobs` (plural).
- **Failure mode:** Postgres "relation does not exist" error. Cost ~30s
  but more importantly broke the flow.
- **Evidence:** First `docker compose exec ... psql` query failed with
  `ERROR: relation "hardware_firmware_blob" does not exist`.
- **How to avoid:** Either run `\dt hardware*` first, or read the model
  file (`backend/app/models/hardware_firmware.py`) for the canonical
  `__tablename__`. SQLAlchemy ORM and raw SQL diverge on pluralization;
  trust neither without checking.

### 2. Heredoc-quoted nested f-strings in shell exec
- **What was done:** First version of the redetect script tried to inline
  Python through `docker compose exec -T backend bash -c "/app/.venv/bin/python -c '
  ... f\"  {r[0].rsplit(\\\"/\\\",1)[-1]:<14}  cat={r[1]:<10}  ...\"'"`
- **Failure mode:** Backslash-escaped quotes inside an f-string inside
  single-quoted python inside double-quoted bash inside docker exec —
  shell ate the escapes, Python crashed with `SyntaxError: unexpected
  character after line continuation character`.
- **Evidence:** Actual error: `print(f"  {r[0].rsplit(\"/\",1)[-1]:<14}...`
  with `^` pointing at the `"` after `rsplit(`.
- **How to avoid:** For Python more complex than `import x; print(x)`,
  write the script to a file (Write tool) and exec the file with
  `docker compose cp + python /tmp/script.py`. Never pipe complex
  Python through nested shell quoting. The cycle cost was ~1 minute
  but the diagnostic difficulty was disproportionate.

### 3. Not pre-checking VARCHAR(20) for ADVISORY cve_id
- **What was done:** First advisory entry was named "MediaTek SSPM/SPMFW/
  MCUPM presence advisory" — the matcher generates
  `cve_id = "ADVISORY-" + name.upper().replace(" ", "-") = 52 chars`.
  The DB column is `cve_id VARCHAR(20)`.
- **Failure mode:** `StringDataRightTruncationError: value too long for
  type character varying(20)` on the FIRST insert during cve-match.
- **Evidence:** Asyncpg traceback in the redetect script output, with the
  full 52-char cve_id visible in the bind parameters.
- **How to avoid:** When adding entries that flow through computed-name
  generation, grep for the column constraint first
  (`grep "VARCHAR(2[0-9])" backend/alembic/versions/*` or `\d` in psql).
  This anti-pattern also lurks in the existing kamakiri ADVISORY entry
  (31 chars) — it just hasn't fired because no MTK bootloader has
  chipset_target populated yet. Latent landmine.

### 4. Docker image / disk drift after YAML rename
- **What was done:** Renamed advisory entry "MediaTek SSPM/SPMFW/MCUPM
  presence advisory" → "MTK PM" on disk, but the rebuilt container
  STILL had the old YAML baked in (the rebuild ran before the rename).
  Re-ran the script expecting the fix, got the same VARCHAR error.
- **Failure mode:** ~2 minutes of "wait, I just fixed that" confusion
  before realizing the image wasn't updated.
- **Evidence:** Bind parameters in the second error still showed
  `'ADVISORY-MEDIATEK-SSPM/SPMFW/MCUPM-PRESENCE-ADVISORY'` despite the
  on-disk YAML having `name: MTK PM`.
- **How to avoid:** Either rebuild after EVERY YAML edit, or always
  `docker compose cp` the YAML before testing. Mixing the two creates
  ambiguity about which version is live. Per CLAUDE.md rule #1 the
  authoritative path is `docker compose up -d --build`, but for fast
  iteration `docker cp` works as long as you commit to it consistently.

### 5. Silent-skip branches with no telemetry
- **What was done:** The cve_matcher's `if not blob_chipset: continue`
  guard at line 181-182 has been there since early phases. It silently
  skips chipset_regex YAML entries when chipset_target is NULL — which
  was 100% of MTK subsystem blobs before this session.
- **Failure mode:** Anyone writing chipset_regex YAML entries before
  this session would see "0 cves matched" with no signal as to why.
  No logging, no counter, no warning.
- **Evidence:** Identified by reading the matcher source after the
  pre-flight DB query showed NULL chipset_target. The protocol of "look
  at the data first" caught it; the matcher itself doesn't surface it.
- **How to avoid:** Add a counter or DEBUG log to silent-skip branches in
  matchers, especially when the skip is conditional on a field that may
  legitimately be empty for some inputs. A future improvement: emit a
  matcher-summary stat like
  `{"chipset_skipped": N, "version_skipped": M}` so YAML authors can see
  which guards their entries are tripping.

### 6. Two scheduled wakeups for the same waiting period
- **What was done:** Scheduled a wakeup after the second rebuild (~60s)
  and another after the final rebuild (~90s) before realizing the work
  would complete before either fired. Both wakeups landed in the
  conversation as "continue" prompts after the user-facing summary
  was already written.
- **Failure mode:** Two redundant /loop-style continuations, each
  landing a stale "do this next" prompt on a completed task tree.
  Recoverable (just acknowledge and confirm done) but noisy.
- **Evidence:** Two consecutive `<task-notification>` blocks at end of
  session, each repeating the wakeup prompt I scheduled.
- **How to avoid:** Only schedule a wakeup when the work CAN'T continue
  in-line. If you're going to keep working through Bash run_in_background,
  the foreground completion notification is sufficient — don't double-
  arm a ScheduleWakeup as belt-and-braces.

## Latent Bugs Surfaced (Not Fixed This Session)

| Bug | Location | Why deferred |
|-----|----------|--------------|
| `cve_id VARCHAR(20)` too tight for any ADVISORY-VENDOR-NAME longer than 11 chars | `backend/alembic/versions/*` (sbom_vulnerabilities table) | Needs Alembic migration. Already tracked as concept in intake (`data-analysis-cache-operation-varchar-fix` is the same VARCHAR-too-tight pattern). Bundle into one VARCHAR-widening pass. |
| `mtk_lk` parser doesn't populate chipset_target on modem.img / md1*.img / cam_vpu*.img | `backend/app/services/hardware_firmware/parsers/mediatek_lk.py` | Out of scope for MTK MCU coverage. Forces YAML entries for those formats to omit chipset_regex (over-broad firing as compromise). Future per-format chipset extraction would close this. |
| Existing kamakiri advisory ADVISORY-MEDIATEK-KAMAKIRI-BROM = 31 chars | `backend/app/services/hardware_firmware/known_firmware.yaml:168-178` | Same VARCHAR(20) issue; never crashed because no MTK bootloader has chipset_target populated to satisfy the entry's chipset_regex. Will crash the day mtk_lk gains chipset extraction. |

## Quality Rule Candidates

None of high enough confidence + clean-regex specificity to add to
`harness.json` automatically. The lessons belong in:

- YAML header comment in `known_firmware.yaml` documenting the cve_id
  length constraint (≤ 11 chars for advisory entries until the column
  is widened)
- `cve_matcher.py` docstring noting the silent-skip behavior on missing
  `chipset_target` (so future YAML authors know to verify their
  entries actually fire)
- A future stat block in the matcher output showing skip counts per
  guard, so authors can self-diagnose
