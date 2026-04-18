# Patterns: Phase C4 Tier 0 parser-detected CVE matcher (2026-04-17 session)

> Extracted: 2026-04-17
> Campaign: (no formal campaign file — handoff-driven continuation)
> Handoff: `.planning/knowledge/handoff-2026-04-17-mtk-phase-c.md`
> Commit: `e74a31d`

This captures lessons from a single-commit continuation session that
implemented the Tier 0 `parser_version_pin` matcher predicted by
`hw-firmware-mtk-subsystem-parsers-antipatterns.md` #10. Scope was
~30 minutes: one new matcher function (~45 LOC), wire-in line,
docstring updates, and 12 new tests + 3 stale-assertion fixes.

## Successful Patterns

### 1. Handoff-driven continuation with executable implementation sketch
- **Description:** The prior session's handoff file contained a ready-to-paste
  Python sketch of `_match_parser_detected`, a field-mapping table
  (parser record → SbomVulnerability column), the exact line number to
  wire it in at (~line 512 of `match_firmware_cves`), and a regression
  target (DPCS10 aggregate `hw_firmware_cves=1`). The continuation
  followed the sketch essentially verbatim — the only variance was
  making the function sync instead of async (zero awaits inside).
- **Evidence:** Commit `e74a31d` lands 30 minutes after session start with
  zero re-analysis. No research agents spawned, no classifier inspection,
  no schema drilling — the handoff had already decided all of those.
- **Applies when:** Writing a handoff at session end. An implementation
  sketch (code + line numbers + field mapping + one test assertion) is
  worth 10x more than a prose summary. The next session should be able
  to copy-paste and run, not re-decide. Cost to the outgoing session:
  ~10 minutes of extra synthesis. Savings to the incoming session:
  ~30 minutes of re-analysis.

### 2. New tier = no new mock scaffolding when it only reads in-memory data
- **Description:** Tier 0 adds zero `db.execute()` calls — it reads
  `blob.metadata_` directly. The existing `_mock_db_for_matcher` (2-call
  side_effect) and `_mock_db_full_matcher` (2-4 call side_effect) continued
  working unchanged. The Tier 0 integration test used
  `_mock_db_for_matcher` as-is; no new helper.
- **Evidence:** `test_match_firmware_cves_persists_parser_version_pin_tier`
  and `test_match_firmware_cves_tier0_dedups_on_rerun` passed first try
  against the original mock harness. 12 new tests added to a single file
  with zero fixture duplication.
- **Applies when:** Adding a feature that operates on already-fetched
  objects (ORM rows in memory, validated input, decoded payloads).
  Check the existing test harness's assumptions before extending it —
  "new tier" does not imply "new scaffolding." The reverse (new DB call
  → new side_effect entry) is the real signal to extend the harness.

### 3. Field-mapping defaults via `or` chain to handle both missing and empty
- **Description:** The parser record comes from
  `blob.metadata_["known_vulnerabilities"]` — a JSONB column, values can
  be `None`, missing keys, empty strings, or legitimate values. Using
  `v.get("severity") or "medium"` handles all three cases in one
  expression. Alternatives — `v.get("severity", "medium")` fails on
  empty-string input; `v.get("severity") if v.get("severity") else "medium"`
  is verbose.
- **Evidence:** Test `test_defaults_when_optional_fields_missing` covers
  missing keys; real DPCS10 data in `mediatek_geniezone.py` populates
  all fields but the next parser might not.
- **Applies when:** Reading dict-shaped user/parser/config data where the
  caller's contract is "this field may be missing or empty." Prefer `or`
  chain for scalar defaults when both states mean "use the default." If
  empty-string is a legitimate distinct value, use the longer form.

### 4. Pre-commit rebuild per CLAUDE.md #8 / prior antipattern #9
- **Description:** Used `docker cp` to hot-iterate on the source + test
  files during development (dev deps are only in the running container;
  a rebuild would drop pytest). Before commit: ran
  `docker compose up -d --build backend worker` and verified with
  `docker compose ps --format "{{.Service}}\t{{.CreatedAt}}"` that both
  services showed fresh timestamps. Hot-patch was the iteration surface
  only, never the ship-ready state.
- **Evidence:** Rebuild completed at 19:13:21 MDT. Both backend and
  worker recreated in the same step. Tier 0 code verified present in
  the fresh container (`grep -c` returned 4 matches across the expected
  strings). Commit `e74a31d` landed against the rebuilt state.
- **Applies when:** Any code change that modifies backend or worker
  Python files. The prior session's antipattern #9 ("docker cp claiming
  done") is the failure mode; this pattern is the complement — cp is
  fine for iteration, but the last step before `git commit` must be
  `up -d --build` + timestamp verification. Meta-lesson: reading a
  knowledge file you're about to contribute to is cheap insurance.

### 5. Run pre-existing test failures to find stale test assertions
- **Description:** The first full test run of `test_hardware_firmware_cve_matcher.py`
  after Tier 0 changes surfaced 3 stale assertions (Tier 4 tests asserting
  `confidence == "medium"` when commit `9e1de6c` had silently changed it
  to `"low"`). These were pre-existing — my change didn't touch them —
  but would have been caught by anyone re-running the suite. Fixed them
  in the same commit since they were in the same file.
- **Evidence:** Running pytest on the whole file showed 3 failures
  unrelated to Tier 0; the failure output named the stale assertion
  lines directly. 10-minute fix.
- **Applies when:** After any implementation in a test file that hasn't
  run recently, always run the WHOLE file's tests (not just the new
  ones) before committing. It either confirms clean state or surfaces
  drift the previous session missed. Free signal; trivial cost.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Make `_match_parser_detected` sync, not async | Function awaits nothing — pure in-memory iteration over blob metadata. Marking sync avoids the unnecessary `await` at call site and signals "no I/O." | Correct — single-line call `all_matches.extend(_match_parser_detected(blobs))` at top of per-blob loop. |
| Accept parser records as whole list, iterate inside | Handoff sketch used `blobs: Sequence[...]` matching Tier 4/5 signatures. Preserves the outer-level consistency (Tier 0/4/5 are whole-firmware; Tier 1/2/3 are per-blob loop). | Correct — integration follows the two-layer pattern already in the file. |
| Fix 3 stale Tier 4 assertions in the same commit as Tier 0 | Same test file, trivial fix, pre-existing failure would break any reviewer re-running the suite. Not fixing them would leave the suite red after my commit. | Correct — net effect is 34/34 passing, a cleaner baseline for Phase C5. |
| Use `v.get(x) or default` for field-mapping defaults | JSONB values can be null, empty string, or missing; `or` chain collapses all three into "use default." Alternatives either miss empty-string or require verbose ternaries. | Correct — test `test_defaults_when_optional_fields_missing` passes, and future parsers emitting sparse records will behave sanely. |
| Router aggregate bucket split unchanged | The router's `_KERNEL_TIERS = {kernel_cpe, kernel_subsystem}` does "everything else goes to hw_firmware_cves." Tier 0's `parser_version_pin` automatically lands in the right bucket without code change. | Correct — verified at `hardware_firmware.py:173-182`. Future Tier 1/2 hits would also automatically land correctly. |

## Applicability note

Handoff → 30-min continuation → commit is a repeatable shape when:

1. **The handoff file carries executable content.** Field mapping tables,
   line-number references, one regression test assertion. Prose alone is
   not sufficient; the successor will re-synthesize anyway.
2. **The fix lives in an existing pipeline the reader already uses.** The
   prior antipattern (#10) was "parser CVEs only in metadata, UI reads
   sbom_vulnerabilities." Tier 0's design threads parser output through
   the same pipeline. Zero UI/frontend change needed — this is what made
   the continuation cheap.
3. **Existing test scaffolding fits the new layer.** Tier 0 needed zero
   new fixtures. If the new layer needs a new harness, the 30-min window
   probably doesn't hold and the continuation should be replanned.
