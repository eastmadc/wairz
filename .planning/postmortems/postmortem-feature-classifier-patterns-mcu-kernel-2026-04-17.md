# Postmortem: Classifier patterns — NXP iMX-RT MCU + ARM zImage + vendor signed archives

> Date: 2026-04-17
> Campaign: `.planning/campaigns/completed/feature-classifier-patterns-mcu-kernel.md`
> Duration: single session (~1 hour of execution; no pre-work)
> Outcome: completed

## Summary

Four blob families surfaced by the RespArray medical firmware (project 00815038) after the extraction-integrity fix — NXP i.MX RT Cortex-M MCU images, Edan frontboard MCU images, Linux kernel images (zImage/uImage/vmlinuz), and a vendor-specific signed archive with magic `a3 df bb bf` — were taught to the hardware-firmware classifier. Execution was straight-line: research → YAML patterns → classifier magic gates → tests → verify. All 5 phases completed in order with no rework. 12 new tests added, 225 related tests continue to pass.

## What Broke

### 1. `pytest` CLI not on PATH in backend container
- **What happened:** First attempt `docker compose exec backend pytest` failed with "executable file not found". Second attempt via `python -m pytest` failed because the system Python in the container has no test dependencies — they live in `/app/.venv`.
- **Caught by:** The shell itself (both commands exited non-zero). No hook involved; direct CLI feedback.
- **Cost:** Two extra `docker compose exec` round-trips (~30s). No code rework.
- **Fix:** Invoke tests as `.venv/bin/python -m pytest …` from `/app`. Once located, the venv-based invocation worked first try for every subsequent batch.
- **Infrastructure created:** None needed for this campaign, but worth noting: CLAUDE.md could explicitly document the backend venv path. Adding this as a recommendation rather than a hook — it's a knowledge artifact, not an automation.

## What Safety Systems Caught

No hooks blocked or corrected anything during this campaign. The hook-errors.jsonl tail shows only pre-existing noise from unrelated sessions (`.env.example` protection, cross-project writes). This campaign's small blast radius — one YAML, one Python module, one test file — didn't meaningfully exercise the safety pipeline.

| System | What It Caught | Times | Impact Prevented |
|--------|---------------|-------|-----------------|
| (none) | Campaign was within all existing guardrails | 0 | n/a |

## Scope Analysis

- **Planned:** Five patterns (iMX-RT, Edan, zImage, uImage, vmlinuz), two magic-byte gates (zImage header, signed-archive placeholder), new `mcu`/`kernel` categories, one new `edan` vendor, tests.
- **Built:** Exactly the above. No additions, no deferrals.
- **Drift:** None. The only judgment call was dropping the iMX-RT BOOT_DATA magic-byte check at offset 0x1000 — the classifier's magic buffer is 64 bytes (hard-coded in `detector._MAGIC_READ_BYTES`), so offset 0x1000 is unreachable without widening the read or routing to a parser. Filename-based detection covers all observed cases in the sample firmware; the decision was recorded in the Decision Log rather than adding a half-working magic gate.

## Patterns

- **Trivial "extend-a-table" campaigns are reliable when the substrate is well-factored.** The YAML + loader pattern established in the hardware-firmware phase 1 campaign made this work near-mechanical: add rows to a YAML, validate via an existing test harness shape, done. Two earlier campaigns (phase 1 patterns, phase 2 parsers) paid off here.
- **Intake briefs that include exact regex suggestions compress the work dramatically.** The intake file already contained the exact filename patterns and magic offsets. The campaign mostly translated intake into code. When intake does the design work, the build is boilerplate.
- **Magic-buffer ceiling (64 B) is a recurring constraint.** This is the second campaign in recent memory where an intake proposed a deep-offset magic check (>64 B) that had to be downgraded to filename-based detection. Worth tracking as a friction point — a future campaign could parameterize the magic read size per filename-category hint so MCU / kernel families can get 4 KB of header.

## Recommendations

1. **Document the backend venv path in CLAUDE.md.** One sentence: "Tests run via `docker compose exec backend .venv/bin/python -m pytest ...` — the container's system Python has no app deps." Prevents the round-trip on future sessions.
2. **Close the acceptance-criterion loop on live firmware.** The intake claims re-detection on firmware b5bcf2db should lift blob count 11 → 15+. This was not executed (requires the running DB + the project). Next session with that project active should run detection and record the delta. If the count doesn't lift as expected, we'll learn where the classifier still misses — file this as a `.planning/intake/` follow-up if the result is surprising.
3. **Consider a follow-up campaign: variable magic-read size.** If MCU / kernel deep-header parsing becomes valuable (IVT, BOOT_DATA, bzImage protected_mode_header), the 64-byte hard cap in `detector._MAGIC_READ_BYTES` needs a filename-category-aware override. Low urgency — no current blocker — but worth an intake note.

## Numbers

| Metric | Value |
|--------|-------|
| Phases planned | 5 |
| Phases completed | 5 |
| Commits | 0 (uncommitted at postmortem time) |
| Files changed | 4 (classifier.py, firmware_patterns.yaml, vendor_prefixes.yaml, test_hardware_firmware_classifier_patterns.py) + 1 campaign doc + 1 postmortem |
| Circuit breaker trips | 0 |
| Quality gate blocks | 0 |
| Anti-pattern warnings | 0 |
| Rework cycles | 0 |
| Tests added | 12 |
| Test pass rate | 225/225 across hardware/classifier/firmware-classif/extraction-integrity/firmware-paths |
