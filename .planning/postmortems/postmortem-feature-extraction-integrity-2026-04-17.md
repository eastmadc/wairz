# Postmortem: Extraction Integrity Campaign

> Date: 2026-04-17
> Campaign: `.planning/campaigns/completed/feature-extraction-integrity.md`
> Duration: Single session (~4 hours wall clock, 7 commits from 72a2049 through bf5805e)
> Outcome: **completed** — 5 phases + 1 live-found fix commit

## Summary

A user-reported gap (`md1dsp.img` invisible to hw-firmware detector on DPCS10) triggered a 4-scout research-fleet that exposed a systemic pattern: `Firmware.extracted_path` as a single-string walk root combined with 12 upstream silent-drop sites in the extraction pipeline. Campaign delivered an architectural fix (helper + JSONB cache), migrated all 13+ downstream consumers, ran a live backfill (+296 blobs, +362,035 CVE matches on the 10-firmware sample), and added regression guards (harness quality rule + grep-check test). During live verification of a new upload, a second-order gap was discovered (multi-archive medical firmware ZIPs) and fixed in the same session.

## What Broke

### 1. `git stash --include-untracked` ate the campaign file (recurring)
- **What happened:** Archon created `.planning/campaigns/feature-extraction-integrity.md` (untracked), then ran `git stash push --include-untracked` for a Phase 1 checkpoint. Stash captured the new planning files.
- **Caught by:** Immediate `ls` check before delegating.
- **Cost:** ~2 minutes. Committed the planning files BEFORE delegation as the fix.
- **Fix:** Moved to "commit planning files, use HEAD as checkpoint" pattern.
- **Infrastructure:** None added, but this is the SECOND campaign with this failure mode (also bit hw-firmware-phase2-enrichment). Pattern is now clear enough that Archon should default to "commit planning docs first, stash only tracked source after" — consider documenting in skill or adding to CLAUDE.md.

### 2. Docker image bake captured mid-agent state
- **What happened:** User triggered a rebuild. During the rebuild, the Phase 5 agent was writing `firmware.py` (adding the `/audit` route). The image COPY step captured the source tree AS IT WAS mid-write, so the baked image lacked the final code.
- **Caught by:** Live curl test of the new `/audit` endpoint returning 404 despite OpenAPI spec apparently having it.
- **Cost:** ~3 minutes for a second rebuild.
- **Fix:** Rebuilt again after agent completed.
- **Infrastructure:** None, but the lesson is "rebuild is a BARRIER — don't parallelize with live code writes."

### 3. `uvicorn` runs without `--reload` → stale module cache masked the live fix
- **What happened:** User uploaded firmware mid-campaign. I had `docker cp`'d the fix into the container. A fresh `python -c "inspect..."` showed the fix was present. But the running uvicorn worker had cached the module from container-startup time (18:04) and used the OLD code for the upload.
- **Caught by:** On-disk audit of the user's upload — no `*_extracted/` sibling dirs present despite our fix supposedly adding them.
- **Cost:** ~5 minutes of diagnosis + 5 minutes for the real rebuild.
- **Fix:** Rebuild backend + worker; bake the code into the image.
- **Infrastructure:** Knowledge memo added — `docker cp` updates disk but NOT live Python imports when uvicorn has no `--reload`.

### 4. Phase 3b agent ran out of budget mid-work
- **What happened:** Phase 3b delegation asked for 8+ consumer migrations. Agent completed 7 (ToolContext + filesystem/binary/strings MCP tools + assessment + update_mechanism + component_map + graph.py). Ran out of budget before hitting component_map router + scanner services.
- **Caught by:** Budget-exhaustion message from the agent runtime.
- **Cost:** Had to complete Phase 3b's commit myself by verifying what was done + committing the partial work.
- **Fix:** User said "we can continue", re-verified all files were functionally complete even if the agent's docs said "deferred." Tests passed 244/244, so committed.
- **Infrastructure:** None. Accept that large delegations can bounce; verify + commit partial work.

### 5. Phase 2 `get_detection_roots` heuristic was incomplete (found live)
- **What happened:** On the RespArray firmware upload, the helper stopped at `target/extracted/` (an empty shell dir) rather than climbing to `target/` where the real firmware files sat. Returned 1 root instead of 2.
- **Caught by:** Live inspection of project 00815038 user-reported extraction issue.
- **Cost:** ~10 minutes of code-reading + design of the "shallow-container rescue" heuristic.
- **Fix:** Added fallback: if the primary container has ≤1 qualifying child but its parent has raw firmware files (strict extensions) at the file level, promote the parent as an additional root. Safe because `_dir_has_raw_image` is non-recursive + specific-extension.
- **Infrastructure:** New tests added covering the promotion case.

### 6. Classifier blind spot: NXP iMX RT MCU + custom archive format
- **What happened:** RespArray firmware contains `imxrt1052_*.bin`, `ix_iv_070(*).bin`, and 6 "tar.xz" files with a proprietary `a3 df bb bf` magic (not real xz). None classified as hw firmware.
- **Caught by:** Live detection run returning 11 blobs (DTBs only) instead of the expected ≥15.
- **Cost:** Scope-reduced — not fixed in this campaign; queued as `feature-classifier-patterns-mcu-kernel.md` intake.
- **Fix:** Deferred. Explicit follow-up intake written so nothing is lost.
- **Infrastructure:** New intake file, tracked for a future single-session campaign.

## What Safety Systems Caught

| System | What It Caught | Times | Impact Prevented |
|--------|---------------|-------|-----------------|
| Full hw-firmware regression (pytest) | Zero regressions across 5 consumer-migration phases + 6 upstream fixes | 6 phases | Silent test breaks. 192 → 251 test count, all green. |
| Pre-delegation context read (Archon) | Phase 2 discovered `sbom_service._scan_kernel_from_vermagic` already existed; scoped phase 2 down | 1 | ~200 LOC of redundant code (same pattern as prior hw-firmware-phase2) |
| Mandatory grep check (Phase 3b) | Identified 8+ remaining `firmware.extracted_path` reads, classified as legitimate-per-binary vs needing migration | 1 | Half-migrated code state — clarified completeness criteria |
| Ruff I001 import-sort | Phase 3b agent added 5 imports, out of order | 1 | Merge review noise, CI rejection |
| Live verification step | RespArray extraction bug (sibling dirs not visible) discovered via live audit | 1 | Would have taken another user bug report |
| Integration test `test_mtk_parsers_fire_on_dpcs10_shape_fixture` | Proved the Phase 3a migration actually closed the original DPCS10 bug | 1 | Shipping "it compiles" without end-condition evidence |
| `test_no_new_direct_extracted_path_reads` | Regression guard for FUTURE PRs; passes on current codebase | ongoing | Re-introduction of single-path walks |
| Harness quality rule `auto-extraction-roots-no-direct-extracted-path` | Same, at hook-level | ongoing | Same, with earlier-stage detection |

## Scope Analysis

- **Planned:** 5 phases — P1 stop bleeding / P2 helper / P3a+b consumer migration / P4 backfill / P5 observability. Estimated 5 sessions.
- **Built:** 5 planned phases + 1 live-found fix commit (84d94ce: multi-archive ZIP sibling extraction) landed mid-campaign. All in a single session.
- **Drift:** **Green.** The live-found fix extended the campaign's spirit (data-loss gap → fix) without changing the direction. All phases shipped as spec'd.

## Patterns

1. **Pre-delegation context reads pay off AGAIN.** Phase 2 scope reduction (sbom_service already injected kernel CPE) saved ~200 LOC. Same pattern that saved work in hw-firmware-phase2. Now a reliably-high-ROI step.
2. **Research-fleet → Archon pipeline still feels well-sized.** 4 scouts × 1 wave produced 6,000 words of implementation-ready briefs. Consensus across all 4 scouts gave high confidence in the diagnosis.
3. **Live verification > unit testing for external-data-sensitive campaigns.** Phase 2 enrichment caught schema edge cases in kernel.org vulns.git during live run. This campaign caught the RespArray multi-archive gap during live user upload. Not a coincidence — both involved heterogeneous real-world inputs the mocks couldn't anticipate.
4. **"Stop the bleeding" before architectural fix is the right sequence.** P1 fixed 6 silent-drop sites WITHOUT introducing any helper. P2 introduced the helper. Clean separation meant P1 could have been merged standalone if we'd paused.
5. **Per-phase commits + mandatory grep after migration phases.** Gave atomic reverts + ensured we didn't ship a half-migrated state.
6. **Backfill scripts are cheap insurance.** 150 LOC script + 6 tests gave the whole campaign a verifiable "it actually works" end-condition via 362,035 CVE matches landing on real firmware.

## Recommendations

1. **Add "commit planning docs before stashing tracked source" to Archon's protocol.** This is now the 2nd campaign with this failure. 2 minutes × every future campaign = worth a rule.
2. **Consider adding `--reload` to uvicorn in dev mode.** Not for production, but in local dev the stale-module surprise is a meaningful debugging cost when combined with `docker cp`-style iteration. Gate behind an env var (e.g., `DEV_MODE=1`).
3. **Document the "rebuild is a barrier — don't parallelize with live code writes" lesson.** Add to CLAUDE.md as a learned rule (optional — this is a session-coordination concern more than a code concern).
4. **Follow-up campaign:** launch `feature-classifier-patterns-mcu-kernel` in the next session. The RespArray firmware provides a perfect acceptance test. Expected: 11 → ≥15 blobs after classifier tuning.
5. **Eventually tighten the harness rule's regex scope.** Currently scoped to walk-service directories via `filePattern`. If the allowlist grows (future per-binary services), consider moving to an AST-level linter rule that can distinguish "walk vs. single-binary-resolve" usage.
6. **The `_scan_android_apps` 5-→-10-partition pattern is likely an AOSP-wide gap.** Check `assessment_service._phase_android` too — we migrated it but didn't explicitly expand its partition list. Could be lurking.

## Numbers

| Metric | Value |
|--------|-------|
| Phases planned | 5 |
| Phases completed | 5 + 1 live-fix |
| Commits | 7 (feat×5 + fix×1 + chore×1 archive implicit) |
| Files changed (campaign-scope) | 26 (17 services + 4 routers/schemas + 2 workers + 3 tests) |
| Insertions / Deletions | +4,672 / -271 |
| New tests added | 59 (20 unpack_integrity + 29 firmware_paths + 3 integration + 6 backfill + 1 grep-check) |
| Test baseline → final | 192 → 251 hw-firmware / extraction-integrity suite |
| Frontend typecheck errors | 0 throughout |
| Circuit breaker trips | 0 |
| Quality gate blocks | 1 (ruff I001, auto-fixed) |
| Anti-pattern warnings (new) | 0 |
| Rework cycles | 1 (Phase 2 "extracted"-climb revert — my original attempt caused DPCS10 regression, reverted and replaced with shallow-rescue) |
| Pip deps added | 0 |
| Docker volumes added | 0 (kernel_vulns_data already existed from prior campaign) |
| Sub-agents spawned | 5 phases × 1 agent + 4 research scouts = 9 delegations |
| Live verification runs | 2 (post-P4 backfill, post-P5 `/audit` on RespArray) |

## Live Verification Results

| Metric | Baseline | After Campaign |
|--------|----------|----------------|
| DPCS10_260414-1134 hw-firmware blobs | 244 | 260 (+16) |
| DPCS10_260413-1709 | 244 | 260 (+16) |
| DPCS10_260403-1601 (pre-detector) | 0 | 258 (+258) |
| RespArray_1.05.00.17.zip | 0 (before live-fix) | 11 (after) |
| glkvm-RM10 | 0 | 8 (+8) |
| Total production DB blob count | 490 | 786 (+296) |
| Total blob-linked CVE matches | 0 | 362,035 |
| `firmware.extracted_path` reads in walk-sites | 13+ | 0 (all legitimate per-binary callers remain) |
| `/audit` endpoint | N/A | live, returns HTTP 200 on real firmware |
| Regression guard test | N/A | passes; will fail-loud on future re-introduction |

---
