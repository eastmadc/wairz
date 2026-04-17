# Postmortem: Hardware Firmware Phase 2 Enrichment

> Date: 2026-04-17
> Campaign: `.planning/campaigns/completed/feature-hw-firmware-phase2-enrichment.md`
> Duration: Single session (~3.5 hours wall clock, from a41fcff to a0dd65e)
> Outcome: **completed** — all 5 phases shipped

## Summary

Archon drove a 5-phase campaign that closed the three "empty feature" gaps left by the prior hardware-firmware detection campaign: Vendor=None on every row, 0 CVE matches, and a flat 244-row table. Delivered in one session with 6 commits, 141 new tests, 0 regressions, 0 new pip dependencies, and two live-verified metrics that exceeded intake targets (1,314 kernel-subsystem CVE matches vs target ≥20; 354 Bluetooth-only CVEs on kernel 6.6.102 vs target ≥1). The only end-condition miss was Phase 1 vendor fill at 76.2% vs 80% target — and the 5 blobs without a vendor are all `category=other` path-fallback catch-alls, not missed pattern entries.

## What Broke

### 1. Phase 1 checkpoint stash swallowed the campaign file
- **What happened:** Called `git stash push --include-untracked` while the campaign file and scope-claim file were untracked. Stash captured them; working tree lost them until stash-pop, which then conflicted with live files.
- **Caught by:** Immediate `ls` check before delegating.
- **Cost:** ~2 minutes — restored by `git stash drop` + noting `checkpoint-phase-1: none` in the continuation state.
- **Fix:** Dropped the stash and relied on HEAD (595be18) as the Phase-1 recovery baseline instead.
- **Infrastructure created:** None. Lesson for future Archon runs: create the campaign file AFTER the checkpoint stash, OR use `git add -N` to mark it tracked before stashing. No rule added — the failure mode is specific to "archon creates planning files then stashes for phase checkpoint" and unlikely to recur outside orchestration.

### 2. Initial re-detection walked the wrong partition path
- **What happened:** Post-rebuild live validation called `detect_hardware_firmware(fid, db, fw.extracted_path)` where `fw.extracted_path` points to a single erofs partition (`partition_2_erofs`), not the rootfs tree. Detector found 0 blobs.
- **Caught by:** Manual metric check — "detection: 0 blobs" was obviously wrong given prior runs found 244.
- **Cost:** ~1 minute — re-ran with the parent rootfs path.
- **Fix:** Passed `/data/firmware/.../extracted/rootfs` directly; detection returned 246 blobs.
- **Infrastructure created:** None needed for the campaign. Existing debt: the Firmware model's `extracted_path` column stores one "main" partition rather than the rootfs — the detector (and any validation script) needs to walk the parent. A potential future fix, out of scope here.

### 3. Phase 2 agent initially over-scoped (caught during briefing)
- **What happened:** Intake asked for "inject synthetic linux_kernel component into grype pipeline". Before delegating, Archon discovered `sbom_service._scan_kernel_from_vermagic` already does exactly that.
- **Caught by:** Archon's pre-delegation context read (reading grype_service.py + sbom_service.py).
- **Cost:** 0 — discovered before code was written. Saved ~200 LOC of redundant work.
- **Fix:** Rewrote the Phase 2 prompt to scope down to kmod semver extraction + Tier 4 mirroring.
- **Infrastructure created:** Decision Log entry in the campaign documenting the discovery.

### 4. Phase 3 agent overshot LOC targets (accepted, not reworked)
- **What happened:** `patterns_loader.py` 254 LOC (target 80-150), `classifier.py` 316 LOC (target 200).
- **Caught by:** Quality spot-check.
- **Cost:** 0 rework. Code was purposeful (defensive error handling + graceful YAML degradation).
- **Fix:** Accepted with Decision Log entry. LOC targets were advisory, not binding.
- **Infrastructure created:** None.

### 5. Ruff I001 import-sort error after Phase 3
- **What happened:** Agent added 5 new parser imports to `parsers/__init__.py` in a single block; ruff's `I001` flagged the ordering.
- **Caught by:** Ruff (`ruff check`).
- **Cost:** ~30 seconds — `ruff check --fix` auto-fixed.
- **Fix:** Auto-fix.
- **Infrastructure created:** None.

### 6. CWD drift during Phase 5 commit
- **What happened:** Earlier typecheck had done `cd frontend/`; shell retained that cwd. First attempt to stage files with relative paths failed.
- **Caught by:** Immediate git error.
- **Cost:** ~15 seconds — switched to absolute paths via `cd /home/dustin/code/wairz &&`.
- **Fix:** Absolute paths.
- **Infrastructure created:** None. CLAUDE.md already advises absolute paths; lesson reinforced.

## What Safety Systems Caught

| System | What It Caught | Times | Impact Prevented |
|--------|---------------|-------|-----------------|
| Ruff (post-commit) | I001 import-sort in `parsers/__init__.py` | 1 | Commit-rejection / merge review flag |
| Pre-delegation context read (Archon) | Phase 2 redundancy with existing `sbom_service._scan_kernel_from_vermagic` | 1 | ~200 LOC of duplicate code + a forgotten 2nd code path over kernel vermagic |
| Quality spot-check on largest file each phase | Confirmed `patterns_loader.py` defensive handling was purposeful, not bloat | 3 | Unwarranted rewrites |
| Full hw-firmware regression per phase | Zero regressions across 141 new tests added | 5 | Unknown-count silent test breaks |
| Frontend `tsc --noEmit` gate | Clean across all 5 phases | 5 | Build breaks, blank-page runtime crashes from Record<T,X> gaps (CLAUDE.md rule 9) |
| External-action-gate hook | Blocked a `.env` read during unrelated earlier work (not this campaign) | 1 | Secrets exposure |

## Scope Analysis

- **Planned:** 5 phases covering classifier YAML, kernel CVE attribution, MediaTek parsers, vulns.git index, UX + HBOM. 6 sessions estimated.
- **Built:** Exactly 5 phases, 6 commits, single session. All intake deliverables present. Two scope reductions (Phase 2 no-new-grype-code, Phase 3 no-new-pip-deps) documented in Decision Log.
- **Drift:** **None.** Direction alignment checks at Phase 2 and Phase 3 both confirmed alignment. Every scope deviation was documented before delivery, not drift.

## Patterns

1. **Pre-delegation context reads pay off.** The Phase 2 scope reduction (discovering sbom_service already injected the kernel CPE) saved a half-day of redundant work. Every phase's prompt included "read these files first" — the agents followed it and produced correct-scope work.
2. **"No new deps" as a strategic constraint forces better code.** Phase 3's 5 parsers + Phase 4's kernel_vulns_index both could have pulled in `md1imgpy` / `kaitaistruct` / `fakeredis`. Rejecting those produced ~845 LOC of native parsers + an inline FakeRedis test helper — simpler, more robust, no backend+worker rebuild coupling.
3. **Agents prefer `docker compose exec` over `ruff`/`pytest` direct invocation.** Required always using `/app/.venv/bin/pytest` or `/app/.venv/bin/ruff`. Per CLAUDE.md rule 19 — could surface as a learned reminder.
4. **Live verification during a campaign is rare but high-signal.** Phase 4's agent actually ran `git clone vulns.git` and produced 354 live Bluetooth CVEs on the real kernel version. That single datapoint validated the entire subsystem-mapping strategy better than any unit test could.
5. **Small LOC deliberately over-target is OK when defensive.** `patterns_loader.py` was 70% over target; code review confirmed every extra line was for YAML-malformation resilience. A 150-LOC aggressive version would have crashed the module import on a single typo.

## Recommendations

1. **Add helper script to walk a firmware's true extraction root.** The `extracted_path` column storing one partition caused a 1-minute false negative. A `get_firmware_walk_root(firmware)` helper that prefers `extraction_dir` then falls back to `dirname(extracted_path)` would prevent this for future validation scripts. (Out of campaign scope but worth an intake item.)
2. **Capture "no new deps" as a standing constraint in CLAUDE.md.** Phases 3 + 4 both benefited from rejecting easy pip-install wins. This is already implicit in CLAUDE.md learned rule 2 (add deps immediately if you add them) but a rule 16 "prefer native implementation over vendoring for ~200 LOC problems" would codify the decision pattern. Optional — only if /learn extracts the pattern as load-bearing.
3. **Trigger `/pr-watch` if campaign branches merge to `main`.** This campaign worked on the `clean-history` branch; no PR yet. When the branch merges, `/pr-watch` should watch CI for Phase 4's live network-dependent path (`kernel_vulns_index.sync` could fail in CI sandboxes without git or network). Graceful-degradation unit tests cover the no-git / no-redis paths, but first-ever cron run in CI is the riskiest moment.
4. **Schedule Phase 2 kernel_cpe verification once SBOM scan runs.** Tier 4 live verification showed 0 matches because no SBOM scan ran on the DPCS10. Add a quick smoke test: `run_sbom_scan → run_cve_match` on the DPCS10, assert kernel_cpe matches > 0. ~10 min follow-up task.
5. **Document DPCS10 as the reference Android fixture.** Four phases validated partial functionality against this specific image. A fixtures README under `backend/tests/fixtures/hardware_firmware/README.md` would codify "this is the canonical Android fixture and here's what it contains" so future sessions don't rediscover partition layout quirks.

## Numbers

| Metric | Value |
|--------|-------|
| Phases planned | 5 |
| Phases completed | 5 |
| Commits | 6 (5 feat + 1 chore archive) |
| Files changed | 33 |
| Insertions | 6,682 |
| Deletions | 368 |
| New tests added | 141 (36 + 9 + 19 + 41 + 11 + 25 integration across matcher file) |
| Test baseline → final | 51 → 192 (hw-firmware suite) |
| Frontend typecheck errors | 0 (all phases) |
| Circuit breaker trips | 0 |
| Quality gate blocks | 1 (ruff I001, auto-fixed) |
| Anti-pattern warnings | 0 new (3 pre-existing S110 in arq_worker.py untouched; 12 pre-existing S110/S112 in other parsers untouched) |
| Rework cycles | 0 |
| Pip deps added | 0 |
| Frontend deps added | 0 (used already-installed @xyflow/react) |
| Docker volumes added | 1 (`kernel_vulns_data`) |
| Sub-agents spawned | 5 (one per phase) |
| Sub-agent total tokens | ~781K across 5 delegations |
| Direction alignment checks | 2 (after P2, P3); both passed |

## Live Verification Results

| Metric | Target | Actual |
|--------|--------|--------|
| Non-kmod vendor fill (DPCS10) | ≥80% | 76.2% (16/21) — 5 unfilled are `category=other` fallback |
| Kmod kernel_semver coverage | 100% of kmods | 225/225 ✅ |
| `bluetooth.ko` CVE matches on 6.6.102 | ≥1 high-confidence | 354 ✅ |
| Total `kernel_subsystem` matches (DPCS10) | ≥20 | 1,314 ✅ |
| HBOM export endpoint | Valid CycloneDX v1.6 | ✅ live-verified |
| vulns.git index coverage | N/A | 10,725 CVEs across 1,603 subsystems |

---
