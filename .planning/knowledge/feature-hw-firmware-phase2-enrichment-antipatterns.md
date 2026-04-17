# Anti-patterns: Hardware Firmware Phase 2 Enrichment

> Extracted: 2026-04-17
> Campaign: `.planning/campaigns/completed/feature-hw-firmware-phase2-enrichment.md`

## Failed Patterns

### 1. `git stash --include-untracked` before committing a new campaign file

- **What was done:** Archon created `.planning/campaigns/feature-hw-firmware-phase2-enrichment.md` (new file, untracked) and `.planning/coordination/claims/archon-hw-firmware-phase2.json` (new, untracked), then ran `git stash push --include-untracked -m "checkpoint-phase-1"` to create a Phase 1 rollback point.
- **Failure mode:** The stash captured the untracked campaign and claim files. When Phase 1 completed and Archon tried to update the campaign, the file was gone. `git stash pop` then conflicted with newly-created files and aborted.
- **Evidence:** Campaign Continuation State shows `checkpoint-phase-1: none (stash conflict; rely on git HEAD 595be18)`.
- **How to avoid:** Either (a) commit the campaign + claim files BEFORE stashing for a phase checkpoint, or (b) use `git add -N {file}` to mark them intent-to-add so they're tracked-with-no-content (stash excludes them). Preferred: commit the planning files first and use the commit hash as the rollback reference — stash is unreliable when untracked files are in play.

### 2. Using `Firmware.extracted_path` directly as the detector's walk root

- **What was done:** Post-rebuild validation called `detect_hardware_firmware(fid, db, fw.extracted_path)` to re-scan the DPCS10 Android image.
- **Failure mode:** Detector returned 0 blobs. `extracted_path` stores ONE partition (e.g., `.../rootfs/partition_2_erofs`), not the rootfs tree. The detector walked an empty partition and found nothing.
- **Evidence:** Postmortem "What Broke" entry 2.
- **How to avoid:** For Android/multi-partition images, walk `dirname(extracted_path)` or the `extraction_dir` column instead. Better: add a helper `firmware_walk_root(firmware) -> str` that picks the right level based on `firmware.firmware_type`. For the detector itself: document in the docstring that `extracted_path` argument should be the rootfs, not a single partition.

### 3. Shell `cwd` drift during long multi-step sessions

- **What was done:** Ran `cd frontend && npx tsc --noEmit` to typecheck. Later, tried to stage files with relative paths (`git add backend/app/...`) — failed because cwd was still `frontend/`.
- **Failure mode:** `fatal: pathspec ... did not match any files`. 15-second recovery.
- **Evidence:** Pre-commit error during Phase 5 archival.
- **How to avoid:** Either (a) always use absolute paths, or (b) always `cd` back to repo root immediately after a subdirectory operation (`cd /home/dustin/code/wairz && npx ... && cd -`). Bash's working-directory persistence across tool calls is subtle and bites long sessions. The Bash tool description already advises absolute paths — this failure confirms it's load-bearing.

### 4. Over-broad delegation to sub-agents for tightly-scoped refactors

- **What was done:** Phase 1 delegation gave the agent a ~4000-token prompt with full YAML schema, 40+ specific example patterns, and line-by-line `classifier.py` rewire instructions. Agent delivered cleanly but at 254 LOC for `patterns_loader.py` vs 80-150 target (70% over).
- **Failure mode:** Not a true failure — code was purposeful — but illustrates that sub-agents tend to write _more_ defensive code than the spec asks for. Target LOC budgets become advisory rather than enforceable.
- **Evidence:** Decision Log "Phase 1 delivered over target LOC but passes quality bar".
- **How to avoid:** If you care about LOC, set it as a hard constraint with "if you exceed this, rewrite" language. Otherwise, accept that sub-agents ship defensive-style code by default — this is rarely bad.

### 5. Relying on an agent's reported test count

- **What was done:** Phase 3 agent reported "Ruff clean on all 5 new parsers". Truth: 1 I001 import-sort error in the modified `parsers/__init__.py` (which the agent had added 5 imports to).
- **Failure mode:** Would have merged with a lint failure. Caught by Archon running `ruff check` independently as a quality gate.
- **Evidence:** I001 auto-fix after Phase 3.
- **How to avoid:** Always re-run verification commands after a delegation. Treat agent reports as hints, not evidence. Per Bash tool usage notes: "Trust but verify".

### 6. Intake items that have already been partly implemented

- **What was done:** The Phase 2 intake asked to "inject synthetic linux_kernel component into grype pipeline" without surveying whether that injection already existed. It did — in `sbom_service._scan_kernel_from_vermagic` (line 1216). The intake was written 2 days before the prior campaign shipped that helper.
- **Failure mode:** Delegating the intake verbatim would have produced ~200 LOC of redundant code.
- **Evidence:** Decision Log "Phase 2 scoped down after discovery". Phase 2 actual delta: +97 LOC vs implied ~250 LOC.
- **How to avoid:** When loading an intake older than the last major merge to main, grep for the key symbols the intake proposes to add. Update the intake (or the delegation prompt) to reflect current reality before spawning the agent.

## Decisions NOT Made (worth noting)

These are options the campaign considered and rejected — recording them so future campaigns don't re-evaluate:

- **`product_name` / `product_source` VARCHAR columns:** rejected for `metadata_` JSONB. Reason: optional field, avoid migration. Future UI sort-by-product can use a computed index.
- **`md1imgpy` pip dep:** rejected for native Python port. Reason: GPL-3 redistribution review + no md1dsp support.
- **`kaitaistruct` + build-time `.ksy` compilation:** rejected. Reason: ~400 LOC generated per format + compile step in Docker build = fragility.
- **`fakeredis` test dep:** rejected for inline FakeRedis mock class. Reason: zero-dep test suite.
- **Per-firmware `installed` CycloneDX property:** rejected for `dependencies.provides`. Reason: `installed` isn't in CycloneDX v1.6 schema.
- **Storing `_KMOD_TO_SUBSYSTEM` in YAML:** rejected, stays in matcher module. Reason: tightly coupled to matcher logic + basename normalization; YAML-ification adds indirection without user-facing benefit.

## Bugs Found During Live Verification (Phase 4)

Real kernel.org vulns.git data surfaced three schema edge cases that unit-test-only development would have missed:

1. **`cveID` (capital D) vs spec's `cveId`.** Extractor now accepts both keys.
2. **`status="unaffected" lessThan="X"` range encoding.** Means "fixed at version X"; extractor derives `[None, X)` from those.
3. **Single-point `status="affected" version="X"` without `lessThan`.** Extractor generates implicit upper bound `X.<patch+1>` via `_next_patch()` helper.

These are documented in the Phase 4 Feature Ledger and would be easy to miss without the live run. Rule: when a spec's schema is authored by a real org (not the consumer), expect drift between the documented schema and the shipped data.
