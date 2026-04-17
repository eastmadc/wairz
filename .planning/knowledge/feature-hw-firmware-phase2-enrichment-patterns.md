# Patterns: Hardware Firmware Phase 2 Enrichment

> Extracted: 2026-04-17
> Campaign: `.planning/campaigns/completed/feature-hw-firmware-phase2-enrichment.md`
> Postmortem: `.planning/postmortems/postmortem-feature-hw-firmware-phase2-enrichment-2026-04-17.md`
> Audit entries matched: 30 (campaign-period audit.jsonl)

## Successful Patterns

### 1. Pre-delegation context reads catch scope redundancy

- **Description:** Before delegating any phase, Archon reads the files the phase will touch to confirm the spec still matches reality. For Phase 2, reading `grype_service.py` + `sbom_service.py` revealed that `_scan_kernel_from_vermagic` (line 1216) already injected the synthetic `linux-kernel` CPE the intake asked the phase to build. The delegation prompt was rewritten to scope down before any code was written.
- **Evidence:** Decision Log entry "Phase 2 scoped down after discovery"; Phase 2 delivered at +97 LOC net change vs. the intake's implied ~250 LOC.
- **Applies when:** Any multi-phase campaign where the intake was written before the current codebase state was fully surveyed. Especially valuable for "wire X into Y" phases — the integration may already partly exist.

### 2. "No new dependencies" as a strategic constraint

- **Description:** Phase 3 (MediaTek parsers) and Phase 4 (vulns.git index) both had obvious pip-install paths: `md1imgpy`, `kaitaistruct`, `fakeredis`. Archon rejected all three in the delegation prompts and asked for native implementations. Result: 845 LOC of native parsers + 559-LOC inline FakeRedis fixture, zero deps, zero backend+worker rebuild coupling.
- **Evidence:** Decision Log "Phase 3 no-deps strategy"; `git diff backend/pyproject.toml` shows empty across the whole campaign.
- **Applies when:** The proposed dep is (a) GPL-3/AGPL, or (b) <500 LOC of format parsing that can be ported natively, or (c) only used in tests (use inline mocks instead). Also applies when the dep would require rebuilding the Docker image, which in Wairz triggers the "rebuild worker too" rule (CLAUDE.md rule 8).

### 3. Live verification during a campaign phase

- **Description:** Phase 4's delegate agent actually ran `git clone vulns.git` and `kvi.lookup("net/bluetooth/", "6.6.102")` inside the backend container. Indexed 10,725 CVEs; returned 354 high-confidence Bluetooth matches. The delegation prompt explicitly asked for a live run, not just unit tests, and surfaced three real-world schema edge cases that stubbed tests would have missed (`cveID` capital D; `status=unaffected lessThan=X`; single-point versions without `lessThan`).
- **Evidence:** Phase 4 Feature Ledger entry; three real-world schema fixes documented.
- **Applies when:** The phase depends on external data or network (vuln feeds, NVD, GitHub API, package registries). A single live run will surface schema drift and edge cases that no mock can. Only applies when the data source is free / public / idempotent — don't live-hit rate-limited APIs from a build.

### 4. YAML-driven classification with graceful degradation

- **Description:** `patterns_loader.py` compiles regexes at import time but wraps every step in defensive try/except: missing YAML file → log + empty tables; malformed YAML top-level → log + empty; regex compile failure on one entry → log + skip that entry, continue with others. Single-entry errors never take down the whole classifier.
- **Evidence:** `patterns_loader._safe_load`, `_compile_patterns`; 117/117 tests pass including malformed-YAML coverage.
- **Applies when:** Any module that loads user-authorable / community-contributed data (YAML patterns, JSON manifests, regex rules). The alternative — strict validation that crashes on first error — makes local development harder when a collaborator ships a bad entry.

### 5. Per-phase commits with scope claim for multi-session campaigns

- **Description:** Each phase landed as its own commit (a41fcff, e6cd4b0, 28fc27f, 3f7fcf0, a102004) with a descriptive message that explains _why_ the scope was what it was. The scope claim (`archon-hw-firmware-phase2.json`) registered the campaign's file scope at start and was released at archive time. Future Archon runs can detect in-progress claims before delegating.
- **Evidence:** `git log --oneline` for the session; `.planning/coordination/claims/` lifecycle.
- **Applies when:** Any multi-phase campaign. Even if the whole campaign completes in one session (as this one did), per-phase commits document why each deviation was chosen and give clean revert points.

### 6. Delegate-and-verify — re-run agent claims yourself

- **Description:** After every agent delegation, Archon re-ran the pytest + ruff commands directly (not trusting the agent's reported counts). The Phase 3 I001 import-sort issue was caught this way — the agent reported "clean" but ruff actually had 1 new issue. 30-second auto-fix.
- **Evidence:** Post-Phase-3 ruff check + `ruff --fix` step.
- **Applies when:** Always, after any sub-agent delegation. Agent summaries describe intent, not necessarily outcome. Re-running validation takes ~30 seconds and catches ~1 issue per phase on average.

### 7. Direction alignment check as a gate, not a ceremony

- **Description:** Every 2 phases, Archon re-read the campaign's direction field and compared it to the Feature Ledger. Neither alignment check caught drift, but both confirmed each phase was still serving the original "fix empty feature: Vendor=None, 0 CVEs, flat table" direction. Value is less in catching drift than in forcing the orchestrator to re-read the goal.
- **Evidence:** Two alignment entries in the Decision Log.
- **Applies when:** Any Archon campaign of ≥3 phases. Even when alignment passes, the forced re-read catches scope creep one phase later.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Adopt intake's 5-phase decomposition verbatim | Intake was already research-backed (4 OSS scouts) and phase-decomposed | ✅ Delivered in 1 session vs 6 estimated |
| Store `product` + `kernel_semver` in `metadata_` JSONB, not new columns | Avoids migration churn for optional fields | ✅ No migrations needed across 5 phases |
| Phase 2: skip grype_service.py changes, add Tier 4 instead | sbom_service already injects the linux-kernel CPE | ✅ Saved ~200 LOC redundant work |
| Phase 3: native parsers instead of md1imgpy / kaitaistruct | GPL-3 licensing + Docker build fragility | ✅ Zero new deps; 845 LOC native |
| Rename `mtk_gfh` → `mtk_lk` in magic-byte classifier | `\x88\x16\x88\x58` is the LK partition header, not GFH alone | ✅ Tests + classifier_patterns updated |
| Phase 4: lazy Redis-backed index; fail-soft if empty | Don't block first CVE match on cold-cache 100MB clone | ✅ 354 live matches after first daily sync |
| Phase 4: 45-entry basename → subsystem dict in the matcher module | Tight coupling to matcher logic; YAML-ification adds indirection without value | ✅ Covers ~80% of common kmods |
| Phase 5: use `dependencies.provides` (CycloneDX 1.6 idiom) over per-firmware `installed` property | `installed` isn't in the v1.6 schema; `provides` is the canonical chip→firmware link | ✅ Valid v1.6 doc generated |
| Phase 5: 4-tab layout (Tree default, Flat, Drivers, Driver graph) | Preserves all existing UX (Flat, Drivers) + adds new (Tree, Graph) | ✅ Frontend typecheck clean; BlobDetail pane unchanged |
| Commit archive (a0dd65e) removes the intake file | Intake item is now delivered; keeping the intake would re-queue it | ✅ 24 intake items remain (this one dropped) |

## How to apply these patterns on the next campaign

- **Before delegating a "wire X into Y" phase:** do a 5-minute grep for existing calls to X or Y. Half the time the integration already exists and the phase is smaller than the intake suggested.
- **Before adding any pip dep:** can the format be parsed in ~200 LOC of native code? If yes, it probably should be. If the dep is GPL-3 and you're planning to redistribute, the answer is almost always "native port".
- **Before declaring a phase done:** re-run the verification commands directly. Don't trust the agent's report — verify.
- **When emitting CycloneDX/HBOM:** the 1.6 spec has evolved away from ad-hoc "installed" properties; use `dependencies.provides` and `dependencies.dependsOn` as the canonical link types.
