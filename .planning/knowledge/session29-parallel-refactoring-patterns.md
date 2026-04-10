# Patterns: Session 29 — Parallel Visual Polish + Review Backlog

> Extracted: 2026-04-10
> Work: ThreatIntelTab polish, R4 Error Boundary, R5 config centralization, R7 pagination, R10 firmware dedup
> Method: 2 Explore agents (research) → 5 build agents (parallel, zero file overlap)

## Successful Patterns

### 1. File-overlap analysis before parallel dispatch
- **Description:** Before launching 5 parallel build agents, mapped which files each would touch. Verified zero overlap across all workstreams (ThreatIntelTab.tsx / App.tsx+ErrorBoundary.tsx / statusConfig.ts+4 consumers / projects.py+documents.py / files.py). This allowed true parallel execution with no merge conflicts.
- **Evidence:** All 5 agents completed independently. `git diff --stat` showed 13 code files changed with no conflicts. TypeScript clean on first check.
- **Applies when:** Running 3+ parallel agents on the same codebase. Always map file ownership before dispatch.

### 2. Research-then-execute two-phase workflow
- **Description:** Launched 2 Explore agents in parallel first (one for ThreatIntelTab state, one for R1-R10 assessment). Used their findings to determine which items were actionable, estimate effort/risk, and write precise build prompts. Did NOT start building until research completed.
- **Evidence:** Research revealed R1 (1816 lines, high risk), R3 (710 lines, high risk), R8/R9 (medium risk, needs coordination) should be skipped. Built only R4, R5, R7, R10 (all low risk, trivial-small effort). Zero rework needed.
- **Applies when:** Backlog triage with 5+ items of varying effort/risk. Research phase prevents wasted work on high-risk items.

### 3. Superset config extraction for centralization
- **Description:** When centralizing duplicated SEVERITY_CONFIG across 4 files, created a superset type with all properties any consumer needs (icon, className, bg, label, order). Each consumer uses only the properties it needs. This avoids needing separate configs for slightly different use cases.
- **Evidence:** `SeverityConfigEntry` in statusConfig.ts has both `className` (text color) and `bg` (badge background). FindingsList uses `.bg`, VulnerabilityRow uses `.bg`, both work from the same config.
- **Applies when:** Extracting duplicated configs where consumers use overlapping but not identical property sets.

### 4. Backward-compatible API pagination
- **Description:** Added `limit`/`offset` Query params with defaults matching previous behavior (limit=100, offset=0). Existing callers without params get identical results. No frontend changes needed.
- **Evidence:** `curl /api/v1/projects` returns same results as before. `curl /api/v1/projects?limit=1&offset=1` returns correct subset.
- **Applies when:** Adding pagination to existing endpoints. Always use optional params with backward-compatible defaults.

### 5. Deps.py as centralized dependency pattern
- **Description:** `files.py` had a 15-line `get_file_service()` that reimplemented firmware lookup identical to `deps.py:resolve_firmware`. Replaced with `Depends(resolve_firmware)` + a 2-line wrapper. Eliminated duplicate code and ensures consistent error handling.
- **Evidence:** `files.py` diff shows -15 lines of custom firmware lookup, +3 lines of import + Depends usage. All 6 file endpoints still work (verified via curl).
- **Applies when:** Any router that resolves firmware should use `Depends(resolve_firmware)` from deps.py, never reimplement the lookup.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Skip R1 (emulation_service.py 1816 lines) | High risk: 34 methods with internal state coupling. Medium-large effort. | Correct — would have consumed the session and risked regression |
| Skip R3 (ProjectDetailPage.tsx 710 lines) | High risk: stores interact with ProjectStore, polling/SSE embedded. | Correct — needs dedicated session with careful state extraction |
| Skip R8/R9 (error handling + commit patterns) | Medium risk, needs coordinated approach across 20+ routers. | Correct — these are architectural decisions, not quick wins |
| Do R4 Error Boundary first | Trivial effort (54 lines), zero risk, massive safety improvement. No error boundary = single route crash kills entire app. | Completed in 43 seconds. High value/effort ratio. |
| Group R7+R10 assessment together | Both backend-only, different files, small scope. | Both completed cleanly in one research assessment |
