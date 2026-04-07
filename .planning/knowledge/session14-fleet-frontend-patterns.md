# Patterns: Session 14 — Fleet Wave (Binary Diff + Frontend Gaps + Intel HEX)

> Extracted: 2026-04-07
> Campaign: .planning/fleet/session-binary-diff-frontend-gaps.md
> Postmortem: none (session-level extraction)

## Successful Patterns

### 1. Worktree agents wrote to main repo (silent fallback)
- **Description:** Fleet agents spawned with `isolation: "worktree"` returned `worktreeBranch: undefined` but their changes persisted in the main working directory. The worktree mechanism silently fell back to writing directly to the repo.
- **Evidence:** Second round of agents found all work "already done" — confirming first round wrote to the main tree.
- **Applies when:** Using Fleet with worktree isolation. Don't assume worktree branches will be created — verify with `git branch` and check working directory.

### 2. Zero-overlap scope partitioning enables safe parallelism
- **Description:** Three agents (binary diff backend+frontend, CVE triage UI, Security Tools page) ran simultaneously with zero file overlap. All completed without conflicts.
- **Evidence:** All three agents completed, TypeScript compiled clean, no merge conflicts.
- **Applies when:** Any multi-agent work where file scopes can be cleanly partitioned.

### 3. Docker cp bypasses stale build cache
- **Description:** `docker compose build` used cached COPY layers even after source files changed. Direct `docker cp` into running containers was the reliable workaround.
- **Evidence:** Built backend 3 times with cache; `grep` inside container showed old code. `docker cp` immediately fixed it.
- **Applies when:** Docker builds don't pick up Python file changes. Use `docker cp` for quick iteration, then do a proper `--no-cache` build later.

### 4. Custom JSON Schema form renderer (no external deps)
- **Description:** Built a custom form renderer for tool input schemas instead of adding @rjsf/core dependency. Handles string, number, boolean, enum, and path fields. ~150 lines of code.
- **Evidence:** ToolForm.tsx works for all 81 tool schemas without any new npm dependencies.
- **Applies when:** Building forms from JSON Schema where schemas are simple (1-5 fields). Avoid adding heavy form libraries when the use case is straightforward.

### 5. RTOS injection into SBOM at router level
- **Description:** Instead of modifying the SbomService class (which only has extracted_root), injected RTOS components from firmware.os_info at the router level after generate_sbom() returns.
- **Evidence:** uC/OS-II appears in SBOM as operating-system component with high confidence.
- **Applies when:** Adding metadata-derived components to SBOM that don't come from filesystem scanning.

### 6. Pure Python Intel HEX parser (no external tools)
- **Description:** Wrote a self-contained Intel HEX parser supporting all 6 record types, checksum validation, region detection, and gap padding. No dependency on objcopy or intelhex library.
- **Evidence:** Correctly parsed Signia PowerPack firmware: 2 memory regions, entry point, 405KB binary output.
- **Applies when:** Processing Intel HEX files in Docker containers where external tools may not be available.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Use fleet for 3 parallel streams | Zero scope overlap between binary diff, CVE triage, and security tools | All three completed simultaneously |
| Docker cp instead of rebuild | Build cache was stale, --no-cache takes 5+ min on RPi | Immediate deployment, saved ~15 min |
| Custom form renderer vs @rjsf | Avoid new dependency for simple schemas | Worked for all 81 tools |
| RTOS injection at router level | SbomService doesn't have firmware DB access | Clean separation, no service refactoring needed |
| Pure Python HEX parser | Can't guarantee objcopy in Docker | Portable, testable, handles edge cases |
| ARM Cortex-M manual override | cpu_rec returned None for raw binary blob | Correct identification confirmed by string analysis |
