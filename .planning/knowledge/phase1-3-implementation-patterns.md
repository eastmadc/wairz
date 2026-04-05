# Phase 1-3 Bulk Implementation Patterns

**Type:** pattern
**Source:** session 2026-04-03, phases 1-3 roadmap implementation
**Applies to:** large multi-feature implementation sessions, parallel agent workflows

## Summary
Implemented 15 roadmap items (22 new MCP tools, +5,526 lines) in a single session using research-first then parallel-build methodology. All 355 tests passing, validated against real firmware.

## Details

### Research-first, build-second
Every phase followed: spawn 3-5 parallel research agents, review findings, then spawn 3-4 parallel build agents. This prevented wrong technology choices (e.g., discovered capa lacks MIPS support before committing to an implementation approach). User explicitly prefers this pattern.

### Manual JSON construction over heavy libraries
For SPDX 2.3 and VEX document generation, built JSON manually instead of pulling in spdx-tools or similar libraries. Rationale:
- Avoids ARM64/aarch64 compatibility risks on the target platform (Raspberry Pi)
- Matches existing pattern (CycloneDX SBOM was already manual JSON)
- Fewer pip dependencies = faster Docker builds, smaller attack surface
- Only redis>=5.0.0 was added across all 15 features

### Minimize new dependencies
21 of 22 tools used existing dependencies or subprocess calls to already-installed binaries (semgrep, radare2, etc.). This is the preferred approach: wrap existing tools via subprocess rather than adding Python library deps.

### Match existing parameter conventions
Binary analysis tools use `binary_path` not `path`. New tools must match existing conventions in their category. The capa tool initially used `path` and was caught by tests.

### Phase structure for parallel work
Breaking work into phases with clear boundaries (Phase 1 = foundational, Phase 2A/2B = analysis categories, Phase 3 = orchestration) allowed clean parallel execution without merge conflicts.

## Example
```
Phase workflow:
1. Research agents (parallel): "deep research capa binary analysis for embedded firmware"
2. Review: check findings, decide approach (subprocess vs library, parameter names)
3. Build agents (parallel): each agent gets one feature + isolated worktree
4. Verify: import checks, test suite, real firmware validation
```
