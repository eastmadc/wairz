# Patterns: Binary Diff Enhancement

> Extracted: 2026-04-08
> Campaign: .planning/campaigns/binary-diff-enhancement.md
> Postmortem: none

## Successful Patterns

### 1. LIEF over pyelftools for function body access
- **Description:** Chose LIEF for binary diff because it provides `get_content_from_virtual_address()` to read actual function bytes. pyelftools could only read symbol metadata (name, size) but not body content, making hash-based comparison impossible.
- **Evidence:** Decision Log entry 2026-04-06; comparison_service.py `_extract_function_hashes()` uses LIEF body reads + SHA-256
- **Applies when:** Any binary analysis task needing raw function bytes (diffing, hashing, content extraction)

### 2. Graceful fallback hierarchy for stripped binaries
- **Description:** Implemented `.symtab` → `.dynsym` → section hash comparison fallback chain. Most embedded binaries are stripped (no .symtab), so function-level diff isn't always possible. Section-level comparison still provides value.
- **Evidence:** Phase 1 design; section fallback renders in UI with yellow "stripped binary" banner
- **Applies when:** Any tool that needs function-level analysis — always plan a degraded-but-useful fallback for stripped binaries

### 3. Separate instruction diff endpoint from binary diff
- **Description:** Kept Capstone instruction-level diff as a separate POST endpoint (`/compare/binary/instructions`) rather than inlining it in the binary diff response. This keeps the binary diff fast (just hashes) and loads instruction detail on-demand.
- **Evidence:** Decision Log entry 2026-04-06; router has separate endpoint
- **Applies when:** When detailed analysis is expensive — provide summary first, detail on-demand

### 4. Fleet wave parallel build for independent features
- **Description:** Binary diff backend (Phase 1-2) and frontend (Phase 3) were built in parallel via fleet waves in session 14, alongside CVE Triage UI and Security Tools Page.
- **Evidence:** Session 14 handoff describes 3 parallel fleet tracks
- **Applies when:** Multiple independent features can be built simultaneously if scope boundaries are clean

### 5. Tests that compile real ELF binaries via gcc
- **Description:** Test fixtures use `subprocess.run(["gcc", ...])` inside pytest to compile tiny C programs with controlled function differences (add/mul/sub). This creates ELF binaries where we know exactly which functions are added, removed, or modified — enabling deterministic assertions on LIEF/Capstone output.
- **Evidence:** S35 `test_comparison_service.py` — `elf_pair` fixture compiles SRC_A and SRC_B with known diffs; `stripped_elf` fixture compiles + strips. 61 tests pass in 3.8s.
- **Applies when:** Testing any binary analysis tool that needs real ELF input (not mocks). Compile tiny C programs rather than shipping pre-built binaries — it's portable, explicit, and self-documenting.

### 6. Test-driven bugfinding in silent-failure code
- **Description:** Writing unit tests for code that uses `except Exception: return None` is especially high-value because such code cannot fail visibly. Tests immediately exposed that LIEF `is_imported`→`imported` rename silently broke import/export extraction.
- **Evidence:** S35 — `test_extracts_libc_imports` failed because `_extract_imports` returned None. Investigation revealed LIEF 0.15+ renamed `sym.is_imported` to `sym.imported`, and the except clause swallowed the AttributeError.
- **Applies when:** Any service with broad exception handling (especially `return None` on failure). Tests are the only way to distinguish "correctly found no data" from "code is broken but silent."

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| LIEF over pyelftools | pyelftools can't read function body bytes; LIEF provides `get_content_from_virtual_address()` | Worked — enabled hash-based comparison |
| .symtab → .dynsym → section fallback | Most firmware binaries are stripped; need coverage at every level | Worked — section comparison provides value for stripped binaries |
| Defer Tier 3 (radiff2) | Phase 1-2 deliver core value; radiff2 adds complexity | Correct call — Capstone + LIEF covers the primary use case |
| Separate instruction diff endpoint | Keep binary diff response fast; load asm detail on-demand | Worked — UI remains responsive |
| LIEF `imported`/`exported` over `is_imported`/`is_exported` | LIEF 0.15+ renamed these properties; old names raise AttributeError | Fixed S35 — silent bug found by tests |
