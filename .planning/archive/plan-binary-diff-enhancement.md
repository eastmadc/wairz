# Plan: Binary Diff Enhancement (Tier 1-2)

**Priority:** High | **Effort:** Medium (~10h across 4 phases) | **Status:** completed (session 14)
**Completed 2026-04-07:** Capstone instruction diff (session 12), decompilation diff REST endpoint, basic block hashing, frontend viewers all implemented.
**Seed:** `.planning/seeds/binary-diff-enhancement.yaml`
**Campaign:** `.planning/campaigns/binary-diff-enhancement.md`
**Route:** `/citadel:archon` (4 phases: backend Tier 1, backend Tier 2, frontend, E2E verify)

## Goal

Enhance existing LIEF-based binary comparison with instruction-level assembly diff (Capstone), stripped binary support (section-level + basic block hashing), and decompilation diff (Ghidra). Currently the comparison service handles function-level body hashing and section fallback, but lacks instruction-level granularity and decompilation-level semantic diffing.

## Current Implementation (verified 2026-04-06)

`comparison_service.py` already provides:
- LIEF-based function symbol extraction with body hashing (`_extract_function_hashes()`)
- Import/export set comparison
- Section-level hash fallback for stripped binaries
- `FirmwareDiff`, `BinaryDiff`, `FunctionDiffEntry` dataclasses
- File-level diff with SHA-256 hash comparison

What is missing:
- **Instruction-level diff** within modified functions (which exact instructions changed)
- **Decompilation diff** showing C pseudocode side-by-side
- **Basic block hashing** for better stripped binary matching
- **Control flow graph (CFG) comparison** for structural changes

## Phase 1: Capstone Instruction-Level Diff (~3h)

**Goal:** For functions marked as "modified" (same name, different body hash), show exactly which instructions changed.

**Implementation approach:**
1. Add `capstone` to `pyproject.toml` dependencies (already supports ARM, ARM64, MIPS, x86 -- all architectures Wairz handles)
2. New function `_instruction_diff(binary_a, binary_b, func_name, arch, mode) -> list[InstructionChange]`:
   - Use LIEF to extract function bytes at symbol offset + size
   - Disassemble both versions with Capstone (`Cs(arch, mode)` + `.disasm(code, addr)`)
   - Normalize: strip absolute addresses from operands (replace with relative offsets)
   - Run `difflib.SequenceMatcher` on normalized instruction tuples `(mnemonic, normalized_operands)`
   - Return list of `InstructionChange(offset, old_insn, new_insn, change_type)` where change_type is "added"/"removed"/"modified"
3. Add `instructions_changed: list[InstructionChange]` to `FunctionDiffEntry` dataclass
4. Populate automatically for all "modified" functions in `diff_binary()`

**Architecture detection:** Use LIEF's `binary.header.machine_type` to map to Capstone constants:
- `lief.ELF.ARCH.ARM` -> `CS_ARCH_ARM, CS_MODE_ARM` or `CS_MODE_THUMB`
- `lief.ELF.ARCH.AARCH64` -> `CS_ARCH_ARM64, CS_MODE_ARM`
- `lief.ELF.ARCH.MIPS` -> `CS_ARCH_MIPS, CS_MODE_MIPS32` (+ endianness)
- `lief.ELF.ARCH.x86_64` / `i386` -> `CS_ARCH_X86, CS_MODE_64` or `CS_MODE_32`

**Libraries:**
- `capstone>=5.0` -- multi-arch disassembly engine, pip-installable, pure Python bindings
- `difflib` (stdlib) -- SequenceMatcher for instruction-level comparison

## Phase 2: Decompilation Diff via Ghidra (~3h)

**Goal:** Side-by-side C pseudocode diff for modified functions using existing Ghidra infrastructure.

**Implementation approach:**
1. New function `diff_decompilation(binary_a, binary_b, function_name) -> DecompilationDiff`:
   - Reuse existing `analysis_service.decompile_function()` for both binaries (leverages Ghidra headless + caching)
   - Run `difflib.unified_diff()` on the decompiled C source lines
   - Return structured diff with context lines, additions, removals
2. New `DecompilationDiff` dataclass: `source_a: str, source_b: str, unified_diff: str, changes: list[DiffHunk]`
3. New REST endpoint: `GET /api/v1/projects/{pid}/comparison/{cid}/decompilation-diff?binary={path}&function={name}`
4. New MCP tool: `diff_decompilation` in `tools/comparison.py`

**Caching:** Both decompilations are independently cached in `analysis_cache` table (keyed by binary hash + function name). Only the diff computation itself is uncached (fast, <100ms).

**Considerations:**
- Ghidra decompilation takes 30-120s per binary, but cached after first run
- Function name matching across versions may fail if symbols renamed -- fall back to address-based matching
- Truncate diff output to MAX_TOOL_OUTPUT_KB for MCP responses

## Phase 3: Basic Block Hashing for Stripped Binaries (~2h)

**Goal:** Better diffing for stripped binaries beyond section-level comparison.

**Implementation approach:**
1. New function `_extract_basic_blocks(binary_path) -> dict[int, BasicBlock]`:
   - Use LIEF to get `.text` section bytes
   - Use Capstone to disassemble and split on branch/jump instructions to identify basic blocks
   - Hash each basic block's normalized instruction sequence (mnemonic + operand types, not absolute addresses)
2. Compare basic block hash sets between two binaries:
   - Blocks with same hash = unchanged code
   - Blocks present only in A = removed code
   - Blocks present only in B = added code
   - Report percentage of unchanged vs changed blocks
3. Add `basic_block_stats: BasicBlockStats` to `BinaryDiff` for stripped binary results

**Note:** This is a lightweight alternative to full CFG comparison. For deeper analysis, consider integrating QBinDiff (Quarkslab's belief-propagation-based differ) or Ghidriff (Ghidra-based Python differ) in a future phase.

## Phase 4: Frontend Enhancement (~2h)

**Goal:** Display instruction-level and decompilation diffs in the comparison UI.

**Changes to `ComparisonPage.tsx`:**
1. Expandable function rows showing instruction-level diff (color-coded: green=added, red=removed, yellow=modified)
2. "View Decompilation Diff" button on modified functions -> side-by-side Monaco diff editor
3. Basic block coverage indicator for stripped binaries (progress bar showing % unchanged)
4. Use Monaco Editor's built-in diff viewer (`MonacoDiffEditor`) for decompilation side-by-side

## Key Files

- `backend/app/services/comparison_service.py` -- core diff logic (extend)
- `backend/app/routers/comparison.py` -- REST endpoints (add decompilation-diff)
- `backend/app/schemas/comparison.py` -- response models (add InstructionChange, DecompilationDiff)
- `backend/app/ai/tools/comparison.py` -- MCP tools (add diff_decompilation)
- `frontend/src/pages/ComparisonPage.tsx` -- comparison UI (enhance)
- `frontend/src/api/comparison.ts` -- API client (add decompilation-diff)

## Acceptance Criteria

- [ ] Modified functions show instruction-level diff with colored additions/removals
- [ ] Decompilation diff available for any function present in both binaries
- [ ] Stripped binaries show basic block coverage statistics instead of "no symbol-level diff"
- [ ] Architecture auto-detected from ELF header (ARM, ARM64, MIPS, x86)
- [ ] All diffs truncated to MAX_TOOL_OUTPUT_KB for MCP tool responses
- [ ] Frontend displays instruction diff inline and decompilation diff in Monaco side-by-side

## Future Considerations

- **QBinDiff integration:** Quarkslab's belief-propagation function matcher could improve matching accuracy for renamed/reordered functions. Python library, supports Ghidra export. Would require `pip install qbindiff` and a Ghidra BinExport step.
- **Ghidriff integration:** Python CLI wrapping Ghidra's FlatProgramAPI for function-level diffing with HTML/JSON output. Could replace custom matching logic entirely.
- **AI-assisted diff summarization:** Use LLM to summarize what changed semantically (e.g., "buffer size check added", "authentication bypass removed"). This is an emerging practice per 2025 research (SySS, DeepBits).
