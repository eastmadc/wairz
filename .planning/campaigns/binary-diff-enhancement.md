# Campaign: Binary Diff Enhancement

**Status:** active
**Direction:** Replace broken pyelftools binary diff with LIEF body hashing + Capstone instruction diff
**Seed:** `.planning/seeds/binary-diff-enhancement.yaml`
**Branch:** feature/binary-diff-enhancement

## Claimed Scope
- `backend/app/services/comparison_service.py`
- `backend/app/routers/comparison.py`
- `backend/app/schemas/comparison.py`
- `frontend/src/pages/ComparisonPage.tsx`
- `frontend/src/api/comparison.ts`
- `frontend/src/types/`

## Phases

| # | Status | Type | Phase | Done When |
|---|--------|------|-------|-----------|
| 1 | pending | build | LIEF function hashing backend | `diff_binary()` returns hash-based diffs; section fallback works |
| 2 | pending | build | Capstone instruction diff endpoint | POST `/compare/binary/instructions` returns assembly diff |
| 3 | pending | build | Frontend: enhanced binary detail tab | Clicking modified function shows inline instruction diff |
| 4 | pending | verify | E2E test with real firmware | Compare the two DPCS10 firmware versions, verify function-level diffs appear |

## Phase 1: LIEF Function Hashing Backend

**Goal:** Replace `_extract_functions()` in comparison_service.py with LIEF body hashing.

**Changes:**

### comparison_service.py
1. **New `_extract_function_hashes(binary_path)` function:**
   - `lief.parse()` the binary
   - Try `.symtab` first (iterate static symbols for STT_FUNC)
   - Fall back to `.dynsym` (dynamic symbols)
   - For each function: `binary.get_content_from_virtual_address(addr, size)` → SHA-256
   - Return `{name: {size, hash, addr}}` or None
   
2. **New `_extract_section_hashes(binary_path)` function:**
   - Hash `.text`, `.rodata`, `.data`, `.bss` sections
   - Return `{section_name: {hash, size}}`
   - Used as fallback when no function symbols exist

3. **Update `diff_binary()`:**
   - Call `_extract_function_hashes()` instead of `_extract_functions()`
   - Compare by hash (not just size) — hash differs = modified
   - If no function symbols: fall back to section hash comparison
   - Populate new fields: `hash_a`, `hash_b`, `addr_a`, `addr_b` on FunctionDiffEntry

4. **New `_extract_import_export_sets(binary_path)` function:**
   - Use LIEF to extract imported/exported function names
   - Compare sets between versions (added/removed imports are security-relevant)

### schemas/comparison.py
- Add `hash_a`, `hash_b`, `addr_a`, `addr_b` optional fields to `FunctionDiffEntryResponse`
- Add `sections_changed: list[SectionDiffResponse]` to `BinaryDiffResponse`
- Add `imports_added`, `imports_removed`, `exports_added`, `exports_removed` to `BinaryDiffResponse`

### End Condition
- `diff_binary()` detects functions with same size but different hashes
- Section fallback works for stripped binaries
- All existing tests pass

---

## Phase 2: Capstone Instruction Diff Endpoint

**Goal:** Add API endpoint that returns disassembly diff for a specific function.

**Changes:**

### comparison_service.py
1. **New `diff_function_instructions(binary_a_path, binary_b_path, function_name, arch_hint)` function:**
   - Use LIEF to locate function by name in both binaries
   - Read function bytes via `get_content_from_virtual_address()`
   - Map ELF e_machine → Capstone `(CS_ARCH, CS_MODE)`:
     - `EM_AARCH64` → `(CS_ARCH_ARM64, CS_MODE_ARM)`
     - `EM_ARM` → `(CS_ARCH_ARM, CS_MODE_ARM)` or THUMB
     - `EM_MIPS` → `(CS_ARCH_MIPS, CS_MODE_MIPS32)` + endian
     - `EM_386` → `(CS_ARCH_X86, CS_MODE_32)`
     - `EM_X86_64` → `(CS_ARCH_X86, CS_MODE_64)`
   - Disassemble both, normalize to relative offsets
   - Generate unified diff with `difflib.unified_diff()`
   - Return `InstructionDiff` dataclass

### comparison.py (router)
- New endpoint: `POST /api/v1/projects/{project_id}/compare/binary/instructions`
- Input: `InstructionDiffRequest(firmware_a_id, firmware_b_id, binary_path, function_name)`
- Output: `InstructionDiffResponse(function_name, arch, diff_text, lines_added, lines_removed)`

### schemas/comparison.py
- Add `InstructionDiffRequest` and `InstructionDiffResponse` models

### comparison.ts (API client)
- Add `diffInstructions(projectId, fwAId, fwBId, binaryPath, functionName)` function

### End Condition
- Endpoint returns instruction-level diff for a modified function
- Architecture auto-detected from ELF header
- Cross-architecture comparison returns error message (not crash)

---

## Phase 3: Frontend Enhanced Binary Detail Tab

**Goal:** Make modified functions clickable, show instruction diff inline.

**Changes:**

### ComparisonPage.tsx
1. **Modified functions list becomes clickable:**
   - Each modified function row gets an expand/collapse toggle
   - Clicking calls `diffInstructions()` API
   - Loading state while fetching

2. **Inline instruction diff display:**
   - Reuse the same unified diff rendering as text diff tab
   - Green/red/blue highlighting for added/removed/context lines
   - Show function name + architecture as header
   - Monospace font, scrollable container

3. **Section diff display (for stripped binaries):**
   - When no function-level diff available, show section comparison table
   - Columns: Section, Size A, Size B, Hash Match (✓/✗)
   - Yellow info banner: "Binary is stripped — showing section-level changes"

4. **Import/export changes:**
   - Show added/removed imports and exports below function list
   - Security-relevant: new imports (e.g., `system()`, `exec()`) highlighted

### End Condition
- Clicking modified function shows instruction diff inline
- Stripped binaries show section-level comparison
- TypeScript typecheck clean

---

## Phase 4: E2E Verification

**Goal:** Test with the real DPCS10 firmware versions in project b59b8887.

**Steps:**
1. Compare DPCS10_260320 vs DPCS10_260403
2. Click `libaudiopolicyenginedefault.so` in binaries tab
3. Verify: function-level diffs appear (not "no symbol-level diff available")
4. Click a modified function → verify instruction diff renders
5. Find a stripped binary in the firmware → verify section fallback works

### End Condition
- Real firmware comparison shows function-level diffs
- Instruction diff is readable and correct
- No 500 errors, no UI crashes

---

## Decision Log
- 2026-04-06: Chose LIEF over pyelftools for function extraction — LIEF can read function body bytes, pyelftools cannot
- 2026-04-06: Chose .symtab → .dynsym → section fallback hierarchy for maximum coverage
- 2026-04-06: Deferred Tier 3 (radiff2) to separate campaign — Phase 1-2 deliver the core value
- 2026-04-06: Instruction diff endpoint is separate from binary diff (not inline) to keep responses fast

## Feature Ledger

| Feature | Status | Phase | Notes |
|---------|--------|-------|-------|
| LIEF function body hashing | pending | 1 | Replaces pyelftools size-only |
| Section hash fallback | pending | 1 | For stripped binaries |
| Import/export set diff | pending | 1 | Security-relevant changes |
| Capstone instruction diff | pending | 2 | Per-function assembly diff |
| Architecture auto-detection | pending | 2 | ELF e_machine → Capstone |
| Clickable function rows | pending | 3 | Expand to show asm diff |
| Section diff UI | pending | 3 | Fallback for stripped binaries |
| Import/export UI | pending | 3 | Highlight security-relevant |
| E2E with real firmware | pending | 4 | DPCS10 comparison test |

## Continuation State
Phase: 1, Sub-step: not started
Files modified: none yet
Blocking: none
