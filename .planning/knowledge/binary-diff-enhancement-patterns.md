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

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| LIEF over pyelftools | pyelftools can't read function body bytes; LIEF provides `get_content_from_virtual_address()` | Worked — enabled hash-based comparison |
| .symtab → .dynsym → section fallback | Most firmware binaries are stripped; need coverage at every level | Worked — section comparison provides value for stripped binaries |
| Defer Tier 3 (radiff2) | Phase 1-2 deliver core value; radiff2 adds complexity | Correct call — Capstone + LIEF covers the primary use case |
| Separate instruction diff endpoint | Keep binary diff response fast; load asm detail on-demand | Worked — UI remains responsive |
