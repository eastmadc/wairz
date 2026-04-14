# Anti-patterns: Binary Diff Enhancement

> Extracted: 2026-04-08 (updated 2026-04-13 with S35 findings)
> Campaign: .planning/campaigns/completed/binary-diff-enhancement.md

## Failed Patterns

### 1. Campaign file phase status not updated during execution
- **What was done:** Campaign file phases and Feature Ledger all show "pending" / "not started" even though the campaign is marked `Status: completed` and work was delivered across sessions 12-14.
- **Failure mode:** Campaign file becomes unreliable as a source of truth — cannot tell what was actually built vs. what was planned.
- **Evidence:** Campaign file shows Phase 1-4 all "pending", Continuation State says "not started", but intake plan confirms completion and code exists in comparison_service.py
- **How to avoid:** When completing campaign phases (especially across multiple sessions), update the campaign file's phase status and Feature Ledger in the same commit as the code changes. The campaign file should always reflect reality.

### 2. pyelftools assumption for binary content access
- **What was done:** Initial comparison_service.py used pyelftools for binary diff, which could only compare function names and sizes — not actual content.
- **Failure mode:** Two functions with the same name and size but different code appeared identical, making the diff tool miss real changes.
- **Evidence:** Decision Log entry about choosing LIEF over pyelftools
- **How to avoid:** When building binary analysis tools, verify the library can access raw bytes (function bodies, section content), not just metadata. Test with a known-different binary pair early.

### 3. LIEF API version drift silently broke import/export extraction
- **What was done:** Used `sym.is_imported` and `sym.is_exported` — the LIEF <0.15 API. LIEF 0.15+ renamed these to `sym.imported` and `sym.exported`. The `except Exception: return None` handler silently caught the resulting `AttributeError`.
- **Failure mode:** `_extract_imports()` and `_extract_exports()` always returned `None`, making import/export diff comparisons impossible. No error, no warning, just silently missing data in the UI.
- **Evidence:** S35 unit test `test_extracts_libc_imports` failed → investigation via `dir(sym)` revealed the rename. Fixed by changing to `sym.imported`/`sym.exported`.
- **How to avoid:** (a) When using LIEF, verify attribute names with `dir()` on the actual object — LIEF renames properties across minor versions. (b) Avoid `except Exception: return None` when `None` is also a valid "no data" return — at minimum log the exception. (c) Pin LIEF version or test against the installed version's API.

### 4. Bare `except Exception: return None` hides real bugs
- **What was done:** Multiple functions in comparison_service.py use `except Exception: return None` as a catch-all for parse failures.
- **Failure mode:** When the exception is an API breakage (AttributeError, TypeError) rather than a genuine parse failure (corrupt file), the bug is completely invisible. The function returns the same `None` as "no data found."
- **Evidence:** `_extract_imports()` and `_extract_exports()` both used this pattern. LIEF API rename went undetected for months.
- **How to avoid:** Use specific exception types (`except lief.exception`, `except (OSError, ValueError)`) instead of bare `Exception`. If `return None` is the correct response for parse failures, at least add `logger.debug("...", exc_info=True)` for API-level errors. Test with known-good binaries that MUST return non-None.
