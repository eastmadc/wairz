# Anti-patterns: Session 5 — YARA, Multi-Firmware, Comparison Improvements

> Extracted: 2026-04-03
> Source: session 5 commits and debugging

## Failed Patterns

### 1. scalar_one_or_none() on tables that can have multiple rows
- **What was done:** Security audit endpoint queried `Firmware.where(project_id == X)` and called `scalar_one_or_none()`, assuming one firmware per project.
- **Failure mode:** `MultipleResultsFound` exception (500 error) when user uploaded a second firmware version.
- **Evidence:** User hit the bug immediately after uploading a second firmware to a project.
- **How to avoid:** Never use `scalar_one_or_none()` on a one-to-many relationship. Use `.order_by().limit(1)` for "get first" or `.all()` for "get all". Grep for `scalar_one_or_none` across the codebase when adding multi-record support to any entity.

### 2. Global truncation limit across categories
- **What was done:** Comparison service used a single `total_entries` counter shared across added/removed/modified categories, with a 500 global limit.
- **Failure mode:** When one category (added: 1,796 files) consumed the entire budget, other categories (removed: 88, modified: many) got 0 entries. User saw only "Added" with 0 removed/modified.
- **Evidence:** User reported comparison showing only added files despite real changes existing between firmware versions.
- **How to avoid:** Always truncate per-category when returning categorized results. Each category should have its own independent limit.

### 3. YARA rules with unreferenced strings
- **What was done:** Wrote YARA rules with strings defined in the `strings:` section but not referenced in the `condition:` section.
- **Failure mode:** `yara.SyntaxError: unreferenced string "$rc4"` — YARA compiler treats unreferenced strings as errors.
- **Evidence:** 5 separate unreferenced string errors across 3 rule files caught during test runs.
- **How to avoid:** Every string defined in a YARA rule's `strings:` section MUST appear in its `condition:`. Use `any of them` if all strings should match. Test rule compilation before committing.

### 4. Complex regex in YARA rules
- **What was done:** Used a negative lookahead regex for IP address matching (`(?!10\.)(?!127\.)...`) in a YARA rule.
- **Failure mode:** `yara.SyntaxError: invalid regular expression` — YARA's regex engine doesn't support all PCRE features (no lookaheads).
- **Evidence:** IP address detection rule failed to compile with "invalid regular expression" error.
- **How to avoid:** YARA uses a limited regex syntax (no lookaheads, lookbehinds, or backreferences). Simplify patterns or use multiple simpler rules.

### 5. Assuming yara.Rules supports len()
- **What was done:** Called `len(rules)` on a compiled `yara.Rules` object.
- **Failure mode:** `TypeError: object of type 'yara.Rules' has no len()`.
- **Evidence:** Test failures in `test_compiles_builtin_rules` and `test_compiles_extra_rules`.
- **How to avoid:** `yara.Rules` is iterable but doesn't support `len()`. Use `sum(1 for _ in rules)` to count. Always check library API docs rather than assuming standard Python protocols.

### 6. Merge-induced syntax errors in squash commits
- **What was done:** Used `git checkout clean-history -- file.py` to resolve merge conflicts during squash, but the source branch had code that assumed a different try/except structure than what was in the conflict.
- **Failure mode:** `SyntaxError: invalid syntax` — an `elif` appeared after an `except` clause where it wasn't valid.
- **Evidence:** `file_service.py` line 378 had `elif os.path.isdir(entry_path)` after `except Exception: is_broken = True`, which is invalid Python.
- **How to avoid:** After any merge/squash, always run the test suite before committing. Conflict resolution by taking one side wholesale can miss structural incompatibilities.

### 7. Fatal exit on recoverable state (MCP server)
- **What was done:** MCP server called `sys.exit(1)` when project had no firmware, making the error indistinguishable from network/Docker problems.
- **Failure mode:** Users couldn't connect MCP to a new project, got "Failed to reconnect" with no actionable information. GH #21.
- **Evidence:** `_load_project()` raised `ValueError` → caught in `run_server()` → `sys.exit(1)`.
- **How to avoid:** Services should start in degraded mode rather than crashing. Return errors at the operation level, not at startup. Reserve `sys.exit()` for truly unrecoverable states (DB unreachable, config missing).

### 8. Stale intake items
- **What was done:** Intake plan listed "File search (GH #2)" as a priority, but it was already fully implemented in session 2.
- **Failure mode:** Wasted research time discovering the feature already existed.
- **Evidence:** FileTree component already had complete search UI with glob patterns, results overlay, and click-to-navigate.
- **How to avoid:** Before building from an intake item, verify the current state. Grep for existing implementations. Check if the GitHub issue reporter confirmed the fix. Intake plans decay fast — always verify before executing.
