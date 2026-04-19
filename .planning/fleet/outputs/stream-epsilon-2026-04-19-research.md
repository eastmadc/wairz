# Stream Epsilon — Research (Wave 2, 2026-04-19)

Intake: `feature-latte-llm-taint-analysis.md` (two MCP tools, isolated files, LLM-in-client).

## Baseline

- **Parent branch HEAD:** `4cc5354` (Wave 1 ship).
- **Current MCP tool count:** 170 (via `create_tool_registry()` with all registrants). Target post-ship: 172 (two new tools registered).
- **pyyaml:** present — `backend/pyproject.toml:41 pyyaml>=6.0`, import check `yaml.__version__ == 6.0.3`. No dependency work.

## Existing plumbing to reuse (read-only)

- **ToolContext** (`backend/app/ai/tool_registry.py`): `project_id`, `firmware_id`, `extracted_path`, `db (AsyncSession)`, `extraction_dir`, `detection_roots`. Method `resolve_path(virtual_path) → real_fs_path` is the canonical sandbox gate (rule 1 — path traversal).
- **ToolRegistry.register(name, description, input_schema, handler)** — single-shape signature. `create_tool_registry()` (NOT `build_registry` — research brief has stale name) is the factory in `backend/app/ai/__init__.py`.
- **Cache surface** (`app/services/ghidra_service.py`):
  - `get_analysis_cache()` returns the singleton cache.
  - `get_binary_sha256(path)` — thread-executor SHA256.
  - `get_cached(firmware_id, binary_sha256, operation, db) → dict | None`.
  - `store_cached(firmware_id, binary_path, binary_sha256, operation, dict, db)` — uses `db.flush()` internally per rule 3.
  - `get_imports(binary_path, firmware_id, db) → list[{library, name}]`.
  - `get_xrefs_to(...)`, `get_xrefs_from(...)` — both return `list[dict]` and do reverse-scan fallback.
- **`analysis_cache.operation`:** `VARCHAR(512)` (rule 15). Cache keys up to 512 chars fit safely.
- **Existing sinks/sources** (`backend/app/ai/tools/binary.py:61-73`): `_DEFAULT_SOURCES` + `_DEFAULT_SINKS` tuples used by `trace_dataflow`. We can reference the list for parity but ship our own YAML (intake mandates YAML dictionaries) so the LATTE tool has first-class extensibility without editing Python.
- **Truncation:** `app.utils.truncation.truncate_output(text)` — 30KB cap, cuts at last newline. Called automatically by `registry.execute()`.

## Existing helper tools composed at handler level

The new tools are pure prompt composers — they call the underlying CACHE methods (not the registered tool handlers, which return formatted strings). Specifically we reuse:

- `cache.get_imports(...)` — filter to sinks (stage 1).
- Inline xref walk on `cache.get_cached(sha, "xrefs")` — avoids re-dispatching through `registry.execute`.
- `decompile_function(path, name, firmware_id, db)` from `app/services/ghidra_service.py` — cached; already how `_handle_decompile_function` uses it.

## Conventions observed

- **Returns:** every handler returns `str` — multi-line formatted text; no structured types. Prompts for MCP client are also strings.
- **Ghidra cache keys:** e.g. `taint_analysis:<md5-12>`, `disasm:<func>`, `string_refs:<md5-12>`. Our new keys: `taint_scan:<md5-12>`, `taint_deepdive:<md5-12>`. Both ≤ 40 chars → VARCHAR(512) safe (rule 15).
- **Errors:** raise/catch inside handler, return `f"Error: {msg}"` — never bubble.
- **Tests:** `backend/tests/test_*.py`, pytest-asyncio. Canonical fixtures (`firmware_root`, `tool_context`) available via `conftest.py`. Tool-handler tests mock `MagicMock()` on `db`; service-layer mocking via `unittest.mock.patch`.

## Plan — Tools

### Tool 1: `scan_taint_analysis`

**Inputs:** `binary_path` (req), `min_confidence` (low|medium|high, default=medium), `max_candidates` (int, default=50, cap=200), `focus_cwe` (optional list).

**Pipeline:**

1. Resolve path via `context.resolve_path(binary_path)`; check file exists.
2. `cache.get_imports(...)` → filter to any import name appearing in `_taint_sinks.yaml` `sink_name` set.
3. For each matched sink, enumerate callers via `cache.get_cached(sha, "xrefs", db)` and the same reverse-scan pattern used in `_handle_find_callers`.
4. **Rank** each candidate caller by score:
   - `+2` per distinct dangerous sink invoked
   - `+1` per distinct user-input source reachable (sources imported in the caller's function — approximated by which source names appear in the caller's xrefs_from)
   - `+1` if caller is `main` or the function has `>=3` callers (centrality proxy via incoming xref count)
5. **Confidence gate:**
   - `low`: keep everything with score ≥ 1.
   - `medium`: require ≥ 2 sinks OR ≥ 1 source + ≥ 1 sink.
   - `high`: require ≥ 2 sinks AND ≥ 1 source.
6. Slice to `max_candidates`, descending score.
7. For each candidate, pull cached decompilation via `decompile_function(...)`. Skip (best-effort) if decomp fails — don't error the whole scan.
8. Compose prompt: header (binary info), candidate list (function name + offset + sinks touched + sources visible + decomp snippet capped at 2KB each), sink inventory, CoT instruction block, JSON output schema.
9. Cache the composed prompt in `analysis_cache` keyed on `(sha, f"taint_scan:{md5(min_confidence|max_candidates|focus_cwe)}")`.
10. Truncate to 30KB and return.

### Tool 2: `deep_dive_taint_analysis`

**Inputs:** `binary_path` (req), `function_name` (req), `include_callers` (default 2), `include_callees` (default 5), `focus_cwe` (optional list).

**Pipeline:**

1. Resolve path; sanity-check function exists (via cache.get_cached "functions").
2. Decompile target via `decompile_function`.
3. Walk 2 hops in each direction: `xrefs_to` (callers of target, then callers of those), `xrefs_from` (callees). Dedupe.
4. Classify xrefs: match against sources YAML → "POTENTIAL SOURCE"; match against sinks YAML → "POTENTIAL SINK".
5. Compose 4-stage CoT prompt matching LATTE paper shape:
   - **Stage 1 — Sink-ID:** "Which call sites in the decomp body act as sinks? Quote 3+ consecutive lines for each."
   - **Stage 2 — Source-ID:** "Which parameters / call sites introduce untrusted input? Quote 3+ lines for each."
   - **Stage 3 — Dataflow:** "For each (source, sink) pair, trace how data propagates. Cite line numbers from the decomp."
   - **Stage 4 — CWE + exploitability:** "Classify by CWE-78/120/134/190/787 etc. State confidence low/med/high. Output JSON schema."
6. Cache under `taint_deepdive:<md5(function|include_callers|include_callees)>`.
7. Truncate to 30KB.

## YAML schema

`_taint_sinks.yaml`:

```yaml
# Sink families; name must match symbol imported by binary
families:
  command_injection:
    cwe: CWE-78
    sinks: [system, popen, execl, execle, execlp, execv, execve, execvp,
            doSystemCmd, twsystem, CsteSystem, do_system]
  buffer_overflow:
    cwe: CWE-120
    sinks: [strcpy, strcat, sprintf, vsprintf, gets, memcpy, strncpy]
  format_string:
    cwe: CWE-134
    sinks: [printf, fprintf, vprintf, vfprintf, syslog]
  integer_overflow:
    cwe: CWE-190
    sinks: [malloc, calloc, realloc]
  path_traversal:
    cwe: CWE-22
    sinks: [fopen, open, openat, unlink, rename]
```

`_taint_sources.yaml`:

```yaml
families:
  network:
    sources: [recv, recvfrom, recvmsg, read, accept]
  env:
    sources: [getenv, secure_getenv]
  user_io:
    sources: [fgets, scanf, fscanf, sscanf, gets]
  http:
    sources: [websGetVar, httpGetEnv, CGI_get_field, get_cgi, websGetFormString]
  nvram:
    sources: [nvram_get, nvram_safe_get, nvram_bufget]
  files:
    sources: [fread, fgetc]
```

## Test strategy (rule 19 applied)

**Evidence-first:** `backend/tests/fixtures/` has `apk/`, `hardware_firmware/`, `mobsf_baselines/` — NO taint fixtures. No existing DVRF binary.

**Decision:** DO NOT compile a real ELF. Instead, unit-test the composition layer by mocking `cache.get_imports`, `cache.get_cached(..., "xrefs")`, and `decompile_function` with synthetic data that represents a 5-function binary with 3 planted CWE patterns. This tests the filter/rank/prompt pipeline end-to-end WITHOUT a physical binary — which is what the tool boundary actually needs. The DVRF 80% recall target is an INTEGRATION test requiring real Ghidra + real binary; mark as `TBD at integration test` follow-up.

Tests cover:

1. Sink YAML loads + parses.
2. Source YAML loads + parses.
3. `scan_taint_analysis` ranks correctly given mocked imports + xrefs.
4. `min_confidence=high` prunes candidates with only 1 sink / 0 source.
5. Prompt contains: binary info, candidate list, sink inventory, instruction block.
6. Prompt fits under 30KB.
7. Cache key stable across calls with same args.
8. `deep_dive_taint_analysis` 4-stage structure present in output.
9. Deep-dive quotes decompiled lines anchored by line number.
10. Path traversal rejection on both tools.

## Risks identified

- **Class-shape change** (rule 20): new tool registration = new class in registry at import time. Requires `docker compose up -d --build backend worker`, not just restart.
- **`db.flush()` not commit** (rule 3): we use `cache.store_cached` which already flushes.
- **Prompt size blow-up:** 50 candidates × 2KB decomp = 100KB pre-truncate. Truncation at 30KB will cut off mid-candidate. Cap decomp snippet per candidate at 1.5KB and hard cap `max_candidates ≤ 20` when the composed body would exceed 25KB pre-truncate.

## File manifest (new only — rule: `git add` specific files, never `-A`)

```
backend/app/ai/tools/taint_llm.py
backend/app/ai/tools/_taint_sinks.yaml
backend/app/ai/tools/_taint_sources.yaml
backend/tests/test_taint_llm.py
.planning/fleet/outputs/stream-epsilon-2026-04-19-research.md
.planning/fleet/outputs/stream-epsilon-2026-04-19-wave2.md
```

Modified:

```
backend/app/ai/__init__.py   # ADD-ONLY: import + register_taint_llm_tools call
```

No docker-compose, no pyproject, no existing tool files.
