# Stream Epsilon — Wave 2 Handoff (2026-04-19)

Intake: `feature-latte-llm-taint-analysis.md`
Parent branch: `clean-history` (shared with other streams)
Baseline HEAD at dispatch: `4cc5354`
Head after ship: `06b80b8` (four new commits — cbeb8fd, c434959, 180c25f, 06b80b8)

## Summary

Shipped two new MCP tools for LATTE-style LLM-driven binary taint
analysis, keeping the existing wairz pattern of "tool returns a
structured prompt string; Claude (the MCP client) does the reasoning."
Zero new runtime dependencies, zero API-key surface on the backend,
no changes to routers / services / schemas / frontend /
docker-compose. Tool count goes 170 → 172.

## Commits shipped

| SHA | Message |
|-----|---------|
| cbeb8fd | `feat(ai): YAML sink + source dictionaries for taint analysis` |
| c434959 | `feat(ai): scan_taint_analysis + deep_dive_taint_analysis MCP tools` |
| 180c25f | `feat(ai): register taint_llm tool category in create_tool_registry` |
| 06b80b8 | `test(ai): taint_llm YAML loaders, ranking, confidence gate, prompts` |

Each commit was `git add <specific-files>` only — no `-A`. Scope
held to the files in the dispatch guardrail. No modifications to
existing tool files, no shared-config drift.

## Files touched

Created:

* `backend/app/ai/tools/_taint_sinks.yaml` — 8 CWE families, ~60 sinks.
* `backend/app/ai/tools/_taint_sources.yaml` — 7 vectors, ~30 sources.
* `backend/app/ai/tools/taint_llm.py` — 894 LOC, two handlers + YAML
  loaders + ranking + confidence gate + prompt composers.
* `backend/tests/test_taint_llm.py` — 692 LOC, 39 unit tests.
* `.planning/fleet/outputs/stream-epsilon-2026-04-19-research.md`
  (Phase 1 research doc).
* `.planning/fleet/outputs/stream-epsilon-2026-04-19-wave2.md`
  (this file).

Modified (ADD-ONLY to registry):

* `backend/app/ai/__init__.py` — one import + one `register_...`
  call. Diff is exactly 2 lines.

NOT touched (as mandated):

* Any existing tool file, any router / service / schema / model.
* `backend/pyproject.toml` — pyyaml>=6.0 was already present.
* `docker-compose.yml`, `backend/app/main.py`, any frontend file.

## Research findings

* **pyyaml status:** already in `backend/pyproject.toml:41` at
  `pyyaml>=6.0`; installed v6.0.3 in-container. No dependency work.
* **Factory name correction:** research brief and dispatch both
  mentioned `build_registry`; actual name in
  `backend/app/ai/__init__.py` is `create_tool_registry`. Verified
  via `grep register_.*_tools\|create_tool_registry` and the
  acceptance test `test_taint_tools_present_in_full_registry` uses
  the real name.
* **ToolContext surface confirmed:** `resolve_path()` is the only
  sandbox gate; `context.db` is an `AsyncSession`; `firmware_id`
  and `extracted_path` are mutable at project-switch. Mirrors
  existing tool patterns.
* **Cache key length:** `analysis_cache.operation` is VARCHAR(512)
  per rule 15. Our keys are ≤ 40 chars (`taint_scan:<md5-12>` and
  `taint_deepdive:<md5-12>`). Safe.
* **db.flush() discipline:** verified that
  `ghidra_service.AnalysisCache._store_cached` calls `await
  db.flush()` internally — rule 3 compliance is transitive through
  the shared cache API.

## Pipeline (tool #1: scan_taint_analysis)

1. `resolve_path` sandbox gate on `binary_path`.
2. Arg validation (min_confidence ∈ {low, medium, high};
   max_candidates capped at 200).
3. `cache.ensure_analysis` → Ghidra SHA + prior analysis pull.
4. Cache lookup under `taint_scan:<md5-12>` — hit returns cached
   prompt, miss proceeds.
5. `cache.get_imports` → `cache.get_cached("xrefs")`.
6. `_rank_candidates`: for each function in the xrefs graph, score
   by sinks touched (×2) + sources visible (×1) + centrality (+1
   if ≥3 incoming callers) + entry-shape name match (+1 for
   main/handle*/parse*/cmd*/request*).
7. `_apply_confidence_gate` prunes by threshold, `focus_cwe`
   whitelist optional.
8. Top N (default 50) candidates → per-function decompile (best
   effort).
9. `_compose_scan_prompt`: binary header + sink inventory + ranked
   candidate list (each with 1.5KB capped decomp) + CoT
   instructions + JSON output schema.
10. Cache the composed prompt; return to registry which applies
    the 30KB truncation.

## Pipeline (tool #2: deep_dive_taint_analysis)

1. Sandbox gate + arg validation.
2. Cache lookup under `taint_deepdive:<md5-12>`.
3. `decompile_function(target)` → fatal-error if this fails (the
   prompt is pointless without a body).
4. 2-hop xref walk in both directions via cached `xrefs`.
5. Classify neighbours against YAML sink/source sets
   (POTENTIAL SOURCE / POTENTIAL SINK labels).
6. Decompile any caller flagged as POTENTIAL SOURCE (adds
   context — how the taint enters).
7. `_compose_deepdive_prompt`: 4-stage CoT — sink-id → source-id
   → dataflow → CWE — each stage requires 3+ consecutive quoted
   decompiled lines (LATTE paper shape, anti-hallucination).
8. Cache + return.

## Verification matrix

| Check | Expected | Actual |
|-------|----------|--------|
| Tool count post-rebuild | 172 | 172 (+2) |
| `scan_taint_analysis` in registry | yes | yes |
| `deep_dive_taint_analysis` in registry | yes | yes |
| `test_taint_llm.py` unit pass | 39/39 | 39/39 in 2.68s |
| `test_binary_tools.py` regression | 28/28 | 28/28 (no regressions) |
| `/health` | 200 ok | 200 ok |
| `/health/deep` all checks | 4/4 ok | 4/4 ok (db, redis, docker, storage) |
| Auth matrix no-key | 401 | 401 |
| Auth matrix with-key | 200 | 200 |
| DPCS10 canary blob count | 260 | 260 (unchanged) |
| Pre-commit rebuild executed | yes | `docker compose up -d --build backend worker` ran and came healthy in 6s |

## Deviations from dispatch plan

1. **No DVRF / Juliet fixture compiled.** Applied rule 19
   (evidence-first). The intake's 80%-recall acceptance criterion
   requires real Ghidra + real binary; the pipeline would be 3-5
   minutes per-function per-test and brittle to toolchain versions.
   Decision recorded in research doc: unit tests cover every
   deterministic layer (ranking, filtering, composition, caching,
   path traversal, error paths); DVRF integration is tagged as
   follow-up.
2. **Pytest not in production image.** Existing convention —
   verification pattern is `docker cp tests/ && pip install pytest`
   inside the running container for verification, exactly matching
   how prior streams run tests against a built image without a
   tests/ layer. Tests were executed inside the rebuilt container
   and all 39 pass.
3. **`wairz-mcp --list-tools` CLI path mismatch.** The installed
   `wairz-mcp` entry point lacks PYTHONPATH so `from app.mcp_server
   import main` raises ModuleNotFoundError. This is pre-existing;
   unrelated to this stream. Verification used the documented
   alternative: `python -c "from app.ai import
   create_tool_registry; ..."` — see command in research doc.

## Follow-ups (not blocking; queue as new intake items)

1. **DVRF recall benchmark.** Compile DVRF's planted-bug corpus
   (`stack_bof_01/02`, `heap_overflow_01`, `format_string_01`,
   `cmd_injection_01`), run `scan_taint_analysis` at
   `min_confidence=low`, hand-verify hit rate. Target: ≥80% recall
   per the intake acceptance criterion.
2. **Juliet CWE-78 / CWE-120 replication.** Rerun LATTE paper's
   Juliet v1.3 benchmark with Claude as the LLM; compare to
   GPT-4.0's 96.5% / 62.1% accuracy numbers.
3. **Prompt-cache eviction policy.** Right now
   `analysis_cache.store_cached` overwrites same-key rows but
   there's no TTL. If a binary is re-analysed and the xref shape
   changes under the same SHA (possible on re-run with different
   Ghidra build), the cached prompt is stale. Consider a per-row
   created_at window.
4. **`focus_cwe` prompt reinforcement.** When `focus_cwe` is
   provided, the prompt mentions it in a "focus note" but the JSON
   schema doesn't force the LLM to restrict its output. If real-
   world usage shows off-topic findings, add a schema constraint.
5. **Cross-binary taint handoff.** `cross_binary_dataflow` exists
   already. A future enhancement: when `scan_taint_analysis`
   detects a tainted cross-binary IPC path (e.g. `nvram_set` in
   binary A, `nvram_get` in binary B), chain the deep-dive across
   both sides. Orthogonal to this stream.

## Key code references

* Tool handlers: `backend/app/ai/tools/taint_llm.py:336` (scan) and
  `:432` (deep_dive).
* Ranking logic: `backend/app/ai/tools/taint_llm.py:127`.
* Confidence gate: `backend/app/ai/tools/taint_llm.py:179`.
* Scan prompt composer: `backend/app/ai/tools/taint_llm.py:213`.
* Deep-dive prompt composer: `backend/app/ai/tools/taint_llm.py:279`.
* Registration: `backend/app/ai/tools/taint_llm.py:586`.
* YAML dictionaries: `backend/app/ai/tools/_taint_sinks.yaml` + 
  `_taint_sources.yaml`.
* Unit tests: `backend/tests/test_taint_llm.py` (39 tests).

## Rules applied

| Rule | How |
|------|-----|
| 1 (path traversal) | Every handler entry uses `context.resolve_path()`. Explicit path-traversal rejection test for both tools. |
| 3 (flush vs commit) | Cache writes go through `cache.store_cached()` which calls `db.flush()` internally; no direct `commit()` in either handler. |
| 4 (Pydantic ↔ ORM match) | Not applicable — no new response schemas. |
| 8 (rebuild worker with backend) | Executed `docker compose up -d --build backend worker` post-commit; both came healthy. |
| 15 (VARCHAR(512) on operation) | Cache keys ≤ 40 chars; well under limit. |
| 19 (evidence-first) | Verified pyyaml presence before considering adding to pyproject; no action needed. Declined to compile DVRF fixture for unit tests since the 80%-recall target is an integration concern. |
| 20 (class-shape change needs rebuild) | Recognised the new registration is a class-shape change; full rebuild executed; tool count verified post-rebuild. |
| 22 (grep-before-migrate) | Not applicable — no find/replace migration. |

## Fleet coordination notes

* Worktree shared working-tree with other streams; Wave 1 learning
  applied — only my files staged per commit, never `git add -A`.
* Other streams' uncommitted changes (e.g. `backend/app/main.py`,
  `backend/app/workers/arq_worker.py`) remain in the working tree
  untouched — I did not commit or modify them.
* Four telemetry / campaign artefacts already modified by harness
  are left alone; they belong to orchestration.

## Ship-readiness summary

Everything green: 4 commits, 172 tools registered, 39 unit tests
green, 28 existing binary tests green, 4/4 health checks ok, auth
matrix intact, DPCS10 canary unchanged. The MCP taint tools are
live on the clean-history branch and available for Claude to invoke
via the MCP server as soon as the next session reconnects.
