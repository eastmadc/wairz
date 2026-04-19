# Anti-patterns: Wairz Intake Sweep — Wave 1 + Wave 2 (session 435cb5c2)

> Extracted: 2026-04-19
> Campaign: `.planning/campaigns/wairz-intake-sweep-2026-04-19.md`
> Waves: Cross-phase parallel dispatch (6 streams, 28 commits, 6 intakes closed)

## Failed patterns

### 1. `isolation: "worktree"` with `worktreePath: "ok"` sentinel is NOT working-tree isolation (confirmed 3× this session)

- **What was done:** Six Agent spawns across two waves used `isolation: "worktree"`. Each returned `<worktreePath>ok</worktreePath>` at completion. Streams committed to parent branch `clean-history`, as documented in Phase 1 anti-pattern #3.
- **Failure mode (Wave 1, Alpha ↔ Gamma):** Stream Alpha's D3 commit `f614c43` included two Stream Gamma files (`FindingsList.tsx` + `FindingsPage.tsx`) that Gamma had modified but not yet committed. Alpha's `git add` captured them because the on-disk working tree was shared.
- **Failure mode (Wave 2, Delta ↔ Zeta):** Stream Delta's arq-worker commit `e8548fd` swept in 8 unrelated Stream Zeta frontend files (API_BASE helper + drift migration). Same mechanism.
- **Failure mode (Wave 2, Epsilon ↔ Zeta):** Zeta's initial report attributed its commit-1 content to "Stream Epsilon's e8548fd" — actually Delta's SHA, but the cross-stream attribution confusion itself is a symptom of shared working-tree state.
- **Evidence:** `git log --name-only` on each cross-attributed commit shows files from different streams' scopes in one commit. Content was always correct (no lost work); attribution and commit boundaries were wrong.
- **Why strict `git add <paths>` alone didn't prevent it:** Wave 2 prompts explicitly forbade `git add -A` and required `git status` before every `git add`. Still happened. When two agents modify unrelated files in rapid sequence, the agent running `git add` sees the OTHER stream's unstaged files on disk, and even specific-path adds can race when a hook auto-commits on file-write or when `git add` is invoked on a directory that contains the other stream's in-flight files.
- **How to avoid:**
  - **Option A (preferred):** Fleet harness must create TRUE separate worktrees — each agent operates on a different on-disk path (`git worktree add ../wairz-stream-{name}`). The `worktreePath: "ok"` sentinel hides whether this happened. Confirm via `git worktree list` that each stream has a unique path.
  - **Option B:** Each agent runs `git checkout -b feat/stream-{name}-{date}` BEFORE any file writes. Orchestrator merges branches sequentially after all streams complete. Rollback becomes `git branch -D feat/stream-{name}-{date}` (trivial).
  - **Option C (current session — acceptable for truly disjoint-file waves):** accept the shared working tree, design streams with strict file-disjointness, tolerate cross-stream commit attribution as noise. Content correctness is preserved; bisect becomes harder.

### 2. `tsc --noEmit` exits 0 silently when tsconfig uses project references (Rule 17 class, caught by canary)

- **What was done:** Wave 1 Stream Gamma ran `(cd frontend && npx tsc --noEmit)` after every 1-2 file edits per Rule 22. Every run exited 0, which read as "no type errors."
- **Failure mode:** `frontend/tsconfig.json` has `"files": []` + `"references": [...]`. In this mode `tsc --noEmit` has nothing to check and exits 0 without type-checking ANY file. The "green" was silent failure, indistinguishable from success at the exit-code level.
- **Evidence:** Rule-17 canary — `echo 'const x: number = "string"; export default x;' > __canary.ts && tsc --noEmit` — exited 0 with no error on the deliberately-broken canary. Gamma then switched to `tsc -b --force`, which invokes the referenced projects and catches errors.
- **How to avoid:** In wairz specifically, **ALWAYS use `npx tsc -b --force` for frontend typecheck.** `--noEmit` is broken under the current tsconfig shape. The Rule-17 canary remains the universal tool — run it once per session before trusting ANY "green" typecheck output. Wave 2 Stream Zeta was explicitly instructed on this and passed cleanly on first try.

### 3. Intake scope descriptions drift from live state (Rule 19 catches stale specs; 4 instances this session)

- **What was done:** Each Wave stream ran its intake's acceptance criteria as-written.
- **Failure mode:** Four intake items described conditions no longer present in the live system:
  - **Alpha/D1:** intake said "findings created before source was added have NULL" — live `SELECT COUNT(*) FROM findings WHERE source IS NULL` returned 0. Backfill shipped as idempotent no-op.
  - **Alpha/D2:** intake said FirmwareDetailResponse needs 2 new fields — `device_metadata` already present. Work reduced to 1 field.
  - **Zeta/A2:** intake said VITE_API_KEY read once at module load, requires fix — existing `getApiKey()` already re-reads per call. No work needed beyond preserving the pattern.
  - **Zeta/A3:** intake said SecurityScanPage.tsx:129 hard-codes `/api/v1/...` — already patched to use a local `API_BASE`. Work was centralising the helper, not bug-fixing.
- **How to avoid:** Make Rule 19 the FIRST phase of every stream prompt, not an afterthought. A one-paragraph research section that explicitly asks "verify the intake's premise against live state before writing code" — with SQL counts, `grep`, and `curl` probes — surfaces stale specs in under 2 minutes. Wave 2 prompts did this correctly and caught 3 of the 4 stale conditions.

### 4. Existing ToolRegistry API probe used wrong signature twice (two agents independently)

- **What was done:** Stream Epsilon's dispatch prompt suggested `from app.ai import build_registry` and `r.list_tools()`. Actual factory is `create_tool_registry()` (takes 0 args) and registry exposes `.get_anthropic_tools()`, not `.list_tools()`.
- **Failure mode:** Epsilon noticed the factory-name issue during research and adjusted. I (orchestrator) used the same wrong shape in the final verification and got two sequential `AttributeError`/`TypeError`, wasting 2 probes.
- **How to avoid:** When dispatching Agents, read the actual factory signature via `grep -n "def create_tool_registry\|def build_registry" backend/app/ai/__init__.py` ONCE and paste the real signature into the prompt. Don't guess from the intake file (which often lags the code). Post-dispatch, run one quick smoke `python -c "from app.ai import create_tool_registry; print(dir(create_tool_registry()))"` to surface the real API before relying on it in verification.

### 5. Pre-existing `wairz-mcp --list-tools` CLI is broken (surfaced by Epsilon)

- **What was done:** Epsilon's verification battery included `wairz-mcp --list-tools` as a sanity check for registered tool count.
- **Failure mode:** The CLI raises `ModuleNotFoundError: from app.mcp_server import main`. Pre-existing; unrelated to Epsilon's work. Epsilon fell back to `python -c "from app.ai import create_tool_registry"` which worked.
- **How to avoid:** Queue a separate tiny intake to fix the CLI entry point (likely a `pyproject.toml` entry-point mismatch after a refactor). Meanwhile, verification batteries should use the Python-import path directly rather than the CLI wrapper.

## Crosscutting lessons

- **Fleet-level isolation is the #1 durability issue for parallel waves.** Three cross-stream file-sweep incidents in six streams (50% hit rate) with clean strict-add discipline. Any future multi-stream wave must either rely on true worktree isolation or explicit per-stream branches. The "it worked in Phase 1" pattern held only because Phase 1's four streams were aggressively disjoint (middleware/services/workers/compose); Wave 2's streams had more subtle surface contact (both Delta and Zeta touched `frontend/src/` indirectly via docker-compose healthcheck and frontend deps) and exposed the flaw.

- **Rule 19 (evidence-first) now pays for itself 4× per wave.** In this session, Rule 19 application saved 2-3 diffs across Alpha + Zeta + Epsilon. The pattern is: intake specs rot between filing and execution; live state is always more authoritative than the markdown. A 30-second SQL/grep probe at the top of every stream is a cheap, reliable spec-accuracy filter.

- **Rule 17 (canary silent CLI) is not optional for frontend typecheck in this repo.** The tsconfig references shape makes `--noEmit` a silent-pass. Add `tsc -b --force` + a canary check to every frontend stream prompt.

- **Rebuild-worker-with-backend (Rule 8) was applied correctly 6/6 times this session.** Alpha, Delta, Epsilon all ran `docker compose up -d --build backend worker` after their changes; Beta/Gamma/Zeta used restart-only (correct — no class-shape changes in worker-imported code). No regressions. Rule 8 has reached reliable-recall territory.

- **Anti-pattern #4 from Phase 1 (rate-limit counter state) was avoided in all 6 streams** — auth matrix ran LAST in every stream's verification battery, as prompted. No rate-limit starvation.

- **New pattern candidate (not yet a rule):** "When an intake bundles N independent sub-tasks (Alpha had 7: D1/D2/D3/I1/I2/I3/I4), commit each sub-task separately. The per-commit verification gate catches early failures before downstream alembic revisions pile on." — Alpha shipped 8 commits; Delta shipped 7; each slice was individually reversible. Beta/Gamma/Zeta with 2-5 commits each showed the same pattern. Candidate graduation to a Learned Rule in a future session.
