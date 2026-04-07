# Anti-patterns: Session 14 — Fleet Wave (Binary Diff + Frontend Gaps + Intel HEX)

> Extracted: 2026-04-07
> Campaign: .planning/fleet/session-binary-diff-frontend-gaps.md

## Failed Patterns

### 1. Trusting worktree branch preservation
- **What was done:** Spawned 3 agents with `isolation: "worktree"`, expected changes on named branches after completion.
- **Failure mode:** All agents returned `worktreeBranch: undefined`. Changes were in the working directory, not on branches. Had to re-verify all work existed.
- **Evidence:** `git branch` showed no new branches; second agent round found work "already done".
- **How to avoid:** After fleet with worktrees, immediately check `git status` for uncommitted changes. Don't assume branches were created. Consider running without worktree isolation when scopes are guaranteed non-overlapping.

### 2. Docker build cache staleness with COPY layers
- **What was done:** Ran `docker compose build backend` after modifying Python source files.
- **Failure mode:** The Docker COPY layer used a cached version even though source files on disk had changed. Three consecutive builds all produced containers with old code.
- **Evidence:** `grep "Inject detected RTOS" /app/app/routers/sbom.py` returned 0 inside container despite local file having the code.
- **How to avoid:** On RPi/ARM, Docker BuildKit cache can be overly aggressive. Use `docker cp` for quick iteration during development. For production, use `docker compose up -d --build` or `--no-cache`.

### 3. ScrollArea requires bounded height parent
- **What was done:** Used shadcn `<ScrollArea className="flex-1">` inside a flex column with unbounded height.
- **Failure mode:** ScrollArea rendered all content at full height with no scrollbar. The tool list showed all 81 tools without scrolling.
- **Evidence:** User reported "not scrollable" twice. Fixed by replacing with `overflow-y-auto` div inside an explicit `calc(100vh - 10rem)` container.
- **How to avoid:** Never use ScrollArea in a flex-1 context without an explicit height constraint on an ancestor. Use `overflow-y-auto` with a `style={{ height: 'calc(100vh - Xrem)' }}` parent instead.

### 4. Agent-generated code referencing non-existent type fields
- **What was done:** CVE triage agent generated VulnerabilityRow.tsx that accessed `v.fix_version`.
- **Failure mode:** `fix_version` doesn't exist on the `SbomVulnerability` TypeScript interface. TypeScript build failed with "Type 'unknown' is not assignable to type 'ReactNode'".
- **Evidence:** `npm run build` error on VulnerabilityRow.tsx line 247.
- **How to avoid:** When giving agents type schemas, include the EXACT interface definition from types/index.ts, not a summarized version. Agents hallucinate fields that sound reasonable but don't exist.

### 5. Spawning background Docker builds that conflict
- **What was done:** Started multiple `docker compose build` commands (foreground + background) simultaneously.
- **Failure mode:** Builds competed for the Docker daemon, one hung and had to be killed with `pkill`. Exit code 144 (SIGTERM).
- **Evidence:** Two background tasks failed with exit code 144 after `pkill -f "docker compose build"`.
- **How to avoid:** Never run parallel Docker builds. Cancel previous builds before starting new ones.
