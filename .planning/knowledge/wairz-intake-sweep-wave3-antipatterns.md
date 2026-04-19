# Anti-patterns: Wairz Intake Sweep — Wave 3 (session 198243b8)

> Extracted: 2026-04-19
> Campaign: `.planning/campaigns/wairz-intake-sweep-2026-04-19.md`
> Wave: 3-stream parallel dispatch (α infra, β frontend store, γ Phase-7 maintenance) — 18 commits, 5+ intakes closed, 4 cross-stream sweep incidents recovered

## Failed patterns

### 1. `git checkout -b feat/{branch}` ALONE is not sufficient under shared on-disk checkout (confirmed 4× this wave)

- **What was done:** Wave 3 dispatch prompts instructed every sub-agent to run `git checkout -b feat/stream-{name}-2026-04-19` BEFORE any file write — the CLAUDE.md Rule #23 mitigation as originally written. Each stream created its branch on start.
- **Failure mode (α, 2 incidents):** Mid-edit, the main checkout's HEAD flipped between branches (because γ was also running `git checkout` on the shared tree). α's `git commit` landed on γ's branch twice before α detected the pattern and ran `git worktree add .worktrees/stream-alpha`.
- **Failure mode (β, 2 incidents):** β wrote changes to three stores in memory; `git commit` errored showing HEAD had become α's branch. Follow-up `git checkout feat/stream-beta-2026-04-19` found β's in-memory edits reverted to baseline (zero `currentProjectId` references). Edits were nullified until β ran `git worktree add` and replayed.
- **Failure mode (γ, 2 incidents):** γ's mcp_server.py fix was committed to α's branch as `e68d14d`. γ recovered via `git cherry-pick` onto its branch as `17ff896`. γ's first handoff commit accidentally picked up α's `.env.example` + `docker-compose.yml` changes (26 lines + 10 lines); γ recovered via `git reset --hard c954039` + reflog-replay of the intended 5 commits.
- **Evidence:** All 3 stream handoffs (`.planning/fleet/outputs/stream-{alpha,beta,gamma}-2026-04-19-wave3.md`) independently document this. `git log --name-only` on cross-attributed commits shows files from the WRONG stream's scope.
- **Why the mitigation was incomplete:** `git checkout -b` creates the branch but DOES NOT isolate the working tree — it remains shared. When two concurrent agents run `git checkout` in the same tree within the same second, the second one's switch silently reverts the first's in-flight edits. This is git-correct behavior (all three branches point at the same working tree); it's ORCHESTRATION-incorrect because sub-agents expect isolation.
- **How to avoid:**
  - **Use `git worktree add .worktrees/{stream-name} -b feat/{branch}` + operate INSIDE that path.** This is the durable fix. β did it proactively and had 0 sweeps across 4 commits.
  - Symlink `frontend/node_modules` from the main checkout into the worktree to avoid a 2GB npm-install.
  - Add `.worktrees/` to `.gitignore` (done post-merge this session).
  - The Fleet harness's `isolation: "worktree"` parameter + `worktreePath: "ok"` sentinel is STILL a no-op at the working-tree level. Harness should be fixed to actually issue `git worktree add` per stream. Until then, sub-agent prompts MUST include the `worktree add` command.
  - **Recovery when it happens anyway:** `git cherry-pick` a commit from the wrong branch; `git reset --hard {baseline} && git reflog` to replay the right commits. This session's 4 recovery attempts all succeeded with zero content loss — but each cost ~10-15 min.

### 2. Intake specifications can be actively WRONG, not just drifted (3 instances this wave)

- **What was done:** Each stream read its intake's "Problem" + "Approach" + "Files" + "Acceptance Criteria" sections and initially planned to implement as-written.
- **Failure mode (β S1):** Intake's `loadRootDirectory: async (projectId: string, firmwareId: string) => ...` prescribed a 2-arg signature. Actual code had 1-arg `loadRootDirectory(firmwareId)` + used `useProjectStore.getState().selectedFirmwareId` internally. Implementing the intake verbatim would have required widening 12+ call sites.
- **Failure mode (β S3 modes):** Intake's `DeviceMode = 'adb' | 'brom' | 'edl' | 'fastboot' | 'unknown'` listed 5 modes. Grep of the actual bridge code: only `adb`, `brom`, `preloader`. Four of the intake's modes were NEVER emitted by any code path. Implementing verbatim would have added 4 dead values to the type system.
- **Failure mode (β S3 scope):** Intake prescribed frontend-only typing ("remove `as any` casts, add DeviceInfo/DeviceDetail types"). Backend Pydantic `DeviceInfo` had `extra='ignore'` silently stripping the 4 BROM fields before they ever reached the frontend. Frontend typing alone would have left the feature runtime-broken (`dev.mode` always `undefined`). Real fix was end-to-end: backend schema + service + router + frontend.
- **Evidence:** β's research doc (`.planning/fleet/outputs/stream-beta-2026-04-19-research.md`) has the SQL/grep probes that caught each. Three saves in one stream.
- **How to avoid:** **Rule #19 is not optional — it is the FIRST PHASE of every stream.** Intakes are hypotheses written at a point in time; the source of truth is the current code + DB. Grep the actual signatures/values/fields/schemas BEFORE codifying any intake-prescribed shape. For type unions, grep the full set of values emitted at the data source (bridge script, DB enum, API response schema). For schema changes, run a pydantic round-trip in-container (`docker exec -i <container> python -c "<NEW_SCHEMA>(**test_data).model_dump()"`) to see whether the field survives — before shipping frontend type changes.

### 3. Pydantic `extra='ignore'` silently strips fields on API boundaries (β's root-cause of the BROM bug)

- **What was done:** `backend/app/schemas/device.py` inherited Pydantic v2's default `extra='ignore'` on `DeviceInfo`. Four BROM-specific fields (`mode`, `available`, `error`, `chipset`) were emitted by the device bridge script and plumbed through the service partially, but `DeviceInfo(**d)` at `routers/device.py:51` silently dropped them.
- **Failure mode:** Frontend `DeviceAcquisitionPage.tsx` had 5 `as any` casts to read `dev.mode`, `dev.available`, `dev.error`, `deviceDetail.chipset`. At runtime these evaluated to `undefined` (not a TypeScript-compile-time error; the `as any` bypassed checking). The BROM-specific UI branches were DEAD — never triggered because the data wasn't there. The feature silently regressed without any test or user signal.
- **Evidence:** β's in-container pydantic round-trip showed `DeviceInfo(**{'mode':'brom', ...}).model_dump()` returned only the 5 declared fields. Confirmed against wairz-backend-1 live.
- **How to avoid:**
  - **For DTOs on API boundaries**, prefer explicit field declarations + `extra='forbid'` (drift surfaces as loud `ValidationError`, not silent strip).
  - **For ingestion DTOs** that deliberately accept unknown keys (e.g., webhook receivers), use `extra='allow'` with an explicit comment explaining why.
  - `extra='ignore'` should be the rarest of the three — use only when the field set is stable AND extra fields are legitimately out-of-scope.
  - **Test:** for every new DTO crossing backend↔frontend, run a pydantic round-trip against a full payload (not just declared fields) and confirm nothing drops unexpectedly.

### 4. `protect-files` hook feedback loop with `/learn` skill

- **What was done:** γ attempted to adopt 4 candidate quality rules into `.claude/harness.json` (the standard `/learn` output path).
- **Failure mode:** `protectedFiles: [".claude/harness.json"]` causes the hook to block writes; agents cannot append rules. The 4 candidate rules documented in session-435cb5c2's antipatterns remain unadopted across multiple sessions.
- **Evidence:** γ's handoff notes the DEFERRED verdict; campaign Continuation State names this as the blocker; `.planning/proposals/citadel-protect-files-learn-exception.md` has been on the queue since session 435cb5c2.
- **How to avoid:** Resolve the proposal. Two options:
  - **(a)** Allow `/learn` skill's writes to `.claude/harness.json` via an explicit hook exception (requires harness wiring to pass skill-name context to the hook).
  - **(b)** Move quality rules out of `harness.json` into a separate file (e.g., `.claude/quality-rules.json`) that is NOT protected, let `/learn` write there, have the harness load both paths. Simpler, ~30 min work.
  - Until resolved, `/learn` cannot append rules even on legitimate high-confidence findings. This is a systemic friction, not a Wave-3-specific issue — but it recurred again this session.

### 5. Stale `harness.json` `typecheck.command` — known bug, cannot self-heal under protect-files

- **What was done:** `.claude/harness.json:6` holds `"command": "npx tsc --noEmit"`. CLAUDE.md Rule #24 (ratified two sessions ago) says the correct command is `npx tsc -b --force`; the `--noEmit` form exits 0 silently under wairz's tsconfig-with-references shape.
- **Failure mode:** Any harness feature that invokes the `typecheck.command` (file-write hook, skill-level verification) runs the broken command. Actual enforcement is zero. Agents who trust the hook output will see "0 errors" on genuinely broken code.
- **Evidence:** `head -10 .claude/harness.json` shows the stale command; CLAUDE.md Rule #24 documents the expected replacement; Wave 3 γ's handoff notes the block.
- **How to avoid:** Same fix as anti-pattern #4 — unblock `protect-files` for harness.json edits. Also: any stream that runs `--force` canary (Rule #17 canary + tsc -b --force, β did this) should be explicit that the harness's own typecheck.command is stale and use the direct `npx tsc -b --force` invocation. Do not trust `harness.typecheck.command` until the bug is fixed.

### 6. Intake YAML status-word capitalisation drift

- **What was done:** `.planning/intake/apk-scan-deep-linking.md` body said "**Status:** Completed" (with capital C) while convention elsewhere is `status: completed` (lowercase) in YAML front-matter. γ also found 5 security-* intakes where the body was done but the YAML header was stale.
- **Failure mode:** `grep -l 'status: completed' .planning/intake/*.md` (case-sensitive) misses capital-C entries; close-out queries need `grep -li` to catch both cases. Semantic searches (`status: Completed` vs `status: completed`) treat identical meaning as different strings.
- **Evidence:** γ's Sub-item 1 normalisation commit (`e1f94c3`) included the case fix; sub-item 2 bumped 5 other intake headers.
- **How to avoid:**
  - Enforce lowercase in the intake template (`.planning/intake/_TEMPLATE.md`).
  - Add a simple harness rule on `.planning/intake/**/*.md`: pattern `^(Status|status):\s+(Completed|Pending|Partial|Draft|Active)\s*$` (capitalised-value alarm) → message: "Intake YAML status should be lowercase: `completed`, `pending`, `partial`, `draft`, `active`."
  - Status-bump should happen in the same commit that ships the intake's work, not wait for a maintenance-sweep stream months later.

## Crosscutting lessons

- **Rule #23 damage is ~50% under per-branch-only discipline; ~0% under worktree-add discipline.** Wave 3 observed 4 sweep incidents across 14 commits (a 29% incident rate if we count each sweep as one). β had 0 sweeps in 4 commits *after* creating a worktree. α and γ had 2 each in ~10 commits *before* creating worktrees. The data is thin but directionally consistent with session 435cb5c2's 50% hit rate under shared-checkout + per-branch-only.

- **Rule #19 paid for itself 4× this wave.** β had 3 saves in one stream. α and γ each had at least one. The total saved work is hard to measure but plausibly 1-2 hours across the wave (avoided dead-code ships, avoided multi-file refactors that were in the wrong direction).

- **Rule #25 makes Rule #23 recovery tractable.** Per-sub-task commits meant that when γ had to cherry-pick one sub-item's content OR reset+replay, the surface was small. A bundled "feat(gamma): everything" commit would have forced recovery of 5 intermixed sub-items in one go, vastly harder.

- **The `docker cp` + in-container validation pattern (Rule #20 applied)** is specifically well-suited to the parallel-streams model: it lets a stream validate its backend changes against the live stack without disturbing peer streams. Orchestrator still does the Rule #8 rebuild at the end. This combination was clean across all Wave 3 streams that touched backend code.

- **Harness-level systemic blockers (protect-files/harness.json, stale typecheck.command)** are recurring costs. They don't belong in any one campaign's anti-patterns — they belong in harness maintenance. The cost of NOT fixing them is that every future `/learn` leaves high-confidence rules unadopted.

## Candidate quality rules extracted

These are regex-able patterns with concrete evidence from Wave 3. Adoption is BLOCKED on protect-files for now; candidate forms recorded here for when the gate opens:

### auto-wave3-pydantic-extra-ignore-on-api-schemas (HIGH severity, MEDIUM recurrence)

```json
{
  "name": "auto-wave3-pydantic-extra-ignore-on-api-schemas",
  "pattern": "extra\\s*=\\s*['\"]ignore['\"]",
  "filePattern": "backend/app/schemas/*.py",
  "message": "Learned from wave3 β: Pydantic `extra='ignore'` on API-boundary schemas silently strips fields sent by the service layer — β found DeviceInfo dropping 4 BROM fields, surfacing as `(dev as any).mode === undefined` at runtime with zero compile-time signal. Prefer `extra='forbid'` (loud drift) or explicit field declarations. Use `extra='allow'` only for ingestion DTOs with a documented reason."
}
```

### auto-wave3-tsc-noEmit-is-broken-here (HIGH confidence, already Rule #24)

```json
{
  "name": "auto-wave3-frontend-tsc-no-noEmit",
  "pattern": "tsc\\s+--noEmit",
  "filePattern": "{.claude/harness.json,**/package.json,.github/workflows/**}",
  "message": "Learned from wave-1+2+3: frontend tsconfig uses `files: []` + project references; `tsc --noEmit` exits 0 silently without checking. Use `npx tsc -b --force` (Rule #24). Rule-17 canary mandatory: write a bad .ts, run the command, confirm it fails before trusting any 'green' output."
}
```

### auto-wave3-intake-status-lowercase (LOW recurrence, adopt optional)

```json
{
  "name": "auto-wave3-intake-yaml-status-lowercase",
  "pattern": "^status:\\s+(Completed|Pending|Partial|Draft|Active)\\s*$",
  "filePattern": ".planning/intake/**/*.md",
  "message": "Learned from wave3 γ: intake YAML `status:` values should be lowercase (`completed`, `pending`, `partial`, `draft`, `active`) for close-out query coherence. Capitalised values work but break case-sensitive greps."
}
```

Note: none of these three are being appended to harness.json this session — `protect-files` blocks. When the proposal lands, adopt as a batch.
