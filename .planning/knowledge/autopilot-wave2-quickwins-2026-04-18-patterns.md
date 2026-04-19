# Patterns: Autopilot Wave 2 — Deep-Dive Continue (2026-04-18)

> Extracted: 2026-04-18
> Campaign: not a registered campaign — the second autopilot run
>   ("/autopilot deep dive continue; keep going as long as you can")
>   that followed the first Option-A wrap in session 59045370
> Prior /learns this session:
>   1. autopilot-seed-option-a-2026-04-18-patterns.md
>   2. unpack-escape-symlink-fix-2026-04-18-patterns.md
>   3. deployment-loop-closure-2026-04-18-patterns.md
>   4. mex-adoption-complementarity-2026-04-18-patterns.md
> Commits covered: ~13 (7610332 → a51208d)
> Postmortem: none

## Scope delivered

13 commits spanning sbom_service hygiene, infra/CI hygiene, five
frontend edits (Q12-Q16), VulHunt EventSource hardening, vulhunt
digest pin + device-type tightening, cwe_checker serialisation +
AST-based async-subprocess linter, useFirmwareList hook (10 pages
migrated), /health/deep endpoint, intake status updates, handoff
doc extension.  Rebuild + recreate of backend+worker twice during
the run (rule 8).

## Successful Patterns

### 1. Bundle unrelated small commits by *theme*, not by random grouping

- **Description:** 17 items from the quick-wins bundle shipped in
  **5 commits**, each grouping items that shared an editing
  signature: "sbom_service hygiene" (Q1+Q2+Q3), "infra/CI hygiene"
  (Q5+Q7+Q10+Q11), "VulHunt EventSource fixes" (Q14+Q15), "env
  surface tightening" (Q6+Q9), "vulhunt digest + device types"
  (Q8+Q17).  Each commit stays reviewable at one diff — ~20-80
  lines — because the changes target files in the same codebase
  neighbourhood.  Items that DIDN'T share a neighbourhood (Q12, Q13,
  Q16) got their own commits.
- **Evidence:** commits 7610332, 5b6e360, e05e9a7, b9f438f, 46229f0
  all touch 1-3 files in a narrow domain.  commits 3c15c80, f8db46c,
  46b408a are single-item commits that would have been awkward to
  bundle.
- **Applies when:** A quick-wins-style intake with many small
  independent items.  The axis for bundling is "what review mental
  model does the reviewer need?"  Same file or same subsystem →
  bundle.  Different subsystems → split.  Never bundle purely by
  "small" size — a one-line sbom fix plus a one-line frontend fix
  requires two review contexts.

### 2. Intake acceptance criteria double as verification scripts

- **Description:** The `frontend-firmware-hook-dedup.md` intake
  listed specific acceptance commands:
    grep -rn 'listFirmware(' frontend/src/pages/      → 0 hits
    grep -rn 'useFirmwareList' frontend/src/pages/    → 9 hits
  Ran both after migration.  First returned 0 (confirmation).
  Second returned 10 (not 9 — HardwareFirmwarePage also had the
  pattern, missed by intake author).  Acceptance grep caught both
  the win AND the under-counted scope in one second.
- **Evidence:** commit 97c7c7a note explicitly calls out "10 pages
  (intake said 9; HardwareFirmwarePage also had the duplicate-fetch
  pattern)."  Caught because the acceptance criteria were
  executable, not prose.
- **Applies when:** Any intake with a "find/replace all" migration.
  Write the acceptance as a grep or count BEFORE starting so the
  intake author's scope estimate is verified against reality at
  completion time.  A grep that returns more hits than expected is
  a signal the migration needs to cover more ground than the intake
  anticipated.

### 3. AST-based lint beats grep for "X inside Y" patterns

- **Description:** The async-subprocess linter guards CLAUDE.md
  rule #5.  Intake specified a grep:
    grep -B5 'subprocess\.run|Popen|...' | grep -B5 'async def'
  That grep false-positives when an async def 5 lines above
  actually contains a nested sync helper that uses subprocess.
  Replaced with an AST visitor that walks AsyncFunctionDef bodies
  with explicit nested-def pruning.  100 LOC of Python; zero CI
  false positives.
- **Evidence:** backend/scripts/lint_async_subprocess.py uses
  `ast.walk(func_node)` with a two-pass "collect nested-def line
  ranges, then skip subprocess calls inside those ranges" guard.
  Canaried with a known-bad file (exits 1 as expected); canaried
  with the real codebase (exits 0 — no existing violations).
- **Applies when:** Enforcing "X inside Y" code-shape rules at
  CI time.  If X and Y are both AST node types (function, class,
  async def, try/except), the AST implementation is ~3× the effort
  of grep but ~0× the false-positive cost.  For simpler regex-
  shaped rules (pattern in filename glob), stick with ruff or
  harness.json regex.

### 4. Zustand useShallow for multi-field destructures avoids selector-per-field noise

- **Description:** `SbomPage.tsx` had a 17-field destructure from
  `useVulnerabilityStore()`.  Individual selectors × 17 would be
  verbose and error-prone.  Wrapped the destructure with
  `useShallow((s) => ({ ... }))` from `zustand/react/shallow`.
  Same destructure idiom; re-render scoped to the specific fields
  extracted; type inference unchanged.
- **Evidence:** commit 46b408a, SbomPage.tsx line 715+.  Two
  sites: outer page got 3 individual selectors (vulnerabilities,
  resolutionFilter, sevFilter); inner VulnTable got useShallow.
- **Applies when:** >3 fields from the same store are needed by
  one component.  Below 3, individual selectors are clearer and
  the overhead is negligible.  Above 3, useShallow is the
  idiomatic escape hatch.  Never regress to the bare
  `useStore()` — that's what this commit was fixing.

### 5. Pre-migration grep-all-sites is the size check that matters

- **Description:** Before touching any page for the
  useFirmwareList migration, ran a full
  `grep 'listFirmware\|setFirmwareList' frontend/src/pages`.
  Got 10 pages, 21 total lines (some pages have 6+ call sites —
  ProjectDetailPage).  Knowing the full shape up front informed
  the decision to invalidate-on-mutate (projectStore actions)
  vs. force-reload-at-callsite (would need 6 edits in one file).
- **Evidence:** The projectStore `uploadFirmware` and
  `removeProject` actions now invalidate the list centrally; 5
  callsite-level edits in ProjectDetailPage collapsed to
  `invalidateFirmwareList()`.
- **Applies when:** Any codebase-wide find/replace migration.
  The "grep first, design second" ordering prevents mid-migration
  design changes — if I'd started edit-first at the first page,
  the sixth page's 6 call sites would have forced a rewrite of
  the first five.

## Avoided Anti-patterns

### 1. `docker cp` on pydantic Settings changes (hit wall, lesson learned)

- **What happened:** After adding
  `max_standalone_binary_mb` to `config.py`, I docker cp'd both
  config.py and unpack.py into the running backend + worker, then
  triggered a firmware unpack.  Worker crashed with
    AttributeError: 'Settings' object has no attribute 'max_standalone_binary_mb'
- **Failure mode:** The running worker had already imported
  `Settings` from the OLD config.py and held the class reference
  via `@lru_cache` on `get_settings()`.  docker cp replaced the
  file on disk but the in-memory Settings class retained the old
  shape.  Rule 20 ("docker cp is validation speed, not durable
  state") was right — I just didn't realise this specific class
  of change requires process restart, not just fresh imports.
- **Evidence:** commit ad29b23 history; the abortive first unpack
  failed with the AttributeError before the rebuild-and-retry
  cycle.
- **How to avoid:** When a change touches **pydantic Settings**,
  **dataclasses**, **SQLAlchemy models**, or any class whose
  instances are cached in `@lru_cache` / module-level singletons,
  plan for a full backend+worker rebuild + recreate — docker cp
  alone won't apply the schema change.  Mechanical rule: if the
  diff adds a field to a class, assume restart needed.

### 2. Dropping env_file without auditing the ENV substitutions

- **What almost happened:** Q6 says "Remove env_file: .env from
  frontend".  Naive read: delete the line.  Would have silently
  reverted the nginx `client_max_body_size` default from whatever
  the user had in .env to the Dockerfile's `ENV
  MAX_UPLOAD_SIZE_MB=2048`.  A user who'd set 8192 in .env for
  large firmware would quietly lose the override on next container
  recreate.
- **Failure mode:** Silent config regression.  No error, just a
  different limit applied.
- **Evidence:** Read nginx.conf.template and Dockerfile BEFORE
  editing compose.  Found the interpolation; replaced env_file
  with a targeted `environment: { MAX_UPLOAD_SIZE_MB:
  "${MAX_UPLOAD_SIZE_MB:-2048}" }` block so user-set values in
  .env still propagate.
- **How to avoid:** When tightening an env surface (dropping env
  file vs specifying individual vars), audit the consumer's
  config templates and Dockerfile ENV defaults.  The safe rewrite
  preserves every interpolation path that was actually used.

### 3. Single-commit multi-page migration without mid-flight tsc

- **What almost happened:** The 10-page useFirmwareList migration
  could have been one sweeping edit.  Decided to run tsc after
  every 1-2 pages.  Caught 3 classes of small error:
    - `FirmwareDetail` unused import (type-check flags, fixed)
    - Optional-chain after narrow-to-null (.close() on never)
    - State hook deletion without removing the reference below
- **Failure mode:** A single-commit approach would have caught
  these all at once in a 10-error tsc output, needing bisection.
  Incremental caught them one at a time with instant localisation.
- **Evidence:** commits show tsc exit=0 after every page edit in
  the transcript; no bisection needed; clean tree at final commit.
- **How to avoid:** For multi-file migrations, typecheck every
  1-2 files regardless of perceived safety.  The cost is 3-5
  seconds of tsc per run.  The payback is no "which of these 10
  pages introduced the error" archaeology.

## Key Decisions

| Decision | Rationale | Outcome |
|---|---|---|
| Bundle quick-wins by theme, not item | 17 items in ~8 commits is reviewable; 17 separate commits is noise; one commit of 17 items is unreviewable | 5 themed bundles + 3 standalone commits |
| Option A (serial) for cwe_checker batch, not Option B (per-task session) | Semaphore was already max=2 — parallelism loss is <50%; correctness is the real fix | Commit b9f625a; max_concurrent kept in signature for API-compat but unused |
| AST linter in `backend/scripts/`, not a Ruff plugin | 100 LOC standalone vs. a Ruff plugin build; plugin would be reusable but none of the other repos we control need it | Linter in scripts/; CI step added in lint.yml; canaried |
| useFirmwareList invalidation at store-action level, not at call-site level | ProjectDetailPage had 6 listFirmware call sites — all post-mutation refreshes; centralising at `uploadFirmware` / `removeProject` cuts 5 edits to 1 | Store actions invalidate; hook re-loads on dep change (listProjectId) |
| `MAX_STANDALONE_BINARY_MB = 512` default | Covers PowerPack (268 MB) and most medical / automotive / IoT embedded firmware; half of the `max_upload_size_mb` default so disk pressure stays bounded | Commit ad29b23; env-overridable for operators with larger or smaller appetite |
| Rebuild backend+worker twice in one session | Wave-1 changes (A.1 bind, secrets, VARCHAR migration) + wave-2 changes (cwe_checker, sbom hygiene, config widen, health/deep) — both sets need to be live for the verification table at the end of each wave | Two rebuilds: one mid-session, one at wrap |

## Quality Rule Candidates

**Not adding any to harness.json this wave.**

Candidates considered:
- `pydantic.*BaseSettings` touch → remind to rebuild — too coarse;
  would fire on every edit to config.py including pure docstring
  changes.  Belongs as a CLAUDE.md rule extension, not a regex.
- `asyncio\.gather\(.*\bdb\b` → rule-#7 gatekeeper — too many
  false positives; "db" is a common var name, and the real
  hazard is gather-over-shared-AsyncSession, not just "db" as a
  variable in the same call.  An AST linter could express this
  precisely (see pattern #3), but it's a one-instance bug so far
  (just cwe_checker) — don't institutionalise until a second
  incident.
- Generic "use run_in_executor for sync file I/O" → already
  covered by the existing async-subprocess AST linter's sibling;
  would need its own AST walker.  Defer.

The linter added this wave (`lint_async_subprocess.py`) already
covers the concrete regression class that DID appear.  Future
waves of the same class can consider Python-based AST linters as
the go-to over regex.
