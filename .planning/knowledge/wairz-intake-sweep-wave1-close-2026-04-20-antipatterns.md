# Anti-patterns: Wairz Intake Sweep — Wave 1 close (2026-04-20, session d9f61335)

> Extracted: 2026-04-20
> Campaign: `.planning/campaigns/wairz-intake-sweep-2026-04-19.md`

## Failed Patterns

### 1. Relative-path `node_modules` symlink with miscounted depth
- **What was done:** `ln -sf ../../frontend/node_modules
  .worktrees/stream-alpha/frontend/node_modules` — intending to point
  at `/home/dustin/code/wairz/frontend/node_modules` from the worktree's
  `frontend/` directory.
- **Failure mode:** The relative `../../` from
  `.worktrees/stream-alpha/frontend/` resolves to `.worktrees/`, not
  the main repo root. Result: symlink points at non-existent
  `.worktrees/frontend/node_modules`. `npx tsc` fails with "tsc not
  installed" and the agent spends several tool calls diagnosing the
  apparent missing typescript before realizing the symlink is wrong.
- **Evidence:** This session's initial Wave 1 dispatch; 3 bash calls
  lost before the symlink bug surfaced via
  `ls .worktrees/stream-alpha/frontend/node_modules/.bin/tsc` →
  "No such file or directory".
- **How to avoid:** Use absolute paths for worktree symlinks:
  `ln -sf /home/dustin/code/wairz/frontend/node_modules
  .worktrees/stream-{name}/frontend/node_modules`. Update Rule #23's
  verbatim dispatch command. Or if relative is preferred, use
  `../../../frontend/node_modules` (3 `../` counting:
  `.worktrees/stream-X/frontend/` → `.worktrees/stream-X/` →
  `.worktrees/` → `{repo-root}/` → `{repo-root}/frontend/`).

### 2. "grep the main bundle" as a sufficient Rule #26 freshness check
- **What was done:** Post-rebuild, verified the served frontend by
  grepping ONLY `/assets/index-*.js` for `6e5` / `3e5` / `timeout:`.
- **Failure mode:** Only 2 `6e5` hits appeared in the main bundle
  (the pre-existing yara/audit constants), leading to a false
  "rebuild didn't pick up my changes" alarm. Code-split chunks
  (`DeviceAcquisitionPage-DGzbicTK.js`,
  `HardwareFirmwarePage-C3Nchhvc.js`, `SecurityScanPage-DpR7OhpX.js`)
  hold the real timeout additions for lazy-loaded routes — main
  `index.js` only has the shell + components that aren't
  lazy-loaded.
- **Evidence:** Initial grep: `grep -oE '6e5' /tmp/bundle.js | wc -l`
  → 2. Agent treated this as evidence of a stale build, then dug
  deeper and found the per-page chunks. Had the per-chunk check been
  first, the time spent diagnosing a non-bug would have been saved.
- **How to avoid:** The Rule #26 verification recipe in CLAUDE.md
  should include: "grep ALL files under the served `/assets/`
  directory, not just the main index chunk". Practical shell:
  `for chunk in $(docker exec <ctr> ls /usr/share/nginx/html/assets/
  | grep -E '\\.js$'); do echo "=== $chunk ==="; curl -sf
  "http://127.0.0.1:3000/assets/$chunk" | grep -E '<marker-pattern>'
  | head; done`. Or rely on call-site structure (the endpoint URL
  + `,{timeout:` literal) which is more stable across minifier
  variable renames than literal numeric constants.

### 3. Attempting a 2500+ LOC god-class split at end-of-session
- **What was done:** The session prompt explicitly scheduled Wave 2
  (manifest_checks.py 8-file decomposition) after Wave 1 merged.
  Agent initially considered attempting a "partial scaffolding"
  (extract shared helpers + 1 topic file) to make progress.
- **Failure mode:** Would have introduced a half-split Mixin state
  — some check methods moved to new classes, others still on the
  Mixin. `AndroguardService(ManifestChecksMixin)` still inherits,
  so `self._check_*` dispatch works for both. BUT the composition
  shim `self.manifest_checker = ManifestChecker(self)` would have
  been half-wired. If the session ended mid-refactor, next-session
  pickup would face an ambiguous class-shape mid-transition. Rule
  #8 (class-shape change → rebuild backend+worker) would have been
  owed mid-session, risking a scanner outage. APK scanning is a
  prod-critical path — partial state is MUCH worse than deferral.
- **Evidence:** Assessment at step 6 of task-7: measured
  `backend/app/services/manifest_checks.py` at 2589 LOC; counted
  18 check methods; enumerated 3 shared static helpers; identified
  `androguard_service.py:447` inheritance point. Decided to defer
  whole split. Wrote detailed continuation prompt in the handoff
  + campaign "Session 2026-04-20 summary" section.
- **How to avoid:** Serial refactor streams that change class shape
  (mixin → composition; inheritance chain edits; splitting a class
  across files) need to go in ONE session with enough budget for:
  (a) reading every method to understand self.* access patterns,
  (b) per-commit MCP invariant + Rule #11 runtime smoke test after
  each extract, (c) Rule #8 full rebuild at the end. Estimate
  conservatively (2-4 h for ~2500 LOC). If session budget is
  inadequate at the Wave-2 gate, SKIP the wave and write a
  continuation prompt with: the subpackage layout, per-commit
  discipline, the composition bridge sketch, the acceptance grep.

### 4. Running `git commit` from the wrong working directory after parallel worktrees
- **What was done:** After editing in `.worktrees/stream-gamma/.mex/ROUTER.md`
  via the Edit tool (absolute path), agent ran `git add -A .mex/ROUTER.md
  && git commit -m ...` in a bash command that did NOT `cd` into the
  stream-gamma worktree first. The bash shell was still in the main
  `/home/dustin/code/wairz` checkout (from a prior call that had left
  it there).
- **Failure mode:** The commit hit the main `clean-history` branch
  instead of `feat/stream-gamma-2026-04-20`. git saw no changes
  (because the edit was in the worktree, not main), exited 1 with
  "no changes added to commit". No harm done; retry with `cd
  .worktrees/stream-gamma && git add ...` succeeded. But without the
  wrong-directory error, the commit would have landed on main pre-
  merge, polluting the integration branch with un-reviewed stream
  work.
- **Evidence:** Mid-Stream-γ commit for γ3 ROUTER.md sync. Bash
  output: "On branch clean-history" (wrong branch), "no changes
  added to commit".
- **How to avoid:** ALWAYS chain `cd` into the worktree path
  IN THE SAME bash command as the commit: `cd
  .worktrees/stream-{name} && git add -A {paths} && git commit -m
  ...`. The `cwd` persists across bash calls, but assume it
  resets to `/home/dustin/code/wairz` between distinct steps —
  prefix every commit call with the explicit `cd`. Related to
  Rule #23 discipline: the worktree-per-stream pattern only
  works if ALL git calls land in the worktree, not the main tree.

### 5. Treating "prompt says Wave 2" as prescriptive when evidence says "too big for remaining budget"
- **What was done:** The dispatch prompt included Wave 2 with detailed
  stream-δ instructions, positioned after Wave 1 merges. An agent
  blindly executing the prompt would dive into Wave 2 regardless of
  context/budget state.
- **Failure mode:** Rule #19 (evidence-first) was implicitly at play:
  the intake measured manifest_checks.py at 2263 LOC; the filesystem
  says 2589 LOC. The spec is stale. Executing against stale spec
  without re-scoping risks either a half-done refactor (see anti-
  pattern #3) or a wholesale session timeout mid-commit.
- **Evidence:** This session's explicit "Wave 2 scope assessment"
  step: LOC re-measurement, cross-file dependency analysis,
  cost/benefit reasoning, then deferral. The alternative (blind
  execution) would have attempted the split.
- **How to avoid:** Dispatch prompts are plans, not commitments.
  Before starting any phase described as "multi-hour refactor", re-
  measure the subject (Rule #19) and re-cost against remaining budget
  (prompt's own abort conditions list budget thresholds). If the
  scope has grown or the remaining budget is inadequate, DOCUMENT
  the deferral in the handoff with a re-costed continuation prompt.
  The campaign file's "Continuation State" section is the right
  location; the dispatch prompt should be regenerated for the next
  session with current measurements.

## Not a failure this session (but worth noting as a watched pattern)

- Multiple `TaskUpdate` reminders fired mid-session ("task tools
  haven't been used recently"). Agent responded each time by
  keeping the task list current. This is a working safety net, but
  frequent firings may indicate the TaskList's granularity is too
  coarse (7 tasks for a 3-wave session; sub-tasks could have been
  tracked at commit level). Not worth restructuring — just noting
  for future sessions that the reminder firing rate is calibrated
  for 5-10 minute task intervals.
