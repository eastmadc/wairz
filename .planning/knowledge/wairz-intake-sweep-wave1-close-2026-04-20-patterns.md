# Patterns: Wairz Intake Sweep — Wave 1 close (2026-04-20, session d9f61335)

> Extracted: 2026-04-20
> Campaign: `.planning/campaigns/wairz-intake-sweep-2026-04-19.md` § "Session 2026-04-20 summary"
> Handoff: `.planning/knowledge/handoff-2026-04-20-session-d9f61335-end.md`
> Baseline: 4970448 → 50ed62c (+15 commits)

## Successful Patterns

### 1. Additive-timeout extension across N API files parallelizes cleanly
- **Description:** Adding an explicit `{ timeout: CONST }` override to 6
  different endpoint call sites in 6 different frontend API files, one
  commit per file, using local per-file constants that match the tier
  naming from `findings.ts` (SECURITY_SCAN_TIMEOUT = 600_000 /
  HASH_SCAN_TIMEOUT = 300_000). Three parallel streams in separate
  worktrees, 0 conflicts.
- **Evidence:** Stream α commits cb4530d, e61aae0, 8ac05b5, e3e0dc0,
  d2b487a, d2025db — each touches exactly one file (`frontend/src/api/*.ts`),
  each adds 8-11 lines (constant definition + comment + options-object
  extension). All 6 endpoints' compiled output visible in per-page
  chunks (`DeviceAcquisitionPage-DGzbicTK.js`,
  `HardwareFirmwarePage-C3Nchhvc.js`, `SecurityScanPage-DpR7OhpX.js`,
  main `index-CH5-EjS9.js`) after rebuild.
- **Applies when:** Widening an already-established per-file constant
  convention to more call sites. Do NOT extract to a shared
  `frontend/src/api/timeouts.ts` if the existing code uses local
  constants per-file — follow the convention until it's obviously
  paying abstraction debt (6 files is tolerable; 20 would not be).

### 2. Silent-fallback + `console.warn` beats either extreme for "no data yet" UX
- **Description:** When a UI state setter intentionally writes `[]` or
  `null` on exception to render an empty-state view (e.g.,
  `setAssessments([])` → "Start CRA Assessment" CTA), the silent
  fallback is legitimate UX. But a bare `catch {}` discards ALL ops
  visibility. The judgment-call fix is `catch (e)` + `console.warn(e)`
  + a comment explaining why the fallback is intentional. State
  transitions unchanged; real regressions now surface in devtools.
- **Evidence:** Stream β commit 237422c (CraChecklistTab.tsx:71+87).
  Both loadAssessments and loadAssessment now have `catch (e) {
  console.warn('[CraChecklistTab] loadAssessments failed', e); … }`
  with a block comment documenting the rationale. Bundle verification
  confirmed both console.warn calls ship in `SecurityScanPage-DpR7OhpX.js`.
- **Applies when:** Exception handlers that explicitly rescue to a
  legitimate empty state. Contrast with
  `setFoo({ error: 'Failed' })` where surfacing the real message IS
  the right move (use extractErrorMessage). The test for which
  category a handler falls into: "would surfacing the real error
  break the user's mental model of the UI?" If the answer is yes
  (empty-state placeholder), silent fallback is OK but still log.
  If no (error is user-actionable), surface it.

### 3. Worktree-per-stream pattern (Rule #23) holds across 3 sessions
- **Description:** `git worktree add .worktrees/stream-{name} -b
  feat/stream-{name}-{YYYY-MM-DD}` + operate IN that path for ALL
  writes/commits. Symlink `frontend/node_modules` from the main
  checkout to avoid 2 GB npm-install. Merge back via `git merge
  --no-ff` after the stream completes. Remove the worktree.
- **Evidence:** This session's Wave 1 α/β/γ: all three streams
  operated in real worktrees; 0 cross-stream commit sweeps (3 of 3
  streams), 0 merge conflicts across the 3 `--no-ff` merges. Matches
  Wave-3 evidence from session 198243b8 (β proactive worktree → 0
  sweeps) and addresses the Wave-1/Wave-2 failure modes from 435cb5c2.
  Three consecutive sessions now validate the pattern.
- **Applies when:** ANY parallel-stream dispatch (Fleet, Agent tool
  with `isolation: "worktree"`, or manual multi-stream sessions).
  The `isolation: "worktree"` harness parameter is still a no-op;
  the real `git worktree add` must be in the prompt verbatim.
  Fallback only if the harness context can't run git commands.

### 4. Wave 2 deferral decision — choose safe skip over risky partial refactor
- **Description:** When a refactor target grows between intake measurement
  and execution (in this case 2263 → 2589 LOC manifest_checks.py), and
  the session has limited remaining budget for a multi-commit
  sequential split, the SAFE call is to defer the whole refactor and
  write a detailed continuation prompt. A half-split Mixin leaves the
  scanner in an ambiguous state (some methods on the Mixin, some on a
  new class); the class-shape change breaks CLAUDE.md Rule #8
  cached-instance behavior, and APK scanning breaks at runtime.
- **Evidence:** Session 2026-04-20 Wave 2 explicit assessment:
  2589-LOC file, 18 check methods, 3 shared static helpers, deep
  `self.*` dependencies; full 8-file decomposition estimated 2-4 h of
  focused serial work. Deferred. Handoff contains verbatim
  continuation prompt with subpackage layout + per-commit MCP
  invariant requirement + Rule #11 runtime smoke test.
- **Applies when:** Any refactor where (a) the target size exceeds
  intake measurement, (b) partial progress leaves the system in a
  broken state, and (c) session budget is near the per-commit
  invariant-check threshold. Related to Rule #19 (evidence-first):
  when the condition (LOC size) has diverged from spec (intake), trust
  the measurement and re-scope.

### 5. Frontend-bundle Rule-#26 verification must check per-page chunks, not just `index.js`
- **Description:** After `docker compose up -d --build frontend`, verify
  the shipped JS by iterating `docker exec wairz-frontend-1 ls
  /usr/share/nginx/html/assets/` and grepping EACH per-page chunk
  (`*Page-*.js`) for the expected endpoint + options-object pattern.
  Vite's code-splitting sends each route's code to its own chunk;
  `index.js` only contains the root shell + shared lazy-loaded
  components.
- **Evidence:** This session — 6 Stream α endpoints initially showed
  only 2 `6e5` hits in `index-CH5-EjS9.js`, triggering a false
  "stale bundle" alarm. Per-chunk grep found the real locations:
  `device/dump → {timeout:Ie}` in DeviceAcquisitionPage chunk;
  `cve-match → {timeout:yt}` in HardwareFirmwarePage chunk;
  `attack-surface/scan → {timeout:at}` and `auto-populate →
  {timeout:dt}` in SecurityScanPage chunk. The `index.js` bundle
  only had `uefi-scan` and `vulnerabilities/scan` hits (the
  non-lazy-loaded page components).
- **Applies when:** Any Rule #26 bundle-verification step. The recipe
  to extend the rule: `for chunk in $(docker exec <frontend-ctr> ls
  /usr/share/nginx/html/assets/ | grep -E '<feature-page>Page-'); do
  curl -sf "http://127.0.0.1:3000/assets/$chunk" | grep -E
  '<endpoint-path>[^;)]{0,80}' ; done`.
  See also: when the minifier renames variables, literal numeric
  constants (`6e5`) may not appear — the call-site structure
  (`endpoint`,...,`{timeout:VAR}`) is the reliable tell.

### 6. Absolute path symlinks for worktree `node_modules`
- **Description:** Use an absolute path
  (`ln -sf /home/dustin/code/wairz/frontend/node_modules
  .worktrees/stream-{name}/frontend/node_modules`) rather than a
  relative path. Relative paths are fragile to depth miscounting.
- **Evidence:** This session — initial `ln -sf ../../frontend/node_modules`
  resolved to `.worktrees/frontend/node_modules` (two levels up from
  `.worktrees/stream-alpha/frontend/`, only one level up from the
  worktree root, landing in the non-existent `.worktrees/frontend/`).
  The correct relative would have been `../../../frontend/node_modules`
  (three levels up); using the absolute path skipped the counting
  entirely. Redone all 3 symlinks with absolute paths; `npx tsc -b`
  worked immediately.
- **Applies when:** The worktree-dispatch preamble. Update Rule #23's
  verbatim command to use the absolute host path, or document the
  relative-depth count (`../../../frontend/node_modules`) explicitly.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Use per-file local timeout constants, not a shared `timeouts.ts` | Matches findings.ts pre-existing convention (b437095). Extracting for 6 call sites is premature abstraction per "Don't add features beyond what the task requires." | 6 files, 6 commits, 0 conflicts. Clean. |
| Keep CraChecklistTab silent fallback, add console.warn | Empty-state UX is legitimate here (no-assessments case renders the "Start" CTA). But bare `catch {}` lost ops visibility. Hybrid preserves UX + restores debuggability. | Both handlers log to devtools while maintaining the empty-state render. |
| Defer Wave 2 full (skip partial) | Partial mixin→composition split breaks the scanner (Rule #8 class-shape); risk > reward with limited remaining budget. | No refactor shipped; next-session prompt is detailed enough to resume cleanly. |
| Skip Wave 3 entirely | Prompt says "If budget is tight, skip Wave 3 entirely and do the handoff." | Session closed cleanly after Wave 1 + handoff + /learn. |
| Run the full 8-gate verification + bundle inspection AFTER all 3 merges, not per-merge | The 3 streams are touch-disjoint (α: frontend/src/api, β: frontend/src/pages + components/security, γ: backend + Dockerfile + .mex). No per-merge risk. | One verification pass; one Rule #26 rebuild. |

## Applicability Notes

- Rules #23, #24, #25, #26 all exercised cleanly this session. No new
  rule candidates — the existing rule set is sufficient for Wave 1-style
  additive/refactor work.
- The "Wave 2 deferral" pattern (#4 above) is a candidate for
  promotion to CLAUDE.md as a discipline rule, but it's arguably
  already covered by Rule #19 (evidence-first) + Rule #11
  (post-split verification). Leave as session-level learning unless
  it recurs.
- The "per-page bundle verification" recipe (#5) is a useful
  EXTENSION to Rule #26's current verification method. Suggest
  appending to CLAUDE.md Rule #26 as a practical recipe in a future
  session, or to `.mex/patterns/` as a new "docker rebuild frontend
  + verify" pattern file.

## Cross-references

- Rule #23 validation: this session is the 3rd consecutive session
  where worktree-per-stream held (prior: 198243b8 β; this session α+β+γ).
  Compared against the 435cb5c2 evidence (checkout -b only → 2 sweeps).
- Anti-pattern #5 (stale AnalysisCache docstrings) from
  `wairz-intake-sweep-phase-5-cache-refactor-antipatterns.md` closed
  by commit 9d8dd6b. Evidence: 0 hits on the exclusion grep post-commit.
- Rule #19 applied to Wave 2 deferral: the spec (intake) described a
  2263-LOC file; the filesystem described 2589. The spec was stale;
  trust the DB (filesystem). Re-scoped and deferred rather than
  executing against stale spec.
