# Patterns: Wairz Intake Sweep — Wave 1+2 close (2026-04-21, session b56eb487)

> Extracted: 2026-04-21
> Campaign: `.planning/campaigns/wairz-intake-sweep-2026-04-19.md`
> Handoff: `.planning/knowledge/handoff-2026-04-21-session-b56eb487-end.md`
> Baseline: 4f6d47e → 83acb9d (+35 commits)

## Successful Patterns

### 1. "7 additive + 1 cut-over" god-class split

- **Description:** When converting a monolithic service file (≥1000 LOC)
  to a subpackage, ship 7 commits that are PURELY ADDITIVE (each extracts
  one topic file; the new files exist but callers still use the
  monolith), then ONE cut-over commit that deletes the monolith, updates
  all callers in-place (≤5) or keeps a one-line shim (>5), and adds
  forwarder methods in class-shape cases (Mixin→composition).
- **Evidence:** Both γ (manifest_checks 2589 LOC, 18 methods → 8 topic
  files + checker.py + __init__.py) and δ (security_audit_service 1258
  LOC, 23 functions → 8 topic files + __init__.py) shipped 8-commit
  splits with 0 reverts. Each of commits 1-7 was pure-additive and
  bisect-clean: reverting commit 5 loses only misc.py, not later
  extractions. Commit 8 was the atomic cut-over: for γ, the
  `AndroguardService(ManifestChecksMixin)` → `AndroguardService` swap
  plus 19 `_check_*` forwarders; for δ, the monolith deletion plus 5
  caller updates + 2 test updates in one commit. Each stream's Rule #8
  rebuild + Rule #11 runtime smoke ran ONCE after commit 8, not per
  commit.
- **Applies when:** Any single-file refactor ≥1000 LOC that decomposes
  into ≥5 topic modules. Start with a seam-analysis step (grep class
  names, function definitions, shared constants) to size the topic
  files; aim for ≤500 LOC per topic (γ's components.py was 990 — can
  split further in a follow-up if desired). The cut-over commit should
  include a caller audit — ≤5 → update in-place (cleanest); >5 →
  keep a shim module with `from app.services.new_pkg import *`.

### 2. Rule-19 bulk intake audit via DB/filesystem evidence

- **Description:** When the intake scanner reports N "pending" items, do
  a Rule #19 evidence-first audit BEFORE dispatching work on any of
  them. Probe each intake's acceptance criteria against current
  on-disk / in-DB state. Intakes marked `status: pending` in markdown
  may have been silently shipped in prior sessions — trust the DB, not
  the spec. Flip shipped ones to `status: completed` with an evidence
  paragraph citing specific commit SHAs.
- **Evidence:** α audit of 12 "pending" intakes found 8 were already
  shipped in prior sessions (data-constraints via 435cb5c2 Alpha;
  data-schema-drift via 435cb5c2 Alpha; data-pagination via 435cb5c2
  Beta; infra-cleanup via 435cb5c2 Delta; infra-volumes via 198243b8 α;
  frontend-api-client via 435cb5c2 Zeta; frontend-store-isolation via
  198243b8 β; LATTE via 435cb5c2 Epsilon). 2 were partial with detailed
  status notes (frontend-code-splitting V1 done / V2 partial;
  backend-service-decomposition in-progress via parallel γ stream). 2
  housekeeping fixes (apk-scan YAML frontmatter; next-session-plan
  retyped as reference). Without this audit, the session would have
  dispatched agents to re-do shipped work.
- **Applies when:** Any multi-item session with a "pending intakes"
  list. The markdown scanner only reads `^status:` regex — the actual
  ship state lives in commits / running containers / DB. The audit is
  cheap (30-60 min via one sub-agent) and high-leverage (can cut a
  session's scope in half by eliminating phantom work). Particularly
  valuable when campaigns have been running for multiple sessions and
  intake files drift from actual state.

### 3. Per-chunk bundle verification (Rule #26 extension)

- **Description:** After `docker compose up -d --build frontend`, verify
  β-style code-splitting or virtualization changes by iterating ALL
  per-page chunks under `/usr/share/nginx/html/assets/`, not just the
  main `index.js`. Vite's code-splitting puts each route's code in its
  own chunk; `index.js` only holds the root shell + non-lazy-loaded
  components. A change that adds react-window to a lazy-loaded page
  lands in that page's chunk, not index.js.
- **Evidence:** Stream β virtualized 3 pages (HardwareFirmware BlobTable,
  ComparisonPage, SecurityScanPage). Post-rebuild verification via
  per-chunk grep confirmed:
  - `HardwareFirmwarePage-C-FK-RMF.js`: 3 virt-hints (BlobTable is
    bundled into HardwareFirmwarePage chunk since it's lazy-loaded)
  - `ComparisonPage-BQWZdKeo.js`: 3 virt-hints
  - `SecurityScanPage-l13xIl0K.js`: 3 virt-hints
  Plus previously-virtualized `ExplorePage-B7VyzrGm.js` (15 hits via
  Monaco+tree), `FindingsPage-Bvx1lRv7.js` (3), `SbomPage-CRucvHhP.js`
  (3). 71 total chunks. Anti-pattern #2 from last session now codified
  as a `for chunk in $(...)` loop in the verification recipe.
- **Applies when:** Rule #26 verification after any frontend/src/**
  change that affects a lazy-loaded page. Recipe: `for chunk in $(docker
  exec wairz-frontend-1 ls /usr/share/nginx/html/assets/ | grep -E
  'Page-|Table'); do n=$(docker exec wairz-frontend-1 sh -c "grep -oE
  'rowComponent|itemSize|rowHeight|react-window'
  /usr/share/nginx/html/assets/$chunk 2>/dev/null | wc -l"); if [ "$n" -gt 0
  ]; then echo "$chunk: $n virt-hints"; fi; done`. Use semantic tokens
  (`rowComponent`, `itemSize`) instead of literal library names if
  minification is aggressive — the semantic tokens are part of the
  public API and survive.

### 4. Worktree-per-stream discipline holds across 5 sessions

- **Description:** `git worktree add .worktrees/stream-{name} -b
  feat/stream-{name}-{YYYY-MM-DD}` + operate IN that path for ALL
  writes/commits. Absolute-path symlink `frontend/node_modules` from
  the main checkout (skip 2 GB npm-install). Merge back via `git merge
  --no-ff`. Remove the worktree.
- **Evidence:** This session's 4 streams (α 12 commits + β 3 commits +
  γ 8 commits + δ 8 commits). All four operated in real worktrees;
  0 cross-stream commit sweeps (4 of 4 streams); 0 merge conflicts
  across the 4 `--no-ff` merges. Matches every prior session since
  Wave-3 198243b8 β first adopted the pattern proactively. **5
  consecutive sessions** of clean worktree discipline.
- **Applies when:** ANY parallel-stream dispatch. The `isolation:
  "worktree"` harness parameter is still a no-op; the real `git worktree
  add` must be in the sub-agent prompt verbatim. Symlink MUST be
  absolute-path (`/home/dustin/code/wairz/frontend/node_modules`);
  relative paths are fragile to depth miscounting (anti-pattern #1 from
  last session).

### 5. "cd into worktree in same bash call" for all git commands

- **Description:** Rule #23 worktree discipline relies on all git
  commands landing in the worktree's branch, not the main checkout's.
  Because the Bash tool's `cwd` persists between calls but is NOT
  guaranteed to be the worktree path (it resets to `/home/dustin/code/wairz`
  between distinct tool invocations), prefix every git command with
  `cd /home/dustin/code/wairz/.worktrees/stream-{name} && git ...` in
  the same bash call.
- **Evidence:** All 4 stream agents this session followed this
  discipline; 0 wrong-branch commits (compare with anti-pattern #4 from
  last session: stream-γ had a wrong-branch commit attempt that git
  correctly rejected with "On branch clean-history, no changes added").
  Agent sub-prompts explicitly called out the `cd && git` chaining.
- **Applies when:** Every git command from inside a parallel-stream
  session. Also applies to `docker compose exec` calls that need the
  main checkout's docker-compose.yml — prefix with `cd /home/dustin/code/wairz`
  explicitly rather than assuming the shell is in the right place.

### 6. "No rebuild commits 1-7, full rebuild + smoke on commit 8" for class-shape changes

- **Description:** During a god-class split, commits 1-(N-1) are
  additive — they create new files but don't change any class instance
  shape because the monolith still defines the running class. Rule #8
  (class-shape change → rebuild) doesn't apply. Skip the rebuild;
  verify via local `python3 -m py_compile`. Only commit N (the
  cut-over) changes class shape, so Rule #8 rebuild + Rule #11 smoke
  run ONCE at the end.
- **Evidence:** Both γ and δ adopted this cadence. 8 commits each; 1
  rebuild per stream (not 8). Total session rebuild count: 3 (one
  post-β-merge for frontend; one post-γ-merge for backend+worker; one
  post-δ-merge for backend+worker). Agent reports confirmed the
  MCP 172-tool invariant probe against the OLD container (running
  pre-split code) returned 172 throughout commits 1-7 — because the
  old code was still valid. The real invariant check happened after
  rebuild at commit 8; both splits returned 172 post-rebuild.
- **Applies when:** Any god-class split or subpackage extraction where
  the monolith coexists with the new files through most of the split.
  Does NOT apply to in-place edits that change class shape mid-refactor
  (e.g. removing a field from an existing class) — those need rebuild
  immediately.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Dispatch 3 parallel Wave-1 streams (α intake / β frontend / γ backend) | Disjoint file trees: α touches `.planning/intake/`, β touches `frontend/src/`, γ touches `backend/app/services/`. Zero overlap risk. | 23 commits shipped in parallel with 0 conflicts, 0 sweeps. |
| Rule-19 audit as Stream α (not serial pre-work) | Evidence-first discipline demanded the audit happen BEFORE any new work; but parallelizing it with β and γ cost nothing (disjoint files). | 8 intakes flipped to completed while β and γ worked in parallel. |
| Defer Phase 5 Phase 3-5 splits (sbom, emulation, mobsfscan) | γ+δ took the full session's serial-stream capacity (~2h each). Adding more splits risked half-done state. Intakes already re-measured for next session. | 16 commits for γ+δ; 3 more splits scheduled for next session with accurate LOC re-measurements. |
| δ cut-over: update 5 callers in-place vs keep shim | Intake rule: ≤5 call sites → update. 5 sites + 2 tests = 7 touch points, but the sites are well-localized. Cleanest final state. | Shim deleted in commit 8; single canonical `from app.services.security_audit import ...` path. |
| γ's docker-cp transient for pre-merge smoke testing | The worktree's new files aren't visible to running containers. Rather than wait for merge, γ `docker cp`'d files in, restarted, ran APK smoke test. Caught a latent `xml.etree.ElementTree` import bug before the real merge. | Rule #20 docker-cp pattern validated; commit 1 was amended to add `import xml.etree.ElementTree as ET`. |

## Applicability Notes

- Rules #8, #11, #19, #23, #24, #25, #26 all exercised cleanly this
  session. Two new rule candidates proposed in the handoff (Rule #27 =
  "7 additive + 1 cut-over"; Rule #28 = "re-measure LOC before
  scheduling — intakes drift +14-22%"). User to review + adopt.
- The "7 additive + 1 cut-over" pattern (#1 above) is a natural
  extension of Rule #25 (per-commit discipline). It PRESCRIBES which
  commits change behavior (just one) vs which are housekeeping (the
  rest). Good candidate for future `.mex/patterns/` recipe file.
- Per-chunk bundle verification (#3) generalizes anti-pattern #2 from
  last session into a stable recipe. Worth promoting to a Rule #26
  sub-paragraph or a dedicated `.mex/patterns/docker-rebuild-frontend-verify.md`.
- The Rule-19 bulk audit pattern (#2) is highly reusable for
  multi-session campaigns. When a campaign enters its 4th+ session,
  the intake status markdown WILL have drifted from reality. Dispatch
  a single audit agent before starting work.

## Cross-references

- Rule #23 validation: this session is the 5th consecutive session
  where worktree-per-stream held (prior: 198243b8 β; d9f61335 α+β+γ;
  b56eb487 α+β+γ+δ). Zero cross-stream sweeps across 26 stream
  executions.
- γ's `xml.etree.ElementTree` implicit-import side-effect fix
  (network_security.py) is a pattern to watch: Mixin-based code sometimes
  relies on implicit attribute resolution that breaks when methods are
  moved to a new class with different module context. For future splits,
  add a step between commits 1-7 that runs `python3 -c "from
  app.services.<new_pkg>.<topic> import *"` to catch latent import
  gaps before the cut-over commit.
- Anti-patterns #1 (absolute-path symlink), #2 (per-chunk verification),
  #4 (`cd && git` chaining) from
  `wairz-intake-sweep-wave1-close-2026-04-20-antipatterns.md` all
  AVOIDED this session via explicit sub-agent prompt instructions.
  Discipline held.
