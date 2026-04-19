# Patterns: Bug-fix cluster (session 93a4948d, turn 2)

> Extracted: 2026-04-19
> Campaign: `.planning/campaigns/wairz-intake-sweep-2026-04-19.md` (active)
> Postmortem: none (bug-fix cluster, not a campaign phase)
> Commits: `2cb2cca` (Rule #26 + incident doc), `b437095` (scan timeout + error surface fix)

## Successful Patterns

### 1. HAR-first triage for frontend runtime errors
- **Description:** Asked the user for a Chrome DevTools HAR export at the start of the investigation. The HAR contained the failing request sequence (8 entries, all 200s), timing (`18:48:36.756Z` for the duplicate `/projects` calls), headers (X-API-Key, Referer), and — via the included page title — exact URL context. Parsing the HAR JSON took <10 seconds and supplied enough context to skip several hypothesis levels.
- **Evidence:** `/home/dustin/code/wairz/bug.har` copied via scp; parsed via `python3 -c "import json; har = json.load(open(...))"`. Identified the doubled `/api/v1/projects` call + the Page-envelope response body.
- **Applies when:** a frontend runtime error is reproduced in the user's browser but not on the dev host. HAR skips the repro-on-my-side problem entirely.

### 2. Bundle-vs-commit-date reconciliation for stale-image bugs
- **Description:** `docker compose images frontend --format '{{.CreatedAt}}'` compared against `git log --format='%ci' -1 -- frontend/` yielded the root cause in one grep: image was built **2h 34m before** the fix commit. Before this diagnostic the hypothesis space was wide (StrictMode, dedupe bug, race, backend drift). The timestamp delta collapsed it.
- **Evidence:** Container CreatedAt `2026-04-19T14:47:15Z`; commit `3063283` (adds `unwrap`) `2026-04-19 11:14:53 -0600` = `17:14:53Z`. Commit is 2h 27m newer than image → stale.
- **Applies when:** a frontend error trace points at a function whose *current source code* looks correct. The next question is always "does the running bundle actually have that source?"

### 3. Inspect the shipped JS for the specific change
- **Description:** Grepped the minified bundle for the compiled shape of the `unwrap` helper (`Array.isArray(...):(...==null?void 0:...items)`) to confirm presence/absence before theorising. When present: fix works. When absent: bundle is stale regardless of when it was built.
- **Evidence:** Pre-rebuild bundle `index-3kZyRoWG.js`: `async function _W(){const{data:e}=await Se.get("/projects");return e}` — no unwrap. Post-rebuild bundle `index-CgTNrfjK.js`: `async function _W(){const{data:a}=await Ce.get("/projects");return iR(a)}` — unwrap present.
- **Applies when:** you have a hypothesis about a specific code path in a minified bundle. Grepping the bundle for the expected structure is faster than running the app to test.

### 4. Two-part error fix: make it work + make future failures visible
- **Description:** The scan-timeout fix had two distinct parts. **Part (a)**: extend axios timeout on 4 scan endpoints so they actually complete. **Part (b)**: replace `catch {}` with `catch (e) => extractErrorMessage(e, fallback)` so any *future* failure (auth, 500, new timeout at 10 min, etc.) surfaces the real reason instead of a hardcoded lie. Part (a) alone would silently mask the next class of bug; part (b) alone would expose the current timeout as "timeout of 30000ms exceeded" without fixing it.
- **Evidence:** `frontend/src/api/findings.ts` (timeouts) + `SecurityScanPage.tsx` + `ProjectActionButtons.tsx` (error handlers). Both layers committed together in `b437095`.
- **Applies when:** a bug is caused by a failure-plus-swallow pair. Fix both — the code path AND the observability — in the same commit.

### 5. Match timeout tier to operation type
- **Description:** Used two named constants — `SECURITY_SCAN_TIMEOUT = 6e5` (10 min, tree-walking audits) and `HASH_SCAN_TIMEOUT = 3e5` (5 min, per-binary hash lookups against external APIs) — rather than one blanket value. Existing `exportImport.ts` and `comparison.ts` already used tiered timeouts (30s / 60s / 5min / 10min); the new file matches the convention.
- **Evidence:** `frontend/src/api/findings.ts` post-fix. Shipped as `const i=6e5,c=3e5` in the minified chunk.
- **Applies when:** you're extending timeouts on a cluster of long-running endpoints. One constant per operation *class* beats one constant for all.

### 6. Prove the fix with a post-rebuild bundle grep
- **Description:** After `docker compose up -d --build frontend`, verified the fix was actually in the shipped bundle by grepping for the new constants (`6e5`, `3e5`) and strings (`Security audit failed`, `YARA scan failed`). Didn't trust typecheck+build success alone; proved the artifact that nginx serves.
- **Evidence:** Session log: `grep -oE ',6e5,3e5' /tmp/findings.js` returned `]}const i=6e5,c=3e5;async function u(...)`; `SecurityScanPage-*.js` chunk contained `Security audit failed")]})` post-rebuild.
- **Applies when:** any rebuild-dependent fix. Typecheck proves the source compiles; bundle grep proves the artifact serves.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Rebuild frontend, **zero code change**, for the TypeError on /projects | Source already had `unwrap`; image lagged by 2h 27m | Fix in 15 min from HAR delivery, 0 LOC diff |
| Codify Rule #26 "rebuild frontend on frontend/src/** change" | Backend Rule #8 had no analog; this class of bug would recur | Rule #26 + harness rule `auto-frontend-rebuild-not-restart` + `.mex/` mirror per Rule #21 |
| Two-tier timeouts (10 min scan / 5 min hash) | Semantic clarity + matches existing `exportImport.ts` / `comparison.ts` pattern | Shipped as `i=6e5, c=3e5` in minified chunk |
| `extractErrorMessage(e, 'Security audit failed')` instead of rename `catch` → `catch(_)` | The utility already exists (`frontend/src/utils/error.ts`); passing real error beats silent suppression | Future failures now surface axios error text, HTTPException detail, or fallback |
| Keep 10-min ceiling for now, defer arq-job refactor to next session | Fix timeline matters; 10 min covers typical projects; arq refactor is a 1-2h change | Scope control — next-session candidate noted |
| Flip Option B intake via Rule-19 audit (zero rewrite) | DB showed feature shipped; intake status just stale | Saved ~6 sessions of redundant work (earlier in this session) |
