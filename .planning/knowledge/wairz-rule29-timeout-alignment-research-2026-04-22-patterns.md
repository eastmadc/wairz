# Patterns: Rule #29 Research + Adoption (2026-04-22, session 7e8dd7c3, post-timeout-sweep)

> Extracted: 2026-04-22
> Parent campaign: `.planning/campaigns/completed/wairz-intake-sweep-2026-04-19.md`
> Trigger: user request "yeah do it with deep research" after the initial timeout-sweep cluster
> Commit range: `a183e22..beeddce` (3 commits)
> Sibling knowledge files:
>   - `wairz-frontend-axios-timeout-sweep-2026-04-22-patterns.md` (the preceding reactive bug fix)
>   - `wairz-intake-sweep-wave1-close-2026-04-22-patterns.md` (the campaign close)

## Context

The user, after the initial timeout-sweep fix cluster (10 commits
6814461..31f6003), asked for a deeply-researched Rule #29 rather than
a hand-waved one. The main session dispatched 3 parallel research
agents (backend audit, frontend survey, upstream ecosystem) and
synthesized the results into a formula-grounded rule with explicit
citations. The research surfaced 4 critical frontend↔backend
misalignments the reactive sweep had missed because my estimates of
backend timeouts were wrong.

## Successful Patterns

### 1. Three-agent parallel research for dense rule drafts

- **Description:** When adopting a CLAUDE.md rule that requires
  grounded evidence (not just "I think X is a pattern"), dispatch
  research in parallel across 3 orthogonal dimensions:
  - **Internal backend audit** — what's the actual current state
    of the thing being ruled on? (config values, service-level
    limits, implicit defaults)
  - **Internal frontend audit** — what does current code already
    look like? (drift, duplication, inconsistency)
  - **Upstream ecosystem research** — what do the relevant library
    docs / standards / other-codebases say? (axios default, nginx
    proxy_read_timeout, Cloudflare 524, MDN XHR.timeout)
  The three reports compose naturally: backend = ground truth for
  what the rule must reason about, frontend = current-state baseline
  (drift audit), upstream = sanity check on limits and best
  practices.
- **Evidence:** Session 7e8dd7c3 Rule #29 adoption:
  - Agent A (backend) found 4 critical misalignments invisible
    from frontend code alone, including the 120→300s Ghidra
    timeout bump that had happened at some earlier point without
    the frontend catching up.
  - Agent B (frontend) found that `SECURITY_SCAN_TIMEOUT=600_000`
    is duplicated in 8 files without a canonical owner — drift
    risk invisible without the systematic per-file survey.
  - Agent C (upstream) produced the 5 gateway-timeout ceilings
    (Chrome 300s, nginx/ALB 60s, Cloudflare 100s, uvicorn no-timeout,
    axios 0-default) that anchor the rule's "escalate to 202+polling
    when > 100s" caveat with real numbers, not guesses.
  
  All 3 reports took <10 min combined wall-clock (parallel dispatch).
  Synthesis into the rule draft took ~5 min. The rule's credibility
  comes from specific citations: `config.py:24 ghidra_timeout=300`,
  `binary.py:1637 communicate(timeout=120)`, `client.ts:6 timeout: 30_000`,
  axios request-config docs URL, uvicorn settings URL.
- **Applies when:** Any new CLAUDE.md rule or Learned Rule candidate
  that makes quantitative claims (timeouts, thresholds, size limits,
  drift rates). Three-agent parallel research pays for itself in the
  first time a future author questions a number — having the grep
  line and the docs URL pre-cited in the rule body stops re-litigation
  dead.

### 2. Formula-over-table rule design

- **Description:** Instead of enumerating every endpoint + its
  specific timeout in the rule body (brittle, goes stale the moment
  a new endpoint is added), state a FORMULA the author can apply
  mechanically. The rule then lists the existing tier constants as
  EXAMPLES of the formula's output, not as prescriptive values.
- **Evidence:** Rule #29's formula:
  `frontend_ms ≥ backend_s × 1200` (×1000 ms-conversion + ×1.2 grace).
  A new author adding a long-op endpoint:
  - greps the backend for the authoritative timeout
  - applies the formula
  - either reuses a matching tier constant or adds a new one
  
  The rule ages well: if a new scanner with a 45s timeout lands,
  the author computes `45 × 1200 = 54_000 ms`, picks the next
  tier up (DEVICE_BRIDGE_TIMEOUT=300_000 or adds a new TIER_60s if
  none exists), and the rule's integrity is preserved without
  editing the rule itself. Contrast with "Tier 1: 30s for CRUD,
  Tier 2: 60s for X, Tier 3: 180s for Y, Tier 4: 600s for Z" —
  every new endpoint that doesn't fit would force a rule rewrite.
- **Applies when:** Any CLAUDE.md rule about quantitative derivation
  (timeouts, cache TTLs, budget limits, size thresholds). Lead with
  the formula + mechanical author-check procedure; relegate current
  observed values to citation examples.

### 3. Stale-value-discovery as a side-effect of research

- **Description:** Research dispatched to ground a NEW rule
  frequently surfaces stale values in EXISTING code or docs — the
  rule was needed partly because nobody had a systematic view.
  Ship fixes for the stale values IN THE SAME CLUSTER as the rule
  adoption, so the rule's credibility isn't undermined by its own
  counter-examples.
- **Evidence:** Agent A (backend audit) surfaced that `config.py:24
  ghidra_timeout=300`, but:
  - `CLAUDE.md` env table said "GHIDRA_TIMEOUT: Decompilation
    timeout in seconds (default 120)" — stale
  - `frontend/src/api/analysis.ts:14` comment said "Ghidra
    decompilation takes 30-120 s per GHIDRA_TIMEOUT in config.py"
    — stale
  - `GHIDRA_ANALYSIS_TIMEOUT=180_000` — sized against the stale
    120s belief, missing the real ceiling by 120s
  - My own reactive timeout sweep earlier in the session was built
    against the stale value and shipped the wrong constant
  
  Shipping the rule WITHOUT fixing these would have made Rule #29
  immediately false ("the codebase aligns timeouts via formula")
  because 4 critical misalignments existed. Commit `a183e22` fixed
  2 of them (Ghidra/radare2) in the same cluster. The other 2
  (emulation, fuzzing) are documented as DEFERRED because they
  require a refactor to 202+polling — captured in the rule body
  as "4 critical misalignments found; 2 fixed, 2 pending refactor".
- **Applies when:** Any rule adoption whose research surfaces
  concrete errors. Fix what's cheap (≤1 file edit, same session),
  document what requires refactoring, and cite both explicitly in
  the rule body. This builds credibility — the rule ships already
  partly-enforced.

### 4. Ceiling caveats tied to deployment topology

- **Description:** Rules about timeouts (or any resource limit)
  should explicitly call out the deployment-topology caveats that
  affect whether the rule's values are safe. wairz currently runs
  same-origin (frontend → backend direct), so the 600s
  SECURITY_SCAN_TIMEOUT works. Under a Cloudflare/ALB/nginx
  reverse proxy, intermediate ceilings (100s / 60s / 60s) would
  502/504 first. The rule names both states and gives the escape:
  "use 202+polling if the tier exceeds the proxy's proxy_read_timeout".
- **Evidence:** Rule #29's paragraph:
  > wairz currently deploys same-origin (frontend → backend
  > directly, no proxy), so the 600s tier works — but ANY
  > deployment behind a reverse proxy MUST either tune the proxy's
  > `proxy_read_timeout` ≥ the frontend tier OR convert the
  > endpoint to the 202+polling pattern (precedent: firmware
  > unpacking returns 202 and the frontend polls every 2s).
  
  Precedent `202+polling` example already exists in-tree (CLAUDE.md
  line 180 "Firmware unpacking is non-blocking"), so the rule
  doesn't introduce a new pattern; it reuses one the codebase
  already knows.
- **Applies when:** Any rule whose values depend on network /
  deployment topology (timeouts, upload sizes, connection pool
  limits). Name the current topology; name the ceiling that would
  break the rule; provide the escape hatch.

### 5. Rule-adoption cluster discipline (formula + fixes + mirror + env-table)

- **Description:** A rule adoption is a 4-part atomic cluster:
  (a) CLAUDE.md rule body with formula + citations
  (b) `.mex/context/conventions.md` Verify Checklist mirror (per Rule #21)
  (c) Fixes to any in-tree code that would contradict the rule right
      now (so the rule ships already ~enforced)
  (d) Fixes to any stale docs that cite wrong values (env tables,
      comment blocks, cross-references)
  Ship all 4 in the same cluster so a future reader doesn't find a
  rule that contradicts the current code.
- **Evidence:** Rule #29 cluster (3 commits):
  - `a183e22` — fixes analysis.ts timeouts + updated comment block
    (part c + part d inline)
  - `732d82f` — CLAUDE.md rule body + stale env-table fix
    (part a + part d)
  - `beeddce` — .mex/context/conventions.md mirror (part b)
  
  The 4 parts are NOT always 4 separate commits — part (d) can
  piggyback on (a) or (c) as shown. But every part must exist
  somewhere in the cluster, or the rule is self-inconsistent at
  ship time.
- **Applies when:** Every Learned Rule adoption. Rule #27, #28,
  and #29 all followed this shape. Rules #1–#26 were mostly
  added as single-file CLAUDE.md edits, but that was before the
  `.mex` mirror rule (Rule #21) made the 4-part shape
  explicit — going forward, it's the house style.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Dispatch 3 parallel research agents (backend/frontend/upstream) instead of doing the research serially in-session | User explicitly asked for "deep research"; 3 parallel agents completes in ~10 min wall-clock vs ~30 min serial; each agent's context is focused and doesn't pollute the other's; compression happens naturally (each returns a structured summary). | 3 dense reports in parallel; synthesis produced a rule with 5 citation URLs + exact file:line references + a reusable formula. |
| Ship Ghidra + radare2 timeout fixes IN THE RULE ADOPTION CLUSTER, not as separate commits before/after | Rule #29's body asserts "the codebase aligns timeouts via formula" — this must be true at rule-ship time, not eventually. Fixing in-cluster keeps the rule self-consistent. | 1 extra commit (a183e22) before the rule; 2 of 4 misalignments fixed; 2 remaining documented as DEFERRED in the rule body with reasoning. |
| Defer emulation (1800s) + fuzzing (7200s) mismatches instead of fixing in-cluster | Both require converting from synchronous long-timeout to 202+polling pattern — that's a refactor (new job-status endpoint, new polling UI), not a constant-value edit. Scope-creep risk; rule adoption would stall. | Captured in Rule #29 body as "DEFERRED — requires 202+polling refactor". Next author picking up emulation/fuzzing UX work has the pointer. |
| Bump frontend timeouts 20% beyond backend, not matching-exact | Network latency + JSON serialization + clock skew + backend's own grace before kill can add up to several seconds. 20% × 120s = 24s of headroom; 20% × 300s = 60s; 20% × 600s = 120s. Linear scaling of grace with backend size; cheap and safe. | Formula `frontend_ms = backend_s × 1200` (1000 × 1.2) embeds the 20% grace directly. Author never has to compute grace separately. |
| Not consolidate `SECURITY_SCAN_TIMEOUT` into a `timeouts.ts` shared file in this cluster | Consolidation touches 8 files, adds an import everywhere, changes the house style's "constant lives in the owning file" convention. Worth doing, but as its own PR with its own test. | Captured in Rule #29 body as "next refactor should consolidate to `frontend/src/api/timeouts.ts`". Not a blocker for the rule itself. |

## Applicability Notes

- **For CLAUDE.md Rule #30+ candidates:** the 5-part pattern —
  formula + 3-agent research + in-cluster fixes + stale-doc fix +
  mex mirror — is now the established shape. Rules #27, #28, #29
  validate it across 3 consecutive adoptions. Adopt it for any
  future rule that makes quantitative claims.
- **For the deferred emulation/fuzzing refactor:** the 202+polling
  pattern's reference implementation is firmware unpacking
  (backend: `asyncio.create_task()` in `firmware_service.py`;
  frontend: `setInterval` poll every 2s in `ProjectDetailPage.tsx`
  until `status` changes from `unpacking`). Copy that shape; don't
  invent a new one.
- **For the drift audit:** `SECURITY_SCAN_TIMEOUT` duplication was
  invisible from any single file; only the cross-file agent survey
  caught it. If another session adopts Rule #29's "one canonical
  constant per tier" discipline in practice via a consolidation
  PR, it'll need to touch all 8 call sites + their comments in
  one atomic edit. Rule #25 per-sub-task commits: alembic-style
  commit-per-file might be cleanest, but the timeout constant
  touches work naturally as a single commit because the import
  has to land before the duplicate is deleted.

## Cross-references

- Parent campaign: `.planning/campaigns/completed/wairz-intake-sweep-2026-04-19.md`
- Preceding cluster (reactive sweep): `wairz-frontend-axios-timeout-sweep-2026-04-22-patterns.md`
- Session handoff (pre-this-cluster): `handoff-2026-04-22-session-7e8dd7c3-end.md`
  (does not yet include the Rule #29 research cluster; extend at session end)
- Rule #29 adoption commits: `a183e22`, `732d82f`, `beeddce`
- Sources cited in the rule: axios docs, MDN XHR, nginx proxy_module,
  uvicorn settings, Cloudflare 524 error docs, AWS ALB attributes,
  Chrome 5-min fetch ceiling (Node undici issue), OpenReplay
  WebSockets-vs-SSE-vs-polling article
