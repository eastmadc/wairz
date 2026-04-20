# Anti-patterns: Rule #29 Research + Adoption (2026-04-22, session 7e8dd7c3, post-timeout-sweep)

> Extracted: 2026-04-22
> Parent campaign: `.planning/campaigns/completed/wairz-intake-sweep-2026-04-19.md`
> Commit range: `a183e22..beeddce` (3 commits)
> Sibling: `wairz-frontend-axios-timeout-sweep-2026-04-22-antipatterns.md` (reactive cluster's anti-patterns)

## Failed Patterns

### 1. Estimated backend timeouts instead of verified ones

- **What was done:** In the preceding reactive-sweep cluster
  (commits 6814461..31f6003), I dispatched an audit agent with
  ESTIMATED backend timeout tiers as guidance: `RADARE2=90s`,
  `GHIDRA=180s`, `SECURITY_SCAN=600s`. These were my best guesses
  from reading CLAUDE.md's env table plus pattern intuition.
- **Failure mode:** Rule-#29 research agent A (backend audit)
  verified the actual values in `config.py` and service code:
  `ghidra_timeout=300` (not 120 as the env table claimed),
  `radare2 communicate(timeout=120)` (not 30s worst-case as the
  comment claimed), `fuzzing_timeout_minutes=120` (= 7200s, vs
  the 600s I'd used). Three of my 4 picked tiers were WRONG at
  the ceiling, and the reactive sweep shipped 18 endpoints with
  wrong-sized timeouts. Ghidra decompile in particular — a user-
  facing interactive operation — would fake-fail on any binary
  that took 181-300s.
- **Evidence:**
  - `backend/app/config.py:24 ghidra_timeout: int = 300` (actual)
  - `CLAUDE.md` env table (prior): "GHIDRA_TIMEOUT: Decompilation
    timeout in seconds (default 120)" (stale — fixed in commit
    732d82f)
  - `frontend/src/api/analysis.ts:14` prior comment: "Ghidra
    decompilation takes 30-120 s per GHIDRA_TIMEOUT in config.py"
    (stale — fixed in a183e22)
  - My reactive-sweep commit 3c72a02 shipped `GHIDRA_ANALYSIS_TIMEOUT
    = 180_000` based on the stale 120s belief.
- **How to avoid:** When a CLAUDE.md env table or code comment
  cites a specific default value, **verify against the source** before
  building on it: `grep -n '<setting>' backend/app/config.py` +
  read the actual declaration. Env tables drift silently (the
  default changed from 120 to 300 at some uncertain point; nobody
  updated the docs; the reactive sweep then carried the drift into
  a worse place). Treat stale docs as a symptom: if you find one,
  cross-check everything else in the same table. For timeout work
  specifically, the backend service code is the ground truth, not
  the env table.

### 2. Shipping a Rule before its own code is rule-compliant

- **What was almost done:** I drafted Rule #29's body first, THEN
  realized the codebase violated it in 4 places. The natural path
  would have been to ship Rule #29 + backfill the fixes in a later
  session. That would have left CLAUDE.md saying "the codebase
  aligns timeouts via formula" while the code ran with 4
  misalignments.
- **Failure mode:** A rule that ships while its own current-code
  examples violate it undermines itself. Next author reads the
  rule, greps the codebase, finds `GHIDRA_ANALYSIS_TIMEOUT=180_000`
  when the formula says it should be 360_000, concludes either
  (a) the rule is aspirational / not actually enforced, or
  (b) the rule is wrong. Either way, the rule loses.
- **Evidence (averted):** Caught during rule drafting by the
  research-agent report. Commit `a183e22` fixed 2 of 4 in the same
  cluster; the remaining 2 (emulation, fuzzing) were documented
  as DEFERRED with specific reasoning about WHY they're deferred
  (require 202+polling refactor, not a constant edit). Rule #29
  now ships partly-enforced with a visible debt queue, not a
  silent self-contradiction.
- **How to avoid:** For any Rule adoption, the 5-step check:
  (1) Draft the rule body.
  (2) Apply it MECHANICALLY to the current codebase: grep/audit for
      sites that the rule would flag.
  (3) Fix what's cheap IN THE SAME CLUSTER.
  (4) Document what requires refactoring as DEFERRED in the rule body.
  (5) Only then commit the rule. If you skip (2)-(4), the rule's own
      counter-examples become trivia the next session has to discover.

### 3. Proliferating duplicate constants without a canonical owner

- **What was done:** Over the multi-session campaign, each API file
  that needed a 600s timeout added its own `const SECURITY_SCAN_TIMEOUT
  = 600_000` at the top of the file. By this session's Rule #29
  research: **8 files** defined the same constant with the same value.
- **Failure mode:** Drift waiting to happen. If a future tuning
  decision raises the tier to 900s (e.g. after a backend scanner's
  budget changes), 8 files must be manually edited. Miss even one
  and you have a silent tier split where some calls time out at 10
  min and others at 15 min. Worse: no obvious cross-reference —
  someone grepping for `SECURITY_SCAN_TIMEOUT` finds 8 identical
  definitions and has no way to tell which is canonical.
- **Evidence:** Rule #29 research agent B (frontend survey) found
  SECURITY_SCAN_TIMEOUT declared in: `files.ts`, `sbom.ts`,
  `attackSurface.ts`, `apkScan.ts`, `findings.ts`, `hardwareFirmware.ts`,
  `craCompliance.ts`, and one more via indirection in `analysis.ts`
  comment. Plus `UPLOAD_TIMEOUT` in 4 files (one inline in
  `exportImport.ts`).
- **How to avoid:**
  - The house-style convention (per Rule #29) is "one canonical
    definition in the owning file; all other files import it".
    For SECURITY_SCAN_TIMEOUT specifically, the owning file should
    probably be `findings.ts` (which defines the security-audit
    endpoint, the original motivator). But imports across API
    files add noise — arguably the cleanest solution is a
    `frontend/src/api/timeouts.ts` central file.
  - Future refactor: consolidate all tier constants into
    `timeouts.ts`. ~ 9 files touched (8 duplicate deletions + 1
    new file), low risk, ships a typecheck-verifiable
    single-source-of-truth. Captured in Rule #29 body as TODO.
  - For NEW tiers: ALWAYS put them in `timeouts.ts` from the
    start (once it exists), or in the file that owns the single
    endpoint they're used by. Never copy-paste a constant
    declaration between files.

### 4. Research-then-synthesize with no drift-check loop

- **What almost happened:** I could have synthesized the rule from
  just Agent A's backend audit — it had the 4 misalignments and the
  current backend values. Adding Agents B and C felt like overkill
  for "just write a rule". But Agent B surfaced the 8-file
  duplication that Agent A had no visibility into, and Agent C
  surfaced the Cloudflare 100s / Chrome 300s ceiling that would
  make the 600s tier unsafe under a proxy deployment.
- **Failure mode (averted):** Without Agent B, the rule would have
  codified "use SECURITY_SCAN_TIMEOUT" without acknowledging the
  drift risk — the rule would then recommend a pattern that's ALREADY
  showing maintenance strain. Without Agent C, the rule would have
  codified "600s is fine" without the "only safe same-origin; proxied
  deployments need 202+polling" caveat — the rule would then be
  wrong for the eventual production deployment topology.
- **How to avoid:** For quantitative rules, **three orthogonal axes
  of research** is the minimum bar:
  1. **What is the system's current ground truth?** (backend config,
     service-level declarations)
  2. **What does current user code look like?** (drift, duplication,
     magic numbers, scattered ownership)
  3. **What do upstream constraints say?** (library defaults, gateway
     limits, browser caps, industry convention)
  
  Skipping any one leaves the rule blind-spot. The 3-agent parallel
  dispatch amortizes the cost — each agent runs independently,
  returns in ~3-5 min, and the synthesis step has all 3 on the
  table at once.

## Not a failure this session (but worth noting)

### 5. Skill-suggestion spam for `/ouroboros:welcome` (4th consecutive session)

Same anti-pattern as sessions b56eb487 #2, 7e8dd7c3-handoff #3,
7e8dd7c3-timeout-sweep #3. Fired on each of the 3 research-agent
completions + the user's `/citadel:learn` invocation. Continued
ignoring. Upstream Citadel hook config issue; not a wairz fix.

### 6. Research agent A partially wrong about `radare2 aaa` unbounded

- Agent A reported "radare2 aaa has NO backend timeout (implicit /
  unbounded) at binary.py:1636-1637". Main session verified:
  `binary.py:1637` actually has `proc.communicate(timeout=120)` —
  the 120s is there, it was just on the `communicate()` call rather
  than wrapping the whole coroutine in `asyncio.wait_for`.
- Lesson: research-agent reports are data-points, not oracle
  truth. For claims that flip the rule's logic (e.g. "backend is
  unbounded" vs "backend is bounded at 120s"), spot-verify before
  committing.

## Cross-references

- Sibling patterns file: `wairz-rule29-timeout-alignment-research-2026-04-22-patterns.md`
- Preceding (reactive) cluster antipatterns: `wairz-frontend-axios-timeout-sweep-2026-04-22-antipatterns.md`
- Rule #29 in CLAUDE.md (line 194)
- Rule #21 (CLAUDE.md + mex mirror discipline) — exercised cleanly
  this cluster
