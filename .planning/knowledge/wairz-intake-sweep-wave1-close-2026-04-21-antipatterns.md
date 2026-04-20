# Anti-patterns: Wairz Intake Sweep — Wave 1+2 close (2026-04-21, session b56eb487)

> Extracted: 2026-04-21
> Campaign: `.planning/campaigns/wairz-intake-sweep-2026-04-19.md`
> Baseline: 4f6d47e → 83acb9d (+35 commits across 4 streams)

## Failed Patterns / Near-misses

### 1. Trusting the intake scanner's "pending" list without Rule-19 audit

- **What was attempted:** The session-start intake scanner listed 12
  "pending" items. The dispatch prompt said to dispatch Wave 1 with 3
  streams (data-constraints, frontend-code-splitting,
  infra-cleanup-orphan-reaper) based on that list.
- **Failure mode:** Rule-19 pre-flight probe showed:
  - `data-constraints-and-backpop`: all 4 CHECK constraints + 2 UNIQUE
    constraints + 2 missing indexes + all 5 Project back_populates
    ALREADY LIVE in production DB.
  - `infra-cleanup-migration-and-observability`: all 7 cron jobs
    registered, including the orphan-reaper variants the prompt asked
    me to add.
  - `frontend-code-splitting-and-virtualization`: V1 fully shipped (15
    `React.lazy` in App.tsx); V2 partially shipped (SbomPage + FindingsList
    virtualized).
- **Evidence:** 3 minutes of shell probes (`SELECT conname FROM
  pg_constraint ...`, `grep -c 'React.lazy' App.tsx`, `grep 'cron('
  arq_worker.py`) showed 2 of the 3 prompt-suggested streams were
  entirely phantom work. Without this probe, I would have dispatched
  3 sub-agents to re-implement 50%+ of what was already in production.
- **How to avoid:** ALWAYS run a Rule-19 evidence probe before
  dispatching sub-agents, even (especially) when the dispatch prompt
  seems authoritative. Dispatch prompts capture intent at write-time;
  they can be stale by execution time. The probe takes 1-3 minutes and
  can cut a session's scope in half. This generalizes to any campaign
  that spans multiple sessions — state drifts, intakes age, work gets
  silently shipped from adjacent streams. The scanner's `status: pending`
  regex is a lagging indicator of reality.

### 2. "Skill-suggestion" spam for `/ouroboros:welcome` during mid-campaign dispatch

- **What was observed:** Every task-notification from a sub-agent
  completion included a `<skill-suggestion>` block suggesting
  `/ouroboros:welcome` with "IMPORTANT: Auto-triggering welcome
  experience now. Use AskUserQuestion to confirm or skip."
- **Failure mode:** Would have derailed a production campaign session
  into a first-time-user onboarding experience. The Ouroboros welcome
  skill is for NEW Ouroboros users; this user has been running
  multi-session Citadel+Ouroboros campaigns for months. The suggestion
  heuristic is misfiring.
- **Evidence:** 4 task-notification events this session, each with the
  same `<skill-suggestion>` block. Ignored in all 4 cases per system
  instruction: "Only invoke a skill that appears in that list, or one
  the user explicitly typed as `/<name>` in their message."
- **How to avoid:** Ignore skill-suggestion blocks that don't match the
  user's current intent. The suggestion heuristic doesn't have full
  session context; it sees an agent-completion notification and fires
  on partial signals. Don't call AskUserQuestion for skill suggestions
  mid-campaign.
  (Candidate fix: the skill-suggestion hook should check campaign state
  / session history before suggesting first-time-user skills. Not a
  wairz change — it's a Claude Code / Citadel hook issue. Noted here for
  future session-level awareness.)

### 3. Using `| tail -15` on a `git diff --stat` output with exactly 16 files

- **What was attempted:** `git diff c8718d9..feat/stream-delta-security-audit-split-2026-04-21
  --stat 2>&1 | tail -15`
- **Failure mode:** Truncated the first line of the stat output. The
  diff showed 16 files; `tail -15` dropped the first file (`backend/app/routers/security_audit.py`)
  AND the summary footer. Near-miss — I had to re-run with `head -20`
  to see the full stat. Could have led to a false "missing caller
  update" alarm if I'd acted on the truncated output.
- **Evidence:** Two consecutive bash calls for the same diff; second
  call used `head -20` and revealed the missing router file.
- **How to avoid:** For `git diff --stat` or any columnar output where
  you don't know the line count, prefer `head -N` with N generous OR
  drop the pagination entirely. `git diff --stat` shows a summary line
  at the bottom ("X files changed, ..."); truncating from the top
  drops individual files silently. When you know row count might be
  near your `tail` window, use `head` or no pagination.

### 4. Almost overlooking that δ's merge requires Rule #8 rebuild

- **What almost happened:** After δ's agent completed, I initially
  considered merging and immediately moving to session-end work (handoff
  + /learn). The δ agent's report explicitly called out "Rule #8 rebuild
  is REQUIRED before live backend trust — module locations of
  SecurityFinding, SCANNERS, all scanner functions changed."
- **Failure mode (averted):** Had I skipped the rebuild, the running
  backend container would have continued serving the pre-merge code
  (the `security_audit_service.py` module that no longer exists on
  main). The next `docker compose restart backend` (or next boot) would
  have failed to start: Python import errors on the deleted module
  path, 503s, missing routers. Would only surface at the next
  session's verification gate with a puzzling "works at HEAD but boots
  fail" symptom.
- **Evidence:** δ's agent report flagged "Rule #8 rebuild REQUIRED"
  in bold; I followed through immediately post-merge. Post-rebuild
  verification confirmed: `from app.services.security_audit import ...`
  works, `run_security_audit()` returns valid ScanResult, MCP 172-tool
  invariant held.
- **How to avoid:** Read the agent report's "Notes for merge" section
  BEFORE the `git merge` command. If it says "Rule #8 rebuild REQUIRED",
  chain the rebuild immediately after the merge in the same bash call
  sequence. Don't trust the running containers to keep working across
  a module-deletion merge — they can be serving stale code until the
  next restart exposes the missing module.

## Not a failure this session (but worth noting)

- **Multiple TaskUpdate reminders fired.** Agent responded each time by
  updating task status. The reminder firing rate (every 5-10 minutes
  per task-completion notification) suggests the TaskList granularity
  could be finer (1 task per sub-agent dispatch + 1 per merge + 1 per
  verification gate = ~12 tasks for a 4-stream session instead of the
  5 I used). Not worth restructuring retroactively; noted for next
  session.
- **γ's `docker cp` transient state is NOT a pattern to promote.**
  While it worked (caught the xml.etree import bug before merge), the
  discipline question is: should agents run Rule #11 smoke tests
  BEFORE their branch is merged? γ said yes because the split was big
  and the risk of a post-merge blow-up was material. δ said no (local
  py_compile only, let main session do the smoke post-merge). Both
  worked. The `docker cp` approach is CLAUDE.md Rule #20 territory —
  it's a validation-speed tool, not a durable state. If an agent uses
  it, the agent's report must explicitly say "post-merge rebuild is
  REQUIRED" so the main session doesn't assume the transient state
  persists.

## Cross-references

- Rule #19 (evidence-first) paid off MASSIVELY this session. The initial
  3-minute probe saved ~3 hours of phantom re-work that would have
  shipped 10-15 commits re-doing production-live features. Worth
  elevating to a Rule #19a: "At the start of any multi-item session,
  probe the live system against each intake's acceptance criteria
  BEFORE dispatching agents. Budget 2-5 minutes per item for the
  probe."
- Anti-pattern #1 (absolute-path symlink) from last session: ALL agent
  sub-prompts this session included the absolute-path form verbatim.
  No symlink issues reported. Discipline held.
- Anti-pattern #4 (`cd && git` chaining) from last session: ALL agent
  sub-prompts included the explicit chaining instruction. 0
  wrong-branch commits reported.
- Anti-pattern #2 (per-chunk bundle verification) from last session:
  Main-session post-β-rebuild verification used the per-chunk loop
  from the start. 3 target pages verified in parallel; no false "stale
  bundle" alarms.
