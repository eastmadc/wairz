# Proposal: Citadel `protect-files.js` hook — append-only exception for `/learn`

> Created: 2026-04-19 (session 435cb5c2)
> Audience: Dustin (Citadel harness maintenance)
> Severity: LOW-urgency, 3-session-durable friction

## Observed behaviour (session 435cb5c2)

- `/home/dustin/code/wairz/.claude/harness.json` is listed in `protectedFiles: [".claude/harness.json"]` at line 111-113 of that file.
- Every attempted `Edit` or `Write` against `.claude/harness.json` triggers `PreToolUse:Edit hook error: [node /home/dustin/code/Citadel/hooks_src/protect-files.js]: No stderr output` and the operation is blocked.
- Reading `/home/dustin/code/Citadel/hooks_src/protect-files.js` is ALSO blocked (self-protecting). Cannot introspect the hook's current logic from the wairz side.
- Four quality rules now pending manual adoption across three sessions (69f004fe, B.1, 435cb5c2): `auto-intake-sweep-1-no-docker-stat-sock`, `auto-intake-sweep-1-no-docker-from-env`, `auto-intake-sweep-wave12-tsc-noemit-broken`, and the self-referential `auto-fleet-worktree-requires-branch-checkout` + the harness.json `typecheck.command` fix (`npx tsc --noEmit` → `npx tsc -b --force`).

## Why it matters

`/learn` is designed to append learned quality rules into `.claude/harness.json::qualityRules.custom`. Blocking this defeats the skill's primary write path. The pattern is:
1. Session completes with anti-patterns observed.
2. `/learn` extracts candidate rules.
3. Rules must be manually copy-pasted by the user — which gets skipped session-over-session, so rules rot into documentation-only state.

## Proposed exception

Add an APPEND-ONLY allowlist to `protect-files.js` that permits Edits/Writes to `.claude/harness.json` if and only if the diff satisfies ALL of:

1. **Structural invariant:** the diff adds elements to `qualityRules.custom` (JSON array) and touches no other top-level key. Parse JSON before and after; compare.
2. **Schema invariant:** each added element has exactly the shape `{name: string, pattern: string, filePattern: string, message: string}` — no extra keys, no missing keys, all strings non-empty.
3. **Name uniqueness:** each added element's `name` does not already exist in `qualityRules.custom`. (The existing `/learn` Step 5 dedupe already handles this; belt-and-braces.)
4. **Name namespace:** optionally, restrict to names matching `^auto-[a-z0-9-]+$` to prevent arbitrary rule insertion.

If all four pass → allow. Any other modification → block (preserve current behaviour).

### Optional additional permissive path

Allow `typecheck.command` updates where the NEW value is in an allowlist of known-good commands — e.g., `["npx tsc -b --force", "npx tsc --noEmit", "yarn typecheck", "pnpm typecheck"]`. This addresses the secondary known defect (stale `npx tsc --noEmit` at line 6 of wairz's harness.json).

## Rationale

- `qualityRules.custom` is the specific field `/learn` writes to. Limiting the exception to that field preserves the protection against harness-level tampering (protectedFiles allowlist, trust settings, registeredSkills list, etc. remain immutable via direct edit).
- Schema validation prevents the exception from being abused to inject arbitrary JSON.
- Append-only (not modify-existing) means the exception can never remove a rule or change an existing rule — just add. Removal stays a manual operation.
- Namespace prefix `auto-` matches the convention already visible in wairz's current 17 rules.

## Alternative fixes (less effort, less leverage)

1. **Manual periodic sync:** Dustin copy-pastes pending rules from `.planning/knowledge/*-antipatterns.md` every N sessions. Carries the ongoing tax we see now.
2. **Per-project bypass file:** `.claude/harness.override.json` that `/learn` writes to; a separate tool merges into harness.json. Adds a file, doesn't solve the fundamental block.
3. **Move rules to CLAUDE.md permanently:** promote the 3 session-435cb5c2 rules as Learned Rules #23/#24/#25 (done this session). This is documentation-as-enforcement via agent discipline, not auto-blocking at edit time. The hard-gate via harness.json quality rules is strictly stronger — a rule in CLAUDE.md must be remembered; a rule in harness.json fires automatically.

## Test plan (if implementing)

1. Valid append (name matches `auto-*`, shape correct, new name): should succeed.
2. Name collision (append with existing name): should block.
3. Adds extra key to added rule (e.g., `severity: "high"`): should block.
4. Modifies any other top-level key (e.g., adds to `protectedFiles`): should block.
5. Bulk delete of existing rules: should block (modifying existing array elements).
6. Reorders rules: should block (changes existing elements' order/shape).

Use wairz's existing harness.json as the fixture; exercise each case against a copy.

## Out of scope for this proposal

- Generalising to other protected files (harness.json is the only file needing this today).
- Rule removal / modification (keep manual).
- Rule-content validation (regex validity, message non-triviality) — layer that separately if `/learn` grows more write paths.

## Decision gate

Dustin: approve or reject before session X+2 (if still applicable by then). If rejected, alternative #3 (promotion to CLAUDE.md) already shipped this session — harness-level rules for Phase 1 + Wave 1+2 remain stuck but conventions are at least visible in the Learned Rules list and mex `.mex/context/conventions.md` Verify Checklist.
