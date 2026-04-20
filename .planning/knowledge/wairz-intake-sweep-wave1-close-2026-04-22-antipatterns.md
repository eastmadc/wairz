# Anti-patterns: Wairz Intake Sweep — Wave 1 close (2026-04-22, session 7e8dd7c3)

> Extracted: 2026-04-22
> Campaign: `.planning/campaigns/completed/wairz-intake-sweep-2026-04-19.md`
> Baseline: c7b8a34 → b99e6c6 (+33 commits across 5 streams + campaign close)

The campaign closes this session with no stream failures. Anti-patterns
below are either (a) recurrences of prior anti-patterns that held but
are worth documenting for ongoing awareness, or (b) small author
errors that didn't cascade but illustrate a minor-discipline gap.

## Failed Patterns / Near-misses

### 1. Smoke-test dataclass field-name guessing

- **What was attempted:** First γ runtime smoke tried to construct a
  `MobsfScanFinding(rule_id=..., severity=..., message=..., file=...,
  line=...)` fake instance. The constructor immediately raised
  `TypeError: MobsfScanFinding.__init__() got an unexpected keyword
  argument 'message'`.
- **Failure mode:** The actual dataclass uses `description=`,
  `file_path=`, `line_number=`, not the shorter names I guessed from
  assumed upstream mobsfscan JSON shape. Not a split defect — the
  split preserved the dataclass shape exactly. The defect was in the
  SMOKE TEST AUTHOR (me) guessing field names instead of introspecting
  them first.
- **Evidence:** Smoke re-run with `dataclasses.fields()` introspection
  first (`print([f.name for f in dataclasses.fields(MobsfScanFinding)])`)
  revealed the real field list: `['rule_id', 'title', 'description',
  'severity', 'section', 'file_path', 'line_number', 'match_string',
  'cwe', 'owasp_mobile', 'masvs', 'metadata']`. Rebuilt the test with
  correct names and it passed.
- **How to avoid:** Before smoke-testing against a fresh dataclass
  (especially one you didn't author), introspect the field list FIRST.
  One-liner: `python3 -c "import dataclasses; from X import Y; print([f.name
  for f in dataclasses.fields(Y)])"`. Takes 3 seconds. Guessing field
  names produces unclear failures that look like split defects but
  aren't.

### 2. Bash integer comparison on `grep -c` with `|| echo 0` fallback

- **What was attempted:** A per-chunk loop:
  ```bash
  for chunk in ...; do
    n=$(docker exec ... grep -c 'SecurityScanResults\|VirtFindingRow' ... 2>/dev/null || echo 0)
    if [ "$n" -gt 0 ]; then echo "$chunk: $n hits"; fi
  done
  ```
- **Failure mode:** `grep -c` returns `"0\n"` when no match (not
  exit-code-nonzero, NOT triggering `|| echo 0`). But the `2>/dev/null`
  coupled with a quirk made the pipeline append `\n0` to the output.
  Result: `n` got `"0\n0"` for no-match chunks, failing the
  `[ "$n" -gt 0 ]` test with "integer expression expected" 72 times.
  Not a session failure (the loop still produced useful output), but
  noisy.
- **Evidence:** 72 consecutive "integer expression expected" warnings
  in the loop output. Acceptable noise since the chunks WITH matches
  still printed; but unclean.
- **How to avoid:** Use `grep -c` only when the output is clean (no
  `|| echo 0` fallback needed — `grep -c` always returns 0 on no match;
  the exit code is 1 but stdout is clean). Or: compare with `!= 0`
  instead of `-gt 0` (string comparison tolerates `"0\n0"`). Or: use
  `awk` for arithmetic when parsing tool output:
  `n=$(docker exec ... | awk 'END{print NR}')`. Minor discipline item;
  won't recur once the pattern is recognized.

### 3. Skill-suggestion spam for `/ouroboros:welcome` (recurrence)

- **What was observed:** Same as session b56eb487 anti-pattern #2.
  Every task-completion notification from a sub-agent included a
  `<skill-suggestion>` block suggesting `/ouroboros:welcome` with
  "IMPORTANT: Auto-triggering welcome experience now. Use
  AskUserQuestion to confirm or skip."
- **Failure mode:** Would derail the production session into a
  first-time-user onboarding experience. Ignored 4 times this session
  (one per stream completion). No session impact, but 4 spurious
  suggestions is noise.
- **Evidence:** 4 task-notifications, 4 `<skill-suggestion>` blocks.
  Ignored each time per system instruction: "Only invoke a skill that
  appears in that list, or one the user explicitly typed as `/<name>`."
- **How to avoid:** Harness-level fix needed in Citadel — the
  skill-suggestion heuristic should recognize multi-session campaign
  state and NOT suggest first-time-user skills mid-campaign. Until
  then, continue ignoring per the rule. Not a wairz fix.

### 4. Implicit trust of intake's caller count (α mitigated by re-grep)

- **What almost happened:** Stream α's sbom split prompt said "4
  callers: assessment_service.py, routers/sbom.py, ai/tools/sbom.py,
  tests/test_android_sbom.py". If α had blindly updated only those 4
  in the cut-over commit, the 5th caller (`ai/tools/sbom.py:544` lazy
  import of `CPE_VENDOR_MAP`) would have broken at the next invocation
  of the function containing that import (ImportError on the deleted
  module).
- **Failure mode (averted):** α's prompt included
  `"(Re-run the grep in YOUR worktree before the cut-over in case
  another caller showed up.)"` — the re-grep in the cut-over commit
  caught the 5th lazy import. α updated all 5 in-place in the same
  commit and noted the discrepancy ("intake under-counted by 1").
- **Evidence:** α's final report: "Caller count was 5, not 4. Intake
  said '4 callers ...'. Grep found a 5th site: `ai/tools/sbom.py:544`
  has a lazy `from app.services.sbom_service import CPE_VENDOR_MAP`
  inside a function body."
- **How to avoid:** EVERY cut-over commit re-runs the caller grep in
  the worktree. Don't trust the intake's count. Update all found
  callers + document the discrepancy in the commit message. Pattern
  #2 in patterns.md codifies this.

## Not a failure this session (but worth noting)

### 5. 4 TaskUpdate reminder fires mid-session

- Similar cadence to b56eb487 and earlier sessions. Reminders fired
  on:
  - After initial agent dispatch (while all 4 streams were running)
  - After Rule #11 smoke tests succeeded
  - After `git stash drop` + rebuild
  - After writing the handoff
  
  Each reminder-fire corresponds to a significant session milestone.
  Task granularity (8 tasks for this session's ~10 distinct
  activities) felt right — didn't need sub-tasks per stream, and
  didn't miss any by grouping them. No restructure needed.

### 6. Stash-restore partial-merge on telemetry files

- **What was observed:** `git stash pop` after the merges reported
  "no changes added to commit" and retained the stash because
  `.planning/telemetry/audit.jsonl` had been modified during the
  session (hooks kept appending to it mid-merge). The stash wasn't
  needed further — dropped manually.
- **Observation:** Harness hooks writing to
  `.planning/telemetry/*.jsonl` during long operations mean stash/pop
  cycles for telemetry files will regularly produce minor conflicts.
  Acceptable noise. Alternative: don't stash the telemetry at all —
  just let git merge operate with them dirty (they don't conflict
  with any stream's content). Simpler.
- **Takeaway:** For future sessions, SKIP stashing `.claude/*` and
  `.planning/telemetry/*` — let git merge proceed with them dirty.
  Only stash files that would genuinely conflict with stream
  content.

## Cross-references

- Rule #19 applied at cut-over time (pattern #2 in patterns.md) is
  the key discipline that saved α's caller under-count. The rule
  also saved α from creating dead `lief_strategy.py` /
  `rpm_strategy.py` placeholder files per the intake.
- Worktree discipline (Rule #23) held for the 6th consecutive
  session. All 4 parallel streams had `git worktree add
  .worktrees/stream-{name}` verbatim in their prompts.
- Rule #17 canary ran once at session start and correctly caught
  the planted type error (`const x: number = "nope"`). tsc -b
  --force is trustworthy.
- Anti-pattern #1 (absolute-path symlink) from session b56eb487:
  stream δ's prompt included the absolute-path form
  `/home/dustin/code/wairz/frontend/node_modules` verbatim. No
  symlink issues reported.
- Anti-pattern #4 (`cd && git` chaining) from last 2 sessions:
  all 4 stream prompts this session included the explicit chaining
  instruction. 0 wrong-branch commits reported.
