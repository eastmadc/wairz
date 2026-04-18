# Patterns: mex Adoption — Complementarity Reframe (2026-04-18)

> Extracted: 2026-04-18
> Campaign: not a registered campaign — single-commit adoption (60c9af2)
>   in session 59045370
> Trigger: user pushback on the initial "delete .mex/" recommendation,
>   asking instead "adopt and use alongside citadel, they're
>   complementary; deep research"
> Prior /learns this session:
>   1. autopilot-seed-option-a-2026-04-18-patterns.md (6415d62)
>   2. unpack-escape-symlink-fix-2026-04-18-patterns.md (c736bf7)
>   3. deployment-loop-closure-2026-04-18-patterns.md (11a88c3)
> Postmortem: none

## Successful Patterns

### 1. Revisit a dismissed idea with a sharper question

- **Description:** First-pass diagnosis of `.mex/` listed
  overlap-with-Citadel points and recommended deletion. User pushed
  back with "they're complementary". Re-read the same files looking
  for *where each owns a concern*, not *what's duplicated*. Found
  the forward/backward temporal axis: Citadel extracts patterns from
  completed work (`/learn`), mex prescribes steps for future tasks
  (`ROUTER.md → patterns/INDEX.md`). Different tense, different job.
- **Evidence:** First response argued three deletion options. Second
  response delivered an integration plan that preserved both systems
  and added Rule 21 to keep them in sync. The content of `.mex/` did
  not change between reads — the analysis frame did.
- **Applies when:** Any "this looks redundant, remove it" conclusion.
  Before executing deletion, ask: "what axis am I comparing along,
  and is there another axis where these are orthogonal?" Redundancy
  is frame-dependent. Two files can say similar things and still
  have distinct jobs if they're read at different times.

### 2. Seam analysis before integration

- **Description:** Built an explicit table (Citadel owns / mex owns /
  shared via) BEFORE writing any integration code. Each concern
  (learned rules, verify checklist, task navigation, extracted
  patterns, orchestration, regex gates, campaigns) got one owner
  and a named sync contract. This exposed Rule-21-shaped drift
  risk (CLAUDE.md rules vs. mex conventions checklist) while the
  table was still a draft.
- **Evidence:** The complementarity-matrix markdown table in the
  response enumerates 9 concerns with owners; commit 60c9af2 named
  the drift risk explicitly in the commit message ("two-file-one-
  truth failure mode is the most predictable drift risk").
- **Applies when:** Integrating two systems that will coexist over
  time. The table forces "who owns X?" decisions up front; adopting
  blindly and letting ownership emerge yields the worst drift.

### 3. Refresh before adoption, not after

- **Description:** `.mex/ROUTER.md` had "Current Project State"
  frozen at 2026-04-17: 15 rules (actual: 21), listed
  `analysis_cache.operation VARCHAR(100)` as a known issue (fixed
  4 hours earlier in commit e3053b6), and missed 4 deliverables
  from the same session. Committing it as-is would have encoded
  stale state for another 30+ hours until the next `/learn` noticed.
  Adoption commit refreshed ROUTER.md state AND the Verify Checklist
  in the same change.
- **Evidence:** commit 60c9af2 diff includes both the .mex/ file
  additions (previously untracked) AND targeted edits to ROUTER.md
  state + conventions.md checklist — one commit, consistent state.
- **Applies when:** Adopting / importing existing documentation into
  a repo. "Commit as-is, refresh later" is cheap to defer but expensive
  to repay — readers treat freshly-committed files as authoritative.

### 4. Institutionalize sync with a Rule, not a hope

- **Description:** The two files holding learned rules (CLAUDE.md
  canonical, `.mex/context/conventions.md` derived gate) have a
  known drift failure mode: rule 21 lands in CLAUDE.md, conventions
  checklist doesn't update, the next mex-driven task runs without
  that gate. Rather than rely on discipline, added CLAUDE.md Rule 21
  that explicitly pairs them — the rule is the mechanism. Also
  companion: when ROUTER.md state is stale, its stale lines become
  traps for the next session, so sync discipline extends there too.
- **Evidence:** Rule 21 wording names "same commit", "both wording
  and numbering changes", and extends the sync rule to ROUTER.md
  state as a companion lesson.
- **Applies when:** Two-file-one-truth architectures. If the sync
  isn't automatic (regenerated from one source), it must be named as
  a rule. Verbal commitments to "remember to sync" decay within
  3 sessions. Regex enforcement in harness.json is stronger still,
  but only works when the drift has a code-shape signature —
  prose-to-prose drift needs a rule.

## Avoided Anti-patterns

### 1. Reflexive "untracked = dead, delete it"

- **What almost happened:** First response offered three options with
  "delete outright" as the recommended path. Evidence was
  procedural (untracked, no CLI installed, zero hooks reference it),
  not substantive (the content itself was high-quality and
  non-overlapping in role).
- **Failure mode:** Deleting a well-authored scaffold because it
  failed the "is anything calling it?" check without asking "is the
  content itself useful?" The content files (architecture, stack,
  conventions, decisions, mcp-tools, patterns/*) are ~1500 lines of
  dense, project-specific guidance that would have been lost.
- **Evidence:** The user's pushback prompted a content re-read that
  revealed the forward-task-navigation role. Had the initial
  recommendation been executed, recovering from git would have been
  possible but awkward.
- **How to avoid:** When a directory is untracked and "unused" by
  automation, read its content before recommending deletion. Ask:
  "if this were committed, would it be valuable reference material?"
  An unused but valuable file is a bug to fix (track it, wire it in);
  an unused and valueless file is a bug to delete.

### 2. Adopting a scaffold as-is without refreshing stale claims

- **What almost happened:** Could have done a bare `git add .mex/ &&
  git commit -m "adopt mex"` and called it done. The committed state
  would have said "15 learned rules" when the repo is at 21; would
  have listed a bug that was fixed hours earlier as open.
- **Failure mode:** Freshly-committed files read as authoritative.
  The next agent reading `.mex/ROUTER.md` would have believed the
  stale known-issues list and possibly duplicated work on the
  already-fixed VARCHAR issue.
- **Evidence:** Adoption commit 60c9af2 included 4 targeted edits
  alongside the file tracking — not just `git add .mex/`.
- **How to avoid:** Adoption-of-existing-content is never just
  `git add`. Diff the content against current reality first; refresh
  what's stale; commit the refreshed state. The extra 10-20 minutes
  is cheap insurance against "authoritative-but-wrong" reads.

## Key Decisions

| Decision | Rationale | Outcome |
|---|---|---|
| Keep CLAUDE.md canonical for learned-rule content; `.mex/context/conventions.md` Verify Checklist is derived | Avoids the "two sources of truth" problem; derived is easier to regenerate than reconcile | Rule 21 formalizes the sync; content + numbering match at commit time |
| Adopt `.mex/` without the accompanying `mex` CLI or `setup.sh`/`sync.sh` | The content files stand alone as reference docs; CLI install is a separate tool decision | Smaller adoption surface; no CLI dependency |
| Add CLAUDE.md pointer to `.mex/ROUTER.md` but don't force session-bootstrap reading | Discovery over mandate; CLAUDE.md is auto-loaded, requiring additional mandatory reads dilutes attention | Pointer + companion-scaffold section; agents reach mex when starting a specific task |
| Refresh ROUTER.md state (rule count, known issues, deliverables) AS PART OF adoption commit, not a follow-up | Fresh-commit-stale-state is a trap; one commit = one consistent state | Adoption commit 60c9af2 has 4 in-file edits alongside the 19 file additions |
| Don't port `.planning/knowledge/*-patterns.md` into `.mex/patterns/*.md` during adoption | Different shapes (historical vs. prescriptive) serve different use cases; one-off ports are healthier than blanket migration | Two parallel pattern systems with different timestamps + different purposes |

## Quality Rule Candidates

None reach medium confidence.  The drift risk for Rule 21 has an
obvious signature (CLAUDE.md rules list edited without a same-commit
edit to `.mex/context/conventions.md`), but it's a *missing-edit*
predicate, not a *bad-shape* predicate — harness rules detect shapes
in files, not absences-across-files.  A git pre-commit hook or a
session-end check would be the right enforcement mechanism if the
discipline decays in practice.

If `/citadel:learn` post-hoc starts flagging "rule added but
conventions.md not updated" as a recurring signature over 2-3
sessions, convert it to a hook then.
