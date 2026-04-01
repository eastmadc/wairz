# PR Quality Standards

> Extracted: 2026-03-31
> Source: Session learnings from PRs #16-#21

## Problems Observed

### PR #16 — Too Large
- 44 files, 1200+ lines changed, mixed concerns (security + performance + cleanup + frontend)
- Reviewer has to context-switch between Python backend, TypeScript frontend, Docker infra, and shell scripts
- A single "request changes" blocks the entire PR including unrelated fixes
- Title had a line break from copy-paste (`fix:\n  address 58...`)

### PRs #17-#20 — Better Scoped but Sparse Descriptions
- Body was a single sentence each
- No context on WHY the change was needed
- No test plan
- No before/after or metrics

## Standards Going Forward

### PR Sizing Rules
1. **One concern per PR.** Security fixes, performance fixes, cleanup, and features are separate PRs.
2. **Max 10-15 files per PR.** If it touches more, it's probably multiple PRs.
3. **If a fleet campaign produces 3 waves, consider 3 PRs** — one per wave, or group by domain.
4. **Stacked PRs for dependencies.** PR D (arq) depends on PR C (Redis) — use base branch targeting.

### PR Title Format
```
<type>: <concise description under 70 chars>
```
Types: `fix`, `feat`, `refactor`, `test`, `docs`, `infra`, `perf`

No line breaks. No trailing periods.

### PR Description Template
```markdown
## Summary
<2-3 sentences: what changed and WHY>

## Motivation
<What problem does this solve? Link to issue if applicable.>
<Evidence: metrics, error logs, review findings, infra-audit output>

## Changes
<Bulleted list of specific changes, grouped by file/area>

## Testing
<How was this tested? What commands were run?>
- [ ] Tests pass: `pytest tests/ -v`
- [ ] Build passes: `docker compose up --build`
- [ ] Manual verification: <specific steps>

## Risks & Rollback
<What could go wrong? How to revert?>
<For infra changes: backward compatibility notes>

## Dependencies
<Other PRs that must merge first, or that depend on this one>
```

### Content Quality Checklist
- [ ] PR title is under 70 chars, no line breaks
- [ ] Body explains WHY, not just WHAT
- [ ] Each file change has a reason — no drive-by fixes
- [ ] Test plan includes specific commands, not just "run tests"
- [ ] Dependencies between PRs are documented
- [ ] No local config files (CLAUDE.md, .claude/, .planning/) included
- [ ] Commits are atomic — each could be reverted independently

### Scope Guidelines by Type
| Type | Ideal Size | Example |
|---|---|---|
| Security fix | 1-5 files, single vulnerability class | Auth bypass on emulation endpoints |
| Performance fix | 1-3 files, single bottleneck | Connection pool configuration |
| Dependency swap | 1-2 files | requests → httpx |
| New feature | 5-15 files, one capability | Redis cache layer |
| Refactor | 5-10 files, one extraction | Shared deps.py from 6 routers |
| Test addition | Test files only, no source changes | 89 tests for security code paths |

### How to Apply
- **Before starting a fleet campaign:** Plan PR boundaries. Each wave or domain = one PR.
- **Before committing:** Run `git diff --stat` and ask "would I want to review this as one PR?"
- **Before pushing:** Write the PR body FIRST (in `.planning/pr-body.md`), then push. The description forces you to articulate scope.
- **After pushing:** Review your own PR on GitHub before requesting review. Catch formatting issues, scope creep, stray files.
