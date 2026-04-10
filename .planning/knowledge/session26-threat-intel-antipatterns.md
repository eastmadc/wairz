# Anti-patterns: Session 26 — Threat Intelligence Phases 4-5

> Extracted: 2026-04-10
> Work: abuse.ch suite + CIRCL Hashlookup integration

## Failed Patterns

### 1. Declaring work complete without updating plans
- **What was done:** Built and deployed Phases 4-5, verified tests pass, but initially forgot to update the master plan (next-session-plan.md) with S26 handoff and update intake plan statuses.
- **Failure mode:** Stale intake queue — 12 of 15 items appeared "pending" despite being completed sessions ago.
- **Evidence:** User feedback: "don't forget to update plans and completed items and next steps"
- **How to avoid:** Definition of done includes: (1) update relevant plan-*.md status, (2) write handoff in next-session-plan.md, (3) note what to do next. Saved as feedback memory.

### 2. Not updating S25 handoff in master plan
- **What was done:** S25 work (CI/CD SARIF, ClamAV, VirusTotal, E2E tests) was committed but no handoff was written in next-session-plan.md. The most recent handoff was S24.
- **Failure mode:** Gap in session history makes it harder to understand what happened between S24 and S26.
- **Evidence:** Master plan jumped from S24 to S26 handoff — had to reconstruct S25 from git log.
- **How to avoid:** Every session that produces a commit should also produce a handoff block, even if it's brief.
