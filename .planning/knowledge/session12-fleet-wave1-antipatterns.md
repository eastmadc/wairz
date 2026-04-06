# Anti-patterns: Session 12 — Fleet Wave 1 + RTOS Research

> Extracted: 2026-04-06
> Campaign: .planning/fleet/session-option-a-wave1.md

## Failed Patterns

### 1. Trusting Intake Plans as Source of Truth
- **What was done:** Initial planning assumed intake plan descriptions reflected current code state (e.g., "Binary Diff Phase 1 not started", "CVE Triage needs expandable rows").
- **Failure mode:** Deep research revealed these features were already substantially implemented in Session 11. Would have spawned redundant build agents.
- **Evidence:** SbomPage.tsx (1,366 lines with full VEX triage), ComparisonPage.tsx (834 lines with clickable function diffs) — both fully implemented but intake plans not updated.
- **How to avoid:** Always run codebase audit (grep/read actual files) before trusting .planning/intake/ descriptions. Update intake plans after each session's work.

### 2. Ouroboros MCP Interview from Agent Context
- **What was done:** Attempted to use `mcp__plugin_ouroboros_ouroboros__ouroboros_interview` tool to start a Socratic interview for RTOS requirements.
- **Failure mode:** Tool requires Claude Code subprocess which isn't available from within an agent context (claudecode_present: False). Also tried CLI `ouroboros interview` which turned out to be `ouroboros init` (different command name).
- **Evidence:** Error: "Claude Agent SDK request failed: Command failed with exit code 1"
- **How to avoid:** Use AskUserQuestion for interactive requirements gathering within sessions. Reserve Ouroboros interviews for standalone invocations from the top-level CLI.

### 3. Campaign Files Not Updated After Work
- **What was done:** Session 11 completed Binary Diff, CVE Triage, SSE Event Bus, CycloneDX HBOM, but campaign/intake files still showed "pending" or "not started."
- **Failure mode:** Stale planning artifacts caused confusion during Session 12 planning. 30+ minutes of research could have been saved.
- **Evidence:** binary-diff-enhancement.md showed "Phase 1, Sub-step: not started" when LIEF + Capstone were fully integrated.
- **How to avoid:** At session end, always update campaign status and intake plan status. Mark completed items explicitly.
