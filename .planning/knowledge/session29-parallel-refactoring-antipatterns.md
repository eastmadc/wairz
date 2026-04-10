# Anti-patterns: Session 29 — Parallel Visual Polish + Review Backlog

> Extracted: 2026-04-10
> Work: ThreatIntelTab polish, R4 Error Boundary, R5 config centralization, R7 pagination, R10 firmware dedup

## Failed Patterns

### 1. Running backlog items without current-state research
- **What was done:** The review backlog (R1-R10) was written months ago with specific line counts. R1 was "1637 lines", R3 was "593 lines".
- **Failure mode:** Without research, we would have trusted stale numbers. Actual: R1=1816 (+11%), R3=710 (+20%). The effort estimates and risk levels were outdated. R3 in particular grew 20% and is now more urgent than when flagged.
- **Evidence:** Explore agent found all line counts had drifted. R3's growth from 593→710 would have been invisible without re-assessment.
- **How to avoid:** Always re-measure files before acting on backlog items. Line counts in planning docs decay immediately after writing.

### 2. Extracting configs with property name mismatches
- **What was done:** The R5 config centralization agent initially extracted SEVERITY_CONFIG but consumers used different property names for the same concept (`.className` in some files = text color, `.className` in others = badge background).
- **Failure mode:** First TypeScript check after extraction had errors because some consumers expected `.bg` for badge backgrounds but the shared config used `.className` for that purpose. Required a second edit pass.
- **Evidence:** Audit log shows multiple sequential edits to FindingsList.tsx and FindingDetail.tsx (lines 3372-3391) — the agent needed iterative fixes. R5 agent used 47 tool calls (most of any agent) despite being a "small" refactor.
- **How to avoid:** Before extracting shared configs, inventory the exact property names each consumer accesses. Build the shared type to match the most common pattern, then update outliers in one pass.

### 3. Attempting to curl immediately after docker compose up
- **What was done:** Ran `curl` immediately after `docker compose up -d --build backend` returned.
- **Failure mode:** Backend container was still starting (uvicorn hadn't bound the port yet). curl got empty response, causing JSON parse error. Wasted a debugging cycle checking logs before realizing it was just a timing issue.
- **Evidence:** First curl after rebuild returned empty response. `docker compose logs` showed uvicorn was still in startup sequence. Second curl (a few seconds later) worked fine.
- **How to avoid:** After `docker compose up -d --build`, either check logs for "Application startup complete" or accept that the first curl may fail and retry once.
