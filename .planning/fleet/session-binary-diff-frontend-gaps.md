# Fleet Session: Binary Diff Enhancement + Frontend Gaps

Status: completed
Started: 2026-04-06T14:00:00Z
Direction: Binary diff decompilation REST endpoint + basic block hashing; CVE triage UI (F1); Security Tools page (F2)

## Work Queue
| # | Campaign | Scope | Deps | Status | Wave | Agent |
|---|----------|-------|------|--------|------|-------|
| 1 | Binary diff: decompilation endpoint + basic blocks + frontend | comparison_service, comparison router/schemas, ComparisonPage, comparison API, types | none | active | 1 | builder |
| 2 | CVE Triage UI (F1) | SbomPage, vulnerabilityStore, components/sbom/ | none | active | 1 | builder |
| 3 | Security Tools Page (F2) | SecurityToolsPage (new), components/tools/ (new), Sidebar, App.tsx | none | active | 1 | builder |

## Wave 1 Agents

### Agent: fleet-bindiff-frontend-w1-a1 (binary-diff-decompilation)
**Scope:** backend/app/services/comparison_service.py, backend/app/routers/comparison.py, backend/app/schemas/comparison.py, frontend/src/pages/ComparisonPage.tsx, frontend/src/api/comparison.ts, frontend/src/types/index.ts
**Direction:** Add decompilation diff REST endpoint, basic block hashing for stripped binaries, frontend decompilation viewer

### Agent: fleet-bindiff-frontend-w1-a2 (cve-triage-ui)
**Scope:** frontend/src/pages/SbomPage.tsx, frontend/src/stores/vulnerabilityStore.ts, frontend/src/components/sbom/
**Direction:** Expandable vulnerability rows, inline VEX status buttons, bulk triage toolbar

### Agent: fleet-bindiff-frontend-w1-a3 (security-tools-page)
**Scope:** frontend/src/pages/SecurityToolsPage.tsx, frontend/src/components/tools/, frontend/src/components/layout/Sidebar.tsx, frontend/src/App.tsx
**Direction:** New Security Tools page with categorized tool list, dynamic JSON Schema forms, tool execution UX

## Scope Overlap Check
- Agent 1: comparison_service.py, comparison router, comparison schemas, ComparisonPage.tsx, comparison.ts, types/index.ts
- Agent 2: SbomPage.tsx, vulnerabilityStore.ts, components/sbom/
- Agent 3: SecurityToolsPage.tsx (new), components/tools/ (new), Sidebar.tsx, App.tsx
- Result: ZERO overlap confirmed

## Continuation State
Next wave: 2 (verification + merge)
Blocked items: none
