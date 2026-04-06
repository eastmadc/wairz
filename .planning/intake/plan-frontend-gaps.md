# Plan: Frontend Gaps (F1-F4)

**F3 completed 2026-04-06** — Collapsible unpack log viewer added to ProjectDetailPage for all firmware.

## F1: CVE Triage Workflow UI

**Priority:** Medium | **Effort:** Medium | **Route:** `/citadel:marshal`

### Current State
- SbomPage.tsx has VulnerabilitiesTab with sortable table (severity, CVSS, component, CVE ID)
- Resolution status filters in vulnerabilityStore (open, resolved, ignored, false_positive)
- Individual vulnerability resolution with justification modals exists
- Bulk selection framework partially implemented (checkboxes, select-all)
- Backend VEX mapping fully implemented (sbom.py)
- SbomVulnerability model has resolution_status, resolution_justification, adjusted_severity

### What's Missing
- Expandable vulnerability rows (inline detail, not modal)
- Inline VEX status buttons (one-click open/resolved/ignored/false_positive)
- Bulk triage action execution (framework exists, UI needs completion)

### Key Files
- `frontend/src/pages/SbomPage.tsx` (VulnerabilitiesTab)
- `frontend/src/stores/vulnerabilityStore.ts` (add bulk actions)
- New: `frontend/src/components/sbom/VulnerabilityRow.tsx`
- **Components:** 3-4

---

## F2: Expose MCP Tools in UI

**Priority:** Medium | **Effort:** Large | **Route:** `/ouroboros:interview` then `/citadel:archon`

### Current State
- `frontend/src/api/tools.ts` has `listTools()` and `runTool()` functions
- Backend at `/api/v1/projects/{project_id}/tools` returns tool list with JSON schemas
- Tool execution endpoint accepts tool_name + input parameters
- No "Security Tools" page exists

### What's Missing
- SecurityToolsPage.tsx route + sidebar nav entry
- Tool discovery and categorized display (listTools integration)
- Dynamic form generation from JSON Schema input schemas
- Tool execution with parameter input, progress, and output display

### Key Files
- New: `frontend/src/pages/SecurityToolsPage.tsx`
- Modify: `frontend/src/components/layout/Sidebar.tsx`
- New: `frontend/src/components/tools/ToolCard.tsx`
- New: `frontend/src/components/tools/ToolExecutor.tsx`
- **Components:** 4-5

---

## F3: Show Unpack Log for Successful Extractions

**Priority:** Low | **Effort:** Small | **Route:** `/do` direct edit

### Current State
- `unpack_log` field exists in FirmwareDetail TypeScript type
- ProjectDetailPage.tsx displays unpack_log ONLY on error (lines 417-423)
- Backend stores log in firmware.unpack_log column for all extractions

### What's Missing
- Collapsible log section shown for ALL firmware (not just errors)
- Log viewer with scrollable content

### Key Files
- `frontend/src/pages/ProjectDetailPage.tsx` (lines 395-423)
- New: `frontend/src/components/projects/UnpackLogViewer.tsx`
- **Components:** 1-2

---

## F4: Frontend E2E Tests (Playwright)

**Priority:** Medium | **Effort:** Medium | **Route:** `/citadel:marshal`

### Current State
- Vite + TypeScript + React 19 setup
- No Playwright in package.json
- No test directory or configuration
- 355+ backend tests, 0 frontend tests

### What's Needed
- Install @playwright/test
- Create playwright.config.ts
- Create tests/e2e/ directory
- Smoke tests: create project, upload firmware, explore files, run scan, check findings

### Key Files
- `frontend/package.json` (add devDependency)
- New: `frontend/playwright.config.ts`
- New: `frontend/tests/e2e/project-workflow.spec.ts`
- New: `frontend/tests/e2e/findings-triage.spec.ts`
- **Test files:** 3-4
