# Plan: Frontend Gaps (F1-F4)

**F1 completed 2026-04-07** -- Expandable vuln rows, inline VEX buttons, bulk triage toolbar, keyboard shortcuts (session 14).
**F2 completed 2026-04-07** -- Security Tools page at /tools with 81 tools, categorized list, dynamic JSON Schema forms, execution UI (session 14).
**F3 completed 2026-04-06** -- Collapsible unpack log viewer added to ProjectDetailPage for all firmware.
**F4 partially completed 2026-04-06** -- Playwright installed, 4 E2E test files created (session 12).

## F1: CVE Triage Workflow UI

**Priority:** Medium | **Effort:** Medium (~6h) | **Status:** pending
**Route:** `/citadel:marshal`

### Current State
- SbomPage.tsx has VulnerabilitiesTab with sortable table (severity, CVSS, component, CVE ID)
- Resolution status filters in vulnerabilityStore (open, resolved, ignored, false_positive)
- Individual vulnerability resolution with justification modals exists
- Bulk selection framework partially implemented (checkboxes, select-all)
- Backend VEX mapping fully implemented (sbom.py)
- SbomVulnerability model has resolution_status, resolution_justification, adjusted_severity

### What's Missing
- Expandable vulnerability rows (inline detail, not modal-only)
- Inline VEX status buttons (one-click open/resolved/ignored/false_positive)
- Bulk triage action execution (framework exists, UI needs completion)
- CVE detail panel: description, CVSS vector breakdown, affected versions, references
- Keyboard shortcuts for triage workflow (j/k navigate, r=resolve, i=ignore, f=false positive)

### Implementation Approach
1. **VulnerabilityRow.tsx** -- expandable row component:
   - Click to expand inline detail panel (no modal needed for quick triage)
   - Show: CVE description, CVSS breakdown, affected component path, fix version (if known)
   - Inline status buttons: 4 pill buttons for resolution status (color-coded)
   - "Justification" text input appears when status changes
2. **Bulk triage toolbar** -- appears when checkboxes selected:
   - "Mark selected as..." dropdown with resolution status options
   - "Adjust severity for selected..." dropdown
   - Batch count indicator ("3 of 127 selected")
3. **VulnerabilityStore enhancements:**
   - `bulkUpdateStatus(ids: string[], status: string, justification: string)` action
   - `selectedIds: Set<string>` state
   - Optimistic updates with rollback on API error

### Key Files
- `frontend/src/pages/SbomPage.tsx` (VulnerabilitiesTab -- modify)
- `frontend/src/stores/vulnerabilityStore.ts` (add bulk actions)
- New: `frontend/src/components/sbom/VulnerabilityRow.tsx`
- **Components:** 3-4

### Acceptance Criteria
- [ ] Vulnerability rows expand inline to show CVE detail
- [ ] One-click status change via inline pill buttons
- [ ] Bulk selection + batch status update works for 10+ vulns
- [ ] VEX export reflects triage decisions made in UI
- [ ] Keyboard shortcuts for power-user triage workflow

---

## F2: Expose MCP Tools in UI ("Security Tools" Page)

**Priority:** Medium | **Effort:** Large (~10h) | **Status:** pending
**Route:** `/citadel:archon` (3 phases: page scaffold, dynamic forms, execution UX)

### Current State
- `frontend/src/api/tools.ts` has `listTools()` and `runTool()` functions
- Backend at `/api/v1/projects/{project_id}/tools` returns tool list with JSON schemas
- Tool execution endpoint accepts tool_name + input parameters
- No "Security Tools" page exists
- No `SecurityToolsPage` component

### What's Missing
- SecurityToolsPage.tsx route + sidebar nav entry
- Tool discovery and categorized display (listTools API integration)
- Dynamic form generation from JSON Schema input schemas
- Tool execution with parameter input, progress indicator, and output display
- Tool output formatting (structured JSON -> readable display)

### Implementation Approach

1. **SecurityToolsPage.tsx** -- main page layout:
   - Left panel: categorized tool list (use existing tool category tags from backend)
   - Right panel: selected tool's form + output area
   - Categories: Security, Binary Analysis, SBOM, Emulation, Filesystem, Reporting
   - Search/filter bar at top

2. **ToolCard.tsx** -- tool list item:
   - Tool name, description, category badge
   - "Run" button or click to select
   - Last run timestamp + status indicator

3. **ToolForm.tsx** -- dynamic form from JSON Schema:
   - Use `@rjsf/core` (React JSON Schema Form) for automatic form generation from tool input_schema
   - Or build custom form renderer for simpler schemas (most tool inputs are 1-3 string fields)
   - Path fields: integrate with file tree browser for path selection
   - Boolean fields: toggle switches
   - Enum fields: dropdown selects
   - Required field validation from JSON Schema

4. **ToolOutput.tsx** -- result display:
   - JSON output with syntax highlighting (use Monaco or `react-syntax-highlighter`)
   - Collapsible sections for large outputs
   - Copy-to-clipboard button
   - Error state with retry button
   - Loading state with cancel option

**Library recommendation:** `@rjsf/core` + `@rjsf/utils` + `@rjsf/validator-ajv8` for JSON Schema form generation. Well-maintained, React 19 compatible, handles complex schemas. Alternative: build minimal custom renderer since most tool schemas are simple (3-5 fields max).

### Key Files
- New: `frontend/src/pages/SecurityToolsPage.tsx`
- Modify: `frontend/src/components/layout/Sidebar.tsx` (add nav entry)
- Modify: `frontend/src/App.tsx` (add route)
- New: `frontend/src/components/tools/ToolCard.tsx`
- New: `frontend/src/components/tools/ToolForm.tsx`
- New: `frontend/src/components/tools/ToolOutput.tsx`
- Existing: `frontend/src/api/tools.ts` (already has listTools/runTool)
- **Components:** 5-6

### Acceptance Criteria
- [ ] Security Tools page accessible from sidebar navigation
- [ ] All 60+ MCP tools listed and categorized
- [ ] Dynamic form generated from any tool's JSON Schema input
- [ ] Tool execution shows progress and renders output
- [ ] Path parameters integrate with file browser for selection
- [ ] Search/filter works across tool names and descriptions

---

## F3: Show Unpack Log for Successful Extractions -- COMPLETED

**Status:** completed (session 11)

Collapsible log viewer for all firmware in ProjectDetailPage.

---

## F4: Frontend E2E Tests (Playwright) -- PARTIALLY COMPLETED

**Priority:** Medium | **Effort:** Small (remaining ~3h) | **Status:** in progress
**Route:** `/citadel:marshal`

### Current State (verified 2026-04-06)
- Playwright installed (`frontend/playwright.config.ts` exists)
- 4 test files exist:
  - `frontend/tests/e2e/project-crud.spec.ts`
  - `frontend/tests/e2e/firmware-upload.spec.ts`
  - `frontend/tests/e2e/sbom-scan.spec.ts`
  - `frontend/tests/e2e/navigation.spec.ts`
- 20 tests created in session 12

### What Remains
- **Findings triage tests** -- test bulk selection, status change, VEX export (depends on F1)
- **Emulation workflow tests** -- start emulation, check status, run command
- **Comparison workflow tests** -- upload two firmware, trigger comparison, view diff
- **CI integration** -- add Playwright to GitHub Actions workflow (run on PR)
- **Test fixtures** -- shared test firmware files for reproducible tests
- **Visual regression** -- optional: Playwright screenshot comparison for key pages

### Implementation Approach
1. Add remaining spec files:
   - `frontend/tests/e2e/emulation-workflow.spec.ts`
   - `frontend/tests/e2e/comparison-workflow.spec.ts`
   - `frontend/tests/e2e/findings-triage.spec.ts` (after F1)
2. Add to CI: `.github/workflows/e2e-tests.yml`
   - Spin up Docker Compose (backend + postgres + redis)
   - Run Playwright against `http://localhost:3000`
   - Upload trace artifacts on failure
3. Use `test.describe.configure({ mode: 'serial' })` for workflows that depend on prior state

### Key Files
- `frontend/playwright.config.ts` (exists, may need CI adjustments)
- `frontend/tests/e2e/*.spec.ts` (4 exist, 2-3 more needed)
- New: `.github/workflows/e2e-tests.yml`
- **Test files remaining:** 2-3

### Acceptance Criteria
- [ ] 25+ E2E tests covering all major workflows
- [ ] Tests run in CI on PR (GitHub Actions)
- [ ] Test fixtures provide reproducible firmware for upload tests
- [ ] Trace artifacts uploaded on test failure for debugging
- [ ] All tests pass against a fresh Docker Compose environment
