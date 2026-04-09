# Patterns: CRA Compliance Report Generator

> Extracted: 2026-04-09
> Campaign: .planning/fleet/session-cra-compliance.md
> Postmortem: none

## Successful Patterns

### 1. Fleet Wave Decomposition for Full-Stack Features
- **Description:** Decomposed CRA compliance into Wave 1 (DB models + service) and Wave 2 (REST + MCP tools || Frontend) with clear dependency gates. Wave 2 ran two agents in parallel on non-overlapping scopes.
- **Evidence:** 3 agents completed successfully, all imports validated, TypeScript clean. Total: 2,332 lines across 12 files in one session.
- **Applies when:** Any full-stack feature with backend models + API + frontend. Wave 1 = foundation, Wave 2 = consumers in parallel.

### 2. Exhaustive Agent Briefing with File-Level Patterns
- **Description:** Each fleet agent received the exact file patterns from existing code (Finding model, compliance router, SecurityScanPage tab structure) plus specific line numbers and import conventions. No ambiguity about conventions.
- **Evidence:** All three agents produced code that matched existing project patterns — correct SQLAlchemy style, correct router prefix convention, correct shadcn/ui component usage. Zero convention drift.
- **Applies when:** Spawning fleet agents for code generation. Read 5-6 example files and include concrete patterns in the prompt, not just descriptions.

### 3. Auto-Populate by Pattern Matching Against Existing Findings
- **Description:** CRA requirements are mapped to existing findings via title regex, CWE intersection, and tool source matching — reusing the same approach as the ETSI compliance service. No new scanners needed.
- **Evidence:** Auto-populate on Raspberry Pi OS correctly classified 14/20 requirements (8 pass, 4 fail, 2 partial) using only existing findings from prior security scans.
- **Applies when:** Building compliance frameworks that aggregate existing tool outputs. Define requirement-to-finding mappings, not new scanners.

### 4. Docker Deploy Test Catches Runtime Issues
- **Description:** Rebuilding Docker and smoke-testing the API immediately after code generation caught two real bugs: SQLAlchemy relationship back_populates mismatch and timezone-naive datetime conflict.
- **Evidence:** Both bugs were invisible to import validation and TypeScript checks but caused 500 errors at runtime. Fixed within minutes because they were caught immediately.
- **Applies when:** Always after backend changes. The import check (`python -c "from app..."`) catches syntax/import errors but not ORM mapper initialization or DB type mismatches.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Use Fleet (not Archon) for single-session feature | CRA decomposes into 3+ independent tracks with clear scope boundaries | Completed in one session with parallel Wave 2 |
| Reuse ETSI compliance pattern-matching approach | Existing compliance_service.py already solves finding-to-provision mapping | 833-line service, no reinvention |
| Separate `assessed_at` field per requirement | Allows tracking when each requirement was last reviewed (auto or manual) | Enables incremental re-assessment |
| Put CRA tab in SecurityScanPage (not new page) | Compliance is part of the security assessment workflow, not a separate concern | Clean UX, no routing changes needed |
| Use naive datetimes (not timezone-aware) | Existing DB tables (findings, projects) use `sa.DateTime()` without timezone; mixing causes asyncpg errors | Consistent with codebase; fixed the timezone mismatch |
