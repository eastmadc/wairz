# Patterns: Session 12 — Fleet Wave 1 + RTOS Research

> Extracted: 2026-04-06
> Campaign: .planning/fleet/session-option-a-wave1.md
> Postmortem: none (inline extraction)

## Successful Patterns

### 1. Deep Research Before Fleet Spawning
- **Description:** Ran 4 parallel Explore agents to audit actual codebase state (backend services, frontend pages, campaign files, intake plans) before creating the fleet work queue. This revealed that Binary Diff and CVE Triage were already substantially implemented despite intake plans saying "not started."
- **Evidence:** Research agents discovered SbomPage.tsx already has 1,366-line VulnerabilitiesTab with bulk triage, and ComparisonPage.tsx has 834-line binary diff with clickable functions — preventing duplicate work.
- **Applies when:** Planning any fleet or archon campaign. Always verify current code state vs. plan docs before building.

### 2. Zero-Overlap Scope Partitioning
- **Description:** Fleet Wave 1 assigned 3 agents to completely non-overlapping file scopes: Agent 1 (backend/app/services/sbom*), Agent 2 (backend/app/cli/ + .github/), Agent 3 (frontend/tests/). No merge conflicts.
- **Evidence:** All 3 agents completed and changes merged cleanly to working directory. `git diff --cached --stat` showed 17 files, 1862 insertions with zero conflicts.
- **Applies when:** Decomposing fleet waves. Prefer creating new files over modifying shared files when possible.

### 3. Seed-First for Research-Heavy Features
- **Description:** For RTOS Recognition (research-heavy, ambiguous), ran deep web research + codebase audit first, then crystallized into a seed YAML with exact signatures, rather than jumping into code. Produced a 265-line seed with detection patterns for 7 RTOS + companion libraries.
- **Evidence:** Two parallel research agents (codebase tools + web signatures) produced comprehensive data. Seed ambiguity_score: 0.08 (very low — decisions fully crystallized).
- **Applies when:** Features requiring domain-specific signatures, binary format knowledge, or protocol specs. Interview/research first, build second.

### 4. Tiered Tool Selection for Binary Analysis
- **Description:** Research identified the right tool for each RTOS detection task instead of one-size-fits-all: LIEF for ELF parsing, raw bytes for magic scanning, custom strings for version extraction, cpu_rec for architecture detection, Capstone only when disassembly needed.
- **Evidence:** All tools already installed in backend container. No new dependencies needed.
- **Applies when:** Any binary analysis feature. Match tool to task granularity.

### 5. SQLAlchemy SQLite Compatibility for Stateless CLI
- **Description:** CI/CD agent solved the AssessmentService dependency on PostgreSQL by creating compilation hooks that render JSONB→TEXT and ARRAY→TEXT for SQLite, plus stripping server_default values that reference gen_random_uuid().
- **Evidence:** `python -c "from app.cli.scan import main"` imports cleanly without PostgreSQL running.
- **Applies when:** Creating CLI wrappers or CI tools that reuse services designed for PostgreSQL.

### 6. Playwright Disclaimer Dialog Handling
- **Description:** E2E agent discovered the WAIRZ welcome disclaimer dialog blocks all test interaction. Created a shared `dismissDisclaimer()` helper called at test start.
- **Evidence:** All 20 tests written with dialog handling. Tests would fail without it.
- **Applies when:** Writing any new E2E tests. The disclaimer uses sessionStorage — must be handled per-browser context.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Fleet over sequential Archon | 3 independent scopes with no file overlap | All 3 completed in ~6.5 min wall clock vs. ~15 min sequential |
| Composite GitHub Action (not docker action) | Dockerfile.ci lives in backend/, not .github/actions/ — docker actions require Dockerfile in action dir | Works correctly, builds from backend/ context |
| Ouroboros interview via MCP tool failed | Requires Claude Code subprocess (claudecode_present: False) | Conducted interview manually via AskUserQuestion, produced same quality seed |
| CPE part parameter (a vs o) | Kernel/OS components need cpe:2.3:o:, not cpe:2.3:a: | Added part param to _build_cpe() with backward-compatible default="a" |
| Playwright workers:1 | E2E tests modify shared state (create projects, upload firmware) | Sequential execution prevents test interference |
| aiosqlite dependency added | CLI scan needs async SQLAlchemy without PostgreSQL | Minimal footprint, only used by wairz-scan CLI path |
