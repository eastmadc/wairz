# Patterns: Session 16 — Security Tools Expansion

> Extracted: 2026-04-07
> Session: 16 (security tools expansion, CI/CD SARIF, 9-tab SecurityScanPage)
> Campaign: none (direct build from deep research)

## Successful Patterns

### 1. Deep Research Before Building Security Tools
- **Description:** Used a research agent to systematically compare Wairz's security capabilities against EMBA, Firmwalker, and FACT before writing any code. Produced a ranked gap analysis with 15 items prioritized by value-to-effort ratio.
- **Evidence:** Research identified that info leak detection, dev tools scanning, and network config audit were easy wins (pure Python, no external deps) while cwe_checker and dynamic service enumeration required hard external tool integration. Built the easy wins first.
- **Applies when:** Adding new analysis capabilities to the platform. Research the ecosystem first, then pick the highest-value/lowest-effort items.

### 2. MCP Tool → REST Endpoint → Frontend Tab Pipeline
- **Description:** Established a clean 3-layer pipeline for adding new security scan types: (1) implement as MCP tool handler in `tools/security.py`, (2) add to REST whitelist + create dedicated scan endpoint in `security_audit.py`, (3) add tab in SecurityScanPage. Each layer is independent and testable.
- **Evidence:** Added 3 MCP tools, 6 REST endpoints, and 6 new UI tabs all following this pipeline. Each tool was curl-testable at the REST layer before the frontend was touched.
- **Applies when:** Any new scan type or analysis capability is added. Follow MCP → REST → UI order.

### 3. Generic Tool Scan Runner Pattern
- **Description:** Created `_run_tool_scan()` in `security_audit.py` — a reusable function that executes any MCP tool, parses its text output into findings, and persists them. New scan endpoints become 10-line functions that just call this runner with different tool names and sources.
- **Evidence:** All 6 new endpoints (`dev-tools`, `network-config`, `info-leaks`, `scripts`, `binary-hardening`, `secure-boot`) use this single runner function. Zero code duplication.
- **Applies when:** Adding any new REST scan endpoint that wraps an existing MCP tool. Reuse `_run_tool_scan()`.

### 4. Dual-Format Output Parser
- **Description:** The `_parse_tool_output_to_findings()` parser handles two MCP output formats: (1) `[SEVERITY] /path: detail` and (2) section headings (`### Medium`) with indented `  /path: detail` lines. This covers all current tool output styles.
- **Evidence:** Dev tools output used format 1 (parsed correctly, 2 findings). Info leaks output used format 2 (initially 0 findings until parser was enhanced, then 46 findings). The dual parser was essential — a single-format parser lost half the data.
- **Applies when:** Parsing any MCP tool output into findings. Check which format the tool uses.

### 5. Tab-Based SecurityScanPage with Shared Finding Display
- **Description:** Rather than creating separate pages per scan type, all 9 scan types share a single page with tabs. Common state (findings list, severity badges, finding table) is shared. Only the action button and result card differ per tab. Generic tool scan tabs require only a `TabDef` entry with `endpoint` field.
- **Evidence:** Adding a new scan tab requires only 6 lines in the `TABS` array — no new components, no new state management. The `currentTab.endpoint` check routes to the generic handler automatically.
- **Applies when:** Adding more security scan types in the future. Just add a `TabDef` entry and a REST endpoint.

### 6. SARIF Output for CI/CD Integration
- **Description:** SARIF 2.1.0 output format for the scan CLI enables GitHub Security tab integration. The SARIF structure maps severity to SARIF levels (critical/high→error, medium→warning, low/info→note), embeds CWE tags, and includes file locations.
- **Evidence:** Implemented as a new formatter alongside existing JSON and markdown formatters. GitHub Action auto-uploads SARIF via `github/codeql-action/upload-sarif@v3`.
- **Applies when:** CI/CD pipeline integration for any security tool output. SARIF is the standard format for GitHub Security tab.

### 7. GITHUB_OUTPUT for Action Outputs
- **Description:** The scan CLI writes finding counts and pass/fail result to `$GITHUB_OUTPUT` when running inside GitHub Actions. Downstream steps can read these as `${{ steps.scan.outputs.total-findings }}`.
- **Evidence:** Implemented in `_run()` — detects `GITHUB_OUTPUT` env var and appends structured outputs.
- **Applies when:** Building any CLI tool that needs to communicate results to GitHub Actions workflow steps.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| 3 new tools (dev-tools, network-config, info-leaks) before cwe_checker | Pure Python, no external deps, done in 1 session | All 3 working, 46+ findings on OpenWrt |
| Generic `_run_tool_scan()` runner | Avoids per-tool REST boilerplate, 6 endpoints in ~60 lines total | Clean, reusable, easy to add more |
| Dual output parser (bracket + section heading formats) | Different MCP tools use different output styles | Caught a 0-finding bug on first deploy |
| `--fail-on` replacing `--fail-on-critical` | More flexible: critical/high/medium/low/cvss:N.N | Backwards compatible (old flag still works) |
| SARIF output in scan.py (not in Action shell) | Python can construct proper JSON; shell would be fragile | Clean SARIF 2.1.0 output |
| Tabs on SecurityScanPage (not separate pages) | Unified scan experience, shared finding display, less navigation | 9 tabs, no page bloat |
