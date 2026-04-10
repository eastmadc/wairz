# Patterns: S25 Fleet — CI/CD + E2E + Threat Intel

> Extracted: 2026-04-10
> Campaign: .planning/fleet/session-s25-cicd-e2e-threatintel.md
> Postmortem: none

## Successful Patterns

### 1. Fleet single-wave for 3 independent streams
- **Description:** 3 build agents spawned in parallel with strict scope partitioning (CLI/CI files, frontend tests, backend services). Zero file overlap verified before spawning. All 3 completed successfully with zero merge conflicts.
- **Evidence:** Session file shows all 3 agents complete, merge conflicts = 0
- **Applies when:** Work decomposes into 3+ independent streams that touch different files

### 2. Graceful degradation for external service integrations
- **Description:** ClamAV and VirusTotal services return structured JSON error responses (`{"status": "unavailable", "errors": [...]}`) when services are unreachable or API keys not configured. Both REST endpoints and MCP tools handle this identically.
- **Evidence:** Smoke test showed clean degradation for both `/clamav-scan` and `/vt-scan`
- **Applies when:** Integrating any external service that may not be running or configured

### 3. SARIF 2.1.0 output without extra dependencies
- **Description:** Built SARIF JSON manually using stdlib `json` and `datetime` instead of adding `sarif-om` package. The schema is simple enough (tool.driver.rules + results array) that a library is unnecessary.
- **Evidence:** CLI `--format sarif` produces valid output with zero new dependencies
- **Applies when:** Adding standard output formats (SARIF, CycloneDX) to CLI tools

### 4. Backward compatibility via CLI aliases
- **Description:** `--fail-on-critical` kept as alias for `--fail-on critical`, preserving backward compatibility while adding flexible threshold support (critical/high/medium/cvss:N.N/none).
- **Evidence:** Both `--fail-on-critical` and `--fail-on critical` work in CLI help
- **Applies when:** Extending CLI flag behavior without breaking existing usage

### 5. E2E tests as UI structure verification
- **Description:** New Playwright specs verify UI element presence (tabs, buttons, inputs, graph areas) without triggering long-running operations. Tests use `expect(count).toBeGreaterThan(0)` or `.isVisible()` rather than starting emulation/fuzzing.
- **Evidence:** 15 new tests covering emulation, comparison, and component map pages
- **Applies when:** Writing E2E tests for pages that depend on Docker sidecar containers

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Build SARIF manually, no dependency | CI Docker image should stay lean; SARIF schema is simple | Worked — valid output, zero deps |
| ClamAV via TCP, not Unix socket | Docker service networking requires TCP (clamav:3310) | Correct — Docker DNS resolution works |
| VT rate limit via asyncio.sleep, not token bucket | Free tier is 4 req/min, simple batching is sufficient | Worked — no over-engineering |
| CWE-506 for both ClamAV and VT malware findings | Standard CWE for "Embedded Malicious Code" | Consistent categorization |
| 107 MCP tools total | +4 threat intel tools, +0 CLI tools | Manageable, no performance issues |
