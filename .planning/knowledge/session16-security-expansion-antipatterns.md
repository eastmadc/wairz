# Anti-patterns: Session 16 — Security Tools Expansion

> Extracted: 2026-04-07
> Session: 16 (security tools expansion)

## Failed Patterns

### 1. Single-Format Output Parser
- **What was done:** Initial `_parse_tool_output_to_findings()` only handled `[SEVERITY] detail` format.
- **Failure mode:** Info leaks tool output uses `### Severity (N)` section headings with indented `  /path: detail` lines. Parser returned 0 findings despite tool finding 46 leaks. Raw output showed data was there but not parsed.
- **Evidence:** First deploy: `info-leaks` endpoint returned `findings_created: 0` but `raw_output` contained 46 items. Fixed by adding section heading + indented line parsing.
- **How to avoid:** Always test the parser against the actual tool output format before deploying. Different MCP tools format output differently — don't assume one format fits all.

### 2. Binary Hardening Tabular Output Not Parseable
- **What was done:** `check_all_binary_protections` produces a formatted table (columns: Path, Type, Size, NX, RELRO, etc.) rather than `[SEVERITY] path: detail` lines.
- **Failure mode:** The `_parse_tool_output_to_findings()` parser can't extract individual findings from tabular output. `binary-hardening` endpoint reports 0 findings even though the raw output contains 96 binary rows.
- **Evidence:** Endpoint returns `findings_created: 0` but `raw_output` has complete table. The raw output is still valuable (shown in UI), but individual findings aren't persisted to the Findings page.
- **How to avoid:** For tools with tabular/summary output, either: (a) modify the MCP tool to also output parseable per-item lines, or (b) write a custom parser for that specific output format. The generic runner works best with tools that output severity-tagged lines.
