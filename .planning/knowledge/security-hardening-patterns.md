# Patterns: Security Hardening Campaign

> Extracted: 2026-04-03
> Campaign: .planning/campaigns/security-hardening.md
> Postmortem: none

## Successful Patterns

### 1. Extending existing tool files rather than creating new categories
- **Description:** YARA scanning was added to `security.py` alongside existing security tools rather than creating a separate `tools/yara.py`. Credential patterns were appended to the existing `_CREDENTIAL_PATTERNS` list.
- **Evidence:** Decision Log entry: "YARA tools added to security.py — fits naturally with existing security tools"
- **Applies when:** New security analysis capabilities that share the same domain. Only create a new tool category file when the domain is genuinely distinct (e.g., fuzzing vs. security).

### 2. Python bindings over CLI wrapping for batch operations
- **Description:** Used yara-python (Python bindings) instead of wrapping the YARA CLI tool via subprocess.
- **Evidence:** Decision Log: "faster for batch scanning, no subprocess overhead." YARA scans can process hundreds of files per firmware.
- **Applies when:** Any tool that will process many files in a single invocation. subprocess overhead adds up. Use bindings when available (yara-python, python-magic, etc.).

### 3. Embedding rules in code for simpler deployment
- **Description:** YARA rules were embedded as Python string constants rather than external `.yar` files.
- **Evidence:** Decision Log: "simpler deployment, no file management." 26 rules across 4 categories fit cleanly as constants.
- **Applies when:** Rule sets that are small (<50 rules) and don't need user customization. For larger or user-extensible rule sets, use external files.

### 4. Deferring phases cleanly rather than rushing
- **Description:** Phase 1 (YARA scanning) was initially deferred because it needed a Dockerfile change (yara-python C dependency). Phases 2-4 proceeded independently.
- **Evidence:** Campaign status: "completed (YARA deferred)" — later completed in session 5 when Dockerfile work was in scope.
- **Applies when:** A phase has external dependencies (Dockerfile changes, new containers). Mark as deferred with clear reason, complete other phases, return when the blocker is naturally addressed.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| YARA in security.py, not separate file | Same domain as existing security tools | Correct — consistent tool grouping |
| yara-python over CLI | Batch performance, no subprocess overhead | Correct — scanning 200+ files per firmware |
| Rules embedded in code | Simpler deployment, small rule count | Correct — 26 rules manageable as constants |
| Phase 1 deferred | Needed Dockerfile change not in scope | Correct — completed naturally in session 5 |
