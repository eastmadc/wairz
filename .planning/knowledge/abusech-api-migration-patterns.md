# Patterns: abuse.ch API Migration Fix (Session Debugging)

> Extracted: 2026-04-13
> Source: debugging session — not a formal campaign

## Successful Patterns

### 1. Systematic API endpoint verification before assuming code bugs
- **Description:** All three abuse.ch API failures (401, 401, 301) were verified by making raw HTTP requests from inside the Docker container, isolating the issue to API changes vs. code bugs.
- **Evidence:** Direct `httpx.post()` calls confirmed MalwareBazaar/ThreatFox now require Auth-Key headers and YARAify v2 endpoint is deprecated.
- **Applies when:** Any external API integration starts failing — always test the raw API first before reading service code.

### 2. Comparing old vs. new API response structures
- **Description:** YARAify v1 response structure (`data.tasks[].static_results[].rule_name`) was different from v2 (`data[].tasks[].rule_name`). Inspecting the actual response JSON before writing parsing code prevented a second fix cycle.
- **Evidence:** First fix attempt parsed `data.tasks[].rule_name` (wrong), second inspected the full JSON and found `static_results` nesting.
- **Applies when:** Migrating to a new API version — always dump and inspect the real response before writing parser code.

### 3. Early-exit for missing credentials
- **Description:** When an API requires auth keys that aren't configured, the service now returns empty results immediately instead of making doomed HTTP requests. This eliminates log spam and reduces scan time.
- **Evidence:** Before fix: 30+ hashes × 3 services × 30s timeout = potentially minutes of wasted time. After fix: instant skip with one warning log.
- **Applies when:** Any service that depends on optional external credentials.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Early-exit when no auth key vs. still trying | abuse.ch APIs now hard-require auth — no point trying without | Eliminates log spam, speeds up scans |
| Single warning log in `enrich_iocs()` vs. per-hash warnings | One clear message is actionable; 100 per-hash warnings are noise | Clean logs with clear remediation URL |
| Keep YARAify working without auth key | YARAify v1 API works without auth | Users get partial threat intel even without registering |
