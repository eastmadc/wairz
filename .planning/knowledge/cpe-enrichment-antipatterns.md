# Anti-patterns: CPE Enrichment + Session 15

> Extracted: 2026-04-07
> Campaign: .planning/campaigns/cpe-enrichment.md

## Failed Patterns

### 1. docker cp changes wiped by docker compose up
- **What was done:** Used `docker cp` to deploy backend changes into the running container. Later, `docker compose up -d frontend` recreated the backend container from the old image, wiping all docker cp changes.
- **Failure mode:** Backend returned 500 errors (`ToolRegistry.execute() got an unexpected keyword argument 'truncate'`) because the container had reverted to old code.
- **Evidence:** Session 15 — `docker compose up -d frontend` also recreated the backend container. Had to re-deploy all files with docker cp again.
- **How to avoid:** After any `docker compose up` that recreates containers, always re-apply docker cp changes. Better: rebuild the backend image before `up`, or use volume mounts for development.

### 2. Hard-coded result limits in tool handlers without user override
- **What was done:** Original tools had `MAX_STRINGS = 200`, `MAX_GREP_RESULTS = 100`, etc. as hard constants with no input parameter to override them. The browser Security Tools page inherited these MCP-oriented limits.
- **Failure mode:** Users running tools from the browser expected full results but got truncated output with no way to get more. The 30KB MCP truncation also applied to REST responses unnecessarily.
- **Evidence:** User reported truncation on extract_strings (200 of 1993), had to add `max_results` parameter to 9 tools and bypass REST truncation.
- **How to avoid:** When exposing MCP tools via REST, distinguish between MCP constraints (context window) and browser constraints (none). Add `max_results` parameters from the start with sensible defaults.

### 3. navigator.clipboard fails silently on HTTP
- **What was done:** Copy button used `navigator.clipboard.writeText()` which requires HTTPS or localhost. The app is served over HTTP on a LAN IP.
- **Failure mode:** Copy button appeared to work (showed "Copied") but nothing was actually copied to clipboard. No error thrown because the API just silently fails or `navigator.clipboard` is undefined.
- **Evidence:** User reported copy not working multiple times. Fixed with `execCommand('copy')` fallback.
- **How to avoid:** Always implement a textarea fallback for clipboard operations. Check `navigator.clipboard?.writeText` with optional chaining, not try/catch on a possibly-undefined object.

### 4. Ghidra analysis crashing on raw binaries
- **What was done:** `get_binary_info` called `cache.get_binary_info()` which triggered Ghidra analysis on a raw ARM binary (no ELF/PE/Mach-O header). Ghidra failed and the error propagated as a 500.
- **Failure mode:** Tool returned "Error executing get_binary_info: Ghidra full analysis produced no parseable output" instead of gracefully falling back.
- **Evidence:** User ran get_binary_info on Signia PowerPack firmware.bin (raw Cortex-M binary).
- **How to avoid:** Wrap Ghidra/radare2 calls in try/except when they're the first attempt in a fallback chain. Raw binaries are common in embedded firmware — always have a meaningful fallback.
