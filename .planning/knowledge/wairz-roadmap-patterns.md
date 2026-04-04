# Patterns: Wairz Full Roadmap

> Extracted: 2026-04-04
> Campaign: .planning/campaigns/completed/wairz-roadmap.md
> Postmortem: none

## Successful Patterns

### 1. Incremental Feature Delivery Across Sessions
- **Description:** Features were built incrementally across 8 sessions rather than batched into large campaigns. When the roadmap was audited, all 25 items were already complete.
- **Evidence:** Every phase (1-10) was marked "complete (already exists)" during verification.
- **Applies when:** Planning multi-session work. Build features as they come up rather than deferring to a future "big campaign."

### 2. Standalone Binary Fallback in Unpacking
- **Description:** When all extractors fail on a small file (<10MB), copy it directly and mark as success. Handles single binary uploads (malware samples, test binaries) that have no filesystem to extract.
- **Evidence:** User reported `malware_insulin_pump.bin` upload failure. Fix added PE binary fast path and small-file fallback in `unpack.py`.
- **Applies when:** Adding new firmware type support. Always consider the "no filesystem" case.

### 3. Graceful Fallback for Optional Dependencies
- **Description:** arq job queue falls back to `asyncio.create_task` if Redis/arq is unavailable. API key auth passes all requests if no key is configured. capa install in Dockerfile uses `|| echo WARN` fallback.
- **Evidence:** `routers/firmware.py` — `_arq_unavailable` flag, `middleware/auth.py` — empty `api_key` skips auth.
- **Applies when:** Adding infrastructure features. Always provide a zero-config fallback so the tool works without the optional dependency.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| All phases pre-existing | Prior sessions built features incrementally | Campaign was pure verification — 1 session instead of 8 |
| PE binary as fast path (like ELF) | PE binaries need no filesystem extraction | Correct — copy and succeed |
| Small file fallback (<10MB) | Single binaries aren't firmware images | Correct — handles malware samples |
