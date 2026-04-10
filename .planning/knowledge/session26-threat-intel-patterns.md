# Patterns: Session 26 — Threat Intelligence Phases 4-5

> Extracted: 2026-04-10
> Work: abuse.ch suite + CIRCL Hashlookup integration

## Successful Patterns

### 1. Follow existing service conventions exactly
- **Description:** Both new services (abusech_service.py, hashlookup_service.py) mirror the virustotal_service.py structure: dataclass results, async functions, graceful degradation, batch methods with rate limiting.
- **Evidence:** Zero integration issues — all 6 tools registered and tested on first deploy.
- **Applies when:** Adding any new external API integration to the backend.

### 2. Reuse collect_binary_hashes() across services
- **Description:** All hash-based threat intel services share the same binary collection function from virustotal_service. Avoids duplicating filesystem traversal logic.
- **Evidence:** abuse.ch and CIRCL both import from virustotal_service for hash collection.
- **Applies when:** Any new hash-based lookup service is added.

### 3. Triage intake queue before building
- **Description:** Scanning all 15 intake items revealed 12 were already completed. Only 3 had remaining work, and only 1 (threat intel Phases 4-5) was substantial. This saved a session that could have been wasted on stale items.
- **Evidence:** Autopilot triage identified the exact scope of remaining work.
- **Applies when:** Starting any new session — always scan intake first.

### 4. Single summary finding for informational scans
- **Description:** CIRCL known-good scan returns a single summary finding ("X of Y binaries are known-good") rather than one finding per file. Avoids flooding the findings table with info-level noise.
- **Evidence:** run_known_good_scan() in security_audit_service.py.
- **Applies when:** Integrating informational (non-threat) scan results into the findings system.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| No API key required for abuse.ch/CIRCL | Both services work without auth (just slower rate limits). Lower barrier to entry. | Correct ��� both endpoints work out of the box |
| Polite rate limiting (0.3-0.5s delay) | abuse.ch and CIRCL are free community services. Don't abuse them. | Good practice, no rate limit errors during testing |
| Batch enrichment as single MCP tool | `enrich_firmware_threat_intel` runs all 4 abuse.ch services in one call. Saves Claude tool-call overhead. | Clean UX — one tool for comprehensive threat intel |
| CIRCL bulk endpoint with individual fallback | Bulk POST to /bulk/sha256 is faster but may fail. Individual GET fallback ensures reliability. | Resilient design |
