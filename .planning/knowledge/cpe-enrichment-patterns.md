# Patterns: CPE Enrichment

> Extracted: 2026-04-07
> Campaign: .planning/campaigns/cpe-enrichment.md
> Postmortem: none

## Successful Patterns

### 1. Metadata JSONB for new fields avoids migrations
- **Description:** Stored `enrichment_source` and `cpe_confidence` in the existing JSONB `metadata` column on SbomComponent, then exposed them as Pydantic `@computed_field` properties on the response schema. Zero database migrations needed.
- **Evidence:** Phase 2 completed without any Alembic migration. API returns the fields at the top level via computed fields, frontend consumes them directly.
- **Applies when:** Adding optional/enrichment data to existing models where the metadata JSONB column already exists and is returned in API responses.

### 2. Background service loading with non-blocking fallback
- **Description:** CPE dictionary service starts loading at app startup via `ensure_loaded()` in the lifespan handler. If not loaded yet when an SBOM scan runs, the enrichment pipeline simply skips the NVD fuzzy matching step and uses local methods only. No scan is ever blocked.
- **Evidence:** Phase 1 — startup hook triggers background download, `_enrich_cpes()` checks `cpe_dict._index is not None` before using it. First SBOM scan works immediately, later scans get NVD fuzzy matching once dictionary is cached.
- **Applies when:** Integrating large external data sources (NVD, CVE databases) that take time to download. Never block the main workflow.

### 3. Phased enrichment pipeline with confidence tracking
- **Description:** Built a 5-strategy pipeline where each strategy has a known confidence level (exact_match=0.95, local_fuzzy=0.85, nvd_fuzzy=variable, inherited=0.80, android_sdk=0.90). Every component gets tagged regardless of whether enrichment succeeded.
- **Evidence:** Phase 2 — enrichment stats logging shows per-strategy counts. Components with `enrichment_source: "none"` and `cpe_confidence: 0.0` are explicitly tagged rather than silently left untagged.
- **Applies when:** Multi-strategy analysis pipelines where users need to understand how a result was derived, not just the result.

### 4. Single-session campaign for well-planned work
- **Description:** The CPE enrichment plan (.planning/intake/plan-cpe-enrichment.md) was detailed enough from prior research that all 4 phases completed in a single session with no rework. The plan included specific libraries, API endpoints, threshold values, and file paths.
- **Evidence:** Campaign estimated 1 session, completed in 1 session. All phase end conditions passed on first attempt.
- **Applies when:** Work with detailed plans that include specific implementation choices. Don't over-estimate — a well-researched plan executes fast.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| NVD CPE API 2.0 (not deprecated JSON feeds) | Old JSON feeds deprecated since 2024, API is maintained | Correct — API works, paginated download functional |
| Background download at startup (non-blocking) | Dictionary is ~1M entries, would block first SBOM scan for minutes | Correct — first scan works immediately, dictionary loads in background |
| Confidence in metadata JSONB (not new DB columns) | Avoids Alembic migration, metadata already returned in API | Correct — zero migration, computed fields expose data cleanly |
| 85% threshold for auto-enrich, 70% for suggest | Per the research plan, prevents false positive CPEs | Untested with real NVD data yet — threshold may need tuning |
| Singleton service with Redis cache (7-day TTL) | Avoids re-downloading on every restart | Correct — Redis cache survives container restarts |
