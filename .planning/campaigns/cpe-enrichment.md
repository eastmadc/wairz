---
Status: completed
Direction: Add NVD CPE dictionary fuzzy matching with rapidfuzz, enrichment confidence scoring, and frontend confidence badges
Estimated Sessions: 1
Type: build
---

# Campaign: CPE Enrichment

## Direction

Upgrade SBOM CPE enrichment from static vendor map + name normalization to NVD CPE
dictionary fuzzy matching via rapidfuzz, add enrichment source tracking and confidence
scoring, and show confidence badges in the frontend.

## Phases

| # | Type | Description | Status |
|---|------|-------------|--------|
| 1 | build | CPE dictionary service + rapidfuzz integration | complete |
| 2 | build | Enrichment confidence scoring + model/schema/API updates | complete |
| 3 | build | Frontend confidence badges on SBOM components | complete |
| 4 | verify | End-to-end verification | complete |

## Phase End Conditions

| Phase | Condition | Type | Result |
|-------|-----------|------|--------|
| 1 | `backend/app/services/cpe_dictionary_service.py` exists | file_exists | PASS |
| 1 | `rapidfuzz` in pyproject.toml dependencies | command_passes | PASS |
| 1 | `_enrich_cpes()` calls dictionary service for fuzzy matching | manual | PASS |
| 2 | SbomComponent metadata tracks enrichment_source | manual | PASS |
| 2 | SBOM API response includes enrichment_source and cpe_confidence computed fields | manual | PASS |
| 3 | SBOM components page shows confidence badge (green/yellow/red) | manual | PASS |
| 4 | TypeScript check passes (0 errors) | command_passes | PASS |
| 4 | 353 backend tests pass, 0 regressions | command_passes | PASS |

## Feature Ledger

| Feature | Phase | Status | Files |
|---------|-------|--------|-------|
| CpeDictionaryService with NVD API 2.0 download | 1 | done | `services/cpe_dictionary_service.py` |
| rapidfuzz fuzzy matching (token_sort_ratio, 85% auto-enrich threshold) | 1 | done | `services/cpe_dictionary_service.py` |
| Redis-backed dictionary cache (7-day TTL) | 1 | done | `services/cpe_dictionary_service.py` |
| Background dictionary loading at startup | 1 | done | `main.py` |
| CPE dictionary status + reload REST endpoints | 1 | done | `routers/sbom.py` |
| rapidfuzz added to pyproject.toml | 1 | done | `pyproject.toml` |
| 5-strategy enrichment pipeline (direct, local_fuzzy, nvd_fuzzy, inherited, android_sdk) | 2 | done | `services/sbom_service.py` |
| enrichment_source + cpe_confidence metadata on every component | 2 | done | `services/sbom_service.py` |
| SbomComponentResponse computed fields (enrichment_source, cpe_confidence) | 2 | done | `schemas/sbom.py` |
| EnrichmentSource TypeScript type | 3 | done | `types/index.ts` |
| CPE confidence badge (green/yellow/red) on SBOM component list | 3 | done | `pages/SbomPage.tsx` |
| Enrichment source + confidence in expanded component detail | 3 | done | `pages/SbomPage.tsx` |

## Decision Log

| Decision | Reason |
|----------|--------|
| NVD CPE API 2.0 (not deprecated JSON feeds) | Feeds deprecated, API is current and maintained |
| Background download at startup (non-blocking) | Dictionary is large (~1M entries), don't block SBOM generation |
| Confidence in metadata JSONB (not new columns) | Avoids migration, metadata already returned in API, computed fields extract it |
| 85% threshold for auto-enrich, 70% for suggest | Matches plan, prevents false positive CPEs from polluting results |
| Singleton service with Redis cache | Avoids re-downloading dictionary on every scan |

## Active Context

All 4 phases complete. TypeScript clean, 353 backend tests pass (0 regressions).
