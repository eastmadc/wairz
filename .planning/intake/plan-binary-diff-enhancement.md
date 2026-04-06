# Plan: Binary Diff Enhancement (Tier 1-2)

**Priority:** High | **Effort:** Medium (~8h across 4 phases) | **Status:** campaign created
**Seed:** `.planning/seeds/binary-diff-enhancement.yaml`
**Campaign:** `.planning/campaigns/binary-diff-enhancement.md`
**Route:** `/citadel:archon` (4 phases: backend Tier 1, backend Tier 2, frontend, E2E verify)

## Goal

Replace broken pyelftools binary comparison with LIEF body hashing + Capstone instruction diff.
Currently `libaudiopolicyenginedefault.so` shows "no symbol-level diff available" even though
the binary clearly changed. After this work, users see exactly which functions changed and can
drill into instruction-level assembly diffs.

## Key Files
- `backend/app/services/comparison_service.py` — core diff logic
- `backend/app/routers/comparison.py` — REST endpoints
- `backend/app/schemas/comparison.py` — response models
- `frontend/src/pages/ComparisonPage.tsx` — comparison UI
- `frontend/src/api/comparison.ts` — API client
