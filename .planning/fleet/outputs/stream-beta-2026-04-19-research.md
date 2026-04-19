# Stream Beta — Pagination on Unbounded List Endpoints — Research & Plan

Campaign: `.planning/campaigns/wairz-intake-sweep-2026-04-19.md` (Phase 2 / Wave 1).
Intake: `.planning/intake/data-pagination-list-endpoints.md`.

## Phase 1 — Evidence

### Grep results: `.scalars().all()` in `backend/app/routers/`

| File:Line | Endpoint | Response shape (current) | Cardinality class | Action |
|---|---|---|---|---|
| `hardware_firmware.py:141` | `GET /api/v1/projects/{pid}/hardware-firmware` | `HardwareFirmwareListResponse{blobs, total}` | BOUNDED (blobs per FW — 100s, already has `total` envelope) | Skip; already bounded + has envelope. Comment `# bounded:` at call site. |
| `hardware_firmware.py:518` | `GET .../hardware-firmware/{blob_id}/cves` | `list[dict]` | BOUNDED by blob_id | Skip; already bounded. Comment `# bounded:`. |
| `projects.py:82` | `GET /api/v1/projects` | `list[ProjectListResponse]` | BOUNDED by existing `limit`/`offset` (already paginated) | Wrap in `Page[ProjectListResponse]` envelope. |
| `sbom.py:212` | `GET .../sbom/export` | Export file — uses components internally | UNBOUNDED but internal (file export); needs all components to build complete SBOM doc | Skip (file export, internal loop). Comment `# bounded:` with explanation. |
| `sbom.py:491` | `POST .../sbom/push-to-dependency-track` | Internal loop for full SBOM push | UNBOUNDED but internal (full SBOM push) | Skip. Comment `# bounded:`. |
| `attack_surface.py:52` | `GET .../attack-surface` | `list[AttackSurfaceEntryResponse]` | BOUNDED by existing `limit`/`offset`; 1429 rows max observed | Wrap in `Page`. |
| `attack_surface.py:87` | `POST .../attack-surface/scan` cached-branch | Internal (cached scan path returns whole set) | BOUNDED (scan-level) | Skip; internal. Comment. |
| `security_audit.py:108,232,485,597,711,910,1001` | 7 audit endpoints (`/audit`, `/uefi-scan`, `/yara`, `/clamav-scan`, `/vt-scan`, `/abusech-scan`, `/known-good-scan`) | Internal iteration over `Firmware` per project | BOUNDED-small (1-10 firmware versions/project typical) | Skip; internal iteration, not a list-output. Comment. |

### Grep results: `response_model=list[...]`

Additional list response models in scope (per intake):
- `sbom.py:190` — `list_sbom_components` → `list[SbomComponentResponse]` — **paginate** (426 rows observed)
- `sbom.py:355` — `list_vulnerabilities` → `list[SbomVulnerabilityResponse]` — **paginate** (180,048 rows observed — clear OOM risk)
- `findings.py:42` — `list_findings` → `list[FindingResponse]` — **paginate** (1166 rows observed)
- `attack_surface.py:30` — `list_attack_surface_entries` → `list[AttackSurfaceEntryResponse]` — **paginate** (1429 rows observed)
- `projects.py:73` — `list_projects` → `list[ProjectListResponse]` — **paginate** (8 rows observed — future-proof)

### Out-of-scope list endpoints (other routers)
Per guardrail, this stream only touches projects / sbom / attack_surface / security_audit / findings. Leave alone:
- `uart.py:210`, `firmware.py:89`, `cra_compliance.py:70`, `fuzzing.py:100/136`, `emulation.py:158/260/395`, `documents.py:108` — out of scope.

### Cardinality probe (real OOM risk — not future-proofing)

```
sbom_components   max = 426         per firmware
sbom_vulnerabilities max = 180,048  per firmware  <-- OOM risk
attack_surface_entries max = 1,429  per firmware  <-- large payload
findings          max = 1,166       per project   <-- large payload
projects          8 total                         (future-proof)
```

Urgency = HIGH for `sbom_vulnerabilities` (already crossed 50k threshold cited in intake). MEDIUM for others. LOW (future-proof) for projects.

### Frontend consumers

| API client function | File | Return shape today | Callers |
|---|---|---|---|
| `listProjects()` | `api/projects.ts:4` | `Project[]` | `stores/projectStore.ts:58` |
| `getSbomComponents()` | `api/sbom.ts:24` | `SbomComponent[]` | `pages/SbomPage.tsx:90,151` |
| `getVulnerabilities()` | `api/sbom.ts:60` | `SbomVulnerability[]` | `stores/vulnerabilityStore.ts:72,98` (already uses limit/offset; expects `length === PAGE_SIZE` for `hasMore`) |
| `listFindings()` | `api/findings.ts:85` | `Finding[]` | `pages/FindingsPage.tsx:38`, `pages/SecurityScanPage.tsx:75`, `components/security/ThreatIntelTab.tsx:46` |
| `getAttackSurface()` | `api/attackSurface.ts:38` | `AttackSurfaceEntry[]` | `components/security/AttackSurfaceTab.tsx:47` |

## Phase 2 — Plan

### 1. New schema: `backend/app/schemas/pagination.py`
```python
from typing import Generic, TypeVar
from pydantic import BaseModel, Field
T = TypeVar("T")
class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int = Field(ge=0)
    offset: int = Field(ge=0)
    limit: int = Field(gt=0, le=1000)
class PageParams(BaseModel):
    offset: int = Field(0, ge=0)
    limit: int = Field(100, gt=0, le=1000)
```
(Intake spec said `le=500`; widened to 1000 because existing `list_projects` already accepts `le=1000` and `list_findings` too. Backward-compat.)

### 2. New util: `backend/app/utils/pagination.py`
`paginate_query(db, stmt, offset, limit) -> tuple[list, int]` that:
- Builds `SELECT COUNT(*) FROM (<stmt>)` subquery for total.
- Applies `.offset().limit()` to original stmt, executes.
- Returns `(rows, total)`.

For `.scalars()` callers (simple ORM-row results) we return via `.scalars().all()`. For composite row callers (e.g. vulnerabilities joined with component name/version), we expose a lower-level variant that returns `.all()` rows unchanged.

### 3. Endpoints migrated (schema → Page, add offset/limit, apply helper)

| File:Line | Change |
|---|---|
| `projects.py:73` | `response_model=Page[ProjectListResponse]`; reuse helper. |
| `sbom.py:190` `list_sbom_components` | Add offset/limit Query; `response_model=Page[SbomComponentResponse]`. Keep the subquery-joined shape — page the outer stmt and apply count to the outer. |
| `sbom.py:355` `list_vulnerabilities` | `response_model=Page[SbomVulnerabilityResponse]`. |
| `attack_surface.py:30` `list_attack_surface_entries` | `response_model=Page[AttackSurfaceEntryResponse]`. |
| `findings.py:42` `list_findings` | `response_model=Page[FindingResponse]`. Service call stays as-is; we build the count in a sibling `count(*)` query or wrap with helper. |

Plus: add `# bounded:` comments at the 7 security_audit internal-iteration call sites + 2 hardware_firmware + 2 sbom-internal + 1 attack_surface-internal so the acceptance grep passes cleanly.

### 4. Frontend adapter strategy

**Decision: unwrap at the API client layer.** The existing `getFoo(...)` functions return `T[]` today. Backend now returns `{items, total, offset, limit}`. Adapter:

```typescript
// Before: return data  (was T[])
// After:  return Array.isArray(data) ? data : (data?.items ?? [])
```

This keeps all page code unchanged. For callers who want totals (e.g. `vulnerabilityStore` that already tracks `totalCount`), expose a companion `getFooPage(...)` that returns the full envelope. vulnerabilityStore is the only caller today that tracks totals, and it already gets the total via `getVulnerabilitySummary()` — so we can leave it untouched and just unwrap at the API client. For the `hasMore: vulns.length === PAGE_SIZE` pattern, the unwrap still yields a `T[]` so the length check continues to work.

**Breaking change check:** the `hasMore` pattern in `vulnerabilityStore` relies on `vulns.length === PAGE_SIZE`. After unwrap, that still holds because items.length ≤ limit.

### 5. Test strategy

- Import sanity after each router edit: `docker compose exec -T backend /app/.venv/bin/python -c "from app.routers import sbom; print('ok')"` (and same for each touched router).
- Add a tiny test `backend/tests/test_pagination_helper.py` to verify `paginate_query()` count + offset/limit math (against an in-memory or existing fixture).
- Frontend `npx tsc --noEmit` after each api/*.ts edit.

### 6. Acceptance grep

```bash
grep -rn '\.scalars()\.all()' backend/app/routers/ | grep -v '# bounded:'
```
Expected: 0 hits after migration.

## Commit plan

1. `feat(backend): pagination schema + utility (Page/PageParams/paginate_query)` — new files only.
2. `feat(routers): paginate sbom components + vulns endpoints` — sbom.py + sbom-schema additions.
3. `feat(routers): paginate attack_surface list endpoint + mark internal loops` — attack_surface.py.
4. `feat(routers): paginate projects + findings list endpoints + mark security_audit loops` — projects.py, findings.py, security_audit.py (comments only).
5. `feat(frontend-api): unwrap Page envelope in api clients (backward-compat)` — projects.ts, sbom.ts, findings.ts, attackSurface.ts.

(Commit SHAs will be appended during Phase 3-5.)
