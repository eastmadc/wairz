# Stream Zeta — Frontend API Client Hardening (Wave 2)

Session: 2026-04-19 · Parent: clean-history · Head at start: `4cc5354`

## Phase 1 — Research

### 1. Current `client.ts` shape (pre-change)

- 53 lines total.
- Already has: axios instance (`baseURL: '/api/v1'`), `getApiKey()` (localStorage → env fallback), `appendApiKey(url)` helper for WebSocket URLs, a request interceptor that injects `X-API-Key` (reads getApiKey() on every request — so A2 is effectively already handled for runtime override / env changes captured at the browser session level, modulo Vite HMR re-read), and a minimal response interceptor that `console.error`s + rejects.
- Intake A1 gap confirmed: no 401/403/5xx branch; no toast; no network-offline branch.
- Intake A2 note: the request interceptor reads `getApiKey()` fresh each call — localStorage-based rotation already works without reload. Vite env changes still require dev-server restart (Vite constraint, not ours).

### 2. Drift-site census

**EventSource sites (SSE):** 2
- `frontend/src/hooks/useEventStream.ts:48,53` — already uses `${API_BASE}`.
- `frontend/src/pages/SecurityScanPage.tsx:5,131` — already uses `${API_BASE}` via a local `const API_BASE = import.meta.env.VITE_API_URL || ''` at line 5. So the intake's "hard-coded /api/v1" claim is OUTDATED — someone already patched this. Verify + migrate to `apiUrl()` helper for DRY.

**fetch() sites:** 0 (no raw `fetch` calls outside of node_modules).

**Raw `/api/v1/` string URLs (outside axios `baseURL` scope):**
1. `api/files.ts:53` — `getFileDownloadUrl()` returns `/api/v1/...` (anchor href for downloads)
2. `api/documents.ts:92` — `getDocumentDownloadUrl()` returns `/api/v1/...` (anchor href)
3. `api/emulation.ts:286` — `getPcapDownloadUrl()` returns `/api/v1/...` (anchor href)
4. `api/hardwareFirmware.ts:203` — `buildBlobDownloadUrl()` returns `/api/v1/...` (anchor href)
5. `pages/HardwareFirmwarePage.tsx:298` — inline hbomUrl builder
6. `api/terminal.ts:7` — WS URL `${proto}//${host}/api/v1/...` (appendApiKey wrapper)
7. `api/emulation.ts:93` — WS URL (appendApiKey wrapper)
8. `api/emulation.ts:200` — WS URL (raw, no appendApiKey — separate bug, out of scope)
9. `hooks/useEventStream.ts:48` — SSE URL (uses API_BASE)
10. `pages/SecurityScanPage.tsx:131` — SSE URL (uses API_BASE)

**Scope decision (rule 22 — grep first, design from shape):**
- Download-URL builders (files/documents/emulation-pcap/hw-firmware/hbom) all return relative paths that work via same-origin deploy. They don't go through axios's `baseURL` so `VITE_API_URL` deploy-behind-different-origin breaks them, but the intake's #3 acceptance criterion is specifically about **EventSource + API_BASE consistency**. Migrating download builders is bonus. I'll migrate the two SSE sites + expose `apiUrl()` for future use, and migrate one download builder (`buildBlobDownloadUrl`, `getDocumentDownloadUrl`, `getFileDownloadUrl`, `getPcapDownloadUrl`, `hbomUrl`) as a consistency sweep since it's the same mechanical edit.
- WebSocket URL builders already use `${host}` from `window.location.host`, which by definition matches the browser's current origin. If `VITE_API_URL` points elsewhere, the WS URLs would point to the wrong host — but that's the same behaviour pre- and post-change. Out of scope for this stream (would need WS_BASE or WebSocket-origin routing; separate intake).

### 3. `bulkResolve` current shape

`frontend/src/stores/vulnerabilityStore.ts:123-138`:
```typescript
await Promise.all(
  ids.map((id) =>
    updateVulnerability(projectId, id, {
      resolution_status: status,
      resolution_justification: justification,
    })
  )
)
```
Unbounded. 100+ selected → 100 concurrent PATCHes. Single call site.

### 4. Toaster baseline

`grep -rn "Toaster|sonner|useToast" frontend/src/` returns **0 matches**. No existing toast system.

UI lib present: shadcn-compatible components in `src/components/ui/` (button, card, badge, dialog, etc.) — shadcn/ui already in the dev-deps (`shadcn: ^3.8.4`). Sonner is the shadcn-recommended toast library for React 19.

### 5. `p-limit` / `sonner` dep state

- `p-limit@3.1.0` present in `node_modules/` as a transitive dep. NOT in `package.json`. Will add explicitly to avoid "Phantom dependency" brittleness — if the parent dep drops it, our code silently breaks.
- `sonner` not installed. Will add as a direct dep.

### 6. `Promise.all` in stores (A4 scope audit per rule 22)

- `stores/vulnerabilityStore.ts:125` — unbounded over N ids (target).
- `stores/` — only this one.
- `pages/*` callers: `HardwareFirmwarePage.tsx:112,154`, `SbomPage.tsx:90,151`, `components/explorer/BinaryTabs.tsx:62` — these are **bounded** (fixed small N, ~3-4 concurrent fetches for loading a page dashboard), not a concern.

**A4 scope: bulkResolve method only, as per guardrail.**

---

## Phase 2 — Plan

### Commit 1 — `feat(frontend): API_BASE helper + apiUrl() + migrate drift sites`

**New file `frontend/src/api/config.ts`:**
```typescript
export const API_BASE: string = import.meta.env.VITE_API_URL || ''

/** Build a URL relative to the backend origin. `path` must start with '/'. */
export function apiUrl(path: string): string {
  return `${API_BASE}${path.startsWith('/') ? path : '/' + path}`
}
```

**Migrations (keep patch surface tight — SSE + download builders):**
- `hooks/useEventStream.ts` → import `{ apiUrl }`, drop local `API_BASE` const, use `apiUrl('/api/v1/projects/...')`
- `pages/SecurityScanPage.tsx` → import `{ apiUrl }`, drop local `API_BASE`, use `apiUrl(...)`
- `api/files.ts:53` `getFileDownloadUrl()` → use `apiUrl(...)`
- `api/documents.ts:92` `getDocumentDownloadUrl()` → use `apiUrl(...)`
- `api/emulation.ts:286` `getPcapDownloadUrl()` → use `apiUrl(...)`
- `api/hardwareFirmware.ts:203` `buildBlobDownloadUrl()` → use `apiUrl(...)`
- `pages/HardwareFirmwarePage.tsx:298` `hbomUrl` → use `apiUrl(...)`

### Commit 2 — `feat(frontend): toast system (sonner) + deduped error interceptor in api client`

- Add `sonner` to `package.json`, run `npm install` to refresh lockfile.
- Create `frontend/src/components/Toaster.tsx` that re-exports the sonner `<Toaster />` with project defaults.
- Mount `<Toaster />` in `App.tsx` (once, at root).
- Rewrite `client.ts` response interceptor:
  - Network error → `toast.error('Network error', 'Could not reach the backend')`
  - 401 → `toast.error('Authentication failed', ...)` (deduped)
  - 403 → `toast.error('Forbidden', ...)` (deduped)
  - 5xx → `toast.error('Server error', ...)` (deduped)
- Dedupe via module-level `lastShownAt` map keyed by toast category + 10s throttle.

### Commit 3 — `feat(frontend): bound vulnerabilityStore.bulkResolve via p-limit`

- Add `p-limit@^3.1.0` to `package.json` (already in node_modules transitively).
- Refactor `bulkResolve` to `Promise.allSettled` + `pLimit(5)` + summary toast on partial failure.

### Commit 4 — (optional) `chore(frontend): deprecate appendApiKey in favor of apiUrl for HTTP`

Skip — `appendApiKey` is only used for WebSocket URLs (browser can't set headers on WS upgrade), and its behavior (`?api_key=...` query param) is fundamentally different. Leaving alone.

---

## Scope summary (files I will touch)

Touched:
- `frontend/src/api/client.ts` (interceptor rewrite)
- `frontend/src/api/config.ts` (NEW)
- `frontend/src/hooks/useEventStream.ts`
- `frontend/src/pages/SecurityScanPage.tsx`
- `frontend/src/pages/HardwareFirmwarePage.tsx` (hbomUrl only — one-line change)
- `frontend/src/api/files.ts` (one-line change)
- `frontend/src/api/documents.ts` (one-line change)
- `frontend/src/api/emulation.ts` (one-line change — `getPcapDownloadUrl`)
- `frontend/src/api/hardwareFirmware.ts` (one-line change — `buildBlobDownloadUrl`)
- `frontend/src/stores/vulnerabilityStore.ts` (bulkResolve method only)
- `frontend/src/components/Toaster.tsx` (NEW)
- `frontend/src/App.tsx` (mount `<Toaster />`)
- `frontend/package.json` + `frontend/package-lock.json`

Total file touches: 13. None overlap with Beta's Wave-1 sbom/findings/projects/attack_surface/security_audit unwrap changes (confirmed — Beta edited `api/{sbom,findings,projects,attack_surface,security_audit}.ts`, I'm editing `api/{client,config,files,documents,emulation,hardwareFirmware}.ts` and non-api files).
