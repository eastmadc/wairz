# Stream Zeta — Wave 2 Handoff (Frontend API Client Hardening)

Session: 2026-04-19 · Parent: `clean-history` · Start HEAD: `4cc5354` · End HEAD: `a01236f`

## Research (Phase 1 summary)

- `client.ts` baseline: 53 lines. Already had a request interceptor that reads `getApiKey()` fresh per call (A2 already solved for localStorage rotation; Vite env changes remain a dev-server-restart thing — not ours to fix). Response interceptor was a bare `console.error` + reject.
- **EventSource sites:** 2 — `useEventStream.ts:48` + `SecurityScanPage.tsx:131`. Both already used a local `API_BASE = import.meta.env.VITE_API_URL || ''`. Intake description of "hard-coded /api/v1" at `SecurityScanPage.tsx:129` was **outdated** — someone already patched it. Migration was to centralise the helper, not fix a bug.
- **Raw `/api/v1/` URL builders:** 5 (downloads) + 3 (WS URLs). Migrated all 5 download-URL builders (`files.ts:53`, `documents.ts:92`, `emulation.ts:286`, `hardwareFirmware.ts:203`, `HardwareFirmwarePage.tsx:298`). WS URLs left alone — they use `${host}` from `window.location.host` and changing that requires a separate WS-origin design discussion.
- **Toaster baseline:** 0 matches for `Toaster|sonner|useToast`. No existing toast infrastructure. shadcn-style UI components present in `src/components/ui/`.
- **`p-limit` / `sonner`:** `p-limit@3.1.0` was in `node_modules` transitively but not in `package.json` (phantom dep). `sonner` not installed. Added both explicitly.
- **`Promise.all` in stores (A4 scope audit):** only one site — `vulnerabilityStore.ts:125`. Page-level `Promise.all`s in `HardwareFirmwarePage`, `SbomPage`, `BinaryTabs` are fixed-N bounded (3-4 concurrent), out of scope.

Full research in `.planning/fleet/outputs/stream-zeta-2026-04-19-research.md`.

## Plan (Phase 2)

Three commits:
1. `feat(frontend): API_BASE helper + apiUrl() + migrate drift sites` — `api/config.ts` + 7 file migrations.
2. `feat(frontend): axios interceptors — toast on network/401/403/5xx + dedupe` — sonner mount + client.ts rewrite.
3. `feat(frontend): bound vulnerabilityStore.bulkResolve via p-limit` — A4.

## Commits shipped

| Commit | SHA | Description |
|--------|-----|-------------|
| 1 | `e8548fd` (swept) | Drift-site migrations — `frontend/src/api/config.ts` (NEW), `useEventStream.ts`, `SecurityScanPage.tsx`, `files.ts`, `documents.ts`, `emulation.ts`, `hardwareFirmware.ts`, `HardwareFirmwarePage.tsx` |
| 2 | `bfbfa91` | Axios interceptors + sonner toast + 10s-window dedupe + Toaster component mount |
| 3 | `a01236f` | `bulkResolve` chunked to `pLimit(5)` + `Promise.allSettled` + partial-failure toast |

**Cross-stream interleaving:** commit 1's content (8 files, ~60 LOC) was swept into Stream Epsilon's `e8548fd` ("arq cron jobs") commit before I could stage. My `git add <paths>` succeeded, but by `git commit` time the files were already in Epsilon's tree (Wave-1 learning #1 reproduced live — worktree isolation is not working-tree isolation). Content is correct and in HEAD; just attributed to another commit. No rollback or rework needed — `git show --stat e8548fd` confirms my files are there. Followed discipline by specific-path staging for commits 2 and 3, which landed cleanly as their own commits.

## Verification matrix

| Check | Command | Result |
|-------|---------|--------|
| Rule-17 canary | `echo '...' > __wairz_zeta.ts; npx tsc -b --force` | `error TS2322: Type 'string' is not assignable to type 'number'` — **CANARY OK** (tsc is actually checking) |
| Typecheck clean | `npx tsc -b --force` | **EXIT=0** |
| Production build | `npm run build` | `built in 5.89s` — 19 chunks in `dist/assets/*.js`, largest 398KB (index) + 335KB (xterm) — **OK** |
| EventSource via `apiUrl` | `grep 'new EventSource(' → 2 sites, both constructed from `apiUrl(...)` above the call | **PASS** |
| Raw `/api/v1/` strings | `grep "'/api/v1/\|\"/api/v1/" frontend/src/ \| grep -v node_modules` | **0 matches** (intake acceptance #3) |
| `Promise.all` in stores | `grep 'Promise\.all(' frontend/src/stores/` | **0 matches** (intake acceptance #4 — bulkResolve now uses `Promise.allSettled` + `pLimit`) |
| Backend `/health` | `curl -sf http://127.0.0.1:8000/health` | `{"status":"ok",...}` |
| Backend `/health/deep` | with `X-API-Key` | all 4 checks (db/redis/docker/storage) `ok: True` |
| Auth matrix — noauth | `curl -sI /api/v1/projects` | `401` |
| Auth matrix — with key | `curl -s -H X-API-Key:... /api/v1/projects` | `200` (GET) |
| DPCS10 canary | Postgres `COUNT(*) FROM hardware_firmware_blobs` | `260` (baseline preserved) |

## Deviations from plan

- **No `Toaster.tsx` via shadcn wrapper.** Chose `sonner` over adding the shadcn-cli toast because shadcn's toast is now deprecated in favour of sonner. `components/Toaster.tsx` is a thin wrapper that sets project-wide defaults (`position=top-right`, `richColors`, `closeButton`, 5s duration). Result: a single component + direct `import { toast } from 'sonner'` at any call site.
- **Dedupe is 10s-per-category, not per-call.** Intake said "at most 1 auth-failed per 10s." Implemented as a module-level `Record<'network'|'auth'|'forbidden'|'server', number>` timestamp map in `client.ts`. Extension: adding a category is one line.
- **Axios timeout set to 30s.** Intake didn't specify. 30s matches the `MAX_TOOL_OUTPUT_KB`-style defaults across Wairz; `ECONNABORTED` is caught as a distinct "Request timed out" path so users can tell a timeout apart from a network outage.
- **Commit 1 landed inside Stream Epsilon's commit, not as its own commit** (see "Cross-stream interleaving" above). Content-correct; attribution-wrong. Not a bug, but a process artefact worth noting for the campaign postmortem.

## Follow-ups (noted but not implemented)

1. **Backend bulk-update endpoint** — intake explicitly mentions `POST /api/v1/projects/{id}/sbom/vulnerabilities/bulk-update` as the long-term fix (collapses N round-trips to 1, single DB transaction). Current `bulkResolve` is a client-side stopgap. Queue for a future backend stream.
2. **WebSocket URL origin consistency** — `api/terminal.ts:7`, `api/emulation.ts:93,200` build WS URLs from `window.location.host` directly. If `VITE_API_URL` ever points to a cross-origin backend, WS routing breaks silently. Needs a `wsUrl()` helper + WS-origin decision (keep using `window.location.host`, or derive from `VITE_API_URL`?). Separate intake worth.
3. **`appendApiKey` → `apiUrl` split audit** — `appendApiKey` is used only for WS URLs (browser can't set headers on WS upgrade). `apiUrl` is for HTTP SSE + downloads. Document this split somewhere to prevent the next agent from "consolidating" them.

## Files touched (final list)

- `frontend/src/api/client.ts` (rewrite — interceptors + dedupe)
- `frontend/src/api/config.ts` (NEW)
- `frontend/src/api/files.ts` (one-line download-URL migration)
- `frontend/src/api/documents.ts` (one-line migration)
- `frontend/src/api/emulation.ts` (one-line migration — pcap)
- `frontend/src/api/hardwareFirmware.ts` (one-line migration — blob download)
- `frontend/src/hooks/useEventStream.ts` (SSE URL via `apiUrl`)
- `frontend/src/pages/SecurityScanPage.tsx` (SSE URL via `apiUrl`)
- `frontend/src/pages/HardwareFirmwarePage.tsx` (hbomUrl via `apiUrl`)
- `frontend/src/stores/vulnerabilityStore.ts` (bulkResolve chunking)
- `frontend/src/components/Toaster.tsx` (NEW)
- `frontend/src/App.tsx` (`<Toaster />` mount)
- `frontend/package.json` + `frontend/package-lock.json` (+ sonner, p-limit)

**Touched zero Beta-owned files** (`api/{sbom,findings,projects,attack_surface,security_audit}.ts`).
