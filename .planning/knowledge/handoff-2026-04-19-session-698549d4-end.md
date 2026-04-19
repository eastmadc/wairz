# Session Handoff — 2026-04-19 (session 698549d4)

> Outgoing: Opus 4.7 (1M context), effort=max
> Branch: `clean-history` (1 new commit this session, 147 total ahead of main)
> Baseline HEAD at session start: `238400f`
> Predecessor handoff: `.planning/knowledge/handoff-2026-04-18-session-59045370-end.md` (session 59045370)

---

## Starter prompt for the next session (paste as first message)

```
Resume from session 698549d4. 148 commits ahead of main on branch clean-history.
Read these files in order:

  1. .planning/knowledge/handoff-2026-04-19-session-698549d4-end.md
     — full session manifest: B.1 pure-ASGI auth middleware shipped
       (commit 3d8aa10), network → code-layer auth coverage, all prior
       handoff follow-ons still accurate.

  2. Skim-only:
     .planning/knowledge/security-auth-b1-asgi-middleware-2026-04-19-patterns.md
     for the 7 successful patterns / 5 anti-patterns / 7 decisions from B.1.

  3. CLAUDE.md rules 1-22 canonical. `.mex/context/conventions.md` Verify
     Checklist is the derived task-time gate (Rule 21 keeps them in sync).
     `.mex/ROUTER.md` Current Project State refreshed end-of-session.

Current state (verified live at handoff):
  - Backend healthy: /health 200, /health/deep 200 all four checks
    (db+redis+docker+storage).
  - Auth LIVE: `curl -H "X-API-Key: dev-test-key-wairz-b1" ...` returns
    200, no key returns 401. WebSocket /ws returns close code 4401 on
    auth failure, opens with key.
  - DPCS10 canary (firmware 0ed279d8): 260 blobs.
  - Bundle: `index-*.js` served with Cache-Control: public, max-age=
    31536000, immutable; index.html with no-cache.
  - docker-compose.override.yml (gitignored) keeps 0.0.0.0 bind on
    backend+frontend + injects API_KEY=dev-test-key-wairz-b1 and
    build-args VITE_API_KEY. Safe now that B.1 covers both scopes;
    for production deploy, delete the override, set strong API_KEY in
    .env, and keep 127.0.0.1 bind.
  - Frontend container marked "unhealthy" by Docker — cosmetic, known
    bug: healthcheck uses `wget localhost:3000` which resolves to
    IPv6 ::1 while nginx listens IPv4 only. Trivial Dockerfile fix.

What's left, in priority order:

  B.1.a/b/c — complete the auth-hardening parent intake:
      B.1.a  Require API_KEY unless WAIRZ_ALLOW_NO_AUTH=true. Pydantic
             `api_key: str | None = None` already in place (commit 3d8aa10);
             add the lifespan assert in `backend/app/main.py:17-48` per the
             parent intake `security-auth-hardening.md` Step 2. ~40 min.
      B.1.b  slowapi rate limiting: `uv add slowapi`, Limiter in main.py,
             strict limits on upload + SSE endpoints. 1-2 hours.
      B.1.c  Streaming upload-size check in firmware_service.py — abort
             mid-transfer when chunk sum exceeds MAX_UPLOAD_SIZE_MB. 30-60
             min.

  B.2 — Fuzzing shell injection (3 sites): `fuzzing_service.py:532,827`
        + `emulation_service.py:1383`. Replace `sh -c f"..."` with
        `put_archive` + `exec_run(["sh", file])`. Add CI grep:
        `grep -rn 'sh", "-c",\s*f"' backend/app/services/ → 0 hits`.
        2-3 hours.

  B.3 — Android / ZIP safe-extract: `unpack_android.py:503,525` +
        `unpack_common.py:265` skip per-entry realpath + bomb checks +
        symlink-attr check (info.external_attr >> 16 & 0o170000 == 0o120000).
        New `workers/safe_extract.py`. 3-4 hours.

  C — Hardware firmware expansion (1-2 sessions, use /archon):
      C.1 Qualcomm Adreno GPU + WCNSS Wi-Fi (~200 LOC).
      C.2 Samsung Shannon modem (~120 LOC).
      C.3 Broadcom/Cypress Wi-Fi enhancement (~80 LOC).

  Smaller one-session options:
      D  arq cron for orphan emulation/fuzzing container reaping.
      E  pagination on sbom/attack_surface/security_audit list endpoints.
      F  LATTE LLM taint-analysis MCP tools (research-heavy).
      G  backend god-class decomposition (multi-day).

  Minor one-line fix:
      Frontend Dockerfile healthcheck: `localhost` → `127.0.0.1` to end
      the "unhealthy" cosmetic label. ~1 line, can fold into maintenance.

Ask me ONE question: which scope (B.1.a/b/c, B.2, B.3, C, D, E, F, G,
or maintenance sweep)? Execute without interview once I name one.
```

---

## What shipped this session (by commit)

| SHA | Scope |
|---|---|
| `3d8aa10` | feat(security): B.1 pure-ASGI auth middleware — http + websocket scopes (closes the code-layer gap that A.1 mitigated at the network layer) |

Plus uncommitted session artifacts:
- `.planning/knowledge/security-auth-b1-asgi-middleware-2026-04-19-patterns.md` — /learn extraction
- `.planning/knowledge/handoff-2026-04-19-session-698549d4-end.md` — this file
- `.mex/ROUTER.md` — Current Project State refresh
- `docker-compose.override.yml` — NOT committed (gitignored); carries 0.0.0.0 bind + dev API_KEY

## State of the system (end of session)

| Metric | Value |
|---|---|
| Backend health | healthy — /health 200, /health/deep 200 (db+redis+docker+storage) |
| Backend bind | `0.0.0.0:8000` via `docker-compose.override.yml` (auth covers both scopes; LAN re-expose now code-safe) |
| Frontend bind | `0.0.0.0:3000` — bundle `index-3kZyRoWG.js` (as of handoff time — will rotate on future rebuilds) |
| Frontend Docker health | marked `unhealthy` (cosmetic; wget uses IPv6 `localhost`, nginx is IPv4-only) |
| Auth — http | X-API-Key header → 200. No key → 401. Wrong key → 401. Query `?api_key=` → 200. |
| Auth — websocket | Missing/wrong key → close code **4401** reason `unauthenticated`. Valid key → accept. |
| Health exemptions | `/health`, `/health/deep`, `/api/v1/health` bypass middleware |
| Config type | `api_key: str \| None = None` (was `str = ""`) |
| DB | 7 projects; DPCS10 `0ed279d8` canary: 260 blobs |
| CLAUDE.md | 22 learned rules, unchanged this session |
| `.mex/ROUTER.md` | Current Project State refreshed; rules-22 count still correct |
| Quality rules in harness.json | 15 total; `auto-session-b1-no-basehttpmiddleware-in-auth-dir` DRAFTED in the patterns file, NOT appended (protect-files hook blocks writes to harness.json; manual add pending) |
| Knowledge base | 1 new pattern file this session (B.1) plus this handoff |

## B.1 implementation details (for future reference)

**Files touched (commit 3d8aa10):**
- `backend/app/middleware/asgi_auth.py` — NEW. `APIKeyASGIMiddleware`, pure ASGI, handles http + websocket scopes in `__call__`. Key sources: `X-API-Key` header, `api_key` query param. Exempt paths: `/health`, `/health/deep`, `/api/v1/health`. CORS `OPTIONS` passes. Http fail → 401 JSON. WS fail → `websocket.accept` THEN `websocket.close(code=4401, reason="unauthenticated")` so browsers see `CloseEvent.code=4401` (pre-accept close collapses to HTTP 403 / code 1006).
- `backend/app/middleware/auth.py` — DELETED. Was `BaseHTTPMiddleware`; no other callers.
- `backend/app/main.py` — import + `add_middleware` swap. Comment updated.
- `backend/app/config.py` — `api_key: str = ""` → `api_key: str | None = None`. Class-shape change → rebuild required (rule 20 class-shape exception).
- `frontend/src/api/client.ts` — `getApiKey()` reads `localStorage.wairz.apiKey` first, then `import.meta.env.VITE_API_KEY`. `appendApiKey(url)` for WS URL builders. **Axios per-request interceptor** replaces the module-load `defaults.headers.common[...]` approach — eliminates the alternating-401 race class.
- `frontend/src/api/terminal.ts`, `frontend/src/api/emulation.ts` — WS URL builders wrap in `appendApiKey(...)`.
- `frontend/Dockerfile` — `ARG VITE_API_KEY=""` + `ENV VITE_API_KEY=${VITE_API_KEY}` in the build stage. Pipes compose build args into the static bundle at build time (Vite needs build-time env, NOT runtime).
- `frontend/nginx.conf.template` — explicit Cache-Control: `/index.html` no-cache/no-store/must-revalidate; `/assets/*` public max-age=31536000 immutable. Prevents stale-client 401s across rebuilds.

**Gotchas discovered mid-build (documented in the /learn patterns file):**
1. First WS implementation did `websocket.close` before `websocket.accept` — collapsed to HTTP 403, hid the 4401 code from browsers. Fixed with accept-then-close.
2. First docker-compose override had `ports:` without `!override` tag — Compose APPENDED to the base list, producing double-bind. `docker compose config` revealed the merge; fix was the `!override` yaml tag.
3. First attempt set `VITE_API_KEY` under `services.frontend.environment:` — doesn't bake into the static bundle because Vite reads env at build time. Required Dockerfile ARG + compose `build.args`.
4. Module-load-time axios defaults produced alternating 200/401 pattern in backend logs. Fixed with per-request interceptor.
5. Stale browser bundle (`index-DYkf3PdW.js`) sent requests without `X-API-Key` — corp proxy / Chrome cached old index.html across rebuilds. Fixed with explicit Cache-Control on index.html.

## Acceptance tests (all passing at handoff)

| # | Test | Result |
|---|---|---|
| 1 | HTTP no key | 401 |
| 2 | HTTP X-API-Key header | 200 |
| 2b | HTTP `?api_key=` query | 200 |
| 2c | HTTP wrong key | 401 |
| 3 | `/health` unauth | 200 |
| 3b | `/health/deep` unauth | 200 |
| 4 | WS no key | close 4401 "unauthenticated" |
| 4b | WS wrong key | close 4401 "unauthenticated" |
| 5 | WS good key | OPEN (router 4004 on zero-UUID) |
| 6 | Browser end-to-end | `/api/v1/projects` 200, 7 projects |
| 7 | DPCS10 canary | 260 blobs |

## Open threads

1. **B.1.a — require API_KEY unless `WAIRZ_ALLOW_NO_AUTH=true`**
   - Parent intake `security-auth-hardening.md` Step 2.
   - Add `allow_no_auth: bool = False` to `config.py`, add the
     lifespan assert in `main.py:17-48`.
   - Will fail-fast on fresh-checkout deploys without an API_KEY.
   - ~40 min.

2. **B.1.b — slowapi rate limiting**
   - Parent intake Step 3. `uv add slowapi`, `Limiter(key_func=
     get_remote_address)`, default `100/minute`, upload `5/minute`,
     SSE `10/minute`. In-memory backend (Redis is optional — if down,
     the app still works per the existing "polling fallback"
     discipline).
   - 1-2 hours.

3. **B.1.c — streaming upload-size check**
   - Parent intake Step 4. In `firmware_service.py` upload path,
     accumulate `file_size += len(chunk)`, raise
     `HTTPException(413, ...)` if `> max_bytes`. Saves disk on
     runaway uploads.
   - 30-60 min.

4. **Frontend healthcheck cosmetic fix** — change `localhost` to
   `127.0.0.1` in `frontend/Dockerfile`'s `HEALTHCHECK` (if any) or
   in the compose healthcheck (currently `CMD-SHELL wget -qO
   /dev/null http://localhost:3000/ || exit 1`). One-line fix.

5. **`.claude/harness.json` quality-rule append** — blocked by
   `protect-files` hook in this session. Draft rule content lives
   at the bottom of
   `.planning/knowledge/security-auth-b1-asgi-middleware-2026-04-19-patterns.md`.
   Paste into `qualityRules.custom` in a session where the hook
   permits or via direct edit.

6. **docker-compose.override.yml transition plan** — for prod
   deploy: delete the override, set strong API_KEY in `.env`, keep
   `BACKEND_HOST_BIND=127.0.0.1` + reverse proxy with TLS.

## Verification gate for the next session

Always-run:
- `docker compose ps` — all Up (frontend "unhealthy" is cosmetic).
- `curl -sf http://127.0.0.1:8000/health` → 200.
- `curl -sI http://127.0.0.1:8000/api/v1/projects` → 401 (auth live).
- `curl -sf -H "X-API-Key: dev-test-key-wairz-b1" http://127.0.0.1:8000/api/v1/projects` → 200.
- DPCS10 canary: `docker compose exec postgres psql -U wairz -d wairz -tAc "SELECT COUNT(*) FROM hardware_firmware_blobs WHERE firmware_id='0ed279d8-8e66-4724-a3b5-8c574e11c6de'"` → `260`.

## Rollback safety

All commits are additive. Baseline for rollback is `238400f`
(pre-session HEAD). No destructive schema changes. If B.1 needs to
be reverted:
- `git revert 3d8aa10`
- `docker compose up -d --build backend worker frontend`
- Restore or keep `docker-compose.override.yml` — without B.1
  middleware the `/ws` endpoint is back to unauthenticated on LAN;
  suggest also reverting the override to restore 127.0.0.1 bind.

## For the incoming Citadel session

Entry points:
- `/do` — routed work
- `/autopilot` — intake-item execution
- `/archon` — multi-session campaigns (Option B.2/B.3 or Option C)
- `.mex/ROUTER.md` — forward-task navigation for a specific task type
- This handoff + the B.1 pattern file from this session

The B.1.a/b/c follow-ons are best executed as a bundle — same
middleware + config touches, same test battery shape. Budget
~3-4 hours for all three in one commit with clear intake-per-step
acceptance grep. Alternative: B.2 is independently scoped and
higher blast-radius (shell injection), might be the right next
priority if a security sweep beat goes first.
