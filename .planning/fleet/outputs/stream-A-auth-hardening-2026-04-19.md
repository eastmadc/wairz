# Stream A — Auth Hardening (B.1.a/b/c) Handoff
**Campaign:** wairz-intake-sweep-2026-04-19
**Date:** 2026-04-19
**Branch:** clean-history

---

## Commits Made

| SHA | Scope |
|-----|-------|
| `de3f6bd` | feat(security): B.1.a/b — startup auth guard + slowapi rate limiting |

Note: B.1.c (streaming upload-size check) was already present in commit `ab09e1c` (safe_extract_zip PR). The streaming `file_size > max_bytes` guard was confirmed live and working. No duplicate work needed.

---

## Files Touched

| File | Change |
|------|--------|
| `backend/app/config.py` | Added `allow_no_auth: bool` field with `AliasChoices` accepting `WAIRZ_ALLOW_NO_AUTH` or `ALLOW_NO_AUTH`. Added `from pydantic import AliasChoices, Field` import. |
| `backend/app/main.py` | Added lifespan assert (B.1.a). Added `SlowAPIMiddleware`, `_rate_limit_exceeded_handler`, `app.state.limiter` setup (B.1.b). Imports `limiter` from `app.rate_limit`. |
| `backend/app/rate_limit.py` | NEW. Shared `Limiter(key_func=get_remote_address, default_limits=["100/minute"])` instance. Avoids circular import with `main.py`. |
| `backend/app/routers/firmware.py` | Added `@limiter.limit("5/minute")` on `upload_firmware`. Added `Request` param (slowapi requires it). |
| `backend/app/routers/events.py` | Added `@limiter.limit("10/minute")` on `stream_events`. Imports `limiter` from `app.rate_limit`. |
| `backend/pyproject.toml` | Added `"slowapi>=0.1.9"` to dependencies. |

---

## Verification Results

| # | Test | Result |
|---|------|--------|
| 1a | No API_KEY + WAIRZ_ALLOW_NO_AUTH=false → stderr error + exit | PASS |
| 1b | WAIRZ_ALLOW_NO_AUTH=true + no API_KEY → starts healthy | PASS |
| 2 | 6th firmware upload/minute → 429 Too Many Requests | PASS |
| 3 | 2MB upload to 1MB-limit server → 413 (streaming check) | PASS |
| 4a | No key → 401 (B.1 regression) | PASS |
| 4b | Valid X-API-Key → 200 with projects (B.1 regression) | PASS |
| 5 | DPCS10 canary: firmware_id 0ed279d8 → 260 blobs | PASS |
| 6 | `import app.main` in container → clean | PASS |

---

## Rule-8/20 Rebuild Gotchas

- **Rule 20 (class-shape change):** `config.py` gained `allow_no_auth` field (pydantic `BaseSettings` behind `@lru_cache`). Two `docker compose restart backend worker` calls were needed — once after initial `docker cp`, once after adding `AliasChoices`. Both times health came back within 5s (no image-layer change, just process restart).
- **Rule 8 (worker rebuild):** `docker compose restart backend worker` used (not just backend) for both restarts. Worker container confirmed Up after each restart.
- **slowapi install:** Not yet in the container image. Installed via `/app/.venv/bin/pip install slowapi` inside the running container for validation. A full `docker compose up -d --build backend worker` is required before the next session to bake it into the image layer. The pyproject.toml entry is committed; the build will pick it up correctly.

---

## Estimated Cost

- ~45 min elapsed (B.1.a + B.1.b combined; B.1.c was pre-done)
- ~1 stream session (this agent)
- ~2k tokens execution overhead

---

## Next Steps for Incoming Session

1. **Run `docker compose up -d --build backend worker`** — bakes `slowapi` into the container image. The `docker cp`/`pip install` approach used here is for validation speed only (rule 20); it is NOT durable state.
2. **B.2 — Fuzzing shell injection:** `fuzzing_service.py:532,827` + `emulation_service.py:1383`. Replace `sh -c f"..."` with `put_archive` + `exec_run(["sh", file])`. 2-3 hours.
3. **B.3 — Android/ZIP safe-extract:** `unpack_android.py:503,525` + `unpack_common.py:265`. New `workers/safe_extract.py`. 3-4 hours.
