# Patterns: Session 34 — Upload 413 Debugging

> Extracted: 2026-04-13
> Campaign: ad-hoc debugging (no formal campaign)
> Postmortem: none

## Successful Patterns

### 1. Read nginx error logs first for HTTP 4xx
- **Description:** For any HTTP error from the frontend proxy, `docker compose logs frontend` contains the exact nginx error with body size, client IP, and request path. This immediately identified the 1.14GB body vs 500MB limit.
- **Evidence:** Nginx log line: "client intended to send too large body: 1192729737 bytes" — resolved root cause in one query.
- **Applies when:** Any HTTP error that could originate from the nginx reverse proxy (4xx, 502, 504).

### 2. Trace the full request path before assuming the bottleneck
- **Description:** The 413 could have come from nginx, uvicorn, or the application's own size check. Verifying the nginx rendered config (`client_max_body_size 500M`) and the backend env var (`MAX_UPLOAD_SIZE_MB=500`) confirmed the limit was consistent but too low.
- **Evidence:** Checked nginx config, backend config.py, and env vars before making changes.
- **Applies when:** Size limit or timeout errors where multiple layers (proxy, app server, application) could be the source.

### 3. Update all coordinated defaults when changing a limit
- **Description:** MAX_UPLOAD_SIZE_MB appeared in 4 places: backend/app/config.py (Python default), frontend/Dockerfile (ENV default), .env.example (documentation), .env (runtime). All needed updating for consistency.
- **Evidence:** First rebuild only updated backend+worker but frontend still had 500M because the Dockerfile ENV and .env hadn't changed.
- **Applies when:** Any configuration value that appears as a default in multiple Dockerfiles, config files, and env examples.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Raise limit to 2048MB (2GB) not just 1200MB | Android tablet firmware images commonly reach 1-2GB; a tight limit would cause repeat failures | Correct — provides headroom for full system dumps |
| Update Dockerfile ENV default, not just .env | .env overrides at runtime, but if .env is missing or reset the Dockerfile default should also be correct | Prevented future confusion if .env is regenerated |
