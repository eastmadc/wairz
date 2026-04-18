---
title: "Infra: Secrets Management + Safe Default Bindings"
status: partial
partial_at: 2026-04-18
partial_in: session 59045370 autopilot (commits 10872d6 + 906cfe2)
partial_scope: |
  Shipped: BACKEND_HOST_BIND/FRONTEND_HOST_BIND loopback default,
  POSTGRES_USER/PASSWORD/DB parameterization, DATABASE_URL interpolation
  in backend + worker, FIRMAE_DB_PASSWORD for system-emulation.
  Deferred (blocked by session's secrets-access hook on .env.example):
  .env.example documentation, :?error required-mode enforcement,
  frontend env_file removal, docker-compose.prod.yml with Docker secrets,
  README security section. Real auth-layer fix belongs under
  security-auth-hardening.md (Option B.1).
priority: critical
target: docker-compose.yml, .env.example, backend/app/config.py
---

## Problem

Three related infrastructure exposures.

### E1. Postgres password hardcoded as `wairz:wairz`

`docker-compose.yml:6-8`:
```yaml
POSTGRES_USER: wairz
POSTGRES_PASSWORD: wairz
```

Literal password in the compose file. Every `git clone` inherits the same credential. `DATABASE_URL` at line 59 matches. With port bound to `127.0.0.1:5432` (good) and process on the host able to open loopback sockets, any host compromise = DB access.

### E2. Backend bound to 0.0.0.0 by default

`docker-compose.yml:55`:
```yaml
ports:
  - "${BACKEND_HOST_PORT:-8000}:8000"
```

When the compose is exposed on any non-localhost interface, the backend API listens on every IP. Combined with `api_key: str = ""` default (see `security-auth-hardening.md`), a fresh deploy on a multi-homed VM is fully open.

### E3. Plaintext secrets in `.env`

All external API keys (NVD_API_KEY, VirusTotal, abuse.ch, Dependency-Track) live in `.env`, loaded via `env_file` directive (docker-compose.yml:57, 112). These land in process environment visible to `/proc/<pid>/environ` on the host. Not catastrophic, but standard practice is Docker secrets or sops/vault.

### E4. system-emulation has its own hardcoded password

`docker-compose.yml:192`:
```yaml
POSTGRES_PASSWORD=firmae
```

Even worse — this one is buried in an env override, easy to miss.

## Approach

### Step 1 — Require POSTGRES_PASSWORD (no default)

Change `docker-compose.yml`:
```yaml
postgres:
  environment:
    POSTGRES_USER: ${POSTGRES_USER:-wairz}
    POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required. Set it in .env}
    POSTGRES_DB: ${POSTGRES_DB:-wairz}
```

`${VAR:?error}` syntax makes docker-compose fail fast with a readable error if the variable isn't set.

Update `DATABASE_URL`:
```yaml
backend:
  environment:
    DATABASE_URL: postgresql+asyncpg://${POSTGRES_USER:-wairz}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB:-wairz}
```

Update `.env.example`:
```bash
# REQUIRED: PostgreSQL credentials. Generate a strong random password.
POSTGRES_USER=wairz
POSTGRES_PASSWORD=changeme-use-a-strong-random-password
POSTGRES_DB=wairz
```

### Step 2 — Safe default binding

Change the default port mapping to loopback:

```yaml
backend:
  ports:
    - "${BACKEND_HOST_BIND:-127.0.0.1}:${BACKEND_HOST_PORT:-8000}:8000"

frontend:
  ports:
    - "${FRONTEND_HOST_BIND:-127.0.0.1}:${FRONTEND_HOST_PORT:-3000}:3000"
```

For deployments that need external access, the operator explicitly sets `BACKEND_HOST_BIND=0.0.0.0` AND `API_KEY=...` in `.env`. Add a README section explaining this.

Related: `security-auth-hardening.md` adds startup-time enforcement that `api_key` must be set when binding is non-loopback.

### Step 3 — Fix system-emulation hardcoded password

Replace `docker-compose.yml:192`:
```yaml
system-emulation:
  environment:
    - DOCKER_HOST=unix:///var/run/docker.sock
    - FIRMAE_DB_PASSWORD=${FIRMAE_DB_PASSWORD:?required}
```

Or better, eliminate the inner Postgres entirely if FirmAE is run only for extraction and doesn't need its own DB.

### Step 4 — Remove `env_file: .env` from frontend

`docker-compose.yml:253` — the frontend is static nginx; it doesn't need backend secrets. Remove the `env_file` line to reduce accidental exposure:

```yaml
frontend:
  # REMOVED: env_file: .env
  # Frontend needs only VITE_* env at build time (in Dockerfile), not at runtime
```

### Step 5 — Document secret rotation

Add `.env.example` header:

```bash
# Wairz Environment Configuration
#
# SECURITY:
# - POSTGRES_PASSWORD and API_KEY are REQUIRED.
# - Never commit .env to git. Use .env.example as a template.
# - To rotate API_KEY: edit .env, docker compose up -d backend, reload the browser.
#
# For production: consider Docker secrets or an external secret manager
# (HashiCorp Vault, AWS Secrets Manager, SOPS-encrypted files).
```

### Step 6 (optional) — Docker secrets for production

For a production deploy profile, add a `docker-compose.prod.yml` that uses Docker secrets:

```yaml
services:
  postgres:
    secrets:
      - postgres_password
    environment:
      POSTGRES_PASSWORD_FILE: /run/secrets/postgres_password

secrets:
  postgres_password:
    file: ./secrets/postgres_password.txt
```

## Files

- `docker-compose.yml` (all 4 edits above)
- `docker-compose.dev.yml` (verify, may need same changes)
- `.env.example` (document requirements)
- `README.md` (security section explaining binding + secret requirements)
- `docker-compose.prod.yml` (new, optional — Docker secrets variant)

## Acceptance Criteria

- [ ] `docker compose config` with no `.env` shows an error about missing `POSTGRES_PASSWORD`
- [ ] Fresh clone + `cp .env.example .env` + `docker compose up` works (once user fills in required values)
- [ ] Default deploy binds to `127.0.0.1` — verified by `netstat -tlnp | grep 8000` from host
- [ ] `docker inspect wairz-frontend-1 | jq '.[0].Config.Env'` does not contain NVD_API_KEY or other backend secrets
- [ ] `grep -n 'PASSWORD.*:.*firmae\|PASSWORD.*:.*wairz' docker-compose.yml` returns zero hits (except inside `${...}` interpolation)

## Risks

- Existing users with `.env` will need to set `POSTGRES_PASSWORD` explicitly once — document in upgrade notes
- Changing the PG password requires DB re-init OR a `psql` password-change — first-time setup is easy, migrating an existing DB is one manual step
- External tools/scripts that target `wairz:wairz@postgres:5432` will break — audit `.planning/`, `scripts/`, `backend/alembic/env.py` for hardcoded URLs (shouldn't be any but verify)

## References

- Infrastructure review C1, C2, C4, M1, M8
- Related: `security-auth-hardening.md` (startup-time binding check)
