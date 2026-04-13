# Anti-patterns: Session 34 — Upload 413 Debugging

> Extracted: 2026-04-13
> Campaign: ad-hoc debugging (no formal campaign)

## Failed Patterns

### 1. Rebuilding backend without rebuilding frontend when changing shared env vars
- **What was done:** First rebuild only targeted `frontend backend worker`. Frontend showed "Running" not "Recreated" because its build context hadn't changed. The env var was still 500 at runtime.
- **Failure mode:** `docker compose up -d --build frontend backend worker` only rebuilds images whose build context changed. Frontend's nginx template uses env vars at *runtime* via envsubst, but the container wasn't recreated because the Dockerfile hadn't changed yet.
- **Evidence:** After first rebuild, `docker compose exec frontend printenv MAX_UPLOAD_SIZE_MB` still showed 500.
- **How to avoid:** When changing a Dockerfile ENV default, the image must be rebuilt (`--build`). When changing only `.env` values, the container must be recreated (`up -d` without `--build` is sufficient if the image already has the right default, but the `.env` must be updated first). Always verify the running container's env after changes.

### 2. Hardcoded defaults in Dockerfiles diverging from .env.example
- **What was done:** frontend/Dockerfile had `ENV MAX_UPLOAD_SIZE_MB=500` while the intent was to change the operational default to 2048. The Dockerfile default and .env.example were out of sync after the initial config.py change.
- **Failure mode:** Runtime .env overrides Dockerfile ENV, so even after rebuilding the frontend image with the new default, the old .env value (500) won the override.
- **Evidence:** `printenv` showed 500 even after rebuilding with the updated Dockerfile.
- **How to avoid:** When changing a config default, grep for the old value across ALL Dockerfiles and .env files: `grep -r "OLD_VALUE" --include='Dockerfile*' --include='.env*'`. Update all in the same pass.
