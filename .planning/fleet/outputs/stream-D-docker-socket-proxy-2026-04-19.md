---
stream: D
task: security-docker-socket-proxy
campaign: wairz-intake-sweep-2026-04-19
date: 2026-04-19
commit: bac49eae85ba2d8efd214fde68c865c00fd67ff8
branch: clean-history
---

## Summary

Introduced `tecnativa/docker-socket-proxy:0.3.0` as a sidecar. Backend and worker
no longer mount `/var/run/docker.sock`; they communicate via `tcp://docker-proxy:2375`
with a narrow allowlist (CONTAINERS, IMAGES, NETWORKS, EVENTS, EXEC, POST; VOLUMES=0).

## Verification

| # | Check | Result |
|---|-------|--------|
| 1 | `docker compose config | grep docker.sock` shows only proxy mount | PASS |
| 2 | `GET /api/v1/projects` returns 200 | PASS |
| 3 | `volumes.list()` from backend → 403 Forbidden (VOLUMES=0) | PASS |
| 4 | `containers.list()` from backend → count returned (CONTAINERS=1) | PASS |
| 5 | DPCS10 canary: `COUNT(*)` WHERE firmware_id=0ed279d8... | PASS (260) |
| 6 | `docker compose ps` backend + worker Up | PASS |

## Code Changes (docker.from_env() call sites migrated)

All 10 production call sites replaced with `get_docker_client()` from
`backend/app/utils/docker_client.py`:

- `backend/app/services/emulation_service.py` — `_get_docker_client()` method
- `backend/app/services/fuzzing_service.py` — `_get_docker_client()` method
- `backend/app/services/system_emulation_service.py` — `_get_docker_client()` method
- `backend/app/services/cwe_checker_service.py` — 2 inline calls (check_image_available, run_cwe_checker)
- `backend/app/routers/terminal.py` — 3 calls (_resolve_host_path, websocket_terminal x2)
- `backend/app/routers/emulation.py:676` — WebSocket exec inline call
- `backend/app/ai/tools/emulation.py` — 2 inline calls (get_crash_dump, run_gdb_command)
- `backend/app/ai/tools/fuzzing.py` — 1 inline call (diagnose_fuzzing_campaign)

No `DockerClient(` calls existed anywhere — only `docker.from_env()`.

## New Files

- `backend/app/utils/docker_client.py` — factory function `get_docker_client()`
- `backend/app/config.py` — added `docker_host: str = "tcp://docker-proxy:2375"`

## Notes

- `docker_safety.py` validation wrapper (intake step 4) deferred — out of scope for
  this stream per task instructions ("Do not touch auth-hardening / safe_extract /
  fuzzing_service files"). The proxy allowlist provides the architectural narrowing;
  per-call image/bind validation is a follow-on hardening task.
- `VOLUMES: 0` confirmed enforced — 403 from proxy, not just a client-side block.
- Worker does not have `DEVICE_BRIDGE_HOST` in its environment block (same as before);
  not changed.
