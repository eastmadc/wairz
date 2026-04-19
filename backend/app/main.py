import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.requests import Request

from app.config import get_settings
from app.middleware.asgi_auth import APIKeyASGIMiddleware
from app.rate_limit import limiter  # shared rate-limiter instance (B.1.b)
from app.routers import analysis, apk_scan, attack_surface, comparison, compliance, component_map, cra_compliance, device, documents, emulation, events, export_import, files, findings, firmware, fuzzing, hardware_firmware, kernels, projects, sbom, security_audit, terminal, tools, uart
from app.routers.terminal import system_ws_router as _system_ws_router
from app.services.event_service import event_service
from app.utils.sandbox import PathTraversalError


@asynccontextmanager
async def lifespan(app: FastAPI):
    import sys
    settings = get_settings()
    os.makedirs(settings.storage_root, exist_ok=True)
    os.makedirs(settings.emulation_kernel_dir, exist_ok=True)

    # Refuse to start if auth is not configured (B.1.a).
    # Set API_KEY in .env (or environment) for production.
    # Set WAIRZ_ALLOW_NO_AUTH=true only for local-only single-user deployments.
    if not settings.api_key and not settings.allow_no_auth:
        print(
            "ERROR: api_key is required. Set API_KEY in .env or "
            "WAIRZ_ALLOW_NO_AUTH=true for local-only deployments.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Connect Redis event bus
    try:
        await event_service.connect()
        app.state.event_service = event_service
    except Exception:
        import logging
        logging.getLogger(__name__).warning(
            "Redis unavailable — SSE event bus disabled. "
            "Polling fallback will continue to work."
        )

    # Start loading CPE dictionary in background (non-blocking)
    try:
        from app.services.cpe_dictionary_service import get_cpe_dictionary_service
        cpe_svc = get_cpe_dictionary_service()
        await cpe_svc.ensure_loaded()
    except Exception:
        import logging
        logging.getLogger(__name__).warning(
            "CPE dictionary background load failed — fuzzy matching will use local map only"
        )

    yield

    # Shutdown Redis
    await event_service.disconnect()


app = FastAPI(
    title="Wairz",
    description="AI-Assisted Firmware Reverse Engineering & Security Assessment",
    version="0.1.0",
    lifespan=lifespan,
)

# Attach rate limiter state, 429 handler, and SlowAPI middleware (B.1.b).
# SlowAPIMiddleware intercepts requests and checks @limiter.limit() decorators.
# The exception handler converts RateLimitExceeded → HTTP 429 JSON response.
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

_cors_origins = (
    get_settings().cors_origins.split(",")
    if get_settings().cors_origins
    else ["http://localhost:3000", "http://127.0.0.1:3000"]
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API key auth — pure-ASGI middleware covers both http and websocket
# scopes. The prior BaseHTTPMiddleware-based APIKeyMiddleware only
# intercepted HTTP, leaving /ws terminal and /{session}/terminal ws-to-tcp
# proxy endpoints unauthenticated.
app.add_middleware(APIKeyASGIMiddleware)

app.include_router(projects.router)
app.include_router(firmware.router)
app.include_router(files.router)
app.include_router(analysis.router)
app.include_router(component_map.router)
app.include_router(hardware_firmware.router)
app.include_router(findings.router)
app.include_router(documents.router)
app.include_router(sbom.router)
app.include_router(terminal.router)
app.include_router(emulation.router)
app.include_router(fuzzing.router)
app.include_router(kernels.router)
app.include_router(comparison.router)
app.include_router(export_import.router)
app.include_router(uart.router)
app.include_router(device.router)
app.include_router(security_audit.router)
app.include_router(compliance.router)
app.include_router(cra_compliance.router)
app.include_router(attack_surface.router)
app.include_router(apk_scan.router)
app.include_router(tools.router)
app.include_router(events.router)
app.include_router(_system_ws_router)


@app.exception_handler(PathTraversalError)
async def path_traversal_handler(request: Request, exc: PathTraversalError):
    return JSONResponse(status_code=403, content={"detail": str(exc)})


@app.get("/health")
async def health():
    """Liveness probe + shallow readiness check.

    The default "ok" response stays for backward compatibility —
    orchestrators that just want a 200 see it.  New callers that
    pass ?deep=1 get component-level status: DB round-trip + Redis
    PING + Docker socket presence.  Any component failure flips the
    response to 503 so Docker / k8s / upstream proxies can route
    traffic away.
    """
    from app.config import get_settings
    settings = get_settings()
    return {
        "status": "ok",
        "version": app.version,
        "storage_root_exists": os.path.isdir(settings.storage_root),
    }


@app.get("/health/deep")
async def health_deep():
    """Component-level health — DB round-trip, Redis PING, Docker socket.

    Returns 200 only when all three pass; 503 otherwise with a per-
    component breakdown so on-call can see which component failed.
    Cheap enough to be called every 30 s by an external monitor.
    """
    from app.config import get_settings
    from app.database import async_session_factory
    from sqlalchemy import text as _sql_text

    settings = get_settings()
    checks: dict[str, dict] = {}

    # DB — SELECT 1 round-trip
    try:
        async with async_session_factory() as db:
            await db.execute(_sql_text("SELECT 1"))
        checks["db"] = {"ok": True}
    except Exception as exc:
        checks["db"] = {"ok": False, "error": str(exc)[:200]}

    # Redis — PING via the already-connected event_service
    try:
        r = getattr(event_service, "_redis", None)
        if r is None:
            checks["redis"] = {"ok": False, "error": "not connected"}
        else:
            await r.ping()
            checks["redis"] = {"ok": True}
    except Exception as exc:
        checks["redis"] = {"ok": False, "error": str(exc)[:200]}

    # Docker socket presence — cheap stat, no privileged op
    docker_sock = "/var/run/docker.sock"
    checks["docker"] = {
        "ok": os.path.exists(docker_sock),
        **({} if os.path.exists(docker_sock) else {"error": "socket missing"}),
    }

    # Storage root
    checks["storage"] = {
        "ok": os.path.isdir(settings.storage_root),
        "path": settings.storage_root,
    }

    all_ok = all(c["ok"] for c in checks.values())
    status_code = 200 if all_ok else 503
    return JSONResponse(
        status_code=status_code,
        content={"status": "ok" if all_ok else "degraded", "checks": checks},
    )
