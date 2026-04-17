import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.requests import Request

from app.config import get_settings
from app.middleware.auth import APIKeyMiddleware
from app.routers import analysis, apk_scan, attack_surface, comparison, compliance, component_map, cra_compliance, device, documents, emulation, events, export_import, files, findings, firmware, fuzzing, hardware_firmware, kernels, projects, sbom, security_audit, terminal, tools, uart
from app.routers.terminal import system_ws_router as _system_ws_router
from app.services.event_service import event_service
from app.utils.sandbox import PathTraversalError


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    os.makedirs(settings.storage_root, exist_ok=True)
    os.makedirs(settings.emulation_kernel_dir, exist_ok=True)

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

# API key auth — runs after CORS (Starlette middleware stack is LIFO,
# so adding it after CORSMiddleware means CORS processes first).
app.add_middleware(APIKeyMiddleware)

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
    return {"status": "ok"}
