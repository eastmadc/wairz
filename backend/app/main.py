import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.requests import Request

from app.config import get_settings
from app.routers import analysis, comparison, compliance, component_map, device, documents, emulation, events, export_import, files, findings, firmware, fuzzing, kernels, projects, sbom, security_audit, terminal, uart
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

app.include_router(projects.router)
app.include_router(firmware.router)
app.include_router(files.router)
app.include_router(analysis.router)
app.include_router(component_map.router)
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
app.include_router(events.router)


@app.exception_handler(PathTraversalError)
async def path_traversal_handler(request: Request, exc: PathTraversalError):
    return JSONResponse(status_code=403, content={"detail": str(exc)})


@app.get("/health")
async def health():
    return {"status": "ok"}
