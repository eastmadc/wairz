"""REST endpoints for the hardware firmware graph.

Two endpoints:

* ``GET .../firmware-edges`` — on-demand driver <-> firmware edges for the
  component-map overlay.  Separate from the cached component_map graph so
  the frontend can toggle the overlay without invalidating heavy caches.
* ``GET .../drivers`` — per-driver summary of requested firmware blobs
  (resolved vs unresolved).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.routers.deps import resolve_firmware as _resolve_firmware
from app.schemas.hardware_firmware import (
    FirmwareDriverResponse,
    FirmwareDriversListResponse,
    FirmwareEdgeResponse,
    FirmwareEdgesResponse,
)
from app.services.hardware_firmware.graph import build_driver_firmware_graph

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/hardware-firmware",
    tags=["hardware-firmware"],
)


@router.get("/firmware-edges", response_model=FirmwareEdgesResponse)
async def get_firmware_edges(
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
) -> FirmwareEdgesResponse:
    """Return driver <-> firmware edges for the component-map overlay."""
    result = await build_driver_firmware_graph(firmware.id, db)
    return FirmwareEdgesResponse(
        edges=[
            FirmwareEdgeResponse(
                driver_path=e.driver_path,
                firmware_name=e.firmware_name,
                firmware_blob_path=e.firmware_blob_path,
                source=e.source,
            )
            for e in result.edges
        ],
        kmod_drivers=result.kmod_drivers,
        dtb_sources=result.dtb_sources,
        unresolved_count=result.unresolved_count,
    )


@router.get("/drivers", response_model=FirmwareDriversListResponse)
async def list_drivers(
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
) -> FirmwareDriversListResponse:
    """List drivers (kmod + vmlinux + DTB) with the firmware they request."""
    result = await build_driver_firmware_graph(firmware.id, db)
    by_driver: dict[str, dict] = {}
    for e in result.edges:
        rec = by_driver.setdefault(
            e.driver_path,
            {
                "driver_path": e.driver_path,
                "format": _infer_format(e.driver_path, e.source),
                "firmware_deps": [],
                "firmware_blobs": [],
                "total": 0,
            },
        )
        rec["firmware_deps"].append(e.firmware_name)
        if e.firmware_blob_path:
            rec["firmware_blobs"].append(e.firmware_blob_path)
        rec["total"] += 1

    drivers = [FirmwareDriverResponse(**d) for d in by_driver.values()]
    return FirmwareDriversListResponse(drivers=drivers, total=len(drivers))


def _infer_format(driver_path: str, source: str) -> str:
    if source == "kmod_modinfo":
        return "ko"
    if source == "vmlinux_strings":
        return "vmlinux"
    if source == "dtb_firmware_name":
        return "dtb"
    return "unknown"
