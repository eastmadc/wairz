"""REST endpoints for device acquisition via the wairz-device-bridge."""

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.schemas.device import (
    DeviceBridgeStatus,
    DeviceDetailResponse,
    DeviceInfo,
    DeviceListResponse,
    DumpImportRequest,
    DumpImportResponse,
    DumpPartitionRequest,
    DumpStatusResponse,
)
from app.services.device_service import DeviceService

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/device",
    tags=["device-acquisition"],
)

def get_device_service(db: AsyncSession = Depends(get_db)) -> DeviceService:
    """Create a new service per request. Dump state is module-level in the service."""
    return DeviceService(db)


@router.get("/status", response_model=DeviceBridgeStatus)
async def bridge_status(
    project_id: uuid.UUID,
    service: DeviceService = Depends(get_device_service),
):
    """Check if the device bridge is reachable."""
    return await service.get_bridge_status()


@router.get("/devices", response_model=DeviceListResponse)
async def list_devices(
    project_id: uuid.UUID,
    service: DeviceService = Depends(get_device_service),
):
    """List connected ADB devices."""
    try:
        devices = await service.list_devices()
    except ConnectionError as e:
        raise HTTPException(502, f"Device bridge unreachable: {e}")
    return DeviceListResponse(
        devices=[DeviceInfo(**d) for d in devices],
    )


@router.get("/devices/{device_id}/info", response_model=DeviceDetailResponse)
async def device_info(
    project_id: uuid.UUID,
    device_id: str,
    service: DeviceService = Depends(get_device_service),
):
    """Get device details including getprop and partitions."""
    try:
        info = await service.get_device_info(device_id)
    except ConnectionError as e:
        raise HTTPException(502, f"Device bridge unreachable: {e}")
    except ValueError as e:
        raise HTTPException(400, str(e))

    return DeviceDetailResponse(
        device=DeviceInfo(serial=device_id),
        getprop=info["getprop"],
        partitions=info["partitions"],
        device_metadata=info.get("device_metadata"),
    )


@router.post("/dump", response_model=DumpStatusResponse, status_code=202)
async def start_dump(
    project_id: uuid.UUID,
    request: DumpPartitionRequest,
    service: DeviceService = Depends(get_device_service),
):
    """Start dumping partitions from a device."""
    try:
        state = await service.start_dump(project_id, request.device_id, request.partitions)
    except ConnectionError as e:
        raise HTTPException(502, f"Device bridge unreachable: {e}")
    except ValueError as e:
        raise HTTPException(400, str(e))

    return DumpStatusResponse(
        status=state["status"],
        device_id=state["device_id"],
        partitions=state["partitions"],
    )


@router.get("/dump/status", response_model=DumpStatusResponse)
async def dump_status(
    project_id: uuid.UUID,
    service: DeviceService = Depends(get_device_service),
):
    """Get the status of the current dump."""
    state = await service.get_dump_status()
    return DumpStatusResponse(
        status=state.get("status", "idle"),
        device_id=state.get("device_id"),
        partitions=state.get("partitions", []),
    )


@router.post("/dump/cancel")
async def cancel_dump(
    project_id: uuid.UUID,
    service: DeviceService = Depends(get_device_service),
):
    """Cancel the current dump."""
    state = await service.cancel_dump()
    return state


@router.post("/import", response_model=DumpImportResponse, status_code=201)
async def import_dump(
    project_id: uuid.UUID,
    request: DumpImportRequest,
    service: DeviceService = Depends(get_device_service),
):
    """Import a completed dump as firmware into the project."""
    try:
        firmware = await service.import_dump(
            project_id, request.device_id, request.version_label,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    except ConnectionError as e:
        raise HTTPException(502, str(e))

    return DumpImportResponse(
        firmware_id=str(firmware.id),
        device_metadata=firmware.device_metadata,
        message="Dump imported — unpack pipeline started",
    )
