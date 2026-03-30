"""Shared FastAPI dependencies for router modules."""

import uuid

from fastapi import Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.firmware import Firmware
from app.services.firmware_service import FirmwareService


async def resolve_firmware(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID | None = Query(None, description="Specific firmware ID (defaults to first)"),
    db: AsyncSession = Depends(get_db),
) -> Firmware:
    """Resolve project -> firmware, return firmware record.

    Validates that the firmware exists, belongs to the project, and has been
    unpacked (extracted_path is set). Used as a FastAPI dependency across
    multiple router modules.
    """
    svc = FirmwareService(db)
    if firmware_id:
        firmware = await svc.get_by_id(firmware_id)
        if not firmware or firmware.project_id != project_id:
            raise HTTPException(404, "Firmware not found")
    else:
        firmware = await svc.get_by_project(project_id)
        if not firmware:
            raise HTTPException(404, "No firmware uploaded for this project")
    if not firmware.extracted_path:
        raise HTTPException(400, "Firmware not yet unpacked")
    return firmware
