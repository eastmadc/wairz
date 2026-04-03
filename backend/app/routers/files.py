import asyncio
import dataclasses
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.services.file_service import FileService
from app.services.firmware_service import FirmwareService

router = APIRouter(prefix="/api/v1/projects/{project_id}/files", tags=["files"])


async def get_file_service(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID | None = Query(None, description="Specific firmware ID (defaults to first)"),
    db: AsyncSession = Depends(get_db),
) -> FileService:
    """Resolve project → firmware → extracted_path, return a FileService."""
    firmware_svc = FirmwareService(db)
    if firmware_id:
        firmware = await firmware_svc.get_by_id(firmware_id)
        if not firmware or firmware.project_id != project_id:
            raise HTTPException(404, "Firmware not found")
    else:
        firmware = await firmware_svc.get_by_project(project_id)
        if not firmware:
            raise HTTPException(404, "No firmware uploaded for this project")
    if not firmware.extracted_path:
        raise HTTPException(400, "Firmware not yet unpacked")
    return FileService(firmware.extracted_path, extraction_dir=firmware.extraction_dir)


@router.get("")
async def list_directory(
    path: str = Query("/", description="Directory path to list"),
    service: FileService = Depends(get_file_service),
):
    loop = asyncio.get_running_loop()
    try:
        entries, truncated = await loop.run_in_executor(
            None, service.list_directory, path
        )
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))
    return {
        "path": path,
        "entries": [dataclasses.asdict(e) for e in entries],
        "truncated": truncated,
    }


@router.get("/read")
async def read_file(
    path: str = Query(..., description="File path to read"),
    offset: int = Query(0, ge=0, description="Byte offset to start reading from"),
    length: int | None = Query(None, ge=1, description="Number of bytes to read"),
    format: str = Query("auto", description="Response format: auto, base64"),
    service: FileService = Depends(get_file_service),
):
    loop = asyncio.get_running_loop()
    try:
        content = await loop.run_in_executor(
            None, service.read_file, path, offset, length, format
        )
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))
    except PermissionError as e:
        raise HTTPException(403, str(e))
    return dataclasses.asdict(content)


@router.get("/info")
async def file_info(
    path: str = Query(..., description="File path to inspect"),
    service: FileService = Depends(get_file_service),
):
    loop = asyncio.get_running_loop()
    try:
        info = await loop.run_in_executor(None, service.file_info, path)
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))
    except PermissionError as e:
        raise HTTPException(403, str(e))
    return dataclasses.asdict(info)


@router.get("/search")
async def search_files(
    pattern: str = Query(..., description="Glob pattern to search for"),
    path: str = Query("/", description="Directory to search in"),
    service: FileService = Depends(get_file_service),
):
    loop = asyncio.get_running_loop()
    matches, truncated = await loop.run_in_executor(
        None, service.search_files, pattern, path
    )
    return {
        "pattern": pattern,
        "matches": matches,
        "truncated": truncated,
    }
