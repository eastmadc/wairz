"""REST endpoints for firmware version comparison."""

import asyncio
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.schemas.comparison import (
    BinaryDiffRequest,
    BinaryDiffResponse,
    FirmwareDiffRequest,
    FirmwareDiffResponse,
    InstructionDiffRequest,
    InstructionDiffResponse,
    TextDiffRequest,
    TextDiffResponse,
)
from app.services.comparison_service import (
    diff_binary,
    diff_filesystems,
    diff_function_instructions,
    diff_text_file,
)
from app.services.firmware_service import FirmwareService
from app.utils.sandbox import validate_path

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/compare",
    tags=["comparison"],
)


async def _get_firmware(
    firmware_id: uuid.UUID,
    project_id: uuid.UUID,
    db: AsyncSession,
):
    """Look up a firmware by ID and verify it belongs to the project."""
    svc = FirmwareService(db)
    firmware = await svc.get_by_id(firmware_id)
    if not firmware or firmware.project_id != project_id:
        raise HTTPException(404, f"Firmware {firmware_id} not found in project")
    if not firmware.extracted_path:
        raise HTTPException(400, f"Firmware {firmware_id} not yet unpacked")
    return firmware


@router.post("/firmware", response_model=FirmwareDiffResponse)
async def compare_firmware(
    project_id: uuid.UUID,
    body: FirmwareDiffRequest,
    db: AsyncSession = Depends(get_db),
):
    """Compare two firmware versions' filesystems."""
    fw_a = await _get_firmware(body.firmware_a_id, project_id, db)
    fw_b = await _get_firmware(body.firmware_b_id, project_id, db)

    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None, diff_filesystems, fw_a.extracted_path, fw_b.extracted_path,
    )

    return FirmwareDiffResponse(
        added=[_entry_to_dict(e) for e in result.added],
        removed=[_entry_to_dict(e) for e in result.removed],
        modified=[_entry_to_dict(e) for e in result.modified],
        permissions_changed=[_entry_to_dict(e) for e in result.permissions_changed],
        total_files_a=result.total_files_a,
        total_files_b=result.total_files_b,
        truncated=result.truncated,
    )


@router.post("/binary", response_model=BinaryDiffResponse)
async def compare_binary(
    project_id: uuid.UUID,
    body: BinaryDiffRequest,
    db: AsyncSession = Depends(get_db),
):
    """Compare a specific binary between two firmware versions."""
    fw_a = await _get_firmware(body.firmware_a_id, project_id, db)
    fw_b = await _get_firmware(body.firmware_b_id, project_id, db)

    # Validate the binary path exists in both firmware
    try:
        path_a = validate_path(fw_a.extracted_path, body.binary_path)
    except Exception:
        raise HTTPException(404, f"Binary not found in firmware A: {body.binary_path}")

    try:
        path_b = validate_path(fw_b.extracted_path, body.binary_path)
    except Exception:
        raise HTTPException(404, f"Binary not found in firmware B: {body.binary_path}")

    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None, diff_binary, path_a, path_b, body.binary_path,
    )

    return BinaryDiffResponse(
        binary_path=result.binary_path,
        functions_added=[_func_to_dict(f) for f in result.functions_added],
        functions_removed=[_func_to_dict(f) for f in result.functions_removed],
        functions_modified=[_func_to_dict(f) for f in result.functions_modified],
        info_a=result.info_a,
        info_b=result.info_b,
        sections_a=result.sections_a,
        sections_b=result.sections_b,
        sections_changed=result.sections_changed,
        imports_added=result.imports_added,
        imports_removed=result.imports_removed,
        exports_added=result.exports_added,
        exports_removed=result.exports_removed,
    )


@router.post("/text", response_model=TextDiffResponse)
async def compare_text_file(
    project_id: uuid.UUID,
    body: TextDiffRequest,
    db: AsyncSession = Depends(get_db),
):
    """Compare a specific text file between two firmware versions.

    Returns a unified diff suitable for display.
    """
    fw_a = await _get_firmware(body.firmware_a_id, project_id, db)
    fw_b = await _get_firmware(body.firmware_b_id, project_id, db)

    # Resolve paths — for added/removed files one side may not exist
    try:
        path_a = validate_path(fw_a.extracted_path, body.file_path)
    except Exception:
        path_a = ""  # File doesn't exist in A (added file)

    try:
        path_b = validate_path(fw_b.extracted_path, body.file_path)
    except Exception:
        path_b = ""  # File doesn't exist in B (removed file)

    if not path_a and not path_b:
        return TextDiffResponse(
            path=body.file_path,
            diff="",
            error="File not found in either firmware version",
        )

    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None, diff_text_file, path_a, path_b, body.file_path,
    )

    return TextDiffResponse(**result)


@router.post("/instructions", response_model=InstructionDiffResponse)
async def compare_instructions(
    project_id: uuid.UUID,
    body: InstructionDiffRequest,
    db: AsyncSession = Depends(get_db),
):
    """Compare a specific function's disassembly between two firmware versions.

    Returns a unified diff of the Capstone-disassembled instructions.
    """
    fw_a = await _get_firmware(body.firmware_a_id, project_id, db)
    fw_b = await _get_firmware(body.firmware_b_id, project_id, db)

    # Validate the binary path exists in both firmware
    try:
        path_a = validate_path(fw_a.extracted_path, body.binary_path)
    except Exception:
        raise HTTPException(404, f"Binary not found in firmware A: {body.binary_path}")

    try:
        path_b = validate_path(fw_b.extracted_path, body.binary_path)
    except Exception:
        raise HTTPException(404, f"Binary not found in firmware B: {body.binary_path}")

    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None, diff_function_instructions, path_a, path_b, body.function_name,
    )

    return InstructionDiffResponse(**result)


def _entry_to_dict(entry) -> dict:
    return {
        "path": entry.path,
        "status": entry.status,
        "size_a": entry.size_a,
        "size_b": entry.size_b,
        "perms_a": entry.perms_a,
        "perms_b": entry.perms_b,
    }


def _func_to_dict(entry) -> dict:
    return {
        "name": entry.name,
        "status": entry.status,
        "size_a": entry.size_a,
        "size_b": entry.size_b,
        "hash_a": entry.hash_a,
        "hash_b": entry.hash_b,
        "addr_a": entry.addr_a,
        "addr_b": entry.addr_b,
    }
