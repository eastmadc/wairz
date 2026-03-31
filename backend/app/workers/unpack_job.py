"""ARQ job wrapper for firmware unpacking.

This module adapts the existing unpack logic into an arq-compatible
async job function. The heavy lifting stays in ``unpack.py``; this
file only handles DB bookkeeping and arq integration.
"""

from __future__ import annotations

import logging
import os
import uuid

from sqlalchemy import select

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.models.project import Project
from app.workers.unpack import detect_kernel, unpack_firmware

logger = logging.getLogger(__name__)


async def run_unpack_job(ctx: dict, *, firmware_id: str, project_id: str, storage_path: str) -> None:
    """ARQ job: unpack firmware and persist results.

    Parameters are passed as strings because arq serialises via msgpack
    and UUID objects are not natively supported.
    """
    fw_uuid = uuid.UUID(firmware_id)
    proj_uuid = uuid.UUID(project_id)

    try:
        output_base = os.path.dirname(storage_path)
        result = await unpack_firmware(storage_path, output_base)

        async with async_session_factory() as db:
            try:
                proj_result = await db.execute(
                    select(Project).where(Project.id == proj_uuid)
                )
                project = proj_result.scalar_one_or_none()
                fw_result = await db.execute(
                    select(Firmware).where(Firmware.id == fw_uuid)
                )
                firmware = fw_result.scalar_one_or_none()

                if not project or not firmware:
                    logger.error("run_unpack_job: project or firmware not found")
                    return

                if result.success:
                    firmware.extracted_path = result.extracted_path
                    firmware.extraction_dir = result.extraction_dir
                    firmware.architecture = result.architecture
                    firmware.endianness = result.endianness
                    firmware.os_info = result.os_info
                    firmware.kernel_path = result.kernel_path
                    firmware.unpack_log = result.unpack_log
                    project.status = "ready"
                else:
                    firmware.unpack_log = result.unpack_log
                    project.status = "error"

                await db.commit()
            except Exception:
                await db.rollback()
                raise
    except Exception:
        logger.exception("run_unpack_job failed for firmware %s", firmware_id)
        # Try to mark project as errored
        try:
            async with async_session_factory() as db:
                try:
                    proj_result = await db.execute(
                        select(Project).where(Project.id == proj_uuid)
                    )
                    project = proj_result.scalar_one_or_none()
                    if project:
                        project.status = "error"
                    await db.commit()
                except Exception:
                    await db.rollback()
        except Exception:
            logger.exception("Failed to set error status for project %s", project_id)
