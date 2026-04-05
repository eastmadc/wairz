"""arq background worker for heavy operations.

Runs as a separate process (``arq app.workers.arq_worker.WorkerSettings``)
and picks up jobs enqueued by the FastAPI backend.  Each job creates its own
async DB session via ``async_session_factory`` so it is fully independent of
the request lifecycle.
"""

import logging
import os
import uuid

from arq.connections import RedisSettings
from sqlalchemy import select

from app.config import get_settings
from app.database import async_session_factory
from app.models.firmware import Firmware
from app.models.project import Project

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Redis connection helper
# ---------------------------------------------------------------------------

def get_redis_settings() -> RedisSettings:
    """Build ``arq.RedisSettings`` from the app ``REDIS_URL``."""
    url = get_settings().redis_url  # e.g. redis://redis:6379/0
    return RedisSettings.from_dsn(url)


# ---------------------------------------------------------------------------
# Job: firmware unpacking
# ---------------------------------------------------------------------------

async def unpack_firmware_job(
    ctx: dict,
    *,
    project_id: str,
    firmware_id: str,
    storage_path: str,
) -> None:
    """Unpack firmware in the background (arq job).

    Mirrors ``_run_unpack_background`` from ``routers/firmware.py`` but runs
    inside the arq worker process rather than inside an ``asyncio.create_task``
    on the web server.
    """
    from app.workers.unpack import unpack_firmware  # local import to avoid circular

    pid = uuid.UUID(project_id)
    fid = uuid.UUID(firmware_id)

    async def _update_progress(stage: str, progress: int) -> None:
        async with async_session_factory() as db:
            fw_result = await db.execute(
                select(Firmware).where(Firmware.id == fid)
            )
            firmware = fw_result.scalar_one_or_none()
            if firmware:
                firmware.unpack_stage = stage
                firmware.unpack_progress = progress
                await db.commit()

    try:
        output_base = os.path.dirname(storage_path)
        result = await unpack_firmware(storage_path, output_base, _update_progress)

        async with async_session_factory() as db:
            try:
                proj_result = await db.execute(
                    select(Project).where(Project.id == pid)
                )
                project = proj_result.scalar_one_or_none()
                fw_result = await db.execute(
                    select(Firmware).where(Firmware.id == fid)
                )
                firmware = fw_result.scalar_one_or_none()

                if not project or not firmware:
                    logger.error("arq unpack job: project or firmware not found")
                    return

                if result.success:
                    firmware.extracted_path = result.extracted_path
                    firmware.extraction_dir = result.extraction_dir
                    firmware.architecture = result.architecture
                    firmware.endianness = result.endianness
                    firmware.os_info = result.os_info
                    firmware.kernel_path = result.kernel_path
                    firmware.binary_info = result.binary_info
                    firmware.unpack_log = result.unpack_log
                    firmware.unpack_stage = None
                    firmware.unpack_progress = None
                    project.status = "ready"
                else:
                    firmware.unpack_log = result.unpack_log
                    firmware.unpack_stage = None
                    firmware.unpack_progress = None
                    project.status = "error"

                await db.commit()
            except Exception:
                await db.rollback()
                raise
    except Exception:
        logger.exception("arq unpack job failed for firmware %s", firmware_id)
    finally:
        try:
            async with async_session_factory() as db:
                proj_result = await db.execute(
                    select(Project).where(Project.id == pid)
                )
                project = proj_result.scalar_one_or_none()
                if project and project.status == "unpacking":
                    project.status = "error"
                    await db.commit()
        except Exception:
            logger.exception("Failed to reset status for project %s", project_id)


# ---------------------------------------------------------------------------
# Job: Ghidra decompilation
# ---------------------------------------------------------------------------

async def run_ghidra_analysis_job(
    ctx: dict,
    *,
    binary_path: str,
    function_name: str,
    firmware_id: str,
) -> str:
    """Run Ghidra decompilation as a queued job.

    Returns the decompiled source text (or an error message).
    """
    from app.services.ghidra_service import decompile_function

    fid = uuid.UUID(firmware_id)

    async with async_session_factory() as db:
        try:
            result = await decompile_function(binary_path, function_name, fid, db)
            await db.commit()
            return result
        except Exception:
            await db.rollback()
            logger.exception(
                "arq Ghidra job failed: %s:%s", binary_path, function_name
            )
            raise


# ---------------------------------------------------------------------------
# Job: Grype vulnerability scan
# ---------------------------------------------------------------------------

async def run_vulnerability_scan_job(
    ctx: dict,
    *,
    firmware_id: str,
    project_id: str,
) -> dict:
    """Run Grype vulnerability scan as a queued job."""
    from app.services.grype_service import scan_with_grype

    fid = uuid.UUID(firmware_id)
    pid = uuid.UUID(project_id)

    async with async_session_factory() as db:
        try:
            result = await scan_with_grype(fid, pid, db)
            await db.commit()
            return result
        except Exception:
            await db.rollback()
            logger.exception("arq vulnerability scan job failed for firmware %s", firmware_id)
            raise


# ---------------------------------------------------------------------------
# Job: YARA scan
# ---------------------------------------------------------------------------

async def run_yara_scan_job(
    ctx: dict,
    *,
    project_id: str,
    extracted_paths: list[str],
) -> dict:
    """Run YARA scan across extracted firmware paths as a queued job.

    ``extracted_paths`` is a list of root paths (one per firmware version) to
    scan.  Results are stored as findings in the database.
    """
    import asyncio

    from sqlalchemy import delete

    from app.models.finding import Finding
    from app.schemas.finding import FindingCreate
    from app.services.finding_service import FindingService
    from app.services.security_audit_service import SecurityFinding

    pid = uuid.UUID(project_id)

    try:
        from app.services.yara_service import scan_firmware as yara_scan_firmware
    except ImportError:
        logger.warning("yara_service not available; skipping YARA scan job")
        return {"status": "unavailable"}

    async with async_session_factory() as db:
        try:
            # Clear previous yara_scan findings
            await db.execute(
                delete(Finding).where(
                    Finding.project_id == pid,
                    Finding.source == "yara_scan",
                )
            )
            await db.flush()

            loop = asyncio.get_running_loop()
            total_rules = 0
            total_scanned = 0
            total_matched = 0
            all_findings: list[SecurityFinding] = []

            for path in extracted_paths:
                scan_result = await loop.run_in_executor(
                    None, yara_scan_firmware, path
                )
                total_rules = max(total_rules, scan_result.rules_loaded)
                total_scanned += scan_result.files_scanned
                total_matched += scan_result.files_matched
                all_findings.extend(scan_result.findings)

            # Persist findings using the same pattern as security_audit router
            svc = FindingService(db)
            for sf in all_findings:
                await svc.create(
                    pid,
                    FindingCreate(
                        title=sf.title,
                        severity=sf.severity,
                        description=sf.description,
                        evidence=sf.evidence,
                        file_path=sf.file_path,
                        line_number=sf.line_number,
                        cwe_ids=sf.cwe_ids,
                        source="yara_scan",
                    ),
                )

            await db.commit()

            return {
                "status": "success",
                "rules_loaded": total_rules,
                "files_scanned": total_scanned,
                "files_matched": total_matched,
                "findings_created": len(all_findings),
            }
        except Exception:
            await db.rollback()
            logger.exception("arq YARA scan job failed for project %s", project_id)
            raise


# ---------------------------------------------------------------------------
# arq WorkerSettings — discovered by ``arq app.workers.arq_worker.WorkerSettings``
# ---------------------------------------------------------------------------

class WorkerSettings:
    """Configuration class consumed by the arq CLI runner."""

    functions = [
        unpack_firmware_job,
        run_ghidra_analysis_job,
        run_vulnerability_scan_job,
        run_yara_scan_job,
    ]

    redis_settings = get_redis_settings()

    # Sensible defaults — long timeout for firmware unpacking / Ghidra
    job_timeout = 600  # 10 minutes
    max_jobs = 4
    poll_delay = 0.5  # seconds between Redis polls
