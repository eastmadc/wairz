"""REST endpoints for compliance reporting (ETSI EN 303 645)."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.firmware import Firmware
from app.models.project import Project
from app.services.compliance_service import ETSIComplianceService

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/compliance",
    tags=["compliance"],
)


async def _get_project_or_404(project_id: uuid.UUID, db: AsyncSession) -> Project:
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    return project


@router.get("/etsi")
async def get_etsi_compliance(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID | None = Query(
        None, description="Filter findings to a specific firmware"
    ),
    db: AsyncSession = Depends(get_db),
):
    """Generate an ETSI EN 303 645 compliance report for the project.

    Maps all existing findings to the 13 ETSI provisions and returns
    a structured compliance matrix with pass/fail/partial/not_tested
    status for each provision.
    """
    await _get_project_or_404(project_id, db)

    # If firmware_id given, validate it belongs to project
    if firmware_id:
        result = await db.execute(
            select(Firmware).where(
                Firmware.id == firmware_id,
                Firmware.project_id == project_id,
            )
        )
        if not result.scalar_one_or_none():
            raise HTTPException(404, "Firmware not found")

    service = ETSIComplianceService(db)
    report = service.generate_report(project_id, firmware_id=firmware_id)
    return await report
