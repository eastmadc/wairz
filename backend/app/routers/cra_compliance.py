"""REST endpoints for CRA (EU Cyber Resilience Act) compliance reporting."""

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.firmware import Firmware
from app.models.project import Project
from app.schemas.cra_compliance import (
    CraAssessmentCreate,
    CraAssessmentListResponse,
    CraAssessmentResponse,
    CraRequirementResponse,
    CraRequirementUpdate,
)
from app.services.cra_compliance_service import CRAComplianceService

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/cra",
    tags=["cra-compliance"],
)


async def _get_project_or_404(project_id: uuid.UUID, db: AsyncSession) -> Project:
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    return project


@router.post("/assessments", response_model=CraAssessmentResponse)
async def create_assessment(
    project_id: uuid.UUID,
    body: CraAssessmentCreate,
    db: AsyncSession = Depends(get_db),
):
    """Create a new CRA compliance assessment for the project.

    Initializes all 20 CRA Annex I requirements (13 Part 1 security +
    7 Part 2 vulnerability handling) with status 'not_tested'.
    """
    await _get_project_or_404(project_id, db)

    # If firmware_id provided, validate it belongs to the project
    if body.firmware_id:
        result = await db.execute(
            select(Firmware).where(
                Firmware.id == body.firmware_id,
                Firmware.project_id == project_id,
            )
        )
        if not result.scalar_one_or_none():
            raise HTTPException(404, "Firmware not found")

    service = CRAComplianceService(db)
    assessment = await service.create_assessment(
        project_id=project_id,
        firmware_id=body.firmware_id,
        product_name=body.product_name,
        product_version=body.product_version,
        assessor_name=body.assessor_name,
    )
    return assessment


@router.get("/assessments", response_model=list[CraAssessmentListResponse])
async def list_assessments(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """List all CRA assessments for the project."""
    await _get_project_or_404(project_id, db)

    service = CRAComplianceService(db)
    return await service.list_assessments(project_id)


@router.get("/assessments/{assessment_id}", response_model=CraAssessmentResponse)
async def get_assessment(
    project_id: uuid.UUID,
    assessment_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get a CRA assessment with all requirement results."""
    await _get_project_or_404(project_id, db)

    service = CRAComplianceService(db)
    assessment = await service.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(404, "Assessment not found")
    if assessment.project_id != project_id:
        raise HTTPException(404, "Assessment not found")
    return assessment


@router.post(
    "/assessments/{assessment_id}/auto-populate",
    response_model=CraAssessmentResponse,
)
async def auto_populate_assessment(
    project_id: uuid.UUID,
    assessment_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Auto-populate a CRA assessment from existing tool findings.

    Maps project findings to CRA Annex I requirements based on title
    patterns, CWE IDs, and tool sources. High/critical findings cause
    'fail', lower severity causes 'partial', no findings means 'pass'.
    Non-automatable requirements are left for manual assessment.
    """
    await _get_project_or_404(project_id, db)

    service = CRAComplianceService(db)

    # Verify assessment exists and belongs to this project
    assessment = await service.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(404, "Assessment not found")
    if assessment.project_id != project_id:
        raise HTTPException(404, "Assessment not found")

    return await service.auto_populate(assessment_id)


@router.patch(
    "/assessments/{assessment_id}/requirements/{requirement_id}",
    response_model=CraRequirementResponse,
)
async def update_requirement(
    project_id: uuid.UUID,
    assessment_id: uuid.UUID,
    requirement_id: str,
    body: CraRequirementUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update a single CRA requirement status and/or notes.

    Used for manual assessment of requirements that cannot be
    auto-populated, or to override auto-populated results.
    """
    await _get_project_or_404(project_id, db)

    service = CRAComplianceService(db)

    # Verify assessment exists and belongs to this project
    assessment = await service.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(404, "Assessment not found")
    if assessment.project_id != project_id:
        raise HTTPException(404, "Assessment not found")

    try:
        return await service.update_requirement(
            assessment_id=assessment_id,
            requirement_id=requirement_id,
            status=body.status.value if body.status else None,
            manual_notes=body.manual_notes,
            manual_evidence=body.manual_evidence,
        )
    except ValueError as e:
        raise HTTPException(404, str(e))


@router.get("/assessments/{assessment_id}/export")
async def export_checklist(
    project_id: uuid.UUID,
    assessment_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Export the full CRA checklist as structured JSON.

    Returns a comprehensive document with all 20 requirements grouped
    by Annex I Part 1 (security) and Part 2 (vulnerability handling),
    including evidence, finding IDs, and deadlines.
    """
    await _get_project_or_404(project_id, db)

    service = CRAComplianceService(db)

    # Verify assessment exists and belongs to this project
    assessment = await service.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(404, "Assessment not found")
    if assessment.project_id != project_id:
        raise HTTPException(404, "Assessment not found")

    return await service.export_checklist(assessment_id)


@router.get("/assessments/{assessment_id}/article14/{cve_id}")
async def export_article14_notification(
    project_id: uuid.UUID,
    assessment_id: uuid.UUID,
    cve_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Export an Article 14 ENISA vulnerability notification for a CVE.

    Article 14 of the CRA requires manufacturers to notify ENISA within
    24 hours of becoming aware of an actively exploited vulnerability.
    This generates a structured notification document.
    """
    await _get_project_or_404(project_id, db)

    service = CRAComplianceService(db)

    # Verify assessment exists and belongs to this project
    assessment = await service.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(404, "Assessment not found")
    if assessment.project_id != project_id:
        raise HTTPException(404, "Assessment not found")

    return await service.export_article14_notification(assessment_id, cve_id)
