"""REST endpoints for automated security scanning."""

import asyncio
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.firmware import Firmware
from app.models.finding import Finding
from app.models.project import Project
from app.schemas.finding import FindingResponse, Severity
from app.services.finding_service import FindingService
from app.services.security_audit_service import SecurityFinding, run_security_audit

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/security",
    tags=["security-audit"],
)


class SecurityScanResponse(BaseModel):
    status: str
    checks_run: int
    findings_created: int
    total_findings: int
    errors: list[str] = []


async def _persist_finding(
    svc: FindingService,
    project_id: uuid.UUID,
    sf: SecurityFinding,
) -> Finding:
    """Convert a SecurityFinding to a DB Finding."""
    from app.schemas.finding import FindingCreate

    return await svc.create(
        project_id,
        FindingCreate(
            title=sf.title,
            severity=Severity(sf.severity),
            description=sf.description,
            evidence=sf.evidence,
            file_path=sf.file_path,
            line_number=sf.line_number,
            cwe_ids=sf.cwe_ids,
            source="security_audit",
        ),
    )


@router.post("/audit", response_model=SecurityScanResponse)
async def run_audit(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Run automated security scan on extracted firmware.

    Scans for hardcoded credentials, API keys, weak passwords, setuid
    binaries, insecure services, world-writable files, and embedded
    private keys. Results are persisted as findings with
    source='security_audit'.
    """
    # Get project and firmware
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    result = await db.execute(
        select(Firmware).where(Firmware.project_id == project_id)
    )
    firmware = result.scalar_one_or_none()
    if not firmware or not firmware.extracted_path:
        raise HTTPException(400, "No extracted firmware available — unpack first")

    # Clear previous security_audit findings to allow re-scanning
    result = await db.execute(
        select(Finding).where(
            Finding.project_id == project_id,
            Finding.source == "security_audit",
        )
    )
    old_findings = result.scalars().all()
    for f in old_findings:
        await db.delete(f)
    await db.flush()

    # Run the scan (CPU-bound, run in thread)
    loop = asyncio.get_running_loop()
    scan_result = await loop.run_in_executor(
        None, run_security_audit, firmware.extracted_path
    )

    # Persist findings
    svc = FindingService(db)
    for sf in scan_result.findings:
        await _persist_finding(svc, project_id, sf)

    await db.commit()

    return SecurityScanResponse(
        status="success",
        checks_run=scan_result.checks_run,
        findings_created=len(scan_result.findings),
        total_findings=len(scan_result.findings),
        errors=scan_result.errors,
    )
