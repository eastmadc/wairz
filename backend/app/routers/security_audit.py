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
from app.services.yara_service import scan_firmware as yara_scan_firmware

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
    return await _persist_finding_with_source(svc, project_id, sf, "security_audit")


async def _persist_finding_with_source(
    svc: FindingService,
    project_id: uuid.UUID,
    sf: SecurityFinding,
    source: str,
) -> Finding:
    """Convert a SecurityFinding to a DB Finding with the given source."""
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
            source=source,
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

    # Get all extracted firmware, most recent first
    result = await db.execute(
        select(Firmware)
        .where(
            Firmware.project_id == project_id,
            Firmware.extracted_path.isnot(None),
        )
        .order_by(Firmware.created_at.desc())
    )
    firmware_list = result.scalars().all()
    if not firmware_list:
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

    # Scan all extracted firmware versions
    loop = asyncio.get_running_loop()
    total_checks = 0
    all_findings: list[SecurityFinding] = []
    all_errors: list[str] = []

    for firmware in firmware_list:
        scan_result = await loop.run_in_executor(
            None, run_security_audit, firmware.extracted_path
        )
        total_checks += scan_result.checks_run
        all_findings.extend(scan_result.findings)
        all_errors.extend(scan_result.errors)

    # Persist findings
    svc = FindingService(db)
    for sf in all_findings:
        await _persist_finding(svc, project_id, sf)

    await db.commit()

    return SecurityScanResponse(
        status="success",
        checks_run=total_checks,
        findings_created=len(all_findings),
        total_findings=len(all_findings),
        errors=all_errors,
    )


class YaraScanResponse(BaseModel):
    status: str
    rules_loaded: int
    files_scanned: int
    files_matched: int
    findings_created: int
    errors: list[str] = []


@router.post("/yara", response_model=YaraScanResponse)
async def run_yara_scan(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Scan extracted firmware with YARA rules for malware and suspicious patterns.

    Uses 30+ built-in rules covering IoT botnets, backdoors, crypto miners,
    web shells, embedded private keys, and more. Results are persisted as
    findings with source='yara_scan'.
    """
    # Get project and all extracted firmware
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    result = await db.execute(
        select(Firmware)
        .where(
            Firmware.project_id == project_id,
            Firmware.extracted_path.isnot(None),
        )
        .order_by(Firmware.created_at.desc())
    )
    firmware_list = result.scalars().all()
    if not firmware_list:
        raise HTTPException(400, "No extracted firmware available — unpack first")

    # Clear previous yara_scan findings to allow re-scanning
    result = await db.execute(
        select(Finding).where(
            Finding.project_id == project_id,
            Finding.source == "yara_scan",
        )
    )
    old_findings = result.scalars().all()
    for f in old_findings:
        await db.delete(f)
    await db.flush()

    # Scan all extracted firmware versions
    loop = asyncio.get_running_loop()
    total_rules = 0
    total_scanned = 0
    total_matched = 0
    all_findings: list[SecurityFinding] = []
    all_errors: list[str] = []

    for firmware in firmware_list:
        scan_result = await loop.run_in_executor(
            None, yara_scan_firmware, firmware.extracted_path
        )
        total_rules = max(total_rules, scan_result.rules_loaded)
        total_scanned += scan_result.files_scanned
        total_matched += scan_result.files_matched
        all_findings.extend(scan_result.findings)
        all_errors.extend(scan_result.errors)

    # Persist findings
    svc = FindingService(db)
    for sf in all_findings:
        await _persist_finding_with_source(svc, project_id, sf, "yara_scan")

    await db.commit()

    return YaraScanResponse(
        status="success",
        rules_loaded=total_rules,
        files_scanned=total_scanned,
        files_matched=total_matched,
        findings_created=len(all_findings),
        errors=all_errors,
    )
