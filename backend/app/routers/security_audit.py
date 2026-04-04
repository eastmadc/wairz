"""REST endpoints for automated security scanning."""

import asyncio
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import delete, select
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
    firmware_id: uuid.UUID | None = None,
) -> Finding:
    """Convert a SecurityFinding to a DB Finding."""
    return await _persist_finding_with_source(svc, project_id, sf, "security_audit", firmware_id)


async def _persist_finding_with_source(
    svc: FindingService,
    project_id: uuid.UUID,
    sf: SecurityFinding,
    source: str,
    firmware_id: uuid.UUID | None = None,
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
            firmware_id=firmware_id,
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
    await db.execute(
        delete(Finding).where(
            Finding.project_id == project_id,
            Finding.source == "security_audit",
        )
    )
    await db.flush()

    # Scan all extracted firmware versions
    loop = asyncio.get_running_loop()
    total_checks = 0
    all_findings: list[tuple[SecurityFinding, uuid.UUID]] = []
    all_errors: list[str] = []

    for firmware in firmware_list:
        scan_result = await loop.run_in_executor(
            None, run_security_audit, firmware.extracted_path
        )
        total_checks += scan_result.checks_run
        all_findings.extend((sf, firmware.id) for sf in scan_result.findings)
        all_errors.extend(scan_result.errors)

    # Persist findings
    svc = FindingService(db)
    for sf, fw_id in all_findings:
        await _persist_finding(svc, project_id, sf, fw_id)

    await db.commit()

    return SecurityScanResponse(
        status="success",
        checks_run=total_checks,
        findings_created=len(all_findings),
        total_findings=len(all_findings),
        errors=all_errors,
    )


class UefiScanResponse(BaseModel):
    status: str
    modules_scanned: int
    findings_created: int
    summary: dict[str, int] = {}
    errors: list[str] = []


@router.post("/uefi-scan", response_model=UefiScanResponse)
async def scan_uefi_modules(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Scan all PE32+ UEFI modules for security issues.

    Checks DXE drivers, PEI modules, and SMM drivers for:
    - Missing ASLR (DYNAMIC_BASE flag)
    - Missing DEP/NX (NX_COMPAT flag)
    - Writable + executable sections (W^X violation)
    - Missing HIGH_ENTROPY_VA (64-bit ASLR entropy)
    - SMM modules without proper protections (high risk)
    Results are persisted as findings with source='uefi_scan'.
    """
    import os
    import struct
    from app.ai.tools.uefi import _parse_info_txt

    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    result = await db.execute(
        select(Firmware)
        .where(Firmware.project_id == project_id, Firmware.extracted_path.isnot(None))
        .order_by(Firmware.created_at.desc())
    )
    firmware_list = result.scalars().all()
    if not firmware_list:
        raise HTTPException(400, "No extracted firmware available")

    # Clear previous uefi_scan findings
    await db.execute(
        delete(Finding).where(Finding.project_id == project_id, Finding.source == "uefi_scan")
    )
    await db.flush()

    loop = asyncio.get_running_loop()

    def _scan_pe_modules(firmware) -> tuple[list[SecurityFinding], int, list[str]]:
        findings: list[SecurityFinding] = []
        errors: list[str] = []
        scanned = 0

        # Find .dump directory
        dump_dir = None
        root = firmware.extracted_path
        if root and root.endswith(".dump"):
            dump_dir = root
        elif firmware.extraction_dir:
            try:
                for entry in os.scandir(firmware.extraction_dir):
                    if entry.is_dir() and entry.name.endswith(".dump"):
                        dump_dir = entry.path
                        break
            except OSError:
                pass

        if not dump_dir:
            return findings, 0, ["No UEFIExtract output found"]

        # DllCharacteristics flags
        DYNAMIC_BASE = 0x0040
        HIGH_ENTROPY_VA = 0x0020
        NX_COMPAT = 0x0100
        NO_SEH = 0x0400
        FORCE_INTEGRITY = 0x0080

        # PE section flags
        SCN_MEM_EXECUTE = 0x20000000
        SCN_MEM_WRITE = 0x80000000

        for dirpath, dirs, files in os.walk(dump_dir):
            if "info.txt" not in files:
                continue
            info = _parse_info_txt(os.path.join(dirpath, "info.txt"))
            file_guid = info.get("File GUID", "")
            if not file_guid:
                continue

            module_type = info.get("Subtype", "")
            dirname = os.path.basename(dirpath)
            parts = dirname.split(" ", 1)
            module_name = parts[1] if len(parts) > 1 else file_guid

            # Find PE32 section body
            pe_body = None
            for child in os.listdir(dirpath):
                child_path = os.path.join(dirpath, child)
                if not os.path.isdir(child_path):
                    continue
                if "PE32" not in child:
                    continue
                body = os.path.join(child_path, "body.bin")
                if os.path.isfile(body):
                    try:
                        with open(body, "rb") as f:
                            if f.read(2) == b"MZ":
                                pe_body = body
                                break
                    except OSError:
                        pass

            if not pe_body:
                continue

            scanned += 1
            is_smm = "SMM" in module_type

            try:
                with open(pe_body, "rb") as f:
                    data = f.read(1024)  # Headers fit in first 1KB

                if len(data) < 64:
                    continue

                pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
                if pe_offset + 0x70 > len(data):
                    continue
                if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
                    continue

                machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
                is_64bit = machine == 0x8664 or machine == 0xAA64

                # Optional header magic
                opt_offset = pe_offset + 0x18
                opt_magic = struct.unpack_from("<H", data, opt_offset)[0]
                is_pe32plus = opt_magic == 0x020B

                # DllCharacteristics offset depends on PE32 vs PE32+
                dll_char_offset = opt_offset + (0x46 if is_pe32plus else 0x42)
                if dll_char_offset + 2 > len(data):
                    continue
                dll_chars = struct.unpack_from("<H", data, dll_char_offset)[0]

                severity_prefix = "high" if is_smm else "medium"
                module_label = f"{module_name} ({module_type}, GUID: {file_guid})"

                # Check ASLR
                if not (dll_chars & DYNAMIC_BASE):
                    findings.append(SecurityFinding(
                        title=f"UEFI module missing ASLR: {module_name}",
                        severity="high" if is_smm else "medium",
                        description=(
                            f"UEFI {module_type} '{module_label}' does not have DYNAMIC_BASE "
                            f"(ASLR) enabled. This makes the module easier to exploit via "
                            f"memory corruption vulnerabilities."
                        ),
                        evidence=f"DllCharacteristics: 0x{dll_chars:04X} (DYNAMIC_BASE=0x0040 not set)",
                        file_path=module_name,
                        cwe_ids=["CWE-119"],
                    ))

                # Check DEP/NX
                if not (dll_chars & NX_COMPAT):
                    findings.append(SecurityFinding(
                        title=f"UEFI module missing DEP/NX: {module_name}",
                        severity="high" if is_smm else "medium",
                        description=(
                            f"UEFI {module_type} '{module_label}' does not have NX_COMPAT "
                            f"(DEP) enabled. This allows execution of data as code, "
                            f"making exploitation easier."
                        ),
                        evidence=f"DllCharacteristics: 0x{dll_chars:04X} (NX_COMPAT=0x0100 not set)",
                        file_path=module_name,
                        cwe_ids=["CWE-119"],
                    ))

                # Check HIGH_ENTROPY_VA for 64-bit
                if is_64bit and not (dll_chars & HIGH_ENTROPY_VA):
                    findings.append(SecurityFinding(
                        title=f"UEFI module missing high-entropy ASLR: {module_name}",
                        severity="low",
                        description=(
                            f"64-bit UEFI {module_type} '{module_label}' does not have "
                            f"HIGH_ENTROPY_VA enabled. This limits ASLR entropy."
                        ),
                        evidence=f"DllCharacteristics: 0x{dll_chars:04X} (HIGH_ENTROPY_VA=0x0020 not set)",
                        file_path=module_name,
                        cwe_ids=["CWE-119"],
                    ))

                # Check W^X: scan section headers for writable + executable
                num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
                size_opt = struct.unpack_from("<H", data, pe_offset + 0x14)[0]
                section_start = pe_offset + 0x18 + size_opt

                for i in range(min(num_sections, 20)):
                    sec_offset = section_start + i * 40
                    if sec_offset + 40 > len(data):
                        break
                    sec_name = data[sec_offset:sec_offset + 8].rstrip(b"\x00").decode("ascii", errors="replace")
                    sec_chars = struct.unpack_from("<I", data, sec_offset + 36)[0]
                    if (sec_chars & SCN_MEM_EXECUTE) and (sec_chars & SCN_MEM_WRITE):
                        findings.append(SecurityFinding(
                            title=f"UEFI module has W^X violation: {module_name}",
                            severity="high",
                            description=(
                                f"UEFI {module_type} '{module_label}' has section '{sec_name}' "
                                f"that is both writable and executable. This violates the W^X "
                                f"principle and enables code injection attacks."
                            ),
                            evidence=f"Section '{sec_name}' characteristics: 0x{sec_chars:08X} (WRITE|EXECUTE)",
                            file_path=module_name,
                            cwe_ids=["CWE-119", "CWE-693"],
                        ))

            except Exception as e:
                errors.append(f"Error scanning {module_name}: {e}")

        return findings, scanned, errors

    all_findings: list[tuple[SecurityFinding, uuid.UUID]] = []
    total_scanned = 0
    all_errors: list[str] = []

    for firmware in firmware_list:
        findings, scanned, errors = await loop.run_in_executor(
            None, _scan_pe_modules, firmware
        )
        total_scanned += scanned
        all_findings.extend((sf, firmware.id) for sf in findings)
        all_errors.extend(errors)

    # Persist findings
    svc = FindingService(db)
    for sf, fw_id in all_findings:
        await _persist_finding_with_source(svc, project_id, sf, "uefi_scan", fw_id)
    await db.commit()

    # Summary by type
    summary: dict[str, int] = {}
    for sf, _ in all_findings:
        key = sf.title.split(":")[0] if ":" in sf.title else sf.title
        summary[key] = summary.get(key, 0) + 1

    return UefiScanResponse(
        status="success",
        modules_scanned=total_scanned,
        findings_created=len(all_findings),
        summary=summary,
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
    await db.execute(
        delete(Finding).where(
            Finding.project_id == project_id,
            Finding.source == "yara_scan",
        )
    )
    await db.flush()

    # Scan all extracted firmware versions
    loop = asyncio.get_running_loop()
    total_rules = 0
    total_scanned = 0
    total_matched = 0
    all_yara_findings: list[tuple[SecurityFinding, uuid.UUID]] = []
    all_errors: list[str] = []

    for firmware in firmware_list:
        scan_result = await loop.run_in_executor(
            None, yara_scan_firmware, firmware.extracted_path
        )
        total_rules = max(total_rules, scan_result.rules_loaded)
        total_scanned += scan_result.files_scanned
        total_matched += scan_result.files_matched
        all_yara_findings.extend((sf, firmware.id) for sf in scan_result.findings)
        all_errors.extend(scan_result.errors)

    # Persist findings
    svc = FindingService(db)
    for sf, fw_id in all_yara_findings:
        await _persist_finding_with_source(svc, project_id, sf, "yara_scan", fw_id)

    await db.commit()

    return YaraScanResponse(
        status="success",
        rules_loaded=total_rules,
        files_scanned=total_scanned,
        files_matched=total_matched,
        findings_created=len(all_yara_findings),
        errors=all_errors,
    )
