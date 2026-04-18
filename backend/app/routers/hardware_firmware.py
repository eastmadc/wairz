"""REST endpoints for the hardware firmware graph.

Endpoints:

* ``GET .../`` — list detected hardware firmware blobs (Phase 5)
* ``GET .../{blob_id}`` — one blob with full metadata (Phase 5)
* ``GET .../{blob_id}/cves`` — CVE matches for one blob (Phase 5)
* ``POST .../cve-match`` — (re-)run the three-tier CVE matcher (Phase 5)
* ``GET .../firmware-edges`` — on-demand driver <-> firmware edges for the
  component-map overlay.  Separate from the cached component_map graph so
  the frontend can toggle the overlay without invalidating heavy caches.
* ``GET .../drivers`` — per-driver summary of requested firmware blobs
  (resolved vs unresolved).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import case, func, literal, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.hardware_firmware import HardwareFirmwareBlob
from app.models.sbom import SbomVulnerability
from app.routers.deps import resolve_firmware as _resolve_firmware
from app.schemas.hardware_firmware import (
    FirmwareDriverResponse,
    FirmwareDriversListResponse,
    FirmwareEdgeResponse,
    FirmwareEdgesResponse,
    HardwareFirmwareBlobResponse,
    HardwareFirmwareCveAggregate,
    HardwareFirmwareListResponse,
)


# Severity ordering for the per-blob max_severity rollup. Postgres
# numeric MAX() works on the rank, then we map back to the label.
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_RANK_TO_SEVERITY = {v: k for k, v in _SEVERITY_RANK.items()}


def _severity_case():
    """SQL CASE that ranks SbomVulnerability.severity for MAX() aggregation."""
    return case(
        (SbomVulnerability.severity == "critical", 4),
        (SbomVulnerability.severity == "high", 3),
        (SbomVulnerability.severity == "medium", 2),
        (SbomVulnerability.severity == "low", 1),
        else_=0,
    )


# Kernel-tier set must stay in sync with the matcher (cve_matcher.py)
# and with the run_cve_match aggregate split below.
_KERNEL_TIERS = {"kernel_cpe", "kernel_subsystem"}
from app.services.hardware_firmware.cve_matcher import match_firmware_cves
from app.services.hardware_firmware.graph import build_driver_firmware_graph
from app.services.hardware_firmware.hbom_export import build_hbom

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/hardware-firmware",
    tags=["hardware-firmware"],
)


def _blob_to_response(
    blob: HardwareFirmwareBlob,
    cve_count: int = 0,
    advisory_count: int = 0,
    max_severity: str | None = None,
) -> HardwareFirmwareBlobResponse:
    """Build a response model from an ORM row.

    Falls back to explicit dict construction because the
    ``metadata``/``metadata_`` alias via ``validation_alias`` is sensitive
    to ORM attribute name vs column name and has surprised us before.

    ``cve_count`` / ``advisory_count`` / ``max_severity`` are sourced from
    the list endpoint's GROUP BY join against ``sbom_vulnerabilities`` --
    they default to 0/None for callers (single-blob fetch) that don't
    pre-compute them.
    """
    return HardwareFirmwareBlobResponse(
        id=blob.id,
        firmware_id=blob.firmware_id,
        blob_path=blob.blob_path,
        partition=blob.partition,
        blob_sha256=blob.blob_sha256,
        file_size=blob.file_size,
        category=blob.category,
        vendor=blob.vendor,
        format=blob.format,
        version=blob.version,
        signed=blob.signed,
        signature_algorithm=blob.signature_algorithm,
        cert_subject=blob.cert_subject,
        chipset_target=blob.chipset_target,
        driver_references=blob.driver_references,
        sbom_component_id=blob.sbom_component_id,
        metadata=blob.metadata_ or {},
        detection_source=blob.detection_source,
        detection_confidence=blob.detection_confidence,
        created_at=blob.created_at,
        cve_count=cve_count,
        advisory_count=advisory_count,
        max_severity=max_severity,
    )


@router.get("", response_model=HardwareFirmwareListResponse)
async def list_blobs(
    category: str | None = None,
    vendor: str | None = None,
    signed_only: bool = False,
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
) -> HardwareFirmwareListResponse:
    """List detected hardware firmware blobs for the resolved firmware.

    Each row is decorated with cve_count / advisory_count / max_severity
    rolled up from sbom_vulnerabilities via a single GROUP BY (no N+1).
    The UI uses these to badge the tree without an extra fetch per blob.
    """
    stmt = select(HardwareFirmwareBlob).where(
        HardwareFirmwareBlob.firmware_id == firmware.id,
    )
    if category:
        stmt = stmt.where(HardwareFirmwareBlob.category == category)
    if vendor:
        stmt = stmt.where(HardwareFirmwareBlob.vendor == vendor)
    if signed_only:
        stmt = stmt.where(HardwareFirmwareBlob.signed == "signed")
    stmt = stmt.order_by(HardwareFirmwareBlob.category, HardwareFirmwareBlob.blob_path)
    blobs = (await db.execute(stmt)).scalars().all()

    # Single GROUP BY across all sbom_vulnerabilities for this firmware,
    # split into actual-CVE vs ADVISORY-* presence flags.  We project
    # max_severity via a CASE-rank so the badge color reflects the
    # highest severity across either category.
    rollup_stmt = select(
        SbomVulnerability.blob_id,
        func.sum(
            case((SbomVulnerability.cve_id.like("ADVISORY-%"), 0), else_=1)
        ).label("cve_count"),
        func.sum(
            case((SbomVulnerability.cve_id.like("ADVISORY-%"), 1), else_=0)
        ).label("advisory_count"),
        func.max(_severity_case()).label("max_severity_rank"),
    ).where(
        SbomVulnerability.firmware_id == firmware.id,
        SbomVulnerability.blob_id.is_not(None),
    ).group_by(SbomVulnerability.blob_id)
    rollup = {
        r.blob_id: (
            int(r.cve_count or 0),
            int(r.advisory_count or 0),
            _RANK_TO_SEVERITY.get(int(r.max_severity_rank or 0)),
        )
        for r in (await db.execute(rollup_stmt)).all()
    }

    blob_rows: list[HardwareFirmwareBlobResponse] = []
    for b in blobs:
        cve_n, adv_n, max_sev = rollup.get(b.id, (0, 0, None))
        blob_rows.append(_blob_to_response(b, cve_n, adv_n, max_sev))
    return HardwareFirmwareListResponse(blobs=blob_rows, total=len(blob_rows))


@router.get("/cve-aggregate", response_model=HardwareFirmwareCveAggregate)
async def get_cve_aggregate(
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
) -> HardwareFirmwareCveAggregate:
    """Read-only summary of persisted hw-firmware CVEs for this firmware.

    Distinct from POST /cve-match (which RUNS the matcher); this just
    counts what already lives in sbom_vulnerabilities so the UI header
    badge can render on page load without re-running the matcher every
    time the user navigates back to the page.

    Splits kernel-tier CVEs out from hw-firmware CVEs to mirror the
    aggregate semantics of POST /cve-match.
    """
    stmt = select(
        SbomVulnerability.cve_id,
        SbomVulnerability.match_tier,
        func.max(SbomVulnerability.created_at).label("seen_at"),
    ).where(
        SbomVulnerability.firmware_id == firmware.id,
        SbomVulnerability.blob_id.is_not(None),
    ).group_by(SbomVulnerability.cve_id, SbomVulnerability.match_tier)
    rows = (await db.execute(stmt)).all()

    hwfw_cves: set[str] = set()
    kernel_cves: set[str] = set()
    advisories: set[str] = set()
    last_seen = None
    for cve_id, tier, seen in rows:
        if seen is not None and (last_seen is None or seen > last_seen):
            last_seen = seen
        if cve_id.startswith("ADVISORY-"):
            advisories.add(cve_id)
        elif tier in _KERNEL_TIERS:
            kernel_cves.add(cve_id)
        else:
            hwfw_cves.add(cve_id)
    return HardwareFirmwareCveAggregate(
        hw_firmware_cves=len(hwfw_cves),
        kernel_cves=len(kernel_cves),
        advisory_count=len(advisories),
        last_match_at=last_seen,
    )


@router.get("/firmware-edges", response_model=FirmwareEdgesResponse)
async def get_firmware_edges(
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
) -> FirmwareEdgesResponse:
    """Return driver <-> firmware edges for the component-map overlay."""
    result = await build_driver_firmware_graph(firmware.id, db)
    return FirmwareEdgesResponse(
        edges=[
            FirmwareEdgeResponse(
                driver_path=e.driver_path,
                firmware_name=e.firmware_name,
                firmware_blob_path=e.firmware_blob_path,
                source=e.source,
            )
            for e in result.edges
        ],
        kmod_drivers=result.kmod_drivers,
        dtb_sources=result.dtb_sources,
        unresolved_count=result.unresolved_count,
    )


@router.get("/drivers", response_model=FirmwareDriversListResponse)
async def list_drivers(
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
) -> FirmwareDriversListResponse:
    """List drivers (kmod + vmlinux + DTB) with the firmware they request."""
    result = await build_driver_firmware_graph(firmware.id, db)
    by_driver: dict[str, dict] = {}
    for e in result.edges:
        rec = by_driver.setdefault(
            e.driver_path,
            {
                "driver_path": e.driver_path,
                "format": _infer_format(e.driver_path, e.source),
                "firmware_deps": [],
                "firmware_blobs": [],
                "total": 0,
            },
        )
        rec["firmware_deps"].append(e.firmware_name)
        if e.firmware_blob_path:
            rec["firmware_blobs"].append(e.firmware_blob_path)
        rec["total"] += 1

    drivers = [FirmwareDriverResponse(**d) for d in by_driver.values()]
    return FirmwareDriversListResponse(drivers=drivers, total=len(drivers))


@router.post("/cve-match")
async def run_cve_match(
    force_rescan: bool = False,
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Run the three-tier CVE matcher for the resolved firmware.

    Persists new matches in ``sbom_vulnerabilities`` and commits so the
    follow-up ``/{blob_id}/cves`` query reflects the results.
    """
    matches = await match_firmware_cves(firmware.id, db, force_rescan=force_rescan)
    await db.commit()
    # Report distinct CVEs + a per-lane breakdown so the UI doesn't
    # present the cartesian (kernel_cve × kernel_module) row count as
    # the headline "match" number. Tiers 4 and 5 project each kernel
    # CVE onto every kernel_module blob (by design — so per-blob CVE
    # queries reflect kernel findings) which inflates the row count by
    # ~O(CVEs × modules). Aggregate UI needs distinct-CVE semantics.
    kernel_matches = [m for m in matches if m.tier in _KERNEL_TIERS]
    hwfw_matches = [m for m in matches if m.tier not in _KERNEL_TIERS]
    return {
        "count": len({m.cve_id for m in matches}),
        "rows": len(matches),
        "hw_firmware_cves": len({m.cve_id for m in hwfw_matches}),
        "kernel_cves": len({m.cve_id for m in kernel_matches}),
        "kernel_module_rows": len(kernel_matches),
    }


@router.get("/cdx.json")
async def export_hbom(
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Export a CycloneDX v1.6 HBOM for the resolved firmware.

    Emits one ``hardware`` + one ``firmware`` component per detected blob,
    linked via ``dependencies.provides``.  Any ``sbom_vulnerabilities``
    rows with ``blob_id`` set are attached to the corresponding firmware
    component bom-ref.

    The response is served as ``application/json`` (FastAPI default) and
    is structurally JSON rather than matching a Pydantic schema — the
    CycloneDX spec is the contract.
    """
    return await build_hbom(firmware.id, db)


@router.get("/{blob_id}", response_model=HardwareFirmwareBlobResponse)
async def get_blob(
    blob_id: uuid.UUID,
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
) -> HardwareFirmwareBlobResponse:
    """Fetch a single detected hardware firmware blob by id."""
    stmt = select(HardwareFirmwareBlob).where(
        HardwareFirmwareBlob.id == blob_id,
        HardwareFirmwareBlob.firmware_id == firmware.id,
    )
    blob = (await db.execute(stmt)).scalar_one_or_none()
    if blob is None:
        raise HTTPException(404, "Blob not found")
    return _blob_to_response(blob)


@router.get("/{blob_id}/cves")
async def get_blob_cves(
    blob_id: uuid.UUID,
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Return persisted CVE matches for a single hardware firmware blob."""
    # Validate the blob belongs to this firmware before returning CVEs.
    blob_stmt = select(HardwareFirmwareBlob.id).where(
        HardwareFirmwareBlob.id == blob_id,
        HardwareFirmwareBlob.firmware_id == firmware.id,
    )
    if (await db.execute(blob_stmt)).scalar_one_or_none() is None:
        raise HTTPException(404, "Blob not found")

    stmt = (
        select(SbomVulnerability)
        .where(
            SbomVulnerability.blob_id == blob_id,
            SbomVulnerability.firmware_id == firmware.id,
        )
        .order_by(SbomVulnerability.created_at.desc())
    )
    vulns = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(v.id),
            "blob_id": str(v.blob_id) if v.blob_id else None,
            "cve_id": v.cve_id,
            "severity": v.severity,
            "cvss_score": float(v.cvss_score) if v.cvss_score is not None else None,
            "description": v.description,
            "match_confidence": v.match_confidence,
            "match_tier": v.match_tier,
            "resolution_status": v.resolution_status,
            "created_at": v.created_at.isoformat() if v.created_at else None,
        }
        for v in vulns
    ]


def _infer_format(driver_path: str, source: str) -> str:
    if source == "kmod_modinfo":
        return "ko"
    if source == "vmlinux_strings":
        return "vmlinux"
    if source == "dtb_firmware_name":
        return "dtb"
    return "unknown"
