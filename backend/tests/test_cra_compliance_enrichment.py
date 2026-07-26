"""CRA evidence chain must not assert compliance from a scan that never looked.

The highest-consequence surface of review D2: CRA Annex I 1.2 ("No known
exploitable vulnerabilities"), 2.1 and 2.2 are auto-populated by matching
findings from ``run_vulnerability_scan``. When no findings match, the service
marks the requirement ``pass``. A vulnerability scan run against a missing or
half-populated pinned NVD cache (Rule #37) emits zero findings — so the
regulatory artifact asserted compliance from a scan that never consulted a CVE
source.

Rule #35b: every assertion here round-trips through the real ORM via
``make_live_db`` and SELECTs the persisted row — a mock would confirm
"auto_populate was called" while the demotion silently never fired.

Rule #46: paired canaries throughout — each "is demoted" assertion has a
companion proving the SAME code path leaves a healthy scan alone, so
"demote everything" would not satisfy the suite.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.models.cra_compliance import CraAssessment, CraRequirementResult  # noqa: F401
from app.models.firmware import Firmware
from app.models.project import Project
from app.services.cra_compliance_service import (
    CRA_REQUIREMENTS,
    CVE_ENRICHMENT_TOOL_SOURCES,
    CRAComplianceService,
)
from tests._live_db import make_live_db

# Requirements whose evidence is an automated CVE scan.
CVE_REQ_IDS = sorted(
    r["requirement_id"]
    for r in CRA_REQUIREMENTS
    if CVE_ENRICHMENT_TOOL_SOURCES.intersection(r.get("tool_sources") or [])
)

HEALTHY = {
    "schema_version": 1,
    "engine": "nvd_pinned_cache",
    "manifest_sha": "a1f38452d7df90df6f6b27d5e4762e0f6b4c4a90",
    "enrichment_status": "complete",
    "warning": None,
    "lookups": 42,
}

CACHE_DOWN = {
    "schema_version": 1,
    "engine": "nvd_pinned_cache",
    "manifest_sha": None,
    "enrichment_status": "none",
    "warning": "CVE ENRICHMENT DID NOT RUN — the pinned NVD cache was unavailable.",
    "lookups": 42,
}

DEGRADED = {**CACHE_DOWN, "enrichment_status": "partial", "warning": "under-reports"}
NOTHING_CHECKED = {**HEALTHY, "enrichment_status": "not_applicable", "lookups": 0}


async def _seed(db, provenance):
    project = Project(id=uuid.uuid4(), name="p", status="ready")
    db.add(project)
    await db.flush()
    fw = Firmware(
        id=uuid.uuid4(),
        project_id=project.id,
        original_filename="fw.bin",
        storage_path="/tmp/fw.bin",
        sha256="0" * 64,
        file_size=1,
        vuln_scan_provenance=provenance,
    )
    db.add(fw)
    await db.flush()
    return project, fw


def _statuses(assessment) -> dict[str, str]:
    return {r.requirement_id: r.status for r in assessment.requirement_results}


# ── the gate ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "provenance,label",
    [(CACHE_DOWN, "none"), (DEGRADED, "partial"), (NOTHING_CHECKED, "not_applicable")],
)
@pytest.mark.asyncio
async def test_cve_requirements_are_not_auto_passed_without_enrichment(
    provenance, label
):
    async with make_live_db() as db:
        project, fw = await _seed(db, provenance)
        svc = CRAComplianceService(db)
        assessment = await svc.create_assessment(
            project_id=project.id, firmware_id=fw.id
        )
        updated = await svc.auto_populate(assessment.id)

        statuses = _statuses(updated)
        for req_id in CVE_REQ_IDS:
            assert statuses[req_id] == "not_tested", (
                f"{req_id} was auto-passed with enrichment={label} — that is a "
                f"regulatory assertion of compliance from a scan that never looked"
            )

        # Rule #35b: SELECT the persisted rows, not the in-memory objects.
        rows = (
            await db.execute(
                select(CraRequirementResult).where(
                    CraRequirementResult.assessment_id == assessment.id,
                    CraRequirementResult.requirement_id.in_(CVE_REQ_IDS),
                )
            )
        ).scalars().all()
        assert len(rows) == len(CVE_REQ_IDS)
        for row in rows:
            assert row.status == "not_tested"
            assert "NOT SUBSTANTIATED" in (row.evidence_summary or "")
            assert label in (row.evidence_summary or "")


@pytest.mark.asyncio
async def test_canary_healthy_enrichment_still_auto_passes():
    """Paired canary — the gate must not demote everything unconditionally."""
    async with make_live_db() as db:
        project, fw = await _seed(db, HEALTHY)
        svc = CRAComplianceService(db)
        assessment = await svc.create_assessment(
            project_id=project.id, firmware_id=fw.id
        )
        updated = await svc.auto_populate(assessment.id)
        statuses = _statuses(updated)
        for req_id in CVE_REQ_IDS:
            assert statuses[req_id] == "pass", (
                f"{req_id} was demoted despite a healthy pinned-cache scan — the "
                f"gate is over-firing and the demotion assertions above are vacuous"
            )


@pytest.mark.asyncio
async def test_non_cve_requirements_are_unaffected_by_enrichment():
    """The demotion is scoped: only CVE-evidenced requirements are touched."""
    async with make_live_db() as db:
        project, fw = await _seed(db, CACHE_DOWN)
        svc = CRAComplianceService(db)
        assessment = await svc.create_assessment(
            project_id=project.id, firmware_id=fw.id
        )
        updated = await svc.auto_populate(assessment.id)
        statuses = _statuses(updated)
        # 1.1 (hardcoded creds) has patterns but is NOT CVE-evidenced.
        assert "annex1_part1_1.1" not in CVE_REQ_IDS
        assert statuses["annex1_part1_1.1"] == "pass"


@pytest.mark.asyncio
async def test_null_provenance_does_not_substantiate_compliance():
    """A scan predating provenance stamping is unknown, not clean (Rule #53)."""
    async with make_live_db() as db:
        project, fw = await _seed(db, None)
        svc = CRAComplianceService(db)
        assessment = await svc.create_assessment(
            project_id=project.id, firmware_id=fw.id
        )
        updated = await svc.auto_populate(assessment.id)
        for req_id in CVE_REQ_IDS:
            assert _statuses(updated)[req_id] == "not_tested"


@pytest.mark.asyncio
async def test_project_scoped_assessment_cannot_substantiate_cve_compliance():
    """No firmware_id ⇒ no provenance to point at ⇒ fails safe."""
    async with make_live_db() as db:
        project, _fw = await _seed(db, HEALTHY)
        svc = CRAComplianceService(db)
        assessment = await svc.create_assessment(project_id=project.id)
        updated = await svc.auto_populate(assessment.id)
        for req_id in CVE_REQ_IDS:
            assert _statuses(updated)[req_id] == "not_tested"


# ── the exported artifacts ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_checklist_export_carries_the_enrichment_block_and_caveats():
    async with make_live_db() as db:
        project, fw = await _seed(db, DEGRADED)
        svc = CRAComplianceService(db)
        assessment = await svc.create_assessment(
            project_id=project.id, firmware_id=fw.id
        )
        await svc.auto_populate(assessment.id)
        doc = await svc.export_checklist(assessment.id)

        block = doc["cve_enrichment"]
        assert block["status"] == "partial"
        assert block["substantiates_no_known_vulnerabilities"] is False
        assert block["warning"]
        assert sorted(block["affected_requirements"]) == CVE_REQ_IDS

        entries = (
            doc["part1_security_requirements"]["requirements"]
            + doc["part2_vulnerability_handling"]["requirements"]
        )
        by_id = {e["requirement_id"]: e for e in entries}
        for req_id in CVE_REQ_IDS:
            assert by_id[req_id]["cve_evidenced"] is True
            assert by_id[req_id]["enrichment_caveat"], (
                f"{req_id} left the building with no enrichment caveat"
            )
        assert by_id["annex1_part1_1.1"]["enrichment_caveat"] is None


@pytest.mark.asyncio
async def test_canary_checklist_export_has_no_caveats_when_healthy():
    async with make_live_db() as db:
        project, fw = await _seed(db, HEALTHY)
        svc = CRAComplianceService(db)
        assessment = await svc.create_assessment(
            project_id=project.id, firmware_id=fw.id
        )
        await svc.auto_populate(assessment.id)
        doc = await svc.export_checklist(assessment.id)
        assert doc["cve_enrichment"]["substantiates_no_known_vulnerabilities"] is True
        entries = (
            doc["part1_security_requirements"]["requirements"]
            + doc["part2_vulnerability_handling"]["requirements"]
        )
        assert all(e["enrichment_caveat"] is None for e in entries)


@pytest.mark.asyncio
async def test_article14_notification_marks_an_incomplete_component_list():
    async with make_live_db() as db:
        project, fw = await _seed(db, CACHE_DOWN)
        svc = CRAComplianceService(db)
        assessment = await svc.create_assessment(
            project_id=project.id, firmware_id=fw.id
        )
        doc = await svc.export_article14_notification(assessment.id, "CVE-2024-1234")
        assert doc["cve_enrichment"]["status"] == "none"
        assert doc["cve_enrichment"]["affected_components_complete"] is False
        assert doc["cve_enrichment"]["warning"]


@pytest.mark.asyncio
async def test_canary_article14_complete_when_enrichment_healthy():
    async with make_live_db() as db:
        project, fw = await _seed(db, HEALTHY)
        svc = CRAComplianceService(db)
        assessment = await svc.create_assessment(
            project_id=project.id, firmware_id=fw.id
        )
        doc = await svc.export_article14_notification(assessment.id, "CVE-2024-1234")
        assert doc["cve_enrichment"]["affected_components_complete"] is True


# ── Rule #46 META-CANARY on the requirement set itself ─────────────────────


def test_meta_canary_cve_requirement_set_is_non_empty_and_locked():
    """If CVE_REQ_IDS were empty, every demotion assertion above is vacuous."""
    assert CVE_REQ_IDS, (
        "no requirement is CVE-evidenced — every demotion test above would "
        "pass trivially; CVE_ENRICHMENT_TOOL_SOURCES no longer intersects "
        "CRA_REQUIREMENTS"
    )
    assert "annex1_part1_1.2" in CVE_REQ_IDS  # "No known exploitable vulnerabilities"
    # Rule #31 width lesson, caught by this very lock: the hand-count was 3
    # (1.2 / 2.1 / 2.2); the real intersection is 4 — annex1_part1_1.5
    # "Address vulnerabilities without delay" is evidenced SOLELY by
    # run_vulnerability_scan, so auto-passing it from an unenriched scan is
    # the same false-clean assertion.
    assert len(CVE_REQ_IDS) == 4, (
        f"CVE-evidenced requirement set changed to {CVE_REQ_IDS} — confirm the "
        f"new members are genuinely CVE-scan-evidenced, then update this lock"
    )
