"""MCP tools must not report a CVE count without its enrichment verdict.

An MCP client is an LLM that reads the tool output top-to-bottom and
summarises. "No vulnerabilities found." with no marker becomes "the firmware
is clean" in the assistant's answer — which is precisely the false-clean
verdict the pinned-cache work exists to prevent (Rule #37).

``run_vulnerability_scan`` already did this correctly (warning first, then the
count); it is the reference shape. These tests cover the FOUR tools the
original Rule #47 enumeration missed, plus ``export_sbom``'s VEX summary,
which the review's list also missed.

Rule #35b: every test round-trips through the real ORM via ``make_live_db``.
Rule #46: every marker-present assertion is paired with a healthy canary.
"""

from __future__ import annotations

import json
import uuid

import pytest

from app.ai.tools.sbom import (
    _handle_assess_vulnerabilities,
    _handle_check_component_cves,
    _handle_export_sbom,
    _handle_get_sbom_components,
    _handle_list_vulnerabilities_for_assessment,
)
from app.models.firmware import Firmware
from app.models.project import Project
from app.models.sbom import SbomComponent
from tests._live_db import make_live_db

HEALTHY = {
    "schema_version": 1,
    "engine": "nvd_pinned_cache",
    "manifest_sha": "a1f38452d7df90df6f6b27d5e4762e0f6b4c4a90",
    "enrichment_status": "complete",
    "warning": None,
}

CACHE_DOWN = {
    "schema_version": 1,
    "engine": "nvd_pinned_cache",
    "manifest_sha": None,
    "enrichment_status": "none",
    "warning": "CVE ENRICHMENT DID NOT RUN — the pinned NVD cache was unavailable.",
}


class _Ctx:
    """Minimal ToolContext stand-in: the handlers only use these three."""

    def __init__(self, db, project_id, firmware_id):
        self.db = db
        self.project_id = project_id
        self.firmware_id = firmware_id


async def _seed(db, provenance, *, with_component=True):
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
    if with_component:
        db.add(
            SbomComponent(
                id=uuid.uuid4(),
                firmware_id=fw.id,
                name="busybox",
                version="1.31.0",
                type="library",
                detection_source="binary",
                detection_confidence="high",
                cpe="cpe:2.3:a:busybox:busybox:1.31.0:*:*:*:*:*:*:*",
            )
        )
        await db.flush()
    return _Ctx(db, project.id, fw.id)


def _is_banner_first(out: str) -> bool:
    """The marker must PRECEDE the number it invalidates."""
    return out.lstrip().startswith("!! CVE ENRICHMENT")


# ── list_vulnerabilities_for_assessment ────────────────────────────────────


@pytest.mark.asyncio
async def test_empty_vuln_list_is_qualified_when_enrichment_failed():
    async with make_live_db() as db:
        ctx = await _seed(db, CACHE_DOWN)
        out = await _handle_list_vulnerabilities_for_assessment({}, ctx)
        assert "No vulnerabilities found" in out
        assert _is_banner_first(out), (
            "an assistant reading this top-to-bottom would report the firmware "
            f"as clean; got: {out[:120]!r}"
        )
        assert "NONE" in out


@pytest.mark.asyncio
async def test_canary_empty_vuln_list_is_bare_when_enrichment_healthy():
    async with make_live_db() as db:
        ctx = await _seed(db, HEALTHY)
        out = await _handle_list_vulnerabilities_for_assessment({}, ctx)
        # Default filters are echoed; the point is that NO banner precedes it.
        assert out.startswith("No vulnerabilities found")
        assert "CVE ENRICHMENT" not in out


# ── get_sbom_components ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_component_listing_is_qualified_when_enrichment_failed():
    async with make_live_db() as db:
        ctx = await _seed(db, CACHE_DOWN)
        out = await _handle_get_sbom_components({}, ctx)
        assert "busybox" in out
        assert _is_banner_first(out)


@pytest.mark.asyncio
async def test_canary_component_listing_is_bare_when_enrichment_healthy():
    async with make_live_db() as db:
        ctx = await _seed(db, HEALTHY)
        out = await _handle_get_sbom_components({}, ctx)
        assert out.startswith("Found 1 component(s):")


# ── check_component_cves ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_no_cves_for_component_is_qualified(monkeypatch):
    """_search_nvd returns [] both for 'no CVEs' and for 'could not answer'."""
    import app.services.vulnerability_service as vs

    monkeypatch.setattr(vs, "_search_nvd", lambda *a, **k: [])
    async with make_live_db() as db:
        ctx = await _seed(db, CACHE_DOWN)
        out = await _handle_check_component_cves(
            {"component_name": "busybox", "version": "1.31.0"}, ctx
        )
        assert "No known CVEs found" in out
        assert _is_banner_first(out)


@pytest.mark.asyncio
async def test_canary_no_cves_is_bare_when_enrichment_healthy(monkeypatch):
    import app.services.vulnerability_service as vs

    monkeypatch.setattr(vs, "_search_nvd", lambda *a, **k: [])
    async with make_live_db() as db:
        ctx = await _seed(db, HEALTHY)
        out = await _handle_check_component_cves(
            {"component_name": "busybox", "version": "1.31.0"}, ctx
        )
        assert out.startswith("No known CVEs found")


# ── assess_vulnerabilities ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_triage_output_is_qualified_when_coverage_is_incomplete():
    async with make_live_db() as db:
        ctx = await _seed(db, CACHE_DOWN)
        out = await _handle_assess_vulnerabilities(
            {"assessments": [{"vulnerability_id": str(uuid.uuid4())}]}, ctx
        )
        assert _is_banner_first(out), (
            "'assessed everything' is false when the underlying scan "
            "under-reported the set being triaged"
        )


@pytest.mark.asyncio
async def test_canary_triage_output_is_bare_when_enrichment_healthy():
    async with make_live_db() as db:
        ctx = await _seed(db, HEALTHY)
        out = await _handle_assess_vulnerabilities(
            {"assessments": [{"vulnerability_id": str(uuid.uuid4())}]}, ctx
        )
        assert out.startswith("Assessed 0 vulnerability(ies)")


# ── export_sbom (VEX summary) ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_vex_summary_declares_incomplete_enrichment():
    """VEX asserts exploitability; omission reads as 'not affected'."""
    async with make_live_db() as db:
        ctx = await _seed(db, CACHE_DOWN)
        out = await _handle_export_sbom({"format": "cyclonedx-vex-json"}, ctx)
        doc = json.loads(out)
        assert "CVE_ENRICHMENT_WARNING" in doc
        assert "not a 'not affected' determination" in doc["CVE_ENRICHMENT_WARNING"]
        assert doc["cve_enrichment_status"] == "none"
        # The warning is the FIRST key, so a truncating reader still sees it.
        assert next(iter(doc)) == "CVE_ENRICHMENT_WARNING"


@pytest.mark.asyncio
async def test_canary_vex_summary_clean_when_enrichment_healthy():
    async with make_live_db() as db:
        ctx = await _seed(db, HEALTHY)
        out = await _handle_export_sbom({"format": "cyclonedx-vex-json"}, ctx)
        doc = json.loads(out)
        assert "CVE_ENRICHMENT_WARNING" not in doc
        assert doc["cve_enrichment_status"] == "complete"


# ── Rule #46 META-CANARY on the detector itself ────────────────────────────


def test_meta_canary_banner_detector_would_catch_a_trailing_marker():
    """_is_banner_first must actually reject a banner placed AFTER the count."""
    assert _is_banner_first("!! CVE ENRICHMENT: NONE — ...\n\nFound 0 CVEs")
    assert not _is_banner_first("Found 0 CVEs\n!! CVE ENRICHMENT: NONE — ...")
    assert not _is_banner_first("Found 0 CVEs")
