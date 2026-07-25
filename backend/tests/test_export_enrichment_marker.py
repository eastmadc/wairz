"""Exported artifacts must carry the CVE-enrichment verdict (review D2).

These are the artifacts that LEAVE THE BUILDING — a .wairz project archive and
a CycloneDX HBOM are read offline, by an importer or an auditor with no access
to this database. An empty ``sbom_vulnerabilities.json`` or a missing
``vulnerabilities`` array is byte-identical whether it means "no known CVEs" or
"the pinned NVD cache was unavailable and nothing was looked up" (Rule #37).

Rule #35b: both suites round-trip through the real ORM via ``make_live_db``.
Rule #46: every "marker is present" assertion is paired with a healthy-scan
canary, so "always warn" would not satisfy the suite.
"""

from __future__ import annotations

import io
import json
import uuid
import zipfile

import pytest

from app.models.firmware import Firmware
from app.models.hardware_firmware import HardwareFirmwareBlob  # noqa: F401
from app.models.project import Project
from app.services.export_service import ExportService
from app.services.hardware_firmware.hbom_export import build_hbom
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


async def _seed(db, provenance):
    project = Project(id=uuid.uuid4(), name="p", status="ready")
    db.add(project)
    await db.flush()
    fw = Firmware(
        id=uuid.uuid4(),
        project_id=project.id,
        original_filename="router.bin",
        storage_path="/nonexistent/router.bin",
        sha256="0" * 64,
        file_size=1,
        vuln_scan_provenance=provenance,
    )
    db.add(fw)
    await db.flush()
    return project, fw


def _read(buf: io.BytesIO, name: str) -> str:
    with zipfile.ZipFile(buf) as zf:
        return zf.read(name).decode()


def _names(buf: io.BytesIO) -> set[str]:
    with zipfile.ZipFile(buf) as zf:
        return set(zf.namelist())


# ── .wairz project archive ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_archive_flags_a_firmware_whose_vuln_list_is_untrustworthy():
    async with make_live_db() as db:
        project, fw = await _seed(db, CACHE_DOWN)
        buf = await ExportService(db).export_project(project.id)

        names = _names(buf)
        assert "CVE_ENRICHMENT_WARNING.txt" in names, (
            "an archive whose vulnerability data was never enriched left the "
            "building with no top-level marker"
        )
        top = _read(buf, "CVE_ENRICHMENT_WARNING.txt")
        assert "not looked up" in top
        assert str(fw.id) in top

        sidecar = json.loads(
            _read(buf, f"firmware/{fw.id}/sbom_vulnerabilities.enrichment.json")
        )
        assert sidecar["applies_to"] == "sbom_vulnerabilities.json"
        assert sidecar["trustworthy"] is False
        assert sidecar["status"] == "none"
        assert sidecar["vulnerability_count"] == 0
        assert sidecar["warning"]

        meta = json.loads(_read(buf, f"firmware/{fw.id}/metadata.json"))
        assert meta["cve_enrichment"]["trustworthy"] is False


@pytest.mark.asyncio
async def test_canary_healthy_archive_has_no_top_level_warning():
    """The file's PRESENCE is the signal — a clean export must not carry it."""
    async with make_live_db() as db:
        project, fw = await _seed(db, HEALTHY)
        buf = await ExportService(db).export_project(project.id)

        assert "CVE_ENRICHMENT_WARNING.txt" not in _names(buf)
        sidecar = json.loads(
            _read(buf, f"firmware/{fw.id}/sbom_vulnerabilities.enrichment.json")
        )
        assert sidecar["trustworthy"] is True
        assert sidecar["status"] == "complete"
        assert "a1f38452d7df" in sidecar["source"]


@pytest.mark.asyncio
async def test_archive_sidecar_is_always_written_even_when_clean():
    """A reader must never have to infer meaning from a MISSING sidecar."""
    async with make_live_db() as db:
        project, fw = await _seed(db, None)
        buf = await ExportService(db).export_project(project.id)
        sidecar = json.loads(
            _read(buf, f"firmware/{fw.id}/sbom_vulnerabilities.enrichment.json")
        )
        # NULL provenance is unknown, which is NOT trustworthy (Rule #53).
        assert sidecar["status"] == "unknown"
        assert sidecar["trustworthy"] is False
        assert "CVE_ENRICHMENT_WARNING.txt" in _names(buf)


# ── CycloneDX HBOM ─────────────────────────────────────────────────────────


def _props(hbom: dict) -> dict[str, str]:
    return {p["name"]: p["value"] for p in hbom["metadata"]["properties"]}


@pytest.mark.asyncio
async def test_hbom_metadata_declares_untrustworthy_enrichment():
    async with make_live_db() as db:
        _project, fw = await _seed(db, CACHE_DOWN)
        hbom = await build_hbom(fw.id, db)

        props = _props(hbom)
        assert props["wairz:cve_enrichment:status"] == "none"
        assert props["wairz:cve_enrichment:trustworthy"] == "false"
        assert "INCOMPLETE" in props["wairz:cve_enrichment:advisory"]
        assert props["wairz:cve_enrichment:warning"]
        # The absent vulnerabilities array is exactly what the advisory covers.
        assert "vulnerabilities" not in hbom


@pytest.mark.asyncio
async def test_canary_healthy_hbom_carries_no_advisory():
    async with make_live_db() as db:
        _project, fw = await _seed(db, HEALTHY)
        hbom = await build_hbom(fw.id, db)

        props = _props(hbom)
        assert props["wairz:cve_enrichment:trustworthy"] == "true"
        assert props["wairz:cve_enrichment:status"] == "complete"
        assert "wairz:cve_enrichment:advisory" not in props
        assert "wairz:cve_enrichment:warning" not in props


@pytest.mark.asyncio
async def test_hbom_stays_valid_cyclonedx_shape():
    """properties[] is the spec's extension point — don't break the document."""
    async with make_live_db() as db:
        _project, fw = await _seed(db, CACHE_DOWN)
        hbom = await build_hbom(fw.id, db)
        assert hbom["bomFormat"] == "CycloneDX"
        assert hbom["specVersion"] == "1.6"
        for prop in hbom["metadata"]["properties"]:
            assert set(prop) == {"name", "value"}
            assert isinstance(prop["value"], str)
        # Round-trips as JSON (no non-serialisable provenance leaked in).
        json.dumps(hbom)
