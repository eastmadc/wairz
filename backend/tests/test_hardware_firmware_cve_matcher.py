"""Unit tests for the three-tier hardware firmware CVE matcher.

Uses the same mock-session pattern as ``test_hardware_firmware_graph.py``.
Covers the Phase 4 surface: YAML load, curated match rules, metadata
fallback, advisory-only families, persistence, and idempotency.
"""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.models.hardware_firmware import HardwareFirmwareBlob
from app.models.sbom import SbomVulnerability
from app.services.hardware_firmware.cve_matcher import (
    CveMatch,
    _load_known_firmware,
    _match_curated,
    _stringify_metadata,
    match_firmware_cves,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_blob(
    *,
    vendor: str | None,
    category: str,
    version: str | None = None,
    chipset_target: str | None = None,
    metadata: dict | None = None,
    blob_id: uuid.UUID | None = None,
) -> MagicMock:
    """Build a HardwareFirmwareBlob-shaped mock."""
    blob = MagicMock(spec=HardwareFirmwareBlob)
    blob.id = blob_id or uuid.uuid4()
    blob.vendor = vendor
    blob.category = category
    blob.version = version
    blob.chipset_target = chipset_target
    blob.metadata_ = metadata or {}
    return blob


def _mock_db_for_matcher(
    *,
    blobs: list,
    existing: list[tuple[uuid.UUID, str]] | None = None,
) -> AsyncMock:
    """Mock AsyncSession: first execute() returns blobs, second returns dedup keys."""
    existing = existing or []

    blobs_result = MagicMock()
    blobs_result.scalars.return_value.all.return_value = blobs

    existing_result = MagicMock()
    # second execute() is `select(blob_id, cve_id)` — code does .all()
    existing_result.all.return_value = existing

    db = AsyncMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.execute = AsyncMock(side_effect=[blobs_result, existing_result])
    return db


# ---------------------------------------------------------------------------
# YAML load
# ---------------------------------------------------------------------------


def test_load_known_firmware_has_seeded_entries() -> None:
    families = _load_known_firmware()
    assert isinstance(families, list)
    assert len(families) >= 10, (
        f"Expected >=10 curated CVE families, got {len(families)}"
    )
    # Each family needs the core fields for matching.
    for fam in families:
        assert "name" in fam
        assert "vendor" in fam
        assert "category" in fam
        # cves may be present-and-empty (advisory-only families)
        assert "cves" in fam


# ---------------------------------------------------------------------------
# _stringify_metadata
# ---------------------------------------------------------------------------


def test_stringify_metadata() -> None:
    md = {
        "fw_version_raw": "7.35.180.11",
        "tags": ["alpha", "beta", 42, None],
        "nested": {"ignored": "not-returned"},
        "num": 100,
        "flag": True,
    }
    out = _stringify_metadata(md)
    # Only top-level strings + strings inside lists must be returned.
    assert "7.35.180.11" in out
    assert "alpha" in out
    assert "beta" in out
    assert "not-returned" not in out  # nested dict ignored
    # Non-strings filtered.
    for v in out:
        assert isinstance(v, str)


# ---------------------------------------------------------------------------
# _match_curated
# ---------------------------------------------------------------------------


class TestMatchCurated:
    def _families(self) -> list[dict]:
        return _load_known_firmware()

    def test_exact_vendor_category_matches_broadpwn(self) -> None:
        blob = _make_blob(
            vendor="broadcom",
            category="wifi",
            version="7.35.180.11",
            chipset_target="bcm4358",
        )
        matches = _match_curated(blob, self._families())
        cve_ids = {m.cve_id for m in matches}
        assert "CVE-2017-9417" in cve_ids
        # All matches must be tier=curated_yaml, confidence=high
        for m in matches:
            assert m.tier == "curated_yaml"
            assert m.confidence == "high"

    def test_chipset_regex_required_when_present(self) -> None:
        # Matching vendor/category/version but chipset missing entirely
        # (BroadPwn demands a bcm4xxx chipset_target).
        blob = _make_blob(
            vendor="broadcom",
            category="wifi",
            version="7.35.180.11",
            chipset_target=None,
        )
        matches = _match_curated(blob, self._families())
        broadpwn_hits = [m for m in matches if m.cve_id == "CVE-2017-9417"]
        assert broadpwn_hits == []

    def test_chipset_regex_miss_excludes(self) -> None:
        blob = _make_blob(
            vendor="broadcom",
            category="wifi",
            version="7.35.180.11",
            chipset_target="bcm1234",  # miss — regex wants bcm43xx
        )
        matches = _match_curated(blob, self._families())
        assert "CVE-2017-9417" not in {m.cve_id for m in matches}

    def test_version_regex_miss_filters_out(self) -> None:
        # BroadPwn version_regex wants 7.30-7.59.x; 8.x falls outside.
        blob = _make_blob(
            vendor="broadcom",
            category="wifi",
            version="8.10.0.0",
            chipset_target="bcm4358",
        )
        matches = _match_curated(blob, self._families())
        assert "CVE-2017-9417" not in {m.cve_id for m in matches}

    def test_metadata_version_fallback_matches(self) -> None:
        # blob.version None, but metadata carries a matching version string.
        blob = _make_blob(
            vendor="broadcom",
            category="wifi",
            version=None,
            chipset_target="bcm4358",
            metadata={"fw_version_raw": "7.35.180.11"},
        )
        matches = _match_curated(blob, self._families())
        assert "CVE-2017-9417" in {m.cve_id for m in matches}

    def test_advisory_when_cves_empty(self) -> None:
        # kamakiri BROM — MediaTek bootloader, cves: []
        blob = _make_blob(
            vendor="mediatek",
            category="bootloader",
            chipset_target="mt6785",
        )
        matches = _match_curated(blob, self._families())
        advisories = [m for m in matches if m.cve_id.startswith("ADVISORY-")]
        assert len(advisories) >= 1
        kamakiri = [m for m in advisories if "KAMAKIRI" in m.cve_id]
        assert len(kamakiri) == 1
        # Advisories should be tier=curated_yaml, confidence=high
        assert kamakiri[0].tier == "curated_yaml"
        assert kamakiri[0].confidence == "high"

    def test_returns_multiple_cves_for_shannon_cluster(self) -> None:
        blob = _make_blob(
            vendor="samsung",
            category="modem",
            version="s5123",
        )
        matches = _match_curated(blob, self._families())
        shannon = {
            m.cve_id
            for m in matches
            if m.cve_id
            in {
                "CVE-2023-24033",
                "CVE-2023-26496",
                "CVE-2023-26072",
                "CVE-2023-26073",
                "CVE-2023-26074",
            }
        }
        assert len(shannon) == 5

    def test_vendor_mismatch_filters_out(self) -> None:
        # Wrong vendor: should never match BroadPwn even with right category/version
        blob = _make_blob(
            vendor="qualcomm",
            category="wifi",
            version="7.35.180.11",
            chipset_target="bcm4358",
        )
        matches = _match_curated(blob, self._families())
        assert "CVE-2017-9417" not in {m.cve_id for m in matches}

    def test_category_mismatch_filters_out(self) -> None:
        blob = _make_blob(
            vendor="broadcom",
            category="modem",  # BroadPwn is wifi
            version="7.35.180.11",
            chipset_target="bcm4358",
        )
        matches = _match_curated(blob, self._families())
        assert "CVE-2017-9417" not in {m.cve_id for m in matches}


# ---------------------------------------------------------------------------
# match_firmware_cves — persistence + idempotency
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_match_firmware_cves_no_blobs_returns_empty() -> None:
    firmware_id = uuid.uuid4()

    # Only the blobs query runs; short-circuit on empty.
    blobs_result = MagicMock()
    blobs_result.scalars.return_value.all.return_value = []
    db = AsyncMock()
    db.execute = AsyncMock(return_value=blobs_result)
    db.add = MagicMock()
    db.flush = AsyncMock()

    out = await match_firmware_cves(firmware_id, db)
    assert out == []
    db.add.assert_not_called()
    db.flush.assert_not_called()


@pytest.mark.asyncio
async def test_match_firmware_cves_persists_sbom_vulnerability() -> None:
    firmware_id = uuid.uuid4()
    blob_id = uuid.uuid4()

    blob = _make_blob(
        vendor="broadcom",
        category="wifi",
        version="7.35.180.11",
        chipset_target="bcm4358",
        blob_id=blob_id,
    )
    db = _mock_db_for_matcher(blobs=[blob], existing=[])

    matches = await match_firmware_cves(firmware_id, db)
    assert len(matches) >= 1
    # All persisted rows were SbomVulnerability instances with blob_id set.
    assert db.add.call_count == len(matches)
    added_rows = [call.args[0] for call in db.add.call_args_list]
    for row in added_rows:
        assert isinstance(row, SbomVulnerability)
        assert row.blob_id == blob_id
        assert row.firmware_id == firmware_id
        assert row.component_id is None
        assert row.match_tier == "curated_yaml"
        assert row.match_confidence == "high"
        assert row.resolution_status == "open"
    db.flush.assert_awaited_once()


@pytest.mark.asyncio
async def test_match_firmware_cves_is_idempotent() -> None:
    firmware_id = uuid.uuid4()
    blob_id = uuid.uuid4()

    blob = _make_blob(
        vendor="broadcom",
        category="wifi",
        version="7.35.180.11",
        chipset_target="bcm4358",
        blob_id=blob_id,
    )

    # First run: no existing rows.
    db1 = _mock_db_for_matcher(blobs=[blob], existing=[])
    run1 = await match_firmware_cves(firmware_id, db1)
    first_inserts = db1.add.call_count
    assert first_inserts >= 1

    # Second run: feed back the (blob_id, cve_id) pairs the first run produced.
    # The matcher still *returns* all matches (function signature contract),
    # but must not persist any new rows.
    existing_pairs = [(m.blob_id, m.cve_id) for m in run1]
    db2 = _mock_db_for_matcher(blobs=[blob], existing=existing_pairs)
    run2 = await match_firmware_cves(firmware_id, db2)
    # Returns the recomputed matches (same count), but no new inserts.
    assert len(run2) == len(run1)
    db2.add.assert_not_called()


@pytest.mark.asyncio
async def test_match_firmware_cves_force_rescan_reinserts() -> None:
    firmware_id = uuid.uuid4()
    blob_id = uuid.uuid4()

    blob = _make_blob(
        vendor="broadcom",
        category="wifi",
        version="7.35.180.11",
        chipset_target="bcm4358",
        blob_id=blob_id,
    )
    # Existing rows present, but force_rescan=True should still insert.
    db = _mock_db_for_matcher(
        blobs=[blob],
        existing=[(blob_id, "CVE-2017-9417")],
    )
    matches = await match_firmware_cves(firmware_id, db, force_rescan=True)
    # force_rescan should bypass the dedup set.
    assert db.add.call_count == len(matches)


# ---------------------------------------------------------------------------
# CveMatch dataclass importable
# ---------------------------------------------------------------------------


def test_cve_match_dataclass_importable() -> None:
    m = CveMatch(
        blob_id=uuid.uuid4(),
        cve_id="CVE-2017-9417",
        severity="critical",
        cvss_score=9.8,
        description="test",
        confidence="high",
        tier="curated_yaml",
    )
    assert m.cve_id == "CVE-2017-9417"
    assert m.tier == "curated_yaml"
