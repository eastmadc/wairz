"""Unit tests for the CycloneDX v1.6 HBOM exporter.

Uses the same mock-AsyncSession pattern as ``test_hardware_firmware_cve_matcher``
— no live database is required.  Each test builds shaped mocks for the
``Firmware`` parent row, a handful of ``HardwareFirmwareBlob`` rows, and
any ``SbomVulnerability`` rows, then asserts the resulting CycloneDX
document's structural shape.
"""
from __future__ import annotations

import re
import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.models.firmware import Firmware
from app.models.hardware_firmware import HardwareFirmwareBlob
from app.models.sbom import SbomVulnerability
from app.services.hardware_firmware.hbom_export import build_hbom

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _make_firmware(
    *,
    firmware_id: uuid.UUID | None = None,
    original_filename: str = "DPCS10.zip",
    sha256: str = "a" * 64,
    version_label: str | None = "v1.0",
) -> MagicMock:
    fw = MagicMock(spec=Firmware)
    fw.id = firmware_id or uuid.uuid4()
    fw.original_filename = original_filename
    fw.sha256 = sha256
    fw.version_label = version_label
    return fw


def _make_blob(
    *,
    blob_id: uuid.UUID | None = None,
    firmware_id: uuid.UUID | None = None,
    blob_path: str = "/vendor/firmware/wcn6750.bin",
    partition: str | None = "vendor",
    category: str = "wifi",
    vendor: str | None = "qualcomm",
    format: str = "raw_bin",
    version: str | None = "1.2.3",
    signed: str = "signed",
    signature_algorithm: str | None = None,
    cert_subject: str | None = None,
    chipset_target: str | None = "wcn6750",
    blob_sha256: str = "b" * 64,
    file_size: int = 4096,
    metadata: dict | None = None,
    detection_source: str = "magic_bytes",
    detection_confidence: str = "high",
) -> MagicMock:
    blob = MagicMock(spec=HardwareFirmwareBlob)
    blob.id = blob_id or uuid.uuid4()
    blob.firmware_id = firmware_id or uuid.uuid4()
    blob.blob_path = blob_path
    blob.partition = partition
    blob.category = category
    blob.vendor = vendor
    blob.format = format
    blob.version = version
    blob.signed = signed
    blob.signature_algorithm = signature_algorithm
    blob.cert_subject = cert_subject
    blob.chipset_target = chipset_target
    blob.blob_sha256 = blob_sha256
    blob.file_size = file_size
    blob.metadata_ = metadata or {}
    blob.detection_source = detection_source
    blob.detection_confidence = detection_confidence
    return blob


def _make_vuln(
    *,
    cve_id: str,
    blob_id: uuid.UUID,
    firmware_id: uuid.UUID,
    severity: str = "high",
    cvss_score: float | None = 7.8,
    cvss_vector: str | None = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    description: str | None = "Test CVE description",
    match_tier: str | None = "curated_yaml",
    match_confidence: str | None = "high",
) -> MagicMock:
    v = MagicMock(spec=SbomVulnerability)
    v.id = uuid.uuid4()
    v.blob_id = blob_id
    v.firmware_id = firmware_id
    v.cve_id = cve_id
    v.severity = severity
    v.cvss_score = cvss_score
    v.cvss_vector = cvss_vector
    v.description = description
    v.match_tier = match_tier
    v.match_confidence = match_confidence
    return v


def _mock_db(
    *,
    firmware: MagicMock | None,
    blobs: list[MagicMock],
    vulns: list[MagicMock] | None = None,
) -> AsyncMock:
    """Mock AsyncSession with the three executes build_hbom performs.

    Execution order in build_hbom:
      1. SELECT Firmware WHERE id=?
      2. SELECT HardwareFirmwareBlob WHERE firmware_id=? ORDER BY ...
      3. SELECT SbomVulnerability WHERE firmware_id=? AND blob_id IS NOT NULL
    """
    vulns = vulns or []

    # 1. Firmware
    fw_result = MagicMock()
    fw_result.scalar_one_or_none.return_value = firmware

    # 2. Blobs
    blobs_result = MagicMock()
    blobs_result.scalars.return_value.all.return_value = blobs

    # 3. Vulns
    vulns_result = MagicMock()
    vulns_result.scalars.return_value.all.return_value = vulns

    db = AsyncMock()
    db.execute = AsyncMock(side_effect=[fw_result, blobs_result, vulns_result])
    return db


def _three_blob_fixture() -> (
    tuple[uuid.UUID, MagicMock, list[MagicMock], list[MagicMock]]
):
    """Build the canonical 3-blob + 1 CVE fixture described in the spec.

    * MediaTek / wifi / signed (has CVE).
    * ARM / gpu / unsigned.
    * None / kernel_module (unknown vendor) — asserts manufacturer omitted.
    """
    firmware_id = uuid.uuid4()
    firmware = _make_firmware(firmware_id=firmware_id)

    wifi_blob = _make_blob(
        firmware_id=firmware_id,
        blob_path="/vendor/firmware/mt7961.bin",
        partition="vendor",
        category="wifi",
        vendor="mediatek",
        format="mtk_wifi_hdr",
        version="8.1.0",
        signed="signed",
        chipset_target="mt7961",
        blob_sha256="1" * 64,
        file_size=131072,
        metadata={"fw_version_raw": "8.1.0-mtk"},
    )
    gpu_blob = _make_blob(
        firmware_id=firmware_id,
        blob_path="/vendor/firmware/mali_csffw.bin",
        partition="vendor",
        category="gpu",
        vendor="arm",
        format="raw_bin",
        version=None,
        signed="unsigned",
        chipset_target="mali-g710",
        blob_sha256="2" * 64,
        file_size=32768,
    )
    km_blob = _make_blob(
        firmware_id=firmware_id,
        blob_path="/vendor/lib/modules/touch_ic.ko",
        partition="vendor",
        category="kernel_module",
        vendor=None,  # unknown
        format="ko",
        version=None,
        signed="unknown",
        chipset_target=None,
        blob_sha256="3" * 64,
        file_size=65536,
        metadata={"kernel_semver": "6.6.102"},
    )

    cve = _make_vuln(
        cve_id="CVE-2024-9001",
        blob_id=wifi_blob.id,
        firmware_id=firmware_id,
    )

    return firmware_id, firmware, [wifi_blob, gpu_blob, km_blob], [cve]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_hbom_bomFormat_and_specVersion() -> None:
    firmware_id, fw, blobs, vulns = _three_blob_fixture()
    db = _mock_db(firmware=fw, blobs=blobs, vulns=vulns)

    doc = await build_hbom(firmware_id, db)

    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    assert doc["version"] == 1
    # Metadata tool attribution present.
    assert doc["metadata"]["tools"][0]["vendor"] == "Wairz"
    assert doc["metadata"]["tools"][0]["name"] == "hardware-firmware-detector"


@pytest.mark.asyncio
async def test_hbom_emits_two_components_per_blob() -> None:
    firmware_id, fw, blobs, vulns = _three_blob_fixture()
    db = _mock_db(firmware=fw, blobs=blobs, vulns=vulns)

    doc = await build_hbom(firmware_id, db)

    comps = doc["components"]
    # 3 blobs -> 6 components (hardware + firmware per blob).
    assert len(comps) == 6
    # CycloneDX 1.6 component.type enum has "device" for physical
    # hardware (not "hardware" — that's not in the spec enum).
    hw_count = sum(1 for c in comps if c["type"] == "device")
    fw_count = sum(1 for c in comps if c["type"] == "firmware")
    assert hw_count == 3
    assert fw_count == 3


@pytest.mark.asyncio
async def test_hbom_dependencies_link_chip_to_firmware() -> None:
    firmware_id, fw, blobs, vulns = _three_blob_fixture()
    db = _mock_db(firmware=fw, blobs=blobs, vulns=vulns)

    doc = await build_hbom(firmware_id, db)

    deps = doc["dependencies"]
    assert len(deps) == 3
    for blob, dep in zip(blobs, deps, strict=True):
        assert dep["ref"] == f"chip_{blob.id}"
        assert dep["provides"] == [f"fw_{blob.id}"]


@pytest.mark.asyncio
async def test_hbom_vulnerabilities_attached_to_firmware_refs() -> None:
    firmware_id, fw, blobs, vulns = _three_blob_fixture()
    db = _mock_db(firmware=fw, blobs=blobs, vulns=vulns)

    doc = await build_hbom(firmware_id, db)

    wifi_blob = blobs[0]
    assert "vulnerabilities" in doc
    vs = doc["vulnerabilities"]
    assert len(vs) == 1
    v = vs[0]
    assert v["id"] == "CVE-2024-9001"
    # affects points at the firmware component bom-ref, not the chip.
    assert v["affects"] == [{"ref": f"fw_{wifi_blob.id}"}]
    # Rating carries severity + score.
    assert v["ratings"][0]["severity"] == "high"
    assert v["ratings"][0]["score"] == pytest.approx(7.8)
    # Match provenance lives in properties.  Tiers are now plural
    # (multi-source rollup) and an affected_blob_count counter is
    # surfaced for downstream filtering.
    prop_names = {p["name"]: p["value"] for p in v.get("properties", [])}
    assert prop_names.get("wairz:match_tiers") == "curated_yaml"
    assert prop_names.get("wairz:match_confidence") == "high"
    assert prop_names.get("wairz:affected_blob_count") == "1"


@pytest.mark.asyncio
async def test_hbom_dedups_same_cve_across_blobs() -> None:
    """Same CVE on N blobs collapses to ONE vulnerability entry with
    N affects refs — the canonical CycloneDX 1.6 shape and the fix for
    the 222 MB DPCS10 HBOM bloat (177K rows → 1.2K distinct CVEs).
    """
    firmware_id = uuid.uuid4()
    fw = _make_firmware(firmware_id=firmware_id)
    blob_a = _make_blob(firmware_id=firmware_id, blob_path="/lib/modules/a.ko")
    blob_b = _make_blob(firmware_id=firmware_id, blob_path="/lib/modules/b.ko")
    blob_c = _make_blob(firmware_id=firmware_id, blob_path="/lib/modules/c.ko")
    # Same CVE on three blobs (kernel_cpe tier projects identically
    # onto every kmod blob — typical pattern).
    vulns = [
        _make_vuln(
            cve_id="CVE-2024-KERNEL",
            blob_id=b.id,
            firmware_id=firmware_id,
            match_tier="kernel_cpe",
        )
        for b in (blob_a, blob_b, blob_c)
    ]
    db = _mock_db(firmware=fw, blobs=[blob_a, blob_b, blob_c], vulns=vulns)

    doc = await build_hbom(firmware_id, db)

    vs = doc["vulnerabilities"]
    assert len(vs) == 1, "three rows for one CVE must collapse to one entry"
    entry = vs[0]
    assert entry["id"] == "CVE-2024-KERNEL"

    # affects[] carries one ref per blob — three refs, all distinct.
    refs = {a["ref"] for a in entry["affects"]}
    assert refs == {f"fw_{blob_a.id}", f"fw_{blob_b.id}", f"fw_{blob_c.id}"}

    # Identical ratings across the three rows collapse to ONE rating
    # (severity / score / vector dedupe).
    assert len(entry["ratings"]) == 1

    # affected_blob_count surfaces the rollup size.
    props = {p["name"]: p["value"] for p in entry.get("properties", [])}
    assert props["wairz:affected_blob_count"] == "3"


@pytest.mark.asyncio
async def test_hbom_picks_highest_priority_tier_for_description() -> None:
    """Same CVE matched by parser_version_pin (specific) AND kernel_cpe
    (broad projection) must keep the parser-pin description, not the
    kernel description — most specific source wins for canonical text.
    """
    firmware_id = uuid.uuid4()
    fw = _make_firmware(firmware_id=firmware_id)
    gz_blob = _make_blob(firmware_id=firmware_id, blob_path="/firmware/gz.img")
    km_blob = _make_blob(firmware_id=firmware_id, blob_path="/lib/modules/x.ko")
    parser_match = _make_vuln(
        cve_id="CVE-2025-20707",
        blob_id=gz_blob.id,
        firmware_id=firmware_id,
        description="GZ_hypervisor 3.2.1.004 predates Feb 2026 PSB fix",
        match_tier="parser_version_pin",
    )
    kernel_match = _make_vuln(
        cve_id="CVE-2025-20707",
        blob_id=km_blob.id,
        firmware_id=firmware_id,
        description="Generic kernel CPE description",
        match_tier="kernel_cpe",
    )
    db = _mock_db(
        firmware=fw,
        blobs=[gz_blob, km_blob],
        vulns=[parser_match, kernel_match],
    )

    doc = await build_hbom(firmware_id, db)

    vs = doc["vulnerabilities"]
    assert len(vs) == 1
    entry = vs[0]
    # Description from the parser-pin row wins (higher tier priority).
    assert "GZ_hypervisor" in entry["description"]

    # Both tiers surfaced in properties for filtering.
    props = {p["name"]: p["value"] for p in entry["properties"]}
    tiers = props["wairz:match_tiers"].split(",")
    assert "parser_version_pin" in tiers
    assert "kernel_cpe" in tiers
    # Parser-pin (priority 4) listed before kernel_cpe (priority 1).
    assert tiers.index("parser_version_pin") < tiers.index("kernel_cpe")


@pytest.mark.asyncio
async def test_hbom_hashes_present_on_firmware_components() -> None:
    firmware_id, fw, blobs, vulns = _three_blob_fixture()
    db = _mock_db(firmware=fw, blobs=blobs, vulns=vulns)

    doc = await build_hbom(firmware_id, db)

    firmware_comps = [c for c in doc["components"] if c["type"] == "firmware"]
    assert len(firmware_comps) == 3
    for comp in firmware_comps:
        assert "hashes" in comp
        assert comp["hashes"][0]["alg"] == "SHA-256"
        assert len(comp["hashes"][0]["content"]) == 64


@pytest.mark.asyncio
async def test_hbom_omits_manufacturer_on_unknown_vendor() -> None:
    firmware_id, fw, blobs, vulns = _three_blob_fixture()
    db = _mock_db(firmware=fw, blobs=blobs, vulns=vulns)

    doc = await build_hbom(firmware_id, db)

    # blobs[2] is the kernel_module with vendor=None.
    km_blob = blobs[2]
    chip_ref = f"chip_{km_blob.id}"
    fw_ref = f"fw_{km_blob.id}"

    hw_comp = next(c for c in doc["components"] if c.get("bom-ref") == chip_ref)
    fw_comp = next(c for c in doc["components"] if c.get("bom-ref") == fw_ref)

    assert "manufacturer" not in hw_comp
    # Firmware comp should not carry supplier either.
    assert "supplier" not in fw_comp
    # But the chip name should not claim a stub vendor string.
    assert "Unknown" not in hw_comp["name"]
    assert "unknown" not in hw_comp["name"].split()
    # Chip name falls back to the category.
    assert hw_comp["name"] == "kernel_module"


@pytest.mark.asyncio
async def test_hbom_properties_include_category_format_partition() -> None:
    firmware_id, fw, blobs, vulns = _three_blob_fixture()
    db = _mock_db(firmware=fw, blobs=blobs, vulns=vulns)

    doc = await build_hbom(firmware_id, db)

    # Wifi blob, mediatek/wifi/mtk_wifi_hdr on partition=vendor.
    wifi_blob = blobs[0]
    fw_ref = f"fw_{wifi_blob.id}"
    fw_comp = next(c for c in doc["components"] if c.get("bom-ref") == fw_ref)
    props = {p["name"]: p["value"] for p in fw_comp["properties"]}

    assert props["hw-firmware:category"] == "wifi"
    assert props["hw-firmware:format"] == "mtk_wifi_hdr"
    assert props["hw-firmware:partition"] == "vendor"
    assert props["hw-firmware:signed"] == "signed"
    assert props["hw-firmware:chipset-target"] == "mt7961"
    # Parser metadata flattened.
    assert props.get("hw-firmware:meta:fw_version_raw") == "8.1.0-mtk"


@pytest.mark.asyncio
async def test_hbom_serialNumber_is_urn_uuid() -> None:
    firmware_id, fw, blobs, vulns = _three_blob_fixture()
    db = _mock_db(firmware=fw, blobs=blobs, vulns=vulns)

    doc = await build_hbom(firmware_id, db)

    urn_regex = (
        r"^urn:uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    )
    assert re.match(urn_regex, doc["serialNumber"])


@pytest.mark.asyncio
async def test_hbom_handles_empty_firmware_gracefully() -> None:
    """0 blobs, 0 vulns → still emits a valid v1.6 document."""
    firmware_id = uuid.uuid4()
    fw = _make_firmware(firmware_id=firmware_id)
    db = _mock_db(firmware=fw, blobs=[], vulns=[])

    doc = await build_hbom(firmware_id, db)

    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    assert doc["components"] == []
    assert doc["dependencies"] == []
    assert "vulnerabilities" not in doc  # empty -> omit


@pytest.mark.asyncio
async def test_hbom_metadata_component_from_firmware_row() -> None:
    """metadata.component mirrors the parent Firmware row when present."""
    firmware_id, fw, blobs, vulns = _three_blob_fixture()
    db = _mock_db(firmware=fw, blobs=blobs, vulns=vulns)

    doc = await build_hbom(firmware_id, db)

    comp = doc["metadata"]["component"]
    assert comp["type"] == "firmware"
    assert comp["bom-ref"] == "firmware-image"
    assert comp["name"] == "DPCS10.zip"
    assert comp["version"] == "v1.0"
    assert comp["hashes"][0]["alg"] == "SHA-256"


@pytest.mark.asyncio
async def test_hbom_coerces_unknown_severity() -> None:
    """Severity outside the CycloneDX enum is mapped to 'unknown'."""
    firmware_id = uuid.uuid4()
    fw = _make_firmware(firmware_id=firmware_id)
    blob = _make_blob(firmware_id=firmware_id)
    vuln = _make_vuln(
        cve_id="CVE-2024-X",
        blob_id=blob.id,
        firmware_id=firmware_id,
        severity="weird-severity",  # not in the CycloneDX enum
        cvss_score=None,
    )
    db = _mock_db(firmware=fw, blobs=[blob], vulns=[vuln])

    doc = await build_hbom(firmware_id, db)

    assert doc["vulnerabilities"][0]["ratings"][0]["severity"] == "unknown"
