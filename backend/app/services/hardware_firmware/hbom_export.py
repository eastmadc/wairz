"""CycloneDX v1.6 HBOM (Hardware Bill of Materials) exporter.

Builds a CycloneDX v1.6 HBOM from ``HardwareFirmwareBlob`` rows.  For each
detected blob we emit two linked components:

* a ``hardware`` component describing the chip
  (bom-ref = ``chip_<blob.id>``), and
* a ``firmware`` component describing the binary
  (bom-ref = ``fw_<blob.id>``), with ``hashes`` from ``blob_sha256`` and
  properties carrying category / format / partition / chipset / signing
  metadata.

Chip -> firmware is expressed via the top-level ``dependencies`` array
(``provides``: the chip "provides" the firmware) per the HBOM convention.

CVE data (``sbom_vulnerabilities`` rows with ``blob_id`` set) is emitted
in the top-level ``vulnerabilities`` array keyed off the firmware
component bom-refs.

The implementation is pure Python dict building — no shell, no
subprocess, no file I/O.
"""
from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.firmware import Firmware
from app.models.hardware_firmware import HardwareFirmwareBlob
from app.models.sbom import SbomVulnerability

# CycloneDX v1.6 severity enum — any value outside this set is coerced to
# "unknown" so downstream consumers validating against the schema don't
# reject the document.
_VALID_SEVERITIES = {
    "critical",
    "high",
    "medium",
    "low",
    "info",
    "none",
    "unknown",
}


def _iso_utc_now() -> str:
    """Return an ISO-8601 UTC timestamp with trailing ``Z`` suffix."""
    return (
        datetime.now(tz=UTC)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _build_hardware_component(blob: HardwareFirmwareBlob) -> dict:
    """Build a CycloneDX v1.6 ``hardware`` component for a blob.

    ``manufacturer`` is included only when ``blob.vendor`` is populated
    (None / unknown vendor -> omitted rather than stubbed out).
    """
    ref = f"chip_{blob.id}"
    vendor = (blob.vendor or "").strip()
    category = (blob.category or "hardware").strip()

    # Name: "<vendor> <category>" if we have a vendor, otherwise just the
    # category.  Always human-readable.
    name = f"{vendor} {category}".strip() if vendor else category

    comp: dict = {
        "type": "hardware",
        "bom-ref": ref,
        "name": name,
    }
    if vendor:
        comp["manufacturer"] = {"name": vendor}
    if blob.chipset_target:
        comp["modelNumber"] = blob.chipset_target
    return comp


def _build_firmware_component(blob: HardwareFirmwareBlob) -> dict:
    """Build a CycloneDX v1.6 ``firmware`` component for a blob.

    ``supplier`` is only emitted when we have a vendor (omitted on
    unknown), matching the ``manufacturer`` rule on the chip component.
    """
    ref = f"fw_{blob.id}"
    basename = os.path.basename(blob.blob_path) or blob.blob_path
    vendor = (blob.vendor or "").strip()

    comp: dict = {
        "type": "firmware",
        "bom-ref": ref,
        "name": basename,
    }
    if blob.version:
        comp["version"] = blob.version
    if vendor:
        comp["supplier"] = {"name": vendor}
    if blob.blob_sha256:
        comp["hashes"] = [
            {"alg": "SHA-256", "content": blob.blob_sha256},
        ]

    # Properties — carry all the firmware-specific metadata the top-level
    # CycloneDX component schema doesn't have a home for.  The
    # ``hw-firmware:`` prefix namespaces these away from other consumers.
    props: list[dict] = []

    def _add_prop(name: str, value: str | None) -> None:
        if value is None or value == "":
            return
        props.append({"name": name, "value": str(value)})

    _add_prop("hw-firmware:category", blob.category)
    _add_prop("hw-firmware:format", blob.format)
    _add_prop("hw-firmware:partition", blob.partition)
    _add_prop("hw-firmware:blob-path", blob.blob_path)
    _add_prop("hw-firmware:signed", blob.signed)
    _add_prop("hw-firmware:signature-algorithm", blob.signature_algorithm)
    _add_prop("hw-firmware:cert-subject", blob.cert_subject)
    _add_prop("hw-firmware:chipset-target", blob.chipset_target)
    _add_prop("hw-firmware:detection-source", blob.detection_source)
    _add_prop("hw-firmware:detection-confidence", blob.detection_confidence)
    _add_prop("hw-firmware:file-size", str(blob.file_size))

    # Flatten top-level string/int metadata into properties too so
    # parser-specific fields (kernel_semver, product, fw_version_raw, ...)
    # survive into the HBOM.
    md = blob.metadata_ or {}
    for key, value in md.items():
        if isinstance(value, (str, int, float, bool)):
            _add_prop(f"hw-firmware:meta:{key}", str(value))

    if props:
        comp["properties"] = props

    return comp


def _build_vulnerability(
    vuln: SbomVulnerability,
    firmware_ref: str,
) -> dict:
    """Build a CycloneDX v1.6 vulnerability entry.

    ``affects.ref`` points at the firmware component bom-ref, mirroring
    how grype-produced vulnerabilities attach to software components.
    """
    severity = (vuln.severity or "unknown").lower()
    if severity not in _VALID_SEVERITIES:
        severity = "unknown"

    entry: dict = {
        "id": vuln.cve_id,
        "affects": [{"ref": firmware_ref}],
    }

    ratings: list[dict] = []
    rating: dict = {"severity": severity}
    if vuln.cvss_score is not None:
        try:
            rating["score"] = float(vuln.cvss_score)
        except (TypeError, ValueError):  # pragma: no cover - defensive
            pass
    if vuln.cvss_vector:
        rating["vector"] = vuln.cvss_vector
        # Derive CycloneDX "method" from the vector prefix.
        v = vuln.cvss_vector.upper()
        if v.startswith("CVSS:3.1"):
            rating["method"] = "CVSSv31"
        elif v.startswith("CVSS:3"):
            rating["method"] = "CVSSv3"
        elif v.startswith("CVSS:4"):
            rating["method"] = "CVSSv4"
    ratings.append(rating)
    entry["ratings"] = ratings

    if vuln.description:
        entry["description"] = vuln.description

    # Wairz-specific match provenance stays in properties so downstream
    # tooling can filter on tier/confidence without parsing description.
    props: list[dict] = []
    if vuln.match_tier:
        props.append({"name": "wairz:match_tier", "value": vuln.match_tier})
    if vuln.match_confidence:
        props.append(
            {"name": "wairz:match_confidence", "value": vuln.match_confidence},
        )
    if props:
        entry["properties"] = props

    return entry


async def build_hbom(
    firmware_id: uuid.UUID,
    db: AsyncSession,
) -> dict:
    """Build a CycloneDX v1.6 HBOM for the given firmware image.

    Returns a JSON-serialisable ``dict``.  Skips firmware-image metadata
    gracefully when the parent ``firmware`` row can't be resolved — the
    rest of the document still validates against CycloneDX v1.6.
    """
    # Parent firmware row (for the metadata.component header).  Optional
    # because the HBOM is still valid without it — we just lose the
    # "firmware-image" root component.
    fw_row = (
        await db.execute(
            select(Firmware).where(Firmware.id == firmware_id),
        )
    ).scalar_one_or_none()

    # Load blobs for this firmware, deterministically ordered so the
    # output is stable for snapshot tests.
    blob_stmt = (
        select(HardwareFirmwareBlob)
        .where(HardwareFirmwareBlob.firmware_id == firmware_id)
        .order_by(
            HardwareFirmwareBlob.category,
            HardwareFirmwareBlob.blob_path,
        )
    )
    blobs = (await db.execute(blob_stmt)).scalars().all()

    # Pre-fetch all hw-firmware vulns in one query and bucket by blob.
    vuln_stmt = (
        select(SbomVulnerability)
        .where(
            SbomVulnerability.firmware_id == firmware_id,
            SbomVulnerability.blob_id.is_not(None),
        )
        .order_by(SbomVulnerability.cve_id)
    )
    vulns = (await db.execute(vuln_stmt)).scalars().all()

    vulns_by_blob: dict[uuid.UUID, list[SbomVulnerability]] = {}
    for v in vulns:
        if v.blob_id is None:
            continue
        vulns_by_blob.setdefault(v.blob_id, []).append(v)

    # ── Build components + dependencies ────────────────────────────────
    components: list[dict] = []
    dependencies: list[dict] = []
    vuln_entries: list[dict] = []

    for blob in blobs:
        chip_ref = f"chip_{blob.id}"
        fw_ref = f"fw_{blob.id}"

        components.append(_build_hardware_component(blob))
        components.append(_build_firmware_component(blob))
        dependencies.append({"ref": chip_ref, "provides": [fw_ref]})

        for v in vulns_by_blob.get(blob.id, []):
            vuln_entries.append(_build_vulnerability(v, fw_ref))

    # ── Assemble the document ──────────────────────────────────────────
    metadata: dict = {
        "timestamp": _iso_utc_now(),
        "tools": [
            {
                "vendor": "Wairz",
                "name": "hardware-firmware-detector",
                "version": "0.1",
            },
        ],
    }
    if fw_row is not None:
        metadata["component"] = {
            "type": "firmware",
            "bom-ref": "firmware-image",
            "name": fw_row.original_filename or str(fw_row.id),
        }
        if fw_row.version_label:
            metadata["component"]["version"] = fw_row.version_label
        if fw_row.sha256:
            metadata["component"]["hashes"] = [
                {"alg": "SHA-256", "content": fw_row.sha256},
            ]

    hbom: dict = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": metadata,
        "components": components,
        "dependencies": dependencies,
    }
    if vuln_entries:
        hbom["vulnerabilities"] = vuln_entries

    return hbom
