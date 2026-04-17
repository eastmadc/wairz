"""Multi-tier CVE matcher for hardware firmware blobs.

Tier 1 — Chipset CPE lookup (high confidence): if blob.chipset_target
  matches a CPE in the NVD dictionary, query by CPE.
Tier 2 — NVD free-text (medium): keyword search on "{vendor} {category}
  firmware" against NVD descriptions, filter by version substring.
Tier 3 — Curated YAML (high, human-vetted): load known_firmware.yaml
  and match each entry against the blob's vendor/category/version/chipset.
Tier 4 — Kernel CPE (medium): read the ``linux-kernel`` SbomComponent
  rows (produced by sbom_service ``_scan_kernel_from_vermagic`` and
  enriched by grype) and mirror their CVEs onto every kernel_module blob
  so each .ko surfaces the kernel-level findings instead of leaving them
  on the component alone.

Results land in sbom_vulnerabilities with blob_id set and
match_confidence + match_tier populated.  Idempotent — dedups on
(firmware_id, blob_id, cve_id).
"""
from __future__ import annotations

import logging
import re
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import yaml
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.hardware_firmware import HardwareFirmwareBlob
from app.models.sbom import SbomComponent, SbomVulnerability

logger = logging.getLogger(__name__)

_YAML_PATH = Path(__file__).parent / "known_firmware.yaml"


@dataclass
class CveMatch:
    """One CVE match against one blob."""

    blob_id: uuid.UUID
    cve_id: str
    severity: str
    cvss_score: float | None
    description: str
    confidence: str  # high | medium | low
    tier: str  # chipset_cpe | nvd_freetext | curated_yaml | kernel_cpe


def _load_known_firmware() -> list[dict]:
    """Load curated CVE families from YAML.  Cached in module scope."""
    if not _YAML_PATH.is_file():
        logger.warning("known_firmware.yaml missing at %s", _YAML_PATH)
        return []
    try:
        with _YAML_PATH.open("r") as f:
            data = yaml.safe_load(f)
        return data.get("families", []) if data else []
    except yaml.YAMLError as exc:
        logger.error("Failed to parse known_firmware.yaml: %s", exc)
        return []


def _stringify_metadata(md: dict) -> list[str]:
    """Return all string values found in metadata (one level deep)."""
    out: list[str] = []
    for v in md.values():
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, list):
            out.extend(x for x in v if isinstance(x, str))
    return out


def _match_curated(
    blob: HardwareFirmwareBlob, families: list[dict]
) -> list[CveMatch]:
    """Tier 3 — curated YAML match."""
    matches: list[CveMatch] = []
    blob_vendor = (blob.vendor or "").lower()
    blob_category = (blob.category or "").lower()
    blob_version = blob.version or ""
    blob_chipset = blob.chipset_target or ""
    metadata_values = _stringify_metadata(blob.metadata_ or {})

    for fam in families:
        if fam.get("vendor", "").lower() != blob_vendor:
            continue
        if fam.get("category", "").lower() != blob_category:
            continue

        # Optional chipset regex
        chipset_re = fam.get("chipset_regex")
        if chipset_re:
            if not blob_chipset:
                continue
            if not re.search(chipset_re, blob_chipset, re.IGNORECASE):
                continue

        # Optional version regex — match against version OR any metadata value
        version_re = fam.get("version_regex")
        if version_re:
            version_ok = False
            if blob_version and re.search(version_re, blob_version, re.IGNORECASE):
                version_ok = True
            else:
                for v in metadata_values:
                    if re.search(version_re, v, re.IGNORECASE):
                        version_ok = True
                        break
            if not version_ok:
                continue

        cves = fam.get("cves", [])
        severity = fam.get("severity", "medium")
        cvss_score = fam.get("cvss_score")
        desc = f"{fam.get('name', '(unnamed)')}: {fam.get('notes', '').strip()}"

        if not cves:
            # Advisory-only (e.g. kamakiri BROM — no CVE assigned)
            matches.append(
                CveMatch(
                    blob_id=blob.id,
                    cve_id=(
                        "ADVISORY-"
                        + fam.get("name", "unknown").upper().replace(" ", "-")
                    ),
                    severity=severity,
                    cvss_score=cvss_score,
                    description=desc,
                    confidence="high",
                    tier="curated_yaml",
                )
            )
            continue

        for cve_id in cves:
            matches.append(
                CveMatch(
                    blob_id=blob.id,
                    cve_id=cve_id,
                    severity=severity,
                    cvss_score=cvss_score,
                    description=desc,
                    confidence="high",
                    tier="curated_yaml",
                )
            )
    return matches


async def _match_chipset_cpe(
    blob: HardwareFirmwareBlob,
) -> list[CveMatch]:
    """Tier 1 — chipset CPE lookup.  Best-effort (returns [] if CPE service unavailable).

    Phase 4 ships this as a stub: even with CPE service loaded, we don't
    yet query NVD for CPE -> CVE (that's a larger separate loop).  Kept as
    a structured stub so Phase 5/6 can extend without touching the matcher
    pipeline shape.
    """
    if not blob.chipset_target:
        return []
    try:
        from app.services.cpe_dictionary_service import CpeDictionaryService

        svc = CpeDictionaryService()
        if not await svc.ensure_loaded():
            return []
        # We validated the CPE path works; actual CPE -> CVE query is
        # deferred to a later phase so Phase 4 remains scoped.
    except Exception:
        logger.debug(
            "CPE dictionary unavailable for tier 1 match", exc_info=True
        )
        return []
    return []


async def _match_nvd_freetext(
    blob: HardwareFirmwareBlob,
) -> list[CveMatch]:
    """Tier 2 — NVD free-text keyword search.

    Current implementation: placeholder.  Real NVD keyword API is rate-
    limited and asynchronous; Phase 4 ships with Tier 3 active and Tiers
    1/2 as stubs that return [].  Users can run the existing SBOM-grype
    pipeline for userspace CVEs; hardware firmware CVEs come from Tier 3
    curated YAML.
    """
    return []


async def _match_kernel_cpe(
    blobs: Sequence[HardwareFirmwareBlob],
    firmware_id: uuid.UUID,
    db: AsyncSession,
) -> list[CveMatch]:
    """Tier 4 — mirror linux-kernel component CVEs onto each kernel_module blob.

    Reads ``SbomComponent`` rows flagged as the Linux kernel (by name /
    type / ``kernel_*`` detection source) for this firmware, pulls the
    grype-supplied ``SbomVulnerability`` rows attached to those
    components, and projects a ``CveMatch`` onto every ``kernel_module``
    blob.  The persistence layer in :func:`match_firmware_cves` dedups on
    ``(blob_id, cve_id)``, so callers can safely re-run this tier.
    """
    kmod_blobs = [b for b in blobs if (b.category or "").lower() == "kernel_module"]
    if not kmod_blobs:
        return []

    # Locate every linux-kernel SbomComponent for this firmware.  Match on
    # name (case-insensitive) plus a loose "operating-system" type or any
    # detection source beginning with ``kernel_``.
    name_lower = func.lower(SbomComponent.name)
    comp_stmt = select(SbomComponent).where(
        SbomComponent.firmware_id == firmware_id,
        name_lower.in_(("linux-kernel", "linux_kernel", "linux")),
        or_(
            SbomComponent.type == "operating-system",
            SbomComponent.detection_source.like("kernel_%"),
        ),
    )
    components = (await db.execute(comp_stmt)).scalars().all()
    if not components:
        return []

    comp_ids = [c.id for c in components]
    vuln_stmt = select(SbomVulnerability).where(
        SbomVulnerability.component_id.in_(comp_ids),
    )
    vulns = (await db.execute(vuln_stmt)).scalars().all()
    if not vulns:
        return []

    matches: list[CveMatch] = []
    for vuln in vulns:
        # cvss_score arrives as Decimal off the Numeric column; coerce so
        # downstream consumers see a float | None consistently with the
        # other tiers.
        cvss_score = float(vuln.cvss_score) if vuln.cvss_score is not None else None
        severity = vuln.severity or "unknown"
        description = vuln.description or ""
        for blob in kmod_blobs:
            matches.append(
                CveMatch(
                    blob_id=blob.id,
                    cve_id=vuln.cve_id,
                    severity=severity,
                    cvss_score=cvss_score,
                    description=description,
                    confidence="medium",
                    tier="kernel_cpe",
                )
            )
    return matches


async def match_firmware_cves(
    firmware_id: uuid.UUID,
    db: AsyncSession,
    force_rescan: bool = False,
) -> list[CveMatch]:
    """Run the multi-tier matcher for all hardware firmware blobs of one firmware.

    - Skips blobs that already have cves in sbom_vulnerabilities unless
      force_rescan=True.
    - Persists matches to sbom_vulnerabilities with blob_id + match_tier +
      match_confidence.  Dedups on (firmware_id, blob_id, cve_id).
    """
    families = _load_known_firmware()

    # Fetch all blobs for this firmware
    stmt = select(HardwareFirmwareBlob).where(
        HardwareFirmwareBlob.firmware_id == firmware_id,
    )
    blobs = (await db.execute(stmt)).scalars().all()
    if not blobs:
        return []

    # Fetch existing hw-firmware CVEs for dedup key
    existing_stmt = select(
        SbomVulnerability.blob_id,
        SbomVulnerability.cve_id,
    ).where(
        SbomVulnerability.firmware_id == firmware_id,
        SbomVulnerability.blob_id.is_not(None),
    )
    existing = {(r[0], r[1]) for r in (await db.execute(existing_stmt)).all()}

    all_matches: list[CveMatch] = []
    for blob in blobs:
        # Tier 3 (always)
        all_matches.extend(_match_curated(blob, families))
        # Tier 1 / Tier 2 stubs
        all_matches.extend(await _match_chipset_cpe(blob))
        all_matches.extend(await _match_nvd_freetext(blob))

    # Tier 4 — kernel CPE (pulls grype's kernel-component CVEs onto each kmod blob)
    all_matches.extend(await _match_kernel_cpe(blobs, firmware_id, db))

    # Persist matches
    inserted = 0
    for m in all_matches:
        if (m.blob_id, m.cve_id) in existing and not force_rescan:
            continue
        vuln = SbomVulnerability(
            component_id=None,
            firmware_id=firmware_id,
            blob_id=m.blob_id,
            cve_id=m.cve_id,
            severity=m.severity,
            cvss_score=m.cvss_score,
            description=m.description,
            match_confidence=m.confidence,
            match_tier=m.tier,
            resolution_status="open",
        )
        db.add(vuln)
        existing.add((m.blob_id, m.cve_id))
        inserted += 1

    await db.flush()
    logger.info(
        "HW firmware CVE matcher: %d blobs scanned, %d new matches (%d total)",
        len(blobs),
        inserted,
        len(all_matches),
    )
    return all_matches
