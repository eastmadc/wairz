"""READ-side surfacing of ``firmware.vuln_scan_provenance`` (Rule #47 consumers).

The pinned-NVD-cache work (Rule #37) records, for every completed vulnerability
scan, WHICH CVE source answered each component lookup. That stamp exists so a
scan run against a missing or half-populated cache cannot read as a clean one:
an unenriched scan persists ``status='completed'`` with **zero**
``sbom_vulnerabilities`` rows, byte-identical to a genuinely clean firmware.

The original work enumerated the three WRITERS of that stamp and missed the
READERS. This module is the single place every reader goes through, so the
contract — *the warning must precede or accompany the number it invalidates* —
is stated once and cannot drift (Rule #54: derive, don't hand-maintain).

Rule #53 discipline: :func:`substantiates_no_known_vulnerabilities` keys on an
explicit ALLOWLIST of statuses that constitute positive evidence a lookup
actually happened. It never keys on ``warning is None`` — a missing warning is
absence-of-evidence, and clearing a verdict on absence-of-evidence is exactly
the laundering this branch exists to prevent.
"""

from __future__ import annotations

from typing import Any

from app.services.jsonb_normalizers import (
    _normalize_firmware_vuln_scan_provenance,
)

# Every value ``summarise_nvd_provenance`` can emit, plus ``unknown`` for a NULL
# column. Mirrored by ``NvdEnrichmentStatus`` in frontend/src/types/index.ts and
# by the ``ENRICHMENT_CONFIG`` Record map in SbomPage.tsx (Rule #9): adding a
# value here means updating BOTH frontend sites in the same commit.
ENRICHMENT_STATUSES: tuple[str, ...] = (
    "complete",
    "live",
    "partial",
    "none",
    "not_applicable",
    "unknown",
)

# POSITIVE evidence that CVE enrichment actually ran and resolved every lookup.
# Rule #53: an allowlist of proof, never a denylist of known-bad labels — a new
# status value defaults to NOT substantiating, which fails safe.
#
# ``not_applicable`` is deliberately EXCLUDED. It means "no CPE-bearing
# component was looked up", i.e. nothing was checked — which cannot substantiate
# a "no known vulnerabilities" claim any more than an unavailable cache can.
SUBSTANTIATING_STATUSES: frozenset[str] = frozenset({"complete", "live"})

# Canonical wording for a NULL ``vuln_scan_provenance`` column. Absence of
# provenance is NOT evidence of enrichment (see the normaliser's docstring), so
# a NULL reads as ``unknown`` WITH a warning, never silently as a healthy scan.
UNKNOWN_PROVENANCE_WARNING = (
    "CVE ENRICHMENT PROVENANCE NOT RECORDED for this scan — it predates "
    "provenance stamping (or was written by another path). Vulnerability "
    "counts here cannot be attributed to a pinned NVD cache generation; "
    "re-run the scan to obtain a reproducible, provenance-stamped result."
)


class EnrichmentVerdict:
    """What a consumer needs to render a vulnerability count honestly.

    ``status`` is one of :data:`ENRICHMENT_STATUSES`; ``warning`` is a
    human-readable string meant to be rendered VERBATIM, ahead of the count it
    invalidates; ``provenance`` is the normalised JSONB aggregate (or ``None``).
    """

    __slots__ = ("status", "warning", "provenance")

    def __init__(
        self,
        status: str,
        warning: str | None,
        provenance: dict | None,
    ) -> None:
        self.status = status
        self.warning = warning
        self.provenance = provenance

    @property
    def substantiated(self) -> bool:
        """True only on POSITIVE evidence enrichment ran (Rule #53)."""
        return self.status in SUBSTANTIATING_STATUSES

    @property
    def source_label(self) -> str:
        """Short provenance identity for exports and evidence chains."""
        prov = self.provenance or {}
        engine = prov.get("engine") or "unknown"
        sha = prov.get("manifest_sha")
        if engine == "nvd_pinned_cache" and sha:
            return f"pinned NVD cache manifest {str(sha)[:12]}"
        return str(engine)

    def as_response_fields(self) -> dict[str, Any]:
        """The three fields every API/export payload carries."""
        return {
            "nvd_enrichment_status": self.status,
            "nvd_enrichment_warning": self.warning,
            "nvd_provenance": self.provenance,
        }

    def banner(self, count_noun: str = "vulnerability count") -> str | None:
        """One-line marker to print ABOVE a count, or ``None`` when clean."""
        if self.substantiated:
            return None
        return (
            f"!! CVE ENRICHMENT: {self.status.upper()} — the {count_noun} "
            f"below is NOT a clean verdict. {self.warning or ''}".strip()
        )


def read_firmware_enrichment(firmware: Any) -> EnrichmentVerdict:
    """Resolve a ``Firmware`` row's CVE-enrichment verdict.

    Accepts the ORM row (or anything exposing ``vuln_scan_provenance``). Reads
    through the Rule #35c normaliser, so a hand-edited wrong-typed column
    collapses to ``unknown`` rather than crashing a reader or — worse — reading
    as healthy.
    """
    raw = getattr(firmware, "vuln_scan_provenance", None)
    return verdict_from_provenance(raw)


def verdict_from_provenance(raw: Any) -> EnrichmentVerdict:
    """Same as :func:`read_firmware_enrichment` for a bare JSONB value."""
    prov = _normalize_firmware_vuln_scan_provenance(raw)
    if prov is None:
        return EnrichmentVerdict("unknown", UNKNOWN_PROVENANCE_WARNING, None)
    status = prov.get("enrichment_status") or "unknown"
    if status not in ENRICHMENT_STATUSES:
        # An unrecognised value fails SAFE: treat as unknown, keep any warning.
        status = "unknown"
    warning = prov.get("warning")
    if status == "unknown" and not warning:
        warning = UNKNOWN_PROVENANCE_WARNING
    return EnrichmentVerdict(status, warning, prov)


def substantiates_no_known_vulnerabilities(verdict: EnrichmentVerdict) -> bool:
    """May a zero-vulnerability result be asserted as regulatory evidence?

    Used by the CRA compliance evidence chain. Rule #53: allowlist of positive
    evidence only.
    """
    return verdict.substantiated
