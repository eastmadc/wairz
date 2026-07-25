"""Rule #47 read-side contract: an unenriched scan is never a clean verdict.

Every consumer that renders a vulnerability count goes through
``nvd_provenance_surface``. These tests pin the ONE property the branch exists
to guarantee: a ``0`` produced without CVE enrichment must be visibly
distinguishable from a ``0`` produced by a healthy pinned-cache scan.

Rule #46: every absence-asserting assertion below has a paired canary that
synthesizes the violation and confirms the gate fires.
"""

import pytest

from app.services.nvd_provenance_surface import (
    ENRICHMENT_STATUSES,
    SUBSTANTIATING_STATUSES,
    UNKNOWN_PROVENANCE_WARNING,
    EnrichmentVerdict,
    read_firmware_enrichment,
    substantiates_no_known_vulnerabilities,
    verdict_from_provenance,
)


class _Row:
    """Stand-in for the Firmware ORM row (only the column is read)."""

    def __init__(self, prov):
        self.vuln_scan_provenance = prov


# ── NULL / malformed provenance reads as UNKNOWN, never as healthy ──────────


def test_null_provenance_is_unknown_with_a_warning():
    v = read_firmware_enrichment(_Row(None))
    assert v.status == "unknown"
    assert v.warning == UNKNOWN_PROVENANCE_WARNING
    assert v.substantiated is False


@pytest.mark.parametrize("bad", [[], "complete", 7, 0, True])
def test_wrong_typed_provenance_collapses_to_unknown_not_complete(bad):
    """A hand-edited / legacy column must never launder into a clean verdict."""
    v = read_firmware_enrichment(_Row(bad))
    assert v.status == "unknown"
    assert v.substantiated is False


def test_unrecognised_status_value_fails_safe():
    """Rule #53: an unknown label is not positive evidence — fail safe."""
    v = verdict_from_provenance({"enrichment_status": "totally_fine", "warning": None})
    assert v.status == "unknown"
    assert v.substantiated is False


# ── the substantiation allowlist (Rule #53) ────────────────────────────────


@pytest.mark.parametrize("status", sorted(SUBSTANTIATING_STATUSES))
def test_substantiating_statuses_are_clean(status):
    v = verdict_from_provenance({"enrichment_status": status, "warning": None})
    assert v.substantiated is True
    assert v.banner() is None


@pytest.mark.parametrize(
    "status", sorted(set(ENRICHMENT_STATUSES) - SUBSTANTIATING_STATUSES)
)
def test_non_substantiating_statuses_always_emit_a_banner(status):
    v = verdict_from_provenance(
        {"enrichment_status": status, "warning": "cache was unavailable"}
    )
    assert v.substantiated is False
    banner = v.banner("total vulnerabilities found")
    assert banner is not None
    assert status.upper() in banner
    assert "NOT a clean verdict" in banner


def test_not_applicable_does_not_substantiate_a_clean_claim():
    """'Nothing was looked up' is not 'nothing was found'."""
    v = verdict_from_provenance(
        {"enrichment_status": "not_applicable", "warning": None}
    )
    assert v.substantiated is False
    assert substantiates_no_known_vulnerabilities(v) is False


def test_substantiation_never_keys_on_absence_of_a_warning():
    """Rule #53 laundering guard: warning=None must NOT clear a bad status."""
    v = verdict_from_provenance({"enrichment_status": "none", "warning": None})
    assert v.warning is None
    assert v.substantiated is False, (
        "a missing warning is absence-of-evidence, not evidence of enrichment"
    )
    assert v.banner() is not None


# ── Rule #46 META-CANARIES ─────────────────────────────────────────────────


def test_canary_a_substantiating_allowlist_would_catch_a_bad_addition():
    """Synthesize the violation: if 'none' were ever allowlisted, prove we'd see it."""
    poisoned = SUBSTANTIATING_STATUSES | {"none"}
    assert "none" in poisoned  # the synthetic violation exists
    # The production allowlist must NOT contain it.
    assert "none" not in SUBSTANTIATING_STATUSES
    assert "partial" not in SUBSTANTIATING_STATUSES
    assert "unknown" not in SUBSTANTIATING_STATUSES
    assert "not_applicable" not in SUBSTANTIATING_STATUSES


def test_canary_b_banner_gate_actually_fires_on_a_synthetic_bad_status():
    """A hand-built verdict with a bad status must produce a banner."""
    synthetic = EnrichmentVerdict("partial", "synthetic degrade", {"engine": "x"})
    assert synthetic.banner() is not None
    # ...and the same gate stays silent for a genuinely clean one, so the
    # assertion above is not vacuously true for every input.
    assert EnrichmentVerdict("complete", None, {"engine": "x"}).banner() is None


def test_canary_c_status_list_is_the_frontend_mirror_size_lock():
    """Rule #9 size-lock: adding a status means updating the frontend Record map."""
    assert len(ENRICHMENT_STATUSES) == 6, (
        "ENRICHMENT_STATUSES changed — update NvdEnrichmentStatus and the "
        "ENRICHMENT_CONFIG Record map in frontend/src (Rule #9) in the SAME commit"
    )


def test_source_label_reports_the_pinned_manifest_identity():
    v = verdict_from_provenance(
        {
            "enrichment_status": "complete",
            "engine": "nvd_pinned_cache",
            "manifest_sha": "a1f38452d7df90df6f6b27d5e4762e0f6b4c4a90",
        }
    )
    assert v.source_label == "pinned NVD cache manifest a1f38452d7df"


def test_as_response_fields_carries_all_three():
    v = verdict_from_provenance({"enrichment_status": "partial", "warning": "w"})
    fields = v.as_response_fields()
    assert set(fields) == {
        "nvd_enrichment_status",
        "nvd_enrichment_warning",
        "nvd_provenance",
    }
    assert fields["nvd_enrichment_status"] == "partial"
