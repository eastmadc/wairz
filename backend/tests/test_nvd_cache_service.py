"""Pinned NVD cache service — offline, reproducible CVE lookup (Rule #37).

Covers the path/CPE parsing, the populate-time cpe->cve index build, the
cache-first lookup (hit / miss / unavailable modes), the memoised index
invalidation on manifest-sha change, and the probe. Uses a synthetic fixture
cache in tmp_path (no network, no DB). Async entry points are driven via
asyncio.run so the tests do not depend on the pytest-asyncio mode.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from app.services import nvd_cache_service as ncs
from app.services.nvd_cache_service import (
    _cpe_vendor_product,
    _cve_path,
    build_cpe_index,
    lookup_cves_for_cpe,
    probe,
)


def _cpe(vendor, product, version="*"):
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def _feed_layout_path(cve_id: str, cache: Path) -> Path:
    """INDEPENDENT oracle for the EMBA nvd-json-data-feeds on-disk layout.

    Every fixture writes through THIS, never through the production
    ``_cve_path`` — otherwise the fixture and the code under test share the
    same (possibly wrong) formula and every cache-*hit* test is TAUTOLOGICAL:
    a broken ``_cve_path`` writes the file to the wrong place and then looks
    for it in that same wrong place, so the test passes. That is exactly what
    happened with the leading-zero bug (`int(num) // 100`, ~8% of the cache
    silently unreachable): under a re-introduction canary the whole cache-hit
    suite stayed GREEN and only the hand-written layout table went red.

    Re-derived from the feed itself, not from the production source:

        CVE-2021-44228 → CVE-2021/CVE-2021-442xx/CVE-2021-44228.json
        CVE-1999-0001  → CVE-1999/CVE-1999-00xx/CVE-1999-0001.json

    The bucket is the id's numeric component with its LAST TWO CHARACTERS
    replaced by ``xx`` — a character-level substitution, deliberately using
    NO integer arithmetic, so no implementation detail (and no leading-zero
    stripping) can be shared with ``_cve_path``.
    """
    prefix, year, num = cve_id.split("-")
    assert prefix == "CVE" and year.isdigit() and num.isdigit(), cve_id
    # Real NVD ids are >= 4 digits; the oracle deliberately refuses shorter
    # input rather than guessing a layout the feed never exercises.
    assert len(num) >= 4, f"{cve_id}: NVD ids carry >= 4 digits"
    chars = list(num)
    chars[-1] = "x"
    chars[-2] = "x"
    bucket = f"CVE-{year}-{''.join(chars)}"
    return cache / f"CVE-{year}" / bucket / f"{cve_id}.json"


def _write_cve(cache: Path, cve_id: str, *, vendor="acme", product="widget", version_end=None):
    """Write a bare NVD API-2.0 CVE object at the feed layout path.

    Path comes from the INDEPENDENT ``_feed_layout_path`` oracle above — never
    from ``_cve_path`` — so a wrong production formula fails to FIND what the
    fixture wrote instead of silently agreeing with it.
    """
    path = _feed_layout_path(cve_id, cache)
    path.parent.mkdir(parents=True, exist_ok=True)
    cpe_match = {"criteria": _cpe(vendor, product), "vulnerable": True}
    if version_end is not None:
        cpe_match["versionEndExcluding"] = version_end
    doc = {
        "id": cve_id,
        "descriptions": [{"lang": "en", "value": f"{cve_id} test"}],
        "configurations": [{"nodes": [{"cpeMatch": [cpe_match]}]}],
        "metrics": {},
    }
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def _write_manifest(cache: Path, sha="abc123", count=2):
    cache.mkdir(parents=True, exist_ok=True)
    (cache / ncs._MANIFEST_NAME).write_text(
        json.dumps({"sha256": sha, "populated_at": "2026-07-24T00:00:00Z", "cve_count": count}),
        encoding="utf-8",
    )


def setup_function(_):
    ncs._INDEX_CACHE.clear()  # reset the module memos between tests
    ncs._INTEGRITY_CACHE.clear()


# ── path + cpe parsing ───────────────────────────────────────────────

def test_cve_path_feed_layout(tmp_path):
    p = _cve_path("CVE-2021-44228", tmp_path)
    assert p == tmp_path / "CVE-2021" / "CVE-2021-442xx" / "CVE-2021-44228.json"


def test_cve_path_rejects_malformed():
    assert _cve_path("not-a-cve", Path("/x")) is None
    assert _cve_path("CVE-2021-abc", Path("/x")) is None


def test_cpe_vendor_product():
    assert _cpe_vendor_product(_cpe("Apache", "Log4j")) == "apache:log4j"
    assert _cpe_vendor_product("cpe:2.3:o:linux:linux_kernel:5.4") == "linux:linux_kernel"
    assert _cpe_vendor_product("garbage") is None


# ── index build + lookup ─────────────────────────────────────────────

def test_build_index_and_cache_hit(tmp_path):
    _write_cve(tmp_path, "CVE-2021-0001", vendor="acme", product="widget")
    _write_cve(tmp_path, "CVE-2021-0002", vendor="acme", product="widget")
    _write_cve(tmp_path, "CVE-2021-0003", vendor="other", product="thing")
    stats = build_cpe_index(tmp_path)
    assert stats["cves_indexed"] == 3
    _write_manifest(tmp_path, sha="s1", count=3)

    cves, prov = asyncio.run(lookup_cves_for_cpe(_cpe("acme", "widget"), tmp_path))
    assert prov.mode == "cache_hit"
    assert prov.manifest_sha == "s1"
    assert {c.id for c in cves} == {"CVE-2021-0001", "CVE-2021-0002"}


def test_cache_miss_when_no_matching_product(tmp_path):
    _write_cve(tmp_path, "CVE-2021-0001", vendor="acme", product="widget")
    build_cpe_index(tmp_path)
    _write_manifest(tmp_path)
    cves, prov = asyncio.run(lookup_cves_for_cpe(_cpe("nobody", "nothing"), tmp_path))
    assert cves == [] and prov.mode == "cache_miss"


def test_cache_unavailable_when_no_manifest(tmp_path):
    # No manifest ⇒ cache_unavailable ⇒ cves is None (caller decides fallback).
    cves, prov = asyncio.run(lookup_cves_for_cpe(_cpe("acme", "widget"), tmp_path))
    assert cves is None and prov.mode == "cache_unavailable"


def test_unparseable_cpe_is_cache_miss_not_unavailable(tmp_path):
    # Healthy (populated) cache + a garbage CPE ⇒ a plain miss, not unavailable
    # and not degraded (the cache is fine; the input is not).
    _write_cve(tmp_path, "CVE-2021-0001")
    build_cpe_index(tmp_path)
    _write_manifest(tmp_path, count=1)
    cves, prov = asyncio.run(lookup_cves_for_cpe("garbage-cpe", tmp_path))
    assert cves == [] and prov.mode == "cache_miss"
    assert prov.degraded is False


def test_index_memo_invalidates_on_sha_change(tmp_path):
    _write_cve(tmp_path, "CVE-2021-0001", vendor="acme", product="widget")
    build_cpe_index(tmp_path)
    _write_manifest(tmp_path, sha="s1")
    asyncio.run(lookup_cves_for_cpe(_cpe("acme", "widget"), tmp_path))
    # Add a CVE + rebuild index + bump the manifest sha → memo must refresh.
    _write_cve(tmp_path, "CVE-2021-0002", vendor="acme", product="widget")
    build_cpe_index(tmp_path)
    _write_manifest(tmp_path, sha="s2")
    cves, prov = asyncio.run(lookup_cves_for_cpe(_cpe("acme", "widget"), tmp_path))
    assert prov.manifest_sha == "s2"
    assert {c.id for c in cves} == {"CVE-2021-0001", "CVE-2021-0002"}


# ── degraded (half-populated) cache detection ────────────────────────
#
# The defect these guard: a volume whose MANIFEST + cpe_index were written but
# whose CVE files are absent (interrupted refresh, wiped volume, the pre-fix
# zero-padding path bug) answered every lookup with the *valid reproducible*
# `cache_miss`, so a scan persisted "0 vulnerabilities / completed" that was
# indistinguishable from a genuinely clean firmware.


def _wipe_cve_files(cache: Path) -> int:
    """Delete every CVE json (keep MANIFEST + cpe_index) — the partial-cache shape."""
    n = 0
    for p in cache.rglob("CVE-*.json"):
        if p.name in (ncs._INDEX_NAME, ncs._MANIFEST_NAME):
            continue
        p.unlink()
        n += 1
    return n


def test_partial_cache_is_degraded_not_clean_miss(tmp_path):
    """Index + manifest present, CVE files gone ⇒ cache_degraded, never cache_miss."""
    for i in (1, 2, 3):
        _write_cve(tmp_path, f"CVE-2021-000{i}", vendor="acme", product="widget")
    build_cpe_index(tmp_path)
    _write_manifest(tmp_path, sha="s1", count=3)
    assert _wipe_cve_files(tmp_path) == 3

    cves, prov = asyncio.run(lookup_cves_for_cpe(_cpe("acme", "widget"), tmp_path))
    assert cves == []
    assert prov.mode == "cache_degraded"
    assert prov.degraded is True
    assert prov.manifest_sha == "s1"  # provenance identity still reported
    assert prov.integrity_reasons  # names WHY it is untrustworthy
    # A degraded cache must NOT masquerade as unavailable either: returning None
    # would hand the lookup to the live-NVD fallback path (Rule #37 opt-in only).
    assert cves is not None


def test_partial_cache_degrades_even_for_unrelated_product(tmp_path):
    """The degrade is cache-level: a CPE with no index entry still reports degraded."""
    _write_cve(tmp_path, "CVE-2021-0001", vendor="acme", product="widget")
    build_cpe_index(tmp_path)
    _write_manifest(tmp_path, count=1)
    _wipe_cve_files(tmp_path)
    cves, prov = asyncio.run(lookup_cves_for_cpe(_cpe("nobody", "nothing"), tmp_path))
    assert cves == [] and prov.mode == "cache_degraded" and prov.degraded is True


def test_empty_index_with_declared_cves_is_degraded(tmp_path):
    """Manifest claims N CVEs but the index resolved nothing ⇒ degraded."""
    build_cpe_index(tmp_path)  # nothing to index
    _write_manifest(tmp_path, count=369356)
    cves, prov = asyncio.run(lookup_cves_for_cpe(_cpe("acme", "widget"), tmp_path))
    assert cves == [] and prov.mode == "cache_degraded" and prov.degraded is True
    assert any("index empty" in r for r in prov.integrity_reasons)


def test_skipped_candidate_files_mark_the_lookup_degraded(tmp_path):
    """One missing candidate among many ⇒ degraded + skipped count (silent-loss guard).

    This is the per-lookup signal, independent of the sampled integrity check:
    the sample hits CVE-2021-0001 (present), only 0002 is removed.
    """
    for i in (1, 2, 3):
        _write_cve(tmp_path, f"CVE-2021-000{i}", vendor="acme", product="widget")
    build_cpe_index(tmp_path)
    _write_manifest(tmp_path, count=3)
    (_feed_layout_path("CVE-2021-0002", tmp_path)).unlink()

    cves, prov = asyncio.run(lookup_cves_for_cpe(_cpe("acme", "widget"), tmp_path))
    assert {c.id for c in cves} == {"CVE-2021-0001", "CVE-2021-0003"}
    assert prov.mode == "cache_degraded" and prov.degraded is True
    assert (prov.candidates, prov.resolved, prov.skipped) == (3, 2, 1)


def test_healthy_cache_is_not_flagged_degraded(tmp_path):
    """Rule #46 companion canary: the gate must not flag a healthy cache.

    Without this the degrade signal could be trivially satisfied by always
    reporting degraded, which is as useless as never reporting it.
    """
    for i in range(1, 25):
        _write_cve(tmp_path, f"CVE-2021-{i:04d}", vendor="acme", product=f"p{i % 5}")
    build_cpe_index(tmp_path)
    _write_manifest(tmp_path, count=24)
    hit, prov_hit = asyncio.run(lookup_cves_for_cpe(_cpe("acme", "p1"), tmp_path))
    miss, prov_miss = asyncio.run(lookup_cves_for_cpe(_cpe("acme", "absent"), tmp_path))
    assert hit and prov_hit.mode == "cache_hit" and prov_hit.degraded is False
    assert miss == [] and prov_miss.mode == "cache_miss" and prov_miss.degraded is False


def test_integrity_verdict_memoised_per_manifest_sha(tmp_path):
    """Integrity costs 16 stat()s ONCE per pinned generation, not per lookup."""
    _write_cve(tmp_path, "CVE-2021-0001", vendor="acme", product="widget")
    build_cpe_index(tmp_path)
    _write_manifest(tmp_path, sha="s1", count=1)
    asyncio.run(lookup_cves_for_cpe(_cpe("acme", "widget"), tmp_path))
    assert ncs._INTEGRITY_CACHE[str(tmp_path)]["manifest_sha"] == "s1"
    # New generation (sha bump) must re-judge rather than reuse the old verdict.
    _wipe_cve_files(tmp_path)
    _write_manifest(tmp_path, sha="s2", count=1)
    _, prov = asyncio.run(lookup_cves_for_cpe(_cpe("acme", "widget"), tmp_path))
    assert prov.mode == "cache_degraded" and prov.manifest_sha == "s2"


# ── probe ────────────────────────────────────────────────────────────

def test_probe_ready_and_not_ready(tmp_path):
    assert probe(tmp_path)["ready"] is False  # empty
    _write_cve(tmp_path, "CVE-2021-0001")
    build_cpe_index(tmp_path)
    _write_manifest(tmp_path, sha="s1", count=1)
    p = probe(tmp_path)
    assert p["ready"] is True
    assert p["manifest_sha"] == "s1" and p["cve_count"] == 1 and p["index_present"] is True
    assert p["degraded"] is False and p["degraded_reasons"] == []


def test_probe_not_ready_on_degraded_cache(tmp_path):
    """Half-populated volume ⇒ ready=False WITH reasons (boot-time visibility)."""
    _write_cve(tmp_path, "CVE-2021-0001")
    build_cpe_index(tmp_path)
    _write_manifest(tmp_path, sha="s1", count=1)
    _wipe_cve_files(tmp_path)
    ncs._INTEGRITY_CACHE.clear()
    p = probe(tmp_path)
    assert p["manifest_present"] is True and p["index_present"] is True
    assert p["ready"] is False and p["degraded"] is True
    assert any("absent on disk" in r for r in p["degraded_reasons"])


# ── independent path oracle (the self-referential-fixture fix) ───────

@pytest.mark.parametrize("cve_id,expected_rel", [
    # Zero-padded ids are the case the ORIGINAL formula got wrong: int("0001")//100
    # == 0 -> "CVE-1999-0xx", a directory that does not exist. These expectations are
    # written by HAND from the real EMBA feed layout, NOT derived from _cve_path, so
    # a wrong formula cannot satisfy them.
    ("CVE-1999-0001", "CVE-1999/CVE-1999-00xx/CVE-1999-0001.json"),
    ("CVE-1999-0250", "CVE-1999/CVE-1999-02xx/CVE-1999-0250.json"),
    ("CVE-2019-0773", "CVE-2019/CVE-2019-07xx/CVE-2019-0773.json"),
    ("CVE-2015-0045", "CVE-2015/CVE-2015-00xx/CVE-2015-0045.json"),
    ("CVE-2021-44228", "CVE-2021/CVE-2021-442xx/CVE-2021-44228.json"),
    ("CVE-2024-26581", "CVE-2024/CVE-2024-265xx/CVE-2024-26581.json"),
])
def test_cve_path_matches_hand_written_feed_layout(cve_id, expected_rel):
    assert _cve_path(cve_id, Path("/c")) == Path("/c") / expected_rel


def test_cve_path_never_strips_leading_zeros():
    """Regression guard for the ~8% silent data loss: a bucket must keep the number's
    zero padding, so the directory component is always len(num)-2 digits + 'xx'."""
    for num in ("0001", "0099", "0100", "44228"):
        p = _cve_path(f"CVE-2020-{num}", Path("/c"))
        bucket = p.parent.name
        assert bucket == f"CVE-2020-{num[:-2]}xx"
        assert len(bucket.split("-")[-1]) == len(num) - 2 + 2


@pytest.mark.parametrize("num", [
    # Every id-width + zero-padding shape the real feed carries. Widths 4-7
    # (CVE-2024-1000000 exists), leading zeros in every position, and the
    # boundary values (…00, …99) where an arithmetic bucket rounds wrongly.
    "0001", "0010", "0099", "0100", "0250", "0773", "1000", "9999",
    "10000", "10099", "26581", "44228", "100000", "100099", "1000000",
])
def test_cve_path_agrees_with_the_independent_feed_oracle(num, tmp_path):
    """``_cve_path`` must equal the fixture's independently-derived layout.

    This is the bridge that makes every cache-*hit* test in this file a real
    oracle rather than a tautology: the fixtures write via
    ``_feed_layout_path`` (character substitution, no arithmetic) and the
    service reads via ``_cve_path`` (slicing). If the two ever disagree the
    lookups miss and the hit tests go red — this test names the disagreement
    directly instead of leaving it to be inferred from a mode assertion.
    """
    cve_id = f"CVE-2020-{num}"
    assert _cve_path(cve_id, tmp_path) == _feed_layout_path(cve_id, tmp_path)


# ── provenance SURFACING (the truthfulness guarantee end-to-end) ──────
#
# The defect these guard: the provenance aggregate was computed and then read by
# NOBODY — the router logged a count, assessment_service took findings_created,
# the MCP tool printed severities. So a completed scan against an unavailable
# cache persisted "0 vulnerabilities" that no consumer could distinguish from a
# genuinely clean firmware.

import uuid  # noqa: E402
from unittest.mock import AsyncMock, MagicMock  # noqa: E402

from app.services.vulnerability_service import (  # noqa: E402
    VulnerabilityService,
    summarise_nvd_provenance,
)


def _scan_component(cache: Path, cpe_str: str):
    """Drive the REAL service lookup path against a fixture cache; return the
    scan-level provenance verdict the summary would carry."""
    from app.models.sbom import SbomComponent

    svc = VulnerabilityService.__new__(VulnerabilityService)  # skip get_settings
    svc.db = MagicMock()
    svc._api_key = None
    svc._nvd_cache_path = str(cache)
    svc._allow_live_fallback = False
    svc._nvd_provenance = None
    svc._rate_delay = 0
    comp = SbomComponent(
        id=uuid.uuid4(), name="widget", version="1.0", cpe=cpe_str,
        type="library", detection_source="test", detection_confidence="high",
    )
    asyncio.run(svc._query_nvd_for_component(comp, uuid.uuid4()))
    return summarise_nvd_provenance(svc._nvd_provenance)


def test_summary_verdict_unavailable_cache_says_enrichment_did_not_run(tmp_path):
    prov = _scan_component(tmp_path, _cpe("acme", "widget"))  # no manifest at all
    assert prov["enrichment_status"] == "none"
    assert prov["worst_mode"] == "cache_unavailable"
    w = prov["warning"]
    # Rule #46 style assertion on the MESSAGE, not just the flag: an operator
    # reading this must not be able to mistake it for a clean verdict.
    assert w and "DID NOT RUN" in w and "not looked up" in w


def test_summary_verdict_degraded_cache_says_under_report(tmp_path):
    for i in (1, 2, 3):
        _write_cve(tmp_path, f"CVE-2021-000{i}", vendor="acme", product="widget")
    build_cpe_index(tmp_path)
    _write_manifest(tmp_path, sha="s1", count=3)
    _wipe_cve_files(tmp_path)
    prov = _scan_component(tmp_path, _cpe("acme", "widget"))
    assert prov["enrichment_status"] == "partial"
    assert prov["degraded"] is True and prov["worst_mode"] == "cache_degraded"
    assert "UNDER-REPORT" in prov["warning"]
    assert prov["manifest_sha"] == "s1"  # generation identity still attributable


def test_summary_verdict_healthy_cache_is_complete_with_no_warning(tmp_path):
    _write_cve(tmp_path, "CVE-2021-0001", vendor="acme", product="widget")
    build_cpe_index(tmp_path)
    _write_manifest(tmp_path, sha="s1", count=1)
    prov = _scan_component(tmp_path, _cpe("acme", "widget"))
    assert prov["enrichment_status"] == "complete"
    assert prov["warning"] is None and prov["degraded"] is False
    assert prov["manifest_sha"] == "s1"


def test_summary_verdict_healthy_miss_is_complete_not_a_warning(tmp_path):
    """A miss on a HEALTHY cache is the reproducible answer — no false alarm."""
    _write_cve(tmp_path, "CVE-2021-0001", vendor="acme", product="widget")
    build_cpe_index(tmp_path)
    _write_manifest(tmp_path, sha="s1", count=1)
    prov = _scan_component(tmp_path, _cpe("nobody", "nothing"))
    assert prov["enrichment_status"] == "complete" and prov["warning"] is None


def test_summarise_no_lookups_is_not_applicable():
    prov = summarise_nvd_provenance(None)
    assert prov["enrichment_status"] == "not_applicable" and prov["warning"] is None


# ── router persistence + surfacing ───────────────────────────────────


def test_provenance_stamp_skipped_for_cached_short_circuit():
    """A cached (no-op) run must NOT overwrite a real manifest sha."""
    from app.routers.sbom import _vuln_scan_provenance_from_summary

    assert _vuln_scan_provenance_from_summary({"status": "cached"}, grype=False) is None
    assert _vuln_scan_provenance_from_summary({"status": "cached"}, grype=True) is None


def test_provenance_stamp_records_grype_engine_rather_than_null():
    from app.routers.sbom import _vuln_scan_provenance_from_summary

    stamp = _vuln_scan_provenance_from_summary(
        {"status": "success", "total_components_scanned": 4}, grype=True
    )
    assert stamp["engine"] == "grype" and stamp["schema_version"] == 1
    assert stamp["enrichment_status"] == "unpinned"
    assert "not the pinned nvd cache" in stamp["warning"].lower()


def _fake_db(total_vulns: int):
    db = AsyncMock()
    db.scalar = AsyncMock(side_effect=[1, total_vulns, 0])  # comps, vulns, findings
    db.execute = AsyncMock(return_value=MagicMock(all=MagicMock(return_value=[])))
    return db


def test_scan_status_summary_surfaces_persisted_degraded_provenance():
    """The polling endpoint's summary must carry the warning, not a bare 0."""
    from app.routers.sbom import _build_vuln_scan_summary

    fw = MagicMock()
    fw.id = uuid.uuid4()
    fw.vuln_scan_provenance = {
        "schema_version": 1,
        "engine": "nvd_pinned_cache",
        "manifest_sha": "a1f38452d7df",
        "enrichment_status": "none",
        "warning": "CVE ENRICHMENT DID NOT RUN — the pinned NVD cache was unavailable",
    }
    out = asyncio.run(_build_vuln_scan_summary(_fake_db(0), fw))
    assert out.total_vulnerabilities_found == 0
    assert out.nvd_enrichment_status == "none"
    assert "DID NOT RUN" in out.nvd_enrichment_warning
    assert out.nvd_provenance["manifest_sha"] == "a1f38452d7df"


def test_scan_status_summary_null_provenance_is_unknown_with_warning():
    """A pre-provenance scan reports 'unknown' + a warning — never 'complete'."""
    from app.routers.sbom import _build_vuln_scan_summary

    fw = MagicMock()
    fw.id = uuid.uuid4()
    fw.vuln_scan_provenance = None
    out = asyncio.run(_build_vuln_scan_summary(_fake_db(5104), fw))
    assert out.nvd_enrichment_status == "unknown"
    assert out.nvd_enrichment_warning and "NOT RECORDED" in out.nvd_enrichment_warning
    assert out.nvd_provenance is None


def test_scan_status_summary_healthy_provenance_has_no_warning():
    from app.routers.sbom import _build_vuln_scan_summary

    fw = MagicMock()
    fw.id = uuid.uuid4()
    fw.vuln_scan_provenance = {
        "schema_version": 1, "engine": "nvd_pinned_cache",
        "manifest_sha": "a1f38452d7df", "enrichment_status": "complete",
        "warning": None,
    }
    out = asyncio.run(_build_vuln_scan_summary(_fake_db(18), fw))
    assert out.nvd_enrichment_status == "complete"
    assert out.nvd_enrichment_warning is None


# ── a RAISING lookup must not read as a clean scan (review 2026-07-25) ────────
#
# The defect these guard: the per-file guard in _lookup_sync covered only
# (OSError, json.JSONDecodeError) around the READ, while nvdlib's
# CVE(...)/getvars() construction sat outside the try entirely. Two reachable
# escapes — a torn write truncated mid-UTF-8 (UnicodeDecodeError, a ValueError)
# and an unexpected record shape (AttributeError) — aborted the WHOLE lookup for
# that CPE. scan_components swallows per-component exceptions, so the component
# disappeared from the scan AND from the provenance histogram: with every lookup
# raising, lookups==0 → enrichment_status "not_applicable" + warning None, i.e.
# a false clean verdict. Both layers are now closed; these are the canaries.


def test_torn_write_record_is_skipped_not_raised(tmp_path):
    """Truncated mid-UTF-8 (interrupted tar -x) ⇒ degraded+skipped, never a raise."""
    p = _write_cve(tmp_path, "CVE-2021-0001", vendor="acme", product="widget")
    _write_cve(tmp_path, "CVE-2021-0002", vendor="acme", product="widget")
    build_cpe_index(tmp_path)
    _write_manifest(tmp_path, sha="s1", count=2)
    doc = json.loads(p.read_text(encoding="utf-8"))
    doc["descriptions"] = [{"lang": "en", "value": "héllo"}]
    raw = json.dumps(doc, ensure_ascii=False).encode("utf-8")
    p.write_bytes(raw[: raw.find("é".encode()) + 1])  # cut mid multi-byte char

    cves, prov = asyncio.run(lookup_cves_for_cpe(_cpe("acme", "widget"), tmp_path))
    assert {c.id for c in cves} == {"CVE-2021-0002"}
    assert prov.mode == "cache_degraded" and prov.degraded is True
    assert (prov.candidates, prov.resolved, prov.skipped) == (2, 1, 1)


def test_unexpected_record_shape_is_skipped_not_raised(tmp_path):
    """nvdlib CVE(...)/getvars() failure ⇒ degraded+skipped, never a raise."""
    p = _write_cve(tmp_path, "CVE-2021-0001", vendor="acme", product="widget")
    _write_cve(tmp_path, "CVE-2021-0002", vendor="acme", product="widget")
    build_cpe_index(tmp_path)
    _write_manifest(tmp_path, sha="s1", count=2)
    doc = json.loads(p.read_text(encoding="utf-8"))
    doc["metrics"] = {"cvssMetricV31": "not-a-list"}  # AttributeError in getvars()
    p.write_text(json.dumps(doc), encoding="utf-8")

    cves, prov = asyncio.run(lookup_cves_for_cpe(_cpe("acme", "widget"), tmp_path))
    assert {c.id for c in cves} == {"CVE-2021-0002"}
    assert prov.mode == "cache_degraded" and prov.skipped == 1


def test_every_lookup_raising_is_partial_not_not_applicable(monkeypatch):
    """Backstop layer: even if a lookup raises, the scan must NOT verdict clean.

    ``not_applicable`` (warning None) means "no CPE-bearing component existed".
    A component that WAS looked up and whose lookup blew up must never collapse
    into that verdict — that is the false-clean-verdict failure mode.
    """
    from app.models.sbom import SbomComponent
    from app.services import vulnerability_service as vs

    async def _boom(*_a, **_k):
        raise RuntimeError("volume unreadable")

    monkeypatch.setattr(vs, "lookup_cves_for_cpe", _boom)

    comp = SbomComponent(
        id=uuid.uuid4(), name="widget", version="1.0", cpe=_cpe("acme", "widget"),
        type="library", detection_source="test", detection_confidence="high",
    )
    svc = VulnerabilityService.__new__(VulnerabilityService)
    svc._api_key = None
    svc._nvd_cache_path = "/nonexistent"
    svc._allow_live_fallback = False
    svc._nvd_provenance = None
    svc._rate_delay = 0
    svc._create_findings_from_vulns = AsyncMock(return_value=0)

    db = AsyncMock()
    db.scalar = AsyncMock(side_effect=[0, 1])       # existing vulns, comp count
    comps = MagicMock()
    comps.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=[comp])))
    sev = MagicMock(all=MagicMock(return_value=[]))
    db.execute = AsyncMock(side_effect=[comps, sev])
    svc.db = db

    summary = asyncio.run(svc.scan_components(uuid.uuid4(), uuid.uuid4()))
    assert summary["total_vulnerabilities_found"] == 0
    assert summary["nvd_enrichment_status"] == "partial"
    assert summary["nvd_enrichment_status"] != "not_applicable"
    w = summary["nvd_enrichment_warning"]
    assert w and "UNDER-REPORT" in w and "RuntimeError" in str(
        summary["nvd_provenance"]["degraded_reasons"]
    )


# ── Rule #35b LIVE CANARIES for firmware.vuln_scan_provenance ─────────────────
#
# Everything above this line asserts against MagicMock rows: they prove
# "the writer assigned something", never "the column round-trips through the
# real ORM in the shape the normaliser and the reader expect". That gap is the
# documented cause of the months-long confidence=None bug in this repo
# (CLAUDE.md Rule #35b) — a mock replaced the SESSION, so no test ever observed
# the constructor arguments.
#
# These drive the REAL writers (the 202+polling background runner AND the MCP
# tool handler — a third writer that had NO test at all) against real Project /
# Firmware / SbomComponent rows created through the production ORM, then
# expunge the identity map and re-SELECT so the assertions read bytes that
# actually went through JSONB bind/result serialization.

from sqlalchemy import select as _select  # noqa: E402

from tests._live_db import make_live_db  # noqa: E402


class _SessionHandle:
    """``async_session_factory()`` stand-in that hands back the live session.

    The background runner owns its own session via ``async_session_factory()``
    (Rule #39 outer-wrapper shape), which under pytest would try to reach
    ``db:5432``. Handing it the live SQLite session lets the REAL runner code
    execute unmodified. ``__aexit__`` deliberately does NOT close — the test
    still has to SELECT the row the runner persisted.
    """

    def __init__(self, db):
        self._db = db

    async def __aenter__(self):
        return self._db

    async def __aexit__(self, *_exc):
        return False


def _patch_settings(monkeypatch, cache_dir):
    """Point BOTH get_settings bindings at a fixture cache, NVD backend.

    ``vulnerability_service`` binds ``get_settings`` at module scope; the
    background runner lazy-imports it from ``app.config`` inside the function
    body (Rule #30 — the patch target differs per binding site), so both are
    patched. ``grype_available`` is likewise lazy-imported by the runner, so
    it is patched on its SOURCE module.
    """
    from types import SimpleNamespace

    from app import config as app_config
    from app.services import grype_service
    from app.services import vulnerability_service as vs

    fake = SimpleNamespace(
        nvd_api_key=None,
        nvd_cache_path=str(cache_dir),
        nvd_allow_live_fallback=False,
        vulnerability_backend="nvd",
    )
    monkeypatch.setattr(app_config, "get_settings", lambda: fake)
    monkeypatch.setattr(vs, "get_settings", lambda: fake)
    monkeypatch.setattr(grype_service, "grype_available", lambda: False)
    return fake


async def _seed_scan_target(db, *, cpe: str):
    """Create Project + Firmware + one CPE-bearing SbomComponent for real."""
    from app.models.firmware import Firmware
    from app.models.project import Project
    from app.models.sbom import SbomComponent

    project = Project(name="live-canary", description="Rule #35b")
    db.add(project)
    await db.flush()
    fw = Firmware(
        project_id=project.id,
        original_filename="canary.bin",
        storage_path="/tmp/canary.bin",
        sha256="c" * 64,
        file_size=4096,
        vuln_scan_status="queued",
    )
    db.add(fw)
    await db.flush()
    db.add(SbomComponent(
        firmware_id=fw.id,
        name="widget",
        version="1.0",
        type="library",
        cpe=cpe,
        detection_source="live-canary",
        detection_confidence="high",
    ))
    await db.commit()
    return project.id, fw.id


async def _reselect_firmware(db, firmware_id):
    """Re-read the row from the DATABASE, not the identity map.

    ``expire_on_commit=False`` (wairz's session config, Rule #32) means a plain
    re-SELECT would hand back the same in-memory instance with the values the
    writer assigned — proving nothing about persistence. Expunging first forces
    a real load, so the assertions below observe the value AFTER a JSONB
    serialize/deserialize round-trip.
    """
    from app.models.firmware import Firmware

    db.expunge_all()
    return (await db.execute(
        _select(Firmware).where(Firmware.id == firmware_id)
    )).scalar_one()


def _assert_canonical_stamp(prov: dict):
    """Every sub-key the Rule #35c canonical shape declares must be present.

    A stamp missing ``modes`` / ``lookups`` / ``degraded_reasons`` still reads
    as a dict to the normaliser and still renders a status to the REST summary
    — it just silently drops the evidence an operator needs to judge the
    verdict. Assert the SHAPE, not merely truthiness.
    """
    from app.services.jsonb_normalizers import (
        FIRMWARE_VULN_SCAN_PROVENANCE_SCHEMA_VERSION,
        _normalize_firmware_vuln_scan_provenance,
    )

    assert _normalize_firmware_vuln_scan_provenance(prov) == prov
    assert prov["schema_version"] == FIRMWARE_VULN_SCAN_PROVENANCE_SCHEMA_VERSION
    assert prov["engine"] == "nvd_pinned_cache"
    for key in (
        "enrichment_status", "warning", "modes", "lookups", "degraded",
        "worst_mode", "manifest_sha",
    ):
        assert key in prov, f"canonical stamp lost '{key}' in persistence"
    assert isinstance(prov["modes"], dict) and isinstance(prov["lookups"], int)


async def test_live_canary_background_runner_persists_degraded_provenance(
    tmp_path, monkeypatch
):
    """The REAL 202+polling writer, a REAL firmware row, a re-SELECT.

    Degraded (half-populated) cache ⇒ the persisted row must carry
    enrichment_status "partial" + the UNDER-REPORT warning ALONGSIDE
    vuln_scan_status "completed". "completed with 0 vulns and no marker" is
    precisely the false-clean verdict this branch exists to prevent, and until
    now nothing proved the marker survived the write.
    """
    from app.routers import sbom as sbom_router

    for i in (1, 2, 3):
        _write_cve(tmp_path, f"CVE-2021-000{i}", vendor="acme", product="widget")
    build_cpe_index(tmp_path)
    _write_manifest(tmp_path, sha="live-degraded-sha", count=3)
    _wipe_cve_files(tmp_path)
    ncs._INDEX_CACHE.clear()
    ncs._INTEGRITY_CACHE.clear()

    _patch_settings(monkeypatch, tmp_path)
    async with make_live_db() as db:
        project_id, firmware_id = await _seed_scan_target(
            db, cpe=_cpe("acme", "widget")
        )
        monkeypatch.setattr(
            sbom_router, "async_session_factory", lambda: _SessionHandle(db)
        )
        await sbom_router._run_vuln_scan_background(firmware_id, project_id, False)

        fw = await _reselect_firmware(db, firmware_id)
        assert fw.vuln_scan_status == "completed"
        assert fw.vuln_scan_error is None
        assert fw.vuln_scan_started_at is not None
        assert fw.vuln_scan_finished_at is not None

        prov = fw.vuln_scan_provenance
        assert isinstance(prov, dict), "JSONB round-trip did not yield a dict"
        _assert_canonical_stamp(prov)
        assert prov["enrichment_status"] == "partial"
        assert prov["degraded"] is True
        assert prov["worst_mode"] == "cache_degraded"
        assert prov["manifest_sha"] == "live-degraded-sha"
        assert "UNDER-REPORT" in prov["warning"]
        assert prov["lookups"] == 1
        assert prov["modes"].get("cache_degraded") == 1
        assert prov["degraded_reasons"]

        # The reader the frontend/polling endpoint actually calls, against the
        # PERSISTED row — closes the write→read loop rather than asserting the
        # writer and reader agree on a mock.
        summary = await sbom_router._build_vuln_scan_summary(db, fw)
        assert summary.total_vulnerabilities_found == 0
        assert summary.nvd_enrichment_status == "partial"
        assert "UNDER-REPORT" in summary.nvd_enrichment_warning
        assert summary.nvd_provenance["manifest_sha"] == "live-degraded-sha"


async def test_live_canary_background_runner_persists_complete_provenance(
    tmp_path, monkeypatch
):
    """Healthy cache ⇒ persisted "complete" + warning None + real CVE rows.

    The Rule #46 companion to the degraded canary: without it, a writer that
    stamped "partial" unconditionally would satisfy the suite.
    """
    from app.models.sbom import SbomVulnerability
    from app.routers import sbom as sbom_router

    _write_cve(tmp_path, "CVE-2021-0001", vendor="acme", product="widget")
    _write_cve(tmp_path, "CVE-2021-0002", vendor="acme", product="widget")
    build_cpe_index(tmp_path)
    _write_manifest(tmp_path, sha="live-healthy-sha", count=2)

    _patch_settings(monkeypatch, tmp_path)
    async with make_live_db() as db:
        project_id, firmware_id = await _seed_scan_target(
            db, cpe=_cpe("acme", "widget")
        )
        monkeypatch.setattr(
            sbom_router, "async_session_factory", lambda: _SessionHandle(db)
        )
        await sbom_router._run_vuln_scan_background(firmware_id, project_id, False)

        fw = await _reselect_firmware(db, firmware_id)
        assert fw.vuln_scan_status == "completed"
        prov = fw.vuln_scan_provenance
        _assert_canonical_stamp(prov)
        assert prov["enrichment_status"] == "complete"
        assert prov["warning"] is None
        assert prov["degraded"] is False
        assert prov["manifest_sha"] == "live-healthy-sha"
        assert prov["populated_at"] == "2026-07-24T00:00:00Z"
        assert prov["cve_count"] == 2
        assert prov["modes"] == {"cache_hit": 1}

        # The count the summary reports must equal the rows actually persisted
        # — the value-flow assertion a mock cannot make.
        persisted = (await db.execute(
            _select(SbomVulnerability).where(
                SbomVulnerability.firmware_id == firmware_id
            )
        )).scalars().all()
        assert {v.cve_id for v in persisted} == {"CVE-2021-0001", "CVE-2021-0002"}
        summary = await sbom_router._build_vuln_scan_summary(db, fw)
        assert summary.total_vulnerabilities_found == len(persisted) == 2
        assert summary.nvd_enrichment_status == "complete"
        assert summary.nvd_enrichment_warning is None


async def test_live_canary_background_runner_persists_unavailable_provenance(
    tmp_path, monkeypatch
):
    """No cache at all ⇒ persisted "none" + DID-NOT-RUN warning, not NULL.

    A NULL column reads as "unknown" — truthful but weaker. The runner must
    record the affirmative "enrichment did not run" so a 0-vulnerability
    result is never attributable to a clean firmware.
    """
    from app.routers import sbom as sbom_router

    _patch_settings(monkeypatch, tmp_path / "does-not-exist")
    async with make_live_db() as db:
        project_id, firmware_id = await _seed_scan_target(
            db, cpe=_cpe("acme", "widget")
        )
        monkeypatch.setattr(
            sbom_router, "async_session_factory", lambda: _SessionHandle(db)
        )
        await sbom_router._run_vuln_scan_background(firmware_id, project_id, False)

        fw = await _reselect_firmware(db, firmware_id)
        assert fw.vuln_scan_status == "completed"
        prov = fw.vuln_scan_provenance
        assert prov is not None, "unavailable cache persisted NULL provenance"
        _assert_canonical_stamp(prov)
        assert prov["enrichment_status"] == "none"
        assert prov["worst_mode"] == "cache_unavailable"
        assert "DID NOT RUN" in prov["warning"]
        assert prov["manifest_sha"] is None


async def test_live_canary_mcp_tool_handler_persists_provenance(
    tmp_path, monkeypatch
):
    """The THIRD writer — the MCP ``run_vulnerability_scan`` handler.

    Untested entirely before this: it stamps provenance on its own (Rule #47
    consumer enumeration) with ``flush()`` rather than ``commit()`` (Rule #3,
    the MCP dispatch owns the transaction), so a regression here would leave
    the REST status endpoint reporting an older run's provenance next to rows
    this scan just wrote. Asserts the persisted row AND the rendered text.
    """
    from dataclasses import dataclass

    from app.ai.tools.sbom import _handle_run_vulnerability_scan

    @dataclass
    class _Ctx:
        db: object
        firmware_id: uuid.UUID
        project_id: uuid.UUID

    for i in (1, 2, 3):
        _write_cve(tmp_path, f"CVE-2021-000{i}", vendor="acme", product="widget")
    build_cpe_index(tmp_path)
    _write_manifest(tmp_path, sha="live-mcp-sha", count=3)
    _wipe_cve_files(tmp_path)
    ncs._INDEX_CACHE.clear()
    ncs._INTEGRITY_CACHE.clear()

    _patch_settings(monkeypatch, tmp_path)
    async with make_live_db() as db:
        project_id, firmware_id = await _seed_scan_target(
            db, cpe=_cpe("acme", "widget")
        )
        out = await _handle_run_vulnerability_scan(
            {}, _Ctx(db=db, firmware_id=firmware_id, project_id=project_id)
        )
        # Rule #3: the handler only flush()es — the dispatch commits. Commit
        # here so the re-SELECT reads what the real dispatch would have stored.
        await db.commit()

        fw = await _reselect_firmware(db, firmware_id)
        prov = fw.vuln_scan_provenance
        assert prov is not None, "MCP handler did not persist provenance"
        _assert_canonical_stamp(prov)
        assert prov["enrichment_status"] == "partial"
        assert prov["manifest_sha"] == "live-mcp-sha"
        assert prov["degraded"] is True

        # The assistant-facing text must lead with the warning, BEFORE the
        # count it invalidates — a bare "0" is the false clean verdict.
        assert "UNDER-REPORT" in out
        assert out.index("UNDER-REPORT") < out.index("Total vulnerabilities found")
        assert "live-mcp-sha" in out


async def test_live_canary_mcp_tool_handler_healthy_scan_has_no_warning(
    tmp_path, monkeypatch
):
    """Rule #46 companion: the MCP handler must not warn on a healthy cache."""
    from dataclasses import dataclass

    from app.ai.tools.sbom import _handle_run_vulnerability_scan

    @dataclass
    class _Ctx:
        db: object
        firmware_id: uuid.UUID
        project_id: uuid.UUID

    _write_cve(tmp_path, "CVE-2021-0001", vendor="acme", product="widget")
    build_cpe_index(tmp_path)
    _write_manifest(tmp_path, sha="live-mcp-ok-sha", count=1)

    _patch_settings(monkeypatch, tmp_path)
    async with make_live_db() as db:
        project_id, firmware_id = await _seed_scan_target(
            db, cpe=_cpe("acme", "widget")
        )
        out = await _handle_run_vulnerability_scan(
            {}, _Ctx(db=db, firmware_id=firmware_id, project_id=project_id)
        )
        await db.commit()

        fw = await _reselect_firmware(db, firmware_id)
        prov = fw.vuln_scan_provenance
        _assert_canonical_stamp(prov)
        assert prov["enrichment_status"] == "complete"
        assert prov["warning"] is None
        assert "UNDER-REPORT" not in out and "DID NOT RUN" not in out
        # The tool renders the generation identity truncated to 12 chars.
        assert "live-mcp-ok-" in out and "enrichment: complete" in out


# ── Rule #37 content integrity: a pin that is re-derivable from the volume ────
#
# The defect these guard: `MANIFEST.json`'s field was NAMED `sha256` but held
# the upstream feed's git COMMIT, and `refresh-nvd-cache.sh --apply` overwrote
# the pin with whatever HEAD happened to be. Nothing was ever re-derived from
# the bytes on the volume, so the pin was a provenance label wearing an
# integrity field's name. A feed that silently REMOVES CVEs still matches its
# own commit, and every downstream verdict then reads `enrichment_status:
# complete` over a cache with holes.

from app.services.nvd_cache_service import (  # noqa: E402
    compute_content_digest,
    verify_content_digest,
)


def _populate(cache: Path, ids=("CVE-2021-0001", "CVE-2021-0002", "CVE-2022-1234")):
    for cid in ids:
        _write_cve(cache, cid, vendor="acme", product="widget")
    return cache


def test_content_digest_is_deterministic_and_counts_the_volume(tmp_path):
    _populate(tmp_path)
    a = compute_content_digest(tmp_path)
    b = compute_content_digest(tmp_path)
    assert a == b
    assert a["content_sha256"] == b["content_sha256"]
    assert len(a["content_sha256"]) == 64
    assert a["file_count"] == 3
    assert a["total_bytes"] == sum(
        p.stat().st_size for p in tmp_path.rglob("CVE-*.json")
    )
    assert a["digest_version"] == 1 and a["algo"] == "sha256"


def test_content_digest_is_independent_of_creation_order(tmp_path):
    """Two volumes with the same payloads must pin identically.

    The digest sorts by relative path, so a `tar -x` that lands files in a
    different order (or a different filesystem's walk order) does not produce
    a spurious drift — otherwise the gate would cry wolf and get switched off.
    """
    a, b = tmp_path / "a", tmp_path / "b"
    _populate(a, ids=("CVE-2021-0001", "CVE-2021-0002", "CVE-2022-1234"))
    _populate(b, ids=("CVE-2022-1234", "CVE-2021-0002", "CVE-2021-0001"))
    assert (
        compute_content_digest(a)["content_sha256"]
        == compute_content_digest(b)["content_sha256"]
    )


def test_content_digest_ignores_the_derived_artefacts(tmp_path):
    """cpe_index.json + MANIFEST.json must NOT feed the digest.

    The manifest RECORDS the digest and the index is rebuilt from the
    payloads, so including either would make the digest depend on itself and
    no pin could ever be stable across a re-index.
    """
    _populate(tmp_path)
    before = compute_content_digest(tmp_path)["content_sha256"]
    build_cpe_index(tmp_path)
    _write_manifest(tmp_path, sha=before, count=3)
    assert compute_content_digest(tmp_path)["content_sha256"] == before


# Rule #46: an absence-asserting gate ("no drift") is worthless without a
# canary that synthesizes each drift shape and confirms the gate FIRES.
# These are that canary, one per shape the threat model names.

def test_content_digest_detects_a_single_byte_edit(tmp_path):
    """Tampering: a record rewritten in place."""
    _populate(tmp_path)
    before = compute_content_digest(tmp_path)["content_sha256"]
    target = _feed_layout_path("CVE-2021-0001", tmp_path)
    raw = bytearray(target.read_bytes())
    raw[-2] = raw[-2] ^ 0x01
    target.write_bytes(bytes(raw))
    assert compute_content_digest(tmp_path)["content_sha256"] != before


def test_content_digest_detects_a_removed_cve(tmp_path):
    """The branch's own threat model: a feed that silently REMOVES CVEs."""
    _populate(tmp_path)
    before = compute_content_digest(tmp_path)["content_sha256"]
    _feed_layout_path("CVE-2021-0002", tmp_path).unlink()
    after = compute_content_digest(tmp_path)
    assert after["content_sha256"] != before and after["file_count"] == 2


def test_content_digest_detects_an_added_cve(tmp_path):
    _populate(tmp_path)
    before = compute_content_digest(tmp_path)["content_sha256"]
    _write_cve(tmp_path, "CVE-2023-9999", vendor="acme", product="widget")
    assert compute_content_digest(tmp_path)["content_sha256"] != before


def test_content_digest_detects_a_file_in_the_wrong_bucket(tmp_path):
    """Same bytes, wrong path — the leading-zero class of defect.

    A byte-only digest would call this clean; the cache would still be
    unreachable for ~8% of ids. The relative path is hashed alongside the
    bytes precisely so a misplaced file is drift.

    Deliberately ONE file: with several, moving one also permutes the sorted
    order, so the digest would change even for a path-blind construction and
    the test would pass for the wrong reason. (It did — caught by neutralizing
    the path from the digest and watching this test stay green. Rule #46
    applies to the canary itself.)
    """
    _populate(tmp_path, ids=("CVE-2021-0001",))
    before = compute_content_digest(tmp_path)["content_sha256"]
    src = _feed_layout_path("CVE-2021-0001", tmp_path)
    wrong = tmp_path / "CVE-2021" / "CVE-2021-0xx" / "CVE-2021-0001.json"
    wrong.parent.mkdir(parents=True, exist_ok=True)
    src.rename(wrong)
    after = compute_content_digest(tmp_path)
    # Same payload, same count, same bytes — ONLY the layout moved.
    assert after["file_count"] == 1
    assert after["total_bytes"] == wrong.stat().st_size
    assert after["content_sha256"] != before  # ...different layout ⇒ drift


def test_verify_content_digest_match_and_drift(tmp_path):
    _populate(tmp_path)
    pinned = compute_content_digest(tmp_path)["content_sha256"]

    ok = verify_content_digest(tmp_path, pinned)
    assert ok["ok"] is True and ok["status"] == "match"
    assert ok["expected"] == ok["actual"] == pinned

    # Case-insensitive + whitespace-tolerant: the pin arrives from a file.
    assert verify_content_digest(tmp_path, f"  {pinned.upper()}\n ")["ok"] is True

    _feed_layout_path("CVE-2021-0002", tmp_path).unlink()
    drift = verify_content_digest(tmp_path, pinned)
    assert drift["ok"] is False and drift["status"] == "drift"
    assert drift["expected"] == pinned and drift["actual"] != pinned


def test_verify_content_digest_absent_pin_is_not_a_pass(tmp_path):
    """Rule #53: a verifier must key on evidence, never on absence of a claim.

    "We never pinned it" is not evidence of integrity. Returning ok=True for a
    missing pin would let an unpinned volume launder straight through the gate
    — the shape this whole rule family exists to prevent.
    """
    _populate(tmp_path)
    for empty in (None, "", "   \n"):
        out = verify_content_digest(tmp_path, empty)
        assert out["ok"] is False and out["status"] == "not_pinned"
        assert out["expected"] is None and len(out["actual"]) == 64


def test_probe_reports_content_verifiability_without_re_deriving(tmp_path):
    """A legacy feed-commit-only manifest must NOT read as content-verifiable."""
    _populate(tmp_path)
    build_cpe_index(tmp_path)
    # Legacy shape: identity is the upstream git commit, nothing re-derivable.
    _write_manifest(tmp_path, sha="a1f38452d7df90df6f6b27d5e4762e0f6b4c4a90", count=3)
    legacy = probe(tmp_path)
    assert legacy["ready"] is True          # populated — usable
    assert legacy["content_verifiable"] is False   # ...but not verifiable
    assert legacy["content_sha256"] is None

    digest = compute_content_digest(tmp_path)["content_sha256"]
    (tmp_path / ncs._MANIFEST_NAME).write_text(json.dumps({
        "sha256": digest,
        "content_sha256": digest,
        "feed_commit": "a1f38452d7df90df6f6b27d5e4762e0f6b4c4a90",
        "populated_at": "2026-07-25T00:00:00Z",
        "cve_count": 3,
    }), encoding="utf-8")
    ncs._INDEX_CACHE.clear()
    ncs._INTEGRITY_CACHE.clear()
    pinned = probe(tmp_path)
    assert pinned["content_verifiable"] is True
    assert pinned["content_sha256"] == digest
    assert pinned["feed_commit"] == "a1f38452d7df90df6f6b27d5e4762e0f6b4c4a90"
