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


def _write_cve(cache: Path, cve_id: str, *, vendor="acme", product="widget", version_end=None):
    """Write a bare NVD API-2.0 CVE object at the feed layout path."""
    path = _cve_path(cve_id, cache)
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
    (_cve_path("CVE-2021-0002", tmp_path)).unlink()

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
    # a wrong formula cannot satisfy them (the previous fixture called _cve_path to
    # decide where to write, making every cache-hit test tautological).
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
