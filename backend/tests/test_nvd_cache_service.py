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
    ncs._INDEX_CACHE.clear()  # reset the module memo between tests


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
    build_cpe_index(tmp_path)
    _write_manifest(tmp_path)
    cves, prov = asyncio.run(lookup_cves_for_cpe("garbage-cpe", tmp_path))
    assert cves == [] and prov.mode == "cache_miss"


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


# ── probe ────────────────────────────────────────────────────────────

def test_probe_ready_and_not_ready(tmp_path):
    assert probe(tmp_path)["ready"] is False  # empty
    _write_cve(tmp_path, "CVE-2021-0001")
    build_cpe_index(tmp_path)
    _write_manifest(tmp_path, sha="s1", count=1)
    p = probe(tmp_path)
    assert p["ready"] is True
    assert p["manifest_sha"] == "s1" and p["cve_count"] == 1 and p["index_present"] is True


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
