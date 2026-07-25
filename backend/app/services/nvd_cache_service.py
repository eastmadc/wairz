"""Pinned NVD cache — offline, reproducible, provenance-stamped CVE lookup.

Resolves the CVEs affecting a CPE from a BUILD-TIME-PINNED local NVD cache
(mirroring the EMBA ``nvd-json-data-feeds`` layout: one JSON per CVE at
``CVE-{year}/CVE-{year}-{nn}xx/CVE-{year}-{n}.json`` (zero-padding preserved), the bare NVD API-2.0
CVE object) instead of a live NVD API call. This makes firmware assessments:

- **reproducible** — same firmware + same pinned cache ⇒ identical CVE set;
- **offline / air-gap-friendly** — no network egress at scan time;
- **provenance-stamped** — every scan records the cache manifest sha + populated_at.

Rule #37 offline-trust-anchor discipline: the cache is populated out-of-band by
``scripts/refresh-nvd-cache.sh`` and pinned by a manifest sha; it is NEVER fetched
at scan time. Live NVD is an EXPLICIT opt-in fallback only
(``settings.nvd_allow_live_fallback``, default False) — a cache miss with the flag
off returns a truthful "no data" (Axiom-analog: never a fabricated clean verdict).

The 369k-file cache is too large to bake into the image / commit — it lives on a
named Docker volume populated by the refresh script. A ``cpe_index.json`` built at
populate-time maps ``vendor:product`` → ``[cve_ids]`` so a lookup reads only the
candidate CVE files (Rule #5 — never walk 369k files per lookup).
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

_INDEX_NAME = "cpe_index.json"
_MANIFEST_NAME = "MANIFEST.json"
_INDEX_SCHEMA_VERSION = 1

# Module-memoised index keyed by cache dir; invalidated on manifest-sha change.
_INDEX_CACHE: dict[str, dict] = {}


@dataclass(frozen=True)
class CacheProvenance:
    """What the pinned cache did for a lookup — stamped onto the assessment.

    mode:
      cache_hit          — the pinned cache resolved candidate CVEs.
      cache_miss         — the cache is present but no CVE matched the CPE.
      cache_unavailable  — no pinned cache (missing / malformed manifest).
      live_fallback      — the caller fell back to a live NVD query (opt-in).
    """

    mode: str
    manifest_sha: str | None = None
    populated_at: str | None = None
    cve_count: int | None = None


def _cve_path(cve_id: str, cache_dir: Path) -> Path | None:
    """Resolve CVE-{year}/CVE-{year}-{nn}xx/CVE-{year}-{n}.json."""
    parts = cve_id.strip().upper().split("-")
    if len(parts) != 3 or parts[0] != "CVE" or not parts[2].isdigit():
        return None
    year, num = parts[1], parts[2]
    # Bucket = the CVE number with its last two digits replaced by "xx", PRESERVING
    # zero padding: CVE-1999-0001 lives in CVE-1999-00xx and CVE-2019-0773 in
    # CVE-2019-07xx. The original `int(num) // 100` stripped leading zeros and
    # produced CVE-1999-0xx / CVE-2019-7xx — directories that do not exist — so
    # every zero-padded CVE was silently unreachable (measured: 24,616 of 306,918,
    # ~8%). _lookup_sync skips a missing file and still reports cache_hit, so the
    # loss was invisible. Caught by an independent audit, 2026-07-25.
    bucket = f"CVE-{year}-{num[:-2]}xx" if len(num) > 2 else f"CVE-{year}-{num}"
    return Path(cache_dir) / f"CVE-{year}" / bucket / f"CVE-{year}-{num}.json"


def _cpe_vendor_product(cpe: str) -> str | None:
    """`cpe:2.3:a:vendor:product:version:...` → `vendor:product` (lowercased)."""
    parts = cpe.split(":")
    if len(parts) >= 5 and parts[0] == "cpe" and parts[1] == "2.3":
        vendor, product = parts[3].lower(), parts[4].lower()
        if vendor and product:
            return f"{vendor}:{product}"
    return None


def _read_manifest_sync(cache_dir: Path) -> dict:
    try:
        return json.loads((Path(cache_dir) / _MANIFEST_NAME).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _load_index_sync(cache_dir: Path, manifest_sha: str | None) -> dict:
    """Load + memoise the cpe->cve index (invalidated on manifest-sha change)."""
    key = str(cache_dir)
    cached = _INDEX_CACHE.get(key)
    if cached is not None and cached.get("_sha") == manifest_sha:
        return cached["vp"]
    try:
        idx = json.loads((Path(cache_dir) / _INDEX_NAME).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    vp = idx.get("vendor_product", {})
    _INDEX_CACHE[key] = {"_sha": manifest_sha, "vp": vp}
    return vp


def _lookup_sync(cpe: str, cache_dir: Path) -> tuple[list | None, CacheProvenance]:
    # Lazy import: reuse the exact CVE-object wrapping _search_nvd produces so the
    # downstream _cpe_is_vulnerable_in_cve / _parse_nvd_cve path is unchanged.
    from nvdlib.classes import CVE  # noqa: PLC0415

    from app.services.vulnerability_service import _to_obj  # noqa: PLC0415

    manifest = _read_manifest_sync(cache_dir)
    if not manifest:
        return None, CacheProvenance(mode="cache_unavailable")

    prov_base = {
        "manifest_sha": manifest.get("sha256"),
        "populated_at": manifest.get("populated_at"),
        "cve_count": manifest.get("cve_count"),
    }
    vp = _cpe_vendor_product(cpe)
    if vp is None:
        return [], CacheProvenance(mode="cache_miss", **prov_base)

    index = _load_index_sync(cache_dir, manifest.get("sha256"))
    cve_ids = index.get(vp, [])
    cves: list = []
    for cid in cve_ids:
        path = _cve_path(cid, cache_dir)
        if path is None or not path.exists():
            continue
        try:
            cve_data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        cve_obj = CVE({k: _to_obj(v) for k, v in cve_data.items()})
        cve_obj.getvars()
        cves.append(cve_obj)
    return cves, CacheProvenance(mode="cache_hit" if cves else "cache_miss", **prov_base)


async def lookup_cves_for_cpe(
    cpe: str, cache_dir: str | Path
) -> tuple[list | None, CacheProvenance]:
    """Cache-first CVE lookup for a CPE (Rule #5 — reads run in a thread executor).

    Returns (cves, provenance):
      - cves is None  ⇒ mode cache_unavailable (caller decides live fallback).
      - cves is []    ⇒ cache present, no match (a valid reproducible result —
        do NOT live-fallback, that would break reproducibility).
      - cves is [..]  ⇒ candidate CVE objects (same shape _search_nvd returns);
        the caller still runs _cpe_is_vulnerable_in_cve to refine.
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _lookup_sync, cpe, Path(cache_dir))


def build_cpe_index(cache_dir: str | Path) -> dict:
    """Walk the pinned cache and write cpe_index.json (populate-time only).

    Maps vendor:product → sorted[cve_ids] from every CVE's configurations CPE
    criteria, so a lookup reads only the candidate files. Returns build stats.
    Slow (walks ~369k files) — invoked by scripts/refresh-nvd-cache.sh, never at
    scan time.
    """
    cache_dir = Path(cache_dir)
    vp_map: dict[str, set] = defaultdict(set)
    n = 0
    for path in cache_dir.rglob("CVE-*.json"):
        if path.name in (_INDEX_NAME, _MANIFEST_NAME):
            continue
        try:
            cve_data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        cid = cve_data.get("id")
        if not cid:
            continue
        for cfg in cve_data.get("configurations", []) or []:
            for node in cfg.get("nodes", []) or []:
                for match in node.get("cpeMatch", []) or []:
                    vp = _cpe_vendor_product(match.get("criteria", ""))
                    if vp:
                        vp_map[vp].add(cid)
        n += 1
    out = {
        "schema_version": _INDEX_SCHEMA_VERSION,
        "vendor_product": {k: sorted(v) for k, v in sorted(vp_map.items())},
    }
    (cache_dir / _INDEX_NAME).write_text(json.dumps(out), encoding="utf-8")
    return {"cves_indexed": n, "vendor_products": len(vp_map)}


def probe(cache_dir: str | Path) -> dict:
    """Presence/size/mtime probe for the lifespan startup log.

    Returns {ready: bool, ...}. ready=False when the manifest or index is
    absent/malformed — the operator must run scripts/refresh-nvd-cache.sh --apply.
    """
    cache_dir = Path(cache_dir)
    manifest = _read_manifest_sync(cache_dir)
    index_path = cache_dir / _INDEX_NAME
    return {
        "ready": bool(manifest) and index_path.exists(),
        "path": str(cache_dir),
        "manifest_sha": manifest.get("sha256"),
        "populated_at": manifest.get("populated_at"),
        "cve_count": manifest.get("cve_count"),
        "index_present": index_path.exists(),
    }
