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
import hashlib
import json
import logging
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

_INDEX_NAME = "cpe_index.json"
_MANIFEST_NAME = "MANIFEST.json"
_INDEX_SCHEMA_VERSION = 1

# Version of the CONTENT-DIGEST construction below. Bumping it changes every
# derived digest, so it is part of the pinned value's meaning: a pin recorded
# under v1 is not comparable to a v2 digest, and the verifier says so instead
# of reporting a bogus drift.
CONTENT_DIGEST_VERSION = 1
# Read size for the per-file hash — bounded so a corrupt/huge file cannot pull
# the whole cache into memory.
_DIGEST_CHUNK = 1 << 20

# Module-memoised index keyed by cache dir; invalidated on manifest-sha change.
_INDEX_CACHE: dict[str, dict] = {}
# Module-memoised integrity verdict keyed by cache dir; same invalidation rule.
_INTEGRITY_CACHE: dict[str, dict] = {}
# How many index-referenced CVE files to stat when judging cache integrity.
# Deterministic even spread over the sorted index keys — 16 stat() calls ONCE per
# manifest sha, not per lookup (Rule #5: never walk 369k files at scan time).
_INTEGRITY_SAMPLE = 16

MODE_CACHE_HIT = "cache_hit"
MODE_CACHE_MISS = "cache_miss"
MODE_CACHE_DEGRADED = "cache_degraded"
MODE_CACHE_UNAVAILABLE = "cache_unavailable"
MODE_LIVE_FALLBACK = "live_fallback"

# Worst-first ordering used by consumers to reduce a per-component mode histogram
# to one honest scan-level verdict. cache_hit/cache_miss are equally trustworthy
# (a miss on a healthy cache IS the reproducible answer); everything above them
# means the answer is either non-reproducible or incomplete.
MODE_SEVERITY: dict[str, int] = {
    MODE_CACHE_HIT: 0,
    MODE_CACHE_MISS: 0,
    MODE_LIVE_FALLBACK: 1,
    MODE_CACHE_DEGRADED: 2,
    MODE_CACHE_UNAVAILABLE: 3,
}


@dataclass(frozen=True)
class CacheProvenance:
    """What the pinned cache did for a lookup — stamped onto the assessment.

    mode:
      cache_hit          — the pinned cache resolved candidate CVEs.
      cache_miss         — the cache is present, healthy, and no CVE matched the
                           CPE (a VALID reproducible "no known CVEs").
      cache_degraded     — the manifest + index are present but the cache is
                           demonstrably incomplete (index empty while the
                           manifest declares CVEs, sampled index-referenced CVE
                           files absent on disk, or candidate files skipped
                           mid-lookup). Results UNDER-REPORT; an empty result in
                           this mode must NEVER be read as "no known CVEs".
      cache_unavailable  — no pinned cache (missing / malformed manifest).
      live_fallback      — the caller fell back to a live NVD query (opt-in).

    ``degraded`` is the boolean consumers gate on; ``candidates``/``resolved``/
    ``skipped`` quantify the per-lookup loss and ``integrity_reasons`` carries
    the cache-level reasons (tuple so the dataclass stays hashable/frozen).
    """

    mode: str
    manifest_sha: str | None = None
    populated_at: str | None = None
    cve_count: int | None = None
    degraded: bool = False
    candidates: int = 0
    resolved: int = 0
    skipped: int = 0
    integrity_reasons: tuple[str, ...] = ()


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


def _sample_cve_ids(index: dict, n: int) -> list[str]:
    """Pick up to ``n`` index-referenced CVE ids, evenly spread over sorted keys.

    Deterministic (same cache ⇒ same sample ⇒ same verdict) and cheap: one id per
    sampled vendor:product entry.
    """
    keys = sorted(index)
    if not keys:
        return []
    step = max(1, len(keys) // n)
    out: list[str] = []
    for k in keys[::step][:n]:
        ids = index.get(k) or []
        if ids:
            out.append(ids[0])
    return out


def _integrity_sync(cache_dir: Path, manifest: dict, index: dict) -> dict:
    """Judge whether a present-looking cache is actually populated.

    A half-populated volume (manifest + index written, CVE files missing or
    wiped) previously reported the *valid reproducible* ``cache_miss`` for every
    CPE — a clean verdict indistinguishable from "no known CVEs". Two cheap
    signals close that:

    1. index empty while the manifest declares CVEs (or index unreadable);
    2. a deterministic 16-file sample of index-referenced CVE paths that are
       absent on disk.

    Memoised per (cache_dir, manifest_sha) — 16 ``stat()`` calls once per pinned
    cache generation, never per lookup.
    """
    key = str(cache_dir)
    sha = manifest.get("sha256")
    cached = _INTEGRITY_CACHE.get(key)
    if cached is not None and cached.get("manifest_sha") == sha:
        return cached

    declared = manifest.get("cve_count") or 0
    reasons: list[str] = []
    if not index:
        reasons.append(
            f"cpe index empty or unreadable while the manifest declares "
            f"{declared} CVEs"
            if declared
            else "cpe index empty or unreadable"
        )
    sample = _sample_cve_ids(index, _INTEGRITY_SAMPLE)
    present = 0
    for cid in sample:
        path = _cve_path(cid, cache_dir)
        if path is not None and path.exists():
            present += 1
    if sample and present < len(sample):
        reasons.append(
            f"{len(sample) - present}/{len(sample)} sampled index-referenced "
            f"CVE files are absent on disk"
        )

    verdict = {
        "manifest_sha": sha,
        "vendor_products": len(index),
        "declared_cve_count": declared,
        "sampled": len(sample),
        "sampled_present": present,
        "degraded": bool(reasons),
        "reasons": reasons,
    }
    if reasons:
        logger.warning(
            "NVD cache at %s is DEGRADED (manifest_sha=%s): %s — CVE results "
            "will UNDER-REPORT; repopulate with scripts/refresh-nvd-cache.sh --apply",
            cache_dir, sha, "; ".join(reasons),
        )
    _INTEGRITY_CACHE[key] = verdict
    return verdict


def _lookup_sync(cpe: str, cache_dir: Path) -> tuple[list | None, CacheProvenance]:
    # Lazy import: reuse the exact CVE-object wrapping _search_nvd produces so the
    # downstream _cpe_is_vulnerable_in_cve / _parse_nvd_cve path is unchanged.
    from nvdlib.classes import CVE  # noqa: PLC0415

    from app.services.vulnerability_service import _to_obj  # noqa: PLC0415

    manifest = _read_manifest_sync(cache_dir)
    if not manifest:
        return None, CacheProvenance(mode=MODE_CACHE_UNAVAILABLE, degraded=True)

    prov_base = {
        "manifest_sha": manifest.get("sha256"),
        "populated_at": manifest.get("populated_at"),
        "cve_count": manifest.get("cve_count"),
    }
    index = _load_index_sync(cache_dir, manifest.get("sha256"))
    integrity = _integrity_sync(cache_dir, manifest, index)
    reasons = tuple(integrity["reasons"])

    vp = _cpe_vendor_product(cpe)
    if vp is None:
        # Unparseable CPE — nothing to look up. Still honest about cache health:
        # a degraded cache cannot produce a trustworthy "no CVEs" for anything.
        return [], CacheProvenance(
            mode=MODE_CACHE_DEGRADED if integrity["degraded"] else MODE_CACHE_MISS,
            degraded=integrity["degraded"],
            integrity_reasons=reasons,
            **prov_base,
        )

    cve_ids = index.get(vp, [])
    cves: list = []
    skipped = 0
    for cid in cve_ids:
        path = _cve_path(cid, cache_dir)
        if path is None or not path.exists():
            skipped += 1  # index says this CVE exists; the file does not
            continue
        try:
            cve_data = json.loads(path.read_text(encoding="utf-8"))
            cve_obj = CVE({k: _to_obj(v) for k, v in cve_data.items()})
            cve_obj.getvars()
        except Exception:  # noqa: BLE001 — see below; a bad record must not abort the lookup
            # DELIBERATELY broad, and construction is INSIDE the guard.
            #
            # The narrow `(OSError, json.JSONDecodeError)` guard covered only the
            # read+parse, and only those two types. Two reachable escapes:
            #   * a torn write (interrupted `tar -x` in refresh-nvd-cache.sh, the
            #     exact failure this module's degrade detection exists for) leaves
            #     a file truncated mid-UTF-8 → UnicodeDecodeError (a ValueError,
            #     NOT a JSONDecodeError) → uncaught;
            #   * nvdlib's CVE(...)/getvars() sat outside the try entirely and
            #     raises AttributeError on an unexpected record shape
            #     (reproduced: "'str' object has no attribute 'cvssData'").
            # Either one aborted the WHOLE lookup for that CPE, and
            # VulnerabilityService.scan_components swallows per-component
            # exceptions — so the component vanished from the scan AND from the
            # provenance histogram, yielding lookups=0 → "not_applicable" with a
            # null warning: a false clean verdict, the one outcome this module
            # exists to make impossible.
            #
            # Counting it as `skipped` instead routes it through the existing
            # honest path: skipped ⇒ degraded ⇒ mode cache_degraded ⇒
            # enrichment_status "partial" ⇒ UNDER-REPORT warning.
            skipped += 1
            continue
        cves.append(cve_obj)

    if skipped:
        reasons = (
            *reasons,
            f"{skipped}/{len(cve_ids)} candidate CVE files for {vp} were "
            f"missing or unparseable",
        )
    degraded = bool(integrity["degraded"] or skipped)
    if degraded:
        # Deliberately NOT cache_unavailable: a degraded cache still returns the
        # CVEs it could resolve (partial > nothing) and must NOT trigger the
        # live-NVD fallback path, which is reserved for a wholly absent cache.
        # The mode + degraded flag make the incompleteness loud instead.
        mode = MODE_CACHE_DEGRADED
    else:
        mode = MODE_CACHE_HIT if cves else MODE_CACHE_MISS
    return cves, CacheProvenance(
        mode=mode,
        degraded=degraded,
        candidates=len(cve_ids),
        resolved=len(cves),
        skipped=skipped,
        integrity_reasons=reasons,
        **prov_base,
    )


async def lookup_cves_for_cpe(
    cpe: str, cache_dir: str | Path
) -> tuple[list | None, CacheProvenance]:
    """Cache-first CVE lookup for a CPE (Rule #5 — reads run in a thread executor).

    Returns (cves, provenance):
      - cves is None  ⇒ mode cache_unavailable (caller decides live fallback).
      - cves is []    ⇒ cache present, no match. A valid reproducible result ONLY
        when ``provenance.degraded`` is False — do NOT live-fallback, that would
        break reproducibility. When ``degraded`` is True (mode cache_degraded)
        the empty result means "the cache could not answer", NOT "no CVEs".
      - cves is [..]  ⇒ candidate CVE objects (same shape _search_nvd returns);
        the caller still runs _cpe_is_vulnerable_in_cve to refine. May STILL be
        ``degraded`` (partial) — see CacheProvenance.
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
    # A rebuilt index invalidates both memos even if the manifest sha is unchanged
    # (the refresh script writes the manifest after the index).
    _INDEX_CACHE.pop(str(cache_dir), None)
    _INTEGRITY_CACHE.pop(str(cache_dir), None)
    return {"cves_indexed": n, "vendor_products": len(vp_map)}


def _iter_cve_files(cache_dir: Path):
    """Every CVE payload file under the cache, as (relative_posix_path, Path).

    Excludes the two DERIVED artefacts (``cpe_index.json``, ``MANIFEST.json``):
    the index is rebuilt from the payloads and the manifest RECORDS the digest,
    so including either would make the digest depend on itself.
    """
    for path in cache_dir.rglob("CVE-*.json"):
        if path.name in (_INDEX_NAME, _MANIFEST_NAME) or not path.is_file():
            continue
        yield path.relative_to(cache_dir).as_posix(), path


def compute_content_digest(cache_dir: str | Path) -> dict:
    """Re-derive a SHA-256 over the cache's ACTUAL bytes (Rule #37 integrity).

    The pin exists to make a tampered / truncated / rewritten feed detectable.
    A pin that records the upstream git commit cannot do that — it is a
    *provenance* label the refresh script copies from whatever HEAD happened to
    be, never re-derived from what landed on the volume. A feed that silently
    REMOVES CVEs still matches its own commit, and every downstream verdict
    then reports ``enrichment_status: complete`` over a cache with holes.

    This digest is re-derivable from the volume alone:

        outer = sha256()
        for relpath, file in sorted-by-relpath(CVE-*.json):
            outer.update(f"{relpath}\\0{sha256(file bytes)}\\n")

    Sorting by relative path makes it independent of filesystem walk order;
    including the path makes a file MOVED to a wrong bucket (the leading-zero
    class of bug) change the digest even though its bytes did not; hashing the
    bytes makes a truncated or edited record change it too.

    Returns ``{digest_version, algo, content_sha256, file_count, total_bytes}``.
    Walks the whole cache (~369k files / ~2 GB) — an OUT-OF-BAND operation only,
    never called at scan time or from the lifespan probe (Rule #5).
    """
    cache_dir = Path(cache_dir)
    outer = hashlib.sha256()
    outer.update(f"nvd-cache-content-digest/v{CONTENT_DIGEST_VERSION}\n".encode())
    file_count = 0
    total_bytes = 0
    for relpath, path in sorted(_iter_cve_files(cache_dir), key=lambda t: t[0]):
        inner = hashlib.sha256()
        size = 0
        with path.open("rb") as fh:
            while chunk := fh.read(_DIGEST_CHUNK):
                inner.update(chunk)
                size += len(chunk)
        outer.update(f"{relpath}\0{inner.hexdigest()}\n".encode())
        file_count += 1
        total_bytes += size
    return {
        "digest_version": CONTENT_DIGEST_VERSION,
        "algo": "sha256",
        "content_sha256": outer.hexdigest(),
        "file_count": file_count,
        "total_bytes": total_bytes,
    }


def verify_content_digest(cache_dir: str | Path, expected: str | None) -> dict:
    """Re-derive the content digest and compare it to a pinned value.

    ``ok`` is True ONLY when a non-empty ``expected`` was supplied AND the
    freshly-derived digest equals it. An absent pin returns
    ``ok=False, status="not_pinned"`` — deliberately NOT "ok": "we never pinned
    it" is not evidence of integrity, and a verifier that passes on a missing
    pin is the Rule #53 laundering shape (matching the absence of a claim
    instead of the evidence behind it).
    """
    derived = compute_content_digest(cache_dir)
    pinned = (expected or "").strip().lower()
    actual = derived["content_sha256"]
    if not pinned:
        status = "not_pinned"
    elif pinned == actual:
        status = "match"
    else:
        status = "drift"
    return {
        **derived,
        "ok": status == "match",
        "status": status,
        "expected": pinned or None,
        "actual": actual,
    }


def probe(cache_dir: str | Path) -> dict:
    """Presence + integrity probe for the lifespan startup log.

    Returns {ready: bool, ...}. ``ready`` is False when the manifest or index is
    absent/malformed OR when the present-looking cache is DEGRADED (index empty,
    or sampled index-referenced CVE files missing on disk) — in every one of
    those states the operator must run scripts/refresh-nvd-cache.sh --apply.
    ``degraded_reasons`` carries the why, so a half-populated volume is visible
    at boot instead of masquerading as a healthy cache that finds nothing.
    """
    cache_dir = Path(cache_dir)
    manifest = _read_manifest_sync(cache_dir)
    index_path = cache_dir / _INDEX_NAME
    present = bool(manifest) and index_path.exists()
    integrity = (
        _integrity_sync(
            cache_dir, manifest, _load_index_sync(cache_dir, manifest.get("sha256"))
        )
        if present
        else {"degraded": True, "reasons": ["manifest or cpe index absent"]}
    )
    return {
        "ready": present and not integrity["degraded"],
        "path": str(cache_dir),
        "manifest_sha": manifest.get("sha256"),
        "populated_at": manifest.get("populated_at"),
        "cve_count": manifest.get("cve_count"),
        # Rule #37 integrity identity, reported WITHOUT re-deriving it (a
        # re-derivation reads ~2 GB and has no business in a boot probe).
        # ``content_verifiable`` says whether this generation carries a digest
        # that scripts/refresh-nvd-cache.sh --verify can check at all: a legacy
        # manifest whose only identity is the upstream feed commit is a
        # provenance label, not an integrity gate, and the probe must not let
        # that pass for one.
        "content_sha256": manifest.get("content_sha256"),
        "feed_commit": manifest.get("feed_commit"),
        "content_verifiable": bool(manifest.get("content_sha256")),
        "index_present": index_path.exists(),
        "manifest_present": bool(manifest),
        "degraded": bool(integrity["degraded"]),
        "degraded_reasons": list(integrity["reasons"]),
        "integrity": integrity,
    }
