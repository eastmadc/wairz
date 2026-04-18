"""Tests for ``app.services.firmware_paths`` — detection-roots helper.

Phase 2 of ``feature-extraction-integrity``. Covers:

* Multi-partition Android OTA (DPCS10 shape) — rootfs/ + scatter sibling.
* ACM-style nested Linux extraction.
* Single-image bare-metal firmware.
* APK extraction directory.
* No-extraction firmware row (null path).
* JSONB cache hit, stale invalidation, and explicit invalidation.
* ``get_primary_root`` fallback semantics.
* ``realpath`` deduplication.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.firmware_paths import (
    _compute_roots_sync,
    _dedup_by_realpath,
    get_detection_roots,
    get_primary_root,
    invalidate_detection_roots,
)

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _make_firmware(
    *,
    extracted_path: str | None,
    device_metadata: dict | None = None,
) -> MagicMock:
    """Return a MagicMock that mimics the ``Firmware`` ORM row interface.

    ``device_metadata`` is writable so the helper can persist the cache.
    """
    fw = MagicMock()
    fw.extracted_path = extracted_path
    fw.device_metadata = device_metadata
    return fw


def _build_dpcs10_tree(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    """DPCS10-shape layout.

    Returns (extraction_dir, rootfs_dir, scatter_dir, partition_dir).
    """
    extraction = tmp_path / "extracted"
    extraction.mkdir()
    rootfs = extraction / "rootfs"
    for p in ("vendor", "system", "odm"):
        (rootfs / p).mkdir(parents=True)
    partition = rootfs / "partition_2_erofs"
    partition.mkdir()

    scatter = extraction / "DPCS10_260414-1134"
    scatter.mkdir()
    for name in ("lk.img", "md1dsp.img", "tee.img", "preloader_foo.bin"):
        (scatter / name).write_bytes(b"\xde\xad\xbe\xef" * 32)
    return extraction, rootfs, scatter, partition


def _reals(paths) -> set[str]:
    """Sync helper: realpath-set for a list of paths.

    Wrapped in a sync function to keep ruff's ASYNC240 check happy inside
    async test bodies.
    """
    return {os.path.realpath(str(p)) for p in paths}


def _real(path) -> str:
    return os.path.realpath(str(path))


def _isdir(path) -> bool:
    return os.path.isdir(str(path))


# ---------------------------------------------------------------------------
# 1. Multi-partition Android OTA
# ---------------------------------------------------------------------------


async def test_dpcs10_android_ota_returns_rootfs_and_scatter(tmp_path: Path):
    """Scatter-zip plus rootfs siblings: both show up, rootfs leads."""
    _, rootfs, scatter, partition = _build_dpcs10_tree(tmp_path)
    fw = _make_firmware(extracted_path=str(partition))

    roots = await get_detection_roots(fw)

    # Must include at least rootfs + scatter
    resolved = _reals(roots)
    assert _real(rootfs) in resolved
    assert _real(scatter) in resolved
    # Ordering: rootfs first (score 0 beats default score 1).
    assert _real(roots[0]) == _real(rootfs)


async def test_dpcs10_includes_nested_partition_when_caller_pointed_at_it(
    tmp_path: Path,
):
    """``partition_2_erofs`` is buried under ``rootfs/`` and must be
    returned as its own root because ``extracted_path`` pointed at it."""
    _, _, _, partition = _build_dpcs10_tree(tmp_path)
    fw = _make_firmware(extracted_path=str(partition))

    roots = await get_detection_roots(fw)
    assert _real(partition) in _reals(roots)


# ---------------------------------------------------------------------------
# 2. ACM nested Linux
# ---------------------------------------------------------------------------


async def test_acm_nested_linux_returns_extraction_root(tmp_path: Path):
    """ACM-style deeply nested extracts resolve to the extraction dir
    (consumers recurse from there; we don't promote every intermediate)."""
    extraction = tmp_path / "extracted"
    zimg = extraction / "zImage-restore_extract"
    zimg.mkdir(parents=True)
    gz = zimg / "gzip.uncompressed_extract"
    gz.mkdir()
    # DTBs at the zImage-restore level and actual extractable content inside.
    (extraction / "acm.dtb").write_bytes(b"\xd0\x0d\xfe\xed" + b"X" * 200)
    (gz / "vmlinux.bin").write_bytes(b"\x7fELF" + b"X" * 400)

    fw = _make_firmware(extracted_path=str(extraction))
    roots = await get_detection_roots(fw)

    # At minimum, the extraction root must be a detection root.
    assert _real(extraction) in _reals(roots)
    # Nothing points at a vanished intermediate — every returned root
    # exists on disk.
    for r in roots:
        assert _isdir(r)


# ---------------------------------------------------------------------------
# 3. Single-image bare-metal (hex / ELF)
# ---------------------------------------------------------------------------


async def test_bare_metal_hex_returns_single_parent(tmp_path: Path):
    """A flat dir with one blob must NOT spawn sibling exploration."""
    extraction = tmp_path / "extracted"
    extraction.mkdir()
    (extraction / "fw.elf").write_bytes(b"\x7fELF" + b"X" * 400)

    fw = _make_firmware(extracted_path=str(extraction))
    roots = await get_detection_roots(fw)

    assert len(roots) == 1
    assert _real(roots[0]) == _real(extraction)


# ---------------------------------------------------------------------------
# 4. APK extraction
# ---------------------------------------------------------------------------


async def test_apk_extracted_returns_single_root(tmp_path: Path):
    """An ``apk_extracted/`` dir with normal APK children is a single root."""
    apk = tmp_path / "apk_extracted"
    (apk / "res").mkdir(parents=True)
    (apk / "META-INF").mkdir()
    (apk / "classes.dex").write_bytes(b"dex\n035\0" + b"X" * 400)

    fw = _make_firmware(extracted_path=str(apk))
    roots = await get_detection_roots(fw)

    assert len(roots) == 1
    assert _real(roots[0]) == _real(apk)


# ---------------------------------------------------------------------------
# 5. Null extracted_path
# ---------------------------------------------------------------------------


async def test_null_extracted_path_returns_empty():
    fw = _make_firmware(extracted_path=None)
    roots = await get_detection_roots(fw)
    assert roots == []


async def test_empty_string_extracted_path_returns_empty():
    fw = _make_firmware(extracted_path="")
    roots = await get_detection_roots(fw)
    assert roots == []


async def test_missing_extracted_path_returns_empty(tmp_path: Path):
    """A row whose on-disk extraction was deleted should return []."""
    gone = tmp_path / "gone"
    # never created
    fw = _make_firmware(extracted_path=str(gone))
    roots = await get_detection_roots(fw)
    assert roots == []


# ---------------------------------------------------------------------------
# 6. Cache hit
# ---------------------------------------------------------------------------


async def test_cache_hit_returns_cached_list_without_recomputing(tmp_path: Path):
    """Pre-populated cache short-circuits the walk."""
    # Build a real on-disk tree but have the cache point *somewhere else*
    # that also exists. If caching works, we never look at extracted_path.
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    cached_dir = tmp_path / "totally_unrelated"
    cached_dir.mkdir()

    fw = _make_firmware(
        extracted_path=str(extracted),
        device_metadata={"detection_roots": [str(cached_dir)], "other_key": "x"},
    )
    roots = await get_detection_roots(fw, use_cache=True)

    assert roots == [str(cached_dir)]


async def test_use_cache_false_ignores_cache(tmp_path: Path):
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    cached_dir = tmp_path / "cached"
    cached_dir.mkdir()

    fw = _make_firmware(
        extracted_path=str(extracted),
        device_metadata={"detection_roots": [str(cached_dir)]},
    )
    roots = await get_detection_roots(fw, use_cache=False)

    resolved = _reals(roots)
    assert _real(cached_dir) not in resolved
    assert _real(extracted) in resolved


# ---------------------------------------------------------------------------
# 7. Cache invalidation on stale path
# ---------------------------------------------------------------------------


async def test_stale_cache_is_invalidated_and_recomputed(tmp_path: Path):
    """Cache containing a missing path must NOT be returned."""
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    fw = _make_firmware(
        extracted_path=str(extracted),
        device_metadata={
            "detection_roots": [str(tmp_path / "does_not_exist")],
        },
    )
    roots = await get_detection_roots(fw, use_cache=True)

    resolved = _reals(roots)
    assert _real(extracted) in resolved
    assert str(tmp_path / "does_not_exist") not in roots


async def test_cache_with_non_list_value_is_ignored(tmp_path: Path):
    """Bogus cache types (e.g. old string value) are ignored."""
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    fw = _make_firmware(
        extracted_path=str(extracted),
        device_metadata={"detection_roots": "not a list"},
    )
    roots = await get_detection_roots(fw, use_cache=True)
    assert roots == [str(extracted)]


# ---------------------------------------------------------------------------
# 8. invalidate_detection_roots clears cache
# ---------------------------------------------------------------------------


async def test_invalidate_detection_roots_clears_and_flushes(tmp_path: Path):
    db = AsyncMock()
    fw = _make_firmware(
        extracted_path=str(tmp_path),
        device_metadata={
            "detection_roots": [str(tmp_path)],
            "device_model": "DPCS10",
        },
    )

    await invalidate_detection_roots(fw, db)

    assert "detection_roots" not in (fw.device_metadata or {})
    # Other keys preserved.
    assert fw.device_metadata.get("device_model") == "DPCS10"
    db.flush.assert_awaited_once()


async def test_invalidate_noop_when_cache_absent():
    db = AsyncMock()
    fw = _make_firmware(
        extracted_path="/tmp/fake",
        device_metadata={"device_model": "X"},
    )
    await invalidate_detection_roots(fw, db)
    db.flush.assert_not_awaited()
    assert fw.device_metadata == {"device_model": "X"}


async def test_invalidate_with_only_detection_roots_nulls_metadata(
    tmp_path: Path,
):
    """If detection_roots was the only key, device_metadata becomes None."""
    db = AsyncMock()
    fw = _make_firmware(
        extracted_path=str(tmp_path),
        device_metadata={"detection_roots": [str(tmp_path)]},
    )
    await invalidate_detection_roots(fw, db)
    assert fw.device_metadata is None


# ---------------------------------------------------------------------------
# 9. get_primary_root fallback
# ---------------------------------------------------------------------------


def test_get_primary_root_falls_back_to_extracted_path(tmp_path: Path):
    fw = _make_firmware(
        extracted_path=str(tmp_path),
        device_metadata=None,
    )
    assert get_primary_root(fw) == str(tmp_path)


def test_get_primary_root_returns_cached_first(tmp_path: Path):
    """Cached list trumps ``extracted_path`` (assumes cache is authoritative)."""
    cached = tmp_path / "cached_root"
    cached.mkdir()
    fw = _make_firmware(
        extracted_path=str(tmp_path / "other_root"),
        device_metadata={"detection_roots": [str(cached), "/tmp/second"]},
    )
    assert get_primary_root(fw) == str(cached)


def test_get_primary_root_falls_back_when_cache_path_missing(tmp_path: Path):
    """If cached[0] vanished on disk, fall back to ``extracted_path``."""
    fw = _make_firmware(
        extracted_path=str(tmp_path),
        device_metadata={"detection_roots": [str(tmp_path / "missing")]},
    )
    assert get_primary_root(fw) == str(tmp_path)


def test_get_primary_root_none_for_empty_row():
    fw = _make_firmware(extracted_path=None, device_metadata=None)
    assert get_primary_root(fw) is None


def test_get_primary_root_preserves_empty_string_extracted_path():
    """Edge case: extracted_path="" is returned as-is per spec."""
    fw = _make_firmware(extracted_path="", device_metadata=None)
    # Either "" or None acceptable — both signal no root.
    assert get_primary_root(fw) in ("", None)


# ---------------------------------------------------------------------------
# 10. Realpath dedup
# ---------------------------------------------------------------------------


def test_dedup_by_realpath_removes_symlink_duplicate(tmp_path: Path):
    real = tmp_path / "real_dir"
    real.mkdir()
    link = tmp_path / "link_dir"
    link.symlink_to(real, target_is_directory=True)

    out = _dedup_by_realpath([str(real), str(link)])
    # Only one entry survives — the first one wins.
    assert len(out) == 1
    assert out[0] == str(real)


def test_dedup_preserves_distinct_paths(tmp_path: Path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    out = _dedup_by_realpath([str(a), str(b)])
    assert len(out) == 2


async def test_symlink_sibling_not_double_counted(tmp_path: Path):
    """End-to-end: a rootfs/ + rootfs-sym -> rootfs layout must not
    produce two entries pointing at the same realpath."""
    extraction = tmp_path / "extracted"
    rootfs = extraction / "rootfs"
    for p in ("vendor", "system", "odm"):
        (rootfs / p).mkdir(parents=True)
    sibling_link = extraction / "rootfs-sym"
    sibling_link.symlink_to(rootfs, target_is_directory=True)

    fw = _make_firmware(extracted_path=str(rootfs))
    roots = await get_detection_roots(fw)

    reals = [_real(r) for r in roots]
    assert len(set(reals)) == len(reals), (
        f"Duplicate real paths in {roots}"
    )


# ---------------------------------------------------------------------------
# Cache persistence path
# ---------------------------------------------------------------------------


async def test_persist_writes_detection_roots_to_metadata_and_flushes(
    tmp_path: Path,
):
    """When a db session is provided, the JSONB cache gets populated."""
    _, _, _, partition = _build_dpcs10_tree(tmp_path)
    fw = _make_firmware(
        extracted_path=str(partition),
        device_metadata={"device_model": "DPCS10"},
    )
    db = AsyncMock()

    roots = await get_detection_roots(fw, db=db)

    assert roots  # sanity
    assert fw.device_metadata.get("detection_roots") == roots
    # Preserved prior key.
    assert fw.device_metadata.get("device_model") == "DPCS10"
    db.flush.assert_awaited_once()


async def test_persist_no_flush_when_db_absent(tmp_path: Path):
    """Compute-only mode: no db → no mutation of ``device_metadata``."""
    extraction = tmp_path / "extracted"
    extraction.mkdir()
    fw = _make_firmware(
        extracted_path=str(extraction),
        device_metadata={"device_model": "DPCS10"},
    )
    roots = await get_detection_roots(fw)
    assert roots == [str(extraction)]
    # No mutation.
    assert "detection_roots" not in (fw.device_metadata or {})


# ---------------------------------------------------------------------------
# Internal helper sanity (lightweight coverage for edge-cases)
# ---------------------------------------------------------------------------


def test_compute_roots_handles_only_raw_images_in_scatter(tmp_path: Path):
    """A dir that has .img/.bin files but no android siblings still gets
    promoted to a detection root."""
    extraction = tmp_path / "ext"
    scatter = extraction / "FW_4_0_1"
    scatter.mkdir(parents=True)
    (scatter / "boot.img").write_bytes(b"X" * 100)
    (scatter / "tee.img").write_bytes(b"X" * 100)

    roots = _compute_roots_sync(str(extraction))

    reals = {_real(r) for r in roots}
    assert _real(scatter) in reals


def test_compute_roots_ignores_hidden_and_cache_dirs(tmp_path: Path):
    """``.git`` and ``__pycache__`` never promoted even if they have .img."""
    extraction = tmp_path / "ext"
    extraction.mkdir()
    bogus = extraction / "__pycache__"
    bogus.mkdir()
    (bogus / "fake.img").write_bytes(b"X" * 100)
    hidden = extraction / ".git"
    hidden.mkdir()
    (hidden / "also.img").write_bytes(b"X" * 100)
    # A legit partition_* dir to ensure the walk ran.
    legit = extraction / "partition_0_raw"
    legit.mkdir()

    roots = _compute_roots_sync(str(extraction))
    reals = {_real(r) for r in roots}
    assert _real(bogus) not in reals
    assert _real(hidden) not in reals
    assert _real(legit) in reals


async def test_persist_failure_is_non_fatal(tmp_path: Path):
    """A DB flush that raises must not blow up the caller — roots still returned."""
    extraction = tmp_path / "ext"
    extraction.mkdir()
    fw = _make_firmware(
        extracted_path=str(extraction),
        device_metadata=None,
    )
    db = AsyncMock()
    db.flush.side_effect = RuntimeError("simulated connection error")

    # Should NOT raise.
    roots = await get_detection_roots(fw, db=db)
    assert roots == [str(extraction)]


# ---------------------------------------------------------------------------
# Post-scatter-relocation layout — regression guard
# ---------------------------------------------------------------------------
#
# After ``_relocate_scatter_subdirs`` runs, the scatter version subdirectory
# is empty and the firmware blobs live as direct children of
# ``extraction/``.  The detector must treat the extraction container
# itself as a walk root so those blobs surface.  Without this guard the
# helper returns only [rootfs, rootfs/partition_*], dropping ~14
# MediaTek blobs (lk.img, tee.img, gz.img, preloader*.bin, scp/sspm/
# spmfw/md1dsp/modem.img, cam_vpu*, logo.bin) from downstream detection.


def test_post_relocation_layout_includes_container(tmp_path: Path):
    """Files at ``extracted/`` top level → container is a detection root."""
    extraction = tmp_path / "extracted"
    extraction.mkdir()
    # Android rootfs with system + vendor children (valid partition-like
    # layout — proves the helper doesn't mistakenly skip the container
    # just because rootfs/ is also present).
    rootfs = extraction / "rootfs"
    (rootfs / "system").mkdir(parents=True)
    (rootfs / "vendor").mkdir()
    # Scatter version subdir — empty after relocation.
    (extraction / "DPCS10_260414-1134").mkdir()
    # Relocated firmware blobs live directly under extraction/
    for name in (
        "lk.img", "tee.img", "gz.img", "scp.img", "sspm.img",
        "spmfw.img", "md1dsp.img", "modem.img",
        "preloader_aiot8788ep1_64_bsp_k66.bin",
    ):
        (extraction / name).write_bytes(b"\x00" * 64)

    roots = _compute_roots_sync(str(rootfs))
    real_roots = _reals(roots)
    assert os.path.realpath(str(extraction)) in real_roots, (
        f"Expected extraction container as a detection root; got {roots}"
    )
    assert os.path.realpath(str(rootfs)) in real_roots, (
        f"Expected rootfs as a detection root; got {roots}"
    )


def test_linux_rootfs_only_container_not_included(tmp_path: Path):
    """Pure Linux rootfs (no raw images at extraction root) → container
    is NOT promoted.  Regression guard so the fix for the Android post-
    relocation case doesn't over-include for Linux tarballs."""
    extraction = tmp_path / "extracted"
    extraction.mkdir()
    rootfs = extraction / "rootfs"
    (rootfs / "etc").mkdir(parents=True)
    (rootfs / "bin").mkdir()
    (rootfs / "lib").mkdir()
    # No .img / .bin at the extraction top level.

    roots = _compute_roots_sync(str(rootfs))
    real_roots = _reals(roots)
    assert os.path.realpath(str(extraction)) not in real_roots, (
        f"Linux extraction container should not be promoted; got {roots}"
    )


def test_pre_relocation_scatter_subdir_still_detected(tmp_path: Path):
    """Pre-relocation layout (files still in DPCS10_*/ subdir) → the
    subdir is a detection root per ``_dir_has_raw_image`` — unchanged
    from pre-fix behaviour."""
    extraction = tmp_path / "extracted"
    extraction.mkdir()
    rootfs = extraction / "rootfs"
    (rootfs / "system").mkdir(parents=True)
    scatter = extraction / "DPCS10_260414-1134"
    scatter.mkdir()
    for name in ("lk.img", "tee.img", "gz.img"):
        (scatter / name).write_bytes(b"\x00" * 64)

    roots = _compute_roots_sync(str(rootfs))
    real_roots = _reals(roots)
    assert os.path.realpath(str(scatter)) in real_roots, (
        f"Pre-relocation scatter subdir should still be a root; got {roots}"
    )


# ---------------------------------------------------------------------------
# Pytest collection sanity marker
# ---------------------------------------------------------------------------

# asyncio_mode = "auto" in pyproject.toml, so no @pytest.mark.asyncio needed.
# Verify at least one test can still be marked explicitly without conflict.
@pytest.mark.asyncio
async def test_explicit_asyncio_marker_still_works(tmp_path: Path):
    fw = _make_firmware(extracted_path=str(tmp_path))
    roots = await get_detection_roots(fw)
    assert roots == [str(tmp_path)]
