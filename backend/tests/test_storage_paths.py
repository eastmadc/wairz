"""Tests for the containment-checked storage purge primitive.

The primitive is the only sanctioned way wairz removes firmware bytes,
so its refusal behaviour is security-relevant (CLAUDE.md Security #1 —
realpath BOTH sides before comparing, so a symlink planted inside the
storage root cannot redirect an rmtree outside it).
"""

from __future__ import annotations

import os
import uuid

import pytest

from app.services.storage_paths import (
    firmware_storage_dir,
    project_storage_dir,
    purge_dir_within_root,
    purge_dir_within_root_sync,
)


def test_project_storage_dir_shape():
    pid = uuid.uuid4()
    assert project_storage_dir("/data/firmware", pid) == f"/data/firmware/projects/{pid}"


def test_firmware_storage_dir_shape():
    pid, fid = uuid.uuid4(), uuid.uuid4()
    assert firmware_storage_dir("/data/firmware", pid, fid) == (
        f"/data/firmware/projects/{pid}/firmware/{fid}"
    )


def test_purge_removes_directory_inside_root(tmp_path):
    root = tmp_path / "storage"
    target = root / "projects" / "abc"
    target.mkdir(parents=True)
    (target / "payload.bin").write_bytes(b"x" * 32)

    assert purge_dir_within_root_sync(str(root), str(target)) is True
    assert not target.exists()


def test_purge_missing_directory_is_a_noop(tmp_path):
    root = tmp_path / "storage"
    root.mkdir()
    assert purge_dir_within_root_sync(str(root), str(root / "nope")) is False


def test_purge_refuses_the_storage_root_itself(tmp_path):
    root = tmp_path / "storage"
    root.mkdir()
    with pytest.raises(ValueError, match="outside storage root"):
        purge_dir_within_root_sync(str(root), str(root))
    assert root.exists()


def test_purge_refuses_path_outside_root(tmp_path):
    root = tmp_path / "storage"
    root.mkdir()
    outside = tmp_path / "precious"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep me")

    with pytest.raises(ValueError, match="outside storage root"):
        purge_dir_within_root_sync(str(root), str(outside))
    assert (outside / "keep.txt").exists()


def test_purge_refuses_traversal_escape(tmp_path):
    root = tmp_path / "storage"
    root.mkdir()
    outside = tmp_path / "precious"
    outside.mkdir()

    escape = os.path.join(str(root), "projects", "..", "..", "precious")
    with pytest.raises(ValueError, match="outside storage root"):
        purge_dir_within_root_sync(str(root), escape)
    assert outside.exists()


def test_purge_refuses_symlink_pointing_outside_root(tmp_path):
    """A symlink planted INSIDE the root must not redirect the rmtree.

    This is the realpath-both-sides contract: the link resolves outside,
    so the purge is refused even though the literal path is inside.
    """
    root = tmp_path / "storage"
    (root / "projects").mkdir(parents=True)
    outside = tmp_path / "precious"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep me")

    link = root / "projects" / "evil"
    link.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="outside storage root"):
        purge_dir_within_root_sync(str(root), str(link))
    assert (outside / "keep.txt").exists()


@pytest.mark.asyncio
async def test_async_wrapper_matches_sync(tmp_path):
    root = tmp_path / "storage"
    target = root / "projects" / "abc"
    target.mkdir(parents=True)
    assert await purge_dir_within_root(str(root), str(target)) is True
    assert await purge_dir_within_root(str(root), str(target)) is False
