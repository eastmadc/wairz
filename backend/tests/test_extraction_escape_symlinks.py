"""Regression tests for remove_extraction_escape_symlinks().

Guards the PowerPack_40.5.1.bin bug where binwalk3 -e -C planted a
symlink in the extraction dir pointing back at the uploaded firmware.
``find_filesystem_root`` saw "1 file" and marked extraction successful;
the sandbox then 404'd the file because the absolute symlink target
was outside the extracted tree.  The function under test strips these
noise artifacts WITHOUT disturbing rootfs-internal symlinks.

Scenarios:
    1. Escape symlink to sibling file is removed.
    2. Escape symlink to outside path (e.g. /etc/passwd) is removed.
    3. Broken symlink (target missing) is removed.
    4. Rootfs-internal absolute symlink (bin -> /usr/bin inside the
       tree) is preserved — deeper than top level, never touched.
    5. Regular files and dirs at top level are preserved.
    6. binwalk3 ``<input>.extracted/`` subdirectory is preserved
       (it's a dir, not a symlink).
    7. Symlink whose realpath equals extraction_dir itself is
       preserved (degenerate case — shouldn't escape).
    8. Called on empty or missing dir returns 0 without raising.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from app.workers.unpack_common import remove_extraction_escape_symlinks


class TestEscapeSymlinkRemoval:
    def test_escape_symlink_to_sibling_is_removed(self, tmp_path: Path) -> None:
        extraction = tmp_path / "extracted"
        extraction.mkdir()
        # A real file OUTSIDE the extraction dir
        outside = tmp_path / "original.bin"
        outside.write_bytes(b"original firmware content")
        # A symlink INSIDE extraction pointing at it — exactly the
        # binwalk3 pattern.
        (extraction / "original.bin").symlink_to(outside)

        removed = remove_extraction_escape_symlinks(str(extraction))

        assert removed == 1
        assert not (extraction / "original.bin").exists()
        # The outside file itself must not be touched.
        assert outside.exists()

    def test_escape_symlink_to_host_path_is_removed(self, tmp_path: Path) -> None:
        extraction = tmp_path / "extracted"
        extraction.mkdir()
        (extraction / "passwd").symlink_to("/etc/passwd")

        removed = remove_extraction_escape_symlinks(str(extraction))

        assert removed == 1
        assert not (extraction / "passwd").exists()

    def test_broken_symlink_is_removed(self, tmp_path: Path) -> None:
        extraction = tmp_path / "extracted"
        extraction.mkdir()
        (extraction / "dangling").symlink_to(tmp_path / "nonexistent.bin")

        removed = remove_extraction_escape_symlinks(str(extraction))

        assert removed == 1
        assert not (extraction / "dangling").exists()


class TestLegitimateContentPreserved:
    def test_rootfs_internal_symlink_preserved(self, tmp_path: Path) -> None:
        """/bin -> /usr/bin style absolute symlinks INSIDE the rootfs
        must NOT be touched.  We only scan the top level."""
        extraction = tmp_path / "extracted"
        rootfs = extraction / "rootfs"
        usr_bin = rootfs / "usr" / "bin"
        usr_bin.mkdir(parents=True)
        (usr_bin / "sh").write_bytes(b"\x7fELF" + b"\x00" * 12)
        # Internal symlink — absolute but resolves inside rootfs
        (rootfs / "bin").symlink_to("/usr/bin")

        removed = remove_extraction_escape_symlinks(str(extraction))

        assert removed == 0
        # Top-level rootfs dir is preserved
        assert rootfs.is_dir()
        # Internal symlink survives
        assert (rootfs / "bin").is_symlink()

    def test_regular_files_and_dirs_preserved(self, tmp_path: Path) -> None:
        """Regular content at the top level must be untouched — this
        covers the Android scatter-extraction case (CLAUDE.md rule #18)
        where .img files sit at the top level of extraction_dir after
        _relocate_scatter_subdirs moves them."""
        extraction = tmp_path / "extracted"
        extraction.mkdir()
        (extraction / "modem.img").write_bytes(b"\xaa" * 1024)
        (extraction / "md1dsp.img").write_bytes(b"\xbb" * 512)
        (extraction / "boot").mkdir()
        (extraction / "boot" / "kernel").write_bytes(b"\xcc" * 256)

        removed = remove_extraction_escape_symlinks(str(extraction))

        assert removed == 0
        assert (extraction / "modem.img").exists()
        assert (extraction / "md1dsp.img").exists()
        assert (extraction / "boot" / "kernel").exists()

    def test_binwalk_extracted_subdir_preserved(self, tmp_path: Path) -> None:
        """binwalk3's real output is ``<input>.extracted/`` — a
        directory with genuine carved content.  We remove only the
        top-level symlink; the subdir stays."""
        extraction = tmp_path / "extracted"
        extraction.mkdir()
        outside = tmp_path / "mixed.bin"
        outside.write_bytes(b"\x1f\x8b" + b"\x00" * 128)

        # binwalk3 planted both artifacts
        (extraction / "mixed.bin").symlink_to(outside)
        carved_dir = extraction / "mixed.bin.extracted" / "400"
        carved_dir.mkdir(parents=True)
        (carved_dir / "decompressed.bin").write_bytes(b"real content")

        removed = remove_extraction_escape_symlinks(str(extraction))

        assert removed == 1
        # Symlink gone
        assert not (extraction / "mixed.bin").exists()
        # Real carved content preserved
        assert (carved_dir / "decompressed.bin").exists()
        assert (carved_dir / "decompressed.bin").read_bytes() == b"real content"

    def test_symlink_pointing_into_extraction_preserved(self, tmp_path: Path) -> None:
        """A symlink inside extraction_dir whose target is ALSO inside
        extraction_dir is legitimate content (e.g. a rootfs
        convenience link) — must not be removed.  Guards against an
        over-zealous predicate that catches intra-root absolute
        symlinks."""
        extraction = tmp_path / "extracted"
        extraction.mkdir()
        (extraction / "real.bin").write_bytes(b"\x7fELF" + b"\x00" * 12)
        (extraction / "alias.bin").symlink_to(extraction / "real.bin")

        removed = remove_extraction_escape_symlinks(str(extraction))

        assert removed == 0
        assert (extraction / "real.bin").exists()
        assert (extraction / "alias.bin").is_symlink()


class TestEdgeCases:
    def test_empty_dir_returns_zero(self, tmp_path: Path) -> None:
        extraction = tmp_path / "extracted"
        extraction.mkdir()
        assert remove_extraction_escape_symlinks(str(extraction)) == 0

    def test_missing_dir_returns_zero(self, tmp_path: Path) -> None:
        missing = tmp_path / "does_not_exist"
        assert remove_extraction_escape_symlinks(str(missing)) == 0

    def test_idempotent_on_clean_tree(self, tmp_path: Path) -> None:
        extraction = tmp_path / "extracted"
        rootfs = extraction / "rootfs"
        rootfs.mkdir(parents=True)
        (rootfs / "a").write_bytes(b"x")
        # First call — no escape symlinks
        assert remove_extraction_escape_symlinks(str(extraction)) == 0
        # Second call — still no escape symlinks
        assert remove_extraction_escape_symlinks(str(extraction)) == 0
        assert (rootfs / "a").exists()

    def test_powerpack_repro(self, tmp_path: Path) -> None:
        """End-to-end repro of the PowerPack bug shape.

        Simulates the DB state snapshot: a firmware upload dir with a
        large sibling file and an `extracted/` dir that contains only
        the binwalk3-planted symlink pointing at that file.  After
        the fix, the cleanup empties the extraction dir so
        find_filesystem_root's fallback won't falsely succeed.
        """
        fw_dir = tmp_path / "projects" / "p1" / "firmware" / "f1"
        fw_dir.mkdir(parents=True)
        original = fw_dir / "PowerPack_40.5.1_EGIA_EEA_Release.bin"
        original.write_bytes(b"\x00" * (1024 * 1024))  # 1 MB stand-in

        extraction = fw_dir / "extracted"
        extraction.mkdir()
        (extraction / original.name).symlink_to(original)

        # Precondition: the bug-triggering artifact exists
        assert (extraction / original.name).is_symlink()

        removed = remove_extraction_escape_symlinks(str(extraction))

        assert removed == 1
        # Post-fix: extraction dir is now empty — find_filesystem_root
        # will return None and _analyze_filesystem will correctly set
        # result.error instead of claiming success.
        assert list(extraction.iterdir()) == []
        # Original upload untouched
        assert original.exists()


@pytest.mark.parametrize("count", [0, 1, 5])
def test_returns_accurate_count(tmp_path: Path, count: int) -> None:
    extraction = tmp_path / "extracted"
    extraction.mkdir()
    outside = tmp_path / "sidecar.bin"
    outside.write_bytes(b"x")
    for i in range(count):
        (extraction / f"link_{i}").symlink_to(outside)

    assert remove_extraction_escape_symlinks(str(extraction)) == count
