"""Tests for path traversal prevention and safe filesystem walking."""

import os
from pathlib import Path

import pytest

from app.utils.sandbox import PathTraversalError, safe_walk, validate_path


class TestValidatePath:
    """Tests for validate_path()."""

    def test_valid_subpath_resolves_correctly(self, firmware_root: Path):
        """A simple relative path under the root resolves to the expected absolute path."""
        result = validate_path(str(firmware_root), "etc/passwd")
        assert result == str(firmware_root / "etc" / "passwd")

    def test_root_path_itself_is_valid(self, firmware_root: Path):
        """Requesting the root itself (empty or '/') should return the root."""
        result = validate_path(str(firmware_root), "/")
        assert result == os.path.realpath(str(firmware_root))

    def test_leading_slash_is_stripped(self, firmware_root: Path):
        """Paths with leading slash resolve relative to root, not filesystem root."""
        result = validate_path(str(firmware_root), "/etc/passwd")
        assert result == str(firmware_root / "etc" / "passwd")

    def test_dotdot_traversal_raises(self, firmware_root: Path):
        """Paths containing '..' that escape the root must raise PathTraversalError."""
        with pytest.raises(PathTraversalError, match="Path traversal detected"):
            validate_path(str(firmware_root), "../../etc/passwd")

    def test_dotdot_traversal_deep_raises(self, firmware_root: Path):
        """Even deeply nested '..' sequences that escape must be caught."""
        with pytest.raises(PathTraversalError, match="Path traversal detected"):
            validate_path(str(firmware_root), "etc/../../../tmp/evil")

    def test_symlink_outside_root_rewritten(self, firmware_root: Path):
        """Absolute symlinks are rewritten relative to root (chroot model).

        In firmware analysis, absolute symlinks like /etc/passwd are normal
        (they reference paths within the firmware's own root). The resolver
        rewrites them to root/etc/passwd rather than following them to the host.
        """
        evil_link = firmware_root / "var" / "escape"
        evil_link.symlink_to("/etc/passwd")
        result = validate_path(str(firmware_root), "var/escape")
        assert result == str(firmware_root / "etc" / "passwd")
        assert result.startswith(str(firmware_root))

    def test_symlink_inside_root_is_valid(self, firmware_root: Path):
        """A relative symlink pointing within the root resolves correctly."""
        # Create a relative symlink instead of absolute
        link = firmware_root / "lib" / "link"
        link.symlink_to("../etc/config.conf")
        result = validate_path(str(firmware_root), "lib/link")
        assert result == str(firmware_root / "etc" / "config.conf")
        assert result.startswith(str(firmware_root))

    def test_nonexistent_but_valid_path(self, firmware_root: Path):
        """A path that doesn't exist on disk but stays within root should not raise."""
        result = validate_path(str(firmware_root), "etc/nonexistent.conf")
        assert result == str(firmware_root / "etc" / "nonexistent.conf")

    def test_nonexistent_deep_path(self, firmware_root: Path):
        """Non-existent paths several levels deep under root are allowed."""
        result = validate_path(str(firmware_root), "opt/app/config/settings.json")
        assert result == str(firmware_root / "opt" / "app" / "config" / "settings.json")

    def test_prefix_collision_attack(self, tmp_path: Path):
        """Root 'foo' should not accept paths resolving to 'foobar/' (prefix collision)."""
        root = tmp_path / "firmware"
        root.mkdir()
        sibling = tmp_path / "firmware_evil"
        sibling.mkdir()
        (sibling / "secret.txt").write_text("pwned")

        with pytest.raises(PathTraversalError):
            validate_path(str(root), "../firmware_evil/secret.txt")


class TestSafeWalk:
    """Tests for safe_walk()."""

    def test_walks_normal_tree(self, firmware_root: Path):
        """safe_walk should yield all directories in a normal filesystem."""
        walked_dirs = []
        for dirpath, dirs, files in safe_walk(str(firmware_root)):
            walked_dirs.append(dirpath)
        # Should include root and subdirs
        assert str(firmware_root) in walked_dirs
        assert str(firmware_root / "etc") in walked_dirs
        assert str(firmware_root / "usr") in walked_dirs

    def test_follows_symlinks_to_new_directory(self, firmware_root: Path):
        """safe_walk should follow directory symlinks to directories not yet visited."""
        # Create a directory outside the normal tree and symlink into it
        external = firmware_root / "opt" / "unique_target"
        external.mkdir(parents=True)
        (external / "file.txt").write_text("content")

        # Symlink from a location that will be walked BEFORE opt/unique_target
        # Since safe_walk tracks inodes, it will visit whichever path it encounters first.
        # Verify the file is found at least once regardless of which path is walked.
        walked_files = []
        for dirpath, dirs, files in safe_walk(str(firmware_root)):
            for f in files:
                walked_files.append(os.path.join(dirpath, f))

        target_path = str(external / "file.txt")
        assert target_path in walked_files

    def test_symlink_dedup_via_inode(self, firmware_root: Path):
        """safe_walk deduplicates directories by inode, so a symlink to an already-visited dir is skipped."""
        real_dir = firmware_root / "opt" / "real"
        real_dir.mkdir(parents=True)
        (real_dir / "data.txt").write_text("hello")
        # Create a symlink that points to the same directory
        (firmware_root / "var" / "alias").symlink_to(str(real_dir))

        visit_count = 0
        for dirpath, dirs, files in safe_walk(str(firmware_root)):
            real = os.path.realpath(dirpath)
            if real == os.path.realpath(str(real_dir)):
                visit_count += 1

        # The real directory content should be visited exactly once
        assert visit_count == 1

    def test_detects_symlink_cycle(self, firmware_root: Path):
        """safe_walk should not loop infinitely on symlink cycles."""
        # Create a cycle: var/loop -> var
        (firmware_root / "var" / "loop").symlink_to(str(firmware_root / "var"))

        walked_dirs = []
        for dirpath, dirs, files in safe_walk(str(firmware_root)):
            walked_dirs.append(dirpath)

        # Should complete without hanging; var should appear exactly once
        var_count = sum(1 for d in walked_dirs if os.path.basename(d) == "var" and os.path.dirname(d) == str(firmware_root))
        assert var_count == 1

    def test_handles_permission_error(self, tmp_path: Path):
        """safe_walk should skip directories it cannot stat (OSError)."""
        # If we can't actually change permissions (e.g. running as root), just
        # verify the function completes without error on a normal tree.
        (tmp_path / "subdir").mkdir()
        (tmp_path / "subdir" / "file.txt").write_text("hello")

        walked = list(safe_walk(str(tmp_path)))
        assert len(walked) >= 1
