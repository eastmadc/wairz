"""Tests for file hashing utilities."""

import hashlib
from pathlib import Path

import pytest

from app.utils.hashing import compute_file_sha256


class TestComputeFileSha256:
    """Tests for compute_file_sha256()."""

    def test_known_content_hash(self, tmp_path: Path):
        """Hash of known content matches independently computed value."""
        content = b"hello world\n"
        path = tmp_path / "known.bin"
        path.write_bytes(content)

        expected = hashlib.sha256(content).hexdigest()
        assert compute_file_sha256(str(path)) == expected

    def test_empty_file(self, tmp_path: Path):
        """Hash of an empty file matches SHA256 of empty bytes."""
        path = tmp_path / "empty.bin"
        path.write_bytes(b"")

        expected = hashlib.sha256(b"").hexdigest()
        assert compute_file_sha256(str(path)) == expected

    def test_large_file_chunked_reading(self, tmp_path: Path):
        """A file larger than the 8192-byte chunk size is hashed correctly."""
        # Create a file that spans multiple chunks (3 * 8192 = 24576 bytes)
        content = b"A" * 8192 + b"B" * 8192 + b"C" * 8192
        path = tmp_path / "large.bin"
        path.write_bytes(content)

        expected = hashlib.sha256(content).hexdigest()
        assert compute_file_sha256(str(path)) == expected

    def test_binary_content(self, tmp_path: Path):
        """Hash works correctly with arbitrary binary data."""
        content = bytes(range(256)) * 10
        path = tmp_path / "binary.bin"
        path.write_bytes(content)

        expected = hashlib.sha256(content).hexdigest()
        assert compute_file_sha256(str(path)) == expected

    def test_deterministic(self, tmp_path: Path):
        """Calling the function twice on the same file yields the same hash."""
        path = tmp_path / "deterministic.bin"
        path.write_bytes(b"test determinism")

        hash1 = compute_file_sha256(str(path))
        hash2 = compute_file_sha256(str(path))
        assert hash1 == hash2

    def test_nonexistent_file_raises(self, tmp_path: Path):
        """Attempting to hash a file that doesn't exist raises an error."""
        with pytest.raises(FileNotFoundError):
            compute_file_sha256(str(tmp_path / "no_such_file.bin"))
