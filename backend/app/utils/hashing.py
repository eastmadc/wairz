"""Shared file hashing utilities."""

import hashlib


def compute_file_sha256(file_path: str) -> str:
    """Compute SHA256 hash of a file, reading in 8192-byte chunks."""
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
    return sha.hexdigest()
