import os
from collections.abc import Iterator


class PathTraversalError(ValueError):
    """Raised when a path escapes the allowed root directory."""


def validate_path(extracted_root: str, requested_path: str) -> str:
    """Resolve and validate that path stays within extracted_root.

    Resolves symlinks relative to the firmware root (not the host filesystem).
    This is critical for firmware with absolute symlinks like /bin -> /system/bin
    which must resolve within the extracted tree, not on the host.

    Raises:
        PathTraversalError: If the resolved path escapes extracted_root.
    """
    real_root = os.path.realpath(extracted_root)

    # Resolve the path within the firmware root, handling absolute symlinks
    full_path = _resolve_within_root(real_root, requested_path)

    # Must be the root itself or under root + separator
    if full_path != real_root and not full_path.startswith(real_root + os.sep):
        raise PathTraversalError("Path traversal detected")

    return full_path


def _resolve_within_root(root: str, path: str, max_depth: int = 40) -> str:
    """Resolve a path within a chroot-like root, following symlinks.

    Unlike os.path.realpath() which resolves against the host filesystem,
    this rewrites absolute symlink targets relative to the root directory.
    For example, with root=/extracted and bin -> /system/bin, this resolves
    to /extracted/system/bin instead of the host's /system/bin.
    """
    # Normalize: strip leading /, split into components, remove . and empty
    parts = [p for p in path.strip("/").split("/") if p and p != "."]

    resolved = root
    seen: set[str] = set()  # cycle detection

    for part in parts:
        if part == "..":
            # Go up but never above root
            parent = os.path.dirname(resolved)
            if parent.startswith(root):
                resolved = parent
            else:
                raise PathTraversalError("Path traversal detected")
            continue

        candidate = os.path.join(resolved, part)

        # Check for symlink and resolve it
        depth = 0
        while os.path.islink(candidate) and depth < max_depth:
            target = os.readlink(candidate)
            if target.startswith("/"):
                # Absolute symlink — rewrite relative to root
                candidate = os.path.join(root, target.lstrip("/"))
            else:
                # Relative symlink — resolve from current directory
                candidate = os.path.normpath(os.path.join(os.path.dirname(candidate), target))

            # Cycle detection
            if candidate in seen:
                break
            seen.add(candidate)
            depth += 1

            # Ensure we haven't escaped root
            if not candidate.startswith(root + os.sep) and candidate != root:
                raise PathTraversalError("Path traversal detected")

        resolved = candidate

    return resolved


def safe_walk(
    top: str, *, followlinks: bool = True
) -> Iterator[tuple[str, list[str], list[str]]]:
    """Like os.walk() but follows symlinks safely with cycle detection.

    Firmware filesystems frequently use symlinks for standard directories
    (e.g. /bin -> /usr/bin, /lib -> /usr/lib). Plain os.walk() skips these
    entirely because followlinks defaults to False.  This wrapper enables
    followlinks and tracks visited real-directory inodes to break cycles.
    """
    visited: set[tuple[int, int]] = set()  # (dev, inode) pairs

    for dirpath, dirs, files in os.walk(top, followlinks=followlinks):
        # Check if we've already visited this real directory (cycle detection)
        try:
            st = os.stat(dirpath)
            key = (st.st_dev, st.st_ino)
            if key in visited:
                dirs.clear()  # prune — don't recurse further
                continue
            visited.add(key)
        except OSError:
            dirs.clear()
            continue

        yield dirpath, dirs, files
