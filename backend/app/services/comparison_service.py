"""Service for comparing firmware versions — filesystem and binary diffing."""

import os
from dataclasses import dataclass, field

from app.utils.hashing import compute_file_sha256
from app.utils.sandbox import safe_walk


MAX_DIFF_ENTRIES = 500


@dataclass
class FileDiffEntry:
    """A single file difference between two firmware versions."""

    path: str
    status: str  # "added", "removed", "modified", "permissions_changed"
    size_a: int | None = None
    size_b: int | None = None
    perms_a: str | None = None
    perms_b: str | None = None


@dataclass
class FirmwareDiff:
    """Result of comparing two firmware filesystem trees."""

    added: list[FileDiffEntry] = field(default_factory=list)
    removed: list[FileDiffEntry] = field(default_factory=list)
    modified: list[FileDiffEntry] = field(default_factory=list)
    permissions_changed: list[FileDiffEntry] = field(default_factory=list)
    total_files_a: int = 0
    total_files_b: int = 0
    truncated: bool = False


@dataclass
class FunctionDiffEntry:
    """A function-level difference between two binaries."""

    name: str
    status: str  # "added", "removed", "modified"
    size_a: int | None = None
    size_b: int | None = None


@dataclass
class BinaryDiff:
    """Result of comparing two versions of a binary."""

    binary_path: str
    functions_added: list[FunctionDiffEntry] = field(default_factory=list)
    functions_removed: list[FunctionDiffEntry] = field(default_factory=list)
    functions_modified: list[FunctionDiffEntry] = field(default_factory=list)
    info_a: dict = field(default_factory=dict)
    info_b: dict = field(default_factory=dict)


def _file_sha256(path: str) -> str | None:
    """Compute SHA256 hash of a file, returning None on error."""
    try:
        return compute_file_sha256(path)
    except (OSError, PermissionError):
        return None


def _get_perms(path: str) -> str:
    """Get file permissions as octal string."""
    try:
        return oct(os.stat(path).st_mode)[-4:]
    except OSError:
        return "????"


def _scan_tree(root: str) -> dict[str, tuple[str | None, int, str]]:
    """Walk a filesystem tree and return {rel_path: (sha256, size, perms)} for files."""
    real_root = os.path.realpath(root)
    result: dict[str, tuple[str | None, int, str]] = {}

    for dirpath, _dirs, files in safe_walk(root):
        for name in files:
            abs_path = os.path.join(dirpath, name)
            rel_path = "/" + os.path.relpath(abs_path, real_root)

            try:
                stat = os.stat(abs_path)
                size = stat.st_size
            except OSError:
                continue

            sha = _file_sha256(abs_path)
            perms = _get_perms(abs_path)
            result[rel_path] = (sha, size, perms)

    return result


def diff_filesystems(root_a: str, root_b: str) -> FirmwareDiff:
    """Compare two extracted firmware filesystem trees.

    Returns categorized differences: added, removed, modified, permissions_changed.
    """
    tree_a = _scan_tree(root_a)
    tree_b = _scan_tree(root_b)

    paths_a = set(tree_a.keys())
    paths_b = set(tree_b.keys())

    result = FirmwareDiff(
        total_files_a=len(tree_a),
        total_files_b=len(tree_b),
    )

    # Truncate per category so one large category doesn't starve the others
    # Added files (in B but not in A)
    for path in sorted(paths_b - paths_a):
        if len(result.added) >= MAX_DIFF_ENTRIES:
            result.truncated = True
            break
        sha_b, size_b, perms_b = tree_b[path]
        result.added.append(FileDiffEntry(
            path=path, status="added", size_b=size_b, perms_b=perms_b,
        ))

    # Removed files (in A but not in B)
    for path in sorted(paths_a - paths_b):
        if len(result.removed) >= MAX_DIFF_ENTRIES:
            result.truncated = True
            break
        sha_a, size_a, perms_a = tree_a[path]
        result.removed.append(FileDiffEntry(
            path=path, status="removed", size_a=size_a, perms_a=perms_a,
        ))

    # Common files — check for modifications
    for path in sorted(paths_a & paths_b):
        if len(result.modified) >= MAX_DIFF_ENTRIES and len(result.permissions_changed) >= MAX_DIFF_ENTRIES:
            result.truncated = True
            break
        sha_a, size_a, perms_a = tree_a[path]
        sha_b, size_b, perms_b = tree_b[path]

        content_changed = (sha_a != sha_b) and sha_a is not None and sha_b is not None
        perm_changed = perms_a != perms_b

        if content_changed and len(result.modified) < MAX_DIFF_ENTRIES:
            result.modified.append(FileDiffEntry(
                path=path, status="modified",
                size_a=size_a, size_b=size_b,
                perms_a=perms_a, perms_b=perms_b,
            ))
        elif perm_changed and len(result.permissions_changed) < MAX_DIFF_ENTRIES:
            result.permissions_changed.append(FileDiffEntry(
                path=path, status="permissions_changed",
                size_a=size_a, size_b=size_b,
                perms_a=perms_a, perms_b=perms_b,
            ))

    return result


def diff_binary(binary_a_path: str, binary_b_path: str, binary_rel_path: str) -> BinaryDiff:
    """Compare two versions of the same ELF binary at the function level.

    Uses pyelftools to extract function symbols and compare sets.
    """
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection

    result = BinaryDiff(binary_path=binary_rel_path)

    # Always extract basic info (file size, arch, etc.)
    result.info_a = _extract_binary_info(binary_a_path)
    result.info_b = _extract_binary_info(binary_b_path)

    # Compute file hashes for comparison
    sha_a = _file_sha256(binary_a_path)
    sha_b = _file_sha256(binary_b_path)
    result.info_a["sha256"] = sha_a
    result.info_b["sha256"] = sha_b
    result.info_a["identical"] = sha_a == sha_b

    funcs_a = _extract_functions(binary_a_path)
    funcs_b = _extract_functions(binary_b_path)

    if funcs_a is None or funcs_b is None:
        result.info_a["stripped"] = funcs_a is None or len(funcs_a) == 0
        result.info_b["stripped"] = funcs_b is None or len(funcs_b) == 0
        return result

    names_a = set(funcs_a.keys())
    names_b = set(funcs_b.keys())

    # Added functions
    for name in sorted(names_b - names_a):
        result.functions_added.append(FunctionDiffEntry(
            name=name, status="added", size_b=funcs_b[name],
        ))

    # Removed functions
    for name in sorted(names_a - names_b):
        result.functions_removed.append(FunctionDiffEntry(
            name=name, status="removed", size_a=funcs_a[name],
        ))

    # Modified functions (size changed)
    for name in sorted(names_a & names_b):
        size_a = funcs_a[name]
        size_b = funcs_b[name]
        if size_a != size_b:
            result.functions_modified.append(FunctionDiffEntry(
                name=name, status="modified", size_a=size_a, size_b=size_b,
            ))

    return result


MAX_TEXT_DIFF_SIZE = 512 * 1024  # 512 KB per file for text diffing

# Extensions commonly containing readable/diffable content in firmware
_TEXT_EXTENSIONS = frozenset({
    ".conf", ".cfg", ".ini", ".json", ".xml", ".yaml", ".yml",
    ".sh", ".ash", ".bash", ".csh", ".lua", ".py", ".pl", ".rb",
    ".html", ".htm", ".css", ".js", ".php", ".cgi",
    ".txt", ".log", ".md", ".csv", ".tsv",
    ".service", ".timer", ".mount", ".socket", ".target",
    ".rules", ".pem", ".crt", ".key",
})

# Paths that are always interesting for firmware comparison
_TEXT_PATH_PATTERNS = (
    "/etc/", "/usr/share/", "/www/", "/opt/",
    "init.d/", "rc.d/", "crontab",
)


def is_diffable_text(path: str, abs_path: str) -> bool:
    """Check if a file is likely a text file worth diffing."""
    _, ext = os.path.splitext(path.lower())
    if ext in _TEXT_EXTENSIONS:
        return True
    if any(p in path for p in _TEXT_PATH_PATTERNS):
        # Check if it's actually text by reading first bytes
        try:
            with open(abs_path, "rb") as f:
                chunk = f.read(512)
                if b"\x00" in chunk:
                    return False
                return True
        except OSError:
            return False
    return False


def diff_text_file(path_a: str, path_b: str, rel_path: str) -> dict:
    """Generate a unified diff between two text files.

    Returns a dict with the diff lines and metadata.
    """
    import difflib

    result: dict = {
        "path": rel_path,
        "diff": "",
        "lines_added": 0,
        "lines_removed": 0,
        "truncated": False,
        "error": None,
    }

    try:
        size_a = os.path.getsize(path_a) if os.path.exists(path_a) else 0
        size_b = os.path.getsize(path_b) if os.path.exists(path_b) else 0

        if size_a > MAX_TEXT_DIFF_SIZE or size_b > MAX_TEXT_DIFF_SIZE:
            result["error"] = f"File too large for text diff ({max(size_a, size_b)} bytes)"
            return result

        lines_a: list[str] = []
        lines_b: list[str] = []

        if os.path.exists(path_a):
            with open(path_a, "r", errors="replace") as f:
                lines_a = f.readlines()

        if os.path.exists(path_b):
            with open(path_b, "r", errors="replace") as f:
                lines_b = f.readlines()

        diff_lines = list(difflib.unified_diff(
            lines_a, lines_b,
            fromfile=f"a{rel_path}",
            tofile=f"b{rel_path}",
            lineterm="",
        ))

        # Count additions and removals (skip header lines)
        for line in diff_lines[2:]:
            if line.startswith("+") and not line.startswith("+++"):
                result["lines_added"] += 1
            elif line.startswith("-") and not line.startswith("---"):
                result["lines_removed"] += 1

        # Truncate if diff is very large
        if len(diff_lines) > 500:
            diff_lines = diff_lines[:500]
            diff_lines.append("\n... diff truncated (500 lines shown) ...")
            result["truncated"] = True

        result["diff"] = "\n".join(diff_lines)

    except Exception as e:
        result["error"] = str(e)

    return result


def _extract_functions(binary_path: str) -> dict[str, int] | None:
    """Extract function names and sizes from an ELF binary.

    Returns {function_name: size} or None if parsing fails.
    """
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection

    try:
        with open(binary_path, "rb") as f:
            elf = ELFFile(f)
            functions: dict[str, int] = {}

            for section_name in (".symtab", ".dynsym"):
                section = elf.get_section_by_name(section_name)
                if section and isinstance(section, SymbolTableSection):
                    for sym in section.iter_symbols():
                        if (sym.entry.st_info.type == "STT_FUNC"
                                and sym.name
                                and sym.entry.st_shndx != "SHN_UNDEF"
                                and sym.entry.st_size > 0):
                            functions[sym.name] = sym.entry.st_size

            return functions
    except Exception:
        return None


def _extract_binary_info(binary_path: str) -> dict:
    """Extract basic binary metadata."""
    from elftools.elf.elffile import ELFFile

    try:
        info: dict = {}
        stat = os.stat(binary_path)
        info["file_size"] = stat.st_size

        with open(binary_path, "rb") as f:
            elf = ELFFile(f)
            info["arch"] = elf.header.e_machine
            info["bits"] = elf.elfclass
            info["endian"] = "little" if elf.little_endian else "big"

        return info
    except Exception:
        return {"file_size": os.path.getsize(binary_path) if os.path.exists(binary_path) else 0}
