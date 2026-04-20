"""Shared-library SONAME + filename version parser.

Scans ``/lib``, ``/usr/lib``, ``/lib64``, ``/usr/lib64`` recursively via
``safe_walk`` for ``.so`` files, pulls the ELF DT_SONAME via pyelftools,
and maps the library to a component via ``SONAME_COMPONENT_MAP``. When
the SONAME's trailing version looks like a bare ABI number, falls back
to reading binary content and matching ``VERSION_PATTERNS``.

Previously ``SbomService._scan_library_sonames /
_extract_version_from_library_content / _parse_library_file /
_parse_so_version`` in the ``sbom_service.py`` monolith.
"""

from __future__ import annotations

import logging
import os
import re

from elftools.elf.elffile import ELFFile

from app.services.sbom.constants import (
    CPE_VENDOR_MAP,
    MAX_BINARY_READ,
    SONAME_COMPONENT_MAP,
    VERSION_PATTERNS,
    IdentifiedComponent,
)
from app.services.sbom.normalization import is_useless_version
from app.services.sbom.purl import build_cpe, build_purl
from app.services.sbom.strategies.base import SbomStrategy, StrategyContext
from app.utils.sandbox import safe_walk

logger = logging.getLogger(__name__)


def parse_so_version(filename: str) -> tuple[str | None, str | None]:
    """Parse a .so filename into (name, version).

    Examples:
        libssl.so.1.1 -> (libssl, 1.1)
        libcrypto.so.1.1.1k -> (libcrypto, 1.1.1k)
        libc.so.6 -> (libc, 6)
        libfoo.so -> (libfoo, None)
    """
    # Match libXXX.so.VERSION
    match = re.match(r"^(lib[\w+-]+)\.so\.(.+)$", filename)
    if match:
        name = match.group(1)
        version = match.group(2)
        return name, version

    # Match libXXX.so (no version)
    match = re.match(r"^(lib[\w+-]+)\.so$", filename)
    if match:
        return match.group(1), None

    # Match libXXX-VERSION.so
    match = re.match(r"^(lib[\w+-]+)-(\d[\d.]+\w*)\.so$", filename)
    if match:
        return match.group(1), match.group(2)

    return None, None


def parse_library_file(abs_path: str) -> dict | None:
    """Extract component name and version from a shared library file.

    Returns a dict with ``name``, ``version``, ``soname`` keys, or None
    if the file isn't a parseable ELF library.
    """
    basename = os.path.basename(abs_path)

    # Try to get SONAME from ELF
    soname: str | None = None
    try:
        with open(abs_path, "rb") as f:
            magic = f.read(4)
            if magic != b"\x7fELF":
                return None
            f.seek(0)
            elf = ELFFile(f)
            for seg in elf.iter_segments():
                if seg.header.p_type == "PT_DYNAMIC":
                    for tag in seg.iter_tags():
                        if tag.entry.d_tag == "DT_SONAME":
                            soname = tag.soname
                    break
    except Exception as exc:
        # Malformed ELF, truncated file, pyelftools bug, etc. We still
        # fall back to filename parsing at the call site, so a quiet
        # failure here is expected — but unusual libraries trip this
        # often enough that a debug log helps diagnose false negatives.
        logger.debug("SONAME ELF parse failed for %s: %s", abs_path, exc)
        return None

    # Parse version from filename: libfoo.so.1.2.3 -> name=libfoo, version=1.2.3
    name, version = parse_so_version(soname or basename)
    if not name:
        return None

    # Map library name to component name
    component_name = SONAME_COMPONENT_MAP.get(name, name)

    return {
        "name": component_name,
        "version": version,
        "soname": soname or basename,
    }


def extract_version_from_library_content(
    abs_path: str,
    component_name: str,
) -> str | None:
    """Read a library binary and match VERSION_PATTERNS for its component."""
    try:
        with open(abs_path, "rb") as f:
            data = f.read(MAX_BINARY_READ)
    except OSError:
        return None

    name_lower = component_name.lower()
    for pattern_name, pattern in VERSION_PATTERNS:
        if pattern_name.lower() != name_lower:
            continue
        m = pattern.search(data)
        if m:
            return m.group(1).decode("ascii", errors="replace")
    return None


class SoFilesStrategy(SbomStrategy):
    """Scan shared library files for SONAME + version information.

    Uses safe_walk() for recursive scanning so libraries in
    subdirectories (e.g. /lib/ipsec/, /usr/lib/lua/) are found. When a
    library has a useless version (single digit like "6"), falls back
    to reading binary content for a real version string.
    """

    name = "so_files"

    _LIB_DIRS = ("/lib", "/usr/lib", "/lib64", "/usr/lib64")

    def run(self, ctx: StrategyContext) -> None:
        seen_libs: set[str] = set()

        for lib_dir in self._LIB_DIRS:
            abs_dir = ctx.abs_path(lib_dir)
            if not os.path.isdir(abs_dir):
                continue

            for dirpath, _dirs, files in safe_walk(abs_dir):
                # Stay inside the extracted root
                if not dirpath.startswith(ctx.extracted_root):
                    continue

                for entry in files:
                    if ".so" not in entry:
                        continue
                    abs_path = os.path.join(dirpath, entry)
                    if not os.path.isfile(abs_path):
                        continue
                    # Skip symlinks to avoid double-counting
                    if os.path.islink(abs_path):
                        continue

                    dir_rel = "/" + os.path.relpath(dirpath, ctx.extracted_root)
                    file_rel = f"{dir_rel}/{entry}"

                    lib_info = parse_library_file(abs_path)
                    if not lib_info or lib_info["name"] in seen_libs:
                        continue

                    version = lib_info["version"]
                    component_name = lib_info["name"]

                    # If the version is useless, try to extract from binary
                    # content. If content extraction also fails, skip —
                    # a dedicated scanner or the binary string scanner
                    # will find the real version.
                    if is_useless_version(version):
                        content_version = extract_version_from_library_content(
                            abs_path, component_name
                        )
                        if content_version:
                            version = content_version
                        else:
                            continue

                    seen_libs.add(component_name)
                    vendor_product = CPE_VENDOR_MAP.get(component_name.lower())
                    cpe = None
                    if vendor_product:
                        cpe = build_cpe(
                            vendor_product[0], vendor_product[1], version
                        )

                    comp = IdentifiedComponent(
                        name=component_name,
                        version=version,
                        type="library",
                        cpe=cpe,
                        purl=build_purl(component_name, version),
                        supplier=vendor_product[0] if vendor_product else None,
                        detection_source="library_soname",
                        detection_confidence="high",
                        file_paths=[file_rel],
                        metadata={"soname": lib_info.get("soname", "")},
                    )
                    ctx.store.add(comp)
