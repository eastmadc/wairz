"""ELF binary string-based version detection.

Walks ``/bin``, ``/sbin``, ``/usr/bin``, ``/usr/sbin`` and matches
``VERSION_PATTERNS`` against extracted printable strings. Caps total
scanned binaries at ``MAX_BINARIES_SCAN`` to bound runtime on large
firmware.

Also includes a "generic" fallback that matches ``{binary_name}
{semver}`` pairs when no curated pattern hits — primarily for oddball
daemons like ``rssh``.

Previously ``SbomService._scan_binary_version_strings /
_scan_binary_strings / _try_generic_binary_detection /
_extract_printable_strings`` in the ``sbom_service.py`` monolith.
"""

from __future__ import annotations

import logging
import os
import re

from app.services.sbom.constants import (
    CPE_VENDOR_MAP,
    GENERIC_EXCLUDE_NAMES,
    MAX_BINARIES_SCAN,
    MAX_BINARY_READ,
    VERSION_PATTERNS,
    IdentifiedComponent,
)
from app.services.sbom.normalization import ComponentStore
from app.services.sbom.purl import build_cpe, build_purl
from app.services.sbom.strategies.base import SbomStrategy, StrategyContext

logger = logging.getLogger(__name__)


def extract_printable_strings(
    data: bytes,
    min_length: int = 4,
) -> list[bytes]:
    """Extract printable ASCII strings from binary data."""
    strings = []
    current = bytearray()
    for byte in data:
        if 0x20 <= byte < 0x7F:
            current.append(byte)
        else:
            if len(current) >= min_length:
                strings.append(bytes(current))
            current = bytearray()
    if len(current) >= min_length:
        strings.append(bytes(current))
    return strings


class BinaryStringsStrategy(SbomStrategy):
    """Extract versions from /bin, /sbin, /usr/bin, /usr/sbin ELF binaries."""

    name = "binary_strings"

    _BIN_DIRS = ("/bin", "/sbin", "/usr/bin", "/usr/sbin")

    def run(self, ctx: StrategyContext) -> None:
        scanned = 0

        for bin_dir in self._BIN_DIRS:
            abs_dir = ctx.abs_path(bin_dir)
            if not os.path.isdir(abs_dir):
                continue
            try:
                entries = os.listdir(abs_dir)
            except OSError:
                continue

            for entry in sorted(entries):
                if scanned >= MAX_BINARIES_SCAN:
                    return

                abs_path = os.path.join(abs_dir, entry)
                if not os.path.isfile(abs_path):
                    continue
                # Skip symlinks
                if os.path.islink(abs_path):
                    continue

                # Quick ELF check
                try:
                    with open(abs_path, "rb") as f:
                        if f.read(4) != b"\x7fELF":
                            continue
                except OSError:
                    continue

                scanned += 1
                self._scan_binary(abs_path, f"{bin_dir}/{entry}", ctx)

    @classmethod
    def _scan_binary(
        cls,
        abs_path: str,
        rel_path: str,
        ctx: StrategyContext,
    ) -> None:
        """Extract printable strings from a binary and match version patterns."""
        try:
            with open(abs_path, "rb") as f:
                data = f.read(MAX_BINARY_READ)
        except OSError:
            return

        # Extract printable ASCII strings (min length 4)
        strings = extract_printable_strings(data, min_length=4)
        combined = b"\n".join(strings)

        curated_matched = False
        for component_name, pattern in VERSION_PATTERNS:
            match = pattern.search(combined)
            if match:
                version = match.group(1).decode("ascii", errors="replace")

                # Skip if we already have this component from a
                # higher-confidence source
                key = (component_name.lower(), version)
                existing = ctx.store.get(key)
                if existing and existing.detection_confidence == "high":
                    curated_matched = True
                    continue

                vendor_product = CPE_VENDOR_MAP.get(component_name.lower())
                cpe = None
                if vendor_product:
                    cpe = build_cpe(
                        vendor_product[0], vendor_product[1], version
                    )

                comp = IdentifiedComponent(
                    name=component_name,
                    version=version,
                    type="application",
                    cpe=cpe,
                    purl=build_purl(component_name, version),
                    supplier=vendor_product[0] if vendor_product else None,
                    detection_source="binary_strings",
                    detection_confidence="medium",
                    file_paths=[rel_path],
                    metadata={},
                )
                ctx.store.add(comp)
                curated_matched = True

        # --- Generic fallback: filename-anchored version detection ---
        # If no curated pattern matched, check whether the binary's own
        # name appears alongside a semver string in its extracted strings.
        if not curated_matched:
            cls._try_generic_detection(abs_path, rel_path, strings, ctx.store)

    @staticmethod
    def _try_generic_detection(
        abs_path: str,
        rel_path: str,
        strings: list[bytes],
        store: ComponentStore,
    ) -> None:
        """Fallback: detect component when binary name appears with a version.

        Matches patterns like ``rssh 2.3.4`` or ``rssh/2.3.4`` where the
        first token matches the binary's filename. False positives are
        filtered by excluding library/toolchain names and requiring the
        detected name to match the filesystem filename.
        """
        basename = os.path.basename(abs_path)
        # Primary name: the filename itself (e.g. "rssh")
        primary = basename.split(".")[0].lower()
        # Yocto-style suffix: hexdump.util-linux → "util-linux"
        suffix = (
            basename.rsplit(".", 1)[-1].lower() if "." in basename else None
        )

        candidates: list[str] = [primary]
        if suffix and suffix != primary:
            candidates.append(suffix)

        for name in candidates:
            if not name or len(name) < 2:
                continue
            if name in GENERIC_EXCLUDE_NAMES:
                continue
            # Require the name not to start with "lib" (library deps)
            if name.startswith("lib") and len(name) > 3:
                continue

            # Build a regex anchored to this name
            name_bytes = re.escape(name.encode("ascii"))
            pattern = re.compile(
                rb"(?:^|\s)" + name_bytes + rb"[\s/v_:-]+(\d+\.\d+(?:\.\d+)?(?:[a-z]\d*)?)\b",
                re.IGNORECASE,
            )
            combined = b"\n".join(strings)
            match = pattern.search(combined)
            if not match:
                continue

            version = match.group(1).decode("ascii", errors="replace")

            # Skip if version contains wildcards (protocol compat strings)
            if "*" in version or "?" in version:
                continue

            # Skip if we already have this from a better source
            key = (name, version)
            existing = store.get(key)
            if existing:
                continue

            vendor_product = CPE_VENDOR_MAP.get(name)
            cpe = None
            if vendor_product:
                cpe = build_cpe(
                    vendor_product[0], vendor_product[1], version
                )

            comp = IdentifiedComponent(
                name=name,
                version=version,
                type="application",
                cpe=cpe,
                purl=build_purl(name, version),
                supplier=vendor_product[0] if vendor_product else None,
                detection_source="binary_strings",
                detection_confidence="low",
                file_paths=[rel_path],
                metadata={"detection_method": "generic_filename_match"},
            )
            store.add(comp)
            logger.info(
                "Generic binary detection: %s %s from %s",
                name, version, rel_path,
            )
            return  # One detection per binary is sufficient
