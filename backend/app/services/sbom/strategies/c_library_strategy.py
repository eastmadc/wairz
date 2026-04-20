"""Dedicated C library detection (glibc / uClibc-ng / musl).

Firmware has exactly one C library; we return after the first
identification. Reads up to ``MAX_LIBC_READ`` because libc binaries are
large and the version string may be far into the file.

Previously ``SbomService._scan_c_library`` in the ``sbom_service.py``
monolith.
"""

from __future__ import annotations

import os
import re

from app.services.sbom.constants import MAX_LIBC_READ, IdentifiedComponent
from app.services.sbom.purl import build_cpe, build_purl
from app.services.sbom.strategies.base import SbomStrategy, StrategyContext


class CLibraryStrategy(SbomStrategy):
    """Identify the firmware's C library (glibc / uClibc-ng / musl)."""

    name = "c_library"

    # Static candidates; dynamic ones are discovered from /lib listing.
    _STATIC_CANDIDATES = (
        "/lib/libc.so.6",
        "/lib/libc.so.0",
    )

    def run(self, ctx: StrategyContext) -> None:
        candidates: list[str] = list(self._STATIC_CANDIDATES)

        # Dynamic candidates from /lib directory listing
        lib_abs = ctx.abs_path("/lib")
        if os.path.isdir(lib_abs):
            try:
                for entry in os.listdir(lib_abs):
                    if entry.startswith(("ld-linux", "ld-musl-", "ld-uClibc")):
                        candidates.append(f"/lib/{entry}")
                    elif entry.startswith("libc.so."):
                        path = f"/lib/{entry}"
                        if path not in candidates:
                            candidates.append(path)
            except OSError:
                pass

        checked_realpaths: set[str] = set()

        for candidate in candidates:
            abs_path = ctx.abs_path(candidate)
            try:
                real_path = os.path.realpath(abs_path)
            except OSError:
                continue
            if not real_path.startswith(ctx.extracted_root):
                continue
            if not os.path.isfile(real_path):
                continue
            if real_path in checked_realpaths:
                continue
            checked_realpaths.add(real_path)

            try:
                with open(real_path, "rb") as f:
                    if f.read(4) != b"\x7fELF":
                        continue
                    f.seek(0)
                    data = f.read(MAX_LIBC_READ)
            except OSError:
                continue

            rel_path = "/" + os.path.relpath(real_path, ctx.extracted_root)

            if self._try_glibc(data, rel_path, ctx):
                return
            if self._try_uclibc(data, rel_path, ctx):
                return
            if self._try_musl(data, rel_path, ctx):
                return

    # --- flavour-specific detectors ------------------------------------

    @staticmethod
    def _try_glibc(data: bytes, rel_path: str, ctx: StrategyContext) -> bool:
        # String match: "GNU C Library ... version 2.31"
        m = re.search(rb"GNU C Library[^\n]*version (\d+\.\d+(?:\.\d+)?)", data)
        if not m:
            m = re.search(rb"stable release version (\d+\.\d+(?:\.\d+)?)", data)
        if m:
            version = m.group(1).decode("ascii", errors="replace")
            ctx.store.add(IdentifiedComponent(
                name="glibc",
                version=version,
                type="library",
                cpe=build_cpe("gnu", "glibc", version),
                purl=build_purl("glibc", version),
                supplier="gnu",
                detection_source="binary_strings",
                detection_confidence="high",
                file_paths=[rel_path],
                metadata={"detection_note": "dedicated C library scan"},
            ))
            return True

        # Fallback: pick highest GLIBC_X.Y symbol version
        glibc_versions = re.findall(rb"GLIBC_(\d+\.\d+(?:\.\d+)?)", data)
        if glibc_versions:
            parsed = []
            for v in set(glibc_versions):
                try:
                    parts = tuple(int(x) for x in v.decode("ascii").split("."))
                    parsed.append((parts, v.decode("ascii")))
                except (ValueError, UnicodeDecodeError):
                    continue
            if parsed:
                parsed.sort(key=lambda x: x[0], reverse=True)
                version = parsed[0][1]
                ctx.store.add(IdentifiedComponent(
                    name="glibc",
                    version=version,
                    type="library",
                    cpe=build_cpe("gnu", "glibc", version),
                    purl=build_purl("glibc", version),
                    supplier="gnu",
                    detection_source="binary_strings",
                    detection_confidence="medium",
                    file_paths=[rel_path],
                    metadata={
                        "detection_note": "inferred from GLIBC symbol versions",
                    },
                ))
                return True
        return False

    @staticmethod
    def _try_uclibc(data: bytes, rel_path: str, ctx: StrategyContext) -> bool:
        m = re.search(rb"uClibc(?:-ng)? (\d+\.\d+\.\d+)", data)
        if m:
            version = m.group(1).decode("ascii", errors="replace")
            ctx.store.add(IdentifiedComponent(
                name="uclibc-ng",
                version=version,
                type="library",
                cpe=build_cpe("uclibc", "uclibc", version),
                purl=build_purl("uclibc-ng", version),
                supplier="uclibc",
                detection_source="binary_strings",
                detection_confidence="high",
                file_paths=[rel_path],
                metadata={"detection_note": "dedicated C library scan"},
            ))
            return True
        return False

    @staticmethod
    def _try_musl(data: bytes, rel_path: str, ctx: StrategyContext) -> bool:
        m = re.search(rb"musl libc (\d+\.\d+\.\d+)", data)
        if m:
            version = m.group(1).decode("ascii", errors="replace")
            ctx.store.add(IdentifiedComponent(
                name="musl",
                version=version,
                type="library",
                cpe=build_cpe("musl-libc", "musl", version),
                purl=build_purl("musl", version),
                supplier="musl-libc",
                detection_source="binary_strings",
                detection_confidence="high",
                file_paths=[rel_path],
                metadata={"detection_note": "dedicated C library scan"},
            ))
            return True
        return False
