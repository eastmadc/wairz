"""Dedicated BusyBox binary scanner.

BusyBox installs as a single binary with hundreds of symlinks, so the
generic binary scanner (which skips symlinks) may miss it depending on
layout. This strategy resolves symlinks explicitly and reads the actual
binary to extract the version string.

Previously ``SbomService._scan_busybox`` in the ``sbom_service.py``
monolith.
"""

from __future__ import annotations

import os
import re

from app.services.sbom.constants import MAX_BINARY_READ, IdentifiedComponent
from app.services.sbom.purl import build_cpe, build_purl
from app.services.sbom.strategies.base import SbomStrategy, StrategyContext

# Common locations where the real busybox binary (or a symlink to it)
# lives. /bin/sh is almost always a symlink to busybox on embedded systems.
_CANDIDATES = (
    "/bin/busybox",
    "/bin/busybox.nosuid",
    "/bin/busybox.suid",
    "/usr/bin/busybox",
    "/sbin/busybox",
    "/bin/sh",
)


class BusyBoxStrategy(SbomStrategy):
    """Explicitly search for BusyBox; resolve symlinks to read the real binary."""

    name = "busybox"

    def run(self, ctx: StrategyContext) -> None:
        checked_realpaths: set[str] = set()

        for candidate in _CANDIDATES:
            abs_path = ctx.abs_path(candidate)

            # Resolve symlinks so we read the actual binary
            try:
                real_path = os.path.realpath(abs_path)
            except OSError:
                continue

            # Stay inside the extracted root
            if not real_path.startswith(ctx.extracted_root):
                continue
            if not os.path.isfile(real_path):
                continue
            # Don't scan the same underlying file twice
            if real_path in checked_realpaths:
                continue
            checked_realpaths.add(real_path)

            # Quick ELF check
            try:
                with open(real_path, "rb") as f:
                    if f.read(4) != b"\x7fELF":
                        continue
            except OSError:
                continue

            # Read and search for BusyBox version string
            try:
                with open(real_path, "rb") as f:
                    data = f.read(MAX_BINARY_READ)
            except OSError:
                continue

            match = re.search(rb"BusyBox v(\d+\.\d+(?:\.\d+)?)", data)
            if match:
                version = match.group(1).decode("ascii", errors="replace")
                rel_path = "/" + os.path.relpath(real_path, ctx.extracted_root)

                comp = IdentifiedComponent(
                    name="busybox",
                    version=version,
                    type="application",
                    cpe=build_cpe("busybox", "busybox", version),
                    purl=build_purl("busybox", version),
                    supplier="busybox",
                    detection_source="binary_strings",
                    detection_confidence="high",
                    file_paths=[rel_path],
                    metadata={"detection_note": "dedicated busybox scan"},
                )
                ctx.store.add(comp)
                return  # Found it, no need to check more candidates
