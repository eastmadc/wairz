"""Dedicated GCC toolchain version detector.

Probes a few common binaries for the ``GCC: (toolchain) X.Y.Z`` string
embedded by the compiler.  Returns after first match because the GCC
version is consistent across a build.

Previously ``SbomService._scan_gcc_version`` in the ``sbom_service.py``
monolith.
"""

from __future__ import annotations

import os
import re

from app.services.sbom.constants import MAX_BINARY_READ, IdentifiedComponent
from app.services.sbom.purl import build_cpe, build_purl
from app.services.sbom.strategies.base import SbomStrategy, StrategyContext

_PROBE_PATHS = (
    "/bin/busybox",
    "/sbin/init",
    "/lib/libc.so.6",
    "/lib/libc.so.0",
    "/usr/sbin/httpd",
    "/usr/bin/curl",
)


class GccStrategy(SbomStrategy):
    """Extract the GCC toolchain version from a common probe binary."""

    name = "gcc"

    def run(self, ctx: StrategyContext) -> None:
        checked_realpaths: set[str] = set()

        for probe in _PROBE_PATHS:
            abs_path = ctx.abs_path(probe)
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
                    data = f.read(MAX_BINARY_READ)
            except OSError:
                continue

            m = re.search(rb"GCC: \(([^)]*)\) (\d+\.\d+\.\d+)", data)
            if m:
                toolchain = m.group(1).decode("ascii", errors="replace")
                version = m.group(2).decode("ascii", errors="replace")
                rel_path = "/" + os.path.relpath(real_path, ctx.extracted_root)

                metadata: dict = {"detection_note": "dedicated GCC scan"}
                if toolchain:
                    metadata["toolchain"] = toolchain

                ctx.store.add(IdentifiedComponent(
                    name="gcc",
                    version=version,
                    type="application",
                    cpe=build_cpe("gnu", "gcc", version),
                    purl=build_purl("gcc", version),
                    supplier="gnu",
                    detection_source="binary_strings",
                    detection_confidence="high",
                    file_paths=[rel_path],
                    metadata=metadata,
                ))
                return
