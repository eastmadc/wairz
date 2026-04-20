"""Syft directory scan — broad ecosystem coverage via anchore/syft CLI.

Syft detects packages across 30+ ecosystems (dpkg, Python, Go, Java,
Node, Rust, Ruby, etc.). Results are added with medium confidence so
that Wairz's custom firmware-specific strategies can override them for
components they detect with higher confidence.

Previously ``SbomService._run_syft_scan`` + ``_SYFT_TYPE_MAP`` in the
``sbom_service.py`` monolith.
"""

from __future__ import annotations

import json
import os
import subprocess
from shutil import which

from app.services.sbom.constants import IdentifiedComponent
from app.services.sbom.strategies.base import SbomStrategy, StrategyContext

# Map Syft package types to Wairz component types
_SYFT_TYPE_MAP = {
    "deb": "application",
    "rpm": "application",
    "apk": "application",
    "python": "library",
    "go-module": "library",
    "java-archive": "library",
    "npm": "library",
    "gem": "library",
    "rust-crate": "library",
    "php-composer": "library",
    "lua-rock": "library",
    "binary": "application",
    "linux-kernel": "operating-system",
}


class SyftStrategy(SbomStrategy):
    """Run ``syft dir:<root> -o cyclonedx-json`` and import components."""

    name = "syft"

    def run(self, ctx: StrategyContext) -> None:
        from app.config import get_settings
        settings = get_settings()

        if not settings.syft_enabled or not which("syft"):
            return

        # Scan the primary extracted root
        scan_dirs = [ctx.extracted_root]

        # For Android multi-partition extractions, also scan sibling partitions
        # (vendor, product, etc.) that aren't under the system root. This
        # preserves the monolith's side-scan behaviour so nothing regresses
        # — the coordinator's per-partition loop also covers siblings, but
        # Syft's own directory scan catches packaging metadata that lives
        # outside the directories Wairz walks directly.
        parent = os.path.dirname(ctx.extracted_root)
        if os.path.basename(parent) == "rootfs":
            try:
                for sibling in os.listdir(parent):
                    sibling_path = os.path.join(parent, sibling)
                    if (
                        sibling_path != ctx.extracted_root
                        and os.path.isdir(sibling_path)
                    ):
                        scan_dirs.append(sibling_path)
            except OSError:
                pass

        cdx_components: list[dict] = []
        for scan_dir in scan_dirs:
            try:
                proc = subprocess.run(
                    ["syft", f"dir:{scan_dir}", "-o", "cyclonedx-json", "-q"],
                    capture_output=True,
                    timeout=settings.syft_timeout,
                    text=True,
                )
                if proc.returncode != 0:
                    continue
                cdx = json.loads(proc.stdout)
                cdx_components.extend(cdx.get("components", []))
            except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
                continue

        for cdx_comp in cdx_components:
            # Skip file-hash entries (not real packages)
            if cdx_comp.get("type") == "file":
                continue

            name = cdx_comp.get("name", "").strip()
            version = cdx_comp.get("version", "").strip() or None
            if not name:
                continue

            # Skip noise: Windows installer stubs, unknown entries
            if name.startswith("wininst-") or name == "unknown":
                continue

            # Extract Syft metadata from properties array
            props = {
                p["name"]: p["value"]
                for p in cdx_comp.get("properties", [])
                if "name" in p and "value" in p
            }
            syft_type = props.get("syft:package:type", "")
            cataloger = props.get("syft:package:foundBy", "")
            file_path = props.get("syft:location:0:path", "")

            comp_type = _SYFT_TYPE_MAP.get(syft_type, "library")

            comp = IdentifiedComponent(
                name=name,
                version=version,
                type=comp_type,
                cpe=cdx_comp.get("cpe"),
                purl=cdx_comp.get("purl"),
                supplier=None,
                detection_source="syft",
                detection_confidence="medium",
                file_paths=[file_path] if file_path else [],
                metadata={"syft_cataloger": cataloger, "syft_type": syft_type},
            )
            ctx.store.add(comp)
