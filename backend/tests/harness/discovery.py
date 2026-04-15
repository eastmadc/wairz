"""APK test fixture discovery.

Discovers APK test fixtures from multiple sources:
  1. Real APK files in a configurable directory (default: tests/fixtures/apk/files/)
  2. Synthetic APK fixtures from apk_fixture_manifests.py (mock-based)
  3. Well-known vulnerable APK definitions (DIVA, InsecureBankv2, OVAA)

Each discovered fixture is represented as an APKFixture dataclass that
carries metadata (name, path, expected findings, etc.) and can be used
by the scan orchestrator to run multi-phase analysis.
"""

from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class FixtureSource(str, Enum):
    """Where the APK fixture came from."""

    REAL_FILE = "real_file"  # Actual .apk on disk
    SYNTHETIC = "synthetic"  # Generated from apk_fixture_manifests.py
    WELL_KNOWN = "well_known"  # Known vulnerable APK (DIVA, etc.)


class ScanPhase(str, Enum):
    """Scan phases available in the harness."""

    MANIFEST = "manifest"
    BYTECODE = "bytecode"
    SAST = "sast"


@dataclass
class APKFixture:
    """A single APK test fixture with metadata.

    Attributes:
        name: Human-readable name (e.g. "DIVA", "debuggable.apk")
        path: Absolute path to APK file (None for synthetic-only fixtures)
        source: Where the fixture came from
        package_name: Expected Android package name (if known)
        expected_manifest_checks: Set of MANIFEST-NNN IDs expected to fire
        expected_bytecode_patterns: Set of BYTECODE-NNN IDs expected to fire
        expected_min_findings: Minimum total findings expected (for baselines)
        expected_max_findings: Maximum total findings expected (FP cap)
        tags: Freeform tags for filtering (e.g. "vulnerable", "clean", "priv-app")
        fixture_def: Raw fixture definition dict (for synthetic fixtures)
        sha256: SHA256 of the APK file (computed lazily)
        firmware_location: Simulated firmware path (e.g. "/system/priv-app/")
    """

    name: str
    path: str | None = None
    source: FixtureSource = FixtureSource.REAL_FILE
    package_name: str | None = None
    expected_manifest_checks: set[str] = field(default_factory=set)
    expected_bytecode_patterns: set[str] = field(default_factory=set)
    expected_min_findings: int | None = None
    expected_max_findings: int | None = None
    tags: set[str] = field(default_factory=set)
    fixture_def: dict[str, Any] | None = None
    sha256: str | None = None
    firmware_location: str | None = None

    def compute_sha256(self) -> str | None:
        """Compute SHA256 hash of the APK file (lazy, cached)."""
        if self.sha256:
            return self.sha256
        if not self.path or not os.path.isfile(self.path):
            return None
        h = hashlib.sha256()
        with open(self.path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        self.sha256 = h.hexdigest()
        return self.sha256

    @property
    def is_real_file(self) -> bool:
        return self.path is not None and os.path.isfile(self.path)

    @property
    def is_priv_app(self) -> bool:
        return self.firmware_location is not None and "priv-app" in self.firmware_location

    @property
    def is_platform_signed(self) -> bool:
        return "platform-signed" in self.tags


# ---------------------------------------------------------------------------
# Well-known vulnerable APK definitions
# ---------------------------------------------------------------------------

WELL_KNOWN_APKS: dict[str, dict[str, Any]] = {
    "diva": {
        "name": "DIVA (Damn Insecure Vulnerable App)",
        "package_name": "jakhar.aseem.diva",
        "expected_manifest_checks": {
            "MANIFEST-001",  # debuggable
            "MANIFEST-002",  # allowBackup
            "MANIFEST-003",  # cleartext traffic (default for targetSdk < 28)
            "MANIFEST-005",  # outdated minSdk
            "MANIFEST-006",  # exported components
        },
        "expected_min_findings": 4,
        "expected_max_findings": 15,
        "tags": {"vulnerable", "reference", "training"},
    },
    "insecurebankv2": {
        "name": "InsecureBankv2",
        "package_name": "com.android.insecurebankv2",
        "expected_manifest_checks": {
            "MANIFEST-001",  # debuggable
            "MANIFEST-002",  # allowBackup
            "MANIFEST-006",  # exported components
        },
        "expected_min_findings": 5,
        "expected_max_findings": 12,
        "tags": {"vulnerable", "reference", "training"},
    },
    "ovaa": {
        "name": "OVAA (Oversecured Vulnerable Android App)",
        "package_name": "oversecured.ovaa",
        "expected_manifest_checks": {
            "MANIFEST-001",  # debuggable
            "MANIFEST-002",  # allowBackup
            "MANIFEST-006",  # exported components
        },
        "expected_min_findings": 3,
        "expected_max_findings": 15,
        "tags": {"vulnerable", "reference"},
    },
}


def discover_real_apks(
    search_dirs: list[str | Path] | None = None,
    *,
    recursive: bool = True,
) -> list[APKFixture]:
    """Discover real APK files on disk.

    Args:
        search_dirs: Directories to search. Defaults to
            tests/fixtures/apk/files/ relative to backend root.
        recursive: Whether to search subdirectories.

    Returns:
        List of APKFixture objects for each .apk found.
    """
    if search_dirs is None:
        backend_root = Path(__file__).resolve().parent.parent.parent
        search_dirs = [backend_root / "tests" / "fixtures" / "apk" / "files"]

    fixtures: list[APKFixture] = []

    for search_dir in search_dirs:
        search_path = Path(search_dir)
        if not search_path.is_dir():
            logger.debug("APK search dir does not exist: %s", search_path)
            continue

        glob_pattern = "**/*.apk" if recursive else "*.apk"
        for apk_path in sorted(search_path.glob(glob_pattern)):
            if not apk_path.is_file():
                continue

            name = apk_path.stem
            # Check if this matches a well-known APK by filename
            well_known = _match_well_known(apk_path.name)
            tags = {"real-file"}

            # Detect firmware location from path components
            firmware_location = _detect_firmware_location(apk_path)
            if firmware_location:
                tags.add("firmware-embedded")
                if "priv-app" in firmware_location:
                    tags.add("priv-app")

            fixture = APKFixture(
                name=well_known["name"] if well_known else apk_path.name,
                path=str(apk_path),
                source=FixtureSource.WELL_KNOWN if well_known else FixtureSource.REAL_FILE,
                package_name=well_known.get("package_name") if well_known else None,
                expected_manifest_checks=set(well_known.get("expected_manifest_checks", set())) if well_known else set(),
                expected_min_findings=well_known.get("expected_min_findings") if well_known else None,
                expected_max_findings=well_known.get("expected_max_findings") if well_known else None,
                tags=tags | set(well_known.get("tags", set())) if well_known else tags,
                firmware_location=firmware_location,
            )
            fixtures.append(fixture)

    logger.info("Discovered %d real APK fixtures", len(fixtures))
    return fixtures


def discover_synthetic_fixtures() -> list[APKFixture]:
    """Discover all synthetic APK fixtures from apk_fixture_manifests.py.

    Returns APKFixture objects built from the manifest definitions.
    These don't have real APK files — they use the mock_apk_factory
    for unit testing.
    """
    try:
        from tests.fixtures.apk.apk_fixture_manifests import ALL_FIXTURES
    except ImportError:
        logger.warning("Could not import ALL_FIXTURES from apk_fixture_manifests")
        return []

    fixtures: list[APKFixture] = []
    for fixture_def in ALL_FIXTURES.values():
        name = fixture_def.get("filename", fixture_def.get("package", "unknown"))
        tags = {"synthetic"}

        # Clean fixtures should produce no findings
        expected_checks = set(fixture_def.get("expected_checks", set()))
        if not expected_checks:
            tags.add("clean")

        fixtures.append(APKFixture(
            name=name,
            path=None,
            source=FixtureSource.SYNTHETIC,
            package_name=fixture_def.get("package"),
            expected_manifest_checks=expected_checks,
            tags=tags,
            fixture_def=fixture_def,
        ))

    logger.info("Discovered %d synthetic APK fixtures", len(fixtures))
    return fixtures


def discover_all(
    search_dirs: list[str | Path] | None = None,
    *,
    include_synthetic: bool = True,
    include_real: bool = True,
    tags_filter: set[str] | None = None,
) -> list[APKFixture]:
    """Discover all available APK test fixtures.

    Combines real APK files and synthetic fixtures into a unified list.
    Optionally filters by tags.

    Args:
        search_dirs: Directories to search for real APKs.
        include_synthetic: Whether to include synthetic fixtures.
        include_real: Whether to include real file fixtures.
        tags_filter: If set, only return fixtures whose tags intersect.

    Returns:
        Combined list of APKFixture objects, deduplicated by name.
    """
    all_fixtures: list[APKFixture] = []
    seen_names: set[str] = set()

    if include_real:
        for f in discover_real_apks(search_dirs):
            if f.name not in seen_names:
                all_fixtures.append(f)
                seen_names.add(f.name)

    if include_synthetic:
        for f in discover_synthetic_fixtures():
            if f.name not in seen_names:
                all_fixtures.append(f)
                seen_names.add(f.name)

    if tags_filter:
        all_fixtures = [
            f for f in all_fixtures
            if f.tags & tags_filter
        ]

    logger.info("Total APK fixtures discovered: %d", len(all_fixtures))
    return all_fixtures


def _match_well_known(filename: str) -> dict[str, Any] | None:
    """Match an APK filename to a well-known vulnerable APK definition."""
    lower = filename.lower()
    for key, defn in WELL_KNOWN_APKS.items():
        if key in lower:
            return defn
    return None


def _detect_firmware_location(apk_path: Path) -> str | None:
    """Detect if an APK is inside a firmware-like directory structure.

    Looks for /system/app/, /system/priv-app/, /vendor/app/ etc.
    in the path components.
    """
    parts = apk_path.parts
    for i, part in enumerate(parts):
        if part in ("system", "vendor", "product", "system_ext"):
            remaining = "/".join(parts[i:])
            for marker in ("priv-app", "app", "framework"):
                if marker in remaining:
                    return f"/{remaining}"
    return None
