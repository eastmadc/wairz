"""Component deduplication + name/version normalization.

``ComponentStore`` owns the ``(normalized_name, normalized_version) →
IdentifiedComponent`` dict that the coordinator previously held as
``SbomService._components``. Every strategy calls ``store.add(comp)``;
the store resolves duplicates by preferring higher-confidence
detections while merging file-path sets.

History: extracted from ``SbomService._normalize_name /
_normalize_version / _add_component / _is_useless_version`` helpers in
``sbom_service.py``. Behaviour is preserved bit-for-bit.
"""

from __future__ import annotations

import re

from app.services.sbom.constants import IdentifiedComponent


def normalize_name(name: str) -> str:
    """Normalize package name for dedup (underscores → hyphens, lowercase)."""
    return name.lower().replace("_", "-")


def normalize_version(version: str | None) -> str | None:
    """Treat '0.0.0' and 'UNKNOWN' as equivalent to no version for merges."""
    if version in (None, "", "0.0.0", "UNKNOWN"):
        return None
    return version


def is_useless_version(version: str | None) -> bool:
    """Return True if the version is missing or unlikely to be a real
    software version.

    SONAME versions like "6" (libc.so.6), "0" (libc.so.0), or "200"
    (libnl-3.so.200) are just ABI version numbers, not real upstream
    software versions. Real versions have at least one dot (e.g. "1.2",
    "2.31", "1.0.2k").
    """
    if not version:
        return True
    # A bare integer (no dots) is almost always a SONAME ABI version
    return bool(re.fullmatch(r"\d+", version))


class ComponentStore:
    """Dedup-aware accumulator for IdentifiedComponent instances.

    Thread-unsafe. One instance per ``SbomService.generate_sbom()`` run.
    """

    _CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}

    def __init__(self) -> None:
        self._components: dict[tuple[str, str | None], IdentifiedComponent] = {}
        self._current_partition: str | None = None

    # --- partition context for source_partition stamping ------------------

    def set_partition(self, partition_name: str | None) -> None:
        """Stamp subsequent add() calls with this partition name.

        Called by the coordinator as it walks multi-partition firmware
        (scatter-zip, Android vendor/product/etc.).
        """
        self._current_partition = partition_name

    @property
    def current_partition(self) -> str | None:
        return self._current_partition

    # --- core add / merge -------------------------------------------------

    def add(self, comp: IdentifiedComponent) -> None:
        """Add or merge a component, preferring higher-confidence detections."""
        # Stamp source partition from the current scanning context
        if self._current_partition and not comp.source_partition:
            comp.source_partition = self._current_partition

        key = (normalize_name(comp.name), normalize_version(comp.version))
        existing = self._components.get(key)

        if existing is None:
            self._components[key] = comp
            return

        existing_rank = self._CONFIDENCE_RANK.get(existing.detection_confidence, 0)
        new_rank = self._CONFIDENCE_RANK.get(comp.detection_confidence, 0)

        # Merge file paths
        merged_paths = list(set(existing.file_paths + comp.file_paths))

        if new_rank > existing_rank:
            # Replace with higher-confidence data, keep merged paths
            comp.file_paths = merged_paths
            self._components[key] = comp
        else:
            existing.file_paths = merged_paths

    # --- accessors used by enrichment + coordinator -----------------------

    def get(
        self,
        key: tuple[str, str | None],
    ) -> IdentifiedComponent | None:
        """Look up a component by its (normalized_name, version) key."""
        return self._components.get(key)

    def values(self):
        """Iterator over the stored components."""
        return self._components.values()

    def items(self):
        """Iterator over (key, component) pairs."""
        return self._components.items()

    def __contains__(self, key: tuple[str, str | None]) -> bool:
        return key in self._components

    def __len__(self) -> int:
        return len(self._components)
