"""SBOM subpackage — identifies software components from unpacked firmware.

Decomposed from ``app/services/sbom_service.py`` into topic modules:

- :mod:`.constants` — CPE vendor maps, version patterns, SONAME maps,
  service risks, firmware markers, byte-read limits,
  :class:`IdentifiedComponent` dataclass.
- :mod:`.purl` — Pure CPE / PURL construction helpers.
- :mod:`.normalization` — Name/version normalization + :class:`ComponentStore`.
- :mod:`.strategies` — Individual detection strategies (Syft, dpkg, opkg,
  APKs, kernel, SONAME, C library, GCC, binary strings, …).
- :mod:`.enrichment` — Post-scan CPE enrichment pipeline.
- :mod:`.service_risks` — Post-scan annotation of known-service risk levels.
- :mod:`.service` — :class:`SbomService` coordinator that runs all strategies
  + post-processing passes.

Public API is re-exported here — callers should use
``from app.services.sbom import SbomService`` going forward.
"""

from __future__ import annotations

from app.services.sbom.constants import (
    CPE_VENDOR_MAP,
    FIRMWARE_MARKERS,
    KNOWN_SERVICE_RISKS,
    SONAME_COMPONENT_MAP,
    VERSION_PATTERNS,
    IdentifiedComponent,
)
from app.services.sbom.service import SbomService

__all__ = [
    "SbomService",
    "IdentifiedComponent",
    "CPE_VENDOR_MAP",
    "SONAME_COMPONENT_MAP",
    "VERSION_PATTERNS",
    "FIRMWARE_MARKERS",
    "KNOWN_SERVICE_RISKS",
]
