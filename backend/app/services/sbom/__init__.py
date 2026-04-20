"""SBOM subpackage — identifies software components from unpacked firmware.

Decomposed from ``app/services/sbom_service.py`` into topic modules:

- ``constants``: CPE vendor maps, version patterns, SONAME maps, service risks,
  firmware markers, byte-read limits, ``IdentifiedComponent`` dataclass.
- ``purl``: Pure CPE / PURL construction helpers.
- ``normalization``: Name/version normalization + component dedup store.
- ``strategies.*``: Individual detection strategies (Syft, dpkg, opkg, APKs,
  kernel, SONAME, C library, GCC, binary strings, …).
- ``enrichment``: Post-scan CPE enrichment pipeline.
- ``service_risks``: Post-scan annotation of known-service risk levels.
- ``service``: ``SbomService`` coordinator that runs all strategies + post-
  processing passes.

Public API is re-exported here — callers should use
``from app.services.sbom import SbomService`` going forward.
"""

from __future__ import annotations

# The cut-over commit re-exports SbomService + IdentifiedComponent + key
# constants here. Until then this file is intentionally near-empty so the
# additive commits don't accidentally create two paths to SbomService.
