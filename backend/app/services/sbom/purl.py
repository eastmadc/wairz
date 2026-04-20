"""Pure CPE 2.3 and PURL (Package URL) construction helpers.

These functions have no state and no I/O, so they live outside the
``SbomService`` class for easier unit testing.  Strategies import them
directly.

History: extracted from ``SbomService._build_cpe / _build_os_cpe /
_build_purl`` static methods in the ``sbom_service.py`` monolith. Names
kept identical (without the leading underscore) to preserve blame.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def build_cpe(
    vendor: str,
    product: str,
    version: str | None,
    part: str = "a",
) -> str | None:
    """Build a CPE 2.3 string.

    Args:
        vendor: CPE vendor field.
        product: CPE product field.
        version: Software version (None returns None).
        part: CPE part — ``"a"`` for application (default), ``"o"`` for
              operating-system, ``"h"`` for hardware.
    """
    if not version:
        return None
    ver = version.strip()
    return f"cpe:2.3:{part}:{vendor}:{product}:{ver}:*:*:*:*:*:*:*"


def build_os_cpe(vendor: str, product: str, version: str | None) -> str | None:
    """Convenience wrapper for OS-type CPE (``part='o'``)."""
    if not version:
        return None
    ver = version.strip()
    return f"cpe:2.3:o:{vendor}:{product}:{ver}:*:*:*:*:*:*:*"


def build_purl(
    name: str,
    version: str | None,
    pkg_type: str = "generic",
) -> str | None:
    """Build a packageurl (PURL) string.

    Attempts the ``packageurl-python`` library first, falling back to
    manual string construction so a malformed ``pkg_type`` doesn't break
    the scan.
    """
    if not version:
        return None
    try:
        from packageurl import PackageURL
        purl = PackageURL(type=pkg_type, name=name, version=version)
        return str(purl)
    except Exception as exc:
        # Fallback: construct manually. Log so recurring failures on
        # malformed version strings or unsupported pkg_types surface
        # in logs instead of silently producing a malformed purl.
        logger.debug(
            "PackageURL construction failed for %s@%s (type=%s): %s; "
            "using manual fallback",
            name, version, pkg_type, exc,
        )
        return f"pkg:{pkg_type}/{name}@{version}"
