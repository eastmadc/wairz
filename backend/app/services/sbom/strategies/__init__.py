"""SBOM detection strategies.

Each strategy implements a single component-identification approach
(package-manager databases, Syft directory scan, SONAME parsing, binary
string extraction, Android APK enumeration, …). They share a common
``SbomStrategy`` interface and are orchestrated by
``app.services.sbom.service.SbomService``.

Re-exports become populated as additive commits land. Consumers should
import named strategies directly, e.g.::

    from app.services.sbom.strategies import SyftStrategy
"""

from __future__ import annotations

from app.services.sbom.strategies.base import SbomStrategy, StrategyContext

__all__ = ["SbomStrategy", "StrategyContext"]
