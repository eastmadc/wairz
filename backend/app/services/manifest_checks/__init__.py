"""Manifest security checks package.

Re-exports the public surface historically provided by the single-file
``app.services.manifest_checks`` module.  Currently exposes
``ManifestFinding`` (canonical dataclass) and ``ManifestChecksMixin``
(the legacy monolithic Mixin); once Phase 5 part 1 of the
backend-service-decomposition intake is complete, this will also expose
``ManifestChecker`` (composition-based replacement) and
``ManifestChecksMixin`` will be removed.
"""

from __future__ import annotations

from app.services.manifest_checks._base import ManifestFinding
from app.services.manifest_checks._legacy import ManifestChecksMixin

__all__ = ["ManifestChecksMixin", "ManifestFinding"]
