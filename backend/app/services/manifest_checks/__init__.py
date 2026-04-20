"""Manifest security checks package.

Re-exports the public surface historically provided by the single-file
``app.services.manifest_checks`` module.  Exposes ``ManifestFinding``
(canonical dataclass) and ``ManifestChecker`` (composition-based
replacement for the old ``ManifestChecksMixin``).
"""

from __future__ import annotations

from app.services.manifest_checks._base import ManifestFinding
from app.services.manifest_checks.checker import ManifestChecker

__all__ = ["ManifestChecker", "ManifestFinding"]
