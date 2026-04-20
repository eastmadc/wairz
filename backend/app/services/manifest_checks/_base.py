"""Shared primitives for manifest_checks topic modules.

Defines:
- ``ManifestFinding`` dataclass (canonical).
- SDK-version thresholds used by ``_check_min_sdk``.
- Android XML namespace constant.
- SDK → Android-version lookup table and helper.
- Module-level helpers ``_get_manifest_attr``, ``_is_true``,
  ``_is_false_or_absent`` used across topic check modules.

Imported by ``_legacy.py`` (during the split-in-progress phase) and by
each ``manifest_checks/<topic>.py`` module after extraction.  External
callers should import ``ManifestFinding`` via
``app.services.manifest_checks`` (re-exported from ``__init__``) rather
than touching this file directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# SDK thresholds (MANIFEST-005)
# ---------------------------------------------------------------------------

#: Minimum SDK version considered reasonably secure (Android 7.0 Nougat).
_MIN_SDK_SECURE_THRESHOLD: int = 24
#: SDK below which is critically outdated (Android 4.4 KitKat).
_MIN_SDK_CRITICAL_THRESHOLD: int = 19


# ---------------------------------------------------------------------------
# Android XML namespace
# ---------------------------------------------------------------------------

#: Shared Android manifest namespace URI.  Many checks construct
#: ``f"{{{_NS_ANDROID}}}{attr}"`` qualified names to read manifest XML.
_NS_ANDROID: str = "http://schemas.android.com/apk/res/android"


# ---------------------------------------------------------------------------
# SDK → human-friendly Android version lookup
# ---------------------------------------------------------------------------

_SDK_VERSION_MAP: dict[int, str] = {
    1: "1.0", 2: "1.1", 3: "1.5", 4: "1.6", 5: "2.0", 6: "2.0.1",
    7: "2.1", 8: "2.2", 9: "2.3", 10: "2.3.3", 11: "3.0", 12: "3.1",
    13: "3.2", 14: "4.0", 15: "4.0.3", 16: "4.1", 17: "4.2", 18: "4.3",
    19: "4.4", 20: "4.4W", 21: "5.0", 22: "5.1", 23: "6.0", 24: "7.0",
    25: "7.1", 26: "8.0", 27: "8.1", 28: "9.0", 29: "10", 30: "11",
    31: "12", 32: "12L", 33: "13", 34: "14", 35: "15",
}


def _sdk_to_android_version(sdk: int) -> str:
    """Map an SDK API level to a human-friendly Android version string."""
    return _SDK_VERSION_MAP.get(sdk, f"API {sdk}")


# ---------------------------------------------------------------------------
# ManifestFinding dataclass (canonical definition)
# ---------------------------------------------------------------------------

@dataclass
class ManifestFinding:
    """A single manifest security finding."""

    check_id: str
    title: str
    severity: str  # "critical", "high", "medium", "low", "info"
    description: str
    evidence: str = ""
    cwe_ids: list[str] = field(default_factory=list)
    confidence: str = "high"  # "high", "medium", "low"
    suppressed: bool = False
    suppression_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "cwe_ids": self.cwe_ids,
            "confidence": self.confidence,
        }
        if self.suppressed:
            d["suppressed"] = True
            d["suppression_reason"] = self.suppression_reason
        return d


# ---------------------------------------------------------------------------
# Shared manifest-attribute helpers
# ---------------------------------------------------------------------------

def _get_manifest_attr(apk_obj: Any, tag: str, attr: str) -> str | None:
    """Extract a manifest attribute value via Androguard.

    Returns the raw string value or None if the attribute is absent.
    Tries both bare attribute name and full namespace URI since
    Androguard behaviour varies by version.
    """
    ns = _NS_ANDROID
    for name in (attr, f"{{{ns}}}{attr}"):
        try:
            val = apk_obj.get_attribute_value(tag, name)
            if val is not None:
                return str(val)
        except Exception:
            continue
    return None


def _is_true(val: str | None) -> bool:
    """Check if a manifest attribute value represents boolean true."""
    if val is None:
        return False
    return val.lower() in ("true", "0xffffffff", "-1")


def _is_false_or_absent(val: str | None) -> bool:
    """Check if a manifest attribute is absent or explicitly false."""
    if val is None:
        return True
    return val.lower() in ("false", "0x0", "0")
