"""Androguard-based APK analysis service.

Provides deep static analysis of Android APK files: permissions,
components, signature verification, manifest parsing.  All methods
are synchronous (CPU-bound) and should be called via
``loop.run_in_executor()`` from async handlers.
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Permission risk classification
# ---------------------------------------------------------------------------

_DANGEROUS_PERMISSIONS: set[str] = {
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.BODY_SENSORS",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.NEARBY_WIFI_DEVICES",
    "android.permission.POST_NOTIFICATIONS",
}

_SIGNATURE_PERMISSIONS: set[str] = {
    "android.permission.INSTALL_PACKAGES",
    "android.permission.DELETE_PACKAGES",
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
    "android.permission.WRITE_SECURE_SETTINGS",
    "android.permission.READ_LOGS",
    "android.permission.DUMP",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.CHANGE_COMPONENT_ENABLED_STATE",
    "android.permission.GRANT_RUNTIME_PERMISSIONS",
    "android.permission.REVOKE_RUNTIME_PERMISSIONS",
    "android.permission.MANAGE_USERS",
    "android.permission.INTERACT_ACROSS_USERS_FULL",
    "android.permission.MASTER_CLEAR",
}


def classify_permission(perm: str) -> str:
    """Classify an Android permission as 'dangerous', 'signature', or 'normal'."""
    if perm in _DANGEROUS_PERMISSIONS:
        return "dangerous"
    if perm in _SIGNATURE_PERMISSIONS:
        return "signature"
    return "normal"


class AndroguardService:
    """Wraps Androguard to analyse individual APK files."""

    @staticmethod
    def is_available() -> bool:
        """Return True if androguard is importable."""
        try:
            import androguard  # noqa: F401
            return True
        except ImportError:
            return False

    # ------------------------------------------------------------------
    # Core analysis
    # ------------------------------------------------------------------

    def analyze_apk(self, apk_path: str) -> dict[str, Any]:
        """Analyse an APK and return structured metadata.

        Raises ``ImportError`` if androguard is not installed, or
        ``FileNotFoundError`` / ``ValueError`` on bad input.
        """
        from androguard.misc import AnalyzeAPK

        if not os.path.isfile(apk_path):
            raise FileNotFoundError(f"APK not found: {apk_path}")

        apk_obj, dex_list, analysis = AnalyzeAPK(apk_path)

        result: dict[str, Any] = {
            "package": apk_obj.get_package() or "unknown",
            "version_code": apk_obj.get_androidversion_code(),
            "version_name": apk_obj.get_androidversion_name(),
            "min_sdk": apk_obj.get_min_sdk_version(),
            "target_sdk": apk_obj.get_target_sdk_version(),
            "permissions": sorted(apk_obj.get_permissions()),
            "activities": sorted(apk_obj.get_activities()),
            "services": sorted(apk_obj.get_services()),
            "receivers": sorted(apk_obj.get_receivers()),
            "providers": sorted(apk_obj.get_providers()),
            "main_activity": apk_obj.get_main_activity(),
            "is_signed": apk_obj.is_signed(),
            "signatures": [],
        }

        # Certificate info
        try:
            certs = apk_obj.get_certificates()
            for cert in certs:
                sig_info: dict[str, Any] = {}
                try:
                    sig_info["issuer"] = str(cert.issuer.human_friendly) if hasattr(cert.issuer, "human_friendly") else str(cert.issuer)
                except Exception:
                    sig_info["issuer"] = "unknown"
                try:
                    sig_info["subject"] = str(cert.subject.human_friendly) if hasattr(cert.subject, "human_friendly") else str(cert.subject)
                except Exception:
                    sig_info["subject"] = "unknown"
                try:
                    sig_info["serial"] = str(cert.serial_number)
                except Exception:
                    sig_info["serial"] = "unknown"
                try:
                    sig_info["algorithm"] = cert.signature_algo or "unknown"
                except Exception:
                    sig_info["algorithm"] = "unknown"
                try:
                    sig_info["not_before"] = str(cert["tbs_certificate"]["validity"]["not_before"].native)
                    sig_info["not_after"] = str(cert["tbs_certificate"]["validity"]["not_after"].native)
                except Exception:
                    pass

                # Debug/test certificate detection
                sig_info["is_debug"] = self._is_debug_cert(sig_info)
                result["signatures"].append(sig_info)
        except Exception as exc:
            logger.warning("Failed to extract certificate info from %s: %s", apk_path, exc)

        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_debug_cert(sig_info: dict[str, Any]) -> bool:
        """Heuristic check for debug/test signing certificates."""
        for field in ("issuer", "subject"):
            val = sig_info.get(field, "").lower()
            if any(kw in val for kw in ("android debug", "debug", "test", "cn=android debug")):
                return True
        return False

    def get_permissions_with_risk(self, apk_path: str) -> list[dict[str, str]]:
        """Return permissions with risk classification.

        Lightweight wrapper that only extracts permissions (still uses
        full ``AnalyzeAPK`` under the hood — Androguard has no lighter API).
        """
        info = self.analyze_apk(apk_path)
        return [
            {"permission": p, "risk": classify_permission(p)}
            for p in info["permissions"]
        ]

    def check_signatures(self, apk_path: str) -> dict[str, Any]:
        """Verify APK signatures and check for debug/test certs."""
        info = self.analyze_apk(apk_path)
        warnings: list[str] = []

        if not info["is_signed"]:
            warnings.append("APK is NOT signed")

        for sig in info["signatures"]:
            if sig.get("is_debug"):
                warnings.append(
                    f"Debug/test certificate detected: {sig.get('subject', 'unknown')}"
                )
            algo = sig.get("algorithm", "").lower()
            if "md5" in algo or "sha1" in algo:
                warnings.append(
                    f"Weak signature algorithm: {sig.get('algorithm')}"
                )

        return {
            "package": info["package"],
            "is_signed": info["is_signed"],
            "signatures": info["signatures"],
            "warnings": warnings,
        }
