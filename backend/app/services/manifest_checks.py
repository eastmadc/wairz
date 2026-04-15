"""Manifest security check methods for AndroguardService.

Extracted from androguard_service.py to keep file sizes manageable.
Contains all 18 individual _check_* methods, helper methods for
manifest attribute parsing, and the signatureOrSystem detection logic.

This module defines ManifestChecksMixin which AndroguardService inherits.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Minimum SDK version considered reasonably secure (Android 7.0 Nougat)
_MIN_SDK_SECURE_THRESHOLD = 24
# SDK below which is critically outdated (Android 4.4 KitKat)
_MIN_SDK_CRITICAL_THRESHOLD = 19


# ---------------------------------------------------------------------------
# ManifestFinding dataclass (canonical definition)
# ---------------------------------------------------------------------------
# Re-exported by androguard_service.py for backward compatibility.

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


class ManifestChecksMixin:
    """Mixin providing individual manifest security check methods.

    Inherited by AndroguardService. Each _check_* method returns a list
    of ManifestFinding objects and operates on an Androguard APK object.
    """

    # ------------------------------------------------------------------
    # Individual manifest checks
    # ------------------------------------------------------------------

    @staticmethod
    def _get_manifest_attr(apk_obj: Any, tag: str, attr: str) -> str | None:
        """Extract a manifest attribute value via Androguard.

        Returns the raw string value or None if the attribute is absent.
        Tries both bare attribute name and full namespace URI since
        Androguard behaviour varies by version.
        """
        ns = "http://schemas.android.com/apk/res/android"
        for name in (attr, f"{{{ns}}}{attr}"):
            try:
                val = apk_obj.get_attribute_value(tag, name)
                if val is not None:
                    return str(val)
            except Exception:
                continue
        return None

    @staticmethod
    def _is_true(val: str | None) -> bool:
        """Check if a manifest attribute value represents boolean true."""
        if val is None:
            return False
        return val.lower() in ("true", "0xffffffff", "-1")

    @staticmethod
    def _is_false_or_absent(val: str | None) -> bool:
        """Check if a manifest attribute is absent or explicitly false."""
        if val is None:
            return True
        return val.lower() in ("false", "0x0", "0")

    def _check_debuggable(
        self,
        apk_obj: Any,
        *,
        is_platform_signed: bool = False,
        is_debug_signed: bool = False,
    ) -> list[ManifestFinding]:
        """MANIFEST-001: android:debuggable=true check.

        MobSF base severity: **high** (CWE-489).

        Context-aware adjustments:
        - Platform-signed APK: escalate to **critical** — a debuggable
          system component allows full process inspection of a privileged
          app, which can leak platform keys and bypass SELinux policies.
        - Debug-signed APK: lower confidence to **medium** — likely a
          development/test build; still flagged but may be intentional.
        - targetSdk ≥ 28 (Pie): add note that modern AGP strips this by
          default in release builds, so its presence is more suspicious.
        """
        val = self._get_manifest_attr(apk_obj, "application", "debuggable")
        if not self._is_true(val):
            return []

        # Gather target SDK for context enrichment
        target_sdk_str = apk_obj.get_target_sdk_version()
        try:
            target_sdk = int(target_sdk_str) if target_sdk_str else 0
        except (ValueError, TypeError):
            target_sdk = 0

        # --- Severity adjustment based on signing context ---
        severity = "high"  # MobSF base
        if is_platform_signed:
            # Platform-signed + debuggable = catastrophic — attacker can
            # attach to a system-privileged process and access platform key
            # material, bypass MAC policies, and pivot to other system apps.
            severity = "critical"

        # --- Confidence adjustment based on signing context ---
        confidence = "high"
        if is_debug_signed:
            # Debug-signed APKs are likely dev/test builds where
            # debuggable=true is expected; still worth flagging but
            # lower confidence that it represents a production issue.
            confidence = "medium"

        # --- Build context-enriched description ---
        base_desc = (
            "The android:debuggable flag is set to true in the "
            "AndroidManifest.xml. This allows attackers to attach a "
            "debugger to the running process, inspect memory, and "
            "modify runtime behavior."
        )

        context_notes: list[str] = []
        if is_platform_signed:
            context_notes.append(
                "This APK is platform-signed, making debuggable access "
                "critically dangerous — an attacker can inspect a "
                "system-privileged process, leak platform signing keys, "
                "and bypass SELinux MAC policies."
            )
        if is_debug_signed:
            context_notes.append(
                "This APK appears to be signed with a debug/test "
                "certificate, suggesting it may be a development build "
                "rather than a production release."
            )
        if target_sdk >= 28:
            context_notes.append(
                f"With targetSdk={target_sdk} (≥28), Android Gradle "
                "Plugin strips android:debuggable in release builds by "
                "default — its presence here is suspicious and may "
                "indicate a debug build leaked into production."
            )

        if context_notes:
            description = base_desc + " " + " ".join(context_notes)
        else:
            description = (
                base_desc + " Debug builds should never be shipped "
                "in production firmware."
            )

        # --- Evidence enrichment ---
        evidence_parts = [f"android:debuggable={val}"]
        if target_sdk:
            evidence_parts.append(f"targetSdk={target_sdk}")
        if is_platform_signed:
            evidence_parts.append("platform_signed=true")
        if is_debug_signed:
            evidence_parts.append("debug_signed=true")

        return [
            ManifestFinding(
                check_id="MANIFEST-001",
                title="Application is debuggable",
                severity=severity,
                description=description,
                evidence=", ".join(evidence_parts),
                cwe_ids=["CWE-489"],
                confidence=confidence,
            )
        ]

    def _check_allow_backup(
        self,
        apk_obj: Any,
        *,
        is_platform_signed: bool = False,
        is_priv_app: bool = False,
    ) -> list[ManifestFinding]:
        """MANIFEST-002: android:allowBackup=true (or default) check.

        MobSF base severity: **medium** (CWE-921).

        Context-aware adjustments:
        - targetSdk ≥ 31 and explicitly set to true: escalate to **high**
          — the developer deliberately overrode Android 12's secure default,
          indicating intentional backup exposure.
        - Platform-signed priv-app: escalate to **high** — backup of a
          privileged system component can leak device-level secrets
          (Wi-Fi configs, VPN credentials, system settings).
        - targetSdk < 23 (pre-Marshmallow): add note about full backup
          extraction without user confirmation on older devices.
        """
        val = self._get_manifest_attr(apk_obj, "application", "allowBackup")

        # Default is true if attribute is absent (pre-Android 12)
        # Starting from targetSdk 31+, default changed to false
        target_sdk_str = apk_obj.get_target_sdk_version()
        try:
            target_sdk = int(target_sdk_str) if target_sdk_str else 0
        except (ValueError, TypeError):
            target_sdk = 0

        if val is not None and not self._is_true(val):
            # Explicitly set to false — no finding
            return []

        # If absent and targetSdk >= 31, default is false — no finding
        if val is None and target_sdk >= 31:
            return []

        # --- Determine if explicitly enabled vs. default ---
        explicitly_enabled = val is not None and self._is_true(val)

        evidence_detail = (
            f"android:allowBackup={val}"
            if val is not None
            else "android:allowBackup not set (defaults to true)"
        )

        # Confidence: high when explicitly set, medium when relying on default
        confidence = "high" if val is not None else "medium"

        # --- Severity adjustment based on context ---
        severity = "medium"  # MobSF base

        if explicitly_enabled and target_sdk >= 31:
            # Developer deliberately overrode Android 12's secure default
            # (backup is off by default for SDK ≥ 31).  This is a conscious
            # choice to expose data, warranting higher severity.
            severity = "high"

        if is_platform_signed and is_priv_app:
            # Privileged system components may store device-level secrets;
            # backup exposure is more severe than for regular apps.
            severity = "high"

        # --- Build context-enriched description ---
        base_desc = (
            "The application allows its data to be backed up via "
            "adb backup. An attacker with physical or ADB access can "
            "extract application data including databases, shared "
            "preferences, and internal files."
        )

        context_notes: list[str] = []

        if is_platform_signed and is_priv_app:
            context_notes.append(
                "This is a platform-signed privileged system app — "
                "backup can expose device-level secrets such as Wi-Fi "
                "configurations, VPN credentials, and system settings."
            )
        elif is_priv_app:
            context_notes.append(
                "This APK resides in /system/priv-app/ and may store "
                "sensitive device configuration data."
            )

        if explicitly_enabled and target_sdk >= 31:
            context_notes.append(
                f"With targetSdk={target_sdk} (≥31), Android 12+ "
                "defaults allowBackup to false — the developer "
                "deliberately overrode this secure default, indicating "
                "intentional backup exposure."
            )
        elif target_sdk and target_sdk < 23:
            context_notes.append(
                f"With targetSdk={target_sdk} (<23, pre-Marshmallow), "
                "full backup extraction can occur without user "
                "confirmation on older devices."
            )

        if context_notes:
            description = base_desc + " " + " ".join(context_notes)
        else:
            description = (
                base_desc + " For privileged system apps this is "
                "especially concerning as they may store sensitive "
                "device configuration."
            )

        # --- Evidence enrichment ---
        evidence_parts = [evidence_detail]
        if target_sdk:
            evidence_parts.append(f"targetSdk={target_sdk}")
        if is_platform_signed:
            evidence_parts.append("platform_signed=true")
        if is_priv_app:
            evidence_parts.append("priv_app=true")

        return [
            ManifestFinding(
                check_id="MANIFEST-002",
                title="Application allows backup",
                severity=severity,
                description=description,
                evidence=", ".join(evidence_parts),
                cwe_ids=["CWE-921"],
                confidence=confidence,
            )
        ]

    def _check_cleartext_traffic(
        self, apk_obj: Any
    ) -> list[ManifestFinding]:
        """MANIFEST-003: android:usesCleartextTraffic=true check.

        MobSF base severity: **high** (CWE-319).
        """
        val = self._get_manifest_attr(
            apk_obj, "application", "usesCleartextTraffic"
        )

        # Default is true for targetSdk < 28, false for >= 28
        target_sdk_str = apk_obj.get_target_sdk_version()
        try:
            target_sdk = int(target_sdk_str) if target_sdk_str else 0
        except (ValueError, TypeError):
            target_sdk = 0

        explicitly_true = self._is_true(val)
        default_true = val is None and target_sdk < 28

        if not explicitly_true and not default_true:
            return []

        evidence_detail = (
            f"android:usesCleartextTraffic={val}"
            if val is not None
            else f"android:usesCleartextTraffic not set (defaults to true for targetSdk={target_sdk})"
        )

        # Confidence: high when explicitly set, medium when relying on default
        confidence = "high" if explicitly_true else "medium"

        return [
            ManifestFinding(
                check_id="MANIFEST-003",
                title="Application permits cleartext HTTP traffic",
                severity="high",
                description=(
                    "The application allows cleartext (non-TLS) network "
                    "traffic. This exposes data in transit to eavesdropping "
                    "and man-in-the-middle attacks. Applications should "
                    "enforce HTTPS for all network communication."
                ),
                evidence=evidence_detail,
                cwe_ids=["CWE-319"],
                confidence=confidence,
            )
        ]

    def _check_test_only(self, apk_obj: Any) -> list[ManifestFinding]:
        """MANIFEST-004: android:testOnly=true check."""
        val = self._get_manifest_attr(apk_obj, "application", "testOnly")
        if not self._is_true(val):
            return []

        return [
            ManifestFinding(
                check_id="MANIFEST-004",
                title="Application is marked as test-only",
                severity="high",
                description=(
                    "The android:testOnly flag is set to true. Test-only "
                    "applications have relaxed security restrictions and "
                    "should never appear in production firmware. This flag "
                    "bypasses some system security checks and may indicate "
                    "a development build was shipped by mistake."
                ),
                evidence=f"android:testOnly={val}",
                cwe_ids=["CWE-489"],
            )
        ]

    def _check_min_sdk(
        self, apk_obj: Any
    ) -> list[ManifestFinding]:
        """MANIFEST-005: minSdkVersion too low check.

        MobSF base severity: **high** for critically outdated (<19),
        **medium** for outdated (<24), **info** when absent.
        """
        min_sdk_str = apk_obj.get_min_sdk_version()
        try:
            min_sdk = int(min_sdk_str) if min_sdk_str else None
        except (ValueError, TypeError):
            min_sdk = None

        if min_sdk is None:
            return [
                ManifestFinding(
                    check_id="MANIFEST-005",
                    title="minSdkVersion not specified",
                    severity="info",
                    description=(
                        "The minSdkVersion is not set in the manifest. "
                        "Without a minimum SDK constraint the app may run "
                        "on very old Android versions lacking critical "
                        "security patches."
                    ),
                    evidence="minSdkVersion not set",
                    cwe_ids=["CWE-1104"],
                    confidence="low",
                )
            ]

        findings: list[ManifestFinding] = []

        if min_sdk < _MIN_SDK_CRITICAL_THRESHOLD:
            findings.append(
                ManifestFinding(
                    check_id="MANIFEST-005",
                    title=f"Critically outdated minSdkVersion ({min_sdk})",
                    severity="high",
                    description=(
                        f"minSdkVersion is {min_sdk} (Android "
                        f"{_sdk_to_android_version(min_sdk)}), which is below "
                        f"API {_MIN_SDK_CRITICAL_THRESHOLD} (Android 4.4 KitKat). "
                        "This ancient API level lacks TLS 1.2 by default, "
                        "modern certificate pinning support, and many "
                        "security hardening features introduced in later "
                        "Android releases."
                    ),
                    evidence=f"minSdkVersion={min_sdk}",
                    cwe_ids=["CWE-1104"],
                )
            )
        elif min_sdk < _MIN_SDK_SECURE_THRESHOLD:
            findings.append(
                ManifestFinding(
                    check_id="MANIFEST-005",
                    title=f"Outdated minSdkVersion ({min_sdk})",
                    severity="low",
                    description=(
                        f"minSdkVersion is {min_sdk} (Android "
                        f"{_sdk_to_android_version(min_sdk)}), below "
                        f"API {_MIN_SDK_SECURE_THRESHOLD} (Android 7.0 Nougat). "
                        "This means the app supports devices that lack "
                        "file-based encryption, network security config "
                        "enforcement, and other modern security features."
                    ),
                    evidence=f"minSdkVersion={min_sdk}",
                    cwe_ids=["CWE-1104"],
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Exported component analysis (MANIFEST-006)
    # ------------------------------------------------------------------

    _COMPONENT_TAGS: list[tuple[str, str]] = [
        ("activity", "Activity"),
        ("activity-alias", "Activity-alias"),
        ("service", "Service"),
        ("receiver", "Broadcast Receiver"),
        ("provider", "Content Provider"),
    ]

    _NS_ANDROID = "http://schemas.android.com/apk/res/android"

    def _check_exported_components(
        self, apk_obj: Any
    ) -> list[ManifestFinding]:
        """MANIFEST-006: Exported components without permission protection.

        MobSF base severity: **high** for ≥5 components, **medium** for 2–4,
        **low** for 1.

        An exported component that declares no ``android:permission`` can be
        invoked by any app on the device, potentially leaking data or
        triggering privileged behaviour.

        Export is explicit (``android:exported="true"``) or implicit when
        the component has an ``<intent-filter>`` *and* targetSdk < 31
        (in targetSdk >= 31, exported must be explicit).
        """
        findings: list[ManifestFinding] = []

        try:
            manifest_xml = apk_obj.get_android_manifest_xml()
        except Exception as exc:
            logger.warning("Failed to parse manifest XML: %s", exc)
            return findings

        if manifest_xml is None:
            return findings

        # Determine targetSdk to know default export behaviour
        target_sdk_str = apk_obj.get_target_sdk_version()
        try:
            target_sdk = int(target_sdk_str) if target_sdk_str else 0
        except (ValueError, TypeError):
            target_sdk = 0

        ns = self._NS_ANDROID
        main_activity = apk_obj.get_main_activity()
        exported_unprotected: list[dict[str, str]] = []

        for tag_name, component_type in self._COMPONENT_TAGS:
            elements = manifest_xml.findall(f".//{tag_name}")
            for elem in elements:
                comp_name = (
                    elem.get(f"{{{ns}}}name")
                    or elem.get("name")
                    or "unknown"
                )

                # Determine if exported
                exported_attr = elem.get(f"{{{ns}}}exported") or elem.get("exported")
                has_intent_filter = len(elem.findall("intent-filter")) > 0

                if exported_attr is not None:
                    is_exported = exported_attr.lower() in ("true", "0xffffffff", "-1")
                else:
                    # Implicit export: components with intent-filters are
                    # exported by default when targetSdk < 31
                    if has_intent_filter and target_sdk < 31:
                        is_exported = True
                    elif tag_name == "provider":
                        # Content providers are exported by default when
                        # targetSdk < 17 (API 17 changed the default)
                        is_exported = target_sdk < 17
                    else:
                        is_exported = False

                if not is_exported:
                    continue

                # Check for permission protection on the component
                perm = elem.get(f"{{{ns}}}permission") or elem.get("permission")

                # For providers, also check readPermission / writePermission
                if tag_name == "provider":
                    read_perm = (
                        elem.get(f"{{{ns}}}readPermission")
                        or elem.get("readPermission")
                    )
                    write_perm = (
                        elem.get(f"{{{ns}}}writePermission")
                        or elem.get("writePermission")
                    )
                    if perm or (read_perm and write_perm):
                        continue
                elif perm:
                    continue

                # Skip the main launcher activity — it must be exported
                # and is inherently user-facing (not a meaningful finding)
                if comp_name == main_activity:
                    continue

                exported_unprotected.append({
                    "component": comp_name,
                    "type": component_type,
                    "has_intent_filter": str(has_intent_filter),
                    "explicit_export": str(exported_attr is not None),
                })

        if not exported_unprotected:
            return findings

        # Build evidence string
        evidence_lines = []
        for comp in exported_unprotected:
            export_note = (
                "explicitly exported"
                if comp["explicit_export"] == "True"
                else "implicitly exported (has intent-filter)"
            )
            evidence_lines.append(
                f"  {comp['type']}: {comp['component']} ({export_note})"
            )
        evidence = (
            f"{len(exported_unprotected)} exported component(s) without "
            f"permission:\n" + "\n".join(evidence_lines)
        )

        # Severity scales with exposed component count (MobSF baseline).
        # Firmware context bump (+1) is applied uniformly in
        # scan_manifest_security() for priv-app / platform-signed APKs.
        if len(exported_unprotected) >= 5:
            severity = "high"
        elif len(exported_unprotected) >= 2:
            severity = "medium"
        else:
            severity = "low"

        # Confidence: high when all components are explicitly exported,
        # medium when any are implicitly exported via intent-filter default
        all_explicit = all(
            c["explicit_export"] == "True" for c in exported_unprotected
        )
        confidence = "high" if all_explicit else "medium"

        findings.append(
            ManifestFinding(
                check_id="MANIFEST-006",
                title="Exported components without permission protection",
                severity=severity,
                description=(
                    "The application exports components that are accessible "
                    "to any other app on the device without requiring a "
                    "permission. Exported activities can be launched, exported "
                    "services can be bound to, exported receivers can receive "
                    "broadcasts, and exported providers can be queried — all "
                    "by third-party apps. This may allow unauthorized access "
                    "to sensitive functionality or data."
                ),
                evidence=evidence,
                cwe_ids=["CWE-926"],
                confidence=confidence,
            )
        )

        return findings

    # ------------------------------------------------------------------
    # Custom permissions with weak protectionLevel (MANIFEST-007)
    # ------------------------------------------------------------------

    # Protection levels that provide meaningful access control
    _STRONG_PROTECTION_LEVELS: set[str] = {
        "signature",
        "signatureorsystem",
        "signature|privileged",
        # Numeric value 0x02 = signature, 0x03 = signatureOrSystem
        "0x2", "0x02", "2",
        "0x3", "0x03", "3",
    }

    def _check_custom_permissions(
        self, apk_obj: Any
    ) -> list[ManifestFinding]:
        """MANIFEST-007: Custom permissions with weak protectionLevel.

        Apps that define custom ``<permission>`` elements with
        ``protectionLevel="normal"`` (default) or ``"dangerous"``
        provide weaker access control than ``"signature"`` or
        ``"signatureOrSystem"``.  Normal permissions are auto-granted;
        dangerous permissions only require user approval.  Only
        signature-level permissions ensure that the calling app is
        signed with the same key.
        """
        findings: list[ManifestFinding] = []

        try:
            manifest_xml = apk_obj.get_android_manifest_xml()
        except Exception as exc:
            logger.warning("Failed to parse manifest XML: %s", exc)
            return findings

        if manifest_xml is None:
            return findings

        ns = self._NS_ANDROID
        weak_perms: list[dict[str, str]] = []

        permission_elements = manifest_xml.findall(".//permission")
        for elem in permission_elements:
            perm_name = (
                elem.get(f"{{{ns}}}name")
                or elem.get("name")
                or "unknown"
            )

            protection_level = (
                elem.get(f"{{{ns}}}protectionLevel")
                or elem.get("protectionLevel")
            )

            # Default protectionLevel is "normal" (0x0) if not specified
            effective_level = (protection_level or "normal").strip().lower()

            if effective_level not in self._STRONG_PROTECTION_LEVELS:
                weak_perms.append({
                    "permission": perm_name,
                    "protectionLevel": protection_level or "(not set, defaults to normal)",
                })

        if not weak_perms:
            return findings

        evidence_lines = [
            f"  {wp['permission']} — protectionLevel={wp['protectionLevel']}"
            for wp in weak_perms
        ]
        evidence = (
            f"{len(weak_perms)} custom permission(s) with weak "
            f"protectionLevel:\n" + "\n".join(evidence_lines)
        )

        # Severity scales with count
        if len(weak_perms) >= 3:
            severity = "medium"
        else:
            severity = "low"

        findings.append(
            ManifestFinding(
                check_id="MANIFEST-007",
                title="Custom permissions with weak protectionLevel",
                severity=severity,
                description=(
                    "The application defines custom permissions with a "
                    "protectionLevel of 'normal' or 'dangerous' instead of "
                    "'signature'. Normal permissions are auto-granted to any "
                    "requesting app. Dangerous permissions only require user "
                    "consent. Only signature-level permissions ensure that "
                    "the calling app is signed with the same developer key, "
                    "providing meaningful access control. Third-party apps "
                    "could declare and obtain these permissions to access "
                    "protected components."
                ),
                evidence=evidence,
                cwe_ids=["CWE-732"],
                confidence="medium",
            )
        )

        return findings

    # ------------------------------------------------------------------
    # signatureOrSystem protection detection (for severity reduction)
    # ------------------------------------------------------------------

    # Protection levels that imply platform-level trust.  An APK that
    # *declares* permissions at these levels is enforcing platform-key
    # gating on its own components — a strong signal that it is a
    # legitimate system component rather than a third-party app that
    # happened to land in /system/priv-app/.
    _SIGNATURE_SYSTEM_LEVELS: set[str] = {
        "signature",
        "signatureorsystem",
        "signature|privileged",
        # Numeric values: 0x02 = signature, 0x03 = signatureOrSystem
        "0x2", "0x02", "2",
        "0x3", "0x03", "3",
    }

    # Well-known AOSP/OEM uses-permissions that require platform signing.
    # If an APK *requests* any of these, it was designed to run as a
    # platform-signed component.
    _PLATFORM_SIGNATURE_PERMISSIONS: set[str] = {
        "android.permission.INSTALL_PACKAGES",
        "android.permission.DELETE_PACKAGES",
        "android.permission.STATUS_BAR",
        "android.permission.STATUS_BAR_SERVICE",
        "android.permission.MANAGE_USERS",
        "android.permission.INTERACT_ACROSS_USERS",
        "android.permission.INTERACT_ACROSS_USERS_FULL",
        "android.permission.MANAGE_DEVICE_ADMINS",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.MASTER_CLEAR",
        "android.permission.REBOOT",
        "android.permission.SHUTDOWN",
        "android.permission.SET_TIME",
        "android.permission.WRITE_SECURE_SETTINGS",
        "android.permission.MODIFY_PHONE_STATE",
        "android.permission.CONNECTIVITY_INTERNAL",
        "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
        "android.permission.MANAGE_USB",
        "android.permission.CHANGE_COMPONENT_ENABLED_STATE",
        "android.permission.GRANT_RUNTIME_PERMISSIONS",
        "android.permission.REVOKE_RUNTIME_PERMISSIONS",
        "android.permission.MANAGE_APP_OPS_MODES",
    }

    def _has_signature_or_system_protection(
        self, apk_obj: Any
    ) -> bool:
        """Detect whether APK has signatureOrSystem-level protection.

        An APK is considered to have signatureOrSystem protection when
        **any** of these conditions is met:

        1. It **declares** one or more ``<permission>`` elements with a
           ``protectionLevel`` of ``signature``, ``signatureOrSystem``,
           or ``signature|privileged``.
        2. It **requests** (via ``<uses-permission>``) a well-known
           platform-signature permission that only platform-signed apps
           can hold (e.g., ``INSTALL_PACKAGES``, ``WRITE_SECURE_SETTINGS``).
        3. It has ``android:sharedUserId="android.uid.system"`` or
           ``android:sharedUserId="android.uid.phone"`` — explicit system
           UID sharing requires platform signing.

        These heuristics are lightweight (manifest-only, no crypto
        verification) and designed to have **high precision / low recall**:
        if any signal fires, the APK is almost certainly a genuine system
        component, justifying severity reduction.
        """
        # --- Check 1: declared permissions with signature protection -----
        try:
            manifest_xml = apk_obj.get_android_manifest_xml()
        except Exception:
            return False

        if manifest_xml is None:
            return False

        ns = self._NS_ANDROID

        for elem in manifest_xml.findall(".//permission"):
            protection = (
                elem.get(f"{{{ns}}}protectionLevel")
                or elem.get("protectionLevel")
            )
            if protection and protection.strip().lower() in self._SIGNATURE_SYSTEM_LEVELS:
                return True

        # --- Check 2: uses well-known platform-signature permissions -----
        requested_perms: set[str] = set()
        try:
            perms = apk_obj.get_permissions()
            if perms:
                requested_perms = set(perms)
        except Exception:
            pass

        if requested_perms & self._PLATFORM_SIGNATURE_PERMISSIONS:
            return True

        # --- Check 3: sharedUserId = android.uid.system / phone ----------
        shared_uid = None
        try:
            shared_uid = (
                manifest_xml.get(f"{{{ns}}}sharedUserId")
                or manifest_xml.get("sharedUserId")
            )
        except Exception:
            pass

        if shared_uid and shared_uid in (
            "android.uid.system",
            "android.uid.phone",
            "android.uid.bluetooth",
            "android.uid.nfc",
        ):
            return True

        return False

    # ------------------------------------------------------------------
    # StrandHogg 1.0 task hijacking (MANIFEST-008)
    # ------------------------------------------------------------------

    # launchMode values that make StrandHogg 1.0 exploitable when
    # combined with a non-default taskAffinity
    _STRANDHOGG_V1_LAUNCH_MODES: set[str] = {
        "singletask",
        "singleinstance",
    }

    def _check_strandhogg_v1(
        self, apk_obj: Any
    ) -> list[ManifestFinding]:
        """MANIFEST-008: StrandHogg 1.0 task hijacking via taskAffinity.

        MobSF base severity: **high** (CWE-1021).

        StrandHogg 1.0 (CVE-2020-0096) exploits the Android task/activity
        stack by combining a non-default ``taskAffinity`` with either
        ``allowTaskReparenting=true`` or a ``launchMode`` of
        ``singleTask``/``singleInstance``.  A malicious app can inject its
        activity into the victim app's task stack, presenting a phishing
        UI while the user believes they are interacting with the
        legitimate application.

        An empty ``taskAffinity=""`` is also suspicious: it opts the
        activity out of the default task grouping, which may be intentional
        but is a prerequisite for reparenting attacks.
        """
        findings: list[ManifestFinding] = []

        try:
            manifest_xml = apk_obj.get_android_manifest_xml()
        except Exception as exc:
            logger.warning("Failed to parse manifest XML: %s", exc)
            return findings

        if manifest_xml is None:
            return findings

        ns = self._NS_ANDROID
        package = apk_obj.get_package() or ""
        vulnerable_activities: list[dict[str, str]] = []

        for elem in manifest_xml.findall(".//activity"):
            activity_name = (
                elem.get(f"{{{ns}}}name") or elem.get("name") or "unknown"
            )

            # --- taskAffinity ---
            task_affinity = (
                elem.get(f"{{{ns}}}taskAffinity")
                or elem.get("taskAffinity")
            )
            # Default taskAffinity equals the package name; only flag
            # activities that deviate from the default.
            if task_affinity is None:
                continue  # uses default (package name) — not vulnerable
            # Empty string or a different package's affinity are suspicious
            affinity_is_empty = task_affinity.strip() == ""
            affinity_is_foreign = (
                not affinity_is_empty and task_affinity != package
            )
            if not affinity_is_empty and not affinity_is_foreign:
                continue  # matches own package — safe

            # --- Check for enabling conditions ---
            allow_reparenting = elem.get(
                f"{{{ns}}}allowTaskReparenting"
            ) or elem.get("allowTaskReparenting")
            reparenting_enabled = (
                allow_reparenting is not None
                and allow_reparenting.lower() in ("true", "0xffffffff", "-1")
            )

            launch_mode = (
                elem.get(f"{{{ns}}}launchMode") or elem.get("launchMode")
            )
            risky_launch_mode = (
                launch_mode is not None
                and launch_mode.strip().lower() in self._STRANDHOGG_V1_LAUNCH_MODES
            )

            if not reparenting_enabled and not risky_launch_mode:
                # Non-default affinity alone is informational — only flag
                # when combined with an enabling condition.
                continue

            reasons: list[str] = []
            if affinity_is_empty:
                reasons.append('taskAffinity=""')
            else:
                reasons.append(f'taskAffinity="{task_affinity}"')
            if reparenting_enabled:
                reasons.append("allowTaskReparenting=true")
            if risky_launch_mode:
                reasons.append(f"launchMode={launch_mode}")

            vulnerable_activities.append({
                "activity": activity_name,
                "detail": ", ".join(reasons),
            })

        if not vulnerable_activities:
            return findings

        evidence_lines = [
            f"  {va['activity']}: {va['detail']}"
            for va in vulnerable_activities
        ]
        evidence = (
            f"{len(vulnerable_activities)} activity(ies) vulnerable to "
            f"StrandHogg 1.0 task hijacking:\n"
            + "\n".join(evidence_lines)
        )

        findings.append(
            ManifestFinding(
                check_id="MANIFEST-008",
                title="StrandHogg 1.0 task hijacking vulnerability",
                severity="high",
                description=(
                    "One or more activities declare a non-default "
                    "taskAffinity combined with allowTaskReparenting=true "
                    "or a launchMode of singleTask/singleInstance. This "
                    "configuration allows a malicious app to hijack the "
                    "application's task stack by inserting its own activity, "
                    "enabling phishing attacks that impersonate the "
                    "legitimate app's UI (StrandHogg 1.0 / CVE-2020-0096). "
                    "Users believe they are interacting with the real app "
                    "while providing credentials or sensitive data to the "
                    "attacker."
                ),
                evidence=evidence,
                cwe_ids=["CWE-1021"],
                confidence="medium",
            )
        )

        return findings

    # ------------------------------------------------------------------
    # StrandHogg 2.0 task hijacking (MANIFEST-009)
    # ------------------------------------------------------------------

    def _check_strandhogg_v2(
        self, apk_obj: Any
    ) -> list[ManifestFinding]:
        """MANIFEST-009: StrandHogg 2.0 task hijacking via launchMode.

        MobSF base severity: **high** (CWE-1021), reduced to **low** when
        ``minSdk >= 29`` (OS-level mitigation present).

        StrandHogg 2.0 (CVE-2020-0096) is a privilege-escalation variant
        that does *not* require a specific taskAffinity.  Activities with
        ``launchMode="singleInstance"`` or ``"singleTask"`` create a
        separate task back-stack entry.  On Android < 10 (API 29) the
        system does not verify the calling app's identity, allowing any
        app to invoke these activities and position a malicious overlay
        on top.

        This check flags activities that use these launch modes and are
        also exported (reachable by other apps), especially when the
        app's minSdk is below 29 (where the OS-level fix was applied).
        """
        findings: list[ManifestFinding] = []

        try:
            manifest_xml = apk_obj.get_android_manifest_xml()
        except Exception as exc:
            logger.warning("Failed to parse manifest XML: %s", exc)
            return findings

        if manifest_xml is None:
            return findings

        ns = self._NS_ANDROID

        # Check minSdk — Android 10 (API 29) patched the OS-level vuln
        min_sdk_str = apk_obj.get_min_sdk_version()
        try:
            min_sdk = int(min_sdk_str) if min_sdk_str else 0
        except (ValueError, TypeError):
            min_sdk = 0

        target_sdk_str = apk_obj.get_target_sdk_version()
        try:
            target_sdk = int(target_sdk_str) if target_sdk_str else 0
        except (ValueError, TypeError):
            target_sdk = 0

        main_activity = apk_obj.get_main_activity()
        risky_activities: list[dict[str, str]] = []

        for elem in manifest_xml.findall(".//activity"):
            activity_name = (
                elem.get(f"{{{ns}}}name") or elem.get("name") or "unknown"
            )

            launch_mode = (
                elem.get(f"{{{ns}}}launchMode") or elem.get("launchMode")
            )
            if (
                launch_mode is None
                or launch_mode.strip().lower()
                not in self._STRANDHOGG_V1_LAUNCH_MODES  # same risky set
            ):
                continue

            # Check if the activity is exported
            exported_attr = (
                elem.get(f"{{{ns}}}exported") or elem.get("exported")
            )
            has_intent_filter = len(elem.findall("intent-filter")) > 0

            if exported_attr is not None:
                is_exported = exported_attr.lower() in (
                    "true", "0xffffffff", "-1"
                )
            else:
                # Implicit export via intent-filter for targetSdk < 31
                is_exported = has_intent_filter and target_sdk < 31

            if not is_exported:
                continue

            # Skip main activity — it must be exported and is always
            # singleTask in many apps for a good reason
            if activity_name == main_activity:
                continue

            risky_activities.append({
                "activity": activity_name,
                "launchMode": launch_mode.strip(),
                "exported": "explicit" if exported_attr else "implicit",
            })

        if not risky_activities:
            return findings

        evidence_lines = [
            f"  {ra['activity']}: launchMode={ra['launchMode']}, "
            f"exported ({ra['exported']})"
            for ra in risky_activities
        ]
        evidence = (
            f"{len(risky_activities)} exported activity(ies) with risky "
            f"launchMode:\n" + "\n".join(evidence_lines)
        )

        # Severity depends on whether the OS-level fix applies.
        # Firmware context bump (+1) is applied uniformly in
        # scan_manifest_security() for priv-app / platform-signed APKs.
        if min_sdk >= 29:
            # OS patched at API 29 — lower risk
            severity = "low"
            confidence = "low"  # OS-level mitigation makes exploitation unlikely
            evidence += (
                f"\nNote: minSdk={min_sdk} (>= 29) — OS-level mitigation "
                "present, but app-level risk remains for overlay attacks."
            )
        else:
            severity = "high"
            confidence = "medium"  # Pattern match; exploitability depends on context

        findings.append(
            ManifestFinding(
                check_id="MANIFEST-009",
                title="StrandHogg 2.0 task hijacking risk",
                severity=severity,
                description=(
                    "Exported activities with launchMode singleTask or "
                    "singleInstance create separate task back-stack entries "
                    "that can be exploited by malicious apps to overlay "
                    "phishing UIs (StrandHogg 2.0 / CVE-2020-0096). On "
                    "Android < 10 (API 29) the OS does not verify the "
                    "calling app's identity, enabling seamless UI hijacking. "
                    "Even on patched OS versions, exported activities with "
                    "these launch modes present a broader attack surface."
                ),
                evidence=evidence,
                cwe_ids=["CWE-1021"],
                confidence=confidence,
            )
        )

        return findings

    # ------------------------------------------------------------------
    # App Links / Browsable intent validation (MANIFEST-010)
    # ------------------------------------------------------------------

    def _check_app_links(
        self, apk_obj: Any
    ) -> list[ManifestFinding]:
        """MANIFEST-010: Browsable activities and Android App Links validation.

        Activities with ``<intent-filter>`` containing
        ``<category android:name="android.intent.category.BROWSABLE"/>``
        and a ``<data>`` element with ``android:scheme="http"`` or
        ``"https"`` handle web URLs.  Without ``android:autoVerify="true"``
        on the intent-filter, the system shows a disambiguation dialog
        instead of sending the URL directly to the app, and any app can
        register the same scheme+host, enabling phishing via intent
        interception.

        This check flags:
        1. Browsable activities handling http/https without autoVerify
        2. Browsable activities using custom schemes (potential deep link
           hijacking since custom schemes have no ownership verification)
        """
        findings: list[ManifestFinding] = []

        try:
            manifest_xml = apk_obj.get_android_manifest_xml()
        except Exception as exc:
            logger.warning("Failed to parse manifest XML: %s", exc)
            return findings

        if manifest_xml is None:
            return findings

        ns = self._NS_ANDROID
        unverified_http_links: list[dict[str, str]] = []
        custom_scheme_links: list[dict[str, str]] = []

        _WEB_SCHEMES = {"http", "https"}

        for elem in manifest_xml.findall(".//activity"):
            activity_name = (
                elem.get(f"{{{ns}}}name") or elem.get("name") or "unknown"
            )

            for intent_filter in elem.findall("intent-filter"):
                # Check for BROWSABLE category
                categories = intent_filter.findall("category")
                is_browsable = any(
                    (
                        cat.get(f"{{{ns}}}name") or cat.get("name") or ""
                    ) == "android.intent.category.BROWSABLE"
                    for cat in categories
                )
                if not is_browsable:
                    continue

                # Check for VIEW action (required for app links)
                actions = intent_filter.findall("action")
                has_view_action = any(
                    (
                        act.get(f"{{{ns}}}name") or act.get("name") or ""
                    ) == "android.intent.action.VIEW"
                    for act in actions
                )

                # Check autoVerify on the intent-filter
                auto_verify = (
                    intent_filter.get(f"{{{ns}}}autoVerify")
                    or intent_filter.get("autoVerify")
                )
                is_auto_verified = (
                    auto_verify is not None
                    and auto_verify.lower() in ("true", "0xffffffff", "-1")
                )

                # Examine <data> elements for schemes and hosts
                data_elements = intent_filter.findall("data")
                schemes: set[str] = set()
                hosts: set[str] = set()

                for data_elem in data_elements:
                    scheme = (
                        data_elem.get(f"{{{ns}}}scheme")
                        or data_elem.get("scheme")
                    )
                    host = (
                        data_elem.get(f"{{{ns}}}host")
                        or data_elem.get("host")
                    )
                    if scheme:
                        schemes.add(scheme.lower())
                    if host:
                        hosts.add(host)

                web_schemes = schemes & _WEB_SCHEMES
                custom_schemes = schemes - _WEB_SCHEMES - {"", "content", "file"}

                # Flag 1: http/https without autoVerify
                if web_schemes and has_view_action and not is_auto_verified:
                    host_str = ", ".join(sorted(hosts)) if hosts else "(any host)"
                    unverified_http_links.append({
                        "activity": activity_name,
                        "schemes": ", ".join(sorted(web_schemes)),
                        "hosts": host_str,
                    })

                # Flag 2: Custom schemes (no verification mechanism exists)
                if custom_schemes and has_view_action:
                    custom_scheme_links.append({
                        "activity": activity_name,
                        "schemes": ", ".join(sorted(custom_schemes)),
                        "hosts": ", ".join(sorted(hosts)) if hosts else "(any)",
                    })

        # Build findings for unverified HTTP/HTTPS app links
        if unverified_http_links:
            evidence_lines = [
                f"  {link['activity']}: {link['schemes']}://{link['hosts']}"
                for link in unverified_http_links
            ]
            evidence = (
                f"{len(unverified_http_links)} browsable activity(ies) "
                f"handling web URLs without autoVerify:\n"
                + "\n".join(evidence_lines)
            )

            findings.append(
                ManifestFinding(
                    check_id="MANIFEST-010",
                    title="Unverified App Links (http/https without autoVerify)",
                    severity="medium",
                    description=(
                        "Activities handle http/https URLs via browsable "
                        "intent filters but do not set autoVerify=\"true\". "
                        "Without Digital Asset Links verification, any app "
                        "can register the same URL patterns and intercept "
                        "links intended for this application. This enables "
                        "phishing attacks where a malicious app captures "
                        "login URLs, OAuth callbacks, or password reset "
                        "links. The system will show a disambiguation dialog "
                        "instead of routing directly to this app, degrading "
                        "user experience and security."
                    ),
                    evidence=evidence,
                    cwe_ids=["CWE-939"],
                    confidence="medium",
                )
            )

        # Build findings for custom scheme deep links
        if custom_scheme_links:
            evidence_lines = [
                f"  {link['activity']}: {link['schemes']}:// "
                f"(hosts: {link['hosts']})"
                for link in custom_scheme_links
            ]
            evidence = (
                f"{len(custom_scheme_links)} activity(ies) using custom "
                f"URL schemes:\n" + "\n".join(evidence_lines)
            )

            findings.append(
                ManifestFinding(
                    check_id="MANIFEST-010",
                    title="Custom URL scheme deep links (no verification possible)",
                    severity="low",
                    description=(
                        "Activities register custom URL schemes for deep "
                        "linking. Unlike http/https App Links, custom "
                        "schemes (e.g. myapp://) have no ownership "
                        "verification mechanism — any app can register the "
                        "same scheme. If the app uses custom scheme deep "
                        "links for sensitive operations (OAuth callbacks, "
                        "payment confirmations, etc.), a malicious app could "
                        "register the same scheme and intercept these intents."
                    ),
                    evidence=evidence,
                    cwe_ids=["CWE-939"],
                    confidence="low",
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Network Security Config analysis (MANIFEST-011)
    # ------------------------------------------------------------------

    def _check_network_security_config(
        self, apk_obj: Any
    ) -> list[ManifestFinding]:
        """MANIFEST-011: Network Security Configuration analysis.

        Parses the ``network_security_config.xml`` resource (if present)
        and flags:
        - Cleartext traffic allowed globally or per-domain
        - User-installed CA certificates trusted (enables MITM)
        - Missing or weak certificate pinning configuration
        - Overly permissive domain configurations
        - Pin expiration issues

        Reference:
        https://developer.android.com/training/articles/security-config
        """
        findings: list[ManifestFinding] = []

        # 1) Check if a network security config is referenced
        nsc_ref = self._get_manifest_attr(
            apk_obj, "application", "networkSecurityConfig"
        )

        if nsc_ref is None:
            # No custom NSC — behaviour governed by usesCleartextTraffic
            # and targetSdk defaults. Absence is not a finding by itself
            # (covered by MANIFEST-003).
            return []

        # 2) Resolve and parse the XML resource
        nsc_xml = self._extract_network_security_config_xml(apk_obj, nsc_ref)
        if nsc_xml is None:
            findings.append(
                ManifestFinding(
                    check_id="MANIFEST-011",
                    title="Network security config referenced but not found",
                    severity="info",
                    description=(
                        "The manifest declares android:networkSecurityConfig "
                        f"pointing to '{nsc_ref}', but the resource could not "
                        "be extracted from the APK. The runtime will use "
                        "default network security settings."
                    ),
                    evidence=f"android:networkSecurityConfig=\"{nsc_ref}\"",
                    cwe_ids=["CWE-295"],
                    confidence="medium",
                )
            )
            return findings

        try:
            root = ET.fromstring(nsc_xml)
        except ET.ParseError as exc:
            findings.append(
                ManifestFinding(
                    check_id="MANIFEST-011",
                    title="Malformed network security config XML",
                    severity="low",
                    description=(
                        f"Failed to parse network_security_config: {exc}. "
                        "The runtime may ignore this config entirely, "
                        "falling back to default (less secure) behaviour."
                    ),
                    evidence=f"Parse error: {exc}",
                    cwe_ids=["CWE-436"],
                    confidence="medium",
                )
            )
            return findings

        # 3) Analyse <base-config>
        findings.extend(self._analyse_nsc_base_config(root))

        # 4) Analyse <domain-config> entries
        findings.extend(self._analyse_nsc_domain_configs(root))

        # 5) Analyse <debug-overrides>
        findings.extend(self._analyse_nsc_debug_overrides(root))

        return findings

    # -- NSC XML extraction -------------------------------------------------

    @staticmethod
    def _extract_network_security_config_xml(
        apk_obj: Any, nsc_ref: str
    ) -> str | None:
        """Attempt to extract the network security config XML content.

        The ``nsc_ref`` value is typically ``@xml/network_security_config``
        or a direct resource reference.  We try multiple strategies to
        locate the actual XML within the APK.
        """
        # Derive the likely filename from the resource reference
        # e.g. "@xml/network_security_config" → "res/xml/network_security_config.xml"
        if nsc_ref.startswith("@xml/"):
            res_name = nsc_ref[5:]  # strip "@xml/"
        elif nsc_ref.startswith("@"):
            # Could be @xml/foo or other resource type
            parts = nsc_ref.lstrip("@").split("/", 1)
            res_name = parts[-1] if len(parts) == 2 else nsc_ref
        else:
            # Could be a raw hex resource ID
            res_name = "network_security_config"

        candidate_paths = [
            f"res/xml/{res_name}.xml",
            f"r/x/{res_name}.xml",  # obfuscated resource paths
            f"res/xml/network_security_config.xml",  # fallback common name
        ]

        # Try to get the file from the APK
        for path in candidate_paths:
            try:
                data = apk_obj.get_file(path)
                if data:
                    # Androguard may return bytes or string
                    if isinstance(data, bytes):
                        return data.decode("utf-8", errors="replace")
                    return str(data)
            except Exception:
                continue

        # Try via Androguard's AXML parser for compiled XML
        try:
            from androguard.core.axml import AXMLPrinter

            for path in candidate_paths:
                try:
                    data = apk_obj.get_file(path)
                    if data:
                        axml = AXMLPrinter(data)
                        xml_str = axml.get_xml()
                        if isinstance(xml_str, bytes):
                            return xml_str.decode("utf-8", errors="replace")
                        return str(xml_str)
                except Exception:
                    continue
        except ImportError:
            pass

        return None

    # -- NSC base-config analysis -------------------------------------------

    def _analyse_nsc_base_config(
        self, root: ET.Element
    ) -> list[ManifestFinding]:
        """Analyse the <base-config> element of a network security config."""
        findings: list[ManifestFinding] = []

        base_config = root.find("base-config")
        if base_config is None:
            return findings

        # Check cleartextTrafficPermitted on base-config
        cleartext = base_config.get("cleartextTrafficPermitted", "").lower()
        if cleartext == "true":
            findings.append(
                ManifestFinding(
                    check_id="MANIFEST-011",
                    title="Network security config allows cleartext traffic globally",
                    severity="high",
                    description=(
                        "The <base-config> element explicitly permits "
                        "cleartext (HTTP) traffic for all domains. This "
                        "exposes all network communication to eavesdropping "
                        "and modification. Even when individual domain "
                        "configs override this, the broad default is risky "
                        "as new domains added to the app will inherit "
                        "cleartext permission."
                    ),
                    evidence='<base-config cleartextTrafficPermitted="true">',
                    cwe_ids=["CWE-319"],
                )
            )

        # Check trust-anchors in base-config
        findings.extend(
            self._check_trust_anchors(base_config, context="base-config")
        )

        return findings

    # -- NSC domain-config analysis -----------------------------------------

    def _analyse_nsc_domain_configs(
        self, root: ET.Element
    ) -> list[ManifestFinding]:
        """Analyse all <domain-config> elements."""
        findings: list[ManifestFinding] = []

        for domain_config in root.findall("domain-config"):
            domains = [
                d.text.strip() if d.text else "*"
                for d in domain_config.findall("domain")
            ]
            domain_str = ", ".join(domains) if domains else "(no domains)"
            include_subdomains = any(
                d.get("includeSubdomains", "").lower() == "true"
                for d in domain_config.findall("domain")
            )
            subdomain_note = " (including subdomains)" if include_subdomains else ""

            # a) Cleartext traffic per-domain
            cleartext = domain_config.get(
                "cleartextTrafficPermitted", ""
            ).lower()
            if cleartext == "true":
                findings.append(
                    ManifestFinding(
                        check_id="MANIFEST-011",
                        title=f"Cleartext traffic permitted for specific domains",
                        severity="medium",
                        description=(
                            f"The network security config allows cleartext "
                            f"HTTP traffic for: {domain_str}{subdomain_note}. "
                            f"This may be intentional for local development "
                            f"or legacy services, but exposes communication "
                            f"with these domains to interception."
                        ),
                        evidence=(
                            f'<domain-config cleartextTrafficPermitted="true"> '
                            f"domains: {domain_str}"
                        ),
                        cwe_ids=["CWE-319"],
                        confidence="high",
                    )
                )

            # Wildcard / overly broad domains
            for d in domain_config.findall("domain"):
                dtext = (d.text or "").strip()
                inc_sub = d.get("includeSubdomains", "").lower() == "true"
                # Flag very broad domains like bare TLDs with includeSubdomains
                if inc_sub and dtext.count(".") == 0 and dtext:
                    findings.append(
                        ManifestFinding(
                            check_id="MANIFEST-011",
                            title="Overly broad domain in network security config",
                            severity="high",
                            description=(
                                f"The domain '{dtext}' with "
                                f"includeSubdomains=\"true\" matches an "
                                f"extremely broad set of hostnames. This "
                                f"likely captures unintended traffic."
                            ),
                            evidence=f'<domain includeSubdomains="true">{dtext}</domain>',
                            cwe_ids=["CWE-183"],
                            confidence="medium",
                        )
                    )

            # b) Trust anchors per-domain
            findings.extend(
                self._check_trust_anchors(
                    domain_config, context=f"domain-config ({domain_str})"
                )
            )

            # c) Pin-set analysis per-domain
            findings.extend(
                self._check_pin_set(domain_config, domain_str)
            )

        return findings

    # -- NSC debug-overrides analysis ---------------------------------------

    def _analyse_nsc_debug_overrides(
        self, root: ET.Element
    ) -> list[ManifestFinding]:
        """Analyse the <debug-overrides> element."""
        findings: list[ManifestFinding] = []

        debug_overrides = root.find("debug-overrides")
        if debug_overrides is None:
            return findings

        # debug-overrides only activate when android:debuggable=true,
        # but their presence is still worth noting

        trust_anchors = debug_overrides.find("trust-anchors")
        if trust_anchors is not None:
            user_certs = [
                c for c in trust_anchors.findall("certificates")
                if c.get("src", "").lower() == "user"
            ]
            if user_certs:
                findings.append(
                    ManifestFinding(
                        check_id="MANIFEST-011",
                        title="Debug overrides trust user-installed certificates",
                        severity="info",
                        description=(
                            "The <debug-overrides> section trusts "
                            "user-installed CA certificates. This is common "
                            "for development/debugging with proxy tools "
                            "(Burp Suite, mitmproxy) and only activates in "
                            "debuggable builds. Verify that release builds "
                            "do NOT set android:debuggable=true."
                        ),
                        evidence='<debug-overrides><trust-anchors><certificates src="user"/></trust-anchors></debug-overrides>',
                        cwe_ids=["CWE-295"],
                        confidence="low",
                    )
                )

        return findings

    # -- NSC shared helpers -------------------------------------------------

    @staticmethod
    def _check_trust_anchors(
        config_element: ET.Element, *, context: str
    ) -> list[ManifestFinding]:
        """Check <trust-anchors> within a config element for user cert trust."""
        findings: list[ManifestFinding] = []

        trust_anchors = config_element.find("trust-anchors")
        if trust_anchors is None:
            return findings

        for cert_elem in trust_anchors.findall("certificates"):
            src = cert_elem.get("src", "").lower()

            if src == "user":
                findings.append(
                    ManifestFinding(
                        check_id="MANIFEST-011",
                        title=f"User-installed CA certificates trusted ({context})",
                        severity="high",
                        description=(
                            f"The {context} trusts user-installed CA "
                            f"certificates. This allows any CA certificate "
                            f"installed by the user (or MDM) to intercept "
                            f"TLS traffic. An attacker with physical device "
                            f"access or MDM control can perform MitM attacks. "
                            f"Production apps should only trust system CAs "
                            f"unless there is a specific enterprise requirement."
                        ),
                        evidence=(
                            f"<trust-anchors><certificates src=\"user\"/> "
                            f"in {context}"
                        ),
                        cwe_ids=["CWE-295"],
                        confidence="high",
                    )
                )

            elif src not in ("system", ""):
                # Custom CA file — note it but don't flag as high
                findings.append(
                    ManifestFinding(
                        check_id="MANIFEST-011",
                        title=f"Custom CA certificate bundled ({context})",
                        severity="info",
                        description=(
                            f"The {context} includes a custom CA certificate "
                            f"file (src=\"{cert_elem.get('src')}\"). This is "
                            f"used for certificate pinning or connecting to "
                            f"servers with private CAs. Ensure the bundled "
                            f"certificate corresponds to a legitimate CA and "
                            f"has not been compromised."
                        ),
                        evidence=(
                            f"<certificates src=\"{cert_elem.get('src')}\"/> "
                            f"in {context}"
                        ),
                        cwe_ids=["CWE-295"],
                        confidence="low",
                    )
                )

            overridePins = cert_elem.get("overridePins", "").lower()
            if overridePins == "true":
                findings.append(
                    ManifestFinding(
                        check_id="MANIFEST-011",
                        title=f"Certificate pinning bypass enabled ({context})",
                        severity="high",
                        description=(
                            f"The {context} sets overridePins=\"true\" on a "
                            f"trust anchor. This means the trusted CA can "
                            f"bypass certificate pinning, effectively "
                            f"defeating the protection pinning provides. "
                            f"An attacker who compromises this CA (or installs "
                            f"their own CA when src=\"user\") can intercept "
                            f"pinned connections."
                        ),
                        evidence=(
                            f"<certificates overridePins=\"true\"/> in {context}"
                        ),
                        cwe_ids=["CWE-295"],
                        confidence="high",
                    )
                )

        return findings

    @staticmethod
    def _check_pin_set(
        domain_config: ET.Element, domain_str: str
    ) -> list[ManifestFinding]:
        """Analyse <pin-set> within a domain-config element."""
        findings: list[ManifestFinding] = []

        pin_set = domain_config.find("pin-set")
        if pin_set is None:
            # No pinning configured — not a finding by itself (many apps
            # don't pin), but absence is notable for high-security contexts
            return findings

        pins = pin_set.findall("pin")
        expiration = pin_set.get("expiration", "")

        if not pins:
            findings.append(
                ManifestFinding(
                    check_id="MANIFEST-011",
                    title=f"Empty pin-set for {domain_str}",
                    severity="medium",
                    description=(
                        f"A <pin-set> is declared for {domain_str} but "
                        f"contains no <pin> entries. This is effectively a "
                        f"no-op — the app declares intent to pin but has no "
                        f"actual pins, providing no additional security."
                    ),
                    evidence=f"<pin-set> with 0 pins for {domain_str}",
                    cwe_ids=["CWE-295"],
                    confidence="high",
                )
            )
            return findings

        # Check pin algorithms
        weak_pins = []
        for pin in pins:
            digest = pin.get("digest", "").upper()
            if digest and digest != "SHA-256":
                weak_pins.append(digest)

        if weak_pins:
            findings.append(
                ManifestFinding(
                    check_id="MANIFEST-011",
                    title=f"Weak pin digest algorithm for {domain_str}",
                    severity="medium",
                    description=(
                        f"Certificate pins for {domain_str} use digest "
                        f"algorithm(s): {', '.join(set(weak_pins))}. "
                        f"SHA-256 is the recommended minimum. Weaker "
                        f"algorithms may be vulnerable to collision attacks."
                    ),
                    evidence=(
                        f"Pin digests: {', '.join(set(weak_pins))} "
                        f"for {domain_str}"
                    ),
                    cwe_ids=["CWE-328"],
                    confidence="high",
                )
            )

        # Only one pin — no backup pin
        if len(pins) < 2:
            findings.append(
                ManifestFinding(
                    check_id="MANIFEST-011",
                    title=f"Single certificate pin without backup for {domain_str}",
                    severity="medium",
                    description=(
                        f"Only one certificate pin is configured for "
                        f"{domain_str}. Google recommends at least one "
                        f"backup pin to avoid bricking the app if the "
                        f"primary pinned certificate is rotated. Without "
                        f"a backup pin, a certificate rotation will cause "
                        f"complete connection failure."
                    ),
                    evidence=f"1 pin configured for {domain_str}",
                    cwe_ids=["CWE-295"],
                    confidence="medium",
                )
            )

        # Check expiration
        if expiration:
            findings.append(
                ManifestFinding(
                    check_id="MANIFEST-011",
                    title=f"Certificate pin expiration set for {domain_str}",
                    severity="info",
                    description=(
                        f"The pin-set for {domain_str} has an expiration "
                        f"date of {expiration}. After this date, pinning "
                        f"is disabled and the app falls back to normal "
                        f"certificate validation. Verify the expiration "
                        f"date is intentional and that pins will be "
                        f"refreshed before expiry via app updates."
                    ),
                    evidence=(
                        f'<pin-set expiration="{expiration}"> '
                        f"for {domain_str}"
                    ),
                    cwe_ids=["CWE-298"],
                    confidence="low",
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Task hijacking via allowTaskReparenting (MANIFEST-012)
    # ------------------------------------------------------------------

    def _check_allow_task_reparenting(
        self, apk_obj: Any
    ) -> list[ManifestFinding]:
        """MANIFEST-012: allowTaskReparenting=true enables task hijacking.

        When ``android:allowTaskReparenting="true"`` is set on an activity,
        Android may move that activity from the task that started it into
        the task of the app whose affinity it shares when that app next
        comes to the foreground.  A malicious app can exploit this to
        steal sensitive activities into its own task stack, enabling UI
        spoofing or data theft (CWE-926).
        """
        findings: list[ManifestFinding] = []

        try:
            manifest_xml = apk_obj.get_android_manifest_xml()
        except Exception:
            return findings

        if manifest_xml is None:
            return findings

        ns = self._NS_ANDROID

        # Check application-level default
        app_elem = manifest_xml.find(".//application")
        app_level_reparenting = False
        if app_elem is not None:
            val = app_elem.get(f"{{{ns}}}allowTaskReparenting") or app_elem.get(
                "allowTaskReparenting"
            )
            if val and val.lower() in ("true", "0xffffffff", "-1"):
                app_level_reparenting = True

        vulnerable_activities: list[str] = []

        for activity in manifest_xml.findall(".//activity"):
            name = (
                activity.get(f"{{{ns}}}name")
                or activity.get("name")
                or "unknown"
            )
            val = activity.get(f"{{{ns}}}allowTaskReparenting") or activity.get(
                "allowTaskReparenting"
            )
            # Activity inherits from application if not explicitly set
            if val is not None:
                activity_reparenting = val.lower() in ("true", "0xffffffff", "-1")
            else:
                activity_reparenting = app_level_reparenting

            if activity_reparenting:
                vulnerable_activities.append(name)

        if app_level_reparenting and not vulnerable_activities:
            # Application-level flag but no activities found — still flag it
            findings.append(
                ManifestFinding(
                    check_id="MANIFEST-012",
                    title="Application-level allowTaskReparenting enabled",
                    severity="medium",
                    description=(
                        "The <application> element sets "
                        "android:allowTaskReparenting=\"true\", which allows "
                        "all activities to be moved between task stacks. "
                        "A malicious app can hijack activities into its own "
                        "task by matching task affinity, enabling UI spoofing "
                        "or data interception."
                    ),
                    evidence='android:allowTaskReparenting="true" on <application>',
                    cwe_ids=["CWE-926"],
                    confidence="high",
                )
            )
        elif vulnerable_activities:
            for name in vulnerable_activities[:20]:
                findings.append(
                    ManifestFinding(
                        check_id="MANIFEST-012",
                        title=f"Activity allows task reparenting: {name}",
                        severity="medium",
                        description=(
                            f"Activity {name} has "
                            f"android:allowTaskReparenting=\"true\" (directly "
                            f"or inherited from <application>). This allows "
                            f"the activity to be moved to a different task "
                            f"stack at runtime, which a malicious app can "
                            f"exploit for UI spoofing or data theft."
                        ),
                        evidence=f'allowTaskReparenting="true" on {name}',
                        cwe_ids=["CWE-926"],
                        confidence="high",
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Implicit intent hijacking (MANIFEST-013)
    # ------------------------------------------------------------------

    def _check_implicit_intent_hijacking(
        self, apk_obj: Any
    ) -> list[ManifestFinding]:
        """MANIFEST-013: Exported components with intent filters vulnerable to hijacking.

        When a component declares an ``<intent-filter>``, Android
        implicitly marks it as exported (pre-API 31).  If such a component
        handles sensitive actions without requiring a permission, any app
        on the device can send intents to it, potentially intercepting or
        injecting data (CWE-927).

        This check focuses on **services** and **broadcast receivers**
        with intent filters but no permission protection — activities are
        already covered by MANIFEST-006 (exported components).
        """
        findings: list[ManifestFinding] = []

        try:
            manifest_xml = apk_obj.get_android_manifest_xml()
        except Exception:
            return findings

        if manifest_xml is None:
            return findings

        ns = self._NS_ANDROID

        for tag in ("service", "receiver"):
            for elem in manifest_xml.findall(f".//{tag}"):
                intent_filters = elem.findall("intent-filter")
                if not intent_filters:
                    continue

                name = (
                    elem.get(f"{{{ns}}}name")
                    or elem.get("name")
                    or "unknown"
                )

                # Check explicit exported status
                exported = elem.get(f"{{{ns}}}exported") or elem.get("exported")
                if exported and exported.lower() in ("false", "0x0", "0"):
                    continue  # Explicitly not exported

                # Check for permission protection
                perm = elem.get(f"{{{ns}}}permission") or elem.get("permission")
                if perm:
                    continue  # Protected by a permission

                # Collect action names for evidence
                actions: list[str] = []
                for intent_filter in intent_filters:
                    for action_elem in intent_filter.findall("action"):
                        action_name = (
                            action_elem.get(f"{{{ns}}}name")
                            or action_elem.get("name")
                        )
                        if action_name:
                            actions.append(action_name)

                component_type = tag.capitalize()
                findings.append(
                    ManifestFinding(
                        check_id="MANIFEST-013",
                        title=(
                            f"{component_type} with implicit intent: {name}"
                        ),
                        severity="medium",
                        description=(
                            f"{component_type} {name} declares intent filters "
                            f"without requiring a permission. Any app can send "
                            f"intents matching these filters, potentially "
                            f"triggering unintended behaviour or intercepting "
                            f"sensitive data. Consider adding "
                            f"android:permission or setting "
                            f'android:exported="false".'
                        ),
                        evidence=(
                            f"Intent actions: {', '.join(actions[:5])}"
                            if actions
                            else f"<intent-filter> on {tag} {name}"
                        ),
                        cwe_ids=["CWE-927"],
                        confidence="high" if actions else "medium",
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # APK signing scheme version (MANIFEST-014)
    # ------------------------------------------------------------------

    def _check_signing_scheme(
        self, apk_obj: Any
    ) -> list[ManifestFinding]:
        """MANIFEST-014: Check APK signing scheme version.

        APK Signature Scheme v1 (JAR signing) is vulnerable to the
        Janus vulnerability (CVE-2017-13156) on Android < 7.0 and
        doesn't protect all APK contents.  v2/v3 schemes provide
        whole-APK integrity verification and are required for modern
        Android versions (CWE-347).
        """
        findings: list[ManifestFinding] = []

        try:
            # Androguard can detect which signing schemes are present
            is_signed_v1 = False
            is_signed_v2 = False
            is_signed_v3 = False

            try:
                is_signed_v1 = apk_obj.is_signed_v1()
            except Exception:
                pass
            try:
                is_signed_v2 = apk_obj.is_signed_v2()
            except Exception:
                pass
            try:
                is_signed_v3 = apk_obj.is_signed_v3()
            except Exception:
                pass

            if not is_signed_v1 and not is_signed_v2 and not is_signed_v3:
                findings.append(
                    ManifestFinding(
                        check_id="MANIFEST-014",
                        title="APK is not signed",
                        severity="critical",
                        description=(
                            "The APK does not have any valid signature. "
                            "Unsigned APKs cannot be installed on Android "
                            "devices and indicate a development or tampered "
                            "build."
                        ),
                        evidence="No v1, v2, or v3 signature detected",
                        cwe_ids=["CWE-347"],
                        confidence="high",
                    )
                )
            elif is_signed_v1 and not is_signed_v2 and not is_signed_v3:
                findings.append(
                    ManifestFinding(
                        check_id="MANIFEST-014",
                        title="APK uses only v1 (JAR) signing scheme",
                        severity="medium",
                        description=(
                            "The APK is signed with only the v1 (JAR) "
                            "signing scheme. v1 signatures are vulnerable "
                            "to the Janus attack (CVE-2017-13156) on "
                            "Android < 7.0 and do not protect all APK "
                            "contents. APK Signature Scheme v2 or v3 "
                            "should be used for whole-file integrity."
                        ),
                        evidence="Signing: v1=true, v2=false, v3=false",
                        cwe_ids=["CWE-347"],
                        confidence="high",
                    )
                )
            elif is_signed_v1 and is_signed_v2 and not is_signed_v3:
                # v1+v2 is acceptable but v3 adds key rotation support
                findings.append(
                    ManifestFinding(
                        check_id="MANIFEST-014",
                        title="APK lacks v3 signing (no key rotation support)",
                        severity="info",
                        description=(
                            "The APK is signed with v1+v2 schemes but not "
                            "v3. APK Signature Scheme v3 adds key rotation "
                            "support, allowing certificates to be updated "
                            "without requiring a new package name. Consider "
                            "adding v3 signing for future-proofing."
                        ),
                        evidence="Signing: v1=true, v2=true, v3=false",
                        cwe_ids=["CWE-347"],
                        confidence="low",
                    )
                )
        except Exception as e:
            logger.debug("Signing scheme check failed: %s", e)

        return findings

    # ------------------------------------------------------------------
    # Backup agent (MANIFEST-015)
    # ------------------------------------------------------------------

    def _check_backup_agent(
        self, apk_obj: Any
    ) -> list[ManifestFinding]:
        """MANIFEST-015: Custom backup agent specified.

        When ``android:backupAgent`` is set, the app specifies a custom
        class to handle backup/restore operations.  If backup is also
        enabled (``android:allowBackup="true"`` or default), the backup
        agent may serialize sensitive data to cloud or local backup
        storage.  A custom agent is more concerning than default backup
        because it may intentionally include app secrets, tokens, or
        encryption keys in the backup payload (CWE-312).
        """
        findings: list[ManifestFinding] = []

        backup_agent = self._get_manifest_attr(
            apk_obj, "application", "backupAgent"
        )

        if backup_agent:
            # Check if allowBackup is also enabled
            allow_backup = self._get_manifest_attr(
                apk_obj, "application", "allowBackup"
            )
            backup_enabled = allow_backup is None or self._is_true(allow_backup)

            if backup_enabled:
                findings.append(
                    ManifestFinding(
                        check_id="MANIFEST-015",
                        title=f"Custom backup agent: {backup_agent}",
                        severity="medium",
                        description=(
                            f"The application specifies a custom backup agent "
                            f"class ({backup_agent}) with backup enabled. "
                            f"Custom backup agents control exactly what data "
                            f"is serialized during backup operations. If the "
                            f"agent includes sensitive data (tokens, keys, "
                            f"credentials), this data may be extracted from "
                            f"ADB backups or cloud backup storage. Review the "
                            f"backup agent implementation to verify no "
                            f"sensitive data is included."
                        ),
                        evidence=(
                            f'android:backupAgent="{backup_agent}", '
                            f'allowBackup="{allow_backup or "true (default)"}"'
                        ),
                        cwe_ids=["CWE-312"],
                        confidence="medium",
                    )
                )
            else:
                findings.append(
                    ManifestFinding(
                        check_id="MANIFEST-015",
                        title=f"Custom backup agent (backup disabled): {backup_agent}",
                        severity="info",
                        description=(
                            f"A custom backup agent ({backup_agent}) is "
                            f"declared but android:allowBackup is false. "
                            f"The backup agent is not currently active. "
                            f"If backup is re-enabled in the future, review "
                            f"the agent to ensure no sensitive data is "
                            f"serialized."
                        ),
                        evidence=(
                            f'android:backupAgent="{backup_agent}", '
                            f'allowBackup="false"'
                        ),
                        cwe_ids=["CWE-312"],
                        confidence="low",
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Dangerous/high-risk permissions (MANIFEST-016)
    # ------------------------------------------------------------------

    # High-risk permission groups for targeted findings
    _HIGH_RISK_PERMISSION_GROUPS: dict[str, tuple[str, str, str]] = {
        # permission -> (category, risk_description, cwe)
        "android.permission.SEND_SMS": (
            "SMS", "Can send SMS messages (potential toll fraud)", "CWE-284"
        ),
        "android.permission.RECEIVE_SMS": (
            "SMS", "Can intercept incoming SMS (OTP theft risk)", "CWE-284"
        ),
        "android.permission.READ_SMS": (
            "SMS", "Can read SMS messages (privacy/OTP theft)", "CWE-284"
        ),
        "android.permission.CALL_PHONE": (
            "Phone", "Can make calls without user interaction", "CWE-284"
        ),
        "android.permission.READ_CALL_LOG": (
            "Phone", "Can read call history (privacy risk)", "CWE-284"
        ),
        "android.permission.PROCESS_OUTGOING_CALLS": (
            "Phone", "Can intercept/redirect outgoing calls", "CWE-284"
        ),
        "android.permission.RECORD_AUDIO": (
            "Surveillance", "Can record audio from microphone", "CWE-284"
        ),
        "android.permission.CAMERA": (
            "Surveillance", "Can access camera for photos/video", "CWE-284"
        ),
        "android.permission.ACCESS_FINE_LOCATION": (
            "Location", "Can access precise GPS location", "CWE-284"
        ),
        "android.permission.ACCESS_BACKGROUND_LOCATION": (
            "Location", "Can access location in background", "CWE-284"
        ),
        "android.permission.READ_CONTACTS": (
            "PII", "Can read user contacts (data exfiltration)", "CWE-284"
        ),
        "android.permission.WRITE_CONTACTS": (
            "PII", "Can modify user contacts", "CWE-284"
        ),
        "android.permission.READ_CALENDAR": (
            "PII", "Can read calendar events (privacy risk)", "CWE-284"
        ),
        "android.permission.MANAGE_EXTERNAL_STORAGE": (
            "Storage", "Full access to shared storage (all files)", "CWE-284"
        ),
        "android.permission.REQUEST_INSTALL_PACKAGES": (
            "Install", "Can request to install other APKs", "CWE-284"
        ),
        "android.permission.SYSTEM_ALERT_WINDOW": (
            "Overlay", "Can draw over other apps (tapjacking)", "CWE-1021"
        ),
        "android.permission.BIND_ACCESSIBILITY_SERVICE": (
            "Accessibility", "Can observe and control UI (keylogging risk)", "CWE-284"
        ),
        "android.permission.BIND_DEVICE_ADMIN": (
            "Admin", "Can act as device administrator", "CWE-284"
        ),
        "android.permission.WRITE_SETTINGS": (
            "Settings", "Can modify system settings", "CWE-284"
        ),
        "android.permission.READ_PHONE_STATE": (
            "Phone", "Can read phone identity (IMEI, phone number)", "CWE-284"
        ),
    }

    def _check_dangerous_permissions(
        self, apk_obj: Any
    ) -> list[ManifestFinding]:
        """MANIFEST-016: High-risk and dangerous permissions usage.

        Flags permissions that represent significant privacy or security
        risks.  Rather than listing every dangerous permission (which
        would be noisy), this focuses on high-risk categories: SMS/phone
        abuse, surveillance (camera/mic), location tracking, overlay
        attacks, device admin, and accessibility abuse.
        """
        findings: list[ManifestFinding] = []

        try:
            permissions = apk_obj.get_permissions()
        except Exception:
            return findings

        if not permissions:
            return findings

        requested = set(permissions)

        # Group high-risk permissions by category
        by_category: dict[str, list[tuple[str, str, str]]] = {}
        for perm in requested:
            if perm in self._HIGH_RISK_PERMISSION_GROUPS:
                cat, desc, cwe = self._HIGH_RISK_PERMISSION_GROUPS[perm]
                by_category.setdefault(cat, []).append((perm, desc, cwe))

        for category, perms in sorted(by_category.items()):
            perm_names = [p[0].split(".")[-1] for p in perms]
            cwe_ids = list({p[2] for p in perms})

            severity = "medium"
            # Escalate for surveillance + SMS categories
            if category in ("Surveillance", "SMS", "Overlay", "Accessibility", "Admin"):
                severity = "high"

            findings.append(
                ManifestFinding(
                    check_id="MANIFEST-016",
                    title=f"High-risk {category} permissions requested",
                    severity=severity,
                    description=(
                        f"The app requests {len(perms)} high-risk "
                        f"{category.lower()}-related permission(s): "
                        + "; ".join(f"{p[0].split('.')[-1]} — {p[1]}" for p in perms)
                        + ". Verify these permissions are essential for "
                        f"the app's core functionality and that sensitive "
                        f"data access is properly justified."
                    ),
                    evidence=f"Permissions: {', '.join(perm_names)}",
                    cwe_ids=cwe_ids,
                    confidence="medium",
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Intent filter data scheme hijacking (MANIFEST-017)
    # ------------------------------------------------------------------

    # Schemes that are security-sensitive in intent filters
    _SENSITIVE_SCHEMES: dict[str, tuple[str, str]] = {
        "file": (
            "File URI scheme allows access to local files",
            "CWE-94",
        ),
        "content": (
            "Content URI scheme may expose content provider data",
            "CWE-200",
        ),
        "javascript": (
            "JavaScript URI scheme enables code injection in WebViews",
            "CWE-94",
        ),
        "data": (
            "Data URI scheme may enable content injection",
            "CWE-94",
        ),
    }

    def _check_intent_scheme_hijacking(
        self, apk_obj: Any
    ) -> list[ManifestFinding]:
        """MANIFEST-017: Insecure data URI schemes in intent filters.

        Intent filters that accept ``file://``, ``content://``,
        ``javascript://``, or ``data:`` URI schemes on exported
        components may enable local file access, content provider data
        leakage, or code injection through crafted intents (CWE-94,
        CWE-200).
        """
        findings: list[ManifestFinding] = []

        try:
            manifest_xml = apk_obj.get_android_manifest_xml()
        except Exception:
            return findings

        if manifest_xml is None:
            return findings

        ns = self._NS_ANDROID

        for tag in ("activity", "activity-alias", "service", "receiver"):
            for elem in manifest_xml.findall(f".//{tag}"):
                name = (
                    elem.get(f"{{{ns}}}name")
                    or elem.get("name")
                    or "unknown"
                )

                # Only check exported components (explicitly or implicitly)
                exported = elem.get(f"{{{ns}}}exported") or elem.get("exported")
                has_intent_filter = len(elem.findall("intent-filter")) > 0
                if exported and exported.lower() in ("false", "0x0", "0"):
                    continue
                if not exported and not has_intent_filter:
                    continue  # Not exported

                for intent_filter in elem.findall("intent-filter"):
                    for data_elem in intent_filter.findall("data"):
                        scheme = (
                            data_elem.get(f"{{{ns}}}scheme")
                            or data_elem.get("scheme")
                        )
                        if not scheme:
                            continue
                        scheme_lower = scheme.lower()

                        if scheme_lower in self._SENSITIVE_SCHEMES:
                            desc, cwe = self._SENSITIVE_SCHEMES[scheme_lower]
                            component_type = tag.replace("-", " ").title()

                            severity = "high"
                            if scheme_lower in ("javascript", "data"):
                                severity = "high"
                            elif scheme_lower == "file":
                                severity = "high"
                            else:
                                severity = "medium"

                            findings.append(
                                ManifestFinding(
                                    check_id="MANIFEST-017",
                                    title=(
                                        f"Insecure {scheme}:// scheme in "
                                        f"{component_type}: {name}"
                                    ),
                                    severity=severity,
                                    description=(
                                        f"{component_type} {name} accepts "
                                        f"intents with the {scheme}:// URI "
                                        f"scheme. {desc}. An attacker can "
                                        f"craft an intent with a malicious "
                                        f"{scheme}:// URI to exploit this "
                                        f"component."
                                    ),
                                    evidence=(
                                        f'<data android:scheme="{scheme}"> '
                                        f"in {tag} {name}"
                                    ),
                                    cwe_ids=[cwe],
                                    confidence="high",
                                )
                            )

        return findings

    # ------------------------------------------------------------------
    # Shared User ID (MANIFEST-018)
    # ------------------------------------------------------------------

    def _check_shared_user_id(
        self, apk_obj: Any
    ) -> list[ManifestFinding]:
        """MANIFEST-018: android:sharedUserId usage.

        The ``android:sharedUserId`` attribute is deprecated since
        API 29 (Android 10) and allows multiple apps signed with the
        same certificate to share a Linux UID, giving them access to
        each other's data directories.  This widens the attack surface:
        if *any* app sharing the UID is compromised, all other apps in
        the group are also exposed (CWE-250).

        System UIDs (``android.uid.system``, ``android.uid.phone``, etc.)
        are flagged at info level since they are expected for platform
        components.
        """
        findings: list[ManifestFinding] = []

        try:
            manifest_xml = apk_obj.get_android_manifest_xml()
        except Exception:
            return findings

        if manifest_xml is None:
            return findings

        ns = self._NS_ANDROID

        shared_uid = (
            manifest_xml.get(f"{{{ns}}}sharedUserId")
            or manifest_xml.get("sharedUserId")
        )

        if not shared_uid:
            return findings

        # Well-known system UIDs — expected for platform components
        system_uids = {
            "android.uid.system",
            "android.uid.phone",
            "android.uid.bluetooth",
            "android.uid.nfc",
            "android.uid.log",
            "android.uid.shell",
        }

        if shared_uid in system_uids:
            findings.append(
                ManifestFinding(
                    check_id="MANIFEST-018",
                    title=f"System sharedUserId: {shared_uid}",
                    severity="info",
                    description=(
                        f"The application uses sharedUserId=\"{shared_uid}\", "
                        f"a well-known system UID. This is expected for "
                        f"platform components but means the app runs with "
                        f"elevated system privileges. The sharedUserId "
                        f"attribute is deprecated since Android 10 (API 29)."
                    ),
                    evidence=f'android:sharedUserId="{shared_uid}"',
                    cwe_ids=["CWE-250"],
                    confidence="high",
                )
            )
        else:
            findings.append(
                ManifestFinding(
                    check_id="MANIFEST-018",
                    title=f"Custom sharedUserId: {shared_uid}",
                    severity="medium",
                    description=(
                        f"The application uses a custom "
                        f"sharedUserId=\"{shared_uid}\". Apps sharing this "
                        f"UID (and signed with the same certificate) can "
                        f"access each other's private data directories. "
                        f"If any app in the shared UID group is compromised, "
                        f"all others are also exposed. The sharedUserId "
                        f"attribute is deprecated since Android 10 (API 29) "
                        f"due to these security implications."
                    ),
                    evidence=f'android:sharedUserId="{shared_uid}"',
                    cwe_ids=["CWE-250"],
                    confidence="high",
                )
            )

        return findings


# ---------------------------------------------------------------------------
# Module-level helpers
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
