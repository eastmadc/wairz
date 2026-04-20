"""Backup and debug-flag manifest checks.

MANIFEST-001 (debuggable), MANIFEST-002 (allowBackup), MANIFEST-004
(testOnly), MANIFEST-015 (backupAgent).  These all inspect
``<application>``-level flags that control whether the APK can be
debugged or have its data extracted via backup.

The ``BackupAndDebugChecks`` class is composed by ``ManifestChecker``
and takes a reference to the outer scanner (``AndroguardService``) via
``__init__`` for future extensibility; none of the current methods
actually require scanner state, but preserving the convention keeps
the composition surface uniform across topic modules.
"""

from __future__ import annotations

from typing import Any

from app.services.manifest_checks._base import (
    ManifestFinding,
    _get_manifest_attr,
    _is_true,
)


class BackupAndDebugChecks:
    """Topic module for backup/debug-flag manifest checks."""

    def __init__(self, scanner: Any) -> None:
        self.scanner = scanner

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
        val = _get_manifest_attr(apk_obj, "application", "debuggable")
        if not _is_true(val):
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
        val = _get_manifest_attr(apk_obj, "application", "allowBackup")

        # Default is true if attribute is absent (pre-Android 12)
        # Starting from targetSdk 31+, default changed to false
        target_sdk_str = apk_obj.get_target_sdk_version()
        try:
            target_sdk = int(target_sdk_str) if target_sdk_str else 0
        except (ValueError, TypeError):
            target_sdk = 0

        if val is not None and not _is_true(val):
            # Explicitly set to false — no finding
            return []

        # If absent and targetSdk >= 31, default is false — no finding
        if val is None and target_sdk >= 31:
            return []

        # --- Determine if explicitly enabled vs. default ---
        explicitly_enabled = val is not None and _is_true(val)

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

    def _check_test_only(self, apk_obj: Any) -> list[ManifestFinding]:
        """MANIFEST-004: android:testOnly=true check."""
        val = _get_manifest_attr(apk_obj, "application", "testOnly")
        if not _is_true(val):
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

        backup_agent = _get_manifest_attr(
            apk_obj, "application", "backupAgent"
        )

        if backup_agent:
            # Check if allowBackup is also enabled
            allow_backup = _get_manifest_attr(
                apk_obj, "application", "allowBackup"
            )
            backup_enabled = allow_backup is None or _is_true(allow_backup)

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
