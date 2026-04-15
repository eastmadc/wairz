"""Factory for building mock Androguard APK objects from fixture manifests.

Usage in tests:

    from tests.fixtures.apk.mock_apk_factory import build_mock_apk
    from tests.fixtures.apk.apk_fixture_manifests import DEBUGGABLE_APK

    mock_apk = build_mock_apk(DEBUGGABLE_APK)
    # Pass to AndroguardService methods that accept an apk_obj

Or use the pytest fixtures from conftest_apk.py for convenience.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any
from unittest.mock import MagicMock

NS_ANDROID = "http://schemas.android.com/apk/res/android"


def build_mock_apk(fixture: dict[str, Any]) -> MagicMock:
    """Build a mock Androguard APK object from a fixture definition.

    The mock implements enough of the Androguard APK interface for
    AndroguardService.scan_manifest_security() to work correctly:
      - get_package()
      - get_min_sdk_version()
      - get_target_sdk_version()
      - get_main_activity()
      - get_android_manifest_xml()
      - get_attribute_value(tag, attr)
      - get_permissions()
      - get_file() — returns network_security_config XML if defined
      - get_certificates() — returns empty list (no real cert)
      - is_signed_v1() / is_signed_v2() / is_signed_v3()

    Args:
        fixture: A dict from apk_fixture_manifests.py with keys:
            xml, package, min_sdk, target_sdk, permissions,
            network_security_config (optional), signing_v1/v2/v3 (optional)

    Returns:
        A MagicMock that behaves like androguard.core.apk.APK
    """
    apk = MagicMock()
    manifest_tree = ET.fromstring(fixture["xml"])

    apk.get_package.return_value = fixture["package"]
    apk.get_min_sdk_version.return_value = fixture["min_sdk"]
    apk.get_target_sdk_version.return_value = fixture["target_sdk"]

    # Main activity: find the LAUNCHER intent-filter
    main_activity = None
    for activity in manifest_tree.iter("activity"):
        for intent_filter in activity.iter("intent-filter"):
            for cat in intent_filter.iter("category"):
                cat_name = cat.get(f"{{{NS_ANDROID}}}name", "")
                if "LAUNCHER" in cat_name:
                    main_activity = activity.get(f"{{{NS_ANDROID}}}name", "")
                    break
    apk.get_main_activity.return_value = main_activity

    # Manifest XML tree
    apk.get_android_manifest_xml.return_value = manifest_tree

    # Attribute extraction (used by _get_manifest_attr in androguard_service)
    def _get_attribute_value(tag: str, attr: str) -> str | None:
        if tag == "application":
            elem = manifest_tree.find(".//application")
        elif tag == "manifest":
            elem = manifest_tree
        else:
            elem = manifest_tree.find(f".//{tag}")

        if elem is None:
            return None

        # Try both bare and namespaced attribute names
        for name in (attr, f"{{{NS_ANDROID}}}{attr}"):
            val = elem.get(name)
            if val is not None:
                return val
        return None

    apk.get_attribute_value.side_effect = _get_attribute_value

    # Permissions
    apk.get_permissions.return_value = list(fixture.get("permissions", []))

    # Network security config file
    nsc_xml = fixture.get("network_security_config")
    if nsc_xml:
        apk.get_file.return_value = nsc_xml.encode("utf-8")
    else:
        apk.get_file.return_value = None

    # Certificates (empty — no real signing)
    apk.get_certificates.return_value = []

    # Signing scheme flags
    apk.is_signed_v1.return_value = fixture.get("signing_v1", True)
    apk.is_signed_v2.return_value = fixture.get("signing_v2", True)
    apk.is_signed_v3.return_value = fixture.get("signing_v3", False)

    return apk
