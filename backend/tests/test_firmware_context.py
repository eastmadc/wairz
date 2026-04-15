"""Tests for firmware-aware context enrichment utility."""

import unittest

from app.utils.firmware_context import (
    FirmwareContext,
    _apk_location_context,
    _build_risk_note,
    enrich_description,
    enrich_evidence,
)


class TestFirmwareContext(unittest.TestCase):
    """Unit tests for FirmwareContext dataclass."""

    def test_empty_context(self):
        ctx = FirmwareContext()
        self.assertTrue(ctx.is_empty)
        self.assertEqual(ctx.summary_line(), "")
        self.assertEqual(ctx.to_dict(), {})

    def test_full_context(self):
        ctx = FirmwareContext(
            device_model="Pixel 6",
            manufacturer="Google",
            android_version="13",
            api_level=33,
            security_patch="2023-10-05",
            architecture="arm64",
            partition="system",
            firmware_filename="pixel6-factory.zip",
            bootloader_state="locked",
            is_priv_app=True,
            is_system_app=True,
        )
        self.assertFalse(ctx.is_empty)
        d = ctx.to_dict()
        self.assertEqual(d["device_model"], "Pixel 6")
        self.assertEqual(d["manufacturer"], "Google")
        self.assertEqual(d["api_level"], 33)
        self.assertEqual(d["partition"], "system")
        self.assertTrue(d["is_priv_app"])
        self.assertTrue(d["is_system_app"])

    def test_summary_line(self):
        ctx = FirmwareContext(
            device_model="Galaxy S21",
            manufacturer="Samsung",
            android_version="12",
            api_level=31,
            security_patch="2023-06-01",
            architecture="arm64",
            partition="system",
        )
        summary = ctx.summary_line()
        self.assertIn("Samsung Galaxy S21", summary)
        self.assertIn("Android 12", summary)
        self.assertIn("API 31", summary)
        self.assertIn("arm64", summary)
        self.assertIn("/system", summary)

    def test_summary_line_partial(self):
        ctx = FirmwareContext(device_model="RouterX", architecture="mips")
        summary = ctx.summary_line()
        self.assertIn("RouterX", summary)
        self.assertIn("mips", summary)


class TestApkLocationContext(unittest.TestCase):
    """Tests for APK location path parsing."""

    def test_priv_app(self):
        ctx = _apk_location_context(
            "/fw/system/priv-app/Settings/Settings.apk", "/fw"
        )
        self.assertTrue(ctx.is_priv_app)
        self.assertTrue(ctx.is_system_app)
        self.assertEqual(ctx.partition, "system")

    def test_system_app(self):
        ctx = _apk_location_context(
            "/fw/system/app/Calculator/Calc.apk", "/fw"
        )
        self.assertFalse(ctx.is_priv_app)
        self.assertTrue(ctx.is_system_app)
        self.assertEqual(ctx.partition, "system")

    def test_vendor_app(self):
        ctx = _apk_location_context(
            "/fw/vendor/app/NfcReader/NfcReader.apk", "/fw"
        )
        self.assertTrue(ctx.is_vendor_app)
        self.assertEqual(ctx.partition, "vendor")

    def test_product_app(self):
        ctx = _apk_location_context(
            "/fw/product/app/Chrome/Chrome.apk", "/fw"
        )
        self.assertEqual(ctx.partition, "product")

    def test_no_path(self):
        ctx = _apk_location_context(None, None)
        self.assertFalse(ctx.is_priv_app)
        self.assertIsNone(ctx.partition)


class TestEnrichDescription(unittest.TestCase):
    """Tests for finding description enrichment."""

    def test_empty_context_passthrough(self):
        ctx = FirmwareContext()
        result = enrich_description("Original desc", ctx)
        self.assertEqual(result, "Original desc")

    def test_enrichment_adds_context_block(self):
        ctx = FirmwareContext(
            device_model="Pixel 6",
            manufacturer="Google",
            android_version="13",
            api_level=33,
            architecture="arm64",
            partition="system",
        )
        result = enrich_description("App is debuggable", ctx)
        self.assertIn("App is debuggable", result)
        self.assertIn("[Firmware Context]", result)
        self.assertIn("Google Pixel 6", result)
        self.assertIn("Android: 13 (API 33)", result)
        self.assertIn("arm64", result)

    def test_priv_app_risk_note(self):
        ctx = FirmwareContext(
            device_model="TestDevice",
            is_priv_app=True,
            partition="system",
        )
        result = enrich_description("Backup enabled", ctx)
        self.assertIn("[Risk Impact]", result)
        self.assertIn("privileged system app", result)

    def test_vendor_app_risk_note(self):
        ctx = FirmwareContext(
            device_model="TestDevice",
            is_vendor_app=True,
            partition="vendor",
        )
        result = enrich_description("Cleartext enabled", ctx)
        self.assertIn("vendor-bundled", result)

    def test_old_api_level_risk_note(self):
        ctx = FirmwareContext(
            device_model="OldPhone",
            android_version="5.1",
            api_level=22,
        )
        result = enrich_description("Backup enabled", ctx)
        self.assertIn("API level 22", result)
        self.assertIn("lacks modern security defaults", result)

    def test_no_risk_note_when_disabled(self):
        ctx = FirmwareContext(
            device_model="Test",
            is_priv_app=True,
        )
        result = enrich_description("Desc", ctx, include_risk_note=False)
        self.assertNotIn("[Risk Impact]", result)

    def test_debuggable_firmware_risk_note(self):
        ctx = FirmwareContext(
            device_model="Test",
            security_posture={"ro_debuggable": "1"},
        )
        result = enrich_description("Desc", ctx)
        self.assertIn("ro.debuggable=1", result)

    def test_unlocked_bootloader_risk_note(self):
        ctx = FirmwareContext(
            device_model="Test",
            bootloader_state="unlocked",
        )
        result = enrich_description("Desc", ctx)
        self.assertIn("bootloader is unlocked", result)


class TestEnrichEvidence(unittest.TestCase):
    """Tests for finding evidence enrichment."""

    def test_adds_firmware_line(self):
        ctx = FirmwareContext(
            device_model="Pixel",
            manufacturer="Google",
            android_version="14",
            api_level=34,
        )
        result = enrich_evidence("debuggable=true", ctx)
        self.assertIn("debuggable=true", result)
        self.assertIn("Firmware context:", result)
        self.assertIn("Google Pixel", result)

    def test_empty_context_passthrough(self):
        ctx = FirmwareContext()
        result = enrich_evidence("some evidence", ctx)
        self.assertEqual(result, "some evidence")

    def test_empty_evidence_with_context(self):
        ctx = FirmwareContext(
            device_model="Test",
            android_version="12",
        )
        result = enrich_evidence("", ctx)
        self.assertIn("Firmware context:", result)


class TestBuildRiskNote(unittest.TestCase):
    """Tests for risk note generation."""

    def test_no_risk_factors(self):
        ctx = FirmwareContext()
        self.assertEqual(_build_risk_note(ctx), "")

    def test_system_app_note(self):
        ctx = FirmwareContext(is_system_app=True, partition="system")
        note = _build_risk_note(ctx)
        self.assertIn("pre-installed system app", note)

    def test_combined_risk_factors(self):
        ctx = FirmwareContext(
            is_priv_app=True,
            android_version="4.4",
            api_level=19,
            bootloader_state="unlocked",
            security_posture={"ro_debuggable": "1"},
        )
        note = _build_risk_note(ctx)
        self.assertIn("privileged system app", note)
        self.assertIn("API level 19", note)
        self.assertIn("bootloader is unlocked", note)
        self.assertIn("ro.debuggable=1", note)


if __name__ == "__main__":
    unittest.main()
